#!/usr/bin/env python3
"""Measure the real public TLS proxy path without logging credentials or IPs."""

import argparse
import concurrent.futures
import json
import math
from pathlib import Path
import socket
import statistics
import subprocess
import time


XRAY = "/usr/local/lib/xray/v26.3.27/xray"
TARGETS = ("https://www.cloudflare.com/cdn-cgi/trace",
           "https://www.microsoft.com/", "https://www.wikipedia.org/")


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--regions", default="hk,jp,us,sg,de,nl")
    parser.add_argument("--samples", type=int, default=12)
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()
    if not 1 <= args.samples <= 60 or not 1 <= args.timeout <= 30:
        parser.error("samples must be 1..60; timeout must be 1..30")
    config = json.loads(Path("/etc/xray/proxy.json").read_text())
    wanted = {"proxy-ws", "proxy-xhttp"} | {"proxy-ws-" + r for r in args.regions.split(",") if r}
    client = {"log": {"loglevel": "none"}, "inbounds": [], "outbounds": [],
              "routing": {"rules": []}}
    jobs, reservations = [], []
    try:
        for inbound in config["inbounds"]:
            tag = inbound["tag"]
            if tag not in wanted:
                continue
            reservation = socket.socket()
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
            reservations.append(reservation)
            stream = inbound["streamSettings"]
            network = stream["network"]
            transport = {"network": network, "security": "tls",
                         "tlsSettings": {"serverName": "weesai.com", "allowInsecure": False,
                                         "alpn": ["h2"] if network == "xhttp" else ["http/1.1"]}}
            path = stream[network + "Settings"]["path"]
            transport[network + "Settings"] = (
                {"path": path, "host": "weesai.com", "mode": "stream-up"} if network == "xhttp"
                else {"path": path, "headers": {"Host": "weesai.com"}})
            client["inbounds"].append({"tag": tag, "listen": "127.0.0.1", "port": port,
                                       "protocol": "socks", "settings": {"auth": "noauth", "udp": False}})
            client["outbounds"].append({"tag": tag, "protocol": "vless", "mux": {"enabled": False},
                "settings": {"vnext": [{"address": "weesai.com", "port": 443, "users": [
                    {"id": inbound["settings"]["clients"][0]["id"], "encryption": "none"}]}]},
                "streamSettings": transport})
            client["routing"]["rules"].append({"type": "field", "inboundTag": [tag], "outboundTag": tag})
            jobs.append((tag, port))
    finally:
        for reservation in reservations:
            reservation.close()
    process = subprocess.Popen([XRAY, "run", "-format", "json", "-config", "/dev/stdin"],
                               stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        process.stdin.write(json.dumps(client).encode())
        process.stdin.close()
        for _, port in jobs:
            deadline = time.monotonic() + 10
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("benchmark client startup failed")
                    time.sleep(0.05)

        def measure(job):
            tag, port = job
            totals, ttfbs, failures, attempts = [], [], 0, []
            for i in range(args.samples):
                result = subprocess.run([
                    "curl", "--silent", "--output", "/dev/null", "--noproxy", "",
                    "--connect-timeout", str(args.timeout), "--max-time", str(args.timeout),
                    "--proxy", f"socks5h://127.0.0.1:{port}",
                    "--write-out", "%{http_code} %{time_starttransfer} %{time_total}",
                    TARGETS[i % len(TARGETS)]], capture_output=True, timeout=args.timeout + 3)
                fields = result.stdout.split()
                ok = result.returncode == 0 and len(fields) == 3 and 200 <= int(fields[0]) < 400
                elapsed = float(fields[2]) * 1000 if len(fields) == 3 else args.timeout * 1000
                attempts.append(round(elapsed, 1))
                if ok:
                    ttfbs.append(round(float(fields[1]) * 1000, 1))
                    totals.append(round(elapsed, 1))
                else:
                    failures += 1
            row = {"node": tag, "attempts": args.samples, "successes": len(totals),
                   "failures": failures, "median_ttfb_ms": statistics.median(ttfbs) if ttfbs else None,
                   "p90_total_ms": percentile(totals, 0.9),
                   "median_attempt_ms": statistics.median(attempts), "attempts_ms": attempts}
            print(json.dumps(row), flush=True)
            return row

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            rows = list(executor.map(measure, jobs))
        print(json.dumps({"nodes": len(rows), "attempts": sum(r["attempts"] for r in rows),
                          "failures": sum(r["failures"] for r in rows),
                          "vantage": "server-to-public-TLS-endpoint; not mainland client RTT"}))
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


if __name__ == "__main__":
    main()
