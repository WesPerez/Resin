#!/usr/bin/env python3
"""Explicit live checks through the public TLS endpoint; never print credentials or IPs."""

import argparse
import concurrent.futures
import ipaddress
import json
from pathlib import Path
import re
import socket
import subprocess
import time
import urllib.parse
import urllib.request


XRAY = "/usr/local/lib/xray/v26.3.27/xray"
API = "http://172.17.0.1:10834"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--regions", default="", help="Comma-separated lower-case region codes")
    parser.add_argument("--samples", type=int, default=2, choices=range(1, 5))
    args = parser.parse_args()
    config = json.loads(Path("/etc/xray/proxy.json").read_text())
    token = Path("/etc/resin-apps/admin.token").read_text().strip()

    def get(path):
        request = urllib.request.Request(API + path, headers={"Authorization": "Bearer " + token})
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.load(response)

    wanted = set(filter(None, args.regions.split(",")))
    selected = [i for i in config["inbounds"] if
                (i["tag"] in {"proxy-ws", "proxy-xhttp"} and not wanted)
                or (re.fullmatch(r"proxy-ws-[a-z]{2}", i["tag"])
                    and (not wanted or i["tag"][-2:] in wanted))]
    if not selected:
        raise SystemExit("No matching region inbounds")

    client = {"log": {"loglevel": "none", "access": "none", "error": "none"},
              "inbounds": [], "outbounds": [], "routing": {"rules": []}}
    reservations, jobs = [], []
    for inbound in selected:
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        reservations.append(reservation)
        tag = inbound["tag"]
        network = inbound["streamSettings"]["network"]
        stream = {"network": network, "security": "tls",
                  "tlsSettings": {"serverName": "weesai.com", "allowInsecure": False,
                                  "alpn": ["h2"] if network == "xhttp" else ["http/1.1"]}}
        path = inbound["streamSettings"][network + "Settings"]["path"]
        if network == "ws":
            stream["wsSettings"] = {"path": path, "headers": {"Host": "weesai.com"}}
        else:
            stream["xhttpSettings"] = {"path": path, "host": "weesai.com", "mode": "stream-up"}
        client["inbounds"].append({"tag": tag, "listen": "127.0.0.1", "port": port,
                                   "protocol": "socks", "settings": {"auth": "noauth", "udp": False}})
        client["outbounds"].append({"tag": tag, "protocol": "vless", "mux": {"enabled": False},
            "settings": {"vnext": [{"address": "weesai.com", "port": 443,
                "users": [{"id": inbound["settings"]["clients"][0]["id"], "encryption": "none"}]}]},
            "streamSettings": stream})
        client["routing"]["rules"].append({"type": "field", "inboundTag": [tag], "outboundTag": tag})
        jobs.append((tag, port))

    for reservation in reservations:
        reservation.close()
    process = subprocess.Popen([XRAY, "run", "-format", "json", "-config", "/dev/stdin"],
                               stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    results = []
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
                    if time.monotonic() >= deadline or process.poll() is not None:
                        raise RuntimeError("Temporary client did not start")
                    time.sleep(0.1)

        def check(job):
            tag, port = job
            region = tag[-2:] if tag not in {"proxy-ws", "proxy-xhttp"} else None
            endpoints = ["https://www.cloudflare.com/cdn-cgi/trace",
                         "https://1.1.1.1/cdn-cgi/trace",
                         "https://cp.cloudflare.com/cdn-cgi/trace", "https://myip.ipip.net"]
            exits, seen_regions, errors, successes = set(), set(), [], 0
            database_disagreements = set()
            for attempt in range(args.samples + 3):
                url = endpoints[attempt % len(endpoints)] + "?verify=" + str(time.time_ns())
                response = subprocess.run(["curl", "-fsS", "--max-time", "18", "--noproxy", "",
                    "--proxy", f"socks5h://127.0.0.1:{port}", url], capture_output=True)
                if response.returncode:
                    errors.append("transport")
                    continue
                body = response.stdout.decode(errors="replace").strip()
                location = re.search(r"(?m)^loc=([A-Z]{2})$", body)
                match = re.search(r"(?m)^ip=([0-9a-fA-F:.]+)$", body)
                if match:
                    raw_ip = match.group(1)
                else:
                    raw_ip = body if len(body) < 50 else ""
                    if not raw_ip:
                        match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", body)
                        raw_ip = match.group(0) if match else ""
                try:
                    address = str(ipaddress.ip_address(raw_ip))
                    database_region = get("/api/v1/geoip/lookup?" + urllib.parse.urlencode({"ip": address}))["region"]
                    # Resin uses trace loc first. Its fallback MMDB can return
                    # provider labels (google/cloudflare), not country codes.
                    actual = location.group(1).lower() if location else database_region
                    if location and database_region != actual:
                        database_disagreements.add(database_region)
                except Exception:
                    errors.append("ip-lookup")
                    continue
                seen_regions.add(actual)
                if region is not None and region != actual:
                    errors.append("region-mismatch")
                    continue
                exits.add(address)
                successes += 1
                if successes >= args.samples:
                    break
            result = {"node": (region.upper() + "-Auto") if region else tag,
                      "successes": successes, "distinct_exits": len(exits),
                      "observed_regions": sorted(seen_regions), "retry_reasons": errors,
                      "database_disagreements": sorted(database_disagreements),
                      "passed": successes >= args.samples and "region-mismatch" not in errors}
            print(json.dumps(result), flush=True)
            return result

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            results = list(executor.map(check, jobs))
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    print(json.dumps({"tested": len(results), "passed": sum(r["passed"] for r in results),
                      "failed_nodes": [r["node"] for r in results if not r["passed"]]}))
    return 0 if results and all(r["passed"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
