#!/usr/bin/env python3
"""Explicit live subscription verification with an isolated loopback client."""

import argparse
import json
from pathlib import Path
import socket
import statistics
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import yaml


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    args = parser.parse_args()
    runtime = args.runtime_dir.resolve()
    token = Path("/etc/xray/subscription-token").read_text().strip()
    config = yaml.safe_load((runtime / "sub" / (token + ".yaml")).read_bytes())
    reservations = [socket.socket(), socket.socket()]
    for reservation in reservations:
        reservation.bind(("127.0.0.1", 0))
    mixed, controller = [s.getsockname()[1] for s in reservations]
    config.update({"mixed-port": mixed, "external-controller": f"127.0.0.1:{controller}",
                   "bind-address": "127.0.0.1", "allow-lan": False, "log-level": "silent",
                   "profile": {"store-selected": False}})
    base = f"http://127.0.0.1:{controller}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def api(path, method="GET", body=None, timeout=15):
        request = urllib.request.Request(base + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json"})
        with opener.open(request, timeout=timeout) as response:
            data = response.read()
        return json.loads(data) if data else None

    with tempfile.TemporaryDirectory(prefix="mihomo-live-", dir=runtime) as directory:
        config_path = Path(directory) / "config.yaml"
        config_path.write_text(yaml.safe_dump(config, sort_keys=False))
        config_path.chmod(0o600)
        for reservation in reservations:
            reservation.close()
        process = subprocess.Popen([str(runtime / "mihomo"), "-d", str(runtime), "-f", str(config_path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 15
            while True:
                try:
                    api("/version", timeout=1)
                    groups = api("/proxies", timeout=1).get("proxies", {})
                    if "Auto-Fast" not in groups or "PROXY" not in groups:
                        raise OSError("Mihomo configuration not loaded yet")
                    break
                except (OSError, urllib.error.URLError):
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("isolated Mihomo startup failed") from None
                    time.sleep(0.1)
            fast = next(g for g in config["proxy-groups"] if g["name"] == "Auto-Fast")
            delays = {}
            query = urllib.parse.urlencode({"url": fast["url"], "timeout": 5000})
            for name in fast["proxies"]:
                try:
                    result = api("/proxies/" + urllib.parse.quote(name, safe="") + "/delay?" + query)
                    delays[name] = result.get("delay")
                except urllib.error.HTTPError:
                    delays[name] = None
            print(json.dumps({"url_test_ms": delays}), flush=True)
            api("/proxies/PROXY", "PUT", {"name": "Auto-Fast"})
            choices = [("Auto-Fast", 12), ("weesai.com-vless-443", 3),
                       ("weesai.com-vless-443-ws", 3)]
            targets = ("https://www.cloudflare.com/cdn-cgi/trace",
                       "https://www.microsoft.com/", "https://www.wikipedia.org/")
            overall = True
            for choice, samples in choices:
                api("/proxies/PROXY", "PUT", {"name": choice})
                timings, failures, errors = [], 0, []
                selected = api("/proxies/Auto-Fast").get("now") if choice == "Auto-Fast" else choice
                for index in range(samples):
                    response = subprocess.run([
                        "curl", "--silent", "--output", "/dev/null", "--noproxy", "",
                        "--proxy", f"socks5h://127.0.0.1:{mixed}", "--connect-timeout", "5",
                        "--max-time", "10", "--write-out", "%{http_code} %{time_starttransfer}",
                        targets[index % len(targets)]], capture_output=True, timeout=13)
                    fields = response.stdout.split()
                    if response.returncode == 0 and len(fields) == 2 and 200 <= int(fields[0]) < 400:
                        timings.append(round(float(fields[1]) * 1000, 1))
                    else:
                        failures += 1
                        errors.append({"target": urllib.parse.urlsplit(targets[index % len(targets)]).hostname,
                                       "curl_exit": response.returncode,
                                       "http_status": fields[0].decode() if fields else None})
                print(json.dumps({"group": choice, "selected": selected, "attempts": samples,
                                  "successes": len(timings), "failures": failures,
                                  "median_ttfb_ms": statistics.median(timings) if timings else None,
                                  "errors": errors}), flush=True)
                overall = overall and failures == 0
            return 0 if overall else 1
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"status": "error", "category": type(exc).__name__}))
        raise SystemExit(1) from None
