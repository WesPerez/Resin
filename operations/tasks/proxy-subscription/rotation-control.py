#!/usr/bin/env python3
"""Provision and verify independent browsing exits for the shared quality pool."""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import copy
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

import yaml

import rotation_pool as POOL
import site_policy


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("site_control", ROOT / "site-control.py")
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)
XRAY = Path("/etc/xray/proxy.json")
XRAY_BIN = "/usr/local/lib/xray/v26.3.27/xray"


def backup(label):
    target = Path("/root/deployment-backups") / (label + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    target.mkdir(mode=0o700)
    for path in (XRAY, POOL.SLOTS, POOL.AUDIT_SLOTS, POOL.STATE, POOL.POLICY, site_policy.STATE):
        if path.exists():
            shutil.copy2(path, target / path.name)
    shutil.copytree("/var/lib/proxy-subscription", target / "subscription")
    return target


def provision():
    with CONTROL.data_lock():
        api = CONTROL.api_client()
        saved = backup("proxy-rotation")
        slots = POOL.load_slots() if POOL.SLOTS.exists() else {}
        platforms = api.call("/api/v1/platforms?limit=1000")
        platforms = platforms["items"] if isinstance(platforms, dict) else platforms
        by_name = {p["name"]: p for p in platforms}
        for region, capacity in POOL.CAPACITY.items():
            for number in range(1, capacity + 1):
                name = region.upper() + f"-{number:02d}"
                if name in slots:
                    continue
                platform_name = "Browse" + name.replace("-", "")
                if platform_name in by_name:
                    raise ValueError("unowned browsing platform already exists")
                platform = api.call("/api/v1/platforms", "POST", {"name": platform_name,
                    "region_filters": [region], "regex_filters": site_policy.DENY,
                    "passive_circuit_breaker_disabled": True})
                slots[name] = {"region": region, "uuid": str(uuid.uuid4()),
                               "platform_name": platform_name, "platform_id": platform["id"],
                               "email": "browse-" + name.lower()}
                site_policy.atomic_json(POOL.SLOTS, slots)
        audits = json.loads(POOL.AUDIT_SLOTS.read_text()) if POOL.AUDIT_SLOTS.exists() else {}
        for region in POOL.CAPACITY:
            if region in audits:
                continue
            platform_name = "BrowseCheck" + region.upper()
            if platform_name in by_name:
                raise ValueError("unowned audit platform already exists")
            platform = api.call("/api/v1/platforms", "POST", {"name": platform_name,
                "region_filters": [region], "regex_filters": site_policy.DENY,
                "passive_circuit_breaker_disabled": True})
            audits[region] = {"region": region, "uuid": str(uuid.uuid4()),
                "platform_name": platform_name, "platform_id": platform["id"],
                "email": "browsecheck-" + region}
            site_policy.atomic_json(POOL.AUDIT_SLOTS, audits)
        config = json.loads(XRAY.read_text())
        inbound = next(i for i in config["inbounds"] if i["tag"] == "proxy-ws")
        template = next(i for i in config["outbounds"] if i["tag"] == "resin-sg")
        for slot in [*slots.values(), *audits.values()]:
            clients = inbound["settings"]["clients"]
            expected = {"id": slot["uuid"], "email": slot["email"]}
            existing = [c for c in clients if c.get("email") == slot["email"] or c["id"] == slot["uuid"]]
            if existing and existing != [expected]:
                raise ValueError("browsing client ownership mismatch")
            if not existing:
                clients.append(expected)
            outbound = copy.deepcopy(template)
            outbound["tag"] = slot["email"]
            outbound["settings"]["servers"][0]["users"][0]["user"] = slot["platform_name"]
            present = [o for o in config["outbounds"] if o["tag"] == outbound["tag"]]
            if present and present != [outbound]:
                raise ValueError("browsing outbound ownership mismatch")
            if not present:
                config["outbounds"].append(outbound)
            rule = {"type": "field", "inboundTag": ["proxy-ws"], "user": [slot["email"]],
                    "outboundTag": slot["email"]}
            present = [r for r in config["routing"]["rules"] if r.get("user") == rule["user"]]
            if present and present != [rule]:
                raise ValueError("browsing routing ownership mismatch")
            if not present:
                config["routing"]["rules"].append(rule)
        with tempfile.TemporaryDirectory(prefix="rotation-config-") as directory:
            candidate = Path(directory) / "proxy.json"
            site_policy.atomic_json(candidate, config)
            subprocess.run([XRAY_BIN, "run", "-test", "-config", str(candidate)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
            if json.loads(XRAY.read_text()) != config:
                try:
                    site_policy.atomic_json(XRAY, config)
                    subprocess.run(["systemctl", "restart", "xray-proxy.service"], check=True, timeout=30)
                    subprocess.run(["systemctl", "is-active", "--quiet", "xray-proxy.service"], check=True)
                except BaseException:
                    shutil.copy2(saved / XRAY.name, XRAY)
                    subprocess.run(["systemctl", "restart", "xray-proxy.service"], check=True, timeout=30)
                    raise
        print(json.dumps({"provisioned": len(slots), "backup": str(saved)}), flush=True)


def curl(proxy, url, limit=8):
    started = time.monotonic()
    completed = subprocess.run(["curl", "--silent", "--show-error", "--noproxy", "", "--proxy", proxy,
        "--connect-timeout", "4", "--max-time", str(limit), "--write-out", "\n%{http_code}", url],
        capture_output=True, timeout=limit + 2)
    body, _, status = completed.stdout.rpartition(b"\n")
    return {"status": int(status) if status.isdigit() else 0, "code": completed.returncode,
            "ms": round((time.monotonic() - started) * 1000),
            "error": completed.stderr.decode(errors="replace")[:200]}, body


def probe(item, proxy=None):
    proxy = proxy or f"socks5h://172.17.0.1:{item['port']}"
    checks, identities = [], []
    for url in ("https://www.cloudflare.com/cdn-cgi/trace", "https://www.gstatic.com/generate_204",
                "https://www.cloudflare.com/cdn-cgi/trace"):
        check, body = curl(proxy, url)
        checks.append(check)
        if check["code"] or check["status"] not in (200, 204):
            break
        if url.endswith("/trace"):
            trace = dict(line.split("=", 1) for line in body.decode(errors="replace").splitlines() if "=" in line)
            identities.append({"ip": trace.get("ip"), "region": trace.get("loc", "").lower()})
    expected = {"ip": item["expected_ip"], "region": item["region"]}
    passed = len(checks) == 3 and all(not c["code"] and c["status"] in (200, 204) for c in checks)
    passed = passed and identities == [expected, expected] and max(c["ms"] for c in checks) <= 6000
    return dict(item, passed=passed, checks=checks, observed=identities,
                checked_at=time.time(), validation_path="bridge")


@contextmanager
def client(config, listener_ports=None):
    with tempfile.TemporaryDirectory(prefix="rotation-mihomo-") as directory:
        listener_count = len(config.get("listeners", [])) if listener_ports is not None else 0
        sockets = [socket.socket() for _ in range(2 + listener_count)]
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        ports = [sock.getsockname()[1] for sock in sockets]
        mixed, controller = ports[:2]
        config = copy.deepcopy(config)
        listeners = config.get("listeners", []) if listener_ports is not None else []
        for listener, port in zip(listeners, ports[2:]):
            listener["port"] = port
            listener_ports.append(port)
        config.update({"mixed-port": mixed, "external-controller": f"127.0.0.1:{controller}",
                       "allow-lan": False, "bind-address": "127.0.0.1", "listeners": listeners,
                       "profile": {"store-selected": False}, "log-level": "warning"})
        path = Path(directory) / "config.yaml"
        path.write_text(yaml.safe_dump(config, sort_keys=False))
        path.chmod(0o600)
        shutil.copyfile("/opt/proxy-site-quality/Country.mmdb", Path(directory) / "Country.mmdb")
        for sock in sockets:
            sock.close()
        evidence = Path("/var/lib/proxy-region-latency") / ("rotation-client-" + str(time.time_ns()) + ".log")
        with evidence.open("w") as log:
            os.fchmod(log.fileno(), 0o600)
            subprocess.run([str(CONTROL.CLIENT.MIHOMO), "-t", "-d", directory, "-f", str(path)],
                           check=True, stdout=log, stderr=log, timeout=20)
            process = subprocess.Popen([str(CONTROL.CLIENT.MIHOMO), "-d", directory, "-f", str(path)],
                                       stdout=log, stderr=log)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

            def call(endpoint, value=None, timeout=5):
                req = urllib.request.Request(f"http://127.0.0.1:{controller}" + endpoint,
                    data=json.dumps(value).encode() if value is not None else None,
                    method="PUT" if value is not None else "GET", headers={"Content-Type": "application/json"})
                with opener.open(req, timeout=timeout) as response:
                    body = response.read()
                    return json.loads(body) if body else None

            try:
                deadline = time.monotonic() + 15
                while True:
                    try:
                        if "PROXY" in call("/proxies")["proxies"]:
                            break
                    except OSError:
                        pass
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("Mihomo failed to start")
                    time.sleep(0.1)
                yield f"socks5h://127.0.0.1:{mixed}", call
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def verify(slots, candidates):
    config = CONTROL.CLIENT.subscription_config(staged=True)
    config["proxies"] = POOL.proxy_entries(config, slots, candidates)
    config["proxy-groups"] = [{"name": "PROXY", "type": "select", "proxies": list(candidates)}]
    config["rules"] = ["MATCH,PROXY"]
    result = {}
    with client(config) as (proxy, call):
        for name, row in candidates.items():
            call("/proxies/PROXY", {"name": name})
            checked = probe(row, proxy)
            checked["validation_path"] = "subscription"
            result[name] = checked
            print(json.dumps({"slot": name, "passed": checked["passed"],
                              "ip": checked["expected_ip"], "ms": [c["ms"] for c in checked["checks"]]}), flush=True)
    return result


def refresh(activate=False):
    with CONTROL.data_lock():
        api, slots, state = CONTROL.api_client(), POOL.load_slots(), POOL.load_state()
        before = copy.deepcopy(state)
        live, identities = api.nodes(), site_policy.bridge_identities()
        existing = POOL.effective(state, slots, identities, live)
        used, items = set(), []
        for row in existing.values():
            used.add(row["expected_ip"])
            items.append(row)
        for region, capacity in POOL.CAPACITY.items():
            retained = sum(row["region"] == region for row in existing.values())
            if retained >= capacity:
                continue
            # Fast rotating upstreams dominate the head of the US list. Search the
            # whole bounded reserve when slots are missing, including slower fixed exits.
            for node in CONTROL.REGIONS.shortlist(live, region, limit=200 if region == "us" else capacity * 8):
                port = CONTROL.REGIONS.bridge_port(node)
                if port not in identities or node["egress_ip"] in used:
                    continue
                used.add(node["egress_ip"])
                items.append({"region": region, "port": port, "node_hash": node["node_hash"],
                              "slot_identity": identities[port], "expected_ip": node["egress_ip"]})
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(probe, items))
        available = {r["expected_ip"]: r for r in results if r["passed"]}
        chosen, claimed = {}, set()
        for name, prior in existing.items():
            if prior["expected_ip"] in available:
                chosen[name] = available[prior["expected_ip"]]
                claimed.add(prior["expected_ip"])
        for name, slot in slots.items():
            if name in chosen:
                continue
            row = next((r for r in available.values() if r["region"] == slot["region"]
                        and r["expected_ip"] not in claimed), None)
            if row is not None:
                chosen[name] = row
                claimed.add(row["expected_ip"])
        report = {"started_at": time.time(), "bridge": results}
        report_path = Path("/var/lib/proxy-region-latency") / ("rotation-check-" + str(time.time_ns()) + ".json")
        site_policy.atomic_json(report_path, report)
        state["approved"] = chosen
        prior_policy = POOL.POLICY.read_bytes() if POOL.POLICY.exists() else None
        try:
            staged = POOL.enforce(api, state, slots, staged=True)
            checked = verify(slots, staged) if staged else {}
            report["subscription"] = checked
            report["finished_at"] = time.time()
            site_policy.atomic_json(report_path, report)
            state["approved"] = {name: row for name, row in checked.items() if row["passed"]}
            state["last_report"] = str(report_path)
            site_policy.atomic_json(POOL.STATE, state)
            approved = POOL.enforce(api, state, slots)
            if activate:
                if len(approved) < 12:
                    raise RuntimeError("at least twelve independently verified exits required for first publication")
                site_policy.atomic_json(POOL.POLICY, {"version": 1, "mode": "balanced"})
            if POOL.enabled():
                CONTROL.render()
            print(json.dumps({"published": len(approved), "regions": dict(Counter(r["region"] for r in approved.values())),
                              "report": str(report_path)}), flush=True)
        except BaseException:
            if activate:
                if prior_policy is None:
                    POOL.POLICY.unlink(missing_ok=True)
                else:
                    site_policy.atomic_json(POOL.POLICY, json.loads(prior_policy))
            site_policy.atomic_json(POOL.STATE, before)
            POOL.enforce(api, before, slots)
            if POOL.enabled():
                CONTROL.render()
            raise


def main():
    os.umask(0o077)
    def terminate(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("provision", "refresh", "activate", "enforce", "unify"))
    parser.add_argument("--wait-seconds", type=int, default=0)
    parser.add_argument("--limit", type=int, default=site_policy.OPERATING['rotation_batch_size'])
    args = parser.parse_args()
    CONTROL.WAIT_SECONDS = args.wait_seconds
    if args.mode == "provision":
        provision()
    elif args.mode == "unify" or (args.mode == "refresh" and POOL.unified()):
        import unified_quality
        unified_quality.refresh(sys.modules[__name__], activate=args.mode == "unify", limit=args.limit)
    elif args.mode == "enforce":
        with CONTROL.data_lock():
            if POOL.enabled():
                import unified_quality
                api = CONTROL.api_client()
                try:
                    unified_quality.close_audits(api)
                    print(json.dumps({"approved": len(POOL.enforce(api))}))
                finally:
                    CONTROL.render()
    else:
        refresh(activate=args.mode == "activate")
        if POOL.enabled() and not POOL.unified():
            # refresh() has released the data lock. Keep the site's independent
            # browser -> data lock order and failure status, in the same timer.
            subprocess.run([sys.executable, str(ROOT / "site-control.py"), "refresh",
                            "--wait-seconds", str(args.wait_seconds)], check=True, timeout=900)


if __name__ == "__main__":
    try:
        main()
    except CONTROL.PoolBusy:
        print(json.dumps({"status": "skipped", "reason": "pool maintenance active or queued"}))
