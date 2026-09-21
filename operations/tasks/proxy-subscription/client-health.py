#!/usr/bin/env python3
"""Small real Mihomo canary through the public TLS/VLESS ingress, with identity checks."""

import argparse
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import time
import urllib.request

import yaml

import client_pools
import rotation_pool
import site_policy

STATUS = Path("/var/lib/proxy-region-latency/client-health.json")
TARGETS = ("https://www.cloudflare.com/cdn-cgi/trace",
           "https://www.gstatic.com/generate_204",
           "https://www.cloudflare.com/cdn-cgi/trace")


def load_rotation():
    spec = importlib.util.spec_from_file_location("rotation_control", Path(__file__).with_name("rotation-control.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def route_version(approved):
    identities = {name: [row.get(key) for key in rotation_pool.IDENTITY_FIELDS]
                  for name, row in sorted(approved.items())}
    return hashlib.sha256(json.dumps(identities, sort_keys=True).encode()).hexdigest()[:16]


def public_subscription(config, url_path=Path("/root/proxy-subscription-url.txt")):
    started = time.monotonic()
    result = {"passed": False, "status": None, "matches_publication": False}
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url_path.read_text().strip(), timeout=site_policy.OPERATING['subscription_timeout_seconds']) as response:
            result["status"] = response.status
            body = response.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024:
            raise ValueError("subscription response exceeds limit")
        result["matches_publication"] = yaml.safe_load(body) == config
        result["passed"] = result["status"] == 200 and result["matches_publication"]
    except Exception as exc:
        # URLs and parser errors can contain the subscription token or node credentials.
        result["error"] = type(exc).__name__
    result["ms"] = round((time.monotonic() - started) * 1000)
    return result


def probe(rotation, proxy, allowed_ips, strict):
    checks, identities = [], []
    for url in TARGETS:
        check, body = rotation.curl(proxy, url, limit=site_policy.OPERATING['client_probe_timeout_seconds'])
        checks.append({key: check[key] for key in ("status", "code", "ms")})
        expected_status = 200 if url.endswith("/trace") else 204
        if check["code"] or check["status"] != expected_status:
            break
        if url.endswith("/trace"):
            trace = dict(line.split("=", 1) for line in body.decode(errors="replace").splitlines() if "=" in line)
            try:
                address = str(ipaddress.ip_address(trace.get("ip", "")))
            except ValueError:
                address = None
            identities.append((address, trace.get("loc", "").lower()))
    identity_valid = (len(identities) == 2 and identities[0] == identities[1]
                      and identities[0][0] in allowed_ips and identities[0][1] != "cn")
    passed = len(checks) == 3 and all(not check["code"] and check["status"] == expected
                                     for check, expected in zip(checks, (200, 204, 200)))
    return {"passed": bool(passed and identity_valid), "identity_valid": identity_valid,
            "checks": checks, "scope": "approved_site_exits" if strict else "validated_global_pool"}


def run(staged=False, general_only=False):
    rotation = load_rotation()
    api = rotation.CONTROL.api_client()
    entries, slots, state = client_pools.load(), rotation_pool.load_slots(), rotation_pool.load_state()
    nodes = api.nodes()
    identities = site_policy.bridge_identities()
    approved = rotation_pool.effective(state, slots, identities, nodes, require_sites=True)
    version = route_version(approved)
    generation = site_policy.BRIDGE.parent.resolve().name
    general_ips = {node.get("egress_ip") for node in nodes
                   if node.get("enabled") is True and node.get("has_outbound") is True
                   and node.get("circuit_open_since") is None and node.get("region") != "cn"
                   and any(tag.get("subscription_name") == "managed-apps-public-pool"
                           and tag.get("tag", "").startswith("managed-apps-public-pool/")
                           for tag in node.get("tags", []))}
    strict_ips = {row["expected_ip"] for row in approved.values()}
    config = rotation.CONTROL.CLIENT.subscription_config(staged=staged)
    download = None if staged else public_subscription(config)
    if staged:
        config = client_pools.render(config, entries, slots, approved)
    wanted = ["Global-Auto"] + ([] if general_only else [client_pools.STRICT_NAME])
    config["proxies"] = [row for row in config["proxies"] if row["name"] in wanted]
    if {row["name"] for row in config["proxies"]} != set(wanted):
        raise ValueError("published profile is missing stable client identities")
    config["proxy-groups"] = [{"name": "PROXY", "type": "select", "proxies": wanted}]
    config["rules"] = ["MATCH,PROXY"]
    started = time.time()
    report = {"version": 1, "started_at": started, "scope": "server_public_ingress",
              "bridge_generation": generation, "strict_version": version, "strict_approved_count": len(approved),
              "staged": staged, "subscription": download, "general": None, "strict": None}
    with rotation.client(config) as (proxy, call):
        for name in wanted:
            strict = name == client_pools.STRICT_NAME
            if strict and not strict_ips:
                report["strict"] = {"passed": False, "skipped": True, "reason": "strict_pool_empty"}
                continue
            call("/proxies/PROXY", {"name": name})
            report["strict" if strict else "general"] = probe(rotation, proxy, strict_ips if strict else general_ips, strict)
    current = rotation_pool.effective(rotation_pool.load_state(), slots, site_policy.bridge_identities(),
                                      api.nodes(), require_sites=True)
    report["inconclusive"] = route_version(current) != version or site_policy.BRIDGE.parent.resolve().name != generation
    report["finished_at"] = time.time()
    report["ok"] = (not report["inconclusive"] and report["general"]["passed"]
                    and (staged or download["passed"])
                    and (general_only or report["strict"]["passed"]))
    # No qualified strict exit is a missing prerequisite, not a failed probe.
    # Keep ok=False so callers cannot mistake this for full channel acceptance.
    report["deferred"] = (not report["inconclusive"] and not general_only
                          and report["general"]["passed"] and (staged or download["passed"])
                          and report["strict"].get("reason") == "strict_pool_empty")
    report["status"] = ("ok" if report["ok"] else "skipped" if report["inconclusive"]
                        else "deferred" if report["deferred"] else "failed")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true")
    parser.add_argument("--general-only", action="store_true")
    parser.add_argument("--output", type=Path, default=STATUS)
    args = parser.parse_args()
    try:
        report = run(args.staged, args.general_only)
    except Exception as exc:
        report = {"version": 1, "finished_at": time.time(), "ok": False, "inconclusive": False,
                  "status": "failed", "scope": "server_public_ingress", "error": type(exc).__name__}
    site_policy.atomic_json(args.output, report)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ok"] or report["inconclusive"] else 75 if report.get("deferred") else 1


if __name__ == "__main__":
    raise SystemExit(main())
