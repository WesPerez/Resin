#!/usr/bin/env python3
"""Restrict a rendered subscription to current browser-approved regional exits."""

import argparse
import importlib.util
import json
from pathlib import Path

import yaml

import site_policy
import rotation_pool


def restrict(config, approvals):
    by_name = {p["name"]: p for p in config["proxies"]}
    names = [r.upper() + "-Auto" for r in ("us", "hk", "sg", "jp", "ca", "de", "nl") if r in approvals]
    names += [r.upper() + "-Auto" for r in sorted(approvals) if r.upper() + "-Auto" not in names]
    for name in names:
        if name not in by_name or by_name[name].get("network") != "ws":
            raise ValueError("approved region is missing its validated subscription inbound")
    config["proxies"] = [by_name[name] for name in names]
    config["proxy-groups"] = []
    if names:
        for group in ("Auto-Fast", "Auto-Region"):
            config["proxy-groups"].append({"name": group, "type": "fallback",
                "url": "https://www.gstatic.com/generate_204", "interval": 300, "lazy": True,
                "timeout": 5000, "expected-status": 204, "proxies": names})
    config["proxy-groups"].append({"name": "PROXY", "type": "select",
                                   "proxies": ["Auto-Fast", "Auto-Region", *names] if names else ["REJECT"]})
    config["rules"] = ["MATCH,PROXY"]
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--policy", type=Path, default=site_policy.POLICY)
    parser.add_argument("--state", type=Path, default=site_policy.STATE)
    parser.add_argument("--bridge", type=Path, default=site_policy.BRIDGE)
    args = parser.parse_args()
    if rotation_pool.unified() or not site_policy.strict_enabled(args.policy):
        return
    try:
        state = site_policy.load_state(args.state)
        identities = site_policy.bridge_identities(args.bridge)
    except (OSError, ValueError, KeyError, TypeError):
        state, identities = {"approved": {}}, {}
    spec = importlib.util.spec_from_file_location("region_latency", Path(__file__).with_name("region-latency.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    api = module.API(Path("/etc/resin-apps/admin.token").read_text().strip())
    approved = site_policy.effective(state, identities, api.nodes())
    manifest = json.loads(Path("/etc/xray/resin-region-platforms.json").read_text())
    for region, row in list(approved.items()):
        platform = api.call("/api/v1/platforms/" + manifest["Proxy" + region.upper()]["id"])
        if platform["regex_filters"] != site_policy.filters(row) or platform["routable_node_count"] != 1:
            approved.pop(region)
    config = restrict(yaml.safe_load(args.input.read_text()), approved)
    args.input.write_text(yaml.safe_dump(config, sort_keys=False, allow_unicode=False))
    print(json.dumps({"subscription_mode": "strict", "regions": sorted(approved)}))


if __name__ == "__main__":
    main()
