#!/usr/bin/env python3
"""Install explicitly owned, initially closed client pool identities and Xray routes."""

import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

import client_pools
import site_policy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--install", action="store_true")
    mode.add_argument("--activate", action="store_true")
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("rotation_control", Path(__file__).with_name("rotation-control.py"))
    rotation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rotation)
    with rotation.CONTROL.data_lock():
        api = rotation.CONTROL.api_client()
        saved = rotation.backup("proxy-client-pools")
        if client_pools.MANIFEST.exists():
            shutil.copy2(client_pools.MANIFEST, saved / client_pools.MANIFEST.name)
            entries = client_pools.load(complete=False)
        else:
            entries = {}
        if args.activate:
            entries = client_pools.load()
            client_pools.verify_xray(json.loads(rotation.XRAY.read_text()), entries)
            approved = rotation.POOL.effective(rotation.POOL.load_state(), rotation.POOL.load_slots(),
                                                site_policy.bridge_identities(), api.nodes(), require_sites=True)
            counts = client_pools.enforce(api, approved, entries)
            health_spec = importlib.util.spec_from_file_location("client_health", Path(__file__).with_name("client-health.py"))
            health = importlib.util.module_from_spec(health_spec)
            health_spec.loader.exec_module(health)
            report = health.run(staged=True)
            site_policy.atomic_json(saved / "preflight.json", report)
            if (report["inconclusive"] or not report["general"]["passed"]
                    or approved and not report["strict"]["passed"]):
                raise RuntimeError("public client preflight failed; subscription policy unchanged")
            prior = rotation.POOL.POLICY.read_bytes() if rotation.POOL.POLICY.exists() else None
            try:
                site_policy.atomic_json(rotation.POOL.POLICY, {"version": 1, "mode": "split"})
                rotation.POOL.enforce(api)
                rotation.CONTROL.render()
            except BaseException:
                if prior is None:
                    rotation.POOL.POLICY.unlink(missing_ok=True)
                else:
                    site_policy.atomic_json(rotation.POOL.POLICY, json.loads(prior))
                rotation.POOL.enforce(api)
                rotation.CONTROL.render()
                raise
            print(json.dumps({"status": "split_published", "routable": counts, "backup": str(saved)}))
            return
        platforms = api.call("/api/v1/platforms?limit=1000")
        platforms = platforms["items"] if isinstance(platforms, dict) else platforms
        by_name = {row["name"]: row for row in platforms}
        for name, definition in client_pools.definitions().items():
            if name in entries:
                continue
            if definition["platform_name"] in by_name:
                raise ValueError("unowned client pool platform already exists")
            platform = api.call("/api/v1/platforms", "POST", {
                "name": definition["platform_name"], "regex_filters": site_policy.DENY,
                "region_filters": [definition["region"]] if definition["region"] else [],
                "passive_circuit_breaker_disabled": definition["kind"] == "strict"})
            entries[name] = dict(definition, uuid=str(uuid.uuid4()), platform_id=platform["id"])
            site_policy.atomic_json(client_pools.MANIFEST, {"version": 1, "owner": client_pools.OWNER,
                                                           "entries": entries})
        original = json.loads(rotation.XRAY.read_text())
        config = client_pools.configure_xray(original, entries)
        with tempfile.TemporaryDirectory(prefix="client-pools-config-") as directory:
            candidate = Path(directory) / "proxy.json"
            site_policy.atomic_json(candidate, config)
            subprocess.run([rotation.XRAY_BIN, "run", "-test", "-config", str(candidate)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
            if config != original:
                try:
                    site_policy.atomic_json(rotation.XRAY, config)
                    subprocess.run(["systemctl", "restart", "xray-proxy.service"], check=True, timeout=30)
                    subprocess.run(["systemctl", "is-active", "--quiet", "xray-proxy.service"], check=True)
                except BaseException:
                    site_policy.atomic_json(rotation.XRAY, original)
                    subprocess.run(["systemctl", "restart", "xray-proxy.service"], check=True, timeout=30)
                    raise
        print(json.dumps({"status": "provisioned_closed", "identities": len(entries), "backup": str(saved)}))


if __name__ == "__main__":
    main()
