#!/usr/bin/env python3
"""Publish and periodically revalidate the fixed subscription exit allowlist."""

import argparse
import copy
from contextlib import contextmanager
from datetime import datetime, timezone
import errno
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse

import site_policy
import rotation_pool


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("region_latency", ROOT / "region-latency.py")
REGIONS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REGIONS)
CLIENT_SPEC = importlib.util.spec_from_file_location("site_client", ROOT / "verify-site-subscription.py")
CLIENT = importlib.util.module_from_spec(CLIENT_SPEC)
CLIENT_SPEC.loader.exec_module(CLIENT)
AUDIT_SPEC = importlib.util.spec_from_file_location("site_quality", ROOT / "site-quality.py")
AUDIT = importlib.util.module_from_spec(AUDIT_SPEC)
AUDIT_SPEC.loader.exec_module(AUDIT)
MANIFEST = Path("/etc/xray/resin-region-platforms.json")
WAIT_SECONDS = 0
RECOVERY_REGIONS = ("us", "hk", "sg", "jp", "de", "nl", "ca")


class PoolBusy(RuntimeError):
    pass


def error_summary(exc):
    error = {"status": "error", "category": type(exc).__name__}
    if isinstance(exc, OSError) and exc.errno is not None:
        error["errno"] = errno.errorcode.get(exc.errno, "UNKNOWN")
    if isinstance(exc, urllib.error.HTTPError):
        error.update(http_status=exc.code, endpoint=urllib.parse.urlsplit(exc.url).path)
    return error


def api_client():
    return REGIONS.API(Path("/etc/resin-apps/admin.token").read_text().strip())


@contextmanager
def data_lock(held=False):
    if held:
        yield
        return
    with open(REGIONS.LOCK_PATH, "a") as lock, open(REGIONS.LOCK_PATH + ".priority", "a") as priority:
        deadline = time.monotonic() + WAIT_SECONDS
        while not REGIONS.acquire_probe_lock(lock, priority):
            if time.monotonic() >= deadline:
                raise PoolBusy("pool maintenance active or queued; retry after it completes")
            time.sleep(1)
        yield


def render():
    subprocess.run(["bash", str(ROOT / "render-proxy-subscription.sh")], check=True,
                   stdout=subprocess.DEVNULL, timeout=30)


@contextmanager
def browser_lock(wait_seconds=0):
    with open("/run/lock/proxy-site-quality.lock", "a") as lock:
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise PoolBusy("browser audit already running") from exc
                time.sleep(1)
        yield


def qualify(state, api, manifest):
    """Caller holds the data lock while temporary exact routes are under test."""
    candidates = copy.deepcopy(site_policy.effective(
        state, site_policy.bridge_identities(), api.nodes(), require_client=False))
    previous = copy.deepcopy(site_policy.effective(state, site_policy.bridge_identities(), api.nodes()))
    for region, row in state["approved"].items():
        row["validation_path"] = "bridge"
        if region in candidates:
            row.update(success_streak=0, expires_at=0)
    reports, paths = [], []
    site_policy.atomic_json(site_policy.STATE, state)
    try:
        if candidates:
            staged = {"approved": candidates}
            result = site_policy.enforce(api, manifest, staged, require_client=False)
            remaining = {region: staged["approved"][region] for region in result["approved_regions"]}
            if remaining:
                config = CLIENT.subscription_config(staged=True)
                deadline = time.monotonic() + 480
                for _ in range(2):
                    report, path = CLIENT.verify_round(CLIENT.restrict(config, remaining), remaining, deadline=deadline)
                    reports.append(report)
                    paths.append(str(path))
                    site_policy.record_failures(state, report)
                    site_policy.atomic_json(site_policy.STATE, state)
                    passing = {key[0] for key in site_policy.report_passes(report)}
                    remaining = {region: row for region, row in remaining.items() if region in passing}
                    if not remaining:
                        break
                if len(reports) == 2 and remaining:
                    qualified = site_policy.approve_reports(reports)
                    blocked = site_policy.quarantined_ips(state)
                    state["approved"].update({region: row for region, row in qualified["approved"].items()
                                              if row["expected_ip"] not in blocked})
    finally:
        # A failed check or process error must close the temporary candidate routes.
        blocked = site_policy.quarantined_ips(state)
        for region, row in previous.items():
            current = state["approved"].get(region, {})
            if (row["expected_ip"] not in blocked and site_policy.valid_approval(region, row, time.time())
                    and all(row[key] == current.get(key) for key in CLIENT.ITEM_FIELDS)
                    and not site_policy.valid_approval(region, current, time.time())):
                state["approved"][region] = row
        state["last_client_reports"] = paths
        persisted = False
        try:
            site_policy.atomic_json(site_policy.STATE, state)
            persisted = True
        finally:
            try:
                result = site_policy.enforce(api, manifest, state if persisted else {"approved": {}})
            finally:
                render()
    return result


def enforce(held=False, publish=False):
    if not site_policy.strict_enabled():
        return
    with data_lock(held):
        result = site_policy.enforce(api_client(), json.loads(MANIFEST.read_text()))
        if rotation_pool.enabled():
            result["rotation_exits"] = len(rotation_pool.enforce(api_client()))
        if publish:
            render()
        print(json.dumps(result), flush=True)


def revoke(region):
    with data_lock():
        state = site_policy.load_state()
        row = state["approved"][region]
        row.update(success_streak=0, expires_at=0, revoked=True)
        site_policy.atomic_json(site_policy.STATE, state)
        result = site_policy.enforce(api_client(), json.loads(MANIFEST.read_text()), state)
        render()
        print(json.dumps(result), flush=True)


def seed(paths):
    reports = [json.loads(Path(path).read_text()) for path in paths]
    state = site_policy.approve_reports(reports)
    state["reports"] = paths
    with data_lock():
        try:
            previous = site_policy.load_state()
        except FileNotFoundError:
            previous = {"version": 1, "approved": {}}
        state["quarantined"] = previous.setdefault("quarantined", {})
        for report in reports:
            site_policy.record_failures(previous, report)
        site_policy.atomic_json(site_policy.STATE, previous)
        approved = site_policy.effective(state, site_policy.bridge_identities(), api_client().nodes(),
                                         require_client=False)
        if not approved:
            if site_policy.strict_enabled():
                site_policy.enforce(api_client(), json.loads(MANIFEST.read_text()), previous)
                render()
            raise RuntimeError("approved exits are no longer current")
        state["approved"] = approved
        site_policy.atomic_json(site_policy.STATE, state)
        print(json.dumps({"status": "seeded", "regions": sorted(approved)}), flush=True)


def quarantine(paths):
    with data_lock():
        state = site_policy.load_state()
        for path in paths:
            site_policy.record_failures(state, json.loads(Path(path).read_text()))
        site_policy.atomic_json(site_policy.STATE, state)
        result = site_policy.enforce(api_client(), json.loads(MANIFEST.read_text()), state)
        render()
        result["quarantined_ips"] = len(site_policy.quarantined_ips(state))
        print(json.dumps(result), flush=True)


def activate():
    with browser_lock(), data_lock():
        api = api_client()
        manifest = json.loads(MANIFEST.read_text())
        state = site_policy.load_state()
        if not site_policy.effective(state, site_policy.bridge_identities(), api.nodes(), require_client=False):
            raise RuntimeError("no currently approved subscription exits")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = Path("/root/deployment-backups") / ("proxy-site-quality-" + stamp)
        backup.mkdir(parents=True, mode=0o700)
        platforms = {}
        for name, spec in manifest.items():
            row = api.call("/api/v1/platforms/" + spec["id"])
            if row["name"] != name or row["region_filters"] != [spec["region"]]:
                raise RuntimeError("platform backup ownership mismatch")
            platforms[name] = {k: row[k] for k in ("id", "name", "region_filters", "regex_filters", "allocation_policy",
                                                 "passive_circuit_breaker_disabled")}
        site_policy.atomic_json(backup / "platforms.json", platforms)
        shutil.copy2(site_policy.STATE, backup / "site-approved.json")
        shutil.copytree("/var/lib/proxy-subscription", backup / "subscription")
        existed = site_policy.POLICY.exists()
        if existed:
            shutil.copy2(site_policy.POLICY, backup / "site-quality-policy.json")
        try:
            site_policy.atomic_json(site_policy.POLICY, {"version": 1, "mode": "strict"})
            result = qualify(state, api, manifest)
        except Exception:
            if existed:
                shutil.copy2(backup / "site-quality-policy.json", site_policy.POLICY)
            else:
                site_policy.POLICY.unlink(missing_ok=True)
            for row in platforms.values():
                api.call("/api/v1/platforms/" + row["id"], "PATCH",
                         {k: row[k] for k in ("regex_filters", "allocation_policy", "passive_circuit_breaker_disabled")})
            for source in (backup / "subscription").iterdir():
                if source.is_file():
                    shutil.copy2(source, Path("/var/lib/proxy-subscription") / source.name)
                    os.chown(Path("/var/lib/proxy-subscription") / source.name, 0, __import__("grp").getgrnam("www-data").gr_gid)
            raise
        result["backup"] = str(backup)
        print(json.dumps(result), flush=True)


def refresh_items(state, api):
    identities = site_policy.bridge_identities()
    live = {row["node_hash"]: row for row in api.nodes()}
    items, missing = [], []
    excluded = site_policy.quarantined_ips(state)
    excluded.update(row["expected_ip"] for row in state["approved"].values() if row.get("revoked"))
    for region, row in state["approved"].items():
        if row.get("revoked"):
            continue
        node = live.get(row["node_hash"])
        if (row["expected_ip"] not in excluded and identities.get(row["port"]) == row["slot_identity"] and node
                and REGIONS.eligible(node, region) and REGIONS.bridge_port(node) == row["port"]
                and node["egress_ip"] == row["expected_ip"]):
            items.append({key: row[key] for key in CLIENT.ITEM_FIELDS})
        else:
            missing.append(region)
            excluded.add(row["expected_ip"])
    if len(items) < 3:
        missing.extend(region for region in RECOVERY_REGIONS
                       if region not in state["approved"] and region not in missing)
    if missing:
        # Keep a bounded reserve search active even while one region is healthy.
        replacements = []
        if rotation_pool.enabled():
            verified = rotation_pool.effective(rotation_pool.load_state(), rotation_pool.load_slots(),
                                               identities, list(live.values()))
            for region in missing:
                candidate = next((row for row in verified.values() if row["region"] == region
                                  and row["expected_ip"] not in excluded), None)
                if candidate:
                    replacements.append({key: candidate[key] for key in CLIENT.ITEM_FIELDS})
        unresolved = [region for region in missing if not any(row["region"] == region for row in replacements)]
        if unresolved:
            replacements.extend(AUDIT.candidates(api, unresolved, 1, excluded))
        items.extend(replacements[:max(0, 3 - len(items))])
    return items


def update_bridge_state(state, items, report, identities):
    site_policy.record_failures(state, report)
    passing = site_policy.report_passes(report)
    checked_at = datetime.fromisoformat(report["started_at"]).timestamp()
    for item in items:
        previous = state["approved"].get(item["region"], {})
        if previous.get("revoked"):
            continue
        if any(previous.get(key) != item[key] for key in CLIENT.ITEM_FIELDS):
            # A replacement starts its own evidence streak; old passes never transfer.
            state["approved"][item["region"]] = dict(item, success_streak=0,
                checked_at=0, expires_at=0, validation_path="bridge")
    for row in state["approved"].values():
        if row.get("revoked"):
            continue
        key = tuple(row[field] for field in CLIENT.ITEM_FIELDS)
        if key in passing and identities.get(row["port"]) == row["slot_identity"]:
            # A bridge pass cannot extend an existing client approval.
            if not site_policy.valid_approval(row["region"], row, time.time()):
                row["success_streak"] += 1
                row["checked_at"] = checked_at
                row["expires_at"] = checked_at + site_policy.TTL_SECONDS
                row["validation_path"] = "bridge"
        elif not (site_policy.valid_approval(row["region"], row, time.time())
                  and row["expected_ip"] not in site_policy.quarantined_ips(state)
                  and identities.get(row["port"]) == row["slot_identity"]):
            row["success_streak"] = 0
            row["expires_at"] = 0


def refresh(audit_only=False, discover=False, reports=(), regions="us,hk,sg"):
    if not audit_only and rotation_pool.unified():
        print(json.dumps({"status": "skipped", "reason": "shared pool owns browser validation"}))
        return
    if not audit_only and not site_policy.strict_enabled():
        raise RuntimeError("strict subscription policy is not enabled")
    if not audit_only:
        with data_lock():
            pass
    with browser_lock():
        original = site_policy.load_state()
        fingerprint = json.dumps(original, sort_keys=True)
        items = [{k: row[k] for k in ("region", "port", "node_hash", "expected_ip", "slot_identity")}
                 for row in original["approved"].values() if not row.get("revoked")]
        if not audit_only:
            items = refresh_items(original, api_client())
        if audit_only and reports:
            prior = json.loads(Path(reports[-1]).read_text())
            excluded = site_policy.quarantined_ips(original)
            items = [{key: row[key] for key in CLIENT.ITEM_FIELDS} for row in prior["nodes"]
                     if row.get("passed") and row["region"] in regions.split(",") and row["expected_ip"] not in excluded]
        if discover:
            excluded = site_policy.quarantined_ips(original)
            excluded.update(row["expected_ip"] for row in original["approved"].values() if row.get("revoked"))
            items = AUDIT.candidates(api_client(), regions.split(","), 3, excluded)
        if not items:
            if not audit_only:
                enforce(publish=True)
            print(json.dumps({"status": "skipped", "reason": "no configured candidates"}), flush=True)
            return
        report, report_path = CLIENT.browser_check(items, timeout=600 if audit_only else 300)
        if audit_only:
            print(json.dumps({"report": str(report_path)}), flush=True)
            return
        with data_lock():
            if json.dumps(site_policy.load_state(), sort_keys=True) != fingerprint:
                raise RuntimeError("approval state changed during browser checks")
            update_bridge_state(original, items, report, site_policy.bridge_identities())
            original["last_report"] = str(report_path)
            result = qualify(original, api_client(), json.loads(MANIFEST.read_text()))
            print(json.dumps(result), flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    def terminate(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("seed", "activate", "enforce", "refresh", "audit", "discover", "revoke", "quarantine"))
    parser.add_argument("--report", action="append", default=[])
    parser.add_argument("--lock-held", action="store_true")
    parser.add_argument("--render", action="store_true")
    parser.add_argument("--wait-seconds", type=int, default=0)
    parser.add_argument("--region")
    parser.add_argument("--regions", default="us,hk,sg")
    args = parser.parse_args()
    WAIT_SECONDS = args.wait_seconds
    try:
        if args.mode == "seed":
            seed(args.report)
        elif args.mode == "activate":
            activate()
        elif args.mode == "enforce":
            enforce(args.lock_held, args.render)
        elif args.mode == "audit":
            refresh(audit_only=True, reports=args.report, regions=args.regions)
        elif args.mode == "discover":
            refresh(audit_only=True, discover=True, regions=args.regions)
        elif args.mode == "revoke":
            revoke(args.region)
        elif args.mode == "quarantine":
            quarantine(args.report)
        else:
            refresh()
    except PoolBusy:
        print(json.dumps({"status": "skipped", "reason": "pool maintenance active or queued"}))
    except Exception as exc:
        print(json.dumps(error_summary(exc)), file=sys.stderr)
        sys.exit(1)
