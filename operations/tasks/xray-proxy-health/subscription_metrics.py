#!/usr/bin/env python3
"""Read bounded, credential-free subscription status for the minute health sample."""

from datetime import datetime
import json
import math
from pathlib import Path
import time

PATHS = {
    "policy": Path("/etc/xray/rotation-policy.json"),
    "client": Path("/var/lib/proxy-region-latency/client-health.json"),
    "pools": Path("/var/lib/proxy-region-latency/client-pools-status.json"),
    "bridge": Path("/var/lib/resin-singbox-bridge/runtime.json"),
    "maintenance": Path("/var/lib/resin-pool-maintainer/last-unified-run.json"),
}


def read_status(path):
    try:
        with path.open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            return {}, "oversized"
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("version") != 1:
            return {}, "invalid"
        return value, "ok"
    except FileNotFoundError:
        return {}, "missing"
    except (OSError, ValueError):
        return {}, "unreadable_or_invalid"


def age_seconds(value, now):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return round(now - value)


def boolean(value):
    return value if type(value) is bool else None


def nonnegative_integer(value):
    return value if type(value) is int and value >= 0 else None


def collect(paths=PATHS, now=None):
    now = time.time() if now is None else now
    result = {"version": 1, "enabled": False, "alerts": []}

    def alert(code, level="warn"):
        result["alerts"].append({"code": code, "level": level})

    def section(name, field, max_age, required=True):
        data, status = read_status(paths[name])
        age = age_seconds(data.get(field), now)
        result[name] = {"status": status, "age_seconds": age}
        if status != "ok":
            if required or status != "missing":
                alert("subscription_" + name + "_" + status)
        elif age is None or age < -60 or age > max_age:
            result[name]["status"] = "stale_or_invalid_time"
            alert("subscription_" + name + "_stale")
        return data

    policy, policy_status = read_status(paths["policy"])
    if policy_status not in ("ok", "missing"):
        alert("subscription_policy_" + policy_status)
    elif policy_status == "ok" and policy.get("mode") not in ("balanced", "unified", "split"):
        alert("subscription_policy_invalid_mode")
    result["enabled"] = policy.get("mode") == "split"
    if result["enabled"]:
        client = section("client", "finished_at", 900)
        for name in ("general", "strict"):
            check = client.get(name)
            result["client"][name + "_passed"] = boolean(check.get("passed")) if isinstance(check, dict) else None
        result["client"]["inconclusive"] = boolean(client.get("inconclusive"))
        download = client.get("subscription")
        result["client"]["subscription_passed"] = boolean(download.get("passed")) if isinstance(download, dict) else None
        strict = client.get("strict")
        waiting = (isinstance(strict, dict) and strict.get("reason") == "strict_pool_empty"
                   and strict.get("passed") is False
                   and result["client"]["general_passed"] is True
                   and result["client"]["subscription_passed"] is True
                   and client.get("inconclusive") is False)
        result["client"]["strict_status"] = ("waiting_for_qualified_exit" if waiting
            else "passed" if result["client"]["strict_passed"] is True else "unverified")
        if result["client"]["status"] == "ok":
            if result["client"]["subscription_passed"] is not True:
                alert("subscription_download_probe_failed", "crit")
            if client.get("inconclusive"):
                alert("subscription_client_inconclusive")
            elif result["client"]["general_passed"] is not True:
                alert("subscription_general_probe_failed", "crit")
            elif result["client"]["strict_passed"] is not True and not waiting:
                alert("subscription_strict_probe_failed")
        pools = section("pools", "updated_at", 1800)
        routable = pools.get("routable") if isinstance(pools.get("routable"), dict) else {}
        for name, key in (("Global-Auto", "general_count"), ("Sites-Verified", "strict_count")):
            count = routable.get(name)
            count = nonnegative_integer(count)
            result["pools"][key] = count
            if count is None:
                alert("subscription_" + key + "_unknown")
            elif count == 0:
                alert("subscription_" + key + "_empty", "crit" if key == "general_count" else "warn")

    bridge = section("bridge", "updated_at", 120, required=result["enabled"])
    if result["bridge"]["status"] == "ok":
        instances = bridge.get("instances")
        instances = instances if isinstance(instances, dict) else {}
        result["bridge"].update(instances=len(instances), capacity=nonnegative_integer(bridge.get("capacity")),
                                 switches=nonnegative_integer(bridge.get("switches")),
                                 draining=sum(isinstance(row, dict) and row.get("draining_since") is not None
                                              for row in instances.values()))
        if bridge.get("active_generation") not in instances or not bridge.get("frontend_pid"):
            alert("subscription_bridge_unavailable", "crit")
        capacity = bridge.get("capacity")
        # Occupied generations preserve existing TCP sessions; capacity alone
        # does not mean the active proxy has failed. Availability is checked above.
        result["bridge"]["waiting_for_connections"] = (type(capacity) is int and capacity > 0
                                                        and len(instances) >= capacity)

    maintenance = section("maintenance", "last_run_finished_at", 3 * 3600, required=result["enabled"])
    if result["maintenance"]["status"] in ("ok", "stale_or_invalid_time"):
        for name in ("global", "cn"):
            status = maintenance.get(name + "_status")
            # Do not copy arbitrary upstream strings into logs.
            status = status if status in ("success", "failed", "primary_failed", "skipped", "deferred", "not_due") else "unknown"
            result["maintenance"][name] = status
            if status in ("failed", "primary_failed", "unknown"):
                alert("subscription_" + name + "_maintenance_" + status)
    return result


if __name__ == "__main__":
    print(json.dumps(collect(), sort_keys=True))
