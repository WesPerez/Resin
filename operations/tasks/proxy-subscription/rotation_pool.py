"""Independent, expiring subscription exits with a shared browser quality gate."""

import copy
from datetime import datetime
import json
from pathlib import Path
import re
import time
import uuid

import site_policy


POLICY = Path("/etc/xray/rotation-policy.json")
SLOTS = Path("/etc/xray/rotation-slots.json")
AUDIT_SLOTS = Path("/etc/xray/rotation-audit-slots.json")
STATE = Path("/var/lib/proxy-region-latency/rotation-state.json")
TTL = site_policy.OPERATING['rotation_ttl_minutes'] * 60
QUALITY_TTL = site_policy.TTL_SECONDS
CAPACITY = {"us": 8, "hk": 4, "sg": 4, "jp": 4, "de": 2, "nl": 2}
SITE_DOMAINS = ("linux.do", "ldstatic.com", "agentrouter.org")


def enabled(path=POLICY):
    if not path.exists():
        return False
    if json.loads(path.read_text()) not in ({"version": 1, "mode": "balanced"}, {"version": 1, "mode": "unified"},
                                          {"version": 1, "mode": "split"}):
        raise ValueError("invalid rotation policy")
    return True


def unified(path=POLICY):
    return enabled(path) and json.loads(path.read_text())["mode"] in ("unified", "split")


def split_enabled(path=POLICY):
    return enabled(path) and json.loads(path.read_text())["mode"] == "split"


def site_qualified(name, row, now=None):
    now = time.time() if now is None else now
    quality = row.get("site_quality", {})
    if (quality.get("version") != 1 or quality.get("selected") != name
            or quality.get("identity") != [row.get(k) for k in IDENTITY_FIELDS]
            or not 0 <= now - quality.get("checked_at", 0) < QUALITY_TTL):
        return False
    reports = quality.get("reports", [])
    if len(reports) != 2 or reports[0] == reports[1]:
        return False
    key = tuple(row.get(k) for k in IDENTITY_FIELDS)
    try:
        previous_finish = None
        for index, path in enumerate(reports):
            evidence = json.loads(Path(path).read_text())
            if evidence.get("selected") != name or evidence.get("validation_path") != "subscription":
                return False
            roles = ("audit", "public") if index == 0 else ("public",)
            if evidence.get("route_role") not in roles:
                return False
            started = datetime.fromisoformat(evidence["started_at"]).timestamp()
            finished = datetime.fromisoformat(evidence["finished_at"]).timestamp()
            if previous_finish is not None and started < previous_finish:
                return False
            if key not in site_policy.report_passes(evidence, now, selected=name):
                return False
            previous_finish = finished
        return quality["checked_at"] == started
    except (OSError, ValueError, KeyError, TypeError):
        return False


IDENTITY_FIELDS = ("region", "port", "node_hash", "slot_identity", "expected_ip")


def load_slots(path=SLOTS):
    slots = json.loads(path.read_text())
    ids, platforms = set(), set()
    for name, row in slots.items():
        if (not re.fullmatch(r"[A-Z]{2}-[0-9]{2}", name) or name[:2].lower() != row["region"]
                or row["region"] not in CAPACITY or not 1 <= int(name[3:]) <= CAPACITY[row["region"]]
                or row["platform_name"] != "Browse" + name.replace("-", "")
                or row["email"] != "browse-" + name.lower()
                or str(uuid.UUID(row["uuid"])) != row["uuid"] or row["uuid"] in ids
                or not row["platform_id"] or row["platform_id"] in platforms):
            raise ValueError("invalid browsing slot ownership")
        ids.add(row["uuid"])
        platforms.add(row["platform_id"])
    return slots


def load_state():
    if not STATE.exists():
        return {"version": 1, "approved": {}, "failures": {}}
    state = json.loads(STATE.read_text())
    if state.get("version") != 1 or not isinstance(state.get("approved"), dict):
        raise ValueError("invalid rotation state")
    return state


def blocked_ips(state, now=None):
    blocked = site_policy.quarantined_ips(state, now)
    if site_policy.STATE.exists():
        blocked.update(site_policy.quarantined_ips(site_policy.load_state(), now))
    return blocked


def effective(state, slots, identities, nodes, now=None, staged=False, require_sites=None):
    now = time.time() if now is None else now
    result, seen = {}, set()
    require_sites = unified() if require_sites is None else require_sites
    blocked = blocked_ips(state, now) if require_sites else set()
    for name, row in state["approved"].items():
        if name not in slots or row.get("region") != slots[name]["region"] or row.get("passed") is not True:
            continue
        if not staged and row.get("validation_path") != "subscription":
            continue
        if not staged and require_sites and not site_qualified(name, row, now):
            continue
        if row.get("expected_ip") in blocked:
            continue
        lifetime = QUALITY_TTL if require_sites else TTL
        if not (0 <= now - row.get("checked_at", 0) < lifetime):
            continue
        identity = {"approved": {row["region"]: dict(row, success_streak=2,
                    expires_at=row["checked_at"] + lifetime, validation_path="subscription")}}
        if not site_policy.effective(identity, identities, nodes, now):
            continue
        if row["expected_ip"] in seen:
            continue
        seen.add(row["expected_ip"])
        result[name] = row
    return result


def enforce(api, state=None, slots=None, staged=False):
    slots = load_slots() if slots is None else slots
    try:
        state = load_state() if state is None else state
        approved = effective(state, slots, site_policy.bridge_identities(), api.nodes(), staged=staged)
    except (OSError, ValueError, KeyError, TypeError):
        approved = {}
    for name, slot in slots.items():
        endpoint = "/api/v1/platforms/" + slot["platform_id"]
        platform = api.call(endpoint)
        if platform["name"] != slot["platform_name"] or platform["region_filters"] != [slot["region"]]:
            raise ValueError("browsing platform ownership mismatch")
        patch = {"regex_filters": site_policy.filters(approved[name]) if name in approved else site_policy.DENY,
                 "allocation_policy": "PREFER_LOW_LATENCY", "passive_circuit_breaker_disabled": True}
        if any(platform.get(key) != value for key, value in patch.items()):
            platform = api.call(endpoint, "PATCH", patch)
        expected = 1 if name in approved else 0
        if (any(platform.get(key) != value for key, value in patch.items())
                or platform["routable_node_count"] != expected):
            api.call(endpoint, "PATCH", {"regex_filters": site_policy.DENY})
            approved.pop(name, None)
    if split_enabled():
        import client_pools
        client_pools.enforce(api, approved)
    return approved


def proxy_entries(config, slots, names):
    template = next(p for p in config["proxies"] if p["name"] == "weesai.com-vless-443-ws")
    result = []
    for name in names:
        row = copy.deepcopy(template)
        row.update(name=name, uuid=slots[name]["uuid"], udp=False)
        result.append(row)
    return result


def group(name, members, strategy="sticky-sessions", kind="load-balance"):
    value = {"name": name, "type": kind, "proxies": members, "url": "https://www.gstatic.com/generate_204",
             "interval": 180, "timeout": 6000, "lazy": True, "expected-status": 204}
    if kind == "load-balance":
        value["strategy"] = strategy
    return value


def render(config, stable, slots, approved):
    if split_enabled():
        import client_pools
        return client_pools.render(config, client_pools.load(), slots, approved)
    if unified():
        return render_simple(config, slots, approved)
    config = copy.deepcopy(config)
    names = [name for name in slots if name in approved]
    stable_proxies = stable["proxies"]
    stable_names = [p["name"] for p in stable_proxies]
    config["proxies"] = proxy_entries(config, slots, names) + stable_proxies
    groups = []
    if names:
        groups += [group("Auto-Fast", names), group("Auto-Rotate", names, "round-robin")]
        for region in CAPACITY:
            members = [name for name in names if name[:2].lower() == region]
            if members:
                groups.append(group(region.upper() + "-Pool", members))
    groups.append({"name": "PROXY", "type": "select",
                   "proxies": ["Auto-Fast", "Auto-Rotate",
                               *[r.upper() + "-Pool" for r in CAPACITY
                                 if any(n[:2].lower() == r for n in names)], *names] if names else ["REJECT"]})
    if stable_names:
        groups.append(group("Sites-Auto", stable_names, kind="fallback"))
    groups.append({"name": "Site-Stable", "type": "select",
                   "proxies": ["Sites-Auto", *stable_names] if stable_names else ["REJECT"]})
    # Separate pools avoid browsers randomly sharing an exit. Sites stay on their verified routes.
    rules = [f"DOMAIN-SUFFIX,{domain},Site-Stable" for domain in SITE_DOMAINS]
    listeners = []
    programs = ("msedge.exe", "chrome.exe", "firefox.exe", "brave.exe")
    for index in range(min(4, len(names))):
        browser = "Browser-" + str(index + 1)
        members = names[index::4]
        pool_name = browser + "-Auto"
        groups.append(group(pool_name, members))
        groups.append({"name": browser, "type": "select", "proxies": ["PROXY", pool_name]})
        listeners.append({"name": browser.lower(), "type": "mixed", "listen": "127.0.0.1",
                          "port": 17891 + index})
        rules.append(f"IN-NAME,{browser.lower()},{pool_name}")
        rules.append(f"PROCESS-NAME,{programs[index]},{browser}")
    rules.append("MATCH,PROXY")
    config.update({"proxy-groups": groups, "rules": rules, "listeners": listeners,
                   "find-process-mode": "strict"})
    config.pop("find-process", None)
    return config


def render_simple(config, slots, approved):
    config = copy.deepcopy(config)
    names = [name for name in slots if name in approved]
    config["proxies"] = proxy_entries(config, slots, names)
    members = names or ["REJECT"]
    fast = group("Auto-Fast", members, kind="url-test")
    fast.update(tolerance=150, interval=300)
    config["proxy-groups"] = [
        {"name": "PROXY", "type": "select", "proxies": ["Auto-Fast", "Auto-Rotate", *names]},
        fast, group("Auto-Rotate", members, "sticky-sessions")]
    config["rules"] = ["MATCH,PROXY"]
    config.pop("listeners", None)
    config.pop("find-process", None)
    config["find-process-mode"] = "off"
    return config


def published(api):
    slots = load_slots()
    config = json.loads(Path("/etc/xray/proxy.json").read_text())
    clients = next(row for row in config["inbounds"] if row["tag"] == "proxy-ws")["settings"]["clients"]
    outbounds = {row["tag"]: row for row in config["outbounds"]}
    for slot in slots.values():
        expected = {"id": slot["uuid"], "email": slot["email"]}
        outbound = outbounds.get(slot["email"], {})
        rule = {"type": "field", "inboundTag": ["proxy-ws"], "user": [slot["email"]],
                "outboundTag": slot["email"]}
        if ([row for row in clients if row.get("email") == slot["email"] or row["id"] == slot["uuid"]] != [expected]
                or outbound.get("protocol") != "socks" or rule not in config["routing"]["rules"]
                or outbound["settings"]["servers"][0]["users"][0]["user"] != slot["platform_name"]):
            raise ValueError("published browsing identity does not match Xray")
    approved = effective(load_state(), slots, site_policy.bridge_identities(), api.nodes())
    for name in list(approved):
        platform = api.call("/api/v1/platforms/" + slots[name]["platform_id"])
        if (platform["name"] != slots[name]["platform_name"]
                or platform["region_filters"] != [slots[name]["region"]]
                or platform["regex_filters"] != site_policy.filters(approved[name])
                or platform.get("passive_circuit_breaker_disabled") is not True
                or platform["routable_node_count"] != 1):
            approved.pop(name)
    if split_enabled():
        import client_pools
        entries = client_pools.load()
        client_pools.verify_xray(config, entries)
        client_pools.verify_routes(api, approved, entries)
    return slots, approved
