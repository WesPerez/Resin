"""Stable client identities for general connectivity and the strict site pool."""

import copy
import hashlib
import json
from pathlib import Path
import re
import time
import uuid

import site_policy

MANIFEST = Path("/etc/xray/client-pools.json")
STATUS = Path("/var/lib/proxy-region-latency/client-pools-status.json")
OWNER = "proxy-subscription-client-pools"
GENERAL_FILTER = ["^managed-apps-public-pool/"]
GENERAL = {"Global-Auto": None, **{region.upper() + "-General": region
                                for region in ("us", "hk", "sg", "jp", "de", "nl")}}
STRICT_NAME = "Sites-Verified"


def definitions():
    result = {}
    for name, region in GENERAL.items():
        suffix = region or "all"
        result[name] = {"kind": "general", "region": region,
                        "platform_name": "ClientGeneral" + suffix.upper(),
                        "email": "client-general-" + suffix}
    result[STRICT_NAME] = {"kind": "strict", "region": None,
                           "platform_name": "ClientSites", "email": "client-sites"}
    return result


def load(path=MANIFEST, complete=True):
    data = json.loads(path.read_text())
    expected = definitions()
    if data.get("owner") != OWNER or data.get("version") != 1:
        raise ValueError("invalid client pool ownership")
    entries = data.get("entries", {})
    if complete and set(entries) != set(expected):
        raise ValueError("incomplete client pool provisioning")
    ids, platforms = set(), set()
    for name, entry in entries.items():
        if (name not in expected or any(entry.get(key) != value for key, value in expected[name].items())
                or str(uuid.UUID(entry["uuid"])) != entry["uuid"] or entry["uuid"] in ids
                or not entry.get("platform_id") or entry["platform_id"] in platforms):
            raise ValueError("invalid client pool identity")
        ids.add(entry["uuid"])
        platforms.add(entry["platform_id"])
    return entries


def desired(entry, approved):
    strict = entry["kind"] == "strict"
    filters = sorted({pattern for row in approved.values() for pattern in site_policy.filters(row)})
    return {"regex_filters": (filters or site_policy.DENY) if strict else GENERAL_FILTER,
            "region_filters": [entry["region"]] if entry["region"] else [],
            "allocation_policy": "PREFER_LOW_LATENCY",
            "passive_circuit_breaker_disabled": strict}


def matches(platform, patch):
    # Resin serializes an empty region slice as JSON null. Both mean no region filter.
    return all((platform.get(key) or []) == value if key == "region_filters" else
               platform.get(key) == value for key, value in patch.items())


def enforce(api, approved, entries=None):
    entries = load() if entries is None else entries
    counts = {}
    for name, entry in sorted(entries.items(), key=lambda pair: pair[1]["kind"] != "strict"):
        endpoint = "/api/v1/platforms/" + entry["platform_id"]
        platform = api.call(endpoint)
        if platform["name"] != entry["platform_name"]:
            raise ValueError("client pool platform ownership mismatch")
        patch = desired(entry, approved)
        if not matches(platform, patch):
            platform = api.call(endpoint, "PATCH", patch)
        # Read back independently: an accepted PATCH is not proof of routing state.
        platform = api.call(endpoint)
        if (not matches(platform, patch)
                or entry["kind"] == "strict" and platform["routable_node_count"] != len(approved)):
            api.call(endpoint, "PATCH", {"regex_filters": site_policy.DENY})
            raise RuntimeError("client pool route verification failed")
        counts[name] = platform["routable_node_count"]
    identities = {name: [row.get(key) for key in ("port", "slot_identity", "expected_ip")]
                  for name, row in sorted(approved.items())}
    version = hashlib.sha256(json.dumps(identities, sort_keys=True).encode()).hexdigest()[:16]
    site_policy.atomic_json(STATUS, {"version": 1, "updated_at": time.time(),
                                   "strict_version": version, "strict_approved": sorted(approved),
                                   "routable": counts})
    return counts


def verify_routes(api, approved, entries):
    for entry in entries.values():
        platform = api.call("/api/v1/platforms/" + entry["platform_id"])
        if (platform["name"] != entry["platform_name"]
                or not matches(platform, desired(entry, approved))
                or entry["kind"] == "strict" and platform["routable_node_count"] != len(approved)):
            raise ValueError("published client pool does not match the approved routes")


def configure_xray(config, entries):
    config = copy.deepcopy(config)
    inbound = next(row for row in config["inbounds"] if row["tag"] == "proxy-ws")
    template = next(row for row in config["outbounds"] if row["tag"] == "resin-sg")
    for entry in entries.values():
        expected = {"id": entry["uuid"], "email": entry["email"]}
        clients = inbound["settings"]["clients"]
        present = [row for row in clients if row.get("email") == entry["email"] or row["id"] == entry["uuid"]]
        if present and present != [expected]:
            raise ValueError("client pool Xray identity conflict")
        if not present:
            clients.append(expected)
        outbound = copy.deepcopy(template)
        outbound["tag"] = entry["email"]
        # Resin V1 uses Platform.Account. Empty accounts route each connection
        # independently, which would change a browser's IP between page resources.
        outbound["settings"]["servers"][0]["users"][0]["user"] = entry["platform_name"] + ".profile"
        present = [row for row in config["outbounds"] if row["tag"] == outbound["tag"]]
        if present and present != [outbound]:
            raise ValueError("client pool Xray outbound conflict")
        if not present:
            config["outbounds"].append(outbound)
        rule = {"type": "field", "inboundTag": ["proxy-ws"], "user": [entry["email"]],
                "outboundTag": entry["email"]}
        present = [row for row in config["routing"]["rules"] if entry["email"] in row.get("user", [])]
        if present and present != [rule]:
            raise ValueError("client pool Xray routing conflict")
        if not present:
            config["routing"]["rules"].append(rule)
    return config


def verify_xray(config, entries):
    if configure_xray(config, entries) != config:
        raise ValueError("client pool Xray routes are not installed")


def render(config, entries, slots, approved):
    import rotation_pool
    result = copy.deepcopy(config)
    proxies = rotation_pool.proxy_entries(config, entries, list(entries))
    names = [name for name in slots if name in approved]
    proxies += rotation_pool.proxy_entries(config, slots, names)
    general = list(GENERAL)
    fast = rotation_pool.group("Auto-Fast", general, kind="url-test")
    fast.update(interval=60, tolerance=150, lazy=False)
    rotate = rotation_pool.group("Auto-Rotate", general, "sticky-sessions")
    rotate.update(interval=60, lazy=False)
    result.update({"proxies": proxies, "proxy-groups": [
        {"name": "PROXY", "type": "select", "proxies": ["Auto-Fast", "Auto-Rotate", *general]},
        fast, rotate,
        {"name": "Site-Strict", "type": "select", "proxies": [STRICT_NAME, *names]},
    ], "rules": [*[f"DOMAIN-SUFFIX,{domain},Site-Strict" for domain in rotation_pool.SITE_DOMAINS],
                 "MATCH,PROXY"], "find-process-mode": "off"})
    # The stable strict identity stays in cached profiles even when the pool is empty.
    # Server-side DENY then closes it; newly approved exits work without profile refresh.
    result.pop("listeners", None)
    result.pop("find-process", None)
    return result
