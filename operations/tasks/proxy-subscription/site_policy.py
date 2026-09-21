"""Strict, expiring browser-audited routing for the public subscription only."""

from datetime import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
import time
from operating_settings import load as load_operating_settings


POLICY = Path("/etc/xray/site-quality-policy.json")
STATE = Path("/var/lib/proxy-region-latency/site-approved.json")
BRIDGE = Path("/var/lib/resin-singbox-bridge/current/bridge.json")
TARGETS = {"linux.do": "https://linux.do/", "agentrouter.org": "https://agentrouter.org/console/log",
           "agentrouter.org/register": "https://agentrouter.org/register"}
OPERATING = load_operating_settings()
TTL_SECONDS = OPERATING['site_ttl_minutes'] * 60
QUARANTINE_SECONDS = OPERATING['challenge_quarantine_hours'] * 60 * 60
NETWORK_COOLDOWN_SECONDS = OPERATING['network_cooldown_minutes'] * 60
MAX_LOAD_MS = OPERATING['max_page_load_ms']
DENY = ["^$"]


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=".site-", delete=False) as handle:
            temporary = Path(handle.name)
            os.fchmod(handle.fileno(), 0o600)
            json.dump(value, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def bridge_identities(path=BRIDGE):
    config = json.loads(Path(path).read_text())
    outbounds = {row["tag"]: row for row in config["outbounds"]}
    routes = {tag: row.get("outbound") for row in config["route"]["rules"]
              for tag in row.get("inbound", []) if row.get("action") == "route"}
    result = {}
    for row in config["inbounds"]:
        port = row.get("listen_port", 0)
        if row.get("listen") != "172.17.0.1" or row.get("type") != "socks" or not 12000 <= port <= 13000 or port == 12400:
            continue
        outbound = outbounds.get(routes.get(row["tag"]))
        if outbound:
            result[port] = hashlib.sha256(json.dumps(outbound, sort_keys=True).encode()).hexdigest()
    return result


def strict_enabled(path=POLICY):
    if not Path(path).exists():
        return False
    if json.loads(Path(path).read_text()) != {"version": 1, "mode": "strict"}:
        raise ValueError("invalid strict site policy")
    return True


def load_state(path=STATE):
    row = json.loads(Path(path).read_text())
    if row.get("version") != 1 or not isinstance(row.get("approved"), dict):
        raise ValueError("invalid site approval state")
    return row


def valid_approval(region, row, now, require_client=True):
    try:
        return (re.fullmatch(r"[a-z]{2}", region) is not None
                and row["region"] == region and region != "cn" and not row.get("revoked")
                and (not require_client or row.get("validation_path") == "subscription")
                and 12000 <= row["port"] <= 13000 and row["port"] != 12400
                and re.fullmatch(r"[0-9a-f]{32}", row["node_hash"]) is not None
                and re.fullmatch(r"[0-9a-f]{64}", row["slot_identity"]) is not None
                and ipaddress.ip_address(row["expected_ip"]).is_global
                and row["success_streak"] >= 2
                and now - TTL_SECONDS <= row["checked_at"] <= now + 60
                and row["checked_at"] < row["expires_at"] <= row["checked_at"] + TTL_SECONDS
                and row["expires_at"] > now)
    except (KeyError, TypeError, ValueError):
        return False


def effective(state, identities, nodes=None, now=None, require_client=True):
    now = time.time() if now is None else now
    live = {n["node_hash"]: n for n in nodes} if nodes is not None else None
    excluded = quarantined_ips(state, now)
    result = {}
    for region, row in state["approved"].items():
        if (not valid_approval(region, row, now, require_client)
                or identities.get(row["port"]) != row["slot_identity"] or row["expected_ip"] in excluded):
            continue
        if live is not None:
            node = live.get(row["node_hash"])
            tag = "managed-apps-public-pool/socks-172.17.0.1:" + str(row["port"])
            if (node is None or not node.get("enabled") or not node.get("has_outbound")
                    or node.get("circuit_open_since") is not None
                    or node.get("region") != region or node.get("egress_ip") != row["expected_ip"]
                    or not any(t.get("tag") == tag and t.get("subscription_name") == "managed-apps-public-pool"
                               for t in node.get("tags", []))):
                continue
        result[region] = row
    return result


def quarantined_ips(state, now=None):
    now = time.time() if now is None else now
    return {ip for ip, row in state.get("quarantined", {}).items() if row["until"] > now}


def record_failures(state, report, now=None):
    now = time.time() if now is None else now
    finished = datetime.fromisoformat(report["finished_at"]).timestamp()
    if not now - QUARANTINE_SECONDS <= finished <= now + 60:
        raise ValueError("failure evidence expired or future-dated")
    passing = report_passes(report, now=finished, selected=report.get("selected"))
    excluded = state.setdefault("quarantined", {})
    transients = state.setdefault("transient_failures", {})
    scope = report.get("validation_path", "bridge")
    for row in report["nodes"]:
        if not isinstance(row.get("port"), int) or not 12000 <= row["port"] <= 13000 or row["port"] == 12400:
            continue
        key = tuple(row[field] for field in ("region", "port", "node_hash", "slot_identity", "expected_ip"))
        failure_key = scope + ":" + row["expected_ip"]
        if key in passing:
            if transients.get(failure_key, {}).get("checked_at", 0) <= finished:
                transients.pop(failure_key, None)
            if scope == "subscription":
                bridge_key = "bridge:" + row["expected_ip"]
                if transients.get(bridge_key, {}).get("checked_at", 0) <= finished:
                    transients.pop(bridge_key, None)
            continue
        sites = {host: site.get("verdict", "unknown") for host, site in row["sites"].items()}
        traces = [row.get("before"), row.get("after")]
        for site in row["sites"].values():
            traces.extend([site.get("browser_trace_before"), site.get("browser_trace_after")])
        ips = {str(ipaddress.ip_address(row["expected_ip"]))}
        ips.update(str(ipaddress.ip_address(trace["ip"])) for trace in traces if trace)
        challenge = "challenge" in sites.values()
        if not challenge and len(ips) == 1:
            prior = transients.get(failure_key, {})
            if prior.get("checked_at", 0) > finished:
                continue
            count = prior.get("count", 0) if 0 <= finished - prior.get("checked_at", 0) < TTL_SECONDS else 0
            if prior.get("checked_at") != finished:
                count += 1
            transients[failure_key] = {"count": count, "checked_at": finished, "sites": sites}
            if count < 2:
                continue
        for ip in ips:
            previous = excluded.get(ip, {})
            prior_challenge = previous.get("last_challenge_at", 0)
            repeated = challenge and 0 < finished - prior_challenge < QUARANTINE_SECONDS
            duration = QUARANTINE_SECONDS if repeated or len(ips) > 1 else NETWORK_COOLDOWN_SECONDS
            if finished + duration <= now:
                continue
            if previous.get("until", 0) >= finished + duration:
                continue
            excluded[ip] = {"until": finished + duration, "checked_at": finished,
                            "last_challenge_at": finished if challenge else prior_challenge,
                            "validation_path": report.get("validation_path", "bridge"),
                            "identity_valid": row.get("identity_valid", False), "sites": sites,
                            "reason": "ip_rotation" if len(ips) > 1 else "challenge" if challenge else "transient"}
    blocked = quarantined_ips(state, now)
    for row in state["approved"].values():
        if row["expected_ip"] in blocked:
            row.update(success_streak=0, expires_at=0, validation_path="bridge")


def filters(row):
    return ["^" + re.escape("managed-apps-public-pool/socks-172.17.0.1:" + str(row["port"])) + "$"]


def enforce(api, manifest, state=None, identities=None, now=None, require_client=True):
    state_error = False
    if state is None:
        try:
            state = load_state()
        except (OSError, ValueError, TypeError):
            state = {"approved": {}}
            state_error = True
    if identities is None:
        try:
            identities = bridge_identities()
        except (OSError, ValueError, KeyError, TypeError):
            identities = {}
            state_error = True
    approved = effective(state, identities, api.nodes(), now, require_client)
    updated = []
    for name, spec in manifest.items():
        region = spec["region"]
        if name != "Proxy" + region.upper() or not re.fullmatch(r"[a-z]{2}", region):
            raise ValueError("invalid subscription platform manifest")
        endpoint = "/api/v1/platforms/" + spec["id"]
        current = api.call(endpoint)
        if current["name"] != name or current["region_filters"] != [region]:
            raise ValueError("subscription platform ownership mismatch")
        row = approved.get(region)
        patch = {"regex_filters": filters(row) if row else DENY,
                 "allocation_policy": "PREFER_LOW_LATENCY",
                 # A destination failure must not disable the only browsing exit.
                 "passive_circuit_breaker_disabled": True}
        if any(current.get(key) != value for key, value in patch.items()):
            current = api.call(endpoint, "PATCH", patch)
            if any(current.get(key) != value for key, value in patch.items()):
                raise RuntimeError("strict platform verification failed")
            updated.append(region)
        if current["routable_node_count"] > (1 if row else 0):
            api.call(endpoint, "PATCH", {"regex_filters": DENY})
            raise RuntimeError("strict platform has unexpected routes")
        if row and current["routable_node_count"] == 0:
            approved.pop(region, None)
            api.call(endpoint, "PATCH", {"regex_filters": DENY})
    return {"status": "strict", "approved_regions": sorted(approved), "updated": updated,
            "state_error": state_error}


def report_passes(report, now=None, selected=None):
    now = time.time() if now is None else now
    if report.get("targets") != TARGETS or report.get("headed") is not True:
        raise ValueError("browser audit scope mismatch")
    client_report = report.get("validation_path") == "subscription"
    if client_report and report.get("client") != "Mihomo":
        raise ValueError("subscription audit client mismatch")
    if client_report and report.get("dns_enabled") is not True:
        raise ValueError("subscription audit must preserve DNS configuration")
    started = datetime.fromisoformat(report["started_at"]).timestamp()
    finished = datetime.fromisoformat(report["finished_at"]).timestamp()
    if not now - TTL_SECONDS <= started <= finished <= now + 60:
        raise ValueError("browser audit expired or incomplete")
    result = {}
    for row in report["nodes"]:
        if not row.get("port") or not row.get("passed") or not row.get("identity_valid"):
            continue
        if client_report and (row.get("proxy_host") != "127.0.0.1"
                or not isinstance(row.get("proxy_port"), int) or not 1 <= row["proxy_port"] <= 65535
                or row["proxy_port"] == row["port"]
                or row.get("selected") != (selected or row["region"].upper() + "-Auto")):
            continue
        before = {"ip": row["expected_ip"], "region": row["region"]}
        if row.get("before") != before or row.get("after") != before or set(row["sites"]) != set(TARGETS):
            continue
        good = True
        for host, site in row["sites"].items():
            expected = ("normal" if host == "linux.do" else "register_no_challenge"
                        if host == "agentrouter.org/register" else "login_no_challenge")
            if (site.get("verdict") != expected or site.get("http_status") != 200
                    or site.get("browser_trace_before") != before or site.get("browser_trace_after") != before
                    or site.get("challenge_widgets") != 0 or site.get("load_ms") is None
                    or site.get("critical_failures") != [] or site.get("critical_pending") != 0
                    or site.get("content_ready", site.get("document_complete")) is not True
                    or site["load_ms"] > MAX_LOAD_MS):
                good = False
        if good:
            result[(row["region"], row["port"], row["node_hash"], row["slot_identity"], row["expected_ip"])] = row
    return result


def approve_reports(reports, now=None):
    now = time.time() if now is None else now
    if len(reports) < 2:
        raise ValueError("two separate browser audit rounds required")
    if len({r["started_at"] for r in reports}) != len(reports):
        raise ValueError("duplicate browser audit round")
    reports = sorted(reports, key=lambda r: r["started_at"])
    for previous, current in zip(reports, reports[1:]):
        if datetime.fromisoformat(current["started_at"]) < datetime.fromisoformat(previous["finished_at"]):
            raise ValueError("browser audit rounds must not overlap")
    matching = report_passes(reports[0], now)
    for report in reports[1:]:
        latest = report_passes(report, now)
        matching = {key: latest[key] for key in matching.keys() & latest.keys()}
    approved = {}
    for key, row in sorted(matching.items()):
        region = row["region"]
        candidate = {k: row[k] for k in ("region", "port", "node_hash", "slot_identity", "expected_ip")}
        checked_at = datetime.fromisoformat(reports[-1]["started_at"]).timestamp()
        candidate.update(checked_at=checked_at, expires_at=checked_at + TTL_SECONDS,
                         success_streak=len(reports), validation_path=("subscription" if all(
                             report.get("validation_path") == "subscription" for report in reports) else "bridge"))
        if valid_approval(region, candidate, now, require_client=False):
            approved.setdefault(region, candidate)
    if not approved:
        raise ValueError("no repeatedly verified subscription exits")
    return {"version": 1, "approved": approved}
