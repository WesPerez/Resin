"""Qualify every shared-pool exit through both sites on its actual subscription route."""

import copy
from datetime import datetime
import json
import ipaddress
from pathlib import Path
import re
import shutil
import time

import rotation_pool as POOL
import site_policy


def key(row):
    return ":".join(str(row[k]) for k in POOL.IDENTITY_FIELDS)


def prune_evidence(state, state_dir=Path("/var/lib/proxy-region-latency"),
                   browser_dir=Path("/var/lib/proxy-site-browser"), now=None):
    """Caller holds both locks; retain referenced reports and their browser artifacts."""
    cutoff = (time.time() if now is None else now) - 48 * 3600
    roots = (state_dir, browser_dir)
    retained = set()

    def references(value):
        if isinstance(value, dict):
            for child in value.values():
                references(child)
        elif isinstance(value, list):
            for child in value:
                references(child)
        elif isinstance(value, str) and value.startswith("/"):
            path = Path(value)
            if any(path.is_relative_to(root) for root in roots):
                retained.add(path)

    references(state)
    pending = list(retained)
    visited = set()
    while pending:
        path = pending.pop()
        if path in visited:
            continue
        visited.add(path)
        if path.suffix == ".json" and path.is_file() and not path.is_symlink():
            references(json.loads(path.read_text()))
            pending.extend(retained - visited)

    patterns = (
        (state_dir, r"(?:unified-client-\d+\.json|rotation-client-\d+\.log|rotation-acceptance-\d+\.json)"),
        (browser_dir, r"(?:unified-site|shared-acceptance|rotate-acceptance)-\d+"),
    )
    removed = 0
    for root, pattern in patterns:
        for path in root.iterdir():
            if (not re.fullmatch(pattern, path.name) or path.is_symlink()
                    or path.stat().st_mtime >= cutoff
                    or any(ref == path or ref.is_relative_to(path) for ref in retained)):
                continue
            if path.is_dir():
                children = list(path.rglob("*"))
                if any(child.is_symlink() or child.stat().st_mtime >= cutoff for child in children):
                    continue
                shutil.rmtree(path)
            elif path.is_file():
                path.unlink()
            else:
                continue
            removed += 1
    return removed


def browser_round(rotation, config, name, row, route_role="public"):
    with rotation.client(config) as (proxy, call):
        call("/proxies/PROXY", {"name": name})
        selected_before = call("/proxies/PROXY")["now"]
        item = {field: row[field] for field in POOL.IDENTITY_FIELDS}
        item.update(proxy_host="127.0.0.1", proxy_port=int(proxy.rsplit(":", 1)[1]))
        report, raw = rotation.CONTROL.CLIENT.browser_check([item], "unified-site", timeout=120)
        report.update(validation_path="subscription", client="Mihomo",
                      dns_enabled=config.get("dns", {}).get("enable") is True,
                      selected=name, raw_report=str(raw), route_role=route_role)
        report["nodes"][0]["selected"] = call("/proxies/PROXY")["now"]
        if (selected_before != name or report["nodes"][0]["selected"] != name
                or site_policy.bridge_identities().get(row["port"]) != row["slot_identity"]):
            report["nodes"][0].update(passed=False, identity_valid=False)
        path = Path("/var/lib/proxy-region-latency") / ("unified-client-" + str(time.time_ns()) + ".json")
        site_policy.atomic_json(path, report)
        return report, path


def patch_route(api, slot, candidate=None):
    endpoint = "/api/v1/platforms/" + slot["platform_id"]
    platform = api.call(endpoint)
    if platform["name"] != slot["platform_name"] or platform["region_filters"] != [slot["region"]]:
        raise ValueError("candidate platform ownership mismatch")
    patch = {"regex_filters": site_policy.filters(candidate) if candidate else site_policy.DENY,
             "allocation_policy": "PREFER_LOW_LATENCY", "passive_circuit_breaker_disabled": True}
    if any(platform.get(k) != v for k, v in patch.items()):
        platform = api.call(endpoint, "PATCH", patch)
    if (any(platform.get(k) != v for k, v in patch.items())
            or platform.get("routable_node_count") != (1 if candidate else 0)):
        api.call(endpoint, "PATCH", {"regex_filters": site_policy.DENY})
        raise RuntimeError("audit route did not bind exactly one candidate")


def close_audits(api):
    if POOL.AUDIT_SLOTS.exists():
        for slot in json.loads(POOL.AUDIT_SLOTS.read_text()).values():
            patch_route(api, slot)


def qualify(rotation, slots, name, candidate, api):
    """Use an unpublished identity until both browser rounds pass."""
    audit = json.loads(POOL.AUDIT_SLOTS.read_text())[candidate["region"]]
    config = rotation.CONTROL.CLIENT.subscription_config(staged=True)
    base = config
    prior = POOL.load_state()["approved"].get(name, {})
    renewal = prior and key(prior) == key(candidate) and POOL.site_qualified(name, prior)
    testing = slots[name] if renewal else audit
    patch_route(api, testing, candidate)
    config = POOL.render_simple(base, {name: testing}, {name: candidate})
    paths, reports = [], []
    for _ in range(2):
        report, path = browser_round(rotation, config, name, candidate, "public" if renewal else "audit")
        reports.append(report)
        paths.append(str(path))
        passed = tuple(candidate[k] for k in POOL.IDENTITY_FIELDS) in site_policy.report_passes(report, selected=name)
        print(json.dumps({"slot": name, "round": len(reports), "passed": passed,
                          "sites": {h: s["verdict"] for h, s in report["nodes"][0]["sites"].items()},
                          "report": str(path)}), flush=True)
        if not passed:
            return None, reports
    # Only a twice-verified exit may replace the public slot. Check its real UUID too.
    if not renewal:
        patch_route(api, slots[name], candidate)
        report, path = browser_round(rotation, POOL.render_simple(base, slots, {name: candidate}), name, candidate)
        reports.append(report)
        paths.append(str(path))
        if tuple(candidate[k] for k in POOL.IDENTITY_FIELDS) not in site_policy.report_passes(report, selected=name):
            return None, reports
    checked = datetime.fromisoformat(reports[-1]["started_at"]).timestamp()
    row = dict(candidate, validation_path="subscription", passed=True)
    row["site_quality"] = {"version": 1, "selected": name,
                           "identity": [row[k] for k in POOL.IDENTITY_FIELDS],
                           "checked_at": checked, "reports": paths[-2:]}
    row["checked_at"] = checked
    return row, reports


def prior_passes(row, failures, now=None):
    now = time.time() if now is None else now
    failure = failures.get(key(row), {})
    paths = failure.get("reports", [])
    paths = row.get("site_quality", {}).get("reports", paths)
    count = 0
    for path in paths:
        if not path:
            continue
        try:
            report = json.loads(Path(path).read_text())
            finished = datetime.fromisoformat(report["finished_at"]).timestamp()
            if not max(now - POOL.QUALITY_TTL, failure.get("checked_at", 0)) <= finished <= now:
                continue
            count += any(node.get("passed") and node.get("identity_valid") and key(node) == key(row)
                         for node in report["nodes"])
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return count


def schedule_candidates(ordered, verified, now):
    hard_urgent, urgent, renewals, additions = [], [], [], []
    for pair in ordered:
        row = verified.get(pair[0])
        if row is None:
            additions.append(pair)
        elif now - row["site_quality"]["checked_at"] >= POOL.QUALITY_TTL - 15 * 60:
            hard_urgent.append(pair)
        elif now - row["site_quality"]["checked_at"] >= POOL.QUALITY_TTL - 30 * 60:
            urgent.append(pair)
        else:
            renewals.append(pair)
    # New exits need 390 seconds of budget, so tail-only scheduling starves them.
    planned = hard_urgent + additions[:2] + urgent
    del additions[:2]
    while renewals or additions:
        planned.extend(renewals[:2])
        del renewals[:2]
        planned.extend(additions[:1])
        del additions[:1]
    return planned


def region_gain(pair, verified):
    region = pair[1]["region"]
    filled = sum(row.get("region") == region for row in verified.values())
    return max(0, POOL.CAPACITY.get(region, 0) - filled)


def candidates(rotation, slots, state, api):
    identities, live = site_policy.bridge_identities(), api.nodes()
    current = POOL.effective(state, slots, identities, live, require_sites=False)
    verified = POOL.effective(state, slots, identities, live, require_sites=True)
    failures = state.get("site_failures", {})
    now = time.time()
    blocked = POOL.blocked_ips(state, now)
    used = {row["expected_ip"] for row in verified.values()}
    output = []
    scores = {}
    strict = site_policy.effective(site_policy.load_state(), identities, live)
    region_nodes = {
        region: sorted((node for node in live if rotation.CONTROL.REGIONS.eligible(node, region)),
                       key=lambda node: (node.get("failure_count", 0),
                                         rotation.CONTROL.REGIONS.reference_score(node), node["node_hash"]))
        for region in {slot["region"] for slot in slots.values()}
    }
    for name, slot in slots.items():
        row = verified.get(name)
        if row is not None:
            # Recheck before expiry, without renewing browser evidence from curl alone.
            if now - row["site_quality"]["checked_at"] > 30 * 60:
                output.append((name, row))
            continue
        choices = []
        if slot["region"] in strict:
            choices.append(strict[slot["region"]])
        if name in current:
            choices.append(current[name])
        # Score every route before IP deduplication, so a faster alias cannot hide browser evidence.
        for node in region_nodes[slot["region"]]:
            port = rotation.CONTROL.REGIONS.bridge_port(node)
            if port in identities:
                choices.append({"region": slot["region"], "port": port, "node_hash": node["node_hash"],
                                "slot_identity": identities[port], "expected_ip": node["egress_ip"]})
        for row in choices:
            identity = key(row)
            if identity not in scores:
                scores[identity] = prior_passes(row, failures, now)
        choices.sort(key=lambda row: (-scores[key(row)], key(row) in failures,
                     failures.get(key(row), {}).get("checked_at", 0)))
        for row in choices:
            if (row["expected_ip"] in used or row["expected_ip"] in blocked
                    or ipaddress.ip_address(row["expected_ip"]).version != 4
                    or failures.get(key(row), {}).get("until", 0) > now):
                continue
            used.add(row["expected_ip"])
            output.append((name, row))
            break
    # Prior successful site checks first, then US/HK/SG before exploration elsewhere.
    ordered = sorted(output, key=lambda pair: (0 if pair[0] in verified else 1,
                  verified.get(pair[0], {}).get("site_quality", {}).get("checked_at", 0),
                  0 if pair[1]["expected_ip"] in {r["expected_ip"] for r in strict.values()} else 1,
                  -scores.get(key(pair[1]), 0),
                  -region_gain(pair, verified),
                  state.get("site_attempts", {}).get(pair[0], 0),
                  ("us", "hk", "sg", "jp", "de", "nl").index(pair[1]["region"])))
    return schedule_candidates(ordered, verified, now)


def refresh(rotation, activate=False, limit=8):
    control = rotation.CONTROL
    deadline = time.monotonic() + 660
    with control.browser_lock():
        with control.data_lock():
            api, slots, state = control.api_client(), POOL.load_slots(), POOL.load_state()
            planned = candidates(rotation, slots, state, api)[:limit]
        for name, candidate in planned:
            current = state["approved"].get(name)
            renewal = (current is not None and key(current) == key(candidate)
                       and POOL.site_qualified(name, current))
            if time.monotonic() + (270 if renewal else 390) > deadline:
                continue
            # Yield to pool maintenance between candidates, never during an identity check.
            with control.data_lock():
                api, state = control.api_client(), POOL.load_state()
                before = copy.deepcopy(state)
                identities = site_policy.bridge_identities()
                if identities.get(candidate["port"]) != candidate["slot_identity"]:
                    continue
                probe = rotation.probe(candidate)
                reports = []
                qualified = None
                try:
                    if probe["passed"]:
                        qualified, reports = qualify(rotation, slots, name, probe, api)
                    state.setdefault("site_attempts", {})[name] = time.time()
                    for report in reports:
                        site_policy.record_failures(state, report)
                    failure_key = key(candidate)
                    if qualified is not None:
                        state["approved"][name] = qualified
                        state.setdefault("site_failures", {}).pop(failure_key, None)
                    else:
                        prior = state.setdefault("site_failures", {}).get(failure_key, {})
                        repeated = time.time() - prior.get("checked_at", 0) < 86400
                        challenge = any(s["verdict"] == "challenge" for r in reports
                                        for n in r["nodes"] for s in n["sites"].values())
                        state["site_failures"][failure_key] = {"checked_at": time.time(),
                            "until": time.time() + (86400 if challenge and repeated else
                                                   1800 if challenge or repeated else 300),
                            "challenge": challenge, "count": prior.get("count", 0) + 1,
                            "reports": [r.get("raw_report") for r in reports]}
                        old = state["approved"].get(name, {})
                        keep = (not challenge and not repeated and old
                                and key(old) == failure_key and POOL.site_qualified(name, old)
                                and old["expected_ip"] not in POOL.blocked_ips(state)
                                and POOL.effective({"approved": {name: old}}, slots, identities, api.nodes()))
                        if not keep:
                            state["approved"].pop(name, None)
                    site_policy.atomic_json(POOL.STATE, state)
                except BaseException:
                    site_policy.atomic_json(POOL.STATE, before)
                    raise
                finally:
                    try:
                        close_audits(api)
                        POOL.enforce(api, slots=slots)
                    finally:
                        if POOL.unified():
                            control.render()
        with control.data_lock():
            api, state = control.api_client(), POOL.load_state()
            approved = POOL.effective(state, slots, site_policy.bridge_identities(), api.nodes(), require_sites=True)
            if activate:
                if not approved:
                    raise RuntimeError("no shared-pool exit passed both browser rounds")
                rotation.backup("proxy-unified")
                site_policy.atomic_json(POOL.POLICY, {"version": 1, "mode": "unified"})
            approved = POOL.enforce(api)
            control.render()
            try:
                removed = prune_evidence(state)
                if removed:
                    print(json.dumps({"expired_artifacts_removed": removed}), flush=True)
            except (OSError, ValueError) as exc:
                print(json.dumps({"artifact_retention": "skipped", "error": type(exc).__name__}), flush=True)
            print(json.dumps({"mode": "unified", "site_qualified": len(approved),
                              "slots": list(approved)}), flush=True)
