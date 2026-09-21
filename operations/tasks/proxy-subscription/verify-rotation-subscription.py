#!/usr/bin/env python3
"""Explicit live acceptance of the public three-group shared-pool subscription."""

import argparse
from datetime import datetime
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.parse
import urllib.request

import yaml

import rotation_pool as POOL
import site_policy
import unified_quality


SPEC = importlib.util.spec_from_file_location("rotation_control", Path(__file__).with_name("rotation-control.py"))
CONTROL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROL)


def trace(proxy, source="127.0.0.1", diagnostics=None, stage=None):
    started = time.monotonic()
    row = {"stage": stage, "source": source, "passed": False}
    try:
        result = subprocess.run(["curl", "--silent", "--show-error", "--fail", "--noproxy", "",
            "--proxy", proxy, "--interface", source, "--connect-timeout", "4", "--max-time", "10",
            "--write-out", "\n%{http_code}", "https://www.cloudflare.com/cdn-cgi/trace"],
            capture_output=True, timeout=12)
        body, _, status = result.stdout.rpartition(b"\n")
        row.update(code=result.returncode, status=int(status) if status.isdigit() else 0,
                   error=result.stderr.decode(errors="replace").strip()[:400])
        if result.returncode:
            raise RuntimeError(f"rotation trace failed: curl={row['code']} HTTP={row['status']} {row['error']}")
        fields = dict(line.split("=", 1) for line in body.decode().splitlines() if "=" in line)
        row.update(ip=fields["ip"], passed=True)
        return fields["ip"]
    except Exception as exc:
        row["exception"] = type(exc).__name__ + ": " + str(exc)
        raise
    finally:
        row["ms"] = round((time.monotonic() - started) * 1000)
        if diagnostics is not None:
            diagnostics.append(row)


def settle_fast(call):
    target = urllib.parse.quote("https://www.gstatic.com/generate_204", safe="")
    call("/group/Auto-Fast/delay?url=" + target + "&timeout=6000&expected=204", timeout=15)
    deadline = time.monotonic() + 30
    previous, stable_since = None, time.monotonic()
    while time.monotonic() < deadline:
        current = call("/proxies/Auto-Fast")["now"]
        if current != previous:
            previous, stable_since = current, time.monotonic()
        # Mihomo caches url-test selection for ten seconds after startup.
        if time.monotonic() - stable_since >= 12:
            return current
        time.sleep(1)
    raise RuntimeError("initial Auto-Fast selection did not settle")


def public_config():
    url = Path("/root/proxy-subscription-url.txt").read_text().strip()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=20) as response:
        body = response.read()
    token = Path("/etc/xray/subscription-token").read_text().strip()
    local = (Path("/var/lib/proxy-subscription") / (token + ".yaml")).read_bytes()
    if body != local:
        raise RuntimeError("public subscription does not match local publication")
    config = yaml.safe_load(body)
    groups = {g["name"]: g for g in config["proxy-groups"]}
    if list(groups) != ["PROXY", "Auto-Fast", "Auto-Rotate"]:
        raise RuntimeError("subscription must contain exactly three groups")
    if (groups["Auto-Fast"]["type"] != "url-test" or groups["Auto-Fast"].get("tolerance") != 150
            or groups["Auto-Rotate"]["type"] != "load-balance"
            or groups["Auto-Rotate"].get("strategy") != "sticky-sessions"
            or config.get("listeners") or config["rules"] != ["MATCH,PROXY"]):
        raise RuntimeError("published strategy mismatch")
    return config, groups


def record_browser_failure(api, browser, evidence_path):
    """Apply attributable failure evidence while the caller owns the data lock."""
    checked = browser["result"]
    nodes = checked.get("nodes", [])
    selected = checked.get("selected")
    if (checked.get("validation_path") != "subscription" or not selected
            or checked.get("client") != "Mihomo" or checked.get("dns_enabled") is not True
            or len(nodes) != 1 or nodes[0].get("selected") != selected
            or nodes[0].get("identity_valid") is not True or nodes[0].get("passed") is not False):
        return {"recorded": False, "reason": "not_single_attributable_failure"}
    state = POOL.load_state()
    site_policy.record_failures(state, checked)
    finished = datetime.fromisoformat(checked["finished_at"]).timestamp()
    row = nodes[0]
    failure_key = unified_quality.key(row)
    prior = state.setdefault("site_failures", {}).get(failure_key, {})
    if prior.get("checked_at", 0) <= finished:
        challenge = any(site.get("verdict") == "challenge" for site in row["sites"].values())
        quarantine = state.get("quarantined", {}).get(row["expected_ip"], {})
        state["site_failures"][failure_key] = {
            "checked_at": finished, "until": max(finished + 300, quarantine.get("until", 0)),
            "challenge": challenge,
            "count": prior.get("count", 0) + (prior.get("checked_at") != finished),
            "reports": [browser["report"]],
        }
    state["last_failed_acceptance"] = str(evidence_path)
    site_policy.atomic_json(POOL.STATE, state)
    try:
        approved = POOL.enforce(api, state=state)
    finally:
        CONTROL.CONTROL.render()
    return {"recorded": True, "approved": sorted(approved)}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--minimum-exits", type=int, default=1)
    parser.add_argument("--wait-seconds", type=int, default=30)
    args = parser.parse_args()
    CONTROL.CONTROL.WAIT_SECONDS = args.wait_seconds
    with CONTROL.CONTROL.browser_lock(wait_seconds=args.wait_seconds), CONTROL.CONTROL.data_lock():
        config, groups = public_config()
        api = CONTROL.CONTROL.api_client()
        _, approved = POOL.published(api)
        names = set(approved)
        if (names != {p["name"] for p in config["proxies"]}
                or any(set(groups[g]["proxies"]) != names for g in ("Auto-Fast", "Auto-Rotate"))
                or len(names) < args.minimum_exits):
            raise RuntimeError("published membership differs from the qualified shared pool")
        report = {"started_at": time.time(), "public_matches": True, "passed": False,
                  "exits": {}, "trace_checks": []}
        evidence = Path("/var/lib/proxy-region-latency") / ("rotation-acceptance-" + str(time.time_ns()) + ".json")
        failed_browser = None
        try:
            with CONTROL.client(config) as (proxy, call):
                for name, row in approved.items():
                    call("/proxies/PROXY", {"name": name})
                    checked = CONTROL.probe(row, proxy)
                    report["exits"][name] = checked
                    if not checked["passed"]:
                        raise RuntimeError("published exit failed: " + name)
                allowed = {row["expected_ip"] for row in approved.values()}
                call("/proxies/PROXY", {"name": "Auto-Fast"})
                report["fast_initial_selection"] = settle_fast(call)
                report["fast"] = [trace(proxy, diagnostics=report["trace_checks"], stage="fast") for _ in range(3)]
                if len(set(report["fast"])) != 1 or not set(report["fast"]) <= allowed:
                    raise RuntimeError("stable group did not retain an approved exit")
                selected = call("/proxies/Auto-Fast")["now"]
                row = approved[selected]
                item = {key: row[key] for key in POOL.IDENTITY_FIELDS}
                item.update(proxy_host="127.0.0.1", proxy_port=int(proxy.rsplit(":", 1)[1]))
                checked, path = CONTROL.CONTROL.CLIENT.browser_check([item], "shared-acceptance", timeout=120)
                checked.update(validation_path="subscription", client="Mihomo", dns_enabled=config["dns"]["enable"],
                               selected=selected)
                checked["nodes"][0]["selected"] = call("/proxies/Auto-Fast")["now"]
                report["browser"] = {"report": str(path), "result": checked}
                if not site_policy.report_passes(checked, selected=selected):
                    failed_browser = report["browser"]
                    raise RuntimeError("both websites did not pass through Auto-Fast")
                call("/proxies/PROXY", {"name": "Auto-Rotate"})
                report["sticky"] = [trace(proxy, diagnostics=report["trace_checks"], stage="sticky") for _ in range(3)]
                if len(set(report["sticky"])) != 1:
                    raise RuntimeError("rotation did not preserve the current session")
                # New source keys exercise distinct sessions without changing the 10-minute TTL.
                report["new_sessions"] = [trace(proxy, f"127.0.0.{n}", report["trace_checks"], "new_session")
                                          for n in range(2, 18)]
                if not set(report["new_sessions"]) <= allowed:
                    raise RuntimeError("rotation selected an unapproved exit")
                if len(approved) > 1 and len(set(report["new_sessions"])) < 2:
                    raise RuntimeError("new sessions did not spread across the qualified pool")
                row = next(row for row in approved.values() if row["expected_ip"] == report["sticky"][0])
                item = {key: row[key] for key in POOL.IDENTITY_FIELDS}
                item.update(proxy_host="127.0.0.1", proxy_port=int(proxy.rsplit(":", 1)[1]))
                checked, path = CONTROL.CONTROL.CLIENT.browser_check([item], "rotate-acceptance", timeout=120)
                report["rotation_browser"] = {"report": str(path), "result": checked,
                    "scope": "page usability; each destination may use a different qualified exit"}
                if not checked["nodes"][0]["passed"]:
                    failed_browser = report["rotation_browser"]
                    raise RuntimeError("both websites did not pass through Auto-Rotate")
            report["passed"] = True
        except Exception as exc:
            report["error"] = type(exc).__name__ + ": " + str(exc)
            if failed_browser is not None:
                try:
                    report["failure_writeback"] = record_browser_failure(api, failed_browser, evidence)
                except Exception as cleanup_exc:
                    report["failure_writeback_error"] = type(cleanup_exc).__name__ + ": " + str(cleanup_exc)
            raise
        finally:
            report["finished_at"] = time.time()
            site_policy.atomic_json(evidence, report)
    print(json.dumps({"passed": True, "independent_exits": len(approved),
                      "new_session_unique_ips": len(set(report["new_sessions"])), "evidence": str(evidence)}))


if __name__ == "__main__":
    main()
