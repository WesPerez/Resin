#!/usr/bin/env python3
"""Audit subscription exits with a fresh browser; never interact with challenges."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import urlsplit

import site_policy


SPEC = importlib.util.spec_from_file_location("region_latency", Path(__file__).with_name("region-latency.py"))
REGIONS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REGIONS)
TARGETS = site_policy.TARGETS
PASS_VERDICTS = ("normal", "login_no_challenge", "register_no_challenge")
BRIDGE = Path("/var/lib/resin-singbox-bridge/current/bridge.json")


def classify(host, status, url, title, text, headers, topic_links=0, login_controls=0,
             challenge_widgets=0):
    path = urlsplit(url).path
    combined = (title + "\n" + text).lower()
    if headers.get("cf-mitigated", "").lower() == "challenge" or challenge_widgets:
        return "challenge"
    if (path.startswith("/challenge") or "just a moment" in title.lower()
            or "\u8bf7\u7a0d\u5019" in title or "\u6ed1\u52a8\u9a8c\u8bc1" in title
            or (len(text) < 1500 and any(marker in combined for marker in (
                "verify you are human", "verifying you are human", "checking your browser",
                "\u8bf7\u9a8c\u8bc1\u60a8\u662f\u771f\u4eba", "\u8bbf\u95ee\u9a8c\u8bc1", "\u62d6\u52a8\u5230\u6700\u53f3\u8fb9")))):
        return "challenge"
    if status == 429:
        return "rate_limited"
    if not status or status >= 400:
        return "http_error"
    if urlsplit(url).hostname not in (host, "www." + host):
        return "unexpected_redirect"
    if host == "linux.do" and "linux do" in title.lower() and topic_links > 0:
        return "normal"
    if host == "agentrouter.org" and path == "/login" and "agent router" in combined and login_controls > 0:
        return "login_no_challenge"
    if host == "agentrouter.org" and path == "/register" and "agent router" in combined and login_controls > 0:
        return "register_no_challenge"
    return "unknown"


def critical_resource(host, url, resource_type):
    domain = urlsplit(url).hostname or ""
    path = urlsplit(url).path
    # Discourse telemetry and long polling do not gate rendering the forum.
    if host == "linux.do" and (path == "/srv/pv" or path.startswith("/message-bus/")):
        return False
    owned = domain == host or domain.endswith("." + host)
    if host == "linux.do":
        owned = owned or domain == "ldstatic.com" or domain.endswith(".ldstatic.com")
    if not owned:
        return False
    if resource_type in ("document", "script", "stylesheet"):
        return not path.startswith("/cdn-cgi/")
    if resource_type in ("xhr", "fetch"):
        return (path.endswith(".json") if host == "linux.do" else path.startswith(("/api/status", "/api/option")))
    return False


def trace(proxy, diagnostics=None):
    if proxy:
        proxy = proxy.replace("socks5://", "socks5h://", 1)
    command = ["curl", "--silent", "--show-error", "--noproxy", "", "--connect-timeout", "3",
               "--max-time", "6", "--fail", "https://www.cloudflare.com/cdn-cgi/trace"]
    command[1:1] = ["--proxy", proxy or ""]
    started = time.monotonic()
    try:
        result = subprocess.run(command, capture_output=True, timeout=8)
        if diagnostics is not None:
            diagnostics.update(curl_exit=result.returncode, elapsed_ms=round((time.monotonic() - started) * 1000))
        if result.returncode:
            if diagnostics is not None:
                diagnostics["error"] = result.stderr.decode(errors="replace").strip()[:400]
            return None
        values = dict(line.split("=", 1) for line in result.stdout.decode().splitlines() if "=" in line)
        return {"ip": str(ipaddress.ip_address(values["ip"])), "region": values["loc"].lower()}
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        if diagnostics is not None:
            diagnostics.update(error_type=type(exc).__name__, elapsed_ms=round((time.monotonic() - started) * 1000))
        return None


def bridge_identities():
    return site_policy.bridge_identities(BRIDGE)


def candidates(api, regions, limit, excluded_ips=()):
    nodes = api.nodes()
    manifest = json.loads(Path("/etc/xray/resin-region-platforms.json").read_text())
    identities = bridge_identities()
    result = []
    seen = set(excluded_ips)
    for region in regions:
        spec = manifest.get("Proxy" + region.upper())
        if not spec:
            continue
        platform = api.call("/api/v1/platforms/" + spec["id"])
        exact = {pattern for pattern in platform["regex_filters"] if pattern.startswith("^")}
        rows = REGIONS.shortlist(nodes, region, limit=64, seed=0)
        rows.sort(key=lambda n: not any("^" + re.escape(tag) + "$" in exact for tag in REGIONS.managed_tags(n, region)))
        count = 0
        for node in rows:
            port = REGIONS.bridge_port(node)
            if port not in identities or node["egress_ip"] in seen:
                continue
            seen.add(node["egress_ip"])
            result.append({"region": region, "port": port, "node_hash": node["node_hash"],
                           "expected_ip": node["egress_ip"], "slot_identity": identities[port]})
            count += 1
            if count >= limit:
                break
    return result


def browser_trace(context):
    page = context.new_page()
    page.set_default_timeout(2000)
    try:
        response = page.goto("https://www.cloudflare.com/cdn-cgi/trace", timeout=8000,
                             wait_until="domcontentloaded")
        if response.status != 200:
            return None
        values = dict(line.split("=", 1) for line in page.locator("body").inner_text().splitlines() if "=" in line)
        return {"ip": str(ipaddress.ip_address(values["ip"])), "region": values["loc"].lower()}
    except Exception:
        return None
    finally:
        page.close()


def browser_probe(browser, proxy, host, directory, label):
    from playwright.sync_api import Error as BrowserError

    target = TARGETS[host]
    target_key = host
    host = urlsplit(target).hostname
    context = browser.new_context(proxy={"server": proxy} if proxy else None, locale="zh-CN",
                                  timezone_id="Asia/Shanghai", viewport={"width": 1280, "height": 900})
    page = context.new_page()
    page.set_default_timeout(2000)
    before = browser_trace(context)
    started = time.monotonic()
    responses = []
    pending, failures, page_errors = set(), [], []

    def requested(request):
        if critical_resource(host, request.url, request.resource_type):
            pending.add(request)

    def failed(request):
        pending.discard(request)
        if critical_resource(host, request.url, request.resource_type):
            failures.append({"url": request.url.split("?", 1)[0], "type": request.resource_type,
                             "error": request.failure})

    def navigation(response):
        if response.status >= 400 and critical_resource(host, response.url, response.request.resource_type):
            failures.append({"url": response.url.split("?", 1)[0], "type": response.request.resource_type,
                             "status": response.status})
        if response.request.is_navigation_request() and response.frame == page.main_frame:
            responses.append({"status": response.status, "path": urlsplit(response.url).path,
                              "headers": {k: v for k, v in response.headers.items()
                                          if k in ("server", "cf-mitigated")}})

    page.on("response", navigation)
    page.on("request", requested)
    page.on("requestfinished", lambda request: pending.discard(request))
    page.on("requestfailed", failed)
    page.on("pageerror", lambda error: page_errors.append(str(error)[:400]))
    row = {"verdict": "unknown", "browser_trace_before": before, "coverage": "unauthenticated"}
    try:
        # Page usability is decided below; slow optional resources can delay DOMContentLoaded.
        page.goto(target, wait_until="commit", timeout=15000)
        deadline = started + 22
        normal_at = None
        rendered_at = None
        confirmed = False
        verdict = "unknown"
        title, body, widgets, login_controls, complete, ready = "", "", 0, 0, False, False
        latest = {"status": 0, "headers": {}}
        while time.monotonic() < deadline:
            try:
                snapshot = page.evaluate("""() => ({title: document.title,
                    body: document.body ? document.body.innerText : '',
                    complete: document.readyState === 'complete',
                    ready: document.readyState !== 'loading',
                    topics: document.querySelectorAll('#main-outlet a[href^="/t/"], #main-outlet a[href*="linux.do/t/"]').length,
                    widgets: Array.from(document.querySelectorAll('iframe[src*="challenges.cloudflare.com"], #nc_1_wrapper, .nc-container')).filter(e => {
                        const r = e.getBoundingClientRect(), s = getComputedStyle(e);
                        return r.width > 20 && r.height > 20 && s.visibility !== 'hidden' && s.display !== 'none';
                    }).length,
                    login: Array.from(document.querySelectorAll('button')).filter(b => /GitHub|LinuxDO/.test(b.innerText)).length})""")
            except BrowserError:
                page.wait_for_timeout(500)
                continue
            title, body = snapshot["title"], snapshot["body"]
            latest = responses[-1] if responses else {"status": 0, "headers": {}}
            widgets, login_controls = snapshot["widgets"], snapshot["login"]
            complete = snapshot["complete"]
            ready = snapshot["ready"]
            verdict = classify(host, latest["status"], page.url, title, body, latest["headers"],
                               snapshot["topics"], login_controls, widgets)
            if verdict in PASS_VERDICTS and rendered_at is None:
                rendered_at = time.monotonic()
            if verdict in PASS_VERDICTS and failures:
                verdict = "asset_failure"
            if verdict in PASS_VERDICTS and (not ready or pending):
                verdict = "loading"
            if verdict in PASS_VERDICTS:
                if normal_at is None:
                    normal_at = time.monotonic()
                observed = time.monotonic()
                if normal_at + 3 <= observed <= deadline:
                    confirmed = True
                    break
            else:
                normal_at = None
            if verdict == "rate_limited":
                break
            page.wait_for_timeout(1000)
        elapsed = round((time.monotonic() - started) * 1000)
        load_ms = round((rendered_at - started) * 1000) if rendered_at else None
        if verdict in (*PASS_VERDICTS, "loading") and load_ms is not None and load_ms > site_policy.MAX_LOAD_MS:
            verdict = "slow"
        if verdict in PASS_VERDICTS and not confirmed:
            verdict = "loading"
        row.update(verdict=verdict, http_status=latest["status"], elapsed_ms=elapsed,
                   load_ms=load_ms,
                   settled_ms=round((normal_at - started) * 1000) if normal_at else None,
                   slow_load=load_ms is not None and load_ms > 12000,
                   title=title[:160], path=urlsplit(page.url).path, headers=latest["headers"],
                   challenge_widgets=widgets, login_controls=login_controls,
                   document_complete=complete,
                   content_ready=verdict in PASS_VERDICTS,
                   body_sha256=hashlib.sha256(body.encode()).hexdigest(), body_length=len(body),
                   user_agent=page.evaluate("navigator.userAgent"))
    except BrowserError as exc:
        row.update(verdict="network_error", error_type=type(exc).__name__, error=str(exc)[:500],
                   elapsed_ms=round((time.monotonic() - started) * 1000))
    finally:
        screenshot = directory / (label + "-" + target_key.replace("/", "-") + ".png")
        try:
            page.screenshot(path=str(screenshot), timeout=3000)
            row["screenshot"] = str(screenshot)
        except BrowserError:
            row["screenshot_failed"] = True
        row["navigation_responses"] = responses
        row.update(critical_failures=failures, critical_pending=len(pending), page_errors=page_errors,
                   pending_resources=[{"url": request.url.split("?", 1)[0], "type": request.resource_type}
                                      for request in pending])
        row["challenge_response_seen"] = any(r["headers"].get("cf-mitigated") == "challenge" for r in responses)
        row["browser_trace_after"] = browser_trace(context)
        context.close()
    return row


def audit(args):
    from playwright.sync_api import sync_playwright

    os.umask(0o077)
    directory = Path(args.output)
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    if args.items:
        items = json.loads(Path(args.items).read_text())
    elif args.approved_state:
        items = [{k: row[k] for k in ("region", "port", "node_hash", "expected_ip", "slot_identity")}
                 for row in site_policy.load_state(Path(args.approved_state))["approved"].values()]
    elif args.recheck_report:
        prior = json.loads(Path(args.recheck_report).read_text())
        items = [{k: row[k] for k in ("region", "port", "node_hash", "expected_ip", "slot_identity")}
                 for row in prior["nodes"] if row.get("passed") and row.get("port")]
    else:
        api = REGIONS.API(Path("/etc/resin-apps/admin.token").read_text().strip())
        items = candidates(api, args.regions.split(","), args.per_region)
    if args.include_direct:
        items.insert(0, {"region": "direct", "port": None, "node_hash": "direct"})
    report = {"started_at": datetime.now(timezone.utc).isoformat(), "targets": TARGETS,
              "browser": "Chromium, fresh context, no challenge interaction", "nodes": []}
    report["headed"] = args.headed
    # Audit-only runs detect generation drift without delaying pool maintenance.
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=args.browser, headless=not args.headed,
                                             args=["--no-sandbox", "--disable-dev-shm-usage"])
        report["browser_version"] = browser.version
        try:
            for item in items:
                proxy_host = item.get("proxy_host", "172.17.0.1")
                if proxy_host not in ("172.17.0.1", "127.0.0.1"):
                    raise ValueError("browser audit proxy must be local")
                proxy_port = item.get("proxy_port", item["port"])
                proxy = "socks5://" + proxy_host + ":" + str(proxy_port) if proxy_port else None
                diagnostics = {}
                before = trace(proxy, diagnostics)
                row = dict(item, before=before, trace_diagnostics=diagnostics, sites={})
                row["checked_at"] = time.time()
                if before:
                    for host in TARGETS:
                        row["sites"][host] = browser_probe(browser, proxy, host, directory,
                                                           str(item["port"] or "direct"))
                        if row["sites"][host].get("verdict") not in PASS_VERDICTS:
                            row["early_stop_after"] = host
                            break
                after = trace(proxy) if before else None
                row["after"] = after
                current = ({item["port"]: item["slot_identity"]} if args.items else bridge_identities()) if item["port"] else {}
                row["slot_identity_checked_by_parent"] = bool(args.items)
                row["identity_valid"] = bool(before and before == after
                    and all(site["browser_trace_before"] == before == site["browser_trace_after"]
                            for site in row["sites"].values()) and (not item["port"] or (
                    before["ip"] == item["expected_ip"] and before["region"] == item["region"]
                    and current.get(item["port"]) == item["slot_identity"])))
                row["passed"] = row["identity_valid"] and len(row["sites"]) == len(TARGETS) and all(
                    site["verdict"] in PASS_VERDICTS for site in row["sites"].values())
                report["nodes"].append(row)
                (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
                print(json.dumps({"region": row["region"], "port": row["port"],
                                  "identity_valid": row["identity_valid"], "passed": row["passed"],
                                  "sites": {h: s["verdict"] for h, s in row["sites"].items()}}), flush=True)
        finally:
            browser.close()
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["summary"] = {"probed": len(report["nodes"]), "passed": sum(n["passed"] for n in report["nodes"]),
                         "verdicts": dict(Counter(s["verdict"] for n in report["nodes"] for s in n["sites"].values()))}
    (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["summary"]), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--regions", default="us,ca,jp,hk,sg,de,nl")
    parser.add_argument("--per-region", type=int, choices=range(1, 9), default=2)
    parser.add_argument("--include-direct", action="store_true")
    parser.add_argument("--browser", default="/root/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome")
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--recheck-report")
    parser.add_argument("--approved-state")
    parser.add_argument("--items")
    parser.add_argument("--output", required=True)
    audit(parser.parse_args())
