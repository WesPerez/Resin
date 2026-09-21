import copy
from contextlib import nullcontext
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import site_policy as POLICY


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AUDIT = load("site_quality", "site-quality.py")
SUB = load("site_subscription", "site-subscription.py")
CONTROL = load("site_control", "site-control.py")
NOW = 1800000000


class ErrorDiagnosticsTests(unittest.TestCase):
    def test_readonly_filesystem_reports_errno_without_private_path_or_message(self):
        result = CONTROL.error_summary(OSError(30, "private-token", "/private/secret"))
        self.assertEqual(result, {"status": "error", "category": "OSError", "errno": "EROFS"})


def approval():
    return {"region": "us", "port": 12001, "node_hash": "a" * 32,
            "slot_identity": "b" * 64, "expected_ip": "8.8.8.8",
            "checked_at": NOW - 60, "expires_at": NOW + 1000, "success_streak": 2,
            "validation_path": "subscription"}


def report(start, finish):
    row = approval()
    trace = {"ip": row["expected_ip"], "region": "us"}
    sites = {host: {"verdict": ("normal" if host == "linux.do" else "register_no_challenge"
                               if host == "agentrouter.org/register" else "login_no_challenge"),
                   "http_status": 200, "browser_trace_before": trace, "browser_trace_after": trace,
                   "critical_failures": [], "critical_pending": 0, "document_complete": True,
                   "challenge_widgets": 0, "load_ms": 1000} for host in POLICY.TARGETS}
    return {"started_at": datetime.fromtimestamp(start, timezone.utc).isoformat(),
            "finished_at": datetime.fromtimestamp(finish, timezone.utc).isoformat(),
            "targets": POLICY.TARGETS, "headed": True,
            "nodes": [dict(row, before=trace, after=trace, sites=sites, passed=True, identity_valid=True)]}


def client_report(value):
    value.update(validation_path="subscription", client="Mihomo", dns_enabled=True)
    for row in value["nodes"]:
        row.update(proxy_host="127.0.0.1", proxy_port=32001, selected=row["region"].upper() + "-Auto")
    return value


class EarlyStopTest(unittest.TestCase):
    def test_failed_first_page_skips_remaining_targets_and_retains_quarantine(self):
        item = approval()
        trace = {"ip": item["expected_ip"], "region": item["region"]}
        browser = Mock(version="test")
        playwright = SimpleNamespace(chromium=Mock())
        playwright.chromium.launch.return_value = browser
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            items = root / "items.json"
            items.write_text(json.dumps([item]))
            args = SimpleNamespace(output=str(root / "audit"), items=str(items), include_direct=False,
                                   headed=True, browser="/unused-test-browser")
            with patch.dict("sys.modules", {"playwright.sync_api": SimpleNamespace(sync_playwright=lambda: nullcontext(playwright))}), \
                    patch.object(AUDIT, "trace", return_value=trace), \
                    patch.object(AUDIT, "browser_probe", return_value={"verdict": "challenge",
                        "browser_trace_before": trace, "browser_trace_after": trace}) as probe, \
                    patch("builtins.print"):
                AUDIT.audit(args)
            result = json.loads((root / "audit" / "report.json").read_text())
        probe.assert_called_once()
        self.assertEqual(result["nodes"][0]["early_stop_after"], "linux.do")
        self.assertFalse(result["nodes"][0]["passed"])
        self.assertEqual(POLICY.report_passes(result), {})
        state = {"approved": {}}
        POLICY.record_failures(state, result)
        self.assertEqual(state["quarantined"][item["expected_ip"]]["reason"], "challenge")


class ClassificationTest(unittest.TestCase):
    def test_register_and_critical_cdn_resources(self):
        self.assertEqual(AUDIT.classify("agentrouter.org", 200, "https://agentrouter.org/register",
                                       "New API", "Agent Router", {}, login_controls=2), "register_no_challenge")
        self.assertTrue(AUDIT.critical_resource("linux.do", "https://cdn3.ldstatic.com/app.js", "script"))
        self.assertFalse(AUDIT.critical_resource("linux.do", "https://analytics.example.com/a", "fetch"))
        self.assertFalse(AUDIT.critical_resource("linux.do", "https://evil-ldstatic.com/a", "script"))
        self.assertFalse(AUDIT.critical_resource("linux.do", "https://linux.do/srv/pv", "fetch"))
        self.assertFalse(AUDIT.critical_resource("linux.do", "https://linux.do/message-bus/abc/poll", "xhr"))
        self.assertTrue(AUDIT.critical_resource("linux.do", "https://linux.do/latest.json", "xhr"))
    def test_200_slider_is_not_a_pass(self):
        self.assertEqual(AUDIT.classify("agentrouter.org", 200, "https://agentrouter.org/console/log",
                                       "\u6ed1\u52a8\u9a8c\u8bc1\u9875\u9762", "", {}), "challenge")

    def test_normal_site_requires_positive_landmarks(self):
        self.assertEqual(AUDIT.classify("agentrouter.org", 200, "https://agentrouter.org/login",
                                       "New API", "Agent Router", {}, login_controls=2), "login_no_challenge")
        self.assertEqual(AUDIT.classify("agentrouter.org", 200, "https://agentrouter.org/login",
                                       "Agent Router", "login " * 100, {}), "unknown")
        self.assertEqual(AUDIT.classify("linux.do", 200, "https://linux.do/",
                                       "LINUX DO", "", {}, topic_links=3), "normal")
        self.assertEqual(AUDIT.classify("linux.do", 200, "https://linux.do/",
                                       "LINUX DO", "", {}), "unknown")

    def test_challenge_headers_widgets_and_redirect_override_branding(self):
        for url, headers, widgets in (("https://linux.do/", {"cf-mitigated": "challenge"}, 0),
                                      ("https://linux.do/", {}, 1),
                                      ("https://linux.do/challenge", {}, 0)):
            self.assertEqual(AUDIT.classify("linux.do", 200, url, "LINUX DO", "", headers,
                                           topic_links=3, challenge_widgets=widgets), "challenge")

    def test_forum_article_mentioning_challenge_is_not_rejected(self):
        self.assertEqual(AUDIT.classify("linux.do", 200, "https://linux.do/", "LINUX DO",
                                       "verify you are human " + "article " * 300, {}, topic_links=5), "normal")


class BrowserTimingTest(unittest.TestCase):
    def probe(self, snapshot_at):
        page = Mock()
        page.url = "https://linux.do/"
        page.main_frame = object()
        callbacks = {}
        clock = SimpleNamespace(now=1000)
        page.on.side_effect = lambda event, callback: callbacks.update({event: callback})
        response = Mock(status=200, url=page.url, headers={}, frame=page.main_frame)
        response.request.resource_type = "document"
        response.request.is_navigation_request.return_value = True
        page.goto.side_effect = lambda *args, **kwargs: callbacks["response"](response)
        page.evaluate.side_effect = lambda script: (
            "test-browser" if script == "navigator.userAgent" else snapshot_at(clock.now - 1000))
        page.wait_for_timeout.side_effect = lambda ms: setattr(clock, "now", clock.now + ms / 1000)
        browser = Mock()
        browser.new_context.return_value.new_page.return_value = page
        with patch.dict("sys.modules", {"playwright.sync_api": SimpleNamespace(Error=RuntimeError)}), \
                patch.object(AUDIT, "browser_trace", return_value={"ip": "8.8.8.8", "region": "us"}), \
                patch.object(AUDIT.time, "monotonic", side_effect=lambda: clock.now):
            return AUDIT.browser_probe(browser, None, "linux.do", Path("/unused-test-artifacts"), "test")

    @staticmethod
    def normal(**changes):
        return dict({"title": "LINUX DO", "body": "Topics", "complete": True,
                     "ready": True, "topics": 3, "widgets": 0, "login": 0}, **changes)

    def test_visible_challenge_interrupts_an_initially_normal_page(self):
        result = self.probe(lambda elapsed: self.normal(widgets=int(elapsed >= 2)))
        self.assertEqual(result["verdict"], "challenge")
        self.assertFalse(result["content_ready"])

    def test_normal_content_near_deadline_does_not_pass_without_settling(self):
        result = self.probe(lambda elapsed: self.normal(ready=elapsed >= 20))
        self.assertEqual(result["verdict"], "loading")
        self.assertFalse(result["content_ready"])

    def test_optional_loading_does_not_block_settled_usable_content(self):
        result = self.probe(lambda elapsed: self.normal(complete=False))
        self.assertEqual(result["verdict"], "normal")
        self.assertTrue(result["content_ready"])
        self.assertFalse(result["document_complete"])
        self.assertGreaterEqual(result["elapsed_ms"], 3000)


class ApprovalTest(unittest.TestCase):
    def test_rendered_content_does_not_wait_for_noncritical_images(self):
        checked = report(NOW - 100, NOW - 50)
        page = checked["nodes"][0]["sites"]["linux.do"]
        page.update(document_complete=False, content_ready=True)
        self.assertTrue(POLICY.report_passes(checked, NOW))
        page["critical_pending"] = 1
        self.assertFalse(POLICY.report_passes(checked, NOW))

    def test_slow_but_rendered_page_is_distinct_from_excessive_first_render(self):
        checked = report(NOW - 100, NOW - 50)
        page = checked["nodes"][0]["sites"]["linux.do"]
        page.update(load_ms=15000, settled_ms=21000, slow_load=True)
        self.assertTrue(POLICY.report_passes(checked, NOW))
        page["load_ms"] = POLICY.MAX_LOAD_MS + 1
        self.assertEqual(POLICY.report_passes(checked, NOW), {})

    def test_visible_page_with_failed_or_pending_assets_is_not_approved(self):
        for key, value in (("critical_failures", [{"error": "EOF"}]), ("critical_pending", 1),
                           ("document_complete", False)):
            checked = report(NOW - 100, NOW - 50)
            checked["nodes"][0]["sites"]["linux.do"][key] = value
            self.assertEqual(POLICY.report_passes(checked, NOW), {})
    def test_two_nonoverlapping_passes_required(self):
        first, second = report(NOW - 300, NOW - 200), report(NOW - 100, NOW - 50)
        approved = POLICY.approve_reports([first, second], NOW)["approved"]
        self.assertEqual(set(approved), {"us"})
        self.assertEqual(approved["us"]["checked_at"], NOW - 100)
        for rows in ([first], [first, first], [first, report(NOW - 250, NOW - 150)]):
            with self.assertRaises(ValueError):
                POLICY.approve_reports(rows, NOW)

    def test_renewed_slot_ip_challenge_or_error_cannot_be_approved(self):
        first = report(NOW - 300, NOW - 200)
        for field, value in (("slot_identity", "c" * 64), ("expected_ip", "1.1.1.1"), ("passed", False)):
            second = report(NOW - 100, NOW - 50)
            second["nodes"][0][field] = value
            with self.assertRaises(ValueError):
                POLICY.approve_reports([first, second], NOW)
        second = report(NOW - 100, NOW - 50)
        second["nodes"][0]["sites"]["linux.do"]["verdict"] = "challenge"
        with self.assertRaises(ValueError):
            POLICY.approve_reports([first, second], NOW)

    def test_stale_results_do_not_get_a_new_ttl_at_import(self):
        with self.assertRaises(ValueError):
            POLICY.approve_reports([report(NOW - 7200, NOW - 7100), report(NOW - 7000, NOW - 6900)], NOW)

    def test_expired_or_changed_approvals_are_denied(self):
        row = approval()
        state = {"approved": {"us": row}}
        self.assertEqual(set(POLICY.effective(state, {12001: "b" * 64}, now=NOW)), {"us"})
        self.assertEqual(POLICY.effective(state, {12001: "c" * 64}, now=NOW), {})
        self.assertEqual(POLICY.effective(state, {12001: "b" * 64}, now=NOW + 2000), {})
        row["success_streak"] = 1
        self.assertEqual(POLICY.effective(state, {12001: "b" * 64}, now=NOW), {})

    def test_global_failure_count_does_not_revoke_a_routable_verified_exit(self):
        row = approval()
        state = {"approved": {"us": row}}
        node = {"node_hash": row["node_hash"], "region": "us", "egress_ip": row["expected_ip"],
                "enabled": True, "has_outbound": True, "circuit_open_since": None,
                "failure_count": 2,
                "tags": [{"tag": "managed-apps-public-pool/socks-172.17.0.1:12001",
                          "subscription_name": "managed-apps-public-pool"}]}
        self.assertEqual(set(POLICY.effective(state, {12001: row["slot_identity"]}, [node], NOW)), {"us"})
        node["circuit_open_since"] = NOW - 1
        self.assertEqual(POLICY.effective(state, {12001: row["slot_identity"]}, [node], NOW), {})

    def test_bridge_passes_cannot_publish_without_two_client_passes(self):
        reports = [report(NOW - 300, NOW - 200), report(NOW - 100, NOW - 50)]
        state = POLICY.approve_reports(reports, NOW)
        self.assertEqual(POLICY.effective(state, {12001: "b" * 64}, now=NOW), {})
        self.assertEqual(set(POLICY.effective(state, {12001: "b" * 64}, now=NOW,
                                             require_client=False)), {"us"})
        client_report(reports[0])
        self.assertEqual(POLICY.approve_reports(reports, NOW)["approved"]["us"]["validation_path"], "bridge")
        client_report(reports[1])
        state = POLICY.approve_reports(reports, NOW)
        self.assertEqual(set(POLICY.effective(state, {12001: "b" * 64}, now=NOW)), {"us"})

    def test_manual_revocation_survives_success_streak(self):
        row = approval()
        row.update(revoked=True, success_streak=20)
        self.assertEqual(POLICY.effective({"approved": {"us": row}}, {12001: "b" * 64}, now=NOW), {})
        self.assertFalse(POLICY.valid_approval("us", row, NOW, require_client=False))

    def test_client_report_must_bind_the_selected_region_and_loopback_proxy(self):
        for key, value in (("proxy_host", "172.17.0.1"), ("proxy_port", 12001), ("selected", "HK-Auto")):
            checked = client_report(report(NOW - 100, NOW - 50))
            checked["nodes"][0][key] = value
            self.assertEqual(POLICY.report_passes(checked, NOW), {})
        checked = report(NOW - 100, NOW - 50)
        checked["validation_path"] = "subscription"
        with self.assertRaises(ValueError):
            POLICY.report_passes(checked, NOW)

    def test_strict_enforcement_never_falls_back_to_broad_pool(self):
        row = approval()
        state = {"approved": {"us": row}}
        manifest = {"ProxyUS": {"region": "us", "id": "us"}, "ProxyJP": {"region": "jp", "id": "jp"}}
        class API:
            def __init__(self):
                self.platforms = {r: {"name": "Proxy" + r.upper(), "region_filters": [r],
                                     "regex_filters": ["^managed-apps-public-pool/.*"],
                                     "allocation_policy": "BALANCED", "routable_node_count": 100}
                                  for r in ("us", "jp")}
            def nodes(self):
                return [{"node_hash": "a" * 32, "region": "us", "egress_ip": "8.8.8.8",
                         "enabled": True, "has_outbound": True, "circuit_open_since": None,
                         "tags": [{"tag": "managed-apps-public-pool/socks-172.17.0.1:12001",
                                   "subscription_name": "managed-apps-public-pool"}]}]
            def call(self, path, method="GET", data=None):
                current = self.platforms[path.rsplit("/", 1)[-1]]
                if method == "PATCH":
                    current.update(data)
                    current["routable_node_count"] = 0 if data["regex_filters"] == POLICY.DENY else 1
                return copy.deepcopy(current)
        api = API()
        POLICY.enforce(api, manifest, state, {12001: "b" * 64}, NOW)
        self.assertEqual(api.platforms["us"]["regex_filters"], POLICY.filters(row))
        self.assertTrue(api.platforms["us"]["passive_circuit_breaker_disabled"])
        self.assertEqual(api.platforms["jp"]["regex_filters"], POLICY.DENY)
        POLICY.enforce(api, manifest, state, {12001: "c" * 64}, NOW)
        self.assertEqual(api.platforms["us"]["regex_filters"], POLICY.DENY)


class ClientGateTest(unittest.TestCase):
    def run_gate(self, state, reports, has_candidate=True):
        candidates = copy.deepcopy(state["approved"]) if has_candidate else {}
        events = []

        def enforce(api, manifest, state, require_client=True):
            events.append("publish-routes" if require_client else "stage-routes")
            return {"approved_regions": [region for region, row in state["approved"].items()
                                         if POLICY.valid_approval(region, row, NOW, require_client)]}

        def verify(*args, **kwargs):
            events.append("client-check")
            result = reports.pop(0)
            if isinstance(result, Exception):
                raise result
            return result, Path("/evidence/client.json")

        with patch.object(POLICY, "effective", return_value=candidates), \
                patch.object(POLICY, "bridge_identities", return_value={}), \
                patch.object(POLICY, "enforce", side_effect=enforce), \
                patch.object(POLICY, "atomic_json"), patch.object(POLICY.time, "time", return_value=NOW), \
                patch.object(CONTROL.CLIENT, "subscription_config", return_value={}), \
                patch.object(CONTROL.CLIENT, "restrict", return_value={}), \
                patch.object(CONTROL.CLIENT, "verify_round", side_effect=verify), \
                patch.object(CONTROL, "render", side_effect=lambda: events.append("render")):
            try:
                result = CONTROL.qualify(state, Mock(), {})
            except RuntimeError:
                result = {"error": True}
        return result, events

    def test_publication_requires_two_client_rounds(self):
        state = {"approved": {"us": dict(approval(), validation_path="bridge")}}
        reports = [report(NOW - 300, NOW - 200), report(NOW - 100, NOW - 50)]
        for row in reports:
            client_report(row)
        result, events = self.run_gate(state, reports)
        self.assertEqual(result["approved_regions"], ["us"])
        self.assertEqual(events, ["stage-routes", "client-check", "client-check", "publish-routes", "render"])

    def test_challenge_or_process_failure_closes_staged_routes(self):
        failed = report(NOW - 300, NOW - 200)
        failed["nodes"][0]["passed"] = False
        failed["nodes"][0]["sites"]["linux.do"]["verdict"] = "challenge"
        for attempt in (failed, RuntimeError("browser failed")):
            state = {"approved": {"us": dict(approval(), validation_path="bridge")}}
            _, events = self.run_gate(state, [attempt])
            self.assertEqual(state["approved"]["us"]["success_streak"], 0)
            self.assertEqual(state["approved"]["us"]["expires_at"], 0)
            self.assertEqual(events[-2:], ["publish-routes", "render"])

    def test_single_transient_failure_keeps_unexpired_existing_approval(self):
        failed = report(NOW - 300, NOW - 200)
        failed["nodes"][0]["passed"] = False
        for attempt in (failed, RuntimeError("browser failed")):
            original = approval()
            state = {"approved": {"us": copy.deepcopy(original)}}
            self.run_gate(state, [attempt])
            self.assertEqual(state["approved"]["us"], original)

    def test_first_recovery_pass_is_preserved_without_publishing(self):
        state = {"approved": {"us": dict(approval(), success_streak=1)}}
        result, events = self.run_gate(state, [], has_candidate=False)
        self.assertEqual(result["approved_regions"], [])
        self.assertEqual(state["approved"]["us"]["success_streak"], 1)
        self.assertEqual(events, ["publish-routes", "render"])


class ReplacementTest(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(CONTROL, "RECOVERY_REGIONS", ())
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(CONTROL.rotation_pool, "enabled", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_bridge_pass_does_not_renew_client_evidence(self):
        original = approval()
        state = {"approved": {"us": copy.deepcopy(original)}}
        checked = report(NOW - 30, NOW - 10)
        item = {key: original[key] for key in CONTROL.CLIENT.ITEM_FIELDS}
        with patch.object(POLICY.time, "time", return_value=NOW):
            CONTROL.update_bridge_state(state, [item], checked, {12001: "b" * 64})
        self.assertEqual(state["approved"]["us"], original)

    def test_one_working_region_keeps_searching_for_reserves(self):
        row = approval()
        api = Mock()
        api.nodes.return_value = [{"node_hash": row["node_hash"], "region": "us",
            "egress_ip": row["expected_ip"], "enabled": True, "has_outbound": True,
            "tags": [{"tag": "managed-apps-public-pool/socks-172.17.0.1:12001",
                      "subscription_name": "managed-apps-public-pool"}]}]
        reserve = dict(row, region="hk", port=12002, expected_ip="1.1.1.1")
        with patch.object(CONTROL, "RECOVERY_REGIONS", ("us", "hk", "sg")), \
                patch.object(POLICY, "bridge_identities", return_value={12001: "b" * 64}), \
                patch.object(CONTROL.AUDIT, "candidates", return_value=[reserve]) as discover:
            items = CONTROL.refresh_items({"approved": {"us": row}}, api)
            self.assertEqual([item["region"] for item in items], ["us", "hk"])
            discover.assert_called_once_with(api, ["hk", "sg"], 1, set())

    def test_failed_ip_cannot_return_after_two_later_passes(self):
        failed = report(NOW - 500, NOW - 400)
        failed["nodes"][0]["sites"]["linux.do"]["verdict"] = "challenge"
        state = {"approved": {"us": approval()}}
        POLICY.record_failures(state, failed, NOW)
        renewed = POLICY.approve_reports([client_report(report(NOW - 300, NOW - 200)),
                                          client_report(report(NOW - 100, NOW - 50))], NOW)
        state["approved"] = renewed["approved"]
        self.assertEqual(POLICY.effective(state, {12001: "b" * 64}, now=NOW), {})
        self.assertNotIn("8.8.8.8", POLICY.quarantined_ips(state, NOW + 3600))
        self.assertNotIn("8.8.8.8", POLICY.quarantined_ips(state, NOW + 86400))

    def test_rotating_ip_quarantine_includes_every_observed_exit(self):
        checked = report(NOW - 100, NOW - 50)
        checked["nodes"][0]["after"] = {"ip": "1.1.1.1", "region": "us"}
        checked["nodes"][0]["sites"]["linux.do"]["browser_trace_before"] = {"ip": "9.9.9.9", "region": "us"}
        state = {"approved": {}}
        POLICY.record_failures(state, checked, NOW)
        self.assertEqual(POLICY.quarantined_ips(state, NOW), {"8.8.8.8", "1.1.1.1", "9.9.9.9"})

    def test_network_failure_cools_down_without_daylong_ip_ban(self):
        checked = report(NOW - 100, NOW - 50)
        checked["nodes"][0].update(before=None, after=None, sites={}, passed=False, identity_valid=False)
        state = {"approved": {"us": dict(approval(), expires_at=NOW + 4000)}}
        POLICY.record_failures(state, checked, NOW)
        self.assertEqual(POLICY.quarantined_ips(state, NOW), set())
        self.assertEqual(state["approved"]["us"]["success_streak"], 2)
        checked["finished_at"] = datetime.fromtimestamp(NOW - 25, timezone.utc).isoformat()
        POLICY.record_failures(state, checked, NOW)
        self.assertEqual(POLICY.quarantined_ips(state, NOW), {"8.8.8.8"})
        self.assertEqual(POLICY.quarantined_ips(state, NOW + 1800), set())
        self.assertEqual(state["approved"]["us"]["success_streak"], 0)
        self.assertEqual(POLICY.effective(state, {12001: "b" * 64}, now=NOW + 1800), {})

    def test_browser_timeout_retains_challenge_and_marks_unfinished_items_failed(self):
        partial = report(NOW - 100, NOW - 50)
        partial.pop("finished_at")
        partial["nodes"][0]["sites"]["linux.do"]["verdict"] = "challenge"
        first = {key: approval()[key] for key in CONTROL.CLIENT.ITEM_FIELDS}
        second = dict(first, port=12002, expected_ip="1.1.1.1")
        interrupted = CONTROL.CLIENT.interrupted_report([first, second], partial["started_at"],
                                                        partial, subprocess.TimeoutExpired("browser", 1))
        interrupted["finished_at"] = datetime.fromtimestamp(NOW - 50, timezone.utc).isoformat()
        state = {"approved": {}}
        POLICY.record_failures(state, interrupted, NOW)
        self.assertEqual(POLICY.quarantined_ips(state, NOW), {"8.8.8.8"})
        self.assertEqual(POLICY.quarantined_ips(state, NOW + 3600), set())
        self.assertTrue(all(not row["passed"] for row in interrupted["nodes"]))

    def test_repeated_challenge_has_long_quarantine_but_reimport_does_not(self):
        first = report(NOW - 300, NOW - 200)
        first["nodes"][0]["sites"]["linux.do"]["verdict"] = "challenge"
        state = {"approved": {}}
        POLICY.record_failures(state, first, NOW)
        POLICY.record_failures(state, first, NOW)
        self.assertEqual(POLICY.quarantined_ips(state, NOW + 1800), set())
        second = report(NOW - 100, NOW - 50)
        second["nodes"][0]["sites"]["linux.do"]["verdict"] = "challenge"
        POLICY.record_failures(state, second, NOW)
        self.assertEqual(POLICY.quarantined_ips(state, NOW + 3600), {"8.8.8.8"})

    def test_unrelated_ports_do_not_quarantine_subscription_ip(self):
        for port in (12400, 30005, 33403):
            checked = report(NOW - 100, NOW - 50)
            checked["nodes"][0]["port"] = port
            checked["nodes"][0]["sites"]["linux.do"]["verdict"] = "challenge"
            state = {"approved": {}}
            POLICY.record_failures(state, checked, NOW)
            self.assertEqual(POLICY.quarantined_ips(state, NOW), set())

    def test_slow_assets_and_unknown_only_cool_down(self):
        for verdict in ("slow", "asset_failure", "loading", "unknown"):
            checked = report(NOW - 100, NOW - 50)
            checked["nodes"][0]["sites"]["linux.do"]["verdict"] = verdict
            state = {"approved": {}}
            POLICY.record_failures(state, checked, NOW)
            self.assertEqual(POLICY.quarantined_ips(state, NOW), set())
            self.assertEqual(state["transient_failures"]["bridge:8.8.8.8"]["count"], 1)
            self.assertEqual(POLICY.quarantined_ips(state, NOW + 1800), set())

    def test_missing_candidate_is_replaced_without_reenabling_revoked_region(self):
        row = approval()
        revoked = dict(row, region="hk", expected_ip="1.1.1.1", revoked=True)
        state = {"approved": {"us": row, "hk": revoked}}
        api = Mock()
        api.nodes.return_value = []
        replacement = dict(row, port=12002, slot_identity="c" * 64, expected_ip="9.9.9.9")
        with patch.object(POLICY, "bridge_identities", return_value={}), \
                patch.object(CONTROL.AUDIT, "candidates", return_value=[replacement]) as discover:
            self.assertEqual(CONTROL.refresh_items(state, api), [replacement])
            discover.assert_called_once_with(api, ["us"], 1, {"8.8.8.8", "1.1.1.1"})

    def test_current_candidate_keeps_its_exit(self):
        row = approval()
        api = Mock()
        api.nodes.return_value = [{"node_hash": row["node_hash"], "region": "us",
            "egress_ip": row["expected_ip"], "enabled": True, "has_outbound": True,
            "tags": [{"tag": "managed-apps-public-pool/socks-172.17.0.1:12001",
                      "subscription_name": "managed-apps-public-pool"}]}]
        with patch.object(POLICY, "bridge_identities", return_value={12001: "b" * 64}), \
                patch.object(CONTROL.AUDIT, "candidates") as discover:
            items = CONTROL.refresh_items({"approved": {"us": row}}, api)
            self.assertEqual(items, [{key: row[key] for key in CONTROL.CLIENT.ITEM_FIELDS}])
            discover.assert_not_called()

    def test_replacement_does_not_inherit_prior_evidence(self):
        state = {"approved": {"us": approval()}}
        checked = report(NOW - 100, NOW - 50)
        checked["nodes"][0].update(port=12002, slot_identity="c" * 64)
        item = {key: checked["nodes"][0][key] for key in CONTROL.CLIENT.ITEM_FIELDS}
        with patch.object(POLICY.time, "time", return_value=NOW):
            CONTROL.update_bridge_state(state, [item], checked, {12002: "c" * 64})
            self.assertEqual(state["approved"]["us"]["success_streak"], 1)
            self.assertEqual(POLICY.effective(state, {12002: "c" * 64}, require_client=False), {})
            CONTROL.update_bridge_state(state, [item], report_for_item(item), {12002: "c" * 64})
            self.assertEqual(state["approved"]["us"]["success_streak"], 2)
            self.assertEqual(POLICY.effective(state, {12002: "c" * 64}), {})
            self.assertEqual(set(POLICY.effective(state, {12002: "c" * 64}, require_client=False)), {"us"})

    def test_generation_change_during_audit_cannot_accumulate_a_pass(self):
        state = {"approved": {"us": approval()}}
        item = {key: approval()[key] for key in CONTROL.CLIENT.ITEM_FIELDS}
        with patch.object(POLICY.time, "time", return_value=NOW):
            CONTROL.update_bridge_state(state, [item], report(NOW - 100, NOW - 50), {12001: "c" * 64})
        self.assertEqual(state["approved"]["us"]["success_streak"], 0)


def report_for_item(item):
    checked = report(NOW - 40, NOW - 10)
    checked["nodes"][0].update(item)
    return checked


class SubscriptionTest(unittest.TestCase):
    def config(self):
        return {"proxies": [{"name": name, "network": "ws"} for name in (
            "US-Auto", "JP-Auto", "HK-Auto", "weesai.com-vless-443-ws")],
                "proxy-groups": [], "rules": ["MATCH,PROXY"]}

    def test_only_approved_exits_are_published_and_order_is_stable(self):
        config = SUB.restrict(self.config(), {"hk": {}, "us": {}})
        self.assertEqual([p["name"] for p in config["proxies"]], ["US-Auto", "HK-Auto"])
        self.assertEqual(config["proxy-groups"][0]["type"], "fallback")
        self.assertEqual(config["proxy-groups"][0]["proxies"], ["US-Auto", "HK-Auto"])

    def test_no_approved_exit_rejects_instead_of_direct_or_unchecked_fallback(self):
        config = SUB.restrict(self.config(), {})
        self.assertEqual(config["proxies"], [])
        self.assertEqual(config["proxy-groups"], [{"name": "PROXY", "type": "select", "proxies": ["REJECT"]}])
        self.assertEqual(config["rules"], ["MATCH,PROXY"])


if __name__ == "__main__":
    unittest.main()
