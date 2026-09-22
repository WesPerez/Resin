import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import unified_quality as QUALITY
import rotation_pool as POOL
from test_rotation_pool import slots
from test_site_quality import approval, client_report, report, NOW


class UnifiedQualityTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.audit_path = Path(temporary.name) / "audits.json"
        self.audit = dict(slots()["US-01"], platform_id="audit", platform_name="BrowseCheckUS", uuid="audit")
        self.audit_path.write_text(json.dumps({"us": self.audit}))
        self.rotation = SimpleNamespace(CONTROL=SimpleNamespace(CLIENT=Mock()))
        self.rotation.CONTROL.CLIENT.subscription_config.return_value = {
            "proxies": [{"name": "weesai.com-vless-443-ws"}], "dns": {"enable": True}}
        self.patches = []
        self.rounds = []

    def check(self, failed_round=None):
        def browser(rotation, config, name, candidate, route_role="public"):
            number = len(self.rounds) + 1
            self.rounds.append((route_role, config["proxies"][0]["uuid"]))
            value = client_report(report(NOW - 400 + number * 80, NOW - 350 + number * 80))
            value["selected"] = name
            value["route_role"] = route_role
            value["nodes"][0]["selected"] = name
            if number == failed_round:
                value["nodes"][0]["passed"] = False
                value["nodes"][0]["sites"]["linux.do"]["verdict"] = "challenge"
            return value, self.audit_path.parent / f"report-{number}.json"

        with patch.object(POOL, "AUDIT_SLOTS", self.audit_path), \
                patch.object(POOL, "load_state", return_value={"approved": {}}), \
                patch.object(QUALITY, "patch_route", side_effect=lambda api, slot, row: self.patches.append(slot["platform_id"])), \
                patch.object(QUALITY, "browser_round", side_effect=browser), \
                patch.object(QUALITY.time, "time", return_value=NOW):
            return QUALITY.qualify(self.rotation, slots(), "US-01", dict(approval(), passed=True), Mock())

    def test_replacement_does_not_touch_public_slot_until_two_passes(self):
        value, reports = self.check(failed_round=2)
        self.assertIsNone(value)
        self.assertEqual(self.patches, ["audit"])
        self.assertEqual(self.rounds, [("audit", "audit"), ("audit", "audit")])

    def test_replacement_checks_real_public_uuid_before_approval(self):
        value, reports = self.check()
        self.assertEqual(self.patches, ["audit", "1"])
        self.assertEqual(self.rounds[-1], ("public", slots()["US-01"]["uuid"]))
        self.assertEqual(len(reports), 3)
        self.assertEqual(len(value["site_quality"]["reports"]), 2)

    def test_public_route_failure_cannot_approve(self):
        value, reports = self.check(failed_round=3)
        self.assertIsNone(value)

    def test_ambiguous_route_is_closed(self):
        api = Mock()
        api.call.return_value = {"name": self.audit["platform_name"], "region_filters": ["us"],
            "regex_filters": QUALITY.site_policy.filters(approval()), "routable_node_count": 2,
            "allocation_policy": "PREFER_LOW_LATENCY", "passive_circuit_breaker_disabled": True}
        with self.assertRaises(RuntimeError):
            QUALITY.patch_route(api, self.audit, approval())
        self.assertEqual(api.call.call_args.args[-1], {"regex_filters": QUALITY.site_policy.DENY})

    def test_failed_exit_cannot_return_under_a_different_slot(self):
        row = dict(approval(), passed=True)
        state = {"approved": {"US-02": row},
                 "quarantined": {row["expected_ip"]: {"until": NOW + 60}}}
        with patch.object(POOL, "site_qualified", return_value=True), \
                patch.object(POOL.site_policy, "STATE", self.audit_path.parent / "missing"), \
                patch.object(POOL.site_policy, "effective", return_value={"us": row}):
            self.assertEqual(POOL.effective(state, slots(), {}, [], NOW, require_sites=True), {})
            state["quarantined"] = {}
            row["checked_at"] = NOW - 65 * 60
            self.assertEqual(set(POOL.effective(state, slots(), {}, [], NOW, require_sites=True)), {"US-02"})

    def test_prior_page_passes_are_prioritized_but_do_not_bypass_cooldown(self):
        proven = approval()
        untested = dict(proven, port=12002, node_hash="c" * 32, expected_ip="9.9.9.9")
        path = self.audit_path.parent / "prior.json"
        path.write_text(json.dumps(client_report(report(NOW - 300, NOW - 200))))
        failures = {QUALITY.key(proven): {"reports": [str(path)], "until": NOW - 1}}
        state = {"approved": {}, "site_failures": failures}
        rows = [untested, proven]
        nodes = [dict(row, egress_ip=row["expected_ip"]) for row in rows]
        self.rotation.CONTROL.REGIONS = SimpleNamespace(
            eligible=lambda node, region: node["region"] == region,
            reference_score=lambda node: 1,
            bridge_port=lambda node: node["port"])
        api = Mock()
        api.nodes.return_value = nodes
        with patch.object(POOL, "effective", return_value={}), \
                patch.object(POOL, "blocked_ips", return_value=set()), \
                patch.object(QUALITY.site_policy, "bridge_identities", return_value={r["port"]: r["slot_identity"] for r in rows}), \
                patch.object(QUALITY.site_policy, "effective", return_value={}), \
                patch.object(QUALITY.site_policy, "load_state", return_value={"approved": {}}), \
                patch.object(QUALITY.time, "time", return_value=NOW):
            selected = QUALITY.candidates(self.rotation, {"US-01": slots()["US-01"]}, state, api)
            self.assertEqual(selected[0][1]["expected_ip"], proven["expected_ip"])
            failures[QUALITY.key(proven)]["until"] = NOW + 60
            selected = QUALITY.candidates(self.rotation, {"US-01": slots()["US-01"]}, state, api)
            self.assertEqual(selected[0][1]["expected_ip"], untested["expected_ip"])
        self.assertEqual(QUALITY.prior_passes(untested, failures), 0)

    def test_failure_invalidates_earlier_passing_round(self):
        row = approval()
        path = self.audit_path.parent / "old-pass.json"
        path.write_text(json.dumps(client_report(report(NOW - 300, NOW - 200))))
        row["site_quality"] = {"reports": [str(path)]}
        self.assertEqual(QUALITY.prior_passes(row, {}, NOW), 1)
        failures = {QUALITY.key(row): {"checked_at": NOW - 100, "reports": [str(path)]}}
        self.assertEqual(QUALITY.prior_passes(row, failures, NOW), 0)
        self.assertEqual(QUALITY.prior_passes(row, {}, NOW + POOL.QUALITY_TTL), 0)

    def test_untested_candidate_precedes_fast_failed_candidate_after_cooldown(self):
        failed = approval()
        fresh = dict(failed, port=12002, node_hash="c" * 32, expected_ip="9.9.9.9")
        rows = [failed, fresh]
        state = {"approved": {}, "site_failures": {
            QUALITY.key(failed): {"checked_at": NOW - 400, "until": NOW - 1}}}
        self.rotation.CONTROL.REGIONS = SimpleNamespace(
            eligible=lambda node, region: node["region"] == region,
            reference_score=lambda node: node["port"], bridge_port=lambda node: node["port"])
        api = Mock()
        api.nodes.return_value = [dict(row, egress_ip=row["expected_ip"]) for row in rows]
        with patch.object(POOL, "effective", return_value={}), \
                patch.object(POOL, "blocked_ips", return_value=set()), \
                patch.object(QUALITY.site_policy, "bridge_identities", return_value={r["port"]: r["slot_identity"] for r in rows}), \
                patch.object(QUALITY.site_policy, "effective", return_value={}), \
                patch.object(QUALITY.site_policy, "load_state", return_value={"approved": {}}), \
                patch.object(QUALITY.time, "time", return_value=NOW):
            selected = QUALITY.candidates(self.rotation, {"US-01": slots()["US-01"]}, state, api)
        self.assertEqual(selected[0][1]["expected_ip"], fresh["expected_ip"])

    def test_faster_alias_cannot_hide_a_previously_verified_route(self):
        proven = approval()
        alias = dict(proven, port=12002, node_hash="c" * 32)
        independent = dict(proven, port=12003, node_hash="d" * 32, expected_ip="9.9.9.9")
        rows = [alias, independent, proven]
        nodes = [dict(row, egress_ip=row["expected_ip"], reference_latency_ms=index)
                 for index, row in enumerate(rows, 1)]
        path = self.audit_path.parent / "prior-alias.json"
        path.write_text(json.dumps(client_report(report(NOW - 300, NOW - 200))))
        state = {"approved": {}, "site_failures": {
            QUALITY.key(proven): {"reports": [str(path)], "until": NOW - 1}}}
        self.rotation.CONTROL.REGIONS = SimpleNamespace(
            shortlist=Mock(return_value=nodes[:2]),
            eligible=lambda node, region: node["region"] == region,
            reference_score=lambda node: node["reference_latency_ms"],
            bridge_port=lambda node: node["port"])
        api = Mock()
        api.nodes.return_value = nodes
        with patch.object(POOL, "effective", return_value={}), \
                patch.object(POOL, "blocked_ips", return_value=set()), \
                patch.object(QUALITY.site_policy, "bridge_identities", return_value={r["port"]: r["slot_identity"] for r in rows}), \
                patch.object(QUALITY.site_policy, "effective", return_value={}), \
                patch.object(QUALITY.site_policy, "load_state", return_value={"approved": {}}), \
                patch.object(QUALITY.time, "time", return_value=NOW):
            selected = QUALITY.candidates(self.rotation, slots(), state, api)
        self.assertEqual([row["port"] for _, row in selected], [proven["port"], independent["port"]])
        self.assertEqual(len({row["expected_ip"] for _, row in selected}), 2)


class CandidateScheduleTest(unittest.TestCase):
    def test_new_exit_gets_a_turn_before_routine_renewals_fill_the_batch(self):
        verified = {f"US-{n:02d}": {"site_quality": {"checked_at": NOW - 35 * 60}}
                    for n in range(1, 9)}
        ordered = [(name, row) for name, row in verified.items()]
        ordered.extend([(name, {}) for name in ("HK-01", "SG-01")])
        result = QUALITY.schedule_candidates(ordered, verified, NOW)
        self.assertEqual([name for name, _ in result[:6]],
                         ["HK-01", "SG-01", "US-01", "US-02", "US-03", "US-04"])
        self.assertCountEqual([name for name, _ in result], [name for name, _ in ordered])

    def test_near_expiry_renewals_stay_ahead_of_new_candidates(self):
        verified = {"US-01": {"site_quality": {"checked_at": NOW - 80 * 60}},
                    "SG-01": {"site_quality": {"checked_at": NOW - 75 * 60}},
                    "US-02": {"site_quality": {"checked_at": NOW - 40 * 60}}}
        ordered = [(name, row) for name, row in verified.items()] + [("HK-01", {})]
        result = QUALITY.schedule_candidates(ordered, verified, NOW)
        self.assertEqual([name for name, _ in result], ["US-01", "SG-01", "HK-01", "US-02"])

    def test_new_budget_does_not_displace_expiring_approvals_from_limited_batch(self):
        verified = {f"US-{n:02d}": {"site_quality": {"checked_at": NOW - 80 * 60}}
                    for n in range(1, 9)}
        ordered = list(verified.items()) + [("HK-01", {}), ("SG-01", {})]
        result = QUALITY.schedule_candidates(ordered, verified, NOW)
        self.assertEqual([name for name, _ in result[:8]], list(verified))
        self.assertCountEqual([name for name, _ in result], [name for name, _ in ordered])

    def test_region_deficit_prioritizes_available_capacity(self):
        verified = {"JP-01": {"region": "jp"}}
        self.assertGreater(QUALITY.region_gain(("US-01", {"region": "us"}), verified),
                           QUALITY.region_gain(("DE-01", {"region": "de"}), verified))
        verified.update({f"US-{n:02d}": {"region": "us"} for n in range(1, 9)})
        self.assertEqual(QUALITY.region_gain(("US-01", {"region": "us"}), verified), 0)

    def test_empty_or_one_sided_queues_preserve_order(self):
        additions = [("US-01", {}), ("HK-01", {})]
        self.assertEqual(QUALITY.schedule_candidates([], {}, NOW), [])
        self.assertEqual(QUALITY.schedule_candidates(additions, {}, NOW), additions)
        verified = {name: {"site_quality": {"checked_at": NOW - 40 * 60}} for name, _ in additions}
        renewals = list(verified.items())
        self.assertEqual(QUALITY.schedule_candidates(renewals, verified, NOW), renewals)


class EvidenceRetentionTest(unittest.TestCase):
    def test_retention_preserves_references_recent_files_and_unowned_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_dir, browser_dir = root / "state", root / "browser"
            state_dir.mkdir()
            browser_dir.mkdir()
            old = NOW - 49 * 3600

            def artifact(path, content="{}"):
                path.parent.mkdir(exist_ok=True)
                path.write_text(content)
                os.utime(path, (old, old))
                os.utime(path.parent, (old, old))
                return path

            raw = artifact(browser_dir / "unified-site-1" / "report.json")
            approval = artifact(state_dir / "unified-client-1.json", json.dumps({"raw_report": str(raw)}))
            failed = artifact(browser_dir / "unified-site-2" / "report.json")
            expired = artifact(browser_dir / "unified-site-3" / "report.json")
            log = artifact(state_dir / "rotation-client-1.log", "client log")
            unowned = artifact(state_dir / "site-approved.json")
            recent = artifact(state_dir / "unified-client-2.json")
            os.utime(recent, (NOW, NOW))
            active = artifact(browser_dir / "unified-site-4" / "report.json")
            os.utime(active, (NOW, NOW))
            linked = state_dir / "rotation-client-2.log"
            linked.symlink_to(unowned)
            state = {"approved": {"US-01": {"site_quality": {"reports": [str(approval)]}}},
                     "site_failures": {"failed": {"reports": [str(failed)]}}}
            self.assertEqual(QUALITY.prune_evidence(state, state_dir, browser_dir, NOW), 2)
            self.assertFalse(expired.parent.exists())
            self.assertFalse(log.exists())
            for path in (raw, approval, failed, unowned, recent, active, linked):
                self.assertTrue(path.exists(), str(path))

    def test_unreadable_reference_aborts_pruning(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "unified-client-1.json"
            report.write_text("invalid json")
            with self.assertRaises(ValueError):
                QUALITY.prune_evidence({"reports": [str(report)]}, root, root, NOW)


if __name__ == "__main__":
    unittest.main()
