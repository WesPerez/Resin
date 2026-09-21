import json
from pathlib import Path
import tempfile
import unittest

from subscription_metrics import collect


class SubscriptionMetricsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = {name: Path(self.temp.name) / (name + ".json")
                      for name in ("policy", "client", "pools", "bridge", "maintenance")}
        self.write("policy", mode="split")
        self.write("client", finished_at=9990, general={"passed": True}, strict={"passed": True}, inconclusive=False)
        self.write("pools", updated_at=9990, routable={"Global-Auto": 12, "Sites-Verified": 2})
        self.write("bridge", updated_at=9990, active_generation="a", frontend_pid=1, instances={"a": {}}, capacity=4)
        self.write("maintenance", last_run_finished_at="1970-01-01T02:46:30Z", global_status="success", cn_status="success")

    def write(self, name, **value):
        if name == "client":
            value.setdefault("subscription", {"passed": True})
        self.paths[name].write_text(json.dumps(dict(version=1, **value)))

    def collect(self):
        return collect(self.paths, now=10000)

    def codes(self):
        return {row["code"]: row["level"] for row in self.collect()["alerts"]}

    def test_healthy_states_exclude_secrets(self):
        self.assertEqual(self.collect()["alerts"], [])
        self.write("pools", updated_at=9990, routable={"Global-Auto": 12, "Sites-Verified": 2}, secret="do-not-log")
        self.assertNotIn("do-not-log", json.dumps(self.collect()))
        self.write("client", finished_at=9990, general={"passed": "do-not-log"}, inconclusive="do-not-log")
        self.assertNotIn("do-not-log", json.dumps(self.collect()))
        self.assertIn("subscription_client_inconclusive", self.codes())

    def test_missing_and_stale_canary_never_look_healthy(self):
        self.paths["client"].unlink()
        self.assertIn("subscription_client_missing", self.codes())
        self.assertIsNone(self.collect()["client"]["general_passed"])
        self.write("client", finished_at=100, general={"passed": True}, strict={"passed": True})
        self.assertIn("subscription_client_stale", self.codes())

    def test_general_failure_is_critical_strict_failure_is_separate(self):
        self.write("client", finished_at=9990, general={"passed": True}, strict={"passed": False})
        self.assertEqual(self.codes(), {"subscription_strict_probe_failed": "warn"})
        self.write("client", finished_at=9990, general={"passed": False}, strict={"passed": True})
        self.assertEqual(self.codes(), {"subscription_general_probe_failed": "crit"})

    def test_empty_strict_pool_reports_availability_without_duplicate_failed_probe(self):
        self.write("client", finished_at=9990, general={"passed": True},
                   strict={"passed": False, "reason": "strict_pool_empty"}, inconclusive=False)
        self.write("pools", updated_at=9990, routable={"Global-Auto": 12, "Sites-Verified": 0})
        self.assertEqual(self.codes(), {"subscription_strict_count_empty": "warn"})
        self.assertEqual(self.collect()["client"]["strict_status"], "waiting_for_qualified_exit")
        self.write("client", finished_at=9990, general={"passed": False},
                   strict={"passed": False, "reason": "strict_pool_empty"}, inconclusive=False)
        self.assertIn("subscription_general_probe_failed", self.codes())

    def test_transition_and_unknown_capacity_are_explicit(self):
        self.write("client", finished_at=9990, inconclusive=True)
        self.assertIn("subscription_client_inconclusive", self.codes())
        self.paths["pools"].write_text("{invalid")
        self.assertIsNone(self.collect()["pools"]["general_count"])
        self.assertIn("subscription_pools_unreadable_or_invalid", self.codes())

    def test_subscription_download_failure_is_not_hidden_by_working_proxies(self):
        self.write("client", finished_at=9990, general={"passed": True}, strict={"passed": True},
                   subscription={"passed": False})
        self.assertEqual(self.codes(), {"subscription_download_probe_failed": "crit"})

    def test_cn_failure_and_full_bridge_do_not_report_general_outage(self):
        self.write("maintenance", last_run_finished_at=9990, global_status="success", cn_status="failed")
        self.write("bridge", updated_at=9990, active_generation="a", frontend_pid=1,
                   instances={name: {} for name in "abcd"}, capacity=4)
        self.assertEqual(self.codes(), {"subscription_cn_maintenance_failed": "warn"})
        self.assertTrue(self.collect()["bridge"]["waiting_for_connections"])

    def test_deferred_refresh_is_observable_without_hiding_an_unavailable_bridge(self):
        self.write("maintenance", last_run_finished_at=9990, global_status="deferred", cn_status="success")
        self.write("bridge", updated_at=9990, active_generation="a", frontend_pid=1,
                   instances={name: {} for name in "abcd"}, capacity=4)
        self.assertEqual(self.codes(), {})
        self.assertEqual(self.collect()["maintenance"]["global"], "deferred")
        self.assertTrue(self.collect()["bridge"]["waiting_for_connections"])
        self.write("bridge", updated_at=9990, active_generation="missing", frontend_pid=1,
                   instances={name: {} for name in "abcd"}, capacity=4)
        self.assertEqual(self.codes(), {"subscription_bridge_unavailable": "crit"})

    def test_legacy_install_does_not_require_split_files(self):
        for path in self.paths.values():
            path.unlink()
        self.assertFalse(self.collect()["enabled"])
        self.assertEqual(self.codes(), {})


if __name__ == "__main__":
    unittest.main()
