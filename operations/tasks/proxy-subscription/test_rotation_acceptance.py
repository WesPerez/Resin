import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import rotation_pool as POOL
import site_policy
from test_site_quality import approval, client_report, report, NOW

SPEC = importlib.util.spec_from_file_location(
    "rotation_acceptance_test", Path(__file__).with_name("verify-rotation-subscription.py"))
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class AcceptanceFailureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.addCleanup(patch.stopall)
        patch.object(POOL, "STATE", self.root / "state.json").start()
        patch.object(site_policy.time, "time", return_value=NOW).start()
        self.enforce = patch.object(POOL, "enforce", return_value={"US-02": {}}).start()
        self.render = patch.object(VERIFY.CONTROL.CONTROL, "render").start()
        self.api = Mock()
        row = dict(approval(), passed=True, validation_path="subscription")
        other = dict(row, expected_ip="9.9.9.9", port=row["port"] + 1)
        site_policy.atomic_json(POOL.STATE, {"version": 1, "approved": {"US-01": row, "US-02": other}})

    def browser_failure(self, verdict="challenge", finished=NOW - 30):
        checked = client_report(report(finished - 30, finished))
        checked["selected"] = "US-01"
        node = checked["nodes"][0]
        node.update(selected="US-01", passed=False)
        node["sites"]["linux.do"].update(verdict=verdict, http_status=403 if verdict == "challenge" else 0)
        return {"result": checked, "report": str(self.root / "browser.json")}

    def apply(self, browser):
        return VERIFY.record_browser_failure(self.api, browser, self.root / "acceptance.json")

    def test_challenge_is_persisted_enforced_and_republished(self):
        browser = self.browser_failure()
        result = self.apply(browser)
        state = POOL.load_state()
        failed_ip = browser["result"]["nodes"][0]["expected_ip"]
        self.assertTrue(result["recorded"])
        self.assertIn(failed_ip, site_policy.quarantined_ips(state))
        self.assertEqual(state["approved"]["US-01"]["validation_path"], "bridge")
        self.assertEqual(state["approved"]["US-02"]["validation_path"], "subscription")
        self.assertEqual(state["last_failed_acceptance"], str(self.root / "acceptance.json"))
        self.assertEqual(next(iter(state["site_failures"].values()))["reports"], [browser["report"]])
        self.enforce.assert_called_once_with(self.api, state=state)
        self.render.assert_called_once_with()

    def test_first_transient_keeps_approval_and_second_is_quarantined(self):
        self.apply(self.browser_failure("network_error", NOW - 40))
        self.assertEqual(POOL.load_state()["approved"]["US-01"]["validation_path"], "subscription")
        self.apply(self.browser_failure("network_error", NOW - 10))
        self.assertEqual(POOL.load_state()["approved"]["US-01"]["validation_path"], "bridge")

    def test_changed_selection_and_ambiguous_rotation_do_not_write(self):
        baseline = POOL.STATE.read_bytes()
        for field, value in (("selected", "US-02"), ("identity_valid", False)):
            browser = self.browser_failure()
            browser["result"]["nodes"][0][field] = value
            self.assertFalse(self.apply(browser)["recorded"])
        browser = self.browser_failure()
        browser["result"].pop("validation_path")
        self.assertFalse(self.apply(browser)["recorded"])
        self.assertEqual(POOL.STATE.read_bytes(), baseline)
        self.enforce.assert_not_called()
        self.render.assert_not_called()

    def test_success_is_not_reclassified_as_a_failure(self):
        browser = self.browser_failure()
        browser["result"]["nodes"][0]["passed"] = True
        baseline = POOL.STATE.read_bytes()
        self.assertFalse(self.apply(browser)["recorded"])
        self.assertEqual(POOL.STATE.read_bytes(), baseline)

    def test_same_failure_is_idempotent(self):
        browser = self.browser_failure()
        self.apply(browser)
        first = copy.deepcopy(POOL.load_state())
        self.apply(browser)
        self.assertEqual(POOL.load_state()["quarantined"], first["quarantined"])
        self.assertEqual(POOL.load_state()["site_failures"], first["site_failures"])

    def test_persisted_failure_is_republished_when_enforcement_raises(self):
        self.enforce.side_effect = RuntimeError("route update failed")
        with self.assertRaisesRegex(RuntimeError, "route update failed"):
            self.apply(self.browser_failure())
        self.assertEqual(POOL.load_state()["approved"]["US-01"]["validation_path"], "bridge")
        self.render.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
