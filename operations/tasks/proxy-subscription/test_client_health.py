import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch
from contextlib import ExitStack

spec = importlib.util.spec_from_file_location("client_health", Path(__file__).with_name("client-health.py"))
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)


class ClientHealthTests(unittest.TestCase):
    def run_canary(self, *, approved=False, general=True, strict=True, subscription=True, general_only=False):
        client = MagicMock()
        client.__enter__.return_value = ("socks5h://example.invalid:1", Mock())
        config = {"proxies": [{"name": "Global-Auto"}, {"name": health.client_pools.STRICT_NAME}]}
        api = SimpleNamespace(nodes=Mock(return_value=[]))
        rotation = SimpleNamespace(client=Mock(return_value=client), CONTROL=SimpleNamespace(
            api_client=Mock(return_value=api), CLIENT=SimpleNamespace(subscription_config=Mock(return_value=config))))
        with ExitStack() as stack:
            stack.enter_context(patch.object(health, "load_rotation", return_value=rotation))
            stack.enter_context(patch.object(health.client_pools, "load", return_value={}))
            stack.enter_context(patch.object(health.rotation_pool, "load_slots", return_value={}))
            stack.enter_context(patch.object(health.rotation_pool, "load_state", return_value={}))
            stack.enter_context(patch.object(health.rotation_pool, "effective", return_value=(
                {"slot": {"expected_ip": "192.0.2.1"}} if approved else {})))
            stack.enter_context(patch.object(health.site_policy, "bridge_identities", return_value={}))
            stack.enter_context(patch.object(health.site_policy, "BRIDGE", Path("/synthetic/generation/config.json")))
            stack.enter_context(patch.object(health, "public_subscription", return_value={"passed": subscription}))
            probe = stack.enter_context(patch.object(health, "probe", side_effect=[{"passed": general}, {"passed": strict}]))
            return health.run(general_only=general_only), probe.call_count

    def test_empty_strict_pool_defers_only_after_general_and_subscription_pass(self):
        report, probes = self.run_canary()
        self.assertEqual(report["status"], "deferred")
        self.assertFalse(report["ok"])
        self.assertFalse(report["strict"]["passed"])
        self.assertTrue(report["strict"]["skipped"])
        self.assertEqual(probes, 1)
        for failure in ({"general": False}, {"subscription": False}):
            report, _ = self.run_canary(**failure)
            self.assertEqual(report["status"], "failed")
            self.assertFalse(report["deferred"])

    def test_qualified_strict_probe_failure_is_not_hidden_and_general_only_still_works(self):
        report, probes = self.run_canary(approved=True, strict=False)
        self.assertEqual(probes, 2)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["deferred"])
        self.assertTrue(self.run_canary(approved=True)[0]["ok"])
        self.assertTrue(self.run_canary(general_only=True)[0]["ok"])

    def test_deferred_command_is_distinct_from_full_acceptance(self):
        report, _ = self.run_canary()
        with patch.object(health, "run", return_value=report), \
                patch.object(health.site_policy, "atomic_json"), \
                patch("sys.argv", ["client-health.py"]), patch("builtins.print"):
            self.assertEqual(health.main(), 75)

    def result(self, first="1.1.1.1", last="1.1.1.1", middle=204, region="US"):
        checks = [({"code": 0, "status": 200, "ms": 100}, f"ip={first}\nloc={region}\n".encode()),
                  ({"code": 0, "status": middle, "ms": 100}, b""),
                  ({"code": 0, "status": 200, "ms": 100}, f"ip={last}\nloc={region}\n".encode())]
        rotation = SimpleNamespace(curl=Mock(side_effect=checks))
        return health.probe(rotation, "socks5h://127.0.0.1:1", {"1.1.1.1"}, True)

    def test_pass_requires_both_real_identity_samples_and_https_quorum(self):
        self.assertTrue(self.result()["passed"])
        self.assertFalse(self.result(first="8.8.8.8", last="8.8.8.8")["passed"])
        self.assertFalse(self.result(last="8.8.8.8")["passed"])
        self.assertFalse(self.result(middle=200)["passed"])
        self.assertFalse(self.result(region="CN")["passed"])

    def test_raw_errors_and_egress_addresses_are_not_in_metric(self):
        result = self.result()
        self.assertNotIn("1.1.1.1", str(result))
        self.assertTrue(all(set(row) == {"code", "status", "ms"} for row in result["checks"]))

    def test_download_requires_public_config_to_match_publication(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = b'proxies: []\n'
        opener = Mock()
        opener.open.return_value = response
        with patch.object(health.urllib.request, "build_opener", return_value=opener):
            path = Mock(read_text=Mock(return_value="https://example.test/private-token"))
            self.assertTrue(health.public_subscription({"proxies": []}, path)["passed"])
            self.assertFalse(health.public_subscription({"proxies": ["expected"]}, path)["passed"])
            opener.open.side_effect = RuntimeError("private-token")
            result = health.public_subscription({"proxies": []}, path)
            self.assertFalse(result["passed"])
            self.assertNotIn("private-token", str(result))


if __name__ == "__main__":
    unittest.main()
