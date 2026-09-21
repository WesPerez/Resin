import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

spec = importlib.util.spec_from_file_location("client_health", Path(__file__).with_name("client-health.py"))
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)


class ClientHealthTests(unittest.TestCase):
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
