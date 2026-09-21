from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import singbox_bridge_pool as bridge


class BridgeReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "current").mkdir()
        self.config = {"inbounds": [
            {"type": "socks", "listen": "172.17.0.1", "listen_port": 12000},
            {"type": "socks", "listen": "172.17.0.1", "listen_port": 12400,
             "users": [{"username": "direct", "password": "private"}]},
        ]}
        (self.root / "current" / "bridge.json").write_text(json.dumps(self.config))
        self.expected = {("172.17.0.1", 12000), ("172.17.0.1", 12400)}
        self.args = argparse.Namespace(output_dir=str(self.root), pid=4242, timeout_seconds=0.3)

    def test_all_configured_listeners_include_direct(self):
        self.assertEqual(bridge.configured_listeners(self.config), self.expected)

    def test_invalid_or_duplicate_listeners_are_rejected(self):
        for row in (
            {"type": "http", "listen": "172.17.0.1", "listen_port": 12000},
            {"type": "socks", "listen": "0.0.0.0", "listen_port": 12000},
            {"type": "socks", "listen": "172.17.0.1", "listen_port": True},
            {"type": "socks", "listen": "172.17.0.1", "listen_port": 65536},
        ):
            with self.subTest(row=row), self.assertRaises(bridge.BridgeError):
                bridge.configured_listeners({"inbounds": [row]})
        with self.assertRaises(bridge.BridgeError):
            bridge.configured_listeners({"inbounds": []})
        with self.assertRaisesRegex(bridge.BridgeError, "duplicate"):
            bridge.configured_listeners({"inbounds": [self.config["inbounds"][0]] * 2})

    def test_listener_table_checks_owner_address_family_and_tcp_state(self):
        (self.root / "fd").mkdir()
        (self.root / "net").mkdir()
        for inode in (123, 456, 789):
            (self.root / "fd" / str(inode)).symlink_to(f"socket:[{inode}]")
        ipv4 = "010011AC" if sys.byteorder == "little" else "AC110001"
        ipv6 = "000000FD000000000000000001000000" if sys.byteorder == "little" else "FD000000000000000000000000000001"
        (self.root / "net" / "tcp").write_text(
            "header\n"
            f"0: {ipv4}:2EE0 00000000:0000 0A 0:0 0:0 0 0 0 123\n"
            f"1: {ipv4}:3070 00000000:0000 0A 0:0 0:0 0 0 0 999\n"
            f"2: {ipv4}:3071 00000000:0000 01 0:0 0:0 0 0 0 456\n"
        )
        (self.root / "net" / "tcp6").write_text(
            f"header\n0: {ipv6}:3070 {ipv6}:0000 0A 0:0 0:0 0 0 0 789\n"
        )
        self.assertEqual(bridge.process_tcp_listeners(self.root),
                         {("172.17.0.1", 12000), ("fd00::1", 12400)})
        (self.root / "net" / "tcp6").unlink()
        self.assertEqual(bridge.process_tcp_listeners(self.root), {("172.17.0.1", 12000)})

    def test_process_identity_handles_spaces_and_parentheses(self):
        fields = ["S", *(["0"] * 18), "12345"]
        (self.root / "stat").write_text("4242 (sing-box (worker)) " + " ".join(fields))
        self.assertEqual(bridge.process_identity(self.root), "12345")
        fields[0] = "Z"
        (self.root / "stat").write_text("4242 (sing-box) " + " ".join(fields))
        with self.assertRaisesRegex(bridge.BridgeError, "exited"):
            bridge.process_identity(self.root)

    @mock.patch.object(bridge, "process_identity", return_value="12345")
    @mock.patch.object(bridge, "process_tcp_listeners")
    def test_waits_for_last_listener_before_reporting_ready(self, listeners, _identity):
        listeners.side_effect = [{("172.17.0.1", 12000)}, self.expected]
        output = io.StringIO()
        with mock.patch.object(bridge.time, "sleep") as sleep, contextlib.redirect_stdout(output):
            self.assertEqual(bridge.command_wait_listeners(self.args), 0)
        sleep.assert_called_once()
        result = json.loads(output.getvalue())
        self.assertEqual(result["listener_count"], 2)
        self.assertEqual(result["status"], "ready")
        self.assertNotIn("private", output.getvalue())

    @mock.patch.object(bridge, "process_identity", return_value="12345")
    @mock.patch.object(bridge, "process_tcp_listeners", return_value=set())
    def test_timeout_fails_when_only_other_processes_own_the_ports(self, _listeners, _identity):
        now = [0.0]
        def advance(seconds):
            now[0] += seconds
        with mock.patch.object(bridge.time, "monotonic", side_effect=lambda: now[0]), \
             mock.patch.object(bridge.time, "sleep", side_effect=advance):
            with self.assertRaisesRegex(bridge.BridgeError, "timed out: missing=2"):
                bridge.command_wait_listeners(self.args)
        self.assertAlmostEqual(now[0], self.args.timeout_seconds)

    def test_exit_or_pid_reuse_fails_before_readiness(self):
        for identities in (
            ["12345", bridge.BridgeError("bridge process unavailable before readiness")],
            ["12345", "67890"],
        ):
            with self.subTest(identities=identities), \
                 mock.patch.object(bridge, "process_identity", side_effect=identities), \
                 mock.patch.object(bridge, "process_tcp_listeners") as listeners:
                with self.assertRaises(bridge.BridgeError):
                    bridge.command_wait_listeners(self.args)
                listeners.assert_not_called()

    def test_invalid_pid_or_timeout_is_rejected(self):
        for pid, timeout in ((0, 60), (1, 60), (4242, 0), (4242, float("nan")), (4242, 121)):
            self.args.pid, self.args.timeout_seconds = pid, timeout
            with self.subTest(pid=pid, timeout=timeout), self.assertRaises(bridge.BridgeError):
                bridge.command_wait_listeners(self.args)


if __name__ == "__main__":
    unittest.main()
