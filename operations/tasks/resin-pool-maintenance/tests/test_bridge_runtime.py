"""Unit checks plus opt-in, exclusively loopback, real HAProxy/sing-box validation."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import bridge_runtime as runtime


class RuntimeTests(unittest.TestCase):
    def test_client_maps_only_capacity_errors_to_deferral(self):
        with patch.object(sys, 'argv', ['bridge_runtime.py', 'switch']):
            with patch.object(runtime, 'request', side_effect=RuntimeError(
                    'RuntimeError: generation_capacity_reached: live TCP sessions defer this update')):
                self.assertEqual(runtime.main(), 75)
            with patch.object(runtime, 'request', side_effect=RuntimeError('frontend did not switch to prepared backend')):
                with self.assertRaises(RuntimeError):
                    runtime.main()
            with patch.object(runtime, 'request', side_effect=RuntimeError(
                    'other error: RuntimeError: generation_capacity_reached: live TCP sessions defer this update')):
                with self.assertRaises(RuntimeError):
                    runtime.main()

    def test_capacity_preflight_is_read_only_and_rejects_incomplete_status(self):
        snapshot = {'owner': runtime.OWNER, 'active_generation': 'current',
                    'capacity': 2, 'instances': {'current': {}, 'draining': {}}}
        with patch.object(sys, 'argv', ['bridge_runtime.py', 'capacity']):
            with patch.object(runtime, 'request', return_value=snapshot) as request:
                self.assertEqual(runtime.main(), 75)
                self.assertEqual(request.call_args.args[1], {'command': 'status'})
            with patch.object(runtime, 'request', return_value={**snapshot, 'capacity': 3}):
                self.assertEqual(runtime.main(), 0)
            with patch.object(runtime, 'request', return_value={**snapshot, 'active_generation': None}):
                with self.assertRaises(RuntimeError):
                    runtime.main()

    def test_ranges_do_not_expose_unconfigured_ports(self):
        self.assertEqual(runtime.port_ranges([12000, 12001, 12400, 13000]),
                         ["12000-12001", "12400", "13000"])

    def test_unknown_socket_ownership_never_means_idle(self):
        with patch.object(Path, "iterdir", side_effect=PermissionError):
            self.assertIsNone(runtime.connection_count(12345))

    def test_runtime_loopback_is_allowed_but_external_or_duplicate_is_not(self):
        row = {"type": "socks", "listen": "127.76.0.2", "listen_port": 12000}
        self.assertEqual(runtime.configured_listeners({"inbounds": [row]}), {("127.76.0.2", 12000)})
        for rows in ([row, row], [dict(row, listen="0.0.0.0")], [dict(row, listen="8.8.8.8")]):
            with self.assertRaises(ValueError):
                runtime.configured_listeners({"inbounds": rows})


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(4096):
            self.request.sendall(data)


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


@unittest.skipUnless(os.environ.get("BRIDGE_RUNTIME_INTEGRATION") == "1", "opt-in local integration")
class LiveRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bridge-runtime-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = self.root / "run"
        self.echo = EchoServer(("127.0.0.1", 0), Echo)
        self.addCleanup(self.echo.server_close)
        threading.Thread(target=self.echo.serve_forever, daemon=True).start()
        self.addCleanup(self.echo.shutdown)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.config = {"log": {"disabled": True}, "inbounds": [{"type": "socks", "tag": "test",
                       "listen": "127.0.0.1", "listen_port": self.port}],
                       "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}
        self.promote("generation-1")
        self.log = (self.root / "supervisor.log").open("w")
        self.addCleanup(self.log.close)
        self.process = subprocess.Popen([sys.executable, runtime.__file__, "serve", "--root", str(self.root),
                                         "--runtime-dir", str(self.run)], stdout=self.log, stderr=self.log)
        self.addCleanup(runtime.Runtime.stop_process, self.process)
        for _ in range(200):
            if (self.run / "control.sock").exists():
                break
            if self.process.poll() is not None:
                self.fail((self.root / "supervisor.log").read_text())
            time.sleep(0.1)
        else:
            self.fail("runtime did not start")

    def promote(self, name, invalid=False):
        directory = self.root / "generations" / name
        directory.mkdir(parents=True, exist_ok=True)
        config = dict(self.config, outbounds=[{"type": "invalid"}]) if invalid else self.config
        data = json.dumps(config).encode()
        (directory / "bridge.json").write_bytes(data)
        (directory / "manifest.json").write_text(json.dumps({"owner": "resin-pool-maintenance",
                                                            "config_sha256": hashlib.sha256(data).hexdigest()}))
        staged = self.root / "current.next"
        staged.symlink_to(directory)
        os.replace(staged, self.root / "current")

    def call(self, command):
        return runtime.request(self.run / "control.sock", {"command": command})

    def connect(self):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        self.addCleanup(sock.close)
        sock.sendall(b"\x05\x01\x00")
        self.assertEqual(sock.recv(2), b"\x05\x00")
        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + self.echo.server_address[1].to_bytes(2, "big"))
        response = sock.recv(10)
        self.assertEqual(response[:2], b"\x05\x00")
        return sock

    def exchange(self, sock, text):
        sock.sendall(text)
        self.assertEqual(sock.recv(len(text)), text)

    def test_long_connection_survives_two_switches_rollback_and_failed_candidate(self):
        held = self.connect()
        self.exchange(held, b"before")
        frontend = self.call("status")["frontend_pid"]
        for name in ("generation-2", "generation-3"):
            self.promote(name)
            self.assertEqual(self.call("switch")["status"], "switched")
            self.exchange(held, name.encode())
            with self.connect() as new:
                self.exchange(new, b"new-connection")
            self.assertEqual(self.call("status")["frontend_pid"], frontend)
        self.promote("generation-invalid", invalid=True)
        with self.assertRaises(RuntimeError):
            self.call("switch")
        self.exchange(held, b"failed-candidate-keeps-traffic")
        self.promote("generation-1")
        self.call("switch")
        self.exchange(held, b"rollback")
        self.assertEqual(self.call("status")["active_generation"], "generation-1")

    def test_capacity_defers_update_then_recovers_after_user_sessions_drain(self):
        held = [self.connect()]
        for number in range(2, 5):
            self.promote(f"generation-{number}")
            self.call("switch")
            held.append(self.connect())
        self.promote("generation-5")
        with self.assertRaisesRegex(RuntimeError, "generation_capacity_reached"):
            self.call("switch")
        for sock in held:
            self.exchange(sock, b"capacity-keeps-existing-sessions")
        for sock in held[1:]:
            sock.close()
        deadline = time.monotonic() + 25
        while len(self.call("status")["instances"]) > 2 and time.monotonic() < deadline:
            time.sleep(1)
        self.assertLessEqual(len(self.call("status")["instances"]), 2)
        self.call("switch")
        self.exchange(held[0], b"oldest-session-survives-capacity-recovery")

    def test_active_backend_crash_does_not_kill_healthy_draining_sessions(self):
        held = self.connect()
        self.promote("generation-2")
        self.call("switch")
        before = self.call("status")
        pid = before["instances"]["generation-2"]["pid"]
        os.kill(pid, signal.SIGKILL)
        deadline = time.monotonic() + 20
        while self.call("status")["instances"]["generation-2"]["pid"] == pid and time.monotonic() < deadline:
            time.sleep(1)
        after = self.call("status")
        self.assertNotEqual(after["instances"]["generation-2"]["pid"], pid)
        self.assertEqual(after["frontend_pid"], before["frontend_pid"])
        self.exchange(held, b"healthy-old-generation-survives-other-process-crash")
        with self.connect() as new:
            self.exchange(new, b"recovered")


if __name__ == "__main__":
    unittest.main()
