import datetime as dt
import io
import importlib.util
import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "resin_egress_guard.py"
SPEC = importlib.util.spec_from_file_location("resin_egress_guard", MODULE_PATH)
assert SPEC and SPEC.loader
guard_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = guard_module
SPEC.loader.exec_module(guard_module)


class FakeClient:
    def __init__(self, node_hash="a" * 64):
        self.node_hash = node_hash
        self.deleted = []

    def get_lease(self, platform_id, account):
        if not self.node_hash:
            return None
        return {
            "platform_id": platform_id,
            "account": account,
            "node_hash": self.node_hash,
            "egress_ip": "198.51.100.1",
            "created_at_ns": "123456789",
        }

    def delete_lease(self, platform_id, account):
        self.deleted.append((platform_id, account))
        self.node_hash = ""
        return "deleted"

    def rotate_lease(self, platform_id, account, **kwargs):
        self.rotated = getattr(self, "rotated", [])
        self.rotated.append((platform_id, account, kwargs))
        self.node_hash = "b" * 64
        return "rotated"


def make_guard(tmp: Path):
    platform = guard_module.PlatformConfig("aedc2fe9-c7eb-464e-b3f9-908dc9429dd7", "AppsGlobal")
    instance = guard_module.InstanceConfig("unified", "http://proxy.internal:10834", "unused", (platform,))
    limits = guard_module.Limits(
        min_interval=dt.timedelta(seconds=30),
        burst_window=dt.timedelta(minutes=15),
        burst_max=3,
        account_cooldown=dt.timedelta(hours=1),
        ambiguous_window=dt.timedelta(seconds=60),
        ambiguous_threshold=2,
        platform_guard_window=dt.timedelta(seconds=60),
        platform_guard_account_limit=20,
        platform_guard_cooldown=dt.timedelta(minutes=5),
    )
    guard = object.__new__(guard_module.Guard)
    guard.config = {"evidence_window_seconds": 300}
    guard.instances = {"unified": instance}
    guard.clients = {"unified": FakeClient()}
    guard.platforms = {("unified", platform.id): platform}
    guard.platform_names = {("unified", platform.name): platform}
    guard.endpoints = {("proxy.internal", 10834): "unified"}
    guard.limits = limits
    guard.state_path = tmp / "state.json"
    guard.state = guard_module.new_state()
    guard.state_lock = guard_module.threading.RLock()
    guard.account_locks = tuple(guard_module.threading.Lock() for _ in range(64))
    guard.active_accounts = {}
    guard.confirm_write = True
    guard.persist_state = True
    guard.stop_event = guard_module.threading.Event()
    guard.sub2_config = {}
    guard.sub2_profiles = ()
    guard.last_sub2_poll_monotonic = 0.0
    guard.sub2_forward_tail = None
    guard.sub2_admin = None
    return guard, platform


def forward_log_line(account_id: int, request_id: str, when: dt.datetime | None = None) -> str:
    timestamp = guard_module.isoformat(when or guard_module.utc_now())
    payload = {
        "account_id": account_id,
        "client_request_id": request_id,
        "stream": True,
        "error": guard_module.SUB2_FORWARD_ERROR,
    }
    return f"{timestamp}\tINFO\tgateway\topenai.forward_failed\t{json.dumps(payload)}"


def upstream_status_log_line(account_id=2323, request_id="request-524", status=524, when=None,
                             event="gateway.failover_switch_account", **changes):
    payload = {"account_id": account_id, "client_request_id": request_id, "upstream_status": status}
    payload.update(changes)
    timestamp = guard_module.isoformat(when or guard_module.utc_now())
    return f"{timestamp}\tWARN\thandler/failover_loop.go:199\t{event}\t{json.dumps(payload)}"


class GuardTests(unittest.TestCase):
    def test_unmanaged_platform_does_not_block_poll_watermark(self):
        with tempfile.TemporaryDirectory() as directory:
            guard, platform = make_guard(Path(directory))
            row = {"id": "unmanaged-event", "ts": guard_module.isoformat(guard_module.utc_now()),
                   "net_ok": False, "platform_id": "other-platform", "platform_name": "BrowseUS",
                   "account": "example", "node_hash": "a" * 64, "resin_error": "connect_failed"}
            guard.clients["unified"].list_logs = mock.Mock(return_value=[row])
            result = guard.poll_resin_once()
            self.assertEqual(result, {"evidence": 0, "deleted": 0, "errors": 0})
            self.assertIn("last_success_at", guard.state["poll"]["unified"])
            self.assertFalse(guard.state["handled"])
            self.assertFalse(guard.clients["unified"].deleted)

    def test_known_platform_identity_mismatch_remains_an_error(self):
        for known_id in (True, False):
            with self.subTest(known_id=known_id), tempfile.TemporaryDirectory() as directory:
                guard, platform = make_guard(Path(directory))
                row = {"id": "mismatch", "ts": guard_module.isoformat(guard_module.utc_now()),
                       "net_ok": False, "platform_id": platform.id if known_id else "changed-id",
                       "platform_name": "changed-name" if known_id else platform.name,
                       "account": "example", "node_hash": "a" * 64, "resin_error": "connect_failed"}
                guard.clients["unified"].list_logs = mock.Mock(return_value=[row])
                result = guard.poll_resin_once()
                self.assertEqual(result["errors"], 1)
                self.assertNotIn("unified", guard.state["poll"])
                self.assertFalse(guard.clients["unified"].deleted)

    def test_log_queries_isolate_each_platform_and_its_cursor(self):
        platforms = (guard_module.PlatformConfig("first-id", "AppsGlobal"),
                     guard_module.PlatformConfig("second-id", "AppsCN"))
        client = object.__new__(guard_module.ResinClient)
        client.config = guard_module.InstanceConfig("test", "http://internal:10834", "unused", platforms)
        client._json = mock.Mock(side_effect=[
            {"items": [{"id": "a"}], "has_more": True, "next_cursor": "first-cursor"},
            {"items": [{"id": "b"}], "has_more": False},
            {"items": [{"id": "c"}], "has_more": False},
        ])
        rows = client.list_logs(guard_module.utc_now(), 3, 20)
        queries = [guard_module.urllib.parse.parse_qs(guard_module.urllib.parse.urlsplit(call.args[1]).query)
                   for call in client._json.call_args_list]
        self.assertEqual([query["platform_id"] for query in queries], [["first-id"], ["first-id"], ["second-id"]])
        self.assertNotIn("cursor", queries[0])
        self.assertEqual(queries[1]["cursor"], ["first-cursor"])
        self.assertNotIn("cursor", queries[2])
        self.assertEqual([row["id"] for row in rows], ["a", "b", "c"])

    def test_feedback_listeners_support_multiple_private_addresses(self):
        self.assertEqual(
            ("172.17.0.1", "172.20.0.1"),
            guard_module.parse_feedback_listeners({
                "listen_addresses": ["172.17.0.1", "172.20.0.1"],
            }),
        )
        self.assertEqual(
            ("127.0.0.1",),
            guard_module.parse_feedback_listeners({"listen": "127.0.0.1"}),
        )
        with self.assertRaises(guard_module.GuardError):
            guard_module.parse_feedback_listeners({
                "listen_addresses": ["172.17.0.1", "172.17.0.1"],
            })

    def test_proxy_internal_must_resolve_only_to_private_addresses(self):
        private = [(guard_module.socket.AF_INET, guard_module.socket.SOCK_STREAM, 6, "", ("172.17.0.1", 10834))]
        public = [(guard_module.socket.AF_INET, guard_module.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 10834))]
        with mock.patch.object(guard_module.socket, "getaddrinfo", return_value=private):
            self.assertEqual(
                guard_module.validate_private_base_url("http://proxy.internal:10834"),
                "http://proxy.internal:10834",
            )
        with mock.patch.object(guard_module.socket, "getaddrinfo", return_value=public):
            with self.assertRaises(guard_module.GuardError):
                guard_module.validate_private_base_url("http://proxy.internal:10834")
        with self.assertRaises(guard_module.GuardError):
            guard_module.validate_private_base_url("http://example.com:10834")

    def test_delete_race_reports_lease_absent(self):
        client = object.__new__(guard_module.ResinClient)
        client._request = mock.Mock(return_value=(404, b""))
        client.platform_exists = mock.Mock(return_value=True)
        self.assertEqual(client.delete_lease("platform", "account"), "lease_absent")

    def test_delete_404_distinguishes_missing_platform(self):
        client = object.__new__(guard_module.ResinClient)
        client._request = mock.Mock(return_value=(404, b""))
        client.platform_exists = mock.Mock(return_value=False)
        self.assertEqual(client.delete_lease("platform", "account"), "platform_not_found")

    def test_delete_404_uses_nested_resin_error_message(self):
        client = object.__new__(guard_module.ResinClient)
        client._request = mock.Mock(return_value=(
            404, b'{"error":{"code":"NOT_FOUND","message":"platform not found"}}',
        ))
        client.platform_exists = mock.Mock()
        self.assertEqual(client.delete_lease("platform", "account"), "platform_not_found")
        client.platform_exists.assert_not_called()

    def test_delete_5xx_is_transient(self):
        client = object.__new__(guard_module.ResinClient)
        client.config = guard_module.InstanceConfig("unified", "http://127.0.0.1", "unused", ())
        client._request = mock.Mock(return_value=(503, b"{}"))
        with self.assertRaises(guard_module.GuardError):
            client.delete_lease("platform", "account")

    def test_precise_matching_node_is_deleted(self):
        with tempfile.TemporaryDirectory() as raw:
            guard, platform = make_guard(Path(raw))
            event = guard_module.Event(
                incident_id="resin:unified:1",
                occurred_at=guard_module.utc_now(),
                source="resin_request_log",
                instance="unified",
                platform_id=platform.id,
                platform_name=platform.name,
                account="sub2-42",
                kind="upstream_connect_failed",
                node_hash="a" * 64,
            )
            self.assertEqual(guard.process_event(event)["status"], "deleted")
            self.assertEqual(guard.clients["unified"].deleted, [(platform.id, "sub2-42")])

    def test_stale_node_does_not_delete_new_lease(self):
        with tempfile.TemporaryDirectory() as raw:
            guard, platform = make_guard(Path(raw))
            event = guard_module.Event(
                incident_id="resin:unified:2",
                occurred_at=guard_module.utc_now(),
                source="resin_request_log",
                instance="unified",
                platform_id=platform.id,
                platform_name=platform.name,
                account="sub2-42",
                kind="upstream_connect_failed",
                node_hash="b" * 64,
            )
            self.assertEqual(guard.process_event(event)["status"], "stale_node")
            self.assertEqual(guard.clients["unified"].deleted, [])

    def test_observe_only_does_not_delete_lease(self):
        with tempfile.TemporaryDirectory() as raw:
            guard, platform = make_guard(Path(raw))
            guard.confirm_write = False
            event = guard_module.Event(
                incident_id="resin:unified:observe",
                occurred_at=guard_module.utc_now(),
                source="resin_request_log",
                instance="unified",
                platform_id=platform.id,
                platform_name=platform.name,
                account="sub2-42",
                kind="upstream_connect_failed",
                node_hash="a" * 64,
            )
            self.assertEqual(guard.process_event(event)["status"], "observe_only")
            self.assertEqual(guard.clients["unified"].deleted, [])

    def test_ambiguous_copy_requires_two_events(self):
        with tempfile.TemporaryDirectory() as raw:
            guard, platform = make_guard(Path(raw))
            first = guard_module.Event(
                incident_id="resin:unified:a",
                occurred_at=guard_module.utc_now(),
                source="resin_request_log",
                instance="unified",
                platform_id=platform.id,
                platform_name=platform.name,
                account="sub2-42",
                kind="eof",
                node_hash="a" * 64,
                ambiguous=True,
            )
            second = guard_module.Event(**{**first.__dict__, "incident_id": "resin:unified:b"})
            self.assertEqual(guard.process_event(first)["status"], "awaiting_confirmation")
            self.assertEqual(guard.process_event(second)["status"], "deleted")

    def test_feedback_rejects_generic_403_kind(self):
        with tempfile.TemporaryDirectory() as raw:
            guard, _ = make_guard(Path(raw))
            with self.assertRaises(guard_module.GuardError):
                guard.feedback_event({
                    "version": 1,
                    "event_id": "0c16ea1c-4458-4249-9617-cf0d5f62628c",
                    "proxy_host": "proxy.internal",
                    "proxy_port": 10834,
                    "platform": "AppsGlobal",
                    "account": "sub2-42",
                    "kind": "http_403",
                })

    def test_sub2_ignores_gateway_status_and_accepts_oauth_transport(self):
        now = guard_module.utc_now()
        profile = guard_module.Sub2Profile(
            key="global",
            instance="unified",
            platform_id="aedc2fe9-c7eb-464e-b3f9-908dc9429dd7",
            platform_name="AppsGlobal",
            proxy_host="proxy.internal",
            proxy_port=10834,
            username_template="sub2-{account_id}",
        )
        gateway_prefix = now.isoformat() + "\tINFO\topenai.upstream_failover_switching\t"
        gateway = {
            "account_id": 42,
            "request_id": "req-1",
            "proxy_host": "proxy.internal",
            "proxy_port": 10834,
            "proxy_name": "global",
            "proxy_username": "AppsGlobal.sub2-42",
        }
        for status in (429, 502, 504, 524):
            self.assertIsNone(guard_module.parse_sub2_line(
                gateway_prefix + json.dumps({**gateway, "upstream_status": status}),
                [profile], now, dt.timedelta(minutes=15),
            ))

        oauth_prefix = now.isoformat() + "\tERROR\ttoken_refresh.retry_exhausted\t"
        accepted = guard_module.parse_sub2_line(
            oauth_prefix + json.dumps({
                "account_id": 42,
                "platform": "grok",
                "error": "grok_oauth_request_failed auth.x.ai/oauth2/token: TLS handshake timeout",
            }),
            [profile], now, dt.timedelta(minutes=15),
        )
        self.assertIsNotNone(accepted)
        self.assertEqual(accepted.kind, "oauth_tls_timeout")

    def test_feedback_rejects_gateway_statuses(self):
        with tempfile.TemporaryDirectory() as raw:
            guard, _ = make_guard(Path(raw))
            for kind in ("gateway_502", "gateway_504", "gateway_524", "upstream_524"):
                with self.assertRaises(guard_module.GuardError):
                    guard.feedback_event({
                        "version": 1,
                        "event_id": "0c16ea1c-4458-4249-9617-cf0d5f62628c",
                        "proxy_host": "proxy.internal",
                        "proxy_port": 10834,
                        "platform": "AppsGlobal",
                        "account": "sub2-42",
                        "kind": kind,
                        "source": "metapi",
                    })

    def test_feedback_requires_an_allowed_source(self):
        with tempfile.TemporaryDirectory() as raw:
            guard, _ = make_guard(Path(raw))
            payload = {
                "version": 1,
                "event_id": "0c16ea1c-4458-4249-9617-cf0d5f62628c",
                "proxy_host": "proxy.internal",
                "proxy_port": 10834,
                "platform": "AppsGlobal",
                "account": "sub2-42",
                "kind": "transport_connect",
            }
            with self.assertRaises(guard_module.GuardError):
                guard.feedback_event(payload)
            accepted = guard.feedback_event({**payload, "source": "sub2api"})
            self.assertEqual(accepted.source, "sub2api")

    def test_sub2_poll_uses_the_stricter_guard_evidence_window(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            guard, platform = make_guard(root)
            occurred_at = guard_module.utc_now() - dt.timedelta(minutes=10)
            payload = {
                "account_id": 42,
                "request_id": "old-request",
                "upstream_status": 502,
                "proxy_host": "proxy.internal",
                "proxy_port": 10834,
                "proxy_name": "global",
                "proxy_username": "AppsGlobal.sub2-42",
            }
            log_path = root / "sub2api.log"
            log_path.write_text(
                occurred_at.isoformat()
                + "\tINFO\topenai.upstream_failover_switching\t"
                + json.dumps(payload)
                + "\n",
                encoding="utf-8",
            )
            guard.sub2_config = {
                "enabled": True,
                "poll_interval_seconds": 1,
                "path": str(log_path),
                "tail_bytes": 4096,
                "evidence_window_seconds": 900,
            }
            guard.sub2_profiles = (
                guard_module.Sub2Profile(
                    key="global",
                    instance="unified",
                    platform_id=platform.id,
                    platform_name=platform.name,
                    proxy_host="proxy.internal",
                    proxy_port=10834,
                    username_template="sub2-{account_id}",
                ),
            )

            self.assertEqual(
                {"evidence": 0, "deleted": 0, "errors": 0},
                guard.poll_sub2_once(),
            )


class Sub2ForwardTests(unittest.TestCase):
    def profile(self):
        return guard_module.Sub2Profile(
            key="global",
            instance="unified",
            platform_id="aedc2fe9-c7eb-464e-b3f9-908dc9429dd7",
            platform_name="AppsGlobal",
            proxy_host="proxy.internal",
            proxy_port=10834,
            username_template="AppsGlobal.sub2-{account_id}",
            proxy_id=387,
            proxy_name="Global",
            target_host="api.openai.com",
        )

    def log_line(self, now, **changes):
        payload = {
            "account_id": 2300,
            "client_request_id": "client-request-1",
            "request_id": "request-1",
            "stream": True,
            "error": guard_module.SUB2_FORWARD_ERROR,
        }
        payload.update(changes)
        return "\t".join((
            now.isoformat(),
            "ERROR",
            "handler/openai_gateway_handler.go:755",
            "openai.forward_failed",
            json.dumps(payload),
        ))

    def account(self, account_id=2300, parent=None, proxy_id=387, username=None, proxy_updated=None):
        return {
            "id": account_id,
            "parent_account_id": parent,
            "proxy_id": proxy_id,
            "updated_at": guard_module.isoformat(guard_module.utc_now()),
            "proxy": {
                "id": proxy_id,
                "name": "Global",
                "host": "proxy.internal",
                "port": 10834,
                "username": username or "AppsGlobal.sub2-2300",
                "status": "active",
                "updated_at": guard_module.isoformat(proxy_updated or (guard_module.utc_now() - dt.timedelta(days=1))),
            },
        }

    def test_parser_accepts_exact_signal_and_rejects_near_matches(self):
        now = guard_module.utc_now()
        signal = guard_module.parse_sub2_forward_failed_line(
            self.log_line(now), now, dt.timedelta(minutes=5)
        )
        self.assertIsNotNone(signal)
        self.assertEqual(signal.account_id, 2300)
        self.assertEqual(signal.request_id, "client-request-1")
        for changes in (
            {"stream": False},
            {"error": "stream usage incomplete"},
            {"account_id": None},
            {"client_request_id": "", "request_id": ""},
            {"account_id": True},
        ):
            self.assertIsNone(guard_module.parse_sub2_forward_failed_line(
                self.log_line(now, **changes), now, dt.timedelta(minutes=5)
            ))
        fallback = guard_module.parse_sub2_forward_failed_line(
            self.log_line(now, client_request_id="", request_id="server-request"),
            now,
            dt.timedelta(minutes=5),
        )
        self.assertEqual(fallback.request_id, "server-request")
        self.assertIsNone(guard_module.parse_sub2_forward_failed_line(
            self.log_line(now - dt.timedelta(minutes=6)), now, dt.timedelta(minutes=5)
        ))

    def test_parser_ignores_http_status_events_including_524(self):
        now = guard_module.utc_now()
        window = dt.timedelta(minutes=5)
        for event in (
            "gateway.failover_switch_account", "gateway.failover_same_account_retry",
            "openai.upstream_failover_switching", "openai.pool_mode_same_account_retry",
            "openai_messages.upstream_failover_switching", "openai_messages.pool_mode_same_account_retry",
            "openai.websocket_upstream_failover_switching",
        ):
            for status in (502, 503, 504, 524):
                with self.subTest(event=event, status=status):
                    self.assertIsNone(guard_module.parse_sub2_forward_failed_line(
                        upstream_status_log_line(event=event, status=status, when=now), now, window,
                    ))
        for changes in (
            {"status": 200}, {"status": 401}, {"status": 403}, {"status": 429},
            {"status": 500}, {"status": 502}, {"status": 503}, {"status": 504},
            {"status": "524"}, {"status": 524.5}, {"status": True}, {"status": None},
            {"event": "http request completed"}, {"event": "openai.forward_failed"},
            {"event": "unknown", "error": "upstream returned 524"},
            {"account_id": None}, {"account_id": True}, {"request_id": ""},
            {"when": now - dt.timedelta(minutes=6)}, {"when": now + dt.timedelta(minutes=3)},
        ):
            with self.subTest(changes=changes):
                self.assertIsNone(guard_module.parse_sub2_forward_failed_line(
                    upstream_status_log_line(**changes), now, window,
                ))

    def test_524_cannot_be_reclassified_as_missing_terminal(self):
        now = guard_module.utc_now()
        self.assertIsNone(guard_module.parse_sub2_forward_failed_line(
            self.log_line(now, upstream_status=524), now, dt.timedelta(minutes=5),
        ))

    def test_legacy_524_signal_never_looks_up_an_account(self):
        signal = guard_module.Sub2ForwardSignal("signal", guard_module.utc_now(), 2300, "req", "upstream_524", 524)
        admin = mock.Mock()
        self.assertIsNone(guard_module.resolve_sub2_forward_signal(signal, admin, [self.profile()]))
        admin.get_account.assert_not_called()

    def test_log_tail_starts_at_eof_and_handles_partial_lines(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "sub2api.log"
            path.write_text("old\n", encoding="utf-8")
            tail = guard_module.Sub2LogTail(path)
            tail.start()
            self.assertEqual(tail.poll(), [])
            with path.open("ab") as handle:
                handle.write(b"new-part")
                handle.flush()
            self.assertEqual(tail.poll(), [])
            with path.open("ab") as handle:
                handle.write(b"-rest\n")
                handle.flush()
            self.assertEqual(tail.poll(), ["new-part-rest"])
            tail.close()

    def test_log_tail_drains_renamed_file_before_new_file(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / "sub2api.log"
            path.write_bytes(b"")
            tail = guard_module.Sub2LogTail(path)
            tail.start()
            old_handle = path.open("ab")
            old_handle.write(b"L1\nL2-part")
            old_handle.flush()
            self.assertEqual(tail.poll(), ["L1"])
            rotated = root / "sub2api-rotated.log"
            path.rename(rotated)
            path.write_bytes(b"L3\n")
            old_handle.write(b"-rest\n")
            old_handle.flush()
            old_handle.close()
            self.assertEqual(tail.poll(), ["L2-part-rest", "L3"])
            tail.close()

    def test_log_tail_recovers_missing_file_copytruncate_and_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "sub2api.log"
            tail = guard_module.Sub2LogTail(path)
            tail.start()
            self.assertEqual(tail.poll(), [])
            path.write_bytes(b"created\xff\n")
            self.assertEqual(tail.poll(), ["created\ufffd"])
            with path.open("ab") as handle:
                handle.write(b"discard-part")
                handle.flush()
            self.assertEqual(tail.poll(), [])
            with path.open("r+b") as handle:
                handle.truncate(0)
                handle.write(b"after-truncate\n")
                handle.flush()
            self.assertEqual(tail.poll(), ["after-truncate"])
            tail.close()

    def test_log_tail_enforces_per_poll_budget_across_rotation(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / "sub2api.log"
            path.write_bytes(b"")
            tail = guard_module.Sub2LogTail(path, max_read_bytes=1024)
            tail.start()
            old = path.open("ab")
            old.write((b"a" * 600) + b"\n")
            old.flush()
            path.rename(root / "old.log")
            path.write_bytes((b"b" * 600) + b"\n")
            self.assertEqual([len(line) for line in tail.poll()], [600])
            old.close()
            self.assertEqual([len(line) for line in tail.poll()], [600])
            tail.close()

    def test_pending_forward_lines_survive_state_reload(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "state.json"
            state = guard_module.new_state()
            state["forward_pending"] = ["one", "two"]
            guard_module.atomic_write_json(path, state)
            pending = guard_module.load_state(path)["forward_pending"]
            self.assertEqual([item["line"] for item in pending], ["one", "two"])
            self.assertTrue(all(item["retry_count"] == 0 for item in pending))
            guard_module.atomic_write_json(path, {**state, "forward_pending": pending})
            self.assertEqual(guard_module.load_state(path)["forward_pending"], pending)

    def test_pending_state_rejects_malformed_structured_entry(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "state.json"
            state = guard_module.new_state()
            state["forward_pending"] = [{"line": "one", "retry_count": -1}]
            guard_module.atomic_write_json(path, state)
            with self.assertRaises(guard_module.GuardError):
                guard_module.load_state(path)

    def test_resolver_normalizes_shadow_and_checks_proxy_update(self):
        now = guard_module.utc_now()
        signal = guard_module.Sub2ForwardSignal("signal", now, 9999, "req")
        accounts = {9999: self.account(9999, parent=2300), 2300: self.account()}
        admin = mock.Mock()
        admin.get_account.side_effect = accounts.__getitem__
        event = guard_module.resolve_sub2_forward_signal(signal, admin, [self.profile()])
        self.assertIsNotNone(event)
        self.assertEqual(event.account, "sub2-2300")
        accounts[2300] = self.account(proxy_updated=now + dt.timedelta(seconds=1))
        self.assertIsNone(guard_module.resolve_sub2_forward_signal(signal, admin, [self.profile()]))

    def test_resolver_rejects_proxy_identity_and_status_mismatch(self):
        now = guard_module.utc_now()
        signal = guard_module.Sub2ForwardSignal("signal", now, 2300, "req")
        for changed in (
            {"proxy_id": 999},
            {"username": "AppsGlobal.sub2-999"},
            {"status": "disabled"},
        ):
            account = self.account(proxy_id=changed.get("proxy_id", 387), username=changed.get("username"))
            if "status" in changed:
                account["proxy"]["status"] = changed["status"]
            admin = mock.Mock()
            admin.get_account.return_value = account
            self.assertIsNone(guard_module.resolve_sub2_forward_signal(signal, admin, [self.profile()]))

    def test_forward_event_rotates_once_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as raw:
            guard, platform = make_guard(Path(raw))
            guard.clients["unified"].get_lease = mock.Mock(return_value={
                "platform_id": platform.id,
                "account": "sub2-2300",
                "node_hash": "a" * 64,
                "egress_ip": "198.51.100.1",
                "created_at_ns": "123456789",
            })
            event = guard_module.Event(
                incident_id="sub2:forward:2300:req",
                occurred_at=guard_module.utc_now(),
                source="sub2api_forward",
                instance="unified",
                platform_id=platform.id,
                platform_name=platform.name,
                account="sub2-2300",
                kind="missing_terminal",
                target_host="api.openai.com",
                rotate=True,
            )
            self.assertEqual(guard.process_event(event)["status"], "rotated")
            self.assertEqual(guard.process_event(event)["status"], "duplicate")
            call = guard.clients["unified"].rotated[0]
            self.assertEqual(call[1], "sub2-2300")
            self.assertEqual(call[2]["expected_created_at_ns"], "123456789")
            self.assertEqual(call[2]["expected_egress_ip"], "198.51.100.1")
            self.assertFalse(call[2]["preserve_connections"])

    def test_observe_only_never_posts_rotate(self):
        with tempfile.TemporaryDirectory() as raw:
            guard, platform = make_guard(Path(raw))
            guard.confirm_write = False
            guard.clients["unified"].get_lease = mock.Mock(return_value={
                "platform_id": platform.id, "account": "sub2-2300",
                "node_hash": "a" * 64, "created_at_ns": "123",
                "egress_ip": "198.51.100.1",
            })
            guard.clients["unified"].rotate_lease = mock.Mock()
            event = guard_module.Event(
                "observe", guard_module.utc_now(), "sub2api_forward", "unified",
                platform.id, platform.name, "sub2-2300", "missing_terminal",
                target_host="api.openai.com", rotate=True,
            )
            self.assertEqual(guard.process_event(event)["status"], "observe_only")
            guard.clients["unified"].rotate_lease.assert_not_called()


class APIClientTests(unittest.TestCase):
    def resin_client(self):
        client = object.__new__(guard_module.ResinClient)
        client.config = guard_module.InstanceConfig("unified", "http://127.0.0.1", "unused", ())
        return client

    def test_resin_rotate_maps_all_expected_statuses(self):
        client = self.resin_client()
        cases = (
            (409, {"status": "stale_lease"}, "stale_lease"),
            (422, {"status": "no_alternative"}, "no_alternative"),
            (200, {"status": "no_alternative"}, "no_alternative"),
            (404, {}, "lease_absent"),
            (400, {}, "invalid_request"),
        )
        for status, body, expected in cases:
            client._request = mock.Mock(return_value=(status, json.dumps(body).encode()))
            client.platform_exists = mock.Mock(return_value=True)
            self.assertEqual(client.rotate_lease(
                "platform", "account", expected_node_hash="a" * 32,
                expected_egress_ip="198.51.100.1", expected_created_at_ns="123",
                target_host="api.openai.com",
            ), expected)
        client._request = mock.Mock(return_value=(503, b"{}"))
        with self.assertRaises(guard_module.GuardError):
            client.rotate_lease(
                "platform", "account", expected_node_hash="a" * 32,
                expected_egress_ip="198.51.100.1", expected_created_at_ns="123",
                target_host="api.openai.com",
            )

    def test_preserving_rotation_never_falls_back_to_forced_close(self):
        client = self.resin_client()
        client._request = mock.Mock(return_value=(400, b'{}'))
        with self.assertRaisesRegex(guard_module.GuardError, "connection-preserving rotation unavailable"):
            client.rotate_lease(
                "platform", "account", expected_node_hash="a" * 32,
                expected_egress_ip="198.51.100.1", expected_created_at_ns="123",
                target_host="api.justwoker.icu", preserve_connections=True,
            )
        client._request.assert_called_once()
        self.assertTrue(client._request.call_args.args[2]["preserve_connections"])

    def test_preserving_rotation_requires_zero_closed_connections(self):
        lease = {
            "platform_id": "platform", "account": "account", "node_hash": "b" * 32,
            "egress_ip": "198.51.100.2", "created_at_ns": "456",
        }
        for closed in (None, True, "0", 1, 0):
            with self.subTest(closed=closed):
                client = self.resin_client()
                client._request = mock.Mock(return_value=(200, json.dumps({
                    "status": "rotated", "lease": lease, "closed_connections": closed,
                }).encode()))
                client.get_lease = mock.Mock(return_value=lease)
                args = dict(expected_node_hash="a" * 32, expected_egress_ip="198.51.100.1",
                            expected_created_at_ns="123", target_host="api.justwoker.icu",
                            preserve_connections=True)
                if type(closed) is int and closed == 0:
                    self.assertEqual(client.rotate_lease("platform", "account", **args), "rotated")
                    client.get_lease.assert_called_once()
                else:
                    with self.assertRaisesRegex(guard_module.GuardError, "did not confirm"):
                        client.rotate_lease("platform", "account", **args)

    def test_resin_rotate_requires_new_node_and_egress_ip(self):
        client = self.resin_client()
        def response(node, ip, **changes):
            lease = {
                "platform_id": "platform", "account": "account", "node_hash": node,
                "egress_ip": ip, "created_at_ns": "456",
            }
            lease.update(changes)
            return 200, json.dumps({"status": "rotated", "lease": lease}).encode()
        replacement = response("b" * 32, "198.51.100.2")
        client._request = mock.Mock(side_effect=[
            replacement,
            (200, json.dumps(json.loads(replacement[1])["lease"]).encode()),
        ])
        self.assertEqual(client.rotate_lease(
            "platform", "account", expected_node_hash="a" * 32,
            expected_egress_ip="198.51.100.1", expected_created_at_ns="123",
            target_host="api.openai.com",
        ), "rotated")
        for bad in (
            response("a" * 32, "198.51.100.2"),
            response("b" * 32, "198.51.100.1"),
            response("b" * 32, "198.51.100.2", account="other"),
            response("b" * 32, "198.51.100.2", created_at_ns="123"),
        ):
            client._request = mock.Mock(return_value=bad)
            with self.assertRaises(guard_module.GuardError):
                client.rotate_lease(
                    "platform", "account", expected_node_hash="a" * 32,
                    expected_egress_ip="198.51.100.1", expected_created_at_ns="123",
                    target_host="api.openai.com",
                )

    def test_resin_rotate_rejects_followup_get_mismatch(self):
        client = self.resin_client()
        post_lease = {
            "platform_id": "platform", "account": "account", "node_hash": "b" * 32,
            "egress_ip": "198.51.100.2", "created_at_ns": "456",
        }
        persisted = {**post_lease, "node_hash": "c" * 32}
        client._request = mock.Mock(side_effect=[
            (200, json.dumps({"status": "rotated", "lease": post_lease}).encode()),
            (200, json.dumps(persisted).encode()),
        ])
        with self.assertRaises(guard_module.GuardError):
            client.rotate_lease(
                "platform", "account", expected_node_hash="a" * 32,
                expected_egress_ip="198.51.100.1", expected_created_at_ns="123",
                target_host="api.openai.com",
            )

    def test_sub2_admin_url_is_loopback_only(self):
        for value in ("http://127.0.0.1:13080", "http://localhost:13080", "http://[::1]:13080"):
            self.assertEqual(guard_module.validate_sub2_admin_base_url(value), value)
        for value in ("http://0.0.0.0:13080", "http://10.0.0.1:13080", "http://user@127.0.0.1:13080"):
            with self.assertRaises(guard_module.GuardError):
                guard_module.validate_sub2_admin_base_url(value)

    def test_sub2_admin_never_includes_response_or_key_in_errors(self):
        client = guard_module.Sub2AdminClient("http://127.0.0.1:13080", "very-secret", 1)
        error = urllib.error.HTTPError(
            "http://127.0.0.1:13080/api/v1/admin/accounts/1", 500, "bad", {},
            io.BytesIO(b'{"credentials":"leaked-secret"}'),
        )
        client.opener = mock.Mock()
        client.opener.open.side_effect = error
        with self.assertRaises(guard_module.GuardError) as raised:
            client.get_account(1)
        message = str(raised.exception)
        self.assertNotIn("very-secret", message)
        self.assertNotIn("leaked-secret", message)

    def test_sub2_admin_uses_api_key_credential(self):
        client = guard_module.Sub2AdminClient("http://127.0.0.1:13080", "key-value", 1)
        response = mock.MagicMock()
        response.__enter__.return_value.status = 200
        response.__enter__.return_value.read.return_value = b'{"data":{"id":2300}}'
        client.opener = mock.Mock()
        client.opener.open.return_value = response
        client.get_account(2300)
        request = client.opener.open.call_args.args[0]
        self.assertEqual(request.get_header("X-api-key"), "key-value")
        self.assertIsNone(request.get_header("Authorization"))

    def test_sub2_admin_401_does_not_leak_credential_or_body(self):
        client = guard_module.Sub2AdminClient("http://127.0.0.1:13080", "private-key", 1)
        client.opener = mock.Mock()
        client.opener.open.side_effect = urllib.error.HTTPError(
            "http://127.0.0.1:13080/api/v1/admin/accounts/2300", 401, "unauthorized", {},
            io.BytesIO(b'{"error":"body-secret"}'),
        )
        with self.assertRaisesRegex(guard_module.GuardError, "HTTP 401") as raised:
            client.get_account(2300)
        self.assertNotIn("private-key", str(raised.exception))
        self.assertNotIn("body-secret", str(raised.exception))

    def test_sub2_admin_probe_checks_configured_account_identity(self):
        client = guard_module.Sub2AdminClient("http://127.0.0.1:13080", "key-value", 1)
        client.get_account = mock.Mock(return_value={"id": 2300})
        self.assertEqual(client.verify_account_access(2300), {"account_id": 2300})
        client.get_account.assert_called_once_with(2300)


class ForwardPollTests(unittest.TestCase):
    def test_fresh_and_persisted_524_never_rotate_after_upgrade(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            guard, platform, path = self.configure(root)
            line = upstream_status_log_line()
            guard.state["forward_pending"] = [{
                "line": line, "retry_count": 1,
                "first_seen": guard_module.isoformat(guard_module.utc_now()),
                "next_attempt": guard_module.isoformat(guard_module.utc_now() + dt.timedelta(minutes=1)),
            }]
            guard_module.atomic_write_json(root / "state.json", guard.state)
            guard.state = guard_module.load_state(root / "state.json")
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n" + line + "\n")
                handle.write(upstream_status_log_line(event="gateway.failover_same_account_retry") + "\n")
                handle.write(upstream_status_log_line(account_id=2324, status=403) + "\n")
            counts = guard.poll_sub2_forward_once()
            self.assertEqual((counts["evidence"], counts["rotated"], counts["errors"]), (0, 0, 0))
            client = guard.clients["unified"]
            self.assertFalse(getattr(client, "rotated", []))
            self.assertEqual(client.deleted, [])
            guard.sub2_admin.get_account.assert_not_called()
            guard.state = guard_module.load_state(root / "state.json")
            self.assertEqual(guard.state["forward_pending"], [])
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            self.assertEqual(guard.poll_sub2_forward_once()["rotated"], 0)
            self.assertFalse(getattr(client, "rotated", []))
            guard.sub2_forward_tail.close()

    def test_524_event_and_mislabeled_feedback_cannot_touch_a_lease(self):
        for kind, status in (("upstream_524", 0), ("transport_timeout", 524)):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as raw:
                guard, platform = make_guard(Path(raw))
                client = mock.Mock()
                guard.clients["unified"] = client
                event = guard_module.Event(
                    incident_id="http-timeout", occurred_at=guard_module.utc_now(),
                    source="sub2api", instance="unified", platform_id=platform.id,
                    platform_name=platform.name, account="sub2-2323", kind=kind,
                    http_status=status, rotate=kind == "upstream_524",
                )
                self.assertEqual(guard.process_event(event)["status"], "ignored")
                self.assertEqual(client.mock_calls, [])
                self.assertEqual(guard.state["accounts"], {})

    def test_524_observe_cooldown_and_newer_lease_never_rotate(self):
        for mode in ("observe", "cooldown", "newer_lease"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as raw:
                guard, platform, path = self.configure(Path(raw))
                fixtures = Sub2ForwardTests()
                account = fixtures.account(2323, username="AppsGlobal.sub2-2323")
                account["credentials"] = {"base_url": "https://api.justwoker.icu/v1"}
                guard.sub2_profiles = (fixtures.profile(),)
                guard.sub2_admin.get_account.return_value = account
                now = guard_module.utc_now()
                if mode == "observe":
                    guard.confirm_write = False
                elif mode == "cooldown":
                    guard.state["accounts"][f"unified:{platform.id}:sub2-2323"] = {
                        "last_rotation_at": guard_module.isoformat(now),
                    }
                else:
                    lease = guard.clients["unified"].get_lease(platform.id, "sub2-2323")
                    lease["created_at_ns"] = str(int((now + dt.timedelta(seconds=10)).timestamp() * 1_000_000_000))
                    guard.clients["unified"].get_lease = mock.Mock(return_value=lease)
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(upstream_status_log_line(when=now) + "\n")
                counts = guard.poll_sub2_forward_once()
                self.assertEqual((counts["rotated"], counts["errors"]), (0, 0))
                self.assertFalse(getattr(guard.clients["unified"], "rotated", []))
                self.assertEqual(guard.state["forward_pending"], [])
                guard.sub2_forward_tail.close()

    def configure(self, root: Path):
        guard, platform = make_guard(root)
        path = root / "sub2api.log"
        path.write_bytes(b"")
        guard.sub2_forward_tail = guard_module.Sub2LogTail(path)
        guard.sub2_forward_tail.start()
        guard.sub2_admin = mock.Mock()
        guard.sub2_profiles = ()
        guard.sub2_config = {
            "forward_failed": {
                "window_seconds": 300,
                "retry_max_attempts": 2,
                "retry_ttl_seconds": 300,
                "retry_initial_seconds": 1,
                "retry_max_seconds": 2,
            }
        }
        return guard, platform, path

    @mock.patch.object(guard_module, "resolve_sub2_forward_signal")
    def test_transient_admin_failure_is_persisted_and_later_line_continues(self, resolve):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            guard, platform, path = self.configure(root)
            first = guard_module.Event(
                "sub2:forward:1:first", guard_module.utc_now(), "sub2api_forward", "unified",
                platform.id, platform.name, "sub2-1", "missing_terminal",
                target_host="api.openai.com", rotate=True,
            )
            second = guard_module.Event(**{**first.__dict__, "incident_id": "sub2:forward:1:second", "account": "sub2-2"})
            resolve.side_effect = [guard_module.GuardError("admin 503"), second]
            with path.open("a", encoding="utf-8") as handle:
                handle.write(forward_log_line(1, "first") + "\n")
                handle.write(forward_log_line(2, "second") + "\n")
            counts = guard.poll_sub2_forward_once()
            self.assertEqual((counts["errors"], counts["rotated"], counts["deferred"]), (1, 1, 1))
            pending = guard.state["forward_pending"]
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]["retry_count"], 1)
            loaded = guard_module.load_state(root / "state.json")
            self.assertEqual(loaded["forward_pending"], pending)
            guard.sub2_forward_tail.close()

    @mock.patch.object(guard_module, "resolve_sub2_forward_signal")
    def test_transient_rotate_failure_dead_letters_at_limit(self, resolve):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            guard, platform, path = self.configure(root)
            event = guard_module.Event(
                "sub2:forward:1:first", guard_module.utc_now(), "sub2api_forward", "unified",
                platform.id, platform.name, "sub2-1", "missing_terminal",
                target_host="api.openai.com", rotate=True,
            )
            resolve.return_value = event
            guard.clients["unified"].rotate_lease = mock.Mock(side_effect=guard_module.GuardError("rotate 503"))
            with path.open("a", encoding="utf-8") as handle:
                handle.write(forward_log_line(1, "first") + "\n")
            first = guard.poll_sub2_forward_once()
            self.assertEqual((first["errors"], first["deferred"]), (1, 1))
            guard.state["forward_pending"][0]["next_attempt"] = guard_module.isoformat(guard_module.utc_now() - dt.timedelta(seconds=1))
            second = guard.poll_sub2_forward_once()
            self.assertEqual((second["errors"], second["dead_lettered"]), (1, 1))
            self.assertEqual(guard.state["forward_pending"], [])
            self.assertEqual(len(guard.state["forward_dead_letters"]), 1)
            self.assertEqual(guard.state["forward_dead_letters"][0]["incident_id"], event.incident_id)
            guard.sub2_forward_tail.close()

    @mock.patch.object(guard_module, "resolve_sub2_forward_signal")
    def test_no_alternative_does_not_block_later_request(self, resolve):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            guard, platform, path = self.configure(root)
            events = [
                guard_module.Event(
                    f"sub2:forward:1:{request_id}", guard_module.utc_now(), "sub2api_forward", "unified",
                    platform.id, platform.name, f"sub2-{index}", "missing_terminal",
                    target_host="api.openai.com", rotate=True,
                )
                for index, request_id in ((1, "first"), (2, "second"))
            ]
            resolve.side_effect = events
            guard.clients["unified"].rotate_lease = mock.Mock(side_effect=["no_alternative", "rotated"])
            with path.open("a", encoding="utf-8") as handle:
                handle.write(forward_log_line(1, "first") + "\n")
                handle.write(forward_log_line(2, "second") + "\n")
            counts = guard.poll_sub2_forward_once()
            self.assertEqual((counts["errors"], counts["rotated"]), (0, 1))
            self.assertEqual(guard.state["forward_pending"], [])
            self.assertIn(events[0].incident_id, guard.state["handled"])
            self.assertIn(events[1].incident_id, guard.state["handled"])
            guard.sub2_forward_tail.close()

    @mock.patch.object(guard_module, "resolve_sub2_forward_signal")
    def test_transient_delete_failure_is_persisted(self, resolve):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            guard, platform, path = self.configure(root)
            event = guard_module.Event(
                "sub2:forward:1:first", guard_module.utc_now(), "sub2api_forward", "unified",
                platform.id, platform.name, "sub2-1", "missing_terminal", rotate=False,
            )
            resolve.return_value = event
            guard.clients["unified"].delete_lease = mock.Mock(side_effect=guard_module.GuardError("delete 503"))
            with path.open("a", encoding="utf-8") as handle:
                handle.write(forward_log_line(1, "first") + "\n")
            counts = guard.poll_sub2_forward_once()
            self.assertEqual((counts["errors"], counts["deferred"]), (1, 1))
            self.assertEqual(guard.state["forward_pending"][0]["retry_count"], 1)
            guard.sub2_forward_tail.close()


class GuardLimitTests(unittest.TestCase):
    def forward_event(self, platform, account="sub2-1", incident="req-1"):
        return guard_module.Event(
            f"sub2:forward:1:{incident}", guard_module.utc_now(), "sub2api_forward", "unified",
            platform.id, platform.name, account, "missing_terminal",
            target_host="api.openai.com", rotate=True,
        )

    def test_persisted_request_id_deduplicates_after_restart(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            guard, platform = make_guard(root)
            event = self.forward_event(platform)
            self.assertEqual(guard.process_event(event)["status"], "rotated")
            state = guard_module.load_state(root / "state.json")
            restarted, _ = make_guard(root)
            restarted.state = state
            self.assertEqual(restarted.process_event(event)["status"], "duplicate")
            self.assertEqual(getattr(restarted.clients["unified"], "rotated", []), [])

    def test_transient_rotate_error_is_not_marked_handled(self):
        with tempfile.TemporaryDirectory() as raw:
            guard, platform = make_guard(Path(raw))
            event = self.forward_event(platform)
            guard.clients["unified"].rotate_lease = mock.Mock(
                side_effect=guard_module.GuardError("temporary rotate failure")
            )
            with self.assertRaises(guard_module.GuardError):
                guard.process_event(event)
            self.assertNotIn(event.incident_id, guard.state["handled"])
            guard.clients["unified"].rotate_lease = FakeClient().rotate_lease
            self.assertEqual(guard.process_event(event)["status"], "rotated")

    def test_no_alternative_is_terminal_for_incident(self):
        with tempfile.TemporaryDirectory() as raw:
            guard, platform = make_guard(Path(raw))
            event = self.forward_event(platform)
            guard.clients["unified"].rotate_lease = mock.Mock(return_value="no_alternative")
            self.assertEqual(guard.process_event(event)["status"], "no_alternative")
            self.assertIn(event.incident_id, guard.state["handled"])
            self.assertEqual(guard.process_event(event)["status"], "duplicate")
            later = self.forward_event(platform, incident="req-2")
            self.assertEqual(guard.process_event(later)["status"], "no_alternative")

    def test_account_limit_and_platform_storm_guard(self):
        with tempfile.TemporaryDirectory() as raw:
            guard, platform = make_guard(Path(raw))
            first = self.forward_event(platform, "sub2-1", "one")
            self.assertEqual(guard.process_event(first)["status"], "rotated")
            second = self.forward_event(platform, "sub2-1", "two")
            limited = guard.process_event(second)
            self.assertEqual((limited["status"], limited["reason"]), ("rate_limited", "min_interval"))

            guard.limits = guard_module.Limits(
                min_interval=dt.timedelta(seconds=1), burst_window=dt.timedelta(minutes=15),
                burst_max=3, account_cooldown=dt.timedelta(hours=1),
                ambiguous_window=dt.timedelta(minutes=1), ambiguous_threshold=2,
                platform_guard_window=dt.timedelta(minutes=1), platform_guard_account_limit=1,
                platform_guard_cooldown=dt.timedelta(minutes=5),
            )
            guard.clients["unified"] = FakeClient()
            self.assertEqual(guard.process_event(self.forward_event(platform, "sub2-2", "three"))["status"], "rate_limited")


class DurableRecoveryTests(unittest.TestCase):
    def test_newly_created_log_is_replayed_after_checkpoint_write_failure(self):
        with tempfile.TemporaryDirectory() as raw:
            guard, _, path = ForwardPollTests().configure(Path(raw))
            guard.sub2_forward_tail.close()
            path.unlink()
            guard.sub2_forward_tail = guard_module.Sub2LogTail(path)
            guard.sub2_forward_tail.start()
            guard.poll_sub2_forward_once()
            guard.sub2_admin.get_account.side_effect = guard_module.GuardError("admin unavailable")
            path.write_text(forward_log_line(1, "first-created") + "\n")
            with mock.patch.object(guard_module, "atomic_write_json", side_effect=OSError("disk unavailable")):
                self.assertEqual(guard.poll_sub2_forward_once()["errors"], 1)
            self.assertEqual(guard.poll_sub2_forward_once()["evidence"], 1)
            self.assertEqual(len(guard.state["forward_pending"]), 1)
            guard.sub2_forward_tail.close()

    def test_slow_lease_lookup_does_not_hold_global_state_lock(self):
        with tempfile.TemporaryDirectory() as raw:
            guard, platform = make_guard(Path(raw))
            entered = guard_module.threading.Event()
            release = guard_module.threading.Event()
            event = GuardLimitTests().forward_event(platform)
            lease = guard.clients["unified"].get_lease(platform.id, event.account)

            def lookup(*args):
                entered.set()
                release.wait(2)
                return lease

            guard.clients["unified"].get_lease = lookup
            thread = guard_module.threading.Thread(target=guard.process_event, args=(event,))
            thread.start()
            try:
                self.assertTrue(entered.wait(1))
                acquired = guard.state_lock.acquire(timeout=0.2)
                self.assertTrue(acquired)
                if acquired:
                    guard.state_lock.release()
            finally:
                release.set()
                thread.join(2)
            self.assertFalse(thread.is_alive())

    def test_cursor_recovers_partial_line_and_events_written_during_restart(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "sub2api.log"
            path.write_bytes(b"old\n")
            tail = guard_module.Sub2LogTail(path)
            tail.start()
            with path.open("ab") as handle:
                handle.write(b"first\npart")
            self.assertEqual(tail.poll(), ["first"])
            checkpoint = tail.snapshot()
            tail.close()
            with path.open("ab") as handle:
                handle.write(b"ial\nunread\n")
            restored = guard_module.Sub2LogTail(path, checkpoint=checkpoint)
            restored.start()
            self.assertEqual(restored.poll(), ["partial", "unread"])
            restored.close()

    def test_cursor_recovers_rotated_file_without_joining_partial_to_new_file(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "sub2api.log"
            path.write_bytes(b"")
            tail = guard_module.Sub2LogTail(path)
            tail.start()
            checkpoint = tail.snapshot()
            tail.close()
            path.rename(path.with_name("sub2api-rotated.log"))
            path.with_name("sub2api-rotated.log").write_bytes(b"old-final\nincomplete")
            path.write_bytes(b"new-first\n")
            restored = guard_module.Sub2LogTail(path, checkpoint=checkpoint)
            restored.start()
            self.assertEqual(restored.poll(), ["old-final", "new-first"])
            restored.close()

    def test_copytruncate_regrowth_and_oversized_line_are_bounded(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "sub2api.log"
            path.write_bytes(b"old\n")
            tail = guard_module.Sub2LogTail(path, max_read_bytes=1024)
            tail.start()
            path.write_bytes(b"replacement-longer-than-original\n")
            self.assertEqual(tail.poll(), ["replacement-longer-than-original"])
            with mock.patch.object(guard_module, "MAX_FORWARD_LINE_CHARS", 32):
                with path.open("ab") as handle:
                    handle.write(b"x" * 100)
                self.assertEqual(tail.poll(), [])
                self.assertLessEqual(len(tail.buffer), 32)
                checkpoint = tail.snapshot()
                tail.close()
                with path.open("ab") as handle:
                    handle.write(b"x\nvalid\n")
                tail = guard_module.Sub2LogTail(path, checkpoint=checkpoint)
                tail.start()
                self.assertEqual(tail.poll(), ["valid"])
                tail.close()

    def test_initial_partial_line_is_not_treated_as_a_new_event(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "sub2api.log"
            path.write_bytes(b"old partial")
            tail = guard_module.Sub2LogTail(path)
            tail.start()
            with path.open("ab") as handle:
                handle.write(b" remainder\nnew\n")
            self.assertEqual(tail.poll(), ["new"])
            tail.close()

    def test_queue_and_cursor_commit_together_and_skip_idle_writes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            guard, _, path = ForwardPollTests().configure(root)
            guard.poll_sub2_forward_once()
            with mock.patch.object(guard_module, "atomic_write_json") as write:
                guard.poll_sub2_forward_once()
                write.assert_not_called()
            with path.open("a") as handle:
                handle.write(forward_log_line(1, "durable") + "\n")
                handle.write("unrelated private log text\n")
            guard.sub2_admin.get_account.side_effect = guard_module.GuardError("admin 503")
            with mock.patch.object(guard_module, "atomic_write_json", side_effect=OSError("disk unavailable")):
                self.assertEqual(guard.poll_sub2_forward_once()["errors"], 1)
            counts = guard.poll_sub2_forward_once()
            self.assertEqual(counts["evidence"], 1)
            persisted = guard_module.load_state(root / "state.json")
            self.assertEqual(len(persisted["forward_pending"]), 1)
            self.assertEqual(persisted["forward_cursor"], guard.sub2_forward_tail.snapshot())
            self.assertNotIn("private log", json.dumps(persisted))
            guard.sub2_forward_tail.close()
            restarted, _ = make_guard(root)
            restarted.state = persisted
            restarted.sub2_config = guard.sub2_config
            restarted.sub2_admin = guard.sub2_admin
            restarted.sub2_forward_tail = guard_module.Sub2LogTail(path, checkpoint=persisted["forward_cursor"])
            with path.open("a") as handle:
                handle.write(forward_log_line(2, "after-restart") + "\n")
            self.assertEqual(restarted.poll_sub2_forward_once()["evidence"], 1)
            self.assertEqual(len(restarted.state["forward_pending"]), 2)
            restarted.sub2_forward_tail.close()

    def test_successful_post_failed_get_keeps_original_cas_after_restart(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            guard, platform = make_guard(root)
            event = GuardLimitTests().forward_event(platform)
            before = {"platform_id": platform.id, "account": event.account,
                      "node_hash": "a" * 32, "egress_ip": "198.51.100.1",
                      "created_at_ns": str(int(event.occurred_at.timestamp() * 1e9) - 1000)}
            after = {**before, "node_hash": "b" * 32, "egress_ip": "198.51.100.2",
                     "created_at_ns": str(int(before["created_at_ns"]) + 2000)}
            client = object.__new__(guard_module.ResinClient)
            client.config = guard.instances["unified"]
            writes = []
            current = dict(before)
            failed_get = False

            def request(method, path, payload=None):
                nonlocal failed_get
                if method == "GET":
                    if failed_get:
                        failed_get = False
                        return 503, b"{}"
                    return 200, json.dumps(current).encode()
                writes.append(payload)
                if payload["expected_created_at_ns"] != current["created_at_ns"]:
                    return 409, b'{"status":"stale_lease"}'
                current.update(after)
                failed_get = True
                return 200, json.dumps({"status": "rotated", "lease": after}).encode()

            client._request = request
            guard.clients["unified"] = client
            with self.assertRaises(guard_module.GuardError):
                guard.process_event(event)
            restarted, _ = make_guard(root)
            restarted.state = guard_module.load_state(root / "state.json")
            restarted.clients["unified"] = client
            self.assertEqual(restarted.process_event(event)["status"], "stale_lease")
            self.assertEqual(len(writes), 2)
            self.assertEqual(writes[0], writes[1])
            self.assertEqual(current, after)
            self.assertNotIn(event.incident_id, restarted.state["rotation_intents"])

    def test_missing_platform_is_not_reported_as_missing_lease(self):
        client = object.__new__(guard_module.ResinClient)
        client.config = guard_module.InstanceConfig("unified", "http://127.0.0.1", "unused", ())
        client._request = mock.Mock(return_value=(404, b"{}"))
        with self.assertRaisesRegex(guard_module.GuardError, "platform not found"):
            client.get_lease("platform", "account")

    def test_slow_legacy_scan_does_not_delay_forward_polling(self):
        with tempfile.TemporaryDirectory() as raw:
            guard, _ = make_guard(Path(raw))
            entered = guard_module.threading.Event()
            release = guard_module.threading.Event()
            polls = []

            def legacy():
                entered.set()
                release.wait(2)
                return {"evidence": 0}

            def forward():
                self.assertTrue(entered.wait(1))
                polls.append(1)
                if len(polls) == 2:
                    release.set()
                    guard.stop_event.set()
                return {"evidence": 0}

            guard.poll_resin_once = legacy
            guard.poll_sub2_once = lambda: {"evidence": 0}
            guard.poll_sub2_forward_once = forward
            guard.sub2_config = {"forward_failed": {"poll_interval_seconds": 0.05}}
            guard.loop()
            self.assertEqual(len(polls), 2)


if __name__ == "__main__":
    unittest.main()
