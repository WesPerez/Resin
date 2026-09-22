from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import sys
import tempfile
import urllib.request
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "lib"
sys.path.insert(0, str(SCRIPTS))
SCRIPT = SCRIPTS / "resin_pool_sync.py"
SPEC = importlib.util.spec_from_file_location("resin_pool_sync_test", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class FakeClient:
    def __init__(self, platform=None):
        self.platform_patches: list[dict[str, object]] = []
        self.platform = dict(platform or {
            "id": "platform",
            "name": "GrokEU",
            "regex_filters": [],
            "region_filters": [],
        })

    def request(self, method, path, body=None):
        if method == "PATCH" and path.startswith("/api/v1/platforms/"):
            self.platform_patches.append(dict(body or {}))
            self.platform.update(dict(body or {}))
            if len(self.platform_patches) == 1:
                return {"id": "platform", "regex_filters": ["unexpected"]}
            return dict(self.platform)
        if method == "GET" and path.startswith("/api/v1/platforms/"):
            return dict(self.platform)
        raise AssertionError((method, path, body))


class ResinPoolSyncTests(unittest.TestCase):
    def test_global_non_empty_mode_ignores_legacy_count_and_ratio_fields(self):
        config = {
            "selection": {"max_nodes": 1000},
            "safety": {
                "mode": "non_empty",
                "min_selected": 999,
                "min_passed": 999,
                "min_ratio_to_previous": 1.0,
            },
        }
        MODULE.fail_closed_guards(
            config,
            {"selected_count": 1, "passed_count": 1},
            {"selected_count": 1000},
        )
        self.assertEqual(MODULE.minimum_active_node_count(config, {"selected_count": 1000}), 1)

    def test_global_non_empty_mode_rejects_empty_or_over_limit_pool(self):
        config = {"selection": {"max_nodes": 1000}, "safety": {"mode": "non_empty"}}
        with self.assertRaisesRegex(MODULE.SyncError, "non-empty"):
            MODULE.fail_closed_guards(
                config, {"selected_count": 0, "passed_count": 0}, {}
            )
        with self.assertRaisesRegex(MODULE.SyncError, "1000-node"):
            MODULE.fail_closed_guards(
                config, {"selected_count": 1001, "passed_count": 1001}, {}
            )

    def test_global_non_empty_mode_allows_probe_results_above_publish_capacity(self):
        config = {"selection": {"max_nodes": 1000}, "safety": {"mode": "non_empty"}}
        MODULE.fail_closed_guards(
            config,
            {"selected_count": 1000, "passed_count": 2000},
            {},
        )

    def test_safety_mode_is_required(self):
        with self.assertRaisesRegex(MODULE.SyncError, "safety.mode is required"):
            MODULE.fail_closed_guards(
                {"selection": {"max_nodes": 1000}},
                {"selected_count": 1, "passed_count": 1},
                {},
            )

    def test_cn_gate_retains_count_and_ratio_protection(self):
        config = {
            "selection": {"max_nodes": 4},
            "safety": {
                "mode": "cn_gate",
                "min_selected": 2,
                "min_passed": 2,
                "min_ratio_to_previous": 0.5,
            },
        }
        with self.assertRaisesRegex(MODULE.SyncError, "CN pool gate"):
            MODULE.fail_closed_guards(
                config, {"selected_count": 1, "passed_count": 1}, {"selected_count": 4}
            )

    def test_resin_base_url_rejects_public_http_and_url_components(self):
        client = MODULE.ResinClient("http://127.0.0.1:10833", "secret")
        self.assertEqual(client.base_url, "http://127.0.0.1:10833")
        for base_url in (
            "http://localhost:10833",
            "http://8.8.8.8:10833",
            "http://user@127.0.0.1:10833",
            "http://:secret@127.0.0.1:10833",
            "http://127.0.0.1:10833?tenant=prod",
            "http://127.0.0.1:10833#admin",
        ):
            with self.subTest(base_url=base_url):
                with self.assertRaises(MODULE.SyncError):
                    MODULE.ResinClient(base_url, "secret")

    def test_admin_redirect_handler_rejects_redirect_before_following(self):
        request = urllib.request.Request(
            "http://127.0.0.1:10833/api/v1/health",
            headers={"Authorization": "Bearer secret"},
        )
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code):
                with self.assertRaisesRegex(MODULE.SyncError, "redirects are not allowed"):
                    MODULE.NoRedirectHandler().redirect_request(
                        request,
                        None,
                        code,
                        "Redirect",
                        {"Location": "http://127.0.0.1:10834/"},
                        "http://127.0.0.1:10834/",
                    )
        self.assertEqual(request.get_header("Authorization"), "Bearer secret")

    def test_subscription_patch_defaults_keep_alive_nodes_and_ephemeral(self):
        patch = MODULE.subscription_patch_from_config({}, "proxy-content")
        self.assertTrue(patch["incremental_alive_nodes"])
        self.assertTrue(patch["ephemeral"])
        self.assertEqual(patch["ephemeral_node_evict_delay"], "72h")

    def test_resin_identity_count_matches_parser_semantics(self):
        content = (
            "socks5://127.0.0.1:12000\n"
            "socks5h://127.0.0.1:12000\n"
            "# ignored\n"
            "http://127.0.0.1:12001\n"
        )
        identities, lines = MODULE.resin_proxy_identities(content)
        self.assertEqual(lines, 3)
        self.assertEqual(len(identities), 2)
        expected, reported = MODULE.derive_expected_resin_node_count(
            content, {"selected_count": 3}
        )
        self.assertEqual((expected, reported), (2, 3))

    def test_expected_resin_node_count_rejects_report_line_mismatch(self):
        with self.assertRaisesRegex(MODULE.SyncError, "line count does not match"):
            MODULE.derive_expected_resin_node_count(
                "socks5h://127.0.0.1:12000\n",
                {"selected_count": 2},
            )

    def test_subscription_node_state_uses_live_api_counts(self):
        for active, evicted in [(0, 0), (2, 1), (0, 3)]:
            with self.subTest(active=active, evicted=evicted):
                self.assertEqual(MODULE.subscription_node_state({
                    "managed_node_count": active + evicted,
                    "node_count": active, "evicted_node_count": evicted,
                }), (active + evicted, evicted))

    def test_subscription_node_state_rejects_legacy_and_invalid_counts(self):
        valid = {"managed_node_count": 3, "evicted_node_count": 1, "node_count": 2}
        for field in valid:
            for value in [None, True, "1", 1.5, -1]:
                with self.subTest(field=field, value=value):
                    with self.assertRaisesRegex(MODULE.SyncError, "valid live node counts"):
                        MODULE.subscription_node_state({**valid, field: value})
        for invalid in [{}, {"node_count": 2},
                        {**valid, "evicted_node_count": 4},
                        {**valid, "managed_node_count": 4}]:
            with self.subTest(invalid=invalid):
                with self.assertRaises(MODULE.SyncError):
                    MODULE.subscription_node_state(invalid)

    def test_verify_subscription_allows_only_historical_evicted_deficit(self):
        content = "socks5h://127.0.0.1:12000\n"
        digest = MODULE.sha256_bytes(content.encode())

        class Client:
            def __init__(self, rows):
                self.rows = list(rows)
                self.index = 0

            def request(self, method, path):
                if method != "GET" or path != "/api/v1/subscriptions/subscription":
                    raise AssertionError((method, path))
                row = dict(self.rows[min(self.index, len(self.rows) - 1)])
                self.index += 1
                return row

        def run(client, **kwargs):
            with mock.patch.object(MODULE.time, "sleep"), mock.patch.object(
                MODULE.time, "monotonic", side_effect=iter([0.0, 0.0, 0.1, 0.1, 0.2, 0.2])
            ):
                return MODULE.verify_subscription(
                    client,
                    "subscription",
                    digest,
                    2,
                    allow_additional_nodes=False,
                    timeout=0.15,
                    settle_reads=2,
                    **kwargs,
                )

        base = {"id": "subscription", "content": content, "last_error": ""}
        accepted = run(
            Client([{**base, "node_count": 1}]),
            max_evicted_nodes=1,
            minimum_node_count=1,
        )
        self.assertEqual(accepted["node_count"], 1)

        with self.assertRaisesRegex(MODULE.SyncError, "expected exactly 2 nodes"):
            run(
                Client([{**base, "node_count": 1}]),
                max_evicted_nodes=0,
                minimum_node_count=1,
            )

        with self.assertRaisesRegex(MODULE.SyncError, "expected between 1 and 2 nodes"):
            run(
                Client([{**base, "node_count": 3}]),
                max_evicted_nodes=1,
                minimum_node_count=1,
            )

    def test_verify_subscription_requires_settled_reads(self):
        content = "socks5h://127.0.0.1:12000\n"
        digest = MODULE.sha256_bytes(content.encode())

        class Client:
            def __init__(self):
                self.rows = [
                    {"id": "subscription", "content": content, "node_count": 2, "last_error": ""},
                    {"id": "subscription", "content": content, "node_count": 1, "last_error": ""},
                ]
                self.index = 0

            def request(self, _method, _path):
                row = self.rows[min(self.index, len(self.rows) - 1)]
                self.index += 1
                return row

        clock = iter([0.0, 0.0, 0.1, 0.1, 0.2, 0.2])
        with (
            mock.patch.object(MODULE.time, "sleep"),
            mock.patch.object(MODULE.time, "monotonic", side_effect=clock),
            self.assertRaisesRegex(MODULE.SyncError, "expected exactly 2 nodes"),
        ):
            MODULE.verify_subscription(
                Client(),
                "subscription",
                digest,
                2,
                allow_additional_nodes=False,
                timeout=0.15,
                settle_reads=2,
            )

    def test_verify_subscription_incremental_mode_allows_additional_nodes(self):
        content = "socks5h://127.0.0.1:12000\n"
        digest = MODULE.sha256_bytes(content.encode())

        class Client:
            def request(self, _method, _path):
                return {
                    "id": "subscription",
                    "content": content,
                    "node_count": 3,
                    "last_error": "",
                }

        verified = MODULE.verify_subscription(
            Client(),
            "subscription",
            digest,
            2,
            allow_additional_nodes=True,
            timeout=0.1,
            settle_reads=1,
        )
        self.assertEqual(verified["node_count"], 3)

    def test_verify_subscription_rejects_last_error_even_when_count_matches(self):
        content = "socks5h://127.0.0.1:12000\n"
        digest = MODULE.sha256_bytes(content.encode())

        class Client:
            def request(self, _method, _path):
                return {
                    "id": "subscription",
                    "content": content,
                    "node_count": 1,
                    "last_error": "refresh failed",
                }

        with self.assertRaisesRegex(MODULE.SyncError, "last_error=True"):
            MODULE.verify_subscription(
                Client(),
                "subscription",
                digest,
                1,
                allow_additional_nodes=False,
                timeout=0.01,
                settle_reads=1,
            )

    def test_merge_filters_preserves_trusted_managed_alternation(self):
        before = ["^(trusted-grok-local-pool|managed-grok-public-pool)/"]
        desired = MODULE.merge_platform_regex_filters(
            before,
            ["^managed-grok-public-pool/"],
            "^managed-grok-public-pool/",
            "managed-grok-public-pool",
        )
        self.assertEqual(desired, before)

    def test_merge_filters_preserves_non_owner_trusted_filter(self):
        desired = MODULE.merge_platform_regex_filters(
            ["^trusted-grok-local-pool/", "^old-owner/"],
            ["^managed-grok-public-pool/"],
            "^managed-grok-public-pool/",
            "managed-grok-public-pool",
        )
        self.assertEqual(
            desired,
            ["^trusted-grok-local-pool/", "^managed-grok-public-pool/"],
        )

    def test_merge_filters_can_explicitly_remove_unvalidated_trusted_filter(self):
        desired = MODULE.merge_platform_regex_filters(
            ["^(trusted-grok-local-pool|managed-grok-public-pool)/"],
            ["^managed-grok-public-pool/"],
            "^managed-grok-public-pool/",
            "managed-grok-public-pool",
            preserve_existing_trusted=False,
        )
        self.assertEqual(desired, ["^managed-grok-public-pool/"])

    def test_find_subscription_fetches_full_detail(self):
        class Client:
            def __init__(self):
                self.calls = []

            def request(self, method, path, body=None):
                self.calls.append((method, path, body))
                if path.startswith("/api/v1/subscriptions?"):
                    return {"items": [{"id": "sub", "name": "managed"}]}
                if path == "/api/v1/subscriptions/sub":
                    return {"id": "sub", "name": "managed", "content": "full"}
                raise AssertionError((method, path, body))

        client = Client()
        row = MODULE.find_subscription(client, "managed")
        self.assertEqual(row["content"], "full")
        self.assertEqual(client.calls[-1][0:2], ("GET", "/api/v1/subscriptions/sub"))

    def test_current_subscription_is_added_as_private_validation_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = {
                "sources": [],
                "validation": {"max_source_bytes": 1024},
                "resin": {
                    "current_subscription_allowed_non_public_proxy_ips": [
                        "172.17.0.1"
                    ]
                },
            }
            effective = MODULE.config_with_current_subscription(
                config,
                {"id": "sub", "content": "http://user:pass@1.1.1.1:80\n"},
                root,
            )
            source = effective["sources"][0]
            source_path = Path(source["path"])
            self.assertEqual(source["id"], MODULE.CURRENT_MANAGED_SOURCE_ID)
            self.assertEqual(
                source["allowed_non_public_proxy_ips"], ["172.17.0.1"]
            )
            self.assertEqual(source_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                source_path.read_text(encoding="utf-8"),
                "http://user:pass@1.1.1.1:80\n",
            )

    def test_run_revalidates_current_subscription_before_no_change(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state_dir = root / "state"
            config_path = root / "config.json"
            current_content = "http://user:pass@1.1.1.1:80\n"
            config = {
                "version": 1,
                "state_dir": str(state_dir),
                "lock_file": str(root / "maintainer.lock"),
                "sources": [],
                "validation": {"max_source_bytes": 1024},
                "selection": {},
                "safety": {"mode": "non_empty"},
                "resin": {
                    "base_url": "http://127.0.0.1:10833",
                    "subscription_name": "managed",
                    "platform_id": "platform",
                    "platform_name": "GrokEU",
                    "platform_regex_filters": ["^managed/"],
                    "region_filters": [],
                },
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            config_path.chmod(0o600)
            subscription = {
                "id": "subscription",
                "name": "managed",
                "content": current_content,
                "node_count": 1,
                "last_error": "",
                "update_interval": "24h",
                "enabled": True,
                "ephemeral": True,
                "incremental_alive_nodes": True,
                "ephemeral_node_evict_delay": "72h",
            }
            platform = {
                "id": "platform",
                "name": "GrokEU",
                "regex_filters": ["^managed/"],
                "region_filters": [],
            }
            captured_sources = []

            class NoChangeClient:
                def request(self, method, path, body=None):
                    if method == "GET" and path == "/api/v1/subscriptions/subscription":
                        return dict(subscription)
                    raise AssertionError((method, path, body))

            def validate(effective, output_file, report_file):
                captured_sources.extend(effective["sources"])
                source_path = Path(effective["sources"][-1]["path"])
                output_file.write_bytes(source_path.read_bytes())
                output_file.chmod(0o600)
                report = {
                    "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "input_count": 1,
                    "passed_count": 1,
                    "selected_count": 1,
                    "unique_egress_count": 1,
                    "output_sha256": MODULE.sha256_file(output_file),
                }
                report_file.write_text(json.dumps(report), encoding="utf-8")
                report_file.chmod(0o600)
                return report

            args = argparse.Namespace(
                command="run",
                config=str(config_path),
                admin_token_file=str(root / "unused-token"),
                confirm_production_write=True,
            )
            with (
                mock.patch.object(MODULE, "load_token", return_value="secret"),
                mock.patch.object(MODULE, "ResinClient", return_value=NoChangeClient()),
                mock.patch.object(MODULE, "find_subscription", return_value=subscription),
                mock.patch.object(MODULE, "get_platform", return_value=platform),
                mock.patch.object(MODULE, "validation_from_config", side_effect=validate),
            ):
                self.assertEqual(MODULE.run(args), 0)

            self.assertEqual(captured_sources[-1]["id"], MODULE.CURRENT_MANAGED_SOURCE_ID)
            state = json.loads((state_dir / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["selected_count"], 1)
            manifest = json.loads(
                next((state_dir / "runs").iterdir()).joinpath("manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(manifest["node_count"], 1)

    def test_run_rejects_no_change_when_subscription_state_drifted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state_dir = root / "state"
            config_path = root / "config.json"
            current_content = "http://user:pass@1.1.1.1:80\n"
            config = {
                "version": 1,
                "state_dir": str(state_dir),
                "lock_file": str(root / "maintainer.lock"),
                "sources": [],
                "validation": {"max_source_bytes": 1024},
                "selection": {},
                "safety": {"mode": "non_empty"},
                "resin": {
                    "base_url": "http://127.0.0.1:10833",
                    "subscription_name": "managed",
                    "platform_id": "platform",
                    "platform_name": "GrokEU",
                    "platform_regex_filters": ["^managed/"],
                    "region_filters": [],
                    "verify_timeout_seconds": 0.01,
                    "verify_settle_reads": 1,
                },
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            config_path.chmod(0o600)
            subscription = {
                "id": "subscription",
                "name": "managed",
                "content": current_content,
                "node_count": 0,
                "last_error": "refresh failed",
                "update_interval": "24h",
                "enabled": True,
                "ephemeral": True,
                "incremental_alive_nodes": True,
                "ephemeral_node_evict_delay": "72h",
            }
            platform = {
                "id": "platform",
                "name": "GrokEU",
                "regex_filters": ["^managed/"],
                "region_filters": [],
            }

            class DriftedClient:
                def request(self, method, path, body=None):
                    if method == "GET" and path == "/api/v1/subscriptions/subscription":
                        return dict(subscription)
                    raise AssertionError((method, path, body))

            def validate(effective, output_file, report_file):
                source_path = Path(effective["sources"][-1]["path"])
                output_file.write_bytes(source_path.read_bytes())
                output_file.chmod(0o600)
                report = {
                    "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "input_count": 1,
                    "passed_count": 1,
                    "selected_count": 1,
                    "unique_egress_count": 1,
                    "output_sha256": MODULE.sha256_file(output_file),
                }
                report_file.write_text(json.dumps(report), encoding="utf-8")
                report_file.chmod(0o600)
                return report

            args = argparse.Namespace(
                command="run",
                config=str(config_path),
                admin_token_file=str(root / "unused-token"),
                confirm_production_write=True,
            )
            with (
                mock.patch.object(MODULE, "load_token", return_value="secret"),
                mock.patch.object(MODULE, "ResinClient", return_value=DriftedClient()),
                mock.patch.object(MODULE, "find_subscription", return_value=subscription),
                mock.patch.object(MODULE, "get_platform", return_value=platform),
                mock.patch.object(MODULE, "validation_from_config", side_effect=validate),
                self.assertRaisesRegex(MODULE.SyncError, "last_error=True"),
            ):
                MODULE.run(args)

            self.assertFalse((state_dir / "state.json").exists())

    def test_run_rejects_subscription_drift_during_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state_dir = root / "state"
            config_path = root / "config.json"
            config = {
                "version": 1,
                "state_dir": str(state_dir),
                "lock_file": str(root / "maintainer.lock"),
                "sources": [],
                "validation": {"max_source_bytes": 1024},
                "safety": {"mode": "non_empty"},
                "resin": {
                    "subscription_name": "managed",
                    "platform_id": "platform",
                    "platform_name": "GrokEU",
                    "platform_regex_filters": ["^managed/"],
                    "region_filters": [],
                },
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            config_path.chmod(0o600)
            before = {
                "id": "subscription",
                "name": "managed",
                "content": "http://u:p@1.1.1.1:80\n",
            }
            after = {
                "id": "subscription",
                "name": "managed",
                "content": "http://u:p@2.2.2.2:80\n",
            }
            platform = {
                "id": "platform",
                "name": "GrokEU",
                "regex_filters": ["^managed/"],
                "region_filters": [],
            }

            def validate(_effective, output_file, report_file):
                output_file.write_text(before["content"], encoding="utf-8")
                output_file.chmod(0o600)
                report_file.write_text("{}", encoding="utf-8")
                report_file.chmod(0o600)
                return {
                    "input_count": 1,
                    "passed_count": 1,
                    "selected_count": 1,
                    "unique_egress_count": 1,
                }

            args = argparse.Namespace(
                command="run",
                config=str(config_path),
                admin_token_file=str(root / "unused-token"),
                confirm_production_write=True,
            )
            with (
                mock.patch.object(MODULE, "load_token", return_value="secret"),
                mock.patch.object(MODULE, "ResinClient", return_value=object()),
                mock.patch.object(MODULE, "find_subscription", side_effect=[before, after]),
                mock.patch.object(MODULE, "get_platform", return_value=platform),
                mock.patch.object(MODULE, "validation_from_config", side_effect=validate),
            ):
                with self.assertRaisesRegex(
                    MODULE.SyncError, "state changed during validation"
                ):
                    MODULE.run(args)

    def test_restore_subscription_get_verifies_restored_values(self):
        class Client:
            def __init__(self):
                self.row = {
                    "id": "subscription",
                    "content": "new",
                    "update_interval": "1h",
                    "enabled": True,
                    "ephemeral": True,
                    "incremental_alive_nodes": True,
                    "ephemeral_node_evict_delay": "72h",
                }
                self.calls = []

            def request(self, method, path, body=None):
                self.calls.append((method, path, body))
                if method == "PATCH":
                    self.row.update(dict(body or {}))
                    return dict(self.row)
                if method == "POST":
                    return None
                if method == "GET":
                    return dict(self.row)
                raise AssertionError((method, path, body))

        client = Client()
        before = {
            "id": "subscription",
            "content": "old",
            "update_interval": "24h",
            "enabled": False,
            "ephemeral": False,
            "incremental_alive_nodes": False,
            "ephemeral_node_evict_delay": "6h",
        }
        result = MODULE.restore_subscription(client, {}, before, None)
        self.assertTrue(result["subscription_restored"])
        self.assertIn(("GET", "/api/v1/subscriptions/subscription", None), client.calls)

    def test_restore_created_subscription_verifies_delete(self):
        class Client:
            def __init__(self):
                self.exists = True
                self.calls = []

            def request(self, method, path, body=None):
                self.calls.append((method, path, body))
                if method == "DELETE":
                    self.exists = False
                    return None
                if method == "GET":
                    return {"id": "created"} if self.exists else None
                raise AssertionError((method, path, body))

        client = Client()
        result = MODULE.restore_subscription(client, {}, None, "created")
        self.assertTrue(result["created_subscription_removed"])
        self.assertIn(("GET", "/api/v1/subscriptions/created", None), client.calls)

    def test_ambiguous_create_result_is_not_reported_as_rolled_back(self):
        client = mock.Mock()
        result = MODULE.restore_subscription(
            client,
            {},
            None,
            None,
            create_attempted=True,
        )
        self.assertFalse(result["created_subscription_removed"])
        self.assertEqual(result["error"], "subscription create result is ambiguous")
        client.request.assert_not_called()

    def test_prune_allows_only_the_current_run_record(self):
        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp)
            current = state_dir / "runs" / "current"
            current.mkdir(parents=True)
            old = state_dir / "runs" / "old"
            old.mkdir()
            MODULE.write_json(
                old / "manifest.json",
                {"owner": MODULE.OWNER, "status": "completed"},
            )
            self.assertEqual(MODULE.prune_owned_runs(state_dir, 1, current), ["old"])
            self.assertFalse(old.exists())

    def test_platform_response_failure_restores_previous_filters(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state_dir = root / "state"
            run_dir = state_dir / "runs" / "validated"
            run_dir.mkdir(parents=True)
            output = b"http://user:pass@1.1.1.1:80\n"
            output_hash = hashlib.sha256(output).hexdigest()
            config_path = root / "config.json"
            config = {
                "version": 1,
                "state_dir": str(state_dir),
                "lock_file": str(root / "maintainer.lock"),
                "safety": {"mode": "non_empty"},
                "resin": {
                    "base_url": "http://127.0.0.1:10833",
                    "subscription_name": "managed",
                    "platform_id": "11111111-1111-1111-1111-111111111111",
                    "platform_name": "GrokEU",
                    "platform_regex_filters": ["^desired/"],
                    "region_filters": [],
                },
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            config_path.chmod(0o600)
            config_hash = MODULE.sha256_file(config_path)
            (run_dir / "validated-proxies.txt").write_bytes(output)
            (run_dir / "validated-proxies.txt").chmod(0o600)
            report = {
                "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "input_count": 1,
                "passed_count": 1,
                "selected_count": 1,
                "unique_egress_count": 1,
                "output_sha256": output_hash,
            }
            manifest = {
                "owner": MODULE.OWNER,
                "status": "validated_only",
                "config_sha256": config_hash,
                "validation": {"output_sha256": output_hash},
            }
            for name, value in (("validation-report.json", report), ("manifest.json", manifest)):
                path = run_dir / name
                path.write_text(json.dumps(value), encoding="utf-8")
                path.chmod(0o600)

            before_subscription = {"id": "subscription", "content": "old"}
            before_platform = {
                "id": config["resin"]["platform_id"],
                "name": "GrokEU",
                "regex_filters": ["^old/"],
                "region_filters": ["us"],
            }
            client = FakeClient(before_platform)
            old_state = {
                "owner": MODULE.OWNER,
                "version": MODULE.STATE_VERSION,
                "selected_count": 1,
                "passed_count": 1,
                "content_sha256": "old-digest",
                "subscription_id": "subscription",
            }
            MODULE.write_json(state_dir / "state.json", old_state)
            args = argparse.Namespace(
                command="apply",
                config=str(config_path),
                validated_run=str(run_dir),
                admin_token_file=str(root / "unused-token"),
                confirm_production_write=True,
            )
            patches = (
                mock.patch.object(MODULE, "load_token", return_value="secret"),
                mock.patch.object(MODULE, "ResinClient", return_value=client),
                mock.patch.object(MODULE, "find_subscription", return_value=before_subscription),
                mock.patch.object(
                    MODULE,
                    "update_subscription",
                    return_value={"id": "subscription"},
                ),
                mock.patch.object(MODULE, "refresh_subscription", return_value=None),
                mock.patch.object(
                    MODULE,
                    "verify_subscription",
                    return_value={"id": "subscription", "node_count": 1},
                ),
                mock.patch.object(
                    MODULE,
                    "restore_subscription",
                    return_value={"attempted": True, "subscription_restored": True},
                ),
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                with self.assertRaisesRegex(MODULE.SyncError, "platform filter update verification failed"):
                    MODULE.run(args)

            self.assertEqual(
                client.platform_patches,
                [
                    {"regex_filters": ["^desired/"], "region_filters": []},
                    {"regex_filters": ["^old/"], "region_filters": ["us"]},
                ],
            )
            self.assertEqual(
                json.loads((state_dir / "state.json").read_text(encoding="utf-8")),
                old_state,
            )


if __name__ == "__main__":
    unittest.main()
