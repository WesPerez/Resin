from __future__ import annotations

import dataclasses
import concurrent.futures
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "lib"
SCRIPT = SCRIPTS / "proxy_probe.py"
SPEC = importlib.util.spec_from_file_location("proxy_probe_selection_test", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def result(
    host: str,
    *,
    source_id: str,
    username: str = "",
    password: str = "",
    latency: float = 1.0,
    ok: bool = True,
    category: str = "passed",
    failed_target: str = "",
):
    spec = MODULE.ProxySpec(
        "http",
        host,
        80,
        username,
        password,
        (source_id,),
    )
    return MODULE.ProbeResult(
        spec,
        ok,
        category,
        latency,
        egress_ip=host if ok else "",
        region="us" if ok else "",
        failed_target=failed_target,
    )


class ProxySelectionTests(unittest.TestCase):
    def test_tls_context_is_shared_without_disabling_verification(self):
        with mock.patch.object(MODULE, "_TLS_CONTEXT", None), mock.patch.object(
            MODULE.ssl, "create_default_context", wraps=MODULE.ssl.create_default_context
        ) as create:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                contexts = list(executor.map(lambda _: MODULE.verified_tls_context(), range(32)))
            create.assert_called_once_with()
            self.assertTrue(all(context is contexts[0] for context in contexts))
            self.assertTrue(contexts[0].check_hostname)
            self.assertEqual(contexts[0].verify_mode, MODULE.ssl.CERT_REQUIRED)

    def test_selection_clamps_zero_and_oversized_limits_to_1000(self):
        rows = [
            result(f"203.0.{index // 250}.{index % 250 + 1}", source_id="bulk")
            for index in range(1100)
        ]
        for configured in (0, 5000):
            with self.subTest(configured=configured):
                selected = MODULE.select_results(
                    rows,
                    max_nodes=configured,
                    max_per_egress=0,
                    allowed_regions=[],
                    require_egress=True,
                )
                self.assertEqual(len(selected), 1000)

    def test_default_target_is_generic(self):
        self.assertEqual(
            MODULE.validation_target_hosts({}),
            ("www.cloudflare.com",),
        )

    def test_target_host_config_keeps_legacy_compatibility_and_deduplicates(self):
        self.assertEqual(
            MODULE.validation_target_hosts({"target_host": "GROK.com."}),
            ("grok.com",),
        )
        self.assertEqual(
            MODULE.validation_target_hosts(
                {"target_hosts": ["grok.com", "AUTH.x.ai", "grok.com"]}
            ),
            ("grok.com", "auth.x.ai"),
        )
        with self.assertRaisesRegex(ValueError, "invalid target host"):
            MODULE.normalize_target_hosts("https://auth.x.ai")
        self.assertEqual(
            MODULE.validation_min_target_hosts_passed(
                {"target_hosts": ["one.example", "two.example"]},
                ("one.example", "two.example"),
            ),
            2,
        )
        self.assertEqual(
            MODULE.validation_min_target_hosts_passed(
                {"min_target_hosts_passed": 1},
                ("one.example", "two.example"),
            ),
            1,
        )
        with self.assertRaisesRegex(ValueError, "between 1 and target host count"):
            MODULE.normalize_min_target_hosts_passed(3, 2)

    @mock.patch.object(MODULE, "_tls_tunnel")
    def test_probe_requires_every_target_host(self, tls_tunnel):
        sockets = [mock.Mock(), mock.Mock()]
        tls_tunnel.side_effect = sockets
        spec = MODULE.ProxySpec("http", "1.1.1.1", 80)

        probe = MODULE.probe_one(
            spec,
            mock.Mock(),
            5,
            ("grok.com", "auth.x.ai"),
            False,
        )

        self.assertTrue(probe.ok)
        self.assertEqual(
            [call.args[3] for call in tls_tunnel.call_args_list],
            ["grok.com", "auth.x.ai"],
        )
        for tls in sockets:
            tls.close.assert_called_once_with()

    @mock.patch.object(MODULE, "_tls_tunnel")
    def test_probe_reports_the_target_that_failed(self, tls_tunnel):
        first = mock.Mock()
        tls_tunnel.side_effect = [first, MODULE.ProbeError("target_tls_timeout")]
        spec = MODULE.ProxySpec("http", "1.1.1.1", 80)

        probe = MODULE.probe_one(
            spec,
            mock.Mock(),
            5,
            ("grok.com", "auth.x.ai"),
            False,
        )

        self.assertFalse(probe.ok)
        self.assertEqual(probe.category, "target_tls_timeout")
        self.assertEqual(probe.failed_target, "auth.x.ai")
        first.close.assert_called_once_with()

    @mock.patch.object(MODULE, "_tls_tunnel")
    def test_probe_accepts_configured_target_quorum(self, tls_tunnel):
        first = mock.Mock()
        third = mock.Mock()
        tls_tunnel.side_effect = [
            first,
            MODULE.ProbeError("target_tls_timeout"),
            third,
        ]
        spec = MODULE.ProxySpec("http", "1.1.1.1", 80)

        probe = MODULE.probe_one(
            spec,
            mock.Mock(),
            5,
            ("one.example", "two.example", "three.example"),
            False,
            2,
        )

        self.assertTrue(probe.ok)
        self.assertEqual(
            [call.args[3] for call in tls_tunnel.call_args_list],
            ["one.example", "two.example", "three.example"],
        )
        first.close.assert_called_once_with()
        third.close.assert_called_once_with()

    def test_duplicate_proxy_retains_all_source_ids(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sources = []
            for source_id in ("one", "two"):
                path = root / f"{source_id}.txt"
                path.write_text("http://user:pass@1.1.1.1:80\n", encoding="utf-8")
                path.chmod(0o600)
                sources.append({"id": source_id, "type": "file", "path": str(path)})

            specs, audits = MODULE.load_sources(
                sources, MODULE.PublicResolver(), timeout=1, max_bytes=1024
            )

        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0].source_ids, ("one", "two"))
        self.assertEqual([row["input_count"] for row in audits], [1, 1])

    def test_private_proxy_is_allowed_only_for_explicit_file_source(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bridge.txt"
            path.write_text("socks5://172.17.0.1:12000\n", encoding="utf-8")
            path.chmod(0o600)
            source = {
                "id": "local-bridge",
                "type": "file",
                "path": str(path),
                "allowed_non_public_proxy_ips": ["172.17.0.1"],
            }
            specs, _ = MODULE.load_sources(
                [source], MODULE.PublicResolver(), timeout=1, max_bytes=1024
            )

        self.assertEqual(specs[0].allowed_non_public_ip, "172.17.0.1")
        resolver = MODULE.PublicResolver()
        self.assertEqual(
            resolver.resolve(
                specs[0].host,
                specs[0].port,
                allowed_non_public_ip=specs[0].allowed_non_public_ip,
            )[0],
            "172.17.0.1",
        )

    def test_non_public_allowlist_is_rejected_for_url_sources(self):
        source = {
            "id": "remote",
            "type": "url",
            "url": "https://example.com/proxies.txt",
            "allowed_non_public_proxy_ips": ["172.17.0.1"],
        }
        with self.assertRaisesRegex(ValueError, "requires a file source"):
            MODULE.load_sources(
                [source], MODULE.PublicResolver(), timeout=1, max_bytes=1024
            )

    def test_selection_caps_each_source(self):
        rows = [
            result(f"1.1.1.{index}", source_id="one", latency=float(index))
            for index in range(1, 5)
        ] + [
            result(f"2.2.2.{index}", source_id="two", latency=float(index + 10))
            for index in range(1, 4)
        ]

        selected = MODULE.select_results(
            rows,
            max_nodes=10,
            max_per_egress=1,
            allowed_regions=[],
            require_egress=True,
            max_per_source=2,
        )

        counts = {}
        for row in selected:
            counts[row.spec.source_ids[0]] = counts.get(row.spec.source_ids[0], 0) + 1
        self.assertEqual(counts, {"one": 2, "two": 2})

    def test_selection_can_exclude_a_region(self):
        cn = result("3.3.3.3", source_id="one", latency=1)
        us = result("4.4.4.4", source_id="one", latency=2)
        cn = dataclasses.replace(cn, region="cn")
        us = dataclasses.replace(us, region="us")

        selected = MODULE.select_results(
            [cn, us],
            max_nodes=10,
            max_per_egress=1,
            allowed_regions=[],
            excluded_regions=["cn"],
            require_egress=True,
        )

        self.assertEqual([row.region for row in selected], ["us"])

    def test_selection_rejects_overlapping_region_filters(self):
        with self.assertRaisesRegex(ValueError, "must not overlap"):
            MODULE.select_results(
                [],
                max_nodes=10,
                max_per_egress=1,
                allowed_regions=["cn"],
                excluded_regions=["cn"],
                require_egress=True,
            )

    def test_selection_caps_shared_credential_group(self):
        rows = [
            result(
                f"3.3.3.{index}",
                source_id="one",
                username="shared",
                password="credential",
                latency=float(index),
            )
            for index in range(1, 5)
        ]

        selected = MODULE.select_results(
            rows,
            max_nodes=10,
            max_per_egress=1,
            allowed_regions=[],
            require_egress=True,
            max_per_credential_group=2,
        )

        self.assertEqual(len(selected), 2)
        self.assertEqual(
            len({row.spec.credential_group_id for row in selected}),
            1,
        )

    def test_selection_prefers_previous_managed_nodes_over_faster_new_nodes(self):
        previous = result(
            "6.6.6.6",
            source_id="resin-current-managed-subscription",
            latency=900,
        )
        fresh = result("7.7.7.7", source_id="new", latency=10)

        selected = MODULE.select_results(
            [fresh, previous],
            max_nodes=1,
            max_per_egress=1,
            allowed_regions=[],
            require_egress=True,
            preferred_source_ids=["resin-current-managed-subscription"],
        )

        self.assertEqual([row.spec.host for row in selected], ["6.6.6.6"])

    def test_explicit_credential_group_override_is_honored(self):
        spec = MODULE.ProxySpec(
            "socks5",
            "127.0.0.1",
            12000,
            credential_group_override="upstream-group",
        )
        self.assertEqual(spec.credential_group_id, "upstream-group")

    def test_report_has_per_source_failure_counts_without_credentials(self):
        passed = result(
            "4.4.4.4",
            source_id="one",
            username="secret-user",
            password="secret-pass",
        )
        failed = result(
            "5.5.5.5",
            source_id="one",
            username="secret-user",
            password="secret-pass",
            ok=False,
            category="proxy_connect_timeout",
            failed_target="auth.x.ai",
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report_path = root / "report.json"
            MODULE.write_validation_artifacts(
                root / "validated.txt",
                report_path,
                [passed, failed],
                [passed],
                [{"id": "one", "status": "loaded"}],
                1.0,
                ("grok.com", "auth.x.ai"),
                1,
            )
            payload = report_path.read_text(encoding="utf-8")
            report = json.loads(payload)

        self.assertNotIn("secret-user", payload)
        self.assertNotIn("secret-pass", payload)
        self.assertEqual(report["target_hosts"], ["grok.com", "auth.x.ai"])
        self.assertEqual(report["min_target_hosts_passed"], 1)
        self.assertEqual(
            report["target_failures"],
            {"auth.x.ai": {"proxy_connect_timeout": 1}},
        )
        self.assertEqual(report["sources"][0]["input_count"], 2)
        self.assertEqual(report["sources"][0]["passed_count"], 1)
        self.assertEqual(report["sources"][0]["selected_count"], 1)
        self.assertEqual(
            report["sources"][0]["categories"],
            {"passed": 1, "proxy_connect_timeout": 1},
        )


if __name__ == "__main__":
    unittest.main()
