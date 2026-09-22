from __future__ import annotations

import importlib.util
import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "lib"
sys.path.insert(0, str(SCRIPTS))
SCRIPT = SCRIPTS / "singbox_bridge_pool.py"
SPEC = importlib.util.spec_from_file_location("singbox_bridge_pool_test", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class SingboxBridgePoolTests(unittest.TestCase):
    def test_refresh_parser_accepts_repeated_target_hosts(self):
        args = MODULE.build_parser().parse_args(
            [
                "refresh",
                "--source-url",
                "https://raw.githubusercontent.com/owner/repo/main/config.json",
                "--output-dir",
                "/tmp/bridge",
                "--target-host",
                "grok.com",
                "--target-host",
                "auth.x.ai",
            ]
        )
        self.assertEqual(args.target_hosts, ["grok.com", "auth.x.ai"])

    def test_refresh_parser_accepts_target_quorum_and_region_exclusion(self):
        args = MODULE.build_parser().parse_args(
            [
                "refresh",
                "--source-url",
                "https://raw.githubusercontent.com/owner/repo/main/config.json",
                "--output-dir",
                "/tmp/bridge",
                "--target-host",
                "one.example",
                "--target-host",
                "two.example",
                "--target-host",
                "three.example",
                "--min-target-hosts-passed",
                "2",
                "--excluded-region",
                "cn",
            ]
        )
        self.assertEqual(args.min_target_hosts_passed, 2)
        self.assertEqual(args.excluded_regions, ["cn"])

    def test_refresh_defaults_to_one_healthy_slot(self):
        args = MODULE.build_parser().parse_args(
            [
                "refresh",
                "--source-url",
                "https://raw.githubusercontent.com/owner/repo/main/config.json",
                "--output-dir",
                "/tmp/bridge",
            ]
        )
        self.assertIsNone(args.minimum_healthy_nodes)
        self.assertEqual(
            1 if args.minimum_healthy_nodes is None else args.minimum_healthy_nodes,
            1,
        )
        self.assertEqual(args.candidate_limit, 0)

    def test_source_url_is_restricted_to_github_raw(self):
        resolver = mock.Mock()
        MODULE.validate_source_url(
            "https://raw.githubusercontent.com/owner/repo/main/config.json", resolver
        )
        resolver.resolve.assert_called_once()
        with self.assertRaisesRegex(MODULE.BridgeError, "not allowlisted"):
            MODULE.validate_source_url("https://example.com/config.json", resolver)

    def test_sanitize_drops_tag_and_untrusted_keys(self):
        outbound = MODULE.sanitize_outbound(
            {
                "type": "vless",
                "tag": "upstream-name",
                "server": "example.com",
                "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000",
                "tls": {
                    "enabled": True,
                    "server_name": "example.com",
                    "utls": {"enabled": True, "fingerprint": "chrome", "evil": 1},
                    "evil": 1,
                },
                "transport": {
                    "type": "ws",
                    "path": "/ws",
                    "headers": {"Host": "example.com"},
                    "evil": 1,
                },
                "detour": "direct",
            }
        )
        self.assertNotIn("tag", outbound)
        self.assertNotIn("detour", outbound)
        self.assertNotIn("evil", outbound["tls"])
        self.assertNotIn("evil", outbound["tls"]["utls"])
        self.assertNotIn("evil", outbound["transport"])

    def test_sanitize_accepts_empty_transport_headers(self):
        outbound = MODULE.sanitize_outbound(
            {
                "type": "vless",
                "server": "example.com",
                "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000",
                "transport": {"type": "ws", "headers": {}},
            }
        )
        self.assertEqual(outbound["transport"]["headers"], {})

    def test_load_candidates_keeps_alternate_credentials_per_endpoint(self):
        raw = {
            "outbounds": [
                {
                    "type": "trojan",
                    "server": "example.com",
                    "server_port": 443,
                    "password": "one",
                },
                {
                    "type": "trojan",
                    "server": "EXAMPLE.com",
                    "server_port": 443,
                    "password": "one",
                },
                {
                    "type": "trojan",
                    "server": "EXAMPLE.com",
                    "server_port": 443,
                    "password": "two",
                },
                {"type": "direct", "tag": "direct"},
            ]
        }
        candidates, report = MODULE.load_candidates(json.dumps(raw).encode())
        self.assertEqual(len(candidates), 2)
        self.assertEqual(report["rejected"], {"duplicate_endpoint": 1})
        self.assertEqual({row["password"] for row in candidates}, {"one", "two"})

    def test_build_config_maps_each_inbound_to_one_outbound(self):
        candidates = [
            {
                "type": "shadowsocks",
                "server": "1.1.1.1",
                "server_port": 443,
                "method": "aes-128-gcm",
                "password": "secret",
            },
            {
                "type": "trojan",
                "server": "8.8.8.8",
                "server_port": 443,
                "password": "secret",
            },
        ]
        config, bridges = MODULE.build_config(
            candidates, listen="127.0.0.1", base_port=20000
        )
        self.assertEqual([row["listen_port"] for row in config["inbounds"]], [20000, 20001])
        self.assertEqual(
            [row["outbound"] for row in config["route"]["rules"]],
            ["candidate-0000", "candidate-0001"],
        )
        self.assertEqual(len(bridges), 2)

    def test_build_config_adds_authenticated_direct_inbound_without_a_bridge_slot(self):
        config, bridges = MODULE.build_config(
            [
                {
                    "type": "trojan",
                    "server": "8.8.8.8",
                    "server_port": 443,
                    "password": "secret",
                }
            ],
            listen="172.17.0.1",
            base_port=12000,
            direct_port=12400,
            direct_username="sub2-direct",
            direct_password="direct-secret",
        )

        self.assertEqual(len(bridges), 1)
        self.assertEqual(config["inbounds"][-1], {
            "type": "socks",
            "tag": "managed-direct-egress",
            "listen": "172.17.0.1",
            "listen_port": 12400,
            "users": [{"username": "sub2-direct", "password": "direct-secret"}],
        })
        self.assertEqual(config["route"]["rules"][-1]["outbound"], "direct")

    def test_build_config_skips_direct_port_without_shifting_existing_slots(self):
        candidates = [
            {
                "type": "trojan",
                "server": "8.8.8.8",
                "server_port": 443,
                "password": f"secret-{index}",
            }
            for index in range(1000)
        ]
        config, bridges = MODULE.build_config(
            candidates,
            listen="172.17.0.1",
            base_port=12000,
            direct_port=12400,
            direct_username="sub2-direct",
            direct_password="direct-secret",
        )

        self.assertEqual([row["port"] for row in bridges[:400]], list(range(12000, 12400)))
        self.assertEqual(bridges[400]["port"], 12401)
        self.assertEqual(bridges[-1]["port"], 13000)
        self.assertEqual(len({row["listen_port"] for row in config["inbounds"]}), 1001)

    def test_build_config_can_reserve_the_base_port(self):
        config, bridges = MODULE.build_config(
            [
                {
                    "type": "trojan",
                    "server": "8.8.8.8",
                    "server_port": 443,
                    "password": "secret",
                }
            ],
            listen="172.17.0.1",
            base_port=12000,
            direct_port=12000,
            direct_username="sub2-direct",
            direct_password="direct-secret",
        )

        self.assertEqual(bridges[0]["port"], 12001)
        self.assertEqual([row["listen_port"] for row in config["inbounds"]], [12001, 12000])

    def test_current_direct_inbound_match_detects_managed_route_and_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generation = root / "generations" / "generation-1"
            generation.mkdir(parents=True)
            config, _ = MODULE.build_config(
                [
                    {
                        "type": "trojan",
                        "server": "8.8.8.8",
                        "server_port": 443,
                        "password": "secret",
                    }
                ],
                listen="172.17.0.1",
                base_port=12000,
                direct_port=12400,
                direct_username="sub2-direct",
                direct_password="direct-secret",
            )
            MODULE.write_json(generation / "bridge.json", config)
            (root / "current").symlink_to(Path("generations") / "generation-1")

            self.assertTrue(MODULE.current_direct_inbound_matches(
                root,
                listen="172.17.0.1",
                port=12400,
                username="sub2-direct",
                password="direct-secret",
            ))
            self.assertFalse(MODULE.current_direct_inbound_matches(
                root,
                listen="172.17.0.1",
                port=12400,
                username="sub2-direct",
                password="wrong",
            ))

    def test_credential_group_is_independent_of_endpoint(self):
        first = {
            "type": "vless",
            "server": "1.1.1.1",
            "server_port": 443,
            "uuid": "00000000-0000-0000-0000-000000000000",
        }
        second = {**first, "server": "8.8.8.8"}
        self.assertEqual(
            MODULE.credential_group_id(first), MODULE.credential_group_id(second)
        )

    def test_resolve_current_rejects_path_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "current").symlink_to("../escape")
            args = mock.Mock(output_dir=str(root), artifact="bridge.json")
            with self.assertRaisesRegex(MODULE.BridgeError, "pointer is invalid"):
                MODULE.command_resolve_current(args)

    def test_prune_generations_keeps_current_staged_and_unowned(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generations = root / "generations"
            generations.mkdir()
            for name in ("001", "002", "003", "004"):
                generation = generations / name
                generation.mkdir()
                (generation / "manifest.json").write_text(
                    json.dumps({"owner": MODULE.OWNER}), encoding="utf-8"
                )
                (generation / "manifest.json").chmod(0o600)
            unowned = generations / "000-unowned"
            unowned.mkdir()
            (unowned / "manifest.json").write_text(
                json.dumps({"owner": "someone-else"}), encoding="utf-8"
            )
            (unowned / "manifest.json").chmod(0o600)
            (root / "current").symlink_to("generations/004")
            (root / "staged").symlink_to("generations/001")

            removed = MODULE.prune_generations(root, 2)

            self.assertEqual(removed, ["002"])
            self.assertTrue((generations / "001").is_dir())
            self.assertTrue((generations / "003").is_dir())
            self.assertTrue((generations / "004").is_dir())
            self.assertTrue(unowned.is_dir())

    @mock.patch("builtins.print")
    def test_commit_clears_staged_and_is_idempotent(self, _print):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generations = root / "generations"
            generation = generations / "new"
            old = generations / "old"
            generation.mkdir(parents=True)
            old.mkdir()
            for path in (generation, old):
                MODULE.write_json(path / "manifest.json", {"owner": MODULE.OWNER})
            (root / "current").symlink_to("generations/new")
            (root / "staged").symlink_to("generations/old")
            args = mock.Mock(output_dir=str(root), retain_generations=1)

            self.assertEqual(MODULE.command_commit(args), 0)
            self.assertFalse((root / "staged").exists())
            self.assertEqual((root / "current").resolve(), generation)
            self.assertFalse(old.exists())
            self.assertEqual(MODULE.command_commit(args), 0)

    def test_prune_command_keeps_only_current_generation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generations = root / "generations"
            generations.mkdir()
            current = generations / "current-generation"
            old = generations / "old-generation"
            for path in (current, old):
                path.mkdir()
                MODULE.write_json(path / "manifest.json", {"owner": MODULE.OWNER})
            (root / "current").symlink_to("generations/current-generation")

            self.assertEqual(
                MODULE.command_prune(
                    argparse.Namespace(output_dir=str(root), retain_generations=1)
                ),
                0,
            )
            self.assertTrue(current.exists())
            self.assertFalse(old.exists())

    def test_mutating_operations_use_an_exclusive_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            lock = Path(temp) / ".bridge-pool.lock"
            with MODULE.exclusive_lock(lock):
                with self.assertRaisesRegex(
                    MODULE.BridgeError, "another bridge pool operation is active"
                ):
                    with MODULE.exclusive_lock(lock):
                        self.fail("second lock unexpectedly succeeded")

    @mock.patch("builtins.print")
    def test_rollback_restores_previous_generation(self, _print):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            previous = root / "generations" / "old"
            current = root / "generations" / "new"
            previous.mkdir(parents=True)
            current.mkdir()
            (root / "current").symlink_to("generations/new")
            (root / "staged").symlink_to("generations/old")

            self.assertEqual(
                MODULE.command_rollback(mock.Mock(output_dir=str(root))), 0
            )

            self.assertEqual((root / "current").resolve(), previous)
            self.assertFalse((root / "staged").exists())

    @mock.patch("builtins.print")
    def test_first_generation_rollback_removes_current(self, _print):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generation = root / "generations" / "new"
            generation.mkdir(parents=True)
            (root / "current").symlink_to("generations/new")
            (root / "staged").symlink_to("generations")

            self.assertEqual(
                MODULE.command_rollback(mock.Mock(output_dir=str(root))), 0
            )

            self.assertFalse((root / "current").exists())
            self.assertFalse((root / "current").is_symlink())
            self.assertFalse((root / "staged").exists())

    @mock.patch.object(MODULE, "resolve_public_endpoint", return_value="1.1.1.1")
    def test_pin_public_endpoint_preserves_sni_and_websocket_host(self, _resolve):
        pinned = MODULE.pin_public_endpoint(
            {
                "type": "vless",
                "server": "edge.example.com",
                "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000",
                "tls": {"enabled": True},
                "transport": {"type": "ws", "path": "/ws"},
            }
        )
        self.assertEqual(pinned["server"], "1.1.1.1")
        self.assertEqual(pinned["tls"]["server_name"], "edge.example.com")
        self.assertEqual(
            pinned["transport"]["headers"]["Host"], "edge.example.com"
        )

    def test_load_current_candidates_preserves_generation_order(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generation = root / "generations" / "generation-1"
            generation.mkdir(parents=True)
            candidates = [
                {
                    "type": "trojan",
                    "server": "1.1.1.1",
                    "server_port": 443,
                    "password": "first",
                },
                {
                    "type": "vless",
                    "server": "8.8.8.8",
                    "server_port": 443,
                    "uuid": "00000000-0000-0000-0000-000000000000",
                },
            ]
            config, _ = MODULE.build_config(candidates, listen="127.0.0.1", base_port=20000)
            MODULE.write_json(generation / "bridge.json", config)
            (root / "current").symlink_to(Path("generations") / "generation-1")

            current = MODULE.load_current_candidates(root, target=2)

        self.assertEqual([row["server"] for row in current], ["1.1.1.1", "8.8.8.8"])

    def test_fixed_slots_retain_order_and_fill_holes(self):
        current = [
            {"type": "trojan", "server": "1.1.1.1", "server_port": 443, "password": "c0"},
            {"type": "trojan", "server": "2.2.2.2", "server_port": 443, "password": "c1"},
            {"type": "trojan", "server": "3.3.3.3", "server_port": 443, "password": "c2"},
        ]
        new = [
            {"type": "trojan", "server": "4.4.4.4", "server_port": 443, "password": "n0"},
            {"type": "trojan", "server": "5.5.5.5", "server_port": 443, "password": "n0"},
            {"type": "trojan", "server": "6.6.6.6", "server_port": 443, "password": "n2"},
        ]
        candidates = current + new
        bridges = [{"port": 30000 + index} for index in range(len(candidates))]

        def result(index, egress, *, ok=True):
            group = MODULE.credential_group_id(candidates[index])
            spec = MODULE.ProxySpec(
                "socks5h",
                "127.0.0.1",
                bridges[index]["port"],
                credential_group_override=group,
            )
            return MODULE.ProbeResult(spec, ok, "passed" if ok else "failed", float(index), egress_ip=egress)

        results = [
            result(0, "egress-a"),
            result(1, "", ok=False),
            result(2, "egress-a"),
            result(3, "egress-b"),
            result(4, "egress-c"),
            result(5, "egress-d"),
        ]
        chosen, selected, stats = MODULE.select_fixed_slots(
            candidates,
            results,
            bridges,
            target=3,
            max_per_credential_group=1,
            max_per_egress=1,
            current_count=3,
        )

        self.assertEqual([row["server"] for row in chosen], ["1.1.1.1", "4.4.4.4", "6.6.6.6"])
        self.assertEqual([row.egress_ip for row in selected], ["egress-a", "egress-b", "egress-d"])
        self.assertEqual(
            stats,
            {
                "retained_count": 1,
                "retained_unhealthy_count": 0,
                "replaced_count": 2,
                "added_count": 0,
            },
        )

        changes = MODULE.build_slot_changes(
            current,
            chosen,
            results,
            selected,
            candidates,
            [{"port": row["port"], "index": index} for index, row in enumerate(bridges)],
            base_port=12000,
            direct_port=12400,
        )
        self.assertEqual(
            [row["status"] for row in changes],
            ["retained", "replaced", "replaced"],
        )
        self.assertEqual([row["port"] for row in changes], [12000, 12001, 12002])
        self.assertNotEqual(changes[1]["before_endpoint_id"], changes[1]["after_endpoint_id"])

    def test_unfilled_failed_slot_keeps_its_fixed_port(self):
        current = [
            {"type": "trojan", "server": "1.1.1.1", "server_port": 443, "password": "c0"},
            {"type": "trojan", "server": "2.2.2.2", "server_port": 443, "password": "c1"},
            {"type": "trojan", "server": "3.3.3.3", "server_port": 443, "password": "c2"},
        ]
        bridges = [{"port": 30000 + index} for index in range(len(current))]

        def result(index, egress, *, ok=True):
            spec = MODULE.ProxySpec(
                "socks5h",
                "127.0.0.1",
                bridges[index]["port"],
                credential_group_override=MODULE.credential_group_id(current[index]),
            )
            return MODULE.ProbeResult(
                spec, ok, "passed" if ok else "failed", float(index), egress_ip=egress
            )

        chosen, selected, stats = MODULE.select_fixed_slots(
            current,
            [result(0, "egress-a"), result(1, "", ok=False), result(2, "egress-c")],
            bridges,
            target=3,
            max_per_credential_group=1,
            current_count=3,
        )

        self.assertEqual([row["server"] for row in chosen], ["1.1.1.1", "2.2.2.2", "3.3.3.3"])
        self.assertEqual([row.egress_ip for row in selected], ["egress-a", "egress-c"])
        self.assertEqual(stats["retained_unhealthy_count"], 1)
        self.assertFalse(MODULE.refresh_requires_publish(stats))
        self.assertTrue(
            MODULE.refresh_requires_publish(stats, subscription_changed=True)
        )

    def test_healthy_slot_indices_and_subscription_omit_unhealthy_slot(self):
        candidates = [
            {"type": "trojan", "server": "1.1.1.1", "server_port": 443, "password": "c0"},
            {"type": "trojan", "server": "2.2.2.2", "server_port": 443, "password": "c1"},
            {"type": "trojan", "server": "3.3.3.3", "server_port": 443, "password": "c2"},
        ]
        bridges = [{"port": 20000 + index, "index": index} for index in range(3)]
        selected = [
            MODULE.ProbeResult(
                MODULE.ProxySpec(
                    "socks5h",
                    "127.0.0.1",
                    bridges[index]["port"],
                    credential_group_override=MODULE.credential_group_id(candidates[index]),
                ),
                True,
                "passed",
                1.0,
                egress_ip=f"egress-{index}",
            )
            for index in (0, 2)
        ]

        indices = MODULE.healthy_slot_indices(candidates, selected, candidates, bridges)
        self.assertEqual(indices, [0, 2])
        self.assertEqual(
            MODULE.build_subscription(
                "172.17.0.1",
                [{"port": 12000}, {"port": 12001}, {"port": 12002}],
                indices,
            ).decode().splitlines(),
            ["socks5h://172.17.0.1:12000", "socks5h://172.17.0.1:12002"],
        )

    def test_current_subscription_matches_active_generation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generation = root / "generations" / "current"
            generation.mkdir(parents=True)
            (root / "current").symlink_to("generations/current")
            expected = b"socks5h://172.17.0.1:12000\n"
            (generation / "proxies.txt").write_bytes(expected)

            self.assertTrue(MODULE.current_subscription_matches(root, expected))
            self.assertFalse(
                MODULE.current_subscription_matches(
                    root, b"socks5h://172.17.0.1:12001\n"
                )
            )

    def test_fixed_slots_keep_passing_nodes_that_share_an_egress(self):
        current = [
            {"type": "trojan", "server": "1.1.1.1", "server_port": 443, "password": "c0"},
            {"type": "trojan", "server": "2.2.2.2", "server_port": 443, "password": "c1"},
        ]
        bridges = [{"port": 30000}, {"port": 30001}]
        results = []
        for index, candidate in enumerate(current):
            spec = MODULE.ProxySpec(
                "socks5h",
                "127.0.0.1",
                bridges[index]["port"],
                credential_group_override=MODULE.credential_group_id(candidate),
            )
            results.append(MODULE.ProbeResult(spec, True, "passed", 1.0, egress_ip="shared"))

        chosen, selected, stats = MODULE.select_fixed_slots(
            current,
            results,
            bridges,
            target=2,
            max_per_credential_group=0,
            max_per_egress=0,
            current_count=2,
        )

        self.assertEqual(chosen, current)
        self.assertEqual(len(selected), 2)
        self.assertEqual(stats["retained_count"], 2)

    def test_fixed_slots_replace_cn_current_slot_with_non_cn_candidate(self):
        current = [
            {"type": "trojan", "server": "1.1.1.1", "server_port": 443, "password": "old"}
        ]
        replacement = {
            "type": "trojan",
            "server": "2.2.2.2",
            "server_port": 443,
            "password": "new",
        }
        candidates = [*current, replacement]
        bridges = [{"port": 30000}, {"port": 30001}]
        results = []
        for index, (egress, region) in enumerate(
            [("203.0.113.1", "cn"), ("203.0.113.2", "us")]
        ):
            spec = MODULE.ProxySpec(
                "socks5h",
                "127.0.0.1",
                bridges[index]["port"],
                credential_group_override=MODULE.credential_group_id(candidates[index]),
            )
            results.append(
                MODULE.ProbeResult(
                    spec, True, "passed", 1.0, egress_ip=egress, region=region
                )
            )

        chosen, selected, stats = MODULE.select_fixed_slots(
            candidates,
            results,
            bridges,
            target=1,
            max_per_credential_group=0,
            current_count=1,
            excluded_regions=["cn"],
        )

        self.assertEqual(chosen, [replacement])
        self.assertEqual([row.region for row in selected], ["us"])
        self.assertEqual(stats["replaced_count"], 1)

    def test_slot_changes_marks_passing_but_excluded_current_slot_unhealthy(self):
        current = [
            {"type": "trojan", "server": "1.1.1.1", "server_port": 443, "password": "old"}
        ]
        bridges = [{"port": 30000, "index": 0}]
        spec = MODULE.ProxySpec(
            "socks5h",
            "127.0.0.1",
            30000,
            credential_group_override=MODULE.credential_group_id(current[0]),
        )
        results = [
            MODULE.ProbeResult(
                spec,
                True,
                "passed",
                1.0,
                egress_ip="203.0.113.1",
                region="cn",
            )
        ]
        chosen, selected, stats = MODULE.select_fixed_slots(
            current,
            results,
            bridges,
            target=1,
            max_per_credential_group=0,
            current_count=1,
            excluded_regions=["cn"],
        )

        changes = MODULE.build_slot_changes(
            current,
            chosen,
            results,
            selected,
            current,
            bridges,
            base_port=12000,
        )

        self.assertEqual(stats["retained_unhealthy_count"], 1)
        self.assertEqual(changes[0]["status"], "retained_unhealthy")
        self.assertEqual(changes[0]["probe_category"], "selection_excluded")

    def test_refresh_publishes_only_when_fixed_slots_change(self):
        self.assertFalse(
            MODULE.refresh_requires_publish(
                {"retained_count": 400, "replaced_count": 0, "added_count": 0}
            )
        )
        self.assertTrue(
            MODULE.refresh_requires_publish(
                {"retained_count": 399, "replaced_count": 1, "added_count": 0}
            )
        )
        self.assertTrue(
            MODULE.refresh_requires_publish(
                {"retained_count": 0, "replaced_count": 0, "added_count": 400}
            )
        )

    def test_refresh_defers_small_batches_until_capacity_or_age_requires_publish(self):
        stats = {"retained_count": 370, "replaced_count": 30, "added_count": 0}
        self.assertFalse(MODULE.refresh_requires_publish(
            stats,
            current_healthy_count=370,
            minimum_healthy_nodes=3,
            minimum_replacements=80,
            generation_age_hours=3,
            maximum_generation_age_hours=24,
        ))
        self.assertTrue(MODULE.refresh_requires_publish(
            stats,
            current_healthy_count=370,
            minimum_healthy_nodes=3,
            minimum_replacements=80,
            generation_age_hours=24,
            maximum_generation_age_hours=24,
        ))
        self.assertTrue(MODULE.refresh_requires_publish(
            stats,
            current_healthy_count=2,
            minimum_healthy_nodes=3,
            minimum_replacements=80,
            generation_age_hours=3,
            maximum_generation_age_hours=24,
        ))

    @mock.patch.object(MODULE, "prune_generations", return_value=[])
    @mock.patch.object(MODULE, "publish")
    @mock.patch.object(MODULE, "probe_candidates")
    @mock.patch.object(MODULE, "public_candidate_subset")
    @mock.patch.object(MODULE, "load_candidates")
    @mock.patch.object(MODULE, "download_source", return_value=b"source")
    @mock.patch.object(MODULE, "load_current_candidates")
    def test_refresh_publishes_partial_hole_replacements_above_health_floor(
        self,
        load_current,
        _download,
        load_candidates,
        public_subset,
        probe_candidates,
        publish,
        _prune,
    ):
        current = [
            {"type": "trojan", "server": "1.1.1.1", "server_port": 443, "password": "c0"},
            {"type": "trojan", "server": "2.2.2.2", "server_port": 443, "password": "c1"},
            {"type": "trojan", "server": "3.3.3.3", "server_port": 443, "password": "c2"},
        ]
        replacement = {
            "type": "trojan",
            "server": "4.4.4.4",
            "server_port": 443,
            "password": "n0",
        }
        combined = [*current, replacement]
        bridges = [
            {"port": 20000 + index, "index": index}
            for index in range(len(combined))
        ]

        def result(index, egress, *, ok=True):
            spec = MODULE.ProxySpec(
                "socks5h",
                "127.0.0.1",
                bridges[index]["port"],
                credential_group_override=MODULE.credential_group_id(combined[index]),
            )
            return MODULE.ProbeResult(
                spec, ok, "passed" if ok else "failed", float(index), egress_ip=egress
            )

        load_current.return_value = current
        load_candidates.return_value = ([replacement], {"protocols": {"trojan": 1}})
        public_subset.return_value = ([replacement], {})
        probe_candidates.return_value = (
            [
                result(0, "egress-a"),
                result(1, "", ok=False),
                result(2, "", ok=False),
                result(3, "egress-d"),
            ],
            bridges,
        )
        publish.return_value = {
            "selected_count": 3,
            "healthy_slot_count": 2,
            "unique_egress_count": 2,
            "source_sha256": "hash",
            "run_id": "test-run",
            "generation": "test-generation",
        }
        with tempfile.TemporaryDirectory() as temp:
            args = mock.Mock(
                output_dir=temp,
                source_url="https://raw.githubusercontent.com/owner/repo/main/config.json",
                singbox_binary="/unused/sing-box",
                target_nodes=5,
                minimum_healthy_nodes=2,
                candidate_limit=2000,
                max_per_egress=0,
                max_per_credential_group=1,
                retain_generations=2,
                download_timeout=1,
                dns_workers=1,
                probe_listen="127.0.0.1",
                probe_base_port=20000,
                probe_timeout=1,
                probe_workers=1,
                probe_batch_size=4,
                target_hosts=["grok.com", "auth.x.ai"],
                min_target_hosts_passed=1,
                excluded_regions=[],
                publish_listen="172.17.0.1",
                publish_base_port=12000,
                minimum_replacements_to_publish=1,
                maximum_generation_age_hours=0,
            )

            self.assertEqual(MODULE.command_refresh(args), 0)

        self.assertEqual(public_subset.call_args.kwargs["limit"], 2000)

        published_candidates = publish.call_args.args[2]
        self.assertEqual(
            [row["server"] for row in published_candidates],
            ["1.1.1.1", "4.4.4.4", "3.3.3.3"],
        )
        self.assertEqual(publish.call_args.kwargs["replaced_count"], 1)
        self.assertEqual(publish.call_args.kwargs["retained_unhealthy_count"], 1)
        self.assertEqual(publish.call_args.kwargs["published_indices"], [0, 1])

    def test_publish_listen_requires_private_literal_ip_and_formats_ipv6(self):
        self.assertEqual(MODULE.validate_publish_listen("10.0.0.1"), "10.0.0.1")
        self.assertEqual(MODULE.validate_publish_listen("fd00::1"), "fd00::1")
        self.assertEqual(MODULE.format_proxy_host("fd00::1"), "[fd00::1]")
        for value in ("0.0.0.0", "127.0.0.1", "169.254.1.1", "8.8.8.8", "localhost"):
            with self.assertRaisesRegex(MODULE.BridgeError, "private literal IP"):
                MODULE.validate_publish_listen(value)

    def test_probe_listen_requires_loopback_literal_ip(self):
        self.assertEqual(MODULE.validate_probe_listen("127.0.0.1"), "127.0.0.1")
        self.assertEqual(MODULE.validate_probe_listen("::1"), "::1")
        for value in ("0.0.0.0", "172.17.0.1", "8.8.8.8", "localhost"):
            with self.assertRaisesRegex(MODULE.BridgeError, "loopback literal IP"):
                MODULE.validate_probe_listen(value)

    def test_startup_error_detail_never_exposes_raw_log(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "startup.log"
            path.write_text("secret-host secret-password bind: address already in use")
            self.assertEqual(MODULE.startup_error_detail(path), "listen_address_in_use")
            path.write_text("secret-host too many open files")
            self.assertEqual(MODULE.startup_error_detail(path), "file_descriptor_limit")
            path.write_text("secret-password unknown fatal error")
            self.assertEqual(MODULE.startup_error_detail(path), "unclassified_startup_failure")

    def test_probe_ports_stay_inside_reserved_range(self):
        MODULE.validate_probe_port_range(20000, 10000)
        MODULE.validate_probe_port_range(29999, 1)
        MODULE.validate_probe_port_range(65535, 1)
        for base, count in ((20000, 10001), (29999, 2), (65535, 2), (0, 1)):
            with self.assertRaises(MODULE.BridgeError):
                MODULE.validate_probe_port_range(base, count)

    @mock.patch.object(MODULE, "probe_many", return_value=[])
    @mock.patch.object(MODULE, "wait_for_ports")
    @mock.patch.object(MODULE, "run_singbox_check")
    @mock.patch.object(MODULE.subprocess, "Popen")
    def test_probe_candidates_forwards_target_quorum(
        self, popen, _check, _wait, probe_many
    ):
        process = mock.Mock()
        process.poll.return_value = 0
        popen.return_value = process
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.dict(
                MODULE.os.environ, {"RUNTIME_DIRECTORY": temp}, clear=False
            ):
                MODULE.probe_candidates(
                    Path("/unused/sing-box"),
                    [
                        {
                            "type": "trojan",
                            "server": "1.1.1.1",
                            "server_port": 443,
                            "password": "secret",
                        }
                    ],
                    listen="127.0.0.1",
                    base_port=20000,
                    timeout=1,
                    workers=1,
                    batch_size=1,
                    target_host=["one.example", "two.example", "three.example"],
                    min_target_hosts_passed=2,
                )

        self.assertEqual(probe_many.call_args.kwargs["min_target_hosts_passed"], 2)

    @mock.patch.object(MODULE, "run_singbox_check")
    def test_manifest_contains_only_aggregate_probe_metrics(self, _check):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidates = [
                {"type": "trojan", "server": "1.1.1.1", "server_port": 443, "password": "secret-a"},
                {"type": "vless", "server": "8.8.8.8", "server_port": 443, "uuid": "secret-uuid"},
            ]
            selected = [
                MODULE.ProbeResult(
                    MODULE.ProxySpec("socks5h", "127.0.0.1", 20000, credential_group_override="g0"),
                    True,
                    "passed",
                    1.0,
                    egress_ip="egress-a",
                ),
                MODULE.ProbeResult(
                    MODULE.ProxySpec("socks5h", "127.0.0.1", 20001, credential_group_override="g1"),
                    True,
                    "passed",
                    2.0,
                    egress_ip="egress-b",
                ),
            ]
            args = mock.Mock(
                output_dir=str(root),
                publish_listen="fd00::1",
                publish_base_port=12000,
                singbox_binary="/unused/sing-box",
                source_url="https://raw.githubusercontent.com/example/repo/config.json",
                target_hosts=("grok.com", "auth.x.ai"),
                min_target_hosts_passed=2,
                excluded_regions=[],
            )
            MODULE.publish(
                args,
                b"source-bytes",
                candidates,
                selected,
                {"protocols": {"trojan": 1, "vless": 1}},
                {},
                probe_input_count=4,
                passed_count=3,
                retained_count=1,
                retained_unhealthy_count=0,
                replaced_count=1,
                added_count=0,
            )
            manifest_path = (root / "current").resolve() / "manifest.json"
            payload = manifest_path.read_text(encoding="utf-8")
            manifest = json.loads(payload)
            slot_changes_payload = ((root / "current").resolve() / "slot-changes.json").read_text(
                encoding="utf-8"
            )
            slot_changes = json.loads(slot_changes_payload)
            subscription = ((root / "current").resolve() / "proxies.txt").read_text(
                encoding="utf-8"
            )

        self.assertEqual(manifest["probe_input_count"], 4)
        self.assertEqual(manifest["passed_count"], 3)
        self.assertEqual(manifest["retained_count"], 1)
        self.assertEqual(manifest["retained_unhealthy_count"], 0)
        self.assertEqual(manifest["replaced_count"], 1)
        self.assertEqual(manifest["added_count"], 0)
        self.assertEqual(manifest["healthy_slot_count"], 2)
        self.assertEqual(manifest["protocols"], {"trojan": 1, "vless": 1})
        self.assertEqual(manifest["credential_group_count"], 2)
        self.assertEqual(manifest["max_credential_group_count"], 1)
        self.assertEqual(manifest["slot_changes_file"], "slot-changes.json")
        self.assertEqual(slot_changes["generation"], manifest["generation"])
        self.assertEqual(slot_changes["changes"], [])
        self.assertEqual(manifest["target_hosts"], ["grok.com", "auth.x.ai"])
        self.assertEqual(manifest["min_target_hosts_passed"], 2)
        self.assertEqual(manifest["excluded_regions"], [])
        self.assertTrue(manifest["run_id"])
        self.assertNotIn("secret-a", payload)
        self.assertNotIn("secret-uuid", payload)
        self.assertNotIn("1.1.1.1", payload)
        self.assertNotIn("raw.githubusercontent.com", payload)
        self.assertNotIn("secret-a", slot_changes_payload)
        self.assertNotIn("secret-uuid", slot_changes_payload)
        self.assertEqual(subscription.splitlines(), ["socks5h://[fd00::1]:12000", "socks5h://[fd00::1]:12001"])

    @mock.patch.object(MODULE, "run_singbox_check")
    def test_publish_excludes_unhealthy_slots_from_subscription(self, _check):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidates = [
                {"type": "trojan", "server": "1.1.1.1", "server_port": 443, "password": "a"},
                {"type": "trojan", "server": "2.2.2.2", "server_port": 443, "password": "b"},
                {"type": "trojan", "server": "3.3.3.3", "server_port": 443, "password": "c"},
            ]
            selected = [
                MODULE.ProbeResult(
                    MODULE.ProxySpec("socks5h", "127.0.0.1", 20000 + index),
                    True,
                    "passed",
                    1.0,
                    egress_ip=f"egress-{index}",
                )
                for index in (0, 2)
            ]
            args = mock.Mock(
                output_dir=str(root),
                publish_listen="172.17.0.1",
                publish_base_port=12000,
                singbox_binary="/unused/sing-box",
                source_url="https://raw.githubusercontent.com/example/repo/config.json",
                target_hosts=("grok.com",),
                min_target_hosts_passed=1,
                excluded_regions=[],
            )
            manifest = MODULE.publish(
                args,
                b"source-bytes",
                candidates,
                selected,
                {"protocols": {"trojan": 3}},
                {},
                published_indices=[0, 2],
            )
            generation = (root / "current").resolve()
            self.assertEqual(
                (generation / "proxies.txt").read_text(encoding="utf-8").splitlines(),
                ["socks5h://172.17.0.1:12000", "socks5h://172.17.0.1:12002"],
            )
            self.assertEqual(manifest["slot_count"], 3)
            self.assertEqual(manifest["selected_count"], 2)
            self.assertEqual(manifest["healthy_slot_count"], 2)
            self.assertEqual(manifest["published_count"], 2)
            self.assertEqual(manifest["protocols"], {"trojan": 2})

    @mock.patch.object(
        MODULE,
        "run_singbox_check",
        side_effect=MODULE.BridgeError("invalid generated config"),
    )
    def test_publish_removes_incomplete_generation_on_precommit_failure(self, _check):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidates = [
                {"type": "trojan", "server": "1.1.1.1", "server_port": 443, "password": "a"}
            ]
            selected = [
                MODULE.ProbeResult(
                    MODULE.ProxySpec("socks5h", "127.0.0.1", 20000),
                    True,
                    "passed",
                    1.0,
                    egress_ip="egress-a",
                )
            ]
            args = mock.Mock(
                output_dir=str(root),
                publish_listen="172.17.0.1",
                publish_base_port=12000,
                singbox_binary="/unused/sing-box",
                target_hosts=("grok.com",),
                min_target_hosts_passed=1,
                excluded_regions=[],
            )
            with self.assertRaisesRegex(MODULE.BridgeError, "invalid generated config"):
                MODULE.publish(
                    args,
                    b"source-bytes",
                    candidates,
                    selected,
                    {},
                    {},
                    published_indices=[0],
                )
            generations = root / "generations"
            self.assertFalse(list(generations.iterdir()) if generations.exists() else [])


class PreparedGenerationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.old = self.root / "generations" / "previous"
        self.old.mkdir(parents=True)
        MODULE.write_json(self.old / "manifest.json", {"owner": MODULE.OWNER, "generation": "previous"})
        (self.root / "current").symlink_to("generations/previous")
        self.candidate = {"type": "trojan", "server": "1.1.1.1", "server_port": 443, "password": "test"}
        self.args = argparse.Namespace(output_dir=str(self.root), publish_listen="172.17.0.1",
            publish_base_port=12000, singbox_binary="/unused/sing-box", prepare_only=True)
        selected = [MODULE.ProbeResult(MODULE.ProxySpec("socks5h", "127.0.0.1", 20000),
                                      True, "passed", 1.0, egress_ip="8.8.8.8")]
        with mock.patch.object(MODULE, "run_singbox_check"):
            self.manifest = MODULE.publish(self.args, b"source", [self.candidate], selected, {}, {})
        self.prepared = self.root / "prepared.json"
        self.new = self.root / "generations" / self.manifest["generation"]
        self.promote = argparse.Namespace(output_dir=str(self.root), max_age_seconds=1800)

    def test_prepare_keeps_current_and_prune_protects_both_generations(self):
        self.assertEqual((self.root / "current").resolve(), self.old)
        self.assertFalse((self.root / "staged").is_symlink())
        MODULE.prune_generations(self.root, 1)
        self.assertTrue(self.old.exists())
        self.assertTrue(self.new.exists())

    @mock.patch("builtins.print")
    def test_promote_then_rollback_keeps_previous_generation(self, _print):
        self.assertEqual(MODULE.command_promote(self.promote), 0)
        self.assertEqual((self.root / "current").resolve(), self.new)
        self.assertEqual((self.root / "staged").resolve(), self.old)
        self.assertFalse(self.prepared.exists())
        MODULE.command_rollback(argparse.Namespace(output_dir=str(self.root)))
        self.assertEqual((self.root / "current").resolve(), self.old)

    def test_generation_drift_discards_preparation_without_changing_current(self):
        other = self.root / "generations" / "another"
        other.mkdir()
        MODULE._atomic_current_link(self.root, other)
        with self.assertRaisesRegex(MODULE.BridgeError, "changed during preparation"):
            MODULE.command_promote(self.promote)
        self.assertFalse(self.prepared.exists())
        self.assertEqual((self.root / "current").resolve(), other)
        self.assertFalse((self.root / "staged").is_symlink())

    def test_stale_preparation_is_discarded(self):
        prepared = MODULE.load_json(self.prepared)
        prepared["prepared_at"] -= 1801
        MODULE.write_json(self.prepared, prepared)
        with self.assertRaisesRegex(MODULE.BridgeError, "stale"):
            MODULE.command_promote(self.promote)
        self.assertFalse(self.prepared.exists())
        self.assertEqual((self.root / "current").resolve(), self.old)

    def test_modified_config_is_rejected_before_pointer_switch(self):
        (self.new / "bridge.json").write_text("{}")
        with self.assertRaisesRegex(MODULE.BridgeError, "artifact integrity"):
            MODULE.command_promote(self.promote)
        self.assertEqual((self.root / "current").resolve(), self.old)
        self.assertFalse((self.root / "staged").is_symlink())

    @mock.patch("builtins.print")
    def test_interrupted_promotion_can_finish_idempotently(self, _print):
        MODULE._stage_previous_generation(self.root, self.old)
        MODULE._atomic_current_link(self.root, self.new)
        self.assertEqual(MODULE.command_promote(self.promote), 0)
        self.assertEqual((self.root / "current").resolve(), self.new)
        self.assertEqual((self.root / "staged").resolve(), self.old)
        self.assertFalse(self.prepared.exists())


class DiscoveryRegressionTests(unittest.TestCase):
    def test_connection_parameters_distinguish_same_endpoint(self):
        base = {"type": "vless", "server": "example.com", "server_port": 443, "uuid": "test",
                "tls": {"enabled": True, "server_name": "one.example"},
                "transport": {"type": "ws", "path": "/one"}}
        variants = [base, dict(base, tls={"enabled": True, "server_name": "two.example"}),
                    dict(base, transport={"type": "ws", "path": "/two"})]
        parsed, _ = MODULE.load_candidates(json.dumps({"outbounds": variants + [dict(base, tag="alias")]}).encode())
        self.assertEqual(len(parsed), 3)
        self.assertEqual(len({MODULE.endpoint_key(row) for row in parsed}), 3)

    def test_source_failure_still_health_checks_existing_candidates(self):
        current = {"type": "trojan", "server": "1.1.1.1", "server_port": 443, "password": "test"}
        with tempfile.TemporaryDirectory() as directory:
            args = MODULE.build_parser().parse_args(["refresh", "--output-dir", directory,
                "--source-url", "https://raw.githubusercontent.com/example/repo/main/config.json",
                "--target-nodes", "1"])
            with mock.patch.object(MODULE, "load_current_candidates", return_value=[current]), \
                    mock.patch.object(MODULE, "download_source", side_effect=MODULE.BridgeError("source unavailable")), \
                    mock.patch.object(MODULE, "probe_candidates", side_effect=RuntimeError("health checks reached")) as probe:
                with self.assertRaisesRegex(RuntimeError, "health checks reached"):
                    MODULE.command_refresh(args)
                self.assertEqual(probe.call_args.args[1], [current])


if __name__ == "__main__":
    unittest.main()
