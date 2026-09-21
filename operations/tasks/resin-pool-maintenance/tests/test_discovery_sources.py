import argparse
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_singbox_bridge_pool import MODULE


NODE = {"type": "trojan", "server": "1.1.1.1", "server_port": 443, "password": "test-only"}
DATA = json.dumps({"outbounds": [NODE]}).encode()
NOW = 1800000000


class DiscoverySourcesTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = self.root / "sources.json"
        self.args = argparse.Namespace(discovery_config=str(self.config), download_timeout=10,
                                       subscription_converter="/unused/converter")

    def configure(self, **values):
        MODULE.write_json(self.config, {"version": 1, **values})

    def test_search_parser_uses_result_links_only(self):
        gist = "a" * 32
        parser = MODULE.GistSearchResults()
        parser.feed(f'<a class="Link--muted" href="/other/{"b" * 32}">outside</a>'
                    f'<div class="gist-snippet"><div><a class="Link--muted" href="/owner/{gist}">result</a>'
                    f'<a class="Link--muted" href="/owner/{gist}#comments">comments</a>'
                    f'<a class="Link--muted" href="https://evil.example/owner/{"c" * 32}">external</a>'
                    f'</div></div><a class="Link--muted" href="/other/{"d" * 32}">outside</a>')
        self.assertEqual(parser.ids, [gist])

    def test_raw_hosts_reject_credentials_ports_redirect_targets_and_queries(self):
        resolver = mock.Mock()
        MODULE.validate_source_url("https://gist.githubusercontent.com/owner/id/raw/rev/nodes.txt", resolver)
        for url in ("https://example.com/config", "http://raw.githubusercontent.com/config",
                    "https://token@raw.githubusercontent.com/config", "https://gist.githubusercontent.com:444/config",
                    "https://raw.githubusercontent.com/config?token=secret", "https://127.0.0.1/config"):
            with self.subTest(url=url), self.assertRaises(MODULE.BridgeError):
                MODULE.validate_source_url(url, resolver)

    def test_partial_source_failure_is_cached_without_retrying_every_maintenance(self):
        self.configure(sources=["https://raw.githubusercontent.com/good/config.json",
                                "https://raw.githubusercontent.com/bad/config.json"])
        with mock.patch.object(MODULE.time, "time", return_value=NOW), \
                mock.patch.object(MODULE, "download_source", side_effect=[DATA, MODULE.BridgeError("unavailable")]) as fetch:
            rows, report = MODULE.discover_sources(self.args, self.root)
            again, cached = MODULE.discover_sources(self.args, self.root)
        self.assertEqual(rows, [NODE])
        self.assertEqual(again, rows)
        self.assertEqual(report["status"], "partial")
        self.assertTrue(cached["cache_hit"])
        self.assertEqual(fetch.call_count, 2)
        self.assertNotIn("test-only", json.dumps(report))

    def test_failed_refresh_uses_recent_cache_without_extending_its_expiry(self):
        self.configure(sources=["https://raw.githubusercontent.com/good/config.json"])
        with mock.patch.object(MODULE.time, "time", return_value=NOW), \
                mock.patch.object(MODULE, "download_source", return_value=DATA):
            MODULE.discover_sources(self.args, self.root)
        with mock.patch.object(MODULE.time, "time", return_value=NOW + 7 * 3600), \
                mock.patch.object(MODULE, "download_source", side_effect=MODULE.BridgeError("unavailable")):
            rows, report = MODULE.discover_sources(self.args, self.root)
        self.assertEqual(rows, [NODE])
        self.assertTrue(report["cached_fallback"])
        self.assertEqual(MODULE.load_json(self.root / "discovery-cache.json")["fetched_at"], NOW)
        with mock.patch.object(MODULE.time, "time", return_value=NOW + 25 * 3600), \
                mock.patch.object(MODULE, "download_source", side_effect=MODULE.BridgeError("unavailable")):
            rows, _ = MODULE.discover_sources(self.args, self.root)
        self.assertEqual(rows, [])

    def test_private_gist_is_not_downloaded(self):
        gist = "a" * 32
        self.configure(gist={"ids": [gist]})
        with mock.patch.object(MODULE.time, "time", return_value=NOW), \
                mock.patch.object(MODULE, "download_source", return_value=json.dumps({"id": gist, "public": False}).encode()) as fetch:
            rows, report = MODULE.discover_sources(self.args, self.root)
        self.assertEqual(rows, [])
        self.assertEqual(report["search_errors"], 1)
        fetch.assert_called_once()

    def test_truncated_gist_always_downloads_raw_and_limits_files_per_gist(self):
        gist = "a" * 32
        raw = f"https://gist.githubusercontent.com/owner/{gist}/raw/{'b' * 40}/nodes.yaml"
        self.configure(gist={"ids": [gist]})
        metadata = {"id": gist, "public": True, "files": {"nodes.yaml": {"filename": "nodes.yaml",
            "language": "YAML", "size": len(DATA), "truncated": True, "content": "untrusted partial content", "raw_url": raw}}}
        with mock.patch.object(MODULE.time, "time", return_value=NOW), \
                mock.patch.object(MODULE, "download_source", side_effect=[json.dumps(metadata).encode(), DATA]) as fetch:
            rows, report = MODULE.discover_sources(self.args, self.root)
        self.assertEqual(rows, [NODE])
        self.assertEqual(fetch.call_args_list[-1].args[0], raw)
        self.assertEqual(report["sources_ok"], 1)

    def test_malformed_optional_node_cannot_invalidate_other_candidates(self):
        bad = dict(NODE, password="invalid-test-config")

        def check(binary, path, **kwargs):
            if "invalid-test-config" in path.read_text():
                raise MODULE.BridgeError("invalid config")

        with mock.patch.object(MODULE, "run_singbox_check", side_effect=check):
            self.assertEqual(MODULE.compatible_candidates(Path("/unused/sing-box"), [NODE, bad]), [NODE])

    def test_converter_receives_data_on_stdin_and_never_network_arguments(self):
        def run(command, **kwargs):
            self.assertEqual(command, ["/trusted/converter"])
            self.assertEqual(kwargs["input"], b"unparsed subscription")
            kwargs["stdout"].write(DATA)
            return mock.Mock(returncode=0)

        with mock.patch.object(MODULE.subprocess, "run", side_effect=run):
            rows, _ = MODULE.convert_candidates(b"unparsed subscription", "/trusted/converter")
        self.assertEqual(rows, [NODE])

    def test_source_dns_failure_is_normalized_for_current_pool_fallback(self):
        with mock.patch.object(MODULE, "PublicResolver") as resolver:
            resolver.return_value.resolve.side_effect = MODULE.ProbeError("proxy_dns_failed")
            with self.assertRaisesRegex(MODULE.BridgeError, "DNS or address"):
                MODULE.download_source("https://raw.githubusercontent.com/owner/repo/config.json", 10)

    def test_download_and_parse_failures_are_distinct_without_secret_details(self):
        self.configure(sources=["https://raw.githubusercontent.com/a/config", "https://raw.githubusercontent.com/b/config"])
        with mock.patch.object(MODULE.time, "time", return_value=NOW), \
                mock.patch.object(MODULE, "download_source", side_effect=[MODULE.BridgeError("source download returned HTTP 429"), DATA]), \
                mock.patch.object(MODULE, "convert_candidates", side_effect=MODULE.BridgeError("bad password=test-secret")):
            _, report = MODULE.discover_sources(self.args, self.root)
        self.assertEqual(report["sources"][0]["http_status"], 429)
        self.assertEqual(report["sources"][0]["error_stage"], "download")
        self.assertEqual(report["sources"][1]["error_stage"], "parse")
        self.assertNotIn("test-secret", json.dumps(report))

    def test_incompatible_batch_has_a_finite_check_budget(self):
        rows = [dict(NODE, server_port=port) for port in range(10000, 11000)]
        with mock.patch.object(MODULE, "run_singbox_check", side_effect=MODULE.BridgeError("invalid")) as check:
            self.assertEqual(MODULE.compatible_candidates(Path("/unused/sing-box"), rows), [])
        self.assertLessEqual(check.call_count, 64)

    def test_deep_source_or_outbound_is_rejected_without_crashing_refresh(self):
        with self.assertRaises(MODULE.BridgeError):
            MODULE.load_candidates(b"[" * 2000 + b"]" * 2000)
        nested = {}
        for _ in range(20):
            nested = {"extra": nested}
        rows, report = MODULE.load_candidates(json.dumps({"outbounds": [NODE, dict(NODE, tls=nested)]}).encode())
        self.assertEqual(rows, [NODE])
        self.assertEqual(report["rejected"]["outbound nesting exceeds limit"], 1)


if __name__ == "__main__":
    unittest.main()
