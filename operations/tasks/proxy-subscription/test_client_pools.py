import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

import client_pools as pools
import rotation_pool


def entries():
    return {name: dict(row, uuid=str(uuid.uuid4()), platform_id="platform-" + name)
            for name, row in pools.definitions().items()}


class ClientPoolTests(unittest.TestCase):
    def setUp(self):
        self.entries = entries()
        self.base = {"proxies": [{"name": "weesai.com-vless-443-ws", "type": "vless", "uuid": "base",
                                  "network": "ws", "server": "example.invalid"}],
                     "listeners": [{"port": 17891}], "find-process": True}

    def test_empty_strict_pool_keeps_general_and_stable_strict_identities(self):
        rendered = pools.render(self.base, self.entries, {}, {})
        by_name = {row["name"]: row for row in rendered["proxy-groups"]}
        self.assertEqual(set(by_name["Auto-Fast"]["proxies"]), set(pools.GENERAL))
        self.assertEqual(by_name["Site-Strict"]["proxies"], [pools.STRICT_NAME])
        self.assertEqual(rendered["rules"][-1], "MATCH,PROXY")
        for domain in rotation_pool.SITE_DOMAINS:
            self.assertIn(f"DOMAIN-SUFFIX,{domain},Site-Strict", rendered["rules"][:-1])
        self.assertNotIn("listeners", rendered)
        self.assertEqual(len(rendered["proxies"]), 8)

    def test_browser_failures_do_not_change_general_filter(self):
        for name in pools.GENERAL:
            self.assertEqual(pools.desired(self.entries[name], {})["regex_filters"], pools.GENERAL_FILTER)
        strict = self.entries[pools.STRICT_NAME]
        self.assertEqual(pools.desired(strict, {})["regex_filters"], ["^$"])
        desired = pools.desired(strict, {"US-01": {"port": 12001}, "SG-01": {"port": 12002}})
        self.assertEqual(len(desired["regex_filters"]), 2)
        self.assertTrue(all(pattern.endswith("$") for pattern in desired["regex_filters"]))
        self.assertNotIn(pools.GENERAL_FILTER[0], desired["regex_filters"])

    def test_api_null_region_list_matches_empty_but_not_a_required_region(self):
        self.assertTrue(pools.matches({"region_filters": None}, {"region_filters": []}))
        self.assertFalse(pools.matches({"region_filters": None}, {"region_filters": ["us"]}))
        self.assertFalse(pools.matches({"regex_filters": None}, {"regex_filters": ["^$"]}))

    def test_strict_route_count_mismatch_is_closed_before_error(self):
        entry = self.entries[pools.STRICT_NAME]
        row = dict(pools.desired(entry, {}), name=entry["platform_name"], routable_node_count=9)
        calls = []
        class API:
            def call(self, endpoint, method="GET", data=None):
                calls.append((method, data))
                return row
        with self.assertRaises(RuntimeError):
            pools.enforce(API(), {}, {pools.STRICT_NAME: entry})
        self.assertEqual(calls[-1], ("PATCH", {"regex_filters": ["^$"]}))

    def test_xray_installs_only_explicit_user_routes_and_is_idempotent(self):
        config = {"inbounds": [{"tag": "proxy-ws", "settings": {"clients": [{"id": "old", "email": "existing"}]}}],
                  "outbounds": [{"tag": "direct", "protocol": "freedom"},
                                {"tag": "resin-sg", "protocol": "socks", "settings": {
                                    "servers": [{"address": "127.0.0.1", "port": 9999,
                                                 "users": [{"user": "ProxySG", "pass": "fixture"}]}]}}],
                  "routing": {"rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"}]}}
        original = copy.deepcopy(config)
        installed = pools.configure_xray(config, self.entries)
        self.assertEqual(config, original)
        self.assertEqual(pools.configure_xray(installed, self.entries), installed)
        self.assertEqual(installed["routing"]["rules"][0], original["routing"]["rules"][0])
        self.assertTrue(all(row.get("user") for row in installed["routing"]["rules"][1:]))
        for outbound in installed["outbounds"][2:]:
            self.assertTrue(outbound["settings"]["servers"][0]["users"][0]["user"].endswith(".profile"))
        pools.verify_xray(installed, self.entries)
        with self.assertRaises(ValueError):
            pools.verify_xray(original, self.entries)

    def test_manifest_rejects_duplicate_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pools.json"
            rows = copy.deepcopy(self.entries)
            rows["US-General"]["uuid"] = rows["Global-Auto"]["uuid"]
            path.write_text(json.dumps({"version": 1, "owner": pools.OWNER, "entries": rows}))
            with self.assertRaises(ValueError):
                pools.load(path)

    def test_split_policy_keeps_browser_gate_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text('{"version":1,"mode":"split"}')
            self.assertTrue(rotation_pool.split_enabled(path))
            self.assertTrue(rotation_pool.unified(path))


if __name__ == "__main__":
    unittest.main()
