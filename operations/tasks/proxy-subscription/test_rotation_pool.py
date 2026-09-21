import copy
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

import rotation_pool as POOL
from test_site_quality import approval, report, client_report, NOW


def slots():
    return {f"US-{n:02d}": {"region": "us", "uuid": str(uuid.UUID(int=n)),
            "email": f"browse-us-{n:02d}", "platform_name": f"BrowseUS{n:02d}",
            "platform_id": str(n)} for n in range(1, 9)} | {
        f"HK-{n:02d}": {"region": "hk", "uuid": str(uuid.UUID(int=n + 8)),
            "email": f"browse-hk-{n:02d}", "platform_name": f"BrowseHK{n:02d}",
            "platform_id": str(n + 8)} for n in range(1, 5)}


class RotationTest(unittest.TestCase):
    def setUp(self):
        split = patch.object(POOL, "split_enabled", return_value=False)
        split.start()
        self.addCleanup(split.stop)
        patcher = patch.object(POOL, "unified", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def config(self, approved=None, stable=True):
        base = {"proxies": [{"name": "weesai.com-vless-443-ws", "uuid": "original",
                              "type": "vless", "network": "ws"}]}
        site = {"proxies": [{"name": "SG-Auto"}]} if stable else {"proxies": []}
        return POOL.render(base, site, slots(), slots() if approved is None else approved)

    def test_twelve_independent_exits_and_separate_stable_route(self):
        config = self.config()
        self.assertEqual(len(config["proxies"]), 13)
        self.assertEqual(len({p["uuid"] for p in config["proxies"] if "uuid" in p}), 12)
        groups = {g["name"]: g for g in config["proxy-groups"]}
        self.assertEqual(groups["Auto-Fast"]["strategy"], "sticky-sessions")
        self.assertEqual(groups["Auto-Rotate"]["strategy"], "round-robin")
        self.assertNotIn("SG-Auto", groups["Auto-Fast"]["proxies"])
        self.assertNotIn("PROXY", groups["Site-Stable"]["proxies"])
        self.assertEqual(config["rules"][:3], [f"DOMAIN-SUFFIX,{d},Site-Stable" for d in POOL.SITE_DOMAINS])
        self.assertEqual(config["rules"][-1], "MATCH,PROXY")

    def test_browser_pools_are_disjoint_and_manual_choice_is_respected(self):
        config = self.config()
        groups = {g["name"]: g for g in config["proxy-groups"]}
        sets = [set(groups[f"Browser-{i}-Auto"]["proxies"]) for i in range(1, 5)]
        self.assertEqual(sum(map(len, sets)), len(set.union(*sets)))
        self.assertEqual([x["port"] for x in config["listeners"]], list(range(17891, 17895)))
        for i in range(1, 5):
            self.assertEqual(groups[f"Browser-{i}"]["proxies"][0], "PROXY")
            self.assertIn(f"IN-NAME,browser-{i},Browser-{i}-Auto", config["rules"])

    def test_empty_pools_fail_closed(self):
        config = self.config({}, stable=False)
        groups = {g["name"]: g for g in config["proxy-groups"]}
        self.assertEqual(groups["PROXY"]["proxies"], ["REJECT"])
        self.assertEqual(groups["Site-Stable"]["proxies"], ["REJECT"])
        self.assertEqual(config["proxies"], [])

    def test_unreadable_approvals_close_owned_platforms(self):
        class API:
            def call(self, endpoint, method="GET", data=None):
                spec = next(iter(slots().values()))
                row = {"name": spec["platform_name"], "region_filters": [spec["region"]],
                       "regex_filters": ["previous"], "allocation_policy": "PREFER_LOW_LATENCY",
                       "passive_circuit_breaker_disabled": True, "routable_node_count": 1}
                if data is not None:
                    self.patch = data
                    row.update(data, routable_node_count=0)
                return row
        api = API()
        with patch.object(POOL, "load_state", side_effect=ValueError("invalid")):
            self.assertEqual(POOL.enforce(api, slots={"US-01": slots()["US-01"]}), {})
        self.assertEqual(api.patch["regex_filters"], POOL.site_policy.DENY)

    def test_tampered_slot_ownership_and_duplicate_identity_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "slots.json"
            good = slots()
            path.write_text(json.dumps(good))
            self.assertEqual(POOL.load_slots(path), good)
            for key, value in (("email", "other"), ("region", "jp"), ("platform_name", "AppsGlobal"),
                               ("uuid", good["US-02"]["uuid"]), ("platform_id", good["US-02"]["platform_id"])):
                bad = copy.deepcopy(good)
                bad["US-01"][key] = value
                path.write_text(json.dumps(bad))
                with self.assertRaises(ValueError):
                    POOL.load_slots(path)

    def test_expired_failed_staged_duplicate_or_changed_exits_excluded(self):
        row = dict(approval(), passed=True)
        state = {"approved": {"US-01": row}}
        identities = {row["port"]: row["slot_identity"]}
        with patch.object(POOL.site_policy, "effective", return_value={"us": row}):
            self.assertEqual(set(POOL.effective(state, slots(), identities, [], NOW)), {"US-01"})
            for key, value in (("checked_at", NOW - POOL.TTL), ("passed", False),
                               ("validation_path", "bridge")):
                bad = {"approved": {"US-01": dict(row, **{key: value})}}
                self.assertEqual(POOL.effective(bad, slots(), identities, [], NOW), {})
            state["approved"]["US-02"] = row
            self.assertEqual(len(POOL.effective(state, slots(), identities, [], NOW)), 1)
        self.assertEqual(POOL.effective(state, slots(), {}, [], NOW), {})

    def test_simple_ui_has_exactly_three_groups_and_one_shared_pool(self):
        base = {"proxies": [{"name": "weesai.com-vless-443-ws"}],
                "listeners": [{"port": 17891}], "find-process": True}
        config = POOL.render_simple(base, slots(), slots())
        self.assertEqual([g["name"] for g in config["proxy-groups"]], ["PROXY", "Auto-Fast", "Auto-Rotate"])
        _, fast, rotate = config["proxy-groups"]
        self.assertEqual(fast["type"], "url-test")
        self.assertEqual(fast["tolerance"], 150)
        self.assertEqual(rotate["strategy"], "sticky-sessions")
        self.assertEqual(fast["proxies"], rotate["proxies"])
        self.assertEqual(config["rules"], ["MATCH,PROXY"])
        self.assertNotIn("listeners", config)
        self.assertEqual(config["find-process-mode"], "off")

    def test_shared_pool_requires_real_two_round_browser_evidence(self):
        row = dict(approval(), passed=True)
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for i, times in enumerate(((NOW - 300, NOW - 200), (NOW - 100, NOW - 50))):
                evidence = client_report(report(*times))
                evidence["selected"] = "US-01"
                evidence["route_role"] = "audit" if i == 0 else "public"
                evidence["nodes"][0]["selected"] = "US-01"
                path = Path(directory) / f"round-{i}.json"
                path.write_text(json.dumps(evidence))
                paths.append(str(path))
            row["site_quality"] = {"version": 1, "selected": "US-01",
                "identity": [row[k] for k in POOL.IDENTITY_FIELDS], "checked_at": NOW - 100, "reports": paths}
            self.assertTrue(POOL.site_qualified("US-01", row, NOW))
            self.assertFalse(POOL.site_qualified("US-02", row, NOW))
            self.assertFalse(POOL.site_qualified("US-01", dict(row, expected_ip="1.1.1.1"), NOW))
            self.assertFalse(POOL.site_qualified("US-01", row, NOW + POOL.QUALITY_TTL))
            evidence["route_role"] = "audit"
            path.write_text(json.dumps(evidence))
            self.assertFalse(POOL.site_qualified("US-01", row, NOW))
            evidence.pop("route_role")
            path.write_text(json.dumps(evidence))
            self.assertFalse(POOL.site_qualified("US-01", row, NOW))
            evidence["route_role"] = "public"
            path.write_text(json.dumps(evidence))
            first = json.loads(Path(paths[0]).read_text())
            first["route_role"] = "public"
            Path(paths[0]).write_text(json.dumps(first))
            self.assertTrue(POOL.site_qualified("US-01", row, NOW))
            evidence["nodes"][0]["sites"]["linux.do"]["verdict"] = "challenge"
            path.write_text(json.dumps(evidence))
            self.assertFalse(POOL.site_qualified("US-01", row, NOW))

    def test_connectivity_only_approval_cannot_enter_shared_pool(self):
        row = dict(approval(), passed=True)
        with patch.object(POOL.site_policy, "effective", return_value={"us": row}):
            self.assertEqual(POOL.effective({"approved": {"US-01": row}}, slots(), {}, [], NOW,
                                           require_sites=True), {})


if __name__ == "__main__":
    unittest.main()
