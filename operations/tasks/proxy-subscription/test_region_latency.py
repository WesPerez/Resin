import copy
import importlib.util
from pathlib import Path
import re
import fcntl
import subprocess
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("region_latency", Path(__file__).with_name("region-latency.py"))
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)


def node(number, latency, region="us", egress=None, source=None):
    source = source or MODULE.source_for(region)
    return {"node_hash": f"{number:064x}", "enabled": True, "has_outbound": True,
            "region": region, "egress_ip": egress or f"192.0.2.{number}",
            "circuit_open_since": None, "failure_count": 0,
            "reference_latency_ms": latency,
            "tags": [{"subscription_name": source, "tag": f"{source}/slot-{number}.[x]"}]}


class FakeAPI:
    def __init__(self):
        self.rows = [node(1, 10), node(2, 100), node(3, 20, "jp")]
        self.platforms = {r: {"id": r, "name": "Proxy" + r.upper(), "region_filters": [r],
                              "regex_filters": [MODULE.source_filter(r)],
                              "allocation_policy": "BALANCED", "routable_node_count": 2}
                          for r in ("us", "jp")}
        self.patches = []
        self.fail_jp = False

    def nodes(self):
        return copy.deepcopy(self.rows)

    def call(self, path, method="GET", data=None):
        if "/actions/probe-latency" in path:
            return {"latency_ewma_ms": 30}
        region = path.rsplit("/", 1)[1]
        if method == "PATCH":
            if self.fail_jp and region == "jp" and data["allocation_policy"] == "PREFER_LOW_LATENCY":
                raise RuntimeError("injected patch failure")
            self.patches.append((region, copy.deepcopy(data)))
            self.platforms[region].update(data)
        return copy.deepcopy(self.platforms[region])


class RegionLatencyTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(MODULE, "bridge_port", return_value=12001)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(MODULE, "probe_bridge", return_value=30)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_filters_are_source_bounded_and_exact(self):
        row = node(1, 10)
        filters = MODULE.selected_filters([row], "us")
        self.assertEqual(filters[0], "*^managed-apps-public-pool/.*")
        self.assertRegex(row["tags"][0]["tag"], filters[1])
        self.assertIsNone(re.search(filters[1], row["tags"][0]["tag"] + "extra"))
        self.assertIsNone(re.search(filters[1], row["tags"][0]["tag"].replace(".[x]", "-x")))

    def test_shortlist_excludes_bad_wrong_region_source_and_duplicate_exit(self):
        good = node(1, 30)
        duplicate = node(2, 90, egress=good["egress_ip"])
        bad = node(3, 1)
        bad["circuit_open_since"] = "now"
        rows = [good, duplicate, bad, node(4, 1, "jp"), node(5, 1, source="unmanaged")]
        self.assertEqual(MODULE.shortlist(rows, "us"), [good])

    def test_cn_is_separate_and_unknown_latency_sorts_last(self):
        rows = [node(1, None, "cn"), node(2, 60, "cn"), node(3, float("nan"), "cn")]
        self.assertEqual(MODULE.shortlist(rows, "cn")[0]["node_hash"], rows[1]["node_hash"])
        self.assertTrue(MODULE.selected_filters(rows[:1], "cn")[0].startswith("*^managed-apps-cn-public-pool/"))

    def test_apply_and_rollback_are_subscription_scoped(self):
        manifest = {"ProxyUS": {"region": "us", "id": "us"}, "ProxyJP": {"region": "jp", "id": "jp"}}
        api = FakeAPI()
        MODULE.optimize(api, manifest, False)
        self.assertEqual(api.patches, [])
        before = copy.deepcopy(api.platforms)
        api.fail_jp = True
        with self.assertRaisesRegex(RuntimeError, "prior filters restored"):
            MODULE.optimize(api, manifest, True)
        self.assertEqual(api.platforms, before)
        api.fail_jp = False
        MODULE.optimize(api, manifest, True)
        self.assertEqual(api.platforms["us"]["allocation_policy"], "PREFER_LOW_LATENCY")
        self.assertEqual(api.platforms["us"]["region_filters"], ["us"])

    def test_no_fresh_success_restores_regional_pool(self):
        api = FakeAPI()
        call = api.call
        def fail_probes(path, method="GET", data=None):
            if "/actions/" in path:
                raise TimeoutError()
            return call(path, method, data)
        api.call = fail_probes
        with mock.patch.object(MODULE, "probe_bridge", return_value=None):
            MODULE.optimize(api, {"ProxyUS": {"region": "us", "id": "us"}}, True)
        self.assertEqual(api.platforms["us"]["regex_filters"], [MODULE.source_filter("us")])

    def test_exploration_keeps_fast_candidates_and_distinct_exits(self):
        rows = [node(i, i) for i in range(1, 41)]
        selected = MODULE.shortlist(rows, "us", seed=1)
        self.assertEqual(len(selected), 16)
        self.assertEqual(selected[:12], rows[:12])
        self.assertTrue(all(row in rows[16:] for row in selected[12:]))
        self.assertEqual(len({row["egress_ip"] for row in selected}), 16)

    def test_save_and_restore_preserve_unrelated_platform_fields(self):
        api = FakeAPI()
        manifest = {"ProxyUS": {"region": "us", "id": "us"}}
        original = copy.deepcopy(api.platforms["us"])
        with tempfile.TemporaryDirectory() as directory:
            saved = Path(directory) / "original.json"
            MODULE.save_restore_point(api, manifest, saved)
            MODULE.optimize(api, manifest, True)
            MODULE.save_restore_point(api, manifest, saved)
            MODULE.restore(api, manifest, saved)
        self.assertEqual(api.platforms["us"], original)


class ProbeSafetyTest(unittest.TestCase):
    def test_bridge_port_only_accepts_managed_local_slots(self):
        row = node(1, 10)
        source = MODULE.source_for("us")
        for value, expected in (("12000", 12000), ("13000", 13000), ("12400", None),
                                ("13100", None), ("19999", None), ("12000/extra", None)):
            row["tags"][0]["tag"] = source + "/socks-172.17.0.1:" + value
            self.assertEqual(MODULE.bridge_port(row), expected)
        row["tags"][0]["tag"] = source + "/socks-127.0.0.1:12000"
        self.assertIsNone(MODULE.bridge_port(row))
        row["region"] = "cn"
        self.assertIsNone(MODULE.bridge_port(row))

    def test_probe_requires_multiple_targets_and_penalizes_partial_success(self):
        ok = subprocess.CompletedProcess([], 0, b"\n200 0.100", b"")
        failed = subprocess.CompletedProcess([], 28, b"\n000 5.000", b"")
        with mock.patch.object(MODULE.subprocess, "run", side_effect=[ok, ok, ok]):
            self.assertEqual(MODULE.probe_bridge(12001, float("inf")), 100)
        with mock.patch.object(MODULE.subprocess, "run", side_effect=[ok, failed, ok]):
            self.assertEqual(MODULE.probe_bridge(12001, float("inf")), 10100)
        with mock.patch.object(MODULE.subprocess, "run", side_effect=[failed, failed, ok]):
            self.assertIsNone(MODULE.probe_bridge(12001, float("inf")))
        with mock.patch.object(MODULE.subprocess, "run") as run:
            self.assertIsNone(MODULE.probe_bridge(12001, 0))
            run.assert_not_called()

    def test_wrong_exit_region_is_rejected_before_other_targets(self):
        trace = subprocess.CompletedProcess([], 0, b"ip=192.0.2.1\nloc=US\n\n200 0.100", b"")
        with mock.patch.object(MODULE.subprocess, "run", return_value=trace) as run:
            self.assertEqual(MODULE.probe_bridge(12001, float("inf"), "de"), "region-mismatch")
            self.assertEqual(run.call_count, 1)

    def test_mismatched_exit_is_excluded_even_in_pool_fallback(self):
        api = FakeAPI()
        with mock.patch.object(MODULE, "bridge_port", return_value=12001), mock.patch.object(
            MODULE, "probe_bridge", return_value="region-mismatch"
        ):
            MODULE.optimize(api, {"ProxyUS": {"region": "us", "id": "us"}}, True)
        filters = api.platforms["us"]["regex_filters"]
        self.assertEqual(filters[0], MODULE.source_filter("us"))
        self.assertEqual(len(filters), 3)
        self.assertTrue(all(pattern.startswith("!^") for pattern in filters[1:]))

    def test_queued_maintenance_prevents_new_probes(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory) / "data"
            priority = Path(directory) / "priority"
            with data.open("a") as lock, priority.open("a") as reader, priority.open("a") as writer:
                fcntl.flock(writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertFalse(MODULE.acquire_probe_lock(lock, reader))
                fcntl.flock(writer, fcntl.LOCK_UN)
                self.assertTrue(MODULE.acquire_probe_lock(lock, reader))
                # Priority is not retained during probes: maintenance can queue.
                fcntl.flock(writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with data.open("a") as contender:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)


if __name__ == "__main__":
    unittest.main()
