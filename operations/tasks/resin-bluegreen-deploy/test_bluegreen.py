import copy
import json
import os
from pathlib import Path
import shlex
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from bluegreen import Deployment, DeploymentError, backup_database


IMAGE = "example.invalid/resin@sha256:" + "a" * 64


class FakeDeployment(Deployment):
    def __init__(self, root):
        with patch.dict(os.environ, {
            "RESIN_SLOT_STATE_ROOT": str(root / "state"),
            "RESIN_SLOT_CACHE_ROOT": str(root / "cache"),
            "RESIN_SLOT_LOG_ROOT": str(root / "log"),
            "RESIN_BLUEGREEN_LOCK_FILE": str(root / "deploy.lock"),
            "UNIFIED_RESIN_LOCK": str(root / "data.lock"),
        }):
            super().__init__()
        self.containers = {}
        self.tcp = {s: [] for s in self.ports}
        self.table = {"PREROUTING": [], "OUTPUT": []}
        self.events = []
        self.fail_probe = False
        self.fail_switch = None
        self.interrupt = False
        self.failed_rollback = False
        self.fail_health = None

    def add(self, slot):
        name = "resin-apps" if slot == "legacy" else f"resin-apps-{slot}"
        info = {"Id": slot + "-id", "State": {"Running": True, "StartedAt": "now"},
                "Config": {"Image": IMAGE, "Labels": {"io.resin.unlimited-drain": "1",
                    "com.docker.compose.project": f"resin-{slot}"}}, "Mounts": []}
        self.containers[name] = info
        self.containers[info["Id"]] = info
        return {"id": info["Id"], "slot": slot, "image": IMAGE}

    def inspect(self, container):
        return self.containers.get(container)

    def prepare_image(self, image):
        self.events.append("pull")

    def validate_probe_config(self):
        return {}

    def require_existing_conntrack(self):
        pass

    def validate_compose(self, slot, image):
        return {}

    def compose(self, slot, image, *args):
        self.events.append("start")
        self.add(slot)

    def snapshot(self, source, slot, service):
        self.events.append("snapshot")

    def live_connections(self, slot):
        return self.tcp[slot]

    def health(self, slot):
        if slot == self.fail_health:
            raise DeploymentError("unhealthy")

    def ready(self, record):
        self.health(record["slot"])

    def check_data(self, slot, entry=False):
        if entry and self.interrupt:
            raise KeyboardInterrupt()
        if entry and self.fail_probe:
            raise DeploymentError("data plane failed")

    def ipt(self, *args, check=True):
        action, chain, *rest = args
        code, output = 0, ""
        if action == "-N":
            self.table[chain] = []
        elif action == "-S":
            if chain not in self.table:
                code = 1
            else:
                output = "\n".join(shlex.join(["-A", chain, *spec]) for spec in self.table[chain])
        elif action == "-C":
            code = int(rest not in self.table.get(chain, []))
        elif action == "-I":
            self.table[chain].insert(0, rest[1:])
        elif action == "-A":
            self.table[chain].append(rest)
        elif action == "-R":
            if self.fail_switch and rest[1:] == self.target_spec(self.fail_switch):
                raise DeploymentError("injected replace failure")
            if self.failed_rollback and rest[1:] == self.target_spec("legacy"):
                raise DeploymentError("injected rollback failure")
            self.table[chain][int(rest[0])-1] = rest[1:]
            self.events.append("replace")
        if code and check:
            raise DeploymentError("iptables failed")
        return subprocess.CompletedProcess(args, code, output, "")


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dep = FakeDeployment(self.root)
        self.legacy = self.dep.add("legacy")
        self.dep.tcp["legacy"] = ["ESTAB old tunnel"]
        self.calls = []

        def run(args, **kwargs):
            self.calls.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        self.mockrun = patch("bluegreen.run", side_effect=run)
        self.mockrun.start()
        self.addCleanup(self.mockrun.stop)

    def test_initial_migration_keeps_legacy_connections(self):
        self.dep.deploy(IMAGE, initial=True)
        self.assertEqual(self.dep.load()["active"]["slot"], "blue")
        self.dep.verify_nat("blue")
        self.assertEqual(self.dep.events[:3], ["pull", "snapshot", "start"])
        self.assertFalse(any("stop" in x or "kill" in x for x in self.calls))
        self.dep.tcp["legacy"] = []
        self.dep.reap(self.dep.load())
        self.assertIn(["docker", "stop", "--timeout", "-1", "legacy-id"], self.calls)

    def test_switch_is_one_replace_and_no_builtin_replacement(self):
        self.dep.ensure_nat("legacy")
        jumps = copy.deepcopy({c: self.dep.table[c] for c in ("PREROUTING", "OUTPUT")})
        self.dep.switch_nat("blue")
        self.dep.ensure_nat("blue")
        self.dep.switch_nat("blue")
        self.assertEqual(self.dep.events.count("replace"), 1)
        self.assertEqual(jumps, {c: self.dep.table[c] for c in jumps})

    def test_post_switch_probe_failure_restores_legacy_and_drains_candidate(self):
        self.dep.fail_probe = True
        with self.assertRaisesRegex(DeploymentError, "data plane"):
            self.dep.deploy(IMAGE, initial=True)
        self.dep.verify_nat("legacy")
        self.assertEqual(self.dep.load()["active"], self.legacy)
        self.assertIn(["docker", "update", "--restart=no", "blue-id"], self.calls)
        self.assertIn(["docker", "kill", "--signal=TERM", "blue-id"], self.calls)
        self.assertFalse(any("legacy-id" in x for x in self.calls))

    def test_signal_rolls_back_with_non_success(self):
        self.dep.interrupt = True
        with self.assertRaises(KeyboardInterrupt):
            self.dep.deploy(IMAGE, initial=True)
        self.dep.verify_nat("legacy")

    def test_failed_rollback_keeps_both_containers(self):
        self.dep.fail_probe = True
        self.dep.failed_rollback = True
        with self.assertRaisesRegex(DeploymentError, "CRITICAL"):
            self.dep.deploy(IMAGE, initial=True)
        self.assertEqual(self.dep.load()["pending"]["slot"], "blue")
        self.assertFalse(self.calls)

    def test_atomic_replace_failure_preserves_old(self):
        self.dep.fail_switch = "blue"
        with self.assertRaisesRegex(DeploymentError, "replace"):
            self.dep.deploy(IMAGE, initial=True)
        self.dep.verify_nat("legacy")

    def test_crash_pending_recovery_before_signal(self):
        candidate = self.dep.add("blue")
        state = {"version": 1, "active": self.legacy, "draining": [], "pending": candidate}
        self.dep.save(state)
        self.dep.ensure_nat("legacy")
        self.dep.switch_nat("blue")
        self.dep.reconcile()
        self.dep.verify_nat("legacy")
        self.assertNotIn("pending", self.dep.load())
        self.assertEqual(self.dep.load()["draining"][0]["slot"], "blue")

    def test_crash_after_compose_before_pending_save_adopts_candidate(self):
        self.dep.add("blue")
        state = {"version": 1, "active": self.legacy, "draining": [],
                 "preparing": {"slot": "blue", "image": IMAGE}}
        self.dep.save(state)
        self.dep.reconcile()
        self.assertNotIn("preparing", self.dep.load())
        self.assertEqual(self.dep.load()["draining"][0]["slot"], "blue")
        self.dep.verify_nat("legacy")

    def test_interrupted_create_does_not_adopt_previous_stopped_generation(self):
        old = self.dep.add("blue")
        self.dep.containers[old["id"]]["State"]["Running"] = False
        state = {"version": 1, "active": self.legacy, "draining": [],
                 "preparing": {"slot": "blue", "image": IMAGE, "prior_id": old["id"]}}
        self.dep.save(state)
        self.dep.reconcile()
        self.assertNotIn("preparing", self.dep.load())
        self.assertEqual(self.dep.load()["draining"], [])

    def test_retire_idempotency_uses_container_start_identity(self):
        old = self.dep.add("blue")
        active = self.dep.add("green")
        state = {"version": 1, "active": active, "draining": [old]}
        self.dep.reap(state)
        self.dep.reap(state)
        self.assertEqual(sum("kill" in x for x in self.calls), 1)
        self.dep.containers[old["id"]]["State"]["StartedAt"] = "restarted"
        self.dep.reap(state)
        self.assertEqual(sum("kill" in x for x in self.calls), 2)

    def test_reuse_rejects_running_or_live_tcp_or_retirement_record(self):
        state = {"draining": []}
        blue = self.dep.add("blue")
        with self.assertRaises(DeploymentError):
            self.dep.reusable("blue", state)
        self.dep.containers[blue["id"]]["State"]["Running"] = False
        self.dep.tcp["blue"] = ["CLOSE-WAIT data"]
        with self.assertRaises(DeploymentError):
            self.dep.reusable("blue", state)
        self.dep.tcp["blue"] = []
        state["draining"] = [blue]
        with self.assertRaises(DeploymentError):
            self.dep.reusable("blue", state)
        state["draining"] = []
        self.dep.reusable("blue", state)

    def test_unexpected_nat_rules_fail_closed(self):
        self.dep.ensure_nat("legacy")
        self.dep.table[self.dep.chain].append(["-j", "RETURN"])
        with self.assertRaises(DeploymentError):
            self.dep.switch_nat("blue")

    def test_uninitialized_restore_noop(self):
        self.dep.reconcile()
        self.assertNotIn(self.dep.chain, self.dep.table)

    def test_unhealthy_active_never_changes_nat(self):
        self.dep.save({"version": 1, "active": self.legacy, "draining": []})
        self.dep.fail_health = "legacy"
        with self.assertRaises(DeploymentError):
            self.dep.reconcile()
        self.assertNotIn(self.dep.chain, self.dep.table)

    def test_legacy_rollback_checks_process_not_dnat_health(self):
        self.dep.containers[self.legacy["id"]]["State"]["Pid"] = 12345
        with patch("bluegreen.run", return_value=subprocess.CompletedProcess([], 0,
                   'LISTEN 0 128 172.17.0.1:10834 0.0.0.0:* users:(("resin",pid=12345,fd=7))', "")):
            Deployment.ready(self.dep, self.legacy)
        with patch("bluegreen.run", return_value=subprocess.CompletedProcess([], 0, "", "")):
            with self.assertRaises(DeploymentError):
                Deployment.ready(self.dep, self.legacy)

    def test_locks_released_without_drain_process(self):
        with self.dep.locked(maintenance=True):
            with self.assertRaises(DeploymentError):
                with self.dep.locked():
                    pass
        with self.dep.locked():
            pass


class SnapshotTests(unittest.TestCase):
    def test_slot_snapshot_replaces_stale_wal_and_archives_logs(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            dep = FakeDeployment(root)
            source = dep.add("legacy")
            mounts = []
            writers = []
            try:
                for kind, destination, dbname in (("state", "/var/lib/resin", "state.db"),
                                                   ("cache", "/var/cache/resin", "cache.db")):
                    directory = root / "source" / kind
                    directory.mkdir(parents=True)
                    db = sqlite3.connect(directory / dbname)
                    writers.append(db)
                    db.execute("PRAGMA journal_mode=WAL")
                    db.execute("CREATE TABLE endpoints (enabled INTEGER)")
                    db.execute("CREATE TABLE sample (value TEXT)")
                    db.execute("INSERT INTO sample VALUES ('source')")
                    db.commit()
                    mounts.append({"Type": "bind", "Destination": destination, "Source": str(directory)})
                dep.containers[source["id"]]["Mounts"] = mounts
                for kind, path in dep.roots.items():
                    (path / "blue").mkdir(parents=True)
                    (path / "blue" / "old.db-wal").write_text("stale")
                (dep.roots["log"] / "blue" / "request_logs-old.db").write_text("keep audit")
                Deployment.snapshot(dep, source, "blue", {"environment": {
                    "RESIN_RUNTIME_UID": os.getuid(), "RESIN_RUNTIME_GID": os.getgid()}})
                for kind, dbname in (("state", "state.db"), ("cache", "cache.db")):
                    self.assertEqual((dep.roots[kind] / "blue").stat().st_mode & 0o777, 0o750)
                    self.assertEqual((dep.roots[kind] / "blue" / dbname).stat().st_mode & 0o777, 0o640)
                    with sqlite3.connect(dep.roots[kind] / "blue" / dbname) as db:
                        self.assertEqual(db.execute("SELECT value FROM sample").fetchall(), [("source",)])
                    self.assertFalse((dep.roots[kind] / "blue" / "old.db-wal").exists())
                self.assertEqual(list((dep.roots["log"] / "blue").iterdir()), [])
                archives = list((dep.roots["log"] / "archive").glob("*/request_logs-old.db"))
                self.assertEqual(archives[0].read_text(), "keep audit")
            finally:
                for writer in writers:
                    writer.close()

    def test_online_wal_backup_is_consistent_and_missing_source_fails(self):
        with tempfile.TemporaryDirectory() as root:
            source, target = Path(root) / "live.db", Path(root) / "snapshot.db"
            with sqlite3.connect(source) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("CREATE TABLE entries (value TEXT)")
                db.execute("INSERT INTO entries VALUES ('committed')")
                db.commit()
                db.execute("INSERT INTO entries VALUES ('uncommitted')")
                backup_database(source, target)
                with sqlite3.connect(target) as snapshot:
                    self.assertEqual(snapshot.execute("SELECT value FROM entries").fetchall(), [("committed",)])
            with self.assertRaises(DeploymentError):
                backup_database(Path(root) / "missing.db", Path(root) / "bad.db")


if __name__ == "__main__":
    unittest.main()
