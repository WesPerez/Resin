#!/usr/bin/env python3
"""Deploy Resin behind one conntrack DNAT target without killing old tunnels."""

import argparse
import contextlib
import fcntl
import http.client
import ipaddress
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time


class DeploymentError(RuntimeError):
    pass


def run(args, *, env=None, check=True, timeout=120):
    args = list(map(str, args))
    result = subprocess.run(args, text=True, capture_output=True, env=env, timeout=timeout, check=False)
    if check and result.returncode:
        # CLI stderr can contain credentials or upstream responses.
        raise DeploymentError(f"{Path(args[0]).name} {args[1]} failed (exit {result.returncode})")
    return result


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def backup_database(source, target):
    if not source.is_file():
        raise DeploymentError(f"required source database missing: {source}")
    with contextlib.closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as src:
        with contextlib.closing(sqlite3.connect(target)) as dst:
            deadline = time.monotonic() + 30

            def progress(_status, _remaining, _total):
                if time.monotonic() > deadline:
                    raise DeploymentError(f"snapshot timed out: {source.name}")

            src.backup(dst, pages=256, progress=progress)
            if dst.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise DeploymentError(f"invalid snapshot: {source.name}")


class Deployment:
    def __init__(self):
        get = os.environ.get
        self.address = str(ipaddress.IPv4Address(get("RESIN_ENTRY_ADDRESS", "172.17.0.1")))
        self.ports = {name: int(get(key, default)) for name, key, default in (
            ("legacy", "RESIN_ENTRY_PORT", "10834"),
            ("blue", "RESIN_BLUE_PORT", "10835"),
            ("green", "RESIN_GREEN_PORT", "10836"),
        )}
        if len(set(self.ports.values())) != 3 or any(not 0 < p < 65536 for p in self.ports.values()):
            raise DeploymentError("entry and slot ports must be distinct TCP ports")
        self.chain = get("RESIN_NAT_CHAIN", "RESIN_BLUEGREEN")
        if not self.chain.replace("_", "").isalnum() or len(self.chain) > 28:
            raise DeploymentError("invalid dedicated NAT chain")
        self.roots = {kind: Path(get(key, default)).resolve() for kind, key, default in (
            ("state", "RESIN_SLOT_STATE_ROOT", "/var/lib/resin-slots"),
            ("cache", "RESIN_SLOT_CACHE_ROOT", "/var/cache/resin-slots"),
            ("log", "RESIN_SLOT_LOG_ROOT", "/var/log/resin-slots"),
        )}
        roots = list(self.roots.values())
        if any(a == b or a in b.parents or b in a.parents for i, a in enumerate(roots) for b in roots[i+1:]):
            raise DeploymentError("slot state, cache and log roots must be separate")
        self.record = self.roots["state"] / "deployment.json"
        self.lock = Path(get("RESIN_BLUEGREEN_LOCK_FILE", "/run/lock/resin-bluegreen-deploy.lock"))
        self.data_lock = Path(get("UNIFIED_RESIN_LOCK", "/run/lock/resin-pool-maintenance-data-plane.lock"))
        self.compose_file = get("RESIN_COMPOSE_FILE", "/etc/resin-apps/slot-compose.yml")
        self.env_file = get("RESIN_ENV_FILE", "/etc/resin-apps/compose.env")
        self.docker = get("DOCKER_BIN", "docker")
        self.iptables = get("IPTABLES_BIN", "iptables")
        self.ss = get("SS_BIN", "ss")
        self.nsenter = get("NSENTER_BIN", "nsenter")
        self.config = Path(get("RESIN_BLUEGREEN_CONFIG", "/etc/resin-apps/bluegreen.json"))
        self.attempts = int(get("RESIN_HEALTH_ATTEMPTS", "30"))

    @contextlib.contextmanager
    def locked(self, maintenance=False):
        with contextlib.ExitStack() as stack:
            for path in [self.lock] + ([self.data_lock] if maintenance else []):
                path.parent.mkdir(parents=True, exist_ok=True)
                stream = stack.enter_context(path.open("a"))
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise DeploymentError(f"maintenance lock is busy: {path.name}") from exc
            yield

    def load(self):
        if not self.record.exists():
            return None
        state = json.loads(self.record.read_text())
        if state.get("version") != 1 or state["active"]["slot"] not in self.ports:
            raise DeploymentError("invalid deployment record")
        return state

    def save(self, state):
        atomic_json(self.record, state)

    def inspect(self, container):
        result = run([self.docker, "inspect", container], check=False)
        if result.returncode:
            run([self.docker, "info", "--format", "{{.ServerVersion}}"])
            return None
        return json.loads(result.stdout)[0]

    def slot_env(self, slot, image):
        env = os.environ.copy()
        env.update({
            "RESIN_COMPOSE_PROJECT": f"resin-{slot}", "RESIN_CONTAINER_NAME": f"resin-apps-{slot}",
            "RESIN_IMAGE": image, "RESIN_WATCHTOWER_ENABLED": "false",
            "RESIN_LISTEN_ADDRESS": self.address, "RESIN_PORT": str(self.ports[slot]),
            "RESIN_SHUTDOWN_PRESERVE_CONNECTIONS": "1", "RESIN_DRAIN_TIMEOUT": "0",
            "RESIN_STOP_GRACE_PERIOD": "11m",
        })
        for kind, root in self.roots.items():
            env[f"RESIN_{kind.upper()}_HOST_DIR"] = str(root / slot)
        return env

    def compose(self, slot, image, *args):
        return run([self.docker, "compose", "--env-file", self.env_file, "-f", self.compose_file, *args],
                   env=self.slot_env(slot, image), timeout=180)

    def validate_compose(self, slot, image):
        cfg = json.loads(self.compose(slot, image, "config", "--format", "json").stdout)
        svc = cfg["services"]["resin"]
        expected = self.slot_env(slot, image)
        env = svc.get("environment", {})
        correct = cfg["name"] == expected["RESIN_COMPOSE_PROJECT"]
        correct &= svc.get("container_name") == expected["RESIN_CONTAINER_NAME"]
        correct &= svc.get("network_mode") == "host" and svc.get("image") == image
        correct &= str(svc.get("labels", {}).get("com.centurylinklabs.watchtower.enable")) == "false"
        for key in ("RESIN_PORT", "RESIN_LISTEN_ADDRESS", "RESIN_SHUTDOWN_PRESERVE_CONNECTIONS", "RESIN_DRAIN_TIMEOUT"):
            correct &= str(env.get(key)) == expected[key]
        mounts = {v["target"]: v["source"] for v in svc.get("volumes", []) if v["type"] == "bind"}
        for kind, target in (("state", "/var/lib/resin"), ("cache", "/var/cache/resin"), ("log", "/var/log/resin")):
            correct &= mounts.get(target) == str(self.roots[kind] / slot)
        if not correct:
            raise DeploymentError("Compose lacks isolated slot/drain settings; refusing to start or recreate any container")
        return svc

    def prepare_image(self, image):
        digest = image.rsplit("@sha256:", 1)
        if len(digest) != 2 or len(digest[1]) != 64 or any(c not in "0123456789abcdef" for c in digest[1]):
            raise DeploymentError("an immutable registry image@sha256:digest is required")
        run([self.docker, "pull", image], timeout=600)
        info = json.loads(run([self.docker, "image", "inspect", image]).stdout)[0]
        if info["Config"].get("Labels", {}).get("io.resin.unlimited-drain") != "1":
            raise DeploymentError("candidate image does not advertise unlimited drain support")

    def validate_probe_config(self):
        cfg = json.loads(self.config.read_text())
        if not cfg.get("clients") or not cfg.get("probe_target") or not cfg.get("proxy_token_file"):
            raise DeploymentError("bluegreen.json requires clients, probe_target and proxy_token_file")
        if not Path(cfg["proxy_token_file"]).is_file():
            raise DeploymentError("probe token file is missing")
        for client in cfg["clients"]:
            info = self.inspect(client)
            if not info or not info["State"]["Running"]:
                raise DeploymentError(f"probe client unavailable: {client}")
        return cfg

    def require_existing_conntrack(self):
        rules = [shlex.split(line) for line in self.ipt("-S").stdout.splitlines()]
        targets = {line[line.index("-j") + 1] for line in rules if "-j" in line}
        if not targets.intersection({"DNAT", "SNAT", "MASQUERADE", "REDIRECT"}):
            raise DeploymentError("first migration needs existing NAT/conntrack hooks before legacy sessions begin")

    def live_connections(self, slot):
        result = run([self.ss, "-H", "-tan", "state", "all", f"sport = :{self.ports[slot]}"])
        return [line for line in result.stdout.splitlines() if line.split()[0] != "LISTEN"]

    def reusable(self, slot, state):
        info = self.inspect(f"resin-apps-{slot}")
        if (info and info["State"]["Running"]) or self.live_connections(slot):
            raise DeploymentError(f"inactive slot {slot} is still running or draining")
        if any(x["slot"] == slot for x in state.get("draining", [])):
            raise DeploymentError(f"slot {slot} still has a retirement record; run reconcile first")
        if info and info["Config"].get("Labels", {}).get("com.docker.compose.project") != f"resin-{slot}":
            raise DeploymentError(f"unmanaged container occupies slot {slot}")

    def snapshot(self, source, target_slot, service):
        info = self.inspect(source["id"])
        if not info or not info["State"]["Running"]:
            raise DeploymentError("snapshot source is not running")
        mounts = {v["Destination"]: Path(v["Source"]) for v in info["Mounts"] if v["Type"] == "bind"}
        state_source, cache_source = mounts["/var/lib/resin"], mounts["/var/cache/resin"]
        prepared = {}
        try:
            for kind, root in self.roots.items():
                root.mkdir(parents=True, exist_ok=True, mode=0o700)
                prepared[kind] = Path(tempfile.mkdtemp(prefix=f".{target_slot}-", dir=root))
            backup_database(state_source / "state.db", prepared["state"] / "state.db")
            backup_database(cache_source / "cache.db", prepared["cache"] / "cache.db")
            with sqlite3.connect(prepared["state"] / "state.db") as db:
                if db.execute("SELECT 1 FROM endpoints WHERE enabled = 1 LIMIT 1").fetchone():
                    raise DeploymentError("custom endpoint listeners require explicit port mapping before two-slot deployment")
            mmdb = cache_source / "country.mmdb"
            if mmdb.is_file():
                shutil.copyfile(mmdb, prepared["cache"] / "country.mmdb")
            uid = int(service["environment"].get("RESIN_RUNTIME_UID", 993))
            gid = int(service["environment"].get("RESIN_RUNTIME_GID", 984))
            generation = str(time.time_ns())
            for kind, temporary in prepared.items():
                for item in [temporary, *temporary.iterdir()]:
                    os.chown(item, uid, gid)
                    os.chmod(item, 0o750 if item.is_dir() else 0o640)
                target = self.roots[kind] / target_slot
                if target.exists():
                    archive = self.roots[kind] / "archive"
                    archive.mkdir(exist_ok=True, mode=0o700)
                    os.rename(target, archive / f"{target_slot}-{generation}")
                os.rename(temporary, target)
            # Metrics and request logs start empty; prior generations stay archived.
        finally:
            for temporary in prepared.values():
                if temporary.exists():
                    shutil.rmtree(temporary)

    def ipt(self, *args, check=True):
        return run([self.iptables, "-w", "5", "-t", "nat", *args], check=check)

    def rules(self):
        return [shlex.split(line) for line in self.ipt("-S", self.chain).stdout.splitlines()
                if line.startswith("-A ")]

    def target_spec(self, slot):
        base = ["-p", "tcp", "-m", "comment", "--comment", "resin-bluegreen-target"]
        if slot == "legacy":
            return base + ["-j", "RETURN"]
        return base + ["-j", "DNAT", "--to-destination", f"{self.address}:{self.ports[slot]}"]

    def jump_spec(self):
        return ["-d", f"{self.address}/32", "-p", "tcp", "--dport", str(self.ports["legacy"]),
                "-m", "comment", "--comment", "resin-bluegreen-entry", "-j", self.chain]

    def valid_rules(self):
        rules = self.rules()
        if len(rules) != 1 or rules[0][2:] not in [self.target_spec(s) for s in self.ports]:
            raise DeploymentError("dedicated NAT chain has unexpected rules; refusing to overwrite")
        return rules

    def ensure_nat(self, slot):
        if self.ipt("-S", self.chain, check=False).returncode:
            self.ipt("-N", self.chain)
        if not self.rules():
            self.ipt("-A", self.chain, *self.target_spec(slot))
        self.valid_rules()
        # Complete target first, then both stable entry jumps.
        for chain in ("PREROUTING", "OUTPUT"):
            lines = [shlex.split(line) for line in self.ipt("-S", chain).stdout.splitlines()]
            jumps = [line for line in lines if "-j" in line and line[line.index("-j")+1] == self.chain]
            if jumps:
                if len(jumps) != 1 or self.ipt("-C", chain, *self.jump_spec(), check=False).returncode:
                    raise DeploymentError(f"unexpected entry jumps in {chain}")
            else:
                self.ipt("-I", chain, "1", *self.jump_spec())

    def switch_nat(self, slot):
        self.valid_rules()
        if self.rules()[0][2:] != self.target_spec(slot):
            self.ipt("-R", self.chain, "1", *self.target_spec(slot))
        self.verify_nat(slot)

    def verify_nat(self, slot):
        if self.valid_rules()[0][2:] != self.target_spec(slot):
            raise DeploymentError(f"NAT target does not match {slot}")
        for chain in ("PREROUTING", "OUTPUT"):
            self.ipt("-C", chain, *self.jump_spec())

    def health(self, slot):
        for _ in range(self.attempts):
            conn = http.client.HTTPConnection(self.address, self.ports[slot], timeout=2)
            try:
                conn.request("GET", "/healthz", headers={"Connection": "close"})
                if conn.getresponse().status == 200:
                    return
            except (OSError, http.client.HTTPException):
                pass
            finally:
                conn.close()
            time.sleep(1)
        raise DeploymentError(f"health check failed for {slot}")

    def ready(self, record):
        info = self.inspect(record["id"])
        if not info or not info["State"]["Running"]:
            raise DeploymentError("previous active container is no longer running")
        if record["slot"] == "legacy":
            # Once NAT is installed, GET entry:10834 probes the candidate. Check
            # the legacy process/listener directly so rollback can recover a dead candidate.
            listeners = run([self.ss, "-H", "-ltnp", f"sport = :{self.ports['legacy']}"]).stdout
            if f"pid={info['State']['Pid']}," not in listeners:
                raise DeploymentError("legacy process no longer owns the entry listener")
        else:
            self.health(record["slot"])

    def check_data(self, slot, entry=False):
        cfg = self.validate_probe_config()
        script = Path(__file__).with_name("probe.py")
        port = self.ports["legacy"] if entry else self.ports[slot]
        command = [sys.executable, script, self.config, self.address, str(port)]
        run(command, timeout=30)
        for client in cfg["clients"]:
            info = self.inspect(client)
            if not info or not info["State"]["Running"]:
                raise DeploymentError(f"probe client unavailable: {client}")
            run([self.nsenter, "-t", str(info["State"]["Pid"]), "-n", *command], timeout=30)

    def container_record(self, slot):
        name = "resin-apps" if slot == "legacy" else f"resin-apps-{slot}"
        info = self.inspect(name)
        if not info or not info["State"]["Running"]:
            raise DeploymentError(f"container not running: {name}")
        record = {"slot": slot, "id": info["Id"], "image": info["Config"]["Image"]}
        if slot != "legacy":
            record["cache_db"] = str(self.roots["cache"] / slot / "cache.db")
        return record

    def retire(self, state, record):
        if not any(x["id"] == record["id"] for x in state["draining"]):
            state["draining"].append(record.copy())
            self.save(state)
        self.reap(state)

    def reap(self, state):
        for record in list(state["draining"]):
            if record["id"] == state["active"]["id"]:
                raise DeploymentError("active container cannot be retired")
            info = self.inspect(record["id"])
            if not info:
                if self.live_connections(record["slot"]):
                    raise DeploymentError("unowned connections occupy retired slot")
                state["draining"].remove(record)
                self.save(state)
                continue
            if info["State"]["Running"]:
                if record["slot"] == "legacy":
                    if self.live_connections("legacy"):
                        continue
                    run([self.docker, "stop", "--timeout", "-1", record["id"]], timeout=30)
                else:
                    if info["Config"].get("Labels", {}).get("io.resin.unlimited-drain") != "1":
                        raise DeploymentError("cannot signal a slot without unlimited drain support")
                    run([self.docker, "update", "--restart=no", record["id"]])
                    if record.get("signalled_started_at") != info["State"]["StartedAt"]:
                        run([self.docker, "kill", "--signal=TERM", record["id"]])
                        record["signalled_started_at"] = info["State"]["StartedAt"]
                        self.save(state)
                    continue
            if self.live_connections(record["slot"]):
                continue
            state["draining"].remove(record)
            self.save(state)

    def recover_pending(self, state):
        self.adopt_preparing(state)
        pending = state.get("pending")
        if pending:
            self.ensure_nat(state["active"]["slot"])
            self.switch_nat(state["active"]["slot"])
            if not any(x["id"] == pending["id"] for x in state["draining"]):
                state["draining"].append(pending)
            state.pop("pending")
            self.save(state)

    def adopt_preparing(self, state):
        preparing = state.get("preparing")
        if not preparing:
            return
        slot = preparing["slot"]
        info = self.inspect(f"resin-apps-{slot}")
        if info and info["Id"] != preparing.get("prior_id"):
            if (info["Config"]["Image"] != preparing["image"] or
                    info["Config"].get("Labels", {}).get("com.docker.compose.project") != f"resin-{slot}"):
                raise DeploymentError("preparing slot container does not match the recorded deployment")
            state["pending"] = {"slot": slot, "image": preparing["image"], "id": info["Id"]}
        state.pop("preparing")
        self.save(state)

    def deploy(self, image, initial=False):
        state = self.load()
        if initial:
            if state:
                raise DeploymentError("already initialized; use reconcile or deploy")
            old = self.container_record("legacy")
            legacy = self.inspect(old["id"])
            if legacy["Config"].get("Labels", {}).get("com.centurylinklabs.watchtower.enable") == "true":
                raise DeploymentError("legacy Watchtower auto-update must be disabled first")
            self.require_existing_conntrack()
            state = {"version": 1, "active": old, "draining": []}
        elif not state:
            raise DeploymentError("not initialized; use init")
        old = state["active"]
        self.ready(old)
        if state.get("pending") or state.get("preparing"):
            raise DeploymentError("pending transaction exists; run reconcile")
        new_slot = "green" if old["slot"] == "blue" else "blue"
        self.reusable(new_slot, state)
        service = self.validate_compose(new_slot, image)
        self.validate_probe_config()
        self.prepare_image(image)
        self.snapshot(old, new_slot, service)
        candidate = None
        committed = False
        try:
            prior = self.inspect(f"resin-apps-{new_slot}")
            state["preparing"] = {"slot": new_slot, "image": image,
                                  "prior_id": prior["Id"] if prior else None}
            self.save(state)
            self.compose(new_slot, image, "up", "-d", "--no-deps", "--force-recreate", "--pull", "never", "resin")
            candidate = self.container_record(new_slot)
            state.pop("preparing")
            state["pending"] = candidate
            self.save(state)
            self.health(new_slot)
            self.check_data(new_slot)
            self.ensure_nat(old["slot"])
            self.verify_nat(old["slot"])
            self.switch_nat(new_slot)
            self.check_data(new_slot, entry=True)
            state["active"] = candidate
            state.pop("pending")
            state["draining"].append(old)
            self.save(state)
            committed = True
        except BaseException:
            if candidate is None and state.get("preparing"):
                self.adopt_preparing(state)
                candidate = state.get("pending")
            if candidate and not committed:
                try:
                    self.ready(old)
                    self.ensure_nat(old["slot"])
                    self.switch_nat(old["slot"])
                    state["active"] = old
                    state["draining"] = [x for x in state["draining"] if x["id"] != old["id"]]
                    state.pop("pending", None)
                    self.retire(state, candidate)
                except BaseException as rollback_error:
                    raise DeploymentError("CRITICAL: rollback incomplete; both containers retained; inspect status before recovery") from rollback_error
            raise
        self.reap(state)
        print(f"active={new_slot}; old={old['slot']} draining; entry={self.address}:{self.ports['legacy']}")

    def reconcile(self, start=False):
        state = self.load()
        if not state:
            print("uninitialized; NAT unchanged")
            return
        info = self.inspect(state["active"]["id"])
        if not info:
            raise DeploymentError("active container missing; refusing to route to an unverified replacement")
        if not info["State"]["Running"]:
            if not start:
                raise DeploymentError("active container stopped; use start to restore its exact container")
            run([self.docker, "start", state["active"]["id"]])
        self.ready(state["active"])
        self.recover_pending(state)
        self.ensure_nat(state["active"]["slot"])
        self.switch_nat(state["active"]["slot"])
        self.reap(state)

    def status(self):
        print(json.dumps(self.load() or {"active": "uninitialized"}, indent=2))
        for slot in self.ports:
            print(f"{slot}_live_tcp={len(self.live_connections(slot))}")
        result = self.ipt("-S", self.chain, check=False)
        print(result.stdout.strip() or "NAT chain absent")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("init", "deploy", "status", "restore", "reconcile", "start"))
    parser.add_argument("image", nargs="?")
    args = parser.parse_args()
    if (args.action in ("init", "deploy")) != bool(args.image):
        parser.error("init/deploy require an immutable image digest; other actions take no image")

    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f"interrupted by signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    try:
        deployment = Deployment()
        if args.action == "status":
            deployment.status()
            return
        with deployment.locked(maintenance=args.action in ("init", "deploy")):
            if args.action in ("init", "deploy"):
                deployment.deploy(args.image, initial=args.action == "init")
            else:
                deployment.reconcile(start=args.action == "start")
    except KeyboardInterrupt:
        print("resin-bluegreen: interrupted; run status/reconcile", file=sys.stderr)
        sys.exit(130)
    except (DeploymentError, OSError, ValueError, KeyError, sqlite3.Error, subprocess.TimeoutExpired) as exc:
        print(f"resin-bluegreen: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
