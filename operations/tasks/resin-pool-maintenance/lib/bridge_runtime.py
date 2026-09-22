#!/usr/bin/env python3
"""Keep bridge TCP sessions alive while atomically switching new connections."""

import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time

from singbox_bridge_pool import process_identity, process_tcp_listeners

OWNER = "resin-bridge-runtime"
MAX_GENERATIONS = 4
IDLE_GRACE = 10


def configured_listeners(config):
    inbounds = config.get("inbounds", [])
    if not 1 <= len(inbounds) <= 1001:
        raise ValueError("invalid bridge listener count")
    result = set()
    for inbound in inbounds:
        host = ipaddress.ip_address(inbound["listen"])
        port = inbound["listen_port"]
        if (inbound.get("type") != "socks" or host.version != 4
                or not (host.is_private or host.is_loopback) or host.is_unspecified
                or type(port) is not int or not 1024 <= port <= 65535
                or (str(host), port) in result):
            raise ValueError("invalid runtime listener")
        result.add((str(host), port))
    return result


def atomic_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def connection_count(pid, listen_address=None, listen_ports=None):
    """Count accepted sessions, including closing; upstream idle pools are not users."""
    process = Path("/proc") / str(pid)
    try:
        inodes = set()
        for path in (process / "fd").iterdir():
            try:
                target = os.readlink(path)
            except FileNotFoundError:
                continue
            if target.startswith("socket:["):
                inodes.add(target[8:-1])
        count = 0
        wanted_address = socket.inet_aton(listen_address)[::-1].hex().upper() if listen_address else None
        for table in ("tcp", "tcp6"):
            for line in (process / "net" / table).read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) >= 10 and fields[9] in inodes and fields[3] not in ("06", "07", "0A"):
                    address, port = fields[1].split(":")
                    if wanted_address is not None and (address != wanted_address or int(port, 16) not in listen_ports):
                        continue
                    count += 1
        return count
    except OSError:
        return None


def port_ranges(ports):
    ranges = []
    for port in sorted(ports):
        if ranges and port == ranges[-1][1] + 1:
            ranges[-1][1] = port
        else:
            ranges.append([port, port])
    return [str(first) if first == last else f"{first}-{last}" for first, last in ranges]


def request(path, message, timeout=90):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(timeout)
        client.connect(str(path))
        client.sendall(json.dumps(message).encode() + b"\n")
        data = bytearray()
        while b"\n" not in data:
            block = client.recv(65536)
            if not block:
                raise RuntimeError("runtime response incomplete")
            data.extend(block)
            if len(data) > 1024 * 1024:
                raise RuntimeError("runtime response too large")
        result = json.loads(data.split(b"\n", 1)[0])
        if result.get("status") == "error":
            raise RuntimeError(result.get("error", "runtime request failed"))
        return result


class Runtime:
    def __init__(self, root, runtime_dir, binary, haproxy, idle_grace=IDLE_GRACE):
        self.root = root.resolve()
        self.runtime_dir = runtime_dir
        self.binary = binary
        self.haproxy = haproxy
        self.idle_grace = idle_grace
        self.instances = {}
        self.active = None
        self.frontend = None
        self.listeners = None
        self.stopping = False
        self.switches = 0
        self.last_error = None
        self.runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.admin = self.runtime_dir / "haproxy.sock"
        self.control = self.runtime_dir / "control.sock"
        self.frontend_config = self.runtime_dir / "haproxy.cfg"

    def generation_config(self, directory):
        directory = directory.resolve(strict=True)
        if directory.parent != self.root / "generations" or not re.fullmatch(r"[A-Za-z0-9-]+", directory.name):
            raise ValueError("invalid current generation")
        content = (directory / "bridge.json").read_bytes()
        manifest = json.loads((directory / "manifest.json").read_text())
        if manifest.get("owner") != "resin-pool-maintenance" or manifest.get("config_sha256") != hashlib.sha256(content).hexdigest():
            raise ValueError("generation integrity check failed")
        config = json.loads(content)
        return config

    def current(self):
        directory = (self.root / "current").resolve(strict=True)
        config = self.generation_config(directory)
        listeners = configured_listeners(config)
        hosts = {host for host, _ in listeners}
        if len(hosts) != 1 or not listeners or any(port < 1024 for _, port in listeners):
            raise ValueError("bridge requires one nonprivileged TCP listen address")
        host = ipaddress.ip_address(next(iter(hosts)))
        if host.version != 4 or not (host.is_private or host.is_loopback):
            raise ValueError("bridge frontend must use a private IPv4 address")
        if self.listeners is not None and listeners != self.listeners:
            raise ValueError("changing frontend listeners requires an explicit migration")
        self.listeners = listeners
        return directory.name, config

    def launch(self, generation, config, preferred_address=None):
        previous = self.instances.get(generation)
        used = {row["address"] for name, row in self.instances.items() if name != generation}
        address = preferred_address or next((f"127.76.0.{number}" for number in range(2, MAX_GENERATIONS + 2)
                        if f"127.76.0.{number}" not in used), None)
        if address is None or address in used:
            raise RuntimeError("generation_capacity_reached: live TCP sessions defer this update")
        runtime_config = copy.deepcopy(config)
        for inbound in runtime_config["inbounds"]:
            inbound["listen"] = address
        path = self.root / "generations" / generation / "bridge-runtime.json"
        atomic_json(path, runtime_config)
        log_path = self.root / "generations" / generation / "runtime.log"
        env = {key: value for key, value in os.environ.items() if key != "NOTIFY_SOCKET"}
        with log_path.open("ab") as log:
            os.fchmod(log.fileno(), 0o600)
            subprocess.run([self.binary, "check", "-c", str(path)], check=True,
                           stdout=log, stderr=log, timeout=30, env=env)
            process = subprocess.Popen([self.binary, "run", "-c", str(path)],
                                       stdout=log, stderr=log, env=env)
        row = {"process": process, "address": address, "started_at": time.time(),
               "draining_since": None, "idle_since": None, "connections": None,
               "config_sha256": hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()}
        self.instances[generation] = row
        self.save()
        expected = configured_listeners(runtime_config)
        deadline = time.monotonic() + 60
        try:
            identity = process_identity(Path("/proc") / str(process.pid))
            while True:
                if process.poll() is not None:
                    raise RuntimeError("backend exited before readiness")
                proc = Path("/proc") / str(process.pid)
                if process_identity(proc) != identity:
                    raise RuntimeError("backend process identity changed")
                if expected <= process_tcp_listeners(proc):
                    return row
                if time.monotonic() >= deadline:
                    raise RuntimeError("backend listeners did not become ready")
                time.sleep(0.1)
        except BaseException:
            self.stop_process(process)
            self.instances.pop(generation)
            if previous is not None:
                self.instances[generation] = previous
            self.save()
            raise

    def write_frontend_config(self, address):
        host = next(iter(self.listeners))[0]
        binds = ",".join(f"{host}:{ports}" for ports in port_ranges(port for _, port in self.listeners))
        self.frontend_config.write_text(
            "global\n  maxconn 20000\n  nbthread 2\n"
            f"  stats socket {self.admin} mode 600 level admin\n"
            "defaults\n  mode tcp\n  timeout connect 8s\n"
            "  timeout client 24h\n  timeout server 24h\n"
            f"frontend ingress\n  bind {binds}\n  default_backend bridge\n"
            # A server without a port inherits the connection's destination port.
            f"backend bridge\n  server current {address}\n")
        self.frontend_config.chmod(0o600)

    def admin_command(self, command):
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(5)
            client.connect(str(self.admin))
            client.sendall(command.encode() + b"\n")
            client.shutdown(socket.SHUT_WR)
            data = bytearray()
            while True:
                block = client.recv(65536)
                if not block:
                    break
                data.extend(block)
                if len(data) > 1024 * 1024:
                    raise RuntimeError("frontend response too large")
            return data.decode()

    def frontend_address(self):
        lines = self.admin_command("show servers state bridge").splitlines()
        header = next((line.lstrip("# ").split() for line in lines if line.startswith("#")), None)
        if header is None:
            raise RuntimeError("invalid frontend server state response")
        for line in lines:
            if line.startswith("#"):
                continue
            row = dict(zip(header, line.split()))
            if row.get("be_name") == "bridge" and row.get("srv_name") == "current":
                return row["srv_addr"]
        raise RuntimeError("frontend backend state is unavailable")

    def launch_frontend(self):
        self.write_frontend_config(self.instances[self.active]["address"])
        self.admin.unlink(missing_ok=True)
        with (self.runtime_dir / "haproxy.log").open("ab") as log:
            os.fchmod(log.fileno(), 0o600)
            subprocess.run([self.haproxy, "-c", "-f", str(self.frontend_config)],
                           check=True, stdout=log, stderr=log, timeout=15)
            self.frontend = subprocess.Popen([self.haproxy, "-db", "-f", str(self.frontend_config)],
                                             stdout=log, stderr=log)
        deadline = time.monotonic() + 30
        while True:
            if self.frontend.poll() is not None:
                raise RuntimeError("frontend exited before readiness")
            try:
                if (self.listeners <= process_tcp_listeners(Path("/proc") / str(self.frontend.pid))
                        and self.frontend_address() == self.instances[self.active]["address"]):
                    return
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("frontend readiness timed out")
            time.sleep(0.1)

    def switch(self):
        generation, config = self.current()
        if generation == self.active:
            digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
            if self.instances[generation]["config_sha256"] != digest or self.instances[generation]["process"].poll() is not None:
                raise RuntimeError("active generation is unavailable or changed")
            if self.frontend_address() != self.instances[generation]["address"]:
                raise RuntimeError("frontend and active generation disagree")
            return {"status": "unchanged", "generation": generation}
        self.sweep()
        if generation in self.instances:
            row = self.instances[generation]
            digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
            if row["process"].poll() is not None or row["config_sha256"] != digest:
                raise RuntimeError("rollback backend is unavailable or changed")
        else:
            row = self.launch(generation, config)
        try:
            self.admin_command(f"set server bridge/current addr {row['address']}")
            if self.frontend_address() != row["address"]:
                raise RuntimeError("frontend did not switch to prepared backend")
        except BaseException:
            # Do not kill a backend after an uncertain switch: it may own live sessions.
            row["draining_since"] = time.time()
            self.save()
            raise
        previous = self.active
        if previous in self.instances:
            self.instances[previous]["draining_since"] = time.time()
        self.active = generation
        row["draining_since"] = row["idle_since"] = None
        self.switches += 1
        self.last_error = None
        self.write_frontend_config(row["address"])
        self.save()
        return {"status": "switched", "generation": generation, "previous": previous,
                "draining": len(self.instances) - 1}

    def snapshot(self):
        return {"version": 1, "owner": OWNER, "updated_at": time.time(),
                "active_generation": self.active, "frontend_pid": self.frontend.pid if self.frontend else None,
                "switches": self.switches, "last_error": self.last_error,
                "capacity": MAX_GENERATIONS,
                "instances": {generation: {key: value for key, value in row.items()
                                             if key not in ("process", "idle_since")}
                              | {"pid": row["process"].pid}
                              for generation, row in self.instances.items()}}

    def save(self):
        atomic_json(self.root / "runtime.json", self.snapshot())

    def sweep(self):
        if self.frontend is None:
            return
        active = self.instances[self.active]
        if active["process"].poll() is not None:
            # A failed backend has already lost its sessions; other generations remain alive.
            config = self.generation_config(self.root / "generations" / self.active)
            digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
            if digest != active["config_sha256"]:
                raise RuntimeError("active backend configuration changed; recovery refused")
            self.launch(self.active, config, preferred_address=active["address"])
        if self.frontend.poll() is not None:
            self.launch_frontend()
        address = self.frontend_address()
        for generation, row in list(self.instances.items()):
            if row["process"].poll() is not None:
                if generation == self.active or row["address"] == address:
                    raise RuntimeError("active backend exited")
                del self.instances[generation]
                continue
            count = connection_count(row["process"].pid, row["address"], {port for _, port in self.listeners})
            row["connections"] = count
            if generation == self.active or row["address"] == address:
                continue
            if count is None or count > 0:
                row["idle_since"] = None
            elif row["idle_since"] is None:
                row["idle_since"] = time.monotonic()
            elif time.monotonic() - row["idle_since"] >= self.idle_grace:
                self.stop_process(row["process"])
                del self.instances[generation]
        self.save()

    @staticmethod
    def stop_process(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def serve(self):
        generation, config = self.current()
        self.launch(generation, config)
        self.active = generation
        self.launch_frontend()
        self.control.unlink(missing_ok=True)
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(self.control))
            self.control.chmod(0o600)
            server.listen(8)
            server.settimeout(1)
            self.save()
            notify = os.environ.get("NOTIFY_SOCKET")
            if notify:
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
                    client.connect("\0" + notify[1:] if notify.startswith("@") else notify)
                    client.sendall(b"READY=1")
            last_sweep = 0
            while not self.stopping:
                if time.monotonic() - last_sweep >= 5:
                    try:
                        self.sweep()
                    except Exception as exc:
                        # Preserve live generations while retrying a failed component.
                        self.last_error = type(exc).__name__ + ": " + str(exc)[:200]
                        self.save()
                    last_sweep = time.monotonic()
                try:
                    client, _ = server.accept()
                except socket.timeout:
                    continue
                with client:
                    client.settimeout(5)
                    try:
                        message = bytearray()
                        while b"\n" not in message and len(message) < 4096:
                            block = client.recv(4096)
                            if not block:
                                break
                            message.extend(block)
                        command = json.loads(message).get("command")
                        if command == "switch":
                            result = self.switch()
                        elif command == "status":
                            result = {"status": "ok", **self.snapshot()}
                        else:
                            raise ValueError("unknown runtime command")
                    except Exception as exc:
                        # Exceptions contain only our categorical messages, not child output/config.
                        self.last_error = type(exc).__name__ + ": " + str(exc)[:200]
                        self.save()
                        result = {"status": "error", "error": self.last_error}
                    try:
                        client.sendall(json.dumps(result).encode() + b"\n")
                    except OSError:
                        pass

    def close(self):
        processes = ([self.frontend] if self.frontend is not None else []) + [row["process"] for row in self.instances.values()]
        for process in processes:
            try:
                self.stop_process(process)
            except (OSError, subprocess.TimeoutExpired):
                pass  # systemd also owns and cleans up the entire cgroup.
        self.control.unlink(missing_ok=True)
        self.admin.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("serve", "switch", "status", "capacity"))
    parser.add_argument("--root", type=Path, default=Path("/var/lib/resin-singbox-bridge"))
    parser.add_argument("--runtime-dir", type=Path, default=Path("/run/resin-singbox-bridge"))
    parser.add_argument("--binary", default="/opt/resin-singbox-bridge/bin/sing-box")
    parser.add_argument("--haproxy", default="/usr/sbin/haproxy")
    args = parser.parse_args()
    if args.command != "serve":
        # Client-side classification works with the existing live daemon. Updating
        # maintenance must not restart it and interrupt accepted TCP sessions.
        try:
            result = request(args.runtime_dir / "control.sock", {
                "command": "status" if args.command == "capacity" else args.command})
        except RuntimeError as exc:
            if args.command != "switch" or str(exc) not in {
                "generation_capacity_reached: live TCP sessions defer this update",
                "RuntimeError: generation_capacity_reached: live TCP sessions defer this update",
            }:
                raise
            print(json.dumps({"status": "deferred", "reason": "generation_capacity_reached"}))
            return 75
        if args.command == "capacity":
            instances = result.get("instances")
            capacity = result.get("capacity")
            if (result.get("owner") != OWNER or not isinstance(instances, dict)
                    or type(capacity) is not int or capacity < 1
                    or result.get("active_generation") not in instances):
                raise RuntimeError("bridge runtime status is incomplete")
            if len(instances) >= capacity:
                print(json.dumps({"status": "deferred", "reason": "generation_capacity_reached"}))
                return 75
            result = {"status": "ready", "available_generations": capacity - len(instances)}
        print(json.dumps(result))
        return 0
    runtime = Runtime(args.root, args.runtime_dir, args.binary, args.haproxy)
    def stop(*_):
        runtime.stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        runtime.serve()
    finally:
        runtime.close()


if __name__ == "__main__":
    sys.exit(main())
