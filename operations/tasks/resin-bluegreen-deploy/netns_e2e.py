#!/usr/bin/env python3
"""Root-only isolated kernel NAT + real Resin CONNECT/drain test. No Docker or internet."""

import argparse
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

from bluegreen import Deployment, run


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(4096):
            self.request.sendall(data)


def connect():
    conn = socket.create_connection(("10.203.0.1", 10834), timeout=3)
    conn.sendall(b"CONNECT 127.0.0.1:19000 HTTP/1.1\r\nHost: 127.0.0.1:19000\r\n\r\n")
    response = b""
    while not response.endswith(b"\r\n\r\n"):
        response += conn.recv(1)
        if len(response) > 4096:
            raise RuntimeError("oversized CONNECT response")
    if not response.startswith(b"HTTP/1.1 200"):
        raise RuntimeError("CONNECT failed")
    return conn


def ping(conn):
    payload = os.urandom(128)
    conn.sendall(payload)
    answer = b""
    while len(answer) < len(payload):
        data = conn.recv(len(payload) - len(answer))
        if not data:
            raise RuntimeError("tunnel closed before client finished")
        answer += data
    assert answer == payload


def client():
    conns = []
    try:
        for line in sys.stdin:
            action = line.strip()
            if action == "open":
                conns.append(connect())
            elif action == "ping":
                for conn in conns:
                    ping(conn)
            elif action == "close":
                for conn in conns:
                    conn.close()
                conns.clear()
            elif action == "burst":
                for _ in range(20):
                    with connect() as conn:
                        ping(conn)
            else:
                raise RuntimeError("unknown action")
            print("ok", flush=True)
    finally:
        for conn in conns:
            conn.close()


def inner(binary):
    assert os.readlink("/proc/self/ns/net") != os.environ["E2E_HOST_NETNS"]
    run(["ip", "link", "set", "lo", "up"])
    holder = subprocess.Popen(["unshare", "--net", "sleep", "infinity"])
    processes = [holder]
    handles = []
    clients = []
    with tempfile.TemporaryDirectory(prefix="resin-netns-") as root:
        root = Path(root)
        try:
            for _ in range(100):
                if os.readlink(f"/proc/{holder.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                    break
                time.sleep(0.01)
            run(["ip", "link", "add", "rveth0", "type", "veth", "peer", "name", "rveth1"])
            run(["ip", "link", "set", "rveth1", "netns", str(holder.pid)])
            run(["ip", "addr", "add", "10.203.0.1/24", "dev", "rveth0"])
            run(["ip", "link", "set", "rveth0", "up"])
            prefix = ["nsenter", "-t", str(holder.pid), "-n"]
            run([*prefix, "ip", "link", "set", "lo", "up"])
            run([*prefix, "ip", "addr", "add", "10.203.0.2/24", "dev", "rveth1"])
            run([*prefix, "ip", "link", "set", "rveth1", "up"])
            # Docker already registers NAT/conntrack hooks on the production host.
            # Model that before legacy TCP sessions begin, not at first migration.
            run(["iptables", "-t", "nat", "-N", "DOCKER"])
            run(["iptables", "-t", "nat", "-A", "DOCKER", "-d", "192.0.2.1", "-p", "tcp",
                 "--dport", "65000", "-j", "DNAT", "--to-destination", "192.0.2.2:65000"])
            for chain in ("PREROUTING", "OUTPUT"):
                run(["iptables", "-t", "nat", "-A", chain, "-j", "DOCKER"])
            echo = socketserver.ThreadingTCPServer(("127.0.0.1", 19000), Echo)
            echo.daemon_threads = True
            threading.Thread(target=echo.serve_forever, daemon=True).start()
            os.environ["RESIN_ENTRY_ADDRESS"] = "10.203.0.1"
            dep = Deployment()
            slots = {}
            for slot in ("legacy", "blue", "green"):
                env = os.environ.copy()
                env.update({"RESIN_LISTEN_ADDRESS": dep.address, "RESIN_PORT": str(dep.ports[slot]),
                            "RESIN_ADMIN_TOKEN": "", "RESIN_PROXY_TOKEN": "", "RESIN_AUTH_VERSION": "V1",
                            "RESIN_PROXY_BYPASS": "127.*", "RESIN_SHUTDOWN_PRESERVE_CONNECTIONS": "1",
                            "RESIN_DRAIN_TIMEOUT": "0", "RESIN_PROBE_CONCURRENCY": "2",
                            "RESIN_RESOURCE_FETCH_TIMEOUT": "1s", "RESIN_NODE_DNS_UPSTREAMS": '["local"]'})
                for kind in ("state", "cache", "log"):
                    directory = root / slot / kind
                    directory.mkdir(parents=True)
                    env[f"RESIN_{kind.upper()}_DIR"] = str(directory)
                output = (root / f"{slot}.log").open("w+")
                handles.append(output)
                process = subprocess.Popen([binary], env=env, cwd=root, stdout=output, stderr=output)
                slots[slot] = process
                processes.append(process)
                dep.health(slot)

            for command in ([sys.executable, __file__, "--client"], [*prefix, sys.executable, __file__, "--client"]):
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True)
                clients.append(process)
                processes.append(process)

            def both(action):
                for process in clients:
                    process.stdin.write(action + "\n")
                    process.stdin.flush()
                for process in clients:
                    import select
                    assert select.select([process.stdout], [], [], 15)[0], f"client timed out: {action}"
                    reply = process.stdout.readline().strip()
                    if reply != "ok":
                        raise AssertionError(f"client failed: {action}: {process.stderr.read()}")

            def count(slot):
                return len(run(["ss", "-H", "-tn", "state", "established", f"sport = :{dep.ports[slot]}"]).stdout.splitlines())

            # Existing unmapped connections must survive the very first NAT installation.
            both("open")
            assert count("legacy") == 2
            dep.ensure_nat("legacy")
            dep.switch_nat("blue")
            both("ping")
            both("open")
            assert count("legacy") == 2 and count("blue") == 2
            both("ping")
            print("PASS: initial migration preserves legacy TCP on OUTPUT and PREROUTING", flush=True)

            # Exercise both directions repeatedly with new connections in flight.
            stop = threading.Event()
            errors = []
            successful = []

            def traffic():
                while not stop.is_set():
                    try:
                        with connect() as conn:
                            ping(conn)
                            successful.append(1)
                    except Exception as exc:
                        errors.append(type(exc).__name__)

            thread = threading.Thread(target=traffic)
            thread.start()
            try:
                for _ in range(5):
                    dep.switch_nat("green")
                    both("burst")
                    dep.switch_nat("blue")
                    both("ping")
                dep.switch_nat("green")
            finally:
                stop.set()
                thread.join(10)
            assert not thread.is_alive() and not errors and len(successful) > 0, errors
            before = count("green")
            both("open")
            assert count("green") == before + 2
            assert count("blue") == 2
            both("ping")
            print(f"PASS: atomic switch/rollback with {len(successful)} new host tunnels, 200 bridge/host burst tunnels, zero failures", flush=True)

            slots["blue"].send_signal(signal.SIGTERM)
            for _ in range(100):
                result = run(["ss", "-H", "-ltn", "sport = :10835"])
                if not result.stdout.strip():
                    break
                time.sleep(0.01)
            assert not result.stdout.strip()
            both("ping")
            assert slots["blue"].poll() is None
            slots["blue"].send_signal(signal.SIGTERM)
            time.sleep(0.1)
            both("ping")
            assert slots["blue"].poll() is None
            assert dep.live_connections("blue")
            both("close")
            assert slots["blue"].wait(timeout=15) == 0
            print("PASS: real Resin SIGTERM keeps both CONNECT tunnels alive until clients close", flush=True)
            dep.ensure_nat("green")
            first = run(["iptables-save", "-t", "nat"]).stdout
            dep.ensure_nat("green")
            dep.switch_nat("green")
            second = run(["iptables-save", "-t", "nat"]).stdout
            assert [x for x in first.splitlines() if not x.startswith("#")] == [x for x in second.splitlines() if not x.startswith("#")]
            print("PASS: NAT restoration is idempotent", flush=True)
        except BaseException:
            for handle in handles:
                handle.flush()
                handle.seek(0)
                print(handle.name, handle.read()[-4000:], file=sys.stderr)
            raise
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
            for process in reversed(processes):
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for handle in handles:
                handle.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary")
    parser.add_argument("--inner", action="store_true")
    parser.add_argument("--client", action="store_true")
    args = parser.parse_args()
    if args.client:
        client()
    elif args.inner:
        inner(args.binary)
    else:
        if os.geteuid() != 0 or not args.binary:
            parser.error("requires root and --binary /absolute/path/to/resin")
        env = os.environ.copy()
        env["E2E_HOST_NETNS"] = os.readlink("/proc/self/ns/net")
        result = subprocess.run(["unshare", "--net", sys.executable, __file__, "--inner", "--binary",
                                 str(Path(args.binary).resolve())], env=env, timeout=180, check=False)
        sys.exit(result.returncode)
