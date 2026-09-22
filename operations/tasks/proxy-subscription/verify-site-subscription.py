#!/usr/bin/env python3
"""Check every subscription exit through an isolated real Mihomo client."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import copy
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

import yaml

import site_policy


ROOT = Path(__file__).resolve().parent
MIHOMO = Path("/opt/proxy-site-quality/mihomo")
ITEM_FIELDS = ("region", "port", "node_hash", "slot_identity", "expected_ip")


def interrupted_report(items, started, partial, error):
    report = dict(partial, started_at=started, finished_at=datetime.now(timezone.utc).isoformat(),
                  targets=site_policy.TARGETS, headed=True, incomplete=True, nodes=[])
    prior = {row["port"]: row for row in partial.get("nodes", [])}
    for item in items:
        row = dict(item, before=None, after=None, sites={}, trace_diagnostics={})
        row.update(prior.get(item["port"], {}))
        row.update(passed=False, identity_valid=False, audit_error=type(error).__name__)
        report["nodes"].append(row)
    return report


def browser_check(items, label="site-recheck", timeout=180):
    identity = pwd.getpwnam("proxy-site-browser")
    stamp = str(time.time_ns())
    request = Path("/var/lib/proxy-site-browser") / ("request-" + stamp + ".json")
    output = request.parent / (label + "-" + stamp)
    site_policy.atomic_json(request, items)
    os.chown(request, identity.pw_uid, identity.pw_gid)
    command = ["setpriv", "--reuid", str(identity.pw_uid), "--regid", str(identity.pw_gid),
               "--clear-groups", "--ambient-caps=-all", "--inh-caps=-all", "--no-new-privs", "--reset-env",
               "xvfb-run", "-a", "/usr/bin/python3", "-B", "/opt/proxy-site-quality/site-quality.py",
               "--items", str(request), "--browser", "/opt/proxy-site-quality/chromium/chrome",
               "--headed", "--output", str(output)]
    started = datetime.now(timezone.utc).isoformat()
    process = None
    error = None
    try:
        process = subprocess.Popen(command, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
            if code:
                error = subprocess.CalledProcessError(code, command)
        except subprocess.TimeoutExpired as exc:
            error = exc
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        request.unlink(missing_ok=True)
    path = output / "report.json"
    if error is not None:
        try:
            partial = json.loads(path.read_text())
        except (OSError, ValueError):
            partial = {}
        report = interrupted_report(items, started, partial, error)
        site_policy.atomic_json(path, report)
        return report, path
    return json.loads(path.read_text()), path


def subscription_config(staged=False):
    token = Path("/etc/xray/subscription-token").read_text().strip()
    if not staged:
        return yaml.safe_load((Path("/var/lib/proxy-subscription") / (token + ".yaml")).read_bytes())
    # Use the canonical renderer in a private directory; no public file is replaced.
    with tempfile.TemporaryDirectory(prefix="site-preview-") as directory:
        env = dict(os.environ, XRAY_SUBSCRIPTION_OUTPUT_DIR=directory + "/sub",
                   XRAY_SUBSCRIPTION_URL_FILE=directory + "/url",
                   XRAY_SITE_POLICY=directory + "/no-strict-policy",
                   XRAY_ROTATION_POLICY=directory + "/no-rotation-policy")
        subprocess.run(["bash", str(ROOT / "render-proxy-subscription.sh")], env=env,
                       check=True, stdout=subprocess.DEVNULL, timeout=30)
        return yaml.safe_load((Path(directory) / "sub" / (token + ".yaml")).read_bytes())


def restrict(config, approvals):
    spec = importlib.util.spec_from_file_location("site_subscription", ROOT / "site-subscription.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.restrict(copy.deepcopy(config), approvals)
    result["listeners"] = []
    return result


def verify_round(config, approvals, mihomo=MIHOMO, auto_fast=False, deadline=None):
    if not approvals:
        raise ValueError("no subscription exits to verify")
    config = copy.deepcopy(config)
    names = {p["name"] for p in config["proxies"]}
    if not all(region.upper() + "-Auto" in names for region in approvals):
        raise ValueError("verification config is missing a candidate")
    report = {"started_at": datetime.now(timezone.utc).isoformat(), "targets": site_policy.TARGETS,
              "headed": True, "validation_path": "subscription", "client": "Mihomo",
              "dns_enabled": config.get("dns", {}).get("enable") is True,
              "nodes": [], "reports": []}
    evidence_path = Path("/var/lib/proxy-region-latency") / ("client-round-" + str(time.time_ns()) + ".json")
    with tempfile.TemporaryDirectory(prefix="site-mihomo-") as directory, evidence_path.with_suffix(".log").open("w") as log:
        os.fchmod(log.fileno(), 0o600)
        report["client_log"] = str(evidence_path.with_suffix(".log"))
        reservations = [socket.socket(), socket.socket()]
        try:
            for sock in reservations:
                sock.bind(("127.0.0.1", 0))
            mixed, controller = [sock.getsockname()[1] for sock in reservations]
            config.update({"mixed-port": mixed, "external-controller": f"127.0.0.1:{controller}",
                           "bind-address": "127.0.0.1", "allow-lan": False, "log-level": "warning",
                           "profile": {"store-selected": False}})
            shutil.copyfile("/opt/proxy-site-quality/Country.mmdb", Path(directory) / "Country.mmdb")
            config_path = Path(directory) / "config.yaml"
            config_path.write_text(yaml.safe_dump(config, sort_keys=False))
            config_path.chmod(0o600)
            subprocess.run([str(mihomo), "-t", "-d", directory, "-f", str(config_path)],
                           check=True, stdout=log, stderr=log, timeout=20)
        finally:
            for sock in reservations:
                sock.close()
        process = subprocess.Popen([str(mihomo), "-d", directory, "-f", str(config_path)],
                                   stdout=log, stderr=log)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def call(path, body=None):
            req = urllib.request.Request(f"http://127.0.0.1:{controller}" + path,
                                         data=json.dumps(body).encode() if body is not None else None,
                                         method="PUT" if body is not None else "GET",
                                         headers={"Content-Type": "application/json"})
            with opener.open(req, timeout=5) as response:
                data = response.read()
                return json.loads(data) if data else None

        try:
            startup_deadline = time.monotonic() + 15
            while True:
                try:
                    call("/version")
                    groups = call("/proxies").get("proxies", {})
                    if "PROXY" not in groups or "Auto-Fast" not in groups:
                        raise OSError("Mihomo configuration is not loaded yet")
                    break
                except OSError:
                    if time.monotonic() > startup_deadline or process.poll() is not None:
                        raise RuntimeError("Mihomo failed to start") from None
                    time.sleep(0.1)
            choices = ["Auto-Fast"] if auto_fast else [region.upper() + "-Auto" for region in approvals]
            for choice in choices:
                call("/proxies/PROXY", {"name": choice})
                selected = call("/proxies/Auto-Fast")["now"] if auto_fast else choice
                region = selected[:2].lower()
                if region not in approvals:
                    raise RuntimeError("client selected an unapproved exit")
                row = approvals[region]
                entry = {key: row[key] for key in ITEM_FIELDS}
                entry.update(proxy_host="127.0.0.1", proxy_port=mixed)
                timeout = min(120, deadline - time.monotonic()) if deadline else 120
                if timeout <= 0:
                    raise TimeoutError("subscription verification deadline exceeded")
                checked, path = browser_check([entry], "public-verification", timeout=timeout)
                result = checked["nodes"][0]
                result["selected"] = selected
                if auto_fast and call("/proxies/Auto-Fast")["now"] != selected:
                    result["passed"] = False
                    result["selection_changed"] = True
                if site_policy.bridge_identities().get(row["port"]) != row["slot_identity"]:
                    result.update(passed=False, identity_valid=False)
                report["nodes"].append(result)
                report["reports"].append(str(path))
                report["finished_at"] = datetime.now(timezone.utc).isoformat()
                site_policy.atomic_json(evidence_path, report)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["summary"] = {"probed": len(report["nodes"]), "passed": sum(row["passed"] for row in report["nodes"]),
                         "verdicts": dict(Counter(site["verdict"] for row in report["nodes"]
                                                  for site in row["sites"].values()))}
    site_policy.atomic_json(evidence_path, report)
    print(json.dumps({"client": "Mihomo", "auto_fast": auto_fast, **report["summary"], "report": str(evidence_path)}), flush=True)
    return report, evidence_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mihomo", type=Path, default=MIHOMO)
    parser.add_argument("--auto-fast", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    approvals = site_policy.effective(site_policy.load_state(), site_policy.bridge_identities())
    report, path = verify_round(restrict(subscription_config(), approvals), approvals, args.mihomo, args.auto_fast)
    if len(site_policy.report_passes(report)) != len(report["nodes"]):
        subprocess.run([sys.executable, str(ROOT / "site-control.py"), "quarantine", "--report", str(path),
                        "--wait-seconds", "30"], check=True, timeout=90)
        raise RuntimeError("published subscription browser verification failed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"status": "error", "category": type(exc).__name__}), flush=True)
        raise SystemExit(1) from None
