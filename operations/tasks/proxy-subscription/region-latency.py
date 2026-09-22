#!/usr/bin/env python3
"""Maintain subscription-only regional shortlists using fresh successful probes."""

import argparse
import concurrent.futures
from datetime import datetime, timezone
import fcntl
import json
import math
import os
from pathlib import Path
import random
import re
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import site_policy


BASE = "http://172.17.0.1:10834"
FIELDS = ("regex_filters", "allocation_policy")
LOCK_PATH = "/run/lock/resin-pool-maintenance-data-plane.lock"


def acquire_probe_lock(lock, priority):
    try:
        fcntl.flock(priority, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False
    finally:
        fcntl.flock(priority, fcntl.LOCK_UN)


def source_for(region):
    return "managed-apps-cn-public-pool" if region == "cn" else "managed-apps-public-pool"


def source_filter(region):
    return "^" + source_for(region) + "/.*"


def managed_tags(node, region):
    source = source_for(region)
    return sorted({t["tag"] for t in node.get("tags", [])
                   if t.get("subscription_name") == source
                   and t.get("tag", "").startswith(source + "/")})


def eligible(node, region):
    return (node.get("enabled") is True and node.get("has_outbound") is True
            and node.get("circuit_open_since") is None and node.get("region") == region
            and node.get("failure_count", 0) <= 1
            and bool(node.get("egress_ip")) and bool(managed_tags(node, region)))


def reference_score(node):
    value = node.get("reference_latency_ms")
    return value if isinstance(value, (int, float)) and math.isfinite(value) and value > 0 else math.inf


def shortlist(nodes, region, limit=16, seed=None):
    ordered = sorted((n for n in nodes if eligible(n, region)),
                     key=lambda n: (n.get("failure_count", 0), reference_score(n), n["node_hash"]))
    # Prefer independent exits. Aliases of the same exit are not extra capacity.
    seen, selected = set(), []
    for node in ordered:
        if node["egress_ip"] in seen:
            continue
        seen.add(node["egress_ip"])
        selected.append(node)
        if len(selected) == limit:
            break
    # Reserve a small exploration budget so new/previously slow nodes can
    # displace the old shortlist instead of being permanently excluded.
    if limit >= 8 and len(selected) == limit:
        remaining = [n for n in ordered if n["egress_ip"] not in seen]
        random.Random(seed).shuffle(remaining)
        exploration = []
        for candidate in remaining:
            if candidate["egress_ip"] not in {n["egress_ip"] for n in exploration}:
                exploration.append(candidate)
            if len(exploration) == 4:
                break
        if exploration:
            selected = selected[:-len(exploration)] + exploration
    return selected


def selected_filters(nodes, region):
    tags = sorted({managed_tags(n, region)[0] for n in nodes})
    # The first rule is MUST; exact tag alternatives are ORed by Resin.
    return ["*" + source_filter(region)] + ["^" + re.escape(tag) + "$" for tag in tags]


def bridge_port(node):
    for tag in managed_tags(node, node["region"]):
        match = re.fullmatch(r"managed-apps-public-pool/socks-172\.17\.0\.1:(\d+)", tag)
        if match and 12000 <= int(match[1]) <= 13000 and int(match[1]) != 12400:
            return int(match[1])
    return None


def probe_bridge(port, deadline, region=None):
    # Measure only validated local fixed ports, never arbitrary tag URLs.
    times = []
    for host, path in (("www.cloudflare.com", "/cdn-cgi/trace"),
                       ("www.microsoft.com", "/"), ("www.wikipedia.org", "/")):
        if time.monotonic() >= deadline:
            return None
        response = subprocess.run([
            "curl", "--silent", "--output", "-" if path == "/cdn-cgi/trace" else "/dev/null",
            "--noproxy", "",
            "--proxy", f"socks5h://172.17.0.1:{port}", "--connect-timeout", "3",
            "--max-time", "5", "--write-out", "\n%{http_code} %{time_total}",
            f"https://{host}{path}"], capture_output=True, timeout=7)
        body, _, metrics = response.stdout.rpartition(b"\n")
        fields = metrics.split()
        if response.returncode == 0 and len(fields) == 2 and 200 <= int(fields[0]) < 400:
            if path == "/cdn-cgi/trace" and region:
                trace = dict(line.split("=", 1) for line in body.decode(errors="replace").splitlines()
                             if "=" in line)
                actual = trace.get("loc", "").lower()
                if re.fullmatch(r"[a-z]{2}", actual) and actual != region:
                    return "region-mismatch"
                if actual != region:
                    return None
            times.append(float(fields[1]) * 1000)
    if len(times) < 2:
        return None
    # A node passing all targets must outrank partial connectivity.
    return (3 - len(times)) * 10000 + statistics.mean(times)


class API:
    def __init__(self, token):
        self.token = token

    def call(self, path, method="GET", data=None):
        body = json.dumps(data).encode() if data is not None else None
        request = urllib.request.Request(BASE + path, method=method, data=body, headers={
            "Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.load(response)

    def nodes(self):
        rows, offset = [], 0
        while True:
            page = self.call("/api/v1/nodes?enabled=true&has_outbound=true&circuit_open=false"
                             f"&limit=1000&offset={offset}")
            rows.extend(page["items"])
            offset += len(page["items"])
            if offset >= page["total"]:
                return rows
            if not page["items"]:
                raise RuntimeError("incomplete node inventory")


def optimize(api, manifest, apply):
    original = {}
    for name, spec in manifest.items():
        region = spec.get("region", "")
        if not re.fullmatch(r"[a-z]{2}", region) or name != "Proxy" + region.upper():
            raise RuntimeError("invalid subscription platform manifest")
        row = api.call("/api/v1/platforms/" + urllib.parse.quote(spec["id"], safe=""))
        if row["name"] != name or row["region_filters"] != [region]:
            raise RuntimeError("subscription platform ownership mismatch")
        original[name] = row
    nodes = api.nodes()
    candidates = {name: shortlist(nodes, spec["region"]) for name, spec in manifest.items()}
    if not apply:
        print(json.dumps({"mode": "check", "regions": len(manifest),
                          "candidate_probes": sum(map(len, candidates.values()))}))
        return

    deadline = time.monotonic() + 300

    def probe(node):
        try:
            if time.monotonic() >= deadline:
                return node["node_hash"], None
            port = bridge_port(node)
            if port is not None:
                return node["node_hash"], probe_bridge(port, deadline, node["region"])
            if node["region"] != "cn":
                return node["node_hash"], None
            result = api.call("/api/v1/nodes/" + node["node_hash"] + "/actions/probe-latency", "POST")
            latency = result.get("latency_ewma_ms")
            if isinstance(latency, (int, float)) and math.isfinite(latency) and latency > 0:
                return node["node_hash"], latency
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, subprocess.TimeoutExpired):
            pass
        return node["node_hash"], None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        scores = dict(executor.map(probe, [n for group in candidates.values() for n in group]))
    live = {n["node_hash"]: n for n in api.nodes()}
    applied, report = [], []
    try:
        for name, spec in manifest.items():
            region = spec["region"]
            passing = [n for n in candidates[name] if isinstance(scores.get(n["node_hash"]), (int, float))
                       and n["node_hash"] in live and eligible(live[n["node_hash"]], region)]
            passing.sort(key=lambda n: scores[n["node_hash"]])
            fully_reachable = [n for n in passing if scores[n["node_hash"]] < 10000]
            chosen = (fully_reachable if len(fully_reachable) >= 2 else passing)[:8]
            filters = selected_filters(chosen, region) if chosen else [source_filter(region)]
            mismatched = [n for n in candidates[name] if scores.get(n["node_hash"]) == "region-mismatch"]
            if not chosen:
                filters += ["!" + pattern for pattern in selected_filters(mismatched, region)[1:]]
            patch = {"regex_filters": filters, "allocation_policy": "PREFER_LOW_LATENCY"}
            endpoint = "/api/v1/platforms/" + urllib.parse.quote(spec["id"], safe="")
            current = api.call(endpoint)
            if any(current[k] != original[name][k] for k in (*FIELDS, "region_filters", "name")):
                raise RuntimeError("platform changed concurrently")
            if any(current[k] != patch[k] for k in FIELDS):
                applied.append(name)
                updated = api.call(endpoint, "PATCH", patch)
                if any(updated.get(k) != patch[k] for k in FIELDS):
                    raise RuntimeError("platform update verification failed")
                if chosen and updated["routable_node_count"] < 1:
                    api.call(endpoint, "PATCH", {"regex_filters": [source_filter(region)]})
                    chosen = []
            report.append({"region": region, "probed": len(candidates[name]),
                           "selected": len(chosen), "pool_fallback": not bool(chosen),
                           "region_mismatches_excluded": len(mismatched),
                           "median_probe_score": round(statistics.median(scores[n["node_hash"]]
                               for n in chosen), 1) if chosen else None})
    except Exception:
        rollback_failed = False
        for name in reversed(applied):
            try:
                api.call("/api/v1/platforms/" + manifest[name]["id"], "PATCH",
                         {k: original[name][k] for k in FIELDS})
            except Exception:
                rollback_failed = True
        if rollback_failed:
            raise RuntimeError("regional update failed; rollback incomplete") from None
        raise RuntimeError("regional update failed; prior filters restored") from None
    print(json.dumps({"status": "success", "updated": len(applied), "regions": report,
                      "finished_at": datetime.now(timezone.utc).isoformat()}), flush=True)


def save_restore_point(api, manifest, path):
    if path.exists():
        return
    saved = {}
    for name, spec in manifest.items():
        row = api.call("/api/v1/platforms/" + spec["id"])
        if row["name"] != name or row["region_filters"] != [spec["region"]]:
            raise RuntimeError("restore point ownership mismatch")
        saved[name] = {"id": row["id"], "region_filters": row["region_filters"],
                       **{k: row[k] for k in FIELDS}}
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", prefix=".restore-", dir=path.parent,
                                         delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(saved, handle)
            handle.flush()
            os.fsync(handle.fileno())
        # Publish a complete snapshot without overwriting an existing one.
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def restore(api, manifest, path):
    saved = json.loads(path.read_text())
    for name, row in saved.items():
        if name not in manifest or manifest[name]["id"] != row["id"]:
            raise RuntimeError("restore manifest mismatch")
        current = api.call("/api/v1/platforms/" + row["id"])
        if current["name"] != name or current["region_filters"] != row["region_filters"]:
            raise RuntimeError("restore platform ownership mismatch")
    for row in saved.values():
        api.call("/api/v1/platforms/" + row["id"], "PATCH", {k: row[k] for k in FIELDS})
    print(json.dumps({"status": "restored", "regions": len(saved)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--restore", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    with open(LOCK_PATH, "a") as lock, open(LOCK_PATH + ".priority", "a") as priority:
        if not acquire_probe_lock(lock, priority):
            print(json.dumps({"status": "skipped", "reason": "pool maintenance active or queued"}))
            return
        credentials = os.environ.get("CREDENTIALS_DIRECTORY")
        token_path = Path(credentials) / "admin_token" if credentials else Path("/etc/resin-apps/admin.token")
        manifest = json.loads(Path("/etc/xray/resin-region-platforms.json").read_text())
        api = API(token_path.read_text().strip())
        saved = Path("/var/lib/proxy-region-latency/original-platforms.json")
        if site_policy.strict_enabled():
            if args.restore:
                raise RuntimeError("disable strict site policy before restoring broad regional pools")
            if args.apply:
                result = site_policy.enforce(api, manifest)
                import rotation_pool
                if rotation_pool.enabled():
                    result["rotation_exits"] = len(rotation_pool.enforce(api))
                print(json.dumps(result), flush=True)
            else:
                approved = site_policy.effective(site_policy.load_state(), site_policy.bridge_identities(), api.nodes())
                for name, spec in manifest.items():
                    current = api.call("/api/v1/platforms/" + spec["id"])
                    row = approved.get(spec["region"])
                    if (current["name"] != name or current["region_filters"] != [spec["region"]]
                            or current["regex_filters"] != (site_policy.filters(row) if row else site_policy.DENY)
                            or current["routable_node_count"] != (1 if row else 0)):
                        raise RuntimeError("strict platform verification failed")
                print(json.dumps({"mode": "strict-check", "approved_regions": sorted(approved)}))
            return
        if args.restore:
            restore(api, manifest, saved)
        else:
            if args.apply:
                save_restore_point(api, manifest, saved)
            optimize(api, manifest, args.apply)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Upstream exception strings may contain URLs or node identifiers.
        print(json.dumps({"status": "error", "category": type(exc).__name__}), file=sys.stderr)
        sys.exit(1)
