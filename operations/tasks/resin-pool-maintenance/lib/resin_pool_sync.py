#!/usr/bin/env python3
"""Validate configured proxy sources and atomically sync a Resin subscription."""

from __future__ import annotations

import argparse
import copy
import contextlib
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping, Sequence

from proxy_probe import (
    atomic_write,
    parse_proxy_line,
    reselect_validation_artifacts,
    validation_from_config,
)


OWNER = "resin-pool-maintenance"
READABLE_OWNERS = {OWNER}
STATE_VERSION = 1
CURRENT_MANAGED_SOURCE_ID = "resin-current-managed-subscription"
MAX_POOL_NODES = 1000


class SyncError(RuntimeError):
    pass


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        raise SyncError("Admin API redirects are not allowed")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def maintenance_run_id() -> str:
    return str(os.environ.get("RESIN_MAINTENANCE_RUN_ID") or "") or (
        dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + f"-{os.getpid()}"
    )


def safety_mode(config: Mapping[str, Any]) -> str:
    """Require an explicit pool safety policy; never infer one from defaults."""
    safety = config.get("safety")
    if not isinstance(safety, Mapping):
        raise SyncError("safety.mode is required")
    mode = safety.get("mode")
    if not isinstance(mode, str) or not mode.strip():
        raise SyncError("safety.mode is required")
    normalized = mode.strip().lower()
    if normalized not in {"non_empty", "cn_gate"}:
        raise SyncError("unsupported safety mode")
    return normalized


def correlation_fields(manifest: Mapping[str, Any]) -> dict[str, str]:
    fields = {"run_id": str(manifest.get("run_id") or maintenance_run_id())}
    for name in ("bridge_generation", "bridge_run_id"):
        value = manifest.get(name)
        if isinstance(value, str) and value:
            fields[name] = value
    return fields


def copy_bridge_correlation(
    target: dict[str, Any], manifest: Mapping[str, Any]
) -> None:
    for name in ("bridge_generation", "bridge_run_id"):
        value = manifest.get(name)
        if isinstance(value, str) and value:
            target[name] = value


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resin_proxy_identity(line: str) -> tuple[Any, ...]:
    """Return the identity Resin hashes for the proxy formats we publish.

    Resin maps socks5 and socks5h to the same ``socks`` outbound and ignores
    the display tag when hashing a node.  The validator's fingerprints are
    intentionally more literal, so the maintenance gate must use Resin's
    identity semantics when deriving an expected node count.
    """
    spec = parse_proxy_line(line)
    if spec is None:
        raise SyncError("validated subscription contains an empty or comment-only node")
    node_type = "socks" if spec.scheme in {"socks5", "socks5h"} else "http"
    tls_enabled = spec.scheme == "https"
    return (
        node_type,
        spec.host,
        spec.port,
        spec.username,
        spec.password,
        tls_enabled,
    )


def resin_proxy_identities(content: str) -> tuple[set[tuple[Any, ...]], int]:
    """Parse published lines and derive Resin-compatible unique identities."""
    identities: set[tuple[Any, ...]] = set()
    non_comment_lines = 0
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        non_comment_lines += 1
        try:
            identities.add(resin_proxy_identity(line))
        except (TypeError, ValueError) as exc:
            raise SyncError("validated subscription contains an unsupported proxy line") from exc
    if not identities:
        raise SyncError("validated subscription contains no supported proxy nodes")
    return identities, non_comment_lines


def safe_message(exc: BaseException) -> str:
    if isinstance(exc, SyncError):
        return str(exc)
    if isinstance(exc, urllib.error.HTTPError):
        return f"Admin API HTTP {exc.code}"
    return exc.__class__.__name__


def load_json(path: Path, *, require_private: bool = True) -> dict[str, Any]:
    if not path.is_file():
        raise SyncError(f"missing JSON file: {path}")
    if require_private and path.stat().st_mode & 0o077:
        raise SyncError(f"JSON file must use mode 0600: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SyncError(f"invalid JSON file: {path}") from exc
    if not isinstance(value, dict):
        raise SyncError(f"JSON root must be an object: {path}")
    return value


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    atomic_write(path, payload, mode=0o600)


def load_token(path: Path) -> str:
    if not path.is_file() or path.stat().st_mode & 0o077:
        raise SyncError("admin token file must exist with mode 0600")
    token = path.read_text(encoding="utf-8").strip()
    if not token:
        raise SyncError("admin token file is empty")
    return token


class ResinClient:
    def __init__(self, base_url: str, token: str, timeout: float = 20.0) -> None:
        try:
            parsed = urllib.parse.urlsplit(base_url)
            hostname = parsed.hostname
            username = parsed.username
            password = parsed.password
            parsed.port
        except ValueError as exc:
            raise SyncError("invalid Resin base URL") from exc
        if (
            parsed.scheme not in ("http", "https")
            or not hostname
            or parsed.path not in ("", "/")
            or username is not None
            or password is not None
            or parsed.query
            or parsed.fragment
            or "?" in base_url
            or "#" in base_url
        ):
            raise SyncError("invalid Resin base URL")
        try:
            host_ip = ipaddress.ip_address(hostname)
        except ValueError:
            host_ip = None
        if parsed.scheme == "http" and (host_ip is None or host_ip.is_global):
            raise SyncError("plain HTTP Resin base URL must use a literal non-public IP")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirectHandler()
        )

    def request(self, method: str, path: str, body: Mapping[str, Any] | None = None) -> Any:
        data = None
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}",
            "User-Agent": "resin-pool-maintainer/1",
        }
        if body is not None:
            data = json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(2 * 1024 * 1024)
                if not raw:
                    return None
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            raise SyncError(f"Admin API HTTP {exc.code} for {method} {path.split('?', 1)[0]}") from None
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise SyncError(f"Admin API request failed for {method} {path.split('?', 1)[0]}") from exc


def get_page_items(payload: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise SyncError(f"invalid {label} list response")
    return [row for row in payload["items"] if isinstance(row, dict)]


def find_subscription(client: ResinClient, name: str) -> dict[str, Any] | None:
    query = urllib.parse.urlencode({"limit": 100, "offset": 0, "keyword": name})
    rows = get_page_items(client.request("GET", f"/api/v1/subscriptions?{query}"), "subscription")
    exact = [row for row in rows if row.get("name") == name]
    if len(exact) > 1:
        raise SyncError("multiple exact Resin subscriptions found")
    if not exact:
        return None
    subscription_id = str(exact[0].get("id") or "")
    if not subscription_id:
        raise SyncError("Resin subscription list row has no id")
    row = client.request(
        "GET", f"/api/v1/subscriptions/{urllib.parse.quote(subscription_id, safe='')}"
    )
    if (
        not isinstance(row, dict)
        or row.get("id") != subscription_id
        or row.get("name") != name
    ):
        raise SyncError("Resin subscription identity mismatch")
    return row


def get_platform(client: ResinClient, platform_id: str, expected_name: str) -> dict[str, Any]:
    row = client.request("GET", f"/api/v1/platforms/{urllib.parse.quote(platform_id, safe='')}")
    if not isinstance(row, dict) or row.get("id") != platform_id or row.get("name") != expected_name:
        raise SyncError("Resin platform identity mismatch")
    return row


def subscription_signature(row: Mapping[str, Any] | None) -> tuple[Any, ...] | None:
    if row is None:
        return None
    content = str(row.get("content") or "").encode("utf-8")
    return (
        str(row.get("id") or ""),
        sha256_bytes(content),
        str(row.get("source_type") or ""),
        bool(row.get("enabled")),
        bool(row.get("ephemeral")),
        bool(row.get("incremental_alive_nodes")),
        str(row.get("update_interval") or ""),
        str(row.get("ephemeral_node_evict_delay") or ""),
    )


def platform_signature(row: Mapping[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return (
        tuple(str(item) for item in (row.get("regex_filters") or [])),
        tuple(str(item) for item in (row.get("region_filters") or [])),
    )


def _is_trusted_regex_filter(value: str) -> bool:
    """Identify the explicit trusted fallback naming convention used by Resin."""
    return "trusted" in value.lower()


def _contains_managed_marker(value: str, managed_regex: str, subscription_name: str) -> bool:
    lowered = value.lower()
    return bool(
        (managed_regex and managed_regex.lower() in lowered)
        or (subscription_name and subscription_name.lower() in lowered)
    )


def merge_platform_regex_filters(
    before_filters: list[str],
    configured_filters: list[str],
    managed_regex: str,
    subscription_name: str,
    *,
    preserve_existing_trusted: bool = True,
) -> list[str]:
    """Apply configured filters, optionally preserving an existing trusted fallback.

    Resin evaluates multiple filters together, so an existing trusted+managed
    alternation must remain the sole owner of the managed branch instead of
    being paired with an additional managed-only filter.
    """
    if not preserve_existing_trusted:
        return list(configured_filters)
    trusted_filters = [item for item in before_filters if _is_trusted_regex_filter(item)]
    managed_trusted = any(
        _contains_managed_marker(item, managed_regex, subscription_name)
        for item in trusted_filters
    )
    desired = list(trusted_filters)
    for item in configured_filters:
        is_managed_only = (
            _contains_managed_marker(item, managed_regex, subscription_name)
            and not _is_trusted_regex_filter(item)
        )
        if managed_trusted and is_managed_only:
            continue
        if item not in desired:
            desired.append(item)
    return desired


def config_with_current_subscription(
    config: Mapping[str, Any],
    subscription: Mapping[str, Any] | None,
    run_dir: Path,
) -> dict[str, Any]:
    effective = copy.deepcopy(dict(config))
    resin = effective.get("resin") or {}
    if resin.get("include_current_subscription", True) is not True:
        return effective
    sources = effective.get("sources") or []
    if not isinstance(sources, list):
        raise SyncError("sources must be an array")
    if any(
        isinstance(source, Mapping)
        and str(source.get("id") or "") == CURRENT_MANAGED_SOURCE_ID
        for source in sources
    ):
        raise SyncError(f"source id is reserved: {CURRENT_MANAGED_SOURCE_ID}")
    if subscription is None:
        return effective
    content = str(subscription.get("content") or "").encode("utf-8")
    if not content:
        return effective
    max_bytes = int(
        (effective.get("validation") or {}).get(
            "max_source_bytes", 4 * 1024 * 1024
        )
    )
    if len(content) > max_bytes:
        raise SyncError("current managed subscription exceeds validation source size limit")
    source_path = run_dir / "current-managed-proxies.txt"
    atomic_write(source_path, content, mode=0o600)
    effective["sources"] = [
        *sources,
        {
            "id": CURRENT_MANAGED_SOURCE_ID,
            "type": "file",
            "path": str(source_path),
            "enabled": True,
            "allowed_non_public_proxy_ips": list(
                ((effective.get("resin") or {}).get(
                    "current_subscription_allowed_non_public_proxy_ips"
                ) or [])
            ),
        },
    ]
    selection = effective.setdefault("selection", {})
    if not isinstance(selection, dict):
        raise SyncError("selection must be an object")
    preferred = selection.get("preferred_source_ids") or []
    if not isinstance(preferred, list) or not all(isinstance(item, str) for item in preferred):
        raise SyncError("selection.preferred_source_ids must be a string array")
    selection["preferred_source_ids"] = list(
        dict.fromkeys([*preferred, CURRENT_MANAGED_SOURCE_ID])
    )
    return effective


def subscription_node_state(subscription: Mapping[str, Any]) -> tuple[int, int]:
    """Read the serving Resin process's authenticated, live subscription counts.

    Missing fields indicate an incompatible provider. Fail before any write;
    never infer a count from a delayed cache or silently widen the gate.
    """
    fields = ("managed_node_count", "evicted_node_count", "node_count")
    counts = [subscription.get(field) for field in fields]
    if any(type(count) is not int or count < 0 for count in counts):
        raise SyncError("Resin subscription API lacks valid live node counts; upgrade Resin first")
    managed, evicted, active = counts
    if active + evicted != managed:
        raise SyncError("Resin subscription API returned inconsistent node counts")
    return managed, evicted


def new_run_dir(state_dir: Path) -> Path:
    runs = state_dir / "runs"
    runs.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_dir, 0o700)
    os.chmod(runs, 0o700)
    base = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for suffix in range(100):
        name = base if suffix == 0 else f"{base}-{suffix:02d}"
        path = runs / name
        try:
            path.mkdir(mode=0o700)
            return path
        except FileExistsError:
            continue
    raise SyncError("unable to allocate run directory")


def read_previous_state(state_dir: Path) -> dict[str, Any]:
    path = state_dir / "state.json"
    if not path.exists():
        return {}
    return load_json(path)


def fail_closed_guards(config: Mapping[str, Any], report: Mapping[str, Any], previous: Mapping[str, Any]) -> None:
    safety = config.get("safety") or {}
    mode = safety_mode(config)
    selected = int(report.get("selected_count") or 0)
    passed = int(report.get("passed_count") or 0)
    # ``passed_count`` is the size of the probe result set and may exceed the
    # subscription capacity. Only the selected/published pool is capped.
    if selected > MAX_POOL_NODES:
        raise SyncError(f"selected pool exceeds the {MAX_POOL_NODES}-node limit")
    if mode == "non_empty":
        if selected < 1 or passed < 1:
            raise SyncError("non-empty pool invariant failed")
        return
    if mode != "cn_gate":
        raise SyncError("unsupported safety mode")
    minimum = int(safety.get("min_selected", 2))
    min_passed = int(safety.get("min_passed", minimum))
    if selected < minimum or passed < min_passed:
        raise SyncError(f"CN pool gate failed: selected={selected}, passed={passed}, minimum={minimum}")
    previous_selected = int(previous.get("selected_count") or 0)
    configured_max = int((config.get("selection") or {}).get("max_nodes") or 0)
    if configured_max > 0:
        previous_selected = min(previous_selected, configured_max)
    ratio = float(safety.get("min_ratio_to_previous", 0.5))
    if previous_selected > 0 and selected < int(previous_selected * ratio):
        raise SyncError(
            f"fail-closed: selected count {selected} is below previous ratio threshold"
        )


def minimum_active_node_count(
    config: Mapping[str, Any], previous: Mapping[str, Any]
) -> int:
    """Derive the active-node floor independently of report line counts."""
    safety = config.get("safety") or {}
    if safety_mode(config) == "non_empty":
        return 1
    minimum = int(safety.get("min_selected", 2))
    previous_selected = int(previous.get("selected_count") or 0)
    configured_max = int((config.get("selection") or {}).get("max_nodes") or 0)
    if configured_max > 0:
        previous_selected = min(previous_selected, configured_max)
    ratio = float(safety.get("min_ratio_to_previous", 0.5))
    ratio_floor = int(previous_selected * ratio) if previous_selected > 0 else 0
    return max(1, minimum, ratio_floor)


def derive_expected_resin_node_count(
    content: str, report: Mapping[str, Any]
) -> tuple[int, int]:
    """Cross-check the signed report and count nodes using Resin semantics."""
    identities, non_comment_lines = resin_proxy_identities(content)
    try:
        reported_selected = int(report.get("selected_count") or 0)
    except (TypeError, ValueError) as exc:
        raise SyncError("validation report selected_count is not an integer") from exc
    if reported_selected < 1 or non_comment_lines != reported_selected:
        raise SyncError(
            "validated proxy artifact line count does not match validation report"
        )
    if non_comment_lines > MAX_POOL_NODES:
        raise SyncError(f"validated subscription exceeds the {MAX_POOL_NODES}-node limit")
    return len(identities), non_comment_lines


def subscription_patch_from_config(config: Mapping[str, Any], content: str) -> dict[str, Any]:
    resin = config.get("resin") or {}
    return {
        "content": content,
        "update_interval": str(resin.get("update_interval", "24h")),
        "enabled": True,
        "ephemeral": bool(resin.get("ephemeral", True)),
        "incremental_alive_nodes": bool(resin.get("incremental_alive_nodes", True)),
        "ephemeral_node_evict_delay": str(resin.get("ephemeral_node_evict_delay", "72h")),
    }


def create_subscription(client: ResinClient, config: Mapping[str, Any], content: str) -> dict[str, Any]:
    resin = config.get("resin") or {}
    body = {
        "name": str(resin["subscription_name"]),
        "source_type": "local",
        **subscription_patch_from_config(config, content),
    }
    row = client.request("POST", "/api/v1/subscriptions", body)
    if not isinstance(row, dict) or not row.get("id"):
        raise SyncError("invalid subscription create response")
    return row


def update_subscription(client: ResinClient, subscription_id: str, patch: Mapping[str, Any]) -> dict[str, Any]:
    row = client.request(
        "PATCH",
        f"/api/v1/subscriptions/{urllib.parse.quote(subscription_id, safe='')}",
        patch,
    )
    if not isinstance(row, dict) or row.get("id") != subscription_id:
        raise SyncError("invalid subscription update response")
    return row


def get_subscription_by_id(
    client: ResinClient,
    subscription_id: str,
    *,
    allow_missing: bool = False,
) -> dict[str, Any] | None:
    path = f"/api/v1/subscriptions/{urllib.parse.quote(subscription_id, safe='')}"
    try:
        row = client.request("GET", path)
    except urllib.error.HTTPError as exc:
        if allow_missing and exc.code == 404:
            return None
        raise
    except SyncError as exc:
        if allow_missing and str(exc).startswith("Admin API HTTP 404 for GET "):
            return None
        raise
    if row is None and allow_missing:
        return None
    if not isinstance(row, dict) or row.get("id") != subscription_id:
        raise SyncError("Resin subscription identity mismatch")
    return row


def refresh_subscription(client: ResinClient, subscription_id: str) -> None:
    client.request(
        "POST",
        f"/api/v1/subscriptions/{urllib.parse.quote(subscription_id, safe='')}/actions/refresh",
        {},
    )


def verify_subscription(
    client: ResinClient,
    subscription_id: str,
    expected_digest: str,
    expected_node_count: int,
    *,
    allow_additional_nodes: bool,
    max_evicted_nodes: int = 0,
    minimum_node_count: int = 1,
    timeout: float = 120.0,
    settle_reads: int = 2,
) -> dict[str, Any]:
    if expected_node_count < 1:
        raise SyncError("expected subscription node count must be positive")
    if max_evicted_nodes < 0:
        raise SyncError("max evicted node count must not be negative")
    if minimum_node_count < 1:
        raise SyncError("minimum active node count must be positive")
    if settle_reads < 1:
        raise SyncError("subscription settle reads must be positive")
    if timeout <= 0:
        raise SyncError("subscription verification timeout must be positive")
    lower_bound = max(
        minimum_node_count,
        expected_node_count - min(max_evicted_nodes, expected_node_count - 1),
    )
    upper_bound = None if allow_additional_nodes else expected_node_count
    deadline = time.monotonic() + timeout
    last: dict[str, Any] | None = None
    consecutive_matches = 0
    last_digest_matches = False
    last_node_count: int | None = None
    last_error_present = False
    while time.monotonic() < deadline:
        row = client.request(
            "GET", f"/api/v1/subscriptions/{urllib.parse.quote(subscription_id, safe='')}"
        )
        if isinstance(row, dict):
            last = row
            content = str(row.get("content") or "").encode("utf-8")
            last_digest_matches = sha256_bytes(content) == expected_digest
            try:
                node_count = int(row.get("node_count") or 0)
            except (TypeError, ValueError):
                node_count = -1
            last_node_count = node_count
            last_error = row.get("last_error")
            last_error_present = not (
                last_error is None
                or (isinstance(last_error, str) and not last_error.strip())
            )
            count_matches = node_count >= lower_bound and (
                upper_bound is None or node_count <= upper_bound
            )
            if last_digest_matches and count_matches and not last_error_present:
                consecutive_matches += 1
                if consecutive_matches >= settle_reads:
                    return row
            else:
                consecutive_matches = 0
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(1.0, remaining))
    observed_count = last_node_count if last_node_count is not None else 0
    if upper_bound is None:
        expected_relation = f"at least {lower_bound}"
    elif lower_bound == upper_bound:
        expected_relation = f"exactly {upper_bound}"
    else:
        expected_relation = f"between {lower_bound} and {upper_bound}"
    raise SyncError(
        "subscription verification timed out: "
        f"expected {expected_relation} nodes, observed {observed_count}; "
        f"digest_match={last_digest_matches}, last_error={last_error_present}"
    )


def subscription_matches_patch(row: Mapping[str, Any], patch: Mapping[str, Any]) -> bool:
    for key, expected in patch.items():
        actual = row.get(key)
        if key in {"enabled", "ephemeral", "incremental_alive_nodes"}:
            if bool(actual) != bool(expected):
                return False
        elif key == "content":
            if str(actual or "") != str(expected or ""):
                return False
        elif str(actual or "") != str(expected or ""):
            return False
    return True


def restore_subscription(
    client: ResinClient,
    config: Mapping[str, Any],
    before: Mapping[str, Any] | None,
    created_id: str | None,
    *,
    create_attempted: bool = False,
) -> dict[str, Any]:
    result: dict[str, Any] = {"attempted": True}
    if create_attempted and before is None and not created_id:
        result.update(
            {
                "created_subscription_removed": False,
                "error": "subscription create result is ambiguous",
            }
        )
        return result
    result_key = "created_subscription_removed" if created_id else "subscription_restored"
    try:
        if created_id:
            client.request(
                "DELETE",
                f"/api/v1/subscriptions/{urllib.parse.quote(created_id, safe='')}",
            )
            if get_subscription_by_id(client, created_id, allow_missing=True) is not None:
                raise SyncError("created subscription still exists after rollback")
            result["created_subscription_removed"] = True
        elif before:
            subscription_id = str(before["id"])
            patch = {
                "content": str(before.get("content") or ""),
                "update_interval": str(before.get("update_interval") or "24h"),
                "enabled": bool(before.get("enabled")),
                "ephemeral": bool(before.get("ephemeral")),
                "incremental_alive_nodes": bool(before.get("incremental_alive_nodes")),
                "ephemeral_node_evict_delay": str(before.get("ephemeral_node_evict_delay") or "72h"),
            }
            update_subscription(client, subscription_id, patch)
            refresh_subscription(client, subscription_id)
            restored = get_subscription_by_id(client, subscription_id)
            if restored is None or not subscription_matches_patch(restored, patch):
                raise SyncError("subscription restore verification failed")
            result["subscription_restored"] = True
    except Exception as exc:
        result[result_key] = False
        result["error"] = safe_message(exc)
    return result


def prune_owned_runs(state_dir: Path, keep: int, current: Path) -> list[str]:
    if keep < 1:
        raise SyncError("retain_runs must be at least 1")
    runs_dir = (state_dir / "runs").resolve()
    if not runs_dir.is_dir():
        return []
    candidates: list[Path] = []
    for path in runs_dir.iterdir():
        if not path.is_dir() or path.resolve().parent != runs_dir or path.resolve() == current.resolve():
            continue
        manifest = path / "manifest.json"
        try:
            value = load_json(manifest)
        except SyncError:
            continue
        if value.get("owner") in READABLE_OWNERS:
            candidates.append(path)
    candidates.sort(key=lambda item: item.name, reverse=True)
    removed: list[str] = []
    for path in candidates[max(0, keep - 1) :]:
        shutil.rmtree(path)
        removed.append(path.name)
    return removed


@contextlib.contextmanager
def exclusive_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise SyncError("another pool-maintenance run is active") from exc
    try:
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def load_validated_run(
    config: Mapping[str, Any],
    config_path: Path,
    state_dir: Path,
    raw_run_dir: str,
    *,
    require_config_hash: bool = True,
) -> tuple[Path, dict[str, Any], dict[str, Any], Path, Path]:
    runs_dir = (state_dir / "runs").resolve()
    run_dir = Path(raw_run_dir).resolve()
    if run_dir.parent != runs_dir or not run_dir.is_dir():
        raise SyncError("validated run must be a direct child of the configured runs directory")
    manifest_path = run_dir / "manifest.json"
    report_file = run_dir / "validation-report.json"
    output_file = run_dir / "validated-proxies.txt"
    manifest = load_json(manifest_path)
    report = load_json(report_file)
    if not output_file.is_file() or output_file.stat().st_mode & 0o077:
        raise SyncError("validated proxy artifact is missing or not private")
    if manifest.get("owner") not in READABLE_OWNERS or manifest.get("status") != "validated_only":
        raise SyncError("validated run manifest is not eligible for apply")
    if require_config_hash and manifest.get("config_sha256") != sha256_file(config_path):
        raise SyncError("validated run config hash mismatch")
    content_digest = sha256_file(output_file)
    if report.get("output_sha256") != content_digest:
        raise SyncError("validated proxy artifact hash mismatch")
    validation = manifest.get("validation") or {}
    if validation.get("output_sha256") != content_digest:
        raise SyncError("validated run manifest hash mismatch")
    created_raw = str(report.get("created_at") or "").replace("Z", "+00:00")
    try:
        created_at = dt.datetime.fromisoformat(created_raw)
    except ValueError as exc:
        raise SyncError("validated report timestamp is invalid") from exc
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=dt.timezone.utc)
    max_age = int((config.get("safety") or {}).get("max_validation_age_seconds", 21600))
    age = (dt.datetime.now(dt.timezone.utc) - created_at.astimezone(dt.timezone.utc)).total_seconds()
    if age < 0 or age > max_age:
        raise SyncError("validated run is stale")
    if int(report.get("selected_count") or 0) > MAX_POOL_NODES:
        raise SyncError(f"validated run exceeds the {MAX_POOL_NODES}-node limit")
    return run_dir, manifest, report, output_file, report_file


def run(args: argparse.Namespace) -> int:
    config_path = Path(args.config).resolve()
    config = load_json(config_path)
    if int(config.get("version") or 0) != 1:
        raise SyncError("unsupported config version")
    safety_mode(config)
    state_dir = Path(str(config.get("state_dir") or "/var/lib/resin-pool-maintainer")).resolve()
    lock_path = Path(str(config.get("lock_file") or "/run/lock/resin-pool-maintainer.lock"))
    retain_runs = int(config.get("retain_runs", 1))
    if retain_runs < 1:
        raise SyncError("retain_runs must be at least 1")
    resin = config.get("resin") or {}
    subscription_name = str(resin.get("subscription_name") or "managed-apps-public-pool")
    platform_id = str(resin.get("platform_id") or "")
    platform_name = str(resin.get("platform_name") or "AppsGlobal")
    managed_regex = str(resin.get("managed_regex") or f"^{subscription_name}/")

    with exclusive_lock(lock_path):
        if args.command == "reselect":
            run_dir, manifest, _, output_file, report_file = load_validated_run(
                config,
                config_path,
                state_dir,
                args.validated_run,
                require_config_hash=False,
            )
            report = reselect_validation_artifacts(config, output_file, report_file)
            manifest.setdefault("run_id", maintenance_run_id())
            previous = read_previous_state(state_dir)
            fail_closed_guards(config, report, previous)
            content_digest = sha256_file(output_file)
            manifest.update(
                {
                    "status": "validated_only",
                    "config_sha256": sha256_file(config_path),
                    "reselected_at": utc_now(),
                    "validation": {
                        "input_count": report["input_count"],
                        "passed_count": report["passed_count"],
                        "selected_count": report["selected_count"],
                        "unique_egress_count": report["unique_egress_count"],
                        "output_sha256": content_digest,
                    },
                }
            )
            write_json(run_dir / "manifest.json", manifest)
            prune_owned_runs(state_dir, retain_runs, run_dir)
            print(
                json.dumps(
                    {
                        "status": "reselected",
                        **correlation_fields(manifest),
                        **manifest["validation"],
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "apply":
            run_dir, manifest, report, output_file, report_file = load_validated_run(
                config, config_path, state_dir, args.validated_run
            )
            manifest.setdefault("run_id", maintenance_run_id())
            manifest.update({"status": "running", "apply_started_at": utc_now()})
            write_json(run_dir / "manifest.json", manifest)
        else:
            run_dir = new_run_dir(state_dir)
            manifest = {
                "owner": OWNER,
                "version": STATE_VERSION,
                "run_id": maintenance_run_id(),
                "started_at": utc_now(),
                "status": "running",
                "config_sha256": sha256_file(config_path),
            }
            bridge_generation = str(os.environ.get("RESIN_BRIDGE_GENERATION") or "")
            bridge_run_id = str(os.environ.get("RESIN_BRIDGE_RUN_ID") or "")
            if bridge_generation:
                manifest["bridge_generation"] = bridge_generation
            if bridge_run_id:
                manifest["bridge_run_id"] = bridge_run_id
            write_json(run_dir / "manifest.json", manifest)
            output_file = run_dir / "validated-proxies.txt"
            report_file = run_dir / "validation-report.json"
            report = {}
        # Keep only the run currently being validated/applied. The run
        # directory is still needed for this transaction and for the optional
        # validate/apply hand-off, but older reports are not runtime state.
        prune_owned_runs(state_dir, retain_runs, run_dir)
        client: ResinClient | None = None
        observed_sub: dict[str, Any] | None = None
        observed_platform: dict[str, Any] | None = None
        try:
            if args.command != "apply":
                validation_config = config
                if args.command == "run":
                    if not args.confirm_production_write:
                        raise SyncError("production sync requires --confirm-production-write")
                    if not platform_id:
                        raise SyncError("resin.platform_id is required")
                    token = load_token(Path(args.admin_token_file))
                    client = ResinClient(
                        str(resin.get("base_url") or "http://172.17.0.1:10833"),
                        token,
                        timeout=float(resin.get("api_timeout_seconds", 20)),
                    )
                    observed_sub = find_subscription(client, subscription_name)
                    observed_platform = get_platform(client, platform_id, platform_name)
                    validation_config = config_with_current_subscription(
                        config, observed_sub, run_dir
                    )
                report = validation_from_config(validation_config, output_file, report_file)
            previous = read_previous_state(state_dir)
            fail_closed_guards(config, report, previous)
            content_bytes = output_file.read_bytes()
            content = content_bytes.decode("utf-8")
            expected_node_count, content_line_count = derive_expected_resin_node_count(
                content, report
            )
            content_digest = sha256_bytes(content_bytes)
            max_body = int(resin.get("max_api_body_bytes", 900_000))
            if len(content_bytes) > max_body:
                raise SyncError("validated subscription exceeds Resin API body safety limit")

            manifest["validation"] = {
                "input_count": report["input_count"],
                "passed_count": report["passed_count"],
                "selected_count": report["selected_count"],
                "resin_node_count": expected_node_count,
                "validated_line_count": content_line_count,
                "unique_egress_count": report["unique_egress_count"],
                "output_sha256": content_digest,
            }
            if os.environ.get("RESIN_BRIDGE_GENERATION"):
                manifest["validation"]["bridge_generation"] = os.environ[
                    "RESIN_BRIDGE_GENERATION"
                ]
            if args.command == "validate":
                manifest.update({"status": "validated_only", "completed_at": utc_now()})
                write_json(run_dir / "manifest.json", manifest)
                print(
                    json.dumps(
                        {
                            "status": "validated_only",
                            **correlation_fields(manifest),
                            **manifest["validation"],
                        },
                        sort_keys=True,
                    )
                )
                return 0

            if not args.confirm_production_write:
                raise SyncError("production sync requires --confirm-production-write")
            if not platform_id:
                raise SyncError("resin.platform_id is required")
            if client is None:
                token = load_token(Path(args.admin_token_file))
                client = ResinClient(
                    str(resin.get("base_url") or "http://172.17.0.1:10833"),
                    token,
                    timeout=float(resin.get("api_timeout_seconds", 20)),
                )

            before_sub = find_subscription(client, subscription_name)
            before_platform = get_platform(client, platform_id, platform_name)
            if args.command == "run" and (
                subscription_signature(before_sub) != subscription_signature(observed_sub)
                or observed_platform is None
                or platform_signature(before_platform) != platform_signature(observed_platform)
            ):
                raise SyncError("Resin state changed during validation; refusing stale overwrite")
            before_evicted_count = 0
            if before_sub is not None:
                _, before_evicted_count = subscription_node_state(before_sub)
            active_node_floor = minimum_active_node_count(config, previous)
            verify_timeout = float(resin.get("verify_timeout_seconds") or 120.0)
            verify_settle_reads = int(resin.get("verify_settle_reads") or 2)
            before_filters = list(before_platform.get("regex_filters") or [])
            before_regions = list(before_platform.get("region_filters") or [])
            configured_filters = resin.get("platform_regex_filters")
            preserve_existing_trusted = resin.get(
                "preserve_existing_trusted_filters",
                True,
            )
            if not isinstance(preserve_existing_trusted, bool):
                raise SyncError(
                    "resin.preserve_existing_trusted_filters must be a boolean"
                )
            if configured_filters is None:
                if not any(
                    _contains_managed_marker(item, managed_regex, subscription_name)
                    for item in before_filters
                ):
                    raise SyncError(
                        "resin.platform_regex_filters is required when adding a source; Resin regex filters use AND semantics"
                    )
                desired_filters = before_filters
            elif isinstance(configured_filters, list) and all(isinstance(item, str) for item in configured_filters):
                normalized_filters = list(dict.fromkeys(item.strip() for item in configured_filters if item.strip()))
                if not normalized_filters:
                    raise SyncError("resin.platform_regex_filters must not be empty")
                desired_filters = merge_platform_regex_filters(
                    before_filters,
                    normalized_filters,
                    managed_regex,
                    subscription_name,
                    preserve_existing_trusted=preserve_existing_trusted,
                )
            else:
                raise SyncError("resin.platform_regex_filters must be a string array")
            configured_regions = resin.get("region_filters")
            if configured_regions is None:
                desired_regions = before_regions
            elif isinstance(configured_regions, list) and all(isinstance(item, str) for item in configured_regions):
                desired_regions = list(dict.fromkeys(item.strip().lower() for item in configured_regions if item.strip()))
            else:
                raise SyncError("resin.region_filters must be a string array")
            existing_digest = ""
            if before_sub is not None:
                existing_digest = sha256_bytes(str(before_sub.get("content") or "").encode("utf-8"))
            desired_subscription_settings = subscription_patch_from_config(config, content)
            existing_settings_match = (
                before_sub is not None
                and subscription_matches_patch(before_sub, desired_subscription_settings)
            )
            if (
                existing_digest == content_digest
                and existing_settings_match
                and desired_filters == before_filters
                and desired_regions == before_regions
            ):
                if before_sub is None:
                    raise SyncError("no-change verification requires an existing subscription")
                verified_current = verify_subscription(
                    client,
                    str(before_sub.get("id") or ""),
                    content_digest,
                    expected_node_count,
                    allow_additional_nodes=bool(
                        before_sub.get("incremental_alive_nodes")
                    ),
                    max_evicted_nodes=before_evicted_count,
                    minimum_node_count=active_node_floor,
                    timeout=verify_timeout,
                    settle_reads=verify_settle_reads,
                )
                state = {
                    "owner": OWNER,
                    "version": STATE_VERSION,
                    "updated_at": utc_now(),
                    "selected_count": report["selected_count"],
                    "passed_count": report["passed_count"],
                    "content_sha256": content_digest,
                    "subscription_id": before_sub.get("id") if before_sub else "",
                    "node_count": int(verified_current.get("node_count") or 0),
                    "resin_node_count": expected_node_count,
                    "historical_evicted_allowance": before_evicted_count,
                    "run_id": manifest.get("run_id", maintenance_run_id()),
                }
                copy_bridge_correlation(state, manifest)
                write_json(state_dir / "state.json", state)
                manifest.update(
                    {
                        "status": "no_change",
                        "completed_at": utc_now(),
                        "node_count": state["node_count"],
                        "resin_node_count": expected_node_count,
                        "historical_evicted_allowance": before_evicted_count,
                    }
                )
                write_json(run_dir / "manifest.json", manifest)
                removed = prune_owned_runs(state_dir, retain_runs, run_dir)
                print(
                    json.dumps(
                        {
                            "status": "no_change",
                            **correlation_fields(manifest),
                            **manifest["validation"],
                            "pruned_runs": len(removed),
                        },
                        sort_keys=True,
                    )
                )
                return 0

            created_id: str | None = None
            create_attempted = False
            platform_patch_attempted = False
            state_committed = False
            try:
                patch = subscription_patch_from_config(config, content)
                if before_sub is None:
                    create_attempted = True
                    current_sub = create_subscription(client, config, content)
                    created_id = str(current_sub["id"])
                else:
                    current_sub = update_subscription(client, str(before_sub["id"]), patch)
                subscription_id = str(current_sub["id"])
                refresh_subscription(client, subscription_id)
                verified_sub = verify_subscription(
                    client,
                    subscription_id,
                    content_digest,
                    expected_node_count,
                    allow_additional_nodes=bool(
                        resin.get("incremental_alive_nodes", True)
                    ),
                    max_evicted_nodes=before_evicted_count,
                    minimum_node_count=active_node_floor,
                    timeout=verify_timeout,
                    settle_reads=verify_settle_reads,
                )

                if desired_filters != before_filters or desired_regions != before_regions:
                    platform_patch: dict[str, Any] = {}
                    if desired_filters != before_filters:
                        platform_patch["regex_filters"] = desired_filters
                    if desired_regions != before_regions:
                        platform_patch["region_filters"] = desired_regions
                    # A failed response can arrive after Resin committed the change.
                    # From this point onward rollback must restore the prior filters.
                    platform_patch_attempted = True
                    updated_platform = client.request(
                        "PATCH",
                        f"/api/v1/platforms/{urllib.parse.quote(platform_id, safe='')}",
                        platform_patch,
                    )
                    if (
                        not isinstance(updated_platform, dict)
                        or list(updated_platform.get("regex_filters") or []) != desired_filters
                        or list(updated_platform.get("region_filters") or []) != desired_regions
                    ):
                        raise SyncError("platform filter update verification failed")
                final_platform = get_platform(client, platform_id, platform_name)
                if list(final_platform.get("regex_filters") or []) != desired_filters:
                    raise SyncError("platform regex filters do not match the locked configuration")
                if list(final_platform.get("region_filters") or []) != desired_regions:
                    raise SyncError("platform region filters do not match the locked configuration")

                state = {
                    "owner": OWNER,
                    "version": STATE_VERSION,
                    "updated_at": utc_now(),
                    "selected_count": report["selected_count"],
                    "passed_count": report["passed_count"],
                    "content_sha256": content_digest,
                    "subscription_id": subscription_id,
                    "node_count": int(verified_sub.get("node_count") or 0),
                    "resin_node_count": expected_node_count,
                    "historical_evicted_allowance": before_evicted_count,
                    "platform_id": platform_id,
                    "run_id": manifest.get("run_id", maintenance_run_id()),
                }
                copy_bridge_correlation(state, manifest)
                manifest.update(
                    {
                        "status": "completed",
                        "completed_at": utc_now(),
                        "subscription_id": subscription_id,
                        "node_count": state["node_count"],
                        "resin_node_count": expected_node_count,
                        "historical_evicted_allowance": before_evicted_count,
                        "platform_filter_added": desired_filters != before_filters,
                        "platform_regions_changed": desired_regions != before_regions,
                    }
                )
                write_json(run_dir / "manifest.json", manifest)
                removed = prune_owned_runs(state_dir, retain_runs, run_dir)
                # Commit state only after all API verification and run cleanup
                # steps that can trigger rollback have succeeded.
                write_json(state_dir / "state.json", state)
                state_committed = True
                print(
                    json.dumps(
                        {
                            "status": "completed",
                            **correlation_fields(manifest),
                            **manifest["validation"],
                            "node_count": state["node_count"],
                            "platform_routable_node_count": int(final_platform.get("routable_node_count") or 0),
                            "pruned_runs": len(removed),
                        },
                        sort_keys=True,
                    )
                )
                return 0
            except Exception as exc:
                if state_committed:
                    # The API and state are committed; post-commit output errors
                    # must not roll back a successfully applied pool.
                    raise
                rollback: dict[str, Any] = {}
                if platform_patch_attempted:
                    try:
                        client.request(
                            "PATCH",
                            f"/api/v1/platforms/{urllib.parse.quote(platform_id, safe='')}",
                            {
                                "regex_filters": before_filters,
                                "region_filters": before_regions,
                            },
                        )
                        restored_platform = get_platform(client, platform_id, platform_name)
                        if platform_signature(restored_platform) != (
                            tuple(before_filters),
                            tuple(before_regions),
                        ):
                            raise SyncError("platform filter rollback verification failed")
                        rollback["platform_restored"] = True
                    except Exception as rollback_exc:
                        rollback["platform_restored"] = False
                        rollback["platform_error"] = safe_message(rollback_exc)
                rollback.update(
                    restore_subscription(
                        client,
                        config,
                        before_sub,
                        created_id,
                        create_attempted=create_attempted,
                    )
                )
                manifest.update(
                    {
                        "status": "rolled_back"
                        if all(
                            value is not False
                            for key, value in rollback.items()
                            if key.endswith("restored") or key == "created_subscription_removed"
                        )
                        else "rollback_incomplete",
                        "completed_at": utc_now(),
                        "error": safe_message(exc),
                        "rollback": rollback,
                    }
                )
                write_json(run_dir / "manifest.json", manifest)
                raise
        except Exception as exc:
            if manifest.get("status") == "running":
                manifest.update({"status": "failed_closed", "completed_at": utc_now(), "error": safe_message(exc)})
                write_json(run_dir / "manifest.json", manifest)
            raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="validate sources without changing Resin")
    validate.add_argument("--config", required=True)
    run_cmd = sub.add_parser("run", help="validate and sync through the Resin Admin API")
    run_cmd.add_argument("--config", required=True)
    run_cmd.add_argument("--admin-token-file", required=True)
    run_cmd.add_argument("--confirm-production-write", action="store_true")
    apply_cmd = sub.add_parser("apply", help="apply a fresh hash-locked validation run")
    apply_cmd.add_argument("--config", required=True)
    apply_cmd.add_argument("--validated-run", required=True)
    apply_cmd.add_argument("--admin-token-file", required=True)
    apply_cmd.add_argument("--confirm-production-write", action="store_true")
    reselect_cmd = sub.add_parser("reselect", help="reselect from a hash-locked validation report")
    reselect_cmd.add_argument("--config", required=True)
    reselect_cmd.add_argument("--validated-run", required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return run(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SyncError, ValueError, OSError) as exc:
        print(json.dumps({"status": "error", "error": safe_message(exc)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2)
