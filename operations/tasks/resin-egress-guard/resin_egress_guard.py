#!/usr/bin/env python3
"""Central Resin sticky-lease recovery daemon.

The daemon consumes Resin request-log metadata for every configured instance,
accepts authenticated transport/reputation feedback from downstream HTTP
clients, and optionally imports bounded Sub2API failure evidence. It only
reads, deletes, or atomically rotates the precise Resin Platform.Account lease. It never
replays the failed request and never calls a model, sign-in, check-in, or test
endpoint.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping, Sequence


STATE_VERSION = 1
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_FEEDBACK_BYTES = 16 * 1024
MAX_HANDLED_INCIDENTS = 8192
MAX_EVIDENCE_TIMESTAMPS = 16
MAX_FORWARD_PENDING_LINES = 2048
MAX_FORWARD_LINE_CHARS = 256 * 1024
MAX_FORWARD_DEAD_LETTERS = 256
DEFAULT_FORWARD_RETRY_MAX_ATTEMPTS = 8
DEFAULT_FORWARD_RETRY_TTL_SECONDS = 300
DEFAULT_FORWARD_RETRY_INITIAL_SECONDS = 1.0
DEFAULT_FORWARD_RETRY_MAX_SECONDS = 30.0
DEFAULT_LEASE_EVENT_CLOCK_SKEW_SECONDS = 2
ACCOUNT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
PRIVATE_RESIN_HOSTNAMES = {"proxy.internal"}
OAUTH_TRANSPORT_MARKERS = (
    ("oauth_eof", (": eof", "unexpected eof")),
    ("oauth_tls_timeout", ("tls handshake timeout",)),
    ("oauth_socks_failure", ("general socks server failure", "socks server failure")),
    ("oauth_timeout", ("context deadline exceeded", "i/o timeout", "connection timed out")),
    ("oauth_connection", ("connection refused", "connection reset by peer")),
)
OAUTH_AUTH_EXCLUDE_MARKERS = (
    "invalid_grant",
    "invalid_refresh_token",
    "refresh_token_reused",
    "refresh_token_invalidated",
    "app_session_terminated",
    "entitlement_denied",
    "grok_oauth_token_refresh_failed",
    "grok_oauth_entitlement",
)
SUB2_FORWARD_ERROR = "stream usage incomplete: missing terminal event"
BENIGN_ERROR_MARKERS = (
    "context canceled",
    "context_cancel",
    "operation canceled",
    "operation_cancel",
    "client canceled",
    "client_cancel",
)
AMBIGUOUS_COPY_MARKERS = (
    "copy",
    "eof",
    "closed_pipe",
    "connection_reset",
    "reset_by_peer",
    "broken_pipe",
)


class GuardError(RuntimeError):
    pass


@dataclass(frozen=True)
class PlatformConfig:
    id: str
    name: str


@dataclass(frozen=True)
class InstanceConfig:
    key: str
    base_url: str
    admin_token_credential: str
    platforms: tuple[PlatformConfig, ...]


@dataclass(frozen=True)
class Sub2Profile:
    key: str
    instance: str
    platform_id: str
    platform_name: str
    proxy_host: str
    proxy_port: int
    username_template: str
    proxy_id: int = 0
    proxy_name: str = ""
    target_host: str = ""

    def proxy_username_for(self, account_id: int) -> str:
        username = self.username_template.replace("{account_id}", str(account_id))
        # Historic configs store the Resin account suffix while Sub2API stores
        # the complete SOCKS username. Accept both forms, but always expose a
        # single canonical full username to identity checks.
        if "." not in username:
            username = self.platform_name + "." + username
        if not username.startswith(self.platform_name + "."):
            raise GuardError(f"invalid proxy username template for Sub2 profile {self.key}")
        account = username.split(".", 1)[1]
        if not ACCOUNT_RE.fullmatch(account):
            raise GuardError(f"invalid rendered account for Sub2 profile {self.key}")
        return username

    def account_for(self, account_id: int) -> str:
        return self.proxy_username_for(account_id).split(".", 1)[1]


@dataclass(frozen=True)
class Event:
    incident_id: str
    occurred_at: dt.datetime
    source: str
    instance: str
    platform_id: str
    platform_name: str
    account: str
    kind: str
    node_hash: str = ""
    target_host: str = ""
    http_status: int = 0
    ambiguous: bool = False
    rotate: bool = False


@dataclass(frozen=True)
class Sub2ForwardSignal:
    incident_id: str
    occurred_at: dt.datetime
    account_id: int
    request_id: str
    kind: str = "missing_terminal"
    http_status: int = 0


@dataclass(frozen=True)
class Limits:
    min_interval: dt.timedelta
    burst_window: dt.timedelta
    burst_max: int
    account_cooldown: dt.timedelta
    ambiguous_window: dt.timedelta
    ambiguous_threshold: int
    platform_guard_window: dt.timedelta
    platform_guard_account_limit: int
    platform_guard_cooldown: dt.timedelta


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def isoformat(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat()


def parse_timestamp(value: Any) -> dt.datetime | None:
    if value in (None, ""):
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def safe_error(exc: BaseException) -> str:
    if isinstance(exc, GuardError):
        return str(exc)
    return exc.__class__.__name__


def log_event(event: str, **fields: Any) -> None:
    payload = {"ts": isoformat(utc_now()), "event": event, **fields}
    print(json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True), flush=True)


def validate_private_base_url(raw: str) -> str:
    value = raw.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise GuardError("invalid Resin base URL")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        if parsed.hostname not in PRIVATE_RESIN_HOSTNAMES:
            raise GuardError("Resin base URL must use a private IP or approved internal hostname")
        port = int(parsed.port or (443 if parsed.scheme == "https" else 80))
        try:
            rows = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
            addresses = {
                ipaddress.ip_address(str(row[4][0]).split("%", 1)[0])
                for row in rows
            }
        except (OSError, ValueError) as exc:
            raise GuardError("approved Resin hostname did not resolve safely") from exc
        if not addresses or any(not (item.is_loopback or item.is_private) for item in addresses):
            raise GuardError("approved Resin hostname must resolve only to private or loopback IPs")
    else:
        if not (address.is_loopback or address.is_private):
            raise GuardError("Resin base URL must use a private or loopback IP")
    return value


def validate_listen_address(raw: str) -> str:
    try:
        address = ipaddress.ip_address(raw.strip())
    except ValueError as exc:
        raise GuardError("feedback listen address must be a literal IP") from exc
    if not (address.is_loopback or address.is_private):
        raise GuardError("feedback listener must use a private or loopback IP")
    return str(address)


def parse_feedback_listeners(feedback: Mapping[str, Any]) -> tuple[str, ...]:
    raw_addresses = feedback.get("listen_addresses")
    if raw_addresses is None:
        raw_addresses = [feedback.get("listen") or "127.0.0.1"]
    if not isinstance(raw_addresses, list) or not raw_addresses:
        raise GuardError("feedback listen_addresses must be a non-empty array")
    if len(raw_addresses) > 8:
        raise GuardError("feedback listen_addresses exceeds the limit")
    listeners: list[str] = []
    for raw in raw_addresses:
        listener = validate_listen_address(str(raw or ""))
        if listener in listeners:
            raise GuardError("feedback listen_addresses must be unique")
        listeners.append(listener)
    return tuple(listeners)


def credential_path(name: str) -> Path:
    if not name or Path(name).name != name:
        raise GuardError("credential name must be a basename")
    directory = os.environ.get("CREDENTIALS_DIRECTORY", "").strip()
    if not directory:
        raise GuardError("CREDENTIALS_DIRECTORY is required")
    return Path(directory) / name


def read_secret_credential(name: str) -> str:
    path = credential_path(name)
    if not path.is_file() or path.stat().st_mode & 0o077:
        raise GuardError(f"credential {name} must exist and be private")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise GuardError(f"credential {name} is empty")
    return value


def load_json_file(path: Path, *, private: bool = True) -> dict[str, Any]:
    if not path.is_file():
        raise GuardError(f"missing JSON file: {path}")
    if private and path.stat().st_mode & 0o077:
        raise GuardError(f"JSON file must be private: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GuardError(f"invalid JSON file: {path}") from exc
    if not isinstance(value, dict):
        raise GuardError(f"JSON root must be an object: {path}")
    return value


def atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}-{threading.get_ident()}")
    payload = (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def new_state() -> dict[str, Any]:
    return {
        "version": STATE_VERSION,
        "accounts": {},
        "handled": {},
        "poll": {},
        "platforms": {},
        "forward_pending": [],
        "forward_dead_letters": [],
        "forward_cursor": None,
        "rotation_intents": {},
    }


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return new_state()
    value = load_json_file(path)
    if value.get("version") != STATE_VERSION:
        raise GuardError("state version mismatch")
    for key in ("accounts", "handled", "poll", "platforms"):
        if not isinstance(value.get(key), dict):
            raise GuardError("state schema is invalid")
    if not isinstance(value.setdefault("rotation_intents", {}), dict):
        raise GuardError("state rotation_intents is invalid")
    value.setdefault("forward_cursor", None)
    pending = value.setdefault("forward_pending", [])
    if not isinstance(pending, list):
        raise GuardError("state schema is invalid")
    now = utc_now()
    normalized: list[dict[str, Any]] = []
    migrated = 0
    for item in pending:
        if isinstance(item, str):
            line = item
            first_seen = now
            retry_count = 0
            next_attempt = now
            migrated += 1
        elif isinstance(item, Mapping):
            line = str(item.get("line") or "")
            first_seen = parse_timestamp(item.get("first_seen"))
            retry_count = as_int(item.get("retry_count"))
            next_attempt = parse_timestamp(item.get("next_attempt"))
            if first_seen is None or retry_count is None or retry_count < 0 or next_attempt is None:
                raise GuardError("state forward_pending entry is invalid")
        else:
            raise GuardError("state forward_pending entry is invalid")
        if not line or len(line) > MAX_FORWARD_LINE_CHARS:
            raise GuardError("state forward_pending line is invalid")
        normalized.append({
            "line": line,
            "first_seen": isoformat(first_seen),
            "retry_count": retry_count,
            "next_attempt": isoformat(next_attempt),
        })
    if len(normalized) > MAX_FORWARD_PENDING_LINES:
        discarded = len(normalized) - MAX_FORWARD_PENDING_LINES
        normalized = normalized[-MAX_FORWARD_PENDING_LINES:]
        log_event("forward_pending_truncated", discarded=discarded, reason="state_load_capacity")
    if migrated:
        log_event("forward_pending_migrated", count=migrated)
    value["forward_pending"] = normalized
    dead_letters = value.setdefault("forward_dead_letters", [])
    if not isinstance(dead_letters, list) or any(not isinstance(item, Mapping) for item in dead_letters):
        raise GuardError("state forward_dead_letters is invalid")
    if len(dead_letters) > MAX_FORWARD_DEAD_LETTERS:
        discarded = len(dead_letters) - MAX_FORWARD_DEAD_LETTERS
        value["forward_dead_letters"] = dead_letters[-MAX_FORWARD_DEAD_LETTERS:]
        log_event("forward_dead_letters_truncated", discarded=discarded, reason="state_load_capacity")
    return value


class ResinClient:
    def __init__(self, config: InstanceConfig, token: str, timeout: float) -> None:
        self.config = config
        self.base_url = validate_private_base_url(config.base_url)
        self.timeout = timeout
        self.headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "resin-egress-guard/1",
        }
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _request(self, method: str, path: str, payload: Mapping[str, Any] | None = None) -> tuple[int, bytes]:
        body = None
        headers = dict(self.headers)
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path,
            data=body,
            headers=headers,
            method=method.upper(),
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return int(response.status), response.read(MAX_RESPONSE_BYTES)
        except urllib.error.HTTPError as exc:
            return int(exc.code or 0), exc.read(MAX_RESPONSE_BYTES)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise GuardError(f"Resin API unavailable for {self.config.key}") from exc

    def _json(self, method: str, path: str, expected: set[int]) -> Any:
        status, raw = self._request(method, path)
        if status not in expected:
            raise GuardError(f"Resin {self.config.key} {method} failed with HTTP {status}")
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GuardError(f"Resin {self.config.key} returned invalid JSON") from exc

    @staticmethod
    def _error_message(row: Any) -> str:
        if not isinstance(row, Mapping):
            return ""
        error = row.get("error")
        if isinstance(error, Mapping):
            return str(error.get("message") or "").strip().lower()
        return " ".join(
            str(row.get(key) or "") for key in ("error", "message", "detail", "reason")
        ).strip().lower()

    def verify(self) -> dict[str, Any]:
        info = self._json("GET", "/api/v1/system/info", {200})
        runtime = self._json("GET", "/api/v1/system/config", {200})
        if not isinstance(info, dict) or not isinstance(runtime, dict):
            raise GuardError(f"Resin {self.config.key} system response is invalid")
        for platform in self.config.platforms:
            row = self._json(
                "GET",
                f"/api/v1/platforms/{urllib.parse.quote(platform.id, safe='')}",
                {200},
            )
            if not isinstance(row, dict) or row.get("id") != platform.id or row.get("name") != platform.name:
                raise GuardError(f"Resin {self.config.key} platform identity mismatch")
        return {
            "version": str(info.get("version") or ""),
            "git_commit": str(info.get("git_commit") or ""),
            "request_log_enabled": bool(runtime.get("request_log_enabled")),
        }

    def list_logs(self, after: dt.datetime, max_pages: int, page_limit: int) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        # Separate queries keep busy, unrelated platforms from exhausting our
        # pagination budget. The API accepts one exact platform ID per query.
        for platform in self.config.platforms:
            cursor = ""
            for _ in range(max_pages):
                query: dict[str, str | int] = {
                    "from": isoformat(after),
                    "net_ok": "false",
                    "platform_id": platform.id,
                    "limit": page_limit,
                }
                if cursor:
                    query["cursor"] = cursor
                payload = self._json(
                    "GET",
                    "/api/v1/request-logs?" + urllib.parse.urlencode(query),
                    {200},
                )
                if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
                    raise GuardError(f"Resin {self.config.key} request-log response is invalid")
                rows.extend(row for row in payload["items"] if isinstance(row, dict))
                if not payload.get("has_more"):
                    break
                cursor = str(payload.get("next_cursor") or "")
                if not cursor:
                    raise GuardError(f"Resin {self.config.key} request-log cursor is missing")
            else:
                raise GuardError(f"Resin {self.config.key} request-log page limit exceeded")
        return rows

    def get_lease(self, platform_id: str, account: str) -> dict[str, Any] | None:
        path = "/api/v1/platforms/{}/leases/{}".format(
            urllib.parse.quote(platform_id, safe=""),
            urllib.parse.quote(account, safe=""),
        )
        status, raw = self._request("GET", path)
        if status == 404:
            if not self.platform_exists(platform_id):
                raise GuardError(f"Resin {self.config.key} platform not found")
            return None
        if status != 200:
            raise GuardError(f"Resin {self.config.key} lease lookup failed with HTTP {status}")
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GuardError(f"Resin {self.config.key} lease response is invalid") from exc
        if not isinstance(row, dict) or row.get("platform_id") != platform_id or row.get("account") != account:
            raise GuardError(f"Resin {self.config.key} lease identity mismatch")
        return row

    def platform_exists(self, platform_id: str) -> bool:
        path = f"/api/v1/platforms/{urllib.parse.quote(platform_id, safe='')}"
        status, raw = self._request("GET", path)
        if status == 404:
            return False
        if status != 200:
            raise GuardError(f"Resin {self.config.key} platform lookup failed with HTTP {status}")
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GuardError(f"Resin {self.config.key} platform response is invalid") from exc
        if not isinstance(row, Mapping) or row.get("id") != platform_id:
            raise GuardError(f"Resin {self.config.key} platform identity mismatch")
        return True

    def _classify_missing_lease(self, platform_id: str) -> str:
        return "lease_absent" if self.platform_exists(platform_id) else "platform_not_found"

    def delete_lease(self, platform_id: str, account: str) -> str:
        path = "/api/v1/platforms/{}/leases/{}".format(
            urllib.parse.quote(platform_id, safe=""),
            urllib.parse.quote(account, safe=""),
        )
        status, raw = self._request("DELETE", path)
        if status == 204:
            return "deleted"
        if status == 404:
            try:
                row = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                row = {}
            message = self._error_message(row)
            if "platform not found" in message:
                return "platform_not_found"
            if "lease not found" in message:
                return "lease_absent"
            return self._classify_missing_lease(platform_id)
        raise GuardError(f"Resin {self.config.key} lease delete failed with HTTP {status}")

    def rotate_lease(
        self,
        platform_id: str,
        account: str,
        *,
        expected_node_hash: str,
        expected_egress_ip: str,
        expected_created_at_ns: str,
        target_host: str,
        preserve_connections: bool = False,
    ) -> str:
        path = "/api/v1/platforms/{}/leases/{}/rotate".format(
            urllib.parse.quote(platform_id, safe=""),
            urllib.parse.quote(account, safe=""),
        )
        payload = {
            "expected_node_hash": expected_node_hash,
            "expected_created_at_ns": expected_created_at_ns,
            "target_host": target_host,
            "exclude_egress_ip": True,
        }
        if preserve_connections:
            payload["preserve_connections"] = True
        status, raw = self._request("POST", path, payload)
        try:
            row = json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            raise GuardError(f"Resin {self.config.key} rotate response is invalid") from exc
        result = str(row.get("status") or "") if isinstance(row, Mapping) else ""
        if status == 200 and result == "rotated":
            if preserve_connections and (
                type(row.get("closed_connections")) is not int or row["closed_connections"] != 0
            ):
                raise GuardError(f"Resin {self.config.key} did not confirm connection-preserving rotation")
            replacement = row.get("lease") if isinstance(row, Mapping) else None
            if not isinstance(replacement, Mapping):
                raise GuardError(f"Resin {self.config.key} rotate response is missing the replacement lease")
            replacement_hash = str(replacement.get("node_hash") or "").strip()
            replacement_ip = str(replacement.get("egress_ip") or "").strip()
            if not replacement_hash or replacement_hash == expected_node_hash:
                raise GuardError(f"Resin {self.config.key} rotate did not change the node")
            if not expected_egress_ip or not replacement_ip or replacement_ip == expected_egress_ip:
                raise GuardError(f"Resin {self.config.key} rotate did not change the egress IP")
            replacement_created = as_int(replacement.get("created_at_ns"))
            expected_created = as_int(expected_created_at_ns)
            if (
                replacement.get("platform_id") != platform_id
                or replacement.get("account") != account
                or replacement_created is None
                or expected_created is None
                or replacement_created <= expected_created
            ):
                raise GuardError(f"Resin {self.config.key} rotate replacement identity is invalid")
            persisted = self.get_lease(platform_id, account)
            if persisted is None:
                raise GuardError(f"Resin {self.config.key} rotated lease was not persisted")
            if (
                persisted.get("platform_id") != platform_id
                or persisted.get("account") != account
                or str(persisted.get("node_hash") or "").strip() != replacement_hash
                or str(persisted.get("egress_ip") or "").strip() != replacement_ip
                or as_int(persisted.get("created_at_ns")) != replacement_created
            ):
                raise GuardError(f"Resin {self.config.key} persisted rotated lease does not match the response")
            return "rotated"
        if status == 409 and result == "stale_lease":
            return "stale_lease"
        if status in {200, 422} and result == "no_alternative":
            return "no_alternative"
        if status == 404:
            message = self._error_message(row)
            if "platform not found" in message:
                return "platform_not_found"
            if "lease not found" in message:
                return "lease_absent"
            return self._classify_missing_lease(platform_id)
        if status == 400:
            if preserve_connections:
                # Older Resin rejects this unknown field before mutating the lease.
                # Never retry without it: that would abort unrelated in-flight requests.
                raise GuardError(f"Resin {self.config.key} connection-preserving rotation unavailable (HTTP 400)")
            return "invalid_request"
        if status >= 500:
            raise GuardError(f"Resin {self.config.key} lease rotate temporarily failed with HTTP {status}")
        raise GuardError(f"Resin {self.config.key} lease rotate failed with HTTP {status}")


def parse_config(raw: Mapping[str, Any]) -> tuple[dict[str, Any], tuple[InstanceConfig, ...], Limits]:
    if raw.get("version") != 1:
        raise GuardError("unsupported config version")
    instances_raw = raw.get("instances")
    if not isinstance(instances_raw, list) or not instances_raw:
        raise GuardError("instances must be a non-empty array")
    instances: list[InstanceConfig] = []
    seen_keys: set[str] = set()
    seen_endpoints: set[tuple[str, int]] = set()
    for item in instances_raw:
        if not isinstance(item, Mapping):
            raise GuardError("instance entry must be an object")
        key = str(item.get("key") or "").strip()
        if not key or key in seen_keys:
            raise GuardError("instance keys must be unique")
        base_url = validate_private_base_url(str(item.get("base_url") or ""))
        parsed = urllib.parse.urlsplit(base_url)
        endpoint = (str(parsed.hostname), int(parsed.port or (443 if parsed.scheme == "https" else 80)))
        if endpoint in seen_endpoints:
            raise GuardError("instance endpoints must be unique")
        platform_rows = item.get("platforms")
        if not isinstance(platform_rows, list) or not platform_rows:
            raise GuardError(f"instance {key} requires platforms")
        platforms: list[PlatformConfig] = []
        for platform in platform_rows:
            if not isinstance(platform, Mapping):
                raise GuardError("platform entry must be an object")
            platform_id = str(platform.get("id") or "").strip()
            platform_name = str(platform.get("name") or "").strip()
            try:
                uuid.UUID(platform_id)
            except ValueError as exc:
                raise GuardError(f"instance {key} has invalid platform UUID") from exc
            if not platform_name:
                raise GuardError(f"instance {key} has empty platform name")
            platforms.append(PlatformConfig(platform_id, platform_name))
        instances.append(
            InstanceConfig(
                key=key,
                base_url=base_url,
                admin_token_credential=str(item.get("admin_token_credential") or "").strip(),
                platforms=tuple(platforms),
            )
        )
        seen_keys.add(key)
        seen_endpoints.add(endpoint)
    limits_raw = raw.get("limits") or {}
    if not isinstance(limits_raw, Mapping):
        raise GuardError("limits must be an object")
    limits = Limits(
        min_interval=dt.timedelta(seconds=max(1, int(limits_raw.get("min_interval_seconds", 30)))),
        burst_window=dt.timedelta(seconds=max(1, int(limits_raw.get("burst_window_seconds", 900)))),
        burst_max=max(1, int(limits_raw.get("burst_max", 3))),
        account_cooldown=dt.timedelta(seconds=max(1, int(limits_raw.get("account_cooldown_seconds", 3600)))),
        ambiguous_window=dt.timedelta(seconds=max(1, int(limits_raw.get("ambiguous_window_seconds", 60)))),
        ambiguous_threshold=max(1, int(limits_raw.get("ambiguous_threshold", 2))),
        platform_guard_window=dt.timedelta(seconds=max(1, int(limits_raw.get("platform_guard_window_seconds", 60)))),
        platform_guard_account_limit=max(1, int(limits_raw.get("platform_guard_account_limit", 20))),
        platform_guard_cooldown=dt.timedelta(seconds=max(1, int(limits_raw.get("platform_guard_cooldown_seconds", 300)))),
    )
    return dict(raw), tuple(instances), limits


def read_log_tail(path: Path, max_bytes: int) -> list[str]:
    if not path.is_absolute() or not path.is_file():
        raise GuardError("Sub2API log must be an existing absolute file")
    try:
        size = path.stat().st_size
        offset = max(0, size - max_bytes)
        with path.open("rb") as handle:
            handle.seek(offset)
            if offset:
                handle.readline()
            return handle.read(max_bytes).decode("utf-8", "replace").splitlines()
    except OSError as exc:
        raise GuardError("Sub2API log is not readable") from exc


class Sub2LogTail:
    """Incrementally follows one active log and drains a renamed file first."""

    def __init__(self, path: Path, max_read_bytes: int = 2 * 1024 * 1024,
                 checkpoint: Mapping[str, Any] | None = None) -> None:
        if not path.is_absolute():
            raise GuardError("Sub2API log must be an absolute path")
        self.path = path
        self.max_read_bytes = max(1024, max_read_bytes)
        self.handle: Any = None
        self.identity: tuple[int, int] | None = None
        self.buffer = b""
        self.started = False
        self.discard_line = False
        self.checkpoint = checkpoint
        self.last_anchor = ""

    def _open(self, *, at_end: bool, path: Path | None = None) -> bool:
        path = path or self.path
        try:
            handle = path.open("rb")
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise GuardError("Sub2API log is not readable") from exc
        stat = os.fstat(handle.fileno())
        if not path.is_file() or not os.path.samestat(stat, path.stat()):
            handle.close()
            raise GuardError("Sub2API log is not a regular file")
        if at_end:
            handle.seek(0, os.SEEK_END)
            if handle.tell():
                self.discard_line = os.pread(handle.fileno(), 1, handle.tell() - 1) != b"\n"
        self.handle = handle
        self.identity = (stat.st_dev, stat.st_ino)
        return True

    def _anchor(self, offset: int) -> str:
        return hashlib.sha256(os.pread(self.handle.fileno(), min(64, offset), max(0, offset - 64))).hexdigest()

    def snapshot(self) -> dict[str, Any] | None:
        if self.handle is None or self.identity is None:
            return {"path": str(self.path), "missing": True} if self.started else None
        # Re-read an incomplete line after restart; never persist its raw bytes.
        offset = self.handle.tell() - len(self.buffer)
        return {"path": str(self.path), "device": self.identity[0], "inode": self.identity[1],
                "offset": offset, "anchor": self._anchor(offset), "discard_line": self.discard_line}

    def restore(self, checkpoint: Mapping[str, Any] | None) -> None:
        self.close()
        if checkpoint is None:
            self.started = True
            return
        self.checkpoint = checkpoint
        self.start()

    def start(self) -> None:
        if not self.started:
            checkpoint = self.checkpoint
            if checkpoint is None:
                self._open(at_end=True)
            elif (isinstance(checkpoint, Mapping) and checkpoint.get("path") == str(self.path)
                  and checkpoint.get("missing") is True):
                self._open(at_end=False)
            else:
                if (not isinstance(checkpoint, Mapping) or checkpoint.get("path") != str(self.path)
                        or any(type(checkpoint.get(key)) is not int or checkpoint[key] < 0
                               for key in ("device", "inode", "offset"))
                        or not re.fullmatch(r"[0-9a-f]{64}", str(checkpoint.get("anchor") or ""))):
                    raise GuardError("Sub2API log checkpoint is invalid")
                candidates = [self.path]
                candidates.extend(sorted(self.path.parent.glob(self.path.stem + "*"))[:256])
                for candidate in dict.fromkeys(candidates):
                    try:
                        stat = candidate.stat()
                    except FileNotFoundError:
                        continue
                    if (stat.st_dev, stat.st_ino) != (checkpoint["device"], checkpoint["inode"]):
                        continue
                    if self._open(at_end=False, path=candidate):
                        offset = checkpoint["offset"]
                        if stat.st_size >= offset and self._anchor(offset) == checkpoint["anchor"]:
                            self.handle.seek(offset)
                            self.discard_line = bool(checkpoint.get("discard_line"))
                        else:
                            log_event("forward_cursor_reset", reason="truncated")
                        break
                if self.handle is None:
                    log_event("forward_cursor_reset", reason="rotated_file_unavailable")
                    self._open(at_end=False)
            self.started = True
            if self.handle is not None:
                self.last_anchor = self._anchor(self.handle.tell())

    def close(self) -> None:
        if self.handle is not None:
            self.handle.close()
        self.handle = None
        self.identity = None
        self.buffer = b""
        self.started = False
        self.discard_line = False
        self.last_anchor = ""

    def _current_identity(self) -> tuple[int, int] | None:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise GuardError("Sub2API log is not readable") from exc
        return stat.st_dev, stat.st_ino

    def _read_available(self, budget: int) -> tuple[bytes, int]:
        chunks: list[bytes] = []
        remaining = max(0, budget)
        while remaining > 0:
            chunk = self.handle.read(min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks), remaining

    def _consume(self, raw: bytes) -> list[str]:
        if self.discard_line:
            _, newline, raw = raw.partition(b"\n")
            if not newline:
                return []
            self.discard_line = False
        parts = (self.buffer + raw).split(b"\n")
        self.buffer = parts.pop()
        oversized = sum(len(part) > MAX_FORWARD_LINE_CHARS for part in parts)
        if len(self.buffer) > MAX_FORWARD_LINE_CHARS:
            self.buffer = b""
            self.discard_line = True
            oversized += 1
        if oversized:
            log_event("forward_oversized_lines_discarded", count=oversized)
        return [part.rstrip(b"\r").decode("utf-8", "replace") for part in parts
                if len(part) <= MAX_FORWARD_LINE_CHARS]

    def poll(self) -> list[str]:
        if not self.started:
            self.start()
            return []
        if self.handle is None:
            # A file created after startup contains only new data.
            if not self._open(at_end=False):
                return []
        offset = self.handle.tell()
        if offset > os.fstat(self.handle.fileno()).st_size or (
                self.last_anchor and self._anchor(offset) != self.last_anchor):
            self.handle.seek(0)
            self.buffer = b""
            self.discard_line = False
            log_event("forward_cursor_reset", reason="copytruncate")
        raw, budget = self._read_available(self.max_read_bytes)
        lines = self._consume(raw)
        current = self._current_identity()
        if current is not None and current != self.identity:
            # A rename can still receive final bytes. Drain the old descriptor,
            # then continue from the beginning of the replacement file.
            tail, budget = self._read_available(budget)
            lines.extend(self._consume(tail))
            if budget > 0 and not tail:
                self.handle.close()
                self.handle = None
                self.identity = None
                self.buffer = b""
                self.discard_line = False
                self._open(at_end=False)
                if self.handle is not None:
                    replacement, budget = self._read_available(budget)
                    lines.extend(self._consume(replacement))
        if self.handle is not None:
            self.last_anchor = self._anchor(self.handle.tell())
        return lines

def parse_sub2_profiles(raw: Mapping[str, Any]) -> tuple[Sub2Profile, ...]:
    rows = raw.get("profiles") or []
    if not isinstance(rows, list):
        raise GuardError("sub2api_log.profiles must be an array")
    result: list[Sub2Profile] = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise GuardError("Sub2 profile must be an object")
        result.append(
            Sub2Profile(
                key=str(row.get("key") or "").strip(),
                instance=str(row.get("instance") or "").strip(),
                platform_id=str(row.get("platform_id") or "").strip(),
                platform_name=str(row.get("platform_name") or "").strip(),
                proxy_host=str(row.get("proxy_host") or "").strip(),
                proxy_port=int(row.get("proxy_port") or 0),
                username_template=str(row.get("username_template") or "").strip(),
                proxy_id=int(row.get("proxy_id") or 0),
                proxy_name=str(row.get("proxy_name") or "").strip(),
                target_host=str(row.get("target_host") or "").strip(),
            )
        )
    return tuple(result)


def resolve_sub2_profile(payload: Mapping[str, Any], profiles: Sequence[Sub2Profile]) -> Sub2Profile | None:
    host = str(payload.get("proxy_host") or "").strip()
    port = as_int(payload.get("proxy_port"))
    name = str(payload.get("proxy_name") or "").strip().lower()
    matches: list[Sub2Profile] = []
    for profile in profiles:
        if host and host != profile.proxy_host:
            continue
        if port is not None and port != profile.proxy_port:
            continue
        if name and profile.key.lower() not in name and profile.platform_name.lower() not in name:
            continue
        matches.append(profile)
    return matches[0] if len(matches) == 1 else None


def parse_sub2_line(
    line: str,
    profiles: Sequence[Sub2Profile],
    now: dt.datetime,
    window: dt.timedelta,
) -> Event | None:
    prefix, separator, raw_payload = line.rpartition("\t")
    if not separator:
        return None
    event_prefix, separator, event_name = prefix.rpartition("\t")
    if not separator:
        return None
    timestamp_text = event_prefix.split("\t", 1)[0]
    occurred_at = parse_timestamp(timestamp_text)
    if occurred_at is None or occurred_at < now - window or occurred_at > now + dt.timedelta(minutes=2):
        return None
    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, Mapping):
        return None
    account_id = as_int(payload.get("account_id"))
    if account_id is None or account_id < 1:
        return None
    if event_name != "token_refresh.retry_exhausted":
        return None
    if str(payload.get("platform") or "").lower() != "grok":
        return None
    error_text = str(payload.get("error") or "")
    normalized = error_text.lower()
    if any(marker in normalized for marker in OAUTH_AUTH_EXCLUDE_MARKERS):
        return None
    if "grok_oauth_request_failed" not in normalized or "auth.x.ai/oauth2/token" not in normalized:
        return None
    kind = next(
        (name for name, markers in OAUTH_TRANSPORT_MARKERS if any(marker in normalized for marker in markers)),
        "",
    )
    if not kind:
        return None
    profile = next((item for item in profiles if item.key == "global"), None)
    if profile is None:
        return None
    account = profile.account_for(account_id)
    return Event(
        incident_id=f"sub2:oauth:{timestamp_text}:{account_id}:{kind}",
        occurred_at=occurred_at,
        source="sub2api_log",
        instance=profile.instance,
        platform_id=profile.platform_id,
        platform_name=profile.platform_name,
        account=account,
        kind=kind,
        target_host="auth.x.ai",
    )


def parse_sub2_forward_failed_line(
    line: str,
    now: dt.datetime,
    window: dt.timedelta,
) -> Sub2ForwardSignal | None:
    parts = line.split("\t", 4)
    if len(parts) != 5 or parts[3] != "openai.forward_failed":
        return None
    occurred_at = parse_timestamp(parts[0])
    if occurred_at is None or occurred_at < now - window or occurred_at > now + dt.timedelta(minutes=2):
        return None
    try:
        payload = json.loads(parts[4])
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, Mapping):
        return None
    # HTTP origin timeouts are not evidence that the proxy's egress failed.
    if as_int(payload.get("upstream_status")) == 524:
        return None
    if payload.get("stream") is not True or str(payload.get("error") or "") != SUB2_FORWARD_ERROR:
        return None
    account_id = as_int(payload.get("account_id"))
    request_id = str(payload.get("client_request_id") or payload.get("request_id") or "").strip()
    if account_id is None or account_id < 1 or not request_id or len(request_id) > 256:
        return None
    return Sub2ForwardSignal(
        incident_id=f"sub2:forward:{account_id}:{request_id}",
        occurred_at=occurred_at,
        account_id=account_id,
        request_id=request_id,
    )


def validate_sub2_admin_base_url(raw: str) -> str:
    value = raw.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise GuardError("Sub2API admin base URL must be an HTTP(S) loopback origin")
    return value


class Sub2AdminClient:
    def __init__(self, base_url: str, admin_key: str, timeout: float) -> None:
        self.base_url = validate_sub2_admin_base_url(base_url)
        self.timeout = timeout
        self.headers = {
            "Accept": "application/json",
            "x-api-key": admin_key,
            "User-Agent": "resin-egress-guard/1",
        }
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def get_account(self, account_id: int) -> dict[str, Any]:
        path = f"/api/v1/admin/accounts/{account_id}"
        request = urllib.request.Request(self.base_url + path, headers=self.headers, method="GET")
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                status = int(response.status)
                raw = response.read(MAX_RESPONSE_BYTES)
        except urllib.error.HTTPError as exc:
            status = int(exc.code or 0)
            raw = exc.read(MAX_RESPONSE_BYTES)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise GuardError("Sub2API admin API unavailable") from exc
        if status != 200:
            raise GuardError(f"Sub2API account lookup failed with HTTP {status}")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GuardError("Sub2API account lookup returned invalid JSON") from exc
        if not isinstance(payload, Mapping) or payload.get("code") not in (None, 0, "0"):
            raise GuardError("Sub2API account lookup was rejected")
        account = payload.get("data", payload)
        if not isinstance(account, Mapping) or as_int(account.get("id")) != account_id:
            raise GuardError("Sub2API account lookup identity mismatch")
        return dict(account)

    def verify_account_access(self, account_id: int) -> dict[str, Any]:
        account = self.get_account(account_id)
        return {"account_id": as_int(account.get("id"))}


def sub2_profile_for_account(account: Mapping[str, Any], profiles: Sequence[Sub2Profile]) -> Sub2Profile | None:
    proxy = account.get("proxy")
    if not isinstance(proxy, Mapping):
        return None
    proxy_id = as_int(proxy.get("id")) or as_int(account.get("proxy_id")) or 0
    host = str(proxy.get("host") or "").strip()
    port = as_int(proxy.get("port")) or 0
    name = str(proxy.get("name") or "").strip()
    matches = [
        profile for profile in profiles
        if profile.proxy_id > 0 and proxy_id == profile.proxy_id
        and host == profile.proxy_host and port == profile.proxy_port
        and (not profile.proxy_name or name == profile.proxy_name)
    ]
    return matches[0] if len(matches) == 1 else None


def resolve_sub2_forward_signal(
    signal: Sub2ForwardSignal,
    admin: Sub2AdminClient,
    profiles: Sequence[Sub2Profile],
) -> Event | None:
    if signal.kind != "missing_terminal" or signal.http_status:
        return None
    source = admin.get_account(signal.account_id)
    parent_id = as_int(source.get("parent_account_id"))
    identity_id = parent_id if parent_id is not None and parent_id > 0 else signal.account_id
    identity = admin.get_account(identity_id) if identity_id != signal.account_id else source
    source_profile = sub2_profile_for_account(source, profiles)
    profile = sub2_profile_for_account(identity, profiles)
    if profile is None or source_profile != profile:
        return None
    proxy = identity.get("proxy")
    if not isinstance(proxy, Mapping) or str(proxy.get("status") or "") != "active":
        return None
    expected_account = profile.account_for(identity_id)
    expected_proxy_username = profile.proxy_username_for(identity_id)
    if str(proxy.get("username") or "").strip() != expected_proxy_username:
        return None
    if identity_id != signal.account_id:
        source_proxy = source.get("proxy")
        if not isinstance(source_proxy, Mapping) or str(source_proxy.get("username") or "").strip() != expected_proxy_username:
            return None
    proxy_updated_at = parse_timestamp(proxy.get("updated_at"))
    if proxy_updated_at is not None and proxy_updated_at > signal.occurred_at:
        return None
    target_host = profile.target_host
    return Event(
        incident_id=signal.incident_id,
        occurred_at=signal.occurred_at,
        source="sub2api_forward",
        instance=profile.instance,
        platform_id=profile.platform_id,
        platform_name=profile.platform_name,
        account=expected_account,
        kind=signal.kind,
        target_host=target_host,
        http_status=signal.http_status,
        rotate=True,
    )


def request_log_event(instance: str, row: Mapping[str, Any]) -> Event | None:
    if row.get("net_ok") is not False:
        return None
    incident = str(row.get("id") or "").strip()
    occurred_at = parse_timestamp(row.get("ts"))
    platform_id = str(row.get("platform_id") or "").strip()
    platform_name = str(row.get("platform_name") or "").strip()
    account = str(row.get("account") or "").strip()
    node_hash = str(row.get("node_hash") or "").strip()
    if not incident or occurred_at is None or not platform_id or not platform_name or not account or not node_hash:
        return None
    combined = " ".join(
        str(row.get(key) or "").lower()
        for key in ("resin_error", "upstream_stage", "upstream_err_kind", "upstream_errno", "upstream_err_msg")
    )
    if any(marker in combined for marker in BENIGN_ERROR_MARKERS):
        return None
    ambiguous = any(marker in combined for marker in AMBIGUOUS_COPY_MARKERS)
    kind = str(row.get("resin_error") or row.get("upstream_err_kind") or "resin_transport").strip().lower()
    return Event(
        incident_id=f"resin:{instance}:{incident}",
        occurred_at=occurred_at,
        source="resin_request_log",
        instance=instance,
        platform_id=platform_id,
        platform_name=platform_name,
        account=account,
        kind=kind or "resin_transport",
        node_hash=node_hash,
        target_host=str(row.get("target_host") or "").strip(),
        http_status=as_int(row.get("http_status")) or 0,
        ambiguous=ambiguous,
    )


class Guard:
    def __init__(self, config: Mapping[str, Any], instances: Sequence[InstanceConfig], limits: Limits) -> None:
        self.config = dict(config)
        self.instances = {item.key: item for item in instances}
        timeout = float(self.config.get("api_timeout_seconds", 10))
        self.clients = {
            item.key: ResinClient(item, read_secret_credential(item.admin_token_credential), timeout)
            for item in instances
        }
        self.platforms: dict[tuple[str, str], PlatformConfig] = {}
        self.platform_names: dict[tuple[str, str], PlatformConfig] = {}
        self.endpoints: dict[tuple[str, int], str] = {}
        for item in instances:
            parsed = urllib.parse.urlsplit(item.base_url)
            default_port = 443 if parsed.scheme == "https" else 80
            self.endpoints[(str(parsed.hostname), int(parsed.port or default_port))] = item.key
            for platform in item.platforms:
                self.platforms[(item.key, platform.id)] = platform
                self.platform_names[(item.key, platform.name)] = platform
        self.limits = limits
        self.state_path = Path(str(self.config.get("state_file") or "/var/lib/server-scheduled-tasks/resin-egress-guard/state.json"))
        self.state = load_state(self.state_path)
        self.state_lock = threading.RLock()
        self.account_locks = tuple(threading.Lock() for _ in range(64))
        self.active_accounts: dict[str, set[str]] = {}
        self.confirm_write = False
        self.persist_state = True
        self.stop_event = threading.Event()
        self.sub2_config = self.config.get("sub2api_log") or {}
        self.sub2_profiles = parse_sub2_profiles(self.sub2_config) if isinstance(self.sub2_config, Mapping) else ()
        self.last_sub2_poll_monotonic = 0.0
        self.last_resin_poll_monotonic = 0.0
        self.sub2_forward_tail: Sub2LogTail | None = None
        self.sub2_admin: Sub2AdminClient | None = None
        if isinstance(self.sub2_config, Mapping):
            forward = self.sub2_config.get("forward_failed") or {}
            admin = self.sub2_config.get("admin") or {}
            if isinstance(forward, Mapping) and forward.get("enabled"):
                path = Path(str(self.sub2_config.get("path") or ""))
                self.sub2_forward_tail = Sub2LogTail(path, checkpoint=self.state.get("forward_cursor"))
                if not isinstance(admin, Mapping):
                    raise GuardError("sub2api_log.admin must be an object")
                self.sub2_admin = Sub2AdminClient(
                    str(admin.get("base_url") or ""),
                    read_secret_credential(str(admin.get("credential") or "")),
                    float(admin.get("timeout_seconds") or 3),
                )

    def verify(self, *, require_request_logs: bool) -> list[dict[str, Any]]:
        if self.sub2_forward_tail is not None:
            if self.sub2_admin is None:
                raise GuardError("Sub2API forward recovery requires the admin client")
            if not self.sub2_profiles or any(
                item.proxy_id <= 0 or not item.proxy_name or not item.target_host
                for item in self.sub2_profiles
            ):
                raise GuardError("Sub2API forward recovery profiles require proxy_id, proxy_name and target_host")
            for profile in self.sub2_profiles:
                if (
                    len(profile.target_host) > 253
                    or any(char in profile.target_host for char in "/\\?#@ \t\r\n")
                    or profile.username_template.count("{account_id}") != 1
                ):
                    raise GuardError(f"Sub2API forward recovery profile {profile.key} is invalid")
                profile.proxy_username_for(1)
            admin_config = self.sub2_config.get("admin") or {}
            probe_account_id = as_int(admin_config.get("probe_account_id")) if isinstance(admin_config, Mapping) else None
            if probe_account_id is None or probe_account_id <= 0:
                raise GuardError("Sub2API forward recovery requires admin.probe_account_id")
            self.sub2_admin.verify_account_access(probe_account_id)
            self.sub2_forward_tail.start()
        result = []
        for key, client in self.clients.items():
            status = client.verify()
            if require_request_logs and not status["request_log_enabled"]:
                raise GuardError(f"Resin {key} request logging is disabled")
            result.append({"instance": key, **status})
        return result

    def _state_key(self, event: Event) -> str:
        return f"{event.instance}:{event.platform_id}:{event.account}"

    def _platform_key(self, event: Event) -> str:
        return f"{event.instance}:{event.platform_id}"

    def _validate_event(self, event: Event, now: dt.datetime) -> None:
        if event.instance not in self.instances:
            raise GuardError("event references an unmanaged Resin instance")
        platform = self.platforms.get((event.instance, event.platform_id))
        if platform is None or platform.name != event.platform_name:
            raise GuardError("event platform identity mismatch")
        if not ACCOUNT_RE.fullmatch(event.account):
            raise GuardError("event account is invalid")
        max_age = dt.timedelta(seconds=max(1, int(self.config.get("evidence_window_seconds", 300))))
        if event.occurred_at < now - max_age or event.occurred_at > now + dt.timedelta(minutes=2):
            raise GuardError("event is outside the evidence window")

    def _prune_state(self, now: dt.datetime) -> None:
        handled = self.state["handled"]
        cutoff = now - dt.timedelta(days=2)
        ordered = sorted(
            (
                (incident, parse_timestamp(timestamp))
                for incident, timestamp in handled.items()
            ),
            key=lambda row: row[1] or dt.datetime.min.replace(tzinfo=dt.timezone.utc),
            reverse=True,
        )
        self.state["handled"] = {
            incident: isoformat(timestamp)
            for incident, timestamp in ordered[:MAX_HANDLED_INCIDENTS]
            if timestamp is not None and timestamp >= cutoff
        }
        intents = self.state.setdefault("rotation_intents", {})
        self.state["rotation_intents"] = {
            key: intent for key, intent in intents.items()
            if isinstance(intent, Mapping) and (parse_timestamp(intent.get("at")) or cutoff) > cutoff
        }

    def _record_handled(self, event: Event, now: dt.datetime) -> None:
        self.state["handled"][event.incident_id] = isoformat(now)
        self.state.setdefault("rotation_intents", {}).pop(event.incident_id, None)

    def _ambiguous_ready(self, event: Event, account_state: dict[str, Any], now: dt.datetime) -> bool:
        if not event.ambiguous:
            return True
        evidence = account_state.setdefault("ambiguous_evidence", {})
        raw_values = evidence.get(event.kind)
        values = raw_values if isinstance(raw_values, list) else []
        cutoff = now - self.limits.ambiguous_window
        timestamps = [value for value in (parse_timestamp(item) for item in values) if value is not None and value >= cutoff]
        timestamps.append(event.occurred_at)
        timestamps = sorted(timestamps)[-MAX_EVIDENCE_TIMESTAMPS:]
        evidence[event.kind] = [isoformat(value) for value in timestamps]
        return len(timestamps) >= self.limits.ambiguous_threshold

    def _account_eligible(self, account_state: Mapping[str, Any], now: dt.datetime) -> tuple[bool, str]:
        cooldown_until = parse_timestamp(account_state.get("cooldown_until"))
        if cooldown_until is not None and now < cooldown_until:
            return False, "account_cooldown"
        last_rotation = parse_timestamp(account_state.get("last_rotation_at"))
        if last_rotation is not None and now - last_rotation < self.limits.min_interval:
            return False, "min_interval"
        burst_started = parse_timestamp(account_state.get("burst_started_at"))
        burst_count = as_int(account_state.get("burst_count")) or 0
        if burst_started is not None and now - burst_started < self.limits.burst_window and burst_count >= self.limits.burst_max:
            return False, "burst_exhausted"
        return True, "eligible"

    def _platform_guard_eligible(self, event: Event, now: dt.datetime) -> tuple[bool, str]:
        key = self._platform_key(event)
        item = self.state["platforms"].setdefault(key, {})
        cooldown_until = parse_timestamp(item.get("cooldown_until"))
        if cooldown_until is not None and now < cooldown_until:
            return False, "platform_guard"
        cutoff = now - self.limits.platform_guard_window
        recent = item.get("recent_rotations")
        rows = recent if isinstance(recent, list) else []
        filtered = [
            row for row in rows
            if isinstance(row, Mapping) and (parse_timestamp(row.get("at")) or dt.datetime.min.replace(tzinfo=dt.timezone.utc)) >= cutoff
        ]
        accounts = {str(row.get("account") or "") for row in filtered}
        accounts.update(self.active_accounts.get(key, set()))
        if event.account not in accounts and len(accounts) >= self.limits.platform_guard_account_limit:
            item["cooldown_until"] = isoformat(now + self.limits.platform_guard_cooldown)
            item["recent_rotations"] = filtered
            return False, "platform_guard_tripped"
        item["recent_rotations"] = filtered
        return True, "eligible"

    def _record_rotation(self, event: Event, account_state: dict[str, Any], now: dt.datetime) -> None:
        burst_started = parse_timestamp(account_state.get("burst_started_at"))
        burst_count = as_int(account_state.get("burst_count")) or 0
        if burst_started is None or now - burst_started >= self.limits.burst_window:
            account_state["burst_started_at"] = isoformat(now)
            account_state["burst_count"] = 1
        else:
            account_state["burst_count"] = burst_count + 1
        account_state["last_rotation_at"] = isoformat(now)
        if int(account_state["burst_count"]) >= self.limits.burst_max:
            account_state["cooldown_until"] = isoformat(now + self.limits.account_cooldown)
        platform_state = self.state["platforms"].setdefault(self._platform_key(event), {})
        rows = platform_state.setdefault("recent_rotations", [])
        rows.append({"account": event.account, "at": isoformat(now)})

    def process_event(self, event: Event) -> dict[str, Any]:
        lock = self.account_locks[hash(self._state_key(event)) % len(self.account_locks)]
        with lock:
            try:
                return self._process_event(event)
            finally:
                with self.state_lock:
                    self.active_accounts.get(self._platform_key(event), set()).discard(event.account)

    def _lease_io(self, operation: Any, *args: Any, **kwargs: Any) -> Any:
        # The account lock remains held, but unrelated accounts can progress
        # while this network operation waits. Call only inside state_lock.
        self.state_lock.release()
        try:
            return operation(*args, **kwargs)
        finally:
            self.state_lock.acquire()

    def _process_event(self, event: Event) -> dict[str, Any]:
        now = utc_now()
        with self.state_lock:
            self._validate_event(event, now)
            if event.http_status == 524 or event.kind == "upstream_524":
                return {"status": "ignored", "reason": "upstream_http_status"}
            if event.incident_id in self.state["handled"]:
                return {"status": "duplicate"}
            account_state = self.state["accounts"].setdefault(self._state_key(event), {})
            if not self._ambiguous_ready(event, account_state, now):
                self._record_handled(event, now)
                self._save_locked(now)
                return {"status": "awaiting_confirmation"}
            eligible, reason = self._account_eligible(account_state, now)
            if not eligible:
                self._record_handled(event, now)
                self._save_locked(now)
                return {"status": "rate_limited", "reason": reason}
            eligible, reason = self._platform_guard_eligible(event, now)
            if not eligible:
                self._record_handled(event, now)
                self._save_locked(now)
                return {"status": "rate_limited", "reason": reason}
            client = self.clients[event.instance]
            self.active_accounts.setdefault(self._platform_key(event), set()).add(event.account)
            lease = self._lease_io(client.get_lease, event.platform_id, event.account)
            if lease is None:
                self._record_handled(event, now)
                self._save_locked(now)
                return {"status": "lease_absent"}
            current_hash = str(lease.get("node_hash") or "")
            if event.node_hash and current_hash != event.node_hash:
                self._record_handled(event, now)
                self._save_locked(now)
                return {"status": "stale_node"}
            if event.rotate:
                created_at_ns = as_int(lease.get("created_at_ns"))
                if created_at_ns is None or created_at_ns <= 0:
                    raise GuardError("Resin lease is missing created_at_ns")
                lease_created_at = dt.datetime.fromtimestamp(created_at_ns / 1_000_000_000, dt.timezone.utc)
                skew_seconds = max(0, min(5, float(self.config.get(
                    "lease_event_clock_skew_seconds", DEFAULT_LEASE_EVENT_CLOCK_SKEW_SECONDS
                ))))
                if event.occurred_at + dt.timedelta(seconds=skew_seconds) < lease_created_at:
                    self._record_handled(event, now)
                    self._save_locked(now)
                    return {"status": "stale_event"}
            if not self.confirm_write:
                self._record_handled(event, now)
                self._save_locked(now)
                log_event(
                    "lease_rotation_observed",
                    status="would_rotate" if event.rotate else "would_delete",
                    source=event.source,
                    instance=event.instance,
                    platform=event.platform_name,
                    account=event.account,
                    kind=event.kind,
                    target_host=event.target_host,
                    preserve_connections=False,
                )
                return {"status": "observe_only"}
            if event.rotate:
                expected_created_at_ns = str(created_at_ns)
                current_egress_ip = str(lease.get("egress_ip") or "").strip()
                if not current_egress_ip:
                    raise GuardError("Resin lease is missing egress_ip")
                if not event.target_host:
                    raise GuardError("rotation event is missing target_host")
                intents = self.state.setdefault("rotation_intents", {})
                intent = intents.get(event.incident_id)
                if intent is None:
                    if len(intents) >= MAX_HANDLED_INCIDENTS:
                        raise GuardError("rotation intent capacity exceeded")
                    intent = {
                        "at": isoformat(now), "instance": event.instance,
                        "platform_id": event.platform_id, "account": event.account,
                        "target_host": event.target_host, "node_hash": current_hash,
                        "egress_ip": current_egress_ip, "created_at_ns": expected_created_at_ns,
                    }
                    intents[event.incident_id] = intent
                if any(intent.get(key) != getattr(event, key)
                       for key in ("instance", "platform_id", "account", "target_host")):
                    self._record_handled(event, now)
                    self._save_locked(now)
                    return {"status": "stale_identity"}
                # Persist the original CAS before POST. A lost success response or
                # failed verification must never let a retry rotate the next lease.
                self._save_locked(now)
                outcome = self._lease_io(client.rotate_lease,
                    event.platform_id,
                    event.account,
                    expected_node_hash=intent["node_hash"],
                    expected_egress_ip=intent["egress_ip"],
                    expected_created_at_ns=intent["created_at_ns"],
                    target_host=event.target_host,
                    preserve_connections=False,
                )
            else:
                outcome = self._lease_io(client.delete_lease, event.platform_id, event.account)
            # Transient outcomes retain the incident so a later poll can try
            # again. Terminal CAS/no-resource results are safe to deduplicate.
            if outcome == "server_error":
                raise GuardError(f"Resin lease operation is temporarily incomplete: {outcome}")
            self._record_handled(event, now)
            if outcome in {"deleted", "rotated"}:
                self._record_rotation(event, account_state, now)
            self._save_locked(now)
            log_event(
                "lease_rotation",
                status=outcome,
                source=event.source,
                instance=event.instance,
                platform=event.platform_name,
                account=event.account,
                kind=event.kind,
                target_host=event.target_host,
                preserve_connections=False,
            )
            return {"status": outcome}

    def _save_locked(self, now: dt.datetime) -> None:
        self._prune_state(now)
        if self.persist_state:
            atomic_write_json(self.state_path, self.state)

    def feedback_event(self, payload: Mapping[str, Any]) -> Event:
        if payload.get("version") != 1:
            raise GuardError("unsupported feedback version")
        proxy_host = str(payload.get("proxy_host") or "").strip()
        proxy_port = as_int(payload.get("proxy_port")) or 0
        instance = self.endpoints.get((proxy_host, proxy_port))
        if instance is None:
            raise GuardError("feedback proxy endpoint is unmanaged")
        platform_name = str(payload.get("platform") or "").strip()
        platform = self.platform_names.get((instance, platform_name))
        if platform is None:
            raise GuardError("feedback platform is unmanaged")
        kind = str(payload.get("kind") or "").strip().lower()
        if kind not in {
            "cloudflare_challenge",
            "transport_connect",
            "transport_tls",
            "transport_timeout",
            "transport_reset",
        }:
            raise GuardError("feedback kind is not eligible")
        event_id = str(payload.get("event_id") or "").strip()
        try:
            uuid.UUID(event_id)
        except ValueError as exc:
            raise GuardError("feedback event_id must be a UUID") from exc
        source = str(payload.get("source") or "").strip()
        feedback_config = self.config.get("feedback") or {}
        allowed_sources_raw = (
            feedback_config.get("allowed_sources", ["metapi", "sub2api"])
            if isinstance(feedback_config, Mapping)
            else ["metapi", "sub2api"]
        )
        if not isinstance(allowed_sources_raw, list) or not allowed_sources_raw:
            raise GuardError("feedback allowed_sources must be a non-empty array")
        allowed_sources = {
            str(item or "").strip()
            for item in allowed_sources_raw
            if str(item or "").strip()
        }
        if source not in allowed_sources:
            raise GuardError("feedback source is not allowed")
        return Event(
            incident_id=f"feedback:{event_id}",
            occurred_at=parse_timestamp(payload.get("occurred_at")) or utc_now(),
            source=source[:64],
            instance=instance,
            platform_id=platform.id,
            platform_name=platform.name,
            account=str(payload.get("account") or "").strip(),
            kind=kind,
            target_host=str(payload.get("target_host") or "").strip()[:253],
            http_status=as_int(payload.get("http_status")) or 0,
            ambiguous=kind == "transport_reset",
        )

    def poll_resin_once(self) -> dict[str, int]:
        now = utc_now()
        overlap = dt.timedelta(seconds=max(1, int(self.config.get("request_log_overlap_seconds", 10))))
        lookback = dt.timedelta(seconds=max(10, int(self.config.get("request_log_initial_lookback_seconds", 120))))
        max_pages = max(1, int(self.config.get("request_log_max_pages", 10)))
        page_limit = max(20, min(2000, int(self.config.get("request_log_page_limit", 500))))
        counts = {"evidence": 0, "deleted": 0, "errors": 0}
        for key, client in self.clients.items():
            with self.state_lock:
                last_poll = parse_timestamp((self.state["poll"].get(key) or {}).get("last_success_at"))
            after = max(now - lookback, (last_poll - overlap) if last_poll else now - lookback)
            try:
                rows = client.list_logs(after, max_pages, page_limit)
                events = [event for row in rows if (event := request_log_event(key, row)) is not None]
                events.sort(key=lambda item: (item.occurred_at, item.incident_id))
                complete = True
                for event in events:
                    # This Resin instance serves other applications too. Unknown
                    # platforms are outside our policy; a known ID OR name with
                    # mismatched identity still passes through strict validation.
                    if ((key, event.platform_id) not in self.platforms
                            and (key, event.platform_name) not in self.platform_names):
                        continue
                    counts["evidence"] += 1
                    try:
                        outcome = self.process_event(event)
                        if outcome.get("status") == "deleted":
                            counts["deleted"] += 1
                    except GuardError as exc:
                        counts["errors"] += 1
                        complete = False
                        log_event("event_error", source=event.source, error=safe_error(exc))
                if complete:
                    with self.state_lock:
                        self.state["poll"][key] = {"last_success_at": isoformat(now)}
                        self._save_locked(now)
            except GuardError as exc:
                counts["errors"] += 1
                log_event("poll_error", instance=key, error=safe_error(exc))
        return counts

    def poll_sub2_once(self) -> dict[str, int]:
        if not isinstance(self.sub2_config, Mapping) or not self.sub2_config.get("enabled"):
            return {"evidence": 0, "deleted": 0, "errors": 0}
        interval = max(1.0, float(self.sub2_config.get("poll_interval_seconds", 30)))
        current_monotonic = time.monotonic()
        if self.last_sub2_poll_monotonic and current_monotonic - self.last_sub2_poll_monotonic < interval:
            return {"evidence": 0, "deleted": 0, "errors": 0}
        self.last_sub2_poll_monotonic = current_monotonic
        now = utc_now()
        sub2_window_seconds = max(10, int(self.sub2_config.get("evidence_window_seconds", 900)))
        guard_window_seconds = max(1, int(self.config.get("evidence_window_seconds", 300)))
        window = dt.timedelta(seconds=min(sub2_window_seconds, guard_window_seconds))
        max_bytes = max(1024, int(self.sub2_config.get("tail_bytes", 16 * 1024 * 1024)))
        path = Path(str(self.sub2_config.get("path") or ""))
        counts = {"evidence": 0, "deleted": 0, "errors": 0}
        try:
            events = [
                event
                for line in read_log_tail(path, max_bytes)
                if (event := parse_sub2_line(line, self.sub2_profiles, now, window)) is not None
            ]
            events.sort(key=lambda item: (item.occurred_at, item.incident_id))
            for event in events:
                counts["evidence"] += 1
                try:
                    outcome = self.process_event(event)
                    if outcome.get("status") == "deleted":
                        counts["deleted"] += 1
                except GuardError as exc:
                    counts["errors"] += 1
                    log_event("event_error", source=event.source, error=safe_error(exc))
        except GuardError as exc:
            counts["errors"] += 1
            log_event("sub2_log_error", error=safe_error(exc))
        return counts

    def poll_sub2_forward_once(self) -> dict[str, int]:
        counts = {"evidence": 0, "rotated": 0, "errors": 0, "deferred": 0, "dead_lettered": 0}
        if self.sub2_forward_tail is None or self.sub2_admin is None:
            return counts
        now = utc_now()
        forward = self.sub2_config.get("forward_failed") or {}
        window_seconds = max(1, int(forward.get("window_seconds", self.config.get("evidence_window_seconds", 300))))
        window = dt.timedelta(seconds=min(window_seconds, max(1, int(self.config.get("evidence_window_seconds", 300)))))
        max_attempts = max(1, min(100, int(forward.get("retry_max_attempts", DEFAULT_FORWARD_RETRY_MAX_ATTEMPTS))))
        retry_ttl = dt.timedelta(seconds=max(1, min(86400, int(
            forward.get("retry_ttl_seconds", DEFAULT_FORWARD_RETRY_TTL_SECONDS)
        ))))
        retry_initial = max(0.05, min(3600.0, float(
            forward.get("retry_initial_seconds", DEFAULT_FORWARD_RETRY_INITIAL_SECONDS)
        )))
        retry_max = max(retry_initial, min(3600.0, float(
            forward.get("retry_max_seconds", DEFAULT_FORWARD_RETRY_MAX_SECONDS)
        )))
        if not all(value < float("inf") for value in (retry_initial, retry_max)):
            raise GuardError("Sub2API forward retry intervals must be finite")

        def fresh_pending(line: str, signal: Sub2ForwardSignal) -> dict[str, Any]:
            payload: dict[str, Any] = {"account_id": signal.account_id, "request_id": signal.request_id}
            if signal.http_status:
                payload["upstream_status"] = signal.http_status
            else:
                payload.update(stream=True, error=SUB2_FORWARD_ERROR)
            minimal_line = "\t".join((isoformat(signal.occurred_at), "WARN", "guard",
                                      line.split("\t", 4)[3], json.dumps(payload)))
            return {
                "line": minimal_line,
                "first_seen": isoformat(now),
                "retry_count": 0,
                "next_attempt": isoformat(now),
            }

        def dead_letter(entry: Mapping[str, Any], reason: str) -> None:
            signal = parse_sub2_forward_failed_line(str(entry.get("line") or ""), now, window)
            row = {
                "at": isoformat(now),
                "first_seen": str(entry.get("first_seen") or ""),
                "retry_count": as_int(entry.get("retry_count")) or 0,
                "reason": reason[:128],
                "incident_id": signal.incident_id if signal is not None else "",
            }
            dead = self.state.setdefault("forward_dead_letters", [])
            dead.append(row)
            if len(dead) > MAX_FORWARD_DEAD_LETTERS:
                discarded = len(dead) - MAX_FORWARD_DEAD_LETTERS
                del dead[:discarded]
                log_event("forward_dead_letters_truncated", discarded=discarded, reason="capacity")
            counts["dead_lettered"] += 1
            log_event(
                "forward_incident_dead_lettered",
                incident_id=row["incident_id"],
                retry_count=row["retry_count"],
                reason=row["reason"],
            )

        try:
            self.sub2_forward_tail.start()
            previous_cursor = self.sub2_forward_tail.snapshot()
            new_lines = self.sub2_forward_tail.poll()
            cursor = self.sub2_forward_tail.snapshot()
            with self.state_lock:
                pending = list(self.state.get("forward_pending") or [])
                accepted = [fresh_pending(line, signal) for line in new_lines
                            if (signal := parse_sub2_forward_failed_line(line, now, window)) is not None]
                pending.extend(accepted)
                if len(pending) > MAX_FORWARD_PENDING_LINES:
                    discarded = len(pending) - MAX_FORWARD_PENDING_LINES
                    for item in pending[:discarded]:
                        dead_letter(item, "queue_capacity")
                    del pending[:discarded]
                    log_event("forward_pending_truncated", discarded=discarded, reason="capacity")
                cursor_changed = cursor != self.state.get("forward_cursor")
                if self.persist_state and (accepted or cursor_changed):
                    staged_state = dict(self.state)
                    staged_state["forward_pending"] = pending
                    staged_state["forward_cursor"] = cursor
                    try:
                        atomic_write_json(self.state_path, staged_state)
                    except (OSError, GuardError):
                        self.sub2_forward_tail.restore(previous_cursor)
                        raise
                self.state["forward_pending"] = pending
                self.state["forward_cursor"] = cursor
            if not pending:
                return counts
            retained: list[dict[str, Any]] = []
            for entry in pending:
                line = str(entry.get("line") or "")
                signal = parse_sub2_forward_failed_line(line, now, window)
                if signal is None:
                    continue
                next_attempt = parse_timestamp(entry.get("next_attempt"))
                if next_attempt is not None and next_attempt > now:
                    retained.append(entry)
                    counts["deferred"] += 1
                    continue
                counts["evidence"] += 1
                try:
                    event = resolve_sub2_forward_signal(signal, self.sub2_admin, self.sub2_profiles)
                    if event is None:
                        continue
                    outcome = self.process_event(event)
                    if outcome.get("status") == "rotated":
                        counts["rotated"] += 1
                except GuardError as exc:
                    counts["errors"] += 1
                    log_event("event_error", source="sub2api_forward", error=safe_error(exc))
                    retry_count = (as_int(entry.get("retry_count")) or 0) + 1
                    first_seen = parse_timestamp(entry.get("first_seen")) or now
                    if retry_count >= max_attempts or now - first_seen >= retry_ttl:
                        with self.state_lock:
                            entry["retry_count"] = retry_count
                            dead_letter(entry, "max_attempts" if retry_count >= max_attempts else "ttl_expired")
                    else:
                        delay = min(retry_max, retry_initial * (2 ** max(0, retry_count - 1)))
                        entry["retry_count"] = retry_count
                        entry["next_attempt"] = isoformat(now + dt.timedelta(seconds=delay))
                        retained.append(entry)
                        counts["deferred"] += 1
            with self.state_lock:
                self.state["forward_pending"] = retained
                self._save_locked(now)
        except (GuardError, OSError) as exc:
            counts["errors"] += 1
            log_event("sub2_forward_log_error", error=safe_error(exc))
        except (TypeError, ValueError, OverflowError) as exc:
            counts["errors"] += 1
            log_event("sub2_forward_config_error", error=safe_error(exc))
        return counts

    def loop(self) -> None:
        resin_interval = max(1.0, float(self.config.get("poll_interval_seconds", 3)))
        forward = self.sub2_config.get("forward_failed") or {} if isinstance(self.sub2_config, Mapping) else {}
        forward_interval = max(0.05, float(forward.get("poll_interval_seconds", 0.25))) if isinstance(forward, Mapping) else 0.25

        def poll_legacy_sources() -> None:
            while not self.stop_event.is_set():
                try:
                    resin = self.poll_resin_once()
                    sub2 = self.poll_sub2_once()
                    if any(resin.values()) or any(sub2.values()):
                        log_event("poll_summary", resin=resin, sub2api=sub2)
                except (GuardError, OSError) as exc:
                    log_event("legacy_poll_error", error=safe_error(exc))
                self.stop_event.wait(resin_interval)

        # Slow paginated request-log queries must not hold up the live log tail.
        legacy = threading.Thread(target=poll_legacy_sources, name="resin-legacy-poll", daemon=True)
        legacy.start()
        try:
            while not self.stop_event.is_set():
                forward_counts = self.poll_sub2_forward_once()
                if any(forward_counts.values()):
                    log_event("poll_summary", sub2api_forward=forward_counts)
                self.stop_event.wait(forward_interval)
        finally:
            self.stop_event.set()
            legacy.join(timeout=5)
            if self.sub2_forward_tail is not None:
                self.sub2_forward_tail.close()


class FeedbackServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], guard: Guard, token: str) -> None:
        self.guard = guard
        self.token = token
        super().__init__(address, FeedbackHandler)


class FeedbackHandler(BaseHTTPRequestHandler):
    server: FeedbackServer

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(self, status: int, payload: Mapping[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path != "/healthz":
            self._send(404, {"error": "not_found"})
            return
        self._send(200, {"status": "ok"})

    def do_POST(self) -> None:
        if self.path != "/v1/failures":
            self._send(404, {"error": "not_found"})
            return
        if self.headers.get("Authorization", "") != f"Bearer {self.server.token}":
            self._send(401, {"error": "unauthorized"})
            return
        length = as_int(self.headers.get("Content-Length")) or 0
        if length < 2 or length > MAX_FEEDBACK_BYTES:
            self._send(400, {"error": "invalid_body"})
            return
        try:
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, Mapping):
                raise GuardError("feedback body must be an object")
            event = self.server.guard.feedback_event(payload)
            outcome = self.server.guard.process_event(event)
        except (json.JSONDecodeError, GuardError) as exc:
            self._send(400, {"error": safe_error(exc)})
            return
        except Exception as exc:
            log_event("feedback_error", error=safe_error(exc))
            self._send(503, {"error": "guard_unavailable"})
            return
        self._send(202, outcome)


@contextlib.contextmanager
def exclusive_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise GuardError("another resin-egress-guard process is active") from exc
    try:
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def build_guard(config_path: Path) -> Guard:
    raw = load_json_file(config_path)
    config, instances, limits = parse_config(raw)
    return Guard(config, instances, limits)


def command_validate(args: argparse.Namespace) -> int:
    guard = build_guard(Path(args.config).resolve())
    result = guard.verify(require_request_logs=args.require_request_logs)
    print(json.dumps({"status": "ok", "instances": result}, sort_keys=True))
    return 0


def command_scan(args: argparse.Namespace) -> int:
    guard = build_guard(Path(args.config).resolve())
    guard.verify(require_request_logs=True)
    guard.confirm_write = False
    guard.persist_state = False
    resin = guard.poll_resin_once()
    sub2 = guard.poll_sub2_once()
    forward = guard.poll_sub2_forward_once()
    print(json.dumps({
        "status": "dry_run",
        "resin": resin,
        "sub2api": sub2,
        "sub2api_forward": forward,
    }, sort_keys=True))
    return 0


def command_serve(args: argparse.Namespace) -> int:
    if not args.confirm_production_write and not args.observe_only:
        raise GuardError("serve requires --confirm-production-write")
    guard = build_guard(Path(args.config).resolve())
    statuses = guard.verify(require_request_logs=True)
    guard.confirm_write = bool(args.confirm_production_write and not args.observe_only)
    feedback = guard.config.get("feedback") or {}
    if not isinstance(feedback, Mapping):
        raise GuardError("feedback config must be an object")
    listeners = parse_feedback_listeners(feedback)
    port = int(feedback.get("port") or 19085)
    if port < 1 or port > 65535:
        raise GuardError("feedback port is invalid")
    token = read_secret_credential(str(feedback.get("token_credential") or ""))
    servers: list[FeedbackServer] = []
    try:
        for listen in listeners:
            servers.append(FeedbackServer((listen, port), guard, token))
    except Exception:
        for server in servers:
            server.server_close()
        raise
    threads = [
        threading.Thread(
            target=server.serve_forever,
            name=f"resin-feedback-{index + 1}",
            daemon=True,
        )
        for index, server in enumerate(servers)
    ]

    def shutdown_servers() -> None:
        for server in servers:
            server.shutdown()

    def stop(_signum: int, _frame: Any) -> None:
        guard.stop_event.set()
        threading.Thread(target=shutdown_servers, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    log_event(
        "guard_started",
        instances=statuses,
        feedback_listeners=list(listeners),
        feedback_port=port,
        observe_only=not guard.confirm_write,
        sub2_upstream_rotation_statuses=[],
    )
    for thread in threads:
        thread.start()
    try:
        guard.loop()
    finally:
        shutdown_servers()
        for server in servers:
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)
    log_event("guard_stopped")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--require-request-logs", action="store_true")
    validate.set_defaults(func=command_validate)
    scan = commands.add_parser("scan")
    scan.set_defaults(func=command_scan)
    serve = commands.add_parser("serve")
    serve.add_argument("--confirm-production-write", action="store_true")
    serve.add_argument(
        "--observe-only",
        action="store_true",
        help="poll and record evidence but never delete a Resin lease",
    )
    serve.set_defaults(func=command_serve)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    config_path = Path(args.config).resolve()
    raw = load_json_file(config_path)
    lock_path = Path(str(raw.get("lock_file") or "/run/lock/resin-egress-guard.lock"))
    with exclusive_lock(lock_path):
        return int(args.func(args))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GuardError as exc:
        print(f"resin-egress-guard: {safe_error(exc)}", file=sys.stderr)
        raise SystemExit(2)
