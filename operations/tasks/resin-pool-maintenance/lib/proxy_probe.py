#!/usr/bin/env python3
"""Validate line-based HTTP/SOCKS proxies without exposing credentials."""

from __future__ import annotations

import base64
import concurrent.futures
import dataclasses
import datetime as dt
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SUPPORTED_SCHEMES = {"http", "https", "socks5", "socks5h"}
MAX_POOL_NODES = 1000
MAX_HEADER_BYTES = 16 * 1024
MAX_TRACE_BYTES = 16 * 1024
USER_AGENT = "resin-pool-maintainer/1"
_TLS_CONTEXT: ssl.SSLContext | None = None
_TLS_CONTEXT_LOCK = threading.Lock()


def verified_tls_context() -> ssl.SSLContext:
    global _TLS_CONTEXT
    # A read-only SSLContext is thread-safe. Load the CA store once per run,
    # not once per target per node, while retaining certificate/hostname checks.
    if _TLS_CONTEXT is None:
        with _TLS_CONTEXT_LOCK:
            if _TLS_CONTEXT is None:
                _TLS_CONTEXT = ssl.create_default_context()
    return _TLS_CONTEXT


class ProbeError(RuntimeError):
    def __init__(self, category: str, message: str = "") -> None:
        super().__init__(message or category)
        self.category = category


@dataclasses.dataclass(frozen=True)
class ProxySpec:
    scheme: str
    host: str
    port: int
    username: str = ""
    password: str = ""
    source_ids: tuple[str, ...] = ()
    allowed_non_public_ip: str = ""
    credential_group_override: str = ""

    @property
    def canonical(self) -> str:
        auth = ""
        if self.username or self.password:
            user = urllib.parse.quote(self.username, safe="")
            password = urllib.parse.quote(self.password, safe="")
            auth = f"{user}:{password}@"
        host = f"[{self.host}]" if ":" in self.host and not self.host.startswith("[") else self.host
        return f"{self.scheme}://{auth}{host}:{self.port}"

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.canonical.encode("utf-8")).hexdigest()

    @property
    def credential_group_id(self) -> str:
        if self.credential_group_override:
            return self.credential_group_override
        if not (self.username or self.password):
            return self.fingerprint[:16]
        material = f"{self.username}\0{self.password}".encode("utf-8")
        return hashlib.sha256(material).hexdigest()[:16]


@dataclasses.dataclass
class ProbeResult:
    spec: ProxySpec
    ok: bool
    category: str
    latency_ms: float = 0.0
    egress_ip: str = ""
    region: str = ""
    failed_target: str = ""

    def safe_dict(self) -> dict[str, Any]:
        egress_hash = ""
        if self.egress_ip:
            egress_hash = hashlib.sha256(self.egress_ip.encode("ascii")).hexdigest()[:16]
        return {
            "proxy_id": self.spec.fingerprint[:16],
            "source_ids": list(self.spec.source_ids),
            "credential_group_id": self.spec.credential_group_id,
            "ok": self.ok,
            "category": self.category,
            "latency_ms": round(self.latency_ms, 2),
            "egress_id": egress_hash,
            "region": self.region,
            "failed_target": self.failed_target,
        }


def normalize_target_hosts(raw: Any) -> tuple[str, ...]:
    if isinstance(raw, str):
        values: Sequence[Any] = (raw,)
    elif isinstance(raw, Sequence) and not isinstance(raw, (bytes, bytearray)):
        values = raw
    else:
        raise ValueError("target hosts must be a string or string array")
    if not values or len(values) > 8:
        raise ValueError("target hosts must contain between 1 and 8 entries")

    normalized: list[str] = []
    seen: set[str] = set()
    for raw_host in values:
        if not isinstance(raw_host, str):
            raise ValueError("target host must be a string")
        host = raw_host.strip().rstrip(".")
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("invalid target host") from exc
        labels = host.split(".")
        if (
            not host
            or len(host) > 253
            or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or any(not (char.isalnum() or char == "-") for char in label)
                for label in labels
            )
        ):
            raise ValueError("invalid target host")
        if host not in seen:
            seen.add(host)
            normalized.append(host)
    return tuple(normalized)


def validation_target_hosts(validation: Mapping[str, Any]) -> tuple[str, ...]:
    if "target_hosts" in validation:
        return normalize_target_hosts(validation["target_hosts"])
    return normalize_target_hosts(validation.get("target_host", "www.cloudflare.com"))


def normalize_min_target_hosts_passed(raw: Any, target_count: int) -> int:
    if target_count < 1:
        raise ValueError("target_count must be positive")
    if raw is None:
        return target_count
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ValueError("min_target_hosts_passed must be an integer")
    if raw < 1 or raw > target_count:
        raise ValueError("min_target_hosts_passed must be between 1 and target host count")
    return raw


def validation_min_target_hosts_passed(
    validation: Mapping[str, Any], target_hosts: Sequence[str]
) -> int:
    return normalize_min_target_hosts_passed(
        validation.get("min_target_hosts_passed"), len(target_hosts)
    )


def _split_endpoint(raw: str) -> tuple[str, int]:
    value = raw.strip()
    if value.startswith("["):
        close = value.find("]")
        if close < 0 or close + 2 > len(value) or value[close + 1] != ":":
            raise ValueError("invalid bracketed endpoint")
        host = value[1:close]
        port_raw = value[close + 2 :]
    else:
        if value.count(":") != 1:
            raise ValueError("endpoint must be host:port")
        host, port_raw = value.rsplit(":", 1)
    host = host.strip()
    if not host:
        raise ValueError("empty host")
    port = int(port_raw)
    if port < 1 or port > 65535:
        raise ValueError("port out of range")
    return host, port


def parse_proxy_line(raw: str) -> ProxySpec | None:
    line = raw.strip().lstrip("\ufeff")
    if not line or line.startswith("#") or line.startswith(";"):
        return None

    if "://" in line:
        parsed = urllib.parse.urlsplit(line)
        scheme = parsed.scheme.lower()
        if scheme not in SUPPORTED_SCHEMES:
            raise ValueError("unsupported proxy scheme")
        if parsed.path not in ("", "/") or parsed.query:
            raise ValueError("proxy URI must not contain path or query")
        host = parsed.hostname or ""
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("invalid proxy port") from exc
        if not host or port is None:
            raise ValueError("proxy URI requires host and port")
        username = urllib.parse.unquote(parsed.username or "")
        password = urllib.parse.unquote(parsed.password or "")
        return ProxySpec(scheme, host, port, username, password)

    if "@" in line:
        auth, endpoint = line.rsplit("@", 1)
        if ":" not in auth:
            raise ValueError("proxy credentials require user:password")
        username, password = auth.split(":", 1)
        host, port = _split_endpoint(endpoint)
        return ProxySpec("http", host, port, username, password)

    parts = line.split(":")
    if len(parts) == 4 and parts[1].isdigit():
        host, port_raw, username, password = parts
        port = int(port_raw)
        if port < 1 or port > 65535:
            raise ValueError("port out of range")
        return ProxySpec("http", host, port, username, password)

    host, port = _split_endpoint(line)
    return ProxySpec("http", host, port)


class PublicResolver:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: dict[tuple[str, int, str], tuple[str, int]] = {}

    @staticmethod
    def _public_ip(raw: str) -> bool:
        try:
            return ipaddress.ip_address(raw).is_global
        except ValueError:
            return False

    def resolve(
        self,
        host: str,
        port: int,
        allowed_non_public_ip: str = "",
    ) -> tuple[str, int]:
        key = (host.lower(), port, allowed_non_public_ip)
        with self._lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached

        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            normalized = str(literal)
            if not literal.is_global and normalized != allowed_non_public_ip:
                raise ProbeError("blocked_non_public_proxy")
            value = (normalized, socket.AF_INET6 if literal.version == 6 else socket.AF_INET)
        else:
            try:
                infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except OSError as exc:
                raise ProbeError("proxy_dns_failed") from exc
            candidates: list[tuple[str, int]] = []
            rejected_non_public = False
            for family, _, _, _, sockaddr in infos:
                address = sockaddr[0]
                if family not in (socket.AF_INET, socket.AF_INET6):
                    continue
                if self._public_ip(address):
                    candidates.append((address, family))
                else:
                    rejected_non_public = True
            if rejected_non_public:
                raise ProbeError("blocked_non_public_proxy")
            if not candidates:
                raise ProbeError("blocked_non_public_proxy")
            candidates.sort(key=lambda item: (item[1] != socket.AF_INET, item[0]))
            value = candidates[0]

        with self._lock:
            self._cache[key] = value
        return value


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ProbeError("proxy_protocol_eof")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_headers(sock: socket.socket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(min(4096, MAX_HEADER_BYTES - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if len(data) >= MAX_HEADER_BYTES:
            raise ProbeError("proxy_header_too_large")
    if b"\r\n\r\n" not in data:
        raise ProbeError("proxy_header_incomplete")
    return bytes(data)


def _open_proxy_socket(spec: ProxySpec, resolver: PublicResolver, timeout: float) -> socket.socket:
    address, family = resolver.resolve(
        spec.host,
        spec.port,
        allowed_non_public_ip=spec.allowed_non_public_ip,
    )
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sockaddr: tuple[Any, ...]
        if family == socket.AF_INET6:
            sockaddr = (address, spec.port, 0, 0)
        else:
            sockaddr = (address, spec.port)
        sock.connect(sockaddr)
        if spec.scheme == "https":
            context = verified_tls_context()
            sock = context.wrap_socket(sock, server_hostname=spec.host)
            sock.settimeout(timeout)
        return sock
    except Exception:
        sock.close()
        raise


def _http_connect(sock: socket.socket, spec: ProxySpec, target_host: str, target_port: int) -> None:
    headers = [
        f"CONNECT {target_host}:{target_port} HTTP/1.1",
        f"Host: {target_host}:{target_port}",
        f"User-Agent: {USER_AGENT}",
        "Proxy-Connection: keep-alive",
    ]
    if spec.username or spec.password:
        token = base64.b64encode(f"{spec.username}:{spec.password}".encode("utf-8")).decode("ascii")
        headers.append(f"Proxy-Authorization: Basic {token}")
    payload = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii")
    sock.sendall(payload)
    response = _recv_headers(sock)
    first = response.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
    parts = first.split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise ProbeError("proxy_invalid_http_response")
    status = int(parts[1])
    if status < 200 or status >= 300:
        if status == 407:
            raise ProbeError("proxy_auth_rejected")
        raise ProbeError(f"proxy_connect_http_{status}")


def _socks5_connect(sock: socket.socket, spec: ProxySpec, target_host: str, target_port: int) -> None:
    methods = b"\x00\x02" if spec.username or spec.password else b"\x00"
    sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
    version, method = _recv_exact(sock, 2)
    if version != 5 or method == 0xFF:
        raise ProbeError("proxy_socks_method_rejected")
    if method == 2:
        user = spec.username.encode("utf-8")
        password = spec.password.encode("utf-8")
        if len(user) > 255 or len(password) > 255:
            raise ProbeError("proxy_credentials_too_long")
        sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
        auth_version, auth_status = _recv_exact(sock, 2)
        if auth_version != 1 or auth_status != 0:
            raise ProbeError("proxy_auth_rejected")
    elif method != 0:
        raise ProbeError("proxy_socks_method_unsupported")

    encoded_host = target_host.encode("idna")
    if len(encoded_host) > 255:
        raise ProbeError("target_host_too_long")
    request = b"\x05\x01\x00\x03" + bytes([len(encoded_host)]) + encoded_host + target_port.to_bytes(2, "big")
    sock.sendall(request)
    version, reply, reserved, atyp = _recv_exact(sock, 4)
    if version != 5 or reserved != 0:
        raise ProbeError("proxy_invalid_socks_response")
    if reply != 0:
        raise ProbeError(f"proxy_socks_reply_{reply}")
    if atyp == 1:
        _recv_exact(sock, 4)
    elif atyp == 4:
        _recv_exact(sock, 16)
    elif atyp == 3:
        length = _recv_exact(sock, 1)[0]
        _recv_exact(sock, length)
    else:
        raise ProbeError("proxy_invalid_socks_address")
    _recv_exact(sock, 2)


def _open_tunnel(
    spec: ProxySpec,
    resolver: PublicResolver,
    timeout: float,
    target_host: str,
    target_port: int = 443,
) -> socket.socket:
    try:
        sock = _open_proxy_socket(spec, resolver, timeout)
    except ProbeError:
        raise
    except socket.timeout as exc:
        raise ProbeError("proxy_connect_timeout") from exc
    except ssl.SSLError as exc:
        raise ProbeError("https_proxy_tls_failed") from exc
    except OSError as exc:
        raise ProbeError("proxy_connect_failed") from exc

    try:
        if spec.scheme in ("http", "https"):
            _http_connect(sock, spec, target_host, target_port)
        else:
            _socks5_connect(sock, spec, target_host, target_port)
        return sock
    except Exception:
        sock.close()
        raise


def _tls_tunnel(
    spec: ProxySpec,
    resolver: PublicResolver,
    timeout: float,
    target_host: str,
) -> ssl.SSLSocket:
    sock = _open_tunnel(spec, resolver, timeout, target_host)
    try:
        context = verified_tls_context()
        tls = context.wrap_socket(sock, server_hostname=target_host)
        tls.settimeout(timeout)
        if not tls.getpeercert():
            raise ProbeError("target_certificate_missing")
        return tls
    except ProbeError:
        sock.close()
        raise
    except socket.timeout as exc:
        sock.close()
        raise ProbeError("target_tls_timeout") from exc
    except ssl.SSLError as exc:
        sock.close()
        raise ProbeError("target_tls_failed") from exc
    except OSError as exc:
        sock.close()
        raise ProbeError("target_connect_failed") from exc


def _trace_egress(
    spec: ProxySpec,
    resolver: PublicResolver,
    timeout: float,
) -> tuple[str, str]:
    tls = _tls_tunnel(spec, resolver, timeout, "cloudflare.com")
    try:
        request = (
            "GET /cdn-cgi/trace HTTP/1.1\r\n"
            "Host: cloudflare.com\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        tls.sendall(request)
        data = bytearray()
        while len(data) < MAX_TRACE_BYTES:
            chunk = tls.recv(min(4096, MAX_TRACE_BYTES - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        header, separator, body = bytes(data).partition(b"\r\n\r\n")
        if not separator:
            raise ProbeError("trace_response_incomplete")
        first = header.split(b"\r\n", 1)[0].split()
        if len(first) < 2 or first[1] != b"200":
            raise ProbeError("trace_http_failed")
        values: dict[str, str] = {}
        for raw_line in body.decode("utf-8", "replace").splitlines():
            key, marker, value = raw_line.partition("=")
            if marker:
                values[key.strip().lower()] = value.strip()
        egress_ip = values.get("ip", "")
        try:
            parsed_ip = ipaddress.ip_address(egress_ip)
        except ValueError as exc:
            raise ProbeError("trace_ip_invalid") from exc
        if not parsed_ip.is_global:
            raise ProbeError("trace_ip_non_public")
        region = values.get("loc", "").lower()
        if region and (len(region) != 2 or not region.isalpha()):
            region = ""
        return str(parsed_ip), region
    finally:
        tls.close()


def probe_one(
    spec: ProxySpec,
    resolver: PublicResolver,
    timeout: float,
    target_hosts: str | Sequence[str],
    trace_egress: bool,
    min_target_hosts_passed: int | None = None,
) -> ProbeResult:
    started = time.monotonic()
    normalized_targets = normalize_target_hosts(target_hosts)
    required_targets = normalize_min_target_hosts_passed(
        min_target_hosts_passed, len(normalized_targets)
    )
    passed_targets = 0
    first_failure: tuple[str, str] | None = None
    for target_host in normalized_targets:
        try:
            tls = _tls_tunnel(spec, resolver, timeout, target_host)
            tls.close()
        except ProbeError as exc:
            if first_failure is None:
                first_failure = (exc.category, target_host)
        except socket.timeout:
            if first_failure is None:
                first_failure = ("timeout", target_host)
        except Exception:
            if first_failure is None:
                first_failure = ("unexpected_error", target_host)
        else:
            passed_targets += 1

    if passed_targets < required_targets:
        category, failed_target = first_failure or ("target_quorum_failed", "")
        return ProbeResult(
            spec=spec,
            ok=False,
            category=category,
            latency_ms=(time.monotonic() - started) * 1000,
            failed_target=failed_target,
        )

    egress_ip = ""
    region = ""
    if trace_egress:
        try:
            egress_ip, region = _trace_egress(spec, resolver, timeout)
        except ProbeError as exc:
            return ProbeResult(
                spec=spec,
                ok=False,
                category=exc.category,
                latency_ms=(time.monotonic() - started) * 1000,
                failed_target="cloudflare.com",
            )
        except socket.timeout:
            return ProbeResult(
                spec,
                False,
                "timeout",
                (time.monotonic() - started) * 1000,
                failed_target="cloudflare.com",
            )
        except Exception:
            return ProbeResult(
                spec,
                False,
                "unexpected_error",
                (time.monotonic() - started) * 1000,
                failed_target="cloudflare.com",
            )
    return ProbeResult(
        spec=spec,
        ok=True,
        category="passed",
        latency_ms=(time.monotonic() - started) * 1000,
        egress_ip=egress_ip,
        region=region,
    )


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, resolver: PublicResolver) -> None:
        super().__init__()
        self._resolver = resolver

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        validate_public_url(newurl, self._resolver)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def validate_public_url(url: str, resolver: PublicResolver) -> None:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError("source URL must be credential-free public HTTPS")
    port = parsed.port or 443
    resolver.resolve(parsed.hostname, port)


def download_source(url: str, resolver: PublicResolver, timeout: float, max_bytes: int) -> bytes:
    validate_public_url(url, resolver)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), SafeRedirectHandler(resolver))
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/plain,*/*;q=0.5"})
    try:
        with opener.open(request, timeout=timeout) as response:
            final_url = response.geturl()
            validate_public_url(final_url, resolver)
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > max_bytes:
                raise ValueError("source exceeds configured size limit")
            data = response.read(max_bytes + 1)
    except (urllib.error.URLError, OSError) as exc:
        raise ValueError("source download failed") from exc
    if len(data) > max_bytes:
        raise ValueError("source exceeds configured size limit")
    return data


def load_sources(
    sources: Sequence[Mapping[str, Any]],
    resolver: PublicResolver,
    timeout: float,
    max_bytes: int,
) -> tuple[list[ProxySpec], list[dict[str, Any]]]:
    now = dt.datetime.now(dt.timezone.utc)
    specs: dict[str, ProxySpec] = {}
    audits: list[dict[str, Any]] = []
    seen_source_ids: set[str] = set()
    for source in sources:
        source_id = str(source.get("id") or "").strip()
        source_type = str(source.get("type") or "").strip().lower()
        if not source_id or source_type not in ("file", "url"):
            raise ValueError("each source requires id and type=file|url")
        if source_id in seen_source_ids:
            raise ValueError(f"duplicate source id: {source_id}")
        seen_source_ids.add(source_id)
        if source.get("enabled", True) is not True:
            audits.append({"id": source_id, "status": "disabled"})
            continue
        allowed_non_public_ips: set[str] = set()
        raw_allowed_ips = source.get("allowed_non_public_proxy_ips") or []
        if raw_allowed_ips:
            if source_type != "file" or not isinstance(raw_allowed_ips, list):
                raise ValueError(
                    f"source {source_id}: non-public proxy allowlist requires a file source"
                )
            for raw_ip in raw_allowed_ips:
                try:
                    parsed_ip = ipaddress.ip_address(str(raw_ip))
                except ValueError as exc:
                    raise ValueError(
                        f"source {source_id}: invalid non-public proxy allowlist"
                    ) from exc
                allowed_network = (
                    ipaddress.ip_network("172.16.0.0/12")
                    if parsed_ip.version == 4
                    else ipaddress.ip_network("fc00::/7")
                )
                if parsed_ip not in allowed_network:
                    raise ValueError(
                        f"source {source_id}: local bridge allowlist must use RFC1918 172.16/12 or ULA"
                    )
                allowed_non_public_ips.add(str(parsed_ip))
        expires_at = None
        raw_expiry = source.get("expires_at")
        if raw_expiry not in (None, ""):
            try:
                expires_at = dt.datetime.fromisoformat(
                    str(raw_expiry).strip().replace("Z", "+00:00")
                )
            except ValueError as exc:
                raise ValueError(f"source {source_id}: invalid expiry") from exc
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=dt.timezone.utc)
            expires_at = expires_at.astimezone(dt.timezone.utc)
        if expires_at is not None and expires_at <= now:
            audits.append({"id": source_id, "status": "expired", "expires_at": expires_at.isoformat()})
            continue

        if source_type == "file":
            path = Path(str(source.get("path") or ""))
            if not path.is_file():
                raise ValueError(f"source {source_id}: file not found")
            if path.stat().st_size > max_bytes:
                raise ValueError(f"source {source_id}: file exceeds size limit")
            if path.stat().st_mode & 0o077:
                raise ValueError(f"source {source_id}: credential file must use mode 0600")
            data = path.read_bytes()
        else:
            url = str(source.get("url") or "")
            data = download_source(url, resolver, timeout, max_bytes)

        decoded = data.decode("utf-8-sig", "replace")
        parsed_count = 0
        rejected_count = 0
        source_canonicals: set[str] = set()
        for raw_line in decoded.splitlines():
            try:
                spec = parse_proxy_line(raw_line)
            except (TypeError, ValueError):
                rejected_count += 1
                continue
            if spec is None:
                continue
            try:
                literal_host = str(ipaddress.ip_address(spec.host))
            except ValueError:
                literal_host = ""
            if literal_host in allowed_non_public_ips:
                spec = dataclasses.replace(spec, allowed_non_public_ip=literal_host)
            parsed_count += 1
            source_canonicals.add(spec.canonical)
            existing = specs.get(spec.canonical)
            if existing is None:
                specs[spec.canonical] = dataclasses.replace(spec, source_ids=(source_id,))
            elif source_id not in existing.source_ids:
                specs[spec.canonical] = dataclasses.replace(
                    existing,
                    source_ids=(*existing.source_ids, source_id),
                    allowed_non_public_ip=(
                        existing.allowed_non_public_ip or spec.allowed_non_public_ip
                    ),
                )
        audits.append(
            {
                "id": source_id,
                "status": "loaded",
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "parsed": parsed_count,
                "input_count": len(source_canonicals),
                "rejected_lines": rejected_count,
            }
        )
    return list(specs.values()), audits


def probe_many(
    specs: Sequence[ProxySpec],
    *,
    timeout: float,
    workers: int,
    batch_size: int,
    target_host: str | Sequence[str],
    trace_egress: bool,
    min_target_hosts_passed: int | None = None,
) -> list[ProbeResult]:
    if workers < 1 or workers > 1000:
        raise ValueError("workers must be between 1 and 1000")
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    target_hosts = normalize_target_hosts(target_host)
    required_targets = normalize_min_target_hosts_passed(
        min_target_hosts_passed, len(target_hosts)
    )
    resolver = PublicResolver()
    results: list[ProbeResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="proxy-probe") as pool:
        for start in range(0, len(specs), batch_size):
            batch = specs[start : start + batch_size]
            mapped = pool.map(
                lambda item: probe_one(
                    item,
                    resolver,
                    timeout,
                    target_hosts,
                    trace_egress,
                    required_targets,
                ),
                batch,
            )
            results.extend(mapped)
    return results


def select_results(
    results: Sequence[ProbeResult],
    *,
    max_nodes: int,
    max_per_egress: int,
    allowed_regions: Iterable[str],
    require_egress: bool,
    excluded_regions: Iterable[str] = (),
    min_per_region: int = 0,
    max_per_source: int = 0,
    max_per_credential_group: int = 0,
    preferred_source_ids: Iterable[str] = (),
) -> list[ProbeResult]:
    if min_per_region < 0:
        raise ValueError("min_per_region must not be negative")
    if (
        max_nodes < 0
        or max_per_egress < 0
        or max_per_source < 0
        or max_per_credential_group < 0
    ):
        raise ValueError("selection limits must not be negative")
    max_nodes = min(max_nodes or MAX_POOL_NODES, MAX_POOL_NODES)
    allowed = {item.strip().lower() for item in allowed_regions if item.strip()}
    excluded = {item.strip().lower() for item in excluded_regions if item.strip()}
    if allowed.intersection(excluded):
        raise ValueError("allowed_regions and excluded_regions must not overlap")
    candidates = [row for row in results if row.ok]
    if allowed:
        candidates = [row for row in candidates if row.region in allowed]
    if excluded:
        candidates = [row for row in candidates if row.region not in excluded]
    if require_egress:
        candidates = [row for row in candidates if row.egress_ip]
    preferred_sources = {
        item.strip() for item in preferred_source_ids if item.strip()
    }

    def selection_key(row: ProbeResult) -> tuple[int, float | str, str]:
        preferred = bool(preferred_sources.intersection(row.spec.source_ids))
        if preferred:
            return (0, row.spec.fingerprint, row.spec.fingerprint)
        return (1, row.latency_ms, row.spec.fingerprint)

    candidates.sort(key=selection_key)
    region_count = len({row.region for row in candidates if row.region})
    required_region_slots = region_count * min_per_region
    if max_nodes > 0 and required_region_slots > max_nodes:
        raise ValueError(
            f"max_nodes={max_nodes} cannot preserve {min_per_region} node(s) for each of {region_count} regions"
        )

    selected: list[ProbeResult] = []
    selected_fingerprints: set[str] = set()
    per_egress: defaultdict[str, int] = defaultdict(int)
    per_source: defaultdict[str, int] = defaultdict(int)
    per_credential_group: defaultdict[str, int] = defaultdict(int)

    def add(row: ProbeResult) -> bool:
        if max_nodes > 0 and len(selected) >= max_nodes:
            return False
        if row.spec.fingerprint in selected_fingerprints:
            return False
        key = row.egress_ip or row.spec.fingerprint
        if max_per_egress > 0 and per_egress[key] >= max_per_egress:
            return False
        source_ids = row.spec.source_ids or ("unknown",)
        if max_per_source > 0 and any(
            per_source[source_id] >= max_per_source for source_id in source_ids
        ):
            return False
        credential_group = row.spec.credential_group_id
        if (
            max_per_credential_group > 0
            and per_credential_group[credential_group] >= max_per_credential_group
        ):
            return False
        per_egress[key] += 1
        for source_id in source_ids:
            per_source[source_id] += 1
        per_credential_group[credential_group] += 1
        selected_fingerprints.add(row.spec.fingerprint)
        selected.append(row)
        return True

    if min_per_region:
        by_region: defaultdict[str, list[ProbeResult]] = defaultdict(list)
        for row in candidates:
            if row.region:
                by_region[row.region].append(row)
        ordered_regions = sorted(
            by_region,
            key=lambda region: (selection_key(by_region[region][0]), region),
        )
        region_offsets: defaultdict[str, int] = defaultdict(int)
        for _ in range(min_per_region):
            for region in ordered_regions:
                rows = by_region[region]
                while region_offsets[region] < len(rows):
                    row = rows[region_offsets[region]]
                    region_offsets[region] += 1
                    if add(row):
                        break
                if max_nodes > 0 and len(selected) >= max_nodes:
                    return selected
        selected_regions = Counter(row.region for row in selected if row.region)
        missing = [region for region in ordered_regions if selected_regions[region] < min_per_region]
        if missing:
            raise ValueError("not enough unique egresses to satisfy min_per_region")

    for row in candidates:
        add(row)
        if max_nodes > 0 and len(selected) >= max_nodes:
            break
    return selected


def build_source_reports(
    source_audit: Sequence[Mapping[str, Any]],
    results: Sequence[ProbeResult],
    selected: Sequence[ProbeResult],
) -> list[dict[str, Any]]:
    selected_ids = {row.spec.fingerprint for row in selected}
    reports: list[dict[str, Any]] = []
    for raw_audit in source_audit:
        audit = dict(raw_audit)
        source_id = str(audit.get("id") or "")
        if audit.get("status") == "loaded":
            source_results = [row for row in results if source_id in row.spec.source_ids]
            categories = Counter(row.category for row in source_results)
            audit.update(
                {
                    "input_count": len(source_results),
                    "passed_count": sum(1 for row in source_results if row.ok),
                    "selected_count": sum(
                        1 for row in source_results if row.spec.fingerprint in selected_ids
                    ),
                    "categories": dict(sorted(categories.items())),
                }
            )
        reports.append(audit)
    return reports


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    temp = Path(temp_name)
    os.fchmod(fd, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        os.chmod(path, mode)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temp.exists():
            temp.unlink()


def write_validation_artifacts(
    output_file: Path,
    report_file: Path,
    results: Sequence[ProbeResult],
    selected: Sequence[ProbeResult],
    source_audit: Sequence[Mapping[str, Any]],
    elapsed_seconds: float,
    target_hosts: Sequence[str] = (),
    min_target_hosts_passed: int | None = None,
) -> dict[str, Any]:
    content = "".join(f"{row.spec.canonical}\n" for row in selected).encode("utf-8")
    atomic_write(output_file, content)
    categories = Counter(row.category for row in results)
    regions = Counter(row.region or "unknown" for row in results if row.ok)
    unique_egress = len({row.egress_ip for row in results if row.egress_ip})
    target_failures: defaultdict[str, Counter[str]] = defaultdict(Counter)
    for row in results:
        if not row.ok and row.failed_target:
            target_failures[row.failed_target][row.category] += 1
    required_targets = (
        normalize_min_target_hosts_passed(min_target_hosts_passed, len(target_hosts))
        if target_hosts
        else 0
    )
    report = {
        "version": 1,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": "validated",
        "input_count": len(results),
        "passed_count": sum(1 for row in results if row.ok),
        "selected_count": len(selected),
        "unique_egress_count": unique_egress,
        "categories": dict(sorted(categories.items())),
        "regions": dict(sorted(regions.items())),
        "elapsed_seconds": round(elapsed_seconds, 3),
        "target_hosts": list(target_hosts),
        "min_target_hosts_passed": required_targets,
        "target_failures": {
            target: dict(sorted(categories.items()))
            for target, categories in sorted(target_failures.items())
        },
        "output_sha256": hashlib.sha256(content).hexdigest(),
        "credential_group_count": len({row.spec.credential_group_id for row in results}),
        "selected_credential_group_count": len(
            {row.spec.credential_group_id for row in selected}
        ),
        "sources": build_source_reports(source_audit, results, selected),
        "results": [row.safe_dict() for row in results],
    }
    atomic_write(report_file, (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    return report


def validation_from_config(config: Mapping[str, Any], output_file: Path, report_file: Path) -> dict[str, Any]:
    validation = config.get("validation") or {}
    selection = config.get("selection") or {}
    sources = config.get("sources") or []
    if not isinstance(validation, Mapping) or not isinstance(selection, Mapping) or not isinstance(sources, list):
        raise ValueError("invalid validation configuration")
    timeout = float(validation.get("timeout_seconds", 5.0))
    workers = int(validation.get("workers", 200))
    batch_size = int(validation.get("batch_size", 500))
    target_hosts = validation_target_hosts(validation)
    min_target_hosts_passed = validation_min_target_hosts_passed(validation, target_hosts)
    trace_egress = bool(validation.get("trace_egress", True))
    max_source_bytes = int(validation.get("max_source_bytes", 4 * 1024 * 1024))
    if timeout <= 0 or timeout > 60:
        raise ValueError("timeout_seconds must be in (0, 60]")
    resolver = PublicResolver()
    specs, source_audit = load_sources(sources, resolver, timeout, max_source_bytes)
    started = time.monotonic()
    results = probe_many(
        specs,
        timeout=timeout,
        workers=workers,
        batch_size=batch_size,
        target_host=target_hosts,
        trace_egress=trace_egress,
        min_target_hosts_passed=min_target_hosts_passed,
    )
    selected = select_results(
        results,
        max_nodes=int(selection.get("max_nodes", MAX_POOL_NODES)),
        max_per_egress=int(selection.get("max_per_egress", 0)),
        allowed_regions=selection.get("allowed_regions") or [],
        require_egress=bool(selection.get("require_egress", True)),
        excluded_regions=selection.get("excluded_regions") or [],
        min_per_region=int(selection.get("min_per_region", 0)),
        max_per_source=int(selection.get("max_per_source", 0)),
        max_per_credential_group=int(selection.get("max_per_credential_group", 0)),
        preferred_source_ids=selection.get("preferred_source_ids") or [],
    )
    return write_validation_artifacts(
        output_file,
        report_file,
        results,
        selected,
        source_audit,
        time.monotonic() - started,
        target_hosts,
        min_target_hosts_passed,
    )


def reselect_validation_artifacts(
    config: Mapping[str, Any],
    output_file: Path,
    report_file: Path,
) -> dict[str, Any]:
    try:
        report = json.loads(report_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("invalid validation report") from exc
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise ValueError("validation report has no reusable results")
    validation = config.get("validation") or {}
    selection = config.get("selection") or {}
    sources = config.get("sources") or []
    if not isinstance(validation, Mapping) or not isinstance(selection, Mapping) or not isinstance(sources, list):
        raise ValueError("invalid reselection configuration")

    configured_targets = validation_target_hosts(validation)
    configured_min_targets = validation_min_target_hosts_passed(validation, configured_targets)
    report_targets = report.get("target_hosts")
    if report_targets is None:
        if len(configured_targets) != 1:
            raise ValueError("legacy validation report cannot be reused for multiple target hosts")
        report_targets = list(configured_targets)
    elif normalize_target_hosts(report_targets) != configured_targets:
        raise ValueError("target hosts changed since validation")
    report_min_targets = report.get("min_target_hosts_passed")
    if report_min_targets is None:
        if configured_min_targets != len(configured_targets):
            raise ValueError("legacy validation report cannot be reused with target quorum")
        report_min_targets = len(configured_targets)
    if (
        normalize_min_target_hosts_passed(report_min_targets, len(configured_targets))
        != configured_min_targets
    ):
        raise ValueError("target host quorum changed since validation")

    resolver = PublicResolver()
    specs, source_audit = load_sources(
        sources,
        resolver,
        float(validation.get("timeout_seconds", 5.0)),
        int(validation.get("max_source_bytes", 4 * 1024 * 1024)),
    )
    expected_sources = {
        str(row.get("id")): str(row.get("sha256"))
        for row in report.get("sources") or []
        if isinstance(row, Mapping) and row.get("status") == "loaded"
    }
    live_sources = {
        str(row.get("id")): str(row.get("sha256"))
        for row in source_audit
        if row.get("status") == "loaded"
    }
    if not expected_sources or live_sources != expected_sources:
        raise ValueError("source hashes changed since validation")

    by_id: dict[str, ProxySpec] = {}
    for spec in specs:
        short_id = spec.fingerprint[:16]
        if short_id in by_id:
            raise ValueError("proxy fingerprint prefix collision")
        by_id[short_id] = spec
    reconstructed: list[ProbeResult] = []
    for raw in report["results"]:
        if not isinstance(raw, Mapping):
            raise ValueError("invalid validation result row")
        spec = by_id.get(str(raw.get("proxy_id") or ""))
        if spec is None:
            raise ValueError("validation result does not match current sources")
        # The report intentionally stores only a stable egress hash. Selection
        # needs identity and presence for de-duplication, not the raw IP.
        egress_identity = str(raw.get("egress_id") or "")
        reconstructed.append(
            ProbeResult(
                spec=spec,
                ok=bool(raw.get("ok")),
                category=str(raw.get("category") or "unknown"),
                latency_ms=float(raw.get("latency_ms") or 0),
                egress_ip=f"sha256:{egress_identity}" if egress_identity else "",
                region=str(raw.get("region") or ""),
                failed_target=str(raw.get("failed_target") or ""),
            )
        )
    selected = select_results(
        reconstructed,
        max_nodes=int(selection.get("max_nodes", MAX_POOL_NODES)),
        max_per_egress=int(selection.get("max_per_egress", 0)),
        allowed_regions=selection.get("allowed_regions") or [],
        require_egress=bool(selection.get("require_egress", True)),
        excluded_regions=selection.get("excluded_regions") or [],
        min_per_region=int(selection.get("min_per_region", 0)),
        max_per_source=int(selection.get("max_per_source", 0)),
        max_per_credential_group=int(selection.get("max_per_credential_group", 0)),
        preferred_source_ids=selection.get("preferred_source_ids") or [],
    )
    content = "".join(f"{row.spec.canonical}\n" for row in selected).encode("utf-8")
    atomic_write(output_file, content)
    report["selected_count"] = len(selected)
    report["unique_egress_count"] = len(
        {row.egress_ip for row in selected if row.egress_ip}
    )
    report["regions"] = dict(
        sorted(Counter(row.region or "unknown" for row in selected).items())
    )
    report["categories"] = dict(
        sorted(Counter(row.category for row in reconstructed).items())
    )
    report["selected_credential_group_count"] = len(
        {row.spec.credential_group_id for row in selected}
    )
    report["sources"] = build_source_reports(source_audit, reconstructed, selected)
    report["output_sha256"] = hashlib.sha256(content).hexdigest()
    report["target_hosts"] = list(configured_targets)
    report["min_target_hosts_passed"] = configured_min_targets
    report["reselected_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    report["reselection"] = {
        "max_nodes": min(
            int(selection.get("max_nodes", MAX_POOL_NODES)) or MAX_POOL_NODES,
            MAX_POOL_NODES,
        ),
        "max_per_egress": int(selection.get("max_per_egress", 0)),
        "max_per_source": int(selection.get("max_per_source", 0)),
        "max_per_credential_group": int(selection.get("max_per_credential_group", 0)),
        "min_per_region": int(selection.get("min_per_region", 0)),
        "allowed_regions": sorted(
            {str(item).strip().lower() for item in (selection.get("allowed_regions") or []) if str(item).strip()}
        ),
        "excluded_regions": sorted(
            {str(item).strip().lower() for item in (selection.get("excluded_regions") or []) if str(item).strip()}
        ),
        "require_egress": bool(selection.get("require_egress", True)),
    }
    atomic_write(report_file, (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    return report


__all__ = [
    "ProbeError",
    "ProxySpec",
    "PublicResolver",
    "atomic_write",
    "parse_proxy_line",
    "probe_many",
    "normalize_target_hosts",
    "normalize_min_target_hosts_passed",
    "reselect_validation_artifacts",
    "select_results",
    "validation_target_hosts",
    "validation_min_target_hosts_passed",
    "validation_from_config",
]
