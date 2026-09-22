#!/usr/bin/env python3
"""Build and probe an isolated sing-box bridge pool from a public config feed."""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import copy
import datetime as dt
import fcntl
import hashlib
from html.parser import HTMLParser
import http.client
import ipaddress
import json
import os
import random
import re
import signal
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from proxy_probe import (
    ProbeError,
    ProbeResult,
    ProxySpec,
    PublicResolver,
    atomic_write,
    normalize_min_target_hosts_passed,
    normalize_target_hosts,
    probe_many,
)


OWNER = "resin-pool-maintenance"
READABLE_OWNERS = {OWNER}
MAX_POOL_NODES = 1000
MIN_RETAIN_GENERATIONS = 1
USER_AGENT = "resin-singbox-bridge-pool/1"
SUPPORTED_TYPES = {"vless", "vmess", "trojan", "shadowsocks"}
ALLOWED_OUTBOUND_KEYS = {
    "vless": {"type", "server", "server_port", "uuid", "flow", "tls", "transport"},
    "vmess": {
        "type",
        "server",
        "server_port",
        "uuid",
        "security",
        "alter_id",
        "tls",
        "transport",
    },
    "trojan": {"type", "server", "server_port", "password", "tls", "transport"},
    "shadowsocks": {"type", "server", "server_port", "method", "password"},
}
ALLOWED_TLS_KEYS = {"enabled", "server_name", "utls", "reality"}
ALLOWED_UTLS_KEYS = {"enabled", "fingerprint"}
ALLOWED_REALITY_KEYS = {"enabled", "public_key", "short_id"}
ALLOWED_TRANSPORT_KEYS = {"type", "path", "headers", "service_name", "host"}
ALLOWED_TRANSPORT_TYPES = {"ws", "grpc", "httpupgrade"}
MAX_SOURCE_BYTES = 16 * 1024 * 1024
PRIVATE_LISTEN_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


class BridgeError(RuntimeError):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, RecursionError) as exc:
        raise BridgeError(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise BridgeError(f"JSON root must be an object: {path}")
    return value


def write_json(path: Path, value: Mapping[str, Any], mode: int = 0o600) -> None:
    data = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode()
    atomic_write(path, data, mode=mode)


def read_private_secret(path: Path, label: str) -> str:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BridgeError(f"cannot stat {label}") from exc
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise BridgeError(f"{label} must be a regular non-symlink file")
    if stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}:
        raise BridgeError(f"{label} must have mode 0400 or 0600")
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise BridgeError(f"cannot read {label}") from exc
    if not value:
        raise BridgeError(f"{label} is empty")
    return value


def configured_direct_port(args: argparse.Namespace) -> int:
    value = getattr(args, "direct_port", 0)
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return 0
    try:
        return int(value or 0)
    except ValueError:
        return 0


def managed_bridge_ports(
    base_port: int,
    count: int,
    *,
    reserved_port: int | None = None,
) -> list[int]:
    """Allocate stable bridge ports while leaving a fixed direct port unused."""
    if base_port < 1 or base_port > 65535:
        raise BridgeError("publish base port must be between 1 and 65535")
    if count < 0:
        raise BridgeError("bridge port count must not be negative")
    if reserved_port is not None and (reserved_port < 1 or reserved_port > 65535):
        raise BridgeError("direct publish port must be between 1 and 65535")

    ports: list[int] = []
    port = base_port
    while len(ports) < count:
        if port > 65535:
            raise BridgeError("publish port range exceeds 65535")
        if port != reserved_port:
            ports.append(port)
        port += 1
    return ports


def optional_text_argument(args: argparse.Namespace, name: str) -> str:
    value = getattr(args, name, "")
    return value if isinstance(value, str) else ""


def validate_publish_listen(value: str) -> str:
    """Require a literal RFC1918/ULA address for the published SOCKS pool."""
    text = str(value)
    if not text or text != text.strip() or "%" in text:
        raise BridgeError("publish listen must be a private literal IP")
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise BridgeError("publish listen must be a private literal IP") from exc
    if not any(address in network for network in PRIVATE_LISTEN_NETWORKS):
        raise BridgeError("publish listen must be a private literal IP")
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_global
    ):
        raise BridgeError("publish listen must be a private literal IP")
    return str(address)


def validate_probe_listen(value: str) -> str:
    text = str(value)
    if not text or text != text.strip() or "%" in text:
        raise BridgeError("probe listen must be a loopback literal IP")
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise BridgeError("probe listen must be a loopback literal IP") from exc
    if not address.is_loopback:
        raise BridgeError("probe listen must be a loopback literal IP")
    return str(address)


def format_proxy_host(host: str) -> str:
    """Format a host for a URI authority, including IPv6 brackets."""
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def validate_source_url(url: str, resolver: PublicResolver, *, discovery: bool = False) -> None:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise BridgeError("invalid source URL") from exc
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise BridgeError("source URL must be credential-free HTTPS")
    hosts = {"raw.githubusercontent.com", "gist.githubusercontent.com"}
    if discovery:
        hosts = {"gist.github.com", "api.github.com"}
    if parsed.hostname.lower() not in hosts:
        raise BridgeError("source URL host is not allowlisted")
    if port not in (None, 443):
        raise BridgeError("source URL port must be 443")
    if (parsed.query and not discovery) or parsed.fragment:
        raise BridgeError("source URL must not contain query or fragment")
    resolver.resolve(parsed.hostname, parsed.port or 443)


def download_source(url: str, timeout: float, max_bytes: int = MAX_SOURCE_BYTES,
                    *, discovery: bool = False) -> bytes:
    resolver = PublicResolver()
    try:
        validate_source_url(url, resolver, discovery=discovery)
        parsed = urllib.parse.urlsplit(url)
        resolved_ip, _ = resolver.resolve(parsed.hostname or "", parsed.port or 443)
    except ProbeError as exc:
        raise BridgeError("source DNS or address validation failed") from exc

    class PinnedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self) -> None:
            self.sock = socket.create_connection(
                (resolved_ip, self.port), self.timeout, self.source_address
            )
            if self._context is None:
                self._context = ssl.create_default_context()
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)

    connection = PinnedHTTPSConnection(
        parsed.hostname or "", parsed.port or 443, timeout=timeout
    )
    try:
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        connection.request(
            "GET",
            path,
            headers={"Accept": "*/*", "User-Agent": USER_AGENT},
        )
        response = connection.getresponse()
        if response.status != 200:
            raise BridgeError(f"source download returned HTTP {response.status}")
        try:
            length = response.headers.get("Content-Length")
            if length and int(length) > max_bytes:
                raise BridgeError("source exceeds size limit")
            data = response.read(max_bytes + 1)
        finally:
            response.close()
    except (http.client.HTTPException, OSError, ValueError) as exc:
        raise BridgeError("source download failed") from exc
    finally:
        connection.close()
    if len(data) > max_bytes:
        raise BridgeError("source exceeds size limit")
    return data


class GistSearchResults(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.depth = 0
        self.snippet_depth: int | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        classes = (attributes.get("class") or "").split()
        if tag == "div":
            self.depth += 1
            if "gist-snippet" in classes:
                self.snippet_depth = self.depth
        if tag != "a" or self.snippet_depth is None or "Link--muted" not in classes:
            return
        href = attributes.get("href") or ""
        parsed = urllib.parse.urlsplit(href)
        if parsed.netloc or parsed.scheme or parsed.fragment or parsed.query:
            return
        match = re.fullmatch(r"/[A-Za-z0-9-]+/([a-f0-9]{20,40})", parsed.path)
        if match and match[1] not in self.ids:
            self.ids.append(match[1])

    def handle_endtag(self, tag: str) -> None:
        if tag == "div":
            if self.snippet_depth == self.depth:
                self.snippet_depth = None
            self.depth = max(0, self.depth - 1)


def convert_candidates(data: bytes, converter: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    try:
        return load_candidates(data)
    except (BridgeError, UnicodeDecodeError):
        if not converter:
            raise BridgeError("non-singbox source requires the subscription converter")
    if len(data) > MAX_SOURCE_BYTES:
        raise BridgeError("converter input exceeds size limit")
    try:
        with tempfile.TemporaryFile() as output:
            result = subprocess.run([converter], input=data, stdout=output, stderr=subprocess.DEVNULL,
                                    timeout=15, check=False)
            if result.returncode:
                raise BridgeError("subscription converter rejected source")
            output.seek(0)
            converted = output.read(MAX_SOURCE_BYTES + 1)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BridgeError("subscription converter failed") from exc
    if len(converted) > MAX_SOURCE_BYTES:
        raise BridgeError("converter output exceeds size limit")
    return load_candidates(converted)


def discovery_error(exc: Exception, stage: str) -> dict[str, Any]:
    # Never persist raw parser errors or upstream response bodies; they can contain credentials.
    message = str(exc) if isinstance(exc, BridgeError) else ""
    code = re.fullmatch(r"source download returned HTTP ([0-9]{3})", message)
    if code:
        return {"error_stage": stage, "error": "http_status", "http_status": int(code[1])}
    kind = ("dns_or_address" if "DNS or address validation" in message else
            "budget_exhausted" if message == "discovery time budget exhausted" else
            "size_limit" if "size limit" in message else
            "format_or_unsupported" if stage == "parse" else "unavailable")
    return {"error_stage": stage, "error": kind}


def discover_sources(args: argparse.Namespace, output_dir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    config_path = optional_text_argument(args, "discovery_config")
    if not config_path:
        return [], {"status": "disabled"}
    config = load_json(Path(config_path))
    if config.get("version") != 1:
        raise BridgeError("invalid discovery configuration version")
    sources = config.get("sources", [])
    gist = config.get("gist", {})
    if not isinstance(gist, dict):
        raise BridgeError("invalid Gist configuration")
    protocols = gist.get("protocols", [])
    pinned_gists = gist.get("ids", [])
    if (not isinstance(sources, list) or len(sources) > 8
            or any(not isinstance(url, str) for url in sources)
            or not isinstance(protocols, list) or len(protocols) > 4
            or any(protocol not in {"ss", "vless", "vmess", "trojan"} for protocol in protocols)
            or not isinstance(pinned_gists, list) or len(pinned_gists) > 6
            or any(not isinstance(gist_id, str) or not re.fullmatch(r"[a-f0-9]{20,40}", gist_id)
                   for gist_id in pinned_gists)):
        raise BridgeError("invalid discovery source list")
    try:
        interval = int(config.get("refresh_hours", 6)) * 3600
        limit = int(config.get("candidate_limit", 300))
        max_gists = int(gist.get("max_gists", 4))
        max_files = int(gist.get("max_files", 4))
        if not (3600 <= interval <= 86400 and 1 <= limit <= 1000
                and 1 <= max_gists <= 6 and 1 <= max_files <= 6):
            raise ValueError
    except (ValueError, TypeError) as exc:
        raise BridgeError("invalid discovery limits") from exc
    now = time.time()
    config_hash = sha256_bytes(json.dumps(config, sort_keys=True).encode())
    cache_path = output_dir / "discovery-cache.json"
    cache: dict[str, Any] = {}
    if cache_path.exists():
        cache = load_json(cache_path)
        if cache.get("owner") != OWNER or cache.get("config_sha256") != config_hash:
            cache = {}
    cached: list[dict[str, Any]] = []
    if cache.get("candidates") and 0 <= now - cache.get("fetched_at", 0) < 86400:
        cached, _ = load_candidates(json.dumps({"outbounds": cache["candidates"]}).encode())
    if cache.get("discovery_version") == 2 and 0 <= now - cache.get("attempted_at", 0) < interval:
        return cached[:limit], dict(cache.get("report", {}), cache_hit=True, candidate_count=min(len(cached), limit))
    deadline = time.monotonic() + 120
    report: dict[str, Any] = {"version": 2, "status": "success", "cache_hit": False, "sources": [],
                            "search_errors": 0, "search_failures": []}

    def fetch(url: str, metadata: bool = False) -> bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BridgeError("discovery time budget exhausted")
        return download_source(url, min(args.download_timeout, 10, remaining),
                               2 * 1024 * 1024 if metadata else MAX_SOURCE_BYTES, discovery=metadata)

    gist_ids = list(dict.fromkeys(pinned_gists))[:max_gists]
    # Interleave protocol results so one protocol cannot consume the whole budget.
    searches: list[list[str]] = []
    for protocol in protocols:
        try:
            query = urllib.parse.urlencode({"q": protocol + "://", "s": "updated", "o": "desc"})
            parser = GistSearchResults()
            parser.feed(fetch("https://gist.github.com/search?" + query, True).decode("utf-8"))
            searches.append(parser.ids[:max_gists])
            if not parser.ids:
                report["search_errors"] += 1
                report["search_failures"].append({"stage": "search", "protocol": protocol, "error": "no_results"})
        except (BridgeError, UnicodeError, ValueError) as exc:
            report["search_errors"] += 1
            report["search_failures"].append({"stage": "search", "protocol": protocol, **discovery_error(exc, "search")})
    for index in range(max_gists):
        for result in searches:
            if index < len(result) and result[index] not in gist_ids and len(gist_ids) < max_gists:
                gist_ids.append(result[index])
    urls = list(dict.fromkeys(sources))
    source_kinds = {url: "configured" for url in urls}
    raw_count = 0
    for gist_id in gist_ids:
        if raw_count >= max_files:
            break
        try:
            metadata = json.loads(fetch("https://api.github.com/gists/" + gist_id, True))
            if metadata.get("public") is not True or metadata.get("id") != gist_id:
                raise BridgeError("Gist is not public")
            files = sorted(metadata.get("files", {}).values(),
                           key=lambda item: (Path(item.get("filename", "")).suffix.lower() not in {".yaml", ".yml"},
                                             -int(item.get("size", 0))))
            for file in files:
                if (Path(file.get("filename", "")).suffix.lower() not in {".yaml", ".yml", ".json", ".txt", ".conf", ""}
                        or file.get("language") not in (None, "Text", "JSON", "YAML", "INI")):
                    continue
                url = file.get("raw_url", "")
                parsed = urllib.parse.urlsplit(url)
                if (parsed.hostname != "gist.githubusercontent.com" or gist_id not in parsed.path.split("/")
                        or not isinstance(file.get("size"), int) or not 0 < file["size"] <= MAX_SOURCE_BYTES):
                    continue
                if url not in urls:
                    urls.append(url)
                    source_kinds[url] = "pinned_gist" if gist_id in pinned_gists else "search_gist"
                    raw_count += 1
                break
        except (BridgeError, ValueError, TypeError, AttributeError, RecursionError) as exc:
            report["search_errors"] += 1
            report["search_failures"].append({"stage": "metadata", "gist_id_hash": sha256_bytes(gist_id.encode())[:16],
                                              **discovery_error(exc, "metadata")})
    candidates: dict[str, dict[str, Any]] = {}
    converter = optional_text_argument(args, "subscription_converter")
    for url in urls:
        source = {"id": sha256_bytes(url.encode())[:16], "status": "failed", "kind": source_kinds[url]}
        stage = "download"
        try:
            data = fetch(url)
            stage = "parse"
            rows, _ = convert_candidates(data, converter)
            if not rows:
                raise BridgeError("source contained no supported candidates")
            source.update(status="success", content_sha256=sha256_bytes(data), supported_count=len(rows))
            random.Random(sha256_bytes(data)).shuffle(rows)
            for row in rows[:limit]:
                candidates.setdefault(endpoint_key(row), row)
        except (BridgeError, UnicodeError, ValueError) as exc:
            source.update(discovery_error(exc, stage))
        report["sources"].append(source)
    selected = list(candidates.values())
    random.Random(int(now // interval)).shuffle(selected)
    report["discovered_count"] = len(selected)
    report["sources_ok"] = sum(source["status"] == "success" for source in report["sources"])
    report["sources_ok_by_kind"] = {kind: sum(source["status"] == "success" and source["kind"] == kind
                                             for source in report["sources"])
                                    for kind in ("configured", "pinned_gist", "search_gist")}
    report["status"] = ("success" if report["sources_ok"] == len(urls) and not report["search_errors"] and urls
                        else "partial" if selected else "failed")
    if not selected:
        selected = cached
        report["cached_fallback"] = bool(cached)
    selected = selected[:limit]
    report["candidate_count"] = len(selected)
    write_json(cache_path, {"version": 1, "discovery_version": 2, "owner": OWNER, "config_sha256": config_hash,
        "attempted_at": now, "fetched_at": now if candidates else cache.get("fetched_at", 0),
        "candidates": selected, "report": report})
    return selected, report


def _copy_keys(value: Mapping[str, Any], allowed: set[str]) -> dict[str, Any]:
    return {key: copy.deepcopy(value[key]) for key in allowed if key in value}


def sanitize_outbound(raw: Mapping[str, Any]) -> dict[str, Any]:
    pending: list[tuple[Any, int]] = [(raw, 0)]
    while pending:
        value, depth = pending.pop()
        if depth > 12:
            raise BridgeError("outbound nesting exceeds limit")
        if isinstance(value, dict):
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)
    outbound_type = str(raw.get("type") or "")
    if outbound_type not in SUPPORTED_TYPES:
        raise BridgeError("unsupported outbound type")
    outbound = _copy_keys(raw, ALLOWED_OUTBOUND_KEYS[outbound_type])
    server = str(outbound.get("server") or "").strip()
    try:
        port = int(outbound.get("server_port") or 0)
    except (TypeError, ValueError) as exc:
        raise BridgeError("invalid server port") from exc
    if not server or port < 1 or port > 65535:
        raise BridgeError("invalid server endpoint")
    outbound["server"] = server
    outbound["server_port"] = port

    if "tls" in outbound:
        if not isinstance(outbound["tls"], Mapping):
            raise BridgeError("invalid TLS settings")
        tls = _copy_keys(outbound["tls"], ALLOWED_TLS_KEYS)
        if "utls" in tls:
            if not isinstance(tls["utls"], Mapping):
                raise BridgeError("invalid uTLS settings")
            tls["utls"] = _copy_keys(tls["utls"], ALLOWED_UTLS_KEYS)
        if "reality" in tls:
            if not isinstance(tls["reality"], Mapping):
                raise BridgeError("invalid Reality settings")
            tls["reality"] = _copy_keys(tls["reality"], ALLOWED_REALITY_KEYS)
        outbound["tls"] = tls

    if "transport" in outbound:
        if not isinstance(outbound["transport"], Mapping):
            raise BridgeError("invalid transport settings")
        transport = _copy_keys(outbound["transport"], ALLOWED_TRANSPORT_KEYS)
        if transport.get("type") not in ALLOWED_TRANSPORT_TYPES:
            raise BridgeError("unsupported transport type")
        headers = transport.get("headers")
        if headers is not None:
            if not isinstance(headers, Mapping) or set(headers) - {"Host"}:
                raise BridgeError("unsupported transport headers")
            transport["headers"] = (
                {"Host": copy.deepcopy(headers["Host"])} if "Host" in headers else {}
            )
        outbound["transport"] = transport
    return outbound


def endpoint_key(outbound: Mapping[str, Any]) -> str:
    server = str(outbound["server"]).lower().rstrip(".")
    identity = sanitize_outbound(outbound)
    identity["server"] = server
    # SNI, Reality keys and transport paths are part of a connection, not aliases.
    configuration_digest = sha256_bytes(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    )
    return f"{outbound['type']}|{server}|{int(outbound['server_port'])}|{configuration_digest}"


def endpoint_id(outbound: Mapping[str, Any]) -> str:
    return hashlib.sha256(endpoint_key(outbound).encode()).hexdigest()[:16]


def credential_group_id(outbound: Mapping[str, Any]) -> str:
    outbound_type = str(outbound["type"])
    if outbound_type in {"vless", "vmess"}:
        credential = str(outbound.get("uuid") or "")
    elif outbound_type == "trojan":
        credential = str(outbound.get("password") or "")
    else:
        credential = "\0".join(
            (str(outbound.get("method") or ""), str(outbound.get("password") or ""))
        )
    return hashlib.sha256(f"{outbound_type}\0{credential}".encode()).hexdigest()[:16]


def resolve_public_endpoint(outbound: Mapping[str, Any]) -> str:
    server = str(outbound["server"])
    port = int(outbound["server_port"])
    try:
        literal = ipaddress.ip_address(server)
    except ValueError:
        literal = None
    if literal is not None:
        if not literal.is_global:
            raise BridgeError("non-public server endpoint")
        return str(literal)
    try:
        infos = socket.getaddrinfo(server, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise BridgeError("server DNS failed") from exc
    addresses = {
        info[4][0]
        for info in infos
        if info[0] in (socket.AF_INET, socket.AF_INET6)
    }
    if not addresses:
        raise BridgeError("server DNS returned no address")
    for address in addresses:
        try:
            if not ipaddress.ip_address(address).is_global:
                raise BridgeError("server DNS includes non-public address")
        except ValueError as exc:
            raise BridgeError("server DNS returned invalid address") from exc
    return sorted(
        addresses,
        key=lambda item: (ipaddress.ip_address(item).version != 4, item),
    )[0]


def pin_public_endpoint(outbound: Mapping[str, Any]) -> dict[str, Any]:
    pinned = copy.deepcopy(dict(outbound))
    original_server = str(pinned["server"])
    address = resolve_public_endpoint(pinned)
    try:
        ipaddress.ip_address(original_server)
        original_is_ip = True
    except ValueError:
        original_is_ip = False
    if address == original_server or original_is_ip:
        return pinned
    pinned["server"] = address
    tls = pinned.get("tls")
    if isinstance(tls, dict) and tls.get("enabled") is True and not tls.get("server_name"):
        tls["server_name"] = original_server
    transport = pinned.get("transport")
    if isinstance(transport, dict) and transport.get("type") in {"ws", "httpupgrade"}:
        headers = transport.setdefault("headers", {})
        if isinstance(headers, dict) and not headers.get("Host"):
            headers["Host"] = original_server
    if (
        isinstance(transport, dict)
        and transport.get("type") == "grpc"
        and not isinstance(tls, dict)
    ):
        raise BridgeError("cannot safely pin plaintext gRPC endpoint")
    return pinned


def load_candidates(data: bytes) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    try:
        document = json.loads(data)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise BridgeError("source is not valid JSON") from exc
    raw_outbounds = document.get("outbounds") if isinstance(document, dict) else None
    if not isinstance(raw_outbounds, list):
        raise BridgeError("source lacks an outbound array")

    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    categories: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    for raw in raw_outbounds:
        if not isinstance(raw, Mapping) or raw.get("type") not in SUPPORTED_TYPES:
            continue
        try:
            outbound = sanitize_outbound(raw)
        except BridgeError as exc:
            categories[str(exc)] += 1
            continue
        key = endpoint_key(outbound)
        if key in seen:
            categories["duplicate_endpoint"] += 1
            continue
        seen.add(key)
        protocols[str(outbound["type"])] += 1
        candidates.append(outbound)
    if not candidates:
        raise BridgeError("source yielded no supported candidates")
    return candidates, {
        "supported_input_count": sum(protocols.values()) + categories["duplicate_endpoint"],
        "unique_endpoint_count": len(candidates),
        "protocols": dict(sorted(protocols.items())),
        "rejected": dict(sorted(categories.items())),
    }


def _current_generation_dir(output_dir: Path) -> Path | None:
    pointer = output_dir / "current"
    if not pointer.exists() and not pointer.is_symlink():
        return None
    if not pointer.is_symlink():
        raise BridgeError("current pointer is not a symlink")
    generation_dir = pointer.resolve()
    generations_dir = (output_dir / "generations").resolve()
    if generation_dir.parent != generations_dir or not generation_dir.is_dir():
        raise BridgeError("current pointer is invalid")
    return generation_dir


def _staged_generation_dir(output_dir: Path) -> tuple[bool, Path | None]:
    """Return whether a transaction exists and its previous generation.

    A staged pointer to the generations directory itself records that the
    transaction had no previous generation.
    """
    pointer = output_dir / "staged"
    if not pointer.exists() and not pointer.is_symlink():
        return False, None
    if not pointer.is_symlink():
        raise BridgeError("staged pointer is not a symlink")
    target = pointer.resolve()
    generations_dir = (output_dir / "generations").resolve()
    if target == generations_dir:
        return True, None
    if target.parent != generations_dir or not target.is_dir():
        raise BridgeError("staged pointer is invalid")
    return True, target


def _fsync_directory(path: Path) -> None:
    directory_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _remove_pointer(path: Path) -> None:
    if not path.is_symlink():
        raise BridgeError(f"{path.name} pointer is missing")
    path.unlink()
    _fsync_directory(path.parent)


@contextlib.contextmanager
def exclusive_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise BridgeError("bridge output directory is invalid")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise BridgeError("bridge operation lock is invalid") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise BridgeError("bridge operation lock is not a regular file")
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise BridgeError("another bridge pool operation is active") from exc
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def load_current_candidates(output_dir: Path, target: int) -> list[dict[str, Any]]:
    generation_dir = _current_generation_dir(output_dir)
    if generation_dir is None:
        return []
    config_path = generation_dir / "bridge.json"
    if not config_path.is_file() or config_path.stat().st_mode & 0o077:
        raise BridgeError("current bridge configuration is invalid")
    config = load_json(config_path)
    raw_outbounds = config.get("outbounds")
    if not isinstance(raw_outbounds, list):
        raise BridgeError("current bridge configuration lacks outbounds")
    current: list[dict[str, Any]] = []
    for raw in raw_outbounds:
        if not isinstance(raw, Mapping) or raw.get("type") not in SUPPORTED_TYPES:
            continue
        try:
            # Revalidate the persisted generation before allowing it to keep a
            # slot. This also pins a hostname if an older generation used one.
            current.append(pin_public_endpoint(sanitize_outbound(raw)))
        except BridgeError as exc:
            raise BridgeError("current bridge contains an invalid endpoint") from exc
    if len(current) > target:
        raise BridgeError("current bridge has more nodes than the configured target")
    return current


def public_candidate_subset(
    candidates: Sequence[dict[str, Any]],
    *,
    seed: str,
    limit: int,
    workers: int,
) -> tuple[list[dict[str, Any]], Counter[str]]:
    if limit < 0:
        raise BridgeError("candidate limit must not be negative")
    ordered = list(candidates)
    random.Random(seed).shuffle(ordered)
    errors: Counter[str] = Counter()
    public: list[dict[str, Any]] = []
    seen_pinned_endpoints: set[str] = set()

    def check(item: dict[str, Any]) -> tuple[dict[str, Any], str]:
        try:
            return pin_public_endpoint(item), ""
        except BridgeError as exc:
            return item, str(exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for item, error in pool.map(check, ordered):
            if error:
                errors[error] += 1
                continue
            key = endpoint_key(item)
            if key in seen_pinned_endpoints:
                errors["duplicate_pinned_endpoint"] += 1
                continue
            seen_pinned_endpoints.add(key)
            public.append(item)
            # A zero limit means probe every source candidate. The final
            # fixed-slot selection still enforces MAX_POOL_NODES.
            if limit > 0 and len(public) >= limit:
                break
        pool.shutdown(wait=True, cancel_futures=True)
    return public, errors


def build_config(
    candidates: Sequence[dict[str, Any]],
    *,
    listen: str,
    base_port: int,
    direct_port: int | None = None,
    direct_username: str = "",
    direct_password: str = "",
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if direct_port is not None:
        if direct_port < 1 or direct_port > 65535:
            raise BridgeError("direct publish port must be between 1 and 65535")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", direct_username):
            raise BridgeError("direct SOCKS username is invalid")
        if not direct_password or direct_password != direct_password.strip():
            raise BridgeError("direct SOCKS password is invalid")
    bridge_ports = managed_bridge_ports(
        base_port,
        len(candidates),
        reserved_port=direct_port,
    )
    outbounds: list[dict[str, Any]] = [{"type": "direct", "tag": "direct"}]
    bridges: list[dict[str, Any]] = []
    inbounds: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    for index, (raw, port) in enumerate(zip(candidates, bridge_ports)):
        tag = f"candidate-{index:04d}"
        inbound_tag = f"bridge-{index:04d}"
        outbound = copy.deepcopy(raw)
        outbound["tag"] = tag
        outbounds.append(outbound)
        inbounds.append(
            {
                "type": "socks",
                "tag": inbound_tag,
                "listen": listen,
                "listen_port": port,
            }
        )
        rules.append({"inbound": [inbound_tag], "action": "route", "outbound": tag})
        bridges.append(
            {
                "index": index,
                "tag": tag,
                "inbound_tag": inbound_tag,
                "port": port,
                "endpoint_id": endpoint_id(raw),
                "protocol": raw["type"],
            }
        )
    if direct_port is not None:
        direct_tag = "managed-direct-egress"
        inbounds.append(
            {
                "type": "socks",
                "tag": direct_tag,
                "listen": listen,
                "listen_port": direct_port,
                "users": [{"username": direct_username, "password": direct_password}],
            }
        )
        rules.append({"inbound": [direct_tag], "action": "route", "outbound": "direct"})
    config = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "final": "direct"},
    }
    return config, bridges


def run_singbox_check(binary: Path, config_path: Path, *, timeout: float = 60) -> None:
    try:
        result = subprocess.run(
            [str(binary), "check", "-c", str(config_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BridgeError("sing-box configuration check failed or timed out") from exc
    if result.returncode != 0:
        raise BridgeError("sing-box rejected generated configuration")


def compatible_candidates(binary: Path, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Isolate malformed discovery nodes before they can invalidate the entire bridge."""
    with tempfile.TemporaryDirectory(prefix="resin-discovery-check-") as directory:
        path = Path(directory) / "check.json"
        deadline = time.monotonic() + 30
        checks = 0

        def check(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
            nonlocal checks
            remaining = deadline - time.monotonic()
            if not rows or remaining <= 0 or checks >= 64:
                return []
            checks += 1
            config, _ = build_config(rows, listen="127.0.0.1", base_port=20000)
            write_json(path, config)
            try:
                run_singbox_check(binary, path, timeout=min(5, remaining))
                return rows
            except BridgeError:
                if len(rows) == 1:
                    return []
                middle = len(rows) // 2
                return check(rows[:middle]) + check(rows[middle:])

        return check(candidates)


def wait_for_ports(listen: str, ports: Iterable[int], process: subprocess.Popen[Any]) -> None:
    pending = set(ports)
    deadline = time.monotonic() + 20
    while pending and time.monotonic() < deadline:
        if process.poll() is not None:
            raise BridgeError("sing-box exited before probe startup")
        for port in list(pending):
            try:
                with socket.create_connection((listen, port), timeout=0.2):
                    pending.remove(port)
            except OSError:
                pass
        if pending:
            time.sleep(0.1)
    if pending:
        raise BridgeError("sing-box bridge startup timed out")


def configured_listeners(config: Mapping[str, Any]) -> set[tuple[str, int]]:
    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list) or not 1 <= len(inbounds) <= MAX_POOL_NODES + 1:
        raise BridgeError("invalid bridge listener configuration")
    expected: set[tuple[str, int]] = set()
    for inbound in inbounds:
        if not isinstance(inbound, dict) or inbound.get("type") != "socks":
            raise BridgeError("unexpected bridge listener type")
        listen = validate_publish_listen(inbound.get("listen", ""))
        port = inbound.get("listen_port")
        if type(port) is not int or not 1 <= port <= 65535:
            raise BridgeError("invalid bridge listener port")
        if (listen, port) in expected:
            raise BridgeError("duplicate bridge listener")
        expected.add((listen, port))
    return expected


def process_identity(process_dir: Path) -> str:
    try:
        fields = (process_dir / "stat").read_text().rsplit(")", 1)[1].split()
        if fields[0] in {"Z", "X"}:
            raise BridgeError("bridge process exited before readiness")
        return fields[19]
    except (OSError, IndexError) as exc:
        raise BridgeError("bridge process unavailable before readiness") from exc


def process_tcp_listeners(process_dir: Path) -> set[tuple[str, int]]:
    # The network tables contain other processes too; match this PID's socket FDs.
    try:
        owned = set()
        for descriptor in (process_dir / "fd").iterdir():
            try:
                target = str(descriptor.readlink())
            except FileNotFoundError:
                continue
            match = re.fullmatch(r"socket:\[(\d+)\]", target)
            if match:
                owned.add(match.group(1))
        listeners = set()
        for table in ("tcp", "tcp6"):
            try:
                lines = (process_dir / "net" / table).read_text().splitlines()[1:]
            except FileNotFoundError:
                if table == "tcp6":
                    continue
                raise
            for line in lines:
                fields = line.split()
                if fields[3] != "0A" or fields[9] not in owned:
                    continue
                address, port = fields[1].split(":")
                packed = b"".join(
                    int(address[index:index + 8], 16).to_bytes(4, sys.byteorder)
                    for index in range(0, len(address), 8)
                )
                listeners.add((str(ipaddress.ip_address(packed)), int(port, 16)))
        return listeners
    except (OSError, ValueError, IndexError, OverflowError) as exc:
        raise BridgeError("cannot inspect bridge process listeners") from exc


def command_wait_listeners(args: argparse.Namespace) -> int:
    if args.pid <= 1 or not 0 < args.timeout_seconds <= 120:
        raise BridgeError("invalid bridge readiness PID or timeout")
    expected = configured_listeners(load_json(Path(args.output_dir) / "current" / "bridge.json"))
    process_dir = Path("/proc") / str(args.pid)
    identity = process_identity(process_dir)
    started = time.monotonic()
    deadline = started + args.timeout_seconds
    while True:
        if process_identity(process_dir) != identity:
            raise BridgeError("bridge process changed before readiness")
        pending = expected - process_tcp_listeners(process_dir)
        if process_identity(process_dir) != identity:
            raise BridgeError("bridge process changed before readiness")
        if not pending:
            print(json.dumps({"status": "ready", "listener_count": len(expected),
                              "elapsed_seconds": round(time.monotonic() - started, 3)}))
            return 0
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BridgeError(f"bridge listener readiness timed out: missing={len(pending)}")
        time.sleep(min(0.1, remaining))


def startup_error_detail(log_path: Path) -> str:
    # Classify stderr without disclosing upstream addresses or credentials.
    with log_path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        handle.seek(max(0, handle.tell() - 8192))
        message = handle.read().decode("utf-8", errors="replace")
    for text, category in (
        ("address already in use", "listen_address_in_use"),
        ("too many open files", "file_descriptor_limit"),
        ("permission denied", "permission_denied"),
        ("cannot assign requested address", "listen_address_unavailable"),
        ("out of memory", "out_of_memory"),
    ):
        if text in message.lower():
            return category
    return "unclassified_startup_failure"


def terminate_process(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def probe_candidates(
    binary: Path,
    candidates: Sequence[dict[str, Any]],
    *,
    listen: str,
    base_port: int,
    timeout: float,
    workers: int,
    batch_size: int,
    target_host: str | Sequence[str],
    min_target_hosts_passed: int | None = None,
) -> tuple[list[ProbeResult], list[dict[str, Any]]]:
    config, bridges = build_config(candidates, listen=listen, base_port=base_port)
    runtime_root = Path(os.environ.get("RUNTIME_DIRECTORY") or "/run")
    runtime_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="resin-singbox-probe-", dir=runtime_root) as temp:
        runtime_dir = Path(temp)
        os.chmod(runtime_dir, 0o700)
        config_path = runtime_dir / "bridge.json"
        write_json(config_path, config)
        run_singbox_check(binary, config_path)
        log_path = runtime_dir / "startup.log"
        with log_path.open("wb") as startup_log:
            process = subprocess.Popen(
                [str(binary), "run", "-c", str(config_path)],
                stdout=startup_log,
                stderr=startup_log,
                start_new_session=True,
            )
            try:
                try:
                    wait_for_ports(listen, (row["port"] for row in bridges), process)
                except BridgeError as exc:
                    raise BridgeError(f"{exc}; cause={startup_error_detail(log_path)}") from exc
                specs = [
                    ProxySpec(
                        "socks5h",
                        listen,
                        row["port"],
                        source_ids=("fixed-port-singbox-bridge",),
                        allowed_non_public_ip=(
                            listen if not ipaddress.ip_address(listen).is_global else ""
                        ),
                        credential_group_override=credential_group_id(
                            candidates[row["index"]]
                        ),
                    )
                    for row in bridges
                ]
                results = probe_many(
                    specs,
                    timeout=timeout,
                    workers=workers,
                    batch_size=batch_size,
                    target_host=target_host,
                    trace_egress=True,
                    min_target_hosts_passed=min_target_hosts_passed,
                )
            finally:
                terminate_process(process)
    return results, bridges


def select_fixed_slots(
    candidates: Sequence[dict[str, Any]],
    results: Sequence[ProbeResult],
    bridges: Sequence[dict[str, Any]],
    target: int,
    max_per_credential_group: int,
    *,
    max_per_egress: int = 0,
    current_count: int = 0,
    excluded_regions: Iterable[str] = (),
) -> tuple[list[dict[str, Any]], list[ProbeResult], dict[str, int]]:
    """Retain healthy current slots in order and fill holes with new results.

    ``candidates`` is ordered as current generation first, then new candidates.
    The returned candidate/result lists are slot ordered, so a retained node
    keeps its port and a replacement occupies the first empty slot.
    """
    if target < 1:
        raise BridgeError("target node count must be positive")
    if current_count < 0 or current_count > target or current_count > len(candidates):
        raise BridgeError("current bridge exceeds the configured target")
    if max_per_credential_group < 0:
        raise BridgeError("max per credential group must not be negative")
    if max_per_egress < 0:
        raise BridgeError("max per egress must not be negative")

    excluded = {
        str(item).strip().lower()
        for item in excluded_regions
        if str(item).strip()
    }

    by_port = {int(row["port"]): index for index, row in enumerate(bridges)}
    by_index: dict[int, ProbeResult] = {}
    for result in results:
        index = by_port.get(int(result.spec.port))
        if index is not None and index not in by_index:
            by_index[index] = result

    slots: list[dict[str, Any] | None] = [None] * target
    slot_results: list[ProbeResult | None] = [None] * target
    holes = list(range(current_count, target))
    egress_counts: Counter[str] = Counter()
    credential_counts: Counter[str] = Counter()
    retained_count = 0
    retained_unhealthy_count = 0
    replaced_count = 0
    added_count = 0

    def eligible(index: int) -> ProbeResult | None:
        result = by_index.get(index)
        if (
            result is None
            or not result.ok
            or not result.egress_ip
            or result.region.strip().lower() in excluded
        ):
            return None
        if max_per_egress > 0 and egress_counts[result.egress_ip] >= max_per_egress:
            return None
        group = result.spec.credential_group_id
        if max_per_credential_group > 0 and credential_counts[group] >= max_per_credential_group:
            return None
        egress_counts[result.egress_ip] += 1
        credential_counts[group] += 1
        return result

    # The first current_count entries are fixed slots. A failed or duplicate
    # current result leaves its original slot in ``holes``.
    for index in range(current_count):
        result = eligible(index)
        if result is None:
            holes.append(index)
            continue
        slots[index] = copy.deepcopy(candidates[index])
        slot_results[index] = result
        retained_count += 1
    holes.sort()

    # Fill holes in slot order using only new candidates, preserving source
    # order and never displacing an already retained current node.
    hole_index = 0
    for index in range(current_count, len(candidates)):
        if hole_index >= len(holes):
            break
        result = eligible(index)
        if result is None:
            continue
        slot = holes[hole_index]
        hole_index += 1
        slots[slot] = copy.deepcopy(candidates[index])
        slot_results[slot] = result
        if slot < current_count:
            replaced_count += 1
        else:
            added_count += 1

    # Keep an unreplaced failed current slot at the same local port. Resin's
    # circuit breaker already excludes it; collapsing the hole would silently
    # move every later upstream behind a different fixed bridge port.
    for index in range(current_count):
        if slots[index] is None:
            slots[index] = copy.deepcopy(candidates[index])
            retained_unhealthy_count += 1

    chosen = [candidate for candidate in slots if candidate is not None]
    selected = [row for row in slot_results if row is not None]
    return chosen, selected, {
        "retained_count": retained_count,
        "retained_unhealthy_count": retained_unhealthy_count,
        "replaced_count": replaced_count,
        "added_count": added_count,
    }


def _probe_candidates_by_port(
    probe_candidates: Sequence[dict[str, Any]],
    probe_bridges: Sequence[Mapping[str, Any]],
) -> dict[int, dict[str, Any]]:
    by_port: dict[int, dict[str, Any]] = {}
    for position, row in enumerate(probe_bridges):
        try:
            port = int(row["port"])
            index = int(row.get("index", position))
        except (KeyError, TypeError, ValueError) as exc:
            raise BridgeError("probe bridge mapping is invalid") from exc
        if index < 0 or index >= len(probe_candidates):
            raise BridgeError("probe bridge candidate index is invalid")
        if port in by_port:
            raise BridgeError("probe bridge ports are duplicated")
        by_port[port] = probe_candidates[index]
    return by_port


def healthy_slot_indices(
    chosen: Sequence[dict[str, Any]],
    selected_results: Sequence[ProbeResult],
    probe_candidates: Sequence[dict[str, Any]],
    probe_bridges: Sequence[Mapping[str, Any]],
) -> list[int]:
    """Map healthy probe results back to the fixed slots in ``chosen``."""
    candidates_by_port = _probe_candidates_by_port(probe_candidates, probe_bridges)
    healthy_endpoint_ids: set[str] = set()
    for result in selected_results:
        try:
            candidate = candidates_by_port[int(result.spec.port)]
        except (KeyError, TypeError, ValueError) as exc:
            raise BridgeError("selected probe result has no candidate mapping") from exc
        healthy_endpoint_ids.add(endpoint_id(candidate))
    if len(healthy_endpoint_ids) != len(selected_results):
        raise BridgeError("selected probe results contain duplicate candidates")

    indices = [
        index
        for index, candidate in enumerate(chosen)
        if endpoint_id(candidate) in healthy_endpoint_ids
    ]
    if len(indices) != len(healthy_endpoint_ids):
        raise BridgeError("selected probe result is not present in the fixed slots")
    return indices


def build_subscription(
    listen: str,
    bridges: Sequence[Mapping[str, Any]],
    published_indices: Sequence[int],
) -> bytes:
    """Build the Resin source using only healthy fixed-slot bridge ports."""
    proxy_host = format_proxy_host(listen)
    seen: set[int] = set()
    lines: list[str] = []
    for raw_index in published_indices:
        try:
            index = int(raw_index)
        except (TypeError, ValueError) as exc:
            raise BridgeError("published bridge slot is invalid") from exc
        if index < 0 or index >= len(bridges):
            raise BridgeError("published bridge slots are duplicated or out of range")
        try:
            port = int(bridges[index]["port"])
        except (KeyError, TypeError, ValueError) as exc:
            raise BridgeError("published bridge slot is invalid") from exc
        if port in seen:
            raise BridgeError("published bridge slots are duplicated or out of range")
        seen.add(port)
        lines.append(f"socks5h://{proxy_host}:{port}\n")
    return "".join(lines).encode()


def current_subscription_matches(output_dir: Path, expected: bytes) -> bool:
    """Return whether the active generation already publishes this source."""
    generation = _current_generation_dir(output_dir)
    if generation is None:
        return False
    try:
        return (generation / "proxies.txt").read_bytes() == expected
    except OSError:
        return False


def build_slot_changes(
    current: Sequence[dict[str, Any]],
    chosen: Sequence[dict[str, Any]],
    results: Sequence[ProbeResult],
    selected_results: Sequence[ProbeResult],
    probe_candidates: Sequence[dict[str, Any]],
    probe_bridges: Sequence[dict[str, Any]],
    *,
    base_port: int,
    direct_port: int | None = None,
) -> list[dict[str, Any]]:
    """Describe fixed-slot outcomes without exposing upstream credentials."""
    ports = managed_bridge_ports(base_port, len(chosen), reserved_port=direct_port)
    candidate_by_port = _probe_candidates_by_port(probe_candidates, probe_bridges)
    result_by_endpoint = {
        endpoint_id(candidate_by_port[int(row.spec.port)]): row
        for row in results
        if int(row.spec.port) in candidate_by_port
    }
    selected_endpoint_ids = {
        endpoint_id(candidate_by_port[int(row.spec.port)])
        for row in selected_results
        if int(row.spec.port) in candidate_by_port
    }
    changes: list[dict[str, Any]] = []
    for index, (candidate, port) in enumerate(zip(chosen, ports)):
        previous = current[index] if index < len(current) else None
        after_id = endpoint_id(candidate)
        before_id = endpoint_id(previous) if previous is not None else ""
        result = result_by_endpoint.get(after_id)
        if previous is None:
            status = "added"
        elif before_id != after_id:
            status = "replaced"
        elif after_id not in selected_endpoint_ids:
            status = "retained_unhealthy"
        else:
            status = "retained"
        if result is None:
            probe_category = "unhealthy"
        elif result.ok and after_id not in selected_endpoint_ids:
            probe_category = "selection_excluded"
        else:
            probe_category = result.category
        changes.append(
            {
                "slot": index,
                "port": port,
                "status": status,
                "before_endpoint_id": before_id,
                "after_endpoint_id": after_id,
                "probe_category": probe_category,
                "failed_target": result.failed_target if result is not None else "",
            }
        )
    return changes


def refresh_requires_publish(
    selection_stats: Mapping[str, int],
    *,
    subscription_changed: bool = False,
    current_healthy_count: int | None = None,
    minimum_healthy_nodes: int = 0,
    minimum_replacements: int = 1,
    generation_age_hours: float | None = None,
    maximum_generation_age_hours: float = 0,
) -> bool:
    """Publish only for material capacity loss or an aged pending refresh."""
    if subscription_changed:
        return True
    replaced = int(selection_stats.get("replaced_count") or 0)
    if int(selection_stats.get("added_count") or 0) > 0:
        return True
    if replaced < 1:
        return False
    if minimum_replacements < 1:
        raise BridgeError("minimum replacements to publish must be positive")
    if (
        current_healthy_count is not None
        and minimum_healthy_nodes > 0
        and current_healthy_count < minimum_healthy_nodes
    ):
        return True
    if replaced >= minimum_replacements:
        return True
    return bool(
        maximum_generation_age_hours > 0
        and generation_age_hours is not None
        and generation_age_hours >= maximum_generation_age_hours
    )


def current_generation_age_hours(output_dir: Path) -> float | None:
    generation = _current_generation_dir(output_dir)
    if generation is None:
        return None
    try:
        manifest = load_json(generation / "manifest.json")
        created_at = dt.datetime.fromisoformat(
            str(manifest.get("created_at") or "").replace("Z", "+00:00")
        )
    except (BridgeError, ValueError):
        return None
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=dt.timezone.utc)
    return max(
        0.0,
        (
            dt.datetime.now(dt.timezone.utc)
            - created_at.astimezone(dt.timezone.utc)
        ).total_seconds() / 3600,
    )


def current_direct_inbound_matches(
    output_dir: Path,
    *,
    listen: str,
    port: int,
    username: str,
    password: str,
) -> bool:
    generation = _current_generation_dir(output_dir)
    if generation is None:
        return False
    try:
        config = load_json(generation / "bridge.json")
    except BridgeError:
        return False
    expected = {
        "type": "socks",
        "tag": "managed-direct-egress",
        "listen": listen,
        "listen_port": port,
        "users": [{"username": username, "password": password}],
    }
    inbound_matches = any(
        row == expected for row in (config.get("inbounds") or []) if isinstance(row, dict)
    )
    route = config.get("route") if isinstance(config.get("route"), dict) else {}
    rule_matches = any(
        row == {
            "inbound": ["managed-direct-egress"],
            "action": "route",
            "outbound": "direct",
        }
        for row in (route.get("rules") or [])
        if isinstance(row, dict)
    )
    return inbound_matches and rule_matches


def selected_candidates(
    candidates: Sequence[dict[str, Any]],
    results: Sequence[ProbeResult],
    bridges: Sequence[dict[str, Any]],
    target: int,
    max_per_credential_group: int,
    *,
    current_count: int = 0,
    excluded_regions: Iterable[str] = (),
) -> tuple[list[dict[str, Any]], list[ProbeResult]]:
    chosen, selected, _ = select_fixed_slots(
        candidates,
        results,
        bridges,
        target,
        max_per_credential_group,
        current_count=current_count,
        excluded_regions=excluded_regions,
    )
    return chosen, selected


def _atomic_current_link(output_dir: Path, generation_dir: Path) -> None:
    relative = generation_dir.relative_to(output_dir)
    if relative.parts[0] != "generations" or len(relative.parts) != 2:
        raise BridgeError("generation directory is outside the managed root")
    current = output_dir / "current"
    temporary = output_dir / f".current.tmp-{os.getpid()}"
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    os.symlink(str(relative), temporary)
    os.replace(temporary, current)
    _fsync_directory(output_dir)


def _stage_previous_generation(output_dir: Path, generation_dir: Path | None) -> None:
    staged = output_dir / "staged"
    temporary = output_dir / f".staged.tmp-{os.getpid()}"
    for path in (temporary, staged):
        if path.exists() or path.is_symlink():
            path.unlink()
    if generation_dir is None:
        os.symlink("generations", temporary)
    else:
        relative = generation_dir.relative_to(output_dir)
        if relative.parts[0] != "generations" or len(relative.parts) != 2:
            raise BridgeError("previous generation is outside the managed root")
        os.symlink(str(relative), temporary)
    os.replace(temporary, staged)
    _fsync_directory(output_dir)


def prune_generations(output_dir: Path, keep: int) -> list[str]:
    if keep < MIN_RETAIN_GENERATIONS:
        raise BridgeError(
            f"retain generations must be at least {MIN_RETAIN_GENERATIONS}"
        )
    generations_dir = (output_dir / "generations").resolve()
    protected: set[Path] = set()
    for name in ("current", "staged"):
        pointer = output_dir / name
        if pointer.is_symlink():
            target = pointer.resolve()
            if target.parent == generations_dir:
                protected.add(target)
    # A committed old generation may still own live TCP sessions. The runtime
    # removes it from this registry only after its sockets drain and process exits.
    runtime_path = output_dir / "runtime.json"
    if runtime_path.exists():
        runtime = load_json(runtime_path)
        if runtime.get("owner") != "resin-bridge-runtime" or runtime.get("version") != 1:
            raise BridgeError("unrecognized bridge runtime registry; refusing to prune")
        for generation in runtime.get("instances", {}):
            if not re.fullmatch(r"[A-Za-z0-9-]+", generation):
                raise BridgeError("invalid runtime generation; refusing to prune")
            protected.add(generations_dir / generation)
    prepared_path = output_dir / "prepared.json"
    if prepared_path.exists():
        prepared = load_json(prepared_path)
        generation = prepared.get("generation")
        if isinstance(generation, str) and re.fullmatch(r"[A-Za-z0-9-]+", generation):
            target = generations_dir / generation
            if target.is_dir():
                protected.add(target)
    owned: list[Path] = []
    for path in generations_dir.iterdir():
        if not path.is_dir() or path.resolve().parent != generations_dir:
            continue
        manifest_path = path / "manifest.json"
        try:
            manifest = load_json(manifest_path)
        except BridgeError:
            continue
        if manifest.get("owner") in READABLE_OWNERS:
            owned.append(path.resolve())
    owned.sort(key=lambda item: item.name, reverse=True)
    # With a one-generation retention policy, the current transaction
    # pointers are the complete protection set. This keeps an older name from
    # surviving merely because it sorts newer than the current timestamp.
    retained = protected if keep == MIN_RETAIN_GENERATIONS else set(owned[:keep]) | protected
    removed: list[str] = []
    for path in owned:
        if path in retained:
            continue
        shutil.rmtree(path)
        removed.append(path.name)
    return removed


def publish(
    args: argparse.Namespace,
    source_data: bytes,
    candidates: Sequence[dict[str, Any]],
    selected: Sequence[ProbeResult],
    source_report: Mapping[str, Any],
    probe_errors: Mapping[str, int],
    *,
    probe_input_count: int | None = None,
    passed_count: int | None = None,
    retained_count: int = 0,
    retained_unhealthy_count: int = 0,
    replaced_count: int | None = None,
    added_count: int = 0,
    slot_changes: Sequence[Mapping[str, Any]] = (),
    published_indices: Sequence[int] | None = None,
) -> dict[str, Any]:
    output_dir = Path(args.output_dir).resolve()
    publish_listen = validate_publish_listen(args.publish_listen)
    direct_port = configured_direct_port(args)
    managed_bridge_ports(
        args.publish_base_port,
        len(candidates),
        reserved_port=(direct_port or None),
    )
    config, bridges = build_config(
        candidates,
        listen=publish_listen,
        base_port=args.publish_base_port,
        direct_port=(direct_port or None),
        direct_username=optional_text_argument(args, "direct_username"),
        direct_password=optional_text_argument(args, "direct_password"),
    )
    if published_indices is None:
        normalized_published_indices = list(range(len(bridges)))
        if len(selected) != len(normalized_published_indices):
            raise BridgeError(
                "published bridge slots must be supplied for a partial healthy set"
            )
    else:
        try:
            normalized_published_indices = [int(index) for index in published_indices]
        except (TypeError, ValueError) as exc:
            raise BridgeError("published bridge slots are invalid") from exc
        if len(selected) != len(normalized_published_indices):
            raise BridgeError(
                "published bridge slots do not match healthy probe results"
            )
    if any(
        index < 0 or index >= len(bridges)
        for index in normalized_published_indices
    ) or len(set(normalized_published_indices)) != len(normalized_published_indices):
        raise BridgeError("published bridge slots are invalid")
    if not normalized_published_indices:
        raise BridgeError("published bridge slots must not be empty")
    generation = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    generation_name = f"{generation}-{sha256_bytes(source_data)[:8]}"
    run_id = str(os.environ.get("RESIN_MAINTENANCE_RUN_ID") or "") or (
        f"{generation_name}-{os.getpid()}"
    )
    generation_dir = output_dir / "generations" / generation_name
    generation_dir.mkdir(parents=True, mode=0o700)
    os.chmod(generation_dir, 0o700)
    try:
        config_path = generation_dir / "bridge.json"
        manifest_path = generation_dir / "manifest.json"
        run_singbox_check(Path(args.singbox_binary), _write_candidate_config(config_path, config))
        subscription = build_subscription(
            publish_listen, bridges, normalized_published_indices
        )
        subscription_path = generation_dir / "proxies.txt"
        atomic_write(subscription_path, subscription)
        slot_changes_path = generation_dir / "slot-changes.json"
        write_json(
            slot_changes_path,
            {
                "version": 1,
                "owner": OWNER,
                "run_id": run_id,
                "generation": generation_name,
                "changes": list(slot_changes),
            },
        )
        categories = Counter(row.category for row in selected)
        published_candidates = [candidates[index] for index in normalized_published_indices]
        protocols = Counter(
            str(candidate.get("type") or "unknown") for candidate in published_candidates
        )
        credential_groups = Counter(row.spec.credential_group_id for row in selected)
        actual_probe_input_count = len(selected) if probe_input_count is None else int(probe_input_count)
        actual_passed_count = len(selected) if passed_count is None else int(passed_count)
        actual_replaced_count = (
            len(candidates) - int(retained_count)
            if replaced_count is None
            else int(replaced_count)
        )
        target_hosts = normalize_target_hosts(
            vars(args).get("target_hosts") or "www.cloudflare.com"
        )
        min_target_hosts_passed = normalize_min_target_hosts_passed(
            vars(args).get("min_target_hosts_passed"), len(target_hosts)
        )
        excluded_regions = sorted(
            {
                str(item).strip().lower()
                for item in vars(args).get("excluded_regions", ())
                if str(item).strip()
            }
        )
        manifest = {
            "owner": OWNER,
            "version": 1,
            "run_id": run_id,
            "created_at": utc_now(),
            "source_sha256": sha256_bytes(source_data),
            "source": dict(source_report),
            "probe_input_count": actual_probe_input_count,
            "passed_count": actual_passed_count,
            "retained_count": int(retained_count),
            "retained_unhealthy_count": int(retained_unhealthy_count),
            "replaced_count": actual_replaced_count,
            "added_count": int(added_count),
            "slot_count": len(candidates),
            "healthy_slot_count": len(normalized_published_indices),
            "selected_count": len(normalized_published_indices),
            "published_count": len(normalized_published_indices),
            "unique_egress_count": len({row.egress_ip for row in selected if row.egress_ip}),
            "protocols": dict(sorted(protocols.items())),
            "credential_group_count": len(credential_groups),
            "max_credential_group_count": max(credential_groups.values(), default=0),
            "regions": dict(sorted(Counter(row.region or "unknown" for row in selected).items())),
            "direct_endpoint": (
                f"socks5h://{format_proxy_host(publish_listen)}:{direct_port}"
                if direct_port > 0
                else None
            ),
            "selected_categories": dict(sorted(categories.items())),
            "target_hosts": list(target_hosts),
            "min_target_hosts_passed": min_target_hosts_passed,
            "excluded_regions": excluded_regions,
            "preprobe_errors": dict(sorted(probe_errors.items())),
            "generation": generation_name,
            "config_file": "bridge.json",
            "config_sha256": sha256_bytes(config_path.read_bytes()),
            "subscription_file": "proxies.txt",
            "subscription_sha256": sha256_bytes(subscription),
            "slot_changes_file": "slot-changes.json",
            "slot_changes_sha256": sha256_bytes(slot_changes_path.read_bytes()),
            "base_port": args.publish_base_port,
        }
        write_json(manifest_path, manifest)
    except Exception:
        shutil.rmtree(generation_dir, ignore_errors=True)
        raise
    previous_generation = _current_generation_dir(output_dir)
    if vars(args).get("prepare_only"):
        write_json(output_dir / "prepared.json", {
            "version": 1, "owner": OWNER, "generation": generation_name,
            "base_generation": previous_generation.name if previous_generation else None,
            "manifest_sha256": sha256_bytes(manifest_path.read_bytes()),
            "prepared_at": time.time(), "status": "prepared",
        })
        return manifest
    _stage_previous_generation(output_dir, previous_generation)
    _atomic_current_link(output_dir, generation_dir)
    return manifest


def _write_candidate_config(path: Path, config: Mapping[str, Any]) -> Path:
    write_json(path, config)
    return path


def validate_probe_port_range(base_port: int, count: int) -> None:
    if base_port < 1 or base_port + count > 65536:
        raise BridgeError("probe port range exceeds 65535")
    if 20000 <= base_port < 30000 and base_port + count > 30000:
        raise BridgeError("probe candidates exceed reserved ports 20000-29999")


def command_refresh(args: argparse.Namespace) -> int:
    if args.target_nodes < 1:
        raise BridgeError("target node count must be positive")
    args.target_nodes = min(args.target_nodes, MAX_POOL_NODES)
    if args.candidate_limit < 0:
        raise BridgeError("candidate limit must not be negative")
    if args.candidate_limit > 0 and args.candidate_limit < args.target_nodes:
        raise BridgeError(
            "candidate limit must be zero (unlimited) or at least the target node count"
        )
    if args.retain_generations < MIN_RETAIN_GENERATIONS:
        raise BridgeError(
            f"retain generations must be at least {MIN_RETAIN_GENERATIONS}"
        )
    if args.dns_workers < 1 or args.dns_workers > 1000:
        raise BridgeError("DNS workers must be between 1 and 1000")
    if args.probe_workers < 1 or args.probe_workers > 1000:
        raise BridgeError("probe workers must be between 1 and 1000")
    if args.probe_batch_size < 1:
        raise BridgeError("probe batch size must be positive")
    if args.max_per_egress < 0:
        raise BridgeError("max per egress must not be negative")
    if args.download_timeout <= 0 or args.probe_timeout <= 0:
        raise BridgeError("download and probe timeouts must be positive")
    if args.minimum_replacements_to_publish < 1:
        raise BridgeError("minimum replacements to publish must be positive")
    if args.maximum_generation_age_hours < 0:
        raise BridgeError("maximum generation age must not be negative")
    minimum_healthy_nodes = (
        1 if args.minimum_healthy_nodes is None else args.minimum_healthy_nodes
    )
    if minimum_healthy_nodes < 1 or minimum_healthy_nodes > args.target_nodes:
        raise BridgeError("minimum healthy nodes must be between 1 and target nodes")
    args.publish_listen = validate_publish_listen(args.publish_listen)
    args.probe_listen = validate_probe_listen(args.probe_listen)
    direct_port = configured_direct_port(args)
    if direct_port:
        direct_password_file = optional_text_argument(args, "direct_password_file")
        if not direct_password_file:
            raise BridgeError("direct SOCKS password file is required")
        args.direct_password = read_private_secret(
            Path(direct_password_file), "direct SOCKS password file"
        )
    else:
        args.direct_password = ""
    managed_bridge_ports(
        args.publish_base_port,
        args.target_nodes,
        reserved_port=(direct_port or None),
    )
    if args.probe_base_port < 1:
        raise BridgeError("probe port range exceeds 65535")
    try:
        args.target_hosts = normalize_target_hosts(args.target_hosts or "www.cloudflare.com")
        args.min_target_hosts_passed = normalize_min_target_hosts_passed(
            vars(args).get("min_target_hosts_passed"), len(args.target_hosts)
        )
    except ValueError as exc:
        raise BridgeError("invalid target host configuration") from exc
    output_dir = Path(args.output_dir).resolve()
    staged = output_dir / "staged"
    if staged.exists() or staged.is_symlink():
        raise BridgeError("incomplete staged generation requires rollback")
    current = load_current_candidates(output_dir, args.target_nodes)
    try:
        source_data = download_source(args.source_url, args.download_timeout)
        candidates, source_report = load_candidates(source_data)
        source_report["download_status"] = "success"
    except BridgeError as exc:
        # Upstream failure must not suspend health checks of the existing pool.
        source_data = json.dumps({"outbounds": current}, sort_keys=True).encode()
        candidates = []
        source_report = {"download_status": "failed_current_revalidated", "error": str(exc),
                         "supported_input_count": 0, "unique_endpoint_count": 0}
    try:
        additions, discovery_report = discover_sources(args, output_dir)
        if additions:
            parsed_count = len(additions)
            additions = compatible_candidates(Path(args.singbox_binary), additions)
            discovery_report["compatible_count"] = len(additions)
            discovery_report["compatibility_rejected_count"] = parsed_count - len(additions)
            cache_path = output_dir / "discovery-cache.json"
            cache = load_json(cache_path)
            if cache.get("owner") == OWNER:
                cache["candidates"] = additions
                cache["report"].update(compatible_count=len(additions),
                                       compatibility_rejected_count=parsed_count - len(additions))
                write_json(cache_path, cache)
    except (BridgeError, ValueError, TypeError, OSError) as exc:
        additions, discovery_report = [], {"status": "failed", "error_type": type(exc).__name__}
    source_report["discovery"] = discovery_report
    if additions:
        candidates = list({endpoint_key(row): row for row in [*candidates, *additions]}.values())
        source_data = json.dumps({"primary_sha256": sha256_bytes(source_data),
            "discovery_sha256": sha256_bytes(json.dumps(additions, sort_keys=True).encode())}, sort_keys=True).encode()
    if discovery_report["status"] != "disabled":
        print(json.dumps({"discovery": discovery_report}), flush=True)
    public, preprobe_errors = public_candidate_subset(
        candidates,
        seed=sha256_bytes(source_data),
        limit=args.candidate_limit,
        workers=args.dns_workers,
    )
    current_keys = {endpoint_key(item) for item in current}
    filtered_public: list[dict[str, Any]] = []
    for item in public:
        if endpoint_key(item) in current_keys:
            preprobe_errors["duplicate_current_endpoint"] += 1
            continue
        filtered_public.append(item)
    combined = [*current, *filtered_public]
    validate_probe_port_range(args.probe_base_port, len(combined))
    if len(combined) < minimum_healthy_nodes:
        raise BridgeError("not enough candidates to reach the minimum healthy node threshold")
    results, bridges = probe_candidates(
        Path(args.singbox_binary),
        combined,
        listen=args.probe_listen,
        base_port=args.probe_base_port,
        timeout=args.probe_timeout,
        workers=args.probe_workers,
        batch_size=args.probe_batch_size,
        target_host=args.target_hosts,
        min_target_hosts_passed=args.min_target_hosts_passed,
    )
    chosen, selected, selection_stats = select_fixed_slots(
        combined,
        results,
        bridges,
        args.target_nodes,
        args.max_per_credential_group,
        max_per_egress=args.max_per_egress,
        current_count=len(current),
        excluded_regions=vars(args).get("excluded_regions", ()),
    )
    published_indices = healthy_slot_indices(
        chosen,
        selected,
        combined,
        bridges,
    )
    slot_changes = build_slot_changes(
        current,
        chosen,
        results,
        selected,
        combined,
        bridges,
        base_port=args.publish_base_port,
        direct_port=(direct_port or None),
    )
    if len(selected) < minimum_healthy_nodes:
        categories = Counter(row.category for row in results)
        raise BridgeError(
            "fail-closed: healthy_slots="
            f"{len(selected)}, minimum={minimum_healthy_nodes}, "
            f"target={args.target_nodes}, categories={dict(categories)}"
        )
    generation_age_hours = current_generation_age_hours(output_dir)
    direct_change_required = bool(
        direct_port
        and not current_direct_inbound_matches(
            output_dir,
            listen=args.publish_listen,
            port=direct_port,
            username=optional_text_argument(args, "direct_username"),
            password=optional_text_argument(args, "direct_password"),
        )
    )
    publish_ports = managed_bridge_ports(
        args.publish_base_port,
        len(chosen),
        reserved_port=(direct_port or None),
    )
    expected_subscription = build_subscription(
        args.publish_listen,
        [{"port": port} for port in publish_ports],
        published_indices,
    )
    subscription_changed = not current_subscription_matches(
        output_dir, expected_subscription
    )
    if not direct_change_required and not refresh_requires_publish(
        selection_stats,
        subscription_changed=subscription_changed,
        current_healthy_count=selection_stats["retained_count"],
        minimum_healthy_nodes=minimum_healthy_nodes,
        minimum_replacements=args.minimum_replacements_to_publish,
        generation_age_hours=generation_age_hours,
        maximum_generation_age_hours=args.maximum_generation_age_hours,
    ):
        if vars(args).get("prepare_only"):
            base = _current_generation_dir(output_dir)
            write_json(output_dir / "prepared.json", {
                "version": 1, "owner": OWNER, "status": "unchanged",
                "base_generation": base.name if base else None,
                "prepared_at": time.time(),
            })
        print(
            json.dumps(
                {
                    "status": "unchanged",
                    "slot_count": len(chosen),
                    "selected_count": len(published_indices),
                    "healthy_slot_count": len(published_indices),
                    "published_count": len(published_indices),
                    "unique_egress_count": len(
                        {row.egress_ip for row in selected if row.egress_ip}
                    ),
                    "source_sha256": sha256_bytes(source_data),
                    "retained_count": selection_stats["retained_count"],
                    "retained_unhealthy_count": selection_stats[
                        "retained_unhealthy_count"
                    ],
                    "replaced_count": selection_stats["replaced_count"],
                    "added_count": selection_stats["added_count"],
                    "publish_deferred": selection_stats["replaced_count"] > 0,
                    "subscription_changed": subscription_changed,
                    "direct_change_required": False,
                    "minimum_replacements_to_publish": args.minimum_replacements_to_publish,
                    "generation_age_hours": (
                        round(generation_age_hours, 3)
                        if generation_age_hours is not None
                        else None
                    ),
                },
                sort_keys=True,
            )
        )
        return 0
    manifest = publish(
        args,
        source_data,
        chosen,
        selected,
        source_report,
        preprobe_errors,
        probe_input_count=len(results),
        passed_count=sum(1 for row in results if row.ok),
        retained_count=selection_stats["retained_count"],
        retained_unhealthy_count=selection_stats["retained_unhealthy_count"],
        replaced_count=selection_stats["replaced_count"],
        added_count=selection_stats["added_count"],
        slot_changes=slot_changes,
        published_indices=published_indices,
    )
    pruned = prune_generations(output_dir, args.retain_generations)
    print(
        json.dumps(
            {
                "status": "prepared" if vars(args).get("prepare_only") else "published",
                "selected_count": manifest["selected_count"],
                "healthy_slot_count": manifest["healthy_slot_count"],
                "unique_egress_count": manifest["unique_egress_count"],
                "run_id": manifest["run_id"],
                "generation": manifest["generation"],
                "source_sha256": manifest["source_sha256"],
                "pruned_generations": len(pruned),
                "direct_change_applied": direct_change_required,
            },
            sort_keys=True,
        )
    )
    return 0


def command_promote(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir).resolve()
    prepared_path = output_dir / "prepared.json"
    if prepared_path.is_symlink():
        raise BridgeError("prepared state must be a regular file")

    def clear_prepared() -> None:
        prepared_path.unlink()
        _fsync_directory(output_dir)

    prepared = load_json(prepared_path)
    if prepared.get("owner") != OWNER or prepared.get("version") != 1:
        raise BridgeError("prepared generation ownership mismatch")
    current = _current_generation_dir(output_dir)
    staged, previous = _staged_generation_dir(output_dir)
    already_promoted = bool(staged and current and current.name == prepared.get("generation")
                            and prepared.get("base_generation") == (previous.name if previous else None))
    if not already_promoted and prepared.get("base_generation") != (current.name if current else None):
        clear_prepared()
        raise BridgeError("current generation changed during preparation")
    if not already_promoted and not 0 <= time.time() - prepared.get("prepared_at", 0) <= args.max_age_seconds:
        clear_prepared()
        raise BridgeError("prepared generation is stale")
    if staged and not already_promoted:
        raise BridgeError("incomplete staged generation requires rollback")
    if prepared.get("status") == "unchanged":
        clear_prepared()
        print(json.dumps({"status": "unchanged", "bridge_restart": False}))
        return 0
    if prepared.get("status") != "prepared":
        raise BridgeError("invalid prepared generation status")
    generation = prepared.get("generation", "")
    if not re.fullmatch(r"[A-Za-z0-9-]+", generation):
        raise BridgeError("invalid prepared generation")
    generation_dir = output_dir / "generations" / generation
    if generation_dir.is_symlink() or generation_dir.resolve().parent != (output_dir / "generations").resolve():
        raise BridgeError("prepared generation escapes managed root")
    manifest_path = generation_dir / "manifest.json"
    manifest = load_json(manifest_path)
    if (sha256_bytes(manifest_path.read_bytes()) != prepared.get("manifest_sha256")
            or manifest.get("owner") != OWNER or manifest.get("generation") != generation):
        raise BridgeError("prepared manifest integrity mismatch")
    for filename, field in (("bridge.json", "config_sha256"), ("proxies.txt", "subscription_sha256"),
                            ("slot-changes.json", "slot_changes_sha256")):
        path = generation_dir / filename
        if path.is_symlink() or sha256_bytes(path.read_bytes()) != manifest.get(field):
            raise BridgeError("prepared artifact integrity mismatch")
    if not already_promoted:
        _stage_previous_generation(output_dir, current)
        _atomic_current_link(output_dir, generation_dir)
    clear_prepared()
    print(json.dumps({"status": "promoted", "generation": generation}))
    return 0


def command_commit(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir).resolve()
    raw_keep = getattr(args, "retain_generations", MIN_RETAIN_GENERATIONS)
    try:
        keep = int(raw_keep)
    except (TypeError, ValueError):
        keep = MIN_RETAIN_GENERATIONS
    if keep < MIN_RETAIN_GENERATIONS:
        raise BridgeError(
            f"retain generations must be at least {MIN_RETAIN_GENERATIONS}"
        )
    staged, _ = _staged_generation_dir(output_dir)
    current = _current_generation_dir(output_dir)
    if current is None:
        raise BridgeError("current pointer is missing")
    if not staged:
        pruned = prune_generations(output_dir, keep)
        print(
            json.dumps(
                {"status": "already_committed", "pruned_generations": len(pruned)},
                sort_keys=True,
            )
        )
        return 0
    _remove_pointer(output_dir / "staged")
    pruned = prune_generations(output_dir, keep)
    print(
        json.dumps(
            {
                "status": "committed",
                "generation": current.name,
                "pruned_generations": len(pruned),
            },
            sort_keys=True,
        )
    )
    return 0


def command_prune(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir).resolve()
    raw_keep = getattr(args, "retain_generations", MIN_RETAIN_GENERATIONS)
    try:
        keep = int(raw_keep)
    except (TypeError, ValueError):
        keep = MIN_RETAIN_GENERATIONS
    removed = prune_generations(output_dir, keep)
    print(json.dumps({"status": "pruned", "pruned_generations": len(removed)}, sort_keys=True))
    return 0


def command_rollback(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir).resolve()
    staged, previous = _staged_generation_dir(output_dir)
    if not staged:
        raise BridgeError("staged pointer is missing")
    current = output_dir / "current"
    rolled_back_from = current.resolve().name if current.is_symlink() else ""
    if previous is None:
        if current.exists() and not current.is_symlink():
            raise BridgeError("current pointer is not a symlink")
        if current.is_symlink():
            current.unlink()
            _fsync_directory(output_dir)
        restored = ""
    else:
        _atomic_current_link(output_dir, previous)
        restored = previous.name
    _remove_pointer(output_dir / "staged")
    print(
        json.dumps(
            {
                "status": "rolled_back",
                "from_generation": rolled_back_from,
                "restored_generation": restored,
            },
            sort_keys=True,
        )
    )
    return 0


def command_resolve_current(args: argparse.Namespace) -> int:
    root = Path(args.output_dir).resolve()
    pointer = root / "current"
    if not pointer.is_symlink():
        raise BridgeError("current pointer is missing")
    generation_dir = pointer.resolve()
    generations_dir = (root / "generations").resolve()
    if generation_dir.parent != generations_dir or not generation_dir.is_dir():
        raise BridgeError("current pointer is invalid")
    target = generation_dir / args.artifact
    if not target.is_file() or target.stat().st_mode & 0o077:
        raise BridgeError("current target is invalid")
    print(target)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    refresh = sub.add_parser("refresh")
    refresh.add_argument("--source-url", required=True)
    refresh.add_argument("--prepare-only", action="store_true")
    refresh.add_argument("--discovery-config", default="")
    refresh.add_argument("--subscription-converter", default="")
    refresh.add_argument("--output-dir", required=True)
    refresh.add_argument("--singbox-binary", default="/usr/local/bin/sing-box")
    refresh.add_argument("--target-nodes", type=int, default=MAX_POOL_NODES)
    refresh.add_argument("--minimum-healthy-nodes", type=int)
    refresh.add_argument(
        "--candidate-limit",
        type=int,
        default=0,
        help="maximum public candidates to probe; 0 probes all source candidates",
    )
    refresh.add_argument("--max-per-egress", type=int, default=0)
    refresh.add_argument("--max-per-credential-group", type=int, default=0)
    refresh.add_argument(
        "--retain-generations", type=int, default=MIN_RETAIN_GENERATIONS
    )
    refresh.add_argument("--download-timeout", type=float, default=30)
    refresh.add_argument("--dns-workers", type=int, default=64)
    refresh.add_argument("--probe-listen", default="127.0.0.1")
    refresh.add_argument("--probe-base-port", type=int, default=20000)
    refresh.add_argument("--probe-timeout", type=float, default=8)
    refresh.add_argument("--probe-workers", type=int, default=200)
    refresh.add_argument("--probe-batch-size", type=int, default=300)
    refresh.add_argument("--target-host", dest="target_hosts", action="append")
    refresh.add_argument("--min-target-hosts-passed", type=int)
    refresh.add_argument(
        "--excluded-region", dest="excluded_regions", action="append", default=[]
    )
    refresh.add_argument("--publish-listen", default="172.17.0.1")
    refresh.add_argument("--publish-base-port", type=int, default=12000)
    refresh.add_argument("--direct-port", type=int, default=0)
    refresh.add_argument("--direct-username", default="sub2-direct")
    refresh.add_argument("--direct-password-file", default="")
    refresh.add_argument("--minimum-replacements-to-publish", type=int, default=1)
    refresh.add_argument("--maximum-generation-age-hours", type=float, default=0)
    refresh.set_defaults(func=command_refresh)

    ready = sub.add_parser("wait-listeners")
    ready.add_argument("--output-dir", required=True)
    ready.add_argument("--pid", type=int, required=True)
    ready.add_argument("--timeout-seconds", type=float, default=60)
    ready.set_defaults(func=command_wait_listeners)

    promote = sub.add_parser("promote")
    promote.add_argument("--output-dir", required=True)
    promote.add_argument("--max-age-seconds", type=int, default=1800)
    promote.set_defaults(func=command_promote)

    commit = sub.add_parser("commit")
    commit.add_argument("--output-dir", required=True)
    commit.add_argument(
        "--retain-generations", type=int, default=MIN_RETAIN_GENERATIONS
    )
    commit.set_defaults(func=command_commit)

    prune = sub.add_parser("prune")
    prune.add_argument("--output-dir", required=True)
    prune.add_argument(
        "--retain-generations", type=int, default=MIN_RETAIN_GENERATIONS
    )
    prune.set_defaults(func=command_prune)

    rollback = sub.add_parser("rollback")
    rollback.add_argument("--output-dir", required=True)
    rollback.set_defaults(func=command_rollback)

    resolve = sub.add_parser("resolve-current")
    resolve.add_argument("--output-dir", required=True)
    resolve.add_argument(
        "--artifact",
        choices=("bridge.json", "proxies.txt", "manifest.json", "slot-changes.json"),
        default="bridge.json",
    )
    resolve.set_defaults(func=command_resolve_current)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command in {"refresh", "promote", "commit", "prune", "rollback"}:
            output_dir = Path(args.output_dir).resolve()
            with exclusive_lock(output_dir / ".bridge-pool.lock"):
                return int(args.func(args))
        return int(args.func(args))
    except BridgeError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
