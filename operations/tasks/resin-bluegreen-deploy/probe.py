#!/usr/bin/env python3
"""One authenticated CONNECT plus a bounded HTTPS response, without logging secrets."""

import base64
import http.client
import json
from pathlib import Path
import socket
import ssl
import sys
from urllib.parse import urlsplit


def probe(config, address, port):
    target = urlsplit(config["probe_target"])
    if target.scheme != "https" or not target.hostname or target.username or target.fragment:
        raise ValueError("probe_target must be an HTTPS URL without userinfo or fragment")
    token = Path(config["proxy_token_file"]).read_text().strip()
    identity = config.get("probe_identity", "Default.bluegreen-check")
    credential = base64.b64encode(f"{identity}:{token}".encode()).decode()
    authority = f"{target.hostname}:{target.port or 443}"
    with socket.create_connection((address, int(port)), timeout=10) as raw:
        raw.sendall((f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
                     f"Proxy-Authorization: Basic {credential}\r\n\r\n").encode())
        response = http.client.HTTPResponse(raw)
        response.begin()
        if response.status != 200:
            raise ValueError(f"CONNECT returned HTTP {response.status}")
        with ssl.create_default_context().wrap_socket(raw, server_hostname=target.hostname) as conn:
            path = target.path or "/"
            if target.query:
                path += "?" + target.query
            conn.sendall((f"GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n").encode())
            reply = http.client.HTTPResponse(conn)
            reply.begin()
            if reply.status != config.get("probe_status", 200):
                raise ValueError(f"probe target returned HTTP {reply.status}")
            # No body is logged; bound the work even when a target streams forever.
            reply.read(4096)


if __name__ == "__main__":
    try:
        probe(json.loads(Path(sys.argv[1]).read_text()), sys.argv[2], sys.argv[3])
    except (OSError, ValueError, http.client.HTTPException):
        print("CONNECT/TLS data-plane probe failed", file=sys.stderr)
        sys.exit(1)
