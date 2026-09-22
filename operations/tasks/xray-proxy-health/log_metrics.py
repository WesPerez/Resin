#!/usr/bin/env python3
"""Bounded, rotation-aware Nginx samples; missing data is never zero traffic."""

import argparse
import datetime as dt
import json
import os
import re
from pathlib import Path

MAX_BYTES = 8 * 1024 * 1024
ACCESS_TIME = re.compile(r"\[([^]]+)\]")
FIELDS = re.compile(r"(?:^|\s)(status|duration|bytes)=([^\s]+)")
KEYS = {
    "ws": ("ws_101", "ws_503", "ws_429", "ws_other", "ws_503_zero_ms",
           "ws_101_zero_bytes", "ws_101_short_le5s", "ws_total", "ws_503_ratio",
           "ws_101_short_ratio"),
    "xhttp": ("xhttp_2xx", "xhttp_499", "xhttp_other", "xhttp_total"),
    "error": ("limit_conn_events", "limit_req_events"),
}


def timestamp(line, kind):
    try:
        if kind == "error":
            return dt.datetime.strptime(line[:19], "%Y/%m/%d %H:%M:%S").astimezone().timestamp()
        match = ACCESS_TIME.search(line)
        if match:
            return dt.datetime.strptime(match[1], "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        pass
    return None


def sample(path, kind, start, max_bytes=MAX_BYTES):
    counts = dict.fromkeys(KEYS[kind], 0)
    seen = set()
    status = "ok"
    # Opening current first also lets us deduplicate a rename between the opens.
    for candidate in (Path(path), Path(str(path) + ".1")):
        try:
            with candidate.open("rb") as stream:
                info = os.fstat(stream.fileno())
                identity = (info.st_dev, info.st_ino)
                if identity in seen:
                    continue
                seen.add(identity)
                offset = max(0, info.st_size - max_bytes)
                stream.seek(offset)
                if offset:
                    stream.readline()  # Discard the partial first line.
                lines = stream.read(max_bytes).decode("utf-8", errors="replace").splitlines()
        except FileNotFoundError:
            if candidate == Path(path):
                status = "missing"
            continue
        except OSError:
            status = "unreadable"
            continue
        # If the bounded read begins inside the requested minute, counts are incomplete.
        if offset and lines:
            first = next((value for line in lines[:100]
                          if (value := timestamp(line, kind)) is not None), None)
            if first is None or first >= start:
                status = "truncated"
        for line in lines:
            event_time = timestamp(line, kind)
            if event_time is None or not start <= event_time < start + 60:
                continue
            if kind == "error":
                counts["limit_conn_events"] += 'limiting connections by zone "proxy_ws_conn"' in line
                counts["limit_req_events"] += 'limiting requests by zone "proxy_ws_handshake"' in line
                continue
            fields = dict(FIELDS.findall(line))
            code = fields.get("status", "")
            if not re.fullmatch(r"[1-5][0-9]{2}", code):
                status = "invalid_format"
                continue
            if kind == "xhttp":
                counts["xhttp_2xx" if code.startswith("2") else
                       "xhttp_499" if code == "499" else "xhttp_other"] += 1
            else:
                counts["ws_" + code if code in ("101", "503", "429") else "ws_other"] += 1
                if code == "101":
                    counts["ws_101_zero_bytes"] += fields.get("bytes") == "0"
                    try:
                        duration = float(fields["duration"])
                        counts["ws_101_short_le5s"] += 0 <= duration <= 5
                    except (KeyError, ValueError):
                        status = "invalid_format"
                elif code == "503":
                    counts["ws_503_zero_ms"] += fields.get("duration") == "0.000"
    if kind == "ws":
        counts["ws_total"] = sum(counts[key] for key in ("ws_101", "ws_503", "ws_429", "ws_other"))
        counts["ws_503_ratio"] = round(counts["ws_503"] / counts["ws_total"], 4) if counts["ws_total"] else 0
        counts["ws_101_short_ratio"] = round(counts["ws_101_short_le5s"] / counts["ws_101"], 4) if counts["ws_101"] else 0
    elif kind == "xhttp":
        counts["xhttp_total"] = sum(counts[key] for key in ("xhttp_2xx", "xhttp_499", "xhttp_other"))
    if status != "ok":
        counts = dict.fromkeys(counts)
    return counts, {"status": status, "complete": status == "ok"}


def collect(paths, start):
    result = {"metric_schema": 3, "log_sources": {}}
    for kind, path in paths.items():
        counts, source = sample(path, kind, start)
        result.update(counts)
        result["log_sources"][kind] = source
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for kind in KEYS:
        parser.add_argument("--" + kind, required=True)
    parser.add_argument("--start", type=int, required=True)
    args = parser.parse_args()
    print(json.dumps(collect({kind: getattr(args, kind) for kind in KEYS}, args.start)))


if __name__ == "__main__":
    main()
