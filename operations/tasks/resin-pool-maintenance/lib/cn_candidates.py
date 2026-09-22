#!/usr/bin/env python3
"""Keep previous CN candidates first, then country lists, then fair global exploration."""

import argparse
from collections import deque
import ipaddress
import json
from pathlib import Path
import re

COUNTRY = ("proxyscrape.txt", "proxifly.txt", "proxyscrape-v4.txt")
GLOBAL = ("speedx.txt", "monosans.txt", "vakhov.txt", "rooster.txt", "proxifly-all.txt",
          "hideip.txt", "monosans-anon.txt", "mmpx12.txt", "dedeoglu.txt")
ENDPOINT = re.compile(r"^(?:https?://)?([0-9.]+):([0-9]+)/?$")


def read_candidates(path):
    try:
        with path.open() as stream:
            lines = stream.read(8 * 1024 * 1024).splitlines()
    except FileNotFoundError:
        return []
    result, seen = [], set()
    for line in lines:
        match = ENDPOINT.fullmatch(line.strip())
        if not match:
            continue
        try:
            address = ipaddress.IPv4Address(match[1])
            port = int(match[2])
        except ValueError:
            continue
        if not address.is_global or not 1 <= port <= 65535:
            continue
        endpoint = f"{address}:{port}"
        if endpoint not in seen:
            result.append(endpoint)
            seen.add(endpoint)
    return result


def select(previous, directory, limit):
    if not 1 <= limit <= 10000:
        raise ValueError("invalid CN candidate limit")
    sources = {"previous": read_candidates(previous)}
    sources.update({name: read_candidates(directory / name) for name in (*COUNTRY, *GLOBAL)})
    result, seen, contributions = [], set(), dict.fromkeys(sources, 0)
    for group in (("previous",), COUNTRY, GLOBAL):
        queues = {name: deque(sources[name]) for name in group}
        while any(queues.values()) and len(result) < limit:
            for name, queue in queues.items():
                while queue:
                    candidate = queue.popleft()
                    if candidate not in seen:
                        result.append(candidate)
                        seen.add(candidate)
                        contributions[name] += 1
                        break
                if len(result) >= limit:
                    break
    return result, {"candidate_count": len(result), "input_counts": {name: len(rows) for name, rows in sources.items()},
                    "selected_counts": contributions, "previous_selected": contributions["previous"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--limit", type=int, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    rows, report = select(args.previous, args.directory, args.limit)
    args.report.write_text(json.dumps(report) + "\n")
    print("\n".join(rows))


if __name__ == "__main__":
    main()
