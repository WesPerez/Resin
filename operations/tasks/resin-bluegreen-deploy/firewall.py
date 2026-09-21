#!/usr/bin/env python3
"""Mirror existing Resin UFW permissions to slot ports on live bridges only."""

import argparse
import json
import shlex

from bluegreen import Deployment, DeploymentError, run


def plan(deployment):
    links = {entry["ifname"] for entry in json.loads(run(["ip", "-json", "link", "show", "type", "bridge"]).stdout)}
    commands = []
    for line in run(["ufw", "show", "added"]).stdout.splitlines():
        words = shlex.split(line)
        if words[:4] != ["ufw", "allow", "in", "on"]:
            continue
        try:
            interface = words[4]
            source = words[words.index("from") + 1]
            destination = words[words.index("to") + 1]
            port = words[words.index("port") + 1]
            protocol = words[words.index("proto") + 1]
        except (ValueError, IndexError):
            continue
        if interface not in links or destination != deployment.address or port != str(deployment.ports["legacy"]) or protocol != "tcp":
            continue
        for slot in ("blue", "green"):
            command = ["ufw", "allow", "in", "on", interface, "from", source, "to", destination,
                       "port", str(deployment.ports[slot]), "proto", "tcp", "comment", "Resin bluegreen"]
            if command not in commands:
                commands.append(command)
    if not commands:
        raise DeploymentError("no existing Resin UFW rules on live bridges; inspect firewall before migration")
    return commands


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    deployment = Deployment()
    with deployment.locked():
        for command in plan(deployment):
            print(shlex.join(command))
            if args.apply:
                run(command)
