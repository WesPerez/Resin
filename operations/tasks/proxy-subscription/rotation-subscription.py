#!/usr/bin/env python3
"""Combine the strict site route with independently verified rotating exits."""

import argparse
import importlib.util
from pathlib import Path

import yaml

import rotation_pool
import site_policy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=rotation_pool.POLICY)
    args = parser.parse_args()
    if not rotation_pool.enabled(args.policy):
        return
    if not rotation_pool.unified() and not site_policy.strict_enabled():
        raise ValueError("balanced subscription requires the strict site policy")
    spec = importlib.util.spec_from_file_location("region_latency", Path(__file__).with_name("region-latency.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    api = module.API(Path("/etc/resin-apps/admin.token").read_text().strip())
    slots, approved = rotation_pool.published(api)
    config = rotation_pool.render(yaml.safe_load(args.base.read_text()),
                                  yaml.safe_load(args.input.read_text()), slots, approved)
    args.input.write_text(yaml.safe_dump(config, sort_keys=False))


if __name__ == "__main__":
    main()
