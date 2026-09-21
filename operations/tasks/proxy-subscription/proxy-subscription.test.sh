#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
for script in "$root"/*.sh; do bash -n "$script"; done
jq empty "$root/examples/xray-proxy.json.example"
python3 "$root/test_subscription.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$root/test_region_latency.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$root/test_site_quality.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$root/test_rotation_pool.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$root/test_unified_quality.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$root/test_rotation_acceptance.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$root/test_client_pools.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$root/test_client_health.py"
systemd-analyze verify "$root/systemd/proxy-client-health.service" "$root/systemd/proxy-client-health.timer"
printf 'proxy-subscription offline checks passed\n'
