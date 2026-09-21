#!/usr/bin/env bash
set -euo pipefail

TASK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

bash -n \
  "$TASK_DIR/resin-pool-maintenance.sh" \
  "$TASK_DIR/lib/global-pool.sh" \
  "$TASK_DIR/lib/cn-pool.sh" \
  "$TASK_DIR/probe-cn-candidate.sh" \
  "$TASK_DIR/global-pool.test.sh" \
  "$TASK_DIR/cn-pool.test.sh" \
  "$TASK_DIR/orchestrator.test.sh"

python3 - "$TASK_DIR/lib" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for path in sorted(root.glob("*.py")):
    compile(path.read_text(encoding="utf-8"), str(path), "exec")
PY

python3 -m json.tool "$TASK_DIR/global.json.example" >/dev/null
python3 -m json.tool "$TASK_DIR/cn.json.example" >/dev/null

if rg -n 'CODEX_SKILLS_ROOT|/root/\.codex/skills' \
  "$TASK_DIR" --glob '!*.test.sh'; then
  printf '%s\n' 'runtime still depends on Codex Profile skills' >&2
  exit 1
fi

if rg -n 'managed-grok-public-pool|platform_name.*GrokEU|/run/resin-pool-maintainer-fallback' \
  "$TASK_DIR/lib/resin_pool_sync.py" \
  "$TASK_DIR/lib/global-pool.sh"; then
  printf '%s\n' 'runtime still contains retired Global defaults' >&2
  exit 1
fi

if rg -n 'BRIDGE_MINIMUM_HEALTHY_NODES' "$TASK_DIR" \
  --glob '!resin-pool-maintenance.test.sh'; then
  printf '%s\n' 'retired Global count floor remains in the unified task' >&2
  exit 1
fi

if rg -n 'maintain-resin-grok-pool|resin-cn-pool-maintenance|resin-apps-pool-maintainer' \
  "$TASK_DIR/lib" "$TASK_DIR"/*.json.example "$TASK_DIR"/systemd; then
  printf '%s\n' 'retired owner or compatibility path remains in active runtime' >&2
  exit 1
fi

rg -q 'OWNER = "resin-pool-maintenance"' \
  "$TASK_DIR/lib/resin_pool_sync.py" \
  "$TASK_DIR/lib/singbox_bridge_pool.py"

if rg -n 'discover_linuxdo_proxy_batch|linuxdo-current-public-batches|refresh-forum-fallback|fallback-sync' \
  "$TASK_DIR" --glob '!*.test.sh'; then
  printf '%s\n' 'retired direct-proxy fallback remains in the fixed-port pool task' >&2
  exit 1
fi

bash "$TASK_DIR/global-pool.test.sh"
bash "$TASK_DIR/cn-pool.test.sh"
bash "$TASK_DIR/orchestrator.test.sh"
PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s "$TASK_DIR/tests" -p 'test_*.py' -v

systemd-analyze verify \
  "$TASK_DIR/systemd/resin-pool-maintenance.service" \
  "$TASK_DIR/systemd/resin-pool-maintenance.timer" \
  "$TASK_DIR/../resin-bluegreen-deploy/systemd/resin-apps.service" \
  "$TASK_DIR/systemd/resin-singbox-bridge.service"

printf '%s\n' 'PASS: unified Resin Global/CN maintenance test suite'
