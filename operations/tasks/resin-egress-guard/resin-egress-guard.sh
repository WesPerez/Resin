#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
TASK_DIR="${TASK_DIR:-/opt/resin-operations/operations/tasks/resin-egress-guard}"
CONFIG_PATH="${CONFIG_PATH:-/etc/server-scheduled-tasks/resin-egress-guard.json}"

exec "$PYTHON_BIN" "$TASK_DIR/resin_egress_guard.py" --config "$CONFIG_PATH" "$@"
