#!/usr/bin/env bash
set -euo pipefail

TASK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

python3 -m unittest discover -s "$TASK_DIR/tests" -p 'test_*.py' -v
python3 -m py_compile "$TASK_DIR/resin_egress_guard.py"
bash -n "$TASK_DIR/resin-egress-guard.sh"
systemd-analyze verify "$TASK_DIR/systemd/resin-egress-guard.service"
