#!/usr/bin/env bash
set -Eeuo pipefail
TASK_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$TASK_DIR/bluegreen.py" restore
