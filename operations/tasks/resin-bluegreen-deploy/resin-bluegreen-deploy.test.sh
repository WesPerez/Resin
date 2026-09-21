#!/usr/bin/env bash
set -Eeuo pipefail
TASK_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$TASK_DIR"
exec python3 -m unittest -v test_bluegreen.py
