#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
TASK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$TASK_DIR/lib"
GLOBAL_HELPER="${GLOBAL_HELPER:-$LIB_DIR/global-pool.sh}"
CN_HELPER="${CN_HELPER:-$LIB_DIR/cn-pool.sh}"
GLOBAL_CONFIG_PATH="${GLOBAL_CONFIG_PATH:-/etc/resin-pool-maintainer/config.json}"
CN_CONFIG_PATH="${CN_CONFIG_PATH:-/etc/resin-app-pools/cn.json}"
GLOBAL_STATE_DIR="${GLOBAL_STATE_DIR:-/var/lib/resin-pool-maintainer}"
ORCHESTRATOR_STATE_PATH="${ORCHESTRATOR_STATE_PATH:-${GLOBAL_STATE_DIR}/orchestrator-state.json}"
LAST_RUN_PATH="${LAST_RUN_PATH:-${GLOBAL_STATE_DIR}/last-unified-run.json}"
UNIFIED_LOCK_PATH="${UNIFIED_RESIN_LOCK:-/run/lock/resin-pool-maintenance-data-plane.lock}"
PRIORITY_LOCK_PATH="${UNIFIED_RESIN_PRIORITY_LOCK:-${UNIFIED_LOCK_PATH}.priority}"
LOCK_WAIT_SECONDS="${UNIFIED_RESIN_LOCK_WAIT_SECONDS:-780}"
MAINTENANCE_LOCK_PATH="${UNIFIED_RESIN_MAINTENANCE_LOCK:-${UNIFIED_LOCK_PATH}.maintenance}"
export PYTHONPATH="${LIB_DIR}${PYTHONPATH:+:${PYTHONPATH}}"

usage() {
  printf 'usage: %s run <admin-token-file> <direct-proxy-token-file>\n' "$0"
}

require_file() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]] || {
    printf 'required file is missing: %s\n' "$path" >&2
    return 2
  }
}

require_private_file() {
  local path="$1" mode
  require_file "$path" || return
  mode="$(stat -c '%a' "$path")"
  [[ "$mode" == "400" || "$mode" == "600" ]] || {
    printf 'private file mode must be 0400/0600: %s\n' "$path" >&2
    return 2
  }
}

read_last_global_success() {
  if [[ -f "$ORCHESTRATOR_STATE_PATH" ]]; then
    jq -r '.last_global_success_epoch // 0' "$ORCHESTRATOR_STATE_PATH" 2>/dev/null || printf '0\n'
  else
    printf '0\n'
  fi
}

write_status() {
  local global_status="$1" cn_status="$2" overall_status="$3"
  local last_global_success_epoch="$4" run_started_at="$5" run_finished_at="$6" run_id="$7"
  local status_dir
  status_dir="$(dirname -- "$LAST_RUN_PATH")"
  mkdir -p -m 0700 "$status_dir"
  "$PYTHON_BIN" - "$ORCHESTRATOR_STATE_PATH" "$LAST_RUN_PATH" \
    "$global_status" "$cn_status" "$overall_status" \
    "$last_global_success_epoch" "$run_started_at" "$run_finished_at" "$run_id" <<'PY'
import json
import os
import sys
from pathlib import Path

state_path, run_path, global_status, cn_status, overall_status, last_global, started, finished, run_id = sys.argv[1:]
state = {
    "version": 1,
    "last_global_success_epoch": int(last_global),
    "last_run_started_at": started,
    "last_run_finished_at": finished,
    "global_status": global_status,
    "cn_status": cn_status,
    "overall_status": overall_status,
    "run_id": run_id,
}
for raw_path in (state_path, run_path):
    path = Path(raw_path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    payload = (json.dumps(state, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode()
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    os.chmod(path, 0o600)
PY
}

run_cn() {
  local admin_token_file="$1" rc
  printf '%s\n' 'POOL CN begin'
  UNIFIED_LOCK_HELD=1 \
    CN_CONFIG="$CN_CONFIG_PATH" \
    CN_SYNC_SCRIPT="$LIB_DIR/resin_pool_sync.py" \
    PYTHON_BIN="$PYTHON_BIN" \
    PYTHONPATH="$PYTHONPATH" \
    "$CN_HELPER" "$admin_token_file"
  rc=$?
  if [[ "$rc" -ne 0 ]]; then
    return "$rc"
  fi
  printf '%s\n' 'POOL CN success'
}

rollback_global_bridge() {
  UNIFIED_LOCK_HELD=1 \
    CONFIG_PATH="$GLOBAL_CONFIG_PATH" \
    PYTHON_BIN="$PYTHON_BIN" \
    PYTHONPATH="$PYTHONPATH" \
    "$GLOBAL_HELPER" rollback-bridge >/dev/null 2>&1 || {
      printf '%s\n' 'POOL Global bridge rollback failed' >&2
      return 1
    }
}

run_global_primary() {
  local admin_token_file="$1" direct_token_file="$2"
  local rc

  printf '%s\n' 'POOL Global primary begin'
  CONFIG_PATH="$GLOBAL_CONFIG_PATH" PYTHON_BIN="$PYTHON_BIN" \
    PYTHONPATH="$PYTHONPATH" "$GLOBAL_HELPER" capacity-bridge
  rc=$?
  if [[ "$rc" -ne 0 ]]; then return "$rc"; fi
  CONFIG_PATH="$GLOBAL_CONFIG_PATH" PYTHON_BIN="$PYTHON_BIN" \
    PYTHONPATH="$PYTHONPATH" "$GLOBAL_HELPER" prepare-bridge "$direct_token_file"
  rc=$?
  if [[ "$rc" -ne 0 ]]; then return "$rc"; fi
  acquire_data_lock || return
  run_global_commit "$admin_token_file"
  rc=$?
  release_data_lock
  return "$rc"
}

acquire_data_lock() {
  if ! flock -w "$LOCK_WAIT_SECONDS" 6; then
    printf '%s\n' 'POOL maintenance priority wait expired' >&2
    return 1
  fi
  if ! flock -w "$LOCK_WAIT_SECONDS" 7; then
    flock -u 6
    printf '%s\n' 'POOL data-plane lock wait expired; pools unchanged' >&2
    return 1
  fi
  DATA_LOCK_STARTED_AT="$SECONDS"
  printf '%s\n' 'POOL data-plane lock acquired'
}

release_data_lock() {
  flock -u 7
  flock -u 6
  printf 'POOL data-plane lock released held_seconds=%s\n' "$((SECONDS - DATA_LOCK_STARTED_AT))"
}

run_global_commit() {
  local admin_token_file="$1" rc
  UNIFIED_LOCK_HELD=1 CONFIG_PATH="$GLOBAL_CONFIG_PATH" PYTHON_BIN="$PYTHON_BIN" \
    PYTHONPATH="$PYTHONPATH" "$GLOBAL_HELPER" promote-bridge
  rc=$?
  if [[ "$rc" -ne 0 ]]; then rollback_global_bridge || return 1; return "$rc"; fi
  UNIFIED_LOCK_HELD=1 CONFIG_PATH="$GLOBAL_CONFIG_PATH" PYTHON_BIN="$PYTHON_BIN" \
    PYTHONPATH="$PYTHONPATH" "$GLOBAL_HELPER" restart-bridge
  rc=$?
  if [[ "$rc" -ne 0 ]]; then rollback_global_bridge || return 1; return "$rc"; fi
  BRIDGE_CHECK_VIA_SYNC=1 UNIFIED_LOCK_HELD=1 CONFIG_PATH="$GLOBAL_CONFIG_PATH" PYTHON_BIN="$PYTHON_BIN" \
    PYTHONPATH="$PYTHONPATH" "$GLOBAL_HELPER" check-bridge
  rc=$?
  if [[ "$rc" -ne 0 ]]; then rollback_global_bridge || return 1; return "$rc"; fi
  UNIFIED_LOCK_HELD=1 CONFIG_PATH="$GLOBAL_CONFIG_PATH" PYTHON_BIN="$PYTHON_BIN" \
    PYTHONPATH="$PYTHONPATH" "$GLOBAL_HELPER" sync "$admin_token_file"
  rc=$?
  if [[ "$rc" -ne 0 ]]; then rollback_global_bridge || return 1; return "$rc"; fi
  UNIFIED_LOCK_HELD=1 CONFIG_PATH="$GLOBAL_CONFIG_PATH" PYTHON_BIN="$PYTHON_BIN" \
    PYTHONPATH="$PYTHONPATH" "$GLOBAL_HELPER" commit-bridge
  rc=$?
  if [[ "$rc" -ne 0 ]]; then rollback_global_bridge || return 1; return "$rc"; fi
  printf '%s\n' 'POOL Global primary success'
}

run_all() {
  local admin_token_file="${1:-}" direct_token_file="${2:-}"
  [[ -n "$admin_token_file" && -n "$direct_token_file" ]] || { usage >&2; return 2; }
  command -v jq >/dev/null 2>&1 || { printf '%s\n' 'jq is required' >&2; return 2; }
  require_private_file "$admin_token_file" || return
  require_private_file "$direct_token_file" || return
  require_file "$GLOBAL_HELPER" || return
  require_file "$CN_HELPER" || return

  mkdir -p -m 0700 "$(dirname -- "$UNIFIED_LOCK_PATH")" "$GLOBAL_STATE_DIR"
  [[ "$LOCK_WAIT_SECONDS" =~ ^[0-9]+$ ]] || return 2
  exec 5>"$MAINTENANCE_LOCK_PATH"
  if ! flock -n 5; then
    printf '%s\n' 'POOL maintenance already active; skipped duplicate run'
    return 0
  fi
  exec 6>"$PRIORITY_LOCK_PATH"
  exec 7>"$UNIFIED_LOCK_PATH"
  acquire_data_lock || return

  local started finished last_global_success_epoch global_status cn_status overall_status run_id global_rc
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  export RESIN_MAINTENANCE_RUN_ID="$run_id"
  last_global_success_epoch="$(read_last_global_success)"
  [[ "$last_global_success_epoch" =~ ^[0-9]+$ ]] || last_global_success_epoch=0

  if run_cn "$admin_token_file"; then
    cn_status=success
  else
    cn_status=failed
    printf '%s\n' 'POOL CN failed; Global processing continues' >&2
  fi
  release_data_lock

  # Serialize maintenance separately so quality checks can run during preparation.
  if run_global_primary "$admin_token_file" "$direct_token_file"; then
    global_status=success
    last_global_success_epoch="$(date +%s)"
  else
    global_rc=$?
    if [[ "$global_rc" == 75 ]]; then
      global_status=deferred
      printf '%s\n' 'POOL Global update deferred; live TCP sessions retain previous pool'
    else
      global_status=primary_failed
      printf '%s\n' 'POOL Global primary failed; previous fixed-port pool retained' >&2
    fi
  fi

  case "$global_status" in
    success)
      [[ "$cn_status" == success ]] && overall_status=success || overall_status=failed
      ;;
    deferred)
      [[ "$cn_status" == success ]] && overall_status=deferred || overall_status=failed
      ;;
    *)
      overall_status=failed
      ;;
  esac
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  write_status "$global_status" "$cn_status" "$overall_status" \
    "$last_global_success_epoch" "$started" "$finished" "$run_id"
  printf 'POOL SUMMARY run_id=%s global=%s cn=%s overall=%s\n' \
    "$run_id" "$global_status" "$cn_status" "$overall_status"
  [[ "$overall_status" == success || "$overall_status" == deferred ]]
}

case "${1:-}" in
  --help|-h)
    usage
    ;;
  run)
    shift
    run_all "$@"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
