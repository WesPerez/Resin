#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TASK_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="${RESIN_POOL_LIB_DIR:-$SCRIPT_DIR}"
CONFIG_PATH="${CONFIG_PATH:-/etc/resin-pool-maintainer/config.json}"
BRIDGE_OUTPUT_DIR="${BRIDGE_OUTPUT_DIR:-/var/lib/resin-singbox-bridge}"
BRIDGE_SOURCE_URL="${BRIDGE_SOURCE_URL:-https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/singbox.json}"
BRIDGE_TARGET_HOSTS="${BRIDGE_TARGET_HOSTS:-www.cloudflare.com www.microsoft.com www.wikipedia.org}"
SINGBOX_BINARY="${SINGBOX_BINARY:-/opt/resin-singbox-bridge/bin/sing-box}"
BRIDGE_SERVICE="${BRIDGE_SERVICE:-resin-singbox-bridge.service}"
BRIDGE_SWITCH_MODE="${BRIDGE_SWITCH_MODE:-graceful}"
BRIDGE_STAGED_LINK="${BRIDGE_STAGED_LINK:-${BRIDGE_OUTPUT_DIR}/staged}"
SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-/usr/bin/systemctl}"
UNIFIED_LOCK_PATH="${UNIFIED_RESIN_LOCK:-/run/lock/resin-pool-maintenance-data-plane.lock}"

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf 'required file is missing: %s\n' "$path" >&2
    exit 2
  fi
}

bridge_manifest_value() {
  local field="$1" manifest="${BRIDGE_OUTPUT_DIR}/current/manifest.json"
  require_file "$manifest"
  jq -er --arg field "$field" '.[$field] | select(type == "string" and length > 0)' \
    "$manifest"
}

wait_bridge_listeners() {
  local bridge_pid
  bridge_pid="$("$SYSTEMCTL_BIN" show "$BRIDGE_SERVICE" --property=MainPID --value)"
  if [[ ! "$bridge_pid" =~ ^[0-9]+$ ]] || (( bridge_pid <= 1 )); then
    printf 'bridge service has no running main process\n' >&2
    return 1
  fi
  "$PYTHON_BIN" "${LIB_DIR}/singbox_bridge_pool.py" wait-listeners \
    --output-dir "$BRIDGE_OUTPUT_DIR" --pid "$bridge_pid" \
    --timeout-seconds "${BRIDGE_LISTENER_WAIT_SECONDS:-60}"
}

switch_bridge() {
  case "$BRIDGE_SWITCH_MODE" in
    graceful)
      "$PYTHON_BIN" "${LIB_DIR}/bridge_runtime.py" switch --root "$BRIDGE_OUTPUT_DIR" \
        --runtime-dir "${BRIDGE_RUNTIME_DIR:-/run/resin-singbox-bridge}"
      ;;
    restart)
      # Explicit migration rollback only; periodic production updates use graceful.
      "$SYSTEMCTL_BIN" restart "$BRIDGE_SERVICE"
      wait_bridge_listeners
      ;;
    *) printf 'invalid BRIDGE_SWITCH_MODE\n' >&2; return 2 ;;
  esac
}

run_resin_sync() {
  local script="$1" config_path="$2" token_file="$3"
  local bridge_generation bridge_run_id
  bridge_generation="$(bridge_manifest_value generation)"
  if ! bridge_run_id="$(bridge_manifest_value run_id 2>/dev/null)"; then
    # Generations created before correlation metadata was introduced remain
    # valid. Associate them with this maintenance run rather than refusing a
    # first post-migration sync.
    bridge_run_id="${RESIN_MAINTENANCE_RUN_ID:-bridge-${bridge_generation}}"
  fi
  [[ -n "$bridge_run_id" ]] || bridge_run_id="bridge-${bridge_generation}"
  export RESIN_BRIDGE_GENERATION="$bridge_generation"
  export RESIN_BRIDGE_RUN_ID="$bridge_run_id"
  exec "$PYTHON_BIN" "$script" run \
    --config "$config_path" \
    --admin-token-file "$token_file" \
    --confirm-production-write
}

case "${1:-}" in
  capacity-bridge)
    case "$BRIDGE_SWITCH_MODE" in
      graceful)
        exec "$PYTHON_BIN" "${LIB_DIR}/bridge_runtime.py" capacity --root "$BRIDGE_OUTPUT_DIR" \
          --runtime-dir "${BRIDGE_RUNTIME_DIR:-/run/resin-singbox-bridge}"
        ;;
      restart)
        printf '%s\n' 'bridge capacity check skipped: explicit restart rollback mode' >&2
        ;;
      *) printf 'invalid BRIDGE_SWITCH_MODE\n' >&2; exit 2 ;;
    esac
    ;;
  refresh-bridge|prepare-bridge)
    script="${LIB_DIR}/singbox_bridge_pool.py"
    require_file "$script"
    direct_password_file="${2:-${BRIDGE_DIRECT_PASSWORD_FILE:-}}"
    require_file "$direct_password_file"
    read -r -a target_hosts <<<"$BRIDGE_TARGET_HOSTS"
    if [[ "${#target_hosts[@]}" -eq 0 ]]; then
      printf 'BRIDGE_TARGET_HOSTS must not be empty\n' >&2
      exit 2
    fi
    target_args=()
    if [[ "$1" == prepare-bridge ]]; then
      target_args+=(--prepare-only)
    fi
    if [[ -n "${BRIDGE_DISCOVERY_CONFIG:-}" ]]; then
      target_args+=(--discovery-config "$BRIDGE_DISCOVERY_CONFIG"
                    --subscription-converter "${BRIDGE_SUBSCRIPTION_CONVERTER:-/opt/resin-subscription-converter/bin/subscription-converter}")
    fi
    for target_host in "${target_hosts[@]}"; do
      target_args+=(--target-host "$target_host")
    done
    exec "$PYTHON_BIN" "$script" \
      refresh \
      --source-url "$BRIDGE_SOURCE_URL" \
      --output-dir "$BRIDGE_OUTPUT_DIR" \
      --singbox-binary "$SINGBOX_BINARY" \
      --target-nodes "${BRIDGE_TARGET_NODES:-1000}" \
      --minimum-healthy-nodes 1 \
      --candidate-limit "${BRIDGE_CANDIDATE_LIMIT:-0}" \
      --max-per-egress 0 \
      --max-per-credential-group "${BRIDGE_MAX_PER_CREDENTIAL_GROUP:-0}" \
      --minimum-replacements-to-publish 1 \
      --maximum-generation-age-hours "${BRIDGE_MAX_GENERATION_AGE_HOURS:-24}" \
      --retain-generations "${BRIDGE_RETAIN_GENERATIONS:-1}" \
      --dns-workers "${BRIDGE_DNS_WORKERS:-16}" \
      --probe-workers "${BRIDGE_PROBE_WORKERS:-32}" \
      --probe-batch-size "${BRIDGE_PROBE_BATCH_SIZE:-64}" \
      --probe-base-port "${BRIDGE_PROBE_BASE_PORT:-20000}" \
      --min-target-hosts-passed "${BRIDGE_MIN_TARGET_HOSTS_PASSED:-2}" \
      --excluded-region cn \
      "${target_args[@]}" \
      --publish-listen "${BRIDGE_PUBLISH_LISTEN:-172.17.0.1}" \
      --publish-base-port "${BRIDGE_PUBLISH_BASE_PORT:-12000}" \
      --direct-port "${BRIDGE_DIRECT_PORT:-12400}" \
      --direct-username "${BRIDGE_DIRECT_USERNAME:-sub2-direct}" \
      --direct-password-file "$direct_password_file"
    ;;
  promote-bridge)
    exec "$PYTHON_BIN" "${LIB_DIR}/singbox_bridge_pool.py" promote --output-dir "$BRIDGE_OUTPUT_DIR"
    ;;
  restart-bridge)
    current_link="${BRIDGE_OUTPUT_DIR}/current"
    require_file "${current_link}/bridge.json"
    if [[ ! -L "$BRIDGE_STAGED_LINK" ]]; then
      printf '{"status":"unchanged","bridge_restart":false}\n'
      exit 0
    fi
    if [[ -f /etc/xray/site-quality-policy.json ]]; then
      # Revoke approvals for changed slots before the new process serves them.
      "$PYTHON_BIN" "$TASK_DIR/../proxy-subscription/site-control.py" enforce --lock-held
    fi
    switch_bridge
    ;;
  commit-bridge)
    require_file "${BRIDGE_OUTPUT_DIR}/current/bridge.json"
    script="${LIB_DIR}/singbox_bridge_pool.py"
    require_file "$script"
    exec "$PYTHON_BIN" "$script" commit \
      --output-dir "$BRIDGE_OUTPUT_DIR" \
      --retain-generations "${BRIDGE_RETAIN_GENERATIONS:-1}"
    ;;
  rollback-bridge)
    if [[ ! -L "$BRIDGE_STAGED_LINK" ]]; then
      exit 0
    fi
    staged_target="$(readlink -f -- "$BRIDGE_STAGED_LINK")"
    generations_target="$(readlink -f -- "${BRIDGE_OUTPUT_DIR}/generations")"
    current_link="${BRIDGE_OUTPUT_DIR}/current"
    if [[ "$staged_target" == "$generations_target" ]]; then
      "$SYSTEMCTL_BIN" stop "$BRIDGE_SERVICE"
      rm -- "$current_link"
    else
      require_file "${staged_target}/bridge.json"
      case "$staged_target" in
        "$generations_target"/*) ;;
        *) printf 'rollback generation is outside the managed root\n' >&2; exit 2 ;;
      esac
      temporary="${BRIDGE_OUTPUT_DIR}/.current.rollback-$$"
      ln -s -- "generations/${staged_target##*/}" "$temporary"
      mv -Tf -- "$temporary" "$current_link"
      if [[ -f /etc/xray/site-quality-policy.json ]]; then
        "$PYTHON_BIN" "$TASK_DIR/../proxy-subscription/site-control.py" enforce --lock-held
      fi
      switch_bridge
    fi
    rm -- "$BRIDGE_STAGED_LINK"
    script="${LIB_DIR}/singbox_bridge_pool.py"
    require_file "$script"
    "$PYTHON_BIN" "$script" prune \
      --output-dir "$BRIDGE_OUTPUT_DIR" \
      --retain-generations "${BRIDGE_RETAIN_GENERATIONS:-1}" >/dev/null
    ;;
  check-bridge)
    if [[ ! -L "$BRIDGE_STAGED_LINK" ]]; then
      printf '{"status":"unchanged","bridge_check":false}\n'
      exit 0
    fi
    if [[ "${BRIDGE_CHECK_VIA_SYNC:-0}" == 1 ]] && jq -e \
      --arg path "${BRIDGE_OUTPUT_DIR}/current/proxies.txt" '
        (.sources | length) == 1 and .sources[0].type == "file" and .sources[0].path == $path
        and .resin.include_current_subscription == false and .safety.mode == "non_empty"
        and (.validation.target_hosts | sort) == ["www.cloudflare.com", "www.microsoft.com", "www.wikipedia.org"]
        and .validation.min_target_hosts_passed >= 2 and .validation.trace_egress == true
        and .validation.timeout_seconds == 8
        and .selection.require_egress == true and .selection.max_nodes <= 1000
        and (.selection.excluded_regions | index("cn")) != null
      ' "$CONFIG_PATH" >/dev/null 2>&1; then
      printf '{"status":"validated_by_sync","bridge_check":false}\n'
      exit 0
    fi
    script="${LIB_DIR}/resin_pool_sync.py"
    require_file "$script"
    require_file "${BRIDGE_OUTPUT_DIR}/current/proxies.txt"
    runtime_root="${RUNTIME_DIRECTORY:-/run/resin-pool-maintenance}"
    mkdir -p -m 0700 "$runtime_root"
    temporary_dir="$(mktemp -d "${runtime_root}/postrestart-check.XXXXXX")"
    trap 'rm -rf -- "$temporary_dir"' EXIT
    check_config="$temporary_dir/config.json"
    check_output="$temporary_dir/validated-proxies.txt"
    check_report="$temporary_dir/report.json"
    "$PYTHON_BIN" - "$check_config" "${BRIDGE_OUTPUT_DIR}/current/proxies.txt" \
      "${BRIDGE_PROBE_WORKERS:-32}" "${BRIDGE_PROBE_BATCH_SIZE:-64}" <<'PY'
import json
import sys
config_path, source_path, workers, batch_size = sys.argv[1:]
config = {
    "sources": [{
        "id": "postrestart-singbox-bridge",
        "type": "file",
        "path": source_path,
        "allowed_non_public_proxy_ips": ["172.17.0.1"],
    }],
    "validation": {
        "workers": int(workers),
        "batch_size": int(batch_size),
        "timeout_seconds": 8,
        "target_hosts": ["www.cloudflare.com", "www.microsoft.com", "www.wikipedia.org"],
        "min_target_hosts_passed": 2,
        "trace_egress": True,
    },
    "selection": {
        "max_nodes": 1000,
        "max_per_egress": 0,
        "max_per_credential_group": 0,
        "min_per_region": 1,
        "require_egress": True,
        "allowed_regions": [],
        "excluded_regions": ["cn"],
    },
}
with open(config_path, "w", encoding="utf-8") as handle:
    json.dump(config, handle)
PY
    chmod 0600 "$check_config"
    "$PYTHON_BIN" - "$LIB_DIR" "$check_config" "$check_output" "$check_report" <<'PY'
import sys
from pathlib import Path
lib_dir, config_path, output_path, report_path = sys.argv[1:]
sys.path.insert(0, str(Path(lib_dir)))
from proxy_probe import validation_from_config
from resin_pool_sync import load_json
validation_from_config(load_json(Path(config_path)), Path(output_path), Path(report_path))
PY
    "$PYTHON_BIN" - "$check_report" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
passed = int(report.get("passed_count") or 0)
selected = int(report.get("selected_count") or 0)
if passed < 1 or selected < 1:
    raise SystemExit(
        f"post-restart bridge validation yielded no usable nodes: "
        f"selected={selected}, passed={passed}"
    )
PY
    rm -rf -- "$temporary_dir"
    trap - EXIT
    ;;
  sync)
    script="${LIB_DIR}/resin_pool_sync.py"
    token_file="${2:-}"
    require_file "$script"
    require_file "$CONFIG_PATH"
    require_file "$token_file"
    mkdir -p -- "$(dirname -- "$UNIFIED_LOCK_PATH")"
    if [[ "${UNIFIED_LOCK_HELD:-0}" != "1" ]]; then
      exec 8>"$UNIFIED_LOCK_PATH"
      if ! flock -n 8; then
        printf 'unified Resin data plane is already being updated; skipping Global sync\n' >&2
        exit 0
      fi
    fi
    run_resin_sync "$script" "$CONFIG_PATH" "$token_file"
    ;;
  *)
    printf 'usage: %s {capacity-bridge|prepare-bridge|refresh-bridge|promote-bridge|restart-bridge|check-bridge|sync <admin-token-file>|commit-bridge|rollback-bridge}\n' "$0" >&2
    exit 2
    ;;
esac
