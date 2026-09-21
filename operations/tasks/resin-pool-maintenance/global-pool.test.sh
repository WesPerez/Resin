#!/usr/bin/env bash
set -euo pipefail

# Legacy restart is retained only as an explicit migration rollback path.
export BRIDGE_SWITCH_MODE=restart

TASK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$TASK_DIR/lib/global-pool.sh"
TEST_ROOT="$(mktemp -d /tmp/resin-global-pool-test.XXXXXX)"

cleanup() {
  local status=$?
  trap - EXIT
  rm -rf -- "$TEST_ROOT"
  exit "$status"
}
trap cleanup EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$TEST_ROOT/lib" "$TEST_ROOT/source"
: >"$TEST_ROOT/lib/singbox_bridge_pool.py"
: >"$TEST_ROOT/lib/resin_pool_sync.py"
: >"$TEST_ROOT/sing-box"
: >"$TEST_ROOT/config.json"
: >"$TEST_ROOT/token"
: >"$TEST_ROOT/direct-token"
chmod 0600 "$TEST_ROOT/direct-token"

cat >"$TEST_ROOT/python" <<'FAKE_PYTHON'
#!/usr/bin/env bash
set -euo pipefail
printf 'bridge_generation=%s\n' "${RESIN_BRIDGE_GENERATION:-}" >"$FAKE_PYTHON_ENV_LOG"
printf 'bridge_run_id=%s\n' "${RESIN_BRIDGE_RUN_ID:-}" >>"$FAKE_PYTHON_ENV_LOG"
printf '%s\n' "$@" >"$FAKE_PYTHON_LOG"
exit "${FAKE_PYTHON_STATUS:-0}"
FAKE_PYTHON
chmod 0755 "$TEST_ROOT/python"
cat >"$TEST_ROOT/systemctl" <<'FAKE_SYSTEMCTL'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >>"$FAKE_SYSTEMCTL_LOG"
if [[ "${1:-}" == show ]]; then
  printf '%s\n' "${FAKE_MAINPID:-4242}"
fi
FAKE_SYSTEMCTL
chmod 0755 "$TEST_ROOT/systemctl"

# Real bridge helpers remain testable; the cross-task production hook is isolated.
cat >"$TEST_ROOT/isolated-python" <<'ISOLATED_PYTHON'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  */proxy-subscription/site-control.py)
    printf '%s\n' "$@" >>"$FAKE_SITE_CONTROL_LOG"
    exit 0
    ;;
  */singbox_bridge_pool.py)
    if [[ "${2:-}" == wait-listeners ]]; then
      printf '%s\n' "$@" >>"$FAKE_BRIDGE_READY_LOG"
      exit "${FAKE_BRIDGE_READY_STATUS:-0}"
    fi
    ;;
esac
exec python3 "$@"
ISOLATED_PYTHON
chmod 0755 "$TEST_ROOT/isolated-python"
export PYTHON_BIN="$TEST_ROOT/isolated-python"
export FAKE_SITE_CONTROL_LOG="$TEST_ROOT/site-control.log"
export FAKE_BRIDGE_READY_LOG="$TEST_ROOT/listener-ready.log"

# Capacity preflight never restarts the bridge; preserve exact deferred/error codes.
for expected in 0 75 1; do
  status=0
  BRIDGE_SWITCH_MODE=graceful FAKE_PYTHON_STATUS="$expected" \
    FAKE_PYTHON_LOG="$TEST_ROOT/capacity.log" FAKE_PYTHON_ENV_LOG="$TEST_ROOT/capacity.env" \
    PYTHON_BIN="$TEST_ROOT/python" RESIN_POOL_LIB_DIR="$TEST_ROOT/lib" \
    "$SCRIPT" capacity-bridge || status=$?
  [[ "$status" -eq "$expected" ]] || fail 'capacity result was not preserved'
  grep -Fxq -- capacity "$TEST_ROOT/capacity.log" || fail 'capacity command missing'
done
BRIDGE_SWITCH_MODE=restart "$SCRIPT" capacity-bridge 2>"$TEST_ROOT/capacity-skip.log"
grep -Fq 'skipped' "$TEST_ROOT/capacity-skip.log" || fail 'rollback capacity skip was not explained'
status=0
BRIDGE_SWITCH_MODE=invalid "$SCRIPT" capacity-bridge >/dev/null 2>&1 || status=$?
[[ "$status" -eq 2 ]] || fail 'invalid bridge mode was accepted'

FAKE_PYTHON_LOG="$TEST_ROOT/refresh.log" \
FAKE_PYTHON_ENV_LOG="$TEST_ROOT/refresh.env" \
PYTHON_BIN="$TEST_ROOT/python" \
RESIN_POOL_LIB_DIR="$TEST_ROOT/lib" \
BRIDGE_OUTPUT_DIR="$TEST_ROOT/bridge" \
SINGBOX_BINARY="$TEST_ROOT/sing-box" \
BRIDGE_TARGET_NODES=1000 \
"$SCRIPT" refresh-bridge "$TEST_ROOT/direct-token"

grep -Fxq -- 'refresh' "$TEST_ROOT/refresh.log" || fail 'bridge refresh mode missing'
grep -Fxq -- '--target-nodes' "$TEST_ROOT/refresh.log" || fail 'bridge target missing'
grep -Fxq -- '1000' "$TEST_ROOT/refresh.log" || fail 'bridge target value missing'
grep -Fxq -- '--minimum-healthy-nodes' "$TEST_ROOT/refresh.log" \
  || fail 'bridge non-empty validation flag missing'
[[ "$(awk '$0 == "--minimum-healthy-nodes" { getline; print; exit }' "$TEST_ROOT/refresh.log")" == '1' ]] \
  || fail 'bridge must only require a non-empty validated set'
[[ "$(awk '$0 == "--max-per-egress" { getline; print; exit }' "$TEST_ROOT/refresh.log")" == '0' ]] \
  || fail 'bridge egress count cap was not disabled'
[[ "$(awk '$0 == "--candidate-limit" { getline; print; exit }' "$TEST_ROOT/refresh.log")" == '0' ]] \
  || fail 'bridge candidate probe limit was not unlimited'
[[ "$(awk '$0 == "--max-per-credential-group" { getline; print; exit }' "$TEST_ROOT/refresh.log")" == '0' ]] \
  || fail 'bridge credential group limit was not disabled'
[[ "$(awk '$0 == "--min-target-hosts-passed" { getline; print; exit }' "$TEST_ROOT/refresh.log")" == '2' ]] \
  || fail 'bridge target quorum does not match Global validation'
grep -Fxq -- '--excluded-region' "$TEST_ROOT/refresh.log" \
  || fail 'bridge Global region exclusion flag missing'
[[ "$(awk '$0 == "--excluded-region" { getline; print; exit }' "$TEST_ROOT/refresh.log")" == 'cn' ]] \
  || fail 'bridge CN exclusion value missing'
[[ "$(grep -Fxc -- '--target-host' "$TEST_ROOT/refresh.log")" -eq 3 ]] \
  || fail 'bridge target host count mismatch'
grep -Fxq -- 'www.cloudflare.com' "$TEST_ROOT/refresh.log" || fail 'Cloudflare target missing'
grep -Fxq -- 'www.microsoft.com' "$TEST_ROOT/refresh.log" || fail 'Microsoft target missing'
grep -Fxq -- 'www.wikipedia.org' "$TEST_ROOT/refresh.log" || fail 'Wikipedia target missing'
grep -Fxq -- '--direct-port' "$TEST_ROOT/refresh.log" || fail 'direct port flag missing'
grep -Fxq -- '12400' "$TEST_ROOT/refresh.log" || fail 'direct port value missing'
grep -Fxq -- '--direct-password-file' "$TEST_ROOT/refresh.log" \
  || fail 'direct password flag missing'
grep -Fxq -- "$TEST_ROOT/direct-token" "$TEST_ROOT/refresh.log" \
  || fail 'direct password path missing'

mkdir -p "$TEST_ROOT/bridge/generations/old" "$TEST_ROOT/bridge/generations/new"
: >"$TEST_ROOT/bridge/generations/old/bridge.json"
: >"$TEST_ROOT/bridge/generations/new/bridge.json"
printf '{"owner":"resin-pool-maintenance","generation":"old","run_id":"test-run"}\n' >"$TEST_ROOT/bridge/generations/old/manifest.json"
chmod 0600 "$TEST_ROOT/bridge/generations/old/manifest.json"
ln -s generations/new "$TEST_ROOT/bridge/current"
ln -s generations/old "$TEST_ROOT/bridge/staged"
FAKE_SYSTEMCTL_LOG="$TEST_ROOT/restart.log" \
SYSTEMCTL_BIN="$TEST_ROOT/systemctl" \
BRIDGE_OUTPUT_DIR="$TEST_ROOT/bridge" \
"$SCRIPT" restart-bridge
grep -Fxq -- 'restart' "$TEST_ROOT/restart.log" || fail 'bridge restart missing'
grep -Fxq -- 'wait-listeners' "$TEST_ROOT/listener-ready.log" || fail 'restart did not wait for listeners'
grep -Fxq -- '4242' "$TEST_ROOT/listener-ready.log" || fail 'readiness did not use the service MainPID'

status=0
FAKE_BRIDGE_READY_STATUS=2 FAKE_SYSTEMCTL_LOG="$TEST_ROOT/restart-not-ready.log" \
SYSTEMCTL_BIN="$TEST_ROOT/systemctl" BRIDGE_OUTPUT_DIR="$TEST_ROOT/bridge" \
"$SCRIPT" restart-bridge >/dev/null 2>&1 || status=$?
[[ "$status" -eq 2 && -L "$TEST_ROOT/bridge/staged" ]] \
  || fail 'readiness failure did not retain the rollback marker and fail restart'

status=0
FAKE_MAINPID=0 FAKE_SYSTEMCTL_LOG="$TEST_ROOT/restart-no-pid.log" \
SYSTEMCTL_BIN="$TEST_ROOT/systemctl" BRIDGE_OUTPUT_DIR="$TEST_ROOT/bridge" \
"$SCRIPT" restart-bridge >/dev/null 2>&1 || status=$?
[[ "$status" -ne 0 ]] || fail 'missing MainPID was accepted as ready'

BRIDGE_OUTPUT_DIR="$TEST_ROOT/bridge" "$SCRIPT" commit-bridge
[[ ! -e "$TEST_ROOT/bridge/staged" ]] || fail 'bridge commit marker remains'
[[ ! -e "$TEST_ROOT/bridge/generations/old" ]] || fail 'old generation was not pruned after commit'
BRIDGE_OUTPUT_DIR="$TEST_ROOT/bridge" "$SCRIPT" commit-bridge

rm -f "$TEST_ROOT/restart-unchanged.log"
FAKE_SYSTEMCTL_LOG="$TEST_ROOT/restart-unchanged.log" \
SYSTEMCTL_BIN="$TEST_ROOT/systemctl" \
BRIDGE_OUTPUT_DIR="$TEST_ROOT/bridge" \
"$SCRIPT" restart-bridge
[[ ! -e "$TEST_ROOT/restart-unchanged.log" ]] \
  || fail 'unchanged bridge unexpectedly restarted'

check_skill="$TEST_ROOT/check-lib"
mkdir -p "$check_skill"
cat >"$check_skill/proxy_probe.py" <<'FAKE_PROBE'
import json
def validation_from_config(config, output, report):
    assert config["selection"]["max_nodes"] == 1000
    assert config["selection"]["max_per_egress"] == 0
    assert config["selection"]["max_per_credential_group"] == 0
    output.write_text("", encoding="utf-8")
    report.write_text(json.dumps({"passed_count": 383, "selected_count": 383}), encoding="utf-8")
FAKE_PROBE
cat >"$check_skill/resin_pool_sync.py" <<'FAKE_SYNC'
import json
def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))
FAKE_SYNC
: >"$TEST_ROOT/bridge/generations/new/proxies.txt"
printf '{"generation":"new","run_id":"test-run"}\n' >"$TEST_ROOT/bridge/generations/new/manifest.json"
chmod 0600 "$TEST_ROOT/bridge/generations/new/manifest.json"
unchanged_output="$(
  RESIN_POOL_LIB_DIR="$TEST_ROOT/check-lib" \
  BRIDGE_OUTPUT_DIR="$TEST_ROOT/bridge" \
  RUNTIME_DIRECTORY="$TEST_ROOT/runtime-unchanged" \
  "$SCRIPT" check-bridge
)"
[[ "$unchanged_output" == '{"status":"unchanged","bridge_check":false}' ]] \
  || fail 'unchanged bridge check was not skipped'
[[ ! -e "$TEST_ROOT/runtime-unchanged" ]] \
  || fail 'unchanged bridge check created a runtime directory'

# Recreate a previous generation for the explicit rollback test; successful
# commits intentionally remove historical generations.
mkdir -p "$TEST_ROOT/bridge/generations/old"
: >"$TEST_ROOT/bridge/generations/old/bridge.json"
printf '{"owner":"resin-pool-maintenance","generation":"old","run_id":"test-run"}\n' >"$TEST_ROOT/bridge/generations/old/manifest.json"
chmod 0600 "$TEST_ROOT/bridge/generations/old/manifest.json"
ln -s generations/old "$TEST_ROOT/bridge/staged"
RESIN_POOL_LIB_DIR="$TEST_ROOT/check-lib" \
BRIDGE_OUTPUT_DIR="$TEST_ROOT/bridge" \
RUNTIME_DIRECTORY="$TEST_ROOT/runtime" \
"$SCRIPT" check-bridge
if find "$TEST_ROOT/runtime" -maxdepth 1 -name 'postrestart-check.*' | grep -q .; then
  fail 'bridge check temporary directory remains'
fi

jq -n --arg path "$TEST_ROOT/bridge/current/proxies.txt" '{
  sources: [{type: "file", path: $path}], resin: {include_current_subscription: false},
  safety: {mode: "non_empty"}, validation: {target_hosts: ["www.cloudflare.com", "www.microsoft.com", "www.wikipedia.org"],
  min_target_hosts_passed: 2, trace_egress: true, timeout_seconds: 8}, selection: {require_egress: true, max_nodes: 1000, excluded_regions: ["cn"]}
}' >"$TEST_ROOT/equivalent.json"
delegated="$(BRIDGE_CHECK_VIA_SYNC=1 CONFIG_PATH="$TEST_ROOT/equivalent.json" \
  BRIDGE_OUTPUT_DIR="$TEST_ROOT/bridge" "$SCRIPT" check-bridge)"
[[ "$delegated" == '{"status":"validated_by_sync","bridge_check":false}' ]] \
  || fail 'equivalent sync gate did not replace duplicate probing'
jq '.resin.include_current_subscription = true' "$TEST_ROOT/equivalent.json" >"$TEST_ROOT/different.json"
BRIDGE_CHECK_VIA_SYNC=1 CONFIG_PATH="$TEST_ROOT/different.json" \
  RESIN_POOL_LIB_DIR="$TEST_ROOT/check-lib" BRIDGE_OUTPUT_DIR="$TEST_ROOT/bridge" \
  RUNTIME_DIRECTORY="$TEST_ROOT/runtime-different" "$SCRIPT" check-bridge
[[ -d "$TEST_ROOT/runtime-different" ]] || fail 'non-equivalent sync skipped independent validation'

status=0
FAKE_BRIDGE_READY_STATUS=2 FAKE_SYSTEMCTL_LOG="$TEST_ROOT/rollback-not-ready.log" \
SYSTEMCTL_BIN="$TEST_ROOT/systemctl" BRIDGE_OUTPUT_DIR="$TEST_ROOT/bridge" \
"$SCRIPT" rollback-bridge >/dev/null 2>&1 || status=$?
[[ "$status" -eq 2 && -L "$TEST_ROOT/bridge/staged" ]] \
  || fail 'failed rollback readiness cleared the transaction marker'

: >"$TEST_ROOT/listener-ready.log"
FAKE_SYSTEMCTL_LOG="$TEST_ROOT/rollback.log" \
SYSTEMCTL_BIN="$TEST_ROOT/systemctl" \
BRIDGE_OUTPUT_DIR="$TEST_ROOT/bridge" \
"$SCRIPT" rollback-bridge
[[ "$(readlink "$TEST_ROOT/bridge/current")" == 'generations/old' ]] \
  || fail 'bridge rollback did not restore old generation'
grep -Fxq -- 'restart' "$TEST_ROOT/rollback.log" || fail 'bridge rollback restart missing'
grep -Fxq -- 'wait-listeners' "$TEST_ROOT/listener-ready.log" || fail 'rollback did not wait for listeners'

FAKE_PYTHON_LOG="$TEST_ROOT/sync.log" \
FAKE_PYTHON_ENV_LOG="$TEST_ROOT/sync.env" \
PYTHON_BIN="$TEST_ROOT/python" \
RESIN_POOL_LIB_DIR="$TEST_ROOT/lib" \
BRIDGE_OUTPUT_DIR="$TEST_ROOT/bridge" \
CONFIG_PATH="$TEST_ROOT/config.json" \
UNIFIED_RESIN_LOCK="$TEST_ROOT/unified.lock" \
"$SCRIPT" sync "$TEST_ROOT/token"

grep -Fxq -- 'run' "$TEST_ROOT/sync.log" || fail 'sync run mode missing'
grep -Fxq -- '--confirm-production-write' "$TEST_ROOT/sync.log" \
  || fail 'production confirmation missing'
grep -Fxq -- "$TEST_ROOT/token" "$TEST_ROOT/sync.log" || fail 'credential path missing'
grep -Fxq -- 'bridge_generation=old' "$TEST_ROOT/sync.env" || fail 'bridge generation context missing'
grep -Fxq -- 'bridge_run_id=test-run' "$TEST_ROOT/sync.env" || fail 'bridge run id context missing'

# A generation written before correlation metadata was introduced must remain
# usable and receive a deterministic bridge run association.
printf '{"generation":"legacy"}\n' >"$TEST_ROOT/bridge/generations/old/manifest.json"
FAKE_PYTHON_LOG="$TEST_ROOT/legacy-sync.log" \
FAKE_PYTHON_ENV_LOG="$TEST_ROOT/legacy-sync.env" \
RESIN_MAINTENANCE_RUN_ID=maintenance-legacy \
PYTHON_BIN="$TEST_ROOT/python" \
RESIN_POOL_LIB_DIR="$TEST_ROOT/lib" \
BRIDGE_OUTPUT_DIR="$TEST_ROOT/bridge" \
CONFIG_PATH="$TEST_ROOT/config.json" \
UNIFIED_RESIN_LOCK="$TEST_ROOT/legacy-unified.lock" \
"$SCRIPT" sync "$TEST_ROOT/token"
grep -Fxq -- 'bridge_generation=legacy' "$TEST_ROOT/legacy-sync.env" \
  || fail 'legacy bridge generation context missing'
grep -Fxq -- 'bridge_run_id=maintenance-legacy' "$TEST_ROOT/legacy-sync.env" \
  || fail 'legacy bridge run id fallback missing'

status=0
"$SCRIPT" fallback-sync "$TEST_ROOT/token" >/dev/null 2>&1 || status=$?
[[ "$status" -eq 2 ]] || fail 'retired fallback command is still accepted'

printf 'PASS: Resin Global helper tests\n'
