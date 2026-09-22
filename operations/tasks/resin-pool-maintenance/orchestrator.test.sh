#!/usr/bin/env bash
set -euo pipefail

TASK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$TASK_DIR/resin-pool-maintenance.sh"
TEST_ROOT="$(mktemp -d /tmp/resin-pool-orchestrator-test.XXXXXX)"
cleanup() { rm -rf -- "$TEST_ROOT"; }
trap cleanup EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$TEST_ROOT/state" "$TEST_ROOT/locks"
printf 'admin-token\n' >"$TEST_ROOT/admin.token"
printf 'direct-token\n' >"$TEST_ROOT/direct.token"
chmod 0600 "$TEST_ROOT/admin.token" "$TEST_ROOT/direct.token"

cat >"$TEST_ROOT/cn-helper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'cn:%s\n' "$*" >>"$TEST_LOG"
[[ "${TEST_CN_FAIL:-0}" != "1" ]] || exit 7
EOF

cat >"$TEST_ROOT/global-helper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
action="${1:-}"
if [[ "$action" == prepare-bridge || "$action" == capacity-bridge ]]; then
  flock -n "$UNIFIED_RESIN_LOCK" true || exit 41
  flock -n "$UNIFIED_RESIN_LOCK.priority" true || exit 42
else
  if flock -n "$UNIFIED_RESIN_LOCK" true; then exit 43; fi
fi
printf 'global:%s\n' "$*" >>"$TEST_LOG"
if [[ "$action" == promote-bridge && "${TEST_PROMOTE_FAIL:-0}" == "1" ]]; then
  exit 8
fi
if [[ "$action" == restart-bridge && "${TEST_RESTART_FAIL:-0}" == "1" ]]; then
  exit 10
fi
if [[ "$action" == capacity-bridge && "${TEST_CAPACITY_FULL:-0}" == "1" ]]; then exit 75; fi
if [[ "$action" == restart-bridge && "${TEST_CAPACITY_RACE:-0}" == "1" ]]; then exit 75; fi
if [[ "$action" == rollback-bridge && "${TEST_ROLLBACK_FAIL:-0}" == "1" ]]; then exit 8; fi
if [[ "$action" == sync && "${TEST_GLOBAL_PRIMARY_FAIL:-0}" == "1" ]]; then
  exit 9
fi
EOF
chmod 0755 "$TEST_ROOT/cn-helper" "$TEST_ROOT/global-helper"

run_task() {
  TEST_LOG="$TEST_ROOT/calls.log" \
  TEST_CAPACITY_FULL="${TEST_CAPACITY_FULL:-0}" \
  TEST_CAPACITY_RACE="${TEST_CAPACITY_RACE:-0}" \
  TEST_ROLLBACK_FAIL="${TEST_ROLLBACK_FAIL:-0}" \
  TEST_CN_FAIL="${TEST_CN_FAIL:-0}" \
  TEST_GLOBAL_PRIMARY_FAIL="${TEST_GLOBAL_PRIMARY_FAIL:-0}" \
  TEST_PROMOTE_FAIL="${TEST_PROMOTE_FAIL:-0}" \
  TEST_RESTART_FAIL="${TEST_RESTART_FAIL:-0}" \
  GLOBAL_HELPER="$TEST_ROOT/global-helper" \
  CN_HELPER="$TEST_ROOT/cn-helper" \
  GLOBAL_STATE_DIR="$TEST_ROOT/state" \
  ORCHESTRATOR_STATE_PATH="$TEST_ROOT/state/orchestrator-state.json" \
  LAST_RUN_PATH="$TEST_ROOT/state/last-unified-run.json" \
  UNIFIED_RESIN_LOCK="$TEST_ROOT/locks/data-plane.lock" \
  "$SCRIPT" run "$@"
}

: >"$TEST_ROOT/calls.log"
run_task "$TEST_ROOT/admin.token" "$TEST_ROOT/direct.token" >"$TEST_ROOT/success.out"
expected=$'cn:'"$TEST_ROOT/admin.token"$'\nglobal:capacity-bridge\nglobal:prepare-bridge '"$TEST_ROOT/direct.token"$'\nglobal:promote-bridge\nglobal:restart-bridge\nglobal:check-bridge\nglobal:sync '"$TEST_ROOT/admin.token"$'\nglobal:commit-bridge\n'
cmp -s "$TEST_ROOT/calls.log" <(printf '%s' "$expected") || fail 'success call order mismatch'
jq -e '
  .global_status == "success" and
  .cn_status == "success" and
  .overall_status == "success" and
  .last_global_success_epoch > 0 and
  (.run_id | type == "string" and length > 0)
' "$TEST_ROOT/state/last-unified-run.json" >/dev/null || fail 'success status mismatch'
grep -q '^POOL SUMMARY run_id=' "$TEST_ROOT/success.out" || fail 'run id summary missing'
last_success="$(jq -r '.last_global_success_epoch' "$TEST_ROOT/state/orchestrator-state.json")"

: >"$TEST_ROOT/calls.log"
run_task "$TEST_ROOT/admin.token" "$TEST_ROOT/direct.token" >"$TEST_ROOT/skipped.out"
expected=$'cn:'"$TEST_ROOT/admin.token"$'\nglobal:capacity-bridge\nglobal:prepare-bridge '"$TEST_ROOT/direct.token"$'\nglobal:promote-bridge\nglobal:restart-bridge\nglobal:check-bridge\nglobal:sync '"$TEST_ROOT/admin.token"$'\nglobal:commit-bridge\n'
cmp -s "$TEST_ROOT/calls.log" <(printf '%s' "$expected") \
  || fail 'hourly run did not call the full Global helper'
grep -Fxq "cn:$TEST_ROOT/admin.token" "$TEST_ROOT/calls.log" || fail 'not-due run skipped CN'
jq -e '
  .global_status == "success" and
  .cn_status == "success" and
  .overall_status == "success"
' "$TEST_ROOT/state/last-unified-run.json" >/dev/null || fail 'hourly status mismatch'
grep -Fq 'POOL Global primary begin' "$TEST_ROOT/skipped.out" \
  || fail 'hourly run did not begin Global maintenance'

: >"$TEST_ROOT/calls.log"
status=0
TEST_GLOBAL_PRIMARY_FAIL=1 run_task \
  "$TEST_ROOT/admin.token" "$TEST_ROOT/direct.token" >"$TEST_ROOT/primary-fail.out" 2>"$TEST_ROOT/primary-fail.err" || status=$?
[[ "$status" -eq 1 ]] || fail 'primary failure did not fail unified service'
grep -Fxq 'global:rollback-bridge' "$TEST_ROOT/calls.log" || fail 'primary failure did not roll back bridge'
[[ "$(wc -l <"$TEST_ROOT/calls.log")" -eq 8 ]] \
  || fail 'primary failure invoked an unexpected path'
if grep -Eq '^global:(refresh-forum-fallback|fallback-sync)' "$TEST_ROOT/calls.log"; then
  fail 'primary failure invoked a retired fallback path'
fi
jq -e --argjson previous "$last_success" '
  .global_status == "primary_failed" and
  .overall_status == "failed" and
  .last_global_success_epoch == $previous
' "$TEST_ROOT/state/last-unified-run.json" >/dev/null || fail 'primary failure retention semantics mismatch'
grep -Fq 'previous fixed-port pool retained' "$TEST_ROOT/primary-fail.err" \
  || fail 'primary failure did not report fixed-port pool retention'

: >"$TEST_ROOT/calls.log"
status=0
TEST_PROMOTE_FAIL=1 run_task \
  "$TEST_ROOT/admin.token" "$TEST_ROOT/direct.token" >"$TEST_ROOT/promote-fail.out" 2>"$TEST_ROOT/promote-fail.err" || status=$?
[[ "$status" -eq 1 ]] || fail 'promote failure did not fail unified service'
grep -Fxq 'global:rollback-bridge' "$TEST_ROOT/calls.log" || fail 'promote failure did not roll back under the data lock'
[[ "$(wc -l <"$TEST_ROOT/calls.log")" -eq 5 ]] || fail 'promote failure continued to restart or sync'

: >"$TEST_ROOT/calls.log"
status=0
TEST_RESTART_FAIL=1 run_task \
  "$TEST_ROOT/admin.token" "$TEST_ROOT/direct.token" >"$TEST_ROOT/restart-fail.out" 2>"$TEST_ROOT/restart-fail.err" || status=$?
[[ "$status" -eq 1 ]] || fail 'restart/readiness failure did not fail unified service'
grep -Fxq 'global:rollback-bridge' "$TEST_ROOT/calls.log" || fail 'restart/readiness failure did not roll back'
[[ "$(wc -l <"$TEST_ROOT/calls.log")" -eq 6 ]] || fail 'restart/readiness failure continued to check or sync'

: >"$TEST_ROOT/calls.log"
status=0
TEST_CN_FAIL=1 run_task \
  "$TEST_ROOT/admin.token" "$TEST_ROOT/direct.token" >"$TEST_ROOT/cn-fail.out" 2>"$TEST_ROOT/cn-fail.err" || status=$?
[[ "$status" -eq 1 ]] || fail 'CN failure did not fail unified service'
grep -Fxq 'global:commit-bridge' "$TEST_ROOT/calls.log" || fail 'CN failure incorrectly blocked Global maintenance'
jq -e '
  .global_status == "success" and
  .cn_status == "failed" and
  .overall_status == "failed"
' "$TEST_ROOT/state/last-unified-run.json" >/dev/null || fail 'CN failure status mismatch'

printf '%s\n' 'PASS: unified Resin orchestrator scheduling and failure semantics tests'

: >"$TEST_ROOT/calls.log"
exec 8>"$TEST_ROOT/locks/data-plane.lock"
flock -x 8
status=0
UNIFIED_RESIN_LOCK_WAIT_SECONDS=0 run_task \
  "$TEST_ROOT/admin.token" "$TEST_ROOT/direct.token" >"$TEST_ROOT/locked.out" 2>&1 || status=$?
[[ "$status" -eq 1 && ! -s "$TEST_ROOT/calls.log" ]] || fail 'busy data plane reported success or changed pools'
flock -u 8

exec 9>"$TEST_ROOT/locks/data-plane.lock.maintenance"
flock -x 9
run_task "$TEST_ROOT/admin.token" "$TEST_ROOT/direct.token" >"$TEST_ROOT/duplicate.out"
[[ ! -s "$TEST_ROOT/calls.log" ]] || fail 'duplicate queued maintenance changed pools'
flock -u 9

flock -x 8
UNIFIED_RESIN_LOCK_WAIT_SECONDS=5 run_task \
  "$TEST_ROOT/admin.token" "$TEST_ROOT/direct.token" >"$TEST_ROOT/waited.out" &
waiter=$!
sleep 0.2
[[ ! -s "$TEST_ROOT/calls.log" ]] || fail 'maintenance ran without data-plane lock'
flock -u 8
wait "$waiter" || fail 'maintenance did not resume after optimizer released lock'
grep -Fq 'POOL Global primary success' "$TEST_ROOT/waited.out" || fail 'queued update was skipped'
printf '%s\n' 'PASS: maintenance priority, bounded wait, and duplicate exclusion tests'

# Capacity backpressure is deferred; failures in either pool or rollback remain failures.
for mode in TEST_CAPACITY_FULL TEST_CAPACITY_RACE; do
  : >"$TEST_ROOT/calls.log"
  export "$mode=1"
  run_task "$TEST_ROOT/admin.token" "$TEST_ROOT/direct.token" >"$TEST_ROOT/deferred.out"
  jq -e --argjson previous "$last_success" '.global_status == "deferred" and .overall_status == "deferred" and .last_global_success_epoch >= $previous' "$TEST_ROOT/state/last-unified-run.json" >/dev/null || fail 'capacity was not deferred'
  if [[ "$mode" == TEST_CAPACITY_FULL ]]; then
    ! grep -q 'global:prepare-bridge' "$TEST_ROOT/calls.log" || fail 'full capacity still performed expensive preparation'
  else
    grep -Fxq 'global:rollback-bridge' "$TEST_ROOT/calls.log" || fail 'capacity race did not restore previous generation'
    ! grep -q 'global:sync' "$TEST_ROOT/calls.log" || fail 'capacity race synced an unserved generation'
  fi
  status=0
  TEST_CN_FAIL=1 run_task "$TEST_ROOT/admin.token" "$TEST_ROOT/direct.token" >"$TEST_ROOT/deferred-cn-fail.out" 2>&1 || status=$?
  [[ "$status" == 1 ]] || fail 'deferral hid a CN failure'
  unset "$mode"
done
status=0
TEST_CAPACITY_RACE=1 TEST_ROLLBACK_FAIL=1 run_task "$TEST_ROOT/admin.token" "$TEST_ROOT/direct.token" >"$TEST_ROOT/rollback-fail.out" 2>&1 || status=$?
[[ "$status" == 1 ]] || fail 'deferral hid a rollback failure'
printf '%s\n' 'PASS: deferred capacity, expensive-work preflight, and rollback failure semantics'
