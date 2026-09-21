#!/usr/bin/env bash
set -euo pipefail

TASK_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REAL_SCRIPT="${TASK_DIR}/lib/cn-pool.sh"
PROBE_SCRIPT="${TASK_DIR}/probe-cn-candidate.sh"
TEST_ROOT="$(mktemp -d /tmp/resin-cn-pool-test.XXXXXX)"
cleanup() { rm -rf -- "$TEST_ROOT"; }
trap cleanup EXIT

bash -n "$REAL_SCRIPT" "$PROBE_SCRIPT"
! rg -q 'CODEX_SKILLS_ROOT|/root/\.codex/skills' \
  "$REAL_SCRIPT" "${TASK_DIR}/systemd/resin-pool-maintenance.service"
python3 -m json.tool "${TASK_DIR}/cn.json.example" >/dev/null
! rg -qi 'elysiver' "$PROBE_SCRIPT" "${TASK_DIR}/cn.json.example"
jq -e '
  (.validation.target_hosts | length) == 3 and
  .validation.min_target_hosts_passed == 2 and
  (.validation.generic_probe_urls | length) == 3 and
  .validation.generic_probe_min_successes == 2
' "${TASK_DIR}/cn.json.example" >/dev/null

mkdir -p "$TEST_ROOT/fake-bin"
cat >"$TEST_ROOT/fake-bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
url="${*: -1}"
case "$url" in
  *cdn-cgi/trace) printf 'loc=%s\n' "${TEST_TRACE_REGION:-CN}" ;;
  *hicloud*) printf '%s' "${TEST_HICLOUD_CODE:-204}" ;;
  *baidu*) printf '%s' "${TEST_BAIDU_CODE:-200}" ;;
  *bilibili*) printf '%s' "${TEST_BILIBILI_CODE:-503}" ;;
  *) exit 1 ;;
esac
EOF
chmod 0755 "$TEST_ROOT/fake-bin/curl"

probe_urls=$'https://connectivitycheck.platform.hicloud.com/generate_204\nhttps://www.baidu.com/\nhttps://www.bilibili.com/robots.txt'
PATH="$TEST_ROOT/fake-bin:$PATH" \
CN_GENERIC_PROBE_URLS="$probe_urls" \
CN_GENERIC_PROBE_MIN_SUCCESSES=2 \
  "$PROBE_SCRIPT" 1.1.1.1:8080 >"$TEST_ROOT/probe.out"
grep -qx '1.1.1.1:8080' "$TEST_ROOT/probe.out"

status=0
PATH="$TEST_ROOT/fake-bin:$PATH" \
TEST_BAIDU_CODE=503 \
CN_GENERIC_PROBE_URLS="$probe_urls" \
CN_GENERIC_PROBE_MIN_SUCCESSES=2 \
  "$PROBE_SCRIPT" 1.1.1.1:8080 >/dev/null || status=$?
[[ "$status" -eq 1 ]]

mkdir -p "$TEST_ROOT/task/lib" "$TEST_ROOT/state/sources" "$TEST_ROOT/locks"
cp "$REAL_SCRIPT" "$TEST_ROOT/task/lib/cn-pool.sh"
cp "$TASK_DIR/lib/cn_candidates.py" "$TEST_ROOT/task/lib/cn_candidates.py"
sed -i 's#curl -fsSL --max-time 30 "$url" -o "$output" 2>/dev/null || :#case "$url" in *proxyscrape*) printf "1.1.1.1:8080\\n8.8.8.8:8080\\n9.9.9.9:8080\\n" > "$output" ;; *) : > "$output" ;; esac#' \
  "$TEST_ROOT/task/lib/cn-pool.sh"
chmod 0755 "$TEST_ROOT/task/lib/cn-pool.sh"

cat >"$TEST_ROOT/task/probe-cn-candidate.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${TEST_PROBE_ABORT:-}" == yes ]]; then exit 255; fi
printf '%s\n' "$1"
EOF
chmod 0755 "$TEST_ROOT/task/probe-cn-candidate.sh"

cat >"$TEST_ROOT/task/lib/resin_pool_sync.py" <<'EOF'
#!/usr/bin/env python3
import os
import sys
if os.environ.get("TEST_SYNC_RESULT") == "fail":
    sys.exit(7)
print('{"status":"completed","selected_count":3}')
EOF
chmod 0755 "$TEST_ROOT/task/lib/resin_pool_sync.py"

cat >"$TEST_ROOT/config.json" <<'EOF'
{
  "version": 1,
  "validation": {
    "generic_probe_urls": [
      "https://connectivitycheck.platform.hicloud.com/generate_204",
      "https://www.baidu.com/",
      "https://www.bilibili.com/robots.txt"
    ],
    "generic_probe_min_successes": 2
  }
}
EOF
printf 'test-token\n' >"$TEST_ROOT/admin.token"
chmod 0600 "$TEST_ROOT/config.json" "$TEST_ROOT/admin.token"

source_file="$TEST_ROOT/state/sources/cn-validated-http.txt"
old_content=$'http://198.51.100.1:8080\nhttp://198.51.100.2:8080\n'

run_script() {
  CN_CONFIG="$TEST_ROOT/config.json" \
  CN_SOURCE="$source_file" \
  CN_STATE_DIR="$TEST_ROOT/state" \
  CN_LOCK="$TEST_ROOT/locks/cn.lock" \
  CN_SHARED_LOCK="$TEST_ROOT/locks/shared.lock" \
  "$TEST_ROOT/task/lib/cn-pool.sh" "$TEST_ROOT/admin.token" \
    >"$TEST_ROOT/out.log" 2>"$TEST_ROOT/err.log"
}

printf '%s' "$old_content" >"$source_file"
chmod 0600 "$source_file"
TEST_SYNC_RESULT=ok run_script
grep -qx 'http://1.1.1.1:8080' "$source_file"

printf '%s' "$old_content" >"$source_file"
status=0
TEST_SYNC_RESULT=fail run_script || status=$?
[[ "$status" -eq 7 ]]
cmp -s "$source_file" <(printf '%s' "$old_content")
grep -q 'restored previous candidate file' "$TEST_ROOT/err.log"

printf '%s' "$old_content" >"$source_file"
status=0
TEST_PROBE_ABORT=yes run_script || status=$?
[[ "$status" -eq 124 ]]
cmp -s "$source_file" <(printf '%s' "$old_content")

printf '%s' "$old_content" >"$source_file"
(
  exec 8>"$TEST_ROOT/locks/shared.lock"
  flock -n 8
  sleep 5
) &
holder=$!
sleep 0.1
TEST_SYNC_RESULT=ok run_script
cmp -s "$source_file" <(printf '%s' "$old_content")
kill "$holder" 2>/dev/null || :
wait "$holder" 2>/dev/null || :

printf '%s\n' 'PASS: Resin CN helper generic gate, rollback and locking tests'
