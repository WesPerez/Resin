#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TASK_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$SCRIPT_DIR"
SYNC_SCRIPT="${CN_SYNC_SCRIPT:-${LIB_DIR}/resin_pool_sync.py}"
export PYTHONPATH="${LIB_DIR}${PYTHONPATH:+:${PYTHONPATH}}"
CONFIG_PATH="${CN_CONFIG:-/etc/resin-app-pools/cn.json}"
SOURCE_PATH="${CN_SOURCE:-/var/lib/resin-cn-pool-maintainer/sources/cn-validated-http.txt}"
STATE_DIR="${CN_STATE_DIR:-/var/lib/resin-cn-pool-maintainer}"
LOCK_PATH="${CN_LOCK:-/var/lib/resin-cn-pool-maintainer/wrapper.lock}"
# Both the CN pool and the Global pool write the same unified Resin instance
# (proxy.internal:10834). They therefore share a wrapper-level data-plane lock,
# while each resin_pool_sync invocation keeps its own config lock. This avoids
# cross-pool writes and avoids self-deadlocking the CN invocation on cn.json's
# private lock file.
SHARED_LOCK_PATH="${CN_SHARED_LOCK:-/run/lock/resin-pool-maintenance-data-plane.lock}"
# The CN funnel is wide and cheap to probe in parallel; a 30-node target needs
# far more raw candidates than the previous 4-node target did.
MAX_CANDIDATES="${CN_MAX_CANDIDATES:-1500}"

if [[ "${1:-}" == "--help" ]]; then
  printf 'usage: %s <apps-admin-token-file>\n' "$0"
  exit 0
fi
if [[ "${1:-}" == "" ]]; then
  printf 'usage: %s <apps-admin-token-file>\n' "$0" >&2
  exit 2
fi
admin_token_file="$1"

require_private_file() {
  local path="$1" mode
  [[ -f "$path" && ! -L "$path" ]] || { printf 'missing private file: %s\n' "$path" >&2; exit 2; }
  mode="$(stat -c '%a' "$path")"
  [[ "$mode" == "400" || "$mode" == "600" ]] || { printf 'private file mode must be 0400/0600: %s\n' "$path" >&2; exit 2; }
}

require_private_file "$admin_token_file"
require_private_file "$CONFIG_PATH"
[[ -f "$SYNC_SCRIPT" && -x "$SYNC_SCRIPT" && -x "$TASK_DIR/probe-cn-candidate.sh" ]] || {
  printf 'missing Resin sync runtime: %s\n' "$SYNC_SCRIPT" >&2
  exit 2
}
command -v jq >/dev/null 2>&1 || exit 2

mapfile -t generic_probe_urls < <(jq -r '.validation.generic_probe_urls[]? // empty' "$CONFIG_PATH")
generic_probe_min_successes="$(jq -r '.validation.generic_probe_min_successes // empty' "$CONFIG_PATH")"
if [[ "${#generic_probe_urls[@]}" -lt 2 || "${#generic_probe_urls[@]}" -gt 8 || ! "$generic_probe_min_successes" =~ ^[1-9][0-9]*$ ]]; then
  printf 'invalid generic CN probe configuration: %s\n' "$CONFIG_PATH" >&2
  exit 2
fi
if [[ "$generic_probe_min_successes" -gt "${#generic_probe_urls[@]}" ]]; then
  printf 'generic CN probe quorum exceeds target count: %s\n' "$CONFIG_PATH" >&2
  exit 2
fi
for url in "${generic_probe_urls[@]}"; do
  if [[ ! "$url" =~ ^https://[^[:space:]]+$ ]]; then
    printf 'invalid generic CN probe URL in config: %s\n' "$CONFIG_PATH" >&2
    exit 2
  fi
done
CN_GENERIC_PROBE_URLS="$(printf '%s\n' "${generic_probe_urls[@]}")"
CN_GENERIC_PROBE_MIN_SUCCESSES="$generic_probe_min_successes"
export CN_GENERIC_PROBE_URLS CN_GENERIC_PROBE_MIN_SUCCESSES

mkdir -p "$STATE_DIR" "$(dirname "$SOURCE_PATH")"
chmod 0700 "$STATE_DIR" "$(dirname "$SOURCE_PATH")"
exec 9>"$LOCK_PATH"
if ! flock -n 9; then
  printf 'CN pool maintenance already holds its wrapper lock; skipping this run\n' >&2
  exit 0
fi

work_dir="$(mktemp -d /tmp/resin-cn-discovery.XXXXXX)"
previous_source="$work_dir/previous-source.txt"
source_installed=false

restore_previous_source() {
  if [[ "$source_installed" != true ]]; then
    return 0
  fi
  source_installed=false
  if [[ -f "$previous_source" ]]; then
    install -m 0600 "$previous_source" "$SOURCE_PATH" || {
      printf 'failed to restore previous CN candidate file: %s\n' "$SOURCE_PATH" >&2
      return 0
    }
    printf 'CN sync failed; restored previous candidate file: %s\n' "$SOURCE_PATH" >&2
  else
    rm -f -- "$SOURCE_PATH" || :
    printf 'CN sync failed; removed uncommitted candidate file: %s\n' "$SOURCE_PATH" >&2
  fi
}

cleanup() {
  restore_previous_source
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

collect_source() {
  local url="$1" output="$2"
  curl -fsSL --max-time 30 "$url" -o "$output" 2>/dev/null || :
}

collect_source 'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=CN&ssl=yes&anonymity=all' "$work_dir/proxyscrape.txt"
collect_source 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/countries/CN/data.txt' "$work_dir/proxifly.txt"
collect_source 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt' "$work_dir/speedx.txt"
collect_source 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt' "$work_dir/monosans.txt"
collect_source 'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt' "$work_dir/vakhov.txt"
collect_source 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt' "$work_dir/rooster.txt"
# Additional CN-heavy public lists. Reaching a 30-node pool needs a much wider
# candidate funnel, because only a small fraction of free CN proxies pass the
# loc=CN trace plus the generic HTTPS quorum.
collect_source 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt' "$work_dir/proxifly-all.txt"
collect_source 'https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt' "$work_dir/hideip.txt"
collect_source 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/http.txt' "$work_dir/monosans-anon.txt"
collect_source 'https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt' "$work_dir/mmpx12.txt"
collect_source 'https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt' "$work_dir/dedeoglu.txt"
collect_source 'https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&country=cn&protocol=http&proxy_format=ipport&format=text' "$work_dir/proxyscrape-v4.txt"

# A filename-sorted global list must not consume the cap before the CN-specific lists.
"$PYTHON_BIN" "$LIB_DIR/cn_candidates.py" --previous "$SOURCE_PATH" \
  --directory "$work_dir" --limit "$MAX_CANDIDATES" --report "$work_dir/candidate-report.json" \
  > "$work_dir/candidates.txt"
printf 'CN candidates %s\n' "$(cat "$work_dir/candidate-report.json")"
chmod 0600 "$work_dir/candidates.txt"

if [[ ! -s "$work_dir/candidates.txt" ]]; then
  printf 'no CN candidates collected; retaining previous pool\n' >&2
  exit 1
fi

export CN_PROBE_METRICS_FILE="$work_dir/probe-results.txt"
: > "$CN_PROBE_METRICS_FILE"
chmod 0600 "$CN_PROBE_METRICS_FILE"
set +e
xargs -r -P 24 -n 1 "$TASK_DIR/probe-cn-candidate.sh" < "$work_dir/candidates.txt" > "$work_dir/validated.txt"
xargs_status=$?
set -e
printf 'CN probe_results %s\n' "$(jq -Rsc 'split("\n") | map(select(length > 0)) | group_by(.) | map({key:.[0],value:length}) | from_entries' "$CN_PROBE_METRICS_FILE")"
# 123 means individual candidates failed. 124 means a child aborted with 255;
# xargs then stopped scheduling, so its partial results must not replace the pool.
if [[ "$xargs_status" -ne 0 && "$xargs_status" -ne 123 ]]; then
  printf 'candidate probe runner failed: %s\n' "$xargs_status" >&2
  exit "$xargs_status"
fi
# Target up to 30 stable CN egress IPs so the pool has enough spread to route
# many identities. Selection still happens in resin_pool_sync.py; this only
# feeds it the validated candidates, and the sync gate still bounds the result.
sort -u "$work_dir/validated.txt" | head -n 30 | sed 's#^#http://#' > "$work_dir/next-source.txt"
chmod 0600 "$work_dir/next-source.txt"

validated_count="$(wc -l < "$work_dir/next-source.txt")"
printf 'CN gate candidate_count=%s https_passed=%s minimum=2\n' "$(wc -l < "$work_dir/candidates.txt")" "$validated_count"
if [[ "$validated_count" -lt 2 ]]; then
  printf 'only %s CN candidates passed the generic network gate; retaining previous pool\n' "$validated_count" >&2
  exit 1
fi

# Serialize with the Global pool maintenance (same Resin instance). Skip
# silently when the shared lock is busy, matching the CN lock policy.
if [[ "${UNIFIED_LOCK_HELD:-0}" != "1" ]]; then
  exec 8>"$SHARED_LOCK_PATH"
  if ! flock -n 8; then
    printf 'Apps pool maintenance already holds the shared data-plane lock; skipping CN sync\n' >&2
    exit 0
  fi
fi

if [[ -f "$SOURCE_PATH" ]]; then
  install -m 0600 "$SOURCE_PATH" "$previous_source"
fi
install -m 0600 "$work_dir/next-source.txt" "$SOURCE_PATH"
source_installed=true

# On any failure the EXIT trap restores the previous candidate file before the
# work_dir is removed, so the next run starts from the last committed source.
"$PYTHON_BIN" "$SYNC_SCRIPT" run \
  --config "$CONFIG_PATH" \
  --admin-token-file "$admin_token_file" \
  --confirm-production-write
source_installed=false
