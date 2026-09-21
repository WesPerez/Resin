#!/usr/bin/env bash
set -euo pipefail

candidate="${1:-}"
if [[ ! "$candidate" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$ ]]; then
  exit 2
fi

work_dir="$(mktemp -d /tmp/resin-cn-probe.XXXXXX)"
cleanup() { rm -rf -- "$work_dir"; }
trap cleanup EXIT

mapfile -t probe_urls < <(printf '%s\n' "${CN_GENERIC_PROBE_URLS:-}" | sed '/^[[:space:]]*$/d')
min_successes="${CN_GENERIC_PROBE_MIN_SUCCESSES:-}"
if [[ "${#probe_urls[@]}" -lt 2 || "${#probe_urls[@]}" -gt 8 || ! "$min_successes" =~ ^[1-9][0-9]*$ ]]; then
  exit 2
fi
if [[ "$min_successes" -gt "${#probe_urls[@]}" ]]; then
  exit 2
fi
for url in "${probe_urls[@]}"; do
  [[ "$url" =~ ^https://[^[:space:]]+$ ]] || exit 2
done

probe_url() {
  local url="$1" code
  code="$(curl -sS -L -x "http://$candidate" \
    --connect-timeout 5 --max-time 12 -o /dev/null \
    -w '%{http_code}' "$url" 2>/dev/null)" || return 1
  [[ "$code" =~ ^[23][0-9][0-9]$ ]]
}

record_result() {
  if [[ -n "${CN_PROBE_METRICS_FILE:-}" ]]; then
    printf '%s\n' "$1" >> "$CN_PROBE_METRICS_FILE"
  fi
}

trace="$(curl -fsS -x "http://$candidate" --connect-timeout 4 --max-time 8 \
  'https://speed.cloudflare.com/cdn-cgi/trace' 2>/dev/null)" || { record_result trace_failed; exit 1; }
printf '%s\n' "$trace" | tr -d '\r' | grep -qx 'loc=CN' || { record_result not_cn; exit 1; }

for index in "${!probe_urls[@]}"; do
  (
    probe_url "${probe_urls[$index]}" && printf 'ok\n' || printf 'fail\n'
  ) > "$work_dir/target-$index" &
done
wait
successes="$(grep -h -c '^ok$' "$work_dir"/target-* | awk '{sum += $1} END {print sum + 0}')"
[[ "$successes" -ge "$min_successes" ]] || { record_result https_failed; exit 1; }
record_result passed

printf '%s\n' "$candidate"
