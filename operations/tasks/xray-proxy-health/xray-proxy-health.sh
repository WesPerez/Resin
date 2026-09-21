#!/usr/bin/env bash
set -u -o pipefail

umask 077

TASK_DIR=$(cd "$(dirname "$0")" && pwd)
ENV_FILE=${XRAY_PROXY_HEALTH_ENV_FILE:-/etc/server-scheduled-tasks/xray-proxy-health.env}
LOG_PATH=/var/log/nginx/proxy-ws-access.log
XHTTP_LOG_PATH=/var/log/nginx/proxy-xhttp-access.log
BACKEND_SERVICE=xray-proxy.service
BACKEND_PORT=12762
XHTTP_BACKEND_PORT=12763
REGION_BACKEND_PORTS=auto
ERROR_LOG_PATH=/var/log/nginx/weesai-error.log
METRICS_PATH=/var/log/xray-proxy-health/metrics.jsonl
ALERT_LOG_PATH=/var/log/xray-proxy-health/alerts.log
STATE_DIR=/var/lib/server-scheduled-tasks/xray-proxy-health
COUNTERS_PATH=/var/lib/server-scheduled-tasks/xray-proxy-health/counters.prev
ALERT_STATE_PATH=/var/lib/server-scheduled-tasks/xray-proxy-health/alert.state
LOCK_PATH=/run/lock/xray-proxy-health.lock
TLS_SERVERNAME=weesai.com
TLS_CONNECT=127.0.0.1:443
WS_TOTAL_MIN=20
WS_503_RATIO_WARN_PCT=50
WS_503_COUNT_WARN=100
WS_SHORT_MIN=20
WS_SHORT_RATIO_WARN_PCT=50
XHTTP_TOTAL_MIN=2
XHTTP_BAD_RATIO_WARN_PCT=50
XHTTP_BAD_COUNT_WARN=5
CONN_443_WARN=600
CONN_BACKEND_WARN=600
MAX_PEER_443_WARN=300
PRE_WS_GAP_WARN=200
PRE_WS_MAX_PEER_WARN=200
MEM_AVAILABLE_WARN_MB=200
SWAP_USED_WARN_MB=3000
TCP_RETRANS_DELTA_WARN=1000
TCP_SYNRETRANS_DELTA_WARN=100
TCP_TIMEOUT_DELTA_WARN=100
TCP_LISTEN_DROP_DELTA_WARN=1
TCP_BACKLOG_DROP_DELTA_WARN=1
ALERT_COOLDOWN_SEC=600
COUNTER_SCHEMA=2

if [[ -r "$ENV_FILE" ]]; then
    . "$ENV_FILE"
fi

if [[ "$REGION_BACKEND_PORTS" == auto ]]; then
    REGION_BACKEND_PORTS=$(jq -er '[.inbounds[]
        | select(.tag | test("^proxy-ws-[a-z]{2}$")) | .port]
        | unique | if length > 0 then map(tostring) | join(" ") else error("no region listeners") end' \
        /etc/xray/proxy.json) || exit 1
fi
[[ "$REGION_BACKEND_PORTS" =~ ^[0-9]+(\ [0-9]+)*$ ]] || exit 1

mkdir -p "$STATE_DIR" "$(dirname "$METRICS_PATH")"
chmod 0700 "$STATE_DIR" 2>/dev/null || true
chmod 0750 "$(dirname "$METRICS_PATH")" 2>/dev/null || true

exec 9>"$LOCK_PATH"
flock -n 9 || exit 0

bool_json() {
    if "$@" >/dev/null 2>&1; then
        printf 'true'
    else
        printf 'false'
    fi
}

svc_nginx=$(systemctl is-active nginx.service 2>/dev/null || printf 'unknown')
svc_backend=$(systemctl is-active "$BACKEND_SERVICE" 2>/dev/null || printf 'unknown')
listen_443=$(bool_json bash -c "ss -Hln 'sport = :443' | awk 'NF{found=1} END{exit !found}'")
listen_backend=$(bool_json bash -c "ss -Hln | awk -v p=\":$BACKEND_PORT\" 'index(\$5,p) > 0 {found=1} END{exit !found}'")
listen_xhttp=$(bool_json bash -c "ss -Hln | awk -v p=\":$XHTTP_BACKEND_PORT\" 'index(\$5,p) > 0 {found=1} END{exit !found}'")
declare -A listen_region
listen_region_all=true
region_listeners_json="["
region_json_sep=""
for region_port in $REGION_BACKEND_PORTS; do
    listen_region[$region_port]=$(bool_json bash -c "ss -Hln 'sport = :$region_port' | awk 'NF{found=1} END{exit !found}'")
    [[ "${listen_region[$region_port]}" == true ]] || listen_region_all=false
region_listeners_json+="${region_json_sep}{\"port\":${region_port},\"listening\":${listen_region[$region_port]}}"
    region_json_sep=","
done
region_listeners_json+="]"

tcp443_ok=false
if timeout 3 bash -c ": >/dev/tcp/127.0.0.1/443" >/dev/null 2>&1; then
    tcp443_ok=true
fi

tls_ok=false
tls_ms=-1
tls_tmp=$(mktemp)
tls_start=$(date +%s%3N)
if timeout 5 openssl s_client -connect "$TLS_CONNECT" -servername "$TLS_SERVERNAME" -brief </dev/null >"$tls_tmp" 2>&1; then
    if grep -Eq '^(Protocol version:|Protocol[[:space:]]*:)' "$tls_tmp"; then
        tls_ok=true
    fi
fi
tls_end=$(date +%s%3N)
if [[ "$tls_ok" == true ]]; then
    tls_ms=$((tls_end - tls_start))
fi
rm -f "$tls_tmp"

window_epoch=$(( $(date +%s) / 60 * 60 - 60 ))
window_min=$(date -d "@$window_epoch" '+%d/%b/%Y:%H:%M')
log_metrics=$(python3 "$TASK_DIR/log_metrics.py" --start "$window_epoch" \
    --ws "$LOG_PATH" --xhttp "$XHTTP_LOG_PATH" --error "$ERROR_LOG_PATH") || exit 1
log_sources=$(jq -c '.log_sources' <<< "$log_metrics")
# Internal zero defaults allow threshold arithmetic; output retains null for missing samples.
read -r ws_101 ws_503 ws_429 ws_other ws_503_zero_ms ws_101_zero_bytes ws_101_short_le5s \
    ws_total ws_503_ratio ws_101_short_ratio xhttp_2xx xhttp_499 xhttp_other xhttp_total \
    limit_conn_events limit_req_events < <(jq -r '[.ws_101,.ws_503,.ws_429,.ws_other,
    .ws_503_zero_ms,.ws_101_zero_bytes,.ws_101_short_le5s,.ws_total,.ws_503_ratio,
    .ws_101_short_ratio,.xhttp_2xx,.xhttp_499,.xhttp_other,.xhttp_total,
    .limit_conn_events,.limit_req_events] | map(. // 0) | @tsv' <<< "$log_metrics")

conn_443_est=$(ss -Hnt state established '( sport = :443 )' 2>/dev/null | awk 'NF{n++} END{print n+0}')
# Loopback connections appear once for each endpoint; count only the socket whose peer is an Xray backend.
backend_ports_pattern=":($BACKEND_PORT|$XHTTP_BACKEND_PORT"
for region_port in $REGION_BACKEND_PORTS; do
    backend_ports_pattern+="|$region_port"
done
backend_ports_pattern+=")\$"
conn_backend_est=$(ss -Hnt state established 2>/dev/null | awk -v pattern="$backend_ports_pattern" '$4 ~ pattern {n++} END{print n+0}')
conn_443_timewait=$(ss -Hnt state time-wait '( sport = :443 )' 2>/dev/null | awk 'NF{n++} END{print n+0}')
conn_443_synrecv=$(ss -Hnt state syn-recv '( sport = :443 )' 2>/dev/null | awk 'NF{n++} END{print n+0}')
read -r peer_count_443_est max_peer_443_est < <(
    ss -Hnt state established '( sport = :443 )' 2>/dev/null | awk '
        NF {
            peer=$4
            sub(/:[^:]+$/, "", peer)
            if (!(peer in seen)) { seen[peer]=1; peers++ }
            count[peer]++
        }
        END {
            for (peer in count) if (count[peer] > max) max=count[peer]
            printf "%d %d\n", peers+0, max+0
        }
    '
)
if ! [[ "$peer_count_443_est" =~ ^[0-9]+$ ]]; then peer_count_443_est=0; fi
if ! [[ "$max_peer_443_est" =~ ^[0-9]+$ ]]; then max_peer_443_est=0; fi
conn_443_backend_gap=$((conn_443_est - conn_backend_est))
if (( conn_443_backend_gap < 0 )); then conn_443_backend_gap=0; fi

mem_available_kb=$(awk '/^MemAvailable:/{print $2; exit}' /proc/meminfo)
swap_total_kb=$(awk '/^SwapTotal:/{print $2; exit}' /proc/meminfo)
swap_free_kb=$(awk '/^SwapFree:/{print $2; exit}' /proc/meminfo)
if [[ -z "$mem_available_kb" ]]; then mem_available_kb=0; fi
if [[ -z "$swap_total_kb" ]]; then swap_total_kb=0; fi
if [[ -z "$swap_free_kb" ]]; then swap_free_kb=0; fi
mem_available_mb=$((mem_available_kb / 1024))
swap_used_mb=$(( (swap_total_kb - swap_free_kb) / 1024 ))

nginx_master=$(systemctl show nginx.service -p MainPID --value 2>/dev/null)
if [[ -z "$nginx_master" ]]; then nginx_master=0; fi
rss_nginx_kb=$(ps -eo pid=,ppid=,rss= 2>/dev/null | awk -v master="$nginx_master" '$2 == master {sum += $3} END{print sum+0}')
backend_pid=$(systemctl show "$BACKEND_SERVICE" -p MainPID --value 2>/dev/null)
if [[ -z "$backend_pid" ]]; then backend_pid=0; fi
rss_backend_kb=0
if [[ "$backend_pid" =~ ^[0-9]+$ && "$backend_pid" -gt 0 && -r "/proc/$backend_pid/status" ]]; then
    rss_backend_kb=$(awk '/^VmRSS:/{print $2; exit}' "/proc/$backend_pid/status")
fi
if [[ -z "$rss_backend_kb" ]]; then rss_backend_kb=0; fi

snmp_counter() {
    local key=$1
    awk -v wanted="$key" '
        $1 == "Tcp:" && !header { for (i=2; i<=NF; i++) field_pos[$i]=i; header=1; next }
        $1 == "Tcp:" && header { if (wanted in field_pos) print $(field_pos[wanted]); exit }
    ' /proc/net/snmp 2>/dev/null
}

netstat_counter() {
    local key=$1
    awk -v wanted="$key" '
        $1 == "TcpExt:" && !header { for (i=2; i<=NF; i++) field_pos[$i]=i; header=1; next }
        $1 == "TcpExt:" && header { if (wanted in field_pos) print $(field_pos[wanted]); exit }
    ' /proc/net/netstat 2>/dev/null
}

tcp_retrans=$(snmp_counter RetransSegs); if [[ -z "$tcp_retrans" ]]; then tcp_retrans=0; fi
tcp_outrsts=$(snmp_counter OutRsts); if [[ -z "$tcp_outrsts" ]]; then tcp_outrsts=0; fi
tcp_inerrs=$(snmp_counter InErrs); if [[ -z "$tcp_inerrs" ]]; then tcp_inerrs=0; fi
tcp_currestab=$(snmp_counter CurrEstab); if [[ -z "$tcp_currestab" ]]; then tcp_currestab=0; fi
tcp_synretrans=$(netstat_counter TCPSynRetrans); if [[ -z "$tcp_synretrans" ]]; then tcp_synretrans=0; fi
tcp_timeouts=$(netstat_counter TCPTimeouts); if [[ -z "$tcp_timeouts" ]]; then tcp_timeouts=0; fi
tcp_listen_overflows=$(netstat_counter ListenOverflows); if [[ -z "$tcp_listen_overflows" ]]; then tcp_listen_overflows=0; fi
tcp_listen_drops=$(netstat_counter ListenDrops); if [[ -z "$tcp_listen_drops" ]]; then tcp_listen_drops=0; fi
tcp_backlog_drop=$(netstat_counter TCPBacklogDrop); if [[ -z "$tcp_backlog_drop" ]]; then tcp_backlog_drop=0; fi

previous_value() {
    awk -F= -v wanted="$1" '$1 == wanted {print $2; exit}' "$COUNTERS_PATH" 2>/dev/null
}

counter_delta() {
    old=$(previous_value "$1")
    current=$2
    if [[ "$counter_state_valid" == true && "$old" =~ ^[0-9]+$ && "$current" =~ ^[0-9]+$ && "$current" -ge "$old" ]]; then
        printf '%s' "$((current - old))"
    else
        printf '0'
    fi
}

counter_state_valid=false
if [[ "$(previous_value counter_schema)" == "$COUNTER_SCHEMA" ]]; then
    counter_state_valid=true
fi
tcp_retrans_delta=$(counter_delta tcp_retrans "$tcp_retrans")
tcp_synretrans_delta=$(counter_delta tcp_synretrans "$tcp_synretrans")
tcp_outrsts_delta=$(counter_delta tcp_outrsts "$tcp_outrsts")
tcp_inerrs_delta=$(counter_delta tcp_inerrs "$tcp_inerrs")
tcp_timeouts_delta=$(counter_delta tcp_timeouts "$tcp_timeouts")
tcp_listen_overflows_delta=$(counter_delta tcp_listen_overflows "$tcp_listen_overflows")
tcp_listen_drops_delta=$(counter_delta tcp_listen_drops "$tcp_listen_drops")
tcp_backlog_drop_delta=$(counter_delta tcp_backlog_drop "$tcp_backlog_drop")
{
    printf 'counter_schema=%s\n' "$COUNTER_SCHEMA"
    printf 'tcp_retrans=%s\n' "$tcp_retrans"
    printf 'tcp_synretrans=%s\n' "$tcp_synretrans"
    printf 'tcp_outrsts=%s\n' "$tcp_outrsts"
    printf 'tcp_inerrs=%s\n' "$tcp_inerrs"
    printf 'tcp_timeouts=%s\n' "$tcp_timeouts"
    printf 'tcp_listen_overflows=%s\n' "$tcp_listen_overflows"
    printf 'tcp_listen_drops=%s\n' "$tcp_listen_drops"
    printf 'tcp_backlog_drop=%s\n' "$tcp_backlog_drop"
} > "$COUNTERS_PATH.tmp"
mv -f "$COUNTERS_PATH.tmp" "$COUNTERS_PATH"

level=ok
alerts_text=
add_crit() {
    level=crit
    if [[ -n "$alerts_text" ]]; then alerts_text="$alerts_text,$1"; else alerts_text=$1; fi
}
add_warn() {
    if [[ "$level" != crit ]]; then level=warn; fi
    if [[ -n "$alerts_text" ]]; then alerts_text="$alerts_text,$1"; else alerts_text=$1; fi
}

[[ "$svc_nginx" == active ]] || add_crit nginx_inactive
[[ "$svc_backend" == active ]] || add_crit backend_inactive
[[ "$listen_443" == true ]] || add_crit listen_443_missing
[[ "$listen_backend" == true ]] || add_crit listen_backend_missing
[[ "$listen_xhttp" == true ]] || add_warn listen_xhttp_missing
[[ "$listen_region_all" == true ]] || add_warn region_listeners_missing
[[ "$tcp443_ok" == true ]] || add_crit tcp443_failed
[[ "$tls_ok" == true ]] || add_crit tls_failed
while read -r source status; do
    [[ "$status" == ok ]] || add_warn "${source}_log_${status}"
done < <(jq -r '.log_sources | to_entries[] | [.key,.value.status] | @tsv' <<< "$log_metrics")
subscription_metrics=$(python3 "$TASK_DIR/subscription_metrics.py") || subscription_metrics='{"alerts":[{"level":"warn","code":"subscription_metrics_failed"}]}'
while read -r severity code; do
    if [[ "$severity" == crit ]]; then add_crit "$code"; else add_warn "$code"; fi
done < <(jq -r '.alerts[] | [.level,.code] | @tsv' <<< "$subscription_metrics")
if (( ws_total >= WS_TOTAL_MIN && ws_503 * 100 >= ws_total * WS_503_RATIO_WARN_PCT )); then add_warn ws_503_ratio_high; fi
if (( ws_503 >= WS_503_COUNT_WARN )); then add_warn ws_503_count_high; fi
if (( ws_101 >= WS_SHORT_MIN && ws_101_short_le5s * 100 >= ws_101 * WS_SHORT_RATIO_WARN_PCT )); then add_warn ws_short_ratio_high; fi
if (( xhttp_total >= XHTTP_TOTAL_MIN && xhttp_other * 100 >= xhttp_total * XHTTP_BAD_RATIO_WARN_PCT )); then add_warn xhttp_error_ratio_high; fi
if (( xhttp_other >= XHTTP_BAD_COUNT_WARN )); then add_warn xhttp_error_count_high; fi
if (( limit_conn_events > 0 )); then add_warn ws_limit_conn_events; fi
if (( limit_req_events > 0 )); then add_warn ws_handshake_rate_events; fi
if (( conn_443_est >= CONN_443_WARN )); then add_warn conn_443_high; fi
if (( conn_backend_est >= CONN_BACKEND_WARN )); then add_warn conn_backend_high; fi
if (( max_peer_443_est >= MAX_PEER_443_WARN )); then add_warn max_peer_443_high; fi
if (( conn_443_backend_gap >= PRE_WS_GAP_WARN && max_peer_443_est >= PRE_WS_MAX_PEER_WARN )); then add_warn pre_ws_stall_candidate; fi
if (( mem_available_mb < MEM_AVAILABLE_WARN_MB )); then add_warn memory_available_low; fi
if (( swap_used_mb > SWAP_USED_WARN_MB )); then add_warn swap_used_high; fi
if (( tcp_retrans_delta >= TCP_RETRANS_DELTA_WARN )); then add_warn tcp_retrans_high; fi
if (( tcp_synretrans_delta >= TCP_SYNRETRANS_DELTA_WARN )); then add_warn tcp_synretrans_high; fi
if (( tcp_timeouts_delta >= TCP_TIMEOUT_DELTA_WARN )); then add_warn tcp_timeouts_high; fi
if (( tcp_listen_overflows_delta >= TCP_LISTEN_DROP_DELTA_WARN )); then add_warn tcp_listen_overflows; fi
if (( tcp_listen_drops_delta >= TCP_LISTEN_DROP_DELTA_WARN )); then add_warn tcp_listen_drops; fi
if (( tcp_backlog_drop_delta >= TCP_BACKLOG_DROP_DELTA_WARN )); then add_warn tcp_backlog_drops; fi

# Preserve null in JSON and human-readable summaries as well as the source status.
while read -r key; do
    printf -v "$key" '%s' null
done < <(jq -r 'to_entries[] | select(.value == null) | .key' <<< "$log_metrics")

alerts_json='[]'
if [[ -n "$alerts_text" ]]; then
    alerts_json=$(printf '%s\n' "$alerts_text" | tr ',' '\n' | jq -Rsc 'split("\n") | map(select(length > 0))')
fi
ok_json=true
if [[ "$level" != ok ]]; then ok_json=false; fi

metric=$(jq -cn \
    --arg ts "$(date --iso-8601=seconds)" \
    --arg level "$level" \
    --arg svc_nginx "$svc_nginx" \
    --arg svc_backend "$svc_backend" \
    --arg window_min "$window_min" \
    --argjson ok "$ok_json" \
    --argjson listen_443 "$listen_443" \
    --argjson listen_backend "$listen_backend" \
    --argjson listen_xhttp "$listen_xhttp" \
    --argjson listen_region_all "$listen_region_all" \
    --argjson region_listeners "$region_listeners_json" \
    --argjson tcp443_ok "$tcp443_ok" \
    --argjson tls_ok "$tls_ok" \
    --argjson tls_ms "$tls_ms" \
    --argjson ws_101 "$ws_101" \
    --argjson ws_503 "$ws_503" \
    --argjson ws_429 "$ws_429" \
    --argjson ws_other "$ws_other" \
    --argjson ws_total "$ws_total" \
    --argjson ws_503_ratio "$ws_503_ratio" \
    --argjson ws_101_short_ratio "$ws_101_short_ratio" \
    --argjson ws_503_zero_ms "$ws_503_zero_ms" \
    --argjson ws_101_zero_bytes "$ws_101_zero_bytes" \
    --argjson ws_101_short_le5s "$ws_101_short_le5s" \
    --argjson xhttp_2xx "$xhttp_2xx" \
    --argjson xhttp_499 "$xhttp_499" \
    --argjson xhttp_other "$xhttp_other" \
    --argjson xhttp_total "$xhttp_total" \
    --argjson limit_conn_events "$limit_conn_events" \
    --argjson limit_req_events "$limit_req_events" \
    --argjson conn_443_est "$conn_443_est" \
    --argjson conn_backend_est "$conn_backend_est" \
    --argjson conn_443_timewait "$conn_443_timewait" \
    --argjson conn_443_synrecv "$conn_443_synrecv" \
    --argjson peer_count_443_est "$peer_count_443_est" \
    --argjson max_peer_443_est "$max_peer_443_est" \
    --argjson conn_443_backend_gap "$conn_443_backend_gap" \
    --argjson mem_available_mb "$mem_available_mb" \
    --argjson swap_used_mb "$swap_used_mb" \
    --argjson rss_nginx_kb "$rss_nginx_kb" \
    --argjson rss_backend_kb "$rss_backend_kb" \
    --argjson tcp_retrans_delta "$tcp_retrans_delta" \
    --argjson tcp_synretrans_delta "$tcp_synretrans_delta" \
    --argjson tcp_outrsts_delta "$tcp_outrsts_delta" \
    --argjson tcp_inerrs_delta "$tcp_inerrs_delta" \
    --argjson tcp_currestab "$tcp_currestab" \
    --argjson tcp_timeouts_delta "$tcp_timeouts_delta" \
    --argjson tcp_listen_overflows_delta "$tcp_listen_overflows_delta" \
    --argjson tcp_listen_drops_delta "$tcp_listen_drops_delta" \
    --argjson tcp_backlog_drop_delta "$tcp_backlog_drop_delta" \
    --argjson log_sources "$log_sources" \
    --argjson alerts "$alerts_json" \
    '{metric_schema:3,log_sources:$log_sources,ts:$ts,window_min:$window_min,ok:$ok,level:$level,svc_nginx:$svc_nginx,svc_xray_proxy:$svc_backend,listen_443:$listen_443,listen_backend:$listen_backend,listen_xhttp:$listen_xhttp,listen_region_all:$listen_region_all,region_listeners:$region_listeners,tcp443_ok:$tcp443_ok,tls_ok:$tls_ok,tls_ms:$tls_ms,ws_101:$ws_101,ws_503:$ws_503,ws_429:$ws_429,ws_other:$ws_other,ws_total:$ws_total,ws_503_ratio:$ws_503_ratio,ws_101_short_ratio:$ws_101_short_ratio,ws_503_zero_ms:$ws_503_zero_ms,ws_101_zero_bytes:$ws_101_zero_bytes,ws_101_short_le5s:$ws_101_short_le5s,xhttp_2xx:$xhttp_2xx,xhttp_499:$xhttp_499,xhttp_other:$xhttp_other,xhttp_total:$xhttp_total,limit_conn_events:$limit_conn_events,limit_req_events:$limit_req_events,conn_443_est:$conn_443_est,conn_backend_est:$conn_backend_est,conn_443_backend_gap:$conn_443_backend_gap,conn_443_timewait:$conn_443_timewait,conn_443_synrecv:$conn_443_synrecv,peer_count_443_est:$peer_count_443_est,max_peer_443_est:$max_peer_443_est,mem_available_mb:$mem_available_mb,swap_used_mb:$swap_used_mb,rss_nginx_kb:$rss_nginx_kb,rss_backend_kb:$rss_backend_kb,tcp_retrans_delta:$tcp_retrans_delta,tcp_synretrans_delta:$tcp_synretrans_delta,tcp_outrsts_delta:$tcp_outrsts_delta,tcp_inerrs_delta:$tcp_inerrs_delta,tcp_currestab:$tcp_currestab,tcp_timeouts_delta:$tcp_timeouts_delta,tcp_listen_overflows_delta:$tcp_listen_overflows_delta,tcp_listen_drops_delta:$tcp_listen_drops_delta,tcp_backlog_drop_delta:$tcp_backlog_drop_delta,alerts:$alerts}')

metric=$(jq -c --argjson subscription "$subscription_metrics" '. + {subscription:$subscription}' <<< "$metric")
printf '%s\n' "$metric" >> "$METRICS_PATH"
printf '%s\n' "$metric" > "$STATE_DIR/last-status.json.tmp"
mv -f "$STATE_DIR/last-status.json.tmp" "$STATE_DIR/last-status.json"

now_epoch=$(date +%s)
previous_fp=
previous_alert_epoch=0
if [[ -r "$ALERT_STATE_PATH" ]]; then
    IFS=' ' read -r previous_fp previous_alert_epoch < "$ALERT_STATE_PATH" || true
fi
fingerprint=$(printf '%s' "$alerts_text" | sha256sum | cut -c1-16)
if [[ -n "$alerts_text" ]]; then
    should_log=false
    if [[ "$fingerprint" != "$previous_fp" ]]; then should_log=true; fi
    if ! [[ "$previous_alert_epoch" =~ ^[0-9]+$ ]]; then should_log=true; fi
    if [[ "$previous_alert_epoch" =~ ^[0-9]+$ && $((now_epoch - previous_alert_epoch)) -ge ALERT_COOLDOWN_SEC ]]; then should_log=true; fi
    if [[ "$should_log" == true ]]; then
        printf '%s level=%s alerts=%s metric=%s\n' "$(date --iso-8601=seconds)" "$level" "$alerts_text" "$metric" >> "$ALERT_LOG_PATH"
        logger -t xray-proxy-health -p local0.warning -- "level=$level alerts=$alerts_text ws503=$ws_503 ws_total=$ws_total xhttp_other=$xhttp_other xhttp_total=$xhttp_total conn443=$conn_443_est conn_backend=$conn_backend_est pre_ws_gap=$conn_443_backend_gap max_peer=$max_peer_443_est mem_available_mb=$mem_available_mb"
        printf '%s %s\n' "$fingerprint" "$now_epoch" > "$ALERT_STATE_PATH"
    fi
elif [[ -n "$previous_fp" ]]; then
    printf '%s level=resolved previous=%s\n' "$(date --iso-8601=seconds)" "$previous_fp" >> "$ALERT_LOG_PATH"
    logger -t xray-proxy-health -p local0.info -- level=resolved
    : > "$ALERT_STATE_PATH"
fi

printf 'xray_proxy_health level=%s ws101=%s ws503=%s ws_short=%s ws_total=%s xhttp2xx=%s xhttp499=%s xhttp_other=%s tls=%s conn443=%s conn_backend=%s pre_ws_gap=%s max_peer=%s mem_available_mb=%s\n' \
    "$level" "$ws_101" "$ws_503" "$ws_101_short_le5s" "$ws_total" "$xhttp_2xx" "$xhttp_499" "$xhttp_other" "$tls_ok" "$conn_443_est" "$conn_backend_est" "$conn_443_backend_gap" "$max_peer_443_est" "$mem_available_mb"
exit 0
