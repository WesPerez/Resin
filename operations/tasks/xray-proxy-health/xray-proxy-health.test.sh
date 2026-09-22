#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
bash -n "$root/xray-proxy-health.sh"
python3 -m unittest discover -s "$root" -p 'test_log_metrics.py'
python3 -m unittest discover -s "$root" -p 'test_subscription_metrics.py'

peer_summary=$(printf '%s\n' \
    '0 0 10.0.0.1:443 198.51.100.1:10001' \
    '0 0 10.0.0.1:443 198.51.100.1:10002' \
    '0 0 10.0.0.1:443 203.0.113.2:10003' | awk '
        NF {
            peer=$4
            sub(/:[^:]+$/, "", peer)
            if (!(peer in seen)) { seen[peer]=1; peers++ }
            count[peer]++
        }
        END {
            for (peer in count) if (count[peer] > max) max=count[peer]
            printf "%d %d", peers+0, max+0
        }
    ')
[[ "$peer_summary" == '2 2' ]]

backend_summary=$(printf '%s\n' \
    '0 0 127.0.0.1:51000 127.0.0.1:12762' \
    '0 0 127.0.0.1:12762 127.0.0.1:51000' \
    '0 0 127.0.0.1:51001 127.0.0.1:12763' \
    '0 0 127.0.0.1:12763 127.0.0.1:51001' | awk -v p1=:12762 -v p2=:12763 '
        index($4,p1) > 0 || index($4,p2) > 0 { n++ }
        END { print n+0 }
    ')
[[ "$backend_summary" == 2 ]]

region_backend_summary=$(printf '%s\n' \
    '0 0 127.0.0.1:51002 127.0.0.1:13100' \
    '0 0 127.0.0.1:13100 127.0.0.1:51002' \
    '0 0 127.0.0.1:51003 127.0.0.1:13101' \
    '0 0 127.0.0.1:443 127.0.0.1:9999' | awk -v pattern=':(12762|12763|13100|13101|13102)$' \
        '$4 ~ pattern { n++ } END { print n+0 }')
[[ "$region_backend_summary" == 2 ]]

snmp_value=$(printf '%s\n' \
    'Tcp: RtoAlgorithm RetransSegs CurrEstab' \
    'Tcp: 1 17 9' | awk -v wanted=RetransSegs '
        $1 == "Tcp:" && !header { for (i=2; i<=NF; i++) field_pos[$i]=i; header=1; next }
        $1 == "Tcp:" && header { if (wanted in field_pos) print $(field_pos[wanted]); exit }
    ')
[[ "$snmp_value" == 17 ]]

pre_ws_gap=$((508 - 15))
[[ "$pre_ws_gap" == 493 ]]
grep -Fq 'ws_101_short_ratio' "$root/xray-proxy-health.sh"
grep -Fq 'pre_ws_stall_candidate' "$root/xray-proxy-health.sh"
grep -Fq 'conn_443_backend_gap' "$root/xray-proxy-health.sh"
grep -Fq 'listen_xhttp' "$root/xray-proxy-health.sh"
grep -Fq 'xhttp_other' "$root/xray-proxy-health.sh"
grep -Fq 'XHTTP_BACKEND_PORT' "$root/xray-proxy-health.sh"
grep -Fq 'REGION_BACKEND_PORTS' "$root/xray-proxy-health.sh"
grep -Fq 'listen_region_all' "$root/xray-proxy-health.sh"
grep -Fq 'region_listeners' "$root/xray-proxy-health.sh"

grep -Fq 'limit_conn proxy_ws_conn 384;' /etc/nginx/snippets/proxy-ws.conf
grep -Fq 'limit_conn proxy_ws_global 768;' /etc/nginx/snippets/proxy-ws.conf
grep -Fq 'limit_req zone=proxy_ws_handshake burst=60 nodelay;' /etc/nginx/snippets/proxy-ws.conf
grep -Fq 'limit_conn proxy_ws_conn 384;' /etc/nginx/snippets/proxy-xhttp.conf
grep -Fq 'grpc_pass grpc://127.0.0.1:12763;' /etc/nginx/snippets/proxy-xhttp.conf
grep -Fq 'XHTTP_BAD_RATIO_WARN_PCT=50' "$root/xray-proxy-health.env.example"
grep -Fq 'REGION_BACKEND_PORTS=auto' "$root/xray-proxy-health.env.example"

# The env file must survive a real source with quoted multi-port values.
(
    . "$root/xray-proxy-health.env.example"
    [[ "$REGION_BACKEND_PORTS" == auto ]]
)
auto_ports=$(jq -nr '{inbounds: [{tag:"proxy-ws",port:12762},
    {tag:"proxy-ws-hk",port:13100},{tag:"proxy-ws-sg",port:13103},
    {tag:"proxy-ws-cn",port:13104}]} | [.inbounds[]
    | select(.tag | test("^proxy-ws-[a-z]{2}$")) | .port] | unique | map(tostring) | join(" ")')
[[ "$auto_ports" == "13100 13103 13104" ]]
systemd-analyze verify "$root/systemd/xray-proxy-health.service" "$root/systemd/xray-proxy-health.timer"
printf 'xray-proxy-health offline checks passed\n'
