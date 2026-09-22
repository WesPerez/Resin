#!/usr/bin/env bash
set -euo pipefail

umask 077

config=${XRAY_PROXY_CONFIG:-/etc/xray/proxy.json}
token_file=${XRAY_SUBSCRIPTION_TOKEN_FILE:-/etc/xray/subscription-token}
subscription_dir=${XRAY_SUBSCRIPTION_OUTPUT_DIR:-/var/lib/proxy-subscription}
url_file=${XRAY_SUBSCRIPTION_URL_FILE:-/root/proxy-subscription-url.txt}
server_name=weesai.com

uuid=$(jq -er '.inbounds[] | select(.tag == "proxy-ws") | .settings.clients[0].id' "$config")
ws_path=$(jq -er '.inbounds[] | select(.tag == "proxy-ws") | .streamSettings.wsSettings.path' "$config")
backend_port=$(jq -er '.inbounds[] | select(.tag == "proxy-ws") | .port' "$config")
xhttp_uuid=$(jq -er '.inbounds[] | select(.tag == "proxy-xhttp") | .settings.clients[0].id' "$config")
xhttp_network=$(jq -er '.inbounds[] | select(.tag == "proxy-xhttp") | .streamSettings.network' "$config")
xhttp_security=$(jq -er '.inbounds[] | select(.tag == "proxy-xhttp") | .streamSettings.security' "$config")
xhttp_path=$(jq -er '.inbounds[] | select(.tag == "proxy-xhttp") | .streamSettings.xhttpSettings.path' "$config")
xhttp_mode=$(jq -er '.inbounds[] | select(.tag == "proxy-xhttp") | .streamSettings.xhttpSettings.mode' "$config")
xhttp_backend_port=$(jq -er '.inbounds[] | select(.tag == "proxy-xhttp") | .port' "$config")
regions=$(jq -ce '[.inbounds[] | select(.tag | test("^proxy-ws-[a-z]{2}$"))
    | {region: (.tag | ltrimstr("proxy-ws-")),
       path: (.streamSettings | if .network == "ws" then .wsSettings.path else .xhttpSettings.path end),
       network: .streamSettings.network}]
    | sort_by(if .region == "hk" then "0" elif .region == "jp" then "1"
        elif .region == "us" then "2" else "3" + .region end)' "$config")
token=$(tr -d '\r\n' < "$token_file")

[[ "$uuid" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]
[[ "$xhttp_uuid" == "$uuid" ]]
[[ "$ws_path" =~ ^/ws/[0-9a-f]{64}$ ]]
[[ "$backend_port" == 12762 ]]
[[ "$xhttp_network" == xhttp ]]
[[ "$xhttp_security" == none ]]
[[ "$xhttp_path" =~ ^/xhttp/[0-9a-f]{64}$ ]]
[[ "$xhttp_mode" == stream-up ]]
[[ "$xhttp_backend_port" == 12763 ]]
jq -e '
    . as $config
    | (.inbounds[] | select(.tag == "proxy-ws") | .settings.clients[0].id) as $uuid
    | [.inbounds[] | select(.tag | test("^proxy-ws-[a-z]{2}$"))] as $regions
    | ($regions | length > 0)
      and all($regions[];
        . as $inbound | (.tag | ltrimstr("proxy-ws-")) as $region
        | .listen == "127.0.0.1" and .protocol == "vless"
          and (.port | type == "number" and . >= 13100 and . <= 13999)
          and .settings.clients[0].id == $uuid and .settings.decryption == "none"
          and .streamSettings.security == "none"
          and ((.streamSettings.network == "ws" and (.streamSettings.wsSettings.path | test("^/ws/[0-9a-f]{64}$")))
            or (.streamSettings.network == "xhttp" and .streamSettings.xhttpSettings.mode == "stream-up"
                and (.streamSettings.xhttpSettings.path | test("^/(ws|xhttp)/[0-9a-f]{64}$"))))
          and ([$config.routing.rules[] | select(.inboundTag == [$inbound.tag]
               and .outboundTag == ("resin-" + $region))] | length == 1)
          and ([$config.outbounds[] | select(.tag == ("resin-" + $region)
               and .protocol == "socks" and .settings.servers[0].users[0].user == ("Proxy" + ($region | ascii_upcase)))] | length == 1))
      and (($regions | map(.tag)) | length == (unique | length))
      and (($regions | map(.port)) | length == (unique | length))
      and (([.inbounds[] | .streamSettings | if .network == "ws" then .wsSettings.path else .xhttpSettings.path end])
          | length == (unique | length))' "$config" >/dev/null
[[ "$token" =~ ^[0-9a-f]{64}$ ]]
[[ "$server_name" =~ ^[A-Za-z0-9.-]+$ ]]

if [[ $EUID -eq 0 ]]; then
    install -d -o root -g www-data -m 0750 "$subscription_dir"
else
    mkdir -p "$subscription_dir"
fi

tmp=$(mktemp "$subscription_dir/.subscription.XXXXXX")
url_tmp=
base_tmp=
cleanup() {
    if [[ -n "$tmp" && -e "$tmp" ]]; then rm -f "$tmp"; fi
    if [[ -n "$url_tmp" && -e "$url_tmp" ]]; then rm -f "$url_tmp"; fi
    if [[ -n "$base_tmp" && -e "$base_tmp" ]]; then rm -f "$base_tmp"; fi
}
trap cleanup EXIT

cat > "$tmp" <<YAML
mixed-port: 7890
allow-lan: false
mode: rule
log-level: warning
ipv6: false
unified-delay: true
tcp-concurrent: true
find-process: false

profile:
  store-selected: true

dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '*.lan'
    - '*.local'
    - '+.msftconnecttest.com'
    - '+.msftncsi.com'
  nameserver:
    - 223.5.5.5
    - 119.29.29.29
  fallback:
    - https://1.1.1.1/dns-query
    - https://dns.google/dns-query
  proxy-server-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  fallback-filter:
    geoip: true
    geoip-code: CN

proxies:
  - name: "$server_name-vless-443"
    type: vless
    server: "$server_name"
    port: 443
    uuid: "$uuid"
    tls: true
    servername: "$server_name"
    client-fingerprint: chrome
    network: xhttp
    udp: true
    encryption: ""
    alpn:
      - h2
    xhttp-opts:
      path: "$xhttp_path"
      host: "$server_name"
      mode: stream-up

  - name: "$server_name-vless-443-ws"
    type: vless
    server: "$server_name"
    port: 443
    uuid: "$uuid"
    tls: true
    servername: "$server_name"
    client-fingerprint: chrome
    network: ws
    udp: true
    ws-opts:
      path: "$ws_path"
      headers:
        Host: "$server_name"

YAML

while IFS=$'\t' read -r region region_path region_network; do
    cat >> "$tmp" <<YAML
  - name: "${region^^}-Auto"
    type: vless
    server: "$server_name"
    port: 443
    uuid: "$uuid"
    tls: true
    servername: "$server_name"
    client-fingerprint: chrome
    network: "$region_network"
    udp: false

YAML
    if [[ "$region_network" == ws ]]; then
        cat >> "$tmp" <<YAML
    ws-opts:
      path: "$region_path"
      headers:
        Host: "$server_name"

YAML
    else
        cat >> "$tmp" <<YAML
    alpn:
      - h2
    xhttp-opts:
      path: "$region_path"
      host: "$server_name"
      mode: stream-up

YAML
    fi
done < <(jq -r '.[] | [.region, .path, .network] | @tsv' <<<"$regions")

cat >> "$tmp" <<YAML
proxy-groups:
  - name: Auto-Fast
    type: url-test
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 100
    lazy: true
    expected-status: 204
    timeout: 5000
    proxies:
YAML
fast_count=0
for region in us ca jp hk sg de nl; do
    if jq -e --arg region "$region" 'any(.[]; .region == $region and .network == "ws")' <<<"$regions" >/dev/null; then
        printf '      - "%s-Auto"\n' "${region^^}" >> "$tmp"
        fast_count=$((fast_count + 1))
    fi
done
[[ "$fast_count" -gt 0 ]]

cat >> "$tmp" <<YAML

  - name: Auto-Region
    type: url-test
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 100
    lazy: true
    expected-status: 204
    timeout: 5000
    proxies:
YAML
while read -r region; do
    printf '      - "%s-Auto"\n' "${region^^}" >> "$tmp"
done < <(jq -r '.[].region' <<<"$regions")

cat >> "$tmp" <<YAML

  - name: PROXY
    type: select
    proxies:
      - Auto-Fast
      - "$server_name-vless-443"
      - Auto-Region
      - "$server_name-vless-443-ws"
YAML
while read -r region; do
    printf '      - "%s-Auto"\n' "${region^^}" >> "$tmp"
done < <(jq -r '.[].region' <<<"$regions")

cat >> "$tmp" <<YAML
rules:
  - MATCH,PROXY
YAML

base_tmp=$(mktemp "$subscription_dir/.base.XXXXXX")
cp "$tmp" "$base_tmp"
python3 "$(dirname -- "${BASH_SOURCE[0]}")/site-subscription.py" "$tmp" \
    --policy "${XRAY_SITE_POLICY:-/etc/xray/site-quality-policy.json}" \
    --state "${XRAY_SITE_APPROVED:-/var/lib/proxy-region-latency/site-approved.json}" \
    --bridge "${XRAY_SITE_BRIDGE:-/var/lib/resin-singbox-bridge/current/bridge.json}"
python3 "$(dirname -- "${BASH_SOURCE[0]}")/rotation-subscription.py" "$tmp" --base "$base_tmp" \
    --policy "${XRAY_ROTATION_POLICY:-/etc/xray/rotation-policy.json}"

if [[ $EUID -eq 0 ]]; then
    chown root:www-data "$tmp"
fi
chmod 0640 "$tmp"
mv -f "$tmp" "$subscription_dir/$token.yaml"
tmp=

if [[ -f "$url_file" ]] && [[ "$(<"$url_file")" == "https://$server_name/sub/$token.yaml" ]]; then
    printf 'Mihomo subscription rendered; existing URL retained\n'
    exit 0
fi
url_tmp=$(mktemp "$(dirname "$url_file")/.proxy-subscription-url.XXXXXX")
printf 'https://%s/sub/%s.yaml\n' "$server_name" "$token" > "$url_tmp"
if [[ $EUID -eq 0 ]]; then
    chown root:root "$url_tmp"
fi
chmod 0600 "$url_tmp"
mv -f "$url_tmp" "$url_file"
url_tmp=

printf 'Mihomo subscription rendered with region auto nodes\n'
