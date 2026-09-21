#!/usr/bin/env bash
set -euo pipefail
umask 077

# Configure every region in the Resin manifest on Xray and Nginx.
#
# Usage:
#   configure-region-nodes.sh            # check mode: build the complete
#                                        #   candidate config in a temp dir,
#                                        #   run real "xray run -test" and a
#                                        #   real "nginx -t" against it, and
#                                        #   change nothing
#   configure-region-nodes.sh --apply    # after the same checks pass: create a
#                                        #   timestamped backup, install,
#                                        #   re-verify installed files, restart
#                                        #   xray-proxy, reload nginx
#
# Idempotent and fail-closed: every existing inbound/outbound/route/location is
# fully validated, missing artifacts are added, conflicts are rejected.
# Resin credentials are read from root-only files and never appear in argv,
# logs, or Git.

mode=check
case "${1:-}" in
    "") ;;
    --check) ;;
    --apply) mode=apply ;;
    *) echo "usage: $0 [--check|--apply]" >&2; exit 2 ;;
esac

config=/etc/xray/proxy.json
nginx_snippet=/etc/nginx/snippets/proxy-ws.conf
proxy_token_file=/etc/resin-apps/proxy.token
resin_address=172.17.0.1
resin_port=10834
resin_platforms_file=/etc/xray/resin-region-platforms.json
xray_bin=/usr/local/lib/xray/v26.3.27/xray
backup_root=/root/deployment-backups

[[ -r "$config" ]]
[[ -r "$nginx_snippet" ]]
[[ -r "$proxy_token_file" ]]
[[ -r "$resin_platforms_file" ]]
jq -e 'length > 0 and all(to_entries[];
    .value.id and (.value.region | test("^[a-z]{2}$"))
    and .key == ("Proxy" + (.value.region | ascii_upcase)))' "$resin_platforms_file" >/dev/null

work=$(mktemp -d /tmp/xray-region-nodes.XXXXXX)
config_tmp="$work/proxy.json"
snippet_tmp="$work/proxy-ws.conf"
secret_tmp="$work/secret.json"
nginx_conf_tmp="$work/nginx.conf"
cleanup() { rm -r "$work"; }
rollback_armed=0
backup_dir=""
on_exit() {
    status=$?
    if [[ "$rollback_armed" == 1 ]]; then
        rollback_armed=0
        printf 'apply failed (status=%s); restoring backup %s\n' "$status" "$backup_dir" >&2
        install -o root -g root -m 0600 "$backup_dir/etc-xray/proxy.json" "$config" || true
        install -o root -g root -m 0644 "$backup_dir/etc-nginx-snippets/proxy-ws.conf" "$nginx_snippet" || true
        if "$xray_bin" run -test -config "$config" >/dev/null 2>&1; then
            systemctl restart xray-proxy.service || true
        else
            printf 'rollback warning: restored xray config failed its test\n' >&2
        fi
        if nginx -t >/dev/null 2>&1; then
            systemctl reload nginx.service || true
        else
            printf 'rollback warning: restored nginx config failed its test\n' >&2
        fi
        printf 'rollback completed\n' >&2
        status=1
    fi
    cleanup
    exit "$status"
}
trap on_exit EXIT

cp "$config" "$config_tmp"
cp "$nginx_snippet" "$snippet_tmp"

# Build a root-only credential file so the token never appears in argv.
umask 077
jq -n --rawfile token "$proxy_token_file" \
    '{pass: ($token | gsub("\\s"; ""))}' > "$secret_tmp"
jq -e '.pass | length > 0' "$secret_tmp" >/dev/null

uuid=$(jq -er '.inbounds[] | select(.tag == "proxy-ws") | .settings.clients[0].id' "$config_tmp")
[[ "$uuid" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]

mapfile -t regions < <(jq -r '[.[].region] | unique
    | sort_by(if . == "hk" then "0" elif . == "jp" then "1"
        elif . == "us" then "2" else "3" + . end)[]' "$resin_platforms_file")
declare -a configured_ports=()
next_port=13103

# Preserve published WS transports and paths. Protocol migrations need a
# separate, parallel rollout because existing clients retain their old config.

for region in "${regions[@]}"; do
    inbound_tag="proxy-ws-$region"
    outbound_tag="resin-$region"
    platform_user="Proxy${region^^}"

    # --- inbound ---------------------------------------------------------
    inbound_count=$(jq --arg tag "$inbound_tag" \
        '[.inbounds[] | select(.tag == $tag)] | length' "$config_tmp")
    if [[ "$inbound_count" -eq 0 ]]; then
        case "$region" in
            hk) port=13100 ;;
            jp) port=13101 ;;
            us) port=13102 ;;
            *)
                while jq -e --argjson port "$next_port" 'any(.inbounds[]; .port == $port)' "$config_tmp" >/dev/null \
                    || [[ -n "$(ss -Hltn "sport = :$next_port")" ]]; do
                    next_port=$((next_port + 1))
                    (( next_port <= 13999 ))
                done
                port=$next_port
                next_port=$((next_port + 1))
                ;;
        esac
        [[ -z "$(ss -Hltn "sport = :$port")" ]]
        jq -e --argjson port "$port" 'all(.inbounds[]; .port != $port)' "$config_tmp" >/dev/null
        path="/ws/$(openssl rand -hex 32)"
        printf '%s\n' "$path" > "$work/path"
        jq --arg tag "$inbound_tag" \
           --argjson port "$port" --rawfile path "$work/path" '
            (.inbounds[] | select(.tag == "proxy-ws") | .settings.clients[0].id) as $uuid |
            .inbounds += [{
                tag: $tag, listen: "127.0.0.1", port: $port,
                protocol: "vless",
                settings: {clients: [{id: $uuid, email: $tag}], decryption: "none"},
                streamSettings: {network: "ws", security: "none", wsSettings: {path: ($path | rtrimstr("\n"))}},
                sniffing: {enabled: true, destOverride: ["http", "tls"], routeOnly: true}
            }]' "$config_tmp" > "$config_tmp.new"
        jq empty "$config_tmp.new"
        mv "$config_tmp.new" "$config_tmp"
        printf 'inbound %s: added\n' "$inbound_tag"
    elif [[ "$inbound_count" -eq 1 ]]; then
        port=$(jq -er --arg tag "$inbound_tag" '.inbounds[] | select(.tag == $tag) | .port' "$config_tmp")
        [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 13100 && port <= 13999 ))
        inbound=$(jq -c --arg tag "$inbound_tag" \
            '.inbounds[] | select(.tag == $tag)' "$config_tmp")
        jq -e --argjson port "$port" --slurpfile config "$config_tmp" '
            ($config[0].inbounds[] | select(.tag == "proxy-ws") | .settings.clients[0].id) as $uuid |
            .listen == "127.0.0.1" and .port == $port and .protocol == "vless"
            and .settings.clients[0].id == $uuid and .settings.decryption == "none"
            and .streamSettings.network == "ws" and .streamSettings.security == "none"
            and (.streamSettings.wsSettings.path | test("^/ws/[0-9a-f]{64}$"))' \
            <<<"$inbound" >/dev/null
    else
        echo "reject: duplicate inbound $inbound_tag" >&2
        exit 1
    fi
    configured_ports+=("$port")
    path=$(jq -r --arg tag "$inbound_tag" \
        '.inbounds[] | select(.tag == $tag) | .streamSettings.wsSettings.path' "$config_tmp")

    # --- outbound --------------------------------------------------------
    outbound_count=$(jq --arg tag "$outbound_tag" \
        '[.outbounds[] | select(.tag == $tag)] | length' "$config_tmp")
    if [[ "$outbound_count" -eq 0 ]]; then
        jq --arg tag "$outbound_tag" --arg user "$platform_user" \
           --arg addr "$resin_address" --argjson port "$resin_port" \
           --slurpfile secret "$secret_tmp" '
            .outbounds += [{
                tag: $tag, protocol: "socks",
                settings: {servers: [{
                    address: $addr, port: $port,
                    users: [{user: $user, pass: $secret[0].pass}]
                }]}
            }]' "$config_tmp" > "$config_tmp.new"
        jq empty "$config_tmp.new"
        mv "$config_tmp.new" "$config_tmp"
        printf 'outbound %s: added\n' "$outbound_tag"
    elif [[ "$outbound_count" -eq 1 ]]; then
        outbound=$(jq -c --arg tag "$outbound_tag" \
            '.outbounds[] | select(.tag == $tag)' "$config_tmp")
        jq -e --arg addr "$resin_address" --argjson port "$resin_port" \
           --arg user "$platform_user" --slurpfile secret "$secret_tmp" '
            .protocol == "socks"
            and .settings.servers[0].address == $addr
            and .settings.servers[0].port == $port
            and .settings.servers[0].users[0].user == $user
            and .settings.servers[0].users[0].pass == $secret[0].pass' \
            <<<"$outbound" >/dev/null
    else
        echo "reject: duplicate outbound $outbound_tag" >&2
        exit 1
    fi

    # --- routing rule ----------------------------------------------------
    rule_count=$(jq --arg itag "$inbound_tag" --arg otag "$outbound_tag" \
        '[.routing.rules[] | select(.type == "field" and .inboundTag == [$itag])] | length' \
        "$config_tmp")
    if [[ "$rule_count" -eq 0 ]]; then
        jq --arg itag "$inbound_tag" --arg otag "$outbound_tag" '
            .routing.rules += [{type: "field", inboundTag: [$itag], outboundTag: $otag}]' \
            "$config_tmp" > "$config_tmp.new"
        jq empty "$config_tmp.new"
        mv "$config_tmp.new" "$config_tmp"
        printf 'routing rule %s: added\n' "$inbound_tag"
    elif [[ "$rule_count" -eq 1 ]]; then
        jq -e --arg itag "$inbound_tag" --arg otag "$outbound_tag" \
            '.routing.rules[]
            | select(.type == "field" and .inboundTag == [$itag])
            | .outboundTag == $otag' "$config_tmp" >/dev/null
    else
        echo "reject: conflicting routing rules for $inbound_tag" >&2
        exit 1
    fi

    # --- nginx location --------------------------------------------------
    printf 'location = %s {\n' "$path" > "$work/location-pattern"
    cat > "$work/expected-location" <<NGINX
location = $path {
    proxy_pass http://127.0.0.1:$port;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$remote_addr;
    proxy_set_header X-Forwarded-Proto https;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_socket_keepalive on;
    proxy_connect_timeout 10s;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    limit_conn proxy_ws_conn 384;
    limit_conn proxy_ws_global 768;
    limit_conn_status 429;
    limit_req zone=proxy_ws_handshake burst=60 nodelay;
    limit_req_status 429;
    access_log /var/log/nginx/proxy-ws-access.log proxy_ws;
}
NGINX
    awk -v pattern="$(cat "$work/location-pattern")" '
        $0 == pattern { inside=1 }
        inside { print }
        inside && $0 == "}" { inside=0 }
    ' "$snippet_tmp" > "$work/existing-location"
    if [[ -s "$work/existing-location" ]]; then
        cmp -s "$work/expected-location" "$work/existing-location" || {
            printf 'reject: conflicting nginx location for %s\n' "$inbound_tag" >&2
            exit 1
        }
    else
        cat "$work/expected-location" >> "$snippet_tmp"
        printf 'nginx location %s: added\n' "$inbound_tag"
    fi
done

# --- whole-file invariants -----------------------------------------------
jq empty "$config_tmp"
jq -e --slurpfile manifest "$resin_platforms_file" '
    ($manifest[0] | length) as $count |
    ([.inbounds[] | select(.tag | test("^proxy-ws-[a-z]{2}$"))] | length == $count) and
    ([.outbounds[] | select(.tag | test("^resin-[a-z]{2}$"))] | length == $count) and
    ([.routing.rules[] | select(.inboundTag? and (.inboundTag | length == 1)
        and (.inboundTag[0] | test("^proxy-ws-[a-z]{2}$")))] | length == $count) and
    (([.inbounds[].port]) | length == (unique | length)) and
    (.outbounds[0].tag == "direct") and
    (([.inbounds[] | select(.tag | test("^proxy-ws"))
        | .streamSettings |
          (if .network == "ws" then .wsSettings.path else .xhttpSettings.path end)]) as $paths
        | ($paths | length) == ($paths | unique | length))' \
    "$config_tmp" >/dev/null

# --- real xray test on the candidate config -------------------------------
"$xray_bin" run -test -config "$config_tmp" >/dev/null 2>&1

# --- real nginx -t against the candidate snippet --------------------------
{
    printf 'pid %s/nginx.pid;\n' "$work"
    printf 'error_log stderr warn;\n'
    printf 'events { worker_connections 16; }\n'
    printf 'http {\n'
    printf '    include /etc/nginx/mime.types;\n'
    printf '    include /etc/nginx/conf.d/proxy-security.conf;\n'
    printf '    server {\n'
    printf '        listen 127.0.0.1:18443;\n'
    printf '        server_name weesai.com;\n'
    printf '        include "%s";\n' "$snippet_tmp"
    printf '    }\n'
    printf '}\n'
} > "$nginx_conf_tmp"
nginx -t -q -c "$nginx_conf_tmp" 2>"$work/nginx-test.err"

if [[ "$mode" == check ]]; then
    printf 'check passed: candidate xray config and nginx snippet are valid\n'
    exit 0
fi

if cmp -s "$config" "$config_tmp" && cmp -s "$nginx_snippet" "$snippet_tmp"; then
    printf 'already configured; no service restart needed\n'
    exit 0
fi

# --- apply: back up, install, re-verify, restart --------------------------
backup_dir="$backup_root/proxy-region-nodes-$(date +%Y%m%dT%H%M%S)"
mkdir -p "$backup_dir/etc-xray" "$backup_dir/etc-nginx-snippets"
cp -a "$config" "$backup_dir/etc-xray/"
cp -a "$nginx_snippet" "$backup_dir/etc-nginx-snippets/"
rollback_armed=1

install -o root -g root -m 0600 "$config_tmp" "$config"
install -o root -g root -m 0644 "$snippet_tmp" "$nginx_snippet"

"$xray_bin" run -test -config "$config" >/dev/null 2>&1
nginx -t >/dev/null
systemctl restart xray-proxy.service
systemctl reload nginx.service

for port in "${configured_ports[@]}"; do
    ready=false
    for attempt in {1..50}; do
        listeners=$(ss -Hltn "sport = :$port" | awk '{print $4}')
        if [[ "$listeners" == "127.0.0.1:$port" ]]; then ready=true; break; fi
        sleep 0.2
    done
    if [[ "$ready" != true ]]; then
        printf 'region listener not ready on loopback: %s\n' "$port" >&2
        exit 1
    fi
done
[[ "$(systemctl is-active xray-proxy.service)" == active ]]
[[ "$(systemctl is-active nginx.service)" == active ]]
rollback_armed=0

printf 'applied. backup: %s\n' "$backup_dir"
