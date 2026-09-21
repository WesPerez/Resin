#!/usr/bin/env bash
set -euo pipefail

# Discover healthy exit regions and ensure their routing platforms exist on Resin.
# persist their IDs for rollback. The admin token is passed to curl through a
# root-only temporary header file (never argv, logs, or Git) and removed on
# exit. Node data and tokens are never printed.

base=${RESIN_ADMIN_BASE_URL:-http://172.17.0.1:10834}
token_file=${RESIN_ADMIN_TOKEN_FILE:-/etc/resin-apps/admin.token}
output=${REGION_PLATFORMS_FILE:-/etc/xray/resin-region-platforms.json}

[[ -r "$token_file" ]]
token=$(tr -d '\r\n' < "$token_file")
[[ -n "$token" ]]

work=$(mktemp -d /tmp/resin-region-platforms.XXXXXX)
auth_header="$work/auth.header"
cleanup() { rm -r "$work"; }
trap cleanup EXIT

umask 077
printf 'Authorization: Bearer %s\n' "$token" > "$auth_header"
unset token

curl_auth=("--header" "@$auth_header")

list_platforms() {
    curl -fsS --max-time 15 \
        "${curl_auth[@]}" \
        -H 'Accept: application/json' \
        "$base/api/v1/platforms?keyword=$1"
}

get_platform() {
    curl -fsS --max-time 15 \
        "${curl_auth[@]}" \
        -H 'Accept: application/json' \
        "$base/api/v1/platforms/$1"
}

create_platform() {
    curl -fsS --max-time 15 -X POST \
        "${curl_auth[@]}" \
        -H 'Content-Type: application/json' \
        -H 'Accept: application/json' \
        --data "$(jq -nc \
            --arg name "$1" \
            --arg region "$2" \
            --arg source "$3" \
            '{name: $name, regex_filters: [$source], region_filters: [$region]}')" \
        "$base/api/v1/platforms"
}

# Keep only region metadata from the paginated node inventory.
offset=0
while :; do
    curl -fsS --max-time 30 "${curl_auth[@]}" \
        "$base/api/v1/nodes?enabled=true&has_outbound=true&circuit_open=false&limit=1000&offset=$offset" \
        | jq '{total, size: (.items | length), regions: [.items[]
            | select(.enabled and .has_outbound and .circuit_open_since == null)
            | select((.egress_ip // "") != "" and (.region // "" | test("^[a-z]{2}$")))
            | select(any(.tags[]?; .subscription_name == "managed-apps-public-pool"
                or .subscription_name == "managed-apps-cn-public-pool"))
            | .region]}' > "$work/page-$offset.json"
    size=$(jq -er '.size' "$work/page-$offset.json")
    total=$(jq -er '.total' "$work/page-$offset.json")
    (( offset + size >= total )) && break
    (( size > 0 ))
    offset=$((offset + size))
done
jq -s '[.[].regions[]] | unique' "$work"/page-*.json > "$work/regions.json"
if [[ -r "$output" ]]; then
    jq --slurpfile previous "$output" \
        '. + [$previous[0][] | .region] | unique' "$work/regions.json" > "$work/regions.next"
    mv "$work/regions.next" "$work/regions.json"
fi
jq -e 'length > 0 and all(.[]; test("^[a-z]{2}$"))' "$work/regions.json" >/dev/null

created=0
while read -r region; do
    name="Proxy${region^^}"
    source='^managed-apps-public-pool/.*'
    if [[ "$region" == cn ]]; then source='^managed-apps-cn-public-pool/.*'; fi
    id=$(list_platforms "$name" \
        | jq -r --arg name "$name" '[.. | objects | select(.name? == $name)][0].id // empty')
    if [[ -z "$id" ]]; then
        id=$(create_platform "$name" "$region" "$source" | jq -er '.id')
        created=$((created + 1))
    fi
    row=$(get_platform "$id")
    jq -e --arg id "$id" --arg name "$name" --arg region "$region" --arg source "$source" '
        .id == $id and .name == $name
        and .region_filters == [$region]
        and (.regex_filters == [$source]
             or (.allocation_policy == "PREFER_LOW_LATENCY"
                 and .regex_filters[0] == ("*" + $source)
                 and (.regex_filters | length > 1))
             or (.allocation_policy == "PREFER_LOW_LATENCY"
                 and .regex_filters[0] == $source
                 and (.regex_filters[1:] | length > 0 and all(.[]; startswith("!^")))))
        and (.routable_node_count | type == "number" and . >= 0)' <<<"$row" >/dev/null
    count=$(jq -r '.routable_node_count' <<<"$row")
    jq -n --arg id "$id" --arg region "$region" --arg source "$source" --argjson count "$count" \
        '{id: $id, region: $region, regex_filters: [$source], routable_node_count: $count}' \
        > "$work/$name.json"
    printf '%s ready: %s routable nodes\n' "$name" "$count"
done < <(jq -r '.[]' "$work/regions.json")

jq -s 'map({key: ("Proxy" + (.region | ascii_upcase)), value: .}) | from_entries' \
    "$work"/Proxy*.json > "$work/manifest.json"
jq -e 'length > 0 and all(.[]; .id and (.region | test("^[a-z]{2}$")))' "$work/manifest.json" >/dev/null

install -o root -g root -m 0600 "$work/manifest.json" "$output"
printf 'region platform manifest installed; created=%s\n' "$created"
