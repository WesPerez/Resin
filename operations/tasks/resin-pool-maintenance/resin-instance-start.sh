#!/usr/bin/env bash
set -euo pipefail

if [[ "${#}" -ne 1 ]]; then
  printf 'usage: %s <resin-binary>\n' "$0" >&2
  exit 2
fi

: "${CREDENTIALS_DIRECTORY:?systemd credentials are required}"

binary="$1"
admin_token_file="${CREDENTIALS_DIRECTORY}/admin_token"
proxy_token_file="${CREDENTIALS_DIRECTORY}/proxy_token"

for path in "$binary" "$admin_token_file" "$proxy_token_file"; do
  if [[ ! -f "$path" ]]; then
    printf 'required file is missing: %s\n' "$path" >&2
    exit 2
  fi
done

RESIN_ADMIN_TOKEN="$(tr -d '\r\n' <"$admin_token_file")"
RESIN_PROXY_TOKEN="$(tr -d '\r\n' <"$proxy_token_file")"
if [[ -z "$RESIN_ADMIN_TOKEN" || -z "$RESIN_PROXY_TOKEN" ]]; then
  printf 'Resin credentials must be non-empty\n' >&2
  exit 2
fi

export RESIN_ADMIN_TOKEN RESIN_PROXY_TOKEN
exec "$binary"
