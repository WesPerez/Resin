#!/bin/sh
set -eu

cache_dir="${RESIN_CACHE_DIR:-/var/cache/resin}"
state_dir="${RESIN_STATE_DIR:-/var/lib/resin}"
log_dir="${RESIN_LOG_DIR:-/var/log/resin}"

load_secret_file() {
  var_name="$1"
  file_var_name="${var_name}_FILE"
  eval "value=\${${var_name}:-}"
  eval "file_path=\${${file_var_name}:-}"

  if [ -n "$value" ] && [ -n "$file_path" ]; then
    echo "fatal: set only one of ${var_name} or ${file_var_name}" >&2
    exit 1
  fi
  if [ -z "$file_path" ]; then
    return
  fi
  if [ ! -r "$file_path" ]; then
    echo "fatal: secret file is not readable: ${file_path}" >&2
    exit 1
  fi
  value="$(tr -d '\r\n' < "$file_path")"
  export "${var_name}=${value}"
}

load_secret_file RESIN_ADMIN_TOKEN
load_secret_file RESIN_PROXY_TOKEN

if [ "$#" -eq 0 ]; then
  set -- /usr/local/bin/resin
fi

runtime_user="resin:resin"
if [ -n "${RESIN_RUNTIME_UID:-}" ] || [ -n "${RESIN_RUNTIME_GID:-}" ]; then
  if [ -z "${RESIN_RUNTIME_UID:-}" ] || [ -z "${RESIN_RUNTIME_GID:-}" ]; then
    echo "fatal: RESIN_RUNTIME_UID and RESIN_RUNTIME_GID must be set together" >&2
    exit 1
  fi
  case "${RESIN_RUNTIME_UID}:${RESIN_RUNTIME_GID}" in
    *[!0-9:]*|:*|*:)
      echo "fatal: RESIN_RUNTIME_UID and RESIN_RUNTIME_GID must be numeric" >&2
      exit 1
      ;;
  esac
  runtime_user="${RESIN_RUNTIME_UID}:${RESIN_RUNTIME_GID}"
fi

require_writable_dir() {
  dir="$1"
  label="$2"

  if [ ! -d "$dir" ]; then
    mkdir -p "$dir"
  fi
  if [ ! -w "$dir" ]; then
    cat >&2 <<EOF
fatal: ${label} directory is not writable: ${dir}
hint: mount it with write permission, or use Docker named volumes.
EOF
    exit 1
  fi
}

if [ "$(id -u)" -eq 0 ]; then
  mkdir -p "$cache_dir" "$state_dir" "$log_dir"
  if [ "${RESIN_SKIP_CHOWN:-0}" != "1" ]; then
    chown -R "$runtime_user" "$cache_dir" "$state_dir" "$log_dir"
  fi
  exec su-exec "$runtime_user" "$@"
fi

require_writable_dir "$cache_dir" "cache"
require_writable_dir "$state_dir" "state"
require_writable_dir "$log_dir" "log"

exec "$@"
