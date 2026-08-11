#!/usr/bin/env bash
# dotenv.sh - shared .env loader for the d810 shell tooling.
#
# Extracted from run_system_tests_docker.sh so warm_gate.sh resolves the same
# values from the same file. Loading is NON-OVERRIDING: a variable already
# present in the environment always wins over the .env entry, so callers can
# still override per-invocation. Overrides are reported on stderr.
#
# Safe under "set -u": the bookkeeping globals are initialised here.
#
# Usage:
#   . "$(dirname "$0")/lib/dotenv.sh"
#   _load_dotenv_non_overriding "$REPO_ROOT/.env" || exit 1

DOTENV_LOADED_KEYS=""
ENV_OVERRIDE_TRACED_KEYS=""

_trim_whitespace() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

_display_env_value() {
  local name="$1"
  local value="$2"
  case "$name" in
    *TOKEN*|*KEY*|*SECRET*|*PASSWORD*|*CREDENTIAL*) printf '<redacted>' ;;
    *) printf '%s' "$value" ;;
  esac
}

_trace_override() {
  local name="$1"
  local value="$2"
  local source="$3"
  local displaced_source="$4"
  local displaced_value="$5"
  printf '[env] %s=%s source=%s, overrides %s=%s\n' \
    "$name" \
    "$(_display_env_value "$name" "$value")" \
    "$source" \
    "$displaced_source" \
    "$(_display_env_value "$name" "$displaced_value")"
  ENV_OVERRIDE_TRACED_KEYS="$ENV_OVERRIDE_TRACED_KEYS $name"
}

_load_dotenv_non_overriding() {
  local path="$1"
  local raw line assignment name value current line_number=0
  [ -f "$path" ] || return 0

  while IFS= read -r raw || [ -n "$raw" ]; do
    line_number=$((line_number + 1))
    raw="${raw%$'\r'}"
    line="$(_trim_whitespace "$raw")"
    case "$line" in
      ""|\#*) continue ;;
      export[[:space:]]*) assignment="$(_trim_whitespace "${line#export}")" ;;
      *) assignment="$line" ;;
    esac

    if [[ ! "$assignment" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
      echo "ERROR: $path:$line_number: malformed entry" >&2
      return 1
    fi
    name="${assignment%%=*}"
    value="$(_trim_whitespace "${assignment#*=}")"
    case "$value" in
      \"*)
        if [ "${value%\"}" = "$value" ] || [ "${#value}" -lt 2 ]; then
          echo "ERROR: $path:$line_number: unterminated double quote" >&2
          return 1
        fi
        value="${value:1:${#value}-2}"
        ;;
      \'*)
        if [ "${value%\'}" = "$value" ] || [ "${#value}" -lt 2 ]; then
          echo "ERROR: $path:$line_number: unterminated single quote" >&2
          return 1
        fi
        value="${value:1:${#value}-2}"
        ;;
    esac

    if printenv "$name" >/dev/null 2>&1; then
      current="$(printenv "$name")"
      if [ "$current" != "$value" ]; then
        _trace_override "$name" "$current" "process environment" ".env" "$value"
      fi
    else
      export "$name=$value"
      DOTENV_LOADED_KEYS="$DOTENV_LOADED_KEYS $name"
    fi
  done < "$path"
}
