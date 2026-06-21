#!/usr/bin/env bash
# Run the explicit config-v2 CI rehearsal through the Docker system wrapper.
#
# Usage:
#   ./tools/scripts/run_config_v2_ci_rehearsal.sh [-w WORKTREE] [-o LOG] [-- PYTEST_ARGS...]
#
# Examples:
#   ./tools/scripts/run_config_v2_ci_rehearsal.sh
#   D810_REPO_ROOT=/path/to/d810 ./tools/scripts/run_config_v2_ci_rehearsal.sh -w <target-worktree>
#
# The job is reversible: unset D810_CONFIG_V2_CI_REHEARSAL, or set it to a
# disabled value, to return normal system tests to the existing project
# configuration path. This script always enables it for the rehearsal run.
# The rehearsal selector is part of the named job contract and cannot be
# overridden through passthrough pytest arguments.
set -euo pipefail

SELECTOR="TestConfigV2CIRehearsalCoverage"
OUT="logs/config-v2-ci-runtime-switch-rehearsal-coverage-v2.log"
WORKTREE=""
EXTRA_PYTEST=()

usage() {
  sed -n '2,/^set -euo pipefail$/p' "$0" | sed '$d'
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -w|--worktree)
      WORKTREE="${2:?missing value for $1}"
      shift 2
      ;;
    -o|--out)
      OUT="${2:?missing value for $1}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      EXTRA_PYTEST=("$@")
      break
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

for arg in "${EXTRA_PYTEST[@]}"; do
  case "$arg" in
    -k*|--keyword|--keyword=*)
      echo "ERROR: passthrough pytest args cannot override the fixed selector: $SELECTOR" >&2
      exit 2
      ;;
  esac
done

if [ -n "${D810_REPO_ROOT:-}" ]; then
  REPO_ROOT="$(cd "$D810_REPO_ROOT" && pwd)"
else
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
fi

RUNNER="$REPO_ROOT/tools/scripts/run_system_tests_docker.sh"
if [ ! -x "$RUNNER" ]; then
  echo "ERROR: Docker system wrapper is not executable: $RUNNER" >&2
  exit 1
fi

WRAPPER_ARGS=(system -l -o "$OUT")
if [ -n "$WORKTREE" ]; then
  WRAPPER_ARGS+=(-w "$WORKTREE")
fi

echo "config-v2 CI rehearsal job:"
echo "  env:      D810_CONFIG_V2_CI_REHEARSAL=1"
echo "  selector: $SELECTOR"
echo "  output:   .tmp/$OUT"

exec env D810_CONFIG_V2_CI_REHEARSAL=1 \
  "$RUNNER" "${WRAPPER_ARGS[@]}" -- -k "$SELECTOR" -s "${EXTRA_PYTEST[@]}"
