#!/bin/bash
# tools/scripts/run_unit_tests.sh
#
# Thin wrapper around `pytest tests/unit` for the local developer loop.
#
# Serial behaviour is UNCHANGED: with no flags this runs exactly what
#   PYTHONPATH=src:tests pyenv exec python -m pytest tests/unit -p no:cacheprovider
# already runs. All addopts/markers from pyproject.toml (the
# "not profile and not pseudocode_dump and not manual and not slow and not
# rhad" deselection) apply unmodified -- parallelism is opt-in only.
#
# Parallel execution is opt-in via -n/--numprocesses (pytest-xdist),
# forwarded to pytest. --dist requires -n to be set (xdist only activates
# once -n is given); it defaults to "load" when -n is set and --dist is
# not. Measured starting points for this repo (see
# .superpowers/sdd/d81-4tsd-unit-xdist/task-1-report.md):
#   tools/scripts/run_unit_tests.sh -n auto --dist loadfile
#   tools/scripts/run_unit_tests.sh -n 4 --dist load
#
# Any remaining arguments (a node id, -k EXPR, -x, etc.) are passed through
# to pytest unchanged, e.g. to reproduce a single parallel-only failure
# together with the file/tests suspected of poisoning it:
#   tools/scripts/run_unit_tests.sh -n 2 --dist loadfile tests/unit/some_test.py
#
# Usage:
#   tools/scripts/run_unit_tests.sh [-n N|auto] [--dist load|loadfile|...] [PYTEST_ARGS...]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

WORKERS=""
DIST=""
EXTRA_ARGS=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    -n|--numprocesses)
      WORKERS="$2"
      shift 2
      ;;
    --dist)
      DIST="$2"
      shift 2
      ;;
    --)
      shift
      EXTRA_ARGS+=("$@")
      break
      ;;
    *)
      EXTRA_ARGS+=("$1")
      shift
      ;;
  esac
done

# Only default to the full tests/unit tree when the caller did not already
# name a path/node id of their own -- otherwise pytest would collect the
# union of "tests/unit" and the caller's target, i.e. always the whole
# suite, silently defeating a targeted reproduction run.
HAS_POSITIONAL=0
for arg in "${EXTRA_ARGS[@]}"; do
  case "$arg" in
    -*) ;;
    *) HAS_POSITIONAL=1 ;;
  esac
done

PYTEST_ARGS=(-p no:cacheprovider)
if [ "$HAS_POSITIONAL" -eq 0 ]; then
  PYTEST_ARGS+=(tests/unit)
fi

if [ -n "$WORKERS" ]; then
  PYTEST_ARGS+=(-n "$WORKERS" --dist "${DIST:-load}")
elif [ -n "$DIST" ]; then
  echo "run_unit_tests.sh: --dist given without -n/--numprocesses;" \
    "xdist only activates once -n is set" >&2
  exit 2
fi

PYTEST_ARGS+=("${EXTRA_ARGS[@]}")

export PYTHONPATH="src:tests${PYTHONPATH:+:$PYTHONPATH}"
exec pyenv exec python -m pytest "${PYTEST_ARGS[@]}"
