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
#   tools/scripts/run_unit_tests.sh -n auto --dist load
#   tools/scripts/run_unit_tests.sh -n 4 --dist load
#
# Any remaining arguments (a node id, -k EXPR, -x, etc.) are passed through
# to pytest unchanged, e.g. to reproduce a single parallel-only failure
# together with the file/tests suspected of poisoning it:
#   tools/scripts/run_unit_tests.sh -n 2 --dist loadfile tests/unit/some_test.py
#
# --dry-run prints the resolved PYTHONPATH and `pytest` invocation as one
# line and exits 0 without running anything.
#
# Usage:
#   tools/scripts/run_unit_tests.sh [-n N|auto] [--dist load|loadfile|...] \
#       [--dry-run] [PYTEST_ARGS...]
#
# NOTE (ticket d81-4tsd, review 1, C1): this script must stay correct under
# bash 3.2 (macOS ships that as /bin/bash; it predates the bash 4.4
# exemption that lets "${arr[@]}" expand safely under `set -u` when arr is
# empty -- referencing it directly throws "unbound variable"). Every
# expansion of EXTRA_ARGS below therefore uses the
# ${arr[@]+"${arr[@]}"} idiom, which works on bash 3.2 through current.
# Do not "simplify" it back to a bare "${EXTRA_ARGS[@]}".
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

WORKERS=""
DIST=""
DRY_RUN=0
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
    --dry-run)
      DRY_RUN=1
      shift
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
#
# A flag's own VALUE (e.g. the "foo" in "-k foo", or the "3" in
# "--maxfail 3") is not a path and does not start with "-" either, so
# "does not start with -" is not a safe positional test (ticket d81-4tsd
# review 1, I3): it misclassified every bare-value pass-through flag as a
# target, which silently dropped tests/unit and let pytest's
# testpaths = ["tests"] fall back to collecting tests/system too. Test
# for an existing file/dir instead, stripping a trailing
# "::Class::test" node-id suffix first so
# "path/to/test.py::TestX::test_y" still counts as a real target.
HAS_POSITIONAL=0
for arg in ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}; do
  if [ -e "${arg%%::*}" ]; then
    HAS_POSITIONAL=1
  fi
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

PYTEST_ARGS+=(${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"})

RESOLVED_PYTHONPATH="src:tests${PYTHONPATH:+:$PYTHONPATH}"

if [ "$DRY_RUN" -eq 1 ]; then
  printf 'PYTHONPATH=%s pyenv exec python -m pytest' "$RESOLVED_PYTHONPATH"
  for a in "${PYTEST_ARGS[@]}"; do
    printf ' %s' "$a"
  done
  printf '\n'
  exit 0
fi

export PYTHONPATH="$RESOLVED_PYTHONPATH"
exec pyenv exec python -m pytest "${PYTEST_ARGS[@]}"
