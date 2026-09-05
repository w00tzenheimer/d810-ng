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
# line, each argument shell-quoted (`printf %q`) so a multi-word value
# (e.g. -k "a or b") is visibly one word rather than four, and exits 0
# without running anything.
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
# Do not "simplify" it back to a bare "${EXTRA_ARGS[@]}". `${#arr[@]}` and
# indexed access `${arr[$i]}` ARE nounset-safe on an empty array on bash
# 3.2 (verified) and are used below for the option-grammar walk.
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
      if [ "$#" -lt 2 ]; then
        echo "run_unit_tests.sh: -n/--numprocesses requires a value" >&2
        exit 2
      fi
      WORKERS="$2"
      shift 2
      ;;
    --dist)
      if [ "$#" -lt 2 ]; then
        echo "run_unit_tests.sh: --dist requires a value" >&2
        exit 2
      fi
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
# Classify by OPTION GRAMMAR, never by filesystem state (ticket d81-4tsd,
# re-review 1): a token that is the value of a preceding value-taking
# option is never positional, regardless of what it names -- including
# when that value happens to collide with a real path in this repo (e.g.
# "-k tests", "-k docs"). review-1's fix used `[ -e ... ]`, which "solved"
# the original "-k foo" case but still misclassified any -k/--maxfail/etc.
# value that happened to name an existing top-level entry (docs, src,
# tests, build, samples, resources, rule-tests, conftest.py, ...). A
# positional is a token that does NOT start with "-" and was NOT consumed
# as a value by a preceding option.
#
# Known value-taking short options (a following separate token is that
# option's value; -x is a flag, not one of these):
#   -k -m -n -p -o -W -c
# Known value-taking long options:
#   --dist --durations --durations-min --maxfail --tb --rootdir --timeout
#   --junitxml --deselect --ignore --ignore-glob --confcutdir --basetemp
#   --log-level --log-file
# A glued "--opt=value" or short "-kexpr"/"-n4" form is a single token: it
# starts with "-" (never positional) and never consumes the next token
# (its value, if any, is already glued in).
# An unrecognised "--long" option with no "=" is assumed value-less only
# if the NEXT token also starts with "-" (or there is no next token);
# otherwise the next token is assumed to be its value and is consumed
# (never treated as positional). This can swallow a genuine positional
# immediately after an actually-value-less unknown flag -- an accepted,
# documented tradeoff, since the alternative (assuming value-less) is the
# one this whole fix exists to eliminate: silently treating an option's
# value as a target.
HAS_POSITIONAL=0
EXTRA_COUNT=${#EXTRA_ARGS[@]}
i=0
while [ "$i" -lt "$EXTRA_COUNT" ]; do
  arg="${EXTRA_ARGS[$i]}"
  case "$arg" in
    --*=*)
      ;;
    -k|-m|-n|-p|-o|-W|-c|--dist|--durations|--durations-min|--maxfail|--tb|\
--rootdir|--timeout|--junitxml|--deselect|--ignore|--ignore-glob|\
--confcutdir|--basetemp|--log-level|--log-file)
      i=$((i + 1))
      ;;
    --*)
      next_i=$((i + 1))
      if [ "$next_i" -lt "$EXTRA_COUNT" ]; then
        case "${EXTRA_ARGS[$next_i]}" in
          -*) ;;
          *) i=$next_i ;;
        esac
      fi
      ;;
    -*)
      ;;
    *)
      HAS_POSITIONAL=1
      ;;
  esac
  i=$((i + 1))
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
  printf -v quoted_pythonpath '%q' "$RESOLVED_PYTHONPATH"
  printf 'PYTHONPATH=%s pyenv exec python -m pytest' "$quoted_pythonpath"
  for a in "${PYTEST_ARGS[@]}"; do
    printf -v quoted_arg '%q' "$a"
    printf ' %s' "$quoted_arg"
  done
  printf '\n'
  exit 0
fi

export PYTHONPATH="$RESOLVED_PYTHONPATH"
exec pyenv exec python -m pytest "${PYTEST_ARGS[@]}"
