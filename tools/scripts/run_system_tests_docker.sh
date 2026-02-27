#!/bin/bash
# Run d810 system tests or pseudocode dump in a local Docker image.
# Paths are repo-relative; no host-specific paths.
#
# Usage:
#   ./run_system_tests_docker.sh system [--worktree REL_PATH]
#   ./run_system_tests_docker.sh dump [OPTIONS] [-- PYTEST_ARGS...]
#
# Commands:
#   system    Run full system tests: pytest tests/system
#   dump      Run dump pseudocode e2e test (optionally with --dump-function-pseudocode, etc.)
#
# Options for dump:
#   -f, --function NAME     Pass --dump-function-pseudocode NAME
#   -m, --maturity LIST     Pass --dump-microcode-maturity LIST (comma-separated)
#   -p, --project NAME      Pass --dump-project NAME (JSON project name)
#   -o, --out FILE          Redirect stdout+stderr to FILE under work dir .tmp/
#   -w, --worktree REL      Use worktree at REPO_ROOT/WORKTREE_ROOT/REL as /work (WORKTREE_ROOT defaults to .worktrees)
#   -l, --logs              Mount .tmp/logs at /root/.idapro/logs
#   --                      Remaining args passed to pytest
#
# Environment:
#   D810_DOCKER_IMAGE       Docker image (default: idapro-9.3)
#   D810_REPO_ROOT          Repo root (default: git rev-parse --show-toplevel from cwd)
#   D810_WORKTREE_ROOT      Dir under repo root for worktrees (default: .worktrees)
#   D810_NO_CYTHON          If set, passed into container (e.g. 1)
#   D810_TEST_BINARY        Passed into container (e.g. libobfuscated.dll)
#
# Examples:
#   ./run_system_tests_docker.sh system
#   ./run_system_tests_docker.sh dump -f sub_7FFD3338C040 -m LOCOPT,CALLS,GLBOPT1,GLBOPT2 -p hodur_flag2.json -o hodur_flag2_dump.txt
#   ./run_system_tests_docker.sh dump -f AntiDebug_ExceptionFilter -p example_libobfuscated.json -o antidebug_dump4.txt -w verifycpp-on-ngcfgpass -l
set -e

DOCKER_IMAGE="${D810_DOCKER_IMAGE:-idapro-9.3}"

# Repo root: env or git from current dir (script may be run from repo root or tools/scripts)
if [ -n "${D810_REPO_ROOT}" ]; then
  REPO_ROOT="${D810_REPO_ROOT}"
else
  REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || true
  if [ -z "${REPO_ROOT}" ]; then
    echo "ERROR: Not inside a git repo and D810_REPO_ROOT not set." >&2
    exit 1
  fi
fi
REPO_ROOT="$(cd "$REPO_ROOT" && pwd)"

CMD="${1:-}"
shift || true
if [ "$CMD" != "system" ] && [ "$CMD" != "dump" ]; then
  echo "Usage: $0 system [--worktree REL] | dump [OPTIONS] [-- PYTEST_ARGS...]" >&2
  echo "Commands: system | dump" >&2
  exit 1
fi

WORK_DIR="$REPO_ROOT"
WORKTREE_ROOT="${D810_WORKTREE_ROOT:-.worktrees}"
WORKTREE_REL=""
DUMP_FUNCTION=""
DUMP_MATURITY=""
DUMP_PROJECT=""
DUMP_OUT=""
MOUNT_LOGS=""
EXTRA_PYTEST=()

while [ $# -gt 0 ]; do
  case "$1" in
    -w|--worktree)
      WORKTREE_REL="$2"
      shift 2
      ;;
    -f|--function)
      DUMP_FUNCTION="$2"
      shift 2
      ;;
    -m|--maturity)
      DUMP_MATURITY="$2"
      shift 2
      ;;
    -p|--project)
      DUMP_PROJECT="$2"
      shift 2
      ;;
    -o|--out)
      DUMP_OUT="$2"
      shift 2
      ;;
    -l|--logs)
      MOUNT_LOGS=1
      shift
      ;;
    --)
      shift
      EXTRA_PYTEST=("$@")
      break
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [ -n "$WORKTREE_REL" ]; then
  WORK_DIR="$REPO_ROOT/$WORKTREE_ROOT/$WORKTREE_REL"
  if [ ! -d "$WORK_DIR" ]; then
    echo "ERROR: Worktree not found: $WORK_DIR" >&2
    exit 1
  fi
fi

# Inside container: work dir is always /work; src is either /work/src or worktree src
if [ -n "$WORKTREE_REL" ]; then
  PYWORK="/work/src"
else
  PYWORK="/work/src"
fi

# Docker mount: host path -> container path (use variables so no host-specific paths in printed commands)
VOL_WORK="-v ${WORK_DIR}:/work"
VOL_LOGS=""
if [ -n "$MOUNT_LOGS" ]; then
  LOGS_DIR="${WORK_DIR}/.tmp/logs"
  mkdir -p "$LOGS_DIR"
  VOL_LOGS="-v ${LOGS_DIR}:/root/.idapro/logs"
fi

ENV_IDA="IDA_PREFIX=/app/ida IDA_INSTALL_DIR=/app/ida D810_LIBCLANG_PATH=/app/ida/libclang.so"
ENV_PYTHON="PYTHONPATH=${PYWORK}:/app/ida/python:\$PYTHONPATH"
ENV_TEST="D810_NO_CYTHON=${D810_NO_CYTHON:-1} D810_TEST_BINARY=${D810_TEST_BINARY:-libobfuscated.dll}"

run_bash() {
  local inner="$1"
  docker run --rm \
    $VOL_WORK \
    $VOL_LOGS \
    -w /work \
    --entrypoint /bin/bash "$DOCKER_IMAGE" -lc "$inner"
}

if [ "$CMD" = "system" ]; then
  run_bash "export $ENV_IDA $ENV_PYTHON
    /app/ida/.venv/bin/pip install -e .[dev] -q
    /app/ida/.venv/bin/python -m d810.speedups.install
    $ENV_TEST /app/ida/.venv/bin/python -m pytest tests/system -v"
  exit 0
fi

# dump
PYTEST_CMD="/app/ida/.venv/bin/python -m pytest -s tests/system/e2e/test_dump_function_pseudocode.py"
DUMP_ARGS=()
[ -n "$DUMP_FUNCTION" ] && DUMP_ARGS+=(--dump-function-pseudocode "$DUMP_FUNCTION")
[ -n "$DUMP_MATURITY" ] && DUMP_ARGS+=(--dump-microcode-maturity "$DUMP_MATURITY")
[ -n "$DUMP_PROJECT" ]  && DUMP_ARGS+=(--dump-project "$DUMP_PROJECT")
[ ${#EXTRA_PYTEST[@]} -gt 0 ] && DUMP_ARGS+=("${EXTRA_PYTEST[@]}")

REDIR=""
TRUNCATE_CMD=""
if [ -n "$DUMP_OUT" ]; then
  mkdir -p "${WORK_DIR}/.tmp"
  LOG_PATH="/work/.tmp/${DUMP_OUT}"
  TRUNCATE_CMD=": > \"$LOG_PATH\"; "
  REDIR="> \"$LOG_PATH\" 2>&1"
fi

INNER="export $ENV_IDA $ENV_PYTHON
  $TRUNCATE_CMD/app/ida/.venv/bin/pip install -e .[dev] -q
  /app/ida/.venv/bin/python -m d810.speedups.install
  $ENV_TEST $PYTEST_CMD ${DUMP_ARGS[*]} -v $REDIR"
run_bash "$INNER"
