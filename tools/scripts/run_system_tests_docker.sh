#!/bin/bash
# Run d810 system tests or pseudocode dump in a local Docker image.
# Paths are repo-relative; no host-specific paths.
#
# Usage:
#   ./run_system_tests_docker.sh system [OPTIONS] [-- PYTEST_ARGS...]
#   ./run_system_tests_docker.sh dump [OPTIONS] [-- PYTEST_ARGS...]
#   ./run_system_tests_docker.sh shell [OPTIONS]
#   ./run_system_tests_docker.sh exec [OPTIONS] -- COMMAND [ARGS...]
#
# Commands:
#   system    Run SETUP then: pytest tests/system -v [PYTEST_ARGS...]
#   dump      Run SETUP then: pytest -s tests/system/e2e/test_dump_function_pseudocode.py [OPTIONS]
#   shell     Run SETUP then start an interactive bash (docker run -it)
#   exec      Run SETUP then exec COMMAND with ARGS (e.g. exec -- python -c 'print(1)' or exec -- bash -c '...')
#
# SETUP (same for all commands): export IDA/PYTHONPATH env, pip install -e .[dev], python -m d810.speedups.install
#
# Options (system/shell/exec):
#   -w, --worktree REL      Use worktree at REPO_ROOT/WORKTREE_ROOT/REL as /work. REL is relative to
#                           WORKTREE_ROOT (default .worktrees). If your worktree is under a different
#                           root (e.g. .claude/worktrees/agent-foo), set D810_WORKTREE_ROOT and pass
#                           only the relative part: D810_WORKTREE_ROOT=.claude/worktrees -w agent-foo.
#   -l, --logs              Mount work dir .tmp/logs at /root/.idapro/logs
#   -o, --out FILE          (system only) Redirect stdout+stderr to WORK_DIR/.tmp/FILE. Use a relative
#                           filename (e.g. out.txt), not an absolute path; the script prepends .tmp/.
#   --                      Remaining args passed to pytest (system only) or used as command separator (exec)
#
# Options (dump only):
#   -f, --function NAME     Pass --dump-function-pseudocode NAME
#   -m, --maturity LIST     Pass --dump-microcode-maturity LIST (comma-separated)
#   -p, --project NAME      Pass --dump-project NAME (JSON project name)
#   -o, --out FILE          Redirect stdout+stderr to WORK_DIR/.tmp/FILE; truncated each run. Use a
#                           relative filename (e.g. dump.txt), not an absolute path; the script prepends .tmp/.
#   --                      Remaining args passed to pytest (e.g. --dump-microcode-d810, --dump-terminal-return-valranges, --dump-microcode-maturity MATURITY)
#
# Options (exec): same as system/shell; then -- COMMAND [ARGS...] to run after SETUP (required).
#
# Inside the container:
#   CMD=system|dump|shell|exec   Current command (also set for shell/exec so scripts can branch)
#   PYTHON=/app/ida/.venv/bin/python   Venv Python interpreter
#   PIP=/app/ida/.venv/bin/pip         Venv pip
#   IDA_PREFIX, IDA_INSTALL_DIR, D810_LIBCLANG_PATH, PYTHONPATH, D810_NO_CYTHON, D810_TEST_BINARY  Set for tests
#
# Environment (host):
#   D810_DOCKER_IMAGE       Docker image (default: idapro-9.3)
#   D810_REPO_ROOT         Repo root (default: git rev-parse --show-toplevel from cwd)
#   D810_WORKTREE_ROOT     Dir under repo root for worktrees (default: .worktrees)
#   D810_NO_CYTHON         Passed into container (default: 1)
#   D810_TEST_BINARY       Passed into container (default: libobfuscated.dll)
#
# Examples:
#   ./run_system_tests_docker.sh system
#   ./run_system_tests_docker.sh system -w my-worktree
#   ./run_system_tests_docker.sh shell
#   ./run_system_tests_docker.sh shell -w verifycpp-on-ngFlowGraphTransform -l
#   ./run_system_tests_docker.sh exec -- python -c 'print("hello world")'
#   ./run_system_tests_docker.sh exec -- bash -c 'echo hi && $PYTHON -m pytest tests/unit/ -v'
#   ./run_system_tests_docker.sh dump -f sub_7FFD3338C040 -m LOCOPT,CALLS,GLBOPT1,GLBOPT2 -p hodur_flag2.json -o hodur_flag2_dump.txt
#   ./run_system_tests_docker.sh dump -f AntiDebug_ExceptionFilter -p example_libobfuscated.json -o antidebug_dump4.txt -w verifycpp-on-ngFlowGraphTransform -l
#
# Dump examples (hodur_flag2 / hodur_func):
#   ./run_system_tests_docker.sh dump -f sub_7FFD3338C040 -p hodur_flag2.json -o sub7FFD_docker_fresh_$(date +%Y%m%d%H%M%S).txt -l
#   ./run_system_tests_docker.sh dump -f hodur_func -p example_hodur.json -o hodur_func_baseline_$(date +%Y%m%d%H%M%S).txt -l
#   (with worktree under .claude/worktrees): D810_WORKTREE_ROOT=.claude/worktrees ./run_system_tests_docker.sh dump -w agent-xyz -f sub_7FFD3338C040 -p hodur_flag2.json -o sub7FFD_$(date +%Y%m%d%H%M%S).txt -l
#   (dump post-d810 microcode and terminal return valranges; pass after --):
#   ./run_system_tests_docker.sh dump -f sub_7FFD3338C040 -p hodur_flag2.json -o sub7FFD_full_$(date +%Y%m%d%H%M%S).txt -l -- --dump-microcode-d810 --dump-terminal-return-valranges --dump-microcode-maturity LOCOPT,CALLS,GLBOPT1
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
if [ "$CMD" != "system" ] && [ "$CMD" != "dump" ] && [ "$CMD" != "shell" ] && [ "$CMD" != "exec" ]; then
  if [ "$CMD" = "-h" ] || [ "$CMD" = "--help" ]; then
    sed -n '2,/^set -e$/p' "$0" | sed '$d'
    exit 0
  fi
  echo "Usage: $0 system | dump [OPTIONS] [-- PYTEST_ARGS...] | shell | exec [OPTIONS] -- COMMAND [ARGS...]" >&2
  echo "Commands: system | dump | shell | exec" >&2
  echo "Run with --help for full help." >&2
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
EXEC_ARGS=()

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
      if [ "$CMD" = "exec" ]; then
        EXEC_ARGS=("$@")
      else
        EXTRA_PYTEST=("$@")
      fi
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

# Plan: print what we're about to do so agents see worktree, output path, and options
echo "$0 plan:"
echo "  command: $CMD"
if [ -n "$WORKTREE_REL" ]; then
  echo "  worktree: $WORK_DIR (WORKTREE_ROOT=$WORKTREE_ROOT, REL=$WORKTREE_REL)"
else
  echo "  worktree: $WORK_DIR (repo root)"
fi
if [ -n "$DUMP_OUT" ]; then
  echo "  output:   stdout+stderr -> $WORK_DIR/.tmp/$DUMP_OUT"
fi
if [ -n "$MOUNT_LOGS" ]; then
  echo "  logs:     $LOGS_DIR -> /root/.idapro/logs in container"
fi
case "$CMD" in
  system) echo "  run:      pytest tests/system -v${EXTRA_PYTEST[*]:+ ${EXTRA_PYTEST[*]}}" ;;
  dump)
    echo "  run:      pytest test_dump_function_pseudocode.py"
    [ -n "$DUMP_FUNCTION" ] && echo "  function: $DUMP_FUNCTION"
    [ -n "$DUMP_PROJECT" ]  && echo "  project:  $DUMP_PROJECT"
    [ -n "$DUMP_MATURITY" ] && echo "  maturity: $DUMP_MATURITY"
    [ ${#EXTRA_PYTEST[@]} -gt 0 ] && echo "  extra:    ${EXTRA_PYTEST[*]}"
    ;;
  exec) echo "  exec:     ${EXEC_ARGS[*]}" ;;
  shell) echo "  run:      interactive shell" ;;
esac
echo ""

ENV_IDA="IDA_PREFIX=/app/ida IDA_INSTALL_DIR=/app/ida D810_LIBCLANG_PATH=/app/ida/libclang.so"
ENV_PYTHON="PYTHONPATH=${PYWORK}:/app/ida/python:\$PYTHONPATH"
ENV_TEST="D810_NO_CYTHON=${D810_NO_CYTHON:-1} D810_TEST_BINARY=${D810_TEST_BINARY:-libobfuscated.dll}"

IDA_VENV_PIP="/app/ida/.venv/bin/pip"
IDA_VENV_PYTHON="/app/ida/.venv/bin/python"

# One-time setup: export env, pip install -e .[dev], d810.speedups.install
SETUP_CMD="export $ENV_IDA $ENV_PYTHON && $IDA_VENV_PIP install -e .[dev] -q && $IDA_VENV_PYTHON -m d810.speedups.install"

run_bash() {
  local inner="$1"
  docker run --rm \
    $VOL_WORK \
    $VOL_LOGS \
    -w /work \
    --entrypoint /bin/bash "$DOCKER_IMAGE" -lc "$inner"
}

run_bash_it() {
  local inner="$1"
  docker run -it --rm \
    $VOL_WORK \
    $VOL_LOGS \
    -w /work \
    -e "CMD=$CMD" \
    -e "PYTHON=$IDA_VENV_PYTHON" \
    -e "PIP=$IDA_VENV_PIP" \
    -e "D810_NO_CYTHON=${D810_NO_CYTHON:-1}" \
    -e "D810_TEST_BINARY=${D810_TEST_BINARY:-libobfuscated.dll}" \
    --entrypoint /bin/bash "$DOCKER_IMAGE" -lc "$inner"
}

run_bash_exec() {
  local inner="$SETUP_CMD && exec \"\$@\""
  docker run --rm \
    $VOL_WORK \
    $VOL_LOGS \
    -w /work \
    -e "CMD=exec" \
    -e "PYTHON=$IDA_VENV_PYTHON" \
    -e "PIP=$IDA_VENV_PIP" \
    -e "D810_NO_CYTHON=${D810_NO_CYTHON:-1}" \
    -e "D810_TEST_BINARY=${D810_TEST_BINARY:-libobfuscated.dll}" \
    --entrypoint /bin/bash "$DOCKER_IMAGE" -lc "$inner" -- "${EXEC_ARGS[@]}"
}

if [ "$CMD" = "system" ]; then
  SYSTEM_ARGS=()
  [ ${#EXTRA_PYTEST[@]} -gt 0 ] && SYSTEM_ARGS+=("${EXTRA_PYTEST[@]}")
  SYS_REDIR=""
  SYS_TRUNCATE=""
  if [ -n "$DUMP_OUT" ]; then
    mkdir -p "${WORK_DIR}/.tmp"
    SYS_LOG="/work/.tmp/${DUMP_OUT}"
    SYS_TRUNCATE=": > \"$SYS_LOG\"; "
    SYS_REDIR="> \"$SYS_LOG\" 2>&1"
  fi
  run_bash "$SETUP_CMD && ${SYS_TRUNCATE}$ENV_TEST $IDA_VENV_PYTHON -m pytest tests/system -v ${SYSTEM_ARGS[*]} $SYS_REDIR"
  exit 0
fi

if [ "$CMD" = "shell" ]; then
  run_bash_it "$SETUP_CMD && exec bash"
  exit 0
fi

if [ "$CMD" = "exec" ]; then
  if [ ${#EXEC_ARGS[@]} -eq 0 ]; then
    echo "ERROR: exec requires a command after -- (e.g. $0 exec -- python -c 'print(1)')" >&2
    exit 1
  fi
  run_bash_exec
  exit 0
fi

# dump
PYTEST="$IDA_VENV_PYTHON -m pytest"
PYTEST_DUMP="$PYTEST -s tests/system/e2e/test_dump_function_pseudocode.py"
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

INNER="$SETUP_CMD && ${TRUNCATE_CMD}$ENV_TEST $PYTEST_DUMP ${DUMP_ARGS[*]} -v $REDIR"
run_bash "$INNER"
