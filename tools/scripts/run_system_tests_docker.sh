#!/bin/bash
# Run d810 system tests or pseudocode dump in a local Docker image.
# Paths are repo-relative; no host-specific paths.
#
# Usage:
#   ./run_system_tests_docker.sh system [OPTIONS] [-- PYTEST_ARGS...]
#   ./run_system_tests_docker.sh test [OPTIONS] [-- PYTEST_ARGS...]
#   ./run_system_tests_docker.sh dump [OPTIONS] [-- PYTEST_ARGS...]
#   ./run_system_tests_docker.sh shell [OPTIONS]
#   ./run_system_tests_docker.sh exec [OPTIONS] -- COMMAND [ARGS...]
#
# Commands:
#   system    Run SETUP then: pytest tests/system -v [PYTEST_ARGS...]
#   test      Run SETUP then: pytest -v [PYTEST_ARGS...] (all tests)
#   dump      Run SETUP then: pytest -s tests/system/e2e/test_dump_function_pseudocode.py [OPTIONS]
#   shell     Run SETUP then start an interactive bash (docker run -it)
#   exec      Run SETUP then exec COMMAND with ARGS (e.g. exec -- python -c 'print(1)' or exec -- bash -c '...')
#
# SETUP (same for all commands): export IDA/PYTHONPATH env, pip install -e .[dev], python -m d810.speedups.install
#
# Options (system/test/shell/exec):
#   -w, --worktree REL      Use worktree at REPO_ROOT/WORKTREE_ROOT/REL as /work. REL is relative to
#                           WORKTREE_ROOT (default .worktrees). If your worktree is under a different
#                           root (e.g. .claude/worktrees/agent-foo), set D810_WORKTREE_ROOT and pass
#                           only the relative part: D810_WORKTREE_ROOT=.claude/worktrees -w agent-foo.
#   -l, --logs              Mount work dir .tmp/logs at /root/.idapro/logs
#   -o, --out FILE          (system/test only) Redirect stdout+stderr to WORK_DIR/.tmp/FILE. Use a relative
#                           filename (e.g. out.txt), not an absolute path; the script prepends .tmp/.
#   --enable-debug-logging  Set D810_DEBUG_LOGGING=1 inside the container so getLogger uses DEBUG as
#                           the default level instead of INFO (explicit caller levels are unaffected).
#   --                      Remaining args passed to pytest (system/test) or used as command separator (exec)
#
# Options (dump only):
#   -f, --function NAME     Pass --dump-function-pseudocode NAME
#   -m, --maturity LIST     Pass --dump-microcode-maturity LIST (comma-separated)
#   -p, --project NAME      Pass --dump-project NAME (JSON project name)
#   -o, --out FILE          Redirect stdout+stderr to WORK_DIR/.tmp/FILE; truncated each run. Use a
#                           relative filename (e.g. dump.txt), not an absolute path; the script prepends .tmp/.
#   --enable-debug-logging  Set D810_DEBUG_LOGGING=1 inside the container (see system/shell/exec above).
#   --                      Remaining args passed to pytest (e.g. --dump-microcode-d810, --dump-terminal-return-valranges, --dump-microcode-maturity MATURITY)
#
# Options (exec): same as system/shell; then -- COMMAND [ARGS...] to run after SETUP (required).
#
# Inside the container:
#   CMD=system|test|dump|shell|exec   Current command (also set for shell/exec so scripts can branch)
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
#   D810_DOCKER_MEMORY      Memory limit for container (default: 4g). OOM-kills if exceeded.
#
# Examples:
#   ./run_system_tests_docker.sh system
#   ./run_system_tests_docker.sh system -w my-worktree
#   (explicit repo root, e.g. when not cwd in repo): D810_REPO_ROOT=/path/to/d810 ./run_system_tests_docker.sh system -w recon-lifecycle
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
DOCKER_MEMORY="${D810_DOCKER_MEMORY:-4g}"

# Convert memory string (e.g., "20g", "4G", "512m") to bytes for RLIMIT_DATA enforcement.
# Docker --memory is NOT enforced on macOS Docker Desktop; resource.setrlimit IS enforced
# inside the container.
_mem_to_bytes() {
  local val="${1%[gGmMkK]}"
  local unit="${1: -1}"
  case "$unit" in
    g|G) echo $(( val * 1073741824 )) ;;
    m|M) echo $(( val * 1048576 )) ;;
    k|K) echo $(( val * 1024 )) ;;
    *)   echo "$1" ;;
  esac
}
MEMORY_BYTES=$(_mem_to_bytes "$DOCKER_MEMORY")

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
if [ "$CMD" != "system" ] && [ "$CMD" != "test" ] && [ "$CMD" != "dump" ] && [ "$CMD" != "shell" ] && [ "$CMD" != "exec" ]; then
  if [ "$CMD" = "-h" ] || [ "$CMD" = "--help" ]; then
    sed -n '2,/^set -e$/p' "$0" | sed '$d'
    exit 0
  fi
  echo "Usage: $0 system | test | dump [OPTIONS] [-- PYTEST_ARGS...] | shell | exec [OPTIONS] -- COMMAND [ARGS...]" >&2
  echo "Commands: system | test | dump | shell | exec" >&2
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
ENABLE_DEBUG_LOGGING=""
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
    --enable-debug-logging)
      ENABLE_DEBUG_LOGGING=1
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
if [ -n "$ENABLE_DEBUG_LOGGING" ]; then
  echo "  debug:    D810_DEBUG_LOGGING=1 (getLogger default level -> DEBUG)"
fi
case "$CMD" in
  system) echo "  run:      pytest tests/system -v${EXTRA_PYTEST[*]:+ ${EXTRA_PYTEST[*]}}" ;;
  test)   echo "  run:      pytest -v${EXTRA_PYTEST[*]:+ ${EXTRA_PYTEST[*]}}" ;;
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
[ -n "${D810_DIAG_SNAPSHOT:-}" ] && ENV_TEST="$ENV_TEST D810_DIAG_SNAPSHOT=$D810_DIAG_SNAPSHOT"
[ -n "${D810_TERMINAL_TAIL_SPLITTER:-}" ] && ENV_TEST="$ENV_TEST D810_TERMINAL_TAIL_SPLITTER=$D810_TERMINAL_TAIL_SPLITTER"
[ -n "${D810_LOOP_CARRIER_BACKEDGE_REFRESH:-}" ] && ENV_TEST="$ENV_TEST D810_LOOP_CARRIER_BACKEDGE_REFRESH=$D810_LOOP_CARRIER_BACKEDGE_REFRESH"
[ -n "${D810_TAIL_DISTINCT_BYTE:-}" ] && ENV_TEST="$ENV_TEST D810_TAIL_DISTINCT_BYTE=$D810_TAIL_DISTINCT_BYTE"
if [ -n "$ENABLE_DEBUG_LOGGING" ]; then
  ENV_TEST="$ENV_TEST D810_DEBUG_LOGGING=1 D810_DIAG_SNAPSHOT=1 D810_FACT_LIFECYCLE=${D810_FACT_LIFECYCLE:-1}"
fi

IDA_VENV_PIP="/app/ida/.venv/bin/pip"
IDA_VENV_PYTHON="/app/ida/.venv/bin/python"

# One-time setup: export env, pip install -e .[dev], d810.speedups.install
SETUP_CMD="export $ENV_IDA $ENV_PYTHON && $IDA_VENV_PIP install -e .[dev] -q && $IDA_VENV_PYTHON -m d810.speedups.install"

run_bash() {
  local inner="$1"
  local extra_env=""
  [ -n "${D810_BISECT_SKIP:-}" ] && extra_env="-e D810_BISECT_SKIP=$D810_BISECT_SKIP"
  [ -n "${D810_EXACT_NODE_EDGE_START:-}" ] && extra_env="$extra_env -e D810_EXACT_NODE_EDGE_START=$D810_EXACT_NODE_EDGE_START"
  [ -n "${D810_EXACT_NODE_EDGE_STOP:-}" ] && extra_env="$extra_env -e D810_EXACT_NODE_EDGE_STOP=$D810_EXACT_NODE_EDGE_STOP"
  [ -n "${D810_RECON_RELAX_LATECLONE_SHARED_BLOCKS:-}" ] && extra_env="$extra_env -e D810_RECON_RELAX_LATECLONE_SHARED_BLOCKS=$D810_RECON_RELAX_LATECLONE_SHARED_BLOCKS"
  [ -n "${D810_RECON_FORCE_KEEP_PER_PRED_SHARED_BLOCKS:-}" ] && extra_env="$extra_env -e D810_RECON_FORCE_KEEP_PER_PRED_SHARED_BLOCKS=$D810_RECON_FORCE_KEEP_PER_PRED_SHARED_BLOCKS"
  [ -n "${D810_RECON_FORCE_CLONE_PRIMARY_SHARED_BLOCKS:-}" ] && extra_env="$extra_env -e D810_RECON_FORCE_CLONE_PRIMARY_SHARED_BLOCKS=$D810_RECON_FORCE_CLONE_PRIMARY_SHARED_BLOCKS"
  [ -n "${D810_RECON_PRESERVE_EXACT_SIDE_EFFECT_CORRIDORS:-}" ] && extra_env="$extra_env -e D810_RECON_PRESERVE_EXACT_SIDE_EFFECT_CORRIDORS=$D810_RECON_PRESERVE_EXACT_SIDE_EFFECT_CORRIDORS"
  [ -n "${D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS:-}" ] && extra_env="$extra_env -e D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS=$D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS"
  [ -n "${D810_HODUR_RETURN_FRONTIER_CARRIER_PRESERVE:-}" ] && extra_env="$extra_env -e D810_HODUR_RETURN_FRONTIER_CARRIER_PRESERVE=$D810_HODUR_RETURN_FRONTIER_CARRIER_PRESERVE"
  [ -n "${D810_RECON_DEBUG_INTRA_CORRIDOR:-}" ] && extra_env="$extra_env -e D810_RECON_DEBUG_INTRA_CORRIDOR=$D810_RECON_DEBUG_INTRA_CORRIDOR"
  [ -n "${D810_RECON_DEBUG_CORRIDOR_BLOCKS:-}" ] && extra_env="$extra_env -e D810_RECON_DEBUG_CORRIDOR_BLOCKS=$D810_RECON_DEBUG_CORRIDOR_BLOCKS"
  [ -n "${D810_RECON_RETURN_FRONTIER_CARRIER_AUDIT:-}" ] && extra_env="$extra_env -e D810_RECON_RETURN_FRONTIER_CARRIER_AUDIT=$D810_RECON_RETURN_FRONTIER_CARRIER_AUDIT"
  [ -n "${D810_CAPTURE_POST_MATURITY:-}" ] && extra_env="$extra_env -e D810_CAPTURE_POST_MATURITY=$D810_CAPTURE_POST_MATURITY"
  [ -n "${D810_RECON_ROUND_CTX_PROBE:-}" ] && extra_env="$extra_env -e D810_RECON_ROUND_CTX_PROBE=$D810_RECON_ROUND_CTX_PROBE"
  [ -n "${D810_RECON_SKIP_PRIMARY:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_PRIMARY=$D810_RECON_SKIP_PRIMARY"
  [ -n "${D810_RECON_SKIP_FRONTIER:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_FRONTIER=$D810_RECON_SKIP_FRONTIER"
  [ -n "${D810_RECON_SKIP_FORCE_EDGE:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_FORCE_EDGE=$D810_RECON_SKIP_FORCE_EDGE"
  [ -n "${D810_RECON_SKIP_NARROW_BRANCH_LOCAL:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_NARROW_BRANCH_LOCAL=$D810_RECON_SKIP_NARROW_BRANCH_LOCAL"
  [ -n "${D810_RECON_ENABLE_STANDALONE_SRW:-}" ] && extra_env="$extra_env -e D810_RECON_ENABLE_STANDALONE_SRW=$D810_RECON_ENABLE_STANDALONE_SRW"
  [ -n "${D810_RECON_SKIP_SRW_STRATEGY:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_SRW_STRATEGY=$D810_RECON_SKIP_SRW_STRATEGY"
  [ -n "${D810_RECON_SKIP_MISSING_VIA_PRED:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_MISSING_VIA_PRED=$D810_RECON_SKIP_MISSING_VIA_PRED"
  [ -n "${D810_RECON_SKIP_RESIDUAL_ALIAS:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_RESIDUAL_ALIAS=$D810_RECON_SKIP_RESIDUAL_ALIAS"
  [ -n "${D810_RECON_SKIP_ISLAND_RESCUE:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_ISLAND_RESCUE=$D810_RECON_SKIP_ISLAND_RESCUE"
  [ -n "${D810_HODUR_ONLY:-}" ] && extra_env="$extra_env -e D810_HODUR_ONLY=$D810_HODUR_ONLY"
  [ -n "${D810_HODUR_SKIP:-}" ] && extra_env="$extra_env -e D810_HODUR_SKIP=$D810_HODUR_SKIP"
  [ -n "${D810_HODUR_ENABLE_TRAMPOLINE_SKIP:-}" ] && extra_env="$extra_env -e D810_HODUR_ENABLE_TRAMPOLINE_SKIP=$D810_HODUR_ENABLE_TRAMPOLINE_SKIP"
  [ -n "${D810_HODUR_ENABLE_SPURIOUS_REDIRECT:-}" ] && extra_env="$extra_env -e D810_HODUR_ENABLE_SPURIOUS_REDIRECT=$D810_HODUR_ENABLE_SPURIOUS_REDIRECT"
  [ -n "${D810_ENABLE_HANDLER_CHAIN_COMPOSER:-}" ] && extra_env="$extra_env -e D810_ENABLE_HANDLER_CHAIN_COMPOSER=$D810_ENABLE_HANDLER_CHAIN_COMPOSER"
  [ -n "${D810_HCC_REGION_FUSION:-}" ] && extra_env="$extra_env -e D810_HCC_REGION_FUSION=$D810_HCC_REGION_FUSION"
  [ -n "${D810_HCC_EXPERIMENTAL_CONVERGENCE_DUPLICATION:-}" ] && extra_env="$extra_env -e D810_HCC_EXPERIMENTAL_CONVERGENCE_DUPLICATION=$D810_HCC_EXPERIMENTAL_CONVERGENCE_DUPLICATION"
  [ -n "${D810_HCC_TAIL_EXTENSION:-}" ] && extra_env="$extra_env -e D810_HCC_TAIL_EXTENSION=$D810_HCC_TAIL_EXTENSION"
  [ -n "${D810_HCC_TAIL_EXTENSION_SKIP_REF236:-}" ] && extra_env="$extra_env -e D810_HCC_TAIL_EXTENSION_SKIP_REF236=$D810_HCC_TAIL_EXTENSION_SKIP_REF236"
  [ -n "${D810_HCC_CALL_BARRIER:-}" ] && extra_env="$extra_env -e D810_HCC_CALL_BARRIER=$D810_HCC_CALL_BARRIER"
  [ -n "${D810_HCC_CHAINED_GUARDED_SOURCE:-}" ] && extra_env="$extra_env -e D810_HCC_CHAINED_GUARDED_SOURCE=$D810_HCC_CHAINED_GUARDED_SOURCE"
  [ -n "${D810_HCC_USE_DEF_VETO:-}" ] && extra_env="$extra_env -e D810_HCC_USE_DEF_VETO=$D810_HCC_USE_DEF_VETO"
  [ -n "${D810_LFG_BOUNDED_POSTPROCESS:-}" ] && extra_env="$extra_env -e D810_LFG_BOUNDED_POSTPROCESS=$D810_LFG_BOUNDED_POSTPROCESS"
  [ -n "${D810_DEFERRED_WATCH_BLOCKS:-}" ] && extra_env="$extra_env -e D810_DEFERRED_WATCH_BLOCKS=$D810_DEFERRED_WATCH_BLOCKS"
  [ -n "${D810_DEFERRED_DIAG_PHASES:-}" ] && extra_env="$extra_env -e D810_DEFERRED_DIAG_PHASES=$D810_DEFERRED_DIAG_PHASES"
  [ -n "${D810_DIAG_FULL_COVERAGE_CHAIN:-}" ] && extra_env="$extra_env -e D810_DIAG_FULL_COVERAGE_CHAIN=$D810_DIAG_FULL_COVERAGE_CHAIN"
  [ -n "${D810_PREFER_DIRECT_FOR_TRANSITION:-}" ] && extra_env="$extra_env -e D810_PREFER_DIRECT_FOR_TRANSITION=$D810_PREFER_DIRECT_FOR_TRANSITION"
  [ -n "${D810_DEFERRED_TRANSACTIONAL:-}" ] && extra_env="$extra_env -e D810_DEFERRED_TRANSACTIONAL=$D810_DEFERRED_TRANSACTIONAL"
  [ -n "${D810_DEFERRED_STAGED_ATOMIC:-}" ] && extra_env="$extra_env -e D810_DEFERRED_STAGED_ATOMIC=$D810_DEFERRED_STAGED_ATOMIC"
  [ -n "${D810_TRACE_REDIRECT_GOTO_CONSTRUCTION:-}" ] && extra_env="$extra_env -e D810_TRACE_REDIRECT_GOTO_CONSTRUCTION=$D810_TRACE_REDIRECT_GOTO_CONSTRUCTION"
  [ -n "${D810_TRACE_MOD_CONSTRUCTION:-}" ] && extra_env="$extra_env -e D810_TRACE_MOD_CONSTRUCTION=$D810_TRACE_MOD_CONSTRUCTION"
  [ -n "${D810_FENCE_INSN_OPT_AT_GLBOPT1:-}" ] && extra_env="$extra_env -e D810_FENCE_INSN_OPT_AT_GLBOPT1=$D810_FENCE_INSN_OPT_AT_GLBOPT1"
  [ -n "${D810_FORCE_BLK129_TO_BLK130:-}" ] && extra_env="$extra_env -e D810_FORCE_BLK129_TO_BLK130=$D810_FORCE_BLK129_TO_BLK130"
  docker run --rm \
    --add-host files.pythonhosted.org:151.101.0.223 \
    --memory "$DOCKER_MEMORY" \
    -e "D810_MEMORY_LIMIT_BYTES=$MEMORY_BYTES" \
    $extra_env \
    $VOL_WORK \
    $VOL_LOGS \
    -w /work \
    --entrypoint /bin/bash "$DOCKER_IMAGE" -lc "$inner"
}

run_bash_it() {
  local inner="$1"
  local extra_env=""
  [ -n "${D810_EXACT_NODE_EDGE_START:-}" ] && extra_env="$extra_env -e D810_EXACT_NODE_EDGE_START=$D810_EXACT_NODE_EDGE_START"
  [ -n "${D810_EXACT_NODE_EDGE_STOP:-}" ] && extra_env="$extra_env -e D810_EXACT_NODE_EDGE_STOP=$D810_EXACT_NODE_EDGE_STOP"
  [ -n "${D810_RECON_RELAX_LATECLONE_SHARED_BLOCKS:-}" ] && extra_env="$extra_env -e D810_RECON_RELAX_LATECLONE_SHARED_BLOCKS=$D810_RECON_RELAX_LATECLONE_SHARED_BLOCKS"
  [ -n "${D810_RECON_FORCE_KEEP_PER_PRED_SHARED_BLOCKS:-}" ] && extra_env="$extra_env -e D810_RECON_FORCE_KEEP_PER_PRED_SHARED_BLOCKS=$D810_RECON_FORCE_KEEP_PER_PRED_SHARED_BLOCKS"
  [ -n "${D810_RECON_FORCE_CLONE_PRIMARY_SHARED_BLOCKS:-}" ] && extra_env="$extra_env -e D810_RECON_FORCE_CLONE_PRIMARY_SHARED_BLOCKS=$D810_RECON_FORCE_CLONE_PRIMARY_SHARED_BLOCKS"
  [ -n "${D810_RECON_PRESERVE_EXACT_SIDE_EFFECT_CORRIDORS:-}" ] && extra_env="$extra_env -e D810_RECON_PRESERVE_EXACT_SIDE_EFFECT_CORRIDORS=$D810_RECON_PRESERVE_EXACT_SIDE_EFFECT_CORRIDORS"
  [ -n "${D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS:-}" ] && extra_env="$extra_env -e D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS=$D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS"
  [ -n "${D810_HODUR_RETURN_FRONTIER_CARRIER_PRESERVE:-}" ] && extra_env="$extra_env -e D810_HODUR_RETURN_FRONTIER_CARRIER_PRESERVE=$D810_HODUR_RETURN_FRONTIER_CARRIER_PRESERVE"
  [ -n "${D810_RECON_DEBUG_INTRA_CORRIDOR:-}" ] && extra_env="$extra_env -e D810_RECON_DEBUG_INTRA_CORRIDOR=$D810_RECON_DEBUG_INTRA_CORRIDOR"
  [ -n "${D810_RECON_DEBUG_CORRIDOR_BLOCKS:-}" ] && extra_env="$extra_env -e D810_RECON_DEBUG_CORRIDOR_BLOCKS=$D810_RECON_DEBUG_CORRIDOR_BLOCKS"
  [ -n "${D810_RECON_RETURN_FRONTIER_CARRIER_AUDIT:-}" ] && extra_env="$extra_env -e D810_RECON_RETURN_FRONTIER_CARRIER_AUDIT=$D810_RECON_RETURN_FRONTIER_CARRIER_AUDIT"
  [ -n "${D810_CAPTURE_POST_MATURITY:-}" ] && extra_env="$extra_env -e D810_CAPTURE_POST_MATURITY=$D810_CAPTURE_POST_MATURITY"
  [ -n "${D810_RECON_ROUND_CTX_PROBE:-}" ] && extra_env="$extra_env -e D810_RECON_ROUND_CTX_PROBE=$D810_RECON_ROUND_CTX_PROBE"
  [ -n "${D810_RECON_SKIP_PRIMARY:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_PRIMARY=$D810_RECON_SKIP_PRIMARY"
  [ -n "${D810_RECON_SKIP_FRONTIER:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_FRONTIER=$D810_RECON_SKIP_FRONTIER"
  [ -n "${D810_RECON_SKIP_FORCE_EDGE:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_FORCE_EDGE=$D810_RECON_SKIP_FORCE_EDGE"
  [ -n "${D810_RECON_SKIP_NARROW_BRANCH_LOCAL:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_NARROW_BRANCH_LOCAL=$D810_RECON_SKIP_NARROW_BRANCH_LOCAL"
  [ -n "${D810_RECON_ENABLE_STANDALONE_SRW:-}" ] && extra_env="$extra_env -e D810_RECON_ENABLE_STANDALONE_SRW=$D810_RECON_ENABLE_STANDALONE_SRW"
  [ -n "${D810_RECON_SKIP_SRW_STRATEGY:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_SRW_STRATEGY=$D810_RECON_SKIP_SRW_STRATEGY"
  [ -n "${D810_RECON_SKIP_MISSING_VIA_PRED:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_MISSING_VIA_PRED=$D810_RECON_SKIP_MISSING_VIA_PRED"
  [ -n "${D810_RECON_SKIP_RESIDUAL_ALIAS:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_RESIDUAL_ALIAS=$D810_RECON_SKIP_RESIDUAL_ALIAS"
  [ -n "${D810_RECON_SKIP_ISLAND_RESCUE:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_ISLAND_RESCUE=$D810_RECON_SKIP_ISLAND_RESCUE"
  [ -n "${D810_HODUR_ONLY:-}" ] && extra_env="$extra_env -e D810_HODUR_ONLY=$D810_HODUR_ONLY"
  [ -n "${D810_HODUR_SKIP:-}" ] && extra_env="$extra_env -e D810_HODUR_SKIP=$D810_HODUR_SKIP"
  [ -n "${D810_HODUR_ENABLE_TRAMPOLINE_SKIP:-}" ] && extra_env="$extra_env -e D810_HODUR_ENABLE_TRAMPOLINE_SKIP=$D810_HODUR_ENABLE_TRAMPOLINE_SKIP"
  [ -n "${D810_HODUR_ENABLE_SPURIOUS_REDIRECT:-}" ] && extra_env="$extra_env -e D810_HODUR_ENABLE_SPURIOUS_REDIRECT=$D810_HODUR_ENABLE_SPURIOUS_REDIRECT"
  [ -n "${D810_ENABLE_HANDLER_CHAIN_COMPOSER:-}" ] && extra_env="$extra_env -e D810_ENABLE_HANDLER_CHAIN_COMPOSER=$D810_ENABLE_HANDLER_CHAIN_COMPOSER"
  [ -n "${D810_HCC_REGION_FUSION:-}" ] && extra_env="$extra_env -e D810_HCC_REGION_FUSION=$D810_HCC_REGION_FUSION"
  [ -n "${D810_HCC_EXPERIMENTAL_CONVERGENCE_DUPLICATION:-}" ] && extra_env="$extra_env -e D810_HCC_EXPERIMENTAL_CONVERGENCE_DUPLICATION=$D810_HCC_EXPERIMENTAL_CONVERGENCE_DUPLICATION"
  [ -n "${D810_HCC_TAIL_EXTENSION:-}" ] && extra_env="$extra_env -e D810_HCC_TAIL_EXTENSION=$D810_HCC_TAIL_EXTENSION"
  [ -n "${D810_HCC_TAIL_EXTENSION_SKIP_REF236:-}" ] && extra_env="$extra_env -e D810_HCC_TAIL_EXTENSION_SKIP_REF236=$D810_HCC_TAIL_EXTENSION_SKIP_REF236"
  [ -n "${D810_HCC_CALL_BARRIER:-}" ] && extra_env="$extra_env -e D810_HCC_CALL_BARRIER=$D810_HCC_CALL_BARRIER"
  [ -n "${D810_HCC_CHAINED_GUARDED_SOURCE:-}" ] && extra_env="$extra_env -e D810_HCC_CHAINED_GUARDED_SOURCE=$D810_HCC_CHAINED_GUARDED_SOURCE"
  [ -n "${D810_HCC_USE_DEF_VETO:-}" ] && extra_env="$extra_env -e D810_HCC_USE_DEF_VETO=$D810_HCC_USE_DEF_VETO"
  [ -n "${D810_LFG_BOUNDED_POSTPROCESS:-}" ] && extra_env="$extra_env -e D810_LFG_BOUNDED_POSTPROCESS=$D810_LFG_BOUNDED_POSTPROCESS"
  [ -n "${D810_DEFERRED_WATCH_BLOCKS:-}" ] && extra_env="$extra_env -e D810_DEFERRED_WATCH_BLOCKS=$D810_DEFERRED_WATCH_BLOCKS"
  [ -n "${D810_DEFERRED_DIAG_PHASES:-}" ] && extra_env="$extra_env -e D810_DEFERRED_DIAG_PHASES=$D810_DEFERRED_DIAG_PHASES"
  [ -n "${D810_DIAG_FULL_COVERAGE_CHAIN:-}" ] && extra_env="$extra_env -e D810_DIAG_FULL_COVERAGE_CHAIN=$D810_DIAG_FULL_COVERAGE_CHAIN"
  [ -n "${D810_PREFER_DIRECT_FOR_TRANSITION:-}" ] && extra_env="$extra_env -e D810_PREFER_DIRECT_FOR_TRANSITION=$D810_PREFER_DIRECT_FOR_TRANSITION"
  [ -n "${D810_DEFERRED_TRANSACTIONAL:-}" ] && extra_env="$extra_env -e D810_DEFERRED_TRANSACTIONAL=$D810_DEFERRED_TRANSACTIONAL"
  [ -n "${D810_DEFERRED_STAGED_ATOMIC:-}" ] && extra_env="$extra_env -e D810_DEFERRED_STAGED_ATOMIC=$D810_DEFERRED_STAGED_ATOMIC"
  [ -n "${D810_TRACE_REDIRECT_GOTO_CONSTRUCTION:-}" ] && extra_env="$extra_env -e D810_TRACE_REDIRECT_GOTO_CONSTRUCTION=$D810_TRACE_REDIRECT_GOTO_CONSTRUCTION"
  [ -n "${D810_TRACE_MOD_CONSTRUCTION:-}" ] && extra_env="$extra_env -e D810_TRACE_MOD_CONSTRUCTION=$D810_TRACE_MOD_CONSTRUCTION"
  [ -n "${D810_FENCE_INSN_OPT_AT_GLBOPT1:-}" ] && extra_env="$extra_env -e D810_FENCE_INSN_OPT_AT_GLBOPT1=$D810_FENCE_INSN_OPT_AT_GLBOPT1"
  [ -n "${D810_FORCE_BLK129_TO_BLK130:-}" ] && extra_env="$extra_env -e D810_FORCE_BLK129_TO_BLK130=$D810_FORCE_BLK129_TO_BLK130"
  docker run -it --rm \
    --memory "$DOCKER_MEMORY" \
    -e "D810_MEMORY_LIMIT_BYTES=$MEMORY_BYTES" \
    $extra_env \
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
  local inner="export $ENV_TEST && $SETUP_CMD && exec \"\$@\""
  local extra_env=""
  [ -n "${D810_EXACT_NODE_EDGE_START:-}" ] && extra_env="$extra_env -e D810_EXACT_NODE_EDGE_START=$D810_EXACT_NODE_EDGE_START"
  [ -n "${D810_EXACT_NODE_EDGE_STOP:-}" ] && extra_env="$extra_env -e D810_EXACT_NODE_EDGE_STOP=$D810_EXACT_NODE_EDGE_STOP"
  [ -n "${D810_RECON_RELAX_LATECLONE_SHARED_BLOCKS:-}" ] && extra_env="$extra_env -e D810_RECON_RELAX_LATECLONE_SHARED_BLOCKS=$D810_RECON_RELAX_LATECLONE_SHARED_BLOCKS"
  [ -n "${D810_RECON_FORCE_KEEP_PER_PRED_SHARED_BLOCKS:-}" ] && extra_env="$extra_env -e D810_RECON_FORCE_KEEP_PER_PRED_SHARED_BLOCKS=$D810_RECON_FORCE_KEEP_PER_PRED_SHARED_BLOCKS"
  [ -n "${D810_RECON_FORCE_CLONE_PRIMARY_SHARED_BLOCKS:-}" ] && extra_env="$extra_env -e D810_RECON_FORCE_CLONE_PRIMARY_SHARED_BLOCKS=$D810_RECON_FORCE_CLONE_PRIMARY_SHARED_BLOCKS"
  [ -n "${D810_RECON_PRESERVE_EXACT_SIDE_EFFECT_CORRIDORS:-}" ] && extra_env="$extra_env -e D810_RECON_PRESERVE_EXACT_SIDE_EFFECT_CORRIDORS=$D810_RECON_PRESERVE_EXACT_SIDE_EFFECT_CORRIDORS"
  [ -n "${D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS:-}" ] && extra_env="$extra_env -e D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS=$D810_HODUR_PRESERVE_TERMINAL_BYTE_CORRIDORS"
  [ -n "${D810_HODUR_RETURN_FRONTIER_CARRIER_PRESERVE:-}" ] && extra_env="$extra_env -e D810_HODUR_RETURN_FRONTIER_CARRIER_PRESERVE=$D810_HODUR_RETURN_FRONTIER_CARRIER_PRESERVE"
  [ -n "${D810_RECON_DEBUG_INTRA_CORRIDOR:-}" ] && extra_env="$extra_env -e D810_RECON_DEBUG_INTRA_CORRIDOR=$D810_RECON_DEBUG_INTRA_CORRIDOR"
  [ -n "${D810_RECON_DEBUG_CORRIDOR_BLOCKS:-}" ] && extra_env="$extra_env -e D810_RECON_DEBUG_CORRIDOR_BLOCKS=$D810_RECON_DEBUG_CORRIDOR_BLOCKS"
  [ -n "${D810_RECON_RETURN_FRONTIER_CARRIER_AUDIT:-}" ] && extra_env="$extra_env -e D810_RECON_RETURN_FRONTIER_CARRIER_AUDIT=$D810_RECON_RETURN_FRONTIER_CARRIER_AUDIT"
  [ -n "${D810_CAPTURE_POST_MATURITY:-}" ] && extra_env="$extra_env -e D810_CAPTURE_POST_MATURITY=$D810_CAPTURE_POST_MATURITY"
  [ -n "${D810_RECON_ROUND_CTX_PROBE:-}" ] && extra_env="$extra_env -e D810_RECON_ROUND_CTX_PROBE=$D810_RECON_ROUND_CTX_PROBE"
  [ -n "${D810_RECON_SKIP_PRIMARY:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_PRIMARY=$D810_RECON_SKIP_PRIMARY"
  [ -n "${D810_RECON_SKIP_FRONTIER:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_FRONTIER=$D810_RECON_SKIP_FRONTIER"
  [ -n "${D810_RECON_SKIP_FORCE_EDGE:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_FORCE_EDGE=$D810_RECON_SKIP_FORCE_EDGE"
  [ -n "${D810_RECON_SKIP_NARROW_BRANCH_LOCAL:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_NARROW_BRANCH_LOCAL=$D810_RECON_SKIP_NARROW_BRANCH_LOCAL"
  [ -n "${D810_RECON_ENABLE_STANDALONE_SRW:-}" ] && extra_env="$extra_env -e D810_RECON_ENABLE_STANDALONE_SRW=$D810_RECON_ENABLE_STANDALONE_SRW"
  [ -n "${D810_RECON_SKIP_SRW_STRATEGY:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_SRW_STRATEGY=$D810_RECON_SKIP_SRW_STRATEGY"
  [ -n "${D810_RECON_SKIP_MISSING_VIA_PRED:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_MISSING_VIA_PRED=$D810_RECON_SKIP_MISSING_VIA_PRED"
  [ -n "${D810_RECON_SKIP_RESIDUAL_ALIAS:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_RESIDUAL_ALIAS=$D810_RECON_SKIP_RESIDUAL_ALIAS"
  [ -n "${D810_RECON_SKIP_ISLAND_RESCUE:-}" ] && extra_env="$extra_env -e D810_RECON_SKIP_ISLAND_RESCUE=$D810_RECON_SKIP_ISLAND_RESCUE"
  [ -n "${D810_HODUR_ONLY:-}" ] && extra_env="$extra_env -e D810_HODUR_ONLY=$D810_HODUR_ONLY"
  [ -n "${D810_HODUR_SKIP:-}" ] && extra_env="$extra_env -e D810_HODUR_SKIP=$D810_HODUR_SKIP"
  [ -n "${D810_HODUR_ENABLE_TRAMPOLINE_SKIP:-}" ] && extra_env="$extra_env -e D810_HODUR_ENABLE_TRAMPOLINE_SKIP=$D810_HODUR_ENABLE_TRAMPOLINE_SKIP"
  [ -n "${D810_HODUR_ENABLE_SPURIOUS_REDIRECT:-}" ] && extra_env="$extra_env -e D810_HODUR_ENABLE_SPURIOUS_REDIRECT=$D810_HODUR_ENABLE_SPURIOUS_REDIRECT"
  [ -n "${D810_ENABLE_HANDLER_CHAIN_COMPOSER:-}" ] && extra_env="$extra_env -e D810_ENABLE_HANDLER_CHAIN_COMPOSER=$D810_ENABLE_HANDLER_CHAIN_COMPOSER"
  [ -n "${D810_HCC_REGION_FUSION:-}" ] && extra_env="$extra_env -e D810_HCC_REGION_FUSION=$D810_HCC_REGION_FUSION"
  [ -n "${D810_HCC_EXPERIMENTAL_CONVERGENCE_DUPLICATION:-}" ] && extra_env="$extra_env -e D810_HCC_EXPERIMENTAL_CONVERGENCE_DUPLICATION=$D810_HCC_EXPERIMENTAL_CONVERGENCE_DUPLICATION"
  [ -n "${D810_HCC_TAIL_EXTENSION:-}" ] && extra_env="$extra_env -e D810_HCC_TAIL_EXTENSION=$D810_HCC_TAIL_EXTENSION"
  [ -n "${D810_HCC_TAIL_EXTENSION_SKIP_REF236:-}" ] && extra_env="$extra_env -e D810_HCC_TAIL_EXTENSION_SKIP_REF236=$D810_HCC_TAIL_EXTENSION_SKIP_REF236"
  [ -n "${D810_HCC_CALL_BARRIER:-}" ] && extra_env="$extra_env -e D810_HCC_CALL_BARRIER=$D810_HCC_CALL_BARRIER"
  [ -n "${D810_HCC_CHAINED_GUARDED_SOURCE:-}" ] && extra_env="$extra_env -e D810_HCC_CHAINED_GUARDED_SOURCE=$D810_HCC_CHAINED_GUARDED_SOURCE"
  [ -n "${D810_HCC_USE_DEF_VETO:-}" ] && extra_env="$extra_env -e D810_HCC_USE_DEF_VETO=$D810_HCC_USE_DEF_VETO"
  [ -n "${D810_LFG_BOUNDED_POSTPROCESS:-}" ] && extra_env="$extra_env -e D810_LFG_BOUNDED_POSTPROCESS=$D810_LFG_BOUNDED_POSTPROCESS"
  [ -n "${D810_DEFERRED_WATCH_BLOCKS:-}" ] && extra_env="$extra_env -e D810_DEFERRED_WATCH_BLOCKS=$D810_DEFERRED_WATCH_BLOCKS"
  [ -n "${D810_DEFERRED_DIAG_PHASES:-}" ] && extra_env="$extra_env -e D810_DEFERRED_DIAG_PHASES=$D810_DEFERRED_DIAG_PHASES"
  [ -n "${D810_DIAG_FULL_COVERAGE_CHAIN:-}" ] && extra_env="$extra_env -e D810_DIAG_FULL_COVERAGE_CHAIN=$D810_DIAG_FULL_COVERAGE_CHAIN"
  [ -n "${D810_PREFER_DIRECT_FOR_TRANSITION:-}" ] && extra_env="$extra_env -e D810_PREFER_DIRECT_FOR_TRANSITION=$D810_PREFER_DIRECT_FOR_TRANSITION"
  [ -n "${D810_DEFERRED_TRANSACTIONAL:-}" ] && extra_env="$extra_env -e D810_DEFERRED_TRANSACTIONAL=$D810_DEFERRED_TRANSACTIONAL"
  [ -n "${D810_DEFERRED_STAGED_ATOMIC:-}" ] && extra_env="$extra_env -e D810_DEFERRED_STAGED_ATOMIC=$D810_DEFERRED_STAGED_ATOMIC"
  [ -n "${D810_TRACE_REDIRECT_GOTO_CONSTRUCTION:-}" ] && extra_env="$extra_env -e D810_TRACE_REDIRECT_GOTO_CONSTRUCTION=$D810_TRACE_REDIRECT_GOTO_CONSTRUCTION"
  [ -n "${D810_TRACE_MOD_CONSTRUCTION:-}" ] && extra_env="$extra_env -e D810_TRACE_MOD_CONSTRUCTION=$D810_TRACE_MOD_CONSTRUCTION"
  [ -n "${D810_FENCE_INSN_OPT_AT_GLBOPT1:-}" ] && extra_env="$extra_env -e D810_FENCE_INSN_OPT_AT_GLBOPT1=$D810_FENCE_INSN_OPT_AT_GLBOPT1"
  [ -n "${D810_FORCE_BLK129_TO_BLK130:-}" ] && extra_env="$extra_env -e D810_FORCE_BLK129_TO_BLK130=$D810_FORCE_BLK129_TO_BLK130"
  docker run --rm \
    --add-host files.pythonhosted.org:151.101.0.223 \
    --memory "$DOCKER_MEMORY" \
    -e "D810_MEMORY_LIMIT_BYTES=$MEMORY_BYTES" \
    $extra_env \
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

if [ "$CMD" = "test" ]; then
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
  run_bash "$SETUP_CMD && ${SYS_TRUNCATE}$ENV_TEST $IDA_VENV_PYTHON -m pytest -v ${SYSTEM_ARGS[*]} $SYS_REDIR"
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

# --- BEGIN region oracle hook (Track A.8 of uee-32r3) ---
# Non-fatal: any failure in the oracle is logged but never propagated.
ORACLE_DB="$(ls -t "${WORK_DIR}/.tmp/logs/d810_logs/"*.diag.sqlite3 2>/dev/null | head -1 || true)"
if [ -n "$ORACLE_DB" ]; then
  if [ -n "${DUMP_OUT:-}" ]; then
    ORACLE_BASE="${WORK_DIR}/.tmp/${DUMP_OUT%.txt}"
    ORACLE_OUT="${ORACLE_BASE}.oracle.md"
    ORACLE_ERR="${ORACLE_BASE}.oracle.stderr.log"
  else
    ORACLE_TS="$(date +%Y%m%d-%H%M%S)"
    ORACLE_OUT="${WORK_DIR}/.tmp/oracle_${ORACLE_TS}.oracle.md"
    ORACLE_ERR="${WORK_DIR}/.tmp/oracle_${ORACLE_TS}.oracle.stderr.log"
  fi
  if PYTHONPATH="${WORK_DIR}/src" python3 -m d810.core.diag region-diff \
      --auto --persist \
      --db "$ORACLE_DB" \
      --output "$ORACLE_OUT" \
      2> "$ORACLE_ERR"
  then
    echo "oracle written: $ORACLE_OUT"
  else
    echo "WARN: oracle exited non-zero; see $ORACLE_ERR"
  fi
else
  echo "oracle skipped: no diag DB present (run with --enable-debug-logging to capture one)"
fi
# --- END region oracle hook ---
