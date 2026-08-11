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
# SETUP (same for all commands): export IDA/PYTHONPATH env; install Python
# dependencies unless the image carries d810's baked-runtime label; optionally
# build native Cython speedups.
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
#   --enable-diag-snapshot  Set D810_DIAG_SNAPSHOT=1 inside the container.
#   --enable-llvm-opt       Opt-in only: install/probe LLVM opt in the container,
#                           export LLVM_OPT, and set D810_REQUIRE_LLVM_OPT=1.
#   --disable-fact-lifecycle
#                           Set D810_FACT_LIFECYCLE=0 inside the container.
#   --                      Remaining args passed to pytest (system/test) or used as command separator (exec)
#
# Options (dump only):
#   -f, --function NAME     Pass --dump-function-pseudocode NAME
#   -m, --maturity LIST     Pass --dump-microcode-maturity LIST (comma-separated)
#   -p, --project NAME      Pass --dump-project NAME (JSON project name)
#   -o, --out FILE          Redirect stdout+stderr to WORK_DIR/.tmp/FILE; truncated each run. Use a
#                           relative filename (e.g. dump.txt), not an absolute path; the script prepends .tmp/.
#   --enable-debug-logging  Set D810_DEBUG_LOGGING=1 inside the container (see system/shell/exec above).
#   --enable-diag-snapshot  Set D810_DIAG_SNAPSHOT=1 inside the container.
#   --disable-fact-lifecycle
#                           Set D810_FACT_LIFECYCLE=0 inside the container.
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
#   Precedence: exported process environment > repository .env > defaults.
#   When one source displaces another, the runner prints the winning source and
#   value. Sensitive values are redacted.
#   D810_DOCKER_IMAGE       Docker image (default: idapro-9.4)
#   D810_REPO_ROOT         Repo root (default: git rev-parse --show-toplevel from cwd)
#   D810_WORKTREE_ROOT     Dir under repo root for worktrees (default: .worktrees)
#   D810_NO_CYTHON         Passed into container (default: 1)
#   D810_TEST_BINARY       Passed into container (default: libobfuscated.dll)
#   D810_DOCKER_MEMORY      Memory limit for container (default: 4g). OOM-kills if exceeded.
#
# Examples:
#   ./run_system_tests_docker.sh system
#   ./run_system_tests_docker.sh system -w my-worktree
#   (explicit repo root, e.g. when not cwd in repo): D810_REPO_ROOT=/path/to/d810 ./run_system_tests_docker.sh system -w preanalysis-lifecycle
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

_trace_default_override() {
  local name="$1"
  local default="$2"
  local value source
  printenv "$name" >/dev/null 2>&1 || return 0
  value="$(printenv "$name")"
  [ "$value" != "$default" ] || return 0
  case " $ENV_OVERRIDE_TRACED_KEYS " in *" $name "*) return 0 ;; esac
  case " $DOTENV_LOADED_KEYS " in
    *" $name "*) source=".env" ;;
    *) source="process environment" ;;
  esac
  _trace_override "$name" "$value" "$source" "default" "$default"
}

if printenv D810_REPO_ROOT >/dev/null 2>&1; then
  DOTENV_ROOT="$D810_REPO_ROOT"
else
  DOTENV_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
fi
if [ -n "$DOTENV_ROOT" ]; then
  _load_dotenv_non_overriding "$DOTENV_ROOT/.env" || exit 1
fi

_trace_default_override D810_DOCKER_IMAGE idapro-9.4
_trace_default_override D810_DOCKER_MEMORY 4g
_trace_default_override D810_NO_CYTHON 1
_trace_default_override D810_TEST_BINARY libobfuscated.dll
_trace_default_override D810_WORKTREE_ROOT .worktrees

DOCKER_IMAGE="${D810_DOCKER_IMAGE-idapro-9.4}"
DOCKER_MEMORY="${D810_DOCKER_MEMORY-4g}"
NO_CYTHON="${D810_NO_CYTHON-1}"
TEST_BINARY="${D810_TEST_BINARY-libobfuscated.dll}"
[ -n "$DOCKER_IMAGE" ] || { echo "ERROR: D810_DOCKER_IMAGE is set but empty" >&2; exit 1; }
[ -n "$DOCKER_MEMORY" ] || { echo "ERROR: D810_DOCKER_MEMORY is set but empty" >&2; exit 1; }
RUNTIME_LABEL_KEY="org.d810.test-runtime"
RUNTIME_LABEL_VALUE="dev-emulation-z3-v1"

_image_has_baked_runtime() {
  [ "$(docker image inspect --format "{{ index .Config.Labels \"$RUNTIME_LABEL_KEY\" }}" "$DOCKER_IMAGE" 2>/dev/null || true)" = "$RUNTIME_LABEL_VALUE" ]
}

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
WORKTREE_ROOT="${D810_WORKTREE_ROOT-.worktrees}"
WORKTREE_REL=""
DUMP_FUNCTION=""
DUMP_MATURITY=""
DUMP_PROJECT=""
DUMP_OUT=""
MOUNT_LOGS=""
ENABLE_DEBUG_LOGGING=""
ENABLE_DIAG_SNAPSHOT=""
ENABLE_LLVM_OPT=""
DISABLE_FACT_LIFECYCLE=""
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
    --enable-diag-snapshot)
      ENABLE_DIAG_SNAPSHOT=1
      shift
      ;;
    --enable-llvm-opt)
      ENABLE_LLVM_OPT=1
      shift
      ;;
    --enable-fact-lifecycle)
      echo "ERROR: --enable-fact-lifecycle was removed because fact lifecycle is enabled by default." >&2
      echo "Use --disable-fact-lifecycle to turn it off." >&2
      exit 1
      ;;
    --disable-fact-lifecycle)
      DISABLE_FACT_LIFECYCLE=1
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
VOL_GIT=""
ENV_GIT=""
GIT_COMMON_DIR="$(git -C "$WORK_DIR" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || true)"
if [ -n "$GIT_COMMON_DIR" ] && [ -d "$GIT_COMMON_DIR" ]; then
  VOL_GIT="-v ${GIT_COMMON_DIR}:/d810-git:ro"
  ENV_GIT="GIT_DIR=/d810-git"
fi
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
if [ -n "$ENABLE_DIAG_SNAPSHOT" ]; then
  echo "  diag:     D810_DIAG_SNAPSHOT=1"
fi
if [ -n "$ENABLE_LLVM_OPT" ]; then
  echo "  llvm:     provisioning LLVM opt and requiring verification"
fi
if [ -n "$DISABLE_FACT_LIFECYCLE" ]; then
  echo "  facts:    D810_FACT_LIFECYCLE=0"
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
ENV_TEST="D810_NO_CYTHON=$NO_CYTHON D810_TEST_BINARY=$TEST_BINARY"
[ -n "${D810_DIAG_SNAPSHOT:-}" ] && ENV_TEST="$ENV_TEST D810_DIAG_SNAPSHOT=$D810_DIAG_SNAPSHOT"
[ -n "${D810_FACT_LIFECYCLE:-}" ] && ENV_TEST="$ENV_TEST D810_FACT_LIFECYCLE=$D810_FACT_LIFECYCLE"
[ -n "$ENABLE_DIAG_SNAPSHOT" ] && ENV_TEST="$ENV_TEST D810_DIAG_SNAPSHOT=1"
[ -n "$DISABLE_FACT_LIFECYCLE" ] && ENV_TEST="$ENV_TEST D810_FACT_LIFECYCLE=0"
if [ -n "$ENABLE_DEBUG_LOGGING" ]; then
  ENV_TEST="$ENV_TEST D810_DEBUG_LOGGING=1"
fi
if [ -n "$ENABLE_LLVM_OPT" ]; then
  ENV_TEST="$ENV_TEST D810_REQUIRE_LLVM_OPT=1"
fi

LLVM_OPT_SETUP=""
if [ -n "$ENABLE_LLVM_OPT" ]; then
  LLVM_OPT_SETUP='if ! command -v opt >/dev/null 2>&1; then apt-get update && apt-get install -y --no-install-recommends llvm; fi; LLVM_OPT_PATH="$(command -v opt || find /usr/lib/llvm-*/bin -name opt -type f -perm /111 2>/dev/null | sort -V | tail -1)"; if [ -z "$LLVM_OPT_PATH" ]; then echo "ERROR: --enable-llvm-opt could not find LLVM opt after provisioning" >&2; exit 1; fi; export LLVM_OPT="$LLVM_OPT_PATH"; echo "LLVM opt: $LLVM_OPT"; "$LLVM_OPT" --version | head -n 1'
fi

# Forward every set D810_* env var to the container via docker -e flags.
# Wrapper-only vars (those that only affect this script) are excluded.
_d810_extra_env_flags() {
  local _skip=" D810_DOCKER_IMAGE D810_DOCKER_MEMORY D810_REPO_ROOT D810_WORKTREE_ROOT D810_MEMORY_LIMIT_BYTES "
  local _out=""
  local _var _val
  for _var in ${!D810_@}; do
    case "$_skip" in
      *" $_var "*) continue ;;
    esac
    eval "_val=\${$_var}"
    [ -n "$_val" ] && _out="$_out -e $_var=$_val"
  done
  echo "$_out"
}

IDA_VENV_PIP="/app/ida/.venv/bin/pip"
IDA_VENV_PYTHON="/app/ida/.venv/bin/python"

# Per-container setup exports the runtime environment and installs dependencies
# when using an unlabelled base image. Images labelled as d810 test runtimes
# already contain dev, emulation, and isolated Z3 dependencies, so their install
# step is omitted. BEST-EFFORT Cython compilation remains independent and runs
# when explicitly enabled. The default D810_NO_CYTHON=1 must skip this build: an
# OOM kill of the build container cannot be caught by the shell's fallback.
# (instead of silently falling back to pure-Python). The build needs a C++
# toolchain + the IDA SDK; setup.py auto-downloads the SDK from GitHub when
# IDA_SDK is unset and links against the live IDA runtime (libida.so) via
# IDA_INSTALL_DIR. NOTE: do NOT pass --no-build-isolation — the IDA venv has
# neither setuptools nor Cython, so pip MUST build-isolate to install the
# build-system.requires (setuptools/wheel/Cython). If the build fails, the suite
# still runs on the pure-Python fallback — the '|| echo' below keeps exit 0.
if [ "$NO_CYTHON" = "1" ]; then
  SPEEDUPS_BUILD_CMD="echo '[speedups] native build disabled by D810_NO_CYTHON=1'"
else
  SPEEDUPS_BUILD_CMD="D810_BUILD_SPEEDUPS=1 $IDA_VENV_PIP install -e .[speedups] -q || echo '[speedups] build failed, falling back to pure-Python'"
fi
if _image_has_baked_runtime; then
  DEPENDENCY_SETUP="if $IDA_VENV_PYTHON -c 'import setuptools' >/dev/null 2>&1 && command -v git >/dev/null 2>&1; then echo '[setup] baked runtime dependencies detected; install skipped'; else echo '[setup] baked runtime is stale; refreshing declared test dependencies'; if ! command -v git >/dev/null 2>&1; then apt-get update && apt-get install -y --no-install-recommends git; fi; $IDA_VENV_PIP install -e '.[dev,emulation]' -q; fi"
else
  DEPENDENCY_SETUP="$IDA_VENV_PIP install -e '.[dev,emulation]' -q && $IDA_VENV_PYTHON -m d810.speedups.install"
fi
SETUP_CMD="$LLVM_OPT_SETUP${LLVM_OPT_SETUP:+ && }export $ENV_IDA $ENV_PYTHON $ENV_GIT && $DEPENDENCY_SETUP && { $SPEEDUPS_BUILD_CMD; }"

# Safely reassemble an array of args into a string suitable for embedding in
# a bash -c command that gets re-parsed by another shell (e.g. inside the
# container). Plain ${ARR[*]} flattens the array with a single space and no
# re-quoting, so any element containing whitespace (e.g. a multi-word
# `pytest -k "A or B"` filter) gets word-split again when the reconstructed
# string is parsed downstream. printf '%q' quotes each element so it
# round-trips as exactly one token.
_d810_quote_args() {
  local out="" arg
  for arg in "$@"; do
    out+="$(printf '%q ' "$arg")"
  done
  printf '%s' "$out"
}

run_bash() {
  local inner="$1"
  local extra_env="$(_d810_extra_env_flags)"
  docker run --rm \
    --add-host files.pythonhosted.org:151.101.0.223 \
    --memory "$DOCKER_MEMORY" \
    -e "D810_MEMORY_LIMIT_BYTES=$MEMORY_BYTES" \
    $extra_env \
    $VOL_WORK \
    $VOL_GIT \
    $VOL_LOGS \
    -w /work \
    --entrypoint /bin/bash "$DOCKER_IMAGE" -lc "$inner"
}

run_bash_it() {
  local inner="$1"
  local extra_env="$(_d810_extra_env_flags)"
  docker run -it --rm \
    --memory "$DOCKER_MEMORY" \
    -e "D810_MEMORY_LIMIT_BYTES=$MEMORY_BYTES" \
    $extra_env \
    $VOL_WORK \
    $VOL_GIT \
    $VOL_LOGS \
    -w /work \
    -e "CMD=$CMD" \
    -e "PYTHON=$IDA_VENV_PYTHON" \
    -e "PIP=$IDA_VENV_PIP" \
    -e "D810_NO_CYTHON=$NO_CYTHON" \
    -e "D810_TEST_BINARY=$TEST_BINARY" \
    --entrypoint /bin/bash "$DOCKER_IMAGE" -lc "$inner"
}

run_bash_exec() {
  local inner="export $ENV_TEST && $SETUP_CMD && exec \"\$@\""
  local extra_env="$(_d810_extra_env_flags)"
  docker run --rm \
    --add-host files.pythonhosted.org:151.101.0.223 \
    --memory "$DOCKER_MEMORY" \
    -e "D810_MEMORY_LIMIT_BYTES=$MEMORY_BYTES" \
    $extra_env \
    $VOL_WORK \
    $VOL_GIT \
    $VOL_LOGS \
    -w /work \
    -e "CMD=exec" \
    -e "PYTHON=$IDA_VENV_PYTHON" \
    -e "PIP=$IDA_VENV_PIP" \
    -e "D810_NO_CYTHON=$NO_CYTHON" \
    -e "D810_TEST_BINARY=$TEST_BINARY" \
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
  run_bash "$SETUP_CMD && ${SYS_TRUNCATE}$ENV_TEST $IDA_VENV_PYTHON -m pytest tests/system -v $(_d810_quote_args "${SYSTEM_ARGS[@]}") $SYS_REDIR"
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
  run_bash "$SETUP_CMD && ${SYS_TRUNCATE}$ENV_TEST $IDA_VENV_PYTHON -m pytest -v $(_d810_quote_args "${SYSTEM_ARGS[@]}") $SYS_REDIR"
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

INNER="$SETUP_CMD && ${TRUNCATE_CMD}$ENV_TEST $PYTEST_DUMP $(_d810_quote_args "${DUMP_ARGS[@]}") -v $REDIR"
run_bash "$INNER"
