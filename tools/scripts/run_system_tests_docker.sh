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
# Native speedup builds can take several minutes. This runner waits for Docker
# to exit; when a host terminal or agent shows partial output, only the final
# [docker] completion line and exit status are authoritative.
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
#   --remote HOST           Run the container on a remote Linux Docker engine reached over SSH
#                           (DOCKER_HOST=ssh://HOST). Sources and artifacts stay on this Mac and are
#                           reached through the SMB-backed Docker volume named by D810_REMOTE_VOLUME:
#                           every host bind mount becomes --mount type=volume,volume-subpath=<path
#                           relative to D810_REMOTE_SHARE_ROOT>. Only ONE remote run per worktree is
#                           allowed at a time (lock: WORK_DIR/.tmp/remote-run.lock).
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
#   D810_CYTHON_PROFILE    Test-only Cython trace/profile build (requires D810_NO_CYTHON=0)
#   D810_NATIVE_PROFILE    Opt-in perf/py-spy tooling plus PERFMON/SYS_PTRACE (default: 0)
#   D810_TEST_BINARY       Passed into container (default: libobfuscated.dll)
#   D810_SYSTEM_BATCH_SIZE  Tests per fresh interpreter in system mode (default: 20).
#   D810_EGGLOG_ROOT       Optional absolute host path to a d810-egglog checkout
#   D810_COBRA_ROOT        Optional absolute host path to the pinned d810-cobra checkout
#   D810_COBRA_WHEEL       Optional absolute host path to a recorded prebuilt d810-cobra
#                          wheel (.whl). Installing it skips the in-container clone,
#                          toolchain install and C++ build entirely. Mutually exclusive
#                          with D810_COBRA_ROOT; requires D810_COBRA_WHEEL_SHA256. The
#                          accepted wheels are the PUBLISHED PyPI artifacts, kept in
#                          _gitless/resource/cobra-wheels/0.1.5-published/.
#   D810_COBRA_WHEEL_SHA256  Required with D810_COBRA_WHEEL: 64 lowercase hex characters.
#                          Must match both the bytes on disk and a wheel recorded in this
#                          script; an unrecorded wheel is rejected before any docker run.
#                          An identical filename does NOT imply identical bytes: the
#                          preflight builds in ../0.1.5-preflight/ carry the same names
#                          and sizes as the published wheels and are deliberately refused.
#   D810_DOCKER_MEMORY      Memory limit for container (default: 4g). OOM-kills if exceeded.
#   D810_REMOTE_DOCKER_HOST Remote engine host for --remote (the flag wins when both are given)
#   D810_REMOTE_VOLUME      Docker volume on the remote engine that exports the Mac's SMB share
#                           (default: idapro)
#   D810_REMOTE_SHARE_ROOT  Absolute host directory that the SMB share exports
#                           (default: /srv/share-root). Every mounted host path must live
#                           under it; the runner fails closed otherwise.
#
# Remote mode (one-time setup on the remote engine):
#   The volume is created once, by hand, on the machine that runs the containers:
#
#     read -rs -p 'SMB password for smbuser@smb-server.example: ' SMB_PW && echo && \
#     docker -H ssh://remote-engine.example volume create --driver local \
#       --opt type=cifs --opt device=//smb-server.example/idapro \
#       --opt "o=addr=smb-server.example,username=smbuser,password=${SMB_PW},vers=3.0,uid=0,gid=0,file_mode=0777,dir_mode=0777,nobrl,noperm" \
#       idapro; unset SMB_PW
#
#   All of those options are in-kernel cifs options (docker's local driver calls mount(2) directly,
#   so userspace-only mount.cifs options such as credentials= would NOT work). Verified against the
#   engine: this option string reaches the network layer ("connection refused" against a dead server),
#   while adding one unknown option makes the same mount fail with "invalid argument". The password is stored
#   in the volume's options and is therefore visible to `docker volume inspect` on the remote host:
#   that is the accepted trade for typing it once. Remove it with `docker volume rm idapro`.
#
# Remote examples:
#   ./run_system_tests_docker.sh exec --remote remote-engine.example -w my-worktree -- true
#   ./run_system_tests_docker.sh test --remote remote-engine.example -w my-worktree -o remote.txt -- -q
#
# Examples:
#   ./run_system_tests_docker.sh system
#   ./run_system_tests_docker.sh system -w my-worktree
#   (explicit repo root, e.g. when not cwd in repo): D810_REPO_ROOT=/path/to/d810 ./run_system_tests_docker.sh system -w preanalysis-lifecycle
#   ./run_system_tests_docker.sh shell
#   ./run_system_tests_docker.sh shell -w verifycpp-on-ngFlowGraphTransform -l
#   ./run_system_tests_docker.sh exec -- python -c 'print("hello world")'
#   ./run_system_tests_docker.sh exec -- bash -c 'echo hi && $PYTHON -m pytest tests/unit/ -v'
#   # Routine runtime matrix: full Cython plus the owned pure-Python parity slice.
#   D810_NO_CYTHON=0 ./run_system_tests_docker.sh system -w my-worktree -o system-cython.txt -- -q
#   D810_NO_CYTHON=1 ./run_system_tests_docker.sh system -w my-worktree -o system-python-parity.txt -- -m speedup_parity -q
#   # Release/scheduled evidence still runs the complete suite in both modes.
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
_trace_default_override D810_CYTHON_PROFILE 0
_trace_default_override D810_NATIVE_PROFILE 0
_trace_default_override D810_TEST_BINARY libobfuscated.dll
_trace_default_override D810_SYSTEM_BATCH_SIZE 20
_trace_default_override D810_WORKTREE_ROOT .worktrees
_trace_default_override D810_REMOTE_VOLUME idapro
_trace_default_override D810_REMOTE_SHARE_ROOT /srv/share-root

DOCKER_IMAGE="${D810_DOCKER_IMAGE-idapro-9.4}"
DOCKER_MEMORY="${D810_DOCKER_MEMORY-4g}"
NO_CYTHON="${D810_NO_CYTHON-1}"
CYTHON_PROFILE="${D810_CYTHON_PROFILE-0}"
NATIVE_PROFILE="${D810_NATIVE_PROFILE-0}"
TEST_BINARY="${D810_TEST_BINARY-libobfuscated.dll}"
SYSTEM_BATCH_SIZE="${D810_SYSTEM_BATCH_SIZE-20}"
# Remote execution is opt-in: the flag wins over the environment, and every
# value below only ever affects this wrapper (never the container environment).
REMOTE_HOST="${D810_REMOTE_DOCKER_HOST-}"
REMOTE_VOLUME="${D810_REMOTE_VOLUME-idapro}"
REMOTE_SHARE_ROOT="${D810_REMOTE_SHARE_ROOT-/srv/share-root}"
REMOTE_MODE=0
REMOTE_ENGINE_OS=""
REMOTE_ENGINE_ARCH=""
REMOTE_LOCK_DIR=""
WORK_SUBPATH=""
[ -n "$DOCKER_IMAGE" ] || { echo "ERROR: D810_DOCKER_IMAGE is set but empty" >&2; exit 1; }
[ -n "$DOCKER_MEMORY" ] || { echo "ERROR: D810_DOCKER_MEMORY is set but empty" >&2; exit 1; }
case "$SYSTEM_BATCH_SIZE" in
  ''|*[!0-9]*|0) echo "ERROR: D810_SYSTEM_BATCH_SIZE must be a positive integer" >&2; exit 1 ;;
esac
case "$CYTHON_PROFILE" in
  0|1) ;;
  *) echo "ERROR: D810_CYTHON_PROFILE must be 0 or 1" >&2; exit 1 ;;
esac
case "$NATIVE_PROFILE" in
  0|1) ;;
  *) echo "ERROR: D810_NATIVE_PROFILE must be 0 or 1" >&2; exit 1 ;;
esac
if [ "$CYTHON_PROFILE" = "1" ] && [ "$NO_CYTHON" != "0" ]; then
  echo "ERROR: D810_CYTHON_PROFILE=1 requires D810_NO_CYTHON=0" >&2
  exit 1
fi

# The optional Egglog repository is a wrapper-only host path. Validate it
# before any Docker command, then expose only the fixed container path below.
EGGLOG_EXTENSION_ENABLED=0
if [ -n "${D810_EGGLOG_ROOT+x}" ]; then
  if [ -z "$D810_EGGLOG_ROOT" ] || [[ "$D810_EGGLOG_ROOT" != /* ]]; then
    echo "ERROR: D810_EGGLOG_ROOT must be an absolute existing directory" >&2
    exit 1
  fi
  if [ ! -d "$D810_EGGLOG_ROOT" ]; then
    echo "ERROR: D810_EGGLOG_ROOT must be an absolute existing directory: $D810_EGGLOG_ROOT" >&2
    exit 1
  fi
  D810_EGGLOG_ROOT="$(cd "$D810_EGGLOG_ROOT" && pwd -P)"
  EGGLOG_EXTENSION_ENABLED=1
fi
# CoBRA is a required runtime backend for the API-1 mba-solve contract.  Image
# tags and the d810-cobra distribution version do not identify its manifest:
# idapro-9.4-speedups:latest carried a legacy ``rules`` manifest while still
# reporting d810-cobra 0.1.4.  Install from this immutable source revision on
# every Docker run, so an image-local package can never decide the contract.
#
# D810_COBRA_ROOT is only a local acceleration override.  It must resolve to
# this exact parent and submodule revision; accepting an arbitrary checkout
# would merely reintroduce the version-identity bug this pin prevents.
COBRA_SOURCE_URL="https://github.com/w00tzenheimer/d810-CoBRA.git"
COBRA_SOURCE_REVISION="3b3c406270f1efd8e222f0b05040ae4e074b27d5"
COBRA_CORE_SOURCE_REVISION="72f616f822f538a0cfbea3c880f9d1e68bb9a8f1"
COBRA_EXTENSION_ENABLED=1
COBRA_SOURCE_MODE="pinned-remote"
COBRA_PARENT_SOURCE_ID="$COBRA_SOURCE_REVISION"
COBRA_CORE_SOURCE_ID="$COBRA_CORE_SOURCE_REVISION"
# A published prebuilt wheel is the immutable fast path: it installs in
# seconds and skips the clone, the cmake/ninja provisioning and the 55-object
# C++ build. The table below is the entire allow-list and holds only the
# PUBLISHED PyPI artifacts of d810-cobra 0.1.5, built from tag v0.1.5
# (73b405c106d78e1fdc7576b217de39b7dcd0ddb3) over core third_party/cobra
# 72f616f822f538a0cfbea3c880f9d1e68bb9a8f1.
#
# The commits are kept literal on purpose: a later revision bump must not
# silently re-label an already published wheel. Note the tag commit differs
# from COBRA_SOURCE_REVISION above, which pins what source mode compiles.
#
# Preflight builds from 55540ab84d95bde080a5c1223f034b61fb483492, provenance
# evidence, NOT accepted -- they carry the SAME filenames and the SAME sizes as
# the published wheels but different bytes, so only the hash tells them apart:
#   b71d40e45146004a968a96a1b17493b16ac04f2a98e41c12a1f87a38ddf3ab25  aarch64
#   c642e6a6d61f8b841d97df78375c6e1da43fc05a56c3b68218230ed23beaa762  x86_64
#
# Columns: <sha256> <version>|<arch>|<tag commit>|<core commit>
COBRA_RECORDED_WHEELS="2c85ffe14a1f3c1d2b750790332a7c0a5e911b35f7fc041ebedcd6532382c63c 0.1.5|aarch64|73b405c106d78e1fdc7576b217de39b7dcd0ddb3|72f616f822f538a0cfbea3c880f9d1e68bb9a8f1
352133fd4f91227518714735b463b978760650b5f30c71f5276c0bccb90cb72c 0.1.5|x86_64|73b405c106d78e1fdc7576b217de39b7dcd0ddb3|72f616f822f538a0cfbea3c880f9d1e68bb9a8f1"

_cobra_recorded_wheel_record() {
  local wanted="$1" digest record
  while read -r digest record; do
    [ -n "$digest" ] || continue
    if [ "$digest" = "$wanted" ]; then
      printf '%s' "$record"
      return 0
    fi
  done <<< "$COBRA_RECORDED_WHEELS"
  return 1
}

_sha256_of_file() {
  # macOS hosts ship shasum; Linux hosts ship sha256sum. Either is authoritative.
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{ print $1 }'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    return 1
  fi
}

# D810_COBRA_WHEEL selects the recorded-wheel mode. The two variables are
# required together: a path without its hash cannot be verified, and a hash
# without a path verifies nothing. Every check is host-side and fails closed
# before any container starts; only the engine-architecture probe touches
# Docker, and it never runs a container.
COBRA_WHEEL_BASENAME=""
COBRA_WHEEL_SHA256=""
COBRA_WHEEL_VERSION=""
COBRA_WHEEL_ARCH=""
COBRA_WHEEL_CONTAINER_PATH=""
if [ -n "${D810_COBRA_WHEEL+x}" ] || [ -n "${D810_COBRA_WHEEL_SHA256+x}" ]; then
  # Report the variable the caller actually set. Deciding this from emptiness
  # alone would blame the variable they never touched.
  if [ -n "${D810_COBRA_WHEEL+x}" ] && [ -z "$D810_COBRA_WHEEL" ]; then
    echo "ERROR: D810_COBRA_WHEEL is set but empty; give an absolute path to a recorded .whl file or unset it" >&2
    exit 1
  fi
  if [ -n "${D810_COBRA_WHEEL_SHA256+x}" ] && [ -z "$D810_COBRA_WHEEL_SHA256" ]; then
    echo "ERROR: D810_COBRA_WHEEL_SHA256 is set but empty; give 64 lowercase hex characters or unset it" >&2
    exit 1
  fi
  if [ -z "${D810_COBRA_WHEEL:-}" ]; then
    echo "ERROR: D810_COBRA_WHEEL_SHA256 requires D810_COBRA_WHEEL (absolute path to a recorded .whl file)" >&2
    exit 1
  fi
  if [ -z "${D810_COBRA_WHEEL_SHA256:-}" ]; then
    echo "ERROR: D810_COBRA_WHEEL requires D810_COBRA_WHEEL_SHA256 (64 lowercase hex characters)" >&2
    exit 1
  fi
  if [ -n "${D810_COBRA_ROOT+x}" ]; then
    echo "ERROR: D810_COBRA_WHEEL and D810_COBRA_ROOT are mutually exclusive; unset one of them" >&2
    exit 1
  fi
  if [[ "$D810_COBRA_WHEEL" != /* ]] || [ ! -f "$D810_COBRA_WHEEL" ]; then
    echo "ERROR: D810_COBRA_WHEEL must be an absolute path to an existing .whl file: $D810_COBRA_WHEEL" >&2
    exit 1
  fi
  case "$D810_COBRA_WHEEL" in
    *.whl) ;;
    *)
      echo "ERROR: D810_COBRA_WHEEL must be an absolute path to an existing .whl file: $D810_COBRA_WHEEL" >&2
      exit 1
      ;;
  esac
  # Without pipefail a failing hasher still exits 0 through awk, so the two
  # causes of an empty digest are separated here rather than diagnosed later.
  if [ ! -r "$D810_COBRA_WHEEL" ]; then
    echo "ERROR: D810_COBRA_WHEEL is not readable: $D810_COBRA_WHEEL" >&2
    exit 1
  fi
  if [[ ! "$D810_COBRA_WHEEL_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "ERROR: D810_COBRA_WHEEL_SHA256 must be 64 lowercase hex characters: $D810_COBRA_WHEEL_SHA256" >&2
    exit 1
  fi
  COBRA_WHEEL_ACTUAL_SHA256="$(_sha256_of_file "$D810_COBRA_WHEEL" || true)"
  if [ -z "$COBRA_WHEEL_ACTUAL_SHA256" ]; then
    echo "ERROR: D810_COBRA_WHEEL cannot be verified: neither shasum nor sha256sum is on PATH" >&2
    exit 1
  fi
  if [ "$COBRA_WHEEL_ACTUAL_SHA256" != "$D810_COBRA_WHEEL_SHA256" ]; then
    echo "ERROR: D810_COBRA_WHEEL sha256 mismatch: $D810_COBRA_WHEEL hashes to $COBRA_WHEEL_ACTUAL_SHA256, D810_COBRA_WHEEL_SHA256 declares $D810_COBRA_WHEEL_SHA256" >&2
    exit 1
  fi
  if ! COBRA_WHEEL_RECORD="$(_cobra_recorded_wheel_record "$D810_COBRA_WHEEL_SHA256")"; then
    echo "ERROR: D810_COBRA_WHEEL_SHA256 $D810_COBRA_WHEEL_SHA256 is not a recorded d810-cobra wheel; the accepted published wheels live in _gitless/resource/cobra-wheels/0.1.5-published/ (an identical filename does not imply identical bytes)" >&2
    exit 1
  fi
  COBRA_WHEEL_VERSION="${COBRA_WHEEL_RECORD%%|*}"
  COBRA_WHEEL_RECORD_TAIL="${COBRA_WHEEL_RECORD#*|}"
  COBRA_WHEEL_ARCH="${COBRA_WHEEL_RECORD_TAIL%%|*}"
  COBRA_WHEEL_RECORD_TAIL="${COBRA_WHEEL_RECORD_TAIL#*|}"
  COBRA_WHEEL_PARENT="${COBRA_WHEEL_RECORD_TAIL%%|*}"
  COBRA_WHEEL_CORE="${COBRA_WHEEL_RECORD_TAIL#*|}"
  # pip refuses a renamed wheel, so the basename must still describe the
  # artifact the hash identifies: same version, same CPython ABI, same arch.
  COBRA_WHEEL_BASENAME="$(basename "$D810_COBRA_WHEEL")"
  if [[ ! "$COBRA_WHEEL_BASENAME" =~ ^d810_cobra-([0-9A-Za-z.]+)-cp313-cp313-([0-9A-Za-z._]+)\.whl$ ]]; then
    echo "ERROR: D810_COBRA_WHEEL basename must be d810_cobra-<version>-cp313-cp313-<platform>.whl: $COBRA_WHEEL_BASENAME" >&2
    exit 1
  fi
  COBRA_WHEEL_NAME_VERSION="${BASH_REMATCH[1]}"
  COBRA_WHEEL_NAME_PLATFORM="${BASH_REMATCH[2]}"
  if [ "$COBRA_WHEEL_NAME_VERSION" != "$COBRA_WHEEL_VERSION" ]; then
    echo "ERROR: D810_COBRA_WHEEL basename declares version $COBRA_WHEEL_NAME_VERSION but the recorded wheel is $COBRA_WHEEL_VERSION: $COBRA_WHEEL_BASENAME" >&2
    exit 1
  fi
  case "$COBRA_WHEEL_NAME_PLATFORM" in
    *"$COBRA_WHEEL_ARCH"*) ;;
    *)
      echo "ERROR: D810_COBRA_WHEEL platform tag $COBRA_WHEEL_NAME_PLATFORM does not carry the recorded architecture $COBRA_WHEEL_ARCH: $COBRA_WHEEL_BASENAME" >&2
      exit 1
      ;;
  esac
  # A wheel carries native code, so the engine architecture decides which of
  # the recorded wheels is installable. Ask the engine rather than the host:
  # a remote or emulated engine need not match this machine.
  COBRA_DOCKER_SERVER_ARCH="$(docker version --format '{{.Server.Arch}}' 2>/dev/null || true)"
  case "$COBRA_DOCKER_SERVER_ARCH" in
    arm64) COBRA_DOCKER_ENGINE_ARCH="aarch64" ;;
    amd64) COBRA_DOCKER_ENGINE_ARCH="x86_64" ;;
    *)
      echo "ERROR: D810_COBRA_WHEEL needs a known Docker engine architecture; docker version --format '{{.Server.Arch}}' returned '$COBRA_DOCKER_SERVER_ARCH' (expected arm64 or amd64)" >&2
      exit 1
      ;;
  esac
  if [ "$COBRA_DOCKER_ENGINE_ARCH" != "$COBRA_WHEEL_ARCH" ]; then
    echo "ERROR: D810_COBRA_WHEEL is a $COBRA_WHEEL_ARCH wheel but the Docker engine is $COBRA_DOCKER_ENGINE_ARCH (docker server arch $COBRA_DOCKER_SERVER_ARCH); use the recorded $COBRA_DOCKER_ENGINE_ARCH wheel" >&2
    exit 1
  fi
  COBRA_WHEEL_SHA256="$D810_COBRA_WHEEL_SHA256"
  COBRA_WHEEL_CONTAINER_PATH="/opt/d810-cobra-wheel/$COBRA_WHEEL_BASENAME"
  COBRA_SOURCE_MODE="wheel"
  COBRA_PARENT_SOURCE_ID="$COBRA_WHEEL_PARENT"
  COBRA_CORE_SOURCE_ID="$COBRA_WHEEL_CORE"
fi
if [ -n "${D810_COBRA_ROOT+x}" ]; then
  if [ -z "$D810_COBRA_ROOT" ] || [[ "$D810_COBRA_ROOT" != /* ]]; then
    echo "ERROR: D810_COBRA_ROOT must be an absolute existing directory" >&2
    exit 1
  fi
  if [ ! -d "$D810_COBRA_ROOT" ]; then
    echo "ERROR: D810_COBRA_ROOT must be an absolute existing directory: $D810_COBRA_ROOT" >&2
    exit 1
  fi
  D810_COBRA_ROOT="$(cd "$D810_COBRA_ROOT" && pwd -P)"
  COBRA_PARENT_SOURCE_ID="$(GIT_NO_REPLACE_OBJECTS=1 git -C "$D810_COBRA_ROOT" rev-parse HEAD 2>/dev/null || true)"
  COBRA_CORE_SOURCE_ID="$(GIT_NO_REPLACE_OBJECTS=1 git -C "$D810_COBRA_ROOT/third_party/cobra" rev-parse HEAD 2>/dev/null || true)"
  if [ "$COBRA_PARENT_SOURCE_ID" != "$COBRA_SOURCE_REVISION" ] || [ "$COBRA_CORE_SOURCE_ID" != "$COBRA_CORE_SOURCE_REVISION" ]; then
    echo "ERROR: D810_COBRA_ROOT must be d810-cobra $COBRA_SOURCE_REVISION with third_party/cobra $COBRA_CORE_SOURCE_REVISION" >&2
    exit 1
  fi
  COBRA_PARENT_DIRTY="$(GIT_NO_REPLACE_OBJECTS=1 git -C "$D810_COBRA_ROOT" status --porcelain=v1 --untracked-files=all --ignore-submodules=none 2>/dev/null || true)"
  COBRA_CORE_DIRTY="$(GIT_NO_REPLACE_OBJECTS=1 git -C "$D810_COBRA_ROOT/third_party/cobra" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)"
  if [ -n "$COBRA_PARENT_DIRTY" ] || [ -n "$COBRA_CORE_DIRTY" ]; then
    echo "ERROR: D810_COBRA_ROOT must be clean; use the pinned remote source or remove tracked/untracked changes" >&2
    exit 1
  fi
  COBRA_SOURCE_MODE="mounted-pinned"
fi
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
    --remote)
      if [ $# -lt 2 ] || [ -z "$2" ]; then
        echo "ERROR: --remote requires a HOST argument (e.g. --remote remote-engine.example)" >&2
        exit 1
      fi
      REMOTE_HOST="$2"
      shift 2
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


COBRA_SOURCE_ARCHIVE_DIR=""
COBRA_SOURCE_ARCHIVE_SENTINEL=""
_cleanup_cobra_source_artifact() {
  local source_dir="$COBRA_SOURCE_ARCHIVE_DIR"
  local sentinel="$COBRA_SOURCE_ARCHIVE_SENTINEL"
  [ -n "$source_dir" ] && [ -n "$sentinel" ] || return 0
  case "$source_dir" in "$WORK_DIR"/.tmp/cobra-source.*) ;; *) return 0 ;; esac
  [ -f "$sentinel" ] || return 0
  [ "$(cat "$sentinel")" = "d810-cobra-source-artifact-v1" ] || return 0
  rm -rf "$source_dir"
}

_release_remote_lock() {
  [ -n "$REMOTE_LOCK_DIR" ] || return 0
  case "$REMOTE_LOCK_DIR" in */.tmp/remote-run.lock) ;; *) return 0 ;; esac
  rm -rf "$REMOTE_LOCK_DIR"
}

_d810_exit_cleanup() {
  _release_remote_lock
  _cleanup_cobra_source_artifact
}
trap _d810_exit_cleanup EXIT

# Remote mode reaches host files through one SMB-backed Docker volume, so every
# mounted path must be expressible as a subpath of the exported share root.
_share_relative_path() {
  local host_path="$1" resolved relative
  resolved="$(cd "$host_path" 2>/dev/null && pwd -P)" || true
  if [ -z "$resolved" ]; then
    echo "ERROR: remote mode cannot resolve the host path: $host_path" >&2
    return 1
  fi
  relative="${resolved#"$REMOTE_SHARE_ROOT"/}"
  if [ -z "$relative" ] || [ "$relative" = "$resolved" ]; then
    echo "ERROR: remote mode requires every mounted path to live under the SMB share root" >&2
    echo "       path:       $resolved" >&2
    echo "       share root: $REMOTE_SHARE_ROOT (D810_REMOTE_SHARE_ROOT)" >&2
    return 1
  fi
  printf '%s' "$relative"
}

# Emit the docker arguments for one mount. Local runs keep the historical bind
# mount byte for byte; remote runs address the same bytes through the volume.
MOUNT_ARG_BUF=()
_mount_arg() {
  local host_path="$1" container_path="$2" mode="${3:-}" relative specification
  MOUNT_ARG_BUF=()
  if [ "$REMOTE_MODE" = "1" ]; then
    relative="$(_share_relative_path "$host_path")" || return 1
    specification="type=volume,src=${REMOTE_VOLUME},dst=${container_path},volume-subpath=${relative}"
    if [ "$mode" = "ro" ]; then
      specification="${specification},readonly"
    fi
    MOUNT_ARG_BUF=(--mount "$specification")
  elif [ -n "$mode" ]; then
    MOUNT_ARG_BUF=(-v "${host_path}:${container_path}:${mode}")
  else
    MOUNT_ARG_BUF=(-v "${host_path}:${container_path}")
  fi
}

DOCKER_MOUNTS=()
_add_mount() {
  _mount_arg "$@" || exit 1
  DOCKER_MOUNTS+=("${MOUNT_ARG_BUF[@]}")
}

_acquire_remote_lock() {
  local lock_dir="$WORK_DIR/.tmp/remote-run.lock" holder=""
  mkdir -p "$WORK_DIR/.tmp"
  if ! mkdir "$lock_dir" 2>/dev/null; then
    [ -f "$lock_dir/owner" ] && holder="$(cat "$lock_dir/owner" 2>/dev/null || true)"
    echo "ERROR: another remote run already owns this worktree: $WORK_DIR" >&2
    echo "       lock:   $lock_dir" >&2
    echo "       holder: ${holder:-unknown}" >&2
    echo "       Wait for it to finish, or remove a stale lock with: rm -rf '$lock_dir'" >&2
    exit 1
  fi
  REMOTE_LOCK_DIR="$lock_dir"
  printf 'pid=%s host=%s remote=%s started=%s\n' \
    "$$" "$(hostname 2>/dev/null || echo unknown)" "$REMOTE_HOST" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$lock_dir/owner"
}

_remote_preflight_engine() {
  local engine=""
  if ! engine="$(docker info --format '{{.OSType}} {{.Architecture}}' 2>&1)"; then
    echo "ERROR: remote Docker engine is unreachable: ssh://$REMOTE_HOST" >&2
    echo "       $engine" >&2
    exit 1
  fi
  REMOTE_ENGINE_OS="${engine%% *}"
  REMOTE_ENGINE_ARCH="${engine##* }"
  if [ "$REMOTE_ENGINE_OS" != "linux" ]; then
    echo "ERROR: remote Docker engine must run linux containers; ssh://$REMOTE_HOST reports OSType=$REMOTE_ENGINE_OS" >&2
    exit 1
  fi
  if ! docker volume inspect "$REMOTE_VOLUME" >/dev/null 2>&1; then
    echo "ERROR: remote Docker volume not found on ssh://$REMOTE_HOST: $REMOTE_VOLUME" >&2
    echo "       Create it once with the SMB volume command in --help (D810_REMOTE_VOLUME selects the name)." >&2
    exit 1
  fi
  if ! docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
    echo "ERROR: image not present on the remote engine ssh://$REMOTE_HOST: $DOCKER_IMAGE" >&2
    exit 1
  fi
}

# The volume can exist and still not expose this checkout (wrong share, wrong
# subpath, unmounted CIFS). Prove reachability read-only before any real work.
_remote_probe_volume() {
  printf '[remote] probing %s through volume %s on ssh://%s\n' "$WORK_DIR" "$REMOTE_VOLUME" "$REMOTE_HOST"
  if ! docker run --rm \
      --mount "type=volume,src=${REMOTE_VOLUME},dst=/probe,volume-subpath=${WORK_SUBPATH},readonly" \
      --entrypoint /bin/bash "$DOCKER_IMAGE" \
      -lc 'test -d /probe/src && test -d /probe/tests'; then
    echo "ERROR: the worktree is not reachable through volume $REMOTE_VOLUME at subpath $WORK_SUBPATH" >&2
    echo "       host path: $WORK_DIR" >&2
    echo "       Check that the share is mounted on ssh://$REMOTE_HOST and exports $REMOTE_SHARE_ROOT." >&2
    exit 1
  fi
}

if [ -n "$REMOTE_HOST" ]; then
  REMOTE_MODE=1
  if [[ "$REMOTE_SHARE_ROOT" != /* ]] || [ ! -d "$REMOTE_SHARE_ROOT" ]; then
    echo "ERROR: D810_REMOTE_SHARE_ROOT must be an absolute existing directory: $REMOTE_SHARE_ROOT" >&2
    exit 1
  fi
  REMOTE_SHARE_ROOT="$(cd "$REMOTE_SHARE_ROOT" && pwd -P)"
  WORK_SUBPATH="$(_share_relative_path "$WORK_DIR")" || exit 1
  # Export before any docker invocation so image inspection, the probe and the
  # workload all address the same engine.
  export DOCKER_HOST="ssh://$REMOTE_HOST"
  _remote_preflight_engine
  _acquire_remote_lock
fi

# Profile receipts need to identify the actual image that ran them. Keep this
# test-only metadata separate from the image-selection environment variable,
# which is deliberately wrapper-only and therefore not forwarded by default.
DOCKER_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$DOCKER_IMAGE" 2>/dev/null || echo unknown)"

# Docker mount: host path -> container path (use variables so no host-specific paths in printed commands)
_add_mount "$WORK_DIR" /work
ENV_GIT=""
GIT_COMMON_DIR="$(git -C "$WORK_DIR" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || true)"
if [ -n "$GIT_COMMON_DIR" ] && [ -d "$GIT_COMMON_DIR" ]; then
  _add_mount "$GIT_COMMON_DIR" /d810-git ro
  ENV_GIT="GIT_DIR=/d810-git"
fi
if [ -n "$MOUNT_LOGS" ]; then
  LOGS_DIR="${WORK_DIR}/.tmp/logs"
  mkdir -p "$LOGS_DIR"
  _add_mount "$LOGS_DIR" /root/.idapro/logs
fi
if [ "$EGGLOG_EXTENSION_ENABLED" = "1" ]; then
  _add_mount "$D810_EGGLOG_ROOT" /opt/d810-egglog ro
fi
_materialize_canonical_git_tree() {
  local repository="$1"
  local revision="$2"
  local destination="$3"
  local listing="$4"
  local excluded_gitlink="$5"
  local record metadata relative_path mode object_type object_id output_path

  # ls-tree and cat-file operate on canonical objects directly: unlike
  # checkout-index, neither consults attributes nor runs clean/smudge filters.
  GIT_NO_REPLACE_OBJECTS=1 git -C "$repository" ls-tree -rz "$revision" > "$listing"
  while IFS= read -r -d '' record; do
    metadata="${record%%$'\t'*}"
    relative_path="${record#*$'\t'}"
    read -r mode object_type object_id <<< "$metadata"
    if [ "$object_type" = "commit" ]; then
      if [ "$relative_path" = "$excluded_gitlink" ]; then
        continue
      fi
      echo "ERROR: unexpected unpinned gitlink in CoBRA source: $relative_path" >&2
      return 1
    fi
    if [ "$object_type" != "blob" ]; then
      echo "ERROR: unexpected CoBRA tree object $object_type at $relative_path" >&2
      return 1
    fi
    output_path="$destination/$relative_path"
    mkdir -p "$(dirname "$output_path")"
    case "$mode" in
      100644)
        GIT_NO_REPLACE_OBJECTS=1 git -C "$repository" cat-file blob "$object_id" > "$output_path"
        chmod 644 "$output_path"
        ;;
      100755)
        GIT_NO_REPLACE_OBJECTS=1 git -C "$repository" cat-file blob "$object_id" > "$output_path"
        chmod 755 "$output_path"
        ;;
      120000)
        ln -s "$(GIT_NO_REPLACE_OBJECTS=1 git -C "$repository" cat-file blob "$object_id")" "$output_path"
        ;;
      *)
        echo "ERROR: unsupported CoBRA tree mode $mode at $relative_path" >&2
        return 1
        ;;
    esac
  done < "$listing"
}
COBRA_CACHE_DIR=""
if [ "$COBRA_SOURCE_MODE" = "mounted-pinned" ]; then
  # A worktree's .git file can point at an object database outside its root,
  # which is unavailable after a read-only Docker mount. Materialize canonical
  # bytes on the host while its object database is reachable, then mount only
  # that source tree. checkout-index does not honor export-ignore attributes;
  # GIT_NO_REPLACE_OBJECTS makes both the receipt IDs and exported bytes immune
  # to local refs/replace rewrites.
  mkdir -p "$WORK_DIR/.tmp"
  COBRA_SOURCE_ARCHIVE_DIR="$(mktemp -d "${WORK_DIR}/.tmp/cobra-source.XXXXXX")"
  COBRA_SOURCE_ARCHIVE_SENTINEL="$COBRA_SOURCE_ARCHIVE_DIR/.d810-cobra-source-artifact"
  printf '%s\n' "d810-cobra-source-artifact-v1" > "$COBRA_SOURCE_ARCHIVE_SENTINEL"
  COBRA_SOURCE_TREE="$COBRA_SOURCE_ARCHIVE_DIR/source"
  mkdir -p "$COBRA_SOURCE_TREE/third_party/cobra"
  _materialize_canonical_git_tree "$D810_COBRA_ROOT" "$COBRA_SOURCE_REVISION" "$COBRA_SOURCE_TREE" "$COBRA_SOURCE_ARCHIVE_DIR/parent.entries" "third_party/cobra"
  _materialize_canonical_git_tree "$D810_COBRA_ROOT/third_party/cobra" "$COBRA_CORE_SOURCE_REVISION" "$COBRA_SOURCE_TREE/third_party/cobra" "$COBRA_SOURCE_ARCHIVE_DIR/core.entries" ""
  rm -f "$COBRA_SOURCE_ARCHIVE_DIR/parent.entries" "$COBRA_SOURCE_ARCHIVE_DIR/core.entries"
  _add_mount "$COBRA_SOURCE_TREE" /opt/d810-cobra-source ro
fi
if [ "$COBRA_SOURCE_MODE" = "wheel" ]; then
  # A recorded wheel needs no build cache and no source tree. Mount only the
  # wheel, read-only and under its real basename: pip rejects a renamed wheel
  # because the filename is the artifact's version/ABI/platform declaration.
  _add_mount "$D810_COBRA_WHEEL" "$COBRA_WHEEL_CONTAINER_PATH" ro
else
  # Build outputs are Linux-only and belong to this task's ignored artifact
  # area. Keeping them outside both source forms makes repeated focused runs
  # reuse one pinned build without ever linking a Darwin archive.
  COBRA_CACHE_DIR="${WORK_DIR}/.tmp/cobra-linux"
  mkdir -p "$COBRA_CACHE_DIR"
  _add_mount "$COBRA_CACHE_DIR" /opt/d810-cobra-cache rw
fi
COBRA_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$DOCKER_IMAGE" 2>/dev/null || printf '%s' unknown)"

# Plan: print what we're about to do so agents see worktree, output path, and options
echo "$0 plan:"
echo "  command: $CMD"
if [ -n "$WORKTREE_REL" ]; then
  echo "  worktree: $WORK_DIR (WORKTREE_ROOT=$WORKTREE_ROOT, REL=$WORKTREE_REL)"
else
  echo "  worktree: $WORK_DIR (repo root)"
fi
if [ "$REMOTE_MODE" = "1" ]; then
  echo "  remote:   ssh://$REMOTE_HOST (engine $REMOTE_ENGINE_OS/$REMOTE_ENGINE_ARCH)"
  echo "  volume:   $REMOTE_VOLUME"
  echo "  share root: $REMOTE_SHARE_ROOT"
  echo "  subpath:  $WORK_SUBPATH"
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
if [ "$EGGLOG_EXTENSION_ENABLED" = "1" ]; then
  echo "  extension: d810-egglog (mount ${D810_EGGLOG_ROOT}:/opt/d810-egglog:ro)"
fi
if [ "$COBRA_EXTENSION_ENABLED" = "1" ]; then
  if [ "$COBRA_SOURCE_MODE" = "wheel" ]; then
    echo "  extension: d810-cobra (wheel $COBRA_WHEEL_BASENAME)"
    echo "  cobra wheel: $D810_COBRA_WHEEL -> $COBRA_WHEEL_CONTAINER_PATH (read-only) published sha256 $COBRA_WHEEL_SHA256; d810-cobra $COBRA_WHEEL_VERSION tag v$COBRA_WHEEL_VERSION $COBRA_PARENT_SOURCE_ID core $COBRA_CORE_SOURCE_ID"
  else
    echo "  extension: d810-cobra ($COBRA_SOURCE_MODE $COBRA_SOURCE_REVISION)"
    if [ "$COBRA_SOURCE_MODE" = "mounted-pinned" ]; then
      echo "  cobra source: canonical archive from $D810_COBRA_ROOT -> /opt/d810-cobra-source (read-only)"
    else
      echo "  cobra source: $COBRA_SOURCE_URL@$COBRA_SOURCE_REVISION"
    fi
    echo "  cobra cache: $COBRA_CACHE_DIR -> /opt/d810-cobra-cache (Linux artifacts)"
  fi
fi
case "$CMD" in
  system)
    echo "  run:      fresh pytest batches over tests/system${EXTRA_PYTEST[*]:+ ${EXTRA_PYTEST[*]}}"
    echo "  batch:    $SYSTEM_BATCH_SIZE tests per interpreter"
    ;;
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

if [ "$REMOTE_MODE" = "1" ]; then
  _remote_probe_volume
fi

ENV_IDA="IDA_PREFIX=/app/ida IDA_INSTALL_DIR=/app/ida D810_LIBCLANG_PATH=/app/ida/libclang.so"
ENV_PYTHON="PYTHONPATH=${PYWORK}:/app/ida/python:\$PYTHONPATH"
ENV_TEST="D810_NO_CYTHON=$NO_CYTHON D810_TEST_BINARY=$TEST_BINARY D810_TEST_RUNTIME_IMAGE=$DOCKER_IMAGE D810_TEST_RUNTIME_IMAGE_ID=$DOCKER_IMAGE_ID"
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
PYTEST_EXTENSION_ARGS=""
if [ "$EGGLOG_EXTENSION_ENABLED" = "1" ] || [ "$COBRA_EXTENSION_ENABLED" = "1" ]; then
  PYTEST_EXTENSION_ARGS="-p no:cacheprovider"
fi

LLVM_OPT_SETUP=""
if [ -n "$ENABLE_LLVM_OPT" ]; then
  LLVM_OPT_SETUP='if ! command -v opt >/dev/null 2>&1; then apt-get update && apt-get install -y --no-install-recommends llvm; fi; LLVM_OPT_PATH="$(command -v opt || find /usr/lib/llvm-*/bin -name opt -type f -perm /111 2>/dev/null | sort -V | tail -1)"; if [ -z "$LLVM_OPT_PATH" ]; then echo "ERROR: --enable-llvm-opt could not find LLVM opt after provisioning" >&2; exit 1; fi; export LLVM_OPT="$LLVM_OPT_PATH"; echo "LLVM opt: $LLVM_OPT"; "$LLVM_OPT" --version | head -n 1'
fi

# Forward every set D810_* env var to the container via docker -e flags.
# Wrapper-only vars (those that only affect this script) are excluded.
_d810_extra_env_flags() {
  local _skip=" D810_DOCKER_IMAGE D810_DOCKER_MEMORY D810_EGGLOG_ROOT D810_COBRA_ROOT D810_COBRA_WHEEL D810_COBRA_WHEEL_SHA256 D810_REPO_ROOT D810_WORKTREE_ROOT D810_MEMORY_LIMIT_BYTES D810_SYSTEM_BATCH_SIZE D810_REMOTE_DOCKER_HOST D810_REMOTE_VOLUME D810_REMOTE_SHARE_ROOT "
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
IDA_VENV_PYSPY="/app/ida/.venv/bin/py-spy"

PROFILE_DOCKER_FLAGS=""
PROFILE_SETUP=""
if [ "$NATIVE_PROFILE" = "1" ]; then
  # PERFMON admits perf_event_open without granting the container full
  # privilege. SYS_PTRACE + the narrow seccomp relaxation admit py-spy attach.
  PROFILE_DOCKER_FLAGS="--cap-add=PERFMON --cap-add=SYS_PTRACE --security-opt=seccomp=unconfined"
  PROFILE_SETUP="if ! command -v perf >/dev/null 2>&1; then apt-get update -qq && apt-get install -y --no-install-recommends linux-perf; fi; if [ ! -x $IDA_VENV_PYSPY ]; then $IDA_VENV_PIP install -q py-spy; fi; perf --version; $IDA_VENV_PYSPY --version"
fi

# Per-container setup exports the runtime environment and installs dependencies
# when using an unlabelled base image. A d810 runtime label is only a hint: local
# tags can outlive the image contents they describe, so labelled images must
# prove that pytest, Unicorn, and the isolated Z3 runtime all import before the
# install step is omitted. A stale runtime is refreshed and then probed again;
# an unusable solver must fail setup rather than surface as a collection error.
# Native Cython compilation runs when explicitly enabled and fails closed. The
# default D810_NO_CYTHON=1 skips this build. Remove ignored Linux extension
# artifacts first so a failed rebuild cannot silently import a stale native
# module. The checkout is a read-write host mount, so cleanup must preserve
# Darwin extensions and Windows ``.pyd`` files built for the developer host.
# The build needs a C++
# toolchain + the IDA SDK; setup.py auto-downloads the SDK from GitHub when
# IDA_SDK is unset and links against the live IDA runtime (libida.so) via
# IDA_INSTALL_DIR. NOTE: do NOT pass --no-build-isolation — the IDA venv has
# neither setuptools nor Cython, so pip MUST build-isolate to install the
# build-system.requires (setuptools/wheel/Cython).
SPEEDUPS_CLEAN_CMD="find src/d810/speedups -type f -name '*-linux-gnu.so' -delete"
if [ "$NO_CYTHON" = "1" ]; then
  SPEEDUPS_BUILD_CMD="$SPEEDUPS_CLEAN_CMD && echo '[speedups] native build disabled by D810_NO_CYTHON=1'"
elif [ "$CYTHON_PROFILE" = "1" ]; then
  # A profiling artifact is only useful when it actually contains Cython
  # trace events. Unlike the normal optional speedup build, fail closed here.
  SPEEDUPS_BUILD_CMD="$SPEEDUPS_CLEAN_CMD && DEBUG=1 D810_BUILD_SPEEDUPS=1 $IDA_VENV_PIP install -e .[speedups] -q"
else
  SPEEDUPS_BUILD_CMD="$SPEEDUPS_CLEAN_CMD && D810_BUILD_SPEEDUPS=1 $IDA_VENV_PIP install -e .[speedups] -q"
fi
RUNTIME_PROBE="from d810.speedups import bootstrap; bootstrap.ensure_speedups_on_path(); import pytest, unicorn, z3; assert (4, 13) <= z3.get_version() < (4, 15, 5)"
if _image_has_baked_runtime; then
  DEPENDENCY_SETUP="if $IDA_VENV_PYTHON -c '$RUNTIME_PROBE' >/dev/null 2>&1 && command -v git >/dev/null 2>&1; then echo '[setup] baked runtime dependencies detected; install skipped'; else echo '[setup] baked runtime is stale; refreshing declared test dependencies'; if ! command -v git >/dev/null 2>&1; then apt-get update && apt-get install -y --no-install-recommends git; fi; $IDA_VENV_PIP install -e '.[dev,emulation]' -q && $IDA_VENV_PYTHON -m d810.speedups.install --solver-only && $IDA_VENV_PYTHON -c '$RUNTIME_PROBE'; fi"
else
  DEPENDENCY_SETUP="$IDA_VENV_PIP install -e '.[dev,emulation]' -q && $IDA_VENV_PYTHON -m d810.speedups.install --solver-only && $IDA_VENV_PYTHON -c '$RUNTIME_PROBE'"
fi
EXTENSION_SETUP=""
if [ "$EGGLOG_EXTENSION_ENABLED" = "1" ]; then
  EXTENSION_SETUP="EXTENSION_BUILD_DIR=\$(mktemp -d) && cp -a /opt/d810-egglog/. \"\$EXTENSION_BUILD_DIR/\" && $IDA_VENV_PYTHON -c 'import re, sys, tomllib; project=tomllib.load(open(sys.argv[1], \"rb\"))[\"project\"]; deps=project.get(\"dependencies\", []) + project.get(\"optional-dependencies\", {}).get(\"test\", []); print(\"\\n\".join(dep for dep in deps if re.match(r\"[A-Za-z0-9_.-]+\", dep.strip()).group(0).lower().replace(\"_\", \"-\").replace(\".\", \"-\") != \"d810-ng\"))' \"\$EXTENSION_BUILD_DIR/pyproject.toml\" > \"\$EXTENSION_BUILD_DIR/requirements.txt\" && $IDA_VENV_PIP install \"\$EXTENSION_BUILD_DIR[test]\" --no-deps -q --force-reinstall --no-cache-dir && $IDA_VENV_PIP install -r \"\$EXTENSION_BUILD_DIR/requirements.txt\" -q && $IDA_VENV_PYTHON -c 'import d810_egglog, egglog'"
fi
if [ "$COBRA_EXTENSION_ENABLED" = "1" ]; then
  if [ "$COBRA_SOURCE_MODE" = "wheel" ]; then
    # The recorded wheel is re-hashed inside the container before pip sees
    # it, so a mount that does not deliver the verified bytes fails setup
    # instead of installing an unknown artifact. Runtime dependencies come
    # from the installed distribution's own metadata, minus the mounted
    # D810 package and minus every extra, exactly as the source path does.
    COBRA_SETUP="printf '%s  %s\\n' '$COBRA_WHEEL_SHA256' '$COBRA_WHEEL_CONTAINER_PATH' | sha256sum -c - && $IDA_VENV_PIP install --no-deps --force-reinstall --no-cache-dir -q '$COBRA_WHEEL_CONTAINER_PATH' && COBRA_REQUIREMENTS=\$(mktemp) && $IDA_VENV_PYTHON -c 'import importlib.metadata, re; reqs=importlib.metadata.requires(\"d810-cobra\") or []; keep=[req for req in reqs if not re.search(r\"extra\\s*==\", req) and re.match(r\"[A-Za-z0-9_.-]+\", req.strip()).group(0).lower().replace(\"_\", \"-\").replace(\".\", \"-\") != \"d810-ng\"]; print(\"\\n\".join(keep))' > \"\$COBRA_REQUIREMENTS\" && $IDA_VENV_PIP install -r \"\$COBRA_REQUIREMENTS\" -q && $IDA_VENV_PYTHON -c 'import d810_cobra; manifest=d810_cobra.MANIFEST; assert manifest[\"api_version\"] == 1; assert manifest[\"implements\"] == {\"mba-solve\": \"cobra-solve\"}; from d810_cobra.expr import parse_cobra_output; from d810_cobra.prove import ProofResult, prove_equivalent; from d810_cobra.solve import SolveStatus, binding_available, solve_signature; assert binding_available(); tree=parse_cobra_output(\"(x0 | x1) - (x0 & x1)\", [\"a\", \"b\"]); solved=solve_signature(tree, [\"a\", \"b\"], 32); assert solved.status is SolveStatus.SOLVED and solved.tree is not None; assert prove_equivalent(tree, solved.tree, [\"a\", \"b\"], 32) is ProofResult.PROVED; import d810_cobra._cobra; import importlib.metadata, os, sysconfig; assert importlib.metadata.version(\"d810-cobra\") == \"$COBRA_WHEEL_VERSION\"; binary=os.path.realpath(d810_cobra._cobra.__file__); assert \"$COBRA_WHEEL_ARCH\" in os.path.basename(binary), binary; site_dirs=[os.path.realpath(sysconfig.get_paths()[key]) for key in (\"purelib\", \"platlib\")]; assert any(binary.startswith(site + os.sep) for site in site_dirs), binary'"
  else
    # CoBRA's test extras are not enough to describe its runtime dependencies;
    # derive the project metadata exactly as for Egglog, while omitting the
    # mounted D810 package so the tested worktree remains authoritative.
    if [ "$COBRA_SOURCE_MODE" = "mounted-pinned" ]; then
      COBRA_SOURCE_SETUP="COBRA_BUILD_DIR=\$(mktemp -d) && cp -a /opt/d810-cobra-source/. \"\$COBRA_BUILD_DIR/\""
    else
      # ENV_GIT pins D810's mounted common Git dir for provenance, but a source
      # checkout needs its own writable .git directory.  Scope the unset to the
      # CoBRA acquisition commands; D810's test provenance keeps ENV_GIT.
      COBRA_SOURCE_SETUP="COBRA_BUILD_DIR=\$(mktemp -d) && env -u GIT_DIR git clone --no-checkout '$COBRA_SOURCE_URL' \"\$COBRA_BUILD_DIR\" && env -u GIT_DIR git -C \"\$COBRA_BUILD_DIR\" fetch --depth=1 origin '$COBRA_SOURCE_REVISION' && env -u GIT_DIR git -C \"\$COBRA_BUILD_DIR\" checkout --detach FETCH_HEAD && test \"\$(env -u GIT_DIR git -C \"\$COBRA_BUILD_DIR\" rev-parse HEAD)\" = '$COBRA_SOURCE_REVISION' && env -u GIT_DIR git -C \"\$COBRA_BUILD_DIR\" submodule update --init --recursive --depth=1 && test \"\$(env -u GIT_DIR git -C \"\$COBRA_BUILD_DIR/third_party/cobra\" rev-parse HEAD)\" = '$COBRA_CORE_SOURCE_REVISION'"
    fi
    COBRA_SETUP="$COBRA_SOURCE_SETUP && export COBRA_ROOT=/opt/d810-cobra-cache && export COBRA_SOURCE_KEY='$COBRA_PARENT_SOURCE_ID:$COBRA_CORE_SOURCE_ID:$COBRA_IMAGE_ID' && COBRA_TOOLCHAIN_KEY=\$(if ! command -v cmake >/dev/null 2>&1 || ! command -v ninja >/dev/null 2>&1 || ! command -v c++ >/dev/null 2>&1; then apt-get update >/dev/null 2>&1 && apt-get install -y --no-install-recommends cmake ninja-build build-essential >/dev/null 2>&1; fi; cmake --version | head -1; ninja --version; c++ --version | head -1) && COBRA_MARKER=\"linux-cobra-core-v2:\$COBRA_SOURCE_KEY:\$COBRA_TOOLCHAIN_KEY\" && if [ ! -f \"\$COBRA_ROOT/.linux-build-ok\" ] || [ \"\$(<\"\$COBRA_ROOT/.linux-build-ok\")\" != \"\$COBRA_MARKER\" ]; then rm -rf \"\$COBRA_ROOT\"/* \"\$COBRA_ROOT\"/.[!.]* \"\$COBRA_ROOT\"/..?* 2>/dev/null || true; cp -a \"\$COBRA_BUILD_DIR/third_party/cobra/.\" \"\$COBRA_ROOT/\"; $IDA_VENV_PYTHON \"\$COBRA_BUILD_DIR/tools/build_cobra.py\" --root \"\$COBRA_ROOT\" && printf '%s\\n' \"\$COBRA_MARKER\" > \"\$COBRA_ROOT/.linux-build-ok\"; fi && $IDA_VENV_PYTHON -c 'import re, sys, tomllib; project=tomllib.load(open(sys.argv[1], \"rb\"))[\"project\"]; deps=project.get(\"dependencies\", []) + project.get(\"optional-dependencies\", {}).get(\"test\", []); print(\"\\n\".join(dep for dep in deps if re.match(r\"[A-Za-z0-9_.-]+\", dep.strip()).group(0).lower().replace(\"_\", \"-\").replace(\".\", \"-\") != \"d810-ng\"))' \"\$COBRA_BUILD_DIR/pyproject.toml\" > \"\$COBRA_BUILD_DIR/requirements.txt\" && $IDA_VENV_PIP install \"\$COBRA_BUILD_DIR[test]\" --no-deps -q --force-reinstall --no-cache-dir && $IDA_VENV_PIP install -r \"\$COBRA_BUILD_DIR/requirements.txt\" -q && $IDA_VENV_PYTHON -c 'import d810_cobra; manifest=d810_cobra.MANIFEST; assert manifest[\"api_version\"] == 1; assert manifest[\"implements\"] == {\"mba-solve\": \"cobra-solve\"}; from d810_cobra.expr import parse_cobra_output; from d810_cobra.prove import ProofResult, prove_equivalent; from d810_cobra.solve import SolveStatus, binding_available, solve_signature; assert binding_available(); tree=parse_cobra_output(\"(x0 | x1) - (x0 & x1)\", [\"a\", \"b\"]); solved=solve_signature(tree, [\"a\", \"b\"], 32); assert solved.status is SolveStatus.SOLVED and solved.tree is not None; assert prove_equivalent(tree, solved.tree, [\"a\", \"b\"], 32) is ProofResult.PROVED; import d810_cobra._cobra'"
  fi
  if [ -n "$EXTENSION_SETUP" ]; then
    EXTENSION_SETUP="$EXTENSION_SETUP && $COBRA_SETUP"
  else
    EXTENSION_SETUP="$COBRA_SETUP"
  fi
fi
SETUP_CMD="$LLVM_OPT_SETUP${LLVM_OPT_SETUP:+ && }export $ENV_IDA $ENV_PYTHON $ENV_GIT && $PROFILE_SETUP${PROFILE_SETUP:+ && }$DEPENDENCY_SETUP"
if [ -n "$EXTENSION_SETUP" ]; then
  SETUP_CMD="$SETUP_CMD && $EXTENSION_SETUP"
fi
SETUP_CMD="$SETUP_CMD && { $SPEEDUPS_BUILD_CMD; }"

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

_run_docker_container() {
  printf '[docker] starting container; native speedup builds may take several minutes\n'
  if docker "$@"; then
    printf '[docker] container completed successfully (exit=0)\n'
    return 0
  else
    local status=$?
    printf '[docker] container failed with exit status %s\n' "$status" >&2
    return "$status"
  fi
}

run_bash() {
  local inner="$1"
  local extra_env="$(_d810_extra_env_flags)"
  _run_docker_container run --rm \
    $PROFILE_DOCKER_FLAGS \
    --add-host files.pythonhosted.org:151.101.0.223 \
    --memory "$DOCKER_MEMORY" \
    -e "D810_MEMORY_LIMIT_BYTES=$MEMORY_BYTES" \
    $extra_env \
    "${DOCKER_MOUNTS[@]}" \
    -w /work \
    --entrypoint /bin/bash "$DOCKER_IMAGE" -lc "$inner"
}

run_bash_it() {
  local inner="$1"
  local extra_env="$(_d810_extra_env_flags)"
  _run_docker_container run -it --rm \
    $PROFILE_DOCKER_FLAGS \
    --memory "$DOCKER_MEMORY" \
    -e "D810_MEMORY_LIMIT_BYTES=$MEMORY_BYTES" \
    $extra_env \
    "${DOCKER_MOUNTS[@]}" \
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
  _run_docker_container run --rm \
    $PROFILE_DOCKER_FLAGS \
    --add-host files.pythonhosted.org:151.101.0.223 \
    --memory "$DOCKER_MEMORY" \
    -e "D810_MEMORY_LIMIT_BYTES=$MEMORY_BYTES" \
    $extra_env \
    "${DOCKER_MOUNTS[@]}" \
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
  run_bash "$SETUP_CMD && ${SYS_TRUNCATE}$ENV_TEST $IDA_VENV_PYTHON tools/scripts/run_system_test_batches.py --python $IDA_VENV_PYTHON --batch-size $SYSTEM_BATCH_SIZE --log-dir /root/.idapro/logs/d810_logs tests/system -- $(_d810_quote_args "${SYSTEM_ARGS[@]}") $SYS_REDIR"
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
  run_bash "$SETUP_CMD && ${SYS_TRUNCATE}$ENV_TEST $IDA_VENV_PYTHON -m pytest -v $PYTEST_EXTENSION_ARGS $(_d810_quote_args "${SYSTEM_ARGS[@]}") $SYS_REDIR"
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

INNER="$SETUP_CMD && ${TRUNCATE_CMD}$ENV_TEST $PYTEST_DUMP $PYTEST_EXTENSION_ARGS $(_d810_quote_args "${DUMP_ARGS[@]}") -v $REDIR"
run_bash "$INNER"
