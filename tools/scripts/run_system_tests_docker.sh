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
#   artifacts (remote only) List the runs retained on a worktree's work volume, or with --run RUN_ID
#             copy one back to WORK_DIR/.tmp/remote-runs/RUN_ID. Failed runs are retained too, and
#             the newest D810_REMOTE_RUN_RETENTION runs are kept (default 20).
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
#   -l, --logs              Mount work dir .tmp/logs at /root/.idapro/logs. In remote mode there is
#                           nothing to mount - logs always live on the work volume - so the flag
#                           instead requests that the finished artifacts be copied back to the share
#                           at exit (--enable-debug-logging and --enable-diag-snapshot imply it).
#                           Without any of them the run is still retained under /work/runs/<run-id>
#                           and retrievable with the artifacts subcommand.
#   -o, --out FILE          (system/test only) Redirect stdout+stderr to WORK_DIR/.tmp/FILE. FILE must be one bare
#                           filename (e.g. out.txt), with no slashes; the script prepends .tmp/.
#   --start-batch N         (system only) Skip ahead to batch N (1-based) instead of starting at 1.
#                           Resume recipe: rerun the SAME system command with --start-batch <first
#                           unfinished batch>, where the batch number is the one printed in the
#                           "[system-batch]" lines of the capture. The batcher recomputes the batch
#                           list from the test selection and --batch-size on every run, so the test
#                           selection (PYTEST_ARGS) and D810_SYSTEM_BATCH_SIZE must be identical to
#                           the run being resumed or the numbering will not line up.
#   --enable-debug-logging  Set D810_DEBUG_LOGGING=1 inside the container so getLogger uses DEBUG as
#                           the default level instead of INFO (explicit caller levels are unaffected).
#   --enable-diag-snapshot  Set D810_DIAG_SNAPSHOT=1 inside the container.
#   --enable-llvm-opt       Opt-in only: install/probe LLVM opt in the container,
#                           export LLVM_OPT, and set D810_REQUIRE_LLVM_OPT=1.
#   --disable-fact-lifecycle
#                           Set D810_FACT_LIFECYCLE=0 inside the container.
#   --remote [HOST]         Run on a remote Linux Docker engine reached over SSH. If HOST is
#                           omitted, use D810_REMOTE_DOCKER_HOST from the local .env.
#                           (DOCKER_HOST=ssh://HOST). Sources and artifacts stay on this Mac and are
#                           reached through the SMB-backed Docker volume named by D810_REMOTE_VOLUME:
#                           every host bind mount becomes --mount type=volume,volume-subpath=<path
#                           relative to D810_REMOTE_SHARE_ROOT>. The worktree is mounted READ-ONLY at
#                           /work-src and mirrored at container start into a retained per-worktree
#                           volume (d810-work-<name>-<hash>) that becomes /work, so Cython .so files,
#                           egg-info and pip output never touch the Mac tree. Only <worktree>/.tmp is
#                           mounted read-write, at /work/.tmp, which is where -o captures, -l logs,
#                           and the cobra source archive already live. Files created
#                           there are owned by the share account's uid.
#                           Only ONE remote run per worktree is allowed at a time (lock:
#                           WORK_DIR/.tmp/remote-run.lock): .tmp is shared read-write, so -o files,
#                           logs, diag SQLite databases and finalized artifact staging would collide.
#                           Requires macOS (the .tmp ACL for the share account is macOS-specific).
#                           Root-runner rule: in remote mode always invoke the ROOT
#                           checkout's copy of this script with -w <worktree>; a
#                           worktree's own copy may predate fixes like the engine-
#                           architecture probe (an older copy misreported an x86_64
#                           engine as aarch64, aborting the wheel check). The per-
#                           worktree lock, work volume and cache volume are keyed by
#                           the TARGET worktree path, not by which copy runs.
#   --                      Remaining args passed to pytest (system/test) or used as command separator (exec)
#
# Options (dump only):
#   -f, --function NAME     Pass --dump-function-pseudocode NAME
#   -m, --maturity LIST     Pass --dump-microcode-maturity LIST (comma-separated)
#   -p, --project NAME      Pass --dump-project NAME (JSON project name)
#   -o, --out FILE          Redirect stdout+stderr to WORK_DIR/.tmp/FILE; truncated each run. FILE must be one bare
#                           filename (e.g. dump.txt), with no slashes; the script prepends .tmp/.
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
#   Precedence: exported process environment > repository .env > defaults. A linked worktree
#   has no .env of its own, so the main checkout's .env (the parent of the shared common git
#   dir) is read instead; a worktree that does carry an .env still wins. Set D810_REPO_ROOT to
#   name the directory holding the .env explicitly.
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
#   D810_COBRA_HARNESS_WHEEL_SHA256  TEST HARNESS ONLY. One extra accepted wheel
#                          identity, so the unit tests can exercise wheel mode with a
#                          committed fixture instead of a multi-megabyte artifact that
#                          lives outside git. A run using it says so on stderr and in
#                          its preamble, and its receipt records the fixture hash,
#                          which matches no published artifact. Never set it to run
#                          real work.
#
#   CoBRA source precedence: an explicit D810_COBRA_WHEEL / D810_COBRA_ROOT wins;
#                          otherwise a BAKED image is used (one carrying the
#                          org.d810.cobra.* labels written by the image bake --
#                          nothing is installed, the baked install is only
#                          verified); otherwise the pinned remote source is
#                          cloned and compiled. Source compilation is a
#                          development fallback, never a silent recovery: a
#                          baked image whose label set is incomplete, whose
#                          wheel sha256 was never published, or whose recorded
#                          parent commit is not this script's pin aborts the run.
#   D810_DOCKER_MEMORY      Memory limit for container (default: 4g). OOM-kills if exceeded.
#   D810_REMOTE_DOCKER_HOST Remote engine host for --remote (the flag wins when both are given)
#   D810_REMOTE_VOLUME      Docker volume on the remote engine that exports the Mac's SMB share
#                           (default: idapro)
#   D810_REMOTE_SMB_SHARE   SMB share path used by the one-time setup helper (for example,
#                           //HOST/SHARE). The runner itself uses the resulting Docker volume.
#   D810_REMOTE_SMB_USER    Account the SMB share authenticates as, and the account the runner
#                           grants a .tmp-scoped ACL to. It must match the
#                           credential stored in the volume.
#   D810_REMOTE_SKIP_CLOCK_CHECK
#                           Downgrade the preflight engine-clock check to a warning (default: 0).
#                           The check aborts when the engine clock is more than 120 s off (5 s for a
#                           D810_NATIVE_PROFILE=1 timing leg): a skewed clock makes apt reject
#                           repository signatures and invalidates every duration the run reports.
#   D810_REMOTE_SHARE_ROOT  Absolute host directory that the SMB share exports
#                           Every mounted host path must live under it; the runner fails closed
#                           otherwise. Put machine-specific D810_REMOTE_* values in the ignored .env.
#
# Remote mode (one-time setup on the remote engine):
#   The volume is created once, by hand, with the stdlib helper (shell-agnostic: it reads the
#   password through getpass, never through a shell builtin):
#
#     python3 tools/scripts/setup_remote_test_volume.py
#     python3 tools/scripts/setup_remote_test_volume.py --dry-run   # print the redacted argv
#     python3 tools/scripts/setup_remote_test_volume.py --status    # what exists, password redacted
#     python3 tools/scripts/setup_remote_test_volume.py --remove [--force]  # delete it + the credential
#
#   Create refuses an existing volume (use --recreate); --remove refuses while containers still
#   reference it (use --force). Neither touches the Mac-side per-worktree run locks.
#
#   It runs `docker -H ssh://HOST volume create --driver local --opt type=cifs
#   --opt device=//SMB_HOST/SHARE --opt o=addr=SMB_HOST,username=SMB_USER,password=...,vers=3.0,
#   uid=0,gid=0,file_mode=0700,dir_mode=0700 idapro`.
#
#   All of those options are in-kernel cifs options (docker's local driver calls mount(2) directly,
#   so userspace-only mount.cifs options such as credentials= would NOT work). Verified against the
#   engine: this option string reaches the network layer ("connection refused" against a dead server),
#   while adding one unknown option makes the same mount fail with "invalid argument". The password is stored
#   in the volume's options and is therefore visible to `docker volume inspect` on the remote host:
#   that is the accepted trade for typing it once. Remove it with `docker volume rm idapro`.
#
#   The helper verifies a freshly created volume by mounting it read-only, and deletes it again if
#   that fails, so a credential that does not work is never left persisted. `mount(2)` reports every
#   authorization failure as the same "permission denied", so the helper also reads the engine's
#   kernel log and prints the CIFS status code, which is what actually distinguishes them:
#
#     0xc000006d STATUS_LOGON_FAILURE       password / NT hash mismatch: re-tick the account under
#                                           File Sharing > Options, re-enter the password, --recreate
#     0xc000006e STATUS_ACCOUNT_RESTRICTION account refused for this logon type (e.g. guest disabled)
#     0xc00000cc STATUS_BAD_NETWORK_NAME    the share name in device=//HOST/SHARE is wrong
#
#   `--status` runs the same probe read-only against an existing volume; `--no-verify` opts out.
#   `--status` also lists retained per-worktree runner volumes: those hold source copies and the
#   CoBRA cache, outlive `--remove`, and are deleted only with `--purge-work-volumes`. They are
#   selected by their exact supported role (d810.role=work or d810.role=cobra-cache), plus
#   d810.credential_volume=<volume> and d810.share_root_digest, so another share's volumes or an
#   unknown future role are never in scope; orphans are still reachable when the credential volume
#   is already gone.
#   An SMB password containing a comma is refused up front: the cifs `o=` value is comma-separated.
#
#   The option set deliberately omits nobrl, and --mount-opts REFUSES nobrl/nolock: in remote mode no
#   SQLite database is ever written on this mount. Live databases and logs stay on the work volume
#   (/work/runs/<run-id>/logs) and only finalized artifacts are copied to .tmp/logs afterwards, and
#   only when -l/--logs, --enable-debug-logging or --enable-diag-snapshot asked for them, so
#   byte-range locking here is never relied on. The mount's locking behaviour can still be measured
#   (evidence for the record, not a design input):
#
#     ./run_system_tests_docker.sh exec --remote HOST -w WT -- \
#       /app/ida/.venv/bin/python /work/tools/scripts/sqlite_cifs_probe.py
#
# Remote examples:
#   ./run_system_tests_docker.sh exec --remote -w my-worktree -- true
#   ./run_system_tests_docker.sh test --remote -w my-worktree -o remote.txt -- -q
#   # One container per worktree in parallel, with a measured sequential baseline:
#   python3 tools/scripts/remote_shard_bench.py --remote HOST \
#     --shard 'worktree-a=tests/system/e2e/x.py::case_a' --shard 'worktree-b=tests/system/e2e/x.py::case_b'
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
    D810_REMOTE_DOCKER_HOST|D810_REMOTE_SMB_SHARE|D810_REMOTE_SMB_USER|D810_REMOTE_SHARE_ROOT) printf '<redacted>' ;;
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
  # A linked worktree has its own top level but shares the main checkout's
  # ignored .env, which is where the machine-specific D810_REMOTE_* settings
  # live. Without this fallback `--remote` run from a worktree fails for want
  # of a host that is configured one directory up. The main checkout is the
  # parent of the shared common git dir; it is used only when it really
  # carries a .env, so a worktree with its own .env still wins.
  if [ -n "$DOTENV_ROOT" ] && [ ! -f "$DOTENV_ROOT/.env" ]; then
    _dotenv_common="$(git rev-parse --git-common-dir 2>/dev/null || true)"
    if [ -n "$_dotenv_common" ] && [ -d "$_dotenv_common" ]; then
      _dotenv_common="$(cd "$_dotenv_common" && pwd -P)"
      _dotenv_main="$(dirname "$_dotenv_common")"
      if [ "$_dotenv_main" != "$DOTENV_ROOT" ] && [ -f "$_dotenv_main/.env" ]; then
        DOTENV_ROOT="$_dotenv_main"
      fi
    fi
    unset _dotenv_common _dotenv_main
  fi
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

DOCKER_IMAGE="${D810_DOCKER_IMAGE-idapro-9.4}"
DOCKER_MEMORY="${D810_DOCKER_MEMORY-4g}"
NO_CYTHON="${D810_NO_CYTHON-1}"
CYTHON_PROFILE="${D810_CYTHON_PROFILE-0}"
NATIVE_PROFILE="${D810_NATIVE_PROFILE-0}"
TEST_BINARY="${D810_TEST_BINARY-libobfuscated.dll}"
SYSTEM_BATCH_SIZE="${D810_SYSTEM_BATCH_SIZE-20}"
# Remote execution is opt-in: the flag wins over the environment, and every
# value below only ever affects this wrapper (never the container environment).
CONFIGURED_REMOTE_HOST="${D810_REMOTE_DOCKER_HOST-}"
REMOTE_HOST=""
REMOTE_VOLUME="${D810_REMOTE_VOLUME-idapro}"
REMOTE_SHARE_ROOT="${D810_REMOTE_SHARE_ROOT-}"
REMOTE_SKIP_CLOCK_CHECK="${D810_REMOTE_SKIP_CLOCK_CHECK-0}"
REMOTE_CLOCK_OFFSET=""
# The run store survives the sync wipe so a run without artifact flags is not
# silently lost, which means it needs its own bound. Run ids start with a UTC
# timestamp, so a lexicographic sort is chronological.
REMOTE_RUN_RETENTION="${D810_REMOTE_RUN_RETENTION-20}"
REMOTE_SMB_USER="${D810_REMOTE_SMB_USER-}"
REMOTE_MODE=0
REMOTE_ENGINE_OS=""
REMOTE_ENGINE_ARCH=""
REMOTE_LOCK_DIR=""
WORK_SUBPATH=""
WORK_VOLUME=""
REMOTE_ARCHIVE=""
REMOTE_ARCHIVE_CONTAINER_PATH=""
COBRA_CACHE_VOLUME=""
COBRA_CACHE_VOLUME_STATE=""
REMOTE_TMP_PHYSICAL=""
SOURCE_DIGEST=""
SYNC_SENTINEL="/work/.d810-sync-ok"
# macOS normalizes requested rights, so the presence check compares against the
# normalized spelling that `ls -lde` prints back.
ACL_DIR_REQUEST="read,write,execute,delete,append,list,search,add_file,add_subdirectory,delete_child,readattr,writeattr,readextattr,writeextattr,readsecurity,file_inherit,directory_inherit"
ACL_DIR_NORMALIZED="list,add_file,search,delete,add_subdirectory,delete_child,readattr,writeattr,readextattr,writeextattr,readsecurity,file_inherit,directory_inherit"
ACL_FILE_REQUEST="read,write,execute,delete,append,readattr,writeattr,readextattr,writeextattr,readsecurity"
ACL_FILE_NORMALIZED="read,write,execute,delete,append,readattr,writeattr,readextattr,writeextattr,readsecurity"
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
# Every value that identifies a published d810-cobra artifact -- both wheel
# hashes, the release version, the tag and core commits, and the source
# revision this script pins -- is read from ONE tracked file, which the image
# bake (docker/cobra-bake/cobra_identity.sh) and the tests of both read too.
# Re-declaring any of them here is how a wheel rotation silently desyncs the
# runner from the image that was built for it.
#
# The file is data, not shell: it is parsed, never sourced, so a malformed row
# fails closed instead of executing.
COBRA_IDENTITY_FILE="$(cd "$(dirname "$0")/../.." && pwd -P)/docker/cobra-bake/published_identity"
COBRA_RECORDED_WHEELS=""
COBRA_SOURCE_REVISION=""
COBRA_CORE_SOURCE_REVISION=""
_cobra_load_published_identity() {
  local arch sha version tag core parent wheel rows=0
  if [ ! -r "$COBRA_IDENTITY_FILE" ]; then
    echo "ERROR: the published d810-cobra identity is unreadable: $COBRA_IDENTITY_FILE" >&2
    echo "       Every accepted wheel hash and the pinned source revision come from that file; without it no CoBRA identity can be checked." >&2
    exit 1
  fi
  while read -r arch sha version tag core parent wheel; do
    case "$arch" in ""|\#*) continue ;; esac
    case "$arch" in
      aarch64|x86_64) ;;
      *)
        echo "ERROR: unsupported architecture in $COBRA_IDENTITY_FILE: $arch" >&2
        exit 1
        ;;
    esac
    if [[ ! "$sha" =~ ^[0-9a-f]{64}$ ]] || [ -z "$wheel" ] \
      || [[ ! "$tag" =~ ^[0-9a-f]{40}$ ]] || [[ ! "$core" =~ ^[0-9a-f]{40}$ ]] \
      || [[ ! "$parent" =~ ^[0-9a-f]{40}$ ]] || [ -z "$version" ]; then
      echo "ERROR: malformed row in $COBRA_IDENTITY_FILE: $arch $sha" >&2
      exit 1
    fi
    # Every row describes the same release; a row that disagrees is exactly
    # the drift this file exists to prevent, so refuse rather than pick one.
    if [ -n "$COBRA_SOURCE_REVISION" ] \
      && { [ "$parent" != "$COBRA_SOURCE_REVISION" ] || [ "$core" != "$COBRA_CORE_SOURCE_REVISION" ]; }; then
      echo "ERROR: $COBRA_IDENTITY_FILE describes more than one release" >&2
      exit 1
    fi
    COBRA_SOURCE_REVISION="$parent"
    COBRA_CORE_SOURCE_REVISION="$core"
    COBRA_RECORDED_WHEELS="${COBRA_RECORDED_WHEELS:+$COBRA_RECORDED_WHEELS
}$sha $version|$arch|$tag|$core"
    rows=$((rows + 1))
  done < "$COBRA_IDENTITY_FILE"
  if [ "$rows" -eq 0 ]; then
    echo "ERROR: $COBRA_IDENTITY_FILE names no published d810-cobra wheel" >&2
    exit 1
  fi
}
_cobra_load_published_identity
COBRA_EXTENSION_ENABLED=1
COBRA_SOURCE_MODE="pinned-remote"
COBRA_PARENT_SOURCE_ID="$COBRA_SOURCE_REVISION"
COBRA_CORE_SOURCE_ID="$COBRA_CORE_SOURCE_REVISION"
# A baked image carries the published wheel and says so in its labels, written
# by docker/cobra-bake. Reading them is how this script learns it has nothing
# to install; they are filled in by _detect_baked_cobra once DOCKER_HOST names
# the engine that will actually run the container.
COBRA_BAKED_VERSION=""
COBRA_BAKED_WHEEL_SHA256=""
COBRA_BAKED_TAG_COMMIT=""
COBRA_BAKED_CORE_COMMIT=""
COBRA_BAKED_PARENT_COMMIT=""

# A harness fixture has no release behind it, so its record names none: the
# version and architecture come from the filename pip will read, and the
# commit columns say what the artifact is instead of naming a real revision.
_cobra_harness_wheel_record() {
  local basename version platform arch
  basename="$(basename "$1")"
  if [[ ! "$basename" =~ ^d810_cobra-([0-9A-Za-z.]+)-cp313-cp313-([0-9A-Za-z._]+)\.whl$ ]]; then
    echo "ERROR: D810_COBRA_HARNESS_WHEEL_SHA256 needs a d810_cobra-<version>-cp313-cp313-<platform>.whl basename: $basename" >&2
    return 1
  fi
  version="${BASH_REMATCH[1]}"
  platform="${BASH_REMATCH[2]}"
  case "$platform" in
    *aarch64*) arch="aarch64" ;;
    *x86_64*)  arch="x86_64" ;;
    *)
      echo "ERROR: harness fixture platform tag $platform names neither aarch64 nor x86_64: $basename" >&2
      return 1
      ;;
  esac
  printf '%s|%s|harness-fixture|harness-fixture' "$version" "$arch"
}

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
# "published" or "harness-fixture" - the word the preamble and the error
# messages use, so a fixture can never read as a production artifact.
COBRA_WHEEL_IDENTITY="published"
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
    # The published wheels are megabytes and live outside git, so the unit
    # tests would otherwise have to skip every positive wheel-mode case -- and
    # a skipped test cannot catch the deletion of the directory it needs. This
    # admits ONE extra identity, named explicitly by the harness, and marks
    # every artifact of the run as a fixture rather than a published wheel.
    if [ -n "${D810_COBRA_HARNESS_WHEEL_SHA256:-}" ] \
      && [ "$D810_COBRA_HARNESS_WHEEL_SHA256" = "$D810_COBRA_WHEEL_SHA256" ]; then
      COBRA_WHEEL_RECORD="$(_cobra_harness_wheel_record "$D810_COBRA_WHEEL")" || exit 1
      COBRA_WHEEL_IDENTITY="harness-fixture"
      echo "WARNING: D810_COBRA_HARNESS_WHEEL_SHA256 accepted $D810_COBRA_WHEEL as a TEST HARNESS fixture; it is not a published d810-cobra artifact and this run must not be treated as one" >&2
    else
      echo "ERROR: D810_COBRA_WHEEL_SHA256 $D810_COBRA_WHEEL_SHA256 is not a recorded d810-cobra wheel; the accepted published wheels live in _gitless/resource/cobra-wheels/0.1.5-published/ (an identical filename does not imply identical bytes)" >&2
      exit 1
    fi
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
  # the recorded wheels is installable. That question can only be asked once
  # the engine is known, and --remote picks the engine while parsing arguments,
  # which happens after this block: the probe therefore runs later, from
  # _verify_cobra_wheel_engine_arch, against the engine that will actually run
  # the container.
  COBRA_WHEEL_ARCH_CHECK_PENDING=1
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
if [ "$CMD" != "system" ] && [ "$CMD" != "test" ] && [ "$CMD" != "dump" ] && [ "$CMD" != "shell" ] && [ "$CMD" != "exec" ] && [ "$CMD" != "artifacts" ]; then
  if [ "$CMD" = "-h" ] || [ "$CMD" = "--help" ]; then
    sed -n '2,/^set -e$/p' "$0" | sed '$d'
    exit 0
  fi
  echo "Usage: $0 system | test | dump [OPTIONS] [-- PYTEST_ARGS...] | shell | exec [OPTIONS] -- COMMAND [ARGS...] | artifacts --remote HOST -w WORKTREE [--run RUN_ID]" >&2
  echo "Commands: system | test | dump | shell | exec | artifacts" >&2
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
DUMP_OUT_SET=0
MOUNT_LOGS=""
ENABLE_DEBUG_LOGGING=""
ENABLE_DIAG_SNAPSHOT=""
ENABLE_LLVM_OPT=""
DISABLE_FACT_LIFECYCLE=""
ARTIFACT_RUN=""
START_BATCH=""
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
      if [ $# -lt 2 ]; then
        echo "ERROR: -o/--out requires one bare filename" >&2
        exit 1
      fi
      DUMP_OUT="$2"
      DUMP_OUT_SET=1
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
    --run)
      if [ $# -lt 2 ] || [ -z "$2" ]; then
        echo "ERROR: --run requires a RUN_ID" >&2
        exit 1
      fi
      ARTIFACT_RUN="$2"
      shift 2
      ;;
    --start-batch)
      # Spliced verbatim into the batcher's argv, so it must be exactly a
      # positive integer (^[1-9][0-9]*$) and nothing else: empty, non-digit,
      # or leading-zero values are all refused before any docker contact.
      if [ $# -lt 2 ]; then
        echo "ERROR: --start-batch requires N (positive integer batch number)" >&2
        exit 2
      fi
      case "$2" in
        ''|*[!0-9]*|0*)
          echo "ERROR: --start-batch must be a positive integer (e.g. 7), got '$2'" >&2
          exit 2
          ;;
      esac
      if [ "$CMD" != "system" ]; then
        echo "ERROR: --start-batch is only valid with the system command" >&2
        exit 2
      fi
      START_BATCH="$2"
      shift 2
      ;;
    --remote)
      if [ $# -ge 2 ] && [ -n "$2" ] && [ "${2#-}" = "$2" ]; then
        REMOTE_HOST="$2"
        shift 2
      elif [ -n "$CONFIGURED_REMOTE_HOST" ]; then
        REMOTE_HOST="$CONFIGURED_REMOTE_HOST"
        shift
      else
        echo "ERROR: --remote requires HOST or D810_REMOTE_DOCKER_HOST in .env" >&2
        exit 1
      fi
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

# Output captures are intentionally confined to .tmp. Validate before remote
# setup, which otherwise acquires a lock, creates .tmp, and talks to Docker.
if [ "$DUMP_OUT_SET" = "1" ]; then
  case "$DUMP_OUT" in
    ''|.|..|*/*)
      echo "ERROR: -o/--out must be one bare filename (not empty, . or .., and no /)" >&2
      exit 1
      ;;
  esac
fi

# The run id is interpolated into a container command that copies between two
# fixed directories, so it must name one entry inside them and nothing else: a
# path separator escapes both, and a quote would terminate the interpolation.
# Same standard as -o above, and validated before any Docker contact.
if [ -n "$ARTIFACT_RUN" ]; then
  case "$ARTIFACT_RUN" in
    .|..|*/*|*[!A-Za-z0-9._-]*)
      echo "ERROR: --run must be one bare run id (letters, digits, . _ - only; no /)" >&2
      exit 1
      ;;
  esac
fi

# The retention bound is spliced into the container payload as the operand of
# "head -n -N", so it has to be a count and nothing else: a non-numeric value
# is shell injection, an empty one silently disables the prune (${VAR-20} does
# not substitute for a value that is set but empty), and 0 makes "head -n -0"
# print every run and delete the lot.
case "$REMOTE_RUN_RETENTION" in
  ''|0*|*[!0-9]*)
    echo "ERROR: D810_REMOTE_RUN_RETENTION must be a positive integer (>= 1), got '$REMOTE_RUN_RETENTION'" >&2
    exit 2
    ;;
esac

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

REMOTE_MANIFEST=""
REMOTE_ARCHIVE_DIR=""
_cleanup_remote_manifest() {
  [ -n "$REMOTE_MANIFEST" ] || return 0
  case "$REMOTE_MANIFEST" in */.tmp/remote-manifest.*) rm -f "$REMOTE_MANIFEST" ;; esac
}

_cleanup_remote_archive() {
  [ -n "$REMOTE_ARCHIVE_DIR" ] || return 0
  case "$REMOTE_ARCHIVE_DIR" in */.tmp/remote-src.*) rm -rf "$REMOTE_ARCHIVE_DIR" ;; esac
}

_d810_exit_cleanup() {
  _cleanup_remote_archive
  _cleanup_remote_manifest
  _release_remote_lock
  _cleanup_cobra_source_artifact
}
trap _d810_exit_cleanup EXIT

# Remote mode reaches host files through one SMB-backed Docker volume, so every
# mounted path must be expressible as a subpath of the exported share root.
_share_relative_path() {
  local host_path="$1" resolved relative parent
  if [ -d "$host_path" ] && [ ! -L "$host_path" ]; then
    resolved="$(cd "$host_path" 2>/dev/null && pwd -P)" || true
  elif [ -f "$host_path" ] && [ ! -L "$host_path" ]; then
    # A mounted file -- the recorded CoBRA wheel is the only one -- resolves
    # through its parent: `cd` takes directories, and the basename has to
    # survive because pip reads the artifact's identity from the filename.
    # A symlink is refused on either side so the physical bytes the engine
    # reaches through the share are the bytes named here.
    parent="$(cd "$(dirname "$host_path")" 2>/dev/null && pwd -P)" || true
    [ -n "$parent" ] && resolved="$parent/$(basename "$host_path")"
  fi
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

# What a worktree would actually run: HEAD alone is not enough, because a
# worktree carries uncommitted edits and untracked files that the sync mirrors.
_source_digest() {
  local directory="$1"
  {
    GIT_NO_REPLACE_OBJECTS=1 git -C "$directory" rev-parse HEAD 2>/dev/null || echo no-head
    GIT_NO_REPLACE_OBJECTS=1 git -C "$directory" status --porcelain=v1 -z 2>/dev/null | tr '\0' '\n'
    GIT_NO_REPLACE_OBJECTS=1 git -C "$directory" diff HEAD 2>/dev/null
    GIT_NO_REPLACE_OBJECTS=1 git -C "$directory" ls-files --others --exclude-standard -z 2>/dev/null \
      | tr '\0' '\n' \
      | while IFS= read -r relative; do
          [ -n "$relative" ] || continue
          printf '%s\n' "$relative"
          [ -f "$directory/$relative" ] && shasum -a 256 "$directory/$relative" 2>/dev/null
        done
  } | shasum -a 256 | cut -c1-16
}

# The archive contents come from git's own view of the worktree, never from a
# directory walk: ignored files are secrets and stale build state, and they are
# not covered by the source digest either.
MANIFEST_EXCLUDE_PATTERN='^\.tmp/|^\.tmp$|(^|/)__pycache__/|(^|/)\.pytest_cache/|(^|/)\.mypy_cache/|(^|/)\.ruff_cache/|(^|/)build/|\.egg-info(/|$)|\.so$|\.pyd$|^\.git$'
REMOTE_MANIFEST_EXTRA="$(cd "$(dirname "$0")" && pwd -P)/remote_manifest_extra.txt"
REMOTE_MANIFEST_EXTRA_ENTRIES=""

_manifest_from_git() {
  # Paths are emitted NUL-separated by git; the filter round-trips through
  # newlines, which is safe here because no tracked path contains one.
  {
    GIT_NO_REPLACE_OBJECTS=1 git -C "$WORK_DIR" ls-files -z
    GIT_NO_REPLACE_OBJECTS=1 git -C "$WORK_DIR" ls-files --others --exclude-standard -z
  } | tr '\0' '\n' | grep -v -E "$MANIFEST_EXCLUDE_PATTERN" | LC_ALL=C sort -u | tr '\n' '\0'
}

_append_manifest_allowlist() {
  local manifest="$1" line
  [ -f "$REMOTE_MANIFEST_EXTRA" ] || {
    echo "ERROR: remote allowlist file is missing: $REMOTE_MANIFEST_EXTRA" >&2
    exit 1
  }
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ""|\#*) continue ;; esac
    if [ "$line" = ".env" ] || [ "${line##*/}" = ".env" ]; then
      echo "ERROR: $REMOTE_MANIFEST_EXTRA must never list .env" >&2
      exit 1
    fi
    if [ ! -e "$WORK_DIR/$line" ]; then
      echo "ERROR: allowlisted path does not exist in the worktree: $line" >&2
      exit 1
    fi
    if ! GIT_NO_REPLACE_OBJECTS=1 git -C "$WORK_DIR" check-ignore -q "$line"; then
      echo "ERROR: allowlisted path is not ignored by git (it is already archived): $line" >&2
      exit 1
    fi
    printf '%s\0' "$line" >> "$manifest"
    REMOTE_MANIFEST_EXTRA_ENTRIES="$REMOTE_MANIFEST_EXTRA_ENTRIES $line"
  done < "$REMOTE_MANIFEST_EXTRA"
}

_build_remote_manifest() {
  local manifest="$1"
  _manifest_from_git > "$manifest"
  _append_manifest_allowlist "$manifest"
}

# Hashing the tree and then streaming it leaves a window in which an edit lands
# between the two, so the sentinel would name bytes other than the ones that
# ran. Materialize an immutable archive first and derive the digest from the
# archive itself: the member list followed by the concatenated member contents,
# in archive order, which is content-based and independent of mtimes.
_materialize_remote_archive() {
  local manifest="$1" archive="$2"
  if ! tar -C "$WORK_DIR" --null -T "$manifest" -cf "$archive"; then
    echo "ERROR: could not build the remote source archive: $archive" >&2
    exit 1
  fi
}

_archive_digest() {
  local archive="$1"
  {
    tar -tf "$archive"
    tar -xOf "$archive"
  } | shasum -a 256 | cut -c1-16
}

# One volume per worktree PATH: two worktrees can share a basename under
# different roots, and they must never share a source copy.
_work_volume_name() {
  local path="$1" sanitized digest
  sanitized="$(printf '%s' "$(basename "$path")" | tr -c 'A-Za-z0-9_.-' '-' | cut -c1-40)"
  digest="$(printf '%s' "$path" | shasum -a 256 | cut -c1-8)"
  printf 'd810-work-%s-%s' "$sanitized" "$digest"
}

WORK_VOLUME_STATE=""
_ensure_engine_volume() {
  local name="$1" role="$2" state_variable="$3"
  if docker volume inspect "$name" >/dev/null 2>&1; then
    eval "$state_variable=existing"
    return 0
  fi
  if ! docker volume create \
      --label "d810.role=$role" \
      --label "d810.worktree=$(basename "$WORK_DIR")" \
      --label "d810.share_root_digest=$(printf '%s' "$REMOTE_SHARE_ROOT" | shasum -a 256 | cut -c1-8)" \
      --label "d810.credential_volume=$REMOTE_VOLUME" \
      "$name" >/dev/null; then
    echo "ERROR: could not create $role volume $name on ssh://$REMOTE_HOST" >&2
    exit 1
  fi
  eval "$state_variable=created"
}

_ensure_work_volume() {
  _ensure_engine_volume "$WORK_VOLUME" work WORK_VOLUME_STATE
}

# The share account is read-only everywhere except the ACL below, which is
# scoped to .tmp: the source tree, .git and the share root must never become
# writable for it.
_acl_target_is_scoped() {
  local target="$1" physical parent
  case "$target" in
    "$WORK_DIR"/.tmp|"$WORK_DIR"/.tmp/*) ;;
    *) return 1 ;;
  esac
  [ -n "$REMOTE_TMP_PHYSICAL" ] && [ ! -L "$target" ] || return 1
  if [ -d "$target" ]; then
    physical="$(cd "$target" && pwd -P)" || return 1
  else
    parent="$(dirname "$target")"
    physical="$(cd "$parent" && pwd -P)/$(basename "$target")" || return 1
  fi
  case "$physical" in
    "$REMOTE_TMP_PHYSICAL"|"$REMOTE_TMP_PHYSICAL"/*) return 0 ;;
    *) return 1 ;;
  esac
}

_acl_entry_rights() {
  local account="${2:-$REMOTE_SMB_USER}"
  ls -lde "$1" 2>/dev/null | sed -n "s/^ *[0-9]*: *user:$account allow //p" | head -1
}

_acl_drop_user_entries() {
  local target="$1" account="${2:-$REMOTE_SMB_USER}" index
  while :; do
    index="$(ls -lde "$target" 2>/dev/null | sed -n "s/^ *\([0-9]*\): *user:$account .*/\1/p" | head -1)"
    [ -n "$index" ] || break
    chmod -a# "$index" "$target" || break
  done
}

_ensure_acl() {
  local target="$1" kind="$2" account="${3:-$REMOTE_SMB_USER}" strict="${4:-0}" request normalized present right missing=0
  if ! _acl_target_is_scoped "$target"; then
    echo "ERROR: refusing to grant $REMOTE_SMB_USER access outside the worktree .tmp: $target" >&2
    exit 1
  fi
  if [ ! -e "$target" ]; then
    if [ "$strict" = "1" ]; then
      echo "ERROR: required ACL target is missing: $target" >&2
      exit 1
    fi
    return 0
  fi
  if [ "$kind" = "dir" ]; then
    request="$ACL_DIR_REQUEST"
    normalized="$ACL_DIR_NORMALIZED"
  else
    request="$ACL_FILE_REQUEST"
    normalized="$ACL_FILE_NORMALIZED"
  fi
  present="$(_acl_entry_rights "$target" "$account")"
  if [ -n "$present" ]; then
    for right in ${normalized//,/ }; do
      case ",$present," in
        *",$right,"*) ;;
        *) missing=1 ;;
      esac
    done
    if [ "$missing" = "0" ]; then
      return 0
    fi
    # Present but incomplete: repair by replacing this user's entries only.
    _acl_drop_user_entries "$target" "$account"
  fi
  if ! chmod +a "$account allow $request" "$target"; then
    if [ "$strict" = "1" ]; then
      echo "ERROR: could not grant $account access to $target" >&2
      exit 1
    fi
    # A descendant created by the other account cannot have its ACL changed
    # from here. Inheritance from .tmp covers everything created from now on.
    echo "[remote] note: leaving existing ACL on $target (not owned here)" >&2
  fi
}

_apply_tmp_acls() {
  local account capture
  # Files the container creates are owned by the share account with 0600, so
  # without an inheritable ACE for the invoking user its own artifacts - the -o
  # capture above all - come back unreadable on this Mac.
  local local_account
  local_account="$(id -un)"
  for account in "$REMOTE_SMB_USER" "$local_account"; do
    # The .tmp root must carry the inheritable entries or nothing else can.
    _ensure_acl "$WORK_DIR/.tmp" dir "$account" 1
    # Finalized remote artifacts are copied into .tmp/logs/<run-id>, so this
    # pre-existing directory is required rather than a best-effort descendant.
    _ensure_acl "$WORK_DIR/.tmp/logs" dir "$account" 1
  done
  # A capture from an earlier run is owned by the share account and cannot be
  # re-ACLed from here; it is rewritten anyway, so remove it and let the new
  # file inherit both entries.
  capture="$WORK_DIR/.tmp/$DUMP_OUT"
  if [ -n "$DUMP_OUT" ] && { [ -e "$capture" ] || [ -L "$capture" ]; }; then
    rm -f -- "$capture"
  fi
}

_validate_remote_artifact_dirs() {
  local tmp="$WORK_DIR/.tmp" logs="$WORK_DIR/.tmp/logs" work_physical logs_physical
  work_physical="$(cd "$WORK_DIR" && pwd -P)" || {
    echo "ERROR: cannot resolve worktree for remote artifacts: $WORK_DIR" >&2
    exit 1
  }
  if [ -L "$tmp" ] || { [ -e "$tmp" ] && [ ! -d "$tmp" ]; }; then
    echo "ERROR: remote artifact directory must be a real directory inside the worktree: $tmp" >&2
    exit 1
  fi
  [ -d "$tmp" ] || mkdir "$tmp"
  REMOTE_TMP_PHYSICAL="$(cd "$tmp" && pwd -P)" || {
    echo "ERROR: cannot resolve remote artifact directory: $tmp" >&2
    exit 1
  }
  if [ "$REMOTE_TMP_PHYSICAL" != "$work_physical/.tmp" ]; then
    echo "ERROR: remote artifact directory must stay inside the worktree: $tmp" >&2
    exit 1
  fi
  if [ -L "$logs" ] || { [ -e "$logs" ] && [ ! -d "$logs" ]; }; then
    echo "ERROR: remote artifact directory must be a real directory inside the worktree: $logs" >&2
    exit 1
  fi
  [ -d "$logs" ] || mkdir "$logs"
  logs_physical="$(cd "$logs" && pwd -P)" || {
    echo "ERROR: cannot resolve remote artifact directory: $logs" >&2
    exit 1
  }
  if [ "$logs_physical" != "$REMOTE_TMP_PHYSICAL/logs" ]; then
    echo "ERROR: remote artifact directory must stay inside the worktree: $logs" >&2
    exit 1
  fi
}

_acquire_remote_lock() {
  local lock_dir="$WORK_DIR/.tmp/remote-run.lock" holder=""
  if ! mkdir "$lock_dir" 2>/dev/null; then
    [ -f "$lock_dir/owner" ] && holder="$(cat "$lock_dir/owner" 2>/dev/null || true)"
    echo "ERROR: another remote run already owns this worktree: $WORK_DIR" >&2
    echo "       lock:   $lock_dir" >&2
    echo "       holder: ${holder:-unknown}" >&2
    echo "       Wait for it to finish, or remove a stale lock with: rm -rf '$lock_dir'" >&2
    exit 1
  fi
  REMOTE_LOCK_DIR="$lock_dir"
  printf 'pid=%s started=%s\n' \
    "$$" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$lock_dir/owner"
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
  _remote_check_engine_clock
}

# A skewed engine clock is not a cosmetic problem: apt rejects repository
# signatures as "created after the --not-after date", which is what took the
# CoBRA toolchain down, and every duration a timing leg reports is measured
# against it. Cheap to measure, so measure it before anything depends on it.
_remote_check_engine_clock() {
  local before after engine_epoch midpoint tolerance=120 absolute
  if [ "$NATIVE_PROFILE" = "1" ]; then
    # A timing leg compares durations across hosts; seconds matter there.
    tolerance=5
  fi
  before="$(date -u +%s)"
  if ! engine_epoch="$(docker run --rm --entrypoint /bin/date "$DOCKER_IMAGE" -u +%s 2>/dev/null)"; then
    engine_epoch=""
  fi
  after="$(date -u +%s)"
  case "$engine_epoch" in
    ''|*[!0-9]*)
      echo "ERROR: cannot read the remote engine clock through $DOCKER_IMAGE" >&2
      exit 1
      ;;
  esac
  midpoint=$(( (before + after) / 2 ))
  REMOTE_CLOCK_OFFSET=$(( engine_epoch - midpoint ))
  absolute=${REMOTE_CLOCK_OFFSET#-}
  printf '[remote] engine clock offset: %s s (tolerance %s s)\n' "$REMOTE_CLOCK_OFFSET" "$tolerance"
  if [ "$absolute" -le "$tolerance" ]; then
    return 0
  fi
  if [ "$REMOTE_SKIP_CLOCK_CHECK" = "1" ]; then
    echo "WARNING: engine clock offset ${REMOTE_CLOCK_OFFSET}s exceeds ${tolerance}s; continuing because D810_REMOTE_SKIP_CLOCK_CHECK=1" >&2
    return 0
  fi
  echo "ERROR: engine clock offset ${REMOTE_CLOCK_OFFSET}s exceeds the ${tolerance}s tolerance" >&2
  echo "       resync the engine VM clock (Docker Desktop: restart it, or \`hwclock -s\` in a privileged container) and re-run" >&2
  echo "       set D810_REMOTE_SKIP_CLOCK_CHECK=1 to downgrade this to a warning" >&2
  exit 1
}

# The CoBRA wheel is native code, so it must match the engine that will run it,
# not this machine: --remote points DOCKER_HOST at another architecture. Every
# caller reaches this only after DOCKER_HOST is final.
#
# Both published-wheel paths use it. An explicit wheel is named by the
# operator; a baked one is named by the image's labels, whose recorded hash
# identifies the architecture just as precisely. Either way the check is one
# `docker version` BEFORE any container starts -- the in-container assertion
# is a backstop, and reaching it means a setup container was started for a
# wheel that could never have imported.
COBRA_WHEEL_ARCH_SUBJECT="D810_COBRA_WHEEL"
_verify_cobra_wheel_engine_arch() {
  [ "${COBRA_WHEEL_ARCH_CHECK_PENDING:-0}" = "1" ] || return 0
  COBRA_WHEEL_ARCH_CHECK_PENDING=0
  COBRA_DOCKER_SERVER_ARCH="$(docker version --format '{{.Server.Arch}}' 2>/dev/null || true)"
  case "$COBRA_DOCKER_SERVER_ARCH" in
    arm64) COBRA_DOCKER_ENGINE_ARCH="aarch64" ;;
    amd64) COBRA_DOCKER_ENGINE_ARCH="x86_64" ;;
    *)
      echo "ERROR: $COBRA_WHEEL_ARCH_SUBJECT needs a known Docker engine architecture; docker version --format '{{.Server.Arch}}' returned '$COBRA_DOCKER_SERVER_ARCH' (expected arm64 or amd64)" >&2
      exit 1
      ;;
  esac
  if [ "$COBRA_DOCKER_ENGINE_ARCH" != "$COBRA_WHEEL_ARCH" ]; then
    echo "ERROR: $COBRA_WHEEL_ARCH_SUBJECT is a $COBRA_WHEEL_ARCH wheel but the Docker engine is $COBRA_DOCKER_ENGINE_ARCH (docker server arch $COBRA_DOCKER_SERVER_ARCH); use the recorded $COBRA_DOCKER_ENGINE_ARCH wheel" >&2
    exit 1
  fi
}

# A baked image already carries the published wheel, installed and verified at
# image build time. Its labels are the claim; the in-container verification
# below is the proof, and it stays a hard setup precondition either way.
#
# Read on the engine that will RUN the container: --remote points DOCKER_HOST
# at another machine whose image of the same tag may be a different build.
_cobra_baked_labels() {
  docker image inspect --format \
    '{{ index .Config.Labels "org.d810.cobra.version" }}|{{ index .Config.Labels "org.d810.cobra.wheel_sha256" }}|{{ index .Config.Labels "org.d810.cobra.tag_commit" }}|{{ index .Config.Labels "org.d810.cobra.core_commit" }}|{{ index .Config.Labels "org.d810.cobra.parent_commit" }}' \
    "$DOCKER_IMAGE" 2>/dev/null || true
}

_detect_baked_cobra() {
  [ "$COBRA_EXTENSION_ENABLED" = "1" ] || return 0
  # An explicit wheel or checkout is the operator speaking; it outranks
  # whatever the image happens to carry.
  [ "$COBRA_SOURCE_MODE" = "pinned-remote" ] || return 0

  local raw version sha tag core parent index missing=""
  local -a values names=(version wheel_sha256 tag_commit core_commit parent_commit)
  raw="$(_cobra_baked_labels)"
  IFS='|' read -r version sha tag core parent <<< "$raw"
  values=("$version" "$sha" "$tag" "$core" "$parent")
  # A missing label prints as an empty string, but a missing Labels map prints
  # Go's placeholder; neither is a claim.
  for index in 0 1 2 3 4; do
    case "${values[$index]}" in "<no value>") values[$index]="" ;; esac
  done
  version="${values[0]}" sha="${values[1]}" tag="${values[2]}"
  core="${values[3]}" parent="${values[4]}"

  if [ -z "$version$sha$tag$core$parent" ]; then
    # No claim at all: a vanilla image, or one built before the bake existed.
    return 0
  fi

  for index in 0 1 2 3 4; do
    [ -n "${values[$index]}" ] || missing="$missing org.d810.cobra.${names[$index]}"
  done
  if [ -n "$missing" ]; then
    echo "ERROR: $DOCKER_IMAGE claims a baked d810-cobra but its label set is incomplete; missing:$missing" >&2
    echo "       A partially labelled image is the state in which a run would believe a published wheel is installed when nothing is." >&2
    echo "       Rebuild it with tools/scripts/build_ida_images.sh, or set D810_COBRA_WHEEL to install a published wheel explicitly." >&2
    exit 1
  fi

  local record
  if ! record="$(_cobra_recorded_wheel_record "$sha")"; then
    echo "ERROR: $DOCKER_IMAGE declares org.d810.cobra.wheel_sha256 $sha, which is not a published d810-cobra wheel" >&2
    echo "       The accepted artifacts are the published PyPI wheels; the preflight builds carry the same filenames and sizes and are refused." >&2
    exit 1
  fi
  local record_version record_arch record_tag record_core tail
  record_version="${record%%|*}"
  tail="${record#*|}"
  record_arch="${tail%%|*}"
  tail="${tail#*|}"
  record_tag="${tail%%|*}"
  record_core="${tail#*|}"

  if [ "$version" != "$record_version" ] || [ "$tag" != "$record_tag" ] || [ "$core" != "$record_core" ]; then
    echo "ERROR: $DOCKER_IMAGE labels disagree with the published record for wheel $sha" >&2
    echo "       image:     version $version tag $tag core $core" >&2
    echo "       published: version $record_version tag $record_tag core $record_core" >&2
    exit 1
  fi

  # The bake and this script must describe the same upstream code, or a baked
  # run and a source-built run are not comparable measurements.
  if [ "$parent" != "$COBRA_SOURCE_REVISION" ]; then
    echo "ERROR: $DOCKER_IMAGE was baked against d810-cobra parent commit $parent, but this runner pins $COBRA_SOURCE_REVISION" >&2
    echo "       Rebuild the image from the pinned revision, or update COBRA_SOURCE_REVISION with the bake." >&2
    exit 1
  fi

  COBRA_SOURCE_MODE="baked"
  COBRA_BAKED_VERSION="$version"
  COBRA_BAKED_WHEEL_SHA256="$sha"
  COBRA_BAKED_TAG_COMMIT="$tag"
  COBRA_BAKED_CORE_COMMIT="$core"
  COBRA_BAKED_PARENT_COMMIT="$parent"
  # The container-side assertions are shared with wheel mode and read these.
  COBRA_WHEEL_VERSION="$version"
  COBRA_WHEEL_ARCH="$record_arch"
  COBRA_WHEEL_SHA256="$sha"
  COBRA_PARENT_SOURCE_ID="$tag"
  COBRA_CORE_SOURCE_ID="$core"

  # The baked wheel is native code too. Its architecture comes from the
  # published record for the hash the image declares, so it is known here,
  # before anything is started -- refuse at the cheap `docker version` stage
  # rather than inside a setup container that can only fail to import.
  COBRA_WHEEL_ARCH_SUBJECT="the d810-cobra wheel baked into $DOCKER_IMAGE"
  COBRA_WHEEL_ARCH_CHECK_PENDING=1
  _verify_cobra_wheel_engine_arch
}

# The volume can exist and still not expose this checkout (wrong share, wrong
# subpath, unmounted CIFS). Prove reachability read-only before any real work.
_remote_probe_volume() {
  printf '[remote] probing subpath %s through volume %s\n' "$WORK_SUBPATH" "$REMOTE_VOLUME"
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
  if [ -z "$REMOTE_SHARE_ROOT" ]; then
    echo "ERROR: remote mode requires D810_REMOTE_SHARE_ROOT in the repository's ignored .env" >&2
    exit 1
  fi
  if [ -z "$REMOTE_SMB_USER" ]; then
    echo "ERROR: remote mode requires D810_REMOTE_SMB_USER in the repository's ignored .env" >&2
    exit 1
  fi
  # The account name is interpolated into the sed expressions that read and
  # repair the .tmp ACL, where a / or a regex metacharacter would silently
  # yield "no ACE present" and send the repair path round in circles. Same
  # allowlist the volume helper applies before the name reaches cifs.
  case "$REMOTE_SMB_USER" in
    *[!A-Za-z0-9._@-]*)
      echo "ERROR: D810_REMOTE_SMB_USER must match [A-Za-z0-9._@-]+ (it is used verbatim in ACL matching)" >&2
      exit 1
      ;;
  esac
  # The share ACL below is macOS-specific and the whole remote mode depends on
  # it, so refuse before touching Docker rather than half-way through.
  if [ "$(uname -s)" != "Darwin" ]; then
    echo "ERROR: remote mode needs the macOS share host (uname -s = Darwin); got $(uname -s)" >&2
    exit 1
  fi
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
  # Before the lock and the source archive: a wheel for the wrong engine is a
  # configuration error, not a run to clean up after.
  _verify_cobra_wheel_engine_arch
  # Same reason, same place: the remote engine's copy of this tag decides
  # whether anything has to be installed at all.
  _detect_baked_cobra
  _validate_remote_artifact_dirs
  # The lock still guards the shared read-write .tmp: -o captures, logs, diag
  # SQLite databases and finalized artifact staging all collide between runs.
  _acquire_remote_lock
  WORK_VOLUME="$(_work_volume_name "$WORK_DIR")"
  COBRA_CACHE_VOLUME="d810-cobra-${WORK_VOLUME#d810-work-}"
  _apply_tmp_acls
  # PIDs restart at 1 in every container, so a pid-keyed database name is not
  # unique across concurrent runs on one shared mount. This id is, and it is
  # forwarded to the container like every other D810_* variable.
  export D810_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$-$(printf '%s' "$WORK_DIR" | shasum -a 256 | cut -c1-6)"
  REMOTE_MANIFEST="$WORK_DIR/.tmp/remote-manifest.$$"
  _build_remote_manifest "$REMOTE_MANIFEST"
  REMOTE_ARCHIVE_DIR="$(mktemp -d "$WORK_DIR/.tmp/remote-src.XXXXXX")"
  REMOTE_ARCHIVE="$REMOTE_ARCHIVE_DIR/source.tar"
  _materialize_remote_archive "$REMOTE_MANIFEST" "$REMOTE_ARCHIVE"
  SOURCE_DIGEST="$(_archive_digest "$REMOTE_ARCHIVE")"
  REMOTE_ARCHIVE_CONTAINER_PATH="/work/.tmp/$(basename "$REMOTE_ARCHIVE_DIR")/source.tar"
  _ensure_acl "$REMOTE_ARCHIVE_DIR" dir
  _ensure_acl "$REMOTE_ARCHIVE" file
fi

if [ -z "$REMOTE_HOST" ]; then
  _verify_cobra_wheel_engine_arch
  _detect_baked_cobra
fi

# Two consumers key on the image's identity: the provenance receipt below and
# the CoBRA build cache marker. Both are stores that outlive the run, so a
# placeholder id is worse than no run at all - it produces a receipt that names
# no image and a marker no later run can match, silently forcing a rebuild on
# every subsequent run. Local mode has no image preflight and remote mode is
# only guarded against a PERSISTENT absence, so resolve strictly here.
_require_image_id() {
  local consumer="$1" resolved engine
  resolved="$(docker image inspect --format '{{.Id}}' "$DOCKER_IMAGE" 2>/dev/null || true)"
  case "$resolved" in
    sha256:?*)
      printf '%s' "$resolved"
      return 0
      ;;
  esac
  if [ "$REMOTE_MODE" = "1" ]; then
    engine="the configured remote engine"
  else
    engine="the local Docker engine"
  fi
  echo "ERROR: cannot resolve the image id of $DOCKER_IMAGE on $engine" >&2
  echo "       docker image inspect --format '{{.Id}}' returned: ${resolved:-<empty>} (expected a sha256: digest)" >&2
  echo "       $consumer is keyed by this id; continuing would record a placeholder that outlives the run." >&2
  exit 1
}

# Profile receipts need to identify the actual image that ran them. Keep this
# test-only metadata separate from the image-selection environment variable,
# which is deliberately wrapper-only and therefore not forwarded by default.
DOCKER_IMAGE_ID="$(_require_image_id "the provenance receipt D810_TEST_RUNTIME_IMAGE_ID")"

# Docker mount: host path -> container path (use variables so no host-specific paths in printed commands)
if [ "$REMOTE_MODE" = "1" ]; then
  # Source arrives read-only over SMB and is mirrored into a container-writable
  # volume, so builds (Cython .so, egg-info, pip) never write to the Mac tree.
  _ensure_work_volume
  DOCKER_MOUNTS+=(--mount "type=volume,src=${WORK_VOLUME},dst=/work")
  _add_mount "$WORK_DIR" /work-src ro
  _add_mount "$WORK_DIR/.tmp" /work/.tmp
else
  _add_mount "$WORK_DIR" /work
fi
ENV_GIT=""
GIT_COMMON_DIR="$(git -C "$WORK_DIR" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || true)"
GIT_WORKTREE_DIR="$(git -C "$WORK_DIR" rev-parse --path-format=absolute --git-dir 2>/dev/null || true)"
if [ -n "$GIT_COMMON_DIR" ] && [ -d "$GIT_COMMON_DIR" ]; then
  _add_mount "$GIT_COMMON_DIR" /d810-git ro
  ENV_GIT="GIT_DIR=/d810-git"
  # A linked worktree's .git is a FILE naming <common>/worktrees/<name> as a
  # macOS path, so GIT_DIR=/d810-git alone resolves the MAIN checkout's HEAD.
  # The per-worktree git dir already lives INSIDE the mounted common dir, and
  # its commondir file is the relative "../.." - which only resolves correctly
  # when GIT_DIR keeps that same relative position. Naming it inside the common
  # mount therefore needs no second mount and no explicit GIT_COMMON_DIR (the
  # commondir file wins over the environment variable anyway).
  if [ "$REMOTE_MODE" = "1" ] \
    && [ -n "$GIT_WORKTREE_DIR" ] \
    && [ "$GIT_WORKTREE_DIR" != "$GIT_COMMON_DIR" ] \
    && [ -d "$GIT_WORKTREE_DIR" ]; then
    GIT_WORKTREE_REL="${GIT_WORKTREE_DIR#"$GIT_COMMON_DIR"/}"
    if [ "$GIT_WORKTREE_REL" = "$GIT_WORKTREE_DIR" ]; then
      echo "ERROR: worktree git dir is outside the common dir: $GIT_WORKTREE_DIR" >&2
      exit 1
    fi
    ENV_GIT="GIT_DIR=/d810-git/$GIT_WORKTREE_REL"
  fi
fi
# In remote mode the logs directory always lives on the work volume, so -l has
# no mount to make there. What it (and the two diagnostics flags) now select is
# whether the finished artifacts are also copied back to the share at exit.
REMOTE_STAGE_ARTIFACTS=""
if [ -n "$MOUNT_LOGS" ] || [ -n "$ENABLE_DEBUG_LOGGING" ] || [ -n "$ENABLE_DIAG_SNAPSHOT" ]; then
  REMOTE_STAGE_ARTIFACTS=1
fi
if [ -n "$MOUNT_LOGS" ]; then
  LOGS_DIR="${WORK_DIR}/.tmp/logs"
  mkdir -p "$LOGS_DIR"
  # Remote runs must not put live SQLite writers (diag snapshots, structured
  # logs, the batch driver's database) on the cifs mount. The logs directory
  # lives on the work volume for the duration of the run and only the
  # finalized artifacts are copied to .tmp/logs when the inner shell exits.
  if [ "$REMOTE_MODE" != "1" ]; then
    _add_mount "$LOGS_DIR" /root/.idapro/logs
  fi
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
elif [ "$COBRA_SOURCE_MODE" = "baked" ]; then
  # Nothing to mount and nothing to cache: the wheel is already installed in
  # the image. Only the verification runs.
  :
elif [ "$REMOTE_MODE" = "1" ]; then
  # The Linux CoBRA build must not live on the SMB share: its existing files
  # would need per-file ACLs, and a C++ build over CIFS is slow. Keep it in a
  # retained engine volume, accounted for by the same labels as /work.
  COBRA_CACHE_DIR="$COBRA_CACHE_VOLUME"
  _ensure_engine_volume "$COBRA_CACHE_VOLUME" cobra-cache COBRA_CACHE_VOLUME_STATE
  DOCKER_MOUNTS+=(--mount "type=volume,src=${COBRA_CACHE_VOLUME},dst=/opt/d810-cobra-cache")
else
  # Build outputs are Linux-only and belong to this task's ignored artifact
  # area. Keeping them outside both source forms makes repeated focused runs
  # reuse one pinned build without ever linking a Darwin archive.
  COBRA_CACHE_DIR="${WORK_DIR}/.tmp/cobra-linux"
  mkdir -p "$COBRA_CACHE_DIR"
  _add_mount "$COBRA_CACHE_DIR" /opt/d810-cobra-cache rw
fi
# The CoBRA build cache marker (linux-cobra-core-v2:<parent>:<core>:<image-id>:
# <toolchain>) is stored in a retained volume, so an id resolved here must be
# real on every path, including wheel mode where it is only metadata.
COBRA_IMAGE_ID="$(_require_image_id "the CoBRA build cache marker")"

# Plan: print what we're about to do so agents see worktree, output path, and options
echo "$(basename "$0") plan:"
echo "  command: $CMD"
if [ -n "$WORKTREE_REL" ]; then
  echo "  worktree: $WORKTREE_ROOT/$WORKTREE_REL"
else
  echo "  worktree: repo root"
fi
if [ "$REMOTE_MODE" = "1" ]; then
  echo "  remote:   configured engine ($REMOTE_ENGINE_OS/$REMOTE_ENGINE_ARCH)"
  echo "  engine clock offset: $REMOTE_CLOCK_OFFSET s"
  echo "  volume:   $REMOTE_VOLUME"
  echo "  share root: configured"
  echo "  subpath:  $WORK_SUBPATH (read-only at /work-src; .tmp read-write at /work/.tmp)"
  echo "  source digest: $SOURCE_DIGEST"
  echo "  run id:   $D810_RUN_ID (keys diag databases per run, not per pid)"
  if [ -n "$REMOTE_STAGE_ARTIFACTS" ]; then
    echo "  artifacts: /work/runs/$D810_RUN_ID/logs (work volume) staged to .tmp/logs/$D810_RUN_ID at exit"
  else
    echo "  artifacts: /work/runs/$D810_RUN_ID/logs (work volume, retained; use the artifacts subcommand to copy)"
  fi
  echo "  git:      $ENV_GIT"
  echo "  archive:  $REMOTE_ARCHIVE_CONTAINER_PATH (tracked + untracked-not-ignored, ignored content excluded)"
  echo "  allowlist: ${REMOTE_MANIFEST_EXTRA_ENTRIES:- none} (from $(basename "$REMOTE_MANIFEST_EXTRA"))"
  echo "  work volume: $WORK_VOLUME ($WORK_VOLUME_STATE, retained source copy)"
  echo "  cobra cache volume: $COBRA_CACHE_VOLUME ($COBRA_CACHE_VOLUME_STATE)"
  echo "  share user: configured (ACL scoped to worktree .tmp)"
fi
if [ -n "$DUMP_OUT" ]; then
  echo "  output:   stdout+stderr -> .tmp/$DUMP_OUT"
fi
if [ -n "$MOUNT_LOGS" ]; then
  echo "  logs:     .tmp/logs -> /root/.idapro/logs in container"
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
  if [ "$COBRA_SOURCE_MODE" = "baked" ]; then
    echo "  extension: d810-cobra (baked $COBRA_BAKED_VERSION ${COBRA_BAKED_WHEEL_SHA256:0:12} tag ${COBRA_BAKED_TAG_COMMIT:0:7})"
    echo "  cobra baked: $DOCKER_IMAGE labels published sha256 $COBRA_BAKED_WHEEL_SHA256; d810-cobra $COBRA_BAKED_VERSION tag v$COBRA_BAKED_VERSION $COBRA_BAKED_TAG_COMMIT core $COBRA_BAKED_CORE_COMMIT parent $COBRA_BAKED_PARENT_COMMIT; nothing installed, verification still enforced"
  elif [ "$COBRA_SOURCE_MODE" = "wheel" ]; then
    echo "  extension: d810-cobra (wheel $COBRA_WHEEL_BASENAME)"
    echo "  cobra wheel: $D810_COBRA_WHEEL -> $COBRA_WHEEL_CONTAINER_PATH (read-only) $COBRA_WHEEL_IDENTITY sha256 $COBRA_WHEEL_SHA256; d810-cobra $COBRA_WHEEL_VERSION tag v$COBRA_WHEEL_VERSION $COBRA_PARENT_SOURCE_ID core $COBRA_CORE_SOURCE_ID"
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
if [ -n "$REMOTE_CLOCK_OFFSET" ]; then
  # The receipt has to carry it: every duration in the run was measured
  # against this clock.
  ENV_TEST="$ENV_TEST D810_TEST_ENGINE_CLOCK_OFFSET=$REMOTE_CLOCK_OFFSET"
fi
if [ -n "$COBRA_WHEEL_SHA256" ]; then
  # A receipt has to name the artifact that produced the measurement, and for
  # a published wheel -- baked or mounted -- the hash and the tag commit are
  # that identity. The distribution version is not: 0.1.4 shipped a legacy
  # manifest under the same name.
  ENV_TEST="$ENV_TEST D810_TEST_COBRA_WHEEL_SHA256=$COBRA_WHEEL_SHA256 D810_TEST_COBRA_TAG_COMMIT=$COBRA_PARENT_SOURCE_ID D810_TEST_COBRA_SOURCE_MODE=$COBRA_SOURCE_MODE"
fi
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
  local _skip=" D810_DOCKER_IMAGE D810_DOCKER_MEMORY D810_EGGLOG_ROOT D810_COBRA_ROOT D810_COBRA_WHEEL D810_COBRA_WHEEL_SHA256 D810_COBRA_HARNESS_WHEEL_SHA256 D810_REPO_ROOT D810_WORKTREE_ROOT D810_MEMORY_LIMIT_BYTES D810_SYSTEM_BATCH_SIZE D810_REMOTE_DOCKER_HOST D810_REMOTE_VOLUME D810_REMOTE_SMB_SHARE D810_REMOTE_SHARE_ROOT D810_REMOTE_SMB_USER "
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
  # perf's absence used to be invisible: the steps were ';'-joined, so the
  # whole thing returned py-spy's status and a profiling leg with no profiler
  # looked like a successful one.
  PROFILE_SETUP="{ if ! command -v perf >/dev/null 2>&1; then apt-get update -qq && apt-get install -y --no-install-recommends linux-perf; fi; } && { if [ ! -x $IDA_VENV_PYSPY ]; then $IDA_VENV_PIP install -q py-spy; fi; } && { perf --version || { echo 'ERROR: D810_NATIVE_PROFILE=1 but perf is not available; a profiling leg without a profiler is not a valid leg' >&2; exit 1; }; } && $IDA_VENV_PYSPY --version"
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
# A build that produced no loadable extension is silent otherwise: the suite
# runs in the Python fallback and reports the same green. Probe in a fresh
# process (a stale import cache would answer for the previous build) and say
# so in one unmistakable line.
SPEEDUPS_PROBE="$IDA_VENV_PYTHON -c 'from d810.speedups.install import inspect_native_extensions; import sys; result = inspect_native_extensions(); print(\"[speedups] native extension: LOADED (\" + result.detail + \")\") if result.ok else print(result.detail, file=sys.stderr); raise SystemExit(0 if result.ok else 1)'"
SPEEDUPS_PROBE_TOLERANT="{ $SPEEDUPS_PROBE || echo '[speedups] native extension: NOT LOADED (python fallback)'; }"
SPEEDUPS_PROBE_REQUIRED="{ $SPEEDUPS_PROBE || { echo '[speedups] native extension: NOT LOADED (python fallback)' >&2; echo 'ERROR: D810_NO_CYTHON=0 asked for the native extension but none could be loaded; refusing to run the tests in the Python fallback' >&2; exit 1; }; }"
if [ "$NO_CYTHON" = "1" ]; then
  SPEEDUPS_BUILD_CMD="$SPEEDUPS_CLEAN_CMD && echo '[speedups] native build disabled by D810_NO_CYTHON=1' && $SPEEDUPS_PROBE_TOLERANT"
elif [ "$CYTHON_PROFILE" = "1" ]; then
  # A profiling artifact is only useful when it actually contains Cython
  # trace events. Unlike the normal optional speedup build, fail closed here.
  SPEEDUPS_BUILD_CMD="$SPEEDUPS_CLEAN_CMD && DEBUG=1 D810_BUILD_SPEEDUPS=1 $IDA_VENV_PIP install -e .[speedups] -q && $SPEEDUPS_PROBE_REQUIRED"
elif [ "$NO_CYTHON" = "0" ]; then
  # An explicit D810_NO_CYTHON=0 is a request, not a preference: a run that
  # silently fell back to Python answers a different question than the one asked.
  SPEEDUPS_BUILD_CMD="$SPEEDUPS_CLEAN_CMD && D810_BUILD_SPEEDUPS=1 $IDA_VENV_PIP install -e .[speedups] -q && $SPEEDUPS_PROBE_REQUIRED"
else
  SPEEDUPS_BUILD_CMD="$SPEEDUPS_CLEAN_CMD && D810_BUILD_SPEEDUPS=1 $IDA_VENV_PIP install -e .[speedups] -q && $SPEEDUPS_PROBE_TOLERANT"
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
  # One verification for both published-wheel paths: manifest contract,
  # compiled-extension import, a real known-answer solve with an equivalence
  # proof, and the identity assertions. Behaviour, not a boolean -- an
  # importable binding can still be mis-wired, and a pure-Python fallback
  # satisfies every import in the first clause.
  COBRA_VERIFY_CMD="$IDA_VENV_PYTHON -c 'import d810_cobra; manifest=d810_cobra.MANIFEST; assert manifest[\"api_version\"] == 1; assert manifest[\"implements\"] == {\"mba-solve\": \"cobra-solve\"}; from d810_cobra.expr import parse_cobra_output; from d810_cobra.prove import ProofResult, prove_equivalent; from d810_cobra.solve import SolveStatus, binding_available, solve_signature; assert binding_available(); tree=parse_cobra_output(\"(x0 | x1) - (x0 & x1)\", [\"a\", \"b\"]); solved=solve_signature(tree, [\"a\", \"b\"], 32); assert solved.status is SolveStatus.SOLVED and solved.tree is not None; assert prove_equivalent(tree, solved.tree, [\"a\", \"b\"], 32) is ProofResult.PROVED; import d810_cobra._cobra; import importlib.metadata, os, sysconfig; assert importlib.metadata.version(\"d810-cobra\") == \"$COBRA_WHEEL_VERSION\"; binary=os.path.realpath(d810_cobra._cobra.__file__); assert \"$COBRA_WHEEL_ARCH\" in os.path.basename(binary), binary; site_dirs=[os.path.realpath(sysconfig.get_paths()[key]) for key in (\"purelib\", \"platlib\")]; assert any(binary.startswith(site + os.sep) for site in site_dirs), binary'"
  if [ "$COBRA_SOURCE_MODE" = "baked" ]; then
    # The image already installed and verified this wheel at build time; the
    # labels are its claim. Re-prove it here anyway, as a hard precondition:
    # an image can be retagged, and a stale site-packages would otherwise
    # answer for a run that installed nothing.
    COBRA_SETUP="echo '[setup] d810-cobra $COBRA_BAKED_VERSION baked in the image (published sha256 $COBRA_BAKED_WHEEL_SHA256, tag $COBRA_BAKED_TAG_COMMIT); verifying, installing nothing' && $COBRA_VERIFY_CMD"
  elif [ "$COBRA_SOURCE_MODE" = "wheel" ]; then
    # The recorded wheel is re-hashed inside the container before pip sees
    # it, so a mount that does not deliver the verified bytes fails setup
    # instead of installing an unknown artifact. Runtime dependencies come
    # from the installed distribution's own metadata, minus the mounted
    # D810 package and minus every extra, exactly as the source path does.
    COBRA_SETUP="printf '%s  %s\\n' '$COBRA_WHEEL_SHA256' '$COBRA_WHEEL_CONTAINER_PATH' | sha256sum -c - && $IDA_VENV_PIP install --no-deps --force-reinstall --no-cache-dir -q '$COBRA_WHEEL_CONTAINER_PATH' && COBRA_REQUIREMENTS=\$(mktemp) && $IDA_VENV_PYTHON -c 'import importlib.metadata, re; reqs=importlib.metadata.requires(\"d810-cobra\") or []; keep=[req for req in reqs if not re.search(r\"extra\\s*==\", req) and re.match(r\"[A-Za-z0-9_.-]+\", req.strip()).group(0).lower().replace(\"_\", \"-\").replace(\".\", \"-\") != \"d810-ng\"]; print(\"\\n\".join(keep))' > \"\$COBRA_REQUIREMENTS\" && $IDA_VENV_PIP install -r \"\$COBRA_REQUIREMENTS\" -q && $COBRA_VERIFY_CMD"
  else
    # CoBRA's test extras are not enough to describe its runtime dependencies;
    # derive the project metadata exactly as for Egglog, while omitting the
    # mounted D810 package so the tested worktree remains authoritative.
    if [ "$COBRA_SOURCE_MODE" = "mounted-pinned" ]; then
      COBRA_SOURCE_SETUP="COBRA_BUILD_DIR=\$(mktemp -d) && cp -a /opt/d810-cobra-source/. \"\$COBRA_BUILD_DIR/\""
    else
      # ENV_GIT pins D810's mounted Git dirs for provenance, but a source checkout
      # needs its own writable .git directory. Both GIT_DIR and GIT_COMMON_DIR
      # have to be unset: leaving GIT_COMMON_DIR set makes `git clone` try to
      # write into the read-only mount. Scope the unset to the CoBRA acquisition
      # commands; D810's test provenance keeps ENV_GIT.
      COBRA_SOURCE_SETUP="COBRA_BUILD_DIR=\$(mktemp -d) && env -u GIT_DIR -u GIT_COMMON_DIR git clone --no-checkout '$COBRA_SOURCE_URL' \"\$COBRA_BUILD_DIR\" && env -u GIT_DIR -u GIT_COMMON_DIR git -C \"\$COBRA_BUILD_DIR\" fetch --depth=1 origin '$COBRA_SOURCE_REVISION' && env -u GIT_DIR -u GIT_COMMON_DIR git -C \"\$COBRA_BUILD_DIR\" checkout --detach FETCH_HEAD && test \"\$(env -u GIT_DIR -u GIT_COMMON_DIR git -C \"\$COBRA_BUILD_DIR\" rev-parse HEAD)\" = '$COBRA_SOURCE_REVISION' && env -u GIT_DIR -u GIT_COMMON_DIR git -C \"\$COBRA_BUILD_DIR\" submodule update --init --recursive --depth=1 && test \"\$(env -u GIT_DIR -u GIT_COMMON_DIR git -C \"\$COBRA_BUILD_DIR/third_party/cobra\" rev-parse HEAD)\" = '$COBRA_CORE_SOURCE_REVISION'"
    fi
    COBRA_SETUP="$COBRA_SOURCE_SETUP && export COBRA_ROOT=/opt/d810-cobra-cache && export COBRA_SOURCE_KEY='$COBRA_PARENT_SOURCE_ID:$COBRA_CORE_SOURCE_ID:$COBRA_IMAGE_ID' && { if ! command -v cmake >/dev/null 2>&1 || ! command -v ninja >/dev/null 2>&1 || ! command -v c++ >/dev/null 2>&1; then apt-get update > /tmp/d810-cobra-apt.log 2>&1; apt-get install -y --no-install-recommends cmake ninja-build build-essential >> /tmp/d810-cobra-apt.log 2>&1; fi; __cobra_missing=''; for __cobra_tool in cmake ninja c++; do command -v \"\$__cobra_tool\" >/dev/null 2>&1 || __cobra_missing=\"\$__cobra_missing \$__cobra_tool\"; done; if [ -n \"\$__cobra_missing\" ]; then echo '[cobra] last 20 lines of apt output:' >&2; tail -n 20 /tmp/d810-cobra-apt.log >&2 2>/dev/null || true; echo \"ERROR: CoBRA toolchain provisioning failed; still missing:\$__cobra_missing; see apt output above; a skewed engine clock makes apt reject repository signatures\" >&2; exit 1; fi; } && COBRA_TOOLCHAIN_KEY=\$(cmake --version | head -1; ninja --version; c++ --version | head -1) && COBRA_MARKER=\"linux-cobra-core-v2:\$COBRA_SOURCE_KEY:\$COBRA_TOOLCHAIN_KEY\" && if [ ! -f \"\$COBRA_ROOT/.linux-build-ok\" ] || [ \"\$(<\"\$COBRA_ROOT/.linux-build-ok\")\" != \"\$COBRA_MARKER\" ]; then rm -rf \"\$COBRA_ROOT\"/* \"\$COBRA_ROOT\"/.[!.]* \"\$COBRA_ROOT\"/..?* 2>/dev/null || true; cp -a \"\$COBRA_BUILD_DIR/third_party/cobra/.\" \"\$COBRA_ROOT/\"; $IDA_VENV_PYTHON \"\$COBRA_BUILD_DIR/tools/build_cobra.py\" --root \"\$COBRA_ROOT\" && printf '%s\\n' \"\$COBRA_MARKER\" > \"\$COBRA_ROOT/.linux-build-ok\"; fi && $IDA_VENV_PYTHON -c 'import re, sys, tomllib; project=tomllib.load(open(sys.argv[1], \"rb\"))[\"project\"]; deps=project.get(\"dependencies\", []) + project.get(\"optional-dependencies\", {}).get(\"test\", []); print(\"\\n\".join(dep for dep in deps if re.match(r\"[A-Za-z0-9_.-]+\", dep.strip()).group(0).lower().replace(\"_\", \"-\").replace(\".\", \"-\") != \"d810-ng\"))' \"\$COBRA_BUILD_DIR/pyproject.toml\" > \"\$COBRA_BUILD_DIR/requirements.txt\" && $IDA_VENV_PIP install \"\$COBRA_BUILD_DIR[test]\" --no-deps -q --force-reinstall --no-cache-dir && $IDA_VENV_PIP install -r \"\$COBRA_BUILD_DIR/requirements.txt\" -q && $IDA_VENV_PYTHON -c 'import d810_cobra; manifest=d810_cobra.MANIFEST; assert manifest[\"api_version\"] == 1; assert manifest[\"implements\"] == {\"mba-solve\": \"cobra-solve\"}; from d810_cobra.expr import parse_cobra_output; from d810_cobra.prove import ProofResult, prove_equivalent; from d810_cobra.solve import SolveStatus, binding_available, solve_signature; assert binding_available(); tree=parse_cobra_output(\"(x0 | x1) - (x0 & x1)\", [\"a\", \"b\"]); solved=solve_signature(tree, [\"a\", \"b\"], 32); assert solved.status is SolveStatus.SOLVED and solved.tree is not None; assert prove_equivalent(tree, solved.tree, [\"a\", \"b\"], 32) is ProofResult.PROVED; import d810_cobra._cobra'"
  fi
  if [ -n "$EXTENSION_SETUP" ]; then
    EXTENSION_SETUP="$EXTENSION_SETUP && $COBRA_SETUP"
  else
    EXTENSION_SETUP="$COBRA_SETUP"
  fi
fi
# Every setup stage is a hard precondition for the workload. Wrap it so it
# names itself on failure and exits with its OWN status: the composed container
# command used to join the workload to setup with "; ", which detached pytest
# from a failed setup entirely - the container then exited with pytest's status
# and a run with no CoBRA and no native extension reported success. That join
# pre-exists on mainline.
_stage_guard() {
  printf '{ %s; } || { __d810_stage_status=$?; printf "[setup] ERROR: stage %s failed (exit %%s); tests not started\\n" "$__d810_stage_status" >&2; exit $__d810_stage_status; }' "$1" "$2"
}

SETUP_CMD="$LLVM_OPT_SETUP${LLVM_OPT_SETUP:+ && }export $ENV_IDA $ENV_PYTHON $ENV_GIT && $PROFILE_SETUP${PROFILE_SETUP:+ && }$DEPENDENCY_SETUP"
if [ -n "$EXTENSION_SETUP" ]; then
  SETUP_CMD="$SETUP_CMD && $(_stage_guard "$EXTENSION_SETUP" extensions)"
fi
SETUP_CMD="$SETUP_CMD && $(_stage_guard "$SPEEDUPS_BUILD_CMD" native-extension-build)"

# Remote runs mirror the read-only SMB source into the writable work volume.
# The mirror is exact: the destination is emptied first (except the .tmp mount)
# and build outputs and caches are never copied in. The completion sentinel is
# written only after a successful mirror, so a partial copy is never reused.
if [ "$REMOTE_MODE" = "1" ]; then
  REMOTE_SYNC_CMD="set -o pipefail; __digest='$SOURCE_DIGEST'; \
if [ -f '$SYNC_SENTINEL' ] && [ \"\$(cat '$SYNC_SENTINEL')\" = \"\$__digest\" ]; then \
  echo \"[sync] work volume already mirrors source digest \$__digest\"; \
else \
  rm -f '$SYNC_SENTINEL' && \
  __t0=\$(date +%s) && \
  find /work -mindepth 1 -maxdepth 1 ! -name .tmp ! -name runs -exec rm -rf {} + && \
  tar -C /work -xf '$REMOTE_ARCHIVE_CONTAINER_PATH' && \
  printf '%s\\n' \"\$__digest\" > '$SYNC_SENTINEL' && \
  echo \"[sync] mirrored /work-src -> /work in \$((\$(date +%s)-\$__t0))s (digest \$__digest)\"; \
fi"
  # The redirect is unconditional: every remote run keeps its live SQLite
  # writers on the engine volume, never on the cifs share. Copying the result
  # back to the share is what the artifact flags ask for - without them the run
  # store is still complete and reachable through the artifacts subcommand, so
  # the copy is pure share traffic. The run store is excluded from the sync
  # wipe above, so a skipped copy never loses anything.
  REMOTE_STAGING_CMD="__runs_keep=$REMOTE_RUN_RETENTION; \
ls -1 /work/runs 2>/dev/null | sort | head -n -\$__runs_keep | while IFS= read -r __old; do rm -rf \"/work/runs/\$__old\"; done; \
RUN_LOGS=/work/runs/\$D810_RUN_ID/logs && \
mkdir -p \"\$RUN_LOGS\" && \
rm -rf /root/.idapro/logs && mkdir -p /root/.idapro && ln -sfn \"\$RUN_LOGS\" /root/.idapro/logs"
  if [ -n "$REMOTE_STAGE_ARTIFACTS" ]; then
    # The staging trap runs on failure too, so a crashed run still leaves its
    # artifacts both in the run directory and on the share.
    REMOTE_STAGING_CMD="$REMOTE_STAGING_CMD && \
STAGE_DEST=/work/.tmp/logs/\$D810_RUN_ID && \
mkdir -p \"\$STAGE_DEST\" && \
trap 'set +e; __stage_t0=\$(date +%s); cp -a \"\$RUN_LOGS\"/. \"\$STAGE_DEST\"/ 2>/dev/null; \
echo \"[artifacts] staged \$RUN_LOGS -> \$STAGE_DEST in \$((\$(date +%s)-\$__stage_t0))s\"' EXIT"
  fi
  SETUP_CMD="$(_stage_guard "$REMOTE_SYNC_CMD" source-sync) && $(_stage_guard "$REMOTE_STAGING_CMD" artifact-staging) && $SETUP_CMD"
fi

# Safely reassemble an array of args into a string suitable for embedding in
# a bash -c command that gets re-parsed by another shell (e.g. inside the
# container). Plain ${ARR[*]} flattens the array with a single space and no
# re-quoting, so any element containing whitespace (e.g. a multi-word
# `pytest -k "A or B"` filter) gets word-split again when the reconstructed
# string is parsed downstream. printf '%q' quotes each element so it
# round-trips as exactly one token.
_d810_quote_arg() {
  printf '%q' "$1"
}

_d810_quote_args() {
  local out="" arg
  for arg in "$@"; do
    out+="$(_d810_quote_arg "$arg") "
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

# Artifact listing and retrieval must not pay for the dependency setup.
run_bash_plain() {
  local inner="$1"
  _run_docker_container run --rm \
    --memory "$DOCKER_MEMORY" \
    "${DOCKER_MOUNTS[@]}" \
    -w /work \
    --entrypoint /bin/bash "$DOCKER_IMAGE" -lc "$inner"
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
  # exec would replace the shell and with it the staging EXIT trap, so remote
  # runs keep the shell alive and propagate the status themselves.
  local invoke='exec "$@"'
  if [ "$REMOTE_MODE" = "1" ]; then
    invoke='"$@"'
  fi
  local inner="export $ENV_TEST && $SETUP_CMD && $invoke"
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

if [ "$CMD" = "artifacts" ]; then
  if [ "$REMOTE_MODE" != "1" ]; then
    echo "ERROR: artifacts is a remote-mode command (pass --remote HOST)" >&2
    exit 1
  fi
  if [ -z "$ARTIFACT_RUN" ]; then
    # Runs are retained in the work volume, including failed ones.
    run_bash_plain "ls -1 /work/runs 2>/dev/null | sort || true"
  else
    run_bash_plain "test -d '/work/runs/$ARTIFACT_RUN' || { echo \"ERROR: no such run: $ARTIFACT_RUN\" >&2; exit 1; }; mkdir -p '/work/.tmp/remote-runs/$ARTIFACT_RUN' && cp -a '/work/runs/$ARTIFACT_RUN/.' '/work/.tmp/remote-runs/$ARTIFACT_RUN/' && echo \"[artifacts] copied /work/runs/$ARTIFACT_RUN -> .tmp/remote-runs/$ARTIFACT_RUN\""
    echo "  local path: $WORK_DIR/.tmp/remote-runs/$ARTIFACT_RUN"
  fi
  exit 0
fi

if [ "$CMD" = "system" ]; then
  SYSTEM_ARGS=()
  [ ${#EXTRA_PYTEST[@]} -gt 0 ] && SYSTEM_ARGS+=("${EXTRA_PYTEST[@]}")
  SYS_REDIR=""
  SYS_TRUNCATE=""
  if [ -n "$DUMP_OUT" ]; then
    mkdir -p "${WORK_DIR}/.tmp"
    SYS_LOG="/work/.tmp/${DUMP_OUT}"
    SYS_LOG_QUOTED="$(_d810_quote_arg "$SYS_LOG")"
    SYS_TRUNCATE=": > $SYS_LOG_QUOTED && "
    SYS_REDIR="> $SYS_LOG_QUOTED 2>&1"
  fi
  run_bash "$SETUP_CMD && ${SYS_TRUNCATE}$ENV_TEST $IDA_VENV_PYTHON tools/scripts/run_system_test_batches.py --python $IDA_VENV_PYTHON --batch-size $SYSTEM_BATCH_SIZE${START_BATCH:+ --start-batch $START_BATCH} --log-dir /root/.idapro/logs/d810_logs tests/system -- $(_d810_quote_args "${SYSTEM_ARGS[@]}") $SYS_REDIR"
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
    SYS_LOG_QUOTED="$(_d810_quote_arg "$SYS_LOG")"
    SYS_TRUNCATE=": > $SYS_LOG_QUOTED && "
    SYS_REDIR="> $SYS_LOG_QUOTED 2>&1"
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
  LOG_PATH_QUOTED="$(_d810_quote_arg "$LOG_PATH")"
  TRUNCATE_CMD=": > $LOG_PATH_QUOTED && "
  REDIR="> $LOG_PATH_QUOTED 2>&1"
fi

INNER="$SETUP_CMD && ${TRUNCATE_CMD}$ENV_TEST $PYTEST_DUMP $PYTEST_EXTENSION_ARGS $(_d810_quote_args "${DUMP_ARGS[@]}") -v $REDIR"
run_bash "$INNER"
