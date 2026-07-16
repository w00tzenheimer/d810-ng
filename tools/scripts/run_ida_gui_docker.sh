#!/usr/bin/env bash
# Launch native ARM64 IDA 9.3 through XQuartz with a selected D810 worktree.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: run_ida_gui_docker.sh [OPTIONS] [-- IDA_ARGS...]

Options:
  -w, --worktree NAME  Use D810_REPO_ROOT/D810_WORKTREE_ROOT/NAME.
  -l, --logs           Compatibility with run_system_tests_docker.sh; the GUI
                       always mounts persistent D810 logs.
  --enable-debug-logging
                       Set D810_DEBUG_LOGGING=1 in the container.
  --enable-diag-snapshot
                       Set D810_DIAG_SNAPSHOT=1 in the container.
  --disable-fact-lifecycle
                       Set D810_FACT_LIFECYCLE=0 in the container.
  -h, --help           Show this help.
  --                   Pass all remaining arguments to IDA unchanged.

Environment:
  D810_REPO_ROOT         Canonical checkout containing linked worktrees.
                         Defaults to the checkout owning the common Git dir.
  D810_WORKTREE_ROOT     Worktree directory below the repository root.
                         Default: .worktrees
  D810_GUI_DOCKER_IMAGE  D810 GUI runtime image. Default:
                         idapro-9.3-speedups:x11-arm64
  D810_DOCKER_MEMORY     Container memory limit. Default: 4g
  D810_IDA_USER_DIR      Host root for portable D810 config and logs.
                         Default: $HOME/.idapro
  D810_GUI_DISPLAY       Container X11 display.
                         Default: host.docker.internal:0
  D810_XHOST_BIN         XQuartz xhost client. Default: /opt/X11/bin/xhost

Mounts:
  selected checkout             -> /work
  selected checkout             -> /root/.idapro/plugins/d810
  D810_IDA_USER_DIR/cfg/d810    -> /root/.idapro/cfg/d810
  configured D810 log directory -> /root/.idapro/logs
  The image-owned ida.reg is intentionally not replaced.
  D810_REPO_ROOT/samples/bins   -> /samples/bins read-only (when present)

Safety:
  The GUI image must carry org.d810.gui-runtime=x11-dev-emulation-z3-v1.
  Build the default image with:
    docker build -f docker/Dockerfile.test-runtime \
      --build-arg IDA_IMAGE=idapro-9.3:x11-arm64 \
      --build-arg D810_GUI_RUNTIME_LABEL=x11-dev-emulation-z3-v1 \
      -t idapro-9.3-speedups:x11-arm64 .
  A /samples/bins/*.i64 argument is copied to the selected checkout's
  .tmp/ida-gui directory. IDA opens the /work copy and cannot modify the source.

Example:
  run_ida_gui_docker.sh -w truthful-config-v2-project-ui \
    -- /samples/bins/libobfuscated.dll.2026-06-03.i64
EOF
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

xquartz_recovery() {
  cat >&2 <<'EOF'
Start XQuartz and authorize localhost with:
  open -a XQuartz
  /opt/X11/bin/xhost +localhost
EOF
}

canonical_dir() {
  local path="$1"
  [ -d "$path" ] || return 1
  (cd "$path" && pwd -P)
}

canonical_file() {
  local path="$1"
  local directory
  [ -f "$path" ] || return 1
  directory="$(canonical_dir "$(dirname "$path")")" || return 1
  printf '%s/%s\n' "$directory" "$(basename "$path")"
}

WORKTREE_REL=""
MOUNT_LOGS_COMPAT=""
ENABLE_DEBUG_LOGGING=""
ENABLE_DIAG_SNAPSHOT=""
DISABLE_FACT_LIFECYCLE=""
IDA_ARGS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    -w|--worktree)
      [ "$#" -ge 2 ] || fail "$1 requires a worktree name"
      WORKTREE_REL="$2"
      shift 2
      ;;
    -l|--logs)
      MOUNT_LOGS_COMPAT=1
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
    --enable-fact-lifecycle)
      fail "--enable-fact-lifecycle was removed; fact lifecycle is enabled by default"
      ;;
    --disable-fact-lifecycle)
      DISABLE_FACT_LIFECYCLE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      IDA_ARGS=("$@")
      break
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

if [ "${D810_REPO_ROOT+x}" = x ]; then
  [ -n "$D810_REPO_ROOT" ] || fail "D810_REPO_ROOT is set but empty"
  REPO_ROOT="$(canonical_dir "$D810_REPO_ROOT")" \
    || fail "repository root not found: $D810_REPO_ROOT"
else
  GIT_COMMON_DIR="$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null || true)"
  [ -n "$GIT_COMMON_DIR" ] \
    || fail "not inside a Git checkout; set D810_REPO_ROOT"
  if [ "$(basename "$GIT_COMMON_DIR")" = ".git" ]; then
    REPO_ROOT="$(canonical_dir "$GIT_COMMON_DIR/..")" \
      || fail "cannot resolve repository root from $GIT_COMMON_DIR"
  else
    REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
    [ -n "$REPO_ROOT" ] \
      || fail "cannot resolve repository root; set D810_REPO_ROOT"
    REPO_ROOT="$(canonical_dir "$REPO_ROOT")"
  fi
fi

WORKTREE_ROOT="${D810_WORKTREE_ROOT-.worktrees}"
[ -n "$WORKTREE_ROOT" ] || fail "D810_WORKTREE_ROOT is set but empty"
case "$WORKTREE_ROOT" in
  /*) fail "D810_WORKTREE_ROOT must be relative to D810_REPO_ROOT: $WORKTREE_ROOT" ;;
esac

WORK_DIR="$REPO_ROOT"
if [ -n "$WORKTREE_REL" ]; then
  case "$WORKTREE_REL" in
    /*) fail "worktree escapes worktree root: $WORKTREE_REL" ;;
  esac
  WORKTREE_BASE_PATH="$REPO_ROOT/$WORKTREE_ROOT"
  [ -d "$WORKTREE_BASE_PATH" ] \
    || fail "worktree root not found: $WORKTREE_BASE_PATH"
  WORKTREE_BASE="$(canonical_dir "$WORKTREE_BASE_PATH")"
  WORKTREE_PATH="$WORKTREE_BASE/$WORKTREE_REL"
  [ -d "$WORKTREE_PATH" ] || fail "worktree not found: $WORKTREE_PATH"
  WORK_DIR="$(canonical_dir "$WORKTREE_PATH")"
  case "$WORK_DIR/" in
    "$WORKTREE_BASE/"*) ;;
    *) fail "worktree escapes worktree root: $WORKTREE_REL" ;;
  esac
fi

[ -f "$WORK_DIR/ida-plugin.json" ] \
  || fail "selected checkout has no ida-plugin.json: $WORK_DIR"
[ -f "$WORK_DIR/src/d810ng.py" ] \
  || fail "selected checkout has no src/d810ng.py: $WORK_DIR"

DEFAULT_GUI_DOCKER_IMAGE="idapro-9.3-speedups:x11-arm64"
GUI_RUNTIME_LABEL_KEY="org.d810.gui-runtime"
GUI_RUNTIME_LABEL_VALUE="x11-dev-emulation-z3-v1"
DOCKER_IMAGE="${D810_GUI_DOCKER_IMAGE-$DEFAULT_GUI_DOCKER_IMAGE}"
DOCKER_MEMORY="${D810_DOCKER_MEMORY-4g}"
GUI_DISPLAY="${D810_GUI_DISPLAY-host.docker.internal:0}"
IDA_USER_PATH="${D810_IDA_USER_DIR-$HOME/.idapro}"
XHOST_BIN="${D810_XHOST_BIN-/opt/X11/bin/xhost}"
[ -n "$DOCKER_IMAGE" ] || fail "D810_GUI_DOCKER_IMAGE is set but empty"
[ -n "$DOCKER_MEMORY" ] || fail "D810_DOCKER_MEMORY is set but empty"
[ -n "$GUI_DISPLAY" ] || fail "D810_GUI_DISPLAY is set but empty"
[ -n "$IDA_USER_PATH" ] || fail "D810_IDA_USER_DIR is set but empty"
[ -x "$XHOST_BIN" ] || {
  xquartz_recovery
  fail "xhost not found or not executable: $XHOST_BIN"
}

IDA_USER_DIR="$(canonical_dir "$IDA_USER_PATH")" \
  || fail "IDA user directory not found: $IDA_USER_PATH"

D810_CONFIG_PATH="$IDA_USER_DIR/cfg/d810"
mkdir -p "$D810_CONFIG_PATH"
D810_CONFIG_DIR="$(canonical_dir "$D810_CONFIG_PATH")" \
  || fail "cannot prepare D810 configuration directory: $D810_CONFIG_PATH"

DEFAULT_D810_LOG_PATH="$IDA_USER_DIR/logs"
CONFIGURED_LOG_PATH=""
if [ -f "$D810_CONFIG_DIR/options.json" ]; then
  command -v python3 >/dev/null 2>&1 \
    || fail "python3 is required to read $D810_CONFIG_DIR/options.json"
  CONFIGURED_LOG_PATH="$(python3 - "$D810_CONFIG_DIR/options.json" <<'PY'
import json
import pathlib
import sys

try:
    with pathlib.Path(sys.argv[1]).open(encoding="utf-8") as stream:
        value = json.load(stream).get("log_dir", "")
except (OSError, ValueError, AttributeError):
    value = ""

if value:
    print(pathlib.Path(str(value)).expanduser())
PY
)"
fi
if [ -n "$CONFIGURED_LOG_PATH" ]; then
  case "$CONFIGURED_LOG_PATH" in
    /*) ;;
    *) fail "D810 log_dir must be absolute for Docker GUI persistence: $CONFIGURED_LOG_PATH" ;;
  esac
  D810_CONTAINER_LOG_DIR="$CONFIGURED_LOG_PATH"
  D810_LOG_PATH="$CONFIGURED_LOG_PATH"
else
  D810_CONTAINER_LOG_DIR="/root/.idapro/logs"
  D810_LOG_PATH="$DEFAULT_D810_LOG_PATH"
fi
mkdir -p "$D810_LOG_PATH"
D810_LOG_DIR="$(canonical_dir "$D810_LOG_PATH")" \
  || fail "cannot prepare D810 log directory: $D810_LOG_PATH"

if ! XHOST_OUTPUT="$("$XHOST_BIN" 2>&1)"; then
  xquartz_recovery
  fail "XQuartz is not accepting xhost queries"
fi
if ! printf '%s\n' "$XHOST_OUTPUT" | grep -Eq '^(INET|INET6):localhost$'; then
  xquartz_recovery
  fail "XQuartz localhost is not authorized"
fi

command -v docker >/dev/null 2>&1 || fail "docker not found in PATH"
if ! GUI_RUNTIME_LABEL="$(
  docker image inspect \
    --format "{{ index .Config.Labels \"$GUI_RUNTIME_LABEL_KEY\" }}" \
    "$DOCKER_IMAGE" 2>/dev/null
)"; then
  fail "Docker GUI image not found: $DOCKER_IMAGE"
fi
if [ "$GUI_RUNTIME_LABEL" != "$GUI_RUNTIME_LABEL_VALUE" ]; then
  fail "Docker image $DOCKER_IMAGE is not a D810 GUI runtime; expected $GUI_RUNTIME_LABEL_KEY=$GUI_RUNTIME_LABEL_VALUE. Build it with the command shown by --help."
fi

SAMPLES_DIR="$REPO_ROOT/samples/bins"
if [ -d "$SAMPLES_DIR" ]; then
  SAMPLES_DIR="$(canonical_dir "$SAMPLES_DIR")"
fi

IDA_DATABASE_COPY=""
if [ "${#IDA_ARGS[@]}" -gt 0 ]; then
  for IDA_ARG_INDEX in "${!IDA_ARGS[@]}"; do
    case "${IDA_ARGS[$IDA_ARG_INDEX]}" in
    /samples/bins/*.i64)
      [ -d "$SAMPLES_DIR" ] \
        || fail "sample directory not found for ${IDA_ARGS[$IDA_ARG_INDEX]}"
      SAMPLE_REL="${IDA_ARGS[$IDA_ARG_INDEX]#/samples/bins/}"
      SAMPLE_SOURCE="$(canonical_file "$SAMPLES_DIR/$SAMPLE_REL")" \
        || fail "sample database not found: ${IDA_ARGS[$IDA_ARG_INDEX]}"
      case "$SAMPLE_SOURCE" in
        "$SAMPLES_DIR"/*) ;;
        *) fail "sample database escapes samples directory: ${IDA_ARGS[$IDA_ARG_INDEX]}" ;;
      esac
      COPY_DIR="$WORK_DIR/.tmp/ida-gui"
      mkdir -p "$COPY_DIR"
      SAMPLE_BASENAME="$(basename "$SAMPLE_SOURCE")"
      COPY_TEMP="$(mktemp "$COPY_DIR/${SAMPLE_BASENAME%.i64}.docker.XXXXXX")"
      IDA_DATABASE_COPY="$COPY_TEMP.i64"
      mv "$COPY_TEMP" "$IDA_DATABASE_COPY"
      cp -p "$SAMPLE_SOURCE" "$IDA_DATABASE_COPY"
      cmp -s "$SAMPLE_SOURCE" "$IDA_DATABASE_COPY" \
        || fail "sample database copy verification failed: $SAMPLE_SOURCE"
      IDA_ARGS[$IDA_ARG_INDEX]="/work/.tmp/ida-gui/$(basename "$IDA_DATABASE_COPY")"
      break
      ;;
    esac
  done
fi

if [ -n "$ENABLE_DEBUG_LOGGING" ]; then
  export D810_DEBUG_LOGGING=1
fi
if [ -n "$ENABLE_DIAG_SNAPSHOT" ]; then
  export D810_DIAG_SNAPSHOT=1
fi
if [ -n "$DISABLE_FACT_LIFECYCLE" ]; then
  export D810_FACT_LIFECYCLE=0
fi

EXTRA_ENV_ARGS=()
for ENV_NAME in ${!D810_@}; do
  case "$ENV_NAME" in
    D810_GUI_DOCKER_IMAGE|D810_DOCKER_MEMORY|D810_REPO_ROOT|D810_WORKTREE_ROOT|D810_IDA_USER_DIR|D810_GUI_DISPLAY|D810_XHOST_BIN)
      continue
      ;;
  esac
  printenv "$ENV_NAME" >/dev/null 2>&1 || continue
  ENV_VALUE="$(printenv "$ENV_NAME")"
  [ -n "$ENV_VALUE" ] && EXTRA_ENV_ARGS+=( -e "$ENV_NAME=$ENV_VALUE" )
done

printf '%s plan:\n' "$0"
printf '  image:     %s\n' "$DOCKER_IMAGE"
printf '  runtime:   %s=%s\n' "$GUI_RUNTIME_LABEL_KEY" "$GUI_RUNTIME_LABEL"
printf '  memory:    %s\n' "$DOCKER_MEMORY"
printf '  checkout:  %s\n' "$WORK_DIR"
printf '  plugin:    %s -> /root/.idapro/plugins/d810\n' "$WORK_DIR"
printf '  ida reg:   image-owned (preserves Linux IDAPython target)\n'
printf '  d810 cfg:  %s -> /root/.idapro/cfg/d810 (read-write)\n' "$D810_CONFIG_DIR"
printf '  d810 logs: %s -> /root/.idapro/logs (read-write)\n' "$D810_LOG_DIR"
if [ "$D810_CONTAINER_LOG_DIR" != "/root/.idapro/logs" ]; then
  printf '  log alias: %s -> %s (matches options.json)\n' \
    "$D810_LOG_DIR" "$D810_CONTAINER_LOG_DIR"
fi
if [ -d "$SAMPLES_DIR" ]; then
  printf '  samples:   %s -> /samples/bins (read-only)\n' "$SAMPLES_DIR"
fi
if [ -n "$IDA_DATABASE_COPY" ]; then
  printf '  db copy:   %s\n' "$IDA_DATABASE_COPY"
fi
if [ -n "$MOUNT_LOGS_COMPAT" ]; then
  printf '  logs:     persistent D810 logs enabled (-l compatibility)\n'
fi
printf '  display:   %s\n' "$GUI_DISPLAY"
if [ "${#IDA_ARGS[@]}" -gt 0 ]; then
  printf '  ida args:'
  printf ' %q' "${IDA_ARGS[@]}"
  printf '\n'
else
  printf '  ida args:  (none)\n'
fi
printf '\n'

DOCKER_ARGS=(
  run --rm
  --memory "$DOCKER_MEMORY"
  -w /work
  -e "MODE=x11"
  -e "DISPLAY=$GUI_DISPLAY"
  -e "LIBGL_ALWAYS_SOFTWARE=1"
  -e "IDA_PREFIX=/app/ida"
  -e "IDA_INSTALL_DIR=/app/ida"
  -e "D810_LIBCLANG_PATH=/app/ida/libclang.so"
  -e "PYTHONPATH=/root/.idapro/plugins/d810/src:/app/ida/python"
  -v "$WORK_DIR:/work"
  -v "$D810_CONFIG_DIR:/root/.idapro/cfg/d810"
  -v "$D810_LOG_DIR:/root/.idapro/logs"
  -v "$WORK_DIR:/root/.idapro/plugins/d810"
)
if [ "${#EXTRA_ENV_ARGS[@]}" -gt 0 ]; then
  DOCKER_ARGS+=( "${EXTRA_ENV_ARGS[@]}" )
fi
if [ "$D810_CONTAINER_LOG_DIR" != "/root/.idapro/logs" ]; then
  DOCKER_ARGS+=( -v "$D810_LOG_DIR:$D810_CONTAINER_LOG_DIR" )
fi
if [ -d "$SAMPLES_DIR" ]; then
  DOCKER_ARGS+=( -v "$SAMPLES_DIR:/samples/bins:ro" )
fi
DOCKER_ARGS+=( --entrypoint /app/ida/entrypoint.sh "$DOCKER_IMAGE" )
if [ "${#IDA_ARGS[@]}" -gt 0 ]; then
  DOCKER_ARGS+=( "${IDA_ARGS[@]}" )
fi

exec docker "${DOCKER_ARGS[@]}"
