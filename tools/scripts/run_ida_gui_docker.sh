#!/usr/bin/env bash
# Launch native ARM64 IDA 9.3 through XQuartz with a selected D810 worktree.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: run_ida_gui_docker.sh [OPTIONS] [-- IDA_ARGS...]

Options:
  -w, --worktree NAME  Use D810_REPO_ROOT/D810_WORKTREE_ROOT/NAME.
  -h, --help           Show this help.
  --                   Pass all remaining arguments to IDA unchanged.

Environment:
  D810_REPO_ROOT         Canonical checkout containing linked worktrees.
                         Defaults to the checkout owning the common Git dir.
  D810_WORKTREE_ROOT     Worktree directory below the repository root.
                         Default: .worktrees
  D810_GUI_DOCKER_IMAGE  GUI image. Default: idapro-9.3:x11-arm64
  D810_IDA_USER_DIR      Persistent host IDA state. Default: $HOME/.idapro
  D810_GUI_DISPLAY       Container X11 display.
                         Default: host.docker.internal:0
  D810_XHOST_BIN         XQuartz xhost client. Default: /opt/X11/bin/xhost

Mounts:
  selected checkout             -> /work
  selected checkout             -> /root/.idapro/plugins/d810
  D810_IDA_USER_DIR             -> /root/.idapro
  D810_REPO_ROOT/samples/bins   -> /samples/bins (when present)

Example:
  run_ida_gui_docker.sh -w truthful-config-v2-project-ui \
    -- /samples/bins/libobfuscated.dylib.i64
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

WORKTREE_REL=""
IDA_ARGS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    -w|--worktree)
      [ "$#" -ge 2 ] || fail "$1 requires a worktree name"
      WORKTREE_REL="$2"
      shift 2
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

DOCKER_IMAGE="${D810_GUI_DOCKER_IMAGE-idapro-9.3:x11-arm64}"
GUI_DISPLAY="${D810_GUI_DISPLAY-host.docker.internal:0}"
IDA_USER_PATH="${D810_IDA_USER_DIR-$HOME/.idapro}"
XHOST_BIN="${D810_XHOST_BIN-/opt/X11/bin/xhost}"
[ -n "$DOCKER_IMAGE" ] || fail "D810_GUI_DOCKER_IMAGE is set but empty"
[ -n "$GUI_DISPLAY" ] || fail "D810_GUI_DISPLAY is set but empty"
[ -n "$IDA_USER_PATH" ] || fail "D810_IDA_USER_DIR is set but empty"
[ -x "$XHOST_BIN" ] || {
  xquartz_recovery
  fail "xhost not found or not executable: $XHOST_BIN"
}

IDA_USER_DIR="$(canonical_dir "$IDA_USER_PATH")" \
  || fail "IDA user directory not found: $IDA_USER_PATH"
[ -f "$IDA_USER_DIR/idapro.hexlic" ] \
  || fail "IDA user directory has no idapro.hexlic: $IDA_USER_DIR"

if ! XHOST_OUTPUT="$("$XHOST_BIN" 2>&1)"; then
  xquartz_recovery
  fail "XQuartz is not accepting xhost queries"
fi
if ! printf '%s\n' "$XHOST_OUTPUT" | grep -Eq '^(INET|INET6):localhost$'; then
  xquartz_recovery
  fail "XQuartz localhost is not authorized"
fi

command -v docker >/dev/null 2>&1 || fail "docker not found in PATH"
docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1 \
  || fail "Docker GUI image not found: $DOCKER_IMAGE"

SAMPLES_DIR="$REPO_ROOT/samples/bins"
if [ -d "$SAMPLES_DIR" ]; then
  SAMPLES_DIR="$(canonical_dir "$SAMPLES_DIR")"
fi

printf '%s plan:\n' "$0"
printf '  image:     %s\n' "$DOCKER_IMAGE"
printf '  checkout:  %s\n' "$WORK_DIR"
printf '  plugin:    %s -> /root/.idapro/plugins/d810\n' "$WORK_DIR"
printf '  ida state: %s -> /root/.idapro (read-write)\n' "$IDA_USER_DIR"
if [ -d "$SAMPLES_DIR" ]; then
  printf '  samples:   %s -> /samples/bins (read-write)\n' "$SAMPLES_DIR"
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
  -e "MODE=x11"
  -e "DISPLAY=$GUI_DISPLAY"
  -e "LIBGL_ALWAYS_SOFTWARE=1"
  -e "PYTHONPATH=/root/.idapro/plugins/d810/src:/app/ida/python"
  -v "$WORK_DIR:/work"
  -v "$IDA_USER_DIR:/root/.idapro"
  -v "$WORK_DIR:/root/.idapro/plugins/d810"
)
if [ -d "$SAMPLES_DIR" ]; then
  DOCKER_ARGS+=( -v "$SAMPLES_DIR:/samples/bins" )
fi
DOCKER_ARGS+=( --entrypoint /app/ida/entrypoint.sh "$DOCKER_IMAGE" )
if [ "${#IDA_ARGS[@]}" -gt 0 ]; then
  DOCKER_ARGS+=( "${IDA_ARGS[@]}" )
fi

exec docker "${DOCKER_ARGS[@]}"
