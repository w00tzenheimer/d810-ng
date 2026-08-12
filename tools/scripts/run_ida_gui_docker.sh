#!/usr/bin/env bash
# Launch a compatible IDA GUI runtime through XQuartz with a selected D810 worktree.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: run_ida_gui_docker.sh [OPTIONS] [-- IDA_ARGS...]

Modes:
  Plain fresh Docker launch (default) validates XQuartz and the GUI runtime,
  then starts IDA against the selected checkout without named automation.
  Fresh named automation adds --open-config and/or --open-workbench to that
  launch; MCP remains opt-in through --mcp.
  Existing session (--connect) sends named actions to an already-running IDA
  MCP endpoint. It does not launch Docker, authorize XQuartz, copy an IDB, or
  start the MCP plugin.

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
  --open-config        Open and focus the D-810 Configuration dock in the target IDA session.
  --open-workbench     Open and focus the D810 workbench in the target IDA session.
  --function FUNCTION  Exact function name or integer EA for the workbench;
                       without it, the workbench uses IDA's current function.
  --connect            Run named actions in an existing loopback MCP IDA session.
  --mcp-endpoint URL   Connect-only loopback HTTP /mcp endpoint. Default:
                       http://127.0.0.1:13337/mcp
  --mcp                Start the mounted MCP plugin for a named action.
  --mcp-port PORT      Loopback host port for MCP. Default: 13337.
  -h, --help           Show this help.
  --                   End wrapper parsing; see IDA argument boundary below.

Environment:
  D810_REPO_ROOT         Canonical checkout containing linked worktrees.
                         Defaults to the checkout owning the common Git dir.
  D810_WORKTREE_ROOT     Worktree directory below the repository root.
                         Default: .worktrees
  D810_GUI_DOCKER_IMAGE  D810 GUI runtime image. Default:
                         idapro-9.4-speedups:x11
  D810_DOCKER_MEMORY     Container memory limit. Default: 4g
  D810_IDA_USER_DIR      Host root for portable D810 config and logs.
                         Default: $HOME/.idapro
  D810_GUI_DISPLAY       Container X11 display.
                         Default: host.docker.internal:0
  D810_XHOST_BIN         XQuartz xhost client. Default: /opt/X11/bin/xhost
  D810_MCP_PLUGIN_DIR    MCP plugin source override. Default:
                         D810_IDA_USER_DIR/plugins/ida-pro-mcp

Mounts:
  selected checkout             -> /work
  selected checkout             -> /root/.idapro/plugins/d810
  D810_IDA_USER_DIR/cfg/d810    -> /root/.idapro/cfg/d810
  configured D810 log directory -> /root/.idapro/logs
  The image-owned ida.reg is intentionally not replaced.
  D810_REPO_ROOT/samples/bins   -> /samples/bins read-only (when present)
  MCP plugin source            -> /root/.idapro/plugins/ida-pro-mcp
                                  read-only (only with --mcp)

Named-action restrictions:
  --function requires --open-workbench
  --mcp requires --open-config or --open-workbench
  --mcp-port requires --mcp; the host port must be 1024 through 65535.
  --mcp-endpoint requires --connect
  --connect requires --open-config or --open-workbench
  --connect does not accept IDA arguments after --
  --connect cannot be combined with --mcp or --mcp-port.

MCP boundary:
  Fresh --mcp publishes only 127.0.0.1:HOST_PORT and keeps the container port
  fixed at 13337. --connect accepts only a loopback HTTP /mcp endpoint and
  defaults to http://127.0.0.1:13337/mcp.

IDA argument boundary:
  Plain fresh arguments after -- remain separate array elements.
  /samples/bins/*.i64 is copied, verified, and rewritten
  to its /work/.tmp/ida-gui/ copy.
  Named fresh rejects caller -S* arguments after --.
  Connect rejects every argument after --.

Automation artifacts:
  A fresh named launch writes its immutable request below the selected checkout:
    .tmp/ida-gui/automation-request-<request-id>.json
  Terminal fresh named and existing-session results publish their audit at:
    .tmp/ida-gui/automation-<request-id>.json
  Every accepted launch/connect invocation prints a pre-action plan naming the
  selected worktree, copied IDB or N/A, ordered commands, function selector,
  endpoint, request path when applicable, and audit path.

Safety:
  The GUI image must carry org.d810.gui-runtime=x11 (IDA 9.4) or
  x11-dev-emulation-z3-v1 (the compatible IDA 9.3 runtime).
  This script does not build images. It uses the prebuilt default
  idapro-9.4-speedups:x11; override with D810_GUI_DOCKER_IMAGE.
  A /samples/bins/*.i64 argument is copied to the selected checkout's
  .tmp/ida-gui directory. IDA opens the /work copy and cannot modify the source.
  The canonical witness is /samples/bins/libobfuscated.dll.2026-06-03.i64.

Fresh example:
  run_ida_gui_docker.sh -w truthful-config-v2-project-ui \
    --open-config --open-workbench --function 0x401000 --mcp \
    -- /samples/bins/libobfuscated.dll.2026-06-03.i64

Existing-session example:
  run_ida_gui_docker.sh -w truthful-config-v2-project-ui \
    --connect --open-config --open-workbench --function 0x401000 \
    --mcp-endpoint http://127.0.0.1:13337/mcp
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

print_pre_action_plan() {
  printf 'D810 GUI pre-action plan:\n'
  printf '  mode: %s\n' "$PLAN_MODE"
  printf '  selected worktree: %q\n' "$WORK_DIR"
  printf '  copied IDB: %q\n' "$PLAN_COPIED_IDB"
  printf '  ordered commands: %s\n' "$PLAN_COMMANDS"
  printf '  function selector: %q\n' "$PLAN_FUNCTION_SELECTOR"
  printf '  MCP endpoint: %q\n' "$PLAN_MCP_ENDPOINT"
  printf '  request path: %q\n' "$PLAN_REQUEST_PATH"
  printf '  audit path: %q\n\n' "$PLAN_AUDIT_PATH"
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
OPEN_CONFIG=""
OPEN_WORKBENCH=""
FUNCTION_SET=""
FUNCTION_VALUE=""
CONNECT_MODE=""
CONNECT_SET=""
MCP_ENDPOINT_SET=""
MCP_ENDPOINT_VALUE="http://127.0.0.1:13337/mcp"
MCP_ENABLED=""
MCP_PORT_SET=""
MCP_PORT_VALUE="13337"
IDA_ARGS=()
unset D810_GUI_AUTOMATION_REQUEST
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
    --open-config)
      OPEN_CONFIG=1
      shift
      ;;
    --open-workbench)
      OPEN_WORKBENCH=1
      shift
      ;;
    --function)
      [ "$#" -ge 2 ] || fail "$1 requires a function name or EA"
      FUNCTION_SET=1
      FUNCTION_VALUE="$2"
      shift 2
      ;;
    --connect)
      [ -z "$CONNECT_SET" ] || fail "--connect may be specified only once"
      CONNECT_MODE=1
      CONNECT_SET=1
      shift
      ;;
    --mcp-endpoint)
      [ -z "$MCP_ENDPOINT_SET" ] || fail "--mcp-endpoint may be specified only once"
      [ "$#" -ge 2 ] || fail "$1 requires a URL"
      MCP_ENDPOINT_SET=1
      MCP_ENDPOINT_VALUE="$2"
      shift 2
      ;;
    --mcp)
      MCP_ENABLED=1
      shift
      ;;
    --mcp-port)
      [ -z "$MCP_PORT_SET" ] || fail "--mcp-port may be specified only once"
      [ "$#" -ge 2 ] || fail "$1 requires a decimal port"
      MCP_PORT_SET=1
      MCP_PORT_VALUE="$2"
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

NAMED_AUTOMATION=""
if [ -n "$OPEN_CONFIG" ] || [ -n "$OPEN_WORKBENCH" ]; then
  NAMED_AUTOMATION=1
fi
if [ -n "$FUNCTION_SET" ] && [ -z "$OPEN_WORKBENCH" ]; then
  fail "--function requires --open-workbench"
fi
if [ -n "$CONNECT_MODE" ] && [ -z "$NAMED_AUTOMATION" ]; then
  fail "--connect requires --open-config or --open-workbench"
fi
if [ -n "$CONNECT_MODE" ] && [ "${#IDA_ARGS[@]}" -gt 0 ]; then
  fail "--connect does not accept IDA arguments after --"
fi
if [ -n "$CONNECT_MODE" ] && [ -n "$MCP_ENABLED" ]; then
  fail "--mcp cannot be used with --connect"
fi
if [ -n "$CONNECT_MODE" ] && [ -n "$MCP_PORT_SET" ]; then
  fail "--mcp-port cannot be used with --connect"
fi
if [ -n "$MCP_ENDPOINT_SET" ] && [ -z "$CONNECT_MODE" ]; then
  fail "--mcp-endpoint requires --connect"
fi
if [ -n "$MCP_PORT_SET" ] && [ -z "$MCP_ENABLED" ]; then
  fail "--mcp-port requires --mcp"
fi
if [ -n "$MCP_ENABLED" ] && [ -z "$NAMED_AUTOMATION" ]; then
  fail "--mcp requires --open-config or --open-workbench"
fi
MCP_HOST_PORT=""
if [ -n "$MCP_ENABLED" ]; then
  case "$MCP_PORT_VALUE" in
    ""|*[!0-9]*)
      fail "--mcp-port must be a decimal port from 1024 through 65535: $MCP_PORT_VALUE"
      ;;
  esac
  [ "${#MCP_PORT_VALUE}" -le 5 ] \
    || fail "--mcp-port must be a decimal port from 1024 through 65535: $MCP_PORT_VALUE"
  MCP_HOST_PORT=$((10#$MCP_PORT_VALUE))
  [ "$MCP_HOST_PORT" -ge 1024 ] && [ "$MCP_HOST_PORT" -le 65535 ] \
    || fail "--mcp-port must be a decimal port from 1024 through 65535: $MCP_PORT_VALUE"
fi
if [ -n "$NAMED_AUTOMATION" ] && [ "${#IDA_ARGS[@]}" -gt 0 ]; then
  for IDA_ARG in "${IDA_ARGS[@]}"; do
    case "$IDA_ARG" in
      -S*) fail "conflicting IDA -S argument with named startup automation: $IDA_ARG" ;;
    esac
  done
fi

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

PLAN_COMMANDS="none"
if [ -n "$OPEN_CONFIG" ] && [ -n "$OPEN_WORKBENCH" ]; then
  PLAN_COMMANDS="open-config, open-workbench"
elif [ -n "$OPEN_CONFIG" ]; then
  PLAN_COMMANDS="open-config"
elif [ -n "$OPEN_WORKBENCH" ]; then
  PLAN_COMMANDS="open-workbench"
fi
PLAN_FUNCTION_SELECTOR="N/A"
if [ -n "$OPEN_WORKBENCH" ]; then
  if [ -n "$FUNCTION_SET" ]; then
    PLAN_FUNCTION_SELECTOR="$FUNCTION_VALUE"
  else
    PLAN_FUNCTION_SELECTOR="current function"
  fi
fi

if [ -n "$CONNECT_MODE" ]; then
  command -v python3 >/dev/null 2>&1 \
    || fail "python3 is required for existing-session GUI automation"
  CONNECT_CLIENT="$WORK_DIR/tools/scripts/ida_gui_connect.py"
  [ -f "$CONNECT_CLIENT" ] \
    || fail "existing-session MCP client not found: $CONNECT_CLIENT"
  CONNECT_ARGS=(
    --worktree "$WORK_DIR"
    --endpoint "$MCP_ENDPOINT_VALUE"
  )
  if [ -n "$OPEN_CONFIG" ]; then
    CONNECT_ARGS+=( --open-config )
  fi
  if [ -n "$OPEN_WORKBENCH" ]; then
    CONNECT_ARGS+=( --open-workbench )
  fi
  if [ -n "$FUNCTION_SET" ]; then
    CONNECT_ARGS+=( --function "$FUNCTION_VALUE" )
  fi
  PLAN_MODE="connect"
  PLAN_COPIED_IDB="N/A (connect mode)"
  PLAN_MCP_ENDPOINT="$MCP_ENDPOINT_VALUE"
  PLAN_REQUEST_PATH="N/A (sent directly over MCP)"
  PLAN_AUDIT_PATH="$WORK_DIR/.tmp/ida-gui/automation-<request-id>.json"
  print_pre_action_plan
  exec env \
    "PYTHONPATH=$WORK_DIR/src${PYTHONPATH:+:$PYTHONPATH}" \
    python3 "$CONNECT_CLIENT" "${CONNECT_ARGS[@]}"
fi

DEFAULT_GUI_DOCKER_IMAGE="idapro-9.4-speedups:x11"
GUI_RUNTIME_LABEL_KEY="org.d810.gui-runtime"
GUI_RUNTIME_LABEL_VALUES=("x11" "x11-dev-emulation-z3-v1")
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

MCP_PLUGIN_DIR=""
MCP_ENDPOINT=""
if [ -n "$MCP_ENABLED" ]; then
  MCP_PLUGIN_PATH="${D810_MCP_PLUGIN_DIR-$IDA_USER_DIR/plugins/ida-pro-mcp}"
  [ -n "$MCP_PLUGIN_PATH" ] \
    || fail "D810_MCP_PLUGIN_DIR is set but empty"
  MCP_PLUGIN_DIR="$(canonical_dir "$MCP_PLUGIN_PATH")" \
    || fail "MCP plugin source not found: $MCP_PLUGIN_PATH"
  [ -f "$MCP_PLUGIN_DIR/ida-plugin.json" ] \
    || fail "MCP plugin descriptor not found: $MCP_PLUGIN_DIR/ida-plugin.json"
  [ -f "$MCP_PLUGIN_DIR/src/ida_pro_mcp/ida_mcp.py" ] \
    || fail "MCP plugin entry point not found: $MCP_PLUGIN_DIR/src/ida_pro_mcp/ida_mcp.py"
  MCP_ENDPOINT="http://127.0.0.1:$MCP_HOST_PORT/mcp"
fi

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
GUI_RUNTIME_SUPPORTED=""
for EXPECTED_GUI_RUNTIME_LABEL in "${GUI_RUNTIME_LABEL_VALUES[@]}"; do
  if [ "$GUI_RUNTIME_LABEL" = "$EXPECTED_GUI_RUNTIME_LABEL" ]; then
    GUI_RUNTIME_SUPPORTED=1
    break
  fi
done
if [ -z "$GUI_RUNTIME_SUPPORTED" ]; then
  fail "Docker image $DOCKER_IMAGE is not a D810 GUI runtime; expected $GUI_RUNTIME_LABEL_KEY to be one of: ${GUI_RUNTIME_LABEL_VALUES[*]}. Build it with the command shown by --help."
fi

SAMPLES_DIR="$REPO_ROOT/samples/bins"
if [ -d "$SAMPLES_DIR" ]; then
  SAMPLES_DIR="$(canonical_dir "$SAMPLES_DIR")"
fi

IDA_DATABASE_COPY=""
IDA_DATABASE_CONTAINER_PATH=""
AUTOMATION_REQUEST_HOST_PATH=""
AUTOMATION_AUDIT_PATH=""
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
      IDA_DATABASE_CONTAINER_PATH="/work/.tmp/ida-gui/$(basename "$IDA_DATABASE_COPY")"
      IDA_ARGS[$IDA_ARG_INDEX]="$IDA_DATABASE_CONTAINER_PATH"
      break
      ;;
    esac
  done
fi

if [ -n "$NAMED_AUTOMATION" ]; then
  command -v python3 >/dev/null 2>&1 \
    || fail "python3 is required for named GUI startup automation"
  AUTOMATION_DIR="$WORK_DIR/.tmp/ida-gui"
  mkdir -p "$AUTOMATION_DIR"
  D810_GUI_AUTOMATION_REQUEST="$(
    PYTHONPATH="$WORK_DIR/src${PYTHONPATH:+:$PYTHONPATH}" python3 - \
      "$AUTOMATION_DIR" \
      "$OPEN_CONFIG" \
      "$OPEN_WORKBENCH" \
      "$FUNCTION_SET" \
      "$FUNCTION_VALUE" \
      "$IDA_DATABASE_COPY" \
      "$IDA_DATABASE_CONTAINER_PATH" \
      "$MCP_ENDPOINT" <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import secrets
import sys
import tempfile

from d810.ui.gui_automation_logic import (
    GuiAutomationRequest,
    ordered_commands,
    parse_function_selector,
)


def sha256_file(path):
    digest = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


automation_dir = pathlib.Path(sys.argv[1])
open_config = sys.argv[2] == "1"
open_workbench = sys.argv[3] == "1"
selector = parse_function_selector(sys.argv[5] if sys.argv[4] == "1" else None)
database_host_path = sys.argv[6]
database_container_path = sys.argv[7]
mcp_endpoint = sys.argv[8] or None
request_id = secrets.token_hex(16)
created_at_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
created_at_utc = created_at_utc.replace("+00:00", "Z")
request = GuiAutomationRequest(
    request_id=request_id,
    created_at_utc=created_at_utc,
    commands=ordered_commands(open_config, open_workbench),
    function_selector=selector,
    timeout_seconds=30.0,
)
document = {
    "request": {
        "request_id": request.request_id,
        "created_at_utc": request.created_at_utc,
        "commands": [command.value for command in request.commands],
        "function_selector": request.function_selector,
        "timeout_seconds": request.timeout_seconds,
    },
    "context": {
        "mode": "launch",
        "worktree": "/work",
        "idb": {
            "path": database_container_path or None,
            "sha256": (
                sha256_file(database_host_path) if database_host_path else None
            ),
        },
        "mcp_endpoint": mcp_endpoint,
    },
}
destination = automation_dir / f"automation-request-{request.request_id}.json"
temporary = tempfile.NamedTemporaryFile(
    mode="w",
    encoding="utf-8",
    dir=automation_dir,
    prefix=f".{destination.name}.",
    suffix=".tmp",
    delete=False,
)
temporary_path = pathlib.Path(temporary.name)
try:
    with temporary:
        json.dump(document, temporary, allow_nan=False, sort_keys=True)
        temporary.write("\n")
        temporary.flush()
        os.fsync(temporary.fileno())
    os.replace(temporary_path, destination)
except Exception:
    temporary.close()
    temporary_path.unlink(missing_ok=True)
    raise
print(f"/work/.tmp/ida-gui/{destination.name}")
PY
  )"
  AUTOMATION_REQUEST_NAME="$(basename "$D810_GUI_AUTOMATION_REQUEST")"
  AUTOMATION_REQUEST_ID="${AUTOMATION_REQUEST_NAME#automation-request-}"
  AUTOMATION_REQUEST_ID="${AUTOMATION_REQUEST_ID%.json}"
  AUTOMATION_REQUEST_HOST_PATH="$AUTOMATION_DIR/$AUTOMATION_REQUEST_NAME"
  AUTOMATION_AUDIT_PATH="$AUTOMATION_DIR/automation-$AUTOMATION_REQUEST_ID.json"
  export D810_GUI_AUTOMATION_REQUEST
  IDA_ARGS=( -S/work/tools/scripts/ida_gui_bootstrap.py "${IDA_ARGS[@]}" )
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
    D810_GUI_DOCKER_IMAGE|D810_DOCKER_MEMORY|D810_REPO_ROOT|D810_WORKTREE_ROOT|D810_IDA_USER_DIR|D810_GUI_DISPLAY|D810_XHOST_BIN|D810_MCP_PLUGIN_DIR)
      continue
      ;;
  esac
  printenv "$ENV_NAME" >/dev/null 2>&1 || continue
  ENV_VALUE="$(printenv "$ENV_NAME")"
  [ -n "$ENV_VALUE" ] && EXTRA_ENV_ARGS+=( -e "$ENV_NAME=$ENV_VALUE" )
done

PLAN_MODE="fresh plain"
if [ -n "$NAMED_AUTOMATION" ]; then
  PLAN_MODE="fresh named"
fi
if [ -n "$MCP_ENABLED" ]; then
  PLAN_MODE="fresh named MCP"
fi
PLAN_COPIED_IDB="${IDA_DATABASE_COPY:-N/A}"
PLAN_MCP_ENDPOINT="${MCP_ENDPOINT:-N/A}"
PLAN_REQUEST_PATH="${AUTOMATION_REQUEST_HOST_PATH:-N/A}"
PLAN_AUDIT_PATH="${AUTOMATION_AUDIT_PATH:-N/A}"
print_pre_action_plan

printf '%q plan:\n' "$0"
printf '  image:     %q\n' "$DOCKER_IMAGE"
printf '  runtime:   %q=%q\n' "$GUI_RUNTIME_LABEL_KEY" "$GUI_RUNTIME_LABEL"
printf '  memory:    %q\n' "$DOCKER_MEMORY"
printf '  checkout:  %q\n' "$WORK_DIR"
printf '  plugin:    %q -> /root/.idapro/plugins/d810\n' "$WORK_DIR"
printf '  ida reg:   image-owned (preserves Linux IDAPython target)\n'
printf '  d810 cfg:  %q -> /root/.idapro/cfg/d810 (read-write)\n' "$D810_CONFIG_DIR"
printf '  d810 logs: %q -> /root/.idapro/logs (read-write)\n' "$D810_LOG_DIR"
if [ "$D810_CONTAINER_LOG_DIR" != "/root/.idapro/logs" ]; then
  printf '  log alias: %q -> %q (matches options.json)\n' \
    "$D810_LOG_DIR" "$D810_CONTAINER_LOG_DIR"
fi
if [ -d "$SAMPLES_DIR" ]; then
  printf '  samples:   %q -> /samples/bins (read-only)\n' "$SAMPLES_DIR"
fi
if [ -n "$IDA_DATABASE_COPY" ]; then
  printf '  db copy:   %q\n' "$IDA_DATABASE_COPY"
fi
if [ -n "$MOUNT_LOGS_COMPAT" ]; then
  printf '  logs:     persistent D810 logs enabled (-l compatibility)\n'
fi
if [ -n "$MCP_ENABLED" ]; then
  printf '  mcp plugin: %q -> /root/.idapro/plugins/ida-pro-mcp (read-only)\n' \
    "$MCP_PLUGIN_DIR"
  printf '  mcp endpoint: %q\n' "$MCP_ENDPOINT"
fi
printf '  display:   %q\n' "$GUI_DISPLAY"
if [ "${#IDA_ARGS[@]}" -gt 0 ]; then
  printf '  ida args:'
  printf ' %q' "${IDA_ARGS[@]}"
  printf '\n'
else
  printf '  ida args:  (none)\n'
fi
printf '\n'

CONTAINER_PYTHONPATH="/root/.idapro/plugins/d810/src:/app/ida/python"
if [ -n "$MCP_ENABLED" ]; then
  CONTAINER_PYTHONPATH="/root/.idapro/plugins/ida-pro-mcp/src/ida_pro_mcp:$CONTAINER_PYTHONPATH"
fi

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
  -e "PYTHONPATH=$CONTAINER_PYTHONPATH"
  -v "$WORK_DIR:/work"
  -v "$D810_CONFIG_DIR:/root/.idapro/cfg/d810"
  -v "$D810_LOG_DIR:/root/.idapro/logs"
  -v "$WORK_DIR:/root/.idapro/plugins/d810"
)
if [ -n "$MCP_ENABLED" ]; then
  DOCKER_ARGS+=(
    -e "IDA_MCP_HOST=0.0.0.0"
    -e "IDA_MCP_PORT=13337"
    -e "IDA_MCP_TOOL_TIMEOUT_SEC=45"
    -p "127.0.0.1:$MCP_HOST_PORT:13337"
    -v "$MCP_PLUGIN_DIR:/root/.idapro/plugins/ida-pro-mcp:ro"
  )
fi
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
