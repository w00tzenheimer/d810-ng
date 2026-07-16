# Worktree-Aware IDA GUI Docker Launcher Design

**Status:** Approved on 2026-07-16; automation and planning contracts updated
after Tasks A-F.

**Ticket:** `d81-kcin`

## Goal

Provide one truthful macOS entry point for either a fresh native ARM64 IDA 9.3
X11 launch or a bounded action against an existing IDA MCP session. Every mode
must name the selected D810 checkout and print what it is about to do. Fresh
launches reuse scoped portable D810 state without replacing the image's Linux
IDA registry, and they open disposable copies of canonical sample databases.

## Public Interface

The launcher is `tools/scripts/run_ida_gui_docker.sh`:

```bash
./tools/scripts/run_ida_gui_docker.sh [OPTIONS] [-- IDA_ARGS...]
```

The selection and named-action options are:

- `-w, --worktree NAME`: select
  `D810_REPO_ROOT/D810_WORKTREE_ROOT/NAME`; without it, select
  `D810_REPO_ROOT`.
- `--open-config`: open and focus the D-810 Configuration dock.
- `--open-workbench`: open and focus the D810 workbench.
- `--function FUNCTION`: select an exact function name or integer EA for the
  workbench. It requires `--open-workbench`; without it, the named workbench
  action uses IDA's current function.
- `--mcp`: on a fresh named launch, mount and start the MCP plugin.
- `--mcp-port PORT`: select the fresh launch's loopback host port. It requires
  `--mcp`; the accepted range is 1024 through 65535. The container port remains
  13337.
- `--connect`: execute named actions in an existing IDA MCP session.
- `--mcp-endpoint URL`: select the existing-session endpoint. It requires
  `--connect`, accepts only loopback HTTP `/mcp` URLs, and defaults to
  `http://127.0.0.1:13337/mcp`.
- `--`: pass all remaining arguments to IDA unchanged in fresh mode.

`--open-config` always precedes `--open-workbench` when both are requested.
`--function` is not a free-form Python hook, and named fresh automation rejects
caller-supplied IDA `-S` scripts. `--connect` requires at least one named action,
accepts no IDA arguments, and cannot be combined with `--mcp` or `--mcp-port`.
Fresh `--mcp` also requires at least one named action.

The host environment overrides are `D810_REPO_ROOT`, `D810_WORKTREE_ROOT`,
`D810_GUI_DOCKER_IMAGE`, `D810_DOCKER_MEMORY`, `D810_IDA_USER_DIR`,
`D810_GUI_DISPLAY`, `D810_XHOST_BIN`, and `D810_MCP_PLUGIN_DIR`. The defaults
remain `.worktrees`, `idapro-9.3-speedups:x11-arm64`, `4g`, `$HOME/.idapro`,
`host.docker.internal:0`, `/opt/X11/bin/xhost`, and
`D810_IDA_USER_DIR/plugins/ida-pro-mcp` where applicable.

## Mode Boundaries

### Fresh plain launch

Fresh plain mode validates XQuartz, the labeled Docker GUI runtime, the selected
checkout, and scoped IDA state, then starts IDA. It creates no automation request
or audit and does not mount, start, or publish MCP.

### Fresh named launch

A fresh named launch creates an immutable request at
`.tmp/ida-gui/automation-request-<request-id>.json`, prepends the fixed
`ida_gui_bootstrap.py` IDA script, and executes only the closed named command
set. The resulting audit belongs at
`.tmp/ida-gui/automation-<request-id>.json`. The request records ordered
commands, the validated selector, selected-worktree context, copied-IDB path and
hash when present, and the MCP endpoint when MCP is explicitly enabled.

Fresh MCP publication is exactly `127.0.0.1:HOST_PORT:13337`. The plugin source
is mounted read-only and only for `--mcp`; the plan and request report the host
loopback endpoint.

### Existing-session connect

Connect mode resolves and validates the selected checkout, then runs its
`ida_gui_connect.py` client against the requested loopback endpoint. It does not
validate or launch Docker, authorize XQuartz, inspect IDA user state, copy a
database, or mount/start MCP. Its request is sent directly over MCP, so there is
no request file. A terminal typed result publishes the same audit schema beneath
the selected checkout at `.tmp/ida-gui/automation-<request-id>.json`.

## Pre-Action Plan

Before `docker run` or the existing-session MCP exchange, the launcher prints a
stable plan with these fields in this order:

1. mode;
2. selected worktree;
3. copied IDB, or explicit `N/A`;
4. ordered commands;
5. function selector, `current function`, or `N/A`;
6. MCP endpoint, or `N/A`;
7. request path, or explicit direct-MCP/`N/A` status;
8. audit path, exact when the fresh request ID exists and a deterministic
   `<request-id>` pattern for connect.

The connect plan intentionally contains no Docker image/runtime/display, sample
copy, MCP-start, or XQuartz claims.

## Worktree, State, and Sample Boundaries

The selected checkout is mounted read-write at `/work` and
`/root/.idapro/plugins/d810`, so IDA loads exactly the checkout selected by
`-w`. The launcher does not mount the whole host IDA user directory because that
would replace the image-owned Linux runtime registry. Instead, it mounts only
host `cfg/d810` and the configured D810 log directory read-write. This preserves
editable projects, `d810_function_rules.db`, diagnostic databases, and logs
without replacing the container runtime or license state.

`D810_REPO_ROOT/samples/bins` is mounted read-only at `/samples/bins` when
present. A `/samples/bins/*.i64` argument is copied into the selected checkout's
`.tmp/ida-gui/`, verified byte-for-byte, and rewritten to its `/work` path before
IDA starts. The canonical witness is:

```text
/samples/bins/libobfuscated.dll.i64
```

The source sample is never opened directly and its hash must remain unchanged.

## Validation and Error Handling

The launcher canonicalizes the repository, worktree root, selected checkout,
state paths, sample source, and optional MCP source. It rejects worktree escapes,
missing plugin entry points, conflicting or duplicate mode flags, invalid
selectors, unsafe endpoints, invalid host ports, and sample escapes before the
relevant external action. Fresh mode additionally requires localhost-authorized
XQuartz and an image labeled
`org.d810.gui-runtime=x11-dev-emulation-z3-v1`. Recovery instructions use only
`xhost +localhost`; unrestricted `xhost +` is never used.

Paths and pass-through arguments remain Bash array elements. No command is
reconstructed through `eval`.

## Verification and Acceptance Boundary

`tests/unit/tools/test_run_ida_gui_docker.py` executes the real launcher against
mock Docker and XQuartz commands. Together with
`tests/unit/tools/test_ida_gui_connect.py`, the focused suite covers fresh plain,
fresh named, fresh MCP, connect, selector and endpoint validation, immutable
request/audit context, copy safety, loopback publication, complete help, and all
four pre-action plans.

Task F adds no live IDA run. Its evidence is subprocess and repository
verification only. Earlier live acceptance established the base XQuartz lane;
the ticket remains open until the worklist's remaining named GUI lanes are
actually observed and recorded.

## Non-Goals

- Closing or commandeering an existing IDA session.
- Arbitrary remote MCP endpoints or non-loopback Docker publication.
- Arbitrary Python execution through the launcher.
- Changing or retagging `idapro-9.3:latest`.
- Changing `tools/scripts/run_system_tests_docker.sh`.
- Supporting non-XQuartz display transports or non-macOS fresh hosts here.
- Changing the host `~/.idapro/plugins/d810` symlink.
