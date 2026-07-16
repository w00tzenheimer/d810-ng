# D810 GUI Session Automation and Acceptance Worklist

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task by task. Use
> `superpowers:systematic-debugging` for live failures and
> `superpowers:verification-before-completion` before closing a ticket. Steps
> use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make future D810 GUI sessions reproducible and auditable, then finish
live IDA acceptance for the function-centric workbench, registered-pass recipe
composer, config-v2 editor, and SQLite diagnostic explorer/cleaner.

**Architecture:** Keep behavior in IDA-independent Python services and pure
`*_logic.py` modules. Add one narrow IDA automation adapter exposing only named
commands. A worktree-aware Bash launcher drives either a fresh Docker/XQuartz
session or, with explicit `--connect`, an existing MCP-enabled IDA session.
Fresh launch uses an IDAPython startup bootstrap and does not require MCP.
Existing-session control uses a loopback-only MCP endpoint and a fixed
`py_eval` template that can call only the named D810 adapter. Every request and
result is written to a structured JSON audit artifact.

**Tech Stack:** Python 3.13, pytest, IDAPython, IDA 9.3, PySide6 through
`d810.qt_shim`, Bash 3.2-compatible arrays, Docker Desktop ARM64, XQuartz,
SQLite, and the local `ida-pro-mcp` plugin.

## Global constraints

- Work only in branch `diff/truthful-config-v2-project-ui` at
  `/Users/mahmoud/src/idapro/d810/.worktrees/truthful-config-v2-project-ui`.
- Keep terminal-complete and live-accepted status separate. Passing unit tests
  does not close a ticket whose Qt or IDA acceptance is still pending.
- Follow the existing action-logic convention: pure behavior in
  `src/d810/ui/*_logic.py`, thin IDA/Qt adapters, and action matrices in
  `tests/unit/ui/test_*_logic.py`.
- The UI composes registered pass implementations and explains their owned
  transforms. It does not create or edit Python pass implementations in IDA.
- Reuse the existing function rule, tag, and note persistence. A full typed
  function recipe is a sibling record sharing the same function identity and
  invalidation path; it does not replace or reinterpret existing overrides.
- Never open the canonical sample database directly. Mount `samples/bins`
  read-only, copy the selected `.i64` under `.tmp/ida-gui`, byte-verify the
  copy, and give only the copy to IDA.
- Use the DLL database, never the dylib database. The current canonical sample
  is
  `/Users/mahmoud/src/idapro/d810/samples/bins/libobfuscated.dll.2026-06-03.i64`.
- Preserve the GUI image's Linux `/root/.idapro/ida.reg`. Do not mount the
  host's whole `~/.idapro` into the container.
- Do not add a general `--eval`, `--script`, or arbitrary MCP-code option.
  Automation is a closed set of named commands.
- Publish the MCP container port as
  `127.0.0.1:<host-port>:13337`. Never publish it on every host interface.
- Do not use XQuartz coordinate automation as an acceptance oracle. This
  XQuartz server lacks XTEST, and `cliclick` currently lacks macOS
  Accessibility permission.
- Never report a microcode block serial without an EA anchor, such as
  `blk77@0x40ADE6`.
- Do not close IDA or stop a user's existing MCP session when a named command
  fails. Record the failure and return nonzero to the caller.

---

## Resume here: verified state on 2026-07-16

### Branch and commits

The worktree was clean after these commits:

- `410c568fa feat(gui): add worktree-aware IDA Docker launcher`
- `9673807cc fix(gui): isolate Docker runtime and sample state`
- `0af596641 fix(gui): require dependency-complete X11 runtime`
- `2c19f521c fix(ui): detect Qt in venv-backed IDAPython`

Recheck `git status --short --branch` and `git log -5 --oneline` before doing
new work; these hashes describe this checkpoint, not an eternal source of
truth.

### Dependency-complete GUI image

The approved image is `idapro-9.3-speedups:x11-arm64`, built from
`idapro-9.3:x11-arm64` through `docker/Dockerfile.test-runtime` so the IDA
virtualenv includes normal D810 dependencies and the isolated speedup/Z3
installation. At the checkpoint it had:

```text
image id: sha256:3c8c4f7298c7e3f9ff884b5cc4e2ec88f0344f56b3ceea5be8b61432864d9698
architecture: arm64
org.d810.gui-runtime=x11-dev-emulation-z3-v1
org.d810.test-runtime=dev-emulation-z3-v1
```

Build or rebuild it from the selected worktree with:

```bash
docker build \
  -f docker/Dockerfile.test-runtime \
  --build-arg IDA_IMAGE=idapro-9.3:x11-arm64 \
  --build-arg D810_GUI_RUNTIME_LABEL=x11-dev-emulation-z3-v1 \
  -t idapro-9.3-speedups:x11-arm64 \
  .
```

The launcher must reject an image missing the exact GUI runtime label. Do not
retag or modify `idapro-9.3:latest` as part of this lane.

### XQuartz state and recovery

The user started and authorized XQuartz with:

```bash
open -a XQuartz
/opt/X11/bin/xhost +localhost
```

The observed preferences were suitable:

- Security: `Authenticate connections` enabled.
- Security: `Allow connections from network clients` enabled.
- Windows: `Focus On New Windows` enabled.
- Windows: `Click-through Inactive Windows` disabled.
- Windows: `Focus Follows Mouse` disabled.
- Pasteboard: syncing and both clipboard update directions enabled.
- Output: full-screen mode disabled.

The launcher validates that `xhost` reports `INET:localhost` or
`INET6:localhost`. It must never recommend unrestricted `xhost +`.

For an evidence screenshot, identify the X11 window and capture it without
input automation:

```bash
/opt/X11/bin/xwininfo -display :0 -root -tree
/opt/X11/bin/xwd -display :0 -silent -id WINDOW_ID -out /tmp/d810-window.xwd
ffmpeg -hide_banner -loglevel error \
  -f image2 -i /tmp/d810-window.xwd -frames:v 1 /tmp/d810-window.png
```

### Safe current launch

From the worktree:

```bash
./tools/scripts/run_ida_gui_docker.sh \
  -w truthful-config-v2-project-ui \
  -- \
  /samples/bins/libobfuscated.dll.2026-06-03.i64
```

`tools/scripts/run_ida_gui_docker.sh` currently:

- resolves the selected linked worktree like `run_system_tests_docker.sh -w`;
- mounts that checkout at `/work` and `/root/.idapro/plugins/d810`;
- preserves the image-owned Linux IDA registry;
- mounts host `cfg/d810` and the configured D810 log directory;
- thereby reuses existing function override saves and diagnostic databases;
- mounts canonical `samples/bins` read-only;
- copies a selected `.i64` to `.tmp/ida-gui`, byte-verifies it, and opens the
  `/work` copy;
- forwards the supported D810 diagnostic/debug environment toggles; and
- defaults to the labeled dependency-complete GUI image.

The last verified canonical SHA-256 was:

```text
61678430e3fe08f6bb23f41752faa22b57c805e8261277660933d01e3c046dab
```

One last observed safe copy was
`.tmp/ida-gui/libobfuscated.dll.2026-06-03.docker.up7Ey0.i64` with the same
hash. Treat that path as disposable evidence, not as the next session's input.

The last observed container was `050bae6d5474` (`priceless_darwin`). It was an
ephemeral `docker run --rm` QA instance and must not be assumed to exist.

### Qt failure, root cause, and live fix

The original live failure was:

```text
AttributeError: 'QVBoxLayout' object has no attribute 'addLayout'
```

at `src/d810/ui/ida_ui.py:561`. The pre-fix probe showed:

```text
D810_QT_PROBE_BEFORE /app/ida/.venv/bin/python3 False PyQt5 d810.qt_shim False
```

`src/d810/qt_shim.py` had inferred GUI availability from the executable name.
The image correctly uses `/app/ida/.venv/bin/python3`, so the shim incorrectly
installed its headless proxy layouts inside real GUI IDA. Commit `2c19f521c`
replaced that heuristic with `idaapi.is_idaq()` and added
`tests/unit/test_qt_shim.py::test_ida_gui_detection_accepts_virtualenv_backed_idapython`.

The post-fix live probe returned:

```json
{
  "sys_executable": "/app/ida/.venv/bin/python3",
  "qt_available": true,
  "qt_binding": "PySide6",
  "qvboxlayout_module": "PySide6.QtWidgets",
  "qvboxlayout_has_add_layout": true
}
```

The `D-810 Configuration` dock then rendered without a callback traceback and
showed:

- mode `Config v2 (routed)`;
- source `default_unflattening_ollvm.json`;
- runtime `default_unflattening_ollvm_config_v2_canary.json`;
- 11 effective passes; and
- 180 expanded instruction rules and 6 expanded block rules.

This satisfies Slice 0's live config rendering gate. It does not satisfy the
workbench or later dock gates.

### Current public UI seams

- `src/d810/ui/ida_ui.py::D810ConfigForm_t.Show()` opens
  `D-810 Configuration`.
- `src/d810/ui/ida_ui.py::D810GUI.show_windows()` owns the config-dock action.
- `src/d810/ui/actions/deobfuscation_stats.py::DeobfuscationStats.ACTION_ID`
  is stable at `d810ng:deobfuscation_stats`.
- That compatibility action opens
  `DeobfuscationWorkbenchPanel`, supplies the current pseudocode function, and
  calls `show(focus_section="evidence")`.
- The workbench action is pseudocode-only. Automation must resolve a function,
  open/activate pseudocode, and then invoke the stable action ID.
- `src/d810ng.py::D810Plugin.run()` reloads D810; it is not the show-config
  operation.
- The reloader publishes the outer plugin as `__main__.D810`; the real state is
  under `__main__.D810.plugin`.
- `idaapi.run_plugin()` may return false because `D810Plugin.run()` returns
  `None` even when reload/UI work succeeds. Never use that boolean as the
  automation success oracle.

### Current automated verification checkpoint

At `2c19f521c` the following passed:

```text
5906 passed, 29 skipped, 9 warnings, 162 subtests passed in 50.13s
sg scan: clean
import-linter: 13 kept, 0 broken
git diff --check: clean
```

Rerun the actual commands before making a new completion claim:

```bash
PYTHONPATH=src pyenv exec python -m pytest tests/unit -q
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
git diff --check
graphify update .
```

---

## Approved automation contract

Both modes are required.

### Fresh Docker launch

These commands start a new container and open a copied IDB:

```bash
./tools/scripts/run_ida_gui_docker.sh \
  -w truthful-config-v2-project-ui \
  --open-config \
  -- \
  /samples/bins/libobfuscated.dll.2026-06-03.i64

./tools/scripts/run_ida_gui_docker.sh \
  -w truthful-config-v2-project-ui \
  --open-workbench \
  --function FUNCTION_NAME_OR_EA \
  -- \
  /samples/bins/libobfuscated.dll.2026-06-03.i64
```

Fresh named actions use one checked-in IDAPython bootstrap. They do not require
MCP. Both named flags may be supplied together; the deterministic order is
config first and workbench second, leaving workbench focused.

`--function` is optional. When present, it accepts only an exact function name
or an integer EA spelling supported by the pure parser. When absent,
`--open-workbench` uses the current function. If neither resolves to a real
function, the command fails explicitly instead of silently opening a contextless
dock.

MCP is opt-in for a fresh session:

```bash
./tools/scripts/run_ida_gui_docker.sh \
  -w truthful-config-v2-project-ui \
  --mcp \
  --open-workbench \
  --function FUNCTION_NAME_OR_EA \
  -- \
  /samples/bins/libobfuscated.dll.2026-06-03.i64
```

`--mcp` mounts the local MCP plugin, starts it in the IDA process, sets the
container listener to `0.0.0.0:13337`, and publishes it only as
`127.0.0.1:<host-port>:13337`. The default host port is 13337 and a future
override is `--mcp-port PORT`.

### Existing MCP-enabled session

These commands do not launch Docker and do not open another IDB:

```bash
./tools/scripts/run_ida_gui_docker.sh \
  -w truthful-config-v2-project-ui \
  --connect \
  --open-config

./tools/scripts/run_ida_gui_docker.sh \
  -w truthful-config-v2-project-ui \
  --connect \
  --open-workbench \
  --function FUNCTION_NAME_OR_EA
```

The default endpoint is `http://127.0.0.1:13337/mcp`. An endpoint override may
be accepted only when its parsed host is loopback unless the user makes a
separate, explicit security decision in a future specification. `--connect`
requires at least one named action, rejects raw IDA arguments, and never starts
or stops the remote IDA process.

The host client uses only Python's standard library (`urllib.request`, `json`,
`base64`, and `pathlib`). It performs MCP `initialize`, `ping`, and
`tools/call`. The only unsafe call is MCP's existing `py_eval`, with a constant
code template that imports D810's named-command adapter and decodes a strictly
validated data payload. No user text is interpolated as Python source.

### Audit artifact

Each mode writes
`.tmp/ida-gui/automation-<request-id>.json`. Use this schema version 1 shape:

```json
{
  "schema_version": 1,
  "request_id": "opaque-random-token",
  "mode": "launch",
  "created_at_utc": "2026-07-16T18:30:00Z",
  "completed_at_utc": "2026-07-16T18:30:01Z",
  "worktree": "/work",
  "idb": {
    "path": "/work/.tmp/ida-gui/libobfuscated.dll.2026-06-03.docker.ABC123.i64",
    "sha256": "hex-digest"
  },
  "mcp_endpoint": null,
  "requested_commands": ["open-config", "open-workbench"],
  "function_selector": "FUNCTION_NAME_OR_EA",
  "commands": [
    {
      "name": "open-config",
      "started_at_utc": "2026-07-16T18:30:00Z",
      "finished_at_utc": "2026-07-16T18:30:00Z",
      "status": "succeeded",
      "details": {
        "widget_title": "D-810 Configuration"
      },
      "error": null
    }
  ],
  "status": "succeeded",
  "error": null
}
```

Allowed top-level and per-command statuses are `pending`, `succeeded`,
`failed`, and `timed_out`. Writes are atomic (`tempfile` plus `os.replace`). A
bounded startup timeout defaults to 30 seconds. Success means the expected
widget exists and is visible/focused, not merely that a plugin API returned a
truthy value.

---

## Implementation tasks for named GUI automation

### Task A: Pure request, result, and audit logic

**Files:**

- Create: `src/d810/ui/gui_automation_logic.py`
- Create: `tests/unit/ui/test_gui_automation_logic.py`

**Interfaces:**

- `GuiCommand` enum with exactly `OPEN_CONFIG` and `OPEN_WORKBENCH`.
- Immutable `GuiAutomationRequest`, `GuiCommandResult`, and
  `GuiAutomationResult` models.
- `parse_function_selector(value: str | None)` accepts `None`, exact names, and
  integer EA spellings; rejects empty, ambiguous, and executable input.
- `ordered_commands(config: bool, workbench: bool)` returns config before
  workbench and rejects an empty request.
- `audit_document(request, result, context)` returns only JSON-native values.

- [x] Write failing table-driven tests for the two command names, deterministic
  ordering, selectors, timeouts, partial failure, and exact schema-v1 output.
- [x] Add immutable models and pure functions without importing IDA, Qt,
  sqlite3, Docker, or MCP.
- [x] Prove unknown command strings and malformed selectors fail closed.
- [x] Run:

  ```bash
  PYTHONPATH=src pyenv exec python -m pytest \
    tests/unit/ui/test_gui_automation_logic.py -q
  ```

### Task B: Thin IDA named-command adapter

**Files:**

- Create: `src/d810/ui/gui_automation.py`
- Create: `tests/unit/ui/test_gui_automation_adapter_contract.py`
- Update: `src/d810/ui/ida_ui.py`
- Update: `src/d810/ui/actions/deobfuscation_stats.py`

**Interfaces:**

- `run_named_commands(request: GuiAutomationRequest) -> GuiAutomationResult`
  is the only public automation entry point.
- `open_config()` delegates to the loaded state's existing
  `D810GUI.show_windows()` and verifies the `D-810 Configuration` widget.
- `open_workbench(selector)` resolves a real function, opens and activates its
  pseudocode widget, invokes `d810ng:deobfuscation_stats`, and verifies
  `d810-ng Deobfuscation Workbench`.
- All IDA work runs on the IDA main thread. No pure module imports IDA.

- [x] Write failing adapter tests with fake state, function resolver, widget
  registry, action invoker, and main-thread scheduler.
- [x] Make config automation reuse `D810GUI.show_windows()`; do not construct a
  second config form.
- [x] Make workbench automation reuse the stable Stats action and current
  workbench singleton; do not duplicate its snapshot/command logic.
- [x] Verify success from actual widget state and captured function identity.
- [x] Verify a missing plugin state, missing function, Hex-Rays failure,
  action failure, and widget timeout each produce a structured failed result
  without terminating IDA.
- [x] Add an AST/source contract proving the adapter imports
  `gui_automation_logic` while the pure logic file imports neither IDA nor Qt.
- [x] Run:

  ```bash
  PYTHONPATH=src pyenv exec python -m pytest \
    tests/unit/ui/test_gui_automation_logic.py \
    tests/unit/ui/test_gui_automation_adapter_contract.py \
    tests/unit/ui/test_actions_migration.py \
    tests/unit/ui/test_workbench_adapter_contract.py -q
  ```

### Task C: Fresh-launch bootstrap

**Files:**

- Create: `tools/scripts/ida_gui_bootstrap.py`
- Create: `tests/unit/tools/test_ida_gui_bootstrap.py`
- Update: `tools/scripts/run_ida_gui_docker.sh`
- Update: `tests/unit/tools/test_run_ida_gui_docker.py`

**Interfaces:**

- The launcher writes a validated request JSON below `.tmp/ida-gui`.
- It passes only `-S/work/tools/scripts/ida_gui_bootstrap.py` to IDA and points
  the bootstrap to the request with `D810_GUI_AUTOMATION_REQUEST`.
- `D810Plugin.late_init()` starts the existing core state once. The bootstrap
  then polls with an IDA timer until `__main__.D810.plugin` reports loaded,
  dispatches once, writes the audit atomically, and unregisters itself.
- The bootstrap never reloads D810 as a side effect of opening a dock.

- [x] Extend the subprocess harness with failing tests for `--open-config`,
  `--open-workbench`, both-command ordering, `--function`, empty commands, and
  exact request/IDA arguments.
- [x] Unit-test bootstrap polling, one-shot dispatch, 30-second timeout,
  exception capture, and atomic audit output with fake timer and clock seams.
- [x] Parse named flags before `--`; preserve every post-`--` IDA argument.
- [x] Reject a caller-provided conflicting `-S` argument when named startup
  automation is active.
- [x] Keep plain launch behavior byte-for-byte compatible when no named command
  is requested.
- [x] Run:

  ```bash
  PYTHONPATH=src pyenv exec python -m pytest \
    tests/unit/tools/test_run_ida_gui_docker.py \
    tests/unit/tools/test_ida_gui_bootstrap.py -q
  ```

### Task D: Optional loopback MCP on fresh launch

**Files:**

- Update: `tools/scripts/run_ida_gui_docker.sh`
- Update: `tools/scripts/ida_gui_bootstrap.py`
- Update: `tests/unit/tools/test_run_ida_gui_docker.py`
- Update: `tests/unit/tools/test_ida_gui_bootstrap.py`

**External source mounted read-only:**

- Host: `/Users/mahmoud/src/idapro/mcp_servers/ida-pro-mcp`
- Container: `/root/.idapro/plugins/ida-pro-mcp`

**Interfaces:**

- `--mcp` opts into mounting and starting the MCP package.
- `--mcp-port PORT` validates a decimal port from 1024 through 65535.
- Container environment is `IDA_MCP_HOST=0.0.0.0` and
  `IDA_MCP_PORT=13337`.
- Docker publication is exactly
  `-p 127.0.0.1:<host-port>:13337`.

- [x] Write failing launcher tests proving there is no MCP mount, environment,
  or port without `--mcp`.
- [x] Write failing tests for the exact read-only plugin mount and loopback
  publication with `--mcp`.
- [x] Reject missing MCP source, invalid ports, duplicate port flags, and MCP
  flags in `--connect` mode where they do not apply.
- [x] Start the server in the bootstrap through the MCP package's public server
  initialization path, in its background thread, and record server-start
  success/failure in the audit.
- [x] Do not open the MCP configuration dialog and do not expose a generic
  Python execution flag.
- [x] Verify with `docker inspect` that the host binding IP is `127.0.0.1`.

### Task E: Explicit existing-session client

**Files:**

- Create: `tools/scripts/ida_gui_connect.py`
- Create: `tests/unit/tools/test_ida_gui_connect.py`
- Update: `tools/scripts/run_ida_gui_docker.sh`
- Update: `tests/unit/tools/test_run_ida_gui_docker.py`

**Interfaces:**

- `--connect` switches from Docker launch to the host MCP client.
- Default endpoint is `http://127.0.0.1:13337/mcp`.
- The client performs JSON-RPC `initialize`, `ping`, and `tools/call` with
  bounded HTTP timeouts.
- `tools/call` is exactly `py_eval`; its code is a constant template whose only
  operation is importing and calling `run_named_commands` with decoded,
  validated request data.

- [x] Write a local fake HTTP server that captures complete JSON-RPC requests
  and returns success, tool error, malformed JSON, HTTP failure, and timeout.
- [x] Prove the client rejects non-loopback endpoint hosts, endpoint userinfo,
  fragments, unknown commands, and raw post-`--` IDA arguments.
- [x] Prove arbitrary selector text remains data and never appears in the
  Python source portion of the `py_eval` request.
- [x] Decode the MCP structured result, validate it as a D810 automation result,
  and write the same schema-v1 audit used by fresh launch.
- [x] Return zero only when all requested commands succeed. Do not stop or
  otherwise mutate the MCP server lifecycle.
- [x] Run:

  ```bash
  PYTHONPATH=src pyenv exec python -m pytest \
    tests/unit/tools/test_ida_gui_connect.py \
    tests/unit/tools/test_run_ida_gui_docker.py -q
  ```

### Task F: User-facing help and contract verification

**Files:**

- Update: `tools/scripts/run_ida_gui_docker.sh`
- Update: `docs/superpowers/specs/2026-07-16-worktree-aware-ida-gui-docker-launcher-design.md`
- Update: `docs/superpowers/plans/2026-07-16-worktree-aware-ida-gui-docker-launcher.md`
- Update: `.tickets/d81-kcin.md`

- [x] Make `--help` document fresh launch, `--connect`, `--open-config`,
  `--open-workbench`, `--function`, `--mcp`, loopback binding, audit paths, and
  the DLL sample.
- [x] Print a launch/connect plan before acting, including selected worktree,
  copied IDB, named commands, function selector, endpoint, and audit path.
- [x] Add subprocess contract tests for every help and plan field.
- [x] Run the focused GUI automation tests, then the full unit/boundary gates.
- [x] Commit automation separately from live visual acceptance so regressions
  are bisectable.

---

## UI product work and live acceptance

The approved product design is
`docs/superpowers/specs/2026-07-15-deobfuscation-workbench-ui-design.md`.
The parent ticket is `.tickets/d81-38ha.md`.

### Slice 0: truthful config-v2 project UI (`d81-kcin`)

Status: terminal-complete and live config rendering accepted.

- [x] Distinguish legacy and routed config-v2 mode.
- [x] Show source and effective runtime project identities.
- [x] Show 11 effective passes and 180/6 expanded rule counts for the OLLVM
  witness.
- [x] Make unsafe config-v2 edits read-only and duplication lossless.
- [x] Fix virtualenv-backed IDAPython Qt detection.
- [x] Render the live configuration dock without callback errors.
- [x] Add the named `--open-config` automation/audit lane before closing the
  ticket so future acceptance is reproducible.

### Slice 1: read-only workbench (`tcvpu-nyvc`)

Status: complete through live Docker/XQuartz acceptance on 2026-07-16.

- [x] Launch with `--open-workbench --function FUNCTION_NAME_OR_EA` and verify
  the dock opens on the requested function.
- [x] Verify function name/EA, source/runtime project, attack summary, ordered
  stages, outcomes, rule scope, statistics, and artifacts are truthful.
- [x] Verify filtering, row selection, details, refresh, function following,
  theme readability, and dock restoration.
- [x] Export evidence and compare it byte-for-byte with the pure deterministic
  exporter output.
- [x] Close/reopen the dock and verify singleton recreation has no stale Qt
  references or shutdown crash.
- [x] Capture an X11 screenshot plus the automation audit artifact.

### Slice 2: scoped workbench interaction (`tcvpu-z1b4`)

Status: terminal-complete through `ea212f738`; live command acceptance pending.

- [ ] Prove `Analyze` invokes recon collection only and does not mutate
  microcode or start the D810 optimizer.
- [ ] Prove `Deobfuscate` delegates to the existing manager lifecycle exactly
  once.
- [ ] Prove `Function override` opens and saves through the existing function
  rule/tag/note store; do not create a parallel override database.
- [ ] Change function/generation during an action and verify stale completion is
  rejected and rendered stale.
- [ ] Restart D810 and verify the saved function override is reused.

### Slice 3: native decompile comparison (`tcvpu-guv6`)

Status: implementation plan exists; complete headless and live gates remain.

- [ ] Implement the identity-bearing native and D810 comparison artifacts per
  `docs/superpowers/plans/2026-07-16-deobfuscation-workbench-slice-3.md` using
  test-first steps.
- [ ] Capture one native decompile with D810 hooks suppressed without changing
  persistent engine state.
- [ ] Verify baseline and D810 output carry function fingerprint, IDB identity,
  type information, Hex-Rays version, runtime project, and generation.
- [ ] Verify an identity/generation mismatch is labeled stale, never current.
- [ ] Exercise Compare in live IDA and capture the result/audit evidence.

### Slice 4: registered-pass Recipe Composer (`tcvpu-004o`)

Status: headless catalog, drafts, preflight, apply/save, and sibling recipe
persistence are implemented; Qt/live acceptance pending.

- [ ] Add a thin Recipe Composer dock/section backed only by the existing
  recipe service and `workbench_recipe_logic.py`.
- [ ] List registered stable pass IDs and explain each pass's owned transforms.
  Do not present transforms as independently runnable unless registered.
- [ ] Verify add, remove, enable, disable, reorder, template load, and reset are
  deterministic.
- [ ] Block unknown passes, options, missing contracts, and invalid order before
  execution with a specific preflight explanation.
- [ ] Save a full typed recipe beside the existing function override record,
  then prove rule/tag/note values are unchanged.
- [ ] Apply a valid recipe exactly once and reject a stale-generation apply.
- [ ] Keep project-profile save disabled until Slice 5's serializer boundary is
  live-accepted.

### Slice 5: v2-aware advanced project editing (`tcvpu-qzth`)

Status: headless serializers, lossless persistence, routing propagation, and
atomic save/reload are implemented; Qt/live acceptance pending.

- [ ] Add thin editors only for fields with declared serializers.
- [ ] Keep unknown and unsupported document fields visible/read-only and prove
  they survive a save unchanged.
- [ ] Edit pass/rule selection and routing policy, validate the full pipeline,
  write atomically, and reload through the manager.
- [ ] Refuse bundled-default overwrite and every edit that would cause a flat
  rule semantic downgrade.
- [ ] Verify a live routing edit changes family selection as specified and can
  be reverted losslessly.

### Diagnostics D0: read-only SQLite explorer (`tcvpu-u83u`)

Status: headless inventory, newest-first sorting, structured anchored records,
and selection logic are implemented; Qt/live navigation pending.

- [ ] Add a thin diagnostics dock backed by the existing manager facade and
  `workbench_diagnostics_logic.py`; Qt must not import sqlite3 or storage
  models.
- [ ] Discover generated diagnostic databases and default to newest-first using
  timestamp, stable ID, and path tie breakers.
- [ ] Expose explicit sort controls including latest/newest and oldest.
- [ ] Filter by database, snapshot, function, stage, and outcome without an
  arbitrary SQL console.
- [ ] Render every block as `serial@EA` and make function/block rows navigate to
  the anchored IDA address.
- [ ] Keep inventory connections read-only and verify browsing cannot mutate
  the database, WAL, or SHM files.

### Diagnostics D1: transactional SQLite cleaner (`tcvpu-oij1`)

Status: headless cleanup scopes, transactions, active-path protection,
integrity checks, quarantine, WAL handling, and vacuum outcomes are
implemented; Qt confirmation/live acceptance pending.

- [ ] Add explicit actions for selected snapshots, all snapshots in one
  database, keep latest N, older-than, selected databases, all closed
  databases, delete all, and vacuum.
- [ ] Show the exact planned database paths, snapshot IDs, counts, and reclaimed
  estimate before enabling confirmation.
- [ ] Require typed confirmation for `delete all` and all-database operations.
- [ ] Skip active databases and recheck active-path/identity immediately before
  execution to close the TOCTOU window.
- [ ] Delete snapshot-owned rows by exact snapshot ID, dependents first and
  parent last, in one rollback-safe transaction.
- [ ] Fail closed on an unknown snapshot-owned table.
- [ ] Quarantine database, WAL, and SHM sidecars together instead of unlinking
  them; expose restore instructions and the quarantine path.
- [ ] Report cleanup transaction, integrity check, sidecar handling, and vacuum
  as separate outcomes.
- [ ] Refresh the explorer after cleanup and verify newest-first ordering and
  counts remain truthful.

---

## MCP facts for future sessions

The host MCP plugin currently resolves through:

```text
/Users/mahmoud/.idapro/plugins/ida-pro-mcp
  -> /Users/mahmoud/src/idapro/mcp_servers/ida-pro-mcp
```

Its entry point is `src/ida_pro_mcp/ida_mcp.py`, plugin name is `MCP`, version
is 2.0.0, and hotkey is `Ctrl-Alt-M`. It reads `IDA_MCP_HOST` (default
`127.0.0.1`) and `IDA_MCP_PORT` (default `13337`) and serves in a background
thread. Direct protocol methods include `initialize`, `ping`, and `tools/call`.

The MCP plugin exposes an unsafe `py_eval(code)` tool synchronized onto IDA's
main thread. That makes explicit `--connect` possible, but it is also the reason
the Docker port must remain loopback-only and the D810 launcher must never
offer arbitrary evaluation.

For protocol debugging, the `tools/call` request shape is:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "py_eval",
    "arguments": {
      "code": "CONSTANT_D810_NAMED_COMMAND_TEMPLATE"
    }
  }
}
```

Use this only through the checked-in host client after its request-validation
tests pass.

---

## Final verification and ticket closure

- [ ] Run focused tests for every modified UI logic, adapter, launcher,
  bootstrap, MCP client, workbench, recipe, config-v2, and diagnostic module.
- [ ] Run the full unit suite and record exact fresh counts in the ticket.
- [ ] Run the architecture gates from this worktree:

  ```bash
  sg scan --config sgconfig.yml --report-style short
  PYTHONPATH=src lint-imports --config .importlinter
  git diff --check
  ```

- [ ] Run `graphify update .` after code changes.
- [ ] Launch the copied DLL IDB with the dependency-complete image.
- [ ] Capture the named-command audit JSON, relevant IDA output, and an X11
  screenshot for every live ticket acceptance.
- [ ] Verify the canonical sample SHA-256 is unchanged after each session.
- [ ] Update each child ticket with commit, focused tests, full tests,
  architecture gates, live actions, artifact paths, and remaining limitations.
- [ ] Close a child ticket only when its terminal and live gates are both
  complete. Close `d81-38ha` only after all eight child scopes are accepted.

## Explicit non-solutions

- Mounting all of host `~/.idapro` into Linux IDA.
- Opening or copying from `libobfuscated.dylib*.i64` for the DLL acceptance
  lane.
- Trusting `idaapi.run_plugin()`'s boolean as proof a dock opened.
- Using `xdotool`, XTEST, or screen coordinates as the acceptance driver.
- Adding ast-grep or import-linter ignores to bypass a boundary failure.
- Allowing Qt to own pass execution, SQLite cleanup, config persistence, or
  function-override semantics.
- Generating Python pass implementations in IDA.
- Exposing raw SQL or raw Python through launcher flags.
- Deleting an active diagnostic database or unlinking diagnostic files instead
  of quarantining them.
- Calling a headless-complete slice live-complete without direct IDA evidence.
