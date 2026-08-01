# Worktree-Aware IDA GUI Docker Launcher Implementation Plan

**Goal:** Maintain one tested launcher for fresh worktree-aware IDA GUI sessions
and bounded named actions against an existing loopback MCP session.

**Architecture:** `run_ida_gui_docker.sh` owns mode selection, worktree
resolution, fresh-launch validation, immutable request preparation, and the
human-readable pre-action plan. Fresh named execution crosses one fixed
`ida_gui_bootstrap.py` boundary. Existing-session execution crosses one selected-
worktree `ida_gui_connect.py` boundary. Pure automation types, selector parsing,
ordering, result validation, and audit serialization live in
`src/d810/ui/gui_automation_logic.py`.

**Tech stack:** Bash 3.2-compatible arrays, Docker Desktop, XQuartz, Python
standard-library HTTP, pytest subprocess fakes, and pure Python automation
logic.

## Current Shipped Contract

The original fresh-only launcher has been extended through the approved GUI
automation worklist:

- plain fresh launch: no named request, no audit, no MCP intent;
- named fresh launch: `--open-config`, `--open-workbench`, and optional exact
  `--function`, with configuration ordered before workbench;
- named fresh MCP launch: explicit `--mcp`, optional validated `--mcp-port`,
  read-only plugin mount, and loopback-only host publication;
- existing-session action: explicit `--connect` and optional validated
  `--mcp-endpoint`, using the selected worktree client without Docker, XQuartz,
  IDA-state, sample-copy, or MCP-start work;
- immutable fresh request files and one shared structured audit schema beneath
  the selected checkout's `.tmp/ida-gui/`;
- a stable pre-action plan for all four modes.

The launcher still accepts `-l`, `--enable-debug-logging`,
`--enable-diag-snapshot`, and `--disable-fact-lifecycle`, plus safe `D810_*`
environment forwarding for fresh mode.

## Corrected Runtime and Data Boundaries

The whole host IDA user directory is not mounted. Live acceptance showed that
doing so replaces the image-owned Linux registry with incompatible host state.
The implementation mounts only `cfg/d810` and the configured D810 log directory,
preserving project overrides, `d810_function_rules.db`, diagnostics, and logs.

The selected checkout is mounted at `/work` and
`/root/.idapro/plugins/d810`. Canonical `samples/bins` is read-only at
`/samples/bins`. The accepted witness path is exactly:

```text
/samples/bins/libobfuscated.dll.2026-06-03.i64
```

The launcher copies a selected sample into the chosen worktree's
`.tmp/ida-gui/`, verifies it byte-for-byte, and passes only the `/work` copy to
IDA. It never opens the canonical witness directly.

Fresh mode requires the image label
`org.d810.gui-runtime=x11-dev-emulation-z3-v1` and localhost-authorized XQuartz.
MCP host publication is exactly loopback-only, with fixed container port 13337.

## Named Automation Boundaries

The public named-action flags and dependencies are:

```text
--open-config
--open-workbench
--function FUNCTION     requires --open-workbench
--mcp                   fresh named only
--mcp-port PORT         requires --mcp
--connect               existing session, named actions only
--mcp-endpoint URL      requires --connect
```

Both named flags produce the deterministic order `open-config,
open-workbench`. Without `--function`, a workbench action selects the current
function. The selector grammar accepts only exact names or integer EAs. Named
fresh mode rejects caller `-S` scripts, and connect rejects all raw IDA
arguments. Connect also rejects fresh-only `--mcp` and `--mcp-port`.

Plain fresh arguments after `--` remain distinct Bash array elements. The one
rewrite is `/samples/bins/*.i64`: the launcher copies and verifies it, then
replaces that element with the `/work/.tmp/ida-gui/` copy. Named fresh rejects
caller `-S*` elements, while connect rejects every post-`--` element.

A fresh named request is written atomically at:

```text
.tmp/ida-gui/automation-request-<request-id>.json
```

Fresh and connect results use the same audit location and schema:

```text
.tmp/ida-gui/automation-<request-id>.json
```

The existing-session client uses bounded `http.client.HTTPConnection`
exchanges, validates canonical loopback HTTP `/mcp` endpoints, caps response
size, applies one end-to-end deadline, rejects protocol mismatches, and writes
audits atomically inside the selected worktree.

## Task F: Truthful Help and Pre-Action Plan

### Files

- Modify: `tools/scripts/run_ida_gui_docker.sh`
- Modify: `tests/unit/tools/test_run_ida_gui_docker.py`
- Modify:
  `docs/superpowers/specs/2026-07-16-worktree-aware-ida-gui-docker-launcher-design.md`
- Modify:
  `docs/superpowers/plans/2026-07-16-worktree-aware-ida-gui-docker-launcher.md`
- Modify: `.tickets/d81-kcin.md`
- Create ignored evidence: `.superpowers/sdd/task-F-report.md`

### Test-first sequence

1. Add subprocess assertions for complete help and normalized plans for plain
   fresh, named fresh, named fresh MCP, and connect.
2. Run the focused selection and record RED before changing the launcher.
3. Implement the smallest stable plan and help contract.
4. Run the focused selection and the combined launcher/client suite for GREEN.
5. Update this plan, the design spec, the ticket evidence boundary, and the
   ignored Task F report.

The plan fields are, in order: mode, selected worktree, copied IDB or explicit
`N/A`, ordered commands, selector, endpoint, request path, and audit path.
Fresh named plans use exact generated paths. Connect reports a direct MCP
request and the deterministic audit-path pattern; it must not claim a database
copy, Docker/XQuartz work, or MCP startup.

CLI- and path-derived plan values use Bash 3.2 `%q`, so control characters and
newlines cannot create forged plan fields. Fixed mode and command labels remain
plain text; ordinary selectors and loopback URLs remain human-readable.

Help must document both modes, every named/MCP flag, all flag dependencies,
loopback publication, request/audit paths, and the canonical DLL witness.

### Automated verification

Run from the target worktree:

```bash
bash -n tools/scripts/run_ida_gui_docker.sh
PYTHONPATH=src py.test -q \
  tests/unit/tools/test_ida_gui_connect.py \
  tests/unit/tools/test_run_ida_gui_docker.py
PYTHONPATH=src py.test -q tests/unit
black --check src tests
python3 -m compileall -q src tests
git diff --check
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
graphify update .
```

The report must preserve the exact RED and GREEN counts and distinguish focused
Task F proof from the full repository suite.

## Acceptance and Commit Boundary

Task F is automation and documentation only. It must not be described as new
live GUI acceptance. Record the reproducible named `--open-config` command lane
and the request/audit evidence boundary on `d81-kcin`. That ticket remains open
specifically for a live named `--open-config` request/audit confirmation of
Slice 0. Separate workbench, recipe, config-v2, and SQLite live lanes remain on
their child tickets and are not `d81-kcin` completion criteria.

Create one scoped Task F commit containing the launcher, its subprocess tests,
the updated design and plan, and the ticket note. Keep this commit separate from
any later live IDA acceptance evidence.
