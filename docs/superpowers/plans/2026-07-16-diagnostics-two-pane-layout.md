# Diagnostics Two-Pane Layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the Diagnostics Explorer into an equal two-pane layout with browsing and cleanup on the left and full-height structured records on the right.

**Architecture:** Change only `WorkbenchDiagnosticsPanel.OnCreate`. Compose three nested splitters: database/snapshot browser, browser/cleaner left pane, and left/records outer pane. Preserve all existing widgets, signals, adapters, and pure action logic.

**Tech Stack:** Python 3, IDAPython, PySide6/PyQt compatibility through `d810.qt_shim`, pytest AST contract tests, Docker/XQuartz IDA 9.3.

## Global Constraints

- Do not move SQLite, cleanup, navigation, or persistence behavior into Qt.
- Do not remove any current filter, sort, cleaner action, confirmation, or
  result field.
- Keep splitters user-adjustable and initialize the outer split at 1:1.
- Use the existing copied DLL IDB for live acceptance; never modify the
  canonical sample.

---

### Task 1: Lock the nested two-pane contract

**Files:**
- Modify: `tests/unit/ui/test_workbench_diagnostics_panel_contract.py`

**Interfaces:**
- Consumes: `WorkbenchDiagnosticsPanel.OnCreate`
- Produces: a source contract for `_outer_splitter`, `_left_splitter`, and
  `_browser_splitter` ownership and proportions

- [ ] **Step 1: Write the failing test**

Assert that the outer splitter contains only the left pane and record group,
uses equal stretch, and that the left splitter owns the browser and cleaner.

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
PYENV_VERSION=d810 PYTHONPATH=src pyenv exec python -m pytest \
  tests/unit/ui/test_workbench_diagnostics_panel_contract.py \
  -q
```

Expected: FAIL because the current explorer owns three top-level columns and
the cleaner still spans the entire dock.

### Task 2: Implement the layout-only refactor

**Files:**
- Modify: `src/d810/ui/workbench_diagnostics_panel.py`
- Test: `tests/unit/ui/test_workbench_diagnostics_panel_contract.py`

**Interfaces:**
- Consumes: existing database, snapshot, record, and cleaner widgets
- Produces: `_browser_splitter`, `_left_splitter`, and `_outer_splitter`

- [ ] **Step 1: Build the nested splitters**

Keep databases and snapshots side-by-side, place that browser above the cleaner
in a vertical left splitter, and place the left splitter beside the record group
in an equal horizontal outer splitter.

- [ ] **Step 2: Condense cleaner and confirmation controls**

Use compact margins/spacing, wrap controls into grids, and make the plan/result
split vertical so both retain full left-pane width.

- [ ] **Step 3: Run focused diagnostics tests**

Run:

```bash
PYENV_VERSION=d810 PYTHONPATH=src pyenv exec python -m pytest \
  tests/unit/ui/test_workbench_diagnostics_panel_contract.py \
  tests/unit/ui/test_workbench_diagnostics_logic.py \
  tests/unit/ui/test_workbench_diagnostics_commands.py \
  -q
```

Expected: all pass.

### Task 3: Verify live IDA layout and repository gates

**Files:**
- Modify: `docs/superpowers/plans/2026-07-16-d810-gui-session-worklist.md`

**Interfaces:**
- Consumes: the running Docker/XQuartz IDA and `D810.reload()`
- Produces: an X11 capture and recorded acceptance evidence

- [ ] **Step 1: Run unit and architecture verification**

Run the focused suite, full unit suite, cycle scan, ast-grep, import-linter,
`git diff --check`, and `graphify update .`.

- [ ] **Step 2: Reload and inspect live Qt**

Reload D810 in the running container, reopen Diagnostics, verify outer splitter
sizes through MCP, and capture the X11 window.

- [ ] **Step 3: Record evidence and commit**

Add the capture path and exact verification counts to the GUI worklist, then
commit the layout refinement.
