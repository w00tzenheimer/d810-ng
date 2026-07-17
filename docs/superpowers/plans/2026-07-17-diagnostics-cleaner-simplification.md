# Diagnostics Cleaner Simplification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the diagnostics cleaner button grid and Unix timestamp flow with an intent-based composer backed by only explicit selection and count-based retention.

**Architecture:** Retire the time-based cleanup scope from diagnostics through manager-facing UI commands. Keep cleanup planning and execution in the diagnostics service; project action state in pure UI logic; let the Qt panel render a single selector, conditional retention input, preview, and post-preview confirmation controls.

**Tech Stack:** Python 3.13, pytest, IDA Qt/PyQt compatibility shim.

## Global Constraints

- Ticket `tcvpu-f21a` tracks this work.
- No Unix timestamp or time-based cleanup action remains in the supported API.
- Cleanup stays plan-first, transaction-safe, active-session-safe, and uses reversible database quarantine.
- The panel imports no SQLite or diagnostics implementation modules.
- UI execution always requests a WAL checkpoint.

---

### Task 1: Retire time-based cleanup from the supported API

**Files:**
- Modify: `src/d810/diagnostics/workbench_models.py`
- Modify: `src/d810/diagnostics/workbench_cleanup.py`
- Modify: `src/d810/manager/manager.py`
- Modify: `src/d810/manager/state.py`
- Modify: `tests/unit/diagnostics/test_workbench_models.py`
- Modify: `tests/unit/diagnostics/test_workbench_cleanup_plans.py`
- Modify: `tests/unit/diagnostics/test_workbench_cleanup_execution.py`
- Modify: `tests/unit/manager/test_workbench_diagnostics_facade.py`

- [ ] Write focused failing tests that assert only selected/all/retention/database/vacuum scopes remain and no manager time-planning facade is exposed.
- [ ] Remove `OLDER_THAN`, `plan_older_than`, and their manager/state facade methods.
- [ ] Run the focused diagnostics and manager tests.
- [ ] Commit the API retirement.

### Task 2: Project and route the simplified UI intent

**Files:**
- Modify: `src/d810/ui/workbench_diagnostics_logic.py`
- Modify: `src/d810/ui/workbench_diagnostics_commands.py`
- Modify: `tests/unit/ui/test_workbench_diagnostics_logic.py`
- Modify: `tests/unit/ui/test_workbench_diagnostics_commands.py`

- [ ] Write failing tests for the five supported UI action IDs and unconditional WAL checkpoint execution.
- [ ] Remove all-snapshot and time-based actions from UI state/adapter while preserving database maintenance actions.
- [ ] Add a pure execution-options projection that shows optional vacuum only for snapshot plans.
- [ ] Run the focused UI logic and adapter tests.
- [ ] Commit the pure-logic/adapter changes.

### Task 3: Render the single cleaner composer

**Files:**
- Modify: `src/d810/ui/workbench_diagnostics_panel.py`
- Modify: `tests/unit/ui/test_workbench_diagnostics_panel_contract.py`

- [ ] Write failing panel contract tests for one action selector, conditional retention input, no timestamp controls, post-preview confirmation visibility, and no checkpoint toggle.
- [ ] Replace the action grid with an action selector plus `Preview cleanup plan`; move inventory refresh outside the cleaner; conditionally render retention/vacuum controls.
- [ ] Run the panel contract test and focused UI suite.
- [ ] Commit the panel change.

### Task 4: Verify the full slice

**Files:**
- Modify: `docs/superpowers/specs/2026-07-15-deobfuscation-workbench-ui-design.md`

- [ ] Update the workbench design’s cleanup operation list to the approved model.
- [ ] Run `PYTHONPATH=src pytest tests/unit/ui/test_workbench_diagnostics_logic.py tests/unit/ui/test_workbench_diagnostics_commands.py tests/unit/ui/test_workbench_diagnostics_panel_contract.py tests/unit/diagnostics/test_workbench_cleanup_plans.py tests/unit/diagnostics/test_workbench_cleanup_execution.py tests/unit/diagnostics/test_workbench_models.py tests/unit/manager/test_workbench_diagnostics_facade.py -q`.
- [ ] Run `PYTHONPATH=src pytest tests/unit/ -q`, `sg scan --config sgconfig.yml --report-style short`, `PYTHONPATH=src lint-imports --config .importlinter`, and `git diff --check`.
- [ ] Launch the X11 IDA workbench and verify the compositor visually using the live Diagnostics Explorer.
- [ ] Add verification evidence to `tcvpu-f21a`, close it, and commit the verified slice.
