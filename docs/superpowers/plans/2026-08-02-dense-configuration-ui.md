# Dense Configuration UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the D-810 Configuration and Config-v2 Project Editor dense, readable, and resizable at narrow IDA dock sizes without changing behavior.

**Architecture:** Keep the current Qt adapter boundaries and all adapter/manager logic intact. Adjust only widget layout construction: explicit size policies/minimums, compact margins, and user-resizable splitters with sensible initial sizes. Extend source-level contracts so the layout guarantees remain reviewable without importing IDA in unit tests.

**Tech Stack:** Python 3, Qt through `d810.qt_shim` (PyQt5/PyQt6), IDA `PluginForm`, pytest AST/source contracts.

## Global Constraints

- Use `pyenv exec python` for Python commands.
- Preserve all existing signals, adapter calls, read-only fields, and save/validation behavior.
- Use only Qt APIs exposed by `d810.qt_shim`; retain enum compatibility for PyQt5 and PyQt6.
- Run architecture gates from this worktree before claiming completion.

---

### Task 1: Lock down dense layout contracts

**Files:**
- Modify: `tests/unit/ui/test_config_v2_editing_panel_contract.py`
- Create: `tests/unit/ui/test_ida_ui_layout_contract.py`

**Interfaces:**
- Consumes: current `ConfigV2EditingPanel.OnCreate` and `D810Form.OnCreate` source structure.
- Produces: source-level assertions for default splitter sizes, stretch factors, minimum widths, and compact layout policy.

- [ ] **Step 1: Add failing assertions for the Config-v2 editor.**

Assert that `OnCreate` creates a vertical outer splitter containing the structured and preserved groups, sets equal/explicit stretch factors, and calls `setSizes` with a structured/preserved ratio that favors preserved text. Assert that the typed splitter sets explicit sizes and that the three child panes have minimum widths.

- [ ] **Step 2: Add failing assertions for the main configuration panel.**

Assert that the rule splitter has explicit stretch factors, minimum widths for tree/detail, and a default 40/60-ish size hint. Assert that the project and engine groups use compact margins/spacing or bounded size policies rather than unbounded expansion.

- [ ] **Step 3: Run the focused contracts and verify they fail.**

Run:

```bash
pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_editing_panel_contract.py tests/unit/ui/test_ida_ui_contract.py
```

Expected: the new layout assertions fail because the current implementation has no outer editor splitter, no explicit typed splitter sizes, and no rule-pane minimum/stretch contract.

### Task 2: Implement compact, resizable layouts

**Files:**
- Modify: `src/d810/ui/config_v2_editing_panel.py:134-193`
- Modify: `src/d810/ui/ida_ui.py:553-786`

**Interfaces:**
- Consumes: existing widgets and signals constructed in each `OnCreate` method.
- Produces: the same widget attributes and behavior with improved geometry management.

- [ ] **Step 1: Make the main configuration rule area dense.**

Set compact group/layout margins and spacing, retain the project summary as a bounded top section, set minimum widths on `RuleTreeWidget` and `RuleDetailPanel`, set splitter stretch factors so detail receives the larger share, and use an explicit default size such as `[400, 600]`. Keep the rules group as the only expanding middle section and keep the engine row compact.

- [ ] **Step 2: Make the Config-v2 editor resizable.**

Create a vertical outer splitter after the identity group; put `editing_group` and `raw_group` inside it; set both stretch factors and explicit initial sizes favoring preserved text. Keep the description/pass rows at the top of `editing_group` with compact spacing. Set minimum widths for manifest, pipeline, and routing panes, keep their 20/40/40 stretch, and set explicit initial sizes. Add the outer splitter with stretch 1 so it consumes only the intended central space.

- [ ] **Step 3: Preserve action/status behavior.**

Leave `_render`, `_set_status`, adapter mutations, read-only tabs, and final action row unchanged except for any parent layout references required by the new splitter. Do not introduce policy or persistence code into the panel.

### Task 3: Verify the implementation

**Files:**
- No new files.

- [ ] **Step 1: Run the focused UI contracts.**

```bash
pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_editing_panel_contract.py tests/unit/ui/test_ida_ui_contract.py
```

Expected: PASS.

- [ ] **Step 2: Run architecture gates from the target worktree.**

```bash
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
```

Expected: both gates pass with no new violations.

- [ ] **Step 3: Run the broader UI unit slice.**

```bash
pyenv exec python -m pytest -q tests/unit/ui
```

Expected: PASS, or any pre-existing unrelated failures are reported with their exact test names and not attributed to this change.

- [ ] **Step 4: Update the graph and inspect the final diff.**

```bash
graphify update .
git diff --check
git status --short
```

Expected: graphify completes, no whitespace errors, and only the planned UI/contracts plus plan/spec artifacts are changed.
