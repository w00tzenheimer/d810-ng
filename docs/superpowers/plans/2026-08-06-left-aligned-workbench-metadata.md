# Left-Aligned Workbench Metadata Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Left-align the configuration selector and metadata forms consistently across PyQt5 and PySide6 while allowing form values to use the available dock width.

**Architecture:** Add one focused Qt layout-policy helper that owns enum compatibility and applies the approved alignment properties. Keep `ida_ui.py` and `workbench_panel.py` as thin adapters that invoke the helper on their existing controls; no state or workflow logic changes.

**Tech Stack:** Python 3.10+, Qt through `d810.qt_shim`, PyQt5/PySide6 compatibility, pytest, ast-grep, import-linter.

## Global Constraints

- Do not apply a global Qt stylesheet.
- Do not change project selection, workflow, persistence, stage-strip, evidence-table, or action behavior.
- Preserve headless imports and both PyQt5 and PySide6 enum shapes.
- Preserve unrelated worktree edits in `minimal_state_recovery.py` and its tests.

---

### Task 1: Cross-binding left-alignment policy

**Files:**
- Create: `src/d810/ui/qt_layout_policy.py`
- Create: `tests/unit/ui/test_qt_layout_policy.py`

**Interfaces:**
- Consumes: `d810.qt_shim.QtCore` and `d810.qt_shim.QtWidgets`.
- Produces: `configure_left_aligned_form(layout: object) -> None` and `configure_left_aligned_button(button: object) -> None`.

- [ ] **Step 1: Write failing behavior tests**

Test Qt5-style and Qt6-style enum namespaces with recording layout/button objects. Assert that the form receives left/top form alignment, left label alignment, and `AllNonFixedFieldsGrow`; assert that the selector receives a local `QPushButton` left-text stylesheet with leading padding.

- [ ] **Step 2: Run tests and confirm RED**

Run:

```bash
D810_REPO_ROOT=/Users/mahmoud/src/idapro/d810 tools/scripts/run_system_tests_docker.sh exec -w lrea-portable-cfg-case-producer -- /app/ida/.venv/bin/python -m pytest -q tests/unit/ui/test_qt_layout_policy.py
```

Expected: collection failure because `d810.ui.qt_layout_policy` does not exist.

- [ ] **Step 3: Implement the minimal policy helper**

Use `try/except AttributeError` to select `Qt.AlignmentFlag` versus direct Qt5 alignment members and `QFormLayout.FieldGrowthPolicy` versus the Qt5 direct policy member. Apply only:

```python
layout.setFormAlignment(left | top)
layout.setLabelAlignment(left)
layout.setFieldGrowthPolicy(all_non_fixed_fields_grow)
```

Apply the button-local stylesheet:

```css
QPushButton { text-align: left; padding-left: 8px; }
```

- [ ] **Step 4: Run tests and confirm GREEN**

Run the Task 1 command and expect all tests to pass.

### Task 2: Wire both affected panels

**Files:**
- Modify: `src/d810/ui/ida_ui.py:20-30,648-705`
- Modify: `src/d810/ui/workbench_panel.py:60-75,184-219`
- Modify: `tests/unit/ui/test_ida_ui_layout_contract.py`
- Modify: `tests/unit/ui/test_workbench_panel_contract.py`

**Interfaces:**
- Consumes: `configure_left_aligned_form()` and `configure_left_aligned_button()` from Task 1.
- Produces: explicitly left-aligned configuration and Workbench metadata layouts.

- [ ] **Step 1: Write failing adapter-contract tests**

Assert `D810ConfigForm_t.OnCreate` applies the button policy to `self.cfg_select` and the form policy to `identity_layout`. Assert `DeobfuscationWorkbenchPanel.OnCreate` applies the form policy to both `context_layout` and `case_summary`.

- [ ] **Step 2: Run focused tests and confirm RED**

Run:

```bash
D810_REPO_ROOT=/Users/mahmoud/src/idapro/d810 tools/scripts/run_system_tests_docker.sh exec -w lrea-portable-cfg-case-producer -- /app/ida/.venv/bin/python -m pytest -q tests/unit/ui/test_ida_ui_layout_contract.py tests/unit/ui/test_workbench_panel_contract.py
```

Expected: failures naming the missing policy calls.

- [ ] **Step 3: Wire the helpers**

Import the helper functions at the existing UI adapter boundary. Invoke the button helper immediately after constructing `cfg_select`; invoke the form helper immediately after constructing each affected `QFormLayout`.

- [ ] **Step 4: Run focused tests and confirm GREEN**

Run the Task 2 command and expect all tests to pass.

### Task 3: Verification and delivery

**Files:**
- Verify only; no additional production scope.

**Interfaces:**
- Consumes: completed Task 1 and Task 2 changes.
- Produces: committed and pushed UI repair on `diff/lrea-portable-cfg-case-producer`.

- [ ] **Step 1: Run the full unit UI suite**

```bash
D810_REPO_ROOT=/Users/mahmoud/src/idapro/d810 tools/scripts/run_system_tests_docker.sh exec -w lrea-portable-cfg-case-producer -- /app/ida/.venv/bin/python -m pytest -q tests/unit/ui tests/unit/test_qt_shim.py
```

- [ ] **Step 2: Run architecture checks from the target worktree**

```bash
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
```

- [ ] **Step 3: Refresh graphify and inspect the final diff**

```bash
graphify update .
git diff --check
git diff -- src/d810/ui/qt_layout_policy.py src/d810/ui/ida_ui.py src/d810/ui/workbench_panel.py tests/unit/ui/test_qt_layout_policy.py tests/unit/ui/test_ida_ui_layout_contract.py tests/unit/ui/test_workbench_panel_contract.py
```

- [ ] **Step 4: Commit and push only the UI repair files**

Stage the plan, policy helper, panel changes, and UI tests explicitly. Do not stage the unrelated `minimal_state_recovery` files. Commit with `fix ui metadata alignment` and push the current branch.

