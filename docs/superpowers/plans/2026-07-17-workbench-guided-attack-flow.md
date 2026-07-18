# Guided Deobfuscation Workbench Attack Flow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Workbench run the current function's effective D810 attack directly, refresh it, and automatically compare it with a fresh native decompile before exposing tuning.

**Architecture:** A pure workflow projection converts the existing Workbench snapshot, optional command result, and optional comparison into the top attack-card view. `workbench_panel.py` renders the card and coordinates existing manager actions; it does not mutate microcode, implement comparison capture, compose recipes, or persist overrides.

**Tech Stack:** Python 3.13, IDA PluginForm, PyQt5/PyQt6 through `d810.qt_shim`, pytest, ast-grep, import-linter, XQuartz Docker IDA.

## Global Constraints

- Call the established `WorkbenchCommandAdapter.deobfuscate` action; do not add a direct mutation path.
- Treat native decompilation as the oracle; a text difference is not semantic correctness.
- Refresh the Workbench snapshot before automatic comparison.
- Put workflow decisions in pure Python with direct unit tests.
- Support PyQt5/IDA 9.1 and PyQt6/IDA 9.3 using ordinary Qt widgets.
- Keep function rule overrides and saved function recipes distinct.

---

### Task 1: Add a pure attack-card workflow model

**Files:**
- Create: `src/d810/ui/workbench_workflow_logic.py`
- Create: `tests/unit/ui/test_workbench_workflow_logic.py`

**Interfaces:**
- Consumes: `DeobfuscationWorkbenchSnapshot`, `WorkbenchCommandResult`, and `ComparisonView`.
- Produces: `WorkflowPhase`, `WorkflowActionView`, `WorkbenchWorkflowView`, and `project_workbench_workflow(...)`.

- [x] **Step 1: Write failing tests**

```python
def test_current_started_snapshot_offers_immediate_deobfuscation() -> None:
    view = workflow.project_workbench_workflow(_snapshot())

    assert view.phase is workflow.WorkflowPhase.READY
    assert view.primary.action_id == "deobfuscate"
    assert view.primary.label == "Deobfuscate this function"


def test_current_comparison_offers_contextual_tuning() -> None:
    view = workflow.project_workbench_workflow(
        _snapshot(),
        comparison=_comparison_view(text_changed=True),
        last_result=_accepted_deobfuscation_result(),
    )

    assert view.phase is workflow.WorkflowPhase.VERIFY
    assert view.primary.action_id == "compare"
    assert tuple(action.action_id for action in view.secondary) == (
        "diagnostics", "recipe", "function_override",
    )
```

Cover stopped and stale snapshots, transient running, blocked/failed results, and unavailable comparison. Assert no output says the result is correct or derives a result from firing counts.

- [x] **Step 2: Verify the tests fail**

Run: `pytest tests/unit/ui/test_workbench_workflow_logic.py -q`

Expected: FAIL because `d810.ui.workbench_workflow_logic` does not exist.

- [x] **Step 3: Implement the immutable projection**

```python
class WorkflowPhase(str, enum.Enum):
    READY = "ready"
    UNAVAILABLE = "unavailable"
    RUNNING = "running"
    VERIFY = "verify"
    INVESTIGATE = "investigate"


def project_workbench_workflow(
    snapshot: DeobfuscationWorkbenchSnapshot | None,
    *,
    comparison: ComparisonView | None = None,
    last_result: WorkbenchCommandResult | None = None,
    running: bool = False,
    comparison_error: str | None = None,
) -> WorkbenchWorkflowView:
    if snapshot is None:
        return _unavailable_view("Select a pseudocode function.")
    if running:
        return _running_view(snapshot)
    if comparison_error:
        return _comparison_retry_view(snapshot, comparison_error)
    if _needs_investigation(last_result):
        return _investigation_view(snapshot, last_result)
    if comparison is not None and comparison.comparable:
        return _verification_view(snapshot, comparison)
    return _ready_view(snapshot)
```

Use freshness and `engine_started` for availability. A current successful deobfuscation plus a current comparison is `VERIFY`; stale, blocked, failed, or comparison-error results are `INVESTIGATE`. In `READY`, use the direct action for both recognized and unknown shapes, with copy that truthfully names the effective runtime.

- [x] **Step 4: Verify the model**

Run: `pytest tests/unit/ui/test_workbench_workflow_logic.py -q`

Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add src/d810/ui/workbench_workflow_logic.py tests/unit/ui/test_workbench_workflow_logic.py
git commit -m "feat(ui): model guided workbench attack flow"
```

### Task 2: Render the card and coordinate the direct run

**Files:**
- Modify: `src/d810/ui/workbench_panel.py`
- Modify: `tests/unit/ui/test_workbench_panel_contract.py`

**Interfaces:**
- Consumes: `project_workbench_workflow(...)` from Task 1 and existing adapter methods `deobfuscate`, `compare`, `recipe`, and `function_override`.
- Produces: `DeobfuscationWorkbenchPanel._run_recommended_attack()`.

- [x] **Step 1: Write a failing orchestration contract**

```python
def test_recommended_attack_refreshes_before_automatic_comparison() -> None:
    source = _method_source("_run_recommended_attack")

    assert 'self._run_command("deobfuscate", refresh_after=False)' in source
    assert "self.refresh()" in source
    assert "self._run_comparison()" in source
    assert source.index("self.refresh()") < source.index("self._run_comparison()")
```

Also assert the panel imports the pure workflow projection instead of deriving card copy from Qt state.

- [x] **Step 2: Verify it fails**

Run: `pytest tests/unit/ui/test_workbench_panel_contract.py -q`

Expected: FAIL because `_run_recommended_attack` does not exist.

- [x] **Step 3: Implement the portable attack card**

```python
self.workflow_headline = QtWidgets.QLabel()
self.workflow_detail = QtWidgets.QLabel()
self.workflow_detail.setWordWrap(True)
self.workflow_primary_button = QtWidgets.QPushButton()
self.workflow_secondary_layout = QtWidgets.QHBoxLayout()
```

Place an `Attack` group between function context and evidence. Add `_render_workflow()` to render the pure view, one primary button, and contextual secondary buttons. Keep the evidence chooser unchanged. Move existing peer actions under an `Advanced` group, retaining action IDs and manager adapters.

- [x] **Step 4: Coordinate run, refresh, then comparison**

```python
def _run_recommended_attack(self, checked: bool = False) -> None:
    del checked
    snapshot = self._snapshot
    self._workflow_running = True
    self._render_workflow()
    result = self._run_command("deobfuscate", refresh_after=False)
    self._workflow_running = False
    self._workflow_result = result
    if (
        snapshot is not None
        and result is not None
        and should_accept_command_result(snapshot, result)
        and result.refresh_requested
    ):
        self.refresh()
        self._run_comparison()
    self._render_workflow()
```

Refactor `_run_command(...)` to return `WorkbenchCommandResult | None` and accept `refresh_after: bool = True`, preserving Analyze and Function override behavior. Make `_run_comparison()` save either the current comparison view or its caught error before rendering and opening the existing dialog. Clear transient run/comparison state when the selected function identity changes.

Wire contextual buttons: `diagnostics` opens the existing function-scoped explorer, `recipe` opens Recipe Composer, `function_override` invokes the existing command, and `compare` retries capture.

- [x] **Step 5: Verify and commit**

Run: `pytest tests/unit/ui/test_workbench_panel_contract.py -q`

Expected: PASS.

```bash
git add src/d810/ui/workbench_panel.py tests/unit/ui/test_workbench_panel_contract.py
git commit -m "feat(ui): guide workbench deobfuscation flow"
```

### Task 3: Verify and close the feature

**Files:**
- Modify: `.tickets/tcvpu-v3qt.md`
- Modify: `docs/superpowers/plans/2026-07-17-workbench-guided-attack-flow.md`

**Interfaces:**
- Consumes: direct-run Workbench behavior from Task 2.
- Produces: closed ticket with evidence-backed validation.

- [x] **Step 1: Run focused regression tests**

```bash
pytest tests/unit/ui/test_workbench_workflow_logic.py \
  tests/unit/ui/test_workbench_logic.py \
  tests/unit/ui/test_workbench_panel_contract.py \
  tests/unit/ui/test_workbench_commands.py \
  tests/unit/ui/test_workbench_comparison.py -q
```

Expected: PASS.

- [x] **Step 2: Run architecture gates and full units**

```bash
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
pytest tests/unit/ -q
```

Expected: clean ast-grep, 13 kept import contracts, passing unit suite.

- [x] **Step 3: Verify the live PyQt5 GUI**

Reload the mounted plugin in the XQuartz-backed IDA 9.1 session:

```python
import __main__
__main__.D810.reload()
```

Open the Workbench on the copied `libobfuscated.dll.i64` sample, verify the ready card and its direct action, execute one run, and verify an automatic comparison or a truthful retryable comparison failure. Capture a screenshot. Do not save the sample IDB.

- [x] **Step 4: Close and commit**

Set `status: closed` in the ticket and commit the plan update:

```bash
git add -f .tickets/tcvpu-v3qt.md docs/superpowers/plans/2026-07-17-workbench-guided-attack-flow.md
git commit -m "test(ui): verify guided workbench attack flow"
```
