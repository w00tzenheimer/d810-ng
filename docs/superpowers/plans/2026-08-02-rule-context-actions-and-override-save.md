# Rule Context Actions and Override Save Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add state-aware rule-tree context actions that enter the correct edit workflow, focus config-v2 pass editing conservatively, and save ordinary config-v2 edits to the existing writable user override with an explicit Save As escape hatch.

**Architecture:** Keep context-action selection and draft set operations in Qt/IDA-free UI logic. `RuleTreeWidget` emits a typed context intent only when opted in; `D810ConfigForm_t` owns the legacy versus config-v2 split. The structured editor remains a thin adapter over manager-owned validation and atomic persistence, with optional focus metadata and draft retargeting for Save As.

**Tech Stack:** Python 3.13, Qt shim (PyQt5/PySide6), IDA PluginForm, dataclasses/enums, pytest, ast-grep/import-linter, graphify.

## Global Constraints

- Use `pyenv exec python` for every Python command.
- Config-v2 documents remain the source of truth; never downgrade them to flat legacy rule files.
- New UI action logic must be unit-testable without Qt or IDA imports.
- Normal config-v2 save overwrites only the current writable destination through the existing atomic manager writer.
- `Save as another config...` is the explicit opt-in for a different destination; duplicate retains its existing chooser flow.
- Do not add new pass/transform implementations or infer ambiguous config-v2 ownership.
- Preserve the existing function-scoped override dialog behavior.
- Run architecture gates from this worktree and refresh graphify after source edits.

---

### Task 1: Add pure context-action and config-v2 focus policy

**Files:**
- Create: `src/d810/ui/rule_tree_logic.py`
- Modify: `src/d810/ui/project_config_logic.py`
- Test: `tests/unit/ui/test_rule_tree_logic.py`
- Test: `tests/unit/ui/test_project_config_logic.py`

**Interfaces:**
- `RuleTreeContextTarget`, `RuleTreeContextRequest`, `RuleTreeTargetKind`, and `RuleTreeContextAction` are immutable records/enums with no Qt imports.
- `context_action_for(target) -> RuleTreeContextAction | None` returns `Enable`/`Disable` for leaves and `Enable All`/`Disable All` for non-empty aggregates.
- `apply_context_action(enabled_names, target, action) -> set[str]` returns a new legacy draft set without mutating its input.
- `ConfigV2FocusTarget` records `pass_id`, `rule_name`, `message`, and whether the mapping is unambiguous.
- `resolve_config_v2_focus_target(target, pipeline_pass_ids, catalog) -> ConfigV2FocusTarget` matches catalog `owned_rules`/`transforms`, applies the explicit `mba-simplify` instruction-rule mapping, and returns an explanatory ambiguous/unowned result instead of guessing.
- `config_v2_user_destination(config_dir, runtime_path) -> pathlib.Path` returns the runtime path when it is already writable, otherwise the same basename below `config_dir`.

- [ ] **Step 1: Write failing pure-logic tests.** Cover enabled/disabled leaves, zero/partial/full aggregate counts, immutable enabled-set updates, MBA focus, unique transform focus, ambiguous ownership, no owner, and same-basename destination resolution.

```python
def test_disabled_leaf_requests_enable():
    target = RuleTreeContextTarget(
        kind=RuleTreeTargetKind.RULE,
        rule_names=("Add_Xor_Rule_1",),
        enabled_count=0,
        total_count=1,
        rule_name="Add_Xor_Rule_1",
    )
    assert context_action_for(target) is RuleTreeContextAction.ENABLE
```

- [ ] **Step 2: Run the focused tests and verify they fail because the new policy types/functions are absent.**

Run: `PYTHONPATH=src pyenv exec python -m pytest tests/unit/ui/test_rule_tree_logic.py tests/unit/ui/test_project_config_logic.py -q`

Expected: collection or assertion failures for the new symbols only.

- [ ] **Step 3: Implement the immutable policy records and functions.** Normalize rule-name tuples, reject empty targets by returning `None`, preserve input sets, and compute focus candidates only from currently configured pipeline pass IDs.

- [ ] **Step 4: Rerun the focused tests.**

Run: `PYTHONPATH=src pyenv exec python -m pytest tests/unit/ui/test_rule_tree_logic.py tests/unit/ui/test_project_config_logic.py -q`

Expected: all new and existing pure-logic tests pass.

- [ ] **Step 5: Commit the pure policy seam.**

```bash
git add src/d810/ui/rule_tree_logic.py src/d810/ui/project_config_logic.py tests/unit/ui/test_rule_tree_logic.py tests/unit/ui/test_project_config_logic.py
git commit -m "ui: add rule context action policy"
```

### Task 2: Emit opt-in state-aware context intents from the rule tree

**Files:**
- Modify: `src/d810/ui/rule_tree.py`
- Test: `tests/unit/ui/test_rule_tree_contract.py`

**Interfaces:**
- `RuleTreeWidget(..., context_actions_enabled: bool = False)` preserves existing callers by default.
- `context_action_requested = QtCore.pyqtSignal(object)` emits a `RuleTreeContextRequest` for opt-in leaf/category/optimizer menus.
- `set_context_actions_enabled(bool)` permits the owner to change the behavior without reconstructing the widget.
- The existing function-rules dialog remains on its current checkbox/category Select All/Deselect All path because it does not opt in.

- [ ] **Step 1: Add source/AST contract tests before implementation.** Assert the new signal, opt-in constructor/property, policy call, leaf/category menu labels, and the function-rules constructor does not opt in.

- [ ] **Step 2: Run the rule-tree contract test to verify it fails.**

Run: `PYTHONPATH=src pyenv exec python -m pytest tests/unit/ui/test_rule_tree_contract.py -q`

Expected: failures for the missing signal/constructor/policy wiring.

- [ ] **Step 3: Implement item target construction.** Store the optimizer type on leaf items, recursively collect rule names for aggregate headers, and calculate enabled/total counts from the current tree projection.

- [ ] **Step 4: Implement context-menu branching.** When opt-in is enabled, allow intents even in read-only view, add exactly the action label returned by pure policy, and emit the request. When opt-in is disabled, preserve the existing category-only Select All/Deselect All behavior and read-only guard.

- [ ] **Step 5: Run the contract test and existing function-rule action tests.**

Run: `PYTHONPATH=src pyenv exec python -m pytest tests/unit/ui/test_rule_tree_contract.py tests/unit/ui/test_function_rules_action.py -q`

Expected: PASS.

- [ ] **Step 6: Commit the widget seam.**

```bash
git add src/d810/ui/rule_tree.py tests/unit/ui/test_rule_tree_contract.py
git commit -m "ui: add state-aware rule context menus"
```

### Task 3: Route context actions through the configuration form and deterministic destinations

**Files:**
- Modify: `src/d810/ui/ida_ui.py`
- Modify: `tests/unit/ui/test_project_config_adapter_contract.py`
- Modify: `tests/unit/ui/test_project_config_logic.py`
- Test: `tests/unit/ui/test_rule_context_form_contract.py`

**Interfaces:**
- `D810ConfigForm_t._on_rule_context_action(request) -> None` owns the legacy/config-v2 split.
- `_choose_config_v2_destination(snapshot, duplicate=False)` returns the deterministic writable same-basename path without opening a dialog; `duplicate=True` retains the existing Save dialog.
- `_open_config_v2_editor(destination, focus_target=None)` passes optional focus metadata to the panel.

- [ ] **Step 1: Add failing form contract tests.** Assert the rule tree opts in, the new signal is disconnected in `OnClose`, legacy context requests enter `_enter_edit_mode` and apply `apply_context_action`, config-v2 requests call the deterministic destination helper and editor with focus, and edit versus duplicate destination behavior differs.

- [ ] **Step 2: Run the form contract tests to verify the expected source calls are absent.**

Run: `PYTHONPATH=src pyenv exec python -m pytest tests/unit/ui/test_rule_context_form_contract.py tests/unit/ui/test_project_config_adapter_contract.py -q`

Expected: failures for the new handler/wiring.

- [ ] **Step 3: Wire the opt-in tree and context signal.** Connect `context_action_requested`, disconnect it on close, and pass the current known rules exactly as before.

- [ ] **Step 4: Implement legacy handling.** If no edit mode is active, enter EDIT with the current project policy; compute the new enabled set through `apply_context_action`; update the tree and select the requested leaf when applicable. If edit mode is already active, apply directly without re-entering.

- [ ] **Step 5: Implement config-v2 handling.** Resolve the current snapshot and catalog, compute `ConfigV2FocusTarget`, resolve the writable destination, and open the structured editor without mutating the runtime projection. Warn and leave the tree untouched when no snapshot/editor destination is available.

- [ ] **Step 6: Change ordinary config-v2 edit destination resolution.** Keep duplicate's file chooser, but make non-duplicate edit return the current writable runtime path or same-basename user override directly.

- [ ] **Step 7: Run the focused form/logic tests.**

Run: `PYTHONPATH=src pyenv exec python -m pytest tests/unit/ui/test_rule_context_form_contract.py tests/unit/ui/test_project_config_adapter_contract.py tests/unit/ui/test_project_config_logic.py -q`

Expected: PASS.

- [ ] **Step 8: Commit the form orchestration.**

```bash
git add src/d810/ui/ida_ui.py tests/unit/ui/test_rule_context_form_contract.py tests/unit/ui/test_project_config_adapter_contract.py tests/unit/ui/test_project_config_logic.py
git commit -m "ui: route rule context actions into editing workflows"
```

### Task 4: Add focused config-v2 editor and explicit Save As

**Files:**
- Modify: `src/d810/ui/config_v2_editing_panel.py`
- Modify: `src/d810/ui/config_v2_editing_commands.py`
- Modify: `tests/unit/ui/test_config_v2_editing_panel_contract.py`
- Modify: `tests/unit/ui/test_config_v2_editing_commands.py`

**Interfaces:**
- `ConfigV2EditingPanel(adapter, on_saved=None, focus_target=None)` accepts the pure focus record.
- `ConfigV2EditingAdapter.retarget(draft, destination) -> tuple[ConfigV2ProjectDraft, ConfigV2ProjectValidation]` changes only the draft destination and revalidates it.
- The panel exposes `Save as another config...` beside the ordinary `Save atomically and reload` button.

- [ ] **Step 1: Add failing panel/adapter tests.** Assert focus selection/status, Save As button/callback, adapter retargeting and revalidation, and ordinary save still delegates to `save_and_reload_config_v2_project`.

- [ ] **Step 2: Run the tests to verify they fail.**

Run: `PYTHONPATH=src pyenv exec python -m pytest tests/unit/ui/test_config_v2_editing_panel_contract.py tests/unit/ui/test_config_v2_editing_commands.py -q`

Expected: failures for `focus_target`, `retarget`, and Save As wiring.

- [ ] **Step 3: Implement adapter retargeting with a frozen-draft replacement.** Resolve the selected path, preserve all document/source hash fields, and call the existing validation delegate before returning.

- [ ] **Step 4: Implement panel focus.** Select exactly one pipeline row matching the focus pass ID, display the rule/message in the status area, and report missing/ambiguous focus without raising.

- [ ] **Step 5: Implement Save As.** Open a Qt file chooser from the current destination, call adapter `retarget`, update the destination label, preserve unsaved edits, and leave ordinary `_save` unchanged.

- [ ] **Step 6: Run panel and adapter tests.**

Run: `PYTHONPATH=src pyenv exec python -m pytest tests/unit/ui/test_config_v2_editing_panel_contract.py tests/unit/ui/test_config_v2_editing_commands.py -q`

Expected: PASS.

- [ ] **Step 7: Commit the structured-editor affordances.**

```bash
git add src/d810/ui/config_v2_editing_panel.py src/d810/ui/config_v2_editing_commands.py tests/unit/ui/test_config_v2_editing_panel_contract.py tests/unit/ui/test_config_v2_editing_commands.py
git commit -m "ui: add focused config-v2 save-as workflow"
```

### Task 5: Preserve atomic overwrite safety and verify the integrated feature

**Files:**
- Modify: `src/d810/manager/config_v2_editing.py`
- Modify: `tests/unit/manager/test_config_v2_editing.py`

- [ ] **Step 1: Add a failing manager test for overwriting an existing writable destination and refusing a bundled source destination.** Pre-create a destination with sentinel JSON, save a valid edited draft over it, assert the sentinel is gone and the new complete document is lossless, then retarget a bundled source and assert `ConfigV2EditError`.

- [ ] **Step 2: Run the manager test to verify the new guard/coverage fails or lacks the assertion.**

Run: `PYTHONPATH=src pyenv exec python -m pytest tests/unit/manager/test_config_v2_editing.py -q`

- [ ] **Step 3: Add the save-time bundled-source guard.** Use the existing bundled config directory provenance check before atomic replacement; keep writable same-basename overrides valid.

- [ ] **Step 4: Run the complete targeted suite.**

Run: `PYTHONPATH=src pyenv exec python -m pytest tests/unit/ui/test_rule_tree_logic.py tests/unit/ui/test_rule_tree_contract.py tests/unit/ui/test_rule_context_form_contract.py tests/unit/ui/test_project_config_logic.py tests/unit/ui/test_project_config_adapter_contract.py tests/unit/ui/test_config_v2_editing_panel_contract.py tests/unit/ui/test_config_v2_editing_commands.py tests/unit/manager/test_config_v2_editing.py tests/unit/manager/test_config_v2_editing_facade.py -q`

Expected: PASS. If a pre-existing unrelated collection failure appears, report it separately and do not widen this feature.

- [ ] **Step 5: Run architecture gates from the target worktree.**

Run: `sg scan --config sgconfig.yml --report-style short`

Run: `PYTHONPATH=src pyenv exec lint-imports --config .importlinter`

Expected: no broken contracts/import cycles.

- [ ] **Step 6: Refresh the code graph.**

Run: `graphify update .`

Expected: graphify completes and only expected graphify-out changes appear.

- [ ] **Step 7: Review the final diff and commit the integrated feature.**

```bash
git status --short
git diff origin/diff/lrea-portable-cfg-case-producer...HEAD --stat
git log --oneline -8
```

Commit any remaining implementation/test/graph changes with:

```bash
git add src tests graphify-out
git commit -m "ui: improve rule editing context actions"
```
