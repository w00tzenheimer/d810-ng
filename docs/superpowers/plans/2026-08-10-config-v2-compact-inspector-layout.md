# Config-v2 Compact Inspector Layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the config-v2 Project Editor's pass inspector use the same compact, left-aligned layout grammar as the D-810 Configuration host.

**Architecture:** Existing pure inspector projections decide which capability owns space. The Qt panel consumes those projections with shared compact layout helpers: Rules and Transforms keep the elastic catalog workspace, fields-only passes keep elastic Options, and unavailable sections are absent. A shared overflow policy keeps host and inspector footer controls physically consistent.

**Tech Stack:** Python 3.13 via `pyenv exec python`, IDA PluginForm Qt shim (PyQt5/PySide6), pytest, Ruff, ast-grep, import-linter, graphify.

## Global Constraints

- Work only in `/Users/mahmoud/src/idapro/d810/.worktrees/lrea-portable-cfg-case-producer` on `diff/lrea-portable-cfg-case-producer`.
- Preserve unrelated dirty worktree changes; stage only files owned by a task.
- Scope, Backend, and Safety remain read-only registered-pass contract metadata.
- Controls remain declared `FieldEditorSpec` renderings; do not interpret arbitrary project JSON into widgets.
- Rules and rule metadata remain separately scrollable.
- Do not render empty Rules, Transforms, or Options sections or placeholder copy.
- Run all Python commands as `pyenv exec python`.

---

### Task 1: Share the compact overflow-button geometry

**Files:**
- Modify: `src/d810/ui/config_v2_editing_panel.py:_build_footer`
- Test: `tests/unit/ui/test_config_v2_editing_panel_contract.py`
- Test: `tests/unit/ui/test_ida_ui_layout_contract.py`

**Interfaces:**
- Consumes: `configure_overflow_menu_button(button: Any) -> None` from `d810.ui.qt_layout_policy`.
- Produces: Configuration host engine overflow and Project Editor footer overflow consume one shared policy.

- [ ] **Step 1: Write the failing layout-contract tests**

```python
def test_project_editor_footer_uses_the_shared_overflow_policy() -> None:
    assert "configure_overflow_menu_button(self.footer_overflow_button)" in _source("_build_footer")

def test_configuration_host_engine_overflow_uses_the_shared_policy() -> None:
    assert "configure_overflow_menu_button(self.btn_engine_overflow)" in _source("OnCreate")
```

- [ ] **Step 2: Run tests to verify RED**

Run: `PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_editing_panel_contract.py tests/unit/ui/test_ida_ui_layout_contract.py`

Expected: the Project Editor assertion fails because `_build_footer()` does not invoke the shared policy; the Configuration-host assertion remains green.

- [ ] **Step 3: Apply the shared policy in the Project Editor footer**

```python
from d810.ui.qt_layout_policy import configure_overflow_menu_button

def _build_footer(self) -> typing.Any:
    self.footer_overflow_button = QtWidgets.QToolButton()
    configure_overflow_menu_button(self.footer_overflow_button)
    self.footer_overflow_button.setText("...")
```

Keep the helper as the single source for overflow-button geometry. Do not alter menu actions or popup behavior.

- [ ] **Step 4: Run tests to verify GREEN**

Run the Step 2 command. Expected: all focused layout-contract tests pass.

- [ ] **Step 5: Commit the isolated change**

```bash
git add src/d810/ui/config_v2_editing_panel.py tests/unit/ui/test_config_v2_editing_panel_contract.py tests/unit/ui/test_ida_ui_layout_contract.py
git -c user.name='w00tzenheimer' -c user.email='w00tzenheimer@users.noreply.github.com' commit -m "fix(ui): share config-v2 overflow geometry"
```

### Task 2: Compact Details and typed Options forms

**Files:**
- Modify: `src/d810/ui/config_v2_editing_panel.py:OnCreate,_render_typed_options`
- Test: `tests/unit/ui/test_config_v2_editing_panel_contract.py`

**Interfaces:**
- Consumes: `configure_left_aligned_form(layout: Any) -> None`, `ConfigV2InspectorLayout.primary_section`, and `FieldEditorSpec` advisory metadata.
- Produces: a compact left-aligned Details form and typed Options form where annotations occupy only the field's value column.

- [ ] **Step 1: Write the failing inspector layout test**

```python
def test_inspector_details_and_typed_options_use_the_compact_form_policy() -> None:
    source = _source("OnCreate")
    assert "configure_left_aligned_form(details_layout)" in source
    assert "configure_left_aligned_form(self.typed_options_layout)" in source
    assert "self.typed_options_layout.setContentsMargins(0, 0, 0, 0)" in source
```

- [ ] **Step 2: Run test to verify RED**

Run: `PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_editing_panel_contract.py::test_inspector_details_and_typed_options_use_the_compact_form_policy`

Expected: FAIL because the Project Editor creates unconfigured `QFormLayout`s and reserves duplicate inner margins.

- [ ] **Step 3: Implement compact left-aligned forms**

```python
details_layout = QtWidgets.QFormLayout(self.details_body)
details_layout.setContentsMargins(0, 0, 0, 0)
details_layout.setSpacing(4)
configure_left_aligned_form(details_layout)

self.typed_options_layout = QtWidgets.QFormLayout(self.typed_options_body)
self.typed_options_layout.setContentsMargins(0, 0, 0, 0)
self.typed_options_layout.setSpacing(4)
configure_left_aligned_form(self.typed_options_layout)
```

Retain the existing per-field composition: control first, then only its word-wrapped advisory below it. Keep group padding at four pixels and remove only duplicate child-form padding.

- [ ] **Step 4: Run tests to verify GREEN**

Run: `PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_editing_panel_contract.py`

Expected: all panel contract and fake-Qt behavior tests pass, including Rules/Transforms/Options elastic-workspace coverage.

- [ ] **Step 5: Commit the isolated change**

```bash
git add src/d810/ui/config_v2_editing_panel.py tests/unit/ui/test_config_v2_editing_panel_contract.py
git -c user.name='w00tzenheimer' -c user.email='w00tzenheimer@users.noreply.github.com' commit -m "fix(ui): compact config-v2 inspector forms"
```

### Task 3: Verify capability-driven compact rendering

**Files:**
- Modify: `tests/unit/ui/test_config_v2_editing_panel_contract.py`

**Interfaces:**
- Consumes: `ConfigV2InspectorPrimarySection`, `ConfigV2EditingPanel._set_primary_workspace`, and the native Docker launcher.
- Produces: regression coverage proving Rules/Transforms remain elastic primaries, Options is elastic only for fields-only passes, and unavailable sections reserve no space.

- [ ] **Step 1: Write the behavior regression test**

```python
def test_options_only_inspector_keeps_options_elastic_without_catalog_or_sink() -> None:
    panel = _panel_with_behavior_layout()
    panel._set_primary_workspace(ConfigV2InspectorPrimarySection.OPTIONS)
    assert panel.primary_workspace.isVisible() is False
    assert panel.inspector_elastic_sink.isVisible() is False
    assert panel._inspector_layout.stretch_calls == [(0, 0), (1, 1), (2, 0)]
```

Also assert `_render_inspector()` hides catalog groups from `layout.show_rule_catalog` and `layout.show_transform_catalog`, rather than rendering placeholders.

- [ ] **Step 2: Run the focused behavior test**

Run: `PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_editing_panel_contract.py::test_options_only_inspector_keeps_options_elastic_without_catalog_or_sink`

Expected: GREEN if current routing is retained; if RED exposes a real regression, correct only `_set_primary_workspace()` and rerun it.

- [ ] **Step 3: Run automated verification**

Run: `PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui`

Run: `pyenv exec python -m ruff check src/d810/ui/config_v2_editing_panel.py src/d810/ui/qt_layout_policy.py tests/unit/ui/test_config_v2_editing_panel_contract.py`

Run: `sg scan --config sgconfig.yml --report-style short`

Run: `PYTHONPATH=src lint-imports --config .importlinter`

Run: `graphify update .`

Expected: all commands exit zero. Existing zero-node community-label warnings from graphify may remain warnings but must not cause update failure.

- [ ] **Step 4: Run native acceptance without touching the source IDB**

Run: `D810_GUI_DOCKER_IMAGE=idapro-9.4-speedups:x11 ./tools/scripts/run_ida_gui_docker.sh -w lrea-portable-cfg-case-producer --open-config -- /samples/bins/libobfuscated.dll.i64`

In Configuration, select a rule-heavy pass, click `Edit pipeline...`, then inspect a rule-heavy and a fields-only pass. Confirm Details is left aligned; Rules and metadata scroll independently; advisory text remains under its field; unavailable catalog sections are omitted; and the two `...` buttons match. Use only the launcher's disposable IDB copy.

- [ ] **Step 5: Commit verification-only coverage if it changed**

```bash
git add tests/unit/ui/test_config_v2_editing_panel_contract.py
git -c user.name='w00tzenheimer' -c user.email='w00tzenheimer@users.noreply.github.com' commit -m "test(ui): preserve compact config-v2 capability layout"
```

## Plan self-review

- **Spec coverage:** Task 1 covers matching footer controls; Task 2 covers host-aligned Details and typed Options geometry; Task 3 covers capability-driven elastic regions, automation, and native acceptance.
- **Placeholder scan:** no `TBD`, `TODO`, deferred implementation, or vague test instruction remains.
- **Type consistency:** the plan uses existing `configure_left_aligned_form`, `configure_overflow_menu_button`, `ConfigV2InspectorPrimarySection`, and `FieldEditorSpec` interfaces and introduces no cross-layer API.
