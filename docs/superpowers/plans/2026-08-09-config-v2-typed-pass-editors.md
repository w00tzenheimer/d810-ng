# Config-v2 Typed Pass Editors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the generic config-v2 pass inspector with pass-owned, closed typed editor specifications, beginning with a metadata-rich, family-selectable `mba-simplify` transform catalog.

**Architecture:** An IDA-independent editor spec is supplied at config-v2 pass registration, validated through the public recipe catalog, projected by pure UI logic, and rendered by a fixed Qt widget for each editor kind. `mba-simplify` owns an explicit checked-in transform catalog; the renderer never infers a family from an identifier. Existing manager mutations remain the single persistence path.

**Tech Stack:** Python 3.13 through `pyenv exec python`, dataclasses/enums, D810 `PassRegistry`, config-v2 manager facade/adapter, Qt shim for IDA 9.1/PyQt5 and IDA 9.3/PyQt6, pytest, ast-grep, import-linter, graphify.

## Global Constraints

- Work in `/Users/mahmoud/src/idapro/d810/.worktrees/lrea-portable-cfg-case-producer` on `diff/lrea-portable-cfg-case-producer`.
- Public config-v2 editor kinds are closed: `summary`, `fields`, and `transform_catalog`. No callback, arbitrary widget, or UI Python extension point exists.
- Transform family membership is explicit pass-owned metadata. Do not infer it from transform IDs, class names, or source filenames at renderer runtime.
- Existing config-v2 selections remain exact; defaults apply only to newly added or migration-created content without a prior selection.
- Never call an offline proof cost a runtime cost without measurement. Normal config-v2 UI has no raw option editor.
- Keep projections and selection actions Qt-free. Qt calls `set_pass_transforms` exactly once per operator action.
- Preserve any unrelated change in `src/d810/passes/unflatten/state_machine.py`.
- Before handoff run `sg scan --config sgconfig.yml --report-style short`, `PYTHONPATH=src pyenv exec lint-imports --config .importlinter`, and `graphify update .` from this worktree.

## File Structure

- Create `src/d810/core/pass_editor_spec.py`: closed portable editor/transform metadata types.
- Modify `src/d810/passes/registry.py`: store and expose an editor spec per pass.
- Modify `src/d810/manager/workbench_recipe_models.py` and `src/d810/manager/workbench_recipe_service.py`: carry and fail-close public editor specs.
- Create `src/d810/passes/mba_transform_catalog.py`: checked-in explicit `mba-simplify` transform metadata.
- Modify public config-v2 registration modules: supply `summary`, `fields`, or `transform_catalog` explicitly.
- Modify `src/d810/ui/config_v2_editing_logic.py`: pure views and selection actions.
- Create `src/d810/ui/config_v2_transform_catalog.py`: fixed Qt family tree and structured focused-rule inspector.
- Modify `src/d810/ui/config_v2_editing_panel.py`: dispatch fixed renderers and remove raw option editing.

---

### Task 1: Add the portable closed editor-spec contract

**Files:**
- Create: `src/d810/core/pass_editor_spec.py`
- Modify: `src/d810/passes/registry.py`, `src/d810/manager/workbench_recipe_models.py`, `src/d810/manager/workbench_recipe_service.py`
- Test: `tests/unit/core/test_pass_editor_spec.py`, `tests/unit/passes/test_pass_registry.py`, `tests/unit/manager/test_workbench_recipe_service.py`

**Interfaces:**

```python
class PassEditorKind(str, enum.Enum):
    SUMMARY = "summary"
    FIELDS = "fields"
    TRANSFORM_CATALOG = "transform_catalog"

@dataclasses.dataclass(frozen=True, slots=True)
class TransformEditorSpec:
    transform_id: str
    label: str
    family_id: str
    family_label: str
    subfamily_id: str | None
    subfamily_label: str | None
    description: str
    reference: str
    maturities: tuple[str, ...]
    default_selected: bool
    verification: VerificationStatus
    verification_reason: str
    advisory: AdvisoryTone
    advisory_reason: str
    cost: TransformCost

@dataclasses.dataclass(frozen=True, slots=True)
class PassEditorSpec:
    kind: PassEditorKind
    fields: tuple[FieldEditorSpec, ...] = ()
    transforms: tuple[TransformEditorSpec, ...] = ()
```

`PassRegistry.editor_spec_for(pass_id: str) -> PassEditorSpec | None` supplies catalog metadata. `PassCatalogEntry.editor_spec` is mandatory. `RecipeService.catalog()` raises `RecipeEditError` when a public config-v2 pass lacks an editor spec.

- [ ] **Step 1: Write failing tests**

```python
def test_transform_catalog_rejects_missing_explicit_family_metadata() -> None:
    with pytest.raises(ValueError, match="family_id"):
        PassEditorSpec.transform_catalog(_transform(family_id=""))

def test_public_recipe_catalog_rejects_missing_editor_spec() -> None:
    registry = PassRegistry()
    registry.register("public-pass", _Pass, public=True)
    with pytest.raises(RecipeEditError, match="editor spec"):
        RecipeService(registry).catalog()
```

- [ ] **Step 2: Verify RED**

```bash
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/core/test_pass_editor_spec.py tests/unit/passes/test_pass_registry.py tests/unit/manager/test_workbench_recipe_service.py
```

Expected: FAIL because no editor spec model, registry storage, or catalog check exists.

- [ ] **Step 3: Implement the smallest complete contract**

Validate unique transform IDs, non-empty explicit family IDs and labels, approved scalar `FieldControlKind` values, and kind-specific shape: `summary` contains neither fields nor transforms, `fields` contains fields only, and `transform_catalog` contains complete transforms only. Store the spec alongside registration. Update direct `PassCatalogEntry` test fixtures to construct `PassEditorSpec.summary()` explicitly.

- [ ] **Step 4: Verify GREEN**

Run the Step 2 command. Expected: PASS; malformed transform metadata and public catalog omissions fail with stable messages.

- [ ] **Step 5: Commit**

```bash
git add src/d810/core/pass_editor_spec.py src/d810/passes/registry.py src/d810/manager/workbench_recipe_models.py src/d810/manager/workbench_recipe_service.py tests/unit/core/test_pass_editor_spec.py tests/unit/passes/test_pass_registry.py tests/unit/manager/test_workbench_recipe_service.py && git commit -m "feat(config-v2): register closed pass editor specs"
```

### Task 2: Register explicit config-v2 editor metadata

**Files:**
- Create: `src/d810/passes/mba_transform_catalog.py`
- Modify: `src/d810/passes/mba_simplify.py`, `src/d810/passes/constant_simplification.py`, `src/d810/passes/hook_transform_passes.py`, `src/d810/passes/state_machine_spine.py`, `src/d810/passes/cleanup_family_adapter.py`, `src/d810/passes/mba_solve.py`
- Test: `tests/unit/passes/test_mba_transform_catalog.py`, `tests/unit/passes/test_operational_config_v2.py`

**Interfaces:**

```python
MBA_TRANSFORM_SPECS: tuple[TransformEditorSpec, ...]
def mba_transform_editor_spec() -> PassEditorSpec: ...
```

`MBA_TRANSFORM_SPECS` is a checked-in literal metadata source whose IDs must equal `tuple(stage.stage_id for stage in mba_transform_stages())` exactly. Every other public config-v2 pass gets an explicit `PassEditorSpec.summary()` or existing-parser-backed `PassEditorSpec.fields(...)`.

- [ ] **Step 1: Write failing coverage and advisory tests**

```python
def test_mba_catalog_has_one_explicit_spec_for_every_registered_transform() -> None:
    assert {item.transform_id for item in mba_transform_editor_spec().transforms} == {
        item.stage_id for item in mba_transform_stages()
    }

def test_mul_mba_1_describes_costly_proof_without_runtime_claim() -> None:
    item = _transform("mul-mba-1")
    assert item.advisory is AdvisoryTone.WARNING
    assert item.verification is VerificationStatus.SKIPPED
    assert item.cost is TransformCost.PROOF_EXPENSIVE
    assert "runtime" not in item.advisory_reason.lower()
```

- [ ] **Step 2: Verify RED**

```bash
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/passes/test_mba_transform_catalog.py tests/unit/passes/test_mba_transform_options.py tests/unit/passes/test_operational_config_v2.py
```

Expected: FAIL because the explicit MBA catalog and editor registrations are absent.

- [ ] **Step 3: Implement literal metadata and pass registration**

Each MBA entry directly declares ID, label, family/subfamily, concise description, reference, maturities, default, verification, advisory, and cost. No renderer-time name inference is permitted. `Mul_MBA_1` is warning/skipped/proof-expensive; known-incorrect entries are pass-owned danger/default-disabled entries and stay selectable. Validate duplicate, missing, and unknown IDs at catalog construction. Register the MBA catalog and explicit specs for all other public config-v2 passes.

- [ ] **Step 4: Verify GREEN**

Run the Step 2 command. Expected: PASS; every public pass is typed and every MBA transform has exact metadata coverage.

- [ ] **Step 5: Commit**

```bash
git add src/d810/passes/mba_transform_catalog.py src/d810/passes/mba_simplify.py src/d810/passes/constant_simplification.py src/d810/passes/hook_transform_passes.py src/d810/passes/state_machine_spine.py src/d810/passes/cleanup_family_adapter.py src/d810/passes/mba_solve.py tests/unit/passes/test_mba_transform_catalog.py tests/unit/passes/test_operational_config_v2.py && git commit -m "feat(config-v2): catalog explicit transform metadata"
```

### Task 3: Build pure typed-editor projections and selection actions

**Files:**
- Modify: `src/d810/ui/config_v2_editing_logic.py`
- Test: `tests/unit/ui/test_config_v2_editing_logic.py`
- Create: `tests/unit/ui/test_config_v2_transform_catalog_logic.py`

**Interfaces:**

```python
def project_transform_catalog(
    spec: PassEditorSpec,
    selected_ids: AbstractSet[str],
    query: str,
) -> ConfigV2TransformCatalogView: ...

def apply_transform_catalog_selection(
    view: ConfigV2TransformCatalogView,
    selected_ids: AbstractSet[str],
    *,
    target_id: str,
    selected: bool,
) -> tuple[str, ...]: ...
```

The view uses `ConfigV2TransformFamilyView` and `ConfigV2TransformView` records only. It imports no Qt symbol.

- [ ] **Step 1: Write failing projection/action tests**

```python
def test_filtering_family_selection_touches_only_visible_descendants() -> None:
    view = project_transform_catalog(_mba_spec(), {"add-xor-1"}, query="mul")
    assert apply_transform_catalog_selection(
        view, {"add-xor-1"}, target_id="family:multiplication", selected=True
    ) == ("add-xor-1", "mul-mba-1", "mul-mba-2")

def test_existing_selected_danger_transform_remains_selected() -> None:
    view = project_transform_catalog(_mba_spec(), {"mul-mba-2"}, query="")
    assert _transform_view(view, "mul-mba-2").selected is True
    assert _transform_view(view, "mul-mba-2").default_selected is False
```

- [ ] **Step 2: Verify RED**

```bash
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_editing_logic.py tests/unit/ui/test_config_v2_transform_catalog_logic.py
```

Expected: FAIL because catalog projections and visible-scope actions are absent.

- [ ] **Step 3: Implement Qt-free view and action logic**

Build stable family/subfamily nodes from explicit metadata, retaining registered transform order. Filtering keeps matching leaves and their ancestors. Check state and count derive from visible descendants. Group and global actions change only target-visible IDs, then return canonical registered order without duplicates. Defaults are presentation only and projections never mutate a draft.

- [ ] **Step 4: Verify GREEN**

Run the Step 2 command. Expected: PASS; exact counts, tri-state values, filtering, and canonical ordering are all covered.

- [ ] **Step 5: Commit**

```bash
git add src/d810/ui/config_v2_editing_logic.py tests/unit/ui/test_config_v2_editing_logic.py tests/unit/ui/test_config_v2_transform_catalog_logic.py && git commit -m "feat(ui): project typed config-v2 transform catalogs"
```

### Task 4: Render fixed typed editors in the Config-v2 panel

**Files:**
- Create: `src/d810/ui/config_v2_transform_catalog.py`
- Modify: `src/d810/ui/config_v2_editing_panel.py`
- Test: `tests/unit/ui/test_config_v2_editing_panel_contract.py`
- Create: `tests/unit/ui/test_config_v2_transform_catalog_contract.py`

**Interfaces:**

```python
class ConfigV2TransformCatalogWidget(QtWidgets.QWidget):
    def __init__(self, parent: typing.Any, on_selection_changed: typing.Callable[..., None]) -> None: ...
    def set_view(self, view: ConfigV2TransformCatalogView) -> None: ...
    def focused_transform_id(self) -> str | None: ...
```

`ConfigV2EditingPanel` dispatches the selected pass's `PassEditorKind` to fixed `summary`, `fields`, or `transform_catalog` UI. The widget returns an action target; the panel resolves it through `apply_transform_catalog_selection` and calls the adapter exactly once.

- [ ] **Step 1: Write failing fixed-renderer contract tests**

```python
def test_transform_catalog_has_tree_filter_and_structured_inspector() -> None:
    source = _source("src/d810/ui/config_v2_transform_catalog.py")
    assert "QTreeWidget" in source
    assert "QLineEdit" in source
    assert "StructuredDetailsView" in source
    assert "itemChanged" in source

def test_panel_removes_raw_option_editing_and_routes_catalog_selection() -> None:
    source = _source("src/d810/ui/config_v2_editing_panel.py")
    assert "Edit raw options" not in source
    assert "apply_transform_catalog_selection" in source
    assert "set_pass_transforms" in source
```

- [ ] **Step 2: Verify RED**

```bash
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_editing_panel_contract.py tests/unit/ui/test_config_v2_transform_catalog_contract.py
```

Expected: FAIL because neither the fixed catalog widget nor typed renderer routing exists.

- [ ] **Step 3: Implement the fixed widget and one-mutation panel route**

Use a `QTreeWidget` for explicit family/subfamily/leaf hierarchy, with Qt-shim checkable flags and signal suppression during rendering. Above it place a filter plus compact `Select all` and `Clear` controls; place `Select every transform` in an overflow menu. The left tree is the action surface. The right side uses `StructuredDetailsView` to show purpose, advisory, verification, maturity, reference, cost, and optional pattern/constraint sections for the focused transform.

Remove the normal raw options tree/button. `fields` uses only controls backed by `FieldControlKind`; `summary` uses compact structured details. Keep the existing read-only structured contract and `View raw contract` audit dialog. Leaf, family, subfamily, and global actions all call `adapter.set_pass_transforms(...)` once with the pure helper's canonical tuple.

- [ ] **Step 4: Verify GREEN**

Run the Step 2 command. Expected: PASS; raw option editing is absent, compact catalog controls exist, and all selection paths route through one typed mutation.

- [ ] **Step 5: Commit**

```bash
git add src/d810/ui/config_v2_transform_catalog.py src/d810/ui/config_v2_editing_panel.py tests/unit/ui/test_config_v2_editing_panel_contract.py tests/unit/ui/test_config_v2_transform_catalog_contract.py && git commit -m "feat(ui): render typed config-v2 pass editors"
```

### Task 5: Verify compatibility and native IDA behavior

**Files:**
- Modify: `docs/superpowers/plans/2026-07-16-d810-gui-session-worklist.md`
- Modify: `tests/unit/ui/test_config_v2_editing_logic.py`
- Test: `tests/unit/passes/test_operational_config_v2.py`, `tests/unit/ui/test_config_v2_editing_panel_contract.py`

**Interfaces:** Consumes Tasks 1-4 and produces test evidence for portable model behavior and both supported Qt bindings.

- [ ] **Step 1: Add preserved-selection regression coverage**

```python
def test_existing_project_keeps_warning_transform_after_catalog_render_and_save() -> None:
    draft = _draft_with_selected("mul-mba-1")
    view = project_config_v2_editor_view(draft, _validation(), _catalog())
    assert _inspector(view, "mba-simplify").transform_catalog.selected_ids == ("mul-mba-1",)
```

- [ ] **Step 2: Run the focused regression test**

```bash
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_editing_logic.py::test_existing_project_keeps_warning_transform_after_catalog_render_and_save
```

Expected: PASS after Tasks 1-4; it protects the approved compatibility rule.

- [ ] **Step 3: Run complete portable verification**

```bash
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src pyenv exec lint-imports --config .importlinter
graphify update .
```

Expected: all unit tests pass, architecture gates stay clean, and graph data includes the core -> pass registry -> recipe catalog -> pure projection -> Qt relation.

- [ ] **Step 4: Run documented native smoke tests**

Use the established XQuartz/Docker GUI procedure in `docs/superpowers/plans/2026-07-16-d810-gui-session-worklist.md`. On disposable databases in IDA 9.1/PyQt5 and IDA 9.3/PyQt6, open a config-v2 `mba-simplify` pass and prove: the tree displays explicit families/counts; a filtered family action changes only matching descendants; `Mul_MBA_1` says proof-expensive without a runtime claim; saving/reload preserves an explicitly selected warning/danger transform; and no normal raw-option editor appears. Record version, config filename, image name, and result in the worklist.

- [ ] **Step 5: Commit verification evidence**

```bash
git add docs/superpowers/plans/2026-07-16-d810-gui-session-worklist.md tests/unit/ui/test_config_v2_editing_logic.py && git commit -m "test(ui): verify typed config-v2 pass editors"
```

## Plan Self-review

- Spec coverage: Task 1 implements the closed pass-owned protocol; Task 2 creates explicit config-v2 metadata; Task 3 builds the Qt-free hierarchy; Task 4 renders only fixed controls and preserves the mutation boundary; Task 5 verifies compatibility, safety copy, and native behavior.
- Placeholder check: every task has exact files, a failing test, an expected RED command, a minimal implementation direction, a GREEN command, and a commit command. `Open config in editor...` is explicitly future scope, not an unplanned implementation step.
- Type consistency: `PassEditorSpec` flows from registry to `PassCatalogEntry`, through `project_config_v2_editor_view`, into a fixed Qt renderer. Selection remains `tuple[str, ...]` through the existing `set_pass_transforms` API.
