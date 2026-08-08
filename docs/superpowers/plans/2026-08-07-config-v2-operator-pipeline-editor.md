# Config-v2 Operator Pipeline Editor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Replace config-v2's registry-oriented tree and serializer editor with a compact active-pipeline overview, focused Pass Inspector, explicit Pipeline Builder, and validated structured/raw JSON editing.

**Architecture:** ConfigV2EditingService remains the sole authority for document mutations, validation, atomic save, and reload. Qt consumes immutable projections from config_v2_editing_logic and emits narrow intents through ConfigV2EditingAdapter; it never reads or writes project JSON itself. The D-810 Configuration dock becomes an active-pipeline overview, and the PluginForm keeps one draft while switching between focused Inspector and explicit Builder screens.

**Tech Stack:** Python 3.13, IDA PluginForm, Qt via d810.qt_shim (PyQt5/PyQt6), existing JsonTreeEditor / RawJsonDialog, dataclasses/enums, pytest source contracts, native IDA 9.1/9.3 smoke tests.

## Global Constraints

- Use `pyenv exec python` for every Python command.
- Keep config-v2 documents lossless: unknown fields remain preserved and no structured or raw action may modify them.
- Keep ConfigV2EditingService authoritative for transform selection, document replacement, validation, and persistence.
- Never present an execution stage as a selectable transform, or a registered transform as selected unless it occurs in that pass's `options.transforms`.
- Show a transform picker only if a pass's options actually contain a list-valued `transforms` field. Otherwise show "No individually selectable transforms."
- Persist selected transforms in the registry's stable order and keep `transform_options` only for selected transforms.
- Preserve existing `router_resolution` validation exactly.
- Default to structured details and JSON trees. Raw text is opt-in; raw edits warn first and use ordinary manager validation.
- Use only Qt APIs exposed by d810.qt_shim and retain PyQt5/PyQt6 enum fallbacks.
- Do not add pass/transform implementations, infer ambiguous ownership, or create a persistence format.
- Ordinary Save keeps the writable destination and atomic reload; `Save as new...` is the only destination change.
- After source edits, run `sg scan --config sgconfig.yml --report-style short`, `PYTHONPATH=src pyenv exec lint-imports --config .importlinter`, and `graphify update .` in this worktree.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `src/d810/ui/config_v2_editing_logic.py` | Pure projections for active pipeline, inspector, routing, raw document, and footer. |
| `src/d810/manager/config_v2_editing.py` | Validated transform selection and complete-document replacement. |
| `src/d810/manager/manager.py`, `src/d810/manager/state.py` | Facades for the two new config-v2 edit mutations. |
| `src/d810/ui/config_v2_editing_commands.py` | Thin adapter delegation and a named non-mutating draft load. |
| `src/d810/ui/config_v2_pipeline_overview.py` | Active-pass-only configuration-dock widget with inspect/builder signals. |
| `src/d810/ui/config_v2_editing_panel.py` | Compact Inspector/Builder screens, routing controls, JSON dialog, footer. |
| `src/d810/ui/ida_ui.py`, `src/d810/ui/workbench_panel.py`, `src/d810/ui/project_config_logic.py` | Configure active-pipeline routing; reject ambiguous focus. |
| `tests/unit/ui/test_config_v2_editing_logic.py` | Qt-free view-model tests. |
| `tests/unit/manager/test_config_v2_editing.py` | Transform and raw-replacement losslessness tests. |
| `tests/unit/manager/test_config_v2_editing_facade.py` | State/manager facade contracts. |
| `tests/unit/ui/test_config_v2_editing_commands.py` | Adapter delegation/revalidation tests. |
| `tests/unit/ui/test_config_v2_pipeline_overview_contract.py` | Overview widget source contract. |
| `tests/unit/ui/test_config_v2_editing_panel_contract.py` | Inspector/Builder/raw/footer source contract. |
| `tests/unit/ui/test_project_config_logic.py`, `tests/unit/ui/test_project_config_adapter_contract.py` | Focus and navigation contracts. |
| `tests/system/runtime/ui/test_config_v2_operator_pipeline_editor.py` | Opt-in disposable-IDB smoke for IDA 9.1 and 9.3. |

### Task 1: Establish pure operator-facing config-v2 projections

**Files:**
- Modify: `src/d810/ui/config_v2_editing_logic.py`
- Modify: `tests/unit/ui/test_config_v2_editing_logic.py`

**Interfaces:**
- Consumes: ConfigV2ProjectDraft, ConfigV2ProjectValidation, and PassCatalogEntry only; no Qt, IDA, registry, or persistence imports.
- Produces:

```python
class ConfigV2EditorScreen(str, enum.Enum):
    OVERVIEW = "overview"
    INSPECTOR = "inspector"
    BUILDER = "builder"

@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2PipelineOverview:
    description: str
    rows: tuple[ConfigV2PipelineRow, ...]

@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2TransformRow:
    transform_id: str
    selected: bool

@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2PassInspectorView:
    pass_index: int
    pass_id: str
    display_name: str
    purpose: str
    runs_during: str
    selected_transforms: tuple[ConfigV2TransformRow, ...]
    transforms_editable: bool
    options: dict[str, object]
    contract: dict[str, object]
    contract_chips: tuple[tuple[str, str], ...]

@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2RoutingView:
    is_auto: bool
    require: str | None
    preferred: tuple[tuple[str, float], ...]
    denied: tuple[str, ...]

@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2RawDocumentView:
    document: dict[str, object]
    preserved_fields: dict[str, object]

@dataclasses.dataclass(frozen=True, slots=True)
class ConfigV2FooterView:
    dirty: bool
    validation_label: str
    validation_detail: str
    save_enabled: bool

def project_config_v2_editor_view(
    draft: ConfigV2ProjectDraft,
    validation: ConfigV2ProjectValidation,
    catalog: tuple[PassCatalogEntry, ...],
) -> ConfigV2EditorView: ...
```

- ConfigV2PipelineRow has index, pass_id, display_name, purpose, runs_during, selected_transform_summary, and option_summary. It never contains child stages or ownership rows.

- [ ] **Step 1: Write failing active-pipeline tests.** Add catalog fixtures for MBA simplify, constant simplification, and jump fixer. Assert only configured entries appear, pipeline order is preserved, and "2 selected transforms" appears only when two registered IDs are present in `options.transforms`.

```python
def test_editor_overview_lists_only_configured_passes_and_real_selection():
    view = logic.project_config_v2_editor_view(
        _draft_with_pipeline(), _validation(), _catalog()
    )

    assert [row.pass_id for row in view.overview.rows] == [
        "mba-simplify",
        "jump-fixer",
    ]
    assert view.overview.rows[0].selected_transform_summary == "2 selected transforms"
    assert view.overview.rows[1].selected_transform_summary == (
        "No individually selectable transforms"
    )
```

- [ ] **Step 2: Write failing inspector/detail tests.** Assert runs_during is catalog maturity, contract chips are Scope/Backend/Safety in that order, and purpose comes from this explicit presentation table, with fallback "Registered config-v2 pass.":

```python
_PASS_PURPOSES = {
    "constant-simplification": "Fold provably constant program values.",
    "mba-simplify": "Simplify selected mixed-boolean arithmetic transforms.",
    "recover-dispatcher": "Recover dispatcher structure and state.",
    "recover-state-transitions": "Recover state-transition edges.",
    "plan-semantic-regions": "Plan semantic regions for safe lowering.",
    "lower-state-machine": "Lower a recovered state machine.",
    "cleanup-residual-dispatcher": "Remove residual dispatcher structure.",
    "jump-fixer": "Repair direct control-flow jumps after rewrites.",
    "indirect-call-resolver": "Resolve eligible indirect calls.",
    "identity-call-resolver": "Resolve identity-preserving indirect calls.",
    "indirect-branch-resolver": "Resolve eligible indirect branches.",
    "single-trip-loop-peel": "Peel a verified single-trip loop.",
    "simple-flattening-cleanup-unflattener": "Remove simple residual flattening structure.",
    "mba-state-preconditioner": "Prepare state facts for MBA-backed recovery.",
}
```

- [ ] **Step 3: Write failing routing/raw/footer tests.** Assert missing router_resolution maps to is_auto=True; preserved fields remove only description, pipeline_v2, and router_resolution; dirty is exactly document_json != original_document_json; stale/invalid validation disables Save and labels itself "Validate before saving."

- [ ] **Step 4: Run the focused suite and verify failure.**

Run:

```bash
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_editing_logic.py
```

Expected: failures for the new editor view/projection.

- [ ] **Step 5: Implement the pure projection.** Parse the draft once, index catalog by pass ID, and raise ValueError for a configured unknown pass. Make transforms editable only if catalog transforms are non-empty and current options contain list-valued transforms. Render transform rows in stable catalog order and derive selection only from that list. Preserve exact JSON-native values for the structured tree.

- [ ] **Step 6: Remove serializer projection from default rendering.** Remove project_serializer_rows from the normal editor. Keep any serializer vocabulary only for the Developer help action.

- [ ] **Step 7: Rerun focused tests and commit.**

Run:

```bash
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_editing_logic.py
git add src/d810/ui/config_v2_editing_logic.py tests/unit/ui/test_config_v2_editing_logic.py
git commit -m "ui: project config-v2 operator views"
```

Expected: PASS, including the no-Qt/no-IDA import boundary.

### Task 2: Add safe manager mutations for transform selection and raw replacement

**Files:**
- Modify: `src/d810/manager/config_v2_editing.py`
- Modify: `src/d810/manager/manager.py`
- Modify: `src/d810/manager/state.py`
- Modify: `tests/unit/manager/test_config_v2_editing.py`
- Modify: `tests/unit/manager/test_config_v2_editing_facade.py`

**Interfaces:**
- Consumes: existing set_pass_options, _unsupported_projection, and PassRegistry.transform_ids_for.
- Produces:

```python
def set_pass_transforms(
    self,
    draft: ConfigV2ProjectDraft,
    *,
    pass_index: int,
    transform_ids: Sequence[str],
) -> ConfigV2ProjectDraft: ...

def replace_document(
    self,
    draft: ConfigV2ProjectDraft,
    document: Mapping[str, object],
) -> ConfigV2ProjectDraft: ...
```

D810Manager and D810State expose set_config_v2_pass_transforms and replace_config_v2_document with identical argument names.

- [ ] **Step 1: Write failing transform-selection tests.** Select ("add-ollvm-1", "add-xor-1") for MBA simplify and assert saved selection is registry order, not click order. Assert transform_options retains only selected IDs; duplicate/unknown IDs raise ConfigV2EditError; jump fixer rejects selection because it has no list-valued options.transforms.

```python
def test_selecting_mba_transforms_is_ordered_lossless_and_validated(tmp_path):
    service, draft = _service_and_draft(tmp_path)
    changed = service.set_pass_transforms(
        draft,
        pass_index=1,
        transform_ids=("add-ollvm-1", "add-xor-1"),
    )

    assert _pipeline_entry(changed, "mba-simplify")["options"]["transforms"] == [
        "add-xor-1",
        "add-ollvm-1",
    ]
```

- [ ] **Step 2: Write failing raw-replacement tests.** Apply a complete copied document with description/options/routing edits and assert validation stays valid. Change migration_metadata and assert ConfigV2EditError contains "outside declared serializers."

- [ ] **Step 3: Run manager/facade suites and verify the APIs are absent.**

Run:

```bash
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/manager/test_config_v2_editing.py tests/unit/manager/test_config_v2_editing_facade.py
```

Expected: failure for missing manager operations/facades.

- [ ] **Step 4: Implement set_pass_transforms.** Require current options to contain list-valued transforms; reject non-string, duplicate, and unregistered IDs; calculate persisted order with:

```python
requested = tuple(str(item) for item in transform_ids)
selected = set(requested)
ordered = [
    transform_id
    for transform_id in self._registry.transform_ids_for(pass_id)
    if transform_id in selected
]
```

Copy options, replace only options["transforms"], and, if transform_options exists, retain keys in ordered. Delegate to set_pass_options so PipelineConfig/registry validation remains final authority.

- [ ] **Step 5: Implement replace_document.** Require a Mapping; deep-copy to a dict; compare _unsupported_projection(candidate) against current draft projection; reject differences with ConfigV2EditError("document fields outside declared serializers changed"). Call _validate_semantics(candidate, draft.destination_path) before _updated. Do not write/reload a file here.

- [ ] **Step 6: Add exact manager/state delegators and facade contract assertions.** Follow the current set_config_v2_pass_options/routing pattern; no UI import enters manager/state.

- [ ] **Step 7: Rerun and commit.**

Run:

```bash
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/manager/test_config_v2_editing.py tests/unit/manager/test_config_v2_editing_facade.py
git add src/d810/manager/config_v2_editing.py src/d810/manager/manager.py src/d810/manager/state.py tests/unit/manager/test_config_v2_editing.py tests/unit/manager/test_config_v2_editing_facade.py
git commit -m "feat(config): add validated transform and raw edits"
```

Expected: PASS and lossless closed failure.

### Task 3: Extend the thin adapter and conservative focus model

**Files:**
- Modify: `src/d810/ui/config_v2_editing_commands.py`
- Modify: `src/d810/ui/project_config_logic.py`
- Modify: `tests/unit/ui/test_config_v2_editing_commands.py`
- Modify: `tests/unit/ui/test_project_config_logic.py`

**Interfaces:**
- Produces:

```python
def set_pass_transforms(
    self,
    draft: ConfigV2ProjectDraft,
    *,
    pass_index: int,
    transform_ids: Sequence[str],
) -> tuple[ConfigV2ProjectDraft, ConfigV2ProjectValidation]: ...

def replace_document(
    self,
    draft: ConfigV2ProjectDraft,
    document: Mapping[str, object],
) -> tuple[ConfigV2ProjectDraft, ConfigV2ProjectValidation]: ...

def load_view(self) -> tuple[ConfigV2ProjectDraft, ConfigV2ProjectValidation]: ...
```

ConfigV2FocusTarget gains pass_index: int | None. resolve_config_v2_focus_target(pass_id, pipeline_pass_ids, pass_index=None) refuses duplicate or mismatched targets instead of guessing.

- [ ] **Step 1: Write failing adapter tests.** Assert each new method calls its state facade once and revalidates once. Assert load_view creates/validates an ordinary draft and does not materialize a recipe when none exists.

- [ ] **Step 2: Write failing focus tests.** Cover a unique pass ID, duplicate IDs with no index, a valid explicit index, and an index naming another pass.

```python
def test_focus_target_refuses_duplicate_pipeline_pass_without_row_index():
    target = resolve_config_v2_focus_target(
        "mba-simplify", ("mba-simplify", "mba-simplify")
    )

    assert target.pass_index is None
    assert target.unambiguous is False
```

- [ ] **Step 3: Run tests and verify failure.**

```bash
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_editing_commands.py tests/unit/ui/test_project_config_logic.py
```

- [ ] **Step 4: Implement adapter delegates through _edited.** Import only Mapping/Sequence; do not parse JSON or inspect registry. load_view uses the current create-and-validate sequence; reset remains explicit discard behavior.

- [ ] **Step 5: Implement conservative focus.** Supplied index must be in range and name supplied pass. Without an index, select only a pass ID that occurs once. Any other case returns an explanatory no-index target and does not raise.

- [ ] **Step 6: Rerun and commit.**

```bash
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_editing_commands.py tests/unit/ui/test_project_config_logic.py
git add src/d810/ui/config_v2_editing_commands.py src/d810/ui/project_config_logic.py tests/unit/ui/test_config_v2_editing_commands.py tests/unit/ui/test_project_config_logic.py
git commit -m "ui: add config-v2 operator edit intents"
```

Expected: PASS.

### Task 4: Replace the configuration dock ownership tree with active pipeline overview

**Files:**
- Create: `src/d810/ui/config_v2_pipeline_overview.py`
- Modify: `src/d810/ui/ida_ui.py`
- Modify: `src/d810/ui/workbench_panel.py`
- Create: `tests/unit/ui/test_config_v2_pipeline_overview_contract.py`
- Modify: `tests/unit/ui/test_project_config_adapter_contract.py`

**Interfaces:**
- ConfigV2PipelineOverviewWidget.set_overview(overview: ConfigV2PipelineOverview | None) -> None emits inspect_requested(int) and edit_pipeline_requested().
- D810ConfigForm_t._open_config_v2_editor(destination, *, screen, focus_target=None) accepts Inspector only for active-row inspection and Builder for ordinary edit/recipe paths.

- [ ] **Step 1: Add failing widget contract.** Assert public signals above, an Edit pipeline... button, and active rows from overview.rows in ordinal order. Assert source lacks transform_ids, stage_ids, "Transform:", and "Stage:".

- [ ] **Step 2: Add failing form contracts.** Assert OnCreate uses ConfigV2PipelineOverviewWidget rather than PassTreeWidget, connects overview signals, and does not connect PassTreeWidget.edit_requested. Assert ordinary edit and recipe profile use Builder; inspect route uses Inspector and an exact focus target.

- [ ] **Step 3: Run tests and verify the ownership tree fails.**

```bash
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_pipeline_overview_contract.py tests/unit/ui/test_project_config_adapter_contract.py
```

- [ ] **Step 4: Implement overview widget.** Use a non-expandable two-column QTreeWidget or QListWidget; render only N. Display name plus transform summary, with purpose/timing tooltip. Double-click/Enter emit the configured row index. Non-config-v2 gets compact unavailable text. The sole action is Edit pipeline....

- [ ] **Step 5: Load overview only through adapter.** In _apply_project_config_view, when config-v2 is active calculate deterministic user destination, create ConfigV2EditingAdapter, call load_view, and project project_config_v2_editor_view(draft, validation, catalog).overview. Qt must not open/read runtime JSON and must not mutate/reload just to display it.

- [ ] **Step 6: Wire routes.** _inspect_config_v2_pass(index) derives active row, resolves indexed focus target, and opens Inspector. _edit_config, duplicate, and Workbench recipe profile open Builder. Construct replacement panel before closing current panel so a failed construct leaves the old panel usable.

- [ ] **Step 7: Rerun and commit.**

```bash
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_pipeline_overview_contract.py tests/unit/ui/test_project_config_adapter_contract.py
git add src/d810/ui/config_v2_pipeline_overview.py src/d810/ui/ida_ui.py tests/unit/ui/test_config_v2_pipeline_overview_contract.py tests/unit/ui/test_project_config_adapter_contract.py
git commit -m "ui: show config-v2 active pipeline overview"
```

Expected: PASS and no inactive catalog rows crowd the dock.

### Task 5: Implement focused Pass Inspector with structured JSON

**Files:**
- Modify: `src/d810/ui/config_v2_editing_panel.py`
- Modify: `tests/unit/ui/test_config_v2_editing_panel_contract.py`

**Interfaces:**
- ConfigV2EditingPanel(..., screen: ConfigV2EditorScreen = ConfigV2EditorScreen.BUILDER, focus_target=None) keeps one draft for its lifetime.
- _show_inspector(pass_index: int) and _show_builder() change screens with no reset/save/reload.

- [ ] **Step 1: Replace serializer-layout tests with failing Inspector contracts.** Remove requirements for manifest_list, three-pane splitter, routing_view, permanent raw panes, and large description editor. Require JsonTreeEditor, RawJsonDialog, StructuredDetailsView, a stacked Builder/Inspector host, and project_config_v2_editor_view in _render.

- [ ] **Step 2: Add failing interaction contracts.** Require Pass/Purpose/Runs during fields, Scope/Backend/Safety chips, a checkable QListWidget picker, editable options tree, readonly contract tree, View raw contract, Edit raw options, and Edit pipeline.... Require transform callback to call set_pass_transforms and option callbacks to call set_pass_options.

- [ ] **Step 3: Run contract and verify failure.**

```bash
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_editing_panel_contract.py
```

- [ ] **Step 4: Implement state-preserving render.** Store _screen, _selected_pass_index, _editor_view, and catalog lookup. After every adapter edit rerender without changing screen. Apply focus pass_index directly and reject mismatched rows.

- [ ] **Step 5: Implement Inspector controls.** Compact QFormLayout for identity/purpose/timing; three labels for contract chips; picker only when transforms_editable, otherwise exact text "No individually selectable transforms." Populate from pure transform selection, not registry stages. Use JsonTreeEditor for scalar options and readonly contract; raw dialog is options-editable/contract-readonly.

- [ ] **Step 6: Implement callbacks.** Gather checked values in displayed registry order and call set_pass_transforms. Option callbacks accept dict only then call set_pass_options. On rejection rerender authoritative state and show compact error; never leave optimistic invalid tree value.

- [ ] **Step 7: Add Inspector -> Builder route.** Edit pipeline... changes screen and preserves same draft, validation, selection; it does not reset, re-read source, or save.

- [ ] **Step 8: Rerun and commit.**

```bash
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_editing_panel_contract.py
git add src/d810/ui/config_v2_editing_panel.py tests/unit/ui/test_config_v2_editing_panel_contract.py
git commit -m "ui: add config-v2 pass inspector"
```

Expected: PASS.

### Task 6: Implement compact Builder, routing controls, raw-document dialog, and footer

**Files:**
- Modify: `src/d810/ui/config_v2_editing_panel.py`
- Modify: `tests/unit/ui/test_config_v2_editing_panel_contract.py`

**Interfaces:**
- Builder methods:

```python
def _edit_description(self) -> None: ...
def _apply_routing_rows(self) -> None: ...
def _show_raw_document(self) -> None: ...
def _apply_raw_document(self, value: object) -> None: ...
def _discard_unsaved(self) -> None: ...
```

- [ ] **Step 1: Add failing Builder/footer contracts.** Require numbered active-pass list with Add pass..., Remove, Move up, Move down, Open Inspector, Edit description.... Require collapsed Routing group exposing Auto, Require, Prefer, Exclude. Require shared footer with Clean/Unsaved, validation state, ... overflow, Save. Reject default "Save atomically and reload", "Reset draft", and permanent QPlainTextEdit status box.

- [ ] **Step 2: Add failing structured raw-dialog contracts.** Require JsonTreeEditor.set_json(..., editable=False), explicit Edit raw warning before editable mode, optional Open raw JSON..., and every apply through adapter.replace_document. Preserved fields use readonly tree. Serializer manifest wording appears only in Developer help.

- [ ] **Step 3: Run panel contract and verify failure.**

```bash
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_editing_panel_contract.py
```

- [ ] **Step 4: Build Builder.** Header is elided destination plus validation. Description is explicit modal Edit description.... Add pass... opens filtered public catalog picker. Ordered list controls add/remove/reorder/open Inspector; it never lists inactive registry passes.

- [ ] **Step 5: Replace routing JSON with controls.** Collapsed label is Auto routing if no policy, Routing override otherwise. Expanded body has Require combo (Automatic + registered families), preferred-family table (checkbox + finite QDoubleSpinBox bias), and excluded-family checklist. Build prefer/require/deny and call set_routing_override. Manager rejection preserves draft and shows error.

- [ ] **Step 6: Build raw document dialog from Workbench pieces.** It has Structured document and Preserved fields trees. Edit raw warns, "Only declared config-v2 fields may change; all edits are fully validated before save." On confirmation edit the first tree and route every scalar edit through _apply_raw_document. Optional raw text uses RawJsonDialog and same callback. Rejected change rerenders from authoritative draft.

- [ ] **Step 7: Implement compact footer.** Left: <Clean|Unsaved changes> | <Ready|Blocked|Validate before saving>; middle ... menu; right Save. Overflow contains exactly Validate, Discard unsaved, Save as new..., View raw, Developer help. Discard confirms then adapter.reset; Save as retains current retarget chooser; Save uses existing atomic reload then refreshes. Errors appear immediately above in a hideable one/two-line QLabel.

- [ ] **Step 8: Rerun and commit.**

```bash
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/ui/test_config_v2_editing_panel_contract.py
git add src/d810/ui/config_v2_editing_panel.py tests/unit/ui/test_config_v2_editing_panel_contract.py
git commit -m "ui: build compact config-v2 pipeline editor"
```

Expected: PASS; no default raw JSON pane, serializer manifest, or unexplained draft/reset terminology.

### Task 7: Verify the full operator flow in both native GUI bindings

**Files:**
- Create: `tests/system/runtime/ui/test_config_v2_operator_pipeline_editor.py`
- Modify: `tests/unit/ui/test_config_v2_editing_panel_contract.py`
- Modify: `tests/unit/ui/test_project_config_adapter_contract.py`

**Interfaces:**
- Consumes: disposable copied IDB, loaded __main__.D810.plugin.gui.d810_config_form, D810_NATIVE_GUI_SMOKE=1, and D810_EXPECTED_QT_BINDING.
- Produces: opt-in smoke proving actual PyQt5/PyQt6 behavior without source-IDB mutation.

- [ ] **Step 1: Add final route assertions.** Configuration double-click routes to Inspector; every explicit edit route opens Builder; no active UI route uses PassTreeWidget.edit_requested or old "owned" transform state.

- [ ] **Step 2: Write native smoke before claiming actual GUI behavior.** Follow _process_until in test_workbench_maturity_canvas.py: open ordinary config editing, assert Builder/active list/compact footer, open Inspector, exercise an editable transform if present, open raw view and assert readonly initially, then Save as to user config destination. Assert destination exists and copied source IDB hash does not change.

```python
def test_native_config_v2_operator_editor_on_disposable_idb(tmp_path):
    import __main__

    form = __main__.D810.plugin.gui.d810_config_form
    form._edit_config()
    editor = _process_until(lambda: form._config_v2_editor)

    assert editor._screen is ConfigV2EditorScreen.BUILDER
    assert editor.pipeline_list.count() > 0
    assert editor.save_button.text() == "Save"

    editor._show_inspector(0)
    assert editor._screen is ConfigV2EditorScreen.INSPECTOR
```

- [ ] **Step 3: Run focused unit suites.**

```bash
PYTHONPATH=src pyenv exec python -m pytest -q   tests/unit/ui/test_config_v2_editing_logic.py   tests/unit/manager/test_config_v2_editing.py   tests/unit/manager/test_config_v2_editing_facade.py   tests/unit/ui/test_config_v2_editing_commands.py   tests/unit/ui/test_config_v2_pipeline_overview_contract.py   tests/unit/ui/test_config_v2_editing_panel_contract.py   tests/unit/ui/test_project_config_logic.py   tests/unit/ui/test_project_config_adapter_contract.py
```

Expected: PASS.

- [ ] **Step 4: Run architecture gates.**

```bash
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src pyenv exec lint-imports --config .importlinter
```

Expected: no rule/import-boundary violations.

- [ ] **Step 5: Run PyQt6 / IDA 9.3 smoke on copied IDB.**

```bash
open -a XQuartz
/opt/X11/bin/xhost +localhost
./tools/scripts/run_ida_gui_docker.sh   -w lrea-portable-cfg-case-producer   --open-config   -- /samples/bins/libobfuscated.dll.2026-06-03.i64
```

In IDA Python:

```python
import os
import pytest

os.environ["D810_NATIVE_GUI_SMOKE"] = "1"
os.environ["D810_EXPECTED_QT_BINDING"] = "PyQt6"
pytest.main(["-q", "/work/tests/system/runtime/ui/test_config_v2_operator_pipeline_editor.py"])
```

Expected: PASS, PyQt6, and launcher-reported /work/.tmp/ida-gui/ copy.

- [ ] **Step 6: Run PyQt5 / IDA 9.1 smoke on separately copied IDB.**

```bash
D810_GUI_DOCKER_IMAGE=idapro-9.1-speedups:x11-amd64 ./tools/scripts/run_ida_gui_docker.sh   -w lrea-portable-cfg-case-producer   --open-config   -- /samples/bins/libobfuscated.dll.2026-06-03.i64
```

In IDA Python:

```python
import os
import pytest

os.environ["D810_NATIVE_GUI_SMOKE"] = "1"
os.environ["D810_EXPECTED_QT_BINDING"] = "PyQt5"
pytest.main(["-q", "/work/tests/system/runtime/ui/test_config_v2_operator_pipeline_editor.py"])
```

Expected: PASS, PyQt5, no Qt6-only APIs.

- [ ] **Step 7: Refresh graph, inspect, and commit proof.**

```bash
graphify update .
git diff --check
git status --short
git diff --stat
git add src/d810/ui/config_v2_editing_panel.py src/d810/ui/config_v2_pipeline_overview.py src/d810/ui/config_v2_editing_logic.py src/d810/ui/config_v2_editing_commands.py src/d810/ui/ida_ui.py src/d810/ui/project_config_logic.py src/d810/manager/config_v2_editing.py src/d810/manager/manager.py src/d810/manager/state.py tests/unit tests/system/runtime/ui/test_config_v2_operator_pipeline_editor.py graphify-out
git commit -m "test(ui): verify config-v2 operator workflow"
```

Expected: graph update succeeds, git diff --check is silent, and only planned feature/test/graph files are staged.
