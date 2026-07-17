# Scalable Configuration Picker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every discovered D-810 JSON configuration quickly searchable and directly selectable from the native configuration UI.

**Architecture:** A Qt-free catalog projection owns routing labels, stable original indices, and search filtering. A small Qt dialog renders those entries, while `D810ConfigForm_t` remains the only code that activates a project through `_load_config(index)`.

**Tech Stack:** Python 3.13, D810 typed core models, Qt shim, PyQt5/PySide6 under IDA, pytest.

## Global Constraints

- Every JSON discovered by `ProjectManager` remains selectable.
- The displayed filtered row carries the original `ProjectManager` index; no filtered-row index may reach `D810State.load_project`.
- Supported config-v2 mapping labels must be derived from `CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS` and only claim routing when both source and runtime are in the catalog.
- The pure logic module must not import Qt, IDA, manager state, or live Hex-Rays modules.
- Preserve `.superpowers/` and unrelated working-tree files.

---

### Task 1: Add pure configuration picker catalog logic

**Files:**

- Create: `src/d810/ui/project_picker_logic.py`
- Create: `tests/unit/ui/test_project_picker_logic.py`

**Interfaces:**

- Consumes: `Sequence[ProjectConfiguration]` and `CONFIG_V2_SUPPORTED_DEFAULT_MAPPINGS`.
- Produces: `ProjectPickerEntry`, `build_project_picker_entries(projects)`, and `filter_project_picker_entries(entries, query)`.

- [ ] **Step 1: Write the failing test**

```python
def test_picker_entries_keep_project_indices_and_describe_present_v2_pairs() -> None:
    entries = logic.build_project_picker_entries((source, runtime, legacy))

    assert [(entry.project_index, entry.filename) for entry in entries] == [
        (0, "default_unflattening_ollvm.json"),
        (1, "default_unflattening_ollvm_config_v2_canary.json"),
        (2, "other.json"),
    ]
    assert entries[0].behavior == "Config v2 -> default_unflattening_ollvm_config_v2_canary.json"
    assert entries[1].behavior == "Config v2 runtime (direct)"
    assert entries[2].behavior == "Direct project"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `PYTHONPATH=src pytest tests/unit/ui/test_project_picker_logic.py -q`

Expected: FAIL because `d810.ui.project_picker_logic` does not exist.

- [ ] **Step 3: Implement the minimal pure projection**

```python
@dataclasses.dataclass(frozen=True, slots=True)
class ProjectPickerEntry:
    project_index: int
    filename: str
    behavior: str
    description: str
    search_text: str

def build_project_picker_entries(
    projects: Sequence[ProjectConfiguration],
) -> tuple[ProjectPickerEntry, ...]:
    ...

def filter_project_picker_entries(
    entries: Sequence[ProjectPickerEntry], query: str,
) -> tuple[ProjectPickerEntry, ...]:
    ...
```

Build source/runtime labels only when both mapped names are present. Normalize case and whitespace for substring matching while preserving catalog order and `project_index`.

- [ ] **Step 4: Run focused tests to verify green**

Run: `PYTHONPATH=src pytest tests/unit/ui/test_project_picker_logic.py -q`

Expected: PASS.

### Task 2: Add an import-safe native picker dialog

**Files:**

- Create: `src/d810/ui/project_picker_dialog.py`
- Create: `tests/unit/ui/test_project_picker_dialog_contract.py`

**Interfaces:**

- Consumes: `Sequence[ProjectPickerEntry]` and a current original project index.
- Produces: `ProjectPickerDialog.selected_project_index() -> int | None` after acceptance.

- [ ] **Step 1: Write the failing source-contract test**

```python
def test_picker_dialog_filters_pure_entries_and_returns_original_index() -> None:
    source = DIALOG.read_text(encoding="utf-8")

    assert "filter_project_picker_entries" in source
    assert "project_index" in source
    assert "Load selected" in source
    assert "Filter filename, description, or runtime..." in source
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `PYTHONPATH=src pytest tests/unit/ui/test_project_picker_dialog_contract.py -q`

Expected: FAIL because `project_picker_dialog.py` does not exist.

- [ ] **Step 3: Implement the minimal Qt dialog**

```python
class ProjectPickerDialog(QtWidgets.QDialog):
    def __init__(self, entries, *, current_project_index, parent=None) -> None: ...
    def selected_project_index(self) -> int | None: ...
```

Use a `QLineEdit`, `QTableWidget`, `Load selected`, and `Cancel`. Rebuild only visible table rows after filter changes, keep the original entry on each visible row, and accept only a stable original index. Provide an import-safe stub when IDA is unavailable.

- [ ] **Step 4: Run focused tests to verify green**

Run: `PYTHONPATH=src pytest tests/unit/ui/test_project_picker_logic.py tests/unit/ui/test_project_picker_dialog_contract.py -q`

Expected: PASS.

### Task 3: Replace the flat combobox shell and preserve activation behavior

**Files:**

- Modify: `src/d810/ui/ida_ui.py:579-787, 833-849, 1209-1238`
- Modify: `tests/unit/ui/test_project_config_adapter_contract.py`

**Interfaces:**

- Consumes: `ProjectPickerDialog` and the exact `state.project_manager.projects()` sequence.
- Produces: `_open_config_picker()` that calls `_load_config(selected_original_index)` once on acceptance.

- [ ] **Step 1: Write the failing form-contract test**

```python
def test_form_uses_picker_without_loading_a_filtered_row_index() -> None:
    calls = _call_names(_method("_open_config_picker"))

    assert "ProjectPickerDialog" in calls
    assert "selected_project_index" in calls
    assert "_load_config" in calls
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `PYTHONPATH=src pytest tests/unit/ui/test_project_config_adapter_contract.py -q`

Expected: FAIL because `_open_config_picker` does not exist.

- [ ] **Step 3: Implement the form integration**

Replace `QComboBox` construction and signal wiring with a current-config `QPushButton` that opens `_open_config_picker`. Rework `update_cfg_select()` into a caption synchronizer that reads the current manager index but does not load configuration. After `_load_config(index)` succeeds, refresh the button caption and retain the existing runtime snapshot view.

- [ ] **Step 4: Run focused tests to verify green**

Run: `PYTHONPATH=src pytest tests/unit/ui/test_project_picker_logic.py tests/unit/ui/test_project_picker_dialog_contract.py tests/unit/ui/test_project_config_adapter_contract.py -q`

Expected: PASS.

### Task 4: Validate the complete change and native UI

**Files:**

- Modify: `.tickets/tcvpu-313q.md` with results and remaining visual evidence.

- [ ] **Step 1: Run the full test and architecture gates**

Run:

```bash
PYTHONPATH=src pytest tests/unit/ -q
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
git diff --check
graphify update .
```

Expected: unit tests pass; ast-grep exits 0; 13 import contracts remain kept; diff check exits 0.

- [ ] **Step 2: Launch native IDA with the selected worktree**

Run:

```bash
./tools/scripts/run_ida_gui_docker.sh \
  -w truthful-config-v2-project-ui \
  --open-config \
  -- /samples/bins/libobfuscated.dll.2026-06-03.i64
```

Expected: the image mounts the selected worktree plugin, copies the sample database before opening it, and shows the `D-810 Configuration` form in XQuartz.

- [ ] **Step 3: Inspect picker behavior in XQuartz**

Search a known canary filename, select it, reopen the picker, then search its mapped source filename. Verify both are present as independent rows and the selected project identity changes only after `Load selected` or double-click.

- [ ] **Step 4: Commit after fresh evidence**

```bash
git add src/d810/ui/project_picker_logic.py \
  src/d810/ui/project_picker_dialog.py \
  src/d810/ui/ida_ui.py \
  tests/unit/ui/test_project_picker_logic.py \
  tests/unit/ui/test_project_picker_dialog_contract.py \
  tests/unit/ui/test_project_config_adapter_contract.py
git add -f .tickets/tcvpu-313q.md \
  docs/superpowers/specs/2026-07-17-scalable-configuration-picker-design.md \
  docs/superpowers/plans/2026-07-17-scalable-configuration-picker.md
git commit -m "feat(ui): add searchable configuration picker"
```
