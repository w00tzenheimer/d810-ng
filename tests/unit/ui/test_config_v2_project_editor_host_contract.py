from __future__ import annotations

import ast
import copy
import pathlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace

from d810.core import typing
from d810.core.pass_editor_spec import FieldControlKind, FieldEditorSpec
from d810.ui.config_v2_editing_logic import ConfigV2EditorScreen
from d810.ui.project_config_logic import (
    ConfigEditMode,
    ConfigV2FocusTarget,
    resolve_config_v2_focus_target,
)


UI_DIR = Path(__file__).resolve().parents[3] / "src" / "d810" / "ui"
IDA_UI = UI_DIR / "ida_ui.py"
PIPELINE_OVERVIEW = UI_DIR / "config_v2_pipeline_overview.py"
PROJECT_EDITOR = UI_DIR / "config_v2_editing_panel.py"
IDA_UI_TREE = ast.parse(IDA_UI.read_text(encoding="utf-8"), filename=str(IDA_UI))
PIPELINE_OVERVIEW_TREE = ast.parse(
    PIPELINE_OVERVIEW.read_text(encoding="utf-8"),
    filename=str(PIPELINE_OVERVIEW),
)
PROJECT_EDITOR_TREE = ast.parse(
    PROJECT_EDITOR.read_text(encoding="utf-8"),
    filename=str(PROJECT_EDITOR),
)


def test_active_overview_uses_configured_pass_inspection_catalog() -> None:
    method = ast.get_source_segment(
        IDA_UI.read_text(encoding="utf-8"),
        _form_method("_apply_project_config_view"),
    )

    assert method is not None
    assert "adapter.inspection_catalog(validation.pass_ids)" in method


def test_project_editor_uses_draft_rows_for_private_inspection_catalog() -> None:
    source = PROJECT_EDITOR.read_text(encoding="utf-8")

    assert "self._catalog = tuple(adapter.catalog())" in source
    assert "self._inspection_catalog = tuple(" in source
    assert "tuple(row.pass_id for row in self._view.pipeline_rows)" in source
    assert "inspection_catalog(self._validation.pass_ids)" not in source
    assert "for entry in self._catalog" in source


class _Logger:
    def debug(self, *args: object) -> None:
        del args

    def warning(self, *args: object) -> None:
        del args


def _form_method(name: str) -> ast.FunctionDef:
    for node in IDA_UI_TREE.body:
        if isinstance(node, ast.ClassDef) and node.name == "D810ConfigForm_t":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    raise AssertionError(f"D810ConfigForm_t.{name} not found")


def _compiled_form_method(name: str, **extra_globals: object):
    class_node = ast.ClassDef(
        name="ConfigFormHarness",
        bases=[],
        keywords=[],
        body=[copy.deepcopy(_form_method(name))],
        decorator_list=[],
    )
    module = ast.fix_missing_locations(ast.Module(body=[class_node], type_ignores=[]))
    namespace = {
        "ConfigEditMode": ConfigEditMode,
        "ConfigV2EditorScreen": ConfigV2EditorScreen,
        "ConfigV2FocusTarget": ConfigV2FocusTarget,
        "QtWidgets": SimpleNamespace(),
        "logger": _Logger(),
        "pathlib": pathlib,
        "resolve_config_v2_focus_target": resolve_config_v2_focus_target,
    }
    namespace.update(extra_globals)
    exec(compile(module, filename=str(IDA_UI), mode="exec"), namespace)
    return getattr(namespace["ConfigFormHarness"], name)


def _overview_method(name: str) -> ast.FunctionDef:
    for node in PIPELINE_OVERVIEW_TREE.body:
        if (
            isinstance(node, ast.ClassDef)
            and node.name == "ConfigV2PipelineOverviewWidget"
        ):
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    raise AssertionError(f"ConfigV2PipelineOverviewWidget.{name} not found")


def _compiled_overview_method(name: str):
    class_node = ast.ClassDef(
        name="PipelineOverviewHarness",
        bases=[],
        keywords=[],
        body=[copy.deepcopy(_overview_method(name))],
        decorator_list=[],
    )
    module = ast.fix_missing_locations(ast.Module(body=[class_node], type_ignores=[]))
    namespace = {
        "QtCore": SimpleNamespace(Qt=SimpleNamespace(UserRole=32)),
    }
    exec(compile(module, filename=str(PIPELINE_OVERVIEW), mode="exec"), namespace)
    return getattr(namespace["PipelineOverviewHarness"], name)


class _BehaviorSignal:
    def __init__(self) -> None:
        self._callbacks: list[object] = []

    def connect(self, callback: object) -> None:
        self._callbacks.append(callback)

    def emit(self, *args: object) -> None:
        for callback in tuple(self._callbacks):
            callback(*args)


class _OverviewItem:
    def __init__(self, stored_row: int) -> None:
        self._stored_row = stored_row

    def data(self, column: int, role: int) -> int:
        assert (column, role) == (0, 32)
        return self._stored_row


def _allowed_policy(_mode: object, _snapshot: object) -> SimpleNamespace:
    return SimpleNamespace(allowed=True, explanation="")


def test_configuration_overview_owns_both_project_editor_entry_routes() -> None:
    source = ast.unparse(_form_method("OnCreate"))

    assert (
        "self._pipeline_overview.edit_pipeline_requested.connect(self._edit_config)"
        in source
    )
    assert (
        "self._pipeline_overview.inspect_requested.connect("
        "self._inspect_config_v2_pass)" in source
    )


def test_edit_pipeline_opens_the_project_editor_on_builder() -> None:
    destination = pathlib.Path("/config/selected.json")
    snapshot = object()
    opened: list[tuple[pathlib.Path, ConfigV2EditorScreen, object | None]] = []
    form = SimpleNamespace(
        parent=object(),
        state=SimpleNamespace(get_project_runtime_snapshot=lambda: snapshot),
        _choose_config_v2_destination=lambda value, *, duplicate: (
            destination
            if value is snapshot and duplicate is False
            else (_ for _ in ()).throw(AssertionError("wrong destination request"))
        ),
        _open_config_v2_editor=lambda value, *, screen, focus_target=None: opened.append(
            (value, screen, focus_target)
        ),
    )
    edit = _compiled_form_method(
        "_edit_config",
        select_config_edit_policy=_allowed_policy,
    )

    edit(form)

    assert opened == [(destination, ConfigV2EditorScreen.BUILDER, None)]


def test_overview_activation_emits_stored_row_into_exact_host_inspector_focus() -> None:
    rows = (
        SimpleNamespace(index=0, pass_id="preflight"),
        SimpleNamespace(index=1, pass_id="jump-fixer"),
        SimpleNamespace(index=2, pass_id="jump-fixer"),
    )
    destination = pathlib.Path("/config/selected.json")
    snapshot = object()
    opened: list[tuple[pathlib.Path, ConfigV2EditorScreen, ConfigV2FocusTarget]] = []
    form = SimpleNamespace(
        _config_v2_overview=SimpleNamespace(rows=rows),
        state=SimpleNamespace(get_project_runtime_snapshot=lambda: snapshot),
        _choose_config_v2_destination=lambda value, *, duplicate: (
            destination
            if value is snapshot and duplicate is False
            else (_ for _ in ()).throw(AssertionError("wrong destination request"))
        ),
        _open_config_v2_editor=lambda value, *, screen, focus_target: opened.append(
            (value, screen, focus_target)
        ),
    )
    inspect = _compiled_form_method(
        "_inspect_config_v2_pass",
        select_config_edit_policy=_allowed_policy,
    )
    activate = _compiled_overview_method("_activate_item")
    inspect_requested = _BehaviorSignal()
    inspect_requested.connect(types.MethodType(inspect, form))
    overview_widget = SimpleNamespace(
        _overview=SimpleNamespace(rows=rows),
        inspect_requested=inspect_requested,
    )

    activate(overview_widget, _OverviewItem(stored_row=2), 0)

    assert opened == [
        (
            destination,
            ConfigV2EditorScreen.INSPECTOR,
            ConfigV2FocusTarget(
                pass_id="jump-fixer",
                pass_index=2,
                message="Editing config-v2 pass 'jump-fixer' at row 2.",
                unambiguous=True,
            ),
        )
    ]


def _successful_editor_harness(monkeypatch):
    panel_instances = []

    class Adapter:
        def __init__(self, state: object, *, destination: pathlib.Path) -> None:
            self.state = state
            self.destination = destination

    class Panel:
        def __init__(
            self,
            adapter: Adapter,
            *,
            on_saved: object,
            screen: ConfigV2EditorScreen,
            focus_target: ConfigV2FocusTarget | None,
        ) -> None:
            self.adapter = adapter
            self.on_saved = on_saved
            self.screen = screen
            self.focus_target = focus_target
            self.show_count = 0
            self.close_count = 0
            panel_instances.append(self)

        def show(self) -> None:
            self.show_count += 1

        def close(self) -> None:
            self.close_count += 1

    monkeypatch.setitem(
        sys.modules,
        "d810.ui.config_v2_editing_commands",
        types.SimpleNamespace(ConfigV2EditingAdapter=Adapter),
    )
    monkeypatch.setitem(
        sys.modules,
        "d810.ui.config_v2_editing_panel",
        types.SimpleNamespace(ConfigV2EditingPanel=Panel),
    )
    form = SimpleNamespace(
        state=object(),
        parent=object(),
        _config_v2_editor=None,
        _refresh_config_v2_project_view=lambda: None,
    )
    return _compiled_form_method("_open_config_v2_editor"), form, panel_instances


def test_successful_inspector_construction_forwards_exact_focus_target(
    monkeypatch,
) -> None:
    open_editor, form, panel_instances = _successful_editor_harness(monkeypatch)
    destination = pathlib.Path("/config/selected.json")
    focus_target = ConfigV2FocusTarget(
        pass_id="jump-fixer",
        pass_index=2,
        message="Editing config-v2 pass 'jump-fixer' at row 2.",
        unambiguous=True,
    )

    open_editor(
        form,
        destination,
        screen=ConfigV2EditorScreen.INSPECTOR,
        focus_target=focus_target,
    )

    assert len(panel_instances) == 1
    editor = panel_instances[0]
    assert editor.adapter.state is form.state
    assert editor.adapter.destination == destination
    assert editor.screen is ConfigV2EditorScreen.INSPECTOR
    assert editor.focus_target is focus_target
    assert editor.on_saved is form._refresh_config_v2_project_view
    assert editor.show_count == 1
    assert form._config_v2_editor is editor


def test_successful_builder_construction_has_no_focus_target(monkeypatch) -> None:
    open_editor, form, panel_instances = _successful_editor_harness(monkeypatch)

    open_editor(
        form,
        pathlib.Path("/config/selected.json"),
        screen=ConfigV2EditorScreen.BUILDER,
    )

    assert len(panel_instances) == 1
    editor = panel_instances[0]
    assert editor.screen is ConfigV2EditorScreen.BUILDER
    assert editor.focus_target is None
    assert editor.show_count == 1
    assert form._config_v2_editor is editor


def test_failed_replacement_construction_keeps_the_old_editor_usable(
    monkeypatch,
) -> None:
    events: list[str] = []

    class Adapter:
        def __init__(self, _state: object, *, destination: pathlib.Path) -> None:
            del destination
            events.append("adapter constructed")

    class Panel:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs
            events.append("panel construction failed")
            raise RuntimeError("panel construction failed")

    class OldEditor:
        def __init__(self) -> None:
            self.close_count = 0

        def close(self) -> None:
            self.close_count += 1

    critical_messages: list[str] = []
    qt_widgets = SimpleNamespace(
        QMessageBox=SimpleNamespace(
            critical=lambda _parent, _title, message: critical_messages.append(message)
        )
    )
    monkeypatch.setitem(
        sys.modules,
        "d810.ui.config_v2_editing_commands",
        types.SimpleNamespace(ConfigV2EditingAdapter=Adapter),
    )
    monkeypatch.setitem(
        sys.modules,
        "d810.ui.config_v2_editing_panel",
        types.SimpleNamespace(ConfigV2EditingPanel=Panel),
    )
    old_editor = OldEditor()
    form = SimpleNamespace(
        state=object(),
        parent=object(),
        _config_v2_editor=old_editor,
        _refresh_config_v2_project_view=lambda: None,
    )
    open_editor = _compiled_form_method("_open_config_v2_editor", QtWidgets=qt_widgets)

    open_editor(
        form,
        pathlib.Path("/config/selected.json"),
        screen=ConfigV2EditorScreen.BUILDER,
    )

    assert events == ["adapter constructed", "panel construction failed"]
    assert critical_messages == ["panel construction failed"]
    assert old_editor.close_count == 0
    assert form._config_v2_editor is old_editor


def test_project_editor_has_no_project_selector_or_duplicate_edit_entry() -> None:
    editor_source = PROJECT_EDITOR.read_text(encoding="utf-8")

    for host_owned_symbol in (
        "ProjectPickerPopup",
        "build_project_picker_entries",
        "cfg_select",
        "config_v2_user_destination",
        "getOpenFileName",
        "getExistingDirectory",
        "Edit pipeline...",
    ):
        assert host_owned_symbol not in editor_source


def test_edit_pipeline_entry_text_exists_only_in_the_host_overview() -> None:
    owners = []
    for path in sorted(UI_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if any(
            isinstance(node, ast.Constant) and node.value == "Edit pipeline..."
            for node in ast.walk(tree)
        ):
            owners.append(path)

    assert owners == [PIPELINE_OVERVIEW]


def _project_editor_method(name: str) -> ast.FunctionDef:
    for node in ast.walk(PROJECT_EDITOR_TREE):
        if isinstance(node, ast.ClassDef) and node.name == "ConfigV2EditingPanel":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    raise AssertionError(f"ConfigV2EditingPanel.{name} not found")


class _SignalStub:
    def __init__(self) -> None:
        self._callbacks: list[object] = []

    def connect(self, callback: object) -> None:
        self._callbacks.append(callback)

    def emit(self, *args: object) -> None:
        for callback in tuple(self._callbacks):
            callback(*args)


class _WidgetStub:
    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        self.layout: _VBoxLayoutStub | None = None


class _VBoxLayoutStub:
    def __init__(self, parent: _WidgetStub) -> None:
        parent.layout = self
        self.widgets: list[_CheckBoxStub] = []

    def setContentsMargins(self, *margins: int) -> None:
        del margins

    def setSpacing(self, spacing: int) -> None:
        del spacing

    def addWidget(self, widget: _CheckBoxStub) -> None:
        self.widgets.append(widget)

    def addStretch(self, stretch: int) -> None:
        del stretch


class _CheckBoxStub:
    def __init__(self, text: str, *args: object, **kwargs: object) -> None:
        del args, kwargs
        self.text = text
        self._checked = False
        self._blocked = False
        self.toggled = _SignalStub()

    def setChecked(self, checked: bool) -> None:
        changed = self._checked != checked
        self._checked = checked
        if changed and not self._blocked:
            self.toggled.emit(checked)

    def isChecked(self) -> bool:
        return self._checked

    def blockSignals(self, blocked: bool) -> None:
        self._blocked = blocked


class _ScrollAreaStub:
    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        self._widget: _WidgetStub | None = None
        self.minimum_height: int | None = None
        self.maximum_height: int | None = None

    def setWidgetResizable(self, resizable: bool) -> None:
        assert resizable is True

    def setWidget(self, widget: _WidgetStub) -> None:
        self._widget = widget

    def widget(self) -> _WidgetStub:
        assert self._widget is not None
        return self._widget

    def setMinimumHeight(self, height: int) -> None:
        self.minimum_height = height

    def setMaximumHeight(self, height: int) -> None:
        self.maximum_height = height

    def blockSignals(self, blocked: bool) -> bool:
        del blocked
        return False


def _compiled_project_editor_method(name: str):
    class_node = ast.ClassDef(
        name="ProjectEditorHarness",
        bases=[],
        keywords=[],
        body=[copy.deepcopy(_project_editor_method(name))],
        decorator_list=[],
    )
    module = ast.fix_missing_locations(ast.Module(body=[class_node], type_ignores=[]))
    namespace = {
        "FieldControlKind": FieldControlKind,
        "FieldEditorSpec": FieldEditorSpec,
        "CheckableChoiceListWidget": _compiled_checkable_choice_list_widget(),
        "QtWidgets": types.SimpleNamespace(
            QCheckBox=_CheckBoxStub,
            QScrollArea=_ScrollAreaStub,
            QVBoxLayout=_VBoxLayoutStub,
            QWidget=_WidgetStub,
        ),
        "typing": typing,
    }
    exec(compile(module, filename=str(PROJECT_EDITOR), mode="exec"), namespace)
    return getattr(namespace["ProjectEditorHarness"], name)


def _compiled_checkable_choice_list_widget():
    class _ChoiceList(_ScrollAreaStub):
        def __init__(self, choices, selected, callback):
            super().__init__()
            self._choices = tuple(choices)
            self._selected = set(selected)
            self._callback = callback
            self._boxes = {
                choice: _CheckBoxStub(choice) for choice in self._choices
            }
            for choice, box in self._boxes.items():
                box.setChecked(choice in self._selected)
                box.toggled.connect(
                    lambda checked, choice=choice: self._changed(choice, checked)
                )
            self.setMinimumHeight(24 + (len(self._choices) * 20))
            self.setMaximumHeight(24 + (len(self._choices) * 20))

        def choices(self):
            return self._choices

        def _changed(self, choice, checked):
            previous = set(self._selected)
            if checked:
                self._selected.add(choice)
            else:
                self._selected.discard(choice)
            if not self._callback(self.selected_choices()):
                self._selected = previous
                self._boxes[choice].blockSignals(True)
                self._boxes[choice].setChecked(choice in previous)
                self._boxes[choice].blockSignals(False)

        def selected_choices(self):
            return tuple(choice for choice in self._choices if choice in self._selected)

        def checkbox_for(self, choice):
            return self._boxes.get(choice)

    return _ChoiceList


def test_choice_backed_string_lists_emit_checkable_values_in_declared_order() -> None:
    field = FieldEditorSpec(
        field_id="stage.maturities",
        label="Stage maturities",
        path=("stage", "maturities"),
        control=FieldControlKind.STRING_LIST,
        choices=("CANONICAL", "GLOBAL_ANALYZED", "STRUCTURED"),
        default=["CANONICAL"],
    )
    calls: list[tuple[int, object, object]] = []
    panel = SimpleNamespace(
        _current_inspector=lambda: SimpleNamespace(pass_index=4),
        _apply_typed_option_at=lambda pass_index, selected_field, value: (
            calls.append((pass_index, selected_field, value)) or True
        ),
    )

    control = _compiled_project_editor_method("_typed_option_control")(
        panel,
        field,
        ["STRUCTURED", "CANONICAL"],
    )

    assert control.choices() == (
        "CANONICAL",
        "GLOBAL_ANALYZED",
        "STRUCTURED",
    )
    boxes = [control.checkbox_for(choice) for choice in control.choices()]
    assert [box.isChecked() for box in boxes] == [True, False, True]
    assert control.minimum_height == 84
    assert control.maximum_height == 84

    boxes[1].setChecked(True)
    assert calls[-1] == (
        4,
        field,
        ["CANONICAL", "GLOBAL_ANALYZED", "STRUCTURED"],
    )

    boxes[0].setChecked(False)
    assert calls[-1] == (4, field, ["GLOBAL_ANALYZED", "STRUCTURED"])
