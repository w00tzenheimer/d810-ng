from __future__ import annotations

import ast
import copy
import importlib.util
import sys
import types
from pathlib import Path

PANEL = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "d810"
    / "ui"
    / "config_v2_editing_panel.py"
)


def _tree() -> ast.Module:
    return ast.parse(PANEL.read_text(encoding="utf-8"), filename=str(PANEL))


def _method(name: str) -> ast.FunctionDef:
    for node in ast.walk(_tree()):
        if isinstance(node, ast.ClassDef) and node.name == "ConfigV2EditingPanel":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    raise AssertionError(f"ConfigV2EditingPanel.{name} not found")


def _calls(method: ast.FunctionDef) -> set[str]:
    return {
        node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, (ast.Attribute, ast.Name))
    }


def _source(name: str) -> str:
    return ast.unparse(_method(name))


def _string_arguments(name: str, call_name: str) -> list[str]:
    values: list[str] = []
    for node in ast.walk(_method(name)):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != call_name or not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            values.append(first.value)
    return values


def test_panel_projects_one_draft_into_a_stacked_builder_and_inspector() -> None:
    init_source = _source("__init__")
    create_source = _source("OnCreate")
    render_calls = _calls(_method("_render"))

    assert "ConfigV2EditorScreen.BUILDER" in init_source
    assert "self._screen = screen" in init_source
    assert "self._selected_pass_index" in init_source
    assert "self._editor_view" in init_source
    assert "QStackedWidget" in init_source
    assert "builder_page" in create_source
    assert "inspector_page" in create_source
    assert "project_config_v2_editor_view" in render_calls


def test_inspector_shell_is_capability_driven_and_contract_is_on_demand() -> None:
    create_source = _source("OnCreate")
    render_source = _source("_render_inspector")

    assert "ConfigV2InspectorPrimarySection" in PANEL.read_text(encoding="utf-8")
    assert "inspector.layout" in render_source
    assert "setVisible(layout.show_rule_catalog)" in render_source
    assert "setVisible(layout.show_transform_catalog)" in render_source
    assert "setVisible(layout.show_options)" in render_source
    assert "RawJsonDialog" in _source("_show_raw_contract")
    assert "JsonTreeEditor" not in create_source
    assert "No individually selectable transforms." not in create_source
    assert "No individually selectable rules." not in create_source


def test_inspector_header_separates_full_width_identity_from_compact_actions() -> None:
    init_source = _source("__init__")
    create_source = _source("OnCreate")

    assert "self.pass_title_label = QtWidgets.QLabel()" in init_source
    assert "self.pass_title_label.setWordWrap(False)" in init_source
    assert "self.pass_purpose_label = QtWidgets.QLabel()" in init_source
    assert "self.pass_purpose_label.setWordWrap(True)" in init_source
    assert "inspector_header_layout.addWidget(self.pass_title_label)" in create_source
    assert "inspector_header_layout.addWidget(self.pass_purpose_label)" in create_source
    assert (
        "inspector_action_layout.addWidget(self.pass_title_label)" not in create_source
    )
    assert (
        "inspector_action_layout.addWidget(self.pass_purpose_label)"
        not in create_source
    )
    assert "inspector_identity_label" not in init_source
    assert "inspector_identity_strip" not in create_source


def test_builder_description_is_a_compact_preview_with_the_full_text_on_hover() -> None:
    init_source = _source("__init__")
    render_source = _source("_render")

    assert "self.description_label.setWordWrap(False)" in init_source
    assert "self.description_label.setMinimumWidth(0)" in init_source
    assert "project_description_preview(self._view.description)" in render_source
    assert "setToolTip(self._view.description or 'No description')" in render_source


def test_inspector_actions_use_pipeline_details_and_on_demand_contract() -> None:
    source = PANEL.read_text(encoding="utf-8")
    init_source = _source("__init__")
    create_source = _source("OnCreate")

    assert "self.pipeline_button = QtWidgets.QToolButton()" in init_source
    assert "Pipeline" in _string_arguments("__init__", "setText")
    assert "self.pipeline_button.clicked.connect(self._show_builder)" in init_source
    assert "self.details_toggle = QtWidgets.QToolButton()" in init_source
    assert "Details" in _string_arguments("__init__", "setText")
    assert "self.raw_contract_button" in create_source
    assert "RawJsonDialog" in _source("_show_raw_contract")
    assert "JsonTreeEditor" not in create_source
    assert "Edit pipeline..." not in source
    assert "edit_pipeline_button" not in source


def test_details_disclosure_is_collapsed_readonly_contract_metadata() -> None:
    init_source = _source("__init__")
    create_source = _source("OnCreate")
    render_source = _source("_render_inspector")

    assert "self.details_toggle.setCheckable(True)" in init_source
    assert "self.details_toggle.setChecked(False)" in init_source
    assert (
        "self.details_toggle.toggled.connect(self._set_details_expanded)" in init_source
    )
    assert "self.details_body" in init_source
    assert "QFormLayout(self.details_body)" in create_source
    assert "registered pass contract" in init_source
    assert "cannot be changed in a project" in init_source
    for name in ("Scope", "Backend", "Safety"):
        assert name in create_source
    assert "self.details_toggle.setChecked" not in render_source
    assert (
        "self.details_body.setVisible(self.details_toggle.isChecked())" in render_source
    )
    assert "self.inspector_actions.setVisible(False)" in render_source
    assert "self.details_body.setVisible(False)" in render_source


def test_inspector_details_and_typed_options_use_the_compact_form_policy() -> None:
    init_source = _source("__init__")
    create_source = _source("OnCreate")

    assert "configure_left_aligned_form(self.typed_options_layout)" in init_source
    assert "self.typed_options_layout.setContentsMargins(0, 0, 0, 0)" in init_source
    assert "configure_left_aligned_form(details_layout)" in create_source
    assert "details_layout.setContentsMargins(0, 0, 0, 0)" in create_source
    assert "inspector_layout.setSpacing(4)" in create_source
    assert "layout.setSpacing(4)" in create_source


def test_screen_transition_checks_stack_membership_before_switching() -> None:
    source = _source("_set_current_screen")

    assert "self.screen_stack.indexOf(page) < 0" in source
    assert "Config-v2 editor screen is not attached" in source
    assert source.index("self.screen_stack.indexOf(page)") < source.index(
        "self.screen_stack.setCurrentWidget(page)"
    )
    assert "self._set_current_screen()" in _source("_render")


def test_inspector_primary_region_or_elastic_sink_owns_available_height() -> None:
    create_source = _source("OnCreate")
    render_source = _source("_render_inspector")

    assert "self._set_primary_workspace(layout.primary_section)" in render_source
    assert (
        render_source.count(
            "self._set_primary_workspace(ConfigV2InspectorPrimarySection.NONE)"
        )
        == 2
    )
    assert "self.inspector_elastic_sink" in create_source
    assert "self.options_group.setVisible(layout.show_options)" in render_source
    assert (
        "self.summary_message_label.setVisible(layout.show_summary_message)"
        in render_source
    )


def test_inspector_transform_catalog_is_projection_driven_and_fail_closed() -> None:
    render_source = _source("_render_inspector")

    assert "inspector.transform_catalog" in render_source
    assert "self.transform_catalog_widget.set_catalog(None)" in render_source
    assert "stage_ids" not in render_source
    assert "transform_ids" not in render_source


def test_inspector_rule_catalog_uses_the_typed_projection_and_closed_adapter_write() -> None:
    render_source = _source("_render_inspector")
    callback_source = _source("_apply_rule_catalog_selection")

    assert "inspector.rule_catalog" in render_source
    assert "self.rule_catalog_widget.set_catalog(None)" in render_source
    assert "project_rule_catalog" in render_source
    assert "apply_rule_catalog_selection" in callback_source
    assert "apply_rule_catalog_selection_to_options" in callback_source
    assert "set_pass_options" in callback_source


def test_typed_option_controls_keep_experimental_and_advisory_metadata_visible() -> None:
    source = _source("_render_typed_options")

    assert "Experimental:" in source
    assert "Advisory:" in source
    assert "field.experimental_reason" in source
    assert "field.advisory_reason" in source
    assert "transform_option_fields" in source


def test_checkable_items_combine_flags_through_qt_compatibility() -> None:
    source = PANEL.read_text(encoding="utf-8")

    assert source.count("qt_flag_or(item.flags(), _checkable_flag())") == 1
    assert (
        "qt_flag_or(family_item.flags(), _checkable_flag())" in source
    )
    assert "flags() | _checkable_flag()" not in source


def test_inspector_callbacks_delegate_closed_typed_edits_and_rerender_rejections() -> None:
    transform_source = _source("_apply_transform_catalog_selection")
    options_source = _source("_apply_typed_option")
    apply_source = _source("_apply_edit")

    assert "set_pass_transforms" in transform_source
    assert "apply_transform_catalog_selection" in transform_source
    assert "set_pass_options" in options_source
    assert "apply_typed_field_option" in options_source
    assert "self._render()" in apply_source


def test_screen_switches_preserve_the_current_draft_without_io() -> None:
    for method_name in ("_show_inspector", "_show_builder"):
        source = _source(method_name)
        calls = _calls(_method(method_name))

        assert "self._draft =" not in source
        assert not {"reset", "save", "load_view"} & calls
        assert "_render" in calls


def test_exact_focus_uses_the_requested_row_and_rejects_mismatches() -> None:
    source = _source("_apply_focus_target")

    assert "target.unambiguous" in source
    assert "target.pass_index" in source
    assert "inspector.pass_index" in source
    assert "inspector.pass_id == target.pass_id" in source
    assert "self._selected_pass_index = target.pass_index" in source


def test_panel_remains_a_thin_adapter_and_explicit_save_surface() -> None:
    imports = {
        node.module
        for node in ast.walk(_tree())
        if isinstance(node, ast.ImportFrom) and node.module
    }
    calls = set().union(
        *(
            _calls(_method(name))
            for name in (
                "_edit_description",
                "_add_pass",
                "_remove_pass",
                "_move_pass",
                "_apply_routing_rows",
                "_discard_unsaved",
                "_validate",
                "_save_as",
                "_save",
            )
        )
    )

    assert "d810.ui.config_v2_editing_logic" in imports
    assert "d810.manager.config_v2_editing" not in imports
    assert "d810.core.project_config_persistence" not in imports
    assert {"retarget", "save", "validate"}.issubset(calls)


def test_builder_is_a_compact_ordered_active_pass_editor() -> None:
    source = PANEL.read_text(encoding="utf-8")
    init_source = _source("__init__")
    create_source = _source("OnCreate")
    description_source = _source("_edit_description")
    add_source = _source("_add_pass")

    assert "self.pipeline_list" in init_source
    assert "row.index + 1" in _source("_render")
    for label in (
        "Add pass...",
        "Remove",
        "Move up",
        "Move down",
        "Open in editor...",
        "Edit description...",
    ):
        assert label in source
    assert "getMultiLineText" in description_source
    assert "set_description" in description_source
    assert "QLineEdit" in add_source
    assert "self._catalog" in add_source
    assert "manifest_list" not in create_source
    assert "complete_document" not in create_source
    assert "unsupported_document" not in create_source
    assert "catalog_combo" not in init_source
    assert "description_edit" not in init_source


def test_routing_group_exposes_structured_registered_family_controls() -> None:
    source = PANEL.read_text(encoding="utf-8")
    controls_source = _source("_build_routing_controls")
    apply_source = _source("_apply_routing_rows")
    render_source = _source("_render_routing")

    assert "registered_families" in source
    assert "setCheckable(True)" in controls_source
    assert "setChecked(False)" in controls_source
    assert "QDoubleSpinBox" in controls_source
    assert "Auto" in controls_source
    assert "Require" in controls_source
    assert "Prefer" in controls_source
    assert "Exclude" in controls_source
    assert "Automatic" in controls_source
    assert "set_routing_override" in apply_source
    assert "prefer=prefer" in apply_source
    assert "require=require" in apply_source
    assert "deny=deny" in apply_source
    assert "Auto routing" in render_source
    assert "Routing override" in render_source
    assert "routing_view" not in source


def test_raw_document_starts_readonly_and_all_edits_use_replace_document() -> None:
    show_source = _source("_show_raw_document")
    apply_source = _source("_apply_raw_document")

    assert show_source.count("JsonTreeEditor") >= 2
    assert show_source.count("editable=False") >= 2
    assert "Structured document" in show_source
    assert "Preserved fields" in show_source
    assert "Edit raw" in show_source
    assert "Open structured JSON..." in show_source
    assert (
        "Only declared config-v2 fields may change; all edits are fully validated before save."
        in show_source
    )
    assert "editable=True" in show_source
    assert "RawJsonDialog" in show_source
    assert "on_apply=self._apply_raw_document" in show_source
    assert "replace_document" in apply_source
    assert "set_description" not in apply_source
    assert "set_pass_options" not in apply_source


def test_footer_has_only_compact_status_overflow_and_save_controls() -> None:
    source = PANEL.read_text(encoding="utf-8")
    footer_source = _source("_build_footer")
    render_source = _source("_render_footer")
    overflow = _string_arguments("_build_footer", "addAction")

    assert overflow == [
        "Validate",
        "Discard unsaved",
        "Save as new...",
        "View raw",
        "Developer help",
    ]
    assert _string_arguments("_build_footer", "QPushButton") == ["Save"]
    assert "QToolButton()" in footer_source
    assert "..." in _string_arguments("_build_footer", "setText")
    assert "Clean" in render_source
    assert "Unsaved changes" in render_source
    assert "Ready" in render_source
    assert "Blocked" in render_source
    assert "Validate before saving" in render_source
    assert "QLabel" in _source("__init__")
    assert "status_detail" not in source
    assert "Reset draft" not in source
    assert "Save atomically and reload" not in source
    assert "QPlainTextEdit" not in _source("__init__")


def test_project_editor_footer_uses_the_configuration_overflow_policy() -> None:
    footer_source = _source("_build_footer")

    assert (
        "configure_overflow_menu_button(self.footer_overflow_button)"
        in footer_source
    )


def test_serializer_manifest_is_available_only_from_developer_help() -> None:
    source = PANEL.read_text(encoding="utf-8")
    help_source = _source("_show_developer_help")

    assert source.count("Serializer manifest") == 1
    assert "Serializer manifest" in help_source
    assert "project_serializer_rows" in help_source


class _BehaviorSignal:
    def __init__(self) -> None:
        self._callbacks: list[object] = []

    def connect(self, callback: object) -> None:
        self._callbacks.append(callback)

    def emit(self, *args: object) -> None:
        for callback in tuple(self._callbacks):
            callback(*args)


class _BehaviorWidget:
    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        self._visible = True
        self._enabled = True
        self._text = ""
        self.clicked = _BehaviorSignal()
        self.toggled = _BehaviorSignal()
        self.textChanged = _BehaviorSignal()

    def setVisible(self, visible: bool) -> None:
        self._visible = bool(visible)

    def isVisible(self) -> bool:
        return self._visible

    def setEnabled(self, enabled: bool) -> None:
        self._enabled = bool(enabled)

    def isEnabled(self) -> bool:
        return self._enabled

    def setText(self, text: str) -> None:
        self._text = str(text)

    def text(self) -> str:
        return self._text

    def setToolTip(self, tooltip: str) -> None:
        del tooltip

    def setContentsMargins(self, *args: object) -> None:
        del args

    def setSpacing(self, spacing: int) -> None:
        del spacing

    def setWindowTitle(self, title: str) -> None:
        self._text = title


class _BehaviorLayout(_BehaviorWidget):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.children: list[object] = []
        self.stretches: dict[int, int] = {}
        self.stretch_calls: list[tuple[int, int]] = []

    def addWidget(self, widget: object, **kwargs: object) -> None:
        self.children.append(widget)
        if "stretch" in kwargs:
            self.stretches[len(self.children) - 1] = int(kwargs["stretch"])

    def addLayout(self, layout: object) -> None:
        self.children.append(layout)

    def addStretch(self, *args: object) -> None:
        del args

    def indexOf(self, widget: object) -> int:
        try:
            return self.children.index(widget)
        except ValueError:
            return -1

    def setStretch(self, index: int, stretch: int) -> None:
        value = (int(index), int(stretch))
        self.stretch_calls.append(value)
        self.stretches[value[0]] = value[1]


class _BehaviorStackedWidget(_BehaviorWidget):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.pages: list[object] = []
        self._current: object | None = None
        self.set_current_calls: list[object] = []

    def addWidget(self, widget: object) -> None:
        self.pages.append(widget)
        if self._current is None:
            self._current = widget

    def setCurrentWidget(self, widget: object) -> None:
        self.set_current_calls.append(widget)
        assert widget in self.pages
        self._current = widget

    def indexOf(self, widget: object) -> int:
        try:
            return self.pages.index(widget)
        except ValueError:
            return -1

    def currentWidget(self) -> object | None:
        return self._current


class _BehaviorGroupBox(_BehaviorWidget):
    def __init__(self, title: str = "", *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._text = title
        self._checked = False

    def setCheckable(self, checkable: bool) -> None:
        self._checkable = bool(checkable)

    def setChecked(self, checked: bool) -> None:
        changed = self._checked != bool(checked)
        self._checked = bool(checked)
        if changed:
            self.toggled.emit(self._checked)

    def isChecked(self) -> bool:
        return self._checked

    def setTitle(self, title: str) -> None:
        self._text = title


class _BehaviorCheckBox(_BehaviorGroupBox):
    pass


class _BehaviorComboBox(_BehaviorWidget):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._items: list[tuple[str, object]] = []
        self._index = -1

    def addItem(self, label: str, value: object = None) -> None:
        self._items.append((label, value))
        if self._index < 0:
            self._index = 0

    def currentData(self) -> object:
        return self._items[self._index][1] if self._index >= 0 else None

    def findData(self, value: object) -> int:
        return next(
            (
                index
                for index, (_, item_value) in enumerate(self._items)
                if item_value == value
            ),
            -1,
        )

    def setCurrentIndex(self, index: int) -> None:
        self._index = int(index)


class _BehaviorListItem:
    def __init__(self, text: str = "") -> None:
        self._text = text
        self._data: dict[object, object] = {}
        self._checked = 0

    def flags(self) -> int:
        return 0

    def setFlags(self, flags: int) -> None:
        del flags

    def setCheckState(self, checked: int) -> None:
        self._checked = checked

    def checkState(self) -> int:
        return self._checked

    def setData(self, role: object, value: object) -> None:
        self._data[role] = value

    def data(self, role: object) -> object:
        return self._data.get(role)

    def text(self) -> str:
        return self._text


class _BehaviorListWidget(_BehaviorWidget):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._items: list[_BehaviorListItem] = []
        self._row = -1

    def addItem(self, item: _BehaviorListItem) -> None:
        self._items.append(item)

    def count(self) -> int:
        return len(self._items)

    def item(self, index: int) -> _BehaviorListItem:
        return self._items[index]

    def clear(self) -> None:
        self._items.clear()
        self._row = -1

    def setCurrentRow(self, row: int) -> None:
        self._row = row

    def currentItem(self) -> _BehaviorListItem | None:
        return self._items[self._row] if 0 <= self._row < len(self._items) else None


class _BehaviorTableWidget(_BehaviorWidget):
    def __init__(
        self, rows: int, columns: int, *args: object, **kwargs: object
    ) -> None:
        super().__init__(*args, **kwargs)
        self.rows = rows
        self.columns = columns
        self.items: dict[tuple[int, int], object] = {}
        self.widgets: dict[tuple[int, int], object] = {}

    def setHorizontalHeaderLabels(self, labels: list[str]) -> None:
        self.labels = labels

    def setItem(self, row: int, column: int, item: object) -> None:
        self.items[(row, column)] = item

    def setCellWidget(self, row: int, column: int, widget: object) -> None:
        self.widgets[(row, column)] = widget


class _BehaviorSpinBox(_BehaviorWidget):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._value = 0.0

    def setRange(self, minimum: float, maximum: float) -> None:
        self.minimum = minimum
        self.maximum = maximum

    def setDecimals(self, decimals: int) -> None:
        self.decimals = decimals

    def setValue(self, value: float) -> None:
        self._value = float(value)

    def value(self) -> float:
        return self._value


class _BehaviorButton(_BehaviorWidget):
    instances: list["_BehaviorButton"] = []

    def __init__(self, text: str = "", *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._text = text
        self.instances.append(self)

    def click(self) -> None:
        self.clicked.emit()


class _BehaviorDialog(_BehaviorWidget):
    Accepted = 1
    next_exec: object | None = None

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._result = 0

    def accept(self) -> None:
        self._result = self.Accepted

    def reject(self) -> None:
        self._result = 0

    def exec_(self) -> int:
        callback = _BehaviorDialog.next_exec
        if callback is not None:
            callback(self)
        return self._result


class _BehaviorTabs(_BehaviorWidget):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.tabs: list[tuple[object, str]] = []

    def addTab(self, widget: object, label: str) -> None:
        self.tabs.append((widget, label))


class _BehaviorTree:
    instances: list["_BehaviorTree"] = []

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        self.history: list[tuple[object, bool]] = []
        self.callback: object | None = None
        self.instances.append(self)

    def set_json(self, value: object, *, editable: bool) -> None:
        self.history.append((copy.deepcopy(value), editable))

    def set_on_value_changed(self, callback: object) -> None:
        self.callback = callback


class _BehaviorRawDialog(_BehaviorDialog):
    instances: list["_BehaviorRawDialog"] = []

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__()
        self.args = args
        self.kwargs = kwargs
        self.instances.append(self)


class _BehaviorMessageBox:
    class StandardButton:
        Yes = 1
        No = 2
        Discard = 4
        Cancel = 8

    Yes = StandardButton.Yes
    No = StandardButton.No
    Discard = StandardButton.Discard
    Cancel = StandardButton.Cancel
    response = No
    questions: list[tuple[object, ...]] = []

    @classmethod
    def question(cls, *args: object) -> int:
        cls.questions.append(args)
        return cls.response

    @classmethod
    def information(cls, *args: object) -> None:
        del args


class _BehaviorFileDialog:
    destination = ""

    @classmethod
    def getSaveFileName(cls, *args: object) -> tuple[str, str]:
        del args
        return cls.destination, ""


def _load_behavior_panel(monkeypatch):
    _BehaviorButton.instances = []
    _BehaviorDialog.next_exec = None
    _BehaviorTree.instances = []
    _BehaviorRawDialog.instances = []
    _BehaviorMessageBox.questions = []
    _BehaviorMessageBox.response = _BehaviorMessageBox.No
    plugin_form = type("PluginForm", (), {"__init__": lambda self: None})
    qt = types.SimpleNamespace(
        Qt=types.SimpleNamespace(
            CheckState=types.SimpleNamespace(Checked=2, Unchecked=0),
            ItemDataRole=types.SimpleNamespace(UserRole=32),
            ItemFlag=types.SimpleNamespace(ItemIsUserCheckable=1),
        )
    )
    widgets = types.SimpleNamespace(
        QCheckBox=_BehaviorCheckBox,
        QComboBox=_BehaviorComboBox,
        QDialog=_BehaviorDialog,
        QDoubleSpinBox=_BehaviorSpinBox,
        QFileDialog=_BehaviorFileDialog,
        QGroupBox=_BehaviorGroupBox,
        QHBoxLayout=_BehaviorLayout,
        QLabel=_BehaviorWidget,
        QListWidget=_BehaviorListWidget,
        QListWidgetItem=_BehaviorListItem,
        QMessageBox=_BehaviorMessageBox,
        QPushButton=_BehaviorButton,
        QTableWidget=_BehaviorTableWidget,
        QTableWidgetItem=_BehaviorListItem,
        QTabWidget=_BehaviorTabs,
        QToolButton=_BehaviorButton,
        QStackedWidget=_BehaviorStackedWidget,
        QVBoxLayout=_BehaviorLayout,
        QWidget=_BehaviorWidget,
    )
    monkeypatch.setitem(
        sys.modules, "ida_kernwin", types.SimpleNamespace(PluginForm=plugin_form)
    )
    monkeypatch.setitem(
        sys.modules,
        "d810.qt_shim",
        types.SimpleNamespace(
            QtCore=qt,
            QtWidgets=widgets,
            qt_flag_or=lambda *flags: int(flags[0]) | int(flags[1]),
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "d810.ui.workbench_structured_details",
        types.SimpleNamespace(
            JsonTreeEditor=_BehaviorTree,
            RawJsonDialog=_BehaviorRawDialog,
            StructuredDetailsView=_BehaviorWidget,
        ),
    )
    module_name = "d810.ui._task6_behavior_panel"
    spec = importlib.util.spec_from_file_location(module_name, PANEL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    module.registered_families = lambda: (
        types.SimpleNamespace(name="approov"),
        types.SimpleNamespace(name="tigress"),
    )
    return module, module.ConfigV2EditingPanel


class _BehaviorAdapter:
    def __init__(self, *, reject_replace: bool = False) -> None:
        self.reject_replace = reject_replace
        self.clear_calls: list[object] = []
        self.routing_calls: list[
            tuple[object, dict[str, float], str | None, tuple[str, ...]]
        ] = []
        self.replace_calls: list[tuple[object, object]] = []
        self.reset_calls = 0
        self.retarget_calls: list[tuple[object, Path]] = []
        self.save_calls: list[tuple[object, object]] = []

    def clear_routing_override(self, draft: object) -> tuple[object, object]:
        self.clear_calls.append(draft)
        return draft, object()

    def set_routing_override(
        self,
        draft: object,
        *,
        prefer: dict[str, float],
        require: str | None,
        deny: tuple[str, ...],
    ) -> tuple[object, object]:
        self.routing_calls.append((draft, prefer, require, deny))
        return draft, object()

    def replace_document(
        self, draft: object, document: object
    ) -> tuple[object, object]:
        self.replace_calls.append((draft, copy.deepcopy(document)))
        if self.reject_replace:
            raise RuntimeError("rejected replacement")
        return draft, object()

    def reset(self) -> tuple[object, object]:
        self.reset_calls += 1
        return types.SimpleNamespace(), object()

    def retarget(self, draft: object, destination: Path) -> tuple[object, object]:
        self.retarget_calls.append((draft, destination))
        return draft, object()

    def save(self, draft: object, validation: object) -> object:
        self.save_calls.append((draft, validation))
        return types.SimpleNamespace(path=Path("/tmp/saved.json"))

    @property
    def destination(self) -> Path:
        return Path("/tmp/config.json")


def _behavior_panel(panel_type, adapter: _BehaviorAdapter, document: dict[str, object]):
    panel = object.__new__(panel_type)
    panel.parent = None
    panel._adapter = adapter
    panel._on_saved = None
    panel._draft = types.SimpleNamespace(document_json="not JSON")
    panel._validation = object()
    panel._editor_view = types.SimpleNamespace(
        raw_document=types.SimpleNamespace(
            document=copy.deepcopy(document),
            preserved_fields={"unsupported": copy.deepcopy(document["unsupported"])},
        ),
        footer=types.SimpleNamespace(dirty=True),
    )
    panel._raw_document_tree = None
    panel._raw_preserved_tree = None
    panel._raw_document_editable = False
    panel.statuses: list[str] = []
    panel._set_status = panel.statuses.append
    panel._render = panel._render_raw_document_trees
    return panel


def _behavior_document() -> dict[str, object]:
    return {
        "description": "before",
        "unsupported": {"audit": "preserve me"},
        "additional_configuration": {
            "pipeline_v2": [{"pass_id": "mba-simplify", "options": {}}],
            "router_resolution": {"prefer": {}, "require": None, "deny": []},
            "unrelated": {"must": "stay"},
        },
    }


def test_inspector_stretch_routes_each_primary_section_to_the_elastic_owner(
    monkeypatch,
) -> None:
    module, panel_type = _load_behavior_panel(monkeypatch)
    panel = object.__new__(panel_type)
    panel.primary_workspace = _BehaviorStackedWidget()
    panel.rules_group = _BehaviorWidget()
    panel.transforms_group = _BehaviorWidget()
    panel.primary_workspace.addWidget(panel.transforms_group)
    panel.primary_workspace.addWidget(panel.rules_group)
    panel.options_group = _BehaviorWidget()
    panel.inspector_elastic_sink = _BehaviorWidget()
    panel._inspector_layout = _BehaviorLayout()
    panel._inspector_layout.addWidget(panel.primary_workspace, stretch=1)
    panel._inspector_layout.addWidget(panel.options_group, stretch=0)
    panel._inspector_layout.addWidget(panel.inspector_elastic_sink, stretch=0)

    for primary, page in (
        (module.ConfigV2InspectorPrimarySection.RULES, panel.rules_group),
        (
            module.ConfigV2InspectorPrimarySection.TRANSFORMS,
            panel.transforms_group,
        ),
    ):
        panel._inspector_layout.stretch_calls.clear()
        panel._set_primary_workspace(primary)

        assert panel.primary_workspace.isVisible() is True
        assert panel.primary_workspace.currentWidget() is page
        assert panel.inspector_elastic_sink.isVisible() is False
        assert panel._inspector_layout.stretch_calls == [(0, 1), (1, 0), (2, 0)]

    panel._inspector_layout.stretch_calls.clear()
    panel._set_primary_workspace(module.ConfigV2InspectorPrimarySection.OPTIONS)

    assert panel.primary_workspace.isVisible() is False
    assert panel.inspector_elastic_sink.isVisible() is False
    assert panel._inspector_layout.stretch_calls == [(0, 0), (1, 1), (2, 0)]

    panel._inspector_layout.stretch_calls.clear()
    panel._set_primary_workspace(module.ConfigV2InspectorPrimarySection.NONE)

    assert panel.primary_workspace.isVisible() is False
    assert panel.inspector_elastic_sink.isVisible() is True
    assert panel._inspector_layout.stretch_calls == [(0, 0), (1, 0), (2, 1)]


def test_missing_primary_workspace_page_is_a_logged_noop(
    monkeypatch,
) -> None:
    module, panel_type = _load_behavior_panel(monkeypatch)
    panel = object.__new__(panel_type)
    panel.primary_workspace = _BehaviorStackedWidget()
    panel.rules_group = _BehaviorWidget()
    panel.transforms_group = _BehaviorWidget()
    panel.inspector_elastic_sink = _BehaviorWidget()
    panel._inspector_layout = None
    warnings: list[tuple[str, tuple[object, ...]]] = []
    monkeypatch.setattr(
        module.logger,
        "warning",
        lambda message, *args: warnings.append((message, args)),
    )

    primary = module.ConfigV2InspectorPrimarySection.RULES
    panel._set_primary_workspace(primary)

    assert panel.primary_workspace.set_current_calls == []
    assert warnings == [
        (
            "Config-v2 editor primary workspace is not attached: %r",
            (primary,),
        )
    ]


def test_missing_screen_page_is_a_logged_noop_without_qt_transition(
    monkeypatch,
) -> None:
    module, panel_type = _load_behavior_panel(monkeypatch)
    panel = object.__new__(panel_type)
    panel._screen = module.ConfigV2EditorScreen.INSPECTOR
    panel.screen_stack = _BehaviorStackedWidget()
    panel.builder_page = _BehaviorWidget()
    panel.inspector_page = _BehaviorWidget()
    panel.screen_stack.addWidget(panel.builder_page)
    panel.screen_stack.indexOf = lambda widget: -1

    panel._set_current_screen()

    assert panel.screen_stack.set_current_calls == []


def test_routing_group_body_visibility_tracks_expansion(monkeypatch) -> None:
    _, panel_type = _load_behavior_panel(monkeypatch)
    panel = object.__new__(panel_type)
    panel.parent = None
    panel._build_routing_controls()

    assert panel.routing_body.isVisible() is False
    panel.routing_group.setChecked(True)
    assert panel.routing_body.isVisible() is True
    panel.routing_group.setChecked(False)
    assert panel.routing_body.isVisible() is False


def test_auto_routing_uses_typed_clear_and_structured_rows_send_payload(
    monkeypatch,
) -> None:
    module, panel_type = _load_behavior_panel(monkeypatch)
    adapter = _BehaviorAdapter()
    panel = _behavior_panel(panel_type, adapter, _behavior_document())
    panel.routing_auto_check = _BehaviorCheckBox("Auto")
    panel.routing_auto_check.setChecked(True)

    panel._apply_routing_rows()

    assert adapter.clear_calls == [panel._draft]
    assert adapter.replace_calls == []

    panel.routing_auto_check.setChecked(False)
    prefer_item = _BehaviorListItem("approov")
    prefer_item.setCheckState(module._checked_state())
    panel.routing_prefer_rows = {
        "approov": (prefer_item, _BehaviorSpinBox()),
        "tigress": (_BehaviorListItem("tigress"), _BehaviorSpinBox()),
    }
    panel.routing_prefer_rows["approov"][1].setValue(2.5)
    panel.routing_require_combo = _BehaviorComboBox()
    panel.routing_require_combo.addItem("Automatic", None)
    panel.routing_require_combo.addItem("approov", "approov")
    panel.routing_require_combo.setCurrentIndex(1)
    panel.routing_exclude_list = _BehaviorListWidget()
    excluded = _BehaviorListItem("tigress")
    excluded.setData(module._user_role(), "tigress")
    excluded.setCheckState(module._checked_state())
    panel.routing_exclude_list.addItem(excluded)

    panel._apply_routing_rows()

    assert adapter.routing_calls == [
        (panel._draft, {"approov": 2.5}, "approov", ("tigress",))
    ]


def test_structured_raw_surface_excludes_preserved_fields_and_rejects_them(
    monkeypatch,
) -> None:
    _, panel_type = _load_behavior_panel(monkeypatch)
    adapter = _BehaviorAdapter()
    document = _behavior_document()
    panel = _behavior_panel(panel_type, adapter, document)
    panel._raw_document_tree = _BehaviorTree()
    panel._raw_preserved_tree = _BehaviorTree()
    panel._raw_document_editable = True

    panel._render_raw_document_trees()

    structured, editable = panel._raw_document_tree.history[-1]
    preserved, preserved_editable = panel._raw_preserved_tree.history[-1]
    assert editable is True
    assert preserved_editable is False
    assert "unsupported" not in structured
    assert structured["additional_configuration"] == {
        "pipeline_v2": [{"pass_id": "mba-simplify", "options": {}}],
        "router_resolution": {"prefer": {}, "require": None, "deny": []},
    }
    assert preserved == {"unsupported": {"audit": "preserve me"}}

    structured["description"] = "after"
    panel._apply_raw_document(structured)

    assert adapter.replace_calls[-1][1]["description"] == "after"
    assert adapter.replace_calls[-1][1]["unsupported"] == {"audit": "preserve me"}
    panel._apply_raw_document({"unsupported": {"audit": "changed"}})
    assert len(adapter.replace_calls) == 1
    assert panel.statuses[-1] == "Only declared config-v2 fields may change."


def test_raw_warning_cancel_and_rejection_restore_authoritative_structured_tree(
    monkeypatch,
) -> None:
    module, panel_type = _load_behavior_panel(monkeypatch)
    document = _behavior_document()
    panel = _behavior_panel(panel_type, _BehaviorAdapter(), document)

    _BehaviorMessageBox.response = _BehaviorMessageBox.No
    _BehaviorDialog.next_exec = lambda dialog: next(
        button for button in _BehaviorButton.instances if button.text() == "Edit raw"
    ).click()
    panel._show_raw_document()

    cancelled_tree = _BehaviorTree.instances[0]
    assert cancelled_tree.history == [
        (
            {
                "description": "before",
                "additional_configuration": {
                    "pipeline_v2": [{"pass_id": "mba-simplify", "options": {}}],
                    "router_resolution": {"prefer": {}, "require": None, "deny": []},
                },
            },
            False,
        )
    ]

    module, panel_type = _load_behavior_panel(monkeypatch)
    panel = _behavior_panel(panel_type, _BehaviorAdapter(reject_replace=True), document)
    _BehaviorMessageBox.response = _BehaviorMessageBox.Yes

    def edit_then_reject(dialog: object) -> None:
        next(
            button
            for button in _BehaviorButton.instances
            if button.text() == "Edit raw"
        ).click()
        _BehaviorTree.instances[0].callback(
            {
                "description": "rejected",
                "additional_configuration": {
                    "pipeline_v2": [{"pass_id": "mba-simplify", "options": {}}],
                    "router_resolution": {"prefer": {}, "require": None, "deny": []},
                },
            }
        )

    _BehaviorDialog.next_exec = edit_then_reject
    panel._show_raw_document()

    restored_value, restored_editable = _BehaviorTree.instances[0].history[-1]
    assert restored_editable is True
    assert restored_value["description"] == "before"
    assert "unsupported" not in restored_value
    assert panel.statuses[-1] == "Edit failed: rejected replacement"


def test_discard_confirmation_and_save_as_do_not_save_current_destination(
    monkeypatch,
) -> None:
    _, panel_type = _load_behavior_panel(monkeypatch)
    adapter = _BehaviorAdapter()
    panel = _behavior_panel(panel_type, adapter, _behavior_document())

    _BehaviorMessageBox.response = _BehaviorMessageBox.Cancel
    panel._discard_unsaved()
    assert adapter.reset_calls == 0
    _BehaviorMessageBox.response = _BehaviorMessageBox.Discard
    panel._discard_unsaved()
    assert adapter.reset_calls == 1

    _BehaviorFileDialog.destination = "/tmp/retargeted.json"
    panel._save_as()
    assert [destination for _, destination in adapter.retarget_calls] == [
        Path("/tmp/retargeted.json")
    ]
    assert adapter.save_calls == []
    saving_draft = panel._draft
    saving_validation = panel._validation
    panel._save()
    assert adapter.save_calls == [(saving_draft, saving_validation)]
