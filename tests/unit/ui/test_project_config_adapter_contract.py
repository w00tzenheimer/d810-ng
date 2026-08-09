from __future__ import annotations

import ast
import importlib.util
import json
import sys
import types
from pathlib import Path

from d810.manager.config_v2_edit_models import (
    ConfigV2ProjectDraft,
    ConfigV2ProjectValidation,
)
from d810.core.pass_editor_spec import PassEditorSpec
from d810.manager.workbench_recipe_models import PassCatalogEntry
from d810.ui.config_v2_editing_logic import ConfigV2EditorScreen
from d810.ui.project_config_logic import resolve_config_v2_focus_target


IDA_UI = Path(__file__).resolve().parents[3] / "src" / "d810" / "ui" / "ida_ui.py"
ICON_DIR = IDA_UI.parent / "icons"
PASS_TREE = IDA_UI.parent / "pass_tree.py"
PIPELINE_OVERVIEW = IDA_UI.parent / "config_v2_pipeline_overview.py"
WORKBENCH_PANEL = IDA_UI.parent / "workbench_panel.py"
ICON_ASSETS = IDA_UI.parent / "icon_assets.py"
PYPROJECT = IDA_UI.parents[3] / "pyproject.toml"
TREE = ast.parse(IDA_UI.read_text(encoding="utf-8"), filename=str(IDA_UI))
WORKBENCH_TREE = ast.parse(
    WORKBENCH_PANEL.read_text(encoding="utf-8"),
    filename=str(WORKBENCH_PANEL),
)


def _method(name: str) -> ast.FunctionDef:
    for node in TREE.body:
        if isinstance(node, ast.ClassDef) and node.name == "D810ConfigForm_t":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    raise AssertionError(f"D810ConfigForm_t.{name} not found")


def _call_names(method: ast.FunctionDef) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(method):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            names.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            names.add(node.func.attr)
    return names


def _attribute_names(method: ast.FunctionDef) -> set[str]:
    return {node.attr for node in ast.walk(method) if isinstance(node, ast.Attribute)}


def _function(tree: ast.Module, name: str) -> ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"function {name} not found")


def _calls(method: ast.FunctionDef, name: str) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and (
            isinstance(node.func, ast.Name)
            and node.func.id == name
            or isinstance(node.func, ast.Attribute)
            and node.func.attr == name
        )
    ]


def _keyword(call: ast.Call, name: str) -> str | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return ast.unparse(keyword.value)
    return None


def test_load_config_reads_manager_snapshot_and_pure_view() -> None:
    calls = _call_names(_method("_load_config"))

    assert "get_project_runtime_snapshot" in calls
    assert "build_project_config_view" in calls
    assert "_apply_project_config_view" in calls


def test_form_uses_searchable_popup_without_loading_a_filtered_row_index() -> None:
    calls = _call_names(_method("_open_config_picker"))

    assert "ProjectPickerPopup" in calls
    assert "build_project_picker_entries" in calls
    assert "show_for" in calls
    assert "_load_config" in _attribute_names(_method("_open_config_picker"))


def test_current_configuration_control_has_a_dropdown_affordance() -> None:
    source = IDA_UI.read_text(encoding="utf-8")

    assert "▼" in source


def test_config_actions_use_icons_instead_of_unicode_glyphs() -> None:
    source = IDA_UI.read_text(encoding="utf-8")

    for button_name in (
        "btn_new_cfg",
        "btn_duplicate_cfg",
        "btn_edit_cfg",
        "btn_delele_cfg",
    ):
        assert f"{button_name}.setIcon(" in source
    for glyph in ("⧉", "✎", "🗑"):
        assert glyph not in source


def test_config_action_svg_assets_are_packaged() -> None:
    for icon_name in ("new", "duplicate", "edit", "delete"):
        icon_path = ICON_DIR / f"{icon_name}.svg"
        assert icon_path.is_file()
        assert "<svg" in icon_path.read_text(encoding="utf-8")

    assert "ui/icons/*.svg" in PYPROJECT.read_text(encoding="utf-8")


def test_engine_status_uses_svg_icons_instead_of_text_markers() -> None:
    source = IDA_UI.read_text(encoding="utf-8")
    update_status = ast.get_source_segment(source, _method("_update_status"))

    assert update_status is not None
    assert ".setPixmap(" in update_status
    assert "*>" not in update_status
    assert "●" not in source

    for icon_name in ("status-running", "status-stopped"):
        icon_path = ICON_DIR / f"{icon_name}.svg"
        assert icon_path.is_file()
        assert "<svg" in icon_path.read_text(encoding="utf-8")


def test_pass_tree_uses_public_identity_labels() -> None:
    source = PASS_TREE.read_text(encoding="utf-8")

    assert "*>" not in source
    assert "Pass / child" in source
    assert "Transform:" in source
    assert "Stage:" in source


def test_icon_assets_have_a_qpainter_fallback_for_pyqt5_svg_failures() -> None:
    assert ICON_ASSETS.is_file()

    source = ICON_ASSETS.read_text(encoding="utf-8")
    assert "QPainter" in source
    assert "QIcon(pixmap)" in source
    assert "isNull()" in source
    assert "bundled_icon" in IDA_UI.read_text(encoding="utf-8")


def test_project_view_loads_active_pipeline_through_adapter_and_projection() -> None:
    calls = _call_names(_method("_apply_project_config_view"))

    assert "config_v2_user_destination" in calls
    assert "ConfigV2EditingAdapter" in calls
    assert "load_view" in calls
    assert "catalog" in calls
    assert "project_config_v2_editor_view" in calls
    assert "set_overview" in calls
    assert "read_text" not in calls
    assert "open" not in calls


def test_form_replaces_the_ownership_tree_with_active_pipeline_overview() -> None:
    calls = _call_names(_method("OnCreate"))
    source = ast.get_source_segment(
        IDA_UI.read_text(encoding="utf-8"),
        _method("OnCreate"),
    )

    assert PIPELINE_OVERVIEW.is_file()
    assert "ConfigV2PipelineOverviewWidget" in calls
    assert source is not None
    assert "inspect_requested.connect(self._inspect_config_v2_pass)" in source
    assert "edit_pipeline_requested.connect(self._edit_config)" in source
    assert "PassTreeWidget" not in source
    assert "edit_requested.connect" not in source


def test_private_rule_editor_methods_are_removed() -> None:
    source = IDA_UI.read_text(encoding="utf-8")

    assert "def _save_rules" not in source
    assert "RuleTreeWidget" not in source
    assert "RuleDetailPanel" not in source


def test_edit_and_duplicate_handlers_use_the_pure_policy() -> None:
    assert "select_config_edit_policy" in _call_names(_method("_edit_config"))
    assert "select_config_edit_policy" in _call_names(_method("_duplicate_config"))
    assert "_open_config_v2_editor" in _call_names(_method("_edit_config"))
    assert "_open_config_v2_editor" in _call_names(_method("_duplicate_config"))

    for method_name in ("_edit_config", "_duplicate_config"):
        calls = _calls(_method(method_name), "_open_config_v2_editor")
        assert len(calls) == 1
        assert _keyword(calls[0], "screen") == "ConfigV2EditorScreen.BUILDER"


def test_active_pipeline_inspection_uses_an_exact_indexed_focus_target() -> None:
    method = _method("_inspect_config_v2_pass")
    source = ast.get_source_segment(IDA_UI.read_text(encoding="utf-8"), method)
    resolver_calls = _calls(method, "resolve_config_v2_focus_target")
    editor_calls = _calls(method, "_open_config_v2_editor")

    assert source is not None
    assert "self._config_v2_overview.rows" in source
    assert "rows[index]" in source
    assert len(resolver_calls) == 1
    assert _keyword(resolver_calls[0], "pass_index") == "index"
    assert len(editor_calls) == 1
    assert _keyword(editor_calls[0], "screen") == "ConfigV2EditorScreen.INSPECTOR"
    assert _keyword(editor_calls[0], "focus_target") == "focus_target"


def test_config_v2_destination_chooser_imports_pathlib_for_runtime_paths() -> None:
    imported_modules = {
        alias.name
        for node in TREE.body
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    chooser_source = ast.get_source_segment(
        IDA_UI.read_text(encoding="utf-8"),
        _method("_choose_config_v2_destination"),
    )

    assert chooser_source is not None
    assert "pathlib.Path(" in chooser_source
    assert "pathlib" in imported_modules


def test_config_v2_editor_is_owned_and_uses_thin_command_adapter() -> None:
    method = _method("_open_config_v2_editor")
    calls = _call_names(method)
    source = ast.get_source_segment(IDA_UI.read_text(encoding="utf-8"), method)

    assert "ConfigV2EditingAdapter" in calls
    assert "ConfigV2EditingPanel" in calls
    assert "show" in calls
    assert [argument.arg for argument in method.args.kwonlyargs] == [
        "screen",
        "focus_target",
    ]
    panel_calls = _calls(method, "ConfigV2EditingPanel")
    assert len(panel_calls) == 1
    assert _keyword(panel_calls[0], "screen") == "screen"
    assert source is not None
    assert source.index("editor = ConfigV2EditingPanel(") < source.index(
        "self._config_v2_editor.close()"
    )


def test_recipe_profile_opens_builder_before_closing_the_previous_editor() -> None:
    method = _function(WORKBENCH_TREE, "_open_recipe_project_profile")
    source = ast.get_source_segment(WORKBENCH_PANEL.read_text(encoding="utf-8"), method)
    panel_calls = _calls(method, "ConfigV2EditingPanel")

    assert len(panel_calls) == 1
    assert _keyword(panel_calls[0], "screen") == "ConfigV2EditorScreen.BUILDER"
    assert source is not None
    assert source.index("editor = ConfigV2EditingPanel(") < source.index(
        "self._config_v2_editor.close()"
    )


class _Signal:
    def connect(self, callback: object) -> None:
        del callback


class _Widget:
    class LineWrapMode:
        WidgetWidth = 1

    WidgetWidth = 1

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        self.clicked = _Signal()
        self.itemChanged = _Signal()
        self._row = -1
        self._items: list[object] = []
        self._text = ""

    def __getattr__(self, name: str):
        if name.startswith("set") or name in {
            "addLayout",
            "addStretch",
            "addTab",
            "addWidget",
            "expandAll",
        }:
            return lambda *args, **kwargs: None
        raise AttributeError(name)

    def addItem(self, *args: object) -> None:
        self._items.append(args[-1])

    def count(self) -> int:
        return len(self._items)

    def clear(self) -> None:
        self._items.clear()
        self._row = -1

    def currentData(self) -> object | None:
        return None

    def currentRow(self) -> int:
        return self._row

    def hasFocus(self) -> bool:
        return False

    def item(self, index: int) -> object:
        return self._items[index]

    def setCurrentRow(self, index: int) -> None:
        self._row = index

    def setPlainText(self, text: str) -> None:
        self._text = text

    def toPlainText(self) -> str:
        return self._text


class _ListItem:
    def __init__(self, text: str = "") -> None:
        self._text = text
        self._check_state = 0
        self._data: dict[object, object] = {}

    def checkState(self) -> int:
        return self._check_state

    def data(self, role: object) -> object | None:
        return self._data.get(role)

    def flags(self) -> int:
        return 0

    def setCheckState(self, state: int) -> None:
        self._check_state = state

    def setData(self, role: object, value: object) -> None:
        self._data[role] = value

    def setFlags(self, flags: int) -> None:
        del flags

    def setToolTip(self, tooltip: str) -> None:
        del tooltip

    def text(self) -> str:
        return self._text


class _JsonTreeEditor(_Widget):
    def set_json(self, value: object, *, editable: bool) -> None:
        self.value = value
        self.editable = editable

    def set_on_value_changed(self, callback: object) -> None:
        self.callback = callback


class _StructuredDetailsView(_Widget):
    def set_sections(self, sections: object) -> None:
        self.sections = sections


class _RouteAdapter:
    destination = Path("/tmp/task-5-route.json")

    def __init__(self) -> None:
        self.reset_count = 0
        self.transform_edits: list[tuple[int, tuple[str, ...]]] = []
        document = {
            "description": "route proof",
            "additional_configuration": {
                "pipeline_v2": [
                    {"pass_id": "mba-simplify", "options": {"transforms": ["a"]}},
                    {"pass_id": "mba-simplify", "options": {"transforms": ["b"]}},
                ]
            },
        }
        payload = json.dumps(document)
        self.draft = ConfigV2ProjectDraft(
            draft_id="route",
            revision=0,
            source_path=self.destination,
            destination_path=self.destination,
            source_sha256="abc",
            original_document_json=payload,
            document_json=payload,
        )
        self.validation = ConfigV2ProjectValidation(
            draft_id="route",
            revision=0,
            valid=True,
            pass_ids=("mba-simplify", "mba-simplify"),
            stage_ids=(),
            transform_ids=("a", "b"),
            routing_policy_json="{}",
            diagnostics=(),
        )

    def manifest(self) -> tuple[object, ...]:
        return ()

    def catalog(self) -> tuple[PassCatalogEntry, ...]:
        return (
            PassCatalogEntry(
                pass_id="mba-simplify",
                display_name="MBA simplify",
                contract_json='{"inputs": ["microcode"]}',
                option_template_json="{}",
                granularity="function",
                maturity="MMAT_LOCOPT",
                backend_route="mutation_backend",
                safety_policy="verified",
                transform_ids=("a", "b"),
                stage_ids=(),
                configured=True,
                editor_spec=PassEditorSpec.summary(),
            ),
        )

    def reset(self) -> tuple[ConfigV2ProjectDraft, ConfigV2ProjectValidation]:
        self.reset_count += 1
        return self.draft, self.validation

    def set_pass_transforms(
        self,
        draft: ConfigV2ProjectDraft,
        *,
        pass_index: int,
        transform_ids: tuple[str, ...],
    ) -> tuple[ConfigV2ProjectDraft, ConfigV2ProjectValidation]:
        assert draft is self.draft
        self.transform_edits.append((pass_index, transform_ids))
        return self.draft, self.validation


def _load_gui_panel(monkeypatch):
    plugin_form = type(
        "PluginForm",
        (),
        {
            "WOPN_PERSIST": 1,
            "WCLS_SAVE": 2,
            "__init__": lambda self: None,
        },
    )
    ida = types.SimpleNamespace(PluginForm=plugin_form)
    qt = types.SimpleNamespace(
        Qt=types.SimpleNamespace(
            CheckState=types.SimpleNamespace(Checked=2, Unchecked=0),
            ItemDataRole=types.SimpleNamespace(UserRole=32),
            ItemFlag=types.SimpleNamespace(ItemIsUserCheckable=1),
            ScrollBarPolicy=types.SimpleNamespace(
                ScrollBarAsNeeded=1, ScrollBarAlwaysOff=2
            ),
        )
    )
    widgets = types.SimpleNamespace(
        **{
            name: _Widget
            for name in (
                "QComboBox",
                "QFileDialog",
                "QFormLayout",
                "QGroupBox",
                "QHBoxLayout",
                "QInputDialog",
                "QLabel",
                "QListWidget",
                "QPlainTextEdit",
                "QPushButton",
                "QStackedWidget",
                "QTabWidget",
                "QToolButton",
                "QVBoxLayout",
                "QWidget",
            )
        },
        QListWidgetItem=_ListItem,
    )
    monkeypatch.setitem(sys.modules, "ida_kernwin", ida)
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
            JsonTreeEditor=_JsonTreeEditor,
            RawJsonDialog=_Widget,
            StructuredDetailsView=_StructuredDetailsView,
        ),
    )
    module_name = "d810.ui._task5_gui_panel"
    spec = importlib.util.spec_from_file_location(
        module_name,
        IDA_UI.parent / "config_v2_editing_panel.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module.ConfigV2EditingPanel


def test_task4_routes_construct_both_screens_and_focus_duplicate_by_exact_row(
    monkeypatch,
) -> None:
    panel_type = _load_gui_panel(monkeypatch)
    builder_adapter = _RouteAdapter()
    builder = panel_type(builder_adapter, screen=ConfigV2EditorScreen.BUILDER)

    inspector_adapter = _RouteAdapter()
    exact_focus = resolve_config_v2_focus_target(
        "mba-simplify",
        ("mba-simplify", "mba-simplify"),
        pass_index=1,
    )
    inspector = panel_type(
        inspector_adapter,
        screen=ConfigV2EditorScreen.INSPECTOR,
        focus_target=exact_focus,
    )

    assert builder._screen is ConfigV2EditorScreen.BUILDER
    assert inspector._screen is ConfigV2EditorScreen.INSPECTOR
    assert inspector._selected_pass_index == 1
    assert builder_adapter.reset_count == inspector_adapter.reset_count == 1
    owned_draft = inspector._draft
    inspector._show_builder()
    inspector._show_inspector(0)
    assert inspector._draft is owned_draft
    assert inspector_adapter.reset_count == 1
    assert inspector._screen is ConfigV2EditorScreen.INSPECTOR
    assert inspector._selected_pass_index == 0
    inspector._apply_selected_transforms()
    assert inspector_adapter.transform_edits == [(0, ("a",))]

    ambiguous_focus = resolve_config_v2_focus_target(
        "mba-simplify",
        ("mba-simplify", "mba-simplify"),
    )
    refused = panel_type(
        _RouteAdapter(),
        screen=ConfigV2EditorScreen.INSPECTOR,
        focus_target=ambiguous_focus,
    )
    assert refused._selected_pass_index is None


def test_config_v2_save_refreshes_the_current_project_view_without_reloading() -> None:
    calls = _call_names(_method("_refresh_config_v2_project_view"))

    assert "update_cfg_select" in calls
    assert "get_project_runtime_snapshot" in calls
    assert "build_project_config_view" in calls
    assert "_apply_project_config_view" in calls
    assert "load_project" not in calls


def test_ida_ui_does_not_import_core_project_persistence() -> None:
    imported_modules = {
        node.module
        for node in ast.walk(TREE)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }

    assert "d810.core.project_config_persistence" not in imported_modules
