from __future__ import annotations

import ast
import copy
from pathlib import Path
from types import SimpleNamespace


OVERVIEW = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "d810"
    / "ui"
    / "config_v2_pipeline_overview.py"
)


def _source() -> str:
    assert OVERVIEW.is_file(), "the active-pipeline overview widget must exist"
    return OVERVIEW.read_text(encoding="utf-8")


def _widget_class() -> ast.ClassDef:
    tree = ast.parse(_source(), filename=str(OVERVIEW))
    for node in tree.body:
        if (
            isinstance(node, ast.ClassDef)
            and node.name == "ConfigV2PipelineOverviewWidget"
        ):
            return node
    raise AssertionError("ConfigV2PipelineOverviewWidget not found")


def _method(name: str) -> ast.FunctionDef:
    for node in _widget_class().body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"ConfigV2PipelineOverviewWidget.{name} not found")


class _RenderedItem:
    def __init__(self, columns: tuple[str, str]) -> None:
        self.columns = columns

    def setData(self, *args: object) -> None:
        del args

    def setToolTip(self, *args: object) -> None:
        del args


class _RenderedTree:
    def __init__(self) -> None:
        self.items: list[_RenderedItem] = []

    def clear(self) -> None:
        self.items.clear()

    def addTopLevelItem(self, item: _RenderedItem) -> None:
        self.items.append(item)

    def setVisible(self, visible: bool) -> None:
        self.visible = bool(visible)


class _RenderedControl:
    def setText(self, text: str) -> None:
        self.text = text

    def setVisible(self, visible: bool) -> None:
        self.visible = bool(visible)

    def setEnabled(self, enabled: bool) -> None:
        self.enabled = bool(enabled)


def _compiled_set_overview():
    class_node = ast.ClassDef(
        name="OverviewHarness",
        bases=[],
        keywords=[],
        body=[copy.deepcopy(_method("set_overview"))],
        decorator_list=[],
    )
    module = ast.fix_missing_locations(ast.Module(body=[class_node], type_ignores=[]))
    namespace = {
        "ConfigV2PipelineOverview": object,
        "QtCore": SimpleNamespace(Qt=SimpleNamespace(UserRole=32)),
        "QtWidgets": SimpleNamespace(QTreeWidgetItem=_RenderedItem),
    }
    exec(compile(module, filename=str(OVERVIEW), mode="exec"), namespace)
    return namespace["OverviewHarness"].set_overview


def test_widget_exposes_indexed_inspection_and_edit_pipeline_signals() -> None:
    assignments = {
        target.id: ast.unparse(node.value)
        for node in _widget_class().body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }

    assert assignments["inspect_requested"] == "QtCore.pyqtSignal(int)"
    assert assignments["edit_pipeline_requested"] == "QtCore.pyqtSignal()"

    set_overview = _method("set_overview")
    assert ast.unparse(set_overview.args.args[1].annotation) == (
        "ConfigV2PipelineOverview | None"
    )
    assert ast.unparse(set_overview.returns) == "None"


def test_widget_renders_only_active_overview_rows_in_configured_order() -> None:
    source = ast.get_source_segment(_source(), _method("set_overview"))

    assert source is not None
    assert "for row in overview.rows" in source
    assert "row.index + 1" in source
    assert "row.display_name" in source
    assert "row.selected_transform_summary" in source
    assert "row.purpose" in source
    assert "row.runs_during" in source


def test_widget_appends_only_declared_selection_summaries() -> None:
    tree = _RenderedTree()
    widget = SimpleNamespace(
        _overview=None,
        _tree=tree,
        _unavailable=_RenderedControl(),
        _edit_pipeline=_RenderedControl(),
    )
    overview = SimpleNamespace(
        rows=(
            SimpleNamespace(
                index=0,
                display_name="MBA simplify",
                selected_transform_summary="2 selected transforms",
                purpose="Simplify selected transforms.",
                runs_during="MMAT_LOCOPT",
            ),
            SimpleNamespace(
                index=1,
                display_name="Constant simplification",
                selected_transform_summary="",
                purpose="Fold constants.",
                runs_during="MMAT_LOCOPT",
            ),
        )
    )

    _compiled_set_overview()(widget, overview)

    assert [item.columns[1] for item in tree.items] == [
        "MBA simplify - 2 selected transforms",
        "Constant simplification",
    ]


def test_widget_activates_an_exact_configured_row_by_double_click_or_enter() -> None:
    source = _source()

    assert "itemActivated.connect" in source
    assert "QtCore.Qt.UserRole" in source
    assert "inspect_requested.emit" in source


def test_widget_has_one_edit_action_and_compact_unavailable_state() -> None:
    source = _source()
    widget = _widget_class()
    push_buttons = [
        node
        for node in ast.walk(widget)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "QPushButton"
    ]

    assert len(push_buttons) == 1
    assert '"Edit pipeline..."' in source
    assert "Active pipeline unavailable." in source


def test_widget_never_projects_ownership_children_or_catalog_rows() -> None:
    source = _source()

    for forbidden in (
        "transform_ids",
        "stage_ids",
        "Transform:",
        "Stage:",
        "get_workbench_recipe_catalog",
    ):
        assert forbidden not in source
