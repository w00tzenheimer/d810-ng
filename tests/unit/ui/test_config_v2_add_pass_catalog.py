from __future__ import annotations

import ast
import copy
from types import SimpleNamespace
from pathlib import Path

from d810.core.pass_editor_spec import PassEditorSpec
from d810.manager.workbench_recipe_service import RecipeService
from d810.manager.workbench_recipe_models import PassCatalogEntry
from d810.manager.workbench_recipe_models import (
    PassImplementationAvailability,
    PassImplementationStatus,
)
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.ui.filterable_catalog_logic import (
    CatalogColumnSpec,
    CatalogRow,
    CatalogSelectionMode,
    initial_filterable_catalog_state,
    project_filterable_catalog,
    set_catalog_checked,
    set_catalog_query,
    set_catalog_sort,
)


PANEL = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "d810"
    / "ui"
    / "config_v2_editing_panel.py"
)


def _add_method() -> ast.FunctionDef:
    tree = ast.parse(PANEL.read_text(encoding="utf-8"), filename=str(PANEL))
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name != "ConfigV2EditingPanel":
            continue
        for item in node.body:
            if isinstance(item, ast.FunctionDef) and item.name == "_add_pass":
                return item
    raise AssertionError("ConfigV2EditingPanel._add_pass not found")


class _Dialog:
    next_keys: tuple[str, ...] = ()
    next_result = 1
    instances: list["_Dialog"] = []

    def __init__(self, title, columns, rows, *, mode, action_verb, parent):
        self.title = title
        self.columns = tuple(columns)
        self.rows = tuple(rows)
        self.mode = mode
        self.action_verb = action_verb
        self.parent = parent
        self._keys = type(self).next_keys
        self.exec_count = 0
        type(self).instances.append(self)

    def exec_(self) -> int:
        self.exec_count += 1
        return type(self).next_result

    def selected_keys(self) -> tuple[str, ...]:
        return self._keys


def _compiled_add_pass():
    class_node = ast.ClassDef(
        name="PanelHarness",
        bases=[],
        keywords=[],
        body=[copy.deepcopy(_add_method())],
        decorator_list=[],
    )
    module = ast.fix_missing_locations(ast.Module(body=[class_node], type_ignores=[]))
    namespace = {
        "CatalogColumnSpec": CatalogColumnSpec,
        "CatalogRow": CatalogRow,
        "CatalogSelectionMode": CatalogSelectionMode,
        "FilterableCatalogDialog": _Dialog,
        "QtWidgets": SimpleNamespace(
            QDialog=SimpleNamespace(
                DialogCode=SimpleNamespace(Accepted=1),
                Accepted=1,
            )
        ),
    }
    exec(compile(module, filename=str(PANEL), mode="exec"), namespace)
    return namespace["PanelHarness"]._add_pass


def _entry(
    pass_id: str,
    display_name: str,
    *,
    configured: bool,
    purpose: str = "Test purpose",
    implementation: PassImplementationAvailability | None = None,
) -> PassCatalogEntry:
    return PassCatalogEntry(
        pass_id=pass_id,
        display_name=display_name,
        contract_json="{}",
        option_template_json="{}",
        granularity="function",
        maturity="any",
        backend_route="mutation_backend",
        safety_policy="default",
        transform_ids=(),
        stage_ids=(),
        configured=configured,
        editor_spec=PassEditorSpec.summary(),
        purpose=purpose,
        implementation=implementation,
    )


def _panel(catalog, *, selected_index: int | None, keys: tuple[str, ...]):
    _Dialog.instances = []
    _Dialog.next_keys = keys
    _Dialog.next_result = 1
    edits: list[object] = []
    adapter = SimpleNamespace(
        catalog=lambda: tuple(catalog),
        add_passes=lambda draft, pass_ids, *, index: edits.append(
            (draft, tuple(pass_ids), index)
        )
        or ("edited-draft", "validation"),
    )
    panel = SimpleNamespace(
        _catalog=tuple(catalog),
        parent="parent",
        _draft="draft",
        _adapter=adapter,
        _builder_selected_pass_index=lambda: selected_index,
        _apply_edit=lambda operation: operation(),
    )
    return panel, edits


def test_add_pass_refreshes_provider_status_from_adapter_at_open_time() -> None:
    stale = _entry("mba-egraph", "MBA e-graph", configured=True)
    ready = PassImplementationAvailability(
        distribution="d810-egglog",
        status=PassImplementationStatus.READY,
        status_label="Ready",
        detail="d810-egglog is ready.",
        activation_required=True,
        backend_names=("egglog",),
    )
    fresh = _entry(
        "mba-egraph",
        "MBA e-graph",
        configured=True,
        implementation=ready,
    )
    panel, _edits = _panel((stale,), selected_index=None, keys=())
    panel._adapter.catalog = lambda: (fresh,)

    _compiled_add_pass()(panel)

    assert _Dialog.instances[-1].rows[0].cells[-1] == "d810-egglog - Ready"


def test_add_pass_projects_public_catalog_into_shared_multi_check_dialog() -> None:
    entries = (
        _entry("known-pass", "Known pass", configured=True),
        _entry("unconfigured-pass", "Unconfigured pass", configured=False),
    )
    panel, edits = _panel(entries, selected_index=None, keys=())

    _compiled_add_pass()(panel)

    dialog = _Dialog.instances[-1]
    assert [column.label for column in dialog.columns] == [
        "Include",
        "Pass",
        "ID",
        "Purpose",
        "Implementation",
    ]
    assert dialog.mode is CatalogSelectionMode.MULTI_CHECK
    assert dialog.title == "Add pass"
    assert dialog.action_verb == "Add"
    assert dialog.rows == (
        CatalogRow(
            "known-pass",
            (
                "Known pass",
                "known-pass",
                "Test purpose",
                "",
            ),
        ),
        CatalogRow(
            "unconfigured-pass",
            (
                "Unconfigured pass",
                "unconfigured-pass",
                "Test purpose",
                "",
            ),
        ),
    )
    assert edits == []


def test_add_pass_catalog_surfaces_and_searches_provider_availability() -> None:
    unavailable = PassImplementationAvailability(
        distribution="d810-egglog",
        status=PassImplementationStatus.NOT_INSTALLED,
        status_label="Not installed",
        detail="Install d810-egglog before project activation.",
        activation_required=True,
        backend_names=(),
    )
    entries = (
        _entry("builtin", "Built in", configured=True),
        _entry(
            "mba-egraph",
            "MBA e-graph",
            configured=True,
            implementation=unavailable,
        ),
    )
    panel, _edits = _panel(entries, selected_index=None, keys=())

    _compiled_add_pass()(panel)

    dialog = _Dialog.instances[-1]
    assert dialog.rows[0].cells[-1] == ""
    assert dialog.rows[1].cells[-1] == "d810-egglog - Not installed"
    state = initial_filterable_catalog_state(
        dialog.columns, initial_sort_column_id="id"
    )
    view = project_filterable_catalog(
        dialog.rows,
        dialog.columns,
        set_catalog_query(state, "not installed"),
        CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )
    assert tuple(row.key for row in view.rows) == ("mba-egraph",)


def test_real_public_purposes_are_searchable_in_the_catalog_projection() -> None:
    entries = RecipeService(operational_config_v2_pass_registry()).catalog()
    columns = (
        CatalogColumnSpec("include", "Include", searchable=False),
        CatalogColumnSpec("pass", "Pass"),
        CatalogColumnSpec("id", "ID"),
        CatalogColumnSpec("purpose", "Purpose"),
    )
    rows = tuple(
        CatalogRow(entry.pass_id, (entry.display_name, entry.pass_id, entry.purpose))
        for entry in entries
    )
    state = initial_filterable_catalog_state(columns, initial_sort_column_id="id")

    for query, expected_id in (
        ("residual dispatcher", "cleanup_residual_dispatcher"),
        ("safe lowering", "plan_semantic_regions"),
        ("dispatcher structure and state", "recover_dispatcher"),
        ("e-graph", "mba-egraph"),
    ):
        view = project_filterable_catalog(
            rows,
            columns,
            set_catalog_query(state, query),
            CatalogSelectionMode.MULTI_CHECK,
            action_verb="Add",
        )
        assert [row.key for row in view.rows] == [expected_id]


def test_add_pass_preserves_dialog_order_and_inserts_after_selected_builder_row() -> None:
    entries = (
        _entry("first", "First", configured=True),
        _entry("second", "Second", configured=True),
        _entry("third", "Third", configured=True),
    )
    panel, edits = _panel(entries, selected_index=2, keys=("third", "first"))

    _compiled_add_pass()(panel)

    assert edits == [("draft", ("third", "first"), 3)]


def test_add_pass_appends_when_no_builder_row_is_selected() -> None:
    panel, edits = _panel(
        (_entry("first", "First", configured=True),),
        selected_index=None,
        keys=("first",),
    )

    _compiled_add_pass()(panel)

    assert edits == [("draft", ("first",), None)]


def test_add_pass_cancel_and_zero_selection_do_not_edit() -> None:
    panel, edits = _panel(
        (_entry("first", "First", configured=True),),
        selected_index=0,
        keys=(),
    )

    _compiled_add_pass()(panel)

    assert edits == []
    _Dialog.next_result = 0
    _Dialog.next_keys = ("first",)
    _compiled_add_pass()(panel)

    assert edits == []


def test_checked_passes_survive_filter_and_sort_and_return_complete_catalog_order() -> None:
    columns = (
        CatalogColumnSpec("include", "Include", searchable=False),
        CatalogColumnSpec("pass", "Pass"),
        CatalogColumnSpec("id", "ID"),
        CatalogColumnSpec("purpose", "Purpose"),
    )
    rows = (
        CatalogRow("pass.a", ("Zulu", "pass.a", "first")),
        CatalogRow("pass.b", ("Alpha", "pass.b", "second")),
        CatalogRow("pass.c", ("Middle", "pass.c", "third")),
    )
    state = initial_filterable_catalog_state(columns, initial_sort_column_id="id")
    state = set_catalog_checked(
        state,
        "pass.a",
        True,
        valid_keys=(row.key for row in rows),
        mode=CatalogSelectionMode.MULTI_CHECK,
    )
    state = set_catalog_checked(
        state,
        "pass.c",
        True,
        valid_keys=(row.key for row in rows),
        mode=CatalogSelectionMode.MULTI_CHECK,
    )
    state = set_catalog_query(state, "middle")
    assert project_filterable_catalog(
        rows,
        columns,
        state,
        CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    ).checked_keys == ("pass.a", "pass.c")

    state = set_catalog_sort(state, 1)
    state = set_catalog_query(state, "")
    view = project_filterable_catalog(
        rows,
        columns,
        state,
        CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )

    assert [row.key for row in view.rows] == ["pass.b", "pass.c", "pass.a"]
    assert view.checked_keys == ("pass.c", "pass.a")
