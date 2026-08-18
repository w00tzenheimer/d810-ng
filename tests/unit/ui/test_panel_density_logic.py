from __future__ import annotations

import ast
from pathlib import Path

import d810.ui.panel_density_logic as panel_density_logic
from d810.ui.panel_density_logic import (
    CHOICE_LIST_MAX_HEIGHT,
    CHOICE_LIST_MIN_HEIGHT,
    FIELD_SECTION_MAX_HEIGHT,
    MIN_TREE_ROWS,
    choice_list_height,
    plan_panel_density,
    primary_field_section_height,
)


ROW_PX = 20
ROOMY_PX = MIN_TREE_ROWS * ROW_PX * 3
CRAMPED_PX = MIN_TREE_ROWS * ROW_PX - 1


def _plan(
    *,
    available_px: int,
    row_px: int = ROW_PX,
    filter_has_text: bool = False,
    details_requested: bool = False,
):
    return plan_panel_density(
        available_px=available_px,
        row_px=row_px,
        filter_has_text=filter_has_text,
        details_requested=details_requested,
    )


def test_roomy_panel_shows_the_filter_and_honors_the_disclosure_request() -> None:
    expanded = _plan(available_px=ROOMY_PX, details_requested=True)
    collapsed = _plan(available_px=ROOMY_PX, details_requested=False)

    assert expanded.show_filter is True
    assert expanded.show_details is True
    assert collapsed.show_filter is True
    assert collapsed.show_details is False


def test_cramped_panel_sheds_the_filter_and_the_requested_disclosure() -> None:
    plan = _plan(available_px=CRAMPED_PX, details_requested=True)

    assert plan.show_filter is False
    assert plan.show_details is False


def test_cramped_panel_keeps_a_filter_that_already_holds_text() -> None:
    plan = _plan(available_px=CRAMPED_PX, filter_has_text=True)

    assert plan.show_filter is True


def test_canonical_project_disclosure_remains_user_controlled() -> None:
    roomy = _plan(available_px=ROOMY_PX, details_requested=True)
    cramped = _plan(available_px=CRAMPED_PX, details_requested=True)

    assert roomy.show_details is True
    assert cramped.show_details is False


def test_exactly_the_minimum_tree_height_still_counts_as_roomy() -> None:
    plan = _plan(available_px=MIN_TREE_ROWS * ROW_PX, details_requested=True)

    assert plan.show_filter is True
    assert plan.show_details is True


def test_unmeasured_row_height_is_treated_as_roomy_not_cramped() -> None:
    plan = _plan(available_px=0, row_px=0, details_requested=True)

    assert plan.show_filter is True
    assert plan.show_details is True


def test_logic_module_imports_no_ida_or_qt_modules() -> None:
    module_path = Path(panel_density_logic.__file__)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".")[0])

    assert imported_roots.isdisjoint(
        {"idaapi", "ida_kernwin", "ida_hexrays", "PyQt5", "PySide6"}
    )


def test_choice_list_height_clamps_zero_and_small_row_counts_to_minimum() -> None:
    assert choice_list_height(0) == CHOICE_LIST_MIN_HEIGHT
    assert choice_list_height(1) == CHOICE_LIST_MIN_HEIGHT


def test_choice_list_height_scales_dense_choice_lists_without_screen_geometry() -> None:
    four_rows = choice_list_height(4)
    twelve_rows = choice_list_height(12)

    assert CHOICE_LIST_MIN_HEIGHT < four_rows < CHOICE_LIST_MAX_HEIGHT
    assert twelve_rows == CHOICE_LIST_MAX_HEIGHT


def test_choice_list_height_rejects_negative_visible_row_counts() -> None:
    assert choice_list_height(-1) == CHOICE_LIST_MIN_HEIGHT


def test_sparse_primary_field_section_uses_content_height_not_full_viewport() -> None:
    assert primary_field_section_height(scalar_rows=3, choice_row_counts=()) < 240


def test_dense_primary_field_section_caps_height_and_scrolls_internally() -> None:
    assert (
        primary_field_section_height(
            scalar_rows=3,
            choice_row_counts=(8, 12),
        )
        == FIELD_SECTION_MAX_HEIGHT
    )
