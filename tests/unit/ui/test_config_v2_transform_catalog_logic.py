"""Qt-free grouping and selection semantics for typed transform catalogs."""

from __future__ import annotations

import pytest

from d810.passes.mba_transform_catalog import mba_transform_editor_spec


def _logic_module() -> object:
    try:
        from d810.ui import config_v2_editing_logic
    except ImportError as error:
        pytest.fail(f"transform catalog logic is not available: {error}")
    return config_v2_editing_logic


def _transform(view: object, transform_id: str) -> object:
    for family in view.families:
        for subfamily in family.subfamilies:
            for transform in subfamily.transforms:
                if transform.transform_id == transform_id:
                    return transform
    raise AssertionError(f"missing transform {transform_id!r}")


def test_filtering_family_selection_touches_only_visible_descendants() -> None:
    logic = _logic_module()
    view = logic.project_transform_catalog(
        mba_transform_editor_spec(),
        {"add-xor-1"},
        query="mul-mba",
    )

    assert [family.family_id for family in view.families] == ["arithmetic"]
    assert view.families[0].selected_count == 0
    assert view.families[0].visible_count == 4
    assert logic.apply_transform_catalog_selection(
        view,
        {"add-xor-1"},
        target_id="family:arithmetic",
        selected=True,
    ) == (
        "add-xor-1",
        "mul-mba-1",
        "mul-mba-2",
        "mul-mba-3",
        "mul-mba-4",
    )


def test_existing_selected_danger_transform_remains_selected() -> None:
    logic = _logic_module()
    view = logic.project_transform_catalog(
        mba_transform_editor_spec(),
        {"mul-mba-2"},
        query="",
    )
    transform = _transform(view, "mul-mba-2")

    assert transform.selected is True
    assert transform.default_selected is False
    assert transform.advisory == "danger"


def test_select_all_and_clear_apply_only_to_current_visible_catalog() -> None:
    logic = _logic_module()
    view = logic.project_transform_catalog(
        mba_transform_editor_spec(),
        {"add-xor-1", "mul-mba-1"},
        query="mul-mba",
    )

    assert logic.apply_transform_catalog_selection(
        view,
        {"add-xor-1", "mul-mba-1"},
        target_id="visible",
        selected=False,
    ) == ("add-xor-1",)
    assert logic.apply_transform_catalog_selection(
        view,
        {"add-xor-1"},
        target_id="all",
        selected=True,
    ) == tuple(item.transform_id for item in mba_transform_editor_spec().transforms)
