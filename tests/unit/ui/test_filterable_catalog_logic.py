"""Contract tests for the Qt-free filterable catalog selection model."""

from __future__ import annotations

import dataclasses

import pytest

from d810.ui.filterable_catalog_logic import (
    CatalogColumnSpec,
    CatalogRow,
    CatalogSelectionMode,
    CatalogSortDirection,
    FilterableCatalogState,
    project_filterable_catalog,
    set_catalog_checked,
    set_catalog_current,
    set_catalog_query,
    set_catalog_sort,
)


_COLUMNS = (
    CatalogColumnSpec("include", "Include", searchable=False),
    CatalogColumnSpec("pass", "Pass"),
    CatalogColumnSpec("id", "ID"),
    CatalogColumnSpec("purpose", "Purpose"),
)
_ROWS = (
    CatalogRow("pass.z", ("Zeta", "pass.z", "Alpha purpose")),
    CatalogRow("pass.a", ("alpha", "pass.a", "Omega purpose")),
    CatalogRow("pass.m", ("Mu", "pass.m", "Middle purpose")),
)


def _state(
    *,
    query: str = "",
    sort_column: int = 2,
    sort_direction: CatalogSortDirection = CatalogSortDirection.ASCENDING,
    checked_keys: tuple[str, ...] = (),
    current_key: str | None = None,
) -> FilterableCatalogState:
    return FilterableCatalogState(
        query=query,
        sort_column=sort_column,
        sort_direction=sort_direction,
        checked_keys=checked_keys,
        current_key=current_key,
    )


def test_public_models_are_frozen_and_normalize_required_identifiers() -> None:
    column = CatalogColumnSpec("  pass ", "Pass")
    row = CatalogRow("  pass.a ", ("Display text",))
    state = FilterableCatalogState(
        query="  alpha ",
        sort_column=0,
        sort_direction="ascending",
        checked_keys=(" pass.a ", "pass.a"),
        current_key=" pass.a ",
    )

    assert column.column_id == "pass"
    assert row.key == "pass.a"
    assert row.cells == ("Display text",)
    assert state.query == "alpha"
    assert state.checked_keys == ("pass.a",)
    assert state.current_key == "pass.a"
    with pytest.raises(dataclasses.FrozenInstanceError):
        row.key = "other"  # type: ignore[misc]


def test_projection_rejects_duplicate_keys_and_cell_count_mismatch() -> None:
    duplicate_rows = (
        CatalogRow("same", ("one",) * (len(_COLUMNS) - 1)),
        CatalogRow(" same ", ("two",) * (len(_COLUMNS) - 1)),
    )
    with pytest.raises(ValueError, match="duplicate row key"):
        project_filterable_catalog(
            duplicate_rows,
            _COLUMNS,
            _state(),
            CatalogSelectionMode.MULTI_CHECK,
            action_verb="Add",
        )

    with pytest.raises(ValueError, match="cell count"):
        project_filterable_catalog(
            (CatalogRow("one", ("only one",)),),
            _COLUMNS,
            _state(),
            CatalogSelectionMode.MULTI_CHECK,
            action_verb="Add",
        )


def test_projection_rejects_invalid_sort_column_and_checked_keys() -> None:
    with pytest.raises(ValueError, match="sort column"):
        project_filterable_catalog(
            _ROWS,
            _COLUMNS,
            _state(sort_column=len(_COLUMNS)),
            CatalogSelectionMode.MULTI_CHECK,
            action_verb="Add",
        )

    with pytest.raises(ValueError, match="checked key"):
        project_filterable_catalog(
            _ROWS,
            _COLUMNS,
            _state(checked_keys=("not-registered",)),
            CatalogSelectionMode.MULTI_CHECK,
            action_verb="Add",
        )


def test_include_is_widget_owned_and_rows_contain_only_catalog_cells() -> None:
    view = project_filterable_catalog(
        _ROWS,
        _COLUMNS,
        _state(sort_column=2),
        CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )

    assert [row.key for row in view.rows] == ["pass.a", "pass.m", "pass.z"]
    assert view.rows[0].cells == ("alpha", "pass.a", "Omega purpose")


def test_projection_allows_zero_include_column_and_rejects_multiple_include_columns() -> None:
    no_include_columns = _COLUMNS[1:]
    no_include = project_filterable_catalog(
        _ROWS,
        no_include_columns,
        _state(sort_column=1),
        CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )
    assert [row.key for row in no_include.rows] == ["pass.a", "pass.m", "pass.z"]

    duplicate_include_columns = (
        CatalogColumnSpec("include", "Include", searchable=False),
        CatalogColumnSpec("include", "Also include", searchable=False),
        *_COLUMNS[1:],
    )
    with pytest.raises(ValueError, match="at most one Include"):
        project_filterable_catalog(
            _ROWS,
            duplicate_include_columns,
            _state(sort_column=2),
            CatalogSelectionMode.MULTI_CHECK,
            action_verb="Add",
        )


def test_initial_state_requires_explicit_sort_column_id_and_preserves_id_order() -> None:
    from d810.ui.filterable_catalog_logic import initial_filterable_catalog_state

    state = initial_filterable_catalog_state(_COLUMNS, initial_sort_column_id="id")
    initial = project_filterable_catalog(
        _ROWS,
        _COLUMNS,
        state,
        CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )
    checked_state = set_catalog_checked(
        state,
        "pass.a",
        True,
        valid_keys={row.key for row in _ROWS},
        mode=CatalogSelectionMode.MULTI_CHECK,
    )
    after_check = project_filterable_catalog(
        _ROWS,
        _COLUMNS,
        checked_state,
        CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )

    assert state.sort_column == 2
    assert [row.key for row in initial.rows] == ["pass.a", "pass.m", "pass.z"]
    assert [row.key for row in after_check.rows] == ["pass.a", "pass.m", "pass.z"]
    assert after_check.checked_keys == ("pass.a",)
    with pytest.raises(ValueError, match="sort column ID"):
        initial_filterable_catalog_state(_COLUMNS, initial_sort_column_id="missing")
    with pytest.raises(TypeError):
        FilterableCatalogState()  # type: ignore[call-arg]


def test_single_mode_rejects_checked_state_and_uses_current_key() -> None:
    with pytest.raises(ValueError, match="single"):
        project_filterable_catalog(
            _ROWS,
            _COLUMNS,
            _state(checked_keys=("pass.a",)),
            CatalogSelectionMode.SINGLE,
            action_verb="Select",
        )

    view = project_filterable_catalog(
        _ROWS,
        _COLUMNS,
        _state(current_key="pass.m"),
        CatalogSelectionMode.SINGLE,
        action_verb="Select",
    )
    assert view.checked_keys == ()
    assert view.current_key == "pass.m"
    assert view.action_text == "Select 1 pass"
    assert view.action_enabled is True


def test_filtering_is_casefolded_trimmed_and_limited_to_searchable_columns() -> None:
    by_name = project_filterable_catalog(
        _ROWS,
        _COLUMNS,
        _state(query="  zEtA  ", sort_column=1),
        CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )
    assert [row.key for row in by_name.rows] == ["pass.z"]

    by_id = project_filterable_catalog(
        _ROWS,
        _COLUMNS,
        _state(query="PASS.A"),
        CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )
    assert [row.key for row in by_id.rows] == ["pass.a"]

    by_purpose = project_filterable_catalog(
        _ROWS,
        _COLUMNS,
        _state(query="middle PURPOSE"),
        CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )
    assert [row.key for row in by_purpose.rows] == ["pass.m"]

    include_is_not_searchable = project_filterable_catalog(
        _ROWS,
        _COLUMNS,
        _state(query="include"),
        CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )
    assert include_is_not_searchable.rows == ()


def test_filtering_preserves_complete_catalog_sort_order() -> None:
    state = _state(query="purpose", sort_column=1)
    view = project_filterable_catalog(
        _ROWS,
        _COLUMNS,
        state,
        CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )
    assert [row.key for row in view.rows] == ["pass.a", "pass.m", "pass.z"]


def test_sort_transitions_toggle_and_new_columns_start_ascending() -> None:
    state = _state(sort_column=1)
    assert set_catalog_sort(state, 1).sort_direction is CatalogSortDirection.DESCENDING
    assert set_catalog_sort(
        set_catalog_sort(state, 1), 1
    ).sort_direction is CatalogSortDirection.ASCENDING
    changed_column = set_catalog_sort(state, 3)
    assert changed_column.sort_column == 3
    assert changed_column.sort_direction is CatalogSortDirection.ASCENDING

    with pytest.raises(ValueError, match="sort column"):
        set_catalog_sort(state, -1)


def test_equal_sort_values_use_a_deterministic_key_tiebreaker() -> None:
    rows = (
        CatalogRow("key.b", ("same", "b", "")),
        CatalogRow("key.a", ("same", "a", "")),
    )
    ascending = project_filterable_catalog(
        rows,
        _COLUMNS,
        _state(sort_column=1),
        CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )
    descending = project_filterable_catalog(
        rows,
        _COLUMNS,
        _state(sort_column=1, sort_direction=CatalogSortDirection.DESCENDING),
        CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )
    assert [row.key for row in ascending.rows] == ["key.a", "key.b"]
    assert [row.key for row in descending.rows] == ["key.b", "key.a"]


def test_casefold_colliding_keys_have_deterministic_original_key_tiebreakers() -> None:
    columns = _COLUMNS[1:]
    forward = (
        CatalogRow("pass.A", ("same", "pass.A", "")),
        CatalogRow("pass.a", ("same", "pass.a", "")),
    )
    reverse = tuple(reversed(forward))
    expected_ascending = ["pass.A", "pass.a"]
    expected_descending = ["pass.a", "pass.A"]

    for rows in (forward, reverse):
        ascending = project_filterable_catalog(
            rows,
            columns,
            _state(sort_column=0),
            CatalogSelectionMode.MULTI_CHECK,
            action_verb="Add",
        )
        descending = project_filterable_catalog(
            rows,
            columns,
            _state(sort_column=0, sort_direction=CatalogSortDirection.DESCENDING),
            CatalogSelectionMode.MULTI_CHECK,
            action_verb="Add",
        )
        assert [row.key for row in ascending.rows] == expected_ascending
        assert [row.key for row in descending.rows] == expected_descending


def test_include_sort_orders_unchecked_before_checked_in_ascending_order() -> None:
    ascending = project_filterable_catalog(
        _ROWS,
        _COLUMNS,
        _state(sort_column=0, checked_keys=("pass.m",)),
        CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )
    descending = project_filterable_catalog(
        _ROWS,
        _COLUMNS,
        _state(
            sort_column=0,
            sort_direction=CatalogSortDirection.DESCENDING,
            checked_keys=("pass.m",),
        ),
        CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )
    assert [row.key for row in ascending.rows] == ["pass.a", "pass.z", "pass.m"]
    assert [row.key for row in descending.rows] == ["pass.m", "pass.z", "pass.a"]


def test_checked_keys_persist_through_query_and_sort_and_order_over_hidden_rows() -> None:
    state = _state(checked_keys=("pass.z", "pass.a"), sort_column=1)
    filtered = set_catalog_query(state, "middle")
    view = project_filterable_catalog(
        _ROWS,
        _COLUMNS,
        filtered,
        CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )
    assert [row.key for row in view.rows] == ["pass.m"]
    assert view.checked_keys == ("pass.a", "pass.z")
    assert view.action_text == "Add 2 passes"
    assert view.action_enabled is True


def test_checked_transition_preserves_unique_keys_and_rejects_unknown_keys() -> None:
    state = _state(checked_keys=("pass.a",))
    checked = set_catalog_checked(
        state,
        " pass.z ",
        True,
        valid_keys={"pass.a", "pass.z"},
        mode=CatalogSelectionMode.MULTI_CHECK,
    )
    assert checked.checked_keys == ("pass.a", "pass.z")
    unchecked = set_catalog_checked(
        checked,
        "pass.a",
        False,
        valid_keys={"pass.a", "pass.z"},
        mode=CatalogSelectionMode.MULTI_CHECK,
    )
    assert unchecked.checked_keys == ("pass.z",)
    with pytest.raises(ValueError, match="checked key"):
        set_catalog_checked(
            state,
            "unknown",
            True,
            valid_keys={"pass.a", "pass.z"},
            mode=CatalogSelectionMode.MULTI_CHECK,
        )
    with pytest.raises(ValueError, match="multi-check"):
        set_catalog_checked(
            state,
            "pass.z",
            True,
            valid_keys={"pass.a", "pass.z"},
            mode=CatalogSelectionMode.SINGLE,
        )


def test_current_transition_validates_key_and_clears_multi_check_state_in_single_mode() -> None:
    state = _state(checked_keys=("pass.a",))
    updated = set_catalog_current(
        state,
        " pass.m ",
        valid_keys={"pass.a", "pass.m"},
        mode=CatalogSelectionMode.MULTI_CHECK,
    )
    assert updated.current_key == "pass.m"
    assert updated.checked_keys == ("pass.a",)

    single = set_catalog_current(
        state,
        "pass.m",
        valid_keys={"pass.a", "pass.m"},
        mode=CatalogSelectionMode.SINGLE,
    )
    assert single.current_key == "pass.m"
    assert single.checked_keys == ()
    with pytest.raises(ValueError, match="current key"):
        set_catalog_current(
            state,
            "unknown",
            valid_keys={"pass.a", "pass.m"},
            mode=CatalogSelectionMode.MULTI_CHECK,
        )


@pytest.mark.parametrize(
    ("checked_keys", "expected_text", "enabled"),
    [
        ((), "Add 0 passes", False),
        (("pass.a",), "Add 1 pass", True),
        (("pass.a", "pass.m", "pass.z"), "Add 3 passes", True),
    ],
)
def test_action_text_and_enabled_state(
    checked_keys: tuple[str, ...], expected_text: str, enabled: bool
) -> None:
    view = project_filterable_catalog(
        _ROWS,
        _COLUMNS,
        _state(checked_keys=checked_keys),
        CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )
    assert view.action_text == expected_text
    assert view.action_enabled is enabled
