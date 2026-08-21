"""Pure filtering, sorting, and selection logic for reusable catalogs."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

from d810.core.typing import Iterable, Sequence


class CatalogSelectionMode(str, Enum):
    """Selection policy used by a catalog projection."""

    SINGLE = "single"
    MULTI_CHECK = "multi_check"


class CatalogSortDirection(str, Enum):
    """Direction for the active catalog column."""

    ASCENDING = "ascending"
    DESCENDING = "descending"


def _identifier(value: object, name: str) -> str:
    normalized = "" if value is None else str(value).strip()
    if not normalized:
        raise ValueError(f"{name} must not be empty")
    return normalized


def _key_tuple(values: Iterable[object]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        key = _identifier(value, "catalog key")
        if key not in result:
            result.append(key)
    return tuple(result)


@dataclass(frozen=True)
class CatalogColumnSpec:
    """Description of one displayed and optionally searchable column."""

    column_id: str
    label: str
    searchable: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "column_id", _identifier(self.column_id, "column_id"))
        object.__setattr__(self, "label", str(self.label))


@dataclass(frozen=True)
class CatalogRow:
    """Stable row identity and display cells for one catalog entry."""

    key: str
    cells: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "key", _identifier(self.key, "row key"))
        object.__setattr__(self, "cells", tuple(str(cell) for cell in self.cells))


@dataclass(frozen=True)
class FilterableCatalogState:
    """Pure state needed to project and transition a catalog."""

    query: str
    sort_column: int
    sort_direction: CatalogSortDirection
    checked_keys: tuple[str, ...]
    current_key: str | None

    def __post_init__(self) -> None:
        if isinstance(self.sort_column, bool) or not isinstance(self.sort_column, int):
            raise ValueError("sort column must be an integer")
        if self.sort_column < 0:
            raise ValueError("sort column must not be negative")
        try:
            direction = CatalogSortDirection(self.sort_direction)
        except ValueError as error:
            raise ValueError("sort direction is invalid") from error
        object.__setattr__(self, "query", "" if self.query is None else str(self.query).strip())
        object.__setattr__(self, "sort_direction", direction)
        object.__setattr__(self, "checked_keys", _key_tuple(self.checked_keys))
        object.__setattr__(
            self,
            "current_key",
            None if self.current_key is None else _identifier(self.current_key, "current key"),
        )


@dataclass(frozen=True)
class FilterableCatalogView:
    """Projected visible rows and complete-catalog selection information."""

    rows: tuple[CatalogRow, ...]
    checked_keys: tuple[str, ...]
    current_key: str | None
    action_text: str
    action_enabled: bool


def _mode(mode: CatalogSelectionMode) -> CatalogSelectionMode:
    try:
        return CatalogSelectionMode(mode)
    except ValueError as error:
        raise ValueError("catalog selection mode is invalid") from error


def _catalog_inputs(
    rows: Sequence[CatalogRow], columns: Sequence[CatalogColumnSpec]
) -> tuple[
    tuple[CatalogRow, ...], tuple[CatalogColumnSpec, ...], tuple[int | None, ...]
]:
    catalog_rows = tuple(rows)
    catalog_columns = tuple(columns)
    if not catalog_columns:
        raise ValueError("catalog must have at least one column")
    if any(not isinstance(column, CatalogColumnSpec) for column in catalog_columns):
        raise ValueError("catalog columns must be CatalogColumnSpec values")
    if any(not isinstance(row, CatalogRow) for row in catalog_rows):
        raise ValueError("catalog rows must be CatalogRow values")

    include_indexes = [
        index
        for index, column in enumerate(catalog_columns)
        if column.column_id.casefold() == "include"
    ]
    if len(include_indexes) > 1:
        raise ValueError("catalog may contain at most one Include column")
    include_index = include_indexes[0] if include_indexes else None
    cell_indexes: list[int | None] = []
    cell_index = 0
    for index in range(len(catalog_columns)):
        if index == include_index:
            cell_indexes.append(None)
        else:
            cell_indexes.append(cell_index)
            cell_index += 1

    seen: set[str] = set()
    for row in catalog_rows:
        if row.key in seen:
            raise ValueError(f"duplicate row key: {row.key}")
        seen.add(row.key)
        if len(row.cells) != cell_index:
            raise ValueError(
                f"cell count for row {row.key!r} does not match catalog-owned column count"
            )
    return catalog_rows, catalog_columns, tuple(cell_indexes)


def _validate_state(
    state: FilterableCatalogState,
    rows: tuple[CatalogRow, ...],
    columns: tuple[CatalogColumnSpec, ...],
    mode: CatalogSelectionMode,
) -> set[str]:
    if state.sort_column >= len(columns):
        raise ValueError("sort column is out of range")
    valid_keys = {row.key for row in rows}
    unknown_checked = set(state.checked_keys) - valid_keys
    if unknown_checked:
        unknown = sorted(unknown_checked)[0]
        raise ValueError(f"checked key is not registered: {unknown}")
    if state.current_key is not None and state.current_key not in valid_keys:
        raise ValueError(f"current key is not registered: {state.current_key}")
    if mode is CatalogSelectionMode.SINGLE and state.checked_keys:
        raise ValueError("single selection mode does not accept checked keys")
    return valid_keys


def _sort_rows(
    rows: tuple[CatalogRow, ...],
    columns: tuple[CatalogColumnSpec, ...],
    cell_indexes: tuple[int | None, ...],
    state: FilterableCatalogState,
) -> tuple[CatalogRow, ...]:
    column = columns[state.sort_column]
    descending = state.sort_direction is CatalogSortDirection.DESCENDING
    if column.column_id.casefold() == "include":
        checked = set(state.checked_keys)

        def sort_key(row: CatalogRow) -> tuple[bool, str, str]:
            return (row.key in checked, row.key.casefold(), row.key)

    else:
        cell_index = cell_indexes[state.sort_column]
        assert cell_index is not None

        def sort_key(row: CatalogRow) -> tuple[str, str, str]:
            return (
                row.cells[cell_index].casefold(),
                row.key.casefold(),
                row.key,
            )

    return tuple(sorted(rows, key=sort_key, reverse=descending))


def _action_text(action_verb: object, count: int) -> str:
    verb = str(action_verb).strip()
    if not verb:
        raise ValueError("action verb must not be empty")
    noun = "pass" if count == 1 else "passes"
    return f"{verb} {count} {noun}"


def project_filterable_catalog(
    rows: Sequence[CatalogRow],
    columns: Sequence[CatalogColumnSpec],
    state: FilterableCatalogState,
    mode: CatalogSelectionMode,
    *,
    action_verb: str,
) -> FilterableCatalogView:
    """Return the sorted, filtered view without changing the input state."""

    catalog_rows, catalog_columns, cell_indexes = _catalog_inputs(rows, columns)
    selection_mode = _mode(mode)
    _validate_state(state, catalog_rows, catalog_columns, selection_mode)
    sorted_rows = _sort_rows(catalog_rows, catalog_columns, cell_indexes, state)
    query = state.query.casefold()
    searchable_columns = tuple(
        cell_index
        for cell_index, column in zip(cell_indexes, catalog_columns)
        if column.searchable and cell_index is not None
    )
    if query:
        visible_rows = tuple(
            row
            for row in sorted_rows
            if any(query in row.cells[index].casefold() for index in searchable_columns)
        )
    else:
        visible_rows = sorted_rows

    checked_keys = (
        tuple(row.key for row in sorted_rows if row.key in set(state.checked_keys))
        if selection_mode is CatalogSelectionMode.MULTI_CHECK
        else ()
    )
    current_key = state.current_key
    count = len(checked_keys) if selection_mode is CatalogSelectionMode.MULTI_CHECK else bool(
        current_key
    )
    return FilterableCatalogView(
        rows=visible_rows,
        checked_keys=checked_keys,
        current_key=current_key,
        action_text=_action_text(action_verb, int(count)),
        action_enabled=bool(count),
    )


def initial_filterable_catalog_state(
    columns: Sequence[CatalogColumnSpec], *, initial_sort_column_id: str
) -> FilterableCatalogState:
    """Create an explicit initial state from a requested column identifier."""

    _, catalog_columns, _ = _catalog_inputs((), columns)
    normalized_id = _identifier(initial_sort_column_id, "sort column ID")
    matching_indexes = [
        index
        for index, column in enumerate(catalog_columns)
        if column.column_id == normalized_id
    ]
    if len(matching_indexes) != 1:
        raise ValueError(f"sort column ID is not uniquely registered: {normalized_id}")
    return FilterableCatalogState(
        query="",
        sort_column=matching_indexes[0],
        sort_direction=CatalogSortDirection.ASCENDING,
        checked_keys=(),
        current_key=None,
    )


def set_catalog_query(state: FilterableCatalogState, query: str) -> FilterableCatalogState:
    """Set the normalized filter query while preserving selection state."""

    return replace(state, query=query)


def set_catalog_sort(state: FilterableCatalogState, column: int) -> FilterableCatalogState:
    """Select a column, toggling direction when the active column is repeated."""

    if isinstance(column, bool) or not isinstance(column, int) or column < 0:
        raise ValueError("sort column must be a non-negative integer")
    if state.sort_column != column:
        direction = CatalogSortDirection.ASCENDING
    elif state.sort_direction is CatalogSortDirection.ASCENDING:
        direction = CatalogSortDirection.DESCENDING
    else:
        direction = CatalogSortDirection.ASCENDING
    return replace(state, sort_column=column, sort_direction=direction)


def set_catalog_checked(
    state: FilterableCatalogState,
    key: str,
    checked: bool,
    *,
    valid_keys: Iterable[str],
    mode: CatalogSelectionMode,
) -> FilterableCatalogState:
    """Update one checked identity without depending on visible rows."""

    if _mode(mode) is not CatalogSelectionMode.MULTI_CHECK:
        raise ValueError("checked selection requires multi-check mode")
    normalized_key = _identifier(key, "checked key")
    valid = {_identifier(value, "valid key") for value in valid_keys}
    if normalized_key not in valid:
        raise ValueError(f"checked key is not registered: {normalized_key}")
    checked_keys = list(state.checked_keys)
    if checked and normalized_key not in checked_keys:
        checked_keys.append(normalized_key)
    elif not checked:
        checked_keys = [item for item in checked_keys if item != normalized_key]
    return replace(state, checked_keys=tuple(checked_keys))


def set_catalog_current(
    state: FilterableCatalogState,
    key: str | None,
    *,
    valid_keys: Iterable[str],
    mode: CatalogSelectionMode,
) -> FilterableCatalogState:
    """Set the current row, clearing check identities in single mode."""

    selection_mode = _mode(mode)
    normalized_key = None if key is None else _identifier(key, "current key")
    valid = {_identifier(value, "valid key") for value in valid_keys}
    if normalized_key is not None and normalized_key not in valid:
        raise ValueError(f"current key is not registered: {normalized_key}")
    if selection_mode is CatalogSelectionMode.SINGLE:
        return replace(state, current_key=normalized_key, checked_keys=())
    return replace(state, current_key=normalized_key)
