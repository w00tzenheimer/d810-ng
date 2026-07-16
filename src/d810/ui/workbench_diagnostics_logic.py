"""Pure sorting, filtering, selection, and action logic for diagnostics."""

from __future__ import annotations

import dataclasses
import enum

from d810.core.typing import Callable, Sequence, TypeVar
from d810.diagnostics.workbench_models import (
    DiagnosticDatabaseSummary,
    DiagnosticSnapshotSummary,
)


class DatabaseSort(str, enum.Enum):
    RUN_TIME = "run_time"
    FUNCTION = "function"
    FILE_SIZE = "file_size"
    SNAPSHOT_COUNT = "snapshot_count"
    PATH = "path"


class SnapshotSort(str, enum.Enum):
    TIMESTAMP = "timestamp"
    MATURITY = "maturity"
    PHASE = "phase"
    BLOCK_COUNT = "block_count"
    ROW_COUNT = "row_count"


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticActionState:
    action_id: str
    enabled: bool
    reason: str


_T = TypeVar("_T")


def _stable_primary_sort(
    values: Sequence[_T],
    *,
    latest_key: Callable[[_T], tuple[object, ...]],
    primary_key: Callable[[_T], object],
    reverse: bool,
) -> tuple[_T, ...]:
    latest_first = sorted(values, key=latest_key)
    return tuple(sorted(latest_first, key=primary_key, reverse=reverse))


def sort_databases(
    values: Sequence[DiagnosticDatabaseSummary],
    sort: DatabaseSort = DatabaseSort.RUN_TIME,
    *,
    descending: bool | None = None,
) -> tuple[DiagnosticDatabaseSummary, ...]:
    latest_key = lambda item: (
        -(item.recorded_at if item.recorded_at is not None else float("-inf")),
        item.path.casefold(),
        item.path,
    )
    if sort is DatabaseSort.RUN_TIME:
        ordered = tuple(sorted(values, key=latest_key))
        return tuple(reversed(ordered)) if descending is False else ordered

    key: Callable[[DiagnosticDatabaseSummary], object]
    if sort is DatabaseSort.FUNCTION:
        key = lambda item: min(item.function_eas) if item.function_eas else 2**64
    elif sort is DatabaseSort.FILE_SIZE:
        key = lambda item: item.size_bytes
    elif sort is DatabaseSort.SNAPSHOT_COUNT:
        key = lambda item: item.snapshot_count
    else:
        key = lambda item: (item.path.casefold(), item.path)
    return _stable_primary_sort(
        values,
        latest_key=latest_key,
        primary_key=key,
        reverse=bool(descending),
    )


def sort_snapshots(
    values: Sequence[DiagnosticSnapshotSummary],
    sort: SnapshotSort = SnapshotSort.TIMESTAMP,
    *,
    descending: bool | None = None,
) -> tuple[DiagnosticSnapshotSummary, ...]:
    latest_key = lambda item: (
        -item.recorded_at,
        -item.snapshot_id,
        item.database_path.casefold(),
        item.database_path,
    )
    if sort is SnapshotSort.TIMESTAMP:
        ordered = tuple(sorted(values, key=latest_key))
        return tuple(reversed(ordered)) if descending is False else ordered

    if sort is SnapshotSort.MATURITY:
        key = lambda item: item.maturity.casefold()
    elif sort is SnapshotSort.PHASE:
        key = lambda item: item.phase.casefold()
    elif sort is SnapshotSort.BLOCK_COUNT:
        key = lambda item: item.block_count
    else:
        key = lambda item: item.row_count
    return _stable_primary_sort(
        values,
        latest_key=latest_key,
        primary_key=key,
        reverse=bool(descending),
    )


def filter_databases(
    values: Sequence[DiagnosticDatabaseSummary], query: str
) -> tuple[DiagnosticDatabaseSummary, ...]:
    needle = query.strip().casefold()
    if not needle:
        return tuple(values)
    result = []
    for item in values:
        haystack = " ".join(
            (
                item.path,
                *(f"{ea:x} 0x{ea:x}" for ea in item.function_eas),
                item.error or "",
            )
        ).casefold()
        if needle in haystack:
            result.append(item)
    return tuple(result)


def filter_snapshots(
    values: Sequence[DiagnosticSnapshotSummary], query: str
) -> tuple[DiagnosticSnapshotSummary, ...]:
    needle = query.strip().casefold()
    if not needle:
        return tuple(values)
    return tuple(
        item
        for item in values
        if needle
        in " ".join(
            (
                str(item.snapshot_id),
                item.label,
                f"{item.function_ea:x}",
                f"0x{item.function_ea:x}",
                item.maturity,
                item.phase,
                item.database_path,
            )
        ).casefold()
    )


def latest_database_for_function(
    values: Sequence[DiagnosticDatabaseSummary], function_ea: int
) -> DiagnosticDatabaseSummary | None:
    matches = tuple(item for item in values if function_ea in item.function_eas)
    ordered = sort_databases(matches)
    return ordered[0] if ordered else None


def latest_snapshot_for_function(
    values: Sequence[DiagnosticSnapshotSummary], function_ea: int
) -> DiagnosticSnapshotSummary | None:
    matches = tuple(item for item in values if item.function_ea == function_ea)
    ordered = sort_snapshots(matches)
    return ordered[0] if ordered else None


def diagnostic_action_states(
    selected_databases: Sequence[DiagnosticDatabaseSummary],
    *,
    selected_snapshot_ids: Sequence[int],
) -> tuple[DiagnosticActionState, ...]:
    inactive = tuple(item for item in selected_databases if not item.active)
    active_count = len(selected_databases) - len(inactive)
    active_note = (
        f"; {active_count} active database(s) will be skipped" if active_count else ""
    )
    has_database = bool(selected_databases)
    has_inactive = bool(inactive)
    has_snapshots = bool(selected_snapshot_ids)

    def state(action_id: str, enabled: bool, ready: str, missing: str) -> DiagnosticActionState:
        return DiagnosticActionState(
            action_id=action_id,
            enabled=enabled,
            reason=(ready + active_note) if enabled else missing,
        )

    return (
        state(
            "delete_selected_snapshots",
            has_snapshots and has_inactive,
            "Selected snapshot IDs are ready for a cleanup plan",
            "Select snapshots in a closed database",
        ),
        state(
            "delete_all_snapshots",
            has_inactive,
            "Closed databases are ready for an all-snapshots plan",
            "Select a closed database",
        ),
        state(
            "keep_latest",
            has_inactive,
            "Closed databases are ready for a retention plan",
            "Select a closed database",
        ),
        state(
            "older_than",
            has_inactive,
            "Closed databases are ready for a time-based plan",
            "Select a closed database",
        ),
        state(
            "delete_selected_databases",
            has_inactive,
            "Selected closed databases are ready for quarantine",
            "Select a closed database",
        ),
        state(
            "delete_all_closed_databases",
            has_inactive,
            "Closed databases are ready for quarantine",
            "No closed databases are selected",
        ),
        state(
            "vacuum_selected_databases",
            has_inactive,
            "Selected closed databases are ready for vacuum",
            "Select a closed database",
        ),
        state(
            "inspect",
            has_database and any(item.readable for item in selected_databases),
            "Diagnostic database is readable",
            "Select a readable diagnostic database",
        ),
    )
