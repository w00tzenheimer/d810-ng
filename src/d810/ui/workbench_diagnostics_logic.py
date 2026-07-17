"""Pure sorting, filtering, selection, and action logic for diagnostics."""

from __future__ import annotations

import dataclasses
import enum

from d810.core.typing import Callable, Sequence, TypeVar
from d810.diagnostics.workbench_models import (
    DiagnosticCleanupScope,
    DiagnosticDatabaseSummary,
    DiagnosticRecord,
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


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticFunctionGroup:
    function_ea: int
    databases: tuple[DiagnosticDatabaseSummary, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticRecordRow:
    key: str
    source_table: str
    ordinal: int
    anchor: str
    summary: str
    detail: str
    record: DiagnosticRecord


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticCleanupPlanView:
    text: str
    required_phrase: str
    target_count: int
    snapshot_count: int
    estimated_rows: int


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticCleanupExecutionOptions:
    """UI execution options derived from an already-previewed cleanup plan."""

    show_vacuum_after: bool


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
    def latest_key(item: DiagnosticDatabaseSummary) -> tuple[object, ...]:
        return (
            -(item.recorded_at if item.recorded_at is not None else float("-inf")),
            item.path.casefold(),
            item.path,
        )

    if sort is DatabaseSort.RUN_TIME:
        ordered = tuple(sorted(values, key=latest_key))
        return tuple(reversed(ordered)) if descending is False else ordered

    key: Callable[[DiagnosticDatabaseSummary], object]
    if sort is DatabaseSort.FUNCTION:
        def key(item: DiagnosticDatabaseSummary) -> object:
            return min(item.function_eas) if item.function_eas else 2**64

    elif sort is DatabaseSort.FILE_SIZE:
        def key(item: DiagnosticDatabaseSummary) -> object:
            return item.size_bytes

    elif sort is DatabaseSort.SNAPSHOT_COUNT:
        def key(item: DiagnosticDatabaseSummary) -> object:
            return item.snapshot_count

    else:
        def key(item: DiagnosticDatabaseSummary) -> object:
            return (item.path.casefold(), item.path)

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
    def latest_key(item: DiagnosticSnapshotSummary) -> tuple[object, ...]:
        return (
            -item.recorded_at,
            -item.snapshot_id,
            item.database_path.casefold(),
            item.database_path,
        )

    if sort is SnapshotSort.TIMESTAMP:
        ordered = tuple(sorted(values, key=latest_key))
        return tuple(reversed(ordered)) if descending is False else ordered

    key: Callable[[DiagnosticSnapshotSummary], object]
    if sort is SnapshotSort.MATURITY:
        def key(item: DiagnosticSnapshotSummary) -> object:
            return item.maturity.casefold()

    elif sort is SnapshotSort.PHASE:
        def key(item: DiagnosticSnapshotSummary) -> object:
            return item.phase.casefold()

    elif sort is SnapshotSort.BLOCK_COUNT:
        def key(item: DiagnosticSnapshotSummary) -> object:
            return item.block_count

    else:
        def key(item: DiagnosticSnapshotSummary) -> object:
            return item.row_count

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
                "active" if item.active else "closed",
                "readable" if item.readable else "unreadable",
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


def filter_records(
    values: Sequence[DiagnosticRecord], query: str
) -> tuple[DiagnosticRecord, ...]:
    needle = query.strip().casefold()
    if not needle:
        return tuple(values)
    result = []
    for item in values:
        haystack = " ".join(
            (
                item.kind.value,
                item.source_table,
                str(item.snapshot_id),
                *(field.name for field in item.fields),
                *(field.display for field in item.fields),
                *item.warnings,
            )
        ).casefold()
        if needle in haystack:
            result.append(item)
    return tuple(result)


def project_record_rows(
    values: Sequence[DiagnosticRecord],
) -> tuple[DiagnosticRecordRow, ...]:
    rows = []
    for item in values:
        anchor = "" if item.anchor_ea is None else f"0x{item.anchor_ea:X}"
        summary = "; ".join(
            f"{field.name}={field.display}" for field in item.fields[:6]
        )
        if len(item.fields) > 6:
            summary += f"; ... ({len(item.fields)} fields)"
        detail_lines = (
            f"View: {item.kind.value}",
            f"Table: {item.source_table}",
            f"Snapshot ID: {item.snapshot_id}",
            f"Record: {item.ordinal}",
            f"Anchor: {anchor or 'unavailable'}",
            "",
            *(f"{field.name}: {field.display}" for field in item.fields),
        )
        if item.warnings:
            detail_lines += (
                "",
                "Warnings:",
                *(f"- {warning}" for warning in item.warnings),
            )
        rows.append(
            DiagnosticRecordRow(
                key=(
                    f"{item.kind.value}:{item.source_table}:"
                    f"{item.snapshot_id}:{item.ordinal}"
                ),
                source_table=item.source_table,
                ordinal=item.ordinal,
                anchor=anchor,
                summary=summary,
                detail="\n".join(detail_lines),
                record=item,
            )
        )
    return tuple(rows)


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


def group_databases_by_function(
    values: Sequence[DiagnosticDatabaseSummary],
) -> tuple[DiagnosticFunctionGroup, ...]:
    grouped: dict[int, list[DiagnosticDatabaseSummary]] = {}
    for database in values:
        for function_ea in database.function_eas:
            grouped.setdefault(function_ea, []).append(database)
    return tuple(
        DiagnosticFunctionGroup(function_ea, sort_databases(grouped[function_ea]))
        for function_ea in sorted(grouped)
    )


def record_jump_ea(record: DiagnosticRecord) -> int | None:
    return record.anchor_ea


def _scope_value(plan: object) -> str:
    scope = getattr(plan, "scope", "")
    return str(getattr(scope, "value", scope))


def cleanup_required_phrase(plan: object) -> str:
    scope = _scope_value(plan)
    if scope in {"all_snapshots", "all_closed_databases"}:
        return "DELETE ALL"
    if scope == "selected_databases":
        return "QUARANTINE"
    return ""


def project_cleanup_plan(plan: object) -> DiagnosticCleanupPlanView:
    targets = tuple(getattr(plan, "targets", ()))
    skipped = tuple(getattr(plan, "skipped_active_paths", ()))
    snapshot_count = sum(
        len(tuple(getattr(target, "snapshot_ids", ()))) for target in targets
    )
    estimated_rows = sum(
        int(getattr(target, "estimated_rows", 0)) for target in targets
    )
    lines = [
        f"Scope: {_scope_value(plan)}",
        f"Eligible databases: {len(targets)}",
        f"Snapshot IDs: {snapshot_count}",
        f"Estimated affected rows: {estimated_rows}",
    ]
    for target in targets:
        ids = tuple(getattr(target, "snapshot_ids", ()))
        display_ids = ", ".join(str(value) for value in ids) or "none"
        lines.extend(
            (
                "",
                f"Path: {getattr(target, 'path', '')}",
                f"  snapshot IDs: {display_ids}",
                f"  estimated affected rows: {int(getattr(target, 'estimated_rows', 0))}",
            )
        )
    if skipped:
        lines.extend(("", "Active databases skipped:"))
        lines.extend(f"- {path}" for path in skipped)
    required = cleanup_required_phrase(plan)
    if required:
        lines.extend(("", f"Typed confirmation required: {required}"))
    return DiagnosticCleanupPlanView(
        text="\n".join(lines),
        required_phrase=required,
        target_count=len(targets),
        snapshot_count=snapshot_count,
        estimated_rows=estimated_rows,
    )


def cleanup_confirmation_matches(plan: object, entered: str) -> bool:
    required = cleanup_required_phrase(plan)
    return not required or entered.strip().casefold() == required.casefold()


def cleanup_execution_options(plan: object) -> DiagnosticCleanupExecutionOptions:
    """Expose optional storage reclamation only for snapshot cleanup plans."""

    scope = getattr(plan, "scope", None)
    return DiagnosticCleanupExecutionOptions(
        show_vacuum_after=scope
        in {
            DiagnosticCleanupScope.SELECTED_SNAPSHOTS,
            DiagnosticCleanupScope.ALL_SNAPSHOTS,
            DiagnosticCleanupScope.KEEP_LATEST,
        }
    )


def _outcome_lines(values: Sequence[object]) -> tuple[str, ...]:
    if not values:
        return ("- Not requested",)
    return tuple(
        "- "
        + str(
            getattr(getattr(item, "status", ""), "value", getattr(item, "status", ""))
        )
        + f" | {getattr(item, 'path', '')} | {getattr(item, 'detail', '')}"
        + (
            f" | affected={int(getattr(item, 'affected', 0))}"
            if int(getattr(item, "affected", 0))
            else ""
        )
        for item in values
    )


def project_cleanup_result(result: object) -> str:
    logical = tuple(getattr(result, "logical", ()))
    wal = tuple(getattr(result, "wal", ()))
    vacuum = tuple(getattr(result, "vacuum", ()))
    quarantine = tuple(getattr(result, "quarantine", ()))
    integrity = []
    for item in logical:
        status = str(
            getattr(getattr(item, "status", ""), "value", getattr(item, "status", ""))
        )
        if status == "succeeded":
            integrity.append(
                f"- passed inside cleanup transaction | {getattr(item, 'path', '')}"
            )
        else:
            integrity.append(
                f"- transaction did not commit | {getattr(item, 'path', '')} | "
                f"{getattr(item, 'detail', '')}"
            )
    lines = ["Cleanup transaction", *_outcome_lines(logical), "", "Integrity check"]
    lines.extend(integrity or ("- Not applicable",))
    lines.extend(("", "Quarantine / database sidecars", *_outcome_lines(quarantine)))
    lines.extend(("", "WAL / sidecars", *_outcome_lines(wal)))
    lines.extend(("", "Vacuum", *_outcome_lines(vacuum)))
    return "\n".join(lines)


def diagnostic_action_states(
    selected_databases: Sequence[DiagnosticDatabaseSummary],
    *,
    selected_snapshot_ids: Sequence[int],
    all_databases: Sequence[DiagnosticDatabaseSummary] | None = None,
) -> tuple[DiagnosticActionState, ...]:
    inactive = tuple(item for item in selected_databases if not item.active)
    inventory = (
        tuple(selected_databases) if all_databases is None else tuple(all_databases)
    )
    all_closed = tuple(item for item in inventory if not item.active)
    active_count = len(selected_databases) - len(inactive)
    active_note = (
        f"; {active_count} active database(s) will be skipped" if active_count else ""
    )
    has_database = bool(selected_databases)
    has_inactive = bool(inactive)
    has_snapshots = bool(selected_snapshot_ids)

    def state(
        action_id: str, enabled: bool, ready: str, missing: str
    ) -> DiagnosticActionState:
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
            "keep_latest",
            has_inactive,
            "Closed databases are ready for a retention plan",
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
            bool(all_closed),
            "Closed databases are ready for quarantine",
            "No closed databases are available",
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
