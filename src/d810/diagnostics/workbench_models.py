"""Immutable records for the diagnostic database explorer and cleaner."""

from __future__ import annotations

import dataclasses
import enum

from d810.core.typing import Any


class DiagnosticViewKind(str, enum.Enum):
    BLOCKS = "blocks"
    INSTRUCTIONS = "instructions"
    STATE_MACHINE = "state_machine"
    MODIFICATIONS = "modifications"
    FACTS = "facts"
    CONFLICTS = "conflicts"
    PROVENANCE = "provenance"
    RENDERED_PROGRAMS = "rendered_programs"


class DiagnosticCleanupScope(str, enum.Enum):
    SELECTED_SNAPSHOTS = "selected_snapshots"
    ALL_SNAPSHOTS = "all_snapshots"
    KEEP_LATEST = "keep_latest"
    OLDER_THAN = "older_than"
    SELECTED_DATABASES = "selected_databases"
    ALL_CLOSED_DATABASES = "all_closed_databases"
    VACUUM = "vacuum"


class DiagnosticOperation(str, enum.Enum):
    LOGICAL_DELETE = "logical_delete"
    WAL_CHECKPOINT = "wal_checkpoint"
    VACUUM = "vacuum"
    QUARANTINE = "quarantine"


class DiagnosticOperationStatus(str, enum.Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED_ACTIVE = "skipped_active"
    SKIPPED = "skipped"


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticDatabaseSummary:
    path: str
    recorded_at: float | None
    recorded_at_source: str
    function_eas: tuple[int, ...]
    size_bytes: int
    snapshot_count: int
    row_count: int
    active: bool
    schema_version: int | None
    readable: bool
    error: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticSnapshotSummary:
    database_path: str
    snapshot_id: int
    label: str
    function_ea: int
    maturity: str
    phase: str
    block_count: int
    recorded_at: float
    row_count: int


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticField:
    name: str
    value: Any
    display: str
    anchor_ea: int | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticRecord:
    kind: DiagnosticViewKind
    source_table: str
    snapshot_id: int
    ordinal: int
    fields: tuple[DiagnosticField, ...]
    warnings: tuple[str, ...]
    anchor_ea: int | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticCleanupTarget:
    path: str
    snapshot_ids: tuple[int, ...]
    active: bool
    estimated_rows: int


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticCleanupPlan:
    scope: DiagnosticCleanupScope
    targets: tuple[DiagnosticCleanupTarget, ...]
    skipped_active_paths: tuple[str, ...]
    confirmation: str


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticOperationOutcome:
    operation: DiagnosticOperation
    path: str
    status: DiagnosticOperationStatus
    detail: str
    affected: int


@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticCleanupResult:
    plan: DiagnosticCleanupPlan
    logical: tuple[DiagnosticOperationOutcome, ...]
    wal: tuple[DiagnosticOperationOutcome, ...]
    vacuum: tuple[DiagnosticOperationOutcome, ...]
    quarantine: tuple[DiagnosticOperationOutcome, ...]
