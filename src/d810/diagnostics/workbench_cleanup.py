"""Read-only cleanup planning and rollback-safe diagnostic database cleanup."""

from __future__ import annotations

import contextlib
import os
import sqlite3
from pathlib import Path

from d810.core.diag.ownership import (
    legacy_snapshot_owned_tables,
    snapshot_owned_tables,
)
from d810.core.typing import Callable, Iterable, Sequence
from d810.diagnostics.workbench_inventory import (
    _normalized_path,
    _quote_identifier,
    _readonly_connection,
    _table_columns,
    _tables,
)
from d810.diagnostics.workbench_models import (
    DiagnosticCleanupPlan,
    DiagnosticCleanupResult,
    DiagnosticCleanupScope,
    DiagnosticCleanupTarget,
    DiagnosticOperation,
    DiagnosticOperationOutcome,
    DiagnosticOperationStatus,
)


class DiagnosticCleanupPlanError(RuntimeError):
    """The requested database cannot be cleaned safely."""


def _placeholders(values: Sequence[int]) -> str:
    return ",".join("?" for _ in values)


class DiagnosticCleanupService:
    """Build explicit plans before executing any destructive operation."""

    def __init__(
        self,
        *,
        active_paths_provider: Callable[[], Iterable[os.PathLike[str] | str]],
        quarantine_directory: os.PathLike[str] | str | None = None,
    ) -> None:
        self._active_paths_provider = active_paths_provider
        self._quarantine_directory = (
            Path(quarantine_directory).expanduser()
            if quarantine_directory is not None
            else None
        )

    def _active_paths(self) -> set[str]:
        return {_normalized_path(path) for path in self._active_paths_provider()}

    @staticmethod
    def _schema_tables(connection: sqlite3.Connection) -> tuple[str, ...]:
        existing = _tables(connection)
        if "snapshots" not in existing:
            raise DiagnosticCleanupPlanError("missing snapshots table")
        snapshot_columns = set(_table_columns(connection, "snapshots"))
        if not {"id", "timestamp"}.issubset(snapshot_columns):
            raise DiagnosticCleanupPlanError(
                "snapshots table does not contain id and timestamp"
            )
        allowed = set(snapshot_owned_tables()).union(legacy_snapshot_owned_tables())
        actual: list[str] = []
        unknown: list[str] = []
        for table in sorted(existing):
            if table.startswith("sqlite_") or table == "snapshots":
                continue
            if "snapshot_id" not in _table_columns(connection, table):
                continue
            if table not in allowed:
                unknown.append(table)
            else:
                actual.append(table)
        if unknown:
            raise DiagnosticCleanupPlanError(
                "unknown snapshot-owned table(s): " + ", ".join(unknown)
            )
        return tuple(actual)

    @staticmethod
    def _snapshot_ids(connection: sqlite3.Connection) -> tuple[int, ...]:
        return tuple(
            int(row[0])
            for row in connection.execute("SELECT id FROM snapshots ORDER BY id")
        )

    @staticmethod
    def _estimated_rows(
        connection: sqlite3.Connection,
        owned_tables: Sequence[str],
        snapshot_ids: Sequence[int],
    ) -> int:
        if not snapshot_ids:
            return 0
        placeholders = _placeholders(snapshot_ids)
        parameters = tuple(snapshot_ids)
        total = int(
            connection.execute(
                f"SELECT COUNT(*) FROM snapshots WHERE id IN ({placeholders})",
                parameters,
            ).fetchone()[0]
        )
        for table in owned_tables:
            total += int(
                connection.execute(
                    f"SELECT COUNT(*) FROM {_quote_identifier(table)} "
                    f"WHERE snapshot_id IN ({placeholders})",
                    parameters,
                ).fetchone()[0]
            )
        return total

    def _target(
        self,
        path: os.PathLike[str] | str,
        snapshot_ids: Sequence[int] | None,
    ) -> DiagnosticCleanupTarget:
        normalized = _normalized_path(path)
        try:
            with contextlib.closing(_readonly_connection(normalized)) as connection:
                owned = self._schema_tables(connection)
                existing_ids = self._snapshot_ids(connection)
                requested = (
                    existing_ids
                    if snapshot_ids is None
                    else tuple(sorted(set(int(value) for value in snapshot_ids)))
                )
                missing = tuple(value for value in requested if value not in existing_ids)
                if missing:
                    raise DiagnosticCleanupPlanError(
                        "snapshot ID(s) not present: "
                        + ", ".join(str(value) for value in missing)
                    )
                rows = self._estimated_rows(connection, owned, requested)
        except DiagnosticCleanupPlanError:
            raise
        except (OSError, sqlite3.Error) as error:
            raise DiagnosticCleanupPlanError(
                f"cannot inspect diagnostic database {normalized}: {error}"
            ) from error
        return DiagnosticCleanupTarget(
            path=normalized,
            snapshot_ids=requested,
            active=False,
            estimated_rows=rows,
        )

    @staticmethod
    def _confirmation(
        scope: DiagnosticCleanupScope,
        targets: Sequence[DiagnosticCleanupTarget],
        skipped: Sequence[str],
    ) -> str:
        if scope is DiagnosticCleanupScope.VACUUM:
            operation = "Vacuum"
        elif scope in {
            DiagnosticCleanupScope.SELECTED_DATABASES,
            DiagnosticCleanupScope.ALL_CLOSED_DATABASES,
        }:
            operation = "Quarantine"
        else:
            operation = "Delete snapshot rows from"
        details = []
        for target in targets:
            ids = ", ".join(str(value) for value in target.snapshot_ids) or "none"
            details.append(
                f"{target.path} [snapshot IDs: {ids}; {target.estimated_rows} rows]"
            )
        if skipped:
            details.append(
                "Active database(s) skipped: " + ", ".join(sorted(skipped))
            )
        if not details:
            details.append("No eligible closed diagnostic databases")
        return f"{operation}: " + "; ".join(details)

    def _plan_one(
        self,
        scope: DiagnosticCleanupScope,
        path: os.PathLike[str] | str,
        ids_provider: Callable[[sqlite3.Connection], Sequence[int]],
    ) -> DiagnosticCleanupPlan:
        normalized = _normalized_path(path)
        if normalized in self._active_paths():
            skipped = (normalized,)
            return DiagnosticCleanupPlan(
                scope=scope,
                targets=(),
                skipped_active_paths=skipped,
                confirmation=self._confirmation(scope, (), skipped),
            )
        try:
            with contextlib.closing(_readonly_connection(normalized)) as connection:
                self._schema_tables(connection)
                ids = tuple(int(value) for value in ids_provider(connection))
        except DiagnosticCleanupPlanError:
            raise
        except (OSError, sqlite3.Error) as error:
            raise DiagnosticCleanupPlanError(
                f"cannot inspect diagnostic database {normalized}: {error}"
            ) from error
        target = self._target(normalized, ids)
        return DiagnosticCleanupPlan(
            scope=scope,
            targets=(target,),
            skipped_active_paths=(),
            confirmation=self._confirmation(scope, (target,), ()),
        )

    def plan_selected_snapshots(
        self, path: os.PathLike[str] | str, snapshot_ids: Sequence[int]
    ) -> DiagnosticCleanupPlan:
        requested = tuple(sorted(set(int(value) for value in snapshot_ids)))
        return self._plan_one(
            DiagnosticCleanupScope.SELECTED_SNAPSHOTS,
            path,
            lambda _connection: requested,
        )

    def plan_all_snapshots(
        self, path: os.PathLike[str] | str
    ) -> DiagnosticCleanupPlan:
        return self._plan_one(
            DiagnosticCleanupScope.ALL_SNAPSHOTS,
            path,
            self._snapshot_ids,
        )

    def plan_keep_latest(
        self, path: os.PathLike[str] | str, keep: int
    ) -> DiagnosticCleanupPlan:
        if keep < 0:
            raise ValueError("keep must be non-negative")

        def ids(connection: sqlite3.Connection) -> tuple[int, ...]:
            ordered = tuple(
                int(row[0])
                for row in connection.execute(
                    "SELECT id FROM snapshots ORDER BY timestamp DESC, id DESC"
                )
            )
            return tuple(sorted(ordered[keep:]))

        return self._plan_one(DiagnosticCleanupScope.KEEP_LATEST, path, ids)

    def plan_older_than(
        self, path: os.PathLike[str] | str, recorded_before: float
    ) -> DiagnosticCleanupPlan:
        return self._plan_one(
            DiagnosticCleanupScope.OLDER_THAN,
            path,
            lambda connection: tuple(
                int(row[0])
                for row in connection.execute(
                    "SELECT id FROM snapshots WHERE timestamp < ? ORDER BY id",
                    (float(recorded_before),),
                )
            ),
        )

    def _plan_databases(
        self,
        scope: DiagnosticCleanupScope,
        paths: Iterable[os.PathLike[str] | str],
        *,
        include_snapshot_ids: bool,
    ) -> DiagnosticCleanupPlan:
        active = self._active_paths()
        normalized_paths = tuple(sorted({_normalized_path(path) for path in paths}))
        skipped = tuple(path for path in normalized_paths if path in active)
        targets = []
        for path in normalized_paths:
            if path in active:
                continue
            target = self._target(path, None)
            if not include_snapshot_ids:
                target = DiagnosticCleanupTarget(
                    path=target.path,
                    snapshot_ids=(),
                    active=False,
                    estimated_rows=0,
                )
            targets.append(target)
        result = tuple(targets)
        return DiagnosticCleanupPlan(
            scope=scope,
            targets=result,
            skipped_active_paths=skipped,
            confirmation=self._confirmation(scope, result, skipped),
        )

    def plan_selected_databases(
        self, paths: Iterable[os.PathLike[str] | str]
    ) -> DiagnosticCleanupPlan:
        return self._plan_databases(
            DiagnosticCleanupScope.SELECTED_DATABASES,
            paths,
            include_snapshot_ids=True,
        )

    def plan_all_closed_databases(
        self, paths: Iterable[os.PathLike[str] | str]
    ) -> DiagnosticCleanupPlan:
        return self._plan_databases(
            DiagnosticCleanupScope.ALL_CLOSED_DATABASES,
            paths,
            include_snapshot_ids=True,
        )

    def plan_vacuum(
        self, paths: Iterable[os.PathLike[str] | str]
    ) -> DiagnosticCleanupPlan:
        return self._plan_databases(
            DiagnosticCleanupScope.VACUUM,
            paths,
            include_snapshot_ids=False,
        )

    @staticmethod
    def _outcome(
        operation: DiagnosticOperation,
        path: str,
        status: DiagnosticOperationStatus,
        detail: str,
        affected: int = 0,
    ) -> DiagnosticOperationOutcome:
        return DiagnosticOperationOutcome(
            operation=operation,
            path=path,
            status=status,
            detail=detail,
            affected=affected,
        )

    @staticmethod
    def _integrity_errors(
        connection: sqlite3.Connection, owned_tables: Sequence[str]
    ) -> tuple[str, ...]:
        errors: list[str] = []
        for table in owned_tables:
            orphan_count = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM {_quote_identifier(table)} AS child "
                    "LEFT JOIN snapshots AS parent ON parent.id=child.snapshot_id "
                    "WHERE parent.id IS NULL"
                ).fetchone()[0]
            )
            if orphan_count:
                errors.append(f"{table} has {orphan_count} orphan row(s)")
        foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_key_errors:
            errors.append(f"foreign_key_check returned {len(foreign_key_errors)} row(s)")
        integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
        integrity_messages = tuple(
            str(row[0]) for row in integrity_rows if str(row[0]).casefold() != "ok"
        )
        errors.extend(integrity_messages)
        return tuple(errors)

    def _delete_target(
        self, target: DiagnosticCleanupTarget
    ) -> DiagnosticOperationOutcome:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(target.path, timeout=0.1, isolation_level=None)
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("BEGIN IMMEDIATE")
            owned = self._schema_tables(connection)
            existing = set(self._snapshot_ids(connection))
            missing = tuple(value for value in target.snapshot_ids if value not in existing)
            if missing:
                raise DiagnosticCleanupPlanError(
                    "cleanup plan is stale; missing snapshot ID(s): "
                    + ", ".join(str(value) for value in missing)
                )
            current_rows = self._estimated_rows(
                connection, owned, target.snapshot_ids
            )
            if current_rows != target.estimated_rows:
                raise DiagnosticCleanupPlanError(
                    "cleanup plan is stale; affected row count changed from "
                    f"{target.estimated_rows} to {current_rows}"
                )
            affected = 0
            if target.snapshot_ids:
                placeholders = _placeholders(target.snapshot_ids)
                parameters = tuple(target.snapshot_ids)
                for table in owned:
                    cursor = connection.execute(
                        f"DELETE FROM {_quote_identifier(table)} "
                        f"WHERE snapshot_id IN ({placeholders})",
                        parameters,
                    )
                    affected += max(0, int(cursor.rowcount))
                parent = connection.execute(
                    f"DELETE FROM snapshots WHERE id IN ({placeholders})",
                    parameters,
                )
                affected += max(0, int(parent.rowcount))
            integrity_errors = self._integrity_errors(connection, owned)
            if integrity_errors:
                raise DiagnosticCleanupPlanError("; ".join(integrity_errors))
            connection.execute("COMMIT")
            return self._outcome(
                DiagnosticOperation.LOGICAL_DELETE,
                target.path,
                DiagnosticOperationStatus.SUCCEEDED,
                "Logical snapshot deletion committed",
                affected,
            )
        except (OSError, sqlite3.Error, DiagnosticCleanupPlanError) as error:
            if connection is not None and connection.in_transaction:
                connection.execute("ROLLBACK")
            return self._outcome(
                DiagnosticOperation.LOGICAL_DELETE,
                target.path,
                DiagnosticOperationStatus.FAILED,
                str(error),
            )
        finally:
            if connection is not None:
                connection.close()

    @classmethod
    def _checkpoint_path(cls, path: str) -> DiagnosticOperationOutcome:
        try:
            with contextlib.closing(
                sqlite3.connect(path, timeout=0.1, isolation_level=None)
            ) as connection:
                row = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            busy = int(row[0]) if row else 0
            if busy:
                return cls._outcome(
                    DiagnosticOperation.WAL_CHECKPOINT,
                    path,
                    DiagnosticOperationStatus.FAILED,
                    f"WAL checkpoint remained busy ({busy})",
                )
            return cls._outcome(
                DiagnosticOperation.WAL_CHECKPOINT,
                path,
                DiagnosticOperationStatus.SUCCEEDED,
                "WAL checkpoint completed",
            )
        except (OSError, sqlite3.Error) as error:
            return cls._outcome(
                DiagnosticOperation.WAL_CHECKPOINT,
                path,
                DiagnosticOperationStatus.FAILED,
                str(error),
            )

    @staticmethod
    def _vacuum_path(path: str) -> None:
        with contextlib.closing(
            sqlite3.connect(path, timeout=0.1, isolation_level=None)
        ) as connection:
            connection.execute("VACUUM")

    @classmethod
    def _vacuum_outcome(cls, path: str) -> DiagnosticOperationOutcome:
        try:
            cls._vacuum_path(path)
            return cls._outcome(
                DiagnosticOperation.VACUUM,
                path,
                DiagnosticOperationStatus.SUCCEEDED,
                "Vacuum completed",
            )
        except (OSError, sqlite3.Error) as error:
            return cls._outcome(
                DiagnosticOperation.VACUUM,
                path,
                DiagnosticOperationStatus.FAILED,
                str(error),
            )

    @staticmethod
    def _move(source: Path, destination: Path) -> None:
        os.replace(source, destination)

    def _quarantine_target(
        self, target: DiagnosticCleanupTarget
    ) -> DiagnosticOperationOutcome:
        try:
            current = self._target(target.path, None)
        except DiagnosticCleanupPlanError as error:
            return self._outcome(
                DiagnosticOperation.QUARANTINE,
                target.path,
                DiagnosticOperationStatus.FAILED,
                str(error),
            )
        if (
            current.snapshot_ids != target.snapshot_ids
            or current.estimated_rows != target.estimated_rows
        ):
            return self._outcome(
                DiagnosticOperation.QUARANTINE,
                target.path,
                DiagnosticOperationStatus.FAILED,
                "cleanup plan is stale; database contents changed before quarantine",
            )
        source = Path(target.path)
        root = self._quarantine_directory or source.parent / ".d810-quarantine"
        root.mkdir(parents=True, exist_ok=True)
        destination = root / source.name
        suffix = 1
        while destination.exists():
            destination = root / f"{source.name}.{suffix}"
            suffix += 1
        destination.mkdir()
        candidates = (source, Path(str(source) + "-wal"), Path(str(source) + "-shm"))
        moved: list[tuple[Path, Path]] = []
        try:
            if not source.exists():
                raise FileNotFoundError(source)
            for candidate in candidates:
                if not candidate.exists():
                    continue
                target_path = destination / candidate.name
                self._move(candidate, target_path)
                moved.append((candidate, target_path))
            return self._outcome(
                DiagnosticOperation.QUARANTINE,
                target.path,
                DiagnosticOperationStatus.SUCCEEDED,
                f"Moved to reversible quarantine {destination}",
                len(moved),
            )
        except OSError as error:
            rollback_errors: list[str] = []
            for original, quarantined in reversed(moved):
                try:
                    self._move(quarantined, original)
                except OSError as rollback_error:
                    rollback_errors.append(str(rollback_error))
            detail = str(error)
            if rollback_errors:
                detail += "; quarantine rollback failed: " + "; ".join(rollback_errors)
            return self._outcome(
                DiagnosticOperation.QUARANTINE,
                target.path,
                DiagnosticOperationStatus.FAILED,
                detail,
            )

    def execute(
        self,
        plan: DiagnosticCleanupPlan,
        *,
        checkpoint_wal: bool = True,
        vacuum_after: bool = False,
    ) -> DiagnosticCleanupResult:
        active = self._active_paths()
        logical: list[DiagnosticOperationOutcome] = []
        wal: list[DiagnosticOperationOutcome] = []
        vacuum: list[DiagnosticOperationOutcome] = []
        quarantine: list[DiagnosticOperationOutcome] = []
        database_scopes = {
            DiagnosticCleanupScope.SELECTED_DATABASES,
            DiagnosticCleanupScope.ALL_CLOSED_DATABASES,
        }

        for target in plan.targets:
            if target.path in active:
                if plan.scope in database_scopes:
                    operation = DiagnosticOperation.QUARANTINE
                    collection = quarantine
                elif plan.scope is DiagnosticCleanupScope.VACUUM:
                    operation = DiagnosticOperation.VACUUM
                    collection = vacuum
                else:
                    operation = DiagnosticOperation.LOGICAL_DELETE
                    collection = logical
                collection.append(
                    self._outcome(
                        operation,
                        target.path,
                        DiagnosticOperationStatus.SKIPPED_ACTIVE,
                        "Database became active after the cleanup plan was built",
                    )
                )
                continue

            if plan.scope in database_scopes:
                quarantine.append(self._quarantine_target(target))
                continue
            if plan.scope is DiagnosticCleanupScope.VACUUM:
                try:
                    self._target(target.path, None)
                except DiagnosticCleanupPlanError as error:
                    vacuum.append(
                        self._outcome(
                            DiagnosticOperation.VACUUM,
                            target.path,
                            DiagnosticOperationStatus.FAILED,
                            str(error),
                        )
                    )
                else:
                    vacuum.append(self._vacuum_outcome(target.path))
                continue

            logical_outcome = self._delete_target(target)
            logical.append(logical_outcome)
            if logical_outcome.status is not DiagnosticOperationStatus.SUCCEEDED:
                continue
            if checkpoint_wal:
                wal.append(self._checkpoint_path(target.path))
            if vacuum_after:
                vacuum.append(self._vacuum_outcome(target.path))

        return DiagnosticCleanupResult(
            plan=plan,
            logical=tuple(logical),
            wal=tuple(wal),
            vacuum=tuple(vacuum),
            quarantine=tuple(quarantine),
        )
