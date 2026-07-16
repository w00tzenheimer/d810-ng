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
    DiagnosticCleanupScope,
    DiagnosticCleanupTarget,
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
