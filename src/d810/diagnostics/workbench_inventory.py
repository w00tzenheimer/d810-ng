"""Read-only inventory and structured inspection for diagnostic databases."""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
from pathlib import Path
from urllib.parse import quote

from d810.core.diag.ownership import (
    legacy_snapshot_owned_tables,
    snapshot_owned_tables,
)
from d810.core.typing import Callable, Iterable
from d810.diagnostics.workbench_models import (
    DiagnosticDatabaseSummary,
    DiagnosticField,
    DiagnosticRecord,
    DiagnosticSnapshotSummary,
    DiagnosticViewKind,
)

_VIEW_TABLES: dict[DiagnosticViewKind, tuple[str, ...]] = {
    DiagnosticViewKind.BLOCKS: ("blocks", "block_observations", "block_classification"),
    DiagnosticViewKind.INSTRUCTIONS: ("instructions",),
    DiagnosticViewKind.STATE_MACHINE: (
        "state_cfg_nodes",
        "state_cfg_edges",
        "state_cfg_node_blocks",
        "state_cfg_local_segments",
        "state_cfg_local_edges",
        "state_cfg_edge_diagnostics",
        "state_cfg_frontier_closure_diagnostics",
        "state_cfg_edge_alternate_correlations",
        "state_cfg_edge_alternate_selections",
        "condition_chain_interval_dispatcher_rows",
        "state_dispatcher_rows",
        "state_transition_condition_chain_resolutions",
        "state_transition_dispatch_resolutions",
        "switch_case_transition_facts",
        "branch_ownership_proofs",
        "branch_witness_decisions",
        "exit_path_shortcut_decisions",
    ),
    DiagnosticViewKind.MODIFICATIONS: ("modifications",),
    DiagnosticViewKind.FACTS: (
        "fact_observations",
        "fact_mappings",
        "fact_consumers",
        "region_shape_features",
    ),
    DiagnosticViewKind.CONFLICTS: ("fact_conflicts",),
    DiagnosticViewKind.PROVENANCE: ("cfg_provenance", "block_lineage"),
    DiagnosticViewKind.RENDERED_PROGRAMS: (
        "rendered_programs",
        "rendered_program_nodes",
        "rendered_program_lines",
    ),
}

_NON_IDENTITY_BLOCK_COLUMNS = {
    "block_count",
    "block_type",
    "block_index",
    "block_fingerprint",
    "source_block_label",
    "target_block_label",
    "source_block_ea_hex",
    "source_block_ea_i64",
    "target_block_ea_hex",
    "target_block_ea_i64",
}


def _normalized_path(path: os.PathLike[str] | str) -> str:
    return str(Path(path).expanduser().resolve())


def _readonly_connection(path: os.PathLike[str] | str) -> sqlite3.Connection:
    absolute = _normalized_path(path)
    wal_path = Path(absolute + "-wal")
    if wal_path.exists() and wal_path.stat().st_size:
        raise sqlite3.DatabaseError(
            "uncheckpointed WAL is not opened by the immutable explorer"
        )
    uri = "file:" + quote(absolute, safe="/") + "?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }


def _table_columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(
        str(row[1])
        for row in connection.execute(
            f"PRAGMA table_info({_quote_identifier(table)})"
        ).fetchall()
    )


def _owned_tables_for(existing: set[str]) -> tuple[str, ...]:
    candidates = set(snapshot_owned_tables()).union(legacy_snapshot_owned_tables())
    return tuple(sorted(existing.intersection(candidates)))


def _is_block_identity(name: str) -> bool:
    if (
        name in _NON_IDENTITY_BLOCK_COLUMNS
        or name == "snapshot_id"
        or "fingerprint" in name
        or "label" in name
        or "_ea_" in name
        or name.endswith(("ea_hex", "ea_i64"))
    ):
        return False
    return (
        "serial" in name
        or name.endswith(("succs", "preds"))
        or "successor" in name
        or "predecessor" in name
        or "block" in name
        or name in {"target_entry", "dispatcher_entry"}
    )


def _block_ref(serial: int, anchors: dict[int, str]) -> str | None:
    anchor = anchors.get(serial)
    return f"blk{serial}@{anchor}" if anchor else None


def _identity_display(value: object, anchors: dict[int, str]) -> str | None:
    candidate = value
    if isinstance(candidate, str):
        stripped = candidate.strip()
        if not stripped:
            return ""
        try:
            candidate = json.loads(stripped)
        except (TypeError, ValueError, json.JSONDecodeError):
            try:
                candidate = int(stripped, 0)
            except ValueError:
                return stripped
    if isinstance(candidate, bool):
        return str(candidate)
    if isinstance(candidate, int):
        return _block_ref(candidate, anchors)
    if isinstance(candidate, (list, tuple)):
        refs: list[str] = []
        for item in candidate:
            if not isinstance(item, int) or isinstance(item, bool):
                return None
            ref = _block_ref(item, anchors)
            if ref is None:
                return None
            refs.append(ref)
        return ", ".join(refs)
    if isinstance(candidate, dict):
        return None
    return str(candidate)


def _display_anchor_ea(display: str) -> int | None:
    if "@" not in display:
        return None
    candidate = display.split("@", 1)[1].split(",", 1)[0].strip()
    try:
        return int(candidate, 0)
    except ValueError:
        return None


def _value_anchor_ea(name: str, value: object) -> int | None:
    if value is None:
        return None
    if name == "ea_i64" or name.endswith("_ea_i64"):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    if name == "ea_hex" or name.endswith("_ea_hex"):
        try:
            return int(str(value), 0)
        except ValueError:
            return None
    return None


def _view_table_candidates(table: str) -> tuple[str, ...]:
    if table.startswith("state_cfg_"):
        return (table, "dag_" + table.removeprefix("state_cfg_"))
    return (table,)


def _anchors(
    connection: sqlite3.Connection, snapshot_id: int, existing: set[str]
) -> dict[int, str]:
    anchors: dict[int, str] = {}
    if "blocks" in existing:
        columns = set(_table_columns(connection, "blocks"))
        if {"snapshot_id", "serial", "start_ea_hex"}.issubset(columns):
            for row in connection.execute(
                "SELECT serial, start_ea_hex FROM blocks WHERE snapshot_id=?",
                (snapshot_id,),
            ):
                if row[1]:
                    anchors[int(row[0])] = str(row[1])
    if "instructions" in existing:
        columns = set(_table_columns(connection, "instructions"))
        if {"snapshot_id", "block_serial", "ea_hex"}.issubset(columns):
            for row in connection.execute(
                "SELECT block_serial, MIN(ea_hex) FROM instructions "
                "WHERE snapshot_id=? GROUP BY block_serial",
                (snapshot_id,),
            ):
                if row[1] and int(row[0]) not in anchors:
                    anchors[int(row[0])] = str(row[1])
    return anchors


class DiagnosticInventoryService:
    """Discover and inspect diagnostics without ever opening a write connection."""

    def __init__(
        self,
        *,
        roots: Iterable[os.PathLike[str] | str],
        excluded_roots: Iterable[os.PathLike[str] | str] = (),
        active_paths_provider: (
            Callable[[], Iterable[os.PathLike[str] | str]] | None
        ) = None,
    ) -> None:
        self._roots = tuple(Path(root).expanduser() for root in roots)
        self._excluded_roots = tuple(
            Path(root).expanduser().resolve() for root in excluded_roots
        )
        self._active_paths_provider = active_paths_provider or (lambda: ())

    def _active_paths(self) -> set[str]:
        return {_normalized_path(path) for path in self._active_paths_provider()}

    def paths(self) -> tuple[Path, ...]:
        found: set[Path] = set()

        def eligible(path: Path) -> bool:
            resolved = path.resolve()
            return not any(
                resolved == excluded or excluded in resolved.parents
                for excluded in self._excluded_roots
            )

        for root in self._roots:
            if (
                root.is_file()
                and root.name.endswith(".diag.sqlite3")
                and eligible(root)
            ):
                found.add(root.resolve())
            elif root.is_dir():
                found.update(
                    path.resolve()
                    for path in root.rglob("*.diag.sqlite3")
                    if eligible(path)
                )
        return tuple(sorted(found, key=lambda path: str(path)))

    def databases(self) -> tuple[DiagnosticDatabaseSummary, ...]:
        active_paths = self._active_paths()
        summaries = tuple(self._database(path, active_paths) for path in self.paths())
        return tuple(
            sorted(
                summaries,
                key=lambda item: (
                    -(
                        item.recorded_at
                        if item.recorded_at is not None
                        else float("-inf")
                    ),
                    item.path,
                ),
            )
        )

    def _database(
        self, path: Path, active_paths: set[str]
    ) -> DiagnosticDatabaseSummary:
        normalized = _normalized_path(path)
        size = sum(
            candidate.stat().st_size
            for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm"))
            if candidate.exists()
        )
        try:
            with contextlib.closing(_readonly_connection(path)) as connection:
                existing = _tables(connection)
                if "snapshots" not in existing:
                    raise sqlite3.DatabaseError("missing snapshots table")
                row = connection.execute(
                    "SELECT MAX(timestamp), COUNT(*) FROM snapshots"
                ).fetchone()
                recorded_at = float(row[0]) if row[0] is not None else None
                function_eas = tuple(
                    int(item[0])
                    for item in connection.execute(
                        "SELECT DISTINCT func_ea_i64 FROM snapshots "
                        "ORDER BY func_ea_i64"
                    ).fetchall()
                )
                schema_version = int(
                    connection.execute("PRAGMA user_version").fetchone()[0]
                )
                row_count = int(row[1])
                for table in _owned_tables_for(existing):
                    row_count += int(
                        connection.execute(
                            f"SELECT COUNT(*) FROM {_quote_identifier(table)}"
                        ).fetchone()[0]
                    )
                return DiagnosticDatabaseSummary(
                    path=normalized,
                    recorded_at=recorded_at,
                    recorded_at_source="snapshot",
                    function_eas=function_eas,
                    size_bytes=size,
                    snapshot_count=int(row[1]),
                    row_count=row_count,
                    active=normalized in active_paths,
                    schema_version=schema_version,
                    readable=True,
                    error=None,
                )
        except (OSError, sqlite3.Error) as error:
            return DiagnosticDatabaseSummary(
                path=normalized,
                recorded_at=None,
                recorded_at_source="unavailable",
                function_eas=(),
                size_bytes=size,
                snapshot_count=0,
                row_count=0,
                active=normalized in active_paths,
                schema_version=None,
                readable=False,
                error=str(error),
            )

    def snapshots(
        self, path: os.PathLike[str] | str
    ) -> tuple[DiagnosticSnapshotSummary, ...]:
        normalized = _normalized_path(path)
        with contextlib.closing(_readonly_connection(path)) as connection:
            existing = _tables(connection)
            owned = _owned_tables_for(existing)
            result: list[DiagnosticSnapshotSummary] = []
            for row in connection.execute(
                "SELECT id, label, func_ea_i64, maturity, phase, block_count, "
                "timestamp FROM snapshots ORDER BY timestamp DESC, id DESC"
            ):
                snapshot_id = int(row[0])
                count = 0
                for table in owned:
                    count += int(
                        connection.execute(
                            f"SELECT COUNT(*) FROM {_quote_identifier(table)} "
                            "WHERE snapshot_id=?",
                            (snapshot_id,),
                        ).fetchone()[0]
                    )
                result.append(
                    DiagnosticSnapshotSummary(
                        database_path=normalized,
                        snapshot_id=snapshot_id,
                        label=str(row[1]),
                        function_ea=int(row[2]),
                        maturity=str(row[3]),
                        phase=str(row[4]),
                        block_count=int(row[5]),
                        recorded_at=float(row[6]),
                        row_count=count,
                    )
                )
            return tuple(result)

    def records(
        self,
        path: os.PathLike[str] | str,
        snapshot_id: int,
        kind: DiagnosticViewKind,
    ) -> tuple[DiagnosticRecord, ...]:
        with contextlib.closing(_readonly_connection(path)) as connection:
            existing = _tables(connection)
            owned = set(_owned_tables_for(existing))
            anchors = _anchors(connection, snapshot_id, existing)
            result: list[DiagnosticRecord] = []
            ordinal = 0
            for configured_table in _VIEW_TABLES[kind]:
                for table in _view_table_candidates(configured_table):
                    if table not in owned:
                        continue
                    columns = _table_columns(connection, table)
                    if "snapshot_id" not in columns:
                        continue
                    query = (
                        f"SELECT * FROM {_quote_identifier(table)} "
                        "WHERE snapshot_id=? ORDER BY rowid"
                    )
                    rows = connection.execute(query, (snapshot_id,)).fetchall()
                    for row in rows:
                        fields: list[DiagnosticField] = []
                        warnings: list[str] = []
                        for name in columns:
                            value = row[name]
                            if _is_block_identity(name) and value is not None:
                                display = _identity_display(value, anchors)
                                if display is None:
                                    fields.append(
                                        DiagnosticField(
                                            name=name,
                                            value=None,
                                            display="<block anchor unavailable>",
                                            anchor_ea=None,
                                        )
                                    )
                                    warnings.append(
                                        f"Block anchor unavailable for {name}"
                                    )
                                else:
                                    fields.append(
                                        DiagnosticField(
                                            name=name,
                                            value=display,
                                            display=display,
                                            anchor_ea=_display_anchor_ea(display),
                                        )
                                    )
                            else:
                                fields.append(
                                    DiagnosticField(
                                        name=name,
                                        value=value,
                                        display="" if value is None else str(value),
                                        anchor_ea=_value_anchor_ea(name, value),
                                    )
                                )
                        primary_ea = next(
                            (
                                field.anchor_ea
                                for field in fields
                                if field.anchor_ea is not None
                            ),
                            None,
                        )
                        result.append(
                            DiagnosticRecord(
                                kind=kind,
                                source_table=table,
                                snapshot_id=snapshot_id,
                                ordinal=ordinal,
                                fields=tuple(fields),
                                warnings=tuple(warnings),
                                anchor_ea=primary_ea,
                            )
                        )
                        ordinal += 1
            return tuple(result)
