from __future__ import annotations

import ast
from pathlib import Path

from d810.diagnostics.workbench_models import (
    DiagnosticDatabaseSummary,
    DiagnosticField,
    DiagnosticRecord,
    DiagnosticSnapshotSummary,
    DiagnosticViewKind,
)
from d810.ui import workbench_diagnostics_logic as logic


def _database(
    path: str,
    *,
    recorded_at: float,
    function_ea: int,
    size: int,
    snapshots: int,
    active: bool = False,
) -> DiagnosticDatabaseSummary:
    return DiagnosticDatabaseSummary(
        path=path,
        recorded_at=recorded_at,
        recorded_at_source="snapshot",
        function_eas=(function_ea,),
        size_bytes=size,
        snapshot_count=snapshots,
        row_count=snapshots,
        active=active,
        schema_version=1,
        readable=True,
        error=None,
    )


def _snapshot(
    snapshot_id: int,
    *,
    timestamp: float,
    maturity: str,
    phase: str,
    blocks: int,
    rows: int,
    function_ea: int = 0x401000,
) -> DiagnosticSnapshotSummary:
    return DiagnosticSnapshotSummary(
        database_path="/a.diag.sqlite3",
        snapshot_id=snapshot_id,
        label=f"snapshot {snapshot_id}",
        function_ea=function_ea,
        maturity=maturity,
        phase=phase,
        block_count=blocks,
        recorded_at=timestamp,
        row_count=rows,
    )


def test_database_default_and_every_requested_sort_are_deterministic():
    values = (
        _database("/b", recorded_at=20, function_ea=0x402000, size=50, snapshots=2),
        _database("/a", recorded_at=20, function_ea=0x401000, size=100, snapshots=1),
        _database("/c", recorded_at=10, function_ea=0x403000, size=25, snapshots=3),
    )

    assert [item.path for item in logic.sort_databases(values)] == ["/a", "/b", "/c"]
    assert [item.path for item in logic.sort_databases(values, logic.DatabaseSort.FUNCTION)] == ["/a", "/b", "/c"]
    assert [item.path for item in logic.sort_databases(values, logic.DatabaseSort.FILE_SIZE)] == ["/c", "/b", "/a"]
    assert [item.path for item in logic.sort_databases(values, logic.DatabaseSort.SNAPSHOT_COUNT)] == ["/a", "/b", "/c"]
    assert [item.path for item in logic.sort_databases(values, logic.DatabaseSort.PATH)] == ["/a", "/b", "/c"]


def test_snapshot_default_and_every_requested_sort_are_deterministic():
    values = (
        _snapshot(1, timestamp=20, maturity="Z", phase="b", blocks=4, rows=10),
        _snapshot(2, timestamp=20, maturity="A", phase="c", blocks=3, rows=20),
        _snapshot(3, timestamp=10, maturity="M", phase="a", blocks=2, rows=30),
    )

    assert [item.snapshot_id for item in logic.sort_snapshots(values)] == [2, 1, 3]
    assert [item.snapshot_id for item in logic.sort_snapshots(values, logic.SnapshotSort.MATURITY)] == [2, 3, 1]
    assert [item.snapshot_id for item in logic.sort_snapshots(values, logic.SnapshotSort.PHASE)] == [3, 1, 2]
    assert [item.snapshot_id for item in logic.sort_snapshots(values, logic.SnapshotSort.BLOCK_COUNT)] == [3, 2, 1]
    assert [item.snapshot_id for item in logic.sort_snapshots(values, logic.SnapshotSort.ROW_COUNT)] == [1, 2, 3]


def test_filters_and_current_function_latest_selection_preserve_latest_semantics():
    databases = (
        _database("/new-target", recorded_at=30, function_ea=0x401000, size=1, snapshots=1),
        _database("/other", recorded_at=40, function_ea=0x402000, size=1, snapshots=1),
        _database("/old-target", recorded_at=10, function_ea=0x401000, size=1, snapshots=1),
    )
    snapshots = (
        _snapshot(1, timestamp=10, maturity="M1", phase="before", blocks=1, rows=1),
        _snapshot(2, timestamp=30, maturity="M2", phase="after", blocks=1, rows=1),
    )

    assert [item.path for item in logic.filter_databases(databases, "401000")] == [
        "/new-target",
        "/old-target",
    ]
    assert [item.snapshot_id for item in logic.filter_snapshots(snapshots, "AFTER")] == [2]
    assert logic.latest_database_for_function(databases, 0x401000).path == "/new-target"
    assert logic.latest_snapshot_for_function(snapshots, 0x401000).snapshot_id == 2


def test_actions_protect_active_database_and_require_explicit_selection():
    inactive = _database("/a", recorded_at=1, function_ea=1, size=1, snapshots=2)
    active = _database("/b", recorded_at=1, function_ea=2, size=1, snapshots=2, active=True)
    states = {item.action_id: item for item in logic.diagnostic_action_states((inactive, active), selected_snapshot_ids=(1,))}

    assert states["delete_selected_snapshots"].enabled is True
    assert states["delete_selected_databases"].enabled is True
    assert "active" in states["delete_selected_databases"].reason.lower()
    assert states["delete_all_closed_databases"].enabled is True
    assert states["vacuum_selected_databases"].enabled is True

    empty = {item.action_id: item for item in logic.diagnostic_action_states((), selected_snapshot_ids=())}
    assert all(item.enabled is False for item in empty.values())


def test_all_closed_action_uses_full_inventory_not_only_current_selection():
    closed = _database("/closed", recorded_at=1, function_ea=1, size=1, snapshots=1)
    states = {
        item.action_id: item
        for item in logic.diagnostic_action_states(
            (), selected_snapshot_ids=(), all_databases=(closed,)
        )
    }

    assert states["delete_all_closed_databases"].enabled is True
    assert states["delete_selected_databases"].enabled is False


def test_function_grouping_and_jump_projection_are_deterministic():
    databases = (
        _database("/old", recorded_at=1, function_ea=0x401000, size=1, snapshots=1),
        _database("/new", recorded_at=2, function_ea=0x401000, size=1, snapshots=1),
        _database("/other", recorded_at=3, function_ea=0x402000, size=1, snapshots=1),
    )
    groups = logic.group_databases_by_function(databases)
    record = DiagnosticRecord(
        kind=DiagnosticViewKind.BLOCKS,
        source_table="blocks",
        snapshot_id=1,
        ordinal=0,
        fields=(DiagnosticField("serial", "blk7@0x401010", "blk7@0x401010", 0x401010),),
        warnings=(),
        anchor_ea=0x401010,
    )

    assert [group.function_ea for group in groups] == [0x401000, 0x402000]
    assert [item.path for item in groups[0].databases] == ["/new", "/old"]
    assert logic.record_jump_ea(record) == 0x401010


def test_diagnostics_logic_has_no_qt_ida_sqlite_or_peewee_imports():
    path = Path(logic.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    imports.update(
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )

    assert not any(name.startswith(("ida", "PyQt", "PySide")) for name in imports)
    assert not any(token in name for name in imports for token in ("sqlite", "peewee"))
