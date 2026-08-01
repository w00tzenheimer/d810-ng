from __future__ import annotations

import sqlite3
from pathlib import Path

from d810.core.diag.ownership import snapshot_owned_tables
from d810.diagnostics.workbench_cleanup import DiagnosticCleanupService
from d810.diagnostics.workbench_models import DiagnosticOperationStatus


def _full_owned_database(path: Path) -> Path:
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE snapshots (id INTEGER PRIMARY KEY, timestamp REAL)")
    connection.executemany("INSERT INTO snapshots VALUES (?,?)", ((1, 10.0), (2, 20.0)))
    for table in snapshot_owned_tables():
        connection.execute(f'CREATE TABLE "{table}" (snapshot_id INTEGER, payload TEXT)')
        connection.executemany(
            f'INSERT INTO "{table}" VALUES (?,?)', ((1, "delete"), (2, "keep"))
        )
    connection.execute(
        """
        CREATE TRIGGER require_parent_last BEFORE DELETE ON snapshots
        WHEN EXISTS (SELECT 1 FROM blocks WHERE snapshot_id=OLD.id)
        BEGIN SELECT RAISE(ABORT, 'parent deleted before child'); END
        """
    )
    connection.commit()
    connection.close()
    return path


def _ids(path: Path, table: str = "snapshots") -> tuple[int, ...]:
    connection = sqlite3.connect(path)
    column = "id" if table == "snapshots" else "snapshot_id"
    result = tuple(
        int(row[0])
        for row in connection.execute(f'SELECT {column} FROM "{table}" ORDER BY {column}')
    )
    connection.close()
    return result


def test_exact_transactional_delete_covers_every_owned_table_and_parent_last(tmp_path: Path):
    path = _full_owned_database(tmp_path / "all.diag.sqlite3")
    service = DiagnosticCleanupService(active_paths_provider=lambda: ())
    plan = service.plan_selected_snapshots(path, (1,))

    result = service.execute(plan, checkpoint_wal=False)

    assert result.logical[0].status is DiagnosticOperationStatus.SUCCEEDED
    assert result.logical[0].affected == len(snapshot_owned_tables()) + 1
    assert _ids(path) == (2,)
    for table in snapshot_owned_tables():
        assert _ids(path, table) == (2,)
    assert result.wal == ()


def test_execute_revalidates_active_path_and_skips_without_mutation(tmp_path: Path):
    path = _full_owned_database(tmp_path / "active.diag.sqlite3")
    active: list[Path] = []
    service = DiagnosticCleanupService(active_paths_provider=lambda: tuple(active))
    plan = service.plan_selected_snapshots(path, (1,))
    active.append(path)

    result = service.execute(plan)

    assert result.logical[0].status is DiagnosticOperationStatus.SKIPPED_ACTIVE
    assert _ids(path) == (1, 2)


def test_bulk_snapshot_scopes_execute_the_exact_planned_ids_without_time_cleanup(tmp_path: Path):
    all_path = _full_owned_database(tmp_path / "all.diag.sqlite3")
    keep_path = _full_owned_database(tmp_path / "keep.diag.sqlite3")
    service = DiagnosticCleanupService(active_paths_provider=lambda: ())

    all_result = service.execute(service.plan_all_snapshots(all_path), checkpoint_wal=False)
    keep_result = service.execute(service.plan_keep_latest(keep_path, 1), checkpoint_wal=False)

    assert all_result.logical[0].status is DiagnosticOperationStatus.SUCCEEDED
    assert _ids(all_path) == ()
    assert keep_result.logical[0].status is DiagnosticOperationStatus.SUCCEEDED
    assert _ids(keep_path) == (2,)


def test_schema_drift_after_plan_fails_closed_and_preserves_rows(tmp_path: Path):
    path = _full_owned_database(tmp_path / "drift.diag.sqlite3")
    service = DiagnosticCleanupService(active_paths_provider=lambda: ())
    plan = service.plan_selected_snapshots(path, (1,))
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE mystery (snapshot_id INTEGER, payload TEXT)")
    connection.commit()
    connection.close()

    result = service.execute(plan)

    assert result.logical[0].status is DiagnosticOperationStatus.FAILED
    assert "mystery" in result.logical[0].detail
    assert _ids(path) == (1, 2)


def test_schema_drift_blocks_quarantine_and_vacuum_after_plan(tmp_path: Path):
    quarantine_path = _full_owned_database(tmp_path / "quarantine-drift.diag.sqlite3")
    vacuum_path = _full_owned_database(tmp_path / "vacuum-drift.diag.sqlite3")
    service = DiagnosticCleanupService(
        active_paths_provider=lambda: (), quarantine_directory=tmp_path / "quarantine"
    )
    quarantine_plan = service.plan_selected_databases((quarantine_path,))
    vacuum_plan = service.plan_vacuum((vacuum_path,))
    for path in (quarantine_path, vacuum_path):
        connection = sqlite3.connect(path)
        connection.execute("CREATE TABLE mystery (snapshot_id INTEGER, payload TEXT)")
        connection.commit()
        connection.close()

    quarantine_result = service.execute(quarantine_plan)
    vacuum_result = service.execute(vacuum_plan)

    assert quarantine_result.quarantine[0].status is DiagnosticOperationStatus.FAILED
    assert "mystery" in quarantine_result.quarantine[0].detail
    assert quarantine_path.exists()
    assert vacuum_result.vacuum[0].status is DiagnosticOperationStatus.FAILED
    assert "mystery" in vacuum_result.vacuum[0].detail


def test_integrity_failure_rolls_back_complete_operation(tmp_path: Path):
    path = _full_owned_database(tmp_path / "rollback.diag.sqlite3")

    class FailingIntegrityService(DiagnosticCleanupService):
        @staticmethod
        def _integrity_errors(connection, owned_tables):
            return ("forced integrity failure",)

    service = FailingIntegrityService(active_paths_provider=lambda: ())
    plan = service.plan_selected_snapshots(path, (1,))

    result = service.execute(plan)

    assert result.logical[0].status is DiagnosticOperationStatus.FAILED
    assert "forced integrity failure" in result.logical[0].detail
    assert _ids(path) == (1, 2)
    assert _ids(path, "blocks") == (1, 2)


def test_preexisting_orphan_is_detected_and_rolls_back(tmp_path: Path):
    path = _full_owned_database(tmp_path / "orphan.diag.sqlite3")
    connection = sqlite3.connect(path)
    connection.execute("INSERT INTO blocks VALUES (?,?)", (99, "orphan"))
    connection.commit()
    connection.close()
    service = DiagnosticCleanupService(active_paths_provider=lambda: ())
    plan = service.plan_selected_snapshots(path, (1,))

    result = service.execute(plan)

    assert result.logical[0].status is DiagnosticOperationStatus.FAILED
    assert "orphan" in result.logical[0].detail
    assert _ids(path) == (1, 2)


def test_supported_legacy_snapshot_table_is_deleted_transactionally(tmp_path: Path):
    path = tmp_path / "legacy.diag.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE snapshots (id INTEGER PRIMARY KEY, timestamp REAL)")
    connection.execute("CREATE TABLE dag_nodes (snapshot_id INTEGER, payload TEXT)")
    connection.executemany("INSERT INTO snapshots VALUES (?,?)", ((1, 1.0), (2, 2.0)))
    connection.executemany("INSERT INTO dag_nodes VALUES (?,?)", ((1, "old"), (2, "keep")))
    connection.commit()
    connection.close()
    service = DiagnosticCleanupService(active_paths_provider=lambda: ())

    result = service.execute(service.plan_selected_snapshots(path, (1,)), checkpoint_wal=False)

    assert result.logical[0].status is DiagnosticOperationStatus.SUCCEEDED
    assert _ids(path) == (2,)
    assert _ids(path, "dag_nodes") == (2,)


def test_locked_database_reports_failure_without_partial_delete(tmp_path: Path):
    path = _full_owned_database(tmp_path / "locked.diag.sqlite3")
    service = DiagnosticCleanupService(active_paths_provider=lambda: ())
    plan = service.plan_selected_snapshots(path, (1,))
    lock = sqlite3.connect(path)
    lock.execute("BEGIN IMMEDIATE")

    try:
        result = service.execute(plan)
    finally:
        lock.rollback()
        lock.close()

    assert result.logical[0].status is DiagnosticOperationStatus.FAILED
    assert "locked" in result.logical[0].detail.lower()
    assert _ids(path) == (1, 2)


def test_wal_and_vacuum_outcomes_do_not_relabel_committed_delete(tmp_path: Path):
    path = _full_owned_database(tmp_path / "wal.diag.sqlite3")
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.commit()
    connection.close()

    class FailingVacuumService(DiagnosticCleanupService):
        @staticmethod
        def _vacuum_path(path):
            raise sqlite3.OperationalError("forced vacuum failure")

    service = FailingVacuumService(active_paths_provider=lambda: ())
    plan = service.plan_selected_snapshots(path, (1,))

    result = service.execute(plan, vacuum_after=True)

    assert result.logical[0].status is DiagnosticOperationStatus.SUCCEEDED
    assert result.wal[0].status is DiagnosticOperationStatus.SUCCEEDED
    assert result.vacuum[0].status is DiagnosticOperationStatus.FAILED
    assert "forced vacuum failure" in result.vacuum[0].detail
    assert _ids(path) == (2,)


def test_database_cleanup_moves_database_and_sidecars_to_quarantine(tmp_path: Path):
    path = _full_owned_database(tmp_path / "delete.diag.sqlite3")
    wal = Path(str(path) + "-wal")
    shm = Path(str(path) + "-shm")
    live_files = sqlite3.connect(path)
    live_files.execute("PRAGMA journal_mode=WAL")
    live_files.execute("UPDATE snapshots SET timestamp=timestamp WHERE id=1")
    live_files.commit()
    assert wal.exists()
    assert shm.exists()
    quarantine = tmp_path / "quarantine"
    service = DiagnosticCleanupService(
        active_paths_provider=lambda: (), quarantine_directory=quarantine
    )
    plan = service.plan_selected_databases((path,))

    try:
        result = service.execute(plan)
    finally:
        live_files.close()

    assert result.quarantine[0].status is DiagnosticOperationStatus.SUCCEEDED
    assert result.quarantine[0].affected == 3
    assert "Restore by moving each quarantined file" in result.quarantine[0].detail
    assert str(path) in result.quarantine[0].detail
    assert not path.exists()
    assert not wal.exists()
    assert not shm.exists()
    moved = tuple(quarantine.rglob("*"))
    assert any(item.name == path.name for item in moved)
    assert any(item.name == wal.name for item in moved)
    assert any(item.name == shm.name for item in moved)


def test_vacuum_plan_reports_only_vacuum_outcome(tmp_path: Path):
    path = _full_owned_database(tmp_path / "vacuum.diag.sqlite3")
    service = DiagnosticCleanupService(active_paths_provider=lambda: ())

    result = service.execute(service.plan_vacuum((path,)))

    assert result.logical == ()
    assert result.wal == ()
    assert result.quarantine == ()
    assert result.vacuum[0].status is DiagnosticOperationStatus.SUCCEEDED
