from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from d810.diagnostics.workbench_cleanup import (
    DiagnosticCleanupPlanError,
    DiagnosticCleanupService,
)
from d810.diagnostics.workbench_models import DiagnosticCleanupScope


def _database(path: Path) -> Path:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE snapshots (id INTEGER PRIMARY KEY, timestamp REAL);
        CREATE TABLE blocks (snapshot_id INTEGER, serial INTEGER);
        CREATE TABLE instructions (snapshot_id INTEGER, block_serial INTEGER);
        """
    )
    connection.executemany(
        "INSERT INTO snapshots VALUES (?,?)",
        ((1, 10.0), (2, 20.0), (3, 20.0), (4, 30.0)),
    )
    connection.executemany(
        "INSERT INTO blocks VALUES (?,?)",
        ((1, 1), (2, 2), (3, 3), (4, 4)),
    )
    connection.executemany(
        "INSERT INTO instructions VALUES (?,?)",
        ((1, 1), (3, 3), (4, 4)),
    )
    connection.commit()
    connection.close()
    return path


def test_selected_and_all_snapshot_plans_have_exact_ids_rows_and_confirmation(tmp_path: Path):
    path = _database(tmp_path / "a.diag.sqlite3")
    service = DiagnosticCleanupService(active_paths_provider=lambda: ())

    selected = service.plan_selected_snapshots(path, (3, 1))
    all_snapshots = service.plan_all_snapshots(path)

    assert selected.scope is DiagnosticCleanupScope.SELECTED_SNAPSHOTS
    assert selected.targets[0].snapshot_ids == (1, 3)
    assert selected.targets[0].estimated_rows == 6
    assert str(path.resolve()) in selected.confirmation
    assert "1, 3" in selected.confirmation
    assert "6 rows" in selected.confirmation
    assert all_snapshots.targets[0].snapshot_ids == (1, 2, 3, 4)
    assert all_snapshots.targets[0].estimated_rows == 11


def test_keep_latest_and_older_than_use_timestamp_then_id_ties(tmp_path: Path):
    path = _database(tmp_path / "a.diag.sqlite3")
    service = DiagnosticCleanupService(active_paths_provider=lambda: ())

    keep_two = service.plan_keep_latest(path, 2)
    older = service.plan_older_than(path, 20.0)

    assert keep_two.scope is DiagnosticCleanupScope.KEEP_LATEST
    assert keep_two.targets[0].snapshot_ids == (1, 2)
    assert older.scope is DiagnosticCleanupScope.OLDER_THAN
    assert older.targets[0].snapshot_ids == (1,)


def test_active_database_is_excluded_from_every_destructive_plan(tmp_path: Path):
    path = _database(tmp_path / "active.diag.sqlite3")
    service = DiagnosticCleanupService(active_paths_provider=lambda: (path,))

    plans = (
        service.plan_selected_snapshots(path, (1,)),
        service.plan_all_snapshots(path),
        service.plan_keep_latest(path, 1),
        service.plan_older_than(path, 99.0),
        service.plan_selected_databases((path,)),
        service.plan_all_closed_databases((path,)),
        service.plan_vacuum((path,)),
    )

    assert all(plan.targets == () for plan in plans)
    assert all(plan.skipped_active_paths == (str(path.resolve()),) for plan in plans)
    assert all("active" in plan.confirmation.lower() for plan in plans)


def test_database_and_vacuum_plan_scopes_are_explicit(tmp_path: Path):
    first = _database(tmp_path / "a.diag.sqlite3")
    second = _database(tmp_path / "b.diag.sqlite3")
    service = DiagnosticCleanupService(active_paths_provider=lambda: (second,))

    selected = service.plan_selected_databases((second, first))
    closed = service.plan_all_closed_databases((second, first))
    vacuum = service.plan_vacuum((second, first))

    assert selected.scope is DiagnosticCleanupScope.SELECTED_DATABASES
    assert closed.scope is DiagnosticCleanupScope.ALL_CLOSED_DATABASES
    assert vacuum.scope is DiagnosticCleanupScope.VACUUM
    assert [target.path for target in selected.targets] == [str(first.resolve())]
    assert selected.skipped_active_paths == (str(second.resolve()),)
    assert closed.targets == selected.targets
    assert vacuum.targets[0].snapshot_ids == ()


def test_plan_fails_closed_for_unknown_snapshot_owned_table(tmp_path: Path):
    path = _database(tmp_path / "a.diag.sqlite3")
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE mystery (snapshot_id INTEGER, payload TEXT)")
    connection.commit()
    connection.close()

    with pytest.raises(DiagnosticCleanupPlanError, match="mystery"):
        DiagnosticCleanupService(active_paths_provider=lambda: ()).plan_all_snapshots(path)


def test_invalid_retention_and_missing_selected_ids_are_rejected(tmp_path: Path):
    path = _database(tmp_path / "a.diag.sqlite3")
    service = DiagnosticCleanupService(active_paths_provider=lambda: ())

    with pytest.raises(ValueError, match="non-negative"):
        service.plan_keep_latest(path, -1)
    with pytest.raises(DiagnosticCleanupPlanError, match="99"):
        service.plan_selected_snapshots(path, (99,))
