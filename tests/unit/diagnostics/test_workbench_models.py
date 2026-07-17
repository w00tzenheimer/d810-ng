from __future__ import annotations

import dataclasses

from d810.diagnostics import workbench_models as models


def test_diagnostic_workbench_records_are_frozen_slotted_and_tuple_owned():
    database = models.DiagnosticDatabaseSummary(
        path="/tmp/a.diag.sqlite3",
        recorded_at=20.0,
        recorded_at_source="snapshot",
        function_eas=(0x401000,),
        size_bytes=100,
        snapshot_count=2,
        row_count=5,
        active=False,
        schema_version=1,
        readable=True,
        error=None,
    )
    snapshot = models.DiagnosticSnapshotSummary(
        database_path=database.path,
        snapshot_id=7,
        label="after",
        function_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        phase="post_d810",
        block_count=3,
        recorded_at=20.0,
        row_count=4,
    )
    record = models.DiagnosticRecord(
        kind=models.DiagnosticViewKind.BLOCKS,
        source_table="blocks",
        snapshot_id=7,
        ordinal=0,
        fields=(models.DiagnosticField("serial", None, "blk9@0x401000"),),
        warnings=(),
    )

    for value in (database, snapshot, record, record.fields[0]):
        assert dataclasses.is_dataclass(value)
        assert value.__dataclass_params__.frozen is True
        assert not hasattr(value, "__dict__")

    assert isinstance(database.function_eas, tuple)
    assert isinstance(record.fields, tuple)
    assert isinstance(record.warnings, tuple)


def test_cleanup_records_distinguish_logical_wal_vacuum_and_quarantine():
    target = models.DiagnosticCleanupTarget(
        path="/tmp/a.diag.sqlite3",
        snapshot_ids=(3, 4),
        active=False,
        estimated_rows=10,
    )
    plan = models.DiagnosticCleanupPlan(
        scope=models.DiagnosticCleanupScope.SELECTED_SNAPSHOTS,
        targets=(target,),
        skipped_active_paths=(),
        confirmation="Delete 2 snapshots?",
    )
    logical = models.DiagnosticOperationOutcome(
        operation=models.DiagnosticOperation.LOGICAL_DELETE,
        path=target.path,
        status=models.DiagnosticOperationStatus.SUCCEEDED,
        detail="Committed",
        affected=10,
    )
    result = models.DiagnosticCleanupResult(
        plan=plan,
        logical=(logical,),
        wal=(),
        vacuum=(),
        quarantine=(),
    )

    assert result.logical[0].operation is models.DiagnosticOperation.LOGICAL_DELETE
    assert result.wal == ()
    assert result.vacuum == ()
    assert result.quarantine == ()
    assert not hasattr(result, "__dict__")


def test_all_requested_cleanup_scopes_have_explicit_vocabulary():
    assert {item.value for item in models.DiagnosticCleanupScope} == {
        "selected_snapshots",
        "all_snapshots",
        "keep_latest",
        "selected_databases",
        "all_closed_databases",
        "vacuum",
    }
    assert not hasattr(models.DiagnosticCleanupScope, "OLDER_THAN")
