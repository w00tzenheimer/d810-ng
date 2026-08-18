from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from d810.capabilities.idb_preparation import (
    PreparationByteDelta,
    PreparationScriptDescriptor,
    PreparationState,
    PreparationTransactionId,
    PreparationTransactionRecord,
)
from d810.core.execution_journal import DecompilationSessionId, ExecutionAttemptId
from d810.manager.workbench_service import WorkbenchService
from d810.manager.workbench_models import WorkbenchCommandRequest


pytestmark = pytest.mark.pure_python


def _record(*, state: PreparationState = PreparationState.IDB_PREPARED):
    return PreparationTransactionRecord(
        transaction_id=PreparationTransactionId("tx-1"),
        database_identity="idb-a",
        anchor_function_ea=0x401000,
        script_id="normalize",
        script_path="/tmp/normalize.py",
        script_source_sha256="a" * 64,
        authorizing_attempt_id=ExecutionAttemptId.new(
            session=DecompilationSessionId.new(), sequence=1
        ),
        state=state,
        created_at=1.0,
        updated_at=2.0,
    )


def test_applied_transaction_projects_exact_change_counts(tmp_path) -> None:
    script = tmp_path / "normalize.py"
    script.write_text("# normalize\n", encoding="utf-8")
    descriptor = PreparationScriptDescriptor(
        script_id="normalize",
        display_name="Normalize dispatcher",
        path=str(script),
        source_sha256="a" * 64,
        enabled=True,
        portable=True,
    )
    record = _record()
    journal = SimpleNamespace(
        transactions=lambda identity: (record,),
        byte_deltas=lambda transaction_id: (
            PreparationByteDelta(0x401000, 0x75, False, 0x75, True, 0xEB),
            PreparationByteDelta(0x401001, 0x01, False, 0x01, True, 0x90),
            PreparationByteDelta(0x401010, 0x74, False, 0x74, True, 0xEB),
        ),
        type_deltas=lambda transaction_id: (object(), object(), object(), object()),
        affected_functions=lambda transaction_id: (0x401000, 0x402000),
    )
    manager = SimpleNamespace(
        pre_hex_preparation=SimpleNamespace(
            database_identity="idb-a",
            scripts=(descriptor,),
        ),
        _idb_preparation_journal=journal,
        _idb_preparation_gateway=SimpleNamespace(
            transaction_matches_after_image=lambda transaction_id: True
        ),
    )

    summary = WorkbenchService(manager)._preparation(0x401000)

    assert summary.database_identity == "idb-a"
    assert len(summary.scripts) == 1
    transaction = summary.transactions[0]
    assert transaction.bytes_changed == 3
    assert transaction.byte_ranges == ((0x401000, 0x401002), (0x401010, 0x401011))
    assert transaction.type_annotations == 4
    assert transaction.affected_function_eas == (0x401000, 0x402000)
    assert transaction.restore_allowed


def test_projection_marks_source_hash_drift_and_live_interference(tmp_path) -> None:
    script = tmp_path / "normalize.py"
    script.write_text("# changed\n", encoding="utf-8")
    descriptor = PreparationScriptDescriptor(
        script_id="normalize",
        display_name="Normalize dispatcher",
        path=str(script),
        source_sha256="a" * 64,
        enabled=True,
        portable=False,
    )
    record = _record()
    manager = SimpleNamespace(
        pre_hex_preparation=SimpleNamespace(
            database_identity="idb-a",
            scripts=(descriptor,),
        ),
        _idb_preparation_journal=SimpleNamespace(
            transactions=lambda identity: (record,),
            byte_deltas=lambda transaction_id: (),
            type_deltas=lambda transaction_id: (),
            affected_functions=lambda transaction_id: (),
        ),
        _idb_preparation_gateway=SimpleNamespace(
            transaction_matches_after_image=lambda transaction_id: False
        ),
    )

    summary = WorkbenchService(manager)._preparation(0x401000)

    assert not summary.scripts[0].source_hash_matches
    assert not summary.scripts[0].portable
    assert not summary.transactions[0].restore_allowed
    assert "after-image" in summary.transactions[0].restore_blocker


def test_prepare_command_revalidates_source_hash_before_writes(tmp_path) -> None:
    script = tmp_path / "normalize.py"
    script.write_text("# original\n", encoding="utf-8")
    source_hash = hashlib.sha256(script.read_bytes()).hexdigest()
    descriptor = PreparationScriptDescriptor(
        script_id="normalize",
        display_name="Normalize dispatcher",
        path=str(script),
        source_sha256=source_hash,
        enabled=True,
        portable=True,
    )
    calls = []
    manager = SimpleNamespace(
        pre_hex_preparation=SimpleNamespace(
            database_identity="idb-a",
            scripts=(descriptor,),
        ),
        _idb_preparation_journal=SimpleNamespace(transactions=lambda identity: ()),
        _idb_preparation_gateway=SimpleNamespace(),
        prepare_idb_for_hexrays=lambda *args: calls.append(args),
    )
    service = WorkbenchService(manager)
    service._generation = 7
    service._latest_function_ea = 0x401000
    service._latest_function_fingerprint = "sha256:function"
    request = WorkbenchCommandRequest(
        command="prepare_only",
        function_ea=0x401000,
        expected_generation=7,
        function_fingerprint="sha256:function",
        database_identity="idb-a",
        script_source_hashes=(("normalize", source_hash),),
    )

    script.write_text("# changed after preview\n", encoding="utf-8")
    result = service.execute_prepare_only(request)

    assert not result.succeeded
    assert result.status.value == "Stale"
    assert "preview again" in result.message
    assert calls == []
