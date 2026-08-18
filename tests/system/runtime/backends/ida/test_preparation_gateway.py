from __future__ import annotations

import hashlib

import pytest

pytestmark = [pytest.mark.requires_ida, pytest.mark.runtime]

ida_bytes = pytest.importorskip("ida_bytes")
ida_funcs = pytest.importorskip("ida_funcs")

from d810.backends.ida.idb_preparation.gateway import (  # noqa: E402
    IdaPreparationByteWriter,
    IdbPreparationGateway,
)
from d810.backends.ida.idb_preparation.journal import (  # noqa: E402
    SQLitePreparationJournal,
)
from d810.backends.ida.idb_preparation.patch_ledger import IdaPatchLedger  # noqa: E402
from d810.backends.ida.idb_preparation.script_runner import (  # noqa: E402
    TrustedPreparationScriptRunner,
)
from d810.backends.ida.native_patch.reanalysis import (  # noqa: E402
    IdaFunctionReanalyzer,
)
from d810.capabilities.idb_preparation import (  # noqa: E402
    PreparationRunRequest,
    PreparationScriptDescriptor,
    PreparationState,
)
from d810.core.execution_journal import (  # noqa: E402
    DecompilationSessionId,
    ExecutionAttemptId,
)


class _Invalidator:
    def mark_cfunc_dirty(self, function_ea: int) -> bool:
        return False


class _Callers:
    def callers_of(self, function_ea: int) -> frozenset[int]:
        return frozenset()


class _NoDecompiler:
    def decompile(self, function_ea: int):
        raise AssertionError("initial preparation must not call Hex-Rays")


def _owner(ea: int) -> int | None:
    function = ida_funcs.get_func(ea)
    return None if function is None else int(function.start_ea)


def _descriptor(tmp_path, *, replacement: int) -> PreparationScriptDescriptor:
    script = tmp_path / "normalize.py"
    script.write_text(
        f"preparation.patch_bytes(function_ea, bytes([{replacement}]))\n",
        encoding="utf-8",
    )
    return PreparationScriptDescriptor(
        script_id="normalize",
        display_name="Normalize",
        path=str(script),
        source_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
        enabled=True,
        portable=True,
    )


def _request(function_ea: int, descriptor: PreparationScriptDescriptor):
    return PreparationRunRequest(
        database_identity="disposable-idb",
        anchor_function_ea=function_ea,
        script=descriptor,
        authorizing_attempt_id=ExecutionAttemptId.new(
            session=DecompilationSessionId.new(), sequence=1
        ),
    )


def _unmanaged_descriptor(tmp_path, *, replacement: int) -> PreparationScriptDescriptor:
    script = tmp_path / "put-unmanaged.py"
    script.write_text(
        "import ida_bytes\n"
        "preparation.note_range(function_ea, function_ea + 1)\n"
        f"ida_bytes.put_bytes(function_ea, bytes([{replacement}]))\n",
        encoding="utf-8",
    )
    return PreparationScriptDescriptor(
        script_id="put-unmanaged",
        display_name="Put unmanaged byte",
        path=str(script),
        source_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
        enabled=True,
        portable=True,
    )


def _gateway(journal: SQLitePreparationJournal) -> IdbPreparationGateway:
    return IdbPreparationGateway(
        journal=journal,
        patch_ledger=IdaPatchLedger(),
        script_runner=TrustedPreparationScriptRunner(),
        byte_writer=IdaPreparationByteWriter(),
        current_database_identity="disposable-idb",
        native_active_ranges=lambda identity: (),
        function_owner=_owner,
        reanalyzer=IdaFunctionReanalyzer(),
        cache_invalidator=_Invalidator(),
        caller_discovery=_Callers(),
        redo_decompiler=_NoDecompiler(),
    )


def test_pristine_patch_apply_and_restore_reproduces_exact_patch_ledger(
    copy_of_idb, tmp_path
) -> None:
    ea = copy_of_idb.min_ea
    original = int(ida_bytes.get_original_byte(ea)) & 0xFF
    replacement = original ^ 0x01
    before = IdaPatchLedger().capture()
    assert before == ()

    with SQLitePreparationJournal(tmp_path / "journal.sqlite3") as journal:
        gateway = _gateway(journal)
        applied = gateway.run(
            _request(ea, _descriptor(tmp_path, replacement=replacement))
        )
        assert applied.state is PreparationState.IDB_PREPARED
        assert int(ida_bytes.get_byte(ea)) & 0xFF == replacement

        restored = gateway.restore(applied.transaction_id)
        assert restored.ok

    assert int(ida_bytes.get_byte(ea)) & 0xFF == original
    assert IdaPatchLedger().capture() == before


def test_inherited_patch_apply_and_restore_preserves_user_patch_status(
    copy_of_idb, tmp_path
) -> None:
    ea = copy_of_idb.min_ea
    original = int(ida_bytes.get_original_byte(ea)) & 0xFF
    inherited = original ^ 0x01
    replacement = original ^ 0x02
    ida_bytes.patch_byte(ea, inherited)
    before = IdaPatchLedger().capture()
    assert len(before) == 1

    try:
        with SQLitePreparationJournal(tmp_path / "journal.sqlite3") as journal:
            gateway = _gateway(journal)
            applied = gateway.run(
                _request(ea, _descriptor(tmp_path, replacement=replacement))
            )
            assert applied.ok
            restored = gateway.restore(applied.transaction_id)
            assert restored.ok

        assert int(ida_bytes.get_byte(ea)) & 0xFF == inherited
        assert IdaPatchLedger().capture() == before
    finally:
        ida_bytes.revert_byte(ea)


def test_unmanaged_put_bytes_in_declared_range_is_rejected_and_restored(
    copy_of_idb, tmp_path
) -> None:
    ea = copy_of_idb.min_ea
    original = int(ida_bytes.get_original_byte(ea)) & 0xFF
    replacement = original ^ 0x01
    before = IdaPatchLedger().capture()
    assert before == ()

    with SQLitePreparationJournal(tmp_path / "journal.sqlite3") as journal:
        receipt = _gateway(journal).run(
            _request(ea, _unmanaged_descriptor(tmp_path, replacement=replacement))
        )

        assert receipt.state is PreparationState.RESTORED
        assert receipt.failure_reason == f"UNMANAGED_WRITE_DETECTED at {ea:#x}"

    assert int(ida_bytes.get_byte(ea)) & 0xFF == original
    assert IdaPatchLedger().capture() == before


def test_unmanaged_put_bytes_restores_preexisting_live_raw_byte(
    copy_of_idb, tmp_path
) -> None:
    ea = copy_of_idb.min_ea
    original = int(ida_bytes.get_original_byte(ea)) & 0xFF
    preexisting = original ^ 0x01
    replacement = original ^ 0x02
    ida_bytes.put_byte(ea, preexisting)
    before = IdaPatchLedger().capture()
    assert before == ()

    try:
        with SQLitePreparationJournal(tmp_path / "journal.sqlite3") as journal:
            receipt = _gateway(journal).run(
                _request(ea, _unmanaged_descriptor(tmp_path, replacement=replacement))
            )

            assert receipt.state is PreparationState.RESTORED
            assert receipt.failure_reason == f"UNMANAGED_WRITE_DETECTED at {ea:#x}"
            baselines = journal.declared_byte_baselines(receipt.transaction_id)
            assert len(baselines) == 1
            assert baselines[0].ea == ea
            assert not baselines[0].before_is_patched
            assert baselines[0].before_value == preexisting

        assert int(ida_bytes.get_byte(ea)) & 0xFF == preexisting
        assert IdaPatchLedger().capture() == before
    finally:
        ida_bytes.put_byte(ea, original)


def test_managed_patch_restores_preexisting_live_raw_byte(
    copy_of_idb, tmp_path
) -> None:
    ea = copy_of_idb.min_ea
    original = int(ida_bytes.get_original_byte(ea)) & 0xFF
    preexisting = original ^ 0x01
    replacement = original ^ 0x02
    ida_bytes.put_byte(ea, preexisting)
    before = IdaPatchLedger().capture()
    assert before == ()

    try:
        with SQLitePreparationJournal(tmp_path / "journal.sqlite3") as journal:
            gateway = _gateway(journal)
            applied = gateway.run(
                _request(ea, _descriptor(tmp_path, replacement=replacement))
            )
            assert applied.ok
            assert applied.byte_deltas[0].before_value == preexisting

            restored = gateway.restore(applied.transaction_id)
            assert restored.ok

        assert int(ida_bytes.get_byte(ea)) & 0xFF == preexisting
        assert IdaPatchLedger().capture() == before
    finally:
        ida_bytes.put_byte(ea, original)
