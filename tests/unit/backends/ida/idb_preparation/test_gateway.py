from __future__ import annotations

from pathlib import Path

import pytest

from d810.backends.ida.idb_preparation.gateway import IdbPreparationGateway
from d810.backends.ida.idb_preparation.journal import SQLitePreparationJournal
from d810.capabilities.idb_preparation import (
    PreparationPatchRow,
    PreparationRunRequest,
    PreparationScriptDescriptor,
    PreparationState,
    PreparationTypeDelta,
    SerializedTypeSnapshot,
)
from d810.core.execution_journal import DecompilationSessionId, ExecutionAttemptId

pytestmark = pytest.mark.pure_python


class _Writer:
    def __init__(
        self,
        originals: dict[int, int],
        patches: dict[int, int] | None = None,
    ) -> None:
        self.originals = dict(originals)
        self.patches = dict(patches or {})
        self.calls: list[tuple] = []
        self.reads = 0

    def read_byte(self, ea: int) -> int | None:
        self.reads += 1
        if ea not in self.originals:
            return None
        return self.patches.get(ea, self.originals[ea])

    def patch_bytes(self, ea: int, data: bytes) -> None:
        for offset, value in enumerate(data):
            self.patch_byte(ea + offset, value)

    def patch_byte(self, ea: int, value: int) -> None:
        self.calls.append(("patch_byte", ea, value))
        self.patches[ea] = value

    def revert_byte(self, ea: int) -> None:
        self.calls.append(("revert_byte", ea))
        self.patches.pop(ea, None)


class _Ledger:
    def __init__(self, writer: _Writer, *, fail_on_capture: int | None = None) -> None:
        self.writer = writer
        self.fail_on_capture = fail_on_capture
        self.capture_count = 0

    def capture(self) -> tuple[PreparationPatchRow, ...]:
        self.capture_count += 1
        if self.capture_count == self.fail_on_capture:
            raise RuntimeError("capture failed")
        return tuple(
            PreparationPatchRow(
                ea=ea,
                file_position=ea,
                ida_original=self.writer.originals[ea],
                current_value=value,
            )
            for ea, value in sorted(self.writer.patches.items())
        )


class _Runner:
    def __init__(self, action) -> None:
        self.action = action

    def run(self, descriptor, context) -> None:
        self.action(context)


class _Reanalyzer:
    def __init__(self, *, failures_remaining: int = 0) -> None:
        self.calls: list[tuple[str, int | None]] = []
        self.failures_remaining = failures_remaining

    def reanalyze_function(self, function_ea: int) -> None:
        self.calls.append(("reanalyze", function_ea))
        if self.failures_remaining:
            self.failures_remaining -= 1
            raise RuntimeError("reanalysis failed")

    def auto_wait(self) -> None:
        self.calls.append(("auto_wait", None))


class _Invalidator:
    def __init__(self, *, erased: bool = False) -> None:
        self.erased = erased
        self.calls: list[int] = []

    def mark_cfunc_dirty(self, function_ea: int) -> bool:
        self.calls.append(function_ea)
        return self.erased


class _Callers:
    def callers_of(self, function_ea: int) -> set[int]:
        return set()


class _Decompiler:
    def __init__(self, *, fail_on_call: bool = False) -> None:
        self.calls: list[int] = []
        self.fail_on_call = fail_on_call

    def decompile(self, function_ea: int):
        self.calls.append(function_ea)
        if self.fail_on_call:
            raise AssertionError("initial preparation must not call Hex-Rays")
        return object()


class _TypeMetadata:
    def __init__(self, snapshots: dict[int, SerializedTypeSnapshot]) -> None:
        self.snapshots = dict(snapshots)

    def capture(self, item_ea: int) -> SerializedTypeSnapshot:
        return self.snapshots.get(item_ea, SerializedTypeSnapshot.absent())

    def apply(self, item_ea, expected_before, replacement) -> None:
        if self.capture(item_ea) != expected_before:
            raise RuntimeError("type before-image mismatch")
        self.snapshots[item_ea] = replacement

    def restore(self, item_ea, expected_after, original) -> None:
        if self.capture(item_ea) != expected_after:
            raise RuntimeError("type after-image mismatch")
        self.snapshots[item_ea] = original


class _PostDeltaCommitFailureJournal(SQLitePreparationJournal):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self._fail_once = True

    def record_byte_deltas(self, transaction_id, deltas) -> None:
        super().record_byte_deltas(transaction_id, deltas)
        if self._fail_once:
            self._fail_once = False
            raise KeyboardInterrupt("process cut after delta commit")


def _request(database_identity: str = "idb-a") -> PreparationRunRequest:
    return PreparationRunRequest(
        database_identity=database_identity,
        anchor_function_ea=0x401000,
        script=PreparationScriptDescriptor(
            script_id="normalize",
            display_name="Normalize",
            path="normalize.py",
            source_sha256="a" * 64,
            enabled=True,
            portable=True,
        ),
        authorizing_attempt_id=ExecutionAttemptId.new(
            session=DecompilationSessionId.new(), sequence=1
        ),
    )


def _gateway(
    tmp_path: Path,
    *,
    writer: _Writer,
    action,
    database_identity: str = "idb-a",
    ledger: _Ledger | None = None,
    journal: SQLitePreparationJournal | None = None,
    native_ranges: tuple[tuple[int, int], ...] = (),
    reanalyzer: _Reanalyzer | None = None,
    invalidator: _Invalidator | None = None,
    decompiler: _Decompiler | None = None,
    type_metadata: _TypeMetadata | None = None,
) -> tuple[IdbPreparationGateway, SQLitePreparationJournal, _Decompiler]:
    durable_journal = journal or SQLitePreparationJournal(tmp_path / "journal.sqlite3")
    redo = decompiler or _Decompiler()
    gateway = IdbPreparationGateway(
        journal=durable_journal,
        patch_ledger=ledger or _Ledger(writer),
        script_runner=_Runner(action),
        byte_writer=writer,
        current_database_identity=database_identity,
        native_active_ranges=lambda identity: native_ranges,
        function_owner=lambda ea: 0x401000 if ea in writer.originals else None,
        reanalyzer=reanalyzer or _Reanalyzer(),
        cache_invalidator=invalidator or _Invalidator(),
        caller_discovery=_Callers(),
        redo_decompiler=redo,
        type_metadata=type_metadata,
    )
    return gateway, durable_journal, redo


def test_noop_script_reaches_idb_prepared_without_hexrays(tmp_path: Path) -> None:
    writer = _Writer({0x401000: 0x75})
    decompiler = _Decompiler(fail_on_call=True)
    gateway, journal, _ = _gateway(
        tmp_path,
        writer=writer,
        action=lambda context: None,
        decompiler=decompiler,
    )
    try:
        receipt = gateway.run(_request())
        assert receipt.ok
        assert receipt.state is PreparationState.IDB_PREPARED
        assert receipt.byte_deltas == ()
        assert decompiler.calls == []
    finally:
        journal.close()


def test_script_exception_before_writes_is_terminal_failed(tmp_path: Path) -> None:
    writer = _Writer({0x401000: 0x75})

    def _raise(_context) -> None:
        raise RuntimeError("script failed")

    gateway, journal, _ = _gateway(tmp_path, writer=writer, action=_raise)
    try:
        receipt = gateway.run(_request())
        assert receipt.state is PreparationState.FAILED
        assert "script failed" in receipt.failure_reason
        assert writer.calls == []
    finally:
        journal.close()


def test_reusable_transaction_requires_exact_live_after_image(tmp_path: Path) -> None:
    writer = _Writer({0x401000: 0x75})
    gateway, journal, _ = _gateway(
        tmp_path,
        writer=writer,
        action=lambda context: context.patch_bytes(0x401000, b"\xeb"),
    )
    try:
        receipt = gateway.run(_request())
        assert receipt.ok
        assert gateway.transaction_matches_after_image(receipt.transaction_id)

        writer.patches[0x401000] = 0x90
        assert not gateway.transaction_matches_after_image(receipt.transaction_id)
    finally:
        journal.close()


def test_script_exception_after_write_is_compensated(tmp_path: Path) -> None:
    writer = _Writer({0x401000: 0x75})

    def _patch_then_raise(context) -> None:
        context.patch_bytes(0x401000, b"\xeb")
        raise RuntimeError("script failed after write")

    gateway, journal, _ = _gateway(tmp_path, writer=writer, action=_patch_then_raise)
    try:
        receipt = gateway.run(_request())
        assert receipt.state is PreparationState.RESTORED
        assert writer.read_byte(0x401000) == 0x75
        assert writer.calls[-1] == ("revert_byte", 0x401000)
        assert "script failed after write" in receipt.failure_reason
    finally:
        journal.close()


def test_native_range_conflict_makes_no_persistent_write(tmp_path: Path) -> None:
    writer = _Writer({0x401000: 0x75})
    gateway, journal, _ = _gateway(
        tmp_path,
        writer=writer,
        action=lambda context: context.patch_bytes(0x401000, b"\xeb"),
        native_ranges=((0x401000, 0x401001),),
    )
    try:
        receipt = gateway.run(_request())
        assert receipt.state is PreparationState.RESTORED
        assert writer.read_byte(0x401000) == 0x75
        assert "native-patch" in receipt.failure_reason
    finally:
        journal.close()


def test_restore_preserves_inherited_patch_with_patch_not_revert(
    tmp_path: Path,
) -> None:
    writer = _Writer({0x401000: 0x75}, {0x401000: 0x74})
    gateway, journal, _ = _gateway(
        tmp_path,
        writer=writer,
        action=lambda context: context.patch_bytes(0x401000, b"\xeb"),
    )
    try:
        applied = gateway.run(_request())
        assert applied.ok

        restored = gateway.restore(applied.transaction_id)

        assert restored.ok
        assert writer.calls[-1] == ("patch_byte", 0x401000, 0x74)
        assert writer.patches[0x401000] == 0x74
    finally:
        journal.close()


def test_restore_refuses_current_byte_interference(tmp_path: Path) -> None:
    writer = _Writer({0x401000: 0x75})
    gateway, journal, _ = _gateway(
        tmp_path,
        writer=writer,
        action=lambda context: context.patch_bytes(0x401000, b"\xeb"),
    )
    try:
        applied = gateway.run(_request())
        writer.patch_byte(0x401000, 0xCC)
        calls_before_restore = tuple(writer.calls)

        restored = gateway.restore(applied.transaction_id)

        assert not restored.ok
        assert restored.interference_eas == (0x401000,)
        assert tuple(writer.calls) == calls_before_restore
    finally:
        journal.close()


def test_foreign_database_restore_rejects_before_read_or_write(tmp_path: Path) -> None:
    writer_a = _Writer({0x401000: 0x75})
    gateway_a, journal, _ = _gateway(
        tmp_path,
        writer=writer_a,
        action=lambda context: context.patch_bytes(0x401000, b"\xeb"),
    )
    applied = gateway_a.run(_request("idb-a"))
    writer_b = _Writer({0x401000: 0x75})
    gateway_b, _, _ = _gateway(
        tmp_path,
        writer=writer_b,
        action=lambda context: None,
        database_identity="idb-b",
        journal=journal,
    )
    try:
        restored = gateway_b.restore(applied.transaction_id)
        assert not restored.ok
        assert "foreign database" in restored.failure_reason
        assert writer_b.reads == 0
        assert writer_b.calls == []
    finally:
        journal.close()


def test_capture_failure_after_write_enters_recovery_required(tmp_path: Path) -> None:
    writer = _Writer({0x401000: 0x75})
    failing_ledger = _Ledger(writer, fail_on_capture=2)
    gateway, journal, _ = _gateway(
        tmp_path,
        writer=writer,
        ledger=failing_ledger,
        action=lambda context: context.patch_bytes(0x401000, b"\xeb"),
    )
    try:
        receipt = gateway.run(_request())
        assert receipt.state is PreparationState.RECOVERY_REQUIRED
        assert writer.read_byte(0x401000) == 0xEB

        recovery_gateway, _, _ = _gateway(
            tmp_path,
            writer=writer,
            journal=journal,
            action=lambda context: None,
        )
        recovered = recovery_gateway.recover_startup()
        assert len(recovered) == 1
        assert recovered[0].ok
        assert writer.read_byte(0x401000) == 0x75
    finally:
        journal.close()


def test_exception_after_delta_commit_is_compensated(tmp_path: Path) -> None:
    writer = _Writer({0x401000: 0x75})
    journal = _PostDeltaCommitFailureJournal(tmp_path / "journal.sqlite3")
    gateway, _, _ = _gateway(
        tmp_path,
        writer=writer,
        journal=journal,
        action=lambda context: context.patch_bytes(0x401000, b"\xeb"),
    )
    try:
        receipt = gateway.run(_request())
        assert receipt.state is PreparationState.RESTORED
        assert writer.read_byte(0x401000) == 0x75
        assert "process cut after delta commit" in receipt.failure_reason
    finally:
        journal.close()


def test_reanalysis_failure_restores_bytes_and_reconciles_analysis(
    tmp_path: Path,
) -> None:
    writer = _Writer({0x401000: 0x75})
    reanalyzer = _Reanalyzer(failures_remaining=1)
    gateway, journal, _ = _gateway(
        tmp_path,
        writer=writer,
        action=lambda context: context.patch_bytes(0x401000, b"\xeb"),
        reanalyzer=reanalyzer,
    )
    try:
        receipt = gateway.run(_request())
        assert receipt.state is PreparationState.RESTORED
        assert writer.read_byte(0x401000) == 0x75
        assert reanalyzer.calls.count(("reanalyze", 0x401000)) == 2
    finally:
        journal.close()


def test_restore_redoes_only_cfuncs_that_existed(tmp_path: Path) -> None:
    writer = _Writer({0x401000: 0x75})
    invalidator = _Invalidator(erased=True)
    decompiler = _Decompiler()
    gateway, journal, _ = _gateway(
        tmp_path,
        writer=writer,
        action=lambda context: context.patch_bytes(0x401000, b"\xeb"),
        invalidator=invalidator,
        decompiler=decompiler,
    )
    try:
        applied = gateway.run(_request())
        assert decompiler.calls == []
        restored = gateway.restore(applied.transaction_id)
        assert restored.ok
        assert restored.controlled_redo_function_eas == (0x401000,)
        assert decompiler.calls == [0x401000]
    finally:
        journal.close()


def test_restore_does_not_redo_when_no_cfunc_was_invalidated(tmp_path: Path) -> None:
    writer = _Writer({0x401000: 0x75})
    decompiler = _Decompiler(fail_on_call=True)
    gateway, journal, _ = _gateway(
        tmp_path,
        writer=writer,
        action=lambda context: context.patch_bytes(0x401000, b"\xeb"),
        invalidator=_Invalidator(erased=False),
        decompiler=decompiler,
    )
    try:
        applied = gateway.run(_request())
        restored = gateway.restore(applied.transaction_id)
        assert restored.ok
        assert restored.controlled_redo_function_eas == ()
        assert decompiler.calls == []
    finally:
        journal.close()


def test_type_proposal_applies_and_restores_exact_snapshot(tmp_path: Path) -> None:
    writer = _Writer({0x401000: 0x75})
    before = SerializedTypeSnapshot.absent()
    after = SerializedTypeSnapshot.from_parts(b"const-array", b"fields", b"comments")
    types = _TypeMetadata({0x500000: before})
    gateway, journal, _ = _gateway(
        tmp_path,
        writer=writer,
        action=lambda context: None,
        type_metadata=types,
    )
    proposal = PreparationTypeDelta(0x500000, before, after)
    try:
        applied = gateway.run(_request(), type_proposals=(proposal,))
        assert applied.ok
        assert types.capture(0x500000) == after

        restored = gateway.restore(applied.transaction_id)
        assert restored.ok
        assert types.capture(0x500000) == before
    finally:
        journal.close()


def test_restore_refuses_user_type_edit_after_apply(tmp_path: Path) -> None:
    writer = _Writer({0x401000: 0x75})
    before = SerializedTypeSnapshot.from_parts(b"before", None, None)
    after = SerializedTypeSnapshot.from_parts(b"const", None, None)
    user_edit = SerializedTypeSnapshot.from_parts(b"user", None, None)
    types = _TypeMetadata({0x500000: before})
    gateway, journal, _ = _gateway(
        tmp_path,
        writer=writer,
        action=lambda context: None,
        type_metadata=types,
    )
    try:
        applied = gateway.run(
            _request(),
            type_proposals=(PreparationTypeDelta(0x500000, before, after),),
        )
        types.snapshots[0x500000] = user_edit

        restored = gateway.restore(applied.transaction_id)

        assert not restored.ok
        assert restored.interference_type_eas == (0x500000,)
        assert types.capture(0x500000) == user_edit
    finally:
        journal.close()
