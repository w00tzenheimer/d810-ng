"""Fake-based gateway tests: apply/restore, failure injection, and the
certificate/no-rerun boundary.

Task 6 ("Single-operation native gateway, reanalysis, and certificate") of
``_gitless/profile-guided-native-mutation-implementer-plan.md``. No IDA
import anywhere in this module -- every live-IDA seam
(``LiveDatabaseReader``, ``NativeByteWriter``, ``FunctionReanalyzer``,
``CfuncCacheInvalidator``, ``CallerDiscovery``, ``ControlledRedoDecompiler``,
``NativePatchBlobStore``) is a plain structural Protocol, and
:class:`FakeNativeDatabase` plus the small recording fakes below are plain
Python objects, per this repository's "no IDA mocking in unit tests" rule
(``tests/unit/conftest.py``). The Docker system-test suite
(``tests/system/runtime/backends/ida/test_native_patch_gateway.py``) is what
exercises the real ``ida_bytes``/``ida_funcs``/``ida_hexrays`` calls.
"""

from __future__ import annotations

import dataclasses

import pytest

from d810.backends.ida.native_patch.gateway import (
    NativePatchGateway,
    NativePatchRestoreNotCertified,
)
from d810.backends.ida.native_patch.journal import SQLiteNativePatchJournal
from d810.capabilities.native_patch import NativeJournalState
from d810.transforms.native_patch_plan import NativeCertificateState

from . import _plan_fixtures as fixtures

pytestmark = pytest.mark.pure_python


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeNativeDatabase:
    """One shared per-EA byte store standing in for both ``LiveDatabaseReader``
    and ``NativeByteWriter``. Sharing the store is required: the gateway
    reuses the same reader for the pre-write preflight recheck *and* the
    post-write certification recapture, so writes made through the writer
    half must be visible through the reader half.
    """

    def __init__(self, operations):
        self.bytes: dict[int, int] = {}
        self.original: dict[int, int] = {}
        self.reset_item_boundary_calls: list[tuple[int, int]] = []
        self._patch_rows: dict[tuple[int, int], tuple] = {}
        self._item_shape: dict[tuple[int, int], object] = {}
        self._incoming_refs: dict[tuple[int, int], tuple] = {}
        self._ownership: dict[int, object] = {}
        for op in operations:
            key = (op.range.start_ea, op.range.end_ea)
            for offset, ea in enumerate(range(op.range.start_ea, op.range.end_ea)):
                self.bytes[ea] = op.expected_current_bytes[offset]
                self.original[ea] = op.expected_original_bytes[offset]
            self._patch_rows[key] = op.expected_patch_rows
            self._item_shape[key] = op.expected_item_shape
            self._incoming_refs[key] = op.expected_incoming_refs
            self._ownership[op.expected_function_ownership.owning_function_entry_ea] = (
                op.expected_function_ownership
            )

    # -- LiveDatabaseReader --------------------------------------------

    def read_current_bytes(self, start_ea, end_ea):
        values = [self.bytes.get(ea) for ea in range(start_ea, end_ea)]
        if any(v is None for v in values):
            return None
        return bytes(values)

    def read_original_bytes(self, start_ea, end_ea):
        values = [self.original.get(ea) for ea in range(start_ea, end_ea)]
        if any(v is None for v in values):
            return None
        return bytes(values)

    def read_patch_rows(self, start_ea, end_ea):
        return self._patch_rows.get((start_ea, end_ea), ())

    def read_item_shape(self, start_ea, end_ea):
        return self._item_shape[(start_ea, end_ea)]

    def read_incoming_refs(self, start_ea, end_ea):
        return self._incoming_refs.get((start_ea, end_ea), ())

    def read_function_ownership(self, ea):
        return self._ownership.get(ea)

    # -- NativeByteWriter -------------------------------------------------

    def read_byte(self, ea):
        return self.bytes.get(ea)

    def patch_byte(self, ea, value):
        self.bytes[ea] = value

    def revert_byte(self, ea):
        self.bytes[ea] = self.original[ea]

    def reset_item_boundaries(self, start_ea, end_ea):
        self.reset_item_boundary_calls.append((start_ea, end_ea))


def _decode_replacement(ea, data):
    return fixtures.shape(ea, len(data), "jmp")


def _sole_transaction_id(journal: SQLiteNativePatchJournal):
    """The one transaction id a test's journal has prepared so far.

    Test-only introspection: nothing in the public ``NativePatchJournalStore``
    Protocol enumerates transactions (by design -- see ``gateway.py``'s
    ``recover()`` docstring, which leaves enumeration to the caller), so
    these tests read the SQLite row directly rather than adding a
    production API only they would use.
    """
    from d810.capabilities.native_patch import NativePatchTransactionId

    row = journal._conn.execute(  # noqa: SLF001 - test introspection
        "SELECT transaction_id FROM native_patch_transactions"
    ).fetchone()
    return NativePatchTransactionId(value=row["transaction_id"])


class RecordingReanalyzer:
    def __init__(self, raise_on: str | None = None):
        self.calls: list[tuple] = []
        self._raise_on = raise_on

    def reanalyze_function(self, function_ea):
        self.calls.append(("reanalyze_function", function_ea))
        if self._raise_on == "reanalyze_function":
            raise RuntimeError("injected: reanalyze_function")

    def auto_wait(self):
        self.calls.append(("auto_wait",))
        if self._raise_on == "auto_wait":
            raise RuntimeError("injected: auto_wait")


class RecordingCacheInvalidator:
    def __init__(self, raise_on_ea: int | None = None):
        self.calls: list[int] = []
        self._raise_on_ea = raise_on_ea

    def mark_cfunc_dirty(self, function_ea):
        self.calls.append(function_ea)
        if self._raise_on_ea is not None and function_ea == self._raise_on_ea:
            raise RuntimeError("injected: mark_cfunc_dirty")
        return True


class FakeCallerDiscovery:
    def __init__(self, callers: frozenset[int] = frozenset()):
        self.callers = callers
        self.queried: list[int] = []

    def callers_of(self, function_ea):
        self.queried.append(function_ea)
        return self.callers


class RecordingRedoDecompiler:
    def __init__(self):
        self.calls: list[int] = []

    def decompile(self, function_ea):
        self.calls.append(function_ea)
        return object()


class FakeBlobStore:
    def __init__(self):
        self._data: dict[tuple[str, str], dict] = {}

    def get_native_patch_blob(self, scope, key):
        row = self._data.get((scope, key))
        return dict(row) if row is not None else None

    def set_native_patch_blob(self, scope, key, payload):
        self._data[(scope, key)] = dict(payload)

    def clear_native_patch_blob(self, scope, key):
        self._data.pop((scope, key), None)


class RaisingBlobStore(FakeBlobStore):
    def set_native_patch_blob(self, scope, key, payload):
        if scope == "transaction_mirror":
            raise RuntimeError("injected: netnode mirror write failed")
        super().set_native_patch_blob(scope, key, payload)


@dataclasses.dataclass
class Gateway:
    """Bundle of a gateway plus the fakes/journal that back it, so tests can
    both drive ``gateway.apply()``/``gateway.restore()`` and inspect the
    fakes' recorded calls afterward."""

    gateway: NativePatchGateway
    journal: SQLiteNativePatchJournal
    db: FakeNativeDatabase
    reanalyzer: RecordingReanalyzer
    invalidator: RecordingCacheInvalidator
    discovery: FakeCallerDiscovery
    redo: RecordingRedoDecompiler
    blobs: FakeBlobStore


def build_gateway(
    tmp_path,
    operations,
    *,
    callers: frozenset[int] = frozenset(),
    reanalyzer: RecordingReanalyzer | None = None,
    invalidator: RecordingCacheInvalidator | None = None,
    decode_replacement=_decode_replacement,
    blobs: FakeBlobStore | None = None,
) -> Gateway:
    journal = SQLiteNativePatchJournal(tmp_path / "journal.db")
    db = FakeNativeDatabase(operations)
    reanalyzer = reanalyzer or RecordingReanalyzer()
    invalidator = invalidator or RecordingCacheInvalidator()
    discovery = FakeCallerDiscovery(callers)
    redo = RecordingRedoDecompiler()
    blobs = blobs if blobs is not None else FakeBlobStore()
    gateway = NativePatchGateway(
        journal=journal,
        reader=db,
        writer=db,
        decode_replacement=decode_replacement,
        reanalyzer=reanalyzer,
        cache_invalidator=invalidator,
        caller_discovery=discovery,
        redo_decompiler=redo,
        certificate_store=blobs,
        d810_version="test",
    )
    return Gateway(
        gateway=gateway,
        journal=journal,
        db=db,
        reanalyzer=reanalyzer,
        invalidator=invalidator,
        discovery=discovery,
        redo=redo,
        blobs=blobs,
    )


@pytest.fixture
def rig(tmp_path):
    bundle = build_gateway(tmp_path, (fixtures.operation(),))
    yield bundle
    bundle.journal.close()


# ---------------------------------------------------------------------------
# apply(): the success path
# ---------------------------------------------------------------------------


class TestApplySuccess:
    def test_apply_certifies_and_writes_only_replacement_bytes(self, rig) -> None:
        before = dict(rig.db.bytes)
        receipt = rig.gateway.apply(fixtures.plan())

        assert receipt.ok
        assert receipt.state is NativeJournalState.CERTIFIED
        assert receipt.certificate is not None
        assert receipt.certificate.state is NativeCertificateState.APPLIED
        assert rig.db.bytes == {0x1000: 0xEB, 0x1001: 0x01}
        assert before != rig.db.bytes

    def test_apply_reanalyzes_the_owning_function_and_waits(self, rig) -> None:
        rig.gateway.apply(fixtures.plan())
        assert ("reanalyze_function", 0x1000) in rig.reanalyzer.calls
        assert ("auto_wait",) in rig.reanalyzer.calls

    def test_apply_resets_item_boundaries_before_reanalysis(self, rig) -> None:
        # Measured on IDA 9.4 (Docker system-test run): reanalyze_function()
        # alone left a stale successor edge after a byte round-trip;
        # resetting item boundaries across the governed range before
        # reanalysis is what actually fixed it. Pinned here so a future
        # refactor cannot silently drop the call.
        rig.gateway.apply(fixtures.plan())
        assert rig.db.reset_item_boundary_calls == [(0x1000, 0x1002)]

    def test_restore_resets_item_boundaries_before_reanalysis(self, rig) -> None:
        receipt = rig.gateway.apply(fixtures.plan())
        rig.db.reset_item_boundary_calls.clear()

        rig.gateway.restore(receipt.transaction_id)

        assert rig.db.reset_item_boundary_calls == [(0x1000, 0x1002)]

    def test_apply_invalidates_target_and_every_known_caller(self, tmp_path) -> None:
        rig = build_gateway(
            tmp_path, (fixtures.operation(),), callers=frozenset({0x9000, 0x9100})
        )
        rig.gateway.apply(fixtures.plan())
        assert set(rig.invalidator.calls) == {0x1000, 0x9000, 0x9100}
        rig.journal.close()

    def test_apply_performs_one_controlled_redo(self, rig) -> None:
        rig.gateway.apply(fixtures.plan())
        assert rig.redo.calls == [0x1000]

    def test_apply_mirrors_the_transaction_and_records_a_written_receipt(
        self, rig
    ) -> None:
        receipt = rig.gateway.apply(fixtures.plan())
        mirrored = rig.blobs.get_native_patch_blob(
            "transaction_mirror", receipt.transaction_id.value
        )
        assert mirrored is not None
        assert mirrored["plan_hash"] == fixtures.plan().plan_hash

        mirror_receipts = rig.journal.mirror_receipts(receipt.transaction_id)
        assert len(mirror_receipts) == 1
        assert mirror_receipts[0].outcome.value == "mirror_written"

    def test_apply_stores_a_certificate_keyed_by_function_and_database(
        self, rig
    ) -> None:
        plan = fixtures.plan()
        receipt = rig.gateway.apply(plan)
        looked_up = rig.gateway.lookup_certificate(
            plan.function_identity.entry_ea, plan.database_identity
        )
        assert looked_up is not None
        assert looked_up.certificate_id == receipt.certificate.certificate_id
        assert looked_up.native_plan_hash == plan.plan_hash

    def test_mirror_write_failure_is_a_separate_receipt_and_does_not_abort(
        self, tmp_path
    ) -> None:
        rig = build_gateway(tmp_path, (fixtures.operation(),), blobs=RaisingBlobStore())
        receipt = rig.gateway.apply(fixtures.plan())

        assert receipt.ok, "a mirror failure must not abort the apply"
        mirror_receipts = rig.journal.mirror_receipts(receipt.transaction_id)
        assert len(mirror_receipts) == 1
        assert mirror_receipts[0].outcome.value == "mirror_failed"
        rig.journal.close()


# ---------------------------------------------------------------------------
# apply(): preflight rejection right after PREPARED -- zero writes
# ---------------------------------------------------------------------------


class TestApplyPreflightRejection:
    def test_current_bytes_mismatch_abandons_without_writing(self, rig) -> None:
        rig.db.bytes[0x1000] = 0x90  # diverges from expected_current_bytes[0]

        receipt = rig.gateway.apply(fixtures.plan())

        assert not receipt.ok
        assert receipt.state is NativeJournalState.RECOVERY_REQUIRED
        assert "EXTERNAL_INTERFERENCE" in receipt.rejection_reasons
        # No byte the gateway did not author changed.
        assert rig.db.bytes[0x1000] == 0x90
        assert rig.db.bytes[0x1001] == 0x01

    def test_non_interference_rejection_is_a_clean_zero_op_abandon(self, rig) -> None:
        # Function-ownership mismatch is not "external interference" -- it is
        # a precondition failure with nothing written yet, so this is a clean
        # abandon (RESTORED, zero-op) rather than RECOVERY_REQUIRED.
        plan = fixtures.plan(
            operations=(
                dataclasses.replace(
                    fixtures.operation(),
                    expected_function_ownership=dataclasses.replace(
                        fixtures.operation().expected_function_ownership,
                        owning_function_entry_ea=0x2000,
                    ),
                ),
            )
        )
        receipt = rig.gateway.apply(plan)

        assert not receipt.ok
        assert receipt.state is NativeJournalState.RESTORED
        assert rig.db.bytes == {0x1000: 0x75, 0x1001: 0x01}


# ---------------------------------------------------------------------------
# apply(): failure injection after each durable checkpoint
# ---------------------------------------------------------------------------


class TestApplyFailureInjection:
    def test_failure_after_prepared_but_before_any_write_rolls_back_cleanly(
        self, tmp_path
    ) -> None:
        def _broken_decode(ea, data):
            raise RuntimeError("injected: decode_replacement raised")

        rig = build_gateway(
            tmp_path, (fixtures.operation(),), decode_replacement=_broken_decode
        )
        with pytest.raises(RuntimeError, match="injected"):
            rig.gateway.apply(fixtures.plan())

        # Nothing was ever written -- a clean zero-op rollback, not a report
        # of success after nothing happened.
        assert rig.db.bytes == {0x1000: 0x75, 0x1001: 0x01}
        record = rig.journal.get(_sole_transaction_id(rig.journal))
        assert record.state is NativeJournalState.RESTORED
        rig.journal.close()

    def test_failure_after_ida_write_rolls_back_the_written_bytes(
        self, tmp_path
    ) -> None:
        op = fixtures.operation()
        rig = build_gateway(
            tmp_path,
            (op,),
            reanalyzer=RecordingReanalyzer(raise_on="reanalyze_function"),
        )
        with pytest.raises(RuntimeError, match="injected: reanalyze_function"):
            rig.gateway.apply(fixtures.plan())

        # Bytes were written (BYTES_APPLIED durably reached) then rolled back.
        assert rig.db.bytes == {0x1000: 0x75, 0x1001: 0x01}
        record = rig.journal.get(_sole_transaction_id(rig.journal))
        assert record.state is NativeJournalState.RESTORED
        rig.journal.close()

    def test_failure_after_reanalysis_request_rolls_back(self, tmp_path) -> None:
        rig = build_gateway(
            tmp_path,
            (fixtures.operation(),),
            reanalyzer=RecordingReanalyzer(raise_on="auto_wait"),
        )
        with pytest.raises(RuntimeError, match="injected: auto_wait"):
            rig.gateway.apply(fixtures.plan())

        assert rig.db.bytes == {0x1000: 0x75, 0x1001: 0x01}
        rig.journal.close()

    def test_failure_after_cache_invalidation_rolls_back(self, tmp_path) -> None:
        rig = build_gateway(
            tmp_path,
            (fixtures.operation(),),
            invalidator=RecordingCacheInvalidator(raise_on_ea=0x1000),
        )
        with pytest.raises(RuntimeError, match="injected: mark_cfunc_dirty"):
            rig.gateway.apply(fixtures.plan())

        assert rig.db.bytes == {0x1000: 0x75, 0x1001: 0x01}
        rig.journal.close()

    def test_mid_write_failure_classifies_per_byte_and_rolls_back_cleanly(
        self, tmp_path
    ) -> None:
        # A 4-byte operation so a fault can land strictly between two bytes.
        op = fixtures.operation(
            start_ea=0x3000,
            end_ea=0x3004,
            expected_current_bytes=b"\x11\x22\x33\x44",
            replacement_bytes=b"\xaa\xbb\xcc\xdd",
        )
        journal = SQLiteNativePatchJournal(tmp_path / "journal.db")

        class _MidWriteFaultyDb(FakeNativeDatabase):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.patch_count = 0

            def patch_byte(self, ea, value):
                self.patch_count += 1
                if self.patch_count == 3:
                    # Bytes 1 and 2 (offsets 0,1) are already AFTER; this is
                    # byte offset 2 -- fail before it (and offset 3) land.
                    raise RuntimeError("injected: mid-write fault")
                super().patch_byte(ea, value)

        faulty_db = _MidWriteFaultyDb((op,))
        gateway = NativePatchGateway(
            journal=journal,
            reader=faulty_db,
            writer=faulty_db,
            decode_replacement=_decode_replacement,
            reanalyzer=RecordingReanalyzer(),
            cache_invalidator=RecordingCacheInvalidator(),
            caller_discovery=FakeCallerDiscovery(),
            redo_decompiler=RecordingRedoDecompiler(),
            certificate_store=FakeBlobStore(),
        )

        plan = fixtures.plan(operations=(op,))
        with pytest.raises(RuntimeError, match="injected: mid-write"):
            gateway.apply(plan)

        # Every byte is back to its original value -- a clean, fully
        # disambiguated partial write rolled back per-byte.
        assert faulty_db.bytes == {
            0x3000: 0x11,
            0x3001: 0x22,
            0x3002: 0x33,
            0x3003: 0x44,
        }
        journal.close()

    def test_mid_write_external_interference_is_never_auto_overwritten(
        self, tmp_path
    ) -> None:
        """The mandatory negative: a byte matching neither before nor after
        must never be silently overwritten by automatic recovery."""
        op = fixtures.operation(
            start_ea=0x3000,
            end_ea=0x3004,
            expected_current_bytes=b"\x11\x22\x33\x44",
            replacement_bytes=b"\xaa\xbb\xcc\xdd",
        )
        journal = SQLiteNativePatchJournal(tmp_path / "journal.db")

        class _InterferingDb(FakeNativeDatabase):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.patch_count = 0

            def patch_byte(self, ea, value):
                self.patch_count += 1
                super().patch_byte(ea, value)
                if self.patch_count == 2:
                    # Something else corrupts a byte we have not reached yet
                    # (offset 3, ea 0x3003) to a third value.
                    self.bytes[0x3003] = 0xFF
                    raise RuntimeError("injected: interference mid-write")

        db = _InterferingDb((op,))
        gateway = NativePatchGateway(
            journal=journal,
            reader=db,
            writer=db,
            decode_replacement=_decode_replacement,
            reanalyzer=RecordingReanalyzer(),
            cache_invalidator=RecordingCacheInvalidator(),
            caller_discovery=FakeCallerDiscovery(),
            redo_decompiler=RecordingRedoDecompiler(),
            certificate_store=FakeBlobStore(),
        )

        plan = fixtures.plan(operations=(op,))
        with pytest.raises(RuntimeError, match="injected: interference"):
            gateway.apply(plan)

        # The corrupted byte was NEVER touched by recovery.
        assert db.bytes[0x3003] == 0xFF
        record = journal.get(_sole_transaction_id(journal))
        assert record.state is NativeJournalState.RECOVERY_REQUIRED
        journal.close()


# ---------------------------------------------------------------------------
# restore()
# ---------------------------------------------------------------------------


class TestRestore:
    def test_restore_requires_a_certified_transaction(self, rig) -> None:
        record = rig.journal.prepare(fixtures.plan())
        with pytest.raises(NativePatchRestoreNotCertified):
            rig.gateway.restore(record.transaction_id)

    def test_restore_reproduces_the_exact_pre_apply_state(self, rig) -> None:
        before = dict(rig.db.bytes)
        receipt = rig.gateway.apply(fixtures.plan())
        assert receipt.ok

        restored = rig.gateway.restore(receipt.transaction_id)

        assert restored.ok
        assert restored.state is NativeJournalState.RESTORED
        assert rig.db.bytes == before

    def test_restore_uses_patch_byte_for_a_byte_that_carried_an_inherited_patch(
        self, tmp_path
    ) -> None:
        # A byte whose "current" (pre-transaction) value already differs from
        # IDA's true original layer -- an inherited, pre-existing patch.
        # Restoring must reproduce that inherited value with patch_byte, not
        # erase it with revert_byte (which would fall back to the IDA
        # original layer and destroy the inherited patch).
        op = fixtures.operation(
            expected_current_bytes=b"\x75\x01",
            expected_original_bytes=b"\x90\x01",  # ea 0x1000 already patched
            replacement_bytes=b"\xeb\x01",
        )
        rig = build_gateway(tmp_path, (op,))
        receipt = rig.gateway.apply(fixtures.plan(operations=(op,)))
        assert receipt.ok

        restored = rig.gateway.restore(receipt.transaction_id)

        assert restored.ok
        # Restored to the *inherited current* value (0x75), not IDA-original
        # (0x90).
        assert rig.db.bytes[0x1000] == 0x75
        assert rig.db.bytes[0x1001] == 0x01
        rig.journal.close()

    def test_restore_detects_interference_and_requires_recovery(self, rig) -> None:
        receipt = rig.gateway.apply(fixtures.plan())
        assert receipt.ok
        # Something external corrupts a governed byte after certification.
        rig.db.bytes[0x1000] = 0x33

        restored = rig.gateway.restore(receipt.transaction_id)

        assert not restored.ok
        assert restored.state is NativeJournalState.RECOVERY_REQUIRED
        assert 0x1000 in restored.interference_eas
        # The corrupted byte was never auto-overwritten.
        assert rig.db.bytes[0x1000] == 0x33

    def test_restore_reanalyzes_and_invalidates_target_and_callers(
        self, tmp_path
    ) -> None:
        rig = build_gateway(
            tmp_path, (fixtures.operation(),), callers=frozenset({0x9000})
        )
        receipt = rig.gateway.apply(fixtures.plan())
        rig.reanalyzer.calls.clear()
        rig.invalidator.calls.clear()

        rig.gateway.restore(receipt.transaction_id)

        assert ("reanalyze_function", 0x1000) in rig.reanalyzer.calls
        assert set(rig.invalidator.calls) == {0x1000, 0x9000}
        rig.journal.close()


# ---------------------------------------------------------------------------
# recover() -- section 15.4, startup recovery entry point
# ---------------------------------------------------------------------------


class TestRecover:
    def test_recover_on_a_transaction_stuck_at_bytes_applied_rolls_back(
        self, rig
    ) -> None:
        record = rig.journal.prepare(fixtures.plan())
        op = fixtures.operation()
        for offset, ea in enumerate(range(op.range.start_ea, op.range.end_ea)):
            rig.db.bytes[ea] = op.replacement_bytes[offset]
        rig.journal.transition(record.transaction_id, NativeJournalState.BYTES_APPLIED)
        # Process "crashes" here -- restart calls recover().

        rig.gateway.recover(record.transaction_id)

        after = rig.journal.get(record.transaction_id)
        assert after.state is NativeJournalState.RESTORED
        assert rig.db.bytes == {0x1000: 0x75, 0x1001: 0x01}

    def test_recover_on_an_already_terminal_transaction_is_a_no_op(self, rig) -> None:
        receipt = rig.gateway.apply(fixtures.plan())
        rig.gateway.restore(receipt.transaction_id)
        before = rig.journal.get(receipt.transaction_id)

        rig.gateway.recover(receipt.transaction_id)

        after = rig.journal.get(receipt.transaction_id)
        assert after.state == before.state
