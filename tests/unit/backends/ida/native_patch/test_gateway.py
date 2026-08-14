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
from d810.manager.native_normalization import _certificate_matches, recover_startup
from d810.transforms.native_patch_plan import (
    NativeAddressRange,
    NativeCertificateState,
)

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
        self.patch_byte_calls: list[tuple[int, int]] = []
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
        self.patch_byte_calls.append((ea, value))
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


class RecordingExtentRestorer:
    """Fake :class:`FunctionExtentRestorer`.

    ``succeeds=False`` models IDA refusing to re-establish the extent, which
    must downgrade the restore receipt rather than report RESTORED over a
    database whose shape was not restored.
    """

    def __init__(self, succeeds: bool = True, raise_always: bool = False):
        self.calls: list[tuple[int, int]] = []
        self._succeeds = succeeds
        self._raise_always = raise_always

    def restore_function_extent(self, entry_ea: int, end_ea: int) -> bool:
        self.calls.append((entry_ea, end_ea))
        if self._raise_always:
            raise RuntimeError("injected: restore_function_extent")
        return self._succeeds


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
        self.raise_on_callers = False

    def callers_of(self, function_ea):
        self.queried.append(function_ea)
        if self.raise_on_callers:
            raise RuntimeError("injected: caller discovery")
        return self.callers


class RecordingRedoDecompiler:
    def __init__(self):
        self.calls: list[int] = []
        self.raise_on_decompile = False

    def decompile(self, function_ea):
        self.calls.append(function_ea)
        if self.raise_on_decompile:
            raise RuntimeError("injected: controlled redo")
        return object()


class FakeBlobStore:
    def __init__(self):
        self._data: dict[tuple[str, str], dict] = {}
        self.raise_on_clear = False

    def get_native_patch_blob(self, scope, key):
        row = self._data.get((scope, key))
        return dict(row) if row is not None else None

    def set_native_patch_blob(self, scope, key, payload):
        self._data[(scope, key)] = dict(payload)

    def clear_native_patch_blob(self, scope, key):
        if self.raise_on_clear:
            raise RuntimeError("injected: certificate revocation")
        self._data.pop((scope, key), None)


class RaisingBlobStore(FakeBlobStore):
    def set_native_patch_blob(self, scope, key, payload):
        if scope == "transaction_mirror":
            raise RuntimeError("injected: netnode mirror write failed")
        super().set_native_patch_blob(scope, key, payload)


class CrashingCertificateBlobStore(FakeBlobStore):
    """Models process death at the certificate-store cut point.

    ``KeyboardInterrupt`` intentionally bypasses ``apply()``'s ordinary
    exception handler, leaving only the durable journal state for startup to
    reconcile.
    """

    def set_native_patch_blob(self, scope, key, payload):
        if scope == "certificate_transaction":
            raise KeyboardInterrupt("injected: certificate-store crash")
        super().set_native_patch_blob(scope, key, payload)


class FailingCertificateBlobStore(FakeBlobStore):
    def set_native_patch_blob(self, scope, key, payload):
        if scope == "certificate":
            raise RuntimeError("injected: certificate write failed")
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
    extent_restorer: RecordingExtentRestorer
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
    extent_restorer: RecordingExtentRestorer | None = None,
    metadata_executor=None,
    invalidator: RecordingCacheInvalidator | None = None,
    decode_replacement=_decode_replacement,
    blobs: FakeBlobStore | None = None,
) -> Gateway:
    journal = SQLiteNativePatchJournal(tmp_path / "journal.db")
    db = FakeNativeDatabase(operations)
    reanalyzer = reanalyzer or RecordingReanalyzer()
    extent_restorer = extent_restorer or RecordingExtentRestorer()
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
        extent_restorer=extent_restorer,
        metadata_executor=metadata_executor,
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
        extent_restorer=extent_restorer,
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

    def test_obsolete_certificate_payload_fails_closed_as_a_cache_miss(
        self, rig
    ) -> None:
        plan = fixtures.plan()
        key = rig.gateway._certificate_key(  # noqa: SLF001 - storage fixture
            plan.function_identity.entry_ea, plan.database_identity
        )
        rig.blobs.set_native_patch_blob(
            "certificate", key, {"schema_version": 1, "certificate_id": "old"}
        )

        assert (
            rig.gateway.lookup_certificate(
                plan.function_identity.entry_ea, plan.database_identity
            )
            is None
        )

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

    def test_certificate_store_crash_remains_startup_recoverable(
        self, tmp_path
    ) -> None:
        """CERTIFIED must not be durable before both certificate writes are."""
        rig = build_gateway(
            tmp_path,
            (fixtures.operation(),),
            blobs=CrashingCertificateBlobStore(),
        )
        before = dict(rig.db.bytes)

        with pytest.raises(KeyboardInterrupt, match="certificate-store crash"):
            rig.gateway.apply(fixtures.plan())

        transaction_id = _sole_transaction_id(rig.journal)
        assert (
            rig.journal.get(transaction_id).state
            is NativeJournalState.CERTIFICATE_PENDING
        )
        assert rig.db.bytes != before

        recovered = recover_startup(journal=rig.journal, gateway=rig.gateway)

        assert recovered == (transaction_id,)
        assert rig.journal.get(transaction_id).state is NativeJournalState.RESTORED
        assert rig.db.bytes == before
        assert (
            rig.blobs.get_native_patch_blob(
                "certificate_transaction", transaction_id.value
            )
            is None
        )
        rig.journal.close()

    def test_certificate_write_failure_revokes_the_prior_transaction_link(
        self, tmp_path
    ) -> None:
        rig = build_gateway(
            tmp_path,
            (fixtures.operation(),),
            blobs=FailingCertificateBlobStore(),
        )
        before = dict(rig.db.bytes)

        with pytest.raises(RuntimeError, match="certificate write failed"):
            rig.gateway.apply(fixtures.plan())

        transaction_id = _sole_transaction_id(rig.journal)
        assert rig.journal.get(transaction_id).state is NativeJournalState.RESTORED
        assert rig.db.bytes == before
        assert (
            rig.blobs.get_native_patch_blob(
                "certificate_transaction", transaction_id.value
            )
            is None
        )
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
            extent_restorer=RecordingExtentRestorer(),
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
            extent_restorer=RecordingExtentRestorer(),
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
            extent_restorer=RecordingExtentRestorer(),
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
            extent_restorer=RecordingExtentRestorer(),
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

    def test_restore_performs_controlled_redo_after_reanalysis(self, rig) -> None:
        receipt = rig.gateway.apply(fixtures.plan())
        assert receipt.ok
        rig.redo.calls.clear()

        restored = rig.gateway.restore(receipt.transaction_id)

        assert restored.ok
        assert rig.redo.calls == [0x1000]
        assert restored.controlled_redo_function_eas == (0x1000,)

    def test_restore_redo_failure_is_startup_retryable(self, rig) -> None:
        """A restore-lane exception must leave a durable resumable state."""
        before = dict(rig.db.bytes)
        receipt = rig.gateway.apply(fixtures.plan())
        assert receipt.ok
        rig.redo.raise_on_decompile = True

        failed = rig.gateway.restore(receipt.transaction_id)

        assert failed.state is NativeJournalState.RESTORE_FAILED
        assert not failed.ok
        assert rig.journal.get(receipt.transaction_id).state is (
            NativeJournalState.RESTORE_FAILED
        )
        assert rig.db.bytes == before

        rig.redo.raise_on_decompile = False
        recovered = recover_startup(journal=rig.journal, gateway=rig.gateway)

        assert recovered == (receipt.transaction_id,)
        assert (
            rig.journal.get(receipt.transaction_id).state is NativeJournalState.RESTORED
        )

    @pytest.mark.parametrize(
        "stage",
        (
            "reanalyze_function",
            "auto_wait",
            "caller_discovery",
            "cache_invalidation",
        ),
    )
    def test_restore_lifecycle_failure_is_durable_and_startup_retryable(
        self, rig, stage
    ) -> None:
        """Every required restore lifecycle primitive has one failure boundary."""
        receipt = rig.gateway.apply(fixtures.plan())
        assert receipt.ok
        if stage in {"reanalyze_function", "auto_wait"}:
            rig.reanalyzer._raise_on = stage  # noqa: SLF001 - test injection
        elif stage == "caller_discovery":
            rig.discovery.raise_on_callers = True
        else:
            rig.invalidator._raise_on_ea = 0x1000  # noqa: SLF001 - test injection

        failed = rig.gateway.restore(receipt.transaction_id)

        assert failed.state is NativeJournalState.RESTORE_FAILED
        assert failed.failure_reason is not None

        rig.reanalyzer._raise_on = None  # noqa: SLF001 - test injection
        rig.discovery.raise_on_callers = False
        rig.invalidator._raise_on_ea = None  # noqa: SLF001 - test injection
        recover_startup(journal=rig.journal, gateway=rig.gateway)

        assert (
            rig.journal.get(receipt.transaction_id).state is NativeJournalState.RESTORED
        )

    def test_certificate_revocation_failure_requires_acknowledged_retry(
        self, rig
    ) -> None:
        receipt = rig.gateway.apply(fixtures.plan())
        assert receipt.ok
        rig.blobs.raise_on_clear = True

        failed = rig.gateway.restore(receipt.transaction_id)

        assert failed.state is NativeJournalState.RECOVERY_REQUIRED
        assert not failed.ok

        rig.blobs.raise_on_clear = False
        resumed = rig.gateway.restore(
            receipt.transaction_id,
            acknowledge_recovery_required=True,
        )

        assert resumed.ok
        assert resumed.state is NativeJournalState.RESTORED

    def test_restore_revokes_the_applied_certificate(self, rig) -> None:
        """A restored function must never continue to short-circuit a plan."""
        plan = fixtures.plan()
        receipt = rig.gateway.apply(plan)
        assert receipt.ok

        restored = rig.gateway.restore(receipt.transaction_id)

        assert restored.ok
        assert (
            rig.gateway.lookup_certificate(
                plan.function_identity.entry_ea, plan.database_identity
            )
            is None
        )

    def test_restore_reasserts_the_remembered_function_extent(self, rig) -> None:
        """Restoring bytes is not restoring state.

        Erasing a branch orphans its target block and IDA shrinks the owning
        function; reanalysis cannot undo that because reanalysis is what did
        it. The extent must be asserted from the journal's pre-patch record.
        """
        plan = fixtures.plan()
        receipt = rig.gateway.apply(plan)
        assert receipt.ok

        rig.gateway.restore(receipt.transaction_id)

        expected = {
            (
                op.restore_snapshot.function_ownership.owning_function_entry_ea,
                op.restore_snapshot.function_ownership.chunk_ranges[0].end_ea,
            )
            for op in plan.operations
        }
        assert set(rig.extent_restorer.calls) == expected

    def test_extent_is_reasserted_before_reanalysis(self, rig) -> None:
        """Order matters: reanalysis must run over the restored function, not
        the truncated one."""
        receipt = rig.gateway.apply(fixtures.plan())
        assert receipt.ok
        rig.reanalyzer.calls.clear()
        rig.extent_restorer.calls.clear()

        rig.gateway.restore(receipt.transaction_id)

        assert rig.extent_restorer.calls, "extent was never reasserted"
        assert rig.reanalyzer.calls, "reanalysis never ran"

    def test_a_failed_extent_restore_does_not_report_RESTORED(self, tmp_path) -> None:
        """Bytes back but shape not back is a half-restored database. Reporting
        RESTORED there would tell a caller it is clean when it is not."""
        rig = build_gateway(
            tmp_path,
            fixtures.plan().operations,
            extent_restorer=RecordingExtentRestorer(succeeds=False),
        )
        receipt = rig.gateway.apply(fixtures.plan())
        assert receipt.ok

        restored = rig.gateway.restore(receipt.transaction_id)

        assert restored.state is NativeJournalState.RECOVERY_REQUIRED
        assert not restored.ok

    def test_a_raising_extent_restorer_is_treated_as_failure(self, tmp_path) -> None:
        rig = build_gateway(
            tmp_path,
            fixtures.plan().operations,
            extent_restorer=RecordingExtentRestorer(raise_always=True),
        )
        receipt = rig.gateway.apply(fixtures.plan())
        assert receipt.ok

        restored = rig.gateway.restore(receipt.transaction_id)

        assert restored.state is NativeJournalState.RECOVERY_REQUIRED

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


class FakeMetadataExecutor:
    """In-memory metadata state keyed by ``(kind, ea)``.

    Models the one property the real executor must have: ``apply_state`` then
    ``read_state`` returns what was applied, so reversal to a recorded
    before-value is observable.
    """

    def __init__(
        self,
        initial: dict | None = None,
        fail_on_apply: bool = False,
        mutate_then_fail: bool = False,
    ):
        self.state: dict = dict(initial or {})
        self.applied: list[tuple[str, int, str]] = []
        self._fail_on_apply = fail_on_apply
        self._mutate_then_fail = mutate_then_fail

    def read_state(self, kind, ea):
        return self.state.get((kind, ea), "unknown")

    def apply_state(self, kind, ea, target_state):
        self.applied.append((kind.value, ea, target_state))
        if self._fail_on_apply:
            return False
        self.state[(kind, ea)] = target_state
        if self._mutate_then_fail:
            self._mutate_then_fail = False
            return False
        return True


def _plan_with_metadata_actions():
    from d810.transforms.native_patch_plan import (
        NativeMetadataAction,
        NativeMetadataActionKind,
    )

    op = fixtures.operation(
        metadata_actions=(
            NativeMetadataAction(
                kind=NativeMetadataActionKind.RECREATE_ITEM,
                ea=0x1000,
                expected_before="data:1",
                expected_after="code:2",
            ),
            NativeMetadataAction(
                kind=NativeMetadataActionKind.UPDATE_XREF,
                ea=0x1000,
                expected_before="cref:",
                expected_after="cref:0x1010",
            ),
        )
    )
    plan = fixtures.plan(operations=(op,))
    return (
        dataclasses.replace(
            plan,
            function_identity=dataclasses.replace(
                plan.function_identity,
                chunk_ranges=(NativeAddressRange(0x1000, 0x1002),),
            ),
        ),
        op,
    )


class TestMetadataActionExecution:
    """Task 7's unblocking prerequisite: metadata actions execute and reverse.

    They were declared vocabulary and rejected at runtime, which blocked
    migrating the one writer Task 7 names -- it writes zero bytes and is made
    entirely of these actions.
    """

    def _initial_state(self):
        from d810.transforms.native_patch_plan import NativeMetadataActionKind

        return {
            (NativeMetadataActionKind.RECREATE_ITEM, 0x1000): "data:1",
            (NativeMetadataActionKind.UPDATE_XREF, 0x1000): "cref:",
        }

    def test_apply_executes_every_action(self, tmp_path) -> None:
        plan, _ = _plan_with_metadata_actions()
        executor = FakeMetadataExecutor(self._initial_state())
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)

        receipt = rig.gateway.apply(plan)

        assert receipt.ok, receipt.rejection_reasons
        assert [a[2] for a in executor.applied] == ["code:2", "cref:0x1010"]

    def test_metadata_only_operation_never_calls_the_byte_writer(
        self, tmp_path
    ) -> None:
        """A metadata-only request has an identity anchor, not a dummy patch."""
        plan, operation = _plan_with_metadata_actions()
        operation = dataclasses.replace(
            operation,
            replacement_bytes=operation.expected_current_bytes,
            expected_before_shape=operation.expected_after_shape,
            writes_bytes=False,
        )
        plan = dataclasses.replace(plan, operations=(operation,))
        executor = FakeMetadataExecutor(self._initial_state())
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)

        receipt = rig.gateway.apply(plan)

        assert receipt.ok, receipt.rejection_reasons
        assert rig.db.patch_byte_calls == []
        assert rig.db.reset_item_boundary_calls == []
        assert [a[2] for a in executor.applied] == ["code:2", "cref:0x1010"]

    def test_the_observed_before_state_is_journaled_not_the_expected_one(
        self, tmp_path
    ) -> None:
        """Reversal replays what was actually there, so that is what is stored."""
        plan, _ = _plan_with_metadata_actions()
        executor = FakeMetadataExecutor(self._initial_state())
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)

        receipt = rig.gateway.apply(plan)

        recorded = rig.journal.metadata_actions(receipt.transaction_id)
        assert [r.recorded_before for r in recorded] == ["data:1", "cref:"]

    def test_certificate_rejects_metadata_divergence_after_apply(
        self, tmp_path
    ) -> None:
        from d810.transforms.native_patch_plan import NativeMetadataActionKind

        plan, _ = _plan_with_metadata_actions()
        executor = FakeMetadataExecutor(self._initial_state())
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        receipt = rig.gateway.apply(plan)
        assert receipt.certificate is not None
        assert rig.gateway.certificate_matches_current(plan, receipt.certificate)

        executor.state[(NativeMetadataActionKind.UPDATE_XREF, 0x1000)] = "cref:"

        assert not rig.gateway.certificate_matches_current(plan, receipt.certificate)

    def test_metadata_certificate_rejects_function_wide_byte_divergence(
        self, tmp_path
    ) -> None:
        """A metadata anchor cannot certify unrelated bytes in its function."""
        plan, _ = _plan_with_metadata_actions()
        executor = FakeMetadataExecutor(self._initial_state())
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        receipt = rig.gateway.apply(plan)
        assert receipt.certificate is not None

        divergent_plan = dataclasses.replace(
            plan,
            function_identity=dataclasses.replace(
                plan.function_identity,
                inherited_bytes_hash="changed-function-byte-fingerprint",
            ),
            inherited_function_fingerprint="changed-function-byte-fingerprint",
        )

        assert not _certificate_matches(receipt.certificate, divergent_plan)

    def test_live_metadata_certificate_rejects_byte_divergence_outside_anchor(
        self, tmp_path
    ) -> None:
        """Live validation covers the owning function, not just its anchor."""
        plan, _ = _plan_with_metadata_actions()
        plan = dataclasses.replace(
            plan,
            function_identity=dataclasses.replace(
                plan.function_identity,
                chunk_ranges=(NativeAddressRange(0x1000, 0x1004),),
            ),
        )
        executor = FakeMetadataExecutor(self._initial_state())
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        rig.db.bytes.update({0x1002: 0x90, 0x1003: 0x90})
        rig.db.original.update({0x1002: 0x90, 0x1003: 0x90})

        receipt = rig.gateway.apply(plan)

        assert receipt.certificate is not None
        assert rig.gateway.certificate_matches_current(plan, receipt.certificate)

        rig.db.bytes[0x1003] = 0xCC

        assert not rig.gateway.certificate_matches_current(plan, receipt.certificate)

    def test_a_before_state_mismatch_aborts_rather_than_applying(
        self, tmp_path
    ) -> None:
        plan, _ = _plan_with_metadata_actions()
        # The database is not what the plan was authorized against.
        executor = FakeMetadataExecutor({})
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)

        with pytest.raises(Exception):
            rig.gateway.apply(plan)

        assert executor.applied == [], "no action may run after a mismatch"

    def test_primitive_that_mutates_then_reports_failure_is_compensated(
        self, tmp_path
    ) -> None:
        """The before image is durable before the primitive can mutate.

        Supported live actions are deliberately single IDA primitives.  This
        seam proves the remaining possible failure shape: a primitive has
        reached its exact after-state but reports failure.  Emergency
        recovery must reverse it from the pre-recorded state, not leave an
        aggregate action half-applied.
        """
        plan, _ = _plan_with_metadata_actions()
        initial = self._initial_state()
        executor = FakeMetadataExecutor(dict(initial), mutate_then_fail=True)
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)

        with pytest.raises(Exception):
            rig.gateway.apply(plan)

        assert executor.state == initial
        record = rig.journal.get(_sole_transaction_id(rig.journal))
        assert record is not None
        assert record.state is NativeJournalState.RESTORED

    def test_restore_reverses_actions_in_reverse_application_order(
        self, tmp_path
    ) -> None:
        """Actions can depend on each other, so undoing them forwards would
        break those dependencies."""
        plan, _ = _plan_with_metadata_actions()
        executor = FakeMetadataExecutor(self._initial_state())
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        receipt = rig.gateway.apply(plan)
        assert receipt.ok
        executor.applied.clear()

        rig.gateway.restore(receipt.transaction_id)

        assert [a[2] for a in executor.applied] == ["cref:", "data:1"]

    def test_restore_returns_the_metadata_state_to_its_pre_apply_value(
        self, tmp_path
    ) -> None:
        plan, _ = _plan_with_metadata_actions()
        initial = self._initial_state()
        executor = FakeMetadataExecutor(dict(initial))
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        receipt = rig.gateway.apply(plan)
        assert receipt.ok

        rig.gateway.restore(receipt.transaction_id)

        assert executor.state == initial

    def test_a_failed_reversal_does_not_report_RESTORED(self, tmp_path) -> None:
        plan, _ = _plan_with_metadata_actions()
        executor = FakeMetadataExecutor(self._initial_state())
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        receipt = rig.gateway.apply(plan)
        assert receipt.ok
        executor._fail_on_apply = True

        restored = rig.gateway.restore(receipt.transaction_id)

        assert restored.state is NativeJournalState.RECOVERY_REQUIRED

    def test_without_an_executor_metadata_actions_still_fail_closed(
        self, tmp_path
    ) -> None:
        """The pre-existing guarantee must not regress into a silent skip."""
        from d810.backends.ida.native_patch.gateway import (
            NativePatchMetadataActionUnsupported,
        )

        plan, _ = _plan_with_metadata_actions()
        rig = build_gateway(tmp_path, plan.operations)

        with pytest.raises(NativePatchMetadataActionUnsupported):
            rig.gateway.apply(plan)
