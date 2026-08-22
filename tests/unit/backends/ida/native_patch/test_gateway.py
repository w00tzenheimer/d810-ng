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
import json

import pytest

from d810.backends.ida.native_patch.gateway import (
    NativePatchGateway,
    NativePatchIssuerRejected,
    NativePatchRestoreNotCertified,
)
from d810.backends.ida.native_patch.issuer import (
    NativePatchIssuerContract,
    NativePatchIssuerRegistry,
    stage_c_native_cfg_issuer,
)
from d810.backends.ida.native_patch.journal import SQLiteNativePatchJournal
from d810.backends.ida.native_patch.metadata import _scoped_item_token
from d810.capabilities.native_patch import NativeJournalState
from d810.manager.native_normalization import (
    NativeNormalizationOutcome,
    NativeNormalizationRequest,
    _certificate_matches,
    authorize_and_apply,
    recover_startup,
)
from d810.transforms.native_patch_plan import (
    NativeAddressRange,
    NativeCertificateState,
    NativeMetadataAction,
    NativeMetadataActionKind,
    NativeFunctionOwnership,
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
    def __init__(self, raise_on: str | None = None, events: list[str] | None = None):
        self.calls: list[tuple] = []
        self._raise_on = raise_on
        self._events = events

    def reanalyze_function(self, function_ea):
        self.calls.append(("reanalyze_function", function_ea))
        if self._events is not None:
            self._events.append("reanalyze")
        if self._raise_on == "reanalyze_function":
            raise RuntimeError("injected: reanalyze_function")

    def auto_wait(self):
        self.calls.append(("auto_wait",))
        if self._events is not None:
            self._events.append("auto_wait")
        if self._raise_on == "auto_wait":
            raise RuntimeError("injected: auto_wait")


class RecordingExtentRestorer:
    """Fake :class:`FunctionExtentRestorer`.

    ``succeeds=False`` models IDA refusing to re-establish the extent, which
    must downgrade the restore receipt rather than report RESTORED over a
    database whose shape was not restored.
    """

    def __init__(
        self,
        succeeds: bool = True,
        raise_always: bool = False,
        events: list[str] | None = None,
    ):
        self.calls: list[tuple[int, int]] = []
        self.ownership_calls: list[NativeFunctionOwnership] = []
        self._succeeds = succeeds
        self._raise_always = raise_always
        self._events = events

    def restore_function_ownership(self, ownership: NativeFunctionOwnership) -> bool:
        self.ownership_calls.append(ownership)
        if self._events is not None:
            self._events.append("ownership")
        entry_ea = ownership.owning_function_entry_ea
        entry_chunk = next(
            chunk for chunk in ownership.chunk_ranges if chunk.start_ea == entry_ea
        )
        self.calls.append((entry_ea, entry_chunk.end_ea))
        if self._raise_always:
            raise RuntimeError("injected: restore_function_ownership")
        return self._succeeds


class RecordingFlowRestorer:
    def __init__(self, succeeds: bool = True, events: list[str] | None = None):
        self.calls: list[object] = []
        self._succeeds = succeeds
        self._events = events

    def restore_function_flow_refs(self, ownership) -> bool:
        self.calls.append(ownership)
        if self._events is not None:
            self._events.append("flows")
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


class CrashingStageCCertificateUpdateBlobStore(FakeBlobStore):
    """Models process death after the Stage C receipt but before cert update."""

    def set_native_patch_blob(self, scope, key, payload):
        if (
            scope == "certificate"
            and payload.get("schema_version") == 3
            and payload.get("observed_native_cfg_fingerprint") is not None
        ):
            raise KeyboardInterrupt("injected: Stage C certificate update crash")
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
    flow_restorer: RecordingFlowRestorer
    invalidator: RecordingCacheInvalidator
    discovery: FakeCallerDiscovery
    redo: RecordingRedoDecompiler
    blobs: FakeBlobStore


def _issuer_registry() -> NativePatchIssuerRegistry:
    return NativePatchIssuerRegistry(
        (
            NativePatchIssuerContract(
                issuer_id="issuer-1",
                patch_class="lifting_normalization",
                proof_ids=frozenset({"proof-1"}),
                provenance=("test",),
            ),
            stage_c_native_cfg_issuer(),
        )
    )


def _stage_c_plan():
    plan = fixtures.plan(plan_id="stage-c-plan")
    return dataclasses.replace(
        plan,
        patch_class="semantic_deobfuscation",
        issuer_id="stage-c-native-cfg-normalizer",
        proof_id="native-cfg-intent-v1:test",
        proof_hash=plan.target_cfg_fingerprint,
        provenance=("stage-c-native-cfg", "mutation:test"),
    )


def build_gateway(
    tmp_path,
    operations,
    *,
    callers: frozenset[int] = frozenset(),
    reanalyzer: RecordingReanalyzer | None = None,
    extent_restorer: RecordingExtentRestorer | None = None,
    flow_restorer: RecordingFlowRestorer | None = None,
    metadata_executor=None,
    invalidator: RecordingCacheInvalidator | None = None,
    decode_replacement=_decode_replacement,
    blobs: FakeBlobStore | None = None,
) -> Gateway:
    journal = SQLiteNativePatchJournal(tmp_path / "journal.db")
    db = FakeNativeDatabase(operations)
    reanalyzer = reanalyzer or RecordingReanalyzer()
    extent_restorer = extent_restorer or RecordingExtentRestorer()
    flow_restorer = flow_restorer or RecordingFlowRestorer()
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
        flow_restorer=flow_restorer,
        metadata_executor=metadata_executor,
        cache_invalidator=invalidator,
        caller_discovery=discovery,
        redo_decompiler=redo,
        certificate_store=blobs,
        issuer_registry=_issuer_registry(),
        current_database_identity="idb-1",
        d810_version="test",
    )
    return Gateway(
        gateway=gateway,
        journal=journal,
        db=db,
        reanalyzer=reanalyzer,
        extent_restorer=extent_restorer,
        flow_restorer=flow_restorer,
        invalidator=invalidator,
        discovery=discovery,
        redo=redo,
        blobs=blobs,
    )


def _foreign_database_gateway(rig: Gateway) -> NativePatchGateway:
    return NativePatchGateway(
        journal=rig.journal,
        reader=rig.db,
        writer=rig.db,
        decode_replacement=_decode_replacement,
        reanalyzer=rig.reanalyzer,
        extent_restorer=rig.extent_restorer,
        flow_restorer=rig.flow_restorer,
        cache_invalidator=rig.invalidator,
        caller_discovery=rig.discovery,
        redo_decompiler=rig.redo,
        certificate_store=rig.blobs,
        issuer_registry=_issuer_registry(),
        current_database_identity="idb-foreign",
        d810_version="test",
    )


@pytest.fixture
def rig(tmp_path):
    bundle = build_gateway(tmp_path, (fixtures.operation(),))
    yield bundle
    bundle.journal.close()


def test_unregistered_issuer_is_rejected_before_the_journal_or_idb_is_written(
    rig,
) -> None:
    plan = dataclasses.replace(fixtures.plan(), issuer_id="unregistered")

    with pytest.raises(
        NativePatchIssuerRejected, match="unregistered native patch issuer"
    ):
        rig.gateway.apply(plan)

    assert rig.db.patch_byte_calls == []
    assert rig.journal.recoverable_transaction_ids(database_identity="idb-1") == ()


# ---------------------------------------------------------------------------
# apply(): the success path
# ---------------------------------------------------------------------------


class TestApplySuccess:
    def test_aggregate_edge_plan_uses_one_transaction_and_restores_both_ranges(
        self,
        tmp_path,
    ) -> None:
        first = fixtures.operation(operation_id="edge-1")
        second = fixtures.operation(
            operation_id="edge-2",
            start_ea=0x1010,
            end_ea=0x1012,
        )
        rig = build_gateway(tmp_path, (first, second))
        try:
            receipt = rig.gateway.apply(
                fixtures.plan(operations=(first, second), plan_id="stage-c-aggregate")
            )
            assert receipt.ok
            assert (
                len(
                    rig.journal._conn.execute(  # noqa: SLF001 - test introspection
                        "SELECT transaction_id FROM native_patch_transactions"
                    ).fetchall()
                )
                == 1
            )
            assert rig.db.bytes[0x1000] == 0xEB
            assert rig.db.bytes[0x1010] == 0xEB

            restored = rig.gateway.restore(receipt.transaction_id)

            assert restored.ok
            assert rig.db.bytes[0x1000] == 0x75
            assert rig.db.bytes[0x1010] == 0x75
            assert rig.redo.calls.count(0x1000) == 2
        finally:
            rig.journal.close()

    def test_second_aggregate_edge_write_failure_recovers_the_first_edge(
        self,
        tmp_path,
    ) -> None:
        first = fixtures.operation(operation_id="edge-1")
        second = fixtures.operation(
            operation_id="edge-2",
            start_ea=0x1010,
            end_ea=0x1012,
        )
        rig = build_gateway(tmp_path, (first, second))
        original_patch_byte = rig.db.patch_byte

        def _fail_second(ea, value):
            if ea == 0x1010:
                raise RuntimeError("injected second edge write")
            original_patch_byte(ea, value)

        rig.db.patch_byte = _fail_second
        try:
            with pytest.raises(RuntimeError, match="second edge write"):
                rig.gateway.apply(
                    fixtures.plan(
                        operations=(first, second), plan_id="stage-c-aggregate-fail"
                    )
                )

            assert rig.db.bytes[0x1000] == 0x75
            assert rig.db.bytes[0x1001] == 0x01
            assert rig.db.bytes[0x1010] == 0x75
            assert rig.db.bytes[0x1011] == 0x01
        finally:
            rig.journal.close()

    def test_apply_certifies_and_writes_only_replacement_bytes(self, rig) -> None:
        before = dict(rig.db.bytes)
        receipt = rig.gateway.apply(fixtures.plan())

        assert receipt.ok
        assert receipt.state is NativeJournalState.CERTIFIED
        assert receipt.certificate is not None
        assert receipt.certificate.state is NativeCertificateState.APPLIED
        assert rig.db.bytes == {0x1000: 0xEB, 0x1001: 0x01}
        assert before != rig.db.bytes

    def test_stage_c_postcondition_persists_observed_whole_cfg(self, rig) -> None:
        plan = _stage_c_plan()
        receipt = rig.gateway.apply(plan)
        assert receipt.certificate is not None
        assert not receipt.ok
        assert receipt.postcondition_pending
        assert receipt.state is NativeJournalState.POSTCONDITION_PENDING

        receipt_id, certificate = rig.gateway.record_native_cfg_postcondition_receipt(
            plan=plan,
            certificate=receipt.certificate,
            transaction_id=receipt.transaction_id,
            observed_native_cfg_fingerprint=plan.target_cfg_fingerprint,
            live_flowchart_fingerprint="live-physical-flowchart",
        )

        evidence = rig.blobs.get_native_patch_blob(
            "native_cfg_postcondition_receipt", receipt_id
        )
        assert evidence["expected_native_cfg_fingerprint"] == (
            plan.target_cfg_fingerprint
        )
        assert evidence["observed_native_cfg_fingerprint"] == (
            plan.target_cfg_fingerprint
        )
        assert evidence["live_flowchart_fingerprint"] == "live-physical-flowchart"
        assert certificate.observed_native_cfg_fingerprint == (
            plan.target_cfg_fingerprint
        )
        assert (
            rig.journal.get(receipt.transaction_id).state
            is NativeJournalState.CERTIFIED
        )
        assert (
            rig.gateway.lookup_certificate(
                plan.function_identity.entry_ea, plan.database_identity
            ).observed_native_cfg_fingerprint
            == plan.target_cfg_fingerprint
        )

    def test_stage_c_authorization_reports_applied_while_postcondition_is_pending(
        self, rig
    ) -> None:
        result = authorize_and_apply(
            NativeNormalizationRequest(plan=_stage_c_plan(), user_enabled=True),
            gateway=rig.gateway,
        )

        assert result.outcome is NativeNormalizationOutcome.APPLIED
        assert result.apply_receipt.postcondition_pending
        assert not result.apply_receipt.ok

    def test_stage_c_crash_before_observation_is_startup_recoverable(self, rig) -> None:
        plan = _stage_c_plan()
        before = dict(rig.db.bytes)

        receipt = rig.gateway.apply(plan)

        assert receipt.state is NativeJournalState.POSTCONDITION_PENDING
        assert rig.db.bytes != before
        recovered = recover_startup(
            journal=rig.journal,
            gateway=rig.gateway,
            database_identity="idb-1",
        )
        assert recovered == (receipt.transaction_id,)
        assert (
            rig.journal.get(receipt.transaction_id).state is NativeJournalState.RESTORED
        )
        assert rig.db.bytes == before
        assert (
            rig.gateway.lookup_certificate(
                plan.function_identity.entry_ea, plan.database_identity
            )
            is None
        )

    def test_stage_c_failed_postcondition_can_restore_pending_overlay(
        self, rig
    ) -> None:
        plan = _stage_c_plan()
        before = dict(rig.db.bytes)
        receipt = rig.gateway.apply(plan)

        restored = rig.gateway.restore(receipt.transaction_id)

        assert restored.ok
        assert rig.db.bytes == before
        assert (
            rig.gateway.lookup_certificate(
                plan.function_identity.entry_ea, plan.database_identity
            )
            is None
        )

    def test_stage_c_crash_after_receipt_before_certificate_is_recoverable(
        self, tmp_path
    ) -> None:
        blobs = CrashingStageCCertificateUpdateBlobStore()
        rig = build_gateway(tmp_path, (fixtures.operation(),), blobs=blobs)
        plan = _stage_c_plan()
        before = dict(rig.db.bytes)
        try:
            receipt = rig.gateway.apply(plan)
            with pytest.raises(
                KeyboardInterrupt, match="Stage C certificate update crash"
            ):
                rig.gateway.record_native_cfg_postcondition_receipt(
                    plan=plan,
                    certificate=receipt.certificate,
                    transaction_id=receipt.transaction_id,
                    observed_native_cfg_fingerprint=plan.target_cfg_fingerprint,
                    live_flowchart_fingerprint="live-physical-flowchart",
                )

            evidence_rows = [
                payload
                for (scope, _key), payload in blobs._data.items()  # noqa: SLF001
                if scope == "native_cfg_postcondition_receipt"
            ]
            assert len(evidence_rows) == 1
            assert (
                rig.journal.get(receipt.transaction_id).state
                is NativeJournalState.POSTCONDITION_PENDING
            )
            assert recover_startup(
                journal=rig.journal,
                gateway=rig.gateway,
                database_identity="idb-1",
            ) == (receipt.transaction_id,)
            assert rig.db.bytes == before
            assert (
                rig.journal.get(receipt.transaction_id).state
                is NativeJournalState.RESTORED
            )
            assert (
                rig.gateway.lookup_certificate(
                    plan.function_identity.entry_ea, plan.database_identity
                )
                is None
            )
        finally:
            rig.journal.close()

    def test_stage_c_crash_after_persistence_before_terminal_transition_recovers(
        self, rig
    ) -> None:
        plan = _stage_c_plan()
        before = dict(rig.db.bytes)
        receipt = rig.gateway.apply(plan)
        original_transition = rig.journal.transition

        def _crash_before_certified(transaction_id, new_state, *, note=None):
            if new_state is NativeJournalState.CERTIFIED:
                raise KeyboardInterrupt("injected: Stage C terminal transition crash")
            return original_transition(transaction_id, new_state, note=note)

        rig.journal.transition = _crash_before_certified
        with pytest.raises(KeyboardInterrupt, match="terminal transition crash"):
            rig.gateway.record_native_cfg_postcondition_receipt(
                plan=plan,
                certificate=receipt.certificate,
                transaction_id=receipt.transaction_id,
                observed_native_cfg_fingerprint=plan.target_cfg_fingerprint,
                live_flowchart_fingerprint="live-physical-flowchart",
            )
        rig.journal.transition = original_transition

        stored = rig.gateway.lookup_certificate(
            plan.function_identity.entry_ea, plan.database_identity
        )
        assert stored.observed_native_cfg_fingerprint == plan.target_cfg_fingerprint
        assert (
            rig.journal.get(receipt.transaction_id).state
            is NativeJournalState.POSTCONDITION_PENDING
        )
        assert recover_startup(
            journal=rig.journal,
            gateway=rig.gateway,
            database_identity="idb-1",
        ) == (receipt.transaction_id,)
        assert rig.db.bytes == before
        assert (
            rig.journal.get(receipt.transaction_id).state is NativeJournalState.RESTORED
        )
        assert (
            rig.gateway.lookup_certificate(
                plan.function_identity.entry_ea, plan.database_identity
            )
            is None
        )

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

        recovered = recover_startup(
            journal=rig.journal, gateway=rig.gateway, database_identity="idb-1"
        )

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

    def test_direct_gateway_rejects_a_disjoint_plan_for_a_certified_function(
        self, tmp_path
    ) -> None:
        """Journal ownership is by certificate slot, not only byte overlap."""
        plan_a = fixtures.plan(
            operations=(_owned_by_shared_test_function(fixtures.operation()),)
        )
        plan_b, operation_b = _disjoint_same_function_plan()
        rig = build_gateway(tmp_path, plan_a.operations + (operation_b,))
        receipt_a = rig.gateway.apply(plan_a)
        assert receipt_a.ok
        certificate_a = rig.gateway.lookup_certificate(
            plan_a.function_identity.entry_ea,
            plan_a.database_identity,
        )
        assert certificate_a is not None
        bytes_before_b = bytes(rig.db.bytes[ea] for ea in range(0x2000, 0x2002))

        with pytest.raises(ValueError, match="function certificate slot"):
            rig.gateway.apply(plan_b)

        assert bytes(rig.db.bytes[ea] for ea in range(0x2000, 0x2002)) == bytes_before_b
        still_certified = rig.gateway.lookup_certificate(
            plan_a.function_identity.entry_ea,
            plan_a.database_identity,
        )
        assert still_certified is not None
        assert still_certified.certificate_id == certificate_a.certificate_id
        assert _sole_transaction_id(rig.journal) == receipt_a.transaction_id
        rig.journal.close()

    def test_manager_abstains_before_preparing_a_different_certified_plan(
        self, tmp_path
    ) -> None:
        plan_a = fixtures.plan(
            operations=(_owned_by_shared_test_function(fixtures.operation()),)
        )
        plan_b, operation_b = _disjoint_same_function_plan()
        rig = build_gateway(tmp_path, plan_a.operations + (operation_b,))
        receipt_a = rig.gateway.apply(plan_a)
        assert receipt_a.ok
        bytes_before_b = bytes(rig.db.bytes[ea] for ea in range(0x2000, 0x2002))

        result = authorize_and_apply(
            NativeNormalizationRequest(plan=plan_b, user_enabled=True),
            gateway=rig.gateway,
        )

        assert result.outcome is NativeNormalizationOutcome.REJECTED
        assert result.apply_receipt is None
        assert result.reason == "FUNCTION_ALREADY_CERTIFIED_RESTORE_REQUIRED"
        assert bytes(rig.db.bytes[ea] for ea in range(0x2000, 0x2002)) == bytes_before_b
        assert _sole_transaction_id(rig.journal) == receipt_a.transaction_id
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
        # A plan cannot mix one certificate function identity with a
        # different operation owner. Rejecting the malformed plan before
        # journal preparation leaves no mutable recovery state behind.
        with pytest.raises(ValueError, match="function identity"):
            fixtures.plan(
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
        assert record.state is NativeJournalState.RECOVERY_REQUIRED
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
            flow_restorer=RecordingFlowRestorer(),
            cache_invalidator=RecordingCacheInvalidator(),
            caller_discovery=FakeCallerDiscovery(),
            redo_decompiler=RecordingRedoDecompiler(),
            certificate_store=FakeBlobStore(),
            issuer_registry=_issuer_registry(),
            current_database_identity="idb-1",
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
            flow_restorer=RecordingFlowRestorer(),
            cache_invalidator=RecordingCacheInvalidator(),
            caller_discovery=FakeCallerDiscovery(),
            redo_decompiler=RecordingRedoDecompiler(),
            certificate_store=FakeBlobStore(),
            issuer_registry=_issuer_registry(),
            current_database_identity="idb-1",
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
    def test_direct_restore_rejects_foreign_database_before_any_write(
        self, rig
    ) -> None:
        receipt = rig.gateway.apply(fixtures.plan())
        assert receipt.ok
        before_state = rig.journal.get(receipt.transaction_id).state
        before_patch_calls = tuple(rig.db.patch_byte_calls)
        before_ownership_calls = tuple(rig.extent_restorer.ownership_calls)
        foreign = _foreign_database_gateway(rig)

        with pytest.raises(ValueError, match="database identity"):
            foreign.restore(receipt.transaction_id)

        assert rig.journal.get(receipt.transaction_id).state is before_state
        assert tuple(rig.db.patch_byte_calls) == before_patch_calls
        assert tuple(rig.extent_restorer.ownership_calls) == before_ownership_calls

    def test_direct_recover_rejects_foreign_database_before_any_write(
        self, rig
    ) -> None:
        receipt = rig.gateway.apply(fixtures.plan())
        assert receipt.ok
        before_state = rig.journal.get(receipt.transaction_id).state
        before_patch_calls = tuple(rig.db.patch_byte_calls)
        before_ownership_calls = tuple(rig.extent_restorer.ownership_calls)
        foreign = _foreign_database_gateway(rig)

        with pytest.raises(ValueError, match="database identity"):
            foreign.recover(receipt.transaction_id)

        assert rig.journal.get(receipt.transaction_id).state is before_state
        assert tuple(rig.db.patch_byte_calls) == before_patch_calls
        assert tuple(rig.extent_restorer.ownership_calls) == before_ownership_calls

    def test_direct_restore_fails_closed_for_legacy_identityless_row(self, rig) -> None:
        receipt = rig.gateway.apply(fixtures.plan())
        assert receipt.ok
        with rig.journal._conn:  # noqa: SLF001 - legacy-schema regression
            rig.journal._conn.execute(  # noqa: SLF001
                "UPDATE native_patch_transactions SET idb_uuid = NULL "
                "WHERE transaction_id = ?",
                (receipt.transaction_id.value,),
            )
        before_patch_calls = tuple(rig.db.patch_byte_calls)

        with pytest.raises(ValueError, match="database identity"):
            rig.gateway.restore(receipt.transaction_id)

        assert tuple(rig.db.patch_byte_calls) == before_patch_calls

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
        recovered = recover_startup(
            journal=rig.journal, gateway=rig.gateway, database_identity="idb-1"
        )

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
        recover_startup(
            journal=rig.journal, gateway=rig.gateway, database_identity="idb-1"
        )

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

    def test_restore_uses_journaled_function_identity_when_live_ownership_is_gone(
        self, rig
    ) -> None:
        receipt = rig.gateway.apply(fixtures.plan())
        rig.db._ownership.clear()  # noqa: SLF001 - simulate IDA ownership drift

        restored = rig.gateway.restore(receipt.transaction_id)

        assert restored.ok
        assert rig.extent_restorer.calls

    def test_phase_restore_reanalyzes_journaled_identity_after_live_clear(
        self, tmp_path
    ) -> None:
        executor = FakeMetadataExecutor()
        plan, before, _after, _origin = _singleton_phase_recovery_plan()
        executor.state[(NativeMetadataActionKind.RECREATE_ITEM, 0x1000)] = before
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        receipt = rig.gateway.apply(plan)
        assert receipt.ok
        rig.db._ownership.clear()  # noqa: SLF001 - live ownership drift
        restored = rig.gateway.restore(receipt.transaction_id)

        assert restored.state is NativeJournalState.RESTORED
        assert ("reanalyze_function", 0x1000) in rig.reanalyzer.calls
        rig.journal.close()


    def test_restore_reconciles_exact_entry_tail_flags_and_type_snapshot(
        self, rig
    ) -> None:
        op = fixtures.operation()
        ownership = dataclasses.replace(
            op.restore_snapshot.function_ownership,
            chunk_ranges=(
                NativeAddressRange(0x1000, 0x1800),
                NativeAddressRange(0x2000, 0x2010),
            ),
            function_flags=0x4,
        )
        op = dataclasses.replace(
            op,
            expected_function_ownership=ownership,
            restore_snapshot=dataclasses.replace(
                op.restore_snapshot,
                function_ownership=ownership,
            ),
        )
        rig.db._ownership[0x1000] = ownership  # noqa: SLF001 - live-state fixture
        receipt = rig.gateway.apply(fixtures.plan(operations=(op,)))
        assert receipt.ok

        restored = rig.gateway.restore(receipt.transaction_id)

        assert restored.ok
        assert rig.extent_restorer.ownership_calls == [ownership] * 3

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

    def test_restore_reconciles_the_journaled_function_flow_refs(self, rig) -> None:
        plan = fixtures.plan()
        receipt = rig.gateway.apply(plan)
        assert receipt.ok

        restored = rig.gateway.restore(receipt.transaction_id)

        assert restored.ok
        assert (
            rig.flow_restorer.calls
            == [plan.operations[0].restore_snapshot.function_ownership] * 2
        )

    def test_failed_flow_ref_restore_does_not_report_restored(self, tmp_path) -> None:
        rig = build_gateway(
            tmp_path,
            fixtures.plan().operations,
            flow_restorer=RecordingFlowRestorer(succeeds=False),
        )
        receipt = rig.gateway.apply(fixtures.plan())
        assert receipt.ok

        restored = rig.gateway.restore(receipt.transaction_id)

        assert restored.state is NativeJournalState.RECOVERY_REQUIRED
        assert not restored.ok

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

    def test_reopened_gateway_recovers_exact_phase_p_and_persists_cursor(
        self, tmp_path
    ) -> None:
        executor = FakeMetadataExecutor()
        plan, before, after, _origin_target = _phase_recovery_plan()
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        record = rig.journal.prepare(plan)
        _record_phase_attestation(rig, plan, record)
        rig.journal.record_metadata_action(
            record.transaction_id,
            operation_id=plan.operations[0].operation_id,
            kind=NativeMetadataActionKind.RECREATE_ITEM.value,
            ea=0x1000,
            recorded_before=before,
            expected_after=after,
        )
        executor.state[(NativeMetadataActionKind.RECREATE_ITEM, 0x1000)] = after
        for state in (
            NativeJournalState.BYTES_APPLIED,
            NativeJournalState.METADATA_APPLIED,
            NativeJournalState.ANALYSIS_PENDING,
            NativeJournalState.ANALYSIS_VALIDATED,
        ):
            rig.journal.transition(record.transaction_id, state)
        rig.journal.close()

        reopened = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        reopened.gateway.recover(record.transaction_id)

        assert reopened.journal.get(record.transaction_id).state is NativeJournalState.RESTORED
        assert executor.phase_origin_state[0x1000].startswith("data:v2:")
        steps = reopened.journal.analysis_reverse_steps(record.transaction_id)
        assert [row["status"] for row in steps] == ["complete", "complete"]
        reopened.journal.close()

    def test_reopened_gateway_restore_enters_phase_inverse_from_exact_p(
        self, tmp_path
    ) -> None:
        executor = FakeMetadataExecutor()
        plan, before, after, _origin_target = _phase_recovery_plan()
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        record = rig.journal.prepare(plan)
        _record_phase_attestation(rig, plan, record)
        action = plan.operations[0].metadata_actions[0]
        rig.journal.record_metadata_action(
            record.transaction_id,
            operation_id=plan.operations[0].operation_id,
            kind=action.kind.value,
            ea=action.ea,
            recorded_before=before,
            expected_after=after,
        )
        executor.state[(NativeMetadataActionKind.RECREATE_ITEM, 0x1000)] = after
        for state in (
            NativeJournalState.BYTES_APPLIED,
            NativeJournalState.METADATA_APPLIED,
            NativeJournalState.ANALYSIS_PENDING,
            NativeJournalState.ANALYSIS_VALIDATED,
            NativeJournalState.CACHE_INVALIDATED,
            NativeJournalState.CERTIFICATE_PENDING,
            NativeJournalState.CERTIFIED,
        ):
            rig.journal.transition(record.transaction_id, state)
        rig.journal.close()

        reopened = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        restored = reopened.gateway.restore(record.transaction_id)

        assert restored.state is NativeJournalState.RESTORED
        assert [row["status"] for row in reopened.journal.analysis_reverse_steps(record.transaction_id)] == [
            "complete", "complete"
        ]
        reopened.journal.close()

    def test_phase_restore_retry_after_post_inverse_flow_failure_does_not_reanalyze(
        self, tmp_path
    ) -> None:
        executor = FakeMetadataExecutor()
        flow_restorer = RecordingFlowRestorer(succeeds=False)
        plan, before, after, _origin_target = _phase_recovery_plan()
        rig = build_gateway(
            tmp_path,
            plan.operations,
            metadata_executor=executor,
            flow_restorer=flow_restorer,
        )
        record = rig.journal.prepare(plan)
        _record_phase_attestation(rig, plan, record)
        action = plan.operations[0].metadata_actions[0]
        rig.journal.record_metadata_action(
            record.transaction_id,
            operation_id=plan.operations[0].operation_id,
            kind=action.kind.value,
            ea=action.ea,
            recorded_before=before,
            expected_after=after,
        )
        executor.state[(NativeMetadataActionKind.RECREATE_ITEM, 0x1000)] = after
        for state in (
            NativeJournalState.BYTES_APPLIED,
            NativeJournalState.METADATA_APPLIED,
            NativeJournalState.ANALYSIS_PENDING,
            NativeJournalState.ANALYSIS_VALIDATED,
            NativeJournalState.CACHE_INVALIDATED,
            NativeJournalState.CERTIFICATE_PENDING,
            NativeJournalState.CERTIFIED,
        ):
            rig.journal.transition(record.transaction_id, state)

        failed = rig.gateway.restore(record.transaction_id)

        assert failed.state is NativeJournalState.RESTORE_FAILED
        flow_restorer._succeeds = True  # noqa: SLF001 - retry cut-point
        rig.reanalyzer.calls.clear()
        resumed = rig.gateway.restore(record.transaction_id)

        assert resumed.state is NativeJournalState.RESTORED
        assert rig.reanalyzer.calls == []

    def test_reopened_phase_inverse_after_mutation_crash_does_not_repeat_inverse(
        self, tmp_path
    ) -> None:
        executor = FakeMetadataExecutor(phase_inverse_mutate_then_crash=True)
        plan, before, after, _origin_target = _phase_recovery_plan()
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        record = rig.journal.prepare(plan)
        _record_phase_attestation(rig, plan, record)
        action = plan.operations[0].metadata_actions[0]
        rig.journal.record_metadata_action(
            record.transaction_id,
            operation_id=plan.operations[0].operation_id,
            kind=action.kind.value,
            ea=action.ea,
            recorded_before=before,
            expected_after=after,
        )
        executor.state[(NativeMetadataActionKind.RECREATE_ITEM, 0x1000)] = after
        for state in (
            NativeJournalState.BYTES_APPLIED,
            NativeJournalState.METADATA_APPLIED,
            NativeJournalState.ANALYSIS_PENDING,
            NativeJournalState.ANALYSIS_VALIDATED,
        ):
            rig.journal.transition(record.transaction_id, state)
        executor.applied.clear()
        with pytest.raises(KeyboardInterrupt, match="phase inverse"):
            rig.gateway._reverse_analysis_phase(  # noqa: SLF001 - crash cut
                record.transaction_id,
                rig.journal.metadata_actions(record.transaction_id),
                rig.gateway._phase_witness_for_transaction(record.transaction_id),  # noqa: SLF001
            )
        first_apply_count = sum(
            kind == "phase_inverse" for kind, _ea, _state in executor.applied
        )
        rig.journal.close()

        reopened = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        reopened.gateway.recover(record.transaction_id)

        assert first_apply_count == 1
        assert sum(
            kind == "phase_inverse" for kind, _ea, _state in executor.applied
        ) == 1
        assert reopened.journal.get(record.transaction_id).state is NativeJournalState.RESTORED
        reopened.journal.close()

    def test_singleton_grouped_real_apply_close_reopen_restore(self, tmp_path) -> None:
        executor = FakeMetadataExecutor()
        plan, before, _after, _origin_target = _singleton_phase_recovery_plan()
        executor.state[(NativeMetadataActionKind.RECREATE_ITEM, 0x1000)] = before
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)

        receipt = rig.gateway.apply(plan)

        assert receipt.ok
        phase = rig.gateway._phase_witness_for_transaction(  # noqa: SLF001
            receipt.transaction_id
        )
        assert phase is not None
        assert len(phase.groups[0].group_targets) == 1
        rig.journal.close()
        reopened = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        restored = reopened.gateway.restore(receipt.transaction_id)
        assert restored.state is NativeJournalState.RESTORED
        assert executor.phase_origin_state[0x1000].startswith("data:v2:")
        assert reopened.gateway.lookup_certificate(
            plan.function_identity.entry_ea, plan.database_identity
        ) is None
        assert all(
            row["status"] == "complete"
            for row in reopened.journal.analysis_reverse_steps(receipt.transaction_id)
        )
        reopened.journal.close()

    def test_equal_p_attestation_rejects_altered_cleared_state(self) -> None:
        from d810.backends.ida.native_patch.phase_schema import (
            make_analysis_phase_attestation,
            parse_analysis_phase_witness,
        )

        plan, _before, _after, _origin = _phase_recovery_plan()
        payload = json.loads(
            plan.analysis_phase_witness.removeprefix("analysis-phase:v4:")
        )
        payload["reverse_schedule"][1]["cleared_state"]["items"] = [
            [0x1000, 15, "unknown"],
            [0x100F, 1, "unknown"],
        ]
        tampered = "analysis-phase:v4:" + json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        )
        phase = parse_analysis_phase_witness(tampered)

        with pytest.raises(Exception, match="cleared state"):
            make_analysis_phase_attestation(
                tampered, phase, phase.sealed_state, "transaction-id"
            )

    def test_parser_to_gateway_handoff_consumes_exact_observed_schedule(
        self, tmp_path
    ) -> None:
        from d810.backends.ida.native_patch.phase_schema import (
            parse_analysis_phase_attestation,
        )

        executor = FakeMetadataExecutor()
        plan, before, _after, _origin = _singleton_phase_recovery_plan()
        executor.state[(NativeMetadataActionKind.RECREATE_ITEM, 0x1000)] = before
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        receipt = rig.gateway.apply(plan)
        token = rig.journal.analysis_phase_attestation(receipt.transaction_id)
        assert token is not None
        parsed = parse_analysis_phase_attestation(token)
        consumed = rig.gateway._phase_witness_for_transaction(  # noqa: SLF001
            receipt.transaction_id
        )
        assert consumed is not None
        assert consumed.reverse_schedule == parsed.reverse_schedule
        rig.journal.close()

    def test_emergency_phase_lifecycle_orders_ownership_reanalysis_inverse_flows(
        self, tmp_path
    ) -> None:
        executor = FakeMetadataExecutor()
        plan, before, after, _origin = _phase_recovery_plan()
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        record = rig.journal.prepare(plan)
        _record_phase_attestation(rig, plan, record)
        action = plan.operations[0].metadata_actions[0]
        rig.journal.record_metadata_action(
            record.transaction_id, operation_id=plan.operations[0].operation_id,
            kind=action.kind.value, ea=action.ea,
            recorded_before=before, expected_after=after,
        )
        executor.state[(NativeMetadataActionKind.RECREATE_ITEM, 0x1000)] = after
        for state in (
            NativeJournalState.BYTES_APPLIED,
            NativeJournalState.METADATA_APPLIED,
            NativeJournalState.ANALYSIS_PENDING,
            NativeJournalState.ANALYSIS_VALIDATED,
        ):
            rig.journal.transition(record.transaction_id, state)
        rig.gateway.recover(record.transaction_id)

        assert rig.journal.get(record.transaction_id).state is NativeJournalState.RESTORED
        assert rig.extent_restorer.ownership_calls
        assert rig.reanalyzer.calls
        assert executor.applied[-1][0] == "phase_inverse"
        assert rig.flow_restorer.calls
        rig.journal.close()

    def test_emergency_phase_ownership_failure_has_no_later_events(self, tmp_path) -> None:
        executor = FakeMetadataExecutor()
        plan, before, after, _origin = _phase_recovery_plan()
        extent = RecordingExtentRestorer(succeeds=False)
        rig = build_gateway(
            tmp_path, plan.operations, metadata_executor=executor,
            extent_restorer=extent,
        )
        record = rig.journal.prepare(plan)
        _record_phase_attestation(rig, plan, record)
        action = plan.operations[0].metadata_actions[0]
        rig.journal.record_metadata_action(
            record.transaction_id, operation_id=plan.operations[0].operation_id,
            kind=action.kind.value, ea=action.ea,
            recorded_before=before, expected_after=after,
        )
        executor.state[(NativeMetadataActionKind.RECREATE_ITEM, 0x1000)] = after
        for state in (
            NativeJournalState.BYTES_APPLIED,
            NativeJournalState.METADATA_APPLIED,
            NativeJournalState.ANALYSIS_PENDING,
            NativeJournalState.ANALYSIS_VALIDATED,
        ):
            rig.journal.transition(record.transaction_id, state)
        rig.gateway.recover(record.transaction_id)

        assert rig.journal.get(record.transaction_id).state is NativeJournalState.RECOVERY_REQUIRED
        assert rig.reanalyzer.calls == []
        assert executor.applied == []
        assert rig.flow_restorer.calls == []
        rig.journal.close()

    def test_emergency_phase_shared_event_order_for_p_cut(self, tmp_path) -> None:
        events: list[str] = []
        executor = FakeMetadataExecutor(events=events)
        reanalyzer = RecordingReanalyzer(events=events)
        extent = RecordingExtentRestorer(events=events)
        flow = RecordingFlowRestorer(events=events)
        plan, before, after, _origin = _phase_recovery_plan()
        rig = build_gateway(
            tmp_path, plan.operations, metadata_executor=executor,
            reanalyzer=reanalyzer, extent_restorer=extent, flow_restorer=flow,
        )
        record = _seed_phase_recovery_transaction(
            rig, plan, executor, live_state=after,
            journal_state=NativeJournalState.ANALYSIS_VALIDATED,
        )
        rig.gateway.recover(record.transaction_id)

        assert rig.journal.get(record.transaction_id).state is NativeJournalState.RESTORED
        assert events == ["ownership", "reanalyze", "auto_wait", "inverse", "flows"]
        rig.journal.close()

    def test_emergency_phase_shared_event_order_for_ri_cut_without_reanalysis(
        self, tmp_path
    ) -> None:
        events: list[str] = []
        executor = FakeMetadataExecutor(events=events)
        reanalyzer = RecordingReanalyzer(events=events)
        extent = RecordingExtentRestorer(events=events)
        flow = RecordingFlowRestorer(events=events)
        plan, before, after, origin_target = _two_carrier_phase_recovery_plan()
        rig = build_gateway(
            tmp_path, plan.operations, metadata_executor=executor,
            reanalyzer=reanalyzer, extent_restorer=extent, flow_restorer=flow,
        )
        record = _seed_phase_recovery_transaction(
            rig, plan, executor, live_state=after,
            journal_state=NativeJournalState.ANALYSIS_VALIDATED,
        )
        rig.journal.record_analysis_reverse_intent(
            record.transaction_id, 0, "action:0:recreate_item@0x1000"
        )
        rig.journal.record_analysis_reverse_completion(
            record.transaction_id, 0, "action-carrier-deferred"
        )
        rig.journal.record_analysis_reverse_intent(
            record.transaction_id, 1, "carrier:0x1000"
        )
        rig.journal.record_analysis_reverse_completion(
            record.transaction_id, 1, "carrier-restored:0x1000"
        )
        phase_payload = json.loads(
            plan.analysis_phase_witness.removeprefix("analysis-phase:v4:")
        )
        executor.state[(NativeMetadataActionKind.RECREATE_ITEM, 0x1000)] = (
            phase_payload["groups"][0]["origin_data_state"]
        )
        after2 = phase_payload["reverse_schedule"][2]["expected_after"]
        executor.state[(NativeMetadataActionKind.RECREATE_ITEM, 0x2000)] = after2
        rig.gateway.recover(record.transaction_id)

        assert rig.journal.get(record.transaction_id).state is NativeJournalState.RESTORED
        assert events == ["ownership", "inverse", "flows"]
        rig.journal.close()

    def test_emergency_phase_ownership_failure_stops_ri_inverse_and_flows(
        self, tmp_path
    ) -> None:
        events: list[str] = []
        executor = FakeMetadataExecutor(events=events)
        extent = RecordingExtentRestorer(succeeds=False, events=events)
        flow = RecordingFlowRestorer(events=events)
        plan, before, after, origin_target = _two_carrier_phase_recovery_plan()
        rig = build_gateway(
            tmp_path, plan.operations, metadata_executor=executor,
            extent_restorer=extent, flow_restorer=flow,
        )
        record = _seed_phase_recovery_transaction(
            rig, plan, executor, live_state=after,
            journal_state=NativeJournalState.ANALYSIS_VALIDATED,
        )
        rig.journal.record_analysis_reverse_intent(
            record.transaction_id, 0, "action:0:recreate_item@0x1000"
        )
        rig.journal.record_analysis_reverse_completion(
            record.transaction_id, 0, "action-carrier-deferred"
        )
        rig.journal.record_analysis_reverse_intent(
            record.transaction_id, 1, "carrier:0x1000"
        )
        rig.journal.record_analysis_reverse_completion(
            record.transaction_id, 1, "carrier-restored:0x1000"
        )
        phase_payload = json.loads(
            plan.analysis_phase_witness.removeprefix("analysis-phase:v4:")
        )
        executor.state[(NativeMetadataActionKind.RECREATE_ITEM, 0x1000)] = (
            phase_payload["groups"][0]["origin_data_state"]
        )
        after2 = phase_payload["reverse_schedule"][2]["expected_after"]
        executor.state[(NativeMetadataActionKind.RECREATE_ITEM, 0x2000)] = after2
        rig.gateway.recover(record.transaction_id)

        assert rig.journal.get(record.transaction_id).state is NativeJournalState.RECOVERY_REQUIRED
        assert events == ["ownership"]
        rig.journal.close()

    def test_emergency_phase_shared_event_order_for_cleared_carrier_cut(
        self, tmp_path
    ) -> None:
        events: list[str] = []
        executor = FakeMetadataExecutor(events=events)
        extent = RecordingExtentRestorer(events=events)
        flow = RecordingFlowRestorer(events=events)
        plan, before, _after, _origin = _phase_recovery_plan()
        rig = build_gateway(
            tmp_path, plan.operations, metadata_executor=executor,
            extent_restorer=extent, flow_restorer=flow,
        )
        record = _seed_phase_recovery_transaction(
            rig, plan, executor, live_state="unknown",
            journal_state=NativeJournalState.ANALYSIS_VALIDATED,
        )
        rig.journal.record_analysis_reverse_intent(
            record.transaction_id, 0, "action:0:recreate_item@0x1000"
        )
        rig.journal.record_analysis_reverse_completion(
            record.transaction_id, 0, "action-carrier-deferred"
        )
        rig.journal.record_analysis_reverse_intent(
            record.transaction_id, 1, "carrier-delete:0x1000"
        )
        rig.gateway.recover(record.transaction_id)

        assert rig.journal.get(record.transaction_id).state is NativeJournalState.RESTORED
        assert events == ["ownership", "inverse", "flows"]
        rig.journal.close()

    def test_reopened_gateway_exact_b_reverses_action_without_carrier_mutation(
        self, tmp_path
    ) -> None:
        executor = FakeMetadataExecutor()
        plan, before, _after, _origin = _phase_recovery_plan()
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        record = _seed_phase_recovery_transaction(
            rig, plan, executor, live_state=before,
            journal_state=NativeJournalState.METADATA_APPLIED,
        )
        rig.journal.close()

        reopened = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        reopened.gateway.recover(record.transaction_id)

        assert reopened.journal.get(record.transaction_id).state is NativeJournalState.RESTORED
        assert not any(kind == "phase_inverse" for kind, _ea, _state in executor.applied)
        reopened.journal.close()

    def test_reopened_gateway_partial_analysis_prefix_uses_exact_journaled_before(
        self, tmp_path
    ) -> None:
        executor = FakeMetadataExecutor()
        plan, before, _after, _origin = _phase_recovery_plan()
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        record = _seed_phase_recovery_transaction(
            rig, plan, executor, live_state=before,
            journal_state=NativeJournalState.ANALYSIS_PENDING,
        )
        rig.journal.close()

        reopened = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        reopened.gateway.recover(record.transaction_id)

        assert reopened.journal.get(record.transaction_id).state is NativeJournalState.RESTORED
        assert not any(kind == "phase_inverse" for kind, _ea, _state in executor.applied)
        reopened.journal.close()

    def test_reopened_gateway_unknown_phase_drift_is_mutation_free(
        self, tmp_path
    ) -> None:
        executor = FakeMetadataExecutor()
        plan, _before, after, _origin = _phase_recovery_plan()
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        record = _seed_phase_recovery_transaction(
            rig, plan, executor, live_state="drifted-state",
            journal_state=NativeJournalState.ANALYSIS_VALIDATED,
        )
        rig.journal.close()

        reopened = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        reopened.gateway.recover(record.transaction_id)

        assert reopened.journal.get(record.transaction_id).state is NativeJournalState.RECOVERY_REQUIRED
        assert executor.applied == []
        reopened.journal.close()

    def test_reopened_gateway_rejects_completed_cursor_with_live_drift(
        self, tmp_path
    ) -> None:
        executor = FakeMetadataExecutor()
        plan, _before, after, origin_target = _phase_recovery_plan()
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        record = _seed_phase_recovery_transaction(
            rig, plan, executor, live_state=after,
            journal_state=NativeJournalState.ANALYSIS_VALIDATED,
        )
        rig.journal.record_analysis_reverse_intent(
            record.transaction_id, 0, "action:0:recreate_item@0x1000"
        )
        rig.journal.record_analysis_reverse_completion(
            record.transaction_id, 0, "action-carrier-deferred"
        )
        executor.state[(NativeMetadataActionKind.RECREATE_ITEM, 0x1000)] = origin_target
        rig.journal.close()

        reopened = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        reopened.gateway.recover(record.transaction_id)

        assert reopened.journal.get(record.transaction_id).state is NativeJournalState.RECOVERY_REQUIRED
        assert executor.applied == []
        reopened.journal.close()

    def test_two_carrier_wrong_ri_cut_is_recovery_required_without_mutation(
        self, tmp_path
    ) -> None:
        executor = FakeMetadataExecutor()
        plan, before, after, _origin = _two_carrier_phase_recovery_plan()
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        record = _seed_phase_recovery_transaction(
            rig, plan, executor, live_state=after,
            journal_state=NativeJournalState.ANALYSIS_VALIDATED,
        )
        executor.state[(NativeMetadataActionKind.RECREATE_ITEM, 0x2000)] = after
        rig.journal.record_analysis_reverse_intent(
            record.transaction_id, 0, "action:0:recreate_item@0x1000"
        )
        rig.journal.record_analysis_reverse_completion(
            record.transaction_id, 0, "action-carrier-deferred"
        )
        rig.journal.record_analysis_reverse_intent(
            record.transaction_id, 1, "carrier:0x1000"
        )
        rig.journal.record_analysis_reverse_completion(
            record.transaction_id, 1, "carrier-restored:0x1000"
        )
        rig.journal.close()

        reopened = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        reopened.gateway.recover(record.transaction_id)

        assert reopened.journal.get(record.transaction_id).state is NativeJournalState.RECOVERY_REQUIRED
        assert executor.applied == []
        reopened.journal.close()

    def test_skips_only_verified_completed_prefix(
        self, tmp_path
    ) -> None:
        executor = FakeMetadataExecutor()
        plan, _before, after, _origin = _phase_recovery_plan()
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        record = _seed_phase_recovery_transaction(
            rig, plan, executor, live_state=after,
            journal_state=NativeJournalState.ANALYSIS_VALIDATED,
        )
        rig.journal.record_analysis_reverse_intent(
            record.transaction_id, 0, "action:0:recreate_item@0x1000"
        )
        rig.journal.close()

        reopened = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        reopened.gateway.recover(record.transaction_id)
        reopened.gateway.recover(record.transaction_id)

        assert reopened.journal.get(record.transaction_id).state is NativeJournalState.RESTORED
        assert [row["status"] for row in reopened.journal.analysis_reverse_steps(record.transaction_id)] == [
            "complete", "complete"
        ]
        reopened.journal.close()

    def test_resumes_after_del_items_before_create_data(
        self, tmp_path
    ) -> None:
        executor = FakeMetadataExecutor()
        plan, _before, _after, _origin_target = _phase_recovery_plan()
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        record = _seed_phase_recovery_transaction(
            rig, plan, executor, live_state="unknown",
            journal_state=NativeJournalState.ANALYSIS_VALIDATED,
        )
        rig.journal.record_analysis_reverse_intent(
            record.transaction_id, 0, "action:0:recreate_item@0x1000"
        )
        rig.journal.record_analysis_reverse_completion(
            record.transaction_id, 0, "action-carrier-deferred"
        )
        rig.journal.record_analysis_reverse_intent(
            record.transaction_id, 1, "carrier-delete:0x1000"
        )
        rig.journal.close()

        reopened = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        reopened.gateway.recover(record.transaction_id)

        assert reopened.journal.get(record.transaction_id).state is NativeJournalState.RESTORED
        assert not any(kind == "phase_inverse" for kind, _ea, _state in executor.applied)
        reopened.journal.close()


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
        phase_inverse_mutate_then_crash: bool = False,
        events: list[str] | None = None,
    ):
        self.state: dict = dict(initial or {})
        self.applied: list[tuple[str, int, str]] = []
        self.scope_reads: list[tuple[str, int, str | None]] = []
        self._fail_on_apply = fail_on_apply
        self._mutate_then_fail = mutate_then_fail
        self._phase_inverse_mutate_then_crash = phase_inverse_mutate_then_crash
        self.phase_origin_state: dict[int, str] = {}
        self._events = events

    def read_state(self, kind, ea, *, scope_state=None):
        self.scope_reads.append((kind.value, ea, scope_state))
        if scope_state is None and kind is NativeMetadataActionKind.RECREATE_ITEM:
            if int(ea) in self.phase_origin_state:
                return self.phase_origin_state[int(ea)]
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

    def apply_phase_inverse(self, ea, target_state):
        self.applied.append(("phase_inverse", ea, target_state))
        if self._events is not None:
            self._events.append("inverse")
        self.state[(NativeMetadataActionKind.RECREATE_ITEM, ea)] = target_state
        scope = target_state.removeprefix("item-xrefs:v2:")
        try:
            payload = json.loads(scope)
            origin = payload.get("origin_data_state")
        except (TypeError, json.JSONDecodeError):
            origin = None
        if isinstance(origin, str):
            self.phase_origin_state[int(ea)] = origin
        if self._phase_inverse_mutate_then_crash:
            self._phase_inverse_mutate_then_crash = False
            raise KeyboardInterrupt("injected: phase inverse after mutation")
        return True

    def recreate_data_item(self, ea, target_state):
        self.applied.append(("recreate_data", int(ea), target_state))
        if self._events is not None:
            self._events.append("inverse")
        self.state[(NativeMetadataActionKind.RECREATE_ITEM, int(ea))] = target_state
        scope = target_state.removeprefix("item-xrefs:v2:")
        try:
            payload = json.loads(scope)
            origin = payload.get("origin_data_state")
        except (TypeError, json.JSONDecodeError):
            origin = None
        if isinstance(origin, str):
            self.phase_origin_state[int(ea)] = origin
        return True

    def enumerate_item_partition(self, start_ea, end_ea):
        value = self.state.get(
            (NativeMetadataActionKind.RECREATE_ITEM, int(start_ea)), "unknown"
        )
        if value == "unknown":
            return ((int(start_ea), int(end_ea) - int(start_ea), "unknown"),)
        if value.startswith("item-xrefs:v2:"):
            payload = json.loads(value.removeprefix("item-xrefs:v2:"))
            item_state = str(payload["item_state"])
            # The scoped token carries the enclosing origin extent in
            # ``size``; the partition row must expose the current item's
            # extent, which is the tiny code item in this recovery fixture.
            item_size = 2 if item_state == "code:2" else int(payload["size"])
            if item_size == 2:
                return (
                    (int(payload["head_ea"]), item_size, item_state),
                    (
                        int(payload["head_ea"]) + item_size,
                        int(payload["size"]) - item_size,
                        "unknown",
                    ),
                )
            return ((int(payload["head_ea"]), item_size, item_state),)
        if value.startswith("data:v2:"):
            payload = json.loads(value.removeprefix("data:v2:"))
            return ((int(payload["head_ea"]), int(payload["size"]), value),)
        return ((int(start_ea), int(end_ea) - int(start_ea), value),)

    def enumerate_scoped_xrefs(self, extents):
        rows = set()
        for start_ea, _end_ea in extents:
            value = self.state.get(
                (NativeMetadataActionKind.RECREATE_ITEM, int(start_ea)), "unknown"
            )
            if value.startswith("item-xrefs:v2:"):
                payload = json.loads(value.removeprefix("item-xrefs:v2:"))
                rows.update(
                    (
                        int(row["source_ea"]), int(row["target_ea"]),
                        int(row["xref_type"]), bool(row["user_owned"]), bool(row["is_code"]),
                    )
                    for row in payload["xrefs"]
                )
            elif value.startswith("data:v2:"):
                payload = json.loads(value.removeprefix("data:v2:"))
                rows.update(
                    (
                        int(row["source_ea"]), int(row["target_ea"]),
                        int(row["xref_type"]), bool(row["user_owned"]), bool(row["is_code"]),
                    )
                    for row in payload["xrefs"]
                )
        return tuple(sorted(rows))


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


def _phase_recovery_plan() -> tuple[object, object, object, object]:
    """Build one tiny v4 phase plan for restart/recovery cut-point tests."""
    row = {
        "source_ea": 0x1000,
        "target_ea": 0x1010,
        "xref_type": 21,
        "user_owned": False,
        "is_code": True,
    }
    origin = "data:v2:" + json.dumps(
        {
            "bytes": "00" * 16,
            "ea": 0x1000,
            "flags": 0,
            "full_flags": [0] * 16,
            "head_ea": 0x1000,
            "name": "",
            "offset": 0,
            "size": 16,
            "xrefs": [row],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    before = _scoped_item_token(
        ea=0x1000, head_ea=0x1000, size=16, item_state="code:2",
        xrefs=((0x1000, 0x1010, 21, False, True),),
        origin_data_state=origin, group_targets=(0x1000,),
    )
    after = _scoped_item_token(
        ea=0x1000, head_ea=0x1000, size=16, item_state="code:2",
        xrefs=((0x1000, 0x1010, 21, False, True),),
        origin_data_state=origin, group_targets=(0x1000,),
    )
    inverse_origin_payload = json.loads(origin.removeprefix("data:v2:"))
    inverse_origin_payload["xrefs"] = [row]
    inverse_origin = "data:v2:" + json.dumps(
        inverse_origin_payload, sort_keys=True, separators=(",", ":")
    )
    origin_target = _scoped_item_token(
        ea=0x1000, head_ea=0x1000, size=16, item_state=inverse_origin,
        xrefs=((0x1000, 0x1010, 21, False, True),),
        origin_data_state=origin, group_targets=(0x1000,),
    )
    group = {
        "version": 4,
        "origin_data_state": origin,
        "origin_extent": [0x1000, 0x1010],
        "destruction_extent": [0x1000, 0x1010],
        "group_targets": [0x1000],
        "before_items": [[0x1000, 2, "code:2"], [0x1002, 14, "unknown"]],
        "after_items": [[0x1000, 2, "code:2"], [0x1002, 14, "unknown"]],
        "before_xrefs": [row],
        "after_xrefs": [row],
        "reverse_before_xrefs": [row],
        "reverse_after_xrefs": [row],
        "postconditions": [{"ea": 0x1000, "state": after}],
    }
    sealed_state = {
        "items": [[0x1000, 2, "code:2"], [0x1002, 14, "unknown"]],
        "xrefs": [row],
        "extents": [[0x1000, 0x1010]],
    }
    origin_state = {
        "items": [[0x1000, 16, inverse_origin]],
        "xrefs": [row],
        "extents": [[0x1000, 0x1010]],
    }
    payload = {
        "version": 4,
        "groups": [group],
        "sealed_state": sealed_state,
        "origin_state": origin_state,
        "reverse_schedule": [
            {
                "kind": "action", "action_kind": "recreate_item", "ea": 0x1000,
                "index": 0, "expected_after": after,
                "before_state": before, "after_state": after,
                "global_before": sealed_state, "global_after": sealed_state,
            },
            {
                "kind": "group", "head_ea": 0x1000,
                "origin_extent": [0x1000, 0x1010],
                "destruction_extent": [0x1000, 0x1010],
                "before_items": group["before_items"],
                "after_items": group["after_items"],
                "before_xrefs": group["before_xrefs"],
                "after_xrefs": group["after_xrefs"],
                "global_before": sealed_state, "global_after": origin_state,
                "cleared_state": {
                    "items": [[0x1000, 16, "unknown"]],
                    "xrefs": [],
                    "extents": [[0x1000, 0x1010]],
                },
            },
        ],
    }
    token = "analysis-phase:v4:" + json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    )
    action = NativeMetadataAction(
        kind=NativeMetadataActionKind.RECREATE_ITEM,
        ea=0x1000,
        expected_before=before,
        expected_after=after,
    )
    operation = dataclasses.replace(
        fixtures.operation(
            metadata_actions=(action,),
            replacement_bytes=fixtures.operation().expected_current_bytes,
        ),
        writes_bytes=False,
        expected_after_shape=fixtures.operation().expected_before_shape,
    )
    plan = dataclasses.replace(
        fixtures.plan(operations=(operation,)),
        analysis_phase_witness=token,
    )
    return plan, before, after, origin_target


def _singleton_phase_recovery_plan() -> tuple[object, object, object, object]:
    plan, before, after, origin = _phase_recovery_plan()
    ownership = dataclasses.replace(
        plan.operations[0].expected_function_ownership,
        chunk_ranges=(NativeAddressRange(0x1000, 0x1002),),
    )
    operation = dataclasses.replace(
        plan.operations[0],
        expected_function_ownership=ownership,
        restore_snapshot=dataclasses.replace(
            plan.operations[0].restore_snapshot,
            function_ownership=ownership,
        ),
    )
    return (
        dataclasses.replace(
            plan,
            operations=(operation,),
            function_identity=dataclasses.replace(
                plan.function_identity,
                chunk_ranges=(NativeAddressRange(0x1000, 0x1002),),
            ),
        ),
        before,
        after,
        origin,
    )


def _two_carrier_phase_recovery_plan() -> tuple[object, object, object, object]:
    """Expand the miniature authorization to two disjoint carrier groups."""
    plan, before, after, origin = _phase_recovery_plan()
    payload = json.loads(plan.analysis_phase_witness.removeprefix("analysis-phase:v4:"))
    group1 = payload["groups"][0]
    origin_token1 = group1["origin_data_state"]
    origin1 = json.loads(origin_token1.removeprefix("data:v2:"))
    row1 = group1["before_xrefs"][0]
    origin2 = dict(origin1, ea=0x2000, head_ea=0x2000)
    row2 = dict(row1, source_ea=0x2000, target_ea=0x2010)
    origin2["xrefs"] = [row2]
    origin_token2 = "data:v2:" + json.dumps(origin2, sort_keys=True, separators=(",", ":"))
    before2 = _scoped_item_token(
        ea=0x2000, head_ea=0x2000, size=16, item_state="code:2",
        xrefs=((0x2000, 0x2010, 21, False, True),),
        origin_data_state=origin_token2, group_targets=(0x2000,),
    )
    group2 = json.loads(json.dumps(group1))
    group2.update({
        "origin_data_state": origin_token2,
        "origin_extent": [0x2000, 0x2010],
        "destruction_extent": [0x2000, 0x2010],
        "group_targets": [0x2000],
        "before_items": [[0x2000, 2, "code:2"], [0x2002, 14, "unknown"]],
        "after_items": [[0x2000, 2, "code:2"], [0x2002, 14, "unknown"]],
        "before_xrefs": [row2], "after_xrefs": [row2],
        "reverse_before_xrefs": [row2], "reverse_after_xrefs": [row2],
        "postconditions": [{"ea": 0x2000, "state": before2}],
    })
    sealed = {
        "items": [[0x1000, 2, "code:2"], [0x1002, 14, "unknown"],
                  [0x2000, 2, "code:2"], [0x2002, 14, "unknown"]],
        "xrefs": [row1, row2], "extents": [[0x1000, 0x1010], [0x2000, 0x2010]],
    }
    origin_state = {
        "items": [[0x1000, 16, origin_token1], [0x2000, 16, origin_token2]],
        "xrefs": [row1, row2], "extents": [[0x1000, 0x1010], [0x2000, 0x2010]],
    }
    intermediate = {
        "items": [[0x1000, 16, origin_token1], [0x2000, 2, "code:2"], [0x2002, 14, "unknown"]],
        "xrefs": [row1, row2], "extents": sealed["extents"],
    }
    payload["groups"] = [group1, group2]
    payload["sealed_state"] = sealed
    payload["origin_state"] = origin_state
    payload["reverse_schedule"] = [
        {"kind": "action", "action_kind": "recreate_item", "ea": 0x1000,
         "index": 0, "expected_after": after, "before_state": before,
         "after_state": after, "global_before": sealed, "global_after": sealed},
        {"kind": "group", "head_ea": 0x1000, "origin_extent": [0x1000, 0x1010],
         "destruction_extent": [0x1000, 0x1010], "before_items": group1["before_items"],
         "after_items": group1["after_items"], "before_xrefs": [row1],
         "after_xrefs": [row1], "global_before": sealed, "global_after": intermediate,
         "cleared_state": {"items": [[0x1000, 16, "unknown"], [0x2000, 2, "code:2"], [0x2002, 14, "unknown"]],
                            "xrefs": [row2], "extents": sealed["extents"]}},
        {"kind": "action", "action_kind": "recreate_item", "ea": 0x2000,
         "index": 1, "expected_after": before2, "before_state": before2,
         "after_state": before2, "global_before": intermediate, "global_after": intermediate},
        {"kind": "group", "head_ea": 0x2000, "origin_extent": [0x2000, 0x2010],
         "destruction_extent": [0x2000, 0x2010], "before_items": group2["before_items"],
         "after_items": group2["after_items"], "before_xrefs": [row2],
         "after_xrefs": [row2], "global_before": intermediate, "global_after": origin_state,
         "cleared_state": {"items": [[0x1000, 16, origin_token1], [0x2000, 16, "unknown"]],
                            "xrefs": [row1], "extents": sealed["extents"]}},
    ]
    token = "analysis-phase:v4:" + json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return dataclasses.replace(plan, analysis_phase_witness=token), before, after, origin


def _record_phase_attestation(rig, plan, record) -> None:
    from d810.backends.ida.native_patch.phase_schema import (
        make_analysis_phase_attestation,
        parse_analysis_phase_witness,
    )

    phase = parse_analysis_phase_witness(plan.analysis_phase_witness)
    assert phase.sealed_state is not None
    rig.journal.install_analysis_phase_attestation(
        record.transaction_id,
        make_analysis_phase_attestation(
            plan.analysis_phase_witness, phase, phase.sealed_state,
            record.transaction_id.value,
        ),
    )


def _seed_phase_recovery_transaction(
    rig, plan, executor, *, live_state: str, journal_state: NativeJournalState
):
    from d810.backends.ida.native_patch.phase_schema import (
        make_analysis_phase_attestation,
        parse_analysis_phase_witness,
    )

    record = rig.journal.prepare(plan)
    phase = parse_analysis_phase_witness(plan.analysis_phase_witness)
    assert phase.sealed_state is not None
    rig.journal.install_analysis_phase_attestation(
        record.transaction_id,
        make_analysis_phase_attestation(
            plan.analysis_phase_witness, phase, phase.sealed_state,
            record.transaction_id.value,
        ),
    )
    action = plan.operations[0].metadata_actions[0]
    rig.journal.record_metadata_action(
        record.transaction_id,
        operation_id=plan.operations[0].operation_id,
        kind=action.kind.value,
        ea=action.ea,
        recorded_before=action.expected_before,
        expected_after=action.expected_after,
    )
    executor.state[(NativeMetadataActionKind.RECREATE_ITEM, action.ea)] = live_state
    for state in (
        NativeJournalState.BYTES_APPLIED,
        NativeJournalState.METADATA_APPLIED,
        NativeJournalState.ANALYSIS_PENDING,
    ):
        rig.journal.transition(record.transaction_id, state)
        if state is journal_state:
            break
    if rig.journal.get(record.transaction_id).state is not journal_state:
        rig.journal.transition(record.transaction_id, journal_state)
    return record


def _disjoint_same_function_plan():
    """A non-overlapping plan that nevertheless owns function 0x1000."""
    operation = fixtures.operation(
        operation_id="op-2",
        start_ea=0x2000,
        end_ea=0x2002,
    )
    operation = _owned_by_shared_test_function(operation)
    return fixtures.plan(operations=(operation,), plan_id="plan-2"), operation


def _owned_by_shared_test_function(operation):
    ownership = NativeFunctionOwnership(
        owning_function_entry_ea=0x1000,
        chunk_ranges=(NativeAddressRange(0x1000, 0x3000),),
    )
    operation = dataclasses.replace(
        operation,
        expected_function_ownership=ownership,
        restore_snapshot=dataclasses.replace(
            operation.restore_snapshot,
            function_ownership=ownership,
        ),
    )
    return operation


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

    def test_gateway_reads_use_action_scope_and_certificate_postconditions(
        self, tmp_path
    ) -> None:
        from d810.transforms.native_patch_plan import NativeMetadataActionKind

        plan, _ = _plan_with_metadata_actions()
        actions = list(plan.operations[0].metadata_actions)
        actions[0] = dataclasses.replace(
            actions[0],
            expected_before="item-xrefs:v2:before",
            expected_after="item-xrefs:v2:middle",
        )
        actions.insert(
            1,
            dataclasses.replace(
                actions[0],
                expected_before="item-xrefs:v2:middle",
                expected_after="item-xrefs:v2:final",
            ),
        )
        operation = dataclasses.replace(
            plan.operations[0], metadata_actions=tuple(actions)
        )
        plan = dataclasses.replace(plan, operations=(operation,))
        initial = self._initial_state()
        initial[(NativeMetadataActionKind.RECREATE_ITEM, 0x1000)] = (
            "item-xrefs:v2:before"
        )
        executor = FakeMetadataExecutor(initial)
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)

        receipt = rig.gateway.apply(plan)

        assert receipt.certificate is not None
        assert receipt.certificate.metadata_postconditions
        assert any(
            scope == "item-xrefs:v2:before" for _kind, _ea, scope in executor.scope_reads
        )
        assert any(
            scope == "item-xrefs:v2:middle" for _kind, _ea, scope in executor.scope_reads
        )
        executor.scope_reads.clear()
        assert rig.gateway.certificate_matches_current(plan, receipt.certificate)
        assert executor.scope_reads
        assert all(
            scope == "item-xrefs:v2:final"
            for _kind, _ea, scope in executor.scope_reads
            if _kind == "recreate_item"
        )
        assert receipt.certificate.metadata_postconditions.count(
            ("recreate_item", 0x1000, "item-xrefs:v2:final")
        ) == 1

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

    def test_metadata_only_apply_failure_recovers_without_byte_interference(
        self, tmp_path
    ) -> None:
        """An unchanged byte anchor must not poison metadata-only recovery."""
        plan, operation = _plan_with_metadata_actions()
        operation = dataclasses.replace(
            operation,
            replacement_bytes=operation.expected_current_bytes,
            expected_before_shape=operation.expected_after_shape,
            writes_bytes=False,
        )
        plan = dataclasses.replace(plan, operations=(operation,))
        initial = self._initial_state()
        executor = FakeMetadataExecutor(dict(initial), mutate_then_fail=True)
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)

        with pytest.raises(Exception):
            rig.gateway.apply(plan)

        assert executor.state == initial
        record = rig.journal.get(_sole_transaction_id(rig.journal))
        assert record is not None
        assert record.state is NativeJournalState.RESTORED

    def test_already_normalized_metadata_certifies_without_cleanup(
        self, tmp_path
    ) -> None:
        """A no-op certificate request must stay read-only end to end."""
        plan, operation = _plan_with_metadata_actions()
        actions = tuple(
            dataclasses.replace(action, expected_after=action.expected_before)
            for action in operation.metadata_actions
        )
        operation = dataclasses.replace(
            operation,
            replacement_bytes=operation.expected_current_bytes,
            expected_before_shape=operation.expected_after_shape,
            writes_bytes=False,
            metadata_actions=actions,
        )
        plan = dataclasses.replace(plan, operations=(operation,))
        executor = FakeMetadataExecutor(self._initial_state())
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)

        receipt = rig.gateway.apply(plan)

        assert receipt.ok
        assert executor.applied == []
        assert rig.reanalyzer.calls == []
        assert rig.invalidator.calls == []
        assert rig.redo.calls == []

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

    def test_schema4_certificate_reuse_rejects_pending_linked_transaction(
        self, tmp_path
    ) -> None:
        plan, before, _after, _origin = _singleton_phase_recovery_plan()
        executor = FakeMetadataExecutor()
        executor.state[(NativeMetadataActionKind.RECREATE_ITEM, 0x1000)] = before
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        receipt = rig.gateway.apply(plan)
        assert receipt.certificate is not None
        assert rig.gateway.certificate_matches_current(plan, receipt.certificate)
        rig.journal._conn.execute(  # noqa: SLF001 - state cut injection
            "UPDATE native_patch_transactions SET state = ? WHERE transaction_id = ?",
            (NativeJournalState.CERTIFICATE_PENDING.value, receipt.transaction_id.value),
        )
        rig.journal._conn.commit()  # noqa: SLF001 - state cut injection
        assert not rig.gateway.certificate_matches_current(plan, receipt.certificate)
        rig.journal.close()

    def test_schema4_certificate_reuse_rejects_foreign_linked_idb(self, tmp_path) -> None:
        plan, before, _after, _origin = _singleton_phase_recovery_plan()
        executor = FakeMetadataExecutor()
        executor.state[(NativeMetadataActionKind.RECREATE_ITEM, 0x1000)] = before
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        receipt = rig.gateway.apply(plan)
        assert receipt.certificate is not None
        rig.journal._conn.execute(  # noqa: SLF001 - identity cut injection
            "UPDATE native_patch_transactions SET idb_uuid = ? WHERE transaction_id = ?",
            ("idb-foreign", receipt.transaction_id.value),
        )
        rig.journal._conn.commit()  # noqa: SLF001 - identity cut injection
        assert not rig.gateway.certificate_matches_current(plan, receipt.certificate)
        rig.journal.close()

    def test_schema4_certificate_reuse_rejects_embedded_transaction_mismatch(
        self, tmp_path
    ) -> None:
        import hashlib

        plan, before, _after, _origin = _singleton_phase_recovery_plan()
        executor = FakeMetadataExecutor()
        executor.state[(NativeMetadataActionKind.RECREATE_ITEM, 0x1000)] = before
        rig = build_gateway(tmp_path, plan.operations, metadata_executor=executor)
        receipt = rig.gateway.apply(plan)
        assert receipt.certificate is not None
        locator = receipt.certificate.analysis_phase_attestation_locator
        assert locator is not None
        token = rig.journal.analysis_phase_attestation(receipt.transaction_id)
        assert token is not None
        payload = json.loads(token.removeprefix("analysis-attestation:v1:"))
        payload["transaction_id"] = "foreign-transaction"
        altered = "analysis-attestation:v1:" + json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        )
        rig.journal._conn.execute(  # noqa: SLF001 - attestation cut injection
            "UPDATE native_patch_analysis_attestations SET attestation = ? WHERE transaction_id = ?",
            (altered, locator),
        )
        rig.journal._conn.commit()  # noqa: SLF001 - attestation cut injection
        altered_certificate = dataclasses.replace(
            receipt.certificate,
            analysis_phase_attestation_hash=hashlib.sha256(
                altered.encode()
            ).hexdigest(),
        )
        assert not rig.gateway.certificate_matches_current(plan, altered_certificate)
        rig.journal.close()

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

    def test_schema_two_byte_certificate_remains_reusable_but_metadata_does_not(
        self, tmp_path
    ) -> None:
        byte_plan = fixtures.plan()
        rig = build_gateway(tmp_path, byte_plan.operations)
        byte_receipt = rig.gateway.apply(byte_plan)
        assert byte_receipt.certificate is not None
        old_byte_certificate = dataclasses.replace(
            byte_receipt.certificate, schema_version=2
        )
        assert rig.gateway.certificate_matches_current(byte_plan, old_byte_certificate)

        metadata_plan, _ = _plan_with_metadata_actions()
        metadata_executor = FakeMetadataExecutor(self._initial_state())
        metadata_root = tmp_path / "metadata"
        metadata_root.mkdir()
        metadata_rig = build_gateway(
            metadata_root, metadata_plan.operations,
            metadata_executor=metadata_executor,
        )
        metadata_receipt = metadata_rig.gateway.apply(metadata_plan)
        assert metadata_receipt.certificate is not None
        old_metadata_certificate = dataclasses.replace(
            metadata_receipt.certificate, schema_version=2
        )
        assert not metadata_rig.gateway.certificate_matches_current(
            metadata_plan, old_metadata_certificate
        )

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
