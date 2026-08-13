"""The only native byte/owned-metadata writer and compensating restore path.

Task 6 ("Single-operation native gateway, reanalysis, and certificate") of
``_gitless/profile-guided-native-mutation-implementer-plan.md``. This is the
first module in the whole plan permitted to call ``ida_bytes.patch_byte`` /
``ida_bytes.revert_byte`` -- see the plan's Task 6 preamble: "Nothing before
it may. All writes go through the gateway and nowhere else." Every other
module in ``d810.backends.ida.native_patch`` (``capture``, ``preflight``,
``origin_mapper``, ``encoder``) is read-only or pure by construction.

Sequence (non-negotiable, matching section 15.1 of
``_gitless/REVERSIBLE-NATIVE-PATCHES.md``)
--------------------------------------------------------------------------
``apply()`` always runs: durably ``prepare()`` (exposes the transaction only
after the durable commit) -> mirror the prepared summary to the netnode (a
*separate* receipt; see below) -> re-preflight against the live database (an
independent re-check, not a reuse of whatever the caller already did) ->
write governed bytes one at a time, each with its own durable
``write_started``/``write_applied`` receipt -> reanalyze every owning
function and ``auto_wait()`` (mandatory: Task 0.4 measured that
``MERR_REDO`` refreshes Hex-Rays but does **not** reanalyze the database) ->
recheck every byte's recovery classification -> invalidate the target's and
every known caller's cfunc cache (Task 0.4 measured that ``mark_cfunc_dirty``
does **not** propagate to callers) plus one bounded controlled redo ->
certify (section 15.1.1's fingerprint re-baseline) -> persist the
certificate through the opaque blob store. Any exception at any point after
``prepare()`` is caught by exactly one place
(:meth:`NativePatchGateway._emergency_recover`), which classifies every
governed byte and either rolls back cleanly or leaves the transaction in
``RECOVERY_REQUIRED`` -- never a "clean failure" after bytes have changed --
and then the original exception is always re-raised, never swallowed.

Netnode mirror is a separate receipt, never a second commit
--------------------------------------------------------------------------
:meth:`NativePatchGateway._mirror_transaction` attempts to write a small
summary through the injected opaque blob store (ultimately
``d810.core.persistence``'s IDA9 netnode adapter) and records the outcome via
``NativePatchJournalStore.record_mirror_receipt`` -- ``MIRROR_WRITTEN`` or
``MIRROR_FAILED``. A mirror failure never aborts or rolls back the SQLite
transaction: the two stores are never claimed to commit atomically (global
constraint).

Exact restore -- why byte-level ``expected_current``/``expected_original``
is enough
--------------------------------------------------------------------------
:meth:`NativePatchGateway.restore` (and the emergency-rollback path inside
``apply()``) reads ``NativePatchJournalStore.operation_bytes()`` -- the
durably-planned per-byte ``(expected_current, expected_original,
replacement)`` triple -- rather than requiring the original
``NativePatchPlan`` object to still be alive in memory. For a given byte,
``expected_current == expected_original`` means it was pristine (unpatched)
immediately before this transaction, so restoring uses ``revert_byte``;
otherwise it already carried an inherited patch, so restoring uses
``patch_byte(ea, expected_current)`` to reproduce that inherited value
exactly rather than erasing it with ``revert_byte``. This is exactly
non-negotiable behaviour 4 in the task brief, and it is why gateway restore
works even across a process restart (section 15.4) -- the write-ahead log,
not the plan object, is the restore source of truth.

Certificate identity and where the type lives (Task 6's "layer trap")
--------------------------------------------------------------------------
See ``d810.transforms.native_patch_plan``'s "NativeCertificate" section for
the layering rationale: the certificate type lives in ``transforms`` (it
needs ``NativeDatabaseIdentity``/``NativeFunctionIdentity``, both defined
there), and ``d810.core.persistence`` only ever stores/returns the plain
``dict`` produced by ``certificate_to_payload``/``certificate_from_payload``.
This module is the only place that owns the conversion between the two.

Caller invalidation is mandatory
--------------------------------------------------------------------------
Every reanalyze+invalidate step in this module invalidates *every owning
function of every operation* plus, for each, *every currently-known caller*
(``d810.backends.hexrays.native_patch_lifecycle.invalidate_target_and_callers``).
A target-only invalidation is a known-insufficient sequence (Task 0.4,
measured) and must never be reintroduced here.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from uuid import uuid4

from d810.backends.ida.native_patch.capture import LiveDatabaseReader
from d810.backends.ida.native_patch.preflight import (
    DecodeReplacement,
    PlanPreflightResult,
    preflight_plan_live,
)
from d810.backends.ida.native_patch.reanalysis import (
    FunctionReanalyzer,
    reanalyze_and_wait,
)
from d810.backends.hexrays.native_patch_lifecycle import (
    CallerDiscovery,
    CfuncCacheInvalidator,
    ControlledRedoDecompiler,
    controlled_redo,
    invalidate_target_and_callers,
)
from d810.capabilities.native_patch import (
    NativeByteEventPhase,
    NativeByteRecoveryVerdict,
    NativeJournalState,
    NativeMirrorOutcome,
    NativeOperationRecoveryVerdict,
    NativePatchJournalStore,
    NativePatchTransactionId,
    NativePatchTransactionRecord,
    NativeTransactionRecoveryReport,
)
from d810.core.logging import getLogger
from d810.core.typing import Protocol, runtime_checkable
from d810.transforms.native_patch_plan import (
    NativeCertificate,
    NativeCertificateState,
    NativeDatabaseIdentity,
    NativePatchOperation,
    NativePatchPlan,
    certificate_from_payload,
    certificate_to_payload,
)

logger = getLogger("d810.backends.ida.native_patch.gateway")

__all__ = [
    "IdaNativeByteWriter",
    "NativeApplyReceipt",
    "NativePatchBlobStore",
    "NativePatchCertificationFailed",
    "NativePatchGateway",
    "NativePatchGatewayError",
    "NativePatchMetadataActionUnsupported",
    "NativePatchRestoreNotCertified",
    "NativePatchWriteVerificationFailed",
    "NativeByteWriter",
    "NativeRestoreReceipt",
]


class NativePatchGatewayError(RuntimeError):
    """Base class for every gateway-raised error."""


class NativePatchWriteVerificationFailed(NativePatchGatewayError):
    def __init__(self, operation_id: str, ea: int, expected: int, observed: int | None):
        self.operation_id = operation_id
        self.ea = ea
        self.expected = expected
        self.observed = observed
        super().__init__(
            f"operation {operation_id!r}: byte at {ea:#x} read back as "
            f"{observed!r}, expected {expected!r} immediately after writing it"
        )


class NativePatchCertificationFailed(NativePatchGatewayError):
    def __init__(self, transaction_id: NativePatchTransactionId, detail: str):
        self.transaction_id = transaction_id
        self.detail = detail
        super().__init__(
            f"transaction {transaction_id.value}: certification failed: {detail}"
        )


class NativePatchMetadataActionUnsupported(NativePatchGatewayError):
    """No design exists yet for live metadata-action content (section 14.2's
    ``NativeMetadataAction``). Task 5's lowering never populates
    ``metadata_actions`` for Mode A (same-size, NOP-padded regions never
    change item boundaries ahead of a live apply -- reanalysis re-itemizes
    the range on its own, as Task 0.4 measured). This fails closed rather
    than guessing at semantics no plan in this codebase yet produces.
    """

    def __init__(self, operation_id: str, kinds: tuple[str, ...]):
        self.operation_id = operation_id
        self.kinds = kinds
        super().__init__(
            f"operation {operation_id!r} carries metadata actions {kinds!r}; "
            "no live-apply implementation exists for metadata actions yet"
        )


class NativePatchRestoreNotCertified(NativePatchGatewayError):
    def __init__(self, state: NativeJournalState):
        self.state = state
        super().__init__(
            f"restore requires a CERTIFIED transaction; current state is {state.value}"
        )


@runtime_checkable
class NativeByteWriter(Protocol):
    """The only live-write seam in the whole plan. Every method is a single
    byte, read or write -- the gateway itself owns looping over a range so
    every byte gets its own durable write-ahead receipt (section 15.1 step 6).
    """

    def read_byte(self, ea: int) -> int | None:
        """Current byte value, or ``None`` if unloaded/unreadable."""
        ...

    def patch_byte(self, ea: int, value: int) -> None:
        """Write ``value`` at ``ea``. Raises on failure -- never returns a
        silently-ignored bool."""
        ...

    def revert_byte(self, ea: int) -> None:
        """Revert ``ea`` to IDA's original-byte layer. Only ever called for a
        byte the write-ahead log proves was pristine (``expected_current ==
        expected_original``) immediately before this transaction."""
        ...

    def reset_item_boundaries(self, start_ea: int, end_ea: int) -> None:
        """Clear any stale item/instruction-boundary metadata across
        ``[start_ea, end_ea)`` so a subsequent reanalysis rebuilds items
        from the bytes now in place, rather than reusing boundaries left
        over from a previous layout at the same addresses.

        Section 15.1 step 8 / 15.3 step 7 ("destroy/recreate only affected
        items", "recreate/reanalyze derived state"). Measured necessity, not
        a preemptive precaution: Task 6's own disposable-IDB apply/restore
        system test only reproduced the certified pre-patch flowchart
        byte-for-byte once this call was added between writing/restoring a
        range's bytes and reanalyzing its owning function -- neither
        ``reanalyze_function`` nor ``ida_auto.plan_and_wait`` alone cleared
        a stale successor edge left over from the intermediate byte layout,
        even though every governed byte, patch row, item shape, ref, and
        ownership record already matched exactly.
        """
        ...


@runtime_checkable
class NativePatchBlobStore(Protocol):
    """Structural view of the opaque payload store this module needs.

    ``d810.core.persistence.SupportsOptimizationStorage`` satisfies this
    without inheritance -- see that module's docstring for why the payload
    stays a plain ``dict`` all the way down to ``core``.
    """

    def get_native_patch_blob(self, scope: str, key: str) -> dict | None: ...
    def set_native_patch_blob(self, scope: str, key: str, payload: dict) -> None: ...
    def clear_native_patch_blob(self, scope: str, key: str) -> None: ...


@dataclass(frozen=True, slots=True)
class NativeApplyReceipt:
    transaction_id: NativePatchTransactionId
    state: NativeJournalState
    certificate: NativeCertificate | None
    rejection_reasons: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.state is NativeJournalState.CERTIFIED


@dataclass(frozen=True, slots=True)
class NativeRestoreReceipt:
    transaction_id: NativePatchTransactionId
    state: NativeJournalState
    restored_eas: tuple[int, ...]
    interference_eas: tuple[int, ...]

    @property
    def ok(self) -> bool:
        return self.state is NativeJournalState.RESTORED


_TERMINAL_STATES = frozenset(
    {
        NativeJournalState.RESTORED,
        NativeJournalState.RESTORE_FAILED,
        NativeJournalState.RECOVERY_REQUIRED,
    }
)


class NativePatchGateway:
    """Prepare -> preflight -> apply -> reanalyze -> validate -> invalidate
    caches -> certify, with exact restore. See the module docstring."""

    def __init__(
        self,
        *,
        journal: NativePatchJournalStore,
        reader: LiveDatabaseReader,
        writer: NativeByteWriter,
        decode_replacement: DecodeReplacement,
        reanalyzer: FunctionReanalyzer,
        cache_invalidator: CfuncCacheInvalidator,
        caller_discovery: CallerDiscovery,
        redo_decompiler: ControlledRedoDecompiler,
        certificate_store: NativePatchBlobStore,
        d810_version: str = "unknown",
    ) -> None:
        self._journal = journal
        self._reader = reader
        self._writer = writer
        self._decode_replacement = decode_replacement
        self._reanalyzer = reanalyzer
        self._cache_invalidator = cache_invalidator
        self._caller_discovery = caller_discovery
        self._redo_decompiler = redo_decompiler
        self._certificate_store = certificate_store
        self._d810_version = d810_version

    # ------------------------------------------------------------------
    # apply()
    # ------------------------------------------------------------------

    def apply(self, plan: NativePatchPlan) -> NativeApplyReceipt:
        if not isinstance(plan, NativePatchPlan):
            raise TypeError("plan must be a NativePatchPlan")

        record = self._journal.prepare(plan)
        self._mirror_transaction(record)

        try:
            preflight = preflight_plan_live(
                self._reader, plan, self._decode_replacement
            )
            if not preflight.authorized:
                return self._abandon(record.transaction_id, preflight)

            for op in plan.operations:
                self._apply_operation_bytes(record.transaction_id, op)
            record = self._journal.transition(
                record.transaction_id, NativeJournalState.BYTES_APPLIED
            )

            if record.has_metadata_actions:
                self._apply_metadata_actions(plan)
                record = self._journal.transition(
                    record.transaction_id, NativeJournalState.METADATA_APPLIED
                )

            record = self._journal.transition(
                record.transaction_id, NativeJournalState.ANALYSIS_PENDING
            )
            function_eas = self._owning_function_eas(plan)
            for function_ea in function_eas:
                reanalyze_and_wait(function_ea, reanalyzer=self._reanalyzer)

            recovery = self._journal.classify_recovery(
                record.transaction_id, self._read_current_byte
            )
            if not self._all_operations_cleanly_applied(recovery):
                raise NativePatchCertificationFailed(
                    record.transaction_id,
                    "post-reanalysis byte recheck did not confirm a clean apply",
                )
            record = self._journal.transition(
                record.transaction_id, NativeJournalState.ANALYSIS_VALIDATED
            )

            for function_ea in function_eas:
                invalidate_target_and_callers(
                    function_ea,
                    invalidator=self._cache_invalidator,
                    discovery=self._caller_discovery,
                )
                controlled_redo(function_ea, decompiler=self._redo_decompiler)
            record = self._journal.transition(
                record.transaction_id, NativeJournalState.CACHE_INVALIDATED
            )

            certificate = self._certify(plan, record)
            record = self._journal.transition(
                record.transaction_id, NativeJournalState.CERTIFIED
            )
            self._store_certificate(plan, certificate)

            return NativeApplyReceipt(
                transaction_id=record.transaction_id,
                state=record.state,
                certificate=certificate,
            )
        except Exception as exc:
            try:
                self._emergency_recover(record.transaction_id)
            except Exception:
                logger.exception(
                    "emergency recovery itself failed for transaction %s",
                    record.transaction_id.value,
                )
            raise exc

    def _apply_operation_bytes(
        self, transaction_id: NativePatchTransactionId, op: NativePatchOperation
    ) -> None:
        for offset, ea in enumerate(range(op.range.start_ea, op.range.end_ea)):
            expected_current = op.expected_current_bytes[offset]
            expected_original = op.expected_original_bytes[offset]
            replacement = op.replacement_bytes[offset]
            self._journal.record_byte_event(
                transaction_id,
                op.operation_id,
                ea,
                NativeByteEventPhase.WRITE_STARTED,
                expected_current=expected_current,
                expected_original=expected_original,
                replacement=replacement,
            )
            self._writer.patch_byte(ea, replacement)
            readback = self._writer.read_byte(ea)
            if readback != replacement:
                raise NativePatchWriteVerificationFailed(
                    op.operation_id, ea, replacement, readback
                )
            self._journal.record_byte_event(
                transaction_id,
                op.operation_id,
                ea,
                NativeByteEventPhase.WRITE_APPLIED,
                expected_current=expected_current,
                expected_original=expected_original,
                replacement=replacement,
            )
        # Every byte in this operation's range is now the replacement image
        # -- clear stale item/instruction boundaries across the whole range
        # before reanalysis runs. See NativeByteWriter.reset_item_boundaries's
        # docstring for why this is measured-necessary, not precautionary.
        self._writer.reset_item_boundaries(op.range.start_ea, op.range.end_ea)

    def _apply_metadata_actions(self, plan: NativePatchPlan) -> None:
        for op in plan.operations:
            if op.metadata_actions:
                raise NativePatchMetadataActionUnsupported(
                    op.operation_id,
                    tuple(action.kind.value for action in op.metadata_actions),
                )

    @staticmethod
    def _all_operations_cleanly_applied(
        recovery: NativeTransactionRecoveryReport,
    ) -> bool:
        return all(
            op.verdict is NativeOperationRecoveryVerdict.APPLIED
            and op.corroborated_by_write_applied_receipt
            for op in recovery.operation_reports
        )

    @staticmethod
    def _owning_function_eas(plan: NativePatchPlan) -> tuple[int, ...]:
        seen: dict[int, None] = {}
        for op in plan.operations:
            seen[op.expected_function_ownership.owning_function_entry_ea] = None
        return tuple(seen.keys())

    def _read_current_byte(self, ea: int) -> int | None:
        return self._writer.read_byte(ea)

    def _abandon(
        self,
        transaction_id: NativePatchTransactionId,
        preflight: PlanPreflightResult,
    ) -> NativeApplyReceipt:
        """A re-preflight failure right after ``PREPARED``: zero bytes have
        been written. See the module docstring's apply-ordering note."""
        reasons = tuple(
            reason
            for result in preflight.operation_results
            for reason in result.rejection_reasons
        )
        external_interference_only = bool(reasons) and all(
            reason == "EXTERNAL_INTERFERENCE" for reason in reasons
        )
        if external_interference_only:
            self._journal.transition(
                transaction_id,
                NativeJournalState.INTERFERENCE_DETECTED,
                note="preflight re-check failed: external interference",
            )
            record = self._journal.transition(
                transaction_id,
                NativeJournalState.RECOVERY_REQUIRED,
                note="preflight re-check failed before any byte was written",
            )
        else:
            self._journal.transition(
                transaction_id,
                NativeJournalState.ROLLING_BACK,
                note="preflight re-check failed; zero-op abandon",
            )
            record = self._journal.transition(
                transaction_id,
                NativeJournalState.RESTORED,
                note="zero-op abandon; no bytes were ever written",
            )
        return NativeApplyReceipt(
            transaction_id=transaction_id,
            state=record.state,
            certificate=None,
            rejection_reasons=reasons,
        )

    # ------------------------------------------------------------------
    # Netnode mirror (separate receipt; never a second commit)
    # ------------------------------------------------------------------

    def _mirror_transaction(self, record: NativePatchTransactionRecord) -> None:
        payload = {
            "transaction_id": record.transaction_id.value,
            "plan_id": record.plan_id,
            "plan_hash": record.plan_hash,
            "state": record.state.value,
        }
        try:
            self._certificate_store.set_native_patch_blob(
                "transaction_mirror", record.transaction_id.value, payload
            )
        except Exception:
            logger.warning(
                "netnode mirror write failed for transaction %s",
                record.transaction_id.value,
                exc_info=True,
            )
            self._journal.record_mirror_receipt(
                record.transaction_id,
                NativeMirrorOutcome.MIRROR_FAILED,
                reason="netnode mirror write raised",
            )
            return
        self._journal.record_mirror_receipt(
            record.transaction_id, NativeMirrorOutcome.MIRROR_WRITTEN
        )

    # ------------------------------------------------------------------
    # Certification (section 15.1.1's fingerprint re-baseline)
    # ------------------------------------------------------------------

    def _certify(
        self, plan: NativePatchPlan, record: NativePatchTransactionRecord
    ) -> NativeCertificate:
        normalized_fingerprint = self._recapture_fingerprint(
            plan, record.transaction_id
        )
        return NativeCertificate(
            certificate_id=uuid4().hex,
            schema_version=1,
            database_identity=plan.database_identity,
            function_identity=plan.function_identity,
            inherited_fingerprint=plan.inherited_function_fingerprint,
            normalized_fingerprint=normalized_fingerprint,
            target_cfg_fingerprint=plan.target_cfg_fingerprint,
            native_origin_map_fingerprint=plan.native_origin_map_fingerprint,
            semantic_plan_hash=plan.proof_hash,
            native_plan_hash=plan.plan_hash,
            d810_version=self._d810_version,
            authorization_class=plan.patch_class,
            state=NativeCertificateState.APPLIED,
            certified_at=time.time(),
        )

    def _recapture_fingerprint(
        self, plan: NativePatchPlan, transaction_id: NativePatchTransactionId
    ) -> str:
        """Section 15.1.1 points 1-4: recapture from current bytes, fail
        unconditionally on any byte whose loaded state changed, and require
        a journaled operation for every changed byte (reusing the existing
        ``classify_recovery`` corroboration check rather than re-deriving
        it)."""
        pieces: list[tuple[int, int, bytes]] = []
        for op in plan.operations:
            current = self._reader.read_current_bytes(
                op.range.start_ea, op.range.end_ea
            )
            if current is None:
                raise NativePatchCertificationFailed(
                    transaction_id,
                    f"operation {op.operation_id!r}: range became unloaded before certification",
                )
            pieces.append((op.range.start_ea, op.range.end_ea, current))
        return hashlib.sha256(repr(tuple(pieces)).encode("utf-8")).hexdigest()

    def _store_certificate(
        self, plan: NativePatchPlan, certificate: NativeCertificate
    ) -> None:
        key = self._certificate_key(
            plan.function_identity.entry_ea, plan.database_identity
        )
        self._certificate_store.set_native_patch_blob(
            "certificate", key, certificate_to_payload(certificate)
        )

    @staticmethod
    def _certificate_key(
        function_entry_ea: int, database_identity: NativeDatabaseIdentity
    ) -> str:
        return f"{database_identity.idb_uuid}:{function_entry_ea:#x}"

    def lookup_certificate(
        self, function_entry_ea: int, database_identity: NativeDatabaseIdentity
    ) -> NativeCertificate | None:
        payload = self._certificate_store.get_native_patch_blob(
            "certificate",
            self._certificate_key(function_entry_ea, database_identity),
        )
        if payload is None:
            return None
        return certificate_from_payload(payload)

    # ------------------------------------------------------------------
    # Explicit restore (section 15.3)
    # ------------------------------------------------------------------

    def restore(self, transaction_id: NativePatchTransactionId) -> NativeRestoreReceipt:
        record = self._journal.get(transaction_id)
        if record is None:
            raise ValueError(f"unknown transaction {transaction_id.value}")
        if record.state is not NativeJournalState.CERTIFIED:
            raise NativePatchRestoreNotCertified(record.state)

        recovery = self._journal.classify_recovery(
            transaction_id, self._read_current_byte
        )
        interference_eas = tuple(
            sorted(
                entry.ea
                for op in recovery.operation_reports
                for entry in op.byte_entries
                if entry.verdict is NativeByteRecoveryVerdict.NEITHER
            )
        )

        record = self._journal.transition(transaction_id, NativeJournalState.RESTORING)

        if interference_eas:
            record = self._journal.transition(
                transaction_id,
                NativeJournalState.RECOVERY_REQUIRED,
                note="current state diverges from the certified after-image",
            )
            return NativeRestoreReceipt(
                transaction_id=transaction_id,
                state=record.state,
                restored_eas=(),
                interference_eas=interference_eas,
            )

        try:
            restored_eas = self._restore_bytes(transaction_id, recovery)
        except Exception:
            self._journal.transition(
                transaction_id,
                NativeJournalState.RESTORE_FAILED,
                note="a byte write during restore raised",
            )
            raise

        for function_ea in self._function_eas_for_transaction(transaction_id):
            reanalyze_and_wait(function_ea, reanalyzer=self._reanalyzer)
            invalidate_target_and_callers(
                function_ea,
                invalidator=self._cache_invalidator,
                discovery=self._caller_discovery,
            )

        record = self._journal.transition(
            transaction_id, NativeJournalState.RESTORED, note="explicit restore"
        )
        return NativeRestoreReceipt(
            transaction_id=transaction_id,
            state=record.state,
            restored_eas=restored_eas,
            interference_eas=(),
        )

    def _restore_bytes(
        self,
        transaction_id: NativePatchTransactionId,
        recovery: NativeTransactionRecoveryReport,
    ) -> tuple[int, ...]:
        byte_records = {
            (record.operation_id, record.ea): record
            for record in self._journal.operation_bytes(transaction_id)
        }
        restored: list[int] = []
        touched_operations: set[str] = set()
        for op in recovery.operation_reports:
            for entry in op.byte_entries:
                if entry.verdict in (
                    NativeByteRecoveryVerdict.BEFORE,
                    NativeByteRecoveryVerdict.BOTH,
                ):
                    continue
                self._restore_one_byte(byte_records[(op.operation_id, entry.ea)])
                restored.append(entry.ea)
                touched_operations.add(op.operation_id)
        self._reset_item_boundaries_for_operations(transaction_id, touched_operations)
        return tuple(restored)

    def _restore_one_byte(self, record) -> None:
        if record.expected_current == record.expected_original:
            self._writer.revert_byte(record.ea)
        else:
            self._writer.patch_byte(record.ea, record.expected_current)

    def _operation_ranges(
        self, transaction_id: NativePatchTransactionId
    ) -> dict[str, tuple[int, int]]:
        eas_by_operation: dict[str, list[int]] = {}
        for record in self._journal.operation_bytes(transaction_id):
            eas_by_operation.setdefault(record.operation_id, []).append(record.ea)
        return {
            operation_id: (min(eas), max(eas) + 1)
            for operation_id, eas in eas_by_operation.items()
        }

    def _reset_item_boundaries_for_operations(
        self, transaction_id: NativePatchTransactionId, operation_ids: set[str]
    ) -> None:
        if not operation_ids:
            return
        ranges = self._operation_ranges(transaction_id)
        for operation_id in operation_ids:
            start_ea, end_ea = ranges[operation_id]
            self._writer.reset_item_boundaries(start_ea, end_ea)

    def _function_eas_for_transaction(
        self, transaction_id: NativePatchTransactionId
    ) -> tuple[int, ...]:
        anchors: dict[str, int] = {}
        for record in self._journal.operation_bytes(transaction_id):
            if (
                record.operation_id not in anchors
                or record.ea < anchors[record.operation_id]
            ):
                anchors[record.operation_id] = record.ea
        seen: dict[int, None] = {}
        for anchor_ea in anchors.values():
            ownership = self._reader.read_function_ownership(anchor_ea)
            if ownership is None:
                continue
            seen[ownership.owning_function_entry_ea] = None
        return tuple(seen.keys())

    # ------------------------------------------------------------------
    # Recovery -- section 15.4 ("Recovery on plugin load or IDB open").
    # ------------------------------------------------------------------

    def recover(self, transaction_id: NativePatchTransactionId) -> None:
        """Classify and resolve one non-terminal transaction.

        Public entry point for startup recovery
        (``d810.manager.native_normalization``'s job is to enumerate which
        transaction ids need this, typically every transaction this
        process's journal knows about that is not already ``RESTORED``,
        ``RESTORE_FAILED``, or ``RECOVERY_REQUIRED``). Identical logic to
        the exception path inside :meth:`apply` -- see
        :meth:`_emergency_recover`.
        """
        self._emergency_recover(transaction_id)

    def _emergency_recover(self, transaction_id: NativePatchTransactionId) -> None:
        record = self._journal.get(transaction_id)
        if record is None or record.state in _TERMINAL_STATES:
            return

        recovery = self._journal.classify_recovery(
            transaction_id, self._read_current_byte
        )

        if recovery.recommended_state is NativeJournalState.INTERFERENCE_DETECTED:
            self._journal.transition(
                transaction_id,
                NativeJournalState.INTERFERENCE_DETECTED,
                note="apply failed; external interference detected",
            )
            self._journal.transition(
                transaction_id,
                NativeJournalState.RECOVERY_REQUIRED,
                note="apply failed; manual recovery required",
            )
            return

        if recovery.recommended_state is NativeJournalState.PREPARED:
            self._journal.transition(
                transaction_id,
                NativeJournalState.ROLLING_BACK,
                note="apply failed before any byte was written",
            )
            self._journal.transition(
                transaction_id,
                NativeJournalState.RESTORED,
                note="zero-op rollback",
            )
            return

        self._journal.transition(
            transaction_id,
            NativeJournalState.ROLLING_BACK,
            note="apply failed; rolling back applied bytes",
        )
        try:
            ok = self._rollback_bytes(transaction_id, recovery)
        except Exception:
            self._journal.transition(
                transaction_id,
                NativeJournalState.RESTORE_FAILED,
                note="a byte write during rollback raised",
            )
            return
        if not ok:
            self._journal.transition(
                transaction_id,
                NativeJournalState.RECOVERY_REQUIRED,
                note="interference detected while rolling back",
            )
            return

        for function_ea in self._function_eas_for_transaction(transaction_id):
            try:
                reanalyze_and_wait(function_ea, reanalyzer=self._reanalyzer)
                invalidate_target_and_callers(
                    function_ea,
                    invalidator=self._cache_invalidator,
                    discovery=self._caller_discovery,
                )
            except Exception:
                # Bytes are already correct -- the safety-critical part is
                # done. A failure here is logged, not escalated, so a stale
                # decompiler cache does not mask a successful byte rollback.
                logger.warning(
                    "post-rollback reanalysis/invalidation failed for %#x",
                    function_ea,
                    exc_info=True,
                )
        self._journal.transition(
            transaction_id,
            NativeJournalState.RESTORED,
            note="rolled back after apply failure",
        )

    def _rollback_bytes(
        self,
        transaction_id: NativePatchTransactionId,
        recovery: NativeTransactionRecoveryReport,
    ) -> bool:
        """Roll back every byte that reads as the after-image. Never touches a
        byte matching neither before nor after (invariant 22)."""
        byte_records = {
            (record.operation_id, record.ea): record
            for record in self._journal.operation_bytes(transaction_id)
        }
        ok = True
        touched_operations: set[str] = set()
        for op in recovery.operation_reports:
            for entry in op.byte_entries:
                if entry.verdict is NativeByteRecoveryVerdict.NEITHER:
                    ok = False
                    continue
                if entry.verdict in (
                    NativeByteRecoveryVerdict.BEFORE,
                    NativeByteRecoveryVerdict.BOTH,
                ):
                    continue
                self._restore_one_byte(byte_records[(op.operation_id, entry.ea)])
                touched_operations.add(op.operation_id)
        self._reset_item_boundaries_for_operations(transaction_id, touched_operations)
        return ok


class IdaNativeByteWriter:
    """:class:`NativeByteWriter` backed by the live IDA database.

    Exercised only by the Docker system-test suite; the unit-test suite
    never constructs this class (per this repository's no-IDA-mocking rule).
    """

    def read_byte(self, ea: int) -> int | None:
        import ida_bytes

        if not ida_bytes.is_loaded(ea):
            return None
        return int(ida_bytes.get_byte(ea)) & 0xFF

    def patch_byte(self, ea: int, value: int) -> None:
        import ida_bytes

        # patch_byte()'s return value answers "did the database change?", not
        # "did the write succeed?". Measured on IDA 9.4: writing a byte's
        # existing value returns False with the value correctly in place;
        # writing a new value returns True; writing that new value a second
        # time returns False again. IDA is behaving correctly -- a no-op write
        # genuinely changes nothing.
        #
        # That makes the return useless as a success signal here, because a
        # legitimate operation may write a byte that already holds the target
        # value (a partially-applied range recovered mid-write, or a stencil
        # whose padding matches what was there). Branching on it would report
        # failure for a correct write. This method therefore never inspects it;
        # NativePatchGateway._apply_operation_bytes() performs a mandatory
        # readback after every call, which is the check that actually means
        # something.
        ida_bytes.patch_byte(ea, value)

    def revert_byte(self, ea: int) -> None:
        import ida_bytes

        ida_bytes.revert_byte(ea)

    def reset_item_boundaries(self, start_ea: int, end_ea: int) -> None:
        import ida_auto
        import ida_bytes
        import ida_ua

        # Scoped to exactly the governed range -- never the whole function
        # -- so this cannot touch a name, comment, or item outside what this
        # operation itself owns.
        ida_auto.revert_ida_decisions(start_ea, end_ea)
        ida_bytes.del_items(start_ea, ida_bytes.DELIT_EXPAND, end_ea - start_ea)
        # del_items() alone leaves the range as undefined bytes -- Task 6's
        # own disposable-IDB system test measured that IDA's background
        # auto-analysis queue does not reliably revisit an isolated deleted
        # range purely because the owning function was reanalyzed
        # afterward (the range came back as two 1-byte UNKNOWN items rather
        # than the one 2-byte CODE item the original bytes decode as).
        # create_insn() recreates instructions synchronously, deterministically,
        # from the bytes now in place -- Mode A only ever governs ranges the
        # encoder/original bytes both decode cleanly, so this always has a
        # real instruction stream to recreate.
        cursor = start_ea
        while cursor < end_ea:
            length = ida_ua.create_insn(cursor)
            if length <= 0:
                break
            cursor += length
