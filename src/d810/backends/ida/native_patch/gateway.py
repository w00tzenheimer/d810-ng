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
import json
import time
from dataclasses import dataclass, replace
from uuid import uuid4

from d810.backends.ida.native_patch.capture import LiveDatabaseReader
from d810.backends.ida.native_patch.metadata import (
    MetadataActionExecutor,
    MetadataStateMismatch,
    _parse_scoped_item_state,
    _parse_reversible_data_item_state,
    _scoped_item_token,
)
from d810.backends.ida.native_patch.preflight import (
    DecodeReplacement,
    PlanPreflightResult,
    preflight_plan_live,
)
from d810.backends.ida.native_patch.phase_schema import (
    AnalysisPhaseWitness,
    canonical_phase_item_state,
    PhaseExtent,
    PhaseGlobalState,
    PhaseItem,
    PhaseXref,
    PhaseWitnessError,
    make_analysis_phase_attestation,
    parse_analysis_phase_attestation,
    parse_analysis_phase_witness,
)
from d810.backends.ida.native_patch.reanalysis import (
    FunctionExtentRestorer,
    FunctionFlowRestorer,
    FunctionReanalyzer,
    reanalyze_and_wait,
)
from d810.backends.ida.native_patch.issuer import NativePatchIssuerRegistry
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
    NativeAddressRange,
    NativeCertificate,
    NativeMetadataActionKind,
    NativeCertificateState,
    NativeDatabaseIdentity,
    NativeFunctionFlowRef,
    NativeFunctionOwnership,
    NativeFunctionTypeInfo,
    NativePatchOperation,
    NativePatchPlan,
    certificate_from_payload,
    certificate_to_payload,
)

logger = getLogger("d810.backends.ida.native_patch.gateway")


def _metadata_scope_hint(state: str) -> str | None:
    """Return a historical item scope only for composite metadata tokens."""
    return (
        state
        if isinstance(state, str)
        and state.startswith(("item-xrefs:v1:", "item-xrefs:v2:"))
        else None
    )

__all__ = [
    "IdaNativeByteWriter",
    "NativeApplyReceipt",
    "NativePatchBlobStore",
    "NativePatchCertificationFailed",
    "NativePatchGateway",
    "NativePatchGatewayError",
    "NativePatchDatabaseIdentityMismatch",
    "NativePatchMetadataActionUnsupported",
    "NativePatchIssuerRejected",
    "NativePatchRestoreNotCertified",
    "NativePatchWriteVerificationFailed",
    "NativeByteWriter",
    "NativeRestoreReceipt",
]


class NativePatchGatewayError(RuntimeError):
    """Base class for every gateway-raised error."""


class NativePatchDatabaseIdentityMismatch(NativePatchGatewayError, ValueError):
    """A destructive gateway call targeted another IDB's journal row."""


class NativePatchIssuerRejected(NativePatchGatewayError):
    """The plan did not match any exact named issuer contract."""


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
            "restore requires a CERTIFIED transaction or a pending Stage C "
            f"postcondition; current state is {state.value}"
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
    preflight_receipt_id: str | None = None

    @property
    def ok(self) -> bool:
        return self.state is NativeJournalState.CERTIFIED

    @property
    def postcondition_pending(self) -> bool:
        return self.state is NativeJournalState.POSTCONDITION_PENDING


@dataclass(frozen=True, slots=True)
class NativeRestoreReceipt:
    transaction_id: NativePatchTransactionId
    state: NativeJournalState
    restored_eas: tuple[int, ...]
    interference_eas: tuple[int, ...]
    controlled_redo_function_eas: tuple[int, ...] = ()
    failure_reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.state is NativeJournalState.RESTORED

    @property
    def rejection_reasons(self) -> tuple[str, ...]:
        """Expose restore failures in the same shape as apply receipts."""

        return () if self.failure_reason is None else (self.failure_reason,)


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
        extent_restorer: FunctionExtentRestorer,
        flow_restorer: FunctionFlowRestorer,
        metadata_executor: MetadataActionExecutor | None = None,
        cache_invalidator: CfuncCacheInvalidator,
        caller_discovery: CallerDiscovery,
        redo_decompiler: ControlledRedoDecompiler,
        certificate_store: NativePatchBlobStore,
        issuer_registry: NativePatchIssuerRegistry,
        current_database_identity: str,
        d810_version: str = "unknown",
    ) -> None:
        self._journal = journal
        self._reader = reader
        self._writer = writer
        self._decode_replacement = decode_replacement
        self._reanalyzer = reanalyzer
        # Required, not optional-with-a-default: a gateway that silently
        # skips extent restoration produces a RESTORED receipt for a database
        # that was not restored, which is worse than failing to construct.
        self._extent_restorer = extent_restorer
        self._flow_restorer = flow_restorer
        # Optional: a plan with no metadata actions never needs one, and
        # without it any plan that HAS them still fails closed exactly as
        # before rather than being silently skipped.
        self._metadata_executor = metadata_executor
        self._cache_invalidator = cache_invalidator
        self._caller_discovery = caller_discovery
        self._redo_decompiler = redo_decompiler
        self._certificate_store = certificate_store
        if (
            not isinstance(current_database_identity, str)
            or not current_database_identity.strip()
        ):
            raise ValueError("current database identity must be a non-empty string")
        self._current_database_identity = current_database_identity
        if not isinstance(issuer_registry, NativePatchIssuerRegistry):
            raise TypeError("issuer_registry must be a NativePatchIssuerRegistry")
        self._issuer_registry = issuer_registry
        self._d810_version = d810_version

    # ------------------------------------------------------------------
    # apply()
    # ------------------------------------------------------------------

    def apply(self, plan: NativePatchPlan) -> NativeApplyReceipt:
        if not isinstance(plan, NativePatchPlan):
            raise TypeError("plan must be a NativePatchPlan")
        if plan.database_identity.idb_uuid != self._current_database_identity:
            raise NativePatchDatabaseIdentityMismatch(
                "plan database identity does not match the current database identity"
            )

        issuer_validation = self._issuer_registry.validate(plan)
        if not issuer_validation.authorized:
            raise NativePatchIssuerRejected(issuer_validation.reason)

        # The phase witness is part of the authorization boundary.  Parse and
        # validate it before PREPARED is durable so malformed grouped plans
        # cannot enter recovery with an ambiguous inverse authority.
        phase_witness = None
        if plan.analysis_phase_witness is not None:
            if not plan.analysis_phase_witness.startswith("analysis-phase:v4:"):
                raise NativePatchGatewayError(
                    "closure-bearing plans require an analysis-phase:v4 witness"
                )
            try:
                phase_witness = parse_analysis_phase_witness(
                    plan.analysis_phase_witness
                )
            except PhaseWitnessError as error:
                raise NativePatchGatewayError(
                    f"malformed analysis phase witness: {error}"
                ) from error
            if any(operation.writes_bytes for operation in plan.operations):
                raise NativePatchGatewayError(
                    "closure-bearing phase plans must be metadata-only"
                )

        record = self._journal.prepare(plan)
        self._mirror_transaction(record)

        try:
            preflight = preflight_plan_live(
                self._reader, plan, self._decode_replacement
            )
            preflight_receipt_id = self._record_preflight_receipt(
                plan, record.transaction_id, preflight
            )
            if not preflight.authorized:
                return self._abandon(
                    record.transaction_id, preflight, preflight_receipt_id
                )

            for op in plan.operations:
                if op.writes_bytes:
                    self._apply_operation_bytes(record.transaction_id, op)
            record = self._journal.transition(
                record.transaction_id, NativeJournalState.BYTES_APPLIED
            )

            if record.has_metadata_actions:
                self._apply_metadata_actions(plan, record.transaction_id)
                # The action tokens prove only the synchronous phase-A
                # witness.  Verify that witness before IDA is allowed to
                # recursively analyze the newly-created instructions.
                self._verify_metadata_actions(plan)
                if phase_witness is not None:
                    self._verify_phase_partition(
                        phase_witness,
                        items_field="before_items",
                        xrefs_field="before_xrefs",
                    )
                record = self._journal.transition(
                    record.transaction_id, NativeJournalState.METADATA_APPLIED
                )

            record = self._journal.transition(
                record.transaction_id, NativeJournalState.ANALYSIS_PENDING
            )
            function_eas = self._owning_function_eas(plan)
            requires_mutation_cleanup = self._plan_requires_mutation(plan)
            if requires_mutation_cleanup:
                for function_ea in function_eas:
                    reanalyze_and_wait(function_ea, reanalyzer=self._reanalyzer)

            recovery = self._journal.classify_recovery(
                record.transaction_id, self._read_current_byte
            )
            if not self._all_operations_cleanly_applied(plan, recovery):
                raise NativePatchCertificationFailed(
                    record.transaction_id,
                    "post-reanalysis byte recheck did not confirm a clean apply",
                )
            if phase_witness is not None:
                self._verify_analysis_phase(plan, phase_witness)
                # The v4 token is immutable semantic authorization.  Capture
                # the complete concrete post-reanalysis partition separately;
                # non-code item flags are IDA's observed authority and must
                # never be fabricated by the planner.
                observed_p = self._live_phase_global_state(phase_witness)
                attestation = make_analysis_phase_attestation(
                    plan.analysis_phase_witness,
                    phase_witness,
                    observed_p,
                    record.transaction_id.value,
                )
                install_attestation = getattr(
                    self._journal, "install_analysis_phase_attestation", None
                )
                if not callable(install_attestation):
                    raise NativePatchCertificationFailed(
                        record.transaction_id,
                        "atomic observed analysis attestation authority is unavailable",
                    )
                install_attestation(
                    record.transaction_id, attestation,
                )
            else:
                self._verify_metadata_actions(plan)
            record = self._journal.transition(
                record.transaction_id, NativeJournalState.ANALYSIS_VALIDATED
            )

            if requires_mutation_cleanup:
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

            certificate = self._certify(plan, record, phase_witness=phase_witness)
            record = self._journal.transition(
                record.transaction_id, NativeJournalState.CERTIFICATE_PENDING
            )
            self._store_certificate(plan, certificate, record.transaction_id)
            record = self._journal.transition(
                record.transaction_id,
                (
                    NativeJournalState.POSTCONDITION_PENDING
                    if plan.issuer_id == "stage-c-native-cfg-normalizer"
                    else NativeJournalState.CERTIFIED
                ),
            )

            return NativeApplyReceipt(
                transaction_id=record.transaction_id,
                state=record.state,
                certificate=certificate,
                preflight_receipt_id=preflight_receipt_id,
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

    @staticmethod
    def _plan_requires_mutation(plan: NativePatchPlan) -> bool:
        """Whether apply changes bytes or any exact metadata state.

        A fully normalized metadata plan is a read-only certification request.
        Running reanalysis, invalidation, or redo for it would create side
        effects despite every action being a no-op, and can destroy metadata
        the certificate is trying to attest.
        """
        return any(
            operation.writes_bytes
            or any(
                action.expected_before != action.expected_after
                for action in operation.metadata_actions
            )
            for operation in plan.operations
        )

    def _apply_metadata_actions(
        self, plan: NativePatchPlan, transaction_id: NativePatchTransactionId
    ) -> None:
        """Execute every metadata action, journaling what each one replaced.

        Read-verify-apply-verify per action. The *observed* before-state is
        what gets journaled, never the plan's ``expected_before``: reversal
        replays the observed value, because re-deriving a before-state at
        restore time reads the already-mutated database -- the function-extent
        P0 in exact miniature.

        Any mismatch or failed apply raises, which aborts the transaction with
        the actions so far already journaled, so recovery can reverse them.
        """
        if self._metadata_executor is None:
            for op in plan.operations:
                if op.metadata_actions:
                    raise NativePatchMetadataActionUnsupported(
                        op.operation_id,
                        tuple(action.kind.value for action in op.metadata_actions),
                    )
            return

        for op in plan.operations:
            for action in op.metadata_actions:
                observed = self._metadata_executor.read_state(
                    action.kind,
                    action.ea,
                    scope_state=_metadata_scope_hint(action.expected_before),
                )
                if observed != action.expected_before:
                    raise MetadataStateMismatch(
                        action.kind.value,
                        action.ea,
                        action.expected_before,
                        observed,
                    )
                # A repeat observation of an already-normalized request
                # intentionally carries an after==before witness so its
                # metadata target can be certified.  Never send that through
                # an IDA mutator: the gateway must prove reuse read-only.
                if observed == action.expected_after:
                    continue
                # Journal BEFORE applying. An action that is applied but not
                # recorded is unreversible; one recorded but not applied is
                # reversed to the state it already holds, which is a no-op.
                self._journal.record_metadata_action(
                    transaction_id,
                    operation_id=op.operation_id,
                    kind=action.kind.value,
                    ea=action.ea,
                    recorded_before=observed,
                    expected_after=action.expected_after,
                )
                if not self._metadata_executor.apply_state(
                    action.kind, action.ea, action.expected_after
                ):
                    raise MetadataStateMismatch(
                        action.kind.value,
                        action.ea,
                        action.expected_after,
                        self._metadata_executor.read_state(
                            action.kind,
                            action.ea,
                            scope_state=_metadata_scope_hint(action.expected_after),
                        ),
                    )

    def _reverse_metadata_actions(
        self, transaction_id: NativePatchTransactionId
    ) -> tuple[str, ...]:
        """Undo journaled metadata actions, newest first. Returns failures.

        Reverse application order, not address order: actions can depend on
        each other (an item must exist before a cref to it does), so undoing
        them in the order they were made would break those dependencies.
        """
        actions = self._journal.metadata_actions(transaction_id)
        if self._metadata_executor is None:
            if not actions:
                return ()
            return tuple(f"{a.kind}@{a.ea:#x}" for a in actions)

        phase = self._phase_witness_for_transaction(transaction_id)
        if not actions and phase is None:
            return ()
        durable_auth = self._journal.analysis_phase_witness(transaction_id)
        attestation_reader = getattr(self._journal, "analysis_phase_attestation", None)
        if (
            durable_auth is not None
            and durable_auth.startswith("analysis-phase:v4:")
            and callable(attestation_reader)
            and attestation_reader(transaction_id) is None
        ):
            return ("analysis-phase:missing-observed-attestation",)
        if phase is not None:
            phase_state = self._analysis_phase_state(transaction_id, phase)
            if phase_state in {"P", "R_i", "cleared-mid-carrier"}:
                return self._reverse_analysis_phase(transaction_id, actions, phase)
            if phase_state not in {"B", "partial-analysis"}:
                return (f"analysis-phase:{phase_state}-recovery-required",)
            if phase_state == "B":
                try:
                    live = self._live_phase_global_state(
                        phase, items_field="before_items", xrefs_field="before_xrefs"
                    )
                    expected = self._expected_phase_global_state(phase, sealed=False)
                    if live != expected:
                        return ("analysis-phase:global-state-drift-recovery-required",)
                except Exception:
                    return ("analysis-phase:global-state-drift-recovery-required",)
            # Exact B is still the synchronous action partition.  It has not
            # crossed the reanalysis cut point, so ordinary journaled action
            # reversal is the exact inverse and closure recreation is not
            # authorized yet.
        if phase is None and any(
            (_parse_scoped_item_state(action.expected_after, expected_ea=action.ea) or {}).get(
                "origin_data_state"
            )
            is not None
            for action in actions
        ):
            # A closure-bearing transaction is never allowed to downgrade to
            # ordinary per-action reversal when its durable phase authority
            # is missing or malformed.
            return ("analysis-phase:missing-journal-witness",)

        reversible: list[tuple[object, NativeMetadataActionKind]] = []
        for action in reversed(actions):
            try:
                kind = NativeMetadataActionKind(action.kind)
                current = self._metadata_executor.read_state(
                    kind,
                    action.ea,
                    scope_state=_metadata_scope_hint(action.expected_after),
                )
                if current == action.recorded_before:
                    continue
                if current != action.expected_after:
                    return (f"{action.kind}@{action.ea:#x}",)
                reversible.append((action, kind))
            except Exception:
                return (f"{action.kind}@{action.ea:#x}",)
        failed: list[str] = []
        for action, kind in reversible:
            try:
                ok = self._metadata_executor.apply_state(
                    kind, action.ea, action.recorded_before
                )
            except Exception:
                ok = False
            if not ok:
                failed.append(f"{action.kind}@{action.ea:#x}")
        return tuple(failed)

    def _reverse_analysis_phase(
        self,
        transaction_id: NativePatchTransactionId,
        actions,
        phase: AnalysisPhaseWitness,
    ) -> tuple[str, ...]:
        """Remove phase-B closure by the durable natural inverse schedule."""
        assert self._metadata_executor is not None
        failures: list[str] = []
        phase_state = self._analysis_phase_state(transaction_id, phase)
        if phase_state not in {"P", "R_i", "cleared-mid-carrier"}:
            return (
                f"analysis-phase:{phase_state}"
                "-recovery-required",
            )

        schedule = phase.get("reverse_schedule")
        if not isinstance(schedule, tuple):
            return ("analysis-phase:missing-reverse-schedule",)
        durable_steps = self._journal.analysis_reverse_steps(transaction_id)
        if len(durable_steps) != len(schedule):
            return ("analysis-phase:missing-reverse-schedule",)
        try:
            self._verify_reverse_cursor_global_state(
                transaction_id, phase, durable_steps
            )
        except Exception:
            return ("analysis-phase:reverse-cursor-drift",)
        schedule_actions: dict[int, object] = {}
        schedule_step_index: dict[tuple[str, int], int] = {}
        group_heads: list[int] = []
        for step_index, entry in enumerate(schedule):
            kind = entry.get("kind")
            if kind == "action":
                index = entry.get("index")
                if (
                    not isinstance(index, int)
                    or isinstance(index, bool)
                    or index < 0
                    or not isinstance(entry.get("action_kind"), str)
                    or not isinstance(entry.get("ea"), int)
                    or isinstance(entry.get("ea"), bool)
                    or not isinstance(entry.get("expected_after"), str)
                ):
                    return ("analysis-phase:malformed-reverse-schedule",)
                if index in schedule_actions:
                    return ("analysis-phase:duplicate-reverse-action",)
                schedule_actions[index] = entry
                schedule_step_index[("action", index)] = step_index
            elif kind == "group" and isinstance(entry.get("head_ea"), int):
                head_ea = int(entry["head_ea"])
                if head_ea in group_heads:
                    return ("analysis-phase:duplicate-reverse-group",)
                group_heads.append(head_ea)
                schedule_step_index[("group", head_ea)] = step_index
            else:
                return ("analysis-phase:malformed-reverse-schedule",)
            row = durable_steps[step_index]
            if row["step_index"] != step_index or row["kind"] != kind:
                return ("analysis-phase:reverse-schedule-drift",)
            if kind == "group":
                if row["head_ea"] != entry.get("head_ea"):
                    return ("analysis-phase:reverse-schedule-drift",)
            elif (
                row["action_index"] != entry.get("index")
                or row["action_kind"] != entry.get("action_kind")
                or row["ea"] != entry.get("ea")
                or row["expected_after"] != entry.get("expected_after")
            ):
                return ("analysis-phase:reverse-schedule-drift",)
        if not schedule_actions:
            return ("analysis-phase:incomplete-reverse-schedule",)

        journal_by_index: dict[int, object] = {}
        for action in actions:
            matches = [
                index for index, entry in schedule_actions.items()
                if entry.get("action_kind") == str(action.kind)
                and entry.get("ea") == action.ea
                and entry.get("expected_after") == action.expected_after
            ]
            if len(matches) != 1:
                return ("analysis-phase:action-schedule-identity-mismatch",)
            journal_by_index[matches[0]] = action

        # User-owned actions are reversed in the persisted global order. A
        # carrier action is only a witness; its enclosing group owns the P->R
        # inverse and is executed at its durable group schedule position.
        for entry in schedule:
            if entry.get("kind") != "action":
                continue
            action_index = int(entry["index"])
            step_index = schedule_step_index[("action", action_index)]
            action = journal_by_index.get(action_index)
            durable_step = durable_steps[step_index]
            if durable_step["status"] == "complete":
                # A completed action is already part of the durable reverse
                # prefix.  Verify its exact before-state and never replay its
                # mutator after a carrier interruption.
                if action is not None:
                    if (
                        _parse_scoped_item_state(
                            action.expected_after, expected_ea=action.ea
                        )
                        or {}
                    ).get("origin_data_state") is not None:
                        # Carrier item actions are durable witnesses for the
                        # enclosing group; their data transition is executed
                        # by the group step, not by this action row.
                        continue
                    try:
                        kind = NativeMetadataActionKind(action.kind)
                        current = self._metadata_executor.read_state(
                            kind,
                            action.ea,
                            scope_state=_metadata_scope_hint(action.expected_after),
                        )
                    except Exception:
                        current = None
                    if current != action.recorded_before:
                        failures.append(f"{action.kind}@{action.ea:#x}")
                continue
            try:
                self._journal.record_analysis_reverse_intent(
                    transaction_id,
                    step_index,
                    f"action:{action_index}:{entry['action_kind']}@{int(entry['ea']):#x}",
                )
            except Exception:
                return ("analysis-phase:reverse-intent-drift",)
            if action is None:
                try:
                    self._journal.record_analysis_reverse_completion(
                        transaction_id, step_index, "action-noop"
                    )
                except Exception:
                    return ("analysis-phase:reverse-completion-drift",)
                continue
            scope = _parse_scoped_item_state(
                action.expected_after, expected_ea=action.ea
            )
            if scope is not None and scope.get("origin_data_state") is not None:
                try:
                    self._journal.record_analysis_reverse_completion(
                        transaction_id, step_index, "action-carrier-deferred"
                    )
                except Exception:
                    return ("analysis-phase:reverse-completion-drift",)
                continue
            try:
                kind = NativeMetadataActionKind(action.kind)
                current = self._metadata_executor.read_state(
                    kind, action.ea,
                    scope_state=_metadata_scope_hint(action.expected_after),
                )
                if current == action.recorded_before:
                    self._journal.record_analysis_reverse_completion(
                        transaction_id, step_index, "action-already-restored"
                    )
                elif current != action.expected_after:
                    failures.append(f"{action.kind}@{action.ea:#x}")
                elif not self._metadata_executor.apply_state(
                    kind, action.ea, action.recorded_before
                ):
                    failures.append(f"{action.kind}@{action.ea:#x}")
                else:
                    self._journal.record_analysis_reverse_completion(
                        transaction_id, step_index, "action-restored"
                    )
            except Exception:
                failures.append(f"{action.kind}@{action.ea:#x}")
        if failures:
            return tuple(failures)

        groups_by_head: dict[int, object] = {}
        for group in phase.get("groups", ()):
            origin_token = group.get("origin_data_state")
            if not isinstance(origin_token, str):
                return ("analysis-phase:malformed-reverse-groups",)
            origin = _parse_reversible_data_item_state(origin_token)
            if origin is None:
                return ("analysis-phase:malformed-reverse-groups",)
            head_ea = int(origin["head_ea"])
            if head_ea in groups_by_head:
                return ("analysis-phase:duplicate-reverse-group",)
            groups_by_head[head_ea] = group
        if set(group_heads) != set(groups_by_head):
            return ("analysis-phase:incomplete-reverse-groups",)

        for head_ea in group_heads:
            group = groups_by_head[head_ea]
            step_index = schedule_step_index[("group", head_ea)]
            origin_token = group.get("origin_data_state")
            targets = group.get("group_targets")
            if (
                not isinstance(origin_token, str)
                or not isinstance(targets, list)
                or any(not isinstance(ea, int) or isinstance(ea, bool) for ea in targets)
            ):
                return ("analysis-phase:malformed-reverse-groups",)
            try:
                origin = _parse_reversible_data_item_state(origin_token)
                reverse_before = self._phase_xrefs(group, "reverse_before_xrefs")
                reverse_after = self._phase_xrefs(group, "reverse_after_xrefs")
            except Exception:
                return ("analysis-phase:malformed-reverse-groups",)
            if origin is None:
                return ("analysis-phase:malformed-reverse-groups",)
            origin_ea = int(origin["ea"])
            origin_head = int(origin["head_ea"])
            origin_size = int(origin["size"])
            postconditions = group.get("postconditions")
            if not isinstance(postconditions, list):
                return ("analysis-phase:malformed-reverse-groups",)
            postcondition = next(
                (
                    row for row in postconditions
                    if isinstance(row, dict)
                    and row.get("ea") == origin_ea
                    and isinstance(row.get("state"), str)
                ),
                None,
            )
            if postcondition is None:
                return ("analysis-phase:malformed-reverse-groups",)
            current_scope = _parse_scoped_item_state(
                postcondition["state"], expected_ea=origin_ea
            )
            if current_scope is None:
                return ("analysis-phase:malformed-reverse-groups",)
            current_state = _scoped_item_token(
                ea=origin_ea,
                head_ea=origin_head,
                size=origin_size,
                item_state=str(current_scope["item_state"]),
                xrefs=reverse_before,
                origin_data_state=origin_token,
                group_targets=tuple(targets),
            )
            durable_step = durable_steps[step_index]
            if durable_step["status"] not in {"intent", "complete"}:
                if self._metadata_executor.read_state(
                    NativeMetadataActionKind.RECREATE_ITEM,
                    origin_ea,
                    scope_state=current_state,
                ) != current_state:
                    return ("analysis-phase:carrier-state-drift",)
            inverse_data = json.loads(origin_token.removeprefix("data:v2:"))
            inverse_data["xrefs"] = [
                {
                    "source_ea": source,
                    "target_ea": target,
                    "xref_type": xref_type,
                    "user_owned": user_owned,
                    "is_code": is_code,
                }
                for source, target, xref_type, user_owned, is_code in reverse_after
            ]
            inverse_data_state = "data:v2:" + json.dumps(
                inverse_data, sort_keys=True, separators=(",", ":")
            )
            target_state = _scoped_item_token(
                ea=origin_ea,
                head_ea=origin_head,
                size=origin_size,
                item_state=inverse_data_state,
                xrefs=reverse_after,
                origin_data_state=origin_token,
                group_targets=tuple(targets),
            )
            try:
                if durable_step["status"] == "complete":
                    self._verify_reverse_cursor_global_state(
                        transaction_id,
                        phase,
                        self._journal.analysis_reverse_steps(transaction_id),
                    )
                    continue
                intent = (
                    durable_step["intent"]
                    if durable_step["status"] == "intent"
                    else f"carrier:{head_ea:#x}"
                )
                self._journal.record_analysis_reverse_intent(
                    transaction_id, step_index, intent
                )
                current_origin = self._metadata_executor.read_state(
                    NativeMetadataActionKind.RECREATE_ITEM, origin_ea
                )
                if current_origin == origin_token:
                    ok = True
                elif current_origin == "unknown" and durable_step["status"] == "intent":
                    ok = self._metadata_executor.recreate_data_item(
                        origin_ea, target_state
                    )
                elif durable_step["status"] == "intent":
                    ok = False
                else:
                    ok = self._metadata_executor.apply_phase_inverse(
                        origin_ea, target_state
                    )
                if not ok:
                    failures.append(f"analysis-phase@{origin_ea:#x}")
                else:
                    self._journal.record_analysis_reverse_completion(
                        transaction_id,
                        step_index,
                        f"carrier-restored:{origin_ea:#x}",
                    )
            except Exception:
                failures.append(f"analysis-phase@{origin_ea:#x}")
        return tuple(failures)

    def _phase_witness_for_transaction(
        self, transaction_id: NativePatchTransactionId
    ) -> AnalysisPhaseWitness | None:
        attestation_reader = getattr(self._journal, "analysis_phase_attestation", None)
        if callable(attestation_reader):
            attestation_token = attestation_reader(transaction_id)
            if attestation_token is not None:
                try:
                    attestation = parse_analysis_phase_attestation(attestation_token)
                    return replace(
                        attestation.phase_witness,
                        sealed_state=attestation.observed_state,
                        reverse_schedule=attestation.reverse_schedule,
                    )
                except PhaseWitnessError:
                    return None
        durable = self._journal.analysis_phase_witness(transaction_id)
        if durable is not None and not durable.startswith("analysis-phase:v4:"):
            return None
        try:
            return None if durable is None else parse_analysis_phase_witness(durable)
        except PhaseWitnessError:
            return None

    def _analysis_phase_state(
        self, transaction_id: NativePatchTransactionId, phase: AnalysisPhaseWitness
    ) -> str:
        """Classify a journaled phase without mutating live metadata.

        The durable cursor disambiguates an exact carrier cut point from a
        failed item recreation.  Any state that is neither the synchronous B
        partition, the sealed P partition, nor a completed R_i is recovery
        required and never enters an inverse mutator.
        """
        record = self._journal.get(transaction_id)
        # Before the durable analysis barrier, a miniature provider may
        # expose the same code head as P. The journal lifecycle is the
        # authority that distinguishes exact synchronous B/partial-A from
        # post-reanalysis P and prevents a closure inverse too early.
        if record is not None and record.state in {
            NativeJournalState.PREPARED,
            NativeJournalState.BYTES_APPLIED,
            NativeJournalState.METADATA_APPLIED,
            NativeJournalState.ANALYSIS_PENDING,
        }:
            return "B"
        try:
            self._verify_phase_partition(
                phase, items_field="after_items", xrefs_field="after_xrefs"
            )
            return "P"
        except Exception:
            pass
        try:
            self._verify_phase_partition(
                phase, items_field="before_items", xrefs_field="before_xrefs"
            )
            return "B"
        except Exception:
            pass
        steps = self._journal.analysis_reverse_steps(transaction_id)
        if any(row["status"] == "intent" for row in steps):
            return "cleared-mid-carrier"
        if any(row["status"] == "complete" for row in steps):
            return "R_i"
        record = self._journal.get(transaction_id)
        if record is not None and record.state in {
            NativeJournalState.PREPARED,
            NativeJournalState.BYTES_APPLIED,
            NativeJournalState.METADATA_APPLIED,
            NativeJournalState.ANALYSIS_PENDING,
        }:
            return "partial-analysis"
        return "unknown"

    @staticmethod
    def _all_operations_cleanly_applied(
        plan: NativePatchPlan,
        recovery: NativeTransactionRecoveryReport,
    ) -> bool:
        reports = {report.operation_id: report for report in recovery.operation_reports}
        for operation in plan.operations:
            report = reports.get(operation.operation_id)
            if report is None:
                return False
            if operation.writes_bytes:
                if not (
                    report.verdict is NativeOperationRecoveryVerdict.APPLIED
                    and report.corroborated_by_write_applied_receipt
                ):
                    return False
                continue
            # Metadata-only operations retain a byte anchor solely as a live
            # identity/preflight witness.  It must remain at the before/after
            # identical image and there must be no byte-write receipt.
            if report.verdict is not NativeOperationRecoveryVerdict.NOT_APPLIED:
                return False
            if report.corroborated_by_write_applied_receipt:
                return False
        return True

    def _verify_metadata_actions(self, plan: NativePatchPlan) -> None:
        """Re-read every owned metadata action after reanalysis.

        Reanalysis is allowed to rebuild derived state, but it must not erase
        a user-owned tail/xref/switch/item action that the transaction claims
        to have applied.  This second check keeps certification honest for a
        metadata-only operation whose byte anchor is intentionally unchanged.
        """
        if not any(op.metadata_actions for op in plan.operations):
            return
        if self._metadata_executor is None:
            raise NativePatchMetadataActionUnsupported("metadata", ())
        final_actions = {}
        for operation in plan.operations:
            for action in operation.metadata_actions:
                final_actions[(action.kind, action.ea)] = action
        for action in final_actions.values():
            observed = self._metadata_executor.read_state(
                action.kind,
                action.ea,
                scope_state=_metadata_scope_hint(action.expected_after),
            )
            if observed != action.expected_after:
                raise MetadataStateMismatch(
                    action.kind.value,
                    action.ea,
                    action.expected_after,
                    observed,
                )

    @staticmethod
    def _parse_analysis_phase_witness(plan: NativePatchPlan) -> AnalysisPhaseWitness:
        token = plan.analysis_phase_witness
        if not isinstance(token, str) or not token.startswith("analysis-phase:v4:"):
            raise NativePatchCertificationFailed(
                NativePatchTransactionId("phase-witness"),
                "missing or unsupported analysis phase witness",
            )
        try:
            return parse_analysis_phase_witness(token)
        except PhaseWitnessError as error:
            raise NativePatchCertificationFailed(
                NativePatchTransactionId("phase-witness"),
                "malformed analysis phase witness",
            ) from error

    @staticmethod
    def _phase_xrefs(group: dict[str, object], field: str) -> tuple[tuple[int, int, int, bool, bool], ...]:
        rows = group.get(field)
        if not isinstance(rows, list):
            raise MetadataStateMismatch("analysis-phase", 0, field, repr(rows))
        parsed: list[tuple[int, int, int, bool, bool]] = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != {
                "source_ea", "target_ea", "xref_type", "user_owned", "is_code"
            }:
                raise MetadataStateMismatch("analysis-phase", 0, field, repr(row))
            if any(not isinstance(row[key], int) for key in ("source_ea", "target_ea", "xref_type")):
                raise MetadataStateMismatch("analysis-phase", 0, field, repr(row))
            if not isinstance(row["user_owned"], bool) or not isinstance(row["is_code"], bool):
                raise MetadataStateMismatch("analysis-phase", 0, field, repr(row))
            parsed.append((
                int(row["source_ea"]), int(row["target_ea"]),
                int(row["xref_type"]), bool(row["user_owned"]), bool(row["is_code"]),
            ))
        result = tuple(sorted(set(parsed)))
        canonical_rows = [
            {
                "source_ea": source,
                "target_ea": target,
                "xref_type": xref_type,
                "user_owned": user_owned,
                "is_code": is_code,
            }
            for source, target, xref_type, user_owned, is_code in result
        ]
        if canonical_rows != rows:
            raise MetadataStateMismatch("analysis-phase", 0, field, repr(rows))
        return result

    def _verify_phase_partition(
        self, phase: dict[str, object], *, items_field: str, xrefs_field: str
    ) -> None:
        """Reread one exact item partition and its complete scoped xref graph."""
        assert self._metadata_executor is not None
        for group in phase.get("groups", ()):
            if not hasattr(group, "get"):
                raise MetadataStateMismatch("analysis-phase", 0, "group", repr(group))
            origin_token = group.get("origin_data_state")
            targets = group.get("group_targets")
            rows = group.get(items_field)
            if not isinstance(origin_token, str) or not isinstance(targets, list) or not isinstance(rows, list):
                raise MetadataStateMismatch("analysis-phase", 0, items_field, repr(group))
            origin = _parse_reversible_data_item_state(origin_token)
            if origin is None:
                raise MetadataStateMismatch("analysis-phase", 0, "origin", repr(origin_token))
            group_targets = tuple(int(ea) for ea in targets)
            if list(group_targets) != targets or tuple(sorted(group_targets)) != group_targets:
                raise MetadataStateMismatch("analysis-phase", 0, "group_targets", repr(targets))
            xrefs = self._phase_xrefs(group, xrefs_field)
            seen: set[int] = set()
            for row in rows:
                if not isinstance(row, list) or len(row) != 3:
                    raise MetadataStateMismatch("analysis-phase", 0, items_field, repr(row))
                ea, size, item_state = row
                if not isinstance(ea, int) or not isinstance(size, int) or not isinstance(item_state, str):
                    raise MetadataStateMismatch("analysis-phase", 0, items_field, repr(row))
                if ea in seen:
                    raise MetadataStateMismatch("analysis-phase", ea, "unique item", repr(row))
                seen.add(ea)
                if item_state == "unknown":
                    continue
                expected = _scoped_item_token(
                    ea=int(ea),
                    head_ea=int(origin["head_ea"]),
                    size=int(origin["size"]),
                    item_state=item_state,
                    xrefs=xrefs,
                    origin_data_state=origin_token,
                    group_targets=group_targets,
                )
                observed = self._metadata_executor.read_state(
                    NativeMetadataActionKind.RECREATE_ITEM,
                    int(ea),
                    scope_state=expected,
                )
                if observed != expected:
                    raise MetadataStateMismatch("analysis-phase", int(ea), expected, observed)

    def _expected_phase_global_state(
        self, phase: AnalysisPhaseWitness, *, sealed: bool
    ) -> PhaseGlobalState:
        items: dict[tuple[int, int], PhaseItem] = {}
        xrefs: dict[tuple[int, int, int, bool, bool], PhaseXref] = {}
        for group in phase.groups:
            raw_items = group.after_items if sealed else group.before_items
            raw_xrefs = group.after_xrefs if sealed else group.before_xrefs
            for item in raw_items:
                items[(item.ea, item.size)] = item
            for row in raw_xrefs:
                xrefs[(row.source_ea, row.target_ea, row.xref_type, row.user_owned, row.is_code)] = row
        if phase.sealed_state is not None:
            extents = phase.sealed_state.extents
        else:
            extents = tuple(
                PhaseExtent(
                    int(_parse_reversible_data_item_state(group.origin_data_state)["head_ea"]),
                    int(_parse_reversible_data_item_state(group.origin_data_state)["head_ea"])
                    + int(_parse_reversible_data_item_state(group.origin_data_state)["size"]),
                )
                for group in phase.groups
            )
        return PhaseGlobalState(
            items=tuple(sorted(items.values(), key=lambda row: (row.ea, row.size, row.state))),
            xrefs=tuple(sorted(xrefs.values(), key=lambda row: (
                row.source_ea, row.target_ea, row.xref_type, row.user_owned, row.is_code
            ))),
            extents=extents,
        )

    def _live_phase_global_state(
        self, phase: AnalysisPhaseWitness, *, items_field: str = "after_items", xrefs_field: str = "after_xrefs"
    ) -> PhaseGlobalState:
        """Reconstruct the complete live global state through the provider seam."""
        assert self._metadata_executor is not None
        enumerate_partition = getattr(self._metadata_executor, "enumerate_item_partition", None)
        if not callable(enumerate_partition):
            raise MetadataStateMismatch("analysis-phase", 0, "item partition provider", "missing")
        items: dict[tuple[int, int], PhaseItem] = {}
        xrefs: dict[tuple[int, int, int, bool, bool], PhaseXref] = {}
        if phase.sealed_state is None:
            raise MetadataStateMismatch("analysis-phase", 0, "sealed extents", "missing")
        extents = [(extent.low, extent.high) for extent in phase.sealed_state.extents]
        if not extents:
            raise MetadataStateMismatch("analysis-phase", 0, "sealed extents", "empty")
        for low, high in extents:
            try:
                partition = enumerate_partition(low, high)
            except Exception as error:
                raise MetadataStateMismatch("analysis-phase", low, "item partition", repr(error)) from error
            for ea, size, state in partition:
                if (
                    not isinstance(ea, int) or isinstance(ea, bool)
                    or not isinstance(size, int) or isinstance(size, bool)
                    or size <= 0 or not isinstance(state, str) or not state
                ):
                    raise MetadataStateMismatch("analysis-phase", low, "item partition", repr((ea, size, state)))
                try:
                    state = canonical_phase_item_state(state, head_ea=ea)
                except PhaseWitnessError as error:
                    raise MetadataStateMismatch(
                        "analysis-phase", ea, "canonical item state", repr(error)
                    ) from error
                item = PhaseItem(ea, size, state)
                key = (item.ea, item.size)
                previous = items.get(key)
                if previous is not None and previous.state != item.state:
                    raise MetadataStateMismatch("analysis-phase", low, "item partition", repr((previous, item)))
                items[key] = item
        enumerate_xrefs = getattr(self._metadata_executor, "enumerate_scoped_xrefs", None)
        if not callable(enumerate_xrefs):
            raise MetadataStateMismatch("analysis-phase", 0, "scoped xref provider", "missing")
        try:
            raw_xrefs = enumerate_xrefs(tuple(extents))
        except Exception as error:
            raise MetadataStateMismatch("analysis-phase", 0, "scoped xrefs", repr(error)) from error
        for row in raw_xrefs:
            if not isinstance(row, (tuple, list)) or len(row) != 5:
                raise MetadataStateMismatch("analysis-phase", 0, "scoped xrefs", repr(row))
            source, target, xref_type, user_owned, is_code = row
            if (
                not isinstance(source, int) or isinstance(source, bool)
                or not isinstance(target, int) or isinstance(target, bool)
                or not isinstance(xref_type, int) or isinstance(xref_type, bool)
                or not isinstance(user_owned, bool) or not isinstance(is_code, bool)
            ):
                raise MetadataStateMismatch("analysis-phase", 0, "scoped xrefs", repr(row))
            ref = PhaseXref(source, target, xref_type, user_owned, is_code)
            xrefs[(source, target, xref_type, user_owned, is_code)] = ref
        # Overlapping carrier extents can enumerate the same UNKNOWN bytes
        # from two provider views.  Canonicalize the union as one partition,
        # letting concrete items win and regenerating UNKNOWN complements.
        merged_extents: list[tuple[int, int]] = []
        for low, high in sorted(extents):
            if merged_extents and low <= merged_extents[-1][1]:
                merged_extents[-1] = (
                    merged_extents[-1][0], max(merged_extents[-1][1], high)
                )
            else:
                merged_extents.append((low, high))
        concrete = sorted(
            (item for item in items.values() if item.state != "unknown"),
            key=lambda item: (item.ea, item.size, item.state),
        )
        previous_end = -1
        for item in concrete:
            if item.ea < previous_end:
                raise MetadataStateMismatch(
                    "analysis-phase", item.ea, "non-overlapping items", repr(item)
                )
            previous_end = item.ea + item.size
        canonical_items: list[PhaseItem] = []
        for low, high in merged_extents:
            cursor = low
            for item in concrete:
                item_end = item.ea + item.size
                if item_end <= low:
                    continue
                if item.ea >= high:
                    break
                if item.ea < cursor or item_end > high:
                    raise MetadataStateMismatch(
                        "analysis-phase", item.ea, "item within extents", repr(item)
                    )
                if item.ea > cursor:
                    canonical_items.append(PhaseItem(cursor, item.ea - cursor, "unknown"))
                canonical_items.append(item)
                cursor = item_end
            if cursor < high:
                canonical_items.append(PhaseItem(cursor, high - cursor, "unknown"))
        return PhaseGlobalState(
            items=tuple(canonical_items),
            xrefs=tuple(sorted(xrefs.values(), key=lambda row: (
                row.source_ea, row.target_ea, row.xref_type, row.user_owned, row.is_code
            ))),
            extents=tuple(PhaseExtent(low, high) for low, high in extents),
        )

    def _verify_reverse_cursor_global_state(
        self,
        transaction_id: NativePatchTransactionId,
        phase: AnalysisPhaseWitness,
        steps: tuple[dict[str, object], ...],
        *,
        allow_intent_after: bool = True,
    ) -> None:
        """Preflight the exact global state before any reverse mutation."""
        if phase.sealed_state is None or phase.origin_state is None:
            raise MetadataStateMismatch("analysis-phase", 0, "global state", "missing")
        live = self._live_phase_global_state(phase)
        statuses = [row.get("status") for row in steps]
        if any(status not in {"pending", "intent", "complete"} for status in statuses):
            raise MetadataStateMismatch("analysis-phase", 0, "cursor", repr(steps))
        complete = [index for index, status in enumerate(statuses) if status == "complete"]
        intents = [index for index, status in enumerate(statuses) if status == "intent"]
        if complete != list(range(len(complete))):
            raise MetadataStateMismatch("analysis-phase", 0, "cursor", repr(steps))
        if len(intents) > 1 or (intents and intents[0] != len(complete)):
            raise MetadataStateMismatch("analysis-phase", 0, "cursor", repr(steps))
        if intents and any(status != "pending" for status in statuses[intents[0] + 1 :]):
            raise MetadataStateMismatch("analysis-phase", 0, "cursor", repr(steps))
        if intents:
            index = intents[0]
            step = phase.reverse_schedule[index]
            allowed = {step.global_before}
            if allow_intent_after:
                allowed.add(step.global_after)
            if step.cleared_state is not None:
                allowed.add(step.cleared_state)
            if live not in allowed:
                raise MetadataStateMismatch("analysis-phase", 0, "intent global state", repr(live))
            return
        expected = phase.sealed_state if not complete else phase.reverse_schedule[complete[-1]].global_after
        if live != expected:
            raise MetadataStateMismatch("analysis-phase", 0, "cursor global state", repr(live))

    def _verify_analysis_phase(
        self, plan: NativePatchPlan, phase: AnalysisPhaseWitness | None = None
    ) -> None:
        """Verify the exact post-reanalysis item/xref seal (phase P)."""
        payload = phase if phase is not None else self._parse_analysis_phase_witness(plan)
        if self._metadata_executor is None:
            raise NativePatchMetadataActionUnsupported("analysis-phase", ())
        self._verify_phase_partition(payload, items_field="after_items", xrefs_field="after_xrefs")

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
        preflight_receipt_id: str,
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
            preflight_receipt_id=preflight_receipt_id,
        )

    def record_diagnostic_snapshot(self, plan: NativePatchPlan) -> str:
        """Persist a read-only lowering snapshot and return its own receipt id."""
        snapshot_id = uuid4().hex
        payload = {
            "plan_id": plan.plan_id,
            "plan_hash": plan.plan_hash,
            "database_identity": plan.database_identity.idb_uuid,
            "function_ea": plan.function_identity.entry_ea,
            "metadata_actions": [
                {
                    "kind": action.kind.value,
                    "ea": action.ea,
                    "expected_before": action.expected_before,
                    "expected_after": action.expected_after,
                }
                for operation in plan.operations
                for action in operation.metadata_actions
            ],
        }
        self._certificate_store.set_native_patch_blob(
            "native_patch_diagnostic_snapshot", snapshot_id, payload
        )
        return snapshot_id

    def record_certificate_validation_receipt(
        self, plan: NativePatchPlan, certificate: NativeCertificate | None
    ) -> str:
        """Persist the no-rerun validation verdict as its own evidence item."""
        receipt_id = uuid4().hex
        self._certificate_store.set_native_patch_blob(
            "native_patch_preflight_receipt",
            receipt_id,
            {
                "kind": "certificate_validation",
                "plan_id": plan.plan_id,
                "plan_hash": plan.plan_hash,
                "certificate_id": (
                    None if certificate is None else certificate.certificate_id
                ),
            },
        )
        return receipt_id

    def record_native_cfg_postcondition_receipt(
        self,
        *,
        plan: NativePatchPlan,
        certificate: NativeCertificate,
        transaction_id: NativePatchTransactionId,
        observed_native_cfg_fingerprint: str,
        live_flowchart_fingerprint: str,
    ) -> tuple[str, NativeCertificate]:
        """Persist Stage C's recaptured whole-function native CFG witness.

        The expected fingerprint was frozen from the target microcode graph;
        the observed fingerprint comes from the live IDA flowchart's anchor
        quotient.  Keeping both prevents an intended target hash from being
        mistaken for evidence that the resulting native graph was observed.
        """
        if certificate.target_cfg_fingerprint != plan.target_cfg_fingerprint:
            raise ValueError("certificate target CFG does not match the Stage C plan")
        if observed_native_cfg_fingerprint != plan.target_cfg_fingerprint:
            raise ValueError("observed native CFG does not match the frozen target")
        record = self._journal.get(transaction_id)
        if record is None:
            raise ValueError("Stage C transaction is missing")
        self._require_current_database(record)
        if record.plan_id != plan.plan_id or record.plan_hash != plan.plan_hash:
            raise ValueError("Stage C transaction does not own this plan")
        if record.state is not NativeJournalState.POSTCONDITION_PENDING:
            raise ValueError(
                "Stage C postcondition requires a POSTCONDITION_PENDING transaction"
            )
        link = self._certificate_store.get_native_patch_blob(
            "certificate_transaction", transaction_id.value
        )
        if link is None or link.get("certificate_id") != certificate.certificate_id:
            raise ValueError("Stage C transaction certificate link is missing")
        key = link.get("certificate_key")
        if not isinstance(key, str):
            raise ValueError("Stage C transaction certificate key is malformed")
        current_payload = self._certificate_store.get_native_patch_blob(
            "certificate", key
        )
        if current_payload is None:
            raise ValueError("Stage C certificate is missing")
        current = certificate_from_payload(current_payload)
        if current.certificate_id != certificate.certificate_id:
            raise ValueError("Stage C certificate slot changed during validation")

        receipt_id = uuid4().hex
        self._certificate_store.set_native_patch_blob(
            "native_cfg_postcondition_receipt",
            receipt_id,
            {
                "kind": "whole_function_native_cfg_postcondition",
                "transaction_id": transaction_id.value,
                "certificate_id": certificate.certificate_id,
                "plan_id": plan.plan_id,
                "expected_native_cfg_fingerprint": plan.target_cfg_fingerprint,
                "observed_native_cfg_fingerprint": observed_native_cfg_fingerprint,
                "live_flowchart_fingerprint": live_flowchart_fingerprint,
            },
        )
        updated = replace(
            current,
            schema_version=max(3, current.schema_version),
            observed_native_cfg_fingerprint=observed_native_cfg_fingerprint,
        )
        self._certificate_store.set_native_patch_blob(
            "certificate", key, certificate_to_payload(updated)
        )
        self._journal.transition(transaction_id, NativeJournalState.CERTIFIED)
        return receipt_id, updated

    def _record_preflight_receipt(
        self,
        plan: NativePatchPlan,
        transaction_id: NativePatchTransactionId,
        preflight: PlanPreflightResult,
    ) -> str:
        """Persist the actual live preflight verdict separately from the plan."""
        receipt_id = uuid4().hex
        self._certificate_store.set_native_patch_blob(
            "native_patch_preflight_receipt",
            receipt_id,
            {
                "kind": "live_preflight",
                "transaction_id": transaction_id.value,
                "plan_id": plan.plan_id,
                "plan_hash": plan.plan_hash,
                "authorized": preflight.authorized,
                "operation_results": [
                    {
                        "operation_id": result.operation_id,
                        "authorized": result.ok,
                        "rejection_reasons": list(result.rejection_reasons),
                    }
                    for result in preflight.operation_results
                ],
            },
        )
        return receipt_id

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
        self,
        plan: NativePatchPlan,
        record: NativePatchTransactionRecord,
        *,
        phase_witness: AnalysisPhaseWitness | None = None,
    ) -> NativeCertificate:
        normalized_fingerprint = self._recapture_fingerprint(
            plan, record.transaction_id
        )
        final_actions: dict[tuple[str, int], str] = {}
        for operation in plan.operations:
            for action in operation.metadata_actions:
                final_actions[(action.kind.value, int(action.ea))] = action.expected_after
        phase_schema = 3
        if plan.analysis_phase_witness is not None:
            phase_payload = phase_witness or self._parse_analysis_phase_witness(plan)
            phase_postconditions = {
                (
                    str(NativeMetadataActionKind.RECREATE_ITEM.value),
                    int(row["ea"]),
                ): str(row["state"])
                for group in phase_payload["groups"]
                for row in group["postconditions"]
            }
            final_actions.update(phase_postconditions)
            phase_schema = 4
        postconditions = tuple(
            (kind, ea, state)
            for (kind, ea), state in sorted(final_actions.items())
        )
        authorization_hash = None
        attestation_hash = None
        attestation_locator = None
        if plan.analysis_phase_witness is not None:
            authorization_hash = hashlib.sha256(
                plan.analysis_phase_witness.encode()
            ).hexdigest()
            attestation_token = self._journal.analysis_phase_attestation(
                record.transaction_id
            )
            if attestation_token is None:
                raise NativePatchCertificationFailed(
                    record.transaction_id,
                    "observed analysis-phase attestation is missing",
                )
            attestation_hash = hashlib.sha256(attestation_token.encode()).hexdigest()
            attestation_locator = record.transaction_id.value
        return NativeCertificate(
            certificate_id=uuid4().hex,
            schema_version=phase_schema,
            database_identity=plan.database_identity,
            function_identity=plan.function_identity,
            inherited_fingerprint=plan.inherited_function_fingerprint,
            normalized_fingerprint=normalized_fingerprint,
            target_cfg_fingerprint=plan.target_cfg_fingerprint,
            native_origin_map_fingerprint=plan.native_origin_map_fingerprint,
            semantic_plan_hash=plan.proof_hash,
            native_plan_hash=plan.plan_hash,
            metadata_target_fingerprint=plan.metadata_target_fingerprint,
            d810_version=self._d810_version,
            authorization_class=plan.patch_class,
            state=NativeCertificateState.APPLIED,
            certified_at=time.time(),
            metadata_postconditions=postconditions,
            analysis_phase_witness=plan.analysis_phase_witness,
            analysis_phase_authorization_hash=authorization_hash,
            analysis_phase_attestation_hash=attestation_hash,
            analysis_phase_attestation_locator=attestation_locator,
        )

    def _recapture_fingerprint(
        self, plan: NativePatchPlan, transaction_id: NativePatchTransactionId
    ) -> str:
        """Section 15.1.1 points 1-4: recapture from current bytes, fail
        unconditionally on any byte whose loaded state changed, and require
        a journaled operation for every changed byte (reusing the existing
        ``classify_recovery`` corroboration check rather than re-deriving
        it)."""
        try:
            return self._current_normalized_fingerprint(plan)
        except ValueError as error:
            raise NativePatchCertificationFailed(transaction_id, str(error)) from error

    def _current_normalized_fingerprint(self, plan: NativePatchPlan) -> str:
        """Fingerprint the live normalized byte image without trusting a plan.

        Certificate reuse invokes this same read-only capture.  A certificate
        is therefore invalidated by a byte divergence even when its original
        byte anchor was intentionally unchanged by a metadata-only operation.
        Metadata plans never write function bytes, so their certificate can
        and must attest the complete owning-function byte image instead of
        only the operation's immutable anchor.
        """
        if any(operation.metadata_actions for operation in plan.operations):
            ranges = plan.function_identity.chunk_ranges
        else:
            ranges = tuple(operation.range for operation in plan.operations)

        pieces: list[tuple[int, int, bytes]] = []
        for address_range in ranges:
            current = self._reader.read_current_bytes(
                address_range.start_ea, address_range.end_ea
            )
            if current is None:
                raise ValueError(
                    "certificate range "
                    f"{address_range.start_ea:#x}-{address_range.end_ea:#x} "
                    "became unloaded"
                )
            pieces.append((address_range.start_ea, address_range.end_ea, current))
        return hashlib.sha256(repr(tuple(pieces)).encode("utf-8")).hexdigest()

    def certificate_matches_current(
        self, plan: NativePatchPlan, certificate: NativeCertificate
    ) -> bool:
        """Verify the certificate's live byte and owned-metadata witnesses."""
        if certificate.normalized_fingerprint != self._current_normalized_fingerprint(
            plan
        ):
            return False
        if certificate.metadata_target_fingerprint != plan.metadata_target_fingerprint:
            return False
        if (
            plan.issuer_id == "stage-c-native-cfg-normalizer"
            and certificate.observed_native_cfg_fingerprint
            != plan.target_cfg_fingerprint
        ):
            return False
        has_metadata = any(op.metadata_actions for op in plan.operations)
        if not has_metadata:
            return True
        if certificate.schema_version != 3:
            if not (
                plan.analysis_phase_witness is not None
                and certificate.schema_version == 4
                and certificate.analysis_phase_witness
                == plan.analysis_phase_witness
            ):
                return False
        if certificate.schema_version == 4:
            if plan.analysis_phase_witness is None:
                return False
            authorization_hash = hashlib.sha256(
                plan.analysis_phase_witness.encode()
            ).hexdigest()
            if certificate.analysis_phase_authorization_hash != authorization_hash:
                return False
            locator = certificate.analysis_phase_attestation_locator
            if not isinstance(locator, str) or not locator:
                return False
            linked_transaction = self._journal.get(
                NativePatchTransactionId(locator)
            )
            if linked_transaction is None:
                return False
            if linked_transaction.state is not NativeJournalState.CERTIFIED:
                return False
            if linked_transaction.database_identity != plan.database_identity.idb_uuid:
                return False
            if (
                linked_transaction.plan_hash != plan.plan_hash
                or certificate.native_plan_hash != plan.plan_hash
                or certificate.database_identity != plan.database_identity
            ):
                return False
            link_reader = getattr(self._journal, "certificate_link", None)
            link = link_reader(NativePatchTransactionId(locator)) if callable(link_reader) else None
            expected_database_key = self._certificate_key(
                plan.function_identity.entry_ea, plan.database_identity
            )
            expected_function_key = json.dumps(
                {
                    "entry_ea": plan.function_identity.entry_ea,
                    "chunk_ranges": [
                        [row.start_ea, row.end_ea]
                        for row in plan.function_identity.chunk_ranges
                    ],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            if link != {
                "certificate_id": certificate.certificate_id,
                "plan_hash": plan.plan_hash,
                "database_key": expected_database_key,
                "function_key": expected_function_key,
            }:
                return False
            attestation_token = self._journal.analysis_phase_attestation(
                NativePatchTransactionId(locator)
            )
            if attestation_token is None or certificate.analysis_phase_attestation_hash != hashlib.sha256(
                attestation_token.encode()
            ).hexdigest():
                return False
            try:
                attestation = parse_analysis_phase_attestation(attestation_token)
                if attestation.transaction_id != locator:
                    return False
                if attestation.phase_witness.token != plan.analysis_phase_witness:
                    return False
                phase = parse_analysis_phase_witness(plan.analysis_phase_witness)
                if self._live_phase_global_state(phase) != attestation.observed_state:
                    return False
            except (PhaseWitnessError, MetadataStateMismatch):
                return False
        if certificate.analysis_phase_authorization_hash is not None:
            if plan.analysis_phase_witness is None or hashlib.sha256(
                plan.analysis_phase_witness.encode()
            ).hexdigest() != certificate.analysis_phase_authorization_hash:
                return False
        if certificate.schema_version == 4 and certificate.analysis_phase_attestation_hash is None:
            return False
        if self._metadata_executor is None:
            return False
        if certificate.analysis_phase_witness is not None:
            try:
                phase = parse_analysis_phase_witness(certificate.analysis_phase_witness)
                self._verify_phase_partition(
                    phase, items_field="after_items", xrefs_field="after_xrefs"
                )
            except (PhaseWitnessError, MetadataStateMismatch):
                return False
        try:
            if not certificate.metadata_postconditions:
                return False
            for kind_name, ea, expected_after in certificate.metadata_postconditions:
                if (
                    self._metadata_executor.read_state(
                        NativeMetadataActionKind(kind_name),
                        ea,
                        scope_state=_metadata_scope_hint(expected_after),
                    )
                    != expected_after
                ):
                    return False
        except Exception:
            return False
        return True

    def _store_certificate(
        self,
        plan: NativePatchPlan,
        certificate: NativeCertificate,
        transaction_id: NativePatchTransactionId,
    ) -> None:
        key = self._certificate_key(
            plan.function_identity.entry_ea, plan.database_identity
        )
        # Write the transaction link first.  If the second write or the
        # following CERTIFIED transition is interrupted, startup recovery can
        # find and revoke any partial certificate instead of leaving an
        # orphaned applied certificate after rolling back the overlay.
        self._certificate_store.set_native_patch_blob(
            "certificate_transaction",
            transaction_id.value,
            {"certificate_key": key, "certificate_id": certificate.certificate_id},
        )
        self._certificate_store.set_native_patch_blob(
            "certificate", key, certificate_to_payload(certificate)
        )
        database_key = key
        function_key = json.dumps(
            {
                "entry_ea": plan.function_identity.entry_ea,
                "chunk_ranges": [
                    [row.start_ea, row.end_ea]
                    for row in plan.function_identity.chunk_ranges
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        self._journal.record_certificate_link(
            transaction_id,
            certificate.certificate_id,
            certificate.native_plan_hash,
            database_key,
            function_key,
        )

    def _revoke_certificate(self, transaction_id: NativePatchTransactionId) -> bool:
        """Remove only the certificate produced by this restored transaction."""
        link = self._certificate_store.get_native_patch_blob(
            "certificate_transaction", transaction_id.value
        )
        if link is None:
            return True
        key = link.get("certificate_key")
        certificate_id = link.get("certificate_id")
        if not isinstance(key, str) or not isinstance(certificate_id, str):
            return False
        current = self._certificate_store.get_native_patch_blob("certificate", key)
        if current is not None:
            try:
                current_certificate = certificate_from_payload(current)
            except Exception:
                return False
            # A newer normalization at the same function replaced this
            # transaction's certificate; restoring the older transaction may
            # not revoke that newer independent certification.
            if current_certificate.certificate_id == certificate_id:
                self._certificate_store.clear_native_patch_blob("certificate", key)
        self._certificate_store.clear_native_patch_blob(
            "certificate_transaction", transaction_id.value
        )
        return True

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
        try:
            certificate = certificate_from_payload(payload)
        except Exception:
            # A certificate written by an older schema cannot authorize a
            # metadata mutation.  Treat it as absent so the request goes
            # through fresh preflight rather than crashing or trusting a
            # payload without the current-state witness.
            logger.warning("ignoring malformed or obsolete native certificate")
            return None
        if certificate.schema_version not in {2, 3, 4}:
            logger.warning(
                "ignoring obsolete native certificate schema %s",
                certificate.schema_version,
            )
            return None
        return certificate

    # ------------------------------------------------------------------
    # Explicit restore (section 15.3)
    # ------------------------------------------------------------------

    def restore(
        self,
        transaction_id: NativePatchTransactionId,
        *,
        acknowledge_recovery_required: bool = False,
    ) -> NativeRestoreReceipt:
        """Restore or resume one transaction's durable restore lane.

        A restore is idempotent at the byte and metadata primitives.  The
        journal nevertheless records the byte-restored cut point so a restart
        knows whether it is resuming the reversal or its post-restore
        analysis/redo reconciliation. ``RECOVERY_REQUIRED`` remains read-only
        until an operator explicitly acknowledges a retry.
        """
        record = self._journal.get(transaction_id)
        if record is None:
            raise ValueError(f"unknown transaction {transaction_id.value}")
        self._require_current_database(record)
        if record.state is NativeJournalState.RECOVERY_REQUIRED:
            if not acknowledge_recovery_required:
                return NativeRestoreReceipt(
                    transaction_id=transaction_id,
                    state=record.state,
                    restored_eas=(),
                    interference_eas=(),
                    failure_reason="explicit acknowledgement required before retry",
                )
            record = self._journal.transition(
                transaction_id,
                NativeJournalState.RESTORING,
                note="operator acknowledged restore reconciliation retry",
            )
        elif record.state is NativeJournalState.RESTORE_FAILED:
            record = self._journal.transition(
                transaction_id,
                NativeJournalState.RESTORING,
                note="retrying a failed restore",
            )
        elif record.state is NativeJournalState.CERTIFIED:
            record = self._journal.transition(
                transaction_id, NativeJournalState.RESTORING
            )
        elif record.state is NativeJournalState.POSTCONDITION_PENDING:
            record = self._journal.transition(
                transaction_id,
                NativeJournalState.RESTORING,
                note="Stage C postcondition failed; restoring pending overlay",
            )
        elif record.state is NativeJournalState.ANALYSIS_RECONCILED:
            # Resume from the durable post-analysis cut below.  No lifecycle
            # operation may run again before the origin proof.
            pass
        elif record.state not in {
            NativeJournalState.RESTORING,
            NativeJournalState.RESTORE_BYTES_RESTORED,
            NativeJournalState.ANALYSIS_RECONCILED,
        }:
            raise NativePatchRestoreNotCertified(record.state)

        restored_eas: tuple[int, ...] = ()
        if record.state is NativeJournalState.RESTORING:
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
            except Exception as error:
                return self._restore_failed(
                    transaction_id,
                    restored_eas=(),
                    reason=f"a byte write during restore raised: {error}",
                )
            record = self._journal.transition(
                transaction_id,
                NativeJournalState.RESTORE_BYTES_RESTORED,
                note="restore byte image reconciled",
            )

        if record.state is NativeJournalState.ANALYSIS_RECONCILED:
            try:
                phase = self._phase_witness_for_transaction(transaction_id)
                if phase is not None:
                    self._verify_phase_origin(phase)
                certificate_revoked = self._revoke_certificate(transaction_id)
            except Exception as error:
                return self._restore_failed(
                    transaction_id,
                    restored_eas=restored_eas,
                    reason=f"analysis reconciliation cut verification raised: {error}",
                )
            if not certificate_revoked:
                record = self._journal.transition(
                    transaction_id,
                    NativeJournalState.RECOVERY_REQUIRED,
                    note="database restored but applied certificate could not be revoked",
                )
                return NativeRestoreReceipt(
                    transaction_id=transaction_id,
                    state=record.state,
                    restored_eas=restored_eas,
                    interference_eas=(),
                    controlled_redo_function_eas=self._function_eas_for_transaction(transaction_id),
                )
            record = self._journal.transition(
                transaction_id, NativeJournalState.RESTORED,
                note="explicit restore resumed after analysis reconciliation",
            )
            return NativeRestoreReceipt(
                transaction_id=transaction_id,
                state=record.state,
                restored_eas=restored_eas,
                interference_eas=(),
                controlled_redo_function_eas=self._function_eas_for_transaction(transaction_id),
            )

        # Closure-bearing plans are metadata-only.  Their exact inverse is
        # authorized directly from observed P and must not be preceded by a
        # fresh analysis/redo pass that can rematerialize the closure.
        phase_only = self._phase_witness_for_transaction(transaction_id)
        if phase_only is not None:
            try:
                # Reconcile the owning function lifecycle while the exact P
                # closure still exists.  No inverse mutation is permitted
                # until this pass completes and P is reread unchanged.
                phase_state = self._analysis_phase_state(transaction_id, phase_only)
                if phase_state not in {"P", "R_i", "cleared-mid-carrier"}:
                    raise MetadataStateMismatch(
                        "analysis-phase", 0, "exact post-analysis state", "drift"
                    )
                lifecycle_functions = self._function_eas_for_transaction(
                    transaction_id
                )
                ownership_failures = self._restore_function_extents(transaction_id)
                if ownership_failures:
                    raise MetadataStateMismatch(
                        "analysis-phase", 0,
                        "pre-inverse function ownership", ownership_failures,
                    )
                if phase_state == "P":
                    for function_ea in lifecycle_functions:
                        reanalyze_and_wait(function_ea, reanalyzer=self._reanalyzer)
                        invalidate_target_and_callers(
                            function_ea,
                            invalidator=self._cache_invalidator,
                            discovery=self._caller_discovery,
                        )
                        controlled_redo(function_ea, decompiler=self._redo_decompiler)
                    if self._analysis_phase_state(transaction_id, phase_only) != "P":
                        raise MetadataStateMismatch(
                            "analysis-phase", 0, "stable post-analysis state", "drift"
                        )
                else:
                    self._verify_reverse_cursor_global_state(
                        transaction_id,
                        phase_only,
                        self._journal.analysis_reverse_steps(transaction_id),
                    )
                unreversed_metadata = self._reverse_metadata_actions(transaction_id)
                if unreversed_metadata:
                    record = self._journal.transition(
                        transaction_id,
                        NativeJournalState.RECOVERY_REQUIRED,
                        note=f"phase inverse failed: {unreversed_metadata}",
                    )
                    return NativeRestoreReceipt(
                        transaction_id=transaction_id,
                        state=record.state,
                        restored_eas=restored_eas,
                        interference_eas=(),
                        failure_reason=";".join(unreversed_metadata),
                    )
                post_extent_failures = self._restore_function_extents(transaction_id)
                post_flow_failures = self._restore_function_flow_refs(transaction_id)
                if post_extent_failures or post_flow_failures:
                    raise MetadataStateMismatch(
                        "analysis-phase", 0, "post-inverse lifecycle", (
                            post_extent_failures, post_flow_failures
                        )
                    )
                for function_ea in self._function_eas_for_transaction(transaction_id):
                    invalidate_target_and_callers(
                        function_ea,
                        invalidator=self._cache_invalidator,
                        discovery=self._caller_discovery,
                    )
                self._journal.transition(
                    transaction_id,
                    NativeJournalState.ANALYSIS_RECONCILED,
                    note="metadata-only phase inverse reconciled without reanalysis",
                )
                self._verify_phase_origin(phase_only)
                if not self._revoke_certificate(transaction_id):
                    raise RuntimeError("applied certificate could not be revoked")
                record = self._journal.transition(
                    transaction_id,
                    NativeJournalState.RESTORED,
                    note="metadata-only phase restore complete",
                )
                return NativeRestoreReceipt(
                    transaction_id=transaction_id,
                    state=record.state,
                    restored_eas=restored_eas,
                    interference_eas=(),
                    controlled_redo_function_eas=(),
                )
            except Exception as error:
                return self._restore_failed(
                    transaction_id,
                    restored_eas=restored_eas,
                    reason=f"metadata-only phase restore raised: {error}",
                )

        # Re-establish the pre-patch function extent BEFORE reanalysis.
        #
        # Order matters. Restoring bytes is not restoring state: erasing a
        # branch orphans its target block, IDA shrinks the owning function,
        # and reanalysis cannot undo that because reanalysis is what did it.
        # The remembered extent has to be asserted first, so the subsequent
        # reanalyze+invalidate runs over the whole restored function rather
        # than the truncated one.
        try:
            # Defer the exact phase inverse until after the final lifecycle
            # pass.  Reanalysis may decode restored bytes back into transient
            # code items; carrier deletion must be the last operation that
            # can remove those items.
            unreversed_metadata: tuple[str, ...] = ()
            unrestored_extents = self._restore_function_extents(transaction_id)

            reanalyzed_function_eas = self._function_eas_for_transaction(transaction_id)
            for function_ea in reanalyzed_function_eas:
                reanalyze_and_wait(function_ea, reanalyzer=self._reanalyzer)

            unrestored_extents = tuple(
                dict.fromkeys(
                    unrestored_extents + self._restore_function_extents(transaction_id)
                )
            )

            # Keep the journaled flow graph at the exact sealed phase while
            # the carrier inverse runs.  Restoring original flow refs here
            # would make the live state neither P nor an authorized R_i cut;
            # apply that final origin reconciliation after carrier recreation.
            unrestored_flow_refs: tuple[str, ...] = (
                ()
                if self._phase_witness_for_transaction(transaction_id) is not None
                else self._restore_function_flow_refs(transaction_id)
            )
            for function_ea in reanalyzed_function_eas:
                invalidate_target_and_callers(
                    function_ea,
                    invalidator=self._cache_invalidator,
                    discovery=self._caller_discovery,
                )
                controlled_redo(function_ea, decompiler=self._redo_decompiler)

            # Decompilation itself may persist a guessed prototype after the
            # pre-redo snapshot was restored. Reconcile the authoritative
            # journal snapshot once more at the true end of the lifecycle,
            # then invalidate any cfunc built against the transient metadata.
            unrestored_extents = tuple(
                dict.fromkeys(
                    unrestored_extents + self._restore_function_extents(transaction_id)
                )
            )
            for function_ea in reanalyzed_function_eas:
                invalidate_target_and_callers(
                    function_ea,
                    invalidator=self._cache_invalidator,
                    discovery=self._caller_discovery,
                )

            unreversed_metadata = self._reverse_metadata_actions(transaction_id)
            if not unreversed_metadata:
                unrestored_flow_refs = self._restore_function_flow_refs(transaction_id)

            # This is the last lifecycle operation.  Persist the cut before
            # reading the final origin witness so a crash cannot repeat
            # analysis/redo after the exact inverse has been established.
            if not unreversed_metadata and not unrestored_flow_refs:
                self._journal.transition(
                    transaction_id,
                    NativeJournalState.ANALYSIS_RECONCILED,
                    note="restore lifecycle reconciliation complete",
                )

                # The inverse is not complete until every phase carrier has
                # been reread as its exact original data snapshot after the
                # final reanalysis/redo cycle.
                phase = self._phase_witness_for_transaction(transaction_id)
                if phase is not None:
                    self._verify_phase_origin(phase)
        except Exception as error:
            return self._restore_failed(
                transaction_id,
                restored_eas=restored_eas,
                reason=f"restore lifecycle reconciliation raised: {error}",
            )

        if unreversed_metadata or unrestored_extents or unrestored_flow_refs:
            # Bytes are back but the database shape is not. Say so rather than
            # reporting RESTORED: a caller that trusts this receipt would
            # believe a half-restored database is clean.
            record = self._journal.transition(
                transaction_id,
                NativeJournalState.RECOVERY_REQUIRED,
                note=(
                    "bytes restored but database shape was not: "
                    f"unreversed metadata {unreversed_metadata}, "
                    f"unrestored extents {unrestored_extents}, "
                    f"unrestored flow refs {unrestored_flow_refs}"
                ),
            )
            return NativeRestoreReceipt(
                transaction_id=transaction_id,
                state=record.state,
                restored_eas=restored_eas,
                interference_eas=(),
                controlled_redo_function_eas=reanalyzed_function_eas,
            )

        try:
            certificate_revoked = self._revoke_certificate(transaction_id)
        except Exception:
            certificate_revoked = False
        if not certificate_revoked:
            record = self._journal.transition(
                transaction_id,
                NativeJournalState.RECOVERY_REQUIRED,
                note="database restored but applied certificate could not be revoked",
            )
            return NativeRestoreReceipt(
                transaction_id=transaction_id,
                state=record.state,
                restored_eas=restored_eas,
                interference_eas=(),
                controlled_redo_function_eas=reanalyzed_function_eas,
            )

        record = self._journal.transition(
            transaction_id, NativeJournalState.RESTORED, note="explicit restore"
        )
        return NativeRestoreReceipt(
            transaction_id=transaction_id,
            state=record.state,
            restored_eas=restored_eas,
            interference_eas=(),
            controlled_redo_function_eas=reanalyzed_function_eas,
        )

    def _verify_phase_origin(self, phase: AnalysisPhaseWitness) -> None:
        assert self._metadata_executor is not None
        for group in phase.groups:
            origin = _parse_reversible_data_item_state(group.origin_data_state)
            if origin is None:
                raise MetadataStateMismatch(
                    "analysis-phase", 0, "valid origin data", group.origin_data_state
                )
            origin_ea = int(origin["ea"])
            observed = self._metadata_executor.read_state(
                NativeMetadataActionKind.RECREATE_ITEM, origin_ea
            )
            if observed != group.origin_data_state:
                raise MetadataStateMismatch(
                    "analysis-phase", origin_ea, group.origin_data_state, observed
                )

    def _restore_failed(
        self,
        transaction_id: NativePatchTransactionId,
        *,
        restored_eas: tuple[int, ...],
        reason: str,
    ) -> NativeRestoreReceipt:
        """Durably expose a restore cut-point failure for startup retry."""
        record = self._journal.transition(
            transaction_id,
            NativeJournalState.RESTORE_FAILED,
            note=reason,
        )
        return NativeRestoreReceipt(
            transaction_id=transaction_id,
            state=record.state,
            restored_eas=restored_eas,
            interference_eas=(),
            failure_reason=reason,
        )

    def _restore_function_extents(
        self, transaction_id: NativePatchTransactionId
    ) -> tuple[str, ...]:
        """Reassert every remembered function ownership snapshot.

        Ownership comes from the journal, never from a live read: by this
        point the database reflects the *patched* shape, which is exactly what
        is being undone. One function can own several operations; each
        distinct (entry, end) is asserted once.
        """
        expected_by_function, failed = self._journaled_function_ownership(
            transaction_id
        )
        for entry_ea, ownership in sorted(expected_by_function.items()):
            try:
                ok = self._extent_restorer.restore_function_ownership(ownership)
            except Exception:
                ok = False
            if not ok:
                failed.append(f"{entry_ea:#x}")
        return tuple(failed)

    def _journaled_function_ownership(
        self, transaction_id: NativePatchTransactionId
    ) -> tuple[dict[int, NativeFunctionOwnership], list[str]]:
        ownership_rows = self._journal.operation_ownership(transaction_id)
        flow_rows = self._journal.operation_flow_refs(transaction_id)
        metadata_rows = self._journal.operation_function_metadata(transaction_id)
        expected_by_function: dict[int, NativeFunctionOwnership] = {}
        inconsistent: list[str] = []
        for operation_id, (entry_ea, chunks) in ownership_rows.items():
            metadata = metadata_rows.get(operation_id)
            if metadata is None:
                inconsistent.append(f"{entry_ea:#x}:missing_function_metadata")
                continue
            function_flags, serialized_type = metadata
            type_info = None
            if serialized_type is not None:
                type_info = NativeFunctionTypeInfo(
                    type_bytes=serialized_type[0],
                    field_bytes=serialized_type[1],
                    field_comment_bytes=serialized_type[2],
                )
            ownership = NativeFunctionOwnership(
                owning_function_entry_ea=entry_ea,
                chunk_ranges=tuple(
                    NativeAddressRange(start_ea, end_ea) for start_ea, end_ea in chunks
                ),
                flow_refs=tuple(
                    NativeFunctionFlowRef(source, target, xref_type, user)
                    for source, target, xref_type, user in flow_rows.get(
                        operation_id, ()
                    )
                ),
                function_flags=function_flags,
                type_info=type_info,
            )
            previous = expected_by_function.get(entry_ea)
            if previous is not None and previous != ownership:
                inconsistent.append(f"{entry_ea:#x}:inconsistent_snapshot")
                continue
            expected_by_function[entry_ea] = ownership
        return expected_by_function, inconsistent

    def _restore_function_flow_refs(
        self, transaction_id: NativePatchTransactionId
    ) -> tuple[str, ...]:
        """Reconcile exact pre-patch internal code refs from the journal."""
        expected_by_function, inconsistent = self._journaled_function_ownership(
            transaction_id
        )

        failed = list(inconsistent)
        for entry_ea, ownership in sorted(expected_by_function.items()):
            try:
                ok = self._flow_restorer.restore_function_flow_refs(ownership)
            except Exception:
                ok = False
            if not ok:
                failed.append(f"{entry_ea:#x}")
        return tuple(failed)

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
        seen: dict[int, None] = {}
        for entry_ea, _chunks in self._journal.operation_ownership(
            transaction_id
        ).values():
            seen[int(entry_ea)] = None
        return tuple(seen.keys())

    # ------------------------------------------------------------------
    # Recovery -- section 15.4 ("Recovery on plugin load or IDB open").
    # ------------------------------------------------------------------

    def recover(self, transaction_id: NativePatchTransactionId) -> None:
        """Classify and reconcile one interrupted transaction.

        Public entry point for startup recovery
        (``d810.manager.native_normalization``'s job is to enumerate which
        transaction ids need this, typically every transaction this
        process's journal knows about that is not already ``RESTORED``,
        ``RESTORE_FAILED``, or ``RECOVERY_REQUIRED``). Identical logic to
        the exception path inside :meth:`apply` -- see
        :meth:`_emergency_recover`.
        """
        record = self._journal.get(transaction_id)
        if record is None:
            return
        self._require_current_database(record)
        if record.state is NativeJournalState.RESTORED:
            return
        if record.state in {
            NativeJournalState.RESTORING,
            NativeJournalState.RESTORE_BYTES_RESTORED,
            NativeJournalState.ANALYSIS_RECONCILED,
            NativeJournalState.RESTORE_FAILED,
        }:
            self.restore(transaction_id)
            return
        # RECOVERY_REQUIRED is deliberately not auto-written: its explicit
        # acknowledgement is the caller's authority to retry a restore after
        # an interference or certificate-revocation failure.
        if record.state is NativeJournalState.RECOVERY_REQUIRED:
            return
        self._emergency_recover(transaction_id)

    def _emergency_recover_phase(
        self,
        transaction_id: NativePatchTransactionId,
        phase: AnalysisPhaseWitness,
    ) -> bool:
        """Recover a phase transaction with the same ordered lifecycle as restore.

        This lane is entered only after the journal has classified the live
        state as P, an exact R_i cut, or a durable cleared carrier intent.
        Ownership is journal authority; after the inverse starts, no analysis
        operation is allowed to run again.
        """
        phase_state = self._analysis_phase_state(transaction_id, phase)
        if phase_state not in {"P", "R_i", "cleared-mid-carrier"}:
            self._journal.transition(
                transaction_id,
                NativeJournalState.RECOVERY_REQUIRED,
                note=f"phase recovery state is {phase_state}",
            )
            return False
        function_eas = self._function_eas_for_transaction(transaction_id)
        # Every accepted post-analysis cut must begin by reasserting the
        # journaled ownership/flags/type snapshot.  R_i and cleared cuts do
        # not need fresh analysis, but they still need the same ownership
        # authority before their remaining inverse can mutate metadata.
        ownership_failures = self._restore_function_extents(transaction_id)
        if ownership_failures:
            self._journal.transition(
                transaction_id,
                NativeJournalState.RECOVERY_REQUIRED,
                note=f"phase ownership restore failed: {ownership_failures}",
            )
            return False
        if phase_state == "P":
            try:
                for function_ea in function_eas:
                    reanalyze_and_wait(function_ea, reanalyzer=self._reanalyzer)
                    invalidate_target_and_callers(
                        function_ea,
                        invalidator=self._cache_invalidator,
                        discovery=self._caller_discovery,
                    )
                    controlled_redo(function_ea, decompiler=self._redo_decompiler)
            except Exception as error:
                self._journal.transition(
                    transaction_id,
                    NativeJournalState.RECOVERY_REQUIRED,
                    note=f"phase lifecycle reconciliation failed: {error}",
                )
                return False
            if self._analysis_phase_state(transaction_id, phase) != "P":
                self._journal.transition(
                    transaction_id,
                    NativeJournalState.RECOVERY_REQUIRED,
                    note="phase P drifted before inverse",
                )
                return False
        failures = self._reverse_metadata_actions(transaction_id)
        if failures:
            self._journal.transition(
                transaction_id,
                NativeJournalState.RECOVERY_REQUIRED,
                note=f"phase inverse failed: {failures}",
            )
            return False
        self._journal.transition(
            transaction_id,
            NativeJournalState.ANALYSIS_RECONCILED,
            note="phase inverse completed before flow restoration",
        )
        flow_failures = self._restore_function_flow_refs(transaction_id)
        for function_ea in function_eas:
            try:
                invalidate_target_and_callers(
                    function_ea,
                    invalidator=self._cache_invalidator,
                    discovery=self._caller_discovery,
                )
            except Exception as error:
                flow_failures = tuple(flow_failures) + (str(error),)
        if flow_failures:
            self._journal.transition(
                transaction_id,
                NativeJournalState.RECOVERY_REQUIRED,
                note=f"phase flow restoration failed: {flow_failures}",
            )
            return False
        try:
            self._verify_phase_origin(phase)
        except Exception as error:
            self._journal.transition(
                transaction_id,
                NativeJournalState.RECOVERY_REQUIRED,
                note=f"phase origin verification failed: {error}",
            )
            return False
        self._journal.transition(
            transaction_id,
            NativeJournalState.RESTORED,
            note="phase apply failure recovered",
        )
        return True

    def _emergency_recover(self, transaction_id: NativePatchTransactionId) -> None:
        record = self._journal.get(transaction_id)
        if record is None:
            return
        self._require_current_database(record)
        if record.state in _TERMINAL_STATES:
            return

        if record.state in {
            NativeJournalState.CERTIFICATE_PENDING,
            NativeJournalState.POSTCONDITION_PENDING,
        }:
            try:
                certificate_revoked = self._revoke_certificate(transaction_id)
            except Exception:
                certificate_revoked = False
            if not certificate_revoked:
                self._journal.transition(
                    transaction_id,
                    NativeJournalState.RECOVERY_REQUIRED,
                    note="certificate persistence interrupted; certificate cleanup failed",
                )
                return

        phase = self._phase_witness_for_transaction(transaction_id)
        attestation_reader = getattr(self._journal, "analysis_phase_attestation", None)
        durable_auth = self._journal.analysis_phase_witness(transaction_id)
        if (
            durable_auth is not None
            and durable_auth.startswith("analysis-phase:v4:")
            and callable(attestation_reader)
            and attestation_reader(transaction_id) is None
        ):
            self._journal.transition(
                transaction_id,
                NativeJournalState.RECOVERY_REQUIRED,
                note="phase recovery requires a durable observed attestation",
            )
            return
        if phase is not None and self._analysis_phase_state(
            transaction_id, phase
        ) in {"P", "R_i", "cleared-mid-carrier"}:
            if record.state is not NativeJournalState.ROLLING_BACK:
                record = self._journal.transition(
                    transaction_id,
                    NativeJournalState.ROLLING_BACK,
                    note="phase apply failure entering ordered inverse lane",
                )
            self._emergency_recover_phase(transaction_id, phase)
            return

        unreversed_metadata = self._reverse_metadata_actions(transaction_id)
        if unreversed_metadata:
            self._journal.transition(
                transaction_id,
                NativeJournalState.RECOVERY_REQUIRED,
                note=f"apply failed; metadata reversal incomplete: {unreversed_metadata}",
            )
            return

        recovery = self._journal.classify_recovery(
            transaction_id, self._read_current_byte
        )

        # Metadata-only plans carry unchanged bytes as an identity anchor.
        # With no WRITE_APPLIED receipts, byte recovery correctly reports
        # those bytes as NOT_APPLIED; however, a post-BYTES_APPLIED journal
        # state would normally reinterpret that as external interference.
        # Once metadata reversal has succeeded, an all-zero byte delta is an
        # unambiguous rollback case, so continue through the ordinary
        # lifecycle reconciliation lane instead of poisoning the transaction.
        byte_records = self._journal.operation_bytes(transaction_id)
        metadata_anchor_has_no_byte_delta = bool(
            record.has_metadata_actions
            and byte_records
            and all(
                byte.expected_current == byte.replacement
                for byte in byte_records
            )
        )

        if (
            recovery.recommended_state
            is NativeJournalState.INTERFERENCE_DETECTED
            and not metadata_anchor_has_no_byte_delta
        ):
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

        unrestored_extents = self._restore_function_extents(transaction_id)
        if unrestored_extents:
            self._journal.transition(
                transaction_id,
                NativeJournalState.RECOVERY_REQUIRED,
                note=f"post-rollback extent restore failed: {unrestored_extents}",
            )
            return

        function_eas = self._function_eas_for_transaction(transaction_id)
        lifecycle_failed = False
        for function_ea in function_eas:
            try:
                reanalyze_and_wait(function_ea, reanalyzer=self._reanalyzer)
            except Exception:
                lifecycle_failed = True
                logger.warning(
                    "post-rollback reanalysis failed for %#x",
                    function_ea,
                    exc_info=True,
                )
        post_reanalysis_extents = self._restore_function_extents(transaction_id)
        if post_reanalysis_extents:
            unrestored_extents = tuple(
                dict.fromkeys(unrestored_extents + post_reanalysis_extents)
            )
        unrestored_flow_refs = self._restore_function_flow_refs(transaction_id)
        for function_ea in function_eas:
            try:
                invalidate_target_and_callers(
                    function_ea,
                    invalidator=self._cache_invalidator,
                    discovery=self._caller_discovery,
                )
                controlled_redo(function_ea, decompiler=self._redo_decompiler)
            except Exception:
                lifecycle_failed = True
                logger.warning(
                    "post-rollback invalidation/redo failed for %#x",
                    function_ea,
                    exc_info=True,
                )
        final_unrestored_extents = self._restore_function_extents(transaction_id)
        if final_unrestored_extents:
            unrestored_extents = tuple(
                dict.fromkeys(unrestored_extents + final_unrestored_extents)
            )
        final_unrestored_flow_refs = self._restore_function_flow_refs(transaction_id)
        if final_unrestored_flow_refs:
            unrestored_flow_refs = tuple(
                dict.fromkeys(unrestored_flow_refs + final_unrestored_flow_refs)
            )
        for function_ea in function_eas:
            try:
                invalidate_target_and_callers(
                    function_ea,
                    invalidator=self._cache_invalidator,
                    discovery=self._caller_discovery,
                )
            except Exception:
                lifecycle_failed = True
                logger.warning(
                    "post-rollback final invalidation failed for %#x",
                    function_ea,
                    exc_info=True,
                )
        if lifecycle_failed or unrestored_extents or unrestored_flow_refs:
            self._journal.transition(
                transaction_id,
                NativeJournalState.RECOVERY_REQUIRED,
                note=(
                    "post-rollback lifecycle reconciliation failed: "
                    f"extents={unrestored_extents}, "
                    f"flow_refs={unrestored_flow_refs}"
                ),
            )
            return
        self._journal.transition(
            transaction_id,
            NativeJournalState.RESTORED,
            note="rolled back after apply failure",
        )

    def _require_current_database(self, record: NativePatchTransactionRecord) -> None:
        journaled_identity = record.database_identity
        if (
            journaled_identity is None
            or journaled_identity != self._current_database_identity
        ):
            raise NativePatchDatabaseIdentityMismatch(
                "journaled transaction database identity does not match the "
                "current database identity"
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
