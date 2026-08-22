"""Manager-owned bridge from a preanalysis proposal to native normalization.

The Hex-Rays preanalysis layer is allowed to discover an indirect dispatcher
and emit ``NativePatchPlanRequest``.  It must not import this module, build a
gateway, or make an IDA write.  The manager installs this callable at the
registration boundary and supplies the backend-specific plan builder.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass

from d810.backends.ida.native_patch.gateway import NativePatchGateway
from d810.backends.ida.native_patch.indirect_label_plan import (
    IndirectLabelPlanBuildError,
)
from d810.core.execution_journal import (
    ExecutionAttempt,
    ExecutionAttemptId,
    ExecutionAttemptStatus,
    ExecutionDomain,
    ExecutionEffectRef,
)
from d810.core.execution_journal_store import ExecutionJournalStore
from d810.core.typing import Any
from d810.hexrays.preanalysis.indirect_jump_labels import (
    IndirectLabelMaterializationResult,
    NativePatchPlanRequest,
)
from d810.manager.native_normalization import (
    NativeNormalizationOutcome,
    NativeNormalizationRequest,
    NativeNormalizationResult,
    authorize_and_apply,
)
from d810.manager.native_patch_policy import (
    NATIVE_PATCH_FUNCTION_OPT_IN_TAG,
    native_patch_function_is_authorized,
)
from d810.transforms.native_patch_plan import NativeCertificate, NativePatchPlan

__all__ = [
    "ManagerOwnedDeadEdgeNormalizer",
    "ManagerOwnedNativePatchRequestExecutor",
    "NativeMaterializationAttemptReceipt",
    "NativeMaterializationReceipt",
    "NATIVE_PATCH_FUNCTION_OPT_IN_TAG",
    "PreparedNativePatchRequest",
    "native_patch_function_is_authorized",
]


DEAD_EDGE_NATIVE_PASS_ID = "native_dead_edge_normalizer"
_DEAD_EDGE_PROOF_KIND_PRIORITY = (
    "single_trip_loop_peel",
    "z3_opaque_predicate",
)


def _select_dead_edge_candidate_batch(
    candidates: tuple[Any, ...],
) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    """Choose one certificate-compatible homogeneous proof batch.

    The largest batch wins so one function-slot certificate covers the most
    proven sites. Ties use a fixed proof-kind priority rather than discovery
    order, keeping selection stable when recognizers are reordered.
    """
    by_kind: dict[str, list[Any]] = {}
    for candidate in candidates:
        proof_kind = str(getattr(candidate, "proof_kind", ""))
        by_kind.setdefault(proof_kind, []).append(candidate)
    priority = {
        proof_kind: index
        for index, proof_kind in enumerate(_DEAD_EDGE_PROOF_KIND_PRIORITY)
    }
    selected_kind = min(
        by_kind,
        key=lambda proof_kind: (
            -len(by_kind[proof_kind]),
            priority.get(proof_kind, len(priority)),
            proof_kind,
        ),
    )
    selected = tuple(by_kind[selected_kind])
    deferred = tuple(
        candidate
        for candidate in candidates
        if str(getattr(candidate, "proof_kind", "")) != selected_kind
    )
    return selected, deferred


@dataclass(frozen=True, slots=True)
class PreparedNativePatchRequest:
    """A manager/backend-lowered request plus an honest postcondition probe."""

    plan: NativePatchPlan
    observe_result: Callable[[], IndirectLabelMaterializationResult]


@dataclass(frozen=True, slots=True)
class NativeMaterializationAttemptReceipt:
    """Read-only evidence for one manager-owned materialization attempt."""

    attempt: ExecutionAttempt
    normalization: NativeNormalizationResult
    result: IndirectLabelMaterializationResult


@dataclass(frozen=True, slots=True)
class NativeMaterializationReceipt:
    """Read-only evidence retained after one executor invocation."""

    function_ea: int
    plan_id: str
    plan_hash: str
    semantic_plan_hash: str
    metadata_target_fingerprint: str
    attempts: tuple[NativeMaterializationAttemptReceipt, ...]

    @property
    def certificate(self) -> NativeCertificate | None:
        for attempt in reversed(self.attempts):
            if attempt.normalization.certificate is not None:
                return attempt.normalization.certificate
        return None


class ManagerOwnedDeadEdgeNormalizer:
    """Run the named semantic dead-edge pass through manager-owned authority.

    Discovery is deliberately injected so this orchestration stays testable
    without IDA.  The manager supplies the production oracle and builder, and
    the resulting plan still has to pass issuer validation and gateway
    preflight before any journal preparation or IDB write.
    """

    def __init__(
        self,
        *,
        gateway: NativePatchGateway,
        user_enabled: Callable[[int], bool],
        execution_journal: ExecutionJournalStore,
        parent_attempt_scope_for_function: Callable[
            [int], AbstractContextManager[ExecutionAttemptId]
        ],
        discover_candidates: Callable[[int], tuple[tuple[Any, ...], tuple[Any, ...]]],
        build_plan: Callable[
            [int, tuple[Any, ...], ExecutionAttemptId], NativePatchPlan
        ],
        apply_plan: Callable[[NativePatchPlan], NativeNormalizationResult],
    ) -> None:
        self._gateway = gateway
        self._user_enabled = user_enabled
        self._execution_journal = execution_journal
        self._parent_attempt_scope_for_function = parent_attempt_scope_for_function
        self._discover_candidates = discover_candidates
        self._build_plan = build_plan
        self._apply_plan = apply_plan

    def __call__(self, function_ea: int) -> NativeNormalizationResult:
        function_ea = int(function_ea)
        if not self._user_enabled(function_ea):
            return NativeNormalizationResult(
                outcome=NativeNormalizationOutcome.NOT_AUTHORIZED,
                apply_receipt=None,
                certificate=None,
                reason="USER_NOT_OPTED_IN",
            )

        with self._parent_attempt_scope_for_function(function_ea) as parent_attempt_id:
            return self._normalize_with_parent(function_ea, parent_attempt_id)

    def _normalize_with_parent(
        self,
        function_ea: int,
        parent_attempt_id: ExecutionAttemptId,
    ) -> NativeNormalizationResult:
        attempt = self._execution_journal.begin_attempt(
            parent_attempt_id.session,
            parent_attempt_id=parent_attempt_id,
            stage_id=DEAD_EDGE_NATIVE_PASS_ID,
            domain=ExecutionDomain.NATIVE_NORMALIZATION,
        )
        try:
            candidates, abstentions = self._discover_candidates(function_ea)
            if not candidates:
                details = {
                    "function_ea": function_ea,
                    "candidate_count": 0,
                    "abstentions": tuple(repr(item) for item in abstentions),
                }
                self._execution_journal.advance(
                    attempt,
                    status=ExecutionAttemptStatus.ABSTAINED,
                    reason_code="NO_PROVEN_DEAD_EDGES",
                    details=details,
                )
                return NativeNormalizationResult(
                    outcome=NativeNormalizationOutcome.REJECTED,
                    apply_receipt=None,
                    certificate=None,
                    reason="NO_PROVEN_DEAD_EDGES",
                )

            selected_candidates, deferred_candidates = (
                _select_dead_edge_candidate_batch(candidates)
            )
            plan = self._build_plan(
                function_ea,
                selected_candidates,
                attempt.attempt_id,
            )
            diagnostic_snapshot_id = self._gateway.record_diagnostic_snapshot(plan)
            outcome = self._apply_plan(plan)
        except Exception as error:
            self._execution_journal.advance(
                attempt,
                status=ExecutionAttemptStatus.FAILED,
                reason_code=f"{type(error).__name__}: {error}",
                details={"function_ea": function_ea},
            )
            raise

        receipt = outcome.apply_receipt
        effects = [
            ExecutionEffectRef(kind="native_patch_proposal", ref_id=plan.plan_id),
            ExecutionEffectRef(
                kind="native_patch_preflight",
                ref_id=(
                    receipt.preflight_receipt_id
                    if receipt is not None and receipt.preflight_receipt_id is not None
                    else self._gateway.record_certificate_validation_receipt(
                        plan, outcome.certificate
                    )
                ),
            ),
            ExecutionEffectRef(
                kind="native_patch_diagnostic_snapshot",
                ref_id=diagnostic_snapshot_id,
            ),
        ]
        if receipt is not None:
            effects.append(
                ExecutionEffectRef(
                    kind="native_patch_transaction",
                    ref_id=receipt.transaction_id.value,
                )
            )
        if outcome.certificate is not None:
            effects.append(
                ExecutionEffectRef(
                    kind="native_patch_certificate",
                    ref_id=outcome.certificate.certificate_id,
                )
            )
        status = {
            NativeNormalizationOutcome.APPLIED: ExecutionAttemptStatus.COMPLETED,
            NativeNormalizationOutcome.REJECTED: ExecutionAttemptStatus.REJECTED,
        }.get(outcome.outcome, ExecutionAttemptStatus.ABSTAINED)
        self._execution_journal.advance(
            attempt,
            status=status,
            reason_code=outcome.reason,
            effect_refs=tuple(effects),
            details={
                "function_ea": function_ea,
                "candidate_count": len(candidates),
                "selected_candidate_count": len(selected_candidates),
                "selected_proof_kind": str(selected_candidates[0].proof_kind),
                "deferred_candidate_count": len(deferred_candidates),
                "deferred_proof_kinds": tuple(
                    sorted(
                        {str(candidate.proof_kind) for candidate in deferred_candidates}
                    )
                ),
            },
        )
        return outcome


class ManagerOwnedNativePatchRequestExecutor:
    """The only adapter that may turn a label request into ``gateway.apply``.

    ``user_enabled`` is injected by the manager's explicit user policy.  The
    builder runs only after that policy permits a request, so disabled mode is
    read-only even while discovery remains available to the preanalysis hook.
    """

    def __init__(
        self,
        *,
        gateway: NativePatchGateway,
        user_enabled: Callable[[NativePatchPlanRequest], bool],
        execution_journal: ExecutionJournalStore,
        parent_attempt_for_request: Callable[
            [NativePatchPlanRequest], ExecutionAttemptId
        ],
        build_plan: Callable[
            [NativePatchPlanRequest, ExecutionAttemptId], PreparedNativePatchRequest
        ],
    ) -> None:
        self._gateway = gateway
        self._user_enabled = user_enabled
        self._execution_journal = execution_journal
        self._parent_attempt_for_request = parent_attempt_for_request
        self._build_plan = build_plan
        self._reuse_verification_function_ea: int | None = None
        self._last_receipt: NativeMaterializationReceipt | None = None

    def arm_certificate_reuse_verification(self, function_ea: int) -> None:
        """Arm one invocation-local verification for *function_ea*.

        The arm stores no request, plan, parent, or session.  It is consumed
        by the next matching request and cannot authorize a later replay.
        """
        self._reuse_verification_function_ea = int(function_ea)
        self._last_receipt = None

    def clear_lifecycle_state(self) -> None:
        """Drop pending verification and retained read-only evidence."""
        self._reuse_verification_function_ea = None
        self._last_receipt = None

    def disarm_certificate_reuse_verification(self) -> None:
        """Cancel a not-yet-consumed invocation-local verification arm."""
        self._reuse_verification_function_ea = None

    def __call__(
        self, request: NativePatchPlanRequest
    ) -> IndirectLabelMaterializationResult:
        armed_function_ea = self._reuse_verification_function_ea
        self._reuse_verification_function_ea = None
        self._last_receipt = None
        try:
            if not self._user_enabled(request):
                return _compatibility_result(request, "native_patch_policy_disabled")

            parent_attempt_id = self._parent_attempt_for_request(request)
            prepared, first_receipt = self._execute_request(request, parent_attempt_id)
            if prepared is None or first_receipt is None:
                return _compatibility_result(request, "native_plan_unavailable")

            receipts = [first_receipt]
            if (
                armed_function_ea == int(request.materialization.function_ea)
                and first_receipt.normalization.outcome
                is NativeNormalizationOutcome.APPLIED
                and self._user_enabled(request)
            ):
                second_receipt = self._execute_prepared_request(
                    request,
                    prepared,
                    parent_attempt_id,
                )
                if (
                    second_receipt.normalization.outcome
                    is not NativeNormalizationOutcome.ALREADY_NORMALIZED
                ):
                    raise RuntimeError(
                        "certificate reuse verification did not return "
                        f"ALREADY_NORMALIZED: {second_receipt.normalization.reason}"
                    )
                receipts.append(second_receipt)

            plan = prepared.plan
            self._last_receipt = NativeMaterializationReceipt(
                function_ea=int(request.materialization.function_ea),
                plan_id=plan.plan_id,
                plan_hash=plan.plan_hash,
                semantic_plan_hash=plan.proof_hash,
                metadata_target_fingerprint=plan.metadata_target_fingerprint,
                attempts=tuple(receipts),
            )
            return first_receipt.result
        except Exception:
            self._last_receipt = None
            raise
        finally:
            self._reuse_verification_function_ea = None

    def inspect_last_receipt(
        self, *, function_ea: int | None = None
    ) -> NativeMaterializationReceipt:
        """Return read-only evidence from the latest completed invocation."""
        receipt = self._last_receipt
        if receipt is None:
            raise RuntimeError("no native materialization receipt is available")
        if function_ea is not None and int(function_ea) != receipt.function_ea:
            raise ValueError("latest native materialization receipt targets another function")
        return receipt

    def _execute_request(
        self,
        request: NativePatchPlanRequest,
        parent_attempt_id: ExecutionAttemptId,
    ) -> tuple[PreparedNativePatchRequest | None, NativeMaterializationAttemptReceipt | None]:
        attempt = self._execution_journal.begin_attempt(
            parent_attempt_id.session,
            parent_attempt_id=parent_attempt_id,
            stage_id="indirect_label_native_materialization",
            domain=ExecutionDomain.NATIVE_NORMALIZATION,
        )
        try:
            prepared = self._build_plan(request, attempt.attempt_id)
        except IndirectLabelPlanBuildError as error:
            self._execution_journal.advance(
                attempt,
                status=ExecutionAttemptStatus.ABSTAINED,
                reason_code=f"NATIVE_PLAN_UNAVAILABLE:{error}",
                details={
                    "kind": "native_plan_unavailable",
                    "error_type": type(error).__name__,
                    "reason": error.reason.value,
                    "ea": error.ea,
                    "before_shape": error.before_shape,
                    "after_shape": error.after_shape,
                    "message": str(error),
                },
            )
            return None, None
        except Exception:
            self._execution_journal.advance(
                attempt,
                status=ExecutionAttemptStatus.FAILED,
                reason_code="NATIVE_PLAN_OR_APPLY_FAILED",
            )
            raise

        return prepared, self._finish_attempt(request, prepared, attempt)

    def _execute_prepared_request(
        self,
        request: NativePatchPlanRequest,
        prepared: PreparedNativePatchRequest,
        parent_attempt_id: ExecutionAttemptId,
    ) -> NativeMaterializationAttemptReceipt:
        attempt = self._execution_journal.begin_attempt(
            parent_attempt_id.session,
            parent_attempt_id=parent_attempt_id,
            stage_id="indirect_label_native_materialization",
            domain=ExecutionDomain.NATIVE_NORMALIZATION,
        )
        return self._finish_attempt(request, prepared, attempt)

    def _finish_attempt(
        self,
        request: NativePatchPlanRequest,
        prepared: PreparedNativePatchRequest,
        attempt: ExecutionAttempt,
    ) -> NativeMaterializationAttemptReceipt:
        try:
            diagnostic_snapshot_id = self._gateway.record_diagnostic_snapshot(
                prepared.plan
            )
            outcome = authorize_and_apply(
                NativeNormalizationRequest(plan=prepared.plan, user_enabled=True),
                gateway=self._gateway,
            )
        except Exception:
            self._execution_journal.advance(
                attempt,
                status=ExecutionAttemptStatus.FAILED,
                reason_code="NATIVE_PLAN_OR_APPLY_FAILED",
            )
            raise

        effects = [
            ExecutionEffectRef(
                kind="native_patch_proposal", ref_id=prepared.plan.plan_id
            ),
            ExecutionEffectRef(
                kind="native_patch_preflight",
                ref_id=(
                    receipt.preflight_receipt_id
                    if (receipt := outcome.apply_receipt) is not None
                    and receipt.preflight_receipt_id is not None
                    else self._gateway.record_certificate_validation_receipt(
                        prepared.plan, outcome.certificate
                    )
                ),
            ),
            ExecutionEffectRef(
                kind="native_patch_diagnostic_snapshot", ref_id=diagnostic_snapshot_id
            ),
        ]
        if receipt is not None:
            effects.append(
                ExecutionEffectRef(
                    kind="native_patch_transaction",
                    ref_id=receipt.transaction_id.value,
                )
            )
            # A successful receipt is returned only after the gateway's
            # mandatory reanalysis and cache invalidation sequence completes.
            effects.append(
                ExecutionEffectRef(
                    kind="native_patch_reanalysis",
                    ref_id=receipt.transaction_id.value,
                )
            )
        if outcome.certificate is not None:
            effects.append(
                ExecutionEffectRef(
                    kind="native_patch_certificate",
                    ref_id=outcome.certificate.certificate_id,
                )
            )
        terminal_attempt = self._execution_journal.advance(
            attempt,
            status=(
                ExecutionAttemptStatus.COMPLETED
                if outcome.outcome is NativeNormalizationOutcome.APPLIED
                else ExecutionAttemptStatus.ABSTAINED
            ),
            reason_code=outcome.reason,
            effect_refs=tuple(effects),
        )
        if outcome.outcome in {
            NativeNormalizationOutcome.APPLIED,
            NativeNormalizationOutcome.ALREADY_NORMALIZED,
        }:
            result = prepared.observe_result()
        else:
            result = _compatibility_result(
                request,
                f"native_patch_{outcome.outcome.value}:{outcome.reason or 'unknown'}",
            )
        return NativeMaterializationAttemptReceipt(
            attempt=terminal_attempt,
            normalization=outcome,
            result=result,
        )


def _compatibility_result(
    request: NativePatchPlanRequest, reason: str
) -> IndirectLabelMaterializationResult:
    plan = request.materialization
    return IndirectLabelMaterializationResult(
        function_ea=plan.function_ea,
        table_address=plan.table_address,
        table_count=plan.table_count,
        label_start=plan.label_start,
        label_end=plan.label_end,
        target_count=len(plan.target_eas),
        materialized_target_count=0,
        dispatch_jump_ea=request.dispatch_jump_ea,
        jump_xref_count=0,
        switch_info_installed=False,
        appended_tail=False,
        success=False,
        reason=reason,
    )
