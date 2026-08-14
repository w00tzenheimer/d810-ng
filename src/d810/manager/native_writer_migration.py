"""Manager-owned bridge from a preanalysis proposal to native normalization.

The Hex-Rays preanalysis layer is allowed to discover an indirect dispatcher
and emit ``NativePatchPlanRequest``.  It must not import this module, build a
gateway, or make an IDA write.  The manager installs this callable at the
registration boundary and supplies the backend-specific plan builder.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from d810.backends.ida.native_patch.gateway import NativePatchGateway
from d810.backends.ida.native_patch.indirect_label_plan import (
    IndirectLabelPlanBuildError,
)
from d810.core.execution_journal import (
    ExecutionAttemptId,
    ExecutionAttemptStatus,
    ExecutionDomain,
    ExecutionEffectRef,
)
from d810.core.execution_journal_store import ExecutionJournalStore
from d810.hexrays.preanalysis.indirect_jump_labels import (
    IndirectLabelMaterializationResult,
    NativePatchPlanRequest,
)
from d810.manager.native_normalization import (
    NativeNormalizationOutcome,
    NativeNormalizationRequest,
    authorize_and_apply,
)
from d810.manager.native_patch_policy import (
    NATIVE_PATCH_FUNCTION_OPT_IN_TAG,
    native_patch_function_is_authorized,
)
from d810.transforms.native_patch_plan import NativePatchPlan

__all__ = [
    "ManagerOwnedNativePatchRequestExecutor",
    "NATIVE_PATCH_FUNCTION_OPT_IN_TAG",
    "PreparedNativePatchRequest",
    "native_patch_function_is_authorized",
]


@dataclass(frozen=True, slots=True)
class PreparedNativePatchRequest:
    """A manager/backend-lowered request plus an honest postcondition probe."""

    plan: NativePatchPlan
    observe_result: Callable[[], IndirectLabelMaterializationResult]


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

    def __call__(
        self, request: NativePatchPlanRequest
    ) -> IndirectLabelMaterializationResult:
        if not self._user_enabled(request):
            return _compatibility_result(request, "native_patch_policy_disabled")

        parent_attempt_id = self._parent_attempt_for_request(request)
        attempt = self._execution_journal.begin_attempt(
            parent_attempt_id.session,
            parent_attempt_id=parent_attempt_id,
            stage_id="indirect_label_native_materialization",
            domain=ExecutionDomain.NATIVE_NORMALIZATION,
        )
        try:
            prepared = self._build_plan(request, attempt.attempt_id)
            diagnostic_snapshot_id = self._gateway.record_diagnostic_snapshot(
                prepared.plan
            )
            outcome = authorize_and_apply(
                NativeNormalizationRequest(plan=prepared.plan, user_enabled=True),
                gateway=self._gateway,
            )
        except IndirectLabelPlanBuildError as error:
            self._execution_journal.advance(
                attempt,
                status=ExecutionAttemptStatus.ABSTAINED,
                reason_code=f"NATIVE_PLAN_UNAVAILABLE:{error}",
            )
            return _compatibility_result(request, f"native_plan_unavailable:{error}")
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
        self._execution_journal.advance(
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
            return prepared.observe_result()
        return _compatibility_result(
            request,
            f"native_patch_{outcome.outcome.value}:{outcome.reason or 'unknown'}",
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
