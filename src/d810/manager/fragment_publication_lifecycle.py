"""Manager-owned authority for receipt-backed fragment lifecycle transitions."""

from __future__ import annotations

from dataclasses import dataclass, field

from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.hexrays.mutation.mba_mutation_events import (
    MbaMutationReceipt,
    StructuralMutationKind,
)
from d810.transforms.fragment_plan import (
    FragmentPlan,
    FragmentPublicationPurpose,
    FragmentWorkItemScope,
)
from d810.transforms.fragment_validation import FragmentValidationResult


@dataclass(slots=True)
class SessionFragmentPublicationLifecycleAuthority:
    """Validate gateway proof before advancing session lifecycle authority."""

    native_key: NativePreanalysisKey
    state: NativePreanalysisSessionState
    _pending_plan_id: str | None = field(default=None, init=False)
    _pending_atomic_group_id: str | None = field(default=None, init=False)
    _pending_purpose: FragmentPublicationPurpose | None = field(
        default=None,
        init=False,
    )
    _prepublication_validation: FragmentValidationResult | None = field(
        default=None,
        init=False,
    )

    @property
    def evidence_generation(self) -> int:
        return int(self.state.evidence_generation)

    def _require_typed_plan(self, plan: FragmentPlan) -> None:
        if not isinstance(plan, FragmentPlan):
            raise TypeError("fragment lifecycle authority requires a FragmentPlan")
        if plan.native_key != self.native_key:
            raise ValueError("fragment lifecycle plan belongs to another native key")

    def _require_pending_plan(self, plan: FragmentPlan) -> None:
        self._require_typed_plan(plan)
        if (
            self._pending_plan_id != plan.plan_id
            or self._pending_atomic_group_id != plan.atomic_group_id
            or self._pending_purpose is not plan.publication_purpose
        ):
            raise ValueError("fragment lifecycle plan does not match staged authority")

    def _clear_pending(self) -> None:
        self._pending_plan_id = None
        self._pending_atomic_group_id = None
        self._pending_purpose = None
        self._prepublication_validation = None

    def record_fragment_plan_ready(self, plan: FragmentPlan) -> None:
        """Record canonical plan authority before detached staging begins."""
        self._require_typed_plan(plan)
        if self._pending_plan_id is not None:
            raise RuntimeError("fragment lifecycle authority already has a staged plan")
        if (
            plan.publication_purpose
            is FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING
        ):
            self.state.mark_canonical_semantic_plan_ready(plan.normalization_authority)

    def record_fragment_staged(self, plan: FragmentPlan) -> None:
        self._require_typed_plan(plan)
        if self._pending_plan_id is not None:
            raise RuntimeError("fragment lifecycle authority already has a staged plan")
        if (
            plan.publication_purpose
            is FragmentPublicationPurpose.FRONTEND_NORMALIZATION
        ):
            self.state._fragment_publication_mark_normalization_staged()
        else:
            self.state._fragment_publication_mark_semantic_fragment_staged()
        self._pending_plan_id = plan.plan_id
        self._pending_atomic_group_id = plan.atomic_group_id
        self._pending_purpose = plan.publication_purpose

    def record_fragment_validated(
        self,
        plan: FragmentPlan,
        validation: FragmentValidationResult,
    ) -> None:
        self._require_pending_plan(plan)
        if not isinstance(validation, FragmentValidationResult):
            raise TypeError("fragment lifecycle validation proof must be typed")
        if not validation.passed:
            raise ValueError("fragment lifecycle cannot accept failed validation")
        if (
            validation.plan_id != plan.plan_id
            or validation.atomic_group_id != plan.atomic_group_id
        ):
            raise ValueError("fragment lifecycle validation scope drifted")
        if (
            plan.publication_purpose
            is FragmentPublicationPurpose.FRONTEND_NORMALIZATION
        ):
            self.state._fragment_publication_mark_normalization_validated()
        else:
            self.state._fragment_publication_mark_semantic_fragment_validated()
        self._prepublication_validation = validation

    def abort_fragment_publication(
        self,
        plan: FragmentPlan,
        *,
        reason: str,
    ) -> None:
        self._require_pending_plan(plan)
        if (
            plan.publication_purpose
            is FragmentPublicationPurpose.FRONTEND_NORMALIZATION
        ):
            self.state._fragment_publication_abort_normalization(reason=str(reason))
        else:
            self.state._fragment_publication_abort_semantic_fragment(reason=str(reason))
        self._clear_pending()

    def commit_fragment_publication(
        self,
        plan: FragmentPlan,
        receipt: object,
    ) -> None:
        self._require_pending_plan(plan)
        if self._prepublication_validation is None:
            raise RuntimeError("fragment lifecycle commit requires validation proof")
        if not isinstance(receipt, MbaMutationReceipt):
            raise TypeError("fragment lifecycle commit requires a mutation receipt")
        if receipt.kind is not StructuralMutationKind.FRAGMENT_PUBLICATION:
            raise ValueError("fragment lifecycle commit requires a fragment receipt")
        if (
            receipt.fragment_plan_id != plan.plan_id
            or receipt.fragment_atomic_group_id != plan.atomic_group_id
        ):
            raise ValueError("fragment lifecycle receipt scope drifted")
        if receipt.prepublication_validation != self._prepublication_validation:
            raise ValueError("fragment lifecycle receipt changed validation proof")
        if receipt.evidence_generation != self.evidence_generation:
            raise ValueError("fragment lifecycle receipt evidence generation drifted")
        if (
            not receipt.root_publication_confirmed
            or receipt.postpublication_validation is None
            or not receipt.postpublication_validation.passed
            or receipt.operation_count != receipt.planned_operation_count
        ):
            raise ValueError("fragment lifecycle receipt lacks committed proof")
        if (
            plan.publication_purpose
            is FragmentPublicationPurpose.FRONTEND_NORMALIZATION
        ):
            scope = plan.work_item_scope
            if not isinstance(scope, FragmentWorkItemScope):
                raise TypeError(
                    "normalization lifecycle commit requires a work-item scope"
                )
            self.state._fragment_publication_commit_normalization_work_item(
                work_item_id=scope.work_item_id,
                published_operation_ids=tuple(
                    operation.operation_id for operation in plan.operations
                ),
                selected_obligation_ids=scope.selected_obligation_ids,
                remaining_obligation_ids=scope.remaining_obligation_ids,
                unreachable_obligation_ids=scope.unreachable_obligation_ids,
            )
        else:
            self.state._fragment_publication_mark_semantic_fragment_published_and_postvalidated()
            self.state._fragment_publication_mark_receipt_committed()
        self._clear_pending()


__all__ = ["SessionFragmentPublicationLifecycleAuthority"]
