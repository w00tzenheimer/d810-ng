"""Typed lifecycle authority consumed by semantic-fragment publication."""

from __future__ import annotations

from d810.core.typing import Protocol, runtime_checkable
from d810.transforms.fragment_plan import FragmentPlan
from d810.transforms.fragment_validation import FragmentValidationResult
from d810.transforms.cfg_transaction import (
    CfgTransactionFailure,
    TransactionAttemptId,
)


@runtime_checkable
class FragmentPublicationLifecycleAuthority(Protocol):
    """Receipt-backed lifecycle port owned outside the mutation backend."""

    evidence_generation: int

    def record_fragment_plan_ready(self, plan: FragmentPlan) -> None: ...

    def record_fragment_staged(self, plan: FragmentPlan) -> None: ...

    def record_fragment_validated(
        self,
        plan: FragmentPlan,
        validation: FragmentValidationResult,
    ) -> None: ...

    def abort_fragment_publication(
        self,
        plan: FragmentPlan,
        *,
        reason: str,
    ) -> None: ...

    def commit_fragment_publication(
        self,
        plan: FragmentPlan,
        receipt: object,
    ) -> None: ...

    def request_poisoned_generation_restart(
        self,
        plan: FragmentPlan,
        failure: CfgTransactionFailure,
    ) -> bool: ...

    def request_cfg_generation_restart(
        self,
        attempt: TransactionAttemptId,
        failure: CfgTransactionFailure,
    ) -> bool: ...


__all__ = ["FragmentPublicationLifecycleAuthority"]
