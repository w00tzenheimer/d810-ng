"""Typed lifecycle authority consumed by semantic-fragment publication."""

from __future__ import annotations

from d810.core.typing import Protocol, runtime_checkable
from d810.transforms.fragment_plan import FragmentPlan
from d810.transforms.fragment_validation import FragmentValidationResult


@runtime_checkable
class FragmentPublicationLifecycleAuthority(Protocol):
    """Receipt-backed lifecycle port owned outside the mutation backend."""

    evidence_generation: int

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


__all__ = ["FragmentPublicationLifecycleAuthority"]
