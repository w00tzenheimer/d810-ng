"""Capability boundary for portable early frontend-normalization evidence."""

from __future__ import annotations

from d810.core.fragment_authority import NormalizationWorkItemAuthority
from d810.core.typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from d810.analyses.control_flow.frontend_normalization import (
        FrontendNormalizationEvidence,
    )
    from d810.transforms.fragment_plan import FragmentPlan


@runtime_checkable
class FrontendNormalizationEvidenceCapability(Protocol):
    """Supply provider-neutral native transfer proofs for one function."""

    def evidence_for(
        self,
        function_ea: int,
    ) -> "FrontendNormalizationEvidence | None":
        """Return one current portable evidence generation, or ``None``."""
        ...


@runtime_checkable
class FrontendNormalizationPlanCapability(Protocol):
    """Supply receipt-associated portable PREOPT plan intent."""

    def plan_for(
        self,
        function_ea: int,
        evidence_generation: int,
    ) -> "tuple[FragmentPlan, NormalizationWorkItemAuthority] | None":
        """Return one complete plan plus its exact receipt authority."""
        ...


__all__ = [
    "FrontendNormalizationEvidenceCapability",
    "FrontendNormalizationPlanCapability",
]
