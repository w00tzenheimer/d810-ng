"""Capability boundary for portable early frontend-normalization evidence."""

from __future__ import annotations

from d810.core.typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from d810.analyses.control_flow.frontend_normalization import (
        FrontendNormalizationEvidence,
    )


@runtime_checkable
class FrontendNormalizationEvidenceCapability(Protocol):
    """Supply provider-neutral native transfer proofs for one function."""

    def evidence_for(
        self,
        function_ea: int,
    ) -> "FrontendNormalizationEvidence | None":
        """Return one current portable evidence generation, or ``None``."""
        ...


__all__ = ["FrontendNormalizationEvidenceCapability"]
