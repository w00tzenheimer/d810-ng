"""Capability boundary for provider-neutral canonical semantic routes."""

from __future__ import annotations

from d810.core.typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from d810.analyses.control_flow.semantic_route_evidence import (
        CanonicalSemanticEvidence,
    )


@runtime_checkable
class CanonicalSemanticEvidenceCapability(Protocol):
    """Supply one current atomic generation of semantic route proofs."""

    def evidence_for(
        self,
        function_ea: int,
    ) -> "CanonicalSemanticEvidence | None":
        """Return portable semantic evidence for exactly one function."""
        ...


@runtime_checkable
class CanonicalSemanticCandidateEvidenceCapability(Protocol):
    """Supply current route candidates without claiming normalized authority."""

    def candidate_evidence_for(
        self,
        function_ea: int,
    ) -> "CanonicalSemanticEvidence | None":
        """Return portable planning candidates for exactly one function."""
        ...


__all__ = [
    "CanonicalSemanticCandidateEvidenceCapability",
    "CanonicalSemanticEvidenceCapability",
]
