"""Capability boundary for provider-neutral canonical semantic routes."""

from __future__ import annotations

from d810.core.typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from d810.analyses.control_flow.semantic_route_evidence import (
        CanonicalSemanticEvidence,
    )
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.core.semantic_route_oracle import ReferenceRouteOracleSelection


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


@runtime_checkable
class SemanticRouteReferenceOracleCapability(Protocol):
    """Select pinned reference authority for exact fragment rewrite anchors."""

    def reference_oracle_scope_for(
        self,
        function_ea: int,
        native_key: "NativePreanalysisKey",
    ) -> "ReferenceRouteOracleSelection | None":
        """Return the complete configured fragment scope for one exact input."""
        ...

    def reference_oracle_for(
        self,
        function_ea: int,
        native_key: "NativePreanalysisKey",
        rewrite_anchor_eas: tuple[int, ...],
    ) -> "ReferenceRouteOracleSelection | None":
        """Return authority only when input, function, and anchors match."""
        ...


__all__ = [
    "CanonicalSemanticCandidateEvidenceCapability",
    "CanonicalSemanticEvidenceCapability",
    "SemanticRouteReferenceOracleCapability",
]
