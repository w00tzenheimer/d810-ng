"""Live composition adapter for lifecycle-owned canonical route evidence."""

from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.analyses.control_flow.frontend_normalization import (
    FrontendNormalizationEvidence,
)
from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
)
from d810.core.native_preanalysis_key import NativePreanalysisKey


@dataclass(frozen=True, slots=True)
class SessionCanonicalSemanticEvidenceProvider:
    """Expose one normalized lifecycle generation through the pass capability."""

    function_ea: int
    native_key: NativePreanalysisKey
    state: NativePreanalysisSessionState

    def __post_init__(self) -> None:
        function_ea = int(self.function_ea)
        if function_ea < 0:
            raise ValueError("canonical semantic function EA must be non-negative")
        if not isinstance(self.native_key, NativePreanalysisKey):
            raise TypeError("canonical semantic evidence requires a native key")
        if not isinstance(self.state, NativePreanalysisSessionState):
            raise TypeError("canonical semantic evidence requires lifecycle state")
        object.__setattr__(self, "function_ea", function_ea)

    def evidence_for(
        self,
        function_ea: int,
    ) -> CanonicalSemanticEvidence | None:
        if int(function_ea) != self.function_ea:
            return None
        return self.state.canonical_semantic_evidence_for(self.native_key)

    def candidate_evidence_for(
        self,
        function_ea: int,
    ) -> CanonicalSemanticEvidence | None:
        if int(function_ea) != self.function_ea:
            return None
        return self.state.canonical_semantic_candidate_evidence_for(
            self.native_key
        )


@dataclass(frozen=True, slots=True)
class SessionFrontendNormalizationEvidenceProvider:
    """Expose current portable normalization evidence to canonical planning."""

    function_ea: int
    native_key: NativePreanalysisKey
    state: NativePreanalysisSessionState

    def __post_init__(self) -> None:
        function_ea = int(self.function_ea)
        if function_ea < 0:
            raise ValueError("frontend evidence function EA must be non-negative")
        if not isinstance(self.native_key, NativePreanalysisKey):
            raise TypeError("frontend evidence requires a native key")
        if not isinstance(self.state, NativePreanalysisSessionState):
            raise TypeError("frontend evidence requires lifecycle state")
        object.__setattr__(self, "function_ea", function_ea)

    def evidence_for(
        self,
        function_ea: int,
    ) -> FrontendNormalizationEvidence | None:
        if int(function_ea) != self.function_ea:
            return None
        return self.state.frontend_normalization_evidence_for(self.native_key)


__all__ = [
    "SessionCanonicalSemanticEvidenceProvider",
    "SessionFrontendNormalizationEvidenceProvider",
]
