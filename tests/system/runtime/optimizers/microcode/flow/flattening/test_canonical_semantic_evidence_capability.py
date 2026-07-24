"""Live composition of portable canonical semantic evidence."""

from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.capabilities.frontend_normalization import (
    FrontendNormalizationEvidenceCapability,
)
from d810.capabilities.semantic_routes import (
    CanonicalSemanticCandidateEvidenceCapability,
    CanonicalSemanticEvidenceCapability,
)
from d810.optimizers.microcode.flow.flattening import (
    state_machine_cff_unflattener as unflattener_module,
)
from d810.optimizers.microcode.flow.flattening.state_machine_cff_unflattener import (
    StateMachineCffUnflattener,
)
from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
    ResolverSessionState,
)
from tests.native_preanalysis import make_native_key


def test_live_unflattener_injects_session_canonical_semantic_evidence(
    monkeypatch,
) -> None:
    function_ea = 0x401000
    native_key = make_native_key(function_rva=0x1000)
    state = NativePreanalysisSessionState()
    expected_evidence = object()
    expected_candidate = object()
    expected_frontend = object()
    monkeypatch.setattr(
        NativePreanalysisSessionState,
        "canonical_semantic_evidence_for",
        lambda self, key: (
            expected_evidence if self is state and key == native_key else None
        ),
    )
    monkeypatch.setattr(
        NativePreanalysisSessionState,
        "canonical_semantic_candidate_evidence_for",
        lambda self, key: (
            expected_candidate if self is state and key == native_key else None
        ),
    )
    monkeypatch.setattr(
        NativePreanalysisSessionState,
        "frontend_normalization_evidence_for",
        lambda self, key: (
            expected_frontend if self is state and key == native_key else None
        ),
    )
    monkeypatch.setattr(
        unflattener_module,
        "HexRaysValRangeCapability",
        lambda _mba: object(),
    )
    monkeypatch.setattr(
        unflattener_module,
        "HexRaysUseDefSafetyBackend",
        lambda: object(),
    )
    monkeypatch.setattr(
        unflattener_module,
        "HexRaysMachineRecoveryEnginesCapability",
        lambda **_kwargs: object(),
    )
    resolver_state = ResolverSessionState(
        native_preanalysis=state,
        native_key=native_key,
    )
    rule = StateMachineCffUnflattener()
    rule.config = {}

    capabilities = rule._build_capabilities(
        SimpleNamespace(entry_ea=function_ea),
        SimpleNamespace(state_var_stkoff=None),
        None,
        resolver_state=resolver_state,
    )

    provider = capabilities.require(CanonicalSemanticEvidenceCapability)
    assert provider.evidence_for(function_ea) is expected_evidence
    assert provider.evidence_for(function_ea + 1) is None
    candidate_provider = capabilities.require(
        CanonicalSemanticCandidateEvidenceCapability
    )
    assert (
        candidate_provider.candidate_evidence_for(function_ea)
        is expected_candidate
    )
    assert candidate_provider.candidate_evidence_for(function_ea + 1) is None
    frontend_provider = capabilities.require(
        FrontendNormalizationEvidenceCapability
    )
    assert frontend_provider.evidence_for(function_ea) is expected_frontend
    assert frontend_provider.evidence_for(function_ea + 1) is None
