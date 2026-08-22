"""Focused canonical authority diagnostic projections."""

from __future__ import annotations

from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority.ids import authority_id
from d810.transforms.unflatten_authority.diagnostics import (
    PhaseTimings,
    build_phase_payload,
    phase_observation,
)


def test_one_anchored_fact_observation_per_authoritative_phase() -> None:
    verdict = model.UnflattenAuthorityVerdict(
        accepted=False,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        reason=model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        authority_id=authority_id("authority"), binding_id=None, case_id=None,
        candidate_fingerprint=authority_id("candidate"), safety_case=None,
        failed_obligations=(),
    )

    observation = phase_observation(
        verdict,
        maturity="MMAT_GLBOPT1",
        source_ea=0x401000,
        timings=PhaseTimings(inventory_ms=0.5),
    )

    assert observation.fact_id == f"plan:{authority_id('authority')}:precase-rejection"
    assert observation.kind == "unflatten_authority_phase"
    assert observation.semantic_key == authority_id("authority")
    assert observation.phase == "projected_preflight"
    assert observation.source_ea == 0x401000
    assert observation.block_fingerprint == authority_id("candidate")
    assert build_phase_payload(verdict)["schema"] == "unflatten_authority_phase.v1"
