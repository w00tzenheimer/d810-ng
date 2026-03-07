"""Tests for PlannerCandidate, PlannerDecision, and PlannerDecisionReason (H1)."""
from __future__ import annotations

import pytest

from d810.optimizers.microcode.flow.flattening.hodur.planner import (
    HintAdjustment,
    PlannerCandidate,
    PlannerDecision,
    PlannerDecisionReason,
)
from d810.optimizers.microcode.flow.flattening.hodur.provenance import (
    DecisionPhase,
    DecisionReasonCode,
    DecisionRecord,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
    OwnershipScope,
    PlanFragment,
)


def _make_fragment(
    name: str = "test_strategy",
    family: str = FAMILY_DIRECT,
    handlers: int = 10,
    transitions: int = 8,
    blocks_freed: int = 5,
    risk: float = 0.2,
    prereqs: list[str] | None = None,
    owned_blocks: frozenset[int] | None = None,
) -> PlanFragment:
    """Build a minimal PlanFragment for testing."""
    return PlanFragment(
        strategy_name=name,
        family=family,
        ownership=OwnershipScope(
            blocks=owned_blocks or frozenset({1, 2, 3}),
            edges=frozenset(),
            transitions=frozenset(),
        ),
        prerequisites=prereqs or [],
        expected_benefit=BenefitMetrics(
            handlers_resolved=handlers,
            transitions_resolved=transitions,
            blocks_freed=blocks_freed,
            conflict_density=0.0,
        ),
        risk_score=risk,
    )


def _make_candidate(
    fragment: PlanFragment | None = None,
    hint_delta: float = 0.0,
    hint_reasons: tuple[str, ...] = (),
) -> PlannerCandidate:
    """Build a PlannerCandidate for testing."""
    frag = fragment or _make_fragment()
    base = frag.expected_benefit.composite_score()
    adj = HintAdjustment(score_delta=hint_delta, reasons=hint_reasons)
    return PlannerCandidate(
        fragment=frag,
        base_score=base,
        hint_adjustment=adj,
        effective_score=base + hint_delta,
        strategy_name=frag.strategy_name,
        family=frag.family,
    )


# ---------------------------------------------------------------------------
# PlannerDecisionReason enum
# ---------------------------------------------------------------------------


class TestPlannerDecisionReason:
    """Verify enum values and membership."""

    def test_all_values(self) -> None:
        expected = {
            "accepted",
            "rejected_empty",
            "rejected_risk",
            "rejected_policy",
            "rejected_conflict",
            "rejected_prerequisite",
        }
        actual = {m.value for m in PlannerDecisionReason}
        assert actual == expected

    def test_is_str_enum(self) -> None:
        assert isinstance(PlannerDecisionReason.ACCEPTED, str)
        assert PlannerDecisionReason.ACCEPTED == "accepted"

    def test_member_count(self) -> None:
        assert len(PlannerDecisionReason) == 6


# ---------------------------------------------------------------------------
# PlannerCandidate
# ---------------------------------------------------------------------------


class TestPlannerCandidate:
    """Verify construction and property delegation."""

    def test_construction_basic(self) -> None:
        frag = _make_fragment()
        c = _make_candidate(frag)
        assert c.fragment is frag
        assert c.strategy_name == "test_strategy"
        assert c.family == FAMILY_DIRECT

    def test_base_score_from_composite(self) -> None:
        frag = _make_fragment(handlers=10, transitions=8, blocks_freed=5)
        c = _make_candidate(frag)
        expected = 10 * 3.0 + 8 * 2.0 + 5 * 1.0 - 0.0 * 5.0  # 51.0
        assert c.base_score == pytest.approx(expected)

    def test_effective_score_with_positive_hint(self) -> None:
        frag = _make_fragment(handlers=10, transitions=8, blocks_freed=5)
        c = _make_candidate(frag, hint_delta=1.6)
        assert c.effective_score == pytest.approx(c.base_score + 1.6)

    def test_effective_score_with_negative_hint(self) -> None:
        frag = _make_fragment(handlers=10, transitions=8, blocks_freed=5)
        c = _make_candidate(frag, hint_delta=-0.75)
        assert c.effective_score == pytest.approx(c.base_score - 0.75)

    def test_effective_score_zero_hint(self) -> None:
        frag = _make_fragment()
        c = _make_candidate(frag, hint_delta=0.0)
        assert c.effective_score == pytest.approx(c.base_score)

    def test_ownership_delegation(self) -> None:
        frag = _make_fragment(owned_blocks=frozenset({10, 20}))
        c = _make_candidate(frag)
        assert c.ownership is frag.ownership
        assert c.ownership.blocks == frozenset({10, 20})

    def test_prerequisites_delegation(self) -> None:
        frag = _make_fragment(prereqs=["alpha", "beta"])
        c = _make_candidate(frag)
        assert c.prerequisites == ["alpha", "beta"]
        assert c.prerequisites is frag.prerequisites

    def test_risk_score_delegation(self) -> None:
        frag = _make_fragment(risk=0.42)
        c = _make_candidate(frag)
        assert c.risk_score == pytest.approx(0.42)

    def test_frozen(self) -> None:
        c = _make_candidate()
        with pytest.raises(AttributeError):
            c.base_score = 999.0  # type: ignore[misc]

    def test_hint_reasons_stored(self) -> None:
        c = _make_candidate(
            hint_delta=1.0,
            hint_reasons=("transition_report_boost",),
        )
        assert c.hint_adjustment.reasons == ("transition_report_boost",)


# ---------------------------------------------------------------------------
# PlannerDecision
# ---------------------------------------------------------------------------


class TestPlannerDecision:
    """Verify construction and to_decision_record conversion."""

    def test_construction_accepted(self) -> None:
        c = _make_candidate()
        d = PlannerDecision(
            candidate=c,
            reason=PlannerDecisionReason.ACCEPTED,
            detail="selected into pipeline",
        )
        assert d.candidate is c
        assert d.reason == PlannerDecisionReason.ACCEPTED
        assert d.detail == "selected into pipeline"

    def test_construction_default_detail(self) -> None:
        c = _make_candidate()
        d = PlannerDecision(
            candidate=c,
            reason=PlannerDecisionReason.REJECTED_EMPTY,
        )
        assert d.detail == ""

    def test_frozen(self) -> None:
        c = _make_candidate()
        d = PlannerDecision(candidate=c, reason=PlannerDecisionReason.ACCEPTED)
        with pytest.raises(AttributeError):
            d.reason = PlannerDecisionReason.REJECTED_RISK  # type: ignore[misc]

    def test_to_decision_record_accepted(self) -> None:
        frag = _make_fragment(
            name="strat_A",
            family=FAMILY_DIRECT,
            handlers=5,
            transitions=3,
            blocks_freed=2,
            risk=0.1,
            prereqs=["pre1"],
            owned_blocks=frozenset({7, 8}),
        )
        c = _make_candidate(frag, hint_delta=1.5, hint_reasons=("boost",))
        d = PlannerDecision(
            candidate=c,
            reason=PlannerDecisionReason.ACCEPTED,
            detail="selected for pipeline",
        )
        rec = d.to_decision_record()

        assert isinstance(rec, DecisionRecord)
        assert rec.strategy_name == "strat_A"
        assert rec.family == FAMILY_DIRECT
        assert rec.phase == DecisionPhase.SELECTED
        assert rec.reason_code == DecisionReasonCode.ACCEPTED
        assert rec.reason == "selected for pipeline"
        assert rec.composite_score == pytest.approx(c.base_score)
        assert rec.risk_score == pytest.approx(0.1)
        assert rec.handler_count == 5
        assert rec.transition_count == 3
        assert rec.ownership_blocks == frozenset({7, 8})
        assert rec.prerequisites == frozenset({"pre1"})
        assert rec.base_score == pytest.approx(c.base_score)
        assert rec.hint_score_delta == pytest.approx(1.5)
        assert rec.effective_score == pytest.approx(c.effective_score)
        assert rec.hint_reasons == ("boost",)

    def test_to_decision_record_rejected_empty(self) -> None:
        c = _make_candidate()
        d = PlannerDecision(
            candidate=c,
            reason=PlannerDecisionReason.REJECTED_EMPTY,
            detail="no actions",
        )
        rec = d.to_decision_record()
        assert rec.phase == DecisionPhase.INAPPLICABLE
        assert rec.reason_code == DecisionReasonCode.REJECTED_EMPTY
        assert rec.reason == "no actions"

    def test_to_decision_record_rejected_risk(self) -> None:
        c = _make_candidate()
        d = PlannerDecision(
            candidate=c,
            reason=PlannerDecisionReason.REJECTED_RISK,
            detail="risk too high",
        )
        rec = d.to_decision_record()
        assert rec.phase == DecisionPhase.POLICY_FILTERED
        assert rec.reason_code == DecisionReasonCode.REJECTED_RISK

    def test_to_decision_record_rejected_policy(self) -> None:
        c = _make_candidate()
        d = PlannerDecision(
            candidate=c,
            reason=PlannerDecisionReason.REJECTED_POLICY,
        )
        rec = d.to_decision_record()
        assert rec.phase == DecisionPhase.POLICY_FILTERED
        assert rec.reason_code == DecisionReasonCode.REJECTED_POLICY

    def test_to_decision_record_rejected_conflict(self) -> None:
        c = _make_candidate()
        d = PlannerDecision(
            candidate=c,
            reason=PlannerDecisionReason.REJECTED_CONFLICT,
            detail="lost to higher-scoring candidate",
        )
        rec = d.to_decision_record()
        assert rec.phase == DecisionPhase.CONFLICT_DROPPED
        assert rec.reason_code == DecisionReasonCode.REJECTED_CONFLICT

    def test_to_decision_record_rejected_prerequisite(self) -> None:
        c = _make_candidate()
        d = PlannerDecision(
            candidate=c,
            reason=PlannerDecisionReason.REJECTED_PREREQUISITE,
            detail="missing dep: alpha",
        )
        rec = d.to_decision_record()
        assert rec.phase == DecisionPhase.POLICY_FILTERED
        assert rec.reason_code == DecisionReasonCode.BLOCKED

    def test_to_decision_record_empty_detail_uses_reason_value(self) -> None:
        c = _make_candidate()
        d = PlannerDecision(
            candidate=c,
            reason=PlannerDecisionReason.REJECTED_RISK,
        )
        rec = d.to_decision_record()
        assert rec.reason == "rejected_risk"

    def test_all_reasons_mapped(self) -> None:
        """Every PlannerDecisionReason must produce a valid DecisionRecord."""
        from d810.optimizers.microcode.flow.flattening.hodur.planner import (
            _REASON_TO_CODE,
            _REASON_TO_PHASE,
        )
        for reason in PlannerDecisionReason:
            assert reason in _REASON_TO_CODE, f"{reason} missing from _REASON_TO_CODE"
            assert reason in _REASON_TO_PHASE, f"{reason} missing from _REASON_TO_PHASE"
