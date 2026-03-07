"""Integration tests for strict-mode fail-closed gate behavior.

These tests verify the gate infrastructure contracts defined in
``d810.core.gate_modes`` and ``d810.optimizers...hodur.provenance``.
Every unflattening entry path must emit an explicit gate outcome;
strict mode must never continue silently.

Pure-Python only -- no IDA imports, no mocks of ida_hexrays.
"""

from __future__ import annotations

import pytest

from d810.core.gate_modes import GateOperationMode
from d810.optimizers.microcode.flow.flattening.hodur.provenance import (
    DecisionReasonCode,
    GateAccounting,
    GateDecision,
    GateVerdict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_decision(
    gate_name: str = "test_gate",
    verdict: GateVerdict = GateVerdict.PASSED,
    reason: str = "test reason",
    strict_mode: bool = True,
    elapsed_ms: float | None = None,
) -> GateDecision:
    """Build a GateDecision with defaults matching provenance conventions."""
    return GateDecision(
        gate_name=gate_name,
        verdict=verdict,
        reason=reason,
        strict_mode=strict_mode,
        elapsed_ms=elapsed_ms,
    )


def _simulate_gate_evaluation(
    mode: GateOperationMode,
    inner_allowed: bool,
    inner_reason: str,
) -> tuple[bool, str]:
    """Simulate the outer gate wrapper from FlowMaturityContext.

    When mode is COLLECT_ONLY and inner denies, outer returns allowed
    with a "collect-only bypass" reason.  When mode enforces the gate,
    the inner result passes through unchanged.

    This mirrors ``evaluate_unflattening_gate`` at context.py:144-160
    and ``evaluate_fix_predecessor_gate`` at context.py:201-216.
    """
    if not inner_allowed and not mode.enforces_gate:
        return True, f"collect-only bypass (underlying: {inner_reason})"
    return inner_allowed, inner_reason


# ---------------------------------------------------------------------------
# Test 1: COLLECT_ONLY always allows
# ---------------------------------------------------------------------------


class TestGateModeCollectOnlyAlwaysAllows:
    """Gate in COLLECT_ONLY mode overrides inner denial to allowed."""

    def test_inner_denial_is_overridden(self) -> None:
        allowed, reason = _simulate_gate_evaluation(
            mode=GateOperationMode.COLLECT_ONLY,
            inner_allowed=False,
            inner_reason="no dispatcher candidates",
        )
        assert allowed is True
        assert "collect-only" in reason

    def test_inner_approval_passes_through(self) -> None:
        allowed, reason = _simulate_gate_evaluation(
            mode=GateOperationMode.COLLECT_ONLY,
            inner_allowed=True,
            inner_reason="switch-table dispatcher",
        )
        assert allowed is True
        assert reason == "switch-table dispatcher"


# ---------------------------------------------------------------------------
# Test 2: GATE_ONLY fails closed
# ---------------------------------------------------------------------------


class TestGateModeGateOnlyFailsClosed:
    """Gate in GATE_ONLY mode passes inner denial through (fail-closed)."""

    def test_inner_denial_passes_through(self) -> None:
        allowed, reason = _simulate_gate_evaluation(
            mode=GateOperationMode.GATE_ONLY,
            inner_allowed=False,
            inner_reason="no dispatcher candidates",
        )
        assert allowed is False
        assert reason == "no dispatcher candidates"

    def test_inner_approval_passes_through(self) -> None:
        allowed, reason = _simulate_gate_evaluation(
            mode=GateOperationMode.GATE_ONLY,
            inner_allowed=True,
            inner_reason="conditional-chain dispatcher",
        )
        assert allowed is True


# ---------------------------------------------------------------------------
# Test 3: GATE_SELECT also fails closed
# ---------------------------------------------------------------------------


class TestGateModeGateSelectFailsClosed:
    """Gate in GATE_SELECT mode also fails closed (not just GATE_ONLY)."""

    def test_inner_denial_passes_through(self) -> None:
        allowed, reason = _simulate_gate_evaluation(
            mode=GateOperationMode.GATE_SELECT,
            inner_allowed=False,
            inner_reason="unknown dispatcher profile too weak",
        )
        assert allowed is False
        assert reason == "unknown dispatcher profile too weak"

    def test_inner_approval_passes_through(self) -> None:
        allowed, reason = _simulate_gate_evaluation(
            mode=GateOperationMode.GATE_SELECT,
            inner_allowed=True,
            inner_reason="unknown dispatcher with strong candidates",
        )
        assert allowed is True


# ---------------------------------------------------------------------------
# Test 4: GateVerdict enum completeness
# ---------------------------------------------------------------------------


class TestGateVerdictEnumCompleteness:
    """GateVerdict has exactly PASSED, FAILED, BYPASSED, SKIPPED."""

    def test_has_exactly_four_members(self) -> None:
        assert len(GateVerdict) == 4

    def test_expected_members_present(self) -> None:
        expected = {"PASSED", "FAILED", "BYPASSED", "SKIPPED"}
        actual = {v.name for v in GateVerdict}
        assert actual == expected

    def test_no_none_or_empty_value(self) -> None:
        for v in GateVerdict:
            assert v.value is not None
            assert v.value != ""


# ---------------------------------------------------------------------------
# Test 5: GateAccounting tracks all decisions
# ---------------------------------------------------------------------------


class TestGateAccountingTracksAllDecisions:
    """GateAccounting correctly counts, queries, and reports mixed verdicts."""

    def test_mixed_verdicts_counted_correctly(self) -> None:
        acct = GateAccounting()
        acct = acct.add(_make_decision(verdict=GateVerdict.PASSED, reason="ok"))
        acct = acct.add(_make_decision(verdict=GateVerdict.PASSED, reason="ok2"))
        acct = acct.add(_make_decision(verdict=GateVerdict.FAILED, reason="denied"))
        acct = acct.add(_make_decision(verdict=GateVerdict.BYPASSED, reason="bypass"))

        assert acct.passed_count == 2
        assert acct.failed_count == 1
        assert acct.bypassed_count == 1
        assert not acct.all_passed
        assert acct.any_failed()

    def test_all_passed_when_only_passes(self) -> None:
        acct = GateAccounting()
        acct = acct.add(_make_decision(verdict=GateVerdict.PASSED, reason="ok"))
        acct = acct.add(_make_decision(verdict=GateVerdict.PASSED, reason="ok2"))

        assert acct.all_passed is True
        assert acct.any_failed() is False

    def test_all_passed_true_for_empty(self) -> None:
        """Empty accounting vacuously satisfies all_passed (no failures)."""
        acct = GateAccounting()
        assert acct.all_passed is True

    def test_decisions_tuple_preserves_order(self) -> None:
        d1 = _make_decision(gate_name="g1", reason="r1")
        d2 = _make_decision(gate_name="g2", reason="r2")
        acct = GateAccounting().add(d1).add(d2)
        assert acct.decisions == (d1, d2)


# ---------------------------------------------------------------------------
# Test 6: GateDecision records strict_mode bit
# ---------------------------------------------------------------------------


class TestGateDecisionRecordsStrictModeBit:
    """strict_mode flag is preserved and queryable on GateDecision."""

    def test_strict_mode_true_preserved(self) -> None:
        d = _make_decision(strict_mode=True)
        assert d.strict_mode is True

    def test_strict_mode_false_preserved(self) -> None:
        d = _make_decision(strict_mode=False)
        assert d.strict_mode is False

    def test_strict_mode_queryable_across_accounting(self) -> None:
        acct = GateAccounting()
        acct = acct.add(_make_decision(strict_mode=True, reason="strict"))
        acct = acct.add(_make_decision(strict_mode=False, reason="lenient"))

        strict_decisions = [d for d in acct.decisions if d.strict_mode]
        assert len(strict_decisions) == 1
        assert strict_decisions[0].reason == "strict"


# ---------------------------------------------------------------------------
# Test 7: enforces_gate property matches mode semantics
# ---------------------------------------------------------------------------


class TestEnforcesGatePropertyMatchesModeSemantics:
    """enforces_gate is False for COLLECT_ONLY, True for GATE_ONLY/GATE_SELECT."""

    def test_collect_only_does_not_enforce(self) -> None:
        assert GateOperationMode.COLLECT_ONLY.enforces_gate is False

    def test_gate_only_enforces(self) -> None:
        assert GateOperationMode.GATE_ONLY.enforces_gate is True

    def test_gate_select_enforces(self) -> None:
        assert GateOperationMode.GATE_SELECT.enforces_gate is True


# ---------------------------------------------------------------------------
# Test 8: influences_planner property matches mode semantics
# ---------------------------------------------------------------------------


class TestInfluencesPlannerPropertyMatchesModeSemantics:
    """Only GATE_SELECT influences the planner."""

    def test_collect_only_no_influence(self) -> None:
        assert GateOperationMode.COLLECT_ONLY.influences_planner is False

    def test_gate_only_no_influence(self) -> None:
        assert GateOperationMode.GATE_ONLY.influences_planner is False

    def test_gate_select_influences(self) -> None:
        assert GateOperationMode.GATE_SELECT.influences_planner is True


# ---------------------------------------------------------------------------
# Test 9: Denied gate decisions always have non-empty reason
# ---------------------------------------------------------------------------


class TestFlowGateDecisionDeniedHasReason:
    """When a gate denies, the reason string must be non-empty."""

    def test_failed_verdict_with_reason(self) -> None:
        d = _make_decision(verdict=GateVerdict.FAILED, reason="no dispatcher candidates")
        assert d.reason
        assert len(d.reason) > 0

    def test_all_verdicts_carry_reason_in_accounting(self) -> None:
        acct = GateAccounting()
        acct = acct.add(_make_decision(verdict=GateVerdict.PASSED, reason="ok"))
        acct = acct.add(_make_decision(verdict=GateVerdict.FAILED, reason="denied"))
        acct = acct.add(_make_decision(verdict=GateVerdict.BYPASSED, reason="bypass"))
        acct = acct.add(_make_decision(verdict=GateVerdict.SKIPPED, reason="skipped"))

        for d in acct.decisions:
            assert d.reason, f"Decision for {d.gate_name} has empty reason"


# ---------------------------------------------------------------------------
# Test 10: No silent bypass -- every BYPASSED has a reason
# ---------------------------------------------------------------------------


class TestGateAccountingNoSilentBypass:
    """Every BYPASSED verdict must have a non-empty reason.

    No decision may have verdict=None or reason=""."""

    def test_realistic_gate_sequence_all_reasons_present(self) -> None:
        acct = GateAccounting()
        acct = acct.add(_make_decision(
            gate_name="ep1", verdict=GateVerdict.PASSED,
            reason="switch-table dispatcher",
        ))
        acct = acct.add(_make_decision(
            gate_name="ep3", verdict=GateVerdict.BYPASSED,
            reason="collect-only bypass: no strong dispatcher",
        ))
        acct = acct.add(_make_decision(
            gate_name="ep4", verdict=GateVerdict.SKIPPED,
            reason="preconditioner disabled by config",
        ))
        acct = acct.add(_make_decision(
            gate_name="ep5", verdict=GateVerdict.FAILED,
            reason="max dispatcher predecessors 1 < 3",
        ))

        for d in acct.decisions:
            assert d.reason, f"Decision for {d.gate_name} has empty reason"
            assert d.verdict is not None, f"Decision for {d.gate_name} has None verdict"

    def test_no_none_verdict_possible(self) -> None:
        """GateVerdict is an enum; None is not a valid member."""
        with pytest.raises((ValueError, KeyError)):
            GateVerdict(None)  # type: ignore[arg-type]

    def test_bypassed_decisions_all_have_reasons(self) -> None:
        acct = GateAccounting()
        acct = acct.add(_make_decision(
            verdict=GateVerdict.BYPASSED,
            reason="collect-only bypass: profile too weak",
        ))
        acct = acct.add(_make_decision(
            verdict=GateVerdict.BYPASSED,
            reason="BYPASSED_CONFIG_DISABLED: require_unflattening_gate=False",
        ))

        bypassed = [d for d in acct.decisions if d.verdict == GateVerdict.BYPASSED]
        assert len(bypassed) == 2
        for d in bypassed:
            assert d.reason, f"BYPASSED decision for {d.gate_name} has empty reason"


# ---------------------------------------------------------------------------
# Test 11: DecisionReasonCode covers all gate outcomes
# ---------------------------------------------------------------------------


class TestDecisionReasonCodeCoversAllGateOutcomes:
    """DecisionReasonCode has all required gate outcome categories."""

    REQUIRED_GATE_CODES = {
        "ACCEPTED",
        "REJECTED_GATE",
        "REJECTED_GATE_SAFEGUARD",
        "REJECTED_GATE_SEMANTIC",
        "BYPASSED",
        "BYPASSED_SAFEGUARD",
        "BYPASSED_STRICT_MODE_DISABLED",
    }

    def test_all_required_gate_codes_present(self) -> None:
        actual = {rc.name for rc in DecisionReasonCode}
        missing = self.REQUIRED_GATE_CODES - actual
        assert not missing, f"Missing required gate codes: {missing}"

    def test_no_empty_values(self) -> None:
        for rc in DecisionReasonCode:
            assert rc.value, f"{rc.name} has empty value"


# ---------------------------------------------------------------------------
# Test 12: Preconditioner bypass explicit in COLLECT_ONLY
# ---------------------------------------------------------------------------


class TestPreconditionerGateBypassExplicitInCollectOnly:
    """When require_unflattening_gate=False, behavior maps to COLLECT_ONLY."""

    def test_config_disabled_maps_to_collect_only_semantics(self) -> None:
        require_unflattening_gate = False
        mode = (
            GateOperationMode.GATE_SELECT
            if require_unflattening_gate
            else GateOperationMode.COLLECT_ONLY
        )
        assert mode is GateOperationMode.COLLECT_ONLY
        assert not mode.enforces_gate

    def test_bypass_recorded_explicitly_in_accounting(self) -> None:
        """Accounting records a BYPASSED decision, not silence."""
        acct = GateAccounting()
        acct = acct.add(GateDecision(
            gate_name="ep4_preconditioner",
            verdict=GateVerdict.BYPASSED,
            reason="BYPASSED_CONFIG_DISABLED: require_unflattening_gate=False",
            strict_mode=False,
        ))
        assert acct.bypassed_count == 1
        assert not acct.any_failed()
        assert acct.decisions[0].reason.startswith("BYPASSED_CONFIG_DISABLED")

    def test_config_enabled_maps_to_gate_select(self) -> None:
        require_unflattening_gate = True
        mode = (
            GateOperationMode.GATE_SELECT
            if require_unflattening_gate
            else GateOperationMode.COLLECT_ONLY
        )
        assert mode is GateOperationMode.GATE_SELECT
        assert mode.enforces_gate


# ---------------------------------------------------------------------------
# Test 13: Gate mode transition consistency
# ---------------------------------------------------------------------------


class TestGateModeTransitionConsistency:
    """Changing gate mode changes gate behavior consistently.

    FlowMaturityContext requires IDA (mba_t), so we test only the
    GateOperationMode contract via the simulation helper.
    """

    def test_same_inner_denial_different_mode_different_outcome(self) -> None:
        inner_allowed = False
        inner_reason = "no dispatcher candidates"

        # GATE_ONLY: denial passes through
        allowed_strict, _ = _simulate_gate_evaluation(
            GateOperationMode.GATE_ONLY, inner_allowed, inner_reason,
        )
        assert allowed_strict is False

        # COLLECT_ONLY: denial overridden to allow
        allowed_lenient, reason_lenient = _simulate_gate_evaluation(
            GateOperationMode.COLLECT_ONLY, inner_allowed, inner_reason,
        )
        assert allowed_lenient is True
        assert "collect-only" in reason_lenient

    def test_approval_unaffected_by_mode_change(self) -> None:
        inner_allowed = True
        inner_reason = "switch-table dispatcher"

        for mode in GateOperationMode:
            allowed, reason = _simulate_gate_evaluation(mode, inner_allowed, inner_reason)
            assert allowed is True, f"Mode {mode.name} incorrectly blocked an approval"
            assert reason == inner_reason

    def test_all_strict_modes_deny_consistently(self) -> None:
        """Both GATE_ONLY and GATE_SELECT must deny when inner denies."""
        strict_modes = [m for m in GateOperationMode if m.enforces_gate]
        assert len(strict_modes) == 2  # GATE_ONLY, GATE_SELECT

        for mode in strict_modes:
            allowed, _ = _simulate_gate_evaluation(
                mode, inner_allowed=False, inner_reason="test denial",
            )
            assert allowed is False, (
                f"{mode.name} did not fail-closed on inner denial"
            )
