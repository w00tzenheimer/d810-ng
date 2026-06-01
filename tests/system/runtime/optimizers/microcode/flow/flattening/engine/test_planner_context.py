"""Unit tests for engine.planner_context.

Covers:
- LinearizationDecision / StateWriteNeutralization immutability + hashing
- PlannerContextContribution default construction
- CumulativePlannerView query helpers (is_linearized, target_for,
  original_state_for, is_claimed)
- CumulativePlannerView.compile aggregation across fake fragments
- Tolerance of fragments lacking the planner_ctx key or lacking
  ``metadata`` entirely
- Mode 1 regression: replay the sub_7FFD blk[76] pattern and assert
  a second-pass planner sees the prior linearization
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from d810.core.typing import Any

from d810.transforms.planner_context import (
    PLANNER_CTX_METADATA_KEY,
    CumulativePlannerView,
    LinearizationDecision,
    PlannerContextContribution,
    StateWriteNeutralization,
)


# ---------------------------------------------------------------------------
# Fake fragment shim — enough surface to feed CumulativePlannerView.compile.
# ---------------------------------------------------------------------------

@dataclass
class _FakeFragment:
    """Duck-typed stand-in for a PlanFragment."""

    metadata: dict[str, Any] = field(default_factory=dict)


def _contribution(
    *,
    lins: tuple[LinearizationDecision, ...] = (),
    neuts: tuple[StateWriteNeutralization, ...] = (),
    claimed: frozenset[int] = frozenset(),
) -> PlannerContextContribution:
    return PlannerContextContribution(
        linearizations=lins,
        neutralizations=neuts,
        claimed_sources=claimed,
    )


def _frag_with(contribution: PlannerContextContribution | None) -> _FakeFragment:
    meta: dict[str, Any] = {}
    if contribution is not None:
        meta[PLANNER_CTX_METADATA_KEY] = contribution
    return _FakeFragment(metadata=meta)


# ---------------------------------------------------------------------------
# Value types
# ---------------------------------------------------------------------------

class TestValueTypes:
    def test_linearization_decision_is_hashable(self) -> None:
        d1 = LinearizationDecision(src=76, tgt=11, reason="residual", strategy="srw", round_index=0)
        d2 = LinearizationDecision(src=76, tgt=11, reason="residual", strategy="srw", round_index=0)
        # Frozen + slots + hashable -> equal instances collapse into the
        # same set entry. This is what lets CumulativePlannerView dedupe.
        assert hash(d1) == hash(d2)
        assert {d1, d2} == {d1}

    def test_state_write_neutralization_is_hashable(self) -> None:
        n1 = StateWriteNeutralization(src=76, original_state_constant=0x63B2C08B, strategy="srw", round_index=0)
        n2 = StateWriteNeutralization(src=76, original_state_constant=0x63B2C08B, strategy="srw", round_index=0)
        assert {n1, n2} == {n1}

    def test_contribution_defaults_are_empty(self) -> None:
        c = PlannerContextContribution()
        assert c.linearizations == ()
        assert c.neutralizations == ()
        assert c.claimed_sources == frozenset()

    def test_canonical_metadata_key_is_stable(self) -> None:
        # Catch accidental rename of the module-level constant. Any rename
        # must be coordinated with every strategy that writes/reads this key.
        assert PLANNER_CTX_METADATA_KEY == "planner_ctx"


# ---------------------------------------------------------------------------
# CumulativePlannerView queries
# ---------------------------------------------------------------------------

class TestCumulativeViewQueries:
    def test_is_linearized_false_when_empty(self) -> None:
        view = CumulativePlannerView.empty()
        assert view.is_linearized(76) is False
        assert view.linearization_target_for(76) is None
        assert view.original_state_for(76) is None
        assert view.is_claimed(76) is False

    def test_is_linearized_detects_matching_src(self) -> None:
        d = LinearizationDecision(src=76, tgt=11, reason="residual_handoff", strategy="srw", round_index=0)
        view = CumulativePlannerView(
            linearization_decisions=frozenset({d}),
            neutralized_state_writes=frozenset(),
            claimed_sources=frozenset(),
        )
        assert view.is_linearized(76) is True
        assert view.is_linearized(77) is False

    def test_linearization_target_for_prefers_earliest_round(self) -> None:
        d_round_1 = LinearizationDecision(src=76, tgt=11, reason="residual_handoff", strategy="srw", round_index=1)
        d_round_0 = LinearizationDecision(src=76, tgt=42, reason="lfg_preheader", strategy="lfg", round_index=0)
        view = CumulativePlannerView(
            linearization_decisions=frozenset({d_round_1, d_round_0}),
            neutralized_state_writes=frozenset(),
            claimed_sources=frozenset(),
        )
        # First decision wins; later strategies should observe that
        # commitment rather than the "latest" one.
        assert view.linearization_target_for(76) == 42

    def test_original_state_for_returns_pre_neutralization_constant(self) -> None:
        n = StateWriteNeutralization(src=76, original_state_constant=0x63B2C08B, strategy="srw", round_index=0)
        view = CumulativePlannerView(
            linearization_decisions=frozenset(),
            neutralized_state_writes=frozenset({n}),
            claimed_sources=frozenset(),
        )
        assert view.original_state_for(76) == 0x63B2C08B
        assert view.original_state_for(99) is None

    def test_is_claimed_reflects_claimed_sources(self) -> None:
        view = CumulativePlannerView(
            linearization_decisions=frozenset(),
            neutralized_state_writes=frozenset(),
            claimed_sources=frozenset({76, 111}),
        )
        assert view.is_claimed(76) is True
        assert view.is_claimed(77) is False


# ---------------------------------------------------------------------------
# CumulativePlannerView.compile
# ---------------------------------------------------------------------------

class TestCumulativeViewCompile:
    def test_empty_fragment_list_yields_empty_view(self) -> None:
        view = CumulativePlannerView.compile([])
        assert view == CumulativePlannerView.empty()

    def test_fragments_without_metadata_are_skipped(self) -> None:
        # A bare object with no metadata must not crash compile.
        class _Barebones:
            pass

        view = CumulativePlannerView.compile([_Barebones(), _FakeFragment()])
        assert view == CumulativePlannerView.empty()

    def test_fragments_without_planner_ctx_key_are_skipped(self) -> None:
        frag = _FakeFragment(metadata={"other_key": "other_value"})
        view = CumulativePlannerView.compile([frag])
        assert view == CumulativePlannerView.empty()

    def test_fragments_with_wrong_type_under_planner_ctx_are_skipped(self) -> None:
        # Defensive: a dict under the planner_ctx key should not break compile.
        frag = _FakeFragment(metadata={PLANNER_CTX_METADATA_KEY: {"not": "a contribution"}})
        view = CumulativePlannerView.compile([frag])
        assert view == CumulativePlannerView.empty()

    def test_aggregates_across_multiple_fragments(self) -> None:
        d1 = LinearizationDecision(src=76, tgt=11, reason="residual_handoff", strategy="srw", round_index=0)
        n1 = StateWriteNeutralization(src=76, original_state_constant=0x63B2C08B, strategy="srw", round_index=0)
        d2 = LinearizationDecision(src=54, tgt=100, reason="dag_bridge", strategy="srw", round_index=0)

        frag_a = _frag_with(_contribution(lins=(d1,), neuts=(n1,), claimed=frozenset({76})))
        frag_b = _frag_with(_contribution(lins=(d2,), claimed=frozenset({54})))
        frag_c = _frag_with(None)  # no contribution — still aggregated cleanly

        view = CumulativePlannerView.compile([frag_a, frag_b, frag_c])
        assert view.linearization_decisions == frozenset({d1, d2})
        assert view.neutralized_state_writes == frozenset({n1})
        assert view.claimed_sources == frozenset({76, 54})

    def test_duplicate_decisions_dedupe_via_frozenset(self) -> None:
        d = LinearizationDecision(src=76, tgt=11, reason="residual_handoff", strategy="srw", round_index=0)
        frag_a = _frag_with(_contribution(lins=(d,)))
        frag_b = _frag_with(_contribution(lins=(d,)))
        view = CumulativePlannerView.compile([frag_a, frag_b])
        assert len(view.linearization_decisions) == 1


# ---------------------------------------------------------------------------
# Mode 1 regression scenario
# ---------------------------------------------------------------------------

class TestMode1Regression:
    """Replay the sub_7FFD blk[76] pattern in pure-Python and assert a
    second-pass planner using the view refuses to emit a reverse redirect.
    """

    def test_second_pass_observes_linearization_and_skips_reverse_redirect(self) -> None:
        # Round 0: SRW linearizes blk[76] from dispatcher (2) to handler (11),
        # and neutralizes its state write (original was 0x63B2C08B).
        first_pass = _frag_with(_contribution(
            lins=(LinearizationDecision(
                src=76, tgt=11, reason="residual_handoff",
                strategy="srw", round_index=0,
            ),),
            neuts=(StateWriteNeutralization(
                src=76, original_state_constant=0x63B2C08B,
                strategy="srw", round_index=0,
            ),),
            claimed=frozenset({76}),
        ))

        # Engine compiles cumulative view before round 1 strategy runs.
        view = CumulativePlannerView.compile([first_pass])

        # Round 1: a later strategy scanning the projected graph considers
        # emitting RedirectGoto src=76 tgt=2 (back to dispatcher) because it
        # sees a "stateless" block routing into a handler. With planner_ctx
        # available, it checks before acting:
        def would_emit_reverse_redirect(src: int, view: CumulativePlannerView) -> bool:
            if view.is_linearized(src):
                return False
            if view.is_claimed(src):
                return False
            return True

        assert would_emit_reverse_redirect(76, view) is False
        # Sanity check: blocks NOT claimed by prior rounds remain fair game.
        assert would_emit_reverse_redirect(99, view) is True

    def test_second_pass_can_recover_original_state_constant(self) -> None:
        # A later strategy that wants to reason about the original handler
        # exit (before ZeroStateWrite neutralized it) can retrieve it.
        view = CumulativePlannerView.compile([_frag_with(_contribution(
            neuts=(StateWriteNeutralization(
                src=76, original_state_constant=0x63B2C08B,
                strategy="srw", round_index=0,
            ),),
        ))])
        assert view.original_state_for(76) == 0x63B2C08B


# ---------------------------------------------------------------------------
# Phase 2 of uee-jrgq — DagAuthority threading through CumulativePlannerView
# ---------------------------------------------------------------------------


class TestDagAuthorityThreading:
    """Phase 2 plumbing: CumulativePlannerView carries an optional
    DagAuthority through compile()/empty() so consumers can do
    DAG-conformance checks (Phase 3 wiring)."""

    def test_empty_defaults_to_no_authority(self) -> None:
        view = CumulativePlannerView.empty()
        assert view.dag_authority is None

    def test_compile_defaults_to_no_authority(self) -> None:
        view = CumulativePlannerView.compile([])
        assert view.dag_authority is None

    def test_empty_carries_authority_when_provided(self) -> None:
        sentinel = object()  # stand-in DagAuthority — view doesn't dispatch
        view = CumulativePlannerView.empty(dag_authority=sentinel)  # type: ignore[arg-type]
        assert view.dag_authority is sentinel

    def test_compile_carries_authority_when_provided(self) -> None:
        sentinel = object()
        view = CumulativePlannerView.compile([], dag_authority=sentinel)  # type: ignore[arg-type]
        assert view.dag_authority is sentinel

    def test_compile_authority_persists_across_iterations(self) -> None:
        # Simulate the planner's loop: same authority threaded through
        # multiple compile() calls as fragments accumulate.
        sentinel = object()
        v1 = CumulativePlannerView.compile([], dag_authority=sentinel)  # type: ignore[arg-type]
        # Pretend we got a fragment; rebuild with the same authority.
        v2 = CumulativePlannerView.compile([], dag_authority=sentinel)  # type: ignore[arg-type]
        assert v1.dag_authority is sentinel
        assert v2.dag_authority is sentinel
        assert v1.dag_authority is v2.dag_authority

    def test_authority_is_optional_existing_callers_unaffected(self) -> None:
        # Backward-compat: callers that pass only fragments still work.
        view = CumulativePlannerView.compile([])
        assert view.dag_authority is None
        # Existing query methods unaffected by the new field.
        assert view.is_linearized(99) is False
        assert view.linearization_target_for(99) is None
        assert view.is_claimed(99) is False
