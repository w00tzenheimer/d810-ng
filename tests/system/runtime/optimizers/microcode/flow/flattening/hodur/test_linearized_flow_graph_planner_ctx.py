"""Tests for LFG/SSR planner_ctx integration at fragment finalization.

Validates the contributor side of the engine-level coordination mechanism:
the LinearizedFlowGraphStrategy and SemanticStructuredRegionStrategy
terminal PlanFragment MUST carry a PlannerContextContribution under
``metadata["planner_ctx"]`` so later strategies (same pipeline) can
observe its LinearizationDecisions via CumulativePlannerView.

Symmetric to ``test_reconstruction_fragment_builder.py`` which covers the
SRW contributor. We exercise ``_build_linearized_flow_graph_plan_fragment``
directly with a synthetic ``LinearizedFlowGraphPlanningResult`` so the test
stays purely in-process (no IDA decompilation needed).
"""
from __future__ import annotations

from types import SimpleNamespace

from d810.cfg.graph_modification import RedirectGoto, ZeroStateWrite
from d810.optimizers.microcode.flow.flattening.engine.planner_context import (
    PLANNER_CTX_METADATA_KEY,
    CumulativePlannerView,
    PlannerContextContribution,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.linearized_flow_graph import (
    _build_linearized_flow_graph_plan_fragment,
)


def _fake_state_machine(handler_count: int = 3) -> SimpleNamespace:
    """Minimal state machine stub exposing just ``handlers``."""
    return SimpleNamespace(handlers={i: object() for i in range(handler_count)})


def _fake_planning_result(
    *,
    modifications: tuple | None = None,
    owned_blocks: frozenset[int] | None = None,
    owned_edges: frozenset[tuple[int, int]] | None = None,
    owned_transitions: frozenset[tuple[int, int]] | None = None,
    transition_count: int = 0,
    conditional_count: int = 0,
    cleanup_gate_reason: str | None = None,
) -> SimpleNamespace:
    """Mimic a :class:`LinearizedFlowGraphPlanningResult` for the builder."""
    if modifications is None:
        modifications = (RedirectGoto(from_serial=10, old_target=20, new_target=30),)
    if owned_blocks is None:
        owned_blocks = frozenset({10})
    if owned_edges is None:
        owned_edges = frozenset()
    if owned_transitions is None:
        owned_transitions = frozenset()
    return SimpleNamespace(
        accepted=True,
        modifications=modifications,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        owned_transitions=owned_transitions,
        transition_count=transition_count,
        conditional_count=conditional_count,
        terminal_skipped=0,
        unknown_skipped=0,
        skipped_count=0,
        disconnect_count=0,
        cleanup_gate_reason=cleanup_gate_reason,
        residual_dispatcher_preds=(),
        residual_dispatcher_redirect_count=0,
        residual_dispatcher_normalized_count=0,
        dead_island_cleanup_count=0,
        unresolved_bst_targets=0,
    )


def _minimal_fragment(
    *,
    strategy_name: str = "linearized_flow_graph",
    modifications: tuple | None = None,
    owned_blocks: frozenset[int] | None = None,
    round_index: int = 0,
):
    return _build_linearized_flow_graph_plan_fragment(
        strategy_name=strategy_name,
        family="direct",
        prerequisites=[],
        state_machine=_fake_state_machine(),
        bst_node_blocks=frozenset(),
        result=_fake_planning_result(
            modifications=modifications,
            owned_blocks=owned_blocks,
        ),
        round_index=round_index,
    )


class TestPlannerCtxContribution:
    def test_metadata_carries_planner_ctx_key(self) -> None:
        frag = _minimal_fragment()
        assert PLANNER_CTX_METADATA_KEY in frag.metadata

    def test_planner_ctx_value_is_a_contribution(self) -> None:
        frag = _minimal_fragment()
        ctx = frag.metadata[PLANNER_CTX_METADATA_KEY]
        assert isinstance(ctx, PlannerContextContribution)

    def test_linearizations_built_from_redirect_goto_mods(self) -> None:
        mods = (
            RedirectGoto(from_serial=76, old_target=2, new_target=11),
            RedirectGoto(from_serial=54, old_target=2, new_target=100),
        )
        frag = _minimal_fragment(
            modifications=mods,
            owned_blocks=frozenset({76, 54}),
        )
        ctx: PlannerContextContribution = frag.metadata[PLANNER_CTX_METADATA_KEY]
        assert len(ctx.linearizations) == 2
        srcs = {d.src for d in ctx.linearizations}
        tgts = {d.tgt for d in ctx.linearizations}
        assert srcs == {76, 54}
        assert tgts == {11, 100}

    def test_linearization_decisions_record_strategy_and_round_lfg(self) -> None:
        mods = (RedirectGoto(from_serial=76, old_target=2, new_target=11),)
        frag = _minimal_fragment(
            strategy_name="linearized_flow_graph",
            modifications=mods,
            round_index=2,
        )
        ctx: PlannerContextContribution = frag.metadata[PLANNER_CTX_METADATA_KEY]
        (decision,) = ctx.linearizations
        assert decision.strategy == "linearized_flow_graph"
        assert decision.round_index == 2
        assert decision.reason == "linearized_flow_graph"

    def test_linearization_decisions_record_strategy_and_round_ssr(self) -> None:
        mods = (RedirectGoto(from_serial=76, old_target=2, new_target=11),)
        frag = _minimal_fragment(
            strategy_name="semantic_structured_region",
            modifications=mods,
            round_index=1,
        )
        ctx: PlannerContextContribution = frag.metadata[PLANNER_CTX_METADATA_KEY]
        (decision,) = ctx.linearizations
        assert decision.strategy == "semantic_structured_region"
        assert decision.round_index == 1
        assert decision.reason == "semantic_structured_region"

    def test_claimed_sources_populated_from_owned_blocks(self) -> None:
        frag = _minimal_fragment(owned_blocks=frozenset({76, 100, 156}))
        ctx: PlannerContextContribution = frag.metadata[PLANNER_CTX_METADATA_KEY]
        assert ctx.claimed_sources == frozenset({76, 100, 156})

    def test_neutralizations_empty_for_now(self) -> None:
        # Explicit: StateWriteNeutralization is not built in this first pass
        # (ZeroStateWrite mod doesn't carry the pre-zeroing constant).
        mods = (
            RedirectGoto(from_serial=76, old_target=2, new_target=11),
            ZeroStateWrite(block_serial=76, insn_ea=0x180013D94),
        )
        frag = _minimal_fragment(modifications=mods)
        ctx: PlannerContextContribution = frag.metadata[PLANNER_CTX_METADATA_KEY]
        assert ctx.neutralizations == ()

    def test_non_redirect_mods_do_not_produce_linearizations(self) -> None:
        mods = (ZeroStateWrite(block_serial=76, insn_ea=0x1000),)
        frag = _minimal_fragment(modifications=mods)
        ctx: PlannerContextContribution = frag.metadata[PLANNER_CTX_METADATA_KEY]
        assert ctx.linearizations == ()

    def test_default_round_index_is_zero(self) -> None:
        # Regression: the builder accepts round_index with a default so
        # existing callers that don't thread rounds still get a sensible
        # contribution.
        mods = (RedirectGoto(from_serial=76, old_target=2, new_target=11),)
        frag = _minimal_fragment(modifications=mods)
        ctx: PlannerContextContribution = frag.metadata[PLANNER_CTX_METADATA_KEY]
        (decision,) = ctx.linearizations
        assert decision.round_index == 0


class TestCumulativeViewCompilesFromLfgFragment:
    """End-to-end: the engine's CumulativePlannerView.compile must pick up
    the contribution LFG / SSR attached in the shared fragment finalizer.
    """

    def test_later_strategy_sees_lfg_linearization(self) -> None:
        frag = _minimal_fragment(
            strategy_name="linearized_flow_graph",
            modifications=(
                RedirectGoto(from_serial=76, old_target=2, new_target=11),
            ),
            owned_blocks=frozenset({76}),
            round_index=0,
        )
        view = CumulativePlannerView.compile([frag])

        assert view.is_linearized(76) is True
        assert view.linearization_target_for(76) == 11
        assert view.is_claimed(76) is True

        assert view.is_linearized(99) is False
        assert view.is_claimed(99) is False

    def test_later_strategy_sees_ssr_linearization(self) -> None:
        frag = _minimal_fragment(
            strategy_name="semantic_structured_region",
            modifications=(
                RedirectGoto(from_serial=54, old_target=2, new_target=100),
            ),
            owned_blocks=frozenset({54}),
            round_index=0,
        )
        view = CumulativePlannerView.compile([frag])

        assert view.is_linearized(54) is True
        assert view.linearization_target_for(54) == 100
        assert view.is_claimed(54) is True
