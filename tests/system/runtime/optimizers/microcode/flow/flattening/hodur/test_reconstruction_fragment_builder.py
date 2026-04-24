"""Tests for finalize_reconstruction_fragment's planner_ctx integration.

Validates the contributor side of the engine-level coordination mechanism:
the SRW strategy's terminal PlanFragment MUST carry a
PlannerContextContribution under ``metadata["planner_ctx"]`` so later
strategies (same pipeline) can observe its LinearizationDecisions via
CumulativePlannerView.
"""
from __future__ import annotations

import pytest

from d810.cfg.graph_modification import RedirectGoto, ZeroStateWrite
from d810.optimizers.microcode.flow.flattening.engine.planner_context import (
    PLANNER_CTX_METADATA_KEY,
    CumulativePlannerView,
    LinearizationDecision,
    PlannerContextContribution,
)
from d810.optimizers.microcode.flow.flattening.hodur.reconstruction_fragment_builder import (
    finalize_reconstruction_fragment,
)


def _minimal_fragment(
    *,
    modifications: list | None = None,
    owned_blocks: set[int] | None = None,
    round_index: int = 0,
):
    return finalize_reconstruction_fragment(
        strategy_name="state_write_reconstruction",
        modifications=list(modifications) if modifications is not None else [
            RedirectGoto(from_serial=1, old_target=2, new_target=3),
        ],
        owned_blocks=owned_blocks if owned_blocks is not None else {1},
        owned_edges=frozenset(),
        accepted_metadata=[],
        rejected_metadata=[],
        allow_post_apply_bst_cleanup=True,
        post_apply_bst_cleanup_reason=None,
        residual_dispatcher_preds=(),
        structured_region_fidelity=None,
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
        mods = [
            RedirectGoto(from_serial=76, old_target=2, new_target=11),
            RedirectGoto(from_serial=54, old_target=2, new_target=100),
        ]
        frag = _minimal_fragment(modifications=mods, owned_blocks={76, 54})
        ctx: PlannerContextContribution = frag.metadata[PLANNER_CTX_METADATA_KEY]
        assert len(ctx.linearizations) == 2
        srcs = {d.src for d in ctx.linearizations}
        tgts = {d.tgt for d in ctx.linearizations}
        assert srcs == {76, 54}
        assert tgts == {11, 100}

    def test_linearization_decisions_record_strategy_and_round(self) -> None:
        mods = [RedirectGoto(from_serial=76, old_target=2, new_target=11)]
        frag = _minimal_fragment(modifications=mods, round_index=2)
        ctx: PlannerContextContribution = frag.metadata[PLANNER_CTX_METADATA_KEY]
        (decision,) = ctx.linearizations
        assert decision.strategy == "state_write_reconstruction"
        assert decision.round_index == 2
        assert decision.reason == "state_write_reconstruction"

    def test_claimed_sources_populated_from_owned_blocks(self) -> None:
        frag = _minimal_fragment(owned_blocks={76, 100, 156})
        ctx: PlannerContextContribution = frag.metadata[PLANNER_CTX_METADATA_KEY]
        assert ctx.claimed_sources == frozenset({76, 100, 156})

    def test_neutralizations_empty_for_now(self) -> None:
        # Explicit: StateWriteNeutralization is not built in this first pass
        # (ZeroStateWrite mod doesn't carry the pre-zeroing constant).
        mods = [
            RedirectGoto(from_serial=76, old_target=2, new_target=11),
            ZeroStateWrite(block_serial=76, insn_ea=0x180013d94),
        ]
        frag = _minimal_fragment(modifications=mods)
        ctx: PlannerContextContribution = frag.metadata[PLANNER_CTX_METADATA_KEY]
        assert ctx.neutralizations == ()

    def test_non_redirect_mods_do_not_produce_linearizations(self) -> None:
        mods = [ZeroStateWrite(block_serial=76, insn_ea=0x1000)]
        frag = _minimal_fragment(modifications=mods)
        ctx: PlannerContextContribution = frag.metadata[PLANNER_CTX_METADATA_KEY]
        assert ctx.linearizations == ()


class TestDropConflictingRedirects:
    """The finalize_reconstruction_fragment gate — with a cumulative view,
    SRW's contradictory redirects are dropped before fragment construction.
    """

    def _view_with(self, src: int, tgt: int, strategy: str = "ssr") -> CumulativePlannerView:
        # Build a CumulativePlannerView as if a prior SSR fragment had
        # committed to src -> tgt.
        prior_frag_meta = {
            PLANNER_CTX_METADATA_KEY: PlannerContextContribution(
                linearizations=(
                    LinearizationDecision(
                        src=src, tgt=tgt, reason=strategy,
                        strategy=strategy, round_index=0,
                    ),
                ),
            ),
        }

        class _Frag:
            metadata = prior_frag_meta

        return CumulativePlannerView.compile([_Frag()])

    def test_drops_conflicting_redirect_when_view_has_prior_decision(self) -> None:
        view = self._view_with(src=76, tgt=11)  # SSR committed 76 -> 11
        # SRW emits src=76 -> 2 (the Mode 1 override)
        frag = finalize_reconstruction_fragment(
            strategy_name="state_write_reconstruction",
            modifications=[
                RedirectGoto(from_serial=76, old_target=11, new_target=2),
                RedirectGoto(from_serial=99, old_target=2, new_target=55),
            ],
            owned_blocks={76, 99},
            owned_edges=frozenset(),
            accepted_metadata=[],
            rejected_metadata=[],
            allow_post_apply_bst_cleanup=True,
            post_apply_bst_cleanup_reason=None,
            residual_dispatcher_preds=(),
            structured_region_fidelity=None,
            round_index=0,
            cumulative_planner_view=view,
        )
        srcs = {m.from_serial for m in frag.modifications if isinstance(m, RedirectGoto)}
        # blk[76] conflict dropped; blk[99] kept.
        assert srcs == {99}

    def test_keeps_matching_redirect_same_target(self) -> None:
        view = self._view_with(src=76, tgt=11)
        # SRW emits src=76 -> 11 (same target — consistent, not a conflict)
        frag = finalize_reconstruction_fragment(
            strategy_name="state_write_reconstruction",
            modifications=[
                RedirectGoto(from_serial=76, old_target=2, new_target=11),
            ],
            owned_blocks={76},
            owned_edges=frozenset(),
            accepted_metadata=[],
            rejected_metadata=[],
            allow_post_apply_bst_cleanup=True,
            post_apply_bst_cleanup_reason=None,
            residual_dispatcher_preds=(),
            structured_region_fidelity=None,
            round_index=0,
            cumulative_planner_view=view,
        )
        assert len(frag.modifications) == 1

    def test_no_view_means_no_filtering(self) -> None:
        # Without a view, all mods pass through unchanged.
        frag = finalize_reconstruction_fragment(
            strategy_name="state_write_reconstruction",
            modifications=[
                RedirectGoto(from_serial=76, old_target=11, new_target=2),
            ],
            owned_blocks={76},
            owned_edges=frozenset(),
            accepted_metadata=[],
            rejected_metadata=[],
            allow_post_apply_bst_cleanup=True,
            post_apply_bst_cleanup_reason=None,
            residual_dispatcher_preds=(),
            structured_region_fidelity=None,
            round_index=0,
            cumulative_planner_view=None,
        )
        assert len(frag.modifications) == 1


class TestCumulativeViewCompilesFromSrwFragment:
    """End-to-end: the engine's CumulativePlannerView.compile must pick up
    the contribution SRW attached in finalize_reconstruction_fragment.
    """

    def test_mode_1_scenario_visible_to_later_strategies(self) -> None:
        # SRW round 0 emits mod[26]-style redirect: blk[76] -> blk[11].
        frag = _minimal_fragment(
            modifications=[RedirectGoto(from_serial=76, old_target=2, new_target=11)],
            owned_blocks={76},
            round_index=0,
        )
        # Engine aggregates fragments before the next strategy runs.
        view = CumulativePlannerView.compile([frag])

        # A later strategy checking before emitting mod[75]-style reverse
        # redirect sees blk[76] is already linearized and skips.
        assert view.is_linearized(76) is True
        assert view.linearization_target_for(76) == 11
        assert view.is_claimed(76) is True

        # Untouched sources remain fair game.
        assert view.is_linearized(99) is False
        assert view.is_claimed(99) is False
