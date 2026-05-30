"""Tests for finalize_reconstruction_fragment's planner_ctx integration.

Validates the contributor side of the engine-level coordination mechanism:
the SRW strategy's terminal PlanFragment MUST carry a
PlannerContextContribution under ``metadata["planner_ctx"]`` so later
strategies (same pipeline) can observe its LinearizationDecisions via
CumulativePlannerView.
"""
from __future__ import annotations

import pytest

from d810.transforms.graph_modification import (
    ConvertToGoto,
    RedirectGoto,
    ZeroStateWrite,
)
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


# ----------------------------------------------------------------------------
# Phase 3 of uee-jrgq — DAG-as-arbiter conformance via DagAuthority
# ----------------------------------------------------------------------------


class TestDagArbiterConformance:
    """Phase 3: when CumulativePlannerView carries a DagAuthority, the new
    filter_dag_disagreements runs BEFORE the legacy
    _drop_conflicting_redirects filter and drops mods the DAG explicitly
    disagrees with.  Mods in DAG_GAP regions still flow into the legacy
    filter.
    """

    def _stub_authority(self, *, allow_for: dict[int, int] | None = None,
                        disagree_for: dict[int, int] | None = None,
                        gap_for: set[int] | None = None):
        """Build a minimal DagAuthority stand-in for testing.

        Avoids constructing a real LinearizedStateDag (which has many
        required fields) — uses duck typing to provide just the
        ``permits()`` method finalize_reconstruction_fragment exercises.
        """
        from d810.optimizers.microcode.flow.flattening.engine.dag_authority import (
            DagDecision,
        )
        allow = dict(allow_for or {})
        disagree = dict(disagree_for or {})
        gap = set(gap_for or ())

        class _StubAuthority:
            def permits(self, mod):
                src = getattr(mod, "from_serial", None)
                if src is None:
                    src = getattr(mod, "block_serial", None)
                if src is None:
                    return DagDecision.gap("no_source")
                src_int = int(src)
                if src_int in gap:
                    return DagDecision.gap("unknown_source")
                if src_int in disagree:
                    canonical = disagree[src_int]
                    new_tgt = getattr(mod, "new_target", None) or getattr(mod, "goto_target", None)
                    return DagDecision.refuse(
                        f"DAG_DISAGREEMENT:{src_int}->"
                        f"{{planner={new_tgt},dag={canonical}}}"
                    )
                if src_int in allow:
                    return DagDecision.allow(target_entry_anchor=allow[src_int])
                return DagDecision.gap("unknown_source")

        return _StubAuthority()

    def _view_with_authority(self, authority) -> CumulativePlannerView:
        return CumulativePlannerView.empty(dag_authority=authority)

    def _finalize(self, *, modifications, owned_blocks=None, view=None):
        return finalize_reconstruction_fragment(
            strategy_name="state_write_reconstruction",
            modifications=modifications,
            owned_blocks=owned_blocks if owned_blocks is not None else set(),
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

    def test_keeps_mod_when_dag_allows(self) -> None:
        # DAG canonical target == planner target → ALLOW → keep.
        authority = self._stub_authority(allow_for={76: 11})
        view = self._view_with_authority(authority)
        frag = self._finalize(
            modifications=[
                RedirectGoto(from_serial=76, old_target=2, new_target=11),
            ],
            owned_blocks={76},
            view=view,
        )
        assert len(frag.modifications) == 1

    def test_drops_mod_when_dag_disagrees(self) -> None:
        # Planner says 76→2; DAG says 76→11 → DAG_DISAGREEMENT → drop.
        authority = self._stub_authority(disagree_for={76: 11})
        view = self._view_with_authority(authority)
        frag = self._finalize(
            modifications=[
                RedirectGoto(from_serial=76, old_target=2, new_target=2),
            ],
            owned_blocks={76},
            view=view,
        )
        # Mod dropped.
        assert all(
            not isinstance(m, RedirectGoto)
            for m in frag.modifications
        )

    def test_keeps_mod_when_dag_silent_gap(self) -> None:
        # DAG returns DAG_GAP → defer to legacy filter.  With no prior
        # fragment in the cumulative view, legacy filter doesn't drop
        # either, so the mod survives.
        authority = self._stub_authority(gap_for={76})
        view = self._view_with_authority(authority)
        frag = self._finalize(
            modifications=[
                RedirectGoto(from_serial=76, old_target=2, new_target=2),
            ],
            owned_blocks={76},
            view=view,
        )
        assert len(frag.modifications) == 1
        assert isinstance(frag.modifications[0], RedirectGoto)

    def test_drops_dag_disagreement_keeps_others(self) -> None:
        # Mixed batch: 76 disagrees → drop; 99 allowed → keep.
        authority = self._stub_authority(
            disagree_for={76: 11},
            allow_for={99: 55},
        )
        view = self._view_with_authority(authority)
        frag = self._finalize(
            modifications=[
                RedirectGoto(from_serial=76, old_target=2, new_target=2),
                RedirectGoto(from_serial=99, old_target=2, new_target=55),
            ],
            owned_blocks={76, 99},
            view=view,
        )
        srcs = {
            m.from_serial for m in frag.modifications
            if isinstance(m, RedirectGoto)
        }
        assert srcs == {99}

    def test_no_authority_falls_through_to_legacy(self) -> None:
        # Without a DagAuthority, the legacy filter is the only one
        # active.  An unrelated source has no prior linearization, so
        # the mod survives.
        view = CumulativePlannerView.empty()  # no dag_authority
        frag = self._finalize(
            modifications=[
                RedirectGoto(from_serial=76, old_target=2, new_target=11),
            ],
            owned_blocks={76},
            view=view,
        )
        assert len(frag.modifications) == 1

    def test_dag_disagreement_takes_precedence_over_legacy_match(self) -> None:
        # Even when prior fragments would've allowed the mod (legacy
        # filter would keep it because no linearization decision matches),
        # if the DAG disagrees the mod is dropped.  DAG wins.
        authority = self._stub_authority(disagree_for={76: 11})
        # No prior fragment recorded → legacy filter would keep the mod.
        view = self._view_with_authority(authority)
        frag = self._finalize(
            modifications=[
                RedirectGoto(from_serial=76, old_target=2, new_target=2),
            ],
            owned_blocks={76},
            view=view,
        )
        # DAG arbiter dropped it.
        assert all(
            not isinstance(m, RedirectGoto)
            for m in frag.modifications
        )

    def test_convert_to_goto_is_arbitrated(self) -> None:
        # ConvertToGoto goes through the same DAG check as RedirectGoto.
        authority = self._stub_authority(disagree_for={76: 11})
        view = self._view_with_authority(authority)
        frag = self._finalize(
            modifications=[
                ConvertToGoto(block_serial=76, goto_target=2),
            ],
            owned_blocks={76},
            view=view,
        )
        assert all(
            not isinstance(m, ConvertToGoto)
            for m in frag.modifications
        )


# ----------------------------------------------------------------------------
# Phase 6 of uee-jrgq — retirement criterion for the legacy filter cascade
# ----------------------------------------------------------------------------


class TestPhase6RetirementCriterion:
    """Phase 6 of uee-jrgq formalises the retirement contract for the
    pre-DAG legacy filter cascade.  The actual deletion of
    ``_drop_intra_fragment_dup_conflicts`` /
    ``_drop_conflicting_redirects`` and the mod-echo logic in
    ``_build_planner_context_contribution`` is gated on:

      1. The DAG arbiter has authoritative coverage of every emission
         decision point (DAG_GAP returns drop to zero across the
         corpus).
      2. The legacy filters fire zero times across a release cycle.

    These tests pin the *measurement* surface for that gate so a
    future cleanup commit can reliably check criteria (1) and (2)
    without re-deriving the test fixture every time.
    """

    def test_when_dag_authority_allows_legacy_filter_is_no_op(self) -> None:
        # Criterion (2) check: when DAG arbiter has ALLOWED every
        # redirect mod, the legacy ``_drop_conflicting_redirects``
        # filter sees no work to do (because no mod survives to
        # disagree with prior linearizations beyond what the arbiter
        # already vetoed).  This test pins that no-op behaviour so a
        # future deletion does not silently change semantics.
        from d810.optimizers.microcode.flow.flattening.engine.dag_authority import (
            DagDecision,
        )

        class _AllowAllAuthority:
            def permits(self, mod):
                # Allow whatever target the planner proposed.
                return DagDecision.allow(
                    target_entry_anchor=getattr(mod, "new_target", None)
                    or getattr(mod, "goto_target", None),
                )

        view = CumulativePlannerView.empty(dag_authority=_AllowAllAuthority())
        frag = finalize_reconstruction_fragment(
            strategy_name="state_write_reconstruction",
            modifications=[
                RedirectGoto(from_serial=76, old_target=2, new_target=11),
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
        # Both mods kept — DAG arbiter allowed both, legacy never fires.
        srcs = {
            m.from_serial for m in frag.modifications
            if isinstance(m, RedirectGoto)
        }
        assert srcs == {76, 99}

    def test_dag_gap_region_falls_through_to_legacy(self) -> None:
        # Criterion (1) measurement: the legacy filter is doing
        # *real work* today on DAG_GAP regions.  This test pins the
        # current behaviour as a regression guard — when criterion (1)
        # eventually holds (DAG covers all sources), this test will
        # fail by remaining green when the legacy filter is removed,
        # forcing the tester to update both the production code and
        # this assertion together.
        from d810.optimizers.microcode.flow.flattening.engine.dag_authority import (
            DagDecision,
        )

        class _AllGapAuthority:
            def permits(self, mod):
                return DagDecision.gap("unknown_source")

        # Build a cumulative view as if a prior fragment had committed
        # blk[76] -> 11; the DAG is silent on it (DAG_GAP), so the
        # legacy filter must catch the disagreement.
        prior_meta = {
            PLANNER_CTX_METADATA_KEY: PlannerContextContribution(
                linearizations=(
                    LinearizationDecision(
                        src=76, tgt=11, reason="prior",
                        strategy="ssr", round_index=0,
                    ),
                ),
            ),
        }

        class _Frag:
            metadata = prior_meta

        view = CumulativePlannerView.compile(
            [_Frag()], dag_authority=_AllGapAuthority(),
        )
        frag = finalize_reconstruction_fragment(
            strategy_name="state_write_reconstruction",
            modifications=[
                # Disagrees with prior (76 -> 11) by trying 76 -> 2.
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
            round_index=1,
            cumulative_planner_view=view,
        )
        # Legacy filter dropped the conflicting redirect — criterion (1)
        # not yet met (DAG silent + legacy still doing work).
        srcs = {
            m.from_serial for m in frag.modifications
            if isinstance(m, RedirectGoto)
        }
        assert srcs == set(), (
            "regression: when DAG returns DAG_GAP and legacy filter "
            "would drop a Mode 1 conflict, the legacy filter must "
            "still drop it.  If this assertion fires GREEN with the "
            "legacy filter removed, criterion (1) needs to be "
            "re-validated against the current corpus before deletion."
        )
