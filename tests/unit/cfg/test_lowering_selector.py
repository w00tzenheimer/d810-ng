from __future__ import annotations

from d810.cfg.lowering_selector import (
    PredecessorPeelContext,
    ResidualBranchAnchorContext,
    ResidualGotoHandoffContext,
    ResidualPredSplitContext,
    ResidualPrefixPeelContext,
    SharedFeederCandidateScore,
    SharedFeederContext,
    SharedFeederLoweringKind,
    SharedGroupCandidate,
    SharedGroupContext,
    can_peel_predecessor_edge,
    is_backward_same_corridor_target,
    is_live_oneway_noop,
    is_valid_pred_split_pair,
    enumerate_shared_feeder_candidates,
    plan_residual_branch_anchor_handoff,
    plan_residual_goto_handoff,
    plan_residual_pred_split,
    plan_residual_prefix_peel,
    plan_shared_group_duplication,
    resolve_redirect_old_target,
    select_shared_feeder_lowering,
    target_reaches_source_ignoring_blocks,
)


class _DummyBlock:
    def __init__(self, succs: tuple[int, ...]):
        self.succs = succs


class _DummyFlowGraph:
    def __init__(self, mapping: dict[int, tuple[int, ...]]):
        self._mapping = {int(k): tuple(int(v) for v in succs) for k, succs in mapping.items()}

    def get_block(self, serial: int):
        succs = self._mapping.get(int(serial))
        if succs is None:
            return None
        return _DummyBlock(succs)

    def successors(self, serial: int):
        return self._mapping.get(int(serial), ())


class TestTargetReachesSourceIgnoringBlocks:
    def test_direct_hit_returns_true(self):
        fg = _DummyFlowGraph({16: (20,)})
        assert target_reaches_source_ignoring_blocks(
            fg,
            target_entry=16,
            source_block=16,
            ignored_blocks=set(),
        )

    def test_walk_finds_reachable_source(self):
        fg = _DummyFlowGraph({16: (20,), 20: (30,), 30: (14,)})
        assert target_reaches_source_ignoring_blocks(
            fg,
            target_entry=16,
            source_block=14,
            ignored_blocks=set(),
        )

    def test_ignored_blocks_break_path(self):
        fg = _DummyFlowGraph({16: (20,), 20: (14,)})
        assert not target_reaches_source_ignoring_blocks(
            fg,
            target_entry=16,
            source_block=14,
            ignored_blocks={20},
        )


class TestCanPeelPredecessorEdge:
    def test_two_way_predecessor_can_be_peeled(self):
        assert can_peel_predecessor_edge(
            PredecessorPeelContext(
            via_pred=12,
            via_pred_succs=(6, 14),
            source_block=14,
            target_entry=16,
            dispatcher_serial=6,
            bst_node_blocks=frozenset(),
            target_reaches_pred=False,
            )
        )

    def test_single_way_predecessor_cannot_be_peeled(self):
        assert not can_peel_predecessor_edge(
            PredecessorPeelContext(
            via_pred=12,
            via_pred_succs=(14,),
            source_block=14,
            target_entry=16,
            dispatcher_serial=6,
            bst_node_blocks=frozenset(),
            target_reaches_pred=False,
            )
        )

    def test_same_other_successor_rejected(self):
        assert not can_peel_predecessor_edge(
            PredecessorPeelContext(
            via_pred=12,
            via_pred_succs=(14, 16),
            source_block=14,
            target_entry=16,
            dispatcher_serial=6,
            bst_node_blocks=frozenset(),
            target_reaches_pred=False,
            )
        )

    def test_cycle_risk_rejected(self):
        assert not can_peel_predecessor_edge(
            PredecessorPeelContext(
            via_pred=12,
            via_pred_succs=(6, 14),
            source_block=14,
            target_entry=16,
            dispatcher_serial=6,
            bst_node_blocks=frozenset(),
            target_reaches_pred=True,
            )
        )


class TestResolveRedirectOldTarget:
    def test_prefers_branch_arm_target_when_conditional(self):
        assert (
            resolve_redirect_old_target(
                14,
                source_succs=(6, 16),
                ordered_path=(12, 14),
                target_entry_anchor=16,
                source_branch_arm=0,
                source_is_conditional_branch=True,
                bst_node_blocks=frozenset(),
                dispatcher_region=frozenset({6}),
            )
            == 6
        )

    def test_prefers_ordered_path_successor(self):
        assert (
            resolve_redirect_old_target(
                14,
                source_succs=(20, 16),
                ordered_path=(12, 14, 20),
                target_entry_anchor=16,
                source_branch_arm=None,
                source_is_conditional_branch=False,
                bst_node_blocks=frozenset(),
                dispatcher_region=frozenset({6}),
            )
            == 20
        )

    def test_falls_back_to_dispatcher_region_then_non_target(self):
        assert (
            resolve_redirect_old_target(
                14,
                source_succs=(6, 16),
                ordered_path=(12, 14),
                target_entry_anchor=16,
                source_branch_arm=None,
                source_is_conditional_branch=False,
                bst_node_blocks=frozenset(),
                dispatcher_region=frozenset({6}),
            )
            == 6
        )


class TestResidualRedirectHelpers:
    def test_valid_pred_split_pair_requires_oneway_chain(self):
        assert is_valid_pred_split_pair(
            14,
            via_pred=12,
            source_succs=(20,),
            via_pred_succs=(14,),
        )
        assert not is_valid_pred_split_pair(
            14,
            via_pred=12,
            source_succs=(20, 30),
            via_pred_succs=(14,),
        )
        assert not is_valid_pred_split_pair(
            14,
            via_pred=12,
            source_succs=(20,),
            via_pred_succs=(18,),
        )

    def test_live_oneway_noop_detects_matching_target(self):
        assert is_live_oneway_noop(source_succs=(16,), target_entry=16)
        assert not is_live_oneway_noop(source_succs=(20,), target_entry=16)
        assert not is_live_oneway_noop(source_succs=(16, 20), target_entry=16)

    def test_backward_same_corridor_target_detects_on_path_backreach(self):
        assert is_backward_same_corridor_target(
            ordered_path=(12, 14, 16),
            source_block=16,
            target_entry=14,
        )
        assert not is_backward_same_corridor_target(
            ordered_path=(12, 14, 16),
            source_block=14,
            target_entry=16,
        )
        assert not is_backward_same_corridor_target(
            ordered_path=(12, 14, 16),
            source_block=16,
            target_entry=30,
        )


class TestSelectSharedFeederLowering:
    def test_single_pred_uses_block_goto(self):
        decision = select_shared_feeder_lowering(
            SharedFeederContext(
            source_serial=14,
            source_pred_count=1,
            ordered_path=(12, 14),
            via_pred_succs=(6, 14),
            target_entry=16,
            dispatcher_serial=6,
            bst_node_blocks=frozenset(),
            target_reaches_pred=False,
            )
        )
        assert decision.kind == SharedFeederLoweringKind.BLOCK_GOTO

    def test_shared_source_defaults_to_clone_to_preserve_existing_behavior(self):
        decision = select_shared_feeder_lowering(
            SharedFeederContext(
            source_serial=14,
            source_pred_count=2,
            ordered_path=(12, 14),
            via_pred_succs=(6, 14),
            target_entry=16,
            dispatcher_serial=6,
            bst_node_blocks=frozenset(),
            target_reaches_pred=False,
            )
        )
        assert decision.kind == SharedFeederLoweringKind.PRED_SCOPED_CLONE
        assert decision.via_pred == 12

    def test_shared_source_falls_back_to_clone_when_peel_unavailable(self):
        decision = select_shared_feeder_lowering(
            SharedFeederContext(
            source_serial=32,
            source_pred_count=2,
            ordered_path=(30, 32),
            via_pred_succs=(32,),
            target_entry=34,
            dispatcher_serial=6,
            bst_node_blocks=frozenset(),
            target_reaches_pred=False,
            )
        )
        assert decision.kind == SharedFeederLoweringKind.PRED_SCOPED_CLONE
        assert decision.via_pred == 30

    def test_shared_source_falls_back_to_clone_when_target_reaches_pred(self):
        decision = select_shared_feeder_lowering(
            SharedFeederContext(
            source_serial=14,
            source_pred_count=2,
            ordered_path=(12, 14),
            via_pred_succs=(6, 14),
            target_entry=16,
            dispatcher_serial=6,
            bst_node_blocks=frozenset(),
            target_reaches_pred=True,
            )
        )
        assert decision.kind == SharedFeederLoweringKind.PRED_SCOPED_CLONE

    def test_shared_source_enumerates_peel_and_clone_candidates(self):
        candidates = enumerate_shared_feeder_candidates(
            SharedFeederContext(
                source_serial=14,
                source_pred_count=2,
                ordered_path=(12, 14),
                via_pred_succs=(6, 14),
                target_entry=16,
                dispatcher_serial=6,
                bst_node_blocks=frozenset(),
                target_reaches_pred=False,
            )
        )
        assert [candidate.kind for candidate in candidates] == [
            SharedFeederLoweringKind.PRED_EDGE_PEEL,
            SharedFeederLoweringKind.PRED_SCOPED_CLONE,
        ]

    def test_default_selector_still_prefers_clone_while_peel_is_disabled(self):
        decision = select_shared_feeder_lowering(
            SharedFeederContext(
                source_serial=14,
                source_pred_count=2,
                ordered_path=(12, 14),
                via_pred_succs=(6, 14),
                target_entry=16,
                dispatcher_serial=6,
                bst_node_blocks=frozenset(),
                target_reaches_pred=False,
            )
        )
        assert decision.kind == SharedFeederLoweringKind.PRED_SCOPED_CLONE

    def test_custom_scorer_can_veto_clone_and_enable_peel(self):
        class _TestScorer:
            def score(self, context, candidate):
                assert context.source_serial == 14
                if candidate.kind == SharedFeederLoweringKind.PRED_SCOPED_CLONE:
                    return SharedFeederCandidateScore(
                        accepted=False,
                        score=0,
                        reason="clone_rejected_for_test",
                    )
                if candidate.kind == SharedFeederLoweringKind.PRED_EDGE_PEEL:
                    return SharedFeederCandidateScore(
                        accepted=True,
                        score=-2000,
                        reason="peel_preferred_for_test",
                    )
                return SharedFeederCandidateScore(accepted=True, score=0)

        decision = select_shared_feeder_lowering(
            SharedFeederContext(
                source_serial=14,
                source_pred_count=2,
                ordered_path=(12, 14),
                via_pred_succs=(6, 14),
                target_entry=16,
                dispatcher_serial=6,
                bst_node_blocks=frozenset(),
                target_reaches_pred=False,
            ),
            scorer=_TestScorer(),
        )
        assert decision.kind == SharedFeederLoweringKind.PRED_EDGE_PEEL
        assert decision.reason == "peel_preferred_for_test"

    def test_custom_scorer_can_reject_all_candidates(self):
        class _RejectAllScorer:
            def score(self, context, candidate):
                assert context.source_serial == 14
                return SharedFeederCandidateScore(
                    accepted=False,
                    score=0,
                    reason=f"reject_{candidate.kind}",
                )

        decision = select_shared_feeder_lowering(
            SharedFeederContext(
                source_serial=14,
                source_pred_count=2,
                ordered_path=(12, 14),
                via_pred_succs=(6, 14),
                target_entry=16,
                dispatcher_serial=6,
                bst_node_blocks=frozenset(),
                target_reaches_pred=False,
            ),
            scorer=_RejectAllScorer(),
        )
        assert not decision.accepted
        assert decision.kind == SharedFeederLoweringKind.REJECTED
        assert decision.via_pred == 12
        assert decision.reason == "all_candidates_vetoed"


class TestPlanSharedGroupDuplication:
    def test_single_candidate_keeps_old_target_for_other_pred(self):
        plan = plan_shared_group_duplication(
            SharedGroupContext(
                shared_block=10,
                old_target=2,
                shared_preds=(8, 9),
                candidates=(SharedGroupCandidate(via_pred=8, target_entry=24),),
            )
        )
        assert plan.accepted
        assert plan.per_pred_targets == ((9, 2), (8, 24))

    def test_single_candidate_rejects_when_no_keep_pred_exists(self):
        plan = plan_shared_group_duplication(
            SharedGroupContext(
                shared_block=10,
                old_target=2,
                shared_preds=(8,),
                candidates=(SharedGroupCandidate(via_pred=8, target_entry=24),),
            )
        )
        assert not plan.accepted
        assert plan.rejection_reason == "missing_keep_pred"

    def test_two_candidate_group_keeps_explicit_old_target_when_present(self):
        plan = plan_shared_group_duplication(
            SharedGroupContext(
                shared_block=10,
                old_target=2,
                shared_preds=(8, 9),
                candidates=(
                    SharedGroupCandidate(via_pred=8, target_entry=24),
                    SharedGroupCandidate(via_pred=9, target_entry=2),
                ),
            )
        )
        assert plan.accepted
        assert plan.per_pred_targets == ((9, 2), (8, 24))

    def test_two_new_targets_preserves_both_candidates_without_fake_keep(self):
        plan = plan_shared_group_duplication(
            SharedGroupContext(
                shared_block=10,
                old_target=2,
                shared_preds=(8, 9),
                candidates=(
                    SharedGroupCandidate(via_pred=8, target_entry=24),
                    SharedGroupCandidate(via_pred=9, target_entry=30),
                ),
            )
        )
        assert plan.accepted
        assert plan.per_pred_targets == ((8, 24), (9, 30))

    def test_non_candidate_preds_require_multi_clone_rejection(self):
        plan = plan_shared_group_duplication(
            SharedGroupContext(
                shared_block=10,
                old_target=2,
                shared_preds=(8, 9, 11),
                candidates=(
                    SharedGroupCandidate(via_pred=8, target_entry=24),
                    SharedGroupCandidate(via_pred=9, target_entry=30),
                ),
            )
        )
        assert not plan.accepted
        assert plan.rejection_reason == "shared_group_requires_multi_clone"


class TestPlanResidualBranchAnchorHandoff:
    def test_accepts_valid_branch_anchor_handoff(self):
        plan = plan_residual_branch_anchor_handoff(
            ResidualBranchAnchorContext(
                is_conditional_branch_source=True,
                branch_source=12,
                source_block=14,
                via_pred=10,
                prefix_target=16,
                branch_succs=(8, 14),
                old_target=14,
                ordered_path=(12, 14, 15),
                dispatcher_serial=6,
                bst_node_blocks=frozenset(),
                target_reaches_branch=False,
            )
        )
        assert plan.accepted
        assert plan.branch_source == 12
        assert plan.old_target == 14

    def test_rejects_non_branch_anchor(self):
        plan = plan_residual_branch_anchor_handoff(
            ResidualBranchAnchorContext(
                is_conditional_branch_source=False,
                branch_source=12,
                source_block=14,
                via_pred=10,
                prefix_target=16,
                branch_succs=(8, 14),
                old_target=14,
                ordered_path=(12, 14, 15),
                dispatcher_serial=6,
                bst_node_blocks=frozenset(),
                target_reaches_branch=False,
            )
        )
        assert not plan.accepted
        assert plan.rejection_reason == "anchor_not_conditional_branch"

    def test_rejects_collision_with_other_branch_arm(self):
        plan = plan_residual_branch_anchor_handoff(
            ResidualBranchAnchorContext(
                is_conditional_branch_source=True,
                branch_source=12,
                source_block=14,
                via_pred=10,
                prefix_target=8,
                branch_succs=(8, 14),
                old_target=14,
                ordered_path=(12, 14, 15),
                dispatcher_serial=6,
                bst_node_blocks=frozenset(),
                target_reaches_branch=False,
            )
        )
        assert not plan.accepted
        assert plan.rejection_reason == "other_arm_collision"

    def test_rejects_cycle_risk(self):
        plan = plan_residual_branch_anchor_handoff(
            ResidualBranchAnchorContext(
                is_conditional_branch_source=True,
                branch_source=12,
                source_block=14,
                via_pred=10,
                prefix_target=16,
                branch_succs=(8, 14),
                old_target=14,
                ordered_path=(12, 14, 15),
                dispatcher_serial=6,
                bst_node_blocks=frozenset(),
                target_reaches_branch=True,
            )
        )
        assert not plan.accepted
        assert plan.rejection_reason == "cycle_risk"


class TestPlanResidualPrefixPeel:
    def _peel_context(self) -> PredecessorPeelContext:
        return PredecessorPeelContext(
            via_pred=12,
            via_pred_succs=(6, 14),
            source_block=14,
            target_entry=16,
            dispatcher_serial=6,
            bst_node_blocks=frozenset(),
            target_reaches_pred=False,
        )

    def test_accepts_legal_peel(self):
        plan = plan_residual_prefix_peel(
            ResidualPrefixPeelContext(
                peel_context=self._peel_context(),
                already_emitted=False,
                existing_target=None,
                prefix_target=16,
                via_pred_succ_count=2,
            )
        )
        assert plan.accepted
        assert not plan.stop_iteration

    def test_rejects_when_prefix_already_emitted(self):
        plan = plan_residual_prefix_peel(
            ResidualPrefixPeelContext(
                peel_context=self._peel_context(),
                already_emitted=True,
                existing_target=None,
                prefix_target=16,
                via_pred_succ_count=2,
            )
        )
        assert not plan.accepted
        assert plan.rejection_reason == "prefix_already_emitted"

    def test_single_successor_matching_existing_target_stops_iteration(self):
        plan = plan_residual_prefix_peel(
            ResidualPrefixPeelContext(
                peel_context=self._peel_context(),
                already_emitted=False,
                existing_target=16,
                prefix_target=16,
                via_pred_succ_count=1,
            )
        )
        assert not plan.accepted
        assert plan.stop_iteration
        assert plan.rejection_reason == "existing_target_matches_prefix"

    def test_single_successor_conflict_rejects_without_stop(self):
        plan = plan_residual_prefix_peel(
            ResidualPrefixPeelContext(
                peel_context=self._peel_context(),
                already_emitted=False,
                existing_target=20,
                prefix_target=16,
                via_pred_succ_count=1,
            )
        )
        assert not plan.accepted
        assert not plan.stop_iteration
        assert plan.rejection_reason == "existing_target_conflicts"


class TestPlanResidualPredSplit:
    def test_accepts_legal_pred_split(self):
        plan = plan_residual_pred_split(
            ResidualPredSplitContext(
                source_block=14,
                via_pred=12,
                target_entry=16,
                dispatcher_serial=6,
                bst_node_blocks=frozenset(),
                valid_pair=True,
                target_reaches_via_pred=False,
                already_emitted=False,
            )
        )
        assert plan.accepted

    def test_rejects_invalid_target(self):
        plan = plan_residual_pred_split(
            ResidualPredSplitContext(
                source_block=14,
                via_pred=12,
                target_entry=6,
                dispatcher_serial=6,
                bst_node_blocks=frozenset(),
                valid_pair=True,
                target_reaches_via_pred=False,
                already_emitted=False,
            )
        )
        assert not plan.accepted
        assert plan.rejection_reason == "invalid_target"

    def test_rejects_cycle_risk(self):
        plan = plan_residual_pred_split(
            ResidualPredSplitContext(
                source_block=14,
                via_pred=12,
                target_entry=16,
                dispatcher_serial=6,
                bst_node_blocks=frozenset(),
                valid_pair=True,
                target_reaches_via_pred=True,
                already_emitted=False,
            )
        )
        assert not plan.accepted
        assert plan.rejection_reason == "cycle_risk"


class TestPlanResidualGotoHandoff:
    def test_accepts_legal_goto_handoff(self):
        plan = plan_residual_goto_handoff(
            ResidualGotoHandoffContext(
                source_block=14,
                target_entry=16,
                dispatcher_serial=6,
                bst_node_blocks=frozenset(),
                allow_family_fallback_tail=False,
                is_shared_suffix_conditional_tail=False,
                has_prior_branch_cut=False,
                target_reaches_source=False,
                already_emitted=False,
                live_oneway_noop=False,
            )
        )
        assert plan.accepted

    def test_rejects_shared_suffix_tail_without_fallback(self):
        plan = plan_residual_goto_handoff(
            ResidualGotoHandoffContext(
                source_block=14,
                target_entry=16,
                dispatcher_serial=6,
                bst_node_blocks=frozenset(),
                allow_family_fallback_tail=False,
                is_shared_suffix_conditional_tail=True,
                has_prior_branch_cut=False,
                target_reaches_source=False,
                already_emitted=False,
                live_oneway_noop=False,
            )
        )
        assert not plan.accepted
        assert plan.rejection_reason == "shared_suffix_conditional_tail"

    def test_rejects_live_oneway_noop(self):
        plan = plan_residual_goto_handoff(
            ResidualGotoHandoffContext(
                source_block=14,
                target_entry=16,
                dispatcher_serial=6,
                bst_node_blocks=frozenset(),
                allow_family_fallback_tail=False,
                is_shared_suffix_conditional_tail=False,
                has_prior_branch_cut=False,
                target_reaches_source=False,
                already_emitted=False,
                live_oneway_noop=True,
            )
        )
        assert not plan.accepted
        assert plan.rejection_reason == "live_oneway_noop"
