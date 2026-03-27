from __future__ import annotations

from d810.cfg.lowering_selector import (
    PredecessorPeelContext,
    SharedFeederCandidateScore,
    SharedFeederContext,
    SharedFeederLoweringKind,
    SharedGroupCandidate,
    SharedGroupContext,
    can_peel_predecessor_edge,
    enumerate_shared_feeder_candidates,
    plan_shared_group_duplication,
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
