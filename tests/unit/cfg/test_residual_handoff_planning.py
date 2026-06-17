from __future__ import annotations

from d810.transforms.lowering_selector import (
    PredecessorPeelContext,
    ResidualBranchAnchorContext,
    ResidualGotoHandoffContext,
    ResidualPredSplitContext,
    ResidualPrefixPeelContext,
)
from d810.transforms.residual_handoff_planning import (
    ResidualGotoAttempt,
    ResidualHandoffMode,
    ResidualHandoffPlanningContext,
    ResidualPrefixAttempt,
    ResidualPredSplitAttempt,
    ResidualPredSplitSelection,
    plan_residual_handoff,
)


class TestPlanResidualHandoff:
    def test_selects_all_accepted_pred_splits(self):
        decision = plan_residual_handoff(
            ResidualHandoffPlanningContext(
                mode=ResidualHandoffMode.PRED_SPLIT,
                pred_split_attempts=(
                    ResidualPredSplitAttempt(
                        via_pred=8,
                        target_entry=24,
                        state_value=0x1111,
                        context=ResidualPredSplitContext(
                            source_block=10,
                            via_pred=8,
                            target_entry=24,
                            dispatcher_serial=6,
                            condition_chain_blocks=frozenset(),
                            valid_pair=True,
                            target_reaches_via_pred=False,
                            already_emitted=False,
                        ),
                    ),
                    ResidualPredSplitAttempt(
                        via_pred=9,
                        target_entry=30,
                        state_value=0x2222,
                        context=ResidualPredSplitContext(
                            source_block=10,
                            via_pred=9,
                            target_entry=30,
                            dispatcher_serial=6,
                            condition_chain_blocks=frozenset(),
                            valid_pair=True,
                            target_reaches_via_pred=False,
                            already_emitted=False,
                        ),
                    ),
                ),
            )
        )

        assert decision.accepted
        assert decision.kind == ResidualHandoffMode.PRED_SPLIT
        assert decision.pred_splits == (
            ResidualPredSplitSelection(via_pred=8, target_entry=24, state_value=0x1111),
            ResidualPredSplitSelection(via_pred=9, target_entry=30, state_value=0x2222),
        )

    def test_rejects_when_all_pred_splits_are_vetoed(self):
        decision = plan_residual_handoff(
            ResidualHandoffPlanningContext(
                mode=ResidualHandoffMode.PRED_SPLIT,
                pred_split_attempts=(
                    ResidualPredSplitAttempt(
                        via_pred=8,
                        target_entry=24,
                        state_value=0x1111,
                        context=ResidualPredSplitContext(
                            source_block=10,
                            via_pred=8,
                            target_entry=24,
                            dispatcher_serial=6,
                            condition_chain_blocks=frozenset(),
                            valid_pair=False,
                            target_reaches_via_pred=False,
                            already_emitted=False,
                        ),
                    ),
                ),
            )
        )

        assert not decision.accepted
        assert decision.kind == ResidualHandoffMode.REJECTED
        assert decision.rejection_reason == "no_pred_split_candidate"

    def test_selects_accepted_goto_handoff(self):
        decision = plan_residual_handoff(
            ResidualHandoffPlanningContext(
                mode=ResidualHandoffMode.GOTO,
                goto_attempt=ResidualGotoAttempt(
                    target_entry=24,
                    state_value=0x1111,
                    context=ResidualGotoHandoffContext(
                        source_block=10,
                        target_entry=24,
                        dispatcher_serial=6,
                        condition_chain_blocks=frozenset(),
                        allow_family_fallback_tail=False,
                        is_shared_suffix_conditional_tail=False,
                        has_prior_branch_cut=False,
                        target_reaches_source=False,
                        already_emitted=False,
                        live_oneway_noop=False,
                    ),
                ),
            )
        )

        assert decision.accepted
        assert decision.kind == ResidualHandoffMode.GOTO
        assert decision.target_entry == 24
        assert decision.state_value == 0x1111

    def test_selects_branch_anchor_prefix_handoff(self):
        decision = plan_residual_handoff(
            ResidualHandoffPlanningContext(
                mode=ResidualHandoffMode.PREFIX,
                prefix_attempts=(
                    ResidualPrefixAttempt(
                        via_pred=14,
                        prefix_target=20,
                        branch_context=ResidualBranchAnchorContext(
                            is_conditional_branch_source=True,
                            branch_source=12,
                            source_block=18,
                            via_pred=14,
                            prefix_target=20,
                            branch_succs=(18, 22),
                            old_target=18,
                            ordered_path=(12, 14, 18),
                            dispatcher_serial=6,
                            condition_chain_blocks=frozenset(),
                            target_reaches_branch=False,
                        ),
                    ),
                ),
            )
        )

        assert decision.accepted
        assert decision.kind == ResidualHandoffMode.BRANCH_ANCHOR
        assert decision.branch_source == 12
        assert decision.prefix_target == 20

    def test_selects_prefix_peel_when_branch_anchor_rejects(self):
        decision = plan_residual_handoff(
            ResidualHandoffPlanningContext(
                mode=ResidualHandoffMode.PREFIX,
                prefix_attempts=(
                    ResidualPrefixAttempt(
                        via_pred=14,
                        prefix_target=20,
                        branch_context=ResidualBranchAnchorContext(
                            is_conditional_branch_source=False,
                            branch_source=12,
                            source_block=18,
                            via_pred=14,
                            prefix_target=20,
                            branch_succs=(18,),
                            old_target=18,
                            ordered_path=(12, 14, 18),
                            dispatcher_serial=6,
                            condition_chain_blocks=frozenset(),
                            target_reaches_branch=False,
                        ),
                        peel_context=ResidualPrefixPeelContext(
                            peel_context=PredecessorPeelContext(
                                via_pred=14,
                                via_pred_succs=(18, 30),
                                source_block=18,
                                target_entry=20,
                                dispatcher_serial=6,
                                condition_chain_blocks=frozenset(),
                                target_reaches_pred=False,
                            ),
                            already_emitted=False,
                            existing_target=None,
                            prefix_target=20,
                            via_pred_succ_count=2,
                        ),
                    ),
                ),
            )
        )

        assert decision.accepted
        assert decision.kind == ResidualHandoffMode.PREFIX_PEEL
        assert decision.via_pred == 14
        assert decision.prefix_target == 20
