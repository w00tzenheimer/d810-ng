from __future__ import annotations

from d810.cfg.lowering_selector import (
    ResidualGotoHandoffContext,
    ResidualPredSplitContext,
)
from d810.cfg.residual_handoff_planning import (
    ResidualGotoAttempt,
    ResidualHandoffMode,
    ResidualHandoffPlanningContext,
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
                            bst_node_blocks=frozenset(),
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
                            bst_node_blocks=frozenset(),
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
                            bst_node_blocks=frozenset(),
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
                        bst_node_blocks=frozenset(),
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
