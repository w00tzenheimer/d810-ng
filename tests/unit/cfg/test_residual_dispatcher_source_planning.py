from __future__ import annotations

from d810.cfg.graph_modification import EdgeRedirectViaPredSplit, RedirectBranch, RedirectGoto
from d810.cfg.lowering_selector import (
    PredecessorPeelContext,
    ResidualBranchAnchorContext,
    ResidualGotoHandoffContext,
    ResidualPredSplitContext,
    ResidualPrefixPeelContext,
)
from d810.cfg.residual_dispatcher_source_planning import (
    ResidualDispatcherSourceContext,
    ResidualDispatcherSourcePlanKind,
    plan_residual_dispatcher_source,
)
from d810.cfg.residual_handoff_planning import (
    ResidualGotoAttempt,
    ResidualPrefixAttempt,
    ResidualPredSplitAttempt,
)


class TestPlanResidualDispatcherSource:
    def test_prefix_before_branch_anchor_wins(self):
        plan = plan_residual_dispatcher_source(
            ResidualDispatcherSourceContext(
                source_block=18,
                dispatcher_serial=6,
                prefix_before_attempts=(
                    ResidualPrefixAttempt(
                        via_pred=14,
                        prefix_target=20,
                        owned_transition=(0x1111, 0x2222),
                        edge_kind_name="transition",
                        branch_context=ResidualBranchAnchorContext(
                            is_conditional_branch_source=True,
                            branch_source=12,
                            source_block=18,
                            via_pred=14,
                            prefix_target=20,
                            branch_succs=(18, 24),
                            old_target=18,
                            ordered_path=(12, 14, 18),
                            dispatcher_serial=6,
                            bst_node_blocks=frozenset(),
                            target_reaches_branch=False,
                        ),
                    ),
                ),
            )
        )

        assert plan.accepted
        assert plan.kind == ResidualDispatcherSourcePlanKind.PREFIX_BRANCH_ANCHOR
        assert plan.redirected_count == 1
        assert plan.modifications == (
            RedirectBranch(from_serial=12, old_target=18, new_target=20),
        )
        assert plan.claimed_2way_updates == ((((12, 18), 20)),)

    def test_pred_split_path_emits_all_selected_modifications(self):
        plan = plan_residual_dispatcher_source(
            ResidualDispatcherSourceContext(
                source_block=14,
                dispatcher_serial=6,
                pred_split_attempts=(
                    ResidualPredSplitAttempt(
                        via_pred=10,
                        target_entry=18,
                        state_value=0x1111,
                        context=ResidualPredSplitContext(
                            source_block=14,
                            via_pred=10,
                            target_entry=18,
                            dispatcher_serial=6,
                            bst_node_blocks=frozenset(),
                            valid_pair=True,
                            target_reaches_via_pred=False,
                            already_emitted=False,
                        ),
                    ),
                    ResidualPredSplitAttempt(
                        via_pred=11,
                        target_entry=20,
                        state_value=0x2222,
                        context=ResidualPredSplitContext(
                            source_block=14,
                            via_pred=11,
                            target_entry=20,
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

        assert plan.accepted
        assert plan.kind == ResidualDispatcherSourcePlanKind.PRED_SPLIT
        assert plan.redirected_count == 2
        assert plan.modifications == (
            EdgeRedirectViaPredSplit(
                src_block=14,
                old_target=6,
                new_target=18,
                via_pred=10,
                rule_priority=550,
            ),
            EdgeRedirectViaPredSplit(
                src_block=14,
                old_target=6,
                new_target=20,
                via_pred=11,
                rule_priority=550,
            ),
        )

    def test_goto_path_claims_oneway_and_redirected_block(self):
        plan = plan_residual_dispatcher_source(
            ResidualDispatcherSourceContext(
                source_block=14,
                dispatcher_serial=6,
                goto_attempt=ResidualGotoAttempt(
                    target_entry=18,
                    state_value=0x1234,
                    context=ResidualGotoHandoffContext(
                        source_block=14,
                        target_entry=18,
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

        assert plan.accepted
        assert plan.kind == ResidualDispatcherSourcePlanKind.GOTO
        assert plan.modifications == (
            RedirectGoto(from_serial=14, old_target=6, new_target=18),
        )
        assert plan.claimed_1way_updates == ((14, 18),)
        assert plan.redirect_blocks == (14,)

    def test_goto_rejection_is_reported_without_prefix_fallback(self):
        plan = plan_residual_dispatcher_source(
            ResidualDispatcherSourceContext(
                source_block=14,
                dispatcher_serial=6,
                goto_attempt=ResidualGotoAttempt(
                    target_entry=18,
                    state_value=0x1234,
                    context=ResidualGotoHandoffContext(
                        source_block=14,
                        target_entry=18,
                        dispatcher_serial=6,
                        bst_node_blocks=frozenset(),
                        allow_family_fallback_tail=False,
                        is_shared_suffix_conditional_tail=True,
                        has_prior_branch_cut=False,
                        target_reaches_source=False,
                        already_emitted=False,
                        live_oneway_noop=False,
                    ),
                ),
                prefix_after_attempts=(
                    ResidualPrefixAttempt(
                        via_pred=10,
                        prefix_target=22,
                        peel_context=ResidualPrefixPeelContext(
                            peel_context=PredecessorPeelContext(
                                via_pred=10,
                                via_pred_succs=(14, 24),
                                source_block=14,
                                target_entry=22,
                                dispatcher_serial=6,
                                bst_node_blocks=frozenset(),
                                target_reaches_pred=False,
                            ),
                            already_emitted=False,
                            existing_target=None,
                            prefix_target=22,
                            via_pred_succ_count=2,
                        ),
                    ),
                ),
            )
        )

        assert not plan.accepted
        assert plan.rejection_reason == "shared_suffix_conditional_tail"
