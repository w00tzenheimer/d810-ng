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
    apply_residual_dispatcher_source_plan,
    ResidualDispatcherSourcePlan,
    ResidualDispatcherSourcePlanKind,
    plan_residual_dispatcher_source,
)
from d810.cfg.residual_handoff_planning import (
    ResidualGotoAttempt,
    ResidualPrefixAttempt,
    ResidualPredSplitAttempt,
)


class TestPlanResidualDispatcherSource:
    def test_goto_wins_over_prefix_before_branch_anchor(self):
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
                goto_attempt=ResidualGotoAttempt(
                    target_entry=26,
                    state_value=0x3333,
                    context=ResidualGotoHandoffContext(
                        source_block=18,
                        target_entry=26,
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
        assert plan.redirected_count == 1
        assert plan.modifications == (
            RedirectGoto(from_serial=18, old_target=6, new_target=26),
        )
        assert plan.claimed_1way_updates == ((18, 26),)

    def test_prefix_before_branch_anchor_wins_without_goto(self):
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

    def test_apply_source_plan_updates_all_virtual_claims(self):
        plan = ResidualDispatcherSourcePlan(
            accepted=True,
            kind=ResidualDispatcherSourcePlanKind.GOTO,
            modifications=(RedirectGoto(from_serial=14, old_target=6, new_target=18),),
            emitted_edges=((14, 18),),
            owned_blocks=(14, 10),
            owned_edges=((14, 18),),
            owned_transitions=((0x1111, 0x2222),),
            claimed_1way_updates=((14, 18),),
            claimed_2way_updates=((((12, 14), 20)),),
            pred_split_keys=((14, 10, 18),),
            prefix_keys=((10, 14, 22),),
            redirect_blocks=(14,),
        )
        modifications: list = []
        claimed_1way: dict[int, int] = {}
        claimed_2way: dict[tuple[int, int], int] = {}
        emitted: set[tuple[int, int]] = set()
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        owned_transitions: set[tuple[int, int]] = set()
        pred_split_emitted: set[tuple[int, int, int]] = set()
        prefix_emitted: set[tuple[int, int, int]] = set()
        redirected_blocks: set[int] = set()

        apply_residual_dispatcher_source_plan(
            plan,
            modifications=modifications,
            claimed_1way=claimed_1way,
            claimed_2way=claimed_2way,
            emitted=emitted,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
            pred_split_emitted=pred_split_emitted,
            prefix_emitted=prefix_emitted,
            redirected_blocks=redirected_blocks,
        )

        assert modifications == [RedirectGoto(from_serial=14, old_target=6, new_target=18)]
        assert claimed_1way == {14: 18}
        assert claimed_2way == {(12, 14): 20}
        assert emitted == {(14, 18)}
        assert owned_blocks == {14, 10}
        assert owned_edges == {(14, 18)}
        assert owned_transitions == {(0x1111, 0x2222)}
        assert pred_split_emitted == {(14, 10, 18)}
        assert prefix_emitted == {(10, 14, 22)}
        assert redirected_blocks == {14}
