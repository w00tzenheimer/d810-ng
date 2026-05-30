from __future__ import annotations

from d810.transforms.dag_redirect_modification_planning import (
    DagRedirectFallbackContext,
    apply_dag_redirect_emission_plan,
    plan_dag_redirect_fallback,
    plan_dag_redirect_fallback_emission,
)
from d810.transforms.graph_modification import RedirectBranch, RedirectGoto


class TestPlanDagRedirectFallbackEmission:
    def test_rejects_transition_from_two_way_source(self):
        plan = plan_dag_redirect_fallback_emission(
            source_block=12,
            target_entry=18,
            nsucc=2,
            old_target=14,
            source_succs=(14, 20),
            edge_is_transition=True,
            live_oneway_noop=False,
            claimed_1way_target=None,
            claimed_2way_target=None,
        )

        assert not plan.accepted
        assert plan.rejection_reason == "transition_two_way_source"

    def test_emits_branch_redirect_for_two_way_non_transition(self):
        plan = plan_dag_redirect_fallback_emission(
            source_block=12,
            target_entry=18,
            nsucc=2,
            old_target=14,
            source_succs=(14, 20),
            edge_is_transition=False,
            live_oneway_noop=False,
            claimed_1way_target=None,
            claimed_2way_target=None,
        )

        assert plan.accepted
        assert plan.modification == RedirectBranch(
            from_serial=12,
            old_target=14,
            new_target=18,
        )
        assert plan.source_block == 12
        assert plan.target_entry == 18
        assert plan.claim_2way_key == (12, 14)
        assert plan.claim_2way_target == 18

    def test_rejects_oneway_conflict(self):
        plan = plan_dag_redirect_fallback_emission(
            source_block=12,
            target_entry=18,
            nsucc=1,
            old_target=6,
            source_succs=(6,),
            edge_is_transition=False,
            live_oneway_noop=False,
            claimed_1way_target=20,
            claimed_2way_target=None,
        )

        assert not plan.accepted
        assert plan.rejection_reason == "oneway_conflict"
        assert plan.existing_target == 20

    def test_emits_goto_for_oneway(self):
        plan = plan_dag_redirect_fallback_emission(
            source_block=12,
            target_entry=18,
            nsucc=1,
            old_target=6,
            source_succs=(6,),
            edge_is_transition=False,
            live_oneway_noop=False,
            claimed_1way_target=None,
            claimed_2way_target=None,
        )

        assert plan.accepted
        assert plan.modification == RedirectGoto(
            from_serial=12,
            old_target=6,
            new_target=18,
        )
        assert plan.source_block == 12
        assert plan.target_entry == 18
        assert plan.claim_1way_target == 18

    def test_inferrs_oneway_old_target_from_live_successor(self):
        plan = plan_dag_redirect_fallback_emission(
            source_block=12,
            target_entry=18,
            nsucc=1,
            old_target=None,
            source_succs=(6,),
            edge_is_transition=False,
            live_oneway_noop=False,
            claimed_1way_target=None,
            claimed_2way_target=None,
        )

        assert plan.accepted
        assert plan.modification == RedirectGoto(
            from_serial=12,
            old_target=6,
            new_target=18,
        )

    def test_rejects_oneway_when_old_target_cannot_be_inferred(self):
        plan = plan_dag_redirect_fallback_emission(
            source_block=12,
            target_entry=18,
            nsucc=1,
            old_target=None,
            source_succs=(),
            edge_is_transition=False,
            live_oneway_noop=False,
            claimed_1way_target=None,
            claimed_2way_target=None,
        )

        assert not plan.accepted
        assert plan.rejection_reason == "unknown_old_target"


class TestPlanDagRedirectFallback:
    def test_rejects_backwards_corridor_before_emission(self):
        decision = plan_dag_redirect_fallback(
            DagRedirectFallbackContext(
                source_block=12,
                target_entry=18,
                source_handler_is_report_exit=False,
                ordered_path_head_is_report_exit=False,
                source_equals_target=False,
                backward_same_corridor=True,
                allow_semantic_handoff=False,
                target_reaches_source=False,
                source_blocked=False,
                source_terminal_protected=False,
                source_in_report_exit_owned=False,
                source_in_terminal_source_owned_transition=False,
                ordered_path_ends_at_source=True,
                emitted_already=False,
                nsucc=1,
                old_target=6,
                source_succs=(6,),
                edge_is_transition=False,
                live_oneway_noop=False,
                claimed_1way_target=None,
                claimed_2way_target=None,
            )
        )

        assert not decision.accepted
        assert decision.rejection_reason == "backward_same_corridor"

    def test_rejects_target_backreach_without_semantic_handoff(self):
        decision = plan_dag_redirect_fallback(
            DagRedirectFallbackContext(
                source_block=12,
                target_entry=18,
                source_handler_is_report_exit=False,
                ordered_path_head_is_report_exit=False,
                source_equals_target=False,
                backward_same_corridor=False,
                allow_semantic_handoff=False,
                target_reaches_source=True,
                source_blocked=False,
                source_terminal_protected=False,
                source_in_report_exit_owned=False,
                source_in_terminal_source_owned_transition=False,
                ordered_path_ends_at_source=True,
                emitted_already=False,
                nsucc=1,
                old_target=6,
                source_succs=(6,),
                edge_is_transition=False,
                live_oneway_noop=False,
                claimed_1way_target=None,
                claimed_2way_target=None,
            )
        )

        assert not decision.accepted
        assert decision.rejection_reason == "target_reaches_source"

    def test_accepts_and_wraps_emission_plan(self):
        decision = plan_dag_redirect_fallback(
            DagRedirectFallbackContext(
                source_block=12,
                target_entry=18,
                source_handler_is_report_exit=False,
                ordered_path_head_is_report_exit=False,
                source_equals_target=False,
                backward_same_corridor=False,
                allow_semantic_handoff=False,
                target_reaches_source=False,
                source_blocked=False,
                source_terminal_protected=False,
                source_in_report_exit_owned=False,
                source_in_terminal_source_owned_transition=False,
                ordered_path_ends_at_source=True,
                emitted_already=False,
                nsucc=1,
                old_target=6,
                source_succs=(6,),
                edge_is_transition=False,
                live_oneway_noop=False,
                claimed_1way_target=None,
                claimed_2way_target=None,
            )
        )

        assert decision.accepted
        assert decision.emission_plan is not None
        assert decision.emission_plan.modification == RedirectGoto(
            from_serial=12,
            old_target=6,
            new_target=18,
        )


class TestApplyDagRedirectEmissionPlan:
    def test_applies_branch_claims_and_ownership(self):
        plan = plan_dag_redirect_fallback_emission(
            source_block=12,
            target_entry=18,
            nsucc=2,
            old_target=14,
            source_succs=(14, 20),
            edge_is_transition=False,
            live_oneway_noop=False,
            claimed_1way_target=None,
            claimed_2way_target=None,
        )

        modifications = []
        claimed_1way: dict[int, int] = {}
        claimed_2way: dict[tuple[int, int], int] = {}
        emitted: set[tuple[int, int]] = set()
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        owned_transitions: set[tuple[int, int]] = set()

        apply_dag_redirect_emission_plan(
            plan,
            modifications=modifications,
            claimed_1way=claimed_1way,
            claimed_2way=claimed_2way,
            emitted=emitted,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
            owned_transition=(0x11, 0x22),
        )

        assert modifications == [plan.modification]
        assert claimed_1way == {}
        assert claimed_2way == {(12, 14): 18}
        assert emitted == {(12, 18)}
        assert owned_blocks == {12}
        assert owned_edges == {(12, 18)}
        assert owned_transitions == {(0x11, 0x22)}
