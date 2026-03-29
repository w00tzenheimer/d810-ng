from __future__ import annotations

from d810.cfg.dag_redirect_modification_planning import (
    plan_dag_redirect_fallback_emission,
)
from d810.cfg.graph_modification import RedirectBranch, RedirectGoto


class TestPlanDagRedirectFallbackEmission:
    def test_rejects_transition_from_two_way_source(self):
        plan = plan_dag_redirect_fallback_emission(
            source_block=12,
            target_entry=18,
            nsucc=2,
            old_target=14,
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
        assert plan.claim_2way_key == (12, 14)
        assert plan.claim_2way_target == 18

    def test_rejects_oneway_conflict(self):
        plan = plan_dag_redirect_fallback_emission(
            source_block=12,
            target_entry=18,
            nsucc=1,
            old_target=6,
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
        assert plan.claim_1way_target == 18
