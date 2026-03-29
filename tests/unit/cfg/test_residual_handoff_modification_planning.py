from __future__ import annotations

from d810.cfg.graph_modification import RedirectBranch, RedirectGoto
from d810.cfg.residual_handoff_modification_planning import (
    plan_projected_alias_handoff_normalization,
    plan_residual_branch_anchor_emission,
)


class TestPlanResidualBranchAnchorEmission:
    def test_emits_branch_redirect_for_two_way_source(self):
        plan = plan_residual_branch_anchor_emission(
            is_conditional_branch_source=True,
            branch_source=12,
            source_block=14,
            via_pred=10,
            prefix_target=18,
            branch_succs=(14, 20),
            old_target=14,
            ordered_path=(12, 14),
            dispatcher_serial=6,
            bst_node_blocks=frozenset({6}),
            target_reaches_branch=False,
            claimed_branch_target=None,
            owned_transition=(0x11111111, 0x22222222),
            edge_kind_name="transition",
        )

        assert plan.accepted
        assert not plan.already_claimed
        assert plan.modification == RedirectBranch(
            from_serial=12,
            old_target=14,
            new_target=18,
        )

    def test_rejects_oneway_source(self):
        plan = plan_residual_branch_anchor_emission(
            is_conditional_branch_source=False,
            branch_source=12,
            source_block=14,
            via_pred=10,
            prefix_target=18,
            branch_succs=(14,),
            old_target=14,
            ordered_path=(12, 14),
            dispatcher_serial=6,
            bst_node_blocks=frozenset({6}),
            target_reaches_branch=False,
            claimed_branch_target=None,
            owned_transition=None,
            edge_kind_name="transition",
        )

        assert not plan.accepted
        assert plan.modification is None


class TestPlanProjectedAliasHandoffNormalization:
    def test_appends_new_redirect_when_unclaimed(self):
        plan = plan_projected_alias_handoff_normalization(
            source_block=14,
            current_target=6,
            target_entry=21,
            existing_redirect_index=None,
            existing_redirect_old_target=None,
            existing_redirect_target=None,
            already_emitted=False,
        )

        assert plan.accepted
        assert plan.replace_index is None
        assert plan.modification == RedirectGoto(
            from_serial=14,
            old_target=6,
            new_target=21,
        )

    def test_replaces_existing_redirect_when_target_changes(self):
        plan = plan_projected_alias_handoff_normalization(
            source_block=14,
            current_target=6,
            target_entry=21,
            existing_redirect_index=3,
            existing_redirect_old_target=6,
            existing_redirect_target=18,
            already_emitted=False,
        )

        assert plan.accepted
        assert plan.replace_index == 3
        assert plan.replaced_target == 18
        assert plan.modification == RedirectGoto(
            from_serial=14,
            old_target=6,
            new_target=21,
        )

    def test_rejects_when_existing_redirect_already_matches_target(self):
        plan = plan_projected_alias_handoff_normalization(
            source_block=14,
            current_target=6,
            target_entry=21,
            existing_redirect_index=3,
            existing_redirect_old_target=6,
            existing_redirect_target=21,
            already_emitted=False,
        )

        assert not plan.accepted
        assert plan.rejection_reason == "existing_redirect_matches_target"

    def test_rejects_when_emit_key_already_recorded(self):
        plan = plan_projected_alias_handoff_normalization(
            source_block=14,
            current_target=6,
            target_entry=21,
            existing_redirect_index=None,
            existing_redirect_old_target=None,
            existing_redirect_target=None,
            already_emitted=True,
        )

        assert not plan.accepted
        assert plan.rejection_reason == "already_emitted"
