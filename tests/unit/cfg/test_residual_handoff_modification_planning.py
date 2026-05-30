from __future__ import annotations

from d810.transforms.graph_modification import (
    EdgeRedirectViaPredSplit,
    RedirectBranch,
    RedirectGoto,
)
from d810.transforms.residual_handoff_modification_planning import (
    apply_residual_branch_anchor_emission_plan,
    plan_residual_goto_emission,
    plan_residual_pred_split_emissions,
    plan_residual_prefix_peel_emission,
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


class TestApplyResidualBranchAnchorEmissionPlan:
    def test_updates_claims_and_ownership(self):
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

        modifications = []
        claimed_2way: dict[tuple[int, int], int] = {}
        emitted: set[tuple[int, int]] = set()
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        owned_transitions: set[tuple[int, int]] = set()

        apply_residual_branch_anchor_emission_plan(
            plan,
            modifications=modifications,
            claimed_2way=claimed_2way,
            emitted=emitted,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
        )

        assert modifications == [plan.modification]
        assert claimed_2way == {(12, 14): 18}
        assert emitted == {(12, 18)}
        assert owned_blocks == {12}
        assert owned_edges == {(12, 18)}
        assert owned_transitions == {(0x11111111, 0x22222222)}


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


class TestResidualDispatcherEmissionPlanning:
    def test_pred_split_emits_edge_redirects(self):
        plans = plan_residual_pred_split_emissions(
            source_block=14,
            dispatcher_serial=6,
            pred_splits=((10, 18), (11, 20)),
        )

        assert plans == (
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

    def test_goto_emits_redirect_goto(self):
        plan = plan_residual_goto_emission(
            source_block=14,
            dispatcher_serial=6,
            target_entry=18,
        )

        assert plan == RedirectGoto(
            from_serial=14,
            old_target=6,
            new_target=18,
        )

    def test_prefix_peel_emits_branch_for_two_way_pred(self):
        plan = plan_residual_prefix_peel_emission(
            via_pred=12,
            prefix_target=18,
            old_target=14,
            via_pred_succs=(14, 20),
        )

        assert plan == RedirectBranch(
            from_serial=12,
            old_target=14,
            new_target=18,
        )

    def test_prefix_peel_emits_goto_for_one_way_pred(self):
        plan = plan_residual_prefix_peel_emission(
            via_pred=12,
            prefix_target=18,
            old_target=14,
            via_pred_succs=(14,),
        )

        assert plan == RedirectGoto(
            from_serial=12,
            old_target=14,
            new_target=18,
        )
