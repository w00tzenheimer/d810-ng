from __future__ import annotations

from d810.cfg.reconstruction_lowering import (
    plan_conditional_arm_emission,
    plan_direct_emission,
    RedirectSpec,
    SharedGroupEmissionCandidate,
    plan_shared_group_emission,
)


class TestPlanSharedGroupEmission:
    def test_rejects_conflicting_targets_for_same_pred(self):
        plan = plan_shared_group_emission(
            shared_block=10,
            shared_preds=(8, 9),
            old_target=2,
            candidates=(
                SharedGroupEmissionCandidate(via_pred=8, target_entry=24),
                SharedGroupEmissionCandidate(via_pred=8, target_entry=30),
            ),
        )

        assert not plan.accepted
        assert plan.rejection_reason == "shared_block_conflict"

    def test_rejects_noop_when_all_targets_keep_old_target(self):
        plan = plan_shared_group_emission(
            shared_block=10,
            shared_preds=(8, 9),
            old_target=2,
            candidates=(
                SharedGroupEmissionCandidate(via_pred=8, target_entry=2),
                SharedGroupEmissionCandidate(via_pred=9, target_entry=2),
            ),
        )

        assert not plan.accepted
        assert plan.rejection_reason == "noop_or_missing_old_target"

    def test_accepts_and_orders_candidates_for_duplication(self):
        plan = plan_shared_group_emission(
            shared_block=10,
            shared_preds=(8, 9),
            old_target=2,
            candidates=(
                SharedGroupEmissionCandidate(via_pred=9, target_entry=2),
                SharedGroupEmissionCandidate(via_pred=8, target_entry=24),
            ),
        )

        assert plan.accepted
        assert plan.ordered_candidates == (
            SharedGroupEmissionCandidate(via_pred=8, target_entry=24),
            SharedGroupEmissionCandidate(via_pred=9, target_entry=2),
        )
        assert plan.per_pred_targets == ((9, 2), (8, 24))


class TestPlanDirectEmission:
    def test_rejects_missing_old_target(self):
        plan = plan_direct_emission(old_target=None, target_entry=16)
        assert not plan.accepted
        assert plan.rejection_reason == "noop_or_missing_old_target"

    def test_accepts_redirect_when_target_changes(self):
        plan = plan_direct_emission(old_target=6, target_entry=16)
        assert plan.accepted
        assert plan.old_target == 6


class TestPlanConditionalArmEmission:
    def test_redirects_transition_arm_when_it_targets_dispatcher(self):
        plan = plan_conditional_arm_emission(
            horizon_block=14,
            block_succs=(6, 20),
            branch_arm=0,
            target_entry=16,
            dispatcher_serial=6,
            current_entry=None,
        )

        assert plan.accepted
        assert plan.redirects == (
            RedirectSpec(source_block=14, target_block=16, old_target=6),
        )

    def test_two_dispatcher_arms_preserves_passthrough_arm_one_only(self):
        plan = plan_conditional_arm_emission(
            horizon_block=14,
            block_succs=(6, 6),
            branch_arm=0,
            target_entry=16,
            dispatcher_serial=6,
            current_entry=18,
        )

        assert plan.accepted
        assert plan.redirects == (
            RedirectSpec(source_block=14, target_block=18, old_target=6),
        )
