from __future__ import annotations

from d810.cfg.reconstruction_lowering import (
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
