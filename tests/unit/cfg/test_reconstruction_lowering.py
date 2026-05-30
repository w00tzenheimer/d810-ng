from __future__ import annotations

from d810.transforms.reconstruction_lowering import (
    plan_conditional_arm_emission,
    plan_direct_emission,
    plan_passthrough_redirects,
    RedirectSpec,
    SharedGroupEmissionCandidate,
    plan_shared_group_emission,
)


class _DummyBlock:
    def __init__(self, succs: tuple[int, ...]):
        self.succs = succs
        self.nsucc = len(succs)


class _DummyFlowGraph:
    def __init__(self, mapping: dict[int, tuple[int, ...]]):
        self._mapping = {
            int(k): _DummyBlock(tuple(int(v) for v in succs))
            for k, succs in mapping.items()
        }

    def get_block(self, serial: int):
        return self._mapping.get(int(serial))


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


class TestPlanPassthroughRedirects:
    def test_collects_oneway_and_arm1_dispatcher_redirects(self):
        flow_graph = _DummyFlowGraph({
            10: (6,),
            11: (20, 6),
            12: (6, 21),
            14: (30,),
        })

        redirects = plan_passthrough_redirects(
            flow_graph=flow_graph,
            ordered_path=(10, 11, 12, 14),
            horizon_block=14,
            dispatcher_serial=6,
            current_state_entry=18,
        )

        assert redirects == (
            RedirectSpec(source_block=10, target_block=18, old_target=6),
            RedirectSpec(source_block=11, target_block=18, old_target=6),
        )

    def test_ignores_suffix_blocks_after_horizon(self):
        flow_graph = _DummyFlowGraph({
            10: (6,),
            11: (20, 6),
            14: (30, 31),
            15: (6,),
        })

        redirects = plan_passthrough_redirects(
            flow_graph=flow_graph,
            ordered_path=(10, 11, 14, 15),
            horizon_block=14,
            dispatcher_serial=6,
            current_state_entry=18,
        )

        assert redirects == (
            RedirectSpec(source_block=10, target_block=18, old_target=6),
            RedirectSpec(source_block=11, target_block=18, old_target=6),
        )
