from __future__ import annotations

import pytest

from d810.cfg.graph_modification import (
    ConvertToGoto,
    DuplicateAndRedirect,
    RedirectBranch,
    RedirectGoto,
)
from d810.cfg.reconstruction_lowering import SharedGroupEmissionCandidate
from d810.cfg.reconstruction_modification_planning import (
    plan_conditional_arm_reconstruction_modifications,
    plan_direct_reconstruction_modifications,
    plan_passthrough_reconstruction_modifications,
    plan_shared_group_reconstruction_modifications,
)


class _DummyBlock:
    def __init__(self, preds: tuple[int, ...], succs: tuple[int, ...]):
        self.preds = preds
        self.succs = succs
        self.npred = len(preds)
        self.nsucc = len(succs)


class _DummyFlowGraph:
    def __init__(self, mapping: dict[int, tuple[tuple[int, ...], tuple[int, ...]]]):
        self._mapping = {
            int(k): _DummyBlock(tuple(int(v) for v in preds), tuple(int(v) for v in succs))
            for k, (preds, succs) in mapping.items()
        }

    def get_block(self, serial: int):
        return self._mapping.get(int(serial))


class TestPlanDirectReconstructionModifications:
    def test_uses_convert_to_goto_for_two_way_source(self):
        flow_graph = _DummyFlowGraph({
            14: ((12,), (6, 20)),
        })

        plan = plan_direct_reconstruction_modifications(
            flow_graph=flow_graph,
            horizon_block=14,
            target_entry=16,
            ordered_path=(14, 6),
        )

        assert plan.accepted
        assert plan.modifications == (
            ConvertToGoto(block_serial=14, goto_target=16),
        )


class TestPlanConditionalArmReconstructionModifications:
    def test_uses_branch_redirects(self):
        flow_graph = _DummyFlowGraph({
            14: ((12,), (6, 20)),
        })

        plan = plan_conditional_arm_reconstruction_modifications(
            flow_graph=flow_graph,
            horizon_block=14,
            target_entry=16,
            branch_arm=0,
            dispatcher_serial=6,
            current_entry=None,
        )

        assert plan.accepted
        assert plan.modifications == (
            RedirectBranch(from_serial=14, old_target=6, new_target=16),
        )

    def test_rejects_self_target_redirects(self):
        flow_graph = _DummyFlowGraph({
            161: ((159,), (2, 163)),
        })

        plan = plan_conditional_arm_reconstruction_modifications(
            flow_graph=flow_graph,
            horizon_block=161,
            target_entry=163,
            branch_arm=1,
            dispatcher_serial=2,
            current_entry=161,
        )

        assert not plan.accepted
        assert plan.rejection_reason == "invalid_or_noop_redirect"


class TestPlanPassthroughReconstructionModifications:
    def test_preserves_oneway_and_branch_shapes(self):
        flow_graph = _DummyFlowGraph({
            10: ((4,), (6,)),
            11: ((10,), (20, 6)),
            14: ((11,), (30,)),
        })

        plan = plan_passthrough_reconstruction_modifications(
            flow_graph=flow_graph,
            ordered_path=(10, 11, 14),
            horizon_block=14,
            dispatcher_serial=6,
            current_state_entry=18,
        )

        assert plan.accepted
        assert plan.modifications == (
            RedirectGoto(from_serial=10, old_target=6, new_target=18),
            RedirectBranch(from_serial=11, old_target=6, new_target=18),
        )


class TestPlanSharedGroupReconstructionModifications:
    def test_returns_per_pred_redirect_when_all_preds_can_be_rewritten(self):
        flow_graph = _DummyFlowGraph({
            8: ((), (10,)),
            9: ((), (10,)),
            10: ((8, 9), (24,)),
        })

        plan = plan_shared_group_reconstruction_modifications(
            flow_graph=flow_graph,
            shared_block=10,
            ordered_path=(10,),
            shared_candidates=(
                SharedGroupEmissionCandidate(via_pred=9, target_entry=24),
                SharedGroupEmissionCandidate(via_pred=8, target_entry=30),
            ),
        )

        assert plan.accepted
        assert plan.emission_mode == "per_pred_redirect"
        assert plan.ordered_via_preds == (8, 9)
        assert plan.modifications == (
            RedirectGoto(from_serial=9, old_target=10, new_target=24),
            RedirectGoto(from_serial=8, old_target=10, new_target=30),
        )

    def test_returns_duplicate_and_redirect(self):
        flow_graph = _DummyFlowGraph({
            10: ((8, 9), (2,)),
        })

        plan = plan_shared_group_reconstruction_modifications(
            flow_graph=flow_graph,
            shared_block=10,
            ordered_path=(10,),
            shared_candidates=(
                SharedGroupEmissionCandidate(via_pred=9, target_entry=30),
                SharedGroupEmissionCandidate(via_pred=8, target_entry=24),
            ),
        )

        assert plan.accepted
        assert plan.emission_mode == "duplicate_and_redirect"
        assert plan.ordered_via_preds == (8, 9)
        assert plan.modifications == (
            DuplicateAndRedirect(
                source_serial=10,
                per_pred_targets=((8, 24), (9, 30)),
            ),
        )

    def test_force_clone_emits_duplicate_and_redirect(self):
        flow_graph = _DummyFlowGraph({
            8: ((), (10,)),
            11: ((), (10,)),
            10: ((8, 11), (2,)),
        })

        plan = plan_shared_group_reconstruction_modifications(
            flow_graph=flow_graph,
            shared_block=10,
            ordered_path=(8, 10),
            shared_candidates=(
                SharedGroupEmissionCandidate(via_pred=8, target_entry=24),
            ),
            force_clone=True,
        )

        assert plan.accepted
        assert plan.emission_mode == "duplicate_and_redirect"
        assert plan.modifications == (
            DuplicateAndRedirect(
                source_serial=10,
                per_pred_targets=((11, 2), (8, 24)),
            ),
        )

    @pytest.mark.xfail(
        reason=(
            "single_pred_redirect emission mode not yet implemented; "
            "planner currently rejects single-candidate single-pred "
            "shared blocks as missing_keep_pred. Tracked in tk uee-o685"
        ),
        strict=True,
    )
    def test_single_candidate_single_pred_shared_block_falls_back_to_direct_redirect(self):
        flow_graph = _DummyFlowGraph({
            10: ((8,), (2,)),
        })

        plan = plan_shared_group_reconstruction_modifications(
            flow_graph=flow_graph,
            shared_block=10,
            ordered_path=(10,),
            shared_candidates=(
                SharedGroupEmissionCandidate(via_pred=8, target_entry=24),
            ),
        )

        assert plan.accepted
        assert plan.emission_mode == "single_pred_redirect"
        assert plan.ordered_via_preds == (8,)
        assert plan.modifications == (
            RedirectGoto(from_serial=10, old_target=2, new_target=24),
        )
