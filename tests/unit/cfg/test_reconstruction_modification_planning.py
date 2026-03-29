from __future__ import annotations

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
    def test_returns_duplicate_and_redirect(self):
        flow_graph = _DummyFlowGraph({
            10: ((8, 9), (2,)),
        })

        plan = plan_shared_group_reconstruction_modifications(
            flow_graph=flow_graph,
            shared_block=10,
            ordered_path=(10,),
            shared_candidates=(
                SharedGroupEmissionCandidate(via_pred=9, target_entry=2),
                SharedGroupEmissionCandidate(via_pred=8, target_entry=24),
            ),
        )

        assert plan.accepted
        assert plan.ordered_via_preds == (8, 9)
        assert plan.modifications == (
            DuplicateAndRedirect(
                source_serial=10,
                per_pred_targets=((9, 2), (8, 24)),
            ),
        )
