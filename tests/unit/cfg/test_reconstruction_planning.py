from __future__ import annotations

from d810.transforms.reconstruction_planning import (
    ReconstructionEmissionMode,
    ReconstructionLoweringContext,
    ReconstructionLoweringKind,
    ReconstructionPlanningContext,
    plan_reconstruction_candidate,
    plan_reconstruction_lowering,
)
from d810.transforms.reconstruction_lowering import RedirectSpec, SharedGroupEmissionCandidate


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


class TestPlanReconstructionCandidate:
    def test_accepts_direct_private_corridor(self):
        flow_graph = _DummyFlowGraph({
            14: ((12,), (16,)),
            16: ((14,), (18,)),
            18: ((16,), (20,)),
        })
        decision = plan_reconstruction_candidate(
            flow_graph,
            ReconstructionPlanningContext(
                ordered_path=(14, 16, 18),
                horizon_block=14,
                target_entry=24,
                source_anchor_block=10,
                source_branch_arm=None,
                is_conditional_transition=False,
                shared_suffix_blocks=frozenset(),
                dispatcher_region=frozenset(),
                has_unsafe_trailing_insns=False,
            ),
        )
        assert decision.accepted
        assert decision.target_entry == 24
        assert decision.emission_mode == ReconstructionEmissionMode.DIRECT
        assert decision.first_shared_block is None

    def test_accepts_conditional_arm_at_branch_horizon(self):
        flow_graph = _DummyFlowGraph({
            14: ((12,), (16, 18)),
        })
        decision = plan_reconstruction_candidate(
            flow_graph,
            ReconstructionPlanningContext(
                ordered_path=(14, 16),
                horizon_block=14,
                target_entry=24,
                source_anchor_block=14,
                source_branch_arm=1,
                is_conditional_transition=True,
                shared_suffix_blocks=frozenset(),
                dispatcher_region=frozenset(),
                has_unsafe_trailing_insns=False,
            ),
        )
        assert decision.accepted
        assert decision.emission_mode == ReconstructionEmissionMode.CONDITIONAL_ARM

    def test_falls_back_to_pred_split_for_shared_block(self):
        flow_graph = _DummyFlowGraph({
            12: ((8,), (14,)),
            14: ((12, 13), (16,)),
            16: ((14,), (18,)),
        })
        decision = plan_reconstruction_candidate(
            flow_graph,
            ReconstructionPlanningContext(
                ordered_path=(12, 14, 16),
                horizon_block=14,
                target_entry=24,
                source_anchor_block=10,
                source_branch_arm=None,
                is_conditional_transition=False,
                shared_suffix_blocks=frozenset(),
                dispatcher_region=frozenset(),
                has_unsafe_trailing_insns=False,
            ),
        )
        assert decision.accepted
        assert decision.target_entry == 24
        assert decision.emission_mode == ReconstructionEmissionMode.PRED_SPLIT
        assert decision.first_shared_block == 14
        assert decision.via_pred == 12

    def test_rejects_when_no_shared_site_and_trailing_effects_exist(self):
        flow_graph = _DummyFlowGraph({
            12: ((8,), (16, 18)),
        })
        decision = plan_reconstruction_candidate(
            flow_graph,
            ReconstructionPlanningContext(
                ordered_path=(12, 16),
                horizon_block=12,
                target_entry=24,
                source_anchor_block=10,
                source_branch_arm=None,
                is_conditional_transition=False,
                shared_suffix_blocks=frozenset(),
                dispatcher_region=frozenset(),
                has_unsafe_trailing_insns=True,
            ),
        )
        assert not decision.accepted
        assert decision.target_entry == 24
        assert decision.rejection_reason == "blocked_side_effects"


class TestPlanReconstructionLowering:
    def test_dispatches_direct_lowering(self):
        decision = plan_reconstruction_lowering(
            flow_graph=None,
            context=ReconstructionLoweringContext(
                kind=ReconstructionLoweringKind.DIRECT,
                target_entry=16,
                old_target=6,
                horizon_block=14,
            ),
        )

        assert decision.accepted
        assert decision.kind == ReconstructionLoweringKind.DIRECT
        assert decision.redirects == (
            RedirectSpec(source_block=14, target_block=16, old_target=6),
        )

    def test_dispatches_shared_group_lowering(self):
        decision = plan_reconstruction_lowering(
            flow_graph=None,
            context=ReconstructionLoweringContext(
                kind=ReconstructionLoweringKind.SHARED_GROUP,
                shared_block=10,
                shared_preds=(8, 9),
                old_target=2,
                shared_candidates=(
                    SharedGroupEmissionCandidate(via_pred=9, target_entry=2),
                    SharedGroupEmissionCandidate(via_pred=8, target_entry=24),
                ),
            ),
        )

        assert decision.accepted
        assert decision.kind == ReconstructionLoweringKind.SHARED_GROUP
        assert decision.ordered_candidates == (
            SharedGroupEmissionCandidate(via_pred=8, target_entry=24),
            SharedGroupEmissionCandidate(via_pred=9, target_entry=2),
        )
        assert decision.per_pred_targets == ((9, 2), (8, 24))
