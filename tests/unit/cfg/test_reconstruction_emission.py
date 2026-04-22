from __future__ import annotations

from d810.cfg.reconstruction_emission_planning import plan_reconstruction_emission


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


class TestPlanReconstructionEmission:
    def test_accepts_direct_private_corridor(self):
        flow_graph = _DummyFlowGraph({
            14: ((12,), (16,)),
            16: ((14,), (18,)),
            18: ((16,), (20,)),
        })
        decision = plan_reconstruction_emission(
            flow_graph,
            (14, 16, 18),
            horizon_block=14,
            source_anchor_block=10,
            source_branch_arm=None,
            is_conditional_transition=False,
            shared_suffix_blocks=set(),
            dispatcher_region=set(),
            has_unsafe_trailing_insns=False,
        )
        assert decision.accepted
        assert decision.emission_mode == "direct"
        assert decision.first_shared_block is None

    def test_accepts_conditional_arm_at_branch_horizon(self):
        flow_graph = _DummyFlowGraph({
            14: ((12,), (16, 18)),
        })
        decision = plan_reconstruction_emission(
            flow_graph,
            (14, 16),
            horizon_block=14,
            source_anchor_block=14,
            source_branch_arm=1,
            is_conditional_transition=True,
            shared_suffix_blocks=set(),
            dispatcher_region=set(),
            has_unsafe_trailing_insns=False,
        )
        assert decision.accepted
        assert decision.emission_mode == "conditional_arm"

    def test_falls_back_to_pred_split_for_shared_block(self):
        flow_graph = _DummyFlowGraph({
            12: ((8,), (14,)),
            14: ((12, 13), (16,)),
            16: ((14,), (18,)),
        })
        decision = plan_reconstruction_emission(
            flow_graph,
            (12, 14, 16),
            horizon_block=14,
            source_anchor_block=10,
            source_branch_arm=None,
            is_conditional_transition=False,
            shared_suffix_blocks=set(),
            dispatcher_region=set(),
            has_unsafe_trailing_insns=False,
        )
        assert decision.accepted
        assert decision.emission_mode == "pred_split"
        assert decision.first_shared_block == 14
        assert decision.via_pred == 12

    def test_rejects_when_no_shared_site_and_trailing_effects_exist(self):
        flow_graph = _DummyFlowGraph({
            12: ((8,), (16, 18)),
        })
        decision = plan_reconstruction_emission(
            flow_graph,
            (12, 16),
            horizon_block=12,
            source_anchor_block=10,
            source_branch_arm=None,
            is_conditional_transition=False,
            shared_suffix_blocks=set(),
            dispatcher_region=set(),
            has_unsafe_trailing_insns=True,
        )
        assert not decision.accepted
        assert decision.rejection_reason == "blocked_side_effects"
