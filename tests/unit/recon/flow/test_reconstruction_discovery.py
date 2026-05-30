from __future__ import annotations

from types import SimpleNamespace

from d810.ir.flowgraph import InsnKind, OperandKind
from d810.analyses.control_flow.linearized_state_dag import SemanticEdgeKind
from d810.analyses.control_flow.reconstruction_discovery import (
    classify_artifact_return_blocks,
    collect_shared_suffix_blocks,
    discover_reconstruction_candidate_seed,
)
from d810.analyses.control_flow.state_machine_analysis import StateWriteSite


class _Insn:
    def __init__(self, *, kind, l=None, d=None):
        self.kind = kind
        self.l = l
        self.d = d


class _Block:
    def __init__(self, insns):
        self.insn_snapshots = tuple(insns)


class _FlowGraph:
    def __init__(self, blocks):
        self.blocks = blocks


class TestCollectSharedSuffixBlocks:
    def test_collects_union(self) -> None:
        dag = SimpleNamespace(
            nodes=(
                SimpleNamespace(shared_suffix_blocks=(10, 11)),
                SimpleNamespace(shared_suffix_blocks=(11, 12)),
            )
        )

        assert collect_shared_suffix_blocks(dag) == {10, 11, 12}


class TestClassifyArtifactReturnBlocks:
    def test_classifies_xdu_and_const_artifacts(self) -> None:
        flow_graph = _FlowGraph(
            {
                41: _Block(
                    [
                        _Insn(
                            kind=InsnKind.XDU,
                            l=SimpleNamespace(kind=OperandKind.STACK, stkoff=0x30),
                            d=SimpleNamespace(kind=OperandKind.STACK, stkoff=0x680),
                        )
                    ]
                ),
                47: _Block(
                    [
                        _Insn(
                            kind=InsnKind.MOV,
                            l=SimpleNamespace(
                                kind=OperandKind.NUMBER,
                                value=0x12345678,
                            ),
                            d=SimpleNamespace(kind=OperandKind.STACK, stkoff=0x680),
                        )
                    ]
                ),
                71: _Block(
                    [
                        _Insn(
                            kind=InsnKind.MOV,
                            l=SimpleNamespace(
                                kind=OperandKind.NUMBER,
                                value=0x99999999,
                            ),
                            d=SimpleNamespace(kind=OperandKind.STACK, stkoff=0x30),
                        )
                    ]
                ),
            }
        )

        assert classify_artifact_return_blocks(
            flow_graph,
            state_var_stkoff=0x30,
            state_constants={0x12345678},
        ) == {41, 47}


class TestDiscoverReconstructionCandidateSeed:
    def test_discovers_seed_and_preserves_original_dispatcher_entry(
        self,
        monkeypatch,
    ) -> None:
        edge = SimpleNamespace(
            kind=SemanticEdgeKind.TRANSITION,
            target_state=0x22,
            ordered_path=(10, 11),
        )
        site = StateWriteSite(
            block_serial=11,
            state_value=0x22,
            insn_ea=0x1000,
            insn_index=0,
        )

        monkeypatch.setattr(
            "d810.analyses.control_flow.reconstruction_discovery.resolve_transition_path_horizon",
            lambda edge, **kwargs: (11, site),
        )
        monkeypatch.setattr(
            "d810.analyses.control_flow.reconstruction_discovery.resolve_edge_target_entry",
            lambda edge, **kwargs: SimpleNamespace(
                target_entry=88,
                rejection_reason=None,
                original_dispatcher_entry=7,
            ),
        )

        seed, rejection = discover_reconstruction_candidate_seed(
            edge,
            flow_graph=object(),
            node_by_key={},
            state_var_stkoff=0x30,
            constant_result=object(),
            dispatcher_region={7},
        )

        assert rejection is None
        assert seed is not None
        assert seed.horizon_block == 11
        assert seed.site == site
        assert seed.target_entry == 88
        assert seed.original_dispatcher_entry == 7
