from __future__ import annotations

from d810.cfg.terminal_family_split import (
    TerminalFamilySplitCandidate,
    build_terminal_family_split_proposals,
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


class TestBuildTerminalFamilySplitProposals:
    def test_selects_non_primary_bucket_anchor_for_shared_suffix(self):
        candidates = (
            TerminalFamilySplitCandidate(
                source_block=10,
                branch_arm=None,
                family_entry=20,
                path=(20, 30, 40),
                value_family_signature=("keep",),
                lineage_eas=(0x1000,),
            ),
            TerminalFamilySplitCandidate(
                source_block=11,
                branch_arm=None,
                family_entry=21,
                path=(21, 30, 40),
                value_family_signature=("split",),
                lineage_eas=(0x2000,),
            ),
            TerminalFamilySplitCandidate(
                source_block=12,
                branch_arm=None,
                family_entry=22,
                path=(22, 30, 40),
                value_family_signature=("keep",),
                lineage_eas=(0x3000,),
            ),
        )
        flow_graph = _DummyFlowGraph({
            20: (30,),
            21: (30,),
            22: (30,),
            30: (40,),
            40: (),
        })

        proposals = build_terminal_family_split_proposals(
            candidates,
            projected_flow_graph=flow_graph,
        )

        assert proposals == (
            build_expected := proposals[0],
        )
        assert build_expected.suffix_serials == (30, 40)
        assert build_expected.selected_candidate_indexes == (1,)
        assert build_expected.selected_anchors == (21,)
        assert build_expected.primary_signature == ("keep",)
