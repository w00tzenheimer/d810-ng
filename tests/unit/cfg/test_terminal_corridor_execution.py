from __future__ import annotations

from d810.transforms.graph_modification import ConvertToGoto, PrivateTerminalSuffixGroup
from d810.transforms.modification_builder import ModificationBuilder
from d810.transforms.terminal_corridor_emission import (
    plan_direct_terminal_lowering_execution,
    plan_private_terminal_suffix_execution,
)


class _FakeFlowBlock:
    def __init__(self, serial: int, succs: tuple[int, ...], preds: tuple[int, ...], *, tail_opcode=None):
        self.serial = serial
        self.succs = succs
        self.preds = preds
        self.nsucc = len(succs)
        self.tail_opcode = tail_opcode


class _FakeFlowGraph:
    def __init__(self, blocks: tuple[_FakeFlowBlock, ...]):
        self._blocks = {block.serial: block for block in blocks}

    def get_block(self, serial: int):
        return self._blocks.get(serial)


def test_pts_execution_adds_return_fallthrough_fix_and_group():
    builder = ModificationBuilder(
        block_nsucc_map={10: 1, 11: 1, 19: 1},
        block_succ_map={10: (20,), 11: (20,), 19: (30,)},
    )
    flow_graph = _FakeFlowGraph(
        (
            _FakeFlowBlock(10, (20,), ()),
            _FakeFlowBlock(11, (20,), ()),
            _FakeFlowBlock(19, (30,), ()),
            _FakeFlowBlock(30, (), (19,)),
        )
    )

    plan = plan_private_terminal_suffix_execution(
        flow_graph=flow_graph,
        builder=builder,
        anchors=(10, 11),
        shared_entry_serial=20,
        return_block_serial=30,
        suffix_serials=(30,),
    )

    assert plan.modifications[0] == ConvertToGoto(block_serial=19, goto_target=30)
    assert isinstance(plan.modifications[1], PrivateTerminalSuffixGroup)
    assert plan.owned_edges == frozenset({(10, 20), (11, 20)})


def test_dtl_execution_builds_clone_materializer_site():
    builder = ModificationBuilder(
        block_nsucc_map={10: 1},
        block_succ_map={10: (40,)},
    )
    flow_graph = _FakeFlowGraph((_FakeFlowBlock(10, (40,), ()),))

    plan = plan_direct_terminal_lowering_execution(
        flow_graph=flow_graph,
        builder=builder,
        anchors=(10,),
        shared_entry_serial=40,
        return_block_serial=50,
        suffix_serials=(41, 50),
    )

    assert len(plan.supported_sites) == 1
    assert plan.supported_sites[0].anchor_serial == 10
    assert plan.supported_sites[0].materializer_serials == (41,)
    assert len(plan.modifications) == 1
