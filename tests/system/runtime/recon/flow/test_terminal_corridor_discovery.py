from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.cfg.flow.terminal_frontier import TerminalLoweringAction
from d810.analyses.control_flow.terminal_corridor_discovery import (
    CarrierSourceKind,
    CorridorRecommendation,
    ForwardFrontierEntry,
    discover_shared_corridor,
    discover_terminal_corridor_group,
)


class _FakeStackRef:
    def __init__(self, off: int):
        self.off = off


class _FakeStateVar:
    def __init__(self, off: int):
        self.t = ida_hexrays.mop_S
        self.s = _FakeStackRef(off)


class _FakeBlock:
    def __init__(
        self,
        serial: int,
        succs: tuple[int, ...],
        preds: tuple[int, ...],
        *,
        tail_opcode=None,
        block_type: int = 3,
        insns: tuple[object, ...] = (),
    ):
        self.serial = serial
        self.succs = succs
        self.preds = preds
        self.nsucc = len(succs)
        self.npred = len(preds)
        self.tail_opcode = tail_opcode
        self.block_type = block_type
        self._insns = insns

    def iter_insns(self):
        return iter(self._insns)


class _FakeFlowGraph:
    def __init__(self, blocks: tuple[_FakeBlock, ...]):
        self.blocks = {block.serial: block for block in blocks}

    def get_block(self, serial: int):
        return self.blocks.get(serial)

    def successors(self, serial: int):
        block = self.blocks.get(serial)
        return tuple(block.succs) if block is not None else ()

    def predecessors(self, serial: int):
        block = self.blocks.get(serial)
        return tuple(block.preds) if block is not None else ()


def test_discover_shared_corridor_reports_linear_clonable_corridor():
    flow_graph = _FakeFlowGraph(
        (
            _FakeBlock(20, (30,), (10, 11)),
            _FakeBlock(30, (40,), (20,)),
            _FakeBlock(40, (), (30,)),
        )
    )
    entries = (
        ForwardFrontierEntry(
            handler_entry=10,
            terminal_path=(10,),
            forward_candidate=10,
            candidate_succ=20,
            shared_entry=20,
            return_block=40,
            suffix_serials=(20, 30, 40),
            semantic_action=TerminalLoweringAction.PRIVATE_TERMINAL_SUFFIX,
            carrier_source_kind=CarrierSourceKind.UNKNOWN,
            proof_status="unresolved",
        ),
        ForwardFrontierEntry(
            handler_entry=11,
            terminal_path=(11,),
            forward_candidate=11,
            candidate_succ=20,
            shared_entry=20,
            return_block=40,
            suffix_serials=(20, 30, 40),
            semantic_action=TerminalLoweringAction.PRIVATE_TERMINAL_SUFFIX,
            carrier_source_kind=CarrierSourceKind.UNKNOWN,
            proof_status="unresolved",
        ),
    )

    corridor = discover_shared_corridor(
        flow_graph,
        20,
        (30, 40),
        frozenset({2, 30, 40}),
        entries,
    )

    assert corridor.corridor_blocks == (20,)
    assert corridor.clonable is True
    assert corridor.recommendation == CorridorRecommendation.PRIVATE_TERMINAL_CORRIDOR


def test_discover_terminal_corridor_group_collects_shared_frontier():
    flow_graph = _FakeFlowGraph(
        (
            _FakeBlock(2, (10,), (), block_type=4),
            _FakeBlock(10, (20,), (2,)),
            _FakeBlock(11, (20,), (), tail_opcode=ida_hexrays.m_goto),
            _FakeBlock(20, (30,), (10, 11)),
            _FakeBlock(30, (40,), (20,)),
            _FakeBlock(40, (), (30,), tail_opcode=ida_hexrays.m_ret, block_type=1),
        )
    )
    state_machine = SimpleNamespace(
        state_var=_FakeStateVar(0x10),
        state_constants=set(),
        handlers={
            1: SimpleNamespace(check_block=10, handler_blocks=(10,)),
            2: SimpleNamespace(check_block=11, handler_blocks=(11,)),
        },
    )
    snapshot = SimpleNamespace(
        carrier_resolver=None,
        state_var_stkoff=0x10,
        state_machine=state_machine,
        detector=None,
        dispatcher_blocks=frozenset(),
        dispatcher_serial=2,
        state_constants=frozenset(),
        flow_graph=flow_graph,
    )

    result = discover_terminal_corridor_group(
        snapshot,
        anchor_note="unit-test-anchor",
    )

    assert result.failure_reason is None
    assert result.group is not None
    assert result.group.shared_entry == 20
    assert result.group.return_block == 40
    assert result.group.anchors == (10, 11)
    assert tuple(entry.notes for entry in result.group.forward_entries) == (
        "unit-test-anchor",
        "unit-test-anchor",
    )


def test_discover_terminal_corridor_group_rejects_missing_dispatcher_evidence():
    flow_graph = _FakeFlowGraph(
        (
            _FakeBlock(10, (20,), ()),
            _FakeBlock(11, (20,), ()),
            _FakeBlock(20, (30,), (10, 11)),
            _FakeBlock(30, (40,), (20,)),
            _FakeBlock(40, (), (30,), tail_opcode=ida_hexrays.m_ret, block_type=1),
        )
    )
    state_machine = SimpleNamespace(
        state_var=_FakeStateVar(0x10),
        state_constants=set(),
        handlers={
            1: SimpleNamespace(check_block=10, handler_blocks=(10,)),
            2: SimpleNamespace(check_block=11, handler_blocks=(11,)),
        },
    )
    snapshot = SimpleNamespace(
        carrier_resolver=None,
        state_var_stkoff=0x10,
        state_machine=state_machine,
        detector=None,
        dispatcher_blocks=frozenset(),
        dispatcher_serial=-1,
        state_constants=frozenset(),
        flow_graph=flow_graph,
    )

    result = discover_terminal_corridor_group(
        snapshot,
        anchor_note="unit-test-anchor",
    )

    assert result.group is None
    assert result.failure_reason == "missing_bst_result"


def test_discover_terminal_corridor_group_excludes_dispatcher_block_set():
    flow_graph = _FakeFlowGraph(
        (
            _FakeBlock(2, (10,), (), block_type=4),
            _FakeBlock(9, (20,), (), block_type=4),
            _FakeBlock(10, (20,), (2,)),
            _FakeBlock(11, (20,), (), tail_opcode=ida_hexrays.m_goto),
            _FakeBlock(20, (30,), (9, 10, 11)),
            _FakeBlock(30, (40,), (20,)),
            _FakeBlock(40, (), (30,), tail_opcode=ida_hexrays.m_ret, block_type=1),
        )
    )
    state_machine = SimpleNamespace(
        state_var=_FakeStateVar(0x10),
        state_constants=set(),
        handlers={
            1: SimpleNamespace(check_block=10, handler_blocks=(10,)),
            2: SimpleNamespace(check_block=11, handler_blocks=(11,)),
        },
    )
    snapshot = SimpleNamespace(
        carrier_resolver=None,
        state_var_stkoff=0x10,
        state_machine=state_machine,
        detector=None,
        dispatcher_blocks=frozenset({2, 9}),
        dispatcher_serial=2,
        state_constants=frozenset(),
        flow_graph=flow_graph,
    )

    result = discover_terminal_corridor_group(
        snapshot,
        anchor_note="unit-test-anchor",
    )

    assert result.failure_reason is None
    assert result.group is not None
    assert result.group.full_infra >= frozenset({2, 9})
    assert result.group.anchors == (10, 11)
