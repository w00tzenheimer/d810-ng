from __future__ import annotations

from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.semantics import PredicateKind
from d810.transforms.graph_modification import (
    ConvertToGoto,
    DirectTerminalLoweringGroup,
    PrivateTerminalSuffixGroup,
    RedirectGoto,
)
from d810.transforms.modification_builder import ModificationBuilder
from d810.transforms.terminal_corridor_emission import (
    plan_direct_terminal_lowering_execution,
    plan_private_terminal_suffix_execution,
    plan_state_terminal_corridor_lowerings,
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


def _reg(reg: int) -> MopSnapshot:
    return MopSnapshot(t=2, size=8, reg=reg, kind=OperandKind.REGISTER)


def _num(value: int, size: int = 8) -> MopSnapshot:
    return MopSnapshot(t=1, size=size, value=value, kind=OperandKind.NUMBER)


def _stack(stkoff: int, size: int = 8) -> MopSnapshot:
    return MopSnapshot(
        t=4,
        size=size,
        stkoff=stkoff,
        stack_refs=(stkoff,),
        kind=OperandKind.STACK,
    )


def _addr(stkoff: int, size: int = 8) -> MopSnapshot:
    return MopSnapshot(
        t=10,
        size=size,
        stack_refs=(stkoff,),
        kind=OperandKind.ADDRESS,
        sub_l=_stack(stkoff, size=size),
    )


def _mov_addr(stkoff: int, reg: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=1,
        ea=0x1000 + reg,
        operands=(),
        kind=InsnKind.MOV,
        l=_addr(stkoff),
        d=_reg(reg),
    )


def _store(value: MopSnapshot, target_reg: int, ea: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=2,
        ea=ea,
        operands=(),
        kind=InsnKind.STORE,
        l=value,
        d=_reg(target_reg),
    )


def _state_ne_tail(state_stkoff: int, terminal_state: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=3,
        ea=0x3000,
        operands=(),
        kind=InsnKind.COND_JUMP,
        l=_stack(state_stkoff),
        r=_num(terminal_state),
        branch_predicate=PredicateKind.NE,
    )


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    insns: tuple[InsnSnapshot, ...] = (),
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=len(succs),
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=insns,
    )


def test_state_terminal_corridor_lowering_replaces_dispatcher_redirect():
    state_stkoff = 0x58
    result_stkoff = 0x4C
    terminal_state = 0xDD1FF05BF465445C
    dispatcher = 99
    stop = 10
    terminal = 8
    anchor = 7
    flow_graph = FlowGraph(
        blocks={
            4: _block(4, (5,), (), (_mov_addr(result_stkoff, 12),)),
            5: _block(5, (6,), (4,), ()),
            6: _block(6, (7,), (5,), ()),
            7: _block(anchor, (dispatcher,), (6,), (_mov_addr(state_stkoff, 3),)),
            8: _block(
                terminal,
                (stop, dispatcher),
                (dispatcher,),
                (
                    _store(_num(3, size=4), 12, 0x2000),
                    _store(_num(terminal_state), 3, 0x2001),
                    _state_ne_tail(state_stkoff, terminal_state),
                ),
            ),
            10: _block(stop, (), (8,), ()),
            99: _block(dispatcher, (8,), (7, 8), ()),
        },
        entry_serial=4,
        func_ea=0x401000,
    )

    plan = plan_state_terminal_corridor_lowerings(
        flow_graph=flow_graph,
        modifications=(
            RedirectGoto(
                from_serial=anchor,
                old_target=dispatcher,
                new_target=terminal,
            ),
        ),
        dispatcher_entry_serial=dispatcher,
        state_var_stkoff=state_stkoff,
    )

    assert len(plan.modifications) == 1
    (modification,) = plan.modifications
    assert isinstance(modification, DirectTerminalLoweringGroup)
    assert modification.shared_entry_serial == dispatcher
    assert modification.return_block_serial == stop
    assert modification.suffix_serials == (stop,)
    assert modification.sites[0].anchor_serial == anchor
    assert modification.sites[0].materializer_serials == (4, 5, 6, terminal)
    assert modification.sites[0].skip_terminal_control_tail is True
    assert plan.corridors[0].path_blocks == (4, 5, 6, anchor, terminal)
    assert plan.corridors[0].terminal_state == terminal_state


def test_state_terminal_corridor_lowering_proves_nested_join_alias_materializer():
    state_stkoff = 0x58
    result_stkoff = 0x4C
    terminal_state = 0xDD1FF05BF465445C
    dispatcher = 99
    stop = 10
    terminal = 8
    anchor = 7
    flow_graph = FlowGraph(
        blocks={
            4: _block(4, (5, 6), (), (_mov_addr(result_stkoff, 12),)),
            5: _block(5, (6,), (4,), (_mov_addr(result_stkoff, 12),)),
            6: _block(6, (7, terminal), (4, 5), ()),
            7: _block(anchor, (dispatcher,), (6,), (_mov_addr(state_stkoff, 3),)),
            8: _block(
                terminal,
                (stop, dispatcher),
                (6, 7),
                (
                    _store(_num(3, size=4), 12, 0x2000),
                    _store(_num(terminal_state), 3, 0x2001),
                    _state_ne_tail(state_stkoff, terminal_state),
                ),
            ),
            10: _block(stop, (), (8,), ()),
            99: _block(dispatcher, (8,), (7, 8), ()),
        },
        entry_serial=4,
        func_ea=0x401000,
    )

    plan = plan_state_terminal_corridor_lowerings(
        flow_graph=flow_graph,
        modifications=(
            RedirectGoto(
                from_serial=anchor,
                old_target=dispatcher,
                new_target=terminal,
            ),
        ),
        dispatcher_entry_serial=dispatcher,
        state_var_stkoff=state_stkoff,
    )

    assert len(plan.modifications) == 1
    (modification,) = plan.modifications
    assert isinstance(modification, DirectTerminalLoweringGroup)
    assert modification.sites[0].materializer_serials == (4, 5, 6, terminal)
    assert plan.corridors[0].path_blocks == (4, 5, 6, anchor, terminal)


def test_state_terminal_corridor_lowering_rejects_non_state_terminal_guard():
    state_stkoff = 0x58
    result_stkoff = 0x4C
    terminal_state = 0xDD1FF05BF465445C
    dispatcher = 99
    flow_graph = FlowGraph(
        blocks={
            6: _block(6, (7,), (), (_mov_addr(result_stkoff, 12),)),
            7: _block(7, (dispatcher,), (6,), (_mov_addr(state_stkoff, 3),)),
            8: _block(
                8,
                (10, dispatcher),
                (dispatcher,),
                (
                    _store(_num(3, size=4), 12, 0x2000),
                    _store(_num(terminal_state), 3, 0x2001),
                    InsnSnapshot(
                        opcode=3,
                        ea=0x3000,
                        operands=(),
                        kind=InsnKind.COND_JUMP,
                        l=_stack(result_stkoff),
                        r=_num(terminal_state),
                        branch_predicate=PredicateKind.NE,
                    ),
                ),
            ),
            10: _block(10, (), (8,), ()),
            99: _block(dispatcher, (8,), (7, 8), ()),
        },
        entry_serial=7,
        func_ea=0x401000,
    )

    plan = plan_state_terminal_corridor_lowerings(
        flow_graph=flow_graph,
        modifications=(RedirectGoto(from_serial=7, old_target=dispatcher, new_target=8),),
        dispatcher_entry_serial=dispatcher,
        state_var_stkoff=state_stkoff,
    )

    assert plan.modifications == ()
