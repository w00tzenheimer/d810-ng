from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
    PredicateKind,
)
from d810.transforms.exit_path_liveness_policy import (
    exit_path_blocks_live_violations,
)


_OP_MOV = 4
_OP_JZ = 44
_T_NUM = 2
_T_STK = 4
_T_BLOCK = 5
_LIVE = 0x18
_STATE = 0x14


def _stk(stkoff: int) -> MopSnapshot:
    return MopSnapshot(t=_T_STK, size=4, stkoff=stkoff, kind=OperandKind.STACK)


def _num(value: int) -> MopSnapshot:
    return MopSnapshot(t=_T_NUM, size=4, value=value, kind=OperandKind.NUMBER)


def _block_ref(serial: int) -> MopSnapshot:
    return MopSnapshot(t=_T_BLOCK, size=0, block_ref=serial, kind=OperandKind.BLOCK)


def _mov_const(ea: int, dst: int, value: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=_num(value),
        d=_stk(dst),
        kind=InsnKind.MOV,
    )


def _use_stk(ea: int, src: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=_stk(src),
        d=MopSnapshot(t=1, size=4, reg=0, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _jz_stk_const(ea: int, stkoff: int, value: int, taken: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=_OP_JZ,
        ea=ea,
        operands=(),
        l=_stk(stkoff),
        r=_num(value),
        d=_block_ref(taken),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )


def _b(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    insns: tuple[InsnSnapshot, ...] = (),
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x1000 + serial * 0x10,
        insn_snapshots=insns,
    )


def _nested_entry_graph(*, proven_value: int) -> FlowGraph:
    return FlowGraph(
        blocks={
            3: _b(3, (4, 9), (), (_jz_stk_const(0x1030, _LIVE, proven_value, 9),)),
            4: _b(4, (), (3,)),
            9: _b(9, (13,), (3,), (_mov_const(0x1090, _LIVE, 1),)),
            13: _b(13, (20,), (9,)),
            20: _b(20, (), (13,), (_use_stk(0x1200, _LIVE),)),
        },
        entry_serial=3,
        func_ea=0x1000,
    )


def test_no_provider_liveness_allows_redundant_constant_write_on_proven_edge() -> None:
    fg = _nested_entry_graph(proven_value=1)

    assert exit_path_blocks_live_violations(
        fg,
        (9,),
        13,
        _STATE,
        source_blocks=(3,),
        old_target=9,
    ) == set()


def test_no_provider_liveness_keeps_unproven_live_definition_unsafe() -> None:
    fg = _nested_entry_graph(proven_value=2)

    assert exit_path_blocks_live_violations(
        fg,
        (9,),
        13,
        _STATE,
        source_blocks=(3,),
        old_target=9,
    ) == {("stk", _LIVE)}


def test_no_provider_liveness_requires_edge_context_for_redundant_write() -> None:
    fg = _nested_entry_graph(proven_value=1)

    assert exit_path_blocks_live_violations(fg, (9,), 13, _STATE) == {("stk", _LIVE)}
