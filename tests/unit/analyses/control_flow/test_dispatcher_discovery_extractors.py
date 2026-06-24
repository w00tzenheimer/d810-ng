"""FlowGraph -> (comparisons, state_writes) extractor tests (no IDA)."""
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
from d810.analyses.control_flow.state_transition_domain import StateValue
from d810.analyses.control_flow.dispatcher_discovery_extractors import (
    extract_state_arm_comparisons,
    extract_state_writes,
)

C1, C2 = 0x10000001, 0x10000002
STATE_OFF = 0x3C


def _ne_check(const: int, jump_target: int) -> InsnSnapshot:
    """jnz s, const, jump_target -- taken (jump) when s != const."""
    l = MopSnapshot(kind=OperandKind.STACK, stkoff=STATE_OFF, size=4)
    r = MopSnapshot(kind=OperandKind.NUMBER, value=const, size=4)
    d = MopSnapshot(kind=OperandKind.BLOCK, block_ref=jump_target)
    return InsnSnapshot(
        opcode=1, ea=0x1000, operands=(l, r, d), l=l, r=r, d=d,
        kind=InsnKind.EQUALITY_JUMP, branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
    )


def _ne_nested_state_check(const: int, jump_target: int) -> InsnSnapshot:
    """jnz expr(s), const, jump_target -- nested expr keeps typed stack refs."""
    l = MopSnapshot(kind=OperandKind.SUBINSN, stack_refs=(STATE_OFF,), size=4)
    r = MopSnapshot(kind=OperandKind.NUMBER, value=const, size=4)
    d = MopSnapshot(kind=OperandKind.BLOCK, block_ref=jump_target)
    return InsnSnapshot(
        opcode=1, ea=0x1100, operands=(l, r, d), l=l, r=r, d=d,
        kind=InsnKind.EQUALITY_JUMP, branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
    )


def _mov_const_to_state(const: int, *, size: int = 4) -> InsnSnapshot:
    """mov #const, s  -- a constant store to the state slot."""
    l = MopSnapshot(kind=OperandKind.NUMBER, value=const, size=size)
    d = MopSnapshot(kind=OperandKind.STACK, stkoff=STATE_OFF, size=size)
    return InsnSnapshot(opcode=2, ea=0x2000, operands=(l, d), l=l, d=d, kind=InsnKind.MOV)


def _mov_reg_to_state(reg: int) -> InsnSnapshot:
    """mov reg, s -- a write to the state slot whose value is not a constant."""
    l = MopSnapshot(kind=OperandKind.REGISTER, reg=reg, size=4)
    d = MopSnapshot(kind=OperandKind.STACK, stkoff=STATE_OFF, size=4)
    return InsnSnapshot(opcode=3, ea=0x2100, operands=(l, d), l=l, d=d, kind=InsnKind.MOV)


def _add_const_to_state(left: int, right: int) -> InsnSnapshot:
    """add #left, #right, s -- computed writes are explicit unknowns here."""
    l = MopSnapshot(kind=OperandKind.NUMBER, value=left, size=4)
    r = MopSnapshot(kind=OperandKind.NUMBER, value=right, size=4)
    d = MopSnapshot(kind=OperandKind.STACK, stkoff=STATE_OFF, size=4)
    return InsnSnapshot(
        opcode=4, ea=0x2200, operands=(l, r, d), l=l, r=r, d=d, kind=InsnKind.ADD
    )


def _blk(serial, succs, preds, *, tail=None, insns=()):
    body = tuple(insns) + ((tail,) if tail is not None else ())
    return BlockSnapshot(
        serial=serial, block_type=1, succs=tuple(succs), preds=tuple(preds), flags=0,
        start_ea=0x1000 + serial, insn_snapshots=body,
        tail_opcode=tail.opcode if tail is not None else None,
    )


def _graph() -> FlowGraph:
    # 0 -> 1; 1: jnz s,C1 -> 2 (NE arm), fall-through 11 = handler(C1)
    #          11: s = C2 -> 2 ; 2: jnz s,C2 -> 99, fall-through 22 = handler(C2); 22: -> 2 ; 99 exit
    return FlowGraph(
        blocks={
            0: _blk(0, (1,), ()),
            1: _blk(1, (11, 2), (0, 11, 22), tail=_ne_check(C1, 2)),
            11: _blk(11, (1,), (1,), insns=(_mov_const_to_state(C2),)),
            2: _blk(2, (22, 99), (1,), tail=_ne_check(C2, 99)),
            22: _blk(22, (1,), (2,)),
            99: _blk(99, (), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


def test_extracts_comparisons_with_eq_ne_targets():
    comps = extract_state_arm_comparisons(_graph(), state_var_stkoff=STATE_OFF)
    assert set(comps) == {1, 2}
    # NE check: the EQUAL arm is the fall-through, the not-equal arm is the jump target.
    assert comps[1].const == C1 and comps[1].eq_target == 11 and comps[1].ne_target == 2
    assert comps[2].const == C2 and comps[2].eq_target == 22 and comps[2].ne_target == 99


def test_state_var_filter_excludes_other_offsets():
    assert extract_state_arm_comparisons(_graph(), state_var_stkoff=0x999) == {}


def test_state_var_filter_accepts_nested_stack_ref_identity_bridge():
    graph = FlowGraph(
        blocks={
            1: _blk(1, (11, 2), (), tail=_ne_nested_state_check(C1, 2)),
            11: _blk(11, (), (1,)),
            2: _blk(2, (), (1,)),
        },
        entry_serial=1,
        func_ea=0x1000,
    )

    comps = extract_state_arm_comparisons(graph, state_var_stkoff=STATE_OFF)
    assert set(comps) == {1}
    assert comps[1].eq_target == 11
    assert comps[1].ne_target == 2


def test_extracts_constant_state_write():
    writes = extract_state_writes(_graph(), state_var_stkoff=STATE_OFF)
    assert writes == {11: StateValue.of(C2)}  # block 11 stores C2; no others write the slot


def test_state_write_identity_is_size_agnostic():
    graph = FlowGraph(
        blocks={
            0: _blk(0, (), (), insns=(_mov_const_to_state(C1, size=1),)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    assert extract_state_writes(graph, state_var_stkoff=STATE_OFF) == {
        0: StateValue.of(C1)
    }


def test_non_constant_state_write_is_top():
    graph = FlowGraph(
        blocks={
            0: _blk(0, (), (), insns=(_mov_reg_to_state(7),)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    assert extract_state_writes(graph, state_var_stkoff=STATE_OFF) == {
        0: StateValue.top()
    }


def test_computed_state_write_is_top_not_left_constant():
    graph = FlowGraph(
        blocks={
            0: _blk(0, (), (), insns=(_add_const_to_state(C1, C2),)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    assert extract_state_writes(graph, state_var_stkoff=STATE_OFF) == {
        0: StateValue.top()
    }
