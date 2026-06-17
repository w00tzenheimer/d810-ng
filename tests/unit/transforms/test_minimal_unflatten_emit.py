"""Unit tests for the direct interval-set unflatten emitter (epic d81-jfg2)."""
from __future__ import annotations

import pytest

from d810.analyses.control_flow.dispatcher_kind import DispatcherType
from d810.analyses.control_flow.branch_witness import (
    BranchWitnessMap,
    BranchWitnessRow,
)
from d810.analyses.control_flow.branch_witness_provider import (
    build_static_equality_chain_witness_map,
)
from d810.analyses.control_flow.dispatcher_resolution import (
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.analyses.control_flow.minimal_state_recovery import (
    StateWriteTransition,
    TransitionProof,
    _resolve_state_var_alias,
    block_has_live_carrier_write,
    recover_state_write_transitions,
)
from d810.analyses.value_flow.state_write import (
    MicrocodeEvalSeams,
    forward_eval_insn as _portable_forward_eval_insn,
)
from d810.capabilities.providers import BstWalkerProvider, register_bst_walkers
from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
    PredicateKind,
)
from d810.transforms.graph_modification import ConvertToGoto, RedirectBranch, RedirectGoto
from d810.transforms.minimal_unflatten_emit import (
    _recover_initial_state,
    build_state_write_redirects,
    emit_minimal_unflatten,
)

_OP_MOV = 4
_T_NUM, _T_STK, _T_REG = 2, 4, 1
_STATE = 0x64
_CARRIER_OFF = 0x70  # a non-state stack slot (the Approov ``v4`` carrier)


def _seams() -> MicrocodeEvalSeams:
    return MicrocodeEvalSeams(
        mop_type_name=lambda t: {_T_NUM: "mop_n", _T_STK: "mop_S", _T_REG: "mop_r"}.get(t),
        mop_type_value=lambda n, d: {"mop_n": _T_NUM, "mop_S": _T_STK, "mop_r": _T_REG}.get(n, d),
        opcode_value=lambda n, d: {"m_mov": _OP_MOV}.get(n, d),
        opcode_name=lambda op: {_OP_MOV: "m_mov"}.get(op),
        fetch_stable_global_value=lambda _a, _s: None,
        lvar_stkoff=lambda _m, _i: -1,
    )


@pytest.fixture
def _seam():
    from d810.capabilities import providers as _p

    s = _seams()

    def _fwd(insn, stk, reg, off, **kw):
        kw.pop("seams", None)
        return _portable_forward_eval_insn(insn, stk, reg, off, seams=s,
                                           mba=kw.pop("mba", None),
                                           state_var_lvar_idx=kw.pop("state_var_lvar_idx", None))

    register_bst_walkers(BstWalkerProvider(
        detect_state_var_stkoff=lambda *a, **k: None,
        dump_dispatcher_node=lambda *a, **k: None,
        find_pre_header_state=lambda *a, **k: None,
        walk_handler_chain=lambda *a, **k: None,
        forward_eval_insn=_fwd,
        resolve_via_bst_walk=lambda *a, **k: None,
        get_block=lambda mba, serial: mba.get_block(serial),
        block_successors=lambda blk: tuple(blk.succs),
    ))
    try:
        yield
    finally:
        _p.reset_providers_for_tests()


def _mov_state(ea, const):
    return InsnSnapshot(
        opcode=_OP_MOV, ea=ea, operands=(),
        l=MopSnapshot(t=_T_NUM, size=4, value=const, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_STK, size=4, stkoff=_STATE, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )


def _mov_stk(ea, src_off, dst_off):
    # pure stack->stack copy: dst = src (no right operand)
    return InsnSnapshot(
        opcode=_OP_MOV, ea=ea, operands=(),
        l=MopSnapshot(t=_T_STK, size=4, stkoff=src_off, kind=OperandKind.STACK),
        d=MopSnapshot(t=_T_STK, size=4, stkoff=dst_off, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )


def _mov_reg(ea, const, dst_reg):
    return InsnSnapshot(
        opcode=_OP_MOV, ea=ea, operands=(),
        l=MopSnapshot(t=_T_NUM, size=8, value=const, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_REG, size=8, reg=dst_reg, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _use_nested_reg(ea, reg):
    """A nested sub-instruction use, shaped like an indirect-call operand."""
    return InsnSnapshot(
        opcode=_OP_MOV, ea=ea, operands=(),
        l=MopSnapshot(
            t=4,
            size=8,
            kind=OperandKind.SUBINSN,
            sub_l=MopSnapshot(t=_T_REG, size=8, reg=reg, kind=OperandKind.REGISTER),
        ),
        d=MopSnapshot(t=_T_REG, size=8, reg=0, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _stx_reg(ea, value, ptr_reg):
    return InsnSnapshot(
        opcode=1, ea=ea, operands=(),
        l=MopSnapshot(t=_T_NUM, size=8, value=value, kind=OperandKind.NUMBER),
        r=MopSnapshot(t=_T_REG, size=2, reg=256, kind=OperandKind.REGISTER),
        d=MopSnapshot(t=_T_REG, size=8, reg=ptr_reg, kind=OperandKind.REGISTER),
        kind=InsnKind.STORE,
    )


def _mov_reg_const(ea, reg, value=0x1234):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_NUM, size=8, value=value, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_REG, size=8, reg=reg, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _mov_reg_from_stack(ea, reg, stkoff):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=8, stkoff=stkoff, kind=OperandKind.STACK),
        d=MopSnapshot(t=_T_REG, size=8, reg=reg, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _mov_stack_from_reg(ea, stkoff, reg):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_REG, size=8, reg=reg, kind=OperandKind.REGISTER),
        d=MopSnapshot(t=_T_STK, size=8, stkoff=stkoff, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )


def _mov_stack_const(ea, stkoff, value=0x1234):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_NUM, size=8, value=value, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_STK, size=8, stkoff=stkoff, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )


def _call_reg(ea, reg):
    return InsnSnapshot(
        opcode=0x44,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_REG, size=8, reg=reg, kind=OperandKind.REGISTER),
        kind=InsnKind.CALL,
    )


def _state_ne_tail(ea, const):
    return InsnSnapshot(
        opcode=0x33,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=8, stkoff=_STATE, kind=OperandKind.STACK),
        r=MopSnapshot(t=_T_NUM, size=8, value=const, kind=OperandKind.NUMBER),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
    )


def _b(serial, succs, preds, insns=()):
    return BlockSnapshot(
        serial=serial, block_type=0, succs=tuple(succs), preds=tuple(preds),
        flags=0, start_ea=0x1000 + serial * 0x40, insn_snapshots=tuple(insns),
    )


def _disp(point_targets, exit_block, hi=0x100000000):
    rows, cur = [], 0
    for st in sorted(point_targets):
        if st > cur:
            rows.append(IntervalRow(lo=cur, hi=st, target=exit_block))
        rows.append(IntervalRow(lo=st, hi=st + 1, target=point_targets[st]))
        cur = st + 1
    if cur < hi:
        rows.append(IntervalRow(lo=cur, hi=hi, target=exit_block))
    return IntervalDispatcher(rows)


def _eq_block(serial, const, taken, fallthrough, preds=(), insns=()):
    """Equality-chain compare block: ``jz state == const -> taken; fallthrough``."""
    tail = InsnSnapshot(
        opcode=100, ea=0x1000 + serial * 0x40, operands=(),
        l=MopSnapshot(t=_T_STK, size=4, stkoff=_STATE, kind=OperandKind.STACK),
        r=MopSnapshot(t=_T_NUM, size=4, value=const, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=0, size=0, block_ref=taken, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    return BlockSnapshot(
        serial=serial, block_type=4, succs=(fallthrough, taken),
        preds=tuple(preds), flags=0, start_ea=0x1000 + serial * 0x40,
        insn_snapshots=(*insns, tail),
    )


def _use_stk(ea, stkoff):
    """A statement that uses a stack slot: ``return use(stkoff)`` proxy via mov."""
    return InsnSnapshot(
        opcode=_OP_MOV, ea=ea, operands=(),
        l=MopSnapshot(t=_T_STK, size=4, stkoff=stkoff, kind=OperandKind.STACK),
        d=MopSnapshot(t=_T_REG, size=4, reg=0, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _equality_dispatcher(point_targets, entry_block, compare_blocks):
    """Build IntervalDispatcher + StateDispatcherMap for equality-chain rows."""
    rows = tuple(
        StateDispatcherRow(
            state_const=st,
            target_block=target,
            dispatcher_block=entry_block,
            compare_block=cmp_block,
            branch_kind="eq",
            source=DispatcherType.CONDITIONAL_CHAIN,
        )
        for st, target, cmp_block in zip(
            sorted(point_targets), [point_targets[st] for st in sorted(point_targets)], compare_blocks
        )
    )
    dispatch_map = StateDispatcherMap(
        rows=rows,
        dispatcher_entry_block=entry_block,
        dispatcher_blocks=frozenset(compare_blocks),
        state_var_stkoff=_STATE,
        state_var_lvar_idx=None,
        source=DispatcherType.CONDITIONAL_CHAIN,
    )
    interval_rows = [
        IntervalRow(lo=st & 0xFFFFFFFF, hi=(st & 0xFFFFFFFF) + 1, target=target)
        for st, target in point_targets.items()
    ]
    return IntervalDispatcher(interval_rows), dispatch_map


def test_emits_back_edge_redirect_and_entry_bridge(_seam) -> None:
    # entry blk0 -> dispatcher blk2; state-write blk10 writes 0x20 -> dispatcher;
    # route(0x10 initial)=blk10, route(0x20)=blk20.  The transition is anchored on
    # the back-edge blk10->dispatcher, re-pointed onto route(0x20)=blk20.
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),                                   # entry -> dispatcher
            2: _b(2, (10, 20), (0, 10, 20)),                      # dispatcher
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0x20),)),  # writes 0x20 -> dispatcher
            20: _b(20, (2,), (2,)),                               # target handler
        },
        entry_serial=0, func_ea=0x1000,
    )
    disp = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2
    )
    # blk10 is the resolved state-write back-edge -> route(0x20) = blk20
    by_block = {t.write_block: t for t in transitions}
    assert by_block[10].next_state == 0x20
    assert by_block[10].target_handler == 20
    assert by_block[10].is_return is False
    mods = build_state_write_redirects(
        fg, disp, transitions,
        dispatcher_entry_serial=2, pre_header_serial=0, initial_state=0x10,
    )
    gotos = {(m.from_serial, m.old_target, m.new_target) for m in mods if isinstance(m, RedirectGoto)}
    # back-edge blk10 re-pointed off the dispatcher onto blk20
    assert (10, 2, 20) in gotos
    # entry bridge: blk0 -> route(initial 0x10) = blk10
    assert (0, 2, 10) in gotos


def test_entry_bridge_shortcuts_pure_state_only_witness_exit_path(_seam) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(2, (4, 3), (1,), (_state_ne_tail(0x1000, 0x10),)),
            3: _b(3, (4,), (2,)),
            4: _b(4, (5, 6), (2, 3), (_state_ne_tail(0x1010, 0x10),)),
            5: _b(5, (7,), (4,)),
            6: _b(6, (7,), (4,)),
            7: _exit_block(7, (5, 6)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 5}, exit_block=7)

    mods = build_state_write_redirects(
        fg,
        disp,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
        state_var_stkoff=_STATE,
        entry_bridge_exit_path_blocks=(2, 4),
        entry_bridge_requires_witness=True,
    )

    gotos = {(m.from_serial, m.old_target, m.new_target) for m in mods if isinstance(m, RedirectGoto)}
    assert (1, 2, 5) in gotos


def test_entry_bridge_preserves_witness_exit_path_with_live_stack_def(_seam) -> None:
    non_state = 0x88
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(2, (4, 3), (1,), (_mov_stack_const(0x1000, non_state), _state_ne_tail(0x1004, 0x10))),
            3: _b(3, (4,), (2,)),
            4: _b(4, (5,), (2, 3), (_state_ne_tail(0x1010, 0x10),)),
            5: _b(5, (8,), (4,)),
            8: _b(8, (9,), (5,), (_mov_reg_from_stack(0x1080, 1, non_state),)),
            9: _exit_block(9, (8,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 5}, exit_block=9)

    mods = build_state_write_redirects(
        fg,
        disp,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
        state_var_stkoff=_STATE,
        entry_bridge_exit_path_blocks=(2, 4),
        entry_bridge_requires_witness=True,
    )

    gotos = {(m.from_serial, m.old_target, m.new_target) for m in mods if isinstance(m, RedirectGoto)}
    assert (1, 2, 5) not in gotos


def test_entry_bridge_shortcuts_skipped_dead_non_state_def(_seam) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(2, (4, 3), (1,), (_mov_reg_const(0x1000, 2), _state_ne_tail(0x1004, 0x10))),
            3: _b(3, (4,), (2,)),
            4: _b(4, (5,), (2, 3), (_state_ne_tail(0x1010, 0x10),)),
            5: _b(5, (8,), (4,), (_mov_reg_const(0x1050, 2),)),
            8: _b(8, (9,), (5,), (_call_reg(0x1080, 2),)),
            9: _exit_block(9, (8,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 5}, exit_block=9)

    mods = build_state_write_redirects(
        fg,
        disp,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
        state_var_stkoff=_STATE,
        entry_bridge_exit_path_blocks=(2, 4),
        entry_bridge_requires_witness=True,
    )

    gotos = {(m.from_serial, m.old_target, m.new_target) for m in mods if isinstance(m, RedirectGoto)}
    assert (1, 2, 5) in gotos


def test_entry_bridge_shortcuts_dispatcher_local_non_state_temp(_seam) -> None:
    temp_stack = 0x88
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(2, (4, 3), (1,), (_mov_reg_const(0x1000, 2), _state_ne_tail(0x1004, 0x10))),
            3: _b(3, (4,), (2,)),
            4: _b(4, (5, 6), (2, 3), (_mov_stack_from_reg(0x1010, temp_stack, 2), _state_ne_tail(0x1014, 0x10))),
            5: _b(5, (7,), (4,)),
            6: _b(6, (7,), (4,)),
            7: _exit_block(7, (5, 6)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 5}, exit_block=7)

    mods = build_state_write_redirects(
        fg,
        disp,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
        state_var_stkoff=_STATE,
        entry_bridge_exit_path_blocks=(2, 4),
        entry_bridge_requires_witness=True,
    )

    gotos = {(m.from_serial, m.old_target, m.new_target) for m in mods if isinstance(m, RedirectGoto)}
    assert (1, 2, 5) in gotos


def test_entry_bridge_preserves_witness_exit_path_with_live_call_target_reg(_seam) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(2, (4, 3), (1,), (_mov_reg_const(0x1000, 0), _state_ne_tail(0x1004, 0x10))),
            3: _b(3, (4,), (2,), (_mov_reg_const(0x1008, 0, value=0x5555),)),
            4: _b(4, (5,), (2, 3), (_state_ne_tail(0x1010, 0x10),)),
            5: _b(5, (8,), (4,)),
            8: _b(8, (9,), (5,), (_call_reg(0x1080, 0),)),
            9: _exit_block(9, (8,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 5}, exit_block=9)

    mods = build_state_write_redirects(
        fg,
        disp,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
        state_var_stkoff=_STATE,
        entry_bridge_exit_path_blocks=(2, 4),
        entry_bridge_requires_witness=True,
    )

    gotos = {(m.from_serial, m.old_target, m.new_target) for m in mods if isinstance(m, RedirectGoto)}
    assert (1, 2, 5) not in gotos


def test_recovers_initial_state_from_prologue(_seam) -> None:
    # prologue blk0 -> blk1(writes initial 0x10) -> dispatcher blk2.  The prologue
    # is a dispatcher predecessor too, so its folded state IS the initial state --
    # recovered without any caller-supplied initial_state / bst evidence.
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),                                   # entry
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),     # prologue writes 0x10
            2: _b(2, (10, 20), (1, 10, 20)),                      # dispatcher
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0x20),)),  # handler writes 0x20
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0, func_ea=0x1000,
    )
    disp = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2
    )
    assert _recover_initial_state(fg, transitions, 2, None) == 0x10


def test_emit_bails_when_no_entry_bridge(_seam) -> None:
    # The prologue blk1 writes NO state, so the initial state is unrecoverable and
    # the entry can't be bridged.  Removing the dispatcher would orphan every
    # handler, so emit must BAIL (empty plan) and leave the function intact rather
    # than gut it (the OLLVM current-state-shadow failure mode).
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),                                 # NO state write
            2: _b(2, (10, 20), (1, 10, 20)),
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0x20),)),  # resolvable handler
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0, func_ea=0x1000,
    )
    disp = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE, dispatcher_entry_serial=2
    )
    assert len(plan.as_graph_modifications()) == 0


def test_resolves_state_var_alias_through_header_copy(_seam) -> None:
    # Dispatcher header copies the COMPARED slot (_STATE) FROM the next-state slot
    # (0x40): handlers write 0x40, the header does ``_STATE = 0x40`` then routes on
    # _STATE.  At a back-edge _STATE is still stale, so the fold must read 0x40 --
    # _resolve_state_var_alias follows the header copy (OLLVM -fla shadow).
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10,), (0, 10), (_mov_stk(0x2000, 0x40, _STATE),)),  # _STATE <- 0x40
            10: _b(10, (2,), (2,)),
        },
        entry_serial=0, func_ea=0x1000,
    )
    assert _resolve_state_var_alias(fg, 2, _STATE) == 0x40


def test_state_var_alias_unchanged_without_header_copy(_seam) -> None:
    # No copy into the compared slot at the header -> offset unchanged (the clean
    # hodur / sub_7FFD chains must not be remapped).
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10,), (0, 10)),                                     # no copy
            10: _b(10, (2,), (2,), (_mov_state(0x2000, 0x20),)),
        },
        entry_serial=0, func_ea=0x1000,
    )
    assert _resolve_state_var_alias(fg, 2, _STATE) == _STATE


def _mov_carrier(ea, src_off, dst_off=_CARRIER_OFF):
    # pure stack->stack copy to a NON-state slot: the carrier write ``v4 = src``.
    return _mov_stk(ea, src_off, dst_off)


def test_block_has_live_carrier_write_detects_non_state_write() -> None:
    # A block whose only data write is the state-var write is pure glue.
    glue = _b(10, (2,), (8, 9), (_mov_state(0x1000, 0x20),))
    assert block_has_live_carrier_write(glue, _STATE) is False
    # A block that also writes a non-state slot carries a live carrier.
    carrier = _b(
        10, (2,), (8, 9),
        (_mov_state(0x1000, 0x20), _mov_carrier(0x1004, 0x80)),
    )
    assert block_has_live_carrier_write(carrier, _STATE) is True
    # A block with only a carrier write (no state write) still counts.
    carrier_only = _b(11, (2,), (8,), (_mov_carrier(0x1008, 0x80),))
    assert block_has_live_carrier_write(carrier_only, _STATE) is True


def _exit_block(serial, preds):
    # A 0-successor STOP/exit block (the function return).
    return BlockSnapshot(
        serial=serial, block_type=2, succs=(), preds=tuple(preds),
        flags=0, start_ea=0x1000 + serial * 0x40, insn_snapshots=(),
    )


def test_carrier_return_arm_flows_through_shared_block(_seam) -> None:
    # The Approov conditional-handler shape: a 2-way branch (blk7) selects two arms
    # that CONVERGE on a shared block (blk10) carrying a LIVE non-state write (the
    # ``v4 = a1`` carrier = the return value).  Arm A (blk8) writes a CONTINUE state
    # (0x20, a real handler that re-enters the loop and overwrites the carrier); arm
    # B (blk9) writes the EXIT state (0x30, routing to the return).  The carrier is
    # live ONLY on the exit arm, so the recovery must keep the exit arm flowing
    # THROUGH blk10 (carrier preserved -> ``return v4``) while the continue arm
    # bypasses blk10 (its carrier copy is dead).
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),                                       # entry
            1: _b(1, (3,), (0,), (_mov_state(0x900, 0x10),)),         # prologue -> 0x10
            3: _b(3, (7, 20, 99), (1, 10), ()),                       # dispatcher
            7: _b(7, (8, 9), (3,)),                                   # selecting 2-way
            8: _b(8, (10,), (7,), (_mov_state(0x1000, 0x20),)),       # CONTINUE arm -> 0x20
            9: _b(9, (10,), (7,), (_mov_state(0x1010, 0x30),)),       # EXIT arm -> 0x30
            10: _b(10, (3,), (8, 9), (_mov_carrier(0x1020, 0x80),)),  # shared carrier
            20: _b(20, (3,), (3,)),                                   # continue handler
            99: _exit_block(99, (3,)),                                # return/exit
        },
        entry_serial=0, func_ea=0x1000,
    )
    # 0x30 has no handler row -> routes to the exit (default) = a return.
    disp = _disp({0x10: 7, 0x20: 20}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE, dispatcher_entry_serial=3, initial_state=0x10
    )
    mods = plan.as_graph_modifications()
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    # The CONTINUE arm bypasses the carrier block: blk8 -> route(0x20)=blk20.
    assert (8, 10, 20) in gotos
    # The carrier block ITSELF is redirected onto the exit route (blk99): the exit
    # arm's edge blk9 -> blk10 stays intact, so ``blk9 -> blk10(carrier) -> exit``.
    assert (10, 3, 99) in gotos
    # The exit arm (blk9) is NOT bypassed -- it must flow through the carrier block.
    assert not [
        m for m in mods if isinstance(m, RedirectGoto) and m.from_serial == 9
    ]


def test_explicit_stop_row_routes_to_stop_not_catchall(_seam) -> None:
    # OLLVM -fla EXIT shape (ticket llr-gpt3): the EXIT state (0x30) is an EXPLICIT
    # map row routing to a STOP block (blk99), while the dispatcher's catch-all
    # default (blk20) loops back to the dispatcher (NOT a STOP).  The terminal
    # handler blk10 writes the EXIT state, so its back-edge must redirect onto the
    # STOP (blk99) -- routing it to the catch-all default (blk20) strands the
    # output write in a non-returning while(1).
    # blk99 must be a real STOP (BLT_STOP); a bare 0-succ block is ZERO_WAY, not
    # STOP, and _is_stop_block keys on the STOP kind/type.
    stop99 = BlockSnapshot(
        serial=99, block_type=1, succs=(), preds=(2,), flags=0,
        start_ea=0x1000 + 99 * 0x40, insn_snapshots=(), kind=BlockKind.STOP,
    )
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),                                   # entry
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),     # prologue -> 0x10
            2: _b(2, (10, 20, 99), (1, 10, 20)),                  # dispatcher
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0x30),)),  # terminal: writes EXIT 0x30
            20: _b(20, (2,), (2,)),                               # catch-all default (loops back)
            99: stop99,                                           # STOP / return
        },
        entry_serial=0, func_ea=0x1000,
    )
    # Explicit rows: 0x10 -> blk10 (terminal handler), 0x30 -> blk99 (STOP).
    # Catch-all default = blk20 (the loop-back catch-all, NOT a STOP).
    disp = _disp({0x10: 10, 0x30: 99}, exit_block=20)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2
    )
    by_block = {t.write_block: t for t in transitions}
    # blk10 folds to EXIT state 0x30, routed to STOP blk99 -> classified is_return.
    assert by_block[10].next_state == 0x30
    assert by_block[10].target_handler == 99
    assert by_block[10].is_return is True
    mods = build_state_write_redirects(
        fg, disp, transitions,
        dispatcher_entry_serial=2, pre_header_serial=1, initial_state=0x10,
    )
    gotos = {(m.from_serial, m.new_target) for m in mods if isinstance(m, RedirectGoto)}
    # FIX: the terminal back-edge redirects onto the STOP (blk99), NOT the catch-all
    # default (blk20) -- so the function actually returns.
    assert (10, 99) in gotos
    assert (10, 20) not in gotos


def test_return_redirect_falls_back_to_default_when_not_stop(_seam) -> None:
    # CONTROL (hodur / approov shape): when the return routes to the catch-all
    # default which IS the function's exit, the back-edge must still redirect onto
    # default_target exactly as before (byte-identical legacy path).  Here the EXIT
    # arm's state 0x30 has no explicit row -> routes to the catch-all default = the
    # STOP blk99; target_handler == default, so the fix returns default unchanged.
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(2, (10, 99), (1, 10)),
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0x30),)),  # writes UNMAPPED 0x30
            99: _exit_block(99, (2,)),                            # catch-all default = STOP
        },
        entry_serial=0, func_ea=0x1000,
    )
    # 0x30 has NO explicit row -> routes to default = exit_block = blk99 (STOP).
    disp = _disp({0x10: 10}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2
    )
    by_block = {t.write_block: t for t in transitions}
    assert by_block[10].is_return is True
    mods = build_state_write_redirects(
        fg, disp, transitions,
        dispatcher_entry_serial=2, pre_header_serial=1, initial_state=0x10,
    )
    gotos = {(m.from_serial, m.new_target) for m in mods if isinstance(m, RedirectGoto)}
    # default_target IS the STOP -> redirect onto it (unchanged legacy behaviour).
    assert (10, 99) in gotos


def test_pure_glue_via_block_still_bypassed(_seam) -> None:
    # CONTROL: when the shared back-edge block carries ONLY the state-glue (no live
    # carrier write), the predecessor-partitioned model must still BYPASS it exactly
    # as before -- the carrier-preservation must not fire (byte-identical old path).
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (3,), (0,), (_mov_state(0x900, 0x10),)),
            3: _b(3, (7, 20, 99), (1, 10), ()),
            7: _b(7, (8, 9), (3,)),
            8: _b(8, (10,), (7,), (_mov_state(0x1000, 0x20),)),
            9: _b(9, (10,), (7,), (_mov_state(0x1010, 0x30),)),
            10: _b(10, (3,), (8, 9), ()),                            # PURE glue
            20: _b(20, (3,), (3,)),
            99: _exit_block(99, (3,)),
        },
        entry_serial=0, func_ea=0x1000,
    )
    disp = _disp({0x10: 7, 0x20: 20}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE, dispatcher_entry_serial=3, initial_state=0x10
    )
    mods = plan.as_graph_modifications()
    gotos = {
        (m.from_serial, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    # Pure glue: blk8 bypasses to route(0x20)=blk20, blk9 bypasses to the exit
    # (blk99); the shared block is never kept on the path.
    assert (8, 20) in gotos
    assert (9, 99) in gotos
    # The carrier-return path is NOT used (no ``blk10 -> exit`` self-redirect).
    assert (10, 99) not in gotos


def test_terminal_stack_alias_via_block_keeps_carrier_guard(_seam) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (6,), ()),
            2: _b(2, (3, 5), (8,)),
            6: _b(6, (7, 8), (0,), (_state_ne_tail(0x1600, 0x10),)),
            7: _b(7, (8,), (6,)),
            8: _b(8, (9, 2), (6, 7)),
            9: _b(9, (10,), (8,)),
            10: _exit_block(10, (9,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 7, 0x20: 9}, exit_block=3)
    transitions = (
        StateWriteTransition(
            7,
            0x20,
            9,
            False,
            None,
            via_block=8,
            proof=TransitionProof(
                "region_partitioned_fixpoint",
                "stack_address_alias_terminal_guard_partitioned",
                True,
            ),
        ),
    )
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=None,
        initial_state=0x10,
        state_var_stkoff=_STATE,
    )

    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    branches = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectBranch)
    }
    converts = {
        (m.block_serial, m.goto_target)
        for m in mods
        if isinstance(m, ConvertToGoto)
    }
    assert (7, 8, 9) not in gotos
    assert (6, 7) in converts
    assert (8, 9) in converts
    assert (6, 8, 7) not in branches
    assert (8, 2, 9) not in branches


def test_witness_entry_bridge_shortcuts_safe_exit_path(_seam) -> None:
    """Equality-chain entry bridge with a pure exit_path is shortcut."""
    # blk0 -> blk2(dispatcher entry) -> blk4(eq 0x10) -> blk10(handler)
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(2, 0x10, taken=10, fallthrough=99, preds=(0,)),
            10: _b(10, (99,), (2,)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0, func_ea=0x1000,
    )
    disp, dmap = _equality_dispatcher({0x10: 10}, entry_block=2, compare_blocks=(2,))
    branch_witness_map = build_static_equality_chain_witness_map(fg, dmap)
    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE, dispatcher_entry_serial=2,
        initial_state=0x10, branch_witness_map=branch_witness_map,
    )
    gotos = {(m.from_serial, m.old_target, m.new_target) for m in plan.as_graph_modifications() if isinstance(m, RedirectGoto)}
    assert (0, 2, 10) in gotos


def test_witness_entry_bridge_preserves_live_stack_exit_path(_seam) -> None:
    """Equality-chain entry bridge with a live stack definition is preserved."""
    # blk0 -> blk2(dispatcher entry) -> blk4(eq 0x10). blk4 defines a non-state
    # stack slot 0x70. blk10(handler) uses 0x70. Shortcut blk0 -> blk10 would
    # bypass the definition, so the entry bridge must be preserved.
    _LIVE_OFF = 0x70
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(
                2, 0x10, taken=10, fallthrough=99, preds=(0,),
                insns=(_mov_stk(0x1080, _STATE, _LIVE_OFF),),  # live def of 0x70
            ),
            10: _b(10, (99,), (2,), (_use_stk(0x10C0, _LIVE_OFF),)),  # use of 0x70
            99: _exit_block(99, (10,)),
        },
        entry_serial=0, func_ea=0x1000,
    )
    disp, dmap = _equality_dispatcher({0x10: 10}, entry_block=2, compare_blocks=(2,))
    branch_witness_map = build_static_equality_chain_witness_map(fg, dmap)
    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE, dispatcher_entry_serial=2,
        initial_state=0x10, branch_witness_map=branch_witness_map,
    )
    gotos = {(m.from_serial, m.old_target, m.new_target) for m in plan.as_graph_modifications() if isinstance(m, RedirectGoto)}
    branches = {(m.from_serial, m.old_target, m.new_target) for m in plan.as_graph_modifications() if isinstance(m, RedirectBranch)}
    # Entry bridge must NOT shortcut because blk2 defines live 0x70.
    assert (0, 2, 10) not in gotos
    # Feasibility is still useful to prove which arm is live, but unsafe
    # exit_path_effect_summaries must preserve the current CFG instead of mutating branch arms.
    assert (2, 99, 10) not in branches


def test_witness_entry_bridge_preserves_nested_register_use(_seam) -> None:
    """Nested sub-instruction uses, like ``icall rax``, keep register defs live."""
    _RAX = 8
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(
                2, 0x10, taken=10, fallthrough=99, preds=(0,),
                insns=(_mov_reg(0x1080, 0x1234, _RAX),),
            ),
            10: _b(10, (99,), (2,), (_use_nested_reg(0x10C0, _RAX),)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0, func_ea=0x1000,
    )
    disp, dmap = _equality_dispatcher({0x10: 10}, entry_block=2, compare_blocks=(2,))
    branch_witness_map = build_static_equality_chain_witness_map(fg, dmap)
    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE, dispatcher_entry_serial=2,
        initial_state=0x10, branch_witness_map=branch_witness_map,
    )
    gotos = {(m.from_serial, m.old_target, m.new_target) for m in plan.as_graph_modifications() if isinstance(m, RedirectGoto)}
    branches = {(m.from_serial, m.old_target, m.new_target) for m in plan.as_graph_modifications() if isinstance(m, RedirectBranch)}
    assert (0, 2, 10) not in gotos
    assert (2, 99, 10) not in branches


def test_entry_bridge_requires_witness_shortcuts_live_safe_without_provider(_seam) -> None:
    """Missing witness rows keep legacy shortcutting when the exit_path is live-safe."""
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(2, 0x10, taken=10, fallthrough=99, preds=(0,)),
            10: _b(10, (99,), (2,)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=None,
        entry_bridge_requires_witness=True,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in plan.as_graph_modifications()
        if isinstance(m, RedirectGoto)
    }
    assert (0, 2, 10) in gotos


def test_entry_bridge_requires_witness_preserves_live_no_provider_exit_path(_seam) -> None:
    """No-provider fallback preserves a live register def in the dispatcher entry."""
    _RAX = 8
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(
                2, 0x10, taken=10, fallthrough=99, preds=(0,),
                insns=(_mov_reg(0x1080, 0x1234, _RAX),),
            ),
            10: _b(10, (99,), (2,), (_use_nested_reg(0x10C0, _RAX),)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=None,
        entry_bridge_requires_witness=True,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in plan.as_graph_modifications()
        if isinstance(m, RedirectGoto)
    }
    assert (0, 2, 10) not in gotos


def test_entry_bridge_requires_witness_preserves_live_no_provider_stack_exit_path(_seam) -> None:
    """No-provider fallback uses all supplied exit_path blocks, not just old target."""
    _LIVE_OFF = 0x70
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (4,), (0,)),
            4: _b(4, (10,), (2,), (_mov_stk(0x1080, _STATE, _LIVE_OFF),)),
            10: _b(10, (99,), (4,), (_use_stk(0x10C0, _LIVE_OFF),)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=None,
        entry_bridge_exit_path_blocks=(2, 4),
        entry_bridge_requires_witness=True,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in plan.as_graph_modifications()
        if isinstance(m, RedirectGoto)
    }
    assert (0, 2, 10) not in gotos


def test_conditional_entry_bridge_without_policy_uses_legacy_shortcut(_seam) -> None:
    """Conditional-looking CFG alone does not force witness-mode projection."""
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(2, 0x10, taken=10, fallthrough=99, preds=(0,)),
            10: _b(10, (99,), (2,)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=None,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in plan.as_graph_modifications()
        if isinstance(m, RedirectGoto)
    }
    assert (0, 2, 10) in gotos


def test_witness_entry_bridge_shortcuts_dead_non_state_exit_path(_seam) -> None:
    """A non-state definition with no live use can be bypassed."""
    _DEAD_OFF = 0x71
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(
                2, 0x10, taken=10, fallthrough=99, preds=(0,),
                insns=(_mov_stk(0x1080, _STATE, _DEAD_OFF),),  # dead def
            ),
            10: _b(10, (99,), (2,)),  # no use of _DEAD_OFF
            99: _exit_block(99, (10,)),
        },
        entry_serial=0, func_ea=0x1000,
    )
    disp, dmap = _equality_dispatcher({0x10: 10}, entry_block=2, compare_blocks=(2,))
    branch_witness_map = build_static_equality_chain_witness_map(fg, dmap)
    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE, dispatcher_entry_serial=2,
        initial_state=0x10, branch_witness_map=branch_witness_map,
    )
    gotos = {(m.from_serial, m.old_target, m.new_target) for m in plan.as_graph_modifications() if isinstance(m, RedirectGoto)}
    assert (0, 2, 10) in gotos


def test_witness_entry_bridge_shortcuts_state_only_exit_path(_seam) -> None:
    """State-variable definitions are intentionally severed by unflattening."""
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(
                2, 0x10, taken=10, fallthrough=99, preds=(0,),
                insns=(_mov_state(0x1080, 0x10),),  # state-var def
            ),
            10: _b(10, (99,), (2,)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0, func_ea=0x1000,
    )
    disp, dmap = _equality_dispatcher({0x10: 10}, entry_block=2, compare_blocks=(2,))
    branch_witness_map = build_static_equality_chain_witness_map(fg, dmap)
    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE, dispatcher_entry_serial=2,
        initial_state=0x10, branch_witness_map=branch_witness_map,
    )
    gotos = {(m.from_serial, m.old_target, m.new_target) for m in plan.as_graph_modifications() if isinstance(m, RedirectGoto)}
    assert (0, 2, 10) in gotos


def test_back_edge_preserves_unresolved_indirect_state_store(_seam) -> None:
    """Do not route a dispatcher back-edge past a pointer-indirected state store."""
    tail = InsnSnapshot(
        opcode=43, ea=0x1200, operands=(),
        l=MopSnapshot(t=_T_STK, size=8, stkoff=_STATE, kind=OperandKind.STACK),
        r=MopSnapshot(t=_T_NUM, size=8, value=0x20, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=0, size=0, block_ref=2, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            2: _eq_block(2, 0x10, taken=10, fallthrough=99, preds=(8,)),
            8: _b(8, (9, 2), (6, 7), (_stx_reg(0x1180, 0x20, 32), tail)),
            9: _exit_block(9, (8,)),
            10: _b(10, (8,), (2,)),
            99: _exit_block(99, (2,)),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    transitions = (
        StateWriteTransition(
            write_block=8,
            next_state=0x10,
            target_handler=10,
            is_return=False,
            branch_arm=1,
        ),
    )
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
    )
    branches = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectBranch)
    }
    assert (8, 2, 10) not in branches


def test_back_edge_uses_exact_witness_for_terminal_indirect_state_store(_seam) -> None:
    """A terminal indirect state store may redirect through a local branch witness."""
    terminal = 0xDD1FF05BF465445C
    tail = InsnSnapshot(
        opcode=43, ea=0x1200, operands=(),
        l=MopSnapshot(t=_T_STK, size=8, stkoff=_STATE, kind=OperandKind.STACK),
        r=MopSnapshot(t=_T_NUM, size=8, value=terminal, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=0, size=0, block_ref=2, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            2: _eq_block(2, 0x10, taken=10, fallthrough=99, preds=(8,)),
            8: _b(8, (9, 2), (7,), (_stx_reg(0x1180, terminal, 32), tail)),
            9: _exit_block(9, (8,)),
            10: _b(10, (8,), (2,)),
            99: _exit_block(99, (2,)),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    transitions = (
        StateWriteTransition(
            write_block=8,
            next_state=0x10,
            target_handler=10,
            is_return=False,
            branch_arm=1,
        ),
    )
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        branch_witness_map=None,
    )
    converts = {
        (m.block_serial, m.goto_target)
        for m in mods
        if isinstance(m, ConvertToGoto)
    }
    branches = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectBranch)
    }
    assert (8, 9) in converts
    assert (8, 2, 9) not in branches
    assert (8, 2, 10) not in branches
