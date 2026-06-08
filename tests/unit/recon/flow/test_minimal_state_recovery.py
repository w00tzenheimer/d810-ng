"""Unit tests for the minimal per-handler-write + interval-route recovery.

Pure: synthetic ``FlowGraph`` + ``IntervalDispatcher`` (no IDA).  The MBA fold
runs through a registered portable ``forward_eval_insn`` seam.
"""
from __future__ import annotations

import pytest

from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.analyses.control_flow.minimal_state_recovery import (
    recover_handler_transitions,
    recover_state_write_transitions,
    recover_state_write_transitions_via_fixpoint,
    recover_state_write_transitions_via_multicell_fixpoint,
)
from d810.analyses.control_flow.state_transition_domain import (
    StateValue,
    state_value_fixpoint_result,
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
)

_OP_MOV = 4
_OP_XOR = 31
_T_NUM = 2
_T_STK = 4
_T_REG = 1
_OPCODE_NAMES = {_OP_MOV: "m_mov", _OP_XOR: "m_xor"}
_OPCODE_VALUES = {"m_mov": _OP_MOV, "m_xor": _OP_XOR}
_MOP_NAMES = {_T_NUM: "mop_n", _T_STK: "mop_S", _T_REG: "mop_r"}
_MOP_VALUES = {"mop_n": _T_NUM, "mop_S": _T_STK, "mop_r": _T_REG}
_STATE_OFF = 0x64


def _eval_seams() -> MicrocodeEvalSeams:
    return MicrocodeEvalSeams(
        mop_type_name=lambda t: _MOP_NAMES.get(t),
        mop_type_value=lambda name, default: _MOP_VALUES.get(name, default),
        opcode_value=lambda name, default: _OPCODE_VALUES.get(name, default),
        opcode_name=lambda op: _OPCODE_NAMES.get(op),
        fetch_stable_global_value=lambda _a, _s: None,
        lvar_stkoff=lambda _m, _i: -1,
    )


@pytest.fixture
def _seam():
    from d810.capabilities import providers as _providers

    seams = _eval_seams()

    def _fwd(insn, stk_map, reg_map, state_var_stkoff, **kwargs):
        kwargs.pop("seams", None)
        return _portable_forward_eval_insn(
            insn, stk_map, reg_map, state_var_stkoff, seams=seams,
            mba=kwargs.pop("mba", None),
            state_var_lvar_idx=kwargs.pop("state_var_lvar_idx", None),
        )

    register_bst_walkers(
        BstWalkerProvider(
            detect_state_var_stkoff=lambda *a, **k: None,
            dump_dispatcher_node=lambda *a, **k: None,
            find_pre_header_state=lambda *a, **k: None,
            walk_handler_chain=lambda *a, **k: None,
            forward_eval_insn=_fwd,
            resolve_via_bst_walk=lambda *a, **k: None,
            get_block=lambda mba, serial: mba.get_block(serial),
            block_successors=lambda blk: tuple(blk.succs),
        )
    )
    try:
        yield
    finally:
        _providers.reset_providers_for_tests()


def _num(v: int) -> MopSnapshot:
    return MopSnapshot(t=_T_NUM, size=4, value=v, kind=OperandKind.NUMBER)


def _reg(r: int) -> MopSnapshot:
    return MopSnapshot(t=_T_REG, size=4, reg=r, kind=OperandKind.REGISTER)


def _stk(off: int) -> MopSnapshot:
    return MopSnapshot(t=_T_STK, size=4, stkoff=off, kind=OperandKind.STACK)


def _mov(ea: int, src: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(opcode=_OP_MOV, ea=ea, operands=(), l=src, d=dst, kind=InsnKind.MOV)


def _xor(ea: int, l: MopSnapshot, r: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(opcode=_OP_XOR, ea=ea, operands=(), l=l, r=r, d=dst, kind=InsnKind.AND)


def _blk(serial, succs, preds, insns, *, ea=None, kind=BlockKind.UNKNOWN) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial, block_type=0, succs=tuple(succs), preds=tuple(preds),
        flags=0, start_ea=ea if ea is not None else 0x1000 + serial * 0x40,
        insn_snapshots=tuple(insns), kind=kind,
    )


def _stop(serial, preds) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial, block_type=0, succs=(), preds=tuple(preds), flags=0,
        start_ea=0x9000 + serial, insn_snapshots=(), kind=BlockKind.STOP,
    )


def _dispatcher(point_targets: dict[int, int], *, exit_block: int, domain_hi: int = 0x100000000) -> IntervalDispatcher:
    """Total-cover partition: each state -> its target; gaps -> exit_block.

    The exit block therefore owns the most rows, so it is the default target.
    """
    rows: list[IntervalRow] = []
    cursor = 0
    for state in sorted(point_targets):
        if state > cursor:
            rows.append(IntervalRow(lo=cursor, hi=state, target=exit_block))
        rows.append(IntervalRow(lo=state, hi=state + 1, target=point_targets[state]))
        cursor = state + 1
    if cursor < domain_hi:
        rows.append(IntervalRow(lo=cursor, hi=domain_hi, target=exit_block))
    return IntervalDispatcher(rows)


# --- tests ----------------------------------------------------------------


def test_unconditional_literal_transition(_seam) -> None:
    # blk10 writes mov #0x20, state_var; goto dispatcher(2). route(0x20)=blk20.
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20), (10,), (_mov(0x2000, _num(0), _reg(0)),)),
            10: _blk(10, (2,), (2,), (_mov(0x1000, _num(0x20), _stk(_STATE_OFF)),)),
            20: _blk(20, (2,), (2,), (_mov(0x3000, _num(0), _reg(0)),)),
        },
        entry_serial=2, func_ea=0x1000,
    )
    disp = _dispatcher({0x10: 10, 0x20: 20}, exit_block=99)
    edges = {e.handler: e for e in recover_handler_transitions(
        fg, disp, _STATE_OFF, dispatcher_entry_serial=2)}
    assert set(edges) == {10, 20}
    h10 = edges[10]
    assert not h10.is_conditional
    assert h10.arms[0].next_state == 0x20
    assert h10.arms[0].target_handler == 20
    assert h10.arms[0].is_return is False


def test_conditional_two_arm_transition(_seam) -> None:
    # blk30 is 2-way -> {31,32}; each arm writes a distinct next-state.
    fg = FlowGraph(
        blocks={
            2: _blk(2, (30, 40, 50), (31, 32), (_mov(0x2000, _num(0), _reg(0)),)),
            30: _blk(30, (31, 32), (2,), ()),
            31: _blk(31, (2,), (30,), (_mov(0x3100, _num(0xAA), _stk(_STATE_OFF)),)),
            32: _blk(32, (2,), (30,), (_mov(0x3200, _num(0xBB), _stk(_STATE_OFF)),)),
            40: _blk(40, (2,), (2,), ()),
            50: _blk(50, (2,), (2,), ()),
        },
        entry_serial=2, func_ea=0x1000,
    )
    disp = _dispatcher({0x30: 30, 0xAA: 40, 0xBB: 50}, exit_block=99)
    edges = {e.handler: e for e in recover_handler_transitions(
        fg, disp, _STATE_OFF, dispatcher_entry_serial=2)}
    h30 = edges[30]
    assert h30.is_conditional
    targets = {a.next_state: a.target_handler for a in h30.arms}
    assert targets == {0xAA: 40, 0xBB: 50}
    assert all(a.branch_block == 30 for a in h30.arms)


def test_shared_suffix_folds_per_handler(_seam) -> None:
    # blk10 and blk60 both flow into the SHARED xor suffix blk11, with different
    # register constants -> different folded next-states. The scan must fold each
    # for its own entry and stop at the dispatcher, not drift into the other.
    # 0x12345678 ^ 0x081CC5A1 = 0x1A2893D9 ; 0x11111111 ^ 0x22222222 = 0x33333333
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 60, 20, 70), (11,), (_mov(0x2000, _num(0), _reg(0)),)),
            10: _blk(10, (11,), (2,), (_mov(0x1000, _num(0x12345678), _reg(8)),
                                       _mov(0x1004, _num(0x081CC5A1), _reg(9)))),
            60: _blk(60, (11,), (2,), (_mov(0x6000, _num(0x11111111), _reg(8)),
                                       _mov(0x6004, _num(0x22222222), _reg(9)))),
            11: _blk(11, (2,), (10, 60), (_xor(0x1100, _reg(8), _reg(9), _stk(_STATE_OFF)),)),
            20: _blk(20, (2,), (2,), ()),
            70: _blk(70, (2,), (2,), ()),
        },
        entry_serial=2, func_ea=0x1000,
    )
    disp = _dispatcher(
        {0x10: 10, 0x60: 60, 0x1A2893D9: 20, 0x33333333: 70}, exit_block=99
    )
    edges = {e.handler: e for e in recover_handler_transitions(
        fg, disp, _STATE_OFF, dispatcher_entry_serial=2)}
    assert edges[10].arms[0].next_state == 0x1A2893D9
    assert edges[10].arms[0].target_handler == 20
    assert edges[60].arms[0].next_state == 0x33333333
    assert edges[60].arms[0].target_handler == 70


def test_terminal_when_next_state_routes_to_exit(_seam) -> None:
    # blk10 writes a state whose dispatcher route is the default/exit block.
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10,), (10,), (_mov(0x2000, _num(0), _reg(0)),)),
            10: _blk(10, (2,), (2,), (_mov(0x1000, _num(0x7FFFFFFF), _stk(_STATE_OFF)),)),
            99: _stop(99, (2,)),
        },
        entry_serial=2, func_ea=0x1000,
    )
    # 0x7FFFFFFF falls in a gap -> routes to exit(99); 99 is a STOP block.
    disp = _dispatcher({0x10: 10}, exit_block=99)
    edges = {e.handler: e for e in recover_handler_transitions(
        fg, disp, _STATE_OFF, dispatcher_entry_serial=2)}
    arm = edges[10].arms[0]
    assert arm.is_return is True


def test_scan_stops_at_other_handler_entry(_seam) -> None:
    # blk10 writes NO state and its only successor is another handler entry
    # (blk20). The scan must stop at blk20 (boundary), not absorb blk20's write.
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20), (20,), (_mov(0x2000, _num(0), _reg(0)),)),
            10: _blk(10, (20,), (2,), (_mov(0x1000, _num(0), _reg(0)),)),  # no state write
            20: _blk(20, (2,), (10,), (_mov(0x2000, _num(0x20), _stk(_STATE_OFF)),)),
        },
        entry_serial=2, func_ea=0x1000,
    )
    disp = _dispatcher({0x10: 10, 0x20: 20}, exit_block=99)
    edges = {e.handler: e for e in recover_handler_transitions(
        fg, disp, _STATE_OFF, dispatcher_entry_serial=2)}
    # blk10 wrote nothing and stopped at blk20's entry -> no next-state -> return.
    assert edges[10].arms[0].next_state is None
    assert edges[10].arms[0].is_return is True
    # blk20 itself resolves its own literal write.
    assert edges[20].arms[0].next_state == 0x20


def _multicell_xor_fg() -> FlowGraph:
    """One region whose back-edge writes ``state = reg8 ^ reg9`` from local consts.

    The dispatcher (blk2) routes state 0x10 -> handler blk10.  blk10 sets
    reg8/reg9 to constants, its successor blk11 folds ``state = reg8 ^ reg9``
    and re-enters the dispatcher.  Single region (blk10), so the single-PARTITION
    multi-cell fold suffices (no cross-region meet).
    0x12345678 ^ 0x081CC5A1 = 0x1A2893D9.
    """
    return FlowGraph(
        blocks={
            2: _blk(2, (10, 20), (11,), (_mov(0x2000, _num(0), _reg(0)),)),
            10: _blk(10, (11,), (2,), (_mov(0x1000, _num(0x12345678), _reg(8)),
                                       _mov(0x1004, _num(0x081CC5A1), _reg(9)))),
            11: _blk(11, (2,), (10,), (_xor(0x1100, _reg(8), _reg(9), _stk(_STATE_OFF)),)),
            20: _blk(20, (2,), (2,), ()),
        },
        entry_serial=2, func_ea=0x1000,
    )


def test_b1_multicell_folds_opaque_xor_back_edge(_seam) -> None:
    """B1: the multi-cell fixpoint folds an opaque ``reg^reg`` back-edge write.

    The single-cell ``StateValue`` shadow has no anchor for blk11 (its write is
    not a literal), so it emits an unresolved return; the multi-cell variant folds
    the register constants and resolves it -- matching the production fold.
    """
    fg = _multicell_xor_fg()
    # 0x10 routes to the handler region (blk10); its back-edge folds to 0x1A2893D9.
    disp = _dispatcher({0x10: 10, 0x1A2893D9: 20}, exit_block=99)

    prod = {t.write_block: t for t in recover_state_write_transitions(
        fg, disp, _STATE_OFF, dispatcher_entry_serial=2)}
    assert prod[11].next_state == 0x1A2893D9 and prod[11].target_handler == 20

    # Single-cell shadow: blk11 has no state-write anchor -> unresolved (the residual).
    fp = state_value_fixpoint_result(
        nodes=list(fg.blocks),
        entry_nodes=[2],
        successors_of=lambda s: [int(x) for x in fg.get_block(s).succs],
        predecessors_of=lambda s: [int(x) for x in fg.get_block(s).preds],
        state_writes={},
        handler_entry_by_state={0x10: 10, 0x1A2893D9: 20},
        entry_state=StateValue.top(),
    )
    single = {t.write_block: t for t in recover_state_write_transitions_via_fixpoint(
        fg, disp, dispatcher_entry_serial=2, out_states=fp.out_states)}
    # The single-cell fixpoint only carries the state slot: blk11's opaque XOR
    # write is not folded, so it passes through blk10's stale entry-assume (0x10)
    # instead of the real next-state -- DISAGREEING with production.
    assert single[11].next_state != prod[11].next_state

    # Multi-cell shadow: folds reg8^reg9 -> resolves to the production value.
    multi = {t.write_block: t for t in recover_state_write_transitions_via_multicell_fixpoint(
        fg, disp, _STATE_OFF, dispatcher_entry_serial=2)}
    assert multi[11].next_state == 0x1A2893D9
    assert multi[11].target_handler == 20
    assert multi[11].is_return is False
