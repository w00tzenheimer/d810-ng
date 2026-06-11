"""Unit tests for the direct interval-set unflatten emitter (epic d81-jfg2)."""
from __future__ import annotations

import pytest

from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.analyses.control_flow.minimal_state_recovery import (
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
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.transforms.graph_modification import RedirectGoto
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
