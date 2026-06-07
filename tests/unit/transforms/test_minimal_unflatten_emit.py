"""Unit tests for the direct interval-set unflatten emitter (epic d81-jfg2)."""
from __future__ import annotations

import pytest

from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.analyses.control_flow.minimal_state_recovery import (
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
from d810.transforms.minimal_unflatten_emit import build_state_write_redirects

_OP_MOV = 4
_T_NUM, _T_STK, _T_REG = 2, 4, 1
_STATE = 0x64


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
