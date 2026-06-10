"""Unit tests for conditional/multi-arm transition emission (ticket llr-aga1).

The back-edge model (:func:`build_state_write_redirects`) emits one redirect per
dispatcher predecessor and collapses a 2-way-branching handler onto a single
next-state, fragmenting the recovered graph into disconnected cycles.  The
multi-arm model (:func:`recover_handler_transitions`) recovers BOTH arms;
:func:`build_conditional_arm_redirects` emits the missing arm redirects so a
conditional handler reaches both of its successors.

Pure: synthetic ``FlowGraph`` + ``IntervalDispatcher`` (no IDA).  Mirrors
``test_minimal_state_recovery.py`` / ``test_minimal_unflatten_emit.py`` fixtures.
"""
from __future__ import annotations

import pytest

from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.analyses.control_flow.minimal_state_recovery import (
    recover_handler_transitions,
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
from d810.transforms.graph_modification import RedirectBranch, RedirectGoto
from d810.transforms.minimal_unflatten_emit import (
    _existing_redirect_keys,
    build_conditional_arm_redirects,
    build_state_write_redirects,
    emit_minimal_unflatten,
)

from d810.analyses.control_flow.minimal_state_recovery import (
    recover_state_write_transitions_via_partitioned_fixpoint,
)

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
        return _portable_forward_eval_insn(
            insn, stk, reg, off, seams=s,
            mba=kw.pop("mba", None),
            state_var_lvar_idx=kw.pop("state_var_lvar_idx", None),
        )

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


def _mov_reg_state(ea, src_reg):
    # state = reg (opaque to the global fold across two branch predecessors)
    return InsnSnapshot(
        opcode=_OP_MOV, ea=ea, operands=(),
        l=MopSnapshot(t=_T_REG, size=4, reg=src_reg, kind=OperandKind.REGISTER),
        d=MopSnapshot(t=_T_STK, size=4, stkoff=_STATE, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )


def _mov_reg_const(ea, reg, const):
    return InsnSnapshot(
        opcode=_OP_MOV, ea=ea, operands=(),
        l=MopSnapshot(t=_T_NUM, size=4, value=const, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_REG, size=4, reg=reg, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _b(serial, succs, preds, insns=(), *, kind=BlockKind.UNKNOWN):
    return BlockSnapshot(
        serial=serial, block_type=0, succs=tuple(succs), preds=tuple(preds),
        flags=0, start_ea=0x1000 + serial * 0x40, insn_snapshots=tuple(insns), kind=kind,
    )


def _stop(serial, preds):
    return BlockSnapshot(
        serial=serial, block_type=0, succs=(), preds=tuple(preds), flags=0,
        start_ea=0x9000 + serial, insn_snapshots=(), kind=BlockKind.STOP,
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


def _conditional_handler_fg() -> FlowGraph:
    """Entry -> dispatcher; handler blk10 is a 2-way branch to blk11/blk12.

    blk11 writes next-state 0xAA (-> handler blk40); blk12 writes 0xBB
    (-> handler blk50).  Both arm tails re-enter the dispatcher.  blk40 and
    blk50 are terminal-ish handlers that write the exit state (route -> STOP).

        entry(0) -> disp(2)
        route(0x10)=10, route(0xAA)=40, route(0xBB)=50
        10 = 2-way -> {11, 12}
        11 writes 0xAA -> disp ; 12 writes 0xBB -> disp
        40 writes exit-state -> disp ; 50 writes exit-state -> disp
    """
    return FlowGraph(
        blocks={
            0: _b(0, (1,), ()),                                # entry
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),  # prologue writes initial 0x10
            2: _b(2, (10, 11, 12, 40, 50),
                  (1, 11, 12, 40, 50)),                        # dispatcher
            10: _b(10, (11, 12), (2,)),                        # CONDITIONAL handler (2-way)
            11: _b(11, (2,), (10,), (_mov_state(0x1100, 0xAA),)),  # arm A -> disp
            12: _b(12, (2,), (10,), (_mov_state(0x1200, 0xBB),)),  # arm B -> disp
            40: _b(40, (2,), (2,), (_mov_state(0x4000, 0x7FFFFFFF),)),  # -> exit
            50: _b(50, (2,), (2,), (_mov_state(0x5000, 0x7FFFFFFE),)),  # -> exit
            99: _stop(99, (2,)),
        },
        entry_serial=0, func_ea=0x1000,
    )


def test_recover_handler_transitions_sees_both_arms(_seam) -> None:
    """The multi-arm model recovers blk10 as a conditional handler with two arms."""
    fg = _conditional_handler_fg()
    disp = _disp({0x10: 10, 0xAA: 40, 0xBB: 50}, exit_block=99)
    edges = {e.handler: e for e in recover_handler_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2)}
    h10 = edges[10]
    assert h10.is_conditional
    by_state = {a.next_state: a for a in h10.arms}
    assert set(by_state) == {0xAA, 0xBB}
    assert by_state[0xAA].target_handler == 40
    assert by_state[0xBB].target_handler == 50
    # Each arm's write-block (tail) re-enters the dispatcher.
    assert by_state[0xAA].write_block == 11
    assert by_state[0xBB].write_block == 12


def test_conditional_arm_redirects_emit_both_arms(_seam) -> None:
    """A conditional handler emits BOTH arm redirects off the dispatcher.

    The combined plan (back-edge model + conditional-arm pass) re-points blk11
    onto route(0xAA)=40 and blk12 onto route(0xBB)=50, so both successors of the
    handler's branch are reachable instead of collapsing to one.
    """
    fg = _conditional_handler_fg()
    disp = _disp({0x10: 10, 0xAA: 40, 0xBB: 50}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE,
        dispatcher_entry_serial=2, pre_header_serial=1, initial_state=0x10,
    )
    mods = plan.as_graph_modifications()
    edges = {(m.from_serial, m.new_target) for m in mods
             if isinstance(m, (RedirectGoto, RedirectBranch))}
    # both arms re-pointed off the dispatcher onto their routed handlers
    assert (11, 40) in edges
    assert (12, 50) in edges
    # entry bridge intact: prologue -> route(initial 0x10) = blk10
    assert (1, 10) in edges


def test_arm_redirects_preserve_reachability(_seam) -> None:
    """After emission, BFS from entry (dispatcher removed) reaches both arm targets.

    This is the metric the OLLVM thermometer tracks (``reachable_handlers``):
    without the conditional arm redirects, one of {40, 50} is unreachable.
    """
    fg = _conditional_handler_fg()
    disp = _disp({0x10: 10, 0xAA: 40, 0xBB: 50}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE,
        dispatcher_entry_serial=2, pre_header_serial=1, initial_state=0x10,
    )
    mods = plan.as_graph_modifications()

    # Apply redirects to a mutable succ map, then BFS from entry with disp removed.
    rewired = {int(s): [int(x) for x in fg.get_block(s).succs] for s in fg.blocks}
    for m in mods:
        if not isinstance(m, (RedirectGoto, RedirectBranch)):
            continue
        succ = rewired.get(int(m.from_serial))
        if succ and int(m.old_target) in succ:
            succ[succ.index(int(m.old_target))] = int(m.new_target)
    disp_s = 2
    seen, stack = set(), [0]
    while stack:
        b = stack.pop()
        if b in seen or b == disp_s:
            continue
        seen.add(b)
        for s in rewired.get(b, ()):
            if s not in seen and s != disp_s:
                stack.append(s)
    # both conditional targets reachable from the entry without the dispatcher
    assert 40 in seen
    assert 50 in seen


def test_existing_back_edge_edge_is_not_double_redirected(_seam) -> None:
    """The conditional-arm pass never re-points an edge the back-edge model owns.

    The back-edge model resolves each distinct write-block edge; the veto keyed
    on ``(from_serial, old_target)`` keeps the conditional-arm pass from adding a
    second mod on the same source edge.
    """
    fg = _conditional_handler_fg()
    disp = _disp({0x10: 10, 0xAA: 40, 0xBB: 50}, exit_block=99)
    transitions = recover_state_write_transitions_via_partitioned_fixpoint(
        fg, disp, _STATE, dispatcher_entry_serial=2)
    back_edge_mods = build_state_write_redirects(
        fg, disp, transitions,
        dispatcher_entry_serial=2, pre_header_serial=1, initial_state=0x10,
    )
    existing = _existing_redirect_keys(back_edge_mods)
    handler_transitions = recover_handler_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2)
    arm_mods = build_conditional_arm_redirects(
        fg, disp, handler_transitions,
        dispatcher_entry_serial=2, existing=existing,
    )
    # Every arm edge the back-edge model already owns must be vetoed.
    arm_keys = {(int(m.from_serial), int(m.old_target)) for m in arm_mods}
    assert arm_keys.isdisjoint(existing)


def _shared_write_block_fg() -> FlowGraph:
    """The real OLLVM conditional shape: branch selects, then arms CONVERGE on one
    shared write block that re-enters the dispatcher.

    Handler blk10's selecting branch (blk10 itself, 2-way) -> {blk13, blk14}.
    blk13 sets reg8=0xAA, blk14 sets reg8=0xBB; BOTH fall into the SHARED write
    block blk15 which does ``state = reg8`` then re-enters the dispatcher.  The
    global fold of blk15 cannot resolve a single state (it depends on the branch),
    so the back-edge model collapses blk15 onto blk10's own incoming state
    (a self-loop).  The branch-anchored arm pass redirects blk10's two successor
    edges (-> blk13 / -> blk14) onto route(0xAA)=40 / route(0xBB)=50.

        entry(0)->prologue(1 writes 0x10)->disp(2)
        route(0x10)=10, route(0xAA)=40, route(0xBB)=50
        10 = 2-way -> {13, 14}
        13: reg8=0xAA -> 15 ; 14: reg8=0xBB -> 15
        15: state=reg8 -> disp
        40/50: write exit-state -> disp
    """
    return FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(2, (10, 13, 14, 15, 40, 50), (1, 15, 40, 50)),
            10: _b(10, (13, 14), (2,)),                            # selecting branch
            13: _b(13, (15,), (10,), (_mov_reg_const(0x1300, 8, 0xAA),)),
            14: _b(14, (15,), (10,), (_mov_reg_const(0x1400, 8, 0xBB),)),
            15: _b(15, (2,), (13, 14), (_mov_reg_state(0x1500, 8),)),  # shared back-edge
            40: _b(40, (2,), (2,), (_mov_state(0x4000, 0x7FFFFFFF),)),
            50: _b(50, (2,), (2,), (_mov_state(0x5000, 0x7FFFFFFE),)),
            99: _stop(99, (2,)),
        },
        entry_serial=0, func_ea=0x1000,
    )


def test_shared_write_block_conditional_arms_wired_to_routed_handlers(_seam) -> None:
    """The shared-write-block conditional handler is recovered with two arms and each
    arm is wired to its routed handler.

    The selecting branch's per-arm glue blocks (blk13 / blk14) are distinct
    dispatcher predecessors of the shared write block (blk15), so the
    predecessor-partitioned back-edge model resolves each arm directly --
    ``13 -> route(0xAA)=40`` and ``14 -> route(0xBB)=50`` via blk15. The
    branch-anchored arm pass then DEFERS (its glue blocks are already redirect
    sources): emitting a branch-target-change on the *fall-through* arm there is
    redundant and, on the real Tigress shape, harmful (``BLOCK_TARGET_CHANGE``
    cannot retarget a fall-through arm, severing it). The recovered arms must
    reach their routed handlers regardless of which model wired them.
    """
    fg = _shared_write_block_fg()
    disp = _disp({0x10: 10, 0xAA: 40, 0xBB: 50}, exit_block=99)
    edges = {e.handler: e for e in recover_handler_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2)}
    h10 = edges[10]
    assert h10.is_conditional
    by_state = {a.next_state: a for a in h10.arms}
    assert set(by_state) == {0xAA, 0xBB}
    # Both arms share write block 15 and the selecting branch is blk10.
    assert {a.write_block for a in h10.arms} == {15}
    assert all(a.branch_block == 10 for a in h10.arms)

    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE,
        dispatcher_entry_serial=2, pre_header_serial=1, initial_state=0x10,
    )
    mods = plan.as_graph_modifications()
    edge_set = {(m.from_serial, m.old_target, m.new_target) for m in mods
                if isinstance(m, (RedirectGoto, RedirectBranch))}
    # The predecessor-partitioned back-edge model wires each per-arm glue block
    # straight onto its routed handler (bypassing the shared write block 15).
    assert (13, 15, 40) in edge_set
    assert (14, 15, 50) in edge_set


def test_shared_write_block_reachability_no_self_loop(_seam) -> None:
    """After branch-anchored emission both routed handlers are reachable.

    Without the fix, the shared write block collapses to a self-loop on blk10 and
    neither blk40 nor blk50 is reachable; the branch redirect breaks the cycle.
    """
    fg = _shared_write_block_fg()
    disp = _disp({0x10: 10, 0xAA: 40, 0xBB: 50}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE,
        dispatcher_entry_serial=2, pre_header_serial=1, initial_state=0x10,
    )
    mods = plan.as_graph_modifications()
    rewired = {int(s): [int(x) for x in fg.get_block(s).succs] for s in fg.blocks}
    for m in mods:
        if not isinstance(m, (RedirectGoto, RedirectBranch)):
            continue
        succ = rewired.get(int(m.from_serial))
        if succ and int(m.old_target) in succ:
            succ[succ.index(int(m.old_target))] = int(m.new_target)
    disp_s = 2
    seen, stack = set(), [0]
    while stack:
        b = stack.pop()
        if b in seen or b == disp_s:
            continue
        seen.add(b)
        for s in rewired.get(b, ()):
            if s not in seen and s != disp_s:
                stack.append(s)
    assert 10 in seen   # the conditional handler itself
    assert 40 in seen   # arm A target
    assert 50 in seen   # arm B target


def test_unconditional_handler_emits_no_arm_redirects(_seam) -> None:
    """A purely unconditional set of handlers yields zero conditional-arm mods.

    Proves the pass is additive and byte-neutral for the proven 1-way case: the
    back-edge model owns every edge, the conditional-arm pass adds nothing.
    """
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(2, (10, 20), (1, 10, 20)),
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0x20),)),
            20: _b(20, (2,), (2,), (_mov_state(0x2000, 0x7FFFFFFF),)),
            99: _stop(99, (2,)),
        },
        entry_serial=0, func_ea=0x1000,
    )
    disp = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    handler_transitions = recover_handler_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2)
    assert all(not h.is_conditional for h in handler_transitions)
    arm_mods = build_conditional_arm_redirects(
        fg, disp, handler_transitions,
        dispatcher_entry_serial=2, existing=set(),
    )
    assert arm_mods == []
