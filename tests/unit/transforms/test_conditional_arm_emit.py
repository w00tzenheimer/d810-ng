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
    HandlerTransition,
    TransitionArm,
    recover_handler_transitions,
)
from d810.analyses.value_flow.model import FactObservation
from d810.families.state_machine_cff.ollvm_carrier_profile import (
    project_ollvm_value_flow_evidence,
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
from d810.transforms.graph_modification import (
    LowerConditionalStateTransition,
    RedirectBranch,
    RedirectGoto,
    RetargetOutputStore,
    ScalarizeLocalAliasAccess,
    SyntheticCounterBoundCondition,
    ZeroStateWrite,
)
from d810.transforms.minimal_unflatten_emit import (
    ConditionalStateTransitionCandidate,
    _existing_redirect_keys,
    _loop_carrier_route_blocks,
    build_local_alias_scalarizations,
    build_loop_carrier_guard_transitions,
    build_loop_carrier_latch_redirects,
    build_output_store_retargets,
    build_conditional_arm_redirects,
    build_folded_loop_guard_transitions,
    build_state_write_redirects,
    emit_minimal_unflatten,
    lower_conditional_transition_candidates,
)

from d810.analyses.control_flow.minimal_state_recovery import (
    StateWriteTransition,
    recover_state_write_transitions_via_partitioned_fixpoint,
)

_OP_MOV = 4
_OP_LDX = 2
_OP_STX = 1
_OP_SETB = 35
_T_NUM, _T_STK, _T_REG = 2, 4, 1
_STATE = 0x64
_TEMP = 0x74


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


def _mov_stack_const(ea, stkoff, const):
    return InsnSnapshot(
        opcode=_OP_MOV, ea=ea, operands=(),
        l=MopSnapshot(t=_T_NUM, size=4, value=const, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_STK, size=4, stkoff=stkoff, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )


def _mov_state_from_stack(ea, stkoff):
    return InsnSnapshot(
        opcode=_OP_MOV, ea=ea, operands=(),
        l=MopSnapshot(t=_T_STK, size=4, stkoff=stkoff, kind=OperandKind.STACK),
        d=MopSnapshot(t=_T_STK, size=4, stkoff=_STATE, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )


def _stack(stkoff: int, *, size: int = 8, refs: tuple[int, ...] | None = None):
    return MopSnapshot(
        t=_T_STK,
        size=size,
        stkoff=stkoff,
        stack_refs=refs if refs is not None else (stkoff,),
        kind=OperandKind.STACK,
    )


def _reg(reg: int, *, size: int = 4):
    return MopSnapshot(t=_T_REG, size=size, reg=reg, kind=OperandKind.REGISTER)


def _ldx_alias(ea: int, alias_stkoff: int, dest_reg: int, text: str):
    return InsnSnapshot(
        opcode=_OP_LDX,
        ea=ea,
        operands=(),
        display_text=text,
        l=_reg(256, size=2),
        r=_stack(alias_stkoff),
        d=_reg(dest_reg),
        kind=InsnKind.LOAD,
    )


def _stx_alias(ea: int, alias_stkoff: int, text: str):
    return InsnSnapshot(
        opcode=_OP_STX,
        ea=ea,
        operands=(),
        display_text=text,
        l=_reg(24),
        r=_reg(256, size=2),
        d=_stack(alias_stkoff),
        kind=InsnKind.STORE,
    )


def _setb_counter(ea: int, counter_stkoff: int, text: str):
    return InsnSnapshot(
        opcode=_OP_SETB,
        ea=ea,
        operands=(),
        display_text=text,
        l=MopSnapshot(
            t=_T_STK,
            size=4,
            stack_refs=(counter_stkoff,),
            kind=OperandKind.SUBINSN,
            sub_kind=InsnKind.LOAD,
            sub_r=_stack(counter_stkoff),
        ),
        r=MopSnapshot(t=_T_NUM, size=4, value=0x64, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_STK, size=1, stkoff=0x97, kind=OperandKind.STACK),
        kind=InsnKind.UNKNOWN,
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


def test_conflicting_one_way_arm_redirects_are_suppressed(_seam) -> None:
    """A one-way source edge cannot encode two conditional arm targets.

    Hodur-style terminal candidates can recover multiple conditional arms whose
    write boundary is the same dispatcher predecessor.  Emitting both creates
    conflicting ``goto source -> target`` rewrites and lets the deferred modifier
    pick one arm arbitrarily, which can erase effect-bearing exit paths.
    """
    fg = FlowGraph(
        blocks={
            0: _b(0, (10,), ()),
            2: _b(2, (20, 40, 50), (10,)),
            10: _b(10, (2,), (0,), (_mov_state(0x1000, 0xAA),)),
            20: _b(20, (), (2,)),
            40: _b(40, (), (2,)),
            50: _b(50, (), (2,)),
            99: _stop(99, (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 20, 0xAA: 40, 0xBB: 50}, exit_block=99)
    handler_transitions = (
        HandlerTransition(
            handler=20,
            states=(0x10,),
            arms=(
                TransitionArm(
                    next_state=0xAA,
                    target_handler=40,
                    is_return=False,
                    branch_block=None,
                    write_block=10,
                    exit_block=10,
                    ordered_path=(20, 10),
                ),
                TransitionArm(
                    next_state=0xBB,
                    target_handler=50,
                    is_return=False,
                    branch_block=None,
                    write_block=10,
                    exit_block=10,
                    ordered_path=(20, 10),
                ),
            ),
        ),
    )

    arm_mods = build_conditional_arm_redirects(
        fg,
        disp,
        handler_transitions,
        dispatcher_entry_serial=2,
        existing=set(),
    )

    assert [
        m for m in arm_mods
        if isinstance(m, RedirectGoto) and m.from_serial == 10 and m.old_target == 2
    ] == []


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


def _branch_pred_stack_temp_shared_write_fg() -> FlowGraph:
    """OLLVM sibling shape: the selector block is also one predecessor of the
    shared state-write merge.

    blk40 assigns the first next-state to a stack temp and conditionally jumps
    directly to the merge blk42.  The fall-through arm blk41 overwrites that temp
    with the second next-state before reaching the same merge.  A global fold of
    blk42 can keep the stale incoming dispatcher state when ``state = temp`` is
    unresolved; the predecessor-partitioned fold must split ``40 -> 42`` and
    ``41 -> 42`` by the two temp values.
    """
    return FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x20),)),
            2: _b(2, (40, 50, 60), (1, 42, 50, 60)),
            40: _b(
                40,
                (41, 42),
                (2,),
                (_mov_stack_const(0x4000, _TEMP, 0xAA),),
            ),
            41: _b(
                41,
                (42,),
                (40,),
                (_mov_stack_const(0x4100, _TEMP, 0xBB),),
            ),
            42: _b(
                42,
                (2,),
                (40, 41),
                (_mov_state_from_stack(0x4200, _TEMP),),
            ),
            50: _b(50, (2,), (2,), (_mov_state(0x5000, 0x7FFFFFFF),)),
            60: _b(60, (2,), (2,), (_mov_state(0x6000, 0x7FFFFFFE),)),
            99: _stop(99, (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


def test_stack_temp_shared_write_prefers_partitioned_back_edge(_seam) -> None:
    """A stale global state fold must not mask concrete per-predecessor temp writes."""
    fg = _branch_pred_stack_temp_shared_write_fg()
    disp = _disp({0x20: 40, 0xAA: 60, 0xBB: 50}, exit_block=99)

    transitions = recover_state_write_transitions_via_partitioned_fixpoint(
        fg, disp, _STATE, dispatcher_entry_serial=2
    )
    split = {(t.write_block, t.via_block): t for t in transitions if t.via_block == 42}

    assert split[(40, 42)].next_state == 0xAA
    assert split[(40, 42)].target_handler == 60
    assert split[(40, 42)].proof is not None
    assert split[(40, 42)].proof.kind == "predecessor_partitioned"
    assert split[(41, 42)].next_state == 0xBB
    assert split[(41, 42)].target_handler == 50
    assert split[(41, 42)].proof is not None
    assert split[(41, 42)].proof.kind == "predecessor_partitioned"


def test_stack_temp_shared_write_emits_only_write_anchor_routes(_seam) -> None:
    """Do not add a redundant selector fall-through redirect when the back-edge
    split already routes the arm successor through the actual write anchor.
    """
    fg = _branch_pred_stack_temp_shared_write_fg()
    disp = _disp({0x20: 40, 0xAA: 60, 0xBB: 50}, exit_block=99)

    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE,
        dispatcher_entry_serial=2, pre_header_serial=1, initial_state=0x20,
    )
    edge_set = {
        (m.from_serial, m.old_target, m.new_target)
        for m in plan.as_graph_modifications()
        if isinstance(m, (RedirectGoto, RedirectBranch))
    }

    assert (40, 42, 60) in edge_set
    assert (41, 42, 50) in edge_set
    assert (40, 41, 50) not in edge_set


class _FactView:
    def __init__(self, observations: tuple[FactObservation, ...]) -> None:
        self.active_observations = (
            *observations,
            *project_ollvm_value_flow_evidence(observations),
        )


def _ollvm_loop_index_fact(*, source_block: int, source_ea: int) -> FactObservation:
    return FactObservation(
        fact_id="ollvm-loop-index",
        kind="OllvmValueFlowEvidence",
        semantic_key="ollvm_carrier:LOOP_INDEX_CARRIER:%var_398",
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
        confidence=0.82,
        source_block=source_block,
        source_ea=source_ea,
        block_fingerprint=f"blk[{source_block}].0:op_35",
        mop_signature="ollvm_carrier:LOOP_INDEX_CARRIER:%var_398",
        payload={
            "role": "LOOP_INDEX_CARRIER",
            "carrier_token": "%var_398",
            "source_block": source_block,
            "instruction_index": 4,
            "instruction_ea": source_ea,
            "instruction_dstr": "setb [ds:%var_398].4, #0x64.4, %var_3A1.1",
        },
        evidence=("setb [ds:%var_398].4, #0x64.4, %var_3A1.1",),
    )


def _folded_loop_guard_fact(*, guard_block: int, body_state: int, exit_state: int) -> FactObservation:
    guard_ea = 0x1000 + guard_block * 0x40
    return FactObservation(
        fact_id="folded-loop-guard",
        kind="FoldedLoopGuardFact",
        semantic_key=f"folded_loop_guard:guard_ea=0x{guard_ea:x}",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.84,
        source_block=guard_block,
        source_ea=guard_ea,
        block_fingerprint=f"folded_guard:blk[{guard_block}]",
        mop_signature="folded_loop_guard:counter@0xa0",
        payload={
            "guard_ea": guard_ea,
            "body_state": body_state,
            "exit_state": exit_state,
            "counter_stkoff": 0xA0,
            "counter_size": 4,
            "bound": 0x64,
            "signed": False,
        },
        evidence=("setb [ds:%var_398].4, #0x64.4, %var_3A1.1",),
    )


def _ollvm_local_pointer_fact(
    token: str,
    *,
    local_base: str,
    source_block: int = 44,
    source_ea: int = 0xF000,
) -> FactObservation:
    return FactObservation(
        fact_id=f"ollvm-local-pointer:{token}",
        kind="OllvmValueFlowEvidence",
        semantic_key=f"ollvm_carrier:LOCAL_WORKING_POINTER:{token}",
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
        confidence=0.83,
        source_block=source_block,
        source_ea=source_ea,
        block_fingerprint=f"blk[{source_block}].0:mov",
        mop_signature=f"ollvm_carrier:LOCAL_WORKING_POINTER:{token}",
        payload={
            "role": "LOCAL_WORKING_POINTER",
            "carrier_token": token,
            "local_base_token": local_base,
            "source_block": source_block,
            "instruction_index": 1,
            "instruction_ea": source_ea,
            "instruction_dstr": f"mov &({local_base}).8, {token}.8",
        },
        evidence=(f"mov &({local_base}).8, {token}.8",),
    )


def _ollvm_accumulator_fact(
    token: str = "%var_378",
    *,
    multiply_add_base: str = "%var_18",
) -> FactObservation:
    return FactObservation(
        fact_id=f"ollvm-accumulator:{token}",
        kind="OllvmValueFlowEvidence",
        semantic_key=f"ollvm_carrier:ACCUMULATOR_CARRIER:{token}",
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
        confidence=0.80,
        source_block=34,
        source_ea=0x3408,
        block_fingerprint="blk[34].4:store",
        mop_signature=f"ollvm_carrier:ACCUMULATOR_CARRIER:{token}",
        payload={
            "role": "ACCUMULATOR_CARRIER",
            "carrier_token": token,
            "multiply_add_base_token": multiply_add_base,
            "multiply_add_same_base_alias_tokens": ("%var_390",),
            "source_block": 34,
            "instruction_index": 3,
            "instruction_ea": 0x3408,
            "instruction_dstr": (
                "stx ([ds:%var_378].4+(xds([ds:(%var_388+xdu(edx))])*ecx)), "
                "ds, %var_378"
            ),
        },
        evidence=("payload accumulator store",),
    )


def _ollvm_output_pointer_fact(
    token: str = "%var_30",
    *,
    source_block: int = 1,
    source_ea: int = 0x18000E7A9,
) -> FactObservation:
    return FactObservation(
        fact_id=f"ollvm-output-pointer:{token}",
        kind="OllvmValueFlowEvidence",
        semantic_key=f"ollvm_carrier:ARG_OUTPUT_POINTER:{token}",
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
        confidence=0.90,
        source_block=source_block,
        source_ea=source_ea,
        block_fingerprint=f"blk[{source_block}].0:mov",
        mop_signature=f"ollvm_carrier:ARG_OUTPUT_POINTER:{token}",
        payload={
            "role": "ARG_OUTPUT_POINTER",
            "carrier_token": token,
            "source_block": source_block,
            "instruction_index": 0,
            "instruction_ea": source_ea,
            "instruction_dstr": f"mov rdx.8, {token}.8",
        },
        evidence=(f"mov rdx.8, {token}.8",),
    )


def _ollvm_masked_output_store_fact(
    alias: str = "%var_370",
    *,
    source_block: int = 76,
    source_ea: int = 0x18000FA83,
) -> FactObservation:
    return FactObservation(
        fact_id=f"ollvm-output-store:{alias}",
        kind="OllvmValueFlowEvidence",
        semantic_key=f"ollvm_carrier:LOCAL_WORKING_STORE_CANDIDATE:{alias}",
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
        confidence=0.78,
        source_block=source_block,
        source_ea=source_ea,
        block_fingerprint=f"blk[{source_block}].2:store",
        mop_signature=f"ollvm_carrier:LOCAL_WORKING_STORE_CANDIDATE:{alias}",
        payload={
            "role": "LOCAL_WORKING_STORE_CANDIDATE",
            "carrier_token": alias,
            "local_base_token": "%var_18",
            "source_block": source_block,
            "instruction_index": 2,
            "instruction_ea": source_ea,
            "instruction_dstr": (
                "stx ((bnot([ds:%var_378].4) & #0x173063C1.4) | "
                "([ds:%var_378].4 & #0xE8CF9C3E.4)), ds, "
                f"[ds:{alias}.8].8"
            ),
            "store_kind": "masked_output_transform",
        },
        evidence=("masked output store",),
    )


def test_ollvm_output_store_retarget_matches_by_ea_when_fact_block_drifts() -> None:
    live_block = 60
    fact_block = 76
    store_ea = 0x18000FA83
    fg = FlowGraph(
        blocks={
            live_block: _b(
                live_block,
                (99,),
                (40,),
                (
                    _stx_alias(
                        store_ea,
                        0x370,
                        (
                            "stx ((bnot([ds.2:%var_378.8].4) & #0x173063C1.4) | "
                            "([ds.2:%var_378.8].4 & #0xE8CF9C3E.4)), ds.2, "
                            "[ds.2:%var_370.8].8"
                        ),
                    ),
                ),
            ),
            99: _stop(99, (live_block,)),
        },
        entry_serial=live_block,
        func_ea=0x1000,
    )
    facts = _FactView((
        _ollvm_output_pointer_fact("%var_30"),
        _ollvm_masked_output_store_fact(
            "%var_370",
            source_block=fact_block,
            source_ea=store_ea,
        ),
    ))

    mods = build_output_store_retargets(fg, facts)

    assert len(mods) == 1
    mod = mods[0]
    assert isinstance(mod, RetargetOutputStore)
    assert mod.block_serial == live_block
    assert mod.host_ea == store_ea
    assert mod.host_opcode == _OP_STX
    assert mod.alias_token == "%var_370"
    assert mod.output_token == "%var_30"
    assert mod.host_text_sha1
    assert mod.value_size == 4
    assert mod.reason == "output_store_retarget"


def test_ollvm_output_store_retarget_requires_output_pointer_fact() -> None:
    store_ea = 0x18000FA83
    fg = FlowGraph(
        blocks={
            60: _b(
                60,
                (99,),
                (40,),
                (
                    _stx_alias(
                        store_ea,
                        0x370,
                        (
                            "stx ((bnot([ds.2:%var_378.8].4) & #0x173063C1.4) | "
                            "([ds.2:%var_378.8].4 & #0xE8CF9C3E.4)), ds.2, "
                            "[ds.2:%var_370.8].8"
                        ),
                    ),
                ),
            ),
            99: _stop(99, (60,)),
        },
        entry_serial=60,
        func_ea=0x1000,
    )

    mods = build_output_store_retargets(
        fg,
        _FactView((_ollvm_masked_output_store_fact("%var_370", source_ea=store_ea),)),
    )

    assert mods == []


def test_ollvm_loop_index_evidence_marks_routed_predicate_block(_seam) -> None:
    """Raw OLLVM loop evidence is resolved by instruction EA, then routed."""
    fg = _shared_write_block_fg()
    disp = _disp({0x10: 10, 0xAA: 40, 0xBB: 50}, exit_block=99)
    transitions = (
        StateWriteTransition(
            write_block=1,
            next_state=0x10,
            target_handler=10,
            is_return=False,
            branch_arm=None,
        ),
    )

    routed = _loop_carrier_route_blocks(
        fg,
        disp,
        transitions,
        _FactView((_ollvm_loop_index_fact(source_block=999, source_ea=0x900),)),
    )

    assert routed == {10}


def _ollvm_split_loop_guard_fg() -> FlowGraph:
    """OLLVM counted-loop guard split across producer and selector blocks.

    blk30 computes ``counter < 0x64`` and writes selector state 0xAA.  The
    selector blk10 branches to two state-writing arms: body state 0xBB routes to
    blk40 and exit state 0xCC routes to blk50.
    """
    return FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(2, (10, 30, 40, 50), (1, 13, 30, 40, 50)),
            30: _b(
                30,
                (2,),
                (2,),
                (
                    _setb_counter(
                        0x3000,
                        0xA0,
                        "setb [ds:%var_398.8].4, #0x64.4, %var_3A1.1",
                    ),
                    _mov_state(0x3004, 0xAA),
                ),
            ),
            10: _b(10, (11, 12), (2,)),
            11: _b(11, (13,), (10,), (_mov_state(0x1100, 0xBB),)),
            12: _b(12, (13,), (10,), (_mov_state(0x1200, 0xCC),)),
            13: _b(13, (2,), (11, 12)),
            40: _b(40, (2,), (2,), (_mov_state(0x4000, 0x7FFFFFFF),)),
            50: _b(50, (2,), (2,), (_mov_state(0x5000, 0x7FFFFFFE),)),
            99: _stop(99, (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


def test_ollvm_loop_index_evidence_lowers_producer_to_body_exit(_seam) -> None:
    fg = _ollvm_split_loop_guard_fg()
    disp = _disp({0x10: 30, 0xAA: 10, 0xBB: 40, 0xCC: 50}, exit_block=99)
    transitions = (
        StateWriteTransition(
            write_block=30,
            next_state=0xAA,
            target_handler=10,
            is_return=False,
            branch_arm=None,
        ),
    )
    handler_transitions = recover_handler_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2
    )

    candidates = build_loop_carrier_guard_transitions(
        fg,
        disp,
        transitions,
        handler_transitions,
        _FactView((_ollvm_loop_index_fact(source_block=30, source_ea=0x3000),)),
        dispatcher_entry_serial=2,
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert isinstance(candidate, ConditionalStateTransitionCandidate)
    assert candidate.edge_kind == "CONDITIONAL_TRANSITION"
    assert candidate.reason == "loop_carrier_guard"
    assert candidate.suppressed_redirect_sources == frozenset({10, 30})
    lowerings, suppressed = lower_conditional_transition_candidates(candidates)

    assert suppressed == {10, 30}
    assert len(lowerings) == 1
    lowering = lowerings[0]
    assert isinstance(lowering, LowerConditionalStateTransition)
    assert lowering.source_serial == 30
    assert lowering.old_dispatcher_serial == 2
    assert lowering.true_target_serial == 40
    assert lowering.false_target_serial == 50
    assert isinstance(lowering.condition_operand, SyntheticCounterBoundCondition)
    assert lowering.condition_operand.counter_stkoff == 0xA0
    assert lowering.condition_operand.bound == 0x64
    assert lowering.condition_operand.signed is False


def test_folded_loop_guard_evidence_builds_conditional_transition_candidate() -> None:
    fg = FlowGraph(
        blocks={
            2: _b(2, (30, 40, 50), (30, 40, 50)),
            30: _b(
                30,
                (2,),
                (2,),
                (
                    _setb_counter(
                        0x3000,
                        0xA0,
                        "setb [ds:%var_398.8].4, #0x64.4, %var_3A1.1",
                    ),
                    _mov_state(0x3004, 0xAA),
                ),
            ),
            40: _b(40, (2,), (2,), (_mov_state(0x4000, 0xBB),)),
            50: _b(50, (2,), (2,), (_mov_state(0x5000, 0xCC),)),
        },
        entry_serial=30,
        func_ea=0x1000,
    )
    disp = _disp({0xBB: 40, 0xCC: 50}, exit_block=99)
    transitions = (
        StateWriteTransition(
            write_block=30,
            next_state=0xAA,
            target_handler=30,
            is_return=False,
            branch_arm=None,
        ),
    )

    candidates = build_folded_loop_guard_transitions(
        fg,
        disp,
        transitions,
        _FactView((_folded_loop_guard_fact(guard_block=30, body_state=0xBB, exit_state=0xCC),)),
        dispatcher_entry_serial=2,
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.edge_kind == "CONDITIONAL_TRANSITION"
    assert candidate.reason == "folded_loop_guard"
    assert candidate.source_serial == 30
    assert candidate.rewrite_from_ea == 0x3000
    assert candidate.true_target_serial == 40
    assert candidate.false_target_serial == 50
    assert candidate.suppressed_redirect_sources == frozenset({30})
    lowerings, suppressed = lower_conditional_transition_candidates(candidates)
    assert suppressed == {30}
    assert len(lowerings) == 1
    lowering = lowerings[0]
    assert isinstance(lowering, LowerConditionalStateTransition)
    assert isinstance(lowering.condition_operand, SyntheticCounterBoundCondition)
    assert lowering.condition_operand.bound == 0x64
    assert lowering.condition_operand.signed is False


def test_ollvm_payload_latch_redirects_to_predicate_producer() -> None:
    fg = FlowGraph(
        blocks={
            2: _b(2, (19, 34, 86, 108), (19, 34, 86, 108)),
            19: _b(19, (2,), (2,), (_mov_state(0x1900, 0xC0),)),
            34: _b(
                34,
                (2,),
                (2,),
                (
                    _ldx_alias(0x34C3, 0xB8, 24, "ldx ds.2, %var_380.8, ecx.4"),
                    _ldx_alias(0x34D5, 0xA0, 16, "ldx ds.2, %var_398.8, edx.4"),
                    _stx_alias(
                        0x34DF,
                        0xA0,
                        "stx ([ds.2:%var_398.8].4+#1.4), ds.2, %var_398.8",
                    ),
                    _stx_alias(
                        0x350A,
                        0xC0,
                        (
                            "stx ([ds.2:%var_378.8].4+"
                            "(xds.4([ds.2:(%var_388.8+xdu.8(edx.4))].1)*ecx.4)), "
                            "ds.2, %var_378.8"
                        ),
                    ),
                    _mov_state(0x3510, 0xB0),
                ),
            ),
            86: _b(86, (2,), (2,), (_mov_state(0x8600, 0xD0),)),
            108: _b(
                108,
                (2,),
                (2,),
                (
                    _setb_counter(
                        0x10BF4,
                        0xA0,
                        "setb [ds:%var_398.8].4, #0x64.4, %var_3A1.1",
                    ),
                    _mov_state(0x10C00, 0xE0),
                ),
            ),
        },
        entry_serial=34,
        func_ea=0x1000,
    )
    transitions = (
        StateWriteTransition(
            write_block=34,
            next_state=0xB0,
            target_handler=86,
            is_return=False,
            branch_arm=None,
        ),
        StateWriteTransition(
            write_block=86,
            next_state=0xD0,
            target_handler=19,
            is_return=False,
            branch_arm=None,
        ),
        StateWriteTransition(
            write_block=19,
            next_state=0xC0,
            target_handler=108,
            is_return=False,
            branch_arm=None,
        ),
        StateWriteTransition(
            write_block=108,
            next_state=0xE0,
            target_handler=15,
            is_return=False,
            branch_arm=None,
        ),
    )
    facts = _FactView((
        _ollvm_accumulator_fact(),
        _ollvm_loop_index_fact(source_block=108, source_ea=0x10BF4),
        _ollvm_local_pointer_fact("%var_378", local_base="%var_18"),
        _ollvm_local_pointer_fact("%var_380", local_base="%var_18"),
        _ollvm_local_pointer_fact("%var_398", local_base="%var_18"),
        _ollvm_local_pointer_fact("%var_388", local_base="%var_98"),
    ))

    mods, suppressed = build_loop_carrier_latch_redirects(
        fg,
        transitions,
        facts,
        dispatcher_entry_serial=2,
        state_var_stkoff=_STATE,
    )

    assert suppressed == {34}
    redirect = next(m for m in mods if isinstance(m, RedirectGoto))
    zero = next(m for m in mods if isinstance(m, ZeroStateWrite))
    assert redirect.from_serial == 34
    assert redirect.old_target == 2
    assert redirect.new_target == 108
    assert zero.block_serial == 34
    assert zero.insn_ea == 0x3510


def test_ollvm_payload_latch_redirects_existing_body_route_to_predicate_producer() -> None:
    fg = FlowGraph(
        blocks={
            2: _b(2, (34, 104, 108), (108,)),
            34: _b(
                34,
                (104,),
                (104,),
                (
                    _ldx_alias(0x34C3, 0xB8, 24, "ldx ds.2, %var_380.8, ecx.4"),
                    _ldx_alias(0x34D5, 0xA0, 16, "ldx ds.2, %var_398.8, edx.4"),
                    _stx_alias(
                        0x34DF,
                        0xA0,
                        "stx ([ds.2:%var_398.8].4+#1.4), ds.2, %var_398.8",
                    ),
                    _stx_alias(
                        0x350A,
                        0xC0,
                        (
                            "stx ([ds.2:%var_378.8].4+"
                            "(xds.4([ds.2:(%var_388.8+xdu.8(edx.4))].1)*ecx.4)), "
                            "ds.2, %var_378.8"
                        ),
                    ),
                    _mov_state(0x3510, 0xB0),
                ),
            ),
            104: _b(104, (34,), (34,), (_mov_state(0x10400, 0xC0),)),
            108: _b(
                108,
                (2,),
                (2,),
                (
                    _setb_counter(
                        0x10BF4,
                        0xA0,
                        "setb [ds:%var_398.8].4, #0x64.4, %var_3A1.1",
                    ),
                    _mov_state(0x10C00, 0xE0),
                ),
            ),
        },
        entry_serial=34,
        func_ea=0x1000,
    )
    transitions = (
        StateWriteTransition(
            write_block=34,
            next_state=0xB0,
            target_handler=104,
            is_return=False,
            branch_arm=None,
        ),
        StateWriteTransition(
            write_block=104,
            next_state=0xC0,
            target_handler=34,
            is_return=False,
            branch_arm=None,
        ),
        StateWriteTransition(
            write_block=108,
            next_state=0xE0,
            target_handler=15,
            is_return=False,
            branch_arm=None,
        ),
    )
    facts = _FactView((
        _ollvm_accumulator_fact(),
        _ollvm_loop_index_fact(source_block=108, source_ea=0x10BF4),
        _ollvm_local_pointer_fact("%var_378", local_base="%var_18"),
        _ollvm_local_pointer_fact("%var_380", local_base="%var_18"),
        _ollvm_local_pointer_fact("%var_398", local_base="%var_18"),
        _ollvm_local_pointer_fact("%var_388", local_base="%var_98"),
    ))

    mods, suppressed = build_loop_carrier_latch_redirects(
        fg,
        transitions,
        facts,
        dispatcher_entry_serial=2,
        state_var_stkoff=_STATE,
    )

    assert suppressed == {34}
    redirect = next(m for m in mods if isinstance(m, RedirectGoto))
    zero = next(m for m in mods if isinstance(m, ZeroStateWrite))
    assert redirect.from_serial == 34
    assert redirect.old_target == 104
    assert redirect.new_target == 108
    assert zero.block_serial == 34
    assert zero.insn_ea == 0x3510


def test_ollvm_local_alias_scalarization_preserves_loop_carriers() -> None:
    fg = FlowGraph(
        blocks={
            5: _b(
                5,
                (34,),
                (),
                (
                    _stx_alias(
                        0x5000,
                        0xC0,
                        "stx ([ds.2:%var_378.8].4+#1.4), ds.2, %var_378.8",
                    ),
                ),
            ),
            34: _b(
                34,
                (2,),
                (5,),
                (
                    _ldx_alias(
                        0x34C3,
                        0xB8,
                        24,
                        "ldx ds.2, %var_380.8, ecx.4",
                    ),
                    _ldx_alias(
                        0x34D5,
                        0xA0,
                        16,
                        "ldx ds.2, %var_398.8, edx.4",
                    ),
                    _stx_alias(
                        0x34DF,
                        0xA0,
                        "stx ([ds.2:%var_398.8].4+#1.4), ds.2, %var_398.8",
                    ),
                    _stx_alias(
                        0x350A,
                        0xC0,
                        (
                            "stx ([ds.2:%var_378.8].4+"
                            "(xds.4([ds.2:(%var_388.8+xdu.8(edx.4))].1)*ecx.4)), "
                            "ds.2, %var_378.8"
                        ),
                    ),
                    _ldx_alias(
                        0x3510,
                        0xB0,
                        8,
                        "ldx ds.2, %var_388.8, rax.8",
                    ),
                ),
            ),
        },
        entry_serial=34,
        func_ea=0x1000,
    )
    facts = _FactView((
        _ollvm_accumulator_fact(),
        _ollvm_loop_index_fact(source_block=134, source_ea=0x10BF4),
        _ollvm_local_pointer_fact("%var_378", local_base="%var_18"),
        _ollvm_local_pointer_fact("%var_380", local_base="%var_18"),
        _ollvm_local_pointer_fact("%var_398", local_base="%var_18"),
        _ollvm_local_pointer_fact("%var_388", local_base="%var_98"),
    ))

    mods = build_local_alias_scalarizations(fg, facts)

    aliases = {(m.alias_token, m.base_token) for m in mods}
    assert ("%var_378", "%var_378") in aliases
    assert ("%var_380", "%var_380") in aliases
    assert ("%var_398", "%var_398") in aliases
    assert ("%var_388", "%var_388") not in aliases
    assert {m.block_serial for m in mods} == {34}
    assert all(isinstance(m, ScalarizeLocalAliasAccess) for m in mods)
    assert {m.value_size for m in mods} == {4}


def test_ollvm_payload_detection_accepts_native_input_symbol_rendering() -> None:
    fg = FlowGraph(
        blocks={
            34: _b(
                34,
                (86,),
                (98,),
                (
                    _ldx_alias(0xEFC3, 0xB8, 24, "ldx ds.2, %var_380.8, ecx.4"),
                    _ldx_alias(0xEFD5, 0xA0, 16, "ldx ds.2, %var_398.8, edx.4"),
                    _stx_alias(
                        0xEFDF,
                        0xA0,
                        "stx ([ds.2:%var_398.8].4+#1.4), ds.2, %var_398.8",
                    ),
                    _stx_alias(
                        0xEFF5,
                        0xC0,
                        (
                            "stx ([ds.2:%var_378.8].4+"
                            "(xds.4([ds.2:(%fdwReason.8+xdu.8(edx.4))].1)*ecx.4)), "
                            "ds.2, %var_378.8"
                        ),
                    ),
                    _mov_state(0xF08E, 0xB0),
                ),
            ),
            86: _b(86, (19,), (34,), (_mov_state(0x8600, 0xD0),)),
            19: _b(19, (108,), (86,), (_mov_state(0x1900, 0xC0),)),
            108: _b(
                108,
                (2,),
                (19,),
                (
                    _setb_counter(
                        0x10BF4,
                        0xA0,
                        "setb [ds:%var_398.8].4, #0x64.4, %var_3A1.1",
                    ),
                    _mov_state(0x10CD5, 0xE0),
                ),
            ),
        },
        entry_serial=34,
        func_ea=0x1000,
    )
    transitions = (
        StateWriteTransition(
            write_block=34,
            next_state=0xB0,
            target_handler=86,
            is_return=False,
            branch_arm=None,
        ),
        StateWriteTransition(
            write_block=86,
            next_state=0xD0,
            target_handler=19,
            is_return=False,
            branch_arm=None,
        ),
        StateWriteTransition(
            write_block=19,
            next_state=0xC0,
            target_handler=108,
            is_return=False,
            branch_arm=None,
        ),
    )
    facts = _FactView((
        _ollvm_accumulator_fact(),
        _ollvm_loop_index_fact(source_block=108, source_ea=0x10BF4),
        _ollvm_local_pointer_fact("%var_378", local_base="%var_18"),
        _ollvm_local_pointer_fact("%var_380", local_base="%var_18"),
        _ollvm_local_pointer_fact("%var_398", local_base="%var_18"),
        _ollvm_local_pointer_fact("%var_388", local_base="%var_98"),
    ))

    latch_mods, suppressed = build_loop_carrier_latch_redirects(
        fg,
        transitions,
        facts,
        dispatcher_entry_serial=2,
        state_var_stkoff=_STATE,
    )
    scalar_mods = build_local_alias_scalarizations(fg, facts)

    redirect = next(m for m in latch_mods if isinstance(m, RedirectGoto))
    zero = next(m for m in latch_mods if isinstance(m, ZeroStateWrite))
    assert suppressed == {34}
    assert (redirect.from_serial, redirect.old_target, redirect.new_target) == (34, 86, 108)
    assert zero.insn_ea == 0xF08E
    assert {
        (m.block_serial, m.host_ea, m.alias_token)
        for m in scalar_mods
        if isinstance(m, ScalarizeLocalAliasAccess)
    } == {
        (34, 0xEFC3, "%var_380"),
        (34, 0xEFD5, "%var_398"),
        (34, 0xEFDF, "%var_398"),
        (34, 0xEFF5, "%var_378"),
    }


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
