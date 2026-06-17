"""Unit tests for the minimal per-handler-write + interval-route recovery.

Pure: synthetic ``FlowGraph`` + ``IntervalDispatcher`` (no IDA).  The MBA fold
runs through a registered portable ``forward_eval_insn`` seam.
"""
from __future__ import annotations

import pytest

from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.analyses.control_flow.minimal_state_recovery import (
    StateWriteTransition,
    TransitionProof,
    diff_back_edge_transitions,
    diff_back_edge_transitions_partitioned,
    recover_handler_transitions,
    recover_state_write_transitions,
    recover_state_write_transitions_via_fixpoint,
    recover_state_write_transitions_via_multicell_fixpoint,
    recover_state_write_transitions_via_partitioned_fixpoint,
    transitions_use_terminal_stack_alias_guard,
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
from d810.ir.semantics import PredicateKind

_OP_MOV = 4
_OP_XOR = 31
_OP_STORE = 88
_OP_JZ = 44
_T_NUM = 2
_T_STK = 4
_T_REG = 1
_T_ADDR = 10
_OPCODE_NAMES = {_OP_MOV: "m_mov", _OP_XOR: "m_xor", _OP_STORE: "m_stx"}
_OPCODE_VALUES = {"m_mov": _OP_MOV, "m_xor": _OP_XOR, "m_stx": _OP_STORE}
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
    return MopSnapshot(
        t=_T_STK,
        size=4,
        stkoff=off,
        stack_refs=(off,),
        kind=OperandKind.STACK,
    )


def _addr(off: int) -> MopSnapshot:
    return MopSnapshot(
        t=_T_ADDR,
        size=8,
        stack_refs=(off,),
        kind=OperandKind.ADDRESS,
        sub_l=_stk(off),
    )


def _mov(ea: int, src: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(opcode=_OP_MOV, ea=ea, operands=(), l=src, d=dst, kind=InsnKind.MOV)


def _store(ea: int, src: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=_OP_STORE,
        ea=ea,
        operands=(),
        l=src,
        d=dst,
        kind=InsnKind.STORE,
    )


def _xor(ea: int, l: MopSnapshot, r: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(opcode=_OP_XOR, ea=ea, operands=(), l=l, r=r, d=dst, kind=InsnKind.AND)


def _jz_stack_const(ea: int, stkoff: int, const: int, target: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=_OP_JZ,
        ea=ea,
        operands=(),
        l=_stk(stkoff),
        r=_num(const),
        d=MopSnapshot(t=-1, size=0, block_ref=target, kind=OperandKind.BLOCK),
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )


_OP_AND = 21  # m_and (portable evaluator default)
_OP_OR = 22   # m_or  (portable evaluator default)


def _and(ea: int, l: MopSnapshot, r: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(opcode=_OP_AND, ea=ea, operands=(), l=l, r=r, d=dst, kind=InsnKind.AND)


def _or(ea: int, l: MopSnapshot, r: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(opcode=_OP_OR, ea=ea, operands=(), l=l, r=r, d=dst, kind=InsnKind.AND)


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


def test_nested_dispatcher_corridor_uses_concrete_reentry_path(_seam) -> None:
    # Handler blk13 is selected by the inner dispatcher (blk9).  Its arms write
    # the inner state, then jump through an outer dispatcher corridor (blk2/3)
    # before re-entering blk9.  The scan must follow the concrete outer state
    # seeded by blk9 and must not explore the infeasible decoy arm through blk6.
    outer_state = 0x18
    fg = FlowGraph(
        blocks={
            0: _blk(0, (9,), (), ()),
            2: _blk(2, (3, 6), (14, 15, 6), (_jz_stack_const(0x2000, outer_state, 0, 6),)),
            3: _blk(3, (4, 9), (2,), (_jz_stack_const(0x3000, outer_state, 1, 9),)),
            4: _stop(4, (3,)),
            6: _blk(6, (2,), (2,), (_mov(0x6000, _num(0), _stk(_STATE_OFF)),)),
            9: _blk(
                9,
                (10, 13),
                (0, 3),
                (
                    _mov(0x9000, _num(1), _stk(outer_state)),
                    _jz_stack_const(0x9004, _STATE_OFF, 0, 13),
                ),
            ),
            10: _blk(10, (11, 16), (9,), (_jz_stack_const(0xA000, _STATE_OFF, 1, 16),)),
            11: _blk(11, (23,), (10,), ()),
            13: _blk(13, (14, 15), (9,), ()),
            14: _blk(14, (2,), (13,), (_mov(0x1400, _num(1), _stk(_STATE_OFF)),)),
            15: _blk(15, (2,), (13,), (_mov(0x1500, _num(9), _stk(_STATE_OFF)),)),
            16: _blk(16, (9,), (10,), ()),
            23: _blk(23, (9,), (11,), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _dispatcher({0: 13, 1: 16, 9: 23}, exit_block=4)

    edges = {
        edge.handler: edge
        for edge in recover_handler_transitions(
            fg,
            disp,
            _STATE_OFF,
            dispatcher_entry_serial=9,
        )
    }

    h13 = edges[13]
    assert h13.is_conditional
    by_state = {arm.next_state: arm for arm in h13.arms}
    assert set(by_state) == {1, 9}
    assert by_state[1].target_handler == 16
    assert by_state[9].target_handler == 23
    assert {arm.branch_block for arm in h13.arms} == {13}
    assert {arm.ordered_path[1] for arm in h13.arms} == {14, 15}


def test_partitioned_fixpoint_resolves_stack_address_alias_state_store(_seam) -> None:
    # blk10 proves r3 == &state_var; blk11 writes the next state via r3 and
    # re-enters the dispatcher. The provider is structural: no magic constants,
    # only the configured state stack offset and the address alias.
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20), (11,), (_mov(0x2000, _num(0), _reg(0)),)),
            10: _blk(10, (11,), (2,), (_mov(0x1000, _addr(_STATE_OFF), _reg(3)),)),
            11: _blk(11, (2,), (10,), (_store(0x1100, _num(0x20), _reg(3)),)),
            20: _blk(20, (2,), (2,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _dispatcher({0x10: 10, 0x20: 20}, exit_block=99)

    edges = recover_state_write_transitions_via_partitioned_fixpoint(
        fg,
        disp,
        _STATE_OFF,
        dispatcher_entry_serial=2,
    )

    assert len(edges) == 1
    edge = edges[0]
    assert edge.write_block == 11
    assert edge.next_state == 0x20
    assert edge.target_handler == 20
    assert edge.is_return is False
    assert edge.proof is not None
    assert edge.proof.kind == "stack_address_alias_store"


def test_partitioned_fixpoint_resolves_joined_stack_address_alias_state_store(_seam) -> None:
    # Both incoming edges to blk12 prove r3 == &state_var before the shared store.
    # This is the exit-path effect shape from sub_1815C8C30: the state store is
    # not in the alias-defining block, and the shared store block has more than
    # one non-dispatch predecessor.
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 11, 20), (12,), (_mov(0x2000, _num(0), _reg(0)),)),
            10: _blk(10, (12,), (2,), (_mov(0x1000, _addr(_STATE_OFF), _reg(3)),)),
            11: _blk(11, (12,), (2,), (_mov(0x1010, _addr(_STATE_OFF), _reg(3)),)),
            12: _blk(12, (2,), (10, 11), (_store(0x1200, _num(0x20), _reg(3)),)),
            20: _blk(20, (2,), (2,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _dispatcher({0x10: 10, 0x11: 11, 0x20: 20}, exit_block=99)

    edges = recover_state_write_transitions_via_partitioned_fixpoint(
        fg,
        disp,
        _STATE_OFF,
        dispatcher_entry_serial=2,
    )

    assert len(edges) == 1
    edge = edges[0]
    assert edge.write_block == 12
    assert edge.next_state == 0x20
    assert edge.target_handler == 20
    assert edge.is_return is False
    assert edge.proof is not None
    assert edge.proof.kind == "stack_address_alias_store"


def test_partitioned_fixpoint_resolves_nested_join_stack_address_alias_state_store(_seam) -> None:
    # The alias can be established before a join that then flows into the store
    # block. Every incoming edge to blk12 proves the same alias, blk12 preserves
    # it, and blk13 writes through the register.
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 11, 20), (13,), (_mov(0x2000, _num(0), _reg(0)),)),
            10: _blk(10, (12,), (2,), (_mov(0x1000, _addr(_STATE_OFF), _reg(3)),)),
            11: _blk(11, (12,), (2,), (_mov(0x1010, _addr(_STATE_OFF), _reg(3)),)),
            12: _blk(12, (13,), (10, 11), ()),
            13: _blk(13, (2,), (12,), (_store(0x1300, _num(0x20), _reg(3)),)),
            20: _blk(20, (2,), (2,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _dispatcher({0x10: 10, 0x11: 11, 0x20: 20}, exit_block=99)

    edges = recover_state_write_transitions_via_partitioned_fixpoint(
        fg,
        disp,
        _STATE_OFF,
        dispatcher_entry_serial=2,
    )

    assert len(edges) == 1
    edge = edges[0]
    assert edge.write_block == 13
    assert edge.next_state == 0x20
    assert edge.target_handler == 20
    assert edge.is_return is False
    assert edge.proof is not None
    assert edge.proof.kind == "stack_address_alias_store"


def test_partitioned_fixpoint_splits_predecessor_sensitive_stack_alias_store(_seam) -> None:
    # Mirrors sub_1815C8C30's terminal block: through one predecessor r3 is a
    # non-state stack address, through the terminal predecessor r3 is &state.
    # The provider must keep the shared carrier block on the terminal arm via
    # via_block instead of treating the whole block as one state write.
    non_state_off = 0x30
    terminal_state_full = 0xDD1FF05BF465445C
    terminal_state = terminal_state_full & 0xFFFFFFFF
    fg = FlowGraph(
        blocks={
            2: _blk(2, (4, 20), (8,), (_mov(0x2000, _num(0), _reg(0)),)),
            4: _blk(4, (5, 6), (2,), (_mov(0x4000, _addr(non_state_off), _reg(3)),)),
            5: _blk(5, (6,), (4,), (_mov(0x5000, _addr(non_state_off), _reg(3)),)),
            6: _blk(6, (7, 8), (4, 5), (_mov(0x6000, _addr(non_state_off), _reg(3)),)),
            7: _blk(7, (8,), (6,), (_mov(0x7000, _addr(_STATE_OFF), _reg(3)),)),
            8: _blk(
                8,
                (20, 2),
                (6, 7),
                (
                    _store(0x8000, _num(terminal_state_full), _reg(3)),
                    InsnSnapshot(
                        opcode=44,
                        ea=0x8004,
                        operands=(),
                        l=_stk(_STATE_OFF),
                        r=_num(terminal_state_full),
                        kind=InsnKind.EQUALITY_JUMP,
                        branch_predicate=PredicateKind.NE,
                    ),
                ),
            ),
            20: _stop(20, (8,)),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _dispatcher({0x10: 4}, exit_block=4)

    edges = recover_state_write_transitions_via_partitioned_fixpoint(
        fg,
        disp,
        _STATE_OFF,
        dispatcher_entry_serial=2,
    )

    partitioned = [
        edge
        for edge in edges
        if edge.proof is not None
        and edge.proof.kind == "stack_address_alias_terminal_guard_partitioned"
    ]
    assert len(partitioned) == 1
    edge = partitioned[0]
    assert edge.write_block == 7
    assert edge.via_block == 8
    assert edge.next_state == terminal_state
    assert edge.target_handler == 20
    assert edge.proof is not None
    assert (
        edge.proof.reason
        == "predecessor_state_store_through_stack_address_alias_terminal_guard"
    )
    assert transitions_use_terminal_stack_alias_guard(edges) is True


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


def test_b2_partitioned_reproduces_case2_via_block_split(_seam) -> None:
    """B2: two regions share an opaque-XOR back-edge -> a predecessor-partitioned split.

    blk10 and blk60 (distinct dispatcher targets) both fall into the SHARED xor
    back-edge blk11 with different register constants, so blk11 folds to a different
    next-state per incoming edge -- the single-partition fold MEETs them to ⊥.  The
    partitioned shadow must emit one ``via_block=11`` redirect per predecessor,
    byte-identical to the production Case-2 split.
    0x12345678 ^ 0x081CC5A1 = 0x1A2893D9 ; 0x11111111 ^ 0x22222222 = 0x33333333
    """
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

    prod = recover_state_write_transitions(
        fg, disp, _STATE_OFF, dispatcher_entry_serial=2)
    prod_splits = {t.write_block: t for t in prod if t.via_block == 11}
    # Production emits the Case-2 split: blk10->20, blk60->70, both via_block=11.
    assert prod_splits[10].next_state == 0x1A2893D9 and prod_splits[10].target_handler == 20
    assert prod_splits[60].next_state == 0x33333333 and prod_splits[60].target_handler == 70

    # Single-partition multi-cell MEETs the conflicting reg consts -> blk11 unresolved.
    multi = {t.write_block: t for t in recover_state_write_transitions_via_multicell_fixpoint(
        fg, disp, _STATE_OFF, dispatcher_entry_serial=2)}
    assert multi[11].next_state is None and multi[11].is_return is True

    # Partitioned shadow reproduces the split byte-identically.
    pp_splits = {t.write_block: t for t in
                 recover_state_write_transitions_via_partitioned_fixpoint(
                     fg, disp, _STATE_OFF, dispatcher_entry_serial=2) if t.via_block == 11}
    assert pp_splits[10].next_state == 0x1A2893D9 and pp_splits[10].target_handler == 20
    assert pp_splits[10].is_return is False and pp_splits[10].via_block == 11
    assert pp_splits[60].next_state == 0x33333333 and pp_splits[60].target_handler == 70
    assert pp_splits[60].is_return is False and pp_splits[60].via_block == 11


# --- C3b: proof-carrying transitions (ticket llr-1szn / d81-t9ok) ----------
#
# After the C3 flip the authoritative emitter
# (recover_state_write_transitions_via_partitioned_fixpoint) attaches a typed
# TransitionProof to every back-edge naming the oracle that resolved it and
# whether the result is trusted.  Proof is *additive* provenance: the diff
# functions compare only (next_state, target_handler, is_return), so attaching
# it keeps the shadow-diff at 0 and the Docker golden byte-identical.


def test_c3b_global_fold_attaches_trusted_proof(_seam) -> None:
    """A back-edge that folds unambiguously gets a trusted ``global_fold`` proof."""
    fg = _multicell_xor_fg()
    disp = _dispatcher({0x10: 10, 0x1A2893D9: 20}, exit_block=99)
    by_block = {t.write_block: t for t in
                recover_state_write_transitions_via_partitioned_fixpoint(
                    fg, disp, _STATE_OFF, dispatcher_entry_serial=2)}
    p = by_block[11].proof
    assert p is not None
    assert p.oracle_kind == "region_partitioned_fixpoint"
    assert p.kind == "global_fold"
    assert p.trusted is True  # routes to handler blk20, not exit


def test_c3b_predecessor_partitioned_proof(_seam) -> None:
    """The Case-2 opaque-XOR split rows carry ``predecessor_partitioned`` proofs."""
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
    splits = {t.write_block: t for t in
              recover_state_write_transitions_via_partitioned_fixpoint(
                  fg, disp, _STATE_OFF, dispatcher_entry_serial=2) if t.via_block == 11}
    for wb in (10, 60):
        assert splits[wb].proof is not None
        assert splits[wb].proof.kind == "predecessor_partitioned"
        assert splits[wb].proof.trusted is True


def test_c3b_region_agreed_proof(_seam) -> None:
    """Conflicting reg consts that XOR to the same state -> a ``region_agreed`` proof.

    The single-partition meet drops both registers (each disagrees across the two
    predecessors), so the back-edge does not globally fold; partitioning by
    predecessor recovers 0xFF on *both* edges, so they agree on one state and emit
    a plain redirect (not a split) tagged ``region_agreed``.
    0xF0 ^ 0x0F == 0xFF ; 0x0F ^ 0xF0 == 0xFF
    """
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 60, 20), (11,), (_mov(0x2000, _num(0), _reg(0)),)),
            10: _blk(10, (11,), (2,), (_mov(0x1000, _num(0xF0), _reg(8)),
                                       _mov(0x1004, _num(0x0F), _reg(9)))),
            60: _blk(60, (11,), (2,), (_mov(0x6000, _num(0x0F), _reg(8)),
                                       _mov(0x6004, _num(0xF0), _reg(9)))),
            11: _blk(11, (2,), (10, 60), (_xor(0x1100, _reg(8), _reg(9), _stk(_STATE_OFF)),)),
            20: _blk(20, (2,), (2,), ()),
        },
        entry_serial=2, func_ea=0x1000,
    )
    disp = _dispatcher({0x10: 10, 0x60: 60, 0xFF: 20}, exit_block=99)
    rows = recover_state_write_transitions_via_partitioned_fixpoint(
        fg, disp, _STATE_OFF, dispatcher_entry_serial=2)
    by_block = {t.write_block: t for t in rows}
    # No split emitted: the shared back-edge blk11 redirects once to route(0xFF)=20.
    assert all(t.via_block is None for t in rows)
    assert by_block[11].next_state == 0xFF and by_block[11].target_handler == 20
    assert by_block[11].proof is not None
    assert by_block[11].proof.kind == "region_agreed"
    assert by_block[11].proof.trusted is True


def test_c3b_unresolved_proof_is_untrusted(_seam) -> None:
    """A back-edge with no foldable state write -> an UNTRUSTED ``unresolved`` proof."""
    fg = FlowGraph(
        blocks={
            2: _blk(2, (11,), (11,), ()),     # dispatcher header, no state write
            11: _blk(11, (2,), (2,), ()),     # back-edge, writes no state
        },
        entry_serial=2, func_ea=0x1000,
    )
    disp = _dispatcher({}, exit_block=99)
    by_block = {t.write_block: t for t in
                recover_state_write_transitions_via_partitioned_fixpoint(
                    fg, disp, _STATE_OFF, dispatcher_entry_serial=2)}
    t = by_block[11]
    assert t.next_state is None and t.is_return is True
    assert t.proof is not None
    assert t.proof.kind == "unresolved"
    assert t.proof.trusted is False


def test_c3b_diff_ignores_proof_field(_seam) -> None:
    """Both diff functions compare states only -- a proof on one side never diverges.

    The C3 flip keeps the legacy fold wired as a standing equivalence guard.  The
    legacy production rows are unattributed (proof=None) while the authoritative
    fixpoint rows carry proofs; the diff must still report full agreement.
    """
    legacy = (
        StateWriteTransition(11, 0x1A2893D9, 20, False, None, proof=None),
        StateWriteTransition(10, 0x33333333, 70, False, None, via_block=11, proof=None),
    )
    attributed = (
        StateWriteTransition(
            11, 0x1A2893D9, 20, False, None,
            proof=TransitionProof("region_partitioned_fixpoint", "global_fold", True),
        ),
        StateWriteTransition(
            10, 0x33333333, 70, False, None, via_block=11,
            proof=TransitionProof(
                "region_partitioned_fixpoint", "predecessor_partitioned", True
            ),
        ),
    )
    # Plain (non-split) row matches; the via_block split is bucketed case2_opaque
    # by the single-partition diff (its key never reaches the inner predecessor).
    d1 = diff_back_edge_transitions(legacy, attributed)
    assert d1["matched"] == 1 and d1["case2_opaque"] == 1 and d1["mismatch"] == []
    # The B2-aware diff keys splits on (write_block, via_block) -> both match.
    d2 = diff_back_edge_transitions_partitioned(legacy, attributed)
    assert d2["matched"] == 2 and d2["mismatch"] == []
    # Symmetric: attributed-vs-legacy is identical (proof is invisible to the diff).
    assert diff_back_edge_transitions_partitioned(attributed, legacy)["matched"] == 2


# --- masked-OR / switch-table dispatch (abc_or_dispatch, ticket llr-fzvc) ---
#
# A masked dispatcher routes on ``state & MASK`` and each handler advances the
# state with ``state = (state & ~MASK) | M``.  That write READS the state var, so
# the global meet (which collapses the state var to bottom at the dispatcher join)
# cannot fold it.  The seeded region fold carries each region's dispatch key, so
# the masked-OR resolves to ``M`` and routes correctly.


def test_masked_or_back_edge_resolved_via_region_seed(_seam) -> None:
    """``state = (state & ~0xF) | 1`` folds to 1 only with the dispatch-key seed.

    Two masked-OR handlers (blk10 key 0, blk60 key 2) loop back to the dispatcher
    writing DIFFERENT nibble values, so the state var meets to bottom at the
    dispatcher join and the global fold of each state-reading write fails.  The
    seeded region fold enters each handler with its dispatch key and folds
    ``(key & ~0xF) | M == M``, routing blk10->route(1)=20 and blk60->route(3)=70.
    Each handler is its own back-edge, so the resolution is a plain
    ``region_seeded`` redirect (not a partitioned split).
    """
    fg = FlowGraph(
        blocks={
            # Dispatcher with two state-write preds; no register pre-zeroing, so
            # the AND's source (the state var) is genuinely unknown globally.
            2: _blk(2, (10, 60, 20, 70), (10, 60), ()),
            10: _blk(10, (2,), (2,), (
                _and(0x1000, _stk(_STATE_OFF), _num(0xFFFFFFF0), _reg(8)),
                _or(0x1004, _reg(8), _num(1), _stk(_STATE_OFF)),
            )),
            60: _blk(60, (2,), (2,), (
                _and(0x6000, _stk(_STATE_OFF), _num(0xFFFFFFF0), _reg(8)),
                _or(0x6004, _reg(8), _num(3), _stk(_STATE_OFF)),
            )),
            20: _blk(20, (90,), (2,), ()),
            70: _blk(70, (91,), (2,), ()),
            90: _stop(90, (20,)),
            91: _stop(91, (70,)),
        },
        entry_serial=2, func_ea=0x1000,
    )
    disp = _dispatcher({0x0: 10, 0x2: 60, 0x1: 20, 0x3: 70}, exit_block=99)

    by_block = {t.write_block: t for t in
                recover_state_write_transitions_via_partitioned_fixpoint(
                    fg, disp, _STATE_OFF, dispatcher_entry_serial=2)}
    assert by_block[10].next_state == 1 and by_block[10].target_handler == 20
    assert by_block[60].next_state == 3 and by_block[60].target_handler == 70
    for wb in (10, 60):
        assert by_block[wb].is_return is False
        assert by_block[wb].via_block is None
        assert by_block[wb].proof is not None
        assert by_block[wb].proof.kind == "region_seeded"
        assert by_block[wb].proof.trusted is True

    # Without the seed the global/multicell fixpoint cannot fold the state-reading
    # writes -> the back-edges are unresolved (proving the seed is what resolves them).
    multi = {t.write_block: t for t in recover_state_write_transitions_via_multicell_fixpoint(
        fg, disp, _STATE_OFF, dispatcher_entry_serial=2)}
    assert multi[10].next_state is None and multi[60].next_state is None


def test_masked_or_shared_glue_block_partitioned_via_seed(_seam) -> None:
    """A shared state-glue block (abc_or_dispatch blk8) splits per-edge via the seed.

    blk10 (key 0) and blk60 (key 2) each do their own masked-OR write, then fall
    into the SHARED no-op glue block blk11 which branches back to the dispatcher
    (the abc_or_dispatch blk8 funnel).  blk11 is the single back-edge; its
    incoming state meets to bottom (1 vs 3), so neither the global fold nor the
    plain per-predecessor partition resolves it (no register pre-zeroing).  The
    seeded region fold carries each handler's dispatch key, recovers a distinct
    next-state per immediate predecessor, and emits one ``via_block=11`` redirect
    each.
    """
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 60, 20, 70), (11,), ()),
            10: _blk(10, (11,), (2,), (
                _and(0x1000, _stk(_STATE_OFF), _num(0xFFFFFFF0), _reg(8)),
                _or(0x1004, _reg(8), _num(1), _stk(_STATE_OFF)),
            )),
            60: _blk(60, (11,), (2,), (
                _and(0x6000, _stk(_STATE_OFF), _num(0xFFFFFFF0), _reg(8)),
                _or(0x6004, _reg(8), _num(3), _stk(_STATE_OFF)),
            )),
            11: _blk(11, (2,), (10, 60), ()),
            20: _blk(20, (90,), (2,), ()),
            70: _blk(70, (91,), (2,), ()),
            90: _stop(90, (20,)),
            91: _stop(91, (70,)),
        },
        entry_serial=2, func_ea=0x1000,
    )
    disp = _dispatcher({0x0: 10, 0x2: 60, 0x1: 20, 0x3: 70}, exit_block=99)

    splits = {t.write_block: t for t in
              recover_state_write_transitions_via_partitioned_fixpoint(
                  fg, disp, _STATE_OFF, dispatcher_entry_serial=2) if t.via_block == 11}
    assert splits[10].next_state == 1 and splits[10].target_handler == 20
    assert splits[60].next_state == 3 and splits[60].target_handler == 70
    for wb in (10, 60):
        assert splits[wb].via_block == 11
        assert splits[wb].is_return is False
        assert splits[wb].proof is not None
        assert splits[wb].proof.kind == "region_seeded_partitioned"
