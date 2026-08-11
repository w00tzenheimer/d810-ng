"""Unit tests for the minimal per-handler-write + interval-route recovery.

Pure: synthetic ``FlowGraph`` + ``IntervalDispatcher`` (no IDA).  The MBA fold
runs through a registered portable ``forward_eval_insn`` seam.
"""

from __future__ import annotations

import pytest

import d810.analyses.control_flow.minimal_state_recovery as minimal_state_recovery
from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    MaterializedStateRoute,
)
from d810.analyses.control_flow.minimal_state_recovery import (
    HandlerTransition,
    StateWriteTransition,
    TransitionArm,
    TransitionProof,
    diff_back_edge_transitions,
    diff_back_edge_transitions_partitioned,
    recover_handler_transitions,
    recover_state_write_transitions,
    recover_state_write_transitions_via_fixpoint,
    recover_state_write_transitions_via_multicell_fixpoint,
    recover_state_write_transitions_via_partitioned_fixpoint,
    resolve_materialized_indirect_transfer_targets,
    resolve_materialized_handler_exit_states,
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
from d810.capabilities.providers import (
    ConditionChainWalkerProvider,
    register_condition_chain_walkers,
)
from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.semantics import PredicateKind

_OP_MOV = 4
_OP_XOR = 31
_OP_STORE = 88
_OP_JZ = 44
_T_NUM = 2
_T_STK = 4
_T_REG = 1
_T_ADDR = 10
_T_GLOBAL = 7
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
            insn,
            stk_map,
            reg_map,
            state_var_stkoff,
            seams=seams,
            mba=kwargs.pop("mba", None),
            state_var_lvar_idx=kwargs.pop("state_var_lvar_idx", None),
        )

    register_condition_chain_walkers(
        ConditionChainWalkerProvider(
            detect_state_var_stkoff=lambda *a, **k: None,
            dump_dispatcher_node=lambda *a, **k: None,
            find_pre_header_state=lambda *a, **k: None,
            walk_handler_chain=lambda *a, **k: None,
            forward_eval_insn=_fwd,
            resolve_via_condition_chain_walk=lambda *a, **k: None,
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


def _global(gaddr: int) -> MopSnapshot:
    return MopSnapshot(
        t=_T_GLOBAL,
        size=8,
        gaddr=gaddr,
        kind=OperandKind.GLOBAL,
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
    return InsnSnapshot(
        opcode=_OP_MOV, ea=ea, operands=(), l=src, d=dst, kind=InsnKind.MOV
    )


def _store(ea: int, src: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=_OP_STORE,
        ea=ea,
        operands=(),
        l=src,
        d=dst,
        kind=InsnKind.STORE,
    )


def _xor(
    ea: int,
    left: MopSnapshot,
    right: MopSnapshot,
    dst: MopSnapshot,
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=_OP_XOR,
        ea=ea,
        operands=(),
        l=left,
        r=right,
        d=dst,
        kind=InsnKind.UNKNOWN,
        value_op_kind=ValueOpKind.XOR,
    )


def _nested_sub(left: MopSnapshot, right: MopSnapshot) -> MopSnapshot:
    """Portable ``mop_d`` for a nested ``left - right`` expression."""
    return MopSnapshot(
        t=-1,
        size=4,
        kind=OperandKind.SUBINSN,
        sub_kind=InsnKind.SUB,
        sub_value_op_kind=ValueOpKind.SUB,
        sub_l=left,
        sub_r=right,
    )


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
_OP_OR = 22  # m_or  (portable evaluator default)


def _and(
    ea: int,
    left: MopSnapshot,
    right: MopSnapshot,
    dst: MopSnapshot,
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=_OP_AND,
        ea=ea,
        operands=(),
        l=left,
        r=right,
        d=dst,
        kind=InsnKind.AND,
        value_op_kind=ValueOpKind.AND,
    )


def _or(
    ea: int,
    left: MopSnapshot,
    right: MopSnapshot,
    dst: MopSnapshot,
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=_OP_OR,
        ea=ea,
        operands=(),
        l=left,
        r=right,
        d=dst,
        kind=InsnKind.UNKNOWN,
        value_op_kind=ValueOpKind.OR,
    )


def _blk(
    serial, succs, preds, insns, *, ea=None, kind=BlockKind.UNKNOWN
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=tuple(succs),
        preds=tuple(preds),
        flags=0,
        start_ea=ea if ea is not None else 0x1000 + serial * 0x40,
        insn_snapshots=tuple(insns),
        kind=kind,
    )


def _stop(serial, preds) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=(),
        preds=tuple(preds),
        flags=0,
        start_ea=0x9000 + serial,
        insn_snapshots=(),
        kind=BlockKind.STOP,
    )


class _PoisonProvenanceOperand:
    def __getattr__(self, name: str):
        raise AssertionError(f"provenance operand should not be read: {name}")


class _RawLiveGlobalFieldOperand:
    kind = OperandKind.GLOBAL
    size = 8
    gaddr = None

    @property
    def g(self):
        raise AssertionError("raw live global field should not be read")


def _dispatcher(
    point_targets: dict[int, int], *, exit_block: int, domain_hi: int = 0x100000000
) -> IntervalDispatcher:
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


def test_residual_state_key_upgrades_default_terminal_without_source_anchor() -> None:
    state = 0xEC71CA67
    graph = FlowGraph(
        blocks={
            1: _blk(1, (99,), (), (), ea=0x1000),
            20: _blk(20, (), (), (), ea=0x2000),
            30: _blk(30, (), (), (), ea=0x3000),
            99: _stop(99, (1,)),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    dispatcher = _dispatcher({}, exit_block=99)
    transition = StateWriteTransition(
        write_block=1,
        next_state=state,
        target_handler=99,
        is_return=True,
        branch_arm=None,
        proof=TransitionProof("region_partitioned_fixpoint", "global_fold", True),
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x5000,
        materialized_anchor_eas=(0xDEAD,),
        target_eas=(0x2000, 0x3000),
        condition_code=4,
        true_target_ea=0x2000,
        false_target_ea=0x3000,
        selector_state_constant=state,
        resolver_kind="residual_microcode",
    )

    result = resolve_materialized_indirect_transfer_targets(
        (transition,), graph, dispatcher, (transfer,)
    )

    assert result[0].target_handler == 20
    assert result[0].is_return is False
    assert result[0].proof is not None
    assert result[0].proof.kind == "computed_goto_target"


def test_static_fixpoint_terminal_delivery_overrides_intermediate_equality_handler() -> (
    None
):
    """A byte-patch plan's exact terminal arm outranks its selector stub."""
    state = 0x19A7218A
    graph = FlowGraph(
        blocks={
            1: _blk(1, (20,), (), (), ea=0x40C7E5),
            20: _blk(20, (30,), (1,), (), ea=0x40A5D0),
            30: _stop(30, (20,)),
        },
        entry_serial=1,
        func_ea=0x40A560,
    )
    dispatcher = _dispatcher({state: 20}, exit_block=30)
    transition = StateWriteTransition(1, state, 20, False, None)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5E3,
        source_block_ea=0x40A5CA,
        materialized_anchor_eas=(0x40A5D0,),
        target_eas=(0x9000 + 30, 0x40A5F0),
        condition_code=4,
        true_target_ea=0x9000 + 30,
        false_target_ea=0x40A5F0,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        selector_state_on_left=True,
        resolver_kind="static_fixpoint",
    )

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        dispatcher,
        (transfer,),
        condition_chain_handlers=frozenset({20}),
        state_var_reg=20,
    )

    assert resolved.target_handler == 30
    assert resolved.is_return is True
    assert resolved.proof is not None
    assert resolved.proof.kind == "computed_goto_exact_terminal_delivery"


def test_explicit_terminal_state_route_overrides_coarse_self_route() -> None:
    state = 0x19A7218A
    graph = FlowGraph(
        blocks={
            1: _blk(1, (1,), (), (), ea=0x40C7E5),
            30: _stop(30, (1,)),
        },
        entry_serial=1,
        func_ea=0x40A560,
    )
    dispatcher = _dispatcher({state: 1}, exit_block=30)
    transition = StateWriteTransition(1, state, 1, False, None)
    route = MaterializedStateRoute(
        source_block_serial=1,
        state_constant=state,
        target_handler_serial=30,
        proof_kind="terminal_state_route",
    )

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        dispatcher,
        (),
        materialized_state_routes=(route,),
        condition_chain_handlers=frozenset({1, 30}),
        state_var_reg=20,
    )

    assert resolved.target_handler == 30
    assert resolved.is_return is True
    assert resolved.proof is not None
    assert resolved.proof.kind == "computed_goto_exact_terminal_delivery"


def test_source_local_terminal_write_overrides_stale_transition_state() -> None:
    terminal_state = 0x19A7218A
    stale_state = 0xABB95547
    graph = FlowGraph(
        blocks={
            1: _blk(
                1,
                (20,),
                (),
                (_mov(0x40A5D0, _num(terminal_state), _reg(20)),),
                ea=0x40A5D0,
            ),
            20: _blk(20, (20,), (1,), (), ea=0xF1C003B8),
            30: _stop(30, ()),
        },
        entry_serial=1,
        func_ea=0x40A560,
    )
    dispatcher = _dispatcher({stale_state: 20}, exit_block=30)
    transition = StateWriteTransition(1, stale_state, 20, False, None)
    route = MaterializedStateRoute(
        source_block_serial=1,
        state_constant=terminal_state,
        target_handler_serial=30,
        proof_kind="terminal_state_route",
    )

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        dispatcher,
        (),
        materialized_state_routes=(route,),
        condition_chain_handlers=frozenset({20, 30}),
        state_var_reg=20,
    )

    assert resolved.next_state == terminal_state
    assert resolved.target_handler == 30
    assert resolved.is_return is True
    assert resolved.proof is not None
    assert resolved.proof.kind == "computed_goto_exact_terminal_delivery"
    assert resolved.proof.reason == "source_local_terminal_state_write"


def test_residual_state_key_uses_condition_chain_handler_authority_without_dag() -> (
    None
):
    state = 0xEC71CA67
    graph = FlowGraph(
        blocks={
            1: _blk(1, (99,), (), (), ea=0x1000),
            20: _blk(20, (), (), (), ea=0x2000),
            30: _blk(30, (), (), (), ea=0x3000),
            99: _stop(99, (1,)),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    dispatcher = _dispatcher({}, exit_block=99)
    transition = StateWriteTransition(1, state, 99, True, None)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x5000,
        materialized_anchor_eas=(0xDEAD,),
        target_eas=(0x2000, 0x3000),
        condition_code=4,
        true_target_ea=0x2000,
        false_target_ea=0x3000,
        selector_state_constant=state,
        resolver_kind="residual_microcode",
    )

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        dispatcher,
        (transfer,),
        condition_chain_handlers=frozenset({20}),
    )

    assert resolved.target_handler == 20
    assert resolved.is_return is False
    assert resolved.proof is not None
    assert resolved.proof.kind == "computed_goto_target"


def test_residual_state_key_abstains_when_target_is_not_known_handler() -> None:
    state = 0xEC71CA67
    graph = FlowGraph(
        blocks={
            1: _blk(1, (99,), (), (), ea=0x1000),
            20: _blk(20, (), (), (), ea=0x2000),
            30: _blk(30, (), (), (), ea=0x3000),
            99: _stop(99, (1,)),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    dispatcher = _dispatcher({}, exit_block=99)
    transition = StateWriteTransition(1, state, 99, True, None)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0xDEAD,),
        target_eas=(0x3000,),
        condition_code=4,
        true_target_ea=0x3000,
        false_target_ea=0x2000,
        selector_state_constant=state,
        resolver_kind="residual_microcode",
    )

    assert resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        dispatcher,
        (transfer,),
        condition_chain_handlers=frozenset({20}),
    ) == (transition,)


def test_exact_materialized_state_route_upgrades_only_matching_false_terminal() -> None:
    state = 0xA5A94B86
    graph = FlowGraph(
        blocks={
            10: _blk(10, (99,), (), (), ea=0x1000),
            20: _blk(20, (), (), (), ea=0x2000),
            99: _stop(99, (10,)),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    dispatcher = _dispatcher({}, exit_block=99)
    transition = StateWriteTransition(
        write_block=10,
        next_state=state,
        target_handler=99,
        is_return=True,
        branch_arm=None,
    )
    route = MaterializedStateRoute(
        source_block_serial=10,
        state_constant=state,
        target_handler_serial=20,
    )

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        dispatcher,
        (),
        materialized_state_routes=(route,),
        condition_chain_handlers=frozenset({20}),
    )

    assert resolved.target_handler == 20
    assert resolved.is_return is False
    assert resolved.proof is not None
    assert resolved.proof.kind == "computed_goto_state_route"


def test_exact_materialized_state_route_uses_via_block_partition() -> None:
    state = 0xF6A636EF
    graph = FlowGraph(
        blocks={
            10: _blk(10, (11,), (), (), ea=0x1000),
            11: _blk(11, (99,), (10,), (), ea=0x1100),
            20: _blk(20, (), (), (), ea=0x2000),
            30: _blk(30, (), (), (), ea=0x3000),
            99: _stop(99, (11,)),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    dispatcher = _dispatcher({}, exit_block=99)
    transition = StateWriteTransition(10, state, 99, True, None, via_block=11)
    routes = (
        MaterializedStateRoute(10, state, 30),
        MaterializedStateRoute(11, state, 20),
    )

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        dispatcher,
        (),
        materialized_state_routes=routes,
        condition_chain_handlers=frozenset({20, 30}),
    )

    assert resolved.target_handler == 20


def test_exact_materialized_state_route_falls_back_to_write_block_partition() -> None:
    state = 0x23B8E806
    graph = FlowGraph(
        blocks={
            10: _blk(10, (11,), (), (), ea=0x1000),
            11: _blk(11, (99,), (10,), (), ea=0x1100),
            20: _blk(20, (), (), (), ea=0x2000),
            99: _stop(99, (11,)),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    dispatcher = _dispatcher({}, exit_block=99)
    transition = StateWriteTransition(10, state, 99, True, None, via_block=11)

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        dispatcher,
        (),
        materialized_state_routes=(MaterializedStateRoute(10, state, 20),),
        condition_chain_handlers=frozenset({20}),
    )

    assert resolved.target_handler == 20


def test_exact_materialized_state_route_abstains_on_conflict_or_non_handler() -> None:
    state = 0xAE5A330B
    graph = FlowGraph(
        blocks={
            10: _blk(10, (99,), (), (), ea=0x1000),
            20: _blk(20, (), (), (), ea=0x2000),
            30: _blk(30, (), (), (), ea=0x3000),
            99: _stop(99, (10,)),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    dispatcher = _dispatcher({}, exit_block=99)
    transition = StateWriteTransition(10, state, 99, True, None)

    for routes in (
        (
            MaterializedStateRoute(10, state, 20),
            MaterializedStateRoute(10, state, 30),
        ),
        (MaterializedStateRoute(10, state, 30),),
    ):
        assert resolve_materialized_indirect_transfer_targets(
            (transition,),
            graph,
            dispatcher,
            (),
            materialized_state_routes=routes,
            condition_chain_handlers=frozenset({20}),
        ) == (transition,)


def test_global_state_var_detector_ignores_rich_operand_slot_provenance() -> None:
    insn = InsnSnapshot(
        opcode=_OP_JZ,
        ea=0x1010,
        operands=(_PoisonProvenanceOperand(),),
        operand_slots=(("l", _PoisonProvenanceOperand()),),
        l=_global(0x180021320),
        r=_num(0),
        d=MopSnapshot(t=-1, size=0, block_ref=10, kind=OperandKind.BLOCK),
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={2: _blk(2, (10, 99), (), (insn,))},
        entry_serial=2,
        func_ea=0x1000,
    )

    assert minimal_state_recovery._detect_global_state_var(fg, 2) == 0x180021320


def test_global_state_var_detector_ignores_non_branch_globals() -> None:
    call_like = InsnSnapshot(
        opcode=_OP_MOV,
        ea=0x1008,
        operands=(),
        l=MopSnapshot(
            t=-1,
            size=8,
            kind=OperandKind.SUBINSN,
            sub_l=_global(0x180000000),
        ),
        d=_reg(8),
        kind=InsnKind.MOV,
    )
    branch = _jz_stack_const(0x1010, _STATE_OFF, 0x22, 10)
    fg = FlowGraph(
        blocks={2: _blk(2, (10, 99), (), (call_like, branch))},
        entry_serial=2,
        func_ea=0x1000,
    )

    assert minimal_state_recovery._detect_global_state_var(fg, 2) is None


def test_global_state_var_detector_ignores_raw_live_global_field() -> None:
    insn = InsnSnapshot(
        opcode=_OP_JZ,
        ea=0x1010,
        operands=(),
        l=_RawLiveGlobalFieldOperand(),
        r=_num(0),
        d=MopSnapshot(t=-1, size=0, block_ref=10, kind=OperandKind.BLOCK),
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={2: _blk(2, (10, 99), (), (insn,))},
        entry_serial=2,
        func_ea=0x1000,
    )

    assert minimal_state_recovery._detect_global_state_var(fg, 2) is None


def test_unconditional_literal_transition(_seam) -> None:
    # blk10 writes mov #0x20, state_var; goto dispatcher(2). route(0x20)=blk20.
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20), (10,), (_mov(0x2000, _num(0), _reg(0)),)),
            10: _blk(10, (2,), (2,), (_mov(0x1000, _num(0x20), _stk(_STATE_OFF)),)),
            20: _blk(20, (2,), (2,), (_mov(0x3000, _num(0), _reg(0)),)),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _dispatcher({0x10: 10, 0x20: 20}, exit_block=99)
    edges = {
        e.handler: e
        for e in recover_handler_transitions(
            fg, disp, _STATE_OFF, dispatcher_entry_serial=2
        )
    }
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
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _dispatcher({0x30: 30, 0xAA: 40, 0xBB: 50}, exit_block=99)
    edges = {
        e.handler: e
        for e in recover_handler_transitions(
            fg, disp, _STATE_OFF, dispatcher_entry_serial=2
        )
    }
    h30 = edges[30]
    assert h30.is_conditional
    targets = {a.next_state: a.target_handler for a in h30.arms}
    assert targets == {0xAA: 40, 0xBB: 50}
    assert all(a.branch_block == 30 for a in h30.arms)


def test_register_conditional_two_arm_transition(_seam) -> None:
    """The multi-arm scan follows a register-resident dispatcher state variable."""
    state_reg = 20
    fg = FlowGraph(
        blocks={
            2: _blk(2, (30, 40, 50), (31, 32), (_mov(0x2000, _num(0), _reg(0)),)),
            30: _blk(30, (31, 32), (2,), ()),
            31: _blk(31, (2,), (30,), (_mov(0x3100, _num(0xAA), _reg(state_reg)),)),
            32: _blk(32, (2,), (30,), (_mov(0x3200, _num(0xBB), _reg(state_reg)),)),
            40: _blk(40, (2,), (2,), ()),
            50: _blk(50, (2,), (2,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _dispatcher({0x30: 30, 0xAA: 40, 0xBB: 50}, exit_block=99)

    edges = {
        edge.handler: edge
        for edge in recover_handler_transitions(
            fg,
            disp,
            None,
            state_var_reg=state_reg,
            dispatcher_entry_serial=2,
        )
    }

    h30 = edges[30]
    assert h30.is_conditional
    assert {arm.next_state: arm.target_handler for arm in h30.arms} == {
        0xAA: 40,
        0xBB: 50,
    }
    assert all(arm.branch_block == 30 for arm in h30.arms)


def test_handler_scan_stops_at_alternate_dispatcher_region_entry(_seam) -> None:
    """A handler exit must not be owned by a second BST router root.

    Computed-goto comparison trees can have more than one live re-entry node.
    ``dispatcher_entry_serial`` names the canonical root, while a handler can
    jump to another comparison node in the same dispatcher region.  The state
    write remains owned by the handler exit, not by that router node.
    """
    state_reg = 20
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20), (), ()),
            3: _blk(3, (20,), (10,), ()),
            10: _blk(
                10,
                (3,),
                (2,),
                (_mov(0x1010, _num(0x20), _reg(state_reg)),),
            ),
            20: _blk(20, (2,), (3,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _dispatcher({0x10: 10, 0x20: 20}, exit_block=99)

    edges = {
        edge.handler: edge
        for edge in recover_handler_transitions(
            fg,
            disp,
            None,
            state_var_reg=state_reg,
            dispatcher_entry_serial=2,
            dispatcher_region_serials=frozenset({2, 3}),
        )
    }

    arm = edges[10].arms[0]
    assert arm.next_state == 0x20
    assert arm.target_handler == 20
    assert arm.write_block == 10
    assert arm.ordered_path == (10,)


def test_handler_scan_uses_authoritative_handlers_not_coarse_interval_leaves(
    _seam,
) -> None:
    """An interval leaf can be handler glue, not a semantic handler entry."""
    state_reg = 20
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20), (11,), ()),
            10: _blk(10, (11,), (2,), ()),
            11: _blk(
                11,
                (2,),
                (10,),
                (_mov(0x1110, _num(0x20), _reg(state_reg)),),
            ),
            20: _blk(20, (2,), (2,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    # Block 11 is a coarse interval outcome, but exact equality evidence says
    # only blocks 10 and 20 are semantic handlers.
    disp = _dispatcher({0x10: 10, 0x20: 20, 0x30: 11}, exit_block=99)

    edges = {
        edge.handler: edge
        for edge in recover_handler_transitions(
            fg,
            disp,
            None,
            state_var_reg=state_reg,
            dispatcher_entry_serial=2,
            authoritative_handler_serials=frozenset({10, 20}),
        )
    }

    arm = edges[10].arms[0]
    assert arm.next_state == 0x20
    assert arm.target_handler == 20
    assert arm.write_block == 11
    assert arm.ordered_path == (10, 11)


def test_handler_scan_preserves_distinct_unresolved_branch_paths(_seam) -> None:
    state_reg = 20
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10,), (), ()),
            10: _blk(10, (11,), (2,), ()),
            11: _blk(11, (12, 13), (10,), ()),
            12: _blk(12, (), (11,), ()),
            13: _blk(13, (), (11,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    dispatcher = _dispatcher({0x10: 10}, exit_block=99)

    transitions = recover_handler_transitions(
        fg,
        dispatcher,
        None,
        state_var_reg=state_reg,
        dispatcher_entry_serial=2,
        authoritative_handler_serials=frozenset({10}),
    )

    assert len(transitions) == 1
    assert {(arm.branch_block, arm.ordered_path) for arm in transitions[0].arms} == {
        (11, (10, 11, 12)),
        (11, (10, 11, 13)),
    }


def test_exact_exit_route_overrides_stale_inherited_handler_state() -> None:
    transition = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                next_state=0x10,
                target_handler=10,
                is_return=False,
                branch_block=None,
                write_block=11,
                exit_block=11,
                ordered_path=(10, 11),
            ),
        ),
    )
    route = MaterializedStateRoute(
        source_block_serial=11,
        state_constant=0x20,
        target_handler_serial=20,
    )

    (resolved,) = resolve_materialized_handler_exit_states(
        (transition,),
        (route,),
        frozenset({10, 20}),
    )

    (arm,) = resolved.arms
    assert arm.next_state == 0x20
    assert arm.target_handler == 20
    assert arm.is_return is False
    assert arm.source_keyed_block == 11


def test_conditional_arm_route_outranks_generic_route_for_same_unresolved_arm() -> None:
    transition = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                next_state=None,
                target_handler=None,
                is_return=True,
                branch_block=10,
                write_block=12,
                exit_block=13,
                ordered_path=(10, 12, 13),
            ),
        ),
    )
    routes = (
        MaterializedStateRoute(12, 0x30, 30),
        MaterializedStateRoute(
            12,
            0x20,
            20,
            proof_kind="conditional_arm",
        ),
    )

    (resolved,) = resolve_materialized_handler_exit_states(
        (transition,),
        routes,
        frozenset({10, 20, 30}),
    )

    assert resolved.arms[0].next_state == 0x20
    assert resolved.arms[0].target_handler == 20
    assert resolved.arms[0].source_keyed_block == 12


def test_exact_handler_owned_exit_route_repairs_one_self_loop_arm() -> None:
    transition = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                next_state=0x10,
                target_handler=10,
                is_return=False,
                branch_block=10,
                write_block=11,
                exit_block=11,
                ordered_path=(10, 11),
            ),
            TransitionArm(
                next_state=0x30,
                target_handler=30,
                is_return=False,
                branch_block=10,
                write_block=12,
                exit_block=12,
                ordered_path=(10, 12),
            ),
        ),
    )
    route = MaterializedStateRoute(
        source_block_serial=10,
        state_constant=0x20,
        target_handler_serial=20,
        source_handler_serial=10,
        handler_exit_proven=True,
    )

    (resolved,) = resolve_materialized_handler_exit_states(
        (transition,),
        (route,),
        frozenset({10, 20, 30}),
    )

    assert resolved.arms[0].next_state == 0x20
    assert resolved.arms[0].target_handler == 20
    assert resolved.arms[0].is_return is False
    assert resolved.arms[0].source_keyed_block == 10
    assert resolved.arms[1] == transition.arms[1]


def test_exact_handler_owned_exit_route_repairs_imported_clone_self_loop() -> None:
    transition = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                next_state=0x10,
                target_handler=11,
                is_return=False,
                branch_block=None,
                write_block=10,
                exit_block=10,
                ordered_path=(10,),
            ),
        ),
    )
    routes = (
        MaterializedStateRoute(
            source_block_serial=10,
            state_constant=0x10,
            target_handler_serial=11,
        ),
        MaterializedStateRoute(
            source_block_serial=10,
            state_constant=0x20,
            target_handler_serial=20,
            source_handler_serial=10,
            handler_exit_proven=True,
        ),
    )

    (resolved,) = resolve_materialized_handler_exit_states(
        (transition,),
        routes,
        frozenset({10, 11, 20}),
    )

    (arm,) = resolved.arms
    assert arm.next_state == 0x20
    assert arm.target_handler == 20
    assert arm.is_return is False
    assert arm.source_keyed_block == 10


def test_terminal_route_outranks_replayed_handler_self_loop_exit() -> None:
    terminal_state = 0x19A7218A
    stale_state = 0xABB95547
    transition = HandlerTransition(
        handler=301,
        states=(terminal_state,),
        arms=(
            TransitionArm(
                next_state=terminal_state,
                target_handler=301,
                is_return=False,
                branch_block=None,
                write_block=301,
                exit_block=301,
                ordered_path=(301,),
            ),
        ),
    )
    routes = (
        MaterializedStateRoute(
            source_block_serial=301,
            state_constant=terminal_state,
            target_handler_serial=302,
            proof_kind="terminal_state_route",
        ),
        MaterializedStateRoute(
            source_block_serial=301,
            state_constant=stale_state,
            target_handler_serial=286,
            source_handler_serial=301,
            handler_exit_proven=True,
        ),
    )

    (resolved,) = resolve_materialized_handler_exit_states(
        (transition,),
        routes,
        frozenset({286, 301, 302}),
    )

    (arm,) = resolved.arms
    assert arm.next_state == terminal_state
    assert arm.target_handler == 302
    assert arm.is_return is True
    assert arm.source_keyed_block == 301


def test_exact_exit_route_preserves_healthy_nonself_handler_transition() -> None:
    transition = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                next_state=0x20,
                target_handler=20,
                is_return=False,
                branch_block=None,
                write_block=11,
                exit_block=11,
                ordered_path=(10, 11),
            ),
        ),
    )
    route = MaterializedStateRoute(11, 0x30, 30)

    assert resolve_materialized_handler_exit_states(
        (transition,),
        (route,),
        frozenset({10, 20, 30}),
    ) == (transition,)


def test_exact_exit_route_preserves_concrete_unresolved_state_for_direct_routing() -> (
    None
):
    transition = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                next_state=0x30,
                target_handler=None,
                is_return=True,
                branch_block=None,
                write_block=11,
                exit_block=11,
                ordered_path=(10, 11),
            ),
        ),
    )
    route = MaterializedStateRoute(11, 0x40, 40)

    assert resolve_materialized_handler_exit_states(
        (transition,),
        (route,),
        frozenset({10, 40}),
    ) == (transition,)


def test_nested_dispatcher_corridor_uses_concrete_reentry_path(_seam) -> None:
    # Handler blk13 is selected by the inner dispatcher (blk9).  Its arms write
    # the inner state, then jump through an outer dispatcher corridor (blk2/3)
    # before re-entering blk9.  The scan must follow the concrete outer state
    # seeded by blk9 and must not explore the infeasible decoy arm through blk6.
    outer_state = 0x18
    fg = FlowGraph(
        blocks={
            0: _blk(0, (9,), (), ()),
            2: _blk(
                2, (3, 6), (14, 15, 6), (_jz_stack_const(0x2000, outer_state, 0, 6),)
            ),
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


def test_partitioned_fixpoint_multi_entry_recovers_nonpredecessor_writer(_seam) -> None:
    fg = FlowGraph(
        blocks={
            0: _blk(0, (10,), (), ()),
            2: _blk(2, (20,), (12,), ()),
            10: _blk(10, (11,), (0,), (_mov(0x1000, _num(0x20), _stk(_STATE_OFF)),)),
            11: _blk(11, (12,), (10,), ()),
            12: _blk(12, (2,), (11,), ()),
            20: _blk(20, (2,), (2,), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _dispatcher({0x20: 20}, exit_block=99)

    default_edges = recover_state_write_transitions_via_partitioned_fixpoint(
        fg,
        disp,
        _STATE_OFF,
        dispatcher_entry_serial=2,
    )
    assert not any(edge.write_block == 10 for edge in default_edges)

    edges = recover_state_write_transitions_via_partitioned_fixpoint(
        fg,
        disp,
        _STATE_OFF,
        dispatcher_entry_serial=2,
        include_multi_entry_back_edges=True,
    )

    multi = [edge for edge in edges if edge.write_block == 10]
    assert len(multi) == 1
    edge = multi[0]
    assert edge.via_block == 11
    assert edge.next_state == 0x20
    assert edge.target_handler == 20
    assert edge.proof is not None
    assert edge.proof.kind == "multi_entry_global_fold"
    assert not any(edge.write_block == 11 for edge in edges)


def test_partitioned_fixpoint_skips_dispatcher_region_predecessors(_seam) -> None:
    """Router back-edges are not handler state transitions."""
    fg = FlowGraph(
        blocks={
            0: _blk(0, (10,), (), ()),
            2: _blk(2, (20,), (3, 10), ()),
            3: _blk(3, (2,), (20,), ()),
            10: _blk(
                10,
                (2,),
                (0,),
                (_mov(0x1010, _num(0x20), _stk(_STATE_OFF)),),
            ),
            20: _blk(20, (3,), (2,), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _dispatcher({0x20: 20}, exit_block=99)

    edges = recover_state_write_transitions_via_partitioned_fixpoint(
        fg,
        disp,
        _STATE_OFF,
        dispatcher_entry_serial=2,
        dispatcher_region_serials=frozenset({2, 3}),
    )

    assert [(edge.write_block, edge.target_handler) for edge in edges] == [(10, 20)]


def test_multi_entry_scan_does_not_collapse_partitioned_predecessors(_seam) -> None:
    """A shared corridor with two incoming states stays predecessor-specific."""
    fg = FlowGraph(
        blocks={
            0: _blk(0, (10, 60), (), ()),
            2: _blk(2, (10, 60, 20, 70), (12,), ()),
            10: _blk(10, (11,), (0, 2), (_mov(0x1000, _num(0x20), _stk(_STATE_OFF)),)),
            60: _blk(60, (11,), (0, 2), (_mov(0x6000, _num(0x30), _stk(_STATE_OFF)),)),
            11: _blk(11, (12,), (10, 60), ()),
            12: _blk(12, (2,), (11,), ()),
            20: _blk(20, (2,), (2,), ()),
            70: _blk(70, (2,), (2,), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _dispatcher({0x20: 20, 0x30: 70}, exit_block=99)

    edges = recover_state_write_transitions_via_partitioned_fixpoint(
        fg,
        disp,
        _STATE_OFF,
        dispatcher_entry_serial=2,
        include_multi_entry_back_edges=True,
    )

    targets_by_physical_edge: dict[tuple[int, int], set[int]] = {}
    for edge in edges:
        if edge.via_block is None or edge.target_handler is None:
            continue
        targets_by_physical_edge.setdefault(
            (edge.write_block, edge.via_block), set()
        ).add(edge.target_handler)

    assert targets_by_physical_edge[(10, 11)] == {20}
    assert targets_by_physical_edge[(60, 11)] == {70}
    assert (11, 12) not in targets_by_physical_edge
    assert all(len(targets) == 1 for targets in targets_by_physical_edge.values())


def test_partitioned_fixpoint_resolves_joined_stack_address_alias_state_store(
    _seam,
) -> None:
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


def test_partitioned_fixpoint_resolves_nested_join_stack_address_alias_state_store(
    _seam,
) -> None:
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


def test_partitioned_fixpoint_splits_predecessor_sensitive_stack_alias_store(
    _seam,
) -> None:
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
            10: _blk(
                10,
                (11,),
                (2,),
                (
                    _mov(0x1000, _num(0x12345678), _reg(8)),
                    _mov(0x1004, _num(0x081CC5A1), _reg(9)),
                ),
            ),
            60: _blk(
                60,
                (11,),
                (2,),
                (
                    _mov(0x6000, _num(0x11111111), _reg(8)),
                    _mov(0x6004, _num(0x22222222), _reg(9)),
                ),
            ),
            11: _blk(
                11, (2,), (10, 60), (_xor(0x1100, _reg(8), _reg(9), _stk(_STATE_OFF)),)
            ),
            20: _blk(20, (2,), (2,), ()),
            70: _blk(70, (2,), (2,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _dispatcher(
        {0x10: 10, 0x60: 60, 0x1A2893D9: 20, 0x33333333: 70}, exit_block=99
    )
    edges = {
        e.handler: e
        for e in recover_handler_transitions(
            fg, disp, _STATE_OFF, dispatcher_entry_serial=2
        )
    }
    assert edges[10].arms[0].next_state == 0x1A2893D9
    assert edges[10].arms[0].target_handler == 20
    assert edges[60].arms[0].next_state == 0x33333333
    assert edges[60].arms[0].target_handler == 70


def test_terminal_when_next_state_routes_to_exit(_seam) -> None:
    # blk10 writes a state whose dispatcher route is the default/exit block.
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10,), (10,), (_mov(0x2000, _num(0), _reg(0)),)),
            10: _blk(
                10, (2,), (2,), (_mov(0x1000, _num(0x7FFFFFFF), _stk(_STATE_OFF)),)
            ),
            99: _stop(99, (2,)),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    # 0x7FFFFFFF falls in a gap -> routes to exit(99); 99 is a STOP block.
    disp = _dispatcher({0x10: 10}, exit_block=99)
    edges = {
        e.handler: e
        for e in recover_handler_transitions(
            fg, disp, _STATE_OFF, dispatcher_entry_serial=2
        )
    }
    arm = edges[10].arms[0]
    assert arm.is_return is True


def test_scan_stops_at_other_handler_entry(_seam) -> None:
    # blk10 writes NO state and its only successor is another handler entry
    # (blk20). The scan must stop at blk20 (boundary), not absorb blk20's write.
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20), (20,), (_mov(0x2000, _num(0), _reg(0)),)),
            10: _blk(
                10, (20,), (2,), (_mov(0x1000, _num(0), _reg(0)),)
            ),  # no state write
            20: _blk(20, (2,), (10,), (_mov(0x2000, _num(0x20), _stk(_STATE_OFF)),)),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _dispatcher({0x10: 10, 0x20: 20}, exit_block=99)
    edges = {
        e.handler: e
        for e in recover_handler_transitions(
            fg, disp, _STATE_OFF, dispatcher_entry_serial=2
        )
    }
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
            10: _blk(
                10,
                (11,),
                (2,),
                (
                    _mov(0x1000, _num(0x12345678), _reg(8)),
                    _mov(0x1004, _num(0x081CC5A1), _reg(9)),
                ),
            ),
            11: _blk(
                11, (2,), (10,), (_xor(0x1100, _reg(8), _reg(9), _stk(_STATE_OFF)),)
            ),
            20: _blk(20, (2,), (2,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
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

    prod = {
        t.write_block: t
        for t in recover_state_write_transitions(
            fg, disp, _STATE_OFF, dispatcher_entry_serial=2
        )
    }
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
    single = {
        t.write_block: t
        for t in recover_state_write_transitions_via_fixpoint(
            fg, disp, dispatcher_entry_serial=2, out_states=fp.out_states
        )
    }
    # The single-cell fixpoint only carries the state slot: blk11's opaque XOR
    # write is not folded, so it passes through blk10's stale entry-assume (0x10)
    # instead of the real next-state -- DISAGREEING with production.
    assert single[11].next_state != prod[11].next_state

    # Multi-cell shadow: folds reg8^reg9 -> resolves to the production value.
    multi = {
        t.write_block: t
        for t in recover_state_write_transitions_via_multicell_fixpoint(
            fg, disp, _STATE_OFF, dispatcher_entry_serial=2
        )
    }
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
            10: _blk(
                10,
                (11,),
                (2,),
                (
                    _mov(0x1000, _num(0x12345678), _reg(8)),
                    _mov(0x1004, _num(0x081CC5A1), _reg(9)),
                ),
            ),
            60: _blk(
                60,
                (11,),
                (2,),
                (
                    _mov(0x6000, _num(0x11111111), _reg(8)),
                    _mov(0x6004, _num(0x22222222), _reg(9)),
                ),
            ),
            11: _blk(
                11, (2,), (10, 60), (_xor(0x1100, _reg(8), _reg(9), _stk(_STATE_OFF)),)
            ),
            20: _blk(20, (2,), (2,), ()),
            70: _blk(70, (2,), (2,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _dispatcher(
        {0x10: 10, 0x60: 60, 0x1A2893D9: 20, 0x33333333: 70}, exit_block=99
    )

    prod = recover_state_write_transitions(
        fg, disp, _STATE_OFF, dispatcher_entry_serial=2
    )
    prod_splits = {t.write_block: t for t in prod if t.via_block == 11}
    # Production emits the Case-2 split: blk10->20, blk60->70, both via_block=11.
    assert (
        prod_splits[10].next_state == 0x1A2893D9
        and prod_splits[10].target_handler == 20
    )
    assert (
        prod_splits[60].next_state == 0x33333333
        and prod_splits[60].target_handler == 70
    )

    # Single-partition multi-cell MEETs the conflicting reg consts -> blk11 unresolved.
    multi = {
        t.write_block: t
        for t in recover_state_write_transitions_via_multicell_fixpoint(
            fg, disp, _STATE_OFF, dispatcher_entry_serial=2
        )
    }
    assert multi[11].next_state is None and multi[11].is_return is True

    # Partitioned shadow reproduces the split byte-identically.
    pp_splits = {
        t.write_block: t
        for t in recover_state_write_transitions_via_partitioned_fixpoint(
            fg, disp, _STATE_OFF, dispatcher_entry_serial=2
        )
        if t.via_block == 11
    }
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
    by_block = {
        t.write_block: t
        for t in recover_state_write_transitions_via_partitioned_fixpoint(
            fg, disp, _STATE_OFF, dispatcher_entry_serial=2
        )
    }
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
            10: _blk(
                10,
                (11,),
                (2,),
                (
                    _mov(0x1000, _num(0x12345678), _reg(8)),
                    _mov(0x1004, _num(0x081CC5A1), _reg(9)),
                ),
            ),
            60: _blk(
                60,
                (11,),
                (2,),
                (
                    _mov(0x6000, _num(0x11111111), _reg(8)),
                    _mov(0x6004, _num(0x22222222), _reg(9)),
                ),
            ),
            11: _blk(
                11, (2,), (10, 60), (_xor(0x1100, _reg(8), _reg(9), _stk(_STATE_OFF)),)
            ),
            20: _blk(20, (2,), (2,), ()),
            70: _blk(70, (2,), (2,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _dispatcher(
        {0x10: 10, 0x60: 60, 0x1A2893D9: 20, 0x33333333: 70}, exit_block=99
    )
    splits = {
        t.write_block: t
        for t in recover_state_write_transitions_via_partitioned_fixpoint(
            fg, disp, _STATE_OFF, dispatcher_entry_serial=2
        )
        if t.via_block == 11
    }
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
            10: _blk(
                10,
                (11,),
                (2,),
                (_mov(0x1000, _num(0xF0), _reg(8)), _mov(0x1004, _num(0x0F), _reg(9))),
            ),
            60: _blk(
                60,
                (11,),
                (2,),
                (_mov(0x6000, _num(0x0F), _reg(8)), _mov(0x6004, _num(0xF0), _reg(9))),
            ),
            11: _blk(
                11, (2,), (10, 60), (_xor(0x1100, _reg(8), _reg(9), _stk(_STATE_OFF)),)
            ),
            20: _blk(20, (2,), (2,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _dispatcher({0x10: 10, 0x60: 60, 0xFF: 20}, exit_block=99)
    rows = recover_state_write_transitions_via_partitioned_fixpoint(
        fg, disp, _STATE_OFF, dispatcher_entry_serial=2
    )
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
            2: _blk(2, (11,), (11,), ()),  # dispatcher header, no state write
            11: _blk(11, (2,), (2,), ()),  # back-edge, writes no state
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _dispatcher({}, exit_block=99)
    by_block = {
        t.write_block: t
        for t in recover_state_write_transitions_via_partitioned_fixpoint(
            fg, disp, _STATE_OFF, dispatcher_entry_serial=2
        )
    }
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
            11,
            0x1A2893D9,
            20,
            False,
            None,
            proof=TransitionProof("region_partitioned_fixpoint", "global_fold", True),
        ),
        StateWriteTransition(
            10,
            0x33333333,
            70,
            False,
            None,
            via_block=11,
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
            10: _blk(
                10,
                (2,),
                (2,),
                (
                    _and(0x1000, _stk(_STATE_OFF), _num(0xFFFFFFF0), _reg(8)),
                    _or(0x1004, _reg(8), _num(1), _stk(_STATE_OFF)),
                ),
            ),
            60: _blk(
                60,
                (2,),
                (2,),
                (
                    _and(0x6000, _stk(_STATE_OFF), _num(0xFFFFFFF0), _reg(8)),
                    _or(0x6004, _reg(8), _num(3), _stk(_STATE_OFF)),
                ),
            ),
            20: _blk(20, (90,), (2,), ()),
            70: _blk(70, (91,), (2,), ()),
            90: _stop(90, (20,)),
            91: _stop(91, (70,)),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _dispatcher({0x0: 10, 0x2: 60, 0x1: 20, 0x3: 70}, exit_block=99)

    by_block = {
        t.write_block: t
        for t in recover_state_write_transitions_via_partitioned_fixpoint(
            fg, disp, _STATE_OFF, dispatcher_entry_serial=2
        )
    }
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
    multi = {
        t.write_block: t
        for t in recover_state_write_transitions_via_multicell_fixpoint(
            fg, disp, _STATE_OFF, dispatcher_entry_serial=2
        )
    }
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
            10: _blk(
                10,
                (11,),
                (2,),
                (
                    _and(0x1000, _stk(_STATE_OFF), _num(0xFFFFFFF0), _reg(8)),
                    _or(0x1004, _reg(8), _num(1), _stk(_STATE_OFF)),
                ),
            ),
            60: _blk(
                60,
                (11,),
                (2,),
                (
                    _and(0x6000, _stk(_STATE_OFF), _num(0xFFFFFFF0), _reg(8)),
                    _or(0x6004, _reg(8), _num(3), _stk(_STATE_OFF)),
                ),
            ),
            11: _blk(11, (2,), (10, 60), ()),
            20: _blk(20, (90,), (2,), ()),
            70: _blk(70, (91,), (2,), ()),
            90: _stop(90, (20,)),
            91: _stop(91, (70,)),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _dispatcher({0x0: 10, 0x2: 60, 0x1: 20, 0x3: 70}, exit_block=99)

    splits = {
        t.write_block: t
        for t in recover_state_write_transitions_via_partitioned_fixpoint(
            fg, disp, _STATE_OFF, dispatcher_entry_serial=2
        )
        if t.via_block == 11
    }
    assert splits[10].next_state == 1 and splits[10].target_handler == 20
    assert splits[60].next_state == 3 and splits[60].target_handler == 70
    for wb in (10, 60):
        assert splits[wb].via_block == 11
        assert splits[wb].is_return is False
        assert splits[wb].proof is not None
        assert splits[wb].proof.kind == "region_seeded_partitioned"


_OP_ADD = 12  # m_add


def _add(
    ea: int,
    left: MopSnapshot,
    right: MopSnapshot,
    dst: MopSnapshot,
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=_OP_ADD,
        ea=ea,
        operands=(),
        l=left,
        r=right,
        d=dst,
        kind=InsnKind.ADD,
        value_op_kind=ValueOpKind.ADD,
    )


def test_shared_store_partitions_foldable_edges_despite_one_bottom_pred(
    _seam,
) -> None:
    """One unfoldable incoming edge must not discard the proven partitions.

    VM_DecryptPacket shape: every handler routes its next state through ONE
    shared store block (``state = ecx``).  18 of its 19 predecessors fold to a
    distinct exact constant; a single predecessor is a multi-pred merge whose
    register value is bottom.  Bailing on the whole partition leaves the shared
    store ``unresolved`` -- which severs every handler from the entry component,
    because that store is the only path back to the dispatcher.
    """
    fg = FlowGraph(
        blocks={
            # dispatcher
            2: _blk(2, (10, 20, 30, 70, 80), (40,), ()),
            # foldable handlers: each parks its next state in ecx (reg 24)
            10: _blk(10, (40,), (2,), (_mov(0x1000, _num(0x11), _reg(24)),)),
            20: _blk(20, (40,), (2,), (_mov(0x2000, _num(0x22), _reg(24)),)),
            # bottom handler: ecx = eax + ecx with eax never defined -> ⊥
            30: _blk(30, (40,), (2,), (_add(0x3000, _reg(8), _reg(24), _reg(24)),)),
            # the single shared store block -> back-edge to the dispatcher
            40: _blk(40, (2,), (10, 20, 30), (_mov(0x4000, _reg(24), _stk(_STATE_OFF)),)),
            70: _blk(70, (2,), (2,), ()),
            80: _blk(80, (2,), (2,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _dispatcher({0x11: 70, 0x22: 80}, exit_block=99)

    transitions = recover_state_write_transitions_via_partitioned_fixpoint(
        fg, disp, _STATE_OFF, dispatcher_entry_serial=2
    )
    by_write_block = {int(t.write_block): t for t in transitions}

    # The two foldable predecessors each get their own proven redirect.
    assert set(by_write_block) >= {10, 20}, (
        "expected per-predecessor partitions for the foldable edges, got "
        f"{sorted(by_write_block)}"
    )
    assert by_write_block[10].next_state == 0x11
    assert by_write_block[10].target_handler == 70
    assert by_write_block[10].via_block == 40
    assert by_write_block[10].is_return is False
    assert by_write_block[20].next_state == 0x22
    assert by_write_block[20].target_handler == 80
    assert by_write_block[20].via_block == 40
    assert by_write_block[20].is_return is False

    # The shared store must NOT be collapsed into a single unresolved return.
    unresolved = [
        t
        for t in transitions
        if int(t.write_block) == 40 and t.next_state is None and t.is_return
    ]
    assert not unresolved, "shared store must not fall back to an unresolved return"


def test_shared_store_partitions_through_a_bottom_glue_merge(_seam) -> None:
    """A ⊥ predecessor that is pure state-glue is partitioned one level further.

    VM_DecryptPacket residual: the shared store's ⊥ edge comes from a block doing
    ``ecx = eax + ecx``, itself a merge whose predecessors each set BOTH registers
    to distinct constants.  Partitioning only the shared store's immediate
    predecessors leaves that whole sub-tree on the dispatcher, so its handlers stay
    flattened behind a residual comparison chain.  One more level resolves every
    edge exactly.
    """
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20, 60, 70, 80), (40,), ()),
            10: _blk(
                10,
                (30,),
                (2,),
                (_mov(0x1000, _num(0xA0), _reg(8)), _mov(0x1004, _num(0x0B), _reg(24))),
            ),
            20: _blk(
                20,
                (30,),
                (2,),
                (_mov(0x2000, _num(0xB0), _reg(8)), _mov(0x2004, _num(0x0C), _reg(24))),
            ),
            # ⊥ glue merge: 1-way into the shared store, no constant of its own
            30: _blk(30, (40,), (10, 20), (_add(0x3000, _reg(8), _reg(24), _reg(24)),)),
            40: _blk(40, (2,), (30, 50), (_mov(0x4000, _reg(24), _stk(_STATE_OFF)),)),
            50: _blk(50, (40,), (2,), (_mov(0x5000, _num(0x77), _reg(24)),)),
            60: _blk(60, (2,), (2,), ()),
            70: _blk(70, (2,), (2,), ()),
            80: _blk(80, (2,), (2,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    # 0xA0 + 0x0B = 0xAB ; 0xB0 + 0x0C = 0xBC
    disp = _dispatcher({0xAB: 60, 0xBC: 70, 0x77: 80}, exit_block=99)

    transitions = recover_state_write_transitions_via_partitioned_fixpoint(
        fg, disp, _STATE_OFF, dispatcher_entry_serial=2
    )
    by_write_block = {int(t.write_block): t for t in transitions}

    assert set(by_write_block) >= {10, 20, 50}, (
        "expected the ⊥ glue merge to be partitioned one level up, got "
        f"{sorted(by_write_block)}"
    )
    # transitive: anchored on the grandparent, bypassing the glue block
    assert by_write_block[10].next_state == 0xAB
    assert by_write_block[10].target_handler == 60
    assert by_write_block[10].via_block == 30
    assert by_write_block[20].next_state == 0xBC
    assert by_write_block[20].target_handler == 70
    assert by_write_block[20].via_block == 30
    # the ordinary direct edge is unaffected
    assert by_write_block[50].next_state == 0x77
    assert by_write_block[50].target_handler == 80
    assert by_write_block[50].via_block == 40


def _nested_transitive_merge_fg(*, supported: bool) -> FlowGraph:
    """Real residual shape with the source and handler anchors from WowClassicT.

    ``blk123@0x7FF859C08D35`` computes ``edx = eax ^ (edx - ecx)`` and
    enters ``blk3@0x7FF859C070C0``, which writes the dispatcher state before
    entering ``blk4@0x7FF859C070C4``.  Each source has a distinct concrete
    register environment, so the producer must split the two incoming paths.
    """
    nested = _nested_sub(_reg(10), _reg(9))
    if not supported:
        nested = MopSnapshot(
            t=-1,
            size=4,
            kind=OperandKind.SUBINSN,
            sub_kind=InsnKind.CALL,
            sub_l=_reg(10),
            sub_r=_reg(9),
        )
    return FlowGraph(
        blocks={
            # dispatcher entry blk4@0x7FF859C070C4
            4: _blk(4, (45, 122, 121, 34), (3,), (), ea=0x7FF859C070C4),
            # source blk45@0x7FF859C07656 -> 0x764595C6 -> blk121
            45: _blk(
                45,
                (123,),
                (4,),
                (
                    _mov(0x7FF859C07656, _num(0), _reg(8)),
                    _mov(0x7FF859C0765A, _num(0), _reg(9)),
                    _mov(0x7FF859C0765E, _num(0x764595C6), _reg(10)),
                ),
                ea=0x7FF859C07656,
            ),
            # source blk122@0x7FF859C08BFE -> 0x078CAFFE -> blk34
            122: _blk(
                122,
                (123,),
                (4,),
                (
                    _mov(0x7FF859C08BFE, _num(0), _reg(8)),
                    _mov(0x7FF859C08C02, _num(0), _reg(9)),
                    _mov(0x7FF859C08C06, _num(0x078CAFFE), _reg(10)),
                ),
                ea=0x7FF859C08BFE,
            ),
            # merge blk123@0x7FF859C08D35: edx = eax ^ (edx - ecx)
            123: _blk(
                123,
                (3,),
                (45, 122),
                (_xor(0x7FF859C08D35, _reg(8), nested, _reg(10)),),
                ea=0x7FF859C08D35,
            ),
            # state writer blk3@0x7FF859C070C0 -> dispatcher blk4
            3: _blk(
                3,
                (4,),
                (123,),
                (_mov(0x7FF859C070C0, _reg(10), _stk(_STATE_OFF)),),
                ea=0x7FF859C070C0,
            ),
            # Routed targets are ordinary handlers rather than STOP/default rows.
            121: _blk(121, (4,), (4,), (), ea=0x7FF859C08B37),
            34: _blk(34, (4,), (4,), (), ea=0x7FF859C0747A),
        },
        entry_serial=4,
        func_ea=0x7FF859C06F60,
    )


def test_nested_subinsn_transitive_merge_partitions_real_wowclassic_corridors(
    _seam,
) -> None:
    """A supported nested expression must reach the canonical evaluator.

    This is the regression for the two formerly uncovered corridors:
    ``blk45@0x7FF859C07656 -> blk121@0x7FF859C08B37`` and
    ``blk122@0x7FF859C08BFE -> blk34@0x7FF859C0747A``.  Both bypass
    ``blk123@0x7FF859C08D35`` atomically through the predecessor split.
    """
    transitions = recover_state_write_transitions_via_partitioned_fixpoint(
        _nested_transitive_merge_fg(supported=True),
        _dispatcher({0x764595C6: 121, 0x078CAFFE: 34}, exit_block=99),
        _STATE_OFF,
        dispatcher_entry_serial=4,
    )
    by_source = {
        int(transition.write_block): transition
        for transition in transitions
        if int(transition.via_block or -1) == 123
    }

    assert by_source[45].next_state == 0x764595C6
    assert by_source[45].target_handler == 121
    assert by_source[45].via_block == 123
    assert by_source[45].proof is not None
    assert by_source[45].proof.kind == "transitive_glue_partitioned"
    assert by_source[122].next_state == 0x078CAFFE
    assert by_source[122].target_handler == 34
    assert by_source[122].via_block == 123
    assert by_source[122].proof is not None
    assert by_source[122].proof.kind == "transitive_glue_partitioned"


def test_nested_subinsn_transitive_merge_abstains_for_unsupported_expression(
    _seam,
) -> None:
    """Unsupported nested expression kinds cannot manufacture a bypass route."""
    transitions = recover_state_write_transitions_via_partitioned_fixpoint(
        _nested_transitive_merge_fg(supported=False),
        _dispatcher({0x764595C6: 121, 0x078CAFFE: 34}, exit_block=99),
        _STATE_OFF,
        dispatcher_entry_serial=4,
    )

    assert not {
        int(transition.write_block)
        for transition in transitions
        if int(transition.via_block or -1) == 123
    }


def test_nested_subinsn_temp_namespace_does_not_clobber_low_register_state(
    _seam,
) -> None:
    """A nested TEMP 0 must not rewrite r0 before the later state store.

    The glue expression itself writes r2, but the following state writer reads
    r0.  Before the recovery-local shadow namespace, canonical TEMP 0 shared
    the evaluator's register map with r0 and incorrectly changed each state to
    ``r0 - r1``.
    """
    first_state = 0x764595C6
    second_state = 0x078CAFFE
    nested = _nested_sub(_reg(0), _reg(1))
    fg = FlowGraph(
        blocks={
            4: _blk(4, (45, 122, 121, 34), (3,), (), ea=0x7FF859C070C4),
            45: _blk(
                45,
                (123,),
                (4,),
                (
                    _mov(0x7FF859C07656, _num(first_state), _reg(0)),
                    _mov(0x7FF859C0765A, _num(1), _reg(1)),
                ),
                ea=0x7FF859C07656,
            ),
            122: _blk(
                122,
                (123,),
                (4,),
                (
                    _mov(0x7FF859C08BFE, _num(second_state), _reg(0)),
                    _mov(0x7FF859C08C02, _num(1), _reg(1)),
                ),
                ea=0x7FF859C08BFE,
            ),
            123: _blk(
                123,
                (3,),
                (45, 122),
                (_xor(0x7FF859C08D35, _reg(0), nested, _reg(2)),),
                ea=0x7FF859C08D35,
            ),
            # Later dependent state instruction: must observe the original r0.
            3: _blk(
                3,
                (4,),
                (123,),
                (_mov(0x7FF859C070C0, _reg(0), _stk(_STATE_OFF)),),
                ea=0x7FF859C070C0,
            ),
            121: _blk(121, (4,), (4,), (), ea=0x7FF859C08B37),
            34: _blk(34, (4,), (4,), (), ea=0x7FF859C0747A),
        },
        entry_serial=4,
        func_ea=0x7FF859C06F60,
    )

    transitions = recover_state_write_transitions_via_partitioned_fixpoint(
        fg,
        _dispatcher({first_state: 121, second_state: 34}, exit_block=99),
        _STATE_OFF,
        dispatcher_entry_serial=4,
    )
    by_source = {
        int(transition.write_block): transition
        for transition in transitions
        if int(transition.via_block or -1) == 123
    }

    assert by_source[45].next_state == first_state
    assert by_source[45].target_handler == 121
    assert by_source[122].next_state == second_state
    assert by_source[122].target_handler == 34


def test_glue_partition_rejects_a_merge_whose_inputs_are_unknown(_seam) -> None:
    """Soundness: an unfoldable glue write must not pass a STALE carrier through.

    ``_transfer_snapshot_constant_block`` keeps the previous value when an
    instruction cannot fold, so ``ecx = eax + ecx`` with ``eax`` undefined would
    otherwise be read as the incoming ``ecx`` and produce a wrong route.
    """
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20, 60, 70), (40,), ()),
            # neither handler defines eax -> the glue add cannot fold
            10: _blk(10, (30,), (2,), (_mov(0x1000, _num(0x11), _reg(24)),)),
            20: _blk(20, (30,), (2,), (_mov(0x2000, _num(0x22), _reg(24)),)),
            30: _blk(30, (40,), (10, 20), (_add(0x3000, _reg(8), _reg(24), _reg(24)),)),
            40: _blk(40, (2,), (30, 50), (_mov(0x4000, _reg(24), _stk(_STATE_OFF)),)),
            50: _blk(50, (40,), (2,), (_mov(0x5000, _num(0x77), _reg(24)),)),
            60: _blk(60, (2,), (2,), ()),
            70: _blk(70, (2,), (2,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _dispatcher({0x11: 60, 0x22: 70, 0x77: 80}, exit_block=99)
    transitions = recover_state_write_transitions_via_partitioned_fixpoint(
        fg, disp, _STATE_OFF, dispatcher_entry_serial=2
    )
    by_write_block = {int(t.write_block): t for t in transitions}
    # the stale incoming ecx must NOT be mistaken for the glue block's output
    assert 10 not in by_write_block and 20 not in by_write_block
