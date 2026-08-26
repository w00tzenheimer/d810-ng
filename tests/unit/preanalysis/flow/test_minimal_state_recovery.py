"""Unit tests for the minimal per-handler-write + interval-route recovery.

Pure: synthetic ``FlowGraph`` + ``IntervalDispatcher`` (no IDA).  The MBA fold
runs through a registered portable ``forward_eval_insn`` seam.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

import d810.analyses.control_flow.minimal_state_recovery as minimal_state_recovery
import d810.analyses.control_flow.state_carrier as state_carrier
import d810.analyses.control_flow.state_machine_analysis as state_machine_analysis
import d810.analyses.control_flow.semantic_transition as semantic_transition
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
    transition_uses_terminal_stack_alias_guard,
    transitions_use_terminal_stack_alias_guard,
)
from d810.analyses.control_flow.semantic_transition import (
    StateTransitionResolution,
)
from d810.analyses.control_flow.route_predicate import DecisionDag, RouteComparison
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
from d810.ir.semantics import CallKind, PredicateKind
from d810.ir.varnode import Space, Varnode

_OP_MOV = 4
_OP_XOR = 31
_OP_SUB = 13
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


def _sub(
    ea: int,
    left: MopSnapshot,
    right: MopSnapshot,
    dst: MopSnapshot,
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=_OP_SUB,
        ea=ea,
        operands=(),
        l=left,
        r=right,
        d=dst,
        kind=InsnKind.SUB,
        value_op_kind=ValueOpKind.SUB,
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


def _nested_value(
    operation: ValueOpKind,
    left: MopSnapshot,
    right: MopSnapshot,
) -> MopSnapshot:
    kind = {
        ValueOpKind.ADD: InsnKind.ADD,
        ValueOpKind.SUB: InsnKind.SUB,
    }.get(operation, InsnKind.UNKNOWN)
    return MopSnapshot(
        t=-1,
        size=4,
        kind=OperandKind.SUBINSN,
        sub_kind=kind,
        sub_value_op_kind=operation,
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


def _jle_stack_const(ea: int, stkoff: int, const: int, target: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=0x4A,
        ea=ea,
        operands=(),
        l=_stk(stkoff),
        r=_num(const),
        d=MopSnapshot(t=-1, size=0, block_ref=target, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.SLE,
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


def test_bound_decision_dag_route_replays_reciprocal_internal_alias_edge() -> None:
    dag = DecisionDag(
        32,
        {
            1: RouteComparison(1, "jbe", 0x40, 2, 200),
            3: RouteComparison(3, "jz", 0x20, 201, 202),
        },
        root=1,
        aliases={2: 3},
    )
    blocks = {
        1: _blk(1, (2, 200), (), ()),
        2: _blk(2, (3,), (1,), ()),
        3: _blk(3, (201, 202), (2,), ()),
        200: _blk(200, (), (1,), ()),
        201: _blk(201, (), (3,), ()),
        202: _blk(202, (), (3,), ()),
    }
    graph = FlowGraph(blocks, entry_serial=1, func_ea=0x401000)

    assert minimal_state_recovery._bound_decision_dag_route(
        graph,
        dag,
        0x20,
        root=1,
    ) == (201, (1, 2, 3))

    one_sided = dict(blocks)
    one_sided[3] = replace(one_sided[3], preds=())
    assert (
        minimal_state_recovery._bound_decision_dag_route(
            FlowGraph(one_sided, entry_serial=1, func_ea=0x401000),
            dag,
            0x20,
            root=1,
        )
        is None
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


class _DualRouteDispatcher:
    """Test router carrying independently recoverable exact/range evidence.

    The production router is normally one provider at a time.  The C-shaped
    interval transition tests deliberately expose both providers so the shared
    concrete-state resolver can prove agreement (or fail closed on conflict)
    instead of silently applying the old exact-precedence behavior.
    """

    def __init__(
        self,
        *,
        exact_targets: dict[int, int],
        interval_rows: tuple[IntervalRow, ...],
        default_target: int | None = None,
    ) -> None:
        self._exact_targets = {
            int(state) & 0xFFFFFFFF: int(target)
            for state, target in exact_targets.items()
        }
        self._interval = IntervalDispatcher(list(interval_rows), compute_default=False)
        self.default_target = default_target

    def resolve_target(self, state: int) -> int | None:
        return self._exact_targets.get(int(state) & 0xFFFFFFFF)

    def lookup_row(self, state: int) -> IntervalRow | None:
        return self._interval.lookup_row(int(state) & 0xFFFFFFFF)

    def lookup(self, state: int) -> int | None:
        # This is the legacy precedence behavior the shared resolver must not
        # trust when the exact and interval providers disagree.
        return self.resolve_target(state)

    def all_targets(self) -> set[int]:
        return self._interval.all_targets()


# --- tests ----------------------------------------------------------------


def _native_route_resolution(**overrides) -> StateTransitionResolution:
    assert "source_instruction_ea" in StateTransitionResolution.__dataclass_fields__
    values = {
        "fact_id": "transition:native-bound",
        "source_block_serial": 15,
        "source_state_const_hex": "0x0000000016aa65e9",
        "source_instruction_ea": 0x7FF855576BA0,
        "resolved_next_block_serial": 7,
        "resolved_next_state_const_hex": "0x00000000079323f9",
        "resolved_next_state_const_u64": 0x079323F9,
        "resolution_kind": "state_dispatcher_map",
        "resolution_reason": "resolved_exact_state",
        "state_var_stkoff": 0x3C,
    }
    values.update(overrides)
    return StateTransitionResolution(**values)


def _bind_native_route(resolutions):
    binder = getattr(semantic_transition, "bind_native_bound_transition_routes", None)
    assert callable(binder)
    return binder(
        tuple(resolutions),
        block_serial_for_instruction_ea=lambda ea: {
            0x7FF855576BA0: 42,
        }.get(ea),
        current_block_serials=frozenset({7, 42}),
        dispatcher_block_serials=frozenset({2}),
        route_target_for_state=lambda state: 7,
        state_var_stkoff=0x3C,
    )


def test_native_route_binder_rejects_missing_or_ambiguous_native_rebind() -> None:
    assert (
        _bind_native_route((_native_route_resolution(source_instruction_ea=None),))
        == ()
    )
    binder = getattr(semantic_transition, "bind_native_bound_transition_routes", None)
    assert callable(binder)
    assert (
        binder(
            (_native_route_resolution(),),
            block_serial_for_instruction_ea=lambda _ea: (41, 42),
            current_block_serials=frozenset({7, 41, 42}),
            dispatcher_block_serials=frozenset({2}),
            route_target_for_state=lambda _state: 7,
            state_var_stkoff=0x3C,
        )
        == ()
    )


@pytest.mark.parametrize(
    ("overrides", "current_blocks", "dispatcher_blocks", "route_target", "state_off"),
    (
        ({"resolved_next_block_serial": None}, {7, 42}, {2}, 7, 0x3C),
        ({"resolved_next_block_serial": 2}, {2, 42}, {2}, 2, 0x3C),
        ({"resolved_next_block_serial": 99}, {7, 42}, {2}, 99, 0x3C),
        ({"source_state_const_hex": "0x0000000100000000"}, {7, 42}, {2}, 7, 0x3C),
        ({"state_var_stkoff": 0x40}, {7, 42}, {2}, 7, 0x3C),
        ({"resolved_next_block_serial": 8}, {7, 42}, {2}, 7, 0x3C),
    ),
)
def test_native_route_binder_rejects_fail_closed_route_gates(
    overrides,
    current_blocks,
    dispatcher_blocks,
    route_target,
    state_off,
) -> None:
    binder = getattr(semantic_transition, "bind_native_bound_transition_routes", None)
    assert callable(binder)
    assert (
        binder(
            (_native_route_resolution(**overrides),),
            block_serial_for_instruction_ea=lambda _ea: 42,
            current_block_serials=frozenset(current_blocks),
            dispatcher_block_serials=frozenset(dispatcher_blocks),
            route_target_for_state=lambda _state: route_target,
            state_var_stkoff=state_off,
        )
        == ()
    )


def test_native_route_binder_rejects_conflicting_duplicate_source_evidence() -> None:
    assert (
        _bind_native_route(
            (
                _native_route_resolution(fact_id="transition:a"),
                _native_route_resolution(
                    fact_id="transition:b",
                    resolved_next_block_serial=8,
                ),
            )
        )
        == ()
    )


@pytest.mark.parametrize(
    "resolution_reason",
    ("resolved_exact_state", "resolved_folded_state_write"),
)
def test_native_route_binder_accepts_only_authoritative_resolution_reasons(
    resolution_reason,
) -> None:
    routes = _bind_native_route(
        (_native_route_resolution(resolution_reason=resolution_reason),)
    )
    assert len(routes) == 1


def test_native_route_binder_rejects_fabricated_resolution_reason() -> None:
    assert (
        _bind_native_route(
            (_native_route_resolution(resolution_reason="resolved_not_a_real_reason"),)
        )
        == ()
    )


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


def test_partitioned_fixpoint_resolves_stack_address_alias_state_store(
    _seam, monkeypatch
) -> None:
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

    def unexpected_seeded_fallback(*_args, **_kwargs):
        raise AssertionError(
            "stack alias provider must resolve before seeded discovery"
        )

    monkeypatch.setattr(
        minimal_state_recovery,
        "_resolve_back_edge_states",
        unexpected_seeded_fallback,
    )

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


def test_partitioned_fixpoint_state_route_abstention_is_not_terminal(_seam) -> None:
    """A current-snapshot router miss remains unresolved, not terminal."""
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20), (11,), ()),
            10: _blk(
                10,
                (11,),
                (2,),
                (_mov(0x1000, _num(0x20), _stk(_STATE_OFF)),),
            ),
            11: _blk(11, (2,), (10,), ()),
            20: _blk(20, (), (2,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )

    edges = recover_state_write_transitions_via_partitioned_fixpoint(
        fg,
        _dispatcher({0x20: 20}, exit_block=99),
        _STATE_OFF,
        dispatcher_entry_serial=2,
        state_route_resolver=lambda _state: None,
    )

    assert len(edges) == 1
    assert edges[0].next_state == 0x20
    assert edges[0].target_handler is None
    assert edges[0].is_return is False


def test_partitioned_fixpoint_multi_entry_recovers_nonpredecessor_writer(
    _seam, monkeypatch
) -> None:
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

    seeded_requests: list[frozenset[int] | None] = []

    def counted_seeded_resolver(*args, **kwargs):
        seeded_requests.append(kwargs.get("target_back_edges"))
        return {}

    monkeypatch.setattr(
        minimal_state_recovery,
        "_resolve_back_edge_states",
        counted_seeded_resolver,
    )

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
    assert seeded_requests == []


def test_partitioned_fixpoint_multi_entry_state_reader_never_builds_seeded_map(
    _seam, monkeypatch
) -> None:
    """Upstream multi-entry writers are outside the direct seeded-map key domain."""
    fg = FlowGraph(
        blocks={
            0: _blk(0, (2,), (), ()),
            2: _blk(2, (10, 20), (11,), ()),
            10: _blk(
                10,
                (11,),
                (2,),
                (
                    _and(0x1000, _stk(_STATE_OFF), _num(0xFFFFFFF0), _reg(8)),
                    _or(0x1004, _reg(8), _num(1), _stk(_STATE_OFF)),
                ),
            ),
            11: _blk(11, (2,), (10,), ()),
            20: _blk(20, (90,), (2,), ()),
            90: _stop(90, (20,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    def unexpected_seeded_fallback(*_args, **_kwargs):
        raise AssertionError("multi-entry state reader cannot own a direct seed key")

    monkeypatch.setattr(
        minimal_state_recovery,
        "_resolve_back_edge_states",
        unexpected_seeded_fallback,
    )

    edges = recover_state_write_transitions_via_partitioned_fixpoint(
        fg,
        _dispatcher({0: 10, 1: 20}, exit_block=99),
        _STATE_OFF,
        dispatcher_entry_serial=2,
        include_multi_entry_back_edges=True,
        dispatcher_region_serials=frozenset({11}),
    )

    assert not any(edge.write_block == 10 for edge in edges)


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


def test_partitioned_fixpoint_skips_entry_unreachable_dispatcher_predecessors(
    _seam, monkeypatch
) -> None:
    """A stale root predecessor cannot manufacture an unresolved transition."""
    fg = FlowGraph(
        blocks={
            0: _blk(0, (10,), (), ()),
            2: _blk(2, (20,), (10, 12), ()),
            10: _blk(
                10,
                (2,),
                (0,),
                (_mov(0x1010, _num(0x20), _stk(_STATE_OFF)),),
            ),
            12: _blk(12, (2,), (13,), ()),
            13: _blk(13, (12,), (), ()),
            20: _stop(20, (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    seeded_requests: list[frozenset[int] | None] = []

    def counted_seeded_resolver(*_args, **kwargs):
        seeded_requests.append(kwargs.get("target_back_edges"))
        return {}

    monkeypatch.setattr(
        minimal_state_recovery,
        "_resolve_back_edge_states",
        counted_seeded_resolver,
    )

    recovered = recover_state_write_transitions_via_partitioned_fixpoint(
        fg,
        _dispatcher({0x20: 20}, exit_block=99),
        _STATE_OFF,
        dispatcher_entry_serial=2,
    )

    assert [edge.write_block for edge in recovered] == [10]
    assert recovered[0].target_handler == 20
    assert seeded_requests == []


def test_partitioned_fixpoint_can_include_table_proven_unreachable_predecessors(
    _seam,
) -> None:
    """Indirect tables carry reachability that is absent from the microcode CFG."""
    fg = FlowGraph(
        blocks={
            0: _blk(0, (10,), (), ()),
            2: _blk(2, (20,), (10, 12), ()),
            10: _blk(
                10,
                (2,),
                (0,),
                (_mov(0x1010, _num(0x20), _stk(_STATE_OFF)),),
            ),
            12: _blk(
                12,
                (2,),
                (13,),
                (_mov(0x1020, _num(0x30), _stk(_STATE_OFF)),),
            ),
            13: _blk(13, (12,), (), ()),
            20: _stop(20, (2,)),
            30: _stop(30, (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    recovered = recover_state_write_transitions_via_partitioned_fixpoint(
        fg,
        _dispatcher({0x20: 20, 0x30: 30}, exit_block=99),
        _STATE_OFF,
        dispatcher_entry_serial=2,
        include_entry_unreachable_back_edges=True,
    )

    assert [edge.write_block for edge in recovered] == [10, 12]
    assert [edge.target_handler for edge in recovered] == [20, 30]


def test_partitioned_fixpoint_keeps_reachable_unresolved_dispatcher_predecessors(
    _seam, monkeypatch
) -> None:
    """Reachability filtering must not hide an executable unresolved edge."""
    fg = FlowGraph(
        blocks={
            0: _blk(0, (10, 13), (), ()),
            2: _blk(2, (20,), (10, 12), ()),
            10: _blk(
                10,
                (2,),
                (0,),
                (_mov(0x1010, _num(0x20), _stk(_STATE_OFF)),),
            ),
            12: _blk(12, (2,), (13,), ()),
            13: _blk(13, (12,), (0,), ()),
            20: _stop(20, (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    seeded_requests: list[frozenset[int] | None] = []

    def counted_seeded_resolver(*_args, **kwargs):
        seeded_requests.append(kwargs.get("target_back_edges"))
        return {}

    monkeypatch.setattr(
        minimal_state_recovery,
        "_resolve_back_edge_states",
        counted_seeded_resolver,
    )

    recovered = recover_state_write_transitions_via_partitioned_fixpoint(
        fg,
        _dispatcher({0x20: 20}, exit_block=99),
        _STATE_OFF,
        dispatcher_entry_serial=2,
    )

    assert [edge.write_block for edge in recovered] == [10, 12]
    assert recovered[1].next_state is None
    assert recovered[1].proof is not None
    assert recovered[1].proof.kind == "unresolved"
    assert seeded_requests == [frozenset({12})]


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

    # The guarded alias block is semantic control that owns source7's edge;
    # it is not an internal dispatcher entry merely because its branch also
    # mentions the state cell.  Reconciliation must preserve that typed proof
    # and route its concrete state from the real dispatcher root.
    terminal = fg.get_block(20)
    assert terminal is not None
    routed_graph = FlowGraph(
        {
            **fg.blocks,
            20: replace(terminal, preds=(2, 8)),
        },
        fg.entry_serial,
        fg.func_ea,
    )
    route_dag = DecisionDag(
        32,
        {
            2: RouteComparison(2, "jz", terminal_state, 20, 4),
            8: RouteComparison(8, "jnz", terminal_state, 2, 20),
        },
        root=2,
    )
    sibling = StateWriteTransition(
        7,
        0xD21C9415,
        4,
        False,
        None,
        via_block=8,
        proof=TransitionProof(
            "region_partitioned_fixpoint",
            "multi_entry_global_fold",
            True,
            route_source_kinds=("interval",),
        ),
    )
    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (sibling, edge),
        routed_graph,
        _dispatcher({0xD21C9415: 4, terminal_state: 20}, exit_block=4),
        (),
        condition_chain_dag=route_dag,
        condition_chain_handlers=frozenset({4, 20}),
        state_var_stkoff=_STATE_OFF,
    )
    assert resolved.target_handler == 20
    assert resolved.proof is not None
    assert resolved.proof.trusted is True
    assert transition_uses_terminal_stack_alias_guard(resolved) is True


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


def test_default_compare_corridor_with_valid_next_state_is_recovered(_seam) -> None:
    """The comparison-chain fall-through can be a real handler corridor.

    The default target is not automatically an exit: this corridor computes a
    concrete state and loops back to the dispatcher, so it must remain in the
    recovered handler set.
    """
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20, 30), (10, 20, 31), ()),
            10: _blk(
                10,
                (2,),
                (2,),
                (_mov(0x1000, _num(0x20), _stk(_STATE_OFF)),),
            ),
            20: _blk(20, (2,), (2,), ()),
            30: _blk(30, (31,), (2,), ()),
            31: _blk(
                31,
                (2,),
                (30,),
                (_mov(0x3100, _num(0x20), _stk(_STATE_OFF)),),
            ),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    dispatcher = IntervalDispatcher(
        [
            IntervalRow(0x10, 0x11, 10),
            IntervalRow(0x20, 0x21, 20),
        ],
        default_target=30,
    )

    transitions = {
        transition.handler: transition
        for transition in recover_handler_transitions(
            fg,
            dispatcher,
            _STATE_OFF,
            dispatcher_entry_serial=2,
        )
    }

    assert set(transitions) == {10, 20, 30}
    corridor = transitions[30]
    assert corridor.arms[0].next_state == 0x20
    assert corridor.arms[0].target_handler == 20
    assert corridor.arms[0].is_return is False


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


def test_c3b_global_fold_attaches_trusted_proof(_seam, monkeypatch) -> None:
    """A back-edge that folds unambiguously gets a trusted ``global_fold`` proof."""
    fg = _multicell_xor_fg()
    disp = _dispatcher({0x10: 10, 0x1A2893D9: 20}, exit_block=99)

    def unexpected_seeded_fallback(*_args, **_kwargs):
        raise AssertionError("global fold must resolve before seeded discovery")

    monkeypatch.setattr(
        minimal_state_recovery,
        "_resolve_back_edge_states",
        unexpected_seeded_fallback,
    )
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


def test_c3b_predecessor_partitioned_proof(_seam, monkeypatch) -> None:
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

    def unexpected_seeded_fallback(*_args, **_kwargs):
        raise AssertionError(
            "partitioned provider must resolve before seeded discovery"
        )

    monkeypatch.setattr(
        minimal_state_recovery,
        "_resolve_back_edge_states",
        unexpected_seeded_fallback,
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


def test_c3b_region_agreed_proof(_seam, monkeypatch) -> None:
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

    def unexpected_seeded_fallback(*_args, **_kwargs):
        raise AssertionError("region-agreed provider must resolve before seeding")

    monkeypatch.setattr(
        minimal_state_recovery,
        "_resolve_back_edge_states",
        unexpected_seeded_fallback,
    )
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


def test_emulation_provider_resolves_before_seeded_discovery(
    _seam, monkeypatch
) -> None:
    """The concrete provider is above the expensive region-seeded floor."""
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20), (11,), ()),
            10: _blk(10, (11,), (2,), ()),
            11: _blk(
                11,
                (2,),
                (10,),
                (_xor(0x1100, _reg(8), _reg(9), _stk(_STATE_OFF)),),
            ),
            20: _blk(20, (2,), (2,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )

    def exact_emulation(_ctx, pred, _block, arm, _ambiguous):
        return [
            StateWriteTransition(
                pred,
                0xABCD,
                20,
                False,
                arm,
                proof=TransitionProof(
                    "emulation_concrete_leg",
                    "back_edge_concrete_fold",
                    True,
                ),
            )
        ]

    def unexpected_seeded_fallback(*_args, **_kwargs):
        raise AssertionError("emulation must resolve before seeded discovery")

    monkeypatch.setattr(minimal_state_recovery, "_provider_emulation", exact_emulation)
    monkeypatch.setattr(
        minimal_state_recovery,
        "_resolve_back_edge_states",
        unexpected_seeded_fallback,
    )

    transitions = recover_state_write_transitions_via_partitioned_fixpoint(
        fg,
        _dispatcher({0x10: 10, 0xABCD: 20}, exit_block=99),
        _STATE_OFF,
        dispatcher_entry_serial=2,
    )

    assert len(transitions) == 1
    assert transitions[0].write_block == 11
    assert transitions[0].next_state == 0xABCD
    assert transitions[0].target_handler == 20
    assert transitions[0].proof is not None
    assert transitions[0].proof.oracle_kind == "emulation_concrete_leg"
    assert transitions[0].proof.kind == "back_edge_concrete_fold"


def test_c3b_unresolved_proof_is_untrusted(_seam, monkeypatch) -> None:
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
    seeded_requests: list[frozenset[int] | None] = []

    def abstaining_seeded_fallback(*_args, **kwargs):
        seeded_requests.append(kwargs.get("target_back_edges"))
        return {}

    monkeypatch.setattr(
        minimal_state_recovery,
        "_resolve_back_edge_states",
        abstaining_seeded_fallback,
    )
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
    assert seeded_requests == [frozenset({11})]


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


def test_masked_or_back_edge_resolved_via_region_seed(_seam, monkeypatch) -> None:
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
    real_seeded_resolver = minimal_state_recovery._resolve_back_edge_states
    seeded_requests: list[frozenset[int] | None] = []

    def counted_seeded_resolver(*args, **kwargs):
        seeded_requests.append(kwargs.get("target_back_edges"))
        return real_seeded_resolver(*args, **kwargs)

    monkeypatch.setattr(
        minimal_state_recovery,
        "_resolve_back_edge_states",
        counted_seeded_resolver,
    )

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
    assert seeded_requests == [frozenset({10, 60})]

    # Without the seed the global/multicell fixpoint cannot fold the state-reading
    # writes -> the back-edges are unresolved (proving the seed is what resolves them).
    multi = {
        t.write_block: t
        for t in recover_state_write_transitions_via_multicell_fixpoint(
            fg, disp, _STATE_OFF, dispatcher_entry_serial=2
        )
    }
    assert multi[10].next_state is None and multi[60].next_state is None


def test_demand_seeded_resolution_preserves_direct_transition_order(
    _seam, monkeypatch
) -> None:
    """A deferred lower serial stays before an already-resolved later serial."""
    fg = FlowGraph(
        blocks={
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
                (_mov(0x6000, _num(3), _stk(_STATE_OFF)),),
            ),
            20: _blk(20, (90,), (2,), ()),
            70: _blk(70, (91,), (2,), ()),
            90: _stop(90, (20,)),
            91: _stop(91, (70,)),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    real_seeded_resolver = minimal_state_recovery._resolve_back_edge_states
    requests: list[frozenset[int] | None] = []

    def counted_seeded_resolver(*args, **kwargs):
        requests.append(kwargs.get("target_back_edges"))
        return real_seeded_resolver(*args, **kwargs)

    monkeypatch.setattr(
        minimal_state_recovery,
        "_resolve_back_edge_states",
        counted_seeded_resolver,
    )

    transitions = recover_state_write_transitions_via_partitioned_fixpoint(
        fg,
        _dispatcher({0: 10, 1: 20, 2: 60, 3: 70}, exit_block=99),
        _STATE_OFF,
        dispatcher_entry_serial=2,
    )

    assert requests == [frozenset({10})]
    assert [transition.write_block for transition in transitions] == [10, 60]
    assert [transition.next_state for transition in transitions] == [1, 3]
    assert [transition.proof.kind for transition in transitions] == [
        "region_seeded",
        "global_fold",
    ]


def test_seeded_abstention_preserves_partial_partition_proofs(
    _seam, monkeypatch
) -> None:
    """The deferred tail remains seeded -> partial -> unresolved byte-for-byte."""
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20, 30, 40, 50), (11,), ()),
            10: _blk(10, (11,), (2,), (_mov(0x1000, _num(0x20), _reg(8)),)),
            20: _blk(20, (11,), (2,), (_mov(0x2000, _num(0x30), _reg(8)),)),
            30: _blk(30, (11,), (2,), ()),
            11: _blk(
                11, (2,), (10, 20, 30), (_mov(0x1100, _reg(8), _stk(_STATE_OFF)),)
            ),
            40: _blk(40, (90,), (2,), ()),
            50: _blk(50, (91,), (2,), ()),
            90: _stop(90, (40,)),
            91: _stop(91, (50,)),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    requests: list[frozenset[int] | None] = []

    def abstaining_seeded_resolver(*_args, **kwargs):
        requests.append(kwargs.get("target_back_edges"))
        return {}

    monkeypatch.setattr(
        minimal_state_recovery,
        "_resolve_back_edge_states",
        abstaining_seeded_resolver,
    )

    transitions = recover_state_write_transitions_via_partitioned_fixpoint(
        fg,
        _dispatcher(
            {0x10: 10, 0x11: 20, 0x12: 30, 0x20: 40, 0x30: 50},
            exit_block=99,
        ),
        _STATE_OFF,
        dispatcher_entry_serial=2,
    )

    assert requests == [frozenset({11})]
    partial = [transition for transition in transitions if transition.via_block == 11]
    assert [
        (
            transition.write_block,
            transition.next_state,
            transition.target_handler,
            transition.is_return,
            transition.proof.kind,
        )
        for transition in partial
    ] == [
        (10, 0x20, 40, False, "partial_predecessor_partitioned"),
        (20, 0x30, 50, False, "partial_predecessor_partitioned"),
    ]


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


def test_region_seeded_resolver_projects_each_snapshot_once_per_invocation(
    _seam,
    monkeypatch,
) -> None:
    """Shared/cyclic blocks reuse projection but retain path-local evaluation."""
    source_10 = _mov(0x1010, _num(0x11), _reg(1))
    source_20 = _mov(0x1020, _num(0x21), _reg(1))
    shared = _mov(0x1030, _nested_sub(_reg(1), _num(1)), _reg(2))
    left_write = _mov(0x1034, _reg(2), _stk(_STATE_OFF))
    right_write = _mov(0x1038, _reg(2), _stk(_STATE_OFF))
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20), (40,), ()),
            10: _blk(10, (30,), (2,), (source_10,)),
            20: _blk(20, (30,), (2,), (source_20,)),
            # The two region entries reconverge here.  blk32's edge back to
            # blk30 is a real cycle, but the path-local visited set prevents a
            # revisit through that edge while still exploring blk32 -> blk40.
            30: _blk(30, (31, 32), (10, 20, 32), (shared,)),
            31: _blk(31, (40,), (30,), (left_write,)),
            32: _blk(32, (30, 40), (30,), (right_write,)),
            40: _blk(40, (2,), (31, 32), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    dispatcher = _dispatcher({0: 10, 1: 20}, exit_block=99)
    projected: list[int] = []
    real_project = state_machine_analysis.project_instruction_sequence

    def counted_project(snapshot: InsnSnapshot):
        projected.append(id(snapshot))
        return real_project(snapshot)

    monkeypatch.setattr(
        state_machine_analysis,
        "project_instruction_sequence",
        counted_project,
    )

    expected = {
        40: {
            31: {0x10, 0x20},
            32: {0x10, 0x20},
        }
    }
    first = minimal_state_recovery._resolve_back_edge_states(
        fg,
        dispatcher=dispatcher,
        state_var_stkoff=_STATE_OFF,
        dispatcher_entry=2,
        max_depth=24,
    )
    assert first == expected
    unique_snapshots = {
        id(snapshot)
        for block in fg.blocks.values()
        for snapshot in block.insn_snapshots
    }
    assert set(projected) == unique_snapshots
    assert len(projected) == len(unique_snapshots)

    second = minimal_state_recovery._resolve_back_edge_states(
        fg,
        dispatcher=dispatcher,
        state_var_stkoff=_STATE_OFF,
        dispatcher_entry=2,
        max_depth=24,
    )
    assert second == expected
    assert len(projected) == 2 * len(unique_snapshots)


def test_region_seeded_projection_reuse_preserves_mixed_width_and_unresolved_maps(
    _seam,
    monkeypatch,
) -> None:
    """Projection reuse never shares the path-local constant environments."""
    source_10 = _mov(0x2010, _num(0xFF), replace(_reg(3), size=1))
    source_20 = _mov(0x2020, _num(0xA5A5A5A5), replace(_reg(4), size=8))
    widen = InsnSnapshot(
        opcode=2,
        ea=0x2040,
        operands=(),
        kind=InsnKind.XDU,
        l=replace(_reg(3), size=1),
        d=replace(_reg(4), size=8),
    )
    shared_write = _mov(0x2044, replace(_reg(4), size=4), _stk(_STATE_OFF))
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20), (40,), ()),
            10: _blk(10, (40,), (2,), (source_10,)),
            20: _blk(20, (40,), (2,), (source_20,)),
            40: _blk(40, (2,), (10, 20), (widen, shared_write)),
        },
        entry_serial=10,
        func_ea=0x2000,
    )
    dispatcher = _dispatcher({0: 10, 1: 20}, exit_block=99)
    projected: list[int] = []
    real_project = state_machine_analysis.project_instruction_sequence

    def counted_project(snapshot: InsnSnapshot):
        projected.append(id(snapshot))
        return real_project(snapshot)

    monkeypatch.setattr(
        state_machine_analysis,
        "project_instruction_sequence",
        counted_project,
    )

    result = minimal_state_recovery._resolve_back_edge_states(
        fg,
        dispatcher=dispatcher,
        state_var_stkoff=_STATE_OFF,
        dispatcher_entry=2,
        max_depth=24,
    )
    assert result == {
        40: {
            10: {0xFF},
            # Preserve the legacy unresolved-destination behavior: the XDU
            # cannot resolve reg3 on this path, so reg4's prior value remains.
            20: {0xA5A5A5A5},
        },
    }
    unique_snapshots = {
        id(snapshot)
        for block in fg.blocks.values()
        for snapshot in block.insn_snapshots
    }
    assert set(projected) == unique_snapshots
    assert len(projected) == len(unique_snapshots)


def test_region_seeded_projection_provider_runtime_error_propagates(
    _seam,
    monkeypatch,
) -> None:
    source = _mov(0x3010, _num(0x12), _stk(_STATE_OFF))
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10,), (10,), ()),
            10: _blk(10, (2,), (2,), (source,)),
        },
        entry_serial=10,
        func_ea=0x3000,
    )
    dispatcher = _dispatcher({0: 10}, exit_block=99)

    def fail_projection(_snapshot: InsnSnapshot):
        raise RuntimeError("projection provider failed")

    monkeypatch.setattr(
        state_machine_analysis,
        "project_instruction_sequence",
        fail_projection,
    )

    with pytest.raises(RuntimeError, match="projection provider failed"):
        minimal_state_recovery._resolve_back_edge_states(
            fg,
            dispatcher=dispatcher,
            state_var_stkoff=_STATE_OFF,
            dispatcher_entry=2,
            max_depth=24,
        )


@pytest.mark.parametrize(
    "topology_fault", [None, "missing_source_successor", "missing_destination_pred"]
)
def test_seeded_target_filter_uses_reverse_slice_or_full_legacy_fallback(
    _seam, monkeypatch, topology_fault
) -> None:
    """A filtered walk is trusted only for a fully reciprocal FlowGraph."""
    target_preds = () if topology_fault == "missing_destination_pred" else (11,)
    target_successors = () if topology_fault == "missing_source_successor" else (30,)
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20), (30, 40), ()),
            10: _blk(10, (11,), (2,), ()),
            11: _blk(11, target_successors, (10,), ()),
            30: _blk(
                30,
                (2,),
                target_preds,
                (_mov(0x3010, _num(0x30), _stk(_STATE_OFF)),),
            ),
            20: _blk(20, (21,), (2,), ()),
            21: _blk(21, (40,), (20,), ()),
            40: _blk(
                40,
                (2,),
                (21,),
                (_mov(0x4010, _num(0x40), _stk(_STATE_OFF)),),
            ),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    real_transfer = minimal_state_recovery._transfer_snapshot_constant_block
    visited: list[int] = []

    def counted_transfer(block, *args, **kwargs):
        visited.append(int(block.serial))
        return real_transfer(block, *args, **kwargs)

    monkeypatch.setattr(
        minimal_state_recovery,
        "_transfer_snapshot_constant_block",
        counted_transfer,
    )

    states = minimal_state_recovery._resolve_back_edge_states(
        fg,
        dispatcher=_dispatcher({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE_OFF,
        dispatcher_entry=2,
        max_depth=8,
        target_back_edges=frozenset({30}),
    )

    if topology_fault is None:
        assert set(visited) == {10, 11, 30}
    else:
        assert {20, 21, 40}.issubset(visited)
    assert set(states) <= {30}


def test_seeded_reverse_slice_stops_at_dispatcher_boundary(_seam, monkeypatch) -> None:
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20), (30, 40), ()),
            10: _blk(10, (11,), (2,), ()),
            11: _blk(11, (30,), (10,), ()),
            30: _blk(
                30,
                (2,),
                (11,),
                (_mov(0x3010, _num(0x30), _stk(_STATE_OFF)),),
            ),
            20: _blk(20, (21,), (2,), ()),
            21: _blk(21, (40,), (20,), ()),
            40: _blk(
                40,
                (2,),
                (21,),
                (_mov(0x4010, _num(0x40), _stk(_STATE_OFF)),),
            ),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    real_transfer = minimal_state_recovery._transfer_snapshot_constant_block
    visited: list[int] = []

    def counted_transfer(block, *args, **kwargs):
        visited.append(int(block.serial))
        return real_transfer(block, *args, **kwargs)

    monkeypatch.setattr(
        minimal_state_recovery,
        "_transfer_snapshot_constant_block",
        counted_transfer,
    )

    states = minimal_state_recovery._resolve_back_edge_states(
        fg,
        dispatcher=_dispatcher({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE_OFF,
        dispatcher_entry=2,
        max_depth=8,
        target_back_edges=frozenset({30}),
    )

    assert set(visited) == {10, 11, 30}
    assert states[30] == {11: {0x30}}


def _branching_cyclic_seeded_graph(*, reverse_block_order: bool = False) -> FlowGraph:
    blocks = {
        2: _blk(2, (10,), (30,), ()),
        10: _blk(10, (11, 12), (2,), ()),
        11: _blk(11, (13, 14), (10, 14), ()),
        12: _blk(12, (13, 14), (10, 13), ()),
        13: _blk(13, (12, 30), (11, 12), ()),
        14: _blk(14, (11, 30), (11, 12), ()),
        30: _blk(30, (2,), (13, 14), ()),
    }
    items = list(blocks.items())
    if reverse_block_order:
        items.reverse()
    return FlowGraph(blocks=dict(items), entry_serial=2, func_ea=0x1000)


def test_seeded_dfs_budget_is_exact_and_discards_partial_output(
    _seam, monkeypatch
) -> None:
    """Exactly N pops complete; N-1 fails closed without target evidence."""
    fg = _branching_cyclic_seeded_graph()
    dispatcher = _dispatcher({0x10: 10}, exit_block=99)
    real_transfer = minimal_state_recovery._transfer_snapshot_constant_block
    pops = 0

    def counted_transfer(*args, **kwargs):
        nonlocal pops
        pops += 1
        return real_transfer(*args, **kwargs)

    monkeypatch.setattr(
        minimal_state_recovery,
        "_transfer_snapshot_constant_block",
        counted_transfer,
    )
    expected = minimal_state_recovery._resolve_back_edge_states(
        fg,
        dispatcher=dispatcher,
        state_var_stkoff=_STATE_OFF,
        dispatcher_entry=2,
        max_depth=24,
        target_back_edges=frozenset({30}),
    )
    exact_budget = pops
    assert exact_budget > 8
    assert expected == {30: {13: {0x10}, 14: {0x10}}}

    pops = 0
    assert (
        minimal_state_recovery._resolve_back_edge_states(
            fg,
            dispatcher=dispatcher,
            state_var_stkoff=_STATE_OFF,
            dispatcher_entry=2,
            max_depth=24,
            target_back_edges=frozenset({30}),
            _path_state_pop_budget=exact_budget,
        )
        == expected
    )
    assert pops == exact_budget

    pops = 0
    assert (
        minimal_state_recovery._resolve_back_edge_states(
            fg,
            dispatcher=dispatcher,
            state_var_stkoff=_STATE_OFF,
            dispatcher_entry=2,
            max_depth=24,
            target_back_edges=frozenset({30}),
            _path_state_pop_budget=exact_budget - 1,
        )
        == {}
    )
    assert pops == exact_budget - 1


def test_seeded_dfs_budget_zero_and_one(_seam, monkeypatch) -> None:
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10,), (10,), ()),
            10: _blk(10, (2,), (2,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    dispatcher = _dispatcher({0x10: 10}, exit_block=99)
    real_transfer = minimal_state_recovery._transfer_snapshot_constant_block
    pops = 0

    def counted_transfer(*args, **kwargs):
        nonlocal pops
        pops += 1
        return real_transfer(*args, **kwargs)

    monkeypatch.setattr(
        minimal_state_recovery,
        "_transfer_snapshot_constant_block",
        counted_transfer,
    )

    assert (
        minimal_state_recovery._resolve_back_edge_states(
            fg,
            dispatcher=dispatcher,
            state_var_stkoff=_STATE_OFF,
            dispatcher_entry=2,
            max_depth=1,
            target_back_edges=frozenset({10}),
            _path_state_pop_budget=0,
        )
        == {}
    )
    assert pops == 0

    assert minimal_state_recovery._resolve_back_edge_states(
        fg,
        dispatcher=dispatcher,
        state_var_stkoff=_STATE_OFF,
        dispatcher_entry=2,
        max_depth=1,
        target_back_edges=frozenset({10}),
        _path_state_pop_budget=1,
    ) == {10: {None: {0x10}}}
    assert pops == 1


def test_seeded_dfs_budget_warning_anchors_target_serials_to_eas(
    _seam, monkeypatch
) -> None:
    """Budget diagnostics identify snapshot-local blocks with stable EA anchors."""
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10,), (10,), ()),
            10: _blk(10, (2,), (2,), (), ea=0x1800151E1),
        },
        entry_serial=2,
        func_ea=0x180015110,
    )
    warnings: list[str] = []

    monkeypatch.setattr(
        minimal_state_recovery.logger,
        "warning",
        lambda message, *args: warnings.append(message % args),
    )

    assert (
        minimal_state_recovery._resolve_back_edge_states(
            fg,
            dispatcher=_dispatcher({0x10: 10}, exit_block=99),
            state_var_stkoff=_STATE_OFF,
            dispatcher_entry=2,
            max_depth=1,
            target_back_edges=frozenset({10}),
            _path_state_pop_budget=0,
        )
        == {}
    )
    assert warnings == [
        "region-seeded DFS path-state budget exhausted: "
        "target_back_edges=('blk10@0x1800151E1',) budget=0 consumed=0"
    ]


def test_seeded_dfs_budget_is_atomic_across_multiple_targets(_seam) -> None:
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 20), (30, 40), ()),
            10: _blk(10, (30,), (2,), ()),
            20: _blk(20, (21,), (2,), ()),
            21: _blk(21, (40,), (20,), ()),
            30: _blk(30, (2,), (10,), ()),
            40: _blk(40, (2,), (21,), ()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    dispatcher = _dispatcher({0x10: 10, 0x20: 20}, exit_block=99)
    kwargs = dict(
        dispatcher=dispatcher,
        state_var_stkoff=_STATE_OFF,
        dispatcher_entry=2,
        max_depth=8,
        target_back_edges=frozenset({30, 40}),
    )

    assert minimal_state_recovery._resolve_back_edge_states(
        fg, _path_state_pop_budget=5, **kwargs
    ) == {30: {10: {0x10}}, 40: {21: {0x20}}}
    # The first target was already recorded after two pops, but exhaustion before
    # the fifth pop invalidates the complete seeded proof, not only target 40.
    assert (
        minimal_state_recovery._resolve_back_edge_states(
            fg, _path_state_pop_budget=4, **kwargs
        )
        == {}
    )


def test_seeded_dfs_budget_is_deterministic_across_block_insertion_order(
    _seam,
) -> None:
    dispatcher = _dispatcher({0x10: 10}, exit_block=99)
    kwargs = dict(
        dispatcher=dispatcher,
        state_var_stkoff=_STATE_OFF,
        dispatcher_entry=2,
        max_depth=24,
        target_back_edges=frozenset({30}),
        _path_state_pop_budget=64,
    )

    forward = minimal_state_recovery._resolve_back_edge_states(
        _branching_cyclic_seeded_graph(), **kwargs
    )
    reverse = minimal_state_recovery._resolve_back_edge_states(
        _branching_cyclic_seeded_graph(reverse_block_order=True), **kwargs
    )
    assert reverse == forward == {30: {13: {0x10}, 14: {0x10}}}


@pytest.mark.parametrize("bad_budget", [True, 1.0, "1", object()])
def test_seeded_dfs_budget_rejects_non_integer_values(_seam, bad_budget) -> None:
    with pytest.raises(TypeError, match="path-state pop budget must be an integer"):
        minimal_state_recovery._resolve_back_edge_states(
            _branching_cyclic_seeded_graph(),
            dispatcher=_dispatcher({0x10: 10}, exit_block=99),
            state_var_stkoff=_STATE_OFF,
            dispatcher_entry=2,
            max_depth=24,
            _path_state_pop_budget=bad_budget,
        )


def test_seeded_dfs_budget_rejects_negative_values(_seam) -> None:
    with pytest.raises(ValueError):
        minimal_state_recovery._resolve_back_edge_states(
            _branching_cyclic_seeded_graph(),
            dispatcher=_dispatcher({0x10: 10}, exit_block=99),
            state_var_stkoff=_STATE_OFF,
            dispatcher_entry=2,
            max_depth=24,
            _path_state_pop_budget=-1,
        )


def test_seeded_dfs_budget_does_not_swallow_provider_runtime_errors(
    _seam, monkeypatch
) -> None:
    def fail_transfer(*_args, **_kwargs):
        raise RuntimeError("seeded transfer provider failed")

    monkeypatch.setattr(
        minimal_state_recovery,
        "_transfer_snapshot_constant_block",
        fail_transfer,
    )
    with pytest.raises(RuntimeError, match="seeded transfer provider failed"):
        minimal_state_recovery._resolve_back_edge_states(
            _branching_cyclic_seeded_graph(),
            dispatcher=_dispatcher({0x10: 10}, exit_block=99),
            state_var_stkoff=_STATE_OFF,
            dispatcher_entry=2,
            max_depth=24,
            _path_state_pop_budget=64,
        )


def test_seeded_dfs_default_and_explicit_high_budget_preserve_small_graph_parity(
    _seam,
) -> None:
    fg = _branching_cyclic_seeded_graph()
    kwargs = dict(
        dispatcher=_dispatcher({0x10: 10}, exit_block=99),
        state_var_stkoff=_STATE_OFF,
        dispatcher_entry=2,
        max_depth=24,
        target_back_edges=frozenset({30}),
    )
    default = minimal_state_recovery._resolve_back_edge_states(fg, **kwargs)
    explicit = minimal_state_recovery._resolve_back_edge_states(
        fg, _path_state_pop_budget=64, **kwargs
    )
    assert explicit == default == {30: {13: {0x10}, 14: {0x10}}}


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
            40: _blk(
                40, (2,), (10, 20, 30), (_mov(0x4000, _reg(24), _stk(_STATE_OFF)),)
            ),
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
    """Real residual shape with the source and handler anchors from MMORPG.

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


def test_nested_subinsn_transitive_merge_partitions_real_mmorpg_corridors(
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


def test_back_edge_state_inside_interval_resolves_handler(_seam) -> None:
    """A concrete interval state is a normal handler transition."""
    state = 0x16AA65E9
    fg = FlowGraph(
        blocks={
            2: _blk(2, (10, 13, 99), (10,), (), ea=0x2000),
            10: _blk(10, (2,), (2,), (_mov(0x2010, _num(state), _stk(_STATE_OFF)),)),
            13: _blk(13, (2,), (2,), ()),
            99: _blk(99, (), (2,), (), kind=BlockKind.STOP),
        },
        entry_serial=2,
        func_ea=0x2000,
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(
            IntervalRow(0x079323FA, 0x1888937E, 10),
            IntervalRow(0x1888937E, 0x1888937F, 13),
            IntervalRow(0x1BABC1DC, 0x1BABC1DD, 2),
        ),
        default_target=99,
    )

    transitions = recover_state_write_transitions_via_partitioned_fixpoint(
        fg, dispatcher, _STATE_OFF, dispatcher_entry_serial=2
    )

    transition = next(t for t in transitions if t.write_block == 10)
    assert transition.next_state == state
    assert transition.target_handler == 10
    assert transition.is_return is False
    assert transition.proof is not None
    assert transition.proof.trusted is True


def _typed_state_route_reconciliation_fixture(
    *,
    effectful_normalizer: bool = False,
    effectful_carrier: bool = False,
) -> tuple[FlowGraph, DecisionDag]:
    """A compact target-C dispatcher with one exact state normalizer."""

    call = InsnSnapshot(
        opcode=0x41,
        ea=0x1A00,
        operands=(),
        kind=InsnKind.CALL,
        call_kind=CallKind.DIRECT,
    )
    normalizer_insns = (_mov(0x1200, _num(0x1939CB36), _reg(8)),)
    if effectful_normalizer:
        normalizer_insns += (call,)
    carrier_insns = (_mov(0x1300, _reg(8), _stk(_STATE_OFF)),)
    if effectful_carrier:
        carrier_insns += (_store(0x1301, _num(1), _global(0x140001000)),)
    goto_prefix = InsnSnapshot(
        opcode=55,
        ea=0x1F01,
        operands=(),
        l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=3),
        kind=InsnKind.GOTO,
    )
    graph = FlowGraph(
        blocks={
            2: _blk(2, (3,), (4,), normalizer_insns),
            3: _blk(3, (4,), (2, 14, 15, 16), carrier_insns),
            4: _blk(4, (2, 9), (3,), ()),
            9: _blk(9, (12, 15), (4,), ()),
            10: _blk(10, (3,), (12,), (call,)),
            12: _blk(12, (10, 19), (9,), ()),
            13: _blk(13, (3,), (), (_mov(0x1D00, _num(1), _reg(11)),)),
            14: _blk(
                14,
                (3,),
                (13,),
                (_mov(0x1E00, _num(0x1BABC1DC), _reg(8)), goto_prefix),
            ),
            15: _blk(
                15,
                (3,),
                (9,),
                (_mov(0x1F00, _num(0x6CF816C1), _reg(8)), goto_prefix),
            ),
            16: _blk(
                16,
                (3,),
                (10,),
                (_mov(0x2000, _num(0x079323F9), _reg(8)), goto_prefix),
            ),
            19: _blk(19, (3,), (12,), (call,)),
        },
        entry_serial=3,
        func_ea=0x1000,
    )
    dag = DecisionDag(
        32,
        {
            4: RouteComparison(4, "jz", 0x1BABC1DC, 2, 9),
            9: RouteComparison(9, "jz", 0x079323F9, 15, 12),
            12: RouteComparison(12, "jz", 0x1939CB36, 19, 10),
        },
        root=4,
    )
    return graph, dag


def _coarse_transition(source: int, state: int, target: int) -> StateWriteTransition:
    return StateWriteTransition(
        source,
        state,
        target,
        False,
        None,
        via_block=3,
        proof=TransitionProof(
            "region_partitioned_fixpoint",
            "region_seeded",
            True,
            route_source_kinds=("interval",),
        ),
    )


def test_degenerate_empty_decision_dag_does_not_veto_table_route_authority() -> None:
    """A table dispatcher is not a comparison DAG with a one-node self route."""
    graph = FlowGraph(
        {
            1: _blk(1, (2,), (), (), ea=0x180001670),
            2: _blk(2, (2,), (1, 2), (), ea=0x180001688),
            20: _blk(20, (), (), (), ea=0x180001700),
        },
        entry_serial=1,
        func_ea=0x180001670,
    )
    transition = StateWriteTransition(
        1,
        0,
        20,
        False,
        None,
        proof=TransitionProof(
            "region_partitioned_fixpoint",
            "global_fold",
            True,
            route_source_kinds=("switch_table",),
        ),
    )

    resolved = resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        _dispatcher({0: 20}, exit_block=99),
        (),
        condition_chain_dag=DecisionDag(32, {}, root=2),
        condition_chain_handlers=frozenset({20}),
        state_var_stkoff=_STATE_OFF,
    )

    assert resolved == (transition,)


def test_decision_dag_reconciliation_preserves_exact_terminal_without_state() -> None:
    graph = FlowGraph(
        {
            2: _blk(2, (20, 30), (), (), ea=0x180001A90),
            5: _blk(5, (99,), (), (), ea=0x180001AB9),
            20: _blk(20, (), (2,), (), ea=0x180001B20),
            30: _blk(30, (), (2,), (), ea=0x180001B30),
            99: _stop(99, (5,)),
        },
        entry_serial=2,
        func_ea=0x180001A80,
    )
    dag = DecisionDag(
        32,
        {2: RouteComparison(2, "jz", 0xF6A1E, 20, 30)},
        root=2,
    )
    transition = StateWriteTransition(
        5,
        None,
        None,
        True,
        None,
        proof=TransitionProof(
            "region_partitioned_fixpoint",
            "terminal",
            True,
        ),
    )

    resolved = resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        _dispatcher({}, exit_block=99),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({20, 30}),
        state_var_stkoff=_STATE_OFF,
    )

    assert resolved == (transition,)


def test_nonreturn_coarse_target_is_reconciled_to_exact_state_route() -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    transition = _coarse_transition(16, 0x079323F9, 13)

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        _dispatcher({}, exit_block=99),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({13, 15}),
    )

    assert resolved.target_handler == 15
    assert resolved.proof is not None
    assert resolved.proof.oracle_kind == "decision_dag_state_route_reconciliation"
    assert resolved.proof.kind == "decision_dag_reconciled"
    assert resolved.proof.route_source_kinds == ("decision_dag",)


def test_exact_state_normalizer_chain_routes_to_semantic_destination() -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    transition = _coarse_transition(14, 0x1BABC1DC, 13)

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        _dispatcher({}, exit_block=99),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({2, 13, 15, 19}),
        state_var_stkoff=_STATE_OFF,
    )

    assert resolved.target_handler == 19
    assert resolved.is_return is False


def test_recovered_semantic_handler_is_not_reclassified_as_invalid_normalizer() -> (
    None
):
    """A semantic handler may end with the shared next-state carrier shape.

    Target B has several handlers whose real computation precedes a final
    ``CONST -> carrier -> state -> DAG`` suffix.  The suffix resembles a
    normalizer, but the same fragment independently recovers the leaf as a
    transition source.  Keep the incoming route at that handler and reconcile
    the handler's own outgoing transition separately.
    """

    graph, dag = _typed_state_route_reconciliation_fixture()
    semantic_leaf = graph.get_block(2)
    assert semantic_leaf is not None
    graph = FlowGraph(
        {
            **graph.blocks,
            2: replace(
                semantic_leaf,
                insn_snapshots=(
                    _add(0x11F0, _reg(20), _reg(21), _reg(22)),
                    _mov(0x1200, _num(0x1939CB36), _reg(8)),
                ),
            ),
        },
        graph.entry_serial,
        graph.func_ea,
    )
    incoming = _coarse_transition(14, 0x1BABC1DC, 2)
    outgoing = _coarse_transition(2, 0x1939CB36, 19)

    resolved = resolve_materialized_indirect_transfer_targets(
        (incoming, outgoing),
        graph,
        _dispatcher({}, exit_block=99),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({2, 13, 15, 19}),
        state_var_stkoff=_STATE_OFF,
    )

    assert tuple(int(row.write_block) for row in resolved) == (14, 2)
    assert tuple(int(row.target_handler) for row in resolved) == (2, 19)


def test_valid_normalizer_still_chains_when_it_is_also_a_transition_source() -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    incoming = _coarse_transition(14, 0x1BABC1DC, 2)
    normalizer_row = _coarse_transition(2, 0x1939CB36, 19)

    resolved = resolve_materialized_indirect_transfer_targets(
        (incoming, normalizer_row),
        graph,
        _dispatcher({}, exit_block=99),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({2, 13, 15, 19}),
        state_var_stkoff=_STATE_OFF,
    )

    assert tuple(int(row.target_handler) for row in resolved) == (19, 19)


def test_outside_interval_routes_through_surviving_effectful_handler() -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    transition = _coarse_transition(15, 0x6CF816C1, 15)

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        _dispatcher({}, exit_block=99),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({2, 13, 15}),
    )

    assert resolved.target_handler == 10
    assert graph.get_block(10).insn_snapshots[0].is_call


def test_source_carrier_route_accepts_reciprocal_alias_chain_to_stop_sentinel() -> None:
    """Target C's upper interval ends through pure aliases at Hex-Rays STOP."""
    graph, _ = _typed_state_route_reconciliation_fixture()
    blocks = dict(graph.blocks)
    blocks[4] = replace(blocks[4], succs=(5, 9))
    blocks[5] = _blk(5, (6, 12), (4,), (), ea=0x180044988)
    blocks[6] = _blk(6, (7, 2), (5,), (), ea=0x180044993)
    blocks[7] = _blk(7, (17,), (6,), (), ea=0x18004499A)
    blocks[17] = _blk(17, (20,), (7,), (), ea=0x180044C2C)
    blocks[20] = replace(
        _stop(20, (17,)),
        start_ea=0xFFFFFFFFFFFFFFFF,
    )
    blocks[2] = replace(blocks[2], preds=(6,))
    blocks[9] = replace(blocks[9], preds=(4,))
    blocks[12] = replace(blocks[12], preds=(5,))
    graph = FlowGraph(blocks, graph.entry_serial, graph.func_ea)
    dag = DecisionDag(
        32,
        {
            4: RouteComparison(4, "jle", 0x1888937D, 9, 5),
            5: RouteComparison(5, "jle", 0x1BABC1DB, 12, 6),
            6: RouteComparison(6, "jz", 0x1BABC1DC, 2, 7),
            9: RouteComparison(9, "jz", 0x079323F9, 15, 10),
            12: RouteComparison(12, "jnz", 0x1888937E, 19, 13),
        },
        root=4,
        aliases={7: 17, 17: 20},
    )

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (_coarse_transition(15, 0x6CF816C1, 20),),
        graph,
        _dispatcher({}, exit_block=99),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({2, 10, 13, 15, 19}),
        state_var_stkoff=_STATE_OFF,
    )

    assert resolved.target_handler == 20
    assert resolved.is_return is True
    assert resolved.proof is not None
    assert resolved.proof.trusted is True

    nonterminal_blocks = dict(graph.blocks)
    nonterminal_blocks[20] = replace(
        nonterminal_blocks[20],
        kind=BlockKind.ZERO_WAY,
    )
    assert (
        minimal_state_recovery.route_current_u32_decision_forest(
            FlowGraph(nonterminal_blocks, graph.entry_serial, graph.func_ea),
            dag,
            0x6CF816C1,
            entry_serial=4,
        )
        is None
    )

    one_sided_blocks = dict(graph.blocks)
    one_sided_blocks[20] = replace(one_sided_blocks[20], preds=())
    assert (
        minimal_state_recovery.route_current_u32_decision_forest(
            FlowGraph(one_sided_blocks, graph.entry_serial, graph.func_ea),
            dag,
            0x6CF816C1,
            entry_serial=4,
        )
        is None
    )


@pytest.mark.parametrize(
    ("source", "expected_state", "expected_target"),
    (
        (2, 0x1939CB36, 19),
        (15, 0x6CF816C1, 10),
        (16, 0x079323F9, 15),
    ),
)
def test_missing_transition_state_is_recovered_from_exact_source_carrier(
    source: int,
    expected_state: int,
    expected_target: int,
) -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    unresolved = StateWriteTransition(
        source,
        None,
        None,
        False,
        None,
        via_block=None,
        proof=TransitionProof(
            "region_partitioned_fixpoint",
            "unresolved",
            False,
        ),
    )

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (unresolved,),
        graph,
        _dispatcher({}, exit_block=99),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({2, 10, 15, 19}),
        state_var_stkoff=_STATE_OFF,
    )

    assert resolved.next_state == expected_state
    assert resolved.target_handler == expected_target
    assert resolved.via_block == 3
    assert resolved.proof is not None
    assert resolved.proof.oracle_kind == "exact_source_carrier_decision_dag_route"
    assert resolved.proof.kind == "source_carrier_decision_dag_reconciled"
    assert resolved.proof.route_source_kinds == ("decision_dag", "source_carrier")


def test_missing_transition_state_is_recovered_from_exact_stack_carrier() -> None:
    """A pure local stack alias is an exact carrier, not the state cell itself."""

    graph, dag = _typed_state_route_reconciliation_fixture()
    carrier = _stk(_STATE_OFF + 0x100)
    feeder = graph.get_block(3)
    source = graph.get_block(15)
    assert feeder is not None and source is not None
    graph = FlowGraph(
        {
            **graph.blocks,
            3: replace(
                feeder,
                insn_snapshots=(
                    _mov(0x1300, carrier, _stk(_STATE_OFF)),
                ),
            ),
            15: replace(
                source,
                insn_snapshots=(
                    _mov(0x1F00, _num(0x6CF816C1), carrier),
                    source.insn_snapshots[1],
                ),
            ),
        },
        graph.entry_serial,
        graph.func_ea,
    )

    (resolved,) = _resolve_carrier_transition(
        graph,
        dag,
        _unresolved_carrier_transition(15),
    )

    assert resolved.next_state == 0x6CF816C1
    assert resolved.target_handler == 10
    assert resolved.proof is not None
    assert resolved.proof.route_source_kinds == ("decision_dag", "source_carrier")


def test_stack_carrier_enters_reciprocal_decision_dag_alias() -> None:
    """OLLVM carriers may enter a pure alias before the comparison root."""

    graph, dag = _typed_state_route_reconciliation_fixture()
    carrier = _stk(_STATE_OFF + 0x100)
    feeder = graph.get_block(3)
    source = graph.get_block(15)
    root = graph.get_block(4)
    assert feeder is not None and source is not None and root is not None
    graph = FlowGraph(
        {
            **graph.blocks,
            3: replace(
                feeder,
                succs=(17,),
                insn_snapshots=(
                    _mov(0x1300, carrier, _stk(_STATE_OFF)),
                ),
            ),
            4: replace(root, preds=(17,)),
            15: replace(
                source,
                insn_snapshots=(
                    _mov(0x1F00, _num(0x6CF816C1), carrier),
                    source.insn_snapshots[1],
                ),
            ),
            17: _blk(17, (4,), (3,), (), ea=0x180011840),
        },
        graph.entry_serial,
        graph.func_ea,
    )
    dag = DecisionDag(32, dag.nodes, root=dag.root, aliases={17: 4})

    (resolved,) = _resolve_carrier_transition(
        graph,
        dag,
        _unresolved_carrier_transition(15),
    )

    assert resolved.next_state == 0x6CF816C1
    assert resolved.target_handler == 10
    assert resolved.via_block == 3
    assert resolved.proof is not None
    assert resolved.proof.route_source_kinds == ("decision_dag", "source_carrier")


def test_state_cell_cannot_alias_itself_as_a_source_carrier() -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    feeder = graph.get_block(3)
    source = graph.get_block(15)
    assert feeder is not None and source is not None
    graph = FlowGraph(
        {
            **graph.blocks,
            3: replace(
                feeder,
                insn_snapshots=(
                    _mov(0x1300, _stk(_STATE_OFF), _stk(_STATE_OFF)),
                ),
            ),
            15: replace(
                source,
                insn_snapshots=(
                    _mov(0x1F00, _num(0x6CF816C1), _stk(_STATE_OFF)),
                    source.insn_snapshots[1],
                ),
            ),
        },
        graph.entry_serial,
        graph.func_ea,
    )

    assert (
        _resolve_carrier_transition(
            graph,
            dag,
            _unresolved_carrier_transition(15),
        )
        == ()
    )


def _unresolved_carrier_transition(source: int = 15) -> StateWriteTransition:
    return StateWriteTransition(
        source,
        None,
        None,
        False,
        None,
        via_block=None,
        proof=TransitionProof(
            "region_partitioned_fixpoint",
            "unresolved",
            False,
        ),
    )


def _resolve_carrier_transition(
    graph: FlowGraph,
    dag: DecisionDag,
    transition: StateWriteTransition,
) -> tuple[StateWriteTransition, ...]:
    return resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        _dispatcher({}, exit_block=99),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({2, 10, 15, 19}),
        state_var_stkoff=_STATE_OFF,
    )


def test_untrusted_source_carrier_state_disagreement_abstains_atomically() -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    conflicting = replace(
        _unresolved_carrier_transition(15),
        next_state=0x079323F9,
        target_handler=15,
    )
    assert conflicting.proof is not None and not conflicting.proof.trusted

    assert _resolve_carrier_transition(graph, dag, conflicting) == ()


def test_weak_region_seeded_state_is_superseded_by_exact_source_carrier() -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    coarse = replace(
        _coarse_transition(14, 0x1888937E, 13),
        via_block=None,
    )

    (resolved,) = _resolve_carrier_transition(graph, dag, coarse)

    assert resolved.next_state == 0x1BABC1DC
    assert resolved.target_handler == 19
    assert resolved.via_block == 3
    assert resolved.proof is not None
    assert resolved.proof.oracle_kind == "exact_source_carrier_decision_dag_route"
    assert resolved.proof.kind == "source_carrier_decision_dag_reconciled"
    assert resolved.proof.route_source_kinds == ("decision_dag", "source_carrier")
    assert (
        resolved.proof.reason == "exact_source_carrier_u32;decision_dag_final_route;"
        "superseded=region_partitioned_fixpoint:region_seeded:interval"
    )


@pytest.mark.parametrize(
    "proof",
    (
        None,
        TransitionProof(
            "region_partitioned_fixpoint",
            "region_seeded",
            False,
            route_source_kinds=("interval",),
        ),
        TransitionProof(
            "native_bound_transition_route",
            "native_bound_route",
            True,
            route_source_kinds=("native_bound",),
        ),
        TransitionProof(
            "materialized_indirect_transfer",
            "computed_goto_materialized",
            True,
            route_source_kinds=("materialized",),
        ),
        TransitionProof(
            "region_partitioned_fixpoint",
            "global_fold",
            True,
            route_source_kinds=("exact",),
        ),
        TransitionProof(
            "unknown_oracle",
            "unknown_kind",
            True,
            route_source_kinds=(),
        ),
        TransitionProof(
            "region_partitioned_fixpoint",
            "region_seeded",
            True,
            route_source_kinds=("exact", "interval"),
        ),
    ),
    ids=(
        "missing",
        "untrusted",
        "native-bound",
        "materialized",
        "exact-fold",
        "unknown",
        "mixed-sources",
    ),
)
def test_strong_or_malformed_state_disagreement_remains_atomic_conflict(
    proof: TransitionProof | None,
) -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    conflicting = replace(
        _coarse_transition(14, 0x1888937E, 13),
        via_block=None,
        proof=proof,
    )

    assert _resolve_carrier_transition(graph, dag, conflicting) == ()


def test_source_carrier_allows_effect_before_final_overwrite() -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    source = graph.get_block(15)
    assert source is not None
    call = InsnSnapshot(
        opcode=0x41,
        ea=0x1EFF,
        operands=(),
        kind=InsnKind.CALL,
        call_kind=CallKind.DIRECT,
    )
    graph = FlowGraph(
        blocks={
            **graph.blocks,
            15: replace(source, insn_snapshots=(call, *source.insn_snapshots)),
        },
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )

    (resolved,) = _resolve_carrier_transition(
        graph,
        dag,
        _unresolved_carrier_transition(15),
    )

    assert resolved.next_state == 0x6CF816C1
    assert resolved.target_handler == 10


def test_source_carrier_uses_final_exact_overwrite_after_earlier_definitions() -> None:
    """Earlier carrier values are dead once the outgoing value is exact."""

    graph, dag = _typed_state_route_reconciliation_fixture()
    source = graph.get_block(15)
    assert source is not None
    graph = FlowGraph(
        blocks={
            **graph.blocks,
            15: replace(
                source,
                insn_snapshots=(
                    _mov(0x1EFE, _num(0xDEADBEEF), _reg(8)),
                    *source.insn_snapshots,
                ),
            ),
        },
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )

    (resolved,) = _resolve_carrier_transition(
        graph,
        dag,
        _unresolved_carrier_transition(15),
    )

    assert resolved.next_state == 0x6CF816C1
    assert resolved.target_handler == 10
    assert resolved.proof is not None
    assert resolved.proof.route_source_kinds == ("decision_dag", "source_carrier")


def test_direct_state_write_through_goto_bridge_is_not_a_carrier_candidate() -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    source = graph.get_block(16)
    feeder = graph.get_block(3)
    assert source is not None and feeder is not None
    goto_feeder = InsnSnapshot(
        opcode=55,
        ea=0x1300,
        operands=(),
        l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=4),
        kind=InsnKind.GOTO,
    )
    graph = FlowGraph(
        blocks={
            **graph.blocks,
            16: replace(
                source,
                insn_snapshots=(
                    _mov(0x2000, _num(0x079323F9), _stk(_STATE_OFF)),
                    source.insn_snapshots[1],
                ),
            ),
            3: replace(feeder, insn_snapshots=(goto_feeder,)),
        },
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )

    transition = _coarse_transition(16, 0x079323F9, 13)
    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        _dispatcher({}, exit_block=99),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({2, 10, 13, 15, 19}),
        state_var_stkoff=_STATE_OFF,
    )

    assert resolved.target_handler == 15


def test_state_writing_feeder_without_source_carrier_uses_recovered_route() -> None:
    """A state-writing feeder alone is not an exact source-carrier corridor."""

    graph, dag = _typed_state_route_reconciliation_fixture()
    source = graph.get_block(16)
    feeder = graph.get_block(3)
    assert source is not None and feeder is not None
    goto_feeder = InsnSnapshot(
        opcode=55,
        ea=0x2000,
        operands=(),
        l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=3),
        kind=InsnKind.GOTO,
    )
    graph = FlowGraph(
        blocks={
            **graph.blocks,
            16: replace(source, insn_snapshots=(goto_feeder,)),
            3: replace(
                feeder,
                insn_snapshots=(
                    _mov(0x1300, _num(0x079323F9), _stk(_STATE_OFF)),
                ),
            ),
        },
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )

    transition = _coarse_transition(16, 0x079323F9, 13)
    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        _dispatcher({}, exit_block=99),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({2, 10, 13, 15, 19}),
        state_var_stkoff=_STATE_OFF,
    )

    assert resolved.target_handler == 15
    assert resolved.proof is not None
    assert resolved.proof.kind == "decision_dag_reconciled"


def test_trusted_route_with_nonexact_transform_feeder_rejects_atomically() -> None:
    """A trusted route hint cannot replace exact transform authority."""

    graph, dag = _typed_state_route_reconciliation_fixture()
    source = graph.get_block(16)
    feeder = graph.get_block(3)
    assert source is not None and feeder is not None
    graph = FlowGraph(
        blocks={
            **graph.blocks,
            16: replace(
                source,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=55,
                        ea=0x2000,
                        operands=(),
                        l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=3),
                        kind=InsnKind.GOTO,
                    ),
                ),
            ),
            3: replace(
                feeder,
                insn_snapshots=(
                    _xor(0x1300, _reg(8), _reg(24), _stk(_STATE_OFF)),
                ),
            ),
        },
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )
    transition = replace(
        _coarse_transition(16, 0x079323F9, 15),
        proof=TransitionProof(
            "region_partitioned_fixpoint",
            "predecessor_partitioned",
            True,
            route_source_kinds=("interval",),
        ),
    )

    assert resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        _dispatcher({}, exit_block=99),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({2, 10, 13, 15, 19}),
        state_var_stkoff=_STATE_OFF,
    ) == ()


@pytest.mark.parametrize(
    "variant",
    (
        "absent_constant",
        "wrong_width",
        "wrong_carrier",
        "carrier_clobber",
        "goto_before_assignment",
        "call_after_constant",
        "unknown_expression",
        "effectful_feeder",
        "feeder_fork",
        "wrong_feeder_successor",
        "state_identity_mismatch",
    ),
)
def test_malformed_source_carrier_transition_abstains_atomically(
    variant: str,
) -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    source = graph.get_block(15)
    feeder = graph.get_block(3)
    assert source is not None and feeder is not None
    source_insns = source.insn_snapshots
    feeder_insns = feeder.insn_snapshots
    source_succs = source.succs
    feeder_succs = feeder.succs

    if variant == "absent_constant":
        source_insns = source_insns[1:]
    elif variant == "wrong_width":
        write = source_insns[0]
        source_insns = (
            replace(
                write,
                l=replace(write.l, size=8),
                d=replace(write.d, size=8),
            ),
            *source_insns[1:],
        )
    elif variant == "wrong_carrier":
        write = feeder_insns[0]
        feeder_insns = (replace(write, l=_reg(9)),)
    elif variant == "carrier_clobber":
        clobber = _mov(0x1F01, _stk(_STATE_OFF + 4), _reg(8))
        source_insns = (source_insns[0], clobber, *source_insns[1:])
    elif variant == "goto_before_assignment":
        source_insns = (source_insns[1], *source_insns)
    elif variant == "call_after_constant":
        call = InsnSnapshot(
            opcode=0x41,
            ea=0x1F01,
            operands=(),
            kind=InsnKind.CALL,
            call_kind=CallKind.DIRECT,
        )
        source_insns = (source_insns[0], call, *source_insns[1:])
    elif variant == "unknown_expression":
        write = source_insns[0]
        nested_call = MopSnapshot(
            t=-1,
            size=4,
            kind=OperandKind.SUBINSN,
            sub_kind=InsnKind.CALL,
        )
        source_insns = (replace(write, l=nested_call), *source_insns[1:])
    elif variant == "effectful_feeder":
        feeder_insns = (*feeder_insns, _store(0x1301, _num(1), _global(0x140001000)))
    elif variant == "feeder_fork":
        feeder_succs = (4, 10)
    elif variant == "wrong_feeder_successor":
        feeder_succs = (10,)
    elif variant == "state_identity_mismatch":
        write = feeder_insns[0]
        feeder_insns = (replace(write, d=_stk(_STATE_OFF + 4)),)

    graph = FlowGraph(
        blocks={
            **graph.blocks,
            15: replace(source, insn_snapshots=source_insns, succs=source_succs),
            3: replace(feeder, insn_snapshots=feeder_insns, succs=feeder_succs),
        },
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )

    assert (
        _resolve_carrier_transition(
            graph,
            dag,
            _unresolved_carrier_transition(15),
        )
        == ()
    )


def test_conflicting_exact_materialized_and_interval_routes_abstain_atomically() -> (
    None
):
    graph, dag = _typed_state_route_reconciliation_fixture()
    transitions = (
        _coarse_transition(16, 0x079323F9, 13),
        _coarse_transition(15, 0x6CF816C1, 15),
    )

    resolved = resolve_materialized_indirect_transfer_targets(
        transitions,
        graph,
        _dispatcher({}, exit_block=99),
        (),
        materialized_state_routes=(MaterializedStateRoute(16, 0x079323F9, 13),),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({2, 13, 15}),
    )

    assert resolved == ()


def test_native_bound_route_conflicting_with_exact_dag_abstains_atomically() -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    transition = StateWriteTransition(
        16,
        0x079323F9,
        13,
        False,
        None,
        via_block=3,
        proof=TransitionProof(
            "native_bound_transition_route",
            "native_bound_route",
            True,
        ),
    )

    assert (
        resolve_materialized_indirect_transfer_targets(
            (transition,),
            graph,
            _dispatcher({}, exit_block=99),
            (),
            condition_chain_dag=dag,
            condition_chain_handlers=frozenset({2, 13, 15}),
        )
        == ()
    )


def test_native_bound_route_agreeing_with_final_dag_leaf_preserves_proof() -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    proof = TransitionProof(
        "native_bound_transition_route",
        "native_bound_route",
        True,
        reason="fact_id=native-16;native_ea=0x2000",
    )
    transition = replace(
        _coarse_transition(16, 0x079323F9, 15),
        proof=proof,
    )

    assert resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        _dispatcher({}, exit_block=99),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({2, 13, 15}),
    ) == (transition,)


def test_native_bound_intermediate_normalizer_gets_truthful_reconciliation_proof() -> (
    None
):
    graph, dag = _typed_state_route_reconciliation_fixture()
    transition = replace(
        _coarse_transition(14, 0x1BABC1DC, 2),
        proof=TransitionProof(
            "native_bound_transition_route",
            "native_bound_route",
            True,
            reason="fact_id=native-14;native_ea=0x1E00",
        ),
    )

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        _dispatcher({}, exit_block=99),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({2, 13, 15, 19}),
        state_var_stkoff=_STATE_OFF,
    )

    assert resolved.target_handler == 19
    assert resolved.proof is not None
    assert resolved.proof.oracle_kind == "decision_dag_state_route_reconciliation"
    assert resolved.proof.kind == "decision_dag_reconciled"
    assert "native_bound" in resolved.proof.route_source_kinds
    assert "fact_id=native-14" in resolved.proof.reason


def test_materialized_proof_agreeing_with_final_dag_leaf_is_preserved() -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    transition = replace(
        _coarse_transition(16, 0x079323F9, 15),
        proof=TransitionProof(
            "region_partitioned_fixpoint",
            "computed_goto_state_route",
            True,
            reason="resolver_proven_materialized_state_route",
            route_source_kinds=("materialized",),
        ),
    )

    assert resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        _dispatcher({}, exit_block=99),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({2, 13, 15}),
    ) == (transition,)


def test_forged_dag_edge_absent_from_source_graph_abstains() -> None:
    graph, _dag = _typed_state_route_reconciliation_fixture()
    forged_dag = DecisionDag(
        32,
        {
            4: RouteComparison(4, "jz", 0x1BABC1DC, 2, 9),
            9: RouteComparison(9, "jz", 0x079323F9, 13, 12),
            12: RouteComparison(12, "jz", 0x1939CB36, 19, 10),
        },
        root=4,
    )

    assert (
        resolve_materialized_indirect_transfer_targets(
            (_coarse_transition(16, 0x079323F9, 13),),
            graph,
            _dispatcher({}, exit_block=99),
            (),
            condition_chain_dag=forged_dag,
            condition_chain_handlers=frozenset({2, 10, 13, 15, 19}),
        )
        == ()
    )


def test_non_u32_decision_dag_abstains() -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    wide_dag = DecisionDag(64, dag.nodes, root=dag.root)

    assert (
        resolve_materialized_indirect_transfer_targets(
            (_coarse_transition(16, 0x079323F9, 13),),
            graph,
            _dispatcher({}, exit_block=99),
            (),
            condition_chain_dag=wide_dag,
            condition_chain_handlers=frozenset({2, 10, 13, 15, 19}),
        )
        == ()
    )


def test_const_write_plus_goto_leaf_remains_semantic() -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    leaf = graph.get_block(15)
    assert leaf is not None
    assert len(leaf.insn_snapshots) == 2
    assert leaf.insn_snapshots[0].kind is InsnKind.MOV
    assert leaf.insn_snapshots[1].kind is InsnKind.GOTO

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (_coarse_transition(16, 0x079323F9, 13),),
        graph,
        _dispatcher({}, exit_block=99),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({2, 13, 15}),
    )

    assert resolved.target_handler == 15


def test_exact_and_interval_route_conflict_with_dag_abstains_atomically() -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    state = 0x079323F9
    dispatcher = _DualRouteDispatcher(
        exact_targets={state: 15},
        interval_rows=(IntervalRow(state, state + 1, 13),),
    )

    assert (
        resolve_materialized_indirect_transfer_targets(
            (_coarse_transition(16, state, 13),),
            graph,
            dispatcher,
            (),
            condition_chain_dag=dag,
            condition_chain_handlers=frozenset({2, 13, 15}),
        )
        == ()
    )


def test_normalizer_without_exact_shared_state_feeder_abstains() -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    transition = _coarse_transition(14, 0x1BABC1DC, 13)

    assert (
        resolve_materialized_indirect_transfer_targets(
            (replace(transition, via_block=None),),
            graph,
            _dispatcher({}, exit_block=99),
            (),
            condition_chain_dag=dag,
            condition_chain_handlers=frozenset({2, 13, 15, 19}),
        )
        == ()
    )


def test_normalizer_feeder_to_unrelated_local_abstains_atomically() -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    feeder = graph.get_block(3)
    source = graph.get_block(13)
    assert feeder is not None and source is not None
    feeder_write = feeder.insn_snapshots[0]
    graph = FlowGraph(
        blocks={
            **graph.blocks,
            # Keep this transition outside source-carrier recognition so the
            # assertion isolates the normalizer's own feeder-state proof.
            13: replace(source, succs=(3, 10)),
            3: replace(
                feeder,
                insn_snapshots=(replace(feeder_write, d=_stk(_STATE_OFF + 4)),),
            ),
        },
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )

    transition = replace(
        _coarse_transition(13, 0x1BABC1DC, 13),
        via_block=3,
    )
    assert (
        resolve_materialized_indirect_transfer_targets(
            (transition,),
            graph,
            _dispatcher({}, exit_block=99),
            (),
            condition_chain_dag=dag,
            condition_chain_handlers=frozenset({2, 10, 13, 15, 19}),
            state_var_stkoff=_STATE_OFF,
        )
        == ()
    )


def test_mixed_width_state_normalizer_abstains() -> None:
    graph, dag = _typed_state_route_reconciliation_fixture()
    normalizer = graph.get_block(2)
    assert normalizer is not None
    wide_const = MopSnapshot(
        t=_T_NUM,
        size=8,
        value=0x1939CB36,
        kind=OperandKind.NUMBER,
    )
    wide_carrier = MopSnapshot(
        t=_T_REG,
        size=8,
        reg=8,
        kind=OperandKind.REGISTER,
    )
    wide_state = MopSnapshot(
        t=_T_STK,
        size=8,
        stkoff=_STATE_OFF,
        stack_refs=(_STATE_OFF,),
        kind=OperandKind.STACK,
    )
    graph = FlowGraph(
        blocks={
            **graph.blocks,
            2: replace(
                normalizer,
                insn_snapshots=(_mov(0x1200, wide_const, wide_carrier),),
            ),
            3: replace(
                graph.get_block(3),
                insn_snapshots=(_mov(0x1300, wide_carrier, wide_state),),
            ),
        },
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )

    assert (
        resolve_materialized_indirect_transfer_targets(
            (_coarse_transition(14, 0x1BABC1DC, 13),),
            graph,
            _dispatcher({}, exit_block=99),
            (),
            condition_chain_dag=dag,
            condition_chain_handlers=frozenset({2, 13, 15, 19}),
        )
        == ()
    )


def test_exact_state_normalizer_cycle_abstains() -> None:
    graph, _dag = _typed_state_route_reconciliation_fixture()
    cycle_dag = DecisionDag(
        32,
        {4: RouteComparison(4, "jz", 0x1939CB36, 2, 10)},
        root=4,
    )

    assert (
        resolve_materialized_indirect_transfer_targets(
            (_coarse_transition(14, 0x1939CB36, 13),),
            graph,
            _dispatcher({}, exit_block=99),
            (),
            condition_chain_dag=cycle_dag,
            condition_chain_handlers=frozenset({2, 10, 13}),
        )
        == ()
    )


@pytest.mark.parametrize(
    "fixture_kwargs",
    (
        {"effectful_normalizer": True},
        {"effectful_carrier": True},
    ),
)
def test_effectful_state_normalizer_chain_abstains(
    fixture_kwargs: dict[str, bool],
) -> None:
    graph, dag = _typed_state_route_reconciliation_fixture(**fixture_kwargs)

    assert (
        resolve_materialized_indirect_transfer_targets(
            (_coarse_transition(14, 0x1BABC1DC, 13),),
            graph,
            _dispatcher({}, exit_block=99),
            (),
            condition_chain_dag=dag,
            condition_chain_handlers=frozenset({2, 13, 15, 19}),
        )
        == ()
    )


_ARITHMETIC_FEEDER_STATE = 0x011A0881
_ARITHMETIC_FEEDER_LEFT = 0x85CE363D
_ARITHMETIC_FEEDER_RIGHT = 0x84D43EBC


def _goto(ea: int, target: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=55,
        ea=ea,
        operands=(),
        l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=target),
        kind=InsnKind.GOTO,
    )


def _two_stage_state_transform_fixture():
    state = 0x601404BC
    left = 0x43B6183E
    right = 0x23A21C82
    source_serials = (3, 166, 278)
    blocks = {
        source: _blk(
            source,
            (4,),
            (),
            (
                _mov(0x18002D0A3 + source, _num(left), _reg(8)),
                _mov(0x18002D0A8 + source, _num(right), _reg(24)),
            ),
            ea=0x18002D0A3 + source,
        )
        for source in source_serials
    }
    blocks.update(
        {
            4: _blk(
                4,
                (5,),
                source_serials,
                (_xor(0x18002D4F3, _reg(24), _reg(8), _reg(8)),),
                ea=0x18002D4F3,
            ),
            5: _blk(
                5,
                (6,),
                (4,),
                (_mov(0x18002D4FA, _reg(8), _stk(_STATE_OFF)),),
                ea=0x18002D4FA,
            ),
            6: _blk(
                6,
                (100, 101),
                (5,),
                (_jz_stack_const(0x18002D507, _STATE_OFF, state, 100),),
                ea=0x18002D4FE,
            ),
            100: _blk(100, (), (6,), (), ea=0x180031000),
            101: _blk(101, (), (6,), (), ea=0x180031100),
        }
    )
    graph = FlowGraph(blocks, 3, 0x18002CF50)
    dag = DecisionDag(
        32,
        {6: RouteComparison(6, "jz", state, 100, 101)},
        root=6,
    )
    transitions = tuple(
        StateWriteTransition(
            source,
            state,
            100,
            False,
            None,
            via_block=4,
            proof=TransitionProof(
                "region_partitioned_fixpoint",
                "transitive_glue_partitioned",
                True,
                route_source_kinds=("interval",),
            ),
        )
        for source in source_serials
    )
    unresolved_glue = StateWriteTransition(
        4,
        None,
        None,
        True,
        None,
        proof=TransitionProof(
            "region_partitioned_fixpoint",
            "unresolved",
            False,
        ),
    )
    return graph, dag, transitions, unresolved_glue, state


def test_exact_state_transform_accepts_one_pure_state_store_hop(_seam) -> None:
    graph, dag, _transitions, _unresolved, state = (
        _two_stage_state_transform_fixture()
    )

    receipt = state_carrier.prove_exact_u32_state_transform_feeder(
        graph,
        3,
        4,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
        required_comparison_serials=frozenset(dag.nodes),
        expected_state=state,
    )

    assert receipt is not None
    assert receipt.state == state
    assert receipt.feeder_serial == 4
    assert receipt.state_feeder_serial == 5
    assert receipt.comparison_entry_serial == 6


def test_exact_state_transform_accepts_split_final_arithmetic_state_hop(
    _seam,
) -> None:
    """A source-bound arithmetic program may finish in the state feeder."""

    source_serial = 34
    feeder_serial = 101
    state_feeder_serial = 102
    comparison_serial = 4
    source_ea = 0x18020F748
    feeder_ea = 0x18021245E
    state_feeder_ea = 0x180212460
    expected_state = 0x008FE79A
    graph = FlowGraph(
        {
            source_serial: _blk(
                source_serial,
                (feeder_serial,),
                (),
                (
                    _mov(source_ea, _num(0x5615EA58), _reg(8)),
                    _mov(source_ea + 2, _num(0x33573E44), _reg(24)),
                    _mov(source_ea + 8, _num(0x89EEC436), _reg(16)),
                    _goto(source_ea + 13, feeder_serial),
                ),
                ea=source_ea,
            ),
            100: _blk(100, (feeder_serial,), (), (), ea=0x180212440),
            feeder_serial: _blk(
                feeder_serial,
                (state_feeder_serial,),
                (source_serial, 100),
                (
                    _sub(feeder_ea, _reg(16), _reg(8), _reg(16)),
                    _goto(feeder_ea + 2, state_feeder_serial),
                ),
                ea=feeder_ea,
            ),
            131: _blk(131, (state_feeder_serial,), (), (), ea=0x180215000),
            state_feeder_serial: _blk(
                state_feeder_serial,
                (comparison_serial,),
                (feeder_serial, 131),
                (
                    _xor(
                        state_feeder_ea,
                        _reg(24),
                        _reg(16),
                        _stk(_STATE_OFF),
                    ),
                    _goto(state_feeder_ea + 4, comparison_serial),
                ),
                ea=state_feeder_ea,
            ),
            comparison_serial: _blk(
                comparison_serial,
                (200, 201),
                (state_feeder_serial,),
                (
                    _jz_stack_const(
                        0x18020ECE0,
                        _STATE_OFF,
                        expected_state,
                        200,
                    ),
                ),
                ea=0x18020ECE0,
            ),
            200: _blk(200, (), (comparison_serial,), (), ea=0x180218000),
            201: _blk(201, (), (comparison_serial,), (), ea=0x180218100),
        },
        source_serial,
        0x18020EC90,
    )

    receipt = state_carrier.prove_exact_u32_state_transform_feeder(
        graph,
        source_serial,
        feeder_serial,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
        required_comparison_serials=frozenset({comparison_serial}),
        expected_state=expected_state,
    )

    assert receipt is not None
    assert receipt.state == expected_state
    assert receipt.state_feeder_serial == state_feeder_serial
    assert tuple(instruction.operation for instruction in receipt.program) == (
        ValueOpKind.SUB,
        ValueOpKind.XOR,
    )


def test_complete_two_stage_transform_partitions_omit_unresolved_glue(_seam) -> None:
    graph, dag, transitions, unresolved, state = _two_stage_state_transform_fixture()
    rows = (transitions[0], unresolved, *transitions[1:])

    resolved = resolve_materialized_indirect_transfer_targets(
        rows,
        graph,
        _dispatcher({state: 100}, exit_block=101),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({100, 101}),
        state_var_stkoff=_STATE_OFF,
    )

    assert tuple(int(row.write_block) for row in resolved) == (3, 166, 278)
    assert {int(row.target_handler) for row in resolved} == {100}
    assert all(
        row.proof is not None
        and "state_transform_feeder" in row.proof.route_source_kinds
        for row in resolved
    )


def test_incomplete_two_stage_transform_partitions_reject_atomically(_seam) -> None:
    graph, dag, transitions, unresolved, state = _two_stage_state_transform_fixture()

    assert (
        resolve_materialized_indirect_transfer_targets(
            (transitions[0], unresolved, transitions[1]),
            graph,
            _dispatcher({state: 100}, exit_block=101),
            (),
            condition_chain_dag=dag,
            condition_chain_handlers=frozenset({100, 101}),
            state_var_stkoff=_STATE_OFF,
        )
        == ()
    )


@pytest.mark.parametrize(
    "variant",
    (
        "missing-state-feeder-reciprocity",
        "effectful-state-feeder",
        "foreign-state-identity",
        "unexpected-state-feeder-input",
        "transform-extra-successor",
    ),
)
def test_two_stage_transform_malformed_shapes_fail_closed(
    _seam,
    variant: str,
) -> None:
    graph, dag, _transitions, _unresolved, state = (
        _two_stage_state_transform_fixture()
    )
    blocks = dict(graph.blocks)
    if variant == "missing-state-feeder-reciprocity":
        blocks[5] = replace(blocks[5], preds=())
    elif variant == "effectful-state-feeder":
        blocks[5] = replace(
            blocks[5],
            insn_snapshots=(
                *blocks[5].insn_snapshots,
                _store(0x18002D4FB, _num(1), _global(0x140001000)),
            ),
        )
    elif variant == "foreign-state-identity":
        blocks[5] = replace(
            blocks[5],
            insn_snapshots=(
                _mov(0x18002D4FA, _reg(8), _stk(_STATE_OFF + 4)),
            ),
        )
    elif variant == "unexpected-state-feeder-input":
        blocks[5] = replace(
            blocks[5],
            insn_snapshots=(
                _mov(0x18002D4FA, _reg(24), _stk(_STATE_OFF)),
            ),
        )
    elif variant == "transform-extra-successor":
        blocks[4] = replace(blocks[4], succs=(5, 101))
    else:  # pragma: no cover - parametrization is closed above
        raise AssertionError(variant)

    malformed = FlowGraph(blocks, graph.entry_serial, graph.func_ea)
    assert (
        state_carrier.prove_exact_u32_state_transform_feeder(
            malformed,
            3,
            4,
            state_var_stkoff=_STATE_OFF,
            state_var_reg=None,
            required_comparison_serials=frozenset(dag.nodes),
            expected_state=state,
        )
        is None
    )


def _arithmetic_state_feeder_fixture(
    *,
    operation: ValueOpKind = ValueOpKind.XOR,
    left: int = _ARITHMETIC_FEEDER_LEFT,
    right: int = _ARITHMETIC_FEEDER_RIGHT,
    state: int = _ARITHMETIC_FEEDER_STATE,
    source_serial: int = 349,
    feeder_serial: int = 403,
    source_ea: int = 0x1800239A2,
    feeder_ea: int = 0x18002672A,
    proof_kind: str = "predecessor_partitioned",
    proof_trusted: bool = True,
    routed_target: int = 100,
    alternate_target: int = 101,
    recovered_target: int | None = 100,
    is_return: bool = False,
) -> tuple[
    FlowGraph,
    DecisionDag,
    StateWriteTransition,
    object,
]:
    """One exact binary state-transform feeder entering equality root15."""

    if operation is ValueOpKind.XOR:
        transform = _xor(feeder_ea, _reg(8), _reg(9), _stk(_STATE_OFF))
    elif operation is ValueOpKind.ADD:
        transform = _add(feeder_ea, _reg(8), _reg(9), _stk(_STATE_OFF))
    elif operation is ValueOpKind.SUB:
        transform = _sub(feeder_ea, _reg(8), _reg(9), _stk(_STATE_OFF))
    else:
        raise AssertionError(operation)

    graph = FlowGraph(
        blocks={
            source_serial: _blk(
                source_serial,
                (feeder_serial,),
                (),
                (
                    _mov(source_ea, _num(left), _reg(8)),
                    _mov(source_ea + 5, _num(right), _reg(9)),
                    _goto(source_ea + 10, feeder_serial),
                ),
                ea=source_ea,
            ),
            feeder_serial: _blk(
                feeder_serial,
                (15,),
                (source_serial,),
                (
                    transform,
                    _goto(feeder_ea + 5, 15),
                ),
                ea=feeder_ea,
            ),
            15: _blk(
                15,
                (routed_target, alternate_target),
                (feeder_serial,),
                (
                    _jz_stack_const(
                        0x180015268,
                        _STATE_OFF,
                        state,
                        routed_target,
                    ),
                ),
                ea=0x180015268,
            ),
            routed_target: _blk(
                routed_target,
                (200,),
                (15,),
                (),
                ea=0x180016000 + routed_target,
            ),
            alternate_target: _blk(
                alternate_target,
                (200,),
                (15,),
                (),
                ea=0x180017000 + alternate_target,
            ),
            200: _stop(200, (routed_target, alternate_target)),
        },
        entry_serial=source_serial,
        func_ea=0x180015110,
    )
    dag = DecisionDag(
        32,
        {
            15: RouteComparison(
                15,
                "jz",
                state,
                routed_target,
                alternate_target,
            ),
        },
        root=15,
    )
    transition = StateWriteTransition(
        source_serial,
        state,
        recovered_target,
        is_return,
        None,
        via_block=feeder_serial,
        proof=TransitionProof(
            "region_partitioned_fixpoint",
            proof_kind,
            proof_trusted,
            route_source_kinds=("interval",) if proof_trusted else (),
        ),
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(
            IntervalRow(
                state,
                state + 1,
                routed_target,
            ),
        ),
        default_target=200,
    )
    return graph, dag, transition, dispatcher


def _resolve_arithmetic_state_feeder(
    graph: FlowGraph,
    dag: DecisionDag,
    transition: StateWriteTransition,
    dispatcher: object,
) -> tuple[StateWriteTransition, ...]:
    return resolve_materialized_indirect_transfer_targets(
        (transition,),
        graph,
        dispatcher,
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset(
            int(path.target) for path in dag.resolve_paths()
        ),
        state_var_stkoff=_STATE_OFF,
    )


def _captured_nested_state_transform_fixture(
    *,
    source_insns: tuple[InsnSnapshot, ...] | None = None,
    feeder_insns: tuple[InsnSnapshot, ...] | None = None,
    state: int = 0x28F25B96,
) -> tuple[
    FlowGraph,
    DecisionDag,
    StateWriteTransition,
    object,
]:
    """Live source285/feeder446 ``(edx + (eax ^ r8d)) - ecx`` shape."""

    source_serial = 285
    feeder_serial = 446
    source_ea = 0x18001E4D1
    feeder_ea = 0x18002A97B
    target = 118
    alternate = 119
    source_program = source_insns or (
        _mov(source_ea, _num(0x1FB8DFB0), _reg(8)),
        _mov(source_ea + 0xE, _num(0x9D801B98), _reg(16)),
        _mov(source_ea + 0x1E, _num(0x9BE72683), _reg(24)),
        _mov(source_ea + 0x24, _num(0x38E1B931), _reg(72)),
        _goto(source_ea + 0x2B, feeder_serial),
    )
    expression = _nested_value(
        ValueOpKind.ADD,
        _reg(16),
        _nested_value(ValueOpKind.XOR, _reg(8), _reg(72)),
    )
    feeder_program = feeder_insns or (
        _sub(feeder_ea + 9, expression, _reg(24), _stk(_STATE_OFF)),
        _goto(feeder_ea + 0x10, 4),
    )
    graph = FlowGraph(
        {
            source_serial: _blk(
                source_serial,
                (feeder_serial,),
                (),
                source_program,
                ea=source_ea,
            ),
            feeder_serial: _blk(
                feeder_serial,
                (4,),
                (source_serial,),
                feeder_program,
                ea=feeder_ea,
            ),
            4: _blk(
                4,
                (15, alternate),
                (feeder_serial,),
                (_jle_stack_const(0x1800151DB, _STATE_OFF, 0x423C3FEB, 15),),
                ea=0x1800151D0,
            ),
            15: _blk(
                15,
                (target, alternate),
                (4,),
                (_jz_stack_const(0x18001526D, _STATE_OFF, state, target),),
                ea=0x180015268,
            ),
            target: _blk(target, (200,), (15,), (), ea=0x180016680),
            alternate: _blk(alternate, (200,), (4, 15), (), ea=0x180016690),
            200: _stop(200, (target, alternate)),
        },
        source_serial,
        0x180015110,
    )
    dag = DecisionDag(
        32,
        {15: RouteComparison(15, "jz", state, target, alternate)},
        root=15,
    )
    transition = StateWriteTransition(
        source_serial,
        state,
        target,
        False,
        None,
        via_block=feeder_serial,
        proof=TransitionProof(
            "region_partitioned_fixpoint",
            "predecessor_partitioned",
            True,
            route_source_kinds=("interval",),
        ),
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(IntervalRow(state, state + 1, target),),
        default_target=200,
    )
    return graph, dag, transition, dispatcher


def test_captured_nested_u32_state_transform_reconciles_from_existing_evaluator(
    _seam,
) -> None:
    graph, dag, transition, dispatcher = _captured_nested_state_transform_fixture()

    receipt = minimal_state_recovery.prove_exact_u32_state_transform_feeder(
        graph,
        285,
        446,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
        required_comparison_serials=frozenset({4, *dag.nodes}),
        expected_state=0x28F25B96,
    )
    resolved = _resolve_arithmetic_state_feeder(
        graph,
        dag,
        transition,
        dispatcher,
    )

    assert receipt is not None
    assert receipt.state == 0x28F25B96
    assert receipt.source_ea == 0x18001E4D1
    assert receipt.feeder_ea == 0x18002A97B
    assert tuple(instruction.operation for instruction in receipt.program) == (
        ValueOpKind.XOR,
        ValueOpKind.ADD,
        ValueOpKind.SUB,
    )
    assert dict(receipt.source_bindings) == {
        Varnode(Space.REGISTER, 8, 4): 0x1FB8DFB0,
        Varnode(Space.REGISTER, 16, 4): 0x9D801B98,
        Varnode(Space.REGISTER, 24, 4): 0x9BE72683,
        Varnode(Space.REGISTER, 72, 4): 0x38E1B931,
    }
    assert len(resolved) == 1
    assert resolved[0].target_handler == 118
    assert resolved[0].proof is not None
    assert "candidate_scoped_prefix_arm" in resolved[0].proof.route_source_kinds
    assert "state_transform_feeder" in resolved[0].proof.route_source_kinds


def test_state_transform_replays_pure_source_prefix_before_feeder(_seam) -> None:
    """A source-local pure prefix and feeder suffix form one exact program."""

    source_ea = 0x18001E4D1
    feeder_ea = 0x18002A97B
    source_program = (
        InsnSnapshot(
            opcode=0x41,
            ea=source_ea,
            operands=(),
            kind=InsnKind.CALL,
            call_kind=CallKind.DIRECT,
        ),
        _mov(source_ea + 4, _num(0x1FB8DFB0), _reg(8)),
        _mov(source_ea + 8, _num(0x9D801B98), _reg(16)),
        _mov(source_ea + 0xC, _num(0x9BE72683), _reg(24)),
        _mov(source_ea + 0x10, _num(0x38E1B931), _reg(72)),
        _xor(source_ea + 0x14, _reg(8), _reg(72), _reg(80)),
        _add(source_ea + 0x18, _reg(16), _reg(80), _reg(88)),
        _goto(source_ea + 0x1C, 446),
    )
    feeder_program = (
        _sub(feeder_ea + 9, _reg(88), _reg(24), _stk(_STATE_OFF)),
        _goto(feeder_ea + 0x10, 4),
    )
    graph, dag, transition, dispatcher = _captured_nested_state_transform_fixture(
        source_insns=source_program,
        feeder_insns=feeder_program,
    )

    receipt = minimal_state_recovery.prove_exact_u32_state_transform_feeder(
        graph,
        285,
        446,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
        required_comparison_serials=frozenset({4, *dag.nodes}),
        expected_state=0x28F25B96,
    )
    resolved = _resolve_arithmetic_state_feeder(
        graph,
        dag,
        transition,
        dispatcher,
    )

    assert receipt is not None
    assert tuple(instruction.operation for instruction in receipt.program) == (
        ValueOpKind.XOR,
        ValueOpKind.ADD,
        ValueOpKind.SUB,
    )
    assert len(resolved) == 1
    assert resolved[0].target_handler == 118
    assert resolved[0].proof is not None
    assert "state_transform_feeder" in resolved[0].proof.route_source_kinds


@pytest.mark.parametrize(
    "variant",
    ("effect", "selected-alias", "duplicate-result", "source-budget"),
)
def test_state_transform_source_prefix_remains_exact_and_bounded(
    _seam,
    variant: str,
) -> None:
    source_ea = 0x18001E4D1
    feeder_ea = 0x18002A97B
    prefix = [
        _mov(source_ea, _num(0x1FB8DFB0), _reg(8)),
        _mov(source_ea + 4, _num(0x9D801B98), _reg(16)),
        _mov(source_ea + 8, _num(0x9BE72683), _reg(24)),
        _mov(source_ea + 0xC, _num(0x38E1B931), _reg(72)),
        _xor(source_ea + 0x10, _reg(8), _reg(72), _reg(80)),
        _add(source_ea + 0x14, _reg(16), _reg(80), _reg(88)),
    ]
    feeder_left = _reg(88)
    if variant == "effect":
        prefix.append(_store(source_ea + 0x18, _num(1), _global(0x18004C000)))
    elif variant == "selected-alias":
        prefix.append(
            _mov(
                source_ea + 0x18,
                replace(_num(1), size=8),
                replace(_reg(8), size=8),
            )
        )
    elif variant == "duplicate-result":
        prefix.insert(5, _mov(source_ea + 0x13, _num(1), _reg(80)))
    elif variant == "source-budget":
        last = _reg(88)
        for index in range(13):
            output = _reg(96 + index * 8)
            prefix.append(_xor(source_ea + 0x18 + index, last, _reg(8), output))
            last = output
        feeder_left = last
    prefix.append(_goto(source_ea + 0x40, 446))
    feeder_program = (
        _sub(feeder_ea + 9, feeder_left, _reg(24), _stk(_STATE_OFF)),
        _goto(feeder_ea + 0x10, 4),
    )
    graph, dag, _, _ = _captured_nested_state_transform_fixture(
        source_insns=tuple(prefix),
        feeder_insns=feeder_program,
    )

    assert minimal_state_recovery.prove_exact_u32_state_transform_feeder(
        graph,
        285,
        446,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
        required_comparison_serials=frozenset({4, *dag.nodes}),
        expected_state=0x28F25B96,
    ) is None


def test_xdu_widened_u32_state_transform_reuses_low_register_result(_seam) -> None:
    """C06's XDU shell widens a proven U32 expression before the state move."""

    source_serial = 45
    feeder_serial = 123
    state_feeder_serial = 3
    state = 0x764595C6
    source_ea = 0x18004F85F
    feeder_ea = 0x180050F3E
    xdu = InsnSnapshot(
        opcode=2,
        ea=feeder_ea,
        operands=(),
        kind=InsnKind.XDU,
        l=_nested_value(
            ValueOpKind.XOR,
            _reg(8),
            _nested_value(ValueOpKind.SUB, _reg(16), _reg(24)),
        ),
        d=replace(_reg(16), size=8),
    )
    graph = FlowGraph(
        {
            source_serial: _blk(
                source_serial,
                (feeder_serial,),
                (),
                (
                    _mov(source_ea, _num(0x7E174EE2), _reg(8)),
                    _mov(source_ea + 4, _num(0xF1E462F4), _reg(24)),
                    _mov(source_ea + 8, _num(0xFA373E18), _reg(16)),
                    _goto(source_ea + 12, feeder_serial),
                ),
                ea=source_ea,
            ),
            feeder_serial: _blk(
                feeder_serial,
                (state_feeder_serial,),
                (source_serial,),
                (xdu, _goto(feeder_ea + 2, state_feeder_serial)),
                ea=feeder_ea,
            ),
            state_feeder_serial: _blk(
                state_feeder_serial,
                (4,),
                (feeder_serial,),
                (_mov(0x18004F2D8, _reg(16), _stk(_STATE_OFF)),),
                ea=0x18004F2D8,
            ),
            4: _blk(
                4,
                (100, 101),
                (state_feeder_serial,),
                (_jz_stack_const(0x18004F2E4, _STATE_OFF, state, 100),),
                ea=0x18004F2DC,
            ),
            100: _blk(100, (), (4,), (), ea=0x180051200),
            101: _blk(101, (), (4,), (), ea=0x180051300),
        },
        source_serial,
        0x18004F180,
    )

    receipt = state_carrier.prove_exact_u32_state_transform_feeder(
        graph,
        source_serial,
        feeder_serial,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
        required_comparison_serials=frozenset({4}),
        expected_state=state,
    )

    assert receipt is not None
    assert receipt.state == state
    assert tuple(instruction.operation for instruction in receipt.program) == (
        ValueOpKind.SUB,
        ValueOpKind.XOR,
        ValueOpKind.ZEXT,
        ValueOpKind.MOVE,
    )

    inline_blocks = dict(graph.blocks)
    inline_blocks.pop(state_feeder_serial)
    inline_blocks[feeder_serial] = replace(
        inline_blocks[feeder_serial],
        succs=(4,),
        insn_snapshots=(
            xdu,
            _mov(feeder_ea + 1, _reg(16), _stk(_STATE_OFF)),
            _goto(feeder_ea + 2, 4),
        ),
    )
    inline_blocks[4] = replace(inline_blocks[4], preds=(feeder_serial,))
    inline_graph = FlowGraph(inline_blocks, source_serial, graph.func_ea)

    inline_receipt = state_carrier.prove_exact_u32_state_transform_feeder(
        inline_graph,
        source_serial,
        feeder_serial,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
        required_comparison_serials=frozenset({4}),
        expected_state=state,
    )

    assert inline_receipt is not None
    assert inline_receipt.state == state
    assert tuple(instruction.operation for instruction in inline_receipt.program) == (
        ValueOpKind.SUB,
        ValueOpKind.XOR,
        ValueOpKind.ZEXT,
        ValueOpKind.MOVE,
    )


def test_state_transform_reads_low_u32_from_exact_wide_register_definition(
    _seam,
) -> None:
    """C06 may render an exact RDX constant while the feeder reads EDX."""

    source_ea = 0x18005287F
    feeder_ea = 0x180053E66
    wide_value = 0x12345678E26A5418
    right = 0x9753BFD5
    state = (wide_value ^ right) & 0xFFFFFFFF
    graph, dag, _, _ = _captured_nested_state_transform_fixture(
        source_insns=(
            _mov(
                source_ea,
                replace(_num(wide_value), size=8),
                replace(_reg(16), size=8),
            ),
            _mov(source_ea + 8, _num(right), _reg(24)),
            _goto(source_ea + 12, 446),
        ),
        feeder_insns=(
            _xor(feeder_ea, _reg(16), _reg(24), _stk(_STATE_OFF)),
            _goto(feeder_ea + 4, 4),
        ),
        state=state,
    )

    receipt = state_carrier.prove_exact_u32_state_transform_feeder(
        graph,
        285,
        446,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
        required_comparison_serials=frozenset({4, *dag.nodes}),
        expected_state=state,
    )

    assert receipt is not None
    assert receipt.state == state
    assert dict(receipt.source_bindings)[Varnode(Space.REGISTER, 16, 4)] == (
        wide_value & 0xFFFFFFFF
    )


def test_state_transform_reuses_external_register_before_overwriting_it(_seam) -> None:
    """C06 reads source-owned EDX, then writes the final expression to EDX."""

    source_serial = 45
    feeder_serial = 123
    state_feeder_serial = 3
    state = 0x764595C6
    source_ea = 0x180052ACF
    feeder_ea = 0x1800541AE
    graph = FlowGraph(
        {
            source_serial: _blk(
                source_serial,
                (feeder_serial,),
                (),
                (
                    _mov(source_ea, _num(0x3EDE27C9), _stk(_STATE_OFF)),
                    _mov(source_ea + 0x23, _num(0x7E174EE2), _reg(8)),
                    _mov(source_ea + 0x3F, _num(0xF1E462F4), _reg(24)),
                    _mov(
                        source_ea + 0x43,
                        replace(_num(0x9289DCA5), size=8),
                        replace(_reg(16), size=8),
                    ),
                    _mov(source_ea + 0x45, _num(0xFA373E18), _reg(16)),
                    _goto(source_ea + 0x4A, feeder_serial),
                ),
                ea=source_ea,
            ),
            feeder_serial: _blk(
                feeder_serial,
                (state_feeder_serial,),
                (source_serial,),
                (
                    _xor(
                        feeder_ea,
                        _reg(8),
                        _nested_sub(_reg(16), _reg(24)),
                        _reg(16),
                    ),
                    _goto(feeder_ea + 2, state_feeder_serial),
                ),
                ea=feeder_ea,
            ),
            state_feeder_serial: _blk(
                state_feeder_serial,
                (4,),
                (feeder_serial,),
                (_mov(0x1800526C8, _reg(16), _stk(_STATE_OFF)),),
                ea=0x1800526C8,
            ),
            4: _blk(
                4,
                (100, 101),
                (state_feeder_serial,),
                (_jz_stack_const(0x1800526D4, _STATE_OFF, state, 100),),
                ea=0x1800526CC,
            ),
            100: _blk(100, (), (4,), (), ea=0x180055200),
            101: _blk(101, (), (4,), (), ea=0x180055300),
        },
        source_serial,
        0x180052500,
    )

    receipt = state_carrier.prove_exact_u32_state_transform_feeder(
        graph,
        source_serial,
        feeder_serial,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
        required_comparison_serials=frozenset({4}),
        expected_state=state,
    )

    assert receipt is not None
    assert receipt.state == state
    assert tuple(instruction.operation for instruction in receipt.program) == (
        ValueOpKind.SUB,
        ValueOpKind.XOR,
        ValueOpKind.MOVE,
    )


def test_nested_state_transform_isolates_temp_and_register_namespaces(
    _seam,
) -> None:
    """Projected TEMP(0) must not overwrite the distinct REGISTER(0)."""

    source_ea = 0x18001E4D1
    feeder_ea = 0x18002A97B
    expression = _nested_value(ValueOpKind.XOR, _reg(0), _reg(8))
    graph, dag, transition, dispatcher = _captured_nested_state_transform_fixture(
        source_insns=(
            _mov(source_ea, _num(5), _reg(0)),
            _mov(source_ea + 5, _num(3), _reg(8)),
            _goto(source_ea + 10, 446),
        ),
        feeder_insns=(
            _add(feeder_ea + 9, expression, _reg(0), _stk(_STATE_OFF)),
            _goto(feeder_ea + 0x10, 4),
        ),
        state=11,
    )

    receipt = state_carrier.prove_exact_u32_state_transform_feeder(
        graph,
        285,
        446,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
        required_comparison_serials=frozenset({4, *dag.nodes}),
        expected_state=11,
    )
    resolved = _resolve_arithmetic_state_feeder(
        graph,
        dag,
        transition,
        dispatcher,
    )

    assert receipt is not None
    assert receipt.state == 11
    assert len(resolved) == 1
    assert resolved[0].target_handler == 118


def test_state_transform_feeder_routes_from_reciprocal_internal_dag_entry(
    _seam,
) -> None:
    """Route from the physical entry and reject root-only provider evidence."""

    graph, _, transition, dispatcher = _arithmetic_state_feeder_fixture()
    blocks = dict(graph.blocks)
    feeder = blocks[403]
    blocks[403] = replace(
        feeder,
        succs=(16,),
        insn_snapshots=(feeder.insn_snapshots[0], _goto(0x18002672F, 16)),
    )
    blocks[15] = replace(
        blocks[15],
        succs=(100, 16),
        preds=(),
    )
    blocks[16] = _blk(
        16,
        (101, 100),
        (15, 403),
        (
            _jz_stack_const(
                0x180015280,
                _STATE_OFF,
                _ARITHMETIC_FEEDER_STATE,
                101,
            ),
        ),
        ea=0x180015280,
    )
    blocks[100] = replace(blocks[100], preds=(15, 16))
    blocks[101] = replace(blocks[101], preds=(16,))
    internal_entry_graph = FlowGraph(blocks, graph.entry_serial, graph.func_ea)
    dag = DecisionDag(
        32,
        {
            15: RouteComparison(
                15,
                "jz",
                _ARITHMETIC_FEEDER_STATE,
                100,
                16,
            ),
            16: RouteComparison(
                16,
                "jz",
                _ARITHMETIC_FEEDER_STATE,
                101,
                100,
            ),
        },
        root=15,
    )

    assert (
        _resolve_arithmetic_state_feeder(
            internal_entry_graph,
            dag,
            transition,
            dispatcher,
        )
        == ()
    )

    physical_dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(
            IntervalRow(
                _ARITHMETIC_FEEDER_STATE,
                _ARITHMETIC_FEEDER_STATE + 1,
                101,
            ),
        ),
        default_target=200,
    )
    receipt = state_carrier.prove_exact_u32_state_transform_feeder(
        internal_entry_graph,
        349,
        403,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
        required_comparison_serials=frozenset(dag.nodes),
        expected_state=_ARITHMETIC_FEEDER_STATE,
    )
    physical_route = minimal_state_recovery._route_state_through_decision_dag(
        transition,
        internal_entry_graph,
        dag,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
        entry_serial=16,
    )

    assert receipt is not None
    assert receipt.comparison_entry_serial == 16
    assert physical_route is not None
    assert physical_route.target == 101
    physically_bound = _resolve_arithmetic_state_feeder(
        internal_entry_graph,
        dag,
        replace(transition, target_handler=101),
        physical_dispatcher,
    )

    assert len(physically_bound) == 1
    assert physically_bound[0].target_handler == 101
    assert physically_bound[0].proof is not None
    assert "state_transform_feeder" in physically_bound[0].proof.route_source_kinds

    one_sided_blocks = dict(internal_entry_graph.blocks)
    one_sided_blocks[101] = replace(one_sided_blocks[101], preds=())
    one_sided_graph = FlowGraph(
        one_sided_blocks,
        internal_entry_graph.entry_serial,
        internal_entry_graph.func_ea,
    )

    assert (
        _resolve_arithmetic_state_feeder(
            one_sided_graph,
            dag,
            replace(transition, target_handler=101),
            physical_dispatcher,
        )
        == ()
    )


def _captured_direct_internal_dag_entry_fixture():
    """Live source243 -> comparison67 after the outer dispatcher is peeled."""

    state = 0x1D848F83
    source_serial = 243
    root_serial = 5
    internal_serial = 67
    root_target = 390
    root_alternate = 391
    physical_target = 68
    stop = 500
    graph = FlowGraph(
        {
            source_serial: _blk(
                source_serial,
                (internal_serial,),
                (242,),
                (
                    _mov(0x18001B3C2, _num(0x1B1D5B8F), _reg(0)),
                    _mov(0x18001B3D4, _num(state), _stk(_STATE_OFF)),
                    _goto(0x18001B3DE, internal_serial),
                ),
                ea=0x18001B3C2,
            ),
            root_serial: _blk(
                root_serial,
                (root_target, root_alternate),
                (),
                (
                    _jz_stack_const(
                        0x1800151E6,
                        _STATE_OFF,
                        state,
                        root_target,
                    ),
                ),
                ea=0x1800151E1,
            ),
            internal_serial: _blk(
                internal_serial,
                (physical_target, root_target),
                (root_serial, source_serial),
                (
                    _jz_stack_const(
                        0x1800163A0,
                        _STATE_OFF,
                        state,
                        physical_target,
                    ),
                ),
                ea=0x18001639B,
            ),
            root_target: _blk(
                root_target,
                (stop,),
                (root_serial, internal_serial),
                (),
                ea=0x180025F65,
            ),
            root_alternate: _blk(
                root_alternate,
                (stop,),
                (root_serial,),
                (),
                ea=0x180025F80,
            ),
            physical_target: _blk(
                physical_target,
                (stop,),
                (internal_serial,),
                (
                    _mov(0x1800163A6, _num(state), _stk(_STATE_OFF)),
                    _goto(0x1800163AB, stop),
                ),
                ea=0x1800163A6,
            ),
            stop: _stop(stop, (root_target, root_alternate, physical_target)),
        },
        entry_serial=source_serial,
        func_ea=0x180015110,
    )
    dag = DecisionDag(
        32,
        {
            root_serial: RouteComparison(
                root_serial,
                "jz",
                state,
                root_target,
                root_alternate,
            ),
        },
        root=root_serial,
    )
    transition = StateWriteTransition(
        source_serial,
        state,
        root_target,
        False,
        None,
        via_block=internal_serial,
        proof=TransitionProof(
            "region_partitioned_fixpoint",
            "predecessor_partitioned",
            True,
            route_source_kinds=("interval",),
        ),
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(IntervalRow(state, state + 1, root_target),),
        default_target=stop,
    )
    return graph, dag, transition, dispatcher


def test_captured_direct_writer_routes_from_physical_internal_dag_entry(
    _seam,
) -> None:
    graph, dag, transition, dispatcher = _captured_direct_internal_dag_entry_fixture()

    resolved = _resolve_arithmetic_state_feeder(
        graph,
        dag,
        transition,
        dispatcher,
    )

    assert len(resolved) == 1
    assert resolved[0].write_block == 243
    assert resolved[0].via_block == 67
    assert resolved[0].target_handler == 68
    assert resolved[0].proof is not None
    assert resolved[0].proof.trusted
    assert resolved[0].proof.oracle_kind == "decision_dag_state_route_reconciliation"
    assert "internal_decision_dag_entry" in resolved[0].proof.route_source_kinds


def test_direct_internal_dag_entry_accepts_trusted_multi_entry_state(
    _seam,
) -> None:
    graph, dag, transition, dispatcher = _captured_direct_internal_dag_entry_fixture()
    assert transition.proof is not None
    transition = replace(
        transition,
        proof=replace(transition.proof, kind="multi_entry_global_fold"),
    )

    resolved = _resolve_arithmetic_state_feeder(
        graph,
        dag,
        transition,
        dispatcher,
    )

    assert len(resolved) == 1
    assert resolved[0].target_handler == 68
    assert resolved[0].proof is not None
    assert "internal_decision_dag_entry" in resolved[0].proof.route_source_kinds


def test_direct_internal_route_forest_accepts_different_identity_semantic_leaf(
    _seam,
) -> None:
    graph, dag, transition, dispatcher = _captured_direct_internal_dag_entry_fixture()
    blocks = dict(graph.blocks)
    blocks[68] = _blk(
        68,
        (500, 391),
        (67,),
        (
            _jz_stack_const(
                0x1800163A6,
                _STATE_OFF + 4,
                0,
                500,
            ),
        ),
        ea=0x1800163A6,
    )
    blocks[391] = replace(blocks[391], preds=(5, 68))
    graph = replace(graph, blocks=blocks)

    resolved = _resolve_arithmetic_state_feeder(
        graph,
        dag,
        transition,
        dispatcher,
    )

    assert len(resolved) == 1
    assert resolved[0].target_handler == 68
    assert resolved[0].proof is not None
    assert "internal_decision_dag_entry" in resolved[0].proof.route_source_kinds


def test_direct_internal_route_forest_accepts_pure_xdu_prefix_before_comparison(
    _seam,
) -> None:
    """Live blk24 shape: pure XDU work precedes the state comparison tail."""

    graph, dag, transition, dispatcher = _captured_direct_internal_dag_entry_fixture()
    state = int(transition.next_state)
    internal_serial = int(transition.via_block)
    prefixed_serial = 69
    physical_target = 68
    root_target = 390
    stop = 500
    prefix = InsnSnapshot(
        opcode=2,
        ea=0x1800163B0,
        operands=(),
        kind=InsnKind.XDU,
        l=_nested_value(ValueOpKind.ADD, _stk(_STATE_OFF), _num(0x4008534B)),
        d=replace(_reg(8), size=8),
    )
    blocks = dict(graph.blocks)
    blocks[internal_serial] = _blk(
        internal_serial,
        (prefixed_serial, root_target),
        blocks[internal_serial].preds,
        (
            _jz_stack_const(
                0x1800163A0,
                _STATE_OFF,
                state,
                prefixed_serial,
            ),
        ),
        ea=0x18001639B,
    )
    blocks[prefixed_serial] = _blk(
        prefixed_serial,
        (physical_target, stop),
        (internal_serial,),
        (
            prefix,
            _jz_stack_const(
                0x1800163BC,
                _STATE_OFF,
                state,
                physical_target,
            ),
        ),
        ea=0x1800163B0,
    )
    blocks[physical_target] = replace(
        blocks[physical_target],
        preds=(prefixed_serial,),
    )
    blocks[root_target] = replace(
        blocks[root_target],
        preds=(5, internal_serial),
    )
    blocks[stop] = replace(
        blocks[stop],
        preds=(*blocks[stop].preds, prefixed_serial),
        start_ea=0xFFFFFFFFFFFFFFFF,
    )
    graph = replace(graph, blocks=blocks)
    dag = DecisionDag(
        32,
        {
            **dag.nodes,
            internal_serial: RouteComparison(
                internal_serial,
                "jz",
                state,
                prefixed_serial,
                root_target,
            ),
            prefixed_serial: RouteComparison(
                prefixed_serial,
                "jz",
                state,
                physical_target,
                stop,
            ),
        },
        root=dag.root,
        aliases=dag.aliases,
    )

    resolved = _resolve_arithmetic_state_feeder(
        graph,
        dag,
        transition,
        dispatcher,
    )

    assert len(resolved) == 1
    assert resolved[0].target_handler == physical_target
    assert resolved[0].proof is not None
    assert "internal_decision_dag_entry" in resolved[0].proof.route_source_kinds


def test_direct_internal_route_forest_preserves_reciprocal_alias_to_handler(
    _seam,
) -> None:
    """A current pure GOTO alias is part of the physical route authority."""

    graph, dag, transition, dispatcher = _captured_direct_internal_dag_entry_fixture()
    state = int(transition.next_state)
    internal_serial = int(transition.via_block)
    alias_serial = 69
    physical_target = 68
    root_target = 390
    blocks = dict(graph.blocks)
    blocks[internal_serial] = _blk(
        internal_serial,
        (alias_serial, root_target),
        blocks[internal_serial].preds,
        (
            _jz_stack_const(
                0x1800163A0,
                _STATE_OFF,
                state,
                alias_serial,
            ),
        ),
        ea=0x18001639B,
    )
    blocks[alias_serial] = _blk(
        alias_serial,
        (physical_target,),
        (internal_serial,),
        (_goto(0x1800163B0, physical_target),),
        ea=0x1800163B0,
    )
    blocks[physical_target] = replace(blocks[physical_target], preds=(alias_serial,))
    blocks[root_target] = replace(
        blocks[root_target],
        preds=(5, internal_serial),
    )
    graph = replace(graph, blocks=blocks)
    dag = DecisionDag(
        32,
        {
            **dag.nodes,
            internal_serial: RouteComparison(
                internal_serial,
                "jz",
                state,
                alias_serial,
                root_target,
            ),
        },
        root=dag.root,
        aliases={alias_serial: physical_target},
    )

    resolved = _resolve_arithmetic_state_feeder(
        graph,
        dag,
        transition,
        dispatcher,
    )

    assert len(resolved) == 1
    assert resolved[0].target_handler == physical_target
    assert resolved[0].proof is not None
    assert "internal_decision_dag_entry" in resolved[0].proof.route_source_kinds


def _captured_partitioned_internal_transform_fixture():
    """Live sources517/531 -> SUB518 -> omitted comparison23 forest."""

    state_a = 0x43584BDC
    state_b = 0x609157A9
    root = 5
    comparison = 23
    source_a = 517
    source_b = 531
    feeder = 518
    target_a = 68
    target_b = 69
    root_target = 390
    root_alternate = 391
    graph = FlowGraph(
        {
            0: _blk(0, (source_a, source_b), (), (), ea=0x180015110),
            source_a: _blk(
                source_a,
                (feeder,),
                (0,),
                (
                    _mov(0x18002C9E9, _num(0xCD37D389), _reg(0)),
                    _mov(0x18002CA1B, _num(0x10901F65), _reg(8)),
                    _goto(0x18002CA1C, feeder),
                ),
                ea=0x18002C9E9,
            ),
            source_b: _blk(
                source_b,
                (feeder,),
                (0,),
                (
                    _mov(0x18002CC56, _num(0x65E079F7), _reg(0)),
                    _mov(0x18002CC7C, _num(0xC671D1A0), _reg(8)),
                    _goto(0x18002CC7F, feeder),
                ),
                ea=0x18002CC3A,
            ),
            feeder: _blk(
                feeder,
                (comparison,),
                (source_a, source_b),
                (
                    _sub(0x18002CA21, _reg(8), _reg(0), _stk(_STATE_OFF)),
                    _goto(0x18002CA28, comparison),
                ),
                ea=0x18002CA1E,
            ),
            comparison: _blk(
                comparison,
                (target_b, target_a),
                (feeder,),
                (
                    _jz_stack_const(
                        0x180015355,
                        _STATE_OFF,
                        state_b,
                        target_b,
                    ),
                ),
                ea=0x180015350,
            ),
            target_a: _blk(
                target_a,
                (root,),
                (comparison,),
                (_mov(0x1800163A6, _num(state_a), _stk(_STATE_OFF)),),
                ea=0x1800163A6,
            ),
            target_b: _blk(
                target_b,
                (root,),
                (comparison,),
                (_mov(0x1800163B6, _num(state_b), _stk(_STATE_OFF)),),
                ea=0x1800163B6,
            ),
            root: _blk(
                root,
                (root_target, root_alternate),
                (target_a, target_b, root_target, root_alternate),
                (
                    _jz_stack_const(
                        0x1800151E6,
                        _STATE_OFF,
                        state_b,
                        root_target,
                    ),
                ),
                ea=0x1800151E1,
            ),
            root_target: _blk(
                root_target,
                (root,),
                (root,),
                (),
                ea=0x180025F65,
            ),
            root_alternate: _blk(
                root_alternate,
                (root,),
                (root,),
                (),
                ea=0x180025F80,
            ),
        },
        entry_serial=0,
        func_ea=0x180015110,
    )
    dag = DecisionDag(
        32,
        {
            root: RouteComparison(
                root,
                "jz",
                state_b,
                root_target,
                root_alternate,
            ),
        },
        root=root,
    )
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=(
            IntervalRow(state_a, state_a + 1, root_alternate),
            IntervalRow(state_b, state_b + 1, root_target),
        ),
        default_target=root_alternate,
    )
    return graph, dag, dispatcher, (state_a, state_b), (target_a, target_b)


def test_multi_entry_shared_transform_partitions_physical_internal_sources(
    _seam,
) -> None:
    graph, _dag, dispatcher, states, targets = (
        _captured_partitioned_internal_transform_fixture()
    )

    recovered = recover_state_write_transitions_via_partitioned_fixpoint(
        graph,
        dispatcher,
        _STATE_OFF,
        dispatcher_entry_serial=5,
        include_multi_entry_back_edges=True,
    )
    physical = tuple(
        row for row in recovered if row.write_block in {517, 531}
    )

    assert tuple(
        (row.write_block, row.via_block, row.next_state)
        for row in physical
    ) == (
        (517, 518, states[0]),
        (531, 518, states[1]),
    )
    assert all(
        row.proof is not None
        and row.proof.kind == "predecessor_partitioned"
        for row in physical
    )
    assert not any(row.write_block == 518 for row in recovered)


def test_partitioned_transform_routes_from_omitted_physical_comparison_forest(
    _seam,
) -> None:
    graph, dag, dispatcher, _states, targets = (
        _captured_partitioned_internal_transform_fixture()
    )
    recovered = recover_state_write_transitions_via_partitioned_fixpoint(
        graph,
        dispatcher,
        _STATE_OFF,
        dispatcher_entry_serial=5,
        include_multi_entry_back_edges=True,
    )
    physical = tuple(
        row for row in recovered if row.write_block in {517, 531}
    )

    resolved = resolve_materialized_indirect_transfer_targets(
        physical,
        graph,
        dispatcher,
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({390, 391}),
        state_var_stkoff=_STATE_OFF,
    )

    assert tuple(row.write_block for row in resolved) == (517, 531)
    assert tuple(row.via_block for row in resolved) == (518, 518)
    assert tuple(row.target_handler for row in resolved) == targets
    assert all(
        row.proof is not None
        and "state_transform_feeder" in row.proof.route_source_kinds
        and "internal_decision_dag_entry" in row.proof.route_source_kinds
        for row in resolved
    )


@pytest.mark.parametrize(
    "mutation",
    ("missing_source_reciprocity", "missing_forest_reciprocity"),
)
def test_partitioned_internal_transform_malformed_topology_fails_closed(
    _seam,
    mutation: str,
) -> None:
    graph, dag, dispatcher, _states, _targets = (
        _captured_partitioned_internal_transform_fixture()
    )
    blocks = dict(graph.blocks)
    if mutation == "missing_source_reciprocity":
        blocks[518] = replace(blocks[518], preds=(517,))
    else:
        blocks[69] = replace(blocks[69], preds=())
    malformed = replace(graph, blocks=blocks)

    recovered = recover_state_write_transitions_via_partitioned_fixpoint(
        malformed,
        dispatcher,
        _STATE_OFF,
        dispatcher_entry_serial=5,
        include_multi_entry_back_edges=True,
    )
    physical = tuple(
        row for row in recovered if row.write_block in {517, 518, 531}
    )
    resolved = resolve_materialized_indirect_transfer_targets(
        physical,
        malformed,
        dispatcher,
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({390, 391}),
        state_var_stkoff=_STATE_OFF,
    )

    assert resolved == ()


@pytest.mark.parametrize(
    "mutation",
    (
        "source_state_mismatch",
        "untrusted_state",
        "missing_source_reciprocity",
        "malformed_comparison",
        "missing_path_reciprocity",
        "nonhandler_leaf",
    ),
)
def test_direct_internal_dag_entry_malformed_shapes_fail_closed(
    _seam,
    mutation: str,
) -> None:
    graph, dag, transition, dispatcher = _captured_direct_internal_dag_entry_fixture()
    blocks = dict(graph.blocks)
    if mutation == "source_state_mismatch":
        source = blocks[243]
        blocks[243] = replace(
            source,
            insn_snapshots=(
                source.insn_snapshots[0],
                _mov(0x18001B3D4, _num(0x1D848F84), _stk(_STATE_OFF)),
                source.insn_snapshots[2],
            ),
        )
    elif mutation == "untrusted_state":
        assert transition.proof is not None
        transition = replace(
            transition,
            proof=replace(transition.proof, trusted=False),
        )
    elif mutation == "missing_source_reciprocity":
        blocks[67] = replace(blocks[67], preds=(5,))
    elif mutation == "malformed_comparison":
        blocks[67] = replace(
            blocks[67],
            insn_snapshots=(
                _mov(0x18001639B, _num(1), _reg(8)),
                _jz_stack_const(
                    0x1800163A0,
                    _STATE_OFF,
                    0x1D848F83,
                    68,
                ),
            ),
        )
    elif mutation == "missing_path_reciprocity":
        blocks[68] = replace(blocks[68], preds=())
    elif mutation == "nonhandler_leaf":
        blocks[68] = replace(blocks[68], insn_snapshots=())
    else:  # pragma: no cover - parametrization is closed above
        raise AssertionError(mutation)

    malformed = FlowGraph(blocks, graph.entry_serial, graph.func_ea)
    assert (
        _resolve_arithmetic_state_feeder(
            malformed,
            dag,
            transition,
            dispatcher,
        )
        == ()
    )


def test_direct_internal_dag_entry_keeps_source_bound_materialized_consensus(
    _seam,
) -> None:
    graph, dag, transition, dispatcher = _captured_direct_internal_dag_entry_fixture()

    assert (
        resolve_materialized_indirect_transfer_targets(
            (transition,),
            graph,
            dispatcher,
            (),
            materialized_state_routes=(
                MaterializedStateRoute(
                    source_block_serial=243,
                    state_constant=0x1D848F83,
                    target_handler_serial=390,
                ),
            ),
            condition_chain_dag=dag,
            condition_chain_handlers=frozenset(
                int(path.target) for path in dag.resolve_paths()
            ),
            state_var_stkoff=_STATE_OFF,
        )
        == ()
    )


def test_direct_internal_dag_entry_propagates_snapshot_evaluator_failure(
    _seam,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph, dag, transition, dispatcher = _captured_direct_internal_dag_entry_fixture()

    def fail_transfer(*_args, **_kwargs):
        raise RuntimeError("snapshot evaluator failed")

    monkeypatch.setattr(
        minimal_state_recovery,
        "_transfer_snapshot_constant_block",
        fail_transfer,
    )
    with pytest.raises(RuntimeError, match="snapshot evaluator failed"):
        _resolve_arithmetic_state_feeder(
            graph,
            dag,
            transition,
            dispatcher,
        )


def test_nested_state_transform_delegates_every_step_to_shared_evaluator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph, _, _, _ = _captured_nested_state_transform_fixture()
    real_evaluator = state_carrier.forward_eval_instruction
    operations: list[object] = []

    def record_evaluation(instruction, *args, **kwargs):
        operations.append(instruction.operation)
        return real_evaluator(instruction, *args, **kwargs)

    monkeypatch.setattr(
        state_carrier,
        "forward_eval_instruction",
        record_evaluation,
    )

    assert (
        state_carrier.prove_exact_u32_state_transform_feeder(
            graph,
            285,
            446,
            state_var_stkoff=_STATE_OFF,
            state_var_reg=None,
            required_comparison_serials=frozenset({4, 15}),
            expected_state=0x28F25B96,
        )
        is not None
    )
    assert operations == [
        ValueOpKind.MOVE,
        ValueOpKind.MOVE,
        ValueOpKind.MOVE,
        ValueOpKind.MOVE,
        ValueOpKind.XOR,
        ValueOpKind.ADD,
        ValueOpKind.SUB,
    ]


def test_nested_state_transform_evaluator_runtime_error_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph, _, _, _ = _captured_nested_state_transform_fixture()

    def fail_evaluation(*_args, **_kwargs):
        raise RuntimeError("portable evaluator failed")

    monkeypatch.setattr(
        state_carrier,
        "forward_eval_instruction",
        fail_evaluation,
    )

    with pytest.raises(RuntimeError, match="portable evaluator failed"):
        state_carrier.prove_exact_u32_state_transform_feeder(
            graph,
            285,
            446,
            state_var_stkoff=_STATE_OFF,
            state_var_reg=None,
            required_comparison_serials=frozenset({4, 15}),
            expected_state=0x28F25B96,
        )


def test_nested_state_transform_accepts_exact_register_state_identity() -> None:
    graph, _, _, _ = _captured_nested_state_transform_fixture()
    blocks = dict(graph.blocks)
    feeder = blocks[446]
    transform = feeder.insn_snapshots[0]
    blocks[446] = replace(
        feeder,
        insn_snapshots=(
            replace(transform, d=_reg(1724)),
            *feeder.insn_snapshots[1:],
        ),
    )
    register_graph = FlowGraph(blocks, graph.entry_serial, graph.func_ea)

    receipt = state_carrier.prove_exact_u32_state_transform_feeder(
        register_graph,
        285,
        446,
        state_var_stkoff=None,
        state_var_reg=1724,
        required_comparison_serials=frozenset({4, 15}),
        expected_state=0x28F25B96,
    )

    assert receipt is not None
    assert receipt.state_identity == state_carrier.StorageIdentity(
        state_carrier.StorageIdentityKind.REGISTER,
        1724,
    )


@pytest.mark.parametrize(
    "variant",
    (
        "duplicate-source-definition",
        "nonconstant-source-definition",
        "unsupported-expression-op",
        "expression-budget",
        "address-leaf",
        "global-leaf",
        "lvar-leaf",
    ),
)
def test_captured_nested_u32_state_transform_rejects_non_exact_programs(
    _seam,
    variant: str,
) -> None:
    graph, dag, transition, dispatcher = _captured_nested_state_transform_fixture()
    blocks = dict(graph.blocks)
    source = blocks[285]
    feeder = blocks[446]
    if variant == "duplicate-source-definition":
        blocks[285] = replace(
            source,
            insn_snapshots=(
                *source.insn_snapshots[:-1],
                _mov(source.start_ea + 0x28, _num(0x1FB8DFB1), _reg(8)),
                source.insn_snapshots[-1],
            ),
        )
    elif variant == "nonconstant-source-definition":
        blocks[285] = replace(
            source,
            insn_snapshots=(
                _mov(source.start_ea, _reg(80), _reg(8)),
                *source.insn_snapshots[1:],
            ),
        )
    elif variant == "unsupported-expression-op":
        expression = _nested_value(
            ValueOpKind.AND,
            _reg(16),
            _nested_value(ValueOpKind.XOR, _reg(8), _reg(72)),
        )
        blocks[446] = replace(
            feeder,
            insn_snapshots=(
                _sub(feeder.start_ea + 9, expression, _reg(24), _stk(_STATE_OFF)),
                feeder.insn_snapshots[-1],
            ),
        )
    elif variant == "expression-budget":
        expression = _nested_value(
            ValueOpKind.ADD,
            _reg(16),
            _nested_value(
                ValueOpKind.XOR,
                _reg(8),
                _nested_value(ValueOpKind.SUB, _reg(72), _reg(8)),
            ),
        )
        blocks[446] = replace(
            feeder,
            insn_snapshots=(
                _sub(feeder.start_ea + 9, expression, _reg(24), _stk(_STATE_OFF)),
                feeder.insn_snapshots[-1],
            ),
        )
    elif variant == "address-leaf":
        expression = _nested_value(
            ValueOpKind.ADD,
            _reg(16),
            _nested_value(
                ValueOpKind.XOR,
                replace(_addr(_STATE_OFF), size=4),
                _reg(72),
            ),
        )
        blocks[446] = replace(
            feeder,
            insn_snapshots=(
                _sub(feeder.start_ea + 9, expression, _reg(24), _stk(_STATE_OFF)),
                feeder.insn_snapshots[-1],
            ),
        )
    elif variant == "global-leaf":
        expression = _nested_value(
            ValueOpKind.ADD,
            _reg(16),
            _nested_value(
                ValueOpKind.XOR,
                replace(_global(0x18004C000), size=4),
                _reg(72),
            ),
        )
        blocks[446] = replace(
            feeder,
            insn_snapshots=(
                _sub(feeder.start_ea + 9, expression, _reg(24), _stk(_STATE_OFF)),
                feeder.insn_snapshots[-1],
            ),
        )
    else:
        expression = _nested_value(
            ValueOpKind.ADD,
            _reg(16),
            _nested_value(
                ValueOpKind.XOR,
                MopSnapshot(
                    size=4,
                    kind=OperandKind.LVAR,
                    lvar_off=0,
                    lvar_stkoff=_STATE_OFF + 8,
                ),
                _reg(72),
            ),
        )
        blocks[446] = replace(
            feeder,
            insn_snapshots=(
                _sub(feeder.start_ea + 9, expression, _reg(24), _stk(_STATE_OFF)),
                feeder.insn_snapshots[-1],
            ),
        )
    malformed = FlowGraph(blocks, graph.entry_serial, graph.func_ea)

    assert (
        _resolve_arithmetic_state_feeder(
            malformed,
            dag,
            transition,
            dispatcher,
        )
        == ()
    )


@pytest.mark.parametrize(
    (
        "operation",
        "left",
        "right",
        "state",
        "source_serial",
        "feeder_serial",
        "source_ea",
        "feeder_ea",
        "proof_kind",
    ),
    (
        (
            ValueOpKind.XOR,
            0x85CE363D,
            0x84D43EBC,
            0x011A0881,
            349,
            403,
            0x1800239A2,
            0x18002672A,
            "predecessor_partitioned",
        ),
        (
            ValueOpKind.SUB,
            0xB24F8C14,
            0x8E1DAD8C,
            0x2431DE88,
            303,
            490,
            0x18001EEDC,
            0x18002B4D9,
            "predecessor_partitioned",
        ),
        (
            ValueOpKind.SUB,
            0x6A1454EE,
            0x3BFE4A5E,
            0x2E160A90,
            363,
            495,
            0x180024B61,
            0x18002BC5F,
            "predecessor_partitioned",
        ),
        (
            ValueOpKind.SUB,
            0,
            1,
            0xFFFFFFFF,
            700,
            701,
            0x180030000,
            0x180030020,
            "predecessor_partitioned",
        ),
        (
            ValueOpKind.ADD,
            0xFFFFFFFF,
            2,
            1,
            704,
            705,
            0x180030080,
            0x1800300A0,
            "predecessor_partitioned",
        ),
        (
            ValueOpKind.XOR,
            0x85CE363D,
            0x84D43EBC,
            0x011A0881,
            702,
            703,
            0x180030040,
            0x180030060,
            "multi_entry_global_fold",
        ),
    ),
    ids=(
        "xor-403-predecessor",
        "sub-490",
        "sub-495",
        "sub-u32-underflow",
        "add-u32-overflow",
        "xor-multi-entry-parity",
    ),
)
def test_trusted_arithmetic_state_feeder_reconciles_without_const_carrier_proof(
    _seam,
    monkeypatch: pytest.MonkeyPatch,
    operation: ValueOpKind,
    left: int,
    right: int,
    state: int,
    source_serial: int,
    feeder_serial: int,
    source_ea: int,
    feeder_ea: int,
    proof_kind: str,
) -> None:
    graph, dag, transition, dispatcher = _arithmetic_state_feeder_fixture(
        operation=operation,
        left=left,
        right=right,
        state=state,
        source_serial=source_serial,
        feeder_serial=feeder_serial,
        source_ea=source_ea,
        feeder_ea=feeder_ea,
        proof_kind=proof_kind,
    )
    const_carrier_calls = 0

    def reject_const_carrier_path(*_args, **_kwargs):
        nonlocal const_carrier_calls
        const_carrier_calls += 1
        return None

    monkeypatch.setattr(
        minimal_state_recovery,
        "prove_exact_u32_carrier_state_write",
        reject_const_carrier_path,
    )

    resolved = _resolve_arithmetic_state_feeder(
        graph,
        dag,
        transition,
        dispatcher,
    )

    assert const_carrier_calls == 0
    assert len(resolved) == 1
    assert resolved[0].next_state == state
    assert resolved[0].target_handler == 100
    assert resolved[0].proof is not None and resolved[0].proof.trusted
    assert "state_transform_feeder" in resolved[0].proof.route_source_kinds


def test_exact_transform_accepts_trusted_partial_predecessor_partition() -> None:
    graph, dag, transition, dispatcher = _arithmetic_state_feeder_fixture()
    transition = replace(
        transition,
        proof=TransitionProof(
            "region_partitioned_fixpoint",
            "partial_predecessor_partitioned",
            True,
            route_source_kinds=("interval",),
        ),
    )

    (resolved,) = _resolve_arithmetic_state_feeder(
        graph,
        dag,
        transition,
        dispatcher,
    )

    assert resolved.next_state == transition.next_state
    assert resolved.target_handler == transition.target_handler
    assert resolved.proof is not None
    assert "state_transform_feeder" in resolved.proof.route_source_kinds


@pytest.mark.parametrize(
    (
        "source_serial",
        "feeder_serial",
        "source_ea",
        "feeder_ea",
        "left",
        "right",
        "state",
        "target",
    ),
    (
        (
            489,
            490,
            0x18002B4AE,
            0x18002B4D9,
            0x6F3B459D,
            0x540A745D,
            0x1B30D140,
            250,
        ),
        (
            494,
            495,
            0x18002BC45,
            0x18002BC5F,
            0x2A7B0077,
            0x28360137,
            0x0244FF40,
            270,
        ),
    ),
    ids=("captured-row3-sub490", "captured-row5-sub495"),
)
def test_exact_transform_upgrades_untrusted_predecessor_hint(
    _seam,
    source_serial: int,
    feeder_serial: int,
    source_ea: int,
    feeder_ea: int,
    left: int,
    right: int,
    state: int,
    target: int,
) -> None:
    graph, dag, transition, dispatcher = _arithmetic_state_feeder_fixture(
        operation=ValueOpKind.SUB,
        left=left,
        right=right,
        state=state,
        source_serial=source_serial,
        feeder_serial=feeder_serial,
        source_ea=source_ea,
        feeder_ea=feeder_ea,
        proof_trusted=False,
        routed_target=target,
        alternate_target=target + 1,
        recovered_target=None,
        is_return=True,
    )
    assert minimal_state_recovery._has_exact_state_transform_proof(transition)
    assert transition.via_block is not None
    receipt = minimal_state_recovery.prove_exact_u32_state_transform_feeder(
        graph,
        int(transition.write_block),
        int(transition.via_block),
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
        required_comparison_serials=frozenset(dag.nodes),
        expected_state=state,
    )
    assert receipt is not None
    assert dag.route(state) == target
    assert minimal_state_recovery._bound_decision_dag_route(
        graph,
        dag,
        state,
        root=int(dag.root),
    ) == (target, (15,))
    route = minimal_state_recovery._route_state_through_decision_dag(
        transition,
        graph,
        dag,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
    )
    assert route is not None and route.target == target
    provider = minimal_state_recovery._dispatcher_provider_targets(
        dispatcher,
        state,
        condition_chain_handlers=frozenset({target, target + 1}),
    )
    assert provider is not None and provider[0] == frozenset({target})

    resolved = _resolve_arithmetic_state_feeder(
        graph,
        dag,
        transition,
        dispatcher,
    )

    assert len(resolved) == 1
    upgraded = resolved[0]
    assert upgraded.next_state == state
    assert upgraded.target_handler == target
    assert upgraded.is_return is False
    assert upgraded.proof is not None
    assert upgraded.proof.oracle_kind == "exact_state_transform_decision_dag_route"
    assert upgraded.proof.kind == "state_transform_decision_dag_reconciled"
    assert upgraded.proof.trusted is True
    assert upgraded.proof.route_source_kinds == (
        "decision_dag",
        "interval",
        "state_transform_feeder",
    )


def _captured_six_transform_fixture() -> tuple[
    FlowGraph,
    DecisionDag,
    tuple[StateWriteTransition, ...],
    object,
]:
    rows = (
        (349, 403, ValueOpKind.XOR, 0x85CE363D, 0x84D43EBC, 0x011A0881, 100, True),
        (402, 403, ValueOpKind.XOR, 0xD538AF4C, 0xE6E10C5C, 0x33D9A310, 242, True),
        (303, 490, ValueOpKind.SUB, 0xB24F8C14, 0x8E1DAD8C, 0x2431DE88, 221, True),
        (489, 490, ValueOpKind.SUB, 0x6F3B459D, 0x540A745D, 0x1B30D140, 250, False),
        (363, 495, ValueOpKind.SUB, 0x6A1454EE, 0x3BFE4A5E, 0x2E160A90, 371, True),
        (494, 495, ValueOpKind.SUB, 0x2A7B0077, 0x28360137, 0x0244FF40, 270, False),
    )
    source_eas = {
        349: 0x1800239A2,
        402: 0x1800266E9,
        303: 0x18001EEDC,
        489: 0x18002B4AE,
        363: 0x180024B61,
        494: 0x18002BC45,
    }
    feeder_eas = {403: 0x18002672A, 490: 0x18002B4D9, 495: 0x18002BC5F}
    blocks: dict[int, BlockSnapshot] = {}
    transitions: list[StateWriteTransition] = []
    feeder_rows: dict[int, tuple[ValueOpKind, tuple[int, int]]] = {}
    feeder_preds: dict[int, list[int]] = {403: [], 490: [], 495: []}
    for source, feeder, operation, left, right, state, target, trusted in rows:
        feeder_preds[feeder].append(source)
        feeder_rows.setdefault(feeder, (operation, (8, 9)))
        blocks[source] = _blk(
            source,
            (feeder,),
            (),
            (
                _mov(source_eas[source], _num(left), _reg(8)),
                _mov(source_eas[source] + 5, _num(right), _reg(9)),
                _goto(source_eas[source] + 10, feeder),
            ),
            ea=source_eas[source],
        )
        transitions.append(
            StateWriteTransition(
                source,
                state,
                target if trusted else None,
                not trusted,
                None,
                via_block=feeder,
                proof=TransitionProof(
                    "region_partitioned_fixpoint",
                    "predecessor_partitioned",
                    trusted,
                    route_source_kinds=("interval",) if trusted else (),
                ),
            )
        )
    for feeder, (operation, registers) in feeder_rows.items():
        transform = (
            _xor(
                feeder_eas[feeder],
                _reg(registers[0]),
                _reg(registers[1]),
                _stk(_STATE_OFF),
            )
            if operation is ValueOpKind.XOR
            else _sub(
                feeder_eas[feeder],
                _reg(registers[0]),
                _reg(registers[1]),
                _stk(_STATE_OFF),
            )
        )
        blocks[feeder] = _blk(
            feeder,
            (15,),
            tuple(feeder_preds[feeder]),
            (transform, _goto(feeder_eas[feeder] + 5, 15)),
            ea=feeder_eas[feeder],
        )

    comparison_serials = (15, 16, 17, 18, 19, 20)
    targets = tuple(int(row[6]) for row in rows)
    states = tuple(int(row[5]) for row in rows)
    comparisons: dict[int, RouteComparison] = {}
    for index, (serial, state, target) in enumerate(
        zip(comparison_serials, states, targets, strict=True)
    ):
        alternate = comparison_serials[index + 1] if index + 1 < 6 else 999
        blocks[serial] = _blk(
            serial,
            (target, alternate),
            tuple(feeder_rows) if index == 0 else (comparison_serials[index - 1],),
            (_jz_stack_const(0x180015268 + index * 0x10, _STATE_OFF, state, target),),
            ea=0x180015268 + index * 0x10,
        )
        comparisons[serial] = RouteComparison(serial, "jz", state, target, alternate)
    for comparison_serial, target in zip(comparison_serials, targets, strict=True):
        blocks[target] = _blk(
            target,
            (999,),
            (comparison_serial,),
            (),
            ea=0x180030000 + target,
        )
    blocks[999] = _stop(999, targets)
    graph = FlowGraph(blocks, 349, 0x180015110)
    dag = DecisionDag(32, comparisons, root=15)
    dispatcher = _DualRouteDispatcher(
        exact_targets={},
        interval_rows=tuple(
            IntervalRow(state, state + 1, target)
            for state, target in zip(states, targets, strict=True)
        ),
        default_target=999,
    )
    return graph, dag, tuple(transitions), dispatcher


def test_captured_six_transform_rows_reconcile_atomically_in_source_order(
    _seam,
) -> None:
    graph, dag, transitions, dispatcher = _captured_six_transform_fixture()

    resolved = resolve_materialized_indirect_transfer_targets(
        transitions,
        graph,
        dispatcher,
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({100, 221, 242, 250, 270, 371}),
        state_var_stkoff=_STATE_OFF,
    )

    assert tuple(item.write_block for item in resolved) == (
        349,
        402,
        303,
        489,
        363,
        494,
    )
    assert tuple(item.target_handler for item in resolved) == (
        100,
        242,
        221,
        250,
        371,
        270,
    )
    assert all(item.proof is not None and item.proof.trusted for item in resolved)
    assert resolved[3].proof is not None
    assert resolved[3].proof.oracle_kind == "exact_state_transform_decision_dag_route"
    assert resolved[5].proof is not None
    assert resolved[5].proof.oracle_kind == "exact_state_transform_decision_dag_route"


@pytest.mark.parametrize(
    "variant",
    (
        "missing-proof",
        "untrusted-multi-entry-proof",
        "weak-region-seeded-proof",
        "partial-proof",
        "unresolved-proof",
        "foreign-oracle-proof",
        "concrete-state-mismatch",
        "missing-left-definition",
        "clobber-after-definitions",
        "barrier-after-definitions",
        "swapped-operands",
        "wrong-state-identity",
        "wrong-width",
        "call",
        "store",
        "global-read",
        "unknown",
        "extra-value",
        "feeder-fork",
        "wrong-root",
        "missing-source-reciprocity",
        "missing-root-reciprocity",
        "unsupported-operation",
        "stale-source-ea",
        "stale-feeder-ea",
        "stale-root-ea",
    ),
)
def test_arithmetic_state_feeder_malformed_evidence_rejects_atomically(
    _seam,
    variant: str,
) -> None:
    if variant == "swapped-operands":
        graph, dag, transition, dispatcher = _arithmetic_state_feeder_fixture(
            operation=ValueOpKind.SUB,
            left=0xB24F8C14,
            right=0x8E1DAD8C,
            state=0x2431DE88,
            source_serial=303,
            feeder_serial=490,
            source_ea=0x18001EEDC,
            feeder_ea=0x18002B4D9,
        )
    else:
        graph, dag, transition, dispatcher = _arithmetic_state_feeder_fixture()
    source_serial = int(transition.write_block)
    assert transition.via_block is not None
    feeder_serial = int(transition.via_block)
    blocks = dict(graph.blocks)
    source = blocks[source_serial]
    feeder = blocks[feeder_serial]
    root = blocks[15]
    source_insns = source.insn_snapshots
    feeder_insns = feeder.insn_snapshots

    if variant == "missing-proof":
        transition = replace(transition, proof=None)
    elif variant == "untrusted-multi-entry-proof":
        transition = replace(
            transition,
            proof=TransitionProof(
                "region_partitioned_fixpoint",
                "multi_entry_global_fold",
                False,
                route_source_kinds=(),
            ),
        )
    elif variant == "weak-region-seeded-proof":
        transition = replace(
            transition,
            proof=TransitionProof(
                "region_partitioned_fixpoint",
                "region_seeded",
                True,
                route_source_kinds=("interval",),
            ),
        )
    elif variant == "partial-proof":
        transition = replace(
            transition,
            proof=TransitionProof(
                "region_partitioned_fixpoint",
                "partial_predecessor",
                True,
                route_source_kinds=("interval",),
            ),
        )
    elif variant == "unresolved-proof":
        transition = replace(
            transition,
            proof=TransitionProof(
                "region_partitioned_fixpoint",
                "unresolved",
                True,
                route_source_kinds=("interval",),
            ),
        )
    elif variant == "foreign-oracle-proof":
        transition = replace(
            transition,
            proof=TransitionProof(
                "foreign_oracle",
                "predecessor_partitioned",
                True,
                route_source_kinds=("interval",),
            ),
        )
    elif variant == "concrete-state-mismatch":
        transition = replace(
            transition,
            next_state=_ARITHMETIC_FEEDER_STATE + 1,
        )
    elif variant == "missing-left-definition":
        source_insns = source_insns[1:]
    elif variant == "clobber-after-definitions":
        source_insns = (
            *source_insns[:-1],
            _mov(source.start_ea + 8, _num(0), _reg(8)),
            source_insns[-1],
        )
    elif variant == "barrier-after-definitions":
        source_insns = (
            *source_insns[:-1],
            InsnSnapshot(
                opcode=0x41,
                ea=source.start_ea + 8,
                operands=(),
                kind=InsnKind.CALL,
                call_kind=CallKind.DIRECT,
            ),
            source_insns[-1],
        )
    elif variant == "swapped-operands":
        transform = feeder_insns[0]
        feeder_insns = (
            replace(transform, l=transform.r, r=transform.l),
            *feeder_insns[1:],
        )
    elif variant == "wrong-state-identity":
        transform = feeder_insns[0]
        feeder_insns = (replace(transform, d=_stk(_STATE_OFF + 4)), *feeder_insns[1:])
    elif variant == "wrong-width":
        transform = feeder_insns[0]
        feeder_insns = (
            replace(
                transform,
                l=replace(transform.l, size=8),
                r=replace(transform.r, size=8),
                d=replace(transform.d, size=8),
            ),
            *feeder_insns[1:],
        )
    elif variant == "call":
        feeder_insns = (
            feeder_insns[0],
            InsnSnapshot(
                opcode=0x41,
                ea=0x18002672C,
                operands=(),
                kind=InsnKind.CALL,
                call_kind=CallKind.DIRECT,
            ),
            *feeder_insns[1:],
        )
    elif variant == "store":
        feeder_insns = (
            feeder_insns[0],
            _store(0x18002672C, _num(1), _global(0x18004C000)),
            *feeder_insns[1:],
        )
    elif variant == "global-read":
        feeder_insns = (
            feeder_insns[0],
            _mov(0x18002672C, _global(0x18004C000), _reg(10)),
            *feeder_insns[1:],
        )
    elif variant == "unknown":
        feeder_insns = (
            feeder_insns[0],
            InsnSnapshot(
                opcode=0xDE,
                ea=0x18002672C,
                operands=(),
                kind=InsnKind.UNKNOWN,
            ),
            *feeder_insns[1:],
        )
    elif variant == "extra-value":
        feeder_insns = (
            feeder_insns[0],
            _mov(0x18002672C, _num(1), _reg(10)),
            *feeder_insns[1:],
        )
    elif variant == "feeder-fork":
        blocks[feeder_serial] = replace(feeder, succs=(15, 101))
    elif variant == "wrong-root":
        blocks[feeder_serial] = replace(feeder, succs=(101,))
    elif variant == "missing-source-reciprocity":
        blocks[feeder_serial] = replace(feeder, preds=())
    elif variant == "missing-root-reciprocity":
        blocks[15] = replace(root, preds=())
    elif variant == "unsupported-operation":
        transform = feeder_insns[0]
        feeder_insns = (
            replace(
                transform,
                opcode=0xDE,
                kind=InsnKind.UNKNOWN,
                value_op_kind=ValueOpKind.AND,
            ),
            *feeder_insns[1:],
        )
    elif variant == "stale-source-ea":
        blocks[source_serial] = replace(source, start_ea=0)
    elif variant == "stale-feeder-ea":
        blocks[feeder_serial] = replace(feeder, start_ea=0)
    elif variant == "stale-root-ea":
        blocks[15] = replace(root, start_ea=0)

    if source_insns is not source.insn_snapshots:
        blocks[source_serial] = replace(
            blocks[source_serial],
            insn_snapshots=source_insns,
        )
    if feeder_insns is not feeder.insn_snapshots:
        blocks[feeder_serial] = replace(
            blocks[feeder_serial],
            insn_snapshots=feeder_insns,
        )
    malformed = FlowGraph(blocks, graph.entry_serial, graph.func_ea)

    assert (
        _resolve_arithmetic_state_feeder(
            malformed,
            dag,
            transition,
            dispatcher,
        )
        == ()
    )


def test_arithmetic_state_feeder_provider_disagreement_rejects_atomically(
    _seam,
) -> None:
    graph, dag, transition, _dispatcher_unused = _arithmetic_state_feeder_fixture()
    conflicting = _DualRouteDispatcher(
        exact_targets={_ARITHMETIC_FEEDER_STATE: 101},
        interval_rows=(
            IntervalRow(
                _ARITHMETIC_FEEDER_STATE,
                _ARITHMETIC_FEEDER_STATE + 1,
                100,
            ),
        ),
        default_target=200,
    )

    assert (
        _resolve_arithmetic_state_feeder(
            graph,
            dag,
            transition,
            conflicting,
        )
        == ()
    )


def test_arithmetic_state_feeder_provenance_binds_native_block_eas(_seam) -> None:
    graph, dag, transition, dispatcher = _arithmetic_state_feeder_fixture()
    source_serial = int(transition.write_block)
    assert transition.via_block is not None
    feeder_serial = int(transition.via_block)
    native_source_ea = 0x7FF855570100
    native_feeder_ea = 0x7FF855570200
    native_root_ea = 0x7FF855570300
    blocks = dict(graph.blocks)
    blocks[source_serial] = replace(
        blocks[source_serial],
        start_ea=0x1100,
        native_start_ea=native_source_ea,
    )
    blocks[feeder_serial] = replace(
        blocks[feeder_serial],
        start_ea=0x1200,
        native_start_ea=native_feeder_ea,
    )
    blocks[15] = replace(
        blocks[15],
        start_ea=0x1300,
        native_start_ea=native_root_ea,
    )

    resolved = _resolve_arithmetic_state_feeder(
        FlowGraph(blocks, graph.entry_serial, graph.func_ea),
        dag,
        transition,
        dispatcher,
    )

    assert len(resolved) == 1
    assert resolved[0].proof is not None
    reason = resolved[0].proof.reason
    assert f"source_ea=0x{native_source_ea:x}" in reason
    assert f"feeder_ea=0x{native_feeder_ea:x}" in reason
    assert f"root_ea=0x{native_root_ea:x}" in reason
    assert "source_ea=0x1100" not in reason
    assert "feeder_ea=0x1200" not in reason
    assert "root_ea=0x1300" not in reason


_PREFIX_SELECTED_STATE = 0x16AA65E9
_PREFIX_ALTERNATE_STATE = 0x50884FCC
_PREFIX_COMPARE_STATE = 0x423C3FEB
_DAG_COMPARE_STATE = 0x0EE1BCAD


def _candidate_scoped_prefix_fixture() -> tuple[FlowGraph, DecisionDag]:
    """Faithful A-shaped omitted prefix above selected equality root15.

    blk4@0x180037940 is current router plumbing.  Its selected JLE arm enters
    blk15@0x1800379D8; its alternate arm remains semantic and must never be
    redirected by recovery.  The concrete writer serials mirror the saved A
    snapshot identity even though the portable instruction EAs are synthetic.
    """

    graph = FlowGraph(
        blocks={
            4: _blk(
                4,
                (15, 20),
                (401, 402),
                (
                    _jle_stack_const(
                        0x180037970,
                        _STATE_OFF,
                        _PREFIX_COMPARE_STATE,
                        15,
                    ),
                ),
                ea=0x180037940,
            ),
            15: _blk(
                15,
                (100, 101),
                (4, 403, 490, 495),
                (
                    _jz_stack_const(
                        0x180037A08,
                        _STATE_OFF,
                        _DAG_COMPARE_STATE,
                        100,
                    ),
                ),
                ea=0x1800379D8,
            ),
            20: _blk(20, (200,), (4,), (), ea=0x180037A40),
            100: _blk(100, (401, 403, 490), (15,), (), ea=0x180038100),
            101: _blk(101, (402, 495), (15,), (), ea=0x180038140),
            200: _stop(200, (20,)),
            401: _blk(
                401,
                (4,),
                (100,),
                (
                    _mov(
                        0x180046F00,
                        _num(_PREFIX_ALTERNATE_STATE),
                        _stk(_STATE_OFF),
                    ),
                ),
                ea=0x180046EF0,
            ),
            402: _blk(
                402,
                (4,),
                (101,),
                (
                    _mov(
                        0x180047000,
                        _num(_PREFIX_SELECTED_STATE),
                        _stk(_STATE_OFF),
                    ),
                ),
                ea=0x180046FF0,
            ),
            403: _blk(
                403,
                (15,),
                (100,),
                (
                    _mov(
                        0x180047100,
                        _num(_PREFIX_SELECTED_STATE),
                        _stk(_STATE_OFF),
                    ),
                ),
                ea=0x1800470F0,
            ),
            490: _blk(
                490,
                (15,),
                (100,),
                (
                    _mov(
                        0x18004A100,
                        _num(_PREFIX_ALTERNATE_STATE),
                        _stk(_STATE_OFF),
                    ),
                ),
                ea=0x18004A0F0,
            ),
            495: _blk(
                495,
                (15,),
                (101,),
                (
                    _mov(
                        0x18004A600,
                        _num(_DAG_COMPARE_STATE),
                        _stk(_STATE_OFF),
                    ),
                ),
                ea=0x18004A5F0,
            ),
        },
        entry_serial=15,
        func_ea=0x180037880,
    )
    dag = DecisionDag(
        32,
        {
            15: RouteComparison(
                15,
                "jz",
                _DAG_COMPARE_STATE,
                100,
                101,
            ),
        },
        root=15,
    )
    return graph, dag


def _resolve_candidate_scoped_prefix(
    graph: FlowGraph,
    dag: DecisionDag,
    *,
    dispatcher: object | None = None,
) -> tuple[StateWriteTransition, ...]:
    router = dispatcher or _dispatcher(
        {
            _PREFIX_SELECTED_STATE: 101,
            _PREFIX_ALTERNATE_STATE: 101,
            _DAG_COMPARE_STATE: 100,
        },
        exit_block=200,
    )
    recovered = recover_state_write_transitions_via_partitioned_fixpoint(
        graph,
        router,
        _STATE_OFF,
        dispatcher_entry_serial=15,
        dispatcher_region_serials=frozenset({15}),
        include_multi_entry_back_edges=True,
    )
    return resolve_materialized_indirect_transfer_targets(
        recovered,
        graph,
        router,
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({100, 101}),
        state_var_stkoff=_STATE_OFF,
    )


def test_candidate_scoped_prefix_recovers_only_writers_selecting_entry_arm(
    _seam,
) -> None:
    graph, dag = _candidate_scoped_prefix_fixture()

    resolved = _resolve_candidate_scoped_prefix(graph, dag)

    by_source = {int(row.write_block): row for row in resolved}
    assert set(by_source) == {402, 403, 490, 495}
    assert by_source[402].next_state == _PREFIX_SELECTED_STATE
    assert by_source[402].target_handler == 101
    assert by_source[403].target_handler == 101
    assert by_source[490].target_handler == 101
    assert by_source[495].target_handler == 100
    assert all(row.proof is not None and row.proof.trusted for row in resolved)
    assert "candidate_scoped_prefix_arm" in (
        by_source[402].proof.route_source_kinds
        if by_source[402].proof is not None
        else ()
    )
    for source in (403, 490, 495):
        proof = by_source[source].proof
        assert proof is not None
        assert "decision_dag" in proof.route_source_kinds
        assert "candidate_scoped_prefix_arm" not in proof.route_source_kinds
    # The comparison prefix is router plumbing, while the state that selects
    # its alternate arm stays on the original 401->4 edge. Direct-root writer
    # 490 is deliberately admitted even though that same state would take the
    # prefix's alternate arm because its physical edge bypasses blk4.
    assert all(row.write_block not in {4, 401} for row in resolved)
    assert graph.get_block(4).succs == (15, 20)
    assert graph.get_block(401).succs == (4,)
    assert graph.get_block(490).succs == (15,)


@pytest.mark.parametrize(
    "variant",
    (
        "effectful-prefix",
        "swapped-operands",
        "wrong-width",
        "stale-prefix-ea",
        "missing-reciprocal-pred",
        "ambiguous-second-prefix",
    ),
)
def test_candidate_scoped_prefix_invalid_evidence_rejects_fragment_atomically(
    _seam,
    variant: str,
) -> None:
    graph, dag = _candidate_scoped_prefix_fixture()
    prefix = graph.get_block(4)
    entry = graph.get_block(15)
    assert prefix is not None and entry is not None
    blocks = dict(graph.blocks)

    if variant == "effectful-prefix":
        call = InsnSnapshot(
            opcode=0x41,
            ea=0x180037968,
            operands=(),
            kind=InsnKind.CALL,
            call_kind=CallKind.DIRECT,
        )
        blocks[4] = replace(prefix, insn_snapshots=(call, *prefix.insn_snapshots))
    elif variant == "swapped-operands":
        branch = prefix.insn_snapshots[0]
        blocks[4] = replace(
            prefix,
            insn_snapshots=(replace(branch, l=branch.r, r=branch.l),),
        )
    elif variant == "wrong-width":
        branch = prefix.insn_snapshots[0]
        blocks[4] = replace(
            prefix,
            insn_snapshots=(
                replace(
                    branch,
                    l=replace(branch.l, size=8),
                    r=replace(branch.r, size=8),
                ),
            ),
        )
    elif variant == "stale-prefix-ea":
        blocks[4] = replace(prefix, start_ea=0)
    elif variant == "missing-reciprocal-pred":
        blocks[15] = replace(entry, preds=(403, 490, 495))
    elif variant == "ambiguous-second-prefix":
        second_branch = replace(
            prefix.insn_snapshots[0],
            ea=0x180037990,
            d=replace(prefix.insn_snapshots[0].d, block_ref=15),
        )
        blocks[7] = _blk(
            7,
            (15, 21),
            (405,),
            (second_branch,),
            ea=0x180037980,
        )
        blocks[21] = _blk(21, (200,), (7,), (), ea=0x180037A60)
        blocks[405] = _blk(
            405,
            (7,),
            (),
            (
                _mov(
                    0x180047300,
                    _num(_PREFIX_SELECTED_STATE),
                    _stk(_STATE_OFF),
                ),
            ),
            ea=0x1800472F0,
        )
        blocks[15] = replace(entry, preds=(*entry.preds, 7))

    malformed = FlowGraph(
        blocks=blocks,
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )
    assert _resolve_candidate_scoped_prefix(malformed, dag) == ()


def test_candidate_scoped_prefix_preserves_provider_consensus_atomicity(
    _seam,
) -> None:
    graph, dag = _candidate_scoped_prefix_fixture()
    conflicting = _DualRouteDispatcher(
        exact_targets={_PREFIX_SELECTED_STATE: 100},
        interval_rows=(
            IntervalRow(
                _PREFIX_SELECTED_STATE,
                _PREFIX_SELECTED_STATE + 1,
                101,
            ),
        ),
        default_target=200,
    )

    assert (
        _resolve_candidate_scoped_prefix(
            graph,
            dag,
            dispatcher=conflicting,
        )
        == ()
    )


@pytest.mark.parametrize("proof_mode", ("missing", "untrusted", "missing-state"))
def test_candidate_scoped_prefix_requires_trusted_concrete_transition(
    _seam,
    proof_mode: str,
) -> None:
    graph, dag = _candidate_scoped_prefix_fixture()
    recovered = recover_state_write_transitions_via_partitioned_fixpoint(
        graph,
        _dispatcher(
            {
                _PREFIX_SELECTED_STATE: 101,
                _PREFIX_ALTERNATE_STATE: 101,
                _DAG_COMPARE_STATE: 100,
            },
            exit_block=200,
        ),
        _STATE_OFF,
        dispatcher_entry_serial=15,
        dispatcher_region_serials=frozenset({15}),
        include_multi_entry_back_edges=True,
    )
    selected = next(row for row in recovered if int(row.write_block) == 402)
    if proof_mode == "missing":
        selected = replace(selected, proof=None)
    elif proof_mode == "untrusted":
        assert selected.proof is not None
        selected = replace(selected, proof=replace(selected.proof, trusted=False))
    else:
        selected = replace(selected, next_state=None)

    assert (
        resolve_materialized_indirect_transfer_targets(
            (selected,),
            graph,
            _dispatcher({_PREFIX_SELECTED_STATE: 101}, exit_block=200),
            (),
            condition_chain_dag=dag,
            condition_chain_handlers=frozenset({100, 101}),
            state_var_stkoff=_STATE_OFF,
        )
        == ()
    )


def test_candidate_scoped_prefix_revalidates_source_edge_before_selection(
    _seam,
) -> None:
    graph, dag = _candidate_scoped_prefix_fixture()
    dispatcher = _dispatcher(
        {
            _PREFIX_SELECTED_STATE: 101,
            _PREFIX_ALTERNATE_STATE: 101,
            _DAG_COMPARE_STATE: 100,
        },
        exit_block=200,
    )
    recovered = recover_state_write_transitions_via_partitioned_fixpoint(
        graph,
        dispatcher,
        _STATE_OFF,
        dispatcher_entry_serial=15,
        dispatcher_region_serials=frozenset({15}),
        include_multi_entry_back_edges=True,
    )
    selected = next(row for row in recovered if int(row.write_block) == 402)
    source = graph.get_block(402)
    prefix = graph.get_block(4)
    alternate = graph.get_block(20)
    assert source is not None and prefix is not None and alternate is not None
    blocks = dict(graph.blocks)
    blocks[402] = replace(source, succs=(20,))
    blocks[4] = replace(prefix, preds=(401,))
    blocks[20] = replace(alternate, preds=(*alternate.preds, 402))
    drifted = FlowGraph(blocks, graph.entry_serial, graph.func_ea)

    assert (
        resolve_materialized_indirect_transfer_targets(
            (selected,),
            drifted,
            dispatcher,
            (),
            condition_chain_dag=dag,
            condition_chain_handlers=frozenset({100, 101}),
            state_var_stkoff=_STATE_OFF,
        )
        == ()
    )


def test_candidate_scoped_prefix_ignores_different_state_comparison_parent(
    _seam,
) -> None:
    graph, dag = _candidate_scoped_prefix_fixture()
    blocks = dict(graph.blocks)
    root = blocks[15]
    stop = blocks[200]
    blocks[7] = _blk(
        7,
        (15, 21),
        (405,),
        (
            _jle_stack_const(
                0x180037990,
                _STATE_OFF + 4,
                _PREFIX_COMPARE_STATE,
                15,
            ),
        ),
        ea=0x180037980,
    )
    blocks[21] = _blk(21, (200,), (7,), (), ea=0x180037A60)
    blocks[405] = _blk(
        405,
        (7,),
        (100,),
        (
            _mov(
                0x180047300,
                _num(_PREFIX_SELECTED_STATE),
                _stk(_STATE_OFF),
            ),
        ),
        ea=0x1800472F0,
    )
    blocks[100] = replace(blocks[100], succs=(*blocks[100].succs, 405))
    blocks[15] = replace(root, preds=(*root.preds, 7))
    blocks[200] = replace(stop, preds=(*stop.preds, 21))
    extended = FlowGraph(blocks, graph.entry_serial, graph.func_ea)

    resolved = _resolve_candidate_scoped_prefix(extended, dag)
    by_source = {int(row.write_block): row for row in resolved}
    assert set(by_source) == {7, 402, 403, 405, 490, 495}
    for source in (7, 405):
        proof = by_source[source].proof
        assert proof is not None
        assert "decision_dag" in proof.route_source_kinds
        assert "candidate_scoped_prefix_arm" not in proof.route_source_kinds


def test_candidate_scoped_prefix_is_deterministic_across_block_insertion_order(
    _seam,
) -> None:
    graph, dag = _candidate_scoped_prefix_fixture()
    reordered = FlowGraph(
        dict(reversed(tuple(graph.blocks.items()))),
        graph.entry_serial,
        graph.func_ea,
    )

    assert _resolve_candidate_scoped_prefix(reordered, dag) == (
        _resolve_candidate_scoped_prefix(graph, dag)
    )


def _candidate_prefix_partitioned_feeder_fixture() -> tuple[FlowGraph, DecisionDag]:
    """Current-snapshot prefix fed by one predecessor-partitioned XOR block.

    Writers 401 and 402 reach prefix4 only through feeder330.  Their concrete
    register definitions fold to different states at the shared XOR feeder;
    only writer402 selects prefix4's root15 arm.  Writers 403/490/495 enter
    root15 directly and therefore are never filtered by prefix4's predicate.
    """

    selected_left = 0x12345678
    alternate_left = 0x11111111
    graph = FlowGraph(
        blocks={
            4: _blk(
                4,
                (15, 20),
                (330,),
                (
                    _jle_stack_const(
                        0x180037970,
                        _STATE_OFF,
                        _PREFIX_COMPARE_STATE,
                        15,
                    ),
                ),
                ea=0x180037940,
            ),
            15: _blk(
                15,
                (100, 101),
                (4, 403, 490, 495),
                (
                    _jz_stack_const(
                        0x180037A08,
                        _STATE_OFF,
                        _DAG_COMPARE_STATE,
                        100,
                    ),
                ),
                ea=0x1800379D8,
            ),
            20: _blk(20, (200,), (4,), (), ea=0x180037A40),
            100: _blk(100, (401, 403, 490), (15,), (), ea=0x180038100),
            101: _blk(101, (402, 495), (15,), (), ea=0x180038140),
            200: _stop(200, (20,)),
            330: _blk(
                330,
                (4,),
                (401, 402),
                (_xor(0x180042930, _reg(8), _reg(9), _stk(_STATE_OFF)),),
                ea=0x180042900,
            ),
            401: _blk(
                401,
                (330,),
                (100,),
                (
                    _mov(0x180046F00, _num(alternate_left), _reg(8)),
                    _mov(
                        0x180046F04,
                        _num(alternate_left ^ _PREFIX_ALTERNATE_STATE),
                        _reg(9),
                    ),
                ),
                ea=0x180046EF0,
            ),
            402: _blk(
                402,
                (330,),
                (101,),
                (
                    _mov(0x180047000, _num(selected_left), _reg(8)),
                    _mov(
                        0x180047004,
                        _num(selected_left ^ _PREFIX_SELECTED_STATE),
                        _reg(9),
                    ),
                ),
                ea=0x180046FF0,
            ),
            403: _blk(
                403,
                (15,),
                (100,),
                (_mov(0x180047100, _num(_PREFIX_SELECTED_STATE), _stk(_STATE_OFF)),),
                ea=0x1800470F0,
            ),
            490: _blk(
                490,
                (15,),
                (100,),
                (_mov(0x18004A100, _num(_PREFIX_ALTERNATE_STATE), _stk(_STATE_OFF)),),
                ea=0x18004A0F0,
            ),
            495: _blk(
                495,
                (15,),
                (101,),
                (_mov(0x18004A600, _num(_DAG_COMPARE_STATE), _stk(_STATE_OFF)),),
                ea=0x18004A5F0,
            ),
        },
        entry_serial=15,
        func_ea=0x180037880,
    )
    return graph, DecisionDag(
        32,
        {
            15: RouteComparison(
                15,
                "jz",
                _DAG_COMPARE_STATE,
                100,
                101,
            ),
        },
        root=15,
    )


def _candidate_prefix_partitioned_dispatcher() -> object:
    return _dispatcher(
        {
            _PREFIX_SELECTED_STATE: 101,
            _PREFIX_ALTERNATE_STATE: 101,
            _DAG_COMPARE_STATE: 100,
        },
        exit_block=200,
    )


def test_empty_switch_table_dag_is_not_candidate_prefix_authority(_seam) -> None:
    """A switch-table root is not an OLLVM comparison-prefix candidate."""

    graph, dag = _candidate_prefix_partitioned_feeder_fixture()
    observation = minimal_state_recovery.observe_candidate_scoped_prefix_authority(
        graph,
        DecisionDag(dag.width, {}, root=dag.root),
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
    )

    assert observation.status is minimal_state_recovery.CandidatePrefixStatus.NOT_APPLICABLE
    assert observation.authority is None


def _candidate_prefix_partitioned_transitions() -> tuple[StateWriteTransition, ...]:
    def row(source: int, state: int, target: int, via: int) -> StateWriteTransition:
        return StateWriteTransition(
            source,
            state,
            target,
            False,
            None,
            via_block=via,
            proof=TransitionProof(
                "region_partitioned_fixpoint",
                "predecessor_partitioned" if via == 330 else "global_fold",
                True,
            ),
        )

    return (
        row(401, _PREFIX_ALTERNATE_STATE, 101, 330),
        row(402, _PREFIX_SELECTED_STATE, 101, 330),
        row(403, _PREFIX_SELECTED_STATE, 101, 15),
        row(490, _PREFIX_ALTERNATE_STATE, 101, 15),
        row(495, _DAG_COMPARE_STATE, 100, 15),
    )


def test_candidate_prefix_records_exact_alternate_corridor_partition(_seam) -> None:
    """The omitted prefix arm remains a typed, source-bound coverage fact."""

    graph, dag = _candidate_prefix_partitioned_feeder_fixture()
    observation = minimal_state_recovery.observe_candidate_scoped_prefix_authority(
        graph,
        dag,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
    )
    assert observation.authority is not None

    proofs = minimal_state_recovery.collect_candidate_prefix_alternate_corridor_proofs(
        graph,
        _candidate_prefix_partitioned_transitions(),
        observation.authority,
    )

    assert len(proofs) == 1
    proof = proofs[0]
    assert proof.normalized_state == _PREFIX_ALTERNATE_STATE
    assert (
        proof.source_serial,
        proof.source_ea,
        proof.feeder_serial,
        proof.feeder_ea,
        proof.prefix_serial,
        proof.prefix_ea,
        proof.root_serial,
        proof.root_ea,
    ) == (
        401,
        0x180046EF0,
        330,
        0x180042900,
        4,
        0x180037940,
        15,
        0x1800379D8,
    )


def test_candidate_prefix_recovers_each_partitioned_feeder_source_without_seeded_walk(
    _seam,
    monkeypatch,
) -> None:
    """A shared prefix feeder is a pseudo-backedge, not one merged writer."""

    graph, dag = _candidate_prefix_partitioned_feeder_fixture()
    observation = minimal_state_recovery.observe_candidate_scoped_prefix_authority(
        graph,
        dag,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
    )
    assert observation.authority is not None

    monkeypatch.setattr(
        minimal_state_recovery,
        "_resolve_back_edge_states",
        lambda *_args, **_kwargs: pytest.fail(
            "candidate prefix feeders must never enter seeded/global discovery"
        ),
    )
    for candidate in (
        graph,
        FlowGraph(
            dict(reversed(tuple(graph.blocks.items()))),
            graph.entry_serial,
            graph.func_ea,
        ),
    ):
        recovered = recover_state_write_transitions_via_partitioned_fixpoint(
            candidate,
            _candidate_prefix_partitioned_dispatcher(),
            _STATE_OFF,
            dispatcher_entry_serial=15,
            dispatcher_region_serials=frozenset({4, 15}),
            candidate_prefix_authority=observation.authority,
        )

        by_source = {int(row.write_block): row for row in recovered}
        assert tuple(by_source) == (401, 402, 403, 490, 495)
        for source, state in (
            (401, _PREFIX_ALTERNATE_STATE),
            (402, _PREFIX_SELECTED_STATE),
        ):
            row = by_source[source]
            assert row.via_block == 330
            assert row.next_state == state
            assert row.proof is not None
            assert row.proof.kind == "predecessor_partitioned"


def _candidate_prefix_incomplete_feeder_fixture() -> tuple[FlowGraph, DecisionDag]:
    """Root15 has three complete direct groups and one incomplete prefix group."""

    blocks = {
        4: _blk(
            4,
            (5, 15),
            (3,),
            (
                _jle_stack_const(
                    0x1800151DB,
                    _STATE_OFF,
                    0x423C3FEB,
                    15,
                ),
            ),
            ea=0x1800151D0,
        ),
        5: _blk(5, (200,), (4,), (), ea=0x1800151E1),
        15: _blk(
            15,
            (100, 101),
            (4, 405, 492, 497),
            (_jz_stack_const(0x180015298, _STATE_OFF, 0x0EE1BCAD, 100),),
            ea=0x180015268,
        ),
        100: _blk(100, (2, 351, 305, 365), (15,), (), ea=0x180016300),
        101: _blk(101, (230, 404, 491, 496), (15,), (), ea=0x180016340),
        200: _stop(200, (5,)),
        2: _blk(
            2,
            (3,),
            (100,),
            (_mov(0x1800151A0, _num(0x704FAFF6), _reg(8)),),
            ea=0x18001519C,
        ),
        230: _blk(
            230,
            (3,),
            (101,),
            (_mov(0x18001A936, _num(0x60A0D558), _reg(8)),),
            ea=0x18001A932,
        ),
        3: _blk(
            3,
            (4,),
            (2, 230),
            (_mov(0x1800151C9, _reg(8), _stk(_STATE_OFF)),),
            ea=0x1800151C9,
        ),
        351: _blk(351, (405,), (100,), (), ea=0x1800239A2),
        404: _blk(404, (405,), (101,), (), ea=0x1800266E9),
        405: _blk(
            405,
            (15,),
            (351, 404),
            (_mov(0x18002672A, _reg(8), _stk(_STATE_OFF)),),
            ea=0x18002672A,
        ),
        305: _blk(305, (492,), (100,), (), ea=0x18001EEDC),
        491: _blk(491, (492,), (101,), (), ea=0x18002B4AE),
        492: _blk(
            492,
            (15,),
            (305, 491),
            (_mov(0x18002B4D9, _reg(8), _stk(_STATE_OFF)),),
            ea=0x18002B4D9,
        ),
        365: _blk(365, (497,), (100,), (), ea=0x180024B61),
        496: _blk(496, (497,), (101,), (), ea=0x18002BC45),
        497: _blk(
            497,
            (15,),
            (365, 496),
            (_mov(0x18002BC5F, _reg(8), _stk(_STATE_OFF)),),
            ea=0x18002BC5F,
        ),
    }
    return FlowGraph(blocks, 15, 0x180015110), DecisionDag(
        32,
        {15: RouteComparison(15, "jz", 0x0EE1BCAD, 100, 101)},
        root=15,
    )


def _captured_prefix_provider_rows() -> dict[int, tuple[StateWriteTransition, ...]]:
    def row(
        source: int,
        via: int,
        state: int,
        target: int | None,
        *,
        trusted: bool,
    ) -> StateWriteTransition:
        return StateWriteTransition(
            source,
            state,
            target,
            target is None,
            None,
            via_block=via,
            proof=TransitionProof(
                "region_partitioned_fixpoint",
                "predecessor_partitioned",
                trusted,
            ),
        )

    return {
        405: (
            row(351, 405, 0x011A0881, 100, trusted=True),
            row(404, 405, 0x33D9A310, 101, trusted=True),
        ),
        492: (
            row(305, 492, 0x2431DE88, 100, trusted=True),
            row(491, 492, 0x1B30D140, 101, trusted=True),
        ),
        497: (
            row(365, 497, 0x2E160A90, 100, trusted=True),
            row(496, 497, 0x0244FF40, 101, trusted=True),
        ),
        3: (
            row(2, 3, 0x704FAFF6, None, trusted=False),
            row(230, 3, 0x60A0D558, 100, trusted=True),
        ),
    }


def test_candidate_prefix_concrete_alternate_rows_complete_feeder_partition(
    _seam,
    monkeypatch,
) -> None:
    """Concrete alternate-arm rows need no downstream handler authority."""

    graph, dag = _candidate_prefix_incomplete_feeder_fixture()
    observation = minimal_state_recovery.observe_candidate_scoped_prefix_authority(
        graph,
        dag,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
    )
    assert observation.authority is not None
    rows = _captured_prefix_provider_rows()
    provider_calls: list[int] = []

    def provider(_ctx, pred, _block, _arm):
        provider_calls.append(int(pred))
        return list(rows[int(pred)])

    monkeypatch.setattr(
        minimal_state_recovery,
        "_resolve_next_state_before_seeded",
        provider,
    )

    recovered = recover_state_write_transitions_via_partitioned_fixpoint(
        graph,
        _dispatcher(
            {
                0x011A0881: 100,
                0x33D9A310: 101,
                0x2431DE88: 100,
                0x1B30D140: 101,
                0x2E160A90: 100,
                0x0244FF40: 101,
                0x60A0D558: 100,
            },
            exit_block=200,
        ),
        _STATE_OFF,
        dispatcher_entry_serial=15,
        dispatcher_region_serials=frozenset({4, 15}),
        candidate_prefix_authority=observation.authority,
    )

    assert provider_calls == [405, 492, 497, 3]
    assert tuple(int(row.write_block) for row in recovered) == (
        2,
        230,
        351,
        404,
        305,
        491,
        365,
        496,
    )

def test_candidate_prefix_reconciliation_filters_only_physical_feeder_arm(
    _seam,
) -> None:
    """The prefix predicate filters feeder entrants but never direct-root rows."""

    graph, dag = _candidate_prefix_partitioned_feeder_fixture()
    observation = minimal_state_recovery.observe_candidate_scoped_prefix_authority(
        graph,
        dag,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
    )
    assert observation.authority is not None

    resolved = resolve_materialized_indirect_transfer_targets(
        _candidate_prefix_partitioned_transitions(),
        graph,
        _candidate_prefix_partitioned_dispatcher(),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({100, 101}),
        state_var_stkoff=_STATE_OFF,
        candidate_prefix_authority=observation.authority,
    )

    by_source = {int(row.write_block): row for row in resolved}
    assert tuple(by_source) == (402, 403, 490, 495)
    selected = by_source[402]
    assert selected.via_block == 330
    assert selected.target_handler == 101
    assert selected.proof is not None
    assert "candidate_scoped_prefix_arm" in selected.proof.route_source_kinds
    for source in (403, 490, 495):
        proof = by_source[source].proof
        assert proof is not None
        assert "decision_dag" in proof.route_source_kinds
        assert "candidate_scoped_prefix_arm" not in proof.route_source_kinds


def test_candidate_prefix_exact_transform_omits_untrusted_alternate_hint(
    _seam,
) -> None:
    """Exact current transform authority may classify an untrusted alternate."""

    graph, dag = _candidate_prefix_partitioned_feeder_fixture()
    observation = minimal_state_recovery.observe_candidate_scoped_prefix_authority(
        graph,
        dag,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
    )
    assert observation.authority is not None
    transitions = list(_candidate_prefix_partitioned_transitions())
    alternate = transitions[0]
    assert alternate.proof is not None
    transitions[0] = replace(
        alternate,
        target_handler=None,
        is_return=True,
        proof=replace(alternate.proof, trusted=False),
    )

    resolved = resolve_materialized_indirect_transfer_targets(
        tuple(transitions),
        graph,
        _candidate_prefix_partitioned_dispatcher(),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({100, 101}),
        state_var_stkoff=_STATE_OFF,
        candidate_prefix_authority=observation.authority,
    )

    assert tuple(int(row.write_block) for row in resolved) == (402, 403, 490, 495)


def test_candidate_prefix_omits_untrusted_alternate_before_feeder_bypass_proof(
    _seam,
) -> None:
    """An untouched alternate arm does not require proving a semantic feeder skippable."""

    graph, dag = _candidate_prefix_partitioned_feeder_fixture()
    blocks = dict(graph.blocks)
    source = blocks[401]
    feeder = blocks[330]
    blocks[401] = replace(
        source,
        insn_snapshots=(
            _mov(int(source.start_ea) + 4, _num(_PREFIX_ALTERNATE_STATE), _reg(8)),
        ),
    )
    blocks[330] = replace(
        feeder,
        insn_snapshots=(
            _mov(int(feeder.start_ea) + 4, _reg(8), _stk(_STATE_OFF)),
            _mov(int(feeder.start_ea) + 8, _reg(10), _reg(12)),
        ),
    )
    graph = FlowGraph(blocks, graph.entry_serial, graph.func_ea)
    observation = minimal_state_recovery.observe_candidate_scoped_prefix_authority(
        graph,
        dag,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
    )
    assert observation.authority is not None
    alternate, _selected, direct, *_rest = _candidate_prefix_partitioned_transitions()
    assert alternate.proof is not None
    alternate = replace(
        alternate,
        target_handler=None,
        is_return=True,
        proof=replace(alternate.proof, trusted=False),
    )

    resolved = resolve_materialized_indirect_transfer_targets(
        (alternate, direct),
        graph,
        _candidate_prefix_partitioned_dispatcher(),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({100, 101}),
        state_var_stkoff=_STATE_OFF,
        candidate_prefix_authority=observation.authority,
    )

    assert tuple(int(row.write_block) for row in resolved) == (403,)


def test_candidate_prefix_selected_carrier_preserves_semantic_feeder_body(
    _seam,
) -> None:
    """A selected source routes through a predecessor-local clone of its feeder."""

    graph, dag = _candidate_prefix_partitioned_feeder_fixture()
    blocks = dict(graph.blocks)
    source = blocks[402]
    feeder = blocks[330]
    blocks[402] = replace(
        source,
        insn_snapshots=(
            _mov(int(source.start_ea) + 4, _num(_PREFIX_SELECTED_STATE), _reg(8)),
        ),
    )
    blocks[330] = replace(
        feeder,
        insn_snapshots=(
            _mov(int(feeder.start_ea) + 4, _reg(8), _stk(_STATE_OFF)),
            _mov(int(feeder.start_ea) + 8, _reg(10), _reg(12)),
        ),
    )
    graph = FlowGraph(blocks, graph.entry_serial, graph.func_ea)
    observation = minimal_state_recovery.observe_candidate_scoped_prefix_authority(
        graph,
        dag,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
    )
    assert observation.authority is not None
    _alternate, selected, direct, *_rest = _candidate_prefix_partitioned_transitions()
    resolved = resolve_materialized_indirect_transfer_targets(
        (selected, direct),
        graph,
        _candidate_prefix_partitioned_dispatcher(),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({100, 101}),
        state_var_stkoff=_STATE_OFF,
        candidate_prefix_authority=observation.authority,
    )

    assert tuple(int(row.write_block) for row in resolved) == (402, 403)
    assert resolved[0].preserve_via_block is True
    assert resolved[0].proof is not None
    assert "preserved_feeder_clone" in resolved[0].proof.route_source_kinds


def test_selected_carrier_preserves_pure_stack_read_feeder_suffix(
    _seam,
) -> None:
    """A cloned carrier feeder may retain one pure stack-to-register move.

    Target B's ``blk355@0x180042823 -> blk383@0x180044249`` route writes the
    concrete state through ``eax``, then the shared feeder loads an unrelated
    stack value into ``r12`` before entering the comparison DAG.  The feeder
    clone preserves that load; it is not state or route authority.
    """

    graph, dag = _candidate_prefix_partitioned_feeder_fixture()
    blocks = dict(graph.blocks)
    source = blocks[402]
    feeder = blocks[330]
    blocks[402] = replace(
        source,
        insn_snapshots=(
            _mov(int(source.start_ea) + 4, _num(_PREFIX_SELECTED_STATE), _reg(8)),
        ),
    )
    blocks[330] = replace(
        feeder,
        insn_snapshots=(
            _mov(int(feeder.start_ea) + 4, _reg(8), _stk(_STATE_OFF)),
            _mov(
                int(feeder.start_ea) + 8,
                MopSnapshot(
                    t=_T_STK,
                    size=8,
                    stkoff=808,
                    stack_refs=(808,),
                    kind=OperandKind.STACK,
                ),
                MopSnapshot(
                    t=_T_REG,
                    size=8,
                    reg=12,
                    kind=OperandKind.REGISTER,
                ),
            ),
        ),
    )
    graph = FlowGraph(blocks, graph.entry_serial, graph.func_ea)
    observation = minimal_state_recovery.observe_candidate_scoped_prefix_authority(
        graph,
        dag,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
    )
    assert observation.authority is not None
    _alternate, selected, direct, *_rest = _candidate_prefix_partitioned_transitions()
    resolved = resolve_materialized_indirect_transfer_targets(
        (selected, direct),
        graph,
        _candidate_prefix_partitioned_dispatcher(),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({100, 101}),
        state_var_stkoff=_STATE_OFF,
        candidate_prefix_authority=observation.authority,
    )

    assert tuple(int(row.write_block) for row in resolved) == (402, 403)
    assert resolved[0].preserve_via_block is True
    assert resolved[0].proof is not None
    assert "preserved_feeder_clone" in resolved[0].proof.route_source_kinds


def test_selected_carrier_preserves_post_state_setup_corridor(_seam) -> None:
    """Clone setup blocks between the state feeder and comparison prefix.

    The live target route writes the recovered state through a shared feeder,
    initializes non-state registers in a separate one-way block, and only then
    re-enters the dispatcher prefix.  The setup block must execute on the
    rewritten route; bypassing it would change program semantics.
    """

    graph, dag = _candidate_prefix_partitioned_feeder_fixture()
    blocks = dict(graph.blocks)
    source = blocks[402]
    feeder = blocks[330]
    prefix = blocks[4]
    carrier = MopSnapshot(
        size=4,
        kind=OperandKind.LVAR,
        lvar_off=0,
    )
    blocks[402] = replace(
        source,
        insn_snapshots=(
            _mov(int(source.start_ea) + 4, _num(_PREFIX_SELECTED_STATE), carrier),
        ),
    )
    blocks[330] = replace(
        feeder,
        succs=(331,),
        insn_snapshots=(
            _mov(int(feeder.start_ea) + 4, carrier, _stk(_STATE_OFF)),
            _goto(int(feeder.start_ea) + 8, 331),
        ),
    )
    blocks[331] = _blk(
        331,
        (4,),
        (330,),
        (
            _mov(0x180042940, _num(0x11111111), _reg(12)),
            _mov(0x180042944, _num(0x22222222), _reg(13)),
            _mov(
                0x180042948,
                _addr(0x88),
                MopSnapshot(
                    size=8,
                    kind=OperandKind.LVAR,
                    lvar_off=0,
                    lvar_stkoff=_STATE_OFF + 8,
                ),
            ),
            _mov(0x18004294C, _num(0x44444444), _reg(15)),
        ),
        ea=0x180042940,
    )
    blocks[4] = replace(prefix, preds=(331,))
    graph = FlowGraph(blocks, graph.entry_serial, graph.func_ea)
    carrier_proof = state_carrier.prove_exact_u32_carrier_state_write(
        graph,
        402,
        330,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
        required_comparison_serials=frozenset({4}),
    )
    assert carrier_proof is not None
    assert carrier_proof.clone_until_serial == 331
    observation = minimal_state_recovery.observe_candidate_scoped_prefix_authority(
        graph,
        dag,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
    )
    assert observation.authority is not None
    _alternate, selected, direct, *_rest = _candidate_prefix_partitioned_transitions()

    resolved = resolve_materialized_indirect_transfer_targets(
        (selected, direct),
        graph,
        _candidate_prefix_partitioned_dispatcher(),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({100, 101}),
        state_var_stkoff=_STATE_OFF,
        candidate_prefix_authority=observation.authority,
    )

    assert tuple(int(row.write_block) for row in resolved) == (402, 403)
    assert resolved[0].preserve_via_block is True
    assert resolved[0].preserve_via_until == 331
    assert resolved[0].proof is not None
    assert "preserved_feeder_clone" in resolved[0].proof.route_source_kinds


@pytest.mark.parametrize("setup_kind", ("effectful", "state_overwrite"))
def test_selected_carrier_rejects_unsafe_post_state_setup_corridor(
    _seam, setup_kind: str
) -> None:
    """An effect or second state write rejects the whole fragment."""

    graph, dag = _candidate_prefix_partitioned_feeder_fixture()
    blocks = dict(graph.blocks)
    source = blocks[402]
    feeder = blocks[330]
    prefix = blocks[4]
    blocks[402] = replace(
        source,
        insn_snapshots=(
            _mov(int(source.start_ea) + 4, _num(_PREFIX_SELECTED_STATE), _reg(8)),
        ),
    )
    blocks[330] = replace(
        feeder,
        succs=(331,),
        insn_snapshots=(
            _mov(int(feeder.start_ea) + 4, _reg(8), _stk(_STATE_OFF)),
        ),
    )
    setup_insns = (
        (
            InsnSnapshot(
                opcode=0x41,
                ea=0x180042940,
                operands=(),
                kind=InsnKind.CALL,
                call_kind=CallKind.DIRECT,
            ),
        )
        if setup_kind == "effectful"
        else (_mov(0x180042940, _num(0xDEADBEEF), _stk(_STATE_OFF)),)
    )
    blocks[331] = _blk(
        331,
        (4,),
        (330,),
        setup_insns,
        ea=0x180042940,
    )
    blocks[4] = replace(prefix, preds=(331,))
    graph = FlowGraph(blocks, graph.entry_serial, graph.func_ea)
    observation = minimal_state_recovery.observe_candidate_scoped_prefix_authority(
        graph,
        dag,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
    )
    assert observation.authority is not None
    _alternate, selected, direct, *_rest = _candidate_prefix_partitioned_transitions()

    assert (
        resolve_materialized_indirect_transfer_targets(
            (selected, direct),
            graph,
            _candidate_prefix_partitioned_dispatcher(),
            (),
            condition_chain_dag=dag,
            condition_chain_handlers=frozenset({100, 101}),
            state_var_stkoff=_STATE_OFF,
            candidate_prefix_authority=observation.authority,
        )
        == ()
    )


@pytest.mark.parametrize("feeder_kind", ("sub", "carrier"))
def test_candidate_prefix_reconciliation_replays_each_exact_feeder_kind(
    _seam,
    feeder_kind: str,
) -> None:
    """Two-hop prefix authority reuses the existing SUB and carrier proofs."""

    graph, dag = _candidate_prefix_partitioned_feeder_fixture()
    blocks = dict(graph.blocks)
    for source, state in (
        (401, _PREFIX_ALTERNATE_STATE),
        (402, _PREFIX_SELECTED_STATE),
    ):
        source_block = blocks[source]
        source_insns = (
            (_mov(int(source_block.start_ea) + 4, _num(state), _reg(8)),)
            if feeder_kind == "carrier"
            else (
                _mov(int(source_block.start_ea) + 4, _num(state), _reg(8)),
                _mov(int(source_block.start_ea) + 8, _num(0), _reg(9)),
            )
        )
        blocks[source] = replace(source_block, insn_snapshots=source_insns)
    feeder = blocks[330]
    blocks[330] = replace(
        feeder,
        insn_snapshots=(
            (
                _mov(int(feeder.start_ea) + 4, _reg(8), _stk(_STATE_OFF))
                if feeder_kind == "carrier"
                else _sub(
                    int(feeder.start_ea) + 4,
                    _reg(8),
                    _reg(9),
                    _stk(_STATE_OFF),
                )
            ),
        ),
    )
    candidate = FlowGraph(blocks, graph.entry_serial, graph.func_ea)
    observation = minimal_state_recovery.observe_candidate_scoped_prefix_authority(
        candidate,
        dag,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
    )
    assert observation.authority is not None

    resolved = resolve_materialized_indirect_transfer_targets(
        _candidate_prefix_partitioned_transitions(),
        candidate,
        _candidate_prefix_partitioned_dispatcher(),
        (),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({100, 101}),
        state_var_stkoff=_STATE_OFF,
        candidate_prefix_authority=observation.authority,
    )

    assert tuple(int(row.write_block) for row in resolved) == (402, 403, 490, 495)
    selected = resolved[0]
    assert selected.proof is not None
    assert "candidate_scoped_prefix_arm" in selected.proof.route_source_kinds
    if feeder_kind == "sub":
        assert "state_transform_feeder" in selected.proof.route_source_kinds


@pytest.mark.parametrize(
    "variant",
    (
        "one-sided-feeder-edge",
        "unresolved-feeder-source",
        "effectful-feeder",
    ),
)
def test_candidate_prefix_partitioned_feeder_invalid_evidence_is_atomic(
    _seam,
    variant: str,
) -> None:
    graph, dag = _candidate_prefix_partitioned_feeder_fixture()
    blocks = dict(graph.blocks)
    if variant == "one-sided-feeder-edge":
        blocks[4] = replace(blocks[4], preds=())
    elif variant == "unresolved-feeder-source":
        blocks[402] = replace(blocks[402], insn_snapshots=())
    else:
        call = InsnSnapshot(
            opcode=0x41,
            ea=0x180042920,
            operands=(),
            kind=InsnKind.CALL,
            call_kind=CallKind.DIRECT,
        )
        blocks[330] = replace(
            blocks[330],
            insn_snapshots=(call, *blocks[330].insn_snapshots),
        )
    malformed = FlowGraph(blocks, graph.entry_serial, graph.func_ea)
    observation = minimal_state_recovery.observe_candidate_scoped_prefix_authority(
        malformed,
        dag,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
    )
    assert observation.authority is not None

    assert (
        resolve_materialized_indirect_transfer_targets(
            _candidate_prefix_partitioned_transitions(),
            malformed,
            _candidate_prefix_partitioned_dispatcher(),
            (),
            condition_chain_dag=dag,
            condition_chain_handlers=frozenset({100, 101}),
            state_var_stkoff=_STATE_OFF,
            candidate_prefix_authority=observation.authority,
        )
        == ()
    )


def test_candidate_prefix_partitioned_feeder_provider_conflict_is_atomic(
    _seam,
) -> None:
    graph, dag = _candidate_prefix_partitioned_feeder_fixture()
    observation = minimal_state_recovery.observe_candidate_scoped_prefix_authority(
        graph,
        dag,
        state_var_stkoff=_STATE_OFF,
        state_var_reg=None,
    )
    assert observation.authority is not None
    dispatcher = _DualRouteDispatcher(
        exact_targets={_PREFIX_SELECTED_STATE: 100},
        interval_rows=(
            IntervalRow(
                _PREFIX_SELECTED_STATE,
                _PREFIX_SELECTED_STATE + 1,
                101,
            ),
        ),
        default_target=200,
    )

    assert (
        resolve_materialized_indirect_transfer_targets(
            _candidate_prefix_partitioned_transitions(),
            graph,
            dispatcher,
            (),
            condition_chain_dag=dag,
            condition_chain_handlers=frozenset({100, 101}),
            state_var_stkoff=_STATE_OFF,
            candidate_prefix_authority=observation.authority,
        )
        == ()
    )


def test_candidate_prefix_not_applicable_preserves_partitioned_legacy_bytes(
    _seam,
) -> None:
    graph, _dag = _candidate_prefix_partitioned_feeder_fixture()
    dispatcher = _candidate_prefix_partitioned_dispatcher()
    legacy = recover_state_write_transitions_via_partitioned_fixpoint(
        graph,
        dispatcher,
        _STATE_OFF,
        dispatcher_entry_serial=15,
        dispatcher_region_serials=frozenset({15}),
    )

    assert (
        recover_state_write_transitions_via_partitioned_fixpoint(
            graph,
            dispatcher,
            _STATE_OFF,
            dispatcher_entry_serial=15,
            dispatcher_region_serials=frozenset({15}),
            candidate_prefix_authority=None,
        )
        == legacy
    )
