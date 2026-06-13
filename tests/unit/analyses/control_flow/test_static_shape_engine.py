"""``StaticShapeEngine`` equivalence + protocol tests (P1, llr-5knz).

The behavior-neutrality proof at the unit level: the engine's
``.recover(g).to_state_dispatcher_map()`` byte-equals ``build_dispatch_map_any_kind(g)``
on every fixture (same ``default + extra`` resolver chain, same ranking, same map).
"""
from __future__ import annotations

import pytest

from d810.analyses.control_flow.dispatcher_kind import DispatcherType
from d810.analyses.control_flow.dispatcher_recovery import (
    build_dispatch_map_any_kind,
    clear_extra_dispatcher_resolvers,
    register_extra_dispatcher_resolver,
)
from d810.analyses.control_flow.dispatcher_resolution import (
    DispatcherResolution,
    ResolverCandidate,
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.analyses.control_flow.machine_recovery_engine import MachineRecoveryEngine
from d810.analyses.control_flow.recovered_machine import RecoveredMachine
from d810.analyses.control_flow.static_shape_engine import StaticShapeEngine
from d810.capabilities.dispatcher import RouterKind
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
    PredicateKind,
)


# --- FlowGraph builders ------------------------------------------------------


def _mop(
    *,
    kind: OperandKind = OperandKind.UNKNOWN,
    stkoff: int | None = None,
    value: int | None = None,
    block_ref: int | None = None,
    stack_refs: tuple[int, ...] = (),
    switch_cases: tuple[tuple[tuple[int, ...], int], ...] = (),
) -> MopSnapshot:
    return MopSnapshot(
        kind=kind,
        stkoff=stkoff,
        value=value,
        block_ref=block_ref,
        stack_refs=stack_refs,
        switch_cases=switch_cases,
    )


def _insn(
    *,
    kind: InsnKind,
    left: MopSnapshot | None = None,
    right: MopSnapshot | None = None,
    dest: MopSnapshot | None = None,
    branch_predicate: PredicateKind | None = None,
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=1,
        ea=0,
        operands=(),
        l=left,
        r=right,
        d=dest,
        kind=kind,
        branch_predicate=branch_predicate,
    )


def _block(
    serial: int,
    *,
    preds=(),
    succs=(),
    tail: InsnSnapshot | None = None,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=tuple(succs),
        preds=tuple(preds),
        flags=0,
        start_ea=0,
        insn_snapshots=() if tail is None else (tail,),
    )


def _switch_flow_graph() -> FlowGraph:
    state_operand = _mop(kind=OperandKind.SUBINSN, stack_refs=(0x10,))
    switch_cases = _mop(
        kind=OperandKind.CASE_LIST,
        switch_cases=(((0,), 4), ((1, 2), 5), ((), 3)),
    )
    guard_tail = _insn(
        kind=InsnKind.COND_JUMP,
        left=_mop(kind=OperandKind.STACK, stkoff=0x10, stack_refs=(0x10,)),
        right=_mop(kind=OperandKind.NUMBER, value=0xFF),
    )
    table_tail = _insn(kind=InsnKind.TABLE_JUMP, left=state_operand, right=switch_cases)
    return FlowGraph(
        blocks={
            0: _block(0, succs=(2,)),
            2: _block(2, preds=(0, 6), succs=(3, 9), tail=guard_tail),
            3: _block(3, preds=(2, 6), succs=(4, 5), tail=table_tail),
            4: _block(4),
            5: _block(5),
            6: _block(6, succs=(3,)),
            9: _block(9),
        },
        entry_serial=0,
        func_ea=0x401000,
    )


def _eq_cmp(state_stkoff: int, const: int, taken: int) -> InsnSnapshot:
    """``jz [state_stkoff], #const -> taken`` (equality-chain comparator tail)."""
    return _insn(
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.EQ,
        left=_mop(kind=OperandKind.STACK, stkoff=state_stkoff, stack_refs=(state_stkoff,)),
        right=_mop(kind=OperandKind.NUMBER, value=const),
        dest=_mop(block_ref=taken),
    )


def _equality_chain_flow_graph(*, state_const: int = 0x01000010) -> FlowGraph:
    """An equality-chain dispatcher: two jz comparators voting one state slot.

    State constants must be ``> MIN_STATE_CONSTANT`` (0x01000000) for the default
    threshold; ``state_const`` lets a test drive the sub-threshold path.
    """
    second = state_const + 0x10
    state_stkoff = 0x3C
    return FlowGraph(
        blocks={
            0: _block(0, succs=(2,)),
            2: _block(
                2,
                preds=(0, 7, 9),
                succs=(3, 7),
                tail=_eq_cmp(state_stkoff, state_const, taken=7),
            ),
            3: _block(
                3,
                preds=(2,),
                succs=(4, 9),
                tail=_eq_cmp(state_stkoff, second, taken=9),
            ),
            4: _block(4, preds=(3,), succs=(2,)),
            7: _block(7, preds=(2,), succs=(2,)),
            9: _block(9, preds=(3,), succs=(2,)),
        },
        entry_serial=0,
        func_ea=0x401000,
    )


# --- Fake extra resolver (mirrors test_dispatcher_resolver _FakeIndirectResolver) ----


class _FakeIndirectResolver:
    """Protocol-shaped fake (no IDA): accepts only the ``m_ijmp`` flag graph."""

    name = "indirect_jump_table"
    router_kind = RouterKind.INDIRECT_TABLE
    specificity = 12

    def _is_indirect(self, graph) -> bool:
        return any(
            getattr(b.tail, "kind", None) is InsnKind.INDIRECT_JUMP
            for b in graph.blocks.values()
        )

    def accepts(self, graph):
        if not self._is_indirect(graph):
            return None
        return ResolverCandidate(
            resolver_name=self.name,
            router_kind=self.router_kind,
            confidence=1.0,
            specificity=self.specificity,
            reasons=("indirect-jump-table",),
        )

    def resolve(self, graph, candidate):
        if not self._is_indirect(graph):
            return None
        rows = (
            StateDispatcherRow(
                state_const=1,
                target_block=4,
                dispatcher_block=3,
                compare_block=None,
                branch_kind="indirect_jump_table",
                source=DispatcherType.INDIRECT_JUMP,
                row_kind="handler",
            ),
        )
        dmap = StateDispatcherMap(
            rows=rows,
            dispatcher_entry_block=3,
            dispatcher_blocks=frozenset({3}),
            state_var_stkoff=0x30,
            state_var_lvar_idx=None,
            source=DispatcherType.INDIRECT_JUMP,
        )
        return DispatcherResolution(
            dispatcher_map=dmap,
            resolver_name=self.name,
            router_kind=self.router_kind,
            confidence=candidate.confidence,
            ranking_reason=candidate.reasons,
        )


def _indirect_flow_graph() -> FlowGraph:
    ijmp_tail = _insn(kind=InsnKind.INDIRECT_JUMP)
    return FlowGraph(
        blocks={
            0: _block(0, succs=(3,)),
            3: _block(3, preds=(0,), tail=ijmp_tail),
            4: _block(4, preds=(3,)),
        },
        entry_serial=0,
        func_ea=0x401000,
    )


@pytest.fixture(autouse=True)
def _clear_resolvers():
    clear_extra_dispatcher_resolvers()
    yield
    clear_extra_dispatcher_resolvers()


# --- Tests -------------------------------------------------------------------


def test_engine_matches_build_dispatch_map_any_kind():
    g = _equality_chain_flow_graph()
    expected = build_dispatch_map_any_kind(g)
    assert expected is not None
    assert expected.source is DispatcherType.CONDITIONAL_CHAIN
    machine = StaticShapeEngine().recover(g)
    assert machine is not None
    assert machine.to_state_dispatcher_map() == expected


def test_engine_switch_table_equivalence():
    g = _switch_flow_graph()
    expected = build_dispatch_map_any_kind(g)
    assert expected is not None
    assert expected.source is DispatcherType.SWITCH_TABLE
    machine = StaticShapeEngine().recover(g)
    assert machine is not None
    assert machine.to_state_dispatcher_map() == expected


def test_engine_returns_none_on_no_dispatcher():
    g = FlowGraph(blocks={0: _block(0)}, entry_serial=0, func_ea=0x401000)
    assert build_dispatch_map_any_kind(g) is None
    assert StaticShapeEngine().recover(g) is None


def test_engine_respects_min_state_constant():
    low = 0x100
    g = _equality_chain_flow_graph(state_const=low + 1)
    # Default threshold rejects the sub-default constants.
    assert StaticShapeEngine().recover(g) is None
    # Lowering the threshold admits them.
    machine = StaticShapeEngine(min_state_constant=low).recover(g)
    assert machine is not None
    assert machine.source is DispatcherType.CONDITIONAL_CHAIN


def test_engine_provenance_carries_resolver_name():
    g = _equality_chain_flow_graph()
    machine = StaticShapeEngine().recover(g)
    assert machine is not None
    assert machine.provenance[0] == "equality_chain"


def test_engine_satisfies_protocol():
    assert isinstance(StaticShapeEngine(), MachineRecoveryEngine)


def test_engine_consults_extra_resolvers():
    g = _indirect_flow_graph()
    # Before registration the portable chain does not recognize m_ijmp.
    assert StaticShapeEngine().recover(g) is None
    register_extra_dispatcher_resolver(_FakeIndirectResolver())
    machine = StaticShapeEngine().recover(g)
    assert machine is not None
    assert machine.source is DispatcherType.INDIRECT_JUMP
    assert machine.to_state_dispatcher_map().state_to_handler() == {1: 4}


def test_engine_returns_none_on_none_graph():
    assert StaticShapeEngine().recover(None) is None
