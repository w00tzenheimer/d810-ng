"""Unit tests for the ranked DispatcherResolver chain (llr-g3l8 slice 1).

Behavior-neutral: ``build_dispatch_map_any_kind`` now delegates to
``resolve_dispatcher`` over ``default_dispatcher_resolvers()``.  The switch and
equality detectors are disjoint, and equality specificity (10) > switch (5)
preserves the old equality-first precedence, so ranking changes no output.
"""
from __future__ import annotations

from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.analyses.control_flow.dispatcher_kind import DispatcherType
from d810.analyses.control_flow.dispatcher_resolution import (
    DispatcherResolution,
    ResolverCandidate,
)
from d810.analyses.control_flow.dispatcher_recovery import (
    SwitchTableDispatcherResolver,
    build_dispatch_map_any_kind,
    default_dispatcher_resolvers,
)
from d810.analyses.control_flow.dispatcher_resolver import resolve_dispatcher
from d810.capabilities.dispatcher import RouterKind


def _mop(
    *,
    kind: OperandKind = OperandKind.UNKNOWN,
    stkoff: int | None = None,
    value: int | None = None,
    stack_refs: tuple[int, ...] = (),
    switch_cases: tuple[tuple[tuple[int, ...], int], ...] = (),
) -> MopSnapshot:
    return MopSnapshot(
        kind=kind,
        stkoff=stkoff,
        value=value,
        stack_refs=stack_refs,
        switch_cases=switch_cases,
    )


def _insn(
    *,
    kind: InsnKind,
    left: MopSnapshot | None = None,
    right: MopSnapshot | None = None,
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=1,
        ea=0,
        operands=(),
        l=left,
        r=right,
        kind=kind,
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


def _flow_graph(blocks: dict[int, BlockSnapshot]) -> FlowGraph:
    return FlowGraph(
        blocks=blocks,
        entry_serial=min(blocks),
        func_ea=0x401000,
        metadata={"maturity_name": "MMAT_CALLS"},
    )


def _switch_flow_graph() -> FlowGraph:
    """A real SWITCH_TABLE graph (reuses test_switch_table_analysis fixture)."""
    state_operand = _mop(kind=OperandKind.SUBINSN, stack_refs=(0x10,))
    switch_cases = _mop(
        kind=OperandKind.CASE_LIST,
        switch_cases=(
            ((0,), 4),
            ((1, 2), 5),
            ((), 3),
        ),
    )
    guard_tail = _insn(
        kind=InsnKind.COND_JUMP,
        left=_mop(kind=OperandKind.STACK, stkoff=0x10, stack_refs=(0x10,)),
        right=_mop(kind=OperandKind.NUMBER, value=0xFF),
    )
    table_tail = _insn(
        kind=InsnKind.TABLE_JUMP,
        left=state_operand,
        right=switch_cases,
    )
    return _flow_graph({
        0: _block(0, succs=(2,)),
        2: _block(2, preds=(0, 6), succs=(3, 9), tail=guard_tail),
        3: _block(3, preds=(2, 6), succs=(4, 5), tail=table_tail),
        4: _block(4),
        5: _block(5),
        6: _block(6, succs=(3,)),
        9: _block(9),
    })


def test_resolve_dispatcher_on_switch_graph_returns_switch_resolution():
    graph = _switch_flow_graph()

    resolution = resolve_dispatcher(graph, default_dispatcher_resolvers())

    assert isinstance(resolution, DispatcherResolution)
    assert resolution.router_kind is RouterKind.SWITCH
    assert resolution.resolver_name == "switch_table"
    assert resolution.dispatcher_map is not None
    assert resolution.dispatcher_map.state_to_handler() == {0: 4, 1: 5, 2: 5}
    assert resolution.ranking_reason  # populated provenance


def test_accepts_returns_resolver_candidate_never_bool():
    graph = _switch_flow_graph()
    resolver = SwitchTableDispatcherResolver()

    candidate = resolver.accepts(graph)

    assert candidate is not None
    assert not isinstance(candidate, bool)
    assert isinstance(candidate, ResolverCandidate)
    assert candidate.router_kind is RouterKind.SWITCH
    assert candidate.resolver_name == "switch_table"


def test_build_dispatch_map_any_kind_is_behavior_neutral_on_switch():
    """The chain returns the SAME StateDispatcherMap the old first-match code did."""
    graph = _switch_flow_graph()

    dmap = build_dispatch_map_any_kind(graph)

    assert dmap is not None
    assert dmap.source is DispatcherType.SWITCH_TABLE
    assert dmap.state_to_handler() == {0: 4, 1: 5, 2: 5}
    assert dmap.dispatcher_entry_block == 3
    assert dmap.dispatcher_blocks == frozenset({2, 3})
    assert dmap.state_var_stkoff == 0x10


def test_no_dispatcher_graph_returns_none():
    graph = _flow_graph({0: _block(0)})

    assert resolve_dispatcher(graph, default_dispatcher_resolvers()) is None
    assert build_dispatch_map_any_kind(graph) is None


def test_resolve_dispatcher_none_graph_returns_none():
    assert resolve_dispatcher(None, default_dispatcher_resolvers()) is None
