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
from d810.capabilities.dispatcher import RouterKind
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
    """A real SWITCH graph (reuses test_switch_table_analysis fixture)."""
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
    assert dmap.router_kind is RouterKind.SWITCH
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


# --- Extra-resolver registry seam (llr-qb33) ---------------------------------
#
# The IDA-bound indirect jump-table resolver lives in d810.backends.hexrays and
# is injected at runtime by the unflatten entry. These tests cover the PORTABLE seam in
# d810.analyses (registry + front-end consultation) with a fake Protocol-shaped
# resolver, so they stay IDA-free.

from d810.analyses.control_flow.dispatcher_recovery import (  # noqa: E402
    clear_extra_dispatcher_resolvers,
    extra_dispatcher_resolvers,
    register_extra_dispatcher_resolver,
)
from d810.analyses.control_flow.dispatcher_resolution import (  # noqa: E402
    StateDispatcherMap,
    StateDispatcherRow,
)


def _indirect_dmap() -> StateDispatcherMap:
    rows = (
        StateDispatcherRow(
            state_const=1,
            target_block=4,
            dispatcher_block=3,
            compare_block=None,
            branch_kind="indirect_jump_table",
            router_kind=RouterKind.INDIRECT_TABLE,
            row_kind="handler",
        ),
    )
    return StateDispatcherMap(
        rows=rows,
        dispatcher_entry_block=3,
        dispatcher_blocks=frozenset({3}),
        state_var_stkoff=0x30,
        state_var_lvar_idx=None,
        router_kind=RouterKind.INDIRECT_TABLE,
    )


class _FakeIndirectResolver:
    """Protocol-shaped fake (no IDA): accepts only the ``m_ijmp`` flag graph."""

    name = "indirect_jump_table"
    router_kind = RouterKind.INDIRECT_TABLE
    specificity = 12

    def __init__(self, marker: str = "A") -> None:
        self.marker = marker

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
            reasons=("indirect-jump-table", self.marker),
        )

    def resolve(self, graph, candidate):
        if not self._is_indirect(graph):
            return None
        return DispatcherResolution(
            dispatcher_map=_indirect_dmap(),
            resolver_name=self.name,
            router_kind=self.router_kind,
            confidence=candidate.confidence,
            ranking_reason=candidate.reasons,
        )


def _indirect_flow_graph() -> FlowGraph:
    ijmp_tail = _insn(kind=InsnKind.INDIRECT_JUMP)
    return _flow_graph({
        0: _block(0, succs=(3,)),
        3: _block(3, preds=(0,), tail=ijmp_tail),
        4: _block(4, preds=(3,)),
    })


def test_extra_resolver_recognized_by_front_end():
    """A registered indirect resolver makes build_dispatch_map_any_kind fire."""
    clear_extra_dispatcher_resolvers()
    try:
        graph = _indirect_flow_graph()
        # Before registration: portable defaults do NOT recognize m_ijmp.
        assert build_dispatch_map_any_kind(graph) is None

        register_extra_dispatcher_resolver(_FakeIndirectResolver())
        dmap = build_dispatch_map_any_kind(graph)

        assert dmap is not None
        assert dmap.router_kind is RouterKind.INDIRECT_TABLE
        assert dmap.state_to_handler() == {1: 4}
        assert dmap.dispatcher_entry_block == 3
    finally:
        clear_extra_dispatcher_resolvers()


def test_extra_resolver_registration_idempotent_by_name():
    """Re-registering the same name REPLACES (no stale-mba leak across runs)."""
    clear_extra_dispatcher_resolvers()
    try:
        register_extra_dispatcher_resolver(_FakeIndirectResolver(marker="A"))
        register_extra_dispatcher_resolver(_FakeIndirectResolver(marker="B"))
        registered = extra_dispatcher_resolvers()
        assert len(registered) == 1
        assert registered[0].marker == "B"
    finally:
        clear_extra_dispatcher_resolvers()


def test_extra_resolver_inert_on_non_indirect_graph():
    """The seam is behaviour-neutral on a switch graph (no over-fire)."""
    clear_extra_dispatcher_resolvers()
    try:
        register_extra_dispatcher_resolver(_FakeIndirectResolver())
        dmap = build_dispatch_map_any_kind(_switch_flow_graph())
        # Still resolves the SWITCH map; the indirect resolver abstained.
        assert dmap is not None
        assert dmap.router_kind is RouterKind.SWITCH
        assert dmap.state_to_handler() == {0: 4, 1: 5, 2: 5}
    finally:
        clear_extra_dispatcher_resolvers()


# --- Portable IndirectJumpDispatcherResolver + capability seam (llr-dczv) -----
#
# The resolver moved to d810.analyses.control_flow (IDA-free) and now depends on
# an injected IndirectJumpTableCapability instead of calling the IDA-bound
# analysis directly.  These tests exercise the REAL resolver with a fake,
# in-memory capability (no IDA), covering the new requirement that recognition
# SURVIVES materialization: after the m_ijmp is removed (direct flow, no tail),
# accepts() must still fire because the capability returns a non-empty map.

from d810.analyses.control_flow.indirect_jump_resolver import (  # noqa: E402
    IndirectJumpDispatcherResolver,
)
from d810.analyses.control_flow.indirect_jump_table_analysis import (  # noqa: E402
    IndirectJumpTableResult,
)


class _FakeCapability:
    """In-memory IndirectJumpTableCapability: returns a fixed result (or None)."""

    def __init__(self, result: IndirectJumpTableResult | None):
        self._result = result
        self.calls: list[dict | None] = []

    def analyze_indirect_dispatcher(self, graph, *, goto_table_info=None):
        self.calls.append(goto_table_info)
        return self._result


def _indirect_result(rows=1, missing=0) -> IndirectJumpTableResult:
    dmap_rows = tuple(
        StateDispatcherRow(
            state_const=i + 1,
            target_block=4 + i,
            dispatcher_block=3,
            compare_block=None,
            branch_kind="indirect_jump_table",
            router_kind=RouterKind.INDIRECT_TABLE,
            row_kind="handler",
        )
        for i in range(rows)
    )
    dmap = StateDispatcherMap(
        rows=dmap_rows,
        dispatcher_entry_block=3,
        dispatcher_blocks=frozenset({3}),
        state_var_stkoff=0x30,
        state_var_lvar_idx=None,
        router_kind=RouterKind.INDIRECT_TABLE,
    )
    return IndirectJumpTableResult(
        state_dispatcher_map=dmap, entries=(), missing_target_count=missing
    )


def _materialized_flow_graph() -> FlowGraph:
    """A materialized hub: direct flow, NO m_ijmp tail (post-materialization)."""
    return _flow_graph({
        0: _block(0, succs=(3,)),
        3: _block(3, preds=(0,), succs=(4,)),  # plain goto tail, no INDIRECT_TABLE
        4: _block(4, preds=(3,)),
    })


def test_portable_resolver_accepts_on_m_ijmp_graph():
    cap = _FakeCapability(_indirect_result(rows=2))
    resolver = IndirectJumpDispatcherResolver(indirect_tables=cap)

    candidate = resolver.accepts(_indirect_flow_graph())

    assert candidate is not None
    assert isinstance(candidate, ResolverCandidate)
    assert candidate.router_kind is RouterKind.INDIRECT_TABLE
    assert candidate.resolver_name == "indirect_jump_table"
    assert "m_ijmp" in candidate.reasons
    assert "rows=2" in candidate.reasons


def test_portable_resolver_recognizes_materialized_form():
    """RECOGNITION SURVIVES MATERIALIZATION: no m_ijmp tail, capability has rows."""
    cap = _FakeCapability(_indirect_result(rows=3))
    resolver = IndirectJumpDispatcherResolver(indirect_tables=cap)
    graph = _materialized_flow_graph()

    # The cheap m_ijmp pre-gate is FALSE on a materialized graph...
    from d810.analyses.control_flow.indirect_jump_resolver import (
        _graph_has_indirect_jump,
    )
    assert not _graph_has_indirect_jump(graph)

    # ...yet accepts() still fires because the capability returns a non-empty map.
    candidate = resolver.accepts(graph)
    assert candidate is not None
    assert "materialized" in candidate.reasons
    assert "rows=3" in candidate.reasons

    resolution = resolver.resolve(graph, candidate)
    assert isinstance(resolution, DispatcherResolution)
    assert resolution.router_kind is RouterKind.INDIRECT_TABLE
    assert resolution.dispatcher_map.dispatcher_entry_block == 3


def test_portable_resolver_abstains_when_capability_returns_none():
    cap = _FakeCapability(None)
    resolver = IndirectJumpDispatcherResolver(indirect_tables=cap)

    # Even on an m_ijmp graph, a None capability result means no rows -> abstain.
    assert resolver.accepts(_indirect_flow_graph()) is None
    # And on a materialized graph it abstains too (no over-fire).
    assert resolver.accepts(_materialized_flow_graph()) is None


def test_portable_resolver_passes_goto_table_info_through():
    cap = _FakeCapability(_indirect_result())
    resolver = IndirectJumpDispatcherResolver(
        indirect_tables=cap, goto_table_info={"0x401000": {"table_nb_elt": 3}}
    )
    resolver.accepts(_indirect_flow_graph())
    assert cap.calls and cap.calls[-1] == {"0x401000": {"table_nb_elt": 3}}


def test_portable_resolver_satisfies_dispatcher_resolver_protocol():
    from d810.analyses.control_flow.dispatcher_resolver import DispatcherResolver

    resolver = IndirectJumpDispatcherResolver(indirect_tables=_FakeCapability(None))
    assert isinstance(resolver, DispatcherResolver)
