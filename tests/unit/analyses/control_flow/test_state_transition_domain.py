"""Sound forward value-set fixpoint over the state variable (llr-mmfq, Path C).

Pure-Python, no IDA.  The domain replaces the ad-hoc ``_walk_handler_chain``
recursion (``backends/hexrays/evidence/bst_analysis.py``) whose structural
successor-walk over-generates ``conditional_states`` (the diag DAG's 82 vs
oracle-66 ``CONDITIONAL_TRANSITION`` inflation).  A handler yields a conditional
transition only when its *feasible* exit value-set genuinely has >1 constant --
which a sound forward value-set fixpoint computes and a structural walk cannot.

CENTRAL §11.3-11.4: the lattice is the literal LiSA ``NonRedundantPowerset`` /
``ConstantValue`` spec; the fixpoint runs on the portable
``d810.analyses.data_flow.run_fixpoint`` engine (same as ``ReachingDefinitions``
in ``test_worklist_solver.py``).
"""
from __future__ import annotations

from d810.analyses.control_flow.state_transition_domain import (
    StateTransitionDomain,
    StateValue,
)
from d810.analyses.data_flow import run_fixpoint


def _topology(edges: dict[int, list[int]]) -> tuple[set[int], object, object]:
    """Build (nodes, successors_of, predecessors_of) from an edge map."""
    nodes: set[int] = set(edges)
    for succs in edges.values():
        nodes.update(succs)
    preds: dict[int, list[int]] = {n: [] for n in nodes}
    for src, succs in edges.items():
        for dst in succs:
            preds[dst].append(src)
    return nodes, lambda n: edges.get(n, []), lambda n: preds.get(n, [])


class TestStateValueLattice:
    """The ``StateValue`` element: ⊥ (unreachable) ⊑ {consts...} ⊑ ⊤ (unknown)."""

    def test_bottom_is_unreachable(self) -> None:
        b = StateValue.bottom()
        assert b.is_bottom is True
        assert b.is_top is False
        assert b.constants == frozenset()
        assert b.single() is None

    def test_singleton_holds_one_constant(self) -> None:
        v = StateValue.of(5)
        assert v.is_bottom is False
        assert v.is_top is False
        assert v.constants == frozenset({5})
        assert v.single() == 5

    def test_top_is_unknown(self) -> None:
        t = StateValue.top()
        assert t.is_top is True
        assert t.is_bottom is False
        assert t.constants == frozenset()
        assert t.single() is None

    def test_multi_constant_set_has_no_single(self) -> None:
        v = StateValue.of_many([1, 2, 3])
        assert v.constants == frozenset({1, 2, 3})
        assert v.single() is None
        assert v.is_top is False

    def test_join_is_set_union(self) -> None:
        assert StateValue.of(1).join(StateValue.of(2)) == StateValue.of_many([1, 2])

    def test_join_bottom_is_identity(self) -> None:
        v = StateValue.of(7)
        assert v.join(StateValue.bottom()) == v
        assert StateValue.bottom().join(v) == v
        assert StateValue.bottom().join(StateValue.bottom()) == StateValue.bottom()

    def test_join_top_is_absorbing(self) -> None:
        assert StateValue.of(1).join(StateValue.top()).is_top
        assert StateValue.top().join(StateValue.of(1)).is_top

    def test_join_is_commutative(self) -> None:
        a, b = StateValue.of_many([1, 2]), StateValue.of_many([2, 9])
        assert a.join(b) == b.join(a)

    def test_join_past_k_bound_collapses_to_top(self) -> None:
        # Growing the set beyond MAX_CONSTS is genuine unboundedness -> ⊤
        # (keeps the lattice finite-height as a safety valve).
        acc = StateValue.bottom()
        for k in range(StateValue.MAX_CONSTS + 5):
            acc = acc.join(StateValue.of(k))
        assert acc.is_top

    def test_leq_is_the_lattice_order(self) -> None:
        bottom, top = StateValue.bottom(), StateValue.top()
        one, onetwo = StateValue.of(1), StateValue.of_many([1, 2])
        assert bottom.leq(one)          # ⊥ below everything
        assert one.leq(onetwo)          # subset
        assert one.leq(top)             # everything below ⊤
        assert one.leq(one)             # reflexive
        assert not onetwo.leq(one)      # superset not below subset
        assert not top.leq(one)         # ⊤ not below a proper element

    def test_equality_and_hashing(self) -> None:
        assert StateValue.of(1) == StateValue.of(1)
        assert StateValue.of(1) != StateValue.of(2)
        assert StateValue.of_many([1, 2]) == StateValue.of_many([2, 1])
        # frozen/hashable -> usable in sets and as dict keys (fixpoint state).
        assert len({StateValue.of(1), StateValue.of(1), StateValue.of(2)}) == 2


# A synthetic flattened CFF loop:
#   0 pre-header (writes s=10) -> 1 dispatcher
#   1 routes s=10 -> handler entry 2, s=20 -> handler entry 4
#   2 -> 3 : handler-10 exit writes s=20 (back-edge to 1)         [10 -> 20]
#   4 -> 5,6 : handler-20 splits on a program value
#   5 writes s=30 (back-edge), 6 writes s=10 (back-edge)          [20 -> {30,10} conditional]
#   9 : an unreachable block writing s=999 (no predecessor)       [stays ⊥]
_CFF_EDGES = {0: [1], 1: [2, 4], 2: [3], 3: [1], 4: [5, 6], 5: [1], 6: [1], 9: [1]}
_CFF_WRITES = {
    0: StateValue.of(10),
    3: StateValue.of(20),
    5: StateValue.of(30),
    6: StateValue.of(10),
    9: StateValue.of(999),
}


def _run_cff():
    nodes, succ, pred = _topology(_CFF_EDGES)
    domain = StateTransitionDomain(_CFF_WRITES)
    return domain, run_fixpoint(
        domain,
        nodes=nodes,
        entry_nodes={0},
        entry_state=StateValue.top(),  # s is unknown before the pre-header's init write
        successors_of=succ,
        predecessors_of=pred,
        raise_on_nonconvergence=True,
    )


class TestStateTransitionDomainFixpoint:
    def test_fixpoint_converges(self) -> None:
        _, res = _run_cff()
        assert res.converged is True

    def test_strong_update_overwrites_incoming(self) -> None:
        # in[3] is multi-valued ({10,20,30} via the loop) but block 3 writes s=20,
        # so its out is the singleton {20} regardless of the incoming set.
        _, res = _run_cff()
        assert res.in_states[3].constants == {10, 20, 30}
        assert res.out_states[3] == StateValue.of(20)

    def test_dispatcher_accumulates_all_written_states(self) -> None:
        _, res = _run_cff()
        assert res.out_states[1].constants == {10, 20, 30}

    def test_passthrough_block_preserves_value(self) -> None:
        _, res = _run_cff()
        assert res.out_states[4] == res.in_states[4]
        assert res.out_states[4].constants == {10, 20, 30}

    def test_unreachable_block_stays_bottom(self) -> None:
        # Block 9 has no predecessor and is not an entry: it never becomes
        # reachable, so its write of 999 never fires and never pollutes the
        # dispatcher's value-set.
        _, res = _run_cff()
        assert res.out_states[9].is_bottom
        assert 999 not in res.out_states[1].constants

    def test_meet_is_the_lattice_join(self) -> None:
        domain = StateTransitionDomain({})
        assert domain.meet(StateValue.of(1), StateValue.of(2)) == StateValue.of_many(
            [1, 2]
        )

    def test_widen_is_identity_on_current(self) -> None:
        # Finite-height lattice: widening need not accelerate, it returns the
        # current (already-joined) state -- mirrors ReachingDefinitionsDomain.
        domain = StateTransitionDomain({})
        cur = StateValue.of_many([1, 2])
        assert domain.widen(StateValue.of(1), cur) == cur


from d810.analyses.control_flow.state_transition_domain import (  # noqa: E402
    analyze_state_transitions,
    build_state_writes_with_dispatch_assume,
)


def _transitions_of(result, from_state):
    """All StateTransitions a handler emits, as (to_state, is_conditional) pairs."""
    handler = result.handlers.get(from_state)
    if handler is None:
        return []
    return sorted((t.to_state, t.is_conditional) for t in handler.transitions)


class TestDispatchAssume:
    """A handler entry is reached only when ``s == routing_const`` -- the
    dispatcher edge is an ``assume`` that seeds the handler region with ``{E}``.
    An explicit state write in the entry block overrides the assume (it happens
    after the routed entry)."""

    def test_entry_without_write_gets_routing_const(self) -> None:
        merged = build_state_writes_with_dispatch_assume({}, {10: 2, 20: 4})
        assert merged[2] == StateValue.of(10)
        assert merged[4] == StateValue.of(20)

    def test_explicit_write_overrides_entry_assume(self) -> None:
        merged = build_state_writes_with_dispatch_assume(
            {2: StateValue.of(99)}, {10: 2}
        )
        assert merged[2] == StateValue.of(99)


class TestRecoverTransitions:
    def _clean(self):
        nodes, succ, pred = _topology(_CFF_EDGES)
        return analyze_state_transitions(
            nodes=nodes,
            entry_nodes={0},
            successors_of=succ,
            predecessors_of=pred,
            state_writes={k: v for k, v in _CFF_WRITES.items() if k != 9},
            dispatcher_entry=1,
            handler_entry_by_state={10: 2, 20: 4},
            entry_state=StateValue.top(),
        )

    def test_handlers_keyed_by_from_state(self) -> None:
        assert set(self._clean().handlers) == {10, 20}

    def test_single_write_handler_is_unconditional(self) -> None:
        # handler routed on s=10 writes only s=20 -> one unconditional edge.
        assert _transitions_of(self._clean(), 10) == [(20, False)]

    def test_genuine_multi_write_handler_is_conditional(self) -> None:
        # handler routed on s=20 splits and writes s=30 / s=10 on its two arms.
        assert _transitions_of(self._clean(), 20) == [(10, True), (30, True)]


class TestOverCountRegression:
    """The structural ``_walk_handler_chain`` records the *first* write found in
    each arm; an arm that writes B then overwrites it with A is mis-counted as a
    conditional ``{A, B}``.  The sound fixpoint tracks the *reaching* value (A),
    so the handler is correctly a single unconditional transition."""

    def _overwrite_graph(self):
        # 0 pre-header(s=10) -> 1 dispatcher -> 2 (handler-10 entry)
        # 2 -> 3,4   (handler-10 splits)
        # 3: s=50 -> 1            (arm1: one write, back-edge)
        # 4: s=60 -> 5: s=50 -> 1 (arm2: writes 60 then OVERWRITES to 50)
        edges = {0: [1], 1: [2], 2: [3, 4], 3: [1], 4: [5], 5: [1]}
        writes = {
            0: StateValue.of(10),
            3: StateValue.of(50),
            4: StateValue.of(60),
            5: StateValue.of(50),
        }
        nodes, succ, pred = _topology(edges)
        return analyze_state_transitions(
            nodes=nodes,
            entry_nodes={0},
            successors_of=succ,
            predecessors_of=pred,
            state_writes=writes,
            dispatcher_entry=1,
            handler_entry_by_state={10: 2},
            entry_state=StateValue.top(),
        )

    def test_overwritten_arm_is_not_conditional(self) -> None:
        # Sound result: 10 -> 50, single unconditional edge.
        assert _transitions_of(self._overwrite_graph(), 10) == [(50, False)]

    def test_first_write_value_does_not_leak(self) -> None:
        # The structurally-counted spurious target (60) must not appear.
        result = self._overwrite_graph()
        all_targets = {t.to_state for t in result.transitions}
        assert 60 not in all_targets


class TestUnresolvedWriteIsExplicit:
    """An MBA-obfuscated next-state write (⊤) yields no clean transition -- the
    'leaked constant' case made explicit, not silently dropped."""

    def test_top_next_state_yields_no_transition(self) -> None:
        edges = {0: [1], 1: [2], 2: [1]}
        writes = {0: StateValue.of(10), 2: StateValue.top()}  # handler writes MBA
        nodes, succ, pred = _topology(edges)
        result = analyze_state_transitions(
            nodes=nodes,
            entry_nodes={0},
            successors_of=succ,
            predecessors_of=pred,
            state_writes=writes,
            dispatcher_entry=1,
            handler_entry_by_state={10: 2},
            entry_state=StateValue.top(),
        )
        # The handler is known to exist but has no resolvable transition.
        assert 10 in result.handlers
        assert result.handlers[10].transitions == []
