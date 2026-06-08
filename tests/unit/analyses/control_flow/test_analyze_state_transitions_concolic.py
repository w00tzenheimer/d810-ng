"""``analyze_state_transitions_concolic`` == ``analyze_state_transitions`` (S4 A).

Increment A of S4 (ticket ``llr-1szn``): the concolic re-realization of the sound
#2 ``RecoverStateTransitions`` fixpoint must be **byte-identical** to the legacy
``StateTransitionDomain`` path. The ``ConcolicTransitionDomain`` with
``V = StateValue`` (single cell, single partition) reproduces the powerset domain
exactly, so every recovered :class:`TransitionResult` matches transition-for-
transition.

The corpus is the same synthetic flattened CFF loop the legacy domain's unit test
exercises (copied here so the two suites stay independent): a strong-update arm, a
genuinely-conditional split, an overwritten arm, an MBA (⊤) next-state write, and
an unreachable block.
"""
from __future__ import annotations

from d810.analyses.control_flow.state_transition_domain import (
    StateValue,
    analyze_state_transitions,
    analyze_state_transitions_concolic,
)


def _topology(edges: dict[int, list[int]]):
    """Build (nodes, successors_of, predecessors_of) from an edge map."""
    nodes: set[int] = set(edges)
    for succs in edges.values():
        nodes.update(succs)
    preds: dict[int, list[int]] = {n: [] for n in nodes}
    for src, succs in edges.items():
        for dst in succs:
            preds[dst].append(src)
    return nodes, lambda n: edges.get(n, []), lambda n: preds.get(n, [])


# The synthetic flattened CFF loop (mirrors test_state_transition_domain.py):
#   0 pre-header (writes s=10) -> 1 dispatcher
#   1 routes s=10 -> handler entry 2, s=20 -> handler entry 4
#   2 -> 3 : handler-10 exit writes s=20 (back-edge to 1)         [10 -> 20]
#   4 -> 5,6 : handler-20 splits on a program value
#   5 writes s=30 (back-edge), 6 writes s=10 (back-edge)          [20 -> {30,10}]
#   9 : an unreachable block writing s=999 (no predecessor)       [stays ⊥]
_CFF_EDGES = {0: [1], 1: [2, 4], 2: [3], 3: [1], 4: [5, 6], 5: [1], 6: [1], 9: [1]}
_CFF_WRITES = {
    0: StateValue.of(10),
    3: StateValue.of(20),
    5: StateValue.of(30),
    6: StateValue.of(10),
    9: StateValue.of(999),
}


def _both(
    *,
    edges,
    state_writes,
    dispatcher_entry,
    handler_entry_by_state,
    entry_nodes=frozenset({0}),
    entry_state=None,
):
    """Run both analyses over the same inputs; return (legacy, concolic)."""
    nodes, succ, pred = _topology(edges)
    entry = StateValue.top() if entry_state is None else entry_state
    kwargs = dict(
        nodes=nodes,
        entry_nodes=set(entry_nodes),
        successors_of=succ,
        predecessors_of=pred,
        state_writes=state_writes,
        dispatcher_entry=dispatcher_entry,
        handler_entry_by_state=handler_entry_by_state,
        entry_state=entry,
    )
    return analyze_state_transitions(**kwargs), analyze_state_transitions_concolic(
        **kwargs
    )


def _transition_tuples(result):
    """A stable, comparable signature of every emitted transition."""
    return sorted(
        (
            t.from_state,
            t.to_state,
            t.from_block,
            t.condition_block,
            t.is_conditional,
        )
        for t in result.transitions
    )


class TestConcolicMatchesLegacyOnCff:
    """Every recovered transition is identical across the two realizations."""

    def _run(self):
        return _both(
            edges=_CFF_EDGES,
            state_writes={k: v for k, v in _CFF_WRITES.items() if k != 9},
            dispatcher_entry=1,
            handler_entry_by_state={10: 2, 20: 4},
        )

    def test_same_transitions(self) -> None:
        legacy, concolic = self._run()
        assert _transition_tuples(concolic) == _transition_tuples(legacy)

    def test_same_handler_keys(self) -> None:
        legacy, concolic = self._run()
        assert set(concolic.handlers) == set(legacy.handlers)

    def test_same_resolved_count(self) -> None:
        legacy, concolic = self._run()
        assert concolic.resolved_count == legacy.resolved_count

    def test_same_strategy_name(self) -> None:
        legacy, concolic = self._run()
        assert concolic.strategy_name == legacy.strategy_name

    def test_per_handler_transitions_match(self) -> None:
        legacy, concolic = self._run()
        for from_state, handler in legacy.handlers.items():
            legacy_edges = sorted(
                (t.to_state, t.is_conditional) for t in handler.transitions
            )
            concolic_edges = sorted(
                (t.to_state, t.is_conditional)
                for t in concolic.handlers[from_state].transitions
            )
            assert concolic_edges == legacy_edges


class TestConcolicMatchesLegacyOnOverwrite:
    """An overwritten arm (writes 60 then 50) is a single unconditional 10->50
    in both realizations -- the reaching value, not the structural first write."""

    def _run(self):
        edges = {0: [1], 1: [2], 2: [3, 4], 3: [1], 4: [5], 5: [1]}
        writes = {
            0: StateValue.of(10),
            3: StateValue.of(50),
            4: StateValue.of(60),
            5: StateValue.of(50),
        }
        return _both(
            edges=edges,
            state_writes=writes,
            dispatcher_entry=1,
            handler_entry_by_state={10: 2},
        )

    def test_same_transitions(self) -> None:
        legacy, concolic = self._run()
        assert _transition_tuples(concolic) == _transition_tuples(legacy)

    def test_spurious_first_write_absent_in_both(self) -> None:
        legacy, concolic = self._run()
        assert 60 not in {t.to_state for t in legacy.transitions}
        assert 60 not in {t.to_state for t in concolic.transitions}


class TestConcolicMatchesLegacyOnUnresolvedWrite:
    """An MBA (⊤) next-state write yields no clean transition in both."""

    def _run(self):
        edges = {0: [1], 1: [2], 2: [1]}
        writes = {0: StateValue.of(10), 2: StateValue.top()}
        return _both(
            edges=edges,
            state_writes=writes,
            dispatcher_entry=1,
            handler_entry_by_state={10: 2},
        )

    def test_same_transitions(self) -> None:
        legacy, concolic = self._run()
        assert _transition_tuples(concolic) == _transition_tuples(legacy)

    def test_handler_present_but_no_transition_in_both(self) -> None:
        legacy, concolic = self._run()
        assert 10 in legacy.handlers and 10 in concolic.handlers
        assert legacy.handlers[10].transitions == []
        assert concolic.handlers[10].transitions == []


class TestConcolicMatchesLegacyWithDefaultEntryState:
    """Default entry_state (None -> ⊤) path also matches."""

    def test_same_transitions_default_entry(self) -> None:
        nodes, succ, pred = _topology(_CFF_EDGES)
        clean = {k: v for k, v in _CFF_WRITES.items() if k != 9}
        kwargs = dict(
            nodes=nodes,
            entry_nodes={0},
            successors_of=succ,
            predecessors_of=pred,
            state_writes=clean,
            dispatcher_entry=1,
            handler_entry_by_state={10: 2, 20: 4},
        )
        legacy = analyze_state_transitions(**kwargs)
        concolic = analyze_state_transitions_concolic(**kwargs)
        assert _transition_tuples(concolic) == _transition_tuples(legacy)
