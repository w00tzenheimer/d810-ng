"""Worked example for the ``d810.analyses.data_flow`` fixpoint solver.

Pure-Python, no IDA.  Exercises :func:`run_fixpoint` with real
``FlowDomain`` implementations:

- a reaching-definitions lattice over a CFG with a loop (union meet,
  back-edge, natural convergence), and
- a bounded-counter domain that needs widening to converge (and provably
  does NOT converge without it).
"""
from __future__ import annotations

import pytest

from d810.analyses.data_flow import (
    AnalyzedCFG,
    Direction,
    FixpointConfiguration,
    FixpointDidNotConverge,
    run_fixpoint,
)


def _topology(edges: dict[int, list[int]]) -> tuple[set[int], object, object]:
    """Build (nodes, successors_of, predecessors_of) from an edge map."""
    nodes: set[int] = set(edges)
    for succs in edges.values():
        nodes.update(succs)
    preds: dict[int, list[int]] = {n: [] for n in nodes}
    for src, succs in edges.items():
        for dst in succs:
            preds[dst].append(src)

    def successors_of(n: int) -> list[int]:
        return edges.get(n, [])

    def predecessors_of(n: int) -> list[int]:
        return preds.get(n, [])

    return nodes, successors_of, predecessors_of


class ReachingDefinitionsDomain:
    """Forward 'may' reaching-definitions analysis over ``frozenset[str]``.

    State is the set of definition labels (``"x@0"``) that may reach a
    point.  Bottom is the empty set and meet is union, so an as-yet-unreached
    predecessor (``bottom``) contributes nothing to the meet -- no lattice-
    polarity trap.  A node that defines a variable kills prior defs of that
    variable and gens its own.  Finite (powerset of a finite def set), so
    ``widen`` is the identity on the current state.

    Mirrors the engine's real reaching-definitions domain in
    ``d810.evaluator.hexrays_microcode.forward_dataflow``.
    """

    def __init__(self, defs: dict[int, object]) -> None:
        self._defs = defs

    def bottom(self) -> frozenset:
        return frozenset()

    def confluence(self, left: frozenset, right: frozenset) -> frozenset:
        return left | right

    def transfer(self, node: int, in_state: frozenset) -> frozenset:
        d = self._defs.get(node)
        if d is None:
            return in_state
        var, label = d
        killed = {lbl for lbl in in_state if lbl.split("@", 1)[0] == var}
        return (in_state - killed) | {label}

    def equals(self, left: frozenset, right: frozenset) -> bool:
        return left == right

    def widen(self, previous: frozenset, current: frozenset) -> frozenset:
        return current


class TestReachingDefinitionsWorkedExample:
    def _run(self):
        # 0:def x -> 1:def y -> 2(loop head) -> 3:def z -> back to 2 ; 2 -> 4:def w
        edges = {0: [1], 1: [2], 2: [3, 4], 3: [2]}
        nodes, succ, pred = _topology(edges)
        defs = {
            0: ("x", "x@0"),
            1: ("y", "y@1"),
            2: None,
            3: ("z", "z@3"),
            4: ("w", "w@4"),
        }
        domain = ReachingDefinitionsDomain(defs)
        return domain, run_fixpoint(
            domain,
            nodes=nodes,
            entry_nodes={0},
            successors_of=succ,
            predecessors_of=pred,
            raise_on_nonconvergence=True,
        )

    def test_converges(self) -> None:
        _, res = self._run()
        assert res.converged is True

    def test_entry_boundary_is_bottom(self) -> None:
        _, res = self._run()
        assert res.in_states[0] == frozenset()
        assert res.out_states[0] == {"x@0"}

    def test_backedge_carries_def_into_loop_head(self) -> None:
        # in[2] = out[1] | out[3]: the loop body's z@3 reaches the head via 3->2.
        _, res = self._run()
        assert res.in_states[2] == {"x@0", "y@1", "z@3"}

    def test_defs_propagate_through_loop_and_exit(self) -> None:
        _, res = self._run()
        assert res.out_states[3] == {"x@0", "y@1", "z@3"}
        assert res.out_states[4] == {"x@0", "y@1", "z@3", "w@4"}

    def test_result_wraps_in_analyzed_cfg(self) -> None:
        _, res = self._run()
        acfg = AnalyzedCFG(graph={"edges": {0: [1]}}, result=res)
        assert acfg.result is res
        assert acfg.graph == {"edges": {0: [1]}}


_TOP = "TOP"


class BoundedCounterDomain:
    """A deliberately tall lattice: ``transfer`` increments without bound,
    so the analysis only converges once ``widen`` jumps to ``_TOP``.
    """

    def bottom(self) -> object:
        return 0

    def confluence(self, a: object, b: object) -> object:
        if a == _TOP or b == _TOP:
            return _TOP
        return max(a, b)

    def transfer(self, node: int, s: object) -> object:
        return _TOP if s == _TOP else s + 1

    def equals(self, a: object, b: object) -> bool:
        return a == b

    def widen(self, previous: object, current: object) -> object:
        return _TOP if current != previous else current


class TestWideningConvergence:
    def _self_loop(self):
        nodes, succ, pred = _topology({0: [0]})
        return BoundedCounterDomain(), nodes, succ, pred

    def test_widening_forces_convergence_to_top(self) -> None:
        domain, nodes, succ, pred = self._self_loop()
        res = run_fixpoint(
            domain,
            nodes=nodes,
            entry_nodes={0},
            successors_of=succ,
            predecessors_of=pred,
            config=FixpointConfiguration(widening_threshold=1, max_iterations=100),
            raise_on_nonconvergence=True,
        )
        assert res.converged is True
        assert res.out_states[0] == _TOP
        assert res.in_states[0] == _TOP

    def test_without_widening_does_not_converge(self) -> None:
        domain, nodes, succ, pred = self._self_loop()
        # Threshold above the iteration cap => widening never fires.
        res = run_fixpoint(
            domain,
            nodes=nodes,
            entry_nodes={0},
            successors_of=succ,
            predecessors_of=pred,
            config=FixpointConfiguration(widening_threshold=10**9, max_iterations=20),
        )
        assert res.converged is False
        assert res.iterations == 20

    def test_non_convergence_can_raise(self) -> None:
        domain, nodes, succ, pred = self._self_loop()
        with pytest.raises(FixpointDidNotConverge):
            run_fixpoint(
                domain,
                nodes=nodes,
                entry_nodes={0},
                successors_of=succ,
                predecessors_of=pred,
                config=FixpointConfiguration(widening_threshold=10**9, max_iterations=20),
                raise_on_nonconvergence=True,
            )


class DistanceToExitDomain:
    """Backward analysis: number of steps from a node's output to the exit."""

    def bottom(self) -> int:
        return 0

    def confluence(self, a: int, b: int) -> int:
        return min(a, b)

    def transfer(self, node: int, s: int) -> int:
        return s + 1

    def equals(self, a: int, b: int) -> bool:
        return a == b

    def widen(self, previous: int, current: int) -> int:
        return current


def test_backward_direction_propagates_from_exit() -> None:
    # Forward edges 0 -> 1 -> 2; run BACKWARD seeded at the exit (node 2).
    nodes, succ, pred = _topology({0: [1], 1: [2]})
    res = run_fixpoint(
        DistanceToExitDomain(),
        nodes=nodes,
        entry_nodes={2},
        successors_of=succ,
        predecessors_of=pred,
        config=FixpointConfiguration(direction=Direction.BACKWARD),
        raise_on_nonconvergence=True,
    )
    assert res.converged is True
    # Information originates at the exit and increases away from it.
    assert res.out_states[2] == 1
    assert res.out_states[1] == 2
    assert res.out_states[0] == 3


def test_entry_state_boundary_propagates() -> None:
    # A non-bottom entry boundary fact must reach downstream nodes
    # (reaching-defs is a may/union analysis; nothing kills "arg").
    nodes, succ, pred = _topology({0: [1], 1: [2]})
    res = run_fixpoint(
        ReachingDefinitionsDomain({}),  # no per-node defs; only the boundary
        nodes=nodes,
        entry_nodes={0},
        entry_state=frozenset({"arg@entry"}),
        successors_of=succ,
        predecessors_of=pred,
        raise_on_nonconvergence=True,
    )
    assert res.converged is True
    assert res.in_states[0] == {"arg@entry"}  # boundary, not bottom (empty)
    assert res.out_states[2] == {"arg@entry"}  # propagated to the exit


def test_default_entry_boundary_is_bottom() -> None:
    # Without entry_state the entry boundary defaults to domain.bottom().
    nodes, succ, pred = _topology({0: [1]})
    res = run_fixpoint(
        ReachingDefinitionsDomain({}),
        nodes=nodes,
        entry_nodes={0},
        successors_of=succ,
        predecessors_of=pred,
    )
    assert res.in_states[0] == frozenset()
