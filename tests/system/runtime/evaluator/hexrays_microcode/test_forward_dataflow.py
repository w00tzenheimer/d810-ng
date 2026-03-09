"""Unit tests for the generic forward dataflow fixpoint engine.

These tests exercise `run_forward_fixpoint` with simple integer-based
domains -- no IDA dependency required.
"""
from __future__ import annotations

import pytest

from d810.evaluator.hexrays_microcode.forward_dataflow import (
    FixpointResult,
    run_forward_fixpoint,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

BOTTOM: dict[str, int] = {}


def _identity_transfer(node_id: int, in_state: dict[str, int]) -> dict[str, int]:
    """Pass-through transfer: OUT = IN."""
    return dict(in_state)


def _add_one_transfer(node_id: int, in_state: dict[str, int]) -> dict[str, int]:
    """Transfer that increments ``x`` by 1."""
    out = dict(in_state)
    out["x"] = out.get("x", 0) + 1
    return out


def _union_meet(pred_outs: list[dict[str, int]]) -> dict[str, int]:
    """Meet = union of keys, taking the max value for each key."""
    result: dict[str, int] = {}
    for state in pred_outs:
        for k, v in state.items():
            result[k] = max(result.get(k, v), v)
    return result


def _simple_meet(pred_outs: list[dict[str, int]]) -> dict[str, int]:
    """Meet = union of keys, taking the max value for each key (same as _union_meet)."""
    return _union_meet(pred_outs)


def _build_graph(
    edges: list[tuple[int, int]],
) -> tuple[set[int], dict[int, list[int]], dict[int, list[int]]]:
    """Build adjacency lists from edge list.

    Returns:
        (nodes, pred_map, succ_map)
    """
    nodes: set[int] = set()
    pred_map: dict[int, list[int]] = {}
    succ_map: dict[int, list[int]] = {}
    for src, dst in edges:
        nodes.add(src)
        nodes.add(dst)
        succ_map.setdefault(src, []).append(dst)
        pred_map.setdefault(dst, []).append(src)
    # Ensure every node has an entry
    for n in nodes:
        pred_map.setdefault(n, [])
        succ_map.setdefault(n, [])
    return nodes, pred_map, succ_map


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSingleBlockPropagation:
    """One block, entry state={x: 5}, identity transfer -> OUT = {x: 5}."""

    def test_single_block(self) -> None:
        result = run_forward_fixpoint(
            nodes=[0],
            entry_node=0,
            entry_state={"x": 5},
            bottom=BOTTOM,
            predecessors_of=lambda _: [],
            successors_of=lambda _: [],
            meet=_simple_meet,
            transfer=_identity_transfer,
        )
        assert isinstance(result, FixpointResult)
        assert result.out_states[0] == {"x": 5}
        assert result.in_states[0] == {"x": 5}


class TestLinearChainPropagation:
    """3 blocks in chain (0->1->2), transfer adds 1 -> OUT[2] = {x: 3}."""

    def test_linear_chain(self) -> None:
        edges = [(0, 1), (1, 2)]
        nodes, pred_map, succ_map = _build_graph(edges)

        result = run_forward_fixpoint(
            nodes=nodes,
            entry_node=0,
            entry_state={"x": 1},
            bottom=BOTTOM,
            predecessors_of=lambda n: pred_map[n],
            successors_of=lambda n: succ_map[n],
            meet=_simple_meet,
            transfer=_add_one_transfer,
        )
        # Entry: IN={x:1}, transfer adds 1 -> OUT[0]={x:2}
        # Block 1: IN=meet([OUT[0]])={x:2}, transfer -> OUT[1]={x:3}
        # Block 2: IN=meet([OUT[1]])={x:3}, transfer -> OUT[2]={x:4}
        assert result.out_states[0] == {"x": 2}
        assert result.out_states[1] == {"x": 3}
        assert result.out_states[2] == {"x": 4}


class TestBranchAndMergeMeet:
    """Diamond: 0->{1,2}->3. Different transfers on branches, meet at 3."""

    def test_diamond(self) -> None:
        edges = [(0, 1), (0, 2), (1, 3), (2, 3)]
        nodes, pred_map, succ_map = _build_graph(edges)

        def branch_transfer(node_id: int, in_state: dict[str, int]) -> dict[str, int]:
            out = dict(in_state)
            if node_id == 0:
                out["x"] = 0
            elif node_id == 1:
                out["x"] = 10
            elif node_id == 2:
                out["x"] = 20
            else:
                pass  # node 3: identity
            return out

        result = run_forward_fixpoint(
            nodes=nodes,
            entry_node=0,
            entry_state={"x": 0},
            bottom=BOTTOM,
            predecessors_of=lambda n: pred_map[n],
            successors_of=lambda n: succ_map[n],
            meet=_union_meet,
            transfer=branch_transfer,
        )
        # Block 3: IN = meet([OUT[1]={x:10}, OUT[2]={x:20}]) = {x: 20} (max)
        assert result.in_states[3] == {"x": 20}


class TestUnreachableBlockStaysBottom:
    """Block 99 has no predecessors, not connected -> stays at bottom."""

    def test_unreachable(self) -> None:
        # Two connected blocks + one isolated block
        result = run_forward_fixpoint(
            nodes=[0, 1, 99],
            entry_node=0,
            entry_state={"x": 5},
            bottom=BOTTOM,
            predecessors_of=lambda n: [0] if n == 1 else [],
            successors_of=lambda n: [1] if n == 0 else [],
            meet=_simple_meet,
            transfer=_identity_transfer,
        )
        assert result.in_states[99] == BOTTOM
        assert result.out_states[99] == BOTTOM


class TestWorklistConverges:
    """Loop graph (0->1->0) with monotone transfer -> converges."""

    def test_loop_convergence(self) -> None:
        edges = [(0, 1), (1, 0)]
        nodes, pred_map, succ_map = _build_graph(edges)

        # Monotone: increment x but cap at 10 (ensures convergence)
        def capped_transfer(node_id: int, in_state: dict[str, int]) -> dict[str, int]:
            out = dict(in_state)
            val = out.get("x", 0)
            out["x"] = min(val + 1, 10)
            return out

        result = run_forward_fixpoint(
            nodes=nodes,
            entry_node=0,
            entry_state={"x": 0},
            bottom=BOTTOM,
            predecessors_of=lambda n: pred_map[n],
            successors_of=lambda n: succ_map[n],
            meet=_union_meet,
            transfer=capped_transfer,
            max_iterations=200,
        )
        # Should converge: both blocks end up with x=10
        assert result.out_states[0]["x"] == 10
        assert result.out_states[1]["x"] == 10
        assert result.iterations < 200


class TestFixpointResultHasIterationCount:
    """Verify iterations field is populated."""

    def test_iterations_populated(self) -> None:
        result = run_forward_fixpoint(
            nodes=[0],
            entry_node=0,
            entry_state={"x": 1},
            bottom=BOTTOM,
            predecessors_of=lambda _: [],
            successors_of=lambda _: [],
            meet=_simple_meet,
            transfer=_identity_transfer,
        )
        assert result.iterations >= 1


class TestMaxIterationsStopsDivergence:
    """Non-monotone transfer with max_iterations=10 -> returns after <=10."""

    def test_max_iterations(self) -> None:
        edges = [(0, 1), (1, 0)]
        nodes, pred_map, succ_map = _build_graph(edges)

        call_count = 0

        def divergent_transfer(
            node_id: int, in_state: dict[str, int]
        ) -> dict[str, int]:
            nonlocal call_count
            call_count += 1
            # Always produces a new value -> never converges
            return {"x": call_count}

        result = run_forward_fixpoint(
            nodes=nodes,
            entry_node=0,
            entry_state={"x": 0},
            bottom=BOTTOM,
            predecessors_of=lambda n: pred_map[n],
            successors_of=lambda n: succ_map[n],
            meet=_union_meet,
            transfer=divergent_transfer,
            max_iterations=10,
        )
        assert result.iterations == 10
