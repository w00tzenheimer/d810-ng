"""Unit tests for the ``d810.analyses.data_flow`` scaffold.

Landing Sequence step 3 vocabulary -- pure Python, no IDA imports.
Exercises the ``WorkingSet`` worklist logic and smoke-checks the
dataclasses / Protocol / enum the later fixpoint-solver migration
(step 5) is written against.
"""
from __future__ import annotations

import dataclasses

import pytest

from d810.analyses.data_flow import (
    AnalyzedCFG,
    Direction,
    FixpointConfiguration,
    FixpointDidNotConverge,
    FixpointResult,
    FlowDomain,
    WorkingSet,
)


class TestWorkingSet:
    def test_fifo_order_with_dedup(self) -> None:
        ws = WorkingSet([3, 1, 3, 2, 1])
        assert len(ws) == 3
        assert list(ws) == [3, 1, 2]  # insertion order, duplicates dropped
        assert [ws.pop() for _ in range(3)] == [3, 1, 2]

    def test_membership_and_bool(self) -> None:
        ws = WorkingSet()
        assert not ws
        ws.add(7)
        assert ws
        assert 7 in ws
        assert 8 not in ws

    def test_no_duplicate_while_pending(self) -> None:
        ws = WorkingSet()
        ws.add(5)
        ws.add(5)
        assert len(ws) == 1

    def test_readd_allowed_after_pop(self) -> None:
        ws = WorkingSet([1])
        assert ws.pop() == 1
        assert 1 not in ws
        ws.add(1)  # no longer pending, so it may be queued again
        assert 1 in ws and len(ws) == 1

    def test_pop_empty_raises(self) -> None:
        with pytest.raises(KeyError):
            WorkingSet().pop()


class TestConfiguration:
    def test_defaults_match_doc(self) -> None:
        cfg = FixpointConfiguration()
        assert cfg.max_iterations == 1000
        assert cfg.widening_threshold == 4
        assert cfg.descending_iterations == 0
        assert cfg.direction is Direction.FORWARD

    def test_is_frozen(self) -> None:
        cfg = FixpointConfiguration()
        with pytest.raises(dataclasses.FrozenInstanceError):
            cfg.max_iterations = 5  # type: ignore[misc]

    def test_direction_values(self) -> None:
        assert {d.value for d in Direction} == {"forward", "backward"}


class TestFixpointResultAndAnalyzedCFG:
    def test_fixpoint_result_converged_defaults_true(self) -> None:
        r = FixpointResult(in_states={0: "a"}, out_states={0: "b"}, iterations=2)
        assert r.converged is True
        assert r.in_states[0] == "a" and r.out_states[0] == "b"

    def test_analyzed_cfg_holds_graph_and_result(self) -> None:
        sentinel = object()
        r = FixpointResult(in_states={}, out_states={}, iterations=0, converged=False)
        acfg = AnalyzedCFG(graph=sentinel, result=r)
        assert acfg.graph is sentinel
        assert acfg.result.converged is False


class TestFlowDomainProtocol:
    def test_runtime_checkable_structural_match(self) -> None:
        class _Domain:
            def bottom(self): ...
            def confluence(self, left, right): ...
            def transfer(self, node, in_state): ...
            def equals(self, left, right): ...
            def widen(self, previous, current): ...

        assert isinstance(_Domain(), FlowDomain)

    def test_runtime_checkable_rejects_incomplete(self) -> None:
        class _Partial:
            def bottom(self): ...

        assert not isinstance(_Partial(), FlowDomain)


def test_fixpoint_did_not_converge_carries_counts() -> None:
    err = FixpointDidNotConverge(iterations=10, max_iterations=10)
    assert err.iterations == 10 and err.max_iterations == 10
    assert "did not converge" in str(err)
