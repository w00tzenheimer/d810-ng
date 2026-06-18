"""FunctionPassManager wrapper behavior."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.ir.maturity import IRMaturity
from d810.passes.driver import AnalysisContractError
from d810.passes.function_pass_manager import FunctionPassManager
from d810.passes.pass_pipeline import (
    AnalysisContract,
    PassResult,
    PassSpec,
    SchedulerPolicy,
    default,
    no_caps,
)
from d810.passes.scheduler import RunLater, RunLaterDomain

_GRAPH = FlowGraph(
    blocks={
        0: BlockSnapshot(
            serial=0,
            block_type=1,
            succs=(),
            preds=(),
            flags=0,
            start_ea=0x1000,
            insn_snapshots=(),
        )
    },
    entry_serial=0,
    func_ea=0x1000,
)


@dataclass
class _Src:
    flow_graph: object = _GRAPH
    func_ea: int = 0x1000
    live_source: object = "LIVE"


class _Backend:
    def capabilities(self):
        return frozenset()

    def apply(self, plan, live_source, safety_policy):
        raise AssertionError("unexpected backend mutation")


class _MatchingFamily:
    name = "matching"

    def __init__(self, specs):
        self._specs = tuple(specs)

    def detect(self, graph, capabilities, context=None):
        return object()

    def pipeline_for(self, match, context):
        return self._specs


def test_manager_threads_scheduler_across_maturity_runs():
    calls: list[IRMaturity] = []
    request = RunLater(IRMaturity.GLOBAL_ANALYZED, reason="later facts")

    class _AskLater:
        name = "ask_later"

        def run(self, ctx) -> PassResult:
            calls.append(ctx.maturity)
            if ctx.maturity is IRMaturity.CANONICAL:
                return PassResult(run_later=(request,))
            return PassResult()

    family = _MatchingFamily(
        (
            PassSpec(
                "ask_later",
                _AskLater,
                no_caps,
                default,
                scheduler_policy=SchedulerPolicy.REPLAY_AFTER_PIPELINE,
            ),
        )
    )
    manager = FunctionPassManager()

    manager.run(
        source=_Src(),
        family=family,
        backend=_Backend(),
        project_config=None,
        maturity=IRMaturity.CANONICAL,
    )
    assert calls == [IRMaturity.CANONICAL]
    assert manager.scheduler.drain(
        func_ea=0x1000,
        current_maturity=IRMaturity.GLOBAL_ANALYZED,
        domain=RunLaterDomain.OPTIMIZER_RULE,
    ) == ()

    manager.run(
        source=_Src(),
        family=family,
        backend=_Backend(),
        project_config=None,
        maturity=IRMaturity.GLOBAL_ANALYZED,
    )

    assert calls == [
        IRMaturity.CANONICAL,
        IRMaturity.GLOBAL_ANALYZED,
        IRMaturity.GLOBAL_ANALYZED,
    ]


def test_manager_bubbles_analysis_contract_failure_with_pass_id():
    class _NeedsDomtree:
        name = "needs_domtree"

        def run(self, ctx) -> PassResult:
            return PassResult()

    family = _MatchingFamily(
        (
            PassSpec(
                "needs_domtree",
                _NeedsDomtree,
                no_caps,
                default,
                analyses=AnalysisContract(required=frozenset({"domtree"})),
            ),
        )
    )

    with pytest.raises(AnalysisContractError, match="needs_domtree"):
        FunctionPassManager().run(
            source=_Src(),
            family=family,
            backend=_Backend(),
            project_config=None,
            maturity=IRMaturity.CANONICAL,
        )


def test_manager_owns_analysis_manager_per_function():
    manager = FunctionPassManager()
    family = _MatchingFamily(())

    manager.run(
        source=_Src(),
        family=family,
        backend=_Backend(),
        project_config=None,
        maturity=IRMaturity.CANONICAL,
    )

    facts = manager.analysis_manager_for(0x1000)
    assert facts is not None
    assert facts.graph is _GRAPH


def test_manager_threads_input_facts_and_seeded_analysis_inputs():
    captured: dict[str, object] = {}

    class _ReadFacts:
        name = "read_facts"

        def run(self, ctx) -> PassResult:
            captured["observations"] = tuple(ctx.facts.active_observations)
            captured["range_evidence"] = ctx.facts.get_analysis("range_evidence")
            return PassResult()

    family = _MatchingFamily(
        (
            PassSpec("read_facts", _ReadFacts, no_caps, default),
        )
    )
    manager = FunctionPassManager()

    manager.run(
        source=_Src(),
        family=family,
        backend=_Backend(),
        project_config=None,
        maturity=IRMaturity.CANONICAL,
        input_facts=SimpleNamespace(active_observations=("obs",)),
        analysis_seeds={"range_evidence": "R"},
    )

    assert captured == {
        "observations": ("obs",),
        "range_evidence": "R",
    }


def test_manager_replaces_and_clears_input_facts_between_runs():
    observations: list[tuple[str, ...]] = []

    class _ReadFacts:
        name = "read_facts"

        def run(self, ctx) -> PassResult:
            observations.append(tuple(ctx.facts.active_observations))
            return PassResult()

    family = _MatchingFamily((PassSpec("read_facts", _ReadFacts, no_caps, default),))
    manager = FunctionPassManager()

    manager.run(
        source=_Src(),
        family=family,
        backend=_Backend(),
        project_config=None,
        maturity=IRMaturity.CANONICAL,
        input_facts=SimpleNamespace(active_observations=("first",)),
    )
    manager.run(
        source=_Src(),
        family=family,
        backend=_Backend(),
        project_config=None,
        maturity=IRMaturity.CANONICAL,
        input_facts=SimpleNamespace(active_observations=("second",)),
    )
    manager.run(
        source=_Src(),
        family=family,
        backend=_Backend(),
        project_config=None,
        maturity=IRMaturity.CANONICAL,
        input_facts=None,
    )

    assert observations == [("first",), ("second",), ()]


def test_manager_reset_func_clears_owned_facts_and_pipeline_scheduler():
    manager = FunctionPassManager()
    manager.facts_for(_Src()).put_analysis("published", object())
    manager.scheduler.request(
        func_ea=0x1000,
        pass_id="recover_dispatcher",
        current_maturity=IRMaturity.CANONICAL,
        run_later=RunLater(IRMaturity.GLOBAL_ANALYZED),
        domain=RunLaterDomain.PIPELINE_PASS,
    )

    manager.reset_func(0x1000)

    assert manager.analysis_manager_for(0x1000) is None
    assert manager.scheduler.drain(
        func_ea=0x1000,
        current_maturity=IRMaturity.GLOBAL_ANALYZED,
        domain=RunLaterDomain.PIPELINE_PASS,
    ) == ()


def test_function_pass_manager_stays_ida_free():
    source = Path("src/d810/passes/function_pass_manager.py").read_text()
    assert "ida_hexrays" not in source
