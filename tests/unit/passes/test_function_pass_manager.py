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
    PipelineConfigError,
    PassResult,
    PassSpec,
    SchedulerPolicy,
    default,
    no_caps,
)
from d810.passes.pipeline_shadow import PipelineShadowMismatchError
from d810.passes.registry import PassRegistry
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


def _recording_pass(name: str, calls: list[str]):
    def run(self, ctx) -> PassResult:
        calls.append(name)
        return PassResult()

    return type("_RecordPass", (), {"name": name, "run": run})


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
    class _NeedsMemorySsa:
        name = "needs_memoryssa"

        def run(self, ctx) -> PassResult:
            return PassResult()

    family = _MatchingFamily(
        (
            PassSpec(
                "needs_memoryssa",
                _NeedsMemorySsa,
                no_caps,
                default,
                analyses=AnalysisContract(required=frozenset({"memoryssa"})),
            ),
        )
    )

    with pytest.raises(AnalysisContractError, match="needs_memoryssa"):
        FunctionPassManager().run(
            source=_Src(),
            family=family,
            backend=_Backend(),
            project_config=None,
            maturity=IRMaturity.CANONICAL,
        )


def test_manager_satisfies_domtree_from_default_provider():
    captured: dict[str, object] = {}

    class _NeedsDomtree:
        name = "needs_domtree"

        def run(self, ctx) -> PassResult:
            domtree = ctx.facts.require_analysis("domtree")
            captured["dominates_entry"] = domtree.dominates(0, 0)
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

    FunctionPassManager().run(
        source=_Src(),
        family=family,
        backend=_Backend(),
        project_config=None,
        maturity=IRMaturity.CANONICAL,
    )

    assert captured == {"dominates_entry": True}


def test_manager_registers_provider_on_existing_facts():
    captured: dict[str, object] = {}

    class _NeedsAa:
        name = "needs_aa"

        def run(self, ctx) -> PassResult:
            captured["aa"] = ctx.facts.require_analysis("aa")
            return PassResult()

    manager = FunctionPassManager(analysis_providers={})
    manager.facts_for(_Src())
    manager.register_analysis_provider("aa", lambda graph: f"AA:{graph.func_ea:x}")

    manager.run(
        source=_Src(),
        family=_MatchingFamily(
            (
                PassSpec(
                    "needs_aa",
                    _NeedsAa,
                    no_caps,
                    default,
                    analyses=AnalysisContract(required=frozenset({"aa"})),
                ),
            )
        ),
        backend=_Backend(),
        project_config=None,
        maturity=IRMaturity.CANONICAL,
    )

    assert captured == {"aa": "AA:1000"}


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


def test_manager_pipeline_v2_shadow_gate_matching_config_runs_live_specs():
    calls: list[str] = []
    spec = PassSpec("live", _recording_pass("live", calls), no_caps, default)
    registry = PassRegistry()
    registry.register("live", _recording_pass("configured", calls))

    FunctionPassManager().run(
        source=_Src(),
        family=_MatchingFamily((spec,)),
        backend=_Backend(),
        project_config={"pipeline_v2": [spec.config.to_dict()]},
        maturity=IRMaturity.CANONICAL,
        pipeline_v2_shadow_registry=registry,
        require_pipeline_v2_shadow_match=True,
    )

    assert calls == ["live"]


def test_manager_pipeline_v2_shadow_gate_drift_fails_before_execution():
    calls: list[str] = []
    first = PassSpec("first", _recording_pass("first", calls), no_caps, default)
    second = PassSpec("second", _recording_pass("second", calls), no_caps, default)
    registry = PassRegistry()
    registry.register("first", _recording_pass("configured_first", calls))
    registry.register("second", _recording_pass("configured_second", calls))

    with pytest.raises(PipelineShadowMismatchError):
        FunctionPassManager().run(
            source=_Src(),
            family=_MatchingFamily((first, second)),
            backend=_Backend(),
            project_config={"pipeline_v2": [first.config.to_dict()]},
            maturity=IRMaturity.CANONICAL,
            pipeline_v2_shadow_registry=registry,
            require_pipeline_v2_shadow_match=True,
        )

    assert calls == []


def test_manager_pipeline_v2_shadow_gate_requires_registry_when_enabled():
    calls: list[str] = []
    spec = PassSpec("live", _recording_pass("live", calls), no_caps, default)

    with pytest.raises(PipelineConfigError, match="requires a pass registry"):
        FunctionPassManager().run(
            source=_Src(),
            family=_MatchingFamily((spec,)),
            backend=_Backend(),
            project_config={},
            maturity=IRMaturity.CANONICAL,
            require_pipeline_v2_shadow_match=True,
        )

    assert calls == []


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
