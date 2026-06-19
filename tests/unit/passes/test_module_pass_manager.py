"""ModulePassManager project-scope behavior."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from d810.families.state_machine_cff.pipeline import (
    standard_state_machine_passes,
    state_machine_pass_registry,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.ir.maturity import IRMaturity
from d810.passes.module_pass_manager import ModulePassManager
from d810.passes.pass_pipeline import PassResult, PassSpec, default, no_caps
from d810.passes.pipeline_shadow import PipelineShadowMismatchError
from d810.passes.registry import PassRegistry, PassRegistryError
from d810.passes.scheduler import RunLater, RunLaterDomain


def _graph(func_ea: int) -> FlowGraph:
    return FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=1,
                succs=(),
                preds=(),
                flags=0,
                start_ea=func_ea,
                insn_snapshots=(),
            )
        },
        entry_serial=0,
        func_ea=func_ea,
    )


@dataclass
class _Src:
    func_ea: int
    flow_graph: FlowGraph = field(init=False)

    def __post_init__(self) -> None:
        self.flow_graph = _graph(self.func_ea)

    @property
    def live_source(self) -> object:
        return self


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


def test_module_pass_manager_stays_backend_adapter_free():
    text = Path("src/d810/passes/module_pass_manager.py").read_text()

    assert "ida_hexrays" not in text


def test_builds_state_machine_specs_from_pipeline_v2_project_config():
    live_specs = standard_state_machine_passes()
    manager = ModulePassManager(
        pass_registries={"state_machine_cff": state_machine_pass_registry()}
    )

    rebuilt_specs = manager.pass_specs_from_project_config(
        {"pipeline_v2": [spec.config.to_dict() for spec in live_specs]},
        "state_machine_cff",
    )

    assert tuple(spec.pass_id for spec in rebuilt_specs) == tuple(
        spec.pass_id for spec in live_specs
    )
    assert tuple(spec.config for spec in rebuilt_specs) == tuple(
        spec.config for spec in live_specs
    )


def test_manager_compares_pipeline_v2_shadow_with_named_registry():
    live_specs = standard_state_machine_passes()
    manager = ModulePassManager(
        pass_registries={"state_machine_cff": state_machine_pass_registry()}
    )

    comparison = manager.compare_pipeline_v2_shadow(
        {"pipeline_v2": [spec.config.to_dict() for spec in live_specs]},
        "state_machine_cff",
        live_specs,
    )

    assert comparison.enabled is True
    assert comparison.matches is True
    assert comparison.configured_pass_ids == tuple(spec.pass_id for spec in live_specs)


def test_manager_requires_pipeline_v2_shadow_match_with_named_registry():
    live_specs = standard_state_machine_passes()
    manager = ModulePassManager(
        pass_registries={"state_machine_cff": state_machine_pass_registry()}
    )

    comparison = manager.require_pipeline_v2_shadow_match(
        {"pipeline_v2": [spec.config.to_dict() for spec in live_specs]},
        "state_machine_cff",
        live_specs,
    )

    assert comparison.enabled is True
    assert comparison.matches is True


def test_manager_require_pipeline_v2_shadow_match_fails_loudly_on_drift():
    live_specs = standard_state_machine_passes()
    manager = ModulePassManager(
        pass_registries={"state_machine_cff": state_machine_pass_registry()}
    )

    with pytest.raises(PipelineShadowMismatchError) as excinfo:
        manager.require_pipeline_v2_shadow_match(
            {"pipeline_v2": [{"pass_id": "recover_dispatcher"}]},
            "state_machine_cff",
            live_specs,
        )

    assert excinfo.value.comparison.configured_pass_ids == ("recover_dispatcher",)
    assert excinfo.value.comparison.live_pass_ids == tuple(
        spec.pass_id for spec in live_specs
    )


def test_missing_pipeline_v2_is_inert():
    manager = ModulePassManager(
        pass_registries={"state_machine_cff": state_machine_pass_registry()}
    )

    assert manager.pipeline_configs_for({}) == ()
    assert manager.pass_specs_from_project_config({}, "state_machine_cff") == ()


def test_unknown_registry_fails_clearly():
    manager = ModulePassManager()

    with pytest.raises(PassRegistryError, match="unknown pass registry"):
        manager.pass_specs_from_project_config(
            {"pipeline_v2": [{"pass_id": "recover_dispatcher"}]},
            "missing",
        )


def test_owns_isolated_function_managers_per_function():
    manager = ModulePassManager()

    first = manager.function_manager_for(0x1000)
    second = manager.function_manager_for(0x2000)

    assert first is manager.function_manager_for(0x1000)
    assert second is manager.function_manager_for(0x2000)
    assert first is not second


def test_reset_function_clears_only_one_function_manager():
    manager = ModulePassManager()
    first = manager.function_manager_for(0x1000)
    second = manager.function_manager_for(0x2000)
    first.facts_for(_Src(0x1000)).put_analysis("x", 1)
    second.facts_for(_Src(0x2000)).put_analysis("x", 2)

    manager.reset_function(0x1000)

    assert first.analysis_manager_for(0x1000) is None
    assert manager.function_manager_for(0x1000) is not first
    assert manager.function_manager_for(0x2000) is second
    assert second.analysis_manager_for(0x2000).get_analysis("x") == 2


def test_reset_project_clears_all_function_managers_and_schedulers():
    manager = ModulePassManager()
    first = manager.function_manager_for(0x1000)
    second = manager.function_manager_for(0x2000)
    request = RunLater(IRMaturity.GLOBAL_ANALYZED, reason="later")
    first.scheduler.request(
        func_ea=0x1000,
        pass_id="p",
        current_maturity=IRMaturity.CANONICAL,
        run_later=request,
        domain=RunLaterDomain.PIPELINE_PASS,
    )
    second.scheduler.request(
        func_ea=0x2000,
        pass_id="p",
        current_maturity=IRMaturity.CANONICAL,
        run_later=request,
        domain=RunLaterDomain.PIPELINE_PASS,
    )

    manager.reset_project()

    assert first.scheduler.drain(
        func_ea=0x1000,
        current_maturity=IRMaturity.GLOBAL_ANALYZED,
        domain=RunLaterDomain.PIPELINE_PASS,
    ) == ()
    assert second.scheduler.drain(
        func_ea=0x2000,
        current_maturity=IRMaturity.GLOBAL_ANALYZED,
        domain=RunLaterDomain.PIPELINE_PASS,
    ) == ()
    assert manager.function_manager_for(0x1000) is not first
    assert manager.function_manager_for(0x2000) is not second


def test_run_function_uses_isolated_function_manager_state():
    calls: list[int] = []

    class _Record:
        name = "record"

        def run(self, ctx) -> PassResult:
            calls.append(ctx.source.func_ea)
            return PassResult()

    family = _MatchingFamily((PassSpec("record", _Record, no_caps, default),))
    manager = ModulePassManager()

    manager.run_function(
        source=_Src(0x1000),
        family=family,
        backend=_Backend(),
        project_config=None,
        maturity=IRMaturity.CANONICAL,
    )
    manager.run_function(
        source=_Src(0x2000),
        family=family,
        backend=_Backend(),
        project_config=None,
        maturity=IRMaturity.CANONICAL,
    )

    assert calls == [0x1000, 0x2000]
    assert manager.function_manager_for(0x1000).analysis_manager_for(0x1000)
    assert manager.function_manager_for(0x2000).analysis_manager_for(0x2000)


def test_run_function_default_path_does_not_require_pipeline_registry():
    calls: list[str] = []
    spec = PassSpec("live", _recording_pass("live", calls), no_caps, default)
    manager = ModulePassManager()

    manager.run_function(
        source=_Src(0x1000),
        family=_MatchingFamily((spec,)),
        backend=_Backend(),
        project_config={"pipeline_v2": [{"pass_id": "drifted"}]},
        maturity=IRMaturity.CANONICAL,
    )

    assert calls == ["live"]


def test_run_function_pipeline_v2_shadow_gate_matching_config_runs_live_specs():
    calls: list[str] = []
    spec = PassSpec("live", _recording_pass("live", calls), no_caps, default)
    registry = PassRegistry()
    registry.register("live", _recording_pass("configured", calls))
    manager = ModulePassManager(pass_registries={"state_machine_cff": registry})

    manager.run_function(
        source=_Src(0x1000),
        family=_MatchingFamily((spec,)),
        backend=_Backend(),
        project_config={"pipeline_v2": [spec.config.to_dict()]},
        maturity=IRMaturity.CANONICAL,
        pipeline_registry_name="state_machine_cff",
        require_pipeline_v2_shadow_match=True,
    )

    assert calls == ["live"]


def test_run_function_pipeline_v2_shadow_gate_drift_fails_before_execution():
    calls: list[str] = []
    first = PassSpec("first", _recording_pass("first", calls), no_caps, default)
    second = PassSpec("second", _recording_pass("second", calls), no_caps, default)
    registry = PassRegistry()
    registry.register("first", _recording_pass("configured_first", calls))
    registry.register("second", _recording_pass("configured_second", calls))
    manager = ModulePassManager(pass_registries={"state_machine_cff": registry})

    with pytest.raises(PipelineShadowMismatchError):
        manager.run_function(
            source=_Src(0x1000),
            family=_MatchingFamily((first, second)),
            backend=_Backend(),
            project_config={"pipeline_v2": [first.config.to_dict()]},
            maturity=IRMaturity.CANONICAL,
            pipeline_registry_name="state_machine_cff",
            require_pipeline_v2_shadow_match=True,
        )

    assert calls == []


def test_run_function_pipeline_v2_shadow_gate_requires_registry_name():
    calls: list[str] = []
    spec = PassSpec("live", _recording_pass("live", calls), no_caps, default)
    manager = ModulePassManager()

    with pytest.raises(PassRegistryError, match="requires a registry name"):
        manager.run_function(
            source=_Src(0x1000),
            family=_MatchingFamily((spec,)),
            backend=_Backend(),
            project_config={},
            maturity=IRMaturity.CANONICAL,
            require_pipeline_v2_shadow_match=True,
        )

    assert calls == []
