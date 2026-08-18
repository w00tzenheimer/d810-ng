"""ModulePassManager project-scope behavior."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.ir.maturity import IRMaturity
from d810.passes.module_pass_manager import ModulePassManager
from d810.passes.pass_pipeline import (
    PipelineConfigError,
    PassResult,
    PassSpec,
    default,
    no_caps,
)
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


class _UntouchedBackend(_Backend):
    def __init__(self):
        self.capabilities_calls = 0
        self.apply_calls = 0

    def capabilities(self):
        self.capabilities_calls += 1
        return super().capabilities()

    def apply(self, plan, live_source, safety_policy):
        self.apply_calls += 1
        return super().apply(plan, live_source, safety_policy)


class _UntouchedFamily(_MatchingFamily):
    def __init__(self, specs):
        super().__init__(specs)
        self.detect_calls = 0
        self.pipeline_for_calls = 0

    def detect(self, graph, capabilities, context=None):
        self.detect_calls += 1
        return super().detect(graph, capabilities, context=context)

    def pipeline_for(self, match, context):
        self.pipeline_for_calls += 1
        return super().pipeline_for(match, context)


def _recording_pass(name: str, calls: list[str]):
    def run(self, ctx) -> PassResult:
        calls.append(name)
        return PassResult()

    return type("_RecordPass", (), {"name": name, "run": run})


def _project_document(
    *,
    pipeline: tuple[str, ...] | None = ("recover_dispatcher",),
    additional: dict[str, object] | None = None,
    ins_rules: list[dict[str, object]] | None = None,
    blk_rules: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    config: dict[str, object] = {}
    if pipeline is not None:
        config["pipeline_v2"] = [{"pass_id": pass_id} for pass_id in pipeline]
    config.update(additional or {})
    return {
        "ins_rules": list(ins_rules or ()),
        "blk_rules": list(blk_rules or ()),
        "additional_configuration": config,
    }


def _invalid_project_documents() -> tuple[dict[str, object], ...]:
    retired_mode = "pipeline_v2_" + "mode"
    retired_shadow = "require_" + "pipeline_v2_" + "shadow_match"
    active_rule = {"name": "Legacy", "is_activated": True, "config": {}}
    return (
        _project_document(additional={retired_mode: "config-v2"}),
        _project_document(additional={retired_shadow: True}),
        _project_document(ins_rules=[active_rule]),
        _project_document(blk_rules=[active_rule]),
        _project_document(pipeline=("not-a-registered-pass",)),
        _project_document(pipeline=None),
        _project_document(pipeline=()),
    )


def test_module_pass_manager_stays_backend_adapter_free():
    text = Path("src/d810/passes/module_pass_manager.py").read_text()

    assert "ida_hexrays" not in text


def test_module_manager_has_no_shadow_comparison_api():
    assert not hasattr(ModulePassManager, "compare_" + "pipeline_v2_shadow")
    assert not hasattr(ModulePassManager, "require_" + "pipeline_v2_shadow_match")


def test_unknown_registry_fails_clearly():
    manager = ModulePassManager()

    with pytest.raises(PassRegistryError, match="unknown pass registry"):
        manager.pass_registry_for("missing")


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

    assert (
        first.scheduler.drain(
            func_ea=0x1000,
            current_maturity=IRMaturity.GLOBAL_ANALYZED,
            domain=RunLaterDomain.PIPELINE_PASS,
        )
        == ()
    )
    assert (
        second.scheduler.drain(
            func_ea=0x2000,
            current_maturity=IRMaturity.GLOBAL_ANALYZED,
            domain=RunLaterDomain.PIPELINE_PASS,
        )
        == ()
    )
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
    project_config = {
        "ins_rules": [],
        "blk_rules": [],
        "additional_configuration": {
            "pipeline_v2": [{"pass_id": "recover_dispatcher"}]
        },
    }

    manager.run_function(
        source=_Src(0x1000),
        family=family,
        backend=_Backend(),
        project_config=project_config,
        maturity=IRMaturity.CANONICAL,
        pipeline_v2_specs=(family._specs[0],),
    )
    manager.run_function(
        source=_Src(0x2000),
        family=family,
        backend=_Backend(),
        project_config=project_config,
        maturity=IRMaturity.CANONICAL,
        pipeline_v2_specs=(family._specs[0],),
    )

    assert calls == [0x1000, 0x2000]
    assert manager.function_manager_for(0x1000).analysis_manager_for(0x1000)
    assert manager.function_manager_for(0x2000).analysis_manager_for(0x2000)


def test_run_function_rejects_empty_compiled_specs_before_manager_creation():
    calls: list[str] = []
    spec = PassSpec("live", _recording_pass("live", calls), no_caps, default)
    manager = ModulePassManager()
    project_config = {
        "ins_rules": [],
        "blk_rules": [],
        "additional_configuration": {
            "pipeline_v2": [{"pass_id": "recover_dispatcher"}]
        },
    }

    with pytest.raises(PipelineConfigError, match="pipeline_v2_specs"):
        manager.run_function(
            source=_Src(0x1000),
            family=_MatchingFamily((spec,)),
            backend=_Backend(),
            project_config=project_config,
            maturity=IRMaturity.CANONICAL,
            pipeline_v2_specs=(),
        )

    assert calls == []
    assert manager._function_managers == {}


def test_run_function_executes_explicit_compiled_specs():
    calls: list[str] = []
    spec = PassSpec("live", _recording_pass("live", calls), no_caps, default)
    manager = ModulePassManager()

    manager.run_function(
        source=_Src(0x1000),
        family=_MatchingFamily((spec,)),
        backend=_Backend(),
        project_config={
            "ins_rules": [],
            "blk_rules": [],
            "additional_configuration": {
                "pipeline_v2": [{"pass_id": "recover_dispatcher"}]
            },
        },
        maturity=IRMaturity.CANONICAL,
        pipeline_v2_specs=(spec,),
    )

    assert calls == ["live"]


def test_run_function_derives_specs_from_canonical_pipeline():
    calls: list[str] = []
    spec = PassSpec(
        "recover_dispatcher", _recording_pass("recover_dispatcher", calls), no_caps, default
    )
    registry = PassRegistry()
    registry.register("recover_dispatcher", _recording_pass("recover_dispatcher", calls))
    manager = ModulePassManager(pass_registries={"state_machine_cff": registry})

    manager.run_function(
        source=_Src(0x1000),
        family=_MatchingFamily((spec,)),
        backend=_Backend(),
        project_config={
            "ins_rules": [],
            "blk_rules": [],
            "additional_configuration": {
                "pipeline_v2": [{"pass_id": "recover_dispatcher"}]
            },
        },
        maturity=IRMaturity.CANONICAL,
        pipeline_registry_name="state_machine_cff",
    )

    assert calls == ["recover_dispatcher"]


@pytest.mark.parametrize("use_explicit_specs", [False, True])
@pytest.mark.parametrize("project_config", _invalid_project_documents())
def test_run_function_strictly_rejects_invalid_project_before_mutation(
    project_config, use_explicit_specs: bool
):
    calls: list[str] = []
    spec = PassSpec(
        "recover_dispatcher",
        _recording_pass("recover_dispatcher", calls),
        no_caps,
        default,
    )
    family = _UntouchedFamily((spec,))
    backend = _UntouchedBackend()
    manager = ModulePassManager()

    with pytest.raises(PipelineConfigError, match="migrate_project_config_v2.py"):
        manager.run_function(
            source=_Src(0x1000),
            family=family,
            backend=backend,
            project_config=project_config,
            maturity=IRMaturity.CANONICAL,
            pipeline_v2_specs=(spec,) if use_explicit_specs else None,
        )

    assert manager._function_managers == {}
    assert calls == []
    assert family.detect_calls == 0
    assert family.pipeline_for_calls == 0
    assert backend.capabilities_calls == 0
    assert backend.apply_calls == 0
