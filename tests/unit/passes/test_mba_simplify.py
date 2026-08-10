"""Config-v2 ``mba-simplify`` adapter behavior."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from d810.capabilities.resolver import CapabilityNotProvided, CapabilitySet
from d810.core.config import ProjectConfiguration
from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.ir.maturity import IRMaturity
from d810.passes.driver import run_pipeline
from d810.passes.mba_simplify import (
    MbaSimplifyCapability,
    MbaSimplifyPass,
    MbaSimplifyRequest,
    mba_simplify_pass_registry,
)
from d810.passes.pass_pipeline import (
    FunctionPipelineContext,
    PipelineConfig,
    PipelineConfigError,
    PassResult,
)
from d810.passes.registry import PassRegistryError
from d810.passes.pipeline_config_parser import pipeline_configs_from_project_config

_CONF_DIR = Path("src/d810/conf")


def _graph(func_ea: int = 0x1000) -> FlowGraph:
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
class _Source:
    func_ea: int = 0x1000
    live_source: object = "LIVE"

    @property
    def flow_graph(self) -> FlowGraph:
        return _graph(self.func_ea)


class _Facts:
    def view(self):
        return self

    def invalidate_to(self, graph, preserved):
        raise AssertionError("mba-simplify should not emit PatchPlan mutations")


class _Backend:
    def __init__(self, caps=()):
        self._caps = frozenset(caps)

    def capabilities(self):
        return self._caps

    def apply(self, plan, live_source, safety_policy):
        raise AssertionError("mba-simplify should not use MutationBackend.apply")


class _Family:
    name = "test"

    def __init__(self, specs):
        self._specs = tuple(specs)

    def detect(self, graph, capabilities, context=None):
        return object()

    def pipeline_for(self, match, context):
        return self._specs


class _MbaCapability:
    def __init__(self):
        self.requests: list[MbaSimplifyRequest] = []

    def run_mba_simplify(self, request: MbaSimplifyRequest) -> PassResult:
        self.requests.append(request)
        return PassResult()


def _context(capability: _MbaCapability | None = None) -> FunctionPipelineContext:
    source = _Source()
    capabilities = CapabilitySet()
    if capability is not None:
        capabilities = capabilities.with_capability(MbaSimplifyCapability, capability)
    return FunctionPipelineContext(
        source=source,
        graph=source.flow_graph,
        maturity=IRMaturity.GLOBAL_ANALYZED,
        project_config=None,
        facts=_Facts(),
        capabilities=capabilities,
    )


def test_mba_simplify_pass_invokes_capability_with_ordered_rules_and_options():
    capability = _MbaCapability()
    adapter = MbaSimplifyPass(
        transform_ids=("transform-b", "transform-a"),
        implementation_names=("RuleB", "RuleA"),
        transform_options={"transform-a": {"limit": 3}},
    )

    result = adapter.run(_context(capability))

    assert isinstance(result, PassResult)
    assert len(capability.requests) == 1
    request = capability.requests[0]
    assert request.live_source == "LIVE"
    assert request.func_ea == 0x1000
    assert request.maturity is IRMaturity.GLOBAL_ANALYZED
    assert request.rule_names == ("RuleB", "RuleA")
    assert request.rule_options["RuleA"] == {"limit": 3}


def test_mba_simplify_pass_requires_typed_capability():
    adapter = MbaSimplifyPass(
        transform_ids=("transform-a",),
        implementation_names=("RuleA",),
        transform_options={},
    )

    with pytest.raises(CapabilityNotProvided, match="MbaSimplifyCapability"):
        adapter.run(_context())


def test_mba_simplify_empty_rule_selection_is_noop_without_capability():
    adapter = MbaSimplifyPass(
        transform_ids=(),
        implementation_names=(),
        transform_options={},
    )

    assert isinstance(adapter.run(_context()), PassResult)


def test_mba_simplify_registry_builds_default_instruction_canary_mba_stage():
    project = ProjectConfiguration.from_file(
        _CONF_DIR / "default_instruction_only_config_v2_canary.json"
    )
    config = next(
        config
        for config in pipeline_configs_from_project_config(project)
        if config.pass_id == "mba-simplify"
    )

    spec = mba_simplify_pass_registry().build_spec(config)
    adapter = spec.pass_factory()

    assert spec.pass_id == "mba-simplify"
    assert isinstance(adapter, MbaSimplifyPass)
    assert adapter.transform_ids == tuple(config.options["transforms"])
    assert len(adapter.transform_ids) == 178
    assert "FoldReadonlyDataRule" not in adapter.implementation_names
    assert "ConstantSubtreeFoldRule" not in adapter.implementation_names
    assert "z3_solver" in spec.contract.requires.capabilities


def test_mba_simplify_registry_rejects_former_rule_selection_for_execution():
    with pytest.raises(PipelineConfigError, match="unknown fields"):
        PipelineConfig.from_dict(
            {
                "pass": "mba-simplify",
                "rules": {"include": ["RuleA"]},
            }
        )


def test_mba_simplify_registry_preserves_explicit_transform_order():
    config = PipelineConfig.from_dict(
        {
            "pass_id": "mba-simplify",
            "options": {
                "transforms": ["add-xor-2", "add-xor-1"],
                "transform_options": {},
            },
        }
    )

    adapter = mba_simplify_pass_registry().build_spec(config).pass_factory()

    assert isinstance(adapter, MbaSimplifyPass)
    assert adapter.transform_ids == ("add-xor-2", "add-xor-1")
    assert adapter.implementation_names == ("AddXor_Rule_2", "AddXor_Rule_1")


def test_mba_simplify_registry_rejects_options_for_unselected_transforms():
    config = PipelineConfig.from_dict(
        {
            "pass_id": "mba-simplify",
            "options": {
                "transforms": ["add-xor-1"],
                "transform_options": {
                    "z-3-constant-optimization": {"min_nb_opcode": 4}
                },
            },
        }
    )

    with pytest.raises(PassRegistryError, match="z-3-constant-optimization"):
        mba_simplify_pass_registry().build_spec(config)


def test_mba_simplify_pipeline_executes_when_string_and_typed_capabilities_exist():
    capability = _MbaCapability()
    config = PipelineConfig.from_dict(
        {
            "pass_id": "mba-simplify",
            "options": {
                "transforms": ["add-xor-2", "add-xor-1"],
                "transform_options": {},
            },
        }
    )
    spec = mba_simplify_pass_registry().build_spec(config)

    out = run_pipeline(
        source=_Source(),
        family=_Family((spec,)),
        backend=_Backend(caps=("local_instruction_rewrite", "z3_solver")),
        facts=_Facts(),
        project_config=None,
        maturity=IRMaturity.GLOBAL_ANALYZED,
        capabilities=CapabilitySet().with_capability(
            MbaSimplifyCapability,
            capability,
        ),
    )

    assert out == _graph()
    assert len(capability.requests) == 1
    assert capability.requests[0].rule_names == ("AddXor_Rule_2", "AddXor_Rule_1")
    assert capability.requests[0].rule_options == {}
