"""Config-v2 ``mba-simplify`` adapter behavior."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from d810.capabilities.resolver import CapabilityNotProvided, CapabilitySet
from d810.core.config import ProjectConfiguration
from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.ir.maturity import IRMaturity
from d810.passes.driver import CapabilityError, run_pipeline
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
        rule_names=("RuleB", "RuleA"),
        rule_options={"RuleA": {"limit": 3}},
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
    adapter = MbaSimplifyPass(rule_names=("RuleA",), rule_options={})

    with pytest.raises(CapabilityNotProvided, match="MbaSimplifyCapability"):
        adapter.run(_context())


def test_mba_simplify_empty_rule_selection_is_noop_without_capability():
    adapter = MbaSimplifyPass(rule_names=(), rule_options={})

    assert isinstance(adapter.run(_context()), PassResult)


def test_mba_simplify_registry_builds_default_instruction_shadow_first_pass():
    project = ProjectConfiguration.from_file(
        _CONF_DIR / "default_instruction_only.pipeline_v2.json"
    )
    config = pipeline_configs_from_project_config(project)[0]

    spec = mba_simplify_pass_registry().build_spec(config)
    adapter = spec.pass_factory()

    assert spec.pass_id == "mba-simplify"
    assert isinstance(adapter, MbaSimplifyPass)
    assert adapter.rule_names == config.rules.include_order
    assert len(adapter.rule_names) == 179
    assert adapter.rule_options["FoldReadonlyDataRule"] == {
        "fold_writable_constants": True
    }
    assert "z3_solver" in spec.contract.requires.capabilities


def test_mba_simplify_registry_rejects_rule_groups_for_execution():
    config = PipelineConfig.from_dict(
        {
            "pass": "mba-simplify",
            "rules": {
                "include_groups": ["all"],
                "include": ["RuleA"],
            },
        }
    )

    with pytest.raises(PipelineConfigError, match="rule groups"):
        mba_simplify_pass_registry().build_spec(config)


def test_mba_simplify_registry_applies_explicit_excludes():
    config = PipelineConfig.from_dict(
        {
            "pass": "mba-simplify",
            "rules": {
                "include": ["RuleB", "RuleA", "RuleC"],
                "exclude": ["RuleA"],
            },
        }
    )

    adapter = mba_simplify_pass_registry().build_spec(config).pass_factory()

    assert isinstance(adapter, MbaSimplifyPass)
    assert adapter.rule_names == ("RuleB", "RuleC")


def test_mba_simplify_registry_rejects_options_for_unselected_rules():
    config = PipelineConfig.from_dict(
        {
            "pass": "mba-simplify",
            "rules": {
                "include": ["RuleA"],
                "options": {"RuleB": {"limit": 3}},
            },
        }
    )

    with pytest.raises(PipelineConfigError, match="RuleB"):
        mba_simplify_pass_registry().build_spec(config)


def test_mba_simplify_pipeline_missing_backend_capability_fails_before_execution():
    capability = _MbaCapability()
    config = PipelineConfig.from_dict(
        {
            "pass": "mba-simplify",
            "requires": {"capabilities": ["local_instruction_rewrite"]},
            "rules": {"include": ["RuleA"]},
        }
    )
    spec = mba_simplify_pass_registry().build_spec(config)

    with pytest.raises(CapabilityError, match="local_instruction_rewrite"):
        run_pipeline(
            source=_Source(),
            family=_Family((spec,)),
            backend=_Backend(caps=()),
            facts=_Facts(),
            project_config=None,
            maturity=IRMaturity.GLOBAL_ANALYZED,
            capabilities=CapabilitySet().with_capability(
                MbaSimplifyCapability,
                capability,
            ),
        )

    assert capability.requests == []


def test_mba_simplify_pipeline_executes_when_string_and_typed_capabilities_exist():
    capability = _MbaCapability()
    config = PipelineConfig.from_dict(
        {
            "pass": "mba-simplify",
            "requires": {
                "capabilities": ["local_instruction_rewrite", "z3_solver"]
            },
            "rules": {
                "include": ["RuleB", "RuleA"],
                "options": {"RuleA": {"limit": 3}},
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
    assert capability.requests[0].rule_names == ("RuleB", "RuleA")
    assert capability.requests[0].rule_options["RuleA"] == {"limit": 3}
