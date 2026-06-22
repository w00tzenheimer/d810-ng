"""Config-v2 simple legacy flow-rule adapter behavior."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from d810.capabilities.resolver import CapabilityNotProvided, CapabilitySet
from d810.core.config import ProjectConfiguration
from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.ir.maturity import IRMaturity
from d810.passes.driver import CapabilityError, run_pipeline
from d810.passes.legacy_flow_rules import (
    LEGACY_FLOW_RULE_ADAPTER_CAPABILITY,
    LegacyFlowRuleAdapterCapability,
    LegacyFlowRuleAdapterPass,
    LegacyFlowRuleRequest,
    legacy_flow_rule_pass_registry,
    register_legacy_flow_rule_passes,
)
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.passes.pass_pipeline import (
    FunctionPipelineContext,
    PipelineConfig,
    PipelineConfigError,
    PassResult,
)
from d810.passes.pipeline_config_parser import (
    pass_specs_from_project_config,
    pipeline_configs_from_project_config,
)
from d810.passes.registry import PassRegistry, UnknownPassIdError

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
        raise AssertionError("legacy flow-rule adapter should not emit PatchPlan mutations")


class _Backend:
    def __init__(self, caps=()):
        self._caps = frozenset(caps)

    def capabilities(self):
        return self._caps

    def apply(self, plan, live_source, safety_policy):
        raise AssertionError("legacy flow-rule adapter should not use MutationBackend.apply")


class _Family:
    name = "test"

    def __init__(self, specs):
        self._specs = tuple(specs)

    def detect(self, graph, capabilities, context=None):
        return object()

    def pipeline_for(self, match, context):
        return self._specs


class _FlowRuleCapability:
    def __init__(self):
        self.requests: list[LegacyFlowRuleRequest] = []

    def run_legacy_flow_rule(self, request: LegacyFlowRuleRequest) -> PassResult:
        self.requests.append(request)
        return PassResult()


def _context(
    capability: _FlowRuleCapability | None = None,
) -> FunctionPipelineContext:
    source = _Source()
    capabilities = CapabilitySet()
    if capability is not None:
        capabilities = capabilities.with_capability(
            LegacyFlowRuleAdapterCapability,
            capability,
        )
    return FunctionPipelineContext(
        source=source,
        graph=source.flow_graph,
        maturity=IRMaturity.GLOBAL_ANALYZED,
        project_config=None,
        facts=_Facts(),
        capabilities=capabilities,
    )


def test_legacy_flow_rule_pass_invokes_capability_with_options():
    capability = _FlowRuleCapability()
    adapter = LegacyFlowRuleAdapterPass(
        name="jump-fixer",
        legacy_rule="JumpFixer",
        rule_options={"enabled_rules": ["JnzRule1"]},
    )

    result = adapter.run(_context(capability))

    assert isinstance(result, PassResult)
    assert len(capability.requests) == 1
    request = capability.requests[0]
    assert request.live_source == "LIVE"
    assert request.func_ea == 0x1000
    assert request.maturity is IRMaturity.GLOBAL_ANALYZED
    assert request.pass_id == "jump-fixer"
    assert request.legacy_rule == "JumpFixer"
    assert request.rule_options == {"enabled_rules": ["JnzRule1"]}


def test_legacy_flow_rule_pass_requires_typed_capability():
    adapter = LegacyFlowRuleAdapterPass(
        name="jump-fixer",
        legacy_rule="JumpFixer",
        rule_options={},
    )

    with pytest.raises(CapabilityNotProvided, match="LegacyFlowRuleAdapterCapability"):
        adapter.run(_context())


def test_legacy_flow_rule_registry_builds_jump_fixer_shadow_entry():
    project = ProjectConfiguration.from_file(
        _CONF_DIR / "hodur_flag2.pipeline_v2.json"
    )
    config = pipeline_configs_from_project_config(project)[-1]

    spec = legacy_flow_rule_pass_registry().build_spec(config)
    adapter = spec.pass_factory()

    assert spec.pass_id == "jump-fixer"
    assert spec.contract.requires.capabilities == frozenset(
        {LEGACY_FLOW_RULE_ADAPTER_CAPABILITY}
    )
    assert isinstance(adapter, LegacyFlowRuleAdapterPass)
    assert adapter.legacy_rule == "JumpFixer"
    assert "JmpRuleZ3Const" in adapter.rule_options["enabled_rules"]


@pytest.mark.parametrize(
    ("pass_id", "legacy_rule"),
    [
        ("global-constant-inliner", "GlobalConstantInliner"),
        ("forward-constant-propagation", "ForwardConstantPropagationRule"),
        ("identity-call-resolver", "IdentityCallResolver"),
        ("indirect-branch-resolver", "IndirectBranchResolver"),
        ("indirect-call-resolver", "IndirectCallResolver"),
        ("mba-state-preconditioner", "MbaStatePreconditioner"),
        ("jump-fixer", "JumpFixer"),
    ],
)
def test_legacy_flow_rule_registry_builds_supported_simple_ids(
    pass_id,
    legacy_rule,
):
    config = PipelineConfig.from_dict(
        {
            "pass": pass_id,
            "requires": {
                "capabilities": [LEGACY_FLOW_RULE_ADAPTER_CAPABILITY],
            },
            "options": {
                "legacy_rule": legacy_rule,
                "limit": 3,
            },
        }
    )

    adapter = legacy_flow_rule_pass_registry().build_spec(config).pass_factory()

    assert isinstance(adapter, LegacyFlowRuleAdapterPass)
    assert adapter.name == pass_id
    assert adapter.legacy_rule == legacy_rule
    assert adapter.rule_options == {"limit": 3}


def test_legacy_flow_rule_registry_rejects_mismatched_legacy_rule():
    config = PipelineConfig.from_dict(
        {
            "pass": "jump-fixer",
            "options": {"legacy_rule": "ForwardConstantPropagationRule"},
        }
    )

    with pytest.raises(PipelineConfigError, match="JumpFixer"):
        legacy_flow_rule_pass_registry().build_spec(config)


def test_legacy_flow_rule_registry_rejects_rules_selection():
    config = PipelineConfig.from_dict(
        {
            "pass": "jump-fixer",
            "options": {"legacy_rule": "JumpFixer"},
            "rules": {"include": ["JnzRule1"]},
        }
    )

    with pytest.raises(PipelineConfigError, match="rules"):
        legacy_flow_rule_pass_registry().build_spec(config)


def test_legacy_flow_rule_pipeline_missing_backend_capability_fails_before_execution():
    capability = _FlowRuleCapability()
    config = PipelineConfig.from_dict(
        {
            "pass": "jump-fixer",
            "requires": {
                "capabilities": [LEGACY_FLOW_RULE_ADAPTER_CAPABILITY],
            },
            "options": {"legacy_rule": "JumpFixer"},
        }
    )
    spec = legacy_flow_rule_pass_registry().build_spec(config)

    with pytest.raises(CapabilityError, match=LEGACY_FLOW_RULE_ADAPTER_CAPABILITY):
        run_pipeline(
            source=_Source(),
            family=_Family((spec,)),
            backend=_Backend(caps=()),
            facts=_Facts(),
            project_config=None,
            maturity=IRMaturity.GLOBAL_ANALYZED,
            capabilities=CapabilitySet().with_capability(
                LegacyFlowRuleAdapterCapability,
                capability,
            ),
        )

    assert capability.requests == []


def test_legacy_flow_rule_pipeline_executes_when_string_and_typed_capabilities_exist():
    capability = _FlowRuleCapability()
    config = PipelineConfig.from_dict(
        {
            "pass": "jump-fixer",
            "requires": {
                "capabilities": [LEGACY_FLOW_RULE_ADAPTER_CAPABILITY],
            },
            "options": {
                "legacy_rule": "JumpFixer",
                "enabled_rules": ["JnzRule1"],
            },
        }
    )
    spec = legacy_flow_rule_pass_registry().build_spec(config)

    out = run_pipeline(
        source=_Source(),
        family=_Family((spec,)),
        backend=_Backend(caps=(LEGACY_FLOW_RULE_ADAPTER_CAPABILITY,)),
        facts=_Facts(),
        project_config=None,
        maturity=IRMaturity.GLOBAL_ANALYZED,
        capabilities=CapabilitySet().with_capability(
            LegacyFlowRuleAdapterCapability,
            capability,
        ),
    )

    assert out == _graph()
    assert len(capability.requests) == 1
    assert capability.requests[0].legacy_rule == "JumpFixer"
    assert capability.requests[0].rule_options == {"enabled_rules": ["JnzRule1"]}


def test_operational_registry_builds_mba_spine_and_simple_block_shadow():
    shadow = ProjectConfiguration.from_file(
        _CONF_DIR / "default_unflattening_tigress_indirect.pipeline_v2.json"
    )

    specs = pass_specs_from_project_config(
        shadow,
        operational_config_v2_pass_registry(),
    )

    assert [spec.pass_id for spec in specs] == [
        "mba-simplify",
        "recover_dispatcher",
        "recover_state_transitions",
        "plan_semantic_regions",
        "lower_state_machine",
        "cleanup_residual_dispatcher",
        "jump-fixer",
    ]


def test_operational_registry_still_fails_on_unregistered_block_level_egglog():
    shadow = ProjectConfiguration.from_file(
        _CONF_DIR / "example_libobfuscated.pipeline_v2.json"
    )

    with pytest.raises(UnknownPassIdError, match="block-level-egglog-optimizer"):
        pass_specs_from_project_config(shadow, operational_config_v2_pass_registry())


def test_operational_registry_builds_identity_call_shadow():
    shadow = ProjectConfiguration.from_file(_CONF_DIR / "identity_call.pipeline_v2.json")

    specs = pass_specs_from_project_config(
        shadow,
        operational_config_v2_pass_registry(),
    )

    assert [spec.pass_id for spec in specs] == ["identity-call-resolver"]
    adapter = specs[0].pass_factory()
    assert isinstance(adapter, LegacyFlowRuleAdapterPass)
    assert adapter.legacy_rule == "IdentityCallResolver"
    assert adapter.rule_options == {
        "enable_experimental": True,
        "max_trampoline_depth": 32,
        "max_search_instructions": 30,
    }


@pytest.mark.parametrize("config_name", ["default", "default_indirect_resolution"])
def test_operational_registry_builds_indirect_branch_call_shadow(config_name):
    shadow = ProjectConfiguration.from_file(_CONF_DIR / f"{config_name}.pipeline_v2.json")

    specs = pass_specs_from_project_config(
        shadow,
        operational_config_v2_pass_registry(),
    )

    assert [spec.pass_id for spec in specs] == [
        "indirect-branch-resolver",
        "indirect-call-resolver",
    ]
    adapters = [spec.pass_factory() for spec in specs]
    assert all(isinstance(adapter, LegacyFlowRuleAdapterPass) for adapter in adapters)
    assert [adapter.legacy_rule for adapter in adapters] == [
        "IndirectBranchResolver",
        "IndirectCallResolver",
    ]
    assert [adapter.rule_options for adapter in adapters] == [{}, {}]
