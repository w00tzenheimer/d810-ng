"""Config-v2 registered hook-transform behavior."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from d810.capabilities.resolver import CapabilityNotProvided, CapabilitySet
from d810.core.config import ProjectConfiguration
from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.ir.maturity import IRMaturity
from d810.passes.driver import CapabilityError, run_pipeline
from d810.passes.hook_transform_passes import (
    HOOK_TRANSFORM_CAPABILITY,
    HookTransformCapability,
    HookTransformPass,
    HookTransformRequest,
    hook_transform_pass_registry,
)
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.passes.pass_pipeline import (
    FunctionPipelineContext,
    PipelineConfig,
    PassResult,
)
from d810.passes.pipeline_config_parser import (
    pass_specs_from_project_config,
    pipeline_configs_from_project_config,
)
from d810.passes.registry import PassRegistryError

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
        raise AssertionError(
            "hook-transform adapter should not emit PatchPlan mutations"
        )


class _Backend:
    def __init__(self, caps=()):
        self._caps = frozenset(caps)

    def capabilities(self):
        return self._caps

    def apply(self, plan, live_source, safety_policy):
        raise AssertionError(
            "hook-transform adapter should not use MutationBackend.apply"
        )


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
        self.requests: list[HookTransformRequest] = []

    def run_hook_transform(self, request: HookTransformRequest) -> PassResult:
        self.requests.append(request)
        return PassResult()


def _context(
    capability: _FlowRuleCapability | None = None,
) -> FunctionPipelineContext:
    source = _Source()
    capabilities = CapabilitySet()
    if capability is not None:
        capabilities = capabilities.with_capability(
            HookTransformCapability,
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


def test_hook_transform_pass_invokes_capability_with_options():
    capability = _FlowRuleCapability()
    adapter = HookTransformPass(
        name="jump-fixer",
        implementation_name="JumpFixer",
        transform_options={"enabled_rules": ["JnzRule1"]},
    )

    result = adapter.run(_context(capability))

    assert isinstance(result, PassResult)
    assert len(capability.requests) == 1
    request = capability.requests[0]
    assert request.live_source == "LIVE"
    assert request.func_ea == 0x1000
    assert request.maturity is IRMaturity.GLOBAL_ANALYZED
    assert request.pass_id == "jump-fixer"
    assert request.implementation_name == "JumpFixer"
    assert request.transform_options == {"enabled_rules": ["JnzRule1"]}


def test_hook_transform_pass_requires_typed_capability():
    adapter = HookTransformPass(
        name="jump-fixer",
        implementation_name="JumpFixer",
        transform_options={},
    )

    with pytest.raises(CapabilityNotProvided, match="HookTransformCapability"):
        adapter.run(_context())


def test_hook_transform_registry_builds_jump_fixer_canary_entry():
    project = ProjectConfiguration.from_file(
        _CONF_DIR / "hodur_flag2_config_v2_canary.json"
    )
    config = pipeline_configs_from_project_config(project)[-1]

    spec = hook_transform_pass_registry().build_spec(config)
    adapter = spec.pass_factory()

    assert spec.pass_id == "jump-fixer"
    assert spec.contract.requires.capabilities == frozenset({HOOK_TRANSFORM_CAPABILITY})
    assert isinstance(adapter, HookTransformPass)
    assert adapter.implementation_name == "JumpFixer"
    assert "JmpRuleZ3Const" in adapter.transform_options["enabled_rules"]


@pytest.mark.parametrize(
    ("pass_id", "implementation_name"),
    [
        ("forward-constant-propagation", "ForwardConstantPropagationRule"),
        ("identity-call-resolver", "IdentityCallResolver"),
        ("indirect-branch-resolver", "IndirectBranchResolver"),
        ("indirect-call-resolver", "IndirectCallResolver"),
        ("mba-state-preconditioner", "MbaStatePreconditioner"),
        ("jump-fixer", "JumpFixer"),
    ],
)
def test_hook_transform_registry_builds_supported_simple_ids(
    pass_id,
    implementation_name,
):
    registry = hook_transform_pass_registry()
    template = registry.config_template_for(pass_id)

    adapter = registry.build_spec(template).pass_factory()

    assert isinstance(adapter, HookTransformPass)
    assert adapter.name == pass_id
    assert adapter.implementation_name == implementation_name
    assert adapter.transform_options == template.options


def test_global_constant_inliner_is_not_a_registered_pass():
    registry = hook_transform_pass_registry()

    assert "global-constant-inliner" not in registry.registered_pass_ids()


def test_hook_transform_registry_rejects_former_legacy_rule_option():
    config = PipelineConfig.from_dict(
        {
            "pass_id": "jump-fixer",
            "options": {"legacy_rule": "ForwardConstantPropagationRule"},
        }
    )

    with pytest.raises(PassRegistryError, match="editor-visible"):
        hook_transform_pass_registry().build_spec(config)


def test_hook_transform_pipeline_missing_backend_capability_fails_before_execution():
    capability = _FlowRuleCapability()
    config = PipelineConfig.from_dict(
        {
            "pass_id": "jump-fixer",
            "requirements": {
                "required": [HOOK_TRANSFORM_CAPABILITY],
            },
            "options": {},
        }
    )
    spec = hook_transform_pass_registry().build_spec(config)

    with pytest.raises(CapabilityError, match=HOOK_TRANSFORM_CAPABILITY):
        run_pipeline(
            source=_Source(),
            family=_Family((spec,)),
            backend=_Backend(caps=()),
            facts=_Facts(),
            project_config=None,
            maturity=IRMaturity.GLOBAL_ANALYZED,
            capabilities=CapabilitySet().with_capability(
                HookTransformCapability,
                capability,
            ),
        )

    assert capability.requests == []


def test_hook_transform_pipeline_executes_when_capabilities_exist():
    capability = _FlowRuleCapability()
    config = PipelineConfig.from_dict(
        {
            "pass_id": "jump-fixer",
            "requirements": {
                "required": [HOOK_TRANSFORM_CAPABILITY],
            },
            "options": {
                "enabled_rules": ["JnzRule1"],
            },
        }
    )
    spec = hook_transform_pass_registry().build_spec(config)

    out = run_pipeline(
        source=_Source(),
        family=_Family((spec,)),
        backend=_Backend(caps=(HOOK_TRANSFORM_CAPABILITY,)),
        facts=_Facts(),
        project_config=None,
        maturity=IRMaturity.GLOBAL_ANALYZED,
        capabilities=CapabilitySet().with_capability(
            HookTransformCapability,
            capability,
        ),
    )

    assert out == _graph()
    assert len(capability.requests) == 1
    assert capability.requests[0].implementation_name == "JumpFixer"
    assert capability.requests[0].transform_options == {"enabled_rules": ["JnzRule1"]}


def test_operational_registry_builds_mba_spine_and_simple_block_canary():
    canary = ProjectConfiguration.from_file(
        _CONF_DIR / "default_unflattening_tigress_indirect_config_v2_canary.json"
    )

    specs = pass_specs_from_project_config(
        canary,
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


def test_operational_registry_builds_identity_call_canary():
    canary = ProjectConfiguration.from_file(
        _CONF_DIR / "identity_call_config_v2_canary.json"
    )

    specs = pass_specs_from_project_config(
        canary,
        operational_config_v2_pass_registry(),
    )

    assert [spec.pass_id for spec in specs] == ["identity-call-resolver"]
    adapter = specs[0].pass_factory()
    assert isinstance(adapter, HookTransformPass)
    assert adapter.implementation_name == "IdentityCallResolver"
    assert adapter.transform_options == {
        "enable_experimental": True,
        "max_trampoline_depth": 32,
        "max_search_instructions": 30,
    }


@pytest.mark.parametrize("config_name", ["default", "default_indirect_resolution"])
def test_operational_registry_builds_indirect_branch_call_canary(config_name):
    canary = ProjectConfiguration.from_file(
        _CONF_DIR / f"{config_name}_config_v2_canary.json"
    )

    specs = pass_specs_from_project_config(
        canary,
        operational_config_v2_pass_registry(),
    )

    assert [spec.pass_id for spec in specs] == [
        "indirect-branch-resolver",
        "indirect-call-resolver",
    ]
    adapters = [spec.pass_factory() for spec in specs]
    assert all(isinstance(adapter, HookTransformPass) for adapter in adapters)
    assert [adapter.implementation_name for adapter in adapters] == [
        "IndirectBranchResolver",
        "IndirectCallResolver",
    ]
    assert [adapter.transform_options for adapter in adapters] == [{}, {}]
