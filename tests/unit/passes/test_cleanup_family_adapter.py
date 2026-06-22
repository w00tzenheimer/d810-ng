"""Config-v2 cleanup-family adapter boundary behavior."""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from d810.capabilities.resolver import CapabilityNotProvided, CapabilitySet
from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.ir.maturity import IRMaturity
from d810.passes.cleanup_family_adapter import (
    CLEANUP_FAMILY_ADAPTER_CAPABILITY,
    SIMPLE_FLATTENING_CLEANUP_PASS_ID,
    SIMPLE_FLATTENING_CLEANUP_RULE,
    CleanupFamilyAdapterCapability,
    CleanupFamilyAdapterPass,
    CleanupFamilyAdapterRequest,
    cleanup_family_adapter_pass_registry,
)
from d810.passes.pass_pipeline import (
    FunctionPipelineContext,
    PipelineConfig,
    PipelineConfigError,
    PassResult,
)


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
        raise AssertionError("cleanup adapter should not emit PatchPlan mutations")


class _CleanupCapability:
    def __init__(self):
        self.requests: list[CleanupFamilyAdapterRequest] = []

    def run_cleanup_family_rule(
        self,
        request: CleanupFamilyAdapterRequest,
    ) -> PassResult:
        self.requests.append(request)
        return PassResult()


def _context(
    capability: _CleanupCapability | None = None,
) -> FunctionPipelineContext:
    source = _Source()
    capabilities = CapabilitySet()
    if capability is not None:
        capabilities = capabilities.with_capability(
            CleanupFamilyAdapterCapability,
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


def test_cleanup_family_adapter_pass_invokes_typed_capability():
    capability = _CleanupCapability()
    adapter = CleanupFamilyAdapterPass(
        legacy_rule=SIMPLE_FLATTENING_CLEANUP_RULE,
        rule_options={"max_passes": 3},
    )

    result = adapter.run(_context(capability))

    assert isinstance(result, PassResult)
    assert len(capability.requests) == 1
    request = capability.requests[0]
    assert request.live_source == "LIVE"
    assert request.func_ea == 0x1000
    assert request.maturity is IRMaturity.GLOBAL_ANALYZED
    assert request.pass_id == SIMPLE_FLATTENING_CLEANUP_PASS_ID
    assert request.legacy_rule == SIMPLE_FLATTENING_CLEANUP_RULE
    assert request.rule_options == {"max_passes": 3}


def test_cleanup_family_adapter_pass_requires_typed_capability():
    adapter = CleanupFamilyAdapterPass(
        legacy_rule=SIMPLE_FLATTENING_CLEANUP_RULE,
        rule_options={},
    )

    with pytest.raises(CapabilityNotProvided, match="CleanupFamilyAdapterCapability"):
        adapter.run(_context())


def test_cleanup_family_adapter_registry_builds_cleanup_entry():
    config = PipelineConfig.from_dict(
        {
            "pass": SIMPLE_FLATTENING_CLEANUP_PASS_ID,
            "requires": {
                "capabilities": [CLEANUP_FAMILY_ADAPTER_CAPABILITY],
            },
            "options": {
                "legacy_rule": SIMPLE_FLATTENING_CLEANUP_RULE,
                "max_passes": 3,
            },
        }
    )

    spec = cleanup_family_adapter_pass_registry().build_spec(config)
    adapter = spec.pass_factory()

    assert spec.pass_id == SIMPLE_FLATTENING_CLEANUP_PASS_ID
    assert spec.contract.requires.capabilities == frozenset(
        {CLEANUP_FAMILY_ADAPTER_CAPABILITY}
    )
    assert isinstance(adapter, CleanupFamilyAdapterPass)
    assert adapter.legacy_rule == SIMPLE_FLATTENING_CLEANUP_RULE
    assert adapter.rule_options == {"max_passes": 3}


def test_cleanup_family_adapter_registry_rejects_mismatched_legacy_rule():
    config = PipelineConfig.from_dict(
        {
            "pass": SIMPLE_FLATTENING_CLEANUP_PASS_ID,
            "options": {"legacy_rule": "JumpFixer"},
        }
    )

    with pytest.raises(PipelineConfigError, match=SIMPLE_FLATTENING_CLEANUP_RULE):
        cleanup_family_adapter_pass_registry().build_spec(config)


def test_cleanup_family_adapter_registry_rejects_rules_selection():
    config = PipelineConfig.from_dict(
        {
            "pass": SIMPLE_FLATTENING_CLEANUP_PASS_ID,
            "options": {"legacy_rule": SIMPLE_FLATTENING_CLEANUP_RULE},
            "rules": {"include": ["cleanup"]},
        }
    )

    with pytest.raises(PipelineConfigError, match="rules"):
        cleanup_family_adapter_pass_registry().build_spec(config)
