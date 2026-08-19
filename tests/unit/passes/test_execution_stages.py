from __future__ import annotations

import pytest

from d810.passes.constant_simplification import (
    register_constant_simplification_pass,
)
from d810.passes.execution_stages import (
    ExecutionHost,
    ExecutionOwnership,
    ExecutionPipeline,
    ExecutionStageDescriptor,
    IRScope,
    canonical_transform_id,
)
from d810.ir.maturity import IRMaturity
from d810.passes.constant_simplification_options import StageLifecycleDomain
from d810.passes.registry import PassRegistry, PassRegistryError


class _FakePass:
    name = "fake"

    def run(self, _context):
        raise AssertionError("not executed")


def test_legacy_descriptor_projects_explicit_execution_metadata() -> None:
    descriptor = ExecutionStageDescriptor(
        "legacy", "legacy", ExecutionPipeline.FLOW, "Rule"
    )

    assert descriptor.ownership is ExecutionOwnership.HEXRAYS_HOSTED
    assert descriptor.host is ExecutionHost.HEXRAYS_OPTBLOCK
    assert descriptor.scope is IRScope.BLOCK


def test_explicit_execution_metadata_preserves_legacy_pipeline() -> None:
    hosted_instruction = ExecutionStageDescriptor(
        "test",
        "hosted-insn",
        ExecutionPipeline.INSTRUCTION,
        "Rule",
        ownership=ExecutionOwnership.HEXRAYS_HOSTED,
        host=ExecutionHost.HEXRAYS_OPTINSN,
        scope=IRScope.INSTRUCTION,
    )
    owned_function = ExecutionStageDescriptor(
        "test",
        "owned-function",
        ExecutionPipeline.FLOW,
        "Pass",
        ownership=ExecutionOwnership.D810_OWNED,
        host=ExecutionHost.D810_PIPELINE,
        scope=IRScope.FUNCTION,
    )

    assert hosted_instruction.pipeline is ExecutionPipeline.INSTRUCTION
    assert owned_function.pipeline is ExecutionPipeline.FLOW
    assert owned_function.ownership is ExecutionOwnership.D810_OWNED
    assert owned_function.host is ExecutionHost.D810_PIPELINE
    assert owned_function.scope is IRScope.FUNCTION


@pytest.mark.parametrize(
    ("kwargs", "error_type"),
    (
        (
            {
                "ownership": ExecutionOwnership.D810_OWNED,
                "host": ExecutionHost.HEXRAYS_OPTINSN,
                "scope": IRScope.INSTRUCTION,
            },
            ValueError,
        ),
        (
            {
                "ownership": ExecutionOwnership.HEXRAYS_HOSTED,
                "host": ExecutionHost.D810_PIPELINE,
                "scope": IRScope.FUNCTION,
            },
            ValueError,
        ),
        (
            {
                "ownership": ExecutionOwnership.HEXRAYS_HOSTED,
                "host": ExecutionHost.HEXRAYS_OPTINSN,
                "scope": IRScope.FUNCTION,
            },
            ValueError,
        ),
        (
            {
                "ownership": "hexrays_hosted",
            },
            TypeError,
        ),
    ),
)
def test_descriptor_rejects_incoherent_or_untyped_metadata(kwargs, error_type) -> None:
    with pytest.raises(error_type):
        ExecutionStageDescriptor(
            "test",
            "invalid",
            ExecutionPipeline.FLOW,
            "Rule",
            **kwargs,
        )


def test_private_implementation_names_normalize_to_stable_public_ids() -> None:
    assert canonical_transform_id("AddXor_Rule_1") == "add-xor-1"
    assert canonical_transform_id("FoldReadonlyDataRule") == "fold-readonly-data"


def test_constant_simplification_owns_three_stable_stages() -> None:
    registry = register_constant_simplification_pass(PassRegistry())

    stages = registry.stages_for("constant-simplification")

    assert tuple(stage.stage_id for stage in stages) == (
        "fold-readonly-data",
        "fold-constant-subtree",
        "forward-constants",
    )
    assert {stage.pass_id for stage in stages} == {"constant-simplification"}
    assert tuple(stage.pipeline for stage in stages) == (
        ExecutionPipeline.INSTRUCTION,
        ExecutionPipeline.INSTRUCTION,
        ExecutionPipeline.FLOW,
    )
    assert tuple(stage.lifecycle_domain for stage in stages) == (
        StageLifecycleDomain.MICROCODE,
        StageLifecycleDomain.MICROCODE,
        StageLifecycleDomain.MICROCODE,
    )
    assert stages[0].supported_maturities == (
        IRMaturity.CANONICAL,
        IRMaturity.LOCAL_OPTIMIZED,
        IRMaturity.CALL_MODELED,
        IRMaturity.GLOBAL_ANALYZED,
        IRMaturity.STRUCTURED,
    )
    assert stages[1].supported_maturities == (
        IRMaturity.LOCAL_OPTIMIZED,
        IRMaturity.CALL_MODELED,
        IRMaturity.GLOBAL_ANALYZED,
        IRMaturity.GLOBAL_OPTIMIZED,
        IRMaturity.STRUCTURED,
    )
    assert stages[2].supported_maturities == (
        IRMaturity.CALL_MODELED,
        IRMaturity.GLOBAL_ANALYZED,
        IRMaturity.GLOBAL_OPTIMIZED,
        IRMaturity.STRUCTURED,
    )


def test_registry_rejects_stage_owned_by_a_different_pass() -> None:
    registry = PassRegistry()

    with pytest.raises(PassRegistryError, match="owning pass"):
        registry.register(
            "fake",
            _FakePass,
            stages=(
                ExecutionStageDescriptor(
                    pass_id="other",
                    stage_id="work",
                    pipeline=ExecutionPipeline.FLOW,
                    implementation_name="WorkRule",
                ),
            ),
        )


def test_registry_rejects_normalized_stage_id_collision_within_a_pass() -> None:
    registry = PassRegistry()
    first_name = "AddXor_Rule_1"
    second_name = "AddXorRule1"

    with pytest.raises(PassRegistryError, match="duplicate stage id"):
        registry.register(
            "fake",
            _FakePass,
            stages=tuple(
                ExecutionStageDescriptor(
                    pass_id="fake",
                    stage_id=canonical_transform_id(name),
                    pipeline=ExecutionPipeline.INSTRUCTION,
                    implementation_name=name,
                )
                for name in (first_name, second_name)
            ),
        )
