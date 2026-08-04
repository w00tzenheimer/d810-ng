from __future__ import annotations

import pytest

from d810.passes.constant_simplification import (
    register_constant_simplification_pass,
)
from d810.passes.execution_stages import (
    ExecutionPipeline,
    ExecutionStageDescriptor,
    canonical_transform_id,
)
from d810.passes.registry import PassRegistry, PassRegistryError


class _FakePass:
    name = "fake"

    def run(self, _context):
        raise AssertionError("not executed")


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
