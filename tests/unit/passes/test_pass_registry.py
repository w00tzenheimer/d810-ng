"""PassRegistry conformance for PipelineConfig v2."""
from __future__ import annotations

import pytest

from d810.families.state_machine_cff.pipeline import (
    standard_state_machine_passes,
    state_machine_pass_registry,
)
from d810.passes.pass_pipeline import PipelineConfig, PassResult
from d810.passes import pass_pipeline as pp
from d810.passes.registry import (
    DuplicatePassIdError,
    PassRegistry,
    UnknownPassIdError,
)


class _FakePass:
    name = "fake"

    def run(self, ctx):
        return PassResult()


def test_registry_rejects_duplicate_pass_ids():
    registry = PassRegistry()
    registry.register("fake", _FakePass)

    with pytest.raises(DuplicatePassIdError, match="duplicate pass id"):
        registry.register("fake", _FakePass)


def test_registry_rejects_unknown_pass_ids():
    registry = PassRegistry()

    with pytest.raises(UnknownPassIdError, match="unknown pass id"):
        registry.build_spec(PipelineConfig(pass_id="missing"))


def test_state_machine_pass_ids_resolve_to_pass_specs():
    registry = state_machine_pass_registry()
    original_specs = standard_state_machine_passes()

    rebuilt_specs = tuple(
        registry.build_spec(spec.config) for spec in original_specs
    )

    assert [spec.pass_id for spec in rebuilt_specs] == [
        "recover_dispatcher",
        "recover_state_transitions",
        "plan_semantic_regions",
        "lower_state_machine",
        "cleanup_residual_dispatcher",
    ]
    assert [spec.config for spec in rebuilt_specs] == [
        spec.config for spec in original_specs
    ]
    for spec in rebuilt_specs:
        assert spec.pass_factory().name == spec.pass_id


def test_registry_build_spec_preserves_native_pass_contract():
    registry = PassRegistry()
    registry.register("fake", _FakePass)
    contract = pp.PassContract(
        scope=pp.PassScope.FACT,
        requires=pp.PassRequires(
            analyses=frozenset({"dominators"}),
            evidence=frozenset({"dispatcher_predicates"}),
        ),
        invalidates=pp.PassInvalidates(facts=frozenset({"stale_cfg_shape"})),
    )

    spec = registry.build_spec(PipelineConfig(pass_id="fake", contract=contract))

    assert spec.contract is contract
    assert spec.config.contract is contract
    assert spec.config.contract.requires.analyses == frozenset({"dominators"})
    assert spec.config.contract.requires.evidence == frozenset(
        {"dispatcher_predicates"}
    )
    assert spec.config.contract.invalidates.facts == frozenset({"stale_cfg_shape"})


def test_registry_build_spec_preserves_rule_selection_metadata():
    registry = PassRegistry()
    registry.register("fake", _FakePass)
    rules = pp.RuleSelection(
        include_groups=frozenset({"legacy.default_instruction_only"}),
        include=frozenset({"FoldReadonlyDataRule"}),
    )

    spec = registry.build_spec(PipelineConfig(pass_id="fake", rules=rules))

    assert spec.rules is rules
    assert spec.config.rules is rules
    assert spec.config.rules.include_groups == frozenset(
        {"legacy.default_instruction_only"}
    )
    assert spec.config.rules.include == frozenset({"FoldReadonlyDataRule"})
