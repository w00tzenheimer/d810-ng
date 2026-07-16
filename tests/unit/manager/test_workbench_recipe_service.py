from __future__ import annotations

import dataclasses
import json

import pytest

from d810.manager.workbench_recipe_models import FunctionPipelineOverride, RecipePass
from d810.manager.workbench_recipe_service import RecipeEditError, RecipeService
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.passes.pass_pipeline import PipelineConfig


class _Facts:
    def __init__(
        self,
        *,
        analyses: tuple[str, ...] = (),
        facts: tuple[str, ...] = (),
        evidence: tuple[str, ...] = (),
    ) -> None:
        self._analyses = frozenset(analyses)
        self._facts = frozenset(facts)
        self._evidence = frozenset(evidence)

    def has_analysis(self, name: str) -> bool:
        return name in self._analyses

    def has_fact(self, name: str) -> bool:
        return name in self._facts

    def has_evidence(self, name: str) -> bool:
        return name in self._evidence

    def available_analyses(self) -> tuple[str, ...]:
        return tuple(sorted(self._analyses))

    def available_facts(self) -> tuple[str, ...]:
        return tuple(sorted(self._facts))

    def available_evidence(self) -> tuple[str, ...]:
        return tuple(sorted(self._evidence))


def _service() -> RecipeService:
    return RecipeService(operational_config_v2_pass_registry())


def _draft(service: RecipeService):
    return service.create_draft(
        function_ea=0x401000,
        function_fingerprint="sha256:abc",
        workbench_generation=4,
        source_path="/source.json",
        runtime_path="/runtime.json",
        configs=(
            PipelineConfig(
                pass_id="jump-fixer",
                options={"legacy_rule": "JumpFixer"},
            ),
            PipelineConfig(pass_id="recover_dispatcher"),
        ),
    )


def test_catalog_is_sorted_but_draft_keeps_effective_execution_order() -> None:
    service = _service()
    catalog = service.catalog()
    draft = _draft(service)

    assert tuple(entry.pass_id for entry in catalog) == tuple(
        sorted(entry.pass_id for entry in catalog)
    )
    assert next(
        entry for entry in catalog if entry.pass_id == "jump-fixer"
    ).transforms == ("JumpFixer",)
    assert tuple(item.pass_id for item in draft.passes) == (
        "jump-fixer",
        "recover_dispatcher",
    )
    assert [json.loads(item.config_json)["pass_id"] for item in draft.passes] == [
        "jump-fixer",
        "recover_dispatcher",
    ]


def test_add_remove_enable_and_reorder_are_immutable_and_revisioned() -> None:
    service = _service()
    original = _draft(service)
    added = service.add_pass(original, "plan_semantic_regions")
    moved = service.reorder_pass(added, added.passes[2].item_id, 0)
    disabled = service.set_enabled(moved, moved.passes[1].item_id, False)
    removed = service.remove_pass(disabled, disabled.passes[2].item_id)

    assert tuple(item.pass_id for item in original.passes) == (
        "jump-fixer",
        "recover_dispatcher",
    )
    assert tuple(item.pass_id for item in moved.passes) == (
        "plan_semantic_regions",
        "jump-fixer",
        "recover_dispatcher",
    )
    assert disabled.passes[1].enabled is False
    assert tuple(item.pass_id for item in removed.passes) == (
        "plan_semantic_regions",
        "jump-fixer",
    )
    assert (added.revision, moved.revision, disabled.revision, removed.revision) == (
        1,
        2,
        3,
        4,
    )


def test_edit_rejects_unknown_pass_item_and_undeclared_options() -> None:
    service = _service()
    draft = _draft(service)

    with pytest.raises(RecipeEditError, match="unknown registered pass"):
        service.add_pass(draft, "not-registered")
    with pytest.raises(RecipeEditError, match="draft item"):
        service.remove_pass(draft, "missing-item")
    recover = next(
        item for item in draft.passes if item.pass_id == "recover_dispatcher"
    )
    with pytest.raises(RecipeEditError, match="does not declare structured options"):
        service.replace_options(draft, recover.item_id, {"guess": True})


def test_preflight_reports_ordering_requirements_without_auto_reordering() -> None:
    registry = operational_config_v2_pass_registry()
    service = RecipeService(registry)
    draft = service.create_draft(
        function_ea=0x401000,
        function_fingerprint="sha256:abc",
        workbench_generation=4,
        source_path="/source.json",
        runtime_path="/runtime.json",
        configs=(
            registry.config_template_for("recover_state_transitions"),
            registry.config_template_for("recover_dispatcher"),
        ),
    )

    validation = service.validate(
        draft,
        facts=_Facts(
            analyses=("recover_dispatcher",),
            evidence=("ir.branch_target", "ir.state_variable_write"),
        ),
    )

    assert validation.satisfied is False
    assert tuple(item.pass_id for item in draft.passes) == (
        "recover_state_transitions",
        "recover_dispatcher",
    )
    assert any(
        diagnostic.pass_id == "recover_state_transitions"
        and "role.dispatcher" in diagnostic.missing
        for diagnostic in validation.diagnostics
    )


def test_preflight_accepts_declared_output_flow_in_user_selected_order() -> None:
    registry = operational_config_v2_pass_registry()
    service = RecipeService(registry)
    draft = service.create_draft(
        function_ea=0x401000,
        function_fingerprint="sha256:abc",
        workbench_generation=4,
        source_path="/source.json",
        runtime_path="/runtime.json",
        configs=(
            registry.config_template_for("recover_dispatcher"),
            registry.config_template_for("recover_state_transitions"),
        ),
    )

    validation = service.validate(
        draft,
        facts=_Facts(
            analyses=("recover_dispatcher",),
            evidence=("ir.branch_target", "ir.state_variable_write"),
        ),
    )

    assert validation.satisfied is True
    assert validation.diagnostics == ()


def test_validation_blocks_tampered_unknown_and_invalid_config_payloads() -> None:
    service = _service()
    draft = _draft(service)
    unknown = dataclasses.replace(
        draft,
        passes=(
            RecipePass(
                "unknown", "not-registered", True, '{"pass_id":"not-registered"}'
            ),
        ),
    )
    jump = draft.passes[0]
    invalid = dataclasses.replace(
        draft,
        passes=(
            dataclasses.replace(
                jump,
                config_json=(
                    '{"pass_id":"jump-fixer",'
                    '"options":{"legacy_rule":"WrongTransform"}}'
                ),
            ),
        ),
    )

    unknown_validation = service.validate(unknown, facts=_Facts())
    invalid_validation = service.validate(invalid, facts=_Facts())

    assert unknown_validation.satisfied is False
    assert unknown_validation.diagnostics[0].code == "unknown-pass-id"
    assert invalid_validation.satisfied is False
    assert invalid_validation.diagnostics[0].code == "invalid-pass-config"


def test_complete_recipe_serialization_is_canonical_and_excludes_disabled_items() -> (
    None
):
    service = _service()
    draft = _draft(service)
    disabled = service.set_enabled(draft, draft.passes[1].item_id, False)

    first = service.serialize_enabled_configs(disabled)
    second = service.serialize_enabled_configs(disabled)

    assert first == second
    payload = json.loads(first)
    assert [item["pass_id"] for item in payload] == ["jump-fixer"]
    assert first.endswith("\n")


def test_serialized_recipe_round_trip_revalidates_registered_configs() -> None:
    service = _service()
    draft = _draft(service)

    serialized = service.serialize_enabled_configs(draft)
    configs = service.deserialize_configs(serialized)

    assert tuple(config.pass_id for config in configs) == (
        "jump-fixer",
        "recover_dispatcher",
    )


def test_serialized_recipe_rejects_unknown_passes_and_non_list_payloads() -> None:
    service = _service()

    with pytest.raises(RecipeEditError, match="sequence"):
        service.deserialize_configs('{"pass_id":"jump-fixer"}')
    with pytest.raises(RecipeEditError, match="not-registered"):
        service.deserialize_configs('[{"pass_id":"not-registered"}]')


def test_saved_function_recipe_seeds_effective_draft_after_identity_revalidation() -> (
    None
):
    service = _service()
    original = _draft(service)
    override = FunctionPipelineOverride(
        schema_version=1,
        function_ea=0x401000,
        function_fingerprint="sha256:abc",
        source_path="/source.json",
        runtime_path="/runtime.json",
        pass_configs_json=service.serialize_enabled_configs(original),
        updated_at=1.0,
    )

    draft = service.create_draft_from_override(
        override,
        function_ea=0x401000,
        function_fingerprint="sha256:abc",
        workbench_generation=9,
        source_path="/source.json",
        runtime_path="/runtime.json",
    )

    assert draft.workbench_generation == 9
    assert tuple(item.pass_id for item in draft.passes) == (
        "jump-fixer",
        "recover_dispatcher",
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("function_ea", 0x402000, "different function"),
        ("function_fingerprint", "sha256:def", "fingerprint"),
        ("source_path", "/other-source.json", "source project"),
        ("runtime_path", "/other-runtime.json", "runtime project"),
    ),
)
def test_saved_function_recipe_stale_identity_is_rejected(
    field, value, message
) -> None:
    service = _service()
    original = _draft(service)
    values = {
        "function_ea": 0x401000,
        "function_fingerprint": "sha256:abc",
        "source_path": "/source.json",
        "runtime_path": "/runtime.json",
    }
    values[field] = value
    override = FunctionPipelineOverride(
        schema_version=1,
        function_ea=0x401000,
        function_fingerprint="sha256:abc",
        source_path="/source.json",
        runtime_path="/runtime.json",
        pass_configs_json=service.serialize_enabled_configs(original),
        updated_at=1.0,
    )

    with pytest.raises(RecipeEditError, match=message):
        service.create_draft_from_override(
            override,
            workbench_generation=9,
            **values,
        )
