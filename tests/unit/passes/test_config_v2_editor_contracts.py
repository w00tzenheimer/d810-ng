"""Public config-v2 registrations must have fully typed editor coverage."""

from __future__ import annotations

import pytest

from d810.core.pass_editor_spec import (
    AdvisoryTone,
    FieldControlKind,
    FieldEditorSpec,
    PassEditorKind,
    PassEditorSpec,
    RuleEditorSpec,
    TransformCost,
    TransformEditorSpec,
    VerificationStatus,
)
from d810.manager.workbench_recipe_service import RecipeService
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError, PassResult
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.passes.registry import PassRegistry, PassRegistryError


class _Pass:
    name = "public"

    def run(self, context):
        del context
        return PassResult()


def _mode_editor() -> PassEditorSpec:
    return PassEditorSpec.fields_editor(
        (
            FieldEditorSpec(
                field_id="mode",
                label="Mode",
                path=("mode",),
                control=FieldControlKind.ENUM,
                choices=("strict", "aggressive"),
                default="strict",
            ),
        )
    )


def _rule_editor() -> PassEditorSpec:
    return PassEditorSpec.rule_catalog(
        (
            RuleEditorSpec(
                rule_id="known-rule",
                label="Known rule",
                family_id="test",
                family_label="Test",
                subfamily_id=None,
                subfamily_label=None,
                description="A test-only selectable rule.",
                verification=VerificationStatus.VERIFIED,
            ),
        )
    )


def registered_pass_catalog():
    return RecipeService(operational_config_v2_pass_registry()).catalog()


def test_public_config_registration_rejects_a_json_only_option() -> None:
    registry = PassRegistry()

    with pytest.raises(PassRegistryError, match="editor-visible"):
        registry.register_configured(
            "public",
            lambda config: _Pass(),
            config_template=PipelineConfig(
                pass_id="public",
                options={"mode": "strict", "hidden": True},
            ),
            editor_spec=_mode_editor(),
        )


def test_public_config_registration_requires_explicit_template_and_editor_spec() -> None:
    registry = PassRegistry()

    with pytest.raises(PassRegistryError, match="explicit config template"):
        registry.register_configured("public", lambda config: _Pass())

    with pytest.raises(PassRegistryError, match="editor-visible metadata"):
        registry.register_configured(
            "other-public",
            lambda config: _Pass(),
            config_template=PipelineConfig(pass_id="other-public"),
        )


def test_public_config_build_rejects_an_undeclared_option() -> None:
    registry = PassRegistry()
    registry.register_configured(
        "public",
        lambda config: _Pass(),
        config_template=PipelineConfig(
            pass_id="public",
            options={"mode": "strict"},
        ),
        editor_spec=_mode_editor(),
    )

    with pytest.raises(PassRegistryError, match="editor-visible"):
        registry.build_spec(
            PipelineConfig(
                pass_id="public",
                options={"mode": "strict", "hidden": True},
            )
        )


def test_public_config_registration_rejects_a_nested_json_only_option() -> None:
    registry = PassRegistry()
    nested_editor = PassEditorSpec.fields_editor(
        (
            FieldEditorSpec(
                field_id="depth",
                label="Depth",
                path=("limits", "depth"),
                control=FieldControlKind.INTEGER,
                minimum=1,
                default=3,
            ),
        )
    )

    with pytest.raises(PassRegistryError, match="editor-visible"):
        registry.register_configured(
            "public",
            lambda config: _Pass(),
            config_template=PipelineConfig(
                pass_id="public",
                options={"limits": {"depth": 3, "json_only": True}},
            ),
            editor_spec=nested_editor,
        )


def test_public_editor_contract_validation_is_deterministic() -> None:
    registry = PassRegistry()
    registry.register_configured(
        "public",
        lambda config: _Pass(),
        config_template=PipelineConfig(
            pass_id="public",
            options={"mode": "strict"},
        ),
        editor_spec=_mode_editor(),
    )

    assert registry.validate_editor_contracts() == ()


def test_public_rule_catalog_rejects_unknown_selection_before_runtime() -> None:
    registry = PassRegistry()
    editor_spec = _rule_editor()
    registry.register_configured(
        "public-rules",
        lambda config: _Pass(),
        config_template=PipelineConfig(
            pass_id="public-rules",
            options=editor_spec.default_options(),
        ),
        editor_spec=editor_spec,
    )

    with pytest.raises(PassRegistryError, match="unknown rule ID"):
        registry.build_spec(
            PipelineConfig(
                pass_id="public-rules",
                options={"enabled_rules": ["unknown-rule"]},
            )
        )


def test_public_transform_catalog_rejects_unknown_selection_before_runtime() -> None:
    transform = TransformEditorSpec(
        transform_id="known-transform",
        label="Known transform",
        family_id="test",
        family_label="Test",
        subfamily_id=None,
        subfamily_label=None,
        description="A test-only selectable transform.",
        reference="test",
        maturities=("any",),
        default_selected=False,
        verification=VerificationStatus.VERIFIED,
        verification_reason="Verified for the test contract.",
        advisory=AdvisoryTone.NONE,
        advisory_reason="",
        cost=TransformCost.UNKNOWN,
    )
    editor_spec = PassEditorSpec.transform_catalog((transform,))
    registry = PassRegistry()
    registry.register_configured(
        "public-transforms",
        lambda config: _Pass(),
        config_template=PipelineConfig(
            pass_id="public-transforms",
            options=editor_spec.default_options(),
        ),
        editor_spec=editor_spec,
    )

    with pytest.raises(PassRegistryError, match="unknown transform ID"):
        registry.build_spec(
            PipelineConfig(
                pass_id="public-transforms",
                options={"transforms": ["unknown-transform"], "transform_options": {}},
            )
        )


def test_public_transform_catalog_rejects_non_string_option_keys() -> None:
    transform = TransformEditorSpec(
        transform_id="known-transform",
        label="Known transform",
        family_id="test",
        family_label="Test",
        subfamily_id=None,
        subfamily_label=None,
        description="A test-only selectable transform.",
        reference="test",
        maturities=("any",),
        default_selected=False,
        verification=VerificationStatus.VERIFIED,
        verification_reason="Verified for the test contract.",
        advisory=AdvisoryTone.NONE,
        advisory_reason="",
        cost=TransformCost.UNKNOWN,
    )
    editor_spec = PassEditorSpec.transform_catalog((transform,))
    registry = PassRegistry()
    registry.register_configured(
        "public-transforms",
        lambda config: _Pass(),
        config_template=PipelineConfig(
            pass_id="public-transforms",
            options=editor_spec.default_options(),
        ),
        editor_spec=editor_spec,
    )

    with pytest.raises(PipelineConfigError, match="keys must be non-empty strings"):
        registry.build_spec(
            PipelineConfig(
                pass_id="public-transforms",
                options={"transforms": ["known-transform"], "transform_options": {1: {}}},
            )
        )


def test_public_field_rejects_string_false_for_boolean_control() -> None:
    editor_spec = PassEditorSpec.fields_editor(
        (
            FieldEditorSpec(
                field_id="enabled",
                label="Enabled",
                path=("enabled",),
                control=FieldControlKind.BOOLEAN,
                default=False,
            ),
        )
    )
    registry = PassRegistry()
    registry.register_configured(
        "public-boolean",
        lambda config: _Pass(),
        config_template=PipelineConfig(
            pass_id="public-boolean",
            options=editor_spec.default_options(),
        ),
        editor_spec=editor_spec,
    )

    with pytest.raises(PassRegistryError, match="must be a boolean"):
        registry.build_spec(
            PipelineConfig(pass_id="public-boolean", options={"enabled": "false"})
        )


def test_operational_config_v2_public_passes_have_complete_editor_contracts() -> None:
    """A shipping option or rule cannot become JSON-only after registration."""
    registry = operational_config_v2_pass_registry()

    assert registry.validate_editor_contracts() == ()


def test_shipped_passes_project_their_declared_primary_editor_surface() -> None:
    by_pass_id = {entry.pass_id: entry for entry in registered_pass_catalog()}

    assert by_pass_id["constant-simplification"].editor_spec.kind is PassEditorKind.FIELDS
    assert by_pass_id["mba-simplify"].editor_spec.kind is PassEditorKind.TRANSFORM_CATALOG
    assert by_pass_id["jump-fixer"].editor_spec.kind is PassEditorKind.RULE_CATALOG
