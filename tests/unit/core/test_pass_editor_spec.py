"""Contract tests for the closed config-v2 pass editor vocabulary."""

from __future__ import annotations

import pytest


def _editor_module() -> object:
    try:
        from d810.core import pass_editor_spec
    except ImportError as error:
        pytest.fail(f"PassEditorSpec is not available: {error}")
    return pass_editor_spec


def _field(field_id: str, *, control=None):
    spec = _editor_module()
    return spec.FieldEditorSpec(
        field_id=field_id,
        label=field_id.replace("_", " ").title(),
        path=(field_id,),
        control=control or spec.FieldControlKind.TEXT,
        default=False if control is spec.FieldControlKind.BOOLEAN else "",
    )


def test_fields_editor_requires_explicit_complete_section_membership() -> None:
    spec = _editor_module()
    enabled = _field("enabled", control=spec.FieldControlKind.BOOLEAN)
    value = _field("value")

    with pytest.raises(ValueError, match="exactly one section"):
        spec.PassEditorSpec.fields_editor((enabled, value), sections=())

    with pytest.raises(ValueError, match="unassigned field"):
        spec.PassEditorSpec.fields_editor(
            (enabled, value),
            sections=(
                spec.PassEditorSectionSpec(
                    section_id="main",
                    label="Main",
                    field_ids=("enabled",),
                    presentation=spec.PassEditorSectionPresentation.PRIMARY,
                ),
            ),
        )


def test_section_rejects_duplicate_unknown_and_non_boolean_controller_fields() -> None:
    spec = _editor_module()
    enabled = _field("enabled", control=spec.FieldControlKind.BOOLEAN)
    value = _field("value")
    duplicate = (
        spec.PassEditorSectionSpec("a", "A", ("enabled", "value")),
        spec.PassEditorSectionSpec("b", "B", ("value",)),
    )
    with pytest.raises(ValueError, match="more than one section"):
        spec.PassEditorSpec.fields_editor((enabled, value), sections=duplicate)

    with pytest.raises(ValueError, match="unknown field"):
        spec.PassEditorSpec.fields_editor(
            (enabled, value),
            sections=(spec.PassEditorSectionSpec("a", "A", ("missing",)),),
        )

    with pytest.raises(ValueError, match="boolean"):
        spec.PassEditorSpec.fields_editor(
            (enabled, value),
            sections=(
                spec.PassEditorSectionSpec(
                    "a", "A", ("enabled", "value"), controller_field_id="value"
                ),
            ),
        )


def test_editor_rejects_multiple_primary_sections() -> None:
    spec = _editor_module()
    fields = (_field("one"), _field("two"))
    with pytest.raises(ValueError, match="at most one primary"):
        spec.PassEditorSpec.fields_editor(
            fields,
            sections=(
                spec.PassEditorSectionSpec(
                    "one", "One", ("one",),
                    presentation=spec.PassEditorSectionPresentation.PRIMARY,
                ),
                spec.PassEditorSectionSpec(
                    "two", "Two", ("two",),
                    presentation=spec.PassEditorSectionPresentation.PRIMARY,
                ),
            ),
        )


def _transform(*, family_id: str = "multiplication") -> object:
    spec = _editor_module()
    return spec.TransformEditorSpec(
        transform_id="mul-mba-1",
        label="Mul MBA 1",
        family_id=family_id,
        family_label="Multiplication",
        subfamily_id="mba-multiplication",
        subfamily_label="MBA multiplication",
        description="Simplify an MBA multiplication pattern to x * y.",
        reference="MBA obfuscation with double bnot verification",
        maturities=("any",),
        default_selected=True,
        verification=spec.VerificationStatus.SKIPPED,
        verification_reason="Offline SMT proof exceeds the practical budget.",
        advisory=spec.AdvisoryTone.WARNING,
        advisory_reason="SMT verification skipped; this is not a runtime claim.",
        cost=spec.TransformCost.PROOF_EXPENSIVE,
    )


def test_transform_catalog_rejects_missing_explicit_family_metadata() -> None:
    spec = _editor_module()

    with pytest.raises(ValueError, match="family_id"):
        spec.PassEditorSpec.transform_catalog((_transform(family_id=""),))


def test_transform_catalog_rejects_duplicate_transform_ids() -> None:
    spec = _editor_module()

    with pytest.raises(ValueError, match="duplicate transform_id"):
        spec.PassEditorSpec.transform_catalog((_transform(), _transform()))


def test_transform_catalog_can_declare_typed_options_per_transform() -> None:
    spec = _editor_module()
    transform = spec.TransformEditorSpec(
        transform_id="mul-mba-1",
        label="Mul MBA 1",
        family_id="multiplication",
        family_label="Multiplication",
        subfamily_id="mba-multiplication",
        subfamily_label="MBA multiplication",
        description="Simplify an MBA multiplication pattern to x * y.",
        reference="MBA obfuscation with double bnot verification",
        maturities=("any",),
        default_selected=True,
        verification=spec.VerificationStatus.SKIPPED,
        verification_reason="Offline SMT proof exceeds the practical budget.",
        advisory=spec.AdvisoryTone.WARNING,
        advisory_reason="SMT verification skipped; this is not a runtime claim.",
        cost=spec.TransformCost.PROOF_EXPENSIVE,
        option_fields=(
            spec.FieldEditorSpec(
                field_id="max_terms",
                label="Maximum terms",
                path=("max_terms",),
                control=spec.FieldControlKind.INTEGER,
                minimum=1,
                maximum=16,
                default=8,
            ),
        ),
    )

    editor = spec.PassEditorSpec.transform_catalog((transform,))

    assert editor.option_paths() == (
        ("transforms",),
        ("transform_options",),
        ("transform_options", "mul-mba-1", "max_terms"),
    )
    assert editor.default_options() == {
        "transforms": ["mul-mba-1"],
        "transform_options": {"mul-mba-1": {"max_terms": 8}},
    }


def test_transform_selection_seeds_defaults_and_prunes_stale_options() -> None:
    spec = _editor_module()
    transform = spec.TransformEditorSpec(
        transform_id="mul-mba-1",
        label="Mul MBA 1",
        family_id="multiplication",
        family_label="Multiplication",
        subfamily_id="mba-multiplication",
        subfamily_label="MBA multiplication",
        description="Simplify an MBA multiplication pattern to x * y.",
        reference="MBA obfuscation with double bnot verification",
        maturities=("any",),
        default_selected=False,
        verification=spec.VerificationStatus.SKIPPED,
        verification_reason="Offline SMT proof exceeds the practical budget.",
        advisory=spec.AdvisoryTone.WARNING,
        advisory_reason="SMT verification skipped; this is not a runtime claim.",
        cost=spec.TransformCost.PROOF_EXPENSIVE,
        option_fields=(
            spec.FieldEditorSpec(
                field_id="max_terms",
                label="Maximum terms",
                path=("max_terms",),
                control=spec.FieldControlKind.INTEGER,
                minimum=1,
                maximum=16,
                default=8,
            ),
        ),
    )
    editor = spec.PassEditorSpec.transform_catalog((transform,))

    assert editor.options_with_transform_selection(
        {"transforms": [], "transform_options": {"stale": {"value": 1}}},
        ("mul-mba-1",),
    ) == {
        "transforms": ["mul-mba-1"],
        "transform_options": {"mul-mba-1": {"max_terms": 8}},
    }

    with pytest.raises(ValueError, match="sequence of strings"):
        editor.options_with_transform_selection(
            {"transforms": [], "transform_options": {}},
            (1,),
        )


def test_summary_spec_has_no_fields_or_transforms() -> None:
    spec = _editor_module()

    summary = spec.PassEditorSpec.summary()

    assert summary.kind is spec.PassEditorKind.SUMMARY
    assert summary.fields == ()
    assert summary.transforms == ()


def test_fields_editor_renders_nested_defaults_and_validates_choice_lists() -> None:
    spec = _editor_module()
    maturity = spec.FieldEditorSpec(
        field_id="stage.maturities",
        label="Stage maturities",
        path=("stages", "stage", "maturities"),
        control=spec.FieldControlKind.STRING_LIST,
        choices=("CANONICAL", "GLOBAL_ANALYZED", "STRUCTURED"),
        default=["CANONICAL", "STRUCTURED"],
    )
    policy = spec.FieldEditorSpec(
        field_id="stage.policy",
        label="Stage policy",
        path=("stages", "stage", "policy"),
        control=spec.FieldControlKind.ENUM,
        choices=("strict", "aggressive"),
        default="strict",
    )
    editor = spec.PassEditorSpec.fields_editor(
        (maturity, policy),
        sections=(
            spec.PassEditorSectionSpec(
                "stage",
                "Stage",
                ("stage.maturities", "stage.policy"),
                presentation=spec.PassEditorSectionPresentation.PRIMARY,
            ),
        ),
    )

    assert editor.default_options() == {
        "stages": {
            "stage": {
                "maturities": ["CANONICAL", "STRUCTURED"],
                "policy": "strict",
            }
        }
    }
    maturity.validate_value(["STRUCTURED", "CANONICAL"])
    with pytest.raises(ValueError, match="outside its declared choices"):
        maturity.validate_value(["LIFTED"])


def test_experimental_field_requires_operator_facing_reason() -> None:
    spec = _editor_module()

    with pytest.raises(ValueError, match="experimental_reason"):
        spec.FieldEditorSpec(
            field_id="unsafe_mode",
            label="Unsafe mode",
            path=("unsafe_mode",),
            control=spec.FieldControlKind.BOOLEAN,
            default=False,
            experimental=True,
        )


def test_field_advisory_requires_reason_without_hiding_the_control() -> None:
    spec = _editor_module()

    with pytest.raises(ValueError, match="advisory_reason"):
        spec.FieldEditorSpec(
            field_id="unsafe_mode",
            label="Unsafe mode",
            path=("unsafe_mode",),
            control=spec.FieldControlKind.BOOLEAN,
            default=False,
            advisory=spec.AdvisoryTone.DANGER,
        )


def test_rule_catalog_has_explicit_family_metadata_and_typed_defaults() -> None:
    spec = _editor_module()
    rule = spec.RuleEditorSpec(
        rule_id="mul-mba-1",
        label="Multiply MBA pattern",
        family_id="mba",
        family_label="MBA patterns",
        subfamily_id="multiply",
        subfamily_label="Multiplication",
        description="Simplify a multiply-based MBA identity.",
        default_selected=True,
        experimental=True,
        experimental_reason="Proof is intentionally skipped because it is expensive.",
        verification=spec.VerificationStatus.SKIPPED,
        verification_reason="Four multiplications exceed the practical SMT budget.",
    )

    editor = spec.PassEditorSpec.rule_catalog((rule,))

    assert editor.kind is spec.PassEditorKind.RULE_CATALOG
    assert editor.rules == (rule,)
    assert editor.option_paths() == (("enabled_rules",),)
    assert editor.default_options() == {"enabled_rules": ["mul-mba-1"]}
