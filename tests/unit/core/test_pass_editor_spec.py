"""Contract tests for the closed config-v2 pass editor vocabulary."""

from __future__ import annotations

import pytest


def _editor_module() -> object:
    try:
        from d810.core import pass_editor_spec
    except ImportError as error:
        pytest.fail(f"PassEditorSpec is not available: {error}")
    return pass_editor_spec


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
