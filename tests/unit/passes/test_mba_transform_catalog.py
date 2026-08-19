"""Explicit config-v2 operator metadata for mba-simplify transforms."""

from __future__ import annotations

import pytest


def _catalog_module() -> object:
    try:
        from d810.passes import mba_transform_catalog
    except ImportError as error:
        pytest.fail(f"MBA transform editor catalog is not available: {error}")
    return mba_transform_catalog


def _transform(transform_id: str) -> object:
    catalog = _catalog_module()
    return next(
        item
        for item in catalog.mba_transform_editor_spec().transforms
        if item.transform_id == transform_id
    )


def test_mba_catalog_has_one_explicit_spec_for_every_registered_transform() -> None:
    catalog = _catalog_module()
    from d810.passes.mba_transform_options import mba_transform_stages

    assert tuple(
        item.transform_id for item in catalog.mba_transform_editor_spec().transforms
    ) == tuple(item.stage_id for item in mba_transform_stages())
    assert all(
        item.family_id and item.family_label for item in catalog.MBA_TRANSFORM_SPECS
    )


def test_mul_mba_1_describes_costly_proof_without_runtime_claim() -> None:
    catalog = _catalog_module()
    item = _transform("mul-mba-1")

    assert item.advisory is catalog.AdvisoryTone.WARNING
    assert item.verification is catalog.VerificationStatus.SKIPPED
    assert item.cost is catalog.TransformCost.PROOF_EXPENSIVE
    assert "four multiplications" in item.cost_detail.casefold()
    assert "runtime" not in item.advisory_reason.lower()


def test_hodur_complement_mask_is_registered_but_default_disabled() -> None:
    """Egglog may select the certified rule without making it a fast-path default."""

    item = _transform("sub-complement-mask-hodur-1")

    assert item.default_selected is False
    assert "Hodur" in item.description


def test_mba_catalog_exposes_commutative_generation_as_a_boolean_option() -> None:
    """Public config-v2 projects must be able to disable generated variants."""

    catalog = _catalog_module()
    field = next(
        item
        for item in catalog.mba_transform_editor_spec().fields
        if item.path == ("generate_commutative_permutations",)
    )

    assert field.control is catalog.FieldControlKind.BOOLEAN
    assert field.default is True


@pytest.mark.parametrize(
    "transform_id",
    ("z-3-setz-generic", "z-3-setnz-generic", "z-3-lnot-generic"),
)
def test_generic_z3_catalog_exposes_independent_bounded_proof_controls(
    transform_id: str,
) -> None:
    catalog = _catalog_module()
    item = _transform(transform_id)

    assert item.option_fields == (
        catalog.FieldEditorSpec(
            field_id="max_expression_nodes",
            label="Maximum expression nodes",
            path=("max_expression_nodes",),
            control=catalog.FieldControlKind.INTEGER,
            description="Maximum expanded AST node occurrences for one proof.",
            minimum=1,
            maximum=4096,
            default=256,
        ),
        catalog.FieldEditorSpec(
            field_id="proof_timeout_ms",
            label="Proof timeout (ms)",
            path=("proof_timeout_ms",),
            control=catalog.FieldControlKind.INTEGER,
            description="Maximum solver time for one proof in milliseconds.",
            minimum=1,
            maximum=5000,
            default=50,
        ),
    )


@pytest.mark.parametrize("transform_id", ("mul-mba-2", "mul-mba-3"))
def test_known_incorrect_mba_rules_remain_selectable_but_default_disabled(
    transform_id: str,
) -> None:
    catalog = _catalog_module()
    item = _transform(transform_id)

    assert item.advisory is catalog.AdvisoryTone.DANGER
    assert item.default_selected is False
    assert item.verification is catalog.VerificationStatus.KNOWN_INCORRECT
