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


@pytest.mark.parametrize("transform_id", ("mul-mba-2", "mul-mba-3"))
def test_known_incorrect_mba_rules_remain_selectable_but_default_disabled(
    transform_id: str,
) -> None:
    catalog = _catalog_module()
    item = _transform(transform_id)

    assert item.advisory is catalog.AdvisoryTone.DANGER
    assert item.default_selected is False
    assert item.verification is catalog.VerificationStatus.KNOWN_INCORRECT
