"""Config-v2 wiring tests for modular-product predicate recovery."""

from __future__ import annotations

import json
from pathlib import Path

from d810.core.config import ProjectConfiguration
from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation


_ROOT = Path(__file__).resolve().parents[3]
_PROFILE = _ROOT / "src/d810/conf/eidolon_v3_const_solve.json"


def test_eid_profile_selects_modular_product_nonzero_as_an_mba_predicate_transform() -> None:
    profile = ProjectConfiguration(
        path=_PROFILE,
        **json.loads(_PROFILE.read_text(encoding="utf-8")),
    )
    mba_simplify = next(
        entry
        for entry in profile.additional_configuration["pipeline_v2"]
        if entry["pass_id"] == "mba-simplify"
    )

    assert "modular-product-nonzero" in mba_simplify["options"]["transforms"]


def test_hook_bridge_routes_selected_modular_product_transform_to_the_block_pipeline() -> None:
    profile = ProjectConfiguration(
        path=_PROFILE,
        **json.loads(_PROFILE.read_text(encoding="utf-8")),
    )
    activation = pipeline_v2_hook_activation(profile)

    assert activation.configured_pass_ids.count("mba-simplify") == 1
    assert "modular-product-nonzero" not in activation.configured_pass_ids
    rule = next(
        rule
        for rule in activation.block_rules
        if rule.name == "ModularProductNonzeroBlockRule"
    )
    assert rule.config == {}
