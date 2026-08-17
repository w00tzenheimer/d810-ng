"""Config-v2 wiring tests for finite-zero-set predicate recovery."""

from __future__ import annotations

import json
from pathlib import Path

from d810.core.config import ProjectConfiguration
from d810.passes.config_v2_hook_runtime import compile_config_v2_hook_schedule


_ROOT = Path(__file__).resolve().parents[3]
_PROFILE = _ROOT / "src/d810/conf/eidolon_v3_const_solve.json"


def _profile() -> ProjectConfiguration:
    return ProjectConfiguration(
        path=_PROFILE,
        **json.loads(_PROFILE.read_text(encoding="utf-8")),
    )


def test_eid_profile_selects_finite_zero_set_as_an_mba_predicate_transform() -> None:
    mba_simplify = next(
        entry
        for entry in _profile().additional_configuration["pipeline_v2"]
        if entry["pass_id"] == "mba-simplify"
    )

    assert "finite-zero-set-predicate" in mba_simplify["options"]["transforms"]


def test_hook_bridge_routes_the_selected_predicate_transform_to_the_block_pipeline() -> None:
    activation = compile_config_v2_hook_schedule(_profile())

    assert activation.configured_pass_ids.count("mba-simplify") == 1
    assert "finite-zero-set-predicate" not in activation.configured_pass_ids
    rule = next(
        rule
        for rule in activation.block_bindings
        if rule.name == "FiniteZeroSetPredicateBlockRule"
    )
    assert rule.config == {}
