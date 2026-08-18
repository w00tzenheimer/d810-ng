"""Config-v2 wiring tests for the narrow rotate-idiom recovery stage."""

from __future__ import annotations

import json
from pathlib import Path

from d810.core.config import ProjectConfiguration
from d810.passes.pipeline_v2_hook_bridge import pipeline_v2_hook_activation


_ROOT = Path(__file__).resolve().parents[3]
_PROFILE = _ROOT / "src/d810/conf/eidolon_v3_const_solve.json"


def _profile() -> ProjectConfiguration:
    return ProjectConfiguration(
        path=_PROFILE,
        **json.loads(_PROFILE.read_text(encoding="utf-8")),
    )


def test_eid_profile_places_rotate_recovery_directly_after_mba_solve() -> None:
    pass_ids = [
        entry["pass_id"]
        for entry in _profile().additional_configuration["pipeline_v2"]
    ]
    mba_solve_index = pass_ids.index("mba-solve")
    assert pass_ids[mba_solve_index + 1] == "rotate-idiom-recovery"


def test_hook_bridge_exposes_rotate_recovery_as_a_global_flow_rule() -> None:
    activation = pipeline_v2_hook_activation(_profile())

    assert "rotate-idiom-recovery" in activation.configured_pass_ids
    assert [rule.name for rule in activation.block_rules].count(
        "RotateIdiomRecoveryBlockRule"
    ) == 1
    rule = next(
        rule
        for rule in activation.block_rules
        if rule.name == "RotateIdiomRecoveryBlockRule"
    )
    assert rule.config == {"maturities": ["GLOBAL_OPTIMIZED"]}
