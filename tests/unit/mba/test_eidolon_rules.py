"""Proof, profile, and registration coverage for Eidolon's linear-MBA XOR rules."""

import json
from pathlib import Path

import pytest

from d810.backends.mba.z3 import verify_rule
from d810.mba.maturity import MicrocodeMaturity
from d810.mba.rules import eidolon
from d810.passes.mba_transform_catalog import MBA_TRANSFORM_SPECS
from d810.passes.mba_transform_options import mba_transform_stages


_PROFILE = (
    Path(__file__).resolve().parents[3]
    / "src/d810/conf/eidolon_v3_const_solve.json"
)
_TRANSFORM_IDS = (
    "xor-eidolon-key-schedule-1",
    "xor-eidolon-key-schedule-2",
    "xor-eidolon-key-schedule-3",
)


@pytest.mark.parametrize("bit_width", (8, 16, 32, 64))
@pytest.mark.parametrize(
    "rule_name",
    (
        "Xor_EidolonKeySchedule_1",
        "Xor_EidolonKeySchedule_2",
        "Xor_EidolonKeySchedule_3",
    ),
)
def test_eidolon_xor_rules_are_z3_valid_at_every_native_width(rule_name, bit_width):
    rule_type = getattr(eidolon, rule_name, None)
    assert rule_type is not None, f"missing Eidolon transform {rule_name}"
    assert verify_rule(rule_type(), bit_width=bit_width) is True


def test_eidolon_xor_rules_use_named_native_maturities():
    assert eidolon._ALL_MATURITIES == [
        MicrocodeMaturity.PREOPTIMIZED,
        MicrocodeMaturity.LOCOPT,
        MicrocodeMaturity.CALLS,
        MicrocodeMaturity.GLBOPT1,
        MicrocodeMaturity.GLBOPT2,
    ]


def test_eidolon_xor_rules_are_registered_and_catalogued_in_xor_order():
    transform_ids = tuple(stage.stage_id for stage in mba_transform_stages())
    catalog_ids = tuple(spec.transform_id for spec in MBA_TRANSFORM_SPECS)

    assert transform_ids == catalog_ids
    assert transform_ids.index("xor-chain") < transform_ids.index(
        "xor-eidolon-key-schedule-1"
    )
    assert transform_ids.index("xor-eidolon-key-schedule-1") < transform_ids.index(
        "xor-eidolon-key-schedule-2"
    )
    assert transform_ids.index("xor-eidolon-key-schedule-2") < transform_ids.index(
        "xor-eidolon-key-schedule-3"
    )
    assert transform_ids.index("xor-eidolon-key-schedule-3") < transform_ids.index(
        "xor-factor-1"
    )


def test_eidolon_const_solve_profile_activates_every_eidolon_xor_transform():
    project = json.loads(_PROFILE.read_text(encoding="utf-8"))
    pipeline = project["additional_configuration"]["pipeline_v2"]
    simplify = next(item for item in pipeline if item["pass_id"] == "mba-simplify")
    selected = tuple(
        transform_id
        for transform_id in simplify["options"]["transforms"]
        if transform_id.startswith("xor-eidolon-key-schedule-")
    )

    assert selected == _TRANSFORM_IDS
