"""Proof, profile, and registration coverage for Eid's linear-MBA XOR rules."""

import json
from pathlib import Path

import pytest

from d810.backends.mba.z3 import verify_rule
from d810.mba.maturity import MicrocodeMaturity
from d810.mba.rules import eid
from d810.passes.mba_transform_catalog import MBA_TRANSFORM_SPECS
from d810.passes.mba_transform_options import mba_transform_stages


_PROFILES = tuple(
    Path(__file__).resolve().parents[3] / "src/d810/conf" / name
    for name in (
        "eidolon_v3_const_solve.json",
        "eidolon_v4_const_simplify_solve.json",
    )
)
_TRANSFORM_IDS = (
    "add-eid-sbox-offset-13-1",
    "add-eid-sbox-offset-23-1",
    "bnot-eid-sbox-offset-27-1",
    "or-eid-repeated-masked-operand-1",
    "xor-eid-complement-consensus-1",
    "xor-eid-complement-partition-1",
    "xor-eid-complement-partition-2",
    "xor-eid-complement-partition-3",
    "xor-eid-key-schedule-1",
    "xor-eid-key-schedule-2",
    "xor-eid-key-schedule-3",
)

_RULE_NAMES = (
    "Add_EidSboxOffset13_1",
    "Add_EidSboxOffset23_1",
    "Bnot_EidSboxOffset27_1",
    "Or_EidRepeatedMaskedOperand_1",
    "Xor_EidKeySchedule_1",
    "Xor_EidKeySchedule_2",
    "Xor_EidKeySchedule_3",
    "Xor_EidComplementPartition_1",
    "Xor_EidComplementPartition_2",
    "Xor_EidComplementPartition_3",
    "Xor_EidComplementConsensus_1",
)


@pytest.mark.parametrize("bit_width", (8, 16, 32, 64))
@pytest.mark.parametrize("rule_name", _RULE_NAMES)
@pytest.mark.slow
def test_eid_rules_are_z3_valid_at_every_native_width(rule_name, bit_width):
    rule_type = getattr(eid, rule_name, None)
    assert rule_type is not None, f"missing Eid transform {rule_name}"
    assert verify_rule(rule_type(), bit_width=bit_width) is True


def test_eid_xor_rules_use_named_native_maturities():
    assert eid._ALL_MATURITIES == [
        MicrocodeMaturity.PREOPTIMIZED,
        MicrocodeMaturity.LOCOPT,
        MicrocodeMaturity.CALLS,
        MicrocodeMaturity.GLBOPT1,
        MicrocodeMaturity.GLBOPT2,
    ]


def test_eid_rules_are_registered_and_catalogued():
    transform_ids = tuple(stage.stage_id for stage in mba_transform_stages())
    catalog_ids = tuple(spec.transform_id for spec in MBA_TRANSFORM_SPECS)

    assert transform_ids == catalog_ids
    assert transform_ids.index("xor-chain") < transform_ids.index(
        "xor-eid-key-schedule-1"
    )
    assert transform_ids.index("xor-eid-key-schedule-1") < transform_ids.index(
        "xor-eid-key-schedule-2"
    )
    assert transform_ids.index("xor-eid-key-schedule-2") < transform_ids.index(
        "xor-eid-key-schedule-3"
    )
    assert transform_ids.index("xor-eid-key-schedule-3") < transform_ids.index(
        "xor-factor-1"
    )
    assert "or-eid-repeated-masked-operand-1" in transform_ids
    assert "add-eid-sbox-offset-13-1" in transform_ids
    assert "add-eid-sbox-offset-23-1" in transform_ids
    assert "bnot-eid-sbox-offset-27-1" in transform_ids
    assert "xor-eid-complement-consensus-1" in transform_ids
    assert transform_ids.index("xor-eid-complement-partition-1") < transform_ids.index(
        "xor-eid-complement-partition-2"
    )
    assert transform_ids.index("xor-eid-complement-partition-2") < transform_ids.index(
        "xor-eid-complement-partition-3"
    )
    assert transform_ids.index("xor-eid-complement-partition-3") < transform_ids.index(
        "xor-eid-key-schedule-1"
    )


@pytest.mark.parametrize("profile", _PROFILES, ids=lambda path: path.stem)
def test_eid_profiles_activate_every_eid_transform(profile):
    project = json.loads(profile.read_text(encoding="utf-8"))
    pipeline = project["additional_configuration"]["pipeline_v2"]
    simplify = next(item for item in pipeline if item["pass_id"] == "mba-simplify")
    selected = tuple(
        transform_id
        for transform_id in simplify["options"]["transforms"]
        if "-eid-" in transform_id
    )

    assert selected == _TRANSFORM_IDS
