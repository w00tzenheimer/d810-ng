"""Microblock evidence builders for ref_region_oracle.

Tests the per-side evidence schema and the canonical opcode_signature
form. No IDA imports — all helpers operate on plain dataclasses.
"""
from __future__ import annotations

import json

import pytest

from d810.cfg.ref_region_oracle import (
    BlockView,
    D810Evidence,
    InstructionView,
    RefEvidence,
    build_d810_evidence,
    build_ref_evidence_from_spec_path,
    opcode_signature,
    spec_for,
)


def _block_view(
    *,
    serial: int = 161,
    start_ea: int = 0x180012DF0,
    end_ea: int = 0x180012E10,
    instructions: tuple[InstructionView, ...] = (),
    preds: tuple[int, ...] = (),
    succs: tuple[int, ...] = (),
    in_scc: bool = False,
    scc_size: int | None = None,
    block_type: str = "BLT_1WAY",
) -> BlockView:
    return BlockView(
        serial=serial,
        start_ea=start_ea,
        end_ea=end_ea,
        instructions=instructions,
        preds=preds,
        succs=succs,
        in_scc=in_scc,
        scc_size=scc_size,
        block_type=block_type,
    )


def _ins(opcode_name: str) -> InstructionView:
    return InstructionView(opcode_name=opcode_name)


def test_opcode_signature_joins_with_semicolon_space():
    block = _block_view(instructions=(_ins("m_mov"), _ins("m_stx_byte"), _ins("m_goto")))
    assert opcode_signature(block) == "m_mov; m_stx_byte; m_goto"


def test_opcode_signature_empty_block_is_empty_string():
    block = _block_view(instructions=())
    assert opcode_signature(block) == ""


def test_opcode_signature_ignores_operand_changes():
    a = _block_view(instructions=(_ins("m_mov"), _ins("m_mov"), _ins("m_goto")))
    b = _block_view(instructions=(_ins("m_mov"), _ins("m_mov"), _ins("m_goto")))
    assert opcode_signature(a) == opcode_signature(b)


def test_build_d810_evidence_populates_required_fields():
    block = _block_view(
        serial=161,
        start_ea=0x180012DF0,
        end_ea=0x180012E10,
        instructions=(_ins("m_mov"), _ins("m_goto")),
        preds=(120, 142),
        succs=(218,),
        in_scc=False,
        block_type="BLT_1WAY",
    )
    ev = build_d810_evidence(
        block,
        snapshot_id=17,
        snapshot_label="post_bundle_stabilize",
        region_role="terminal_tail.byte_emit",
    )
    assert ev.side == "d810"
    assert ev.snapshot_id == 17
    assert ev.snapshot_label == "post_bundle_stabilize"
    assert ev.block_serial == 161
    assert ev.start_ea_hex == "0x0000000180012df0"
    assert ev.end_ea_hex == "0x0000000180012e10"
    assert ev.opcode_signature == "m_mov; m_goto"
    assert ev.preds == (120, 142)
    assert ev.succs == (218,)
    assert ev.region_role == "terminal_tail.byte_emit"
    assert ev.block_type == "BLT_1WAY"


def test_build_d810_evidence_round_trips_json():
    block = _block_view(instructions=(_ins("m_mov"),))
    ev = build_d810_evidence(
        block,
        snapshot_id=17,
        snapshot_label="post_bundle_stabilize",
        region_role="terminal_tail.byte_emit",
    )
    payload = json.dumps(ev.to_json_dict(), sort_keys=True)
    decoded = json.loads(payload)
    assert decoded["side"] == "d810"
    assert decoded["block_serial"] == 161
    assert decoded["opcode_signature"] == "m_mov"


def test_build_ref_evidence_from_spec_path_uses_path_string():
    ev = build_ref_evidence_from_spec_path(
        ref_block="byte_emit[3]",
        path_string="ref.c:527",
        opcode_signature="m_mov; m_stx_byte; m_jcnd; m_goto",
        region_role="terminal_tail.byte_emit",
        preds=("dispatcher_root",),
        succs=("shared_terminal_tail",),
    )
    assert ev.side == "ref"
    assert ev.ref_block == "byte_emit[3]"
    assert ev.ref_ea_or_line_range == "ref.c:527"
    assert ev.opcode_signature == "m_mov; m_stx_byte; m_jcnd; m_goto"
    assert ev.region_role == "terminal_tail.byte_emit"
    assert ev.preds == ("dispatcher_root",)
    assert ev.succs == ("shared_terminal_tail",)


def test_build_ref_evidence_round_trips_json():
    ev = build_ref_evidence_from_spec_path(
        ref_block="byte_emit[3]",
        path_string="ref.c:527",
        opcode_signature="m_mov",
        region_role="terminal_tail.byte_emit",
    )
    payload = json.dumps(ev.to_json_dict(), sort_keys=True)
    decoded = json.loads(payload)
    assert decoded["side"] == "ref"
    assert decoded["ref_block"] == "byte_emit[3]"


def test_evidence_required_fields_validated_on_construction():
    with pytest.raises(ValueError, match="ref_block"):
        RefEvidence(
            side="ref",
            ref_block="",
            ref_ea_or_line_range="ref.c:527",
            opcode_signature="m_mov",
            region_role="terminal_tail.byte_emit",
            preds=(),
            succs=(),
        )

    with pytest.raises(ValueError, match="block_serial"):
        D810Evidence(
            side="d810",
            snapshot_id=17,
            snapshot_label="post_bundle_stabilize",
            block_serial=None,  # type: ignore[arg-type]
            start_ea_hex="0x0000000180012df0",
            end_ea_hex="0x0000000180012e10",
            opcode_signature="m_mov",
            preds=(),
            succs=(),
            in_scc=False,
            scc_size=None,
            block_type="BLT_1WAY",
            region_role="terminal_tail.byte_emit",
        )
