from __future__ import annotations

import pytest

from d810.analyses.control_flow.state_write_evidence import StateConstantWriteEvidence


def test_state_constant_write_evidence_masks_state_value() -> None:
    evidence = StateConstantWriteEvidence(
        block_serial=7,
        insn_ea=0x1000,
        state_value=0x123456789,
    )

    assert evidence.block_serial == 7
    assert evidence.insn_ea == 0x1000
    assert evidence.state_value == 0x23456789


def test_state_constant_write_evidence_rejects_negative_serial() -> None:
    with pytest.raises(ValueError):
        StateConstantWriteEvidence(block_serial=-1, insn_ea=0, state_value=0)


def test_state_constant_write_evidence_rejects_negative_ea() -> None:
    with pytest.raises(ValueError):
        StateConstantWriteEvidence(block_serial=1, insn_ea=-1, state_value=0)
