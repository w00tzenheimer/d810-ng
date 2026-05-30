from __future__ import annotations

from d810.transforms.semantic_region_materialization import (
    InstructionCaptureDecision,
    InstructionCaptureFacts,
    decide_instruction_capture,
)


def test_decision_skips_goto_and_nop():
    assert decide_instruction_capture(
        InstructionCaptureFacts(is_goto=True),
        opcode=1,
    ) == InstructionCaptureDecision("skip")
    assert decide_instruction_capture(
        InstructionCaptureFacts(is_nop=True),
        opcode=2,
    ) == InstructionCaptureDecision("skip")


def test_decision_aborts_on_closing_forbidden_before_other_checks():
    assert decide_instruction_capture(
        InstructionCaptureFacts(
            is_closing_forbidden=True,
            is_conditional_jump=True,
            is_tail=True,
            block_has_required_payload_evidence=True,
        ),
        opcode=77,
    ) == InstructionCaptureDecision(
        "abort",
        abort_reason="closing_forbidden_opcode=77",
    )


def test_decision_drops_tail_conditional_when_payload_evidence_is_required():
    assert decide_instruction_capture(
        InstructionCaptureFacts(
            is_conditional_jump=True,
            is_tail=True,
            block_has_required_payload_evidence=True,
        ),
        opcode=43,
    ) == InstructionCaptureDecision("drop_control_tail")


def test_decision_aborts_conditional_without_tail_payload_contract():
    assert decide_instruction_capture(
        InstructionCaptureFacts(
            is_conditional_jump=True,
            is_tail=True,
            block_has_required_payload_evidence=False,
        ),
        opcode=43,
    ) == InstructionCaptureDecision(
        "abort",
        abort_reason="jcond_opcode=43",
    )
    assert decide_instruction_capture(
        InstructionCaptureFacts(
            is_conditional_jump=True,
            is_tail=False,
            block_has_required_payload_evidence=True,
        ),
        opcode=43,
    ) == InstructionCaptureDecision(
        "abort",
        abort_reason="jcond_opcode=43",
    )


def test_decision_records_calls_before_state_write_skip():
    assert decide_instruction_capture(
        InstructionCaptureFacts(is_call=True, is_state_write=True),
        opcode=5,
    ) == InstructionCaptureDecision("record_call")


def test_decision_skips_state_write():
    assert decide_instruction_capture(
        InstructionCaptureFacts(is_state_write=True),
        opcode=12,
    ) == InstructionCaptureDecision("skip")


def test_decision_captures_regular_instruction():
    assert decide_instruction_capture(
        InstructionCaptureFacts(),
        opcode=12,
    ) == InstructionCaptureDecision("capture")
