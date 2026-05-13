from __future__ import annotations

from d810.cfg.graph_modification import InsertBlock, NopInstructions
from d810.cfg.materialization_backend import (
    BackendInstructionRef,
    CapturedInstructionPayload,
    MaterializationBackend,
)


class _FakeBackend:
    def capture_payload(
        self,
        block_serial: int,
        *,
        omit_terminal_control: bool = False,
        required_source_eas: frozenset[int] = frozenset(),
    ) -> CapturedInstructionPayload | None:
        instructions = (
            BackendInstructionRef(block_serial=block_serial, ea=0x1000, opcode_name="m_add"),
            BackendInstructionRef(block_serial=block_serial, ea=0x1004, opcode_name="m_stx"),
        )
        if omit_terminal_control:
            instructions = instructions[:1]
        payload = CapturedInstructionPayload(
            source_block=block_serial,
            instructions=instructions,
        )
        if not payload.contains_all_source_eas(required_source_eas):
            return None
        return payload

    def lower_insert_block(
        self,
        *,
        source: int,
        old_target: int,
        target: int,
        payload: CapturedInstructionPayload,
        metadata: dict[str, object] | None = None,
    ) -> InsertBlock:
        return InsertBlock(
            pred_serial=source,
            succ_serial=target,
            old_target_serial=old_target,
            instructions=(),
        )

    def lower_nop_instruction(
        self,
        *,
        block_serial: int,
        insn_ea: int,
        metadata: dict[str, object] | None = None,
    ) -> NopInstructions:
        return NopInstructions(block_serial=block_serial, insn_eas=(insn_ea,))


def test_captured_instruction_payload_tracks_required_source_eas() -> None:
    payload = CapturedInstructionPayload(
        source_block=12,
        instructions=(
            BackendInstructionRef(block_serial=12, ea=0x1000),
            BackendInstructionRef(block_serial=12, ea=0x1004),
        ),
    )

    assert payload.source_eas == frozenset({0x1000, 0x1004})
    assert payload.contains_all_source_eas(frozenset({0x1004}))
    assert not payload.contains_all_source_eas(frozenset({0x1008}))


def test_materialization_backend_protocol_supports_cfg_mod_output() -> None:
    backend: MaterializationBackend = _FakeBackend()

    payload = backend.capture_payload(7, required_source_eas=frozenset({0x1004}))
    assert payload is not None

    insert = backend.lower_insert_block(
        source=1,
        old_target=2,
        target=3,
        payload=payload,
    )
    nop = backend.lower_nop_instruction(block_serial=7, insn_ea=0x1004)

    assert insert == InsertBlock(
        pred_serial=1,
        succ_serial=3,
        old_target_serial=2,
        instructions=(),
    )
    assert nop == NopInstructions(block_serial=7, insn_eas=(0x1004,))
