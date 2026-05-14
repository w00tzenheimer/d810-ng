from __future__ import annotations

from types import SimpleNamespace

from d810.cfg.graph_modification import NopInstructions, ZeroStateWrite
from d810.cfg.modification_builder import ModificationBuilder
from d810.cfg.state_write_cleanup import (
    StateWriteCleanupAction,
    StateWriteCleanupRequest,
    state_write_cleanup_to_graph_modification,
)


def test_state_write_cleanup_request_lowers_to_nop_instruction() -> None:
    request = StateWriteCleanupRequest(
        action=StateWriteCleanupAction.NOP_INSTRUCTION,
        block_serial=7,
        insn_ea=0x1004,
        expected_state=0x55,
        observed_state=0x55,
        reason="unit",
    )

    assert state_write_cleanup_to_graph_modification(request) == NopInstructions(
        block_serial=7,
        insn_eas=(0x1004,),
    )


def test_state_write_cleanup_request_lowers_to_zero_state_write() -> None:
    request = StateWriteCleanupRequest(
        action=StateWriteCleanupAction.ZERO_SOURCE,
        block_serial=7,
        insn_ea=0x1004,
        expected_state=0x55,
        observed_state=0x55,
        reason="unit",
    )

    assert state_write_cleanup_to_graph_modification(request) == ZeroStateWrite(
        block_serial=7,
        insn_ea=0x1004,
    )


def test_modification_builder_lowers_state_write_cleanup_request() -> None:
    builder = ModificationBuilder.from_snapshot(
        SimpleNamespace(flow_graph=None, mba=None),
    )
    request = StateWriteCleanupRequest(
        action=StateWriteCleanupAction.ZERO_SOURCE,
        block_serial=9,
        insn_ea=0x2008,
    )

    assert builder.state_write_cleanup(request) == ZeroStateWrite(
        block_serial=9,
        insn_ea=0x2008,
    )
