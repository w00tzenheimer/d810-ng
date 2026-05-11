"""Live-use anchor probe for byte 6 (Track D, falsification probe #6).

A strict-bar-A (bit-identical) probe that inserts two new microcode
blocks ("anchor reads") consuming byte 6's source-byte read in opposite
directions:

  ANCHOR_A: var_8 ^= *(v190 + #6.8)
  ANCHOR_B: var_8 ^= *(v190 + #6.8)   # net no-op on var_8

The two reads dataflow-pin the source operand so IDA's optimize_global()
cannot DCE byte 6's source read at the snap17 -> snap18 transition. Net
effect on rax-bound %var_8.8: identity. Net effect on memory: zero.

Scope (frozen):
- byte_index == 6 only
- single mechanism: split_xor
- accumulator: %var_8.8 (stkoff 0x818)

Spec: docs/superpowers/specs/2026-05-11-track-d-byte-anchor-design.md
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core import logging
from d810.core.typing import Any

logger = logging.getLogger(__name__)

# Sentinel stack offset of %var_8.8 — the rax-bound return slot. Confirmed
# via prior provenance trace (stkoff=2072 decimal).
_ACCUMULATOR_STKOFF = 0x818

_MECHANISM_SPLIT_XOR = "split_xor"
_MECHANISM_SINGLE_XOR = "single_xor"


def parse_byte_anchor_env(value: str | None) -> str | None:
    """Parse D810_TAIL_ANCHOR_BYTE6_SPLIT_XOR.

    Returns 'split_xor' iff value (stripped) equals '1'. Any other input
    (None, '', '0', non-numeric, 2+) returns None.
    """
    if value is None:
        return None
    text = value.strip()
    if text != "1":
        return None
    return _MECHANISM_SPLIT_XOR


def parse_single_xor_env(value: str | None) -> str | None:
    """Parse D810_TAIL_ANCHOR_BYTE6_SINGLE_XOR.

    Returns 'single_xor' iff value (stripped) equals '1'. The single-XOR
    mechanism inserts only ANCHOR_A (no cancellation pair); the byte 6
    value remains XOR'd into the rax-bound slot permanently. This is a
    deliberate Bar A violation that tests whether a non-cancelling XOR
    survives IDA's optimize_global DCE.
    """
    if value is None:
        return None
    text = value.strip()
    if text != "1":
        return None
    return _MECHANISM_SINGLE_XOR


@dataclass(frozen=True, slots=True)
class ByteEmitAnchorReport:
    """Result of one execute_split_xor_anchor call."""

    applied: bool
    byte_index: int
    mechanism: str
    reason: str
    byte_emit_serial: int | None = None
    anchor_a_serial: int | None = None
    anchor_b_serial: int | None = None
    accumulator_stkoff: int | None = None


def execute_split_xor_anchor(
    *,
    byte_index: int,
    adapter: Any,
    accumulator_stkoff: int = _ACCUMULATOR_STKOFF,
) -> ByteEmitAnchorReport:
    """Insert ANCHOR_A and ANCHOR_B around byte 6's emit block.

    Pure orchestration. `adapter` implements `LiveUseAnchorAdapter`.
    """
    if byte_index != 6:
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=byte_index,
            mechanism=_MECHANISM_SPLIT_XOR,
            reason="probe_byte6_only",
        )

    block = adapter.find_byte_emit_block_by_v190_offset(byte_index)
    if block is None:
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=byte_index,
            mechanism=_MECHANISM_SPLIT_XOR,
            reason="byte_emit_not_resolvable",
        )

    try:
        source_operand = adapter.extract_v190_indexed_operand(
            block.serial, byte_index,
        )
    except Exception:  # noqa: BLE001 — adapter contract: raise on extraction failure
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=byte_index,
            mechanism=_MECHANISM_SPLIT_XOR,
            reason="source_operand_unavailable",
            byte_emit_serial=block.serial,
        )

    try:
        pre_return_serial = adapter.find_pre_return_block()
    except Exception:  # noqa: BLE001 — adapter contract
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=byte_index,
            mechanism=_MECHANISM_SPLIT_XOR,
            reason="pre_return_ambiguous",
            byte_emit_serial=block.serial,
        )

    assert block.succ_serial is not None  # byte 6 emit must be 1-way
    try:
        anchor_a = adapter.insert_anchor_block_xor_pair(
            predecessor_serial=block.serial,
            successor_serial=block.succ_serial,
            source_addr_operand=source_operand,
            accumulator_stkoff=accumulator_stkoff,
        )
    except Exception:  # noqa: BLE001
        logger.exception(
            "byte_anchor: anchor_a insert failed for block %d",
            block.serial,
        )
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=byte_index,
            mechanism=_MECHANISM_SPLIT_XOR,
            reason="anchor_insert_failed:a",
            byte_emit_serial=block.serial,
        )

    try:
        anchor_b = adapter.insert_anchor_block_xor_pair(
            predecessor_serial=pre_return_serial,
            successor_serial=-1,  # adapter resolves: pre-return's existing successor
            source_addr_operand=source_operand,
            accumulator_stkoff=accumulator_stkoff,
        )
    except Exception:  # noqa: BLE001
        logger.exception(
            "byte_anchor: anchor_b insert failed for pre_return %d",
            pre_return_serial,
        )
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=byte_index,
            mechanism=_MECHANISM_SPLIT_XOR,
            reason="anchor_insert_failed:b",
            byte_emit_serial=block.serial,
            anchor_a_serial=anchor_a,
        )

    return ByteEmitAnchorReport(
        applied=True,
        byte_index=byte_index,
        mechanism=_MECHANISM_SPLIT_XOR,
        reason="ok",
        byte_emit_serial=block.serial,
        anchor_a_serial=anchor_a,
        anchor_b_serial=anchor_b,
        accumulator_stkoff=accumulator_stkoff,
    )


def execute_single_xor_anchor(
    *,
    byte_index: int,
    adapter: Any,
    accumulator_stkoff: int = _ACCUMULATOR_STKOFF,
) -> ByteEmitAnchorReport:
    """Insert ONE anchor block (ANCHOR_A) only -- no cancellation pair.

    The byte 6 value remains XOR'd into the rax-bound slot permanently.
    Bar A is violated by design; this variant tests whether a
    non-cancelling XOR survives IDA's optimize_global DCE.
    """
    if byte_index != 6:
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=byte_index,
            mechanism=_MECHANISM_SINGLE_XOR,
            reason="probe_byte6_only",
        )

    block = adapter.find_byte_emit_block_by_v190_offset(byte_index)
    if block is None:
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=byte_index,
            mechanism=_MECHANISM_SINGLE_XOR,
            reason="byte_emit_not_resolvable",
        )

    try:
        source_operand = adapter.extract_v190_indexed_operand(
            block.serial, byte_index,
        )
    except Exception:  # noqa: BLE001
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=byte_index,
            mechanism=_MECHANISM_SINGLE_XOR,
            reason="source_operand_unavailable",
            byte_emit_serial=block.serial,
        )

    assert block.succ_serial is not None
    try:
        anchor_a = adapter.insert_anchor_block_xor_pair(
            predecessor_serial=block.serial,
            successor_serial=block.succ_serial,
            source_addr_operand=source_operand,
            accumulator_stkoff=accumulator_stkoff,
        )
    except Exception:  # noqa: BLE001
        logger.exception(
            "byte_anchor[single]: anchor_a insert failed for block %d",
            block.serial,
        )
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=byte_index,
            mechanism=_MECHANISM_SINGLE_XOR,
            reason="anchor_insert_failed:a",
            byte_emit_serial=block.serial,
        )

    return ByteEmitAnchorReport(
        applied=True,
        byte_index=byte_index,
        mechanism=_MECHANISM_SINGLE_XOR,
        reason="ok",
        byte_emit_serial=block.serial,
        anchor_a_serial=anchor_a,
        anchor_b_serial=None,
        accumulator_stkoff=accumulator_stkoff,
    )
