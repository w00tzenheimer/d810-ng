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
_MECHANISM_LIVE_HOST = "live_host"
_MECHANISM_MULTI_BYTE = "multi_byte_live_host"
_MECHANISM_BYTE_STORE = "byte_store_replica"


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


def parse_reconnect_env(value: str | None) -> tuple[int, ...] | None:
    """Parse D810_TAIL_ANCHOR_RECONNECT_BYTES=3,4,5,6.

    Each byte k in the list triggers: find byte k's own snap17 emit
    block, clone it as a successor of byte 1's emit host. Each clone
    has byte k's NATIVE m_stx (correct byte_index, correct slot
    address from k's natural counter). No patching needed.

    Returns a sorted tuple of unique byte indices, or None if invalid.
    """
    return parse_multi_byte_env(value)


def parse_byte_host_overrides_env(
    value: str | None,
) -> dict[int, int] | None:
    """Parse D810_TAIL_ANCHOR_HOST_OVERRIDES=2:1,4:0.

    Returns a dict mapping target_byte_index -> host_byte_index, or None
    if the value is unset/empty/malformed. Allows hosting each target
    byte's anchor on a DIFFERENT surviving block, so per-anchor writes
    don't dedup against each other on the same chain.
    """
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    overrides: dict[int, int] = {}
    for pair in text.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            return None
        target_s, host_s = pair.split(":", 1)
        try:
            target = int(target_s.strip())
            host = int(host_s.strip())
        except ValueError:
            return None
        if not (0 <= target <= 6) or host not in (0, 1):
            return None
        overrides[target] = host
    return overrides if overrides else None


def parse_byte_store_env(value: str | None) -> tuple[int, ...] | None:
    """Parse D810_TAIL_ANCHOR_STORE_BYTES=2,3,4,5,6.

    Returns a sorted tuple of unique byte indices, or None if invalid.
    Same format as parse_multi_byte_env but selects the byte_store
    replica mechanism instead of XOR.
    """
    return parse_multi_byte_env(value)


def parse_multi_byte_env(value: str | None) -> tuple[int, ...] | None:
    """Parse D810_TAIL_ANCHOR_READ_BYTES=2,3,4,5,6.

    Returns a sorted tuple of unique byte indices in [0, 6], or None
    if the value is unset, empty, or contains any invalid entry.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    parts = [p.strip() for p in text.split(",") if p.strip()]
    if not parts:
        return None
    try:
        bytes_set = {int(p) for p in parts}
    except ValueError:
        return None
    if not all(0 <= b <= 6 for b in bytes_set):
        return None
    return tuple(sorted(bytes_set))


def parse_multi_host_env(value: str | None) -> int | None:
    """Parse D810_TAIL_ANCHOR_LIVE_HOST=N (host byte for multi-byte
    mechanism). Defaults are handled by caller (typically host=1).
    Returns N if value parses to 0 or 1, else None.
    """
    if value is None:
        return None
    text = value.strip()
    if text not in ("0", "1"):
        return None
    return int(text)


def parse_live_host_env(value: str | None) -> int | None:
    """Parse D810_TAIL_ANCHOR_BYTE6_LIVE_HOST=N.

    Returns the host byte index (0 or 1) if value parses to a known
    surviving byte. Any other input returns None. The live-host
    mechanism inserts ANCHOR_A as a successor of the BYTE_N emit
    block (not byte 6's) so that the anchor survives IDA's
    snap17 -> snap18 DCE pass which destroys byte 6's host block.

    Empirical: only bytes 0 and 1's emit blocks survive snap18 in
    sub_7FFD3338C040 baseline.
    """
    if value is None:
        return None
    text = value.strip()
    if text not in ("0", "1"):
        return None
    return int(text)


@dataclass(frozen=True, slots=True)
class MultiByteAnchorReport:
    """Result of one execute_multi_byte_live_host_anchor call.

    Aggregates one ByteEmitAnchorReport per byte index requested.
    `applied` is True iff at least one sub-anchor applied.
    """

    applied: bool
    host_byte_index: int
    read_byte_indices: tuple[int, ...]
    reason: str
    sub_reports: tuple[Any, ...] = ()


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


def execute_live_host_anchor(
    *,
    host_byte_index: int,
    read_byte_index: int,
    adapter: Any,
    accumulator_stkoff: int = _ACCUMULATOR_STKOFF,
) -> ByteEmitAnchorReport:
    """Insert ANCHOR_A as a successor of byte_HOST's emit block,
    reading byte_READ from `(v190+#read_byte_index.8)`.

    Rationale: in sub_7FFD3338C040, hodur's linearization makes byte 6's
    emit block unreachable, so IDA's optimize_global DCEs it (and any
    anchor attached to it). Byte 0 and byte 1's emit blocks survive
    because they're on the linearized live path. Hosting the anchor on
    a surviving block keeps the read of byte 6 alive.

    Returns ByteEmitAnchorReport with `byte_index=read_byte_index`
    (the byte whose load we're trying to preserve).
    """
    if host_byte_index not in (0, 1):
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=read_byte_index,
            mechanism=_MECHANISM_LIVE_HOST,
            reason="host_byte_must_be_0_or_1",
        )
    if read_byte_index != 6:
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=read_byte_index,
            mechanism=_MECHANISM_LIVE_HOST,
            reason="read_byte_must_be_6",
        )

    host_block = adapter.find_byte_emit_block_by_v190_offset(host_byte_index)
    if host_block is None:
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=read_byte_index,
            mechanism=_MECHANISM_LIVE_HOST,
            reason=f"host_byte_{host_byte_index}_not_resolvable",
        )

    try:
        # Searches host_block first, then any block in mba; falls back
        # to the cross-block byte_6 reference (likely block 217).
        source_operand = adapter.extract_v190_indexed_operand(
            host_block.serial, read_byte_index,
        )
    except Exception:  # noqa: BLE001
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=read_byte_index,
            mechanism=_MECHANISM_LIVE_HOST,
            reason="source_operand_unavailable",
            byte_emit_serial=host_block.serial,
        )

    assert host_block.succ_serial is not None
    try:
        anchor_a = adapter.insert_anchor_block_xor_pair(
            predecessor_serial=host_block.serial,
            successor_serial=host_block.succ_serial,
            source_addr_operand=source_operand,
            accumulator_stkoff=accumulator_stkoff,
        )
    except Exception:  # noqa: BLE001
        logger.exception(
            "byte_anchor[live_host]: anchor_a insert failed for host block %d",
            host_block.serial,
        )
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=read_byte_index,
            mechanism=_MECHANISM_LIVE_HOST,
            reason="anchor_insert_failed:a",
            byte_emit_serial=host_block.serial,
        )

    return ByteEmitAnchorReport(
        applied=True,
        byte_index=read_byte_index,
        mechanism=_MECHANISM_LIVE_HOST,
        reason="ok",
        byte_emit_serial=host_block.serial,  # the HOST block, not the byte's block
        anchor_a_serial=anchor_a,
        anchor_b_serial=None,
        accumulator_stkoff=accumulator_stkoff,
    )


def execute_multi_byte_live_host_anchor(
    *,
    host_byte_index: int,
    read_byte_indices: tuple[int, ...],
    adapter: Any,
    accumulator_stkoff: int = _ACCUMULATOR_STKOFF,
) -> MultiByteAnchorReport:
    """Insert one ANCHOR per read_byte_index, all hosted as successors of
    byte_HOST's emit block. Each anchor reads its byte from
    (v190+#k.8) and XORs into the shared accumulator slot.

    Because each anchor is inserted with predecessor=host_block, IDA's
    block-insertion semantics chain them: subsequent insertions wedge
    in BEFORE the previously inserted anchor. The end-of-chain
    successor remains host_block's original successor.

    Returns MultiByteAnchorReport with one ByteEmitAnchorReport per
    byte requested. `applied` is True if at least one sub-anchor
    applied; the caller can inspect sub_reports for per-byte details.
    """
    if host_byte_index not in (0, 1):
        return MultiByteAnchorReport(
            applied=False,
            host_byte_index=host_byte_index,
            read_byte_indices=read_byte_indices,
            reason="host_byte_must_be_0_or_1",
        )
    if not read_byte_indices:
        return MultiByteAnchorReport(
            applied=False,
            host_byte_index=host_byte_index,
            read_byte_indices=read_byte_indices,
            reason="empty_read_byte_list",
        )

    sub_reports: list[ByteEmitAnchorReport] = []
    any_applied = False
    for read_byte in read_byte_indices:
        sub = execute_live_host_anchor(
            host_byte_index=host_byte_index,
            read_byte_index=read_byte,
            adapter=adapter,
            accumulator_stkoff=accumulator_stkoff,
        ) if read_byte == 6 else _execute_live_host_anchor_relaxed(
            host_byte_index=host_byte_index,
            read_byte_index=read_byte,
            adapter=adapter,
            accumulator_stkoff=accumulator_stkoff,
        )
        sub_reports.append(sub)
        if sub.applied:
            any_applied = True

    return MultiByteAnchorReport(
        applied=any_applied,
        host_byte_index=host_byte_index,
        read_byte_indices=read_byte_indices,
        reason="ok" if any_applied else "no_sub_anchor_applied",
        sub_reports=tuple(sub_reports),
    )


def execute_reconnect_byte_emits(
    *,
    target_byte_indices: tuple[int, ...],
    host_byte_index: int,
    adapter: Any,
) -> MultiByteAnchorReport:
    """For each byte k in target_byte_indices, clone byte k's OWN
    snap17 emit block (the one whose m_stx already writes byte k to
    byte k's natural slot) as a successor of byte HOST's emit block.

    No patching: the clone has byte k's native byte_index, address
    operand, and shift -- straight from the dying snap17 block.

    This is the 'reconnect' approach: instead of inserting synthetic
    anchors, splice the existing-but-unreachable byte_emit blocks
    back into the live control flow.
    """
    if host_byte_index not in (0, 1):
        return MultiByteAnchorReport(
            applied=False,
            host_byte_index=host_byte_index,
            read_byte_indices=target_byte_indices,
            reason="host_byte_must_be_0_or_1",
        )
    if not target_byte_indices:
        return MultiByteAnchorReport(
            applied=False,
            host_byte_index=host_byte_index,
            read_byte_indices=target_byte_indices,
            reason="empty_byte_list",
        )

    host_block = adapter.find_byte_emit_block_by_v190_offset(host_byte_index)
    if host_block is None:
        return MultiByteAnchorReport(
            applied=False,
            host_byte_index=host_byte_index,
            read_byte_indices=target_byte_indices,
            reason=f"host_byte_{host_byte_index}_not_resolvable",
        )

    sub_reports: list[ByteEmitAnchorReport] = []
    any_applied = False
    for target_byte in target_byte_indices:
        try:
            # Re-fetch host_block each iteration so we get its CURRENT
            # successor (the previous anchor in the chain, if any). The
            # BlockView captured at find-time goes stale once we mutate.
            host_block_fresh = adapter.find_byte_emit_block_by_v190_offset(
                host_byte_index,
            )
            if host_block_fresh is None:
                raise RuntimeError("host_block no longer resolvable mid-iteration")
            # template_byte_index == target_byte_index: patcher becomes a no-op
            anchor_serial = adapter.insert_byte_emit_replica_anchor(
                predecessor_serial=host_block_fresh.serial,
                successor_serial=host_block_fresh.succ_serial,
                template_byte_index=target_byte,
                target_byte_index=target_byte,
            )
            sub_reports.append(ByteEmitAnchorReport(
                applied=True,
                byte_index=target_byte,
                mechanism="reconnect_byte_emit",
                reason="ok",
                byte_emit_serial=host_block.serial,
                anchor_a_serial=anchor_serial,
            ))
            any_applied = True
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "byte_anchor[reconnect]: failed for byte %d",
                target_byte,
            )
            sub_reports.append(ByteEmitAnchorReport(
                applied=False,
                byte_index=target_byte,
                mechanism="reconnect_byte_emit",
                reason=f"reconnect_failed:{type(exc).__name__}",
                byte_emit_serial=host_block.serial,
            ))

    return MultiByteAnchorReport(
        applied=any_applied,
        host_byte_index=host_byte_index,
        read_byte_indices=target_byte_indices,
        reason="ok" if any_applied else "no_sub_anchor_applied",
        sub_reports=tuple(sub_reports),
    )


def execute_byte_store_replica_anchor(
    *,
    host_byte_index: int,
    target_byte_indices: tuple[int, ...],
    adapter: Any,
    host_overrides: dict[int, int] | None = None,
) -> MultiByteAnchorReport:
    """Insert one m_stx-replica anchor per target byte index. Each
    anchor is hosted on a SURVIVING block (typically byte 1's or
    byte 0's emit block).

    By default every anchor uses ``host_byte_index`` as its host. The
    optional ``host_overrides`` map (target_byte -> host_byte) lets
    specific bytes use a DIFFERENT host. This avoids IDA's optimizer
    dedup'ing same-host anchors that all write to the same slot.

    Example: ``host_byte_index=1`` with
    ``host_overrides={4: 0}`` produces:
      - byte 2 anchor hosted on byte 1's block
      - byte 4 anchor hosted on byte 0's block (separate chain)
    """
    if host_byte_index not in (0, 1):
        return MultiByteAnchorReport(
            applied=False,
            host_byte_index=host_byte_index,
            read_byte_indices=target_byte_indices,
            reason="host_byte_must_be_0_or_1",
        )
    if not target_byte_indices:
        return MultiByteAnchorReport(
            applied=False,
            host_byte_index=host_byte_index,
            read_byte_indices=target_byte_indices,
            reason="empty_target_byte_list",
        )

    overrides = host_overrides or {}

    # Cache host blocks by host_byte to avoid repeated lookups.
    host_cache: dict[int, Any] = {}

    sub_reports: list[ByteEmitAnchorReport] = []
    any_applied = False
    for target_byte in target_byte_indices:
        this_host = int(overrides.get(target_byte, host_byte_index))
        host_block = host_cache.get(this_host)
        if host_block is None:
            host_block = adapter.find_byte_emit_block_by_v190_offset(this_host)
            host_cache[this_host] = host_block
        if host_block is None:
            sub_reports.append(ByteEmitAnchorReport(
                applied=False,
                byte_index=target_byte,
                mechanism=_MECHANISM_BYTE_STORE,
                reason=f"host_byte_{this_host}_not_resolvable",
            ))
            continue
        try:
            anchor_serial = adapter.insert_byte_emit_replica_anchor(
                predecessor_serial=host_block.serial,
                successor_serial=host_block.succ_serial,
                template_byte_index=this_host,
                target_byte_index=target_byte,
            )
            sub_reports.append(ByteEmitAnchorReport(
                applied=True,
                byte_index=target_byte,
                mechanism=_MECHANISM_BYTE_STORE,
                reason="ok",
                byte_emit_serial=host_block.serial,
                anchor_a_serial=anchor_serial,
            ))
            any_applied = True
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "byte_anchor[byte_store]: replica insert failed for byte %d (host %d)",
                target_byte, this_host,
            )
            sub_reports.append(ByteEmitAnchorReport(
                applied=False,
                byte_index=target_byte,
                mechanism=_MECHANISM_BYTE_STORE,
                reason=f"replica_insert_failed:{type(exc).__name__}",
                byte_emit_serial=host_block.serial,
            ))

    return MultiByteAnchorReport(
        applied=any_applied,
        host_byte_index=host_byte_index,
        read_byte_indices=target_byte_indices,
        reason="ok" if any_applied else "no_sub_anchor_applied",
        sub_reports=tuple(sub_reports),
    )


def _execute_live_host_anchor_relaxed(
    *,
    host_byte_index: int,
    read_byte_index: int,
    adapter: Any,
    accumulator_stkoff: int,
) -> ByteEmitAnchorReport:
    """Like execute_live_host_anchor but without the byte_index==6 guard.

    Used by the multi-byte orchestrator to insert anchors for any of
    bytes 0..6 (not just byte 6) hosted on byte_HOST's emit block.
    """
    if host_byte_index not in (0, 1):
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=read_byte_index,
            mechanism=_MECHANISM_MULTI_BYTE,
            reason="host_byte_must_be_0_or_1",
        )
    if not (0 <= read_byte_index <= 6):
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=read_byte_index,
            mechanism=_MECHANISM_MULTI_BYTE,
            reason="read_byte_out_of_range",
        )

    host_block = adapter.find_byte_emit_block_by_v190_offset(host_byte_index)
    if host_block is None:
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=read_byte_index,
            mechanism=_MECHANISM_MULTI_BYTE,
            reason=f"host_byte_{host_byte_index}_not_resolvable",
        )

    try:
        source_operand = adapter.extract_v190_indexed_operand(
            host_block.serial, read_byte_index,
        )
    except Exception:  # noqa: BLE001
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=read_byte_index,
            mechanism=_MECHANISM_MULTI_BYTE,
            reason="source_operand_unavailable",
            byte_emit_serial=host_block.serial,
        )

    assert host_block.succ_serial is not None
    try:
        anchor_a = adapter.insert_anchor_block_xor_pair(
            predecessor_serial=host_block.serial,
            successor_serial=host_block.succ_serial,
            source_addr_operand=source_operand,
            accumulator_stkoff=accumulator_stkoff,
        )
    except Exception:  # noqa: BLE001
        logger.exception(
            "byte_anchor[multi]: anchor insert failed for byte %d on host %d",
            read_byte_index, host_block.serial,
        )
        return ByteEmitAnchorReport(
            applied=False,
            byte_index=read_byte_index,
            mechanism=_MECHANISM_MULTI_BYTE,
            reason="anchor_insert_failed:a",
            byte_emit_serial=host_block.serial,
        )

    return ByteEmitAnchorReport(
        applied=True,
        byte_index=read_byte_index,
        mechanism=_MECHANISM_MULTI_BYTE,
        reason="ok",
        byte_emit_serial=host_block.serial,
        anchor_a_serial=anchor_a,
        anchor_b_serial=None,
        accumulator_stkoff=accumulator_stkoff,
    )
