"""Stable block labels for diagnostics.

Block serials are local to a single MBA snapshot/maturity.  Diagnostics that
compare across maturities or after block creation must include at least the
serial-local snapshot context plus a physical/code identity.  These helpers are
pure ``d810.cfg`` utilities for logs that only have a :class:`FlowGraph`.
"""
from __future__ import annotations

import json
from collections.abc import Iterable

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot, OperandKind


_MATURITY_NAMES = {
    0: "MMAT_ZERO",
    1: "MMAT_GENERATED",
    2: "MMAT_PREOPTIMIZED",
    3: "MMAT_LOCOPT",
    4: "MMAT_CALLS",
    5: "MMAT_GLBOPT1",
    6: "MMAT_GLBOPT2",
    7: "MMAT_GLBOPT3",
    8: "MMAT_LVARS",
}
_MASK64 = 0xFFFFFFFFFFFFFFFF
_SIGNED64_MAX = 0x7FFFFFFFFFFFFFFF


def hex64(value: object | None) -> str | None:
    """Return the fixed-width EA/state text used by diagnostic tables."""
    if value is None:
        return None
    try:
        return f"0x{int(value) & _MASK64:016x}"
    except Exception:
        return None


def _safe_i64(value: object | None) -> int | None:
    if value is None:
        return None
    try:
        value_int = int(value)
    except Exception:
        return None
    if value_int > _SIGNED64_MAX:
        return value_int - (1 << 64)
    return value_int


def _fnv1a_64(text: str) -> int:
    value = 0xCBF29CE484222325
    for byte in text.encode("utf-8", errors="surrogatepass"):
        value ^= byte
        value = (value * 0x100000001B3) & _MASK64
    return value


def maturity_label(value: object | None) -> str:
    """Return a stable maturity label for a metadata value."""
    if value is None:
        return "maturity=?"
    if isinstance(value, str):
        return f"maturity={value}"
    try:
        value_int = int(value)
    except Exception:
        return f"maturity={value}"
    return f"maturity={_MATURITY_NAMES.get(value_int, f'MMAT_{value_int}')}"


def flow_graph_context_label(flow_graph: FlowGraph | None) -> str:
    """Return snapshot/maturity context carried by a FlowGraph."""
    if flow_graph is None:
        return "maturity=? snapshot=?"
    parts = [
        maturity_label(
            flow_graph.metadata.get(
                "producer_stage_id", flow_graph.metadata.get("maturity")
            )
        )
    ]
    snapshot_id = flow_graph.metadata.get("snapshot_id")
    if snapshot_id is not None:
        parts.append(f"snapshot={snapshot_id}")
    phase = flow_graph.metadata.get("phase")
    if phase is not None:
        parts.append(f"phase={phase}")
    return " ".join(parts)


def block_label(flow_graph: FlowGraph | None, serial: int | None) -> str:
    """Format ``blk[N]@0xEA`` using a FlowGraph snapshot."""
    if serial is None:
        return "blk[?]@?"
    serial_int = int(serial)
    if flow_graph is None:
        return f"blk[{serial_int}]@?"
    block = flow_graph.get_block(serial_int)
    if block is None:
        return f"blk[{serial_int}]@?"
    return f"blk[{serial_int}]@0x{int(block.start_ea):x}"


def edge_label(flow_graph: FlowGraph | None, source: int, target: int) -> str:
    """Format a source-to-target edge with EA labels on both ends."""
    return f"{block_label(flow_graph, source)} -> {block_label(flow_graph, target)}"


def instruction_fingerprint(
    instructions: Iterable[InsnSnapshot],
    *,
    limit: int = 4,
) -> str:
    """Return a compact instruction EA/opcode fingerprint."""
    parts: list[str] = []
    for idx, insn in enumerate(instructions):
        if idx >= limit:
            parts.append("...")
            break
        raw_opcode = getattr(insn, "raw_opcode", getattr(insn, "opcode", None))
        parts.append(f"0x{int(insn.ea):x}:op{int(raw_opcode)}")
    return "[" + ",".join(parts) + "]"


def block_fingerprint(
    flow_graph: FlowGraph | None,
    serial: int | None,
    *,
    limit: int = 4,
) -> str:
    """Return a compact fingerprint for a block's current body."""
    if serial is None or flow_graph is None:
        return "fp=[]"
    block = flow_graph.get_block(int(serial))
    if block is None:
        return "fp=[]"
    return "fp=" + instruction_fingerprint(block.insn_snapshots, limit=limit)


def _mop_type_name(value: object | None) -> str | None:
    if not isinstance(value, OperandKind) or value is OperandKind.UNKNOWN:
        return None
    return value.value


def _mop_row(mop: object | None) -> dict[str, object | None]:
    return {
        "t": _mop_type_name(getattr(mop, "kind", None)),
        "o": _safe_i64(getattr(mop, "stkoff", None)),
        "s": _safe_i64(getattr(mop, "size", None)) if mop is not None else None,
        "v": hex64(getattr(mop, "value", None)),
    }


def block_body_observation_fingerprint(
    flow_graph: FlowGraph | None,
    serial: int | None,
) -> str | None:
    """Return the canonical body hash used by ``block_observations``.

    This is the join key for block lineage.  ``block_fingerprint`` is a compact
    human label; this hash mirrors the observation table's EA/opcode/operand
    shape so cloned blocks with duplicate EAs can still be correlated.
    """
    if serial is None or flow_graph is None:
        return None
    block = flow_graph.get_block(int(serial))
    if block is None:
        return None
    ea_fp = json.dumps(
        [hex64(insn.ea) for insn in block.insn_snapshots],
        separators=(",", ":"),
    )
    op_fp = json.dumps(
        [int(getattr(insn, "raw_opcode", getattr(insn, "opcode", 0))) for insn in block.insn_snapshots],
        separators=(",", ":"),
    )
    operand_rows: list[dict[str, object | None]] = []
    for insn in block.insn_snapshots:
        d = _mop_row(getattr(insn, "d", None))
        l = _mop_row(getattr(insn, "l", None))
        r = _mop_row(getattr(insn, "r", None))
        operand_rows.append({
            "d_t": d["t"],
            "d_o": d["o"],
            "d_s": d["s"],
            "l_t": l["t"],
            "l_o": l["o"],
            "l_v": l["v"],
            "r_t": r["t"],
            "r_o": r["o"],
            "r_v": r["v"],
        })
    operand_fp = json.dumps(operand_rows, sort_keys=True, separators=(",", ":"))
    payload = json.dumps(
        {"ea": ea_fp, "op": op_fp, "operand": operand_fp},
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"fnv1a64:0x{_fnv1a_64(payload):016x}"


def block_origin_label(
    flow_graph: FlowGraph | None,
    *,
    assigned_serial: int,
    origin_serial: int | None,
    reason: str,
) -> str:
    """Format clone/insert origin context for diagnostics."""
    assigned = block_label(flow_graph, assigned_serial)
    origin = block_label(flow_graph, origin_serial) if origin_serial is not None else "synthetic"
    return f"{assigned} origin={origin} clone_reason={reason}"


__all__ = [
    "block_fingerprint",
    "block_body_observation_fingerprint",
    "block_label",
    "block_origin_label",
    "edge_label",
    "flow_graph_context_label",
    "hex64",
    "instruction_fingerprint",
    "maturity_label",
]
