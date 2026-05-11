"""Neutral diagnostic observation models.

Dataclasses that flow between runtime publishers and the SQLite diag
sink. Living under :mod:`d810.core` (NOT :mod:`d810.core.diag`) so
that runtime observability modules can construct them without
importing the diag sink. The diag sink and the runtime serializers
both import these from here.

This module has zero imports from :mod:`d810.core.diag`. Formatting
helpers come from :mod:`d810.core.formatting`.

History
-------

These dataclasses formerly lived in ``d810.core.diag.snapshot`` and
were re-exported through facade modules. Phase 2/7 of the event
refactor relocated them so they can be shared by both the sink side
and the producer side without a layer violation.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.formatting import format_block_id

_MASK64 = 0xFFFFFFFFFFFFFFFF
_SYNTHETIC_DAG_NODE_STATE_PREFIX = 0xD810000000000000
_SYNTHETIC_DAG_NODE_STATE_MASK = 0x0000FFFFFFFFFFFF


def _fnv1a_64(text: str) -> int:
    value = 0xCBF29CE484222325
    for byte in text.encode("utf-8", errors="surrogatepass"):
        value ^= byte
        value = (value * 0x100000001B3) & _MASK64
    return value


def dag_node_diagnostic_state(node_or_key: object) -> int:
    """Return a stable state-like identity for a DAG node in diagnostics.

    ``dag_nodes`` and ``dag_local_*`` tables both use this value. Exact
    nodes use their concrete state. Range-backed nodes without a
    concrete state use ``range_lo`` as the representative. Nodes that
    have neither get a stable synthetic identity derived from their
    handler/range tuple, instead of collapsing under state zero.
    """
    key = getattr(node_or_key, "key", node_or_key)

    state_const = getattr(key, "state_const", None)
    if state_const is not None:
        return int(state_const) & _MASK64

    range_lo = getattr(key, "range_lo", None)
    if range_lo is not None:
        return int(range_lo) & _MASK64

    handler_serial = getattr(key, "handler_serial", None)
    if handler_serial is None:
        handler_serial = getattr(node_or_key, "handler_serial", None)
    range_hi = getattr(key, "range_hi", None)
    payload = (
        f"handler={handler_serial if handler_serial is not None else 'none'};"
        f"range_lo=none;"
        f"range_hi={range_hi if range_hi is not None else 'none'}"
    )
    digest = _fnv1a_64(payload) & _SYNTHETIC_DAG_NODE_STATE_MASK
    return _SYNTHETIC_DAG_NODE_STATE_PREFIX | digest


# ---------------------------------------------------------------------------
# MBA snapshot models (neutral data containers shared by runtime
# serializer and SQLite sink).
# ---------------------------------------------------------------------------


@dataclass
class InstructionSnapshot:
    """Snapshot of a single microcode instruction.

    Attributes:
        index: Instruction index within the block.
        ea: Effective address.
        opcode: Numeric opcode.
        opcode_name: Human-readable opcode name (e.g. "m_mov").
        dest_type: Destination mop type (e.g. "mop_S", "mop_r").
        dest_stkoff: Stack offset if dest is mop_S.
        dest_size: Destination operand size in bytes.
        src_l_type: Left source operand mop type.
        src_l_stkoff: Left source stack offset if mop_S.
        src_l_value: Left source immediate value if mop_n.
        src_r_type: Right source operand mop type.
        src_r_stkoff: Right source stack offset if mop_S.
        src_r_value: Right source immediate value if mop_n.
        dstr: IDA's display string for the instruction.
        meta: Optional JSON metadata (iprops, sub-insn tree, etc.).
    """

    index: int
    ea: int
    opcode: int
    opcode_name: str
    dest_type: str | None = None
    dest_stkoff: int | None = None
    dest_size: int | None = None
    src_l_type: str | None = None
    src_l_stkoff: int | None = None
    src_l_value: int | None = None
    src_r_type: str | None = None
    src_r_stkoff: int | None = None
    src_r_value: int | None = None
    dstr: str = ""
    meta: str | None = None

    def __str__(self) -> str:
        return self.dstr


@dataclass
class BlockSnapshot:
    """Snapshot of a single microcode block.

    Attributes:
        serial: Block serial number.
        block_type: Numeric block type (BLT_1WAY=1, BLT_2WAY=2, etc.).
        type_name: Human-readable block type name.
        start_ea: Start effective address (may be None).
        end_ea: End effective address (may be None).
        nsucc: Number of successors.
        npred: Number of predecessors.
        succs: List of successor block serials.
        preds: List of predecessor block serials.
        instructions: List of instruction snapshots.
        meta: Optional JSON metadata (valranges, USE/DEF/DNU, flags).
    """

    serial: int
    block_type: int
    type_name: str
    start_ea: int | None = None
    end_ea: int | None = None
    nsucc: int = 0
    npred: int = 0
    succs: list[int] = field(default_factory=list)
    preds: list[int] = field(default_factory=list)
    instructions: list[InstructionSnapshot] = field(default_factory=list)
    meta: str | None = None

    def __str__(self) -> str:
        block_id = format_block_id(
            self.serial,
            start_ea=self.start_ea,
            synthetic=self.start_ea is None,
        )
        header = (
            f"{block_id} {self.type_name} "
            f"succs={self.succs} preds={self.preds}"
        )
        lines = [header]
        for insn in self.instructions:
            lines.append(f"  {self.serial}.{insn.index} {insn.dstr}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# DAG / modification observation models.
# ---------------------------------------------------------------------------


@dataclass
class DagNode:
    """Snapshot of a DAG node (handler state).

    Attributes:
        state: Stable diagnostic state identity. Exact nodes use the
            handler state constant, range-only nodes use range_lo, and
            anonymous nodes use a synthetic handler-derived identity.
        state_hex: Hex string representation (e.g. "0x000000005D0AEBD3").
        entry_block: Entry block serial number.
        classification: Node classification ("TRANSITION", "EXIT", etc.).
        shared_suffix: Optional JSON array of shared block serials.
    """

    state: int
    state_hex: str
    entry_block: int
    classification: str
    shared_suffix: str | None = None


@dataclass
class DagEdge:
    """Snapshot of a DAG edge (transition).

    Attributes:
        edge_id: Unique edge identifier.
        source_state: Source handler state (or None).
        target_state: Target handler state (or None).
        edge_kind: Edge classification string.
        source_block: Source block serial.
        source_arm: Branch arm (0=fallthrough, 1=taken, None=unconditional).
        target_entry: Target entry block serial (or None).
        ordered_path: JSON array of block serials in the path.
    """

    edge_id: int
    source_state: int | None
    target_state: int | None
    edge_kind: str
    source_block: int | None = None
    source_arm: int | None = None
    target_entry: int | None = None
    ordered_path: str = "[]"


@dataclass
class Modification:
    """Snapshot of a reconstruction modification.

    Attributes:
        mod_index: Modification index.
        mod_type: Type string (e.g. "goto_redirect").
        source_block: Source block serial.
        target_block: Target block serial.
        old_target: Original target block serial.
        write_site_ea: Write site effective address.
        write_site_blk: Write site block serial.
        status: Status string ("emitted", "skipped", "rejected").
        reason: Optional reason string.
    """

    mod_index: int
    mod_type: str
    source_block: int | None = None
    target_block: int | None = None
    old_target: int | None = None
    write_site_ea: int | None = None
    write_site_blk: int | None = None
    status: str = "emitted"
    reason: str | None = None


__all__ = [
    "BlockSnapshot",
    "DagEdge",
    "DagNode",
    "InstructionSnapshot",
    "Modification",
    "dag_node_diagnostic_state",
]

# Internal helper kept exported (single-underscore name) so the diag
# sink can reuse the same hash function on snapshot-row digests.
__all__ = list(__all__) + ["_fnv1a_64"]
