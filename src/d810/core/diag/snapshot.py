"""Write MBA state to SQLite diagnostic snapshot."""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field

_SIGNED64_MAX = 0x7FFFFFFFFFFFFFFF


def _safe_int(val: int | None) -> int | None:
    """Clamp to signed 64-bit range for SQLite. Store as negative if > 2^63."""
    if val is None:
        return None
    if val > _SIGNED64_MAX:
        return val - (1 << 64)
    return val


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
        header = (
            f"blk[{self.serial}] {self.type_name} "
            f"succs={self.succs} preds={self.preds}"
        )
        lines = [header]
        for insn in self.instructions:
            lines.append(f"  {self.serial}.{insn.index} {insn.dstr}")
        return "\n".join(lines)


@dataclass
class DagNode:
    """Snapshot of a DAG node (handler state).

    Attributes:
        state: Handler state constant (integer).
        state_hex: Hex string representation (e.g. "0x5D0AEBD3").
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


def snapshot_mba(
    conn: sqlite3.Connection,
    blocks: list[BlockSnapshot],
    label: str,
    func_ea: int,
    maturity: str = "UNKNOWN",
) -> int:
    """Snapshot MBA blocks and instructions into SQLite.

    Args:
        conn: SQLite connection with schema already created.
        blocks: List of BlockSnapshot dataclasses.
        label: Snapshot label (e.g. "pass0_post_apply").
        func_ea: Function effective address.
        maturity: MBA maturity level string.

    Returns:
        The snapshot_id of the newly created row.
    """
    cursor = conn.execute(
        "INSERT INTO snapshots (label, func_ea, maturity, block_count, timestamp) "
        "VALUES (?, ?, ?, ?, ?)",
        (label, _safe_int(func_ea), maturity, len(blocks), time.time()),
    )
    snap_id = cursor.lastrowid
    assert snap_id is not None

    # Bulk insert blocks
    block_rows = [
        (
            snap_id,
            b.serial,
            b.block_type,
            b.type_name,
            _safe_int(b.start_ea),
            _safe_int(b.end_ea),
            b.nsucc,
            b.npred,
            json.dumps(b.succs),
            json.dumps(b.preds),
            len(b.instructions),
            b.meta,
        )
        for b in blocks
    ]
    conn.executemany(
        "INSERT INTO blocks VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        block_rows,
    )

    # Bulk insert instructions
    insn_rows = []
    for b in blocks:
        for insn in b.instructions:
            insn_rows.append((
                snap_id,
                b.serial,
                insn.index,
                _safe_int(insn.ea),
                insn.opcode,
                insn.opcode_name,
                insn.dest_type,
                _safe_int(insn.dest_stkoff),
                insn.dest_size,
                insn.src_l_type,
                _safe_int(insn.src_l_stkoff),
                _safe_int(insn.src_l_value),
                insn.src_r_type,
                _safe_int(insn.src_r_stkoff),
                _safe_int(insn.src_r_value),
                insn.dstr,
                insn.meta,
            ))
    if insn_rows:
        conn.executemany(
            "INSERT INTO instructions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            insn_rows,
        )

    conn.commit()
    return snap_id


def snapshot_dag(
    conn: sqlite3.Connection,
    snapshot_id: int,
    nodes: list[DagNode],
    edges: list[DagEdge],
) -> None:
    """Snapshot DAG nodes and edges into SQLite.

    Args:
        conn: SQLite connection with schema already created.
        snapshot_id: The snapshot to associate with.
        nodes: List of DagNode dataclasses.
        edges: List of DagEdge dataclasses.
    """
    node_rows = [
        (
            snapshot_id,
            _safe_int(n.state),
            n.state_hex,
            n.entry_block,
            n.classification,
            n.shared_suffix,
        )
        for n in nodes
    ]
    conn.executemany(
        "INSERT INTO dag_nodes VALUES (?,?,?,?,?,?)",
        node_rows,
    )

    edge_rows = [
        (
            snapshot_id,
            e.edge_id,
            _safe_int(e.source_state),
            _safe_int(e.target_state),
            e.edge_kind,
            e.source_block,
            e.source_arm,
            e.target_entry,
            e.ordered_path,
        )
        for e in edges
    ]
    conn.executemany(
        "INSERT INTO dag_edges VALUES (?,?,?,?,?,?,?,?,?)",
        edge_rows,
    )

    conn.commit()


def snapshot_modifications(
    conn: sqlite3.Connection,
    snapshot_id: int,
    modifications: list[Modification],
) -> None:
    """Snapshot reconstruction modifications into SQLite.

    Args:
        conn: SQLite connection with schema already created.
        snapshot_id: The snapshot to associate with.
        modifications: List of Modification dataclasses.
    """
    rows = [
        (
            snapshot_id,
            m.mod_index,
            m.mod_type,
            m.source_block,
            m.target_block,
            m.old_target,
            _safe_int(m.write_site_ea),
            m.write_site_blk,
            m.status,
            m.reason,
        )
        for m in modifications
    ]
    conn.executemany(
        "INSERT INTO modifications VALUES (?,?,?,?,?,?,?,?,?,?)",
        rows,
    )
    conn.commit()


def snapshot_reachability(
    conn: sqlite3.Connection,
    snapshot_id: int,
    all_serials: set[int],
    reachable: set[int] | None = None,
    bst_serials: set[int] | None = None,
    gutted: set[int] | None = None,
    claimed_sources: set[int] | None = None,
) -> None:
    """Snapshot block classification (reachability, BST, gut status).

    Args:
        conn: SQLite connection with schema already created.
        snapshot_id: The snapshot to associate with.
        all_serials: Complete set of block serials to classify.
        reachable: Set of reachable block serials.
        bst_serials: Set of BST block serials.
        gutted: Set of gutted block serials.
        claimed_sources: Set of claimed source block serials.
    """
    _reachable = reachable or set()
    _bst = bst_serials or set()
    _gutted = gutted or set()
    _claimed = claimed_sources or set()

    rows = [
        (
            snapshot_id,
            serial,
            1 if serial in _bst else 0,
            1 if serial in _reachable else 0,
            1 if serial in _gutted else 0,
            1 if serial in _claimed else 0,
        )
        for serial in sorted(all_serials)
    ]
    conn.executemany(
        "INSERT INTO block_classification VALUES (?,?,?,?,?,?)",
        rows,
    )
    conn.commit()
