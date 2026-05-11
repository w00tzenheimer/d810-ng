"""Write MBA state to SQLite diagnostic snapshot."""
from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Mapping as MappingABC
from dataclasses import dataclass, field

from d810.core.diag.formatting import format_block_id
from d810.core.typing import Any, Iterable, Mapping

_SIGNED64_MAX = 0x7FFFFFFFFFFFFFFF
_MASK64 = 0xFFFFFFFFFFFFFFFF
_SYNTHETIC_DAG_NODE_STATE_PREFIX = 0xD810000000000000
_SYNTHETIC_DAG_NODE_STATE_MASK = 0x0000FFFFFFFFFFFF


def _safe_int(val: int | None) -> int | None:
    """Clamp to signed 64-bit range for SQLite. Store as negative if > 2^63."""
    if val is None:
        return None
    if val > _SIGNED64_MAX:
        return val - (1 << 64)
    return val


def _dual(val: int | None) -> tuple[str | None, int | None]:
    """Return (hex_text, signed_i64) pair for an unsigned 64-bit value.

    The hex column is fixed-width 16-digit lowercase so that lexicographic
    sort matches numeric sort.  The i64 column stores the signed
    representation for numeric filtering/sorting in SQL.
    """
    if val is None:
        return (None, None)
    hex_text = f"0x{val & _MASK64:016x}"
    i64 = _safe_int(val)
    return (hex_text, i64)


def _fnv1a_64(text: str) -> int:
    value = 0xCBF29CE484222325
    for byte in text.encode("utf-8", errors="surrogatepass"):
        value ^= byte
        value = (value * 0x100000001B3) & _MASK64
    return value


def dag_node_diagnostic_state(node_or_key: object) -> int:
    """Return a stable state-like identity for a DAG node in diagnostics.

    ``dag_nodes`` and ``dag_local_*`` tables both use this value. Exact nodes
    use their concrete state. Range-backed nodes without a concrete state use
    ``range_lo`` as the representative. Nodes that have neither get a stable
    synthetic identity derived from their handler/range tuple, instead of
    collapsing under state zero.
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


def _hex64_or_none(value: int | None) -> str | None:
    if value is None:
        return None
    return f"0x{int(value) & _MASK64:016x}"


def _insn_ea_fingerprint(block: BlockSnapshot) -> str:
    return json.dumps(
        [_hex64_or_none(insn.ea) for insn in block.instructions],
        separators=(",", ":"),
    )


def _opcode_fingerprint(block: BlockSnapshot) -> str:
    return json.dumps(
        [int(insn.opcode) for insn in block.instructions],
        separators=(",", ":"),
    )


def _operand_fingerprint(block: BlockSnapshot) -> str:
    """Return a stable operand-shape fingerprint for a block body.

    This deliberately avoids ``dstr`` because the display string is a human
    rendering and can change independently of the microcode shape.
    """
    rows: list[dict[str, object | None]] = []
    for insn in block.instructions:
        rows.append({
            "d_t": insn.dest_type,
            "d_o": _safe_int(insn.dest_stkoff),
            "d_s": _safe_int(insn.dest_size),
            "l_t": insn.src_l_type,
            "l_o": _safe_int(insn.src_l_stkoff),
            "l_v": _hex64_or_none(insn.src_l_value),
            "r_t": insn.src_r_type,
            "r_o": _safe_int(insn.src_r_stkoff),
            "r_v": _hex64_or_none(insn.src_r_value),
        })
    return json.dumps(rows, sort_keys=True, separators=(",", ":"))


def _body_fingerprint(block: BlockSnapshot) -> str:
    payload = json.dumps(
        {
            "ea": _insn_ea_fingerprint(block),
            "op": _opcode_fingerprint(block),
            "operand": _operand_fingerprint(block),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"fnv1a64:0x{_fnv1a_64(payload):016x}"


def _block_observation_row(
    snapshot_id: int,
    block: BlockSnapshot,
    *,
    maturity: str,
    phase: str,
) -> tuple[object, ...]:
    start_hex, start_i64 = _dual(block.start_ea)
    return (
        int(snapshot_id),
        int(block.serial),
        str(maturity),
        str(phase),
        start_hex,
        start_i64,
        len(block.instructions),
        _insn_ea_fingerprint(block),
        _opcode_fingerprint(block),
        _operand_fingerprint(block),
        _body_fingerprint(block),
    )


@dataclass
class DagNode:
    """Snapshot of a DAG node (handler state).

    Attributes:
        state: Stable diagnostic state identity. Exact nodes use the handler
            state constant, range-only nodes use range_lo, and anonymous nodes
            use a synthetic handler-derived identity.
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


def snapshot_mba(
    conn: sqlite3.Connection,
    blocks: list[BlockSnapshot],
    label: str,
    func_ea: int,
    maturity: str = "UNKNOWN",
    phase: str = "unknown",
) -> int:
    """Snapshot MBA blocks and instructions into SQLite.

    Args:
        conn: SQLite connection with schema already created.
        blocks: List of BlockSnapshot dataclasses.
        label: Snapshot label (e.g. "pass0_post_apply").
        func_ea: Function effective address.
        maturity: MBA maturity level string.
        phase: Pipeline phase (pre_d810, post_apply, post_gut_wire,
            post_pipeline, or unknown).

    Returns:
        The snapshot_id of the newly created row.
    """
    func_hex, func_i64 = _dual(func_ea)
    cursor = conn.execute(
        "INSERT INTO snapshots "
        "(label, func_ea_hex, func_ea_i64, maturity, phase, block_count, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (label, func_hex, func_i64, maturity, phase, len(blocks), time.time()),
    )
    snap_id = cursor.lastrowid
    assert snap_id is not None

    # Bulk insert blocks
    block_rows = []
    for b in blocks:
        s_hex, s_i64 = _dual(b.start_ea)
        e_hex, e_i64 = _dual(b.end_ea)
        block_rows.append((
            snap_id,
            b.serial,
            b.block_type,
            b.type_name,
            s_hex,
            s_i64,
            e_hex,
            e_i64,
            b.nsucc,
            b.npred,
            json.dumps(b.succs),
            json.dumps(b.preds),
            len(b.instructions),
            b.meta,
        ))
    conn.executemany(
        "INSERT INTO blocks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        block_rows,
    )
    observation_rows = [
        _block_observation_row(
            snap_id,
            b,
            maturity=maturity,
            phase=phase,
        )
        for b in blocks
    ]
    if observation_rows:
        conn.executemany(
            "INSERT INTO block_observations VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            observation_rows,
        )

    # Bulk insert instructions
    insn_rows = []
    for b in blocks:
        for insn in b.instructions:
            ea_hex, ea_i64 = _dual(insn.ea)
            sl_hex, sl_i64 = _dual(insn.src_l_value)
            sr_hex, sr_i64 = _dual(insn.src_r_value)
            insn_rows.append((
                snap_id,
                b.serial,
                insn.index,
                ea_hex,
                ea_i64,
                insn.opcode,
                insn.opcode_name,
                insn.dest_type,
                _safe_int(insn.dest_stkoff),
                insn.dest_size,
                insn.src_l_type,
                _safe_int(insn.src_l_stkoff),
                sl_hex,
                sl_i64,
                insn.src_r_type,
                _safe_int(insn.src_r_stkoff),
                sr_hex,
                sr_i64,
                insn.dstr,
                insn.meta,
            ))
    if insn_rows:
        conn.executemany(
            "INSERT INTO instructions VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            insn_rows,
        )

    # Flush any pending CFG provenance entries under this snapshot_id. Each
    # call to ``log_cfg_provenance`` appends to a per-process buffer; the
    # next ``snapshot_mba`` call drains that buffer and persists it to
    # ``cfg_provenance``. Best-effort: failure here must NOT break snapshots.
    try:
        from d810.core.diag import drain_pending_provenance
        prov_entries = drain_pending_provenance()
        if prov_entries:
            prov_rows = [
                (
                    snap_id,
                    seq_idx,
                    e.pass_name,
                    e.action,
                    int(e.block_serial),
                    (int(e.target_serial) if e.target_serial is not None else None),
                    e.reason,
                    e.extra_json,
                )
                for seq_idx, e in enumerate(prov_entries)
            ]
            conn.executemany(
                "INSERT INTO cfg_provenance VALUES (?,?,?,?,?,?,?,?)",
                prov_rows,
            )
    except Exception:
        pass

    # Flush any pending created-block lineage entries under this snapshot_id.
    # The executor buffers these after PatchPlan apply and before taking the
    # post-apply snapshot so clone/insert origins are attached to the concrete
    # assigned serials visible in this snapshot.  cfg.block_lineage owns the
    # buffer and registers itself as a drainer through the inversion-of-control
    # hook in core.diag — see register_lineage_drainer().
    try:
        from d810.core.diag import drain_lineage_into_snapshot
        drain_lineage_into_snapshot(conn, snap_id)
    except Exception:
        pass

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
    node_rows = []
    for n in nodes:
        st_hex, st_i64 = _dual(n.state)
        node_rows.append((
            snapshot_id,
            st_hex,
            st_i64,
            n.entry_block,
            n.classification,
            n.shared_suffix,
        ))
    conn.executemany(
        "INSERT INTO dag_nodes VALUES (?,?,?,?,?,?)",
        node_rows,
    )

    edge_rows = []
    for e in edges:
        ss_hex, ss_i64 = _dual(e.source_state)
        ts_hex, ts_i64 = _dual(e.target_state)
        edge_rows.append((
            snapshot_id,
            e.edge_id,
            ss_hex,
            ss_i64,
            ts_hex,
            ts_i64,
            e.edge_kind,
            e.source_block,
            e.source_arm,
            e.target_entry,
            e.ordered_path,
        ))
    conn.executemany(
        "INSERT INTO dag_edges VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        edge_rows,
    )

    conn.commit()


def _enum_name(value: object) -> str:
    name = getattr(value, "name", None)
    if name is not None:
        return str(name)
    return str(value)


def _node_state_value(node: object) -> int:
    return dag_node_diagnostic_state(node)


def snapshot_dag_local_facts(
    conn: sqlite3.Connection,
    snapshot_id: int,
    dag: object,
) -> None:
    """Snapshot typed node-local facts from a LinearizedStateDag-like object.

    This intentionally uses duck typing so the core diag module remains pure
    Python and does not import the recon layer. ``snapshot_dag`` stores the
    outer state graph; this stores each node's block roles, local segments, and
    state-local CFG edges for on-demand DB rendering and planner audits.
    """
    nodes = tuple(getattr(dag, "nodes", ()) or ())
    block_rows: list[tuple] = []
    segment_rows: list[tuple] = []
    edge_rows: list[tuple] = []

    for node in nodes:
        state_hex, _state_i64 = _dual(_node_state_value(node))
        if state_hex is None:
            continue
        entry_block = int(getattr(node, "entry_anchor"))

        for role, attr in (
            ("owned", "owned_blocks"),
            ("exclusive", "exclusive_blocks"),
            ("shared_suffix", "shared_suffix_blocks"),
        ):
            for block_index, block_serial in enumerate(
                getattr(node, attr, ()) or ()
            ):
                block_rows.append((
                    snapshot_id,
                    state_hex,
                    entry_block,
                    int(block_serial),
                    block_index,
                    role,
                ))

        for segment_index, segment in enumerate(
            getattr(node, "local_segments", ()) or ()
        ):
            blocks = [int(block) for block in getattr(segment, "blocks", ()) or ()]
            segment_rows.append((
                snapshot_id,
                state_hex,
                entry_block,
                segment_index,
                str(getattr(segment, "segment_id")),
                _enum_name(getattr(segment, "kind")),
                json.dumps(blocks),
            ))

        for edge_index, edge in enumerate(getattr(node, "local_edges", ()) or ()):
            branch_arm = getattr(edge, "branch_arm", None)
            edge_rows.append((
                snapshot_id,
                state_hex,
                entry_block,
                edge_index,
                str(getattr(edge, "source_segment_id")),
                str(getattr(edge, "target_segment_id")),
                _enum_name(getattr(edge, "kind")),
                int(branch_arm) if branch_arm is not None else None,
            ))

    conn.execute("DELETE FROM dag_node_blocks WHERE snapshot_id=?", (snapshot_id,))
    conn.execute("DELETE FROM dag_local_segments WHERE snapshot_id=?", (snapshot_id,))
    conn.execute("DELETE FROM dag_local_edges WHERE snapshot_id=?", (snapshot_id,))

    if block_rows:
        conn.executemany(
            "INSERT INTO dag_node_blocks VALUES (?,?,?,?,?,?)",
            block_rows,
        )
    if segment_rows:
        conn.executemany(
            "INSERT INTO dag_local_segments VALUES (?,?,?,?,?,?,?)",
            segment_rows,
        )
    if edge_rows:
        conn.executemany(
            "INSERT INTO dag_local_edges VALUES (?,?,?,?,?,?,?,?)",
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
    rows = []
    for m in modifications:
        ws_hex, ws_i64 = _dual(m.write_site_ea)
        rows.append((
            snapshot_id,
            m.mod_index,
            m.mod_type,
            m.source_block,
            m.target_block,
            m.old_target,
            ws_hex,
            ws_i64,
            m.write_site_blk,
            m.status,
            m.reason,
        ))
    conn.executemany(
        "INSERT INTO modifications VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        rows,
    )
    conn.commit()


def snapshot_rendered_program(
    conn: sqlite3.Connection,
    snapshot_id: int,
    program,
) -> None:
    """Snapshot a rendered linearized program into SQLite.

    The *program* object is expected to expose:
    ``variant_name``, ``order_strategy``, ``program_strategy``,
    ``label_render_mode``, ``boundary_inline_mode``, ``comment_mode``,
    ``nodes`` and ``lines``. Each node should expose ``node_index``,
    ``label_text``, ``node_kind``, ``state_label``, ``handler_serial``,
    ``entry_anchor``, ``label_num``, ``line_start``, and ``line_end``.
    Each line should expose ``line_no``, ``text``, ``node_index``,
    ``indent_level``, ``line_kind``, and ``target_label``.
    """
    variant_name = str(program.variant_name)
    conn.execute(
        "DELETE FROM rendered_program_lines WHERE snapshot_id=? AND variant_name=?",
        (snapshot_id, variant_name),
    )
    conn.execute(
        "DELETE FROM rendered_program_nodes WHERE snapshot_id=? AND variant_name=?",
        (snapshot_id, variant_name),
    )
    conn.execute(
        "DELETE FROM rendered_programs WHERE snapshot_id=? AND variant_name=?",
        (snapshot_id, variant_name),
    )
    conn.execute(
        "INSERT INTO rendered_programs VALUES (?,?,?,?,?,?,?,?,?)",
        (
            snapshot_id,
            variant_name,
            str(program.order_strategy),
            str(program.program_strategy),
            str(program.label_render_mode),
            str(program.boundary_inline_mode),
            str(program.comment_mode),
            len(program.lines),
            len(program.nodes),
        ),
    )

    node_rows = [
        (
            snapshot_id,
            variant_name,
            int(node.node_index),
            str(node.label_text),
            str(node.node_kind),
            node.state_label,
            _safe_int(node.handler_serial),
            _safe_int(node.entry_anchor),
            _safe_int(node.label_num),
            int(node.line_start),
            int(node.line_end),
        )
        for node in program.nodes
    ]
    if node_rows:
        conn.executemany(
            "INSERT INTO rendered_program_nodes VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            node_rows,
        )

    line_rows = [
        (
            snapshot_id,
            variant_name,
            int(line.line_no),
            _safe_int(line.node_index),
            int(line.indent_level),
            str(line.line_kind),
            line.target_label,
            str(line.text),
        )
        for line in program.lines
    ]
    if line_rows:
        conn.executemany(
            "INSERT INTO rendered_program_lines VALUES (?,?,?,?,?,?,?,?)",
            line_rows,
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


def snapshot_watch_transition(
    conn: sqlite3.Connection,
    *,
    func_ea: int,
    apply_session_id: str,
    mod_index: int | None,
    mod_type: str,
    phase: str,
    block_serial: int,
    prev_type_name: str | None,
    prev_succs: tuple[int, ...] | None,
    prev_preds: tuple[int, ...] | None,
    now_type_name: str | None,
    now_succs: tuple[int, ...] | None,
    now_preds: tuple[int, ...] | None,
) -> None:
    """Persist a single watch-block transition.

    Called by ``DeferredGraphModifier.apply`` when ``D810_DEFERRED_WATCH_BLOCKS``
    is set AND ``D810_DEFERRED_DIAG_PHASES=1`` OR any of the explicit opt-in
    flags enable DB persistence. Each row captures (before, after) state for
    one watched block at one observation point so later SQL queries can
    answer "which mod mutated blk[X]?" programmatically.
    """
    func_hex, func_i64 = _dual(func_ea)
    conn.execute(
        "INSERT INTO watch_block_transitions ("
        "func_ea_hex, func_ea_i64, apply_session_id, mod_index, mod_type, "
        "phase, block_serial, prev_type_name, prev_succs, prev_preds, "
        "now_type_name, now_succs, now_preds, timestamp"
        ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            func_hex,
            func_i64,
            apply_session_id,
            mod_index,
            mod_type,
            phase,
            int(block_serial),
            prev_type_name,
            json.dumps(list(prev_succs)) if prev_succs is not None else None,
            json.dumps(list(prev_preds)) if prev_preds is not None else None,
            now_type_name,
            json.dumps(list(now_succs)) if now_succs is not None else None,
            json.dumps(list(now_preds)) if now_preds is not None else None,
            time.time(),
        ),
    )
    conn.commit()


def _mapping_value(row: Mapping[str, Any] | object, key: str, default: Any = None) -> Any:
    if isinstance(row, MappingABC):
        return row.get(key, default)
    return getattr(row, key, default)


def _json_text(value: Any, default: Any) -> str:
    if value is None:
        value = default
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True)


def _next_table_index(
    conn: sqlite3.Connection,
    table_name: str,
    index_column: str,
    snapshot_id: int,
) -> int:
    row = conn.execute(
        f"SELECT COALESCE(MAX({index_column}), -1) + 1 "
        f"FROM {table_name} WHERE snapshot_id=?",
        (snapshot_id,),
    ).fetchone()
    return int(row[0] if row is not None else 0)


def snapshot_fact_observations(
    conn: sqlite3.Connection,
    snapshot_id: int,
    func_ea: int,
    observations: Iterable[Mapping[str, Any] | object],
) -> None:
    """Snapshot maturity fact observations.

    Rows may be plain mappings or dataclass-like objects.  This keeps the core
    diag layer independent of ``d810.recon.facts`` while still accepting those
    model objects directly.
    """
    func_hex, func_i64 = _dual(func_ea)
    rows = []
    for obs in observations:
        source_ea_hex, source_ea_i64 = _dual(_mapping_value(obs, "source_ea"))
        rows.append((
            snapshot_id,
            func_hex,
            func_i64,
            str(_mapping_value(obs, "fact_id")),
            str(_mapping_value(obs, "kind")),
            str(_mapping_value(obs, "semantic_key")),
            str(_mapping_value(obs, "maturity")),
            str(_mapping_value(obs, "phase")),
            float(_mapping_value(obs, "confidence")),
            _mapping_value(obs, "source_block"),
            source_ea_hex,
            source_ea_i64,
            _mapping_value(obs, "block_fingerprint"),
            _mapping_value(obs, "mop_signature"),
            _json_text(_mapping_value(obs, "payload"), {}),
            _json_text(_mapping_value(obs, "evidence"), []),
        ))
    if rows:
        conn.executemany(
            "INSERT OR REPLACE INTO fact_observations VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
    conn.commit()


def snapshot_fact_mappings(
    conn: sqlite3.Connection,
    snapshot_id: int,
    func_ea: int,
    mappings: Iterable[Mapping[str, Any] | object],
) -> None:
    """Snapshot fact lifecycle mappings for a maturity transition."""
    func_hex, func_i64 = _dual(func_ea)
    rows = []
    start_index = _next_table_index(conn, "fact_mappings", "mapping_index", snapshot_id)
    for offset, mapping in enumerate(mappings):
        index = start_index + offset
        target_ea_hex, target_ea_i64 = _dual(_mapping_value(mapping, "target_ea"))
        status = _mapping_value(mapping, "status")
        status_text = getattr(status, "value", status)
        rows.append((
            snapshot_id,
            func_hex,
            func_i64,
            index,
            str(_mapping_value(mapping, "source_fact_id")),
            _mapping_value(mapping, "target_fact_id"),
            str(_mapping_value(mapping, "source_maturity")),
            str(_mapping_value(mapping, "target_maturity")),
            str(status_text),
            float(_mapping_value(mapping, "confidence")),
            _mapping_value(mapping, "target_block"),
            target_ea_hex,
            target_ea_i64,
            _mapping_value(mapping, "target_mop_signature"),
            _mapping_value(mapping, "reason"),
            _json_text(_mapping_value(mapping, "payload"), {}),
        ))
    if rows:
        conn.executemany(
            "INSERT OR REPLACE INTO fact_mappings VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
    conn.commit()


def snapshot_fact_consumers(
    conn: sqlite3.Connection,
    snapshot_id: int,
    func_ea: int,
    consumers: Iterable[Mapping[str, Any] | object],
) -> None:
    """Snapshot strategy decisions that consumed facts."""
    func_hex, func_i64 = _dual(func_ea)
    rows = []
    start_index = _next_table_index(conn, "fact_consumers", "consumer_index", snapshot_id)
    for offset, consumer in enumerate(consumers):
        index = start_index + offset
        rows.append((
            snapshot_id,
            func_hex,
            func_i64,
            index,
            str(_mapping_value(consumer, "consumer")),
            str(_mapping_value(consumer, "strategy")),
            str(_mapping_value(consumer, "fact_id")),
            str(_mapping_value(consumer, "maturity")),
            str(_mapping_value(consumer, "decision")),
            _mapping_value(consumer, "reason"),
            _json_text(_mapping_value(consumer, "payload"), {}),
        ))
    if rows:
        conn.executemany(
            "INSERT OR REPLACE INTO fact_consumers VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
    conn.commit()


def snapshot_fact_conflicts(
    conn: sqlite3.Connection,
    snapshot_id: int,
    func_ea: int,
    conflicts: Iterable[Mapping[str, Any] | object],
) -> None:
    """Snapshot conflicts between facts or mappings."""
    func_hex, func_i64 = _dual(func_ea)
    rows = []
    for conflict in conflicts:
        rows.append((
            snapshot_id,
            func_hex,
            func_i64,
            str(_mapping_value(conflict, "conflict_id")),
            str(_mapping_value(conflict, "fact_id")),
            str(_mapping_value(conflict, "other_fact_id")),
            str(_mapping_value(conflict, "maturity")),
            str(_mapping_value(conflict, "conflict_kind")),
            str(_mapping_value(conflict, "reason")),
            _json_text(_mapping_value(conflict, "payload"), {}),
        ))
    if rows:
        conn.executemany(
            "INSERT OR REPLACE INTO fact_conflicts VALUES "
            "(?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
    conn.commit()
