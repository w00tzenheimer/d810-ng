"""Write MBA state to SQLite diagnostic snapshot."""
from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Mapping as MappingABC
from dataclasses import dataclass, field

# Neutral observation dataclasses live under d810.core.observability_models
# so the runtime producer and the SQLite sink can share them without a
# layer violation. The names are re-exported here for back-compat with
# existing callers (`from d810.core.diag.snapshot import BlockSnapshot`).
from d810.core.formatting import format_block_id
from d810.core.observability_models import (
    BlockSnapshot as BlockSnapshot,
    DagEdge as DagEdge,
    DagNode as DagNode,
    InstructionSnapshot as InstructionSnapshot,
    Modification as Modification,
    _fnv1a_64,
    dag_node_diagnostic_state as dag_node_diagnostic_state,
)
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
    # The executor buffers these after PatchPlan apply and before
    # taking the post-apply snapshot so clone/insert origins are
    # attached to the concrete assigned serials visible in this
    # snapshot. ``cfg.block_lineage`` owns the buffer and subscribes
    # to ``BlockLineageDrainRequested`` to drain it; the event carries
    # the live conn + snap_id so the subscriber can write rows
    # immediately without round-tripping through the global session
    # lookup.
    try:
        from d810.core.observability import emit
        from d810.core.observability_events import (
            BlockLineageDrainRequested,
        )
        emit(BlockLineageDrainRequested(conn=conn, snapshot_id=snap_id))
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
