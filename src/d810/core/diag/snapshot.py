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
from d810._vendor.peewee import SqliteDatabase
from d810.core.diag import active_diag_db, diag_models_on
from d810.core.diag.models import (
    Block,
    BlockClassification,
    BlockObservation,
    BranchOwnershipProof,
    BstIntervalDispatcherRow,
    CfgProvenance,
    FactConflict,
    FactConsumer,
    FactMapping,
    FactObservation,
    Instruction,
    Modification as ModificationModel,
    RenderedProgram,
    RenderedProgramLine,
    RenderedProgramNode,
    Snapshot,
    StateCfgFrontierClosureDiagnostic,
    StateCfgEdge,
    StateCfgLocalEdge,
    StateCfgLocalSegment,
    StateCfgNode,
    StateCfgNodeBlock,
    StateDispatcherRow,
    StateTransitionDispatchResolution,
    SwitchCaseTransitionFact,
    WatchBlockTransition,
)
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


def _diag_db() -> SqliteDatabase:
    """Return the active diag **write** db for ORM writers.

    This is ``active_diag_db()`` -- the db backing the connection the live
    capture path acquired via ``get_diag_db``. Writers scope the Models to it
    with ``diag_models_on(db)`` (``bind_ctx``) for the write, NEVER relying on
    the mutable process-global ``Model._meta.database`` bind (which a CLI
    ``open_diag_database`` can hijack -> "Cannot operate on a closed database";
    the Phase-B/C live-write hazard).
    """
    db = active_diag_db()
    assert db is not None, "ORM writer called with no active diag db"
    return db

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
) -> dict[str, object]:
    start_hex, start_i64 = _dual(block.start_ea)
    return {
        "snapshot": int(snapshot_id),
        "serial": int(block.serial),
        "maturity": str(maturity),
        "phase": str(phase),
        "start_ea_hex": start_hex,
        "start_ea_i64": start_i64,
        "insn_count": len(block.instructions),
        "insn_ea_fingerprint": _insn_ea_fingerprint(block),
        "opcode_fingerprint": _opcode_fingerprint(block),
        "operand_fingerprint": _operand_fingerprint(block),
        "body_fingerprint": _body_fingerprint(block),
    }


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
    db = _diag_db()
    with diag_models_on(db), db.atomic():
        snapshot = Snapshot.create(
            label=label,
            func_ea_hex=func_hex,
            func_ea_i64=func_i64,
            maturity=maturity,
            phase=phase,
            block_count=len(blocks),
            timestamp=time.time(),
        )
        snap_id = snapshot.id
        assert snap_id is not None

        # Bulk insert blocks
        block_rows = []
        for b in blocks:
            s_hex, s_i64 = _dual(b.start_ea)
            e_hex, e_i64 = _dual(b.end_ea)
            block_rows.append({
                "snapshot": snap_id,
                "serial": b.serial,
                "block_type": b.block_type,
                "type_name": b.type_name,
                "start_ea_hex": s_hex,
                "start_ea_i64": s_i64,
                "end_ea_hex": e_hex,
                "end_ea_i64": e_i64,
                "nsucc": b.nsucc,
                "npred": b.npred,
                "succs": json.dumps(b.succs),
                "preds": json.dumps(b.preds),
                "insn_count": len(b.instructions),
                "meta": b.meta,
            })
        if block_rows:
            Block.insert_many(block_rows).execute()
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
            BlockObservation.insert_many(observation_rows).execute()

        # Bulk insert instructions
        insn_rows = []
        for b in blocks:
            for insn in b.instructions:
                ea_hex, ea_i64 = _dual(insn.ea)
                sl_hex, sl_i64 = _dual(insn.src_l_value)
                sr_hex, sr_i64 = _dual(insn.src_r_value)
                insn_rows.append({
                    "snapshot": snap_id,
                    "block_serial": b.serial,
                    "insn_index": insn.index,
                    "ea_hex": ea_hex,
                    "ea_i64": ea_i64,
                    "opcode": insn.opcode,
                    "opcode_name": insn.opcode_name,
                    "dest_type": insn.dest_type,
                    "dest_stkoff": _safe_int(insn.dest_stkoff),
                    "dest_size": insn.dest_size,
                    "src_l_type": insn.src_l_type,
                    "src_l_stkoff": _safe_int(insn.src_l_stkoff),
                    "src_l_value_hex": sl_hex,
                    "src_l_value_i64": sl_i64,
                    "src_r_type": insn.src_r_type,
                    "src_r_stkoff": _safe_int(insn.src_r_stkoff),
                    "src_r_value_hex": sr_hex,
                    "src_r_value_i64": sr_i64,
                    "dstr": insn.dstr,
                    "meta": insn.meta,
                })
        if insn_rows:
            Instruction.insert_many(insn_rows).execute()

        # Flush any pending CFG provenance entries under this snapshot_id. Each
        # call to ``log_cfg_provenance`` appends to a per-process buffer; the
        # next ``snapshot_mba`` call drains that buffer and persists it to
        # ``cfg_provenance``. Best-effort: failure here must NOT break
        # snapshots.
        try:
            from d810.core.diag import drain_pending_provenance
            prov_entries = drain_pending_provenance()
            if prov_entries:
                prov_rows = [
                    {
                        "snapshot": snap_id,
                        "seq": seq_idx,
                        "pass_name": e.pass_name,
                        "action": e.action,
                        "block_serial": int(e.block_serial),
                        "target_serial": (
                            int(e.target_serial)
                            if e.target_serial is not None else None
                        ),
                        "reason": e.reason,
                        "extra_json": e.extra_json,
                    }
                    for seq_idx, e in enumerate(prov_entries)
                ]
                CfgProvenance.insert_many(prov_rows).execute()
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
    # ORM, bind_ctx-scoped to the active write db (Phase D). A bad ``edge_kind``
    # now surfaces as ``peewee.IntegrityError`` (peewee rewraps the underlying
    # ``sqlite3.IntegrityError``); the constraint test asserts accordingly.
    node_rows = [
        {
            "snapshot": snapshot_id,
            "state_hex": (sv := _dual(n.state))[0],
            "state_i64": sv[1],
            "entry_block": n.entry_block,
            "classification": n.classification,
            "shared_suffix": n.shared_suffix,
        }
        for n in nodes
    ]
    edge_rows = [
        {
            "snapshot": snapshot_id,
            "edge_id": e.edge_id,
            "source_state_hex": (ss := _dual(e.source_state))[0],
            "source_state_i64": ss[1],
            "target_state_hex": (ts := _dual(e.target_state))[0],
            "target_state_i64": ts[1],
            "edge_kind": e.edge_kind,
            "source_block": e.source_block,
            "source_arm": e.source_arm,
            "target_entry": e.target_entry,
            "ordered_path": e.ordered_path,
        }
        for e in edges
    ]
    db = _diag_db()
    with diag_models_on(db), db.atomic():
        if node_rows:
            StateCfgNode.insert_many(node_rows).execute()
        if edge_rows:
            StateCfgEdge.insert_many(edge_rows).execute()


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
    block_rows: list[dict] = []
    segment_rows: list[dict] = []
    edge_rows: list[dict] = []

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
                block_rows.append({
                    "snapshot": snapshot_id,
                    "state_hex": state_hex,
                    "entry_block": entry_block,
                    "block_serial": int(block_serial),
                    "block_index": block_index,
                    "role": role,
                })

        for segment_index, segment in enumerate(
            getattr(node, "local_segments", ()) or ()
        ):
            blocks = [int(block) for block in getattr(segment, "blocks", ()) or ()]
            segment_rows.append({
                "snapshot": snapshot_id,
                "state_hex": state_hex,
                "entry_block": entry_block,
                "segment_index": segment_index,
                "segment_id": str(getattr(segment, "segment_id")),
                "kind": _enum_name(getattr(segment, "kind")),
                "blocks_json": json.dumps(blocks),
            })

        for edge_index, edge in enumerate(getattr(node, "local_edges", ()) or ()):
            branch_arm = getattr(edge, "branch_arm", None)
            edge_rows.append({
                "snapshot": snapshot_id,
                "state_hex": state_hex,
                "entry_block": entry_block,
                "edge_index": edge_index,
                "source_segment_id": str(getattr(edge, "source_segment_id")),
                "target_segment_id": str(getattr(edge, "target_segment_id")),
                "kind": _enum_name(getattr(edge, "kind")),
                "branch_arm": int(branch_arm) if branch_arm is not None else None,
            })

    conn.execute("DELETE FROM state_cfg_node_blocks WHERE snapshot_id=?", (snapshot_id,))
    conn.execute("DELETE FROM state_cfg_local_segments WHERE snapshot_id=?", (snapshot_id,))
    conn.execute("DELETE FROM state_cfg_local_edges WHERE snapshot_id=?", (snapshot_id,))

    db = _diag_db()
    with diag_models_on(db), db.atomic():
        if block_rows:
            StateCfgNodeBlock.insert_many(block_rows).execute()
        if segment_rows:
            StateCfgLocalSegment.insert_many(segment_rows).execute()
        if edge_rows:
            StateCfgLocalEdge.insert_many(edge_rows).execute()

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
        rows.append({
            "snapshot": snapshot_id,
            "mod_index": m.mod_index,
            "mod_type": m.mod_type,
            "source_block": m.source_block,
            "target_block": m.target_block,
            "old_target": m.old_target,
            "write_site_ea_hex": ws_hex,
            "write_site_ea_i64": ws_i64,
            "write_site_blk": m.write_site_blk,
            "status": m.status,
            "reason": m.reason,
        })
    db = _diag_db()
    with diag_models_on(db), db.atomic():
        if rows:
            ModificationModel.insert_many(rows).execute()


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
    node_rows = [
        {
            "snapshot_id": snapshot_id,
            "variant_name": variant_name,
            "node_index": int(node.node_index),
            "label_text": str(node.label_text),
            "node_kind": str(node.node_kind),
            "state_label": node.state_label,
            "handler_serial": _safe_int(node.handler_serial),
            "entry_anchor": _safe_int(node.entry_anchor),
            "label_num": _safe_int(node.label_num),
            "line_start": int(node.line_start),
            "line_end": int(node.line_end),
        }
        for node in program.nodes
    ]
    line_rows = [
        {
            "snapshot_id": snapshot_id,
            "variant_name": variant_name,
            "line_no": int(line.line_no),
            "node_index": _safe_int(line.node_index),
            "indent_level": int(line.indent_level),
            "line_kind": str(line.line_kind),
            "target_label": line.target_label,
            "text": str(line.text),
        }
        for line in program.lines
    ]

    db = _diag_db()
    with diag_models_on(db), db.atomic():
        RenderedProgram.create(
            snapshot=snapshot_id,
            variant_name=variant_name,
            order_strategy=str(program.order_strategy),
            program_strategy=str(program.program_strategy),
            label_render_mode=str(program.label_render_mode),
            boundary_inline_mode=str(program.boundary_inline_mode),
            comment_mode=str(program.comment_mode),
            line_count=len(program.lines),
            node_count=len(program.nodes),
        )
        if node_rows:
            RenderedProgramNode.insert_many(node_rows).execute()
        if line_rows:
            RenderedProgramLine.insert_many(line_rows).execute()

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
        {
            "snapshot": snapshot_id,
            "serial": serial,
            "is_bst": 1 if serial in _bst else 0,
            "is_reachable": 1 if serial in _reachable else 0,
            "is_gutted": 1 if serial in _gutted else 0,
            "in_claimed": 1 if serial in _claimed else 0,
        }
        for serial in sorted(all_serials)
    ]
    db = _diag_db()
    with diag_models_on(db), db.atomic():
        if rows:
            BlockClassification.insert_many(rows).execute()


def snapshot_dag_frontier_closure_diagnostics(
    conn: sqlite3.Connection,
    snapshot_id: int,
    rows: Iterable[Mapping[str, Any] | object],
) -> None:
    """Persist DAG-frontier closure verifier diagnostics.

    Rows are diagnostic-only. They explain verifier leaks and unresolved repair
    candidates, but no behavior code consumes this table.
    """
    conn.execute(
        "DELETE FROM state_cfg_frontier_closure_diagnostics WHERE snapshot_id=?",
        (snapshot_id,),
    )
    db_rows = []
    for row in rows:
        db_rows.append({
            "snapshot": int(snapshot_id),
            "kind": str(_mapping_value(row, "kind")),
            "reason": _mapping_value(row, "reason"),
            "source_block": _mapping_value(row, "source_block"),
            "observed_target": _mapping_value(row, "observed_target"),
            "branch_arm": _mapping_value(row, "branch_arm"),
            "from_dag_scc": _mapping_value(row, "from_dag_scc"),
            "to_dag_scc": _mapping_value(row, "to_dag_scc"),
            "candidate_targets_json": _json_text(
                _mapping_value(row, "candidate_targets"), []
            ),
            "path_json": _json_text(_mapping_value(row, "path"), []),
            "cfg_scc_size": _mapping_value(row, "cfg_scc_size"),
            "payload_json": _json_text(_mapping_value(row, "payload"), {}),
        })
    db = _diag_db()
    with diag_models_on(db), db.atomic():
        if db_rows:
            StateCfgFrontierClosureDiagnostic.insert_many(db_rows).execute()
    conn.commit()


def snapshot_bst_interval_dispatcher_rows(
    conn: sqlite3.Connection,
    snapshot_id: int,
    rows: Iterable[Mapping[str, Any] | object],
    *,
    dispatcher_entry_block: int | None = None,
    maturity: str | None = None,
) -> None:
    """Persist recovered BST interval dispatcher rows for a snapshot."""
    conn.execute(
        "DELETE FROM bst_interval_dispatcher_rows WHERE snapshot_id=?",
        (snapshot_id,),
    )
    db_rows = []
    for row_index, row in enumerate(rows):
        lo = _mapping_value(row, "lo")
        hi = _mapping_value(row, "hi")
        target = _mapping_value(row, "target")
        if target is None:
            continue
        try:
            lo_i = int(lo, 0) if isinstance(lo, str) else int(lo)
            hi_i = int(hi, 0) if isinstance(hi, str) else int(hi)
            target_i = (
                int(target, 0) if isinstance(target, str) else int(target)
            )
        except (TypeError, ValueError):
            continue
        payload = {
            "lo": f"0x{lo_i:x}",
            "hi": f"0x{hi_i:x}",
            "target": target_i,
        }
        db_rows.append({
            "snapshot": int(snapshot_id),
            "row_index": int(row_index),
            "lo_hex": f"0x{lo_i:x}",
            "lo_i64": lo_i,
            "hi_hex": f"0x{hi_i:x}",
            "hi_i64": hi_i,
            "target_block": target_i,
            "dispatcher_entry_block": (
                int(dispatcher_entry_block)
                if dispatcher_entry_block is not None else None
            ),
            "maturity": maturity,
            "payload_json": _json_text(payload, {}),
        })
    db = _diag_db()
    with diag_models_on(db), db.atomic():
        if db_rows:
            BstIntervalDispatcherRow.insert_many(db_rows).execute()
    conn.commit()


def snapshot_state_dispatcher_rows(
    conn: sqlite3.Connection,
    snapshot_id: int,
    rows: Iterable[Mapping[str, Any] | object],
    *,
    dispatcher_entry_block: int | None = None,
    dispatcher_kind: str | None = None,
    maturity: str | None = None,
) -> None:
    """Persist exact state-constant dispatcher rows for a snapshot."""
    conn.execute(
        "DELETE FROM state_dispatcher_rows WHERE snapshot_id=?",
        (snapshot_id,),
    )
    db_rows = []
    for row_index, row in enumerate(rows):
        state_const = _mapping_value(row, "state_const")
        target = _mapping_value(row, "target_block")
        if target is None:
            target = _mapping_value(row, "target")
        if state_const is None or target is None:
            continue
        try:
            state_i = (
                int(state_const, 0)
                if isinstance(state_const, str) else int(state_const)
            )
            target_i = int(target, 0) if isinstance(target, str) else int(target)
        except (TypeError, ValueError):
            continue
        state_hex, state_i64 = _dual(state_i)
        row_dispatcher_entry = _mapping_value(
            row, "dispatcher_entry_block", dispatcher_entry_block
        )
        row_compare_block = _mapping_value(row, "compare_block")
        dispatcher_kind_value = _mapping_value(
            row, "dispatcher_kind",
            _mapping_value(row, "source", dispatcher_kind),
        )
        if hasattr(dispatcher_kind_value, "name"):
            dispatcher_kind_value = dispatcher_kind_value.name
        row_branch_kind = _mapping_value(row, "branch_kind")
        state_row_kind = _mapping_value(row, "row_kind")
        confidence = _mapping_value(row, "confidence", 1.0)
        payload = {
            "state_const": state_hex,
            "target": target_i,
            "compare_block": row_compare_block,
            "branch_kind": row_branch_kind,
            "dispatcher_kind": str(
                dispatcher_kind_value or dispatcher_kind or "unknown"
            ),
            "row_kind": state_row_kind,
        }
        row_payload = _mapping_value(row, "payload")
        if isinstance(row_payload, MappingABC):
            payload = {**payload, **dict(row_payload)}
        db_rows.append({
            "snapshot": int(snapshot_id),
            "row_index": int(row_index),
            "state_const_hex": state_hex,
            "state_const_i64": state_i64,
            "target_block": target_i,
            "dispatcher_entry_block": (
                int(row_dispatcher_entry)
                if row_dispatcher_entry is not None else None
            ),
            "compare_block": (
                int(row_compare_block)
                if row_compare_block is not None else None
            ),
            "dispatcher_kind": str(
                dispatcher_kind_value or dispatcher_kind or "unknown"
            ),
            "branch_kind": (
                str(row_branch_kind) if row_branch_kind is not None else None
            ),
            "maturity": maturity,
            "confidence": float(confidence),
            "payload_json": _json_text(payload, payload),
        })
    db = _diag_db()
    with diag_models_on(db), db.atomic():
        if db_rows:
            StateDispatcherRow.insert_many(db_rows).execute()
    snapshot_state_transition_dispatch_resolutions_from_latest_facts(
        conn,
        snapshot_id,
        resolution_kind="state_dispatcher_row",
        resolution_maturity=maturity,
    )
    conn.commit()


def snapshot_state_transition_dispatch_resolutions_from_latest_facts(
    conn: sqlite3.Connection,
    snapshot_id: int,
    *,
    resolution_kind: str = "state_dispatcher_row",
    resolution_maturity: str | None = None,
) -> int:
    """Persist exact dispatcher transition resolutions from DB facts.

    This is diagnostic-only glue. ``StateTransitionAnchorFact`` and
    ``StateWriteAnchorFact`` rows are already persisted in ``fact_observations``;
    when exact state-dispatcher rows land later, this composes those facts into
    ``state_transition_dispatch_resolutions`` so diagnostics can answer which
    transition facts are resolvable without requiring a separate CLI pass.
    """
    snap_row = conn.execute(
        "SELECT func_ea_hex, maturity FROM snapshots WHERE id=?",
        (int(snapshot_id),),
    ).fetchone()
    if snap_row is None:
        return 0
    func_ea_hex = str(snap_row[0])
    maturity_name = str(resolution_maturity or snap_row[1] or "unknown")
    fact_snapshot_row = conn.execute(
        """
        SELECT snapshot_id
        FROM fact_observations
        WHERE func_ea_hex=?
          AND snapshot_id <= ?
          AND kind='StateTransitionAnchorFact'
        GROUP BY snapshot_id
        ORDER BY snapshot_id DESC
        LIMIT 1
        """,
        (func_ea_hex, int(snapshot_id)),
    ).fetchone()
    if fact_snapshot_row is None:
        return 0
    fact_snapshot_id = int(fact_snapshot_row[0])

    state_to_target: dict[int, int] = {}
    dispatcher_blocks: set[int] = set()
    row_data = conn.execute(
        """
        SELECT state_const_i64, target_block, dispatcher_entry_block,
               compare_block, branch_kind
        FROM state_dispatcher_rows
        WHERE snapshot_id=?
        ORDER BY row_index
        """,
        (int(snapshot_id),),
    ).fetchall()
    for state_i64, target_block, dispatcher_entry, compare_block, branch_kind in row_data:
        state_to_target[int(state_i64) & _MASK64] = int(target_block)
        if dispatcher_entry is not None:
            dispatcher_blocks.add(int(dispatcher_entry))
        if (
            compare_block is not None
            and str(branch_kind or "") != "handler_state_map"
        ):
            dispatcher_blocks.add(int(compare_block))
    if not state_to_target:
        return 0

    write_lookup = _state_write_lookup_for_snapshot(conn, fact_snapshot_id)
    rows = []
    for fact_id, payload_json in conn.execute(
        """
        SELECT fact_id, payload
        FROM fact_observations
        WHERE snapshot_id=?
          AND kind='StateTransitionAnchorFact'
        ORDER BY fact_id
        """,
        (fact_snapshot_id,),
    ).fetchall():
        try:
            payload = json.loads(payload_json) if payload_json else {}
        except (TypeError, ValueError):
            continue
        source_block = payload.get("source_block_serial")
        source_const = _int_from_any(payload.get("source_state_const"))
        source_const_hex = payload.get("source_state_const_hex")
        successor_kind = payload.get("successor_kind")
        stkoff_key = str(payload.get("state_var_stkoff_hex", "")).lower()
        if source_block is None or source_const is None or source_const_hex is None:
            continue
        target_block: int | None = None
        next_const: int | None = None
        next_const_hex: str | None = None
        if successor_kind != "branch":
            reason = (
                f"successor_kind={successor_kind}; "
                "not a dispatcher-bound transition"
            )
        else:
            target_block = state_to_target.get(source_const & _MASK64)
            if target_block is None:
                reason = "state_not_in_dispatcher_map"
            elif target_block in dispatcher_blocks:
                reason = "target_is_dispatcher_block"
                target_block = None
            else:
                next_const = write_lookup.get((int(target_block), stkoff_key))
                if next_const is None:
                    next_const = write_lookup.get((int(target_block), ""))
                if next_const is not None:
                    next_const &= _MASK64
                    next_const_hex = f"0x{next_const:016x}"
                reason = "resolved_exact_state"
        rows.append({
            "fact_id": str(fact_id),
            "source_block_serial": int(source_block),
            "source_state_const_hex": str(source_const_hex),
            "resolved_next_block_serial": target_block,
            "resolved_next_state_const_hex": next_const_hex,
            "resolved_next_state_const_u64": next_const,
            "resolution_kind": str(resolution_kind),
            "resolution_reason": reason,
            "resolution_maturity": maturity_name,
        })
    if not rows:
        return 0
    snapshot_state_transition_dispatch_resolutions(conn, snapshot_id, rows)
    return len(rows)


def _state_write_lookup_for_snapshot(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> dict[tuple[int, str], int]:
    lookup: dict[tuple[int, str], int] = {}
    for (payload_json,) in conn.execute(
        """
        SELECT payload
        FROM fact_observations
        WHERE snapshot_id=?
          AND kind='StateWriteAnchorFact'
        """,
        (int(snapshot_id),),
    ).fetchall():
        try:
            payload = json.loads(payload_json) if payload_json else {}
        except (TypeError, ValueError):
            continue
        block_serial = _int_from_any(payload.get("block_serial"))
        state_const = _int_from_any(payload.get("state_const_u64"))
        if state_const is None:
            state_const = _int_from_any(payload.get("state_const"))
        if block_serial is None or state_const is None:
            continue
        stkoff_key = str(payload.get("state_var_stkoff_hex", "")).lower()
        lookup.setdefault((int(block_serial), stkoff_key), int(state_const))
        lookup.setdefault((int(block_serial), ""), int(state_const))
    return lookup


def _int_from_any(value: object | None) -> int | None:
    if value is None:
        return None
    try:
        if isinstance(value, str):
            return int(value, 0)
        return int(value)
    except (TypeError, ValueError):
        return None


def snapshot_state_transition_dispatch_resolutions(
    conn: sqlite3.Connection,
    snapshot_id: int,
    rows: Iterable[Mapping[str, Any] | object],
) -> None:
    """Persist generic dispatcher resolution rows for a snapshot."""
    conn.execute(
        "DELETE FROM state_transition_dispatch_resolutions WHERE snapshot_id=?",
        (snapshot_id,),
    )
    db_rows_by_key = {}
    for row in rows:
        fact_id = _mapping_value(row, "fact_id")
        source_block = _mapping_value(row, "source_block_serial")
        source_const_hex = _mapping_value(row, "source_state_const_hex")
        resolution_kind = _mapping_value(row, "resolution_kind")
        resolution_reason = _mapping_value(row, "resolution_reason")
        resolution_maturity = _mapping_value(row, "resolution_maturity")
        if (
            fact_id is None
            or source_block is None
            or source_const_hex is None
            or resolution_kind is None
            or resolution_reason is None
            or resolution_maturity is None
        ):
            continue
        db_row = {
            "snapshot": int(snapshot_id),
            "fact_id": str(fact_id),
            "source_block_serial": int(source_block),
            "source_state_const_hex": str(source_const_hex),
            "resolved_next_block_serial": _mapping_value(
                row, "resolved_next_block_serial"
            ),
            "resolved_next_state_const_hex": _mapping_value(
                row, "resolved_next_state_const_hex"
            ),
            "resolved_next_state_const_u64": _mapping_value(
                row, "resolved_next_state_const_u64"
            ),
            "resolution_kind": str(resolution_kind),
            "resolution_reason": str(resolution_reason),
            "resolution_maturity": str(resolution_maturity),
        }
        db_rows_by_key[(int(snapshot_id), str(fact_id), str(resolution_kind))] = (
            db_row
        )
    db_rows = list(db_rows_by_key.values())
    db = _diag_db()
    with diag_models_on(db), db.atomic():
        if db_rows:
            StateTransitionDispatchResolution.insert_many(db_rows).execute()
    conn.commit()


def snapshot_switch_case_transition_facts(
    conn: sqlite3.Connection,
    snapshot_id: int,
    rows: Iterable[Mapping[str, Any] | object],
) -> None:
    """Persist switch-table case transition facts for a snapshot."""
    conn.execute(
        "DELETE FROM switch_case_transition_facts WHERE snapshot_id=?",
        (snapshot_id,),
    )
    db_rows = []
    for row_index, row in enumerate(rows):
        fact_id = _mapping_value(row, "fact_id")
        transition_kind = _mapping_value(row, "transition_kind")
        reason = _mapping_value(row, "reason")
        if fact_id is None or transition_kind is None or reason is None:
            continue
        db_rows.append({
            "snapshot": int(snapshot_id),
            "row_index": int(row_index),
            "fact_id": str(fact_id),
            "source_state_hex": _mapping_value(row, "source_state_hex"),
            "source_state_i64": _mapping_value(row, "source_state_i64"),
            "case_entry_block": _mapping_value(row, "case_entry_block"),
            "transition_kind": str(transition_kind),
            "next_state_a_hex": _mapping_value(row, "next_state_a_hex"),
            "next_state_a_i64": _mapping_value(row, "next_state_a_i64"),
            "next_state_b_hex": _mapping_value(row, "next_state_b_hex"),
            "next_state_b_i64": _mapping_value(row, "next_state_b_i64"),
            "return_value": _mapping_value(row, "return_value"),
            "proof_kind": _mapping_value(row, "proof_kind"),
            "trusted": 1 if bool(_mapping_value(row, "trusted", False)) else 0,
            "reason": str(reason),
            "profile_name": _mapping_value(row, "profile_name"),
            "dispatcher_entry": _mapping_value(row, "dispatcher_entry"),
            "target_block": _mapping_value(row, "target_block"),
            "payload_json": _json_text(_mapping_value(row, "payload"), {}),
        })
    db = _diag_db()
    with diag_models_on(db), db.atomic():
        if db_rows:
            SwitchCaseTransitionFact.insert_many(db_rows).execute()
    conn.commit()


def snapshot_branch_ownership_proofs(
    conn: sqlite3.Connection,
    snapshot_id: int,
    rows: Iterable[Mapping[str, Any] | object],
) -> None:
    """Persist branch ownership proof rows for a snapshot."""
    conn.execute(
        "DELETE FROM branch_ownership_proofs WHERE snapshot_id=?",
        (snapshot_id,),
    )
    db_rows = []
    for row_index, row in enumerate(rows):
        proof_id = _mapping_value(row, "proof_id")
        proof_kind = _mapping_value(row, "proof_kind")
        reason = _mapping_value(row, "reason")
        oracle_kind = _mapping_value(row, "oracle_kind")
        if (
            proof_id is None
            or proof_kind is None
            or reason is None
            or oracle_kind is None
        ):
            continue
        source_state_hex, source_state_i64 = _dual(
            _int_from_any(_mapping_value(row, "source_state"))
        )
        target_state_hex, target_state_i64 = _dual(
            _int_from_any(_mapping_value(row, "target_state"))
        )
        db_rows.append({
            "snapshot": int(snapshot_id),
            "row_index": int(row_index),
            "proof_id": str(proof_id),
            "proof_kind": str(proof_kind),
            "trusted": 1 if bool(_mapping_value(row, "trusted", False)) else 0,
            "reason": str(reason),
            "source_block": _mapping_value(row, "source_block"),
            "branch_arm": _mapping_value(row, "branch_arm"),
            "source_state_hex": source_state_hex,
            "source_state_i64": source_state_i64,
            "target_state_hex": target_state_hex,
            "target_state_i64": target_state_i64,
            "target_entry": _mapping_value(row, "target_entry"),
            "predicate_block": _mapping_value(row, "predicate_block"),
            "dispatcher_entry_block": _mapping_value(
                row, "dispatcher_entry_block"
            ),
            "oracle_kind": str(oracle_kind),
            "evidence_json": _json_text(_mapping_value(row, "evidence"), {}),
            "payload_json": _json_text(_mapping_value(row, "payload"), {}),
        })
    db = _diag_db()
    with diag_models_on(db), db.atomic():
        if db_rows:
            BranchOwnershipProof.insert_many(db_rows).execute()
    conn.commit()


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
    db = _diag_db()
    with diag_models_on(db), db.atomic():
        WatchBlockTransition.create(
            func_ea_hex=func_hex,
            func_ea_i64=func_i64,
            apply_session_id=apply_session_id,
            mod_index=mod_index,
            mod_type=mod_type,
            phase=phase,
            block_serial=int(block_serial),
            prev_type_name=prev_type_name,
            prev_succs=(
                json.dumps(list(prev_succs)) if prev_succs is not None else None
            ),
            prev_preds=(
                json.dumps(list(prev_preds)) if prev_preds is not None else None
            ),
            now_type_name=now_type_name,
            now_succs=(
                json.dumps(list(now_succs)) if now_succs is not None else None
            ),
            now_preds=(
                json.dumps(list(now_preds)) if now_preds is not None else None
            ),
            timestamp=time.time(),
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
        rows.append({
            "snapshot": snapshot_id,
            "func_ea_hex": func_hex,
            "func_ea_i64": func_i64,
            "fact_id": str(_mapping_value(obs, "fact_id")),
            "kind": str(_mapping_value(obs, "kind")),
            "semantic_key": str(_mapping_value(obs, "semantic_key")),
            "maturity": str(_mapping_value(obs, "maturity")),
            "phase": str(_mapping_value(obs, "phase")),
            "confidence": float(_mapping_value(obs, "confidence")),
            "source_block": _mapping_value(obs, "source_block"),
            "source_ea_hex": source_ea_hex,
            "source_ea_i64": source_ea_i64,
            "block_fingerprint": _mapping_value(obs, "block_fingerprint"),
            "mop_signature": _mapping_value(obs, "mop_signature"),
            "payload": _json_text(_mapping_value(obs, "payload"), {}),
            "evidence": _json_text(_mapping_value(obs, "evidence"), []),
        })
    db = _diag_db()
    with diag_models_on(db), db.atomic():
        if rows:
            FactObservation.insert_many(rows).on_conflict("REPLACE").execute()
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
        rows.append({
            "snapshot": snapshot_id,
            "func_ea_hex": func_hex,
            "func_ea_i64": func_i64,
            "mapping_index": index,
            "source_fact_id": str(_mapping_value(mapping, "source_fact_id")),
            "target_fact_id": _mapping_value(mapping, "target_fact_id"),
            "source_maturity": str(_mapping_value(mapping, "source_maturity")),
            "target_maturity": str(_mapping_value(mapping, "target_maturity")),
            "status": str(status_text),
            "confidence": float(_mapping_value(mapping, "confidence")),
            "target_block": _mapping_value(mapping, "target_block"),
            "target_ea_hex": target_ea_hex,
            "target_ea_i64": target_ea_i64,
            "target_mop_signature": _mapping_value(
                mapping, "target_mop_signature"
            ),
            "reason": _mapping_value(mapping, "reason"),
            "payload": _json_text(_mapping_value(mapping, "payload"), {}),
        })
    db = _diag_db()
    with diag_models_on(db), db.atomic():
        if rows:
            FactMapping.insert_many(rows).on_conflict("REPLACE").execute()
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
        rows.append({
            "snapshot": snapshot_id,
            "func_ea_hex": func_hex,
            "func_ea_i64": func_i64,
            "consumer_index": index,
            "consumer": str(_mapping_value(consumer, "consumer")),
            "strategy": str(_mapping_value(consumer, "strategy")),
            "fact_id": str(_mapping_value(consumer, "fact_id")),
            "maturity": str(_mapping_value(consumer, "maturity")),
            "decision": str(_mapping_value(consumer, "decision")),
            "reason": _mapping_value(consumer, "reason"),
            "payload": _json_text(_mapping_value(consumer, "payload"), {}),
        })
    db = _diag_db()
    with diag_models_on(db), db.atomic():
        if rows:
            FactConsumer.insert_many(rows).on_conflict("REPLACE").execute()
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
        rows.append({
            "snapshot": snapshot_id,
            "func_ea_hex": func_hex,
            "func_ea_i64": func_i64,
            "conflict_id": str(_mapping_value(conflict, "conflict_id")),
            "fact_id": str(_mapping_value(conflict, "fact_id")),
            "other_fact_id": str(_mapping_value(conflict, "other_fact_id")),
            "maturity": str(_mapping_value(conflict, "maturity")),
            "conflict_kind": str(_mapping_value(conflict, "conflict_kind")),
            "reason": str(_mapping_value(conflict, "reason")),
            "payload": _json_text(_mapping_value(conflict, "payload"), {}),
        })
    db = _diag_db()
    with diag_models_on(db), db.atomic():
        if rows:
            FactConflict.insert_many(rows).on_conflict("REPLACE").execute()
    conn.commit()
