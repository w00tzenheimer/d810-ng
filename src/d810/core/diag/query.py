"""Query helpers for MBA diagnostic snapshots.

Pure Python + sqlite3 -- no IDA imports.
"""
from __future__ import annotations

import json
import sqlite3
from d810.core.typing import Any


def _dict_factory(cursor: sqlite3.Cursor, row: tuple) -> dict:
    """Row factory that returns dicts keyed by column name."""
    return {col[0]: row[i] for i, col in enumerate(cursor.description)}


def block_detail(
    conn: sqlite3.Connection, snapshot_id: int, serial: int
) -> dict[str, Any] | None:
    """Return full block info with instructions, parsed meta, and classification.

    Returns ``None`` if the block does not exist in the snapshot.
    """
    conn.row_factory = _dict_factory
    cur = conn.execute(
        "SELECT * FROM blocks WHERE snapshot_id=? AND serial=?",
        (snapshot_id, serial),
    )
    blk = cur.fetchone()
    if blk is None:
        return None

    # Parse JSON columns
    blk["succs"] = json.loads(blk["succs"]) if blk["succs"] else []
    blk["preds"] = json.loads(blk["preds"]) if blk["preds"] else []
    blk["meta_parsed"] = json.loads(blk["meta"]) if blk["meta"] else {}

    # Attach instructions
    cur2 = conn.execute(
        "SELECT * FROM instructions "
        "WHERE snapshot_id=? AND block_serial=? ORDER BY insn_index",
        (snapshot_id, serial),
    )
    blk["instructions"] = cur2.fetchall()

    # Attach classification (if present)
    cur3 = conn.execute(
        "SELECT * FROM block_classification "
        "WHERE snapshot_id=? AND serial=?",
        (snapshot_id, serial),
    )
    cls = cur3.fetchone()
    if cls:
        for key in ("is_bst", "is_reachable", "is_gutted", "in_claimed"):
            if key in cls:
                blk[key] = cls[key]

    return blk


def chain(
    conn: sqlite3.Connection,
    snapshot_id: int,
    serials: list[int],
) -> list[dict[str, Any]]:
    """Return block details for each serial in order, with hop status.

    For each block except the last, checks whether the *next* serial in
    ``serials`` appears in the block's successor list.  Sets ``hop_ok``
    (``True`` / ``False``) and ``expected_next`` accordingly.
    """
    results: list[dict[str, Any]] = []
    for i, serial in enumerate(serials):
        blk = block_detail(conn, snapshot_id, serial)
        if blk is not None and i < len(serials) - 1:
            expected_next = serials[i + 1]
            blk["hop_ok"] = expected_next in blk["succs"]
            blk["expected_next"] = expected_next
        results.append(blk)
    return results


def var_writes(
    conn: sqlite3.Connection,
    snapshot_id: int,
    stkoff: int,
) -> list[dict[str, Any]]:
    """Return all instructions that write to a given stack offset.

    Queries instructions where ``dest_stkoff == stkoff`` (i.e. dest is a
    stack variable at the given offset).
    """
    conn.row_factory = _dict_factory
    cur = conn.execute(
        "SELECT i.*, b.start_ea_hex AS block_start_ea_hex "
        "FROM instructions i "
        "LEFT JOIN blocks b "
        "  ON b.snapshot_id=i.snapshot_id AND b.serial=i.block_serial "
        "WHERE i.snapshot_id=? AND i.dest_stkoff=? "
        "ORDER BY i.block_serial, i.insn_index",
        (snapshot_id, stkoff),
    )
    return cur.fetchall()


def return_paths(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> list[dict[str, Any]]:
    """Return all CONDITIONAL_RETURN edges with per-hop analysis.

    For each CONDITIONAL_RETURN edge, parses the ``ordered_path`` and walks
    each block looking for writes to stkoff ``0x7F0`` (the return slot).
    Returns per-hop info including ``serial``, ``has_return_slot_write``,
    and ``write_opcode``.
    """
    conn.row_factory = _dict_factory
    cur = conn.execute(
        "SELECT * FROM dag_edges "
        "WHERE snapshot_id=? AND edge_kind='CONDITIONAL_RETURN'",
        (snapshot_id,),
    )
    edges = cur.fetchall()

    results: list[dict[str, Any]] = []
    for edge in edges:
        path_serials: list[int] = json.loads(edge["ordered_path"])
        hops: list[dict[str, Any]] = []
        for serial in path_serials:
            hop: dict[str, Any] = {"serial": serial}
            # Check if this block has an instruction writing to 0x7F0
            insn_cur = conn.execute(
                "SELECT opcode_name FROM instructions "
                "WHERE snapshot_id=? AND block_serial=? AND dest_stkoff=?",
                (snapshot_id, serial, 0x7F0),
            )
            write_row = insn_cur.fetchone()
            if write_row:
                hop["has_return_slot_write"] = True
                hop["write_opcode"] = write_row["opcode_name"]
            else:
                hop["has_return_slot_write"] = False
                hop["write_opcode"] = None
            hops.append(hop)

        results.append({
            "edge_id": edge["edge_id"],
            "source_state": edge["source_state_hex"],
            "target_state": edge["target_state_hex"],
            "path_serials": path_serials,
            "hops": hops,
        })
    return results


def rendered_program_text(
    conn: sqlite3.Connection,
    snapshot_id: int,
    variant_name: str,
) -> str | None:
    """Return the exact rendered program text for one stored variant."""
    cur = conn.execute(
        "SELECT text FROM rendered_program_lines "
        "WHERE snapshot_id=? AND variant_name=? ORDER BY line_no",
        (snapshot_id, variant_name),
    )
    rows = cur.fetchall()
    if not rows:
        return None
    texts = [row[0] if not isinstance(row, dict) else row["text"] for row in rows]
    return "\n".join(texts)


def rendered_program_nodes(
    conn: sqlite3.Connection,
    snapshot_id: int,
    variant_name: str,
) -> list[dict[str, Any]]:
    """Return rendered label blocks for one stored program variant."""
    conn.row_factory = _dict_factory
    cur = conn.execute(
        "SELECT * FROM rendered_program_nodes "
        "WHERE snapshot_id=? AND variant_name=? ORDER BY node_index",
        (snapshot_id, variant_name),
    )
    return cur.fetchall()


def rendered_program_variants(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> list[dict[str, Any]]:
    """Return stored rendered-program variants for a snapshot."""
    conn.row_factory = _dict_factory
    cur = conn.execute(
        "SELECT * FROM rendered_programs WHERE snapshot_id=? ORDER BY variant_name",
        (snapshot_id,),
    )
    return cur.fetchall()


def _fact_rows(
    conn: sqlite3.Connection,
    table: str,
    snapshot_id: int | None,
    *,
    filters: dict[str, Any] | None = None,
    order_by: str,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Query one fact lifecycle table with exact-match filters."""
    conn.row_factory = _dict_factory
    clauses: list[str] = []
    params: list[Any] = []
    if snapshot_id is not None:
        clauses.append("snapshot_id=?")
        params.append(snapshot_id)
    for column, value in (filters or {}).items():
        if value is None:
            continue
        clauses.append(f"{column}=?")
        params.append(value)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"SELECT * FROM {table}{where} ORDER BY snapshot_id, {order_by}"
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
    cur = conn.execute(sql, params)
    return cur.fetchall()


def fact_observations(
    conn: sqlite3.Connection,
    snapshot_id: int | None,
    *,
    fact_id: str | None = None,
    kind: str | None = None,
    semantic_key: str | None = None,
    maturity: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Return maturity fact observations for one snapshot."""
    return _fact_rows(
        conn,
        "fact_observations",
        snapshot_id,
        filters={
            "fact_id": fact_id,
            "kind": kind,
            "semantic_key": semantic_key,
            "maturity": maturity,
        },
        order_by="kind, semantic_key, fact_id",
        limit=limit,
    )


def fact_mappings(
    conn: sqlite3.Connection,
    snapshot_id: int | None,
    *,
    source_fact_id: str | None = None,
    status: str | None = None,
    source_maturity: str | None = None,
    target_maturity: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Return fact lifecycle mappings for one snapshot."""
    return _fact_rows(
        conn,
        "fact_mappings",
        snapshot_id,
        filters={
            "source_fact_id": source_fact_id,
            "status": status,
            "source_maturity": source_maturity,
            "target_maturity": target_maturity,
        },
        order_by="mapping_index",
        limit=limit,
    )


def fact_consumers(
    conn: sqlite3.Connection,
    snapshot_id: int | None,
    *,
    consumer: str | None = None,
    strategy: str | None = None,
    fact_id: str | None = None,
    decision: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Return strategy fact-consumer decisions for one snapshot."""
    return _fact_rows(
        conn,
        "fact_consumers",
        snapshot_id,
        filters={
            "consumer": consumer,
            "strategy": strategy,
            "fact_id": fact_id,
            "decision": decision,
        },
        order_by="consumer_index",
        limit=limit,
    )


def fact_conflicts(
    conn: sqlite3.Connection,
    snapshot_id: int | None,
    *,
    fact_id: str | None = None,
    conflict_kind: str | None = None,
    maturity: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Return fact conflicts for one snapshot."""
    return _fact_rows(
        conn,
        "fact_conflicts",
        snapshot_id,
        filters={
            "fact_id": fact_id,
            "conflict_kind": conflict_kind,
            "maturity": maturity,
        },
        order_by="conflict_kind, conflict_id",
        limit=limit,
    )


def fact_trace(
    conn: sqlite3.Connection,
    *,
    semantic_key: str,
    kind: str | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Return observations and mappings for one semantic fact key."""
    conn.row_factory = _dict_factory
    clauses = ["semantic_key=?"]
    params: list[Any] = [semantic_key]
    if kind is not None:
        clauses.append("kind=?")
        params.append(kind)
    observations = conn.execute(
        "SELECT * FROM fact_observations "
        f"WHERE {' AND '.join(clauses)} "
        "ORDER BY snapshot_id, maturity, fact_id",
        params,
    ).fetchall()
    observations_by_fact_key = {
        (row["func_ea_hex"], row["fact_id"]): row
        for row in observations
    }
    fact_ids = sorted({row["fact_id"] for row in observations})
    func_eas = sorted({row["func_ea_hex"] for row in observations})
    mappings: list[dict[str, Any]] = []
    if fact_ids:
        placeholders = ",".join("?" for _ in fact_ids)
        func_placeholders = ",".join("?" for _ in func_eas)
        mappings = conn.execute(
            "SELECT * FROM fact_mappings "
            f"WHERE source_fact_id IN ({placeholders}) "
            f"AND func_ea_hex IN ({func_placeholders}) "
            "ORDER BY snapshot_id, target_maturity, source_fact_id, status",
            (*fact_ids, *func_eas),
        ).fetchall()
        for mapping in mappings:
            source = observations_by_fact_key.get((
                mapping["func_ea_hex"],
                mapping["source_fact_id"],
            ))
            if source is None:
                continue
            mapping["source_block"] = source["source_block"]
            mapping["source_ea_hex"] = source["source_ea_hex"]
            mapping["semantic_key"] = source["semantic_key"]
            mapping["kind"] = source["kind"]
    return {"observations": observations, "mappings": mappings}


def fact_diff(
    conn: sqlite3.Connection,
    *,
    source_maturity: str,
    target_maturity: str,
    kind: str | None = None,
    semantic_key: str | None = None,
) -> list[dict[str, Any]]:
    """Compare fact observations from one maturity to a later maturity.

    The diff is intentionally table-driven: mappings produced by the lifecycle
    engine determine REMAPPED/IDENTITY_LOST/etc.; same fact ids observed at the
    target maturity are reported ACTIVE; otherwise the row is CARRIED_FORWARD
    because no target-maturity mapping invalidated the source fact.
    """
    conn.row_factory = _dict_factory
    clauses = ["maturity=?"]
    params: list[Any] = [source_maturity]
    if kind is not None:
        clauses.append("kind=?")
        params.append(kind)
    if semantic_key is not None:
        clauses.append("semantic_key=?")
        params.append(semantic_key)
    source_rows = conn.execute(
        "SELECT * FROM fact_observations "
        f"WHERE {' AND '.join(clauses)} "
        "ORDER BY snapshot_id, kind, semantic_key, fact_id",
        params,
    ).fetchall()
    if not source_rows:
        return []

    source_fact_ids = sorted({row["fact_id"] for row in source_rows})
    source_funcs = sorted({row["func_ea_hex"] for row in source_rows})
    fact_placeholders = ",".join("?" for _ in source_fact_ids)
    func_placeholders = ",".join("?" for _ in source_funcs)
    mapping_rows = conn.execute(
        "SELECT * FROM fact_mappings "
        f"WHERE source_fact_id IN ({fact_placeholders}) "
        f"AND func_ea_hex IN ({func_placeholders}) "
        "AND target_maturity=? "
        "ORDER BY snapshot_id, source_fact_id, status",
        (*source_fact_ids, *source_funcs, target_maturity),
    ).fetchall()
    mappings_by_source: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in mapping_rows:
        key = (row["func_ea_hex"], row["source_fact_id"])
        mappings_by_source.setdefault(key, []).append(row)

    target_clauses = [
        "maturity=?",
        f"func_ea_hex IN ({func_placeholders})",
        f"fact_id IN ({fact_placeholders})",
    ]
    target_params: list[Any] = [target_maturity, *source_funcs, *source_fact_ids]
    if kind is not None:
        target_clauses.append("kind=?")
        target_params.append(kind)
    if semantic_key is not None:
        target_clauses.append("semantic_key=?")
        target_params.append(semantic_key)
    target_rows = conn.execute(
        "SELECT func_ea_hex, fact_id FROM fact_observations "
        f"WHERE {' AND '.join(target_clauses)}",
        target_params,
    ).fetchall()
    target_fact_keys = {
        (row["func_ea_hex"], row["fact_id"])
        for row in target_rows
    }

    result: list[dict[str, Any]] = []
    for source in source_rows:
        source_key = (source["func_ea_hex"], source["fact_id"])
        mappings = mappings_by_source.get(source_key, [])
        if mappings:
            for mapping in mappings:
                result.append({
                    "source_fact_id": source["fact_id"],
                    "target_fact_id": mapping["target_fact_id"],
                    "kind": source["kind"],
                    "semantic_key": source["semantic_key"],
                    "source_maturity": source_maturity,
                    "target_maturity": target_maturity,
                    "status": mapping["status"],
                    "source_block": source["source_block"],
                    "source_ea_hex": source["source_ea_hex"],
                    "target_block": mapping["target_block"],
                    "target_ea_hex": mapping["target_ea_hex"],
                    "source_snapshot_id": source["snapshot_id"],
                    "mapping_snapshot_id": mapping["snapshot_id"],
                    "reason": mapping["reason"],
                })
            continue
        status = (
            "ACTIVE"
            if source_key in target_fact_keys
            else "CARRIED_FORWARD"
        )
        result.append({
            "source_fact_id": source["fact_id"],
            "target_fact_id": source["fact_id"] if status == "ACTIVE" else None,
            "kind": source["kind"],
            "semantic_key": source["semantic_key"],
            "source_maturity": source_maturity,
            "target_maturity": target_maturity,
            "status": status,
            "source_block": source["source_block"],
            "source_ea_hex": source["source_ea_hex"],
            "target_block": source["source_block"] if status == "ACTIVE" else None,
            "target_ea_hex": source["source_ea_hex"] if status == "ACTIVE" else None,
            "source_snapshot_id": source["snapshot_id"],
            "mapping_snapshot_id": None,
            "reason": None,
        })
    return result
