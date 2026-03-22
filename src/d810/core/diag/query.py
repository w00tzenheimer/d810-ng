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
        "SELECT * FROM instructions "
        "WHERE snapshot_id=? AND dest_stkoff=? "
        "ORDER BY block_serial, insn_index",
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
            "source_state": edge["source_state"],
            "target_state": edge["target_state"],
            "path_serials": path_serials,
            "hops": hops,
        })
    return results
