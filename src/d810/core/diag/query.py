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


# Hex-Rays microcode opcode numeric ids used by the diag serializer when the
# human-readable `m_<name>` form is unavailable (see mba_serializer._opcode_name).
# Keep these names in sync with ``ida_hexrays.mcode_t``.
_UND_NAMES = frozenset({"m_und", "op_61"})
_NOP_NAMES = frozenset({"m_nop", "op_1"})
_GOTO_NAMES = frozenset({"m_goto", "op_55"})
_NOP_LIKE_NAMES = _UND_NAMES | _NOP_NAMES


def _classify_block_content(insns: list[dict[str, Any]]) -> str:
    """Classify the "what's left in this block" after d810 applies.

    ``empty`` means zero recorded instructions.
    ``m_und_only`` means every instruction is ``m_und`` (dead, pending removal).
    ``nop_und_only`` means every instruction is ``m_und`` or ``m_nop``.
    ``goto_only`` means a single-instruction trampoline.
    ``has_content`` means at least one live opcode remains.

    Opcode-name matching is tolerant of both the ``m_<name>`` form and the
    numeric fallback ``op_<N>`` the diag serializer emits when symbolic
    naming is unavailable.
    """
    if not insns:
        return "empty"
    opcodes = {i["opcode_name"] for i in insns}
    if opcodes <= _UND_NAMES:
        return "m_und_only"
    if opcodes <= _NOP_LIKE_NAMES:
        return "nop_und_only"
    if len(insns) == 1 and opcodes <= _GOTO_NAMES:
        return "goto_only"
    return "has_content"


def merge_causality(
    conn: sqlite3.Connection,
    from_snapshot_id: int,
    to_snapshot_id: int,
) -> dict[str, Any]:
    """Compare two snapshots and report which FROM blocks vanished in TO.

    For each vanished block (serial in FROM but not in TO), records its
    pre-disappearance shape (``type_name``, ``preds``, ``succs``,
    ``insn_count``, ``tail_opcode``, ``content_class``) and infers its
    **absorber** in TO by finding the TO block that shares the most
    instruction EAs. Only EAs with non-zero ``ea_i64`` are used — synthesized
    instructions (ea=0) are too collision-prone to carry lineage.

    Returns a dict with ``from_snapshot_id``, ``to_snapshot_id``, block
    counts, and a ``vanished`` list sorted by vanished serial. Each
    vanished entry has an ``absorber`` dict (or ``None`` when no lineage
    can be inferred) containing the best-match TO block with the count of
    shared EAs.
    """
    conn.row_factory = _dict_factory
    from_serials = {
        r["serial"]
        for r in conn.execute(
            "SELECT serial FROM blocks WHERE snapshot_id=?", (from_snapshot_id,)
        ).fetchall()
    }
    to_serials = {
        r["serial"]
        for r in conn.execute(
            "SELECT serial FROM blocks WHERE snapshot_id=?", (to_snapshot_id,)
        ).fetchall()
    }
    vanished = sorted(from_serials - to_serials)

    vanished_rows: list[dict[str, Any]] = []
    for serial in vanished:
        blk = conn.execute(
            "SELECT * FROM blocks WHERE snapshot_id=? AND serial=?",
            (from_snapshot_id, serial),
        ).fetchone()
        if blk is None:
            continue
        preds = json.loads(blk["preds"]) if blk["preds"] else []
        succs = json.loads(blk["succs"]) if blk["succs"] else []

        insns = conn.execute(
            "SELECT ea_i64, ea_hex, opcode_name FROM instructions "
            "WHERE snapshot_id=? AND block_serial=? ORDER BY insn_index",
            (from_snapshot_id, serial),
        ).fetchall()

        tail_opcode = insns[-1]["opcode_name"] if insns else None
        content_class = _classify_block_content(insns)

        real_eas = [i["ea_i64"] for i in insns if i["ea_i64"]]
        absorber: dict[str, Any] | None = None
        if real_eas:
            placeholders = ",".join(["?"] * len(real_eas))
            top = conn.execute(
                f"SELECT block_serial, COUNT(*) AS matches FROM instructions "
                f"WHERE snapshot_id=? AND ea_i64 IN ({placeholders}) "
                f"GROUP BY block_serial ORDER BY matches DESC LIMIT 1",
                [to_snapshot_id] + real_eas,
            ).fetchone()
            if top:
                abs_serial = top["block_serial"]
                abs_total = conn.execute(
                    "SELECT insn_count, type_name FROM blocks "
                    "WHERE snapshot_id=? AND serial=?",
                    (to_snapshot_id, abs_serial),
                ).fetchone()
                absorber = {
                    "serial": abs_serial,
                    "type_name": abs_total["type_name"] if abs_total else None,
                    "matching_eas": top["matches"],
                    "absorber_insn_count": (
                        abs_total["insn_count"] if abs_total else None
                    ),
                    "vanished_real_ea_count": len(real_eas),
                }

        # Disposition classifies HOW a block vanished:
        # - ``absorbed``          : at least one real EA survived in a TO block
        # - ``deleted``           : block had real EAs but NONE survived in TO
        #                           (most likely unreachable-block removal)
        # - ``synthesized_only``  : block only had synth (ea=0) insns, so
        #                           lineage cannot be inferred either way
        if absorber is not None:
            disposition = "absorbed"
        elif real_eas:
            disposition = "deleted"
        else:
            disposition = "synthesized_only"

        vanished_rows.append(
            {
                "serial": serial,
                "type_name": blk["type_name"],
                "preds": preds,
                "succs": succs,
                "npred": blk["npred"],
                "nsucc": blk["nsucc"],
                "insn_count": blk["insn_count"],
                "tail_opcode": tail_opcode,
                "content_class": content_class,
                "disposition": disposition,
                "absorber": absorber,
                "start_ea_hex": blk["start_ea_hex"],
                "end_ea_hex": blk["end_ea_hex"],
            }
        )

    return {
        "from_snapshot_id": from_snapshot_id,
        "to_snapshot_id": to_snapshot_id,
        "from_block_count": len(from_serials),
        "to_block_count": len(to_serials),
        "vanished_count": len(vanished),
        "vanished": vanished_rows,
    }
