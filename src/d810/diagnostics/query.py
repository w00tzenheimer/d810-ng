"""Query helpers for MBA diagnostic snapshots.

Pure Python + sqlite3 -- no IDA imports.
"""
from __future__ import annotations

import json
import sqlite3

from d810._vendor.peewee import fn
from d810.core.diag.models import (
    Instruction,
    RenderedProgramLine,
    StateCfgEdge,
)
from d810.core.typing import Any


def _dict_factory(cursor: sqlite3.Cursor, row: tuple) -> dict:
    """Row factory that returns dicts keyed by column name."""
    return {col[0]: row[i] for i, col in enumerate(cursor.description)}


def _reset_row_factory(conn: sqlite3.Connection) -> None:
    """Restore peewee's expected positional row handling.

    The raw-SQL readers in this module set ``conn.row_factory =
    _dict_factory`` on the shared diag connection. peewee's ORM cursor
    wrappers require the default (``None``) row factory, so every ORM
    reader resets it first; the diag CLI interleaves both styles on one
    connection.
    """
    conn.row_factory = None  # type: ignore[assignment]


def block_detail(
    conn: sqlite3.Connection, snapshot_id: int, serial: int
) -> dict[str, Any] | None:
    """Return full block info with instructions, parsed meta, and classification.

    Returns ``None`` if the block does not exist in the snapshot.
    """
    # raw-SQL: SELECT * with arbitrary name-based column access (this
    # function returns the whole block row as a dict and then mutates it);
    # a column-pinned ORM projection would couple it to the Block field set
    # (§3 complex-SQL policy). Same rationale for the instructions /
    # block_classification SELECT * reads below.
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
    # raw-SQL: SELECT i.* LEFT JOIN blocks with an aliased extra column
    # (block_start_ea_hex), returned verbatim as dicts; a star-join with a
    # joined alias is clearer as SQL (§3 complex-SQL policy).
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
    _reset_row_factory(conn)
    edges = list(
        StateCfgEdge.select()
        .where(
            (StateCfgEdge.snapshot == snapshot_id)
            & (StateCfgEdge.edge_kind == "CONDITIONAL_RETURN")
        )
        .dicts()
    )

    results: list[dict[str, Any]] = []
    for edge in edges:
        path_serials: list[int] = json.loads(edge["ordered_path"])
        hops: list[dict[str, Any]] = []
        for serial in path_serials:
            hop: dict[str, Any] = {"serial": serial}
            # Check if this block has an instruction writing to 0x7F0
            write_row = (
                Instruction.select(Instruction.opcode_name)
                .where(
                    (Instruction.snapshot == snapshot_id)
                    & (Instruction.block_serial == serial)
                    & (Instruction.dest_stkoff == 0x7F0)
                )
                .tuples()
                .first()
            )
            if write_row:
                hop["has_return_slot_write"] = True
                hop["write_opcode"] = write_row[0]
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
    _reset_row_factory(conn)
    rows = list(
        RenderedProgramLine.select(RenderedProgramLine.text)
        .where(
            (RenderedProgramLine.snapshot_id == snapshot_id)
            & (RenderedProgramLine.variant_name == variant_name)
        )
        .order_by(RenderedProgramLine.line_no)
        .tuples()
    )
    if not rows:
        return None
    return "\n".join(row[0] for row in rows)


def rendered_program_nodes(
    conn: sqlite3.Connection,
    snapshot_id: int,
    variant_name: str,
) -> list[dict[str, Any]]:
    """Return rendered label blocks for one stored program variant."""
    # raw-SQL: SELECT * returned verbatim as dicts (§3 complex-SQL policy).
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
    # raw-SQL: SELECT * returned verbatim as dicts (§3 complex-SQL policy).
    conn.row_factory = _dict_factory
    cur = conn.execute(
        "SELECT * FROM rendered_programs WHERE snapshot_id=? ORDER BY variant_name",
        (snapshot_id,),
    )
    return cur.fetchall()


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    # raw-SQL: sqlite_master schema probe -- peewee does not model the
    # system catalog; the back-compat readers in this module test optional
    # table presence on older diag DBs (§3 complex-SQL policy).
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _state_hex(value: int) -> str:
    return f"0x{int(value) & 0xFFFFFFFFFFFFFFFF:016x}"


def _state_i64(value: int) -> int:
    value = int(value)
    if value > 0x7FFFFFFFFFFFFFFF:
        return value - (1 << 64)
    return value


def _unique(values: list[Any]) -> list[Any]:
    """Return values in first-seen order, dropping duplicates and ``None``."""
    out: list[Any] = []
    seen: set[Any] = set()
    for value in values:
        if value is None or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _ea_hex_candidates(ea: int) -> list[str]:
    """Return likely persisted spellings for an EA value."""
    value = int(ea)
    masked = value & 0xFFFFFFFFFFFFFFFF
    candidates = [
        f"0x{masked:x}",
        f"0x{masked:X}",
        f"0x{masked:016x}",
        f"0x{masked:016X}",
    ]
    if masked <= 0xFFFFFFFF:
        candidates.extend((f"0x{masked:08x}", f"0x{masked:08X}"))
    return _unique(candidates)


def _placeholders(values: list[Any]) -> str:
    return ",".join("?" for _ in values)


def _observation_select(where_sql: str) -> str:
    # raw-SQL: dynamic-WHERE LEFT JOIN (block_observations + snapshots +
    # blocks) with aliased columns, reused by several callers with
    # different predicates; a hand-built JOIN+alias projection is clearer
    # as SQL (§3 complex-SQL policy).
    return (
        "SELECT bo.snapshot_id, s.label AS snapshot_label, "
        "       bo.serial, bo.maturity, bo.phase, "
        "       bo.start_ea_hex, bo.start_ea_i64, "
        "       b.end_ea_hex, b.end_ea_i64, b.type_name, b.succs, b.preds, "
        "       bo.insn_count, bo.insn_ea_fingerprint, "
        "       bo.opcode_fingerprint, bo.operand_fingerprint, "
        "       bo.body_fingerprint "
        "FROM block_observations bo "
        "LEFT JOIN snapshots s ON s.id = bo.snapshot_id "
        "LEFT JOIN blocks b "
        "  ON b.snapshot_id = bo.snapshot_id AND b.serial = bo.serial "
        f"WHERE {where_sql} "
        "ORDER BY bo.snapshot_id, bo.serial"
    )


def _mark_rows(rows: list[dict[str, Any]], source: str, match_kind: str) -> None:
    for row in rows:
        row["source"] = source
        row.setdefault("match_kind", match_kind)


def _observation_by_serial(
    conn: sqlite3.Connection,
    snapshot_id: int,
    serial: int,
) -> dict[str, Any] | None:
    if not _table_exists(conn, "block_observations"):
        return None
    conn.row_factory = _dict_factory
    row = conn.execute(
        _observation_select("bo.snapshot_id=? AND bo.serial=?"),
        (snapshot_id, serial),
    ).fetchone()
    if row is not None:
        row["source"] = "block_observations"
        row["match_kind"] = "anchor"
    return row


def _observations_by_ea(
    conn: sqlite3.Connection,
    ea: int,
) -> list[dict[str, Any]]:
    if not _table_exists(conn, "block_observations"):
        return []
    conn.row_factory = _dict_factory
    hexes = _ea_hex_candidates(ea)
    rows = conn.execute(
        _observation_select(
            f"bo.start_ea_i64=? OR bo.start_ea_hex IN ({_placeholders(hexes)})"
        ),
        (_state_i64(ea), *hexes),
    ).fetchall()
    _mark_rows(rows, "block_observations", "start_ea")
    return rows


def _observation_correlations(
    conn: sqlite3.Connection,
    anchor: dict[str, Any],
) -> list[dict[str, Any]]:
    clauses = ["(bo.snapshot_id=? AND bo.serial=?)"]
    params: list[Any] = [anchor["snapshot_id"], anchor["serial"]]
    start_ea_i64 = anchor.get("start_ea_i64")
    start_ea_hex = anchor.get("start_ea_hex")
    body_fp = anchor.get("body_fingerprint")
    if start_ea_i64 is not None:
        clauses.append("bo.start_ea_i64=?")
        params.append(start_ea_i64)
    elif start_ea_hex:
        clauses.append("bo.start_ea_hex=?")
        params.append(start_ea_hex)
    if body_fp:
        clauses.append("bo.body_fingerprint=?")
        params.append(body_fp)

    conn.row_factory = _dict_factory
    rows = conn.execute(
        _observation_select(" OR ".join(clauses)),
        params,
    ).fetchall()
    for row in rows:
        row["source"] = "block_observations"
        if (
            row["snapshot_id"] == anchor["snapshot_id"]
            and row["serial"] == anchor["serial"]
        ):
            row["match_kind"] = "anchor"
            continue
        same_start = (
            start_ea_i64 is not None and row.get("start_ea_i64") == start_ea_i64
        ) or (
            start_ea_i64 is None
            and start_ea_hex is not None
            and row.get("start_ea_hex") == start_ea_hex
        )
        same_body = bool(body_fp and row.get("body_fingerprint") == body_fp)
        if same_start and same_body:
            row["match_kind"] = "same_start_ea+same_body"
        elif same_start:
            row["match_kind"] = "same_start_ea"
        elif same_body:
            row["match_kind"] = "same_body"
        else:
            row["match_kind"] = "related"
    return rows


def _basic_block_select(where_sql: str) -> str:
    # raw-SQL: dynamic-WHERE LEFT JOIN (blocks + snapshots) with aliased
    # columns, reused with different predicates (§3 complex-SQL policy).
    return (
        "SELECT b.snapshot_id, s.label AS snapshot_label, "
        "       s.maturity, s.phase, b.serial, b.start_ea_hex, "
        "       b.start_ea_i64, b.end_ea_hex, b.end_ea_i64, "
        "       b.type_name, b.succs, b.preds, b.insn_count "
        "FROM blocks b "
        "LEFT JOIN snapshots s ON s.id = b.snapshot_id "
        f"WHERE {where_sql} "
        "ORDER BY b.snapshot_id, b.serial"
    )


def _basic_block_by_serial(
    conn: sqlite3.Connection,
    snapshot_id: int,
    serial: int,
) -> dict[str, Any] | None:
    if not _table_exists(conn, "blocks"):
        return None
    conn.row_factory = _dict_factory
    row = conn.execute(
        _basic_block_select("b.snapshot_id=? AND b.serial=?"),
        (snapshot_id, serial),
    ).fetchone()
    if row is not None:
        row["source"] = "blocks"
        row["match_kind"] = "anchor"
    return row


def _fallback_block_rows_by_ea(
    conn: sqlite3.Connection,
    ea: int,
) -> list[dict[str, Any]]:
    if not _table_exists(conn, "blocks"):
        return []
    conn.row_factory = _dict_factory
    ea_i64 = _state_i64(ea)
    hexes = _ea_hex_candidates(ea)
    rows = conn.execute(
        _basic_block_select(
            "b.start_ea_i64=? "
            f"OR b.start_ea_hex IN ({_placeholders(hexes)}) "
            "OR (b.start_ea_i64 IS NOT NULL AND b.end_ea_i64 IS NOT NULL "
            "    AND ? >= b.start_ea_i64 AND ? < b.end_ea_i64)"
        ),
        (ea_i64, *hexes, ea_i64, ea_i64),
    ).fetchall()
    for row in rows:
        row["source"] = "blocks"
        start_match = (
            row.get("start_ea_i64") == ea_i64
            or row.get("start_ea_hex") in hexes
        )
        row["match_kind"] = "start_ea" if start_match else "range_contains"
    return rows


def _fallback_instruction_rows_by_ea(
    conn: sqlite3.Connection,
    ea: int,
) -> list[dict[str, Any]]:
    if not _table_exists(conn, "instructions"):
        return []
    # raw-SQL: COUNT(*) + GROUP_CONCAT aggregate over a LEFT JOIN, grouped
    # per (snapshot, block), with an EA-spelling IN-list (§3 complex-SQL).
    conn.row_factory = _dict_factory
    hexes = _ea_hex_candidates(ea)
    rows = conn.execute(
        "SELECT i.snapshot_id, s.label AS snapshot_label, "
        "       s.maturity, s.phase, i.block_serial AS serial, "
        "       b.start_ea_hex, b.start_ea_i64, b.end_ea_hex, b.end_ea_i64, "
        "       b.type_name, b.succs, b.preds, b.insn_count, "
        "       COUNT(*) AS matching_eas, "
        "       GROUP_CONCAT(i.insn_index) AS matching_insn_indexes "
        "FROM instructions i "
        "LEFT JOIN snapshots s ON s.id = i.snapshot_id "
        "LEFT JOIN blocks b "
        "  ON b.snapshot_id = i.snapshot_id AND b.serial = i.block_serial "
        f"WHERE i.ea_i64=? OR i.ea_hex IN ({_placeholders(hexes)}) "
        "GROUP BY i.snapshot_id, i.block_serial "
        "ORDER BY i.snapshot_id, i.block_serial",
        (_state_i64(ea), *hexes),
    ).fetchall()
    _mark_rows(rows, "instructions", "instruction_ea")
    return rows


def _real_instruction_eas(
    conn: sqlite3.Connection,
    snapshot_id: int,
    serial: int,
) -> list[int]:
    if not _table_exists(conn, "instructions"):
        return []
    _reset_row_factory(conn)
    rows = (
        Instruction.select(Instruction.ea_i64)
        .where(
            (Instruction.snapshot == snapshot_id)
            & (Instruction.block_serial == serial)
            & Instruction.ea_i64.is_null(False)
            & (Instruction.ea_i64 != 0)
        )
        .distinct()
        .order_by(Instruction.ea_i64)
        .tuples()
    )
    return [int(row[0]) for row in rows]


def _fallback_instruction_correlations(
    conn: sqlite3.Connection,
    eas: list[int],
) -> list[dict[str, Any]]:
    if not eas or not _table_exists(conn, "instructions"):
        return []
    # raw-SQL: COUNT(DISTINCT ea_i64) aggregate over a LEFT JOIN, grouped
    # per (snapshot, block), with a shared-EA IN-list (§3 complex-SQL).
    conn.row_factory = _dict_factory
    ea_values = _unique([int(ea) for ea in eas if ea])
    rows = conn.execute(
        "SELECT i.snapshot_id, s.label AS snapshot_label, "
        "       s.maturity, s.phase, i.block_serial AS serial, "
        "       b.start_ea_hex, b.start_ea_i64, b.end_ea_hex, b.end_ea_i64, "
        "       b.type_name, b.succs, b.preds, b.insn_count, "
        "       COUNT(DISTINCT i.ea_i64) AS matching_eas "
        "FROM instructions i "
        "LEFT JOIN snapshots s ON s.id = i.snapshot_id "
        "LEFT JOIN blocks b "
        "  ON b.snapshot_id = i.snapshot_id AND b.serial = i.block_serial "
        f"WHERE i.ea_i64 IN ({_placeholders(ea_values)}) "
        "GROUP BY i.snapshot_id, i.block_serial "
        "ORDER BY i.snapshot_id, i.block_serial",
        ea_values,
    ).fetchall()
    _mark_rows(rows, "instructions", "shared_instruction_ea")
    return rows


def block_trace_by_ea(conn: sqlite3.Connection, ea: int) -> dict[str, Any]:
    """Trace all blocks whose observation/start/range/instruction EA matches.

    New databases are queried via ``block_observations`` first.  Older
    databases fall back to ``blocks`` start/range data, then instruction EAs.
    EA-only traces intentionally return all matches and set ``ambiguous`` when
    more than one row matches the same EA.
    """
    messages: list[str] = []
    source = "block_observations"
    if _table_exists(conn, "block_observations"):
        matches = _observations_by_ea(conn, ea)
        if matches:
            return {
                "mode": "ea",
                "ea": int(ea),
                "source": source,
                "messages": messages,
                "ambiguous": len(matches) > 1,
                "matches": matches,
            }
        messages.append(
            "block_observations has no matching rows; falling back to blocks"
        )
    else:
        messages.append(
            "block_observations table not available; falling back to blocks"
        )

    matches = _fallback_block_rows_by_ea(conn, ea)
    source = "blocks"
    if not matches:
        messages.append("blocks had no matching start/range rows; trying instructions")
        matches = _fallback_instruction_rows_by_ea(conn, ea)
        source = "instructions"

    return {
        "mode": "ea",
        "ea": int(ea),
        "source": source,
        "messages": messages,
        "ambiguous": len(matches) > 1,
        "matches": matches,
    }


def block_trace_by_serial(
    conn: sqlite3.Connection,
    snapshot_id: int,
    serial: int,
) -> dict[str, Any]:
    """Trace a block identity from one ``(snapshot_id, serial)`` anchor."""
    messages: list[str] = []
    if _table_exists(conn, "block_observations"):
        anchor = _observation_by_serial(conn, snapshot_id, serial)
        if anchor is not None:
            matches = _observation_correlations(conn, anchor)
            return {
                "mode": "serial",
                "snapshot_id": int(snapshot_id),
                "serial": int(serial),
                "source": "block_observations",
                "messages": messages,
                "anchor": anchor,
                "matches": matches,
                "ambiguous": False,
            }
        messages.append(
            "block_observations has no row for the requested block; "
            "falling back to blocks/instructions"
        )
    else:
        messages.append(
            "block_observations table not available; "
            "falling back to blocks/instructions"
        )

    anchor = _basic_block_by_serial(conn, snapshot_id, serial)
    if anchor is None:
        messages.append("requested block was not found in blocks")
        return {
            "mode": "serial",
            "snapshot_id": int(snapshot_id),
            "serial": int(serial),
            "source": "blocks",
            "messages": messages,
            "anchor": None,
            "matches": [],
            "ambiguous": False,
        }

    real_eas = _real_instruction_eas(conn, snapshot_id, serial)
    matches = _fallback_instruction_correlations(conn, real_eas)
    source = "instructions" if matches else "blocks"
    if not matches and anchor.get("start_ea_i64") is not None:
        matches = _fallback_block_rows_by_ea(conn, int(anchor["start_ea_i64"]))
        source = "blocks"
    if not matches:
        matches = [anchor]

    return {
        "mode": "serial",
        "snapshot_id": int(snapshot_id),
        "serial": int(serial),
        "source": source,
        "messages": messages,
        "anchor": anchor,
        "matches": matches,
        "ambiguous": False,
    }


def _lineage_rows(
    conn: sqlite3.Connection,
    where_sql: str,
    params: list[Any],
) -> list[dict[str, Any]]:
    # raw-SQL: dynamic-WHERE LEFT JOIN (block_lineage + snapshots), reused
    # by direct/origin/child lineage callers (§3 complex-SQL policy).
    conn.row_factory = _dict_factory
    return conn.execute(
        "SELECT bl.snapshot_id, s.label AS snapshot_label, bl.serial, "
        "       bl.origin_snapshot_id, bl.origin_serial, "
        "       bl.origin_start_ea_hex, bl.origin_body_fingerprint, "
        "       bl.creation_kind, bl.creation_reason, bl.planner_block_id, "
        "       bl.source_mod_type, bl.extra_json "
        "FROM block_lineage bl "
        "LEFT JOIN snapshots s ON s.id = bl.snapshot_id "
        f"WHERE {where_sql} "
        "ORDER BY bl.snapshot_id, bl.serial",
        params,
    ).fetchall()


def _cfg_provenance_rows(
    conn: sqlite3.Connection,
    snapshot_id: int,
    serial: int,
) -> list[dict[str, Any]]:
    if not _table_exists(conn, "cfg_provenance"):
        return []
    # raw-SQL: SELECT * returned verbatim as dicts (§3 complex-SQL policy).
    conn.row_factory = _dict_factory
    return conn.execute(
        "SELECT * FROM cfg_provenance "
        "WHERE snapshot_id=? AND (block_serial=? OR target_serial=?) "
        "ORDER BY seq",
        (snapshot_id, serial, serial),
    ).fetchall()


def block_lineage(
    conn: sqlite3.Connection,
    snapshot_id: int,
    serial: int,
) -> dict[str, Any]:
    """Return direct lineage plus provenance fallback for one block."""
    messages: list[str] = []
    observation = (
        _observation_by_serial(conn, snapshot_id, serial)
        if _table_exists(conn, "block_observations")
        else None
    )
    if observation is None:
        observation = _basic_block_by_serial(conn, snapshot_id, serial)

    lineage: list[dict[str, Any]] = []
    origins: list[dict[str, Any]] = []
    children: list[dict[str, Any]] = []
    if _table_exists(conn, "block_lineage"):
        lineage = _lineage_rows(
            conn,
            "bl.snapshot_id=? AND bl.serial=?",
            [snapshot_id, serial],
        )
        if not lineage:
            messages.append(
                "block_lineage has no direct row for the requested block; "
                "checking cfg_provenance fallback"
            )
        for row in lineage:
            origin_snapshot = row.get("origin_snapshot_id")
            origin_serial = row.get("origin_serial")
            if origin_snapshot is None or origin_serial is None:
                continue
            origin = (
                _observation_by_serial(conn, int(origin_snapshot), int(origin_serial))
                if _table_exists(conn, "block_observations")
                else None
            )
            if origin is None:
                origin = _basic_block_by_serial(
                    conn, int(origin_snapshot), int(origin_serial)
                )
            if origin is not None:
                origins.append(origin)

        child_clauses = ["(bl.origin_snapshot_id=? AND bl.origin_serial=?)"]
        child_params: list[Any] = [snapshot_id, serial]
        if observation is not None and observation.get("start_ea_hex"):
            child_clauses.append("bl.origin_start_ea_hex=?")
            child_params.append(observation["start_ea_hex"])
        if observation is not None and observation.get("body_fingerprint"):
            child_clauses.append("bl.origin_body_fingerprint=?")
            child_params.append(observation["body_fingerprint"])
        children = _lineage_rows(
            conn,
            " OR ".join(child_clauses),
            child_params,
        )
        children = [
            row for row in children
            if not (
                row["snapshot_id"] == snapshot_id
                and row["serial"] == serial
            )
        ]
    else:
        messages.append(
            "block_lineage table not available; using cfg_provenance fallback"
        )

    provenance = _cfg_provenance_rows(conn, snapshot_id, serial)
    if not provenance and not lineage:
        if _table_exists(conn, "cfg_provenance"):
            messages.append("cfg_provenance has no rows for the requested block")
        else:
            messages.append("cfg_provenance table not available")

    return {
        "snapshot_id": int(snapshot_id),
        "serial": int(serial),
        "observation": observation,
        "lineage": lineage,
        "origins": origins,
        "children": children,
        "provenance": provenance,
        "messages": messages,
        "lineage_available": _table_exists(conn, "block_lineage"),
        "provenance_available": _table_exists(conn, "cfg_provenance"),
    }


def state_local(
    conn: sqlite3.Connection,
    snapshot_id: int,
    state: int,
) -> dict[str, Any] | None:
    """Return typed state-local DAG facts for one state.

    The returned dict is built from ``state_cfg_nodes`` plus the optional
    ``state_cfg_node_blocks``, ``state_cfg_local_segments``, and ``state_cfg_local_edges`` tables.
    Old databases that lack the typed local tables return the basic node row
    with ``local_facts_available=False`` instead of raising.
    """
    # raw-SQL: this function joins a SELECT * node row with three optional
    # typed-local tables via multi-spelling state_hex IN-lists + entry_block
    # filters and returns SELECT * rows verbatim as dicts; the dynamic
    # multi-table assembly is clearer as SQL (§3 complex-SQL policy).
    conn.row_factory = _dict_factory
    state_value = int(state)
    fixed_hex = _state_hex(state_value)
    fixed_hex_upper = fixed_hex.upper().replace("X", "x")
    short_hex = f"0x{state_value & 0xFFFFFFFF:08x}"
    short_hex_upper = short_hex.upper().replace("X", "x")
    cur = conn.execute(
        "SELECT * FROM state_cfg_nodes "
        "WHERE snapshot_id=? AND (state_hex IN (?, ?, ?, ?) OR state_i64=?) "
        "ORDER BY entry_block LIMIT 1",
        (
            snapshot_id,
            fixed_hex,
            fixed_hex_upper,
            short_hex,
            short_hex_upper,
            _state_i64(state_value),
        ),
    )
    node = cur.fetchone()
    if node is None:
        return None

    required_tables = (
        "state_cfg_node_blocks",
        "state_cfg_local_segments",
        "state_cfg_local_edges",
    )
    table_presence = {
        table: _table_exists(conn, table)
        for table in required_tables
    }
    tables_available = all(table_presence.values())
    result: dict[str, Any] = {
        "node": node,
        "blocks_by_role": {},
        "segments": [],
        "local_edges": [],
        "local_facts_available": False,
        "missing_tables": [
            table for table, present in table_presence.items() if not present
        ],
    }
    if not tables_available:
        return result

    entry_block = int(node["entry_block"])
    state_hexes = tuple(dict.fromkeys((
        node["state_hex"],
        fixed_hex,
        fixed_hex_upper,
        short_hex,
        short_hex_upper,
    )))
    state_hex_placeholders = ",".join("?" for _ in state_hexes)

    blocks_by_role: dict[str, list[int]] = {
        "owned": [],
        "exclusive": [],
        "shared_suffix": [],
    }
    block_rows = conn.execute(
        "SELECT role, block_serial FROM state_cfg_node_blocks "
        f"WHERE snapshot_id=? AND state_hex IN ({state_hex_placeholders}) "
        "AND entry_block=? "
        "ORDER BY role, block_index",
        (snapshot_id, *state_hexes, entry_block),
    ).fetchall()
    for row in block_rows:
        blocks_by_role.setdefault(row["role"], []).append(int(row["block_serial"]))

    segment_rows = conn.execute(
        "SELECT segment_id, kind, blocks_json FROM state_cfg_local_segments "
        f"WHERE snapshot_id=? AND state_hex IN ({state_hex_placeholders}) "
        "AND entry_block=? "
        "ORDER BY segment_index",
        (snapshot_id, *state_hexes, entry_block),
    ).fetchall()
    segments = []
    for row in segment_rows:
        segment = dict(row)
        try:
            segment["blocks"] = json.loads(segment.pop("blocks_json") or "[]")
        except json.JSONDecodeError:
            segment["blocks"] = []
        segments.append(segment)

    local_edges = conn.execute(
        "SELECT source_segment_id, target_segment_id, kind, branch_arm "
        "FROM state_cfg_local_edges "
        f"WHERE snapshot_id=? AND state_hex IN ({state_hex_placeholders}) "
        "AND entry_block=? "
        "ORDER BY edge_index",
        (snapshot_id, *state_hexes, entry_block),
    ).fetchall()

    result["blocks_by_role"] = blocks_by_role
    result["segments"] = segments
    result["local_edges"] = local_edges
    result["local_facts_available"] = bool(
        block_rows or segment_rows or local_edges
    )
    return result


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
    # raw-SQL: cross-snapshot block-vanish/absorber inference -- SELECT *
    # block rows, instruction EA scans, and a COUNT(*) GROUP BY ORDER BY
    # DESC LIMIT 1 best-shared-EA aggregate over an EA IN-list; the
    # aggregate correlation is clearer as SQL (§3 complex-SQL policy).
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
    # raw-SQL: generic dynamic-WHERE SELECT * over a runtime-chosen fact
    # table (table name + optional filters), returned verbatim as dicts;
    # the dynamic table + predicate set is clearer as SQL (§3 policy).
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
    # raw-SQL: dynamic-WHERE SELECT * over fact_observations + a follow-up
    # fact_mappings SELECT * gated by two computed IN-lists (fact ids +
    # func eas), returned verbatim as dicts (§3 complex-SQL policy).
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
    # raw-SQL: three dynamic-WHERE SELECT * passes (source observations,
    # target-maturity mappings, target observations) correlated through
    # computed fact-id/func-ea IN-lists; the multi-pass dynamic correlation
    # is clearer as SQL (§3 complex-SQL policy).
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
