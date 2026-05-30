"""Cascade-egress-plan -- read-only "can the byte tail be rewired?" report.

Reads ``TerminalByteEmitterFact`` rows from a captured diag SQLite + a
target CFG snapshot (usually ``post_bundle_stabilize`` / snap17) and asks
the planner in :mod:`d810.transforms.terminal_tail_cascade_egress_planner`
whether each byte tail can be redirected into a REF-like acyclic cascade.

Pure-Python orchestrator with no d810 runtime imports beyond the cfg-layer
planner that already owns the report shape.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from d810.transforms.terminal_tail_cascade_egress_planner import (
    TerminalByteEmitSite,
    TerminalTailBlock,
    TerminalTailCascadeEgressPlanner,
    format_cascade_egress_plan,
    terminal_byte_emit_site_from_payload,
)


# ---------------------------------------------------------------------------
# Helpers (pure)
# ---------------------------------------------------------------------------


def _json_int_tuple(value: str | None) -> tuple[int, ...]:
    """Parse a JSON-encoded int list from the diag DB, defaulting to ``()``."""
    try:
        parsed = json.loads(value or "[]")
    except json.JSONDecodeError:
        return ()
    if not isinstance(parsed, list):
        return ()
    out: list[int] = []
    for item in parsed:
        try:
            out.append(int(item))
        except (TypeError, ValueError):
            continue
    return tuple(out)


def choose_fact_snapshot(conn: sqlite3.Connection) -> int:
    """Pick the snapshot that holds the ``TerminalByteEmitterFact`` rows.

    Preference order:

    1. Most recent ``MMAT_GLBOPT1 / pre_d810`` snapshot with at least one
       ``TerminalByteEmitterFact`` row -- this is the recon collector's
       expected fire site.
    2. Fall back to the most recent snapshot of any maturity / phase that
       has TerminalByteEmitterFact rows.

    Raises :class:`LookupError` when no fact rows exist at all (callers
    surface this as a CLI error rather than crashing the parser).
    """
    row = conn.execute(
        """
        SELECT f.snapshot_id
        FROM fact_observations f
        JOIN snapshots s ON s.id=f.snapshot_id
        WHERE f.kind='TerminalByteEmitterFact'
          AND s.maturity='MMAT_GLBOPT1'
          AND s.phase='pre_d810'
        GROUP BY f.snapshot_id
        ORDER BY f.snapshot_id DESC
        LIMIT 1
        """
    ).fetchone()
    if row is None:
        row = conn.execute(
            """
            SELECT snapshot_id
            FROM fact_observations
            WHERE kind='TerminalByteEmitterFact'
            GROUP BY snapshot_id
            ORDER BY snapshot_id DESC
            LIMIT 1
            """
        ).fetchone()
    if row is None:
        raise LookupError("no TerminalByteEmitterFact rows found")
    return int(row[0])


def choose_target_snapshot(conn: sqlite3.Connection) -> int:
    """Pick the CFG snapshot to evaluate.

    Preference order:

    1. Most recent ``post_bundle_stabilize`` snapshot with block data
       captured -- the natural rewire target (snap17 in sub_7FFD).
    2. Most recent ``MMAT_GLBOPT1`` non-``post_d810`` non-``dump_raw_*``
       snapshot that has block rows.

    Raises :class:`LookupError` when no candidate exists.
    """
    row = conn.execute(
        """
        SELECT s.id
        FROM snapshots s
        WHERE s.label='post_bundle_stabilize'
          AND EXISTS (SELECT 1 FROM blocks b WHERE b.snapshot_id=s.id LIMIT 1)
        ORDER BY s.id DESC
        LIMIT 1
        """
    ).fetchone()
    if row is None:
        row = conn.execute(
            """
            SELECT s.id
            FROM snapshots s
            WHERE s.maturity='MMAT_GLBOPT1'
              AND s.phase!='post_d810'
              AND s.label NOT LIKE 'dump_raw_%'
              AND EXISTS (SELECT 1 FROM blocks b WHERE b.snapshot_id=s.id LIMIT 1)
            ORDER BY s.id DESC
            LIMIT 1
            """
        ).fetchone()
    if row is None:
        raise LookupError("no target CFG snapshot found")
    return int(row[0])


def load_blocks(
    conn: sqlite3.Connection, snapshot_id: int,
) -> dict[int, TerminalTailBlock]:
    """Build the planner-shaped block map for *snapshot_id*."""
    rows = conn.execute(
        "SELECT serial, type_name, start_ea_hex, succs, preds"
        " FROM blocks WHERE snapshot_id=? ORDER BY serial",
        (snapshot_id,),
    ).fetchall()
    op_rows = conn.execute(
        "SELECT block_serial, opcode_name, COALESCE(dstr, '')"
        " FROM instructions WHERE snapshot_id=? ORDER BY block_serial, insn_index",
        (snapshot_id,),
    ).fetchall()
    opcodes_by_block: dict[int, list[str]] = {}
    text_by_block: dict[int, list[str]] = {}
    for block_serial, opcode, dstr in op_rows:
        s = int(block_serial)
        opcodes_by_block.setdefault(s, []).append(str(opcode or ""))
        text_by_block.setdefault(s, []).append(str(dstr or ""))
    blocks: dict[int, TerminalTailBlock] = {}
    for serial, type_name, start_ea_hex, succs, preds in rows:
        s = int(serial)
        blocks[s] = TerminalTailBlock(
            serial=s,
            succs=_json_int_tuple(succs),
            preds=_json_int_tuple(preds),
            type_name=str(type_name or ""),
            start_ea_hex=start_ea_hex,
            insn_opcodes=tuple(opcodes_by_block.get(s, ())),
            insn_text=tuple(text_by_block.get(s, ())),
        )
    return blocks


def load_sites(
    conn: sqlite3.Connection, snapshot_id: int,
) -> list[TerminalByteEmitSite]:
    """Adapt ``TerminalByteEmitterFact`` payloads at *snapshot_id* into
    planner-shaped :class:`TerminalByteEmitSite` rows.

    Malformed payloads and non-dict rows are silently skipped so the
    planner only ever sees well-formed input.
    """
    rows = conn.execute(
        "SELECT fact_id, payload, source_ea_hex, confidence"
        " FROM fact_observations"
        " WHERE snapshot_id=? AND kind='TerminalByteEmitterFact'"
        " ORDER BY fact_id",
        (snapshot_id,),
    ).fetchall()
    sites: list[TerminalByteEmitSite] = []
    for fact_id, payload_json, source_ea_hex, confidence in rows:
        try:
            payload = json.loads(payload_json or "{}")
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        site = terminal_byte_emit_site_from_payload(
            str(fact_id),
            payload,
            source_ea_hex=source_ea_hex,
            confidence=float(confidence or 0.0),
        )
        if site is not None:
            sites.append(site)
    return sites


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run_plan(
    db_path: Path,
    *,
    fact_snapshot_id: int | None = None,
    target_snapshot_id: int | None = None,
) -> str:
    """Render the cascade-egress plan for *db_path*.

    Returns the text the legacy script produced (two ``# fact /
    target snapshot:`` header lines followed by the cfg-layer's
    ``format_cascade_egress_plan`` body). Missing fact rows or absent
    target snapshots yield a single ``Error:``-prefixed line so the CLI
    can return a non-zero exit code without raising.
    """
    if not db_path.exists():
        return f"Error: diag DB not found: {db_path}\n"
    conn = sqlite3.connect(str(db_path))
    try:
        try:
            fact_id = (
                int(fact_snapshot_id)
                if fact_snapshot_id is not None
                else choose_fact_snapshot(conn)
            )
            target_id = (
                int(target_snapshot_id)
                if target_snapshot_id is not None
                else choose_target_snapshot(conn)
            )
        except LookupError as exc:
            return f"Error: {exc}\n"
        blocks = load_blocks(conn, target_id)
        sites = load_sites(conn, fact_id)
    finally:
        conn.close()
    plan = TerminalTailCascadeEgressPlanner(blocks, sites).build_plan()
    return (
        f"# fact snapshot: {fact_id}\n"
        f"# target snapshot: {target_id}\n"
        + format_cascade_egress_plan(plan)
        + "\n"
    )
