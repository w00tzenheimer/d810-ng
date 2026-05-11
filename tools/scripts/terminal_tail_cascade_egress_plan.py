#!/usr/bin/env python3
"""Build a read-only terminal-tail cascade egress plan from a diag DB.

.. deprecated:: 2026-05-11
    Prefer ``python -m d810.diagnostics cascade-egress-plan`` or
    ``./tools/cff_debug.py egress-plan``. This script is kept as a
    compatibility wrapper; the orchestration + SQL logic now lives at
    ``src/d810/diagnostics/cascade_egress_plan.py`` with unit tests under
    ``tests/unit/diagnostics/test_cascade_egress_plan.py``. The cfg-layer
    planner in ``d810.cfg.terminal_tail_cascade_egress_planner`` is
    unchanged.

The planner resolves ``TerminalByteEmitterFact`` rows from an earlier
fact snapshot into a target CFG snapshot, usually ``post_bundle_stabilize``
(snap17 in the sub7FFD traces), and reports whether each byte tail can
be redirected into a REF-like acyclic cascade.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from d810.cfg.terminal_tail_cascade_egress_planner import (
    TerminalTailBlock,
    TerminalTailCascadeEgressPlanner,
    format_cascade_egress_plan,
    terminal_byte_emit_site_from_payload,
)
from d810.core.typing import Optional


def _json_int_tuple(value: Optional[str]) -> tuple[int, ...]:
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


def _choose_fact_snapshot(conn: sqlite3.Connection) -> int:
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
        raise SystemExit("no TerminalByteEmitterFact rows found")
    return int(row[0])


def _choose_target_snapshot(conn: sqlite3.Connection) -> int:
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
        raise SystemExit("no target CFG snapshot found")
    return int(row[0])


def _load_blocks(
    conn: sqlite3.Connection, snapshot_id: int,
) -> dict[int, TerminalTailBlock]:
    rows = conn.execute(
        """
        SELECT serial, type_name, start_ea_hex, succs, preds
        FROM blocks
        WHERE snapshot_id=?
        ORDER BY serial
        """,
        (snapshot_id,),
    ).fetchall()
    op_rows = conn.execute(
        """
        SELECT block_serial, opcode_name, COALESCE(dstr, '')
        FROM instructions
        WHERE snapshot_id=?
        ORDER BY block_serial, insn_index
        """,
        (snapshot_id,),
    ).fetchall()
    opcodes_by_block: dict[int, list[str]] = {}
    text_by_block: dict[int, list[str]] = {}
    for block_serial, opcode, dstr in op_rows:
        serial = int(block_serial)
        opcodes_by_block.setdefault(serial, []).append(str(opcode or ""))
        text_by_block.setdefault(serial, []).append(str(dstr or ""))

    blocks: dict[int, TerminalTailBlock] = {}
    for serial, type_name, start_ea_hex, succs, preds in rows:
        block_serial = int(serial)
        blocks[block_serial] = TerminalTailBlock(
            serial=block_serial,
            succs=_json_int_tuple(succs),
            preds=_json_int_tuple(preds),
            type_name=str(type_name or ""),
            start_ea_hex=start_ea_hex,
            insn_opcodes=tuple(opcodes_by_block.get(block_serial, ())),
            insn_text=tuple(text_by_block.get(block_serial, ())),
        )
    return blocks


def _load_sites(
    conn: sqlite3.Connection, snapshot_id: int,
):
    rows = conn.execute(
        """
        SELECT fact_id, payload, source_ea_hex, confidence
        FROM fact_observations
        WHERE snapshot_id=? AND kind='TerminalByteEmitterFact'
        ORDER BY fact_id
        """,
        (snapshot_id,),
    ).fetchall()
    sites = []
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", required=True, help="Path to diag .sqlite3")
    ap.add_argument(
        "--fact-snapshot-id",
        type=int,
        help="Snapshot containing TerminalByteEmitterFact rows",
    )
    ap.add_argument(
        "--target-snapshot-id",
        type=int,
        help="CFG snapshot to evaluate, usually post_bundle_stabilize",
    )
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    fact_snapshot_id = args.fact_snapshot_id or _choose_fact_snapshot(conn)
    target_snapshot_id = args.target_snapshot_id or _choose_target_snapshot(conn)
    blocks = _load_blocks(conn, target_snapshot_id)
    sites = _load_sites(conn, fact_snapshot_id)
    plan = TerminalTailCascadeEgressPlanner(blocks, sites).build_plan()

    print(f"# fact snapshot: {fact_snapshot_id}")
    print(f"# target snapshot: {target_snapshot_id}")
    print(format_cascade_egress_plan(plan))
    return 0


if __name__ == "__main__":
    sys.exit(main())
