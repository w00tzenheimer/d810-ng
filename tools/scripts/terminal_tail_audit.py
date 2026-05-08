#!/usr/bin/env python3
"""Terminal-tail region matcher CLI (read-only).

Reads ``TerminalByteEmitterFact`` rows from a diag DB and produces the
byte_emit[k] timeline + first-loss report described in the
``terminal_tail_region_matcher`` module docstring.

Usage:
    PYTHONPATH=src python tools/scripts/terminal_tail_audit.py \\
        --db .tmp/logs/d810_logs/<func>.diag.sqlite3
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from d810.cfg.terminal_tail_region_matcher import (
    ByteEmitObservation,
    _classify_source_form,
    aggregate_byte_emit_timeline,
    format_report,
)


def _iter_observations(
    conn: sqlite3.Connection,
) -> list[ByteEmitObservation]:
    rows = conn.execute(
        """
        SELECT
            f.snapshot_id,
            f.maturity,
            f.phase,
            COALESCE(s.label, '') AS label,
            f.payload
        FROM fact_observations f
        LEFT JOIN snapshots s ON s.id = f.snapshot_id
        WHERE f.kind='TerminalByteEmitterFact'
        ORDER BY f.snapshot_id, f.fact_id
        """
    ).fetchall()
    out: list[ByteEmitObservation] = []
    for snap_id, maturity, phase, label, payload_json in rows:
        try:
            payload = json.loads(payload_json or "{}")
        except json.JSONDecodeError:
            continue
        byte_index = payload.get("byte_index")
        if byte_index is None:
            continue
        block_serial = int(
            payload.get("block_serial") or payload.get("source_block") or -1
        )
        if block_serial < 0:
            continue
        source_expr = payload.get("source_byte_expression") or ""
        source_form = _classify_source_form(source_expr, int(byte_index))
        out.append(
            ByteEmitObservation(
                snapshot_id=int(snap_id),
                maturity=str(maturity or ""),
                phase=str(phase or ""),
                label=str(label or ""),
                block_serial=block_serial,
                byte_index=int(byte_index),
                corridor_role=str(payload.get("corridor_role", "")),
                counter_carrier=payload.get("counter_carrier"),
                source_form=source_form,
                destination_present=bool(
                    payload.get("destination_buffer_expression")
                ),
                counter_update_present=bool(payload.get("counter_carrier")),
                block_ea_hex=payload.get("block_ea_hex"),
            )
        )
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", required=True, help="Path to diag .sqlite3")
    ap.add_argument(
        "--show-edges", action="store_true",
        help="Print every observation with full payload",
    )
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    observations = _iter_observations(conn)

    if not observations:
        print(f"# No TerminalByteEmitterFact rows in {args.db}")
        return 0

    report = aggregate_byte_emit_timeline(observations)
    print(format_report(report))

    if args.show_edges:
        print()
        print("## Per-observation detail")
        for obs in sorted(
            observations,
            key=lambda o: (o.snapshot_id, o.byte_index, o.block_serial),
        ):
            print(
                f"  snap={obs.snapshot_id:3d} {obs.maturity}/{obs.phase:<10s} "
                f"byte={obs.byte_index} blk={obs.block_serial:3d} "
                f"role={obs.corridor_role} src_form={obs.source_form.value}"
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
