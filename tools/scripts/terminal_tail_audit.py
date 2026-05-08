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

from d810.cfg.terminal_tail_loss_localizer import (
    ByteEmitInitialState,
    format_localization_report,
    localize_byte_emit_loss,
)
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


def _build_initial_states_at_snap(
    conn: sqlite3.Connection, snap_id: int,
) -> list[ByteEmitInitialState]:
    """Read TerminalByteEmitterFact at ``snap_id`` and pair each byte_index
    with the corresponding block's start_ea_hex."""
    out: dict[int, ByteEmitInitialState] = {}
    rows = conn.execute(
        "SELECT payload FROM fact_observations "
        "WHERE kind='TerminalByteEmitterFact' AND snapshot_id=?",
        (snap_id,),
    ).fetchall()
    for (payload_json,) in rows:
        try:
            p = json.loads(payload_json or "{}")
        except json.JSONDecodeError:
            continue
        bi = p.get("byte_index")
        if bi is None:
            continue
        role = p.get("corridor_role", "")
        if int(bi) in out and "terminal_tail" not in role:
            continue
        block_serial = int(p.get("block_serial", -1))
        if block_serial < 0:
            continue
        block = conn.execute(
            "SELECT start_ea_hex FROM blocks WHERE snapshot_id=? AND serial=?",
            (snap_id, block_serial),
        ).fetchone()
        if not block:
            continue
        out[int(bi)] = ByteEmitInitialState(
            byte_index=int(bi),
            snapshot_id=int(snap_id),
            block_serial=block_serial,
            start_ea_hex=block[0],
        )
    return list(out.values())


def _build_block_lookup(
    conn: sqlite3.Connection, snap_ids: list[int],
) -> dict[tuple[int, str], tuple[int, int, int, int]]:
    """Build (snapshot_id, start_ea_hex) -> (serial, npred, nsucc, insn_count)
    over the given snapshots."""
    if not snap_ids:
        return {}
    placeholders = ",".join("?" for _ in snap_ids)
    rows = conn.execute(
        f"SELECT snapshot_id, start_ea_hex, serial, npred, nsucc, insn_count "
        f"FROM blocks WHERE snapshot_id IN ({placeholders})",
        snap_ids,
    ).fetchall()
    out: dict[tuple[int, str], tuple[int, int, int, int]] = {}
    for snap_id, start_ea, serial, npred, nsucc, insn_count in rows:
        if start_ea is None:
            continue
        out[(int(snap_id), start_ea)] = (
            int(serial), int(npred or 0), int(nsucc or 0), int(insn_count or 0),
        )
    return out


def _glbopt1_snapshots(
    conn: sqlite3.Connection,
) -> list[tuple[int, str, str]]:
    """Chronological (id, label, phase) for GLBOPT1 snapshots that have
    block data captured. Skips snapshots with no block rows (e.g., the
    intermediate ``state_write_reconstruction_dag`` snapshots that
    only record DAG state, not blocks) and ``dump_raw_*`` post-hoc
    snapshots whose ids are out of sequence."""
    rows = conn.execute(
        """
        SELECT s.id, s.label, s.phase
        FROM snapshots s
        WHERE s.maturity='MMAT_GLBOPT1'
          AND s.label NOT LIKE 'dump_raw_%'
          AND EXISTS (
            SELECT 1 FROM blocks b WHERE b.snapshot_id=s.id LIMIT 1
          )
        ORDER BY s.id
        """,
    ).fetchall()
    return [(int(s), str(label), str(phase)) for s, label, phase in rows]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", required=True, help="Path to diag .sqlite3")
    ap.add_argument(
        "--show-edges", action="store_true",
        help="Print every observation with full payload",
    )
    ap.add_argument(
        "--localize", action="store_true",
        help="Run intermediate-snapshot loss localization (GLBOPT1 only)",
    )
    ap.add_argument(
        "--initial-snap-id", type=int, default=5,
        help="Snapshot id of the initial pre-D810 state (default 5)",
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

    if args.localize:
        print()
        initial_states = _build_initial_states_at_snap(conn, args.initial_snap_id)
        snapshots = _glbopt1_snapshots(conn)
        snap_ids = [s for s, _, _ in snapshots]
        block_lookup = _build_block_lookup(conn, snap_ids)
        # Build fact_lookup: which (snapshot_id, byte_index) pairs have a
        # TerminalByteEmitterFact captured at that snapshot.
        fact_lookup: dict[tuple[int, int], bool] = {}
        for snap_id, payload_json in conn.execute(
            f"SELECT snapshot_id, payload FROM fact_observations "
            f"WHERE kind='TerminalByteEmitterFact' "
            f"AND snapshot_id IN ({','.join('?' for _ in snap_ids)})",
            snap_ids,
        ):
            try:
                p = json.loads(payload_json or "{}")
            except json.JSONDecodeError:
                continue
            bi = p.get("byte_index")
            if bi is None:
                continue
            fact_lookup[(int(snap_id), int(bi))] = True

        loc_report = localize_byte_emit_loss(
            initial_states, snapshots, block_lookup, fact_lookup,
        )
        print(format_localization_report(loc_report))

    return 0


if __name__ == "__main__":
    sys.exit(main())
