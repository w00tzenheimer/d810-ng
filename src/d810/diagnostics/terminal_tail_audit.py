"""Terminal-tail region audit -- post-hoc diag DB consumer.

Reads ``TerminalByteEmitterFact`` rows from a captured diag SQLite and
produces the byte_emit[k] timeline + first-loss report from
:mod:`d810.cfg.terminal_tail_region_matcher` and
:mod:`d810.cfg.terminal_tail_loss_localizer`.

This module is the **post-hoc** side of the byte-cascade observability
stack: the recon collector writes ``TerminalByteEmitterFact`` rows during
decompile, and this module reads + summarises them after the fact. The
core report logic lives in ``d810.cfg.*`` because it is also consumed
during the in-flight reconstruction path; this module is the thin SQL
layer that feeds those report functions.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

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
from d810.core.typing import Iterable


def iter_observations(conn: sqlite3.Connection) -> list[ByteEmitObservation]:
    """Pull every ``TerminalByteEmitterFact`` row, sorted by (snap, fact_id).

    Snapshots without a ``snapshots`` row are tolerated (LEFT JOIN); the
    label simply renders as the empty string. Payloads that fail to parse
    or that lack a ``byte_index`` are skipped silently -- the report logic
    expects only well-formed observations.
    """
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


def build_initial_states_at_snap(
    conn: sqlite3.Connection, snap_id: int,
) -> list[ByteEmitInitialState]:
    """Read ``TerminalByteEmitterFact`` at *snap_id* and pair each byte
    index with the block's ``start_ea_hex``.

    Prefers ``terminal_tail`` corridor-role observations when multiple
    facts target the same byte index.
    """
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


def build_block_lookup(
    conn: sqlite3.Connection, snap_ids: Iterable[int],
) -> dict[tuple[int, str], tuple[int, int, int, int]]:
    """``(snapshot_id, start_ea_hex) -> (serial, npred, nsucc, insn_count)``.

    Empty input returns ``{}`` so callers can pass arbitrary iterables
    without an explicit guard.
    """
    ids = list(snap_ids)
    if not ids:
        return {}
    placeholders = ",".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT snapshot_id, start_ea_hex, serial, npred, nsucc, insn_count "
        f"FROM blocks WHERE snapshot_id IN ({placeholders})",
        ids,
    ).fetchall()
    out: dict[tuple[int, str], tuple[int, int, int, int]] = {}
    for snap_id, start_ea, serial, npred, nsucc, insn_count in rows:
        if start_ea is None:
            continue
        out[(int(snap_id), start_ea)] = (
            int(serial), int(npred or 0), int(nsucc or 0), int(insn_count or 0),
        )
    return out


def glbopt1_snapshots(
    conn: sqlite3.Connection,
) -> list[tuple[int, str, str]]:
    """Chronological ``(id, label, phase)`` for GLBOPT1 snapshots with
    block data captured.

    Skips snapshots whose ``blocks`` table is empty (e.g. intermediate
    ``state_write_reconstruction_dag`` rows that only capture DAG state)
    and ``dump_raw_*`` post-hoc snapshots whose ids are out of sequence.
    """
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


def build_fact_lookup(
    conn: sqlite3.Connection, snap_ids: Iterable[int],
) -> dict[tuple[int, int], bool]:
    """Which ``(snapshot_id, byte_index)`` pairs have a fact captured.

    Used by the loss-localizer to distinguish "byte block lost from CFG"
    from "byte block still present but fact was not re-captured".
    """
    ids = list(snap_ids)
    if not ids:
        return {}
    placeholders = ",".join("?" for _ in ids)
    out: dict[tuple[int, int], bool] = {}
    for snap_id, payload_json in conn.execute(
        f"SELECT snapshot_id, payload FROM fact_observations "
        f"WHERE kind='TerminalByteEmitterFact' "
        f"AND snapshot_id IN ({placeholders})",
        ids,
    ):
        try:
            p = json.loads(payload_json or "{}")
        except json.JSONDecodeError:
            continue
        bi = p.get("byte_index")
        if bi is None:
            continue
        out[(int(snap_id), int(bi))] = True
    return out


def run_audit(
    db_path: Path,
    *,
    show_edges: bool = False,
    localize: bool = False,
    initial_snap_id: int = 5,
) -> str:
    """Render the full terminal-tail audit text for *db_path*.

    Returns the formatted report; missing-fact cases yield a one-line
    explanation rather than raising, so the CLI can produce stable output.
    """
    conn = sqlite3.connect(str(db_path))
    try:
        observations = iter_observations(conn)
        if not observations:
            return f"# No TerminalByteEmitterFact rows in {db_path}\n"
        report = aggregate_byte_emit_timeline(observations)
        pieces = [format_report(report)]
        if show_edges:
            pieces.append("")
            pieces.append("## Per-observation detail")
            for obs in sorted(
                observations,
                key=lambda o: (o.snapshot_id, o.byte_index, o.block_serial),
            ):
                pieces.append(
                    f"  snap={obs.snapshot_id:3d} {obs.maturity}/{obs.phase:<10s} "
                    f"byte={obs.byte_index} blk={obs.block_serial:3d} "
                    f"role={obs.corridor_role} src_form={obs.source_form.value}"
                )
        if localize:
            initial_states = build_initial_states_at_snap(conn, initial_snap_id)
            snapshots = glbopt1_snapshots(conn)
            snap_ids = [s for s, _, _ in snapshots]
            block_lookup = build_block_lookup(conn, snap_ids)
            fact_lookup = build_fact_lookup(conn, snap_ids)
            loc_report = localize_byte_emit_loss(
                initial_states, snapshots, block_lookup, fact_lookup,
            )
            pieces.append("")
            pieces.append(format_localization_report(loc_report))
        return "\n".join(pieces) + "\n"
    finally:
        conn.close()
