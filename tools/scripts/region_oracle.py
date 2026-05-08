#!/usr/bin/env python3
"""REF region-shape oracle CLI.

Compares D810 snapshot region-shape against REF, runs DCE cause
diagnosis for missing byte_emits, and (optionally) persists the
results to the diag DB.

Usage:
    PYTHONPATH=src python tools/scripts/region_oracle.py \\
        --db <diag.sqlite3> --snap17 17 --snap18 18 [--persist]
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from d810.cfg.ref_region_oracle import (
    D810SnapshotInputs,
    FeatureSource,
    RegionFeature,
    d810_features,
    diff_features,
    format_diff_table,
    ref_features,
)
from d810.cfg.scc import compute_live_cfg_sccs, nontrivial_sccs
from d810.cfg.terminal_tail_dce_diagnosis import (
    ByteEmitDceClassification,
    ByteEmitSnapshotEvidence,
    RecommendedAction,
    classify_all,
    format_dce_table,
    recommend_overall_action,
)
from d810.core.diag import create_tables


def _byte_emit_facts_at(conn: sqlite3.Connection, snap_id: int) -> dict[int, dict]:
    """Return byte_index -> payload (terminal_tail role preferred)."""
    out: dict[int, dict] = {}
    for (payload_json,) in conn.execute(
        "SELECT payload FROM fact_observations "
        "WHERE kind='TerminalByteEmitterFact' AND snapshot_id=? "
        "ORDER BY fact_id",
        (snap_id,),
    ):
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
        out[int(bi)] = p
    return out


def _block_at(
    conn: sqlite3.Connection, snap_id: int, ea_hex: str,
) -> tuple[int, int, int] | None:
    """Return (serial, npred, nsucc) or None for snapshot+ea."""
    row = conn.execute(
        "SELECT serial, npred, nsucc FROM blocks "
        "WHERE snapshot_id=? AND start_ea_hex=?",
        (snap_id, ea_hex),
    ).fetchone()
    if row is None:
        return None
    return int(row[0]), int(row[1] or 0), int(row[2] or 0)


def _build_snapshot_inputs(
    conn: sqlite3.Connection, snap_id: int,
) -> D810SnapshotInputs:
    """Compute D810 region-shape features from one snapshot."""
    facts = _byte_emit_facts_at(conn, snap_id)
    byte_emit_present: dict[int, bool] = {}
    byte_emit_block_serial: dict[int, int | None] = {}
    byte_emit_fact_detected: dict[int, bool] = {}
    for k in range(7):
        if k in facts:
            byte_emit_present[k] = True
            byte_emit_block_serial[k] = int(facts[k].get("block_serial", 0))
            byte_emit_fact_detected[k] = True
        else:
            byte_emit_present[k] = False
            byte_emit_block_serial[k] = None
            byte_emit_fact_detected[k] = False

    # SCC analysis on the snapshot's block graph.
    block_succs: dict[int, tuple[int, ...]] = {
        int(s): tuple(json.loads(j or "[]"))
        for s, j in conn.execute(
            "SELECT serial, succs FROM blocks WHERE snapshot_id=?",
            (snap_id,),
        )
    }
    sccs = compute_live_cfg_sccs(block_succs) if block_succs else ()
    cyclic = nontrivial_sccs(sccs) if sccs else ()
    nontrivial_count = len(cyclic)
    max_size = max((s.size for s in cyclic), default=0)

    # Max in-degree.
    in_deg: dict[int, int] = {}
    for src, succs in block_succs.items():
        for t in succs:
            in_deg[t] = in_deg.get(t, 0) + 1
    max_in_degree = max(in_deg.values(), default=0)

    head_loop_isolated = max_size <= 2 and nontrivial_count >= 1
    chunk_loop_isolated = nontrivial_count >= 2 and max_size <= 2
    terminal_tail_acyclic = max_size <= 2  # heuristic — refined later

    return D810SnapshotInputs(
        snapshot_id=snap_id,
        nontrivial_scc_count=nontrivial_count,
        max_scc_size=max_size,
        max_in_degree=max_in_degree,
        byte_emit_present=byte_emit_present,
        byte_emit_block_serial=byte_emit_block_serial,
        byte_emit_fact_detected=byte_emit_fact_detected,
        terminal_tail_acyclic=terminal_tail_acyclic,
        head_loop_isolated=head_loop_isolated,
        chunk_loop_isolated=chunk_loop_isolated,
        cleanup_blocks_present=True,  # heuristic — needs cleanup-block detection
    )


def _build_dce_evidence(
    conn: sqlite3.Connection,
    snap17_id: int,
    snap18_id: int,
    initial_snap_id: int = 5,
) -> list[ByteEmitSnapshotEvidence]:
    """Build per-byte snap17 + snap18 evidence."""
    initial_facts = _byte_emit_facts_at(conn, initial_snap_id)
    snap18_facts = _byte_emit_facts_at(conn, snap18_id)
    out: list[ByteEmitSnapshotEvidence] = []

    # SCC at snap17 to determine in_giant_scc / in_scc.
    block_succs17 = {
        int(s): tuple(json.loads(j or "[]"))
        for s, j in conn.execute(
            "SELECT serial, succs FROM blocks WHERE snapshot_id=?",
            (snap17_id,),
        )
    }
    sccs17 = compute_live_cfg_sccs(block_succs17) if block_succs17 else ()
    cyclic17 = nontrivial_sccs(sccs17) if sccs17 else ()
    block_to_scc: dict[int, int] = {}
    for s in cyclic17:
        for b in s.blocks:
            block_to_scc[b] = s.size

    snap17_byte_blocks: dict[int, str] = {}
    for k, fact in initial_facts.items():
        ea_hex = None
        block = conn.execute(
            "SELECT start_ea_hex FROM blocks WHERE snapshot_id=? AND serial=?",
            (initial_snap_id, int(fact.get("block_serial", 0))),
        ).fetchone()
        if block:
            ea_hex = block[0]
        if ea_hex:
            snap17_byte_blocks[k] = ea_hex

    for k in range(7):
        ea_hex = snap17_byte_blocks.get(k)
        snap17_info = _block_at(conn, snap17_id, ea_hex) if ea_hex else None
        snap18_info = _block_at(conn, snap18_id, ea_hex) if ea_hex else None
        if snap17_info:
            serial17, npred17, nsucc17 = snap17_info
            in_scc = serial17 in block_to_scc
            in_giant = block_to_scc.get(serial17, 0) >= 10
            unique_pred = npred17 == 1
        else:
            serial17, npred17, nsucc17 = None, None, None
            in_scc = False
            in_giant = False
            unique_pred = False

        # Heuristic placeholders — to be tightened in a follow-up.
        snap17_shares_succ = False
        snap17_dominated_by_return = False
        snap17_memory_write_dead = False
        snap18_surviving_absorbs = (
            snap18_info is None and any(b in snap18_facts for b in (1, 6))
            and k in (0, 2, 3, 4, 5)
        )

        out.append(
            ByteEmitSnapshotEvidence(
                byte_index=k,
                snap17_block_serial=serial17,
                snap17_block_ea=ea_hex,
                snap17_npred=npred17,
                snap17_nsucc=nsucc17,
                snap17_in_scc=in_scc,
                snap17_in_giant_scc=in_giant,
                snap17_unique_pred=unique_pred,
                snap17_shares_succ_with_other_byte=snap17_shares_succ,
                snap17_dominated_by_prior_return=snap17_dominated_by_return,
                snap17_memory_write_appears_dead=snap17_memory_write_dead,
                snap18_block_present=snap18_info is not None,
                snap18_fact_detected=k in snap18_facts,
                snap18_surviving_byte_absorbs=snap18_surviving_absorbs,
            )
        )
    return out


def _persist(
    conn: sqlite3.Connection,
    func_ea_hex: str,
    func_ea_i64: int,
    features: list[RegionFeature],
    classifications: tuple[ByteEmitDceClassification, ...],
) -> None:
    """Persist features + DCE causes (idempotent upsert)."""
    create_tables(conn)
    # Replace existing rows for this function.
    conn.execute(
        "DELETE FROM region_shape_features WHERE func_ea_hex=?",
        (func_ea_hex,),
    )
    for f in features:
        conn.execute(
            "INSERT INTO region_shape_features "
            "(func_ea_hex, func_ea_i64, snapshot_id, source, region, "
            " feature, value_text, evidence_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                func_ea_hex,
                func_ea_i64,
                f.snapshot_id,
                f.source.value,
                f.region.value,
                f.feature,
                str(f.value),
                json.dumps(f.evidence),
            ),
        )
    conn.execute(
        "DELETE FROM terminal_tail_dce_causes WHERE func_ea_hex=?",
        (func_ea_hex,),
    )
    for c in classifications:
        conn.execute(
            "INSERT INTO terminal_tail_dce_causes "
            "(func_ea_hex, func_ea_i64, byte_index, last_present_snapshot_id, "
            " first_missing_snapshot_id, last_block_serial, last_ea_hex, "
            " cause, recommended_action, rationale, evidence_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                func_ea_hex,
                func_ea_i64,
                c.byte_index,
                None,  # filled in by a richer extractor
                None,
                c.evidence.snap17_block_serial,
                c.evidence.snap17_block_ea,
                c.cause.value,
                c.recommended_action.value,
                c.rationale,
                json.dumps(
                    {
                        k: getattr(c.evidence, k)
                        for k in c.evidence.__slots__
                    }
                ),
            ),
        )
    conn.commit()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", required=True)
    ap.add_argument("--snap17", type=int, default=17)
    ap.add_argument("--snap18", type=int, default=18)
    ap.add_argument("--initial-snap", type=int, default=5)
    ap.add_argument("--persist", action="store_true",
                    help="Write region_shape_features + terminal_tail_dce_causes rows")
    ap.add_argument("--func-ea", default="0x0000000180012df0")
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)

    ref = list(ref_features())
    snap17_inputs = _build_snapshot_inputs(conn, args.snap17)
    snap18_inputs = _build_snapshot_inputs(conn, args.snap18)
    snap17_feats = list(d810_features(snap17_inputs))
    snap18_feats = list(d810_features(snap18_inputs))

    print("# REF region-shape oracle\n")

    print(f"\n## REF features (n={len(ref)})\n")
    for f in ref:
        print(f"- [{f.region.value}] {f.feature} = {f.value!r}")

    print(f"\n## D810 snap{args.snap17} features (last D810-controlled)\n")
    for f in snap17_feats:
        print(f"- [{f.region.value}] {f.feature} = {f.value!r}")

    print(f"\n## D810 snap{args.snap18} features (post_d810)\n")
    for f in snap18_feats:
        print(f"- [{f.region.value}] {f.feature} = {f.value!r}")

    print(f"\n## REF vs snap{args.snap17} diff\n")
    diff17 = diff_features(ref, snap17_feats)
    print(format_diff_table(diff17))

    print(f"\n## REF vs snap{args.snap18} diff\n")
    diff18 = diff_features(ref, snap18_feats)
    print(format_diff_table(diff18))

    print(f"\n## Per-byte DCE cause table (snap{args.snap17} -> snap{args.snap18})\n")
    evidences = _build_dce_evidence(conn, args.snap17, args.snap18, args.initial_snap)
    classifications = classify_all(evidences)
    print(format_dce_table(classifications))

    print("\n## Recommended overall action\n")
    action, reason = recommend_overall_action(classifications)
    print(f"- **{action.value}** — {reason}")

    if args.persist:
        all_feats = list(ref) + list(snap17_feats) + list(snap18_feats)
        _persist(conn, args.func_ea, int(args.func_ea, 16), all_feats, classifications)
        print(f"\n## Persisted {len(all_feats)} features + {len(classifications)} causes")

    return 0


if __name__ == "__main__":
    sys.exit(main())
