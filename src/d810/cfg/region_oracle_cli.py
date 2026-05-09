"""CLI handler for `python -m d810.core.diag region-diff`.

Lives in d810.cfg because the layered-architecture contract forbids
d810.core.diag from importing d810.cfg. The diag CLI dispatches here
via importlib.import_module(...). The handler is injected with the
core/diag helpers it needs (resolver + persistence) so this module
does NOT static-import them.
"""
from __future__ import annotations

import dataclasses
import json
import sqlite3
import sys
from pathlib import Path

from d810.cfg.ref_region_oracle import (
    BlockView,
    D810SnapshotInputs,
    FeatureRegion,
    FeatureSource,
    RegionFeature,
    _normalize_func_ea_hex,
    build_d810_evidence,
    collect_block_views_for_snapshot,
    d810_features,
    diff_features,
    ref_features,
    spec_for,
)
from d810.cfg.scc import compute_live_cfg_sccs, nontrivial_sccs
from d810.cfg.terminal_tail_dce_diagnosis import (
    ByteEmitSnapshotEvidence,
    classify_all,
    format_dce_table,
    recommend_overall_action,
)


def register_region_diff_parser(sub, common) -> None:
    p = sub.add_parser(
        "region-diff",
        parents=[common],
        help=(
            "Recompute REF vs snap17/snap18 region diff and (optionally) "
            "persist scoped feature + DCE-cause rows."
        ),
    )
    p.add_argument("--func-ea", default=None)
    p.add_argument("--auto", action="store_true")
    p.add_argument("--persist", action="store_true")
    p.add_argument("--snap17", type=int, default=None)
    p.add_argument("--snap18", type=int, default=None)
    p.add_argument("--snap17-label", default=None)
    p.add_argument("--snap18-label", default=None)
    p.add_argument("--output", default=None)
    p.add_argument("--microblocks", action="store_true")
    p.add_argument("--json", action="store_true", dest="json_output")


def _resolve_db_path(args) -> str | None:
    if args.db:
        return args.db
    if args.auto:
        diag_dir = Path(".tmp/logs/d810_logs")
        cands = (
            sorted(
                diag_dir.glob("*.diag.sqlite3"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if diag_dir.exists()
            else []
        )
        return str(cands[0]) if cands else None
    return None


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text)
        print(f"oracle written: {output}")
    else:
        print(text, end="")


def _no_ref_spec_stub(func_ea_hex: str) -> str:
    return (
        "# Region Oracle\n\n"
        f"Function: {func_ea_hex}\n"
        "Status: no_ref_spec\n\n"
        "No REF region spec is registered for this function.\n"
        "D810-only feature extraction was skipped from this run.\n"
    )


# ---------------------------------------------------------------------------
# Snapshot helpers (ported from tools/scripts/region_oracle.py)
# ---------------------------------------------------------------------------


def _byte_emit_facts_at(
    conn: sqlite3.Connection, snap_id: int,
) -> dict[int, dict]:
    """Return byte_index -> payload (terminal_tail role preferred)."""
    out: dict[int, dict] = {}
    try:
        rows = conn.execute(
            "SELECT payload FROM fact_observations "
            "WHERE kind='TerminalByteEmitterFact' AND snapshot_id=? "
            "ORDER BY fact_id",
            (snap_id,),
        ).fetchall()
    except sqlite3.OperationalError:
        return out
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
        out[int(bi)] = p
    return out


def _block_at(
    conn: sqlite3.Connection, snap_id: int, ea_hex: str,
) -> tuple[int, int, int] | None:
    """Return (serial, npred, nsucc) or None for snapshot+ea."""
    try:
        row = conn.execute(
            "SELECT serial, npred, nsucc FROM blocks "
            "WHERE snapshot_id=? AND start_ea_hex=?",
            (snap_id, ea_hex),
        ).fetchone()
    except sqlite3.OperationalError:
        return None
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
    try:
        block_succs: dict[int, tuple[int, ...]] = {
            int(s): tuple(json.loads(j or "[]"))
            for s, j in conn.execute(
                "SELECT serial, succs FROM blocks WHERE snapshot_id=?",
                (snap_id,),
            )
        }
    except sqlite3.OperationalError:
        block_succs = {}
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
    try:
        block_succs17 = {
            int(s): tuple(json.loads(j or "[]"))
            for s, j in conn.execute(
                "SELECT serial, succs FROM blocks WHERE snapshot_id=?",
                (snap17_id,),
            )
        }
    except sqlite3.OperationalError:
        block_succs17 = {}
    sccs17 = compute_live_cfg_sccs(block_succs17) if block_succs17 else ()
    cyclic17 = nontrivial_sccs(sccs17) if sccs17 else ()
    block_to_scc: dict[int, int] = {}
    for s in cyclic17:
        for b in s.blocks:
            block_to_scc[b] = s.size

    snap17_byte_blocks: dict[int, str] = {}
    for k, fact in initial_facts.items():
        ea_hex = None
        try:
            block = conn.execute(
                "SELECT start_ea_hex FROM blocks "
                "WHERE snapshot_id=? AND serial=?",
                (initial_snap_id, int(fact.get("block_serial", 0))),
            ).fetchone()
        except sqlite3.OperationalError:
            block = None
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
            snap18_info is None
            and any(b in snap18_facts for b in (1, 6))
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


# ---------------------------------------------------------------------------
# Per-snapshot feature extraction (real, not placeholder)
# ---------------------------------------------------------------------------


def _build_snapshot_features(
    conn: sqlite3.Connection,
    spec,
    snap_id: int,
    blocks: dict[int, BlockView] | None = None,
) -> list[RegionFeature]:
    """Real D810 snapshot feature extraction.

    Composes ``_build_snapshot_inputs`` + ``d810_features``. Attaches
    microblock evidence per ``byte_emit_<k>_present`` feature where a
    witness block exists.
    """
    inputs = _build_snapshot_inputs(conn, snap_id)
    feats = list(d810_features(inputs))

    if blocks is None:
        try:
            blocks = collect_block_views_for_snapshot(conn, snapshot_id=snap_id)
        except sqlite3.OperationalError:
            blocks = {}

    # Resolve snapshot label for evidence rendering.
    try:
        row = conn.execute(
            "SELECT label FROM snapshots WHERE id=?",
            (snap_id,),
        ).fetchone()
    except sqlite3.OperationalError:
        row = None
    snap_label = (
        str(row[0]) if row and row[0] is not None else f"snap_{snap_id}"
    )

    # Attach microblock evidence to byte_emit_<k>_present features that
    # have a known witness block.
    enriched: list[RegionFeature] = []
    for f in feats:
        witness_serial: int | None = None
        if f.feature.startswith("byte_emit_") and f.feature.endswith(
            "_present"
        ):
            try:
                k = int(f.feature.split("_")[2])
            except (IndexError, ValueError):
                k = -1
            if 0 <= k <= 6:
                witness_serial = inputs.byte_emit_block_serial.get(k)
        witness_block = (
            blocks.get(witness_serial) if witness_serial is not None else None
        )
        if witness_block is not None:
            ev = build_d810_evidence(
                witness_block,
                snapshot_id=snap_id,
                snapshot_label=snap_label,
                region_role="terminal_tail.byte_emit",
            )
            new_evidence = dict(f.evidence)
            new_evidence["microblock"] = ev.to_json_dict()
            enriched.append(
                RegionFeature(
                    source=f.source,
                    region=f.region,
                    feature=f.feature,
                    value=f.value,
                    evidence=new_evidence,
                    snapshot_id=f.snapshot_id,
                )
            )
        else:
            enriched.append(f)
    return enriched


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def _render_markdown(
    spec,
    func_ea_hex,
    snap17,
    snap18,
    ref,
    s17_feats,
    s18_feats,
    diff17,
    diff18,
    microblocks,
    blocks17,
    blocks18,
    classifications=None,
    overall_action=None,
    overall_reason=None,
) -> str:
    lines: list[str] = []
    lines.append("# Region Oracle\n")
    lines.append(f"Function: {spec.func_name} ({func_ea_hex})")
    lines.append(f"snap17: {snap17}, snap18: {snap18}\n")
    lines.append("## Summary\n")
    lines.append(f"REF features registered: {len(ref)}")
    lines.append(f"snap17 blocks: {len(blocks17)}")
    lines.append(f"snap18 blocks: {len(blocks18)}\n")
    lines.append("| feature | REF | D810 snap17 | D810 snap18 | verdict |")
    lines.append("|-|-|-|-|-|")
    s17_by_name = {f.feature: f.value for f in s17_feats}
    s18_by_name = {f.feature: f.value for f in s18_feats}
    for f in ref:
        v17 = s17_by_name.get(f.feature, "?")
        v18 = s18_by_name.get(f.feature, "?")
        verdict = "match" if (f.value == v17 == v18) else "diff"
        lines.append(
            f"| {f.feature} | {f.value} | {v17} | {v18} | {verdict} |"
        )

    if classifications is not None:
        lines.append("\n## Per-byte DCE causes (snap17 -> snap18)\n")
        lines.append(format_dce_table(classifications))
        if overall_action is not None:
            lines.append("\n## Recommended overall action\n")
            lines.append(f"- **{overall_action.value}** — {overall_reason}")

    if microblocks:
        lines.append("\n## Microblock Evidence\n")
        for f in ref:
            lines.append(f"### {f.feature}")
            lines.append(
                f"- REF: present={f.value}; evidence={f.evidence}"
            )
            s17 = next(
                (x for x in s17_feats if x.feature == f.feature), None
            )
            s18 = next(
                (x for x in s18_feats if x.feature == f.feature), None
            )
            if s17:
                lines.append(
                    f"- D810 snap17: present={s17.value}; "
                    f"evidence={s17.evidence}"
                )
            if s18:
                lines.append(
                    f"- D810 snap18: present={s18.value}; "
                    f"evidence={s18.evidence}"
                )
            lines.append("")
    return "\n".join(lines) + "\n"


def handle_region_diff(
    args,
    conn,
    resolve_snap_ids,
    persist_features,
    persist_dce_causes,
) -> int:
    db_path = _resolve_db_path(args)
    if not db_path and args.auto:
        print(
            "oracle skipped: no diag DB present "
            "(run with --enable-debug-logging to capture one)"
        )
        return 0
    if not db_path:
        print("oracle: --db or --auto required", file=sys.stderr)
        return 2

    # Reopen on the resolved path so --auto works.
    if args.auto and not args.db:
        conn = sqlite3.connect(db_path)

    if args.func_ea:
        func_ea_hex = _normalize_func_ea_hex(args.func_ea)
    else:
        try:
            row = conn.execute(
                "SELECT func_ea_hex FROM snapshots LIMIT 1"
            ).fetchone()
        except sqlite3.OperationalError as e:
            print(f"oracle: schema mismatch: {e}", file=sys.stderr)
            return 2
        if row is None or row[0] is None:
            print(
                "oracle: cannot infer func_ea from DB; "
                "pass --func-ea explicitly",
                file=sys.stderr,
            )
            return 2
        func_ea_hex = _normalize_func_ea_hex(str(row[0]))

    spec = spec_for(func_ea_hex)
    if spec is None:
        _emit(_no_ref_spec_stub(func_ea_hex), args.output)
        return 0

    snap17 = args.snap17
    snap18 = args.snap18
    if snap17 is None or snap18 is None:
        snap17_labels = (
            (args.snap17_label,)
            if args.snap17_label
            else spec.snap17_label_preferences
        )
        snap18_labels = (
            (args.snap18_label,)
            if args.snap18_label
            else spec.snap18_label_preferences
        )
        try:
            r17, r18 = resolve_snap_ids(
                conn,
                snap17_labels=snap17_labels,
                snap18_labels=snap18_labels,
            )
        except sqlite3.OperationalError as e:
            print(f"oracle: schema mismatch: {e}", file=sys.stderr)
            return 2
        if snap17 is None:
            snap17 = r17
        if snap18 is None:
            snap18 = r18

    if snap17 is None or snap18 is None:
        print(
            f"oracle: cannot resolve snap17/snap18 (snap17={snap17}, "
            f"snap18={snap18}); pass --snap17/--snap18 explicitly.",
            file=sys.stderr,
        )
        return 2

    if snap17 >= snap18:
        print(
            f"oracle: snap17 ({snap17}) must be < snap18 ({snap18}). "
            "Pass valid IDs explicitly.",
            file=sys.stderr,
        )
        return 2

    # Block-view collection MUST surface schema mismatches (missing
    # columns / tables) as exit-code-2 errors. Silently producing a "0
    # blocks" report masks real bugs in the diag schema or oracle
    # queries. Sparse-population (no rows) is fine — the function
    # naturally returns {} in that case without raising.
    try:
        blocks17 = collect_block_views_for_snapshot(conn, snapshot_id=snap17)
        blocks18 = collect_block_views_for_snapshot(conn, snapshot_id=snap18)
    except sqlite3.OperationalError as e:
        print(f"oracle: schema mismatch: {e}", file=sys.stderr)
        return 2

    ref = list(ref_features(spec))
    s17 = _build_snapshot_features(conn, spec, snap17, blocks=blocks17)
    s18 = _build_snapshot_features(conn, spec, snap18, blocks=blocks18)
    diff17 = list(diff_features(ref, s17))
    diff18 = list(diff_features(ref, s18))

    # Per-byte DCE classification.
    try:
        evidences = _build_dce_evidence(conn, snap17, snap18)
    except sqlite3.OperationalError as e:
        print(f"oracle: schema mismatch: {e}", file=sys.stderr)
        return 2
    classifications = classify_all(evidences)
    overall_action, overall_reason = recommend_overall_action(classifications)

    body = _render_markdown(
        spec,
        func_ea_hex,
        snap17,
        snap18,
        ref,
        s17,
        s18,
        diff17,
        diff18,
        args.microblocks,
        blocks17,
        blocks18,
        classifications=classifications,
        overall_action=overall_action,
        overall_reason=overall_reason,
    )

    if args.json_output:
        payload = {
            "function": {"name": spec.func_name, "func_ea_hex": func_ea_hex},
            "snap17": snap17,
            "snap18": snap18,
            "ref_features": [
                {
                    "feature": f.feature,
                    "value": f.value,
                    "evidence": f.evidence,
                }
                for f in ref
            ],
            "snap17_features": [
                {
                    "feature": f.feature,
                    "value": f.value,
                    "evidence": f.evidence,
                }
                for f in s17
            ],
            "snap18_features": [
                {
                    "feature": f.feature,
                    "value": f.value,
                    "evidence": f.evidence,
                }
                for f in s18
            ],
            "dce_classifications": [
                {
                    "byte_index": c.byte_index,
                    "cause": c.cause.value,
                    "recommended_action": c.recommended_action.value,
                    "rationale": c.rationale,
                }
                for c in classifications
            ],
            "overall_action": {
                "action": overall_action.value,
                "reason": overall_reason,
            },
        }
        body = json.dumps(payload, indent=2, sort_keys=True)

    _emit(body, args.output)

    if args.persist:
        all_feats = list(ref) + list(s17) + list(s18)
        persist_features(
            conn,
            func_ea_hex=func_ea_hex,
            func_ea_i64=int(func_ea_hex, 16),
            features=all_feats,
        )
        cause_rows = [
            {
                "byte_index": c.byte_index,
                "last_present_snapshot_id": snap17,
                "first_missing_snapshot_id": snap18,
                "last_block_serial": c.evidence.snap17_block_serial,
                "last_ea_hex": c.evidence.snap17_block_ea,
                "cause": c.cause.value,
                "recommended_action": c.recommended_action.value,
                "rationale": c.rationale,
                "evidence": dataclasses.asdict(c.evidence),
            }
            for c in classifications
        ]
        persist_dce_causes(
            conn,
            func_ea_hex=func_ea_hex,
            func_ea_i64=int(func_ea_hex, 16),
            causes=cause_rows,
        )

    return 0
