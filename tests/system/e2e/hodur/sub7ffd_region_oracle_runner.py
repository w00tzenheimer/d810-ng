"""Test-support runner for the sub7FFD Hodur region oracle."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from tests.system.e2e.hodur.sub7ffd_region_oracle import (
    BlockView,
    D810SnapshotInputs,
    RegionFeature,
    _normalize_func_ea_hex,
    build_d810_evidence,
    collect_block_views_for_snapshot,
    d810_features,
    diff_features,
    ref_features,
    spec_for,
)
from d810.analyses.control_flow.scc import compute_live_cfg_sccs, nontrivial_sccs
from d810.transforms.terminal_tail_dce_diagnosis import (
    ByteEmitSnapshotEvidence,
    classify_all,
    format_dce_table,
    recommend_overall_action,
)


def _no_ref_spec_stub(func_ea_hex: str) -> str:
    return (
        "# Region Oracle\n\n"
        f"Function: {func_ea_hex}\n"
        "Status: no_ref_spec\n\n"
        "No REF region spec is registered for this function.\n"
        "D810-only feature extraction was skipped from this run.\n"
    )


# ---------------------------------------------------------------------------
# Snapshot helpers
# ---------------------------------------------------------------------------


def resolve_oracle_snap_ids(
    conn: sqlite3.Connection,
    *,
    snap17_labels: tuple[str, ...],
    snap18_labels: tuple[str, ...],
) -> tuple[int | None, int | None]:
    """Resolve snap17 and snap18 IDs for the test harness."""

    def _max_id_for_labels(
        labels: tuple[str, ...], upper_bound: int | None,
    ) -> int | None:
        for label in labels:
            if upper_bound is None:
                row = conn.execute(
                    "SELECT MAX(id) FROM snapshots WHERE label = ?",
                    (label,),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT MAX(id) FROM snapshots "
                    "WHERE label = ? AND id < ?",
                    (label, upper_bound),
                ).fetchone()
            if row is not None and row[0] is not None:
                return int(row[0])
        return None

    snap18 = _max_id_for_labels(snap18_labels, None)
    snap17 = _max_id_for_labels(snap17_labels, snap18)
    return snap17, snap18


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


def _source_form_from_payload(payload: dict, byte_index: int) -> str:
    source = str(payload.get("source_byte_expression") or "")
    if not source or source in {"unknown-source", "guard-only"}:
        return "absent"
    if f"v52[{byte_index}]" in source:
        return "indexed_base_plus_k"
    if byte_index == 0 and source in {"v52[0]", "v52", "*v52"}:
        return "indexed_base_plus_k"
    if f"#{byte_index}." in source or f"#{byte_index:x}." in source.lower():
        return "indexed_base_plus_k"
    if "<<" in source or "|" in source or "^" in source:
        return "folded"
    if byte_index == 0 and "[ds." in source:
        return "base_only"
    return "folded"


def _destination_present_from_payload(payload: dict) -> bool:
    destination = str(payload.get("destination_buffer_expression") or "")
    return bool(destination and destination not in {"unknown-destination", "guard-only"})


def _counter_update_present_from_payload(payload: dict) -> bool:
    counter = str(payload.get("counter_carrier") or "")
    role = str(payload.get("emitter_role") or "")
    if role == "guard_only":
        return False
    return bool(counter and counter != "unknown-counter")


def _early_return_guard_present_from_payload(payload: dict) -> bool:
    guard = str(payload.get("guard_condition") or "")
    return bool(guard and guard != "unknown-guard")


def _build_snapshot_inputs(
    conn: sqlite3.Connection,
    snap_id: int,
    initial_snap_id: int | None = None,
) -> D810SnapshotInputs:
    """Compute D810 region-shape features from one snapshot.

    Survival semantics: ``byte_emit_<k>_present`` is True if either
    (a) a TerminalByteEmitterFact fires at ``snap_id`` directly, OR
    (b) ``initial_snap_id`` is given AND the byte's witness block from
    that baseline snapshot survived (an EA-matching block exists at
    ``snap_id``). ``byte_emit_fact_detected[k]`` is True ONLY when the
    snapshot's own facts confirm the emitter — independent of survival.
    """
    facts = _byte_emit_facts_at(conn, snap_id)
    byte_emit_present: dict[int, bool] = {}
    byte_emit_block_serial: dict[int, int | None] = {}
    byte_emit_fact_detected: dict[int, bool] = {}
    byte_emit_source_form: dict[int, str] = {}
    byte_emit_destination_present: dict[int, bool] = {}
    byte_emit_counter_update_present: dict[int, bool] = {}
    early_return_guard_present: dict[int, bool] = {}

    # Seed: facts firing at snap_id directly.
    for k in range(7):
        if k in facts:
            byte_emit_present[k] = True
            byte_emit_block_serial[k] = int(facts[k].get("block_serial", 0))
            byte_emit_fact_detected[k] = True
            byte_emit_source_form[k] = _source_form_from_payload(facts[k], k)
            byte_emit_destination_present[k] = _destination_present_from_payload(facts[k])
            byte_emit_counter_update_present[k] = _counter_update_present_from_payload(facts[k])
            if k < 6:
                early_return_guard_present[k] = _early_return_guard_present_from_payload(facts[k])
        else:
            byte_emit_present[k] = False
            byte_emit_block_serial[k] = None
            byte_emit_fact_detected[k] = False
            byte_emit_source_form[k] = "absent"
            byte_emit_destination_present[k] = False
            byte_emit_counter_update_present[k] = False
            if k < 6:
                early_return_guard_present[k] = False

    # Survival fallback: if no fact fires at snap_id but an initial
    # snapshot baseline is given, check whether each byte's baseline
    # witness block survived (EA-matching block present at snap_id).
    if initial_snap_id is not None and initial_snap_id != snap_id:
        initial_facts = _byte_emit_facts_at(conn, initial_snap_id)
        for k, fact in initial_facts.items():
            if 0 <= k <= 6 and not byte_emit_present.get(k, False):
                # Resolve baseline witness EA from baseline blocks.
                try:
                    row = conn.execute(
                        "SELECT start_ea_hex FROM blocks "
                        "WHERE snapshot_id=? AND serial=?",
                        (initial_snap_id, int(fact.get("block_serial", 0))),
                    ).fetchone()
                except sqlite3.OperationalError:
                    row = None
                if not row or not row[0]:
                    continue
                ea_hex = row[0]
                survived = _block_at(conn, snap_id, ea_hex)
                if survived is not None:
                    serial_at_snap, _, _ = survived
                    byte_emit_present[k] = True
                    byte_emit_block_serial[k] = serial_at_snap
                    byte_emit_source_form[k] = _source_form_from_payload(fact, k)
                    byte_emit_destination_present[k] = _destination_present_from_payload(fact)
                    byte_emit_counter_update_present[k] = (
                        _counter_update_present_from_payload(fact)
                    )
                    if k < 6:
                        early_return_guard_present[k] = (
                            _early_return_guard_present_from_payload(fact)
                        )
                    # fact_detected stays False — the live fact didn't fire.

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
        byte_emit_source_form=byte_emit_source_form,
        byte_emit_destination_present=byte_emit_destination_present,
        byte_emit_counter_update_present=byte_emit_counter_update_present,
        early_return_guard_present=early_return_guard_present,
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
    initial_snap_id: int | None = None,
) -> list[RegionFeature]:
    """Real D810 snapshot feature extraction.

    Composes ``_build_snapshot_inputs`` + ``d810_features``. Attaches
    microblock evidence per ``byte_emit_<k>_present`` feature where a
    witness block exists.
    """
    inputs = _build_snapshot_inputs(
        conn, snap_id, initial_snap_id=initial_snap_id,
    )
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


def render_region_oracle_report(
    conn: sqlite3.Connection,
    *,
    func_ea_hex: str,
    func_name: str | None = None,
    snap17: int | None = None,
    snap18: int | None = None,
    microblocks: bool = False,
    json_output: bool = False,
) -> str:
    func_ea_hex = _normalize_func_ea_hex(func_ea_hex)
    spec = spec_for(func_ea_hex, func_name=func_name)
    if spec is None:
        return _no_ref_spec_stub(func_ea_hex)

    if snap17 is None or snap18 is None:
        r17, r18 = resolve_oracle_snap_ids(
            conn,
            snap17_labels=spec.snap17_label_preferences,
            snap18_labels=spec.snap18_label_preferences,
        )
        if snap17 is None:
            snap17 = r17
        if snap18 is None:
            snap18 = r18

    if snap17 is None or snap18 is None:
        return (
            "# Region Oracle\n\n"
            f"Function: {func_ea_hex}\n"
            "Status: unresolved_snapshots\n\n"
            f"Cannot resolve snap17/snap18 (snap17={snap17}, snap18={snap18}).\n"
        )

    if snap17 >= snap18:
        return (
            "# Region Oracle\n\n"
            f"Function: {func_ea_hex}\n"
            "Status: invalid_snapshots\n\n"
            f"snap17 ({snap17}) must be < snap18 ({snap18}).\n"
        )

    blocks17 = collect_block_views_for_snapshot(conn, snapshot_id=snap17)
    blocks18 = collect_block_views_for_snapshot(conn, snapshot_id=snap18)

    ref = list(ref_features(spec))
    # Probe for the highest snapshot.id labeled
    # "maturity_MMAT_GLBOPT1_pre_d810" — the canonical baseline for
    # byte_emit fact survival checks. Fall back to id=5 if no row matches.
    initial_snap_id: int | None = 5
    try:
        row = conn.execute(
            "SELECT MAX(id) FROM snapshots "
            "WHERE label = 'maturity_MMAT_GLBOPT1_pre_d810'"
        ).fetchone()
        if row and row[0] is not None:
            initial_snap_id = int(row[0])
    except sqlite3.OperationalError:
        pass

    s17 = _build_snapshot_features(
        conn, spec, snap17, blocks=blocks17,
        initial_snap_id=initial_snap_id,
    )
    s18 = _build_snapshot_features(
        conn, spec, snap18, blocks=blocks18,
        initial_snap_id=initial_snap_id,
    )
    diff17 = list(diff_features(ref, s17))
    diff18 = list(diff_features(ref, s18))

    evidences = _build_dce_evidence(conn, snap17, snap18)
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
        microblocks,
        blocks17,
        blocks18,
        classifications=classifications,
        overall_action=overall_action,
        overall_reason=overall_reason,
    )

    if json_output:
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

    return body


def write_region_oracle_report(
    conn: sqlite3.Connection,
    *,
    func_ea_hex: str,
    func_name: str | None = None,
    output_path: Path,
    microblocks: bool = False,
) -> Path:
    body = render_region_oracle_report(
        conn,
        func_ea_hex=func_ea_hex,
        func_name=func_name,
        microblocks=microblocks,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(body)
    return output_path
