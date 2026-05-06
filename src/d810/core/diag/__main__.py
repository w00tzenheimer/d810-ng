"""CLI for querying MBA diagnostic snapshots.

Usage::

    python -m d810.core.diag chain --db path.sqlite3 131 174 176 200 23 32 62 206 207 218
    python -m d810.core.diag var-writes --db path.sqlite3 0x7F0
    python -m d810.core.diag block --db path.sqlite3 206 --insns
    python -m d810.core.diag return-paths --db path.sqlite3 --snapshot -1
    python -m d810.core.diag program --db path.sqlite3 --snapshot -1
    python -m d810.core.diag program --db path.sqlite3 --snapshot -1 --nodes
    python -m d810.core.diag program --db path.sqlite3 --snapshot 12 --variant semantic_reference_like
    python -m d810.core.diag program --db path.sqlite3 --maturity GLBOPT1 --phase post_d810
    python -m d810.core.diag state-local --db path.sqlite3 --snapshot 6 0x298372CC
    python -m d810.core.diag block-trace --db path.sqlite3 --ea 0x1800134A5
    python -m d810.core.diag block-trace --db path.sqlite3 --snapshot 12 --serial 206
    python -m d810.core.diag block-lineage --db path.sqlite3 --snapshot 12 --serial 206
    PYTHONPATH=src python3 -m d810.core.diag program \\
      --db /Users/mahmoud/src/idapro/d810/.worktrees/state-label-linearization/.tmp/logs/d810_logs/0000000180012b60_1774805543_33.diag.sqlite3 \\
      --maturity GLBOPT1 \\
      --phase post_d810 \\
      --variant semantic_reference_like
    python -m d810.core.diag program-variants --db path.sqlite3 --snapshot -1
    python -m d810.core.diag ea-trace --db path.sqlite3 0x1800134A5

Notes::

    --snapshot -1 resolves to the latest snapshot in the database.
    --maturity accepts GLBOPT1 or MMAT_GLBOPT1 forms.
    when --maturity and/or --phase are provided, they take precedence over
    --snapshot and resolve the newest matching snapshot.
    program variants are stored rendered linearized-program views, such as
    semantic_reference_like.
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys

from d810.core.diag.formatting import format_block_id
from d810.core.diag.query import (
    block_detail,
    block_lineage,
    block_trace_by_ea,
    block_trace_by_serial,
    chain,
    merge_causality,
    fact_conflicts,
    fact_consumers,
    fact_diff,
    fact_mappings,
    fact_observations,
    fact_trace,
    rendered_program_nodes,
    rendered_program_text,
    rendered_program_variants,
    return_paths,
    state_local,
    var_writes,
)


def _normalize_maturity_name(maturity: str | None) -> str | None:
    if maturity is None:
        return None
    mat = maturity.strip().upper()
    if not mat:
        return None
    if not mat.startswith("MMAT_"):
        mat = f"MMAT_{mat}"
    return mat


def _resolve_snapshot_id(
    conn: sqlite3.Connection,
    snapshot: int,
    *,
    maturity: str | None = None,
    phase: str | None = None,
) -> int:
    """Resolve snapshot selector.

    Priority:
    1. `--maturity` / `--phase` selector when provided
    2. explicit snapshot id when >= 0
    3. latest snapshot (`-1`)
    """
    mat = _normalize_maturity_name(maturity)
    if mat is not None or phase is not None:
        if mat is not None and phase is not None:
            row = conn.execute(
                "SELECT MAX(id) FROM snapshots WHERE maturity=? AND phase=?",
                (mat, phase),
            ).fetchone()
        elif mat is not None:
            row = conn.execute(
                "SELECT MAX(id) FROM snapshots WHERE maturity=?",
                (mat,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT MAX(id) FROM snapshots WHERE phase=?",
                (phase,),
            ).fetchone()
        if row is None or row[0] is None:
            selector = []
            if mat is not None:
                selector.append(f"maturity={mat}")
            if phase is not None:
                selector.append(f"phase={phase}")
            print(
                f"ERROR: no snapshot matches {' '.join(selector)}",
                file=sys.stderr,
            )
            sys.exit(1)
        return int(row[0])
    if snapshot >= 0:
        return snapshot
    row = conn.execute("SELECT MAX(id) FROM snapshots").fetchone()
    if row is None or row[0] is None:
        print("ERROR: no snapshots in database", file=sys.stderr)
        sys.exit(1)
    return row[0]


def _snapshot_header(conn: sqlite3.Connection, snapshot_id: int) -> str:
    """Return a one-line header with snapshot maturity and phase."""
    row = conn.execute(
        "SELECT maturity, phase FROM snapshots WHERE id=?",
        (snapshot_id,),
    ).fetchone()
    if row is None:
        return f"snapshot {snapshot_id}"
    maturity, phase = row
    return f"snapshot {snapshot_id} [{maturity} / {phase}]"


def _metadata_lineage_ea(meta: dict | None) -> str | int | None:
    if not meta:
        return None
    for key in (
        "lineage_ea",
        "copy_of_ea",
        "copied_from_ea",
        "source_ea",
        "body_source_ea",
    ):
        value = meta.get(key)
        if value is not None:
            return value[0] if isinstance(value, list) and value else value
    lineage_eas = meta.get("lineage_eas")
    if isinstance(lineage_eas, list) and lineage_eas:
        return lineage_eas[0]
    return None


def _block_identity_lookup(conn: sqlite3.Connection, snapshot_id: int) -> dict[int, str]:
    rows = conn.execute(
        "SELECT serial, start_ea_hex, meta FROM blocks WHERE snapshot_id=?",
        (snapshot_id,),
    ).fetchall()
    lookup: dict[int, str] = {}
    for row in rows:
        if isinstance(row, dict):
            serial = row["serial"]
            start_ea_hex = row["start_ea_hex"]
            meta_text = row["meta"]
        else:
            serial, start_ea_hex, meta_text = row
        meta: dict | None = None
        if meta_text:
            try:
                meta = json.loads(meta_text)
            except json.JSONDecodeError:
                meta = None
        lookup[int(serial)] = format_block_id(
            int(serial),
            start_ea=start_ea_hex,
            lineage_ea=_metadata_lineage_ea(meta),
            synthetic=start_ea_hex is None,
        )
    return lookup


def _block_id_from_lookup(serial: int | None, lookup: dict[int, str]) -> str:
    if serial is None:
        return format_block_id(None)
    return lookup.get(int(serial), format_block_id(int(serial)))


def _block_id_from_row(row: dict, serial_key: str = "serial") -> str:
    serial = row.get(serial_key)
    start_ea = row.get("start_ea_hex") or row.get("block_start_ea_hex")
    meta = row.get("meta_parsed")
    if meta is None and row.get("meta"):
        try:
            meta = json.loads(row["meta"])
        except json.JSONDecodeError:
            meta = None
    return format_block_id(
        serial,
        start_ea=start_ea,
        lineage_ea=_metadata_lineage_ea(meta),
        synthetic=start_ea is None,
    )


def _format_block_list(serials: list[int], lookup: dict[int, str]) -> str:
    return "[" + ", ".join(_block_id_from_lookup(serial, lookup) for serial in serials) + "]"


def _format_chain(results: list[dict], block_lookup: dict[int, str] | None = None) -> str:
    """Format chain query output as compact per-block summary."""
    lookup = block_lookup or {}
    lines: list[str] = []
    for blk in results:
        if blk is None:
            lines.append("  (missing)")
            continue
        serial = blk["serial"]
        block_id = _block_id_from_row(blk)
        tname = blk["type_name"]
        succs = blk["succs"]
        succs_str = _format_block_list(succs, lookup)
        hop_status = ""
        if "hop_ok" in blk:
            expected = blk["expected_next"]
            expected_str = _block_id_from_lookup(expected, lookup)
            actual_str = _block_id_from_lookup(succs[0], lookup) if succs else "?"
            ok_str = "OK" if blk["hop_ok"] else f"BROKEN (actual: {actual_str})"
            hop_status = f" hop->{expected_str} {ok_str}"
        lines.append(f"{block_id} {tname} succs={succs_str}{hop_status}")
        for insn in blk.get("instructions", []):
            idx = insn["insn_index"]
            dstr = insn["dstr"] or ""
            lines.append(f"  {serial}.{idx} {dstr}")
    return "\n".join(lines)


def _format_var_writes(writes: list[dict]) -> str:
    """Format var-writes query output as table."""
    lines: list[str] = []
    for w in writes:
        blk = _block_id_from_row(w, "block_serial")
        idx = w["insn_index"]
        dstr = w.get("dstr", "") or ""
        stkoff = w.get("dest_stkoff")
        stkoff_str = f"stkoff=0x{stkoff:X}" if stkoff is not None else "stkoff=None"
        src_stkoff = w.get("src_l_stkoff")
        src_str = f"src_stkoff=0x{src_stkoff:X}" if src_stkoff is not None else "src=None"
        lines.append(f"{blk}.{idx}  {dstr:<40s} {stkoff_str} {src_str}")
    return "\n".join(lines)


def _format_block(
    blk: dict | None,
    show_insns: bool,
    block_lookup: dict[int, str] | None = None,
) -> str:
    """Format block detail output."""
    if blk is None:
        return "(block not found)"
    lookup = block_lookup or {}
    lines: list[str] = []
    serial = blk["serial"]
    block_id = _block_id_from_row(blk)
    tname = blk["type_name"]
    succs = blk["succs"]
    preds = blk["preds"]
    nsucc = blk["nsucc"]
    npred = blk["npred"]
    lines.append(f"{block_id} {tname} nsucc={nsucc} npred={npred}")
    lines.append(f"  succs={_format_block_list(succs, lookup)}")
    lines.append(f"  preds={_format_block_list(preds, lookup)}")
    meta = blk.get("meta_parsed", {})
    if meta:
        lines.append(f"  meta={json.dumps(meta, indent=2)}")
    for key in ("is_bst", "is_reachable", "is_gutted", "in_claimed"):
        if key in blk:
            lines.append(f"  {key}={blk[key]}")
    if show_insns:
        lines.append(f"  instructions ({blk['insn_count']}):")
        for insn in blk.get("instructions", []):
            idx = insn["insn_index"]
            dstr = insn["dstr"] or ""
            lines.append(f"    {serial}.{idx} {dstr}")
    return "\n".join(lines)


def _format_return_paths(
    paths: list[dict],
    block_lookup: dict[int, str] | None = None,
) -> str:
    """Format return-paths query output."""
    lookup = block_lookup or {}
    lines: list[str] = []
    for p in paths:
        src_hex = p.get("source_state") or "None"
        lines.append(f"edge[{p['edge_id']}] src={src_hex} CONDITIONAL_RETURN")
        lines.append(f"  path={_format_block_list(p['path_serials'], lookup)}")
        for hop in p.get("hops", []):
            serial = hop["serial"]
            flag = "*" if hop.get("has_return_slot_write") else " "
            opcode = hop.get("write_opcode") or ""
            lines.append(f"    [{flag}] {_block_id_from_lookup(serial, lookup)} {opcode}")
    return "\n".join(lines)


def _format_rendered_program_nodes(
    nodes: list[dict],
    block_lookup: dict[int, str] | None = None,
) -> str:
    """Format rendered program node metadata."""
    if not nodes:
        return "(rendered program not found)"
    lookup = block_lookup or {}
    lines: list[str] = []
    for node in nodes:
        parts = [
            f"[{node['node_index']}]",
            node["label_text"],
            node["node_kind"],
            f"lines={node['line_start']}-{node['line_end']}",
        ]
        if node.get("state_label"):
            parts.append(f"state={node['state_label']}")
        if node.get("handler_serial") is not None:
            parts.append(f"handler={_block_id_from_lookup(node['handler_serial'], lookup)}")
        if node.get("entry_anchor") is not None:
            parts.append(f"entry={_block_id_from_lookup(node['entry_anchor'], lookup)}")
        lines.append(" ".join(parts))
    return "\n".join(lines)


def _format_rendered_program_variants(variants: list[dict]) -> str:
    """Format available rendered-program variants for a snapshot."""
    if not variants:
        return "(no rendered programs stored)"
    lines: list[str] = []
    for variant in variants:
        lines.append(
            f"{variant['variant_name']}: "
            f"{variant['line_count']} lines, {variant['node_count']} nodes, "
            f"{variant['order_strategy']}/{variant['program_strategy']}/"
            f"{variant['label_render_mode']}/{variant['boundary_inline_mode']}/"
            f"{variant['comment_mode']}"
        )
    return "\n".join(lines)


def _blk_list(serials: list[int]) -> str:
    return ", ".join(f"blk[{int(serial)}]" for serial in serials)


def _state_label_from_query(state: int) -> str:
    return f"STATE_{int(state) & 0xFFFFFFFF:08X}"


def _format_state_local(result: dict | None, *, state: int) -> str:
    """Format typed state-local DAG facts."""
    if result is None:
        return f"{_state_label_from_query(state)}:\n    // state not found"

    node = result["node"]
    lines: list[str] = [_state_label_from_query(state) + ":"]
    classification = str(node.get("classification") or "unknown").lower()
    lines.append(f"    // entry blk[{node['entry_block']}] [{classification}]")

    if not result.get("local_facts_available"):
        shared_suffix = node.get("shared_suffix")
        if shared_suffix:
            try:
                shared_blocks = json.loads(shared_suffix)
            except json.JSONDecodeError:
                shared_blocks = []
            if shared_blocks:
                lines.append(f"    // shared-suffix: {_blk_list(shared_blocks)}")
        missing = result.get("missing_tables") or []
        detail = (
            f"missing tables: {', '.join(missing)}"
            if missing
            else "no dag_local_* rows for this state"
        )
        lines.append(f"    // local facts unavailable ({detail})")
        return "\n".join(lines)

    blocks_by_role = result.get("blocks_by_role", {})
    owned_blocks = blocks_by_role.get("owned", [])
    shared_blocks = blocks_by_role.get("shared_suffix", [])
    if owned_blocks:
        lines.append(f"    // blocks: {_blk_list(owned_blocks)}")
    if shared_blocks:
        lines.append(f"    // shared-suffix: {_blk_list(shared_blocks)}")

    local_edges = result.get("local_edges", [])
    if local_edges:
        parts = []
        for edge in local_edges:
            kind = str(edge["kind"]).lower()
            parts.append(
                f"{edge['source_segment_id']} -{kind}-> {edge['target_segment_id']}"
            )
        lines.append(f"    // local-cfg: {', '.join(parts)}")
    else:
        lines.append("    // local-cfg: (none)")
    return "\n".join(lines)


def _format_watch_transitions(
    conn: sqlite3.Connection,
    *,
    block: int | None = None,
    session: str | None = None,
    phase: str | None = None,
    changed_only: bool = False,
    sessions_only: bool = False,
) -> str:
    """Render watch_block_transitions rows in log-style format.

    Output mirrors the stdout ``DEFERRED WATCH`` log line format so SQL
    query output looks familiar to anyone who has read the text log.
    """
    if sessions_only:
        rows = conn.execute(
            "SELECT apply_session_id, COUNT(*) AS n, "
            "MIN(timestamp) AS first_ts, MAX(timestamp) AS last_ts "
            "FROM watch_block_transitions "
            "GROUP BY apply_session_id ORDER BY MIN(id)"
        ).fetchall()
        if not rows:
            return "(no watch_block_transitions rows — is the table populated?)"
        lines = [
            f"{sid}: rows={n} window={first_ts:.3f}..{last_ts:.3f}"
            for sid, n, first_ts, last_ts in rows
        ]
        return "\n".join(lines)

    clauses: list[str] = []
    params: list = []
    if block is not None:
        clauses.append("block_serial = ?")
        params.append(int(block))
    if session is not None:
        clauses.append("apply_session_id = ?")
        params.append(session)
    if phase is not None:
        clauses.append("phase = ?")
        params.append(phase)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    rows = conn.execute(
        f"SELECT apply_session_id, mod_index, mod_type, phase, block_serial, "
        f"prev_type_name, prev_succs, prev_preds, "
        f"now_type_name, now_succs, now_preds "
        f"FROM watch_block_transitions {where} ORDER BY id"
    , params).fetchall()
    if not rows:
        return "(no watch_block_transitions rows match the filter)"

    out: list[str] = []
    current_session: str | None = None
    for (
        sid, mod_idx, mod_type, ph, blk,
        p_type, p_succs, p_preds, n_type, n_succs, n_preds,
    ) in rows:
        prev_tuple = (
            None if p_type is None
            else (p_type, tuple(json.loads(p_succs or "[]")), tuple(json.loads(p_preds or "[]")))
        )
        now_tuple = (
            None if n_type is None
            else (n_type, tuple(json.loads(n_succs or "[]")), tuple(json.loads(n_preds or "[]")))
        )
        if changed_only and prev_tuple == now_tuple:
            continue
        if sid != current_session:
            out.append(f"=== session {sid} ===")
            current_session = sid
        mod_tag = f"mod[{mod_idx}]" if mod_idx is not None else ""
        kind_tag = f"{mod_type}".ljust(22)
        header = f"[{ph:<24}] {mod_tag:<10} {kind_tag} blk[{blk}]"
        if prev_tuple is None:
            body = f"_ → {now_tuple}"
        elif now_tuple is None:
            body = f"{prev_tuple} → _"
        elif prev_tuple == now_tuple:
            body = f"(unchanged) {now_tuple}"
        else:
            body = f"{prev_tuple} → {now_tuple}"
        out.append(f"{header}  {body}")
    return "\n".join(out) if out else "(no transitions matched after filters)"


_MERGE_CAUSALITY_FROM_DEFAULT = "state_write_reconstruction_post_apply"
_MERGE_CAUSALITY_TO_DEFAULT = "maturity_MMAT_GLBOPT1_post_d810"


def _resolve_snapshot_by_label(conn: sqlite3.Connection, label: str) -> int:
    """Resolve the newest snapshot whose label matches exactly."""
    row = conn.execute(
        "SELECT MAX(id) FROM snapshots WHERE label=?", (label,)
    ).fetchone()
    if row is None or row[0] is None:
        print(
            f"ERROR: no snapshot with label={label!r}. "
            f"Use `SELECT id, label FROM snapshots` to list available labels.",
            file=sys.stderr,
        )
        sys.exit(1)
    return int(row[0])


_DISPOSITIONS = ("absorbed", "deleted", "synthesized_only")
_CONTENT_CLASSES = (
    "empty",
    "m_und_only",
    "nop_und_only",
    "goto_only",
    "has_content",
)


def _format_merge_causality(result: dict, *, limit: int | None) -> str:
    """Render the merge-causality report: header, cross-tab, detail rows.

    Cross-tab is content_class × disposition so a single glance answers
    "how many vanished handler-body-looking blocks were deleted vs merged".
    When *limit* is ``None`` the detail section is omitted (summary-only
    mode, recommended default). When *limit* is an int, at most that many
    rows are printed.
    """
    from_total = result["from_block_count"]
    to_total = result["to_block_count"]
    vanished = result["vanished"]
    lines: list[str] = []
    lines.append(
        f"MERGE CAUSALITY: FROM snap {result['from_snapshot_id']} "
        f"({from_total} blocks) -> TO snap {result['to_snapshot_id']} "
        f"({to_total} blocks)"
    )
    lines.append(f"vanished: {len(vanished)} blocks")
    lines.append("")

    cross: dict[tuple[str, str], int] = {}
    for row in vanished:
        key = (row["content_class"], row["disposition"])
        cross[key] = cross.get(key, 0) + 1

    lines.append("cross-tab  content_class × disposition")
    header = f"  {'content_class':<14}" + "".join(
        f" {d:>16}" for d in _DISPOSITIONS
    ) + f" {'TOTAL':>8}"
    lines.append(header)
    lines.append("  " + "-" * (len(header) - 2))
    for cls in _CONTENT_CLASSES:
        counts = [cross.get((cls, d), 0) for d in _DISPOSITIONS]
        total = sum(counts)
        if total == 0:
            continue
        cells = "".join(f" {c:>16}" for c in counts)
        lines.append(f"  {cls:<14}{cells} {total:>8}")
    col_totals = [
        sum(cross.get((c, d), 0) for c in _CONTENT_CLASSES) for d in _DISPOSITIONS
    ]
    grand = sum(col_totals)
    lines.append(
        f"  {'TOTAL':<14}"
        + "".join(f" {c:>16}" for c in col_totals)
        + f" {grand:>8}"
    )
    lines.append("")

    if limit is None:
        lines.append(
            "(detail rows suppressed — pass --limit N for per-block entries)"
        )
        return "\n".join(lines)

    for row in vanished[:limit]:
        serial = row["serial"]
        tn = row["type_name"]
        ic = row["insn_count"]
        tail = row["tail_opcode"] or "(no insns)"
        cc = row["content_class"]
        disp = row["disposition"]
        preds = row["preds"]
        succs = row["succs"]
        lines.append(
            f"blk[{serial}] {tn} insn={ic} tail={tail} [{cc}/{disp}]"
        )
        lines.append(f"  preds={preds} -> succs={succs}")
        abs_ = row["absorber"]
        if abs_ is None:
            if disp == "deleted":
                lines.append(
                    "  absorber: none — real EAs did not survive in TO (deleted)"
                )
            else:
                lines.append("  absorber: none — block had no real EAs (synth-only)")
        else:
            lines.append(
                f"  absorber: blk[{abs_['serial']}] {abs_['type_name']} "
                f"({abs_['matching_eas']}/{abs_['vanished_real_ea_count']} EAs "
                f"match; absorber has {abs_['absorber_insn_count']} insns total)"
            )
    if len(vanished) > limit:
        lines.append(f"... {len(vanished) - limit} more rows suppressed")
    return "\n".join(lines)

_RAW_BLOCK_ID_RE = re.compile(r"\bblk\[(\d+)\](?!@)")


def _format_rendered_program_text(text: str | None, block_lookup: dict[int, str]) -> str:
    """Format stored rendered program text with EA-qualified block IDs."""
    if text is None:
        return "(rendered program not found)"

    def _replace(match: re.Match[str]) -> str:
        return _block_id_from_lookup(int(match.group(1)), block_lookup)

    return _RAW_BLOCK_ID_RE.sub(_replace, text)


def _format_fact_rows(rows: list[dict], columns: list[str]) -> str:
    """Format fact lifecycle table rows as compact tab-separated output."""
    if not rows:
        return "(no fact rows found)"
    lines = ["\t".join(columns)]
    for row in rows:
        values = []
        for column in columns:
            value = row.get(column)
            if column == "source_block" and value is not None:
                value = format_block_id(value, start_ea=row.get("source_ea_hex"))
            elif column == "target_block" and value is not None:
                value = format_block_id(value, start_ea=row.get("target_ea_hex"))
            values.append("" if value is None else str(value))
        lines.append("\t".join(values))
    return "\n".join(lines)


def _format_fact_trace(result: dict[str, list[dict]]) -> str:
    """Format one semantic-key fact trace."""
    lines: list[str] = []
    lines.append("observations:")
    lines.append(_format_fact_rows(
        result["observations"],
        [
            "snapshot_id",
            "fact_id",
            "kind",
            "semantic_key",
            "maturity",
            "phase",
            "source_block",
        ],
    ))
    lines.append("")
    lines.append("mappings:")
    lines.append(_format_fact_rows(
        result["mappings"],
        [
            "snapshot_id",
            "source_fact_id",
            "source_maturity",
            "target_maturity",
            "status",
            "confidence",
            "source_block",
            "target_block",
            "reason",
        ],
    ))
    return "\n".join(lines)


def _ea_trace(conn: sqlite3.Connection, ea_values: list[int], exact: bool) -> str:
    """Trace EA(s) across all snapshots and format output."""
    lines: list[str] = []
    for ea in ea_values:
        ea_hex = f"0x{ea:X}"
        if exact:
            rows = conn.execute(
                "SELECT s.id, s.label, b.serial, b.start_ea_hex, b.end_ea_hex,"
                "       b.succs, b.preds, b.type_name "
                "FROM blocks b "
                "JOIN snapshots s ON b.snapshot_id = s.id "
                "WHERE b.start_ea_hex = ? "
                "ORDER BY s.id, b.serial",
                (ea_hex,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT s.id, s.label, b.serial, b.start_ea_hex, b.end_ea_hex,"
                "       b.succs, b.preds, b.type_name "
                "FROM blocks b "
                "JOIN snapshots s ON b.snapshot_id = s.id "
                "WHERE ? BETWEEN b.start_ea_i64 AND b.end_ea_i64 - 1 "
                "ORDER BY s.id, b.serial",
                (ea,),
            ).fetchall()
        mode = "exact start_ea" if exact else "range containment"
        lines.append(f"EA {ea_hex} across snapshots ({mode}):")
        if not rows:
            lines.append("  (not found in any snapshot)")
        else:
            # Collect all snapshot IDs present in results.
            seen_snap_ids: set[int] = {r[0] for r in rows}
            # Also find ALL snapshot IDs so we can report "(not found)".
            all_snap_ids = [
                r[0]
                for r in conn.execute(
                    "SELECT id FROM snapshots ORDER BY id"
                ).fetchall()
            ]
            # Build a lookup from snap_id to its rows.
            snap_rows: dict[int, list] = {}
            for r in rows:
                snap_rows.setdefault(r[0], []).append(r)
            # Determine max label width for alignment.
            label_widths = [len(r[1]) for r in rows]
            all_labels = {
                r[0]: r[1]
                for r in conn.execute(
                    "SELECT id, label FROM snapshots ORDER BY id"
                ).fetchall()
            }
            for sid in all_snap_ids:
                label_widths.append(len(all_labels.get(sid, "")))
            max_label = max(label_widths) if label_widths else 0
            max_snap_digits = len(str(max(all_snap_ids))) if all_snap_ids else 1

            for sid in all_snap_ids:
                label = all_labels.get(sid, "unknown")
                if sid not in seen_snap_ids:
                    lines.append(
                        f"  snap {sid:>{max_snap_digits}} ({label:<{max_label}s})"
                        f" : (not found)"
                    )
                else:
                    for r in snap_rows[sid]:
                        _, _, serial, s_ea, e_ea, succs, preds, tname = r
                        lines.append(
                            f"  snap {sid:>{max_snap_digits}} ({label:<{max_label}s})"
                            f" : {format_block_id(serial, start_ea=s_ea):<24s}"
                            f" [{s_ea}..{e_ea})"
                            f" succs={succs:<12s}"
                            f" preds={preds:<12s}"
                            f" {tname}"
                        )
        if ea != ea_values[-1]:
            lines.append("")
    return "\n".join(lines)


def _short_fp(value: object) -> str:
    text = str(value or "")
    if not text:
        return ""
    if len(text) <= 32:
        return text
    return text[:29] + "..."


def _format_trace_match(row: dict) -> str:
    label = row.get("snapshot_label") or "?"
    type_name = row.get("type_name") or "?"
    start = row.get("start_ea_hex") or "?"
    end = row.get("end_ea_hex") or "?"
    insns = row.get("insn_count")
    match = row.get("match_kind") or "match"
    parts = [
        f"snap {row['snapshot_id']} ({label})",
        f"blk[{row['serial']}]",
        str(type_name),
        f"match={match}",
        f"start={start}",
        f"end={end}",
    ]
    if insns is not None:
        parts.append(f"insns={insns}")
    if row.get("matching_eas") is not None:
        parts.append(f"shared_eas={row['matching_eas']}")
    if row.get("body_fingerprint"):
        parts.append(f"body={_short_fp(row['body_fingerprint'])}")
    return " ".join(parts)


def _format_block_trace(result: dict) -> str:
    """Render block correlation trace output."""
    matches = result.get("matches") or []
    lines: list[str] = []
    if result.get("mode") == "ea":
        lines.append(
            f"BLOCK TRACE ea=0x{int(result['ea']) & 0xFFFFFFFFFFFFFFFF:X} "
            f"source={result['source']}"
        )
        if result.get("ambiguous"):
            lines.append(
                f"AMBIGUOUS: {len(matches)} matching blocks; "
                "refine with --snapshot/--serial if needed"
            )
    else:
        lines.append(
            f"BLOCK TRACE snap {result['snapshot_id']} "
            f"blk[{result['serial']}] source={result['source']}"
        )
        anchor = result.get("anchor")
        if anchor is None:
            lines.append("anchor: (not found)")
        else:
            lines.append(f"anchor: {_format_trace_match(anchor)}")

    for msg in result.get("messages") or []:
        lines.append(f"note: {msg}")

    if not matches:
        lines.append("matches: (none)")
        return "\n".join(lines)

    lines.append("matches:")
    for row in matches:
        lines.append(f"  {_format_trace_match(row)}")
    return "\n".join(lines)


def _format_lineage_row(row: dict) -> str:
    label = row.get("snapshot_label") or "?"
    origin_snapshot = row.get("origin_snapshot_id")
    origin_serial = row.get("origin_serial")
    if origin_snapshot is not None and origin_serial is not None:
        origin = f"origin=snap {origin_snapshot} blk[{origin_serial}]"
    elif row.get("origin_start_ea_hex"):
        origin = f"origin_ea={row['origin_start_ea_hex']}"
    else:
        origin = "origin=?"
    parts = [
        f"snap {row['snapshot_id']} ({label}) blk[{row['serial']}]",
        f"creation_kind={row.get('creation_kind') or '?'}",
        origin,
    ]
    if row.get("creation_reason"):
        parts.append(f"reason={row['creation_reason']}")
    if row.get("planner_block_id"):
        parts.append(f"planner={row['planner_block_id']}")
    if row.get("source_mod_type"):
        parts.append(f"mod={row['source_mod_type']}")
    return " ".join(parts)


def _format_provenance_row(row: dict) -> str:
    target = (
        f"blk[{row['target_serial']}]"
        if row.get("target_serial") is not None
        else "-"
    )
    reason = row.get("reason") or ""
    return (
        f"seq={row['seq']} pass={row['pass_name']} action={row['action']} "
        f"block=blk[{row['block_serial']}] target={target} reason={reason}"
    )


def _format_block_lineage(result: dict) -> str:
    """Render direct block lineage plus fallback provenance."""
    lines: list[str] = [
        f"BLOCK LINEAGE snap {result['snapshot_id']} blk[{result['serial']}]"
    ]
    for msg in result.get("messages") or []:
        lines.append(f"note: {msg}")

    observation = result.get("observation")
    if observation is None:
        lines.append("observation: (not found)")
    else:
        lines.append(f"observation: {_format_trace_match(observation)}")

    lineage_rows = result.get("lineage") or []
    if lineage_rows:
        lines.append("direct lineage:")
        for row in lineage_rows:
            lines.append(f"  {_format_lineage_row(row)}")
    else:
        lines.append("direct lineage: (none)")

    origins = result.get("origins") or []
    if origins:
        lines.append("origin observations:")
        for row in origins:
            lines.append(f"  {_format_trace_match(row)}")

    children = result.get("children") or []
    if children:
        lines.append("derived blocks:")
        for row in children:
            lines.append(f"  {_format_lineage_row(row)}")

    provenance = result.get("provenance") or []
    if provenance:
        lines.append("cfg_provenance:")
        for row in provenance:
            lines.append(f"  {_format_provenance_row(row)}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``python -m d810.core.diag``."""
    # Common args shared by all subcommands via parents= mechanism.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--db", default=".tmp/diag.sqlite3",
        help="Path to SQLite diagnostic database (default: .tmp/diag.sqlite3)",
    )
    common.add_argument(
        "--snapshot", type=int, default=-1,
        help="Snapshot ID (-1 = latest). Ignored when --maturity/--phase are supplied.",
    )
    common.add_argument(
        "--maturity",
        help="Resolve snapshot by maturity (for example: GLBOPT1 or MMAT_GLBOPT1)",
    )
    common.add_argument(
        "--phase",
        help="Resolve snapshot by phase (for example: post_d810, pre_d810, post_apply)",
    )

    parser = argparse.ArgumentParser(
        prog="d810.core.diag",
        description="Query MBA diagnostic snapshots.",
    )
    sub = parser.add_subparsers(dest="command")

    p_chain = sub.add_parser("chain", parents=[common], help="Trace a block chain")
    p_chain.add_argument("serials", nargs="+", type=int)

    p_var = sub.add_parser("var-writes", parents=[common],
                           help="Find writes to a stack variable")
    p_var.add_argument("stkoff", type=lambda x: int(x, 0))

    p_blk = sub.add_parser("block", parents=[common], help="Show block detail")
    p_blk.add_argument("serial", type=int)
    p_blk.add_argument("--insns", action="store_true", help="Include instructions")

    sub.add_parser("return-paths", parents=[common],
                   help="Show return path hop status")

    p_program = sub.add_parser(
        "program",
        parents=[common],
        help="Show a stored rendered linearized-program variant "
        "(optionally resolved by --maturity/--phase)",
    )
    p_program.add_argument(
        "--variant",
        default="semantic_reference_like",
        help="Rendered program variant name (default: semantic_reference_like)",
    )
    p_program.add_argument(
        "--nodes",
        action="store_true",
        help="Show rendered label nodes instead of full text",
    )

    sub.add_parser(
        "program-variants",
        parents=[common],
        help="List stored rendered-program variants for a snapshot",
    )

    p_state_local = sub.add_parser(
        "state-local",
        parents=[common],
        help="Show typed local CFG facts for one LinearizedStateDag state",
    )
    p_state_local.add_argument("state", type=lambda x: int(x, 0))

    p_block_trace = sub.add_parser(
        "block-trace",
        parents=[common],
        help=(
            "Correlate blocks by EA or by a snapshot/serial anchor. "
            "Uses block_observations when present, with old-table fallbacks."
        ),
    )
    trace_selector = p_block_trace.add_mutually_exclusive_group(required=True)
    trace_selector.add_argument(
        "--ea",
        type=lambda x: int(x, 0),
        help="Trace all blocks whose start/range/instruction EA matches",
    )
    trace_selector.add_argument(
        "--serial",
        type=int,
        help="Trace one block from the resolved --snapshot",
    )

    p_block_lineage = sub.add_parser(
        "block-lineage",
        parents=[common],
        help=(
            "Show direct block_lineage rows for one block, plus "
            "cfg_provenance fallback when lineage rows are unavailable."
        ),
    )
    p_block_lineage.add_argument(
        "--serial",
        required=True,
        type=int,
        help="Block serial in the resolved --snapshot",
    )

    p_ea = sub.add_parser(
        "ea-trace", parents=[common],
        help="Trace an EA across all snapshots (block lineage)",
    )
    p_ea.add_argument("eas", nargs="+", type=lambda x: int(x, 0),
                      help="EA values in hex (e.g. 0x1800134A5)")
    p_ea.add_argument("--exact", action="store_true",
                      help="Match start_ea exactly (default: range containment)")

    p_merge = sub.add_parser(
        "merge-causality",
        parents=[common],
        help=(
            "Diff two snapshots by EA/block lineage. For each block in FROM "
            "that is absent in TO, report its pre-disappearance shape and "
            "the inferred TO absorber (the TO block that shares the most "
            "instruction EAs). Defaults compare state_write_reconstruction_"
            "post_apply -> maturity_MMAT_GLBOPT1_post_d810, i.e. the "
            "shrink that happens inside Hex-Rays after d810 returns."
        ),
    )
    p_merge.add_argument(
        "--from-label",
        default=_MERGE_CAUSALITY_FROM_DEFAULT,
        help=f"FROM snapshot label (default: {_MERGE_CAUSALITY_FROM_DEFAULT})",
    )
    p_merge.add_argument(
        "--to-label",
        default=_MERGE_CAUSALITY_TO_DEFAULT,
        help=f"TO snapshot label (default: {_MERGE_CAUSALITY_TO_DEFAULT})",
    )
    p_merge.add_argument(
        "--only-content-class",
        default=None,
        help="Filter vanished entries to one content_class "
        "(empty, m_und_only, nop_und_only, goto_only, has_content)",
    )
    p_merge.add_argument(
        "--only-disposition",
        default=None,
        choices=("absorbed", "deleted", "synthesized_only"),
        help=(
            "Filter vanished entries by disposition: absorbed = merged into "
            "a TO block (EA lineage preserved); deleted = had real EAs in "
            "FROM but none survived in TO (unreachable-block removal); "
            "synthesized_only = no real EAs to infer lineage from."
        ),
    )
    p_merge.add_argument(
        "--limit",
        type=int,
        default=None,
        help=(
            "Show N per-block detail rows after the summary. "
            "Default is summary-only (no detail rows)."
        ),
    )

    p_watch = sub.add_parser(
        "watch-transitions",
        parents=[common],
        help=(
            "Dump watch_block_transitions rows in log-like format. "
            "Captured by DeferredGraphModifier.apply when "
            "D810_DEFERRED_WATCH_BLOCKS is set."
        ),
    )
    p_watch.add_argument(
        "--block", type=int, default=None,
        help="Filter to a single block serial (default: all watched blocks)",
    )
    p_watch.add_argument(
        "--session", default=None,
        help="Filter to a single apply_session_id (default: all sessions)",
    )
    p_watch.add_argument(
        "--transition-phase", dest="transition_phase", default=None,
        help="Filter by transition phase (init, per_mod, post_loop, "
        "post_post_apply_hook, post_optimize_local, ...)",
    )
    p_watch.add_argument(
        "--changed-only", action="store_true",
        help="Only show transitions where prev != now (mutations)",
    )
    p_watch.add_argument(
        "--sessions-only", action="store_true",
        help="List distinct apply_session_ids and row counts, no transition detail",
    )

    p_fact_obs = sub.add_parser(
        "fact-observations",
        parents=[common],
        help="Query fact_observations rows for a snapshot",
    )
    p_fact_obs.add_argument("--fact-id")
    p_fact_obs.add_argument("--kind")
    p_fact_obs.add_argument("--semantic-key")
    p_fact_obs.add_argument("--fact-maturity")
    p_fact_obs.add_argument("--limit", type=int)
    p_fact_obs.add_argument(
        "--all-snapshots",
        action="store_true",
        help="Query matching fact rows across all snapshots instead of one snapshot",
    )
    p_fact_obs.add_argument("--json", action="store_true", dest="json_output")

    p_fact_map = sub.add_parser(
        "fact-mappings",
        parents=[common],
        help="Query fact_mappings rows for a snapshot",
    )
    p_fact_map.add_argument("--source-fact-id")
    p_fact_map.add_argument("--status")
    p_fact_map.add_argument("--source-maturity")
    p_fact_map.add_argument("--target-maturity")
    p_fact_map.add_argument("--limit", type=int)
    p_fact_map.add_argument(
        "--all-snapshots",
        action="store_true",
        help="Query matching fact rows across all snapshots instead of one snapshot",
    )
    p_fact_map.add_argument("--json", action="store_true", dest="json_output")

    p_fact_cons = sub.add_parser(
        "fact-consumers",
        parents=[common],
        help="Query fact_consumers rows for a snapshot",
    )
    p_fact_cons.add_argument("--consumer")
    p_fact_cons.add_argument("--strategy")
    p_fact_cons.add_argument("--fact-id")
    p_fact_cons.add_argument("--decision")
    p_fact_cons.add_argument("--limit", type=int)
    p_fact_cons.add_argument(
        "--all-snapshots",
        action="store_true",
        help="Query matching fact rows across all snapshots instead of one snapshot",
    )
    p_fact_cons.add_argument("--json", action="store_true", dest="json_output")

    p_fact_conf = sub.add_parser(
        "fact-conflicts",
        parents=[common],
        help="Query fact_conflicts rows for a snapshot",
    )
    p_fact_conf.add_argument("--fact-id")
    p_fact_conf.add_argument("--conflict-kind")
    p_fact_conf.add_argument("--fact-maturity")
    p_fact_conf.add_argument("--limit", type=int)
    p_fact_conf.add_argument(
        "--all-snapshots",
        action="store_true",
        help="Query matching fact rows across all snapshots instead of one snapshot",
    )
    p_fact_conf.add_argument("--json", action="store_true", dest="json_output")

    p_fact_trace = sub.add_parser(
        "fact-trace",
        parents=[common],
        help="Trace one fact semantic key across observations and mappings",
    )
    p_fact_trace.add_argument("--semantic-key", required=True)
    p_fact_trace.add_argument("--kind")
    p_fact_trace.add_argument("--json", action="store_true", dest="json_output")

    p_fact_diff = sub.add_parser(
        "fact-diff",
        parents=[common],
        help="Compare fact lifecycle state between two maturities",
    )
    p_fact_diff.add_argument("--from-maturity", required=True)
    p_fact_diff.add_argument("--to-maturity", required=True)
    p_fact_diff.add_argument("--kind")
    p_fact_diff.add_argument("--semantic-key")
    p_fact_diff.add_argument("--json", action="store_true", dest="json_output")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    conn = sqlite3.connect(args.db)
    snap_id = _resolve_snapshot_id(
        conn,
        args.snapshot,
        maturity=getattr(args, "maturity", None),
        phase=getattr(args, "phase", None),
    )

    if args.command == "chain":
        print(_snapshot_header(conn, snap_id))
        result = chain(conn, snap_id, args.serials)
        print(_format_chain(result, _block_identity_lookup(conn, snap_id)))
    elif args.command == "var-writes":
        result = var_writes(conn, snap_id, args.stkoff)
        print(_format_var_writes(result))
    elif args.command == "block":
        print(_snapshot_header(conn, snap_id))
        result = block_detail(conn, snap_id, args.serial)
        print(_format_block(
            result,
            show_insns=args.insns,
            block_lookup=_block_identity_lookup(conn, snap_id),
        ))
    elif args.command == "return-paths":
        result = return_paths(conn, snap_id)
        print(_format_return_paths(result, _block_identity_lookup(conn, snap_id)))
    elif args.command == "program":
        print(_snapshot_header(conn, snap_id))
        if args.nodes:
            print(
                _format_rendered_program_nodes(
                    rendered_program_nodes(conn, snap_id, args.variant),
                    _block_identity_lookup(conn, snap_id),
                )
            )
        else:
            result = rendered_program_text(conn, snap_id, args.variant)
            print(_format_rendered_program_text(
                result,
                _block_identity_lookup(conn, snap_id),
            ))
    elif args.command == "program-variants":
        print(_snapshot_header(conn, snap_id))
        print(
            _format_rendered_program_variants(
                rendered_program_variants(conn, snap_id)
            )
        )
    elif args.command == "state-local":
        print(_snapshot_header(conn, snap_id))
        print(
            _format_state_local(
                state_local(conn, snap_id, args.state),
                state=args.state,
            )
        )
    elif args.command == "block-trace":
        if args.ea is not None:
            print(_format_block_trace(block_trace_by_ea(conn, args.ea)))
        else:
            print(
                _format_block_trace(
                    block_trace_by_serial(conn, snap_id, args.serial)
                )
            )
    elif args.command == "block-lineage":
        print(_format_block_lineage(block_lineage(conn, snap_id, args.serial)))
    elif args.command == "ea-trace":
        print(_ea_trace(conn, args.eas, args.exact))
    elif args.command == "merge-causality":
        from_snap = _resolve_snapshot_by_label(conn, args.from_label)
        to_snap = _resolve_snapshot_by_label(conn, args.to_label)
        result = merge_causality(conn, from_snap, to_snap)
        filtered = list(result["vanished"])
        if args.only_content_class:
            filtered = [
                r for r in filtered
                if r["content_class"] == args.only_content_class
            ]
        if args.only_disposition:
            filtered = [
                r for r in filtered
                if r["disposition"] == args.only_disposition
            ]
        result = dict(result)
        result["vanished"] = filtered
        print(_format_merge_causality(result, limit=args.limit))
    elif args.command == "watch-transitions":
        print(_format_watch_transitions(
            conn,
            block=args.block,
            session=args.session,
            phase=args.transition_phase,
            changed_only=args.changed_only,
            sessions_only=args.sessions_only,
        ))
    elif args.command == "fact-observations":
        fact_snapshot_id = None if args.all_snapshots else snap_id
        rows = fact_observations(
            conn,
            fact_snapshot_id,
            fact_id=args.fact_id,
            kind=args.kind,
            semantic_key=args.semantic_key,
            maturity=args.fact_maturity,
            limit=args.limit,
        )
        if args.json_output:
            print(json.dumps(rows, indent=2, sort_keys=True))
        else:
            print("all snapshots" if args.all_snapshots else _snapshot_header(conn, snap_id))
            columns = [
                "fact_id",
                "kind",
                "semantic_key",
                "maturity",
                "phase",
                "confidence",
                "source_block",
            ]
            if args.all_snapshots:
                columns.insert(0, "snapshot_id")
            print(_format_fact_rows(
                rows,
                columns,
            ))
    elif args.command == "fact-mappings":
        fact_snapshot_id = None if args.all_snapshots else snap_id
        rows = fact_mappings(
            conn,
            fact_snapshot_id,
            source_fact_id=args.source_fact_id,
            status=args.status,
            source_maturity=args.source_maturity,
            target_maturity=args.target_maturity,
            limit=args.limit,
        )
        if args.json_output:
            print(json.dumps(rows, indent=2, sort_keys=True))
        else:
            print("all snapshots" if args.all_snapshots else _snapshot_header(conn, snap_id))
            columns = [
                "source_fact_id",
                "target_fact_id",
                "source_maturity",
                "target_maturity",
                "status",
                "confidence",
                "target_block",
            ]
            if args.all_snapshots:
                columns.insert(0, "snapshot_id")
            print(_format_fact_rows(
                rows,
                columns,
            ))
    elif args.command == "fact-consumers":
        fact_snapshot_id = None if args.all_snapshots else snap_id
        rows = fact_consumers(
            conn,
            fact_snapshot_id,
            consumer=args.consumer,
            strategy=args.strategy,
            fact_id=args.fact_id,
            decision=args.decision,
            limit=args.limit,
        )
        if args.json_output:
            print(json.dumps(rows, indent=2, sort_keys=True))
        else:
            print("all snapshots" if args.all_snapshots else _snapshot_header(conn, snap_id))
            columns = ["consumer", "strategy", "fact_id", "maturity", "decision", "reason"]
            if args.all_snapshots:
                columns.insert(0, "snapshot_id")
            print(_format_fact_rows(
                rows,
                columns,
            ))
    elif args.command == "fact-conflicts":
        fact_snapshot_id = None if args.all_snapshots else snap_id
        rows = fact_conflicts(
            conn,
            fact_snapshot_id,
            fact_id=args.fact_id,
            conflict_kind=args.conflict_kind,
            maturity=args.fact_maturity,
            limit=args.limit,
        )
        if args.json_output:
            print(json.dumps(rows, indent=2, sort_keys=True))
        else:
            print("all snapshots" if args.all_snapshots else _snapshot_header(conn, snap_id))
            columns = [
                "conflict_id",
                "fact_id",
                "other_fact_id",
                "maturity",
                "conflict_kind",
                "reason",
            ]
            if args.all_snapshots:
                columns.insert(0, "snapshot_id")
            print(_format_fact_rows(
                rows,
                columns,
            ))
    elif args.command == "fact-trace":
        result = fact_trace(conn, semantic_key=args.semantic_key, kind=args.kind)
        if args.json_output:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(_format_fact_trace(result))
    elif args.command == "fact-diff":
        rows = fact_diff(
            conn,
            source_maturity=_normalize_maturity_name(args.from_maturity)
            or args.from_maturity,
            target_maturity=_normalize_maturity_name(args.to_maturity)
            or args.to_maturity,
            kind=args.kind,
            semantic_key=args.semantic_key,
        )
        if args.json_output:
            print(json.dumps(rows, indent=2, sort_keys=True))
        else:
            columns = [
                "source_fact_id",
                "target_fact_id",
                "semantic_key",
                "source_maturity",
                "target_maturity",
                "status",
                "source_block",
                "target_block",
            ]
            print(_format_fact_rows(rows, columns))

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
