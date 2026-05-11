"""CLI for querying MBA diagnostic snapshots.

Usage::

    python -m d810.diagnostics chain --db path.sqlite3 131 174 176 200 23 32 62 206 207 218
    python -m d810.diagnostics var-writes --db path.sqlite3 0x7F0
    python -m d810.diagnostics block --db path.sqlite3 206 --insns
    python -m d810.diagnostics return-paths --db path.sqlite3 --snapshot -1
    python -m d810.diagnostics program --db path.sqlite3 --snapshot -1
    python -m d810.diagnostics program --db path.sqlite3 --snapshot -1 --nodes
    python -m d810.diagnostics program --db path.sqlite3 --snapshot 12 --variant semantic_reference_like
    python -m d810.diagnostics program --db path.sqlite3 --maturity GLBOPT1 --phase post_d810
    python -m d810.diagnostics state-local --db path.sqlite3 --snapshot 6 0x298372CC
    python -m d810.diagnostics block-trace --db path.sqlite3 --ea 0x1800134A5
    python -m d810.diagnostics block-trace --db path.sqlite3 --snapshot 12 --serial 206
    python -m d810.diagnostics block-lineage --db path.sqlite3 --snapshot 12 --serial 206
    PYTHONPATH=src python3 -m d810.diagnostics program \\
      --db /Users/mahmoud/src/idapro/d810/.worktrees/state-label-linearization/.tmp/logs/d810_logs/0000000180012b60_1774805543_33.diag.sqlite3 \\
      --maturity GLBOPT1 \\
      --phase post_d810 \\
      --variant semantic_reference_like
    python -m d810.diagnostics program-variants --db path.sqlite3 --snapshot -1
    python -m d810.diagnostics ea-trace --db path.sqlite3 0x1800134A5

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
import importlib
import json
import re
import sqlite3
import sys
from pathlib import Path

from d810.core.typing import Any, Iterable, Mapping

from d810.recon.flow.alternate_correlation import (
    AlternateCorrelation,
    correlate_collapsed_edges,
    persist_alternate_correlations,
)
from d810.core.diag.alternate_selection import (
    AlternateSelection,
    persist_alternate_selections,
    select_alternate_edges,
)
from d810.core.diag.bst_resolution import (
    BstResolution,
    parse_bst_intervals,
    parse_latest_bst_intervals_from_log,
    persist_bst_resolutions,
    resolve_state_transition_facts,
)
from d810.recon.flow.edge_diagnostics import (
    EdgeDiagnostic,
    classify_dag_edges,
    persist_edge_diagnostics,
)
from d810.core.diag.formatting import format_block_id
from d810.diagnostics.query import (
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


def _state_write_trace(
    conn: sqlite3.Connection,
    *,
    block: int,
) -> dict[str, Any]:
    """Return state-write anchor observations + rewrite mappings for ``block``.

    Looks up rows by ``json_extract(payload, '$.block_serial')`` so the
    query works against the canonical fact-observation payload regardless
    of which collector emitted the row.
    """
    conn.row_factory = _dict_factory_for_state_writes  # type: ignore[assignment]
    observations = conn.execute(
        "SELECT * FROM fact_observations "
        "WHERE kind='StateWriteAnchorFact' "
        "  AND json_extract(payload, '$.block_serial')=? "
        "ORDER BY snapshot_id, maturity, fact_id",
        (int(block),),
    ).fetchall()
    if not observations:
        return {"block": int(block), "observations": [], "mappings": []}
    fact_ids = sorted({row["fact_id"] for row in observations})
    placeholders = ",".join("?" for _ in fact_ids)
    mappings = conn.execute(
        f"SELECT * FROM fact_mappings "
        f"WHERE source_fact_id IN ({placeholders}) "
        f"ORDER BY snapshot_id, target_maturity, mapping_index",
        fact_ids,
    ).fetchall()
    return {
        "block": int(block),
        "observations": observations,
        "mappings": mappings,
    }


def _state_write_rewrites(
    conn: sqlite3.Connection,
    *,
    block: int | None,
) -> list[dict[str, Any]]:
    """Return all STATE_CONST_REWRITTEN mapping rows.

    Each row carries original_state_const + rewritten_state_const +
    instruction_ea_hex in its payload, joined with the originating
    observation's source maturity for display.
    """
    conn.row_factory = _dict_factory_for_state_writes  # type: ignore[assignment]
    base_sql = (
        "SELECT * FROM fact_mappings "
        "WHERE status='STATE_CONST_REWRITTEN'"
    )
    params: list[Any] = []
    if block is not None:
        base_sql += " AND json_extract(payload, '$.block_serial')=?"
        params.append(int(block))
    base_sql += " ORDER BY snapshot_id, target_maturity, mapping_index"
    return conn.execute(base_sql, params).fetchall()


def _dict_factory_for_state_writes(cursor: sqlite3.Cursor, row: tuple) -> dict:
    return {col[0]: row[i] for i, col in enumerate(cursor.description)}


def _format_state_write_trace(result: dict[str, Any]) -> str:
    block = result["block"]
    observations = result.get("observations") or []
    mappings = result.get("mappings") or []
    lines = [f"State-write anchor trace for blk[{block}]"]
    if not observations:
        lines.append("  (no StateWriteAnchorFact observations recorded)")
        return "\n".join(lines)

    lines.append("observations:")
    for row in observations:
        try:
            payload = json.loads(row.get("payload") or "{}")
        except json.JSONDecodeError:
            payload = {}
        ea_hex = (
            payload.get("instruction_ea_hex")
            or row.get("source_ea_hex")
            or "?"
        )
        const_hex = payload.get("state_const_hex") or "?"
        stkoff_hex = payload.get("state_var_stkoff_hex") or "?"
        dest_var = payload.get("dest_var_signature") or ""
        maturity = row.get("maturity") or "?"
        phase = row.get("phase") or "?"
        lines.append(
            f"  [{maturity:<20s} {phase:<12s}] "
            f"const={const_hex} stkoff={stkoff_hex} "
            f"dest={dest_var} ea={ea_hex} fact={row.get('fact_id')}"
        )

    if mappings:
        lines.append("mappings:")
        for row in mappings:
            try:
                payload = json.loads(row.get("payload") or "{}")
            except json.JSONDecodeError:
                payload = {}
            status = row.get("status") or "?"
            src_mat = row.get("source_maturity") or "?"
            tgt_mat = row.get("target_maturity") or "?"
            orig = payload.get("original_state_const_hex") or "?"
            new = payload.get("rewritten_state_const_hex")
            transition = f"{src_mat} -> {tgt_mat}"
            if status == "STATE_CONST_REWRITTEN" and new is not None:
                lines.append(
                    f"  [{transition}] {status}: {orig} -> {new}  "
                    f"reason={row.get('reason')}"
                )
            else:
                lines.append(
                    f"  [{transition}] {status} "
                    f"reason={row.get('reason')}"
                )
    else:
        lines.append("mappings: (none)")
    return "\n".join(lines)


def _format_state_write_rewrites(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "(no STATE_CONST_REWRITTEN mappings recorded)"
    lines = [
        "block\toriginal_const\trewritten_const\tsource_maturity\ttarget_maturity\tinstruction_ea\tstkoff",
    ]
    for row in rows:
        try:
            payload = json.loads(row.get("payload") or "{}")
        except json.JSONDecodeError:
            payload = {}
        lines.append(
            "\t".join((
                str(payload.get("block_serial", "?")),
                str(payload.get("original_state_const_hex", "?")),
                str(payload.get("rewritten_state_const_hex", "?")),
                str(row.get("source_maturity") or "?"),
                str(row.get("target_maturity") or "?"),
                str(payload.get("instruction_ea_hex", "?")),
                str(payload.get("state_var_stkoff_hex", "?")),
            ))
        )
    return "\n".join(lines)


def _resolve_oracle_snap_ids(
    conn,
    *,
    snap17_labels: tuple[str, ...],
    snap18_labels: tuple[str, ...],
) -> tuple[int | None, int | None]:
    """Resolve snap17 and snap18 IDs.

    Snap18 is resolved first via MAX(id) over its preference labels.
    Snap17 is then resolved as the highest id whose label is in the
    snap17 preference list AND id < snap18. This handles the common
    case where a GLBOPT1 pipeline runs more than once and creates
    multiple `post_bundle_stabilize` rows whose latest copy lives
    AFTER the actual `GLBOPT1_post_d810` boundary.
    """

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


def _oracle_persist_features(
    conn,
    *,
    func_ea_hex: str,
    func_ea_i64: int,
    features: Iterable[Any],
) -> int:
    """Scoped upsert of region_shape_features.

    Uses INSERT OR REPLACE keyed by the table's primary key
    (func_ea_hex, source, snapshot_id, feature). Never deletes rows
    outside the (source, snapshot_id, feature) tuples being written.
    """
    n = 0
    for f in features:
        conn.execute(
            "INSERT OR REPLACE INTO region_shape_features "
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
                json.dumps(f.evidence, sort_keys=True),
            ),
        )
        n += 1
    conn.commit()
    return n


def _oracle_persist_dce_causes(
    conn,
    *,
    func_ea_hex: str,
    func_ea_i64: int,
    causes: Iterable[Mapping[str, Any]],
) -> int:
    """Scoped upsert of terminal_tail_dce_causes.

    Each cause row carries an ``evidence`` mapping (dict-like) which is
    serialized internally via ``json.dumps(..., sort_keys=True)``. This
    matches the ``_oracle_persist_features`` contract: callers pass a
    structured value, not a pre-serialized string.

    Primary key is (func_ea_hex, byte_index); INSERT OR REPLACE
    naturally upserts per-byte without touching unrelated rows.
    """
    n = 0
    for c in causes:
        conn.execute(
            "INSERT OR REPLACE INTO terminal_tail_dce_causes "
            "(func_ea_hex, func_ea_i64, byte_index, "
            " last_present_snapshot_id, first_missing_snapshot_id, "
            " last_block_serial, last_ea_hex, "
            " cause, recommended_action, rationale, evidence_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                func_ea_hex,
                func_ea_i64,
                int(c["byte_index"]),
                c.get("last_present_snapshot_id"),
                c.get("first_missing_snapshot_id"),
                c.get("last_block_serial"),
                c.get("last_ea_hex"),
                str(c["cause"]),
                str(c["recommended_action"]),
                str(c["rationale"]),
                json.dumps(c["evidence"], sort_keys=True),
            ),
        )
        n += 1
    conn.commit()
    return n


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``python -m d810.diagnostics``."""
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
        prog="d810.diagnostics",
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

    p_state_write_trace = sub.add_parser(
        "state-write-trace",
        parents=[common],
        help=(
            "Trace state-write anchor facts (LOCOPT-pre original + later "
            "rewrites) for one block. Shows the original "
            "'mov #const, stkvar' at MMAT_LOCOPT pre_d810 and any later "
            "mappings with status STATE_CONST_REWRITTEN."
        ),
    )
    p_state_write_trace.add_argument(
        "--block",
        required=True,
        type=int,
        help="Block serial whose state-write anchors should be traced",
    )
    p_state_write_trace.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
    )

    p_state_write_rewrites = sub.add_parser(
        "state-write-rewrites",
        parents=[common],
        help=(
            "List every block whose state-write was rewritten between "
            "an earlier maturity (e.g. MMAT_LOCOPT pre_d810) and a "
            "later maturity, with original_const -> new_const and "
            "the maturity transition that recorded the change."
        ),
    )
    p_state_write_rewrites.add_argument(
        "--block",
        type=int,
        default=None,
        help="Filter to one block serial",
    )
    p_state_write_rewrites.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
    )

    p_dag_edge_diag = sub.add_parser(
        "dag-edge-diagnostics",
        parents=[common],
        help=(
            "Classify recon-time dag_edges by correlating them with "
            "StateWriteAnchor STATE_CONST_REWRITTEN mappings, "
            "StateTransitionAnchor transit chains, and "
            "TerminalByteEmitterFact destinations. "
            "Observability-only: classifications never affect recon "
            "edge target selection or HCC behavior."
        ),
    )
    p_dag_edge_diag.add_argument(
        "--snap-id",
        type=int,
        default=None,
        help=(
            "Snapshot id to classify (default: every snapshot that has "
            "dag_edges rows)"
        ),
    )
    p_dag_edge_diag.add_argument(
        "--kind",
        choices=("all", "terminal_tail"),
        default="all",
        help="Restrict output to terminal-tail edges only",
    )
    p_dag_edge_diag.add_argument(
        "--classification",
        default=None,
        help=(
            "Filter to one classification "
            "(LOCOPT_REWRITTEN_SOURCE / TARGET_UNRESOLVED_AFTER_REWRITE "
            "/ COLLAPSED_TO_REWRITTEN_TARGET / SPURIOUS_CONDITIONAL_ARM "
            "/ BENIGN)"
        ),
    )
    p_dag_edge_diag.add_argument(
        "--persist",
        action="store_true",
        help=(
            "Persist classifications into dag_edge_diagnostics table "
            "(idempotent: existing rows for the snapshot are replaced)"
        ),
    )
    p_dag_edge_diag.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
    )

    p_bst_resolve = sub.add_parser(
        "state-transition-bst-resolutions",
        parents=[common],
        help=(
            "Enrich LOCOPT-pre StateTransitionAnchorFacts with the "
            "single-hop BST routing for their source_state_const, "
            "and (when the resolved handler block has a canonical "
            "state-write at LOCOPT-pre) the next state constant. "
            "Observability-only; no recon edge target selection or "
            "HCC behavior depends on these rows."
        ),
    )
    p_bst_resolve.add_argument(
        "--bst-log",
        default=None,
        help=(
            "Path to a d810.log containing INTERVAL_DISPATCHER_ROWS "
            "(default: .tmp/logs/d810_logs/d810.log relative to cwd)"
        ),
    )
    p_bst_resolve.add_argument(
        "--snap-id",
        type=int,
        default=None,
        help=(
            "LOCOPT-pre snapshot id to enrich (default: pick the "
            "first snapshot whose label contains MMAT_LOCOPT and "
            "phase pre_d810)"
        ),
    )
    p_bst_resolve.add_argument(
        "--block",
        type=int,
        default=None,
        help="Filter output to one source block",
    )
    p_bst_resolve.add_argument(
        "--persist",
        action="store_true",
        help=(
            "Persist resolutions into "
            "state_transition_bst_resolutions table (idempotent)"
        ),
    )
    p_bst_resolve.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
    )

    p_alt_corr = sub.add_parser(
        "dag-edge-alternate-correlations",
        parents=[common],
        help=(
            "Pair COLLAPSED_TO_REWRITTEN_TARGET dag_edges rows with "
            "alternate already-persisted edges from RANGE_BACKED "
            "sibling nodes whose blocks overlap the collapsed source. "
            "Observability-only."
        ),
    )
    p_alt_corr.add_argument(
        "--snap-id",
        type=int,
        default=None,
        help="Snapshot id to correlate (default: every snapshot with "
             "COLLAPSED_TO_REWRITTEN_TARGET diagnostics)",
    )
    p_alt_corr.add_argument(
        "--collapsed-edge",
        type=int,
        default=None,
        help="Filter to one collapsed edge id",
    )
    p_alt_corr.add_argument(
        "--persist",
        action="store_true",
        help="Persist correlations into dag_edge_alternate_correlations",
    )
    p_alt_corr.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
    )

    p_alt_sel = sub.add_parser(
        "dag-edge-alternate-selections",
        parents=[common],
        help=(
            "Decide which correlated alternate edges preserve the "
            "terminal-tail byte progression: bounded BFS (depth <= 2) "
            "from each alternate target through dag_edges to find a "
            "later terminal_tail TerminalByteEmitterFact byte_index. "
            "Observability-only."
        ),
    )
    p_alt_sel.add_argument(
        "--snap-id",
        type=int,
        default=None,
        help="Snapshot id to select for (default: every snapshot with "
             "dag_edge_alternate_correlations rows)",
    )
    p_alt_sel.add_argument(
        "--collapsed-edge",
        type=int,
        default=None,
        help="Filter to one collapsed edge id",
    )
    p_alt_sel.add_argument(
        "--max-depth",
        type=int,
        default=4,
        help=(
            "Maximum BFS depth from the alternate target (default: 4 -- "
            "covers the typical 4-hop OLLVM byte-tail chain "
            "byteN_state -> transit -> byte(N+1)_state -> ... -> "
            "byte(M)_emit_owner)"
        ),
    )
    p_alt_sel.add_argument(
        "--persist",
        action="store_true",
        help="Persist into dag_edge_alternate_selections",
    )
    p_alt_sel.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
    )

    p_region_shape = sub.add_parser(
        "region-shape",
        parents=[common],
        help="List persisted region_shape_features rows for a function.",
    )
    p_region_shape.add_argument(
        "--func-ea",
        required=True,
        help="Function EA in hex (e.g. 0x0000000180012df0).",
    )
    p_region_shape.add_argument(
        "--source",
        choices=("REF", "D810_SNAPSHOT"),
        default=None,
        help="Filter by source (REF or D810_SNAPSHOT).",
    )
    p_region_shape.add_argument(
        "--snapshot-id",
        type=int,
        default=None,
        help="Filter by snapshot_id.",
    )
    p_region_shape.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Emit JSON instead of a table.",
    )

    p_term_dce = sub.add_parser(
        "terminal-tail-dce",
        parents=[common],
        help="List persisted terminal_tail_dce_causes rows.",
    )
    p_term_dce.add_argument("--func-ea", required=True)
    p_term_dce.add_argument("--byte-index", type=int, default=None)
    p_term_dce.add_argument(
        "--json", action="store_true", dest="json_output",
    )

    p_hcc_trace = sub.add_parser(
        "hcc-byte-cascade-trace",
        parents=[common],
        help=(
            "Parse HCC_BYTE_CASCADE_TRACE_ROW lines from a d810 log; optionally"
            " cross-reference %%var_190.8+#k.8 references per snapshot from"
            " the diag DB."
        ),
    )
    p_hcc_trace.add_argument(
        "--log",
        required=True,
        help="Path to d810.log containing HCC_BYTE_CASCADE_TRACE_ROW lines",
    )
    p_hcc_trace.add_argument(
        "--func-label",
        default=None,
        help="Optional function label rendered in the report title",
    )
    p_hcc_trace.add_argument(
        "--json", action="store_true", dest="json_output",
    )

    p_tt_audit = sub.add_parser(
        "terminal-tail-audit",
        parents=[common],
        help=(
            "Audit TerminalByteEmitterFact rows in the diag DB: byte_emit[k]"
            " timeline + first-loss report, optionally with intermediate-"
            "snapshot loss localization."
        ),
    )
    p_tt_audit.add_argument(
        "--show-edges", action="store_true",
        help="Print every observation with snap / maturity / phase / role / src_form",
    )
    p_tt_audit.add_argument(
        "--localize", action="store_true",
        help="Run intermediate-snapshot loss localization (GLBOPT1 only)",
    )
    p_tt_audit.add_argument(
        "--initial-snap-id", type=int, default=5,
        help="Snapshot id of the initial pre-D810 state (default: 5)",
    )

    p_reconcile = sub.add_parser(
        "redirect-reconcile",
        parents=[common],
        help=(
            "Reconcile resolver predictions against live"
            " dispatcher_trampoline_skip emissions. Reads a diag SQLite +"
            " d810.log and prints the AGREE_FULL / HCC_DUP / HCC_REGION_* /"
            " DISAGREE_TARGET / STRATEGY_ONLY_STATE_NOT_IN_BST / BOTH_NONE"
            " bucket breakdown (uee-32r3 Piece 5.5)."
        ),
    )
    p_reconcile.add_argument(
        "--log", required=True, help="Path to d810.log",
    )
    p_reconcile.add_argument(
        "--snap-id", type=int, required=True,
        help="Snapshot ID to reconcile (e.g. MMAT_GLBOPT1 pre_d810)",
    )
    p_reconcile.add_argument(
        "--state-var-stkoff", default="0x3C",
        help="State variable stack offset (hex). Default 0x3C for sub_7FFD.",
    )
    p_reconcile.add_argument(
        "--min-dispatcher-preds", type=int, default=5,
        help="Minimum in-degree to count a block as dispatcher region.",
    )
    p_reconcile.add_argument(
        "--show-edges", action="store_true",
        help="Print every edge with bucket and evidence.",
    )

    p_egress = sub.add_parser(
        "cascade-egress-plan",
        parents=[common],
        help=(
            "Read-only terminal-tail cascade egress plan: resolves"
            " TerminalByteEmitterFact rows from an earlier fact snapshot"
            " into a target CFG snapshot (usually post_bundle_stabilize)"
            " and reports per-byte rewire feasibility."
        ),
    )
    p_egress.add_argument(
        "--fact-snapshot-id", type=int, default=None,
        help="Snapshot containing TerminalByteEmitterFact rows (default: auto)",
    )
    p_egress.add_argument(
        "--target-snapshot-id", type=int, default=None,
        help="CFG snapshot to evaluate, usually post_bundle_stabilize (default: auto)",
    )

    p_return_ledger = sub.add_parser(
        "return-ledger",
        parents=[common],
        help=(
            "Trace return paths to BLT_STOP: pull return-slot writers,"
            " v660 family map, VALRANGES, BFS reachability, and correlate"
            " with AFTER pseudocode returns."
        ),
    )
    p_return_ledger.add_argument(
        "--dump", type=Path, default=None,
        help="Optional Hodur dump file (OUTPUT.txt) for AFTER-return correlation.",
    )
    p_return_ledger.add_argument(
        "--snapshot-id", type=int, default=None,
        help=(
            "Snapshot id to use; default = last pre-gut_and_wire post_apply"
            " with > 200 blocks."
        ),
    )
    p_return_ledger.add_argument(
        "--list-snapshots", action="store_true",
        help="List every snapshot in the DB and exit.",
    )
    p_return_ledger.add_argument(
        "--json", action="store_true", dest="json_output",
    )

    p_gate_audit = sub.add_parser(
        "gate-audit",
        help=(
            "Parse d810 debug logs and produce a gate outcome summary report."
            " Exit code 0 if zero untracked bypasses, 1 otherwise."
        ),
    )
    p_gate_audit.add_argument(
        "log_path",
        nargs="?",
        default=None,
        help=(
            "Path to a log file or directory containing *.log files. Defaults"
            " to ~/.idapro/logs/d810_logs/"
        ),
    )
    p_gate_audit.add_argument(
        "--strict",
        action="store_true",
        help="Fail on ANY bypass, not just untracked ones.",
    )
    p_gate_audit.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output machine-readable JSON instead of a text table.",
    )

    importlib.import_module(
        "d810.cfg.region_oracle_cli"
    ).register_region_diff_parser(sub, common)

    from d810.diagnostics.dump_after import register_parser as _register_dump_after
    from d810.diagnostics.inspect_state_node import (
        register_parser as _register_inspect_state_node,
    )
    from d810.diagnostics.residual_worksheet import (
        register_parser as _register_residual_worksheet,
    )

    _register_dump_after(sub)
    _register_inspect_state_node(sub)
    _register_residual_worksheet(sub)

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    # dump-after is a pure text parser; no diag DB connection needed.
    if args.command == "dump-after":
        from d810.diagnostics.dump_after import run as _run_dump_after

        return _run_dump_after(args)

    # inspect-state-node opens its own DB on a path that may differ from
    # the heuristic default, so it does not flow through the common
    # connection block.
    if args.command == "inspect-state-node":
        from d810.diagnostics.inspect_state_node import run as _run_inspect_state_node

        return _run_inspect_state_node(args)

    # residual-worksheet uses --diag-db / --recon-db, opens its own
    # connections and may auto-discover paths; bypass the common block.
    if args.command == "residual-worksheet":
        from d810.diagnostics.residual_worksheet import run as _run_residual_worksheet

        return _run_residual_worksheet(args)

    # gate-audit reads d810.log only; no diag DB connection needed.
    if args.command == "gate-audit":
        from d810.diagnostics.gate_audit import run_audit as _gate_run_audit

        default_log_dir = Path.home() / ".idapro" / "logs" / "d810_logs"
        log_path = Path(args.log_path) if args.log_path else default_log_dir
        text, rc = _gate_run_audit(
            log_path,
            strict=args.strict,
            as_json=args.json_output,
        )
        sys.stdout.write(text)
        return rc

    conn = sqlite3.connect(args.db)
    # region-shape is function-EA-scoped, not snapshot-scoped; the rows
    # carry snapshot_id directly and may not require any snapshots row
    # to exist (e.g. REF-only persistence ahead of D810 runs).
    if args.command in (
        "region-shape",
        "terminal-tail-dce",
        "region-diff",
        "hcc-byte-cascade-trace",
        "terminal-tail-audit",
        "redirect-reconcile",
        "return-ledger",
        "cascade-egress-plan",
    ):
        # region-diff is function-EA-scoped; it resolves its own snap IDs
        # via labels and tolerates a sparse / schemaless diag DB by
        # returning a structured error.
        snap_id = -1
    else:
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
    elif args.command == "state-write-trace":
        result = _state_write_trace(conn, block=args.block)
        if args.json_output:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(_format_state_write_trace(result))
    elif args.command == "state-write-rewrites":
        rows = _state_write_rewrites(conn, block=args.block)
        if args.json_output:
            print(json.dumps(rows, indent=2, sort_keys=True))
        else:
            print(_format_state_write_rewrites(rows))
    elif args.command == "dag-edge-diagnostics":
        if args.snap_id is not None:
            snap_ids = [int(args.snap_id)]
        else:
            snap_ids = [
                int(r[0])
                for r in conn.execute(
                    "SELECT DISTINCT snapshot_id FROM dag_edges ORDER BY snapshot_id"
                ).fetchall()
            ]
        all_diagnostics: list[EdgeDiagnostic] = []
        for snap in snap_ids:
            all_diagnostics.extend(classify_dag_edges(conn, snap))
        if args.persist:
            persist_edge_diagnostics(conn, all_diagnostics)
        filtered = all_diagnostics
        if args.kind == "terminal_tail":
            filtered = [d for d in filtered if d.is_terminal_tail]
        if args.classification:
            filtered = [
                d for d in filtered
                if d.classification == args.classification
            ]
        if args.json_output:
            print(
                json.dumps(
                    [
                        {
                            "snapshot_id": d.snapshot_id,
                            "edge_id": d.edge_id,
                            "classification": d.classification,
                            "source_state_hex": d.source_state_hex,
                            "target_state_hex": d.target_state_hex,
                            "edge_kind": d.edge_kind,
                            "is_terminal_tail": d.is_terminal_tail,
                            "original_state_const": d.original_state_const,
                            "rewritten_state_const": d.rewritten_state_const,
                            "related_fact_ids": list(d.related_fact_ids),
                            "reason": d.reason,
                        }
                        for d in filtered
                    ],
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            header = (
                f"snap\tedge\tterm\tkind\tclass\t"
                f"source\ttarget\torig\trewritten\treason"
            )
            print(header)
            for d in filtered:
                print(
                    "\t".join(
                        (
                            str(d.snapshot_id),
                            str(d.edge_id),
                            "T" if d.is_terminal_tail else "-",
                            d.edge_kind,
                            d.classification,
                            d.source_state_hex or "<null>",
                            d.target_state_hex or "<null>",
                            d.original_state_const or "-",
                            d.rewritten_state_const or "-",
                            d.reason,
                        )
                    )
                )
            print(
                f"\n# {len(filtered)} edge(s) shown "
                f"(persisted={args.persist}, filter={args.kind}/"
                f"{args.classification or 'any'})"
            )
    elif args.command == "state-transition-bst-resolutions":
        bst_log = args.bst_log or ".tmp/logs/d810_logs/d810.log"
        try:
            intervals = parse_latest_bst_intervals_from_log(bst_log)
        except FileNotFoundError:
            intervals = ()
        if args.snap_id is not None:
            locopt_snap = int(args.snap_id)
        else:
            row = conn.execute(
                "SELECT id FROM snapshots "
                "WHERE label LIKE '%MMAT_LOCOPT%pre_d810%' "
                "ORDER BY id LIMIT 1"
            ).fetchone()
            if row is None:
                print(
                    "no MMAT_LOCOPT pre_d810 snapshot found; "
                    "pass --snap-id explicitly"
                )
                conn.close()
                return 1
            locopt_snap = int(row[0])
        resolutions = resolve_state_transition_facts(
            conn,
            bst_intervals=intervals,
            locopt_snapshot_id=locopt_snap,
        )
        if args.persist:
            persist_bst_resolutions(conn, resolutions)
        filtered = list(resolutions)
        if args.block is not None:
            filtered = [
                r for r in filtered
                if r.source_block_serial == int(args.block)
            ]
        if args.json_output:
            print(
                json.dumps(
                    [
                        {
                            "snapshot_id": r.snapshot_id,
                            "fact_id": r.fact_id,
                            "source_block_serial": r.source_block_serial,
                            "source_state_const_hex": r.source_state_const_hex,
                            "bst_resolved_next_block_serial":
                                r.bst_resolved_next_block_serial,
                            "bst_resolved_next_state_const_hex":
                                r.bst_resolved_next_state_const_hex,
                            "bst_resolved_next_state_const_u64":
                                r.bst_resolved_next_state_const_u64,
                            "bst_resolution_reason": r.bst_resolution_reason,
                            "bst_resolution_maturity":
                                r.bst_resolution_maturity,
                        }
                        for r in filtered
                    ],
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(
                "snap\tsource_blk\tsource_const\t"
                "next_blk\tnext_const\treason\tmaturity"
            )
            for r in filtered:
                print(
                    "\t".join(
                        (
                            str(r.snapshot_id),
                            str(r.source_block_serial),
                            r.source_state_const_hex,
                            (
                                str(r.bst_resolved_next_block_serial)
                                if r.bst_resolved_next_block_serial
                                is not None else "-"
                            ),
                            r.bst_resolved_next_state_const_hex or "-",
                            r.bst_resolution_reason,
                            r.bst_resolution_maturity,
                        )
                    )
                )
            print(
                f"\n# {len(filtered)} resolution(s) shown "
                f"(persisted={args.persist}, "
                f"intervals={len(intervals)})"
            )
    elif args.command == "dag-edge-alternate-correlations":
        if args.snap_id is not None:
            snap_ids = [int(args.snap_id)]
        else:
            snap_ids = [
                int(r[0])
                for r in conn.execute(
                    "SELECT DISTINCT snapshot_id "
                    "FROM dag_edge_diagnostics "
                    "WHERE classification='COLLAPSED_TO_REWRITTEN_TARGET' "
                    "ORDER BY snapshot_id"
                ).fetchall()
            ]
        all_correlations: list[AlternateCorrelation] = []
        for snap in snap_ids:
            all_correlations.extend(correlate_collapsed_edges(conn, snap))
        if args.persist:
            persist_alternate_correlations(conn, all_correlations)
        filtered = list(all_correlations)
        if args.collapsed_edge is not None:
            filtered = [
                c for c in filtered
                if c.collapsed_edge_id == int(args.collapsed_edge)
            ]
        if args.json_output:
            print(
                json.dumps(
                    [
                        {
                            "snapshot_id": c.snapshot_id,
                            "collapsed_edge_id": c.collapsed_edge_id,
                            "alternate_edge_id": c.alternate_edge_id,
                            "collapsed_source_state":
                                c.collapsed_source_state,
                            "collapsed_target_state":
                                c.collapsed_target_state,
                            "alternate_source_state":
                                c.alternate_source_state,
                            "alternate_target_state":
                                c.alternate_target_state,
                            "alternate_ordered_path":
                                c.alternate_ordered_path,
                            "overlap_blocks": list(c.overlap_blocks),
                            "alternate_classification":
                                c.alternate_classification,
                            "reason": c.reason,
                        }
                        for c in filtered
                    ],
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(
                "snap\tcollapsed_edge\talt_edge\t"
                "collapsed_src->collapsed_tgt\t"
                "alt_src->alt_tgt\tpath\toverlap\treason"
            )
            for c in filtered:
                print(
                    "\t".join(
                        (
                            str(c.snapshot_id),
                            str(c.collapsed_edge_id),
                            str(c.alternate_edge_id),
                            f"{c.collapsed_source_state}->"
                            f"{c.collapsed_target_state}",
                            f"{c.alternate_source_state}->"
                            f"{c.alternate_target_state}",
                            c.alternate_ordered_path,
                            ",".join(str(b) for b in c.overlap_blocks),
                            c.reason,
                        )
                    )
                )
            print(
                f"\n# {len(filtered)} correlation(s) shown "
                f"(persisted={args.persist})"
            )
    elif args.command == "dag-edge-alternate-selections":
        if args.snap_id is not None:
            snap_ids = [int(args.snap_id)]
        else:
            snap_ids = [
                int(r[0])
                for r in conn.execute(
                    "SELECT DISTINCT snapshot_id "
                    "FROM dag_edge_alternate_correlations "
                    "ORDER BY snapshot_id"
                ).fetchall()
            ]
        all_selections: list[AlternateSelection] = []
        for snap in snap_ids:
            all_selections.extend(
                select_alternate_edges(
                    conn, snap, max_depth=int(args.max_depth)
                )
            )
        if args.persist:
            persist_alternate_selections(conn, all_selections)
        filtered = list(all_selections)
        if args.collapsed_edge is not None:
            filtered = [
                s for s in filtered
                if s.collapsed_edge_id == int(args.collapsed_edge)
            ]
        if args.json_output:
            print(
                json.dumps(
                    [
                        {
                            "snapshot_id": s.snapshot_id,
                            "collapsed_edge_id": s.collapsed_edge_id,
                            "alternate_edge_id": s.alternate_edge_id,
                            "selected": s.selected,
                            "source_byte_index": s.source_byte_index,
                            "reached_byte_index": s.reached_byte_index,
                            "reached_state_hex": s.reached_state_hex,
                            "reason": s.reason,
                            "evidence": s.evidence,
                        }
                        for s in filtered
                    ],
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(
                "snap\tcollapsed\talt\tsel\tsrc_bi\treached_bi\t"
                "reached_state\treason"
            )
            for s in filtered:
                print(
                    "\t".join(
                        (
                            str(s.snapshot_id),
                            str(s.collapsed_edge_id),
                            str(s.alternate_edge_id),
                            "T" if s.selected else "-",
                            (
                                str(s.source_byte_index)
                                if s.source_byte_index is not None else "-"
                            ),
                            (
                                str(s.reached_byte_index)
                                if s.reached_byte_index is not None else "-"
                            ),
                            s.reached_state_hex or "-",
                            s.reason,
                        )
                    )
                )
            sel_count = sum(1 for s in filtered if s.selected)
            rej_count = len(filtered) - sel_count
            print(
                f"\n# {sel_count} selected / {rej_count} rejected "
                f"(persisted={args.persist}, max_depth={args.max_depth})"
            )
    elif args.command == "region-shape":
        # Layer-safe: only normalizes the func_ea string locally; no cfg import.
        func_ea = args.func_ea.strip().lower()
        if not func_ea.startswith("0x"):
            func_ea = "0x" + func_ea
        clauses = ["func_ea_hex = ?"]
        params: list = [func_ea]
        if args.source:
            clauses.append("source = ?")
            params.append(args.source)
        if args.snapshot_id is not None:
            clauses.append("snapshot_id = ?")
            params.append(int(args.snapshot_id))
        sql = (
            "SELECT source, snapshot_id, region, feature, value_text, "
            "evidence_json FROM region_shape_features WHERE "
            + " AND ".join(clauses)
            + " ORDER BY source, snapshot_id, region, feature"
        )
        rows = list(conn.execute(sql, params))
        if args.json_output:
            out = [
                {
                    "source": r[0],
                    "snapshot_id": r[1],
                    "region": r[2],
                    "feature": r[3],
                    "value_text": r[4],
                    "evidence": json.loads(r[5]) if r[5] else {},
                }
                for r in rows
            ]
            print(json.dumps(out, indent=2, sort_keys=True))
        else:
            print("source\tsnapshot_id\tregion\tfeature\tvalue")
            for r in rows:
                print(f"{r[0]}\t{r[1]!s}\t{r[2]}\t{r[3]}\t{r[4]}")
            print(f"\n# {len(rows)} row(s) shown")
    elif args.command == "terminal-tail-dce":
        func_ea = args.func_ea.strip().lower()
        if not func_ea.startswith("0x"):
            func_ea = "0x" + func_ea
        clauses = ["func_ea_hex = ?"]
        params: list = [func_ea]
        if args.byte_index is not None:
            clauses.append("byte_index = ?")
            params.append(int(args.byte_index))
        sql = (
            "SELECT byte_index, last_present_snapshot_id, "
            "first_missing_snapshot_id, last_block_serial, last_ea_hex, "
            "cause, recommended_action, rationale, evidence_json "
            "FROM terminal_tail_dce_causes WHERE "
            + " AND ".join(clauses)
            + " ORDER BY byte_index"
        )
        rows = list(conn.execute(sql, params))
        if args.json_output:
            out = [
                {
                    "byte_index": r[0],
                    "last_present_snapshot_id": r[1],
                    "first_missing_snapshot_id": r[2],
                    "last_block_serial": r[3],
                    "last_ea_hex": r[4],
                    "cause": r[5],
                    "recommended_action": r[6],
                    "rationale": r[7],
                    "evidence": json.loads(r[8]) if r[8] else {},
                }
                for r in rows
            ]
            print(json.dumps(out, indent=2, sort_keys=True))
        else:
            print("byte_index\tcause\trecommended_action\tlast_pres -> first_miss")
            for r in rows:
                print(f"{r[0]}\t{r[5]}\t{r[6]}\t{r[1]} -> {r[2]}")
            print(f"\n# {len(rows)} cause(s) shown")
    elif args.command == "region-diff":
        cfg_cli = importlib.import_module("d810.cfg.region_oracle_cli")
        rc = cfg_cli.handle_region_diff(
            args,
            conn,
            _resolve_oracle_snap_ids,
            _oracle_persist_features,
            _oracle_persist_dce_causes,
        )
        conn.close()
        return rc

    elif args.command == "hcc-byte-cascade-trace":
        from d810.diagnostics.hcc_byte_cascade_trace import (
            enrich_rows_with_db,
            format_report,
            format_report_json,
            parse_trace_log,
        )

        log_path = Path(args.log)
        if not log_path.exists():
            print(f"error: log not found: {log_path}", file=sys.stderr)
            conn.close()
            return 2
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        rows = parse_trace_log(log_text)
        db_path = Path(args.db)
        if db_path.exists():
            rows = enrich_rows_with_db(rows, db_path)
        if getattr(args, "json_output", False):
            print(format_report_json(rows))
        else:
            print(format_report(rows, func_label=args.func_label))
        conn.close()
        return 0

    elif args.command == "terminal-tail-audit":
        from d810.diagnostics.terminal_tail_audit import run_audit

        db_path = Path(args.db)
        if not db_path.exists():
            print(f"error: db not found: {db_path}", file=sys.stderr)
            conn.close()
            return 2
        text = run_audit(
            db_path,
            show_edges=args.show_edges,
            localize=args.localize,
            initial_snap_id=args.initial_snap_id,
        )
        print(text, end="")
        conn.close()
        return 0

    elif args.command == "cascade-egress-plan":
        from d810.diagnostics.cascade_egress_plan import run_plan

        db_path = Path(args.db)
        text = run_plan(
            db_path,
            fact_snapshot_id=args.fact_snapshot_id,
            target_snapshot_id=args.target_snapshot_id,
        )
        sys.stdout.write(text)
        conn.close()
        return 0 if not text.startswith("Error:") else 2

    elif args.command == "return-ledger":
        from d810.diagnostics.return_ledger import run_ledger

        db_path = Path(args.db)
        text = run_ledger(
            db_path,
            dump_path=args.dump,
            snapshot_id=args.snapshot_id,
            as_json=getattr(args, "json_output", False),
            list_snapshots_only=args.list_snapshots,
        )
        sys.stdout.write(text)
        conn.close()
        return 0 if not text.startswith("Error:") else 2

    elif args.command == "redirect-reconcile":
        from d810.diagnostics.redirect_reconcile import run_reconcile

        db_path = Path(args.db)
        log_path = Path(args.log)
        try:
            stkoff = int(args.state_var_stkoff, 16)
        except (TypeError, ValueError):
            print(
                f"error: --state-var-stkoff must be a hex literal,"
                f" got: {args.state_var_stkoff!r}",
                file=sys.stderr,
            )
            conn.close()
            return 2
        text = run_reconcile(
            db_path,
            log_path,
            snap_id=args.snap_id,
            state_var_stkoff=stkoff,
            min_dispatcher_preds=args.min_dispatcher_preds,
            show_edges=args.show_edges,
        )
        sys.stdout.write(text)
        conn.close()
        return 0 if not text.startswith("Error:") else 2

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
