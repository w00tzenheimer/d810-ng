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
    chain,
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

    p_ea = sub.add_parser(
        "ea-trace", parents=[common],
        help="Trace an EA across all snapshots (block lineage)",
    )
    p_ea.add_argument("eas", nargs="+", type=lambda x: int(x, 0),
                      help="EA values in hex (e.g. 0x1800134A5)")
    p_ea.add_argument("--exact", action="store_true",
                      help="Match start_ea exactly (default: range containment)")

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
        print(_format_rendered_program_variants(rendered_program_variants(conn, snap_id)))
    elif args.command == "ea-trace":
        print(_ea_trace(conn, args.eas, args.exact))
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
