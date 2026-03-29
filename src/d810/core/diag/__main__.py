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
import sqlite3
import sys

from d810.core.diag.query import (
    block_detail,
    chain,
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


def _format_chain(results: list[dict]) -> str:
    """Format chain query output as compact per-block summary."""
    lines: list[str] = []
    for blk in results:
        if blk is None:
            lines.append("  (missing)")
            continue
        serial = blk["serial"]
        tname = blk["type_name"]
        succs = blk["succs"]
        hop_status = ""
        if "hop_ok" in blk:
            expected = blk["expected_next"]
            ok_str = "OK" if blk["hop_ok"] else f"BROKEN (actual: {succs[0] if succs else '?'})"
            hop_status = f" hop->{expected} {ok_str}"
        lines.append(f"blk[{serial}] {tname} succs={succs}{hop_status}")
        for insn in blk.get("instructions", []):
            idx = insn["insn_index"]
            dstr = insn["dstr"] or ""
            lines.append(f"  {serial}.{idx} {dstr}")
    return "\n".join(lines)


def _format_var_writes(writes: list[dict]) -> str:
    """Format var-writes query output as table."""
    lines: list[str] = []
    for w in writes:
        blk = w["block_serial"]
        idx = w["insn_index"]
        dstr = w.get("dstr", "") or ""
        stkoff = w.get("dest_stkoff")
        stkoff_str = f"stkoff=0x{stkoff:X}" if stkoff is not None else "stkoff=None"
        src_stkoff = w.get("src_l_stkoff")
        src_str = f"src_stkoff=0x{src_stkoff:X}" if src_stkoff is not None else "src=None"
        lines.append(f"blk[{blk}].{idx}  {dstr:<40s} {stkoff_str} {src_str}")
    return "\n".join(lines)


def _format_block(blk: dict | None, show_insns: bool) -> str:
    """Format block detail output."""
    if blk is None:
        return "(block not found)"
    lines: list[str] = []
    serial = blk["serial"]
    tname = blk["type_name"]
    succs = blk["succs"]
    preds = blk["preds"]
    nsucc = blk["nsucc"]
    npred = blk["npred"]
    lines.append(f"blk[{serial}] {tname} nsucc={nsucc} npred={npred}")
    lines.append(f"  succs={succs}")
    lines.append(f"  preds={preds}")
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


def _format_return_paths(paths: list[dict]) -> str:
    """Format return-paths query output."""
    lines: list[str] = []
    for p in paths:
        src_hex = p.get("source_state") or "None"
        lines.append(f"edge[{p['edge_id']}] src={src_hex} CONDITIONAL_RETURN")
        lines.append(f"  path={p['path_serials']}")
        for hop in p.get("hops", []):
            serial = hop["serial"]
            flag = "*" if hop.get("has_return_slot_write") else " "
            opcode = hop.get("write_opcode") or ""
            lines.append(f"    [{flag}] blk[{serial}] {opcode}")
    return "\n".join(lines)


def _format_rendered_program_nodes(nodes: list[dict]) -> str:
    """Format rendered program node metadata."""
    if not nodes:
        return "(rendered program not found)"
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
            parts.append(f"handler=blk[{node['handler_serial']}]")
        if node.get("entry_anchor") is not None:
            parts.append(f"entry=blk[{node['entry_anchor']}]")
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
                            f" : serial={serial:<4d}"
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
        print(_format_chain(result))
    elif args.command == "var-writes":
        result = var_writes(conn, snap_id, args.stkoff)
        print(_format_var_writes(result))
    elif args.command == "block":
        print(_snapshot_header(conn, snap_id))
        result = block_detail(conn, snap_id, args.serial)
        print(_format_block(result, show_insns=args.insns))
    elif args.command == "return-paths":
        result = return_paths(conn, snap_id)
        print(_format_return_paths(result))
    elif args.command == "program":
        print(_snapshot_header(conn, snap_id))
        if args.nodes:
            print(
                _format_rendered_program_nodes(
                    rendered_program_nodes(conn, snap_id, args.variant)
                )
            )
        else:
            result = rendered_program_text(conn, snap_id, args.variant)
            print(result if result is not None else "(rendered program not found)")
    elif args.command == "program-variants":
        print(_snapshot_header(conn, snap_id))
        print(_format_rendered_program_variants(rendered_program_variants(conn, snap_id)))
    elif args.command == "ea-trace":
        print(_ea_trace(conn, args.eas, args.exact))

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
