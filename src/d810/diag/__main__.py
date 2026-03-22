"""CLI for querying MBA diagnostic snapshots.

Usage::

    python -m d810.diag chain --db path.sqlite3 131 174 176 200 23 32 62 206 207 218
    python -m d810.diag var-writes --db path.sqlite3 0x7F0
    python -m d810.diag block --db path.sqlite3 206 --insns
    python -m d810.diag return-paths --db path.sqlite3
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys

from d810.diag.query import block_detail, chain, return_paths, var_writes


def _resolve_snapshot_id(conn: sqlite3.Connection, snapshot: int) -> int:
    """Resolve snapshot argument: -1 means latest (max id)."""
    if snapshot >= 0:
        return snapshot
    row = conn.execute("SELECT MAX(id) FROM snapshots").fetchone()
    if row is None or row[0] is None:
        print("ERROR: no snapshots in database", file=sys.stderr)
        sys.exit(1)
    return row[0]


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
        src = p.get("source_state")
        src_hex = f"0x{src:X}" if src is not None else "None"
        lines.append(f"edge[{p['edge_id']}] src={src_hex} CONDITIONAL_RETURN")
        lines.append(f"  path={p['path_serials']}")
        for hop in p.get("hops", []):
            serial = hop["serial"]
            flag = "*" if hop.get("has_return_slot_write") else " "
            opcode = hop.get("write_opcode") or ""
            lines.append(f"    [{flag}] blk[{serial}] {opcode}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``python -m d810.diag``."""
    # Common args shared by all subcommands via parents= mechanism.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--db", default=".tmp/diag.sqlite3",
        help="Path to SQLite diagnostic database (default: .tmp/diag.sqlite3)",
    )
    common.add_argument(
        "--snapshot", type=int, default=-1,
        help="Snapshot ID (-1 = latest, default: -1)",
    )

    parser = argparse.ArgumentParser(
        prog="d810.diag",
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

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    conn = sqlite3.connect(args.db)
    snap_id = _resolve_snapshot_id(conn, args.snapshot)

    if args.command == "chain":
        result = chain(conn, snap_id, args.serials)
        print(_format_chain(result))
    elif args.command == "var-writes":
        result = var_writes(conn, snap_id, args.stkoff)
        print(_format_var_writes(result))
    elif args.command == "block":
        result = block_detail(conn, snap_id, args.serial)
        print(_format_block(result, show_insns=args.insns))
    elif args.command == "return-paths":
        result = return_paths(conn, snap_id)
        print(_format_return_paths(result))

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
