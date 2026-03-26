#!/usr/bin/env python3
"""Extract return-family ledger from a Hodur diagnostic DB.

Traces all paths to BLT_STOP, extracts return-slot writers,
VALRANGES, predecessor chains, BFS reachability, and correlates
with AFTER pseudocode.

Usage:
    python3 tools/scripts/return_family_ledger.py .tmp/OUTPUT.txt
    python3 tools/scripts/return_family_ledger.py .tmp/OUTPUT.txt --json
    python3 tools/scripts/return_family_ledger.py .tmp/OUTPUT.txt --db PATH --snapshot-id 17
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class ReturnSlotWriter:
    block_serial: int
    opcode: str
    src_type: str
    src_stkoff: Optional[int]
    src_value: Optional[str]
    dstr: str


@dataclass
class ReturnPath:
    chain: list[int]  # [root, ..., BLT_STOP]
    root_serial: int
    is_pts: bool
    writer: Optional[ReturnSlotWriter]
    v660_value: Optional[str]
    state_valranges: Optional[str]
    reachable: bool


@dataclass
class AfterReturn:
    line_num: int
    expr: str
    ordinal: int


# ---------------------------------------------------------------------------
# DB queries
# ---------------------------------------------------------------------------

def find_diag_db(dump_file: Path) -> Optional[Path]:
    """Find the matching diag DB for a dump file."""
    log_dirs = [
        dump_file.parent / "logs" / "d810_logs",
        Path.home() / ".idapro" / "logs" / "d810_logs",
        dump_file.parent.parent / "logs" / "d810_logs",
    ]
    # Also check .tmp/logs/d810_logs relative to cwd
    log_dirs.append(Path(".tmp/logs/d810_logs"))

    for d in log_dirs:
        if d.is_dir():
            dbs = sorted(d.glob("*.diag.sqlite3"), key=lambda p: p.stat().st_mtime, reverse=True)
            if dbs:
                return dbs[0]
    return None


def pick_snapshot(db: sqlite3.Connection, snapshot_id: Optional[int] = None) -> int:
    """Pick the best snapshot ID. Default: last 'post_apply' with >200 blocks before any gut_and_wire."""
    if snapshot_id is not None:
        return snapshot_id

    rows = db.execute(
        "SELECT id, label, block_count FROM snapshots ORDER BY id"
    ).fetchall()

    # Find last state_write_reconstruction_post_apply that precedes a post_gut_and_wire
    best = None
    for sid, label, bc in rows:
        if "post_apply" in label and "gut_and_wire" not in label and bc > 200:
            best = sid
        if "gut_and_wire" in label and best is not None:
            return best  # return the one just before gut-and-wire

    # Fallback: last post_apply
    for sid, label, bc in reversed(rows):
        if "post_apply" in label and bc > 200:
            return sid

    return rows[-1][0] if rows else 1


def query_blocks(db: sqlite3.Connection, sid: int) -> dict[int, dict]:
    """Get all blocks for a snapshot."""
    rows = db.execute(
        "SELECT serial, type_name, preds, succs, meta FROM blocks WHERE snapshot_id=?",
        (sid,),
    ).fetchall()
    blocks = {}
    for serial, type_name, preds_json, succs_json, meta_json in rows:
        preds = json.loads(preds_json) if preds_json else []
        succs = json.loads(succs_json) if succs_json else []
        meta = json.loads(meta_json) if meta_json else {}
        blocks[serial] = {
            "serial": serial,
            "type": type_name,
            "preds": preds,
            "succs": succs,
            "valranges": meta.get("valranges", ""),
        }
    return blocks


def query_return_slot_writers(db: sqlite3.Connection, sid: int) -> dict[int, ReturnSlotWriter]:
    """Find all instructions that write to %var_8.8 (dest_stkoff=2032=0x7F0)."""
    rows = db.execute(
        """SELECT block_serial, opcode_name, src_l_type, src_l_stkoff,
                  src_l_value_hex, substr(dstr, 1, 160)
           FROM instructions
           WHERE snapshot_id=? AND dest_stkoff=2032
           ORDER BY block_serial""",
        (sid,),
    ).fetchall()
    writers = {}
    for bs, op, slt, sls, slv, dstr in rows:
        writers[bs] = ReturnSlotWriter(
            block_serial=bs, opcode=op,
            src_type=slt or "", src_stkoff=sls,
            src_value=slv, dstr=dstr or "",
        )
    return writers


def query_v660_writers(db: sqlite3.Connection, sid: int) -> dict[int, str]:
    """Find blocks that write to v660 (dest_stkoff=1632=0x660) with constant values."""
    rows = db.execute(
        """SELECT block_serial, src_l_value_hex
           FROM instructions
           WHERE snapshot_id=? AND dest_stkoff=1632 AND src_l_value_hex IS NOT NULL
           ORDER BY block_serial""",
        (sid,),
    ).fetchall()
    return {bs: val for bs, val in rows}


def bfs_reachable(blocks: dict[int, dict]) -> set[int]:
    """BFS from blk[0] over successor edges."""
    if 0 not in blocks:
        return set()
    visited: set[int] = set()
    q: deque[int] = deque([0])
    while q:
        cur = q.popleft()
        if cur in visited:
            continue
        visited.add(cur)
        for s in blocks[cur]["succs"]:
            if s not in visited:
                q.append(s)
    return visited


# ---------------------------------------------------------------------------
# Path tracing
# ---------------------------------------------------------------------------

def _expand_block(
    serial: int,
    suffix: list[int],
    blocks: dict[int, dict],
    writers: dict[int, ReturnSlotWriter],
    v660_map: dict[int, str],
    reachable: set[int],
    is_pts: bool,
    depth: int = 0,
) -> list[ReturnPath]:
    """Recursively expand multi-pred blocks into separate semantic families.

    If a block has >1 predecessor, split into one family per predecessor.
    Recurse up to depth 3 to catch chains like 207→217→218→240.
    """
    blk = blocks.get(serial, {})
    preds = blk.get("preds", [])
    writer = writers.get(serial)
    chain = [serial] + suffix

    # If this block has multiple preds, split into one family per predecessor
    # (each carries different upstream context = different semantic family).
    if len(preds) > 1 and depth < 3:
        families: list[ReturnPath] = []
        for p in preds:
            families.extend(
                _expand_block(p, chain, blocks, writers, v660_map, reachable, is_pts, depth + 1)
            )
        return families

    # Single pred, no writer: try one level deeper
    if len(preds) == 1 and not writer and depth < 3:
        parent = preds[0]
        if parent in writers or parent in v660_map:
            return _expand_block(parent, chain, blocks, writers, v660_map, reachable, is_pts, depth + 1)

    # Leaf: emit this as a family root
    return [ReturnPath(
        chain=chain,
        root_serial=serial,
        is_pts=is_pts,
        writer=writer,
        v660_value=v660_map.get(serial),
        state_valranges=blk.get("valranges", ""),
        reachable=serial in reachable,
    )]


def trace_return_paths(
    blocks: dict[int, dict],
    writers: dict[int, ReturnSlotWriter],
    v660_map: dict[int, str],
    reachable: set[int],
) -> list[ReturnPath]:
    """Trace all paths from BLT_STOP back through predecessors, splitting semantic families."""
    stop_blocks = [b for b in blocks.values() if b["type"] == "BLT_STOP"]
    if not stop_blocks:
        return []
    stop = stop_blocks[-1]
    paths: list[ReturnPath] = []

    for pred_serial in stop["preds"]:
        pred = blocks.get(pred_serial)
        if pred is None:
            continue

        is_pts = len(pred["preds"]) == 1 and pred_serial != 218

        if is_pts:
            root = pred["preds"][0]
            families = _expand_block(root, [pred_serial, stop["serial"]], blocks, writers, v660_map, reachable, is_pts)
            paths.extend(families)
        else:
            # Shared epilogue — expand each feeder as a semantic family
            for feeder_serial in pred["preds"]:
                families = _expand_block(
                    feeder_serial, [pred_serial, stop["serial"]],
                    blocks, writers, v660_map, reachable, is_pts,
                )
                paths.extend(families)

    return paths


# ---------------------------------------------------------------------------
# AFTER pseudocode
# ---------------------------------------------------------------------------

def extract_after_returns(lines: list[str]) -> list[AfterReturn]:
    """Extract return statements from AFTER pseudocode."""
    start = None
    end = None
    for i, raw in enumerate(lines):
        if "--- AFTER ---" in raw:
            start = i
        if start is not None and "AFTER:" in raw and "lines=" in raw:
            end = i + 1
            break
    if start is None:
        return []

    returns: list[AfterReturn] = []
    ordinal = 0
    i = start
    while i < (end or len(lines)):
        line = lines[i].rstrip()
        stripped = line.strip()
        if stripped.startswith("//") or "__int64" in stripped or stripped.startswith(("BEFORE:", "AFTER:")):
            i += 1
            continue

        if re.search(r"\breturn\b", stripped) and "return_" not in stripped:
            expr_lines = [line]
            j = i + 1
            while ";" not in " ".join(l.rstrip() for l in expr_lines):
                if j >= (end or len(lines)):
                    break
                expr_lines.append(lines[j].rstrip())
                j += 1
            full = " ".join(l.strip() for l in expr_lines)
            m = re.search(r"return\s+(.*?)\s*;", full)
            if m:
                ordinal += 1
                returns.append(AfterReturn(line_num=i + 1, expr=m.group(1).strip(), ordinal=ordinal))
            i = j
            continue
        i += 1
    return returns


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def format_writer(w: Optional[ReturnSlotWriter]) -> str:
    if not w:
        return "(none)"
    src = ""
    if w.src_value:
        src = f"#{w.src_value}"
    elif w.src_stkoff is not None:
        src = f"stkoff=0x{w.src_stkoff:X}"
    else:
        src = w.src_type or "expr"
    return f"{w.opcode} src={src}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Return-family ledger (diag DB + dump)")
    parser.add_argument("dump_file", type=Path, help="Hodur dump file (OUTPUT.txt)")
    parser.add_argument("--db", type=Path, default=None, help="Diag SQLite DB (auto-detected if omitted)")
    parser.add_argument("--snapshot-id", type=int, default=None, help="Snapshot ID (auto-detected)")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--list-snapshots", action="store_true")
    args = parser.parse_args()

    # Find DB
    db_path = args.db or find_diag_db(args.dump_file)
    if not db_path or not db_path.exists():
        print(f"Diag DB not found. Specify with --db", file=sys.stderr)
        sys.exit(1)

    db = sqlite3.connect(str(db_path))

    if args.list_snapshots:
        rows = db.execute("SELECT id, label, block_count FROM snapshots ORDER BY id").fetchall()
        for sid, label, bc in rows:
            print(f"  [{sid:2d}] {label} ({bc} blocks)")
        return

    sid = pick_snapshot(db, args.snapshot_id)
    snap_label = db.execute("SELECT label FROM snapshots WHERE id=?", (sid,)).fetchone()[0]

    # Query structured data
    blocks = query_blocks(db, sid)
    writers = query_return_slot_writers(db, sid)
    v660_map = query_v660_writers(db, sid)
    reachable = bfs_reachable(blocks)

    # Trace paths
    paths = trace_return_paths(blocks, writers, v660_map, reachable)

    # AFTER returns from dump file
    after_returns: list[AfterReturn] = []
    if args.dump_file.exists():
        dump_lines = args.dump_file.read_text().splitlines(keepends=True)
        after_returns = extract_after_returns(dump_lines)

    # Stats
    stop_blocks = [b for b in blocks.values() if b["type"] == "BLT_STOP"]
    stop = stop_blocks[-1] if stop_blocks else None
    live_paths = [p for p in paths if p.reachable]
    dead_paths = [p for p in paths if not p.reachable]

    if args.json:
        out = {
            "db": str(db_path),
            "snapshot_id": sid,
            "snapshot_label": snap_label,
            "total_blocks": len(blocks),
            "reachable_blocks": len(reachable),
            "blt_stop": stop["serial"] if stop else None,
            "blt_stop_preds": stop["preds"] if stop else [],
            "return_slot_writers": {
                str(s): {"opcode": w.opcode, "src_type": w.src_type, "src_stkoff": w.src_stkoff,
                         "src_value": w.src_value, "dstr": w.dstr[:120]}
                for s, w in sorted(writers.items())
            },
            "v660_writers": v660_map,
            "paths": [
                {
                    "chain": p.chain, "root": p.root_serial, "pts": p.is_pts,
                    "writer": format_writer(p.writer), "v660": p.v660_value,
                    "valranges": (p.state_valranges or "")[:160],
                    "reachable": p.reachable,
                }
                for p in paths
            ],
            "live_paths": len(live_paths),
            "dead_paths": len(dead_paths),
            "after_returns": [
                {"R": r.ordinal, "line": r.line_num, "expr": r.expr[:120]}
                for r in after_returns
            ],
        }
        print(json.dumps(out, indent=2))
        return

    # --- Text output ---
    print(f"=== RETURN FAMILY LEDGER ===")
    print(f"DB: {db_path.name}")
    print(f"Snapshot: [{sid}] {snap_label} ({len(blocks)} blocks, {len(reachable)} reachable)")
    if stop:
        print(f"BLT_STOP: blk[{stop['serial']}]  preds={stop['preds']}")
    print(f"Return-slot writers (dest=0x7F0): blk{sorted(writers.keys())}")
    print(f"v660 writers (dest=0x660): {v660_map}")
    print()

    print(f"--- {len(live_paths)} Live Return Paths ---")
    for i, p in enumerate(live_paths, 1):
        tag = "PTS" if p.is_pts else "EPILOGUE"
        chain_str = " -> ".join(f"blk[{s}]" for s in p.chain)
        print(f"\n  [{i}] {tag}  {chain_str}")
        print(f"      writer: {format_writer(p.writer)}")
        if p.v660_value:
            print(f"      v660: {p.v660_value}")
        if p.state_valranges:
            print(f"      valranges: {p.state_valranges[:160]}")

    if dead_paths:
        print(f"\n--- {len(dead_paths)} Dead Paths (BFS-unreachable) ---")
        for p in dead_paths:
            chain_str = " -> ".join(f"blk[{s}]" for s in p.chain)
            print(f"  {chain_str}  (pred chain also unreachable)")

    print(f"\n--- {len(after_returns)} AFTER Returns ---")
    for r in after_returns:
        print(f"  R{r.ordinal}  line {r.line_num}: return {r.expr[:120]}")

    print(f"\n--- Summary ---")
    print(f"Structural paths: {len(paths)} ({len(live_paths)} live, {len(dead_paths)} dead)")
    print(f"AFTER returns: {len(after_returns)}")
    gap = len(live_paths) - len(after_returns)
    if gap > 0:
        print(f"Gap: {gap} live paths > AFTER returns (merge at decompiler)")
    elif gap < 0:
        print(f"Gap: {-gap} AFTER returns > live paths (bifurcation at multi-pred block)")
    else:
        print("Gap: 0 (exact match)")


if __name__ == "__main__":
    main()
