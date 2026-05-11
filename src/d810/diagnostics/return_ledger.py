"""Return-family ledger -- traces paths to BLT_STOP and correlates with AFTER.

Pure Python, no d810 runtime imports. Reads a Hodur diag SQLite + an
optional AFTER-pseudocode dump file and produces the same report shape as
the legacy ``tools/scripts/return_family_ledger.py`` so callers' grep
patterns keep working.

The path tracer assumes the sub_7FFD3338C040 stack layout:

- Return slot at ``dest_stkoff=0x7F0`` (2032) -- the `%var_8.8` carrier
  IDA lowers into the function's return register.
- Auxiliary state slot at ``dest_stkoff=0x660`` (1632) -- the ``v660``
  family used to distinguish near-identical return constants.

If you need to point this at a different function, parametrise those
constants downstream; the helpers below accept the offsets explicitly
where it makes sense so the public surface stays testable.
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections import deque
from dataclasses import dataclass
from pathlib import Path


# Hardcoded stack offsets for sub_7FFD3338C040; preserved from the legacy
# script to keep output bit-identical. Override by passing different values
# to the helpers below if you need a different function.
DEFAULT_RETURN_SLOT_STKOFF = 0x7F0   # 2032; %var_8.8
DEFAULT_V660_STKOFF = 0x660           # 1632; auxiliary state slot


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class ReturnSlotWriter:
    block_serial: int
    opcode: str
    src_type: str
    src_stkoff: int | None
    src_value: str | None
    dstr: str


@dataclass
class ReturnPath:
    chain: list[int]
    root_serial: int
    is_pts: bool
    writer: ReturnSlotWriter | None
    v660_value: str | None
    state_valranges: str | None
    reachable: bool


@dataclass
class AfterReturn:
    line_num: int
    expr: str
    ordinal: int


# ---------------------------------------------------------------------------
# DB queries
# ---------------------------------------------------------------------------


def pick_snapshot(
    conn: sqlite3.Connection, snapshot_id: int | None = None,
) -> int:
    """Pick the snapshot to inspect.

    When *snapshot_id* is supplied it is returned verbatim. Otherwise:

    1. Walk snapshots in ascending id order tracking the last
       ``*_post_apply`` snapshot with >200 blocks.
    2. As soon as a ``gut_and_wire`` snapshot appears, return the
       previously remembered post-apply id (the structural state right
       before destructive shaping).
    3. Fall back to the most recent post-apply >200-block snapshot, or
       the last snapshot in the DB.
    """
    if snapshot_id is not None:
        return snapshot_id
    rows = conn.execute(
        "SELECT id, label, block_count FROM snapshots ORDER BY id"
    ).fetchall()
    best: int | None = None
    for sid, label, bc in rows:
        label = label or ""
        if "post_apply" in label and "gut_and_wire" not in label and bc and bc > 200:
            best = int(sid)
        if "gut_and_wire" in label and best is not None:
            return best
    for sid, label, bc in reversed(rows):
        if "post_apply" in (label or "") and bc and bc > 200:
            return int(sid)
    return int(rows[-1][0]) if rows else 1


def list_snapshots(conn: sqlite3.Connection) -> list[tuple[int, str, int]]:
    """Return ``(id, label, block_count)`` for every snapshot in the DB."""
    rows = conn.execute(
        "SELECT id, label, block_count FROM snapshots ORDER BY id"
    ).fetchall()
    return [(int(sid), str(label or ""), int(bc or 0)) for sid, label, bc in rows]


def query_blocks(conn: sqlite3.Connection, sid: int) -> dict[int, dict]:
    """``serial -> {type, preds, succs, valranges}`` for *sid*."""
    rows = conn.execute(
        "SELECT serial, type_name, preds, succs, meta FROM blocks "
        "WHERE snapshot_id=?",
        (sid,),
    ).fetchall()
    blocks: dict[int, dict] = {}
    for serial, type_name, preds_json, succs_json, meta_json in rows:
        try:
            preds = json.loads(preds_json) if preds_json else []
        except json.JSONDecodeError:
            preds = []
        try:
            succs = json.loads(succs_json) if succs_json else []
        except json.JSONDecodeError:
            succs = []
        try:
            meta = json.loads(meta_json) if meta_json else {}
        except json.JSONDecodeError:
            meta = {}
        blocks[int(serial)] = {
            "serial": int(serial),
            "type": str(type_name or ""),
            "preds": preds,
            "succs": succs,
            "valranges": meta.get("valranges", ""),
        }
    return blocks


def query_return_slot_writers(
    conn: sqlite3.Connection,
    sid: int,
    *,
    dest_stkoff: int = DEFAULT_RETURN_SLOT_STKOFF,
) -> dict[int, ReturnSlotWriter]:
    """All instructions that write to the return-slot stack variable."""
    rows = conn.execute(
        "SELECT block_serial, opcode_name, src_l_type, src_l_stkoff,"
        " src_l_value_hex, substr(dstr, 1, 160)"
        " FROM instructions WHERE snapshot_id=? AND dest_stkoff=?"
        " ORDER BY block_serial",
        (sid, dest_stkoff),
    ).fetchall()
    out: dict[int, ReturnSlotWriter] = {}
    for bs, op, slt, sls, slv, dstr in rows:
        out[int(bs)] = ReturnSlotWriter(
            block_serial=int(bs),
            opcode=str(op or ""),
            src_type=str(slt or ""),
            src_stkoff=int(sls) if sls is not None else None,
            src_value=slv,
            dstr=str(dstr or ""),
        )
    return out


def query_v660_writers(
    conn: sqlite3.Connection,
    sid: int,
    *,
    dest_stkoff: int = DEFAULT_V660_STKOFF,
) -> dict[int, str]:
    """Constant-valued writes to the v660 auxiliary slot."""
    rows = conn.execute(
        "SELECT block_serial, src_l_value_hex FROM instructions"
        " WHERE snapshot_id=? AND dest_stkoff=? AND src_l_value_hex IS NOT NULL"
        " ORDER BY block_serial",
        (sid, dest_stkoff),
    ).fetchall()
    return {int(bs): str(val) for bs, val in rows}


def bfs_reachable(blocks: dict[int, dict]) -> set[int]:
    """BFS from ``blk[0]`` along successor edges."""
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
            s_int = int(s)
            if s_int not in visited:
                q.append(s_int)
    return visited


# ---------------------------------------------------------------------------
# Path tracing
# ---------------------------------------------------------------------------


_SUB7FFD_EPILOGUE_SERIAL = 218  # PTS-vs-EPILOGUE pivot, preserved from legacy script


def _expand_block(
    serial: int,
    suffix: list[int],
    blocks: dict[int, dict],
    writers: dict[int, ReturnSlotWriter],
    v660_map: dict[int, str],
    reachable: set[int],
    is_pts: bool,
    *,
    depth: int = 0,
    max_depth: int = 3,
) -> list[ReturnPath]:
    """Recursively split multi-pred blocks into per-feeder semantic families.

    Walks at most *max_depth* levels back through predecessors so chains like
    ``207 -> 217 -> 218 -> 240`` are captured.
    """
    blk = blocks.get(serial, {})
    preds = [int(p) for p in blk.get("preds", [])]
    writer = writers.get(serial)
    chain = [serial] + suffix

    if len(preds) > 1 and depth < max_depth:
        families: list[ReturnPath] = []
        for p in preds:
            families.extend(
                _expand_block(
                    p, chain, blocks, writers, v660_map, reachable, is_pts,
                    depth=depth + 1, max_depth=max_depth,
                )
            )
        return families

    if len(preds) == 1 and not writer and depth < max_depth:
        parent = preds[0]
        if parent in writers or parent in v660_map:
            return _expand_block(
                parent, chain, blocks, writers, v660_map, reachable, is_pts,
                depth=depth + 1, max_depth=max_depth,
            )

    return [
        ReturnPath(
            chain=chain,
            root_serial=serial,
            is_pts=is_pts,
            writer=writer,
            v660_value=v660_map.get(serial),
            state_valranges=str(blk.get("valranges", "") or ""),
            reachable=serial in reachable,
        )
    ]


def trace_return_paths(
    blocks: dict[int, dict],
    writers: dict[int, ReturnSlotWriter],
    v660_map: dict[int, str],
    reachable: set[int],
) -> list[ReturnPath]:
    """Trace all paths from the latest ``BLT_STOP`` back through preds."""
    stop_blocks = [b for b in blocks.values() if b["type"] == "BLT_STOP"]
    if not stop_blocks:
        return []
    stop = stop_blocks[-1]
    stop_preds = [int(p) for p in stop["preds"]]
    paths: list[ReturnPath] = []
    for pred_serial in stop_preds:
        pred = blocks.get(pred_serial)
        if pred is None:
            continue
        pred_preds = [int(p) for p in pred.get("preds", [])]
        is_pts = len(pred_preds) == 1 and pred_serial != _SUB7FFD_EPILOGUE_SERIAL
        if is_pts:
            root = pred_preds[0]
            paths.extend(
                _expand_block(
                    root, [pred_serial, stop["serial"]],
                    blocks, writers, v660_map, reachable, is_pts,
                )
            )
        else:
            for feeder_serial in pred_preds:
                paths.extend(
                    _expand_block(
                        feeder_serial, [pred_serial, stop["serial"]],
                        blocks, writers, v660_map, reachable, is_pts,
                    )
                )
    return paths


# ---------------------------------------------------------------------------
# AFTER pseudocode extraction
# ---------------------------------------------------------------------------


def extract_after_returns(lines: list[str]) -> list[AfterReturn]:
    """Pull ``return ...;`` statements out of the AFTER pseudocode block."""
    start: int | None = None
    end: int | None = None
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
    upper = end if end is not None else len(lines)
    while i < upper:
        line = lines[i].rstrip()
        stripped = line.strip()
        if (
            stripped.startswith("//")
            or "__int64" in stripped
            or stripped.startswith(("BEFORE:", "AFTER:"))
        ):
            i += 1
            continue
        if re.search(r"\breturn\b", stripped) and "return_" not in stripped:
            expr_lines = [line]
            j = i + 1
            while ";" not in " ".join(part.rstrip() for part in expr_lines):
                if j >= upper:
                    break
                expr_lines.append(lines[j].rstrip())
                j += 1
            full = " ".join(part.strip() for part in expr_lines)
            m = re.search(r"return\s+(.*?)\s*;", full)
            if m:
                ordinal += 1
                returns.append(
                    AfterReturn(
                        line_num=i + 1,
                        expr=m.group(1).strip(),
                        ordinal=ordinal,
                    )
                )
            i = j
            continue
        i += 1
    return returns


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def format_writer(w: ReturnSlotWriter | None) -> str:
    if w is None:
        return "(none)"
    if w.src_value:
        src = f"#{w.src_value}"
    elif w.src_stkoff is not None:
        src = f"stkoff=0x{w.src_stkoff:X}"
    else:
        src = w.src_type or "expr"
    return f"{w.opcode} src={src}"


def render_text(
    *,
    db_path: Path,
    snapshot_id: int,
    snap_label: str,
    blocks: dict[int, dict],
    reachable: set[int],
    writers: dict[int, ReturnSlotWriter],
    v660_map: dict[int, str],
    paths: list[ReturnPath],
    after_returns: list[AfterReturn],
) -> str:
    stop_blocks = [b for b in blocks.values() if b["type"] == "BLT_STOP"]
    stop = stop_blocks[-1] if stop_blocks else None
    live_paths = [p for p in paths if p.reachable]
    dead_paths = [p for p in paths if not p.reachable]
    out: list[str] = [
        "=== RETURN FAMILY LEDGER ===",
        f"DB: {db_path.name}",
        f"Snapshot: [{snapshot_id}] {snap_label} ({len(blocks)} blocks, {len(reachable)} reachable)",
    ]
    if stop is not None:
        out.append(f"BLT_STOP: blk[{stop['serial']}]  preds={stop['preds']}")
    out.append(
        f"Return-slot writers (dest=0x7F0): blk{sorted(writers.keys())}"
    )
    out.append(f"v660 writers (dest=0x660): {v660_map}")
    out.append("")
    out.append(f"--- {len(live_paths)} Live Return Paths ---")
    for i, p in enumerate(live_paths, 1):
        tag = "PTS" if p.is_pts else "EPILOGUE"
        chain_str = " -> ".join(f"blk[{s}]" for s in p.chain)
        out.append("")
        out.append(f"  [{i}] {tag}  {chain_str}")
        out.append(f"      writer: {format_writer(p.writer)}")
        if p.v660_value:
            out.append(f"      v660: {p.v660_value}")
        if p.state_valranges:
            out.append(f"      valranges: {p.state_valranges[:160]}")
    if dead_paths:
        out.append("")
        out.append(f"--- {len(dead_paths)} Dead Paths (BFS-unreachable) ---")
        for p in dead_paths:
            chain_str = " -> ".join(f"blk[{s}]" for s in p.chain)
            out.append(f"  {chain_str}  (pred chain also unreachable)")
    out.append("")
    out.append(f"--- {len(after_returns)} AFTER Returns ---")
    for r in after_returns:
        out.append(f"  R{r.ordinal}  line {r.line_num}: return {r.expr[:120]}")
    out.append("")
    out.append("--- Summary ---")
    out.append(
        f"Structural paths: {len(paths)} ({len(live_paths)} live,"
        f" {len(dead_paths)} dead)"
    )
    out.append(f"AFTER returns: {len(after_returns)}")
    gap = len(live_paths) - len(after_returns)
    if gap > 0:
        out.append(
            f"Gap: {gap} live paths > AFTER returns (merge at decompiler)"
        )
    elif gap < 0:
        out.append(
            f"Gap: {-gap} AFTER returns > live paths"
            f" (bifurcation at multi-pred block)"
        )
    else:
        out.append("Gap: 0 (exact match)")
    return "\n".join(out) + "\n"


def render_json(
    *,
    db_path: Path,
    snapshot_id: int,
    snap_label: str,
    blocks: dict[int, dict],
    reachable: set[int],
    writers: dict[int, ReturnSlotWriter],
    v660_map: dict[int, str],
    paths: list[ReturnPath],
    after_returns: list[AfterReturn],
) -> str:
    stop_blocks = [b for b in blocks.values() if b["type"] == "BLT_STOP"]
    stop = stop_blocks[-1] if stop_blocks else None
    live_paths = [p for p in paths if p.reachable]
    dead_paths = [p for p in paths if not p.reachable]
    payload = {
        "db": str(db_path),
        "snapshot_id": snapshot_id,
        "snapshot_label": snap_label,
        "total_blocks": len(blocks),
        "reachable_blocks": len(reachable),
        "blt_stop": stop["serial"] if stop else None,
        "blt_stop_preds": stop["preds"] if stop else [],
        "return_slot_writers": {
            str(s): {
                "opcode": w.opcode,
                "src_type": w.src_type,
                "src_stkoff": w.src_stkoff,
                "src_value": w.src_value,
                "dstr": w.dstr[:120],
            }
            for s, w in sorted(writers.items())
        },
        "v660_writers": v660_map,
        "paths": [
            {
                "chain": p.chain,
                "root": p.root_serial,
                "pts": p.is_pts,
                "writer": format_writer(p.writer),
                "v660": p.v660_value,
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
    return json.dumps(payload, indent=2) + "\n"


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run_ledger(
    db_path: Path,
    *,
    dump_path: Path | None = None,
    snapshot_id: int | None = None,
    as_json: bool = False,
    list_snapshots_only: bool = False,
) -> str:
    """Render the return-family ledger for *db_path*.

    Returns the rendered text (caller writes it to stdout). Errors render
    as a single line beginning with ``Error:`` so the CLI can produce
    stable output.
    """
    if not db_path.exists():
        return f"Error: diag DB not found: {db_path}\n"
    conn = sqlite3.connect(str(db_path))
    try:
        if list_snapshots_only:
            lines = ["snapshots:"]
            for sid, label, bc in list_snapshots(conn):
                lines.append(f"  [{sid:2d}] {label} ({bc} blocks)")
            return "\n".join(lines) + "\n"
        sid = pick_snapshot(conn, snapshot_id)
        label_row = conn.execute(
            "SELECT label FROM snapshots WHERE id=?", (sid,)
        ).fetchone()
        snap_label = str(label_row[0]) if label_row else ""
        blocks = query_blocks(conn, sid)
        writers = query_return_slot_writers(conn, sid)
        v660_map = query_v660_writers(conn, sid)
        reachable = bfs_reachable(blocks)
        paths = trace_return_paths(blocks, writers, v660_map, reachable)
    finally:
        conn.close()

    after_returns: list[AfterReturn] = []
    if dump_path is not None and dump_path.exists():
        dump_lines = dump_path.read_text(errors="replace").splitlines(keepends=True)
        after_returns = extract_after_returns(dump_lines)

    renderer = render_json if as_json else render_text
    return renderer(
        db_path=db_path,
        snapshot_id=sid,
        snap_label=snap_label,
        blocks=blocks,
        reachable=reachable,
        writers=writers,
        v660_map=v660_map,
        paths=paths,
        after_returns=after_returns,
    )
