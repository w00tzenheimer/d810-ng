"""Diag-DB adapters for the REF region-shape oracle."""
from __future__ import annotations

import json
import sqlite3

from d810.cfg.ref_region_oracle import BlockView, InstructionView
from d810.cfg.scc import compute_live_cfg_sccs, nontrivial_sccs


def collect_block_views_for_snapshot(
    conn: sqlite3.Connection, *, snapshot_id: int,
) -> dict[int, BlockView]:
    """Build BlockView objects for every block at one diag snapshot."""
    raw_blocks: dict[int, tuple[int, int, list[int], list[int], str]] = {}
    for row in conn.execute(
        "SELECT serial, start_ea_i64, end_ea_i64, preds, succs, type_name "
        "FROM blocks WHERE snapshot_id=?",
        (snapshot_id,),
    ):
        serial, start_ea, end_ea, preds_json, succs_json, type_name = row
        preds = json.loads(preds_json or "[]")
        succs = json.loads(succs_json or "[]")
        raw_blocks[int(serial)] = (
            int(start_ea or 0),
            int(end_ea or 0),
            list(int(p) for p in preds),
            list(int(s) for s in succs),
            str(type_name or ""),
        )

    block_succs = {s: tuple(b[3]) for s, b in raw_blocks.items()}
    sccs = compute_live_cfg_sccs(block_succs) if block_succs else ()
    cyclic = nontrivial_sccs(sccs) if sccs else ()
    block_to_size: dict[int, int] = {}
    for scc in cyclic:
        for block in scc.blocks:
            block_to_size[block] = scc.size

    instructions_by_block: dict[int, list[tuple[int, InstructionView]]] = {}
    for row in conn.execute(
        "SELECT block_serial, insn_index, opcode_name FROM instructions "
        "WHERE snapshot_id=? ORDER BY block_serial, insn_index",
        (snapshot_id,),
    ):
        block_serial, index, opcode = row
        instructions_by_block.setdefault(int(block_serial), []).append(
            (int(index or 0), InstructionView(opcode_name=str(opcode or "")))
        )

    result: dict[int, BlockView] = {}
    for serial, (start_ea, end_ea, preds, succs, type_name) in raw_blocks.items():
        pairs = instructions_by_block.get(serial, ())
        ordered = tuple(view for index, view in sorted(pairs, key=lambda p: p[0]))
        result[serial] = BlockView(
            serial=serial,
            start_ea=start_ea,
            end_ea=end_ea,
            instructions=ordered,
            preds=tuple(preds),
            succs=tuple(succs),
            in_scc=serial in block_to_size,
            scc_size=block_to_size.get(serial),
            block_type=type_name,
        )
    return result


__all__ = ["collect_block_views_for_snapshot"]
