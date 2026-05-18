#!/usr/bin/env python3
"""Extract Tigress indirect state-transfer facts from a diagnostics DB.

Run after a full diagnostic dump, for example:

    ./tools/d810cli.py dump -f tigress_flatten_indirect \
      -p default_unflattening_tigress_indirect_engine.json \
      --label tigress_indirect --full-diagnostics

Then:

    pyenv exec python tools/scripts/tigress_indirect_state_transfer_map.py \
      --db .tmp/logs/d810_logs/<func>.diag.sqlite3

The script is intentionally read-only. It reconstructs the finite state domain
from ``state_dispatcher_rows`` and walks snapshot CFG paths to the dispatcher
entry, collecting full-width constant writes to the configured state stack slot.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SnapshotChoice:
    snapshot_id: int
    label: str
    maturity: str
    phase: str
    block_count: int
    dispatcher_entry_block: int
    row_count: int
    missing_count: int


def _parse_json_list(value: object) -> tuple[int, ...]:
    if value in (None, ""):
        return ()
    try:
        raw = json.loads(str(value))
    except json.JSONDecodeError:
        return ()
    if not isinstance(raw, list):
        return ()
    return tuple(int(item) for item in raw)


def _overlaps(left_start: int, left_size: int, right_start: int, right_size: int) -> bool:
    if left_size <= 0 or right_size <= 0:
        return False
    return left_start < right_start + right_size and right_start < left_start + left_size


def choose_snapshot(conn: sqlite3.Connection) -> SnapshotChoice:
    """Choose the strongest snapshot carrying indirect state-dispatcher rows."""
    rows = conn.execute(
        """
        SELECT
          s.id,
          s.label,
          s.maturity,
          s.phase,
          s.block_count,
          r.dispatcher_entry_block,
          COUNT(*) AS row_count,
          SUM(CASE WHEN r.target_block = -1 THEN 1 ELSE 0 END) AS missing_count
        FROM state_dispatcher_rows r
        JOIN snapshots s ON s.id = r.snapshot_id
        WHERE r.dispatcher_kind = 'INDIRECT_JUMP'
        GROUP BY s.id, r.dispatcher_entry_block
        ORDER BY
          row_count DESC,
          missing_count ASC,
          CASE WHEN s.phase = 'pre_d810' THEN 0 ELSE 1 END,
          CASE WHEN s.maturity = 'MMAT_LOCOPT' THEN 0 ELSE 1 END,
          s.block_count DESC,
          s.id ASC
        """
    ).fetchall()
    if not rows:
        raise SystemExit("no INDIRECT_JUMP state_dispatcher_rows found")
    row = rows[0]
    return SnapshotChoice(
        snapshot_id=int(row[0]),
        label=str(row[1]),
        maturity=str(row[2]),
        phase=str(row[3]),
        block_count=int(row[4]),
        dispatcher_entry_block=int(row[5]),
        row_count=int(row[6]),
        missing_count=int(row[7] or 0),
    )


def load_blocks(conn: sqlite3.Connection, snapshot_id: int) -> dict[int, dict[str, Any]]:
    blocks: dict[int, dict[str, Any]] = {}
    for row in conn.execute(
        """
        SELECT serial, type_name, nsucc, npred, succs, preds, start_ea_hex, end_ea_hex
        FROM blocks
        WHERE snapshot_id = ?
        """,
        (snapshot_id,),
    ):
        serial = int(row[0])
        blocks[serial] = {
            "serial": serial,
            "type_name": row[1],
            "nsucc": int(row[2]),
            "npred": int(row[3]),
            "succs": _parse_json_list(row[4]),
            "preds": _parse_json_list(row[5]),
            "start_ea_hex": row[6],
            "end_ea_hex": row[7],
        }
    return blocks


def load_instructions(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> dict[int, list[dict[str, Any]]]:
    by_block: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in conn.execute(
        """
        SELECT
          block_serial,
          insn_index,
          ea_hex,
          ea_i64,
          opcode_name,
          dest_type,
          dest_stkoff,
          dest_size,
          src_l_type,
          src_l_stkoff,
          src_l_value_i64,
          src_r_type,
          src_r_stkoff,
          src_r_value_i64,
          dstr,
          meta
        FROM instructions
        WHERE snapshot_id = ?
        ORDER BY block_serial, insn_index
        """,
        (snapshot_id,),
    ):
        block_serial = int(row[0])
        by_block[block_serial].append(
            {
                "block_serial": block_serial,
                "insn_index": int(row[1]),
                "ea_hex": row[2],
                "ea_i64": int(row[3]),
                "opcode_name": row[4],
                "dest_type": row[5],
                "dest_stkoff": None if row[6] is None else int(row[6]),
                "dest_size": None if row[7] is None else int(row[7]),
                "src_l_type": row[8],
                "src_l_stkoff": None if row[9] is None else int(row[9]),
                "src_l_value_i64": None if row[10] is None else int(row[10]),
                "src_r_type": row[11],
                "src_r_stkoff": None if row[12] is None else int(row[12]),
                "src_r_value_i64": None if row[13] is None else int(row[13]),
                "dstr": row[14] or "",
                "meta": row[15] or None,
            }
        )
    return dict(by_block)


def load_dispatch_rows(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in conn.execute(
        """
        SELECT
          row_index,
          state_const_i64,
          state_const_hex,
          target_block,
          dispatcher_entry_block,
          branch_kind,
          payload_json
        FROM state_dispatcher_rows
        WHERE snapshot_id = ?
          AND dispatcher_kind = 'INDIRECT_JUMP'
        ORDER BY state_const_i64, row_index
        """,
        (snapshot_id,),
    ):
        try:
            payload = json.loads(row[6] or "{}")
        except json.JSONDecodeError:
            payload = {}
        rows.append(
            {
                "row_index": int(row[0]),
                "state": int(row[1]),
                "state_hex": row[2],
                "target_block": int(row[3]),
                "dispatcher_entry_block": int(row[4]),
                "branch_kind": row[5],
                "payload": payload,
            }
        )
    return rows


def _constant_state_write(
    insn: dict[str, Any],
    *,
    state_var_stkoff: int,
) -> dict[str, Any] | None:
    if insn.get("dest_type") != "mop_S":
        return None
    if insn.get("dest_stkoff") != state_var_stkoff:
        return None
    if insn.get("dest_size") != 4:
        return {
            "kind": "non_full_width_state_write",
            "ea": insn["ea_hex"],
            "block": insn["block_serial"],
            "dstr": insn["dstr"],
        }
    if insn.get("src_l_type") == "mop_n" and insn.get("src_l_value_i64") is not None:
        return {
            "kind": "constant_state_write",
            "ea": insn["ea_hex"],
            "block": insn["block_serial"],
            "value": int(insn["src_l_value_i64"]) & 0xFFFFFFFFFFFFFFFF,
            "dstr": insn["dstr"],
        }
    return {
        "kind": "nonconstant_state_write",
        "ea": insn["ea_hex"],
        "block": insn["block_serial"],
        "dstr": insn["dstr"],
    }


def _meta_json(insn: dict[str, Any]) -> dict[str, Any]:
    raw = insn.get("meta")
    if not raw:
        return {}
    try:
        decoded = json.loads(str(raw))
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _record_for_register(
    records: list[dict[str, Any]],
    *,
    names: tuple[str, ...],
    numbers: tuple[int, ...],
) -> dict[str, Any] | None:
    wanted_names = {name.lower() for name in names}
    wanted_numbers = {int(number) for number in numbers}
    for record in records:
        if int(record.get("register", -1)) in wanted_numbers:
            return record
        register_name = str(record.get("register_name") or "").lower()
        if register_name in wanted_names:
            return record
    return None


def _address_stack_offset(source: dict[str, Any] | None) -> int | None:
    if not isinstance(source, dict) or source.get("type") != "mop_a":
        return None
    inner = source.get("sub_operand")
    if not isinstance(inner, dict) or inner.get("type") != "mop_S":
        return None
    stkoff = inner.get("stkoff")
    return None if stkoff is None else int(stkoff)


def _address_global_ea(source: dict[str, Any] | None) -> str | None:
    if not isinstance(source, dict) or source.get("type") != "mop_a":
        return None
    inner = source.get("sub_operand")
    if not isinstance(inner, dict) or inner.get("type") != "mop_v":
        return None
    global_ea = inner.get("global_ea")
    return None if global_ea is None else str(global_ea)


def _constant_value(source: dict[str, Any] | None) -> int | None:
    if not isinstance(source, dict) or source.get("type") != "mop_n":
        return None
    value = source.get("value")
    return None if value is None else int(value)


def _table_initializer_from_call_meta(
    insn: dict[str, Any],
    *,
    table_stkoff: int,
    table_count: int,
    pointer_size: int,
) -> dict[str, Any] | None:
    meta = _meta_json(insn)
    records = meta.get("call_setup_registers")
    if not isinstance(records, list):
        return None
    register_records = [record for record in records if isinstance(record, dict)]
    # Windows x64 argument registers: rcx=dest, rdx=source, r8=size.
    dest = _record_for_register(register_records, names=("rcx",), numbers=(24,))
    source = _record_for_register(register_records, names=("rdx",), numbers=(16,))
    size = _record_for_register(register_records, names=("r8",), numbers=(72,))
    if dest is None or source is None or size is None:
        return None

    dest_stkoff = _address_stack_offset(dest.get("source"))
    byte_count = _constant_value(size.get("source"))
    source_global = _address_global_ea(source.get("source"))
    expected_size = table_count * pointer_size
    if dest_stkoff != int(table_stkoff) or byte_count != int(expected_size):
        return None
    return {
        "block": int(insn["block_serial"]),
        "ea": insn["ea_hex"],
        "dstr": insn.get("dstr", ""),
        "dest_stkoff": dest_stkoff,
        "source_global_ea": source_global,
        "byte_count": byte_count,
        "proof": "call_setup_registers",
    }


def _walk_transfer_paths(
    *,
    start_block: int,
    dispatcher_block: int,
    blocks: dict[int, dict[str, Any]],
    instructions_by_block: dict[int, list[dict[str, Any]]],
    state_var_stkoff: int,
    max_depth: int,
) -> dict[str, Any]:
    complete_paths: list[dict[str, Any]] = []
    terminal_paths: list[dict[str, Any]] = []
    unresolved_paths: list[dict[str, Any]] = []
    seen: set[tuple[int, int | None, int]] = set()

    def dfs(
        block_serial: int,
        last_state: int | None,
        writes: tuple[dict[str, Any], ...],
        path: tuple[int, ...],
    ) -> None:
        if len(path) > max_depth:
            unresolved_paths.append(
                {
                    "reason": "max_depth",
                    "path": list(path),
                    "last_state": last_state,
                    "writes": list(writes),
                }
            )
            return
        if block_serial == dispatcher_block:
            complete_paths.append(
                {
                    "next_state": last_state,
                    "path": list(path),
                    "writes": list(writes),
                    "reason": (
                        "constant_state_write" if last_state is not None else "no_state_write"
                    ),
                }
            )
            return
        key = (block_serial, last_state, len(path))
        if key in seen:
            unresolved_paths.append(
                {
                    "reason": "cycle",
                    "path": list(path),
                    "last_state": last_state,
                    "writes": list(writes),
                }
            )
            return
        seen.add(key)
        block = blocks.get(block_serial)
        if block is None:
            unresolved_paths.append(
                {
                    "reason": "missing_block",
                    "block": block_serial,
                    "path": list(path),
                    "last_state": last_state,
                    "writes": list(writes),
                }
            )
            return

        current_state = last_state
        current_writes = list(writes)
        for insn in instructions_by_block.get(block_serial, ()):
            write = _constant_state_write(insn, state_var_stkoff=state_var_stkoff)
            if write is None:
                continue
            current_writes.append(write)
            if write["kind"] == "constant_state_write":
                current_state = int(write["value"])
            else:
                current_state = None

        succs = tuple(block.get("succs", ()))
        if not succs:
            terminal_paths.append(
                {
                    "path": list(path),
                    "last_state": current_state,
                    "writes": current_writes,
                    "reason": "terminal_block",
                }
            )
            return
        for succ in succs:
            dfs(
                int(succ),
                current_state,
                tuple(current_writes),
                (*path, int(succ)),
            )

    dfs(start_block, None, (), (start_block,))
    return {
        "complete_paths": complete_paths,
        "terminal_paths": terminal_paths,
        "unresolved_paths": unresolved_paths,
    }


def check_table_invariance(
    *,
    blocks: dict[int, dict[str, Any]],
    instructions_by_block: dict[int, list[dict[str, Any]]],
    table_stkoff: int,
    table_count: int,
    pointer_size: int,
) -> dict[str, Any]:
    table_size = table_count * pointer_size
    explicit_writes: list[dict[str, Any]] = []
    initializer_calls: list[dict[str, Any]] = []
    suspicious_calls: list[dict[str, Any]] = []
    for block_serial, insns in instructions_by_block.items():
        for insn in insns:
            dstr = insn.get("dstr", "")
            call_initializer = _table_initializer_from_call_meta(
                insn,
                table_stkoff=table_stkoff,
                table_count=table_count,
                pointer_size=pointer_size,
            )
            if call_initializer is not None:
                initializer_calls.append(call_initializer)
                continue
            if "call" in dstr and "%var_1A8" in dstr:
                record = {
                    "block": block_serial,
                    "ea": insn["ea_hex"],
                    "dstr": dstr,
                }
                if "$off_" in dstr and "#0x128" in dstr:
                    initializer_calls.append(record)
                else:
                    suspicious_calls.append(record)
            dest_stkoff = insn.get("dest_stkoff")
            dest_size = insn.get("dest_size")
            if dest_stkoff is None or dest_size is None:
                continue
            if not _overlaps(int(dest_stkoff), int(dest_size), table_stkoff, table_size):
                continue
            explicit_writes.append(
                {
                    "block": block_serial,
                    "ea": insn["ea_hex"],
                    "dest_stkoff": int(dest_stkoff),
                    "dest_size": int(dest_size),
                    "dstr": dstr,
                }
            )
    return {
        "table_range": {
            "stkoff_start": table_stkoff,
            "stkoff_end_exclusive": table_stkoff + table_size,
            "entry_count": table_count,
            "pointer_size": pointer_size,
        },
        "proved_invariant": not explicit_writes and not suspicious_calls,
        "explicit_overlapping_writes": explicit_writes,
        "initializer_calls": initializer_calls,
        "suspicious_calls": suspicious_calls,
        "block_count": len(blocks),
    }


def prove_state_bounds_with_z3(
    *,
    observed_states: set[int],
    state_base: int,
    table_count: int,
) -> dict[str, Any]:
    try:
        import z3
    except Exception as exc:  # pragma: no cover - environment dependent
        return {
            "solver": "unavailable",
            "proved_non_negative_index": min(observed_states or {0}) >= state_base,
            "proved_table_upper_bound": (
                max(observed_states or {0}) <= state_base + table_count - 1
            ),
            "reason": repr(exc),
        }
    state = z3.Int("state")
    domain = z3.Or(*(state == int(value) for value in sorted(observed_states)))
    lower = z3.Solver()
    lower.add(domain, state < int(state_base))
    upper = z3.Solver()
    upper.add(domain, state > int(state_base + table_count - 1))
    lower_result = lower.check()
    upper_result = upper.check()
    return {
        "solver": "z3",
        "observed_state_count": len(observed_states),
        "state_base": state_base,
        "table_count": table_count,
        "index_expression": "state - state_base",
        "proved_non_negative_index": lower_result == z3.unsat,
        "lower_bound_check": str(lower_result),
        "proved_table_upper_bound": upper_result == z3.unsat,
        "upper_bound_check": str(upper_result),
    }


def extract_transfer_map(
    db_path: Path,
    *,
    snapshot_id: int | None = None,
    state_var_stkoff: int = 0x30,
    table_stkoff: int = 0x70,
    state_base: int = 1,
    table_count: int | None = None,
    pointer_size: int = 8,
    max_depth: int = 64,
) -> dict[str, Any]:
    conn = sqlite3.connect(str(db_path))
    try:
        if snapshot_id is None:
            choice = choose_snapshot(conn)
        else:
            row = conn.execute(
                """
                SELECT s.id, s.label, s.maturity, s.phase, s.block_count,
                       r.dispatcher_entry_block, COUNT(*),
                       SUM(CASE WHEN r.target_block = -1 THEN 1 ELSE 0 END)
                FROM snapshots s
                JOIN state_dispatcher_rows r ON r.snapshot_id = s.id
                WHERE s.id = ? AND r.dispatcher_kind = 'INDIRECT_JUMP'
                GROUP BY s.id, r.dispatcher_entry_block
                """,
                (snapshot_id,),
            ).fetchone()
            if row is None:
                raise SystemExit(f"snapshot {snapshot_id} has no INDIRECT_JUMP rows")
            choice = SnapshotChoice(
                snapshot_id=int(row[0]),
                label=str(row[1]),
                maturity=str(row[2]),
                phase=str(row[3]),
                block_count=int(row[4]),
                dispatcher_entry_block=int(row[5]),
                row_count=int(row[6]),
                missing_count=int(row[7] or 0),
            )
        blocks = load_blocks(conn, choice.snapshot_id)
        instructions_by_block = load_instructions(conn, choice.snapshot_id)
        dispatch_rows = load_dispatch_rows(conn, choice.snapshot_id)
    finally:
        conn.close()

    effective_table_count = int(table_count or len(dispatch_rows))
    transfers: list[dict[str, Any]] = []
    observed_states = {int(row["state"]) for row in dispatch_rows}
    for row in dispatch_rows:
        state = int(row["state"])
        target_block = int(row["target_block"])
        target_ea = row["payload"].get("target_ea_hex")
        if target_block < 0:
            transfers.append(
                {
                    "state": state,
                    "state_hex": row["state_hex"],
                    "target_block": target_block,
                    "target_ea": target_ea,
                    "kind": "missing_target",
                    "next_states": [],
                    "terminal": False,
                    "unresolved": True,
                    "paths": [],
                }
            )
            continue
        walked = _walk_transfer_paths(
            start_block=target_block,
            dispatcher_block=choice.dispatcher_entry_block,
            blocks=blocks,
            instructions_by_block=instructions_by_block,
            state_var_stkoff=state_var_stkoff,
            max_depth=max_depth,
        )
        complete = walked["complete_paths"]
        terminal = walked["terminal_paths"]
        unresolved = walked["unresolved_paths"]
        next_states = sorted(
            {
                int(path["next_state"])
                for path in complete
                if path.get("next_state") is not None
            }
        )
        observed_states.update(next_states)
        if terminal and not complete and not unresolved:
            kind = "terminal"
        elif len(next_states) == 1 and not unresolved:
            kind = "direct"
        elif len(next_states) > 1 and not unresolved:
            kind = "conditional"
        elif complete and not next_states:
            kind = "no_state_write_to_dispatcher"
        else:
            kind = "unresolved"
        transfers.append(
            {
                "state": state,
                "state_hex": row["state_hex"],
                "target_block": target_block,
                "target_ea": target_ea,
                "kind": kind,
                "next_states": next_states,
                "terminal": bool(terminal),
                "unresolved": bool(unresolved) or kind == "unresolved",
                "complete_path_count": len(complete),
                "terminal_path_count": len(terminal),
                "unresolved_path_count": len(unresolved),
                "paths": complete,
                "terminal_paths": terminal,
                "unresolved_paths": unresolved,
            }
        )

    bounds_proof = prove_state_bounds_with_z3(
        observed_states=observed_states,
        state_base=state_base,
        table_count=effective_table_count,
    )
    table_invariance = check_table_invariance(
        blocks=blocks,
        instructions_by_block=instructions_by_block,
        table_stkoff=table_stkoff,
        table_count=effective_table_count,
        pointer_size=pointer_size,
    )
    kind_counts: dict[str, int] = defaultdict(int)
    for transfer in transfers:
        kind_counts[str(transfer["kind"])] += 1

    return {
        "db": str(db_path),
        "snapshot": {
            "id": choice.snapshot_id,
            "label": choice.label,
            "maturity": choice.maturity,
            "phase": choice.phase,
            "block_count": choice.block_count,
            "dispatcher_entry_block": choice.dispatcher_entry_block,
            "row_count": choice.row_count,
            "missing_count": choice.missing_count,
        },
        "state_var": {
            "mop_type": "mop_S",
            "stkoff": state_var_stkoff,
            "size": 4,
        },
        "dispatcher_expression": {
            "state_base": state_base,
            "table_stkoff": table_stkoff,
            "pointer_size": pointer_size,
            "expression": "target_ptr = [sp + table_stkoff + pointer_size * zext(state - state_base)]",
        },
        "z3_bounds_proof": bounds_proof,
        "table_invariance": table_invariance,
        "transfer_kind_counts": dict(sorted(kind_counts.items())),
        "transfers": transfers,
    }


def render_text(report: dict[str, Any]) -> str:
    lines: list[str] = []
    snapshot = report["snapshot"]
    state_var = report["state_var"]
    bounds = report["z3_bounds_proof"]
    invariance = report["table_invariance"]
    lines.append("Tigress indirect state-transfer map")
    lines.append(f"DB: {report['db']}")
    lines.append(
        "Snapshot: "
        f"id={snapshot['id']} label={snapshot['label']} "
        f"maturity={snapshot['maturity']} phase={snapshot['phase']} "
        f"dispatcher_blk={snapshot['dispatcher_entry_block']} rows={snapshot['row_count']}"
    )
    lines.append(
        "State variable: "
        f"{state_var['mop_type']} stkoff=0x{state_var['stkoff']:x} size={state_var['size']}"
    )
    lines.append(
        "Z3 bounds: "
        f"non_negative_index={bounds['proved_non_negative_index']} "
        f"upper_bound={bounds['proved_table_upper_bound']} "
        f"domain_count={bounds.get('observed_state_count', 'n/a')}"
    )
    table_range = invariance["table_range"]
    lines.append(
        "Table invariance: "
        f"proved={invariance['proved_invariant']} "
        f"range=[0x{table_range['stkoff_start']:x},0x{table_range['stkoff_end_exclusive']:x}) "
        f"explicit_writes={len(invariance['explicit_overlapping_writes'])} "
        f"suspicious_calls={len(invariance['suspicious_calls'])} "
        f"initializers={len(invariance['initializer_calls'])}"
    )
    lines.append(f"Transfer kind counts: {report['transfer_kind_counts']}")
    lines.append("Transfers:")
    for transfer in report["transfers"]:
        next_states = ",".join(f"0x{value:x}" for value in transfer["next_states"])
        if not next_states:
            next_states = "-"
        target_ea = transfer.get("target_ea") or "-"
        lines.append(
            f"  state=0x{transfer['state']:x} target_blk={transfer['target_block']} "
            f"target_ea={target_ea} kind={transfer['kind']} next={next_states} "
            f"paths={transfer.get('complete_path_count', 0)} "
            f"terminal={transfer.get('terminal_path_count', 0)} "
            f"unresolved={transfer.get('unresolved_path_count', 0)}"
        )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract a Tigress indirect handler state-transfer map from a D810 diag DB."
    )
    parser.add_argument("--db", required=True, type=Path, help="Diagnostic SQLite DB")
    parser.add_argument("--snapshot-id", type=int, default=None)
    parser.add_argument("--state-var-stkoff", type=lambda value: int(value, 0), default=0x30)
    parser.add_argument("--table-stkoff", type=lambda value: int(value, 0), default=0x70)
    parser.add_argument("--state-base", type=lambda value: int(value, 0), default=1)
    parser.add_argument("--table-count", type=int, default=None)
    parser.add_argument("--pointer-size", type=int, default=8)
    parser.add_argument("--max-depth", type=int, default=64)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = extract_transfer_map(
        args.db,
        snapshot_id=args.snapshot_id,
        state_var_stkoff=args.state_var_stkoff,
        table_stkoff=args.table_stkoff,
        state_base=args.state_base,
        table_count=args.table_count,
        pointer_size=args.pointer_size,
        max_depth=args.max_depth,
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
