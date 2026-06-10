"""Extract indirect-dispatcher state-transfer facts from a diagnostics DB.

Run after a full diagnostic dump, for example:

    ./tools/d810cli.py dump -f tigress_flatten_indirect \
      -p default_unflattening_tigress_indirect.json \
      --label tigress_indirect --full-diagnostics

Then:

    ./tools/d810cli.py indirect-transfer-map \
      --db .tmp/logs/d810_logs/<func>.diag.sqlite3

The command is intentionally read-only. It reconstructs the finite state domain
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

from d810.core.diag import read_diag_db
from d810.core.diag.models import (
    Block,
    CfgProvenance,
    Instruction,
    StateDispatcherRow,
)
from d810.diagnostics.output import add_output_argument, get_output, write_output
from d810.core.typing import Any



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
    # raw-SQL: GROUP BY + COUNT/SUM(CASE...) aggregation with a multi-key
    # ranking ORDER BY built from CASE-WHEN priority expressions (phase,
    # maturity tie-breaks) -- an analytical ranking query that an ORM
    # rewrite would only obscure (§3 complex-SQL policy).
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
    for row in (
        Block.select(
            Block.serial,
            Block.type_name,
            Block.nsucc,
            Block.npred,
            Block.succs,
            Block.preds,
            Block.start_ea_hex,
            Block.end_ea_hex,
        )
        .where(Block.snapshot == snapshot_id)
        .tuples()
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
    for row in (
        Instruction.select(
            Instruction.block_serial,
            Instruction.insn_index,
            Instruction.ea_hex,
            Instruction.ea_i64,
            Instruction.opcode_name,
            Instruction.dest_type,
            Instruction.dest_stkoff,
            Instruction.dest_size,
            Instruction.src_l_type,
            Instruction.src_l_stkoff,
            Instruction.src_l_value_i64,
            Instruction.src_r_type,
            Instruction.src_r_stkoff,
            Instruction.src_r_value_i64,
            Instruction.dstr,
            Instruction.meta,
        )
        .where(Instruction.snapshot == snapshot_id)
        .order_by(Instruction.block_serial, Instruction.insn_index)
        .tuples()
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
    for row in (
        StateDispatcherRow.select(
            StateDispatcherRow.row_index,
            StateDispatcherRow.state_const_i64,
            StateDispatcherRow.state_const_hex,
            StateDispatcherRow.target_block,
            StateDispatcherRow.dispatcher_entry_block,
            StateDispatcherRow.branch_kind,
            StateDispatcherRow.payload_json,
        )
        .where(
            (StateDispatcherRow.snapshot == snapshot_id)
            & (StateDispatcherRow.dispatcher_kind == "INDIRECT_JUMP")
        )
        .order_by(
            StateDispatcherRow.state_const_i64, StateDispatcherRow.row_index
        )
        .tuples()
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


def load_lowered_conditionals(
    conn: sqlite3.Connection,
) -> dict[int, tuple[int, int]]:
    """Map a lowered-conditional source block to its (true_arm, false_arm) blocks.

    §1a lowers a proven conditional state-write-to-dispatcher into a direct
    2-way edge *before* the diagnostic snapshot is captured, so the surviving
    snapshot shows only a 1-way handler with no constant state write. The
    deferred modifier persists the lowering provenance to ``cfg_provenance``
    under action ``LOWER_CONDITIONAL_STATE_TRANSITION`` (diagnostic-only — the
    CFG rewrite itself is unaffected). This reconstructs, per source block, the
    two handler blocks that the conditional now branches to, so the transfer
    map can re-derive the two next-states.

    The lowering provenance is flushed under the post-pipeline snapshot whose
    block serials match the chosen INDIRECT_JUMP snapshot, so we read across all
    snapshots and key on the (maturity-local) block serial.
    """
    lowered: dict[int, tuple[int, int]] = {}
    for row in (
        CfgProvenance.select(
            CfgProvenance.block_serial,
            CfgProvenance.extra_json,
        )
        .where(CfgProvenance.action == "LOWER_CONDITIONAL_STATE_TRANSITION")
        .tuples()
    ):
        source_block = int(row[0])
        try:
            extra = json.loads(row[1] or "{}")
        except json.JSONDecodeError:
            continue
        true_target = extra.get("true_target")
        false_target = extra.get("false_target")
        if true_target is None or false_target is None:
            continue
        lowered[source_block] = (int(true_target), int(false_target))
    return lowered


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
    with read_diag_db(str(db_path)) as db:
        conn = db.connection()
        if snapshot_id is None:
            choice = choose_snapshot(conn)
        else:
            # raw-SQL: GROUP BY + COUNT/SUM(CASE...) aggregate over a JOIN,
            # selecting one snapshot's INDIRECT_JUMP dispatcher summary
            # (§3 complex-SQL policy).
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
        lowered_conditionals = load_lowered_conditionals(conn)

    # Map each handler block to the dispatcher state it implements, so a lowered
    # conditional's true/false ARM blocks can be resolved back to next-states.
    state_by_target_block = {
        int(row["target_block"]): int(row["state"])
        for row in dispatch_rows
        if int(row["target_block"]) >= 0
    }
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
        lowered_via: dict[str, Any] | None = None
        # A state whose handler reaches the dispatcher with NO constant
        # state-write is the surviving fallthrough of a conditional that §1a
        # already lowered into a direct 2-way edge. Re-derive the two
        # next-states from the lowered-conditional arm blocks (each arm block is
        # itself a dispatcher handler whose state is known via the dispatch
        # rows). This records the REAL conditional that the snapshot lost.
        if not next_states and complete and target_block in lowered_conditionals:
            true_block, false_block = lowered_conditionals[target_block]
            arm_states = sorted(
                {
                    state_value
                    for arm_block in (true_block, false_block)
                    for state_value in (state_by_target_block.get(int(arm_block)),)
                    if state_value is not None
                }
            )
            if len(arm_states) > 1:
                next_states = arm_states
                lowered_via = {
                    "true_block": int(true_block),
                    "false_block": int(false_block),
                    "arm_states": arm_states,
                }
        observed_states.update(next_states)
        if terminal and not complete and not unresolved:
            kind = "terminal"
        elif lowered_via is not None and len(next_states) > 1:
            kind = "conditional"
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
                "lowered_conditional": lowered_via,
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
    lines.append("Indirect dispatcher state-transfer map")
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


def _add_arguments(parser: argparse.ArgumentParser, *, include_db: bool) -> None:
    if include_db:
        parser.add_argument("--db", required=True, type=Path, help="Diagnostic SQLite DB")
    parser.add_argument("--snapshot-id", type=int, default=None)
    parser.add_argument(
        "--state-var-stkoff",
        type=lambda value: int(value, 0),
        default=0x30,
        help="state variable stack offset (default: 0x30)",
    )
    parser.add_argument(
        "--table-stkoff",
        type=lambda value: int(value, 0),
        default=0x70,
        help="stack offset of the indirect target table (default: 0x70)",
    )
    parser.add_argument(
        "--state-base",
        type=lambda value: int(value, 0),
        default=1,
        help="base state value subtracted before table indexing (default: 1)",
    )
    parser.add_argument("--table-count", type=int, default=None)
    parser.add_argument("--pointer-size", type=int, default=8)
    parser.add_argument("--max-depth", type=int, default=64)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")


def register_parser(subparsers, common: argparse.ArgumentParser | None = None) -> None:
    parents = [common] if common is not None else []
    parser = subparsers.add_parser(
        "indirect-transfer-map",
        parents=parents,
        help="Extract an indirect-dispatcher state-transfer map from a diag DB.",
        description=(
            "Extract an indirect-dispatcher state-transfer map from D810 "
            "diagnostic snapshots. This is read-only and consumes compact DB "
            "rows, including instruction metadata for table-population proof."
        ),
    )
    _add_arguments(parser, include_db=common is None)
    if common is None:
        add_output_argument(parser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract an indirect-dispatcher state-transfer map from a D810 diag DB."
    )
    _add_arguments(parser, include_db=True)
    add_output_argument(parser)
    return parser


def run(args: argparse.Namespace) -> int:
    report = extract_transfer_map(
        Path(args.db),
        snapshot_id=args.snapshot_id,
        state_var_stkoff=args.state_var_stkoff,
        table_stkoff=args.table_stkoff,
        state_base=args.state_base,
        table_count=args.table_count,
        pointer_size=args.pointer_size,
        max_depth=args.max_depth,
    )
    if args.json:
        write_output(get_output(args), json.dumps(report, indent=2, sort_keys=True))
    else:
        write_output(get_output(args), render_text(report))
    return 0


def main(argv: list[str] | None = None) -> int:
    return run(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
