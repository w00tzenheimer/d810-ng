"""Generic single-hop resolution over exact state-dispatcher rows."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from d810.core.typing import Iterable


@dataclass(frozen=True)
class StateDispatchResolution:
    """Result of resolving one transition fact through dispatcher rows."""

    snapshot_id: int
    fact_id: str
    source_block_serial: int
    source_state_const_hex: str
    resolved_next_block_serial: int | None
    resolved_next_state_const_hex: str | None
    resolved_next_state_const_u64: int | None
    resolution_kind: str
    resolution_reason: str
    resolution_maturity: str

    def to_row(self) -> tuple:
        return (
            int(self.snapshot_id),
            self.fact_id,
            int(self.source_block_serial),
            self.source_state_const_hex,
            self.resolved_next_block_serial,
            self.resolved_next_state_const_hex,
            self.resolved_next_state_const_u64,
            self.resolution_kind,
            self.resolution_reason,
            self.resolution_maturity,
        )


@dataclass(frozen=True)
class LoadedStateDispatcherMap:
    """DB-loaded exact dispatcher map without IDA-time enum imports."""

    rows: tuple[object, ...]
    dispatcher_entry_block: int
    dispatcher_blocks: frozenset[int]
    state_to_handler: dict[int, int]

    def resolve_target(self, state_value: int) -> int | None:
        return self.state_to_handler.get(int(state_value))


def load_latest_state_dispatcher_map_from_db(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int | None = None,
) -> LoadedStateDispatcherMap | None:
    """Load the latest persisted exact state-dispatcher rows."""
    if snapshot_id is None:
        row = conn.execute(
            "SELECT snapshot_id FROM state_dispatcher_rows "
            "GROUP BY snapshot_id ORDER BY snapshot_id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        snapshot_id = int(row[0])
    rows = conn.execute(
        """
        SELECT state_const_i64, target_block, dispatcher_entry_block,
               compare_block, dispatcher_kind, branch_kind, confidence
        FROM state_dispatcher_rows
        WHERE snapshot_id=?
        ORDER BY row_index
        """,
        (int(snapshot_id),),
    ).fetchall()
    if not rows:
        return None

    dispatcher_blocks: set[int] = set()
    model_rows: list[object] = []
    state_to_handler: dict[int, int] = {}
    dispatcher_entry = None
    for row in rows:
        state_const = int(row[0]) & 0xFFFFFFFFFFFFFFFF
        target = int(row[1])
        entry = row[2]
        compare = int(row[3]) if row[3] is not None else None
        branch_kind = str(row[5] or "unknown")
        if entry is not None:
            dispatcher_entry = int(entry)
            dispatcher_blocks.add(int(entry))
        if compare is not None and compare != target and branch_kind != "handler_state_map":
            dispatcher_blocks.add(compare)
        state_to_handler[state_const] = target
        model_rows.append(
            {
                "state_const": state_const,
                "target_block": target,
                "dispatcher_block": (
                    int(entry) if entry is not None else int(compare or target)
                ),
                "compare_block": compare,
                "branch_kind": branch_kind,
                "confidence": float(row[6] if row[6] is not None else 1.0),
            }
        )
    if dispatcher_entry is None:
        dispatcher_entry = int(model_rows[0]["dispatcher_block"])
    return LoadedStateDispatcherMap(
        rows=tuple(model_rows),
        dispatcher_entry_block=int(dispatcher_entry),
        dispatcher_blocks=frozenset(dispatcher_blocks),
        state_to_handler=state_to_handler,
    )


def _select_locopt_state_const_at_block(
    conn: sqlite3.Connection,
    block_serial: int,
    canonical_stkoff_hex: str,
    snapshot_id: int,
) -> int | None:
    rows = conn.execute(
        """
        SELECT payload FROM fact_observations
        WHERE kind='StateWriteAnchorFact' AND snapshot_id=?
        """,
        (int(snapshot_id),),
    ).fetchall()
    for (payload_json,) in rows:
        try:
            payload = json.loads(payload_json) if payload_json else {}
        except (TypeError, ValueError):
            continue
        if int(payload.get("block_serial", -1)) != int(block_serial):
            continue
        if str(payload.get("state_var_stkoff_hex", "")).lower() != canonical_stkoff_hex.lower():
            continue
        const = payload.get("state_const_u64")
        if const is None:
            const = payload.get("state_const")
        if const is None:
            continue
        try:
            return int(const)
        except (TypeError, ValueError):
            continue
    return None


def resolve_state_transition_facts_with_dispatcher(
    conn: sqlite3.Connection,
    *,
    dispatch_map: object | None,
    locopt_snapshot_id: int,
    resolution_kind: str = "state_dispatcher_row",
    resolution_maturity: str = "MMAT_GLBOPT1",
) -> tuple[StateDispatchResolution, ...]:
    """Resolve transition facts using exact dispatcher rows."""
    fact_rows = conn.execute(
        """
        SELECT fact_id, payload
        FROM fact_observations
        WHERE kind='StateTransitionAnchorFact'
          AND snapshot_id=?
        """,
        (int(locopt_snapshot_id),),
    ).fetchall()

    resolutions: list[StateDispatchResolution] = []
    for fact_id, payload_json in fact_rows:
        try:
            payload = json.loads(payload_json) if payload_json else {}
        except (TypeError, ValueError):
            continue

        source_block = payload.get("source_block_serial")
        source_const = payload.get("source_state_const")
        source_const_hex = payload.get("source_state_const_hex")
        successor_kind = payload.get("successor_kind")
        canonical_stkoff_hex = str(payload.get("state_var_stkoff_hex", ""))

        if source_block is None or source_const is None or source_const_hex is None:
            continue

        target_block: int | None = None
        next_const_u64: int | None = None
        next_const_hex: str | None = None
        if successor_kind != "branch":
            reason = (
                f"successor_kind={successor_kind}; "
                "not a dispatcher-bound transition"
            )
        elif dispatch_map is None or not dispatch_map.rows:
            reason = "no_dispatcher_rows_available"
        else:
            target_block = dispatch_map.resolve_target(int(source_const))
            if target_block is None:
                reason = "state_not_in_dispatcher_map"
            elif target_block in dispatch_map.dispatcher_blocks:
                reason = "target_is_dispatcher_block"
                target_block = None
            else:
                next_const = _select_locopt_state_const_at_block(
                    conn,
                    block_serial=int(target_block),
                    canonical_stkoff_hex=canonical_stkoff_hex,
                    snapshot_id=int(locopt_snapshot_id),
                )
                if next_const is not None:
                    next_const_u64 = int(next_const) & 0xFFFFFFFFFFFFFFFF
                    next_const_hex = f"0x{next_const_u64:016x}"
                reason = "resolved_exact_state"

        resolutions.append(
            StateDispatchResolution(
                snapshot_id=int(locopt_snapshot_id),
                fact_id=str(fact_id),
                source_block_serial=int(source_block),
                source_state_const_hex=str(source_const_hex),
                resolved_next_block_serial=target_block,
                resolved_next_state_const_hex=next_const_hex,
                resolved_next_state_const_u64=next_const_u64,
                resolution_kind=resolution_kind,
                resolution_reason=reason,
                resolution_maturity=resolution_maturity,
            )
        )
    return tuple(resolutions)


def persist_state_dispatch_resolutions(
    conn: sqlite3.Connection,
    resolutions: Iterable[StateDispatchResolution],
) -> int:
    """Persist generic dispatcher resolution rows."""
    rows = [r.to_row() for r in resolutions]
    if not rows:
        return 0
    snapshot_ids = sorted({int(r[0]) for r in rows})
    for snap_id in snapshot_ids:
        conn.execute(
            "DELETE FROM state_transition_dispatch_resolutions "
            "WHERE snapshot_id = ?",
            (snap_id,),
        )
    conn.executemany(
        """
        INSERT INTO state_transition_dispatch_resolutions
            (snapshot_id, fact_id, source_block_serial,
             source_state_const_hex, resolved_next_block_serial,
             resolved_next_state_const_hex, resolved_next_state_const_u64,
             resolution_kind, resolution_reason, resolution_maturity)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        rows,
    )
    conn.commit()
    return len(rows)


__all__ = [
    "StateDispatchResolution",
    "load_latest_state_dispatcher_map_from_db",
    "persist_state_dispatch_resolutions",
    "resolve_state_transition_facts_with_dispatcher",
]
