"""Single-hop condition-chain resolution for ``StateTransitionAnchorFact`` enrichment.

This module composes three already-persisted observations to enrich
LOCOPT-pre transition facts with the immediate post-dispatcher target:

1. ``StateTransitionAnchorFact`` -- captures source state const +
   LOCOPT-pre transit chain.
2. The condition-chain interval-dispatcher rows persisted in the diag DB
   (one-hop interval lookup ``state_const -> handler block``).
3. ``StateWriteAnchorFact`` at the resolved handler block at LOCOPT-pre
   (gives the next state constant when the handler has a canonical
   state-write).

All three exist already; this module composes them.  No recon or HCC
behavior depends on the result; the enrichment lives in a dedicated
``state_transition_condition_chain_resolutions`` table.

Resolution rules
----------------

* For each LOCOPT-pre ``StateTransitionAnchorFact`` whose
  ``successor_kind`` is ``branch`` AND whose ``transit_blocks`` chain
  ends at the dispatcher head (the condition-chain interval dispatcher's most
  common target, by frequency), the resolver consults the condition-chain interval rows and
  records the single-hop target handler block + that block's first
  canonical state-write const at LOCOPT-pre, if any.
* When ``successor_kind`` is ``direct`` / ``transit`` / ``loop`` /
  ``exit`` / ``unresolved``, no condition-chain resolution is performed and the
  reason column records why.
* The resolver mirrors :func:`d810.analyses.control_flow.condition_chain_model.resolve_target_via_condition_chain`
  semantics for the interval lookup.

The ``condition_chain_resolution_maturity`` column records which maturity provided
the condition-chain data (always ``MMAT_GLBOPT1`` today; left as a column so the
schema can accommodate later sources without migration).
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass

from d810.core.diag.models import ConditionChainIntervalDispatcherRow, FactObservation
from d810.core.typing import Iterable


_CONDITION_CHAIN_LOG_RE = re.compile(
    r"INTERVAL_DISPATCHER_ROWS:\s*(\[.*\])"
)


@dataclass(frozen=True)
class ConditionChainInterval:
    """One condition-chain interval row: ``[lo, hi) -> target_block``."""

    lo: int
    hi: int
    target_block: int


@dataclass(frozen=True)
class ConditionChainResolution:
    """Result of resolving one ``StateTransitionAnchorFact``."""

    snapshot_id: int
    fact_id: str
    source_block_serial: int
    source_state_const_hex: str
    condition_chain_resolved_next_block_serial: int | None
    condition_chain_resolved_next_state_const_hex: str | None
    condition_chain_resolved_next_state_const_u64: int | None
    condition_chain_resolution_reason: str
    condition_chain_resolution_maturity: str

    def to_row(self) -> tuple:
        return (
            int(self.snapshot_id),
            self.fact_id,
            int(self.source_block_serial),
            self.source_state_const_hex,
            self.condition_chain_resolved_next_block_serial,
            self.condition_chain_resolved_next_state_const_hex,
            self.condition_chain_resolved_next_state_const_u64,
            self.condition_chain_resolution_reason,
            self.condition_chain_resolution_maturity,
        )


def parse_condition_chain_intervals(payload_json: str) -> tuple[ConditionChainInterval, ...]:
    """Parse ``INTERVAL_DISPATCHER_ROWS`` JSON into typed intervals."""
    rows = json.loads(payload_json)
    out: list[ConditionChainInterval] = []
    for row in rows:
        try:
            lo = int(row["lo"], 16)
            hi = int(row["hi"], 16)
            target = int(row["target"])
        except (KeyError, TypeError, ValueError):
            continue
        out.append(ConditionChainInterval(lo=lo, hi=hi, target_block=target))
    return tuple(out)


def parse_latest_condition_chain_intervals_from_log(log_path: str) -> tuple[ConditionChainInterval, ...]:
    """Return the LAST (latest) ``INTERVAL_DISPATCHER_ROWS`` row set
    from a d810 log file.

    Multiple rows are typically logged across decompilation passes;
    we use the last one because it reflects the condition chain after all
    upstream construction completed.
    """
    last_payload: str | None = None
    with open(log_path, "r", encoding="utf-8") as fh:
        for line in fh:
            match = _CONDITION_CHAIN_LOG_RE.search(line)
            if match is not None:
                last_payload = match.group(1)
    if last_payload is None:
        return ()
    return parse_condition_chain_intervals(last_payload)


def load_latest_condition_chain_intervals_from_db(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int | None = None,
) -> tuple[ConditionChainInterval, ...]:
    """Load the latest persisted condition-chain interval-dispatcher rows from diag DB.

    ``snapshot_id`` can be supplied for deterministic inspection.  Without it,
    the latest snapshot that has interval rows is selected.
    """
    if snapshot_id is None:
        row = (
            ConditionChainIntervalDispatcherRow.select(ConditionChainIntervalDispatcherRow.snapshot)
            .group_by(ConditionChainIntervalDispatcherRow.snapshot)
            .order_by(ConditionChainIntervalDispatcherRow.snapshot.desc())
            .limit(1)
            .tuples()
            .first()
        )
        if row is None:
            return ()
        snapshot_id = int(row[0])
    rows = (
        ConditionChainIntervalDispatcherRow.select(
            ConditionChainIntervalDispatcherRow.lo_i64,
            ConditionChainIntervalDispatcherRow.hi_i64,
            ConditionChainIntervalDispatcherRow.target_block,
        )
        .where(ConditionChainIntervalDispatcherRow.snapshot == int(snapshot_id))
        .order_by(ConditionChainIntervalDispatcherRow.row_index)
        .tuples()
    )
    return tuple(
        ConditionChainInterval(
            lo=int(row[0]),
            hi=int(row[1]),
            target_block=int(row[2]),
        )
        for row in rows
    )


def resolve_via_intervals(
    intervals: tuple[ConditionChainInterval, ...],
    state_const: int,
) -> int | None:
    """Single-hop interval lookup.

    Mirrors the semantics of
    :func:`d810.analyses.control_flow.condition_chain_model.resolve_target_via_condition_chain` for the
    interval dispatcher fast path: linear scan over half-open
    ``[lo, hi)`` intervals.  Returns the target block serial or
    ``None`` when no interval matches.
    """
    for interval in intervals:
        if interval.lo <= state_const < interval.hi:
            return int(interval.target_block)
    return None


def _select_locopt_state_const_at_block(
    conn: sqlite3.Connection,
    block_serial: int,
    canonical_stkoff_hex: str,
    snapshot_id: int,
) -> int | None:
    """Return the LOCOPT-pre canonical state-write const at ``block_serial``,
    or ``None`` if the block has no canonical state-write at LOCOPT-pre.

    Reads the ``StateWriteAnchorFact`` payload directly so we don't need
    a parsed ``ValidatedFactView`` here.
    """
    rows = (
        FactObservation.select(FactObservation.payload)
        .where(
            (FactObservation.kind == "StateWriteAnchorFact")
            & (FactObservation.snapshot == int(snapshot_id))
        )
        .tuples()
    )
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


def resolve_state_transition_facts(
    conn: sqlite3.Connection,
    *,
    range_intervals: tuple[ConditionChainInterval, ...],
    locopt_snapshot_id: int,
    condition_chain_resolution_maturity: str = "MMAT_GLBOPT1",
) -> tuple[ConditionChainResolution, ...]:
    """Compute condition-chain resolution rows for LOCOPT-pre transition facts.

    For each ``StateTransitionAnchorFact`` at ``locopt_snapshot_id``:

    * If ``successor_kind != "branch"``: skip (record reason).
    * Otherwise: look up ``source_state_const`` in the condition-chain intervals
      and record the resolved handler block.  When that handler block
      has a canonical state-write at LOCOPT-pre, record its const as
      ``condition_chain_resolved_next_state_const``.  Otherwise the const is
      ``None`` and the row records ``no_local_state_write_at_handler``.

    No recursive walking; single-hop interval resolution only.
    """
    fact_rows = (
        FactObservation.select(
            FactObservation.fact_id, FactObservation.payload
        )
        .where(
            (FactObservation.kind == "StateTransitionAnchorFact")
            & (FactObservation.snapshot == int(locopt_snapshot_id))
        )
        .tuples()
    )

    resolutions: list[ConditionChainResolution] = []
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

        if (
            source_block is None
            or source_const is None
            or source_const_hex is None
        ):
            continue

        if successor_kind != "branch":
            resolutions.append(
                ConditionChainResolution(
                    snapshot_id=int(locopt_snapshot_id),
                    fact_id=str(fact_id),
                    source_block_serial=int(source_block),
                    source_state_const_hex=str(source_const_hex),
                    condition_chain_resolved_next_block_serial=None,
                    condition_chain_resolved_next_state_const_hex=None,
                    condition_chain_resolved_next_state_const_u64=None,
                    condition_chain_resolution_reason=(
                        f"successor_kind={successor_kind};"
                        " not a dispatcher-bound transition"
                    ),
                    condition_chain_resolution_maturity=condition_chain_resolution_maturity,
                )
            )
            continue

        if not range_intervals:
            resolutions.append(
                ConditionChainResolution(
                    snapshot_id=int(locopt_snapshot_id),
                    fact_id=str(fact_id),
                    source_block_serial=int(source_block),
                    source_state_const_hex=str(source_const_hex),
                    condition_chain_resolved_next_block_serial=None,
                    condition_chain_resolved_next_state_const_hex=None,
                    condition_chain_resolved_next_state_const_u64=None,
                    condition_chain_resolution_reason="no_condition_chain_intervals_available",
                    condition_chain_resolution_maturity=condition_chain_resolution_maturity,
                )
            )
            continue

        target_block = resolve_via_intervals(
            range_intervals, int(source_const)
        )
        if target_block is None:
            resolutions.append(
                ConditionChainResolution(
                    snapshot_id=int(locopt_snapshot_id),
                    fact_id=str(fact_id),
                    source_block_serial=int(source_block),
                    source_state_const_hex=str(source_const_hex),
                    condition_chain_resolved_next_block_serial=None,
                    condition_chain_resolved_next_state_const_hex=None,
                    condition_chain_resolved_next_state_const_u64=None,
                    condition_chain_resolution_reason="no_condition_chain_row",
                    condition_chain_resolution_maturity=condition_chain_resolution_maturity,
                )
            )
            continue

        next_const_u64: int | None = None
        next_const_hex: str | None = None
        next_const = _select_locopt_state_const_at_block(
            conn,
            block_serial=int(target_block),
            canonical_stkoff_hex=canonical_stkoff_hex,
            snapshot_id=int(locopt_snapshot_id),
        )
        if next_const is not None:
            next_const_u64 = int(next_const) & 0xFFFFFFFFFFFFFFFF
            next_const_hex = f"0x{next_const_u64:016x}"
            reason = "condition_chain_row_matched_with_local_state_write"
        else:
            reason = "condition_chain_row_matched_no_local_state_write_at_handler"

        resolutions.append(
            ConditionChainResolution(
                snapshot_id=int(locopt_snapshot_id),
                fact_id=str(fact_id),
                source_block_serial=int(source_block),
                source_state_const_hex=str(source_const_hex),
                condition_chain_resolved_next_block_serial=int(target_block),
                condition_chain_resolved_next_state_const_hex=next_const_hex,
                condition_chain_resolved_next_state_const_u64=next_const_u64,
                condition_chain_resolution_reason=reason,
                condition_chain_resolution_maturity=condition_chain_resolution_maturity,
            )
        )
    return tuple(resolutions)


def persist_condition_chain_resolutions(
    conn: sqlite3.Connection,
    resolutions: Iterable[ConditionChainResolution],
) -> int:
    """Persist resolution rows to ``state_transition_condition_chain_resolutions``.

    Idempotent: existing rows for the same ``(snapshot_id, fact_id)``
    are deleted before insertion.  Returns the number of rows inserted.
    """
    rows = [r.to_row() for r in resolutions]
    if not rows:
        return 0
    snapshot_ids = sorted({int(r[0]) for r in rows})
    for snap_id in snapshot_ids:
        conn.execute(
            "DELETE FROM state_transition_condition_chain_resolutions "
            "WHERE snapshot_id = ?",
            (snap_id,),
        )
    conn.executemany(
        """
        INSERT INTO state_transition_condition_chain_resolutions
            (snapshot_id, fact_id, source_block_serial,
             source_state_const_hex, condition_chain_resolved_next_block_serial,
             condition_chain_resolved_next_state_const_hex,
             condition_chain_resolved_next_state_const_u64,
             condition_chain_resolution_reason, condition_chain_resolution_maturity)
        VALUES (?,?,?,?,?,?,?,?,?)
        """,
        rows,
    )
    conn.commit()
    return len(rows)


__all__ = [
    "ConditionChainInterval",
    "ConditionChainResolution",
    "parse_condition_chain_intervals",
    "parse_latest_condition_chain_intervals_from_log",
    "load_latest_condition_chain_intervals_from_db",
    "resolve_via_intervals",
    "resolve_state_transition_facts",
    "persist_condition_chain_resolutions",
]
