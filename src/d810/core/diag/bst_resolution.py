"""Single-hop BST resolution for ``StateTransitionAnchorFact`` enrichment.

This module composes three already-persisted observations to enrich
LOCOPT-pre transition facts with the immediate post-dispatcher target:

1. ``StateTransitionAnchorFact`` -- captures source state const +
   LOCOPT-pre transit chain.
2. The BST ``INTERVAL_DISPATCHER_ROWS`` log line (one-hop interval
   lookup ``state_const -> handler block``).
3. ``StateWriteAnchorFact`` at the resolved handler block at LOCOPT-pre
   (gives the next state constant when the handler has a canonical
   state-write).

All three exist already; this module composes them.  No recon or HCC
behavior depends on the result; the enrichment lives in a dedicated
``state_transition_bst_resolutions`` table.

Resolution rules
----------------

* For each LOCOPT-pre ``StateTransitionAnchorFact`` whose
  ``successor_kind`` is ``branch`` AND whose ``transit_blocks`` chain
  ends at the dispatcher head (the BST interval dispatcher's most
  common target, by frequency), the resolver consults the BST and
  records the single-hop target handler block + that block's first
  canonical state-write const at LOCOPT-pre, if any.
* When ``successor_kind`` is ``direct`` / ``transit`` / ``loop`` /
  ``exit`` / ``unresolved``, no BST resolution is performed and the
  reason column records why.
* The resolver mirrors :func:`d810.recon.flow.bst_model.resolve_target_via_bst`
  semantics for the interval lookup.

The ``bst_resolution_maturity`` column records which maturity provided
the BST data (always ``MMAT_GLBOPT1`` today; left as a column so the
schema can accommodate later sources without migration).
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass

from d810.core.typing import Iterable


_BST_LOG_RE = re.compile(
    r"INTERVAL_DISPATCHER_ROWS:\s*(\[.*\])"
)


@dataclass(frozen=True)
class BstInterval:
    """One BST interval row: ``[lo, hi) -> target_block``."""

    lo: int
    hi: int
    target_block: int


@dataclass(frozen=True)
class BstResolution:
    """Result of resolving one ``StateTransitionAnchorFact``."""

    snapshot_id: int
    fact_id: str
    source_block_serial: int
    source_state_const_hex: str
    bst_resolved_next_block_serial: int | None
    bst_resolved_next_state_const_hex: str | None
    bst_resolved_next_state_const_u64: int | None
    bst_resolution_reason: str
    bst_resolution_maturity: str

    def to_row(self) -> tuple:
        return (
            int(self.snapshot_id),
            self.fact_id,
            int(self.source_block_serial),
            self.source_state_const_hex,
            self.bst_resolved_next_block_serial,
            self.bst_resolved_next_state_const_hex,
            self.bst_resolved_next_state_const_u64,
            self.bst_resolution_reason,
            self.bst_resolution_maturity,
        )


def parse_bst_intervals(payload_json: str) -> tuple[BstInterval, ...]:
    """Parse ``INTERVAL_DISPATCHER_ROWS`` JSON into typed intervals."""
    rows = json.loads(payload_json)
    out: list[BstInterval] = []
    for row in rows:
        try:
            lo = int(row["lo"], 16)
            hi = int(row["hi"], 16)
            target = int(row["target"])
        except (KeyError, TypeError, ValueError):
            continue
        out.append(BstInterval(lo=lo, hi=hi, target_block=target))
    return tuple(out)


def parse_latest_bst_intervals_from_log(log_path: str) -> tuple[BstInterval, ...]:
    """Return the LAST (latest) ``INTERVAL_DISPATCHER_ROWS`` row set
    from a d810 log file.

    Multiple rows are typically logged across decompilation passes;
    we use the last one because it reflects the BST after all
    upstream construction completed.
    """
    last_payload: str | None = None
    with open(log_path, "r", encoding="utf-8") as fh:
        for line in fh:
            match = _BST_LOG_RE.search(line)
            if match is not None:
                last_payload = match.group(1)
    if last_payload is None:
        return ()
    return parse_bst_intervals(last_payload)


def resolve_via_intervals(
    intervals: tuple[BstInterval, ...],
    state_const: int,
) -> int | None:
    """Single-hop interval lookup.

    Mirrors the semantics of
    :func:`d810.recon.flow.bst_model.resolve_target_via_bst` for the
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


def resolve_state_transition_facts(
    conn: sqlite3.Connection,
    *,
    bst_intervals: tuple[BstInterval, ...],
    locopt_snapshot_id: int,
    bst_resolution_maturity: str = "MMAT_GLBOPT1",
) -> tuple[BstResolution, ...]:
    """Compute BST-resolution rows for LOCOPT-pre transition facts.

    For each ``StateTransitionAnchorFact`` at ``locopt_snapshot_id``:

    * If ``successor_kind != "branch"``: skip (record reason).
    * Otherwise: look up ``source_state_const`` in the BST intervals
      and record the resolved handler block.  When that handler block
      has a canonical state-write at LOCOPT-pre, record its const as
      ``bst_resolved_next_state_const``.  Otherwise the const is
      ``None`` and the row records ``no_local_state_write_at_handler``.

    No recursive walking; single-hop interval resolution only.
    """
    fact_rows = conn.execute(
        """
        SELECT fact_id, payload
        FROM fact_observations
        WHERE kind='StateTransitionAnchorFact'
          AND snapshot_id=?
        """,
        (int(locopt_snapshot_id),),
    ).fetchall()

    resolutions: list[BstResolution] = []
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
                BstResolution(
                    snapshot_id=int(locopt_snapshot_id),
                    fact_id=str(fact_id),
                    source_block_serial=int(source_block),
                    source_state_const_hex=str(source_const_hex),
                    bst_resolved_next_block_serial=None,
                    bst_resolved_next_state_const_hex=None,
                    bst_resolved_next_state_const_u64=None,
                    bst_resolution_reason=(
                        f"successor_kind={successor_kind};"
                        " not a dispatcher-bound transition"
                    ),
                    bst_resolution_maturity=bst_resolution_maturity,
                )
            )
            continue

        if not bst_intervals:
            resolutions.append(
                BstResolution(
                    snapshot_id=int(locopt_snapshot_id),
                    fact_id=str(fact_id),
                    source_block_serial=int(source_block),
                    source_state_const_hex=str(source_const_hex),
                    bst_resolved_next_block_serial=None,
                    bst_resolved_next_state_const_hex=None,
                    bst_resolved_next_state_const_u64=None,
                    bst_resolution_reason="no_bst_intervals_available",
                    bst_resolution_maturity=bst_resolution_maturity,
                )
            )
            continue

        target_block = resolve_via_intervals(
            bst_intervals, int(source_const)
        )
        if target_block is None:
            resolutions.append(
                BstResolution(
                    snapshot_id=int(locopt_snapshot_id),
                    fact_id=str(fact_id),
                    source_block_serial=int(source_block),
                    source_state_const_hex=str(source_const_hex),
                    bst_resolved_next_block_serial=None,
                    bst_resolved_next_state_const_hex=None,
                    bst_resolved_next_state_const_u64=None,
                    bst_resolution_reason="no_bst_row",
                    bst_resolution_maturity=bst_resolution_maturity,
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
            reason = "bst_row_matched_with_local_state_write"
        else:
            reason = "bst_row_matched_no_local_state_write_at_handler"

        resolutions.append(
            BstResolution(
                snapshot_id=int(locopt_snapshot_id),
                fact_id=str(fact_id),
                source_block_serial=int(source_block),
                source_state_const_hex=str(source_const_hex),
                bst_resolved_next_block_serial=int(target_block),
                bst_resolved_next_state_const_hex=next_const_hex,
                bst_resolved_next_state_const_u64=next_const_u64,
                bst_resolution_reason=reason,
                bst_resolution_maturity=bst_resolution_maturity,
            )
        )
    return tuple(resolutions)


def persist_bst_resolutions(
    conn: sqlite3.Connection,
    resolutions: Iterable[BstResolution],
) -> int:
    """Persist resolution rows to ``state_transition_bst_resolutions``.

    Idempotent: existing rows for the same ``(snapshot_id, fact_id)``
    are deleted before insertion.  Returns the number of rows inserted.
    """
    rows = [r.to_row() for r in resolutions]
    if not rows:
        return 0
    snapshot_ids = sorted({int(r[0]) for r in rows})
    for snap_id in snapshot_ids:
        conn.execute(
            "DELETE FROM state_transition_bst_resolutions "
            "WHERE snapshot_id = ?",
            (snap_id,),
        )
    conn.executemany(
        """
        INSERT INTO state_transition_bst_resolutions
            (snapshot_id, fact_id, source_block_serial,
             source_state_const_hex, bst_resolved_next_block_serial,
             bst_resolved_next_state_const_hex,
             bst_resolved_next_state_const_u64,
             bst_resolution_reason, bst_resolution_maturity)
        VALUES (?,?,?,?,?,?,?,?,?)
        """,
        rows,
    )
    conn.commit()
    return len(rows)


__all__ = [
    "BstInterval",
    "BstResolution",
    "parse_bst_intervals",
    "parse_latest_bst_intervals_from_log",
    "resolve_via_intervals",
    "resolve_state_transition_facts",
    "persist_bst_resolutions",
]
