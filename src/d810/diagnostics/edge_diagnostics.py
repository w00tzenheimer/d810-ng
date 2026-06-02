"""DAG edge diagnostic classification.

This module classifies recon-time ``state_cfg_edges`` rows by correlating them
with three fact-substrate sources written elsewhere in the diag DB:

* ``StateWriteAnchor STATE_CONST_REWRITTEN`` mappings (per-block proof
  that IDA's MMAT_LOCOPT/CALLS pass replaced a state-write constant
  between maturities).
* ``StateTransitionAnchorFact`` observations (per-source-block CFG
  transit chain captured at LOCOPT-pre).
* ``TerminalByteEmitterFact`` observations with
  ``corridor_role=terminal_tail`` (used to flag whether an edge belongs
  to the terminal byte-tail class we care about most).

Observability-only: classifications are persisted to the
``state_cfg_edge_diagnostics`` table; no recon edge target selection or HCC
behavior depends on them.  Future fact-backed correction passes can
target specific classification rows for narrow review.

Classification rules
--------------------

``LOCOPT_REWRITTEN_SOURCE``
    The edge's source-state entry block has at least one
    ``STATE_CONST_REWRITTEN`` mapping (its state-write was rewritten by
    IDA between LOCOPT and CALLS/GLBOPT1).  This is the base
    classification for any edge whose source has been touched by IDA's
    constant propagation.

``TARGET_UNRESOLVED_AFTER_REWRITE``
    The edge's source is ``LOCOPT_REWRITTEN_SOURCE`` AND the edge has a
    NULL ``target_state_hex`` (recon could not resolve a successor
    state).  Strict subset of ``LOCOPT_REWRITTEN_SOURCE``.

``COLLAPSED_TO_REWRITTEN_TARGET``
    The edge's source is ``LOCOPT_REWRITTEN_SOURCE`` AND the edge's
    ``target_state_hex`` matches the *rewritten* constant of some other
    block's ``STATE_CONST_REWRITTEN`` mapping (i.e. recon's edge target
    is itself a state-constant that IDA created via CP, not a state
    that existed at LOCOPT).  Strict subset of
    ``LOCOPT_REWRITTEN_SOURCE``.

``SPURIOUS_CONDITIONAL_ARM``
    The edge has ``edge_kind = CONDITIONAL_TRANSITION`` AND another
    edge from the same ``source_state_hex`` carries the same
    ``target_state_hex`` (often a sibling ``TRANSITION``).  These are
    typically over-resolved branch arms recon emitted because the
    multi-arm branch was not canonicalized.  Independent of the
    rewrite-source axis: an edge can be both ``LOCOPT_REWRITTEN_SOURCE``
    and ``SPURIOUS_CONDITIONAL_ARM``; the classifier prefers the
    REWRITTEN axis when both apply (rewrite is the more load-bearing
    diagnostic) and includes the spurious flag in the ``reason`` text.

``BENIGN``
    None of the above.  The edge has no rewritten source and is not a
    redundant conditional arm.

Terminal-tail filter
--------------------

An edge is marked ``is_terminal_tail = 1`` when its
``source_block`` matches the ``destination_block`` of some
``terminal_tail`` ``TerminalByteEmitterFact``, OR its source-state
entry_block (per ``state_cfg_node_blocks``) matches such a destination_block.
The flag is independent of the classification axis -- it lets queries
filter to the byte1..byte6 corridor without re-deriving the mapping.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from d810.core.typing import Iterable


_VALID_CLASSIFICATIONS: frozenset[str] = frozenset({
    "BENIGN",
    "LOCOPT_REWRITTEN_SOURCE",
    "TARGET_UNRESOLVED_AFTER_REWRITE",
    "COLLAPSED_TO_REWRITTEN_TARGET",
    "SPURIOUS_CONDITIONAL_ARM",
})


@dataclass(frozen=True)
class EdgeDiagnostic:
    """One classified ``state_cfg_edges`` row."""

    snapshot_id: int
    edge_id: int
    classification: str
    source_state_hex: str | None
    target_state_hex: str | None
    edge_kind: str
    is_terminal_tail: int
    original_state_const: str | None
    rewritten_state_const: str | None
    related_fact_ids: tuple[str, ...]
    reason: str

    def to_row(self) -> tuple:
        return (
            int(self.snapshot_id),
            int(self.edge_id),
            self.classification,
            self.source_state_hex,
            self.target_state_hex,
            self.edge_kind,
            int(self.is_terminal_tail),
            self.original_state_const,
            self.rewritten_state_const,
            json.dumps(list(self.related_fact_ids)),
            self.reason,
        )


def _select_state_const_rewritten_index(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> tuple[
    dict[int, list[dict]],  # block_serial -> list of mapping dicts (orig+rewritten consts)
    set[str],               # rewritten consts (lower-cased, padded hex 0x000000XX)
    dict[str, list[str]],   # rewritten_const_hex -> list of source_fact_ids
]:
    """Build the per-block rewrite map at ``snapshot_id``.

    Reads ``fact_mappings`` rows where ``status='STATE_CONST_REWRITTEN'``
    and the mapping's payload's ``to_maturity`` resolves to the snapshot
    we are classifying (or earlier, in case the rewrite landed before
    the snapshot we are analyzing).  Returns three indexes used by
    callers below.
    """
    by_block: dict[int, list[dict]] = {}
    rewritten_consts: set[str] = set()
    rewritten_to_sources: dict[str, list[str]] = {}

    rows = conn.execute(
        """
        SELECT source_fact_id, payload
        FROM fact_mappings
        WHERE status = 'STATE_CONST_REWRITTEN'
        """
    ).fetchall()
    for source_fact_id, payload_json in rows:
        try:
            payload = json.loads(payload_json) if payload_json else {}
        except (TypeError, ValueError):
            continue
        block_serial = payload.get("block_serial")
        if block_serial is None:
            continue
        try:
            block_serial = int(block_serial)
        except (TypeError, ValueError):
            continue
        original = payload.get("original_const_hex")
        rewritten = payload.get("rewritten_const_hex")
        if original and rewritten:
            entry = {
                "original_const_hex": str(original).lower(),
                "rewritten_const_hex": str(rewritten).lower(),
                "from_maturity": payload.get("from_maturity"),
                "to_maturity": payload.get("to_maturity"),
                "source_fact_id": str(source_fact_id) if source_fact_id else None,
            }
            by_block.setdefault(block_serial, []).append(entry)
            rewritten_consts.add(str(rewritten).lower())
            rewritten_to_sources.setdefault(
                str(rewritten).lower(),
                [],
            ).append(str(source_fact_id) if source_fact_id else "")
    return by_block, rewritten_consts, rewritten_to_sources


def _select_terminal_tail_blocks(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> set[int]:
    """Return the set of block serials that are
    ``terminal_tail`` byte-emit destinations.

    Uses ``fact_observations`` rows of kind ``TerminalByteEmitterFact``
    across **all** snapshots (the byte-emit destination set is a
    function-wide invariant, not a per-snapshot view).  The
    ``snapshot_id`` argument is accepted for symmetry but unused.
    """
    blocks: set[int] = set()
    _ = snapshot_id  # accepted for API symmetry
    rows = conn.execute(
        """
        SELECT payload
        FROM fact_observations
        WHERE kind = 'TerminalByteEmitterFact'
        """,
    ).fetchall()
    for (payload_json,) in rows:
        try:
            payload = json.loads(payload_json) if payload_json else {}
        except (TypeError, ValueError):
            continue
        if payload.get("corridor_role") != "terminal_tail":
            continue
        for key in ("destination_block", "block_serial"):
            raw = payload.get(key)
            if raw is None:
                continue
            try:
                blocks.add(int(raw))
            except (TypeError, ValueError):
                continue
    return blocks


def _select_state_entry_blocks(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> dict[str, set[int]]:
    """Return ``{state_hex: {entry_block, ...}}`` for ``state_cfg_nodes``.

    Used to widen the terminal-tail filter: an edge is terminal_tail if
    its source-state's entry_block (or any owned block) is a known
    byte-emit destination.
    """
    out: dict[str, set[int]] = {}
    rows = conn.execute(
        """
        SELECT state_hex, entry_block FROM state_cfg_nodes WHERE snapshot_id = ?
        """,
        (snapshot_id,),
    ).fetchall()
    for state_hex, entry_block in rows:
        if state_hex is None:
            continue
        out.setdefault(str(state_hex).lower(), set()).add(int(entry_block))
    return out


def _find_sibling_target_states(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> dict[tuple[str, str], list[tuple[int, str]]]:
    """Return ``{(source_state_hex, target_state_hex): [(edge_id, edge_kind), ...]}``.

    Used to identify ``SPURIOUS_CONDITIONAL_ARM`` edges -- a CONDITIONAL_TRANSITION
    is spurious when another edge from the same source_state has the same
    target_state.
    """
    out: dict[tuple[str, str], list[tuple[int, str]]] = {}
    rows = conn.execute(
        """
        SELECT edge_id, source_state_hex, target_state_hex, edge_kind
        FROM state_cfg_edges
        WHERE snapshot_id = ?
          AND source_state_hex IS NOT NULL
          AND target_state_hex IS NOT NULL
        """,
        (snapshot_id,),
    ).fetchall()
    for edge_id, src, tgt, kind in rows:
        key = (str(src).lower(), str(tgt).lower())
        out.setdefault(key, []).append((int(edge_id), str(kind)))
    return out


def classify_dag_edges(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> tuple[EdgeDiagnostic, ...]:
    """Classify every ``state_cfg_edges`` row at ``snapshot_id``.

    Pure read against ``fact_mappings`` / ``fact_observations`` /
    ``state_cfg_nodes`` / ``state_cfg_node_blocks`` / ``state_cfg_edges``.  Caller decides
    whether to persist the returned rows into ``state_cfg_edge_diagnostics``
    (see :func:`persist_edge_diagnostics`).
    """
    by_block, rewritten_consts, rewritten_sources = _select_state_const_rewritten_index(
        conn, snapshot_id
    )
    terminal_tail_blocks = _select_terminal_tail_blocks(conn, snapshot_id)
    state_entry_blocks = _select_state_entry_blocks(conn, snapshot_id)

    # State-hex -> set(blocks owned/exclusive) so we can check whether an
    # edge's source_state's entry blocks intersect terminal-tail destinations.
    state_owned_blocks: dict[str, set[int]] = {}
    rows = conn.execute(
        """
        SELECT state_hex, block_serial FROM state_cfg_node_blocks WHERE snapshot_id = ?
        """,
        (snapshot_id,),
    ).fetchall()
    for state_hex, block_serial in rows:
        if state_hex is None:
            continue
        state_owned_blocks.setdefault(
            str(state_hex).lower(),
            set(),
        ).add(int(block_serial))

    sibling_index = _find_sibling_target_states(conn, snapshot_id)

    diagnostics: list[EdgeDiagnostic] = []
    edge_rows = conn.execute(
        """
        SELECT edge_id, source_state_hex, target_state_hex, edge_kind, source_block
        FROM state_cfg_edges
        WHERE snapshot_id = ?
        """,
        (snapshot_id,),
    ).fetchall()

    for edge_id, src_state, tgt_state, edge_kind, source_block in edge_rows:
        src_state_lower = str(src_state).lower() if src_state is not None else None
        tgt_state_lower = str(tgt_state).lower() if tgt_state is not None else None

        # Terminal-tail flag: source_block is itself a byte-emit
        # destination, OR the source_state owns a block that is.
        is_terminal_tail = 0
        if source_block is not None and int(source_block) in terminal_tail_blocks:
            is_terminal_tail = 1
        elif src_state_lower is not None:
            owned = state_owned_blocks.get(src_state_lower, set())
            if owned & terminal_tail_blocks:
                is_terminal_tail = 1

        related_facts: list[str] = []
        original_const: str | None = None
        rewritten_const: str | None = None

        # --- Rewrite-source detection ---
        rewrite_entries: list[dict] = []
        if src_state_lower is not None:
            for entry_block in state_entry_blocks.get(src_state_lower, set()):
                rewrite_entries.extend(by_block.get(int(entry_block), []))
            for owned_block in state_owned_blocks.get(src_state_lower, set()):
                rewrite_entries.extend(by_block.get(int(owned_block), []))
        if source_block is not None:
            rewrite_entries.extend(by_block.get(int(source_block), []))

        is_rewritten_source = bool(rewrite_entries)
        if rewrite_entries:
            # Take the first entry's consts as representative; multiple
            # rewrites in the same source block are rare and the
            # diagnostic is illustrative not exhaustive.
            original_const = rewrite_entries[0]["original_const_hex"]
            rewritten_const = rewrite_entries[0]["rewritten_const_hex"]
            for entry in rewrite_entries:
                fid = entry.get("source_fact_id")
                if fid:
                    related_facts.append(str(fid))

        # --- Spurious-conditional detection ---
        is_spurious = False
        if (
            edge_kind == "CONDITIONAL_TRANSITION"
            and src_state_lower is not None
            and tgt_state_lower is not None
        ):
            siblings = sibling_index.get(
                (src_state_lower, tgt_state_lower), []
            )
            non_self_kinds = [
                k for (eid, k) in siblings if int(eid) != int(edge_id)
            ]
            if non_self_kinds:
                is_spurious = True

        # --- Classification priority ---
        # TARGET_UNRESOLVED_AFTER_REWRITE > COLLAPSED_TO_REWRITTEN_TARGET >
        # LOCOPT_REWRITTEN_SOURCE > SPURIOUS_CONDITIONAL_ARM > BENIGN.
        # The rewrite axis is more load-bearing than the spurious axis;
        # the spurious flag is recorded in the reason text when both apply.
        if is_rewritten_source and tgt_state is None:
            classification = "TARGET_UNRESOLVED_AFTER_REWRITE"
            reason = (
                f"source has STATE_CONST_REWRITTEN ({original_const} -> "
                f"{rewritten_const}); target_state is NULL"
            )
        elif (
            is_rewritten_source
            and tgt_state_lower is not None
            and tgt_state_lower in rewritten_consts
        ):
            classification = "COLLAPSED_TO_REWRITTEN_TARGET"
            tgt_sources = rewritten_sources.get(tgt_state_lower, [])
            for tgt_fid in tgt_sources:
                if tgt_fid:
                    related_facts.append(str(tgt_fid))
            reason = (
                f"source rewritten ({original_const} -> {rewritten_const}); "
                f"target {tgt_state_lower} matches rewritten const of "
                f"{len(set(tgt_sources))} other block(s)"
            )
        elif is_rewritten_source:
            classification = "LOCOPT_REWRITTEN_SOURCE"
            reason = (
                f"source has STATE_CONST_REWRITTEN ({original_const} -> "
                f"{rewritten_const})"
            )
        elif is_spurious:
            classification = "SPURIOUS_CONDITIONAL_ARM"
            reason = (
                f"CONDITIONAL_TRANSITION sibling of "
                f"{','.join(sorted(set(non_self_kinds)))} edge with same target"
            )
        else:
            classification = "BENIGN"
            reason = ""

        if classification != "BENIGN" and is_spurious and classification != "SPURIOUS_CONDITIONAL_ARM":
            reason = f"{reason}; also SPURIOUS_CONDITIONAL_ARM"

        diagnostics.append(
            EdgeDiagnostic(
                snapshot_id=int(snapshot_id),
                edge_id=int(edge_id),
                classification=classification,
                source_state_hex=src_state,
                target_state_hex=tgt_state,
                edge_kind=str(edge_kind),
                is_terminal_tail=int(is_terminal_tail),
                original_state_const=original_const,
                rewritten_state_const=rewritten_const,
                related_fact_ids=tuple(dict.fromkeys(related_facts)),
                reason=reason,
            )
        )

    return tuple(diagnostics)


def persist_edge_diagnostics(
    conn: sqlite3.Connection,
    diagnostics: Iterable[EdgeDiagnostic],
) -> int:
    """Persist diagnostic rows to ``state_cfg_edge_diagnostics``.

    Idempotent: existing rows for the same ``(snapshot_id, edge_id)`` are
    deleted before insertion.  Returns the number of rows inserted.
    """
    rows = [d.to_row() for d in diagnostics]
    if not rows:
        return 0
    snapshot_ids = sorted({int(r[0]) for r in rows})
    for snap_id in snapshot_ids:
        conn.execute(
            "DELETE FROM state_cfg_edge_diagnostics WHERE snapshot_id = ?",
            (snap_id,),
        )
    conn.executemany(
        """
        INSERT INTO state_cfg_edge_diagnostics
            (snapshot_id, edge_id, classification, source_state_hex,
             target_state_hex, edge_kind, is_terminal_tail,
             original_state_const, rewritten_state_const,
             related_fact_ids, reason)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """,
        rows,
    )
    conn.commit()
    return len(rows)


__all__ = [
    "EdgeDiagnostic",
    "classify_dag_edges",
    "persist_edge_diagnostics",
]
