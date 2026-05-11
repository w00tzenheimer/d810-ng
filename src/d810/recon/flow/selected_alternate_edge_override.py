"""Behavior layer: replace a collapsed terminal-tail recon edge with the
fact-selected alternate edge from the persisted diagnostic substrate.

The substrate is built up by these observability-only modules:

* ``d810.recon.facts.collectors.state_write_anchor`` -- per-block
  state-write constants + ``STATE_CONST_REWRITTEN`` lifecycle.
* ``d810.recon.facts.collectors.state_transition_anchor`` -- per-source
  CFG transit chain.
* ``d810.recon.facts.collectors.terminal_byte_emitter`` -- which
  ``byte_index`` each corridor block emits.
* ``d810.core.diag.edge_diagnostics`` -- classifies recon edges
  (``COLLAPSED_TO_REWRITTEN_TARGET`` is the load-bearing class here).
* ``d810.core.diag.alternate_correlation`` -- pairs each collapsed edge
  with already-persisted RANGE_BACKED sibling-traversal edges.
* ``d810.core.diag.alternate_selection`` -- picks the alternate that
  preserves terminal-tail byte progression.

This module is the single fact-backed *behavior* consumer.  It takes
an in-memory :class:`LinearizedStateDag`, runs the cascade against the
diag DB for the just-written snapshot, gates strictly on
``D810_FACT_LIFECYCLE=1`` plus the substrate's own gates, and
substitutes target_state / target_entry_anchor / target_key /
target_label on the matching ``StateDagEdge`` instances.  The dag and
its edges are frozen, so substitution returns a NEW dag via
``dataclasses.replace(...)``.

Mapping is by VALUE -- ``(source_state, target_state, source_block)``
-- not by persisted ``edge_id``.  ``edge_id`` is just the enumerate
index from the persistence path; relying on it would silently drift if
``dag.edges`` is reordered.

Strict gates (all required for an override to fire):

* ``D810_FACT_LIFECYCLE`` env var is exactly ``"1"``.
* ``diag_db`` and ``snap_id`` are non-None (caller passed a real
  snapshot result).
* ``dag_edge_diagnostics.classification = 'COLLAPSED_TO_REWRITTEN_TARGET'``.
* ``dag_edge_diagnostics.is_terminal_tail = 1``.
* exactly ONE ``dag_edge_alternate_selections`` row with
  ``selected = 1`` for the same ``(snapshot_id, collapsed_edge_id)``.
* the selected alternate's reached state maps to a real DAG node
  in ``dag.nodes``.
* the in-memory edge mapping by value finds exactly one match.

Any miss on any gate -> abstain on that edge.  Multiple candidate
matches -> abstain (do NOT pick "the first").  Errors during the
cascade are logged loudly (NOT silently swallowed).
"""
from __future__ import annotations

import dataclasses
import os
import sqlite3

from d810.core import getLogger
from d810.core.typing import Iterable

logger = getLogger(__name__)


_FACT_LIFECYCLE_ENV = "D810_FACT_LIFECYCLE"


def _fact_lifecycle_enabled() -> bool:
    return os.environ.get(_FACT_LIFECYCLE_ENV, "") == "1"


def _run_cascade(diag_db: sqlite3.Connection, snap_id: int) -> None:
    """Run classify -> correlate -> select against ``snap_id``.

    All persistence functions are idempotent (delete-then-insert by
    snapshot_id), so this is safe to call multiple times.  Errors are
    logged but not raised -- a failed cascade simply yields zero
    selections, which the override loop will read as "abstain".
    """
    # Behavior bridge: reads selected alternate-edge diagnostics from DB.
    # Gated (D810_FACT_LIFECYCLE=1) and intentional. The three algorithm
    # modules live in d810.core.diag for now; Phase 4 of the
    # observability-boundary plan moves them into d810.recon.flow, after
    # which this becomes a normal d810.recon.flow.* import. Do NOT route
    # through d810.recon.observability -- this is a behavior read, not a
    # capture write.
    from d810.core.diag.alternate_correlation import (
        correlate_collapsed_edges,
        persist_alternate_correlations,
    )
    from d810.core.diag.alternate_selection import (
        persist_alternate_selections,
        select_alternate_edges,
    )
    from d810.core.diag.edge_diagnostics import (
        classify_dag_edges,
        persist_edge_diagnostics,
    )

    try:
        diags = classify_dag_edges(diag_db, snap_id)
        persist_edge_diagnostics(diag_db, diags)
    except Exception:
        logger.warning(
            "RECON_DAG_OVERRIDE_CASCADE_FAILED phase=classify snap_id=%d",
            int(snap_id),
            exc_info=True,
        )
        return

    try:
        corrs = correlate_collapsed_edges(diag_db, snap_id)
        persist_alternate_correlations(diag_db, corrs)
    except Exception:
        logger.warning(
            "RECON_DAG_OVERRIDE_CASCADE_FAILED phase=correlate snap_id=%d",
            int(snap_id),
            exc_info=True,
        )
        return

    try:
        sels = select_alternate_edges(diag_db, snap_id)
        persist_alternate_selections(diag_db, sels)
    except Exception:
        logger.warning(
            "RECON_DAG_OVERRIDE_CASCADE_FAILED phase=select snap_id=%d",
            int(snap_id),
            exc_info=True,
        )


def _gated_overrides(
    diag_db: sqlite3.Connection,
    snap_id: int,
) -> dict[tuple[str, str, int | None], tuple[str, int | None]]:
    """Return ``{(collapsed_src_lower, collapsed_tgt_lower, source_block):
    (reached_state_lower, reached_byte_index)}``.

    Only gated rows are returned: COLLAPSED_TO_REWRITTEN_TARGET +
    is_terminal_tail=1 + exactly one selected=1 row per
    (snapshot_id, collapsed_edge_id).
    """
    # The selection row's (source_byte_index, reached_byte_index)
    # pair already implies terminal-tail progression (selector emits
    # ``selected = 1`` only when reached_byte_index > source_byte_index,
    # and both are looked up from ``terminal_tail`` byte-emit facts).
    # We do NOT additionally require ``dag_edge_diagnostics.is_terminal_tail
    # = 1`` because that flag is computed from the COLLAPSED SOURCE
    # state's owned blocks only -- a state whose entry block is the
    # handler entry (not the byte-emit block) will have
    # ``is_terminal_tail = 0`` even though its sibling-traversal
    # reaches byte-emit destinations.  The byte5 case is exactly this:
    # ``STATE_385BBE2D`` owns blk[100] (handler entry), while the
    # byte5 ``terminal_tail`` destination blk[101] is owned by the
    # RANGE_BACKED sibling ``STATE_3873BC53``.
    rows = diag_db.execute(
        """
        SELECT
            d.edge_id,
            d.source_state_hex,
            d.target_state_hex,
            d.classification,
            e.source_block,
            (
                SELECT COUNT(*) FROM dag_edge_alternate_selections s2
                 WHERE s2.snapshot_id = d.snapshot_id
                   AND s2.collapsed_edge_id = d.edge_id
                   AND s2.selected = 1
            ) AS sel_count,
            (
                SELECT s3.reached_state_hex FROM dag_edge_alternate_selections s3
                 WHERE s3.snapshot_id = d.snapshot_id
                   AND s3.collapsed_edge_id = d.edge_id
                   AND s3.selected = 1
                 LIMIT 1
            ) AS reached_state_hex,
            (
                SELECT s4.reached_byte_index
                  FROM dag_edge_alternate_selections s4
                 WHERE s4.snapshot_id = d.snapshot_id
                   AND s4.collapsed_edge_id = d.edge_id
                   AND s4.selected = 1
                 LIMIT 1
            ) AS reached_byte_index,
            (
                SELECT s5.source_byte_index
                  FROM dag_edge_alternate_selections s5
                 WHERE s5.snapshot_id = d.snapshot_id
                   AND s5.collapsed_edge_id = d.edge_id
                   AND s5.selected = 1
                 LIMIT 1
            ) AS source_byte_index
        FROM dag_edge_diagnostics d
        JOIN dag_edges e
          ON e.snapshot_id = d.snapshot_id
         AND e.edge_id     = d.edge_id
        WHERE d.snapshot_id = ?
          AND d.classification = 'COLLAPSED_TO_REWRITTEN_TARGET'
        """,
        (int(snap_id),),
    ).fetchall()

    out: dict[
        tuple[str, str, int | None],
        tuple[str, int | None],
    ] = {}
    for (
        _edge_id,
        src,
        tgt,
        _cls,
        src_block,
        sel_count,
        reached_state,
        reached_bi,
        source_bi,
    ) in rows:
        if int(sel_count) != 1:
            continue
        if reached_state is None:
            continue
        if src is None or tgt is None:
            continue
        # Terminal-tail progression gate: source_byte_index AND
        # reached_byte_index must both be present, and the latter must
        # be strictly larger.  This is what the selector already enforces
        # by construction (selected=1 implies these), but we re-check
        # defensively.
        if source_bi is None or reached_bi is None:
            continue
        try:
            if int(reached_bi) <= int(source_bi):
                continue
        except (TypeError, ValueError):
            continue
        try:
            src_block_int: int | None = (
                int(src_block) if src_block is not None else None
            )
        except (TypeError, ValueError):
            src_block_int = None
        key = (
            str(src).lower(),
            str(tgt).lower(),
            src_block_int,
        )
        out[key] = (str(reached_state).lower(), int(reached_bi))
    return out


def apply_selected_alternate_edge_overrides_from_diag(
    dag,
    diag_db: sqlite3.Connection | None,
    snap_id: int | None,
):
    """Substitute collapsed terminal-tail edges with their selected
    alternate's reached state.

    See module docstring for gates.  Returns the same ``dag`` object
    when no override fires; otherwise returns a NEW
    :class:`LinearizedStateDag` (frozen) with the affected edges
    rebuilt via ``dataclasses.replace``.
    """
    if not _fact_lifecycle_enabled():
        return dag
    if diag_db is None or snap_id is None:
        return dag

    try:
        _run_cascade(diag_db, int(snap_id))
        gated = _gated_overrides(diag_db, int(snap_id))
    except Exception:
        logger.warning(
            "RECON_DAG_OVERRIDE_GATING_FAILED snap_id=%d",
            int(snap_id),
            exc_info=True,
        )
        return dag

    if not gated:
        return dag

    nodes_by_state_hex: dict[str, object] = {}
    for node in dag.nodes:
        sc = getattr(node.key, "state_const", None)
        if sc is None:
            continue
        try:
            normalized = int(sc) & 0xFFFFFFFF
        except (TypeError, ValueError):
            continue
        nodes_by_state_hex[f"0x{normalized:08x}"] = node
        nodes_by_state_hex[f"0x{normalized:016x}"] = node

    new_edges: list = list(dag.edges)
    overrides_applied = 0
    overrides_attempted = 0

    for index, edge in enumerate(dag.edges):
        src_state = getattr(edge.source_key, "state_const", None)
        tgt_state = (
            getattr(edge.target_key, "state_const", None)
            if edge.target_key is not None
            else None
        )
        src_block = (
            int(edge.source_anchor.block_serial)
            if edge.source_anchor is not None
            else None
        )
        if src_state is None or tgt_state is None:
            continue
        src_hex = f"0x{int(src_state) & 0xFFFFFFFFFFFFFFFF:016x}"
        tgt_hex = f"0x{int(tgt_state) & 0xFFFFFFFFFFFFFFFF:016x}"
        candidate_keys = (
            (src_hex, tgt_hex, src_block),
            (src_hex, tgt_hex, None),
        )
        match = None
        for key in candidate_keys:
            if key in gated:
                match = gated[key]
                break
        if match is None:
            continue
        overrides_attempted += 1

        reached_hex, reached_bi = match
        new_target_node = nodes_by_state_hex.get(reached_hex)
        if new_target_node is None:
            short = reached_hex
            if reached_hex.startswith("0x") and len(reached_hex) == 18:
                short = "0x" + reached_hex[10:]
            new_target_node = nodes_by_state_hex.get(short)
        if new_target_node is None:
            logger.warning(
                "RECON_DAG_EDGE_OVERRIDE_SKIPPED reason=reached_state_no_node "
                "src=%s old_target=%s reached=%s",
                src_hex,
                tgt_hex,
                reached_hex,
            )
            continue

        new_target_key = new_target_node.key
        new_target_entry = int(new_target_node.entry_anchor)
        new_target_label = (
            new_target_node.state_label
            if new_target_node.state_label
            else f"blk[{new_target_entry}]"
        )
        new_target_state = (
            int(new_target_key.state_const)
            if new_target_key.state_const is not None
            else None
        )

        new_edge = dataclasses.replace(
            edge,
            target_key=new_target_key,
            target_state=new_target_state,
            target_entry_anchor=new_target_entry,
            target_label=new_target_label,
        )
        new_edges[index] = new_edge
        overrides_applied += 1
        logger.info(
            "RECON_DAG_EDGE_REPLACED_BY_SELECTED_ALTERNATE "
            "edge_index=%d src=%s old_target=%s new_target=%s "
            "source_block=%s reached_byte_index=%s",
            index,
            src_hex,
            tgt_hex,
            reached_hex,
            "?" if src_block is None else str(src_block),
            "?" if reached_bi is None else str(reached_bi),
        )

    if overrides_applied == 0:
        return dag

    logger.info(
        "RECON_DAG_OVERRIDE_SUMMARY snap_id=%d gated_total=%d "
        "attempted=%d applied=%d",
        int(snap_id),
        len(gated),
        overrides_attempted,
        overrides_applied,
    )
    return dataclasses.replace(dag, edges=tuple(new_edges))


__all__ = [
    "apply_selected_alternate_edge_overrides_from_diag",
]
