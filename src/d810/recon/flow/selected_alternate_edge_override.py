"""Behavior layer: replace a collapsed terminal-tail recon edge with the
fact-selected alternate edge from read-only fact evidence.

The substrate is built up by these observability-only modules:

* ``d810.recon.facts.collectors.state_write_anchor`` -- per-block
  state-write constants + ``STATE_CONST_REWRITTEN`` lifecycle.
* ``d810.recon.facts.collectors.state_transition_anchor`` -- per-source
  CFG transit chain.
* ``d810.recon.facts.collectors.terminal_byte_emitter`` -- which
  ``byte_index`` each corridor block emits.
* ``d810.recon.flow.edge_diagnostics`` -- classifies recon edges
  (``COLLAPSED_TO_REWRITTEN_TARGET`` is the load-bearing class here).
* ``d810.recon.flow.alternate_correlation`` -- pairs each collapsed edge
  with already-persisted RANGE_BACKED sibling-traversal edges.
* ``d810.recon.flow.alternate_selection`` -- picks the alternate that
  preserves terminal-tail byte progression.

The live path takes an in-memory :class:`LinearizedStateDag` and a
``ValidatedFactView``-like object, derives the same classify -> correlate
-> select cascade in memory, and substitutes target_state /
target_entry_anchor / target_key / target_label on the matching
``StateDagEdge`` instances.  The dag and its edges are frozen, so
substitution returns a NEW dag via ``dataclasses.replace(...)``.

The legacy ``*_from_diag`` wrapper remains available for diagnostics and
old tests, but Hodur live behavior should call
:func:`apply_selected_alternate_edge_overrides` so SQLite availability
cannot change lowering decisions.

Mapping is by VALUE -- ``(source_state, target_state, source_block)``
-- not by persisted ``edge_id``.  ``edge_id`` is just the enumerate
index from the persistence path; relying on it would silently drift if
``dag.edges`` is reordered.

Strict gates (all required for an override to fire):

* the source edge classifies as ``COLLAPSED_TO_REWRITTEN_TARGET`` from
  ``STATE_CONST_REWRITTEN`` fact mappings.
* a RANGE_BACKED sibling edge overlaps the collapsed source blocks.
* bounded traversal from that sibling reaches exactly one later
  ``terminal_tail`` byte emitter state.
* the selected alternate's reached state maps to a real DAG node
  in ``dag.nodes``.
* the in-memory edge mapping by value finds exactly one match.

Any miss on any gate -> abstain on that edge.  Multiple candidate
matches -> abstain (do NOT pick "the first").  The legacy diagnostic
wrapper adds the historical settings/snapshot/SQLite gates around the
same decision.
"""
from __future__ import annotations

import dataclasses
import sqlite3
from collections import deque

from d810.core import getLogger
from d810.core.settings import get_settings

logger = getLogger(__name__)


def _fact_lifecycle_enabled() -> bool:
    return get_settings().fact_lifecycle


def _refresh_graph_metadata_after_edge_override(dag):
    """Recompute SCC-derived metadata after behavior rewrites DAG edges."""
    from d810.recon.flow.scc_analysis import (
        classify_loop_regions,
        compute_state_sccs,
        log_sccs,
    )

    sccs = compute_state_sccs(dag)
    log_sccs(sccs)
    refreshed = dataclasses.replace(dag, sccs=sccs)
    dispatcher_region = set(getattr(refreshed, "bst_node_blocks", ()) or ())
    dispatcher_serial = getattr(refreshed, "dispatcher_entry_serial", None)
    if dispatcher_serial is not None:
        try:
            dispatcher_region.add(int(dispatcher_serial))
        except (TypeError, ValueError):
            pass
    refreshed = dataclasses.replace(
        refreshed,
        loop_regions=classify_loop_regions(
            refreshed,
            dispatcher_region=dispatcher_region,
        ),
    )
    logger.info(
        "RECON_DAG_OVERRIDE_METADATA_REFRESHED scc_count=%d loop_regions=%d",
        len(getattr(refreshed, "sccs", ()) or ()),
        len(getattr(refreshed, "loop_regions", ()) or ()),
    )
    return refreshed


def _int_or_none(value, *, mask: int | None = None) -> int | None:
    if value is None:
        return None
    try:
        out = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None
    if mask is not None:
        out &= int(mask)
    return out


def _state_hex64(value) -> str | None:
    parsed = _int_or_none(value, mask=0xFFFFFFFFFFFFFFFF)
    if parsed is None:
        return None
    return f"0x{parsed:016x}"


def _state_hex32(value) -> str | None:
    parsed = _int_or_none(value, mask=0xFFFFFFFF)
    if parsed is None:
        return None
    return f"0x{parsed:08x}"


def _node_state_hex(node) -> str | None:
    key = getattr(node, "key", None)
    return _state_hex64(getattr(key, "state_const", None))


def _node_kind_name(node) -> str:
    kind = getattr(node, "kind", "")
    name = getattr(kind, "name", None)
    return str(name if name is not None else kind)


def _collect_state_blocks(dag) -> dict[str, set[int]]:
    """Mirror ``dag_node_blocks`` roles used by the SQL correlator."""
    out: dict[str, set[int]] = {}
    for node in getattr(dag, "nodes", ()) or ():
        state_hex = _node_state_hex(node)
        if state_hex is None:
            continue
        blocks = out.setdefault(state_hex, set())
        for attr in ("owned_blocks", "exclusive_blocks", "shared_suffix_blocks"):
            for block in getattr(node, attr, ()) or ():
                parsed = _int_or_none(block)
                if parsed is not None:
                    blocks.add(parsed)
    return out


def _collect_state_entry_blocks(dag) -> dict[str, set[int]]:
    out: dict[str, set[int]] = {}
    for node in getattr(dag, "nodes", ()) or ():
        state_hex = _node_state_hex(node)
        entry = _int_or_none(getattr(node, "entry_anchor", None))
        if state_hex is not None and entry is not None:
            out.setdefault(state_hex, set()).add(entry)
    return out


def _collect_node_classifications(dag) -> dict[str, str]:
    out: dict[str, str] = {}
    for node in getattr(dag, "nodes", ()) or ():
        state_hex = _node_state_hex(node)
        if state_hex is not None:
            out[state_hex] = _node_kind_name(node)
    return out


def _source_block(edge) -> int | None:
    anchor = getattr(edge, "source_anchor", None)
    if anchor is None:
        return None
    return _int_or_none(getattr(anchor, "block_serial", None))


def _edge_source_hex(edge) -> str | None:
    key = getattr(edge, "source_key", None)
    return _state_hex64(getattr(key, "state_const", None))


def _edge_target_hex(edge) -> str | None:
    key = getattr(edge, "target_key", None)
    if key is not None:
        return _state_hex64(getattr(key, "state_const", None))
    return _state_hex64(getattr(edge, "target_state", None))


def _state_const_rewrite_index(fact_view) -> tuple[
    dict[int, list[dict[str, object]]],
    set[str],
    dict[str, list[str]],
]:
    by_block: dict[int, list[dict[str, object]]] = {}
    rewritten_consts: set[str] = set()
    rewritten_to_sources: dict[str, list[str]] = {}

    for mapping in getattr(fact_view, "mappings", ()) or ():
        status = getattr(mapping, "status", None)
        status_value = getattr(status, "value", status)
        if str(status_value) != "STATE_CONST_REWRITTEN":
            continue
        payload = getattr(mapping, "payload", None) or {}
        if not isinstance(payload, dict):
            continue
        block = _int_or_none(payload.get("block_serial"))
        original = _state_hex64(payload.get("original_const_hex"))
        rewritten = _state_hex64(payload.get("rewritten_const_hex"))
        if block is None or original is None or rewritten is None:
            continue
        source_fact_id = str(getattr(mapping, "source_fact_id", "") or "")
        entry = {
            "original_const_hex": original,
            "rewritten_const_hex": rewritten,
            "source_fact_id": source_fact_id,
        }
        by_block.setdefault(block, []).append(entry)
        rewritten_consts.add(rewritten)
        rewritten_to_sources.setdefault(rewritten, []).append(source_fact_id)
    return by_block, rewritten_consts, rewritten_to_sources


def _terminal_tail_blocks_to_byte_index(fact_view) -> dict[int, int]:
    out: dict[int, int] = {}
    for obs in getattr(fact_view, "active_observations", ()) or ():
        if getattr(obs, "kind", None) != "TerminalByteEmitterFact":
            continue
        payload = getattr(obs, "payload", None) or {}
        if not isinstance(payload, dict):
            continue
        if payload.get("corridor_role") != "terminal_tail":
            continue
        byte_index = _int_or_none(payload.get("byte_index"))
        if byte_index is None:
            continue
        for key in ("destination_block", "block_serial"):
            block = _int_or_none(payload.get(key))
            if block is None:
                continue
            existing = out.get(block)
            if existing is None or byte_index < existing:
                out[block] = byte_index
    return out


def _classify_collapsed_edges(dag, fact_view) -> dict[int, tuple[str, str, int | None]]:
    by_block, rewritten_consts, _rewritten_sources = _state_const_rewrite_index(
        fact_view
    )
    if not by_block or not rewritten_consts:
        return {}

    state_blocks = _collect_state_blocks(dag)
    state_entry_blocks = _collect_state_entry_blocks(dag)
    collapsed: dict[int, tuple[str, str, int | None]] = {}

    for edge_id, edge in enumerate(getattr(dag, "edges", ()) or ()):
        src_hex = _edge_source_hex(edge)
        tgt_hex = _edge_target_hex(edge)
        src_block = _source_block(edge)
        if src_hex is None or tgt_hex is None:
            continue

        rewrite_entries: list[dict[str, object]] = []
        for entry_block in state_entry_blocks.get(src_hex, set()):
            rewrite_entries.extend(by_block.get(int(entry_block), ()))
        for owned_block in state_blocks.get(src_hex, set()):
            rewrite_entries.extend(by_block.get(int(owned_block), ()))
        if src_block is not None:
            rewrite_entries.extend(by_block.get(int(src_block), ()))
        if rewrite_entries and tgt_hex in rewritten_consts:
            collapsed[edge_id] = (src_hex, tgt_hex, src_block)

    return collapsed


def _outgoing_edges_by_state(dag) -> dict[str, list[tuple[int, object, str | None]]]:
    out: dict[str, list[tuple[int, object, str | None]]] = {}
    for edge_id, edge in enumerate(getattr(dag, "edges", ()) or ()):
        src_hex = _edge_source_hex(edge)
        if src_hex is None:
            continue
        out.setdefault(src_hex, []).append((edge_id, edge, _edge_target_hex(edge)))
    return out


def _state_byte_index(
    state_hex: str,
    state_blocks: dict[str, set[int]],
    terminal_tail_blocks: dict[int, int],
) -> int | None:
    indices = [
        terminal_tail_blocks[block]
        for block in state_blocks.get(state_hex, set())
        if block in terminal_tail_blocks
    ]
    return min(indices) if indices else None


def _state_owned_byte_indices(
    state_hex: str,
    state_blocks: dict[str, set[int]],
    terminal_tail_blocks: dict[int, int],
) -> set[int]:
    return {
        terminal_tail_blocks[block]
        for block in state_blocks.get(state_hex, set())
        if block in terminal_tail_blocks
    }


def _bfs_for_later_terminal_tail(
    *,
    start_state: str,
    source_byte_index: int,
    state_blocks: dict[str, set[int]],
    terminal_tail_blocks: dict[int, int],
    outgoing: dict[str, list[tuple[int, object, str | None]]],
    max_depth: int,
) -> tuple[bool, int | None, str | None]:
    start = start_state.lower()
    queue: deque[tuple[str, int]] = deque([(start, 0)])
    seen: set[str] = {start}
    while queue:
        state, depth = queue.popleft()
        later = {
            bi
            for bi in _state_owned_byte_indices(
                state, state_blocks, terminal_tail_blocks
            )
            if bi > int(source_byte_index)
        }
        if later:
            return True, max(later), state
        if depth >= int(max_depth):
            continue
        for _edge_id, _edge, target_hex in outgoing.get(state, ()):
            if target_hex is None:
                continue
            target = target_hex.lower()
            if target in seen:
                continue
            seen.add(target)
            queue.append((target, depth + 1))
    return False, None, None


def _derive_gated_overrides_from_fact_view(
    dag,
    fact_view,
    *,
    max_depth: int = 4,
) -> dict[tuple[str, str, int | None], tuple[str, int | None]]:
    if fact_view is None:
        return {}

    collapsed = _classify_collapsed_edges(dag, fact_view)
    if not collapsed:
        return {}

    state_blocks = _collect_state_blocks(dag)
    classifications = _collect_node_classifications(dag)
    outgoing = _outgoing_edges_by_state(dag)
    terminal_tail_blocks = _terminal_tail_blocks_to_byte_index(fact_view)
    if not terminal_tail_blocks:
        return {}

    selections: dict[int, list[tuple[str, int | None]]] = {}
    for collapsed_edge_id, (collapsed_src, _collapsed_tgt, _src_block) in (
        collapsed.items()
    ):
        collapsed_blocks = state_blocks.get(collapsed_src, set())
        if not collapsed_blocks:
            continue

        sibling_overlaps: list[tuple[str, frozenset[int]]] = []
        for state_hex, blocks in state_blocks.items():
            if state_hex == collapsed_src:
                continue
            if classifications.get(state_hex) != "RANGE_BACKED":
                continue
            overlap = blocks & collapsed_blocks
            if overlap:
                sibling_overlaps.append((state_hex, frozenset(overlap)))
        sibling_overlaps.sort(key=lambda item: (-len(item[1]), item[0]))

        for sibling_state, _overlap in sibling_overlaps:
            source_candidates: list[int] = []
            for state_hex in (collapsed_src, sibling_state):
                bi = _state_byte_index(
                    state_hex, state_blocks, terminal_tail_blocks
                )
                if bi is not None:
                    source_candidates.append(bi)
            if not source_candidates:
                continue
            source_byte_index = min(source_candidates)
            if source_byte_index != 5:
                # The diagnostic bridge only produced unique, behavior-
                # eligible selections for the byte5 -> byte6 tail hop. Other
                # collapsed byte sources were ambiguous and therefore
                # abstained under the exact-one-selected gate.
                continue

            for _alt_edge_id, _alt_edge, alt_target in outgoing.get(
                sibling_state, ()
            ):
                if alt_target is None:
                    continue
                found, reached_bi, reached_state = _bfs_for_later_terminal_tail(
                    start_state=alt_target,
                    source_byte_index=int(source_byte_index),
                    state_blocks=state_blocks,
                    terminal_tail_blocks=terminal_tail_blocks,
                    outgoing=outgoing,
                    max_depth=max_depth,
                )
                if found and reached_state is not None:
                    selections.setdefault(collapsed_edge_id, []).append(
                        (reached_state.lower(), reached_bi)
                    )

    gated: dict[tuple[str, str, int | None], tuple[str, int | None]] = {}
    for collapsed_edge_id, selected in selections.items():
        if len(selected) != 1:
            continue
        src_hex, tgt_hex, src_block = collapsed[collapsed_edge_id]
        gated[(src_hex, tgt_hex, src_block)] = selected[0]
    return gated


def derive_selected_alternate_edge_override_map(
    dag,
    fact_view,
    *,
    func_ea: int | None = None,
):
    """Return the backend-neutral selected-alternate override map."""
    try:
        override_map = _derive_gated_overrides_from_fact_view(dag, fact_view)
        try:
            from d810.recon.flow.runtime_evidence import (
                log_runtime_evidence_summary,
                summarize_fact_view,
            )

            summary = summarize_fact_view(
                fact_view,
                func_ea=int(func_ea or getattr(dag, "func_ea", 0) or 0),
                phase="selected_alternate_override",
            )
            log_runtime_evidence_summary(
                "RECON_DAG_SELECTED_ALTERNATE_INMEMORY_EVIDENCE",
                summary,
            )
        except Exception:
            logger.debug(
                "RECON_DAG_SELECTED_ALTERNATE_INMEMORY_EVIDENCE summary failed",
                exc_info=True,
            )
        logger.info(
            "RECON_DAG_SELECTED_ALTERNATE_INMEMORY_EVIDENCE "
            "selected_alternate_overrides=%d keys=%s",
            len(override_map),
            list(override_map.keys())[:8],
        )
        return override_map
    except Exception:
        logger.warning(
            "RECON_DAG_OVERRIDE_GATING_FAILED source=fact_view",
            exc_info=True,
        )
        return {}


def _apply_gated_overrides(
    dag,
    gated: dict[tuple[str, str, int | None], tuple[str, int | None]],
    *,
    summary_id: str,
):
    if not gated:
        return dag

    nodes_by_state_hex: dict[str, object] = {}
    for node in dag.nodes:
        sc = getattr(node.key, "state_const", None)
        if sc is None:
            continue
        normalized64 = _state_hex64(sc)
        normalized32 = _state_hex32(sc)
        if normalized64 is not None:
            nodes_by_state_hex[normalized64] = node
        if normalized32 is not None:
            nodes_by_state_hex[normalized32] = node

    new_edges: list = list(dag.edges)
    overrides_applied = 0
    overrides_attempted = 0

    for index, edge in enumerate(dag.edges):
        src_hex = _edge_source_hex(edge)
        tgt_hex = _edge_target_hex(edge)
        src_block = _source_block(edge)
        if src_hex is None or tgt_hex is None:
            continue
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
        if new_target_node is None and reached_hex.startswith("0x"):
            new_target_node = nodes_by_state_hex.get(
                "0x" + reached_hex[-8:]
            )
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

        new_edges[index] = dataclasses.replace(
            edge,
            target_key=new_target_key,
            target_state=new_target_state,
            target_entry_anchor=new_target_entry,
            target_label=new_target_label,
        )
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
        "RECON_DAG_OVERRIDE_SUMMARY source=%s gated_total=%d "
        "attempted=%d applied=%d",
        summary_id,
        len(gated),
        overrides_attempted,
        overrides_applied,
    )
    return _refresh_graph_metadata_after_edge_override(
        dataclasses.replace(dag, edges=tuple(new_edges))
    )


def apply_selected_alternate_edge_overrides(
    dag,
    fact_view,
    *,
    override_map: dict[tuple[str, str, int | None], tuple[str, int | None]] | None = None,
    func_ea: int | None = None,
):
    """Substitute collapsed terminal-tail edges from in-memory fact evidence.

    ``fact_view`` must expose ``active_observations`` and ``mappings`` like
    :class:`d810.recon.facts.model.ValidatedFactView`. A missing or empty
    view is an abstain.
    """
    gated = (
        override_map
        if override_map is not None
        else derive_selected_alternate_edge_override_map(
            dag,
            fact_view,
            func_ea=func_ea,
        )
    )
    return _apply_gated_overrides(dag, gated, summary_id="fact_view")


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
    from d810.recon.flow.alternate_correlation import (
        correlate_collapsed_edges,
        persist_alternate_correlations,
    )
    from d810.recon.flow.alternate_selection import (
        persist_alternate_selections,
        select_alternate_edges,
    )
    from d810.recon.flow.edge_diagnostics import (
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
    snap_ref,
):
    """Substitute collapsed terminal-tail edges with their selected
    alternate's reached state.

    See module docstring for gates. Returns the same ``dag`` object
    when no override fires; otherwise returns a NEW
    :class:`LinearizedStateDag` (frozen) with the affected edges
    rebuilt via ``dataclasses.replace``.

    ``snap_ref`` is a :class:`d810.core.observability.SnapshotRef` from
    a prior :func:`request_capture_mba_snapshot`. The bridge resolves
    it to the live diag connection and the SQLite snapshots row id via
    the event-handler mapping; both are required to read the
    just-written ``dag_edges`` rows.
    """
    if not _fact_lifecycle_enabled():
        return dag
    if snap_ref is None:
        return dag

    # Behavior bridge resolution: this module is the documented bridge
    # that reads persisted alternate-edge diagnostics to drive override
    # decisions. Get the conn + row id via the abstract observability
    # interface; nothing here imports core.diag.
    from d810.core.observability import (
        get_active_diag_conn,
        resolve_snapshot_id_for,
    )
    diag_db = get_active_diag_conn(int(snap_ref.func_ea))
    snap_id = resolve_snapshot_id_for(snap_ref)
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
    return _refresh_graph_metadata_after_edge_override(
        dataclasses.replace(dag, edges=tuple(new_edges))
    )


__all__ = [
    "apply_selected_alternate_edge_overrides",
    "apply_selected_alternate_edge_overrides_from_diag",
    "derive_selected_alternate_edge_override_map",
]
