"""Selector for ``dag_edge_alternate_correlations`` rows.

Resolves the ambiguity that the correlation substrate exposes when
multiple alternate edges overlap a collapsed source.  The selector is
**observability-only**: it produces a ``selected``/``rejected``
decision per (collapsed_edge, alternate_edge) pair with a fact-backed
reason; no recon edge target selection or HCC behavior depends on the
output.

Selection rule
--------------

For a collapsed edge whose ``source_byte_index = N`` (cross-linked
from ``TerminalByteEmitterFact.destination_block`` against the
collapsed source's owned blocks):

* Bounded BFS from the alternate's ``target_state`` through
  ``dag_edges``, depth ``<= 2``.
* If any reachable state's owned blocks contain a
  ``corridor_role = terminal_tail``
  ``TerminalByteEmitterFact`` destination with ``byte_index > N``,
  mark **selected** and record the reached byte_index + state.
* Otherwise:
  - if all reachable states from the alternate have only
    ``CONDITIONAL_RETURN`` outgoing edges, mark **rejected** with
    reason ``early_return_arm_no_later_terminal_tail``.
  - otherwise mark **rejected** with reason ``no_later_terminal_tail_within_depth``.

When the source has no derivable byte_index (no terminal_tail emit
fact for the source's blocks), no selection is recorded -- the
correlation row is preserved but no decision is made.

Bounded BFS
-----------

Depth <= 2 means: the alternate's direct target state, then its
direct successors.  Two hops is sufficient for the byte5 -> byte6
case (target ``STATE_10743C4C`` -> ``STATE_6107F8EC`` is one hop).
Recursive walking is explicitly out of scope.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from d810.core.typing import Iterable


_DEFAULT_BFS_DEPTH = 4


@dataclass(frozen=True)
class AlternateSelection:
    """One selection decision for a (collapsed, alternate) pair."""

    snapshot_id: int
    collapsed_edge_id: int
    alternate_edge_id: int
    selected: bool
    source_byte_index: int | None
    reached_byte_index: int | None
    reached_state_hex: str | None
    reason: str
    evidence: dict

    def to_row(self) -> tuple:
        return (
            int(self.snapshot_id),
            int(self.collapsed_edge_id),
            int(self.alternate_edge_id),
            int(bool(self.selected)),
            self.source_byte_index,
            self.reached_byte_index,
            self.reached_state_hex,
            self.reason,
            json.dumps(self.evidence, sort_keys=True),
        )


def _terminal_tail_blocks_to_byte_index(
    conn: sqlite3.Connection,
) -> dict[int, int]:
    """``{block_serial: byte_index}`` for every ``terminal_tail`` byte-emit
    destination, function-wide.

    When multiple facts target the same block with different byte_index
    values, the smaller byte_index wins (defensive; in practice each
    terminal_tail block carries one byte_index)."""
    out: dict[int, int] = {}
    rows = conn.execute(
        """
        SELECT payload FROM fact_observations
        WHERE kind='TerminalByteEmitterFact'
        """,
    ).fetchall()
    for (payload_json,) in rows:
        try:
            payload = json.loads(payload_json) if payload_json else {}
        except (TypeError, ValueError):
            continue
        if payload.get("corridor_role") != "terminal_tail":
            continue
        block = payload.get("destination_block")
        bi = payload.get("byte_index")
        if block is None or bi is None:
            continue
        try:
            block_int = int(block)
            bi_int = int(bi)
        except (TypeError, ValueError):
            continue
        existing = out.get(block_int)
        if existing is None or bi_int < existing:
            out[block_int] = bi_int
    return out


def _state_owned_blocks(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> dict[str, set[int]]:
    out: dict[str, set[int]] = {}
    rows = conn.execute(
        """
        SELECT state_hex, block_serial FROM dag_node_blocks
        WHERE snapshot_id = ?
          AND role IN ('owned', 'exclusive', 'shared_suffix')
        """,
        (int(snapshot_id),),
    ).fetchall()
    for state_hex, block_serial in rows:
        if state_hex is None:
            continue
        out.setdefault(str(state_hex).lower(), set()).add(int(block_serial))
    return out


def _state_byte_index(
    state_hex: str,
    state_owned: dict[str, set[int]],
    terminal_tail_blocks: dict[int, int],
) -> int | None:
    """Return the smallest ``byte_index`` reachable through the state's
    owned blocks, or ``None`` if the state owns no terminal_tail block.

    Used for source-state byte_index lookup -- we use the smallest
    because the source's byte_index is the SOURCE byte (we want to find
    later bytes in the BFS).
    """
    blocks = state_owned.get(state_hex.lower(), set())
    indices = [
        terminal_tail_blocks[blk]
        for blk in blocks
        if blk in terminal_tail_blocks
    ]
    if not indices:
        return None
    return min(indices)


def _state_owned_byte_indices(
    state_hex: str,
    state_owned: dict[str, set[int]],
    terminal_tail_blocks: dict[int, int],
) -> set[int]:
    """Return ALL byte indices for terminal_tail blocks owned by the state.

    Used for reached-state lookup in the BFS: we want to know whether
    the state owns ANY block whose byte_index is later than the source,
    not just the smallest one (a state can own multiple byte_index
    blocks, e.g., STATE_2315233B owns both byte1's blk[211] and byte6's
    blk[217] in sub_7FFD3338C040).
    """
    blocks = state_owned.get(state_hex.lower(), set())
    return {
        terminal_tail_blocks[blk]
        for blk in blocks
        if blk in terminal_tail_blocks
    }


def _outgoing_by_state(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> dict[str, list[tuple[str | None, str]]]:
    """``{source_state_hex: [(target_state_hex, edge_kind), ...]}``."""
    out: dict[str, list[tuple[str | None, str]]] = {}
    rows = conn.execute(
        """
        SELECT source_state_hex, target_state_hex, edge_kind
        FROM dag_edges
        WHERE snapshot_id = ?
        """,
        (int(snapshot_id),),
    ).fetchall()
    for src, tgt, kind in rows:
        if src is None:
            continue
        out.setdefault(str(src).lower(), []).append(
            (str(tgt).lower() if tgt is not None else None, str(kind))
        )
    return out


def _bfs_for_terminal_tail(
    *,
    start_state: str,
    state_owned: dict[str, set[int]],
    terminal_tail_blocks: dict[int, int],
    outgoing: dict[str, list[tuple[str | None, str]]],
    source_byte_index: int,
    max_depth: int,
) -> tuple[
    bool,                     # found later-byte
    int | None,               # reached byte_index
    str | None,               # reached state hex
    bool,                     # all-conditional-return-only flag
    list[str],                # visited state list (for evidence)
]:
    """Bounded BFS through ``outgoing`` from ``start_state``.

    Returns ``(found, reached_bi, reached_state, only_cond_return, visited)``.
    ``only_cond_return`` is True when every outgoing edge from every
    reachable state is ``CONDITIONAL_RETURN`` (no ``TRANSITION`` or
    ``CONDITIONAL_TRANSITION`` arms).
    """
    start = start_state.lower()
    visited: set[str] = {start}
    visited_order: list[str] = [start]
    frontier: list[tuple[str, int]] = [(start, 0)]

    only_cond_return = True
    while frontier:
        state, depth = frontier.pop(0)
        # Check whether THIS state has the property we want: ANY
        # owned terminal_tail byte_index strictly greater than the
        # source.  Use the *largest* matching index for the
        # ``reached_byte_index`` annotation (most informative), but
        # any match is sufficient for selection.
        bi_set = _state_owned_byte_indices(
            state, state_owned, terminal_tail_blocks
        )
        later = {bi for bi in bi_set if bi > source_byte_index}
        if later:
            return True, max(later), state, False, visited_order

        if depth >= max_depth:
            continue

        edges = outgoing.get(state, [])
        for target, kind in edges:
            if kind not in {"CONDITIONAL_RETURN", "EXIT_ROUTINE"}:
                only_cond_return = False
            if target is None:
                continue
            if target in visited:
                continue
            visited.add(target)
            visited_order.append(target)
            frontier.append((target, depth + 1))

    # No later-byte found within depth.
    return False, None, None, only_cond_return, visited_order


def select_alternate_edges(
    conn: sqlite3.Connection,
    snapshot_id: int,
    *,
    max_depth: int = _DEFAULT_BFS_DEPTH,
) -> tuple[AlternateSelection, ...]:
    """Compute selection decisions for every correlation at ``snapshot_id``.

    Pure read; caller persists with :func:`persist_alternate_selections`.
    """
    correlation_rows = conn.execute(
        """
        SELECT collapsed_edge_id, alternate_edge_id,
               collapsed_source_state, alternate_source_state,
               alternate_target_state
        FROM dag_edge_alternate_correlations
        WHERE snapshot_id = ?
        """,
        (int(snapshot_id),),
    ).fetchall()
    if not correlation_rows:
        return ()

    state_owned = _state_owned_blocks(conn, snapshot_id)
    terminal_tail_blocks = _terminal_tail_blocks_to_byte_index(conn)
    outgoing = _outgoing_by_state(conn, snapshot_id)

    selections: list[AlternateSelection] = []
    for (
        collapsed_edge_id,
        alt_edge_id,
        collapsed_source_state,
        alt_source_state,
        alt_target_state,
    ) in correlation_rows:
        if collapsed_source_state is None:
            continue

        # Source byte_index: the collapsed source's own owned blocks
        # may not include a terminal_tail destination directly (the
        # source state's entry block is the handler entry, not the
        # byte-emit block).  Widen the lookup to include the
        # RANGE_BACKED sibling's owned blocks -- by construction, the
        # correlation row exists because that sibling's blocks
        # overlap the source's, and the sibling typically owns the
        # adjacent byte-emit block.  Use the SMALLEST byte_index
        # found across both states (covers byteN whose source state
        # is the handler entry whose CFG successor emits byteN).
        candidates: list[int] = []
        for state_hex in (collapsed_source_state, alt_source_state):
            if state_hex is None:
                continue
            bi = _state_byte_index(
                str(state_hex), state_owned, terminal_tail_blocks
            )
            if bi is not None:
                candidates.append(bi)
        source_byte_index = min(candidates) if candidates else None

        if source_byte_index is None:
            # No byte_index for the collapsed source -> no decision.
            selections.append(
                AlternateSelection(
                    snapshot_id=int(snapshot_id),
                    collapsed_edge_id=int(collapsed_edge_id),
                    alternate_edge_id=int(alt_edge_id),
                    selected=False,
                    source_byte_index=None,
                    reached_byte_index=None,
                    reached_state_hex=None,
                    reason="no_source_byte_index",
                    evidence={},
                )
            )
            continue

        if alt_target_state is None or int(alt_edge_id) < 0:
            # RANGE_BACKED sibling without an outgoing edge.
            selections.append(
                AlternateSelection(
                    snapshot_id=int(snapshot_id),
                    collapsed_edge_id=int(collapsed_edge_id),
                    alternate_edge_id=int(alt_edge_id),
                    selected=False,
                    source_byte_index=source_byte_index,
                    reached_byte_index=None,
                    reached_state_hex=None,
                    reason="alternate_has_no_target_state",
                    evidence={},
                )
            )
            continue

        found, reached_bi, reached_state, only_cond, visited = (
            _bfs_for_terminal_tail(
                start_state=str(alt_target_state),
                state_owned=state_owned,
                terminal_tail_blocks=terminal_tail_blocks,
                outgoing=outgoing,
                source_byte_index=int(source_byte_index),
                max_depth=int(max_depth),
            )
        )

        if found:
            reason = "later_terminal_tail_reached"
        elif only_cond:
            reason = "early_return_arm_no_later_terminal_tail"
        else:
            reason = "no_later_terminal_tail_within_depth"

        selections.append(
            AlternateSelection(
                snapshot_id=int(snapshot_id),
                collapsed_edge_id=int(collapsed_edge_id),
                alternate_edge_id=int(alt_edge_id),
                selected=found,
                source_byte_index=int(source_byte_index),
                reached_byte_index=reached_bi,
                reached_state_hex=reached_state,
                reason=reason,
                evidence={
                    "max_depth": int(max_depth),
                    "visited_states": visited[:16],  # cap for storage
                },
            )
        )

    return tuple(selections)


def persist_alternate_selections(
    conn: sqlite3.Connection,
    selections: Iterable[AlternateSelection],
) -> int:
    """Persist selection rows.  Idempotent: existing rows for the same
    ``(snapshot_id, collapsed_edge_id, alternate_edge_id)`` triple are
    replaced.  Returns the number of rows inserted.
    """
    rows = [s.to_row() for s in selections]
    if not rows:
        return 0
    snapshot_ids = sorted({int(r[0]) for r in rows})
    for snap_id in snapshot_ids:
        conn.execute(
            "DELETE FROM dag_edge_alternate_selections "
            "WHERE snapshot_id = ?",
            (snap_id,),
        )
    conn.executemany(
        """
        INSERT INTO dag_edge_alternate_selections
            (snapshot_id, collapsed_edge_id, alternate_edge_id,
             selected, source_byte_index, reached_byte_index,
             reached_state_hex, reason, evidence_json)
        VALUES (?,?,?,?,?,?,?,?,?)
        """,
        rows,
    )
    conn.commit()
    return len(rows)


__all__ = [
    "AlternateSelection",
    "select_alternate_edges",
    "persist_alternate_selections",
]
