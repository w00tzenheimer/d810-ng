"""Reconcile resolver predictions against live dispatcher_trampoline_skip emissions.

Reads a diag DB + d810.log and produces the bucket breakdown described in
Piece 5.5 of ticket uee-32r3. Buckets surfaced (preserved from the legacy
script):

* ``AGREE_FULL``
* ``HCC_DUP``
* ``HCC_REGION_HANDLER`` / ``HCC_REGION_PRED`` / ``HCC_REGION_TARGET``
* ``AGREE_INTENT_DROPPED_OTHER``
* ``RESOLVER_OK_STRATEGY_USE_DEF_VETO``
* ``DISAGREE_TARGET``
* ``STRATEGY_ONLY_STATE_NOT_IN_BST``
* ``BOTH_NONE``

The actual classification logic lives in :mod:`d810.cfg.redirect_reconciliation`
+ :mod:`d810.cfg.dispatcher_aware_classifier` +
:mod:`d810.cfg.forward_target_resolver`. This module is the thin SQL +
log-parsing layer that feeds those helpers.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import replace as _dc_replace
from pathlib import Path

from d810.cfg.dispatcher_aware_classifier import (
    DispatcherContext,
    classify_backedges_dispatcher_aware,
)
from d810.cfg.forward_target_resolver import resolve_forward_target
from d810.cfg.redirect_reconciliation import (
    format_summary,
    parse_log_signals,
    parse_logged_intent,
    reconcile_edges,
)
from d810.cfg.scc import compute_live_cfg_sccs, nontrivial_sccs


# ---------------------------------------------------------------------------
# Helpers (pure -- no IDA imports)
# ---------------------------------------------------------------------------


def _hex_tok(stkoff: int | None) -> str | None:
    return f"sk:0x{int(stkoff):x}" if stkoff is not None else None


def load_persisted_dup_sources(conn: sqlite3.Connection) -> frozenset[int]:
    """Source blocks that emitted a ``DuplicateAndRedirect`` mod.

    The DupAndRedirect path may not produce per-source log lines but the
    ``modifications`` table is ground truth for "this source was redirected
    via per-pred routing", so we merge these into the HCC_DUP bucket.
    """
    rows = conn.execute(
        "SELECT DISTINCT source_block FROM modifications "
        "WHERE mod_type='DuplicateAndRedirect' AND status='emitted' "
        "AND source_block IS NOT NULL"
    ).fetchall()
    return frozenset(int(r[0]) for r in rows)


def load_bst_table(conn: sqlite3.Connection) -> dict[int, int]:
    """``state_const -> handler_block`` lookup from ``dag_edges``."""
    out: dict[int, int] = {}
    for sc, h in conn.execute(
        "SELECT DISTINCT target_state_i64, target_entry FROM dag_edges "
        "WHERE target_state_i64 IS NOT NULL AND target_entry IS NOT NULL"
    ):
        out[int(sc) & 0xFFFFFFFFFFFFFFFF] = int(h)
    return out


def load_block_succs(
    conn: sqlite3.Connection, snap_id: int,
) -> dict[int, tuple[int, ...]]:
    """``serial -> tuple(succ_serials)`` for *snap_id*."""
    out: dict[int, tuple[int, ...]] = {}
    for s, j in conn.execute(
        "SELECT serial, succs FROM blocks WHERE snapshot_id=?",
        (snap_id,),
    ):
        out[int(s)] = tuple(json.loads(j) or ())
    return out


def load_block_writes_and_predicates(
    conn: sqlite3.Connection,
    snap_id: int,
    block_serials: list[int],
    state_var_stkoff: int,
) -> tuple[
    dict[int, frozenset[str]],
    dict[int, frozenset[str]],
    dict[int, int | None],
]:
    """Returns ``(block_writes, block_predicate_reads, state_consts)``.

    - ``block_writes[serial]`` is the set of stkoff tokens (``sk:0x..``)
      that the block writes to.
    - ``block_predicate_reads[serial]`` is the set of stkoff tokens the
      block's tail instruction reads from (used for predicate-classification).
    - ``state_consts[serial]`` is the last constant written to the state
      variable in that block, or ``None``.
    """
    writes: dict[int, frozenset[str]] = {}
    reads: dict[int, frozenset[str]] = {}
    consts: dict[int, int | None] = {}
    for serial in block_serials:
        write_rows = conn.execute(
            "SELECT dest_stkoff FROM instructions WHERE snapshot_id=? "
            "AND block_serial=? AND dest_stkoff IS NOT NULL",
            (snap_id, serial),
        ).fetchall()
        writes[serial] = frozenset(
            _hex_tok(r[0]) for r in write_rows if r[0] is not None
        )
        tail = conn.execute(
            "SELECT src_l_stkoff, src_r_stkoff FROM instructions "
            "WHERE snapshot_id=? AND block_serial=? "
            "ORDER BY insn_index DESC LIMIT 1",
            (snap_id, serial),
        ).fetchone()
        reads[serial] = (
            frozenset(_hex_tok(s) for s in tail if s is not None)
            if tail
            else frozenset()
        )
        row = conn.execute(
            "SELECT src_l_value_i64 FROM instructions "
            "WHERE snapshot_id=? AND block_serial=? AND dest_stkoff=? "
            "AND src_l_value_i64 IS NOT NULL "
            "ORDER BY insn_index DESC LIMIT 1",
            (snap_id, serial, state_var_stkoff),
        ).fetchone()
        consts[serial] = (
            int(row[0]) & 0xFFFFFFFFFFFFFFFF if row else None
        )
    return writes, reads, consts


def compute_dispatcher_blocks(
    block_succs: dict[int, tuple[int, ...]],
    *,
    min_dispatcher_preds: int,
) -> frozenset[int]:
    """Block serials whose in-degree exceeds *min_dispatcher_preds*."""
    in_deg: dict[int, int] = {}
    for succs in block_succs.values():
        for t in succs:
            in_deg[t] = in_deg.get(t, 0) + 1
    return frozenset(b for b, n in in_deg.items() if n >= min_dispatcher_preds)


def load_persisted_redirect_goto(
    conn: sqlite3.Connection,
) -> dict[int, tuple[int | None, int | None]]:
    """``source_block -> (old_target, new_target)`` for emitted RedirectGoto.

    Only the first row per source is retained (legacy script behaviour).
    """
    out: dict[int, tuple[int | None, int | None]] = {}
    for src, old, tgt in conn.execute(
        "SELECT source_block, old_target, target_block FROM modifications "
        "WHERE mod_type='RedirectGoto' AND status='emitted'"
    ):
        if src is None or int(src) in out:
            continue
        out[int(src)] = (
            int(old) if old is not None else None,
            int(tgt) if tgt is not None else None,
        )
    return out


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run_reconcile(
    db_path: Path,
    log_path: Path,
    *,
    snap_id: int,
    state_var_stkoff: int,
    min_dispatcher_preds: int = 5,
    show_edges: bool = False,
) -> str:
    """Render the full reconciliation report for the given diag DB + log.

    Output matches the legacy script: header lines + ``format_summary``
    table + optional per-edge detail when *show_edges* is true.
    """
    if not log_path.exists():
        return f"Error: log not found: {log_path}\n"
    if not db_path.exists():
        return f"Error: db not found: {db_path}\n"

    state_var_tok = f"sk:0x{state_var_stkoff:x}"
    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    log_signals = parse_log_signals(log_text)
    logged_intent = parse_logged_intent(log_text)

    conn = sqlite3.connect(str(db_path))
    try:
        persisted_dup_sources = load_persisted_dup_sources(conn)
        if persisted_dup_sources:
            log_signals = _dc_replace(
                log_signals,
                hcc_dup_redirect_sources=(
                    log_signals.hcc_dup_redirect_sources | persisted_dup_sources
                ),
            )

        bst_table = load_bst_table(conn)

        def bst(k: int) -> int | None:
            return bst_table.get(int(k) & 0xFFFFFFFFFFFFFFFF)

        block_succs = load_block_succs(conn, snap_id)
        block_serials = sorted(block_succs)
        block_writes, block_predicate_reads, state_consts = (
            load_block_writes_and_predicates(
                conn, snap_id, block_serials, state_var_stkoff,
            )
        )

        dispatcher_blocks = compute_dispatcher_blocks(
            block_succs, min_dispatcher_preds=min_dispatcher_preds,
        )

        sccs = compute_live_cfg_sccs(block_succs)
        backedges: list[tuple[int, int]] = []
        for s in nontrivial_sccs(sccs):
            backedges.extend(s.cyclic_edges)

        ctx = DispatcherContext(
            dispatcher_blocks=dispatcher_blocks,
            excluded_carriers=frozenset({state_var_tok}),
        )
        classifications = classify_backedges_dispatcher_aware(
            backedges,
            block_writes=block_writes,
            block_predicate_reads=block_predicate_reads,
            context=ctx,
        )
        round_trips = [c for c in classifications if c.is_dispatcher_round_trip]

        resolver_targets: dict[tuple[int, int], int | None] = {}
        for c in round_trips:
            rc = state_consts.get(c.src_serial)
            res = resolve_forward_target(
                c,
                src_reaching_const={state_var_tok: rc},
                bst_resolver=bst,
            )
            resolver_targets[(c.src_serial, c.tgt_serial)] = (
                res.new_target if res else None
            )

        persisted = load_persisted_redirect_goto(conn)

        summary = reconcile_edges(
            ((c.src_serial, c.tgt_serial) for c in round_trips),
            resolver_targets=resolver_targets,
            logged_intent=logged_intent,
            persisted=persisted,
            state_consts=state_consts,
            bst_table=bst_table,
            log_signals=log_signals,
        )
    finally:
        conn.close()

    lines: list[str] = [
        f"# Reconciliation: snap {snap_id} ({db_path})",
        "",
        f"- BST table size: {len(bst_table)} state -> handler entries",
        f"- Dispatcher region (in-deg >= {min_dispatcher_preds}): "
        f"{len(dispatcher_blocks)} blocks",
        f"- Round-trip back-edges: {len(round_trips)}",
        f"- Logged trampoline-skip intent: {len(logged_intent)}",
        f"- Persisted RedirectGoto mods: {len(persisted)}",
        f"  → {len(logged_intent) - len(persisted)} logged emissions dropped before persist",
        "",
        format_summary(summary),
    ]
    if show_edges:
        lines.append("")
        lines.append("## Edge detail")
        for e in summary.edges:
            note_suffix = f" — {e.note}" if e.note else ""
            lines.append(
                f"  {e.bucket.value:48s} src={e.src_serial:3d}"
                f" tgt={e.tgt_serial:3d} resolver={e.resolver_target}"
                f" intent={e.logged_intent_target}"
                f" persisted={e.persisted_target} state={e.state_const}"
                + note_suffix
            )
    return "\n".join(lines) + "\n"
