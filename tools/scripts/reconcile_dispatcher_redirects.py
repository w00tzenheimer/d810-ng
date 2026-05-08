#!/usr/bin/env python3
"""Reconcile resolver predictions against live dispatcher_trampoline_skip emissions.

Reads a sub_7FFD-style diag DB + d810.log produced by ``run_system_tests_docker.sh dump``
and prints the bucket breakdown described in Piece 5.5 of ticket uee-32r3.

Usage:
    PYTHONPATH=src python tools/scripts/reconcile_dispatcher_redirects.py \\
        --db .tmp/logs/d810_logs/<func>.diag.sqlite3 \\
        --log .tmp/logs/d810_logs/d810.log \\
        --snap-id 5 \\
        --state-var-stkoff 0x3C
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

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


def _hex_tok(stkoff: int | None) -> str | None:
    return f"sk:0x{int(stkoff):x}" if stkoff is not None else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, help="Path to diag .sqlite3")
    parser.add_argument("--log", required=True, help="Path to d810.log")
    parser.add_argument(
        "--snap-id", type=int, required=True,
        help="Snapshot ID to reconcile (e.g. MMAT_GLBOPT1 pre_d810)",
    )
    parser.add_argument(
        "--state-var-stkoff",
        default="0x3C",
        help="State variable stack offset (hex). Default 0x3C for sub_7FFD.",
    )
    parser.add_argument(
        "--min-dispatcher-preds",
        type=int,
        default=5,
        help="Minimum in-degree to count a block as dispatcher region.",
    )
    parser.add_argument(
        "--show-edges",
        action="store_true",
        help="Print every edge with bucket and evidence.",
    )
    args = parser.parse_args()

    state_var_stkoff = int(args.state_var_stkoff, 16)
    state_var_tok = f"sk:0x{state_var_stkoff:x}"

    log_text = Path(args.log).read_text()
    log_signals = parse_log_signals(log_text)
    logged_intent = parse_logged_intent(log_text)

    conn = sqlite3.connect(args.db)

    bst_table = {
        int(sc) & 0xFFFFFFFFFFFFFFFF: int(h)
        for sc, h in conn.execute(
            "SELECT DISTINCT target_state_i64, target_entry FROM dag_edges "
            "WHERE target_state_i64 IS NOT NULL AND target_entry IS NOT NULL"
        )
    }

    def bst(k: int) -> int | None:
        return bst_table.get(int(k) & 0xFFFFFFFFFFFFFFFF)

    block_succs: dict[int, tuple[int, ...]] = {
        int(s): tuple(json.loads(j) or ())
        for s, j in conn.execute(
            "SELECT serial, succs FROM blocks WHERE snapshot_id=?",
            (args.snap_id,),
        )
    }

    block_writes: dict[int, frozenset[str]] = {}
    block_predicate_reads: dict[int, frozenset[str]] = {}
    state_consts: dict[int, int | None] = {}

    for serial in block_succs:
        ws = conn.execute(
            "SELECT dest_stkoff FROM instructions WHERE snapshot_id=? "
            "AND block_serial=? AND dest_stkoff IS NOT NULL",
            (args.snap_id, serial),
        ).fetchall()
        block_writes[serial] = frozenset(_hex_tok(r[0]) for r in ws if r[0] is not None)
        tail = conn.execute(
            "SELECT src_l_stkoff, src_r_stkoff FROM instructions "
            "WHERE snapshot_id=? AND block_serial=? "
            "ORDER BY insn_index DESC LIMIT 1",
            (args.snap_id, serial),
        ).fetchone()
        block_predicate_reads[serial] = (
            frozenset(_hex_tok(s) for s in tail if s is not None) if tail else frozenset()
        )
        row = conn.execute(
            "SELECT src_l_value_i64 FROM instructions "
            "WHERE snapshot_id=? AND block_serial=? AND dest_stkoff=? "
            "AND src_l_value_i64 IS NOT NULL "
            "ORDER BY insn_index DESC LIMIT 1",
            (args.snap_id, serial, state_var_stkoff),
        ).fetchone()
        state_consts[serial] = (
            int(row[0]) & 0xFFFFFFFFFFFFFFFF if row else None
        )

    in_deg: dict[int, int] = {}
    for s, succs in block_succs.items():
        for t in succs:
            in_deg[t] = in_deg.get(t, 0) + 1
    dispatcher_blocks = frozenset(
        b for b, n in in_deg.items() if n >= args.min_dispatcher_preds
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
            c, src_reaching_const={state_var_tok: rc}, bst_resolver=bst,
        )
        resolver_targets[(c.src_serial, c.tgt_serial)] = (
            res.new_target if res else None
        )

    persisted: dict[int, tuple[int | None, int | None]] = {}
    for src, old, tgt in conn.execute(
        "SELECT source_block, old_target, target_block FROM modifications "
        "WHERE mod_type='RedirectGoto' AND status='emitted'"
    ):
        if src is not None and src not in persisted:
            persisted[int(src)] = (
                int(old) if old is not None else None,
                int(tgt) if tgt is not None else None,
            )

    summary = reconcile_edges(
        ((c.src_serial, c.tgt_serial) for c in round_trips),
        resolver_targets=resolver_targets,
        logged_intent=logged_intent,
        persisted=persisted,
        state_consts=state_consts,
        bst_table=bst_table,
        log_signals=log_signals,
    )

    print(f"# Reconciliation: snap {args.snap_id} ({args.db})")
    print()
    print(f"- BST table size: {len(bst_table)} state -> handler entries")
    print(f"- Dispatcher region (in-deg >= {args.min_dispatcher_preds}): "
          f"{len(dispatcher_blocks)} blocks")
    print(f"- Round-trip back-edges: {len(round_trips)}")
    print(f"- Logged trampoline-skip intent: {len(logged_intent)}")
    print(f"- Persisted RedirectGoto mods: {len(persisted)}")
    print(f"  → {len(logged_intent) - len(persisted)} logged emissions dropped before persist")
    print()
    print(format_summary(summary))

    if args.show_edges:
        print()
        print("## Edge detail")
        for e in summary.edges:
            print(
                f"  {e.bucket.value:48s} src={e.src_serial:3d} tgt={e.tgt_serial:3d} "
                f"resolver={e.resolver_target} intent={e.logged_intent_target} "
                f"persisted={e.persisted_target} state={e.state_const}"
                + (f" — {e.note}" if e.note else "")
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
