# Byte-Tail Runtime Diagnostic-Storage Inventory

Scope: `src/d810/hexrays/mutation/byte_emit_tail_isolation_runtime.py`.

## Summary

- No diagnostic DB writes found. The file only reads the active diag SQLite DB.
- No pure diagnostic/reporting-only DB reads found. Every current read feeds an
  env-gated mutation, planner row, live-block bridge, or DAG safety predicate.
- The `no-hexrays-mutation-diagnostic-storage-imports` ignore must remain until
  these behavior-bearing reads are replaced by in-memory evidence providers.

## DB Read Classification

- `DiagDbFactView.__init__` and `terminal_byte_emit_facts`
  - Tables: `snapshots`, `fact_observations`.
  - Used by: `maybe_run_tail_distinct`, `maybe_run_tail_duplicate_convergence`.
  - Classification: behavior-bearing fact lookup.
  - Replacement boundary: pass a `ValidatedFactView`-like in-memory fact view
    into these probes, matching the existing
    `_load_planner_sites_from_fact_view` path.

- `maybe_run_tail_distinct` / `maybe_run_tail_duplicate_convergence`
  - Access: `get_active_diag_conn(func_ea)` then `DiagDbFactView`.
  - Classification: behavior-bearing fact lookup; the selected fact controls
    which live edge is mutated.
  - Replacement boundary: caller supplies terminal-byte observations already
    collected for the current function; mutation code consumes only a fact-view
    protocol and `LiveMbaAdapter`.

- `_resolve_planner_snapshots`
  - Tables: `snapshots`, `fact_observations`, `blocks`.
  - Used by: `maybe_run_tail_state_cascade`.
  - Classification: behavior-bearing planner lookup.
  - Replacement boundary: remove snapshot selection from mutation runtime by
    providing planner evidence for the active function directly.

- `_load_planner_blocks`
  - Tables: `blocks`, `instructions`.
  - Used by: `maybe_run_tail_state_cascade`.
  - Classification: behavior-bearing planner lookup.
  - Replacement boundary: use `_load_planner_blocks_from_mba` or an explicit
    `TerminalTailPlannerEvidenceProvider` that builds `TerminalTailBlock` rows
    from live MBA/block evidence without SQLite.

- `_load_planner_sites`
  - Table: `fact_observations`.
  - Used by: `maybe_run_tail_state_cascade`.
  - Classification: behavior-bearing fact/planner lookup.
  - Replacement boundary: use `_load_planner_sites_from_fact_view` over an
    in-memory fact view supplied by the reconstruction/observability boundary.

- `_bridge_plan_row_to_live_mba`
  - Table: `blocks` via `start_ea_i64`.
  - Used by: `maybe_run_tail_state_cascade`.
  - Classification: behavior-bearing planner bridge; failed mapping suppresses
    mutation.
  - Replacement boundary: planner rows should already use live serials, or a
    non-SQLite block identity map should be supplied with the planner evidence.

- `_map_snap_successor_to_live`, `_map_snap_serial_to_live`,
  `_snap_start_ea`, `_snap_instruction_eas`, `_snap_serial_for_live_block`
  - Tables: `blocks`, `instructions`.
  - Used by: terminal-tail entry/equality/frontier closure helpers.
  - Classification: behavior-bearing planner bridge.
  - Replacement boundary: use live-MBA lookup plus an in-memory block identity
    map captured before mutation; avoid diag snapshot serials in runtime plans.

- `_load_dag_semantics`
  - Tables: `dag_edges`, `dag_nodes`, `dag_node_blocks`.
  - Used by: DAG SCC and frontier legality checks.
  - Classification: behavior-bearing DAG/planner lookup.
  - Replacement boundary: pass the current `LinearizedStateDag` into the
    mutation backend and use `_load_dag_semantics_from_dag`; do not reconstruct
    semantic reachability from persisted diag rows at mutation time.

- `maybe_run_tail_state_cascade`
  - Access: `get_active_diag_conn(func_ea)`, `_resolve_planner_snapshots`,
    `_load_planner_blocks`, `_load_planner_sites`, and snap-to-live bridge reads.
  - Classification: behavior-bearing planner/DAG/fact lookup.
  - Replacement boundary: convert the env-gated hook to consume a supplied
    `TerminalTailPlannerEvidenceProvider` with in-memory facts, live blocks,
    block identity, and DAG semantics.

## Non-DB In-Memory Path Already Present

`maybe_run_terminal_tail_cascade_egress_lowering(mba, *, fact_view, dag)` already
uses `_load_planner_blocks_from_mba`, `_load_planner_sites_from_fact_view`, and
`_load_dag_semantics_from_dag`. That is the replacement shape to extend to the
remaining env-gated byte-tail probes before the Hex-Rays mutation ignore can be
removed.
