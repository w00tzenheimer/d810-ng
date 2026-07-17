# Diagnostics Cleaner Simplification Design

**Ticket:** `tcvpu-f21a`

## Goal

Make diagnostic cleanup easy to reason about without weakening plan-first,
active-session, transaction, WAL, or quarantine safeguards.

## Decisions

- Retire time-based cleanup completely. D810 exposes no Unix timestamp input,
  action, planner, manager facade, or cleanup scope for it.
- The snapshot-cleanup composer offers exactly two policies: remove selected
  snapshots and retain the latest N snapshots in the selected database.
- The composer exposes one action selector and one `Preview cleanup plan`
  button. The N control is visible only for retention.
- Database maintenance remains explicit but separate: quarantine selected
  databases, quarantine all closed databases, and reclaim storage for selected
  databases.
- The panel always requests a WAL checkpoint. It is a safety invariant, not an
  operator preference.
- Confirmation controls appear only after a preview exists. `Reclaim storage
  after cleanup` appears only for snapshot cleanup plans.

## Boundaries

`d810.diagnostics.workbench_cleanup` remains the sole authority for cleanup
plans and execution. `workbench_diagnostics_logic` projects pure action and
execution state; `workbench_diagnostics_commands` is the allowlisted manager
adapter; `workbench_diagnostics_panel` only renders and forwards user intent.

## Acceptance

- No `OLDER_THAN`, Unix timestamp, or time-based cleanup planner remains.
- The panel has one action selector, conditional retention input, and one
  preview control instead of the snapshot-action button grid.
- UI execution always passes `checkpoint_wal=True`; active database protection,
  exact-plan confirmation, sidecar quarantine, and optional vacuum outcomes
  retain their current behavior.
- Focused diagnostics/UI tests, architecture gates, and a live IDA/X11 check
  pass before ticket closure.
