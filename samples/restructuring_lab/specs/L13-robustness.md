# L13: Robustness (idempotency / reorder / rollback)

Status: planned (2026-06-06). Roadmap: `ROADMAP.md` (L13). Harness: Phases 1-3.

## Goal
Make the optblock-stage lowering robust under IDA's real execution: idempotent
across repeated optblock passes, correct under block reorder, and recoverable via
transactional rollback.

## What d810 already has
`ReorderBlocks` (`graph_modification.py:516`), `dispatcher_residue_cleanup.py`,
`DeferredGraphModifier.apply(enable_snapshot_rollback=, transactional=)`.

## Gap
The lab one-shots via a `done` flag and uses plain `apply(run_optimize_local=True)`.
Idempotency, reorder, and rollback are unexercised in the lab.

## Approach
Three checks: (1) idempotency -- the optblock fires for every block/maturity;
assert re-entry after `done` is a no-op and the result is stable across passes.
(2) rollback -- apply a deliberately-failing plan with
`enable_snapshot_rollback=True`; assert the mba is byte-restored. (3) reorder --
a fallthrough-sensitive case + `ReorderBlocks`; assert clean render.

## Fixture
Reuse P1 for idempotency + rollback; a small fallthrough-sensitive fixture for
reorder (or reuse `lab_flat_cond`).

## Success criteria
Re-entry is a stable no-op; a failing apply leaves the mba unchanged
(snapshot-restored); reorder renders correctly. Observations recorded.

## Risks / IR-dump unknowns
Constructing a clean rollback trigger; reorder semantics vs IDA's own ordering;
ensuring `done` truly prevents double-application across passes.

## Dependencies
P1. Lowest priority (polish); informs production integration.
