# L9: True dead-def removal (not DCE-reliance)

Status: planned (2026-06-06). Roadmap: `ROADMAP.md` (L9). Harness: Phases 1-3.

## Goal
Deterministically remove the originals' now-dead state writes after redirect,
instead of relying on Hex-Rays DCE to clear them.

## What d810 already has
`ZeroStateWrite` (`graph_modification.py:400`, kills the write's source),
`queue_zero_state_write` / `queue_insn_nop`, `insn_snapshot_materializer`
(`IPROP_PERSIST`). De-flatten ledger: "no true dead-def removal".

## Gap
P1-P3 leave the originals' `state = K` writes in place and depend on DCE removing
them once the dispatcher dies. That fails when a write is not provably dead (the
`shared_convergence` negative control -> loop induction).

## Approach
After redirect, compute liveness of the state slot and explicitly NOP/zero the
provably-dead state writes (`queue_zero_state_write`) rather than relying on DCE.
Validate by disabling `optimize_local` (or asserting the writes are gone even
without it).

## Fixture
Reuse P1; add explicit dead-def removal; assert no state writes survive
independent of DCE (e.g. `apply(run_optimize_local=False)` still renders clean).

## Success criteria
State writes removed by explicit op; `mba.verify()` clean; render state-free even
with local-opt disabled. Observation records DCE-independence.

## Risks / IR-dump unknowns
Liveness must prove the write dead before removal (don't remove a still-read
write); `zero` vs `nop` semantics; interaction with L2 (reg-sourced writes).

## Dependencies
P1; complements L2 (full state elimination).
