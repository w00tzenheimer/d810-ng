# L4: Projected-contract gate wiring

Status: planned (2026-06-06). Roadmap: `ROADMAP.md` (L4). Harness: Phases 1-3 +
the production transaction engine.

## Goal
Drive lab inserts through the **projected_contract** (verify the rebuilt CFG on a
projected/virtual `FlowGraph` BEFORE live mutation) -- the AGENTS.md "prove
before commit" gate -- not just post-apply `mba.verify()`.

## What d810 already has
`verify_projected` / `projected_contract` in `passes/transaction_engine.py`,
`passes/transaction_policy.py`, `transforms/contract.py` (`CfgContract`,
`BackendContractOracle`); `PatchPlan` + `new_blocks`.

## Gap
Lab inserts call `queue_create_and_redirect` directly and verify only after
`apply()`. The projected pre-mutation gate is never exercised in the lab.

## Approach
Express the lab reconstruction as a `PatchPlan` (`new_blocks` + ops), run
`projected_contract.verify_projected()` on the projected `FlowGraph`, then apply
only if projected verify passes. Add a negative case: a deliberately malformed
plan must be rejected pre-mutation (no live change).

## Fixture
Reuse P1. Two paths: (a) valid plan -> projected verify green -> apply -> render;
(b) malformed plan (e.g. dangling successor) -> projected verify rejects ->
no mutation, mba unchanged.

## Success criteria
Projected verify green for the valid plan; rejects the malformed plan before any
live mutation; the post-apply `mba.verify()` agrees with the projected verdict.

## Risks / IR-dump unknowns
Building the projected `FlowGraph` from the lab's ad-hoc inserts may require
modeling them as `PatchPlan`/`InsertBlock` ops rather than raw `queue_*` calls.

## Dependencies
None hard. Enables L5 (INTERR coverage) and L10 (maturity contract).
