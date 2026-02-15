# MBA state preconditioner: context and execution plan

## Context

Flattened functions with heavy MBA often need one more local simplification wave
before flow unflatteners can resolve dispatcher fathers reliably.

Instruction rules already run throughout decompilation, but dispatcher state can
still remain noisy at the exact flow pass where unflattening starts. That
creates avoidable ambiguity and pushes unflatteners into conservative/deferred
paths.

## Goal

Introduce a dedicated flow rule that preconditions MBA-heavy dispatcher state
before unflatteners run, without adding new CFG mutation risk.

## Plan

1. Add `MbaStatePreconditioner(FlowOptimizationRule)` in the flow optimizer
   package.
2. Give it a priority between constant preparation and unflatteners so it runs
   in the right phase ordering.
3. Run it once per function per maturity, from block serial `1`, with bounded
   `mba.optimize_local()` rounds.
4. Optionally gate execution through `FlowMaturityContext` so we only spend
   work on functions that qualify for unflattening.
5. Expose config knobs in `CONFIG_SCHEMA` for:
   - max rounds,
   - gate requirement,
   - verify-after-round.
6. Add runtime tests for the contract:
   - once-per-maturity behavior,
   - gate-denied skip behavior,
   - bounded round aggregation.

## Safety notes

- This pass does not edit CFG directly.
- It is bounded and guarded against re-entrant invocation.
- It keeps verification optional and explicit to aid CI diagnosis.
