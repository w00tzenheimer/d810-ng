# Task 4 report: interval-routed entry and transition states

## Scope

Task 4 makes interval-backed state routing use the shared concrete-state
consensus resolver for both entry bridges and transition/back-edge recovery.
The change is fail-closed: absent evidence, conflicting evidence, dispatcher
self-routes, and structural default routes do not authorize a redirect.

## RED

The initial focused RED run was:

```text
PYTHONPATH=src pytest -q \
  tests/unit/preanalysis/flow/test_minimal_state_recovery.py \
  tests/unit/transforms/test_minimal_unflatten_emit.py -vv
```

It collected 253 tests: 248 passed and 5 failed. The failing tests were:

- `test_ambiguous_materialized_route_abstains_even_when_interval_agrees`
- `test_outer_entry_preflight_rejects_legacy_lookup_when_consensus_abstains`
- `test_empty_handler_set_rejects_default_and_dispatcher_self_routes[99]`
- `test_native_and_materialized_entry_route_conflict_abstains_atomically`
- `test_interval_route_source_kinds_are_retained_in_transition_proof`

The last failure initially exposed a test-fixture `NameError` (`_blk`); the
fixture was corrected to use the local block helper before production changes.
An accepted-entry provenance regression was also added and remained RED until
the compiled plan carried typed entry proof metadata.

## Implementation

- Route providers now preserve absent, unique, and conflicting observations;
  materialized ambiguity cannot be collapsed into a target merely because an
  interval route agrees.
- Entry preflight uses the same consensus resolver as transition mutation.
  Structural default and dispatcher-self routes are rejected even when the
  handler evidence set is empty; an explicit singleton route remains
  distinguishable from a structural default.
- Native-bound and materialized evidence for the same original entry edge is
  combined atomically. A disagreement suppresses the bridge/fragment.
- `ConcreteStateRoute.source_kinds` is retained in typed transition proof data
  and in accepted entry proof metadata under
  `concrete_state_route_provenance`.
- Descriptor shape/value failures abstain at the provider boundary while
  arbitrary `RuntimeError` continues to propagate.
- The unused `_CombinedExactStateRouteProvider` was removed.
- Terminal/default classification remains explicit; only a live non-dispatcher
  handler target becomes a normal redirect.

## GREEN

Required focused suite:

```text
PYTHONPATH=src pytest -q \
  tests/unit/analyses/control_flow/test_concrete_state_route.py \
  tests/unit/preanalysis/flow/test_minimal_state_recovery.py \
  tests/unit/transforms/test_minimal_unflatten_emit.py
```

Result: **264 passed**.

Additional gates:

- host `ruff check` on all four changed source/test files: passed;
- `git diff --check`: passed;
- `sg scan --config sgconfig.yml --report-style short`: 0 broken rules;
- `PYTHONPATH=src lint-imports --config .importlinter`: 14 contracts kept,
  0 broken.

## Target C boundary

`.tmp/task4_target_c_green.txt` remains RED. The exact target-C test reached
the post-routing proof stage but failed only on the downstream
`corridor_enumeration_incomplete` rejection, with eight lost corridor blocks.
This is Task 5 corridor-enumeration work; it is not claimed as exact C GREEN
for Task 4.

The generated `samples/bins/unflattening_effect_safety.dll` artifact was
removed before commit.

## Commit

Final commit SHA: `8ace4a0ce99971bae1e8a4835464aa5ea68eb388`

## Fix round 2

The cumulative review of `8ace4a0ce` identified three fail-closed gaps:
scalar entry routing could accept an interval target outside the live handler
set, agreeing materialized/native entry providers could append the same
operation twice, and a malformed interval-row target descriptor could escape
the provider shape-error boundary.

### RED

The new portable tests were added before the production edits and run from the
worktree with `PYTHONPATH=src`. The initial selected run exposed the two
behavioral regressions directly:

- scalar entry routing emitted the unauthorized
  `RedirectGoto(from_serial=0, old_target=2, new_target=20)`;
- agreeing materialized/native providers emitted two identical
  `RedirectGoto(from_serial=1, old_target=2, new_target=10)` operations.

That first six-item run had **5 failures / 1 pass**: the three malformed-row
cases first stopped at a missing `all_targets()` method on the test-only
dispatcher seam. After that seam was corrected, the final six narrow-shape
cases and the separate `RuntimeError` pin exercised the intended provider
boundary.

The malformed-row fixture initially lacked the dispatcher `all_targets()`
test seam, so that harness defect was corrected before the production change.
The final malformed-row pins cover all six `_PROVIDER_SHAPE_ERRORS`
(`AttributeError`, `IndexError`, `KeyError`, `TypeError`, `ValueError`, and
`OverflowError`) and separately require `RuntimeError` propagation.

### Implementation

- Scalar entry consensus now accepts a target from the authoritative handler
  set or from an independently proven matching singleton/equality row; a broad
  interval-only target outside that set abstains. Structural default and
  dispatcher-self routes remain rejected.
- Entry-route operations are deduplicated by explicit graph-operation identity
  across materialized and native-bound providers, including operation kind and
  source/old/new coordinates.
- Interval-row descriptor access is inside the narrow `_PROVIDER_SHAPE_ERRORS`
  boundary; arbitrary exceptions remain visible.

### GREEN

Required focused suite:

```text
PYTHONPATH=src pytest -q \
  tests/unit/analyses/control_flow/test_concrete_state_route.py \
  tests/unit/preanalysis/flow/test_minimal_state_recovery.py \
  tests/unit/transforms/test_minimal_unflatten_emit.py
```

Result: **273 passed**.

Additional gates all passed after the final code edits:

- `ruff check src/d810/transforms/minimal_unflatten_emit.py tests/unit/transforms/test_minimal_unflatten_emit.py`;
- `git diff --check`;
- `sg scan --config sgconfig.yml --report-style short` (0 broken rules);
- `PYTHONPATH=src lint-imports --config .importlinter` (14 contracts kept,
  0 broken).

### Target C boundary

The fixture was rebuilt from this worktree with:

```text
./samples/scripts/build_masm.sh unflattening_effect_safety
```

The exact canonical Docker invocation was run from the main repository root
in **14.09s**, with output at `.tmp/task4_target_c_fix_round2.txt`. It reached the expected
downstream Task 5 gate:

```text
reason=corridor_enumeration_incomplete
lost=blk2@0x180044617, blk3@0x18004464B, blk4@0x18004464E,
     blk5@0x180044658, blk6@0x180044663, blk7@0x18004466A,
     blk12@0x1800447F5, blk17@0x1800448FC
```

The route/entry proof reached the post-routing stage; no Task4-specific
failure preceded the unchanged Task5 corridor-enumeration rejection. The
generated `samples/bins/unflattening_effect_safety.dll` was removed after the
run.

### Code commit

Code/tests commit: `2243ebd07892f67019245a52a3ac2f6f906ab4b3`
