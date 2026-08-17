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

Final commit SHA: `69998b4fc9c7d7574cd9d68dfe3baa395855b97f`
