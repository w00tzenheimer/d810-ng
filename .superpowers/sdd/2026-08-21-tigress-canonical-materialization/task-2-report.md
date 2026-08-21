# Task 2 implementation report

Status: IMPLEMENTED for the grouped planner/gateway/journal/certificate
interfaces and focused acceptance; the dedicated live 31-target canonical
materialization/reversal proof remains pending. The existing E2E xfail was not
changed.

## Files modified

- `src/d810/backends/ida/native_patch/metadata.py`
  - Added strict `item-xrefs:v2` parsing and canonical group provenance.
  - Allowed member `unknown` states only in v2 groups.
  - Added scope-aware grouped reads and auto-only xref reconciliation around
    item recreation, including rollback repair.
- `src/d810/backends/ida/native_patch/indirect_label_plan.py`
  - Captures all requested item states before planning, groups v2 targets by
    enclosing data head, emits cumulative decoded witnesses, and appends
    read-only composite seals after planned user xref actions.
- `src/d810/backends/ida/native_patch/gateway.py`
  - Passes composite scope hints on preflight, failure diagnostics, reverse,
    post-reanalysis, and certificate validation reads.
  - Persists exact metadata postconditions and requires certificate schema 3.
- `src/d810/backends/ida/native_patch/journal.py`
  - Serializes item recreation against conservative `item_graph` and
    `xref_graph` wildcard scopes.
- `src/d810/transforms/native_patch_plan.py`
  - Normalizes v1/v2 composite code targets to their inner code fingerprint
    and serializes exact certificate metadata postconditions.
- `tests/unit/backends/ida/native_patch/test_indirect_label_plan.py`
- `tests/unit/backends/ida/native_patch/test_gateway.py`
- `tests/unit/backends/ida/native_patch/test_journal.py`
- `tests/unit/transforms/test_native_patch_plan.py`
- `tests/system/runtime/backends/ida/test_native_writer_migration.py`

## RED evidence

Before production changes, the new v2 parser, composite fingerprint, and
wildcard journal tests failed as expected: `3 failed, 187 passed`. The failures
were missing v2 group admission, missing composite target normalization, and
the pre-existing byte-range conflict firing before the new xref-graph conflict
could be observed.

## GREEN evidence

- `PYTHONPATH=src pytest -q tests/unit/backends/ida/native_patch/test_indirect_label_plan.py tests/unit/backends/ida/native_patch/test_gateway.py tests/unit/manager/test_native_writer_migration.py`
  - `180 passed`.
- Extended focused matrix including journal and transform certificate tests:
  - `262 passed`.
- `ruff check` on all modified source and test files: all checks passed.
- `git diff --check`: passed.
- IDA Docker focused command from the main repository root:
  - `./tools/scripts/run_system_tests_docker.sh test -w tigress-canonical-materialization -l -o tigress_planner_gateway_green.txt -- tests/system/runtime/backends/ida/test_native_writer_migration.py -q`
  - `4 passed`.
- IDA Docker integration command from the main repository root:
  - `./tools/scripts/run_system_tests_docker.sh test -w tigress-canonical-materialization -l -o tigress_native_integration_green.txt -- tests/system/runtime/backends/ida/test_metadata_action_executor.py tests/system/runtime/backends/ida/test_native_writer_migration.py -q`
  - `29 passed, 126 warnings` (warnings are existing IDA deprecations).
- `graphify update .`: completed and refreshed the code graph.

## Selection/no-skip proof

The exact requested unit paths existed and were run. The exact requested
system paths existed and were run. No test was skipped or xfailed by the
implementation.

## 31-target/certificate/reversal evidence

The generic live migration path proves canonical gateway apply, certificate
reuse without a second mutation, and explicit restore for its discovered
target. The grouped v2 parser/planner and certificate scope tests prove the
provider-neutral contracts. However, this task branch does not yet contain a
dedicated live Tigress test that discovers and applies exactly 31 targets,
proves 31/31 materialization, stale touching-edge rejection, scoped witness
drift invalidation, and exact full-state restoration. That is the remaining
acceptance gap and must not be represented as completed evidence.

## Self-review and concerns

- The v2 implementation necessarily extends `metadata.py`, although the
  ownership list called out planner integration; without that extension the
  gateway could not read or apply v2 tokens.
- Auto-xref reconciliation is deliberately restricted to non-user rows and
  remains fail-closed on ownership drift.
- No E2E expectation or xfail was modified.
- The dedicated 31-target live proof is still required before claiming full
  Task 2 completion.

## Commit

The final commit carries message `test(native): prove canonical Tigress label
materialization`; its exact hash is the value of `git rev-parse HEAD` at
handoff (the report itself is part of that commit).
