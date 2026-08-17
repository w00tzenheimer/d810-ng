# Task 4 report: bounded canonical matching in shadow mode

## Implementation

- Consolidated legacy DSL and canonical typed-template matching in one bounded
  AC/backtracking core in `src/d810/mba/ac_matching.py`.
- Added the shared `match_canonical_term_pattern` API, positive comparison
  budgets, canonical fixed bindings, deterministic accounting, and legacy
  report compatibility.
- Kept canonical template compilation and frozen constraint evaluation at the
  catalogue/adapter boundary; observation resolves bindings through canonical
  native provenance and exact raw-path identity.
- Kept the existing certificate-authorized structural dispatch path unchanged;
  canonical observation does not newly authorize it or mutate live AST state.
- Updated the Task 3 zero-budget transition and current v3 parity-certificate
  fixtures.

## TDD evidence

### RED

Command:

```text
PYTHONPATH=src pyenv exec python -m pytest -q tests/unit/mba/test_ac_matching.py tests/unit/mba/test_compiled_pattern_catalogue.py
```

Result: `3 failed, 16 passed in 124.21s (0:02:04)`.

The failures were the two zero-budget calls that still accepted zero and the
missing shared canonical entry point.

### GREEN

- Portable matcher/catalogue/canonical tests: `39 passed in 68.15s`.
- Required portable Task 4 command: `28 passed in 124.11s (0:02:04)`.
- Required Python Docker log `.tmp/canonical-shadow-python.log`:
  `37 passed, 118 warnings in 0.30s`.
- Required Cython Docker log `.tmp/canonical-shadow-cython.log`:
  `37 passed, 118 warnings in 0.26s`.
- Frozen-constraint probes: `2 passed in 63.54s`.

Both Docker commands were run from `/Users/mahmoud/src/idapro/d810` with the
requested worktree and separate logs.

## Static gates

- Ruff: passed (`All checks passed!`).
- `git diff --check`: passed.
- `sg scan --config sgconfig.yml --report-style short`: passed, 14 contracts
  kept and 0 broken.
- `PYTHONPATH=src lint-imports --config .importlinter`: passed.

`graphify update .` was attempted from the worktree but could not rebuild:
`[Errno 1] Operation not permitted`. No graph artifacts were staged.

## Scoped files

The implementation and tests changed only the Task 4 source/test files plus
this report. No unrelated changes were reverted or staged.

## Follow-up repair evidence

The review follow-up restored four legacy contracts without changing candidate
selection:

- Legacy DSL variables now bind only terminal candidates; canonical typed
  templates retain an explicit adapter policy for internal grouping terms.
- Canonical matches found before the comparison cap are retained and report
  `MATCHED`; the cap remains observable through the comparison count and the
  ordered catalogue boundary.
- Zero or multiple exact raw/native occurrences fail closed as
  `native_path_unavailable` matcher metadata and never claim structural native
  paths.
- N-ary AC alternative visits increment `commuted_branches` with the legacy
  count (`2` in the regression case).

### Follow-up RED

- `test_legacy_variable_binds_only_terminal_candidates` failed because the
  matcher returned `MATCHED` with root path `()` for `Var("x")` against an
  internal `add` term.
- `test_nary_ac_alternatives_preserve_legacy_commuted_branch_count` failed with
  `commuted_branches == 0` instead of `2`.
- `test_canonical_match_keeps_first_branch_when_budget_closes_after_match`
  failed before the repair because the shared matcher cleared the first match
  when the later branch hit the cap.
- Docker RED command:

  ```text
  D810_REPO_ROOT=/Users/mahmoud/src/idapro/d810 ./tools/scripts/run_system_tests_docker.sh test -w domain-lifted-semantic-simplification -o task4-followup-red-python.log -- tests/system/runtime/backends/test_ida_ac_matching.py::test_shadow_matcher_fails_closed_for_synthetic_internal_binding_path -q
  ```

  Result before the repair: `1 failed`; metadata was `matched` instead of
  `native_path_unavailable`.

### Follow-up GREEN

- Focused repair tests: `4 passed in 35.96s`.
- Required portable Task 4 command: `31 passed in 79.02s (0:01:19)`.
- Required Python Docker log `.tmp/canonical-shadow-python.log`:
  `38 passed, 118 warnings in 0.08s`.
- Required Cython Docker log `.tmp/canonical-shadow-cython.log`:
  `38 passed, 118 warnings in 0.10s`.
- Synthetic native-path regression after repair: `1 passed` in the Python
  Docker runtime.
- Final native-path guard rerun after the last adapter-state refinement:
  `1 passed` in `.tmp/task4-followup-final-native-path.log`.

### Follow-up static gates

- Ruff on all changed source/test files: passed (`All checks passed!`).
- `git diff --check`: passed.
- `sg scan --config sgconfig.yml --report-style short`: passed, 14 contracts
  kept and 0 broken.
- `PYTHONPATH=src lint-imports --config .importlinter`: passed.
- A follow-up `graphify update .` was attempted from the worktree but failed
  with `[Errno 1] Operation not permitted`; no graph artifacts were staged.
