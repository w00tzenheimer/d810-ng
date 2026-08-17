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
