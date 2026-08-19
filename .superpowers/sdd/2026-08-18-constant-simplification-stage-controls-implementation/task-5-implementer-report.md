# Task 5 implementer report: bounded predicate proof resources

## Result

Implemented the portable proof policy/result vocabulary, occurrence-budgeted
AST expansion, policy-scoped solver isolation, structured result APIs, and
conclusive-only cache behavior for `Z3MopProver`.

The final commit SHA is recorded below after commit creation.

## RED evidence

Before implementation, the new pure test module was run with:

```text
PYTHONPATH=src pytest -q tests/unit/backends/ast/test_z3_proof_policy.py
```

The run failed with 10 failures, each failing at import time with:
`ModuleNotFoundError: No module named 'd810.backends.ast.z3_proof_policy'`.
This was the intended RED state for the missing portable policy module.

## GREEN evidence

Pure policy/budget tests after implementation:

```text
PYTHONPATH=src pytest -q tests/unit/backends/ast/test_z3_proof_policy.py
..........                                                               [100%]
10 passed in 0.05s
```

Adjacent pure regression tests:

```text
PYTHONPATH=src pytest -q \
  tests/unit/backends/ast/test_z3_proof_policy.py \
  tests/unit/mba/backends/test_z3_no_global_state.py \
  tests/unit/mba/test_native_z3_proof_template.py
........................................................................ [ 70%]
..............................                                           [100%]
102 passed in 1.42s
```

The required IDA Docker command was run from the main repository root:

```text
./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls -o bounded_z3_prover.txt -- tests/system/runtime/backends/ast/test_z3_prover.py tests/system/runtime/backends/ast/test_z3_set_comparisons.py -q
```

The initial bounded suite passed 106 tests. After adding the explicit
`prove_comparison` abstention-retry regression, the final run passed:

```text
====================== 107 passed, 118 warnings in 0.12s =======================
```

The warnings are the existing IDA SWIG deprecation warnings.

Additional final gates from the task worktree:

```text
PYTHONPATH=src python3 -m py_compile \
  src/d810/backends/ast/z3_proof_policy.py \
  src/d810/backends/ast/z3.py \
  src/d810/hexrays/ir/mop_utils.py \
  tests/unit/backends/ast/test_z3_proof_policy.py \
  tests/system/runtime/backends/ast/test_z3_prover.py \
  tests/system/runtime/backends/ast/test_z3_set_comparisons.py
ruff check <all changed source and test files>
git diff --check
```

All completed successfully; Ruff reported `All checks passed!`.

```text
sg scan --config sgconfig.yml --report-style short
```

Exited 0 with no broken-rule output.

```text
PYTHONPATH=src lint-imports --config .importlinter
```

`Contracts: 14 kept, 0 broken.`

## Files modified

- `src/d810/backends/ast/z3_proof_policy.py`: portable frozen policy,
  status/reason/result types, and typed mutable occurrence budget.
- `src/d810/backends/ast/z3.py`: bounded result APIs and fail-closed wrappers;
  fresh local solver/timeout handling; explicit sat/unsat/unknown mapping;
  policy/query-scoped conclusive caches; budget threading into translation and
  visitor paths.
- `src/d810/hexrays/ir/mop_utils.py`: the actual recursive mop-to-AST seam now
  accepts the budget and consumes before cache lookup, descent, or construction;
  bounded calls bypass the global AST template cache so repeated occurrences
  are charged.
- `tests/unit/backends/ast/test_z3_proof_policy.py`: RED/GREEN portable policy
  validation, immutability, repeated-occurrence accounting, and cutoff tests.
- `tests/system/runtime/backends/ast/test_z3_prover.py`: bounded result/status,
  solver isolation, timeout mapping, policy isolation, builder-seam cutoff, and
  retry-after-abstention regressions.
- `tests/system/runtime/backends/ast/test_z3_set_comparisons.py`: bounded
  always-zero/nonzero result and wrapper regression.

## Deviations and risks

- `mop_utils.py` is an additional production file beyond the plan's initial
  file list. This was required by the controller finding: a shadow pre-walker
  would not prove that the actual recursive builder stops before constructing
  an over-budget occurrence. The unbounded builder/cache behavior remains
  unchanged.
- The bounded path deliberately bypasses the global AST template cache to
  account for every recursive occurrence. It creates a fresh builder context;
  this trades bounded-proof cache reuse for sound accounting.
- The Docker command uses the repository's normal `D810_NO_CYTHON=1` test
  configuration. The bounded prover imports the Python `mop_utils` builder
  seam; no separate Cython builder API was changed.
- `graphify update .` was attempted exactly once as requested. It returned only
  the installed graphify version-mismatch warning and produced no tracked graph
  diff (`graphify-out/` contains only the pre-existing cache/stat-index file).

## Task 5 Fix Round 1

The independent review identified context-sensitive cache reuse, discarded
caller solver assertions, stale resolved-AST receipts, and an uncharged nested
`m_ldc` constant. Four permanent Docker regressions were added before fixing.

RED checkpoint, run from the main repository root:

```text
./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls -o task5_fix_round1_red.txt -- tests/system/runtime/backends/ast/test_z3_prover.py tests/system/runtime/backends/ast/test_z3_set_comparisons.py -q
================= 3 failed, 108 passed, 118 warnings in 0.19s ==================
```

The failing tests were the context-resolved zero cache/receipt regression, the
bounded caller-assertion regression, and the `m_ldc` wrapper/nested-constant
budget regression.

GREEN checkpoint, with the equal/unequal/comparison context-cache audit added:

```text
./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls -o task5_fix_round1_green.txt -- tests/system/runtime/backends/ast/test_z3_prover.py tests/system/runtime/backends/ast/test_z3_set_comparisons.py -q
====================== 114 passed, 118 warnings in 0.13s =======================
```

The pure/adjacent and focused system checks also passed:

```text
PYTHONPATH=src pytest -q tests/unit/backends/ast/test_z3_proof_policy.py tests/unit/mba/backends/test_z3_no_global_state.py tests/unit/mba/test_native_z3_proof_template.py
102 passed in 1.47s

./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls -o task5_fix_round1_astproxy.txt -- tests/system/runtime/test_z3_astproxy_regression.py -q
1 passed, 122 warnings in 2.72s
```

Ruff, `py_compile`, `git diff --check`, `sg scan --config sgconfig.yml
--report-style short`, and `PYTHONPATH=src lint-imports --config .importlinter`
all passed; import-linter reported `Contracts: 14 kept, 0 broken.`

The fix bypasses all proof caches when effective `blk`/`ins`, a
`MopSnapshot`, or a caller solver is present; bounded fresh solvers now copy
caller assertions before applying only the local policy timeout; resolved
receipts read the live post-visitor budget; and `m_ldc` charges its nested
numeric constant separately before construction. Equal, unequal, comparison,
and zero/nonzero cache paths are covered by the context audit regressions.

Fix commit SHA: 37ab47636.

## Commit

Commit message: `feat(z3): bound predicate proof resources`

Feature commit SHA: de9194b1b.
