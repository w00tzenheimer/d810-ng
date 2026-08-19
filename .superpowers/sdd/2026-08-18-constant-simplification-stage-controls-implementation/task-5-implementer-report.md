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

## Task 5 Fix Round 2

The independent review's remaining P1 was committed as a permanent regression
before the production fix:

```text
git commit -m "test(z3): cover contextual budget replacements"
1399cbd50
```

RED checkpoint, run from the main repository root:

```text
./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls -o task5_fix_round2_red.txt -- tests/system/runtime/backends/ast/test_z3_prover.py tests/system/runtime/backends/ast/test_z3_set_comparisons.py -q
================= 2 failed, 114 passed, 118 warnings in 0.13s ==================
```

The failures were both parameters of
`test_contextual_nonleaf_replacement_shares_policy_budget`: the one-node case
incorrectly proved with a stale receipt, and the two-node case reported only
the builder's root occurrence.

GREEN checkpoint, using the same required Docker test paths from the main
repository root:

```text
./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls -o task5_fix_round2_green_final.txt -- tests/system/runtime/backends/ast/test_z3_prover.py tests/system/runtime/backends/ast/test_z3_set_comparisons.py -q
====================== 116 passed, 118 warnings in 0.08s =======================
```

The fix gives the portable budget occurrence identities for AST builder
charges. The actual builder marks each constructed or cached AST occurrence;
the visitor consumes the same budget and skips only those already-charged
objects. A contextual recursive replacement therefore retains the original
builder charge and consumes every new replacement node. Direct root resolver
replacement keeps its established replacement-tree budget behavior. The
`m_ldc` regression now also runs the real visitor and asserts its exact receipt
remains two occurrences after translation.

Additional verification:

```text
PYTHONPATH=src pytest -q tests/unit/backends/ast/test_z3_proof_policy.py tests/unit/mba/backends/test_z3_no_global_state.py tests/unit/mba/test_native_z3_proof_template.py
102 passed in 1.26s

./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls -o task5_fix_round2_astproxy.txt -- tests/system/runtime/test_z3_astproxy_regression.py -q
1 passed, 122 warnings in 2.41s
```

The review-only snapshot probe is not present in the worktree; its retained
Round 1 output artifact records `5 passed, 118 warnings`. The permanent
context/MopSnapshot cache regressions were rerun in the required 116-test
suite. No snapshot test file was recreated.

`graphify update .` was attempted once after the changes and was blocked by
the environment during its watch rebuild: `[Errno 1] Operation not permitted`.
No retry was made.

Final gates passed in the task worktree:

```text
ruff check [all changed source/test files]
All checks passed!

PYTHONPATH=src python3 -m py_compile [all changed source/test files]
clean

sg scan --config sgconfig.yml --report-style short
exit 0

PYTHONPATH=src lint-imports --config .importlinter
Contracts: 14 kept, 0 broken.

git diff --check
clean
```

Production fix commit SHA: `753507859` (`fix(z3): share bounded contextual AST budget`).

## Task 5 Fix Round 3

The final review probe was made permanent before the production change:

```text
git commit -m "test(z3): cover repeated cached subtree budget"
28987e197
```

The probe builds a root `m_add` containing the same cached two-leaf `m_add`
subtree twice. Its logical occurrence count is seven (root plus three nodes per
subtree). RED, from the main repository root:

```text
./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls -o task5_fix_round3_red.txt -- tests/system/runtime/backends/ast/test_z3_prover.py tests/system/runtime/backends/ast/test_z3_set_comparisons.py -q
================= 1 failed, 116 passed, 118 warnings in 0.14s ==================
```

The failure was
`test_repeated_cached_subtree_charges_all_descendant_occurrences`: the
five-node budget did not raise because the local cache hit charged only the
reused subtree root.

The builder cache-hit path now recursively charges the reused AST's `left`,
`right`, and `dst` descendants and records each reused identity multiplicity,
without reconstructing nodes. No-budget cache behavior remains unchanged.

GREEN and final verification:

```text
./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls -o task5_fix_round3_green.txt -- tests/system/runtime/backends/ast/test_z3_prover.py tests/system/runtime/backends/ast/test_z3_set_comparisons.py -q
====================== 117 passed, 118 warnings in 0.09s =======================

PYTHONPATH=src pytest -q tests/unit/backends/ast/test_z3_proof_policy.py tests/unit/mba/backends/test_z3_no_global_state.py tests/unit/mba/test_native_z3_proof_template.py
102 passed in 1.09s

./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls -o task5_fix_round3_astproxy.txt -- tests/system/runtime/test_z3_astproxy_regression.py -q
1 passed, 122 warnings in 2.50s
```

The review-only snapshot probe remains absent; its retained artifact records
`5 passed, 118 warnings`, and the permanent snapshot/context regressions are
covered by the required suite. Ruff, `py_compile`, `sg`, lint-imports, and
`git diff --check` all passed (`Contracts: 14 kept, 0 broken.`).

Production fix commit SHA: `35e114973` (`fix(z3): account cached subtree occurrences`).

## Commit

Commit message: `feat(z3): bound predicate proof resources`

Feature commit SHA: de9194b1b.

## Task 5 Fix Round 4

The independent review's three P1 resource-bound findings were reproduced
before the production changes.

Pure RED:

```text
PYTHONPATH=src pytest -q tests/unit/backends/ast/test_z3_proof_policy.py
10 passed, 1 failed
```

The failure was the lifetime-safe identity regression against the old raw
integer-id occurrence store. The required Docker pair RED was:

```text
./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls -o task5_fix_round4_red.txt -- tests/system/runtime/backends/ast/test_z3_prover.py tests/system/runtime/backends/ast/test_z3_set_comparisons.py -q
117 passed, 3 failed, 118 warnings
```

The three failures were the repeated cached `m_ldc` nested-source charge,
contextual replacement pre-construction cutoff, and compiled-resolver budget
threading regressions.

The fix uses generic per-AST extra logical-occurrence metadata in
`AstBuilderContext`; cache hits replay unrepresented source occurrences (such
as an `m_ldc` wrapper's numeric source) while retaining repeated AST identity
multiplicity. `Z3ExpressionNodeBudget` now retains strong occurrence
references and compares them with `is`, so object lifetime/id reuse and custom
equality cannot alias a charge. The resolver path exposes the backend-neutral
`AstNodeBudget` protocol. Python and Cython recursive resolvers consume and
mark every rebuilt `AstNode` before construction, while the independent 4096
leaf-resolution cap remains unchanged when no policy is supplied. The Z3
preparation path passes the same policy budget into contextual resolution.

The m_ldc regression asserts the exact five logical occurrences for
`m_add(m_ldc(7), m_ldc(7))`: max=4 aborts at observed=4, max=5 succeeds at
observed=5, and the real visitor preserves that receipt. A permanent
Python/Cython parity regression exercises the pre-construction cutoff in both
selected resolver backends.

Final verification:

```text
./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls -o task5_fix_round4_green_final2.txt -- tests/system/runtime/backends/ast/test_z3_prover.py tests/system/runtime/backends/ast/test_z3_set_comparisons.py -q
120 passed, 118 warnings

D810_NO_CYTHON=0 ./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls -o task5_fix_round4_cython_final2.txt -- tests/system/runtime/backends/ast/test_z3_prover.py tests/system/runtime/backends/ast/test_z3_set_comparisons.py -q
120 passed, 118 warnings

D810_NO_CYTHON=0 ./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls -o task5_fix_round4_backend_parity_final.txt -- tests/system/runtime/test_pattern_engine_benchmark.py::TestCythonPythonParity::test_recursive_def_resolver_budget_cutoff_matches_python -q
1 passed, 118 warnings

./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls -o task5_fix_round4_astproxy_final.txt -- tests/system/runtime/test_z3_astproxy_regression.py -q
1 passed, 122 warnings

PYTHONPATH=src pytest -q tests/unit/backends/ast/test_z3_proof_policy.py tests/unit/mba/backends/test_z3_no_global_state.py tests/unit/mba/test_native_z3_proof_template.py
103 passed

ruff check [all changed Python source/test files]
All checks passed!

PYTHONPATH=src python3 -m py_compile [all changed Python source/test files]
clean

sg scan --config sgconfig.yml --report-style short
exit 0

PYTHONPATH=src lint-imports --config .importlinter
Contracts: 14 kept, 0 broken.

git diff --check
clean
```

`graphify update .` was attempted after the changes; its watch rebuild was
blocked by the environment with `[Errno 1] Operation not permitted`.

Atomic code/test commit: `a4b5e045c`
(`fix(z3): close bounded resource accounting gaps`).

## Task 5 Fix Round 5b

The follow-up review identified a production-path gap after Round 4: the
policy budget reached the recursive resolver, but contextual definitions were
still built through budget-free native, fallback, and memory-store seams.  A
second continuity finding showed that the direct Z3 preparation path reset the
budget after a bounded definition build.

RED checkpoints:

```text
./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls -o task5_fix5b_red.txt -- tests/system/runtime/backends/ast/test_z3_prover.py -q -k 'bounded_minsn_gateway_routes_to_python_builder or contextual_definition_builder_shares_policy_budget'
1 gateway TypeError + 6 resolver TypeErrors (expected missing node_budget APIs)

./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls -o task5_fix5b_reset_red.txt -- tests/system/runtime/backends/ast/test_z3_prover.py -q -k direct_contextual_resolution_keeps_one_cumulative_budget
1 failed: receipt was 1 instead of the cumulative 3
```

The repair threads the backend-neutral `AstNodeBudget` through native
predecessor search, MopTracker fallback, memory-store resolution, both Python
and Cython recursive walkers, and the direct Z3 preparation call.  Bounded
`minsn_to_ast` always selects the Python builder; the compiled provider remains
the no-budget path.  The bounded Python minsn builder now propagates typed node
limits instead of swallowing them as legacy `RuntimeError`s.  The memory-store
comparison guard no longer catches a builder cutoff.  One budget is retained
through original construction, contextual definition construction, recursive
resolution, and visitor traversal.

Final focused and acceptance verification:

```text
normal Task 5 pair: 129 passed, 118 warnings
Cython/native Task 5 pair: 129 passed, 118 warnings
Cython/Python resolver parity: 1 passed, 118 warnings
AstProxy regression: 1 passed, 122 warnings
def_search snapshot regressions: 14 passed, 118 warnings
pure policy/cache/template tests: 103 passed
ruff: All checks passed!
py_compile: clean
sg scan: exit 0
lint-imports: Contracts: 14 kept, 0 broken.
git diff --check: clean
```

`graphify update .` was retried after the final source changes; its watch
rebuild remained blocked by the environment with `[Errno 1] Operation not
permitted`.

Atomic code/test commit: `540995e67`
(`fix(z3): bound contextual definition expansion`).
