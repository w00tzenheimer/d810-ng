# Task 6 implementer report: bounded Z3 predicate transforms

## Result

Task 6 is implemented in `b7cee6071`:

```text
feat(mba): configure bounded z3 predicates
```

The three generic transforms in `mba-simplify` now own independent immutable
`Z3ProofPolicy` values. Their editor/parser fields are
`max_expression_nodes` (default 256, range 1..4096) and
`proof_timeout_ms` (default 50, range 1..5000). Defaults are materialized only
for selected transforms, through one shared helper used by both the adapter
request and the live hook bridge.

Every `setz`, `setnz`, and `lnot` prover construction passes that rule's policy
and consumes `Z3ProofResult`. Only `PROVED` mutates; `DISPROVED` and every
abstention return no match. A frozen `Z3PredicateProofObserved` event carries
the transform ID, configured bounds, observed nodes, elapsed milliseconds,
status, and typed reason. The existing lifecycle event model and diagnostic
handler persist the structured payload. Conclusive reasons remain `None`; an
abstention retains its concrete `Z3ProofAbstentionReason.value`.

## TDD evidence

Initial RED evidence, before the schema and runtime wiring landed:

```text
PYTHONPATH=src pytest -q \
  tests/unit/passes/test_mba_transform_options.py \
  tests/unit/passes/test_mba_transform_catalog.py \
  tests/unit/passes/test_mba_simplify.py \
  tests/unit/passes/test_pipeline_v2_hook_bridge.py
7 failed, 31 passed in 0.21s
```

The first receipt-test collection also failed with:
`ImportError: cannot import name 'Z3PredicateProofObserved'`.

The final focused/adjacent unit command passed:

```text
PYTHONPATH=src pytest -q \
  tests/unit/passes/test_mba_transform_options.py \
  tests/unit/passes/test_mba_transform_catalog.py \
  tests/unit/passes/test_mba_simplify.py \
  tests/unit/passes/test_pipeline_v2_hook_bridge.py \
  tests/unit/optimizers/test_z3_predicate_options.py \
  tests/unit/core/diag/test_event_handlers.py \
  tests/unit/core/diag/test_models_schema_equivalence.py
127 passed in 1.47s
```

The runtime test explicitly covers all prover-construction sites: equal,
unequal, always-zero, and always-nonzero for both set predicates, and equal
and unequal for lnot. It also verifies low-node setz abstention does not block
setnz and that lnot retains its unrelated timeout.

Required IDA runtime command, launched from the main repository root:

```text
./tools/scripts/run_system_tests_docker.sh test \
  -w constant-simplification-stage-controls \
  -o z3_predicate_bounds.txt -- \
  tests/system/runtime/test_z3_predicate_bounds.py -q
13 passed, 118 warnings in 0.03s
```

The first runtime attempt exposed a native `ida_hexrays.mop_t()` segfault in
the mocked lnot fixture. The fixture was corrected to use a fake zero mop, and
the exact required command then passed.

Final static gates:

```text
ruff check ...                         All checks passed!
PYTHONPATH=src python3 -m py_compile  passed
sg scan --config sgconfig.yml ...      exit 0
PYTHONPATH=src lint-imports ...        Contracts: 14 kept, 0 broken.
git diff --check                       clean
```

`graphify update .` was attempted after the edits; its watch rebuild was
blocked by the environment with `[Errno 1] Operation not permitted`.

Task 7 and Task 8 were not started.

## Review fix round

The independent review identified two Task 6 defects: the portable receipt
accepted arbitrary status/reason strings and the producer synthesized
`proof_abstained`; direct live-rule configuration also duplicated the policy
defaults. The repair is in `9034ae5ad`:

```text
fix(mba): close bounded z3 receipt contract
```

`d810.core.z3_proof` now owns the dependency-free `Z3ProofStatus` and
`Z3ProofAbstentionReason` vocabularies. The frozen observability event accepts
only those exact types, all four abstention reasons, and `None` for conclusive
reasons. The producer validates result shape and returns `False` without
emitting a receipt or allowing mutation when a result is malformed. Enum
values become strings only in the existing diagnostic persistence handler.
The live rule derives omitted direct-configuration values from a fresh
canonical `Z3ProofPolicy()` while retaining one independent immutable policy
per rule. Backend imports continue to re-export the portable enums.

Review-fix RED evidence:

```text
PYTHONPATH=src pytest -q tests/unit/optimizers/test_z3_predicate_options.py
2 failed, 10 passed in 0.10s

./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls \
  -o review_fix_red_z3_predicate_bounds.txt -- \
  tests/system/runtime/test_z3_predicate_bounds.py -q
4 failed, 13 passed, 118 warnings in 0.14s
```

The failures were the new closed-contract, malformed-result, and
canonical-default regressions. After the repair:

```text
PYTHONPATH=src pytest -q \
  tests/unit/passes/test_mba_transform_options.py \
  tests/unit/passes/test_mba_transform_catalog.py \
  tests/unit/passes/test_mba_simplify.py \
  tests/unit/passes/test_pipeline_v2_hook_bridge.py \
  tests/unit/optimizers/test_z3_predicate_options.py \
  tests/unit/core/diag/test_event_handlers.py \
  tests/unit/core/diag/test_models_schema_equivalence.py \
  tests/unit/backends/ast/test_z3_proof_policy.py
140 passed in 1.17s

./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls \
  -o review_fix_final_z3_predicate_bounds.txt -- \
  tests/system/runtime/test_z3_predicate_bounds.py -q
17 passed, 118 warnings in 0.06s

D810_NO_CYTHON=0 ./tools/scripts/run_system_tests_docker.sh test \
  -w constant-simplification-stage-controls -o review_fix_cython_z3_predicate_bounds.txt -- \
  tests/system/runtime/test_z3_predicate_bounds.py -q
17 passed, 118 warnings in 0.14s

./tools/scripts/run_system_tests_docker.sh test -w constant-simplification-stage-controls \
  -o review_fix_green_z3_adjacent_astproxy.txt -- \
  tests/system/runtime/test_z3_astproxy_regression.py -q
1 passed, 122 warnings in 5.23s
```

Ruff, `PYTHONPATH=src python3 -m py_compile`, `sg scan` (`14 kept, 0
broken`), `PYTHONPATH=src lint-imports` (`14 kept, 0 broken`), and
`git diff --check` passed. The graphify update was attempted again but the
environment did not complete its watch rebuild. Task 7 and Task 8 were not
started.
