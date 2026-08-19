# SDD ledger — plan: docs/plans/2026-08-18-constant-simplification-stage-controls-implementation.md

## Run identity

- Base: `a44278899b039409690e7f3431bc3917fb934a00`
- Branch: `diff/constant-simplification-stage-controls`
- Worktree: `/Users/mahmoud/src/idapro/d810/.worktrees/constant-simplification-stage-controls`
- Controller: root agent, `gpt-5.6-sol`, high reasoning
- Implementers/reviewers: fresh `gpt-5.6-luna`, max reasoning, sequential dispatch
- Baseline: 74 focused unit tests passed in 0.85s before changes

## Preflight consistency scan

| Scope | Shared surface / dependency | Ruling |
|---|---|---|
| Task 1 | Portable option and descriptor model | Foundational; finish and review before every later task. |
| Task 2 | Task 1 compiler -> hook activation/runtime | Consume compiled values; do not reparse or rediscover live maturities. |
| Task 3 | Task 2 runtime propagation -> preparation/observer | Observer receives compiled preparation flags; no mutation-rule fallback. |
| Task 4 | Tasks 1-3 schedule/status -> editor/Workbench | UI projects shared immutable values; it may not reconstruct runtime truth. |
| Task 5 | Bounded prover foundation | Independent of constant-stage code; scheduled after UI to avoid concurrent edits and preserve one-task-at-a-time SDD. |
| Task 6 | Task 5 policy/results -> predicate transforms | Configure all prover construction paths and emit typed observations. |
| Task 7 | Tasks 1 and 4 parser/editor -> config migration | Migrate only after canonical parser and save path are reviewed. |
| Task 8 | Tasks 1-7 -> MASM/system acceptance | Acceptance only; production gaps return to the owning earlier task/fix round. |
| Tasks 1 + 2 | `constant_simplification.py`, execution descriptors | Task 1 owns public compiler; Task 2 owns live expansion. Task 2 must preserve Task 1 API. |
| Tasks 1 + 4 | stage metadata/editor registration | Task 1 defines vocabulary; Task 4 renders it. No duplicate support table in UI. |
| Tasks 1 + 7 | canonical/legacy parsing and bundled JSON | Parser lands first; migration asserts semantic equivalence. |
| Tasks 2 + 3 | pipeline activation, manager state | Task 2 carries schedule; Task 3 consumes preparation settings and removes folding side effect. |
| Tasks 2 + 4 | project runtime and effective schedule | Runtime snapshot is the handoff. Workbench must use object/value equality tests. |
| Tasks 2 + 6 | pipeline hook bridge | Task 2 edits constant bundle; Task 6 edits MBA transform options. Preserve both ordered paths. |
| Tasks 3 + 4 | preparation status models | Task 3 owns state semantics; Task 4 owns presentation only. |
| Tasks 3 + 8 | IDB/global const fixtures | Task 8 exercises existing journal/observer; no parallel persistence mechanism. |
| Tasks 4 + 7 | config editor/save path | Task 4 owns generic control; Task 7 owns canonicalization during migration. |
| Tasks 5 + 6 | Z3 API and predicates | Task 5 retains compatibility wrappers; Task 6 uses result APIs and policy. |
| Tasks 5 + 8 | proof results/fixtures | Task 8 asserts receipts and semantic preservation on abstention. |
| Tasks 6 + 8 | proof observations/system assertions | Task 6 owns event schema/emission; Task 8 consumes it. |
| All tasks | repo architecture and generated graph | No ignores/exceptions; run gates at task-relevant checkpoints and final `graphify update .`. |

## Task status

| Task | Base | Implementer | Spec review | Quality review | Verification | Commit | Status |
|---|---|---|---|---|---|---|---|
| 1 | `a44278899` | `/root/constant_stage_task1` | PASS | PASS | 33 focused + 125 config passed; sg/import-linter passed | `111e5b8c4`, `f0b2088ae` | complete |
| 2 | `f0b2088ae` | `/root/constant_stage_task2` | PASS | PASS | 46 units; 8 activation + 7 state-loading Docker passed; sg/import-linter passed | `d31017d96`, `e8759379c`, `b811ad09c`, `d4051c063` | complete after 3 fix rounds |
| 3 | `d4051c063` | `/root/constant_stage_task3` | PASS | PASS | 35 focused + 289 manager + 11 journal; 12 global/pre-Hex + 8 activation Docker passed; ruff/sg/import-linter passed | `be510fabb`, `fafc35c5f`, `01a6cafc0`, `37eebd18a` | complete after 3 fix rounds |
| 4 | `37eebd18a` | `/root/constant_stage_task4` | PASS | PASS | 98 focused + 88 adjacent + 22 renderer tests passed; ruff/sg/import-linter passed | `d946f4b99`, `6d9ea61c1`, `cf9020f08`, `a7ecc6a76` | complete after 1 fix round |
| 5 | `a7ecc6a76` | `/root/constant_stage_task5_fix5b` | PASS | PASS | 129 Python + 129 Cython + 15 focused resolver + 1 parity + 1 AstProxy + 14 def-search + 2 cumulative probes in both modes; 103 pure; ruff/py_compile/sg/import-linter/diff-check passed | `de9194b1b`, `37ab47636`, `1399cbd50`, `753507859`, `28987e197`, `35e114973`, `a4b5e045c`, `540995e67` | complete after 5 fix rounds |
| 6 | `6446f49f1` | `/root/constant_stage_task6` + `/root/constant_stage_task6_defaults_fix` | pending final re-review | pending final re-review | 152 focused/adjacent units + 18 normal/18 Cython IDA runtime; Ruff/py_compile/sg/import-linter/diff-check passed | `b7cee6071`, `9034ae5ad`, `4b0f03a23` | repair implemented; review pending |
| 7 | pending | pending | pending | pending | pending | pending | pending |
| 8 | pending | pending | pending | pending | pending | pending | pending |

## Controller rulings

- Agents may not spawn subagents.
- No two implementers run concurrently.
- Every IDA test command is launched from `/Users/mahmoud/src/idapro/d810` with `-w constant-simplification-stage-controls`.
- The controller reviews report, diff package, tests, and Git status before advancing.
- Review findings go back through a fix dispatch; the controller does not silently patch around a failed task.

## Task 5 Fix Round 4 ledger

- RED: the new lifetime-safe identity test failed against the raw `id()`
  dictionary; the required Docker pair reported 117 passed and 3 intended
  failures for cached `m_ldc`, contextual pre-construction budgeting, and
  compiled-resolver budget threading.
- Production repair: generic cached-Mop extra-occurrence metadata, strong
  identity/multiplicity tracking, and the backend-neutral `AstNodeBudget`
  threaded through both Python and Cython recursive resolvers.
- Verification: Python and Cython bounded pairs each passed 120 tests;
  resolver parity passed 1 test; AstProxy passed 1 test; pure policy/cache
  checks passed 103 tests; static/architecture gates passed.
- `graphify update .` was attempted once and its watch rebuild was blocked by
  `[Errno 1] Operation not permitted`.
- Atomic code/test commit: `a4b5e045c`.

## Task 5 Fix Round 5b ledger

- RED: contextual gateway/seam tests failed because the production resolver and
  minsn gateway had no `node_budget`; the direct Z3 receipt regression failed
  with observed `1` instead of cumulative `3` after the budget reset.
- Production repair: budget propagation through native/fallback/memory-store
  resolution and Python/Cython recursive paths; bounded minsn routing and
  typed-limit propagation; one continuous budget through direct Z3 preparation.
- Verification: normal and Cython pairs each passed 129 tests; resolver parity,
  AstProxy, and 14 def-search snapshot tests passed; 103 pure tests and all
  Ruff/py_compile/sg/import-linter/diff gates passed.
- `graphify update .` was attempted after the final edits and blocked by
  `[Errno 1] Operation not permitted` during its watch rebuild.

## Task 6 ledger

- RED: the focused parser/catalog run failed `7` tests (`3` explicit policy
  cases, `1` omitted-default case, and `3` catalog cases) before the new
  transform fields existed. The first receipt test collection also failed
  with `ImportError: cannot import name 'Z3PredicateProofObserved'`.
- Implementation: the three generic transforms now expose independent node
  and timeout fields; one shared MBA materializer supplies defaults only to
  selected parameterized transforms; every Z3 prover construction receives the
  rule's frozen policy; conclusive results alone mutate; and typed proof events
  persist through the existing lifecycle model and handler.
- Verification: the focused/adjacent unit command passed `127` tests, and the
  required Docker command passed `13` tests with `118` existing SWIG warnings.
  Ruff, py_compile, `sg scan`, `lint-imports`, and `git diff --check` passed.
- `graphify update .` was attempted after Task 6 edits and its watch rebuild
  was blocked by `[Errno 1] Operation not permitted`.
- Product/test commit: `b7cee6071` (`feat(mba): configure bounded z3 predicates`).

## Task 6 independent-review fix ledger

- RED: the new receipt-contract/default-source regressions failed as expected:
  `2 failed, 10 passed` in the focused unit file and `4 failed, 13 passed,
  118 warnings` in the required Docker runtime.
- Repair: portable core-owned proof enums close the event contract; malformed
  producer results return no receipt and cannot mutate; the diagnostic
  handler performs the enum-to-string conversion; direct configure defaults
  come from `Z3ProofPolicy()` rather than duplicated literals.
- Verification: `140` focused/adjacent units passed; normal and Cython-enabled
  bounded runtime pairs each passed `17` tests with `118` warnings; adjacent
  AstProxy runtime passed `1` test with `122` warnings. Ruff, py_compile,
  `sg`, import-linter, and diff-check passed.
- Product/test fix commit: `9034ae5ad` (`fix(mba): close bounded z3 receipt contract`).
- Task 6 report/progress documentation follows in the separate docs commit.

## Task 6 default-authority repair

- RED: the independent review demonstrated that direct `Z3ProofPolicy()`
  defaults and six generic editor field literals were separate authorities.
  The new regression changes the portable authority and checks direct rules,
  editor fields, pass materialization, and bridge rule options together.
- Repair: `d810.core.z3_proof` owns the frozen, dependency-free
  `Z3ProofPolicyAuthority`; runtime policy validation/defaults and all generic
  editor fields consume it. The mapping of parameterized transform fields now
  has deterministic iteration, and the catalog rebuilds from the current
  schema-backed field provider.
- Verification: local focused/adjacent runtime and unit selection passed 152
  tests; the normal Docker runtime passed 18 tests; the Cython-enabled Docker
  runtime passed 18 tests. Ruff, py_compile, sg, import-linter, and diff-check
  passed. The exact Docker outputs are in the worktree `.tmp` files
  `task6_defaults_authority_normal.txt` and
  `task6_defaults_authority_cython.txt`.
- Product/test commit: `4b0f03a23` (`fix(mba): centralize bounded z3 policy limits`).
- Task 7 and Task 8 were not started; final Task 6 review remains with the
  controller.
