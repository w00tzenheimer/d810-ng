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
| 6 | `6446f49f1` | `/root/constant_stage_task6` + `/root/constant_stage_task6_defaults_fix` | PASS | PASS | 152 focused/adjacent units + 18 normal/18 Cython IDA runtime; final controller rerun 134 units; Ruff/py_compile/sg/import-linter/diff-check passed | `b7cee6071`, `9034ae5ad`, `4b0f03a23`, `7d40d1f8f` | complete after 3 review fix rounds |
| 7 | `63d4eb393` | `/root/constant_stage_task7_retry` | PASS | PASS | 150 focused; 68 JSON/171 pipeline configs; adjacent 235 pass with one base-reproduced failure; controller reran 150; ruff/py_compile/sg/import-linter/diff-check passed | `446b1d6b9`, `ea064b829`, `7fc778080` | complete |
| 8 | `84db1bcd4` | `/root/constant_stage_task8_retry` | PASS | PASS | 11 compiled E2E + 217 focused units + 2 native order tests; sg/import-linter/diff-check passed | this commit | acceptance green; provenance fix re-review pending |

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
- Final review cleanup commit: `7d40d1f8f` (`test(z3): clean bounded policy authority regression`); Ruff and the normal 18-case Docker runtime were rerun and passed.
- Final independent review passed the specification. Its sole code-quality
  finding was the unused import removed by `7d40d1f8f`; Ruff and the affected
  normal 18-case runtime suite passed afterward, while the unchanged Cython
  artifact retained its prior 18-pass result.
- The controller independently reran 134 focused units, Ruff, and
  `git diff --check` successfully. Task 6 is accepted; Task 7 and Task 8 were
  not started by the Task 6 workers.

## Task 7 implementation ledger

- Genuine RED was captured against an archived clean `63d4eb393` tree with
  only the new migration test applied: `5 failed`, retained at
  `.tmp/task7-red-before-migration.txt`. The failures covered legacy bundled
  profiles, the two EID profile assertions, external legacy save
  canonicalization, and mixed-input rejection.
- The 13 bundled config-v2 constant entries now use canonical
  `preparation`/`stages` options. Preparation remains disabled for all shipped
  entries because the legacy persist flag was absent; readonly memory policy,
  RVA guard, executable-readonly setting, full stage maturities, and pass gates
  were preserved.
- Runtime parsing canonicalizes accepted legacy constant entries before public
  registry validation. The same compiler performs the projection, so runtime
  behavior is unchanged and mixed canonical/legacy input remains an error.
  Config-v2 draft/load/save paths write the canonical equivalent.
- Verification: 150 focused migration/compiler/editor tests passed; all 68
  JSON files parsed and all 171 pipeline configs built through the project
  parser and operational registry; ruff, py_compile, sg, import-linter, and
  diff-check passed. The adjacent command had 235 passes plus one pre-existing
  Tigress legacy-rule count failure reproduced on base `63d4eb393`.
- Product commit: `ea064b829` (`chore(config): migrate constant stage controls`).
- Independent review added `7fc778080` to strengthen recursive input guards
  and commit a non-empty maturity-gate round-trip assertion. The controller
  inspected that narrow test commit and independently reran the exact 150-test
  focused command, Ruff, and `git diff --check` successfully.
- Final independent verdict: specification PASS and code quality PASS. The
  single adjacent Tigress failure is unchanged and was reproduced on base
  `63d4eb393`; it is not masked or skipped by this work.

## Task 8 runtime rulings

- Ruling: do not add a PREOPT whole-MBA `m_lnot` sweep. A bounded live callback
  probe proved that the ordinary recursive optimizer receives the nested
  `m_lnot`, activates `Z3lnotRuleGeneric`, and invokes it exactly once. The
  proof failed because the pairwise equality prover treats the one-bit flag
  carrier as unconstrained; the existing single-operand
  `prove_always_zero`/`prove_always_nonzero` path owns contextual reaching-def
  expansion. Repair the rule at that existing boundary instead. The cost if
  wrong is a focused lnot regression failure, not a new mutation lifecycle.
- Ruling: the bounded-table fixture must take its index from the function
  argument. Loading the index from global data let `FoldReadonlyDataRule`
  collapse the whole lookup to `0x20` before post-D810 CALLS observation. The
  pointer indirection remains readonly-foldable, while an argument-derived
  index preserves the dynamic `[table + index*8]` access needed to test the
  next natural preparation round.
- Ruling: split the dependent readonly/subtree acceptance oracle. Bounded native
  attempts (`imul`, separate arithmetic, larger MBA/sink, transform-isolated,
  and `mov`/`rol`/`xor`) consistently produced the readonly D810 receipt and
  correct final constant, but Hex-Rays consumed the exposed subtree before a
  second D810 callback. Requiring two D810 mutation receipts would test a
  scheduler race; changing scheduling to manufacture one is outside scope and
  would alter optimizer semantics. The system fixture therefore proves the
  readonly receipt plus final semantic result and exact compiled private order,
  while the existing native instruction-optimizer order regression remains the
  direct D810 ordering oracle. The cost if wrong is weaker evidence about the
  vendor callback interleaving, not weaker evidence about D810's configured
  order or output semantics.

## Task 8a contextual lnot proof ledger

- Live callback probe: nested `m_lnot` was delivered under `m_jcnd`, the exact
  rule was active and invoked once, and pairwise `prove_equal`/`prove_unequal`
  both returned `DISPROVED` for the unresolved one-bit carrier. No sweep or
  lifecycle mutation was justified.
- RED: the focused rule contract captured `16 passed, 4 failed` before the
  single-operand proof change in `.tmp/task8a_lnot_red.txt`.
- Repair: `Z3lnotRuleGeneric` now reuses one contextual, policy-bound prover;
  `prove_always_zero` emits `1`, then `prove_always_nonzero` emits `0`, and all
  inconclusive results remain fail-closed.
- Commit: `4e41e2862` (`fix(z3): resolve contextual lnot predicates`).
- Implementer Docker verification passed all `20` focused runtime tests. The
  controller independently reran the same 20-test Docker file successfully;
  output is `.tmp/root_task8a_lnot_runtime.txt`. The commit diff was reviewed
  for exact context/policy threading, proof order, short-circuiting, and
  fail-closed behavior with no finding.

## Task 8 MASM acceptance ledger

- RED evidence covered absent fixture exports, disabled-stage isolation,
  preparation journal exactness, next-round bounded-table discovery, schedule
  gating, and independently bounded setz/setnz/lnot transforms. No missing
  export, unsupported fixture shape, or low-budget abstention was converted to
  a skip or eligibility-only assertion.
- Implementation adds eight deterministic MASM cases through the existing
  builder, explicit scoped `D810_EXPORT` directives, a canonical config-v2
  canary, and one disposable-IDB E2E contract. The source-basename compatibility
  export has its own RVA so IDA retains all eight case names.
- The final compiled-mode system run passed `11/11` selected tests and retained
  typed mutation/proof receipts: readonly folding, forward propagation, exact
  preparation apply/restore, natural second-round table application, and named
  Z3 setz/setnz/lnot rules. All three one-node policies abstained without
  replacing the original predicate.
- Focused verification passed `218` units, the direct native rule-order oracle
  passed `2` tests, and the tightened scoped-export builder regression passed.
  `sg`, import-linter, and diff-check passed. Artifacts are
  `.tmp/constant_stage_controls_e2e_compiled_v2.txt` and
  `.tmp/constant_stage_controls_rule_order.txt`.
- `graphify update .` was attempted once. Its incremental scanner remained in
  a silent rebuild interval and was interrupted after bounded observation; no
  tracked graph output changed.
- Task 8 acceptance is green. The broader plan remains open while the separate
  provenance repair completes its independent re-review.

### Task 8 independent-review fix round 1

- Explicit `D810_EXPORT` directives are now part of the post-link required
  export set. Verification remains scoped to the PE Export Table, so a symbol
  appearing only in another object table cannot satisfy the check. Behavioral
  builder tests cover present, absent, and out-of-table symbol cases while
  preserving the existing rule that unrelated `PUBLIC` symbols are not
  exported automatically.
- Every mutation family now has a paired negative baseline: disabled readonly
  folding, disabled readonly/subtree composition, maturity-gated forward
  propagation, and one-node-budget predicate proofs all retain the unmodified
  semantic form and have no accepted mutation receipt. Positive receipts pin
  the exact optimizer owner and raw IDA SDK maturity value. The assertions use
  raw metadata deliberately because the legacy human formatter is offset by
  `MMAT_ZERO` in IDA 9.4.
- Pre-Hex preparation captures both rendered states but permits equality when
  native Hex-Rays already folds the value; exact proposal, journal, live type,
  and restoration snapshots remain the mutation authority. The bounded-table
  test likewise names and checks its first/second natural-round renderings and
  exact journal lifecycle.
- Review-fix verification passed `218` focused units, `2` native rule-order
  tests, `7` focused compiled E2E regressions, and the final compiled `11/11`
  E2E suite (`4616` deselected, no skips). Architecture gates, Ruff, shell
  syntax, and diff-check passed. Final artifact:
  `.tmp/constant_stage_controls_e2e_review_fix1_final.txt`.
