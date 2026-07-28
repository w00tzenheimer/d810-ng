# Rhad A560 Whole-Function GENERATED Restoration Plan

> **For agentic workers:** Execute this plan inline in the existing worktree;
> do not delegate it because each accepted row mutates the same ordered program
> and acceptance ledger. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Execution:** Continue inline in the existing
> `/Users/mahmoud/src/idapro/d810/.worktrees/lrea-portable-cfg-integration`
> worktree. Track every checkpoint in `lrea-t5gy`; do not restart, replace, or
> close the ticket. Steps use checkbox (`- [ ]`) syntax for restart-safe progress.

**Goal:** Restore the exact whole body of `sub_40A560` from reference evidence
at actual `MMAT_GENERATED`, reach `CMAT_FINAL`, and prove exact C6 semantics in
one all-or-nothing transaction through the accepted producer and coordinator.

**Architecture:** A deterministic, serial-free Rhad GENERATED manifest owns
every Rhad-compiled operation exactly once. A separate whole-function semantic-
obligation ledger owns every reference effect exactly once, including effects
discharged by native Hex-Rays, existing D810 instruction optimizers, the
existing D810 state-machine unflattener, or a new typed residual contract when
an exact remaining failure proves one necessary. The pure reference compiler
lowers dependency-closed Rhad operations to immutable `FragmentPlan` and current
`PatchPlan` obligations. The accepted PREOPT template preparation, final
GENERATED binding, `MbaMutationGateway`, and shared transaction coordinator
publish the Rhad program. SQLite is the primary proof authority from both
identities through committed receipts, maturity observations, existing-pass
discharge evidence, and `CMAT_FINAL`.

**Tech stack:** Python 3.13, pytest, IDA/Hex-Rays 9.3, SQLite diagnostics,
ast-grep, import-linter, graphify, tk, and the pinned Rhad reference checkout at
commit `21b0d4783703bc4fb6910cfae51d92cd683d2c65`.

## Global Constraints

- Scope is only exact whole-function A560 C6. Do not begin C8B0, CDA0, D200,
  four-function integration, or complete architecture cleanup.
- Preserve the accepted `0x40A605`, `0x40A619`, `0x40A6A4`, and `0x40A77C`
  semantic checksums as permanent regressions, along with the strict 41-row gate.
- Preserve the input SHA-256
  `2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c`.
- Preserve the user-owned untracked
  `tests/system/e2e/test_rhad_generated_microcode_capture.py` unchanged.
- Reuse the current producer, gateway, transaction representation, coordinator,
  and DeferredGraphModifier path. Add no alternate producer or mutation path.
- Production compilation is driven only by typed reference evidence. Exact EAs
  may appear in fixtures and manifest data, never in production dispatch guards.
- No optional compatibility fields, untyped metadata, `mba.build_graph()` at
  GENERATED, CALLS planning/mutation/redo, partial sibling publication, or
  continuation after poison.
- Every unsupported or ambiguous operation rejects before live mutation with a
  typed first failed obligation.
- Preserve reference phase order: indirect-jump reconstruction, constant
  materialization, then dispatcher-state elimination. Dependencies may point
  only within the same or an earlier phase.
- Do not claim whole-function parity from the Rhad GENERATED manifest alone.
  Exact A560 C6 requires exact discharge parity in the separate semantic ledger.
- Existing Hex-Rays and configured D810 passes receive first right of refusal
  for constant materialization and dispatcher elimination. Do not duplicate an
  exactly discharged effect in the Rhad GENERATED producer.
- Use SQLite before log grep. Every block serial in evidence must carry an EA
  anchor. Commit each logical vocabulary, operation-data, runtime, diagnostic,
  regression, and proof slice separately.

## Phase 0: Freeze the accepted authority and inventories

**Files:**

- Modify through tk: `.tickets/lrea-t5gy.md`
- Verify: `docs/experiments/rhad-a560-indirect-jump-reference-inventory.json`
- Verify: `docs/experiments/rhad-a560-indirect-jump-coverage-summary.json`
- Create: `src/d810/conf/semantic_route_oracles/rhad_a560_row16_setcc_table_proof.json`
- Create: `tools/scripts/rhad_investigation/a560_reference_program.py`
- Create: `tests/unit/tools/test_a560_reference_program.py`
- Create: `docs/experiments/rhad-a560-reference-program-manifest.json`
- Create: `docs/experiments/rhad-a560-reference-program-summary.json`

- [x] Audit the target worktree, ticket, pinned reference checkout, graphify
  relationships, accepted commits, fixture hash, and current SQLite authority.
- [x] Select row 17 `rhad:route@0x40A792`; record its evidence and first unmet
  typed scaled-lookup obligation in `lrea-t5gy`.
- [x] Create one canonical, immutable row-16 table-proof artifact and reference
  its content identity from the existing row-16 inventory proof field without
  changing the stable 228-row ledger schema. The artifact must be typed,
  canonicalized deterministically, serial-free, and bind the input SHA-256,
  function `0x40A560`, pinned reference commit, operation ID
  `rhad:route@0x40A77C`, reference order 16, exact native/table evidence, and
  decoded targets. It is required compiler input, not an optional sidecar.
- [x] Write RED tests proving compilation rejects a missing artifact, wrong
  content hash, noncanonical content, wrong fixture/function/reference commit,
  wrong operation/order, or row/artifact disagreement before live mutation.
  Carry the artifact content identity into the row-16 compiled operation,
  compiled-plan identity, and aggregate reference-program identity.
- [x] Persist the complete artifact and its content identity in SQLite compiled
  and published lifecycle diagnostics, and assert diagnostic reconstruction
  matches the checked-in artifact exactly.
- [ ] Make the checked-in 228-row indirect inventory reproducible from the
  pinned reference and unchanged binary. Assert exact reference order, unique
  operation IDs/transfers, source/transfer EAs, predicate producers, targets,
  corridors, imported closure, boundary exits, compiler vocabulary, and proof
  state.
- [ ] Inventory constant-materialization operations in reference order from
  `deob_consts.py`, including opcode/width/address/value/dependencies and native
  ownership. Inventory dispatcher-state operations from `deob_cflow.py`,
  including simple, cmov, prior-branch, and stack-memory-derived predicates.
- [ ] Emit one deterministic manifest with literal phase counts and a content
  hash that includes every required proof-artifact identity; fail generation if
  source/reference/hash/order/closure/artifact authority differs.
- [x] Persist a fresh accepted four-checksum SQLite database under a stable
  `.tmp/logs/d810_logs` path before row-17 publication. Assert its 55/55 receipt,
  seven matched route comparisons, complete witnesses, no poison/rollback/redo,
  maturity through CALLS, and `CMAT_FINAL`.
- [ ] Validate JSON, run the manifest unit test and `git diff --check`, then
  commit the reproducible inventory/manifest tool separately.

## Phase 1: Complete all 228 indirect-jump operations in reference order

### Task 1.1: Typed row-17 scaled-lookup vocabulary

**Files:**

- Modify: `tests/unit/transforms/test_fragment_plan.py`
- Modify: `tests/unit/transforms/test_rhad_reference_compiler.py`
- Modify: `src/d810/transforms/fragment_plan.py`
- Modify: `src/d810/transforms/rhad_reference_compiler.py`

- [x] Write RED tests for a discriminated `explicit_shift` versus
  `scaled_lookup` index-scaling contract. Reject mismatched anchor order, scale,
  stride, index width, entry address, raw value, additive decode, target
  orientation, closure, proof selection, or dependency order.
- [x] Model the two scaling realizations as immutable typed alternatives; do not
  retain optional `shift_ea`/`shift_bits` compatibility fields.
- [x] Compile row 17 literals: zero `0x40A77E`, compare `0x40A780`, `setge`
  `0x40A786`, scaled lookup `0x40A789` at `0x48B4F8` stride 8, decode
  `0x40A790`, transfer `0x40A792`, false target `0x40A794`, true target
  `0x40AEE6`, and boundary exit `0x40A5F0`.
- [x] Run FragmentPlan/compiler tests GREEN and commit vocabulary separately.

### Task 1.2: Row-17 prepared realization and publication

**Files:**

- Modify: `tests/system/runtime/hexrays/test_detached_snippet_import.py`
- Modify only if RED requires: `src/d810/hexrays/mutation/detached_handler_island.py`
- Modify only if RED requires: `src/d810/hexrays/mutation/semantic_fragment_backend.py`
- Modify: `tests/unit/hexrays/preanalysis/test_rhad_generated_checksum.py`
- Modify: `src/d810/manager/rhad_generated_checksum.py`
- Modify: `tests/system/e2e/test_rhad_generated_checksum_publication.py`

- [x] Capture the actual prepared row-17 microinstruction shape and write a RED
  immutable-preflight test for scaled-address lookup, exact origins, signed
  predicate orientation, targets, and false-target adjacency.
- [x] Implement the minimum typed preflight/realization branch without changing
  producer, coordinator, transaction, gateway, or CALLS behavior.
- [x] Extend typed batch data with row 17 and its two dependency-closed imported
  closures; remove `0x40A792` from unresolved transfers and derive exits.
- [x] Write exact SQLite assertions for persisted reference/plan identity, one
  complete receipt, creation witnesses, transfer absence, target survival,
  legitimate topology retirement, no residual indirect transfer, no poison,
  rollback, redo, or INTERR, and `CMAT_FINAL`.
- [x] Run the accepted four-checksum regression and new row-17 checksum; commit
  operation data, runtime support, diagnostics, and regression proof separately.

### Task 1.3: Data-first expansion through row 228

**Files:**

- Modify: `src/d810/manager/rhad_generated_checksum.py`
- Modify: `tests/unit/hexrays/preanalysis/test_rhad_generated_checksum.py`
- Modify as typed gaps require: compiler/FragmentPlan/runtime files above
- Modify: `tests/system/e2e/test_rhad_generated_checksum_publication.py`
- Modify: `docs/experiments/rhad-a560-indirect-jump-coverage-summary.json`

- [x] Preserve the accepted prefix through row 103: 99/228 compiled and
  published operations, aggregate identity
  `sha256:9febc67b5c58404355f1ecf929ffcdf15a8fc040c39825cb9b49b949d1133db2`,
  accepted DB
  `.tmp/logs/000000000040a560_accepted_271_row103_direct.diag.sqlite3`, and
  permanent `0x40A605` regression.
- [ ] Compile row 104 `rhad:route@0x40B519` as the next data-only
  `RhadDirectRoute`: source `0x40A936`, owner `0x40B50D`, transfer `0x40B519`,
  target `0x40A607`, exact nine-instruction split corridor, five-block imported
  closure, exits `0x40A61B`/`0x40A68C`, and dependency row 103. First prove its
  complete corridor is owned by the already accepted native body rooted at
  `0x40A903`; add no new producer, coordinator, gateway, transaction, template,
  or import path unless RED evidence proves a typed contract is missing.
- [ ] Apply each proved shape data-first to consecutive reference rows, never
  skipping an unmet dependency. At every distinct realization subshape, stop,
  write a focused RED contract test, add only the missing typed discriminator,
  and prove pre-live rejection for malformed evidence.
- [ ] After each dependency-closed batch, assert the compiled order equals the
  manifest prefix, all source transfers are removed, imported closure/exits are
  exact, and one receipt/witness set reconstructs all creations.
- [ ] Keep row-level progress and first unmet obligation current in `lrea-t5gy`.
- [ ] Finish only when all 228 operations are compiled and published and the
  indirect-transfer postcondition is zero at authoritative CFG maturity.
- [ ] Commit each distinct vocabulary slice separately from bulk operation data
  and its diagnostic receipt.

## Phase 2: Constant-materialization discharge

**Files:**

- Create: deterministic constant-obligation inventory and semantic-ledger data
- Modify only if an exact residual failure requires it:
  `src/d810/transforms/fragment_plan.py`
- Modify only if an exact residual failure requires it:
  `src/d810/transforms/rhad_reference_compiler.py`
- Modify only if an exact residual failure requires it:
  `src/d810/manager/rhad_generated_checksum.py`
- Modify focused unit/runtime/E2E tests
- Modify: `docs/experiments/rhad-a560-reference-program-summary.json`

- [ ] Inventory every reference `mov`, `movzx`, `add`, `sub`, `sbb`, and `xor`
  constant operation in pinned reference order. Persist the instruction and
  operand path, source-memory identity, source/result widths, extension or
  truncation, immediate value, carry input, flag equivalence, dependencies, and
  exact semantic oracle.
- [ ] Run a cache-disabled integrated A560 canary with normal configured
  instruction optimization rules. Record whether native Hex-Rays or an existing
  D810 constant/subtree-folding pass discharges each obligation, with before and
  after semantic identities and the maturity of discharge.
- [ ] Mark an exactly discharged obligation once in the semantic ledger and do
  not add it to the Rhad GENERATED manifest. Reject duplicate responsibility.
- [ ] For each remaining exact failure, record the typed first failed
  obligation, prove configuration/ordering is not the cause, then use TDD to add
  the smallest typed residual contract with strict mismatch rejection and proof
  through its legitimately owned maturity and `CMAT_FINAL`.
- [ ] Finish only when reference/discharged counts match exactly, no obligation
  is unsupported, and no effect has duplicate realizations. Commit inventory,
  existing-pass evidence, residual vocabulary/runtime, and proof separately.

## Phase 3: Dispatcher-elimination discharge

**Files:**

- Create: deterministic dispatcher-obligation inventory and semantic-ledger data
- Modify only if an exact residual failure requires it:
  `src/d810/transforms/fragment_plan.py`
- Modify only if an exact residual failure requires it:
  `src/d810/transforms/rhad_reference_compiler.py`
- Modify only if an exact residual failure requires it:
  `src/d810/manager/rhad_generated_checksum.py`
- Modify focused unit/runtime/E2E tests
- Modify: `docs/experiments/rhad-a560-reference-program-summary.json`

- [ ] Inventory every immediate, cmov-selected, earlier-conditional, and memory-
  derived state route plus dispatcher entry/egress, cleanup, terminal, and return
  obligation in pinned reference order. Persist state-storage identity/value/
  width, predicate orientation, semantic targets, dependencies, selected family,
  recovered transitions, maturity observations, and exact semantic oracle.
- [ ] Run a separate integrated A560 canary with normal configured flow rules;
  keep the isolated GENERATED checksum on `NoFlowRules`. Test the existing state-
  machine unflattener before adding Rhad behavior.
- [ ] Mark each exactly discharged existing-pass effect once in the semantic
  ledger. Preserve profile scope, fragment-atomic non-state severance vetoes,
  expected state-slot plumbing, and the existing coordinator boundaries.
- [ ] Add a typed residual contract only after an exact remaining failure proves
  it necessary. Do not chase the two known broader dispatcher DSL failures
  unless one blocks a required A560 obligation or protected-family gate.
- [ ] Finish only with exact reference/discharged parity, no residual reference
  dispatcher loop or `JUMPOUT`, no omitted cleanup/terminal/return effect, and no
  duplicate realization. Commit inventory, existing-pass evidence, residual
  vocabulary/runtime, and proof separately.

## Phase 4: Full-program all-or-nothing acceptance

**Files:**

- Modify: `src/d810/transforms/rhad_reference_compiler.py`
- Modify: `src/d810/manager/rhad_generated_checksum.py`
- Modify: `src/d810/hexrays/mutation/semantic_fragment_publication.py` only if a
  focused RED proves a missing typed all-program contract
- Modify focused compiler/transaction/runtime/E2E suites

- [ ] Compile the complete deterministic manifest to dependency-closed
  FragmentPlans and one PatchPlan before live mutation. Assert no unresolved
  dependency, overlapping owner, ambiguous stable identity, missing closure,
  boundary leak, unsupported shape, or partial phase prefix.
- [ ] Immutable-preflight every operation and final binding. Any rejection must
  leave the MBA untouched and persist the exact first failed obligation.
- [ ] Publish once at actual `MMAT_GENERATED` through the sole shared
  coordinator. One committed receipt must cover the complete program and every
  creation witness; partial success is forbidden.
- [ ] At PREOPT/authoritative-CFG/CALLS prove all indirect transfers absent,
  required semantics reachable for as long as source topology exists, legitimate
  retirement handled, dispatcher eliminated, no residual direct/indirect escape,
  and CALLS observation-only.
- [ ] Prove the whole-function semantic-obligation ledger contains every
  reference effect exactly once and names its responsible Rhad operation, native
  Hex-Rays behavior, existing D810 pass, or typed residual contract. Persist both
  the semantic-ledger identity and Rhad GENERATED program identity in SQLite.
- [ ] Prove exact A560 side effects, return behavior, and control-flow canaries
  against the native/reference oracle, then assert `ctree_captured` at
  `CMAT_FINAL` with no poison, rollback, redo, alternate path, or numeric INTERR.

## Phase 5: Final gates and handoff

- [ ] Run focused FragmentPlan/compiler/producer/GENERATED-publication suites.
- [ ] Run transaction/runtime suites and the named Hodur, Sub7FFD, Tigress, and
  Approov protected-family matrix.
- [ ] Run the strict 41-row gate. Do not chase the two known broader
  dispatcher-pattern DSL failures unless one directly blocks A560 or the matrix.
- [ ] Run from this worktree:
  `sg scan --config sgconfig.yml --report-style short` and
  `PYTHONPATH=src lint-imports --config .importlinter`.
- [ ] Recheck fixture SHA-256, run `graphify update .`, inspect graph/diff/status,
  and prove the untracked capture test remains byte-for-byte untouched.
- [ ] Commit compiler vocabulary, operation semantics, diagnostics, regression
  repairs, and final proof record as separate logical commits.
- [ ] Amend `lrea-t5gy` with the exact manifest hash/counts, stable SQLite path,
  receipt/witness counts, maturity sequence, canary results, gate results, input
  hash, and commit IDs. Keep the ticket open for broader work.
- [ ] Run `simba codex-finalize`. Mark the Codex goal complete only when exact
  whole-function A560 C6 is proved; otherwise continue from the first unmet
  typed obligation.
