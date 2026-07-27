# Rhad Second GENERATED Operation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

> Execute inline in the existing
> `/Users/mahmoud/src/idapro/d810/.worktrees/lrea-portable-cfg-integration`
> worktree. The active ticket is `lrea-t5gy`; do not close, restart, or replace
> it. Preserve the user-owned untracked
> `tests/system/e2e/test_rhad_generated_microcode_capture.py`.

**Goal:** Publish `route:rhad-direct@0x40A619`, the earliest unproved
`simple_indirect_jump`, with the accepted `rhad:route@0x40A605` through one
FRONTEND_NORMALIZATION FragmentPlan and one existing GENERATED transaction.

**Architecture:** Typed reference evidence selects and describes the two
operations. The pure compiler emits a conditional operation and a direct
transfer rewrite. FragmentPlan admits the imported direct rewrite only when
reference authority, native-body proof, work-scope selection, oracle identity,
and all existing ownership constraints agree. The manager prepares the typed
batch and calls the existing backend/coordinator once.

**Testing rule:** Every production change starts with a focused failing test
that names the broken contract. Observe RED, implement the minimum typed
behavior, then rerun the focused tests before broader gates.

## Task 1: Persist the approved design and full inventory

**Files:**

- Add `docs/superpowers/specs/2026-07-26-rhad-second-generated-operation-design.md`.
- Add `docs/experiments/rhad-a560-indirect-jump-reference-inventory.json`.
- Add this plan.

- [ ] Generate the 228-row inventory from the pinned donor evidence and current
  portable source-plan evidence.
- [ ] Validate its counts, selected row, typed unmet obligations, and SHA-256.
- [ ] Confirm `git diff --check` and commit only documentation/inventory.

Commands:

```bash
python /tmp/rhad_inventory_builder.py
python -m json.tool docs/experiments/rhad-a560-indirect-jump-reference-inventory.json >/dev/null
shasum -a 256 docs/experiments/rhad-a560-indirect-jump-reference-inventory.json
git diff --check
git add docs/superpowers/specs/2026-07-26-rhad-second-generated-operation-design.md \
  docs/superpowers/plans/2026-07-26-rhad-second-generated-operation.md \
  docs/experiments/rhad-a560-indirect-jump-reference-inventory.json
git commit -m "docs(rhad): specify second generated operation"
```

Expected inventory digest:
`473c93f9ee089272c049259ba6a61901983fa23e685ab87cbcfb44f919b984bf`.

## Task 2: Admit a reference-owned frontend direct rewrite

**Files:**

- Modify `tests/unit/transforms/test_fragment_plan.py`.
- Modify `src/d810/transforms/fragment_plan.py`.

- [ ] Add a positive test constructing a FRONTEND_NORMALIZATION imported direct
  rewrite with matching `FragmentReferenceRouteAuthority`, body `proof_ids`,
  work-scope `selected_obligation_ids`, and `RouteOracleRun`.
- [ ] Add one negative parameterized test for missing authority, missing body
  proof, missing selected obligation, foreign run, and target/owner mismatch.
- [ ] Run the focused test and record the expected RED canonical-only rejection.
- [ ] Implement a named typed predicate for canonical proof or the approved
  reference-owned frontend proof; preserve all existing identity checks.
- [ ] Rerun FragmentPlan tests and commit this contract alone.

Commands:

```bash
PYTHONPATH=src pyenv exec pytest \
  tests/unit/transforms/test_fragment_plan.py -k 'frontend and direct' -vv --tb=short
PYTHONPATH=src pyenv exec pytest tests/unit/transforms/test_fragment_plan.py -q
git diff --check
git add src/d810/transforms/fragment_plan.py tests/unit/transforms/test_fragment_plan.py
git commit -m "feat(fragment): admit referenced frontend direct routes"
```

## Task 3: Compile the typed `RhadDirectRoute`

**Files:**

- Modify `tests/unit/transforms/test_rhad_reference_compiler.py`.
- Modify `src/d810/transforms/rhad_reference_compiler.py`.

- [ ] Expand the fixture base plan to the fourteen-block union and add body
  proof/work-scope facts for both operation ids.
- [ ] Add a positive test asserting the exact `0x40A619 -> 0x40A61B` direct edge,
  `FragmentDirectTransferRewrite`, owner identity, delivery region, reference
  payload, per-operation closure, and final batch boundaries.
- [ ] Add negative tests for non-imported source, missing body proof, source
  corridor escape, target outside closure, closure-union mismatch, boundary
  derivation mismatch, unsupported operation type, and dependency order.
- [ ] Run RED; the expected break is absent `RhadDirectRoute` vocabulary.
- [ ] Add the immutable direct-route type and an explicit compiler dispatcher.
- [ ] Validate each operation closure as a subset, exact closure union as the
  base imported set, and final boundaries after internalized exits.
- [ ] Emit one direct edge, `FragmentDirectTransferRewrite`, and direct
  `ReferenceRouteRewrite`; emit no flag corridor for the direct route.
- [ ] Rerun compiler plus FragmentPlan tests and commit compiler vocabulary and
  semantics separately from runtime changes.

Commands:

```bash
PYTHONPATH=src pyenv exec pytest \
  tests/unit/transforms/test_rhad_reference_compiler.py -vv --tb=short
PYTHONPATH=src pyenv exec pytest \
  tests/unit/transforms/test_rhad_reference_compiler.py \
  tests/unit/transforms/test_fragment_plan.py -q
git diff --check
git add src/d810/transforms/rhad_reference_compiler.py \
  tests/unit/transforms/test_rhad_reference_compiler.py
git commit -m "feat(rhad): compile direct reference routes"
```

## Task 4: Make batch evidence and preparation data-driven

**Files:**

- Modify `tests/unit/hexrays/preanalysis/test_rhad_generated_checksum.py`.
- Modify focused manager/runtime preparation tests discovered by
  `rg -n 'prepare_a560_generated_checksum_templates|build_a560_generated_checksum_plan' tests`.
- Modify `src/d810/manager/rhad_generated_checksum.py`.
- Modify manager registration only if RED proves dispatch still depends on an
  imperative sample-EA guard.

- [ ] Add typed batch-evidence tests proving two ordered operations, three
  preparation roots, fourteen imported blocks, and four final exits.
- [ ] Add rejection tests for a native key absent from the typed registry and
  incomplete target-root preparation.
- [ ] Add an AST-level test that production batch selection and compilation do
  not branch on literal `0x40A560`, `0x40A605`, or `0x40A619`.
- [ ] Run RED; record the first hard-coded production assumption.
- [ ] Introduce a required typed batch evidence object/registry and derive base
  plan blocks, bodies, operation instances, closures, target roots, and
  diagnostics from it.
- [ ] Expand native-body ranges and proofs for the selected direct source and
  its five-block closure.
- [ ] Keep one producer, one backend apply, one GENERATED profile, and no direct
  deferred-modifier access.
- [ ] Rerun preparation/producer and compiler suites; commit producer
  genericity independently.

Commands:

```bash
PYTHONPATH=src:tests pyenv exec pytest \
  tests/unit/hexrays/preanalysis/test_rhad_generated_checksum.py \
  tests/system/runtime/test_manager_native_preanalysis.py -vv --tb=short
PYTHONPATH=src:tests pyenv exec pytest \
  tests/unit/hexrays/preanalysis/test_rhad_generated_checksum.py \
  tests/unit/transforms/test_rhad_reference_compiler.py \
  tests/system/runtime/test_manager_native_preanalysis.py -q
git diff --check
git add src/d810/manager/rhad_generated_checksum.py \
  tests/unit/hexrays/preanalysis/test_rhad_generated_checksum.py
git commit -m "refactor(rhad): drive generated batches from typed evidence"
```

## Task 5: Prove one combined GENERATED transaction and exact canaries

**Files:**

- Modify `tests/system/e2e/test_rhad_generated_checksum_publication.py`.
- Modify focused GENERATED transaction/runtime tests only where the new batch
  reveals a typed missing contract.
- Modify `src/d810/manager/rhad_generated_checksum.py` diagnostic observers.

- [ ] Add E2E assertions that compilation persists both operation identities
  and their reference payloads, publication occurs at actual MMAT_GENERATED,
  and one receipt covers the complete batch.
- [ ] Reconstruct every created block from planned identities and creation
  witnesses.
- [ ] Assert the accepted conditional canary remains exact.
- [ ] Assert the `0x40A619` indirect transfer is absent and targets `0x40A61B`
  while its source exists; after legitimate source removal, assert no residual
  indirect transfer and preserved reachable downstream semantics.
- [ ] Assert GENERATED, PREOPT, LOCOPT/authoritative CFG, CALLS, and CMAT_FINAL;
  CALLS must have no planning, mutation, or redo events.
- [ ] Assert no poison, rollback, redo, alternate mutation path, or numeric
  INTERR.
- [ ] Run RED on the new checksum before changing diagnostics.
- [ ] Generalize the observer over typed operation evidence while preserving
  the accepted canary literals in tests.
- [ ] Rerun the focused publication and transaction suites and commit
  diagnostics independently.

Commands:

```bash
PYTHONPATH=src:tests pyenv exec pytest \
  tests/system/e2e/test_rhad_generated_checksum_publication.py -vv --tb=short
PYTHONPATH=src:tests pyenv exec pytest \
  tests/system/runtime/hexrays/test_generated_fragment_transaction.py \
  tests/system/runtime/test_semantic_fragment_backend.py \
  tests/unit/hexrays/mutation/test_fragment_publication_gateway.py -q
git diff --check
git add src/d810/manager/rhad_generated_checksum.py \
  tests/system/e2e/test_rhad_generated_checksum_publication.py
git commit -m "test(rhad): prove two generated operation shapes"
```

## Task 6: Run the complete acceptance matrix

- [ ] Rerun the accepted `0x40A605` checksum invocation unchanged.
- [ ] Run the new two-operation checksum and query the resulting SQLite DB for
  plan identity, one committed receipt, all maturity observations, CMAT_FINAL,
  and absence of failure events.
- [ ] Run focused compiler and GENERATED publication suites.
- [ ] Run transaction/runtime suites.
- [ ] Run the exact named protected-family matrix recorded in `lrea-t5gy` and
  the strict 41-row parity gate.
- [ ] Read applicable YAML rules for any ast-grep finding, then run ast-grep.
- [ ] Read `.importlinter`, then run every import contract from this worktree.
- [ ] Confirm the input binary SHA-256 remains unchanged.
- [ ] Run `graphify update .` and inspect `git status --short` so only intended
  files plus the preserved user-owned capture test remain.
- [ ] Add a final `tk add-note lrea-t5gy` with commit ids, DB path, exact gates,
  SHA, first unmet next-shape obligation, and honest known non-acceptance
  evidence. Do not close the ticket.
- [ ] Run `simba codex-finalize` and make the final logical verification commit
  only if tracked diagnostic documentation changed.

Commands:

```bash
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
shasum -a 256 tests/fixtures/rhad/*.bin
graphify update .
git diff --check
git status --short
simba codex-finalize
```

Do not chase the two known broad dispatcher-pattern DSL failures unless one
blocks the selected operation or changes a protected-family result.
