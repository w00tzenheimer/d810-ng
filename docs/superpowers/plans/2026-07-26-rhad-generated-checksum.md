# Rhad GENERATED Checksum Implementation Plan

> Execute this plan on the existing
> `/Users/mahmoud/src/idapro/d810/.worktrees/lrea-portable-cfg-integration`
> branch. The active ticket is `lrea-t5gy`. Do not create a replacement ticket,
> merge a donor, or cherry-pick donor commits.

**Goal:** Compile and publish the reference `cmovl`-selected transfer at
`0x40A5F0-0x40A605` during actual `MMAT_GENERATED` through the current shared
transaction coordinator, then prove route-level C6 and ctree completion without
redo, poison, INTERR, or binary mutation.

**Architecture:** A pure `d810.transforms` compiler consumes pinned serial-free
reference evidence and emits the current `FragmentPlan`. A manager-owned
producer runs once at the first top-level `MMAT_GENERATED` optinsn callback. It
uses `HexRaysMutationBackend.apply`, the existing `MbaMutationGateway`, current
FragmentPlan-to-PatchPlan lowering, final binding, and `CfgTransactionCoordinator`.
A GENERATED transaction profile validates structure and `mba.verify(True)`
without inventing a CFG; LOCOPT performs the first authoritative graph check.

**Process:** Every production behavior begins with a focused failing test, the
failure is observed and recorded, and only the minimum implementation needed to
make it green is added. Each slice is committed independently.

## Baseline already completed

- Audited target, replay, and historical worktrees.
- Preserved the pre-existing untracked
  `tests/system/e2e/test_rhad_generated_microcode_capture.py` without editing or
  staging it.
- Verified strict parity ledger has 41 guarantees and passes.
- Queried the latest target A560 diagnostic database.
- Queried replay capture and SQLite evidence for exact closure and maturity
  obligations.
- Amended `lrea-t5gy` with `tk add-note`.
- Committed ticket pivot as `1c13fe629 docs(goal): pivot A560 checksum to generated`.

## Slice 1: Pure reference compiler frontend

**Files:**

- Create `src/d810/transforms/rhad_reference_compiler.py`.
- Modify `src/d810/transforms/fragment_plan.py` only to admit a fully
  reference-owned frontend-normalization route; do not weaken reference input,
  owner, target, or oracle-run validation.
- Create `src/d810/conf/semantic_route_oracles/rhad_reference_operation_inventory.json`.
- Create `tests/unit/transforms/test_rhad_reference_compiler.py`.
- Modify `docs/experiments/rhad-generated-reference-operation-parity.md` only
  if the current worktree lacks the checksum inventory table; do not import the
  replay's claims wholesale.

### 1.1 Write the compiler contract tests first

Each test uses hand-derived literal evidence and checks one break:

- wrong signed predicate orientation swaps the two semantic targets;
- missing comparison constant loses reference evidence;
- missing source terminal fails to replace the unresolved transfer;
- missing/duplicate imported range breaks exact closure;
- missing boundary exit breaks total publication scope;
- unsupported reference shape publishes when it must abstain;
- stale evidence generation is accepted;
- two operations with invalid reference-phase dependency order are accepted.

The A560 happy-path test must assert literal facts:

```python
assert operation.operation_id == "rhad:route@0x40A605"
assert operation.predicate_anchor_ea == 0x40A5F6
assert operation.edge(CONDITIONAL_TAKEN).target_block_id == "native@0x40B6C0"
assert operation.edge(CONDITIONAL_FALLTHROUGH).target_block_id == "native@0x40A607"
assert plan.atomic_group_id == "rhad-generated-reference@0x40A560:g1"
assert tuple(block.semantic_anchor_ea for block in imported) == (
    0x40A607, 0x40A615, 0x40A619, 0x40A680, 0x40A68A,
    0x40B6C0, 0x40B6CA, 0x40B6D0, 0x40B6D4,
)
assert boundary_exit_eas == (0x40A61B, 0x40A68C, 0x40B790)
```

Run RED:

```bash
PYTHONPATH=src pyenv exec pytest \
  tests/unit/transforms/test_rhad_reference_compiler.py -vv --tb=short
```

Expected initial failure: module or compiler contract does not exist.

### 1.2 Implement the minimum pure vocabulary and compiler

Define immutable portable evidence for:

- reference phase and operation category;
- native block interval/exact instruction identity;
- conditional route source, corridor, comparison, signed predicate, targets,
  imported closure, boundary exits, provenance, and dependencies;
- explicit unsupported-shape identities.

Compile directly into current:

- `FragmentBlock` and `FragmentNativeBody`;
- `FragmentComputedBranchNormalization` and conditional-select envelope;
- `FragmentFlagCorridor`;
- `FragmentOperation` and semantic edges;
- `FragmentReferenceRouteAuthority` / `ReferenceRouteRewrite`;
- one `FragmentWorkItemScope` and atomic group.

Do not import live or high-layer modules. Do not duplicate facts already modeled
by current plan types.

### 1.3 Verify and commit

```bash
PYTHONPATH=src pyenv exec pytest \
  tests/unit/transforms/test_rhad_reference_compiler.py \
  tests/unit/transforms/test_fragment_plan.py -q
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
git diff --check
git add \
  src/d810/transforms/rhad_reference_compiler.py \
  src/d810/transforms/fragment_plan.py \
  src/d810/conf/semantic_route_oracles/rhad_reference_operation_inventory.json \
  tests/unit/transforms/test_rhad_reference_compiler.py
git commit -m "feat(rhad): compile generated checksum reference route"
```

## Slice 2: Actual GENERATED lifecycle seam

**Files:**

- Modify `src/d810/core/decompilation_session.py`.
- Modify `src/d810/manager/decompilation_lifecycle.py`.
- Modify `src/d810/hexrays/hooks/optinsn_adapter.py`.
- Modify `tests/unit/manager/test_decompilation_lifecycle.py`.
- Create `tests/system/runtime/hexrays/test_generated_ready_seam.py`.

### 2.1 Write RED event/guard tests

Name and cover these breaks:

- event is emitted while MBA maturity is `MMAT_ZERO`;
- event is skipped at actual `MMAT_GENERATED`;
- event fires more than once in one MBA generation;
- a new MBA generation inherits the old emitted guard;
- native-preanalysis recursion publishes into its detached snippet;
- event lacks current identity index, gateway, or materializer;
- committed GENERATED modification does not make optinsn return true.

The test must exercise `log_info_on_input` with a realistic complete fake MBA
shape, not merely assert a listener mock was called.

Run RED:

```bash
PYTHONPATH=src:tests pyenv exec pytest \
  tests/unit/manager/test_decompilation_lifecycle.py \
  tests/system/runtime/hexrays/test_generated_ready_seam.py \
  -vv --tb=short
```

### 2.2 Add the manager-owned seam

- Add `DecompilationEvent.HEXRAYS_GENERATED_READY`.
- Add once-per-current-MBA lifecycle state and reset it in
  `begin_current_mba_generation`.
- Add `_emit_top_level_generated_ready` adjacent to the PREOPT seam.
- Build the graph-free index, current gateway, and native-body materializer
  through lifecycle factories.
- Emit through the injected event bus; do not import Rhad code in the hook.
- Propagate `microcode_modified` as the optinsn return value.

Update the current identity-index builder so maturity `MMAT_GENERATED` never
calls `build_graph()`.

### 2.3 Verify and commit

```bash
PYTHONPATH=src:tests pyenv exec pytest \
  tests/unit/manager/test_decompilation_lifecycle.py \
  tests/system/runtime/hexrays/test_generated_ready_seam.py \
  tests/system/runtime/test_manager_native_preanalysis.py -q
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
git diff --check
git add \
  src/d810/core/decompilation_session.py \
  src/d810/manager/decompilation_lifecycle.py \
  src/d810/hexrays/hooks/optinsn_adapter.py \
  tests/unit/manager/test_decompilation_lifecycle.py \
  tests/system/runtime/hexrays/test_generated_ready_seam.py
git commit -m "feat(hexrays): emit actual generated maturity seam"
```

## Slice 3: Graph-free GENERATED transaction profile

**Files:**

- Modify `src/d810/backends/hexrays/mutation/backend.py`.
- Modify `src/d810/hexrays/mutation/semantic_fragment_publication.py`.
- Modify `src/d810/hexrays/mutation/semantic_fragment_backend.py` only if a
  missing graph-neutral validation port is proven by RED.
- Modify `src/d810/hexrays/mutation/mba_mutation_events.py` only if the existing
  receipt lacks a required maturity/profile fact.
- Create `tests/system/runtime/hexrays/test_generated_fragment_transaction.py`.
- Extend focused existing semantic-fragment tests instead of duplicating large
  fake MBA infrastructure where practical.

### 3.1 Write RED transaction-profile tests

Name and cover these breaks:

- GENERATED apply calls translator `lift` before or after publication;
- GENERATED preflight calls `build_graph`;
- incomplete source/target/boundary binding writes live state;
- plan-local staged structure diverges from immutable preflight;
- any created block lacks a creation witness;
- one of 13 required semantic effects is not receipted;
- backend verification is skipped;
- expected pre-write rejection poisons the generation;
- post-first-write failure attempts rollback or continues the MBA;
- post-first-write failure does not record first obligation/INTERR and poison;
- PREOPT transaction behavior changes accidentally.

Use the real `CfgTransactionCoordinator`, `MbaMutationGateway`, and backend
participant. Fake only the external IDA object boundary already faked by the
existing runtime test utilities.

Run RED:

```bash
PYTHONPATH=src:tests pyenv exec pytest \
  tests/system/runtime/hexrays/test_generated_fragment_transaction.py \
  tests/unit/backends/hexrays/test_mutation_backend.py \
  tests/unit/hexrays/mutation/test_fragment_publication_gateway.py \
  -vv --tb=short
```

### 3.2 Implement an explicit transaction profile

- Add a typed publication profile/stage value; do not infer it from empty
  edges.
- Thread it through `HexRaysMutationBackend.apply` into the existing semantic
  transaction participant/lifecycle.
- Reuse current immutable projection, final binding, FragmentPlan-to-PatchPlan
  lowering, shared coordinator, gateway, and receipt.
- At GENERATED, replace full live-CFG observations with exact instruction,
  operand, native-body, boundary, effect, and binding observations.
- Keep staged blocks graph-neutral and do not construct use-def lists.
- Call backend `mba.verify(True)` exactly once before commit.
- Return committed transaction authority without translator re-lift at
  GENERATED. Preserve the existing return behavior for other profiles.
- Reuse current post-write poison path. Do not add GENERATED rollback.

### 3.3 Verify and commit

```bash
PYTHONPATH=src:tests pyenv exec pytest \
  tests/system/runtime/hexrays/test_generated_fragment_transaction.py \
  tests/unit/backends/hexrays/test_mutation_backend.py \
  tests/unit/hexrays/mutation/test_fragment_publication_gateway.py \
  tests/system/runtime/test_semantic_fragment_backend.py -q
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
git diff --check
git add \
  src/d810/backends/hexrays/mutation/backend.py \
  src/d810/hexrays/mutation/semantic_fragment_publication.py \
  src/d810/hexrays/mutation/semantic_fragment_backend.py \
  src/d810/hexrays/mutation/mba_mutation_events.py \
  tests/system/runtime/hexrays/test_generated_fragment_transaction.py
git commit -m "feat(hexrays): transact fragments before cfg construction"
```

Stage only files actually changed; do not stage unchanged optional files.

## Slice 4: Exact A560 GENERATED producer

**Files:**

- Create `src/d810/manager/rhad_generated_reference.py`.
- Modify `src/d810/manager/manager.py`.
- Modify manager/session evidence authority only where needed to own the
  immutable ledger; do not store live blocks or detached MBAs.
- Create `tests/system/runtime/test_manager_rhad_generated_reference.py`.
- Add or modify a pinned checksum evidence JSON under
  `src/d810/conf/semantic_route_oracles/` if Slice 1 inventory does not carry
  instance evidence.

### 4.1 Write RED producer tests

Name and cover these breaks:

- foreign function/native key selects the A560 checksum;
- stale evidence generation publishes;
- producer bypasses `HexRaysMutationBackend.apply`;
- producer constructs or invokes `DeferredGraphModifier`;
- one plan becomes more than one transaction;
- compiled plan omits predicate, either arm, terminal rewrite, import, or exit;
- committed receipt is not attached to session semantic ownership;
- `CfgGenerationPoisoned` is swallowed;
- clean evidence rejection becomes a mutation/redo request.

The positive test asserts one backend apply, one committed receipt, 19 deferred
operations, 13 effects, nine creation witnesses, and no alternate gateway.

Run RED:

```bash
PYTHONPATH=src:tests pyenv exec pytest \
  tests/system/runtime/test_manager_rhad_generated_reference.py \
  -vv --tb=short
```

### 4.2 Implement the thin producer

- Load/prepare pinned evidence at the manager composition boundary.
- Compile with the pure compiler.
- Register exactly one manager listener for `HEXRAYS_GENERATED_READY`.
- Construct `HexRaysMutationBackend` with event-provided current gateway and
  native-body materializer.
- Call `apply(..., publication_profile=GENERATED)` once.
- Read current receipt/binding from the backend and set
  `decision["microcode_modified"] = True` only after commit.
- Emit portable diagnostics tied to current plan, attempt, and mutation batch.
- Uninstall the listener during manager teardown.

No production code in this slice may edit `mba`, blocks, instructions,
operands, edges, block order, or call `verify` directly.

### 4.3 Add a structural rule only if existing rules leave a real gap

First prove a missed direct-mutation pattern. If a new rule is needed, read its
top comment/message/note/files/ignores as authoritative, add no ignores, and
test the rule against good and bad fixtures. Do not create a rule merely to grep
for removed donor names.

### 4.4 Verify and commit

```bash
PYTHONPATH=src:tests pyenv exec pytest \
  tests/system/runtime/test_manager_rhad_generated_reference.py \
  tests/system/runtime/hexrays/test_generated_ready_seam.py \
  tests/system/runtime/hexrays/test_generated_fragment_transaction.py -q
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
git diff --check
git add \
  src/d810/manager/rhad_generated_reference.py \
  src/d810/manager/manager.py \
  src/d810/conf/semantic_route_oracles/ \
  tests/system/runtime/test_manager_rhad_generated_reference.py
git commit -m "feat(rhad): publish a560 checksum at generated"
```

Use explicit file paths when staging; never stage the whole configuration
directory if it contains unrelated changes.

## Slice 5: Maturity and diagnostic acceptance

**Files:**

- Extend `src/d810/manager/rhad_generated_reference.py` or create a separate
  manager-owned observer module if separation materially improves clarity.
- Modify existing portable diagnostic event models only when the generic schema
  cannot represent a required fact.
- Create `tests/system/runtime/test_rhad_generated_maturity_observer.py`.
- Create `tests/system/e2e/test_rhad_generated_checksum.py`.
- Do not edit or stage the pre-existing untracked capture test unless the user
  explicitly transfers ownership.

### 5.1 Write RED maturity tests

Name and cover these breaks:

- PREOPT claims graph authority;
- PREOPT loses either direct target or retains `m_ijmp@0x40A605`;
- LOCOPT is not recorded as first authoritative graph;
- route-level reachability is conflated with whole-function A560 C6;
- CALLS observer runs zero or multiple times;
- CALLS performs Rhad planning/mutation or requests redo;
- ctree failure/INTERR is not persisted;
- poison state or first failed obligation is absent from diagnostics.

Run RED with focused unit/runtime fixtures first.

### 5.2 Implement manager-owned observers

- Register PREOPT, LOCOPT, CALLS, session-finished/ctree observations through
  existing event ports.
- Read only current MBA state needed for the maturity observation in high-layer
  adapters; persist portable event payloads through observability.
- Link every observation to the committed plan/attempt/batch identity.
- At CALLS, observe only. Never invoke compiler, planner, gateway, or backend.
- Record route C6 and function C6 as separate fields.

### 5.3 Verify and commit

```bash
PYTHONPATH=src:tests pyenv exec pytest \
  tests/system/runtime/test_rhad_generated_maturity_observer.py \
  tests/system/e2e/test_rhad_generated_checksum.py -q
git diff --check
git add \
  src/d810/manager/rhad_generated_reference.py \
  tests/system/runtime/test_rhad_generated_maturity_observer.py \
  tests/system/e2e/test_rhad_generated_checksum.py
git commit -m "test(rhad): persist generated checksum maturity proof"
```

## Slice 6: Exact Docker checksum and final gates

### 6.1 Re-run the architecture gate before the expensive canary

```bash
PYTHONPATH=src pyenv exec python \
  tools/scripts/portable_cfg_transaction_parity_gate.py
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
```

Require `Portable CFG transaction parity ledger: PASS` and exactly 41 JSON
guarantees.

### 6.2 Run focused tests and protected-family gates

Run the compiler, lifecycle seam, generated transaction, producer, maturity,
existing semantic-fragment, current transaction, and protected-family suites.
Record passed/failed counts and separate any unrelated pre-existing failure.

### 6.3 Run exact cache-disabled Docker A560 canary

Use the repository's current exact A560 Docker command and runtime image, with:

- plugin/runtime cache disabled;
- a disposable IDB;
- persistent host-mounted capture, log, and diagnostic SQLite paths;
- the focused `test_rhad_generated_checksum.py` selection;
- binary hashing before and after;
- enough timeout for ctree completion.

Do not reuse an APK/binary/IDB mutated by another experiment.

### 6.4 Query SQLite as the acceptance authority

Query and retain evidence for:

- reference evidence and compiled plan identity;
- one transaction attempt and ordered phases;
- immutable preflight and final current-MBA binding;
- 19 plan/deferred items and 13 applied semantic effects;
- nine plan reservations/creation witnesses with EA anchors;
- one committed receipt;
- zero poison events and zero successful-path redo;
- GENERATED absence of `m_ijmp@0x40A605`;
- PREOPT survival of `0x40B6C0` and `0x40A607`;
- LOCOPT as first authoritative graph and route reachability;
- exactly one CALLS observation with no Rhad planning/mutation/redo;
- ctree completion and no numeric INTERR;
- route-level C6 distinct from function-level C6.

Compare each row with replay artifact
`.tmp/lrea-generated-publication-replay/diag/000000000040b6c0_1785044437_1.diag.sqlite3`.

### 6.5 Verify bytes

Require input SHA-256 before and after:

```text
2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c
```

### 6.6 Refresh graph and run final checks

```bash
graphify update .
git diff --check
git status --short
```

Update the parity experiment document with commands, artifact paths, counts,
hashes, highest bounded obligation, and first unmet obligation. State explicitly
that this is route-level checksum integration, not full A560 restoration.

Commit the acceptance record separately:

```bash
git add docs/experiments/rhad-generated-reference-operation-parity.md
git commit -m "docs(rhad): record generated checksum acceptance"
```

## Completion audit

Before claiming success:

1. compare `git diff <pivot-parent>..HEAD` to this design and ticket;
2. confirm no donor merge/cherry-pick or compatibility path exists;
3. search changed production files for direct `DeferredGraphModifier`
   construction outside `HexRaysMutationBackend` and direct live mutation;
4. confirm the untracked user capture test remains untouched unless ownership
   changed explicitly;
5. run `simba codex-finalize`;
6. update `lrea-t5gy` with exact commits, commands, diagnostic DB, Docker
   result, binary hash, route-level C6, function-level status, and first unmet
   reference obligation;
7. do not close the ticket if systematic follow-on work remains in its active
   objective; record this checksum as a completed milestone.
