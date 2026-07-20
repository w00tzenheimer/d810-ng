# Decompilation Session Foundation Closure Plan

> Execute only in `/Users/mahmoud/src/idapro/d810/.worktrees/decomp-session-foundation` on `diff/decomp-session-foundation`. Commit every coherent green slice before crossing the next architectural boundary.

**Goal:** Finish one portable, coordinator-owned session, identity, evidence,
and mutation authority around the already-green Rhad A0 proof without adding
new Rhad semantics.

**Architecture:** `d810.core` owns the portable native-analysis key;
`d810.ir` owns serial-free block identities; `d810.analyses` owns portable
facts and evidence merging; `d810.hexrays` owns current-MBA binding and
mutation execution; `d810.manager` owns lifecycle coordination. Optimizers
consume those ports but do not create parallel global authorities.

**Non-goals:** A1/A2 and `0x40E20E`, persistence, serialized MBA snapshots,
netnodes, cache reuse, B2-B5, and replaying or merging the Rhad donor.

## Safety and commit discipline

- Preserve `/Users/mahmoud/src/idapro/d810` at
  `diff/rhad-preopt-import-spike@aa0438157` and preserve its local `TODO.md`.
- Before and after every commit, inspect `git status --short` and stage only
  the files belonging to that slice.
- Use one responsibility per commit. A documentation correction, scanner
  correction, terminology rename, portable type, live-index migration,
  gateway conversion, aggregate, and resolver migration are distinct commits.
- Run the slice's focused tests before committing. Run `sg` and import-linter
  whenever a layer or import changes.
- Do not rewrite the existing green commits. Consider history cleanup only
  after all gates pass and a safety branch exists.

## Task 1: Reconcile the specification

**Files:** `TODO.md`, `.tickets/dsf-dnr9.md`, this plan.

1. Record the strict order and freeze further Rhad semantics.
2. Define the dependency direction: `NativePreanalysisKey` belongs in
   `src/d810/core/native_preanalysis_key.py`; `d810.ir.block_identity` imports
   downward from there; `NativePreanalysisFacts` remains in the analysis layer.
3. Record all commit boundaries and final gates.
4. Verify the diff contains documentation only and commit as:
   `docs: sequence decompilation foundation closure`.

## Task 2: Correct the B0 inventory

**Files:**

- `tools/scripts/codemod_consolidate_decompilation_lifecycle.py`
- `tools/scripts/test_codemod_consolidate_decompilation_lifecycle.py`
- `tools/scripts/codemod_reports/*.json`
- lifecycle migration manifests

1. Add failing scanner tests for lifecycle names embedded in larger
   identifiers, including `_ReconOutcomeLike`, `TestReconPhase*`,
   `TestReconStore*`, `TestReconResult`, `TestReconPipeline*`, and
   `NORMALIZED_RECON_CFG_SCOPE`.
2. Detect production, tests, tools, configuration, CLI declarations, logs,
   documentation, and path/module names. Preserve legitimate English words
   such as `reconstruction` and `reconcile`.
3. Prove `--apply` remains atomic: any unknown/manual candidate prevents every
   write.
4. Regenerate the report. Keep compatibility-bridge and temporary-port
   manifests empty.
5. Run the codemod self-tests and dry-run. Commit only scanner behavior as:
   `tools: detect embedded lifecycle identifiers`.

## Task 3: Finish B0 terminology

1. Use the corrected report as the complete worklist.
2. Rename lifecycle-era production names, configuration keys, CLI names,
   fixtures, test classes/helpers, log names, and documentation references.
3. Do not rename semantic uses of `reconstruction` or `reconcile`.
4. Delete compatibility exports and aliases rather than preserving them.
5. Require dry-run output to report zero candidates and zero unknowns, with
   both migration manifests empty.
6. Run focused renamed tests, `sg`, and import-linter. Commit as:
   `refactor: finish lifecycle terminology migration`.

## Task 4: Land B1.0 portable native key

**Files:**

- Create `src/d810/core/native_preanalysis_key.py`
- Create `tests/unit/core/test_native_preanalysis_key.py`
- Modify only real identity producers needed to construct the key

1. Write pure failing tests for equality, deterministic serialization and
   deserialization, key mismatch, and distinct input/profile/SDK identities.
2. Define the frozen key with input identity, processor, bitness, function
   RVA and fingerprint, profile fingerprint, and SDK fingerprint.
3. Reject empty/invalid components and use a stable schema representation.
4. Wire construction only from real database, loader, profile/configuration,
   function bytes, and SDK values. No production placeholder fingerprints.
5. Run the pure tests, `sg`, and import-linter. Commit as:
   `feat: add portable native preanalysis key`.

## Task 5: Complete B0.2 portable identity

**First commit - portable value migration:**

1. Make `StableBlockIdentity` contain `native_key`,
   `exact_instruction_eas`, and normalized `native_ranges`.
2. Make `MbaBlockHandle` expose `stable_identity`.
3. Update pure callers and tests. Preserve serial-free deterministic
   serialization and input/function scoping.
4. Commit as `refactor: scope stable block identity to native input`.

**Second commit - live index migration:**

1. Update `MbaBlockIdentityIndex` construction and rebinding.
2. Preserve exact ownership, unique containment, sufficient overlap,
   ambiguity, clone/imported duplicate, synthetic handle, stale handle, and
   cross-generation behavior.
3. Persist and log stable identities only; any diagnostic serial also carries
   an EA anchor.
4. Commit as `refactor: bind live MBA blocks by scoped stable identity`.

## Task 6: Complete B0.2 mutation authority

1. Add a structural guard test that rejects direct production `split_block`,
   `copy_block`, insertion, deletion, clone, redirect, local gateway
   construction, adapter serial maps, and cross-maturity EA-to-serial maps
   outside the approved gateway implementation.
2. Inject coordinator-created gateways into one modifier family at a time.
3. For every slice, execute through the gateway, validate the SDK result,
   update the live identity index synchronously, and publish one receipt.
4. Remove `mutation_gateway is None` fallback execution and local
   `MbaMutationGateway(...)` construction as each family migrates.
5. Delete adapter-local serial maps when their final caller moves.
6. Run each family tests and protected smoke gates before committing. Use
   small commits such as `refactor: route <family> mutations through gateway`.

## Task 7: Complete B1 session aggregates

**First commit - aggregate:**

1. Implement `NativePreanalysisFacts` with a matching
   `NativePreanalysisKey`, normalized CFG/closure, transfers, and boundary
   ports.
2. Implement coordinator-owned `ensure`, `get`, `merge_facts`,
   `mark_preopt_bound`, and `finish`.
3. Test idempotent/changed merge, key mismatch, exact-once binding, nested
   sessions, redo survival, and finish cleanup of live indexes, handles, MBA
   ownership, and resolver attachments.
4. Commit as `feat: own native preanalysis facts in lifecycle sessions`.

**Second commit - resolver migration:**

1. Fold bootstrap-route evidence, transfers, boundary ports, generations,
   redo decisions, PREOPT binding, and resolver attachments into the aggregate.
2. Delete resolver function-EA globals and their getters/cleanup facades.
3. Delete the A0-specific parallel lifecycle authority.
4. Run resolver/session tests plus codemod dry-run, `sg`, and import-linter.
5. Commit as `refactor: move resolver evidence into lifecycle sessions`.

## Task 8: Final verification and ticket closure

Run from the exact foundation worktree:

```bash
pyenv exec python tools/scripts/codemod_consolidate_decompilation_lifecycle.py
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
graphify update .
```

Run all unit and focused runtime suites implicated by the commits, then the
complete unit and focused runtime collections without adding unexplained
skips. Run ownership/cache tests with both Python and compiled Cython
implementations.

Run Docker with direct exit-code propagation for:

- Rhad bootstrap route
- full fresh cache-disabled `sub_40D200` semantic oracle
- Hodur
- Sub7ffd
- Tigress
- Approov

Record exact commands, counts, elapsed times, and any expected pre-existing
skips in `.tickets/dsf-dnr9.md`. Close the ticket only after all gates pass,
the foundation worktree is clean, and the donor branch plus local `TODO.md`
remain unchanged.
