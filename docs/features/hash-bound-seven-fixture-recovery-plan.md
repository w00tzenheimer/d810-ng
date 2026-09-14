# Hash-Bound Seven-Fixture Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Import seven exact MASM functions into `libobfuscated.dll`, make D810 fully unflatten every one, and certify each result structurally and semantically on fresh IDBs.

**Architecture:** Keep immutable native inputs, build artifacts, recovery evidence, graph mutation, and semantic certification as separate evidence lanes. Existing D810 static/concolic producers remain the first line; fixes belong at the first proven loss of native extent, predecessor-scoped transition authority, scheduling, route selection, or dispatcher retirement, while the existing planner and deferred transaction remain the only graph writers.

**Tech Stack:** Python 3.13, pytest, IDA/Hex-Rays 9.4, Microsoft `ml64` and `link.exe`, MASM x64, SQLite diagnostics, D810 `DeobfuscationCase`, Unicorn where the native effect surface is emulatable.

**Spec:** `docs/features/hash-bound-seven-fixture-recovery.md`

## Global Constraints

- All seven terminal outcomes are full recoveries; deterministic abstention is diagnostic-only.
- Validate the source image, source IDB, profile, and each MASM SHA-256 before importing.
- Do not track a source DLL, IDB, evidence log, private corpus name, or machine-local path.
- Do not identify durable evidence by `blk.serial` without its native EA anchor.
- Never emit a transition that is not a refinement of the sound static over-approximation.
- Existing planner and deferred transaction code own all `mblock_t` mutation.
- Use a fresh IDB for every native acceptance run.
- Use Microsoft `ml64`/`link.exe` on `reversepc.local` for authoritative PE builds.
- Preserve the main checkout's modified DLL/PDB and untracked fixture WIP.
- Do not merge or push without a separate explicit user request.

---

### Task 1: Import and attest the seven immutable MASM sources

**Files:**
- Create: `samples/src/masm/sub_7FFB0E53C420.asm`
- Create: `samples/src/masm/sub_7FFB0DE51120.asm`
- Create: `samples/src/masm/sub_7FFB0DF992D0.asm`
- Create: `samples/src/masm/sub_7FFB0DFD1D70.asm`
- Create: `samples/src/masm/sub_7FFB0E1E69E0.asm`
- Create: `samples/src/masm/sub_7FFB0E0A2C90.asm`
- Create: `samples/src/masm/sub_7FFB0E086BE0.asm`
- Create: `samples/src/masm/hash_bound_seven_manifest.json`
- Create: `tests/unit/testing/test_hash_bound_masm_manifest.py`

**Interfaces:**
- Consumes: the local package `manifest.json` plus its seven declared MASM paths.
- Produces: a corpus-neutral manifest with `function`, `rva`, `size`, and `masm_sha256`; seven byte-exact tracked sources with exactly one matching `PUBLIC` symbol each.

- [ ] **Step 1: Write the failing identity test**

  Parameterize the seven manifest rows and assert:

  ```python
  payload = fixture_path.read_bytes()
  assert hashlib.sha256(payload).hexdigest() == row["masm_sha256"]
  text = payload.decode("ascii")
  assert len(re.findall(rf"(?m)^PUBLIC\s+{re.escape(row['function'])}\s*$", text)) == 1
  ```

- [ ] **Step 2: Run the test and confirm missing tracked inputs**

  Run: `PYTHONPATH=src pytest -q tests/unit/testing/test_hash_bound_masm_manifest.py`

  Expected: FAIL because the corpus-neutral manifest and sources do not exist.

- [ ] **Step 3: Validate the external package before copying**

  Run a read-only verifier that checks these seven source hashes in manifest order:

  ```text
  092076b62bf2ffb18d32e07e2ec17b8b7166f09d6aaa3e24bc237c37d2161cb2
  7b8ba63d39338634d13ce754e44b2cb75b3fe1c74a458c7ac12c3dd3e6bde5dd
  b4b8f02832eaff8728ce7e4c493a89fcd8e90f8b4e3d35690de4ee80be390e73
  959f90c564ecfe7ff881accf38a90c8d2f3bd73cb26f7fa49fc1f17fa88f5338
  0c446160e198d6ecc00c915906e48718f5b123f98a1b00ba2888e6ae77f2e81c
  c44e8383c2c39fe4a31d50a21447c861906cb6ad696e6420ca63ca6e30e9dc93
  92ca85f671d4c8c2c8230337a987542f4f3b604787b0728787bbdb1df456b0ff
  ```

  Also assert source-image SHA-256 `835fe0d11e03b4bb3886b463efc56791db23808c8b80e9cf40193427eff83109`, source-IDB SHA-256 `e4df2cd9b21167ba250b2fb6408ed21a2324ba53c3346f8cb6326f0f5a9847e0`, and profile SHA-256 `135c6a4ed77329b96539f72de82280a4b0af5582a468764ce9ef05b6d3343c24` against the package manifest. Reject the adjacent-image hash.

- [ ] **Step 4: Import the exact sources and write the sanitized manifest**

  Copy source bytes without reformatting. The tracked manifest contains only relative tracked paths, function names, RVAs, sizes, and MASM hashes. Re-run `git diff --check` and the private terminology hook before staging.

- [ ] **Step 5: Run identity and fixture-builder regressions**

  Run:

  ```bash
  PYTHONPATH=src pytest -q \
    tests/unit/testing/test_hash_bound_masm_manifest.py \
    tests/unit/test_fixture_builder.py
  ```

  Expected: PASS, with seven hash and `PUBLIC` rows certified.

- [ ] **Step 6: Commit the immutable fixture import**

  ```bash
  git add samples/src/masm/sub_7FFB0E53C420.asm \
    samples/src/masm/sub_7FFB0DE51120.asm \
    samples/src/masm/sub_7FFB0DF992D0.asm \
    samples/src/masm/sub_7FFB0DFD1D70.asm \
    samples/src/masm/sub_7FFB0E1E69E0.asm \
    samples/src/masm/sub_7FFB0E0A2C90.asm \
    samples/src/masm/sub_7FFB0E086BE0.asm \
    samples/src/masm/hash_bound_seven_manifest.json \
    tests/unit/testing/test_hash_bound_masm_manifest.py
  git commit -m "test(masm): import seven hash-bound recovery fixtures"
  ```

### Task 2: Qualify isolated and combined Microsoft MASM builds

**Files:**
- Modify only if a layout dependency is demonstrated: `samples/Makefile`
- Generated, tracked only after validation: `samples/bins/libobfuscated.dll`
- Generated, tracked only after validation: `samples/bins/libobfuscated.pdb`
- Test: `tests/unit/test_fixture_builder.py`

**Interfaces:**
- Consumes: seven exact Task 1 MASM sources and `samples/scripts/build_windows.ps1 -MasmFuncs`.
- Produces: seven isolated build receipts and one canonical combined PE/PDB hash pair with all seven exports.

- [ ] **Step 1: Run local syntax compatibility checks per source**

  Run this once per fixture. Record failures as compatibility diagnostics only;
  Microsoft `ml64` remains authoritative.

  ```bash
  for fixture_symbol in sub_7FFB0E53C420 sub_7FFB0DE51120 \
    sub_7FFB0DF992D0 sub_7FFB0DFD1D70 sub_7FFB0E1E69E0 \
    sub_7FFB0E0A2C90 sub_7FFB0E086BE0; do
    make -C samples masm MASM_FUNCS="$fixture_symbol" || exit 1
  done
  ```

- [ ] **Step 2: Mirror only the isolated worktree's `samples/` tree**

  Use the tracked `samples/README.md` rsync exclusions. Confirm `hostname` and Windows OS identity before executing the build; `reversepc.local` is the Windows host, not a VM guest.

- [ ] **Step 3: Build each fixture separately with Microsoft tools**

  Invoke all seven exact subsets:

  ```powershell
  $FixtureSymbols = @(
    "sub_7FFB0E53C420", "sub_7FFB0DE51120", "sub_7FFB0DF992D0",
    "sub_7FFB0DFD1D70", "sub_7FFB0E1E69E0", "sub_7FFB0E0A2C90",
    "sub_7FFB0E086BE0"
  )
  foreach ($FixtureSymbol in $FixtureSymbols) {
    powershell -File G:\idapro\plugins\d810-ng\samples\scripts\build_windows.ps1 `
      -MasmFuncs $FixtureSymbol
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  }
  ```

  For each result, record `ml64` success, `link.exe` success, DLL SHA-256, PDB SHA-256, export name, export RVA, and code extent.

- [ ] **Step 4: Build the canonical all-fixture DLL**

  Run the same script without `-MasmFuncs`, pull artifacts by the documented tar-over-SSH route, strip only the known 29-byte profile preamble, and verify PE32+ plus `Micr` PDB headers.

- [ ] **Step 5: Prove all seven exports and exact native bytes**

  Use `llvm-objdump -p` for export names and a fresh IDA loader/readback for code bytes. Fail if any export is absent, overlaps another function, or differs from the declared fixture extent. Add a `MASM_LINK_LAST_FUNCS` row only if the isolated/combined A/B proves object ordering changes native bytes or a required relative relocation.

- [ ] **Step 6: Commit only the canonical validated artifacts and any proven layout rule**

  ```bash
  git add samples/bins/libobfuscated.dll samples/bins/libobfuscated.pdb samples/Makefile
  git commit -m "test(samples): build canonical seven-fixture PE corpus"
  ```

  Omit `samples/Makefile` from staging when no layout rule changed.

### Task 3: Register strict required DSL cases and fresh-IDB receipts

**Files:**
- Modify: `tests/system/cases/libobfuscated_comprehensive.py`
- Modify: `tests/system/e2e/test_libdeobfuscated_dsl.py`
- Create: `tests/system/e2e/hash_bound_fixture_receipts.py`
- Create: `tests/unit/testing/test_hash_bound_fixture_receipts.py`

**Interfaces:**
- Consumes: canonical DLL, seven manifest extents, D810 run result, per-function diagnostic DB.
- Produces: `HashBoundFixtureReceipt(function, function_ea, code_size, disposition, corridor_count, selector_store_count, applied, rejected, wall_seconds, diagnostics_db)` and seven required pytest parameters.

- [ ] **Step 1: Write failing unit tests for the receipt contract**

  Define a frozen receipt dataclass and `assert_complete_recovery(receipt)` that rejects missing cfunc, any non-committed disposition, residual corridor count above zero, selector plumbing above zero, a diagnostics DB outside the run directory, and missing wall/rewrite counters.

- [ ] **Step 2: Run the receipt tests and confirm the helper is absent**

  Run: `PYTHONPATH=src pytest -q tests/unit/testing/test_hash_bound_fixture_receipts.py`

  Expected: FAIL on the missing module.

- [ ] **Step 3: Implement the receipt parser against existing diagnostics**

  Read `function_outcomes`, transition evidence, transaction outcomes, and dead-store rejection rows from the isolated SQLite DB. Keep `(EA, anchored block identity)` together; never accept aggregate-only evidence as a complete receipt.

- [ ] **Step 4: Register all seven cases as required on Windows**

  Add the seven symbols to `DAC_MASM_CASES` with `must_change=True`, the exact profile, and no `allow_unchanged_pseudocode_if_rules_fired`. Keep `skip_if_function_absent=True` only for non-PE platform portability; within `TestDacMasmFixtures`, assert all seven are present in the canonical Windows DLL before parameter execution.

- [ ] **Step 5: Register exact code extents**

  Add these sizes to the e2e runner's MASM extent map in manifest order:

  ```python
  {
      "sub_7FFB0E53C420": 0x4296,
      "sub_7FFB0DE51120": 0x7470,
      "sub_7FFB0DF992D0": 0x500D,
      "sub_7FFB0DFD1D70": 0x1E6FD,
      "sub_7FFB0E1E69E0": 0x166,
      "sub_7FFB0E0A2C90": 0x95CB,
      "sub_7FFB0E086BE0": 0x8CB0,
  }
  ```

- [ ] **Step 6: Run seven fresh-IDB baselines with diagnostics enabled**

  Invoke the Docker system runner from the main repo root, select each case independently, and write its output and SQLite DB under the isolated worktree `.tmp/<symbol>/`. Record exact DLL hash, profile hash, function bytes, baseline pseudocode, D810 pseudocode, wall time, applied/rejected counts, and first abstention/failure site.

- [ ] **Step 7: Confirm the new cases fail for the documented reasons**

  Expected baseline classifications: one uncertified positive, missing route activation, deferred-store scheduling loss, predecessor provenance loss/timeout, invalid-tail boundary, speculative mid-instruction target/SIGBUS, and unresolved path-sensitive indirect jump. Any mismatch triggers evidence reclassification before production edits.

- [ ] **Step 8: Commit the strict red test harness**

  ```bash
  git add tests/system/cases/libobfuscated_comprehensive.py \
    tests/system/e2e/test_libdeobfuscated_dsl.py \
    tests/system/e2e/hash_bound_fixture_receipts.py \
    tests/unit/testing/test_hash_bound_fixture_receipts.py
  git commit -m "test(unflatten): require complete seven-fixture recovery"
  ```

### Task 4: Build fixture-specific semantic transition oracles

**Files:**
- Create: `tests/system/e2e/hash_bound/hash_bound_semantic_oracle.py`
- Create: `tests/system/e2e/hash_bound/test_hash_bound_semantic_oracle_unit.py`
- Create: `tests/system/e2e/test_hash_bound_semantic_oracle.py`
- Create: `samples/src/masm/hash_bound_seven_semantics.json`

**Interfaces:**
- Consumes: exact native bytes, manifest extents, native CFG snapshots, transition receipts, explicit call/memory summaries, recovered pseudocode/CFG.
- Produces: `SemanticOracleResult(passed, blockers, transition_diffs, effect_diffs)` for every fixture and a reviewed native semantic reference JSON.

- [ ] **Step 1: Write oracle unit tests that reject false positives**

  Cover missing feasible predecessor, wrong target, extra target, mismatched branch partition, out-of-extent transfer, reordered effectful call/write, missing exit, raw computed dispatcher jump, and a cosmetically clean but semantically wrong pseudocode result.

- [ ] **Step 2: Implement a fail-closed reference schema**

  Each fixture reference records entry, native extent, feasible transition partitions, terminal exits, ordered observable effects, and explicit summaries/assumptions. `evaluate_fixture_semantics(reference, recovered)` passes only when all feasible transitions and effects match and both sides have zero unresolved entries.

- [ ] **Step 3: Derive native references from the exact built DLL**

  Use bounded Unicorn differential execution where all reads/calls can be modeled. For functions with unresolved calls or runtime memory, use native slices plus explicit summaries to prove each transition partition and compare ordered call, memory-write, return, and exceptional-exit traces. Store no machine paths or raw private evidence.

- [ ] **Step 4: Cross-check references against package CFG evidence**

  The source-derived reference and package evidence must agree on native EA, instruction bytes, target, and partition. A disagreement is an unresolved oracle failure, not a reason to choose one source silently.

- [ ] **Step 5: Wire each required DSL case to its semantic oracle**

  The system test loads the per-run diagnostics/exports and calls `evaluate_fixture_semantics`. A case cannot pass on pseudocode shape alone.

- [ ] **Step 6: Run oracle unit tests and preserve their red native integration state**

  ```bash
  PYTHONPATH=src pytest -q tests/system/e2e/hash_bound/test_hash_bound_semantic_oracle_unit.py
  ```

  Unit tests pass; the seven native oracle tests remain failing until recovery work completes.

- [ ] **Step 7: Commit semantic oracle infrastructure and references**

  ```bash
  git add samples/src/masm/hash_bound_seven_semantics.json \
    tests/system/e2e/hash_bound \
    tests/system/e2e/test_hash_bound_semantic_oracle.py
  git commit -m "test(unflatten): add seven-fixture semantic oracles"
  ```

### Task 5: Eliminate invalid native extents and speculative targets

**Files:**
- Modify only where the fresh-IDB trace proves ownership: `src/d810/backends/ida/idb_preparation/recovery.py`
- Modify only where the trace proves target admission: `src/d810/backends/ida/native_patch/indirect_label_plan.py`
- Modify only where the portable target check belongs: `src/d810/analyses/control_flow/materialized_indirect_transfer.py`
- Test: `tests/unit/backends/ida/idb_preparation/test_gateway.py`
- Test: `tests/unit/backends/ida/native_patch/test_indirect_label_plan.py`
- Test: `tests/unit/analyses/control_flow/test_materialized_indirect_transfer.py`

**Interfaces:**
- Consumes: authoritative `[entry_ea, entry_ea + size)` plus decoded instruction-start set.
- Produces: typed rejection receipts for out-of-extent tails and non-instruction-start targets; bounded valid CFG input for later recovery.

- [ ] **Step 1: Reduce each native failure to a pure failing test**

  Model the invalid `LOCK` tail and the switch target landing inside a multi-byte instruction. Assert no reanalysis/read crosses the half-open extent and no candidate target is admitted unless it is a decoded instruction start.

- [ ] **Step 2: Run focused tests and prove the current unsafe decision**

  Run the three test modules above with `PYTHONPATH=src pytest -q`. Expected: the new cases fail on target/extent admission, not merely on a crash wrapper.

- [ ] **Step 3: Fix the first proven owner only**

  Add `NativeCodeExtent.contains_instruction(ea)` or the existing equivalent at the admission boundary identified by the diagnostic trace. Return a typed rejection containing source EA, candidate target, extent, decode status, and request fingerprint. Do not add fixture EAs or constants to production code.

- [ ] **Step 4: Run focused unit and architecture gates**

  ```bash
  PYTHONPATH=src pytest -q \
    tests/unit/backends/ida/idb_preparation/test_gateway.py \
    tests/unit/backends/ida/native_patch/test_indirect_label_plan.py \
    tests/unit/analyses/control_flow/test_materialized_indirect_transfer.py
  sg scan --config sgconfig.yml --report-style short
  PYTHONPATH=src lint-imports --config .importlinter
  ```

- [ ] **Step 5: Rebuild, generate fresh IDBs, and prove both fixtures fully recover**

  Run their DSL and semantic-oracle cases independently. Success requires cfunc generation, zero residual dispatcher/state plumbing, no SIGBUS, no extent violation, and semantic pass.

- [ ] **Step 6: Commit the bounded native correction**

  ```bash
  git add src/d810 tests/unit
  git commit -m "fix(native): bound malformed and speculative CFG targets"
  ```

### Task 6: Resolve the predecessor-scoped indirect `RAX` transition

**Files:**
- Modify: `src/d810/analyses/control_flow/materialized_indirect_transfer.py`
- Modify: `src/d810/transforms/minimal_unflatten_emit.py`
- Modify if live adaptation is the proven missing seam: `src/d810/backends/hexrays/evidence/dispatcher/indirect_jump_capability.py`
- Test: `tests/unit/optimizers/microcode/flow/jumps/test_computed_goto_static_choices.py`
- Test: `tests/unit/transforms/test_minimal_unflatten_emit.py`
- Test: `tests/system/e2e/test_computed_goto_resolver.py`

**Interfaces:**
- Consumes: one indirect-jump EA, feasible predecessor identity, path-local reaching definition, constraints, static target over-approximation.
- Produces: one `Resolved(target, predecessor, witness)` per feasible arm or an unresolved whole transition; existing planner consumes the resulting canonical evidence.

- [ ] **Step 1: Write a portable regression for unrelated reaching definitions**

  Build a graph where two feasible predecessors define `RAX` distinctly and unrelated definitions reach the merge in the context-insensitive view. Assert path-local slices resolve only their own aligned targets and preserve distinct successors.

- [ ] **Step 2: Run the focused test and confirm context-insensitive ambiguity**

  Run: `PYTHONPATH=src pytest -q tests/unit/optimizers/microcode/flow/jumps/test_computed_goto_static_choices.py tests/unit/transforms/test_minimal_unflatten_emit.py -x`

- [ ] **Step 3: Implement predecessor-scoped proof**

  Partition definitions by predecessor, evaluate under that predecessor's constraints, intersect each result with the sound static candidate set, and accept only instruction-aligned in-extent targets. A conflict produces a diagnostic rejection; it never redirects automatically.

- [ ] **Step 4: Convert proof receipts to existing transition evidence**

  Preserve native EA, predecessor EA/anchored block identity, operand path, target, assumptions, and request fingerprint. Pass the evidence to the existing planner; do not write live blocks in the resolver.

- [ ] **Step 5: Run focused, native, and semantic tests**

  Run the two unit modules, computed-goto e2e case, and the exact required fixture on a fresh IDB. Require no raw `JMP RAX`, no dispatcher, and semantic-oracle pass.

- [ ] **Step 6: Commit path-sensitive indirect recovery**

  ```bash
  git add src/d810/analyses/control_flow/materialized_indirect_transfer.py \
    src/d810/transforms/minimal_unflatten_emit.py \
    src/d810/backends/hexrays/evidence/dispatcher/indirect_jump_capability.py \
    tests/unit/optimizers/microcode/flow/jumps/test_computed_goto_static_choices.py \
    tests/unit/transforms/test_minimal_unflatten_emit.py \
    tests/system/e2e/test_computed_goto_resolver.py
  git commit -m "fix(unflatten): prove indirect transitions per predecessor"
  ```

  Omit the backend file if the portable evidence lane alone owns the failure.

### Task 7: Preserve state provenance and deferred-store scheduling

**Files:**
- Modify: `src/d810/evaluator/hexrays_microcode/emulator.py`
- Modify: `src/d810/analyses/control_flow/minimal_state_recovery.py`
- Modify: `src/d810/analyses/value_flow/state_write.py`
- Modify: `src/d810/transforms/minimal_unflatten_emit.py`
- Test: `tests/unit/preanalysis/flow/test_minimal_state_recovery.py`
- Test: `tests/unit/transforms/test_minimal_unflatten_emit.py`
- Test: `tests/unit/transforms/unflatten_authority/test_route_projection.py`

**Interfaces:**
- Consumes: state write, predecessor-scoped reaching definitions, path constraints, stable occurrence identity.
- Produces: complete per-arm transition evidence and exactly-once deferred-store scheduling bound to the current graph snapshot.

- [ ] **Step 1: Write regressions for provenance loss and unscheduled proved state**

  One test carries multiple concrete state definitions through a shared store and requires distinct predecessor evidence. A second admits a proved state and asserts its deferred-store analysis is queued exactly once despite duplicate observations.

- [ ] **Step 2: Run tests and confirm the exact first loss**

  Instrument the portable occurrence and backend adapter boundaries. Classify whether the failure is evaluator merge, evidence projection, occurrence identity, or scheduler admission before editing production code.

- [ ] **Step 3: Implement only the proven lifecycle correction**

  Preserve `(source EA, predecessor EA, operand fingerprint, snapshot fingerprint)` through evaluation and projection. Reconcile agreeing duplicates; reject conflicting arm shapes. Schedule on admitted occurrence identity before any coalescing that can erase ownership.

- [ ] **Step 4: Profile the large fixture before performance expansion**

  Run a bounded pyinstrument reproduction with the exact DLL/profile/cache policy. Record dominant maturity and call path. If the run still exceeds the bound, make the smallest measured work-elimination change and prove it with counters plus a second wall measurement.

- [ ] **Step 5: Run focused tests and both native fixture cases**

  Require the provenance-loss and scheduling fixtures to produce cfuncs, commit all transactions, remove corridors/state stores, and pass semantic oracles. Record runtime and rewrite counts.

- [ ] **Step 6: Commit provenance/scheduling recovery**

  ```bash
  git add src/d810/evaluator/hexrays_microcode/emulator.py \
    src/d810/analyses/control_flow/minimal_state_recovery.py \
    src/d810/analyses/value_flow/state_write.py \
    src/d810/transforms/minimal_unflatten_emit.py \
    tests/unit/preanalysis/flow/test_minimal_state_recovery.py \
    tests/unit/transforms/test_minimal_unflatten_emit.py \
    tests/unit/transforms/unflatten_authority/test_route_projection.py
  git commit -m "fix(unflatten): retain state provenance through deferred analysis"
  ```

  Stage only files actually changed after root-cause isolation.

### Task 8: Activate complete routes and retire residual dispatch corridors

**Files:**
- Modify: `src/d810/analyses/control_flow/semantic_route_evidence.py`
- Modify: `src/d810/transforms/dispatcher_corridor_coverage.py`
- Modify: `src/d810/transforms/minimal_unflatten_emit.py`
- Modify if selector-store evidence is incomplete: `src/d810/core/diag/lifecycle.py`
- Test: `tests/unit/analyses/control_flow/test_semantic_route_evidence.py`
- Test: `tests/unit/transforms/unflatten_authority/test_proposal_retirement_entry_closure.py`
- Test: `tests/unit/transforms/test_minimal_unflatten_emit.py`

**Interfaces:**
- Consumes: complete transition set, static authority, corridor ownership, mutation receipts, per-site reached-use evidence.
- Produces: selected complete route, committed corridor bypass/removal, then dead selector stores with per-site diagnostic correlation.

- [ ] **Step 1: Write failing route-activation and corridor-retirement tests**

  Reproduce a complete consistent machine that loses route activation and a committed transition set whose comparison corridor remains reachable. Assert the selected route carries semantic authority and every obsolete comparison has an intentional-retention or removal receipt.

- [ ] **Step 2: Run focused tests and locate the first missing receipt**

  Distinguish route never produced, route rejected by authority, route not selected, selected route not planned, transaction not published, and published edge failing to supersede a comparison. Do not treat downstream DSE as the root cause while the comparison still consumes the state.

- [ ] **Step 3: Implement the smallest sound route/corridor correction**

  Activate only a complete route consistent with the static over-approximation. Retire only corridor nodes owned by the recovered dispatcher and proven obsolete after publication. Preserve real conditional arms and fragment-atomic non-state safety.

- [ ] **Step 4: Persist per-site selector liveness evidence**

  For every retained selector store, record state-write EA, stable anchored block identity, reached-use EA and operand path, comparison/dispatcher identity, responsible strategy, intentional-retention decision, and authority or abstention reason in the isolated DB.

- [ ] **Step 5: Run the two affected native fixtures plus the positive case**

  Require zero residual corridors, zero dispatcher-only selector stores, all semantic oracles passing, and the previously promising positive fixture explicitly certified rather than accepted by line-count reduction.

- [ ] **Step 6: Commit route activation and corridor retirement**

  ```bash
  git add src/d810/analyses/control_flow/semantic_route_evidence.py \
    src/d810/transforms/dispatcher_corridor_coverage.py \
    src/d810/transforms/minimal_unflatten_emit.py \
    src/d810/core/diag/lifecycle.py \
    tests/unit/analyses/control_flow/test_semantic_route_evidence.py \
    tests/unit/transforms/unflatten_authority/test_proposal_retirement_entry_closure.py \
    tests/unit/transforms/test_minimal_unflatten_emit.py
  git commit -m "fix(unflatten): publish routes through dispatcher retirement"
  ```

  Omit diagnostics files if existing per-site rows already prove the required correlation.

### Task 9: Certify all seven and the complete `libobfuscated` DSL corpus

**Files:**
- Modify only for evidence-backed assertions: `tests/system/cases/libobfuscated_comprehensive.py`
- Update reviewed semantic references only when native evidence requires it: `samples/src/masm/hash_bound_seven_semantics.json`
- Create: `.tmp/hash-bound-seven/final-evidence.md` (untracked)

**Interfaces:**
- Consumes: canonical DLL/PDB, seven fresh IDBs, strict DSL cases, seven semantic oracles, focused fixes.
- Produces: final per-case acceptance matrix and full-corpus regression receipt.

- [ ] **Step 1: Rebuild the canonical DLL from the final tracked tree**

  Repeat the authoritative Windows build and pull. Record final DLL/PDB SHA-256 and all seven export RVAs/extents.

- [ ] **Step 2: Run each fixture independently from a fresh IDB**

  From the main repo root invoke `tools/scripts/run_system_tests_docker.sh system -w hash-bound-seven-fixtures -l` with one case selector at a time. Each must produce cfunc, committed recovery, zero residual dispatcher/state plumbing, semantic pass, and runtime/rewrite counters.

- [ ] **Step 3: Run all seven together**

  Run the required seven-case selector against a newly generated IDB. Require seven passes and zero skips/xfails.

- [ ] **Step 4: Run the complete DSL corpus**

  ```bash
  ./tools/scripts/run_system_tests_docker.sh system \
    -w hash-bound-seven-fixtures -l -o hash-bound-full-dsl.txt -- \
    tests/system/e2e/test_libdeobfuscated_dsl.py -v
  ```

  If an unrelated existing case changes after the DLL rebuild, perform a fresh-IDB A/B against the previous canonical DLL and compare function bytes, native reads/widths, baseline pseudocode, and exact assertion before changing D810.

- [ ] **Step 5: Run complete affected unit and architecture gates**

  ```bash
  PYTHONPATH=src pytest -q tests/unit/transforms/unflatten_authority \
    tests/unit/analyses/control_flow tests/unit/backends/ida \
    tests/unit/testing
  sg scan --config sgconfig.yml --report-style short
  PYTHONPATH=src lint-imports --config .importlinter
  graphify update .
  ```

- [ ] **Step 6: Audit the acceptance matrix**

  For every fixture list MASM hash, built-function bytes hash, fresh-IDB hash, cfunc outcome, corridor count, selector-store count, applied/rejected rewrites, semantic oracle result, and wall time. Missing or indirect evidence is a failure.

- [ ] **Step 7: Commit final evidence-backed assertion adjustments**

  ```bash
  git add tests/system/cases/libobfuscated_comprehensive.py \
    samples/src/masm/hash_bound_seven_semantics.json
  git commit -m "test(unflatten): certify seven hash-bound recoveries"
  ```

  Do not add `.tmp` artifacts, merge, or push.
