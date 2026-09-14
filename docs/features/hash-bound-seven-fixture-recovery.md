# Hash-Bound Seven-Fixture Recovery Design

## Objective

Turn the seven immutable MASM functions in the supplied failure package into
required `libobfuscated.dll` DSL regression cases and make D810
fully unflatten every case.

Deterministic abstention is a useful intermediate diagnostic outcome, but it is
not acceptance. Each case must produce a cfunc, remove the dispatcher and state
plumbing, and satisfy a fixture-specific semantic oracle.

## Evidence boundary

The authoritative local input package is selected by its manifest and is bound
to these identities:

- Source image SHA-256:
  `835fe0d11e03b4bb3886b463efc56791db23808c8b80e9cf40193427eff83109`
- Source IDB SHA-256:
  `e4df2cd9b21167ba250b2fb6408ed21a2324ba53c3346f8cb6326f0f5a9847e0`
- D810 evidence revision: `6956c49c1`
- Fixture extraction revision: `fd89bab20`
- D810 profile SHA-256:
  `135c6a4ed77329b96539f72de82280a4b0af5582a468764ce9ef05b6d3343c24`

The adjacent DLL with SHA-256
`a76da32a0a0179e7c68bb783b666664ec35db8e3ea3ced3d6bc66d8181abd7d8`
is incompatible evidence and must not be substituted.

Before importing any fixture, validate the manifest, the MASM SHA-256, the
single `PUBLIC` symbol, and the declared native extent. Copy only the exact
MASM and sanitized, rebuild-relevant provenance. Do not track source DLLs,
IDBs, diagnostic logs, or private absolute paths.

## Fixture inventory and initial failure classes

1. `sub_7FFB0E53C420`, RVA `0x78C420`, size `0x4296`, MASM SHA-256
   `092076b62bf2ffb18d32e07e2ec17b8b7166f09d6aaa3e24bc237c37d2161cb2`.
   Existing output is structurally promising but lacks semantic certification.
2. `sub_7FFB0DE51120`, RVA `0xA1120`, size `0x7470`, MASM SHA-256
   `7b8ba63d39338634d13ce754e44b2cb75b3fe1c74a458c7ac12c3dd3e6bde5dd`.
   Route activation is missing and dispatcher loops remain.
3. `sub_7FFB0DF992D0`, RVA `0x1E92D0`, size `0x500D`, MASM SHA-256
   `b4b8f02832eaff8728ce7e4c493a89fcd8e90f8b4e3d35690de4ee80be390e73`.
   A proved state is not scheduled for deferred-store analysis.
4. `sub_7FFB0DFD1D70`, RVA `0x221D70`, size `0x1E6FD`, MASM SHA-256
   `959f90c564ecfe7ff881accf38a90c8d2f3bd73cb26f7fa49fc1f17fa88f5338`.
   Predecessor state provenance is lost at a store and the current run does
   not produce a cfunc within the bounded interval.
5. `sub_7FFB0E1E69E0`, RVA `0x4369E0`, size `0x166`, MASM SHA-256
   `0c446160e198d6ecc00c915906e48718f5b123f98a1b00ba2888e6ae77f2e81c`.
   Function-boundary recovery crosses the declared extent after an invalid
   `LOCK` instruction.
6. `sub_7FFB0E0A2C90`, RVA `0x2F2C90`, size `0x95CB`, MASM SHA-256
   `c44e8383c2c39fe4a31d50a21447c861906cb6ad696e6420ca63ca6e30e9dc93`.
   A speculative switch target lands in the middle of an instruction and can
   crash the native decompiler.
7. `sub_7FFB0E086BE0`, RVA `0x2D6BE0`, size `0x8CB0`, MASM SHA-256
   `92ca85f671d4c8c2c8230337a987542f4f3b604787b0728787bbdb1df456b0ff`.
   A `JMP RAX` requires predecessor/path-sensitive target recovery.

These classifications describe the source-image/source-IDB evidence. They are
not assumed to survive structural reassembly unchanged.

## Fresh canonical-build baseline

Fresh IDA 9.4 databases over canonical DLL SHA-256
`612a936715bebdf56779582fe555909dcea1c7a9399c070dd2d3a22d8288499d`
reclassified several first failures. The diagnostic runs used the exact
attested profile and were retained under the isolated worktree rather than the
shared D810 log directory.

- `sub_7FFB0E1E69E0`, `sub_7FFB0E0A2C90`, and `sub_7FFB0DF992D0`
  produce no cfunc with or without D810. Their D810 sessions abandon at
  `MMAT_ZERO`, before state-transition recovery.
- `sub_7FFB0E086BE0` also produces no cfunc. Its D810 attempt terminates before
  a diagnostic session database is opened, so missing path-sensitive `RAX`
  evidence is not yet the first observable failure in this build.
- `sub_7FFB0E53C420` reaches state recovery. It assembles 77 transition routes
  but reports four unreached handlers, incomplete written-state evidence,
  ambiguous state-write anchors, and `producer-arena-closed` while validating
  78 projected route proofs.
- `sub_7FFB0DE51120` reaches recovery but exhausts the 256-item live-DAG work
  budget and records `phi_multi_def` at linked EAs `0x180058AE8` and
  `0x180059D66`; no state-machine plan is submitted. A later seven-operation
  DSE transaction does not constitute unflattening success.
- `sub_7FFB0DFD1D70` commits an 81/81-handler transaction, then later recovery
  attempts retain only 46/81 handlers and report `phi_multi_def` at linked EA
  `0x1800684B8` with eight reaching definitions. The run was bounded after
  reaching this first failure rather than treated as a completed benchmark.

The canonical linked RVAs, extents, and per-function byte hashes live in the
tracked fixture manifest. Production fixes must address these fresh-build
first failures; the older source-run classifications remain provenance, not
current causal conclusions.

## Build and corpus integration

The repository MASM workflow remains authoritative:

- Add one source per exported `PUBLIC` function under `samples/src/masm`.
- Let the existing source discovery, Microsoft `ml64`, and linker/export flow
  build the fixtures; do not introduce a parallel build system.
- Preserve `MASM_LINK_LAST_FUNCS` ordering where native layout constraints
  require it.
- Add measured linked MASM extents and seven required cases to the existing
  `libobfuscated.dll` DSL inventory.

Build qualification is incremental. First assemble and link each new fixture
in isolation on `reversepc.local`, which is the Windows build host. Then build
one canonical `libobfuscated.dll` containing all seven. Each generated DLL and
PDB is copied only into the isolated worktree after its content identity is
recorded. The unrelated modified DLL/PDB in the main checkout must never be
overwritten or staged.

Every native test begins with a fresh IDB generated from the exact canonical
DLL. Reused IDBs are prohibited because stale analysis can mask function
boundary, switch, and maturity-specific defects.

## Recovery strategy

Investigation proceeds by failure boundary, not fixture order.

### 1. Native crash and function-boundary safety

Start with `sub_7FFB0E0A2C90` and `sub_7FFB0E1E69E0`.

- Reproduce the failure with the exact canonical fixture bytes and measured
  linked code extents. Keep the source-image extent as separate provenance;
  structural MASM reassembly can relax instructions and change its length.
- Reject switch targets that are not proven instruction starts within the
  function extent.
- Keep malformed-tail recovery bounded to the fixture's authoritative extent.
- Add the narrowest regression before changing production behavior.

A safety correction is not enough by itself: both functions must subsequently
reach D810 recovery and satisfy full unflattening acceptance.

### 2. Path-sensitive indirect transition recovery

Investigate `sub_7FFB0E086BE0` by slicing `RAX` separately for each feasible
predecessor at the indirect jump. Preserve predecessor constraints and emit a
target only when the path-local definition proves a valid instruction-aligned
destination. Unrelated reaching definitions must not contaminate the arm.

This proof enters D810 through existing transition evidence and planning. It
must not mutate Hex-Rays blocks directly or key persistent identity on block
serial alone.

### 3. Provenance, scheduling, and route activation

Investigate `sub_7FFB0DFD1D70`, `sub_7FFB0DF992D0`, and
`sub_7FFB0DE51120` at their first missing authority receipt.

- Preserve predecessor-scoped state provenance across PHIs and stores.
- Schedule every admitted proved state for the deferred-store phase exactly
  once under stable snapshot-local identity.
- Diagnose why a complete route is not activated before extending admission.
- Publish redirects only through the existing planner and deferred transaction.
- Keep fragment-atomic safety: actionable non-state use-def severance rejects
  the fragment, while expected state-slot plumbing does not.

The large `sub_7FFB0DFD1D70` case receives bounded profiling before any broad
architecture change. Evidence must identify the dominant maturity/call path;
invocation counts alone do not justify an optimization.

### 4. Positive-case semantic certification

Treat `sub_7FFB0E53C420` as unresolved until semantics are certified. Its
shorter pseudocode and absent visible loop are structural evidence only.

## Diagnostics

Each fixture run writes an isolated per-function diagnostic database under its
run directory. Evidence must correlate:

- native EA, exact width, and stable EA-anchored block identity;
- state definition and expression;
- predecessor/path constraints;
- consumer comparison or indirect branch;
- recovery strategy and authority decision;
- admitted, rejected, retained, or abstained outcome and reason;
- planner operation and transaction publication result;
- solver/evaluator time, wall time, and request/snapshot fingerprint.

Aggregate counters remain useful but never replace per-site receipts. Block
serials may appear only with an EA anchor.

## Semantic oracles

Each case requires an explicit oracle derived from its native behavior. The
oracle is selected after inspecting its inputs and observable effects, using
the cheapest sound option:

1. Differentially execute the original fixture and the recovered control-flow
   model over boundary values, branch-partition representatives, and
   deterministic randomized inputs when all effects are emulatable.
2. Where full execution depends on external calls or memory, prove each
   recovered transition against the native slice and compare ordered call,
   memory-write, return, and exceptional-exit traces under explicit summaries.
3. For malformed or intentionally exceptional tails, assert the exact native
   termination class and that recovery neither reads nor creates targets
   outside the authoritative extent.

The oracle must cover every feasible dispatcher transition and observable exit.
Unsupported calls, unknown indirect memory, or unconstrained inputs produce an
unresolved test failure until an explicit, reviewable summary or assumption is
added. A textual pseudocode comparison is never the semantic oracle.

## Required DSL assertions

All seven cases are mandatory, not skipped or expected failures. Each asserts:

- a cfunc is produced within its case-specific bounded timeout;
- D810 reports a submitted and committed recovery, not safe bail;
- no recognized dispatcher comparison corridor remains;
- no selector/state store remains live solely because it feeds that corridor;
- no dispatcher constants, synthetic state loop, or computed dispatcher jump
  remains in the exported pseudocode/CFG;
- the fixture-specific semantic oracle passes;
- applied/rejected rewrite counts and wall time are recorded.

Assertions should use structural diagnostics and semantic evidence rather than
fragile local variable names or pseudocode line counts.

## Verification ladder

For each smallest fix:

1. Add a failing unit or bounded native regression reproducing the exact
   failure.
2. Implement the smallest sound correction without fixture-address special
   cases.
3. Run focused unit tests and architecture checks.
4. Rebuild the affected isolated MASM fixture and create a fresh IDB.
5. Run its required DSL case and semantic oracle.
6. Rerun all seven required cases against the canonical DLL.
7. Run the complete `libobfuscated` DSL corpus to expose build-layout drift.
8. Run the affected unit suites, `sg scan`, and `lint-imports` from this
   worktree.

If a previously passing case changes only after the canonical DLL rebuild,
first perform an A/B against its prior DLL using fresh IDBs: compare function
bytes, native read addresses and widths, baseline pseudocode, and the exact
failed assertion. Treat unexplained differences as corpus/build-layout drift,
not automatically as a production regression.

## Completion and publication

Completion requires all seven cases and the full `libobfuscated` DSL corpus to
pass from fresh-IDB runs, plus recorded semantic and runtime evidence. The
branch remains isolated and unpublished during investigation. Merge or push to
`cfg-recon-mainline` requires a separate explicit user request after review of
the final evidence.
