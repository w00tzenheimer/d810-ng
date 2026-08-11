# Decompilation session context for PREOPT evidence epochs

## Problem

The resolver-proven PREOPT union importer needs evidence from more than one
Hex-Rays maturity.  A PREOPT import may make handler bodies visible, then
MMAT_CALLS can recover additional state-write routes and conditional predicate
arms.  Those facts can change the boundary-port plan, but `MERR_LOOP` restarts
only the CALLS loop.  It cannot revisit PREOPT and bind the richer template.

`MERR_REDO` is only a restart code.  It carries no payload.  The durable input
for the next generated/PREOPT MBA must therefore live in d810-owned state,
keyed by the function's decompilation session rather than by a discarded
`mba_t`.

## Existing pieces (legacy baseline to be consolidated)

- `FactCollectionContext` is an immutable, per-callback description of the
  function, provider phase, and pre/post-d810 capture phase.
- `FactLifecycleRuntime` accumulates and validates portable facts across
  maturities.
- `ReconAnalysisRuntime` owns the fact runtime's top-level reset/finish
  lifecycle.
- The computed-goto resolver currently has a narrow `_MaterializationSession`
  plus several function-EA-keyed module registries.

These pieces do not currently form one mutable, top-level decompilation
session that survives an internal `MERR_REDO` rebuild.

## Design

Introduce a Hex-Rays lifecycle-owned `DecompilationSessionContext`.  It must
outlive internal `MERR_REDO` rebuilds, but be released when the real top-level
decompilation finishes.  It must never retain a live `mba_t` from a discarded
generation.

```python
@dataclass(slots=True)
class NativePreanalysisSessionState:
    key: NativePreanalysisKey
    evidence_generation: int
    bound_preopt_generation: int
    facts: NativePreanalysisFacts | None
    imported_instruction_origins: dict[int, int]


@dataclass(slots=True)
class DecompilationSessionContext:
    function_ea: int
    database_identity: str
    top_level_epoch: int
    native_preanalysis: NativePreanalysisSessionState | None
```

Portable evidence and its generation are first-class session state.  Do not
hide them in `extensions`, retrieve them with `getattr()`, or coordinate them
through an optimizer-owned function-EA map.  An optimizer may use a typed
dynamic attachment for private callback-local bookkeeping only when the
portable analysis layer cannot own that type; the attachment must not become
the authority for evidence, generations, or redo decisions.

`FactLifecycleRuntime` remains a fact producer and validator.  Do not turn it
into a cache for native CFGs, templates, or SWIG MBA objects.

## Required lifecycle

1. Before eager native preanalysis, idempotently ensure the session exists.
   The `hxe_flowchart` path performs the same ensure operation for F5 or other
   callers that bypass a d810-owned entry point, and `hxe_prolog` remains a
   defensive fallback.  Only the first ensure emits session-start/reset work.
2. Before resolver byte delivery, capture the pristine native CFG and semantic
   closure into the session.
3. At PREOPT, build or bind the union template from the session's current
   evidence generation.
4. At CALLS, recover new routes/predicate arms, canonicalize every imported
   fictitious EA through `(imported EA -> native EA)` provenance, and merge
   only non-duplicate evidence into the session.
5. If the merged evidence changes the boundary-port plan, increment the
   evidence generation, invalidate the prepared union, and record one bounded
   restart-from-generated decision.  The flowchart callback returns
   `MERR_REDO`; PREOPT never attempts an unsupported direct restart.
6. On the regenerated PREOPT MBA, bind/import only when
   `evidence_generation > bound_preopt_generation`, then update the bound
   generation.
7. If no evidence changes, do not request another full redo.  Retain
   `MERR_LOOP` only for genuine CALLS-local microcode mutations.
8. At top-level decompilation finish, release the session and any imported-EA
   provenance owned by it.

## Migration targets

Fold these computed-goto globals into the session context or a thin
session-owned resolver state object:

- `_MATERIALIZATION_SESSIONS`
- `_RESOLUTIONS_BY_EA`
- `_PREPATCH_PREOPT_UNION_SOURCES`
- `_PREOPT_UNION_PREPARATIONS`
- function-local materialized-transfer accumulation

Delete the address-keyed transfer/fact compatibility facades as each caller is
migrated.  No production logic should coordinate PREOPT epochs by reading a
discarded MBA or by using synthetic imported EAs as stable identity.

## Verification

- A CALLS-only evidence update returns `MERR_LOOP` and does not regenerate.
- A newly discovered boundary route or conditional bridge returns `MERR_REDO`.
- The next PREOPT callback imports the refreshed template exactly once.
- A second CALLS pass with identical evidence does not loop indefinitely.
- Imported predicate/state-write evidence is stored and rebound under native
  EA anchors.
- The session holds no stale MBA object after `MERR_REDO`.
- `sub_40A560`, `sub_40D200`, the other Rhad transfer functions, Hodur, and
  Tigress regressions remain clean before this becomes default behavior.

## Side conversation: durable native preanalysis and serialized MBA templates

### Question

Can d810 run Python before Hex-Rays decompilation to gather native facts, then
make those facts available to the later PREOPT/CALLS lifecycle hooks?  Can the
resulting per-function context be scoped to an IDB, persisted, exported, and
reused?

### Answer: use a two-tier preanalysis path

There are two useful entry points, with different coverage guarantees:

1. **Eager preflight for d810-owned entry points.**  A d810 action, headless
   runner, or explicit API can call `prepare_native_preanalysis(function_ea)`
   immediately before `ida_hexrays.decompile(function_ea)`.  This is truly
   before decompilation begins and is the right place to decode native bytes,
   build a native CFG, run the static computed-goto resolver, and cache the
   result.
2. **`hxe_flowchart` fallback for every decompilation path.**  Users can press
   F5 or another plugin can invoke the decompiler without going through a d810
   action.  The existing `HexraysDecompilationHook.flowchart()` event is the
   earliest d810-controlled Hex-Rays seam and runs before Hex-Rays constructs
   the flowchart used by the rest of the pipeline.  It must lazily prepare the
   same artifact when an eager preflight did not already do so.

The flowchart callback is not a general recursive-microcode sandbox.  It may
perform native decoding and static analysis, and may request `MERR_REDO` when
native delivery changed the IDB.  It must not call `gen_microcode()` or
`decompile()` recursively from inside a Hex-Rays callback.

The later callbacks have separate responsibilities:

- `hxe_preoptimized`: consume resolver-proven evidence and import/apply the
  PREOPT union closure and its exact boundary ports.
- `hxe_calls_done`: recover additional live routes and predicate arms; request
  `MERR_REDO` only when those facts require a regenerated PREOPT template.
- `hxe_stkpnts` and `hxe_build_callinfo`: provide narrowly scoped stack and
  ABI enrichment, not general native-CFG recovery.
- `hxe_prolog` and `hxe_microcode`: are already later than the best native
  discovery seam, so do not make them the primary source of resolver facts.

### What should be injected

Hex-Rays has no arbitrary "context injection" channel.  The safe equivalent
is a d810-owned, immutable evidence artifact consumed by later hooks.  It must
contain stable native identities, not maturity-local block serials:

```python
@dataclass(frozen=True)
class NativePreanalysisEvidence:
    function_rva: int
    input_fingerprint: bytes
    function_fingerprint: bytes
    native_cfg: NativeCfg
    resolver_resolution: ComputedGotoResolution
    state_to_handler_routes: tuple[MaterializedIndirectTransfer, ...]
    conditional_state_choices: tuple[MaterializedIndirectTransfer, ...]
    boundary_ports: DetachedSnippetBoundaryPorts
```

This represents only independently proven facts: decoded native CFG edges,
computed-goto state-to-handler labels, state writes, conditional state choices,
stack-carrier provenance, semantic-closure ranges, and resolver-proven
conditional/direct boundary ports.  Later code resolves those native EA/RVA
anchors against the *current* live MBA before it mutates the live CFG.

### Existing d810 seams

- `src/d810/hexrays/hooks/hexrays_hooks.py` dispatches `flowchart`,
  `preoptimized`, `calls_done`, `stkpnts`, and `build_callinfo` into the d810
  lifecycle.
- `src/d810/hexrays/preanalysis/flowchart_preanalysis.py` is the generic
  registry for the early flowchart seam.
- `src/d810/optimizers/microcode/flow/jumps/computed_goto_resolver.py`
  already resolves and stages computed-goto evidence from that flowchart seam.
- `src/d810/optimizers/microcode/flow/jumps/materialized_computed_goto_island.py`
  owns the PREOPT import path.
- `src/d810/ui/actions/decompile_function.py` currently enters
  `idaapi.decompile()` first and prepares detached snippets afterward.  An
  eager preflight belongs immediately before that first decompile call, with
  the flowchart callback retained as the universal fallback.

### Current registry scope is insufficient

The current resolver and indirect-dispatch registries are module-level Python
maps keyed only by absolute `function_ea`, for example
`_MATERIALIZED_INDIRECT_TRANSFERS: dict[int, ...]`,
`_RESOLUTIONS_BY_EA`, and `_PREOPT_UNION_PREPARATIONS`.  They survive redo
rounds within a loaded Python process but are cleared on resolver
install/uninstall.  They are therefore neither truly IDB-scoped nor durable.

An address-only key is unsafe in a long-lived process: a new IDB can contain an
unrelated function at the same EA.  The durable key must be:

```text
(input identity, processor, bitness, image-base-independent function RVA,
 function-byte fingerprint, relevant d810 profile/configuration, SDK version)
```

Persisted records must encode native locations as RVAs, never as bare EAs.  On
load, d810 rebases RVAs, re-decodes every cited instruction, and validates the
function fingerprint, instruction shape, profile, and SDK before accepting a
record.  Any mismatch invalidates the complete record and falls back to fresh
analysis.

### Important correction: `mba_t` is serializable in IDA 9.3

The earlier design rule, "never retain a live MBA from a discarded generation,"
remains correct for a live SWIG object.  It does *not* mean microcode cannot be
persisted.  IDA 9.3 explicitly provides:

```cpp
void mba_t::serialize(bytevec_t &vout) const;
static mba_t *mba_t::deserialize(const uchar *bytes, size_t nbytes);
```

The IDAPython binding exposes `mba.serialize()` and
`ida_hexrays.mba_t.deserialize(bytes)`.  IDA's own `examples/decompiler/
serialize.py` serializes both `cfunc.mba` and `cfunc`, then deserializes the MBA
before deserializing the ctree.

This enables a stronger cache design:

```text
Native evidence manifest
  - stable RVA/EA proof anchors and validation provenance

Serialized PREOPT (or CALLS) MBA snapshot
  - exact microcode CFG, instructions, operands, lvar state, and source form
  - used as a reusable detached template after validation
```

The deserialized MBA is still an independent microcode array, not the live MBA
currently being optimized.  It cannot be substituted into an in-progress
decompilation.  Instead, d810 rebinds its native anchors against the current
live MBA and imports/copies only the resolver-proven subgraph and boundary
ports through the existing live-CFG mutation APIs.

The serialized snapshot should be treated as version-sensitive and stored with
the same validation envelope: input/function fingerprints, architecture,
Hex-Rays SDK version, maturity, decompiler flags, and d810 profile/config.
It is suitable for an IDB-local cache (for example a plugin-owned netnode/blob)
and a JSON-plus-base64 export artifact.  It is reusable across reopened IDBs of
the same validated binary, including rebased loads after RVA resolution; it is
not safely reusable across a different build merely because absolute EAs
happen to match.

### Proposed lifecycle with durable template support

1. Build or load a validated `NativePreanalysisEvidence` before decompile.
2. If valid, optionally load the serialized PREOPT source MBA instead of
   regenerating the isolated template.
3. At the current live PREOPT maturity, rebind every source/target/boundary
   anchor by native EA/RVA; never carry block serials across maturity or
   snapshots.
4. Import only the proven union region and its exact direct/conditional ports.
5. At CALLS, merge new live evidence.  If the boundary-port plan changed,
   increment the session epoch, invalidate the bound PREOPT template, and
   return `MERR_REDO`.
6. On the next PREOPT generation, rebuild or reload a template for that new
   evidence epoch and bind it once.
7. Release only live MBA references at decompilation completion.  Persisted
   bytes plus their validation manifest may remain in the IDB-local cache or
   exported artifact.

### Open implementation work

- Add a first-class preanalysis registry/service rather than adding another
  address-keyed module global.
- Add an eager `prepare_native_preanalysis()` call before d810-owned decompile
  entry points, while keeping `hxe_flowchart` as a lazy fallback.
- Define a schema-versioned serializable evidence manifest and a strict
  validation policy.
- Prototype `mba_t.serialize()` / `deserialize()` with a PREOPT union template
  and prove that importing the deserialized source yields the same live CFG as
  a freshly generated source.
- Decide whether the first persistence backend is an IDB netnode/blob, a
  sidecar artifact, or both.  Do not make durable cache loading a prerequisite
  for fresh analysis; every cache miss or failed validation must fail open.

### Foundation-closure amendment (2026-07-20)

The current `diff/decomp-session-foundation` branch has already proved Rhad A0,
but that vertical proof landed before the final B0/B0.2/B1 contracts were
closed.  The remaining work is therefore foundation closure, not further Rhad
semantic development.  The following order overrides the older Track A-first
wording below:

1. Reconcile this specification, `dsf-dnr9`, and the standalone execution plan.
2. Make the B0 inventory recognize lifecycle names embedded in larger
   identifiers, then remove every remaining lifecycle-era identifier without a
   compatibility alias or temporary port.
3. Define `NativePreanalysisKey` in `d810.core.native_preanalysis_key`, the
   IDA-free layer below both `d810.ir` and `d810.analyses`.  This prerequisite
   commit must land before `StableBlockIdentity` imports it.
4. Complete portable `StableBlockIdentity`, then complete the live
   `MbaBlockIdentityIndex`, as separate commits.
5. Make the coordinator-created `MbaMutationGateway` the only production
   structural-mutation executor and delete local fallback gateways and serial
   maps in small green commits.
6. Implement `NativePreanalysisFacts` and the coordinator-owned session
   operations, then fold the A0 bootstrap route and resolver state into that
   canonical aggregate.
7. Re-run the fresh cache-disabled Rhad A0 bootstrap and semantic oracles plus
   all protected-family gates.  Do not add A1/A2 semantics.

This resolves the former dependency contradiction: `NativePreanalysisKey`
cannot be defined in `d810.analyses.control_flow.native_preanalysis_session`
because `d810.ir.block_identity` would then need an upward import.  The key is
a core value object; native facts remain in the analysis layer, portable block
identity remains in the IR layer, and live MBA binding remains in the Hex-Rays
layer.

The executable plan and per-commit verification matrix live at
`docs/superpowers/plans/2026-07-20-decomp-session-foundation-closure.md`.

# Rhad Native Preanalysis and Serialized PREOPT Templates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` or `superpowers:executing-plans`
> to implement this plan task-by-task. Track checkboxes as the work proceeds.

**Goal:** Finish the active Rhad PREOPT-union deobfuscation work without
introducing more address-keyed global state, then make the resulting native
evidence and PREOPT source template reusable across a validated future
decompilation.

**Ticket ownership:** Keep the real-loader semantic work under `d81-3rja`.
Open a linked follow-on ticket before beginning durable cache persistence if it
cannot be completed as part of the same reviewable change.  This document is a
specification and execution aid, not the authoritative work tracker.

**Architecture:** The implementation has two deliberately ordered tracks.
Track A finishes the current missing Rhad semantic edge with fresh native and
live-microcode evidence.  Track B introduces a session-owned native-preanalysis
artifact and optional serialized PREOPT-template cache.  Track B must not be
used to paper over an unresolved semantic edge: it may preserve and reuse
proven source microcode, but it must not invent a route, predicate, or handler.

**Tech stack:** IDA 9.3, Hex-Rays microcode (`mba_t`), IDAPython, d810's
native-CFG/semantic-closure analyzers, `MaterializedIndirectTransfer`,
`DetachedSnippetBoundaryPorts`, netnode persistence, JSON/base64 export,
pytest, and the Rhadamanthys native-decompile oracle.

**Plan location:** User-directed project `TODO.md`; do not duplicate it under
`docs/superpowers/plans/` unless the user explicitly asks for a standalone
handoff document.

### Global constraints and non-goals

- No production sample-specific function EAs, state constants, or names.
- Native EAs/RVAs are the only cross-maturity identities.  Never store or
  compare an MBA block serial outside one live MBA operation.
- A serialized MBA is a detached source/template object.  Never replace a live
  MBA with it; always bind it into a fresh live MBA through existing import and
  CFG-mutation APIs.
- Persisted data is accepted only after strict binary, function, instruction,
  architecture, configuration, maturity, and SDK validation.  Validation
  failure is a cache miss, never an error and never a partial import.
- Do not recursively invoke `ida_hexrays.decompile()` or `gen_microcode()` from
  any Hex-Rays callback.
- Do not make a cache a precondition for fresh analysis.  The no-cache path
  remains the default correctness path until cache equivalence is proven.
- `MERR_LOOP` is for a CALLS-local microcode mutation.  Use `MERR_REDO` only
  when a new fact changes the PREOPT source/template or boundary-port plan.
- The final oracle is raw pseudocode compared with the native/reference
  decompilation, not a count of IR blocks or a green unit test alone.
- Keep the legacy LOCOPT/CALLS detached importer disabled in production.  New
  work must extend the PREOPT union path or abstain.

### Standard verification commands

```bash
# Current focused resolver tests; run before any IDA runtime work.
PYTHONPATH=src pytest -q \
  tests/system/runtime/optimizers/microcode/flow/jumps/test_computed_goto_resolver.py \
  -k 'static_conditional_state_choice'

# Exact Rhad target, in the IDA 9.3 Docker runtime.
./tools/scripts/run_system_tests_docker.sh test -- \
  tests/system/e2e/test_rhad_transfer_function_semantic_coverage.py::test_second_real_loader_fully_unflattens_beyond_native_range_oracle

# Diagnostic run when a target mismatch remains.  The probe owns disposable
# copied binaries and writes its transfers JSON plus SQLite snapshot.
./tools/scripts/run_system_tests_docker.sh exec -l --enable-diag-snapshot -- \
  /app/ida/.venv/bin/python tools/scripts/rhad_investigation/probe_transfer_function.py

# Final architecture gates, from this worktree.
PYTHONPATH=src lint-imports --config .importlinter
sg scan --config sgconfig.yml --report-style short
```

### Track A: Rhad semantic work after the session/identity foundation

#### A0. Preserve the bootstrap route through fresh PREOPT regeneration

**Ticket:** `dsf-dnr9`

**Problem statement:** A1 starts after the current earliest semantic loss. On
the fresh, no-cache `sub_40D200` path, the regenerated PREOPT MBA has already
lost the bootstrap route:

```text
0x40D348 -> state 0x699BC698 -> handler 0x40EAA7
```

Without that route, the cleanup body is unreachable. Improving the later
conditional at `0x40E20E` cannot make an unreachable body reachable.

**Design target:**

> Fresh, cache-disabled `sub_40D200` fully deobfuscates through the
> session/identity PREOPT path, with the bootstrap route preserved across redo
> and no dependency on serialized snapshots.

This is a deliberately narrow vertical slice, not permission to build a second
session or identity model. The session-generation and stable-identity pieces
introduced here are the final B0.2/B1 authorities. They must not use a raw MBA
pointer, a persisted block serial, an address-keyed compatibility map, a
serialized template, a netnode, or cache reuse.

**Required sequence:**

1. Run `sub_40D200` from a disposable copied loader with caches disabled and
   diagnostic snapshots enabled. Persist a diagnostic row/report for the first
   missing bootstrap fact before changing resolver behavior.
2. Attach resolver evidence to the active `DecompilationSessionContext` and
   assign monotonically increasing evidence generations. CALLS may merge new
   native facts; a semantic no-op must not advance the generation.
3. Add only the stable identity slice needed by this path: native instruction
   EA intervals, current-MBA rebinding, transaction-local synthetic handles,
   and mutation receipts. A serial is a current binding, never an evidence or
   persistence key.
4. Allow at most one `MERR_REDO` for an evidence generation. PREOPT must
   rebuild the current identity index and rebind the newer generation before
   consuming the bootstrap route.
5. Recover and publish the bootstrap route above. Prefer static native proof;
   CALLS discovery plus the single controlled redo is the generic fallback.
6. Re-run the fresh target and compare it to the native oracle. Only after the
   body is reachable may A1 reassess `0x40E20E` as the next actual semantic gap.
7. Keep serialized snapshots, netnode persistence, and cache reuse out of A0.
   They are later transport/persistence work and must not hide a no-cache
   recovery failure.
8. Retire the probe-only `prepare_detached_handler_snippets(...,
   template_maturity=...)` port when the fresh cache-disabled target succeeds
   through the PREOPT-union path. Until then, its single definition and single
   investigation-tool consumer are bounded by
   `tools/scripts/lifecycle_migration_manifest.json`; the gate must fail if the
   port spreads, loses its consumer without being deleted, or outlives its
   manifest entry.

**Acceptance gates:**

- The target E2E emits a durable bootstrap-route record with source
  `0x40D348`, state `0x699BC698`, and handler `0x40EAA7`; the route remains
  present after the controlled redo.
- The same session reuses its top-level epoch across redo, advances evidence
  generation only for changed facts, and releases live-only bindings at finish.
- Every bootstrap/import source is rebound by native identity or explicitly
  abstains. No diagnostic, resolver map, or persisted artifact identifies it
  by a bare block serial.
- The protected Docker Hodur/Sub7ffd suite remains green after every A0 commit.

#### A1. Recover branch-style conditional state choices in the native resolver

**Problem statement:** The current `sub_40D200` result has a real cleanup body
but retains an infinite `while (1)` because the resolver does not publish a
conditional boundary fact for the native branch at `0x40E20E`.  The native
semantics are already independently observable:

```text
0x40E207  mov ebp, 0x85AE90D3       # fallthrough/continue state
0x40E20C  test al, 1
0x40E20E  je 0x40E583               # taken arm writes exit state
0x40E583  mov ebp, 0x3AF41FBE

0x85AE90D3 -> handler 0x40DC04      # next cleanup iteration
0x3AF41FBE -> handler 0x40F12D      # exit cleanup loop
```

This is not the existing compare/CMOV selector pattern.  It is a generic
branch-style state choice: one exact state is live before a conditional branch,
the other is written on exactly one branch corridor, and both routes reach
independently recovered dispatcher handlers.

**Files:**

- Modify: `src/d810/optimizers/microcode/flow/jumps/computed_goto_resolver.py`
- Test: `tests/system/runtime/optimizers/microcode/flow/jumps/test_computed_goto_resolver.py`
- Verify: `tests/system/e2e/test_rhad_transfer_function_semantic_coverage.py`

**Required interface:** Add a private resolver helper whose input is native
static-fixpoint state plus one decoded conditional block and whose output is
either one ordinary `MaterializedIndirectTransfer` with
`resolver_kind="static_conditional_state_choice"`, or no record.

The resulting record must use existing fields:

```python
MaterializedIndirectTransfer(
    source_jmp_ea=predicate_ea,
    source_block_ea=source_block_ea,
    materialized_anchor_eas=(state_write_ea, predicate_setup_ea, predicate_ea),
    condition_code=condition_code,
    predicate_register=predicate_register,
    predicate_size=predicate_size,
    predicate_compare_constant=predicate_constant,
    predicate_true_state=true_state,
    predicate_false_state=false_state,
    resolver_kind="static_conditional_state_choice",
)
```

`_resolve_static_conditional_state_choice_targets()` remains the only binding
step from state constants to handler EAs.  It must continue to abstain if either
state lacks exactly one handler target or both states bind to the same target.

- [ ] Write a unit test for a branch with a singleton default state before the
  predicate and a singleton alternate state on the taken corridor.  Assert that
  it produces one unbound state-choice transfer with the predicate EA as
  `source_jmp_ea` and correctly oriented `predicate_true_state`/
  `predicate_false_state`.
- [ ] Write a unit test that removes the alternate state write, makes it
  non-singleton, or gives an arm an unknown indirect exit.  Assert that the
  recognizer returns no transfer.
- [ ] Write a unit test that supplies unique state-to-handler routes and asserts
  that `_resolve_static_conditional_state_choice_targets()` emits one
  `static_conditional_state_choice_bridge`; then add the same-target and
  duplicate-target abstention cases.
- [ ] Implement bounded corridor recovery.  It may follow only one direct arm
  through a finite, side-effect-safe corridor and must stop at a return, an
  unknown indirect edge, another conditional, a call, a conflicting state
  write, or a dispatcher transfer whose state cannot be exactly resolved.
- [ ] Reuse the existing live orientation helper for `test`/`jz` semantics.  If
  that helper cannot recognize the actual live predicate shape, add a focused
  test and extend it before creating any synthetic inverse condition.
- [ ] Run the focused runtime resolver tests.  Expected result: all existing
  CMOV and stack-carrier cases remain green, and the new branch-style case
  passes.
- [ ] Run the `sub_40D200` E2E in a fresh copied binary with diagnostic
  snapshots.  Expected pseudocode: no `while (1)`, no `JUMPOUT`, exactly the
  legitimate linked-list cleanup loop, and a visible `free()` call.

#### A2. Reconcile the current result against the native oracle before expanding scope

**Files:**

- Verify: `tests/system/e2e/test_rhad_transfer_function_semantic_coverage.py`
- Verify: `tools/scripts/rhad_investigation/probe_transfer_function.py`
- Inspect: generated copied-binary pseudocode, transfers JSON, and diagnostic
  SQLite database.

- [ ] Regenerate the reference/native output and the d810 output from fresh
  copied binaries.  Delete only sidecars adjacent to those disposable copies;
  always call `close_database(False)`.
- [ ] Compare semantic structure by native EA anchors: recovered calls, finite
  loop shape, returns, and direct conditional arms.  Do not compare MBA serials
  between maturities.
- [ ] Query the diagnostic database for every state choice, bridge request, and
  redirect that contributes to the cleanup loop.  Each reported block serial in
  notes or failures must include its current native EA anchor.
- [ ] If a difference remains, record a single next missing semantic fact in the
  ticket and test that fact before changing the framework.  Do not start cache
  persistence to mask a still-unrecovered transition.

### Track B: session-owned preanalysis evidence

#### B0. Consolidate injected lifecycle ownership before adding session state

**Why this is required:** The current manager constructs a `ReconPhase` and a
`ReconAnalysisRuntime` (which itself owns `FactLifecycleRuntime`), then injects
both references into the instruction optimizer, block optimizer, and ctree
optimizer.  Separately, `FlowGraphReadySubscriber` invokes recon/fact capture,
`HexRaysPostD810Runtime` holds another recon-runtime reference, and the
flowchart/PREOPT/CALLS registries own resolver-local globals.  The current
deduplication guards reduce duplicate collection, but they do not provide one
owner for a top-level decompilation epoch.

Do not add `DecompilationSessionRegistry` as one more peer lifecycle object.
Instead, introduce one manager-owned coordinator that composes the existing
objects and owns their session boundaries.  The old `Recon*` names are removed:
preanalysis owns evidence collection, analysis owns evidence validation and
semantic summaries, and `RuleScopeRuntime` owns rules and hint storage.  The
coordinator owns ordering, current-session identity, and the preanalysis-session
attachment.

**Files:**

- Create: `src/d810/manager/decompilation_lifecycle.py`
- Create: `tests/unit/manager/test_decompilation_lifecycle.py`
- Modify: `src/d810/hexrays/lifecycle.py`
- Modify: `src/d810/hexrays/hooks/hexrays_hooks.py`
- Modify: `src/d810/manager/manager.py`
- Modify: `src/d810/manager/flowgraph_ready.py`
- Modify: `src/d810/hexrays/hooks/optinsn_adapter.py`
- Modify: `src/d810/hexrays/hooks/optblock_adapter.py`
- Modify: `src/d810/hexrays/hooks/ctree_hooks.py`
- Test: `tests/system/runtime/hexrays/test_decompilation_lifecycle.py`

**Coordinator contract:**

```python
class DecompilationLifecycleCoordinator:
    def ensure_hexrays_session(
        self,
        *,
        function_ea: int,
        database_identity: str,
    ) -> tuple[DecompilationSessionContext, bool]: ...

    def capture_flowgraph(
        self,
        *,
        flow_graph: FlowGraph,
        func_ea: int,
        provider_phase: ProviderPhaseSnapshot,
        snapshot: object | None,
    ) -> None: ...

    def current_session(self, function_ea: int) -> DecompilationSessionContext | None: ...

    def finish_hexrays_session(self) -> None: ...
```

The coordinator owns a stack of active sessions, not one bare current EA.  A
genuine nested top-level decompilation receives a new epoch; an internal
`MERR_LOOP` or `MERR_REDO` for the same active function reuses the same session
and therefore does not reset facts, template epochs, or preanalysis evidence.
The boolean returned by `ensure_hexrays_session()` is true only when a new
top-level session was created, so start/reset events are emitted exactly once.

Replace the current argument-free start/finish events with typed session
events.  There is no backward-compatibility requirement, so do not retain
aliases, no-argument wrappers, or dual event dispatch:

```python
DecompilationEvent.SESSION_STARTED = "decompilation.session.started"
DecompilationEvent.SESSION_FINISHED = "decompilation.session.finished"

@dataclass(frozen=True, slots=True)
class DecompilationSessionEvent:
    function_ea: int
    database_identity: str
    top_level_epoch: int
```

The eager pre-decompile capability calls `ensure_hexrays_session()` before
native analysis.  `HexraysDecompilationHook.flowchart()` calls it as the
universal lazy fallback, and `prolog()` calls it defensively if neither path
did.  Only the call that creates the session emits `SESSION_STARTED` with
function and database identity.  `structural()` emits `SESSION_FINISHED` for
the matching context.  Every existing profiling, statistics, diagnostics,
recon, rule-scope, and UI subscriber migrates to accept
`DecompilationSessionEvent`; delete the old `STARTED` and `FINISHED` enum
members and every subscription to them.

**Single-owner rules:**

- `D810Manager` creates exactly one coordinator after it creates the analysis
  bundle, rule-scope runtime, and post-D810 runtime dependencies.
- `FlowGraphReadySubscriber` becomes a coordinator dependency or a thin
  delegate.  There is one path from `FLOWGRAPH_READY` to
  `ReconPhase.run_microcode_collectors()` and
  `ReconAnalysisRuntime.capture_maturity_facts()`.
- Only a newly-created result from `ensure_hexrays_session()` calls
  `ReconAnalysisRuntime.reset_for_func()`
  and clears rule-scope hint state for that epoch.  Remove duplicate direct
  reset/analyze calls from instruction and block optimizer adapters after the
  coordinator path is proven.
- The instruction and block adapters continue to emit portable
  `FLOWGRAPH_READY` payloads.  They do not own session reset, persistence, or
  lifecycle ordering.
- Ctree and post-D810 consumers obtain the same coordinator context through a
  narrow provider interface.  They do not retain their own per-function
  session maps.
- The coordinator never owns a raw live `mba_t`.  Callback-local MBA pointers
  remain callback-local; durable data belongs to recon storage, native facts,
  or serialized template bytes.

- [x] Write unit tests with fake recon/runtime/session dependencies.  Assert
  that two instruction/block maturity emissions for one `(function, maturity)`
  cause one collector capture, that a `MERR_REDO`-style repeated begin reuses
  the same top-level epoch, and that a different function creates a new epoch.
- [x] Write a unit test that verifies finish clears the active session while
  calling `ReconAnalysisRuntime.mark_decompilation_finished()` exactly once.
- [x] Replace `STARTED` and `FINISHED` with `SESSION_STARTED` and
  `SESSION_FINISHED` plus `DecompilationSessionEvent`.  Update every subscriber
  to consume the typed payload; remove the old enum members and all zero-arg
  callbacks in the same change.
- [x] Build the coordinator in `D810Manager.start()` and register it as the
  sole owner of session start, `FLOWGRAPH_READY`, and finish lifecycle
  coordination.
- [ ] Give preanalysis handlers the current context through the
  coordinator/provider, not through independent module-global registries.
- [x] Replace adapter-local `reset_for_func()` and duplicate
  `analyze_and_persist()` calls with coordinator calls.  Keep the portable
  `FLOWGRAPH_READY` emission where it is so the current lifter boundary and
  snapshot timing do not change.
- [ ] Add a runtime test using actual hooks that records this order:
  `SESSION_STARTED`, one reset, one flowgraph capture per provider
  phase, PREOPT/CALLS handlers, and one finish.  Verify the same order across a
  requested `MERR_REDO` rebuild.
- [x] Run the existing recon-runtime, FLOWGRAPH_READY, instruction-adapter,
  block-adapter, and ctree-hook test files before moving resolver globals into
  the session context.

**Terminology and responsibility migration:**

- `ReconPhase` becomes `PreanalysisPhase`: stage-scoped raw evidence
  collection.
- `FactLifecycleRuntime` becomes `PreanalysisFactRuntime`: raw-fact
  deduplication and persistence.
- `ReconAnalysisRuntime` becomes `DecompilationAnalysisRuntime`: validated
  facts, semantic summaries, hints, and consumer outcomes.
- `ReconRuntimeBundle` becomes `AnalysisRuntimeBundle`, and
  `recon_runtime_factory.py` becomes `analysis_runtime_factory.py`.
- `FlowGraphReadySubscriber` is folded into the coordinator's flowgraph method.
- `enable_recon_pipeline` becomes `enable_analysis_pipeline`.
- `recon_fact_profile_modules` becomes `preanalysis_profile_modules`.
- `recon_db` becomes `analysis_db`.

The former runtime currently mixes collection, persistence, analysis, and hint
delivery.  Split those responsibilities explicitly:

```python
class PreanalysisRuntime:
    def begin_session(self, event: DecompilationSessionEvent) -> None: ...
    def capture_flowgraph(self, flow_graph: FlowGraph, phase: ProviderPhaseSnapshot) -> None: ...
    def capture_native(self, facts: NativePreanalysisFacts) -> None: ...
    def finish_session(self, event: DecompilationSessionEvent) -> None: ...

class DecompilationAnalysisRuntime:
    def validated_fact_view(self, function_ea: int, maturity: int) -> ValidatedFactView | None: ...
    def analyze(self, function_ea: int) -> DeobfuscationHints | None: ...
    def record_consumer_outcome(self, ...) -> None: ...
```

`PreanalysisRuntime` never activates rules or mutates microcode.  It records
only native and stage-local evidence.  `DecompilationAnalysisRuntime` never
decodes native bytes or receives a live `mba_t`; it reads validated evidence and
derives summaries/hints.  The coordinator invokes both in the defined order,
then hands hints to `RuleScopeRuntime`.  Mutation remains in the existing
optimizer/pass/importer layers.

- [x] Use the lifecycle codemod to rename every production import, field,
  factory, configuration key, test fixture, and log prefix from `Recon*` to its
  replacement.  Remove `recon` aliases and compatibility exports in the same
  commit.
- [x] Split the existing mixed runtime at the current fact-persistence boundary:
  move collector registration, maturity capture, deduplication, and persistence
  to `PreanalysisRuntime`; move `analyze_and_persist`, validated-view lookup,
  hint derivation, and consumer-outcome recording to
  `DecompilationAnalysisRuntime`.
- [x] Update every injected consumer to request the smallest interface it
  needs: preanalysis collector provider, validated-fact-view provider, analysis
  outcome sink, or rule-scope service.  No adapter receives the whole manager,
  phase, and runtime trio.
- [x] Add negative architecture tests: a preanalysis module may not import
  optimizer mutation code; an analysis module may not import Hex-Rays live MBA
  APIs; a mutation module may consume validated facts but may not write
  preanalysis persistence directly.
- [x] Update graphify inventory and confirm that no production module, config
  key, public property, test helper, log namespace, or documentation still uses
  the `recon` term after the breaking rename.

**Reference inventory and codemod rules:**

- [x] Before editing, run graph queries for `ReconAnalysisRuntime`,
  `ReconPhase`, `FactLifecycleRuntime`, `FlowGraphReadySubscriber`,
  `DecompilationEvent.STARTED`, `DecompilationEvent.FINISHED`, and each resolver
  lifecycle global.  Save the resulting source-file inventory under
  `tools/scripts/codemod_reports/decompilation_lifecycle_before.json`.
- [x] Create
  `tools/scripts/codemod_consolidate_decompilation_lifecycle.py`.  Its default
  mode prints every candidate import, constructor injection, event subscription,
  direct `reset_for_func`, direct `analyze_and_persist`, and resolver-global
  access.  Its `--apply` mode rewrites only the exact AST/import patterns that
  have a corresponding test update in the same commit; unknown patterns exit
  nonzero and remain in the report.
- [x] Re-run the B0 review inventory across `src/`, `tests/`, `tools/`, and
  `pyproject.toml`, including parser-declared CLI names and residual
  `recon_*`/`Recon*` APIs.  The complete current inventory is
  `tools/scripts/codemod_reports/decompilation_lifecycle_full_inventory.json`;
  `lifecycle_migration_manifest.json` uses it as the no-new-manual-boundary
  baseline until each migration batch removes its own candidates.
- [x] Run the codemod in report mode after every migration task.  The final
  report must contain zero references to removed `STARTED`/`FINISHED` events,
  adapter-owned `reset_for_func`/`analyze_and_persist` calls, and removed
  resolver lifecycle globals.
- [x] Use `graphify update .` after the final codemod batch, then run a second
  graph query.  The expected graph has one manager-owned coordinator connected
  to hooks, preanalysis runtime, analysis runtime, rule scope,
  native-preanalysis facts, and resolver;
  instruction/block/ctree adapters consume a context provider rather than each
  holding injected recon/session objects.

#### B0.1. Permanent coordinator ports with self-retiring internal bridges

**Decision:** Make the coordinator API permanent, and confine any temporary
delegation to that coordinator.  Do not add compatibility exports, aliases, or
an EA-keyed facade for the old runtime or resolver maps.  A caller migrates
directly to the intended final port; only the coordinator may temporarily
delegate that port to the current implementation.

**Permanent ports:**

```python
class DecompilationLifecycleCoordinator:
    def begin_session(self, event: DecompilationSessionEvent) -> DecompilationSessionContext: ...
    def capture_flowgraph(self, payload: FlowgraphReadyPayload) -> None: ...
    def finish_session(self, event: DecompilationSessionEvent) -> None: ...

@dataclass(frozen=True, slots=True)
class FlowgraphReadyPayload:
    flow_graph: FlowGraph
    func_ea: int
    provider_phase: ProviderPhaseSnapshot
    snapshot: object | None
```

`begin_session`, `capture_flowgraph`, `finish_session`, and session-owned
evidence are the final architecture.  They are not migration names and must
remain after every `Recon*` name and resolver lifecycle global is gone.

Portable native-preanalysis evidence, its generation, and its PREOPT binding
generation are first-class fields on `DecompilationSessionContext`.  The
portable analysis/session layer never imports an optimizer type.  If the
resolver needs private callback-local bookkeeping that cannot cross that
boundary, it may attach it through an explicit typed attachment API, but that
bookkeeping is not the evidence or redo authority.  The session-owned state
replaces `_MATERIALIZATION_SESSIONS`, `_RESOLUTIONS_BY_EA`,
`_PREPATCH_PREOPT_UNION_SOURCES`, and `_PREOPT_UNION_PREPARATIONS` without
reintroducing an address-keyed registry.

**Temporary bridge rule:** A bridge may exist only as a private coordinator
implementation detail.  It may delegate to `ReconPhase`,
`ReconAnalysisRuntime`, or the current flowgraph subscriber while the caller
migration is in progress, but it may not be imported, registered, or invoked
by an adapter, UI action, resolver callback, test fixture, or configuration.
The bridge stores neither a raw live `mba_t` nor an address-keyed resolver map.

**Self-retirement contract:** Every temporary bridge must declare its exact
legacy candidate kinds and its removal condition in the lifecycle migration
manifest.  The migration gate reads the codemod report and enforces all of the
following:

- no candidate outside the manifest allowlist may be introduced;
- only the coordinator may reference a bridge or legacy runtime implementation
  during the corresponding migration stage;
- the relevant candidate count must monotonically decrease after the caller
  migration begins; and
- when every candidate listed for a bridge reaches zero, the gate fails while
  that bridge still exists or is imported.

The last condition is deliberate: a green final migration gate is impossible
if a temporary bridge was forgotten.  Remove the bridge, its manifest entry,
and its test-only fixture support in the same final batch.

**Mechanical migration sequence:**

1. Add the coordinator ports and typed `DecompilationSessionEvent`, with unit
   tests that preserve the current collection/analysis order through the
   coordinator delegation.
2. Replace the five external lifecycle calls (`reset_for_func` and
   `analyze_and_persist` in instruction/block adapters plus ctree) with their
   permanent coordinator port.  The two lower-level resets inside the current
   runtime are internal composition and move only with the runtime split; they
   are not adapter ownership violations.
3. Fold `FlowGraphReadySubscriber` into `capture_flowgraph`; replace its
   manager construction and test fixtures in one batch, then delete the class.
4. Emit typed start/finish events and migrate the three manager subscriptions.
   Do not auto-wrap zero-argument callbacks: every subscriber must explicitly
   accept `DecompilationSessionEvent` or move behind the coordinator.
5. Add `ResolverSessionState` to the current decompilation session.  Extend the
   codemod with separate proven AST rewrites for resolver-map lookup, write,
   `pop`, and complete cleanup; never rewrite a map name by text substitution.
6. Change `recon_fact_profile_modules` to `preanalysis_profile_modules` only
   in the batch that changes the consuming configuration contract.  Remove the
   manifest allowance for both JSON locations at the same time.
7. Require the migration report to reach zero for removed events, adapter-owned
   calls, `FlowGraphReadySubscriber`, and resolver lifecycle globals; remove
   temporary delegation before marking B0 complete.

**Initial migration accounting:** The current report has 82 manual candidates:
46 resolver-global accesses, 26 direct runtime calls (including 19 tests and
two internal runtime-composition resets), five flowgraph-subscriber references,
three event subscriptions, and two JSON configuration keys.  The lifecycle
manifest must record the exact baseline before the first bridge lands; its
allowlist is a temporary migration budget, never a permanent ignore.

#### B0.2. Centralize stable block identity, current-MBA rebinding, and mutation receipts

**Problem:** A microcode block serial is a disposable coordinate within one
live MBA snapshot. It changes across maturity, `MERR_REDO`, detached import,
and structural mutation. Native EAs are the durable semantic territory, but a
single block start EA is insufficient: folding, splitting, and imported tails
can give one logical block a discontiguous set of native instruction intervals;
clones can also share every native EA with their source. The current code has
several independent start-EA-to-serial maps and one-off serial-remap tables.
They can disagree and cannot safely handle cloned or synthetic blocks.

**Decision:** Establish one centralized identity authority. It treats serials
as maturity-local bindings, native EA interval sets as stable identities, and
session-local logical handles as the identity of cloned or synthetic blocks
that cannot be uniquely recovered from native EAs alone. Do not persist a
serial as an identity and do not guess a match when rebinding is ambiguous.

**Files:**

- Modify: `src/d810/ir/block_identity.py`
- Create: `src/d810/hexrays/ir/mba_identity_index.py`
- Create: `src/d810/hexrays/mutation/mba_mutation_events.py`
- Create: `tests/unit/ir/test_block_identity.py`
- Create: `tests/unit/hexrays/ir/test_mba_identity_index.py`
- Create: `tests/unit/hexrays/mutation/test_mba_mutation_events.py`
- Modify: `src/d810/manager/decompilation_lifecycle.py`
- Modify: `src/d810/hexrays/lifecycle.py`
- Modify: `src/d810/hexrays/hooks/glbopt_diagnostics.py`
- Modify: `src/d810/hexrays/mutation/byte_emit_tail_isolation_runtime.py`
- Modify: `src/d810/transforms/byte_emit_tail_isolation.py`
- Modify: `src/d810/optimizers/microcode/flow/jumps/computed_goto_resolver.py`
- Modify: `src/d810/optimizers/microcode/flow/jumps/materialized_computed_goto_island.py`
- Modify: `src/d810/transforms/block_lineage.py`

**Layering:** `d810.ir.block_identity` contains only immutable, serializable,
IDA-free value types. The live `mblock_t` traversal and binding index lives in
`d810.hexrays.ir.mba_identity_index`, beside `block_helpers.py`. Portable
analyses and transforms receive a narrow resolver protocol or an already-bound
result; they never import a live MBA index. The coordinator owns the current
index for the active decompilation context and rebuilds it at lifecycle
boundaries. No module-global EA-to-serial cache is allowed.

`NativePreanalysisKey` is defined first in
`d810.core.native_preanalysis_key`.  `d810.ir.block_identity` may import that
lower-layer value type; it must not import `d810.analyses` to obtain it.

**Portable identity contract:**

```python
@dataclass(frozen=True, order=True, slots=True)
class NativeEaInterval:
    start_ea: int
    end_ea: int  # exclusive

@dataclass(frozen=True, slots=True)
class NativeEaIntervalSet:
    intervals: tuple[NativeEaInterval, ...]  # normalized, disjoint

@dataclass(frozen=True, slots=True)
class StableBlockIdentity:
    native_key: NativePreanalysisKey
    exact_instruction_eas: frozenset[int]
    native_ranges: NativeEaIntervalSet

@dataclass(frozen=True, slots=True)
class MbaBlockHandle:
    session_id: str
    token: str
    stable_identity: StableBlockIdentity | None
    provenance: BlockHandleProvenance
```

Normalize intervals by sorting and merging adjacent/overlapping
instruction-backed intervals. Exclude empty, fake, external-placeholder, and
EA-less instructions from a portable native identity. A native identity may be
persisted; `MbaBlockHandle` is session-local and is mandatory for a clone,
trampoline, imported duplicate, or other synthetic block whose native EAs are
not unique.

**Live binder contract:**

```python
class MbaBlockIdentityIndex:
    @classmethod
    def build(cls, mba: object, *, session_id: str) -> Self: ...

    def identity_for_serial(self, serial: int) -> StableBlockIdentity | None: ...
    def handle_for_serial(self, serial: int) -> MbaBlockHandle: ...
    def resolve(self, handle: MbaBlockHandle) -> BoundBlock | None: ...
    def rebind(self, identity: StableBlockIdentity) -> RebindResult: ...
    def refresh_from_mba(self, mba: object) -> None: ...
```

The index captures only derived bindings and handles; it never retains the raw
live `mba_t`. The current callback supplies an MBA to `build()` or
`refresh_from_mba()`.

`rebind()` uses an evidence ladder: exact instruction ownership first, then a
unique current instruction-backed block whose interval set contains the EA,
then a uniquely sufficient interval-set overlap. It returns `MISSING` or
`AMBIGUOUS` rather than selecting a block by serial, start EA alone, or a
first-match walk. Every successful binding returns both the current serial and
an EA anchor for logs. A block-range fallback means a unique
instruction-backed ownership interval, never merely `blk.start <= ea < blk.end`.

**Mutation bookkeeping is part of the same authority:** Do not retain
adapter-local `_serial_remap` tables. The index must own all serial shifts in
the current MBA, including inserts, splits, clones, detached imports, deletes,
and redirects that invalidate ownership. Distinguish persistent native identity
from a transaction-local handle; clones and synthetic blocks remain resolvable
only through their unbroken handle chain.

```python
class MbaBlockIdentityIndex:
    def record_insert(self, *, insertion_serial: int,
                      created: MbaBlockHandle, returned_serial: int) -> None: ...
    def record_split(self, *, original: MbaBlockHandle,
                     retained: MbaBlockHandle,
                     created_tail: MbaBlockHandle,
                     returned_tail_serial: int) -> None: ...
    def record_clone(self, *, source: MbaBlockHandle,
                     created: MbaBlockHandle, returned_serial: int) -> None: ...
```

An insert shifts all current bindings at/after the insertion coordinate, then
binds the created handle to the SDK-returned serial. A split partitions the
original native interval set between retained head and created tail when that
partition is provable; otherwise the affected part remains synthetic and may
only be used through its handle. After a batch, or after any SDK operation whose
serial effect is not fully proven, `refresh_from_mba()` rebuilds native bindings
and marks unresolvable synthetic handles stale. A stale or ambiguous binding
aborts the pending mutation batch before a further edge is changed.

**Event integration:** Structural mutations must publish one typed,
post-commit receipt through the mutation control plane. The index is the first,
synchronous consumer; the event also provides lifecycle visibility to lineage
and diagnostics. Individual modifiers do not update maps directly.

```python
@dataclass(frozen=True, slots=True)
class MbaMutationCommitted:
    session_id: str
    function_ea: int
    maturity: int
    mba_generation_before: int
    mba_generation_after: int
    receipt: MbaMutationReceipt
```

The mutation gateway/executor performs: SDK mutation -> validate returned
blocks -> `identity_index.apply(receipt)` synchronously -> emit
`MbaMutationCommitted`. The synchronous application prevents a second
modifier from observing stale bindings; event subscribers must treat the event
as post-commit observation, not delayed correctness. The index does not apply
the receipt a second time from the emitted event. `SESSION_STARTED` creates or
resets empty session-owned index state; the first callback that carries a live
MBA builds its bindings. A typed maturity/rebuild event including `MERR_REDO`
discards serial bindings and rebinds against the callback-local MBA, while
`SESSION_FINISHED` releases transient handles and all live-only references.

**Replacement sequence:**

1. Add pure interval-set normalization, identity equality, and rebinding-result
   tests without IDA.
2. Build the live index with fake MBA/block fixtures. Test exact ownership,
   interval containment, multiple-owner ambiguity, placeholder rejection,
   cloned-EA ambiguity, and a current serial with its EA anchor.
3. Add the mutation receipt protocol and unit tests for insert serial shifts,
   split partitioning, clone handles, delete staleness, unknown-SDK-operation
   refresh, and event ordering.
4. Make `DecompilationLifecycleCoordinator` own one current index per active
   MBA generation. Rebuild it from the callback-local MBA on maturity/rebuild
   events; it must never survive a finished session or retain an MBA pointer.
5. Replace the independent `ea_to_serial` map in
   `glbopt_diagnostics.py`, the start-EA-only `find_block_by_ea()` and
   snapshot-to-live bridge in `byte_emit_tail_isolation_runtime.py`, and the
   portable `MicrocodeAdapter.find_block_by_ea()` contract. The portable caller
   passes `StableBlockIdentity`; the live adapter performs the binding.
6. Move computed-goto resolver, detached-island importer, and block-lineage
   cross-maturity lookups to `StableBlockIdentity` plus rebinding results.
   Persist identity fields beside diagnostic serials; serials remain snapshot
   coordinates only.
7. Delete `_serial_remap` and every module-local cross-maturity EA-to-serial
   map. Add a structural test that rejects new production maps of this form.

**Acceptance gates:**

- A source identity rebinding across PREOPT, LOCOPT, CALLS, GLBOPT1, and an
  explicit `MERR_REDO` resolves to the correct current block or explicitly
  abstains; it never targets a serial from an earlier MBA.
- Inserting a trampoline before an existing block updates every live handle
  through the index, with no adapter-local serial map.
- A cloned/imported block sharing native EAs with its source is never rebound
  through a first-match EA lookup; only its transaction handle may resolve it.
- Diagnostics, planner logs, and test failures emit `blk[N]@0xEA` (or an
  explicit synthetic/ambiguous identity), never a bare block number.
- `sg scan --config sgconfig.yml --report-style short` and
  `PYTHONPATH=src lint-imports --config .importlinter` remain clean.

#### B1. Define portable session records and a runtime registry

**Purpose:** Replace address-only module globals with a top-level-decompilation
session attached to the manager-owned lifecycle coordinator.  The portable
layer stores native facts and lifecycle epochs; the optimizer layer may attach
resolver-specific derived state without creating a reverse import from
`d810.hexrays` into `d810.optimizers`.

**Files:**

- Create: `src/d810/core/native_preanalysis_key.py`
- Create: `tests/unit/core/test_native_preanalysis_key.py`
- Create: `src/d810/analyses/control_flow/native_preanalysis_session.py`
- Create: `tests/unit/analyses/control_flow/test_native_preanalysis_session.py`
- Modify: `src/d810/hexrays/lifecycle.py`
- Modify: `src/d810/manager/manager.py`
- Modify: `src/d810/optimizers/microcode/flow/jumps/computed_goto_resolver.py`

**Portable types:**

`NativePreanalysisKey` is a B1.0 prerequisite and lands before the B0.2
identity changes.  It is defined in `d810.core`, not in this higher analysis
module:

```python
@dataclass(frozen=True, slots=True)
class NativePreanalysisKey:
    input_identity: str
    processor: str
    bitness: int
    function_rva: int
    function_fingerprint: str
    profile_fingerprint: str
    sdk_fingerprint: str

@dataclass(frozen=True, slots=True)
class NativePreanalysisFacts:
    key: NativePreanalysisKey
    native_cfg: NativeCfg
    semantic_closure: NativeSemanticClosure | None
    transfers: tuple[MaterializedIndirectTransfer, ...]
    boundary_ports: DetachedSnippetBoundaryPorts

@dataclass(slots=True)
class DecompilationSessionContext:
    key: NativePreanalysisKey
    top_level_epoch: int
    evidence_epoch: int
    bound_preopt_epoch: int
    facts: NativePreanalysisFacts | None
```

The existing `DecompilationLifecycleCoordinator` must expose these explicit
operations.  Do not add an independently subscribed session registry:

```python
ensure(key: NativePreanalysisKey) -> tuple[DecompilationSessionContext, bool]
get(key: NativePreanalysisKey) -> DecompilationSessionContext | None
merge_facts(key: NativePreanalysisKey, facts: NativePreanalysisFacts) -> bool
mark_preopt_bound(key: NativePreanalysisKey, evidence_epoch: int) -> None
finish(key: NativePreanalysisKey) -> None
```

`merge_facts()` returns `True` only when normalized semantic evidence changed.
It must reject a key mismatch and must not use a block serial as a merge key.

- [x] Write pure B1.0 tests for key equality, deterministic serialization,
  key mismatch rejection, and distinct input/profile/SDK identities.  Construct
  every field from real loader/profile/SDK inputs; do not invent placeholder
  fingerprints in production.
- [x] Land the IDA-free key in `d810.core.native_preanalysis_key` before
  changing `StableBlockIdentity`.
- [x] Write pure unit tests for `ensure`, idempotent merge, changed merge,
  key mismatch rejection, exact-once PREOPT binding, and finish cleanup.
- [x] Implement `NativePreanalysisFacts` and session state in the analysis
  layer using only core/IR/analysis dependencies.  Do not import IDA,
  Hex-Rays, UI, or optimizer modules there.
- [x] Implement these operations on `DecompilationLifecycleCoordinator`; do
  not add an independently subscribed registry for `STARTED`, `FINISHED`, or
  maturity events.
- [x] Move `_RESOLUTIONS_BY_EA`, `_MATERIALIZATION_SESSIONS`,
  `_PREOPT_UNION_PREPARATIONS`, `_PREPATCH_PREOPT_UNION_SOURCES`, and
  materialized-transfer accumulation into resolver-owned session state.  Update
  every caller in one codemod batch, then delete the old globals and their
  getters; do not leave compatibility aliases.
- [x] Add tests that simulate `MERR_REDO`: the session survives an internal
  rebuild, increments evidence epoch only for changed evidence, and releases
  all live-only state at `DecompilationEvent.SESSION_FINISHED`.

#### B2. Add eager preflight plus universal flowchart fallback

**Files:**

- Create: `src/d810/capabilities/native_preanalysis.py`
- Create: `tests/unit/capabilities/test_native_preanalysis.py`
- Modify: `src/d810/ui/actions/decompile_function.py`
- Modify: `src/d810/ui/actions/deobfuscate_this.py`
- Modify: `src/d810/manager/decompilation_lifecycle.py`
- Modify: `src/d810/hexrays/hooks/hexrays_hooks.py`
- Modify: `src/d810/optimizers/microcode/flow/jumps/computed_goto_resolver.py`
- Test: `tests/system/runtime/optimizers/microcode/flow/jumps/test_computed_goto_resolver.py`

**Capability seam:** The UI cannot import the optimizer directly.  Mirror the
existing detached-snippet capability with a `NativePreanalysisPreparer`
protocol:

```python
class NativePreanalysisPreparer(Protocol):
    def __call__(self, function_ea: int) -> bool: ...

def prepare_native_preanalysis(function_ea: int) -> bool: ...
```

The result means "new or validated evidence is available", not "a rewrite was
applied".  The capability fails closed to `False` when no preparer is
registered.

- [ ] Write capability tests for unregistered, registered, replacement, and
  unregister-with-newer-provider cases.
- [ ] Register the resolver implementation during resolver install and remove
  it during uninstall.
- [ ] Invoke `prepare_native_preanalysis(function_ea)` immediately before the
  first `idaapi.decompile(function_ea)` in d810-owned UI actions and headless
  entry points that have an explicit pre-decompile boundary.  It must first
  call the coordinator's idempotent session ensure operation.
- [ ] Make `_on_flowchart_preanalysis()` call the same preparer when the
  session has no valid facts.  The hook must ensure the session before invoking
  the preparer, must not duplicate existing evidence, and must not recursively
  invoke microcode generation.  `hxe_prolog` remains a defensive ensure only.
- [ ] Return `MERR_REDO` only when preflight materially changed native delivery
  that Hex-Rays must rebuild to observe.  Evidence-only preflight proceeds
  without a redo.
- [ ] Add a runtime hook test proving explicit preflight happens before the
  initial decompile call, and a second test proving a direct/F5-equivalent
  decompile still reaches the flowchart fallback.

#### B3. Define snapshot envelopes and validation before persistence

**Purpose:** Make the binary data from `mba_t.serialize()` useful without
allowing a stale/mismatched microcode snapshot to influence a live function.

**Files:**

- Create: `src/d810/analyses/control_flow/preopt_template_manifest.py`
- Create: `tests/unit/analyses/control_flow/test_preopt_template_manifest.py`
- Create: `src/d810/backends/hexrays/evidence/preopt_template_snapshot.py`
- Create: `tests/system/runtime/hexrays/test_preopt_template_snapshot.py`

**Envelope format:**

```python
@dataclass(frozen=True, slots=True)
class PreoptTemplateManifest:
    schema_version: int
    input_identity: str
    processor: str
    bitness: int
    function_rva: int
    function_fingerprint: str
    profile_fingerprint: str
    sdk_fingerprint: str
    maturity: int
    decompiler_flags: int
    evidence_epoch: int
    native_anchor_rvas: tuple[int, ...]

@dataclass(frozen=True, slots=True)
class SerializedPreoptTemplate:
    manifest: PreoptTemplateManifest
    mba_bytes: bytes
```

The manifest owns validation.  `mba_bytes` is opaque to the portable layer.
The Hex-Rays backend owns `capture_preopt_template(mba, manifest)` and
`deserialize_preopt_template(template)`.  The latter must return `None` on any
deserialization failure; it must not raise into a decompilation hook.

- [ ] Write unit tests for manifest equality, mismatch detection, JSON/base64
  round trip, rejected schema version, rejected missing anchor, and rejected
  function fingerprint.
- [ ] Implement fingerprinting over the exact function/native ranges used by
  the closure and include architecture, profile, SDK, maturity, and decompiler
  flags.  A cache hit requires all fields to match exactly.
- [ ] Write an IDA runtime test that generates a small PREOPT MBA, serializes
  it, deserializes it, verifies the resulting MBA, and compares its native EA
  anchors and instruction count with the original snapshot.
- [ ] Write an IDA runtime test that feeds invalid bytes and asserts a clean
  `None` result with no modification to the live MBA.
- [ ] Do not serialize a live MBA reference into a session.  Store only the
  immutable byte string and manifest; deserialization creates a new detached
  MBA when needed.

#### B4. Persist validated snapshots in the IDB and export portable artifacts

**Files:**

- Create: `src/d810/backends/hexrays/evidence/preopt_template_cache.py`
- Create: `tests/unit/backends/hexrays/evidence/test_preopt_template_cache.py`
- Test: `tests/system/runtime/test_netnode_wrapper.py`
- Test: `tests/system/runtime/hexrays/test_preopt_template_snapshot.py`
- Modify: `src/d810/core/persistence.py` only if the existing typed netnode
  wrapper cannot store the envelope without a generic extension.

**Storage contract:**

```text
netnode name: $ d810.preopt_template_cache
record key: SHA-256(canonical PreoptTemplateManifest without evidence_epoch)
record value: schema-versioned JSON manifest + base64 mba bytes
```

The cache must maintain at most one latest template per manifest key and may
replace an older entry only after the new template has been successfully
captured and validated.  A failed write leaves the previous valid entry intact.

- [ ] Write unit tests for put/get/delete, replacement, malformed JSON,
  oversized blob storage, and cache misses.
- [ ] Reuse the existing netnode wrapper's blob fallback rather than writing a
  second raw-netnode implementation.
- [ ] Add explicit `export_preopt_template(path, template)` and
  `import_preopt_template(path)` helpers.  Export uses JSON plus base64 so it is
  inspectable and transportable; import validates before returning a template.
- [ ] Add runtime tests that write a cache record in an IDB, reopen/read it,
  deserialize it, and reject it after a deliberately changed function
  fingerprint.
- [ ] Keep disk/file export opt-in.  IDB-local persistence is automatic only
  after a successful, validated template capture.

#### B5. Reuse a snapshot only as a PREOPT import source

**Files:**

- Modify: `src/d810/optimizers/microcode/flow/jumps/computed_goto_resolver.py`
- Modify: `src/d810/optimizers/microcode/flow/jumps/materialized_computed_goto_island.py`
- Modify: `src/d810/hexrays/mutation/detached_handler_island.py`
- Test: `tests/system/runtime/hexrays/test_detached_snippet_import.py`
- Test: `tests/system/runtime/optimizers/microcode/flow/jumps/test_computed_goto_resolver.py`

- [ ] First add a test that supplies a valid deserialized source template and
  asserts that the normal PREOPT importer receives the same union block set and
  boundary ports as with freshly generated source microcode.
- [ ] Add the complementary test: a valid snapshot whose native anchors no
  longer map uniquely in the current live MBA is rejected, and the fresh
  generation path runs instead.
- [ ] Add a resolver helper that chooses source in this order: current-session
  validated serialized template, freshly generated PREOPT union template,
  abstention.  It must never select the disabled LOCOPT/CALLS importer as a
  fallback.
- [ ] Require live rebinding of every import source, target, and conditional
  boundary by native EA before scheduling a `DeferredGraphModifier` operation.
- [ ] Verify that imported fictitious EAs remain provenance only.  They cannot
  become a cache key, state-route identity, or persisted anchor.
- [ ] Cache a new serialized template only after the fresh-source import and
  its immediate `mba.verify(True)`/d810 verifier preflight succeed.

### Track C: end-to-end validation and rollout

#### C1. Rhad regression matrix

**Files:**

- Verify: `tests/system/e2e/test_rhad_loader_semantic_parity.py`
- Verify: `tests/system/e2e/test_rhad_transfer_function_semantic_coverage.py`
- Verify: `tools/scripts/rhad_investigation/probe_transfer_function.py`

- [ ] Run `sub_40A560` from a fresh copied binary.  Assert no dispatcher loop,
  no `HIBYTE` artifact, correct stack-local presentation, and the known
  oracle-visible calls and return.
- [ ] Run `sub_40D200` from a fresh copied binary.  Assert no `while (1)`, no
  `JUMPOUT`, no `jmp eax`, exactly one legitimate cleanup loop, and all expected
  calls including `free()`.
- [ ] Run the third and fourth transfer-function cases.  Record every remaining
  difference by native EA and classify it as missing semantic evidence,
  presentation/type metadata, or cache/import validation failure.
- [ ] Execute the same target once with cache disabled, once after fresh capture
  and cache write, and once after cache load.  Raw-read all three pseudocode
  artifacts against the oracle.  The cached and fresh paths must be equivalent.

#### C2. Existing-family regression gates

- [x] Run stack-state and indirect-dispatch goldens for Hodur/sub_7FFD,
  Approov, and Tigress.  New cache/session code must be inert unless the
  computed-goto PREOPT profile explicitly opts in.
- [x] Run focused unit tests for every changed module, then the complete unit
  suite, then the relevant IDA runtime/system suites.
- [x] Run `PYTHONPATH=src lint-imports --config .importlinter` and
  `sg scan --config sgconfig.yml --report-style short` from this worktree.
- [x] Run `graphify update .` after implementation changes.
- [ ] Update the Rhad investigation README, the ticket notes, and the blog only
  after the verified implementation proves a reusable behavior.  Do not claim
  cross-IDB persistence or cache equivalence before the cache-on/cache-off
  oracle matrix is green.

### Delivery sequence and review boundaries

The following order is normative. A later item may not use a temporary
authority that an earlier item is supposed to remove.

1. **Commit B0 review closure**: make codemod application truly atomic and
   regenerate the full production inventory, including `tools/`, parser-declared
   CLI names, and residual `recon_*`/`Recon*` APIs. Each migration batch owns
   the inventory candidates it removes; unknown production candidates remain a
   failing review item, not manual follow-up.
2. **Commit B0 terminology and coordinator migration**: migrate all production
   lifecycle consumers to the single coordinator and final preanalysis names.
   Delete the old events, direct adapter runtime calls, and terminology. There
   is no compatibility layer or import alias.
3. **Commit B1.0 portable native key**: define and test the deterministic,
   serializable `NativePreanalysisKey` in `d810.core`.  Use real input,
   processor, bitness, function, profile, and SDK identities.  This commit is a
   prerequisite for portable block identity.
4. **Commit B0.2 portable identity**: make `StableBlockIdentity` contain
   `native_key`, `exact_instruction_eas`, and `native_ranges`; make
   `MbaBlockHandle` expose `stable_identity`; then migrate the live index in a
   separate green commit.
5. **Commit B0.2 mutation authority**: land typed mutation receipts and make
   the coordinator-owned gateway the sole structural-mutation executor. Delete
   adapter-local serial remaps, fallback/local gateway construction, and
   cross-maturity EA-to-serial maps before the resolver relies on this path.
6. **Commit B1 resolver session migration**: move resolver function-EA globals
   into the coordinator-owned session, with generation-aware CALLS merges, one
   controlled `MERR_REDO`, and PREOPT rebinding against the newer generation.
   No live MBA or persisted serial survives the session boundary.
7. **Verify A0** as the fresh PREOPT bootstrap proof. It consumes the final
   B0.2/B1 authorities to preserve `0x40D348 -> 0x699BC698 -> 0x40EAA7` through
   the controlled redo. It must pass with caches disabled and without serialized
   snapshots, netnodes, or cache reuse.
8. **Defer A1+A2** for the entire foundation-closure goal.  Do not add
   `0x40E20E` or other Rhad semantics while architectural authority is changing.
9. **Commit B2** only where explicit preflight/fallback remains necessary after
   the no-cache proof. It extends the established coordinator/session path; it
   does not introduce persistence or alter the no-cache oracle.
10. **Commit B3+B4** as serialization, validation, and persistence primitives.
   They must have standalone unit/runtime proof but need not change production
   import selection yet.
11. **Commit B5+C1+C2** only after cache-on and cache-off output are equivalent
   and all existing architecture gates pass. Replay the Rhad donor only after
   the protected Docker Rhad, Hodur/Sub7ffd, and Tigress gates are green.

Every commit must preserve direct reanalysis without an existing cache.  No
commit may introduce a profile-independent import, a sample-specific address,
or a cache-driven state/edge inference rule.


## Appendix

Some thoughts about the plan for persistence, serialized MBA snapshots, netnodes, cache reuse, or B2–B5.

Persistence is worth doing, but it is not a new deobfuscation capability by itself. It turns already-correct PREOPT evidence into a reusable source artifact. The payoff is faster repeat decompilation, survival across IDA restarts, reproducible debugging, and optional transfer between compatible IDBs.

It should only begin after the fresh, cache-disabled path is correct. Otherwise we will make incorrect evidence durable.

### What B2–B5 unlock

| Stage | Required work | Functionality unlocked |
|---|---|---|
| B2: eager preflight | Add the capability seam, invoke it before D810-owned decompiles, retain the universal flowchart fallback, and keep it idempotent across redo | Evidence or a cache hit can be available for the first PREOPT pass, including direct/F5 decompilation |
| B3: snapshot envelope | Serialize a detached PREOPT MBA, attach an exact manifest, validate fingerprints/SDK/anchors, and safely deserialize it | A PREOPT template becomes an immutable, inspectable, testable in-memory artifact |
| B4: netnode persistence | Store validated envelopes in a dedicated netnode, implement atomic replacement, strict import/export, corruption handling, and invalidation | Templates survive plugin reloads and IDA restarts; optional JSON artifacts can move between compatible IDBs |
| B5: cache reuse | Select validated snapshot → fresh generation → abstention, live-rebind every endpoint, import through the normal gateway, and fail open | Actual cache hits: avoid regenerating/capturing source PREOPT microcode while preserving fresh-path behavior |

These boundaries already appear in [TODO.md](/Users/mahmoud/src/idapro/d810/TODO.md:1046), [B3](/Users/mahmoud/src/idapro/d810/TODO.md:1089), [B4](/Users/mahmoud/src/idapro/d810/TODO.md:1145), and [B5](/Users/mahmoud/src/idapro/d810/TODO.md:1181).

### Important corrections to the current design

1. Do not build PREOPT reuse on the existing `OptimizationCache`.

   Its current fingerprint is effectively `mba.qty:mba.maturity`; it does not hash native bytes, profile configuration, closure ranges, or SDK state. It is also designed around replaying patch descriptions, which is the wrong abstraction for PREOPT source reuse. See [caching.py](/Users/mahmoud/src/idapro/d810/src/d810/backends/hexrays/evidence/caching.py:118).

   We can reuse the generic netnode primitive, but `PreoptTemplateCache` should be a separate typed cache.

2. The existing netnode write is not atomic.

   String replacement deletes the prior value before writing the new one. A failed write can therefore lose the previous valid record, contradicting B4’s contract. See [persistence.py](/Users/mahmoud/src/idapro/d810/src/d810/core/persistence.py:346).

   B4 needs either:

   - a two-slot generation scheme with an active-record pointer, or
   - a staging record that is written, read back, validated, and only then promoted.

   Fault-injection tests should prove that every interrupted step leaves the previous record readable.

3. The manifest should embed `NativePreanalysisKey`.

   The proposed manifest repeats the seven fields already owned by the new key: input identity, processor, bitness, function RVA, function fingerprint, profile fingerprint, and SDK fingerprint. See [native_preanalysis_key.py](/Users/mahmoud/src/idapro/d810/.worktrees/decomp-session-foundation/src/d810/core/native_preanalysis_key.py:37).

   Duplicating them creates two schemas that can drift. I would use:

   ```text
   PreoptTemplateManifest
     schema_version
     native_key: NativePreanalysisKey
     maturity
     decompiler_flags
     evidence_epoch
     native_anchor_rvas
     closure_fingerprint
     payload_sha256
     payload_length
   ```

4. We must decide whether we are caching only source microcode or all evidence.

   The current B3–B5 design caches only the PREOPT source MBA. That avoids `gen_microcode()` and template capture, but native resolver facts and boundary evidence may still need to be recovered each session.

   That is the right first version. Persisting the complete `NativePreanalysisFacts` aggregate would eliminate more work, but adds another schema and a substantially larger invalidation surface. I would defer full fact caching until source-template equivalence is proven.

5. Deserialization is the largest technical uncertainty.

   Hex-Rays exposes `mba_t.serialize()` and `mba_t.deserialize()` directly, returning a newly allocated MBA ([IDA binding](/Users/mahmoud/src/idapro/d810/_gitless/resource/9.3/ida/python/ida_hexrays.py:9914)). Python exception handling cannot protect us if malformed input crashes inside the native SDK.

   Before broad implementation, run a narrow Docker runtime probe covering:

   - repeated serialize/deserialize/verify/destruction cycles;
   - empty, truncated, and corrupted payloads;
   - ownership and cleanup;
   - exact supported IDA/Hex-Rays version;
   - detached source use after the original MBA is gone.

   Initial cache compatibility should be same-SDK only. Cross-SDK deserialization should be rejected through `sdk_fingerprint`.

### Recommended implementation sequence

1. Finish the fresh-path foundation and B2.

   Preflight, flowchart fallback, lifecycle ownership, identity rebinding, and one controlled redo must be green with caching disabled.

2. Land the pure B3 manifest.

   Deterministic encoding, exact key matching, closure-range fingerprinting, anchor normalization, payload digest/length, size limits, and strict schema rejection. No Hex-Rays imports.

3. Land the Hex-Rays snapshot backend.

   Capture bytes from a detached PREOPT source; deserialize into a new MBA; verify maturity, anchors, instruction count, graph integrity, and ownership. Return `None` on supported failures.

4. Land the atomic B4 cache.

   Dedicated `$ d810.preopt_template_cache`, staging/promotion, malformed-record handling, blob fallback, replacement, deletion, and garbage collection. Then add explicit JSON/base64 export/import.

5. Integrate cache loading during B2 preflight.

   A miss, corrupt record, mismatch, or deserialization failure must silently fall through to fresh analysis without requesting a redo merely because the cache failed.

6. Implement B5 source selection.

   Use:

   ```text
   validated current-session snapshot
       -> freshly generated PREOPT template
       -> abstain
   ```

   Rebind every source, target, and conditional boundary through the live identity index before scheduling any mutation. Fictitious EAs remain provenance only.

7. Write only after success.

   Cache a fresh template only after source import, live-MBA verification, D810 verification, and semantic checks succeed. Never cache merely because serialization succeeded.

8. Run the three-way oracle matrix.

   For each Rhad target:

   ```text
   cache disabled
   fresh capture + cache write
   cache load
   ```

   All three must produce equivalent semantic output. Then run Hodur, Sub7ffd, Tigress, and Approov with the cache code inert outside the opted-in computed-goto profile, as required by [TODO.md](/Users/mahmoud/src/idapro/d810/TODO.md:1227).

I would expect roughly 7–9 logical commits. B3 serialization and B5 live rebinding are the high-risk pieces; B4 storage is mechanically straightforward once atomic replacement is designed correctly.
