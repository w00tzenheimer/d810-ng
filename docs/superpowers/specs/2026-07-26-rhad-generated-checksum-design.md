# Rhad GENERATED Checksum Design

## Status and scope

This design amends active ticket `lrea-t5gy`. It preserves the current branch's
transaction foundation and replaces the immediate broad PREOPT objective with
one bounded checksum:

- function: `0x40A560`;
- reference operation: the `cmovl`-selected indirect transfer spanning
  `0x40A5F0-0x40A605`;
- comparison constant: `0x0BB2D365`;
- semantic targets: taken `0x40B6C0`, fallthrough `0x40A607`;
- boundary exits: `0x40A61B`, `0x40A68C`, `0x40B790`.

Success means that this one operation is compiled from portable reference
evidence, published at actual `MMAT_GENERATED` through the existing shared
coordinator, survives PREOPT and the first authoritative CFG, is merely
observed at CALLS, and reaches ctree without redo, poison, or an INTERR. It does
not mean full A560 restoration.

## Authorities

The current worktree is authoritative for:

- `FragmentPlan -> PatchPlan -> final binding`;
- `CfgTransactionCoordinator` ordering;
- immutable projection and preflight;
- `MbaMutationGateway` transaction ownership;
- `DeferredGraphModifier` as the sole low-level mutation implementation;
- creation reservations and witnesses;
- mutation receipts and semantic ownership;
- generation poisoning and lifecycle-controlled restart;
- diagnostic events and SQLite persistence.

The replay worktree is behavioral evidence for:

- the Rhad reference-operation vocabulary and phase ordering;
- the exact A560 conditional orientation;
- the nine-block imported closure;
- the three boundary exits;
- the 19 deferred operation identities and 13 semantic effect identities;
- the GENERATED, PREOPT, LOCOPT, and CALLS acceptance observations.

The historical experiment is evidence only. No donor transaction API, handler
registry, live-object cache, or mutation implementation is an authority.

## Runtime fact that changes the replay design

On IDA 9.3, `hxe_microcode` observes an MBA whose numeric maturity is still
`MMAT_ZERO`. The first instruction-optimizer callback whose live MBA reports
`MMAT_GENERATED` is the actual GENERATED publication boundary. Both snapshots
have nine blocks, no authoritative CFG edges, and incomplete use-def lists.

Therefore:

- publication is emitted from `optinsn_adapter` on the first top-level
  `MMAT_GENERATED` maturity transition;
- `hxe_microcode` remains lifecycle setup and observation only;
- no code calls `mba.build_graph()` or constructs use-def lists at GENERATED;
- LOCOPT is the first authoritative CFG maturity for this checksum.

Every runtime block label in diagnostics includes both the callback-local
serial and a native EA anchor, for example `blk13@0x40B6C0`.

## Approaches considered

### A. Add a GENERATED profile to the current transaction path (selected)

The manager prepares one immutable portable ledger and compiles it into a
current `FragmentPlan`. The actual GENERATED event creates the current-MBA
identity index, gateway, native-body materializer, and `HexRaysMutationBackend`.
The backend lowers the plan through the existing `FragmentTransactionParticipant`
and `CfgTransactionCoordinator`.

The semantic publication lifecycle receives an explicit GENERATED profile. It
uses plan-local structural projection before mutation, final live binding, the
same deferred queue, one backend `mba.verify(True)`, and the same committed
receipt. It does not demand a live CFG projection or re-lift the MBA after
commit. Later maturity observers validate graph properties when Hex-Rays has
actually built the graph.

This is selected because it preserves every current authority while changing
only the maturity-specific observation contract.

### B. Invoke the current PREOPT frontend-normalization adapter at GENERATED

This would reuse more call sites, but it is not semantically valid. The adapter
lifts the live MBA before planning and the backend re-lifts after commit. At
GENERATED there is no authoritative graph, so those lifts either force or
pretend graph authority. Its evidence provider also discovers broad PREOPT work,
which would resume the wrong objective.

Rejected.

### C. Port the replay publisher and GENERATED gateway methods

The replay has a custom handler registry, prepared-publication registry,
generated gateway API, direct `DeferredGraphModifier` construction, manual
reachability validation, and callback-local state flags. Copying those pieces
would create a second transaction path and weaken the current coordinator.

Rejected.

## Portable reference evidence

The compiler input is an immutable, serial-free ledger. For this checksum it
contains:

- ledger identity and reference provenance;
- function/native key and evidence generation;
- source block interval and exact instruction EAs;
- predicate/flag producer EA `0x40A5F0`;
- native comparison constant `0x0BB2D365` and signed comparison semantics;
- normalized microcode branch anchor EA `0x40A5F6`;
- unresolved transfer EA `0x40A605`;
- owned replacement corridor EAs
  `(0x40A5F0, 0x40A5F6, 0x40A5FE, 0x40A601, 0x40A605)`;
- normalized signed-less-than semantics;
- true target EA `0x40B6C0`;
- false target EA `0x40A607`;
- exact imported blocks and native ranges;
- exact boundary exits;
- reference phase `indirect_jump_reconstruction` and dependency identities.

The exact imported closure, derived from the replay diagnostic database, is:

| Block identity | Native interval |
|---|---|
| `native@0x40A607` | `[0x40A607, 0x40A615)` |
| `native@0x40A615` | `[0x40A615, 0x40A61B)` |
| `native@0x40A619` | `[0x40A619, 0x40A61B)` |
| `native@0x40A680` | `[0x40A680, 0x40A68C)` |
| `native@0x40A68A` | `[0x40A68A, 0x40A68C)` |
| `native@0x40B6C0` | `[0x40B6C0, 0x40B6CA)` |
| `native@0x40B6CA` | `[0x40B6CA, 0x40B6D0)` |
| `native@0x40B6D0` | `[0x40B6D0, 0x40B6D6)` |
| `native@0x40B6D4` | `[0x40B6D4, 0x40B6D6)` |

The portable compiler lives under `d810.transforms`. It imports no IDA,
Hex-Rays, backend, mutation, optimizer, hook, or manager module. It rejects:

- a stale or foreign native key/evidence generation;
- an unsupported operation category;
- a missing or ambiguous source, target, imported block, or boundary exit;
- a condition orientation not explicitly represented by the ledger;
- a corridor that omits the producer or terminal transfer;
- duplicate/conflicting imported identities;
- a phase dependency violation.

The operation inventory names the three ordered reference phases and records
unimplemented categories as deferred. The checksum compiler admits only the
selected conditional indirect-jump shape.

## Compiled FragmentPlan

The compiler produces one `FragmentPlan` with:

- one original source block and one cloned replacement rooted at `0x40A5F0`;
- one `FragmentComputedBranchNormalization` describing the `cmovl` envelope;
- one conditional `FragmentOperation` with explicit taken and fallthrough
  semantic edges;
- one flag corridor from producer `0x40A5F0` to consumer `0x40A605`;
- nine `IMPORT_NATIVE` blocks owned by one `FragmentNativeBody`;
- typed boundary ports for `0x40A61B`, `0x40A68C`, and `0x40B790`;
- one work-item/atomic-group identity for the whole semantic fragment;
- reference route authority and provenance attached to the route operation.

The semantic operation is indivisible. The predicate, both arms, terminal
rewrite, imported closure, physical fallthrough helper, and boundary bindings
cannot publish or receipt independently.

The compiler adapts replay vocabulary to current plan fields. It does not add
replay-only duplicate predicate/phase fields when current
`ReferenceRouteRewrite`, `FragmentReferenceRouteAuthority`,
`FragmentComputedBranchNormalization`, or work-item authority already carries
the same fact.

## GENERATED producer and event ownership

`DecompilationEvent` gains `HEXRAYS_GENERATED_READY`. The lifecycle context
tracks whether it was emitted for the current MBA generation, exactly as it
does for PREOPT. A generation reset clears both guards.

`optinsn_adapter` emits the event only when all are true:

- the live MBA maturity is exactly `MMAT_GENERATED`;
- the callback belongs to the active top-level session;
- native preanalysis is not recursively active;
- the event has not already run for this MBA generation;
- a graph-free current-MBA identity index is available;
- the existing gateway and native-body materializer factories succeed.

The hook is a thin dispatcher. It imports no Rhad optimizer or producer module.
The manager installs the Rhad GENERATED listener and supplies all ports through
the event decision.

The producer:

1. obtains the portable checksum ledger owned by the session;
2. compiles or retrieves the immutable compiled `FragmentPlan`;
3. creates `HexRaysMutationBackend` with the current gateway and materializer;
4. calls the backend's sole `apply` entry using the GENERATED transaction
   profile;
5. reads the committed receipt and current-MBA binding from the backend;
6. records diagnostic intent and marks `microcode_modified`;
7. performs no direct MBA or deferred-modifier mutation.

Expected evidence rejection occurs before the first write and is recorded as a
clean failed obligation. `CfgGenerationPoisoned` is not swallowed.

## Graph-free GENERATED transaction profile

The current coordinator remains the only coordinator. The GENERATED profile
changes validation timing, not authority or lowering:

```text
portable ledger
  -> FragmentPlan
  -> immutable structural projection and preflight
  -> current identity binding
  -> FragmentPlan-to-PatchPlan lowering
  -> final-boundary binding
  -> shared coordinator
  -> DeferredGraphModifier queue/apply
  -> mba.verify(True)
  -> gateway commit and receipt
```

At GENERATED:

- identity indexing does not call `build_graph()`;
- preflight validates block/instruction identity, operation ownership,
  imported native-body preparation, target binding, boundary binding, effect
  inventory, and plan-local ordering;
- staging keeps created blocks graph-neutral until Hex-Rays builds CFG state;
- no full live `CfgContract` assertion is made against absent successor lists;
- post-write validation checks exact live instructions, operands, imported
  witnesses, boundary facts, effect inventory, and `mba.verify(True)`;
- commit uses the existing gateway receipt;
- backend return does not re-lift an authoritative `FlowGraph` that does not
  exist yet.

PREOPT and later transaction profiles retain current behavior. A profile must
be explicit; maturity is never inferred from an incidental empty edge set.

## Failure policy

All expected failures occur during compiler validation, immutable projection,
native-body preparation, exact binding, or queue preflight before the first
live write.

After the first write, any exception poisons the current MBA through the
existing gateway and lifecycle authority. The current coordinator records the
first failed obligation and INTERR code, invalidates generation-local bindings,
and requests one controlled lifecycle restart. The producer never rolls back a
partially written GENERATED MBA and never continues it. The successful checksum
path requests no restart or redo.

## Receipt and diagnostics

The diagnostic database is the primary acceptance artifact. Existing generic
transaction tables remain authoritative. Rhad-specific lifecycle observations
link to the generic plan/attempt/batch identities; they do not create another
receipt model.

The committed receipt must prove:

- one `FragmentPlan`, one atomic group, and one mutation batch;
- 19 deferred operations: nine creates, nine imports, one route;
- 13 semantic effects: nine native bodies, one replacement, one fallthrough
  helper, one conditional-taken edge, one conditional-fallthrough edge;
- nine creation witnesses reconstructing every imported block;
- the three boundary exits;
- exact final current-MBA binding;
- backend verification true;
- poison false and redo false.

Maturity observations are separate from mutation receipts:

- GENERATED: indirect transfer at `0x40A605` is absent and both direct route
  operands exist before PREOPT;
- PREOPT: both semantic targets survive; the graph is explicitly
  non-authoritative;
- LOCOPT: first authoritative graph, both roots and imported closure are
  reachable according to the route contract;
- CALLS: the precommitted route is observed exactly once, Rhad planning and
  mutation are false, and redo is false;
- ctree: decompilation completes with no numeric INTERR.

Diagnostics label route-level C6 separately from whole-function A560 C6.

## Rejected replay dependencies

The following replay mechanisms are not ported:

- `hxe_microcode` as the claimed `MMAT_GENERATED` boundary;
- generated/preopt/locopt/calls global handler registries;
- fail-open broad `Exception` handling;
- custom prepared-publication registries and resolver-state live payloads;
- custom `publish_generated_fragment` gateway methods;
- direct construction or invocation of `DeferredGraphModifier` by the producer;
- replay `GeneratedFragmentMutationBackend` transaction machinery;
- manual successor/predecessor edits, block ordering, or reachability walks in
  the Rhad producer;
- private imports from `computed_goto_resolver`;
- `mba.build_graph()` at GENERATED;
- hard-coded callback-local block serials;
- sample-EA guards embedded in generic transaction code;
- post-commit graph re-lift at GENERATED;
- a compatibility bridge between old and current publication APIs.

Exact checksum addresses belong in pinned portable reference evidence and
acceptance tests, not in generic mutation infrastructure.

## Verification boundary

Acceptance requires all of the following:

1. strict 41-row transaction parity gate passes;
2. pure compiler tests pass without live Hex-Rays modules;
3. GENERATED seam and once-per-generation lifecycle tests pass;
4. transaction tests prove pre-write rejection and post-write poison;
5. exact route tests prove operation orientation, closure, boundaries, effect
   inventory, receipt, and no alternate mutation path;
6. `sg scan --config sgconfig.yml --report-style short` passes;
7. `PYTHONPATH=src lint-imports --config .importlinter` passes;
8. focused unit, runtime, and protected-family suites pass;
9. the exact cache-disabled Docker canary reaches ctree without INTERR;
10. diagnostic SQL proves GENERATED, PREOPT, LOCOPT, CALLS, and ctree facts;
11. the input binary SHA-256 remains
    `2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c`;
12. `graphify update .` refreshes the project graph.

The final report compares current evidence with the replay obligation by
obligation and names the first unmet obligation if any item remains red.
