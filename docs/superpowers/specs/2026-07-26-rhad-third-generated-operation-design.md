# Rhad Third GENERATED Operation Design

## Scope and selected reference evidence

This bounded vertical amends active ticket `lrea-t5gy` and preserves the two
accepted operations at `0x40A605` and `0x40A619`. It adds the earliest
reference-ordered variant without an isolated GENERATED proof:

- reference order: 8;
- operation: `rhad:route@0x40A6A4`;
- variant: `existing_conditional_plus_indirect`;
- reference symbol: `JumpInliner._fixup_jmp_and_possible_jcc`;
- source: `0x40A68C`, flag producer `0x40A692`, predicate `0x40A698`;
- unresolved transfer: `0x40A6A4`;
- normalized predicate: signed less-than;
- taken target: `0x40A6A6`;
- fallthrough target: `0x40A800`;
- owned corridor: `0x40A68C`, `0x40A698`, `0x40A69A`, `0x40A6A0`,
  `0x40A6A2`, `0x40A6A4`.

The native `jl 0x40A6A0` preserves the initial table pointer on signed less
than and skips the selected-value overwrite at `0x40A69A`. Reference evidence
therefore orients signed less-than to `0x40A6A6` and signed greater-or-equal to
`0x40A800`.

The selected source is reached through reference-order operation 7,
`route:rhad-direct@0x40A68A`, which rewrites `0x40A68A -> 0x40A68C`. That
already-supported simple operation is a required sibling in the atomic batch;
the goal remains a third *variant* proof rather than a third operation total.

## Coverage and first unmet obligations

The authoritative 228-row inventory contains 39 cmov-selected, 64 simple, 117
existing-conditional, and 8 setcc-indexed operations. The current compiler
vocabulary covers all cmov-selected and simple rows, but only one instance of
each is compiled and vertically proved. Existing-conditional and setcc-indexed
rows have no typed compiler vocabulary or vertical proof.

Reference row 8 records the `0x40A800` target closure as complete but records
the `0x40A6A6` target as
`root_unavailable_in_current_portable_source_plan`. Compilation must reject
until the batch's typed source plan and cached PREOPT template capture own that
arm. The first compiler gap is a serial-free imported conditional-select route;
the first realization gap is graph-free GENERATED binding of an imported
conditional-select that was normalized while its native body was detached.

## Considered approaches

### 1. Typed imported conditional route (selected)

Add a required `RhadExistingConditionalRoute` evidence type. Compile it to the
existing `FragmentComputedBranchNormalization`,
`FragmentImportedConditionalSelectEnvelope`, conditional edges, flag corridor,
and `FragmentReferenceRouteAuthority`. Extend only the existing GENERATED
native-body staging contract so its already-prepared imported source/select/join
roles bind to the two semantic targets before publication.

This preserves serial-free compiler evidence, native-body proof ownership,
immutable preflight, and the single coordinator. It makes ambiguity reject
before live mutation.

### 2. Add mode fields to `RhadConditionalRoute` (rejected)

Optional fields could switch between replacement and imported sources. That
would create compatibility states in which selected/join block IDs and
selected/join identities are partially populated. It conflicts with the
requirement for a typed first failed obligation.

### 3. Lower the two branch arms as direct operations (rejected)

This would erase the native predicate producer and branch orientation from the
operation identity, split one reference operation into unrelated mutations,
and weaken atomic sibling closure. It is not faithful to the reference shape.

## Portable compiler contract

`RhadExistingConditionalRoute` requires:

- stable operation ID, reference order, variant, and symbol;
- source block ID plus source, block-anchor, flag-producer, predicate,
  selected-value, join, and transfer EAs;
- observed and final portable predicate kinds;
- exact taken and fallthrough target block IDs;
- proof-owned corridor, imported closure, boundary exits, phase, and ordered
  dependencies.

The compiler validates exact native ordering, distinct arms, complete closure,
source and envelope identity ownership, native-body `proof_ids`, selected
frontend obligation, matching `RouteOracleRun`, and reference authority. It
emits one conditional `FragmentOperation`. Missing authority, an incomplete
arm, wrong predicate orientation, absent body proof, a foreign oracle run,
unselected scope, or ambiguous/out-of-corridor anchors rejects before live
mutation.

The accepted replacement `RhadConditionalRoute` and imported
`RhadDirectRoute` remain unchanged.

## Dependency-closed batch and GENERATED realization

The FRONTEND_NORMALIZATION batch contains:

1. accepted `rhad:route@0x40A605`;
2. accepted `route:rhad-direct@0x40A619`;
3. dependency `route:rhad-direct@0x40A68A`;
4. selected `rhad:route@0x40A6A4`.

The batch imports the complete union of source and target bodies, including a
typed template root for `0x40A6A6`. The current manager producer captures and
precompiles these bodies before the live MBA, then invokes the existing backend
once at actual MMAT_GENERATED.

The PREOPT native-body materializer already proves and normalizes imported
conditional-select templates. The GENERATED extension adds a typed staging
callback that binds the prepared source branch, selected arm, and join to the
operation's two target bindings without `build_graph`, use-def construction,
local optimization, or another receipt. The shared coordinator remains the
only mutation authority and runs `mba.verify(True)` only after the whole batch.

## Diagnostics and acceptance

SQLite persists inventory identity, all four ordered operation payloads,
FragmentPlan serialization, projection/preflight, live bindings, phases,
selected obligations, witnesses, receipt, and poison/rollback/redo state.
Maturity observations prove all three selected transfer EAs absent while their
source topology exists, exact targets retained or legitimately subsumed, no
reference-owned indirect transfer reappearing, CALLS observation-only behavior,
CMAT_FINAL, and no numeric INTERR.

The exact E2E, protected-family matrix, strict parity gate, ast-grep, all import
contracts, immutable input SHA, inherited-backend no-regression comparison, and
graphify update remain mandatory. Success proves three distinct indirect-jump
variants only; it does not prove all 228 operations or full A560 restoration.
