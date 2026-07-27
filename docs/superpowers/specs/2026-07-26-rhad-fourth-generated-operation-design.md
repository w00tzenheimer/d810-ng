# Rhad Fourth GENERATED Operation Design

## Scope and selected reference evidence

This bounded vertical amends active ticket `lrea-t5gy`, preserves the accepted
33/33 four-operation receipt at `fd81625f8`, and proves exactly one new
reference shape. The 228-row inventory selects the earliest unproved
`setcc_indexed_table` operation:

- reference order 16, `rhad:route@0x40A77C`;
- reference symbol `JumpInliner._fixup_index_access`;
- source block `0x40A766`, flag producer `cmp@0x40A768`, and
  `setl@0x40A76E`;
- `shl eax, 5` at `0x40A771`, table load at `0x40A774`, additive decode at
  `0x40A77A`, and unresolved `jmp eax` at `0x40A77C`;
- signed-less-than true target `0x40A77E` and false target `0x40ABC6`.

The immutable evidence artifact is
`docs/experiments/rhad-a560-setcc-indexed-table-row16-evidence.json`. It is
derived from the unchanged SHA-256
`2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c`
and pinned reference commit `21b0d4783703bc4fb6910cfae51d92cd683d2c65`.

The exact index proof is not merely two target constants. `xor eax,eax`
prezeros all 32 bits, `setl al` writes an 8-bit Boolean, and the untouched high
bits therefore provide an exact zero extension to a 32-bit index. The shift by
5 admits byte offsets 0 and 32 into 32-bit little-endian table entries at
`0x48B81C` and `0x48B83C`. Adding the ESI key `0xFDEE1C81` modulo 2^32 maps
entry 0 (`0x02528F45`) to `0x40ABC6` and entry 1 (`0x02528AFD`) to
`0x40A77E`. No flag writer intervenes between the comparison and `setl`.

## Considered approaches

### 1. Dedicated typed setcc-table normalization (selected)

Add a required `RhadSetccIndexedTableRoute` compiler input and a dedicated
FragmentPlan normalization subtype carrying immutable table-selection
evidence. Compile it to one conditional `FragmentOperation`, one flag
corridor, exact reference authority, and the existing two semantic edge roles.
The PREOPT materializer prepares the imported source as one conditional block;
the existing GENERATED graph-free realizer binds its taken destination and
proves physical fallthrough to the false destination.

This preserves one reference operation as one atomic semantic operation and
makes every table claim available to preflight and SQLite diagnostics.

### 2. Extend existing conditionals with optional table fields (rejected)

Optional table fields would admit partially populated compatibility states and
blur whether a source/select/join topology or a setcc-table topology is owned.
That violates typed first-failure diagnostics.

### 3. Lower the table entries as two direct routes (rejected)

This would erase the flag producer, setcc orientation, index construction, and
table interpretation. It would also split one reference operation into sibling
mutations that could no longer be rejected atomically.

## Portable compiler and FragmentPlan contract

`RhadSetccIndexedTableRoute` requires operation identity, reference order,
variant, symbol, source identity, source and transfer EAs, flag producer,
setcc, zeroing, shift, lookup, additive decode, predicate orientation, exact
owned corridor, table identity, base, widths, extension kind, stride, entry
interpretation, additive key evidence, the two admitted indices and entries,
derived semantic targets, imported closure, boundary exits, phase, selected
scope, native-body proof, and dependencies.

The compiler rejects before live mutation when any of these is ambiguous or
mismatched: reference order or variant, anchor ordering, flag interference,
non-exact source ownership, nonzero or non-Boolean indices, partial-register
extension, shift/stride disagreement, table base or entry width, byte order,
entry address, raw entry value, additive interpretation/key, derived target,
target role/orientation, incomplete closure, foreign target, missing body
proof, unselected work-item scope, mismatched `RouteOracleRun`, or missing
reference authority.

The compiled plan uses a dedicated `FragmentSetccIndexedTableNormalization`
rather than optional fields on `FragmentComputedBranchNormalization`. Its
required `FragmentSetccIndexedTableEvidence` persists the exact derivation in
the plan and reference ledger JSON. The generic `FragmentFlagCorridor`
separately proves that `cmp@0x40A768` supplies `setl@0x40A76E` without an
intervening flag write.

## Dependency-closed batch and publication

The accepted four operations remain unchanged. Reference-order row 16 also
requires row 14 `route:rhad-direct@0x40A74A` (compiled from reference operation
`rhad:route@0x40A74A`) and row 15
`rhad:route@0x40A764`. The resulting seven-operation batch imports the complete
union of their source and target closures. Internalized exits are removed from
the batch boundary; the expected remaining exit set is `0x40A633`,
`0x40A794`, `0x40A9A0`, `0x40ADCE`, `0x40AEE6`, `0x40B1D0`, and
`0x40B790`.

The manager remains a typed exact-input registry selected by
`NativePreanalysisKey`, never by sample EA guards. It captures the additional
target-rooted PREOPT templates before the live MBA and compiles the complete
batch before publication. Actual mutation still occurs once at
`MMAT_GENERATED` through `FragmentPlan -> PatchPlan -> immutable preflight ->
final binding -> shared coordinator -> gateway -> committed receipt`.

The detached materializer already knows how to synthesize a conditional from
portable signed-predicate evidence. A narrow typed realization branch may bind
the prepared setcc source only when the plan subtype, reference authority,
native-body proof, exact live instruction origin, two target bindings, and
physical false-target fallthrough all agree. It uses no helper, graph rebuild,
use-def construction, local optimization, direct modifier path, second
receipt, rollback-after-write, or CALLS mutation.

## Diagnostics and acceptance

The SQLite compiled event persists the row-16 evidence identity and full
reference ledger JSON. The one receipt covers all seven operations and their
required closure; creation witnesses reconstruct every created block. Maturity
observation is derived from typed operations and proves the selected
`0x40A77C` indirect transfer absent, exact two-target behavior while source
topology exists, legitimate later source retirement without residual indirect
transfer, reachable required semantics, PREOPT/LOCOPT/CALLS observations, and
CMAT_FINAL. CALLS remains observation-only.

Acceptance reruns the permanent `0x40A605`, `0x40A619`, and `0x40A6A4`
checksums plus the new row-16 checksum, focused compiler/publication suites,
transaction/runtime suites, the protected-family matrix, strict 41-row gate,
ast-grep, all import-linter contracts, input hash, and `graphify update .`.
Success proves four distinct reference shapes. It does not restore all A560
operations and stops before constant materialization.
