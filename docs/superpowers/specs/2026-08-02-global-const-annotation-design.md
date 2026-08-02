# Function-Referenced Global Const Assistance Design

## Goal

Let a user inspect the globals referenced by one function, use D810's existing
constant-memory evidence to improve decompilation, and optionally persist a
reversible `const` qualifier in the IDB. The feature must not describe absence
of direct write xrefs as proof that a writable global is immutable.

The first useful slice is an explicit, function-scoped command. Existing
microcode folding remains the default optimization path; IDB type mutation is
opt-in and starts with a dry-run preview.

## Non-goals

- Proving that arbitrary writable memory is immutable under pointer aliasing.
- Automatically changing IDB types during every decompilation.
- Replacing `FoldReadonlyDataRule`, `GlobalConstantInliner`, `MopTracker`, or
  initializer-stable global-read analysis.
- Removing a user-authored `const` qualifier merely because a direct write xref
  exists.
- Treating a type annotation receipt as semantic-output verification.

## Existing Foundations

- `FoldReadonlyDataRule` already folds direct globals and table loads. Its
  `fold_writable_constants` option accepts writable-segment addresses with no
  direct `dr_W` xref.
- `GlobalConstantInliner` performs the complementary flow-level rewrite for
  direct and nested `mop_v` operands.
- `compute_initializer_stable_global_reads()` is the stronger per-read proof:
  the static initializer is usable only when no modeled store reaches that read.
- `D810ActionHandler` provides auto-registered actions, injected IDA modules,
  and deferred execution required for stable context-menu mutations.
- The case producer materializes only terminal sessions from typed evidence
  sources. A const-annotation plan or receipt must therefore be a typed source,
  not an opaque log line or `payload_json` convention.

## Approaches Considered

### Port the script as a context-menu action

Reuse native data refs, `dr_W` checks, `tinfo_t.set_const()`, and
`apply_tinfo()` in one action module. This is the smallest textual change, but
it preserves the script's unsafe claims, misses function chunks and indirect
writes, has no mutation ownership, and would put policy and live mutation in
the UI layer. Rejected.

### Use only existing ephemeral folding

Enable `FoldReadonlyDataRule` with `fold_writable_constants=true` and
`GlobalConstantInliner`; make no IDB changes. This is the safest route to better
pseudocode and should remain the default. It does not satisfy users who need a
durable type annotation visible to Hex-Rays and other IDA views.

### Shared evidence plus explicit reversible annotation

Unify the duplicated global-memory classification, expose a function-scoped
dry-run plan, and put optional `tinfo` mutation behind a backend mutation
adapter with IDB-local ownership receipts. This is selected because it reuses
the optimization machinery, keeps the UI thin, and makes persistent changes
auditable and reversible without overstating the evidence.

## Evidence Model

Add IDA-free models under `d810.analyses.value_flow`:

- `GlobalConstEvidenceKind`: `readonly_segment`, `direct_write_xref`,
  `no_direct_write_xref`, `initializer_stable_read`, `unsupported_item`, and
  `unknown_alias_risk`.
- `GlobalConstCandidate`: canonical item EA and range, display name, item size,
  original type text, source reference EAs, direct write EAs, and ordered
  evidence kinds.
- `GlobalConstDecision`: `mark_const`, `remove_owned_const`, or `skip`, plus a
  stable reason identifier.
- `GlobalConstPlan`: function EA, candidate decisions, counts, and a stable
  digest over all inputs that affect application.
- `GlobalConstReceipt`: candidate EA, plan digest, before/after serialized type
  digests, outcome, and ownership identifier.

The model distinguishes evidence strength:

1. A readable, non-writable data segment is eligible for automatic proposal.
2. A writable segment with no direct write xrefs is advisory evidence only.
   It may continue to drive an explicitly aggressive ephemeral fold, but it is
   not enough for automatic persistent annotation.
3. A direct write xref blocks `mark_const`.
4. An initializer-stable read is a property of one read site, not proof that the
   global is immutable. It permits folding that read but not persistent `const`.
5. Unknown item boundaries, unsupported types, overlaps, indirect access, or
   alias uncertainty fail closed for persistent mutation.

## IDA Evidence Adapter

Add `d810.backends.hexrays.evidence.global_const_candidates`.

For one canonical function start it:

1. Enumerates instructions with `idautils.FuncItems()`, so non-contiguous
   function chunks are included and unrelated gap items are excluded.
2. Collects non-executable data refs and canonicalizes each ref to an IDB item
   head and half-open item range.
3. Records every source instruction EA rather than returning only a set of
   target addresses.
4. Queries read/write xrefs across the entire item range, not only the exact
   referenced byte.
5. Captures segment permissions, item size, current `tinfo`, and whether the
   reference was observed as a source or destination in lifted microcode.
6. Emits portable candidates; it never calls `apply_tinfo()`.

Extract the current no-write-xref policy behind a single injected global-memory
facts interface. `FoldReadonlyDataRule`, `GlobalConstantInliner`, `MopTracker`,
and the emulator should consume the same classification instead of maintaining
similar but divergent checks. The compatibility helper
`is_never_written_var()` may remain temporarily, but its implementation and
documentation must state the exact claim: no direct write xref was observed.

## Planning and Mutation

Add a manager-owned `GlobalConstAnnotationService` that converts evidence into
a plan and exposes `preview`, `apply`, and `revert_owned` commands.

Add `d810.backends.hexrays.mutation.global_const_types` as the only live type
mutation surface. It must:

- verify the plan digest immediately before mutation;
- re-read the current type and reject stale plans;
- preserve the complete serialized original `tinfo`;
- use `TINFO_DEFINITE` only after the preceding checks pass;
- record an IDB-local, versioned ownership receipt keyed by item EA;
- remove or restore a qualifier only when the current type and stored receipt
  still match the type D810 applied;
- abstain instead of overwriting a later user edit;
- return one receipt per candidate, including failed and skipped outcomes.

The IDB-local ownership store belongs in the Hex-Rays backend. A named netnode
with a small versioned JSON or serialized-type payload is sufficient for the
first slice. Portable code sees only the receipt protocol and never imports
`ida_netnode` or `ida_typeinf`.

Application is fragment-atomic at the item level, not across the whole
function: one stale or unsupported item fails without rolling back unrelated
successful items. Each item retains its own authoritative receipt. An
unexpected exception while applying one item restores that item's original
type before proceeding or reports an explicit restore failure.

## User Flow

Add one action, `Inspect referenced global constants`, available in pseudocode
and disassembly views.

1. The action resolves the current function and schedules work on the next Qt
   event-loop tick.
2. The service builds a fresh plan.
3. A compact report lists address, name, current type, evidence, proposed
   action, and reason. The initial state is preview-only.
4. `Apply safe annotations` applies only read-only-segment proposals.
5. `Revert D810 annotations` restores only matching D810-owned receipts.
6. After any committed change, mark the function cfunc dirty and invoke the
   existing manager-controlled decompile path.

Do not add an `Apply aggressive` control in the first slice. Users can already
opt into aggressive ephemeral folding through rule configuration; persistent
annotation of writable globals needs a separate design if real demand appears.
The first slice also skips candidates without an existing, non-empty `tinfo`;
it does not synthesize an integer type from item size.

Expose the same operations through the headless API so runtime tests and
investigation scripts do not automate Qt:

```python
preview_global_const_annotations(function_ea)
apply_global_const_annotations(function_ea)
revert_global_const_annotations(function_ea)
```

## Diagnostics and Case Identity

Add typed observation models and typed diagnostic tables for annotation plans
and receipts. Each row includes the session, plan digest, function EA, item EA
and range, evidence classification, proposed action, before/after type digests,
outcome, and reason. The producer must validate that the referenced source
event belongs to the same session.

The action establishes the manager lifecycle session before applying types,
emits its typed plan and receipts, and only then runs native preanalysis and
decompilation in that retained session. This prevents a mutation from becoming
unattributed pre-session state.

Closed-case `runtime_identity` must incorporate a stable digest of committed
annotation receipts in addition to the native key. Function bytes and project
configuration alone do not distinguish decompilations performed under
different global type environments. The annotation receipt is C0 environment
evidence; it does not advance the case to C1-C6 by itself.

## Failure Semantics

- Missing function, unavailable item/type data, unsupported item size, stale
  plan, direct write evidence, or ownership mismatch produce explicit skips.
- No candidate is interpreted as success: the report states that no eligible
  direct global references were found.
- Diagnostic persistence failure does not silently permit mutation. Because
  the mutation changes durable analysis state, an enabled diagnostic session
  must accept the typed plan before applying it. When diagnostic capture is
  disabled, the IDB-local ownership receipt remains mandatory but no case is
  produced. Receipt persistence failure is reported as an incomplete audit and
  blocks the manager-controlled redecompile.
- Revert refuses to act when the current type differs from the recorded D810
  result. It never guesses how to merge a later user edit.
- Dry-run performs no type, netnode, cfunc-cache, project, or diagnostic writes.

## Delivery Slices

This design is intentionally delivered as dependent implementation plans, not
one oversized change:

1. **Evidence and preview:** portable models, the IDA evidence adapter,
   range-aware direct-write classification, a read-only manager preview API,
   and dry-run/headless tests. No type or diagnostic schema changes.
2. **Owned mutation:** the backend type adapter, IDB-local receipts,
   apply/revert service commands, cache invalidation, and IDA round-trip tests.
3. **User surface:** the thin context-menu report/action and headless parity.
4. **Case authority:** typed diagnostic plan/receipt sources, terminal-case
   projection, and annotation-aware runtime identity.
5. **Policy consolidation:** migrate the existing folding rules and evaluators
   to the shared classifier without changing their configured aggressive-mode
   behavior.

The first implementation plan covers slice 1 only. Each later slice begins
after the preceding slice's contracts and tests are green.

## Verification

Unit tests must cover:

- portable classification and decision tables;
- function chunks and exclusion of range gaps;
- canonical item heads, interior refs, and overlapping write ranges;
- direct writes, no direct writes, read-only segments, executable segments,
  missing segments, and unsupported types;
- dry-run non-mutation across type, receipt store, cfunc cache, and diagnostics;
- apply/revert ownership, stale-plan rejection, later-user-edit preservation,
  partial item failure, and restoration after an exception;
- one shared classification consumed by the folding rules and evaluators;
- typed plan/receipt schema equivalence and closed-case projection;
- annotation receipt digest changing closed-case runtime identity;
- action availability, deferred execution, report commands, and redecompile
  invalidation;
- headless preview/apply/revert parity.

Runtime tests in IDA must prove:

- a referenced read-only global receives `const`, changes the relevant
  decompilation when appropriate, and round-trips to its exact original type;
- a writable global with a direct write is skipped;
- a writable global with no direct write xref remains preview-only;
- a user type edit after application prevents automatic revert;
- function-tail references are included;
- the resulting diagnostic database contains the typed plan and receipt tied
  to the terminal session.

Before completion, run focused tests plus the worktree boundary gates:

```bash
pyenv exec python -m pytest -q \
  tests/unit/analyses/value_flow/test_global_const_annotations.py \
  tests/unit/backends/hexrays/evidence/test_global_const_candidates.py
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
```

## Acceptance Criteria

- Existing rule configurations continue to produce ephemeral constant folding
  without any IDB type mutation.
- Preview accurately reports every directly referenced non-executable data item
  in all function chunks and performs zero writes.
- Default apply mutates only eligible read-only-segment items.
- D810 can exactly restore only the types it owns and never overwrites a later
  user edit.
- Persistent annotation plans and receipts are typed, queryable case evidence,
  and their digest participates in closed-case runtime identity.
- Portable layers remain free of live IDA imports and UI code remains a thin
  dispatcher/renderer.
