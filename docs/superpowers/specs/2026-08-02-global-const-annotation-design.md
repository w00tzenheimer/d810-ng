# Constant Simplification and Global Const Assistance Design

## Goal

Give users one public constant-simplification operation instead of asking them
to choose among overlapping rules:

- `FoldReadonlyDataRule`;
- `ConstantSubtreeFoldRule`;
- `GlobalConstantInliner`; and
- `ForwardConstantPropagationRule`.

The public operation is **Simplify constants**. Internally it has three ordered
stages:

1. resolve constant memory reads;
2. fold constant expressions; and
3. propagate constants through the function.

All memory-read decisions come from one constness oracle. A later, optional
global-annotation feature may consume the same oracle, but persistent IDB
mutation is not the organizing concept of the optimizer.

## The Current Problem

The current names expose implementation history rather than a coherent user
model.

- `FoldReadonlyDataRule` materializes values loaded from global memory.
- `GlobalConstantInliner` performs another form of global-value
  materialization at flow level.
- `ForwardConstantPropagationRule` propagates register and stack constants,
  but also carries a private read-only `ldx` resolver that overlaps the memory
  rule.
- `ConstantSubtreeFoldRule` is a downstream expression simplifier, yet it
  appears beside the memory and propagation mechanisms as if it were an
  alternative.
- `allow_executable_readonly` exposes a segment-layout exception to users.
  It does not explain whether D810 is accepting code bytes, a Mach-O data item
  stored in an executable segment, or all read-only executable memory.

This makes users compose the pipeline themselves and makes it possible for the
implementations to disagree about the same read. Consolidation must remove
both problems, not merely rename the rules.

## User-facing Contract

The user-authored configuration exposes one canonical bundle:

```json
{
  "bundle": "constant-simplification",
  "options": {
    "memory_policy": "strict"
  }
}
```

The ordinary UI label is **Simplify constants**. The only initial policy choice
is:

- `strict` (default): materialize reads only when the target data item is
  backed by readable, non-writable memory or by a stronger per-read proof.
- `aggressive_no_direct_writes`: additionally materialize a writable target
  when no direct write xref is observed. This is an optimization heuristic, not
  proof of immutability.

Stage switches may exist in developer diagnostics, focused tests, or advanced
configuration, but the normal configuration editor must not present the three
stages as competing user choices.

This requires an honest configuration seam. The current `PassSpec` represents
one pass with one granularity and maturity contract, so it must not be stretched
into a fictional multi-maturity pass. A small bundle compiler expands the one
public bundle into ordered, private stage pass specs. The editor and public
catalog show the bundle; execution diagnostics may show its stages. Existing
fully expanded config-v2 documents remain a supported compiled form during
migration, but newly authored configuration uses the bundle.

`allow_executable_readonly` is removed from the public contract. Segment
execute permission is not itself the deciding fact. The canonicalized target
must be an IDA data item and the reference must be a data access. A readable,
non-writable data item may therefore be accepted even when its containing
segment is executable; a code item, instruction target, or unresolved item is
rejected.

## One Oracle, Two Questions

The oracle must answer two different questions explicitly:

1. **Can this particular read be materialized as a constant now?**
2. **Can the whole global safely receive a persistent `const` qualifier?**

Conflating these questions is unsound. An initializer may be stable at one read
even though the global is written elsewhere, and absence of a direct write
xref does not rule out pointer aliases or other indirect writes.

The portable result is a decision object, not a boolean:

```python
GlobalConstDecision(
    can_inline_read: bool,
    can_persist_const: bool,
    value: int | None,
    evidence: tuple[GlobalConstEvidence, ...],
    reason: GlobalConstReason,
)
```

The initial decision matrix is:

| Evidence | Inline this read | Persist `const` |
| --- | --- | --- |
| Readable, non-writable data item with no write evidence | yes | yes |
| Same data item in an executable segment | yes | yes |
| Writable item with no direct write xref | aggressive mode only | no |
| Initializer proven stable at this read | yes | no |
| Direct write exists elsewhere, but initializer is stable at this read | yes | no |
| Direct write without a per-read stability proof | no | no |
| Modeled store reaches this read | no | no |
| Code item, unresolved item, unsupported width, or unknown value | no | no |
| Unknown alias risk without stronger proof | strict mode: no | no |

The second row is accepted because the target is proven to be a data item, not
because executable read-only memory has been broadly allowed.

Evidence precedence is explicit. An unknown item or value abstains. A modeled
store reaching the read vetoes it. An initializer-stable proof may then
authorize that read despite unrelated writes. Without that proof, contradictory
write evidence against a supposedly non-writable item abstains. Persistent
`const` requires a non-writable data item and no write evidence anywhere in
the canonical item range.

## Evidence and Backend Boundary

Add an IDA-free evidence and policy model under
`d810.analyses.value_flow`. It owns:

- canonical item range and width;
- source read EA and function EA;
- segment read, write, and execute permissions;
- item kind: data, code, tail, or unresolved;
- direct write xrefs across the whole item range;
- modeled reaching stores for the particular read;
- static initializer bytes and decoded value;
- policy mode; and
- stable reason identifiers.

The live Hex-Rays backend supplies facts through an injected adapter. For
function-scoped inspection it must enumerate `idautils.FuncItems()`, retain
every source EA, canonicalize interior references to item heads and half-open
ranges, and query reads and writes over the full range. Portable analyses must
not import IDA.

The oracle abstains when required facts are unavailable. It must not silently
turn a missing segment, unknown item boundary, failed memory read, or
unsupported width into zero or into permission to fold.

`is_never_written_var()` may remain as a compatibility helper during
migration, but its exact meaning is only “no direct write xref was observed.”
It is never treated as whole-program immutability proof.

## The Three Internal Stages

### 1. Resolve constant memory reads

This is the sole authority for turning a global or table memory read into an
immediate. It handles direct globals, nested global operands, and supported
`ldx` table patterns through the shared oracle and one canonical
materialization implementation.

There must not be separate memory resolvers in a peephole rule, a flow rule,
and forward propagation. Different microcode shapes may require thin adapters,
but those adapters submit the same evidence request and apply the same
decision.

### 2. Fold constant expressions

This stage simplifies arithmetic, logical, and conversion subtrees after
memory values and other immediate inputs are available. It does not classify
global memory and does not decide whether a read-only address is foldable.

The existing `ConstantSubtreeFoldRule` supplies this capability and becomes an
internal stage implementation of **Simplify constants**.

### 3. Propagate constants through the function

This stage carries known values through registers, stack locations, and the
CFG. It consumes constants produced by the first two stages and may expose new
folding opportunities on later iterations. It does not contain a private
read-only-memory resolver.

The existing `ForwardConstantPropagationRule` supplies this capability and
becomes an internal stage implementation of **Simplify constants**.

The three stages need not execute in one Hex-Rays callback or at one maturity.
The bundle compiler schedules phase-appropriate internal pass specs and repeats
them only where the existing optimizer lifecycle permits. “One public
optimizer” means one user contract and one decision authority, not a forced
collapse of valid maturity boundaries.

## Consolidation and Migration

Consolidation proceeds in this order:

1. Introduce the shared evidence request, decision model, and oracle with
   parity tests for the current strict behavior.
2. Route `FoldReadonlyDataRule`, `GlobalConstantInliner`, and the
   `ForwardConstantPropagationRule` read-only `ldx` path through the oracle.
3. Select one canonical memory materializer and reduce the other entry points
   to bounded shape adapters.
4. Add bundle compilation and register the private stage implementations under
   the public `constant-simplification` bundle.
5. Remove the legacy rule names and `allow_executable_readonly` from the
   ordinary catalog and configuration editor.
6. Migrate shipped configurations and fixtures to the canonical optimizer.

A bounded configuration importer may translate legacy user configuration:

- either memory-folding rule enables the memory-resolution stage;
- `ConstantSubtreeFoldRule` enables expression folding;
- `ForwardConstantPropagationRule` enables flow propagation;
- `fold_writable_constants=true` maps to
  `memory_policy=aggressive_no_direct_writes`; and
- `allow_executable_readonly` is ignored with an explicit migration notice
  because item classification now determines the answer.

The importer must reject contradictory legacy combinations rather than run two
materializers. Newly written configuration contains only the canonical
bundle. The UI catalog exposes one public entry; the runtime registry may
expose the compiled internal stage IDs for scheduling and diagnostics while
temporary compatibility aliases exist at the serialization boundary.

Statistics and diagnostics use stable stage identifiers:

- `memory_resolution`;
- `expression_folding`; and
- `flow_propagation`.

They do not require users to understand the legacy class names.

## Persistent Global Annotation as a Later Consumer

Persistent annotation remains useful, but it is a separate subproject. A
function-scoped **Inspect referenced global constants** action may preview
oracle decisions and optionally apply only decisions with
`can_persist_const=true`.

That subproject must retain the safety properties from the original proposal:

- dry-run by default;
- complete original `tinfo` preservation;
- IDB-local, versioned D810 ownership receipts;
- stale-plan and later-user-edit detection;
- no removal of user-authored `const`;
- typed plan and receipt diagnostics; and
- a runtime identity digest that includes committed annotation receipts.

Writable/no-direct-write and initializer-stable-read evidence never authorize
persistent `const`. The script's size-based type guessing is also excluded
from the first annotation slice.

This later feature consumes the oracle; it does not introduce another
definition of constant memory.

## Failure Semantics

- Unknown evidence produces an explicit abstention and stable reason.
- Failure to decode the value prevents materialization even when the target is
  non-writable.
- A modeled store that reaches a read vetoes that read. A direct write
  elsewhere blocks persistent `const`, but does not override a stronger
  initializer-stable proof for the particular read.
- Aggressive mode is visibly heuristic and never upgrades
  `can_persist_const`.
- Configuration that would activate both a legacy materializer and the
  canonical materializer fails with an actionable migration error.
- One stage failure is attributed to that stage; it must not be reported as
  success by an aggregate counter.
- Dry-run annotation performs no type, netnode, cfunc-cache, project, or
  diagnostic writes.

## Delivery Slices

### Subproject A: optimizer consolidation

This is the immediate deliverable:

1. shared oracle and evidence model;
2. one canonical memory materializer;
3. removal of the duplicate forward-propagation memory resolver;
4. canonical three-stage registration and configuration migration;
5. unified UI labels, statistics, and diagnostics; and
6. parity and safety verification.

One implementation plan should cover this subproject in dependency order,
with review checkpoints after the oracle, materializer migration, and public
configuration migration.

### Subproject B: persistent IDB annotation

After consolidation is green, plan the preview/apply/revert service, backend
type mutation adapter, ownership receipts, typed case evidence, and UI action.
This cannot redefine the oracle or weaken its persistent-const decision.

## Verification

Unit and integration tests for Subproject A must cover:

- every row in the decision matrix;
- direct globals, nested globals, and supported `ldx` table reads;
- canonical item heads, interior references, overlapping write ranges, and
  function chunks;
- non-writable data in R-only and R+X segments;
- code items and control-flow references in R+X segments being rejected;
- strict versus aggressive policy;
- initializer-stable per-read decisions;
- missing segments, unknown item boundaries, failed reads, and unsupported
  widths abstaining;
- all memory-read shapes consulting the same oracle;
- exactly one materialization authority being active;
- expression folding containing no global-memory policy;
- forward propagation containing no private global-memory resolver;
- legacy configuration migration and contradiction rejection;
- one public bundle expanding to valid single-granularity, single-maturity
  internal pass specs;
- stage ordering, iteration, counters, and stable diagnostics; and
- output parity with current strict configurations on the runtime corpus.

Runtime tests in IDA must prove that consolidation preserves or improves the
relevant decompilation output for representative direct, nested, table, R+X
data, reaching-write, and initializer-stable cases. Any intentional output
change needs a case-specific explanation and oracle evidence.

Before completion, run the focused suites, configuration migration tests,
runtime oracle cases, and the worktree boundary gates:

```bash
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
```

## Acceptance Criteria

- Users enable one bundle named **Simplify constants**.
- Ordinary configuration does not expose `allow_executable_readonly`.
- R+X non-writable data is accepted through data-item classification, while
  code is rejected.
- Every global-memory materialization consults one constness oracle.
- Exactly one implementation owns memory-read-to-immediate replacement.
- Expression folding only folds expressions.
- Forward propagation only propagates values through function state and the
  CFG.
- Aggressive no-direct-write behavior remains opt-in and is never described as
  proof of immutability.
- Legacy configuration has an explicit, tested migration path without silent
  duplicate execution.
- Persistent annotation, when later implemented, consumes
  `can_persist_const` from the same oracle and cannot infer it from
  `can_inline_read`.
- Portable layers remain free of live IDA imports and the UI remains a thin
  dispatcher and renderer.
