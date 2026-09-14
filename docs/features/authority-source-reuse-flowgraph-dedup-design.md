# Authority Source Reuse and Flowgraph Deduplication Design

Status: approved in chat and approved after written review

Tickets: `d81-2zj2` (stage 1), `d81-if7a` (stage 2)

Base: `a6dca3d963958c43ef8fdac8ac3b48d5198ac8bf`

## Objective

Reduce two costs identified by the pinned OLLVM Pyinstrument capture without
weakening post-mutation validation or changing selected proofs, mutations, or
decompiled output:

1. source-derived authority work repeated between projected preparation and
   observed post-apply validation;
2. repeated `FLOWGRAPH_READY` lifting and preanalysis capture for the same
   authoritative graph occurrence.

The stages are sequential. Stage 2 depends on stage 1 so measurements and
failures remain attributable to one intervention.

## Evidence and limits

The 10 ms Pyinstrument capture completed the exact OLLVM fixture with 9,430
samples. Instrumentation expanded the fixture from about 58 seconds to about
100 seconds, so its times establish attribution only.

Within that capture:

- authority preparation was 14.75 seconds;
- observed revalidation was 6.61 seconds;
- `build_semantic_case` appeared for 3.56 and 3.71 seconds;
- semantic inventory construction appeared for 1.53 and 1.23 seconds;
- loss-ledger validation appeared for 0.77 and 0.80 seconds;
- the instruction-side `FLOWGRAPH_READY` path was 6.65 seconds, including
  2.56 seconds of lifting and 4.48 seconds of preanalysis capture.

These are nested instrumented times and are not speedup predictions. The
candidate must demonstrate eliminated work and then pass a separate
uninstrumented wall bracket.

The preparation and observed phases do not have identical complete inputs.
Preparation evaluates the projected graph. Revalidation evaluates the live
post-apply graph and must detect generation, binding, inventory, and semantic
loss changes. Reusing the projected case or verdict as the observed result is
therefore outside this design.

The completed generic-pattern experiment is also outside this design. Its
root rejection removed 96.43% of targeted `minsn_to_ast` calls, but a matched
whole-function comparison showed no speedup. No new AST cache, AST sharing
layer, or generic-pattern admission change is authorized here.

## Safety model

Only data that is already transaction-owned, immutable for the transaction,
and independent of projected-versus-observed graph state may be reused.

The following remain phase-local and must be reconstructed or checked against
the actual phase graph:

- candidate graph inventory and graph fingerprint;
- observed helper bindings and native coordinates;
- graph generation and maturity;
- phase-specific generic gates;
- semantic loss classification and observed delta;
- final verdict and observed acceptance record.

Mutable descendants are not inferred safe from object identity. Existing
canonical mutation guards, exact transaction ownership, attempt identity, and
fact partitions remain authoritative. A reuse candidate must fail closed when
it cannot prove that an input belongs to the prepared transaction occurrence.
Frozen dataclasses and `MappingProxyType` provide only shallow protection. A
candidate may admit a value only when its complete canonical read path is
transitively closed, or when the existing authoritative canonical digest is
rechecked against the preparation digest. It must not introduce a second,
potentially divergent immutability traversal. If the required digest check
recreates the measured work, the candidate stops rather than weakening it.

`opcode_attrs` is not an example of such a read path: current mainline removes
that backend provenance from canonical route identity. The concrete supported
mutable descendant is a state-transform program instruction's `attrs` mapping,
which deliberately forces per-selection validation today.

## Stage 1: phase-invariant authority reuse

### Measurement

Add opt-in counters around projected preparation and observed revalidation.
For each expensive constructor, record whether each input is:

- the exact prepared occurrence;
- a phase-local projected value;
- a phase-local observed value;
- newly derived from a prepared source value;
- newly derived from the candidate graph.

The receipt must identify the transaction attempt and phase and count calls,
not merely elapsed time. Counter collection must be disabled by default and
must not serialize full evidence in the hot path.

The first result is a reuse ceiling: source-derived constructions that could
be removed without reusing any graph-dependent result. If that ceiling is
negligible, stage 1 stops without a production optimization.

### Candidate boundary

`PreparedUnflattenAuthority` already carries the exact source inventory,
source inputs, projected case, projected ledger, owning plan, proposal, and
preparation attempt. The candidate will extend or factor this existing owner
only if measurement finds source-derived work that the observed phase rebuilds.
It will not introduce a process-global or cross-transaction cache.

The observed phase may consume a precomputed source-side certificate containing
only values whose derivation is independent of the candidate graph. It must
still build the observed inventory, derive observed inputs, build the observed
case, evaluate it, construct the observed ledger and delta, and validate that
ledger. A certificate is invalid unless the exact prepared object, transaction
context, session, attempt, source snapshot, and native input identity match.
Identity or an occurrence-seal hit alone is insufficient: a nested mutable
value such as
`route_evidence.route_proofs[0].state_transform.program[0].attrs["mutable"]`
can change without changing the enclosing frozen-record identity.

### Shadow oracle

During qualification, run the current full observed path as the oracle and the
candidate path as the shadow, or vice versa. The candidate is rejected on any
difference in:

- accepted/rejected reason and phase;
- authority, binding, case, inventory, ledger, delta, evidence and claim IDs;
- observed helper bindings and route-authority verification;
- selected proof-ID sequence;
- patch plan, mutation receipts, and pseudocode bytes.

The shadow path remains opt-in and is removed or disabled after qualification.
It is not a permanent double-validation tax.

## Stage 2: `FLOWGRAPH_READY` occurrence reuse

### Census before policy

Record every producer emission and consumer invocation using:

- decompilation session;
- authoritative native MBA identity and generation;
- maturity;
- producer (`InstructionOptimizerManager` or `BlockOptimizerManager`);
- whether a portable `FlowGraph` was already available;
- consumer name and whether it consumed or retained the snapshot;
- fact-set identity or stable fact digest produced by the consumer.

The census preserves the required ordering: emission occurs after
`reset_for_func` and before analysis/persistence. It must distinguish two
producers observing the same occurrence from two different graph generations
at the same maturity.

The current event payload does not carry the session and authoritative native
generation needed for that distinction. Stage 2 must plumb those coordinates
and first prove that every relevant native mutation advances the generation.
No occurrence cache is implemented until that prerequisite closes.

### Candidate policies

Use the census to select at most one of these bounded policies:

1. If two producers request the exact same authoritative occurrence, lift once
   and share the immutable portable `FlowGraph` within the lifecycle
   coordinator. Invalidate on every generation change, reset, session end, or
   native identity change.
2. If a maturity has no registered consumer, add an explicit demand predicate
   and suppress work before lifting. Absence must be proven from the registered
   consumer contract, not inferred from a missing output row.

Do not hash the full graph merely to form the reuse key; that can recreate the
cost being removed. Do not coarsen maturities, disable events globally, or let
a portable graph survive a mutation boundary.

Demand suppression is deferred unless the registry covers coordinator
publishers, fact collectors, lifecycle derivations, diagnostics, and late
snapshot attachment. In particular, an earlier instruction event without a
snapshot cannot suppress a later block event that attaches the snapshot needed
for persistence.

### Equivalence oracle

Qualification compares baseline and candidate event ledgers. For every
baseline event, the candidate must either produce an equivalent consumer result
from the shared occurrence or prove that no consumer was registered. Fact
records and stable fact digests, selected proof IDs, patch plans, mutation
receipts, and pseudocode bytes must match.

## Tests

Stage 1 requires pure unit tests for exact occurrence admission, foreign
transaction rejection, phase separation, mutation of nested supported values,
generation changes, rejected verdicts, and shadow-oracle mismatch handling.

Stage 2 requires pure lifecycle tests for duplicate producers, same maturity
with different generations, reset ordering, session teardown, consumer demand,
listener failure, and cache invalidation. IDA-dependent emission and native MBA
identity tests remain under `tests/system/runtime`.

Both stages must pass the focused authority suites, architecture gates, DAC
unit and system fixtures, and the exact OLLVM end-to-end fixture. Expected
`XFAIL` results remain distinct from failures and skips.

## Performance acceptance

For each stage:

1. establish baseline call counts and phase timing;
2. show the exact targeted calls eliminated and all replacement costs;
3. run the correctness and shadow-oracle gates;
4. run a randomized, uninstrumented A/B/A or paired bracket on the quiet remote
   amd64 engine with exact source, image, fixture, project, and cache receipts;
5. report work elimination separately from wall time.

A null wall result does not erase real work elimination, but it also does not
authorize a speedup claim or a broader architecture. A regression, oracle
difference, incomplete mutation boundary, or insignificant reuse ceiling stops
that stage.

## Delivery and rollback

Stage 1 and stage 2 use separate commits and review gates. Neither is pushed or
merged without explicit authorization. Every optimization is locally
reversible, defaults to the existing behavior until qualification is complete,
and leaves no persistent cross-session cache.

## Formal design verification

An independent verifier evaluated the alternatives against the transaction and
lifecycle contracts.

- Reusing only transitively stable, phase-invariant source components was
  accepted conditionally, provided the observed inventory, case, ledger,
  bindings, delta, verdict, and exceptions are rebuilt and shadow-compared.
- Reusing the projected case as the observed result was rejected. A mutation
  can remove an effect, change topology, or make an observed binding non-unique;
  projected validation may accept while observed validation must reject.
- A general delta-validation engine was deferred. Its dependency set must
  include negative facts: a newly added incoming edge can invalidate an absence
  claim even if the proof traversed none of that edge's prior nodes.
- Exact-occurrence `FlowGraph` sharing was accepted conditionally with the key
  `(session_id, mba_identity, generation, maturity)`, complete generation
  advancement, deterministic consumers, reset-before-emission ordering, and
  teardown invalidation.
- Demand-based suppression was not accepted without a complete consumer and
  snapshot-attachment registry. Disabling or coarsening events was rejected.

The accepted order is therefore the measured source-certificate experiment,
followed by authoritative occurrence-coordinate plumbing and only then
same-occurrence `FlowGraph` sharing.
