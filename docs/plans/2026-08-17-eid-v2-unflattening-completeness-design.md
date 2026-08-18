# Eid Config-V2 Unflattening Completeness Design

## Goal

Make the existing config-v2 unflattening pipeline used by
`eidolon_v3_const_solve.json` completely and safely unflatten these three live
Eid functions:

- `0x7FF8569F0540`: preserve the state-routed `memcpy` corridor while removing
  the residual comparison dispatcher;
- `0x7FF8568132D0`: preserve the reachable conditional trap and the SRW-lock
  call while removing the dispatcher;
- `0x7FF855576B50`: recover an initial state written inside the dispatcher-entry
  block, resolve interval-routed states, and remove the dispatcher.

The two already-successful targets, `0x7FF8554C4E30` and the function entered at
`0x7FF856884940` containing `0x7FF856886B70`, remain protected controls.

## Scope

This work changes only the existing config-v2 dispatcher recovery, state
transition recovery, route planning, and safety-validation path. It does not
delete the legacy unflattener, migrate the configuration catalogue, redesign
config v2, or add another unflattening strategy.

`eidolon_v3_const_solve.json` already activates the correct passes. Production
success must come from generalized CFG evidence and route planning, not from
adding function-specific configuration or combining the legacy and v2 engines.

## Confirmed Failure Modes

### Shared effectful corridor: `0x7FF8569F0540`

The v2 pipeline recovers most of the state machine and proposes approximately
140 redirects. The projected CFG loses the real route:

```text
0x7FF8569F084C  cmp eax, 0x0EE1BCAD
0x7FF8569F0851  jz  0x7FF856A01EAE
0x7FF856A01EAE  ... call memcpy
```

It also loses a synthetic cut block associated with the same route. The
dispatcher-removal proof reports `authoritative_handler_lost`, and transaction
preflight correctly rejects the mutation because an effectful block would
become unreachable. Later cleanup passes can still make local changes, which
explains the misleading partially unflattened pseudocode.

### Conditional semantic terminal: `0x7FF8568132D0`

The candidate rewrite loses this reachable path:

```text
0x7FF85681EB3B  cmp eax, 0x379D0A55
0x7FF85681EB40  jnz 0x7FF85682AC3B
0x7FF85682AC3B  int3
```

Hex-Rays renders the destination as `__debugbreak()`. It is not alignment
padding: the conditional branch is a real incoming code reference. The safety
veto is correct. The planner must preserve this semantic terminal while
retiring only the dispatcher comparison corridor.

### Same-block initialization and interval routing: `0x7FF855576B50`

The entry computes the state `0x16AA65E9` and writes it inside the same block
that begins the dispatcher comparisons. Current entry-dominance recovery only
examines dispatcher predecessors, so minimal unflattening reports
`initial_state=None` and leaves the function intact.

The recovered value is not an exact comparison point. It selects an interval
in the comparison tree. Two back-edge states are also reported as
`interval-router-insufficient`. Recovery therefore needs both a sound
same-block prefix proof and a single shared concrete-state-to-route resolver
that accepts interval evidence when it proves one target.

## Safety Invariants

1. No function address, API name, state constant, block serial, or sample name
   appears in production decision logic.
2. Existing effect-reachability, authoritative-handler, terminal-reachability,
   predecessor-ownership, and poison/quarantine gates remain fail-closed.
3. A block containing a call, store, semantic terminal, unknown effect, or
   unresolved control transfer is never reclassified as removable dispatcher
   infrastructure merely to make a fixture pass.
4. Dispatcher retirement is transaction-atomic. A rejected full transaction
   is not reported as successful because unrelated cleanup passes changed the
   pseudocode.
5. Block serials in diagnostics and tests are always accompanied by stable EA
   anchors.
6. Native and synthetic blocks must retain exact source-EA provenance through
   route planning and projection.
7. Ambiguous ownership, multiple reaching initial-state definitions, unknown
   operand effects, conflicting interval routes, or incomplete corridor
   enumeration cause abstention.
8. Tests execute the exact `eidolon_v3_const_solve.json` config-v2 profile.

## Architecture

### 1. Exact config-v2 fixture reproduction

The existing large MASM fixtures for `sub_7FF8569F0540` and
`sub_7FF8568132D0` are retained, but their system tests select
`eidolon_v3_const_solve.json`. A third MASM fixture captures
`sub_7FF855576B50` and exports stable data markers that resolve the exact native
calls used by the post-D810 reachability oracle.

The first Docker run is a required RED gate. If a fixture does not reproduce
the corresponding live abstention, the fixture or its linked CFG extent must
be corrected before production code changes.

### 2. Shared concrete-state route resolution

Introduce or consolidate one portable helper that resolves a concrete 32-bit
state through all admissible evidence in this order:

1. exact materialized-state route;
2. exact row in `StateDispatcherMap`;
3. one interval row from the recovered `IntervalDispatcher` or comparison
   dispatcher model;
4. native-bound route evidence carrying exact source anchors.

The result contains a target block and route provenance. It returns no result
unless exactly one route is proven. Entry bridges and back-edge transition
recovery consume this helper; neither implements an independent exact-only
lookup.

### 3. Same-block entry-prefix recovery

Extend portable dispatcher recovery to inspect only the instruction prefix in
the dispatcher-entry block that strictly precedes the first routing predicate.
The prefix proves an initial state only when one constant write to the recovered
state identity reaches the first dispatch and no later prefix instruction
overwrites or invalidates it.

The proof rejects:

- writes after the first dispatcher predicate;
- multiple conflicting state writes;
- nonconstant state writes;
- width or identity mismatches;
- calls, unknown stores, or unsupported effects that invalidate the reaching
  definition;
- entry shapes in which the first predicate boundary cannot be identified.

The recovered value is attached to `StateDispatcherMap.initial_state`, keeping
initial-state authority in recovery rather than adding another emit-only
special case.

### 4. Effectful shared-corridor preservation

Conditional-arm and shared-cut planning may preserve a corridor through a
shared suffix only when immutable source-CFG evidence proves:

- the arm's source predicate and selected state route;
- sole or explicitly partitioned ownership of the rewritten edge;
- every retained semantic/effectful block on the route;
- exact source/synthetic anchor correspondence;
- post-projection reachability of the selected handler and retained effect
  blocks.

The `memcpy` block remains semantic content. Only comparison and state-plumbing
blocks proven by corridor coverage may be retired.

### 5. Conditional terminal preservation

A zero-way block or terminal helper reached by a real conditional dispatcher
edge is a semantic endpoint. Route planning retains that edge and includes the
terminal in authoritative reachability. The policy is based on portable CFG
and instruction semantics, not on the spelling `int3` or `__debugbreak`.

Unreferenced alignment padding remains outside the reachable source CFG and
requires no special treatment.

## Testing Strategy

### Portable unit tests

- same-block initialization before the first predicate;
- conflicting, nonconstant, post-predicate, mixed-width, and effect-barrier
  rejection;
- exact and interval state-route success;
- uncovered and conflicting interval abstention;
- uniquely owned shared suffix preserving an effectful call;
- ambiguous/unowned shared suffix rejection;
- synthetic cut provenance preservation;
- reachable conditional terminal preservation;
- unreachable padding exclusion;
- mixed semantic/corridor loss rejection;
- atomic transaction rejection whenever any retained semantic block is lost.

Every production change follows RED-GREEN-REFACTOR. Tests assert observable
route, reachability, proof, and transaction results rather than source text or
private helper calls.

### Docker system tests

All three MASM targets run through the repository runner from the main checkout
with `-w <worktree>` and `eidolon_v3_const_solve.json`. The assertions require:

- a committed v2 unflattening transaction;
- no target dispatcher constants or residual dispatcher loop;
- exact marker-resolved native effects reachable in the latest post-D810
  snapshot selected from the same diagnostic session;
- `memcpy` retained for target A;
- SRW lock and `__debugbreak()` retained for target B;
- `MessageBoxA`, `GetCurrentProcess`, and `TerminateProcess` retained for target
  C.

Protected OLLVM, Hodur, Tigress, Approov, poison/quarantine, and transaction
runtime suites must remain green.

### Live acceptance

After Docker acceptance, restart IDA with the feature worktree installed and
decompile the three original functions through MCP. For each target capture:

- before/after pseudocode;
- diagnostic session and committed mutation receipt;
- exact call/trap reachability evidence;
- absence of the identified dispatcher structure;
- decompilation elapsed time and any nonfatal errors.

Fixture success without live success is incomplete.

## Out of Scope

- deleting or modifying the legacy unflattening engine;
- migrating the configuration catalogue;
- adding a legacy pass to the Eid profile;
- changing Egglog, MBA rules, or constant solving;
- recognizing MurmurHash, Win32 APIs, or these three functions by name;
- removing reachable traps;
- accepting effect loss because pseudocode looks cleaner;
- unrelated cleanup of the large `minimal_unflatten_emit.py` module.

## Definition of Done

The work is complete only when all three exact Eid v2 fixtures commit safe
transactions, all semantic-effect oracles pass, protected system/runtime suites
remain green, architecture checks pass, and all three original live MCP targets
produce complete pseudocode without omissions or residual dispatchers.
