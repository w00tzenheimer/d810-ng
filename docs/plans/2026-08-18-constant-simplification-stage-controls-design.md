# Constant Simplification Stage Controls Design

## Status

Approved architecture, pending review of this committed specification.

## Goal

Make `constant-simplification` an explicitly scheduled bundle instead of an
always-on expansion into three private rules. Users must be able to enable or
disable each mutation stage, select a safe subset of its supported Hex-Rays
maturities, and see the exact effective schedule in the Deobfuscation
Workbench.

Separate persistent global-const preparation from direct value folding. A user
must be able to add reversible `const` type metadata without also replacing
loads with immediate values.

Add independent expression-size and solver-time bounds to the three generic Z3
predicate transforms owned by `mba-simplify`:

- `z-3-setz-generic`;
- `z-3-setnz-generic`; and
- `z-3-lnot-generic`.

## Current Problem

`src/d810/passes/constant_simplification.py` currently expands one public pass
into three private implementations:

1. `FoldReadonlyDataRule`;
2. `ConstantSubtreeFoldRule`; and
3. `ForwardConstantPropagationRule`.

All three are activated whenever the public pass is enabled. Their maturity
lists are owned by live Hex-Rays objects, so configuration cannot safely narrow
individual stages and the Workbench has to infer the schedule from runtime
objects. Pass-level `maturity_gates` do not currently form one compiled source
of truth with those private maturity lists.

Persistent global const annotation is also coupled to
`FoldReadonlyDataRule` through `persist_global_const_annotations`. That option
adds reversible type persistence beside direct load folding; it does not replace
folding. Consequently, users cannot ask D810 to establish constness while
leaving value materialization to Hex-Rays.

The generic Z3 predicate transforms use the shared `Z3MopProver`. The shared
solver has a 50 ms default timeout, but the three public transforms expose no
independent expression-size or proof-time controls. Their resource use is
therefore not visible in project configuration or the Workbench.

## Chosen Architecture

The public operation has two lifecycle domains:

```text
pre-Hex preparation
    global-const-types

Hex-Rays mutation
    fold-readonly-data
    fold-constant-subtree
    forward-constants
```

Preparation and mutation remain separate authorities. `global-const-types`
applies exact, reversible IDB type changes through the existing preparation
journal. It never emits a replacement microinstruction. The three mutation
stages retain their current implementation responsibilities and become
independently configurable.

The runtime and Workbench consume the same validated, immutable compiled
schedule. Neither the live hook bridge nor the UI independently recomputes
stage eligibility.

## Rejected Alternatives

### Keep const persistence inside readonly folding

This is the smallest code change, but it preserves the false coupling between
proving storage immutable and replacing a read with an immediate. It also makes
the Workbench unable to explain which authority changed the IDB and which
authority changed microcode.

### Replace readonly folding with const preparation

This is cleaner superficially but not behaviorally equivalent. Hex-Rays does
not promise to materialize every const-qualified value, and D810's aggressive
`no direct writes` materialization policy intentionally accepts some writable
objects that must never be persisted as `const`. Direct folding therefore
remains a separate opt-in mutation stage.

### Let configuration add arbitrary maturities

This makes project JSON an authority for implementation safety. A rule could be
scheduled before the representation or use-def information it requires exists.
Configuration may narrow an implementation-declared support set; it may not
expand it.

## Canonical Configuration

The canonical public shape is:

```json
{
  "pass_id": "constant-simplification",
  "maturity_gates": [
    "CANONICAL",
    "LOCAL_OPTIMIZED",
    "CALL_MODELED",
    "GLOBAL_ANALYZED",
    "GLOBAL_OPTIMIZED",
    "STRUCTURED"
  ],
  "options": {
    "preparation": {
      "global_const_types": {
        "enabled": false,
        "discover_bounded_tables": true
      }
    },
    "stages": {
      "fold-readonly-data": {
        "enabled": true,
        "maturities": [
          "CANONICAL",
          "LOCAL_OPTIMIZED",
          "CALL_MODELED",
          "GLOBAL_ANALYZED",
          "STRUCTURED"
        ],
        "memory_policy": "strict",
        "rva_guard": true,
        "allow_executable_readonly": false
      },
      "fold-constant-subtree": {
        "enabled": true,
        "maturities": [
          "LOCAL_OPTIMIZED",
          "CALL_MODELED",
          "GLOBAL_ANALYZED",
          "GLOBAL_OPTIMIZED",
          "STRUCTURED"
        ]
      },
      "forward-constants": {
        "enabled": true,
        "maturities": [
          "CALL_MODELED",
          "GLOBAL_ANALYZED",
          "GLOBAL_OPTIMIZED",
          "STRUCTURED"
        ]
      }
    }
  }
}
```

The default maturity selections equal the implementations' current supported
sets. Existing configurations therefore retain their mutation coverage until a
user deliberately narrows it. Global const preparation remains disabled by
default, matching the current default for
`persist_global_const_annotations`.

Stage IDs are stable public identities. Private Python class names remain
backend bindings and do not appear as editable configuration keys.

## Compatibility And Migration

The parser accepts the current flat options as one legacy input shape:

- `memory_policy`;
- `rva_guard`;
- `allow_executable_readonly`; and
- `persist_global_const_annotations`.

When no canonical `preparation` or `stages` object is present, the parser maps
those values into the canonical structure and supplies the current complete
maturity sets. The Workbench writes only the canonical structure on the next
save.

A configuration that mixes a legacy key with its canonical replacement is
invalid. There is no precedence rule that could silently choose one value over
the other. Unknown preparation, stage, or stage-option keys remain errors.

Legacy activation of the private implementation rules remains supported for
legacy project formats, but it does not gain persistent IDB authority. Only the
public `constant-simplification` preparation configuration may request durable
const annotations.

## Portable Stage Contracts

The portable pass registration owns immutable support metadata:

```text
fold-readonly-data
    CANONICAL
    LOCAL_OPTIMIZED
    CALL_MODELED
    GLOBAL_ANALYZED
    STRUCTURED

fold-constant-subtree
    LOCAL_OPTIMIZED
    CALL_MODELED
    GLOBAL_ANALYZED
    GLOBAL_OPTIMIZED
    STRUCTURED

forward-constants
    CALL_MODELED
    GLOBAL_ANALYZED
    GLOBAL_OPTIMIZED
    STRUCTURED
```

These sets mirror the existing live implementation defaults. They become the
registration authority rather than being rediscovered from instantiated IDA
objects. Runtime construction verifies that the live binding agrees with the
portable contract and fails closed if the two drift.

For each enabled mutation stage:

```text
requested = configured maturities, or the complete supported set when omitted
effective = requested intersect pass-level maturity_gates
```

Validation occurs before hook activation:

- `requested` must be a subset of `supported`;
- an enabled stage must have at least one effective maturity;
- duplicate maturity spellings normalize deterministically;
- provider and portable maturity names normalize through the existing maturity
  vocabulary; and
- a disabled stage contributes no live implementation.

Selecting an unsupported maturity or producing an empty effective set is a
configuration error. The compiler never silently drops invalid values.

## Compiled Effective Schedule

Introduce an immutable compiled schedule containing, per stage:

- public pass and stage identity;
- lifecycle domain;
- backend pipeline;
- private implementation binding;
- enabled state;
- implementation-supported maturities;
- user-requested maturities;
- pass-level gates;
- effective maturities;
- runtime registration order; and
- an inactive or rejected reason when applicable.

The project runtime compiles this once after configuration validation. The hook
bridge activates private rules from it. The Workbench projects the same object.

Instruction and flow callbacks are not presented as one fictional global total
order. At each maturity, the Workbench groups stages by callback pipeline and
shows the actual registration order inside each pipeline.

`global-const-types` is displayed in a separate `PRE_HEXRAYS` preparation row.
It is not assigned a fake microcode maturity and is not intersected with
`maturity_gates`.

## Global Const Preparation

### Whole-item discovery

Before the requested top-level Hex-Rays generation,
`PreHexPreparationController` invokes the existing whole-item discovery for the
selected function when `global_const_types.enabled` is true. Eligible proposals
contain exact serialized before and after types and are applied through the
existing reversible preparation gateway and journal.

Persistent constness retains the strict policy in
`analyses/value_flow/global_constness.py`. Writable storage is not persisted as
`const`, even when the readonly folding stage uses the aggressive
`no direct writes` policy. Folding authority cannot widen preparation
authority.

### Dynamically discovered bounded tables

Some bounded table shapes are visible only after microcode exists. Their
discovery is extracted from `FoldReadonlyDataRule` into an observation-only
subscriber activated when both of these are true:

```text
global_const_types.enabled
global_const_types.discover_bounded_tables
```

The subscriber observes at `CALL_MODELED`, emits no microcode mutation, and
queues exact const proposals for the next natural preparation round. This lets
dynamic discovery operate when `fold-readonly-data` is disabled.

The first implementation does not force a decompilation restart. A pending
proposal is visible in the Workbench with the reason `next preparation round`.
This avoids creating another restart and convergence state machine merely to
remove a one-round delay.

### Failure behavior

Type divergence, journal conflicts, stale database identity, or an unsupported
item kind cause preparation to abstain or fail closed according to the existing
preparation transaction contract. A preparation failure never falls back to an
untracked direct type write.

## Mutation Stage Activation

The bridge expands only enabled stages:

- `fold-readonly-data` receives its memory policy, RVA guard, executable-memory
  override, and exact effective maturities;
- `fold-constant-subtree` receives its exact effective maturities; and
- `forward-constants` receives its exact effective maturities and existing
  forward-propagation options.

The declaration order remains authoritative. Within the instruction pipeline,
readonly folding is registered before subtree folding. The existing
insertion-ordered rule collection preserves that order.

No stage mutates another stage's maturity list after activation. Effective
maturities are immutable inputs supplied during private rule construction.

## Independent Z3 Predicate Bounds

The bounds belong to the existing `mba-simplify.transform_options` entries:

```json
{
  "transform_options": {
    "z-3-setz-generic": {
      "max_expression_nodes": 256,
      "proof_timeout_ms": 50
    },
    "z-3-setnz-generic": {
      "max_expression_nodes": 256,
      "proof_timeout_ms": 50
    },
    "z-3-lnot-generic": {
      "max_expression_nodes": 256,
      "proof_timeout_ms": 50
    }
  }
}
```

Both fields are required typed integers when present:

```text
max_expression_nodes: 1..4096, default 256
proof_timeout_ms:      1..5000, default 50
```

Each transform owns an immutable prover-options value. One transform's options
must not mutate the cached shared solver or alter another transform's later
queries.

`max_expression_nodes` counts expanded AST node occurrences, including
operators, constants, and leaves. Recursive definition resolution consumes the
same budget incrementally and aborts before constructing a tree beyond the
limit. Checking only after expansion is not a resource bound.

`proof_timeout_ms` is applied to a solver instance scoped to that proof
configuration. `unknown`, timeout, translation failure, and node-budget
exhaustion are abstentions, never negative proofs. Any proof cache is scoped by
the complete prover options so a bounded abstention cannot suppress a query
made under different bounds.

Structured proof outcomes distinguish:

```text
proved
disproved
abstained: node_limit
abstained: timeout
abstained: unsupported_expression
abstained: solver_unknown
```

Only a proof result permits a replacement.

## Workbench Controls

The constant-simplification editor renders four sections.

### Global const preparation

- `Enable reversible global const types`;
- `Discover bounded tables from microcode`; and
- a short explanation that dynamic discoveries apply on the next natural
  preparation round.

### Readonly data folding

- enabled checkbox;
- supported-subset maturity selector;
- memory policy;
- RVA guard; and
- executable readonly override with its existing danger advisory.

### Constant subtree folding

- enabled checkbox; and
- supported-subset maturity selector.

### Forward constants

- enabled checkbox; and
- supported-subset maturity selector.

The `mba-simplify` transform editor renders independent node and timeout fields
under each selected generic predicate transform.

## Workbench Effective Schedule

The Pipeline view shows, for every configured stage:

- `enabled` or `disabled`;
- supported maturities;
- requested maturities;
- pass-level gates;
- effective maturities;
- backend pipeline and runtime order; and
- the source of the schedule (`compiled stage contract`).

The preparation row also shows applied and pending const proposals. A dynamic
proposal explicitly says it will apply on the next preparation round. The UI
does not infer this state from logs.

Z3 transform details show the effective node and timeout bounds. Proof receipts
record the transform ID, configured bounds, observed node count where known,
elapsed proof time, and outcome reason.

## Error Handling And Observability

Configuration errors identify the pass, stage, offending value, and supported
set. Examples include:

```text
constant-simplification stage fold-readonly-data does not support LIFTED;
supported: CANONICAL, LOCAL_OPTIMIZED, CALL_MODELED, GLOBAL_ANALYZED, STRUCTURED

constant-simplification stage forward-constants is enabled but its requested
maturities have an empty intersection with pass maturity_gates
```

Routine Z3 abstentions are structured diagnostics, not ERROR log spam.
Unexpected solver or lowering exceptions remain errors and fail closed.

The compiled schedule is included in the Workbench snapshot and can be emitted
as a deterministic diagnostic receipt for fixture assertions.

## Testing

### Portable unit tests

- parse canonical preparation and stage options;
- migrate each legacy flat option;
- reject mixed legacy and canonical keys;
- reject unknown stages and options;
- reject unsupported stage maturities;
- reject enabled stages with empty effective sets;
- prove deterministic maturity normalization and ordering;
- prove disabled stages are absent from live activation requests;
- prove runtime and Workbench receive the same compiled schedule; and
- prove editor controls round-trip the canonical configuration.

### Const preparation tests

- apply and restore a whole-item const proposal without direct folding;
- run direct readonly folding with preparation disabled;
- keep persistent policy strict when folding policy is aggressive;
- discover a bounded table with readonly folding disabled;
- queue dynamic proposals without forcing a restart; and
- surface pending, applied, conflicting, and restored proposals in Workbench
  models.

### Z3 tests

For each of `setz`, `setnz`, and `lnot` independently:

- accept and apply its configured bounds;
- prove one transform's options do not affect the other two;
- abstain before translation when the node budget is exceeded;
- abstain on timeout or solver `unknown`;
- never cache an abstention as a proof;
- preserve sound replacements inside the bounds; and
- round-trip typed fields through the transform editor.

### IDA system tests

A committed fixture exercises:

- const annotation without load materialization;
- readonly folding without const persistence;
- the ordered readonly-fold then subtree-fold chain;
- forward propagation at selected and excluded maturities;
- pass-level maturity-gate intersection;
- dynamic table discovery followed by a second natural preparation round; and
- bounded generic Z3 predicate proofs.

System assertions use the compiled schedule and mutation/proof receipts in
addition to final pseudocode. They do not treat rule eligibility as evidence of
a rewrite.

## Rollout

1. Add portable typed option and stage-contract models with pure schedule tests.
2. Compile constant-simplification activation from the shared schedule.
3. Separate global const preparation and dynamic observation from readonly
   folding.
4. Project the shared schedule and preparation state into the Workbench.
5. Add independent Z3 transform options and bounded prover outcomes.
6. Migrate bundled configuration-v2 profiles to the canonical shape.
7. Run focused unit tests, architecture checks, and the IDA system fixture.
8. Run the broader local unit and Docker system suites before integration.

## Non-goals

- Letting project configuration expand a rule's supported maturity set.
- Treating pre-Hex preparation as a fake Hex-Rays maturity.
- Automatically restarting decompilation for dynamic const proposals.
- Persisting const types for writable storage under the aggressive folding
  policy.
- Removing direct readonly folding.
- Moving the generic Z3 predicate transforms out of `mba-simplify`.
- Extending Egglog as part of this change.
- Turning routine bounded proof abstentions into errors.
