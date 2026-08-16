# Poison Restart Provenance and Early-Quarantine Design

## Problem

While decompiling `sub_7FF856629E30` (`0x7FF856629E30`), the simple
flattening cleanup family applied a `fake_jump` transaction at
`MMAT_GLBOPT1`. Post-publication reachability validation found that the
transaction made an effectful block at `0x7FF85662A96E` unreachable. The live
MBA was therefore poisoned and a controller-owned restart was staged.

The restart lifecycle then exhibited three defects:

1. The synchronous Hex-Rays decompile continued through the remaining D810
   rules, `MMAT_GLBOPT2`, final analysis, and rendering after poison was known.
2. The generic restart was consumed by the computed-goto flowchart handler and
   logged as `computed_goto_calls_evidence_rebind`, although the diagnostic
   receipt identified `poisoned_generation_restart` and the evidence generation
   remained `0`.
3. The recovery generation could re-enter mutation-producing cleanup code. A
   later guard stopped the cleanup family itself, but no common mutation
   authority enforced quarantine across every D810 adapter.

The observed restart did not bind changed evidence. Its only purpose was to
discard an unsafe live MBA and construct a clean one.

## Goals

- Preserve restart kind and provenance from request through consumption.
- Never label poison recovery as computed-goto evidence rebinding.
- Stop all further D810 mutation work as soon as a live MBA is poisoned.
- Run a clean, mutation-abstaining recovery decompile for unexpected poison.
- Reject the observed unsafe `fake_jump` fragment before live publication so
  `sub_7FF856629E30` does not require poison recovery at all.
- Prove the behavior with unit, runtime, committed-fixture, and live evidence.

## Non-goals

- Do not throw Python exceptions through `optblock_t` or `optinsn_t` SWIG
  callbacks to interrupt Hex-Rays.
- Do not rely on undocumented microcode error codes from optimizer callbacks.
- Do not weaken post-publication safety validation or accept poisoned output.
- Do not make Egglog, MBA solving, or computed-goto discovery responsible for
  transaction recovery.
- Do not promise that Hex-Rays itself stops immediately. Its active synchronous
  decompile may continue internally until it returns to the manager; the hard
  guarantee is that D810 performs no further mutation work on that MBA.

## Restart Model

Introduce a typed restart receipt owned by native preanalysis lifecycle state:

```python
class GeneratedRestartKind(Enum):
    EVIDENCE_REBIND = "evidence_rebind"
    POISON_RECOVERY = "poison_recovery"


@dataclass(frozen=True)
class GeneratedRestartReceipt:
    kind: GeneratedRestartKind
    evidence_family: str
    reason: str
    evidence_generation: int
```

The pending lifecycle field stores the complete receipt rather than parallel
generation/family fields. Compatibility properties may project the old fields
temporarily, but all new control flow consumes the typed receipt.

Consumption is owner-specific:

- The flowchart evidence-rebind handler may consume only
  `EVIDENCE_REBIND`. It emits a reason derived from the receipt's actual
  evidence family.
- The manager may consume only `POISON_RECOVERY`, after the poisoned
  `decompile()` call returns. It invalidates the cached cfunc and starts one
  clean recovery decompile without asking the computed-goto handler for
  `MERR_REDO`.
- An owner presented with the other kind abstains and leaves the receipt
  pending.

Evidence and poison retries retain separate one-retry budgets. Consuming a
poison receipt marks the current evidence epoch as a poison-recovery epoch.
Repeated poison in that epoch remains terminal and poisoned output is refused.

## Generation-wide Quarantine

Native preanalysis lifecycle state exposes one authoritative predicate:

```python
native_mutation_quarantined: bool
```

It is true when either:

- poison recovery is pending for the current evidence epoch;
- poison recovery is active after the manager consumed its receipt; or
- the poison retry budget is exhausted.

Quarantine is enforced at multiple boundaries:

1. `optinsn_t` and `optblock_t` adapters return no change before invoking any
   D810 optimizer or pass pipeline.
2. mutation-producing Hex-Rays lifecycle hooks abstain before invoking their
   mutation body.
3. the shared mutation publication gateway refuses a new transaction as a hard
   backstop if quarantine becomes active between planning and publication.

Read-only diagnostics and lifecycle completion remain enabled. Quarantine logs
one structured event per MBA/maturity boundary, not one line per instruction or
block.

The existing cleanup-family guard becomes a redundant defense and remains in
place until all adapter-level tests are established.

## Clean Poison Recovery

After a poisoned top-level `decompile()` returns, the manager performs this
sequence:

1. Read the pending typed receipt.
2. If it is `POISON_RECOVERY`, consume it at the manager boundary.
3. Close any collector attached to the discarded result.
4. Invalidate the cached cfunc.
5. Start one recovery decompile with mutation quarantine active.
6. Accept the result only if no new poison is reported.

The recovery decompile reconstructs the MBA from the unchanged native input.
It is a safety fallback, not evidence rebinding. It does not pass through the
computed-goto `MERR_REDO` consumer.

For `EVIDENCE_REBIND`, existing controller behavior remains: the manager starts
the follow-up, the flowchart owner consumes the evidence receipt, and Hex-Rays
receives the supported `MERR_REDO` at that boundary.

## Pre-mutation `fake_jump` Safety Projection

The immediate cause in `sub_7FF856629E30` must be rejected before mutation.
Before compiling a selected `fake_jump` fragment into live Hex-Rays edits:

1. Apply its supported patch operations to the portable `FlowGraph` snapshot.
2. Recompute entry reachability on the projected graph.
3. Compare the projected reachable effectful block identities with the original
   snapshot, using EA-anchored stable identities rather than block serials.
4. If any previously reachable effectful block becomes unreachable, reject the
   entire fragment as a clean semantic-preflight failure.
5. If an operation cannot be represented faithfully in the portable
   projection, abstain cleanly instead of publishing optimistically.

The live backend is not invoked for a rejected fragment, so the MBA remains
unpoisoned and no restart is requested. Post-publication validation remains
mandatory as defense in depth.

## Observability

Every restart event records:

- restart kind;
- evidence family;
- requester and consumer;
- evidence generation before and after;
- whether native inputs changed;
- whether a fresh decompile or `MERR_REDO` was selected;
- quarantine state.

Expected poison recovery logs use `poison_recovery`, never
`computed_goto_calls_evidence_rebind`. The latter is reserved for an actual
computed-goto/call evidence receipt.

The exact fixture must show a clean preflight rejection containing the lost
effectful EA anchor, with `mutation_started=0`, `poisoned=0`, and no generated
restart.

## Testing

### Pure lifecycle tests

- Request and consume each restart kind with the correct owner.
- Prove the wrong owner cannot consume a receipt.
- Preserve evidence family and reason through consumption.
- Keep evidence generation unchanged for poison recovery.
- Preserve the one-retry poison budget and terminal exhaustion behavior.

### Adapter runtime tests

- After poison is staged, `optinsn_t` invokes zero instruction optimizers.
- After poison is staged, `optblock_t` invokes zero block optimizers or pass
  pipelines.
- The same abstention holds after the manager consumes the poison receipt and
  during recovery.
- Read-only lifecycle completion still runs.

### Controller tests

- Evidence rebinding still follows the flowchart `MERR_REDO` path.
- Poison recovery is consumed by the manager and performs exactly one fresh
  decompile without a computed-goto redo request.
- A second poison is terminal and no poisoned result is returned.

### Transaction tests

- A portable `fake_jump` projection that loses an effectful block is rejected
  before backend apply.
- Safe `fake_jump` fragments still publish.
- Unsupported projection operations abstain cleanly.

### Fixture and live verification

- Commit a MASM fixture exported through the existing fixture flow that
  reproduces the `sub_7FF856629E30` `fake_jump` reachability hazard.
- Run the relevant Docker system tests through
  `tools/scripts/run_system_tests_docker.sh` from the main repository root.
- Live-decompile `0x7FF856629E30` and retain before/after pseudocode, restart
  events, mutation receipts, and elapsed timing.

## Acceptance Criteria

The work is complete only when all of the following are true:

1. The committed fixture rejects the unsafe fragment before live mutation.
2. Its receipt reports `mutation_started=0` and `poisoned=0`.
3. No poison restart is requested for the fixture or live target.
4. A synthetic unexpected-poison case performs one clean recovery decompile,
   with no D810 mutation work after poison and no computed-goto redo label.
5. Ordinary computed-goto/call evidence rebinding still uses `MERR_REDO` and
   retains its exact evidence provenance.
6. The exact live function returns pseudocode without poison exhaustion.
7. Focused tests, relevant system tests, ast-grep, import-linter, and graphify
   update all complete successfully.
