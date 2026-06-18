# Hex-Rays Hooks Lifecycle And Run-Later Plan

Date: 2026-06-17

Worktree: `/Users/mahmoud/src/idapro/d810/.worktrees/llvm-lisa-restructure`

## Goal

Make `src/d810/hexrays/hooks/hexrays_hooks.py` a thin Hex-Rays lifecycle handler while introducing a provider-neutral way for instruction and block optimization work to ask to `run_later` at a later IR maturity.

The design must support the north star:

> D810 should become the LLVM for deobfuscation.

That means Hex-Rays callbacks are not the architecture. They are one provider/backend adapter. D810-owned pass scheduling, IR maturity, analysis invalidation, and mutation planning must live outside the Hex-Rays hook file and outside live IDA object APIs.

## Core Decision

Use three separate concepts:

1. `hooks`
   - Concrete Hex-Rays/IDA callback plumbing.
   - Allowed to subclass `ida_hexrays.Hexrays_Hooks`, `ida_hexrays.optinsn_t`, and `ida_hexrays.optblock_t`.
   - Allowed to touch live `mba_t`, `mblock_t`, and `minsn_t` objects.
   - Must stay in `d810.hexrays.*` or a Hex-Rays backend package.

2. `lifecycle`
   - Provider event normalization.
   - Converts Hex-Rays callbacks and `MMAT_*` values into D810 lifecycle or provider phase events.
   - Should speak in primitive values and D810 types such as `IRMaturity`, not raw IDA maturity constants outside the adapter boundary.

3. `scheduler`
   - D810 pass execution policy.
   - Owns pending pass work, dedupe, maturity eligibility, budget checks, and draining.
   - Owns the `run_later` concept.
   - Must be provider-neutral and must not import Hex-Rays or IDA.

The guiding sentence:

> Hex-Rays lifecycle tells D810 what maturity exists; passes say `run_later`; the scheduler decides when that request runs.

## Public Vocabulary

Use `run_later`.

Do not use these as public pass API terms for the cross-maturity concept:

- `rerun`
- `followup`
- `follow-up`
- `reschedule`
- `defer`
- `continuation`

Reasoning:

- `rerun` sounds like same-maturity retry or fixpoint iteration.
- `followup` is accurate but too wordy.
- `defer` sounds like the current run did not happen.
- `reschedule` is scheduler-internal, not pass-facing.
- `continuation` is too abstract.

The intended public model:

```python
PassResult(
    ...,
    run_later=(RunLater(at=IRMaturity.GLOBAL_ANALYZED),),
)
```

Meaning:

> This pass already ran. Run it again when IR reaches at least the requested later maturity.

`RunLater.at` is the earliest eligible maturity, not necessarily the exact callback point that will run it. The scheduler drains when `current_maturity >= RunLater.at`.

## Provider Example: Angr Analysis Through A Dewolf-Style Lifecycle

This plan must support analysis providers beyond Hex-Rays. A concrete example is an angr-backed deobfuscation analysis pass running against a Dewolf-style decompiler lifecycle.

Do not model this as one giant `AngrPass`.

Use two separate responsibilities:

1. `angr` is a symbolic-analysis provider.
2. D810 passes consume symbolic facts and decide whether to rewrite IR, request later maturity, or record evidence.

The architectural split should look like this:

```text
Decompiler-native phase
  -> backend lifecycle adapter maps to IRMaturity
  -> scheduler drains eligible D810 passes
  -> D810 pass asks an analysis provider for evidence
  -> analysis provider returns facts
  -> D810 pass decides whether to rewrite, observe, or run_later
```

For Hex-Rays, the lifecycle adapter maps `MMAT_*` to `IRMaturity`.

For Dewolf, the lifecycle adapter would map Dewolf pipeline stages to the same `IRMaturity` ladder. The exact Dewolf mapping must be pinned to Dewolf's real pipeline ordering before implementation, but the intended shape is:

|-|-|
| D810 maturity | Dewolf-style stage shape |
| `IRMaturity.LIFTED` | Raw lifted IR, initial instruction translation, initial CFG materialization. |
| `IRMaturity.CANONICAL` | Preprocessing, canonical cleanup, compiler idiom cleanup, early structural normalization. |
| `IRMaturity.LOCAL_OPTIMIZED` | Local expression simplification, local block cleanup, small-scope algebraic simplification. |
| `IRMaturity.GLOBAL_ANALYZED` | SSA construction, reaching definitions, liveness, dominance, dataflow facts, path predicates. |
| `IRMaturity.GLOBAL_OPTIMIZED` | Global simplification, dead-code cleanup, dataflow-driven expression reduction. |
| `IRMaturity.STRUCTURED` | Control-flow analysis, region recovery, loop structuring, high-level flow reconstruction. |
| `IRMaturity.VARIABLE_RECOVERED` | Out-of-SSA, local variable recovery, variable naming, final high-level local model. |

The same D810 pass should not care whether the current provider is Hex-Rays or Dewolf:

```python
PassResult(
    ...,
    run_later=(
        RunLater(
            at=IRMaturity.GLOBAL_ANALYZED,
            reason="need SSA/dataflow/path facts before symbolic proof is actionable",
        ),
    ),
)
```

This means:

> The pass already ran. It found that the current maturity does not expose enough facts. Run it again after the provider reaches at least `IRMaturity.GLOBAL_ANALYZED`.

The pass is not asking for:

- Hex-Rays `MMAT_GLBOPT1`
- a Dewolf-specific class name
- a specific callback name
- a same-maturity retry
- a provider rewind

It is asking for a later semantic maturity.

### Angr Provider Boundary

An angr integration should live behind an analysis-provider boundary.

The angr provider may consume:

1. Function address.
2. Basic-block address ranges.
3. Raw bytes.
4. Disassembly-level instruction facts.
5. CFG edge candidates.
6. Calling convention hints.
7. Segment, import, relocation, and memory-map facts.
8. Optional constraints supplied by D810 analyses.

The angr provider must not require Hex-Rays pseudocode as source truth.

The angr provider should return symbolic evidence such as:

1. Branch predicate is always true.
2. Branch predicate is always false.
3. Path is infeasible.
4. Block has no observable semantic effect.
5. Two expressions are equivalent under a stated constraint set.
6. Dispatcher state update expression has a recovered next-state value.
7. Memory write is dead under the provider's modeled side-effect policy.
8. Proof is inconclusive, with a reason.

The D810 pass owns the deobfuscation decision.

Do not let angr directly mutate Hex-Rays objects, Dewolf IR, D810 portable IR, or CFG topology. Angr produces evidence. D810 passes turn evidence into rewrite plans or backend mutation requests through the existing safe mutation path.

### Example Pass Shapes

Prefer domain names over provider names.

Good pass names:

|-|-|
| Pass name | Provider-independent purpose |
| `OpaquePredicateAnalysis` | Prove branch direction or infeasibility. |
| `BlockSemanticSummaryAnalysis` | Summarize block side effects and detect semantic no-ops. |
| `DispatcherTransitionRecovery` | Recover state-machine next-state expressions. |
| `MBAExpressionProof` | Prove an obfuscated expression equals a simpler expression. |
| `UnreachablePathPruner` | Remove paths proven infeasible under collected constraints. |

Avoid making the public pass API tool-specific unless the pass is truly inseparable from angr.

Prefer:

```text
OpaquePredicateAnalysis uses an angr-backed symbolic provider.
```

Avoid:

```text
AngrOpaquePredicatePass is hard-wired into the scheduler.
```

This keeps room for another provider to satisfy the same analysis contract later, such as Triton, Miasm, a Z3-only symbolic summary provider, native execution traces, or a future D810-owned symbolic engine.

### Example Run-Later Flow

An opaque-predicate pass can run early and ask for a later maturity only when needed.

1. Dewolf reaches local expression cleanup.

2. The Dewolf lifecycle adapter emits:

   ```text
   provider=dewolf
   native_stage=local_expression_simplification
   maturity=IRMaturity.LOCAL_OPTIMIZED
   ```

3. The scheduler drains passes eligible for `IRMaturity.LOCAL_OPTIMIZED`.

4. `OpaquePredicateAnalysis` runs.

5. The pass asks the angr provider to prove a branch predicate.

6. The angr provider returns inconclusive because global SSA/dataflow facts are missing.

7. The pass returns:

   ```python
   PassResult(
       run_later=(
           RunLater(
               at=IRMaturity.GLOBAL_ANALYZED,
               reason="need global dataflow constraints for branch feasibility proof",
           ),
       ),
   )
   ```

8. The scheduler records a pending run by primitive identity:

   ```text
   (provider_function_id, pass_id, IRMaturity.GLOBAL_ANALYZED)
   ```

9. Dewolf later completes SSA/dataflow analysis.

10. The Dewolf lifecycle adapter emits:

    ```text
    provider=dewolf
    native_stage=ssa_dataflow_ready
    maturity=IRMaturity.GLOBAL_ANALYZED
    ```

11. The scheduler drains the pending run.

12. `OpaquePredicateAnalysis` runs again.

13. The angr provider now receives the stronger constraints.

14. If angr proves the branch direction, the D810 pass creates a rewrite plan or backend mutation request through the approved mutation path.

15. If angr remains inconclusive, the pass records evidence and does not mutate.

This example is the intended meaning of `run_later`: not "try again immediately", not "force the provider to rewind", and not "declare every maturity in advance". It is a pass-local request for a future semantic maturity when more facts are expected to exist.

### North-Star Check

This design supports D810 as the LLVM for deobfuscation because:

1. `IRMaturity` is the portable decompiler lifecycle coordinate.
2. Hex-Rays `MMAT_*` is adapter-local.
3. Dewolf pipeline stage names are adapter-local.
4. Angr is an evidence provider, not the pass scheduler.
5. D810 passes own deobfuscation policy.
6. D810 scheduler owns cross-maturity execution policy.
7. Backend adapters own native lifecycle translation.
8. Backend mutation paths own safe provider-specific mutation.

If an angr integration requires importing Hex-Rays hooks into provider-neutral pass code, the boundary is wrong.

If a Dewolf integration requires adding Dewolf-specific stage names to a D810 pass, the boundary is wrong.

If a scheduler has to know how angr works internally, the boundary is wrong.

If a pass can express "run me later when global facts exist" using only `IRMaturity`, the boundary is right.

## Non-Goals

Do not do these in this refactor:

1. Do not rewrite every optimizer rule return type in one sweep.
2. Do not move live `minsn_t`, `mblock_t`, or `mba_t` handling into `d810.passes`, `d810.ir`, `d810.analyses`, or `d810.transforms`.
3. Do not make lifecycle callbacks own pass scheduling policy.
4. Do not make `hexrays_hooks.py` a central composition root.
5. Do not overload `PreservedAnalyses` for cross-maturity scheduling.
6. Do not add `.importlinter` ignores to force the migration through.
7. Do not add ast-grep ignores to hide boundary violations.
8. Do not bypass DeferredGraphModifier or PatchPlan for live CFG mutation.
9. Do not make scheduler state hold live Hex-Rays objects.
10. Do not ask Hex-Rays to rewind to an earlier maturity if a `run_later` request is missed.

## Existing Constraints To Preserve

Before editing architecture-sensitive code, read and obey the target worktree configuration.

Required files to inspect:

- `.importlinter`
- `rules/no-hexrays-hook-direct-optimizer-imports.yml`
- `rules/no-direct-hexrays-mutation-outside-deferred-modifier.yml`
- `rules/no-live-object-access-in-portable-core.yml`
- `rules/no-live-topology-in-engine-strategy-modules.yml`
- `rules/no-hexrays-mutation-diagnostic-storage-imports.yml`
- `rules/no-optimizers-diagnostic-storage-imports.yml`

Important boundary constraints:

1. `d810.passes.*` must not import `d810.hexrays` or `d810.backends.hexrays`.
2. `d810.analyses.control_flow.*` must not import `d810.hexrays` or `d810.backends.hexrays`.
3. Portable core packages must not import `ida*`.
4. Portable core packages must not import Hex-Rays mutation modules.
5. Hex-Rays mutation modules must not import diagnostic storage directly.
6. Optimizers must not import diagnostic storage directly.
7. Live CFG rewrite must route through DeferredGraphModifier or backend mutation primitives.
8. Hook modules must not directly import concrete optimizer handler modules. Use manager-driven composition and injection.

Known rule maintenance issue:

- `rules/no-hexrays-hook-direct-optimizer-imports.yml` may still refer to old hook file paths such as `src/d810/hexrays/hexrays_hooks.py`.
- The actual hook file in this worktree is `src/d810/hexrays/hooks/hexrays_hooks.py`.
- Update the rule selector if necessary so it covers the real hook files.
- Do not add ignores.

## Target Module Layout

End state:

```text
src/d810/hexrays/hooks/hexrays_hooks.py
src/d810/hexrays/hooks/optinsn_adapter.py
src/d810/hexrays/hooks/optblock_adapter.py
src/d810/hexrays/lifecycle.py
src/d810/passes/scheduler.py
src/d810/passes/pass_pipeline.py
src/d810/manager.py
```

Responsibilities:

1. `src/d810/hexrays/hooks/hexrays_hooks.py`
   - Contains only the concrete `ida_hexrays.Hexrays_Hooks` subclass.
   - Receives IDA decompiler lifecycle callbacks.
   - Delegates to lifecycle services or manager-injected callbacks.
   - Returns IDA-required return codes.
   - May temporarily re-export old class names during migration.

2. `src/d810/hexrays/hooks/optinsn_adapter.py`
   - Contains the concrete `ida_hexrays.optinsn_t` subclass.
   - Owns live instruction callback adaptation only.
   - May touch `minsn_t`.
   - May collect rule-level `run_later` requests from an injected context.
   - Must not import concrete optimizer handler modules.

3. `src/d810/hexrays/hooks/optblock_adapter.py`
   - Contains the concrete `ida_hexrays.optblock_t` subclass.
   - Owns live block callback adaptation only.
   - May touch `mblock_t` and `mba_t`.
   - May collect rule-level `run_later` requests from an injected context.
   - Must not import concrete optimizer handler modules.

4. `src/d810/hexrays/lifecycle.py`
   - Converts Hex-Rays maturity and callback state into D810 lifecycle events.
   - Maps Hex-Rays `MMAT_*` to `IRMaturity`.
   - Emits or returns provider phase events with primitive payloads.
   - Contains `_emit_flowgraph_ready_event` or its successor.
   - May import Hex-Rays adapter utilities because it is still under `d810.hexrays`.

5. `src/d810/passes/scheduler.py`
   - Defines `RunLater`.
   - Defines scheduler-owned pending run records.
   - Owns `PassScheduler`.
   - Stores only primitive identities and D810 enum values.
   - Imports `d810.ir.maturity`, not Hex-Rays.

6. `src/d810/passes/pass_pipeline.py`
   - Adds `PassResult.run_later`.
   - Keeps pass result and pipeline semantics provider-neutral.
   - Does not know how Hex-Rays callbacks work.

7. `src/d810/manager.py`
   - Remains the composition root.
   - Builds adapters.
   - Injects optimizer registries, scheduler, lifecycle observers, recon runtime, and pass pipeline.
   - Wires Hex-Rays-specific adapters to provider-neutral services.

## Phase 0: Ticket And Worktree Hygiene

1. Change directory:

   ```bash
   cd /Users/mahmoud/src/idapro/d810/.worktrees/llvm-lisa-restructure
   ```

2. Check worktree status:

   ```bash
   git status --short
   ```

3. Record that existing dirty files may belong to the user or previous work.

4. Do not revert any unrelated changes.

5. Create or attach a `tk` ticket for this work.

6. Do not use markdown TODOs as the tracker.

7. Run graphify first for architecture questions if needed:

   ```bash
   graphify query "How should hexrays hooks, lifecycle events, and pass scheduling be split in this worktree?"
   ```

## Phase 1: Mechanical Extraction With No Behavior Change

Objective:

Move large classes out of `hexrays_hooks.py` without changing runtime semantics.

Steps:

1. Create `src/d810/hexrays/hooks/optinsn_adapter.py`.

2. Move `InstructionOptimizerManager` from `hexrays_hooks.py` into `optinsn_adapter.py`.

3. Keep the class name initially as `InstructionOptimizerManager`.

4. Do not rename the class during the first move.

5. Copy only imports needed by `InstructionOptimizerManager`.

6. Remove imports from `hexrays_hooks.py` only after the moved class compiles in its new module.

7. Ensure `optinsn_adapter.py` imports `ida_hexrays` only because it is a Hex-Rays hook adapter.

8. Ensure `optinsn_adapter.py` does not import concrete optimizer handler modules.

9. Keep optimizer classes injected by `manager.py`.

10. Create `src/d810/hexrays/hooks/optblock_adapter.py`.

11. Move `BlockOptimizerManager` from `hexrays_hooks.py` into `optblock_adapter.py`.

12. Keep the class name initially as `BlockOptimizerManager`.

13. Do not rename the class during the first move.

14. Copy only imports needed by `BlockOptimizerManager`.

15. Ensure `optblock_adapter.py` imports `ida_hexrays` only because it is a Hex-Rays hook adapter.

16. Ensure `optblock_adapter.py` does not import concrete optimizer handler modules.

17. Leave compatibility imports in `hexrays_hooks.py`:

   ```python
   from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager
   from d810.hexrays.hooks.optblock_adapter import BlockOptimizerManager
   ```

18. Add a short compatibility comment if needed:

   ```python
   # Compatibility exports while callers migrate to the adapter modules.
   ```

19. Do not update every import site yet unless a test or import cycle requires it.

20. Run a narrow import check:

   ```bash
   PYTHONPATH=src python3 - <<'PY'
   from d810.hexrays.hooks.hexrays_hooks import HexraysDecompilationHook
   from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager
   from d810.hexrays.hooks.optblock_adapter import BlockOptimizerManager
   print("ok")
   PY
   ```

Expected result:

- The class move succeeds.
- No behavior has intentionally changed.
- `hexrays_hooks.py` is smaller but still provides compatibility exports.

## Phase 2: Extract Lifecycle Translation

Objective:

Move provider event normalization out of the hook file.

Steps:

1. Create `src/d810/hexrays/lifecycle.py` if it does not already exist.

2. Move `DecompilationEvent` from `hexrays_hooks.py` into `hexrays/lifecycle.py`.

3. Move `_emit_flowgraph_ready_event` from `hexrays_hooks.py` into `hexrays/lifecycle.py`.

4. Keep names initially unchanged.

5. If `_emit_flowgraph_ready_event` needs Hex-Rays-specific lifting, keep that in `d810.hexrays.lifecycle` or delegate to an existing Hex-Rays lifter.

6. Do not move `_emit_flowgraph_ready_event` into `d810.passes`, `d810.ir`, `d810.analyses`, or `d810.transforms`.

7. Ensure lifecycle payloads crossing into provider-neutral code contain only:
   - function address
   - maturity as `IRMaturity`
   - primitive IDs
   - immutable snapshots
   - provider phase snapshots

8. Ensure lifecycle payloads do not contain:
   - `mba_t`
   - `mblock_t`
   - `minsn_t`
   - live Hex-Rays verifier objects
   - raw diagnostic storage handles

9. Update `hexrays_hooks.py` to call lifecycle helpers.

10. Keep `hexrays_hooks.py` responsible only for:
    - receiving IDA callback arguments
    - converting or delegating conversion
    - returning the IDA-required value

Expected result:

- Lifecycle translation has a home.
- Hook code no longer owns flowgraph-ready event construction.
- Provider-neutral packages remain free of Hex-Rays imports.

## Phase 3: Make `hexrays_hooks.py` Thin

Objective:

Reduce `hexrays_hooks.py` to callback adapter code.

Allowed in `hexrays_hooks.py`:

1. `ida_hexrays.Hexrays_Hooks` subclass.
2. IDA callback method names.
3. IDA return code handling.
4. Minimal guard logic needed by IDA callback contracts.
5. Delegation to injected lifecycle services.
6. Temporary compatibility re-exports.

Not allowed in `hexrays_hooks.py`:

1. Optimizer manager class definitions.
2. Static optimizer maturity defaults.
3. Pass pipeline scheduling policy.
4. Recon collection logic.
5. Diagnostic persistence.
6. Late mutation probes.
7. Z3 proof logging.
8. Flowgraph translation internals.
9. Direct imports of concrete optimizer handlers.
10. Direct diagnostic storage imports.

Detailed cleanup:

1. Find all remaining top-level helper functions in `hexrays_hooks.py`.

2. For each helper, classify it:
   - IDA callback glue: keep.
   - provider lifecycle translation: move to `d810.hexrays.lifecycle`.
   - optimizer execution: move to `optinsn_adapter.py` or `optblock_adapter.py`.
   - pass scheduling: move to `d810.passes.scheduler`.
   - diagnostics: move behind observability or diagnostics facade.
   - mutation: move behind Hex-Rays mutation/DGM modules.

3. Move one helper category at a time.

4. After each move, run the narrow import check from Phase 1.

5. Do not perform broad semantic rewrites while extracting helpers.

Expected result:

- `hexrays_hooks.py` is explainable as "Hex-Rays decompiler lifecycle callback adapter".

## Phase 4: Add Provider-Neutral Scheduler Types

Objective:

Introduce `run_later` without tying it to Hex-Rays.

Create `src/d810/passes/scheduler.py`.

Minimum types:

```python
from __future__ import annotations

from dataclasses import dataclass

from d810.ir.maturity import IRMaturity


@dataclass(frozen=True)
class RunLater:
    at: IRMaturity
    reason: str = ""


@dataclass(frozen=True)
class PendingRun:
    func_ea: int
    pass_id: str
    at: IRMaturity
    reason: str = ""
```

Minimum scheduler behavior:

```python
class PassScheduler:
    def request(
        self,
        *,
        func_ea: int,
        pass_id: str,
        current_maturity: IRMaturity,
        run_later: RunLater,
    ) -> bool:
        ...

    def drain(
        self,
        *,
        func_ea: int,
        current_maturity: IRMaturity,
    ) -> tuple[PendingRun, ...]:
        ...

    def reset_func(self, func_ea: int) -> None:
        ...

    def reset_all(self) -> None:
        ...
```

Rules:

1. Reject `RunLater.at <= current_maturity`.

2. Same-maturity repeats are not `run_later`.

3. Same-maturity repeats should continue to use existing generation or fixpoint mechanisms.

4. Dedupe by:

   ```python
   (func_ea, pass_id, run_later.at)
   ```

5. Store pending runs by function.

6. Drain pending runs where:

   ```python
   pending.at <= current_maturity
   ```

7. Remove drained pending runs before returning them.

8. Add a per-function request budget.

9. If budget is exceeded, reject the request and emit an observation or logger message.

10. Scheduler must not import:
    - `ida_hexrays`
    - `idaapi`
    - `d810.hexrays`
    - `d810.backends.hexrays`
    - concrete optimizer modules
    - diagnostic storage modules

11. Scheduler must store no live objects.

12. Scheduler must be unit-testable without IDA.

Expected result:

- A provider-neutral scheduler can remember future pass work.

## Phase 5: Extend `PassResult`

Objective:

Allow portable passes to ask to `run_later`.

Modify `src/d810/passes/pass_pipeline.py`.

Steps:

1. Import `RunLater` from `d810.passes.scheduler`.

2. Add a field to `PassResult`:

   ```python
   run_later: tuple[RunLater, ...] = ()
   ```

3. Preserve all existing fields.

4. Give `run_later` a default empty tuple.

5. Do not change existing call sites unless type checking or tests require it.

6. Do not put `run_later` into `PreservedAnalyses`.

7. Add or update tests for:
   - default `PassResult()` construction remains compatible
   - `PassResult(run_later=(RunLater(...),))` stores the request

Expected result:

- Passes can express cross-maturity work through the pass result.

## Phase 6: Connect Pipeline Results To Scheduler

Objective:

When a portable pass returns `run_later`, record it in the scheduler.

Steps:

1. Find the pass driver that runs `PassResult` objects.

2. After each pass returns, iterate:

   ```python
   for request in result.run_later:
       scheduler.request(
           func_ea=context.source.func_ea,
           pass_id=spec.pass_id,
           current_maturity=context.maturity,
           run_later=request,
       )
   ```

3. If `FunctionPipelineContext` does not expose the function address directly, use the existing source identity object.

4. Do not import Hex-Rays to discover function identity.

5. If the scheduler is not available, leave existing behavior unchanged.

6. Prefer dependency injection:
   - pipeline driver receives scheduler
   - manager wires scheduler into driver

7. Avoid global scheduler state unless the repo already has an established lifecycle singleton pattern.

Expected result:

- Portable passes can request later runs.
- The scheduler records those requests.

## Phase 7: Bridge Legacy Instruction And Block Optimizers

Objective:

Let current instruction and block optimizers request `run_later` without rewriting every optimizer return type.

Problem:

- Instruction optimizers may currently return `minsn_t | None`.
- Block optimizers may currently mutate through existing block mechanisms or return booleans.
- Forcing all legacy optimizer rules to return `PassResult` is too much blast radius.

Plan:

1. Introduce a small execution context or request sink.

2. Name the public method:

   ```python
   context.run_later(IRMaturity.GLOBAL_ANALYZED, reason="...")
   ```

3. The context stores:

   ```python
   tuple[RunLater, ...]
   ```

4. The context must not store live Hex-Rays objects unless it remains entirely adapter-local.

5. The adapter creates a fresh context per optimizer invocation or per pass invocation.

6. The optimizer may call:

   ```python
   self.context.run_later(IRMaturity.GLOBAL_ANALYZED, reason="need global facts")
   ```

   or the equivalent local API pattern already used in the optimizer framework.

7. After the optimizer invocation completes, the adapter extracts collected `RunLater` values.

8. The adapter calls the injected scheduler:

   ```python
   scheduler.request(
       func_ea=...,
       pass_id=...,
       current_maturity=...,
       run_later=request,
   )
   ```

9. The adapter is responsible for obtaining `func_ea` and current maturity from Hex-Rays objects.

10. The scheduler remains provider-neutral.

11. Legacy optimizers that never call `run_later` behave exactly as before.

Expected result:

- Existing instruction and block optimizers can opt into later runs incrementally.
- No broad return-type rewrite is required.

## Phase 8: Drain Scheduler On Lifecycle Maturity Events

Objective:

Run pending work when the provider reaches a suitable later IR maturity.

Flow:

1. Hex-Rays callback fires.

2. `hexrays_hooks.py` receives the callback.

3. `hexrays_hooks.py` delegates maturity conversion to `hexrays/lifecycle.py`.

4. `hexrays/lifecycle.py` maps Hex-Rays maturity to `IRMaturity`.

5. Lifecycle coordinator or `manager.py` calls:

   ```python
   scheduler.drain(func_ea=func_ea, current_maturity=maturity)
   ```

6. For each drained `PendingRun`, invoke the appropriate pass or optimizer path.

7. The invocation path must respect the pass family:
   - portable pass pipeline for pipeline passes
   - instruction adapter for instruction optimizer runs
   - block adapter for block optimizer runs

8. Do not make `PassScheduler` know how to call Hex-Rays.

9. Do not make `PassScheduler` import adapter modules.

10. A separate coordinator may translate `PendingRun` into backend-specific execution.

Missed maturity rule:

1. If a pass asks to run later at a maturity that has already passed, reject the request.

2. Do not ask Hex-Rays to rewind.

3. If the same information should be recovered earlier, that is a separate recovery-stage problem, not a `run_later` scheduling problem.

Expected result:

- Later maturity events drain pending requests.
- Provider callback code remains thin.

## Phase 9: Safety And Maturity Policy

Objective:

Ensure `run_later` cannot bypass static safety.

Rules:

1. Passes may ask for `run_later`.

2. The scheduler or scheduler coordinator validates pass eligibility.

3. Validation must check pass metadata:
   - pass id exists
   - requested maturity is later than current maturity
   - requested maturity is allowed by pass metadata
   - requested maturity is supported by the provider
   - request does not exceed budget

4. For legacy block rules with `SAFE_MATURITIES`, continue to respect `SAFE_MATURITIES`.

5. For rule config `maturities`, continue to respect configured maturities.

6. `run_later` must be additive, not a bypass.

7. If static safety says a pass cannot run at `GLOBAL_ANALYZED`, a `RunLater(at=GLOBAL_ANALYZED)` request is rejected.

8. Rejection must be observable.

9. Rejection should not crash decompilation.

10. Profile-specific guards remain profile-specific.

11. Do not generalize OLLVM-only vetoes to Tigress or other profiles.

12. Do not weaken fragment-atomic safety vetoes.

Expected result:

- `run_later` is safe by construction.

## Phase 10: Remove Remaining Hook Bloat

Objective:

After extraction and scheduler introduction, remove responsibilities still stuck in hook modules.

Review every remaining non-trivial block in `hexrays_hooks.py`.

Move by category:

1. Optimizer class state
   - Move to `optinsn_adapter.py` or `optblock_adapter.py`.

2. Rule scoping and active optimizer cache
   - Keep adapter-local if it depends on Hex-Rays callback state.
   - Move manager-owned configuration to `manager.py`.

3. Recon reset and hint application
   - Move to recon runtime or lifecycle subscriber.
   - Manager should wire it.

4. FLOWGRAPH_READY event emission
   - Move to `hexrays/lifecycle.py`.

5. Diagnostic snapshots
   - Move behind diagnostics or observability facade.
   - Do not import diagnostic storage directly from hooks if boundary rules forbid it.

6. Late `_maybe_rewrite_*` probes
   - Move into a Hex-Rays backend mutation service or DGM-backed mutation module.
   - If a probe performs live CFG mutation, it must route through DGM or approved backend mutation primitives.

7. Z3 proof logging
   - Move to analysis/evidence layer or an injected proof observer.
   - Keep hook path as an event source only.

8. Static default maturity lists
   - Move toward pass metadata, optimizer handler defaults, or manager configuration.
   - Do not leave defaults in `hexrays_hooks.py`.

Expected result:

- Hook file is thin and boring.
- Subsystems own their own behavior.

## Phase 11: Update Imports And Compatibility

Objective:

Move callers to the new module layout without breaking compatibility abruptly.

Steps:

1. Update `src/d810/manager.py` imports:

   ```python
   from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager
   from d810.hexrays.hooks.optblock_adapter import BlockOptimizerManager
   from d810.hexrays.hooks.hexrays_hooks import HexraysDecompilationHook
   ```

2. Keep temporary compatibility re-exports in `hexrays_hooks.py`.

3. Use `rg` to find imports of moved classes:

   ```bash
   rg "InstructionOptimizerManager|BlockOptimizerManager|DecompilationEvent|_emit_flowgraph_ready_event" src tests
   ```

4. Update production imports first.

5. Update tests second.

6. Do not update unrelated files.

7. Once all callers use new modules, remove compatibility re-exports only if no downstream compatibility concern remains.

8. If compatibility exports stay, mark them explicitly and keep them minimal.

Expected result:

- `manager.py` wires concrete adapters directly.
- `hexrays_hooks.py` no longer acts as the accidental public module for all Hex-Rays optimizer machinery.

## Phase 12: Tests To Add

Add focused unit tests. Do not rely on live IDA for scheduler behavior.

Scheduler tests:

1. `RunLater` stores an `IRMaturity`.

2. Scheduler accepts a later maturity request.

3. Scheduler rejects same maturity.

4. Scheduler rejects earlier maturity.

5. Scheduler dedupes repeated `(func_ea, pass_id, at)` requests.

6. Scheduler drains when current maturity reaches requested maturity.

7. Scheduler does not drain before requested maturity.

8. Scheduler removes drained entries.

9. `reset_func` clears only that function.

10. `reset_all` clears everything.

11. Budget exhaustion rejects additional requests.

12. Rejected requests are observable or logged.

Pass result tests:

1. Existing `PassResult` construction remains compatible.

2. `PassResult.run_later` defaults to `()`.

3. `PassResult.run_later` accepts `RunLater`.

Pipeline tests:

1. Pipeline records `run_later` returned by a pass.

2. Pipeline does not record anything for empty `run_later`.

3. Pipeline continues to apply rewrite plans as before.

4. `PreservedAnalyses` behavior is unchanged.

Adapter tests:

1. Instruction adapter can collect `context.run_later(...)`.

2. Block adapter can collect `context.run_later(...)`.

3. Legacy optimizer returning old result shape still works.

4. Adapter passes only primitive request data into scheduler.

Boundary tests:

1. Importing `d810.passes.scheduler` works without IDA installed.

2. Importing `d810.passes.pass_pipeline` works without IDA installed.

3. Scheduler does not import `d810.hexrays`.

## Phase 13: Validation Commands

Run from:

```bash
cd /Users/mahmoud/src/idapro/d810/.worktrees/llvm-lisa-restructure
```

Required local validation:

```bash
PYTHONPATH=src pytest tests/unit
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
graphify update .
```

If touching live Hex-Rays behavior, run system tests only through the docker wrapper:

```bash
./tools/scripts/run_system_tests_docker.sh system -w /Users/mahmoud/src/idapro/d810/.worktrees/llvm-lisa-restructure -l -o .tmp/logs/hexrays-hooks-run-later.log
```

Do not run:

```bash
pytest tests/system
```

Raw system pytest can produce false failures because it lacks the expected Docker/IDA environment.

## Acceptance Criteria

The refactor is complete only when all of these are true:

1. `hexrays_hooks.py` contains only Hex-Rays decompiler lifecycle callback adapter code plus optional temporary compatibility exports.

2. `InstructionOptimizerManager` no longer lives in `hexrays_hooks.py`.

3. `BlockOptimizerManager` no longer lives in `hexrays_hooks.py`.

4. Flowgraph-ready lifecycle emission no longer lives in `hexrays_hooks.py`.

5. Provider lifecycle conversion has a dedicated Hex-Rays lifecycle module.

6. `RunLater` exists in provider-neutral pass/scheduler code.

7. `PassResult` supports `run_later`.

8. Portable passes can return `run_later`.

9. Legacy instruction/block optimizers can request `run_later` without a broad return-type rewrite.

10. Scheduler stores only primitive identities and `IRMaturity`, never live Hex-Rays objects.

11. Scheduler rejects same-or-earlier maturity requests.

12. Scheduler dedupes pending requests.

13. Scheduler drains at or after the requested maturity.

14. Scheduler is unit-testable without IDA.

15. No portable module imports `ida_hexrays`, `idaapi`, `d810.hexrays`, or `d810.backends.hexrays`.

16. Hook modules do not directly import concrete optimizer handler modules.

17. Mutation still routes through DeferredGraphModifier, PatchPlan, or approved backend mutation primitives.

18. Diagnostic storage imports do not leak into optimizers or Hex-Rays mutation modules.

19. `.importlinter` passes.

20. `sg scan` passes.

21. Relevant unit tests pass.

22. `graphify update .` has been run after code changes.

## Implementation Order Summary

Execute in this order:

1. Create or attach `tk` ticket.
2. Inspect `.importlinter` and relevant ast-grep rules.
3. Extract instruction optimizer manager to `optinsn_adapter.py`.
4. Extract block optimizer manager to `optblock_adapter.py`.
5. Add compatibility re-exports in `hexrays_hooks.py`.
6. Extract lifecycle event types/helpers to `hexrays/lifecycle.py`.
7. Thin `hexrays_hooks.py` to callback delegation.
8. Add provider-neutral `d810.passes.scheduler`.
9. Add `PassResult.run_later`.
10. Wire portable pass pipeline results into scheduler.
11. Add adapter-local context/sink for legacy optimizer `run_later`.
12. Drain scheduler from lifecycle maturity events.
13. Enforce pass safety and maturity eligibility.
14. Move remaining diagnostics, recon, mutation, and proof logic out of hooks.
15. Update imports and tests.
16. Run validation gates.
17. Update graphify.

## Final Design Check

Before calling the work done, answer these questions:

1. If Hex-Rays were replaced by another provider, could `d810.passes.scheduler` still work?

2. Can `RunLater` be understood without knowing what `MMAT_GLBOPT1` means?

3. Does any portable module import a live Hex-Rays API?

4. Does `hexrays_hooks.py` do anything beyond callback adaptation?

5. Can a pass say `run_later` without scheduling itself directly?

6. Can the scheduler reject unsafe requests without crashing decompilation?

7. Are same-maturity loops still handled by existing generation/fixpoint mechanisms instead of `run_later`?

8. Is lifecycle still provider event vocabulary rather than scheduling policy?

If any answer is wrong, the refactor is not finished.
