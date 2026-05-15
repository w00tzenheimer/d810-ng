# Unflattening Engine Extraction & Architecture Unification

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `flattening/engine` the normal execution model for all
unflattening work, not just the historical Hodur package. The state-machine
unflattener remains the proving client because it has the hardest live
semantics, but the architecture target is broader: simple transforms, legacy
`generic.py` dispatcher lowering, state-machine unflattening, and future CFF
families should all use the same detect -> snapshot -> plan -> execute pipeline
and the same `recon` -> `cfg` -> backend materialization boundaries.

**Architecture:** One execution model (detect -> snapshot -> plan -> execute)
with variable complexity per strategy family. Simple transforms (FakeJump,
BadWhileLoop) are trivial families or strategies with one-edit plans. Complex
attacks (the multi-strategy state-machine pipeline, emulated dispatcher
lowering, future Tigress-like families) use the same engine with richer
detection, snapshot, planning, and validation. Shared analysis belongs in
`recon/flow`; backend-agnostic graph plans belong in `cfg`; Hex-Rays-specific
mutation stays behind the existing backend/materialization layer. `hodur`
should be treated as the historical package/compatibility entrypoint for the
state-machine unflattener, not as the family/framework that owns the
architecture.

**Tech Stack:** Python 3.13, IDA Pro 9+ microcode API, pytest, d810 plugin infrastructure

---

## Table of Contents

1. [Research & Reasoning](#research--reasoning)
2. [Architecture Decision Record](#architecture-decision-record)
3. [Current Status: 2026-05-14](#current-status-2026-05-14)
4. [Revised Execution Order](#revised-execution-order)
5. [Historical Execution Order Correction](#historical-execution-order-correction)
6. [File Structure](#file-structure)
7. [P0: Engine Extraction](#p0-engine-extraction)
8. [P1: CFFStrategyFamily Orchestrator](#p1-cffstrategyfamily-orchestrator)
9. [P2: Wrap Simple Transforms](#p2-wrap-simple-transforms)
10. [P3: Wrap generic.py Emulated-Dispatcher Family](#p3-wrap-genericpy-emulated-dispatcher-family)
11. [P4: Audit linearized_state_dag Generality](#p4-audit-linearized_state_dag-generality)
12. [P5: Document Extension Contract](#p5-document-extension-contract)

---

## Research & Reasoning

### Problem Statement

The hodur subpackage was built as an analysis-driven unflattening strategy for OLLVM-style control flow flattening. During development, it grew into a general-purpose multi-strategy unflattening engine with:
- A `UnflatteningStrategy` protocol (strategy.py, 342 lines)
- A central planner with greedy independent-set conflict resolution (planner.py, 927 lines)
- A transactional executor with verification gates (executor.py, 1013 lines)
- Decision provenance tracking (provenance.py, 388 lines)
- Immutable analysis snapshots (snapshot.py, 91 lines)
- Quality metrics (metrics.py, 49 lines)

This infrastructure was originally architecturally general but lived inside
`flattening/hodur/`, forcing any future strategy to import from a sibling
attack package. The current branch has already extracted the core engine
package. The remaining work is no longer "copy Hodur files into engine"; it is
to make every unflattening family consume the shared engine and to move generic
Hodur-grown algorithms to `recon`/`cfg` when they are not actually
family-specific.

The old unflattening framework (`generic.py`) is still important because it
represents the other production unflattening lineage. Its behavior should be
adapted into the family/strategy model incrementally rather than treated as a
separate paradigm.

### Package Audit Results

#### Existing Packages

**recon/** — Read-only reconnaissance pipeline with 9 collectors, SQLite persistence, analysis classification, hint emission. Extension protocols: `ReconCollector`, `TransitionBuilderStrategy`, `ConsumerOutcomeReport`.

**recon/flow/** — 37 Python files. Algorithm classification:
- Pure algorithms (4): graph_reachability, dispatch_region, interval_map, dag_index
- CFF-general (27+): state_machine_analysis, linearized_state_dag, terminal_family, reconstruction_discovery, path_horizon, dispatcher_detection, transition_builder, transition_report, etc.
- Dispatcher-specific shared analyses (5+): bst_model, bst_analysis, transition_bst_adapter, switch_table_analysis, dispatcher_handler_map
- OLLVM-hardcoded (0): nothing hardcodes OLLVM constants

**Key finding**: recon/flow IS the general CFF analysis framework. It was built through hodur but the abstractions are strategy-agnostic. 65% of files have hodur as the only consumer, but this is because hodur is the first (and only) CFF attack — not because the algorithms are hodur-specific.

**cfg/** — Backend-agnostic CFG infrastructure. FlowGraph snapshots, GraphModification intents, PatchPlan compilation, CfgTransactionEngine, transforms, contracts. Already general-purpose.

**flattening/** (non-hodur) — 18 top-level files:
- `generic.py`: Base classes (GenericDispatcherBlockInfo, GenericDispatcherInfo, GenericDispatcherCollector, GenericUnflatteningRule)
- `unflattener.py`: OLLVM emulation (Unflattener, OllvmDispatcherCollector, OllvmDispatcherInfo)
- `unflattener_switch_case.py`: Tigress jump-table (UnflattenerSwitchCase)
- `unflattener_badwhile_loop.py`: Bad while(1) removal (BadWhileLoop)
- `unflattener_single_iteration.py`: Single-iteration loop removal
- `unflattener_fake_jump.py`: Fake jump simplification
- `unflattener_indirect.py`: Tigress indirect dispatcher
- `services.py`: Experimental composition-based architecture (prototype, not production)
- Plus: abc_block_splitter, block_merge, fix_pred_cond_jump_block, safeguards, exceptions, mba_state_preconditioner

#### Import Coupling Analysis

Hodur's engine files are consumed by:
- **strategy.py**: 21 internal consumers (15 strategies + executor + planner + unflattener + metrics + 2 others)
- **provenance.py**: 4 internal consumers (executor, planner, unflattener) + 1 external (recon/outcome.py under TYPE_CHECKING)
- **snapshot.py**: 20+ internal consumers (all strategies + analysis + unflattener + planner + return_sites)
- **planner.py**: 1 internal (unflattener.py)
- **executor.py**: 1 internal (unflattener.py)
- **metrics.py**: 1 internal (unflattener.py)

No non-hodur production code imports these at runtime (recon/outcome.py imports provenance only under TYPE_CHECKING).

### Completed Pre-Engine Milestone: Switch-Table Dispatcher Linearization

The live branch has now validated an additional dispatcher family before any
`flattening/engine` extraction:

- shared dispatcher IR in `src/d810/recon/flow/dispatcher_handler_map.py`
- shared switch-table analysis in `src/d810/recon/flow/switch_table_analysis.py`
- Hodur fallback adaptation in `src/d810/optimizers/microcode/flow/flattening/hodur/unflattener.py`
- existing downstream strategies reused unchanged via a synthetic BST bridge

This matters architecturally because it proves the next layer of reuse lands in
`recon/flow` first, with Hodur acting as the first consumer. The engine did not
need to change to support this dispatcher family.

Current scope boundary:
- exact/unique case-to-handler mappings are supported
- aliased switch cases are explicitly rejected for now
- full alias/range modeling is deferred to a later phase

### Key Architectural Decisions

#### Decision 1: One Paradigm, Variable Complexity

detect -> snapshot -> plan -> execute is universal, not hodur-specific.

Simple transforms already follow this pattern implicitly:
- BadWhileLoop: detect=1 pattern match, plan=1 edge removal, execute=1 mutation
- FakeJump: detect=1 pattern match, plan=1 simplification, execute=1 mutation

The "overhead" of wrapping them in the engine is ~20 lines of protocol glue with zero runtime cost. The benefit: single mental model, composability, provenance, conflict resolution, rollback safety.

#### Decision 2: generic.py Is Not a Different Paradigm

generic.py's per-father emulation loop (detect dispatcher -> for each father -> emulate state -> redirect goto) IS detect -> snapshot -> plan -> execute with the phases tangled. Untangling it produces N RedirectGoto modifications in a PlanFragment, same as hodur's direct_linearization strategy.

#### Decision 3: recon/flow Stays As-Is

recon/flow is the general CFF analysis framework. It doesn't need reorganization. Consumer count (65% hodur-only) is misleading — hodur is the only CFF attack implemented. The algorithms (state machine analysis, terminal families, reconstruction discovery, DAG construction) are CFF-general by design.

Future strategy packages consume `recon/flow` through its existing contracts where possible, and extend it only when the new behavior is genuinely shared. They bring their own:
- `TransitionBuilderStrategy` implementations (e.g., JumpTableWalkerStrategy)
- `ReconCollector` implementations for their observations
- Strategy implementations against the engine's `UnflatteningStrategy` protocol

#### Decision 4: Dispatcher Analysis Stays in recon/flow

BST comparison-tree dispatchers are common across multiple obfuscators (not OLLVM-exclusive). `bst_analysis.py` is consumed by recon collectors AND hodur. Switch-table dispatcher analysis now also lives in `recon/flow` via `switch_table_analysis.py` and `dispatcher_handler_map.py`. These are all flavors of shared dispatcher analysis, alongside future ones (jump-table, indirect, hybrid).

If a third dispatcher type appears and the pattern needs formalization, we can revisit. YAGNI for now.

#### Decision 5: Don't Pre-Optimize Package Placement

Files that are CFF-general but currently only consumed by hodur stay in recon/flow. Promote to shared infrastructure only when a second consumer actually appears. The principle: consumer count determines urgency, not algorithm generality.

### Extension Model (North Star)

```
recon/
  phase.py            ReconCollector protocol
  flow/
    transition_builder.py   TransitionBuilderStrategy protocol
    ...37 CFF analysis modules (unchanged)

flattening/
  engine/             UnflatteningStrategy protocol + planner + executor
  profiles/           FUTURE: profile/config objects selecting detectors + strategies
  state_machine/      FUTURE: generic state-machine unflattening profile
  hodur/              Compatibility package/entrypoint for the historical name
  tigress_v2/         FUTURE: same shape, consumes shared recon/flow + cfg
  generic.py          LEGACY: gradually adapts to engine (P3)
```

A new contributor:
1. Creates `flattening/their_attack/`
2. Implements `ReconCollector` for their observations
3. Implements `TransitionBuilderStrategy` for their transition discovery
4. Reuses `recon/flow` and `cfg` when the needed abstractions already exist
5. Keeps family-local heuristics inside their package until a second consumer appears
6. Writes strategies against `UnflatteningStrategy` protocol
7. Extends `recon`/`cfg` only when the new behavior is genuinely shared

The state-machine unflattener should follow the same model. The repo may keep
compatibility names such as `hodur/` or `unflattener_hodur.py` while callers are
migrated, but those entrypoints should select a generic state-machine
unflattening profile rather than serving as the architectural home for strategy
algorithms.

---

## Current Status: 2026-05-14

The architecture has moved beyond the original March P0/P1 plan.

The active naming convention is:

- **state-machine unflattener** for the generic family/profile being extracted;
- **Hodur** only for the historical package name, compatibility entrypoint, or
  when referring to commits/files that still carry that name.

Current tree audit against the revised execution order:

- **P0/P1 historical engine extraction:** effectively complete. The engine
  exports family/runtime/planner/provenance/strategy surfaces from
  `flattening/engine`, with `CFFStrategyFamily` in `engine/family.py` and
  shared runtime helpers in `engine/runtime.py`.
- **E0 baseline gate:** baseline artifacts exist under
  `_gitless/baselines/sub7ffd-structure-recovery-pass-2026-05-13/`. Run the
  focused sub7FFD dump/oracle gate for behavior-affecting slices; pure
  extraction slices may use focused unit/import checks plus an explicit note.
- **E1 compatibility imports:** complete for production. Remaining imports from
  `flattening.hodur.strategy/snapshot/planner/executor/provenance/metrics` are
  tests/compatibility checks or family-local strategy surfaces.
- **E1.5 state-machine profile:** partial. `HodurUnflatteningProfile` owns
  strategy order/env filters, and `HodurUnflattener` delegates
  planning/execution to the shared runtime. Remaining gap:
  `hodur/family.py` still owns more artifact/fact/cleanup glue than the target
  state-machine profile shape wants.
- **E2 HCC extraction:** materially advanced beyond the original plan. The
  materialization-boundary work is merged: `CapturedBlockBody` lives in
  `cfg/materialization_payload.py`, `MaterializationBackend` lives in
  `cfg/materialization_backend.py`, and `InsertBlock.captured_body` exists in
  `cfg/graph_modification.py`. Remaining live-analysis leakage is tracked in
  `docs/hodur/live_analysis_strategy_boundary.md`.
- **E3/P2 non-state-machine adoption:** partial and now explicitly a
  strangler migration. FakeJump, SingleIteration, BadWhileLoop, and
  EmulatedDispatcher engine paths exist. The cleanup-family path uses legacy
  cleanup rules as the oracle/source of cases, but newly supported shapes must
  move through neutral evidence, `cfg` graph modifications, engine planning,
  and Hex-Rays backend mutation. BadWhileLoop duplicate cleanup now has a
  neutral evidence bridge; copied side-effect replay and riskier conditional
  shapes remain follow-ups.
- **E4 legacy retirement:** not ready. Legacy paths are intentionally kept, and
  migration tests lock current behavior without claiming full parity.
- **E5 extension contract:** open. There is no `engine/EXTENSION_GUIDE.md` yet;
  `docs/recon/linearized_state_dag.md` is useful background but not a new-family
  extension guide.

Already present on this branch:

- `src/d810/optimizers/microcode/flow/flattening/engine/` contains the
  shared protocol, snapshot, planner, executor, provenance, metrics, family,
  and runtime surfaces.
- `HodurStrategyFamily` implements `CFFStrategyFamily`, and
  `HodurUnflattener` calls `plan_family_pipeline()` /
  `execute_family_pipeline()`.
- `EmulatedDispatcherStrategyFamily` is a second family-shaped consumer of
  the engine surface.
- `FakeJump`, `SingleIteration`, and the safe subset of `BadWhileLoop` already
  have engine-native strategy implementations under `flattening/strategies/`.
  Hodur no longer attaches the migrated cleanup families implicitly
  (`e265dd39`), so their parity is now evaluated as standalone engine
  adoption work rather than as hidden Hodur post-processing.
- `d810.optimizers.microcode.flow.flattening.cleanup_evidence` is the first
  neutral-evidence bridge for legacy cleanup migration. It maps the safe
  `BadWhileLoopDuplicateRedirect` shape into a backend-neutral
  `DispatcherCleanupCandidate` / `CleanupExitShape` /
  `CleanupRewriteIntent`, then lowers it to `DuplicateAndRedirect` through the
  shared cfg/engine/Hex-Rays mutation pipeline (`b0baaf50e`).
- `FixPredecessorOfConditionalJumpBlock` is a parallel E3 cleanup-migration
  lane. The committed slices add a read-only classifier/corpus inventory and
  backend-neutral `CloneConditionalAsGoto` planning; the two-way branch-arm
  extension is being handled as a narrow, regression-gated follow-up. Legacy
  FixPredecessor remains the oracle/source of cases until parity is proven.
- Production imports of generic engine objects have been paid down from Hodur
  compatibility shims to canonical `flattening.engine.*` imports
  (`4408d059`). Compatibility modules still exist for tests, backcompat, and
  any external/runtime consumers that have not been audited.
- The sub7FFD structure-recovery baseline on `structure-recovery-pass` is the
  regression gate for this line of work. Engine extraction must not regress its
  dump, oracle, AFTER stats, frontier diagnostics, or gate audit.
- The post-merge de-specialization/adoption slices landed:
  - `d810.recon.flow.dag_region_detection.detect_linear_transition_regions()`
    now owns the pure semantic-DAG region walk (`d322b957`).
  - `d810.cfg.semantic_region_entry` now owns semantic region entry
    candidate resolution (`3a5ceb53`, follow-up note `cc49dbab`).
  - `d810.cfg.semantic_region_admission` now owns backend-neutral raw
    semantic-region admission/classification predicates (`babe1529`).
  - `d810.cfg.semantic_region_materialization` now owns backend-neutral
    instruction-capture/materialization decisions (`37678021`).
  - `d810.recon.flow.terminal_byte_evidence` now owns read-only terminal
    byte source-EA evidence extraction (`132b2146`).
  - `d810.optimizers.microcode.flow.flattening.engine.fragment_arbitration`
    now owns shared DAG-authoritative fragment arbitration (`54f46a14`).
  - `d810.cfg.flow.sese_hammock` is now the shared exact conditional shape
    classifier used by HCC (`704d458f`).
  - `d810.cfg.semantic_conditional_lowering` now owns exact conditional site
    analysis; the Hodur exact-conditional strategy delegates to that generic
    cfg analyzer (`67d65cdb`), and the pure analyzer tests now live under cfg
    (`ce50f99c`).
  - `d810.cfg.residual_target_resolution` now owns residual
    dispatcher/frontier target resolution (`ca01ff46`), with follow-up cleanup
    removing backend parameters from the cfg API (`255fb9f0`).
  - `d810.cfg.state_var_cleanup` now owns shared state-variable cleanup
    planning, and `d810.recon.flow.return_sites` now owns return-site
    derivation (`4fe6b8fe`).
  - Return-site IDs are family-neutral by default, with Hodur passing an
    explicit `site_id_prefix="hodur"` where compatibility needs stable labels
    (`5ac465b2`).
  - `d810.optimizers.microcode.flow.flattening.hodur.profile` now owns Hodur
    strategy ordering/profile defaults instead of
    `hodur/strategies/__init__.py` (`8771f2a4`, import-cycle fix `4336a7ef`).
  - `d810.cfg.semantic_exact_selection` now owns backend-neutral exact-edge
    pair parsing, focus selection, and window selection for exact semantic
    lowering (`83dc8498`).
  - Exact fork scope helpers and straight-line handoff predicates have moved to
    shared cfg surfaces (`f44b4e32`, `41613203`).
  - The Hodur strategy order now lives in the profile object, and the
    compatibility import cycle is fixed (`8771f2a4`, `4336a7ef`).
  - The runtime materialization path now treats expected serials for
    `CreateConditionalRedirect` as advisory, records actual serial drift in the
    deferred modifier remap, and keeps downstream queued targets aligned
    (`14b598a5`).
  - Baselines were refreshed after Hodur cleanup decoupling; the migration
    baselines now lock current Hodur behavior against legacy cleanup output
    without claiming FakeJump/SingleIteration parity inside Hodur
    (`7d5eb1cf`).
  HCC consumes these helpers while keeping family policy, logging, ordering,
  live Hex-Rays microblock walking, and snapshot materialization local.

What remains:

- E1 is complete for production imports and validation stability. Remaining
  Hodur imports in tests are intentional compatibility checks or
  strategy-specific surfaces that do not yet have a generic extraction target.
- Continue extracting reusable HCC algorithms into `recon`, `cfg`, and
  `engine` based on behavior, not on import churn. The materialization payload
  boundary now exists, but HCC still needs cleanup where strategy code mixes
  policy with live topology checks, call-anchor validation, SCCP/reaching-def
  rescue, and mutation/verify mechanics.
- Continue thinning the state-machine profile/entrypoint now that strategy
  ordering moved into `hodur.profile`. `HodurStrategyFamily` can remain as a
  transitional adapter name while behavior is being extracted, but the target
  shape is not "Hodur owns a family"; it is "the compatibility Hodur entrypoint
  selects a generic state-machine unflattening profile."
- Convert the remaining legacy unflattening families to the engine/family
  model where doing so preserves behavior.
- Document the extension contract for new unflattening families after the
  current package boundaries are proven by the state-machine unflattener and
  one non-state-machine family.

This means the plan should not be executed as a file-move/shim project. The
engine package exists. The active work is now adoption, de-specialization, and
regression-gated behavior preservation across all unflattening families.

---

## Architecture Decision Record

| ID | Decision | Rationale |
|-|-|-|
| ADR-1 | One execution paradigm for all unflattening | Two models = two mental models. Simple strategies have trivial plans with zero overhead. |
| ADR-2 | Engine extracted from hodur, not built from scratch | Hodur's infrastructure proved the engine. The canonical engine package now exists; remaining work should adopt it and move reusable algorithms to the right layer. |
| ADR-3 | recon/flow stays as-is | CFF-general algorithms, not hodur-specific. Consumer count misleading. |
| ADR-4 | generic.py adapts incrementally | Old code keeps working while new strategies added alongside. No big-bang rewrite. |
| ADR-5 | Dispatcher analysis stays in recon/flow | BST and switch-table dispatchers are multi-obfuscator analyses, not Hodur-only quirks. |
| ADR-6 | Compatibility re-exports are transitional, not the architecture | Existing Hodur re-exports may remain while old imports are paid down, but new work should import canonical engine/recon/cfg surfaces directly. Do not add new compatibility shims as the endpoint. |
| ADR-7 | Live behavior defines the extraction boundary | The sub7FFD recovery work showed which algorithms are truly shared: DAG/BST/frontier reasoning belongs in recon/cfg, while Hodur owns family detection and strategy ordering. |
| ADR-8 | Shared dispatcher IR belongs in recon/flow before engine extraction | `DispatcherHandlerMap` and switch-table analysis proved new dispatcher forms should first land as shared recon artifacts plus Hodur adapters. |
| ADR-9 | State-machine unflattening is the family; Hodur is the compatibility name | Extraction succeeds when simple transforms, generic/emulated dispatchers, the state-machine unflattener, and future profiles share detect -> snapshot -> plan -> execute without importing through Hodur. The Hodur entrypoint should select generic state-machine strategies; it should not remain the organizing abstraction. |
| ADR-10 | Do not rebuild the Hodur monolith | `unflattener_hodur.py` may own the compatibility entrypoint, profile defaults, strategy order, env gates, and detector thresholds. It should not absorb `hodur/strategies/*`; strategy wrappers should either shrink, move to generic strategy modules, or disappear when empty. |

---

## Revised Execution Order

The old P0/P1 steps below are now historical. They describe work that has
largely happened already and should not be assigned to an implementer as-is.
The current execution order is:

### E0: Preserve the baseline gate

Before each behavior-affecting extraction slice:

- Start from the `structure-recovery-pass` baseline artifacts archived under
  `_gitless/baselines/sub7ffd-structure-recovery-pass-2026-05-13/`.
- Run or compare the focused sub7FFD dump/oracle when the slice can affect
  planning, execution, CFG lowering, or Hex-Rays materialization.
- Require no new `Failed to decompile`, `INTERR`, `verify_failed`,
  `CFG_50xxx`, unresolved frontier rows, oracle regressions, or AFTER stats
  regressions outside an explicitly accepted behavior change.

### E1: Pay down compatibility imports

Goal: production code should depend on canonical engine surfaces directly.

Status:

- Production import paydown landed in `4408d059`. Current production source no
  longer imports generic engine types through `flattening.hodur.strategy`,
  `flattening.hodur.snapshot`, `flattening.hodur.planner`,
  `flattening.hodur.executor`, `flattening.hodur.provenance`, or
  `flattening.hodur.metrics`.
- `HodurStrategyFamily` preserves Hodur executor policy by constructing the
  shared `TransactionalExecutor` with `safeguard_profile="hodur"`.
- Validation cleanup landed:
  - `d276e3d0` stabilizes exact conditional monkeypatch tests.
  - `1cacc58c` codemods 17 test files from Hodur compatibility imports to
    canonical `flattening.engine.*` imports.
  - `f500732e` stabilizes exact-node frontier monkeypatch tests after the
    codemod exposed another dotted-path ordering hazard.
- Compatibility modules should remain until tests and any external runtime
  consumers no longer need them.

- Replace production imports from `flattening.hodur.strategy`,
  `flattening.hodur.snapshot`, `flattening.hodur.planner`,
  `flattening.hodur.executor`, `flattening.hodur.provenance`, and
  `flattening.hodur.metrics` with `flattening.engine.*` imports when the type
  is engine-generic.
- Keep Hodur-local imports only when the imported object is genuinely
  family-specific.
- Do not remove compatibility modules until all production consumers are gone
  and tests confirm no external runtime path still needs them.

### E1.5: Reframe Hodur as the state-machine compatibility entrypoint

Goal: the state-machine unflattener stops being architecturally identified with
the Hodur package. Hodur becomes a compatibility/profile entrypoint that
selects generic engine, recon, cfg, and backend materialization pieces.

Target shape:

- `unflattener_hodur.py` / `hodur/unflattener.py` owns the plugin-facing
  compatibility entrypoint, historical profile defaults, detector thresholds,
  strategy order, env gates, and legacy rule registration.
- A generic state-machine unflattening family/profile owns the reusable detect
  -> snapshot -> plan -> execute lifecycle.
- `hodur/strategies/*` remain small strategy adapters only while they carry
  Hodur-specific policy, logging, ordering hooks, or live Hex-Rays adaptation.
  They should not be merged into `unflattener_hodur.py`.
- When a strategy adapter becomes backend-neutral, move it to shared
  `flattening/strategies`, `cfg`, `recon`, or `engine`. When it becomes empty,
  delete it.

Implementation sequence:

1. ✅ Introduce a profile/config object carrying state-machine strategy classes
   and current feature gates (`8771f2a4`). Follow-up: generalize the profile
   type when a second non-state-machine adopter needs the same shape.
2. Change `HodurStrategyFamily` from "the owner of Hodur strategies" into an
   adapter over the state-machine profile. Keep the class name temporarily if a
   rename would create too much churn. The next slice should inventory what
   remains in `hodur/family.py` beyond detection/snapshot construction and
   profile adaptation, then move any generic lifecycle behavior into
   `flattening.engine`.
3. ✅ Move the authoritative Hodur strategy list/order out of
   `hodur/strategies/__init__.py` and into the compatibility profile/entrypoint
   (`8771f2a4`, `4336a7ef`).
4. Keep each strategy implementation in its own module. Do not collapse the
   modules into the entrypoint.
5. Once the generic profile is exercised by the state-machine unflattener and
   at least one non-state-machine path, rename the transitional Hodur family
   objects to the generic profile terminology.

Current focus:

- `unflattener_hodur.py` / `hodur/unflattener.py` may remain the plugin-facing
  compatibility entrypoint while the IDA maturity hooks and snapshot timing are
  still tied to the historical package.
- `hodur/profile.py` is the current home for state-machine defaults, feature
  gates, and strategy ordering. A later rename can move the generic shape to a
  neutral profile package after a second adopter proves it.
- `hodur/family.py` should keep detector construction and snapshot adaptation,
  but should not grow new generic planning/execution behavior.
- `hodur/strategies/*` should remain separate modules. Do not merge them into
  the entrypoint; either shrink them to adapters, move generic algorithms out,
  or delete them when empty.

Validation:

- Focused family/profile tests should prove strategy ordering and env gates
  remain stable.
- sub7FFD dump/oracle/AFTER diffs are required if the profile refactor changes
  strategy ordering, gate defaults, or executor configuration.
- Import contracts must continue to prevent `cfg`/`recon` from importing
  Hodur-specific runtime code.

### E2: Extract reusable HCC algorithms by responsibility

Goal: Hodur's HCC remains a strategy, but generic reasoning moves to the
package that owns it.

Completed:

- `detect_linear_transition_regions()` moved to `d810.recon.flow`
  (`d322b957`).
- `EntryEligibility`, `SemanticEntryCandidate`, and
  `resolve_semantic_entry_candidate()` moved to
  `d810.cfg.semantic_region_entry` (`3a5ceb53`, follow-up `cc49dbab`).
- `RawRegionInfo`, source-coverage classification, and YES_HANDLERS
  fusion/admission predicates moved to
  `d810.cfg.semantic_region_admission` (`babe1529`).
- Backend-neutral region instruction-capture/materialization decisions moved
  to `d810.cfg.semantic_region_materialization` (`37678021`).
- Terminal-tail byte source-EA evidence extraction moved to
  `d810.recon.flow.terminal_byte_evidence` (`132b2146`).
- DAG-authoritative fragment arbitration moved to
  `d810.optimizers.microcode.flow.flattening.engine.fragment_arbitration`
  (`54f46a14`).
- Exact conditional shape classification now reuses
  `d810.cfg.flow.sese_hammock` instead of a Hodur-local duplicate
  (`704d458f`).
- Exact conditional site analysis moved to
  `d810.cfg.semantic_conditional_lowering` (`67d65cdb`), with the pure analyzer
  tests migrated to cfg (`ce50f99c`).
- Exact semantic edge parsing/focus/window selection moved to
  `d810.cfg.semantic_exact_selection` (`83dc8498`).
- Exact fork scope helpers and straight-line handoff predicates moved to cfg
  (`f44b4e32`, `41613203`).
- Residual dispatcher/frontier target resolution, dispatcher trampoline skip
  decisions, state-variable cleanup planning, return-site derivation, recon
  artifact helpers, and semantic reference helpers have all moved out of Hodur
  (`ca01ff46`, `255fb9f0`, `b373123d`, `4fe6b8fe`, `5ac465b2`,
  `8bd42176`, `f634c8da`).
- Materialization-boundary payload plumbing is now present: cfg owns
  `CapturedBlockBody`/`MaterializationBackend` abstractions, and
  `InsertBlock.captured_body` can carry opaque backend-captured payloads.

Next candidates, in order:

1. Finish the remaining live-analysis boundary inventory:
   - `docs/hodur/live_analysis_strategy_boundary.md` now records the completed
     profile/live-analysis/use-def/return-cleanup slices, but it still needs to
     become a status document for the remaining leaks;
   - current known hotspots include DSVE evidence, HCC live topology/call-anchor
     validation, body-capture policy boundaries, SCCP/reaching-def rescue, and
     mutation/verify mechanics.
2. Remaining semantic exact/fork/alias lowering analysis:
   - most shared predicates are already extracted; inventory the remaining
     strategy-local logic in `semantic_exact_node.py`,
     `exact_conditional_alias.py`, `exact_conditional_fork.py`, and
     `exact_node_frontier_bypass.py`;
   - move only backend-neutral proof/classification helpers. Keep live
     microblock walking, strategy gates, logging, and fragment emission local.
3. Diagnostics/tracing boundary:
   - `byte_cascade_coverage_tracer.py` remains Hodur-local because its labels
     are HCC-specific, but reusable report models should move to
     `d810.diagnostics` if a second family consumes them;
   - keep runtime capture through observability/core paths, not direct
     diagnostics imports in runtime code.

Recommended next implementer slices:

1. **State-machine profile adapter cleanup.**
   - Inventory `hodur/family.py` after profile extraction and move any generic
     lifecycle code to `flattening.engine`.
   - Keep detector construction, snapshot adaptation, feature gates, and
     profile defaults in Hodur.
   - Validation: profile/family ordering tests and sub7FFD gate only if
     ordering or executor configuration changes.
2. **Remaining live-analysis backend cleanup.**
   - Start with DSVE if Noether has not already finished it: introduce a real
     evidence backend rather than a shallow wrapper, and keep NOP/rewrite
     mechanics behind Hex-Rays mutation.
   - Continue with HCC live topology/materialization policy leaks only after the
     DSVE boundary is clear.
   - Validation: focused DSVE/HCC tests, import contracts, and sub7FFD gate for
     behavior-affecting slices.
3. **E3/P2 non-state-machine adoption slice.**
   - Use FakeJump/SingleIteration/BadWhile migration baselines to select one
     standalone parity improvement.
   - Prefer a BadWhile follow-up that can be expressed with existing
     `GraphModification` primitives or the materialization payload boundary.
   - Do not reattach BadWhile metadata to Hodur.

Parallelizable read-only work:

- **Profile/family boundary inventory.** Identify the next generic lifecycle
  behavior still in `hodur/family.py` and the exact files/classes to change.
- **Materialization-boundary comparison.** Compare this branch to
  `.worktrees/hodur-materialization-boundary` and recommend what to port,
  rewrite, or avoid.
- **Non-state-machine adoption survey.** Inspect P2/P3 families and recommend one
  behavior-preserving adopter slice with tests.

These three investigations are independent of the E1 test fix and can run in
parallel. Only one should move from read-only inventory to code changes at a
time so baseline attribution stays clear.

Do not extract:

- live `mblock_t`/`minsn_t` walking and microcode copy mechanics into cfg or
  recon; these belong behind a backend adapter such as the materialization
  boundary prototype;
- Hodur strategy ordering, env gates, logging labels, and family-local
  thresholds;
- dormant `linearized_flow_graph.py` work unless it is deliberately revived
  into the current HCC path.

### E3: Normalize non-state-machine families onto the engine

Goal: the shared engine is proven by more than the state-machine unflattener.

- Keep the existing `FakeJump`, `SingleIteration`, `BadWhileLoop`, and
  `EmulatedDispatcherStrategyFamily` paths working.
- Identify one legacy rule whose old path still performs meaningful lowering
  and add or complete an engine-family equivalent.
- Prefer examples that use different detection evidence from Hodur so the
  family boundary is exercised rather than merely copied.

Cleanup-family migration rule:

- Use legacy cleanup rules as an oracle/source of cases, not as the endpoint.
- Newly supported cleanup shapes must be represented as neutral evidence and
  backend-neutral rewrite intent, then lowered through `cfg.GraphModification`,
  `PatchPlan`, the engine executor, and Hex-Rays mutation backends.
- Do not add new direct Hex-Rays mutation, block cloning, NOP, copy, split,
  verify, or rewrite mechanics inside strategy code for migrated shapes.
- Legacy live rules may remain for unsupported buckets and parity comparison.
  Retire each bucket only after a focused parity gate proves the new path.
- BadWhileLoop and FixPredecessor are the active examples of this strangler
  pattern: legacy classifies the case, `cleanup_evidence`/`cfg` records the
  neutral proof, and the engine/Hex-Rays backend performs the mutation.

After the state-machine unflattener is reduced to profile/policy plus backend
adapters, the next architecture phase is to prove the engine is not secretly
state-machine-shaped:

1. Freeze the shared engine contract:
   - `recon`: evidence, DAG/BST/transition facts, return sites;
   - `cfg`: backend-neutral lowering decisions and graph plans;
   - `engine`: family runtime, planning, arbitration, provenance, executor;
   - `hexrays`: materialization backend, mutation, verification.
2. Pick one non-state-machine adopter. Prefer the legacy/simple path with the
   best tests and real samples, likely BadWhileLoop/simple CFF cleanup, because
   it already touches graph planning and has known parity gaps.
3. Convert that adopter into a normal family:
   `detect evidence -> build snapshot -> plan generic cfg modifications ->
   execute through engine`.
4. Move shared legacy algorithms into `recon`/`cfg` only as they are needed:
   dispatcher compare-chain recognition, successor/target resolution, copied
   side-effect replay decisions, conditional redirect planning,
   duplicate/split/trampoline safety, opaque guard classification, and
   return/call barrier handling.
5. Reuse the same backend adapter boundary. New legacy migrations should not
   introduce direct Hex-Rays mutation, block cloning, NOP, copy, split, verify,
   or rewrite mechanics inside strategy code.
6. Unify config/profile loading so `hodur_flag2.json`, generic CFF configs, and
   simple-transform configs eventually describe families/profiles against the
   same runtime:
   `family`, `profile`, enabled strategies, gates, and profile settings.
7. Replace compatibility shims with real migrations. Temporary adapters are
   acceptable inside a branch, but the endpoint is migrated or deleted legacy
   paths, not a permanent compatibility layer.
8. Promote `d810cli` as the common validation front door for baselines, AFTER
   stats, oracle diffs, frontier diagnostics, and trace explainers across every
   family.
9. Delete legacy paths only after parity. Each removal needs a focused parity
   test or an explicit abstention contract.

Acceptance for this phase: a second unflattening family can be added or
migrated without copying state-machine internals and without adding new direct
Hex-Rays mutation logic.

### E4: Retire legacy paths only after parity

Goal: old unflatteners are not ripped out before the engine path proves equal
or better behavior.

- For each migrated transform/family, keep old entry points until there is a
  focused parity test or an explicit abstention contract.
- Deprecate old entry points with documentation once the engine path is the
  default.
- Remove old paths only when tests and field samples no longer depend on them.

### E5: Document the extension contract

Goal: a new unflattening family should be implementable without reading Hodur
internals.

The extension guide should explain:

- how to publish observations through recon collectors;
- how to build a profile/family detection result and snapshot;
- how to emit `PlanFragment` instances;
- when to add a new `recon` helper versus a family-local heuristic;
- when to add a new `cfg.GraphModification` or patch primitive;
- how to validate with cff_debug, diag/oracle artifacts, and family-specific
  regression gates.

---

## Historical Execution Order Correction

This section is retained for context. It describes the state of the branch
before the shared engine package and family runtime landed. Do not use it as
the active task ordering; use "Revised Execution Order" above.

This document describes the intended destination, but the live branch is not
ready to execute P0 first.

The current unstable boundary is:
- proof-driven candidate choice in `d810.cfg.lowering_selector`
- the still-heavy direct/terminal strategy cluster in:
  - `src/d810/optimizers/microcode/flow/flattening/hodur/strategies/direct_linearization.py`
  - `src/d810/optimizers/microcode/flow/flattening/hodur/strategies/private_terminal_suffix.py`
  - `src/d810/optimizers/microcode/flow/flattening/hodur/strategies/direct_terminal_lowering.py`

Near-term execution order on the live branch should therefore be:
1. Stabilize proof-driven lowering selection in `d810.cfg.lowering_selector`.
2. Continue live-consumer generalization in `d810.recon` and `d810.cfg` for dispatcher families.
   - completed example: switch-table fallback (`dispatcher_handler_map`, `switch_table_analysis`, Hodur synthetic BST adapter)
3. Extract the direct/terminal strategy cluster into `d810.recon` and `d810.cfg`.
4. Re-audit which remaining Hodur planner/executor types are actually generic.
5. Only then start `flattening/engine` extraction.

Treat the phases below as a north-star rollout, not an immediate
implementation order.

---

## File Structure

Historical note: the engine package described below already exists on the
current branch. The remaining work is not to recreate this tree, but to migrate
call sites and reusable algorithms to the canonical surfaces.

### New Files

```
src/d810/optimizers/microcode/flow/flattening/engine/
  __init__.py                 # Package init, re-exports key types
  strategy.py                 # FROM hodur/strategy.py (342 lines)
  planner.py                  # FROM hodur/planner.py (927 lines)
  executor.py                 # FROM hodur/executor.py (1013 lines)
  provenance.py               # FROM hodur/provenance.py (388 lines)
  snapshot.py                 # FROM hodur/snapshot.py (91 lines)
  metrics.py                  # FROM hodur/metrics.py (49 lines)

tests/unit/optimizers/microcode/flow/flattening/engine/
  __init__.py
  test_strategy_protocol.py   # Unit tests for strategy types
  test_planner.py             # Unit tests for planner logic
  test_snapshot.py            # Unit tests for snapshot construction
```

### Modified Files (P0 only)

```
# Become thin re-export shims:
src/d810/optimizers/microcode/flow/flattening/hodur/strategy.py
src/d810/optimizers/microcode/flow/flattening/hodur/planner.py
src/d810/optimizers/microcode/flow/flattening/hodur/executor.py
src/d810/optimizers/microcode/flow/flattening/hodur/provenance.py
src/d810/optimizers/microcode/flow/flattening/hodur/snapshot.py
src/d810/optimizers/microcode/flow/flattening/hodur/metrics.py

# No changes needed to these (they import from hodur/ which re-exports):
# All 15 strategy files, unflattener.py, analysis.py, etc.
```

---

## P0: Engine Extraction

Historical note: P0 is effectively complete on the current branch. Do not
execute the shim/file-move steps below as new work. Use E1/E2 from the revised
execution order instead.

**Risk:** Medium-high. This is not a pure file move on the current branch.
`snapshot.py`, `planner.py`, and `executor.py` still encode Hodur-specific
types, planner inputs, safeguards, and diagnostics. Promote them only after
the preconditions in "Execution Order Correction" are complete.

**Verification:** All existing unit tests pass. All existing system tests pass. No import errors.

### Task 0.1: Create engine package skeleton

**Files:**
- Create: `src/d810/optimizers/microcode/flow/flattening/engine/__init__.py`
- Create: `tests/unit/optimizers/microcode/flow/flattening/engine/__init__.py`

- [ ] **Step 1: Create engine package directory**

```bash
mkdir -p src/d810/optimizers/microcode/flow/flattening/engine
mkdir -p tests/unit/optimizers/microcode/flow/flattening/engine
```

- [ ] **Step 2: Create engine/__init__.py with public API**

```python
"""Shared unflattening engine: strategy protocol, planner, executor.

This package provides the execution infrastructure for all unflattening
strategies, from simple single-edit transforms to complex multi-strategy
pipelines with conflict resolution and transactional execution.

The canonical pipeline: detect -> snapshot -> plan -> execute.
"""
```

- [ ] **Step 3: Create test package init**

```python
# tests/unit/optimizers/microcode/flow/flattening/engine/__init__.py
```

- [ ] **Step 4: Verify package imports**

Run: `PYTHONPATH=src python -c "import d810.optimizers.microcode.flow.flattening.engine"`
Expected: No error

- [ ] **Step 5: Commit**

```bash
git add src/d810/optimizers/microcode/flow/flattening/engine/__init__.py
git add tests/unit/optimizers/microcode/flow/flattening/engine/__init__.py
git commit -m "feat(engine): create unflattening engine package skeleton"
```

### Task 0.2: Move strategy.py to engine

**Files:**
- Create: `src/d810/optimizers/microcode/flow/flattening/engine/strategy.py`
- Modify: `src/d810/optimizers/microcode/flow/flattening/hodur/strategy.py`

- [ ] **Step 1: Copy hodur/strategy.py to engine/strategy.py**

```bash
cp src/d810/optimizers/microcode/flow/flattening/hodur/strategy.py \
   src/d810/optimizers/microcode/flow/flattening/engine/strategy.py
```

- [ ] **Step 2: Update engine/strategy.py imports**

The file has one internal import (TYPE_CHECKING only):
```python
# OLD (line 16-18):
from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
    AnalysisSnapshot,
)

# NEW:
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
)
```

All other imports are from `d810.cfg` or stdlib — no changes needed.

- [ ] **Step 3: Replace hodur/strategy.py with re-export shim**

Replace the entire contents of `hodur/strategy.py` with:

```python
"""Backward-compatibility shim — canonical location is engine.strategy.

All types re-exported so existing ``from hodur.strategy import ...``
statements continue to work without modification.
"""
from d810.optimizers.microcode.flow.flattening.engine.strategy import (  # noqa: F401
    FAMILY_CLEANUP,
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
    StageResult,
    UnflatteningStrategy,
    VerificationGate,
)
```

- [ ] **Step 4: Run existing tests to verify re-export works**

Run: `PYTHONPATH=src pytest tests/unit/optimizers/microcode/flow/flattening/hodur/test_strategy_no_mba.py -v`
Expected: All tests PASS (they import from hodur.strategy, which now re-exports from engine.strategy)

- [ ] **Step 5: Write engine strategy test**

Create `tests/unit/optimizers/microcode/flow/flattening/engine/test_strategy_protocol.py`:

```python
"""Verify engine.strategy types are importable and functional."""
from __future__ import annotations

from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
    StageResult,
    UnflatteningStrategy,
    VerificationGate,
)


def test_ownership_scope_disjoint():
    a = OwnershipScope(blocks=frozenset({1, 2}), edges=frozenset(), transitions=frozenset())
    b = OwnershipScope(blocks=frozenset({3, 4}), edges=frozenset(), transitions=frozenset())
    assert a.is_disjoint(b)


def test_ownership_scope_overlap():
    a = OwnershipScope(blocks=frozenset({1, 2}), edges=frozenset(), transitions=frozenset())
    b = OwnershipScope(blocks=frozenset({2, 3}), edges=frozenset(), transitions=frozenset())
    assert not a.is_disjoint(b)
    assert a.overlap_blocks(b) == frozenset({2})


def test_ownership_scope_union():
    a = OwnershipScope(blocks=frozenset({1}), edges=frozenset(), transitions=frozenset())
    b = OwnershipScope(blocks=frozenset({2}), edges=frozenset(), transitions=frozenset())
    c = a.union(b)
    assert c.blocks == frozenset({1, 2})


def test_family_constants():
    assert FAMILY_DIRECT == "direct"
    assert FAMILY_FALLBACK == "fallback"
    assert FAMILY_CLEANUP == "cleanup"


def test_plan_fragment_construction():
    scope = OwnershipScope(blocks=frozenset({10}), edges=frozenset(), transitions=frozenset())
    benefit = BenefitMetrics(
        handlers_resolved=2,
        transitions_resolved=5,
        blocks_freed=2,
        conflict_density=0.0,
    )
    frag = PlanFragment(
        strategy_name="test_strategy",
        family=FAMILY_DIRECT,
        ownership=scope,
        prerequisites=[],
        expected_benefit=benefit,
        risk_score=0.0,
        modifications=[],
    )
    assert frag.strategy_name == "test_strategy"
    assert frag.family == FAMILY_DIRECT
    assert frag.expected_benefit.transitions_resolved == 5
```

- [ ] **Step 6: Run new test**

Run: `PYTHONPATH=src pytest tests/unit/optimizers/microcode/flow/flattening/engine/test_strategy_protocol.py -v`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add src/d810/optimizers/microcode/flow/flattening/engine/strategy.py
git add src/d810/optimizers/microcode/flow/flattening/hodur/strategy.py
git add tests/unit/optimizers/microcode/flow/flattening/engine/test_strategy_protocol.py
git commit -m "feat(engine): move strategy protocol to engine, add re-export shim in hodur"
```

### Task 0.3: Move snapshot.py to engine

**Files:**
- Create: `src/d810/optimizers/microcode/flow/flattening/engine/snapshot.py`
- Modify: `src/d810/optimizers/microcode/flow/flattening/hodur/snapshot.py`

- [ ] **Step 1: Copy hodur/snapshot.py to engine/snapshot.py**

```bash
cp src/d810/optimizers/microcode/flow/flattening/hodur/snapshot.py \
   src/d810/optimizers/microcode/flow/flattening/engine/snapshot.py
```

No internal import changes needed — snapshot.py has no hodur-internal imports (only TYPE_CHECKING references).

- [ ] **Step 2: Replace hodur/snapshot.py with re-export shim**

```python
"""Backward-compatibility shim — canonical location is engine.snapshot."""
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (  # noqa: F401
    AnalysisSnapshot,
    ReachabilityInfo,
)
```

- [ ] **Step 3: Run tests**

Run: `PYTHONPATH=src pytest tests/unit/optimizers/microcode/flow/flattening/ -v --tb=short`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add src/d810/optimizers/microcode/flow/flattening/engine/snapshot.py
git add src/d810/optimizers/microcode/flow/flattening/hodur/snapshot.py
git commit -m "feat(engine): move snapshot to engine, add re-export shim"
```

### Task 0.4: Move provenance.py to engine

**Files:**
- Create: `src/d810/optimizers/microcode/flow/flattening/engine/provenance.py`
- Modify: `src/d810/optimizers/microcode/flow/flattening/hodur/provenance.py`

- [ ] **Step 1: Copy hodur/provenance.py to engine/provenance.py**

```bash
cp src/d810/optimizers/microcode/flow/flattening/hodur/provenance.py \
   src/d810/optimizers/microcode/flow/flattening/engine/provenance.py
```

provenance.py imports only `d810.core.logging` — no internal import changes needed.

- [ ] **Step 2: Replace hodur/provenance.py with re-export shim**

```python
"""Backward-compatibility shim — canonical location is engine.provenance."""
from d810.optimizers.microcode.flow.flattening.engine.provenance import (  # noqa: F401
    DecisionPhase,
    DecisionReasonCode,
    DecisionRecord,
    GateAccounting,
    GateDecision,
    GateVerdict,
    PipelineProvenance,
    PlannerInputs,
)
```

- [ ] **Step 3: Update recon/outcome.py TYPE_CHECKING import**

In `src/d810/recon/outcome.py` (line ~19), update the TYPE_CHECKING import:

```python
# OLD:
from d810.optimizers.microcode.flow.flattening.hodur.provenance import (

# NEW:
from d810.optimizers.microcode.flow.flattening.engine.provenance import (
```

This is the only non-hodur file that imports provenance (under TYPE_CHECKING).

- [ ] **Step 4: Run tests**

Run: `PYTHONPATH=src pytest tests/unit/ -v --tb=short -x -q`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/d810/optimizers/microcode/flow/flattening/engine/provenance.py
git add src/d810/optimizers/microcode/flow/flattening/hodur/provenance.py
git add src/d810/recon/outcome.py
git commit -m "feat(engine): move provenance to engine, add re-export shim"
```

### Task 0.5: Move metrics.py to engine

**Files:**
- Create: `src/d810/optimizers/microcode/flow/flattening/engine/metrics.py`
- Modify: `src/d810/optimizers/microcode/flow/flattening/hodur/metrics.py`

- [ ] **Step 1: Copy hodur/metrics.py to engine/metrics.py**

```bash
cp src/d810/optimizers/microcode/flow/flattening/hodur/metrics.py \
   src/d810/optimizers/microcode/flow/flattening/engine/metrics.py
```

- [ ] **Step 2: Update engine/metrics.py TYPE_CHECKING import**

```python
# OLD (TYPE_CHECKING):
from d810.optimizers.microcode.flow.flattening.hodur.strategy import StageResult

# NEW:
from d810.optimizers.microcode.flow.flattening.engine.strategy import StageResult
```

- [ ] **Step 3: Replace hodur/metrics.py with re-export shim**

```python
"""Backward-compatibility shim — canonical location is engine.metrics."""
from d810.optimizers.microcode.flow.flattening.engine.metrics import (  # noqa: F401
    handler_coverage,
    structure_quality_score,
)
```

- [ ] **Step 4: Run tests**

Run: `PYTHONPATH=src pytest tests/unit/ -v --tb=short -x -q`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/d810/optimizers/microcode/flow/flattening/engine/metrics.py
git add src/d810/optimizers/microcode/flow/flattening/hodur/metrics.py
git commit -m "feat(engine): move metrics to engine, add re-export shim"
```

### Task 0.6: Move planner.py to engine

**Files:**
- Create: `src/d810/optimizers/microcode/flow/flattening/engine/planner.py`
- Modify: `src/d810/optimizers/microcode/flow/flattening/hodur/planner.py`

This is the largest move (927 lines). The planner imports from strategy and provenance (both now in engine).

- [ ] **Step 1: Copy hodur/planner.py to engine/planner.py**

```bash
cp src/d810/optimizers/microcode/flow/flattening/hodur/planner.py \
   src/d810/optimizers/microcode/flow/flattening/engine/planner.py
```

- [ ] **Step 2: Update engine/planner.py internal imports**

Replace all `d810.optimizers.microcode.flow.flattening.hodur.` references with `d810.optimizers.microcode.flow.flattening.engine.`:

```python
# Line ~39: provenance import
# OLD:
from d810.optimizers.microcode.flow.flattening.hodur.provenance import (
# NEW:
from d810.optimizers.microcode.flow.flattening.engine.provenance import (

# Line ~46: strategy import
# OLD:
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
# NEW:
from d810.optimizers.microcode.flow.flattening.engine.strategy import (

# Line ~56 (TYPE_CHECKING): snapshot import
# OLD:
from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
# NEW:
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
```

- [ ] **Step 3: Replace hodur/planner.py with re-export shim**

```python
"""Backward-compatibility shim — canonical location is engine.planner."""
from d810.optimizers.microcode.flow.flattening.engine.planner import (  # noqa: F401
    PipelinePolicy,
    PlannerHintSignals,
    UnflatteningPlanner,
)
```

- [ ] **Step 4: Run tests**

Run: `PYTHONPATH=src pytest tests/unit/ -v --tb=short -x -q`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/d810/optimizers/microcode/flow/flattening/engine/planner.py
git add src/d810/optimizers/microcode/flow/flattening/hodur/planner.py
git commit -m "feat(engine): move planner to engine, add re-export shim"
```

### Task 0.7: Move executor.py to engine

**Files:**
- Create: `src/d810/optimizers/microcode/flow/flattening/engine/executor.py`
- Modify: `src/d810/optimizers/microcode/flow/flattening/hodur/executor.py`

This is the second largest move (1013 lines). The executor imports from strategy, provenance, and safeguards.

- [ ] **Step 1: Copy hodur/executor.py to engine/executor.py**

```bash
cp src/d810/optimizers/microcode/flow/flattening/hodur/executor.py \
   src/d810/optimizers/microcode/flow/flattening/engine/executor.py
```

- [ ] **Step 2: Update engine/executor.py internal imports**

Replace hodur-internal imports with engine imports:

```python
# Line ~55: provenance import
# OLD:
from d810.optimizers.microcode.flow.flattening.hodur.provenance import (
# NEW:
from d810.optimizers.microcode.flow.flattening.engine.provenance import (

# Line ~60: strategy import
# OLD:
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
# NEW:
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
```

Note: executor.py also imports from `d810.cfg`, `d810.optimizers.microcode.flow.flattening.safeguards`, and `d810.hexrays`. These are external dependencies — no changes needed.

- [ ] **Step 3: Replace hodur/executor.py with re-export shim**

```python
"""Backward-compatibility shim — canonical location is engine.executor."""
from d810.optimizers.microcode.flow.flattening.engine.executor import (  # noqa: F401
    TransactionalExecutor,
)
```

- [ ] **Step 4: Run tests**

Run: `PYTHONPATH=src pytest tests/unit/ -v --tb=short -x -q`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/d810/optimizers/microcode/flow/flattening/engine/executor.py
git add src/d810/optimizers/microcode/flow/flattening/hodur/executor.py
git commit -m "feat(engine): move executor to engine, add re-export shim"
```

### Task 0.8: Update engine/__init__.py public API

**Files:**
- Modify: `src/d810/optimizers/microcode/flow/flattening/engine/__init__.py`

- [ ] **Step 1: Add public API re-exports to engine/__init__.py**

```python
"""Shared unflattening engine: strategy protocol, planner, executor.

This package provides the execution infrastructure for all unflattening
strategies, from simple single-edit transforms to complex multi-strategy
pipelines with conflict resolution and transactional execution.

The canonical pipeline: detect -> snapshot -> plan -> execute.

Extension points:
    - :class:`UnflatteningStrategy` — implement to add a new strategy
    - :class:`AnalysisSnapshot` — immutable context passed to strategies
    - :class:`UnflatteningPlanner` — conflict-resolving pipeline composer
    - :class:`TransactionalExecutor` — gate-enforcing CFG mutator
"""
from d810.optimizers.microcode.flow.flattening.engine.strategy import (  # noqa: F401
    FAMILY_CLEANUP,
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
    StageResult,
    UnflatteningStrategy,
    VerificationGate,
)
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (  # noqa: F401
    AnalysisSnapshot,
    ReachabilityInfo,
)
from d810.optimizers.microcode.flow.flattening.engine.provenance import (  # noqa: F401
    DecisionPhase,
    GateAccounting,
    GateVerdict,
    PipelineProvenance,
    PlannerInputs,
)
from d810.optimizers.microcode.flow.flattening.engine.planner import (  # noqa: F401
    UnflatteningPlanner,
)
from d810.optimizers.microcode.flow.flattening.engine.executor import (  # noqa: F401
    TransactionalExecutor,
)
from d810.optimizers.microcode.flow.flattening.engine.metrics import (  # noqa: F401
    handler_coverage,
    structure_quality_score,
)
```

- [ ] **Step 2: Verify top-level import**

Run: `PYTHONPATH=src python -c "from d810.optimizers.microcode.flow.flattening.engine import UnflatteningStrategy, UnflatteningPlanner, TransactionalExecutor; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Run full unit test suite**

Run: `PYTHONPATH=src pytest tests/unit/ -v --tb=short -q`
Expected: All PASS, same count as baseline

- [ ] **Step 4: Commit**

```bash
git add src/d810/optimizers/microcode/flow/flattening/engine/__init__.py
git commit -m "feat(engine): add public API exports to engine package"
```

### Task 0.9: Verify no regressions

- [ ] **Step 1: Run full unit test suite**

Run: `PYTHONPATH=src:tests pytest tests/unit/ -v --tb=short -q`
Expected: Same pass/fail count as before P0 changes

- [ ] **Step 2: Verify import-linter compliance (if configured)**

Run: `PYTHONPATH=src python -c "import d810.optimizers.microcode.flow.flattening.hodur.unflattener; print('hodur OK')"`
Expected: No import errors

- [ ] **Step 3: Verify engine is independently importable**

Run: `PYTHONPATH=src python -c "from d810.optimizers.microcode.flow.flattening.engine import UnflatteningStrategy, PlanFragment, OwnershipScope, BenefitMetrics; print('engine OK')"`
Expected: `engine OK`

- [ ] **Step 4: Commit (if any fixups needed)**

---

## P1: CFFStrategyFamily Orchestrator

Historical note: `CFFStrategyFamily`, `DetectionResult`,
`plan_family_pipeline()`, and `execute_family_pipeline()` already exist. The
remaining work is broader adoption by all unflattening families.

**Risk:** Medium. New code that codifies the detect -> snapshot -> plan -> execute pipeline as a reusable base class.

**Depends on:** P0 complete.

### Task 1.1: Design CFFStrategyFamily protocol

**Files:**
- Create: `src/d810/optimizers/microcode/flow/flattening/engine/family.py`
- Create: `tests/unit/optimizers/microcode/flow/flattening/engine/test_family.py`

- [ ] **Step 1: Write test for strategy family protocol**

Create `tests/unit/optimizers/microcode/flow/flattening/engine/test_family.py`:

```python
"""Tests for the CFFStrategyFamily orchestrator."""
from __future__ import annotations

from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_DIRECT,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
    UnflatteningStrategy,
)
from d810.optimizers.microcode.flow.flattening.engine.family import (
    CFFStrategyFamily,
    DetectionResult,
)
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
)


class StubDetectionResult(DetectionResult):
    """Minimal detection result for testing."""

    @property
    def detected(self) -> bool:
        return True

    @property
    def description(self) -> str:
        return "stub"


class StubStrategy:
    """Minimal strategy for testing."""

    name = "stub"
    family = FAMILY_DIRECT

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        return True

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            ownership=OwnershipScope(
                blocks=frozenset(), edges=frozenset(), transitions=frozenset()
            ),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=1,
                transitions_resolved=1,
                blocks_freed=0,
                conflict_density=0.0,
            ),
            risk_score=0.0,
            modifications=[],
        )


def test_detection_result_protocol():
    result = StubDetectionResult()
    assert result.detected is True


def test_strategy_family_strategies_property():
    """CFFStrategyFamily subclasses must provide strategies list."""
    # This test validates the protocol shape, not a concrete family.
    assert hasattr(CFFStrategyFamily, "detect")
    assert hasattr(CFFStrategyFamily, "build_snapshot")
    assert hasattr(CFFStrategyFamily, "strategies")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src pytest tests/unit/optimizers/microcode/flow/flattening/engine/test_family.py -v`
Expected: ImportError — family.py doesn't exist

- [ ] **Step 3: Implement CFFStrategyFamily**

Create `src/d810/optimizers/microcode/flow/flattening/engine/family.py`:

```python
"""CFF Strategy Family — reusable orchestrator for detect -> snapshot -> plan -> execute.

A CFFStrategyFamily is a named collection of strategies that share a detector
and analysis snapshot.  Subclasses implement:

1. ``detect(mba)`` — determine if this family applies to the function
2. ``build_snapshot(mba, detection)`` — build the immutable analysis snapshot
3. ``strategies`` — the list of strategies to poll

The orchestration loop (poll strategies, plan, execute) is inherited from
this base class and uses the shared engine planner and executor.

This is the primary extension point for adding new CFF attacks.  A new
contributor creates a subclass, implements the three methods, and registers
their strategies.  They should reuse `recon`/`cfg` boundaries rather than
forking them, and only extend those packages when the new behavior is
genuinely shared.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass

from d810.core.typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )
    from d810.optimizers.microcode.flow.flattening.engine.strategy import (
        PlanFragment,
        UnflatteningStrategy,
    )


@runtime_checkable
class DetectionResult(Protocol):
    """Result of a strategy family's detection phase.

    Subclasses carry family-specific data (dispatcher info, state machine,
    handler map, etc.).  The engine only checks ``detected``.
    """

    @property
    def detected(self) -> bool:
        """Whether the family's target obfuscation pattern was found."""
        ...

    @property
    def description(self) -> str:
        """Human-readable description of what was detected."""
        ...


class CFFStrategyFamily(abc.ABC):
    """Base class for CFF unflattening strategy families.

    Subclasses implement detection, snapshot construction, and provide
    their list of strategies.  The orchestration pipeline is inherited.

    Example subclass::

        class HodurFamily(CFFStrategyFamily):
            name = "hodur"

            def detect(self, mba) -> DetectionResult:
                return self._detector.detect(mba)

            def build_snapshot(self, mba, detection) -> AnalysisSnapshot:
                return AnalysisSnapshot(...)

            @property
            def strategies(self) -> list[UnflatteningStrategy]:
                return ALL_STRATEGIES
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique name for this strategy family."""
        ...

    @abc.abstractmethod
    def detect(self, mba: object) -> DetectionResult:
        """Run family-specific detection on the microcode.

        Args:
            mba: The mba_t object (typed as object to avoid IDA import
                 in the engine package).

        Returns:
            A DetectionResult whose ``detected`` property indicates
            whether this family should proceed.
        """
        ...

    @abc.abstractmethod
    def build_snapshot(
        self, mba: object, detection: DetectionResult
    ) -> AnalysisSnapshot:
        """Construct the immutable analysis snapshot from detection results.

        Args:
            mba: The mba_t object.
            detection: The result from ``detect()``.

        Returns:
            An AnalysisSnapshot that will be passed to all strategies.
        """
        ...

    @property
    @abc.abstractmethod
    def strategies(self) -> list[UnflatteningStrategy]:
        """The strategies this family provides.

        Returns:
            Ordered list of strategies to poll during planning.
        """
        ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src pytest tests/unit/optimizers/microcode/flow/flattening/engine/test_family.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/d810/optimizers/microcode/flow/flattening/engine/family.py
git add tests/unit/optimizers/microcode/flow/flattening/engine/test_family.py
git commit -m "feat(engine): add CFFStrategyFamily base class for detect->snapshot->plan->execute"
```

### Task 1.2: Add CFFStrategyFamily to engine public API

**Files:**
- Modify: `src/d810/optimizers/microcode/flow/flattening/engine/__init__.py`

- [ ] **Step 1: Add family exports to __init__.py**

Add to the imports in engine/__init__.py:

```python
from d810.optimizers.microcode.flow.flattening.engine.family import (  # noqa: F401
    CFFStrategyFamily,
    DetectionResult,
)
```

- [ ] **Step 2: Verify import**

Run: `PYTHONPATH=src python -c "from d810.optimizers.microcode.flow.flattening.engine import CFFStrategyFamily, DetectionResult; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add src/d810/optimizers/microcode/flow/flattening/engine/__init__.py
git commit -m "feat(engine): export CFFStrategyFamily from engine package"
```

---

## P2: Wrap Simple Transforms

Current note: this is partly complete. The next useful work is not "wrap all
simple transforms for its own sake"; it is to make the engine path the default
only when parity or an explicit abstention contract exists.

**Risk:** Low-medium. Each simple transform becomes a strategy with ~20-30 lines of glue. Old code stays working — new strategies are registered alongside.

**Depends on:** P0 complete. P1 recommended but not strictly required.

**Note:** This phase is incremental. Each transform can be wrapped independently. Start with BadWhileLoop (simplest) as proof-of-concept.

**Current branch status:** `FakeJump` and `SingleIteration` are already live
engine strategies, and `BadWhileLoop` now has an engine-native safe subset.
Hodur no longer consumes these cleanup strategies implicitly, so P2 is a
standalone engine-adoption lane. The remaining gap is not that the legacy
transformations are impossible in the modern architecture, but that the richer
`BadWhileLoop` cases are not yet re-expressed through the shared `cfg` /
`recon` / mutation-planning path.

The current migration strategy is a strangler migration:

- Legacy `BadWhileLoop` remains the oracle/source of observed cases.
- The new cleanup-family path is the real implementation target.
- Supported shapes are admitted only after they have neutral evidence and a
  backend-neutral rewrite intent.
- Strategy/family code should plan; mutation should happen through
  `GraphModification`, `PatchPlan`, and the Hex-Rays mutation backend.
- Unsupported buckets remain explicit follow-ups rather than being retrofitted
  with ad hoc live mutation.

Current state of this track:

- `BadWhileLoopGotoRedirect` and `BadWhileLoopGotoConversion` are already safe
  modeled edits.
- `BadWhileLoopDuplicateRedirect` now has a neutral cleanup-evidence bridge and
  lowers through `DuplicateAndRedirect`.
- `BadWhileLoopConditionalDuplicate` and `BadWhileLoopConditionalRedirect`
  remain modeled but deferred until structural proof and parity gates justify
  enabling them.
- `copied_side_effects` / `duplicate_group_copied_side_effects` remain a
  materialization-boundary follow-up and should use captured payloads rather
  than live `minsn_t` objects in strategy metadata.
- `FixPredecessorOfConditionalJumpBlock` follows the same pattern: legacy is
  the oracle, new supported shapes go through `cfg` planning and Hex-Rays
  backend lowering, and each widened shape needs Hodur/sub7FFD no-regression
  when it affects shared fixtures.

### Task 2.1: BadWhileLoop as a strategy

**Files:**
- Create: `src/d810/optimizers/microcode/flow/flattening/strategies/bad_while_loop_strategy.py`
- Create: `tests/unit/optimizers/microcode/flow/flattening/strategies/__init__.py`
- Create: `tests/unit/optimizers/microcode/flow/flattening/strategies/test_bad_while_loop_strategy.py`

- [ ] **Step 1: Read BadWhileLoop to understand detection logic**

Read `src/d810/optimizers/microcode/flow/flattening/unflattener_badwhile_loop.py` to understand:
- What pattern does it detect?
- What modifications does it emit?
- What are the preconditions?

- [ ] **Step 2: Write test for strategy wrapper**

Create `tests/unit/optimizers/microcode/flow/flattening/strategies/test_bad_while_loop_strategy.py`:

```python
"""Test BadWhileLoop as an engine strategy."""
from __future__ import annotations

from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
)


def test_bad_while_loop_strategy_has_correct_family():
    """BadWhileLoop is a cleanup strategy."""
    from d810.optimizers.microcode.flow.flattening.strategies.bad_while_loop_strategy import (
        BadWhileLoopStrategy,
    )
    strategy = BadWhileLoopStrategy()
    assert strategy.family == FAMILY_CLEANUP
    assert strategy.name == "bad_while_loop"
```

- [ ] **Step 3: Implement the strategy wrapper**

Create `src/d810/optimizers/microcode/flow/flattening/strategies/bad_while_loop_strategy.py`.

The exact implementation depends on what BadWhileLoop detects — read the source first (Step 1) and wrap the detection + modification logic into the `is_applicable()` and `plan()` protocol methods.

The pattern:
```python
"""BadWhileLoop as an engine strategy.

Wraps the existing bad-while-loop detection logic to emit PlanFragment
objects through the engine protocol.
"""
from __future__ import annotations

from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.core.typing import TYPE_CHECKING

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )


class BadWhileLoopStrategy:
    """Remove bad while(1) loop patterns.

    This is a cleanup strategy that detects while(1) loops introduced by
    incomplete unflattening and removes the spurious back-edge.
    """

    name = "bad_while_loop"
    family = FAMILY_CLEANUP

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        # Detect bad while patterns in the snapshot's FlowGraph
        # Reuse detection logic from unflattener_badwhile_loop.py
        ...

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        # Emit ConvertToGoto modifications for detected patterns
        ...
```

**Important:** The implementer MUST read `unflattener_badwhile_loop.py` to extract the detection predicate and modification emit logic. The wrapper should call into the existing detection code, not duplicate it.

- [ ] **Step 4: Run test**

Run: `PYTHONPATH=src pytest tests/unit/optimizers/microcode/flow/flattening/strategies/test_bad_while_loop_strategy.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/d810/optimizers/microcode/flow/flattening/strategies/
git commit -m "feat(engine): wrap BadWhileLoop as engine strategy"
```

### Task 2.2: FakeJump as a strategy (same pattern as 2.1)

Follow the same pattern as Task 2.1 for `unflattener_fake_jump.py`.

### Task 2.3: SingleIteration as a strategy (same pattern as 2.1)

Follow the same pattern as Task 2.1 for `unflattener_single_iteration.py`.

### Task 2.4: Re-express Remaining BadWhileLoop Parity via cfg/recon/mutation

**Why this follow-up exists:** the current `BadWhileLoop` wrapper
intentionally keeps only shapes that can be represented safely through the
shared engine path. The endpoint is not "make legacy BadWhileLoop smarter"; the
endpoint is to use legacy BadWhileLoop as a case oracle while moving each
supported shape into neutral cleanup evidence, `cfg` graph modifications,
engine planning, and Hex-Rays backend mutation.

The wider transformation space mostly still exists in the modern architecture.
What is missing for each remaining bucket is proof that the legacy outcome can
be expressed as a generic graph-modification intent without reintroducing live
CFG surgery inside strategy code.

**Already supported by the modern architecture:**
- `DuplicateAndRedirect` in `src/d810/cfg/graph_modification.py`, compiled and
  materialized by `src/d810/cfg/plan.py`. The safe
  `BadWhileLoopDuplicateRedirect` path now routes through neutral cleanup
  evidence before lowering to this primitive.
- `CreateConditionalRedirect` in `src/d810/cfg/graph_modification.py`, with
  corresponding conditional patch steps in `src/d810/cfg/plan.py`. A previous
  attempt to promote the former
  `dispatcher_case_triangle_requires_trampoline` follow-up was too broad for
  Hodur's structure-recovery baseline, so keep that case classified as
  follow-up until a fact-preserving proof exists.
- trampoline materialization in `src/d810/cfg/plan.py` and
  `src/d810/cfg/flow/edit_simulator.py`
- simple inserted side-effect blocks via `InsertBlock` in
  `src/d810/cfg/graph_modification.py`
- advisory serial drift in `CreateConditionalRedirect` materialization is now
  handled by deferred-modifier remaps (`14b598a5`), so parity work should not
  rely on expected block serials being exact.

**Still missing or immature:**
- a proven story for replaying copied side effects from live dispatcher
  emulation into stable mutation plans. The materialization-boundary prototype
  may provide the right `CapturedBlockBody` carrier for this, but it should be
  integrated as a backend boundary first rather than used directly from
  BadWhile analysis.
- structural proof for the conditional duplicate/conditional redirect cases.
  These edit classes are modeled, but they should remain deferred until an
  explainer/parity gate proves the shape and target are safe.

- [ ] **Step 1: Audit every currently skipped legacy `BadWhileLoop` path**

Classify each skipped case as:
- `DuplicateAndRedirect`
- `CreateConditionalRedirect` (available as a graph primitive, but the
  dispatcher-case triangle promotion remains follow-up until proof-gated)
- `InsertBlock`
- intentionally unsupported / retired

- [x] **Step 1a: Add neutral evidence for the first safe duplicate case**

`cleanup_evidence.py` now maps the safe legacy `BadWhileLoopDuplicateRedirect`
shape into neutral evidence and lowers it to `DuplicateAndRedirect`. This is
the model for future buckets: legacy observes the case, neutral evidence records
the proof, and the shared cfg/engine/Hex-Rays pipeline performs the mutation.

- [ ] **Step 2: Add a richer `BadWhileLoop` planning layer**

Convert legacy analysis outcomes into generic `GraphModification` intents
instead of doing ad hoc live CFG mutation during analysis. Do this one bucket
at a time. Do not promote `BadWhileLoopConditionalRedirect` or
`BadWhileLoopConditionalDuplicate` merely because the dataclasses already
exist; require structural proof and parity.

- [ ] **Step 3: Decide the copied-side-effect replay contract**

Make an explicit decision:
- support it via stable `InsnSnapshot`-backed replay, or
- retire it intentionally and document the unsupported cases

- [ ] **Step 4: Add parity tests for each widened legacy case**

Cover at least:
- duplication rewrites
- conditional redirect block creation
- trampoline-backed materialization
- inserted side-effect blocks, if replay remains supported

- [ ] **Step 5: Widen the engine wrapper only after the planning path exists**

The only behavior that should remain retired by design is the old pattern of
doing live CFG mutation during analysis. The resulting transformations
themselves should stay available when they can be expressed through the shared
mutation pipeline.

---

## P3: Wrap generic.py Emulated-Dispatcher Family

Current note: the emulated dispatcher family boundary exists. Continue with
cases where legacy generic lowering materially rewrites a function and use
those to prove the engine/family model outside Hodur.

**Risk:** Medium. This is the most complex adaptation — generic.py's per-father emulation loop needs to be untangled into plan/execute phases.

**Depends on:** P0 complete. P1 recommended.

**Status on this branch (2026-04-14):**
- The family boundary is now phenotype-based rather than provenance-branded:
  `emulated_dispatcher_family.py`, `emulated_dispatcher_strategy.py`, and
  `unflattener_emulated_dispatcher_engine.py` are the canonical engine path.
- The important correctness rule turned out to be "no partial lowering when
  unresolved fathers remain", not "port more father-history state at all
  costs". The current family now observes candidate metadata but abstains from
  lowering when predecessor coverage is incomplete.
- `approov_vm_dispatcher` is no longer the active red P3 driver. Legacy
  `generic.py` also effectively abstains on that sample, so the sample is now
  useful as an abstention-contract regression, not as the next extraction
  target.
- The next real P3 driver should be a case where legacy generic unflattening
  materially rewrites the function, for example `switch_case_ollvm_pattern`,
  `high_fan_in_pattern`, then `tigress_minmaxarray` as a cross-provenance
  proof if the phenotype still matches.

### Task 3.1: Analyze generic.py emulation loop

**Files:**
- Read: `src/d810/optimizers/microcode/flow/flattening/generic.py` (full file)
- Read: `src/d810/optimizers/microcode/flow/flattening/unflattener.py`

- [ ] **Step 1: Map the emulation loop**

Read `generic.py` and `unflattener.py` to identify:
1. Where detection happens (GenericDispatcherCollector.visit_minsn)
2. Where per-father emulation happens (emulate_dispatcher_with_father_history)
3. Where modifications are queued (DeferredGraphModifier calls)
4. What state is carried between iterations

Document the loop structure as: detect -> (for each father: emulate -> resolve target -> queue redirect) -> apply all.

- [ ] **Step 2: Design the PlanFragment emission**

The per-father loop becomes:
```python
def plan(self, snapshot):
    mods = []
    for father in self.dispatcher.fathers:
        target = self._emulate_and_resolve(father)
        if target is not None:
            mods.append(RedirectGoto(father.serial, target.serial))
    if not mods:
        return None
    return PlanFragment(
        strategy_name="ollvm_emulation",
        family=FAMILY_DIRECT,
        ownership=OwnershipScope(
            blocks=frozenset(m.source_serial for m in mods),
            edges=frozenset(),
            transitions=frozenset(),
        ),
        prerequisites=[],
        expected_benefit=BenefitMetrics(
            handlers_resolved=len(mods),
            transitions_resolved=len(mods),
            blocks_freed=0,
            conflict_density=0.0,
        ),
        risk_score=0.0,
        modifications=mods,
    )
```

- [ ] **Step 3: Document findings in a design note**

Save analysis to `docs/plans/2026-XX-XX-generic-to-engine-adaptation.md` for the implementer.

### Task 3.2: Create EmulatedDispatcherStrategy

**Files:**
- Create: `src/d810/optimizers/microcode/flow/flattening/strategies/emulated_dispatcher_strategy.py`
- Create: `tests/unit/optimizers/microcode/flow/flattening/strategies/test_emulated_dispatcher_strategy.py`

The implementer reads the design note from Task 3.1 and wraps the existing emulation logic. This is more complex than P2 because:
1. The emulation uses live mba_t (needs IDA) — `is_applicable()` and `plan()` need snapshot-based equivalents
2. The dispatcher detection (GenericDispatcherCollector) carries state
3. The per-father loop may need multiple passes

**This task requires careful design.** The implementer should:
1. Keep the existing `GenericUnflatteningRule` working unchanged
2. Create the new strategy as an ALTERNATIVE path
3. Validate both produce the same results on test functions
4. Only then consider deprecating the old path

---

## P4: Audit linearized_state_dag Generality

Current note: keep this audit alive, but treat it as broader recon/family
generality rather than a Hodur-only audit. The `detect_linear_transition_regions`
extraction is one completed result of this direction.

**Risk:** Low (research only, no code changes). High importance — this is the load-bearing wall.

**Depends on:** Nothing. Can run in parallel with P0-P3.

### Task 4.1: Review linearized_state_dag for OLLVM assumptions

**Files:**
- Read: `src/d810/recon/flow/linearized_state_dag.py`

- [ ] **Step 1: Read the module and document**

Check for:
1. Does it assume a single state variable? (OLLVM uses one; other obfuscators may use multiple)
2. Does it assume BST-style dispatch? (Or is it agnostic to how states are resolved?)
3. Does it assume linear handler chains? (Or can it model arbitrary state machine topologies?)
4. Are the `SemanticEdgeKind` values general or OLLVM-specific?
5. Does `build_live_linearized_state_dag_from_graph()` depend on hodur-specific data?

- [ ] **Step 2: Document findings**

Create `docs/plans/2026-XX-XX-linearized-state-dag-audit.md`:
- List any OLLVM assumptions found
- Assess impact on future strategy families
- Recommend changes if needed (or confirm it's CFF-general)

### Task 4.2: Review 5 most-consumed modules

For each of the top-5 most-imported recon/flow modules (`linearized_state_dag`, `transition_builder`, `bst_analysis`, `transition_report`, `state_machine_analysis`):

- [ ] **Step 1: Check for hardcoded OLLVM constants or patterns**

Grep for: magic numbers (0xF6950-0xF719F), OLLVM-specific opcode sets, hardcoded comparison counts, assumptions about while-loop structure.

- [ ] **Step 2: Document any findings**

Add to the audit document from Task 4.1.

---

## P5: Document Extension Contract

Current note: do this after at least one non-state-machine family path has
meaningful engine parity. The guide should describe the shared engine/family
architecture, not Hodur internals.

**Risk:** None (documentation only).

**Depends on:** P0 and P1 complete.

### Task 5.1: Write extension guide

**Files:**
- Create: `src/d810/optimizers/microcode/flow/flattening/engine/EXTENSION_GUIDE.md`

- [ ] **Step 1: Write the guide**

Structure:
1. **Overview**: What the engine provides, what you need to implement
2. **Step-by-step**: How to create a new CFF attack family
   - Create your package under `flattening/`
   - Implement `DetectionResult` for your obfuscator
   - Subclass `CFFStrategyFamily` with detect/build_snapshot/strategies
   - Implement `ReconCollector` for your observations (register in recon)
   - Implement `TransitionBuilderStrategy` for your transition discovery
   - Write strategies against `UnflatteningStrategy` protocol
3. **What you change sparingly**: only extend `recon`, `cfg`, or `engine`
   when the new behavior is demonstrably shared across families
4. **Reference implementation**: Point to hodur as the canonical example
5. **Testing**: How to unit-test strategies without IDA, system-test with IDA

- [ ] **Step 2: Review against hodur's actual structure**

Walk through hodur/ and verify every file maps to one of the extension points described in the guide. If a hodur file doesn't fit, either the guide is incomplete or the file needs recategorization.

- [ ] **Step 3: Commit**

```bash
git add src/d810/optimizers/microcode/flow/flattening/engine/EXTENSION_GUIDE.md
git commit -m "docs(engine): add extension guide for new CFF strategy families"
```

---

## Execution Dependencies

```
E0 baseline gate  ──→  E1 canonical engine imports
                 └─→  E1.5 state-machine profile boundary
                 └─→  E2 reusable HCC algorithm extraction
                 └─→  E3 non-state-machine family normalization

E1/E1.5/E2/E3  ──→  E4 retire legacy paths after parity
E1/E1.5/E2/E3  ──→  E5 extension contract
```

E0 is always active. E1, E1.5, E2, and E3 can proceed independently as long as
each slice preserves the baseline gate. E4 depends on parity evidence. E5
should be written only after the architecture has at least the state-machine
profile plus one non-state-machine profile/family exercising the shared engine
path.

## Risk Assessment

| Phase | Risk | Mitigation |
|-|-|-|
| E0 | Medium — baseline drift is easy during extraction | Keep structure-recovery-pass artifacts; rerun cff_debug/oracle for behavior-affecting slices |
| E1 | Low-medium — import changes can expose hidden IDA dependencies | Replace only engine-generic imports; run import contracts and focused unit slices |
| E1.5 | Medium — profile/entrypoint refactors can accidentally recreate the old monolith or reorder strategies | Move registry/config first; keep strategy modules separate; require focused ordering tests and sub7FFD gate for behavior-affecting changes |
| E2 | Medium — HCC helpers mix pure analysis, live CFG probes, and Hex-Rays instruction capture | Extract one responsibility at a time; keep HCC behavior-preserving; require sub7FFD no-regression when lowering behavior can change |
| E3 | Medium — old generic/simple rules have implicit behavior | Keep old paths until engine parity or explicit abstention is proven |
| E4 | Medium-high — premature deletion loses fallback behavior | Remove only after parity tests and field samples stop depending on legacy path |
| E5 | Low — docs only | Write after the architecture is exercised by more than the state-machine unflattener |

## Success Criteria

1. Existing engine imports keep working:
   `from d810.optimizers.microcode.flow.flattening.engine import UnflatteningStrategy`.
2. Production code no longer imports engine-generic types through
   `flattening.hodur.*` compatibility modules.
3. The historical Hodur entrypoint is represented as a compatibility/profile
   entrypoint over the generic state-machine unflattening engine, and sub7FFD
   does not regress against the `structure-recovery-pass` baseline.
4. At least one non-state-machine family path has meaningful engine parity or a
   documented abstention contract.
5. Reusable algorithms grown inside Hodur/HCC move to `recon` or `cfg` when
   their responsibility is analysis or backend-agnostic CFG planning.
6. New unflattening profiles/families can be built from `recon` collectors,
   a generic state-machine profile/family contract, `PlanFragment`,
   `cfg.GraphModification`, and backend materialization without reading Hodur
   internals or compatibility imports.
