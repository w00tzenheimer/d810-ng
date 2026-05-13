# Unflattening Engine Extraction & Architecture Unification

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract hodur's strategy/planner/executor infrastructure into a shared unflattening engine, making it the single execution paradigm for all unflattening strategies once the live Hodur semantic surface is stable enough to expose the right shared API.

**Architecture:** One execution model (detect -> snapshot -> plan -> execute) with variable complexity per strategy. Simple transforms (FakeJump, BadWhileLoop) can become trivial strategies with 1-edit plans. Complex attacks (hodur's multi-strategy OLLVM pipeline) remain the proving ground for the abstractions before anything is promoted into a shared `flattening/engine` package. Future CFF attacks should consume shared `recon/flow` and `cfg` boundaries where appropriate, not bypass them.

**Tech Stack:** Python 3.13, IDA Pro 9+ microcode API, pytest, d810 plugin infrastructure

---

## Table of Contents

1. [Research & Reasoning](#research--reasoning)
2. [Architecture Decision Record](#architecture-decision-record)
3. [Execution Order Correction](#execution-order-correction)
4. [File Structure](#file-structure)
5. [P0: Engine Extraction](#p0-engine-extraction)
6. [P1: CFFStrategyFamily Orchestrator](#p1-cffstrategyfamily-orchestrator)
7. [P2: Wrap Simple Transforms](#p2-wrap-simple-transforms)
8. [P3: Wrap generic.py Emulated-Dispatcher Family](#p3-wrap-genericpy-emulated-dispatcher-family)
9. [P4: Audit linearized_state_dag Generality](#p4-audit-linearized_state_dag-generality)
10. [P5: Document Extension Contract](#p5-document-extension-contract)

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

This infrastructure is architecturally general but lives inside `flattening/hodur/`, forcing any future strategy to import from a sibling attack package. Meanwhile, the old unflattening framework (`generic.py`) uses a different paradigm: inheritance-based, per-block emulation, no planning phase, no transactions.

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
  hodur/              OLLVM CFF attack (first client of engine + recon/flow)
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

---

## Architecture Decision Record

| ID | Decision | Rationale |
|-|-|-|
| ADR-1 | One execution paradigm for all unflattening | Two models = two mental models. Simple strategies have trivial plans with zero overhead. |
| ADR-2 | Engine extracted from hodur, not built from scratch | hodur's infrastructure IS the engine. Extracting is safer than rewriting. |
| ADR-3 | recon/flow stays as-is | CFF-general algorithms, not hodur-specific. Consumer count misleading. |
| ADR-4 | generic.py adapts incrementally | Old code keeps working while new strategies added alongside. No big-bang rewrite. |
| ADR-5 | Dispatcher analysis stays in recon/flow | BST and switch-table dispatchers are multi-obfuscator analyses, not Hodur-only quirks. |
| ADR-6 | Backward-compat re-exports during transition | hodur/ originals become thin re-exports. Tests keep passing during migration. |
| ADR-7 | Engine extraction is deferred until live Hodur semantics are stabilized | Current shared-feeder selection and direct/terminal lowering still define the real engine boundary. |
| ADR-8 | Shared dispatcher IR belongs in recon/flow before engine extraction | `DispatcherHandlerMap` and switch-table analysis proved new dispatcher forms should first land as shared recon artifacts plus Hodur adapters. |

---

## Execution Order Correction

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

**Risk:** Low-medium. Each simple transform becomes a strategy with ~20-30 lines of glue. Old code stays working — new strategies are registered alongside.

**Depends on:** P0 complete. P1 recommended but not strictly required.

**Note:** This phase is incremental. Each transform can be wrapped independently. Start with BadWhileLoop (simplest) as proof-of-concept.

**Current branch status:** `FakeJump` and `SingleIteration` are already live
engine strategies, and `BadWhileLoop` now has an engine-native safe subset.
The remaining gap is not that the legacy transformations are impossible in the
modern architecture, but that the richer `BadWhileLoop` cases are not yet
re-expressed through the shared `cfg` / `recon` / mutation-planning path.

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
intentionally keeps only the already-resolvable subset that can be expressed as
`RedirectGoto` or `ConvertToGoto` without replaying complex live mutations
during analysis. The wider transformation space mostly still exists in the
modern architecture. What is missing is the planning layer that turns richer
legacy outcomes into generic graph-modification intents.

**Already supported by the modern architecture:**
- `DuplicateAndRedirect` in `src/d810/cfg/graph_modification.py`, compiled and
  materialized by `src/d810/cfg/plan.py`
- `CreateConditionalRedirect` in `src/d810/cfg/graph_modification.py`, with
  corresponding conditional patch steps in `src/d810/cfg/plan.py`
- trampoline materialization in `src/d810/cfg/plan.py` and
  `src/d810/cfg/flow/edit_simulator.py`
- simple inserted side-effect blocks via `InsertBlock` in
  `src/d810/cfg/graph_modification.py`

**Still missing or immature:**
- a `recon` / planning layer that converts richer legacy `BadWhileLoop`
  analysis outcomes into backend-agnostic graph modifications
- a proven story for replaying copied side effects from live dispatcher
  emulation into stable `InsnSnapshot`-backed mutation plans

- [ ] **Step 1: Audit every currently skipped legacy `BadWhileLoop` path**

Classify each skipped case as:
- `DuplicateAndRedirect`
- `CreateConditionalRedirect`
- `InsertBlock`
- intentionally unsupported / retired

- [ ] **Step 2: Add a richer `BadWhileLoop` planning layer**

Convert legacy analysis outcomes into generic `GraphModification` intents
instead of doing ad hoc live CFG mutation during analysis.

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
P0 (engine extraction)  ──→  P1 (CFFStrategyFamily)  ──→  P5 (extension docs)
                        ──→  P2 (simple transforms)
                        ──→  P3 (generic.py adaptation)
P4 (DAG audit)  ← independent, run anytime
```

P0 is the critical path. P4 can run in parallel from day one. P2 and P3 are independent of each other. P5 depends on P0+P1 being stable.

## Risk Assessment

| Phase | Risk | Mitigation |
|-|-|-|
| P0 | Low — pure file moves + re-exports | Re-export shims keep all existing imports working |
| P1 | Medium — new abstraction | Protocol-only, no behavioral changes until adopted |
| P2 | Low — ~20 lines per transform | Old code untouched, new strategies registered alongside |
| P3 | Medium — untangling emulation loop | Keep old GenericUnflatteningRule working, new strategy is alternative |
| P4 | None — research only | Findings may influence future work but no code changes |
| P5 | None — documentation only | Validates architecture by explaining it |

## Success Criteria

1. `PYTHONPATH=src pytest tests/unit/ -v` passes with same count before and after P0
2. `from d810.optimizers.microcode.flow.flattening.engine import UnflatteningStrategy` works
3. hodur's 15 strategies continue to work unchanged via re-export shims
4. A new contributor can read EXTENSION_GUIDE.md and create a strategy family without reading hodur's internals
