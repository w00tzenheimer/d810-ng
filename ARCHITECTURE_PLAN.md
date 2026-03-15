# Architecture Cleanup Plan: Flow Flattening & Hodur

**Date:** 2026-03-11  
**Status:** Approved for Implementation  
**Scope:** `src/d810/optimizers/microcode/flow/flattening/`

---

## 📋 Executive Summary

This plan consolidates findings from the hodur package analysis into actionable steps:

1. **DELETE** unused/experimental code (`services.py`, `unflattener_refactored.py`)
2. **EXTRACT** reusable strategy patterns from hodur to base classes
3. **KEEP** production-tested detection (`dispatcher_detection.py`)
4. **ESTABLISH** clear layering: `recon/` → `strategies/` → `planner/`

**Total Effort:** 8-12 hours  
**Risk:** Low (backed by existing tests)  
**Migration Path:** Gradual with adapters

---

## 🔍 Discovery Summary

### What We Found

| Component | Location | Status | Action |
|-----------|----------|--------|--------|
| `DispatcherCache` | `recon/flow/dispatcher_detection.py` | ✅ Production, cached | **KEEP** - canonical detection |
| `DispatcherAnalysis` | `recon/flow/dispatcher_detection.py` | ✅ Used by hodur | **KEEP** - provides `is_conditional_chain` |
| `services.py` | `flow/flattening/services.py` | ❌ Unused, duplicates detection | **DELETE** |
| `unflattener_refactored.py` | `flow/flattening/unflattener_refactored.py` | ❌ Demo code, never wired | **DELETE** |
| `hodur/strategy.py` | `flow/flattening/hodur/strategy.py` | ✅ Pure Python, protocol-based | **EXTRACT** to `base_strategy.py` |
| `hodur/provenance.py` | `flow/flattening/hodur/provenance.py` | ✅ Pure Python, audit trail | **EXTRACT** to `core/pipeline.py` |
| `hodur/_helpers.py` | `flow/flattening/hodur/_helpers.py` | ⚠️ Mixed utility | **REVIEW** - extract BST helpers |
| `hodur/analysis.py` | `flow/flattening/hodur/analysis.py` | ✅ Uses `DispatcherCache` correctly | **KEEP** - pattern for integration |

### Key Insight

**`DispatcherCache` is already the canonical detection layer.** It's used by hodur as a fast pre-filter:
- ✅ Provides `is_conditional_chain` check (DispatcherType)
- ✅ Provides `state_constants` set
- ✅ Provides `state_variable` candidate
- ✅ Cached by function EA (weakref)
- ✅ Production-tested

**`services.py` was solving a problem that's already solved** — it duplicates detection logic and adds no value over the existing `DispatcherCache`.

---

## 📐 Target Architecture

```
src/d810/
├── core/
│   └── pipeline.py                    # ← EXTRACT from hodur/provenance.py
│       - DecisionPhase, DecisionReasonCode
│       - GateVerdict, GateDecision, GateAccounting
│       - DecisionRecord, PipelineProvenance
│
├── recon/
│   └── flow/
│       ├── dispatcher_detection.py    # ← KEEP (canonical detection)
│       │   - DispatcherCache
│       │   - DispatcherAnalysis
│       │   - DispatcherType (SWITCH_TABLE, CONDITIONAL_CHAIN, INDIRECT_JUMP)
│       │   - BlockAnalysis
│       │   - DispatcherStrategy (IntFlag)
│       │
│       └── transition_builder.py      # ← KEEP (already has StateHandler, etc.)
│
└── optimizers/microcode/flow/flattening/
    ├── __init__.py
    ├── ARCHITECTURE.md                # ← UPDATE with this plan
    │
    ├── # ─── Base Layer (Protocols & Types) ─────────────────────────
    ├── base_strategy.py               # ← EXTRACT from hodur/strategy.py
    │   - FAMILY_DIRECT, FAMILY_FALLBACK, FAMILY_CLEANUP
    │   - OwnershipScope
    │   - BenefitMetrics
    │   - PlanFragment
    │   - UnflatteningStrategy (Protocol)
    │   - StageResult
    │   - VerificationGate
    │
    ├── strategies/                    # ← NEW directory
    │   ├── __init__.py
    │   ├── ollvm_strategy.py          # ← NEW (wrap legacy GenericDispatcherInfo)
    │   ├── hodur_direct.py            # ← NEW (wrap hodur logic)
    │   └── cleanup.py                 # ← NEW (dead code elimination)
    │
    ├── hodur/                         # ← KEEP (becomes consumer of base)
    │   ├── __init__.py
    │   ├── analysis.py                # Uses DispatcherCache correctly
    │   ├── unflattener.py             # Orchestrator, uses strategies
    │   ├── planner.py                 # Uses base_strategy types
    │   ├── provenance.py              # → moved to core/pipeline.py
    │   ├── strategy.py                # → moved to base_strategy.py
    │   └── strategies/                # Existing hodur-specific strategies
    │
    ├── # ─── Legacy (Deprecated) ─────────────────────────────────────
    ├── generic.py                     # DEPRECATED - mark with warnings
    ├── unflattener.py                 # DEPRECATED - legacy OLLVM
    └── unflattener_hodur.py           # DEPRECATED - legacy wrapper
```

---

## 🗓️ Implementation Plan

### Phase 1: Extract Base Types (2-3 hours)

**Goal:** Create reusable foundation from hodur's pure-Python components.

#### Step 1.1: Create `core/pipeline.py`

**Source:** `hodur/provenance.py` (lines 1-350)

```python
# src/d810/core/pipeline.py
"""Pipeline lifecycle and decision provenance tracking.

This module provides types for tracking decisions made during multi-stage
transformation pipelines. Used by unflattening planners to maintain an
audit trail from recon artifacts through to applied modifications.
"""
from __future__ import annotations
import enum
from dataclasses import dataclass, field, replace
from d810.core.typing import TYPE_CHECKING
from d810.core import logging

# Extract from hodur/provenance.py:
# - DecisionPhase (enum)
# - DecisionReasonCode (enum)
# - GateVerdict (enum)
# - GateDecision
# - GateAccounting
# - DecisionInputSummary
# - DecisionRecord
# - PipelineProvenance
```

**Actions:**
- [ ] Copy types from `hodur/provenance.py` to `core/pipeline.py`
- [ ] Remove IDA-specific imports (should be none - already pure Python)
- [ ] Update docstrings to reflect general pipeline usage (not just hodur)
- [ ] Add to `core/__init__.py` exports
- [ ] Run tests to verify no breakage

#### Step 1.2: Create `base_strategy.py`

**Source:** `hodur/strategy.py`

```python
# src/d810/optimizers/microcode/flow/flattening/base_strategy.py
"""Base strategy types for unflattening pipelines.

This module defines the strategy pattern for control-flow unflattening.
All types are pure Python (no IDA imports) for testability.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from d810.core.typing import Protocol, runtime_checkable

# Extract from hodur/strategy.py:
# - FAMILY_DIRECT, FAMILY_FALLBACK, FAMILY_CLEANUP (constants)
# - OwnershipScope
# - BenefitMetrics
# - PlanFragment
# - UnflatteningStrategy (Protocol)
# - StageResult
# - VerificationGate
```

**Actions:**
- [ ] Copy types from `hodur/strategy.py` to `base_strategy.py`
- [ ] Verify zero IDA imports (critical for testability)
- [ ] Add to `flow/flattening/__init__.py` exports
- [ ] Run unit tests on strategy types

#### Step 1.3: Update Hodur Imports

**Files to update:**
- `hodur/strategy.py` → re-export from `base_strategy`
- `hodur/provenance.py` → re-export from `core.pipeline`
- `hodur/planner.py` → import from new locations

```python
# hodur/strategy.py (after extraction)
"""Re-exports from base_strategy for backward compatibility."""
from d810.optimizers.microcode.flow.flattening.base_strategy import (
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
    FAMILY_CLEANUP,
    OwnershipScope,
    BenefitMetrics,
    PlanFragment,
    UnflatteningStrategy,
    StageResult,
    VerificationGate,
)
__all__ = [...]
```

**Actions:**
- [ ] Create re-export stubs in hodur package
- [ ] Update internal hodur imports
- [ ] Run hodur tests to verify no breakage

---

### Phase 2: Delete Unused Code (1 hour)

**Goal:** Remove dead weight and clarify architecture.

#### Step 2.1: Delete Files

```bash
# Delete unused files
rm src/d810/optimizers/microcode/flow/flattening/services.py
rm src/d810/optimizers/microcode/flow/flattening/unflattener_refactored.py

# Delete test file (tests unused code)
rm tests/system/runtime/optimizers/microcode/flow/flattening/test_services_integration.py
```

**Actions:**
- [ ] Verify no production code imports these files
- [ ] Delete files
- [ ] Update any `__init__.py` exports

#### Step 2.2: Update Documentation

**File:** `flow/flattening/ARCHITECTURE.md`

```markdown
## Deprecated Components

The following components have been removed as of v2.0:

- `services.py` - Superseded by strategy pattern in `base_strategy.py`
- `unflattener_refactored.py` - Demo code, never wired into production
- `test_services_integration.py` - Tested unused code

Use the strategy pattern instead:
- See `base_strategy.py` for protocol
- See `strategies/` for implementations
- See `hodur/` for reference implementation
```

**Actions:**
- [ ] Update ARCHITECTURE.md
- [ ] Add deprecation notices to docs
- [ ] Update README if needed

---

### Phase 3: Implement Strategy Pattern (3-4 hours)

**Goal:** Create strategy implementations that wrap existing logic.

#### Step 3.1: Create `strategies/__init__.py`

```python
# src/d810/optimizers/microcode/flow/flattening/strategies/__init__.py
"""Strategy implementations for unflattening pipelines."""

from .ollvm_strategy import OLLVMLinearizationStrategy
from .cleanup_strategy import CleanupStrategy

__all__ = [
    "OLLVMLinearizationStrategy",
    "CleanupStrategy",
]
```

#### Step 3.2: Create `strategies/ollvm_strategy.py`

```python
# src/d810/optimizers/microcode/flow/flattening/strategies/ollvm_strategy.py
"""OLLVM control-flow flattening unflattening strategy."""
from __future__ import annotations
from d810.recon.flow.dispatcher_detection import DispatcherCache, DispatcherType
from d810.optimizers.microcode.flow.flattening.base_strategy import (
    UnflatteningStrategy, PlanFragment, FAMILY_DIRECT, OwnershipScope, BenefitMetrics
)

class OLLVMLinearizationStrategy(UnflatteningStrategy):
    """Unflattens OLLVM-style switch-table dispatchers."""
    
    @property
    def name(self) -> str:
        return "ollvm_linearize"
    
    @property
    def family(self) -> str:
        return FAMILY_DIRECT
    
    def is_applicable(self, snapshot) -> bool:
        # Use DispatcherCache for detection
        cache = DispatcherCache.get_or_create(snapshot.mba)
        analysis = cache.analyze()
        return analysis.is_switch_table  # Already has this!
    
    def plan(self, snapshot) -> PlanFragment | None:
        # Wrap existing generic.py logic
        # Return PlanFragment with modifications
        ...
```

**Actions:**
- [ ] Create strategy file
- [ ] Wrap existing `GenericDispatcherInfo` logic
- [ ] Return `PlanFragment` with `GraphModification` list
- [ ] Test with existing OLLVM test binaries

#### Step 3.3: Create `strategies/cleanup_strategy.py`

```python
# src/d810/optimizers/microcode/flow/flattening/strategies/cleanup_strategy.py
"""Post-unflattening cleanup strategy."""
from __future__ import annotations
from d810.optimizers.microcode.flow.flattening.base_strategy import (
    UnflatteningStrategy, PlanFragment, FAMILY_CLEANUP
)

class CleanupStrategy(UnflatteningStrategy):
    """Removes dead code after unflattening."""
    
    @property
    def name(self) -> str:
        return "cleanup_dead_code"
    
    @property
    def family(self) -> str:
        return FAMILY_CLEANUP
    
    def is_applicable(self, snapshot) -> bool:
        # Check if any blocks are now unreachable
        return snapshot.reachability_info.unreachable_blocks > 0
    
    def plan(self, snapshot) -> PlanFragment | None:
        # Generate cleanup modifications
        ...
```

**Actions:**
- [ ] Create cleanup strategy
- [ ] Hook into existing dead-block elimination
- [ ] Test with post-unflattening cleanup

---

### Phase 4: Wire Into Pipeline (2-3 hours)

**Goal:** Connect strategies to the optimization framework.

#### Step 4.1: Update `hodur/unflattener.py`

```python
# Current: uses monolithic logic
# New: uses strategy pattern

from d810.optimizers.microcode.flow.flattening.strategies import (
    OLLVMLinearizationStrategy,
    CleanupStrategy,
)
from d810.optimizers.microcode.flow.flattening.planner import UnflatteningPlanner

def optimize(self, blk):
    # Create planner with strategy chain
    planner = UnflatteningPlanner(
        strategies=[
            OLLVMLinearizationStrategy(),
            CleanupStrategy(),
        ],
        recon_artifacts=self.recon_artifacts,
    )
    
    # Execute pipeline
    result = planner.execute(self.mba)
    
    return result.changes
```

**Actions:**
- [ ] Update `optimize()` method
- [ ] Wire in recon artifacts
- [ ] Test with existing test suite

#### Step 4.2: Update Tests

**File:** `tests/unit/optimizers/microcode/flow/flattening/`

```python
# Test strategy pattern
from d810.optimizers.microcode.flow.flattening.strategies import OLLVMLinearizationStrategy
from d810.optimizers.microcode.flow.flattening.base_strategy import FAMILY_DIRECT

def test_ollvm_strategy_applicability():
    strategy = OLLVMLinearizationStrategy()
    assert strategy.family == FAMILY_DIRECT
    # Test with mock snapshot
    ...
```

**Actions:**
- [ ] Add unit tests for strategies
- [ ] Update integration tests
- [ ] Verify test coverage

---

### Phase 5: Documentation & Cleanup (1 hour)

#### Step 5.1: Update `ARCHITECTURE.md`

```markdown
# Unflattening Architecture

## Strategy Pattern (Recommended)

New code should use the strategy pattern:

```python
from d810.optimizers.microcode.flow.flattening.base_strategy import UnflatteningStrategy
from d810.optimizers.microcode.flow.flattening.strategies import OLLVMLinearizationStrategy

class MyStrategy(UnflatteningStrategy):
    @property
    def name(self) -> str: return "my_strategy"
    
    def is_applicable(self, snapshot) -> bool: ...
    def plan(self, snapshot) -> PlanFragment | None: ...
```

## Legacy (Deprecated)

- `generic.py` - Inheritance-based, use for existing patterns only
- `unflattener.py` - OLLVM-specific, migrate to strategy pattern
```

#### Step 5.2: Update Docstrings

**Files to update:**
- `base_strategy.py` - Add comprehensive examples
- `dispatcher_detection.py` - Note it's the canonical detection layer
- `hodur/analysis.py` - Document `DispatcherCache` usage pattern

---

## ✅ Acceptance Criteria

### Phase 1 (Extract)
- [ ] `core/pipeline.py` exists with all provenance types
- [ ] `base_strategy.py` exists with strategy protocol
- [ ] Zero IDA imports in extracted files
- [ ] Unit tests pass for extracted types

### Phase 2 (Delete)
- [ ] `services.py` deleted
- [ ] `unflattener_refactored.py` deleted
- [ ] `test_services_integration.py` deleted
- [ ] No import errors in codebase

### Phase 3 (Implement)
- [ ] `strategies/ollvm_strategy.py` exists
- [ ] `strategies/cleanup_strategy.py` exists
- [ ] Strategies return valid `PlanFragment`
- [ ] Strategy tests pass

### Phase 4 (Wire)
- [ ] `hodur/unflattener.py` uses strategy pattern
- [ ] Integration tests pass
- [ ] No regression in unflattening accuracy

### Phase 5 (Document)
- [ ] `ARCHITECTURE.md` updated
- [ ] Deprecation notices added
- [ ] Migration guide documented

---

## 🚧 Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Breaking existing unflattening | High | Keep legacy code, use adapters |
| Test failures | Medium | Run full test suite after each phase |
| Performance regression | Medium | Benchmark before/after |
| Import cycles | Low | Careful module organization |

---

## 📚 References

- `hodur/strategy.py` - Source for `base_strategy.py`
- `hodur/provenance.py` - Source for `core/pipeline.py`
- `dispatcher_detection.py` - Canonical detection layer
- `ARCHITECTURE.md` - Existing architecture doc
- Ticket: d810-xxx (tracking issue)

---

## 🎯 Success Metrics

1. **Code Reduction:** -800 lines (deleted `services.py`, `unflattener_refactored.py`)
2. **Test Coverage:** >80% on new strategy classes
3. **Zero Regression:** All existing tests pass
4. **Clear Layering:** `recon/` → `strategies/` → `planner/` documented
