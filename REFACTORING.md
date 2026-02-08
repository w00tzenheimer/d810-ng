# Refactoring D810

## Status (v0.3.0 - February 2026)

### Completed

| Goal | Status | Location |
|------|--------|----------|
| `OptimizationContext` frozen dataclass | **DONE** | `src/d810/optimizers/core.py:18` |
| `OptimizationRule` Protocol | **DONE** | `src/d810/optimizers/core.py:40` |
| `PatternMatchingRule` ABC | **DONE** | `src/d810/optimizers/core.py:80` |
| `DispatcherFinder` Protocol | **DONE** | `services.py:59` |
| `PathEmulator` class | **DONE** | `services.py:110` |
| `CFGPatcher` class | **DONE** | `services.py:292` |
| `UnflattenerRule` coordinator | **DONE** | `unflattener_refactored.py:29` |
| Symbolic DSL (`Var`, `Const`, operators) | **DONE** | `src/d810/mba/dsl.py` |
| `VerifiableRule` with Z3 self-verification | **DONE** | `src/d810/mba/rules/_base.py:107` |
| Z3 backend (IDA-independent) | **DONE** | `src/d810/mba/backends/z3.py` |
| `D810Manager` centralized optimizer loop | **DONE** | `src/d810/manager.py:75` |
| `DeferredGraphModifier` / `ImmediateGraphModifier` | **DONE** | `src/d810/hexrays/deferred_modifier.py` |
| CFG `verify` parameter for batch safety | **DONE** | `src/d810/hexrays/cfg_utils.py` |
| `create_standalone_block` (safe block creation) | **DONE** | `src/d810/hexrays/cfg_utils.py:477` |
| Declarative DSL rules (183 rules) | **DONE** | `src/d810/mba/rules/` |
| Legacy `rewrite_*.py` removal | **DONE** | Removed 13 files, 155 classes |
| INTERR 50856/50858/51810 CFG fixes | **DONE** | v0.3.0 |

### Remaining Work

| Goal | Status | Notes |
|------|--------|-------|
| Wire `OptimizationRule` Protocol as primary dispatch | **TODO** | Protocol exists but `hexrays_hooks.py` still dispatches via legacy hierarchy |
| Make `UnflattenerRule` the primary unflattening path | **TODO** | Parallel implementation alongside legacy `GenericDispatcherUnflatteningRule` |
| Re-enable `CstSimplificationRule2` | **TODO** | Z3-provable with constraint `c1 \| c2 == MAX_VAL` |
| Evaluate `FoldPureConstantRule` | **TODO** | Disabled; `FoldReadonlyDataRule` is active replacement |
| Clean up `canonicalizer.py` | **TODO** | Dead code with potentially useful AST normalization utils |

---

## Architecture Overview

### Pattern Rule System

Rules are defined declaratively using a symbolic DSL with Z3 self-verification:

```python
from d810.mba.dsl import Var, Const
from d810.mba.rules._base import VerifiableRule

x, y = Var("x"), Var("y")

class XorFromOrAndSub(VerifiableRule):
    name = "XorFromOrAndSub"
    description = "(x | y) - (x & y) => x ^ y"

    @property
    def pattern(self):
        return (x | y) - (x & y)

    @property
    def replacement(self):
        return x ^ y
```

Rules auto-register via `Registrant` metaclass and are adapted for IDA via `IDAPatternAdapter`. Z3 verifies equivalence at import time.

**Rule files:** `src/d810/mba/rules/` (183 rules across 14 files: add, and_, bnot, cst, hodur, misc, mov, mul, neg, or_, predicates, sub, xor, plus experimental)

### Service Decomposition

The monolithic `GenericDispatcherUnflatteningRule` is decomposed into:

- **`DispatcherFinder`** Protocol -- finds CFF dispatchers
- **`PathEmulator`** -- resolves state variables via emulation
- **`CFGPatcher`** -- safe CFG modification wrappers
- **`DeferredGraphModifier`** -- queue-based atomic batch modifications

### CFG Safety

All CFG manipulation functions accept `verify: bool = True`. Batch callers pass `verify=False` to defer MBA verification until all modifications complete, preventing INTERR 50858 cascades.

---

## Original Problems (Resolved)

1. **Deep Inheritance** -- Mitigated by composition-based services and Protocol interfaces
2. **Implicit State** -- `OptimizationContext` frozen dataclass replaces mutable instance vars
3. **Mixed Concerns** -- Separated into `DispatcherFinder`, `PathEmulator`, `CFGPatcher`
4. **Poorly Defined Interfaces** -- `OptimizationRule` Protocol defines clear contracts
5. **Imperative AstNode construction** -- Replaced by declarative DSL with operator overloading
6. **No rule verification** -- Z3-based `VerifiableRule.verify()` catches incorrect rules at import time
