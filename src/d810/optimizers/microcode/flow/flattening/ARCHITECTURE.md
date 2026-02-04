# Unflattening Architecture

This directory contains two architectural approaches for control-flow flattening removal:

## 1. Production (Inheritance-based) - `generic.py`

The current production architecture uses class inheritance:

```
GenericDispatcherBlockInfo
    └── GenericDispatcherInfo
        └── GenericDispatcherCollector
            └── GenericDispatcherUnflatteningRule
                └── OllvmDispatcherUnflatteningRule
                └── TigressDispatcherUnflatteningRule
                └── BadWhileLoopUnflattener
                └── SingleIterationLoopUnflattener
```

**Pros:**
- Battle-tested in production
- All existing unflatteners use this architecture
- Well-understood behavior

**Cons:**
- Difficult to unit test (requires IDA environment)
- Deep inheritance hierarchy
- Hard to extend without affecting other classes

## 2. Experimental (Composition-based) - `services.py`, `unflattener_refactored.py`

An experimental architecture using composition over inheritance:

```python
UnflattenerRule
    ├── DispatcherFinder (protocol)
    │   └── OLLVMDispatcherFinder
    │   └── (future: TigressDispatcherFinder)
    ├── PathEmulator
    └── CFGPatcher
```

**Pros:**
- Easily unit testable (mock dependencies)
- Clear service boundaries
- Single-responsibility components
- Immutable `Dispatcher` dataclass

**Cons:**
- Not yet integrated into production
- May have undiscovered edge cases
- Would require migration effort

## Migration Path

The composition-based architecture is **recommended for new features** but a full migration is not planned due to the risk/reward tradeoff.

### When to use composition-based (`services.py`):

1. **New unflattening strategies** - Start with composition
2. **Experimental prototypes** - Faster iteration
3. **Unit tests** - Much easier to test in isolation

### When to use inheritance-based (`generic.py`):

1. **Existing patterns** - OLLVM, Tigress, etc.
2. **Incremental improvements** - Keep using same base
3. **Production deployments** - Battle-tested

### Gradual Migration Strategy

If migration is desired in the future:

1. **Adapter pattern**: Wrap composition services to expose inheritance interface
2. **Parallel implementation**: New code uses services, old code unchanged
3. **Strangler fig**: Gradually route more traffic to new implementation
4. **Feature flags**: Toggle between implementations per binary

## File Reference

| File | Purpose | Architecture |
|------|---------|--------------|
| `generic.py` | Base classes for unflattening | Inheritance |
| `unflattener.py` | OLLVM-specific unflattening | Inheritance |
| `unflattener_tigress.py` | Tigress-specific unflattening | Inheritance |
| `unflattener_badwhile_loop.py` | BadWhileLoop patterns | Inheritance |
| `unflattener_single_iteration.py` | Single-iteration loops | Inheritance |
| `services.py` | Composable services | Composition |
| `unflattener_refactored.py` | Refactored rule using services | Composition |
| `dispatcher_detection.py` | Dispatcher cache/heuristics | Shared |
| `loop_prover.py` | Z3-based loop verification | Shared |

## Testing

Composition-based tests are in:
- `tests/system/optimizers/microcode/flow/flattening/test_unflattener_services.py`

These demonstrate the testability benefits of the composition approach.
