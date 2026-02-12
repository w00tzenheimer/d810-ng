# PR1: Pattern Engine Dispatcher — Design

## Goal

Introduce a clean dispatcher module (`engine.py`) that gates between Python and Cython implementations of the pattern matching speedups, following the existing CythonMode Pattern 1 from `ast.py`.

## Architecture

A single gate module (`engine.py`) in the pattern_matching package that:
1. Checks `CythonMode().is_enabled()` at import time
2. Attempts Cython imports, falls back to Python on ImportError
3. Exports normalized names so consumers don't care about backend
4. Exposes `_USING_CYTHON` flag and `get_engine_info()` for diagnostics
5. Keeps legacy `PatternStorage` path fully functional alongside new storage

## Approach: Simple Gate Module (Pattern 1)

Follows the established pattern from `src/d810/expr/ast.py` lines 103-145:

```python
# engine.py
from d810.core.cymode import CythonMode

if CythonMode().is_enabled():
    try:
        from d810.speedups.optimizers.c_pattern_match import (
            COpcodeIndexedStorage as OpcodeIndexedStorage,
            match_pattern_nomut,
            CMatchBindings as MatchBindings,
            compute_fingerprint_py as _cy_compute_fingerprint,
        )
        _USING_CYTHON = True
    except (ModuleNotFoundError, ImportError):
        from d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups import (
            OpcodeIndexedStorage,
            match_pattern_nomut,
            MatchBindings,
        )
        _USING_CYTHON = False
else:
    from d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups import (
        OpcodeIndexedStorage,
        match_pattern_nomut,
        MatchBindings,
    )
    _USING_CYTHON = False
```

### Fingerprint Normalization

The Cython `compute_fingerprint_py()` returns a dict, while Python returns `PatternFingerprint`. Since `OpcodeIndexedStorage`/`COpcodeIndexedStorage` compute fingerprints internally during `add_pattern()` and `get_candidates()`, the public fingerprint API is only needed for testing. The dispatcher will:
- Always export `compute_fingerprint` (Python version)
- Also export `PatternFingerprint` and `RulePatternEntry` from Python (these are data containers, no perf benefit from Cython)
- The Cython storage internally uses its own C-struct fingerprints

### handler.py Integration (Light-Touch)

PR1 does NOT replace `PatternStorage` in the hot path. It only:
1. Adds `from .engine import OpcodeIndexedStorage, match_pattern_nomut, MatchBindings, _USING_CYTHON`
2. Exposes `engine_info` property on `PatternOptimizer` for diagnostics
3. Optionally adds a second storage (`self._indexed_storage`) populated alongside `self.pattern_storage` for A/B validation (disabled by default)

The actual hot-path switchover happens in PR2.

### A/B Validation Mechanism

A `D810_PATTERN_ENGINE_VALIDATE` env var enables dual-path validation:
- Both `PatternStorage` and `OpcodeIndexedStorage` are populated during rule registration
- On each lookup, both are queried and results compared
- Mismatches are logged as warnings (not errors, to avoid breaking production)
- This validates the parity fix (d81-pqui) in real-world usage

## Exported API

```python
# From engine.py:
OpcodeIndexedStorage    # COpcodeIndexedStorage or OpcodeIndexedStorage
match_pattern_nomut     # Same name in both backends
MatchBindings           # CMatchBindings or MatchBindings
compute_fingerprint     # Always Python version (used for testing)
PatternFingerprint      # Always Python (data container)
RulePatternEntry        # Always Python (data container)
_USING_CYTHON: bool     # Diagnostics flag
get_engine_info() -> dict  # {"backend": "cython"|"python", "version": ...}
```

## Files

| File | Action | Purpose |
|------|--------|---------|
| `src/d810/optimizers/microcode/instructions/pattern_matching/engine.py` | Create | Dispatcher module |
| `src/d810/optimizers/microcode/instructions/pattern_matching/handler.py` | Modify | Import from engine, add engine_info, optional A/B storage |
| `tests/unit/test_pattern_engine_dispatcher.py` | Create | Engine selection matrix + contract tests |

## Test Strategy

All tests are **unit tests** (no IDA required):

1. **Engine selection matrix** (mock-based):
   - Cython available + CythonMode enabled → `_USING_CYTHON = True`
   - Cython available + CythonMode disabled (D810_NO_CYTHON=1) → `_USING_CYTHON = False`
   - Cython unavailable (ImportError) → `_USING_CYTHON = False`, graceful fallback

2. **Contract tests** (real implementations):
   - Same pattern + same candidate → identical match result from both backends
   - Same patterns registered → same candidates returned from both storages
   - Fingerprint values match between Python compute and storage-internal compute

## Why NOT Alternatives

- **Strategy pattern / EngineConfig**: Over-engineered for 2 backends. YAGNI.
- **ABC + Registry**: Heavy. The existing Registrant metaclass is for rules, not engines.
- **Runtime dispatch (Pattern 3)**: Per-call overhead. Module-level gate is zero-cost after import.

## Dependencies

- PR0 (complete): Baseline benchmarks and parity tests
- d81-pqui (fixed): Fingerprint compatible_with() opcode_hash + const_count checks
- d81-dzar (fixed): Fixture searches all real_asts

## Done Criteria (from COPYCAT_D810_PLAN.md)

- [x] Engine is pluggable → gate module with normalized exports
- [x] Fallback-safe → ImportError handling, always falls back to Python
- [ ] Existing test suite passes unchanged → verify after implementation
- [ ] Unit tests cover engine selection matrix → Task 1
- [ ] Contract test: identical match/replacement across variants → Task 2
