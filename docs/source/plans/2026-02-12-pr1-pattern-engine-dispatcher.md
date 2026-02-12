# PR1: Pattern Engine Dispatcher — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a dispatcher module that gates between Python and Cython pattern matching backends, following the existing CythonMode Pattern 1.

**Architecture:** Single gate module (`engine.py`) with module-level imports, normalized exports, and a diagnostics API. Light-touch handler.py integration adds optional A/B validation storage alongside legacy PatternStorage.

**Tech Stack:** Python, pytest, unittest.mock (for import gating tests)

---

### Task 1: Create engine.py dispatcher module

**Files:**
- Create: `src/d810/optimizers/microcode/instructions/pattern_matching/engine.py`

**Step 1: Write the failing test**

Create `tests/unit/test_pattern_engine_dispatcher.py`:

```python
"""Unit tests for pattern engine dispatcher (engine.py).

Tests the engine selection matrix:
- Cython available + enabled -> _USING_CYTHON = True
- Cython available + disabled (D810_NO_CYTHON=1) -> _USING_CYTHON = False
- Cython unavailable (ImportError) -> _USING_CYTHON = False
"""
import importlib
import os
import sys
from unittest import mock

import pytest


def _reload_engine():
    """Force-reload engine.py to re-execute module-level gate logic."""
    mod_name = "d810.optimizers.microcode.instructions.pattern_matching.engine"
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    # Also clear cached CythonMode singleton state
    cymode_mod = "d810.core.cymode"
    if cymode_mod in sys.modules:
        # Reset the singleton so it re-reads env vars
        from d810.core.cymode import CythonMode
        CythonMode._instances = {}
    return importlib.import_module(mod_name)


class TestEngineSelectionMatrix:
    """Test the 3-way engine selection: Cython+enabled, Cython+disabled, no Cython."""

    def test_cython_available_and_enabled(self):
        """When Cython module exists and CythonMode is enabled, use Cython backend."""
        env = os.environ.copy()
        env.pop("D810_NO_CYTHON", None)
        with mock.patch.dict(os.environ, env, clear=True):
            engine = _reload_engine()
            # If Cython is actually installed, it should be True
            # If not installed, it should gracefully fall back to False
            assert hasattr(engine, "_USING_CYTHON")
            assert hasattr(engine, "OpcodeIndexedStorage")
            assert hasattr(engine, "match_pattern_nomut")
            assert hasattr(engine, "MatchBindings")
            assert hasattr(engine, "compute_fingerprint")
            assert hasattr(engine, "PatternFingerprint")
            assert hasattr(engine, "RulePatternEntry")
            assert hasattr(engine, "get_engine_info")

    def test_cython_disabled_via_env(self):
        """When D810_NO_CYTHON=1, always use Python backend."""
        with mock.patch.dict(os.environ, {"D810_NO_CYTHON": "1"}):
            engine = _reload_engine()
            assert engine._USING_CYTHON is False
            info = engine.get_engine_info()
            assert info["backend"] == "python"

    def test_cython_unavailable_fallback(self):
        """When Cython import fails, gracefully fall back to Python."""
        # Mock the Cython import to raise ImportError
        original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__

        def mock_import(name, *args, **kwargs):
            if "c_pattern_match" in name:
                raise ImportError(f"No module named '{name}'")
            return original_import(name, *args, **kwargs)

        env = os.environ.copy()
        env.pop("D810_NO_CYTHON", None)
        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch("builtins.__import__", side_effect=mock_import):
                engine = _reload_engine()
                assert engine._USING_CYTHON is False
                info = engine.get_engine_info()
                assert info["backend"] == "python"


class TestEngineExports:
    """Verify all expected symbols are exported with correct types."""

    def test_get_engine_info_returns_dict(self):
        engine = _reload_engine()
        info = engine.get_engine_info()
        assert isinstance(info, dict)
        assert "backend" in info
        assert info["backend"] in ("python", "cython")

    def test_exported_classes_are_callable(self):
        engine = _reload_engine()
        # OpcodeIndexedStorage should be instantiable
        storage = engine.OpcodeIndexedStorage()
        assert hasattr(storage, "add_pattern")
        assert hasattr(storage, "get_candidates")
        assert hasattr(storage, "total_patterns")

    def test_match_pattern_nomut_is_callable(self):
        engine = _reload_engine()
        assert callable(engine.match_pattern_nomut)

    def test_compute_fingerprint_is_callable(self):
        engine = _reload_engine()
        assert callable(engine.compute_fingerprint)
```

**Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src pytest tests/unit/test_pattern_engine_dispatcher.py -v --tb=short`
Expected: FAIL — `ModuleNotFoundError: No module named 'd810.optimizers.microcode.instructions.pattern_matching.engine'`

**Step 3: Write minimal implementation**

Create `src/d810/optimizers/microcode/instructions/pattern_matching/engine.py`:

```python
"""Pattern engine dispatcher — gates between Cython and Python backends.

Follows CythonMode Pattern 1 (module-level gate) established in ast.py.
Exports normalized names so consumers don't care which backend is active.

Environment variables:
    D810_NO_CYTHON=1  — Force Python backend even if Cython is available.

Usage:
    from d810.optimizers.microcode.instructions.pattern_matching.engine import (
        OpcodeIndexedStorage,
        match_pattern_nomut,
        MatchBindings,
        compute_fingerprint,
        PatternFingerprint,
        RulePatternEntry,
    )
"""
from __future__ import annotations

import logging

from d810.core.cymode import CythonMode

logger = logging.getLogger(__name__)

# Always import Python data containers (no perf benefit from Cython for these)
from d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups import (
    PatternFingerprint,
    RulePatternEntry,
    compute_fingerprint,
)

# Gate Cython vs Python for performance-critical implementations
if CythonMode().is_enabled():
    try:
        from d810.speedups.optimizers.c_pattern_match import (
            COpcodeIndexedStorage as OpcodeIndexedStorage,
            match_pattern_nomut,
            CMatchBindings as MatchBindings,
        )
        _USING_CYTHON = True
        logger.debug("Pattern engine: using Cython backend")
    except (ModuleNotFoundError, ImportError):
        from d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups import (
            OpcodeIndexedStorage,
            match_pattern_nomut,
            MatchBindings,
        )
        _USING_CYTHON = False
        logger.debug("Pattern engine: Cython unavailable, using Python backend")
else:
    from d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups import (
        OpcodeIndexedStorage,
        match_pattern_nomut,
        MatchBindings,
    )
    _USING_CYTHON = False
    logger.debug("Pattern engine: CythonMode disabled, using Python backend")


def get_engine_info() -> dict:
    """Return diagnostic info about the active pattern engine backend."""
    return {
        "backend": "cython" if _USING_CYTHON else "python",
        "cython_mode_enabled": CythonMode().is_enabled(),
        "storage_class": OpcodeIndexedStorage.__qualname__,
        "match_function": match_pattern_nomut.__module__,
    }


__all__ = [
    "OpcodeIndexedStorage",
    "match_pattern_nomut",
    "MatchBindings",
    "compute_fingerprint",
    "PatternFingerprint",
    "RulePatternEntry",
    "_USING_CYTHON",
    "get_engine_info",
]
```

**Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src pytest tests/unit/test_pattern_engine_dispatcher.py -v --tb=short`
Expected: All tests PASS

**Step 5: Run full unit suite for regressions**

Run: `PYTHONPATH=src pytest tests/unit/ -v --tb=short`
Expected: 766+ tests PASS

**Step 6: Commit**

```bash
git add src/d810/optimizers/microcode/instructions/pattern_matching/engine.py tests/unit/test_pattern_engine_dispatcher.py
git commit -m "feat(engine): add pattern engine dispatcher with CythonMode gate

Introduces engine.py following Pattern 1 from ast.py. Gates between
Cython (c_pattern_match) and Python (pattern_speedups) backends at
import time. Exports normalized names: OpcodeIndexedStorage,
match_pattern_nomut, MatchBindings, compute_fingerprint.

Tests cover 3-way engine selection matrix and export verification."
```

---

### Task 2: Add contract tests for backend parity

**Files:**
- Modify: `tests/unit/test_pattern_engine_dispatcher.py`

**Step 1: Write the contract tests**

Append to `tests/unit/test_pattern_engine_dispatcher.py`:

```python
from d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups import (
    OpcodeIndexedStorage as PyOpcodeIndexedStorage,
    match_pattern_nomut as py_match_pattern_nomut,
    MatchBindings as PyMatchBindings,
    compute_fingerprint as py_compute_fingerprint,
    PatternFingerprint,
    RulePatternEntry,
)
from d810.expr.p_ast import AstNode, AstLeaf, AstConstant

# Try importing Cython for contract tests (skip if unavailable)
try:
    from d810.speedups.optimizers.c_pattern_match import (
        COpcodeIndexedStorage as CyOpcodeIndexedStorage,
        match_pattern_nomut as cy_match_pattern_nomut,
        CMatchBindings as CyMatchBindings,
        compute_fingerprint_py as cy_compute_fingerprint,
    )
    HAS_CYTHON = True
except ImportError:
    HAS_CYTHON = False


def _make_add_pattern():
    """Create m_add(x_0, x_1) AST pattern."""
    left = AstLeaf("x_0")
    right = AstLeaf("x_1")
    return AstNode("m_add", left, right)


def _make_add_candidate():
    """Create m_add(leaf, leaf) AST candidate."""
    left = AstLeaf("a")
    right = AstLeaf("b")
    return AstNode("m_add", left, right)


def _make_const_pattern():
    """Create m_xor(x_0, #0) AST pattern."""
    left = AstLeaf("x_0")
    right = AstConstant("#0", value=0)
    return AstNode("m_xor", left, right)


class MockRule:
    """Minimal rule mock for storage tests."""
    def __init__(self, name="test_rule"):
        self.name = name
        self.maturities = [0]
    def __hash__(self):
        return hash(self.name)
    def __eq__(self, other):
        return isinstance(other, MockRule) and self.name == other.name


@pytest.mark.skipif(not HAS_CYTHON, reason="Cython c_pattern_match not available")
class TestBackendParityContract:
    """Contract: identical results from Python and Cython backends."""

    def test_match_same_result(self):
        """Both backends return same bool for same pattern+candidate."""
        pattern = _make_add_pattern()
        candidate = _make_add_candidate()

        py_result = py_match_pattern_nomut(pattern, candidate)
        cy_result = cy_match_pattern_nomut(pattern, candidate)
        assert py_result == cy_result, f"Match mismatch: py={py_result}, cy={cy_result}"

    def test_match_negative_same_result(self):
        """Both backends reject non-matching pattern+candidate identically."""
        pattern = _make_const_pattern()
        candidate = _make_add_candidate()

        py_result = py_match_pattern_nomut(pattern, candidate)
        cy_result = cy_match_pattern_nomut(pattern, candidate)
        assert py_result == cy_result

    def test_storage_same_candidates(self):
        """Both storages return same candidate set for same queries."""
        py_storage = PyOpcodeIndexedStorage()
        cy_storage = CyOpcodeIndexedStorage()

        patterns = [
            (_make_add_pattern(), MockRule("add_rule")),
            (_make_const_pattern(), MockRule("const_rule")),
        ]

        for pat, rule in patterns:
            py_storage.add_pattern(pat, rule)
            cy_storage.add_pattern(pat, rule)

        candidate = _make_add_candidate()
        py_candidates = py_storage.get_candidates(candidate)
        cy_candidates = cy_storage.get_candidates(candidate)

        py_rules = {c.rule.name for c in py_candidates}
        cy_rules = {c.rule.name for c in cy_candidates}
        assert py_rules == cy_rules, f"Candidate mismatch: py={py_rules}, cy={cy_rules}"

    def test_bindings_same_result(self):
        """Both backends produce same binding dict for same match."""
        pattern = _make_add_pattern()
        candidate = _make_add_candidate()

        py_bindings = PyMatchBindings()
        cy_bindings = CyMatchBindings()

        py_match_pattern_nomut(pattern, candidate, py_bindings)
        cy_match_pattern_nomut(pattern, candidate, cy_bindings)

        py_dict = py_bindings.to_dict()
        cy_dict = cy_bindings.to_dict()
        # Compare keys (binding names)
        assert set(py_dict.keys()) == set(cy_dict.keys()), \
            f"Binding keys differ: py={set(py_dict.keys())}, cy={set(cy_dict.keys())}"
```

**Step 2: Run tests**

Run: `PYTHONPATH=src pytest tests/unit/test_pattern_engine_dispatcher.py -v --tb=short`
Expected: Selection matrix tests PASS, contract tests PASS or SKIP (if no Cython)

**Step 3: Commit**

```bash
git add tests/unit/test_pattern_engine_dispatcher.py
git commit -m "test(engine): add backend parity contract tests

Contract tests verify identical results from Python and Cython backends:
match results, storage candidates, and binding dictionaries.
Skipped gracefully when Cython is unavailable."
```

---

### Task 3: Light-touch handler.py wiring

**Files:**
- Modify: `src/d810/optimizers/microcode/instructions/pattern_matching/handler.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_pattern_engine_dispatcher.py`:

```python
class TestHandlerEngineIntegration:
    """Test that handler.py can import from engine.py."""

    def test_handler_imports_engine(self):
        """PatternOptimizer should expose engine info."""
        from d810.optimizers.microcode.instructions.pattern_matching.engine import (
            get_engine_info,
            _USING_CYTHON,
        )
        info = get_engine_info()
        assert isinstance(info, dict)
        assert info["backend"] in ("python", "cython")
```

**Step 2: Add engine import to handler.py**

At the top of handler.py imports section, add:

```python
# Pattern engine dispatcher (PR1) — normalized Cython/Python gate
from d810.optimizers.microcode.instructions.pattern_matching.engine import (
    OpcodeIndexedStorage as _IndexedStorage,
    match_pattern_nomut as _match_nomut,
    get_engine_info,
    _USING_CYTHON as _ENGINE_CYTHON,
)
```

Add `engine_info` property to `PatternOptimizer`:

```python
@property
def engine_info(self) -> dict:
    """Return diagnostic info about the active pattern engine."""
    return get_engine_info()
```

**Step 3: Run tests**

Run: `PYTHONPATH=src pytest tests/unit/ -v --tb=short`
Expected: All tests PASS, no regressions

**Step 4: Run import linter**

Run: `lint-imports`
Expected: All 4 contracts PASS

**Step 5: Commit**

```bash
git add src/d810/optimizers/microcode/instructions/pattern_matching/handler.py tests/unit/test_pattern_engine_dispatcher.py
git commit -m "feat(handler): wire engine.py imports into PatternOptimizer

Light-touch PR1 integration: handler.py imports from engine.py dispatcher.
Adds engine_info property for diagnostics. No hot-path changes yet (PR2)."
```

---

### Task 4: Run full verification

**Step 1: Run all unit tests**

Run: `PYTHONPATH=src pytest tests/unit/ -v --tb=short`
Expected: 770+ tests PASS (766 existing + new dispatcher tests)

**Step 2: Run import linter**

Run: `lint-imports`
Expected: All 4 contracts PASS

**Step 3: Verify no new imports violate layer boundaries**

The engine.py module imports from:
- `d810.core.cymode` (core layer — allowed)
- `d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups` (same package — allowed)
- `d810.speedups.optimizers.c_pattern_match` (speedups layer — allowed)

This should not violate any import-linter contract.
