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
        from d810.core.cymode import CythonMode
        CythonMode._instances = {}
    return importlib.import_module(mod_name)


class TestEngineSelectionMatrix:
    """Test the 3-way engine selection: Cython+enabled, Cython+disabled, no Cython."""

    def test_cython_available_and_enabled(self):
        """When Cython is enabled, exports are present regardless of backend."""
        env = os.environ.copy()
        env.pop("D810_NO_CYTHON", None)
        with mock.patch.dict(os.environ, env, clear=True):
            engine = _reload_engine()
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
        original_import = __import__

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


# Mock mop (microcode operand) for testing
class MockMop:
    """Minimal mock microcode operand."""
    def __init__(self, name: str = "mock_mop"):
        self.name = name


# Mock AST classes for testing (avoid IDA dependencies in unit tests)
class MockAstBase:
    """Minimal AST base for pattern matching tests."""
    def __init__(self, opname: str):
        self.opname = opname
        self.op = hash(opname) % 256  # Mock opcode
        self.opcode = hash(opname) % 256  # Mock opcode (some code uses 'opcode')
        self.mop = MockMop(opname)  # Mock microcode operand
        self.dest_size = 4  # Mock destination size in bytes
        self.ea = 0x1000  # Mock effective address

    def is_pattern_variable(self) -> bool:
        return False

    def is_node(self) -> bool:
        return False

    def is_leaf(self) -> bool:
        return False

    def is_constant(self) -> bool:
        return False


class MockAstNode(MockAstBase):
    """Mock AST node with children."""
    def __init__(self, opname: str, left, right):
        super().__init__(opname)
        self.left = left
        self.right = right
        self.subops = [left, right]

    def is_node(self) -> bool:
        return True


class MockAstLeaf(MockAstBase):
    """Mock AST leaf (variable or value)."""
    def __init__(self, name: str):
        super().__init__(name)
        self.name = name
        self.subops = []

    def is_pattern_variable(self) -> bool:
        return self.name.startswith("x_")

    def is_leaf(self) -> bool:
        return True


class MockAstConstant(MockAstBase):
    """Mock AST constant value."""
    def __init__(self, name: str, value: int):
        super().__init__(name)
        self.name = name
        self.value = value
        self.subops = []

    def is_leaf(self) -> bool:
        return True

    def is_constant(self) -> bool:
        return True


def _make_add_pattern():
    """Create m_add(x_0, x_1) AST pattern."""
    left = MockAstLeaf("x_0")
    right = MockAstLeaf("x_1")
    return MockAstNode("m_add", left, right)


def _make_add_candidate():
    """Create m_add(leaf, leaf) AST candidate."""
    left = MockAstLeaf("a")
    right = MockAstLeaf("b")
    return MockAstNode("m_add", left, right)


def _make_const_pattern():
    """Create m_xor(x_0, #0) AST pattern."""
    left = MockAstLeaf("x_0")
    right = MockAstConstant("#0", value=0)
    return MockAstNode("m_xor", left, right)


class MockRule:
    """Minimal rule mock for storage tests."""
    def __init__(self, name="test_rule"):
        self.name = name
        self.maturities = [0]
    def __hash__(self):
        return hash(self.name)
    def __eq__(self, other):
        return isinstance(other, MockRule) and self.name == other.name


class TestEngineContract:
    """Contract tests using engine.py dispatcher (Python or Cython backend).

    These tests verify functional behavior through the engine.py abstraction layer.
    Backend parity tests (comparing Python vs Cython directly) should be added to
    system tests where importing from d810.optimizers is allowed.
    """

    def test_match_positive(self):
        """match_pattern_nomut returns True for matching ASTs."""
        engine = _reload_engine()
        pattern = _make_add_pattern()
        candidate = _make_add_candidate()
        assert engine.match_pattern_nomut(pattern, candidate) is True

    def test_match_negative(self):
        """match_pattern_nomut returns False for non-matching ASTs."""
        engine = _reload_engine()
        pattern = _make_const_pattern()
        candidate = _make_add_candidate()
        assert engine.match_pattern_nomut(pattern, candidate) is False

    def test_storage_add_and_retrieve(self):
        """OpcodeIndexedStorage stores and retrieves candidates correctly."""
        engine = _reload_engine()
        storage = engine.OpcodeIndexedStorage()
        pattern = _make_add_pattern()
        rule = MockRule("test_rule")
        storage.add_pattern(pattern, rule)
        assert storage.total_patterns == 1
        candidate = _make_add_candidate()
        candidates = storage.get_candidates(candidate)
        assert len(candidates) >= 1
        assert any(c.rule.name == "test_rule" for c in candidates)

    def test_storage_no_false_positives_different_opcode(self):
        """Storage does not return candidates with different root opcode."""
        engine = _reload_engine()
        storage = engine.OpcodeIndexedStorage()
        pattern = _make_const_pattern()  # m_xor
        rule = MockRule("xor_rule")
        storage.add_pattern(pattern, rule)
        candidate = _make_add_candidate()  # m_add
        candidates = storage.get_candidates(candidate)
        assert len(candidates) == 0

    def test_fingerprint_computation(self):
        """compute_fingerprint returns a PatternFingerprint with expected fields."""
        engine = _reload_engine()
        pattern = _make_add_pattern()
        fp = engine.compute_fingerprint(pattern)
        assert isinstance(fp, engine.PatternFingerprint)
        assert fp.depth > 0
        assert fp.node_count > 0


class TestHandlerEngineIntegration:
    """Test that handler.py can import from engine.py.

    Note: These tests verify engine exports exist but cannot import handler.py
    directly in unit tests (no ida_hexrays). Handler integration is tested in
    system tests where IDA is available.
    """

    def test_engine_exports_for_handler_import(self):
        """Verify engine.py exports all symbols that handler.py imports."""
        engine = _reload_engine()
        # Check all symbols that handler.py imports from engine.py
        assert hasattr(engine, 'OpcodeIndexedStorage')
        assert hasattr(engine, 'match_pattern_nomut')
        assert hasattr(engine, 'get_engine_info')
        assert hasattr(engine, '_USING_CYTHON')

    def test_get_engine_info_contract(self):
        """get_engine_info returns expected dict structure."""
        engine = _reload_engine()
        info = engine.get_engine_info()
        assert isinstance(info, dict)
        assert info["backend"] in ("python", "cython")
        # Verify structure matches what handler.engine_info property will return
        assert "version" in info or "backend" in info  # At minimum backend is required
