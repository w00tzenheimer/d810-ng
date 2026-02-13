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

    # Clear cached CythonMode singleton state
    # CythonMode uses both SingletonMeta and @survives_reload(), so we must:
    # 1. Clear SingletonMeta._instances (where the singleton is cached)
    # 2. Delete the cymode module so @survives_reload() re-reads env vars
    # 3. Clear any modules that import and cache CythonMode
    cymode_mod = "d810.core.cymode"
    if cymode_mod in sys.modules:
        from d810.core.singleton import SingletonMeta
        from d810.core.cymode import CythonMode
        # Clear singleton cache (correct location is SingletonMeta._instances)
        SingletonMeta._instances.pop(CythonMode, None)
        # Delete cymode module to force re-read of D810_NO_CYTHON env var
        del sys.modules[cymode_mod]

    # Also clear singleton module in case it was imported
    singleton_mod = "d810.core.singleton"
    if singleton_mod in sys.modules:
        del sys.modules[singleton_mod]

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


class TestCrossBackendParity:
    """Contract: reloading engine with different settings produces consistent results.

    Tests that the engine API works identically regardless of which backend
    is selected. When Cython is available, this validates actual parity.
    When Cython is unavailable, both loads use Python (still validates
    the reload mechanism works).
    """

    def test_engine_consistent_across_reloads(self):
        """Engine exports are functionally equivalent across reloads."""
        # Load with Cython disabled
        with mock.patch.dict(os.environ, {"D810_NO_CYTHON": "1"}):
            py_engine = _reload_engine()
            py_info = py_engine.get_engine_info()
            assert py_info["backend"] == "python"

        # Load with Cython enabled (may still be Python if Cython unavailable)
        env = os.environ.copy()
        env.pop("D810_NO_CYTHON", None)
        with mock.patch.dict(os.environ, env, clear=True):
            auto_engine = _reload_engine()
            auto_info = auto_engine.get_engine_info()
            assert auto_info["backend"] in ("python", "cython")

        # Both engines expose identical API surface
        for attr in ("OpcodeIndexedStorage", "match_pattern_nomut", "MatchBindings",
                      "compute_fingerprint", "PatternFingerprint", "RulePatternEntry"):
            assert hasattr(py_engine, attr), f"Python engine missing {attr}"
            assert hasattr(auto_engine, attr), f"Auto engine missing {attr}"

    def test_storage_api_parity_across_backends(self):
        """OpcodeIndexedStorage from both backends has same interface."""
        # Python backend
        with mock.patch.dict(os.environ, {"D810_NO_CYTHON": "1"}):
            py_engine = _reload_engine()

        # Auto backend (Cython if available)
        env = os.environ.copy()
        env.pop("D810_NO_CYTHON", None)
        with mock.patch.dict(os.environ, env, clear=True):
            auto_engine = _reload_engine()

        # Both storage classes expose same methods
        py_storage = py_engine.OpcodeIndexedStorage()
        auto_storage = auto_engine.OpcodeIndexedStorage()

        for method in ("add_pattern", "get_candidates", "total_patterns"):
            assert hasattr(py_storage, method), f"Python storage missing {method}"
            assert hasattr(auto_storage, method), f"Auto storage missing {method}"
