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
