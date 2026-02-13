"""Unit tests for non-mutating pattern matching hot-path integration.

These tests verify that the PatternOptimizer correctly switches between
mutating and non-mutating pattern matching based on environment variables.

NOTE: These tests require IDA Pro SDK and are skipped in pure unit test mode.
They verify feature flags and initialization, which requires IDA imports.
"""

import pytest

# Skip all tests in this module if IDA is not available
pytest.importorskip("ida_hexrays", reason="IDA Pro SDK not available")

from d810.optimizers.microcode.instructions.pattern_matching.handler import PatternOptimizer


class TestNomutMatchingHotPath:
    """Test suite for nomut matching hot-path switching."""

    def test_nomut_matching_default_disabled(self, monkeypatch):
        """Verify _use_nomut_matching defaults to False (opt-in)."""
        # Clear any existing env var
        monkeypatch.delenv("D810_NOMUT_MATCHING", raising=False)
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)

        optimizer = PatternOptimizer(
            maturities=[],
            stats=None,
            log_dir=None,
        )

        assert optimizer._use_nomut_matching is False

    def test_nomut_matching_disabled_via_env(self, monkeypatch):
        """Verify D810_NOMUT_MATCHING=0 disables nomut matching."""
        monkeypatch.setenv("D810_NOMUT_MATCHING", "0")
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)

        optimizer = PatternOptimizer(
            maturities=[],
            stats=None,
            log_dir=None,
        )

        assert optimizer._use_nomut_matching is False

    def test_nomut_matching_enabled_via_env(self, monkeypatch):
        """Verify D810_NOMUT_MATCHING=1 enables nomut matching."""
        monkeypatch.setenv("D810_NOMUT_MATCHING", "1")
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)

        optimizer = PatternOptimizer(
            maturities=[],
            stats=None,
            log_dir=None,
        )

        assert optimizer._use_nomut_matching is True

    def test_nomut_matching_requires_indexed_storage(self, monkeypatch):
        """Verify nomut only activates when not using legacy storage."""
        # Enable nomut but force legacy storage
        monkeypatch.setenv("D810_NOMUT_MATCHING", "1")
        monkeypatch.setenv("D810_LEGACY_STORAGE", "1")

        optimizer = PatternOptimizer(
            maturities=[],
            stats=None,
            log_dir=None,
        )

        # Nomut flag is set, but won't be used because legacy storage is active
        assert optimizer._use_nomut_matching is True
        assert optimizer._use_legacy_storage is True
        # In get_optimized_instruction, the condition is:
        # if self._use_nomut_matching and not self._use_legacy_storage:
        # So with legacy storage, the nomut path won't execute

    def test_match_bindings_initialized(self, monkeypatch):
        """Verify _match_bindings is created at init."""
        monkeypatch.delenv("D810_NOMUT_MATCHING", raising=False)
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)

        optimizer = PatternOptimizer(
            maturities=[],
            stats=None,
            log_dir=None,
        )

        assert hasattr(optimizer, "_match_bindings")
        assert optimizer._match_bindings is not None
        # Should be reusable (reset between attempts)
        # Use to_dict() to verify it's empty (count is private in Cython)
        assert len(optimizer._match_bindings.to_dict()) == 0

    def test_legacy_path_active_when_nomut_disabled(self, monkeypatch):
        """Verify legacy path is active when nomut is disabled."""
        monkeypatch.setenv("D810_NOMUT_MATCHING", "0")
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)

        optimizer = PatternOptimizer(
            maturities=[],
            stats=None,
            log_dir=None,
        )

        # Legacy path should be active
        assert optimizer._use_nomut_matching is False
        assert optimizer._use_legacy_storage is False
        # The hot loop will use check_pattern_and_replace instead of nomut

    def test_nomut_path_active_with_indexed_storage(self, monkeypatch):
        """Verify nomut path is active when explicitly enabled with indexed storage."""
        monkeypatch.setenv("D810_NOMUT_MATCHING", "1")
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)

        optimizer = PatternOptimizer(
            maturities=[],
            stats=None,
            log_dir=None,
        )

        # Nomut path should be active
        assert optimizer._use_nomut_matching is True
        assert optimizer._use_legacy_storage is False
        # The hot loop will use _match_nomut + BindingsProxy

    def test_feature_flags_are_independent(self, monkeypatch):
        """D810_NOMUT_MATCHING and D810_LEGACY_STORAGE control different aspects.

        PR4 invariant: The two flags are orthogonal.
        - D810_NOMUT_MATCHING controls whether to use non-mutating match
        - D810_LEGACY_STORAGE controls whether to use legacy pattern storage

        All four combinations are valid, but only some are useful:
        1. nomut=0, legacy=0 (default) -> Indexed storage with clone+match
        2. nomut=1, legacy=0 -> Fast path: nomut + indexed storage (opt-in)
        3. nomut=1, legacy=1 -> Legacy storage ignores nomut (nomut flag set but not used)
        4. nomut=0, legacy=1 -> Legacy path (both optimizations disabled)
        """
        # Test case 1: Default (nomut OFF, indexed storage)
        monkeypatch.delenv("D810_NOMUT_MATCHING", raising=False)
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)
        opt1 = PatternOptimizer(maturities=[], stats=None, log_dir=None)
        assert opt1._use_nomut_matching is False
        assert opt1._use_legacy_storage is False

        # Test case 2: Nomut ON, indexed storage (opt-in fast path)
        monkeypatch.setenv("D810_NOMUT_MATCHING", "1")
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)
        opt2 = PatternOptimizer(maturities=[], stats=None, log_dir=None)
        assert opt2._use_nomut_matching is True
        assert opt2._use_legacy_storage is False

        # Test case 3: Nomut ON, legacy storage (nomut disabled by legacy check)
        monkeypatch.setenv("D810_NOMUT_MATCHING", "1")
        monkeypatch.setenv("D810_LEGACY_STORAGE", "1")
        opt3 = PatternOptimizer(maturities=[], stats=None, log_dir=None)
        assert opt3._use_nomut_matching is True  # Flag set
        assert opt3._use_legacy_storage is True  # But legacy storage takes precedence
        # In get_optimized_instruction: if _use_nomut_matching and not _use_legacy_storage
        # So nomut path won't execute with legacy storage

        # Test case 4: Both disabled (full legacy path)
        monkeypatch.setenv("D810_NOMUT_MATCHING", "0")
        monkeypatch.setenv("D810_LEGACY_STORAGE", "1")
        opt4 = PatternOptimizer(maturities=[], stats=None, log_dir=None)
        assert opt4._use_nomut_matching is False
        assert opt4._use_legacy_storage is True
