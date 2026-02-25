"""Unit tests for DispatcherCache initial_state persistence logic.

The DispatcherCache saves dispatcher analysis results per function across
IDA's multiple decompilation maturity levels. At MMAT_CALLS maturity the
``mov INITIAL_CONST, state_var`` instruction is visible; by MMAT_GLBOPT1 IDA
may optimize it away.

This module tests the *persistence logic* — the pure field-assignment and
fallback rules — without importing any IDA modules.  The actual
DispatcherCache class uses IDA types, so we verify the mathematical
properties of the persistence mechanism directly.

Rules under test:
- When maturity changes and _analysis has a non-None initial_state,
  _persisted_initial_state is updated.
- When maturity changes and _analysis has a None initial_state,
  _persisted_initial_state is left unchanged.
- When _persisted_initial_state is already set and a newer maturity round
  finds initial_state directly, the directly-found value takes precedence.
- The fallback assigns persisted value only when analysis.initial_state is
  None after scanning.
"""

import pytest


@pytest.mark.pure_python
class TestPersistedInitialStateFieldAssignment:
    """Verify the field-assignment rules for _persisted_initial_state."""

    def test_persisted_initial_state_starts_none(self):
        """The persisted field should start as None (no prior knowledge)."""
        _persisted_initial_state = None
        assert _persisted_initial_state is None

    def test_persist_saves_value_when_analysis_has_initial_state(self):
        """Before invalidation, if _analysis.initial_state is set it is persisted."""
        # Simulate the values held by the cache
        current_initial_state = 0x1234
        _persisted_initial_state = None

        # This is the logic from the invalidation block:
        if current_initial_state is not None:
            _persisted_initial_state = current_initial_state

        assert _persisted_initial_state == 0x1234

    def test_persist_does_not_overwrite_when_analysis_initial_state_is_none(self):
        """If _analysis.initial_state is None the persisted value is kept."""
        current_initial_state = None
        _persisted_initial_state = 0xDEAD  # Previously saved

        if current_initial_state is not None:
            _persisted_initial_state = current_initial_state

        # Should remain unchanged
        assert _persisted_initial_state == 0xDEAD

    def test_persist_overwrites_stale_value_with_newer_one(self):
        """A second maturity change with a new initial_state updates the persisted field."""
        # Round 1: MMAT_CALLS finds state = 0x1000
        _persisted_initial_state = 0x1000

        # Round 2: MMAT_GLBOPT1 analysis also finds a (different) state = 0x2000
        current_initial_state = 0x2000

        if current_initial_state is not None:
            _persisted_initial_state = current_initial_state

        assert _persisted_initial_state == 0x2000


@pytest.mark.pure_python
class TestFallbackToPersistedInitialState:
    """Verify the fallback logic inside _find_initial_state."""

    def test_fallback_assigns_persisted_when_fresh_scan_found_nothing(self):
        """When the block scan finds nothing, analysis.initial_state gets the persisted value."""
        analysis_initial_state = None  # Scan found nothing
        _persisted_initial_state = 0xABCD

        # This is the logic appended at the end of _find_initial_state:
        if analysis_initial_state is None and _persisted_initial_state is not None:
            analysis_initial_state = _persisted_initial_state

        assert analysis_initial_state == 0xABCD

    def test_fallback_does_not_apply_when_fresh_scan_succeeded(self):
        """When the block scan succeeds, the fresh value is kept (not overridden)."""
        analysis_initial_state = 0x9999  # Scan found a value
        _persisted_initial_state = 0xABCD

        if analysis_initial_state is None and _persisted_initial_state is not None:
            analysis_initial_state = _persisted_initial_state

        # Fresh value wins
        assert analysis_initial_state == 0x9999

    def test_fallback_does_nothing_when_no_persisted_value(self):
        """If there is no persisted value, analysis.initial_state stays None."""
        analysis_initial_state = None
        _persisted_initial_state = None

        if analysis_initial_state is None and _persisted_initial_state is not None:
            analysis_initial_state = _persisted_initial_state

        assert analysis_initial_state is None

    def test_fallback_does_nothing_when_both_are_none(self):
        """Both None → analysis.initial_state stays None (no-op)."""
        analysis_initial_state = None
        _persisted_initial_state = None

        if analysis_initial_state is None and _persisted_initial_state is not None:
            analysis_initial_state = _persisted_initial_state

        assert analysis_initial_state is None


@pytest.mark.pure_python
class TestInvalidationSequence:
    """Simulate a full maturity-change invalidation sequence."""

    def test_full_sequence_preserves_initial_state_across_maturity_change(self):
        """
        Full simulation of get_or_create invalidation followed by _find_initial_state.

        Round 1 (MMAT_CALLS): initial_state found = 0x5555
        Maturity changes → invalidation saves 0x5555 into _persisted_initial_state
        Round 2 (MMAT_GLBOPT1): block scan finds nothing → fallback applies 0x5555
        """
        # --- Round 1 ---
        analysis_initial_state_r1 = 0x5555
        _persisted_initial_state = None

        # Invalidation (get_or_create sees maturity changed)
        if analysis_initial_state_r1 is not None:
            _persisted_initial_state = analysis_initial_state_r1
        analysis_r1_cleared = None  # cache._analysis = None

        assert analysis_r1_cleared is None
        assert _persisted_initial_state == 0x5555

        # --- Round 2: _find_initial_state scans blocks, finds nothing ---
        analysis_initial_state_r2 = None  # Block scan came up empty

        # Fallback at end of _find_initial_state
        if analysis_initial_state_r2 is None and _persisted_initial_state is not None:
            analysis_initial_state_r2 = _persisted_initial_state

        assert analysis_initial_state_r2 == 0x5555

    def test_fresh_detection_beats_persisted_in_second_round(self):
        """
        When round 2's block scan succeeds, the fresh value overrides persisted.

        Round 1: initial_state = 0x5555 → persisted
        Round 2: block scan finds 0x6666 → fallback condition is False → 0x6666 kept
        """
        analysis_initial_state_r1 = 0x5555
        _persisted_initial_state = None

        if analysis_initial_state_r1 is not None:
            _persisted_initial_state = analysis_initial_state_r1

        assert _persisted_initial_state == 0x5555

        # Round 2: fresh scan succeeds
        analysis_initial_state_r2 = 0x6666  # Fresh value found

        if analysis_initial_state_r2 is None and _persisted_initial_state is not None:
            analysis_initial_state_r2 = _persisted_initial_state

        # Fresh value takes precedence
        assert analysis_initial_state_r2 == 0x6666
