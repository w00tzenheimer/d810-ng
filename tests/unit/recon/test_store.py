"""Unit tests for ReconStore provenance persistence tables."""
from __future__ import annotations

import tempfile
from pathlib import Path

from d810.recon.models import DeobfuscationHints
from d810.recon.store import ReconStore


def _make_store() -> ReconStore:
    """Create a temporary in-memory store for testing."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    return ReconStore(tmp.name)


# ---------------------------------------------------------------------------
# Session summary
# ---------------------------------------------------------------------------


def test_save_and_load_session_summary() -> None:
    """save_session_summary persists and load_session_summary retrieves."""
    store = _make_store()
    try:
        store.save_session_summary(
            func_ea=0x401000,
            collectors_fired=3,
            classification="ollvm_flat",
            confidence=0.85,
            recipes=["unflattening_recipe"],
            suppress_rules=["ConstantFolding"],
        )
        result = store.load_session_summary(0x401000)
        assert result is not None
        assert result["func_ea"] == 0x401000
        assert result["collectors_fired"] == 3
        assert result["classification"] == "ollvm_flat"
        assert result["confidence"] == 0.85
        assert result["recipes"] == ["unflattening_recipe"]
        assert result["suppress_rules"] == ["ConstantFolding"]
    finally:
        store.close()


def test_load_session_summary_missing() -> None:
    """load_session_summary returns None for unknown func_ea."""
    store = _make_store()
    try:
        assert store.load_session_summary(0x999) is None
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Consumer outcomes
# ---------------------------------------------------------------------------


def test_save_and_load_consumer_outcomes() -> None:
    """save_consumer_outcome persists and load_consumer_outcomes retrieves."""
    store = _make_store()
    try:
        store.save_consumer_outcome(
            func_ea=0x401000,
            consumer_name="rule_scope",
            artifacts_available=True,
            summary_available=True,
            verdict_applied=False,
            detail="source=analyzed",
            provenance_json="{}",
        )
        store.save_consumer_outcome(
            func_ea=0x401000,
            consumer_name="hodur_planner",
            artifacts_available=True,
            summary_available=False,
            verdict_applied=True,
            detail="",
            provenance_json="",
        )
        outcomes = store.load_consumer_outcomes(0x401000)
        assert len(outcomes) == 2
        # Ordered by consumer_name
        assert outcomes[0]["consumer_name"] == "hodur_planner"
        assert outcomes[0]["artifacts_available"] is True
        assert outcomes[0]["summary_available"] is False
        assert outcomes[0]["verdict_applied"] is True

        assert outcomes[1]["consumer_name"] == "rule_scope"
        assert outcomes[1]["artifacts_available"] is True
        assert outcomes[1]["summary_available"] is True
        assert outcomes[1]["verdict_applied"] is False
        assert outcomes[1]["detail"] == "source=analyzed"
    finally:
        store.close()


def test_load_consumer_outcomes_empty() -> None:
    """load_consumer_outcomes returns empty list for unknown func_ea."""
    store = _make_store()
    try:
        assert store.load_consumer_outcomes(0x999) == []
    finally:
        store.close()


# ---------------------------------------------------------------------------
# User overrides
# ---------------------------------------------------------------------------


def test_save_and_load_user_override() -> None:
    """save_user_override persists and load_user_override retrieves."""
    store = _make_store()
    try:
        store.save_user_override(
            func_ea=0x401000,
            override_type="classification",
            override_value="ollvm_flat",
            confidence=1.0,
        )
        result = store.load_user_override(0x401000)
        assert result is not None
        assert result["override_value"] == "ollvm_flat"
        assert result["confidence"] == 1.0
    finally:
        store.close()


def test_load_user_override_missing() -> None:
    """load_user_override returns None for unknown func_ea."""
    store = _make_store()
    try:
        assert store.load_user_override(0x999) is None
    finally:
        store.close()


def test_user_override_upsert() -> None:
    """save_user_override with same key updates existing record."""
    store = _make_store()
    try:
        store.save_user_override(0x401000, "classification", "mixed", 0.5)
        store.save_user_override(0x401000, "classification", "ollvm_flat", 0.9)
        result = store.load_user_override(0x401000)
        assert result is not None
        assert result["override_value"] == "ollvm_flat"
        assert result["confidence"] == 0.9
    finally:
        store.close()


# ---------------------------------------------------------------------------
# clear_func behaviour
# ---------------------------------------------------------------------------


def test_clear_func_preserves_user_overrides() -> None:
    """clear_func does NOT delete user_overrides rows."""
    store = _make_store()
    try:
        store.save_user_override(0x401000, "classification", "ollvm_flat", 1.0)
        store.save_session_summary(
            func_ea=0x401000,
            collectors_fired=2,
            classification="ollvm_flat",
            confidence=0.8,
            recipes=["unflattening_recipe"],
            suppress_rules=[],
        )
        store.clear_func(func_ea=0x401000)

        # User override persists
        assert store.load_user_override(0x401000) is not None
        # Session summary cleared
        assert store.load_session_summary(0x401000) is None
    finally:
        store.close()


def test_clear_func_clears_session_summary_and_outcomes() -> None:
    """clear_func deletes session summary and consumer outcome rows."""
    store = _make_store()
    try:
        store.save_session_summary(
            func_ea=0x401000,
            collectors_fired=1,
            classification="ollvm_flat",
            confidence=0.7,
            recipes=[],
            suppress_rules=[],
        )
        store.save_consumer_outcome(
            func_ea=0x401000,
            consumer_name="rule_scope",
            artifacts_available=True,
            summary_available=True,
            verdict_applied=True,
        )
        store.clear_func(func_ea=0x401000)

        assert store.load_session_summary(0x401000) is None
        assert store.load_consumer_outcomes(0x401000) == []
    finally:
        store.close()
