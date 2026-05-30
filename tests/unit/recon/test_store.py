"""Unit tests for ReconStore provenance persistence tables."""
from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

from d810.analyses.control_flow.models import DeobfuscationHints
from d810.passes.store import ReconStore


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
            inferences=["unflattening"],
            suppress_rules=["ConstantFolding"],
        )
        result = store.load_session_summary(0x401000)
        assert result is not None
        assert result["func_ea"] == 0x401000
        assert result["collectors_fired"] == 3
        assert result["classification"] == "ollvm_flat"
        assert result["confidence"] == 0.85
        assert result["inferences"] == ["unflattening"]
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
            inferences=["unflattening"],
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
            inferences=[],
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


# ---------------------------------------------------------------------------
# Aggregate queries
# ---------------------------------------------------------------------------


def test_count_functions_with_hints() -> None:
    store = _make_store()
    try:
        assert store.count_functions_with_hints() == 0
        store.save_hints(DeobfuscationHints(
            func_ea=0x1000, obfuscation_type="flattening", confidence=0.9,
            recommended_inferences=("unflattening",), candidates=(), suppress_rules=(),
        ))
        assert store.count_functions_with_hints() == 1
        store.save_hints(DeobfuscationHints(
            func_ea=0x2000, obfuscation_type="", confidence=0.1,
            recommended_inferences=(), candidates=(), suppress_rules=(),
        ))
        assert store.count_functions_with_hints() == 2
    finally:
        store.close()


def test_count_functions_with_session_summaries() -> None:
    store = _make_store()
    try:
        assert store.count_functions_with_session_summaries() == 0
        store.save_session_summary(
            func_ea=0x1000, collectors_fired=3,
            classification="flattening", confidence=0.8,
            inferences=["unflattening"], suppress_rules=[],
        )
        assert store.count_functions_with_session_summaries() == 1
    finally:
        store.close()


def test_count_functions_with_consumer_outcomes() -> None:
    store = _make_store()
    try:
        assert store.count_functions_with_consumer_outcomes() == 0
        store.save_consumer_outcome(
            func_ea=0x1000, consumer_name="rule_scope",
            artifacts_available=True, summary_available=True,
            verdict_applied=True,
        )
        assert store.count_functions_with_consumer_outcomes() == 1
    finally:
        store.close()


def test_list_functions_with_hints() -> None:
    store = _make_store()
    try:
        store.save_hints(DeobfuscationHints(
            func_ea=0x2000, obfuscation_type="", confidence=0.1,
            recommended_inferences=(), candidates=(), suppress_rules=(),
        ))
        store.save_hints(DeobfuscationHints(
            func_ea=0x1000, obfuscation_type="flattening", confidence=0.9,
            recommended_inferences=("unflattening",), candidates=(), suppress_rules=(),
        ))
        assert store.list_functions_with_hints() == [0x1000, 0x2000]
    finally:
        store.close()


def test_list_functions_missing_session_summary() -> None:
    store = _make_store()
    try:
        store.save_hints(DeobfuscationHints(
            func_ea=0x1000, obfuscation_type="flattening", confidence=0.9,
            recommended_inferences=("unflattening",), candidates=(), suppress_rules=(),
        ))
        # No session summary yet — should appear in the gap list
        assert store.list_functions_missing_session_summary() == [0x1000]

        # Add session summary — gap should close
        store.save_session_summary(
            func_ea=0x1000, collectors_fired=3,
            classification="flattening", confidence=0.9,
            inferences=["unflattening"], suppress_rules=[],
        )
        assert store.list_functions_missing_session_summary() == []
    finally:
        store.close()


def test_load_all_session_summaries() -> None:
    store = _make_store()
    try:
        store.save_session_summary(
            func_ea=0x1000, collectors_fired=3,
            classification="flattening", confidence=0.8,
            inferences=["unflattening"], suppress_rules=[],
        )
        store.save_session_summary(
            func_ea=0x2000, collectors_fired=2,
            classification="", confidence=0.1,
            inferences=[], suppress_rules=[],
        )
        summaries = store.load_all_session_summaries()
        assert len(summaries) == 2
        eas = {s["func_ea"] for s in summaries}
        assert eas == {0x1000, 0x2000}
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Schema migration (backward compatibility with pre-recon-lifecycle DBs)
# ---------------------------------------------------------------------------


def _create_legacy_db(path: str) -> None:
    """Create a DB with old schema missing recommended_inferences_json."""
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS recon_results (
            func_ea         INTEGER NOT NULL,
            maturity        INTEGER NOT NULL,
            collector_name  TEXT    NOT NULL,
            timestamp       REAL    NOT NULL,
            metrics_json    TEXT    NOT NULL,
            candidates_json TEXT    NOT NULL,
            PRIMARY KEY (func_ea, maturity, collector_name)
        );
        CREATE TABLE IF NOT EXISTS deobfuscation_hints (
            func_ea              INTEGER PRIMARY KEY,
            obfuscation_type     TEXT,
            confidence           REAL    NOT NULL,
            candidates_json      TEXT    NOT NULL,
            suppress_rules_json  TEXT    NOT NULL,
            updated_at           REAL    NOT NULL
        );
    """)
    conn.commit()
    conn.close()


def test_migration_adds_recommended_inferences_column() -> None:
    """Opening a store with legacy DB auto-adds recommended_inferences_json."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    _create_legacy_db(tmp.name)

    # Verify old schema lacks the column
    conn = sqlite3.connect(tmp.name)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(deobfuscation_hints)")}
    assert "recommended_inferences_json" not in cols
    conn.close()

    # Opening ReconStore should migrate
    store = ReconStore(tmp.name)
    try:
        # Verify column now exists
        cols = {
            r[1]
            for r in store._conn.execute(
                "PRAGMA table_info(deobfuscation_hints)"
            )
        }
        assert "recommended_inferences_json" in cols

        # save_hints and load_hints should work on the migrated DB
        store.save_hints(DeobfuscationHints(
            func_ea=0x1000,
            obfuscation_type="flattening",
            confidence=0.9,
            recommended_inferences=("unflattening",),
            candidates=(),
            suppress_rules=(),
        ))
        loaded = store.load_hints(func_ea=0x1000)
        assert loaded is not None
        assert loaded.recommended_inferences == ("unflattening",)
    finally:
        store.close()


def test_migration_idempotent_on_fresh_db() -> None:
    """Migration is a no-op on a fresh DB (column already exists)."""
    store = _make_store()
    try:
        cols = {
            r[1]
            for r in store._conn.execute(
                "PRAGMA table_info(deobfuscation_hints)"
            )
        }
        assert "recommended_inferences_json" in cols

        # Full round-trip works
        store.save_hints(DeobfuscationHints(
            func_ea=0x2000,
            obfuscation_type="",
            confidence=0.5,
            recommended_inferences=(),
            candidates=(),
            suppress_rules=(),
        ))
        loaded = store.load_hints(func_ea=0x2000)
        assert loaded is not None
        assert loaded.recommended_inferences == ()
    finally:
        store.close()
