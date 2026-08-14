"""Bounded, capture-safe storage for MBA provider outcomes."""

from __future__ import annotations

import pytest

from d810.mba.provider_history import (
    DEFAULT_PROVIDER_OUTCOME_HISTORY_CAPACITY,
    ProviderOutcomeHistory,
    ProviderOutcomeHistoryTruncated,
)


def test_history_is_bounded_and_rejects_a_truncated_capture_cursor() -> None:
    """A long-lived provider cannot retain every interactive attempt forever."""

    history = ProviderOutcomeHistory[str](capacity=2)
    history.append("before")
    cursor = history.cursor
    history.append("first")
    history.append("second")
    history.append("third")

    assert history.outcomes() == ("second", "third")
    with pytest.raises(ProviderOutcomeHistoryTruncated):
        history.since(cursor)


def test_history_replaces_the_current_attempt_without_consuming_capacity() -> None:
    """Mutation finalization updates one outcome rather than creating a duplicate."""

    history = ProviderOutcomeHistory[str](capacity=2)
    sequence = history.append("improved")
    history.replace(sequence, "applied")

    assert history.outcomes() == ("applied",)


def test_default_capture_window_holds_one_dense_native_function() -> None:
    """Capture storage stays bounded but exceeds the observed 64 callbacks."""

    assert DEFAULT_PROVIDER_OUTCOME_HISTORY_CAPACITY >= 128
