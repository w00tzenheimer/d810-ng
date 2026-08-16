"""Behavioral tests for persisted developer runtime setting precedence."""

from __future__ import annotations

import json

import pytest

from d810.core.config import D810Configuration
from d810.core.settings import (
    apply_saved_runtime_settings,
    get_settings,
    reset_settings,
)


@pytest.fixture(autouse=True)
def _reset_runtime_settings(monkeypatch):
    yield
    monkeypatch.undo()
    reset_settings()


def _options(tmp_path, options: dict[str, object]) -> D810Configuration:
    path = tmp_path / "options.json"
    path.write_text(json.dumps(options), encoding="utf-8")
    return D810Configuration(path)


def test_saved_native_perf_preference_applies_without_environment_override(
    monkeypatch, tmp_path
):
    """Catches a production break where state reset omits native_perf."""
    monkeypatch.delenv("D810_NATIVE_PERF", raising=False)
    reset_settings()
    config = _options(tmp_path, {"native_perf": True})

    apply_saved_runtime_settings(config)

    assert get_settings().native_perf is True


def test_saved_nomut_matching_preference_applies_without_environment_override(
    monkeypatch, tmp_path
):
    """Catches a production break where state reset omits nomut_matching."""
    monkeypatch.delenv("D810_NOMUT_MATCHING", raising=False)
    reset_settings()
    config = _options(tmp_path, {"nomut_matching": True})

    apply_saved_runtime_settings(config)

    assert get_settings().nomut_matching is True


def test_native_perf_environment_override_wins_over_saved_preference(
    monkeypatch, tmp_path
):
    """Catches a production break that lets saved native_perf override env."""
    monkeypatch.setenv("D810_NATIVE_PERF", "1")
    reset_settings()
    config = _options(tmp_path, {"native_perf": False})

    apply_saved_runtime_settings(config)

    assert get_settings().native_perf is True


def test_nomut_matching_environment_override_wins_over_saved_preference(
    monkeypatch, tmp_path
):
    """Catches a production break that lets saved nomut_matching override env."""
    monkeypatch.setenv("D810_NOMUT_MATCHING", "1")
    reset_settings()
    config = _options(tmp_path, {"nomut_matching": False})

    apply_saved_runtime_settings(config)

    assert get_settings().nomut_matching is True
