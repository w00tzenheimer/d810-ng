"""Tests for d810.core.settings — centralized runtime settings."""
from __future__ import annotations

import pytest

from d810.core.settings import (
    D810Settings,
    configure_settings,
    get_settings,
    reset_settings,
)


@pytest.fixture(autouse=True)
def _reset_settings_after_test():
    """Ensure every test starts with a fresh singleton."""
    yield
    reset_settings()


class TestD810Settings:
    def test_defaults(self):
        s = D810Settings()
        assert s.diag_snapshots is False
        assert s.debug_logging is False
        assert s.verify_capture is True
        assert s.capture_post_maturity is None
        assert s.capture_post_file == "/tmp/d810_capture.txt"

    def test_from_env_reads_diag_snapshot(self, monkeypatch):
        monkeypatch.setenv("D810_DIAG_SNAPSHOT", "1")
        reset_settings()
        assert get_settings().diag_snapshots is True

    def test_from_env_reads_debug_logging(self, monkeypatch):
        monkeypatch.setenv("D810_DEBUG_LOGGING", "yes")
        reset_settings()
        assert get_settings().debug_logging is True

    def test_from_env_reads_verify_capture_off(self, monkeypatch):
        monkeypatch.setenv("D810_VERIFY_CAPTURE", "0")
        reset_settings()
        assert get_settings().verify_capture is False

    def test_from_env_reads_capture_post_maturity(self, monkeypatch):
        monkeypatch.setenv("D810_CAPTURE_POST_MATURITY", "7")
        reset_settings()
        assert get_settings().capture_post_maturity == 7

    def test_from_env_invalid_maturity_returns_none(self, monkeypatch):
        monkeypatch.setenv("D810_CAPTURE_POST_MATURITY", "not_a_number")
        reset_settings()
        assert get_settings().capture_post_maturity is None

    def test_configure_settings_overrides(self):
        configure_settings(diag_snapshots=True, capture_post_maturity=5)
        s = get_settings()
        assert s.diag_snapshots is True
        assert s.capture_post_maturity == 5

    def test_configure_settings_rejects_unknown_field(self):
        with pytest.raises(ValueError, match="Unknown D810Settings field"):
            configure_settings(nonexistent_field=True)

    def test_reset_clears_overrides(self, monkeypatch):
        configure_settings(diag_snapshots=True)
        assert get_settings().diag_snapshots is True
        # After reset (no env var), should be False again
        monkeypatch.delenv("D810_DIAG_SNAPSHOT", raising=False)
        reset_settings()
        assert get_settings().diag_snapshots is False

    def test_singleton_identity(self):
        a = get_settings()
        b = get_settings()
        assert a is b
