from __future__ import annotations

from types import SimpleNamespace

from d810.core import observability
from d810.core import diag


def test_active_diag_path_reports_only_the_current_capture_database(monkeypatch):
    monkeypatch.setattr(diag, "_current_db", None)
    assert diag.get_active_diag_path() is None

    monkeypatch.setattr(
        diag,
        "_current_db",
        SimpleNamespace(database="/tmp/current.diag.sqlite3"),
    )
    assert diag.get_active_diag_path() == "/tmp/current.diag.sqlite3"


def test_observability_path_provider_does_not_request_or_create_a_connection(monkeypatch):
    calls = []
    old_provider = observability._diag_path_provider
    try:
        observability.register_diag_path_provider(
            lambda: calls.append("path") or "/tmp/current.diag.sqlite3"
        )
        assert observability.get_active_diag_path() == "/tmp/current.diag.sqlite3"
        assert calls == ["path"]
    finally:
        monkeypatch.setattr(observability, "_diag_path_provider", old_provider)
