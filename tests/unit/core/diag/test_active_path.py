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


def test_active_diag_func_ea_reports_the_session_opening_func_ea(monkeypatch):
    monkeypatch.setattr(diag, "_current_func_ea", None)
    assert diag.get_active_diag_func_ea() is None

    monkeypatch.setattr(diag, "_current_func_ea", 0x7FFB0EB06E50)
    assert diag.get_active_diag_func_ea() == 0x7FFB0EB06E50


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


def test_observability_active_func_ea_provider_does_not_request_or_create_a_connection(
    monkeypatch,
):
    calls = []
    old_provider = observability._diag_active_func_ea_provider
    try:
        observability.register_diag_active_func_ea_provider(
            lambda: calls.append("func_ea") or 0x7FFB0EB06E50
        )
        assert observability.get_active_diag_func_ea() == 0x7FFB0EB06E50
        assert calls == ["func_ea"]
    finally:
        monkeypatch.setattr(
            observability, "_diag_active_func_ea_provider", old_provider
        )


def test_observability_active_func_ea_defaults_to_none_with_no_provider(monkeypatch):
    monkeypatch.setattr(observability, "_diag_active_func_ea_provider", None)
    assert observability.get_active_diag_func_ea() is None
