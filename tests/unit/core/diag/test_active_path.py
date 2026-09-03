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
    # ``register_diag_path_provider`` mutates the module global directly (the
    # real registration path); routing the mutation itself through
    # ``monkeypatch.setattr`` -- rather than calling the register function
    # and restoring by hand afterward -- is what makes pytest's teardown
    # actually undo it. A hand-rolled try/finally restore here previously
    # leaked this lambda as the process-global provider for every later test.
    calls = []
    monkeypatch.setattr(
        observability,
        "_diag_path_provider",
        lambda: calls.append("path") or "/tmp/current.diag.sqlite3",
    )
    assert observability.get_active_diag_path() == "/tmp/current.diag.sqlite3"
    assert calls == ["path"]


def test_observability_active_func_ea_provider_does_not_request_or_create_a_connection(
    monkeypatch,
):
    calls = []
    monkeypatch.setattr(
        observability,
        "_diag_active_func_ea_provider",
        lambda: calls.append("func_ea") or 0x7FFB0EB06E50,
    )
    assert observability.get_active_diag_func_ea() == 0x7FFB0EB06E50
    assert calls == ["func_ea"]


def test_observability_active_func_ea_defaults_to_none_with_no_provider(monkeypatch):
    monkeypatch.setattr(observability, "_diag_active_func_ea_provider", None)
    assert observability.get_active_diag_func_ea() is None
