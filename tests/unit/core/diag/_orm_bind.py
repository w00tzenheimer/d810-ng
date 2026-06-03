"""Test-side diag ORM binding helper (pytest-injected lifecycle).

Production code binds the diag peewee Models *per operation* --
``diag_models_on(active_diag_db())`` on the write path (snapshot writers,
``event_handlers``) and the ``read_diag_db`` context manager on the CLI read
path -- and never relies on a process-global ``Model`` bind. That hazard source
(Phase B/C "Cannot operate on a closed database") is retired.

Unit tests, however, create an in-memory diag DB in the test body and then call
ORM reader *inner* functions (``load_frontier_diagnostics(conn)``,
``StateCfgEdge.select()`` ...) directly, outside any production bind scope. They
therefore need the Models bound to the DB they just created, for the duration of
the test.

``make_bound_diag_db`` is the pytest-native answer: it creates the DB and binds
the Models to it *immediately* (the bind must exist while the test body runs --
an autouse fixture can't bind a DB that the test only creates later), then the
autouse ``_release_diag_test_binds`` fixture in ``tests/unit/conftest.py``
unwinds every bind at teardown so nothing leaks between tests. ``bind_ctx``
restores the prior binding, so this is re-entrant across several DBs in one test.
"""
from __future__ import annotations

from contextlib import ExitStack

from d810._vendor.peewee import SqliteDatabase
from d810.core.diag import create_diag_database, diag_models_on

# The current test's single bound diag DB (a per-test *singleton*) plus the
# bind context backing it. pytest unit tests run sequentially, so one module
# global pair is sufficient; the autouse ``_release_diag_test_binds`` fixture
# disconnects the DB and restores the prior Model bind at teardown, then resets
# both for the next test.
_bind_stack = ExitStack()
_singleton: SqliteDatabase | None = None


def make_bound_diag_db(path: str = ":memory:") -> SqliteDatabase:
    """Return the test's single bound in-memory diag DB (created on first call).

    Singleton per test: the first call creates the DB and binds the Models to it
    (``diag_models_on`` -- the bind must exist while the test body runs, which an
    autouse setup fixture can't do for a DB the test only creates later);
    repeated calls return that same bound DB rather than opening a new one.
    Drop-in for ``create_diag_database`` in tests that exercise the ORM. The DB
    is disconnected and the bind restored at teardown by the autouse fixture.
    """
    global _singleton
    if _singleton is None:
        _singleton = create_diag_database(path)
        _bind_stack.enter_context(diag_models_on(_singleton))
    return _singleton


def release_diag_test_binds() -> None:
    """Restore the prior bind and disconnect the singleton DB (teardown only)."""
    global _singleton
    _bind_stack.close()
    if _singleton is not None:
        _singleton.close()
        _singleton = None
