"""MBA diagnostic snapshot infrastructure.

Queryable SQLite snapshots for block chain tracing, variable provenance,
and DAG correlation without grep/sed.

Session lifecycle:
    open_diag_session(func_ea)   -- called on DecompilationEvent.STARTED
    get_diag_db()                -- returns the session's connection (or None)
    close_diag_session()         -- called on DecompilationEvent.FINISHED
"""
from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

from d810.core.diag.schema import create_tables

_DIAG_ENABLED = os.environ.get("D810_DIAG_SNAPSHOT", "0") == "1"

_current_conn: sqlite3.Connection | None = None
_current_func_ea: int | None = None


def open_diag_session(func_ea: int, log_dir: str | None = None) -> None:
    """Open a diag DB for this decompilation pass.

    Called on DecompilationEvent.STARTED.  All subsequent ``get_diag_db()``
    calls will return the same connection until ``close_diag_session()``.
    """
    global _current_conn, _current_func_ea
    if not _DIAG_ENABLED:
        return
    close_diag_session()  # close any stale session
    if log_dir is None:
        log_dir = os.path.expanduser("~/.idapro/logs/d810_logs")
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    run_id = f"{int(time.time())}_{os.getpid()}"
    db_path = Path(log_dir) / f"{func_ea:016x}_{run_id}.diag.sqlite3"
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    create_tables(conn)
    _current_conn = conn
    _current_func_ea = func_ea


def close_diag_session() -> None:
    """Close the current diag DB.  Called on DecompilationEvent.FINISHED."""
    global _current_conn, _current_func_ea
    if _current_conn is not None:
        try:
            _current_conn.close()
        except Exception:
            pass
    _current_conn = None
    _current_func_ea = None


def get_diag_db(func_ea: int = 0, log_dir: str | None = None) -> sqlite3.Connection | None:
    """Return the current session's diag DB connection, or None if disabled.

    If a session is active (opened via ``open_diag_session``), the session
    connection is returned.  Otherwise a one-off DB is created for backward
    compatibility (e.g. test harness usage outside the decompilation lifecycle).
    """
    if not _DIAG_ENABLED:
        return None
    if _current_conn is not None:
        return _current_conn
    # Fallback: no session open — create a one-off DB (test harness path)
    if log_dir is None:
        log_dir = os.path.expanduser("~/.idapro/logs/d810_logs")
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    run_id = f"{int(time.time())}_{os.getpid()}"
    ea = func_ea if func_ea else 0
    db_path = Path(log_dir) / f"{ea:016x}_{run_id}.diag.sqlite3"
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    create_tables(conn)
    return conn
