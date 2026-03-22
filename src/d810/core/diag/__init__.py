"""MBA diagnostic snapshot infrastructure.

Queryable SQLite snapshots for block chain tracing, variable provenance,
and DAG correlation without grep/sed.
"""
from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

from d810.core.diag.schema import create_tables

_DIAG_ENABLED = os.environ.get("D810_DIAG_SNAPSHOT", "0") == "1"


def get_diag_db(func_ea: int, log_dir: str | None = None) -> sqlite3.Connection | None:
    """Get or create a diagnostic SQLite DB for the given function.

    Returns None if D810_DIAG_SNAPSHOT is not set.
    DB path: {log_dir}/{func_ea:016x}_{run_id}.diag.sqlite3

    Each decompilation gets its own file (per-IDB per-run isolation).
    Safe for parallel Docker runs, multiple IDBs, and abrupt termination.
    """
    if not _DIAG_ENABLED:
        return None
    if log_dir is None:
        log_dir = os.path.expanduser("~/.idapro/logs/d810_logs")
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    run_id = f"{int(time.time())}_{os.getpid()}"
    db_path = Path(log_dir) / f"{func_ea:016x}_{run_id}.diag.sqlite3"
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    create_tables(conn)
    return conn
