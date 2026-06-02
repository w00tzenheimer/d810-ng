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

from d810._vendor.peewee import SqliteDatabase
from d810.core.diag.models import MODELS  # noqa: F401  (re-export; also suppresses
# the implicit ``models -> diag`` parent edge that would otherwise close a
# spurious diag -> schema -> models -> diag cycle, since ``schema`` imports
# ``models`` and ``__init__`` imports ``schema``).
from d810.core.diag.schema import create_tables
from d810.core.settings import get_settings
from d810.core.typing import Callable

_current_db: SqliteDatabase | None = None
_current_conn: sqlite3.Connection | None = None
_current_func_ea: int | None = None


def create_diag_database(db_path: str) -> SqliteDatabase:
    """Open a peewee ``SqliteDatabase`` for the diag DB and apply the schema.

    peewee owns the connection (WAL pragma); raw-SQL diag call-sites get a
    plain ``sqlite3.Connection`` via ``db.connection()`` and are unchanged.
    Used by both the production session paths below and the test harness.
    """
    db = SqliteDatabase(db_path, pragmas={"journal_mode": "wal"})
    db.connect()
    create_tables(db)
    return db

# Inversion-of-control hook for cfg-layer block-lineage drain.
#
# core.diag.snapshot needs to flush pending block-lineage rows under the
# active snapshot_id, but the lineage data lives in d810.cfg (planner-owned).
# core cannot import cfg (layer contract).  cfg.block_lineage registers a
# drainer callable here at module load; snapshot.py invokes it through this
# indirection.  When cfg.block_lineage was never imported (no PatchPlan with
# new_blocks has been applied), the drainer stays None and the drain is a
# no-op — there are no pending rows to flush anyway.
_lineage_drainer: Callable[[sqlite3.Connection, int], int] | None = None


def register_lineage_drainer(
    drainer: Callable[[sqlite3.Connection, int], int],
) -> None:
    """Register a callable that drains pending block-lineage rows.

    The callable receives ``(conn, snapshot_id)`` and writes any pending
    rows to ``conn`` under ``snapshot_id``, returning the number of rows
    inserted.  Called by :func:`snapshot_mba` after CFG provenance flush.
    """
    global _lineage_drainer
    _lineage_drainer = drainer


def drain_lineage_into_snapshot(
    conn: sqlite3.Connection, snapshot_id: int
) -> int:
    """Drain any registered cfg-layer lineage drainer; no-op if unregistered."""
    drainer = _lineage_drainer
    if drainer is None:
        return 0
    try:
        return drainer(conn, snapshot_id)
    except Exception:
        return 0


# Inversion-of-control hook for cfg-layer CFG-provenance drain (Phase 6
# of the diag observability boundary plan). The producer-facing
# ``log_cfg_provenance`` API lives in ``d810.ir.provenance``; this hook
# lets ``snapshot_mba`` ask the cfg producer for its buffered entries
# without core.diag importing from d810.cfg (forbidden by layers).
_provenance_drainer: Callable[[], list] | None = None


def register_provenance_drainer(
    drainer: Callable[[], list],
) -> None:
    """Register a callable that returns the pending CFG-provenance entries.

    The callable takes no arguments and returns a list of entry objects
    that expose ``pass_name``, ``action``, ``block_serial``,
    ``target_serial``, ``reason``, and ``extra_json`` attributes (duck
    typed). ``snapshot_mba`` consumes the list and writes one
    ``cfg_provenance`` row per entry.
    """
    global _provenance_drainer
    _provenance_drainer = drainer


def drain_pending_provenance() -> list:
    """Return pending CFG-provenance entries from the registered drainer.

    Returns an empty list when no drainer is registered (i.e. nothing in
    the runtime has imported ``d810.ir.provenance`` yet).
    """
    drainer = _provenance_drainer
    if drainer is None:
        return []
    try:
        return drainer()
    except Exception:
        return []


def _resolve_log_dir(log_dir: str | None = None) -> Path:
    return Path(log_dir or os.path.expanduser("~/.idapro/logs/d810_logs"))


def find_latest_diag_db_path(func_ea: int = 0, log_dir: str | None = None) -> Path | None:
    """Return the newest non-empty diag DB path for a function, if any."""
    base = _resolve_log_dir(log_dir)
    if not base.exists():
        return None
    pattern = f"{int(func_ea):016x}_*.diag.sqlite3" if func_ea else "*.diag.sqlite3"
    candidates = sorted(base.glob(pattern), key=lambda path: path.stat().st_mtime, reverse=True)
    best_with_snapshots: Path | None = None
    for path in candidates:
        try:
            conn = sqlite3.connect(str(path))
            try:
                row = conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()
                count = int(row[0]) if row is not None and row[0] is not None else 0
            finally:
                conn.close()
        except Exception:
            continue
        if count > 0:
            best_with_snapshots = path
            break
    if best_with_snapshots is not None:
        return best_with_snapshots
    return candidates[0] if candidates else None


def open_diag_session(func_ea: int, log_dir: str | None = None) -> None:
    """Open a diag DB for this decompilation pass.

    Called on DecompilationEvent.STARTED. All subsequent
    ``get_diag_db()`` calls will return the same connection until
    ``close_diag_session()``.

    Also installs the diag event-handler subscribers on the
    observability bus so runtime ``observe_*`` / ``request_capture_*``
    publishers reach the SQLite sink. The install is idempotent.
    """
    global _current_db, _current_conn, _current_func_ea
    if not get_settings().diag_snapshots:
        return
    close_diag_session()  # close any stale session
    resolved_log_dir = _resolve_log_dir(log_dir)
    resolved_log_dir.mkdir(parents=True, exist_ok=True)
    run_id = f"{int(time.time())}_{os.getpid()}"
    db_path = resolved_log_dir / f"{func_ea:016x}_{run_id}.diag.sqlite3"
    db = create_diag_database(str(db_path))
    _current_db = db
    _current_conn = db.connection()
    _current_func_ea = func_ea
    # Dynamic import via importlib to avoid a static import cycle:
    # event_handlers itself imports `get_diag_db` from this module
    # at top level, so a top-level `from event_handlers import ...`
    # here would create a cycle that the dep-scanner rejects.
    try:
        import importlib
        importlib.import_module(
            "d810.core.diag.event_handlers"
        ).install_diag_event_handlers()
    except Exception:
        pass  # diagnostic, never gates decompilation


def close_diag_session() -> None:
    """Close the current diag DB. Called on DecompilationEvent.FINISHED.

    Also unsubscribes the diag event-handler subscribers so any
    close-time emit can't be picked up by a stale subscriber bound to
    an already-closed connection.
    """
    global _current_db, _current_conn, _current_func_ea
    # Uninstall first so subsequent emits do not reach a stale conn.
    # Dynamic import via importlib avoids the same static cycle as
    # in `open_diag_session` above.
    try:
        import importlib
        importlib.import_module(
            "d810.core.diag.event_handlers"
        ).uninstall_diag_event_handlers()
    except Exception:
        pass
    # Closing the peewee db closes its underlying connection.
    if _current_db is not None:
        try:
            _current_db.close()
        except Exception:
            pass
    elif _current_conn is not None:
        try:
            _current_conn.close()
        except Exception:
            pass
    _current_db = None
    _current_conn = None
    _current_func_ea = None


def get_diag_db(func_ea: int = 0, log_dir: str | None = None) -> sqlite3.Connection | None:
    """Return the current session's diag DB connection, or None if disabled.

    If a session is active (opened via ``open_diag_session``), the session
    connection is returned.  Otherwise a one-off DB is created for backward
    compatibility (e.g. test harness usage outside the decompilation lifecycle).
    """
    if not get_settings().diag_snapshots:
        return None
    if _current_conn is not None:
        return _current_conn
    latest_path = find_latest_diag_db_path(func_ea, log_dir=log_dir)
    if latest_path is not None:
        return create_diag_database(str(latest_path)).connection()
    # Fallback: no session open — create a one-off DB (test harness path)
    resolved_log_dir = _resolve_log_dir(log_dir)
    resolved_log_dir.mkdir(parents=True, exist_ok=True)
    run_id = f"{int(time.time())}_{os.getpid()}"
    ea = func_ea if func_ea else 0
    db_path = resolved_log_dir / f"{ea:016x}_{run_id}.diag.sqlite3"
    return create_diag_database(str(db_path)).connection()


# Register this backend with the abstract observability interface.
# Runtime layers reach the diag DB exclusively via
# ``d810.core.observability.{open_observability_session,
# close_observability_session, get_active_diag_conn}`` -- the
# registrations below wire those abstract entry points to this
# concrete backend.  ``core.observability`` lives in the same package
# layer as ``core.diag``, so this back-edge is allowed.
from d810.core.observability import (
    register_diag_conn_provider as _register_diag_conn_provider,
    register_diag_session_handlers as _register_diag_session_handlers,
)

_register_diag_session_handlers(open_diag_session, close_diag_session)
_register_diag_conn_provider(get_diag_db)
