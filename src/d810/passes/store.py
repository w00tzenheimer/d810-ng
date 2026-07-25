"""SQLite persistence for PreanalysisResult and DeobfuscationHints.

Schema follows the existing pattern in ``core/persistence.py``:
- ``INSERT OR REPLACE`` for upsert semantics
- JSON columns for variable-length data (metrics, candidates, inferences)
- Composite primary key ``(func_ea, maturity, collector_name)`` for results
- Single primary key ``func_ea`` for hints

No IDA imports - fully unit-testable.
"""

from __future__ import annotations

import atexit
import json
import queue
import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType
from d810.core.typing import TypeVar

from d810.core import logging
from d810.analyses.control_flow.models import (
    CandidateFlag,
    DeobfuscationHints,
    PreanalysisResult,
)

logger = logging.getLogger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS preanalysis_results (
    func_ea         INTEGER NOT NULL,
    maturity        INTEGER NOT NULL,
    collector_name  TEXT    NOT NULL,
    timestamp       REAL    NOT NULL,
    metrics_json    TEXT    NOT NULL,
    candidates_json TEXT    NOT NULL,
    PRIMARY KEY (func_ea, maturity, collector_name)
);

CREATE TABLE IF NOT EXISTS deobfuscation_hints (
    func_ea                  INTEGER PRIMARY KEY,
    obfuscation_type         TEXT,
    confidence               REAL    NOT NULL,
    recommended_inferences_json TEXT    NOT NULL,
    candidates_json          TEXT    NOT NULL,
    suppress_rules_json      TEXT    NOT NULL,
    updated_at               REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_preanalysis_func_ea
    ON preanalysis_results(func_ea);

CREATE TABLE IF NOT EXISTS preanalysis_session_summary (
    func_ea INTEGER NOT NULL,
    timestamp REAL NOT NULL,
    collectors_fired INTEGER NOT NULL DEFAULT 0,
    classification TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 0.0,
    inferences_json TEXT NOT NULL DEFAULT '[]',
    suppress_rules_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (func_ea)
);

CREATE TABLE IF NOT EXISTS consumer_outcomes (
    func_ea INTEGER NOT NULL,
    consumer_name TEXT NOT NULL,
    timestamp REAL NOT NULL,
    artifacts_available INTEGER NOT NULL DEFAULT 0,
    summary_available INTEGER NOT NULL DEFAULT 0,
    verdict_applied INTEGER NOT NULL DEFAULT 0,
    detail TEXT NOT NULL DEFAULT '',
    provenance_json TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (func_ea, consumer_name)
);

CREATE TABLE IF NOT EXISTS user_overrides (
    func_ea INTEGER NOT NULL,
    override_type TEXT NOT NULL,
    override_value TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    created_at REAL NOT NULL,
    PRIMARY KEY (func_ea, override_type)
);
"""


# -- Schema migrations for existing databases --------------------------------
# Maps (table_name, column_name) -> column_definition for ALTER TABLE ADD COLUMN.
# Each entry is checked on connection; if the column is missing it is added.
_MIGRATIONS: list[tuple[str, str, str]] = [
    (
        "deobfuscation_hints",
        "recommended_inferences_json",
        "TEXT NOT NULL DEFAULT '[]'",
    ),
]


def _get_existing_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    """Return the set of column names for *table*, or empty set if missing."""
    cursor = conn.execute("PRAGMA table_info(%s)" % table)
    return {row[1] for row in cursor.fetchall()}


def _migrate_schema(conn: sqlite3.Connection) -> None:
    """Add any columns required by the current schema but absent in the DB.

    ``CREATE TABLE IF NOT EXISTS`` is a no-op when a table already exists,
    so columns added after initial creation must be back-filled here.
    """
    for table, column, col_def in _MIGRATIONS:
        existing = _get_existing_columns(conn, table)
        if not existing:
            # Table doesn't exist yet (will be created by _SCHEMA).
            continue
        if column not in existing:
            stmt = "ALTER TABLE %s ADD COLUMN %s %s" % (table, column, col_def)
            logger.info("preanalysis store: migrating schema - %s", stmt)
            conn.execute(stmt)
    conn.commit()


def _delete_sqlite_database(db_path: Path) -> None:
    """Remove a SQLite database and its WAL/SHM sidecars."""
    for suffix in ("", "-wal", "-shm"):
        path = Path(str(db_path) + suffix)
        try:
            path.unlink(missing_ok=True)
        except OSError:
            logger.warning(
                "preanalysis store: failed to delete %s", path, exc_info=True
            )


def _ensure_readable_database(db_path: Path) -> None:
    """Discard generated analysis DB state when SQLite reports corruption.

    The analysis DB is generated runtime state. Keeping a malformed file is worse
    than losing cached observations because a read failure can suppress later
    optimizer passes for the whole maturity.
    """
    if not db_path.exists() or db_path.stat().st_size == 0:
        return
    try:
        conn = sqlite3.connect(str(db_path))
        try:
            row = conn.execute("PRAGMA quick_check").fetchone()
        finally:
            conn.close()
    except sqlite3.DatabaseError as exc:
        logger.warning(
            "preanalysis store: deleting unreadable DB %s before open: %s",
            db_path,
            exc,
        )
        _delete_sqlite_database(db_path)
        return
    if row is None or str(row[0]).lower() != "ok":
        logger.warning(
            "preanalysis store: deleting corrupt DB %s before open: %s",
            db_path,
            row[0] if row else "no quick_check row",
        )
        _delete_sqlite_database(db_path)


def _candidate_to_dict(c: CandidateFlag) -> dict:
    return {
        "kind": c.kind,
        "block_serial": c.block_serial,
        "confidence": c.confidence,
        "detail": c.detail,
    }


def _candidate_from_dict(d: dict) -> CandidateFlag:
    return CandidateFlag(
        kind=str(d["kind"]),
        block_serial=int(d["block_serial"]),
        confidence=float(d["confidence"]),
        detail=str(d["detail"]),
    )


class PreanalysisStore:
    """SQLite-backed store for preanalysis results and deobfuscation hints.

    Example:
        >>> store = PreanalysisStore("/tmp/analysis.db")
        >>> store.save_preanalysis_result(result)
        >>> rows = store.load_preanalysis_results(func_ea=0x401000, provider_level=5)
        >>> store.close()
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        _ensure_readable_database(self.db_path)
        self._conn: sqlite3.Connection = sqlite3.connect(str(self.db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.row_factory = sqlite3.Row
        # Migrate existing tables before CREATE TABLE IF NOT EXISTS (no-op
        # for tables that already exist, so new columns must be ALTER'd first).
        _migrate_schema(self._conn)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # PreanalysisResult persistence
    # ------------------------------------------------------------------

    def save_preanalysis_result(self, result: PreanalysisResult) -> None:
        """Upsert one preanalysis result for a function and provider level."""
        self._conn.execute(
            """
            INSERT OR REPLACE INTO preanalysis_results
                (func_ea, maturity, collector_name, timestamp, metrics_json, candidates_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                int(result.func_ea),
                int(result.maturity),
                str(result.collector_name),
                float(result.timestamp),
                json.dumps(dict(result.metrics)),
                json.dumps([_candidate_to_dict(c) for c in result.candidates]),
            ),
        )
        self._conn.commit()

    def load_preanalysis_results(
        self,
        *,
        func_ea: int,
        provider_level: int | None = None,
        **legacy_fields: object,
    ) -> list[PreanalysisResult]:
        """Load all collector results for a specific func/maturity pair."""
        legacy_level = legacy_fields.pop("maturity", None)
        if legacy_fields:
            names = ", ".join(sorted(legacy_fields))
            raise TypeError(f"Unexpected preanalysis store field(s): {names}")
        if provider_level is None:
            if legacy_level is None:
                raise TypeError("provider_level is required")
            provider_level = int(legacy_level)
        cursor = self._conn.execute(
            """
            SELECT collector_name, timestamp, metrics_json, candidates_json
            FROM preanalysis_results
            WHERE func_ea = ? AND maturity = ?
            """,
            (int(func_ea), int(provider_level)),
        )
        return [
            self._row_to_result(row, func_ea=func_ea, provider_level=provider_level)
            for row in cursor.fetchall()
        ]

    def load_all_preanalysis_results(self, *, func_ea: int) -> list[PreanalysisResult]:
        """Load all collector results for a function across all maturities."""
        cursor = self._conn.execute(
            """
            SELECT collector_name, maturity, timestamp, metrics_json, candidates_json
            FROM preanalysis_results
            WHERE func_ea = ?
            """,
            (int(func_ea),),
        )
        rows = cursor.fetchall()
        return [
            self._row_to_result(
                row,
                func_ea=func_ea,
                provider_level=int(row["maturity"]),
            )
            for row in rows
        ]

    def load_latest_preanalysis_result(
        self,
        *,
        func_ea: int,
        collector_name: str,
        provider_level: int | None = None,
        **legacy_fields: object,
    ) -> PreanalysisResult | None:
        """Load the latest result for one collector.

        When *provider_level* is provided, constrain the query to that level.
        Otherwise return the latest row across all maturities, ordered by
        maturity descending then timestamp descending.
        """
        legacy_level = legacy_fields.pop("maturity", None)
        if legacy_fields:
            names = ", ".join(sorted(legacy_fields))
            raise TypeError(f"Unexpected preanalysis store field(s): {names}")
        if provider_level is None and legacy_level is not None:
            provider_level = int(legacy_level)
        if provider_level is None:
            cursor = self._conn.execute(
                """
                SELECT maturity, collector_name, timestamp, metrics_json, candidates_json
                FROM preanalysis_results
                WHERE func_ea = ? AND collector_name = ?
                ORDER BY maturity DESC, timestamp DESC
                LIMIT 1
                """,
                (int(func_ea), str(collector_name)),
            )
        else:
            cursor = self._conn.execute(
                """
                SELECT maturity, collector_name, timestamp, metrics_json, candidates_json
                FROM preanalysis_results
                WHERE func_ea = ? AND collector_name = ? AND maturity = ?
                ORDER BY timestamp DESC
                LIMIT 1
                """,
                (int(func_ea), str(collector_name), int(provider_level)),
            )
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_result(
            row,
            func_ea=func_ea,
            provider_level=int(row["maturity"]),
        )

    @staticmethod
    def _row_to_result(
        row: sqlite3.Row, *, func_ea: int, provider_level: int
    ) -> PreanalysisResult:
        candidates = tuple(
            _candidate_from_dict(d) for d in json.loads(row["candidates_json"] or "[]")
        )
        return PreanalysisResult(
            collector_name=str(row["collector_name"]),
            func_ea=int(func_ea),
            provider_level=int(provider_level),
            timestamp=float(row["timestamp"]),
            metrics=MappingProxyType(json.loads(row["metrics_json"] or "{}")),
            candidates=candidates,
        )

    # ------------------------------------------------------------------
    # DeobfuscationHints persistence
    # ------------------------------------------------------------------

    def save_hints(self, hints: DeobfuscationHints) -> None:
        """Upsert DeobfuscationHints for a function (primary key: func_ea)."""
        self._conn.execute(
            """
            INSERT OR REPLACE INTO deobfuscation_hints
                (func_ea, obfuscation_type, confidence,
                 recommended_inferences_json, candidates_json,
                 suppress_rules_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(hints.func_ea),
                hints.obfuscation_type,
                float(hints.confidence),
                json.dumps(list(hints.recommended_inferences)),
                json.dumps([_candidate_to_dict(c) for c in hints.candidates]),
                json.dumps(list(hints.suppress_rules)),
                time.time(),
            ),
        )
        self._conn.commit()

    def load_hints(self, *, func_ea: int) -> DeobfuscationHints | None:
        """Load DeobfuscationHints for a function, or None if not present."""
        cursor = self._conn.execute(
            """
            SELECT obfuscation_type, confidence, recommended_inferences_json,
                   candidates_json, suppress_rules_json
            FROM deobfuscation_hints
            WHERE func_ea = ?
            """,
            (int(func_ea),),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        candidates = tuple(
            _candidate_from_dict(d) for d in json.loads(row["candidates_json"] or "[]")
        )
        return DeobfuscationHints(
            func_ea=int(func_ea),
            obfuscation_type=row["obfuscation_type"],
            confidence=float(row["confidence"]),
            recommended_inferences=tuple(
                json.loads(row["recommended_inferences_json"] or "[]")
            ),
            candidates=candidates,
            suppress_rules=tuple(json.loads(row["suppress_rules_json"] or "[]")),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Session summary persistence
    # ------------------------------------------------------------------

    def save_session_summary(
        self,
        func_ea: int,
        collectors_fired: int,
        classification: str,
        confidence: float,
        inferences: list[str],
        suppress_rules: list[str],
    ) -> None:
        """Persist per-function session summary (upsert)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO preanalysis_session_summary "
            "(func_ea, timestamp, collectors_fired, classification, confidence, "
            "inferences_json, suppress_rules_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                func_ea,
                time.time(),
                collectors_fired,
                classification,
                confidence,
                json.dumps(inferences),
                json.dumps(suppress_rules),
            ),
        )
        self._conn.commit()

    def load_session_summary(self, func_ea: int) -> dict | None:
        """Load persisted session summary for a function."""
        row = self._conn.execute(
            "SELECT * FROM preanalysis_session_summary WHERE func_ea = ?",
            (func_ea,),
        ).fetchone()
        if row is None:
            return None
        return {
            "func_ea": row["func_ea"],
            "collectors_fired": row["collectors_fired"],
            "classification": row["classification"],
            "confidence": row["confidence"],
            "inferences": json.loads(row["inferences_json"]),
            "suppress_rules": json.loads(row["suppress_rules_json"]),
        }

    # ------------------------------------------------------------------
    # Consumer outcome persistence
    # ------------------------------------------------------------------

    def save_consumer_outcome(
        self,
        func_ea: int,
        consumer_name: str,
        artifacts_available: bool,
        summary_available: bool,
        verdict_applied: bool,
        detail: str = "",
        provenance_json: str = "",
    ) -> None:
        """Persist a consumer outcome record (upsert by func_ea + consumer_name)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO consumer_outcomes "
            "(func_ea, consumer_name, timestamp, artifacts_available, summary_available, "
            "verdict_applied, detail, provenance_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                func_ea,
                consumer_name,
                time.time(),
                int(artifacts_available),
                int(summary_available),
                int(verdict_applied),
                detail,
                provenance_json,
            ),
        )
        self._conn.commit()

    def load_consumer_outcomes(self, func_ea: int) -> list[dict]:
        """Load all consumer outcomes for a function."""
        rows = self._conn.execute(
            "SELECT * FROM consumer_outcomes WHERE func_ea = ? ORDER BY consumer_name",
            (func_ea,),
        ).fetchall()
        return [
            {
                "consumer_name": r["consumer_name"],
                "artifacts_available": bool(r["artifacts_available"]),
                "summary_available": bool(r["summary_available"]),
                "verdict_applied": bool(r["verdict_applied"]),
                "detail": r["detail"],
                "provenance_json": r["provenance_json"],
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Aggregate queries (for E2E pipeline assertions)
    # ------------------------------------------------------------------

    def count_functions_with_hints(self) -> int:
        """Count distinct functions that have deobfuscation hints."""
        row = self._conn.execute(
            "SELECT COUNT(DISTINCT func_ea) AS cnt FROM deobfuscation_hints"
        ).fetchone()
        return int(row["cnt"]) if row else 0

    def count_functions_with_session_summaries(self) -> int:
        """Count distinct functions that have session summaries."""
        row = self._conn.execute(
            "SELECT COUNT(DISTINCT func_ea) AS cnt FROM preanalysis_session_summary"
        ).fetchone()
        return int(row["cnt"]) if row else 0

    def count_functions_with_consumer_outcomes(self) -> int:
        """Count distinct functions that have at least one consumer outcome."""
        row = self._conn.execute(
            "SELECT COUNT(DISTINCT func_ea) AS cnt FROM consumer_outcomes"
        ).fetchone()
        return int(row["cnt"]) if row else 0

    def list_functions_with_hints(self) -> list[int]:
        """Return sorted list of func_ea values that have hints."""
        rows = self._conn.execute(
            "SELECT DISTINCT func_ea FROM deobfuscation_hints ORDER BY func_ea"
        ).fetchall()
        return [int(r["func_ea"]) for r in rows]

    def list_functions_missing_session_summary(self) -> list[int]:
        """Return func_eas that have hints but no session summary."""
        rows = self._conn.execute(
            """
            SELECT DISTINCT h.func_ea
            FROM deobfuscation_hints h
            LEFT JOIN preanalysis_session_summary s ON h.func_ea = s.func_ea
            WHERE s.func_ea IS NULL
            ORDER BY h.func_ea
            """
        ).fetchall()
        return [int(r["func_ea"]) for r in rows]

    def load_all_session_summaries(self) -> list[dict]:
        """Load all session summaries across all functions."""
        rows = self._conn.execute(
            "SELECT * FROM preanalysis_session_summary ORDER BY func_ea"
        ).fetchall()
        return [
            {
                "func_ea": int(r["func_ea"]),
                "collectors_fired": int(r["collectors_fired"]),
                "classification": r["classification"],
                "confidence": float(r["confidence"]),
                "inferences": json.loads(r["inferences_json"]),
                "suppress_rules": json.loads(r["suppress_rules_json"]),
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # User override persistence
    # ------------------------------------------------------------------

    def save_user_override(
        self,
        func_ea: int,
        override_type: str,
        override_value: str,
        confidence: float = 1.0,
    ) -> None:
        """Persist a user classification override (upsert)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO user_overrides "
            "(func_ea, override_type, override_value, confidence, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (func_ea, override_type, override_value, confidence, time.time()),
        )
        self._conn.commit()

    def load_user_override(
        self, func_ea: int, override_type: str = "classification"
    ) -> dict | None:
        """Load a user override for a function, or None."""
        row = self._conn.execute(
            "SELECT override_value, confidence FROM user_overrides "
            "WHERE func_ea = ? AND override_type = ?",
            (func_ea, override_type),
        ).fetchone()
        if row is None:
            return None
        return {
            "override_value": row["override_value"],
            "confidence": row["confidence"],
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def clear_func(self, *, func_ea: int) -> None:
        """Delete all stored data for a function except user overrides.

        User overrides persist across decompilation resets so that manual
        classifications survive re-analysis.
        """
        self._conn.execute(
            "DELETE FROM preanalysis_results WHERE func_ea = ?", (int(func_ea),)
        )
        self._conn.execute(
            "DELETE FROM deobfuscation_hints WHERE func_ea = ?", (int(func_ea),)
        )
        self._conn.execute(
            "DELETE FROM preanalysis_session_summary WHERE func_ea = ?", (int(func_ea),)
        )
        self._conn.execute(
            "DELETE FROM consumer_outcomes WHERE func_ea = ?", (int(func_ea),)
        )
        self._conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    def __enter__(self) -> "PreanalysisStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


_T = TypeVar("_T")
_SENTINEL = object()


def _shutdown_writer(writer: "PreanalysisStoreWriter") -> None:
    """Best-effort WAL flush on interpreter exit."""
    try:
        writer.shutdown()
    except Exception:
        pass


class PreanalysisStoreWriter:
    """Dedicated writer thread for serialized SQLite writes.

    Owns a single ``PreanalysisStore`` connection. Callers submit write
    callables via :meth:`submit` (fire-and-forget) or
    :meth:`submit_sync` (blocking, returns result).
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._queue: queue.Queue = queue.Queue()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name=f"preanalysis-writer-{db_path.name}"
        )
        self._thread.start()
        atexit.register(_shutdown_writer, self)

    def _run(self) -> None:
        store = PreanalysisStore(self._db_path)
        try:
            while True:
                item = self._queue.get()
                if item is _SENTINEL:
                    break
                try:
                    item(store)
                except Exception:
                    logger.debug("PreanalysisStoreWriter: write failed (non-critical)")
        finally:
            store.close()

    def submit(self, fn: Callable[["PreanalysisStore"], None]) -> None:
        """Submit a write callable (fire-and-forget)."""
        self._queue.put(fn)

    def submit_sync(self, fn: "Callable[[PreanalysisStore], _T]") -> "_T":
        """Submit a callable and block until it completes, returning its result."""
        result_box: list = []
        exc_box: list[Exception] = []
        done = threading.Event()

        def _wrapper(store: "PreanalysisStore") -> None:
            try:
                result_box.append(fn(store))
            except Exception as e:
                exc_box.append(e)
            finally:
                done.set()

        self._queue.put(_wrapper)
        done.wait()
        if exc_box:
            raise exc_box[0]
        return result_box[0]

    def flush(self) -> None:
        """Block until all pending writes have been executed."""
        done = threading.Event()
        self._queue.put(lambda _store: done.set())
        done.wait()

    def shutdown(self) -> None:
        """Signal the writer thread to stop and wait for it to finish."""
        self._queue.put(_SENTINEL)
        self._thread.join(timeout=5)


_writers: dict[Path, PreanalysisStoreWriter] = {}
_writers_lock = threading.Lock()


def get_preanalysis_writer(db_path: Path | str) -> PreanalysisStoreWriter:
    """Return the singleton writer for *db_path*, creating it lazily."""
    db_path = Path(db_path)
    writer = _writers.get(db_path)
    if writer is not None:
        return writer
    with _writers_lock:
        writer = _writers.get(db_path)
        if writer is None:
            writer = PreanalysisStoreWriter(db_path)
            _writers[db_path] = writer
    return writer


def shutdown_all_writers() -> None:
    """Shut down every writer thread.  Called on plugin unload."""
    with _writers_lock:
        for writer in _writers.values():
            writer.shutdown()
        _writers.clear()
