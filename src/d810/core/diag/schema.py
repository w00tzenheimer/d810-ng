"""SQLite schema for MBA diagnostic snapshots.

The diag DB is peewee-owned (``SqliteDatabase``). All non-view diag tables are
defined by peewee **Models** in :mod:`d810.core.diag.models` (schema source of
truth); only analytical SQL views remain raw DDL. Diagnostic databases are
disposable: readers and writers reject every schema except the current one.
"""
from __future__ import annotations


from d810._vendor.peewee import SqliteDatabase
from d810.core.diag.models import DiagnosticSchemaVersion, MODELS

DIAGNOSTIC_SCHEMA_VERSION = 2


class DiagnosticSchemaMismatch(RuntimeError):
    """Raised when a disposable diagnostic database is not current."""

    def __init__(self, *, expected: int, observed: int | None, path: str) -> None:
        self.expected = int(expected)
        self.observed = None if observed is None else int(observed)
        self.path = str(path)
        super().__init__(
            "diagnostic schema mismatch: "
            f"expected={self.expected} observed={self.observed!r} path={self.path}"
        )

# Only VIEWs remain raw DDL; every base table is a peewee Model (see models.py).
#
#   * ``var_writes`` -- analytical JOIN view over instructions + blocks.
_SCHEMA_SQL = """\
-- Derived: which instructions write to a given stack variable
CREATE VIEW IF NOT EXISTS var_writes AS
SELECT i.*, b.succs, b.preds
FROM instructions i
JOIN blocks b ON i.snapshot_id = b.snapshot_id AND i.block_serial = b.serial
WHERE i.dest_type = 'mop_S';
"""


def _observed_version(db: SqliteDatabase) -> int | None:
    conn = db.connection()
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type='table' AND name='diagnostic_schema'"
    ).fetchone()
    if exists is None:
        return None
    row = conn.execute(
        "SELECT version FROM diagnostic_schema WHERE singleton=1"
    ).fetchone()
    return None if row is None else int(row[0])


def require_current_schema(db: SqliteDatabase, path: str | None = None) -> None:
    observed = _observed_version(db)
    if observed != DIAGNOSTIC_SCHEMA_VERSION:
        raise DiagnosticSchemaMismatch(
            expected=DIAGNOSTIC_SCHEMA_VERSION,
            observed=observed,
            path=str(path if path is not None else db.database),
        )


def create_tables(db: SqliteDatabase) -> None:
    """Create all diagnostic snapshot tables, views, and indexes on ``db``.

    Existing non-current databases are rejected; no migration is attempted.
    Fresh databases receive the modeled tables and exact version marker.
    """
    conn = db.connection()
    has_objects = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 1"
    ).fetchone() is not None
    if has_objects:
        require_current_schema(db)
    with db.bind_ctx(MODELS):
        db.create_tables(MODELS, safe=True)
        DiagnosticSchemaVersion.insert(
            singleton=1,
            version=DIAGNOSTIC_SCHEMA_VERSION,
        ).on_conflict_ignore().execute()
    conn.executescript(_SCHEMA_SQL)
    conn.execute(f"PRAGMA user_version = {DIAGNOSTIC_SCHEMA_VERSION}")
