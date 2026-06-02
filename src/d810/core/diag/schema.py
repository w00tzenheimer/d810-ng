"""SQLite schema for MBA diagnostic snapshots.

The diag DB is peewee-owned (``SqliteDatabase``). All non-view diag tables are
defined by peewee **Models** in :mod:`d810.core.diag.models` (schema source of
truth); only the SQL **views** (``var_writes`` + the ``dag_*`` back-compat
views) remain raw DDL in ``_SCHEMA_SQL`` below. ``create_tables`` applies the
Models (``db.create_tables(MODELS)``) and then the view DDL.
"""
from __future__ import annotations

import sqlite3

from d810._vendor.peewee import SqliteDatabase
from d810._vendor.playhouse.migrate import SqliteMigrator, migrate
from d810.core.diag.models import MODELS

# Only VIEWs remain raw DDL; every base table is a peewee Model (see models.py).
#
#   * ``var_writes`` -- analytical JOIN view over instructions + blocks.
#   * ``dag_*``      -- back-compat views over the renamed ``state_cfg_*``
#                       base tables (a control-flow graph has cycles -- "DAG"
#                       was a misnomer). They keep old ad-hoc queries and
#                       external ``.diag.sqlite3`` readers working; production
#                       code reads/writes the ``state_cfg_*`` base tables.
_SCHEMA_SQL = """\
-- Derived: which instructions write to a given stack variable
CREATE VIEW IF NOT EXISTS var_writes AS
SELECT i.*, b.succs, b.preds
FROM instructions i
JOIN blocks b ON i.snapshot_id = b.snapshot_id AND i.block_serial = b.serial
WHERE i.dest_type = 'mop_S';

-- Back-compat VIEWs for the renamed recovered-CFG tables.
CREATE VIEW IF NOT EXISTS dag_nodes AS SELECT * FROM state_cfg_nodes;
CREATE VIEW IF NOT EXISTS dag_edges AS SELECT * FROM state_cfg_edges;
CREATE VIEW IF NOT EXISTS dag_node_blocks AS SELECT * FROM state_cfg_node_blocks;
CREATE VIEW IF NOT EXISTS dag_local_segments AS SELECT * FROM state_cfg_local_segments;
CREATE VIEW IF NOT EXISTS dag_local_edges AS SELECT * FROM state_cfg_local_edges;
CREATE VIEW IF NOT EXISTS dag_edge_diagnostics AS SELECT * FROM state_cfg_edge_diagnostics;
CREATE VIEW IF NOT EXISTS dag_frontier_closure_diagnostics
    AS SELECT * FROM state_cfg_frontier_closure_diagnostics;
CREATE VIEW IF NOT EXISTS dag_edge_alternate_correlations
    AS SELECT * FROM state_cfg_edge_alternate_correlations;
CREATE VIEW IF NOT EXISTS dag_edge_alternate_selections
    AS SELECT * FROM state_cfg_edge_alternate_selections;
"""


# Recovered-CFG tables were historically ``dag_*`` base tables; they are now
# ``state_cfg_*`` base tables (+ ``dag_*`` back-compat views).  Maps each old
# base-table name to its new name for in-place migration of older DBs.
_LEGACY_DAG_TABLE_RENAMES = {
    "dag_nodes": "state_cfg_nodes",
    "dag_edges": "state_cfg_edges",
    "dag_node_blocks": "state_cfg_node_blocks",
    "dag_local_segments": "state_cfg_local_segments",
    "dag_local_edges": "state_cfg_local_edges",
    "dag_edge_diagnostics": "state_cfg_edge_diagnostics",
    "dag_frontier_closure_diagnostics": "state_cfg_frontier_closure_diagnostics",
    "dag_edge_alternate_correlations": "state_cfg_edge_alternate_correlations",
    "dag_edge_alternate_selections": "state_cfg_edge_alternate_selections",
}


def _migrate_legacy_dag_tables(db: SqliteDatabase) -> None:
    """Rename pre-existing ``dag_*`` base tables to ``state_cfg_*`` (idempotent).

    Older ``.diag.sqlite3`` files created ``dag_*`` as base tables.  The current
    schema makes ``state_cfg_*`` the base tables and ``dag_*`` read-only views.
    For each pair, if the old base table still exists and the new one does not,
    rename it via ``playhouse.migrate.SqliteMigrator`` (data + attached indexes
    follow the rename), then drop the now-stale ``idx_dag_*`` indexes so the
    schema's ``idx_state_cfg_*`` indexes are canonical.  Must run BEFORE
    ``db.create_tables(MODELS)`` so a renamed legacy table is not shadowed by a
    fresh empty modeled table.
    """
    conn = db.connection()
    existing = {
        name: kind
        for name, kind in conn.execute(
            "SELECT name, type FROM sqlite_master WHERE type IN ('table', 'view')"
        ).fetchall()
    }
    migrator = SqliteMigrator(db)
    ops = [
        migrator.rename_table(old, new)
        for old, new in _LEGACY_DAG_TABLE_RENAMES.items()
        if existing.get(old) == "table" and new not in existing
    ]
    if ops:
        migrate(*ops)
    for (idx_name,) in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_dag_%'"
    ).fetchall():
        conn.execute(f"DROP INDEX IF EXISTS {idx_name}")


def create_tables(db: SqliteDatabase) -> None:
    """Create all diagnostic snapshot tables, views, and indexes on ``db``.

    Order: migrate legacy ``dag_*`` base tables → create the modeled tables
    (``MODELS``) → apply the remaining raw DDL (the ``var_writes`` +
    ``dag_*`` views). Uses IF NOT EXISTS / safe=True so this is idempotent.
    """
    _migrate_legacy_dag_tables(db)
    with db.bind_ctx(MODELS):
        db.create_tables(MODELS, safe=True)
    conn = db.connection()
    conn.executescript(_SCHEMA_SQL)
    conn.execute("PRAGMA user_version = 1")
