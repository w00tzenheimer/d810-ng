"""dag_* -> state_cfg_* table rename: back-compat views + legacy-DB migration.

Ticket llr-l48z / llr-t3nw. The recovered-CFG tables are now ``state_cfg_*``
(a CFG has cycles; "DAG" was a misnomer). Old ``dag_*`` names survive as
read-only views, and pre-existing ``.diag.sqlite3`` files (which had ``dag_*``
as base tables) are migrated in-place by ``create_tables`` via
``playhouse.migrate.SqliteMigrator``. The diag DB is peewee-owned, so these
tests build a ``SqliteDatabase`` (directly, to inject a legacy table before
the schema is applied) or use the ``create_diag_database`` factory.
"""
from __future__ import annotations
from d810.core.diag import create_diag_database

import sqlite3

from d810._vendor.peewee import SqliteDatabase
from d810.core.diag.schema import create_tables


def _kind(conn: sqlite3.Connection, name: str) -> str | None:
    row = conn.execute(
        "SELECT type FROM sqlite_master WHERE name=?", (name,)
    ).fetchone()
    return row[0] if row else None


def _legacy_db(setup_sql: str) -> SqliteDatabase:
    """A peewee db with a pre-existing legacy ``dag_*`` base table injected."""
    db = SqliteDatabase(":memory:")
    db.connect()
    db.connection().executescript(setup_sql)
    return db


class TestFreshDb:
    def test_recovered_cfg_tables_are_state_cfg(self) -> None:
        conn = create_diag_database(":memory:").connection()
        assert _kind(conn, "state_cfg_nodes") == "table"
        assert _kind(conn, "state_cfg_edges") == "table"

    def test_dag_names_are_backcompat_views(self) -> None:
        conn = create_diag_database(":memory:").connection()
        assert _kind(conn, "dag_nodes") == "view"
        assert _kind(conn, "dag_edges") == "view"
        assert _kind(conn, "dag_edge_alternate_selections") == "view"

    def test_write_to_table_is_visible_via_dag_view(self) -> None:
        conn = create_diag_database(":memory:").connection()
        conn.execute(
            "INSERT INTO state_cfg_nodes VALUES (1, '0x5', 7, 9, 'RANGE_BACKED', '{}')"
        )
        via_view = conn.execute(
            "SELECT state_hex FROM dag_nodes WHERE snapshot_id=1"
        ).fetchone()
        assert via_view[0] == "0x5"


class TestLegacyMigration:
    def test_legacy_dag_table_renamed_to_state_cfg_preserving_data(self) -> None:
        db = _legacy_db(
            "CREATE TABLE dag_edges (snapshot_id INTEGER, source_state_hex TEXT);"
            "INSERT INTO dag_edges VALUES (1, '0xABCD');"
        )
        create_tables(db)  # must migrate, not orphan
        conn = db.connection()
        assert _kind(conn, "state_cfg_edges") == "table"
        assert (
            conn.execute("SELECT source_state_hex FROM state_cfg_edges").fetchone()[0]
            == "0xABCD"
        )
        assert _kind(conn, "dag_edges") == "view"
        assert (
            conn.execute("SELECT source_state_hex FROM dag_edges").fetchone()[0]
            == "0xABCD"
        )

    def test_migration_is_idempotent(self) -> None:
        db = _legacy_db(
            "CREATE TABLE dag_nodes (snapshot_id INTEGER, state_hex TEXT);"
            "INSERT INTO dag_nodes VALUES (1, '0x1');"
        )
        create_tables(db)
        create_tables(db)  # second call must not raise or lose data
        conn = db.connection()
        assert _kind(conn, "state_cfg_nodes") == "table"
        assert _kind(conn, "dag_nodes") == "view"
        assert (
            conn.execute("SELECT state_hex FROM state_cfg_nodes").fetchone()[0] == "0x1"
        )
