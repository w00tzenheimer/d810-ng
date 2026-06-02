"""dag_* -> state_cfg_* table rename: back-compat views + legacy-DB migration.

Ticket llr-l48z. The recovered-CFG tables are now ``state_cfg_*`` (a CFG has
cycles; "DAG" was a misnomer). Old ``dag_*`` names survive as read-only views
for back-compat, and pre-existing ``.diag.sqlite3`` files (which had ``dag_*``
as base tables) are migrated in-place by ``create_tables``.
"""
from __future__ import annotations

import sqlite3

from d810.core.diag.schema import create_tables


def _kind(conn: sqlite3.Connection, name: str) -> str | None:
    row = conn.execute(
        "SELECT type FROM sqlite_master WHERE name=?", (name,)
    ).fetchone()
    return row[0] if row else None


class TestFreshDb:
    def test_recovered_cfg_tables_are_state_cfg(self) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        assert _kind(conn, "state_cfg_nodes") == "table"
        assert _kind(conn, "state_cfg_edges") == "table"

    def test_dag_names_are_backcompat_views(self) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        assert _kind(conn, "dag_nodes") == "view"
        assert _kind(conn, "dag_edges") == "view"
        assert _kind(conn, "dag_edge_alternate_selections") == "view"

    def test_write_to_table_is_visible_via_dag_view(self) -> None:
        conn = sqlite3.connect(":memory:")
        create_tables(conn)
        # FK enforcement is off by default, so no snapshots row is needed.
        conn.execute(
            "INSERT INTO state_cfg_nodes VALUES (1, '0x5', 7, 9, 'RANGE_BACKED', '{}')"
        )
        # Old dag_nodes view reflects the new table's data.
        via_view = conn.execute(
            "SELECT state_hex FROM dag_nodes WHERE snapshot_id=1"
        ).fetchone()
        assert via_view[0] == "0x5"


class TestLegacyMigration:
    def test_legacy_dag_table_renamed_to_state_cfg_preserving_data(self) -> None:
        conn = sqlite3.connect(":memory:")
        # Simulate an OLD diag DB: dag_edges as a base TABLE with a row.
        conn.executescript(
            "CREATE TABLE dag_edges (snapshot_id INTEGER, source_state_hex TEXT);"
            "INSERT INTO dag_edges VALUES (1, '0xABCD');"
        )
        create_tables(conn)  # must migrate, not orphan
        # Data now lives in the new base table.
        assert _kind(conn, "state_cfg_edges") == "table"
        assert (
            conn.execute("SELECT source_state_hex FROM state_cfg_edges").fetchone()[0]
            == "0xABCD"
        )
        # Old name is now a view that still serves the data.
        assert _kind(conn, "dag_edges") == "view"
        assert (
            conn.execute("SELECT source_state_hex FROM dag_edges").fetchone()[0]
            == "0xABCD"
        )

    def test_migration_is_idempotent(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.executescript(
            "CREATE TABLE dag_nodes (snapshot_id INTEGER, state_hex TEXT);"
            "INSERT INTO dag_nodes VALUES (1, '0x1');"
        )
        create_tables(conn)
        create_tables(conn)  # second call must not raise or lose data
        assert _kind(conn, "state_cfg_nodes") == "table"
        assert _kind(conn, "dag_nodes") == "view"
        assert (
            conn.execute("SELECT state_hex FROM state_cfg_nodes").fetchone()[0] == "0x1"
        )
