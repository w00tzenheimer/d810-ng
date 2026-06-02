"""Pin that peewee Models reproduce the diag schema for the modeled tables.

Ticket llr-t3nw. The first slice models ``snapshots``, ``state_cfg_nodes``,
``state_cfg_edges`` (schema source of truth). These assertions lock the exact
column layout (name, type, notnull, pk-position) so a future Model edit that
drifts from the original hand-DDL is caught. Captured from peewee's emitted
DDL, which matches the original ``_SCHEMA_SQL`` except ``snapshots.id`` is
``INTEGER NOT NULL PRIMARY KEY`` (notnull=1) vs the old ``INTEGER PRIMARY KEY``
(notnull=0) -- functionally identical for an INTEGER PK (NULL still auto-assigns
the rowid).
"""
from __future__ import annotations
from d810.core.diag import create_diag_database

import sqlite3

from d810.core.diag.schema import create_tables

# (name, type, notnull, pk-position) in column order.
EXPECTED = {
    "snapshots": [
        ("id", "INTEGER", 1, 1),
        ("label", "TEXT", 1, 0),
        ("func_ea_hex", "TEXT", 1, 0),
        ("func_ea_i64", "INTEGER", 1, 0),
        ("maturity", "TEXT", 1, 0),
        ("phase", "TEXT", 1, 0),
        ("block_count", "INTEGER", 1, 0),
        ("timestamp", "REAL", 1, 0),
    ],
    "state_cfg_nodes": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("state_hex", "TEXT", 1, 2),
        ("state_i64", "INTEGER", 1, 0),
        ("entry_block", "INTEGER", 1, 0),
        ("classification", "TEXT", 1, 0),
        ("shared_suffix", "TEXT", 0, 0),
    ],
    "state_cfg_edges": [
        ("snapshot_id", "INTEGER", 1, 1),
        ("edge_id", "INTEGER", 1, 2),
        ("source_state_hex", "TEXT", 0, 0),
        ("source_state_i64", "INTEGER", 0, 0),
        ("target_state_hex", "TEXT", 0, 0),
        ("target_state_i64", "INTEGER", 0, 0),
        ("edge_kind", "TEXT", 1, 0),
        ("source_block", "INTEGER", 0, 0),
        ("source_arm", "INTEGER", 0, 0),
        ("target_entry", "INTEGER", 0, 0),
        ("ordered_path", "TEXT", 1, 0),
    ],
}


def _table_info(conn: sqlite3.Connection, table: str) -> list[tuple]:
    return [
        (r[1], r[2], r[3], r[5])  # name, type, notnull, pk
        for r in conn.execute(f"PRAGMA table_info({table})")
    ]


class TestModeledSchemaEquivalence:
    def test_modeled_tables_match_expected_layout(self) -> None:
        conn = create_diag_database(":memory:").connection()
        for table, expected in EXPECTED.items():
            assert _table_info(conn, table) == expected, table

    def test_no_extra_index_on_fk_column(self) -> None:
        conn = create_diag_database(":memory:").connection()
        # Only the composite-PK autoindex should exist (no FK auto-index).
        for table in ("state_cfg_nodes", "state_cfg_edges"):
            idx = [r[1] for r in conn.execute(f"PRAGMA index_list({table})")]
            assert idx == [f"sqlite_autoindex_{table}_1"], (table, idx)
