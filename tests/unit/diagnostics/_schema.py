"""Helpers for raw diagnostic fixtures that intentionally omit most tables."""

from __future__ import annotations

import sqlite3

from d810.core.diag.schema import DIAGNOSTIC_SCHEMA_VERSION


def mark_current_schema(conn: sqlite3.Connection) -> None:
    """Mark a minimal raw fixture as a current disposable diagnostic DB."""
    conn.execute(
        "CREATE TABLE diagnostic_schema ("
        "singleton INTEGER PRIMARY KEY, version INTEGER NOT NULL)"
    )
    conn.execute(
        "INSERT INTO diagnostic_schema (singleton, version) VALUES (1, ?)",
        (DIAGNOSTIC_SCHEMA_VERSION,),
    )
