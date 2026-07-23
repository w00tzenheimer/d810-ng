from __future__ import annotations

import sqlite3

import pytest

from d810.core.diag import (
    DIAGNOSTIC_SCHEMA_VERSION,
    DiagnosticSchemaMismatch,
    create_diag_database,
    open_diag_database,
)


def _write_version(path: str, version: int | None) -> None:
    conn = sqlite3.connect(path)
    if version is not None:
        conn.execute(
            "CREATE TABLE diagnostic_schema (singleton INTEGER PRIMARY KEY, version INTEGER NOT NULL)"
        )
        conn.execute("INSERT INTO diagnostic_schema VALUES (1, ?)", (version,))
    else:
        conn.execute("CREATE TABLE snapshots (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()


@pytest.mark.parametrize("version", [None, 1, 2, 3, 5])
def test_reader_rejects_noncurrent_schema_without_mutating_file(
    tmp_path, version: int | None
) -> None:
    path = tmp_path / f"schema-{version}.sqlite3"
    _write_version(str(path), version)
    before = path.read_bytes()

    with pytest.raises(DiagnosticSchemaMismatch) as exc_info:
        open_diag_database(str(path))

    assert exc_info.value.expected == DIAGNOSTIC_SCHEMA_VERSION
    assert exc_info.value.observed == version
    assert exc_info.value.path == str(path)
    assert path.read_bytes() == before


def test_writer_creates_only_current_schema_without_legacy_views() -> None:
    db = create_diag_database(":memory:")
    conn = db.connection()
    assert conn.execute(
        "SELECT version FROM diagnostic_schema WHERE singleton=1"
    ).fetchone() == (DIAGNOSTIC_SCHEMA_VERSION,)
    assert conn.execute("PRAGMA user_version").fetchone() == (
        DIAGNOSTIC_SCHEMA_VERSION,
    )
    legacy = conn.execute(
        "SELECT name FROM sqlite_master WHERE name LIKE 'dag_%'"
    ).fetchall()
    assert legacy == []
