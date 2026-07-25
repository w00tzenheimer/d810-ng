"""Read-only ORM access to a current diagnostic DB.

The developer-CLI reader modules inspect existing ``.diag.sqlite3`` files and
must NOT mutate them. ``open_diag_database`` binds the peewee Models to a fresh
connection WITHOUT running DDL/migration, so ``Model.select()`` works while the
inspected DB stays byte-unchanged. Non-current schemas are rejected.
"""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import d810.core.diag as diag

from d810.core.diag import (
    create_diag_database,
    diag_models_on,
    open_diag_database,
)
from d810.core.diag.models import Snapshot


def test_open_diag_session_is_idempotent_for_nested_hexrays_prologs(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(
        diag,
        "get_settings",
        lambda: SimpleNamespace(diag_snapshots=True),
    )
    try:
        diag.open_diag_session(0x40C8B0, log_dir=str(tmp_path))
        first = diag.get_diag_db(0x40C8B0, log_dir=str(tmp_path))

        # Generated/PREOPT re-entry and nested callbacks belong to the same
        # top-level diagnostic authority; they must not rotate the sink.
        diag.open_diag_session(0x40CD8C, log_dir=str(tmp_path))
        second = diag.get_diag_db(0x40CD8C, log_dir=str(tmp_path))

        assert second is first
    finally:
        diag.close_diag_session()


def _seed(path: str) -> None:
    # Write path: create_diag_database no longer applies a global Model bind, so
    # the ORM write binds explicitly (production writers bind the same way).
    wdb = create_diag_database(path)
    with diag_models_on(wdb):
        Snapshot.create(
            label="s",
            func_ea_hex="0x1000",
            func_ea_i64=0x1000,
            maturity="MMAT_GLBOPT1",
            phase="unknown",
            block_count=3,
            timestamp=0.0,
        )
    wdb.close()


def test_orm_reads_work_on_adopted_connection(tmp_path) -> None:
    p = str(tmp_path / "x.diag.sqlite3")
    _seed(p)
    db = open_diag_database(p)
    try:
        assert Snapshot.select().count() == 1
        assert Snapshot.select().first().label == "s"
    finally:
        db.close()


def test_open_is_non_mutating(tmp_path) -> None:
    p = str(tmp_path / "y.diag.sqlite3")
    _seed(p)
    before = (
        sqlite3.connect(p).execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0]
    )
    db = open_diag_database(p)
    try:
        Snapshot.select().count()  # a read must not alter schema
    finally:
        db.close()
    after = (
        sqlite3.connect(p).execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0]
    )
    assert before == after  # no DDL/migration ran
