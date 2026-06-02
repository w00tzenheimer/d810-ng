"""open_diag_database: read-only ORM access to an existing diag DB (llr-ohvr).

The developer-CLI reader modules inspect existing ``.diag.sqlite3`` files and
must NOT mutate them. ``open_diag_database`` binds the peewee Models to a fresh
connection WITHOUT running DDL/migration, so ``Model.select()`` works while the
inspected DB stays byte-unchanged (contrast ``create_diag_database``, the write
path, which creates + migrates).
"""
from __future__ import annotations

import sqlite3

from d810.core.diag import create_diag_database, open_diag_database
from d810.core.diag.models import Snapshot


def _seed(path: str) -> None:
    wdb = create_diag_database(path)
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
    before = sqlite3.connect(p).execute(
        "SELECT COUNT(*) FROM sqlite_master"
    ).fetchone()[0]
    db = open_diag_database(p)
    try:
        Snapshot.select().count()  # a read must not alter schema
    finally:
        db.close()
    after = sqlite3.connect(p).execute(
        "SELECT COUNT(*) FROM sqlite_master"
    ).fetchone()[0]
    assert before == after  # no DDL/migration ran
