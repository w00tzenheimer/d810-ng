"""open_diag_database: read-only ORM access to an existing diag DB (llr-ohvr).

The developer-CLI reader modules inspect existing ``.diag.sqlite3`` files and
must NOT mutate them. ``open_diag_database`` binds the peewee Models to a fresh
connection WITHOUT running DDL/migration, so ``Model.select()`` works while the
inspected DB stays byte-unchanged (contrast ``create_diag_database``, the write
path, which creates + migrates).
"""
from __future__ import annotations

import sqlite3

from d810.core.diag import (
    create_diag_database,
    diag_models_on,
    open_diag_database,
)
from d810.core.diag.models import Snapshot, StateCfgEdge


def test_legacy_dag_schema_db_is_orm_readable_non_mutatingly(tmp_path) -> None:
    """A pre-migration DB (``dag_*`` base tables, no ``state_cfg_*``) is readable
    via the ORM through the TEMP-VIEW overlay, without mutating the file."""
    import sqlite3

    p = str(tmp_path / "legacy.diag.sqlite3")
    conn = sqlite3.connect(p)
    conn.executescript(
        "CREATE TABLE dag_edges (snapshot_id INTEGER, edge_id INTEGER, "
        "source_state_hex TEXT, source_state_i64 INTEGER, target_state_hex TEXT, "
        "target_state_i64 INTEGER, edge_kind TEXT, source_block INTEGER, "
        "source_arm INTEGER, target_entry INTEGER, ordered_path TEXT);"
        "INSERT INTO dag_edges VALUES (1,0,'0x5',5,NULL,NULL,'TRANSITION',NULL,NULL,NULL,'[]');"
    )
    conn.commit()
    conn.close()
    before = sqlite3.connect(p).execute(
        "SELECT COUNT(*) FROM sqlite_master"
    ).fetchone()[0]

    db = open_diag_database(p)
    try:
        # Model targets state_cfg_edges; the overlay maps it onto dag_edges.
        assert StateCfgEdge.select().count() == 1
        assert StateCfgEdge.select().first().source_state_hex == "0x5"
    finally:
        db.close()

    after = sqlite3.connect(p).execute(
        "SELECT COUNT(*) FROM sqlite_master"
    ).fetchone()[0]
    assert before == after  # temp view only; file unchanged


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
