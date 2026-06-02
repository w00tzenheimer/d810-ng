"""peewee Models = schema source of truth for the diag DB (first slice).

Only the first table-slice (``snapshots``, ``state_cfg_nodes``,
``state_cfg_edges``) is modeled here; the remaining tables still come from
``schema._SCHEMA_SQL``. peewee owns the diag connection (see
``core/diag/__init__``); query call-sites stay raw SQL on ``db.connection()``.

Fields are declared in **exact DDL column order**; ``CompositeKey`` suppresses
peewee's implicit ``id`` auto-primary-key; FKs use ``index=False`` to match the
hand-written DDL (which has no index on the FK column). The equivalence with
the original DDL is pinned by ``tests/unit/core/diag/test_models_schema_equivalence.py``.
"""
from __future__ import annotations

from d810._vendor.peewee import (
    Check,
    CompositeKey,
    FloatField,
    ForeignKeyField,
    IntegerField,
    Model,
    SqliteDatabase,
    TextField,
)

# Deferred database: bound to the live diag connection at session-open time
# (core/diag/__init__ calls ``diag_db.init(path)`` / binds it). A deferred
# SqliteDatabase still carries the SQLite SQL dialect for DDL generation.
diag_db = SqliteDatabase(None)


class BaseModel(Model):
    class Meta:
        database = diag_db


class Snapshot(BaseModel):
    # ``id INTEGER PRIMARY KEY`` -> peewee's implicit AutoField ``id`` (first column).
    label = TextField()
    func_ea_hex = TextField()
    func_ea_i64 = IntegerField()
    maturity = TextField()
    phase = TextField(
        default="unknown",
        constraints=[
            Check(
                "phase IN ('pre_d810','post_apply','post_gut_wire',"
                "'post_pipeline','post_d810','unknown')"
            )
        ],
    )
    block_count = IntegerField()
    timestamp = FloatField()

    class Meta:
        table_name = "snapshots"


class StateCfgNode(BaseModel):
    snapshot = ForeignKeyField(
        Snapshot, field="id", column_name="snapshot_id", index=False, null=False
    )
    state_hex = TextField()
    state_i64 = IntegerField()
    entry_block = IntegerField()
    classification = TextField()
    shared_suffix = TextField(null=True)

    class Meta:
        table_name = "state_cfg_nodes"
        primary_key = CompositeKey("snapshot", "state_hex")


class StateCfgEdge(BaseModel):
    snapshot = ForeignKeyField(
        Snapshot, field="id", column_name="snapshot_id", index=False, null=False
    )
    edge_id = IntegerField()
    source_state_hex = TextField(null=True)
    source_state_i64 = IntegerField(null=True)
    target_state_hex = TextField(null=True)
    target_state_i64 = IntegerField(null=True)
    edge_kind = TextField(
        constraints=[
            Check(
                "edge_kind IN ('TRANSITION','CONDITIONAL_TRANSITION',"
                "'CONDITIONAL_RETURN','EXIT_ROUTINE','UNKNOWN')"
            )
        ]
    )
    source_block = IntegerField(null=True)
    source_arm = IntegerField(null=True)
    target_entry = IntegerField(null=True)
    ordered_path = TextField()

    class Meta:
        table_name = "state_cfg_edges"
        primary_key = CompositeKey("snapshot", "edge_id")


# Tables modeled in this slice (order matters: Snapshot first for FK targets).
MODELS = (Snapshot, StateCfgNode, StateCfgEdge)
