"""SQLite schema for MBA diagnostic snapshots."""
from __future__ import annotations

import sqlite3

_SCHEMA_SQL = """\
-- Layer 1: Universal MBA State

-- One row per snapshot checkpoint
CREATE TABLE IF NOT EXISTS snapshots (
    id          INTEGER PRIMARY KEY,
    label       TEXT NOT NULL,
    func_ea     INTEGER NOT NULL,
    maturity    TEXT NOT NULL,
    block_count INTEGER NOT NULL,
    timestamp   REAL NOT NULL
);

-- One row per microcode block
CREATE TABLE IF NOT EXISTS blocks (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
    serial      INTEGER NOT NULL,
    block_type  INTEGER NOT NULL,
    type_name   TEXT NOT NULL,
    start_ea    INTEGER,
    end_ea      INTEGER,
    nsucc       INTEGER NOT NULL,
    npred       INTEGER NOT NULL,
    succs       TEXT NOT NULL,
    preds       TEXT NOT NULL,
    insn_count  INTEGER NOT NULL,
    meta        TEXT,
    PRIMARY KEY (snapshot_id, serial)
);

-- One row per microcode instruction
CREATE TABLE IF NOT EXISTS instructions (
    snapshot_id   INTEGER NOT NULL REFERENCES snapshots(id),
    block_serial  INTEGER NOT NULL,
    insn_index    INTEGER NOT NULL,
    ea            INTEGER NOT NULL,
    opcode        INTEGER NOT NULL,
    opcode_name   TEXT NOT NULL,
    dest_type     TEXT,
    dest_stkoff   INTEGER,
    dest_size     INTEGER,
    src_l_type    TEXT,
    src_l_stkoff  INTEGER,
    src_l_value   INTEGER,
    src_r_type    TEXT,
    src_r_stkoff  INTEGER,
    src_r_value   INTEGER,
    dstr          TEXT,
    meta          TEXT,
    PRIMARY KEY (snapshot_id, block_serial, insn_index)
);

-- Derived: which instructions write to a given stack variable
CREATE VIEW IF NOT EXISTS var_writes AS
SELECT i.*, b.succs, b.preds
FROM instructions i
JOIN blocks b ON i.snapshot_id = b.snapshot_id AND i.block_serial = b.serial
WHERE i.dest_type = 'mop_S';

-- Index for fast variable provenance queries
CREATE INDEX IF NOT EXISTS idx_insn_dest_stkoff
    ON instructions(snapshot_id, dest_stkoff);
CREATE INDEX IF NOT EXISTS idx_insn_opcode
    ON instructions(snapshot_id, opcode_name);

-- Layer 2: Strategy Metadata

-- DAG nodes (one per handler state)
CREATE TABLE IF NOT EXISTS dag_nodes (
    snapshot_id     INTEGER NOT NULL REFERENCES snapshots(id),
    state           INTEGER NOT NULL,
    state_hex       TEXT NOT NULL,
    entry_block     INTEGER NOT NULL,
    classification  TEXT NOT NULL,
    shared_suffix   TEXT,
    PRIMARY KEY (snapshot_id, state)
);

-- DAG edges (one per transition)
CREATE TABLE IF NOT EXISTS dag_edges (
    snapshot_id       INTEGER NOT NULL REFERENCES snapshots(id),
    edge_id           INTEGER NOT NULL,
    source_state      INTEGER,
    target_state      INTEGER,
    edge_kind         TEXT NOT NULL CHECK(edge_kind IN (
        'TRANSITION',
        'CONDITIONAL_TRANSITION',
        'CONDITIONAL_RETURN',
        'EXIT_ROUTINE',
        'UNKNOWN'
    )),
    source_block      INTEGER,
    source_arm        INTEGER,
    target_entry      INTEGER,
    ordered_path      TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, edge_id)
);

-- Reconstruction modifications (one per emitted mod)
CREATE TABLE IF NOT EXISTS modifications (
    snapshot_id     INTEGER NOT NULL REFERENCES snapshots(id),
    mod_index       INTEGER NOT NULL,
    mod_type        TEXT NOT NULL,
    source_block    INTEGER,
    target_block    INTEGER,
    old_target      INTEGER,
    write_site_ea   INTEGER,
    write_site_blk  INTEGER,
    status          TEXT NOT NULL,
    reason          TEXT,
    PRIMARY KEY (snapshot_id, mod_index)
);

-- Block classification (reachability, BST membership, gut status)
CREATE TABLE IF NOT EXISTS block_classification (
    snapshot_id   INTEGER NOT NULL REFERENCES snapshots(id),
    serial        INTEGER NOT NULL,
    is_bst        INTEGER NOT NULL DEFAULT 0,
    is_reachable  INTEGER NOT NULL DEFAULT 1,
    is_gutted     INTEGER NOT NULL DEFAULT 0,
    in_claimed    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (snapshot_id, serial)
);
"""


def create_tables(conn: sqlite3.Connection) -> None:
    """Create all diagnostic snapshot tables, views, and indexes.

    Uses IF NOT EXISTS so this is safe to call multiple times (idempotent).
    """
    conn.executescript(_SCHEMA_SQL)
