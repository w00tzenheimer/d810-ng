"""Unit tests for the ``route`` BST-route provenance diagnostic.

Pure: builds a synthetic in-memory diag DB (no IDA, no real run) with a tiny
dispatcher BST and asserts the reconstructed route + provenance.
"""
from __future__ import annotations

import sqlite3

import pytest

from d810.diagnostics.state_route import (
    build_decision_dag_from_diag,
    format_provenance,
    route_state,
)

SNAP = 5


def _make_db() -> sqlite3.Connection:
    """A 1-node BST: blk3 ``jg #0x100`` -> blk10 (state>0x100, BLT_STOP) else blk4.

    blk4 falls through to blk5 (a 1-way handler corridor, not terminal).
    A literal writer (blk20 ``mov #0x200``) produces state 0x200; the recovery
    rows deliberately mis-record 0x200 -> blk99 to exercise the disagreement flag.
    """
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE blocks(
            snapshot_id INTEGER, serial INTEGER, succs TEXT,
            type_name TEXT, start_ea_hex TEXT);
        CREATE TABLE instructions(
            snapshot_id INTEGER, block_serial INTEGER, dstr TEXT, ea_hex TEXT,
            dest_stkoff INTEGER, src_l_value_i64 INTEGER, src_l_value_hex TEXT,
            opcode_name TEXT);
        CREATE TABLE dag_edges(
            snapshot_id INTEGER, target_state_i64 INTEGER, target_entry INTEGER);
        CREATE TABLE state_dispatcher_rows(
            snapshot_id INTEGER, state_const_i64 INTEGER, target_block INTEGER);
        """
    )
    conn.executemany(
        "INSERT INTO blocks VALUES(?,?,?,?,?)",
        [
            (SNAP, 3, "[4, 10]", "BLT_2WAY", "0x1000"),
            (SNAP, 10, "[]", "BLT_STOP", "0x1100"),
            (SNAP, 4, "[5]", "BLT_1WAY", "0x1200"),
            (SNAP, 5, "[3]", "BLT_1WAY", "0x1300"),
            (SNAP, 20, "[3]", "BLT_1WAY", "0x2000"),
        ],
    )
    conn.executemany(
        "INSERT INTO instructions VALUES(?,?,?,?,?,?,?,?)",
        [
            # root comparison: jg #0x100, @10  (taken when state > 0x100)
            (SNAP, 3, "jg     eax.4, #0x100.4, @10", "0x1000", None, None, None, "op_jg"),
            # leaf entry EAs (first insn per block)
            (SNAP, 10, "stx    rax, ds, var", "0x1100", None, None, None, "op_stx"),
            (SNAP, 4, "mov    #1, eax", "0x1200", None, None, None, "op_mov"),
            # literal writer of state 0x200
            (SNAP, 20, "mov    #0x200.4, %var_694.4", "0x2000", 52, 0x200, "0x0000000000000200", "op_mov"),
        ],
    )
    # recovery deliberately mis-records 0x200 -> blk99 (route says blk10)
    conn.execute("INSERT INTO dag_edges VALUES(?,?,?)", (6, 0x200, 99))
    conn.commit()
    return conn


def test_build_decision_dag_extracts_root_comparison():
    conn = _make_db()
    dag = build_decision_dag_from_diag(conn, SNAP, root=3)
    assert 3 in dag.nodes
    node = dag.nodes[3]
    assert node.op == "jg"
    assert node.const == 0x100
    assert node.true_target == 10  # @10
    assert node.false_target == 4  # the other live successor


def test_route_state_above_pivot_is_terminal():
    conn = _make_db()
    prov = route_state(conn, SNAP, 0x200, slot=52, root=3)
    # 0x200 > 0x100 -> takes the jg arm -> blk10 (BLT_STOP)
    assert prov.handler_block == 10
    assert prov.handler_ea == "0x1100"
    assert prov.reaches_stop is True
    assert prov.stop_chain == [10]
    # one BST step, took=True
    assert [(s.block, s.op, s.took) for s in prov.path] == [(3, "jg", True)]
    # literal writer recorded
    assert prov.literal_writers == [(20, "0x2000")]


def test_route_state_below_pivot_non_terminal():
    conn = _make_db()
    prov = route_state(conn, SNAP, 0x50, slot=52, root=3)
    assert prov.handler_block == 4  # fallthrough
    assert prov.reaches_stop is False


def test_disagreement_flag_when_recovery_target_differs():
    conn = _make_db()
    prov = route_state(conn, SNAP, 0x200, slot=52, root=3)
    # route_predicate says blk10; recovery dag_edges says blk99 -> DISAGREEMENT
    assert prov.recovery_target == 99
    assert prov.recovery_source == "dag_edges(snap6)"
    assert prov.disagreement is True
    text = format_provenance(prov)
    assert "DISAGREEMENT" in text


def test_format_is_stable_text():
    conn = _make_db()
    prov = route_state(conn, SNAP, 0x200, slot=52, root=3)
    text = format_provenance(prov)
    assert "state 0x00000200" in text
    assert "blk10" in text
    assert "exit routine" in text
