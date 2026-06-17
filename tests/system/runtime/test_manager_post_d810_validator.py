"""Runtime tests for post-D810 handoff validation."""

from __future__ import annotations
from d810.core.diag import create_diag_database

import sqlite3

from d810.diagnostics.post_d810_handoff import detect_post_d810_handoff_violations


FUNC_EA_I64 = 0x180012B60
FUNC_EA_HEX = "0x0000000180012B60"


def _seed_snapshot(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int,
    label: str,
    phase: str,
    block_count: int,
) -> None:
    conn.execute(
        """
        INSERT INTO snapshots
            (id, label, func_ea_hex, func_ea_i64, maturity, phase, block_count, timestamp)
        VALUES (?, ?, ?, ?, 'MMAT_GLBOPT1', ?, ?, 0.0)
        """,
        (snapshot_id, label, FUNC_EA_HEX, FUNC_EA_I64, phase, block_count),
    )


def _seed_block(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int,
    serial: int,
) -> None:
    conn.execute(
        """
        INSERT INTO blocks
            (snapshot_id, serial, block_type, type_name, start_ea_hex, start_ea_i64,
             end_ea_hex, end_ea_i64, nsucc, npred, succs, preds, insn_count, meta)
        VALUES (?, ?, 1, 'BLT_1WAY', NULL, NULL, NULL, NULL, 1, 1, '[0]', '[0]', 1, NULL)
        """,
        (snapshot_id, serial),
    )


def _seed_instruction(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int,
    block_serial: int,
    insn_index: int,
    dstr: str,
    dest_stkoff: int | None = None,
    src_l_stkoff: int | None = None,
    src_r_stkoff: int | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO instructions
            (snapshot_id, block_serial, insn_index, ea_hex, ea_i64, opcode, opcode_name,
             dest_type, dest_stkoff, dest_size, src_l_type, src_l_stkoff,
             src_l_value_hex, src_l_value_i64, src_r_type, src_r_stkoff,
             src_r_value_hex, src_r_value_i64, dstr, meta)
        VALUES (?, ?, ?, '0x0', 0, 4, 'm_mov',
                CASE WHEN ? IS NULL THEN NULL ELSE 'mop_S' END, ?, 8,
                CASE WHEN ? IS NULL THEN NULL ELSE 'mop_S' END, ?, NULL, NULL,
                CASE WHEN ? IS NULL THEN NULL ELSE 'mop_S' END, ?, NULL, NULL,
                ?, NULL)
        """,
        (
            snapshot_id,
            block_serial,
            insn_index,
            dest_stkoff,
            dest_stkoff,
            src_l_stkoff,
            src_l_stkoff,
            src_r_stkoff,
            src_r_stkoff,
            dstr,
        ),
    )


def _seed_pre_bundle(conn: sqlite3.Connection, *, snapshot_id: int) -> None:
    for serial in (80, 118):
        _seed_block(conn, snapshot_id=snapshot_id, serial=serial)
    _seed_instruction(
        conn,
        snapshot_id=snapshot_id,
        block_serial=80,
        insn_index=0,
        dstr="ldx    ds.2, %var_178.8, %var_230.8",
    )
    _seed_instruction(
        conn,
        snapshot_id=snapshot_id,
        block_serial=80,
        insn_index=1,
        dstr="mov    #-0x4B6C02C3E6626146.8, %var_678.8",
    )
    _seed_instruction(
        conn,
        snapshot_id=snapshot_id,
        block_serial=80,
        insn_index=2,
        dstr="mov    #-0x4B6C02C3E6626145.8, %var_680.8",
    )
    _seed_instruction(
        conn,
        snapshot_id=snapshot_id,
        block_serial=80,
        insn_index=3,
        dstr="mov    #0xE6334342.4, %var_108.4",
    )
    _seed_instruction(
        conn,
        snapshot_id=snapshot_id,
        block_serial=80,
        insn_index=4,
        dstr="mov    #0x1C6BAB0E.4, %var_110.4",
    )
    _seed_instruction(
        conn,
        snapshot_id=snapshot_id,
        block_serial=118,
        insn_index=0,
        dstr="add    %var_230.8, (%var_680.8-%var_678.8), %var_360.8",
    )


def test_detect_post_d810_handoff_violations_flags_live_only_use_bundle():
    conn = create_diag_database(":memory:").connection()
    _seed_snapshot(conn, snapshot_id=19, label="post_pipeline", phase="post_pipeline", block_count=223)
    _seed_snapshot(conn, snapshot_id=20, label="post_d810", phase="post_d810", block_count=44)
    _seed_pre_bundle(conn, snapshot_id=19)
    _seed_block(conn, snapshot_id=20, serial=17)
    _seed_block(conn, snapshot_id=20, serial=29)
    _seed_instruction(
        conn,
        snapshot_id=20,
        block_serial=17,
        insn_index=0,
        dstr="jnz    %var_310.8{126}, something",
        src_l_stkoff=0x4E8,
    )
    _seed_instruction(
        conn,
        snapshot_id=20,
        block_serial=29,
        insn_index=0,
        dstr="jz     something, %var_320.8, @31",
        src_r_stkoff=0x4D8,
    )

    violations = detect_post_d810_handoff_violations(
        conn,
        func_ea_i64=FUNC_EA_I64,
        maturity_name="MMAT_GLBOPT1",
        post_snapshot_id=20,
    )

    assert len(violations) == 1
    violation = violations[0]
    assert violation.bundle_name == "sub7ffd_80_118_setup_bundle"
    assert violation.pre_snapshot_id == 19
    assert violation.post_snapshot_id == 20
    assert violation.missing_def_offsets == (0x4D8, 0x4E8)
    assert any("blk[17]" in site for site in violation.use_sites)
    assert any("blk[29]" in site for site in violation.use_sites)
    assert violation.def_sites == ()


def test_detect_post_d810_handoff_violations_allows_surviving_defs():
    conn = create_diag_database(":memory:").connection()
    _seed_snapshot(conn, snapshot_id=19, label="post_pipeline", phase="post_pipeline", block_count=223)
    _seed_snapshot(conn, snapshot_id=20, label="post_d810", phase="post_d810", block_count=44)
    _seed_pre_bundle(conn, snapshot_id=19)
    _seed_block(conn, snapshot_id=20, serial=17)
    _seed_block(conn, snapshot_id=20, serial=29)
    _seed_instruction(
        conn,
        snapshot_id=20,
        block_serial=17,
        insn_index=0,
        dstr="mov    something, %var_310.8",
        dest_stkoff=0x4E8,
    )
    _seed_instruction(
        conn,
        snapshot_id=20,
        block_serial=17,
        insn_index=1,
        dstr="jnz    %var_310.8{126}, something",
        src_l_stkoff=0x4E8,
    )
    _seed_instruction(
        conn,
        snapshot_id=20,
        block_serial=29,
        insn_index=0,
        dstr="mov    something, %var_320.8",
        dest_stkoff=0x4D8,
    )
    _seed_instruction(
        conn,
        snapshot_id=20,
        block_serial=29,
        insn_index=1,
        dstr="jz     something, %var_320.8, @31",
        src_r_stkoff=0x4D8,
    )

    violations = detect_post_d810_handoff_violations(
        conn,
        func_ea_i64=FUNC_EA_I64,
        maturity_name="MMAT_GLBOPT1",
        post_snapshot_id=20,
    )

    assert violations == ()
