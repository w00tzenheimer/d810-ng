from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from d810.diagnostics.__main__ import main as diagnostics_main
from d810.diagnostics.indirect_state_transfer_map import extract_transfer_map


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE snapshots (
          id INTEGER PRIMARY KEY,
          label TEXT,
          maturity TEXT,
          phase TEXT,
          block_count INTEGER
        );
        CREATE TABLE blocks (
          snapshot_id INTEGER,
          serial INTEGER,
          type_name TEXT,
          nsucc INTEGER,
          npred INTEGER,
          succs TEXT,
          preds TEXT,
          start_ea_hex TEXT,
          end_ea_hex TEXT
        );
        CREATE TABLE instructions (
          snapshot_id INTEGER,
          block_serial INTEGER,
          insn_index INTEGER,
          ea_hex TEXT,
          ea_i64 INTEGER,
          opcode_name TEXT,
          dest_type TEXT,
          dest_stkoff INTEGER,
          dest_size INTEGER,
          src_l_type TEXT,
          src_l_stkoff INTEGER,
          src_l_value_i64 INTEGER,
          src_r_type TEXT,
          src_r_stkoff INTEGER,
          src_r_value_i64 INTEGER,
          dstr TEXT,
          meta TEXT
        );
        CREATE TABLE state_dispatcher_rows (
          snapshot_id INTEGER,
          dispatcher_kind TEXT,
          dispatcher_entry_block INTEGER,
          row_index INTEGER,
          state_const_i64 INTEGER,
          state_const_hex TEXT,
          target_block INTEGER,
          branch_kind TEXT,
          payload_json TEXT
        );
        """
    )


def _insert_block(
    conn: sqlite3.Connection,
    serial: int,
    *,
    succs: tuple[int, ...] = (),
    preds: tuple[int, ...] = (),
) -> None:
    conn.execute(
        """
        INSERT INTO blocks (
          snapshot_id, serial, type_name, nsucc, npred, succs, preds,
          start_ea_hex, end_ea_hex
        )
        VALUES (1, ?, 'BLT_0WAY', ?, ?, ?, ?, ?, ?)
        """,
        (
            serial,
            len(succs),
            len(preds),
            json.dumps(list(succs)),
            json.dumps(list(preds)),
            f"0x{0x180000000 + serial:x}",
            f"0x{0x180000010 + serial:x}",
        ),
    )


def _insert_state_write(
    conn: sqlite3.Connection,
    block: int,
    value: int,
    *,
    index: int = 0,
    dest_stkoff: int = 0x30,
    dest_size: int = 4,
) -> None:
    conn.execute(
        """
        INSERT INTO instructions (
          snapshot_id, block_serial, insn_index, ea_hex, ea_i64, opcode_name,
          dest_type, dest_stkoff, dest_size, src_l_type, src_l_stkoff,
          src_l_value_i64, src_r_type, src_r_stkoff, src_r_value_i64, dstr, meta
        )
        VALUES (1, ?, ?, ?, ?, 'm_mov', 'mop_S', ?, ?, 'mop_n', NULL, ?,
                NULL, NULL, NULL, ?, NULL)
        """,
        (
            block,
            index,
            f"0x{0x180010000 + block + index:x}",
            0x180010000 + block + index,
            dest_stkoff,
            dest_size,
            value,
            f"%var_{dest_stkoff:x}.{dest_size} = #{value:x}",
        ),
    )


def _insert_dispatch_row(
    conn: sqlite3.Connection,
    state: int,
    target: int,
    *,
    row_index: int,
) -> None:
    conn.execute(
        """
        INSERT INTO state_dispatcher_rows (
          snapshot_id, dispatcher_kind, dispatcher_entry_block, row_index,
          state_const_i64, state_const_hex, target_block, branch_kind,
          payload_json
        )
        VALUES (1, 'INDIRECT_JUMP', 99, ?, ?, ?, ?, 'indirect',
                json_object('target_ea_hex', ?))
        """,
        (row_index, state, f"0x{state:x}", target, f"0x{0x180000000 + target:x}"),
    )


def _insert_call_with_table_setup_meta(conn: sqlite3.Connection, block: int) -> None:
    meta = {
        "opcode": 56,
        "opcode_name": "m_call",
        "call_setup_registers": [
            {
                "register": 16,
                "register_name": "rdx",
                "source": {
                    "type": "mop_a",
                    "sub_operand": {
                        "type": "mop_v",
                        "global_ea": "0x180019f10",
                    },
                },
            },
            {
                "register": 24,
                "register_name": "rcx",
                "source": {
                    "type": "mop_a",
                    "sub_operand": {
                        "type": "mop_S",
                        "stkoff": 0x70,
                    },
                },
            },
            {
                "register": 72,
                "register_name": "r8",
                "source": {
                    "type": "mop_n",
                    "value": 0x20,
                },
            },
        ],
    }
    conn.execute(
        """
        INSERT INTO instructions (
          snapshot_id, block_serial, insn_index, ea_hex, ea_i64, opcode_name,
          dest_type, dest_stkoff, dest_size, src_l_type, src_l_stkoff,
          src_l_value_i64, src_r_type, src_r_stkoff, src_r_value_i64, dstr, meta
        )
        VALUES (1, ?, 9, ?, ?, 'm_call', NULL, NULL, NULL, 'mop_v', NULL, NULL,
                NULL, NULL, NULL, 'call $0x180000000', ?)
        """,
        (
            block,
            f"0x{0x180020000 + block:x}",
            0x180020000 + block,
            json.dumps(meta, sort_keys=True),
        ),
    )


def _base_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "tigress_indirect.diag.sqlite3"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        conn.execute(
            "INSERT INTO snapshots VALUES (1, 'maturity_MMAT_LOCOPT_pre_d810', "
            "'MMAT_LOCOPT', 'pre_d810', 6)"
        )
        _insert_block(conn, 99)
        conn.commit()
    finally:
        conn.close()
    return db_path


def test_extracts_direct_conditional_and_terminal_transfers(tmp_path: Path) -> None:
    db_path = _base_db(tmp_path)
    conn = sqlite3.connect(db_path)
    try:
        _insert_block(conn, 10, succs=(99,), preds=())
        _insert_block(conn, 20, succs=(21, 22), preds=())
        _insert_block(conn, 21, succs=(99,), preds=(20,))
        _insert_block(conn, 22, succs=(99,), preds=(20,))
        _insert_block(conn, 30, succs=(), preds=())
        _insert_state_write(conn, 10, 2)
        _insert_state_write(conn, 21, 3)
        _insert_state_write(conn, 22, 4)
        _insert_dispatch_row(conn, 1, 10, row_index=0)
        _insert_dispatch_row(conn, 2, 20, row_index=1)
        _insert_dispatch_row(conn, 3, 30, row_index=2)
        conn.commit()
    finally:
        conn.close()

    report = extract_transfer_map(db_path, table_count=4)

    assert report["z3_bounds_proof"]["proved_non_negative_index"] is True
    assert report["z3_bounds_proof"]["proved_table_upper_bound"] is True
    assert report["table_invariance"]["proved_invariant"] is True
    assert report["transfer_kind_counts"] == {
        "conditional": 1,
        "direct": 1,
        "terminal": 1,
    }
    by_state = {transfer["state"]: transfer for transfer in report["transfers"]}
    assert by_state[1]["kind"] == "direct"
    assert by_state[1]["next_states"] == [2]
    assert by_state[2]["kind"] == "conditional"
    assert by_state[2]["next_states"] == [3, 4]
    assert by_state[3]["kind"] == "terminal"


def test_diagnostics_cli_exposes_indirect_transfer_map(
    tmp_path: Path,
    capsys,
) -> None:
    db_path = _base_db(tmp_path)
    conn = sqlite3.connect(db_path)
    try:
        _insert_block(conn, 10, succs=(99,), preds=())
        _insert_state_write(conn, 10, 2)
        _insert_dispatch_row(conn, 1, 10, row_index=0)
        conn.commit()
    finally:
        conn.close()

    rc = diagnostics_main(
        [
            "indirect-transfer-map",
            "--db",
            str(db_path),
            "--table-count",
            "4",
            "--json",
        ]
    )

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["transfer_kind_counts"] == {"direct": 1}


def test_d810cli_exposes_indirect_transfer_map_help() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    result = subprocess.run(
        [
            sys.executable,
            str(repo_root / "tools" / "d810cli.py"),
            "indirect-transfer-map",
            "--help",
        ],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )

    assert result.returncode == 0
    assert "indirect-dispatcher state-transfer map" in result.stdout


def test_table_invariance_rejects_overlapping_stack_write(tmp_path: Path) -> None:
    db_path = _base_db(tmp_path)
    conn = sqlite3.connect(db_path)
    try:
        _insert_block(conn, 10, succs=(99,), preds=())
        _insert_state_write(conn, 10, 2)
        _insert_state_write(
            conn,
            10,
            0x180020000,
            index=1,
            dest_stkoff=0x78,
            dest_size=8,
        )
        _insert_dispatch_row(conn, 1, 10, row_index=0)
        conn.commit()
    finally:
        conn.close()

    report = extract_transfer_map(db_path, table_count=4)

    assert report["table_invariance"]["proved_invariant"] is False
    assert report["table_invariance"]["explicit_overlapping_writes"] == [
        {
            "block": 10,
            "ea": "0x18001000b",
            "dest_stkoff": 0x78,
            "dest_size": 8,
            "dstr": "%var_78.8 = #180020000",
        }
    ]


def test_table_invariance_records_initializer_from_call_setup_meta(
    tmp_path: Path,
) -> None:
    db_path = _base_db(tmp_path)
    conn = sqlite3.connect(db_path)
    try:
        _insert_block(conn, 10, succs=(99,), preds=())
        _insert_state_write(conn, 10, 2)
        _insert_call_with_table_setup_meta(conn, 10)
        _insert_dispatch_row(conn, 1, 10, row_index=0)
        conn.commit()
    finally:
        conn.close()

    report = extract_transfer_map(db_path, table_count=4)

    assert report["table_invariance"]["proved_invariant"] is True
    assert report["table_invariance"]["initializer_calls"] == [
        {
            "block": 10,
            "ea": "0x18002000a",
            "dstr": "call $0x180000000",
            "dest_stkoff": 0x70,
            "source_global_ea": "0x180019f10",
            "byte_count": 0x20,
            "proof": "call_setup_registers",
        }
    ]
