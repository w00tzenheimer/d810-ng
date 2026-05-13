from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from d810.core.diag.schema import create_tables
from tools.residual_dispatcher_worksheet import (
    build_residual_dispatcher_worksheet,
    parse_residual_log_events,
    render_markdown,
)

FUNC_EA = 0x1000


def _insert_snapshot(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int,
    label: str,
    phase: str,
    block_count: int,
    maturity: str = "MMAT_GLBOPT1",
) -> None:
    conn.execute(
        "INSERT INTO snapshots VALUES (?,?,?,?,?,?,?,?)",
        (
            snapshot_id,
            label,
            f"0x{FUNC_EA:016x}",
            FUNC_EA,
            maturity,
            phase,
            block_count,
            float(snapshot_id),
        ),
    )


def _insert_block(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int,
    serial: int,
    type_name: str,
    succs: list[int],
    preds: list[int],
) -> None:
    conn.execute(
        "INSERT INTO blocks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            snapshot_id,
            serial,
            1,
            type_name,
            None,
            None,
            None,
            None,
            len(succs),
            len(preds),
            json.dumps(succs),
            json.dumps(preds),
            0,
            "{}",
        ),
    )


def _insert_instruction(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int,
    block_serial: int,
    insn_index: int,
    opcode_name: str,
    dest_stkoff: int | None,
    src_l_value_hex: str | None,
    dstr: str,
) -> None:
    conn.execute(
        "INSERT INTO instructions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            snapshot_id,
            block_serial,
            insn_index,
            "0x0000000000000000",
            0,
            0,
            opcode_name,
            "mop_S" if dest_stkoff is not None else None,
            dest_stkoff,
            None,
            None,
            None,
            src_l_value_hex,
            None,
            None,
            None,
            None,
            None,
            dstr,
            None,
        ),
    )


def _write_diag_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        create_tables(conn)

        _insert_snapshot(
            conn,
            snapshot_id=1,
            label="maturity_MMAT_GLBOPT1_post_d810",
            phase="post_d810",
            block_count=4,
        )
        _insert_block(conn, snapshot_id=1, serial=50, type_name="BLT_1WAY", succs=[99], preds=[20])
        _insert_block(conn, snapshot_id=1, serial=90, type_name="BLT_1WAY", succs=[120], preds=[99])
        _insert_block(conn, snapshot_id=1, serial=99, type_name="BLT_1WAY", succs=[90], preds=[50])
        _insert_block(conn, snapshot_id=1, serial=120, type_name="BLT_STOP", succs=[], preds=[90])
        _insert_instruction(
            conn,
            snapshot_id=1,
            block_serial=50,
            insn_index=0,
            opcode_name="m_mov",
            dest_stkoff=0x660,
            src_l_value_hex="0x00000000deadbeef",
            dstr="vState = 0xDEADBEEF",
        )
        _insert_instruction(
            conn,
            snapshot_id=1,
            block_serial=50,
            insn_index=1,
            opcode_name="m_goto",
            dest_stkoff=None,
            src_l_value_hex=None,
            dstr="goto dispatcher",
        )
        conn.execute(
            "INSERT INTO rendered_programs VALUES (?,?,?,?,?,?,?,?,?)",
            (
                1,
                "semantic_reference_like",
                "semantic",
                "local_boundary_selective",
                "state_family",
                "inline_single_level",
                "minimal",
                3,
                1,
            ),
        )
        conn.execute(
            "INSERT INTO rendered_program_nodes VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                1,
                "semantic_reference_like",
                0,
                "STATE_DEADBEEF",
                "state_family",
                "STATE_DEADBEEF",
                90,
                90,
                None,
                1,
                3,
            ),
        )
        conn.executemany(
            "INSERT INTO rendered_program_lines VALUES (?,?,?,?,?,?,?,?)",
            [
                (1, "semantic_reference_like", 1, 0, 0, "label", None, "STATE_DEADBEEF:"),
                (
                    1,
                    "semantic_reference_like",
                    2,
                    0,
                    1,
                    "statement",
                    None,
                    "    call sub_1800164E0();",
                ),
                (
                    1,
                    "semantic_reference_like",
                    3,
                    0,
                    1,
                    "goto",
                    "EXIT_ROUTINE",
                    "    goto EXIT_ROUTINE;",
                ),
            ],
        )

        _insert_snapshot(
            conn,
            snapshot_id=2,
            label="linearized_flow_graph_state_write_reconstruction_post_apply",
            phase="post_apply",
            block_count=0,
        )
        conn.execute(
            "INSERT INTO dag_edges VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                2,
                0,
                "0x00000000deadbeef",
                None,
                "0x00000000deadbeef",
                None,
                "TRANSITION",
                50,
                None,
                90,
                json.dumps([50, 99, 90]),
            ),
        )
        conn.execute(
            "INSERT INTO modifications VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                2,
                0,
                "RedirectGoto",
                50,
                90,
                99,
                None,
                None,
                None,
                "emitted",
                "",
            ),
        )

        _insert_snapshot(
            conn,
            snapshot_id=3,
            label="post_gut_and_wire",
            phase="post_gut_wire",
            block_count=0,
        )
        conn.executemany(
            "INSERT INTO block_classification VALUES (?,?,?,?,?,?)",
            [
                (3, 50, 0, 1, 0, 1),
                (3, 90, 0, 1, 0, 0),
                (3, 99, 1, 1, 0, 0),
                (3, 120, 0, 1, 0, 0),
            ],
        )
        conn.commit()
    finally:
        conn.close()


def _write_recon_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE recon_results (
                func_ea INTEGER NOT NULL,
                maturity INTEGER NOT NULL,
                collector_name TEXT NOT NULL,
                timestamp REAL NOT NULL,
                metrics_json TEXT NOT NULL,
                candidates_json TEXT NOT NULL,
                PRIMARY KEY (func_ea, maturity, collector_name)
            );
            CREATE TABLE consumer_outcomes (
                func_ea INTEGER NOT NULL,
                consumer_name TEXT NOT NULL,
                timestamp REAL NOT NULL,
                artifacts_available INTEGER NOT NULL DEFAULT 0,
                summary_available INTEGER NOT NULL DEFAULT 0,
                verdict_applied INTEGER NOT NULL DEFAULT 0,
                detail TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (func_ea, consumer_name)
            );
            """
        )
        transition_report = {
            "dispatcher_entry_serial": 99,
            "state_var_stkoff": 0x660,
            "bst_node_blocks": [99],
        }
        conn.execute(
            "INSERT INTO recon_results VALUES (?,?,?,?,?,?)",
            (
                FUNC_EA,
                5,
                "handler_transitions",
                1.0,
                json.dumps({"transition_report": transition_report}),
                "[]",
            ),
        )
        provenance = {
            "rows": [
                {
                    "strategy_name": "linearized_flow_graph",
                    "phase": "applied",
                    "reason_code": "accepted",
                    "reason": "accepted",
                    "notes": "claimed residual handoff",
                    "ownership_blocks": [50],
                }
            ]
        }
        conn.execute(
            "INSERT INTO consumer_outcomes VALUES (?,?,?,?,?,?,?,?)",
            (
                FUNC_EA,
                "hodur_planner",
                2.0,
                1,
                1,
                1,
                "1 applied",
                json.dumps(provenance),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_parse_residual_log_events_parses_supported_residual_lines() -> None:
    log_text = """
    INFO LFG DAG: residual dispatcher handoff blk[50] -> blk[90] (state 0xDEADBEEF)
    INFO LFG DAG: residual dispatcher pred-split blk[60] via blk[58] -> blk[91] (state 0x11111111)
    INFO LFG DAG: residual prefix handoff blk[44] -> blk[77] (bypassing blk[88] via CONDITIONAL_TRANSITION)
    INFO LFG DAG: residual handoff blk[22] -> blk[33] suppressed because an earlier conditional corridor already owns state 0x000000FF
    """.strip()

    events = parse_residual_log_events(log_text)

    assert [event.source_block for event in events] == [50, 60, 88, 22]
    assert events[0].note == "handoff -> blk[90] state=0xDEADBEEF"
    assert events[1].via_pred == 58
    assert events[2].note == "prefix via blk[44] -> blk[77] (conditional_transition)"
    assert events[3].state_value == 0xFF


def test_parse_residual_log_events_parses_unresolved_dispatcher_predecessor_tuple() -> None:
    log_text = """
    INFO Skipping post-apply BST cleanup because unresolved non-BST dispatcher predecessors remain: {'semantic_exact_node_all_plannable_edges': (10, 45, 195, 203, 208)}
    """.strip()

    events = parse_residual_log_events(log_text)

    assert [event.source_block for event in events] == [10, 45, 195, 203, 208]
    assert all(
        event.note == "unresolved dispatcher predecessor (semantic_exact_node_all_plannable_edges)"
        for event in events
    )


def test_build_residual_dispatcher_worksheet_prefers_log_note_and_rendered_corridor(
    tmp_path: Path,
) -> None:
    diag_db = tmp_path / "sample.diag.sqlite3"
    recon_db = tmp_path / "d810_recon.db"
    log_path = tmp_path / "sub_7FFD_dump.txt"
    _write_diag_db(diag_db)
    _write_recon_db(recon_db)
    log_path.write_text(
        "INFO LFG DAG: residual dispatcher handoff blk[50] -> blk[90] (state 0xDEADBEEF)\n",
        encoding="utf-8",
    )

    result = build_residual_dispatcher_worksheet(
        diag_db_path=diag_db,
        recon_db_path=recon_db,
        log_path=log_path,
        func_ea=FUNC_EA,
    )

    assert [row.block for row in result.rows] == [50]
    row = result.rows[0]
    assert "write state=0x00000000deadbeef" in row.post_pipeline_microcode_meaning
    assert "STATE_DEADBEEF" in row.semantic_state_corridor
    assert "call sub_1800164E0();" in row.semantic_state_corridor
    assert row.dag_provenance_note.startswith("handoff -> blk[90] state=0xDEADBEEF")

    rendered = render_markdown(result)
    assert "| blk[50] |" in rendered
    assert "Snapshot: [1] maturity_MMAT_GLBOPT1_post_d810" in rendered


def test_build_residual_dispatcher_worksheet_falls_back_to_dispatcher_preds_without_log(
    tmp_path: Path,
) -> None:
    diag_db = tmp_path / "sample.diag.sqlite3"
    recon_db = tmp_path / "d810_recon.db"
    _write_diag_db(diag_db)
    _write_recon_db(recon_db)

    result = build_residual_dispatcher_worksheet(
        diag_db_path=diag_db,
        recon_db_path=recon_db,
        log_path=None,
        func_ea=FUNC_EA,
    )

    assert [row.block for row in result.rows] == [50]
    assert "planner applied linearized_flow_graph" in result.rows[0].dag_provenance_note
