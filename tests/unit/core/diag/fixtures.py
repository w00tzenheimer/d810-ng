"""Pre-loaded diagnostic DB fixtures based on real debugging scenarios."""
from __future__ import annotations

import json
import sqlite3

from d810.core.diag.schema import create_tables
from d810.core.diag.snapshot import _dual


def create_sub_7ffd_scenario(conn: sqlite3.Connection) -> int:
    """Populate DB with the 0xACD0BD5 -> 0x432DC789 chain scenario.

    Returns snapshot_id.

    Encodes:
    - blk[131] (0xACD0BD5 handler entry) -> blk[174] (MBA check)
    - blk[174] fallthrough -> blk[175] (early return, writes var_8 from var_7C8)
    - blk[174] taken -> blk[176] -> blk[200] -> blk[23] (0x6465D165)
    - blk[23] -> blk[32] (STATE_432DC789_target body) -> blk[62] (0x432DC789)
    - blk[62] -> blk[206] (0x298372CC mask check)
    - blk[206] fallthrough -> blk[207] (m_xdu: writes var_8 from var_7BC!)
    - blk[207] -> blk[218] (return corridor) -> blk[219] (BLT_STOP)
    - blk[217] (correct return corridor: writes var_8 from var_178)
    """
    create_tables(conn)
    fh, fi = _dual(0x180012B60)
    conn.execute(
        "INSERT INTO snapshots VALUES "
        "(1, 'pass0_post_apply', ?, ?, 'MMAT_GLBOPT1', 'post_apply', 233, 0.0)",
        (fh, fi),
    )

    # Blocks with succs/preds and key meta
    blocks = [
        (131, 1, "BLT_1WAY", 1, 0, [174], [129, 148], 2, None),
        (174, 2, "BLT_2WAY", 2, 1, [175, 176], [131, 173], 1,
         '{"valranges": {"0x3C": "==ACD0BD5"}}'),
        (175, 1, "BLT_1WAY", 1, 0, [218], [174], 2, None),
        (176, 1, "BLT_1WAY", 1, 0, [200], [174], 3, None),
        (200, 1, "BLT_1WAY", 1, 0, [23], [176], 5, None),
        (23, 1, "BLT_1WAY", 1, 0, [24], [200, 170], 2,
         '{"valranges": {"0x3C": "==6465D165"}}'),
        (24, 1, "BLT_1WAY", 1, 0, [32], [23], 1, None),
        (32, 1, "BLT_1WAY", 1, 0, [62], [24], 12, None),
        (62, 1, "BLT_1WAY", 1, 0, [206], [32], 3,
         '{"valranges": {"0x3C": "==432DC789"}}'),
        (206, 2, "BLT_2WAY", 2, 1, [207, 208], [62, 204], 1,
         '{"valranges": {"0x3C": "==298372CC"}}'),
        (207, 1, "BLT_1WAY", 1, 0, [218], [206], 3, None),
        (217, 1, "BLT_1WAY", 1, 0, [218], [119, 162], 3, None),
        (218, 1, "BLT_1WAY", 1, 0, [219], [175, 207, 217], 1, None),
        (219, 0, "BLT_STOP", 0, 0, [], [218], 0, None),
    ]
    for serial, btype, tname, nsucc, npred, succs, preds, icnt, meta in blocks:
        conn.execute(
            "INSERT INTO blocks VALUES "
            "(1,?,?,?,NULL,NULL,NULL,NULL,?,?,?,?,?,?)",
            (serial, btype, tname, nsucc, len(preds),
             json.dumps(succs), json.dumps(preds), icnt, meta),
        )

    # Key instructions -- the ones that matter for variable provenance
    #
    # Tuple layout matches schema column order:
    #   block_serial, insn_index, ea_hex, ea_i64, opcode, opcode_name,
    #   dest_type, dest_stkoff, dest_size,
    #   src_l_type, src_l_stkoff, src_l_value_hex, src_l_value_i64,
    #   src_r_type, src_r_stkoff, src_r_value_hex, src_r_value_i64,
    #   dstr, meta
    def _insn_row(
        blk: int, idx: int, ea: int, opcode: int, opcode_name: str,
        dest_type: str | None, dest_stkoff: int | None, dest_size: int | None,
        src_l_type: str | None, src_l_stkoff: int | None, src_l_value: int | None,
        src_r_type: str | None, src_r_stkoff: int | None, src_r_value: int | None,
        dstr: str, meta: str | None,
    ) -> tuple:
        ea_h, ea_i = _dual(ea)
        sl_h, sl_i = _dual(src_l_value)
        sr_h, sr_i = _dual(src_r_value)
        return (
            blk, idx, ea_h, ea_i, opcode, opcode_name,
            dest_type, dest_stkoff, dest_size,
            src_l_type, src_l_stkoff, sl_h, sl_i,
            src_r_type, src_r_stkoff, sr_h, sr_i,
            dstr, meta,
        )

    instructions = [
        # blk[131]: assert mov state var
        _insn_row(131, 0, 0x180014852, 4, "m_mov", "mop_S", 0x3C, 4,
                  "mop_n", None, 0x0ACD0BD5, None, None, None,
                  "mov #0xACD0BD5, %var_7BC.4", None),
        # blk[175]: writes var_8 from var_7C8 (CORRECT return path)
        _insn_row(175, 0, 0x180015C7A, 12, "m_add", "mop_S", 0x7F0, 8,
                  None, None, None, None, None, None,
                  "add (MBA+0xFE), %var_8.8", None),
        # blk[207]: m_xdu writes var_8 from var_7BC (BUG: should be var_7C8)
        _insn_row(207, 1, 0x1800161C8, 38, "m_xdu", "mop_S", 0x7F0, 8,
                  "mop_S", 0x3C, None, None, None, None,
                  "xdu %var_7BC.4, %var_8.8",
                  '{"note": "IDA aliased var_7C8(stkoff=0x30) as var_7BC(stkoff=0x3C) via xdu"}'),
        # blk[217]: writes var_8 from var_178 (CORRECT shared corridor)
        _insn_row(217, 2, 0x1800164C5, 4, "m_mov", "mop_S", 0x7F0, 8,
                  "mop_S", 0x680, None, None, None, None,
                  "mov %var_178.8, %var_8.8", None),
        # blk[218]: reads var_8 into rax (final return)
        _insn_row(218, 0, 0x1800164CD, 4, "m_mov", "mop_r", None, 8,
                  "mop_S", 0x7F0, None, None, None, None,
                  "mov %var_8.8, rax.8", None),
        # blk[32]: state write 0x432DC789 (un-NOPed in duplicate-and-redirect path)
        _insn_row(32, 10, 0x180013405, 4, "m_mov", "mop_S", 0x3C, 4,
                  "mop_n", None, 0x432DC789, None, None, None,
                  "mov #0x432DC789, %var_7BC.4", None),
    ]
    for row in instructions:
        conn.execute(
            "INSERT INTO instructions VALUES "
            "(1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            row,
        )

    # DAG edges
    def _edge_row(
        eid: int, src: int | None, tgt: int | None,
        kind: str, sblk: int | None, sarm: int | None,
        tentry: int | None, path: str,
    ) -> tuple:
        ss_h, ss_i = _dual(src)
        ts_h, ts_i = _dual(tgt)
        return (eid, ss_h, ss_i, ts_h, ts_i, kind, sblk, sarm, tentry, path)

    dag_edges = [
        _edge_row(0, 0x0ACD0BD5, 0x258ED455, "CONDITIONAL_TRANSITION",
                  174, 1, 199, "[131,174,176,199]"),
        _edge_row(1, 0x0ACD0BD5, None, "CONDITIONAL_RETURN",
                  174, 0, None, "[131,174,175,218,219]"),
        _edge_row(2, 0x258ED455, 0x6465D165, "TRANSITION",
                  199, None, 23, "[199]"),
        _edge_row(3, 0x6465D165, 0x432DC789, "TRANSITION",
                  23, None, 62, "[23,24,32]"),
        _edge_row(4, 0x432DC789, 0x298372CC, "TRANSITION",
                  62, None, 205, "[62]"),
        _edge_row(5, 0x298372CC, None, "CONDITIONAL_RETURN",
                  206, 0, None, "[206,207,218,219]"),
    ]
    for row in dag_edges:
        conn.execute(
            "INSERT INTO dag_edges VALUES (1,?,?,?,?,?,?,?,?,?,?)",
            row,
        )

    state_h, state_i = _dual(0x298372CC)
    conn.execute(
        "INSERT INTO dag_nodes VALUES (1, ?, ?, 205, 'RANGE_BACKED', ?)",
        (state_h, state_i, json.dumps([217, 218])),
    )
    for role, serials in (
        ("owned", [205, 207, 206, 217, 218]),
        ("exclusive", [205, 207, 206]),
        ("shared_suffix", [217, 218]),
    ):
        for block_index, serial in enumerate(serials):
            conn.execute(
                "INSERT INTO dag_node_blocks VALUES (1, ?, 205, ?, ?, ?)",
                (state_h, serial, block_index, role),
            )
    for segment_index, (segment_id, kind, blocks_json) in enumerate((
        ("blk[205]", "BRANCH", [205]),
        ("blk[207]", "STRAIGHT_LINE", [207]),
        ("blk[206]", "STRAIGHT_LINE", [206]),
        ("blk[217]", "SHARED_SUFFIX", [217]),
        ("blk[218]", "TERMINAL_SUFFIX", [218]),
    )):
        conn.execute(
            "INSERT INTO dag_local_segments VALUES (1, ?, 205, ?, ?, ?, ?)",
            (state_h, segment_index, segment_id, kind, json.dumps(blocks_json)),
        )
    for edge_index, src, dst, kind, branch_arm in (
        (0, "blk[205]", "blk[207]", "TAKEN", 1),
        (1, "blk[205]", "blk[206]", "FALLTHROUGH", 0),
        (2, "blk[206]", "blk[217]", "SHARED_SUFFIX", None),
        (3, "blk[217]", "blk[218]", "TERMINAL", None),
    ):
        conn.execute(
            "INSERT INTO dag_local_edges VALUES (1, ?, 205, ?, ?, ?, ?, ?)",
            (state_h, edge_index, src, dst, kind, branch_arm),
        )

    # Block classification
    for serial in [131, 174, 175, 176, 200, 23, 24, 32, 62, 206, 207, 217, 218, 219]:
        is_bst = 0
        is_gutted = 0
        conn.execute(
            "INSERT INTO block_classification VALUES (1,?,?,1,?,0)",
            (serial, is_bst, is_gutted),
        )

    conn.execute(
        "INSERT INTO rendered_programs VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "semantic_reference_like",
            "semantic",
            "local_boundary_selective",
            "state_family",
            "inline_single_level",
            "minimal",
            6,
            1,
        ),
    )
    conn.execute(
        "INSERT INTO rendered_program_nodes VALUES (1, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "semantic_reference_like",
            "STATE_139F2922",
            "state_family",
            "STATE_139F2922",
            136,
            136,
            None,
            3,
            6,
        ),
    )
    rendered_lines = [
        (1, "semantic_reference_like", 1, None, 0, "statement", None, "=== LINEARIZED STATE PROGRAM (starting from 0x5D0AEBD3) ==="),
        (1, "semantic_reference_like", 2, None, 0, "blank", None, ""),
        (1, "semantic_reference_like", 3, 0, 0, "label", None, "STATE_139F2922:"),
        (1, "semantic_reference_like", 4, 0, 1, "statement", None, "    v56 = v135 + v136 + v137;"),
        (1, "semantic_reference_like", 5, 0, 1, "if", None, "    if (v56 == 0)"),
        (1, "semantic_reference_like", 6, 0, 2, "goto", "STATE_16F7FF74", "        goto STATE_16F7FF74;"),
    ]
    conn.executemany(
        "INSERT INTO rendered_program_lines VALUES (?,?,?,?,?,?,?,?)",
        rendered_lines,
    )

    conn.commit()
    return 1
