"""Pre-loaded diagnostic DB fixtures based on real debugging scenarios."""
from __future__ import annotations

import json
import sqlite3

from d810.core.diag.schema import create_tables


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
    conn.execute(
        "INSERT INTO snapshots VALUES "
        "(1, 'pass0_post_apply', 0x180012B60, 'MMAT_GLBOPT1', 233, 0.0)"
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
            "INSERT INTO blocks VALUES (1,?,?,?,NULL,NULL,?,?,?,?,?,?)",
            (serial, btype, tname, nsucc, len(preds),
             json.dumps(succs), json.dumps(preds), icnt, meta),
        )

    # Key instructions -- the ones that matter for variable provenance
    instructions = [
        # blk[131]: assert mov state var
        (131, 0, 0x180014852, 4, "m_mov", "mop_S", 0x3C, 4,
         "mop_n", None, 0x0ACD0BD5, None, None, None,
         "mov #0xACD0BD5, %var_7BC.4", None),
        # blk[175]: writes var_8 from var_7C8 (CORRECT return path)
        (175, 0, 0x180015C7A, 12, "m_add", "mop_S", 0x7F0, 8,
         None, None, None, None, None, None,
         "add (MBA+0xFE), %var_8.8", None),
        # blk[207]: m_xdu writes var_8 from var_7BC (BUG: should be var_7C8)
        (207, 1, 0x1800161C8, 38, "m_xdu", "mop_S", 0x7F0, 8,
         "mop_S", 0x3C, None, None, None, None,
         "xdu %var_7BC.4, %var_8.8",
         '{"note": "IDA aliased var_7C8(stkoff=0x30) as var_7BC(stkoff=0x3C) via xdu"}'),
        # blk[217]: writes var_8 from var_178 (CORRECT shared corridor)
        (217, 2, 0x1800164C5, 4, "m_mov", "mop_S", 0x7F0, 8,
         "mop_S", 0x680, None, None, None, None,
         "mov %var_178.8, %var_8.8", None),
        # blk[218]: reads var_8 into rax (final return)
        (218, 0, 0x1800164CD, 4, "m_mov", "mop_r", None, 8,
         "mop_S", 0x7F0, None, None, None, None,
         "mov %var_8.8, rax.8", None),
        # blk[32]: state write 0x432DC789 (un-NOPed in duplicate-and-redirect path)
        (32, 10, 0x180013405, 4, "m_mov", "mop_S", 0x3C, 4,
         "mop_n", None, 0x432DC789, None, None, None,
         "mov #0x432DC789, %var_7BC.4", None),
    ]
    for row in instructions:
        conn.execute(
            "INSERT INTO instructions VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            row,
        )

    # DAG edges
    dag_edges = [
        (0, 0x0ACD0BD5, 0x258ED455, "CONDITIONAL_TRANSITION",
         174, 1, 199, "[131,174,176,199]"),
        (1, 0x0ACD0BD5, None, "CONDITIONAL_RETURN",
         174, 0, None, "[131,174,175,218,219]"),
        (2, 0x258ED455, 0x6465D165, "TRANSITION",
         199, None, 23, "[199]"),
        (3, 0x6465D165, 0x432DC789, "TRANSITION",
         23, None, 62, "[23,24,32]"),
        (4, 0x432DC789, 0x298372CC, "TRANSITION",
         62, None, 205, "[62]"),
        (5, 0x298372CC, None, "CONDITIONAL_RETURN",
         206, 0, None, "[206,207,218,219]"),
    ]
    for eid, src, tgt, kind, sblk, sarm, tentry, path in dag_edges:
        conn.execute(
            "INSERT INTO dag_edges VALUES (1,?,?,?,?,?,?,?,?)",
            (eid, src, tgt, kind, sblk, sarm, tentry, path),
        )

    # Block classification
    for serial in [131, 174, 175, 176, 200, 23, 24, 32, 62, 206, 207, 217, 218, 219]:
        is_bst = 0
        is_gutted = 0
        conn.execute(
            "INSERT INTO block_classification VALUES (1,?,?,1,?,0)",
            (serial, is_bst, is_gutted),
        )

    conn.commit()
    return 1
