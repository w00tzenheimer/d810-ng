"""Pre-loaded diagnostic DB fixtures based on real debugging scenarios."""
from __future__ import annotations

import json
import sqlite3

from d810.core.diag.models import (
    Block,
    BlockClassification,
    Instruction,
    RenderedProgram,
    RenderedProgramLine,
    RenderedProgramNode,
    Snapshot,
    StateCfgEdge,
    StateCfgLocalEdge,
    StateCfgLocalSegment,
    StateCfgNode,
    StateCfgNodeBlock,
)
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

    Rows are written via the peewee ORM; the Models are bound by the caller
    (the in-memory diag DB from ``make_bound_diag_db``), whose connection is
    ``conn``. The caller is responsible for creating the schema (e.g. via
    ``create_diag_database`` / ``make_bound_diag_db``).
    """
    fh, fi = _dual(0x180012B60)
    Snapshot.insert(
        id=1,
        label="pass0_post_apply",
        func_ea_hex=fh,
        func_ea_i64=fi,
        maturity="MMAT_GLBOPT1",
        phase="post_apply",
        block_count=233,
        timestamp=0.0,
    ).execute()

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
    block_eas = {
        131: (0x180014852, 0x180014856),
        32: (0x180013405, 0x180013409),
        175: (0x180015C7A, 0x180015C7E),
        207: (0x1800161C8, 0x1800161CC),
        217: (0x1800164C5, 0x1800164C9),
        218: (0x1800164CD, 0x1800164D1),
    }
    block_rows = []
    for serial, btype, tname, nsucc, npred, succs, preds, icnt, meta in blocks:
        start_hex, start_i64 = _dual(block_eas.get(serial, (None, None))[0])
        end_hex, end_i64 = _dual(block_eas.get(serial, (None, None))[1])
        block_rows.append({
            "snapshot": 1,
            "serial": serial,
            "block_type": btype,
            "type_name": tname,
            "start_ea_hex": start_hex,
            "start_ea_i64": start_i64,
            "end_ea_hex": end_hex,
            "end_ea_i64": end_i64,
            "nsucc": nsucc,
            "npred": len(preds),
            "succs": json.dumps(succs),
            "preds": json.dumps(preds),
            "insn_count": icnt,
            "meta": meta,
        })
    Block.insert_many(block_rows).execute()

    # Key instructions -- the ones that matter for variable provenance
    def _insn_row(
        blk: int, idx: int, ea: int, opcode: int, opcode_name: str,
        dest_type: str | None, dest_stkoff: int | None, dest_size: int | None,
        src_l_type: str | None, src_l_stkoff: int | None, src_l_value: int | None,
        src_r_type: str | None, src_r_stkoff: int | None, src_r_value: int | None,
        dstr: str, meta: str | None,
    ) -> dict:
        ea_h, ea_i = _dual(ea)
        sl_h, sl_i = _dual(src_l_value)
        sr_h, sr_i = _dual(src_r_value)
        return {
            "snapshot": 1,
            "block_serial": blk,
            "insn_index": idx,
            "ea_hex": ea_h,
            "ea_i64": ea_i,
            "opcode": opcode,
            "opcode_name": opcode_name,
            "dest_type": dest_type,
            "dest_stkoff": dest_stkoff,
            "dest_size": dest_size,
            "src_l_type": src_l_type,
            "src_l_stkoff": src_l_stkoff,
            "src_l_value_hex": sl_h,
            "src_l_value_i64": sl_i,
            "src_r_type": src_r_type,
            "src_r_stkoff": src_r_stkoff,
            "src_r_value_hex": sr_h,
            "src_r_value_i64": sr_i,
            "dstr": dstr,
            "meta": meta,
        }

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
    Instruction.insert_many(instructions).execute()

    # DAG edges
    def _edge_row(
        eid: int, src: int | None, tgt: int | None,
        kind: str, sblk: int | None, sarm: int | None,
        tentry: int | None, path: str,
    ) -> dict:
        ss_h, ss_i = _dual(src)
        ts_h, ts_i = _dual(tgt)
        return {
            "snapshot": 1,
            "edge_id": eid,
            "source_state_hex": ss_h,
            "source_state_i64": ss_i,
            "target_state_hex": ts_h,
            "target_state_i64": ts_i,
            "edge_kind": kind,
            "source_block": sblk,
            "source_arm": sarm,
            "target_entry": tentry,
            "ordered_path": path,
        }

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
    StateCfgEdge.insert_many(dag_edges).execute()

    state_h, state_i = _dual(0x298372CC)
    StateCfgNode.insert(
        snapshot=1,
        state_hex=state_h,
        state_i64=state_i,
        entry_block=205,
        classification="RANGE_BACKED",
        shared_suffix=json.dumps([217, 218]),
    ).execute()
    node_block_rows = []
    for role, serials in (
        ("owned", [205, 207, 206, 217, 218]),
        ("exclusive", [205, 207, 206]),
        ("shared_suffix", [217, 218]),
    ):
        for block_index, serial in enumerate(serials):
            node_block_rows.append({
                "snapshot": 1,
                "state_hex": state_h,
                "entry_block": 205,
                "block_serial": serial,
                "block_index": block_index,
                "role": role,
            })
    StateCfgNodeBlock.insert_many(node_block_rows).execute()

    segment_rows = []
    for segment_index, (segment_id, kind, blocks_json) in enumerate((
        ("blk[205]", "BRANCH", [205]),
        ("blk[207]", "STRAIGHT_LINE", [207]),
        ("blk[206]", "STRAIGHT_LINE", [206]),
        ("blk[217]", "SHARED_SUFFIX", [217]),
        ("blk[218]", "TERMINAL_SUFFIX", [218]),
    )):
        segment_rows.append({
            "snapshot": 1,
            "state_hex": state_h,
            "entry_block": 205,
            "segment_index": segment_index,
            "segment_id": segment_id,
            "kind": kind,
            "blocks_json": json.dumps(blocks_json),
        })
    StateCfgLocalSegment.insert_many(segment_rows).execute()

    local_edge_rows = []
    for edge_index, src, dst, kind, branch_arm in (
        (0, "blk[205]", "blk[207]", "TAKEN", 1),
        (1, "blk[205]", "blk[206]", "FALLTHROUGH", 0),
        (2, "blk[206]", "blk[217]", "SHARED_SUFFIX", None),
        (3, "blk[217]", "blk[218]", "TERMINAL", None),
    ):
        local_edge_rows.append({
            "snapshot": 1,
            "state_hex": state_h,
            "entry_block": 205,
            "edge_index": edge_index,
            "source_segment_id": src,
            "target_segment_id": dst,
            "kind": kind,
            "branch_arm": branch_arm,
        })
    StateCfgLocalEdge.insert_many(local_edge_rows).execute()

    # Block classification (all blocks: is_bst=0, is_reachable=1, is_gutted=0)
    BlockClassification.insert_many([
        {
            "snapshot": 1,
            "serial": serial,
            "is_bst": 0,
            "is_reachable": 1,
            "is_gutted": 0,
            "in_claimed": 0,
        }
        for serial in [131, 174, 175, 176, 200, 23, 24, 32, 62, 206, 207, 217, 218, 219]
    ]).execute()

    RenderedProgram.insert(
        snapshot=1,
        variant_name="semantic_reference_like",
        order_strategy="semantic",
        program_strategy="local_boundary_selective",
        label_render_mode="state_family",
        boundary_inline_mode="inline_single_level",
        comment_mode="minimal",
        line_count=8,
        node_count=1,
    ).execute()
    RenderedProgramNode.insert(
        snapshot_id=1,
        variant_name="semantic_reference_like",
        node_index=0,
        label_text="STATE_139F2922",
        node_kind="state_family",
        state_label="STATE_139F2922",
        handler_serial=136,
        entry_anchor=136,
        label_num=None,
        line_start=3,
        line_end=8,
    ).execute()
    rendered_lines = [
        {"snapshot_id": 1, "variant_name": "semantic_reference_like", "line_no": 1,
         "node_index": None, "indent_level": 0, "line_kind": "statement",
         "target_label": None,
         "text": "=== LINEARIZED STATE PROGRAM (starting from 0x5D0AEBD3) ==="},
        {"snapshot_id": 1, "variant_name": "semantic_reference_like", "line_no": 2,
         "node_index": None, "indent_level": 0, "line_kind": "blank",
         "target_label": None, "text": ""},
        {"snapshot_id": 1, "variant_name": "semantic_reference_like", "line_no": 3,
         "node_index": 0, "indent_level": 0, "line_kind": "label",
         "target_label": None, "text": "STATE_139F2922:"},
        {"snapshot_id": 1, "variant_name": "semantic_reference_like", "line_no": 4,
         "node_index": 0, "indent_level": 1, "line_kind": "comment",
         "target_label": None, "text": "    // entry blk[131]"},
        {"snapshot_id": 1, "variant_name": "semantic_reference_like", "line_no": 5,
         "node_index": 0, "indent_level": 1, "line_kind": "comment",
         "target_label": None, "text": "    // local-cfg: blk[131] -> blk[174]"},
        {"snapshot_id": 1, "variant_name": "semantic_reference_like", "line_no": 6,
         "node_index": 0, "indent_level": 1, "line_kind": "statement",
         "target_label": None, "text": "    v56 = v135 + v136 + v137;"},
        {"snapshot_id": 1, "variant_name": "semantic_reference_like", "line_no": 7,
         "node_index": 0, "indent_level": 1, "line_kind": "if",
         "target_label": None, "text": "    if (v56 == 0)"},
        {"snapshot_id": 1, "variant_name": "semantic_reference_like", "line_no": 8,
         "node_index": 0, "indent_level": 2, "line_kind": "goto",
         "target_label": "STATE_16F7FF74", "text": "        goto STATE_16F7FF74;"},
    ]
    RenderedProgramLine.insert_many(rendered_lines).execute()

    conn.commit()
    return 1
