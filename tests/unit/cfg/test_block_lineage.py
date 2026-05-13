"""Tests for pending created-block lineage rows."""
from __future__ import annotations

import json

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.cfg.graph_modification import (
    CreateConditionalRedirect,
    EdgeRedirectViaPredSplit,
    InsertBlock,
)
from d810.cfg.plan import compile_patch_plan
from d810.cfg.block_lineage import (
    build_patch_plan_block_lineage,
    buffer_patch_plan_block_lineage,
    drain_pending_block_lineage,
    reset_pending_block_lineage,
)


def _insn(opcode: int, ea: int) -> InsnSnapshot:
    return InsnSnapshot(opcode=opcode, ea=ea, operands=())


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *,
    start_ea: int,
    insns: tuple[InsnSnapshot, ...] = (),
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1 if succs else 0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=start_ea,
        insn_snapshots=insns,
    )


def _edge_split_pre_cfg() -> FlowGraph:
    return FlowGraph(
        blocks={
            9: _block(9, (10,), (), start_ea=0x1009),
            10: _block(
                10,
                (11,),
                (9,),
                start_ea=0x1010,
                insns=(_insn(1, 0x1010), _insn(2, 0x1014)),
            ),
            11: _block(11, (), (10,), start_ea=0x101C),
        },
        entry_serial=9,
        func_ea=0x1000,
        metadata={
            "snapshot_id": 42,
            "maturity": "MMAT_GLBOPT1",
            "phase": "pre_apply",
        },
    )


def _edge_split_post_cfg() -> FlowGraph:
    return FlowGraph(
        blocks={
            9: _block(9, (11,), (), start_ea=0x1009),
            10: _block(10, (12,), (), start_ea=0x1010),
            11: _block(
                11,
                (12,),
                (9,),
                start_ea=0x1020,
                insns=(_insn(1, 0x1010), _insn(2, 0x1014)),
            ),
            12: _block(12, (), (10, 11), start_ea=0x101C),
        },
        entry_serial=9,
        func_ea=0x1000,
        metadata={
            "snapshot_id": 43,
            "maturity": "MMAT_GLBOPT1",
            "phase": "post_apply",
        },
    )


def _conditional_pre_cfg() -> FlowGraph:
    return FlowGraph(
        blocks={
            9: _block(9, (10,), (), start_ea=0x2009),
            10: _block(
                10,
                (11, 14),
                (9,),
                start_ea=0x2010,
                insns=(_insn(0x70, 0x2010),),
            ),
            11: _block(11, (), (10,), start_ea=0x2011),
            14: _block(14, (), (10,), start_ea=0x2014),
        },
        entry_serial=9,
        func_ea=0x2000,
        metadata={"snapshot_id": 100},
    )


def _conditional_post_cfg() -> FlowGraph:
    return FlowGraph(
        blocks={
            9: _block(9, (14,), (), start_ea=0x2009),
            10: _block(10, (11, 16), (), start_ea=0x2010),
            11: _block(11, (), (10, 15), start_ea=0x2011),
            14: _block(14, (16, 15), (9,), start_ea=0x2020),
            15: _block(15, (11,), (14,), start_ea=0x2024),
            16: _block(16, (), (10, 14), start_ea=0x2014),
        },
        entry_serial=9,
        func_ea=0x2000,
        metadata={"snapshot_id": 101},
    )


def test_build_patch_plan_block_lineage_records_origin_and_source_mod_type() -> None:
    pre_cfg = _edge_split_pre_cfg()
    post_cfg = _edge_split_post_cfg()
    patch_plan = compile_patch_plan(
        [
            EdgeRedirectViaPredSplit(
                src_block=10,
                old_target=11,
                new_target=11,
                via_pred=9,
            )
        ],
        pre_cfg,
    )

    entries = build_patch_plan_block_lineage(patch_plan, pre_cfg, post_cfg)

    assert len(entries) == 1
    entry = entries[0]
    assert entry.serial == 11
    assert entry.origin_snapshot_id == 42
    assert entry.origin_serial == 10
    assert entry.origin_start_ea_hex == "0x0000000000001010"
    assert entry.origin_body_fingerprint == "fnv1a64:0x560db32355579e56"
    assert entry.creation_kind == "edge_split_trampoline"
    assert entry.creation_reason == "patch_plan:edge_split_trampoline"
    assert entry.planner_block_id == "edge_split:0"
    assert entry.source_mod_type == "EdgeRedirectViaPredSplit"

    extra = json.loads(entry.extra_json or "{}")
    assert extra["assigned_label"] == "blk[11]@0x1020"
    assert extra["assigned_start_ea_hex"] == "0x0000000000001020"
    assert extra["assigned_body_fingerprint"] == "fnv1a64:0x560db32355579e56"
    assert extra["assigned_display_fingerprint"] == "fp=[0x1010:op1,0x1014:op2]"
    assert extra["origin_label"] == "blk[10]@0x1010"
    assert extra["origin_display_fingerprint"] == "fp=[0x1010:op1,0x1014:op2]"
    assert extra["incoming_edge"] == {"source": 9, "target": 10}
    assert extra["outgoing_edges"] == [{"source": "edge_split:0", "target": 12}]

    assert entry.as_db_tuple(99) == (
        99,
        11,
        42,
        10,
        "0x0000000000001010",
        "fnv1a64:0x560db32355579e56",
        "edge_split_trampoline",
        "patch_plan:edge_split_trampoline",
        "edge_split:0",
        "EdgeRedirectViaPredSplit",
        entry.extra_json,
    )


def test_buffer_patch_plan_block_lineage_drains_every_created_block() -> None:
    reset_pending_block_lineage()
    pre_cfg = _conditional_pre_cfg()
    post_cfg = _conditional_post_cfg()
    patch_plan = compile_patch_plan(
        [
            CreateConditionalRedirect(
                source_block=9,
                ref_block=10,
                conditional_target=14,
                fallthrough_target=11,
            )
        ],
        pre_cfg,
    )

    try:
        buffered = buffer_patch_plan_block_lineage(patch_plan, pre_cfg, post_cfg)
        drained = drain_pending_block_lineage()

        assert drained == buffered
        assert [entry.serial for entry in drained] == [14, 15]
        assert [entry.creation_kind for entry in drained] == [
            "conditional_redirect_clone",
            "conditional_redirect_fallthrough",
        ]
        assert {entry.source_mod_type for entry in drained} == {
            "CreateConditionalRedirect"
        }
        assert drain_pending_block_lineage() == []
    finally:
        reset_pending_block_lineage()


def test_insert_block_lineage_uses_body_origin_not_incoming_edge() -> None:
    pre_cfg = FlowGraph(
        blocks={
            9: _block(9, (10,), (), start_ea=0x1009),
            10: _block(
                10,
                (11,),
                (9,),
                start_ea=0x1010,
                insns=(_insn(1, 0x1010), _insn(2, 0x1014)),
            ),
            40: _block(
                40,
                (42,),
                (),
                start_ea=0x1040,
                insns=(_insn(0x44, 0x1040),),
            ),
            42: _block(42, (), (40,), start_ea=0x1042),
        },
        entry_serial=9,
        func_ea=0x1000,
        metadata={"snapshot_id": 77},
    )
    post_cfg = FlowGraph(
        blocks={
            9: _block(9, (10,), (), start_ea=0x1009),
            10: _block(10, (11,), (9,), start_ea=0x1010),
            11: _block(11, (), (10,), start_ea=0x101C),
            40: _block(40, (42,), (), start_ea=0x1040),
            42: _block(
                42,
                (43,),
                (40,),
                start_ea=0x1010,
                insns=(_insn(1, 0x2000), _insn(2, 0x2000)),
            ),
            43: _block(43, (), (42,), start_ea=0x1042),
        },
        entry_serial=9,
        func_ea=0x1000,
        metadata={"snapshot_id": 78},
    )
    patch_plan = compile_patch_plan(
        [
            InsertBlock(
                pred_serial=40,
                succ_serial=42,
                instructions=(
                    _insn(1, 0x2000),
                    _insn(2, 0x2000),
                ),
            )
        ],
        pre_cfg,
    )

    entries = build_patch_plan_block_lineage(patch_plan, pre_cfg, post_cfg)

    assert len(entries) == 1
    entry = entries[0]
    assert entry.serial == 42
    assert entry.origin_serial == 10
    assert entry.origin_start_ea_hex == "0x0000000000001010"
    extra = json.loads(entry.extra_json or "{}")
    assert extra["incoming_edge"] == {"source": 40, "target": 43}
    assert extra["origin_label"] == "blk[10]@0x1010"
