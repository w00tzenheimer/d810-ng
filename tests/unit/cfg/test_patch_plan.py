"""Tests for the Phase B PatchPlan execution layer."""
from __future__ import annotations

import pytest

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.cfg.graph_modification import (
    ConvertToGoto,
    CreateConditionalRedirect,
    EdgeRedirectViaPredSplit,
    InsertBlock,
    NopInstructions,
    RedirectGoto,
)
from d810.cfg.plan import (
    LegacyBlockOperation,
    PatchBlockSpec,
    PatchConditionalRedirect,
    PatchConvertToGoto,
    PatchEdgeSplitTrampoline,
    PatchNopInstructions,
    PatchPlan,
    PatchRedirectGoto,
    VirtualBlockId,
    compile_patch_plan,
    ensure_patch_plan,
)


def _block(serial: int, succs: tuple[int, ...], preds: tuple[int, ...]) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1 if succs else 0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0,
        insn_snapshots=(),
    )


def _cfg() -> FlowGraph:
    return FlowGraph(
        blocks={
            9: _block(9, (10,), ()),
            10: _block(10, (11,), (9,)),
            11: _block(11, (), (10,)),
        },
        entry_serial=9,
        func_ea=0,
    )


def _conditional_cfg() -> FlowGraph:
    return FlowGraph(
        blocks={
            9: _block(9, (10,), ()),
            10: _block(10, (11, 14), (9,)),
            11: _block(11, (), (10,)),
            14: _block(14, (), (10,)),
        },
        entry_serial=9,
        func_ea=0,
    )


def test_compile_patch_plan_converts_existing_block_rewrites():
    modifications = [
        RedirectGoto(from_serial=1, old_target=2, new_target=3),
        ConvertToGoto(block_serial=4, goto_target=5),
        NopInstructions(block_serial=6, insn_eas=(0x1000, 0x1004)),
    ]

    patch_plan = compile_patch_plan(modifications)

    assert isinstance(patch_plan, PatchPlan)
    assert patch_plan.steps == (
        PatchRedirectGoto(from_serial=1, old_target=2, new_target=3),
        PatchConvertToGoto(block_serial=4, goto_target=5),
        PatchNopInstructions(block_serial=6, insn_eas=(0x1000, 0x1004)),
    )
    assert patch_plan.new_blocks == ()
    assert not patch_plan.contains_block_creation
    assert patch_plan.as_graph_modifications() == modifications


def test_compile_patch_plan_requires_cfg_for_edge_split_trampoline():
    with pytest.raises(ValueError, match="requires FlowGraph context"):
        compile_patch_plan(
            [
                EdgeRedirectViaPredSplit(
                    src_block=10,
                    old_target=11,
                    new_target=12,
                    via_pred=9,
                )
            ]
        )


def test_compile_patch_plan_finalizes_edge_split_trampoline():
    patch_plan = compile_patch_plan(
        [
            EdgeRedirectViaPredSplit(
                src_block=10,
                old_target=11,
                new_target=12,
                via_pred=9,
            )
        ],
        _cfg(),
    )

    assert patch_plan.contains_block_creation
    assert patch_plan.steps == (
        PatchEdgeSplitTrampoline(
            block_id=VirtualBlockId(namespace="edge_split", ordinal=0),
            assigned_serial=11,
            source_serial=10,
            via_pred=9,
            old_target=11,
            apply_old_target=12,
            new_target=12,
            template_block=10,
        ),
    )
    assert patch_plan.new_blocks[0].kind == "edge_split_trampoline"
    assert patch_plan.relocation_map.assigned_serial_for(
        VirtualBlockId(namespace="edge_split", ordinal=0)
    ) == 11
    assert patch_plan.relocation_map.stop_serial_before == 11
    assert patch_plan.relocation_map.stop_serial_after == 12
    assert patch_plan.legacy_block_operations == ()


def test_compile_patch_plan_finalizes_conditional_redirect():
    patch_plan = compile_patch_plan(
        [
            CreateConditionalRedirect(
                source_block=9,
                ref_block=10,
                conditional_target=14,
                fallthrough_target=11,
            )
        ],
        _conditional_cfg(),
    )

    assert patch_plan.contains_block_creation
    assert patch_plan.steps == (
        PatchConditionalRedirect(
            block_id=VirtualBlockId(namespace="conditional_redirect", ordinal=0),
            assigned_serial=14,
            fallthrough_block_id=VirtualBlockId(
                namespace="conditional_redirect_fallthrough",
                ordinal=1,
            ),
            fallthrough_serial=15,
            source_serial=9,
            ref_block=10,
            conditional_target=16,
            fallthrough_target=11,
        ),
    )
    assert [spec.kind for spec in patch_plan.new_blocks] == [
        "conditional_redirect_clone",
        "conditional_redirect_fallthrough",
    ]
    assert patch_plan.relocation_map.stop_serial_before == 14
    assert patch_plan.relocation_map.stop_serial_after == 16
    assert patch_plan.legacy_block_operations == ()


def test_compile_patch_plan_records_symbolic_block_specs_for_remaining_legacy_block_creation():
    instructions = (InsnSnapshot(opcode=0x77, ea=0x2000, operands=()),)
    modifications = [
        EdgeRedirectViaPredSplit(
            src_block=10,
            old_target=11,
            new_target=12,
            via_pred=9,
        ),
        CreateConditionalRedirect(
            source_block=20,
            ref_block=21,
            conditional_target=30,
            fallthrough_target=31,
        ),
        InsertBlock(pred_serial=40, succ_serial=41, instructions=instructions),
    ]

    patch_plan = compile_patch_plan(modifications, _cfg())

    assert patch_plan.contains_block_creation
    assert len(patch_plan.new_blocks) == 4
    assert all(isinstance(spec, PatchBlockSpec) for spec in patch_plan.new_blocks)
    assert all(isinstance(spec.block_id, VirtualBlockId) for spec in patch_plan.new_blocks)
    assert [spec.kind for spec in patch_plan.new_blocks] == [
        "edge_split_trampoline",
        "conditional_redirect_clone",
        "conditional_redirect_fallthrough",
        "insert_block",
    ]
    assert isinstance(patch_plan.steps[0], PatchEdgeSplitTrampoline)
    assert isinstance(patch_plan.steps[1], PatchConditionalRedirect)
    assert len(patch_plan.legacy_block_operations) == 1
    assert all(isinstance(step, LegacyBlockOperation) for step in patch_plan.legacy_block_operations)
    assert patch_plan.as_graph_modifications() == modifications


def test_ensure_patch_plan_is_idempotent():
    patch_plan = compile_patch_plan([
        RedirectGoto(from_serial=1, old_target=2, new_target=3),
    ])

    assert ensure_patch_plan(patch_plan) is patch_plan
