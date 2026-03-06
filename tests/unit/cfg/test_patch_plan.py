"""Tests for the Phase B PatchPlan execution layer."""
from __future__ import annotations

from d810.cfg.flowgraph import InsnSnapshot
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
    PatchConvertToGoto,
    PatchNopInstructions,
    PatchPlan,
    PatchRedirectGoto,
    VirtualBlockId,
    compile_patch_plan,
    ensure_patch_plan,
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


def test_compile_patch_plan_records_symbolic_block_specs_for_block_creation():
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

    patch_plan = compile_patch_plan(modifications)

    assert patch_plan.contains_block_creation
    assert len(patch_plan.new_blocks) == 3
    assert all(isinstance(spec, PatchBlockSpec) for spec in patch_plan.new_blocks)
    assert all(isinstance(spec.block_id, VirtualBlockId) for spec in patch_plan.new_blocks)
    assert [spec.kind for spec in patch_plan.new_blocks] == [
        "edge_split_trampoline",
        "conditional_redirect_clone",
        "insert_block",
    ]
    assert len(patch_plan.legacy_block_operations) == 3
    assert all(isinstance(step, LegacyBlockOperation) for step in patch_plan.legacy_block_operations)
    assert patch_plan.as_graph_modifications() == modifications


def test_ensure_patch_plan_is_idempotent():
    patch_plan = compile_patch_plan([
        RedirectGoto(from_serial=1, old_target=2, new_target=3),
    ])

    assert ensure_patch_plan(patch_plan) is patch_plan
