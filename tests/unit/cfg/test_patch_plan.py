"""Tests for the Phase B PatchPlan execution layer."""
from __future__ import annotations

import ast
import inspect
import textwrap
from dataclasses import dataclass
from pathlib import Path

import pytest

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.cfg.flow.edit_simulator import project_post_state
from d810.cfg.graph_modification import (
    CloneConditionalAsGoto,
    ConvertToGoto,
    CreateConditionalRedirect,
    DuplicateBlock,
    EdgeRedirectViaPredSplit,
    InsertBlock,
    NopInstructions,
    RedirectGoto,
    RemoveEdge,
)
from d810.cfg.materialization_payload import (
    CapturedBlockBody,
    CapturedBlockBodySummary,
)
from d810.cfg.plan import (
    LegacyBlockOperation,
    PatchBlockSpec,
    PatchCloneConditionalAsGoto,
    PatchConditionalRedirect,
    PatchConvertToGoto,
    PatchDuplicateBlock,
    PatchEdgeRef,
    PatchEdgeSplitTrampoline,
    PatchInsertBlock,
    PatchNopInstructions,
    PatchPlan,
    PatchRedirectGoto,
    PatchRemoveEdge,
    VirtualBlockId,
    compile_patch_plan,
    ensure_patch_plan,
)


@dataclass(frozen=True)
class _BlockRef:
    block_num: int


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *,
    insn_snapshots: tuple[InsnSnapshot, ...] = (),
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1 if succs else 0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0,
        insn_snapshots=insn_snapshots,
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
            10: _block(
                10,
                (11, 14),
                (9,),
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0x70,
                        ea=0x1010,
                        operands=(_BlockRef(14),),
                        operand_slots=(("d", _BlockRef(14)),),
                    ),
                ),
            ),
            11: _block(11, (), (10,)),
            14: _block(14, (), (10,)),
        },
        entry_serial=9,
        func_ea=0,
    )


def _conditional_duplicate_cfg() -> FlowGraph:
    return FlowGraph(
        blocks={
            8: _block(8, (10,), ()),
            10: _block(
                10,
                (11, 12),
                (8,),
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0x70,
                        ea=0x1010,
                        operands=(_BlockRef(11),),
                        operand_slots=(("d", _BlockRef(11)),),
                    ),
                ),
            ),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
            13: _block(13, (), ()),
        },
        entry_serial=8,
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


def test_compile_patch_plan_preserves_corridor_edge_split_as_legacy_block_op():
    modification = EdgeRedirectViaPredSplit(
        src_block=10,
        old_target=11,
        new_target=12,
        via_pred=9,
        clone_until=11,
    )

    patch_plan = compile_patch_plan([modification], _cfg())

    assert patch_plan.steps == (LegacyBlockOperation(modification=modification),)
    assert patch_plan.legacy_block_operations == (
        LegacyBlockOperation(modification=modification),
    )
    assert patch_plan.new_blocks == ()


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


def test_compile_patch_plan_finalizes_conditional_redirect_with_instructions():
    instructions = (InsnSnapshot(opcode=0x77, ea=0x2000, operands=()),)
    patch_plan = compile_patch_plan(
        [
            CreateConditionalRedirect(
                source_block=9,
                ref_block=10,
                conditional_target=14,
                fallthrough_target=11,
                instructions=instructions,
            )
        ],
        _conditional_cfg(),
    )

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
            instructions=instructions,
        ),
    )


def test_compile_patch_plan_finalizes_insert_block():
    instructions = (InsnSnapshot(opcode=0x77, ea=0x2000, operands=()),)
    patch_plan = compile_patch_plan(
        [
            InsertBlock(
                pred_serial=10,
                succ_serial=11,
                instructions=instructions,
            )
        ],
        _cfg(),
    )

    assert patch_plan.contains_block_creation
    assert patch_plan.steps == (
        PatchInsertBlock(
            block_id=VirtualBlockId(namespace="insert_block", ordinal=0),
            assigned_serial=11,
            pred_serial=10,
            succ_serial=12,
            instructions=instructions,
        ),
    )
    assert [spec.kind for spec in patch_plan.new_blocks] == ["insert_block"]
    assert patch_plan.relocation_map.stop_serial_before == 11
    assert patch_plan.relocation_map.stop_serial_after == 12
    assert patch_plan.legacy_block_operations == ()


def test_compile_patch_plan_preserves_opaque_insert_block_body():
    body = CapturedBlockBody(
        backend_id="fake",
        capture_id="fake-body",
        summary=CapturedBlockBodySummary(
            source_blocks=(10,),
            instruction_count=1,
            source_eas=frozenset({0x2000}),
        ),
        payload=object(),
    )
    patch_plan = compile_patch_plan(
        [
            InsertBlock(
                pred_serial=10,
                succ_serial=11,
                captured_body=body,
            )
        ],
        _cfg(),
    )

    assert patch_plan.new_blocks[0].captured_body is body
    assert patch_plan.steps == (
        PatchInsertBlock(
            block_id=VirtualBlockId(namespace="insert_block", ordinal=0),
            assigned_serial=11,
            pred_serial=10,
            succ_serial=12,
            instructions=(),
            captured_body=body,
        ),
    )


def test_compile_patch_plan_finalizes_insert_block_with_explicit_old_target():
    instructions = (InsnSnapshot(opcode=0x77, ea=0x2000, operands=()),)
    patch_plan = compile_patch_plan(
        [
            InsertBlock(
                pred_serial=9,
                succ_serial=11,
                instructions=instructions,
                old_target_serial=10,
            )
        ],
        _conditional_cfg(),
    )

    assert patch_plan.contains_block_creation
    assert patch_plan.steps == (
        PatchInsertBlock(
            block_id=VirtualBlockId(namespace="insert_block", ordinal=0),
            assigned_serial=14,
            pred_serial=9,
            succ_serial=11,
            instructions=instructions,
            old_target_serial=10,
        ),
    )
    assert [spec.kind for spec in patch_plan.new_blocks] == ["insert_block"]
    assert patch_plan.new_blocks[0].incoming_edge == PatchEdgeRef(source=9, target=10)
    assert patch_plan.new_blocks[0].outgoing_edges == (
        PatchEdgeRef(
            source=VirtualBlockId(namespace="insert_block", ordinal=0),
            target=11,
        ),
    )
    assert patch_plan.relocation_map.stop_serial_before == 14
    assert patch_plan.relocation_map.stop_serial_after == 15
    assert patch_plan.legacy_block_operations == ()


def test_compile_patch_plan_finalizes_duplicate_block():
    patch_plan = compile_patch_plan(
        [
            DuplicateBlock(
                source_block=10,
                target_block=11,
                pred_serial=9,
            )
        ],
        _cfg(),
    )

    assert patch_plan.contains_block_creation
    assert patch_plan.steps == (
        PatchDuplicateBlock(
            block_id=VirtualBlockId(namespace="duplicate_block", ordinal=0),
            assigned_serial=11,
            source_serial=10,
            pred_serial=9,
            pred_redirect_kind="one_way",
            source_successors=(12,),
            target_serial=12,
            conditional_target=None,
            fallthrough_target=None,
            fallthrough_block_id=None,
            fallthrough_serial=None,
        ),
    )
    assert [spec.kind for spec in patch_plan.new_blocks] == ["duplicate_block_clone"]
    assert patch_plan.legacy_block_operations == ()


def test_compile_patch_plan_finalizes_duplicate_block_for_private_target_split():
    patch_plan = compile_patch_plan(
        [
            DuplicateBlock(
                source_block=10,
                target_block=None,
                pred_serial=9,
            )
        ],
        _cfg(),
    )

    assert patch_plan.contains_block_creation
    assert patch_plan.steps == (
        PatchDuplicateBlock(
            block_id=VirtualBlockId(namespace="duplicate_block", ordinal=0),
            assigned_serial=11,
            source_serial=10,
            pred_serial=9,
            pred_redirect_kind="one_way",
            source_successors=(12,),
            target_serial=None,
            conditional_target=None,
            fallthrough_target=None,
            fallthrough_block_id=None,
            fallthrough_serial=None,
        ),
    )
    assert [spec.kind for spec in patch_plan.new_blocks] == ["duplicate_block_clone"]
    assert patch_plan.legacy_block_operations == ()


def test_compile_patch_plan_keeps_unsupported_duplicate_block_legacy():
    cfg = FlowGraph(
        blocks={
            44: _block(44, (99, 45), ()),
            45: _block(45, (2,), (44,)),
            2: _block(2, (), (45,)),
            99: _block(99, (), (44,)),
        },
        entry_serial=44,
        func_ea=0,
    )

    patch_plan = compile_patch_plan(
        [
            DuplicateBlock(
                source_block=45,
                target_block=2,
                pred_serial=44,
            )
        ],
        cfg,
    )

    assert len(patch_plan.legacy_block_operations) == 1
    assert isinstance(patch_plan.legacy_block_operations[0], LegacyBlockOperation)
    assert patch_plan.new_blocks[0].kind == "duplicate_block"


def test_compile_patch_plan_finalizes_conditional_duplicate_block():
    patch_plan = compile_patch_plan(
        [
            DuplicateBlock(
                source_block=10,
                target_block=None,
                pred_serial=8,
            )
        ],
        _conditional_duplicate_cfg(),
    )

    assert patch_plan.contains_block_creation
    assert patch_plan.steps == (
        PatchDuplicateBlock(
            block_id=VirtualBlockId(namespace="duplicate_block", ordinal=0),
            assigned_serial=13,
            source_serial=10,
            pred_serial=8,
            pred_redirect_kind="one_way",
            source_successors=(11, 12),
            target_serial=None,
            conditional_target=11,
            fallthrough_target=12,
            fallthrough_block_id=VirtualBlockId(
                namespace="duplicate_block_fallthrough",
                ordinal=1,
            ),
            fallthrough_serial=14,
        ),
    )
    assert [spec.kind for spec in patch_plan.new_blocks] == [
        "duplicate_block_clone",
        "duplicate_block_fallthrough",
    ]
    assert patch_plan.legacy_block_operations == ()


def test_compile_patch_plan_finalizes_clone_conditional_as_goto():
    modification = CloneConditionalAsGoto(
        source_block=10,
        pred_serial=8,
        goto_target=11,
        reason="fix predecessor simple case",
    )

    patch_plan = compile_patch_plan([modification], _conditional_duplicate_cfg())

    assert patch_plan.contains_block_creation
    assert patch_plan.steps == (
        PatchCloneConditionalAsGoto(
            block_id=VirtualBlockId(namespace="clone_conditional_as_goto", ordinal=0),
            assigned_serial=13,
            source_serial=10,
            pred_serial=8,
            goto_target=11,
            source_successors=(11, 12),
            conditional_target=11,
            fallthrough_target=12,
            reason="fix predecessor simple case",
        ),
    )
    assert patch_plan.new_blocks == (
        PatchBlockSpec(
            block_id=VirtualBlockId(namespace="clone_conditional_as_goto", ordinal=0),
            kind="clone_conditional_as_goto",
            template_block=10,
            incoming_edge=PatchEdgeRef(source=8, target=10),
            outgoing_edges=(
                PatchEdgeRef(
                    source=VirtualBlockId(
                        namespace="clone_conditional_as_goto",
                        ordinal=0,
                    ),
                    target=11,
                ),
            ),
        ),
    )
    assert patch_plan.legacy_block_operations == ()
    assert patch_plan.as_graph_modifications() == [modification]


def test_clone_conditional_as_goto_projects_clone_and_pred_redirect_only():
    patch_plan = compile_patch_plan(
        [
            CloneConditionalAsGoto(
                source_block=10,
                pred_serial=8,
                goto_target=11,
            )
        ],
        _conditional_duplicate_cfg(),
    )

    projected = project_post_state(_conditional_duplicate_cfg(), patch_plan)

    assert projected.get_block(8).succs == (13,)
    assert projected.get_block(10).succs == (11, 12)
    assert projected.get_block(13).succs == (11,)
    assert projected.get_block(13).tail_opcode is not None


def test_compile_patch_plan_rejects_clone_conditional_as_goto_without_cfg():
    with pytest.raises(ValueError, match="requires FlowGraph context"):
        compile_patch_plan(
            [
                CloneConditionalAsGoto(
                    source_block=10,
                    pred_serial=8,
                    goto_target=11,
                )
            ]
        )


@pytest.mark.parametrize(
    ("cfg", "modification", "match"),
    (
        (
            _conditional_duplicate_cfg(),
            CloneConditionalAsGoto(source_block=12, pred_serial=8, goto_target=11),
            "does not target source",
        ),
        (
            _conditional_duplicate_cfg(),
            CloneConditionalAsGoto(source_block=10, pred_serial=8, goto_target=13),
            "not one of conditional arms",
        ),
        (
            FlowGraph(
                blocks={
                    8: _block(8, (11,), ()),
                    11: _block(11, (), (8,)),
                    12: _block(12, (), ()),
                },
                entry_serial=8,
                func_ea=0,
            ),
            CloneConditionalAsGoto(source_block=11, pred_serial=8, goto_target=12),
            "expected 2",
        ),
    ),
)
def test_compile_patch_plan_rejects_invalid_clone_conditional_as_goto_shapes(
    cfg: FlowGraph,
    modification: CloneConditionalAsGoto,
    match: str,
):
    with pytest.raises(ValueError, match=match):
        compile_patch_plan([modification], cfg)


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
    assert isinstance(patch_plan.steps[2], PatchInsertBlock)
    assert len(patch_plan.legacy_block_operations) == 0
    assert all(isinstance(step, LegacyBlockOperation) for step in patch_plan.legacy_block_operations)
    assert patch_plan.as_graph_modifications() == modifications


def test_ensure_patch_plan_is_idempotent():
    patch_plan = compile_patch_plan([
        RedirectGoto(from_serial=1, old_target=2, new_target=3),
    ])

    assert ensure_patch_plan(patch_plan) is patch_plan


# ---------------------------------------------------------------------------
# RemoveEdge invariant tests
# ---------------------------------------------------------------------------


def test_patch_remove_edge_exists_but_unused_in_strategies():
    """Document that PatchRemoveEdge/RemoveEdge exist but no Hodur strategy emits them.

    Scans every .py file under hodur/strategies/ for any reference to RemoveEdge.
    This is a meta-test: if it breaks, a strategy started using RemoveEdge and the
    executor / edit-simulator must be audited for correctness.
    """
    strategies_dir = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "d810"
        / "optimizers"
        / "microcode"
        / "flow"
        / "flattening"
        / "hodur"
        / "strategies"
    )
    assert strategies_dir.is_dir(), f"strategies dir not found: {strategies_dir}"

    violations: list[str] = []
    for py_file in sorted(strategies_dir.glob("*.py")):
        source = py_file.read_text()
        if "RemoveEdge" in source:
            violations.append(py_file.name)

    assert violations == [], (
        f"Hodur strategies referencing RemoveEdge: {violations}. "
        "No active strategy should emit RemoveEdge; audit executor if this changes."
    )


def test_modification_builder_has_no_remove_edge_method():
    """The ModificationBuilder -- sole factory for strategy modifications -- must
    not expose a ``remove_edge`` helper.  If one is added, this test forces a
    conscious review of executor/edit-simulator support.

    Uses source inspection to avoid importing the builder into this contract test.
    """
    from pathlib import Path

    bridge_path = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "d810"
        / "cfg"
        / "modification_builder.py"
    )
    assert bridge_path.exists(), f"ModificationBuilder source not found at {bridge_path}"
    source = bridge_path.read_text()
    assert "def remove_edge" not in source, (
        "ModificationBuilder gained a remove_edge method. "
        "Audit executor + edit-simulator before enabling."
    )


def test_compile_patch_plan_compiles_remove_edge():
    """compile_patch_plan has a code path for RemoveEdge.

    This test proves the compiler handles the type correctly (round-trips
    through PatchRemoveEdge), even though no active strategy emits it today.
    """
    modifications = [RemoveEdge(from_serial=5, to_serial=10)]
    patch_plan = compile_patch_plan(modifications)

    assert len(patch_plan.steps) == 1
    step = patch_plan.steps[0]
    assert isinstance(step, PatchRemoveEdge)
    assert step.from_serial == 5
    assert step.to_serial == 10

    # Round-trip back to GraphModification
    roundtripped = step.to_graph_modification()
    assert roundtripped == RemoveEdge(from_serial=5, to_serial=10)
