"""Tests for the Phase B PatchPlan execution layer."""
from __future__ import annotations

import ast
import inspect
import textwrap
from dataclasses import dataclass
from pathlib import Path

import pytest

from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
from d810.ir.maturity import MaturityEnvelope
from d810.transforms.edit_simulator import project_post_state
from d810.transforms.graph_modification import (
    BypassDispatcherTrampoline,
    CanonicalizeJumpTableCaseOverlap,
    CloneConditionalAsGoto,
    CloneConditionalAsGotoFromBranchArm,
    ConvertToGoto,
    CreateConditionalRedirect,
    DuplicateReplayAndRedirect,
    DuplicateReplayEntry,
    DuplicateBlock,
    EdgeRedirectViaPredSplit,
    InsertBlock,
    LowerConditionalStateTransition,
    NormalizeNWayDispatcherExit,
    NopInstructions,
    PhaseCycleLowering,
    RedirectBranch,
    RedirectGoto,
    RemoveEdge,
    RetargetOutputStore,
    ScalarizeLocalAliasAccess,
)
from d810.transforms.materialization_payload import (
    CapturedBlockBody,
    CapturedBlockBodySummary,
)
from d810.transforms.plan import (
    PatchBlockSpec,
    PatchCloneConditionalAsGoto,
    PatchCloneConditionalAsGotoFromBranchArm,
    PatchConditionalRedirect,
    PatchConvertToGoto,
    PatchDuplicateBlock,
    PatchDuplicateReplayEntry,
    PatchDuplicateReplayAndRedirect,
    PatchEdgeRef,
    PatchEdgeSplitCorridor,
    PatchEdgeSplitTrampoline,
    PatchExitPathLoweringSite,
    PatchInsertBlock,
    PatchLowerConditionalStateTransition,
    PatchNormalizeNWayDispatcherExit,
    PatchNopInstructions,
    PatchBypassDispatcherTrampoline,
    PatchCanonicalizeJumpTableCaseOverlap,
    PatchPhaseCycleLowering,
    PatchPlan,
    PatchRedirectBranch,
    PatchRedirectGoto,
    PatchRelocationMap,
    PatchReorderBlocks,
    PatchRemoveEdge,
    PatchRetargetOutputStore,
    PatchScalarizeLocalAliasAccess,
    compile_patch_plan as _compile_patch_plan,
    ensure_patch_plan,
)
from d810.transforms.cfg_transaction import (
    NativeBlockRef,
    LogicalBlockRef,
    PlanBlockRef,
)


@dataclass(frozen=True)
class _BlockRef:
    block_num: int


TEST_MATURITY = MaturityEnvelope(ir=None, provider="hexrays", provider_id=4)


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


def _snapshot_serial(ref, plan: PatchPlan) -> int:
    return dict(plan.source_coordinates)[ref]


def _logical(serial: int) -> LogicalBlockRef:
    return LogicalBlockRef("test-plan-session", f"proxy-{serial}", 0)


def compile_patch_plan(*args, **kwargs) -> PatchPlan:
    """Compile test fixtures with explicit observed-source witnesses."""
    kwargs.setdefault(
        "block_refs_by_serial",
        {serial: _logical(serial) for serial in range(1024)},
    )
    return _compile_patch_plan(*args, **kwargs)


def _assert_plan_ref(ref: PlanBlockRef, plan: PatchPlan) -> None:
    assert isinstance(ref, PlanBlockRef)
    assert ref.plan_id == plan.plan_id


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


def _corridor_cfg() -> FlowGraph:
    return FlowGraph(
        blocks={
            9: _block(9, (10,), ()),
            10: _block(10, (11,), (9,)),
            11: _block(11, (13,), (10,)),
            12: _block(12, (), ()),
            13: _block(13, (), (11,)),
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
                        kind=InsnKind.COND_JUMP,
                    ),
                ),
            ),
            11: _block(11, (), (10,)),
            14: _block(14, (), (10,)),
        },
        entry_serial=9,
        func_ea=0,
    )


def test_redirect_branch_declares_helper_only_for_fallthrough_rewrite() -> None:
    plan = compile_patch_plan(
        [RedirectBranch(from_serial=10, old_target=11, new_target=9)],
        _conditional_cfg(),
        plan_id="fallthrough-helper-plan",
    )

    step = plan.steps[0]
    assert isinstance(step, PatchRedirectBranch)
    assert step.fallthrough_helper_block_id == PlanBlockRef(
        "fallthrough-helper-plan", "redirect_branch_fallthrough:0"
    )
    assert plan.new_blocks == (
        PatchBlockSpec(
            block_id=step.fallthrough_helper_block_id,
            kind="redirect_branch_fallthrough",
            template_block=step.from_serial,
            incoming_edge=PatchEdgeRef(
                source=step.from_serial,
                target=step.fallthrough_helper_block_id,
            ),
            outgoing_edges=(
                PatchEdgeRef(
                    source=step.fallthrough_helper_block_id,
                    target=step.new_target,
                ),
            ),
        ),
    )


def test_redirect_branch_direct_arm_declares_no_helper() -> None:
    plan = compile_patch_plan(
        [RedirectBranch(from_serial=10, old_target=14, new_target=9)],
        _conditional_cfg(),
        plan_id="direct-branch-plan",
    )

    step = plan.steps[0]
    assert isinstance(step, PatchRedirectBranch)
    assert step.fallthrough_helper_block_id is None
    assert plan.new_blocks == ()


def test_redirect_branch_rejects_nonconditional_two_way_tail_before_reservation() -> None:
    cfg = FlowGraph(
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
                        kind=InsnKind.UNKNOWN,
                    ),
                ),
            ),
            11: _block(11, (), (10,)),
            14: _block(14, (), (10,)),
        },
        entry_serial=9,
        func_ea=0,
    )

    with pytest.raises(ValueError, match="redirectable conditional tail"):
        compile_patch_plan(
            [RedirectBranch(from_serial=10, old_target=11, new_target=9)],
            cfg,
            plan_id="malformed-two-way-plan",
        )


def test_patch_operations_reject_bare_block_serials() -> None:
    with pytest.raises(TypeError, match="from_serial must be a typed block reference"):
        PatchRedirectGoto(from_serial=9, old_target=10, new_target=11)

    snapshot = _logical(9)
    with pytest.raises(TypeError, match="goto_target must be a typed block reference"):
        PatchConvertToGoto(block_serial=snapshot, goto_target=10)

    with pytest.raises(TypeError, match="anchor_serial must be a typed block reference"):
        PatchExitPathLoweringSite(anchor_serial=9, kind=object())

    created = PlanBlockRef("typed-plan", "reorder:0")
    with pytest.raises(TypeError, match="copy_lineage source must be a typed block reference"):
        PatchReorderBlocks(
            dfs_block_order=(snapshot,),
            copy_lineage=((9, created),),
        )

    with pytest.raises(TypeError, match="block_id must be a typed block reference"):
        PatchDuplicateBlock(
            block_id=12,
            source_serial=snapshot,
            pred_serial=None,
            pred_redirect_kind="none",
            source_successors=(),
        )


@pytest.mark.parametrize(
    ("case", "message"),
    (
        ("incoming_edge", "incoming_edge must be a PatchEdgeRef"),
        ("outgoing_edges", "outgoing_edges must contain PatchEdgeRef"),
        ("rewritten_edges", "rewritten_edges must contain PatchEdgeRef pairs"),
        (
            "replay_group",
            "per_pred_replays must contain PatchDuplicateReplayEntry",
        ),
        ("replay_entry", "pred_serial must be a typed block reference"),
    ),
)
def test_nested_patch_payloads_reject_untyped_or_malformed_references(
    case: str,
    message: str,
) -> None:
    created = PlanBlockRef("typed-plan", "nested:0")
    snapshot = _logical(9)

    def construct() -> object:
        if case == "incoming_edge":
            return PatchBlockSpec(created, "insert", incoming_edge=object())
        if case == "outgoing_edges":
            return PatchBlockSpec(created, "insert", outgoing_edges=(object(),))
        if case == "rewritten_edges":
            return PatchRelocationMap(
                rewritten_edges=((PatchEdgeRef(snapshot, snapshot), object()),)
            )
        if case == "replay_group":
            return PatchDuplicateReplayAndRedirect(
                source_serial=snapshot,
                dispatcher_entry=snapshot,
                per_pred_replays=(object(),),
            )
        return PatchDuplicateReplayEntry(
            pred_serial=9,
            target_serial=snapshot,
            replay_block_id=created,
            captured_body=object(),
        )

    with pytest.raises(TypeError, match=message):
        construct()


def test_patch_plan_requires_exact_plan_reference_authority() -> None:
    source = _logical(9)
    target = PlanBlockRef("foreign-plan", "target")
    with pytest.raises(ValueError, match="plan authority"):
        PatchPlan(
            plan_id="typed-plan",
            snapshot_id="snap:m4:g7",
            source_maturity=TEST_MATURITY,
            source_generation=7,
            steps=(PatchRedirectGoto(source, source, target),),
        )


def test_patch_relocation_records_only_plan_reference_lineage() -> None:
    created = PlanBlockRef("typed-plan", "insert:0")
    source = _logical(9)
    relocation = PatchRelocationMap(
        planned_lineage=((created, source),),
    )

    assert relocation.planned_lineage == ((created, source),)
    assert not hasattr(relocation, "assigned_serials")


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


def _duplicate_replay_cfg() -> FlowGraph:
    return FlowGraph(
        blocks={
            2: _block(2, (3, 4), (10,),),
            3: _block(3, (), (2,)),
            4: _block(4, (), (2,)),
            8: _block(8, (10,), ()),
            9: _block(9, (10,), ()),
            10: _block(10, (2,), (8, 9)),
            20: _block(20, (), ()),
        },
        entry_serial=8,
        func_ea=0,
    )


def _captured_body(source_serial: int = 10) -> CapturedBlockBody:
    instructions = (InsnSnapshot(opcode=0x77, ea=0x2000, operands=()),)
    return CapturedBlockBody(
        backend_id="fake",
        capture_id=f"fake-body:{source_serial}",
        summary=CapturedBlockBodySummary(
            source_blocks=(source_serial,),
            instruction_count=len(instructions),
            source_eas=frozenset({0x2000}),
        ),
        payload=instructions,
    )


def test_compile_patch_plan_converts_existing_block_rewrites():
    modifications = [
        RedirectGoto(from_serial=1, old_target=2, new_target=3),
        ConvertToGoto(block_serial=4, goto_target=5),
        NopInstructions(block_serial=6, insn_eas=(0x1000, 0x1004)),
    ]

    patch_plan = compile_patch_plan(
        modifications,
        block_refs_by_serial={serial: _logical(serial) for serial in range(1, 8)},
    )

    assert isinstance(patch_plan, PatchPlan)
    assert tuple(type(step) for step in patch_plan.steps) == (
        PatchRedirectGoto,
        PatchConvertToGoto,
        PatchNopInstructions,
    )
    assert all(
        not isinstance(value, int)
        for step in patch_plan.steps
        for name, value in vars(step).items()
        if "serial" in name or "target" in name
    )
    assert patch_plan.new_blocks == ()
    assert {serial for _ref, serial in patch_plan.source_coordinates} == set(
        range(1, 7)
    )


def test_compile_patch_plan_rejects_missing_typed_source_authority() -> None:
    with pytest.raises(TypeError, match="block serial 1 has no typed source authority"):
        _compile_patch_plan(
            [RedirectGoto(from_serial=1, old_target=2, new_target=3)]
        )


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
    step = patch_plan.steps[0]
    assert isinstance(step, PatchEdgeSplitTrampoline)
    assert step.block_id == patch_plan.new_blocks[0].block_id
    _assert_plan_ref(step.block_id, patch_plan)
    assert patch_plan.new_blocks[0].kind == "edge_split_trampoline"
    assert patch_plan.relocation_map.planned_lineage == (
        (step.block_id, step.template_block),
    )
    assert _snapshot_serial(patch_plan.relocation_map.source_stop, patch_plan) == 11


def test_compile_patch_plan_finalizes_corridor_edge_split():
    modification = EdgeRedirectViaPredSplit(
        src_block=10,
        old_target=11,
        new_target=12,
        via_pred=9,
        clone_until=11,
    )

    patch_plan = compile_patch_plan([modification], _corridor_cfg())

    step = patch_plan.steps[0]
    assert isinstance(step, PatchEdgeSplitCorridor)
    assert all(isinstance(ref, PlanBlockRef) for ref in step.clone_block_ids)
    assert all(ref.plan_id == patch_plan.plan_id for ref in step.clone_block_ids)
    assert [spec.kind for spec in patch_plan.new_blocks] == [
        "edge_split_corridor_clone",
        "edge_split_corridor_clone",
    ]


def test_compile_patch_plan_finalizes_conditional_redirect():
    patch_plan = compile_patch_plan(
        [
            CreateConditionalRedirect(
                source_block=9,
                ref_block=10,
                conditional_target=14,
                fallthrough_target=11,
                old_target_serial=10,
            )
        ],
        _conditional_cfg(),
    )

    assert patch_plan.contains_block_creation
    step = patch_plan.steps[0]
    assert isinstance(step, PatchConditionalRedirect)
    _assert_plan_ref(step.block_id, patch_plan)
    _assert_plan_ref(step.fallthrough_block_id, patch_plan)
    assert [spec.kind for spec in patch_plan.new_blocks] == [
        "conditional_redirect_clone",
        "conditional_redirect_fallthrough",
    ]
    assert _snapshot_serial(patch_plan.relocation_map.source_stop, patch_plan) == 14


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

    step = patch_plan.steps[0]
    assert isinstance(step, PatchConditionalRedirect)
    assert step.instructions == instructions


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
    step = patch_plan.steps[0]
    assert isinstance(step, PatchInsertBlock)
    _assert_plan_ref(step.block_id, patch_plan)
    assert step.instructions == instructions
    assert [spec.kind for spec in patch_plan.new_blocks] == ["insert_block"]
    assert _snapshot_serial(patch_plan.relocation_map.source_stop, patch_plan) == 11


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
    step = patch_plan.steps[0]
    assert isinstance(step, PatchInsertBlock)
    assert step.captured_body is body


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
    step = patch_plan.steps[0]
    assert isinstance(step, PatchInsertBlock)
    _assert_plan_ref(step.block_id, patch_plan)
    assert [spec.kind for spec in patch_plan.new_blocks] == ["insert_block"]
    assert patch_plan.new_blocks[0].incoming_edge.source == step.pred_serial
    assert patch_plan.new_blocks[0].incoming_edge.target == step.old_target_serial
    assert patch_plan.new_blocks[0].outgoing_edges[0].source == step.block_id
    assert _snapshot_serial(patch_plan.relocation_map.source_stop, patch_plan) == 14


def test_empty_insert_block_compiles_as_runtime_trampoline():
    patch_plan = compile_patch_plan(
        [
            InsertBlock(
                pred_serial=9,
                old_target_serial=10,
                succ_serial=11,
            )
        ],
        _conditional_cfg(),
    )

    assert patch_plan.contains_block_creation
    assert patch_plan.new_blocks[0].kind == "insert_block"
    assert patch_plan.new_blocks[0].instructions == ()
    assert patch_plan.new_blocks[0].captured_body is None
    assert isinstance(patch_plan.steps[0], PatchInsertBlock)


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
    step = patch_plan.steps[0]
    assert isinstance(step, PatchDuplicateBlock)
    _assert_plan_ref(step.block_id, patch_plan)
    assert [spec.kind for spec in patch_plan.new_blocks] == ["duplicate_block_clone"]


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
    step = patch_plan.steps[0]
    assert isinstance(step, PatchDuplicateBlock)
    assert step.target_serial is None
    assert [spec.kind for spec in patch_plan.new_blocks] == ["duplicate_block_clone"]


def test_compile_patch_plan_finalizes_duplicate_replay_and_redirect_without_legacy() -> None:
    left_body = _captured_body()
    right_body = _captured_body()
    modification = DuplicateReplayAndRedirect(
        source_serial=10,
        dispatcher_entry=2,
        per_pred_replays=(
            DuplicateReplayEntry(
                pred_serial=8,
                target_serial=3,
                captured_body=left_body,
            ),
            DuplicateReplayEntry(
                pred_serial=9,
                target_serial=4,
                captured_body=right_body,
            ),
        ),
    )

    patch_plan = compile_patch_plan([modification], _duplicate_replay_cfg())

    assert patch_plan.contains_block_creation
    step = patch_plan.steps[0]
    assert isinstance(step, PatchDuplicateReplayAndRedirect)
    assert [_snapshot_serial(row.pred_serial, patch_plan) for row in step.per_pred_replays] == [8, 9]
    assert [_snapshot_serial(row.target_serial, patch_plan) for row in step.per_pred_replays] == [3, 4]
    assert all(
        isinstance(row.replay_block_id, PlanBlockRef)
        for row in step.per_pred_replays
    )
    assert all(
        row.replay_block_id.plan_id == patch_plan.plan_id
        for row in step.per_pred_replays
    )
    assert [spec.kind for spec in patch_plan.new_blocks] == [
        "duplicate_replay_insert",
        "duplicate_replay_insert",
        "duplicate_replay_clone",
    ]


def test_compile_patch_plan_rejects_invalid_duplicate_replay_shapes() -> None:
    with pytest.raises(ValueError, match="predecessor 11 not found"):
        compile_patch_plan(
            [
                DuplicateReplayAndRedirect(
                    source_serial=10,
                    dispatcher_entry=2,
                    per_pred_replays=(
                        DuplicateReplayEntry(
                            pred_serial=8,
                            target_serial=3,
                            captured_body=_captured_body(),
                        ),
                        DuplicateReplayEntry(
                            pred_serial=11,
                            target_serial=4,
                            captured_body=_captured_body(),
                        ),
                    ),
                )
            ],
            _duplicate_replay_cfg(),
        )


def test_compile_patch_plan_rejects_unsupported_duplicate_block():
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

    with pytest.raises(ValueError, match="cannot be compiled"):
        compile_patch_plan(
            [
                DuplicateBlock(
                    source_block=45,
                    target_block=2,
                    pred_serial=44,
                )
            ],
            cfg,
        )


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
    step = patch_plan.steps[0]
    assert isinstance(step, PatchDuplicateBlock)
    _assert_plan_ref(step.block_id, patch_plan)
    _assert_plan_ref(step.fallthrough_block_id, patch_plan)
    assert [spec.kind for spec in patch_plan.new_blocks] == [
        "duplicate_block_clone",
        "duplicate_block_fallthrough",
    ]


def test_compile_patch_plan_finalizes_clone_conditional_as_goto():
    modification = CloneConditionalAsGoto(
        source_block=10,
        pred_serial=8,
        goto_target=11,
        reason="fix predecessor simple case",
    )

    patch_plan = compile_patch_plan([modification], _conditional_duplicate_cfg())

    assert patch_plan.contains_block_creation
    step = patch_plan.steps[0]
    assert isinstance(step, PatchCloneConditionalAsGoto)
    _assert_plan_ref(step.block_id, patch_plan)
    assert patch_plan.new_blocks[0].block_id == step.block_id
    assert patch_plan.new_blocks[0].kind == "clone_conditional_as_goto"


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

    patch_plan = compile_patch_plan(modifications, _cfg())

    assert patch_plan.contains_block_creation
    assert len(patch_plan.new_blocks) == 4
    assert all(isinstance(spec, PatchBlockSpec) for spec in patch_plan.new_blocks)
    assert all(isinstance(spec.block_id, PlanBlockRef) for spec in patch_plan.new_blocks)
    assert [spec.kind for spec in patch_plan.new_blocks] == [
        "edge_split_trampoline",
        "conditional_redirect_clone",
        "conditional_redirect_fallthrough",
        "insert_block",
    ]
    assert isinstance(patch_plan.steps[0], PatchEdgeSplitTrampoline)
    assert isinstance(patch_plan.steps[1], PatchConditionalRedirect)
    assert isinstance(patch_plan.steps[2], PatchInsertBlock)


def test_ensure_patch_plan_is_idempotent():
    patch_plan = compile_patch_plan([
        RedirectGoto(from_serial=1, old_target=2, new_target=3),
    ])

    assert ensure_patch_plan(patch_plan) is patch_plan


# ---------------------------------------------------------------------------
# RemoveEdge invariant tests
# ---------------------------------------------------------------------------


def test_patch_remove_edge_exists_but_unused_in_strategies():
    """Document that PatchRemoveEdge/RemoveEdge exist but no Hodur strategy emits them."""
    root = Path(__file__).resolve().parents[3]
    strategy_paths = (
        root / "src/d810/backends/hexrays/evidence/conditional_fork_fallback.py",
        root / "src/d810/backends/hexrays/evidence/counter_hoist.py",
        root / "src/d810/backends/hexrays/evidence/dead_state_variable_elimination.py",
        root / "src/d810/backends/hexrays/evidence/inner_merge_duplication.py",
        root / "src/d810/backends/hexrays/evidence/spurious_backedge_redirect.py",
        root / "src/d810/backends/hexrays/evidence/state_constant_return_fixup.py",
        root / "src/d810/backends/hexrays/evidence/terminal_loop_cleanup.py",
        root / "src/d810/backends/hexrays/evidence/topological_sort.py",
        root / "src/d810/backends/hexrays/evidence/valrange_resolution.py",
        root / "src/d810/transforms/edge_split_conflict.py",
    )

    violations: list[str] = []
    for py_file in strategy_paths:
        assert py_file.is_file(), f"Hodur strategy source not found: {py_file}"
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in {"RemoveEdge", "PatchRemoveEdge"}:
                violations.append(py_file.name)
                break
            if isinstance(node, ast.Attribute) and node.attr in {"RemoveEdge", "PatchRemoveEdge"}:
                violations.append(py_file.name)
                break

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
        / "transforms"
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
    assert _snapshot_serial(step.from_serial, patch_plan) == 5
    assert _snapshot_serial(step.to_serial, patch_plan) == 10



def _branch_arm_clone_cfg() -> FlowGraph:
    """CFG with a 2-way predecessor whose explicit branch arm targets the cond.

    Mirrors :func:`_conditional_duplicate_cfg` but the predecessor at blk[7]
    is itself 2-way: ``pred.tail.d.b == 10`` (arm=1) and fallthrough goes to
    blk[20].  Block 10 is the 2-way conditional with arms 11 (fallthrough)
    and 12 (explicit branch target). Selected goto target is blk[12].
    """
    return FlowGraph(
        blocks={
            7: _block(
                7,
                (20, 10),
                (),
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0x70,
                        ea=0x1007,
                        operands=(_BlockRef(10),),
                        operand_slots=(("d", _BlockRef(10)),),
                    ),
                ),
            ),
            8: _block(8, (10,), ()),
            10: _block(
                10,
                (11, 12),
                (7, 8),
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0x70,
                        ea=0x1010,
                        operands=(_BlockRef(12),),
                        operand_slots=(("d", _BlockRef(12)),),
                    ),
                ),
            ),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
            20: _block(20, (), (7,)),
        },
        entry_serial=7,
        func_ea=0,
    )


def _branch_arm_clone_fallthrough_cfg() -> FlowGraph:
    """CFG with a 2-way predecessor whose fallthrough arm targets the cond."""
    return FlowGraph(
        blocks={
            7: _block(
                7,
                (10, 20),
                (),
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0x70,
                        ea=0x1007,
                        operands=(_BlockRef(20),),
                        operand_slots=(("d", _BlockRef(20)),),
                    ),
                ),
            ),
            8: _block(8, (10,), ()),
            10: _block(
                10,
                (11, 12),
                (7, 8),
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0x70,
                        ea=0x1010,
                        operands=(_BlockRef(12),),
                        operand_slots=(("d", _BlockRef(12)),),
                    ),
                ),
            ),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
            20: _block(20, (), (7,)),
        },
        entry_serial=7,
        func_ea=0,
    )


def test_clone_conditional_as_goto_from_branch_arm_projects_clone_and_arm_redirect():
    patch_plan = compile_patch_plan(
        [
            CloneConditionalAsGotoFromBranchArm(
                source_block=10,
                pred_serial=7,
                pred_arm=1,
                goto_target=12,
            )
        ],
        _branch_arm_clone_cfg(),
    )

    assert patch_plan.contains_block_creation
    assert patch_plan.new_blocks[0].kind == "clone_conditional_as_goto_from_branch_arm"
    assert len(patch_plan.steps) == 1
    step = patch_plan.steps[0]
    assert isinstance(step, PatchCloneConditionalAsGotoFromBranchArm)
    assert _snapshot_serial(step.source_serial, patch_plan) == 10
    assert _snapshot_serial(step.pred_serial, patch_plan) == 7
    assert step.pred_arm == 1
    assert _snapshot_serial(step.goto_target, patch_plan) == 12
    assert _snapshot_serial(step.conditional_target, patch_plan) == 12
    assert _snapshot_serial(step.fallthrough_target, patch_plan) == 11
    assert _snapshot_serial(step.pred_branch_target_serial, patch_plan) == 10
    # Allocator places the clone before existing terminal blocks, which
    # shifts the original pred_fallthrough (blk[20]) one slot up.  The
    # relocation map is applied here, so the recorded fallthrough is whatever
    # serial blk[20] now lives at after the clone slot is reserved.
    assert _snapshot_serial(step.pred_fallthrough_target_serial, patch_plan) >= 20
    _assert_plan_ref(step.block_id, patch_plan)

    # Post-state projection: pred 7's explicit branch arm now points at the
    # clone (block_id), clone points at the selected target 12, and
    # the source conditional 10 retains both arms (still reachable from blk[8]).
    projected = project_post_state(_branch_arm_clone_cfg(), patch_plan)
    assert projected.get_block(10).succs == (11, 12)
    clone = projected.get_block(max(_branch_arm_clone_cfg().blocks))
    assert clone is not None
    assert clone.succs == (12,)


def test_clone_conditional_as_goto_from_fallthrough_arm_projects_clone_and_redirect():
    patch_plan = compile_patch_plan(
        [
            CloneConditionalAsGotoFromBranchArm(
                source_block=10,
                pred_serial=7,
                pred_arm=0,
                goto_target=11,
            )
        ],
        _branch_arm_clone_fallthrough_cfg(),
    )

    assert patch_plan.contains_block_creation
    step = patch_plan.steps[0]
    assert isinstance(step, PatchCloneConditionalAsGotoFromBranchArm)
    assert step.pred_arm == 0
    assert _snapshot_serial(step.goto_target, patch_plan) == 11
    assert _snapshot_serial(step.pred_branch_target_serial, patch_plan) >= 20
    assert _snapshot_serial(step.pred_fallthrough_target_serial, patch_plan) == 10
    assert _snapshot_serial(step.conditional_target, patch_plan) == 12
    assert _snapshot_serial(step.fallthrough_target, patch_plan) == 11

    projected = project_post_state(_branch_arm_clone_fallthrough_cfg(), patch_plan)
    pred = projected.get_block(7)
    assert pred is not None
    clone_serial = max(_branch_arm_clone_fallthrough_cfg().blocks)
    assert clone_serial in pred.succs
    clone = projected.get_block(clone_serial)
    assert clone is not None
    assert clone.succs == (11,)


def test_compile_patch_plan_rejects_clone_conditional_as_goto_from_branch_arm_without_cfg():
    with pytest.raises(ValueError, match="requires FlowGraph context"):
        compile_patch_plan(
            [
                CloneConditionalAsGotoFromBranchArm(
                    source_block=10,
                    pred_serial=7,
                    pred_arm=1,
                    goto_target=12,
                )
            ]
        )


@pytest.mark.parametrize(
    ("modification", "match"),
    (
        (
            CloneConditionalAsGotoFromBranchArm(
                source_block=99,
                pred_serial=7,
                pred_arm=1,
                goto_target=12,
            ),
            "source block 99 not found",
        ),
        (
            CloneConditionalAsGotoFromBranchArm(
                source_block=10,
                pred_serial=8,  # 1-way pred — invalid for branch-arm shape
                pred_arm=1,
                goto_target=12,
            ),
            "expected 2",
        ),
        (
            CloneConditionalAsGotoFromBranchArm(
                source_block=10,
                pred_serial=7,
                pred_arm=2,
                goto_target=12,
            ),
            "pred_arm must be 0 or 1",
        ),
        (
            CloneConditionalAsGotoFromBranchArm(
                source_block=10,
                pred_serial=7,
                pred_arm=0,
                goto_target=12,
            ),
            "pred_arm=0 but pred fallthrough is 20, not source 10",
        ),
        (
            CloneConditionalAsGotoFromBranchArm(
                source_block=10,
                pred_serial=7,
                pred_arm=1,
                goto_target=10,
            ),
            "self-loop to source",
        ),
        (
            CloneConditionalAsGotoFromBranchArm(
                source_block=10,
                pred_serial=7,
                pred_arm=1,
                goto_target=99,
            ),
            "goto target 99 not found",
        ),
    ),
)
def test_compile_patch_plan_rejects_invalid_branch_arm_clone_shapes(
    modification: CloneConditionalAsGotoFromBranchArm,
    match: str,
):
    with pytest.raises(ValueError, match=match):
        compile_patch_plan([modification], _branch_arm_clone_cfg())


def test_compile_patch_plan_round_trips_legacy_flow_primitives():
    condition = ("mop", "cond")
    modifications = [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=2,
            rewrite_from_ea=0x401000,
            condition_operand=condition,
            false_target_serial=20,
            true_target_serial=30,
            proof_id="abc-proof",
            state_register=20,
            state_size=4,
            false_state=0xDEF4B7E6,
            true_state=0xA5540595,
            false_state_write_ea=None,
            true_state_write_ea=0x40C50B,
        ),
        NormalizeNWayDispatcherExit(
            block_serial=11,
            dispatcher_entry_serial=2,
            keep_target_serial=40,
        ),
        BypassDispatcherTrampoline(
            source_serial=12,
            trampoline_serial=2,
            target_serial=41,
        ),
        CanonicalizeJumpTableCaseOverlap(
            jtbl_serial=13,
            retarget_map=((50, 60), (51, 61)),
            deduplicate=True,
        ),
        ScalarizeLocalAliasAccess(
            block_serial=14,
            host_ea=0x401040,
            host_opcode=123,
            alias_token="var_10",
            base_token="var_20",
            host_text_sha1="abc123",
            value_size=8,
        ),
        RetargetOutputStore(
            block_serial=15,
            host_ea=0x401050,
            host_opcode=124,
            alias_token="var_370",
            output_token="var_30",
            host_text_sha1="def456",
            value_size=4,
        ),
        PhaseCycleLowering(
            header_entries=(16,),
            header_target=17,
            body_entries=(18,),
            body_target=16,
            next_phase_entries=(19,),
            next_phase_target=20,
            terminal_entries=(21,),
            terminal_target=22,
            state_roles=(("header", 16),),
        ),
    ]

    plan = compile_patch_plan(modifications)

    assert isinstance(plan.steps[0], PatchLowerConditionalStateTransition)
    assert isinstance(plan.steps[1], PatchNormalizeNWayDispatcherExit)
    assert isinstance(plan.steps[2], PatchBypassDispatcherTrampoline)
    assert isinstance(plan.steps[3], PatchCanonicalizeJumpTableCaseOverlap)
    assert isinstance(plan.steps[4], PatchScalarizeLocalAliasAccess)
    assert isinstance(plan.steps[5], PatchRetargetOutputStore)
    assert isinstance(plan.steps[6], PatchPhaseCycleLowering)
