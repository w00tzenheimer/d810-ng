"""Unit tests for the 2-way predecessor branch-arm clone-as-goto planner.

The sibling planner ``plan_fix_predecessor_clone_from_branch_arm`` is the
engine-path admission for the legacy FixPredecessor live rule's
``change_2way_block_conditional_successor`` shape.  These tests cover the
admission gate and rejection axes called out in the next-slice plan
(``arm_known``-only; reject ambiguous, multi-pred target, side effects, and
non-2-way predecessor shapes).
"""
from __future__ import annotations

from d810.transforms.fix_predecessor_planning import (
    FixPredecessorCloneAsGotoFromBranchArmDecision,
    FixPredecessorOutcome,
    FixPredecessorRejectReason,
    plan_fix_predecessor_clone_from_branch_arm,
)
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.transforms.graph_modification import CloneConditionalAsGotoFromBranchArm


class _BlockRef:
    def __init__(self, block_num: int) -> None:
        self.block_num = block_num


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *,
    branch_target: int | None = None,
) -> BlockSnapshot:
    insns: tuple[InsnSnapshot, ...] = ()
    if branch_target is not None:
        ref = _BlockRef(branch_target)
        insns = (
            InsnSnapshot(
                opcode=0x70,
                ea=0x5000 + serial,
                operands=(ref,),
                operand_slots=(("d", ref),),
            ),
        )
    return BlockSnapshot(
        serial=serial,
        block_type=2 if len(succs) == 2 else (1 if succs else 0),
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x5000 + serial,
        insn_snapshots=insns,
    )


def _arm_one_cfg(*, target_npred: int = 1) -> FlowGraph:
    target_preds = (10,) + tuple(range(40, 40 + max(target_npred - 1, 0)))
    blocks = {
        # pred 7 is 2-way: explicit branch -> 10 (the cond), fallthrough -> 20
        7: _block(7, (20, 10), (), branch_target=10),
        # second pred so cond has multiple predecessors (clone is justified)
        8: _block(8, (10,), ()),
        10: _block(10, (11, 12), (7, 8), branch_target=12),
        11: _block(11, (), (10,)),
        12: _block(12, (), target_preds),
        20: _block(20, (), (7,)),
    }
    for extra in range(40, 40 + max(target_npred - 1, 0)):
        blocks[extra] = _block(extra, (12,), ())
    return FlowGraph(blocks=blocks, entry_serial=7, func_ea=0x401000)


def _arm_zero_cfg() -> FlowGraph:
    # pred 7 is 2-way: explicit branch -> 20, fallthrough -> 10 (the cond)
    blocks = {
        7: _block(7, (10, 20), (), branch_target=20),
        8: _block(8, (10,), ()),
        10: _block(10, (11, 12), (7, 8), branch_target=12),
        11: _block(11, (), (10,)),
        12: _block(12, (), (10,)),
        20: _block(20, (), (7,)),
    }
    return FlowGraph(blocks=blocks, entry_serial=7, func_ea=0x401000)


def test_admits_explicit_branch_arm_when_outcome_matches_target() -> None:
    decision = plan_fix_predecessor_clone_from_branch_arm(
        _arm_one_cfg(),
        pred_serial=7,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
        description="pred 7 arm=1 always takes jump in block 10",
    )

    assert decision.accepted
    candidate = decision.candidate
    assert candidate is not None
    assert candidate.pred_serial == 7
    assert candidate.pred_arm == 1
    assert candidate.conditional_serial == 10
    assert candidate.selected_target_serial == 12
    assert candidate.outcome == FixPredecessorOutcome.ALWAYS_TAKEN
    assert candidate.conditional_target_serial == 12
    assert candidate.fallthrough_target_serial == 11
    assert candidate.pred_branch_target_serial == 10
    assert candidate.pred_fallthrough_target_serial == 20
    assert candidate.lowering_status == "planned_modification_available"
    assert candidate.intent.operation_sequence == (
        "clone_conditional_block",
        "clear_clone_predecessors",
        "convert_clone_to_goto",
        "redirect_predecessor_branch_arm_to_clone",
    )
    assert candidate.to_graph_modification() == CloneConditionalAsGotoFromBranchArm(
        source_block=10,
        pred_serial=7,
        pred_arm=1,
        goto_target=12,
        reason="pred 7 arm=1 always takes jump in block 10",
    )


def test_admits_fallthrough_arm_when_outcome_matches_target() -> None:
    decision = plan_fix_predecessor_clone_from_branch_arm(
        _arm_zero_cfg(),
        pred_serial=7,
        conditional_serial=10,
        selected_target_serial=11,
        outcome=FixPredecessorOutcome.NEVER_TAKEN,
        description="pred 7 arm=0 never takes jump in block 10",
    )

    assert decision.accepted
    candidate = decision.candidate
    assert candidate is not None
    assert candidate.pred_serial == 7
    assert candidate.pred_arm == 0
    assert candidate.conditional_serial == 10
    assert candidate.selected_target_serial == 11
    assert candidate.outcome == FixPredecessorOutcome.NEVER_TAKEN
    assert candidate.conditional_target_serial == 12
    assert candidate.fallthrough_target_serial == 11
    assert candidate.pred_branch_target_serial == 20
    assert candidate.pred_fallthrough_target_serial == 10
    assert candidate.to_graph_modification() == CloneConditionalAsGotoFromBranchArm(
        source_block=10,
        pred_serial=7,
        pred_arm=0,
        goto_target=11,
        reason="pred 7 arm=0 never takes jump in block 10",
    )


def test_rejects_one_way_predecessor() -> None:
    cfg = FlowGraph(
        blocks={
            8: _block(8, (10,), ()),
            9: _block(9, (10,), ()),
            10: _block(10, (11, 12), (8, 9), branch_target=12),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
        },
        entry_serial=8,
        func_ea=0x401000,
    )
    decision = plan_fix_predecessor_clone_from_branch_arm(
        cfg,
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )

    assert not decision.accepted
    assert decision.rejection_reason is FixPredecessorRejectReason.PRED_NOT_TWO_WAY


def test_rejects_ambiguous_branch_arm_when_pred_tail_has_no_explicit_target() -> None:
    # pred 7 has no operand_slots -> infer_conditional_target returns None.
    cfg = FlowGraph(
        blocks={
            7: _block(7, (20, 10), ()),  # 2-way but no tail branch_target
            8: _block(8, (10,), ()),
            10: _block(10, (11, 12), (7, 8), branch_target=12),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
            20: _block(20, (), (7,)),
        },
        entry_serial=7,
        func_ea=0x401000,
    )
    decision = plan_fix_predecessor_clone_from_branch_arm(
        cfg,
        pred_serial=7,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )

    assert not decision.accepted
    assert decision.rejection_reason is FixPredecessorRejectReason.PRED_ARM_AMBIGUOUS


def test_rejects_predecessor_that_does_not_target_source() -> None:
    cfg = FlowGraph(
        blocks={
            7: _block(7, (20, 21), (), branch_target=21),
            8: _block(8, (10,), ()),
            10: _block(10, (11, 12), (8,), branch_target=12),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
            20: _block(20, (), (7,)),
            21: _block(21, (), (7,)),
        },
        entry_serial=7,
        func_ea=0x401000,
    )
    decision = plan_fix_predecessor_clone_from_branch_arm(
        cfg,
        pred_serial=7,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )

    assert not decision.accepted
    assert decision.rejection_reason is (
        FixPredecessorRejectReason.PRED_DOES_NOT_TARGET_SOURCE
    )


def test_rejects_multi_pred_target() -> None:
    decision = plan_fix_predecessor_clone_from_branch_arm(
        _arm_one_cfg(target_npred=3),
        pred_serial=7,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )

    assert not decision.accepted
    assert decision.rejection_reason is (
        FixPredecessorRejectReason.TARGET_NOT_SINGLE_PRED
    )


def test_rejects_conditional_with_body_side_effects() -> None:
    decision = plan_fix_predecessor_clone_from_branch_arm(
        _arm_one_cfg(),
        pred_serial=7,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
        side_effect_blocks=frozenset({10}),
    )

    assert not decision.accepted
    assert decision.rejection_reason is (
        FixPredecessorRejectReason.CONDITIONAL_HAS_SIDE_EFFECTS
    )


def test_rejects_outcome_target_mismatch() -> None:
    decision = plan_fix_predecessor_clone_from_branch_arm(
        _arm_one_cfg(),
        pred_serial=7,
        conditional_serial=10,
        selected_target_serial=11,  # fallthrough arm of cond
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,  # expects conditional arm
    )

    assert not decision.accepted
    assert decision.rejection_reason is (
        FixPredecessorRejectReason.OUTCOME_TARGET_MISMATCH
    )


def test_rejects_self_loop_target() -> None:
    decision = plan_fix_predecessor_clone_from_branch_arm(
        _arm_one_cfg(),
        pred_serial=7,
        conditional_serial=10,
        selected_target_serial=10,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )

    assert not decision.accepted
    assert decision.rejection_reason is FixPredecessorRejectReason.SELF_LOOP_TARGET


def test_rejects_missing_block() -> None:
    cfg = FlowGraph(
        blocks={
            8: _block(8, (10,), ()),
            10: _block(10, (11, 12), (8,), branch_target=12),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
        },
        entry_serial=8,
        func_ea=0x401000,
    )
    decision = plan_fix_predecessor_clone_from_branch_arm(
        cfg,
        pred_serial=99,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )

    assert not decision.accepted
    assert decision.rejection_reason is FixPredecessorRejectReason.MISSING_BLOCK
