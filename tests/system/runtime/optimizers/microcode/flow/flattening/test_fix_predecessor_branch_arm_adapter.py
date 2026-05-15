"""Adapter parity tests for the 2-way branch-arm planner.

Drives synthetic CFGs that mirror the 12 ``two_way_predecessor_arm_known``
records captured from a live ``sub_7FFD3338C040`` corpus dump and asserts
the adapter admits each shape via the new sibling primitive.
"""
from __future__ import annotations

import pytest

from d810.cfg.fix_predecessor_planning import (
    FixPredecessorOutcome,
    FixPredecessorRejectReason,
)
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.cfg.graph_modification import CloneConditionalAsGotoFromBranchArm
from d810.optimizers.microcode.flow.flattening.fix_pred_cond_jump_block import (
    PredecessorModification,
    PredecessorModificationType,
    plan_predecessor_modification_clone_as_goto,
    plan_predecessor_modification_clone_from_branch_arm,
)


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
                ea=0x6000 + serial,
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
        start_ea=0x6000 + serial,
        insn_snapshots=insns,
    )


# 12 sub_7FFD3338C040 records captured 2026-05-15 with the diagnostic
# classifier (matches_arm=True after engine-path admission lands).  Field
# order: pred, cond, target, outcome, arm, cond_succs, cond_preds, target_preds.
SUB_7FFD_ARM_KNOWN_RECORDS: tuple[
    tuple[int, int, int, FixPredecessorOutcome, int, int, int, int], ...
] = (
    (6, 13, 15, FixPredecessorOutcome.ALWAYS_TAKEN, 1, 2, 3, 1),
    (18, 19, 20, FixPredecessorOutcome.NEVER_TAKEN, 0, 2, 3, 1),
    (18, 22, 25, FixPredecessorOutcome.ALWAYS_TAKEN, 1, 2, 4, 1),
    (4, 36, 37, FixPredecessorOutcome.NEVER_TAKEN, 1, 2, 9, 1),
    (60, 61, 63, FixPredecessorOutcome.ALWAYS_TAKEN, 0, 2, 3, 1),
    (60, 65, 70, FixPredecessorOutcome.ALWAYS_TAKEN, 1, 2, 4, 1),
    (73, 74, 76, FixPredecessorOutcome.ALWAYS_TAKEN, 0, 2, 3, 1),
    (73, 77, 79, FixPredecessorOutcome.ALWAYS_TAKEN, 1, 2, 4, 1),
    (85, 86, 88, FixPredecessorOutcome.ALWAYS_TAKEN, 0, 2, 3, 1),
    (89, 91, 92, FixPredecessorOutcome.NEVER_TAKEN, 1, 2, 2, 1),
    (96, 97, 101, FixPredecessorOutcome.ALWAYS_TAKEN, 0, 2, 3, 1),
    (96, 105, 107, FixPredecessorOutcome.ALWAYS_TAKEN, 1, 2, 4, 1),
)


def _synth_cfg(
    *,
    pred: int,
    cond: int,
    target: int,
    outcome: FixPredecessorOutcome,
    arm: int,
    cond_preds: int,
    target_preds: int,
) -> FlowGraph:
    """Build a minimal CFG that exactly reproduces a sub_7FFD record's shape.

    The synthetic block serials use a fixed offset (7000+) for "other" arms
    so they never collide with the captured pred/cond/target serials.
    """
    fallthrough = 7000 + cond  # synthetic non-colliding fallthrough arm of cond
    pred_other = 8000 + pred   # synthetic non-colliding other arm of pred

    if arm == 1:
        # pred's explicit branch arm targets cond; fallthrough arm goes elsewhere.
        pred_succs = (pred_other, cond)
        pred_branch = cond
    else:
        # pred's fallthrough arm targets cond; explicit branch goes elsewhere.
        pred_succs = (cond, pred_other)
        pred_branch = pred_other

    # cond is 2-way.  The selected target is one arm; the other arm is the
    # synthetic ``fallthrough``.  When outcome=ALWAYS_TAKEN, the explicit
    # branch arm of cond must equal ``target``.  When outcome=NEVER_TAKEN,
    # the explicit branch arm must be the OTHER successor (so the
    # fallthrough is ``target``).
    if outcome == FixPredecessorOutcome.ALWAYS_TAKEN:
        cond_succs = (fallthrough, target)
        cond_branch_target = target
    else:
        cond_succs = (target, fallthrough)
        cond_branch_target = fallthrough

    cond_pred_set = (pred,) + tuple(
        range(2000, 2000 + max(cond_preds - 1, 0))
    )

    blocks: dict[int, BlockSnapshot] = {
        pred: _block(pred, pred_succs, (), branch_target=pred_branch),
        pred_other: _block(pred_other, (), (pred,)),
        cond: _block(cond, cond_succs, cond_pred_set, branch_target=cond_branch_target),
        target: _block(
            target,
            (),
            (cond,) + tuple(range(3000, 3000 + max(target_preds - 1, 0))),
        ),
        fallthrough: _block(fallthrough, (), (cond,)),
    }

    # Phantom multi-preds for cond (so the live rule has a reason to clone).
    for extra in range(2000, 2000 + max(cond_preds - 1, 0)):
        blocks[extra] = _block(extra, (cond,), ())
    # Phantom multi-preds for target.
    for extra in range(3000, 3000 + max(target_preds - 1, 0)):
        blocks[extra] = _block(extra, (target,), ())

    return FlowGraph(blocks=blocks, entry_serial=pred, func_ea=0x402000)


@pytest.mark.parametrize("record", SUB_7FFD_ARM_KNOWN_RECORDS)
def test_sub_7ffd_arm_known_records_admit_via_branch_arm_planner(
    record,
) -> None:
    pred, cond, target, outcome, arm, _cond_succs, cond_preds, target_preds = record
    cfg = _synth_cfg(
        pred=pred,
        cond=cond,
        target=target,
        outcome=outcome,
        arm=arm,
        cond_preds=cond_preds,
        target_preds=target_preds,
    )
    modification = PredecessorModification(
        mod_type=(
            PredecessorModificationType.ALWAYS_TAKEN
            if outcome == FixPredecessorOutcome.ALWAYS_TAKEN
            else PredecessorModificationType.NEVER_TAKEN
        ),
        pred_serial=pred,
        cond_block_serial=cond,
        target_serial=target,
        description=f"sub_7FFD record pred={pred} cond={cond} target={target}",
    )

    arm_decision = plan_predecessor_modification_clone_from_branch_arm(
        cfg, modification
    )
    one_way_decision = plan_predecessor_modification_clone_as_goto(cfg, modification)

    # Mutual exclusion: the one-way planner always refuses 2-way preds.
    assert not one_way_decision.accepted

    if arm == 1:
        # Explicit-branch-arm cases are the supported engine-path shape.
        assert arm_decision.accepted, (
            f"branch-arm planner unexpectedly rejected arm=1 sub_7FFD record "
            f"{record} with reason {arm_decision.rejection_reason}"
        )
        candidate = arm_decision.candidate
        assert candidate is not None
        assert candidate.pred_arm == 1
        assert candidate.pred_serial == pred
        assert candidate.conditional_serial == cond
        assert candidate.selected_target_serial == target
        primitive = candidate.to_graph_modification()
        assert primitive == CloneConditionalAsGotoFromBranchArm(
            source_block=cond,
            pred_serial=pred,
            pred_arm=1,
            goto_target=target,
            reason=f"sub_7FFD record pred={pred} cond={cond} target={target}",
        )
    else:
        # Fallthrough-arm cases stay in legacy fallback until a fallthrough
        # rewrite helper lands.  The planner reports the specific reason so
        # downstream consumers can distinguish "engine path declines" from
        # "shape is fundamentally unsupported".
        assert not arm_decision.accepted
        assert arm_decision.rejection_reason is (
            FixPredecessorRejectReason.PRED_FALLTHROUGH_ARM_NOT_SUPPORTED
        )
