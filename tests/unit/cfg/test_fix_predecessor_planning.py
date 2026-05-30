from __future__ import annotations

import pytest

from d810.transforms.fix_predecessor_planning import (
    FixPredecessorOutcome,
    FixPredecessorRejectReason,
    plan_fix_predecessor_clone_as_goto,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot, MopSnapshot
from d810.transforms.graph_modification import CloneConditionalAsGoto


class _BlockRef:
    def __init__(self, block_num: int):
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
                ea=0x1000 + serial,
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
        start_ea=0x1000 + serial,
        insn_snapshots=insns,
    )


def _cfg(
    *,
    pred_succs: tuple[int, ...] = (10,),
    cond_succs: tuple[int, ...] = (11, 12),
    branch_target: int | None = 12,
) -> FlowGraph:
    blocks = {
        8: _block(8, pred_succs, ()),
        10: _block(10, cond_succs, (8,), branch_target=branch_target),
        11: _block(11, (), (10,)),
        12: _block(12, (), (10,)),
        13: _block(13, (), ()),
    }
    return FlowGraph(blocks=blocks, entry_serial=8, func_ea=0x401000)


def test_admits_simple_predecessor_clone_as_goto_candidate() -> None:
    decision = plan_fix_predecessor_clone_as_goto(
        _cfg(),
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
        description="pred 8 always takes jump in block 10",
    )

    assert decision.accepted
    assert decision.candidate is not None
    candidate = decision.candidate
    assert candidate.lowering_status == "planned_modification_available"
    assert candidate.pred_serial == 8
    assert candidate.conditional_serial == 10
    assert candidate.selected_target_serial == 12
    assert candidate.conditional_target_serial == 12
    assert candidate.fallthrough_target_serial == 11
    assert candidate.source_successors == (11, 12)
    assert candidate.intent.clone_source_serial == 10
    assert candidate.intent.clone_goto_target_serial == 12
    assert candidate.intent.redirect_pred_serial == 8
    assert candidate.intent.redirect_old_target_serial == 10
    assert candidate.intent.operation_sequence == (
        "clone_conditional_block",
        "clear_clone_predecessors",
        "convert_clone_to_goto",
        "redirect_predecessor_to_clone",
    )
    assert candidate.to_graph_modification() == CloneConditionalAsGoto(
        source_block=10,
        pred_serial=8,
        goto_target=12,
        reason="pred 8 always takes jump in block 10",
    )


def test_admits_never_taken_fallthrough_candidate_with_mop_snapshot_ref() -> None:
    cfg = FlowGraph(
        blocks={
            8: _block(8, (10,), ()),
            10: BlockSnapshot(
                serial=10,
                block_type=2,
                succs=(11, 12),
                preds=(8,),
                flags=0,
                start_ea=0x1010,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0x70,
                        ea=0x1010,
                        operands=(),
                        operand_slots=(),
                        d=MopSnapshot(t=5, block_ref=12),
                    ),
                ),
            ),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
        },
        entry_serial=8,
        func_ea=0x401000,
    )

    decision = plan_fix_predecessor_clone_as_goto(
        cfg,
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=11,
        outcome=FixPredecessorOutcome.NEVER_TAKEN,
    )

    assert decision.accepted
    assert decision.candidate is not None
    assert decision.candidate.selected_target_serial == 11
    assert decision.candidate.fallthrough_target_serial == 11


@pytest.mark.parametrize(
    ("cfg", "expected_reason"),
    (
        (
            _cfg(cond_succs=(11,), branch_target=None),
            FixPredecessorRejectReason.SOURCE_NOT_CONDITIONAL_2WAY,
        ),
        (
            _cfg(branch_target=None),
            FixPredecessorRejectReason.SOURCE_MISSING_CONDITIONAL_TARGET,
        ),
        (
            _cfg(pred_succs=(9, 10)),
            FixPredecessorRejectReason.PRED_NOT_SIMPLE_ONEWAY,
        ),
        (
            _cfg(pred_succs=(13,)),
            FixPredecessorRejectReason.PRED_DOES_NOT_TARGET_SOURCE,
        ),
    ),
)
def test_rejects_non_matching_source_shapes(
    cfg: FlowGraph,
    expected_reason: FixPredecessorRejectReason,
) -> None:
    decision = plan_fix_predecessor_clone_as_goto(
        cfg,
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=12,
        outcome=FixPredecessorOutcome.ALWAYS_TAKEN,
    )

    assert not decision.accepted
    assert decision.rejection_reason == expected_reason


@pytest.mark.parametrize(
    ("cfg", "selected_target", "outcome", "expected_reason"),
    (
        (
            _cfg(branch_target=13),
            13,
            FixPredecessorOutcome.ALWAYS_TAKEN,
            FixPredecessorRejectReason.CONDITIONAL_TARGET_NOT_SUCCESSOR,
        ),
        (
            _cfg(cond_succs=(12, 12), branch_target=12),
            12,
            FixPredecessorOutcome.ALWAYS_TAKEN,
            FixPredecessorRejectReason.AMBIGUOUS_FALLTHROUGH,
        ),
        (
            _cfg(),
            13,
            FixPredecessorOutcome.ALWAYS_TAKEN,
            FixPredecessorRejectReason.TARGET_NOT_CONDITIONAL_ARM,
        ),
        (
            _cfg(),
            11,
            FixPredecessorOutcome.ALWAYS_TAKEN,
            FixPredecessorRejectReason.OUTCOME_TARGET_MISMATCH,
        ),
        (
            _cfg(cond_succs=(10, 12), branch_target=10),
            10,
            FixPredecessorOutcome.ALWAYS_TAKEN,
            FixPredecessorRejectReason.SELF_LOOP_TARGET,
        ),
    ),
)
def test_rejects_ambiguous_or_unsafe_clone_targets(
    cfg: FlowGraph,
    selected_target: int,
    outcome: FixPredecessorOutcome,
    expected_reason: FixPredecessorRejectReason,
) -> None:
    decision = plan_fix_predecessor_clone_as_goto(
        cfg,
        pred_serial=8,
        conditional_serial=10,
        selected_target_serial=selected_target,
        outcome=outcome,
    )

    assert not decision.accepted
    assert decision.rejection_reason == expected_reason
