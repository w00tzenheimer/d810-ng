"""Diagnostics adapter tests for FixPredecessor candidate planning."""
from __future__ import annotations

from d810.cfg.fix_predecessor_planning import FixPredecessorOutcome
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.cfg.graph_modification import CloneConditionalAsGoto
from d810.optimizers.microcode.flow.flattening.fix_pred_cond_jump_block import (
    PredecessorModification,
    PredecessorModificationType,
    plan_predecessor_modification_clone_as_goto,
)


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
                ea=0x2000 + serial,
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
        start_ea=0x2000 + serial,
        insn_snapshots=insns,
    )


def _cfg() -> FlowGraph:
    return FlowGraph(
        blocks={
            8: _block(8, (10,), ()),
            10: _block(10, (11, 12), (8,), branch_target=12),
            11: _block(11, (), (10,)),
            12: _block(12, (), (10,)),
        },
        entry_serial=8,
        func_ea=0x402000,
    )


def test_live_predecessor_modification_projects_to_clone_as_goto_candidate() -> None:
    modification = PredecessorModification(
        mod_type=PredecessorModificationType.ALWAYS_TAKEN,
        pred_serial=8,
        cond_block_serial=10,
        target_serial=12,
        description="pred 8 always takes jump in block 10",
    )

    decision = plan_predecessor_modification_clone_as_goto(_cfg(), modification)

    assert decision.accepted
    assert decision.candidate is not None
    assert decision.candidate.outcome == FixPredecessorOutcome.ALWAYS_TAKEN
    assert decision.candidate.lowering_status == "planned_modification_available"
    assert decision.candidate.to_graph_modification() == CloneConditionalAsGoto(
        source_block=10,
        pred_serial=8,
        goto_target=12,
        reason="pred 8 always takes jump in block 10",
    )
    assert decision.candidate.intent.operation_sequence == (
        "clone_conditional_block",
        "clear_clone_predecessors",
        "convert_clone_to_goto",
        "redirect_predecessor_to_clone",
    )
