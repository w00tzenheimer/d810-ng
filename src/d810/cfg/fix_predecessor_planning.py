"""CFG planning for FixPredecessor clone-as-goto rewrites.

This module intentionally stops at a backend-neutral candidate model.  The
legacy live rule applies the rewrite by cloning a conditional block, converting
the clone to a one-way goto, and redirecting one predecessor to that clone.
This helper admits that shape and emits the dedicated
``CloneConditionalAsGoto`` graph primitive.  Callers still have to opt into
the planned path explicitly; the legacy live rule remains the default.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.cfg.graph_modification import CloneConditionalAsGoto


class FixPredecessorOutcome(str, Enum):
    """Known outcome of the conditional block for one predecessor."""

    ALWAYS_TAKEN = "always_taken"
    NEVER_TAKEN = "never_taken"


class FixPredecessorRejectReason(str, Enum):
    """Pure-planner rejection reasons for clone-as-goto candidates."""

    MISSING_BLOCK = "missing_block"
    PRED_NOT_SIMPLE_ONEWAY = "pred_not_simple_oneway"
    PRED_DOES_NOT_TARGET_SOURCE = "pred_does_not_target_source"
    SOURCE_NOT_CONDITIONAL_2WAY = "source_not_conditional_2way"
    SOURCE_MISSING_CONDITIONAL_TARGET = "source_missing_conditional_target"
    CONDITIONAL_TARGET_NOT_SUCCESSOR = "conditional_target_not_successor"
    AMBIGUOUS_FALLTHROUGH = "ambiguous_fallthrough"
    TARGET_BLOCK_MISSING = "target_block_missing"
    TARGET_NOT_CONDITIONAL_ARM = "target_not_conditional_arm"
    OUTCOME_TARGET_MISMATCH = "outcome_target_mismatch"
    SELF_LOOP_TARGET = "self_loop_target"


@dataclass(frozen=True)
class FixPredecessorCloneAsGotoIntent:
    """Backend-neutral intent for the live FixPredecessor apply shape."""

    clone_source_serial: int
    clone_goto_target_serial: int
    redirect_pred_serial: int
    redirect_old_target_serial: int
    operation_sequence: tuple[str, ...] = (
        "clone_conditional_block",
        "clear_clone_predecessors",
        "convert_clone_to_goto",
        "redirect_predecessor_to_clone",
    )


@dataclass(frozen=True)
class FixPredecessorCloneAsGotoCandidate:
    """Admitted candidate for the FixPredecessor rewrite."""

    pred_serial: int
    conditional_serial: int
    selected_target_serial: int
    outcome: FixPredecessorOutcome
    conditional_target_serial: int
    fallthrough_target_serial: int
    source_successors: tuple[int, int]
    pred_successors: tuple[int, ...]
    description: str = ""
    lowering_status: str = "planned_modification_available"

    @property
    def intent(self) -> FixPredecessorCloneAsGotoIntent:
        """Return the backend-neutral operation sequence for this candidate."""
        return FixPredecessorCloneAsGotoIntent(
            clone_source_serial=self.conditional_serial,
            clone_goto_target_serial=self.selected_target_serial,
            redirect_pred_serial=self.pred_serial,
            redirect_old_target_serial=self.conditional_serial,
        )

    def to_graph_modification(self) -> CloneConditionalAsGoto:
        """Return the executable backend-neutral graph primitive."""
        return CloneConditionalAsGoto(
            source_block=self.conditional_serial,
            pred_serial=self.pred_serial,
            goto_target=self.selected_target_serial,
            reason=self.description or "fix_predecessor_clone_as_goto",
        )


@dataclass(frozen=True)
class FixPredecessorCloneAsGotoDecision:
    """Decision wrapper for candidate admission."""

    accepted: bool
    candidate: FixPredecessorCloneAsGotoCandidate | None = None
    rejection_reason: FixPredecessorRejectReason | None = None
    detail: str = ""

    @classmethod
    def accept(
        cls,
        candidate: FixPredecessorCloneAsGotoCandidate,
    ) -> "FixPredecessorCloneAsGotoDecision":
        return cls(accepted=True, candidate=candidate)

    @classmethod
    def reject(
        cls,
        reason: FixPredecessorRejectReason,
        detail: str = "",
    ) -> "FixPredecessorCloneAsGotoDecision":
        return cls(accepted=False, rejection_reason=reason, detail=detail)


def _operand_block_ref(operand: object) -> int | None:
    for attr in ("block_num", "block_ref"):
        value = getattr(operand, attr, None)
        if isinstance(value, int):
            return value
    return None


def infer_conditional_target(block: BlockSnapshot) -> int | None:
    """Infer the explicit conditional arm target from a 2-way block snapshot."""
    if block.nsucc != 2 or block.tail is None:
        return None

    for slot_name, operand in block.tail.operand_slots:
        if slot_name != "d":
            continue
        block_ref = _operand_block_ref(operand)
        if block_ref is not None:
            return block_ref

    for operand in block.tail.operands:
        block_ref = _operand_block_ref(operand)
        if block_ref is not None:
            return block_ref

    for operand in (block.tail.d,):
        if operand is None:
            continue
        block_ref = _operand_block_ref(operand)
        if block_ref is not None:
            return block_ref

    return None


def infer_fallthrough_target(
    block: BlockSnapshot,
    *,
    conditional_target: int,
) -> int | None:
    """Return the non-conditional successor when it is unique."""
    fallthrough_targets = tuple(
        succ for succ in block.succs if succ != conditional_target
    )
    if len(fallthrough_targets) != 1:
        return None
    return fallthrough_targets[0]


def plan_fix_predecessor_clone_as_goto(
    cfg: FlowGraph,
    *,
    pred_serial: int,
    conditional_serial: int,
    selected_target_serial: int,
    outcome: FixPredecessorOutcome,
    description: str = "",
) -> FixPredecessorCloneAsGotoDecision:
    """Admit the simple FixPredecessor clone-as-goto candidate shape.

    The admitted shape mirrors the live rule's safe, narrow topology:

    * one-way predecessor currently targets the conditional block
    * source block is a two-way conditional with an explicit branch target
    * selected target is exactly the taken or fallthrough arm implied by
      ``outcome``

    The result is executable through the dedicated graph primitive, but callers
    must still opt into that path explicitly.
    """
    pred_block = cfg.get_block(pred_serial)
    conditional_block = cfg.get_block(conditional_serial)
    if pred_block is None or conditional_block is None:
        return FixPredecessorCloneAsGotoDecision.reject(
            FixPredecessorRejectReason.MISSING_BLOCK,
            "predecessor or conditional block is absent",
        )

    if pred_block.nsucc != 1:
        return FixPredecessorCloneAsGotoDecision.reject(
            FixPredecessorRejectReason.PRED_NOT_SIMPLE_ONEWAY,
            f"pred blk[{pred_serial}] has {pred_block.nsucc} successors",
        )
    if pred_block.succs != (conditional_serial,):
        return FixPredecessorCloneAsGotoDecision.reject(
            FixPredecessorRejectReason.PRED_DOES_NOT_TARGET_SOURCE,
            f"pred blk[{pred_serial}] successors are {pred_block.succs}",
        )

    if conditional_block.nsucc != 2:
        return FixPredecessorCloneAsGotoDecision.reject(
            FixPredecessorRejectReason.SOURCE_NOT_CONDITIONAL_2WAY,
            f"source blk[{conditional_serial}] has {conditional_block.nsucc} successors",
        )

    conditional_target = infer_conditional_target(conditional_block)
    if conditional_target is None:
        return FixPredecessorCloneAsGotoDecision.reject(
            FixPredecessorRejectReason.SOURCE_MISSING_CONDITIONAL_TARGET,
            f"source blk[{conditional_serial}] has no explicit branch target",
        )
    if conditional_target not in conditional_block.succs:
        return FixPredecessorCloneAsGotoDecision.reject(
            FixPredecessorRejectReason.CONDITIONAL_TARGET_NOT_SUCCESSOR,
            f"branch target {conditional_target} is not in {conditional_block.succs}",
        )

    fallthrough_target = infer_fallthrough_target(
        conditional_block,
        conditional_target=conditional_target,
    )
    if fallthrough_target is None:
        return FixPredecessorCloneAsGotoDecision.reject(
            FixPredecessorRejectReason.AMBIGUOUS_FALLTHROUGH,
            f"source blk[{conditional_serial}] successors are {conditional_block.succs}",
        )

    if selected_target_serial not in cfg.blocks:
        return FixPredecessorCloneAsGotoDecision.reject(
            FixPredecessorRejectReason.TARGET_BLOCK_MISSING,
            f"selected target blk[{selected_target_serial}] is absent",
        )
    if selected_target_serial == conditional_serial:
        return FixPredecessorCloneAsGotoDecision.reject(
            FixPredecessorRejectReason.SELF_LOOP_TARGET,
            "clone-as-goto target would point back to the cloned source",
        )
    if selected_target_serial not in {conditional_target, fallthrough_target}:
        return FixPredecessorCloneAsGotoDecision.reject(
            FixPredecessorRejectReason.TARGET_NOT_CONDITIONAL_ARM,
            (
                f"selected target {selected_target_serial} is not one of "
                f"{conditional_target}, {fallthrough_target}"
            ),
        )

    expected_target = (
        conditional_target
        if outcome == FixPredecessorOutcome.ALWAYS_TAKEN
        else fallthrough_target
    )
    if selected_target_serial != expected_target:
        return FixPredecessorCloneAsGotoDecision.reject(
            FixPredecessorRejectReason.OUTCOME_TARGET_MISMATCH,
            (
                f"{outcome.value} expects target {expected_target}, "
                f"got {selected_target_serial}"
            ),
        )

    return FixPredecessorCloneAsGotoDecision.accept(
        FixPredecessorCloneAsGotoCandidate(
            pred_serial=pred_serial,
            conditional_serial=conditional_serial,
            selected_target_serial=selected_target_serial,
            outcome=outcome,
            conditional_target_serial=conditional_target,
            fallthrough_target_serial=fallthrough_target,
            source_successors=(
                int(conditional_block.succs[0]),
                int(conditional_block.succs[1]),
            ),
            pred_successors=tuple(int(succ) for succ in pred_block.succs),
            description=description,
        )
    )


__all__ = [
    "FixPredecessorCloneAsGotoCandidate",
    "FixPredecessorCloneAsGotoDecision",
    "FixPredecessorCloneAsGotoIntent",
    "FixPredecessorOutcome",
    "FixPredecessorRejectReason",
    "infer_conditional_target",
    "infer_fallthrough_target",
    "plan_fix_predecessor_clone_as_goto",
]
