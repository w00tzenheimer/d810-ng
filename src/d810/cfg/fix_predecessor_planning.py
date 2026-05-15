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
from d810.cfg.graph_modification import (
    CloneConditionalAsGoto,
    CloneConditionalAsGotoFromBranchArm,
)


class FixPredecessorOutcome(str, Enum):
    """Known outcome of the conditional block for one predecessor."""

    ALWAYS_TAKEN = "always_taken"
    NEVER_TAKEN = "never_taken"


class FixPredecessorRejectReason(str, Enum):
    """Pure-planner rejection reasons for clone-as-goto candidates."""

    MISSING_BLOCK = "missing_block"
    PRED_NOT_SIMPLE_ONEWAY = "pred_not_simple_oneway"
    PRED_NOT_TWO_WAY = "pred_not_two_way"
    PRED_DOES_NOT_TARGET_SOURCE = "pred_does_not_target_source"
    PRED_ARM_AMBIGUOUS = "pred_arm_ambiguous"
    SOURCE_NOT_CONDITIONAL_2WAY = "source_not_conditional_2way"
    SOURCE_MISSING_CONDITIONAL_TARGET = "source_missing_conditional_target"
    CONDITIONAL_TARGET_NOT_SUCCESSOR = "conditional_target_not_successor"
    AMBIGUOUS_FALLTHROUGH = "ambiguous_fallthrough"
    TARGET_BLOCK_MISSING = "target_block_missing"
    TARGET_NOT_CONDITIONAL_ARM = "target_not_conditional_arm"
    OUTCOME_TARGET_MISMATCH = "outcome_target_mismatch"
    SELF_LOOP_TARGET = "self_loop_target"
    TARGET_NOT_SINGLE_PRED = "target_not_single_pred"
    CONDITIONAL_HAS_SIDE_EFFECTS = "conditional_has_side_effects"


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


@dataclass(frozen=True)
class FixPredecessorCloneAsGotoFromBranchArmIntent:
    """Backend-neutral intent for the 2-way predecessor branch-arm shape."""

    clone_source_serial: int
    clone_goto_target_serial: int
    redirect_pred_serial: int
    redirect_pred_arm: int
    redirect_old_target_serial: int
    operation_sequence: tuple[str, ...] = (
        "clone_conditional_block",
        "clear_clone_predecessors",
        "convert_clone_to_goto",
        "redirect_predecessor_branch_arm_to_clone",
    )


@dataclass(frozen=True)
class FixPredecessorCloneAsGotoFromBranchArmCandidate:
    """Admitted candidate for the 2-way predecessor branch-arm rewrite.

    All members are int and bound to the snapshot CFG.  The candidate is
    only emitted for the conservative shape the legacy live rule already
    redirects via ``change_2way_block_conditional_successor``.
    """

    pred_serial: int
    pred_arm: int
    conditional_serial: int
    selected_target_serial: int
    outcome: FixPredecessorOutcome
    conditional_target_serial: int
    fallthrough_target_serial: int
    source_successors: tuple[int, int]
    pred_successors: tuple[int, int]
    pred_branch_target_serial: int
    pred_fallthrough_target_serial: int
    description: str = ""
    lowering_status: str = "planned_modification_available"

    @property
    def intent(self) -> FixPredecessorCloneAsGotoFromBranchArmIntent:
        """Return the backend-neutral operation sequence for this candidate."""
        return FixPredecessorCloneAsGotoFromBranchArmIntent(
            clone_source_serial=self.conditional_serial,
            clone_goto_target_serial=self.selected_target_serial,
            redirect_pred_serial=self.pred_serial,
            redirect_pred_arm=self.pred_arm,
            redirect_old_target_serial=self.conditional_serial,
        )

    def to_graph_modification(self) -> CloneConditionalAsGotoFromBranchArm:
        """Return the executable backend-neutral graph primitive."""
        return CloneConditionalAsGotoFromBranchArm(
            source_block=self.conditional_serial,
            pred_serial=self.pred_serial,
            pred_arm=self.pred_arm,
            goto_target=self.selected_target_serial,
            reason=self.description or "fix_predecessor_clone_as_goto_from_branch_arm",
        )


@dataclass(frozen=True)
class FixPredecessorCloneAsGotoFromBranchArmDecision:
    """Decision wrapper for branch-arm candidate admission."""

    accepted: bool
    candidate: FixPredecessorCloneAsGotoFromBranchArmCandidate | None = None
    rejection_reason: FixPredecessorRejectReason | None = None
    detail: str = ""

    @classmethod
    def accept(
        cls,
        candidate: FixPredecessorCloneAsGotoFromBranchArmCandidate,
    ) -> "FixPredecessorCloneAsGotoFromBranchArmDecision":
        return cls(accepted=True, candidate=candidate)

    @classmethod
    def reject(
        cls,
        reason: FixPredecessorRejectReason,
        detail: str = "",
    ) -> "FixPredecessorCloneAsGotoFromBranchArmDecision":
        return cls(accepted=False, rejection_reason=reason, detail=detail)


def _resolve_pred_arm_for_target(
    pred_block: BlockSnapshot,
    target_serial: int,
) -> int | None:
    """Return ``0`` or ``1`` for the predecessor arm reaching ``target_serial``.

    Mirrors :func:`d810.cfg.fix_predecessor_classification._resolve_predecessor_arm`
    semantics: ``1`` for the explicit branch arm (operand ``d``), ``0`` for
    the fallthrough arm.  Returns ``None`` when the topology cannot resolve
    a unique arm.
    """
    if pred_block.nsucc != 2:
        return None
    if target_serial not in pred_block.succs:
        return None
    explicit_arm = infer_conditional_target(pred_block)
    if explicit_arm is None:
        return None
    fallthrough = infer_fallthrough_target(
        pred_block, conditional_target=explicit_arm
    )
    if fallthrough is None:
        return None
    if target_serial == explicit_arm:
        return 1
    if target_serial == fallthrough:
        return 0
    return None


def plan_fix_predecessor_clone_from_branch_arm(
    cfg: FlowGraph,
    *,
    pred_serial: int,
    conditional_serial: int,
    selected_target_serial: int,
    outcome: FixPredecessorOutcome,
    side_effect_blocks: frozenset[int] = frozenset(),
    description: str = "",
) -> FixPredecessorCloneAsGotoFromBranchArmDecision:
    """Admit the narrow 2-way predecessor branch-arm clone-as-goto shape.

    The admitted shape is strictly stricter than the legacy live rule's
    handling — the corpus-evidence-driven design only covers cases the
    cleanup-family engine path is safe to migrate today:

    * predecessor is a 2-way conditional with cond in exactly one of its arms
    * predecessor arm is uniquely identifiable from the tail
    * conditional source is a 2-way block with an explicit branch arm
    * selected target matches the arm implied by ``outcome``
    * selected target has at most one predecessor in the snapshot
    * conditional source has no non-tail side effects

    Every other shape is rejected with a specific
    :class:`FixPredecessorRejectReason`.
    """
    pred_block = cfg.get_block(pred_serial)
    conditional_block = cfg.get_block(conditional_serial)
    if pred_block is None or conditional_block is None:
        return FixPredecessorCloneAsGotoFromBranchArmDecision.reject(
            FixPredecessorRejectReason.MISSING_BLOCK,
            "predecessor or conditional block is absent",
        )

    if pred_block.nsucc != 2:
        return FixPredecessorCloneAsGotoFromBranchArmDecision.reject(
            FixPredecessorRejectReason.PRED_NOT_TWO_WAY,
            f"pred blk[{pred_serial}] has {pred_block.nsucc} successors",
        )
    if conditional_serial not in pred_block.succs:
        return FixPredecessorCloneAsGotoFromBranchArmDecision.reject(
            FixPredecessorRejectReason.PRED_DOES_NOT_TARGET_SOURCE,
            f"pred blk[{pred_serial}] successors are {pred_block.succs}",
        )
    pred_branch_target = infer_conditional_target(pred_block)
    if pred_branch_target is None:
        return FixPredecessorCloneAsGotoFromBranchArmDecision.reject(
            FixPredecessorRejectReason.PRED_ARM_AMBIGUOUS,
            f"pred blk[{pred_serial}] has no explicit branch arm",
        )
    pred_fallthrough = infer_fallthrough_target(
        pred_block, conditional_target=pred_branch_target
    )
    if pred_fallthrough is None:
        return FixPredecessorCloneAsGotoFromBranchArmDecision.reject(
            FixPredecessorRejectReason.PRED_ARM_AMBIGUOUS,
            f"pred blk[{pred_serial}] arms collapse to a single target",
        )
    pred_arm = _resolve_pred_arm_for_target(pred_block, conditional_serial)
    if pred_arm is None:
        return FixPredecessorCloneAsGotoFromBranchArmDecision.reject(
            FixPredecessorRejectReason.PRED_ARM_AMBIGUOUS,
            f"pred blk[{pred_serial}] arm reaching cond is not resolvable",
        )

    if conditional_block.nsucc != 2:
        return FixPredecessorCloneAsGotoFromBranchArmDecision.reject(
            FixPredecessorRejectReason.SOURCE_NOT_CONDITIONAL_2WAY,
            f"source blk[{conditional_serial}] has {conditional_block.nsucc} successors",
        )

    conditional_target = infer_conditional_target(conditional_block)
    if conditional_target is None:
        return FixPredecessorCloneAsGotoFromBranchArmDecision.reject(
            FixPredecessorRejectReason.SOURCE_MISSING_CONDITIONAL_TARGET,
            f"source blk[{conditional_serial}] has no explicit branch target",
        )
    if conditional_target not in conditional_block.succs:
        return FixPredecessorCloneAsGotoFromBranchArmDecision.reject(
            FixPredecessorRejectReason.CONDITIONAL_TARGET_NOT_SUCCESSOR,
            f"branch target {conditional_target} is not in {conditional_block.succs}",
        )
    fallthrough_target = infer_fallthrough_target(
        conditional_block,
        conditional_target=conditional_target,
    )
    if fallthrough_target is None:
        return FixPredecessorCloneAsGotoFromBranchArmDecision.reject(
            FixPredecessorRejectReason.AMBIGUOUS_FALLTHROUGH,
            f"source blk[{conditional_serial}] successors are {conditional_block.succs}",
        )

    target_block = cfg.get_block(selected_target_serial)
    if target_block is None:
        return FixPredecessorCloneAsGotoFromBranchArmDecision.reject(
            FixPredecessorRejectReason.TARGET_BLOCK_MISSING,
            f"selected target blk[{selected_target_serial}] is absent",
        )
    if selected_target_serial == conditional_serial:
        return FixPredecessorCloneAsGotoFromBranchArmDecision.reject(
            FixPredecessorRejectReason.SELF_LOOP_TARGET,
            "clone-as-goto target would point back to the cloned source",
        )
    if selected_target_serial not in {conditional_target, fallthrough_target}:
        return FixPredecessorCloneAsGotoFromBranchArmDecision.reject(
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
        return FixPredecessorCloneAsGotoFromBranchArmDecision.reject(
            FixPredecessorRejectReason.OUTCOME_TARGET_MISMATCH,
            (
                f"{outcome.value} expects target {expected_target}, "
                f"got {selected_target_serial}"
            ),
        )

    if target_block.npred > 1:
        return FixPredecessorCloneAsGotoFromBranchArmDecision.reject(
            FixPredecessorRejectReason.TARGET_NOT_SINGLE_PRED,
            (
                f"selected target blk[{selected_target_serial}] has "
                f"{target_block.npred} predecessors"
            ),
        )
    if conditional_serial in side_effect_blocks:
        return FixPredecessorCloneAsGotoFromBranchArmDecision.reject(
            FixPredecessorRejectReason.CONDITIONAL_HAS_SIDE_EFFECTS,
            f"source blk[{conditional_serial}] has body side effects",
        )

    return FixPredecessorCloneAsGotoFromBranchArmDecision.accept(
        FixPredecessorCloneAsGotoFromBranchArmCandidate(
            pred_serial=pred_serial,
            pred_arm=pred_arm,
            conditional_serial=conditional_serial,
            selected_target_serial=selected_target_serial,
            outcome=outcome,
            conditional_target_serial=conditional_target,
            fallthrough_target_serial=fallthrough_target,
            source_successors=(
                int(conditional_block.succs[0]),
                int(conditional_block.succs[1]),
            ),
            pred_successors=(
                int(pred_block.succs[0]),
                int(pred_block.succs[1]),
            ),
            pred_branch_target_serial=int(pred_branch_target),
            pred_fallthrough_target_serial=int(pred_fallthrough),
            description=description,
        )
    )


__all__ = [
    "FixPredecessorCloneAsGotoCandidate",
    "FixPredecessorCloneAsGotoDecision",
    "FixPredecessorCloneAsGotoFromBranchArmCandidate",
    "FixPredecessorCloneAsGotoFromBranchArmDecision",
    "FixPredecessorCloneAsGotoFromBranchArmIntent",
    "FixPredecessorCloneAsGotoIntent",
    "FixPredecessorOutcome",
    "FixPredecessorRejectReason",
    "infer_conditional_target",
    "infer_fallthrough_target",
    "plan_fix_predecessor_clone_as_goto",
    "plan_fix_predecessor_clone_from_branch_arm",
]
