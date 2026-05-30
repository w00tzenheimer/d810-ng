"""Pure CFG planning for dispatcher-predecessor rewrites."""
from __future__ import annotations

from dataclasses import dataclass

from d810.transforms.graph_modification import (
    ConvertToGoto,
    CreateConditionalRedirect,
    GraphModification,
    InsertBlock,
    RedirectGoto,
)


@dataclass(frozen=True, slots=True)
class DispatcherPredecessorRewriteInput:
    """Backend-neutral evidence for one dispatcher predecessor rewrite."""

    source_serial: int
    source_nsucc: int
    source_old_target: int | None
    source_is_conditional: bool
    target_serial: int
    target_nsucc: int
    target_is_conditional: bool
    target_conditional_target: int | None = None
    target_fallthrough_target: int | None = None
    safe_copy_instructions: tuple[object, ...] = ()
    deferred_side_effect_instructions: tuple[object, ...] = ()
    raw_side_effect_count: int = 0
    safe_side_effect_count: int = 0
    defer_side_effects: bool = False
    clone_conditional_targets: bool = False


@dataclass(frozen=True, slots=True)
class DispatcherPredecessorRewriteDecision:
    """CFG-owned rewrite intent for one dispatcher predecessor."""

    modifications: tuple[GraphModification, ...] = ()
    blocker: str | None = None
    defer_side_effects: bool = False


def plan_dispatcher_predecessor_rewrite(
    evidence: DispatcherPredecessorRewriteInput,
) -> DispatcherPredecessorRewriteDecision:
    """Return the graph edit represented by dispatcher predecessor evidence."""

    if evidence.raw_side_effect_count and not evidence.safe_side_effect_count:
        return _blocked("dispatcher_side_effects_not_dependency_safe")

    if evidence.safe_copy_instructions:
        if evidence.defer_side_effects:
            return DispatcherPredecessorRewriteDecision(
                blocker="dispatcher_side_effects_deferred_to_later_maturity",
                defer_side_effects=True,
            )
        return _plan_insert_block(evidence, evidence.safe_copy_instructions)

    if evidence.deferred_side_effect_instructions:
        return _plan_insert_block(evidence, evidence.deferred_side_effect_instructions)

    if evidence.clone_conditional_targets and evidence.target_is_conditional:
        conditional = _plan_conditional_target_clone(evidence)
        if conditional is not None:
            return conditional

    if evidence.source_nsucc == 1:
        if evidence.source_old_target is None:
            return _blocked("dispatcher_source_missing_old_target")
        return DispatcherPredecessorRewriteDecision(
            modifications=(
                RedirectGoto(
                    from_serial=int(evidence.source_serial),
                    old_target=int(evidence.source_old_target),
                    new_target=int(evidence.target_serial),
                ),
            )
        )

    if evidence.source_nsucc == 2 and evidence.source_is_conditional:
        return DispatcherPredecessorRewriteDecision(
            modifications=(
                ConvertToGoto(
                    block_serial=int(evidence.source_serial),
                    goto_target=int(evidence.target_serial),
                ),
            )
        )

    return _blocked("dispatcher_source_shape_not_lowered")


def _plan_insert_block(
    evidence: DispatcherPredecessorRewriteInput,
    instructions: tuple[object, ...],
) -> DispatcherPredecessorRewriteDecision:
    if evidence.source_nsucc != 1:
        return _blocked("dispatcher_insert_requires_one_way_source")
    if evidence.source_old_target is None:
        return _blocked("dispatcher_source_missing_old_target")
    return DispatcherPredecessorRewriteDecision(
        modifications=(
            InsertBlock(
                pred_serial=int(evidence.source_serial),
                succ_serial=int(evidence.target_serial),
                instructions=tuple(instructions),
                old_target_serial=int(evidence.source_old_target),
            ),
        )
    )


def _plan_conditional_target_clone(
    evidence: DispatcherPredecessorRewriteInput,
) -> DispatcherPredecessorRewriteDecision | None:
    if evidence.source_nsucc != 1:
        return _blocked("dispatcher_conditional_target_requires_one_way_source")
    if evidence.target_fallthrough_target is None:
        return _blocked("dispatcher_target_missing_fallthrough")
    if evidence.target_conditional_target is None:
        return _blocked("dispatcher_target_missing_conditional_target")
    if int(evidence.target_conditional_target) == int(evidence.source_serial):
        return _blocked("dispatcher_conditional_target_self_loop")
    if int(evidence.target_fallthrough_target) == int(evidence.source_serial):
        return _blocked("dispatcher_fallthrough_target_self_loop")
    return DispatcherPredecessorRewriteDecision(
        modifications=(
            CreateConditionalRedirect(
                source_block=int(evidence.source_serial),
                ref_block=int(evidence.target_serial),
                conditional_target=int(evidence.target_conditional_target),
                fallthrough_target=int(evidence.target_fallthrough_target),
            ),
        )
    )


def _blocked(reason: str) -> DispatcherPredecessorRewriteDecision:
    return DispatcherPredecessorRewriteDecision(blocker=reason)


__all__ = [
    "DispatcherPredecessorRewriteDecision",
    "DispatcherPredecessorRewriteInput",
    "plan_dispatcher_predecessor_rewrite",
]
