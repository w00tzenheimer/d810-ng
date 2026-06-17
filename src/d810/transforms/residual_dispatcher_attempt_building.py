from __future__ import annotations

from dataclasses import dataclass

from d810.transforms.lowering_selector import (
    PredecessorPeelContext,
    ResidualBranchAnchorContext,
    ResidualGotoHandoffContext,
    ResidualPredSplitContext,
    ResidualPrefixPeelContext,
)
from d810.transforms.residual_handoff_planning import (
    ResidualGotoAttempt,
    ResidualPrefixAttempt,
    ResidualPredSplitAttempt,
)


@dataclass(frozen=True, slots=True)
class ResidualPrefixAttemptBuildContext:
    via_pred: int
    prefix_target: int
    claimed_branch_target: int | None = None
    owned_transition: tuple[int, int] | None = None
    edge_kind_name: str = ""
    is_conditional_branch_source: bool = False
    branch_source: int | None = None
    source_block: int | None = None
    branch_succs: tuple[int, ...] = ()
    old_target: int | None = None
    ordered_path: tuple[int, ...] = ()
    dispatcher_serial: int | None = None
    condition_chain_blocks: frozenset[int] = frozenset()
    target_reaches_branch: bool = False
    via_pred_succs: tuple[int, ...] = ()
    target_reaches_pred: bool = False
    already_emitted: bool = False
    existing_target: int | None = None
    via_pred_succ_count: int | None = None


@dataclass(frozen=True, slots=True)
class ResidualPredSplitAttemptBuildContext:
    via_pred: int
    target_entry: int
    state_value: int
    source_block: int
    dispatcher_serial: int
    condition_chain_blocks: frozenset[int]
    valid_pair: bool
    target_reaches_via_pred: bool
    already_emitted: bool


@dataclass(frozen=True, slots=True)
class ResidualGotoAttemptBuildContext:
    target_entry: int
    state_value: int
    source_block: int
    dispatcher_serial: int
    condition_chain_blocks: frozenset[int]
    allow_family_fallback_tail: bool
    is_shared_suffix_conditional_tail: bool
    has_prior_branch_cut: bool
    target_reaches_source: bool
    already_emitted: bool
    live_oneway_noop: bool


def build_residual_prefix_attempt(
    context: ResidualPrefixAttemptBuildContext,
) -> ResidualPrefixAttempt:
    branch_context = None
    if (
        context.branch_source is not None
        and context.source_block is not None
        and context.old_target is not None
        and context.dispatcher_serial is not None
    ):
        branch_context = ResidualBranchAnchorContext(
            is_conditional_branch_source=bool(context.is_conditional_branch_source),
            branch_source=int(context.branch_source),
            source_block=int(context.source_block),
            via_pred=int(context.via_pred),
            prefix_target=int(context.prefix_target),
            branch_succs=tuple(int(succ) for succ in context.branch_succs),
            old_target=int(context.old_target),
            ordered_path=tuple(int(node) for node in context.ordered_path),
            dispatcher_serial=int(context.dispatcher_serial),
            condition_chain_blocks=frozenset(int(block) for block in context.condition_chain_blocks),
            target_reaches_branch=bool(context.target_reaches_branch),
        )

    peel_context = None
    if context.dispatcher_serial is not None and context.via_pred_succ_count is not None:
        peel_context = ResidualPrefixPeelContext(
            peel_context=PredecessorPeelContext(
                via_pred=int(context.via_pred),
                via_pred_succs=tuple(int(succ) for succ in context.via_pred_succs),
                source_block=int(context.source_block) if context.source_block is not None else 0,
                target_entry=int(context.prefix_target),
                dispatcher_serial=int(context.dispatcher_serial),
                condition_chain_blocks=frozenset(int(block) for block in context.condition_chain_blocks),
                target_reaches_pred=bool(context.target_reaches_pred),
            ),
            already_emitted=bool(context.already_emitted),
            existing_target=(
                int(context.existing_target)
                if context.existing_target is not None
                else None
            ),
            prefix_target=int(context.prefix_target),
            via_pred_succ_count=int(context.via_pred_succ_count),
        )

    return ResidualPrefixAttempt(
        via_pred=int(context.via_pred),
        prefix_target=int(context.prefix_target),
        claimed_branch_target=(
            int(context.claimed_branch_target)
            if context.claimed_branch_target is not None
            else None
        ),
        owned_transition=(
            (int(context.owned_transition[0]), int(context.owned_transition[1]))
            if context.owned_transition is not None
            else None
        ),
        edge_kind_name=context.edge_kind_name,
        branch_context=branch_context,
        peel_context=peel_context,
    )


def build_residual_pred_split_attempt(
    context: ResidualPredSplitAttemptBuildContext,
) -> ResidualPredSplitAttempt:
    return ResidualPredSplitAttempt(
        via_pred=int(context.via_pred),
        target_entry=int(context.target_entry),
        state_value=int(context.state_value),
        context=ResidualPredSplitContext(
            source_block=int(context.source_block),
            via_pred=int(context.via_pred),
            target_entry=int(context.target_entry),
            dispatcher_serial=int(context.dispatcher_serial),
            condition_chain_blocks=frozenset(int(block) for block in context.condition_chain_blocks),
            valid_pair=bool(context.valid_pair),
            target_reaches_via_pred=bool(context.target_reaches_via_pred),
            already_emitted=bool(context.already_emitted),
        ),
    )


def build_residual_goto_attempt(
    context: ResidualGotoAttemptBuildContext,
) -> ResidualGotoAttempt:
    return ResidualGotoAttempt(
        target_entry=int(context.target_entry),
        state_value=int(context.state_value),
        context=ResidualGotoHandoffContext(
            source_block=int(context.source_block),
            target_entry=int(context.target_entry),
            dispatcher_serial=int(context.dispatcher_serial),
            condition_chain_blocks=frozenset(int(block) for block in context.condition_chain_blocks),
            allow_family_fallback_tail=bool(context.allow_family_fallback_tail),
            is_shared_suffix_conditional_tail=bool(context.is_shared_suffix_conditional_tail),
            has_prior_branch_cut=bool(context.has_prior_branch_cut),
            target_reaches_source=bool(context.target_reaches_source),
            already_emitted=bool(context.already_emitted),
            live_oneway_noop=bool(context.live_oneway_noop),
        ),
    )


__all__ = [
    "ResidualGotoAttemptBuildContext",
    "ResidualPredSplitAttemptBuildContext",
    "ResidualPrefixAttemptBuildContext",
    "build_residual_goto_attempt",
    "build_residual_pred_split_attempt",
    "build_residual_prefix_attempt",
]
