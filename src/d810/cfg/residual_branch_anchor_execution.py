from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Mapping

from d810.cfg.lowering_selector import resolve_redirect_old_target, target_reaches_source_ignoring_blocks
from d810.cfg.residual_handoff_modification_planning import (
    apply_residual_branch_anchor_emission_plan,
    plan_residual_branch_anchor_emission,
)


@dataclass(frozen=True, slots=True)
class ResidualBranchAnchorExecutionContext:
    edge: object
    source_block: int
    via_pred: int
    prefix_target: int
    projected_flow_graph: object
    bst_node_blocks: frozenset[int]
    dispatcher_serial: int
    block_succ_map: Mapping[int, tuple[int, ...]]
    ignored_blocks: frozenset[int]
    residual_ignored_blocks: frozenset[int]


@dataclass(slots=True)
class ResidualBranchAnchorMutableState:
    modifications: list
    owned_blocks: set[int]
    owned_edges: set[tuple[int, int]]
    owned_transitions: set[tuple[int, int]]
    emitted: set[tuple[int, int]]
    claimed_2way: dict[tuple[int, int], int]


@dataclass(frozen=True, slots=True)
class ResidualBranchAnchorExecutionResult:
    accepted: bool
    already_claimed: bool = False
    branch_source: int | None = None
    prefix_target: int | None = None
    via_pred: int | None = None
    edge_kind_name: str | None = None


def execute_residual_branch_anchor_handoff(
    context: ResidualBranchAnchorExecutionContext,
    *,
    state: ResidualBranchAnchorMutableState,
) -> ResidualBranchAnchorExecutionResult:
    source_anchor = context.edge.source_anchor
    branch_source = int(source_anchor.block_serial)
    branch_block = context.projected_flow_graph.get_block(branch_source)
    if branch_block is None:
        return ResidualBranchAnchorExecutionResult(accepted=False)

    branch_succs = tuple(int(succ) for succ in tuple(getattr(branch_block, "succs", ())))
    old_target = resolve_redirect_old_target(
        branch_source,
        source_succs=tuple(context.block_succ_map.get(branch_source, ())),
        ordered_path=tuple(int(node) for node in context.edge.ordered_path),
        target_entry_anchor=(
            int(context.edge.target_entry_anchor)
            if context.edge.target_entry_anchor is not None
            else None
        ),
        source_branch_arm=(
            int(context.edge.source_anchor.branch_arm)
            if context.edge.source_anchor.branch_arm is not None
            else None
        ),
        source_is_conditional_branch=(
            context.edge.source_anchor.kind.name == "CONDITIONAL_BRANCH"
        ),
        bst_node_blocks=set(int(block) for block in context.bst_node_blocks),
        dispatcher_region=set(int(block) for block in context.ignored_blocks),
    )
    decision = plan_residual_branch_anchor_emission(
        is_conditional_branch_source=(
            source_anchor.kind.name == "CONDITIONAL_BRANCH"
        ),
        branch_source=branch_source,
        source_block=int(context.source_block),
        via_pred=int(context.via_pred),
        prefix_target=int(context.prefix_target),
        branch_succs=branch_succs,
        old_target=int(old_target),
        ordered_path=tuple(int(node) for node in context.edge.ordered_path),
        dispatcher_serial=int(context.dispatcher_serial),
        bst_node_blocks=frozenset(int(block) for block in context.bst_node_blocks),
        target_reaches_branch=target_reaches_source_ignoring_blocks(
            context.projected_flow_graph,
            target_entry=int(context.prefix_target),
            source_block=branch_source,
            ignored_blocks=(
                set(int(block) for block in context.residual_ignored_blocks)
                | {int(context.source_block), int(context.via_pred)}
            ),
        ),
        claimed_branch_target=state.claimed_2way.get((branch_source, int(old_target))),
        owned_transition=(
            (context.edge.source_key.state_const, context.edge.target_state & 0xFFFFFFFF)
            if context.edge.source_key.state_const is not None
            and context.edge.target_state is not None
            else None
        ),
        edge_kind_name=context.edge.kind.name.lower(),
    )
    if not decision.accepted:
        return ResidualBranchAnchorExecutionResult(accepted=False)
    if decision.already_claimed:
        return ResidualBranchAnchorExecutionResult(
            accepted=True,
            already_claimed=True,
            branch_source=int(decision.branch_source),
            prefix_target=int(decision.prefix_target),
            via_pred=int(decision.via_pred),
            edge_kind_name=decision.edge_kind_name,
        )

    apply_residual_branch_anchor_emission_plan(
        decision,
        modifications=state.modifications,
        claimed_2way=state.claimed_2way,
        emitted=state.emitted,
        owned_blocks=state.owned_blocks,
        owned_edges=state.owned_edges,
        owned_transitions=state.owned_transitions,
    )
    return ResidualBranchAnchorExecutionResult(
        accepted=True,
        already_claimed=False,
        branch_source=int(decision.branch_source),
        prefix_target=int(decision.prefix_target),
        via_pred=int(decision.via_pred),
        edge_kind_name=decision.edge_kind_name,
    )


def emit_residual_branch_anchor_handoff(
    *,
    edge: object,
    source_block: int,
    via_pred: int,
    prefix_target: int,
    projected_flow_graph: object,
    bst_node_blocks: set[int],
    dispatcher_serial: int,
    builder: object,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    owned_transitions: set[tuple[int, int]],
    emitted: set[tuple[int, int]],
    claimed_2way: dict[tuple[int, int], int],
    ignored_blocks: set[int],
    residual_ignored_blocks: set[int],
) -> ResidualBranchAnchorExecutionResult:
    return execute_residual_branch_anchor_handoff(
        ResidualBranchAnchorExecutionContext(
            edge=edge,
            source_block=int(source_block),
            via_pred=int(via_pred),
            prefix_target=int(prefix_target),
            projected_flow_graph=projected_flow_graph,
            bst_node_blocks=frozenset(int(block) for block in bst_node_blocks),
            dispatcher_serial=int(dispatcher_serial),
            block_succ_map=builder.block_succ_map,
            ignored_blocks=frozenset(int(block) for block in ignored_blocks),
            residual_ignored_blocks=frozenset(
                int(block) for block in residual_ignored_blocks
            ),
        ),
        state=ResidualBranchAnchorMutableState(
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
            emitted=emitted,
            claimed_2way=claimed_2way,
        ),
    )


__all__ = [
    "emit_residual_branch_anchor_handoff",
    "ResidualBranchAnchorExecutionContext",
    "ResidualBranchAnchorExecutionResult",
    "ResidualBranchAnchorMutableState",
    "execute_residual_branch_anchor_handoff",
]
