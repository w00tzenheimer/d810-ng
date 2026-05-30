from __future__ import annotations

from dataclasses import dataclass

from d810.transforms.graph_modification import GraphModification, RedirectBranch, RedirectGoto


@dataclass(frozen=True, slots=True)
class DagRedirectFallbackContext:
    source_block: int
    target_entry: int
    source_handler_is_report_exit: bool
    ordered_path_head_is_report_exit: bool
    source_equals_target: bool
    backward_same_corridor: bool
    allow_semantic_handoff: bool
    target_reaches_source: bool
    source_blocked: bool
    source_terminal_protected: bool
    source_in_report_exit_owned: bool
    source_in_terminal_source_owned_transition: bool
    ordered_path_ends_at_source: bool
    emitted_already: bool
    nsucc: int
    old_target: int | None
    source_succs: tuple[int, ...]
    edge_is_transition: bool
    live_oneway_noop: bool
    claimed_1way_target: int | None
    claimed_2way_target: int | None


@dataclass(frozen=True, slots=True)
class DagRedirectEmissionPlan:
    accepted: bool
    modification: GraphModification | None = None
    source_block: int | None = None
    target_entry: int | None = None
    claim_1way_target: int | None = None
    claim_2way_key: tuple[int, int] | None = None
    claim_2way_target: int | None = None
    rejection_reason: str = ""
    existing_target: int | None = None


@dataclass(frozen=True, slots=True)
class DagRedirectDecision:
    accepted: bool
    emission_plan: DagRedirectEmissionPlan | None = None
    rejection_reason: str = ""


def plan_dag_redirect_fallback(
    context: DagRedirectFallbackContext,
) -> DagRedirectDecision:
    if context.source_handler_is_report_exit:
        return DagRedirectDecision(
            accepted=False,
            rejection_reason="report_exit_source_handler",
        )
    if context.ordered_path_head_is_report_exit:
        return DagRedirectDecision(
            accepted=False,
            rejection_reason="report_exit_path_head",
        )
    if context.source_equals_target:
        return DagRedirectDecision(
            accepted=False,
            rejection_reason="source_equals_target",
        )
    if context.backward_same_corridor:
        return DagRedirectDecision(
            accepted=False,
            rejection_reason="backward_same_corridor",
        )
    if context.target_reaches_source and not context.allow_semantic_handoff:
        return DagRedirectDecision(
            accepted=False,
            rejection_reason="target_reaches_source",
        )
    if context.source_blocked:
        return DagRedirectDecision(
            accepted=False,
            rejection_reason="blocked_source",
        )
    if context.source_terminal_protected:
        return DagRedirectDecision(
            accepted=False,
            rejection_reason="terminal_protected_source",
        )
    if context.source_in_report_exit_owned:
        return DagRedirectDecision(
            accepted=False,
            rejection_reason="report_exit_owned_source",
        )
    if context.source_in_terminal_source_owned_transition:
        return DagRedirectDecision(
            accepted=False,
            rejection_reason="terminal_source_owned_transition",
        )
    if not context.ordered_path_ends_at_source:
        return DagRedirectDecision(
            accepted=False,
            rejection_reason="ordered_path_source_mismatch",
        )
    if context.emitted_already:
        return DagRedirectDecision(
            accepted=False,
            rejection_reason="already_emitted",
        )
    emission_plan = plan_dag_redirect_fallback_emission(
        source_block=int(context.source_block),
        target_entry=int(context.target_entry),
        nsucc=int(context.nsucc),
        old_target=(
            int(context.old_target)
            if context.old_target is not None
            else None
        ),
        source_succs=tuple(int(succ) for succ in context.source_succs),
        edge_is_transition=bool(context.edge_is_transition),
        live_oneway_noop=bool(context.live_oneway_noop),
        claimed_1way_target=(
            int(context.claimed_1way_target)
            if context.claimed_1way_target is not None
            else None
        ),
        claimed_2way_target=(
            int(context.claimed_2way_target)
            if context.claimed_2way_target is not None
            else None
        ),
    )
    if not emission_plan.accepted or emission_plan.modification is None:
        return DagRedirectDecision(
            accepted=False,
            rejection_reason=emission_plan.rejection_reason,
            emission_plan=emission_plan,
        )
    return DagRedirectDecision(
        accepted=True,
        emission_plan=emission_plan,
    )


def plan_dag_redirect_fallback_emission(
    *,
    source_block: int,
    target_entry: int,
    nsucc: int,
    old_target: int | None,
    source_succs: tuple[int, ...],
    edge_is_transition: bool,
    live_oneway_noop: bool,
    claimed_1way_target: int | None,
    claimed_2way_target: int | None,
) -> DagRedirectEmissionPlan:
    if nsucc == 2 and edge_is_transition:
        return DagRedirectEmissionPlan(
            accepted=False,
            rejection_reason="transition_two_way_source",
        )

    if nsucc == 2:
        if old_target is None or int(old_target) == int(target_entry):
            return DagRedirectEmissionPlan(
                accepted=False,
                rejection_reason="invalid_old_target",
            )
        if claimed_2way_target is not None:
            if int(claimed_2way_target) == int(target_entry):
                return DagRedirectEmissionPlan(
                    accepted=False,
                    rejection_reason="existing_branch_target",
                    existing_target=int(claimed_2way_target),
                )
            return DagRedirectEmissionPlan(
                accepted=False,
                rejection_reason="branch_conflict",
                existing_target=int(claimed_2way_target),
            )
        return DagRedirectEmissionPlan(
            accepted=True,
            modification=RedirectBranch(
                from_serial=int(source_block),
                old_target=int(old_target),
                new_target=int(target_entry),
            ),
            source_block=int(source_block),
            target_entry=int(target_entry),
            claim_2way_key=(int(source_block), int(old_target)),
            claim_2way_target=int(target_entry),
        )

    if live_oneway_noop:
        return DagRedirectEmissionPlan(
            accepted=False,
            rejection_reason="live_oneway_noop",
        )
    if claimed_1way_target is not None and int(claimed_1way_target) != int(target_entry):
        return DagRedirectEmissionPlan(
            accepted=False,
            rejection_reason="oneway_conflict",
            existing_target=int(claimed_1way_target),
        )
    resolved_old_target = (
        int(old_target)
        if old_target is not None
        else (
            int(source_succs[0])
            if len(tuple(int(succ) for succ in source_succs)) == 1
            else None
        )
    )
    if resolved_old_target is None:
        return DagRedirectEmissionPlan(
            accepted=False,
            rejection_reason="unknown_old_target",
        )
    return DagRedirectEmissionPlan(
        accepted=True,
        modification=RedirectGoto(
            from_serial=int(source_block),
            old_target=resolved_old_target,
            new_target=int(target_entry),
        ),
        source_block=int(source_block),
        target_entry=int(target_entry),
        claim_1way_target=int(target_entry),
    )


def apply_dag_redirect_emission_plan(
    emission_plan: DagRedirectEmissionPlan,
    *,
    modifications: list[GraphModification],
    claimed_1way: dict[int, int],
    claimed_2way: dict[tuple[int, int], int],
    emitted: set[tuple[int, int]],
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    owned_transitions: set[tuple[int, int]],
    owned_transition: tuple[int, int] | None = None,
) -> None:
    if emission_plan.modification is None:
        raise ValueError("dag redirect emission plan has no modification")
    if emission_plan.source_block is None or emission_plan.target_entry is None:
        raise ValueError("dag redirect emission plan is missing source block or target entry")

    source_block = int(emission_plan.source_block)
    target_entry = int(emission_plan.target_entry)
    modifications.append(emission_plan.modification)
    if emission_plan.claim_2way_key is not None and emission_plan.claim_2way_target is not None:
        claimed_2way[
            (int(emission_plan.claim_2way_key[0]), int(emission_plan.claim_2way_key[1]))
        ] = int(emission_plan.claim_2way_target)
    if emission_plan.claim_1way_target is not None:
        claimed_1way[source_block] = int(emission_plan.claim_1way_target)

    emitted.add((source_block, target_entry))
    owned_blocks.add(source_block)
    owned_edges.add((source_block, target_entry))
    if owned_transition is not None:
        owned_transitions.add((int(owned_transition[0]), int(owned_transition[1])))


__all__ = [
    "apply_dag_redirect_emission_plan",
    "DagRedirectDecision",
    "DagRedirectFallbackContext",
    "DagRedirectEmissionPlan",
    "plan_dag_redirect_fallback",
    "plan_dag_redirect_fallback_emission",
]
