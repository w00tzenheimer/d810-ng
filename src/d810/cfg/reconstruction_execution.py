from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from d810.cfg.reconstruction_lowering import SharedGroupEmissionCandidate
from d810.cfg.reconstruction_modification_planning import (
    plan_conditional_arm_reconstruction_modifications,
    plan_direct_reconstruction_modifications,
    plan_passthrough_reconstruction_modifications,
    plan_shared_group_reconstruction_modifications,
)


@dataclass(frozen=True, slots=True)
class ConditionalArmExecutionResult:
    candidate: object
    redirect_count: int
    passthrough_count: int


@dataclass(frozen=True, slots=True)
class DirectExecutionResult:
    accepted_candidate: object | None
    rejected_candidates: tuple[object, ...]
    rejection_reason: str | None
    passthrough_count: int = 0


@dataclass(frozen=True, slots=True)
class SharedGroupExecutionResult:
    shared_block: int
    accepted_candidates: tuple[object, ...]
    rejected_candidates: tuple[object, ...]
    rejection_reason: str | None
    per_pred_targets: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True, slots=True)
class PrimaryReconstructionExecutionResult:
    conditional_results: tuple[ConditionalArmExecutionResult, ...]
    direct_results: tuple[DirectExecutionResult, ...]
    shared_group_results: tuple[SharedGroupExecutionResult, ...]


def _is_conditional_transition(candidate) -> bool:
    edge_kind = getattr(getattr(candidate, "edge", None), "kind", None)
    return getattr(edge_kind, "name", None) == "CONDITIONAL_TRANSITION"


def execute_shared_group_reconstruction(
    *,
    shared_block: int,
    candidates: list,
    flow_graph,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
) -> SharedGroupExecutionResult:
    ordered_input_candidates = tuple(
        SharedGroupEmissionCandidate(
            via_pred=int(candidate.via_pred),
            target_entry=int(candidate.target_entry),
        )
        for candidate in candidates
        if candidate.via_pred is not None
    )
    if not ordered_input_candidates:
        return SharedGroupExecutionResult(
            shared_block=int(shared_block),
            accepted_candidates=(),
            rejected_candidates=(),
            rejection_reason=None,
        )

    shared_plan = plan_shared_group_reconstruction_modifications(
        flow_graph=flow_graph,
        shared_block=int(shared_block),
        ordered_path=tuple(int(serial) for serial in candidates[0].edge.ordered_path),
        shared_candidates=ordered_input_candidates,
    )
    if not shared_plan.accepted:
        return SharedGroupExecutionResult(
            shared_block=int(shared_block),
            accepted_candidates=(),
            rejected_candidates=tuple(
                candidate for candidate in candidates if candidate.via_pred is not None
            ),
            rejection_reason=shared_plan.rejection_reason,
        )

    by_pred = {
        int(candidate.via_pred): candidate
        for candidate in candidates
        if candidate.via_pred is not None
    }
    ordered_candidates = tuple(
        by_pred[int(via_pred)] for via_pred in shared_plan.ordered_via_preds
    )
    modifications.extend(shared_plan.modifications)
    owned_blocks.add(int(shared_block))
    for _, target_entry in shared_plan.per_pred_targets:
        owned_edges.add((int(shared_block), int(target_entry)))
    return SharedGroupExecutionResult(
        shared_block=int(shared_block),
        accepted_candidates=ordered_candidates,
        rejected_candidates=(),
        rejection_reason=None,
        per_pred_targets=tuple(
            (int(pred), int(target))
            for pred, target in shared_plan.per_pred_targets
        ),
    )


def execute_primary_reconstruction_modifications(
    *,
    raw_candidates: list,
    flow_graph,
    node_by_key,
    dispatcher_serial: int,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
) -> PrimaryReconstructionExecutionResult:
    direct_groups: defaultdict[int, list] = defaultdict(list)
    shared_groups: defaultdict[int, list] = defaultdict(list)
    conditional_arm_candidates: list = []
    for candidate in raw_candidates:
        if candidate.emission_mode == "conditional_arm":
            conditional_arm_candidates.append(candidate)
        elif candidate.emission_mode == "direct":
            direct_groups[int(candidate.horizon_block)].append(candidate)
        else:
            assert candidate.first_shared_block is not None
            shared_groups[int(candidate.first_shared_block)].append(candidate)

    conditional_results: list[ConditionalArmExecutionResult] = []
    for candidate in conditional_arm_candidates:
        source_node = node_by_key.get(candidate.edge.source_key)
        pt_entry: int | None = None
        if source_node is not None and candidate.edge.source_key.state_const is not None:
            pt_entry = source_node.entry_anchor

        cond_plan = plan_conditional_arm_reconstruction_modifications(
            flow_graph=flow_graph,
            horizon_block=int(candidate.horizon_block),
            target_entry=int(candidate.target_entry),
            branch_arm=int(candidate.edge.source_anchor.branch_arm or 0),
            dispatcher_serial=dispatcher_serial,
            current_entry=pt_entry,
        )
        if not cond_plan.modifications:
            continue

        modifications.extend(cond_plan.modifications)
        owned_blocks.add(int(candidate.horizon_block))
        owned_edges.add((int(candidate.horizon_block), int(candidate.target_entry)))

        pt_plan = plan_passthrough_reconstruction_modifications(
            flow_graph=flow_graph,
            ordered_path=tuple(int(serial) for serial in candidate.edge.ordered_path),
            horizon_block=int(candidate.horizon_block),
            dispatcher_serial=dispatcher_serial,
            current_state_entry=pt_entry,
        )
        modifications.extend(pt_plan.modifications)
        conditional_results.append(
            ConditionalArmExecutionResult(
                candidate=candidate,
                redirect_count=len(cond_plan.modifications),
                passthrough_count=len(pt_plan.modifications),
            )
        )

    direct_results: list[DirectExecutionResult] = []
    for horizon_block in sorted(direct_groups):
        group = direct_groups[horizon_block]
        targets = {candidate.target_entry for candidate in group}
        if len(targets) > 1:
            direct_results.append(
                DirectExecutionResult(
                    accepted_candidate=None,
                    rejected_candidates=tuple(group),
                    rejection_reason="direct_conflict",
                )
            )
            continue

        direct_candidate = group[0]
        direct_plan = plan_direct_reconstruction_modifications(
            flow_graph=flow_graph,
            horizon_block=int(direct_candidate.horizon_block),
            target_entry=int(direct_candidate.target_entry),
            ordered_path=tuple(
                int(serial) for serial in direct_candidate.edge.ordered_path
            ),
        )
        if not direct_plan.accepted:
            direct_results.append(
                DirectExecutionResult(
                    accepted_candidate=None,
                    rejected_candidates=(direct_candidate,),
                    rejection_reason="noop_or_missing_old_target",
                )
            )
            continue

        modifications.extend(direct_plan.modifications)
        owned_blocks.add(int(direct_candidate.horizon_block))
        owned_edges.add(
            (int(direct_candidate.horizon_block), int(direct_candidate.target_entry))
        )

        passthrough_count = 0
        if _is_conditional_transition(direct_candidate):
            source_node = node_by_key.get(direct_candidate.edge.source_key)
            pt_entry_d: int | None = None
            if (
                source_node is not None
                and direct_candidate.edge.source_key.state_const is not None
            ):
                pt_entry_d = source_node.entry_anchor
            pt_plan_d = plan_passthrough_reconstruction_modifications(
                flow_graph=flow_graph,
                ordered_path=tuple(
                    int(serial) for serial in direct_candidate.edge.ordered_path
                ),
                horizon_block=int(direct_candidate.horizon_block),
                dispatcher_serial=dispatcher_serial,
                current_state_entry=pt_entry_d,
            )
            modifications.extend(pt_plan_d.modifications)
            passthrough_count = len(pt_plan_d.modifications)

        direct_results.append(
            DirectExecutionResult(
                accepted_candidate=direct_candidate,
                rejected_candidates=(),
                rejection_reason=None,
                passthrough_count=passthrough_count,
            )
        )

    shared_group_results: list[SharedGroupExecutionResult] = []
    for shared_block in sorted(shared_groups):
        shared_group_results.append(
            execute_shared_group_reconstruction(
                shared_block=shared_block,
                candidates=shared_groups[shared_block],
                flow_graph=flow_graph,
                modifications=modifications,
                owned_blocks=owned_blocks,
                owned_edges=owned_edges,
            )
        )

    return PrimaryReconstructionExecutionResult(
        conditional_results=tuple(conditional_results),
        direct_results=tuple(direct_results),
        shared_group_results=tuple(shared_group_results),
    )


__all__ = [
    "ConditionalArmExecutionResult",
    "DirectExecutionResult",
    "PrimaryReconstructionExecutionResult",
    "SharedGroupExecutionResult",
    "execute_primary_reconstruction_modifications",
    "execute_shared_group_reconstruction",
]
