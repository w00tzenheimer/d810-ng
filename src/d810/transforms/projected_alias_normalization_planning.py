from __future__ import annotations

from dataclasses import dataclass

from d810.transforms.graph_modification import RedirectGoto
from d810.transforms.lowering_selector import target_reaches_source_ignoring_blocks
from d810.transforms.residual_handoff_modification_planning import (
    plan_projected_alias_handoff_normalization,
)


@dataclass(frozen=True, slots=True)
class ProjectedAliasNormalizationAction:
    source_block: int
    current_target: int
    target_entry: int
    modification: object
    replace_index: int | None = None
    replaced_target: int | None = None


def collect_projected_alias_normalization_actions(
    *,
    dag,
    projected_flow_graph,
    dispatcher_serial: int,
    redirected_blocks: set[int],
    bst_node_blocks: set[int],
    modifications: list,
    emitted: set[tuple[int, int]],
    resolve_projected_path_tail_target,
) -> tuple[ProjectedAliasNormalizationAction, ...]:
    ignored_blocks = set(int(block) for block in bst_node_blocks)
    ignored_blocks.add(int(dispatcher_serial))
    actions: list[ProjectedAliasNormalizationAction] = []

    for source_block in sorted(int(block) for block in redirected_blocks):
        block = projected_flow_graph.get_block(source_block)
        if block is None or tuple(getattr(block, "succs", ())) is None:
            continue
        succs = tuple(int(succ) for succ in tuple(getattr(block, "succs", ())))
        if len(succs) != 1:
            continue
        current_target = int(succs[0])
        projected_handoff = resolve_projected_path_tail_target(
            dag,
            source_block=source_block,
            bst_node_blocks=bst_node_blocks,
        )
        if projected_handoff is None:
            continue
        _, target_entry = projected_handoff
        target_entry = int(target_entry)
        if target_entry == source_block or target_entry == current_target:
            continue
        if target_reaches_source_ignoring_blocks(
            projected_flow_graph,
            target_entry=target_entry,
            source_block=source_block,
            ignored_blocks=ignored_blocks,
        ):
            continue

        emit_key = (source_block, target_entry)
        existing_index = None
        existing_mod_old_target = None
        existing_mod_target = None
        for idx in range(len(modifications) - 1, -1, -1):
            mod = modifications[idx]
            if isinstance(mod, RedirectGoto) and mod.from_serial == source_block:
                existing_index = idx
                existing_mod_old_target = int(mod.old_target)
                existing_mod_target = int(mod.new_target)
                break

        plan = plan_projected_alias_handoff_normalization(
            source_block=source_block,
            current_target=current_target,
            target_entry=target_entry,
            existing_redirect_index=existing_index,
            existing_redirect_old_target=existing_mod_old_target,
            existing_redirect_target=existing_mod_target,
            already_emitted=(emit_key in emitted),
        )
        if not plan.accepted or plan.modification is None:
            continue

        actions.append(
            ProjectedAliasNormalizationAction(
                source_block=source_block,
                current_target=current_target,
                target_entry=target_entry,
                modification=plan.modification,
                replace_index=plan.replace_index,
                replaced_target=plan.replaced_target,
            )
        )

    return tuple(actions)


def apply_projected_alias_normalization_actions(
    actions: tuple[ProjectedAliasNormalizationAction, ...],
    *,
    modifications: list,
    emitted: set[tuple[int, int]],
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    claimed_1way: dict[int, int],
) -> None:
    for action in actions:
        if action.replace_index is not None:
            modifications[action.replace_index] = action.modification
            if action.replaced_target is not None:
                emitted.discard((int(action.source_block), int(action.replaced_target)))
        else:
            modifications.append(action.modification)
        claimed_1way[int(action.source_block)] = int(action.target_entry)
        emitted.add((int(action.source_block), int(action.target_entry)))
        owned_blocks.add(int(action.source_block))
        owned_edges.add((int(action.source_block), int(action.target_entry)))


def normalize_projected_alias_handoffs(
    *,
    dag,
    projected_flow_graph: object,
    dispatcher_serial: int,
    redirected_blocks: set[int],
    bst_node_blocks: set[int],
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    emitted: set[tuple[int, int]],
    claimed_1way: dict[int, int],
    resolve_projected_path_tail_target,
    log_action=None,
) -> int:
    actions = collect_projected_alias_normalization_actions(
        dag=dag,
        projected_flow_graph=projected_flow_graph,
        dispatcher_serial=int(dispatcher_serial),
        redirected_blocks={int(block) for block in redirected_blocks},
        bst_node_blocks={int(block) for block in bst_node_blocks},
        modifications=modifications,
        emitted=emitted,
        resolve_projected_path_tail_target=resolve_projected_path_tail_target,
    )
    apply_projected_alias_normalization_actions(
        actions,
        modifications=modifications,
        emitted=emitted,
        owned_blocks=owned_blocks,
        owned_edges=owned_edges,
        claimed_1way=claimed_1way,
    )
    if log_action is not None:
        for action in actions:
            log_action(action)
    return len(actions)


__all__ = [
    "apply_projected_alias_normalization_actions",
    "ProjectedAliasNormalizationAction",
    "collect_projected_alias_normalization_actions",
    "normalize_projected_alias_handoffs",
]
