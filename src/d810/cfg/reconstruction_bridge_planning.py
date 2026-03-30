from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.mod_claims import collect_mod_claims


@dataclass(frozen=True, slots=True)
class ReconstructionBridgeLogEntry:
    source_block: int
    branch_arm: int | None
    target_block: int
    tag: str


@dataclass(frozen=True, slots=True)
class ReconstructionPreheaderBridgeResult:
    modification: object | None
    resolved_target: int | None


@dataclass(frozen=True, slots=True)
class ReconstructionBridgePlanResult:
    modifications: tuple[object, ...]
    log_entries: tuple[ReconstructionBridgeLogEntry, ...]
    claimed_sources: frozenset[int]
    claimed_targets: frozenset[int]


def collect_reconstruction_claims(
    modifications: list,
    *,
    owned_blocks: set[int],
) -> tuple[set[int], set[int]]:
    claimed_sources, claimed_targets = collect_mod_claims(modifications)
    claimed_sources.update(int(block_serial) for block_serial in owned_blocks)
    return claimed_sources, claimed_targets


def collect_suppressed_bridge_pairs(
    rejected_metadata: list[dict[str, int | str | None]],
) -> set[tuple[int, int]]:
    suppressed_bridge_pairs: set[tuple[int, int]] = set()
    for rej in rejected_metadata:
        if rej.get("rejection_reason") != "backward_same_corridor_target":
            continue
        rej_src = rej.get("source_block")
        rej_tgt = rej.get("target_entry_anchor")
        if rej_src is not None and rej_tgt is not None:
            suppressed_bridge_pairs.add((int(rej_src), int(rej_tgt)))
    return suppressed_bridge_pairs


def plan_reconstruction_preheader_bridge(
    *,
    dag,
    flow_graph,
    builder,
    dispatcher_serial: int,
    bst_node_blocks: set[int],
    dispatcher,
) -> ReconstructionPreheaderBridgeResult:
    if (
        dispatcher is None
        or dag.pre_header_serial is None
        or dag.initial_state is None
    ):
        return ReconstructionPreheaderBridgeResult(
            modification=None,
            resolved_target=None,
        )

    bst_set = {int(dispatcher_serial)}
    bst_set.update(int(block) for block in bst_node_blocks)
    resolved = dispatcher.lookup(dag.initial_state)
    if resolved is None or int(resolved) in bst_set:
        return ReconstructionPreheaderBridgeResult(
            modification=None,
            resolved_target=None,
        )

    pre_blk = flow_graph.get_block(dag.pre_header_serial)
    if pre_blk is None or pre_blk.nsucc != 1:
        return ReconstructionPreheaderBridgeResult(
            modification=None,
            resolved_target=None,
        )

    old_target = int(pre_blk.succs[0])
    if old_target != dispatcher_serial and old_target not in bst_set:
        return ReconstructionPreheaderBridgeResult(
            modification=None,
            resolved_target=None,
        )

    return ReconstructionPreheaderBridgeResult(
        modification=builder.goto_redirect(
            source_block=dag.pre_header_serial,
            target_block=int(resolved),
            old_target=old_target,
        ),
        resolved_target=int(resolved),
    )


def plan_reconstruction_bridge_modifications(
    *,
    dag,
    flow_graph,
    builder,
    dispatcher_serial: int,
    bst_node_blocks: set[int],
    claimed_sources: set[int],
    claimed_targets: set[int],
    suppressed_bridge_pairs: set[tuple[int, int]],
) -> ReconstructionBridgePlanResult:
    bridge_mods: list = []
    log_entries: list[ReconstructionBridgeLogEntry] = []
    bst_set = {int(dispatcher_serial)}
    bst_set.update(int(block) for block in bst_node_blocks)

    for edge in dag.edges:
        if edge.target_entry_anchor is None:
            continue
        target_entry = int(edge.target_entry_anchor)
        if target_entry in bst_set or target_entry in claimed_targets:
            continue

        exit_block: int | None = None
        if edge.ordered_path:
            for serial in reversed(edge.ordered_path):
                if int(serial) not in bst_set:
                    exit_block = int(serial)
                    break
        else:
            src = int(edge.source_anchor.block_serial)
            if src not in bst_set:
                exit_block = src

        if exit_block is None or (exit_block, target_entry) in suppressed_bridge_pairs:
            continue
        if exit_block in claimed_sources:
            continue

        block = flow_graph.get_block(exit_block)
        if block is None:
            continue

        already_wired = any(int(block.succs[i]) == target_entry for i in range(block.nsucc))
        if already_wired:
            claimed_targets.add(target_entry)
            continue

        if block.nsucc == 1:
            old_target = int(block.succs[0])
            if old_target == dispatcher_serial or old_target in bst_set:
                bridge_mods.append(
                    builder.goto_redirect(
                        source_block=exit_block,
                        target_block=target_entry,
                        old_target=old_target,
                    )
                )
                claimed_targets.add(target_entry)
                claimed_sources.add(exit_block)
                log_entries.append(
                    ReconstructionBridgeLogEntry(
                        source_block=exit_block,
                        branch_arm=None,
                        target_block=target_entry,
                        tag=(
                            "empty-path direct wire"
                            if not edge.ordered_path
                            else "1-way"
                        ),
                    )
                )
        elif block.nsucc == 2:
            for arm in range(2):
                arm_target = int(block.succs[arm])
                if arm_target == dispatcher_serial or arm_target in bst_set:
                    if arm == 1:
                        bridge_mods.append(
                            builder.edge_redirect(
                                source_block=exit_block,
                                target_block=target_entry,
                                old_target=arm_target,
                            )
                        )
                        claimed_targets.add(target_entry)
                        claimed_sources.add(exit_block)
                        log_entries.append(
                            ReconstructionBridgeLogEntry(
                                source_block=exit_block,
                                branch_arm=arm,
                                target_block=target_entry,
                                tag=(
                                    "empty-path direct wire"
                                    if not edge.ordered_path
                                    else "2-way"
                                ),
                            )
                        )
                    break

    return ReconstructionBridgePlanResult(
        modifications=tuple(bridge_mods),
        log_entries=tuple(log_entries),
        claimed_sources=frozenset(int(serial) for serial in claimed_sources),
        claimed_targets=frozenset(int(serial) for serial in claimed_targets),
    )


__all__ = [
    "ReconstructionBridgeLogEntry",
    "ReconstructionBridgePlanResult",
    "ReconstructionPreheaderBridgeResult",
    "collect_reconstruction_claims",
    "collect_suppressed_bridge_pairs",
    "plan_reconstruction_bridge_modifications",
    "plan_reconstruction_preheader_bridge",
]
