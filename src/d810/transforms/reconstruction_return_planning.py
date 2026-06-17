from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ReconstructionReturnLogEntry:
    source_block: int
    branch_arm: int | None
    target_block: int
    tag: str
    bypass_block: int | None = None


@dataclass(frozen=True, slots=True)
class ReconstructionReturnSkipEntry:
    source_block: int
    reason: str


@dataclass(frozen=True, slots=True)
class ReconstructionReturnPlanResult:
    modifications: tuple[object, ...]
    log_entries: tuple[ReconstructionReturnLogEntry, ...]
    skipped_entries: tuple[ReconstructionReturnSkipEntry, ...]
    claimed_sources: frozenset[int]


def _edge_kind_name(edge) -> str:
    return getattr(getattr(edge, "kind", None), "name", str(getattr(edge, "kind", None)))


def _is_terminal_stop(flow_graph, serial: int) -> bool:
    block = flow_graph.get_block(serial)
    return block is not None and int(block.nsucc) == 0


def _path_position(ordered: tuple[int, ...], serial: int) -> int | None:
    try:
        return ordered.index(int(serial))
    except ValueError:
        return None


def plan_reconstruction_return_modifications(
    *,
    dag,
    flow_graph,
    builder,
    claimed_sources: set[int],
    dispatcher_serial: int,
    condition_chain_blocks: set[int],
    common_return_corridor: set[int],
    artifact_return_blocks: set[int],
    node_by_key,
) -> ReconstructionReturnPlanResult:
    return_mods: list = []
    log_entries: list[ReconstructionReturnLogEntry] = []
    skipped_entries: list[ReconstructionReturnSkipEntry] = []
    condition_chain_set = {int(dispatcher_serial)}
    condition_chain_set.update(int(block) for block in condition_chain_blocks)

    for edge in dag.edges:
        if _edge_kind_name(edge) != "CONDITIONAL_RETURN":
            continue

        src_serial = int(edge.source_anchor.block_serial)
        src_arm = edge.source_anchor.branch_arm
        if not edge.ordered_path:
            skipped_entries.append(
                ReconstructionReturnSkipEntry(
                    source_block=src_serial,
                    reason="empty_ordered_path",
                )
            )
            continue

        ordered = tuple(int(serial) for serial in edge.ordered_path)
        if len(ordered) < 2:
            skipped_entries.append(
                ReconstructionReturnSkipEntry(
                    source_block=src_serial,
                    reason="path_too_short",
                )
            )
            continue

        source_node = node_by_key.get(edge.source_key)
        node_shared_suffix: set[int] = set()
        if source_node is not None:
            node_shared_suffix = {int(block) for block in source_node.shared_suffix_blocks}

        suffix_entry_serial: int | None = None
        anchor_serial: int | None = None
        terminal = ordered[-1]
        ordered_set = set(ordered)
        corridor_candidates = sorted(block for block in common_return_corridor if block != terminal)
        if not corridor_candidates:
            # The per-node ``shared_suffix_blocks`` fallback includes EVERY block
            # downstream of the handler -- both the return path AND the handler's
            # forward/transition continuation (e.g. block 18's byte-copy arm
            # blocks 19,20,197,201).  A return corridor must lie on the return's
            # OWN path; restricting the candidates to ``ordered`` prevents picking
            # a forward-continuation block (blk19) as the "return entry" and then
            # redirecting the already-correct return arm (208) onto it, which
            # degenerates the successor set (INTERR 50860).  A direct return
            # (``ordered == (anchor, terminal)``) yields no candidates -> the
            # fallback below correctly sees the arm already reaches the terminal
            # and emits nothing.
            corridor_candidates = sorted(
                block
                for block in node_shared_suffix
                if block != terminal
                and block not in condition_chain_set
                and block in ordered_set
            )
        if corridor_candidates:
            suffix_entry_serial = corridor_candidates[0]
        anchor_serial = src_serial

        if suffix_entry_serial is None:
            fallback_emitted = False
            for hop_idx in range(len(ordered) - 1):
                from_serial = ordered[hop_idx]
                expected_next = ordered[hop_idx + 1]
                if from_serial in condition_chain_set or from_serial in claimed_sources:
                    continue
                from_block = flow_graph.get_block(from_serial)
                if from_block is None:
                    continue
                if from_block.nsucc == 1:
                    old_target = int(from_block.succs[0])
                    if old_target == expected_next:
                        continue
                    if _is_terminal_stop(flow_graph, old_target):
                        log_entries.append(
                            ReconstructionReturnLogEntry(
                                source_block=from_serial,
                                branch_arm=None,
                                target_block=old_target,
                                tag="terminal_stop_preserved",
                            )
                        )
                        fallback_emitted = True
                        break
                    return_mods.append(
                        builder.goto_redirect(
                            source_block=from_serial,
                            target_block=expected_next,
                            old_target=old_target,
                        )
                    )
                    claimed_sources.add(from_serial)
                    log_entries.append(
                        ReconstructionReturnLogEntry(
                            source_block=from_serial,
                            branch_arm=None,
                            target_block=expected_next,
                            tag="fallback_1way",
                        )
                    )
                    fallback_emitted = True
                    break
                if from_block.nsucc == 2:
                    check_arms = (
                        [src_arm]
                        if from_serial == src_serial and src_arm is not None
                        else [0, 1]
                    )
                    for arm in check_arms:
                        if arm >= from_block.nsucc:
                            continue
                        arm_target = int(from_block.succs[arm])
                        if arm_target == expected_next:
                            fallback_emitted = True
                            break
                        if _is_terminal_stop(flow_graph, arm_target):
                            log_entries.append(
                                ReconstructionReturnLogEntry(
                                    source_block=from_serial,
                                    branch_arm=arm,
                                    target_block=arm_target,
                                    tag="terminal_stop_preserved",
                                )
                            )
                            fallback_emitted = True
                            break
                        return_mods.append(
                            builder.edge_redirect(
                                source_block=from_serial,
                                target_block=expected_next,
                                old_target=arm_target,
                            )
                        )
                        claimed_sources.add(from_serial)
                        log_entries.append(
                            ReconstructionReturnLogEntry(
                                source_block=from_serial,
                                branch_arm=arm,
                                target_block=expected_next,
                                tag="fallback_2way",
                            )
                        )
                        fallback_emitted = True
                        break
                    if fallback_emitted:
                        break
            if not fallback_emitted:
                skipped_entries.append(
                    ReconstructionReturnSkipEntry(
                        source_block=src_serial,
                        reason="no_suffix_fallback_exhausted",
                    )
                )
            continue

        if anchor_serial in condition_chain_set:
            skipped_entries.append(
                ReconstructionReturnSkipEntry(
                    source_block=int(anchor_serial),
                    reason="anchor_in_condition_chain",
                )
            )
            continue
        if anchor_serial in claimed_sources:
            skipped_entries.append(
                ReconstructionReturnSkipEntry(
                    source_block=int(anchor_serial),
                    reason="anchor_claimed",
                )
            )
            continue

        anchor_block = flow_graph.get_block(anchor_serial)
        if anchor_block is None:
            skipped_entries.append(
                ReconstructionReturnSkipEntry(
                    source_block=int(anchor_serial),
                    reason="anchor_block_not_found",
                )
            )
            continue

        if anchor_block.nsucc == 1:
            old_target = int(anchor_block.succs[0])
            if old_target == suffix_entry_serial:
                continue
            if _is_terminal_stop(flow_graph, old_target):
                log_entries.append(
                    ReconstructionReturnLogEntry(
                        source_block=anchor_serial,
                        branch_arm=None,
                        target_block=old_target,
                        tag="terminal_stop_preserved",
                    )
                )
                continue
            return_mods.append(
                builder.goto_redirect(
                    source_block=anchor_serial,
                    target_block=suffix_entry_serial,
                    old_target=old_target,
                )
            )
            claimed_sources.add(anchor_serial)
            log_entries.append(
                ReconstructionReturnLogEntry(
                    source_block=anchor_serial,
                    branch_arm=None,
                    target_block=suffix_entry_serial,
                    tag="wire_1way",
                    bypass_block=old_target,
                )
            )
            continue

        if anchor_block.nsucc == 2:
            check_arms = (
                [src_arm]
                if anchor_serial == src_serial and src_arm is not None
                else [0, 1]
            )
            terminal_arm: int | None = None
            terminal_target: int | None = None
            for arm in check_arms:
                if arm >= anchor_block.nsucc:
                    continue
                arm_target = int(anchor_block.succs[arm])
                if _is_terminal_stop(flow_graph, arm_target):
                    terminal_arm = arm
                    terminal_target = arm_target
                    break
            if terminal_arm is not None and terminal_target is not None:
                log_entries.append(
                    ReconstructionReturnLogEntry(
                        source_block=anchor_serial,
                        branch_arm=terminal_arm,
                        target_block=terminal_target,
                        tag="terminal_stop_preserved",
                    )
                )
                continue
            wired = False
            for arm in check_arms:
                if arm >= anchor_block.nsucc:
                    continue
                arm_target = int(anchor_block.succs[arm])
                if arm_target == suffix_entry_serial:
                    wired = True
                    break
                if arm == 0:
                    artifact_blk = flow_graph.get_block(arm_target)
                    if (
                        artifact_blk is not None
                        and artifact_blk.nsucc == 1
                        and arm_target in artifact_return_blocks
                        and arm_target not in claimed_sources
                    ):
                        suffix_idx = _path_position(ordered, suffix_entry_serial)
                        artifact_idx = _path_position(ordered, arm_target)
                        if (
                            suffix_idx is None
                            or artifact_idx is None
                            or suffix_idx <= artifact_idx
                        ):
                            skipped_entries.append(
                                ReconstructionReturnSkipEntry(
                                    source_block=arm_target,
                                    reason="artifact_suffix_not_forward",
                                )
                            )
                            wired = True
                            break
                        artifact_old = int(artifact_blk.succs[0])
                        return_mods.append(
                            builder.goto_redirect(
                                source_block=arm_target,
                                target_block=suffix_entry_serial,
                                old_target=artifact_old,
                            )
                        )
                        claimed_sources.add(arm_target)
                        log_entries.append(
                            ReconstructionReturnLogEntry(
                                source_block=arm_target,
                                branch_arm=None,
                                target_block=suffix_entry_serial,
                                tag="redirect_artifact",
                            )
                        )
                        wired = True
                        break
                    wired = True
                    break
                return_mods.append(
                    builder.edge_redirect(
                        source_block=anchor_serial,
                        target_block=suffix_entry_serial,
                        old_target=arm_target,
                    )
                )
                claimed_sources.add(anchor_serial)
                log_entries.append(
                    ReconstructionReturnLogEntry(
                        source_block=anchor_serial,
                        branch_arm=arm,
                        target_block=suffix_entry_serial,
                        tag="wire_2way",
                        bypass_block=arm_target,
                    )
                )
                wired = True
                break
            if not wired:
                skipped_entries.append(
                    ReconstructionReturnSkipEntry(
                        source_block=int(anchor_serial),
                        reason="no_eligible_arm",
                    )
                )
            continue

        skipped_entries.append(
            ReconstructionReturnSkipEntry(
                source_block=int(anchor_serial),
                reason=f"unexpected_nsucc_{anchor_block.nsucc}",
            )
        )

    return ReconstructionReturnPlanResult(
        modifications=tuple(return_mods),
        log_entries=tuple(log_entries),
        skipped_entries=tuple(skipped_entries),
        claimed_sources=frozenset(int(serial) for serial in claimed_sources),
    )


__all__ = [
    "ReconstructionReturnLogEntry",
    "ReconstructionReturnPlanResult",
    "ReconstructionReturnSkipEntry",
    "plan_reconstruction_return_modifications",
]
