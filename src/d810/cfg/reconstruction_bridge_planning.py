from __future__ import annotations

from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.cfg.block_identity import (
    block_label,
    edge_label,
    flow_graph_context_label,
)
from d810.cfg.reconstruction_redirect_log import log_redirect_attempt
from d810.cfg.lowering_selector import (
    SharedFeederContext,
    SharedFeederLoweringKind,
    select_shared_feeder_lowering,
    target_reaches_source_ignoring_blocks,
)
from d810.cfg.mod_claims import collect_mod_claims

logger = getLogger(__name__)


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


@dataclass(frozen=True, slots=True)
class ReconstructionFeederLogEntry:
    source_block: int
    branch_arm: int | None
    target_block: int
    tag: str
    source_pred_count: int | None = None
    via_pred: int | None = None


@dataclass(frozen=True, slots=True)
class ReconstructionFeederPlanResult:
    modifications: tuple[object, ...]
    log_entries: tuple[ReconstructionFeederLogEntry, ...]
    claimed_sources: frozenset[int]
    claimed_targets: frozenset[int]


@dataclass(frozen=True, slots=True)
class ReconstructionFixpointFeederLogEntry:
    source_block: int
    target_block: int
    state_value: int


@dataclass(frozen=True, slots=True)
class ReconstructionFixpointFeederPlanResult:
    modifications: tuple[object, ...]
    log_entries: tuple[ReconstructionFixpointFeederLogEntry, ...]
    claimed_sources: frozenset[int]


def _edge_kind_name(edge) -> str:
    return getattr(getattr(edge, "kind", None), "name", str(getattr(edge, "kind", None)))


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

    log_redirect_attempt(
        phase="preheader_bridge",
        src=int(dag.pre_header_serial),
        old_target=int(old_target),
        new_target=int(resolved),
        dag=dag,
        state_const=int(dag.initial_state) if dag.initial_state is not None else None,
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
    redirect_veto=None,
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
                edge_state = getattr(
                    getattr(edge, "source_key", None), "state_const", None
                )
                log_redirect_attempt(
                    phase="dag_bridge",
                    src=int(exit_block),
                    old_target=int(old_target),
                    new_target=int(target_entry),
                    dag=dag,
                    state_const=edge_state,
                )
                modification = builder.goto_redirect(
                    source_block=exit_block,
                    target_block=target_entry,
                    old_target=old_target,
                )
                veto_reason = None
                if callable(redirect_veto):
                    try:
                        veto_reason = redirect_veto(
                            modification=modification,
                            source_block=int(exit_block),
                            old_target=int(old_target),
                            target_block=int(target_entry),
                            state_value=int(edge_state),
                        )
                    except Exception:
                        logger.debug(
                            "RECON BRIDGE: redirect veto callback raised"
                            " for %s state=0x%08X %s",
                            edge_label(flow_graph, int(exit_block), int(target_entry)),
                            int(edge_state) & 0xFFFFFFFF,
                            flow_graph_context_label(flow_graph),
                            exc_info=True,
                        )
                        veto_reason = None
                if veto_reason:
                    logger.warning(
                        "RECON BRIDGE: redirect vetoed %s old=%s state=0x%08X"
                        " reason=%s %s",
                        edge_label(flow_graph, int(exit_block), int(target_entry)),
                        block_label(flow_graph, int(old_target)),
                        int(edge_state) & 0xFFFFFFFF,
                        veto_reason,
                        flow_graph_context_label(flow_graph),
                    )
                    continue
                bridge_mods.append(modification)
                claimed_targets.add(target_entry)
                claimed_sources.add(exit_block)
                tag = (
                    "empty-path direct wire"
                    if not edge.ordered_path
                    else "1-way"
                )
                log_entries.append(
                    ReconstructionBridgeLogEntry(
                        source_block=exit_block,
                        branch_arm=None,
                        target_block=target_entry,
                        tag=tag,
                    )
                )
        elif block.nsucc == 2:
            for arm in range(2):
                arm_target = int(block.succs[arm])
                if arm_target == dispatcher_serial or arm_target in bst_set:
                    if arm == 1:
                        edge_state = getattr(
                            getattr(edge, "source_key", None), "state_const", None
                        )
                        log_redirect_attempt(
                            phase="dag_bridge",
                            src=int(exit_block),
                            old_target=int(arm_target),
                            new_target=int(target_entry),
                            dag=dag,
                            state_const=edge_state,
                        )
                        modification = builder.edge_redirect(
                            source_block=exit_block,
                            target_block=target_entry,
                            old_target=arm_target,
                        )
                        veto_reason = None
                        if callable(redirect_veto):
                            try:
                                veto_reason = redirect_veto(
                                    modification=modification,
                                    source_block=int(exit_block),
                                    old_target=int(arm_target),
                                    target_block=int(target_entry),
                                    state_value=int(edge_state),
                                )
                            except Exception:
                                logger.debug(
                                    "RECON BRIDGE: redirect veto callback raised"
                                    " for %s state=0x%08X %s",
                                    edge_label(flow_graph, int(exit_block), int(target_entry)),
                                    int(edge_state) & 0xFFFFFFFF,
                                    flow_graph_context_label(flow_graph),
                                    exc_info=True,
                                )
                                veto_reason = None
                        if veto_reason:
                            logger.warning(
                                "RECON BRIDGE: redirect vetoed %s old=%s state=0x%08X"
                                " reason=%s %s",
                                edge_label(flow_graph, int(exit_block), int(target_entry)),
                                block_label(flow_graph, int(arm_target)),
                                int(edge_state) & 0xFFFFFFFF,
                                veto_reason,
                                flow_graph_context_label(flow_graph),
                            )
                            continue
                        bridge_mods.append(modification)
                        claimed_targets.add(target_entry)
                        claimed_sources.add(exit_block)
                        tag = (
                            "empty-path direct wire"
                            if not edge.ordered_path
                            else "2-way"
                        )
                        log_entries.append(
                            ReconstructionBridgeLogEntry(
                                source_block=exit_block,
                                branch_arm=arm,
                                target_block=target_entry,
                                tag=tag,
                            )
                        )
                    break

    return ReconstructionBridgePlanResult(
        modifications=tuple(bridge_mods),
        log_entries=tuple(log_entries),
        claimed_sources=frozenset(int(serial) for serial in claimed_sources),
        claimed_targets=frozenset(int(serial) for serial in claimed_targets),
    )


def plan_reconstruction_feeder_modifications(
    *,
    dag,
    flow_graph,
    projected_flow_graph,
    builder,
    dispatcher_serial: int,
    bst_node_blocks: set[int],
    claimed_sources: set[int],
    claimed_targets: set[int],
    suppressed_bridge_pairs: set[tuple[int, int]],
) -> ReconstructionFeederPlanResult:
    feeder_mods: list = []
    log_entries: list[ReconstructionFeederLogEntry] = []
    bst_set = {int(dispatcher_serial)}
    bst_set.update(int(block) for block in bst_node_blocks)

    for edge in dag.edges:
        if edge.target_entry_anchor is None:
            continue
        edge_kind_name = _edge_kind_name(edge)
        if edge_kind_name not in {"TRANSITION", "CONDITIONAL_TRANSITION", "UNKNOWN"}:
            continue
        target_entry = int(edge.target_entry_anchor)
        if target_entry in bst_set:
            continue

        src_serial = int(edge.source_anchor.block_serial)
        if src_serial in claimed_sources:
            continue
        if (src_serial, target_entry) in suppressed_bridge_pairs:
            continue

        src_block = flow_graph.get_block(src_serial)
        if src_block is None:
            continue

        has_dispatcher_succ = any(
            int(src_block.succs[arm]) == dispatcher_serial
            or int(src_block.succs[arm]) in bst_set
            for arm in range(src_block.nsucc)
        )
        if not has_dispatcher_succ:
            continue

        if src_block.nsucc == 1:
            old_target = int(src_block.succs[0])
            if old_target != dispatcher_serial and old_target not in bst_set:
                continue

            feeder_tag = "UNKNOWN 1-way" if edge_kind_name == "UNKNOWN" else "1-way"
            proj_src = projected_flow_graph.get_block(src_serial)
            src_npred = len(proj_src.preds) if proj_src is not None else 0
            feeder_context = SharedFeederContext(
                source_serial=src_serial,
                source_pred_count=src_npred,
                ordered_path=tuple(int(node) for node in (edge.ordered_path or ())),
                via_pred_succs=(),
                target_entry=target_entry,
                dispatcher_serial=dispatcher_serial,
                bst_node_blocks=frozenset(bst_set),
                target_reaches_pred=False,
            )
            edge_pred = feeder_context.via_pred
            pred_succs: tuple[int, ...] = ()
            if edge_pred is not None:
                pred_block = projected_flow_graph.get_block(edge_pred)
                if pred_block is not None:
                    pred_succs = tuple(int(succ) for succ in getattr(pred_block, "succs", ()))
            target_reaches_pred = (
                target_reaches_source_ignoring_blocks(
                    projected_flow_graph,
                    target_entry=target_entry,
                    source_block=edge_pred,
                    ignored_blocks=bst_set | {dispatcher_serial, src_serial},
                )
                if edge_pred is not None
                else False
            )
            lowering = select_shared_feeder_lowering(
                SharedFeederContext(
                    source_serial=feeder_context.source_serial,
                    source_pred_count=feeder_context.source_pred_count,
                    ordered_path=feeder_context.ordered_path,
                    via_pred_succs=pred_succs,
                    target_entry=feeder_context.target_entry,
                    dispatcher_serial=feeder_context.dispatcher_serial,
                    bst_node_blocks=feeder_context.bst_node_blocks,
                    target_reaches_pred=target_reaches_pred,
                )
            )
            if not lowering.accepted:
                continue
            if lowering.kind == SharedFeederLoweringKind.PRED_SCOPED_CLONE:
                logger.info(
                    "RECON BRIDGE: abstaining from pred-scoped clone without "
                    "corridor/replay proof source=%d via_pred=%s target=%d",
                    src_serial,
                    "None" if lowering.via_pred is None else str(lowering.via_pred),
                    target_entry,
                )
                continue
            elif (
                lowering.kind == SharedFeederLoweringKind.PRED_EDGE_PEEL
                and lowering.via_pred is not None
            ):
                feeder_mods.append(
                    builder.edge_redirect(
                        source_block=lowering.via_pred,
                        target_block=target_entry,
                        old_target=src_serial,
                    )
                )
                feeder_tag += " pred-edge"
                claimed_sources.add(lowering.via_pred)
            else:
                feeder_mods.append(
                    builder.goto_redirect(
                        source_block=src_serial,
                        target_block=target_entry,
                        old_target=old_target,
                    )
                )
                claimed_sources.add(src_serial)
            claimed_targets.add(target_entry)
            log_entries.append(
                ReconstructionFeederLogEntry(
                    source_block=src_serial,
                    branch_arm=None,
                    target_block=target_entry,
                    tag=feeder_tag,
                    source_pred_count=src_npred,
                    via_pred=lowering.via_pred,
                )
            )
        elif src_block.nsucc == 2:
            for arm in range(2):
                arm_target = int(src_block.succs[arm])
                if arm_target == dispatcher_serial or arm_target in bst_set:
                    if arm == 1:
                        feeder_mods.append(
                            builder.edge_redirect(
                                source_block=src_serial,
                                target_block=target_entry,
                                old_target=arm_target,
                            )
                        )
                        claimed_sources.add(src_serial)
                        claimed_targets.add(target_entry)
                        log_entries.append(
                            ReconstructionFeederLogEntry(
                                source_block=src_serial,
                                branch_arm=arm,
                                target_block=target_entry,
                                tag=(
                                    "UNKNOWN 2-way"
                                    if edge_kind_name == "UNKNOWN"
                                    else "2-way"
                                ),
                            )
                        )
                    break

    return ReconstructionFeederPlanResult(
        modifications=tuple(feeder_mods),
        log_entries=tuple(log_entries),
        claimed_sources=frozenset(int(serial) for serial in claimed_sources),
        claimed_targets=frozenset(int(serial) for serial in claimed_targets),
    )


def plan_fixpoint_feeder_modifications(
    *,
    flow_graph,
    builder,
    dispatcher_serial: int,
    bst_node_blocks: set[int],
    claimed_sources: set[int],
    constant_result,
    state_var_stkoff: int | None,
    dispatcher,
    redirect_veto=None,
) -> ReconstructionFixpointFeederPlanResult:
    feeder_mods: list = []
    log_entries: list[ReconstructionFixpointFeederLogEntry] = []
    if (
        constant_result is None
        or state_var_stkoff is None
        or not hasattr(constant_result, "out_stk_maps")
        or dispatcher is None
    ):
        return ReconstructionFixpointFeederPlanResult(
            modifications=(),
            log_entries=(),
            claimed_sources=frozenset(int(serial) for serial in claimed_sources),
        )

    bst_set = {int(dispatcher_serial)}
    bst_set.update(int(block) for block in bst_node_blocks)
    for blk_serial in flow_graph.blocks:
        if blk_serial in claimed_sources:
            continue
        blk = flow_graph.get_block(blk_serial)
        if blk is None or blk.nsucc != 1:
            continue
        old_target = int(blk.succs[0])
        if old_target != dispatcher_serial and old_target not in bst_set:
            continue
        out_map = constant_result.out_stk_maps.get(blk_serial, {})
        state_val = out_map.get(state_var_stkoff)
        if state_val is None:
            continue
        resolved = dispatcher.lookup(state_val)
        if resolved is None or int(resolved) in bst_set:
            continue
        modification = builder.goto_redirect(
            source_block=blk_serial,
            target_block=int(resolved),
            old_target=old_target,
        )
        veto_reason = None
        if callable(redirect_veto):
            try:
                veto_reason = redirect_veto(
                    modification=modification,
                    source_block=int(blk_serial),
                    old_target=int(old_target),
                    target_block=int(resolved),
                    state_value=int(state_val),
                )
            except Exception:
                logger.debug(
                    "RECON FIXPOINT FEEDER: redirect veto callback raised"
                    " for %s state=0x%08X %s",
                    edge_label(flow_graph, int(blk_serial), int(resolved)),
                    int(state_val) & 0xFFFFFFFF,
                    flow_graph_context_label(flow_graph),
                    exc_info=True,
                )
                veto_reason = None
        if veto_reason:
            logger.warning(
                "RECON FIXPOINT FEEDER: redirect vetoed %s old=%s state=0x%08X"
                " reason=%s %s",
                edge_label(flow_graph, int(blk_serial), int(resolved)),
                block_label(flow_graph, int(old_target)),
                int(state_val) & 0xFFFFFFFF,
                veto_reason,
                flow_graph_context_label(flow_graph),
            )
            continue
        feeder_mods.append(modification)
        claimed_sources.add(int(blk_serial))
        log_entries.append(
            ReconstructionFixpointFeederLogEntry(
                source_block=int(blk_serial),
                target_block=int(resolved),
                state_value=int(state_val),
            )
        )

    return ReconstructionFixpointFeederPlanResult(
        modifications=tuple(feeder_mods),
        log_entries=tuple(log_entries),
        claimed_sources=frozenset(int(serial) for serial in claimed_sources),
    )


__all__ = [
    "ReconstructionBridgeLogEntry",
    "ReconstructionBridgePlanResult",
    "ReconstructionFeederLogEntry",
    "ReconstructionFeederPlanResult",
    "ReconstructionFixpointFeederLogEntry",
    "ReconstructionFixpointFeederPlanResult",
    "ReconstructionPreheaderBridgeResult",
    "collect_reconstruction_claims",
    "collect_suppressed_bridge_pairs",
    "plan_fixpoint_feeder_modifications",
    "plan_reconstruction_bridge_modifications",
    "plan_reconstruction_feeder_modifications",
    "plan_reconstruction_preheader_bridge",
]
