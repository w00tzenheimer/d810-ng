"""Simulate CFG edits on an adjacency list without mutating the MBA.

The pure adjacency-graph simulation core (``SimulatedEdit``,
``SimulationResult``, ``simulate_edits``) lives in
:mod:`d810.analyses.control_flow.edit_simulation` (dissolution A0 split,
llr-lyly) so read-only verifiers can consume it without an upward
``analyses -> transforms`` import.  This module re-exports those names and
adds the PatchPlan-coupled glue (``project_post_state``,
``patch_plan_to_simulated_edits``, ``graph_modifications_to_simulated_edits``,
``project_cumulative_state``) on top.
"""

from __future__ import annotations

from d810.analyses.control_flow.edit_simulation import (
    SimulatedEdit,
    SimulationResult,
    simulate_edits,
)
from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind
from d810.transforms.graph_modification import (
    CloneConditionalAsGoto,
    CloneConditionalAsGotoFromBranchArm,
    ConvertToGoto,
    CreateConditionalRedirect,
    DirectTerminalLoweringKind,
    DuplicateBlock,
    EdgeRedirectViaPredSplit,
    GraphModification,
    InsertBlock,
    RedirectBranch,
    RedirectGoto,
    RemoveEdge,
)
from d810.transforms.plan import (
    LegacyBlockOperation,
    PatchCloneConditionalAsGoto,
    PatchCloneConditionalAsGotoFromBranchArm,
    PatchConditionalRedirect,
    PatchConvertToGoto,
    PatchDuplicateBlock,
    PatchDirectTerminalLoweringGroup,
    PatchEdgeSplitCorridor,
    PatchEdgeSplitTrampoline,
    PatchInsertBlock,
    PatchPlan,
    PatchPrivateTerminalSuffix,
    PatchPrivateTerminalSuffixGroup,
    PatchRedirectBranch,
    PatchRedirectGoto,
    PatchRemoveEdge,
    PatchReorderBlocks,
)
from d810.core.logging import getLogger

logger = getLogger(__name__)


def _reorder_trampoline_serials(patch_plan: PatchPlan) -> frozenset[int]:
    """Return the set of old block serials that become trampolines in a ReorderBlocks step."""
    for step in patch_plan.steps:
        match step:
            case PatchReorderBlocks(old_to_new=old_to_new_pairs):
                return frozenset(old for old, _new in old_to_new_pairs)
    return frozenset()


def _tail_opcode_for_existing_block(
    block: BlockSnapshot,
    patch_plan: PatchPlan,
    succs: tuple[int, ...],
) -> InsnKind | None:
    tail_kind = block.tail_kind
    for step in patch_plan.steps:
        match step:
            case PatchConvertToGoto(block_serial=serial) if serial == block.serial:
                tail_kind = InsnKind.GOTO
                break
            case PatchRedirectGoto(from_serial=serial) if (
                serial == block.serial
                and (block.kind == BlockKind.ONE_WAY or block.nsucc == 1)
            ):
                tail_kind = InsnKind.GOTO
                break
            case PatchPrivateTerminalSuffixGroup(anchors=anchors) if (
                block.serial in anchors
            ):
                tail_kind = InsnKind.GOTO
                break
            case PatchDirectTerminalLoweringGroup(sites=sites) if any(
                int(site.anchor_serial) == int(block.serial) for site in sites
            ):
                tail_kind = InsnKind.GOTO
                break
            case PatchRedirectBranch(from_serial=serial) if serial == block.serial:
                tail_kind = block.tail_kind  # successor changes, not opcode
                break
            case PatchReorderBlocks(old_to_new=old_to_new_pairs):
                trampoline_serials = frozenset(old for old, _new in old_to_new_pairs)
                if block.serial in trampoline_serials:
                    tail_kind = InsnKind.GOTO
                    break

    if len(succs) == 1 and tail_kind in {
        None,
        InsnKind.COND_JUMP,
        InsnKind.EQUALITY_JUMP,
    }:
        return InsnKind.GOTO
    if len(succs) == 0 and tail_kind in {
        InsnKind.GOTO,
        InsnKind.COND_JUMP,
        InsnKind.EQUALITY_JUMP,
    }:
        return InsnKind.NOP
    return tail_kind


def _block_kind_for_projected_shape(
    *,
    template_block: BlockSnapshot | None,
    kind: str,
    succs: tuple[int, ...],
    tail_kind: InsnKind | None,
) -> BlockKind:
    if (
        kind in {"conditional_redirect_clone", "duplicate_block_clone"}
        and len(succs) == 2
    ):
        return BlockKind.TWO_WAY
    if kind.endswith("fallthrough") or kind in {
        "clone_conditional_as_goto",
        "direct_terminal_lowering_clone",
        "edge_split_corridor_clone",
        "edge_split_trampoline",
        "insert_block",
    }:
        if len(succs) >= 2:
            return BlockKind.TWO_WAY
        if len(succs) == 1:
            return BlockKind.ONE_WAY
        return BlockKind.ZERO_WAY
    # 2WAY trampoline is always BLT_1WAY (single m_goto to fallthrough target)
    if kind == "reorder_block_2way_trampoline":
        return BlockKind.ONE_WAY
    if tail_kind in {InsnKind.COND_JUMP, InsnKind.EQUALITY_JUMP} and len(succs) == 2:
        return BlockKind.TWO_WAY
    if len(succs) == 1:
        return BlockKind.ONE_WAY
    if len(succs) == 0:
        return BlockKind.ZERO_WAY
    if len(succs) > 2:
        return BlockKind.N_WAY
    if template_block is not None and template_block.kind is not BlockKind.UNKNOWN:
        return template_block.kind
    return BlockKind.NONE


def _tail_kind_for_projected_block(
    *,
    kind: str,
    template_block: BlockSnapshot | None,
    instructions,
    succs: tuple[int, ...],
) -> InsnKind | None:
    if instructions:
        return instructions[-1].kind
    if (
        kind in {"conditional_redirect_clone", "duplicate_block_clone"}
        and len(succs) == 2
    ):
        if template_block is not None and template_block.tail_kind is not None:
            return template_block.tail_kind
        return InsnKind.COND_JUMP
    if kind.endswith("fallthrough") or kind in {
        "clone_conditional_as_goto",
        "direct_terminal_lowering_clone",
        "edge_split_corridor_clone",
        "edge_split_trampoline",
        "insert_block",
    }:
        return InsnKind.GOTO if succs else InsnKind.NOP
    # 2WAY trampoline is always a single m_goto
    if kind == "reorder_block_2way_trampoline":
        return InsnKind.GOTO
    if template_block is not None:
        return template_block.tail_kind
    return InsnKind.GOTO if succs else InsnKind.NOP


def _build_pred_map(adj: dict[int, list[int]]) -> dict[int, tuple[int, ...]]:
    preds: dict[int, list[int]] = {serial: [] for serial in adj}
    for serial, succs in adj.items():
        for succ in succs:
            if succ in preds:
                preds[succ].append(serial)
    return {serial: tuple(pred_list) for serial, pred_list in preds.items()}


def _convert_to_goto_serials(patch_plan: PatchPlan) -> frozenset[int]:
    """Return the set of block serials targeted by PatchConvertToGoto steps."""
    serials: set[int] = set()
    for step in patch_plan.steps:
        match step:
            case PatchConvertToGoto(block_serial=serial):
                serials.add(serial)
    return frozenset(serials)


def _project_existing_blocks(
    pre_cfg: FlowGraph,
    patch_plan: PatchPlan,
    adj: dict[int, list[int]],
) -> dict[int, BlockSnapshot]:
    projected: dict[int, BlockSnapshot] = {}
    trampoline_serials = _reorder_trampoline_serials(patch_plan)
    goto_converted_serials = _convert_to_goto_serials(patch_plan)
    for block in pre_cfg.blocks.values():
        projected_serial = patch_plan.relocation_map.rewrite_serial(block.serial)
        succs = tuple(adj.get(projected_serial, ()))
        tail_kind = _tail_opcode_for_existing_block(block, patch_plan, succs)
        block_kind = _block_kind_for_projected_shape(
            template_block=None,
            kind=(
                "reorder_block_2way_trampoline"
                if block.serial in trampoline_serials
                else "convert_to_goto"
                if block.serial in goto_converted_serials
                else "existing_block"
            ),
            succs=succs,
            tail_kind=tail_kind,
        )
        projected[projected_serial] = BlockSnapshot(
            serial=projected_serial,
            block_type=block.block_type,
            succs=succs,
            preds=(),
            flags=int(block.flags),
            start_ea=int(block.start_ea),
            insn_snapshots=tuple(block.insn_snapshots),
            tail_opcode=block.tail_opcode,
            kind=block_kind,
            tail_kind=tail_kind,
            raw_block_type=block.raw_block_type,
            raw_tail_opcode=block.raw_tail_opcode,
        )
    return projected


def _project_created_blocks(
    pre_cfg: FlowGraph,
    patch_plan: PatchPlan,
    adj: dict[int, list[int]],
) -> dict[int, BlockSnapshot]:
    projected: dict[int, BlockSnapshot] = {}
    for spec in patch_plan.new_blocks:
        assigned_serial = patch_plan.relocation_map.assigned_serial_for(spec.block_id)
        if assigned_serial is None:
            continue
        succs = tuple(adj.get(assigned_serial, ()))
        if not succs and spec.kind.startswith("reorder_block_2way"):
            logger.warning(
                "DIAG _project_created_blocks: %s (kind=%s template=%s) assigned_serial=%d has empty succs! adj_keys_near=%s",
                spec.block_id,
                spec.kind,
                spec.template_block,
                assigned_serial,
                sorted([k for k in adj if abs(k - assigned_serial) < 10]),
            )
        template_block = (
            pre_cfg.get_block(spec.template_block)
            if spec.template_block is not None
            else None
        )
        instructions = tuple(spec.instructions or ())
        tail_kind = _tail_kind_for_projected_block(
            kind=spec.kind,
            template_block=template_block,
            instructions=instructions,
            succs=succs,
        )
        block_kind = _block_kind_for_projected_shape(
            template_block=template_block,
            kind=spec.kind,
            succs=succs,
            tail_kind=tail_kind,
        )
        projected[assigned_serial] = BlockSnapshot(
            serial=assigned_serial,
            block_type=int(getattr(template_block, "block_type", -1)),
            succs=succs,
            preds=(),
            flags=int(getattr(template_block, "flags", 0)),
            start_ea=int(getattr(template_block, "start_ea", pre_cfg.func_ea)),
            insn_snapshots=instructions
            or tuple(getattr(template_block, "insn_snapshots", ())),
            tail_opcode=getattr(template_block, "tail_opcode", None),
            kind=block_kind,
            tail_kind=tail_kind,
            raw_block_type=getattr(template_block, "raw_block_type", None),
            raw_tail_opcode=getattr(template_block, "raw_tail_opcode", None),
        )
    return projected


def project_post_state(pre_cfg: FlowGraph, patch_plan: PatchPlan) -> FlowGraph:
    """Project a PatchPlan onto a new FlowGraph without mutating live MBA state."""
    simulated = simulate_edits(
        pre_cfg.as_adjacency_dict(),
        patch_plan_to_simulated_edits(patch_plan),
    )
    # DIAGNOSTIC: Projected CFG adjacency dump
    if logger.debug_on:
        logger.debug("Projected CFG adjacency after %s:", type(patch_plan).__name__)
        for serial, succs in sorted(simulated.adj.items()):
            clone_marker = " [CLONE]" if serial in simulated.created_clones else ""
            logger.debug("  block %d -> %s%s", serial, succs, clone_marker)
    # DIAG: check if all new_blocks assigned serials are in simulated.adj
    for spec in patch_plan.new_blocks:
        assigned = patch_plan.relocation_map.assigned_serial_for(spec.block_id)
        if (
            assigned is not None
            and assigned not in simulated.adj
            and spec.kind.startswith("reorder_block")
        ):
            logger.warning(
                "DIAG project_post_state: %s (kind=%s) assigned=%d NOT in simulated.adj (adj_max=%d, adj_len=%d, created_clones=%s)",
                spec.block_id,
                spec.kind,
                assigned,
                max(simulated.adj.keys()) if simulated.adj else -1,
                len(simulated.adj),
                sorted(c for c in simulated.created_clones if abs(c - assigned) < 10)[
                    :5
                ],
            )
    projected_blocks = _project_existing_blocks(pre_cfg, patch_plan, simulated.adj)
    projected_blocks.update(_project_created_blocks(pre_cfg, patch_plan, simulated.adj))
    pred_map = _build_pred_map(simulated.adj)
    finalized_blocks = {
        serial: BlockSnapshot(
            serial=block.serial,
            block_type=block.block_type,
            succs=tuple(simulated.adj.get(serial, ())),
            preds=pred_map.get(serial, ()),
            flags=block.flags,
            start_ea=block.start_ea,
            insn_snapshots=block.insn_snapshots,
            tail_opcode=block.tail_opcode,
            kind=block.kind,
            tail_kind=block.tail_kind,
            raw_block_type=block.raw_block_type,
            raw_tail_opcode=block.raw_tail_opcode,
        )
        for serial, block in projected_blocks.items()
    }
    return FlowGraph(
        blocks=finalized_blocks,
        entry_serial=patch_plan.relocation_map.rewrite_serial(pre_cfg.entry_serial),
        func_ea=pre_cfg.func_ea,
        metadata={
            **dict(pre_cfg.metadata),
            "projected_from_patch_plan": True,
        },
    )


def project_cumulative_state(
    base_cfg: FlowGraph,
    patch_plan: PatchPlan,
) -> FlowGraph:
    """Project a PatchPlan onto an already-projected FlowGraph.

    Unlike :func:`project_post_state` which always projects from a fresh
    pre-MBA lift, this function accepts an arbitrary :class:`FlowGraph`
    (including one produced by a prior ``project_post_state`` or
    ``project_cumulative_state`` call) and applies the new plan on top.

    This enables cumulative validation: strategy N's projected contract
    check can run against the virtual CFG that includes strategies 1..N-1's
    modifications, catching cross-strategy serial conflicts before live
    mutation.

    Args:
        base_cfg: The current cumulative FlowGraph (may already be projected).
        patch_plan: The PatchPlan for the next strategy to validate.

    Returns:
        A new FlowGraph reflecting the cumulative post-state after applying
        *patch_plan* onto *base_cfg*.
    """
    return project_post_state(base_cfg, patch_plan)


def graph_modifications_to_simulated_edits(
    modifications: list[GraphModification],
) -> list[SimulatedEdit]:
    """Project GraphModification list to simulator-friendly edit ops."""
    simulated: list[SimulatedEdit] = []

    for mod in modifications:
        match mod:
            case RedirectGoto(from_serial=src, old_target=old, new_target=new):
                simulated.append(
                    SimulatedEdit(
                        kind="goto_redirect",
                        source=src,
                        old_target=old,
                        new_target=new,
                    )
                )

            case RedirectBranch(from_serial=src, old_target=old, new_target=new):
                simulated.append(
                    SimulatedEdit(
                        kind="conditional_redirect",
                        source=src,
                        old_target=old,
                        new_target=new,
                    )
                )

            case ConvertToGoto(block_serial=src, goto_target=new):
                simulated.append(
                    SimulatedEdit(
                        kind="convert_to_goto",
                        source=src,
                        old_target=-1,
                        new_target=new,
                    )
                )

            case EdgeRedirectViaPredSplit(
                src_block=src,
                old_target=old,
                new_target=new,
                via_pred=pred,
                clone_until=clone_until,
            ):
                simulated.append(
                    SimulatedEdit(
                        kind="edge_split_redirect",
                        source=src,
                        old_target=old,
                        new_target=new,
                        via_pred=pred,
                        clone_until=clone_until,
                    )
                )

            case CreateConditionalRedirect(
                source_block=src,
                ref_block=ref,
                conditional_target=conditional,
                fallthrough_target=fallthrough,
            ):
                simulated.append(
                    SimulatedEdit(
                        kind="create_conditional_redirect",
                        source=src,
                        old_target=-1,
                        new_target=conditional,
                        fallthrough_target=fallthrough,
                    )
                )

            case InsertBlock(
                pred_serial=pred,
                succ_serial=succ,
                old_target_serial=old_target,
            ):
                effective_old_target = succ if old_target is None else old_target
                simulated.append(
                    SimulatedEdit(
                        kind="insert_block",
                        source=pred,
                        old_target=effective_old_target,
                        new_target=succ,
                    )
                )

            case DuplicateBlock(
                source_block=src,
                target_block=target,
                pred_serial=pred,
                conditional_target=conditional_target,
                fallthrough_target=fallthrough_target,
            ):
                simulated.append(
                    SimulatedEdit(
                        kind="duplicate_block",
                        source=src,
                        old_target=-1,
                        new_target=target,
                        via_pred=pred,
                        duplicate_target=target,
                        conditional_target=conditional_target,
                        fallthrough_target=fallthrough_target,
                    )
                )

            case CloneConditionalAsGoto(
                source_block=src,
                pred_serial=pred,
                goto_target=target,
            ):
                simulated.append(
                    SimulatedEdit(
                        kind="clone_conditional_as_goto",
                        source=src,
                        old_target=src,
                        new_target=target,
                        via_pred=pred,
                    )
                )

            case CloneConditionalAsGotoFromBranchArm(
                source_block=src,
                pred_serial=pred,
                goto_target=target,
            ):
                simulated.append(
                    SimulatedEdit(
                        kind="clone_conditional_as_goto_from_branch_arm",
                        source=src,
                        old_target=src,
                        new_target=target,
                        via_pred=pred,
                    )
                )

            case RemoveEdge(from_serial=src, to_serial=dst):
                simulated.append(
                    SimulatedEdit(
                        kind="remove_edge",
                        source=src,
                        old_target=dst,
                        new_target=dst,
                    )
                )

            case _:
                # Nop/Duplicate have no topology effect in preflight.
                continue

    return simulated


def patch_plan_to_simulated_edits(patch_plan: PatchPlan) -> list[SimulatedEdit]:
    """Project PatchPlan steps to simulator-friendly edit ops."""
    simulated: list[SimulatedEdit] = []
    stop_serial_before = patch_plan.relocation_map.stop_serial_before
    stop_serial_after = patch_plan.relocation_map.stop_serial_after

    for step in patch_plan.steps:
        match step:
            case PatchRedirectGoto(from_serial=src, old_target=old, new_target=new):
                simulated.append(
                    SimulatedEdit(
                        kind="goto_redirect",
                        source=src,
                        old_target=old,
                        new_target=new,
                    )
                )

            case PatchRedirectBranch(from_serial=src, old_target=old, new_target=new):
                simulated.append(
                    SimulatedEdit(
                        kind="conditional_redirect",
                        source=src,
                        old_target=old,
                        new_target=new,
                    )
                )

            case PatchConvertToGoto(block_serial=src, goto_target=new):
                simulated.append(
                    SimulatedEdit(
                        kind="convert_to_goto",
                        source=src,
                        old_target=-1,
                        new_target=new,
                    )
                )

            case PatchRemoveEdge(from_serial=src, to_serial=dst):
                simulated.append(
                    SimulatedEdit(
                        kind="remove_edge",
                        source=src,
                        old_target=dst,
                        new_target=dst,
                    )
                )

            case PatchEdgeSplitTrampoline(
                source_serial=src,
                old_target=old,
                new_target=new,
                via_pred=pred,
                assigned_serial=assigned,
            ):
                simulated.append(
                    SimulatedEdit(
                        kind="edge_split_redirect",
                        source=src,
                        old_target=old,
                        new_target=new,
                        via_pred=pred,
                        created_serial=assigned,
                        stop_serial_before=stop_serial_before,
                        stop_serial_after=stop_serial_after,
                    )
                )

            case PatchEdgeSplitCorridor(
                source_serial=src,
                via_pred=pred,
                old_target=old,
                new_target=new,
                clone_assigned_serials=clone_serials,
                corridor_serials=corridor_serials,
                source_new_target=source_new_target,
            ):
                for idx, clone_serial in enumerate(clone_serials):
                    next_serial = (
                        clone_serials[idx + 1]
                        if idx < len(clone_serials) - 1
                        else new
                    )
                    simulated.append(
                        SimulatedEdit(
                            kind="edge_split_corridor_clone",
                            source=corridor_serials[idx],
                            old_target=-1,
                            new_target=next_serial,
                            created_serial=clone_serial,
                            stop_serial_before=stop_serial_before,
                            stop_serial_after=stop_serial_after,
                        )
                    )
                simulated.append(
                    SimulatedEdit(
                        kind="edge_split_corridor_anchor",
                        source=pred,
                        old_target=src,
                        new_target=clone_serials[0],
                    )
                )
                if source_new_target is not None:
                    simulated.append(
                        SimulatedEdit(
                            kind="edge_split_corridor_source_redirect",
                            source=src,
                            old_target=old,
                            new_target=source_new_target,
                        )
                    )

            case PatchConditionalRedirect(
                source_serial=src,
                ref_block=ref,
                conditional_target=conditional,
                fallthrough_target=fallthrough,
                assigned_serial=assigned,
                fallthrough_serial=fallthrough_serial,
            ):
                simulated.append(
                    SimulatedEdit(
                        kind="create_conditional_redirect",
                        source=src,
                        old_target=-1,
                        new_target=conditional,
                        fallthrough_target=fallthrough,
                        created_serial=assigned,
                        secondary_created_serial=fallthrough_serial,
                        stop_serial_before=stop_serial_before,
                        stop_serial_after=stop_serial_after,
                    )
                )

            case PatchInsertBlock(
                pred_serial=pred,
                succ_serial=succ,
                assigned_serial=assigned,
                old_target_serial=old_target,
            ):
                effective_old_target = succ if old_target is None else old_target
                simulated.append(
                    SimulatedEdit(
                        kind="insert_block",
                        source=pred,
                        old_target=effective_old_target,
                        new_target=succ,
                        created_serial=assigned,
                        stop_serial_before=stop_serial_before,
                        stop_serial_after=stop_serial_after,
                    )
                )

            case PatchDuplicateBlock(
                source_serial=src,
                pred_serial=pred,
                target_serial=target,
                source_successors=source_successors,
                conditional_target=conditional_target,
                fallthrough_target=fallthrough_target,
                assigned_serial=assigned,
                fallthrough_serial=fallthrough_serial,
            ):
                simulated.append(
                    SimulatedEdit(
                        kind="duplicate_block",
                        source=src,
                        old_target=-1,
                        new_target=target,
                        via_pred=pred,
                        duplicate_target=target,
                        source_successors=source_successors,
                        conditional_target=conditional_target,
                        fallthrough_target=fallthrough_target,
                        created_serial=assigned,
                        secondary_created_serial=fallthrough_serial,
                        stop_serial_before=stop_serial_before,
                        stop_serial_after=stop_serial_after,
                    )
                )

            case PatchCloneConditionalAsGoto(
                source_serial=src,
                pred_serial=pred,
                goto_target=target,
                assigned_serial=assigned,
            ):
                simulated.append(
                    SimulatedEdit(
                        kind="clone_conditional_as_goto",
                        source=src,
                        old_target=src,
                        new_target=target,
                        via_pred=pred,
                        created_serial=assigned,
                        stop_serial_before=stop_serial_before,
                        stop_serial_after=stop_serial_after,
                    )
                )

            case PatchCloneConditionalAsGotoFromBranchArm(
                source_serial=src,
                pred_serial=pred,
                goto_target=target,
                assigned_serial=assigned,
            ):
                simulated.append(
                    SimulatedEdit(
                        kind="clone_conditional_as_goto_from_branch_arm",
                        source=src,
                        old_target=src,
                        new_target=target,
                        via_pred=pred,
                        created_serial=assigned,
                        stop_serial_before=stop_serial_before,
                        stop_serial_after=stop_serial_after,
                    )
                )

            case PatchPrivateTerminalSuffix(
                anchor_serial=anchor,
                shared_entry_serial=shared_entry,
                suffix_serials=suffix,
                clone_assigned_serials=clone_serials,
            ):
                # Model as: create cloned chain, redirect anchor to first clone.
                # Each clone has one successor (next clone), except last (0 succs).
                for idx, clone_serial in enumerate(clone_serials):
                    if idx < len(clone_serials) - 1:
                        next_serial = clone_serials[idx + 1]
                    else:
                        next_serial = None
                    simulated.append(
                        SimulatedEdit(
                            kind="private_terminal_suffix_clone",
                            source=suffix[idx],
                            old_target=-1,
                            new_target=next_serial,
                            created_serial=clone_serial,
                            stop_serial_before=stop_serial_before,
                            stop_serial_after=stop_serial_after,
                        )
                    )
                # Redirect anchor from shared_entry to first clone.
                # Use dedicated kind so simulate_edits() fail-closes when
                # anchor no longer targets shared_entry (backend parity).
                simulated.append(
                    SimulatedEdit(
                        kind="private_terminal_suffix_anchor",
                        source=anchor,
                        old_target=shared_entry,
                        new_target=clone_serials[0],
                    )
                )

            case PatchPrivateTerminalSuffixGroup(
                shared_entry_serial=shared_entry,
                suffix_serials=suffix,
                anchors=anchors,
                per_anchor_clone_assigned_serials=per_anchor_serials,
            ):
                # Model as: for each anchor, create cloned chain + redirect.
                for anchor_idx, anchor in enumerate(anchors):
                    clone_serials = per_anchor_serials[anchor_idx]
                    for idx, clone_serial in enumerate(clone_serials):
                        if idx < len(clone_serials) - 1:
                            next_serial = clone_serials[idx + 1]
                        else:
                            next_serial = None
                        simulated.append(
                            SimulatedEdit(
                                kind="private_terminal_suffix_clone",
                                source=suffix[idx],
                                old_target=-1,
                                new_target=next_serial,
                                created_serial=clone_serial,
                                stop_serial_before=stop_serial_before,
                                stop_serial_after=stop_serial_after,
                            )
                        )
                    simulated.append(
                        SimulatedEdit(
                            kind="private_terminal_suffix_anchor",
                            source=anchor,
                            old_target=shared_entry,
                            new_target=clone_serials[0],
                        )
                    )

            case PatchDirectTerminalLoweringGroup(
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix,
                sites=sites,
                per_site_clone_assigned_serials=per_site_serials,
            ):
                for site in sites:
                    anchor = int(site.anchor_serial)
                    if site.kind is DirectTerminalLoweringKind.RETURN_CONST:
                        simulated.append(
                            SimulatedEdit(
                                kind="direct_terminal_lowering_anchor",
                                source=anchor,
                                old_target=shared_entry,
                                new_target=int(return_block),
                            )
                        )
                        continue
                    clone_serials = tuple(per_site_serials.get(anchor, ()))
                    if not clone_serials:
                        continue
                    clone_sources = tuple(int(serial) for serial in site.materializer_serials)
                    if not clone_sources:
                        clone_sources = tuple(int(serial) for serial in suffix[:-1])
                    for idx, clone_serial in enumerate(clone_serials):
                        if idx < len(clone_serials) - 1:
                            next_serial = clone_serials[idx + 1]
                        else:
                            next_serial = None
                        source = clone_sources[idx] if idx < len(clone_sources) else -1
                        simulated.append(
                            SimulatedEdit(
                                kind="direct_terminal_lowering_clone",
                                source=source,
                                old_target=-1,
                                new_target=next_serial,
                                created_serial=clone_serial,
                                stop_serial_before=stop_serial_before,
                                stop_serial_after=stop_serial_after,
                            )
                        )
                    simulated.append(
                        SimulatedEdit(
                            kind="direct_terminal_lowering_anchor",
                            source=anchor,
                            old_target=shared_entry,
                            new_target=clone_serials[0],
                        )
                    )

            case PatchReorderBlocks(
                old_to_new=old_to_new_pairs,
                two_way_serials=two_way,
                two_way_old_to_trampoline=two_way_trampoline_pairs,
            ):
                two_way_set = set(two_way)
                two_way_copy_map = {
                    old: new for old, new in old_to_new_pairs if old in two_way_set
                }
                two_way_trampoline_map = dict(two_way_trampoline_pairs)

                # Non-2WAY block copy edits
                for old_serial, new_serial in old_to_new_pairs:
                    if old_serial in two_way_set:
                        continue
                    simulated.append(
                        SimulatedEdit(
                            kind="reorder_block_copy",
                            source=old_serial,
                            old_target=old_serial,
                            new_target=None,
                            created_serial=new_serial,
                            stop_serial_before=stop_serial_before,
                            stop_serial_after=stop_serial_after,
                        )
                    )

                # 2WAY block copy + trampoline edits
                for old_serial in two_way:
                    copy_serial = two_way_copy_map.get(old_serial)
                    tramp_serial = two_way_trampoline_map.get(old_serial)
                    if copy_serial is None or tramp_serial is None:
                        continue
                    simulated.append(
                        SimulatedEdit(
                            kind="reorder_block_2way_copy",
                            source=old_serial,
                            old_target=old_serial,
                            new_target=None,
                            created_serial=copy_serial,
                            secondary_created_serial=tramp_serial,
                            stop_serial_before=stop_serial_before,
                            stop_serial_after=stop_serial_after,
                        )
                    )

                # Trampolines: all old blocks (1WAY and 2WAY) redirect to their copies
                for old_serial, new_serial in old_to_new_pairs:
                    simulated.append(
                        SimulatedEdit(
                            kind="reorder_block_trampoline",
                            source=old_serial,
                            old_target=-1,
                            new_target=new_serial,
                        )
                    )

                # Successor remap across all copies
                all_old_to_new = dict(old_to_new_pairs)
                if all_old_to_new:
                    flat = tuple(x for pair in all_old_to_new.items() for x in pair)
                    simulated.append(
                        SimulatedEdit(
                            kind="reorder_block_remap",
                            source=0,
                            old_target=0,
                            new_target=None,
                            source_successors=flat,
                        )
                    )

            case LegacyBlockOperation(
                modification=CreateConditionalRedirect(
                    source_block=src,
                    ref_block=ref,
                    conditional_target=conditional,
                    fallthrough_target=fallthrough,
                ),
                block_id=block_id,
            ):
                assigned = patch_plan.relocation_map.assigned_serial_for(block_id)
                simulated.append(
                    SimulatedEdit(
                        kind="create_conditional_redirect",
                        source=src,
                        old_target=-1,
                        new_target=patch_plan.relocation_map.rewrite_serial(
                            conditional
                        ),
                        fallthrough_target=patch_plan.relocation_map.rewrite_serial(
                            fallthrough
                        ),
                        created_serial=assigned,
                        stop_serial_before=stop_serial_before,
                        stop_serial_after=stop_serial_after,
                    )
                )

            case LegacyBlockOperation(
                modification=InsertBlock(
                    pred_serial=pred,
                    succ_serial=succ,
                    old_target_serial=old_target,
                ),
                block_id=block_id,
            ):
                assigned = patch_plan.relocation_map.assigned_serial_for(block_id)
                relocated_succ = patch_plan.relocation_map.rewrite_serial(succ)
                relocated_old_target = (
                    relocated_succ
                    if old_target is None
                    else patch_plan.relocation_map.rewrite_serial(old_target)
                )
                simulated.append(
                    SimulatedEdit(
                        kind="insert_block",
                        source=pred,
                        old_target=relocated_old_target,
                        new_target=relocated_succ,
                        created_serial=assigned,
                        stop_serial_before=stop_serial_before,
                        stop_serial_after=stop_serial_after,
                    )
                )

            case LegacyBlockOperation(modification=mod):
                simulated.extend(graph_modifications_to_simulated_edits([mod]))

            case _:
                continue

    return simulated
