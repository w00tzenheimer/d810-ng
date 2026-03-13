"""Simulate CFG edits on an adjacency list without mutating the MBA."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field

import ida_hexrays

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.cfg.graph_modification import (
    ConvertToGoto,
    CreateConditionalRedirect,
    EdgeRedirectViaPredSplit,
    GraphModification,
    InsertBlock,
    RedirectBranch,
    RedirectGoto,
    RemoveEdge,
)
from d810.cfg.plan import (
    LegacyBlockOperation,
    PatchConditionalRedirect,
    PatchConvertToGoto,
    PatchDuplicateBlock,
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

_BLT_NONE = int(getattr(ida_hexrays, "BLT_NONE", 0))
_BLT_STOP = int(getattr(ida_hexrays, "BLT_STOP", 1))
_BLT_0WAY = int(getattr(ida_hexrays, "BLT_0WAY", 2))
_BLT_1WAY = int(getattr(ida_hexrays, "BLT_1WAY", 3))
_BLT_2WAY = int(getattr(ida_hexrays, "BLT_2WAY", 4))
_M_NOP = int(getattr(ida_hexrays, "m_nop", 0))
_M_GOTO = int(getattr(ida_hexrays, "m_goto", 2))
_M_JCND = int(getattr(ida_hexrays, "m_jcnd", 3))


@dataclass
class SimulationResult:
    """Result of simulate_edits: adjacency dict plus metadata about created nodes.

    Attributes:
        adj: Post-edit adjacency dict (block serial -> successor serials).
        created_clones: Set of virtual clone node serials created by edge_split_redirect.
        clone_origins: Mapping of virtual clone node serial to the edit that created it.
    """

    adj: dict[int, list[int]]
    created_clones: set[int] = field(default_factory=set)
    clone_origins: dict[int, SimulatedEdit] = field(default_factory=dict)


@dataclass(frozen=True)
class SimulatedEdit:
    """Abstract edit operation on adjacency list.

    Attributes:
        kind: Type of edit - "goto_redirect", "conditional_redirect", or "convert_to_goto".
        source: Block serial of the source block.
        old_target: Block serial of the original target being replaced.
        new_target: Block serial of the new target.
    """

    kind: str  # "goto_redirect", "conditional_redirect", "convert_to_goto", "edge_split_redirect"
    source: int
    old_target: int
    new_target: int | None
    via_pred: int | None = None  # only for edge_split_redirect
    fallthrough_target: int | None = None  # only for create_conditional_redirect
    duplicate_target: int | None = None  # only for duplicate_block
    source_successors: tuple[int, ...] = ()  # only for duplicate_block
    conditional_target: int | None = None  # duplicate/create_conditional info
    created_serial: int | None = None  # finalized serial for symbolic block creation
    secondary_created_serial: int | None = None  # second block for multi-block creation
    stop_serial_before: int | None = None
    stop_serial_after: int | None = None


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
) -> int | None:
    for step in patch_plan.steps:
        match step:
            case PatchConvertToGoto(block_serial=serial) if serial == block.serial:
                return _M_GOTO
            case PatchRedirectGoto(from_serial=serial) if (
                serial == block.serial and int(block.block_type) == _BLT_1WAY
            ):
                return _M_GOTO
            case PatchPrivateTerminalSuffixGroup(anchors=anchors) if (
                block.serial in anchors
            ):
                return _M_GOTO
            case PatchRedirectBranch(from_serial=serial) if serial == block.serial:
                return (
                    block.tail_opcode
                )  # tail stays as m_jcnd — only successor changes, not opcode
            case PatchReorderBlocks(old_to_new=old_to_new_pairs):
                trampoline_serials = frozenset(old for old, _new in old_to_new_pairs)
                if block.serial in trampoline_serials:
                    return _M_GOTO
    return block.tail_opcode


def _block_type_for_projected_shape(
    *,
    template_block: BlockSnapshot | None,
    kind: str,
    succs: tuple[int, ...],
    tail_opcode: int | None,
) -> int:
    if (
        kind in {"conditional_redirect_clone", "duplicate_block_clone"}
        and len(succs) == 2
    ):
        return _BLT_2WAY
    if kind.endswith("fallthrough") or kind in {
        "edge_split_trampoline",
        "insert_block",
    }:
        if len(succs) >= 2:
            return _BLT_2WAY
        if len(succs) == 1:
            return _BLT_1WAY
        return _BLT_0WAY
    # 2WAY trampoline is always BLT_1WAY (single m_goto to fallthrough target)
    if kind == "reorder_block_2way_trampoline":
        return _BLT_1WAY
    if template_block is not None:
        return int(template_block.block_type)
    if tail_opcode == _M_JCND and len(succs) == 2:
        return _BLT_2WAY
    if len(succs) == 1:
        return _BLT_1WAY
    if len(succs) == 0:
        return _BLT_0WAY
    return _BLT_NONE


def _tail_opcode_for_projected_block(
    *,
    kind: str,
    template_block: BlockSnapshot | None,
    instructions,
    succs: tuple[int, ...],
) -> int | None:
    if instructions:
        return int(instructions[-1].opcode)
    if (
        kind in {"conditional_redirect_clone", "duplicate_block_clone"}
        and len(succs) == 2
    ):
        if template_block is not None and template_block.tail_opcode is not None:
            return int(template_block.tail_opcode)
        return _M_JCND
    if kind.endswith("fallthrough") or kind in {
        "edge_split_trampoline",
        "insert_block",
    }:
        return _M_GOTO if succs else _M_NOP
    # 2WAY trampoline is always a single m_goto
    if kind == "reorder_block_2way_trampoline":
        return _M_GOTO
    if template_block is not None:
        return template_block.tail_opcode
    return _M_GOTO if succs else _M_NOP


def _build_pred_map(adj: dict[int, list[int]]) -> dict[int, tuple[int, ...]]:
    preds: dict[int, list[int]] = {serial: [] for serial in adj}
    for serial, succs in adj.items():
        for succ in succs:
            if succ in preds:
                preds[succ].append(serial)
    return {serial: tuple(pred_list) for serial, pred_list in preds.items()}


def _project_existing_blocks(
    pre_cfg: FlowGraph,
    patch_plan: PatchPlan,
    adj: dict[int, list[int]],
) -> dict[int, BlockSnapshot]:
    projected: dict[int, BlockSnapshot] = {}
    trampoline_serials = _reorder_trampoline_serials(patch_plan)
    for block in pre_cfg.blocks.values():
        projected_serial = patch_plan.relocation_map.rewrite_serial(block.serial)
        # Blocks that become trampolines in ReorderBlocks are converted to BLT_1WAY
        if block.serial in trampoline_serials:
            block_type = _BLT_1WAY
        else:
            block_type = int(block.block_type)
        projected[projected_serial] = BlockSnapshot(
            serial=projected_serial,
            block_type=block_type,
            succs=tuple(adj.get(projected_serial, ())),
            preds=(),
            flags=int(block.flags),
            start_ea=int(block.start_ea),
            insn_snapshots=tuple(block.insn_snapshots),
            tail_opcode=_tail_opcode_for_existing_block(block, patch_plan),
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
        tail_opcode = _tail_opcode_for_projected_block(
            kind=spec.kind,
            template_block=template_block,
            instructions=instructions,
            succs=succs,
        )
        projected[assigned_serial] = BlockSnapshot(
            serial=assigned_serial,
            block_type=_block_type_for_projected_shape(
                template_block=template_block,
                kind=spec.kind,
                succs=succs,
                tail_opcode=tail_opcode,
            ),
            succs=succs,
            preds=(),
            flags=int(getattr(template_block, "flags", 0)),
            start_ea=int(getattr(template_block, "start_ea", pre_cfg.func_ea)),
            insn_snapshots=instructions
            or tuple(getattr(template_block, "insn_snapshots", ())),
            tail_opcode=tail_opcode,
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
            ):
                simulated.append(
                    SimulatedEdit(
                        kind="edge_split_redirect",
                        source=src,
                        old_target=old,
                        new_target=new,
                        via_pred=pred,
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
                        old_target=ref,
                        new_target=conditional,
                        fallthrough_target=fallthrough,
                    )
                )

            case InsertBlock(pred_serial=pred, succ_serial=succ):
                simulated.append(
                    SimulatedEdit(
                        kind="insert_block",
                        source=pred,
                        old_target=succ,
                        new_target=succ,
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
                        old_target=ref,
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
            ):
                simulated.append(
                    SimulatedEdit(
                        kind="insert_block",
                        source=pred,
                        old_target=succ,
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
                        old_target=patch_plan.relocation_map.rewrite_serial(ref),
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
                modification=InsertBlock(pred_serial=pred, succ_serial=succ),
                block_id=block_id,
            ):
                assigned = patch_plan.relocation_map.assigned_serial_for(block_id)
                relocated_succ = patch_plan.relocation_map.rewrite_serial(succ)
                simulated.append(
                    SimulatedEdit(
                        kind="insert_block",
                        source=pred,
                        old_target=relocated_succ,
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


def _apply_stop_relocation_once(
    result: dict[int, list[int]],
    *,
    stop_serial_before: int | None,
    stop_serial_after: int | None,
) -> None:
    if stop_serial_before is None or stop_serial_after is None:
        return
    if stop_serial_before not in result:
        return

    old_stop_succs = list(result.get(stop_serial_before, ()))
    for serial, succs in list(result.items()):
        result[serial] = [
            stop_serial_after if succ == stop_serial_before else succ for succ in succs
        ]
    result[stop_serial_after] = old_stop_succs


def simulate_edits(
    adj: dict[int, list[int]],
    edits: list[SimulatedEdit],
) -> SimulationResult:
    """Apply edits to a COPY of adj, return new adjacency. No MBA mutation.

    Operations:
    - ``goto_redirect``: replace first occurrence of old_target with new_target
      in source's successors.
    - ``conditional_redirect``: same as goto_redirect (edge replacement).
    - ``convert_to_goto``: replace ALL successors of source with [new_target].

    Args:
        adj: Original adjacency list (block serial -> successor serials).
        edits: Ordered list of edits to apply sequentially.

    Returns:
        A new adjacency dict with all edits applied. The original is not modified.
    """
    result: dict[int, list[int]] = copy.deepcopy(adj)
    created_clones: set[int] = set()
    clone_origins: dict[int, SimulatedEdit] = {}
    relocated_stop: tuple[int, int] | None = None

    for edit in edits:
        if edit.created_serial is not None:
            relocation = (edit.stop_serial_before, edit.stop_serial_after)
            if (
                edit.stop_serial_before is not None
                and edit.stop_serial_after is not None
                and relocated_stop != relocation
            ):
                _apply_stop_relocation_once(
                    result,
                    stop_serial_before=edit.stop_serial_before,
                    stop_serial_after=edit.stop_serial_after,
                )
                relocated_stop = relocation

        succs = result.get(edit.source, [])

        if edit.kind == "private_terminal_suffix_anchor":
            # Fail-closed: anchor MUST still target shared_entry (old_target).
            # Backend rejects this op otherwise; simulator must match.
            new_succs = list(succs)
            if edit.old_target in new_succs:
                idx = new_succs.index(edit.old_target)
                new_succs[idx] = edit.new_target
                result[edit.source] = new_succs
            # else: skip — anchor no longer targets shared_entry, no edit applied

        elif edit.kind in ("goto_redirect", "conditional_redirect"):
            # Replace first occurrence of old_target with new_target
            new_succs = list(succs)
            try:
                idx = new_succs.index(edit.old_target)
                new_succs[idx] = edit.new_target
            except ValueError:
                # old_target not found — append new_target as fallback
                new_succs.append(edit.new_target)
            result[edit.source] = new_succs

        elif edit.kind == "convert_to_goto":
            # Replace ALL successors with single new_target
            result[edit.source] = [edit.new_target]

        elif edit.kind == "edge_split_redirect":
            if edit.via_pred is not None:
                # Model IDA's edge-split: clone source block, rewire via_pred.
                # 1. Create virtual clone node with [new_target] as successor.
                clone_serial = edit.created_serial
                if clone_serial is None:
                    clone_serial = max(result.keys(), default=-1) + 1
                result[clone_serial] = [edit.new_target]
                created_clones.add(clone_serial)
                clone_origins[clone_serial] = edit
                # 2. Rewire via_pred: replace source with clone in via_pred's successors.
                if edit.via_pred in result:
                    result[edit.via_pred] = [
                        clone_serial if s == edit.source else s
                        for s in result[edit.via_pred]
                    ]
                # 3. Original source keeps its edges unchanged.
            else:
                # Fallback for edge_split without via_pred: conservative add.
                new_succs = list(succs)
                if edit.new_target not in new_succs:
                    new_succs.append(edit.new_target)
                result[edit.source] = new_succs

        elif edit.kind == "insert_block":
            inserted_serial = edit.created_serial
            if inserted_serial is None:
                inserted_serial = max(result.keys(), default=-1) + 1
            result[inserted_serial] = [edit.new_target]

            new_succs = list(succs)
            try:
                idx = new_succs.index(edit.old_target)
                new_succs[idx] = inserted_serial
            except ValueError:
                new_succs.append(inserted_serial)
            result[edit.source] = new_succs

        elif edit.kind == "remove_edge":
            result[edit.source] = [succ for succ in succs if succ != edit.old_target]

        elif edit.kind == "create_conditional_redirect":
            # Model as creating a virtual conditional clone that source points to.
            clone_serial = edit.created_serial
            if clone_serial is None:
                clone_serial = max(result.keys(), default=-1) + 1
            fallthrough_serial = edit.secondary_created_serial
            if fallthrough_serial is None:
                fallthrough_serial = max({*result.keys(), clone_serial}, default=-1) + 1
                if fallthrough_serial == clone_serial:
                    fallthrough_serial += 1
            clone_succs = [edit.new_target, fallthrough_serial]
            result[clone_serial] = clone_succs
            if edit.fallthrough_target is None:
                result[fallthrough_serial] = []
            else:
                result[fallthrough_serial] = [edit.fallthrough_target]
            created_clones.add(clone_serial)
            created_clones.add(fallthrough_serial)
            clone_origins[clone_serial] = edit
            clone_origins[fallthrough_serial] = edit

            new_succs = list(succs)
            try:
                idx = new_succs.index(edit.old_target)
                new_succs[idx] = clone_serial
            except ValueError:
                new_succs.append(clone_serial)
            result[edit.source] = new_succs

        elif edit.kind == "duplicate_block":
            clone_serial = edit.created_serial
            if clone_serial is None:
                clone_serial = max(result.keys(), default=-1) + 1

            duplicate_target = edit.duplicate_target
            source_successors = list(edit.source_successors)
            clone_succs: list[int]

            fallthrough_serial = edit.secondary_created_serial
            needs_fallthrough_clone = (
                len(source_successors) == 2 or fallthrough_serial is not None
            )
            if needs_fallthrough_clone and fallthrough_serial is None:
                fallthrough_serial = max({*result.keys(), clone_serial}, default=-1) + 1
                if fallthrough_serial == clone_serial:
                    fallthrough_serial += 1

            if duplicate_target is not None:
                clone_succs = [duplicate_target]
            elif len(source_successors) <= 1:
                clone_succs = source_successors
            else:
                # 2-way block (m_jcnd): IDA verify.cpp expects
                # succset = [serial+1, tail.d.b] = [fallthrough, conditional].
                # Fallthrough trampoline must be succset[0] (= clone serial+1).
                clone_succs = []
                conditional_target = edit.conditional_target
                if conditional_target is None and source_successors:
                    conditional_target = source_successors[0]
                if fallthrough_serial is not None:
                    clone_succs.append(fallthrough_serial)
                if conditional_target is not None:
                    clone_succs.append(conditional_target)

            result[clone_serial] = clone_succs
            created_clones.add(clone_serial)
            clone_origins[clone_serial] = edit

            if needs_fallthrough_clone and fallthrough_serial is not None:
                if edit.fallthrough_target is None:
                    result[fallthrough_serial] = []
                else:
                    result[fallthrough_serial] = [edit.fallthrough_target]
                created_clones.add(fallthrough_serial)
                clone_origins[fallthrough_serial] = edit

            if edit.via_pred is not None and edit.via_pred in result:
                result[edit.via_pred] = [
                    clone_serial if succ == edit.source else succ
                    for succ in result[edit.via_pred]
                ]

        elif edit.kind == "private_terminal_suffix_clone":
            clone_serial = edit.created_serial
            if clone_serial is None:
                clone_serial = max(result.keys(), default=-1) + 1
            if edit.new_target is not None:
                result[clone_serial] = [edit.new_target]
            else:
                result[clone_serial] = []
            created_clones.add(clone_serial)
            clone_origins[clone_serial] = edit

        elif edit.kind == "reorder_block_copy":
            # Create the new block with a copy of old block's adjacency
            new_serial = edit.created_serial
            if new_serial is None:
                new_serial = max(result.keys(), default=-1) + 1
            old_serial = edit.source
            old_succs = list(result.get(old_serial, []))
            result[new_serial] = old_succs
            created_clones.add(new_serial)
            clone_origins[new_serial] = edit

        elif edit.kind == "reorder_block_2way_copy":
            copy_serial = edit.created_serial
            tramp_serial = getattr(edit, "secondary_created_serial", None)
            if copy_serial is None:
                copy_serial = max(result.keys(), default=-1) + 1
            if tramp_serial is None:
                tramp_serial = copy_serial + 1

            old_serial = edit.source
            old_succs = list(result.get(old_serial, []))
            # BLT_2WAY: succset = [fallthrough(index 0), conditional(index 1)].
            # The copy replaces the fallthrough (index 0) with the trampoline.
            # The conditional target (index 1+) stays for remap.
            if len(old_succs) >= 2:
                # Replace first entry (fallthrough) with trampoline
                original_fallthrough = old_succs[0]
                copy_succs = [tramp_serial] + old_succs[1:]
            elif len(old_succs) == 1:
                # Degenerate: single successor, prepend trampoline
                original_fallthrough = old_succs[0]
                copy_succs = [tramp_serial, old_succs[0]]
            else:
                original_fallthrough = old_serial + 1
                copy_succs = [tramp_serial]
            logger.warning(
                "DIAG sim 2WAY_COPY: old=%d copy=%d tramp=%d old_succs=%s copy_succs=%s ft=%d in_result=%s",
                old_serial,
                copy_serial,
                tramp_serial,
                old_succs,
                copy_succs,
                original_fallthrough,
                copy_serial in result,
            )
            result[copy_serial] = copy_succs
            created_clones.add(copy_serial)

            # Trampoline: single successor = original fallthrough target.
            # The reorder_block_remap step will remap it if needed.
            result[tramp_serial] = [original_fallthrough]
            created_clones.add(tramp_serial)

        elif edit.kind == "reorder_block_trampoline":
            # Convert old block to trampoline -> single successor = its copy
            result[edit.source] = [edit.new_target]

        elif edit.kind == "reorder_block_remap":
            # Remap all non-trampoline blocks' successors through old_to_new
            flat = list(edit.source_successors or ())
            old_to_new = dict(zip(flat[::2], flat[1::2]))
            old_set = set(old_to_new.keys())
            for serial in list(result.keys()):
                if serial in old_set:
                    continue  # trampolines already handled
                result[serial] = [old_to_new.get(s, s) for s in result[serial]]

    return SimulationResult(
        adj=result,
        created_clones=created_clones,
        clone_origins=clone_origins,
    )
