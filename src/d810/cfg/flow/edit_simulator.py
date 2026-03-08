"""Simulate CFG edits on an adjacency list without mutating the MBA."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field

try:
    import ida_hexrays
except ImportError:  # pragma: no cover - exercised in non-IDA unit tests.
    class _FallbackHexRays:
        BLT_NONE = 0
        BLT_STOP = 1
        BLT_0WAY = 2
        BLT_1WAY = 3
        BLT_2WAY = 4

        m_nop = 0
        m_goto = 2
        m_jcnd = 3

    ida_hexrays = _FallbackHexRays()  # type: ignore[assignment]

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
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
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
    PatchRemoveEdge,
    PatchRedirectBranch,
    PatchRedirectGoto,
)

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
    return block.tail_opcode


def _block_type_for_projected_shape(
    *,
    template_block: BlockSnapshot | None,
    kind: str,
    succs: tuple[int, ...],
    tail_opcode: int | None,
) -> int:
    if kind in {"conditional_redirect_clone", "duplicate_block_clone"} and len(succs) == 2:
        return _BLT_2WAY
    if kind.endswith("fallthrough") or kind in {"edge_split_trampoline", "insert_block"}:
        if len(succs) >= 2:
            return _BLT_2WAY
        if len(succs) == 1:
            return _BLT_1WAY
        return _BLT_0WAY
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
    if kind in {"conditional_redirect_clone", "duplicate_block_clone"} and len(succs) == 2:
        if template_block is not None and template_block.tail_opcode is not None:
            return int(template_block.tail_opcode)
        return _M_JCND
    if kind.endswith("fallthrough") or kind in {"edge_split_trampoline", "insert_block"}:
        return _M_GOTO if succs else _M_NOP
    if template_block is not None:
        return template_block.tail_opcode
    return _M_GOTO if succs else _M_NOP


def _build_pred_map(adj: dict[int, list[int]]) -> dict[int, tuple[int, ...]]:
    preds: dict[int, list[int]] = {serial: [] for serial in adj}
    for serial, succs in adj.items():
        for succ in succs:
            if succ in preds:
                preds[succ].append(serial)
    return {
        serial: tuple(pred_list)
        for serial, pred_list in preds.items()
    }


def _project_existing_blocks(
    pre_cfg: FlowGraph,
    patch_plan: PatchPlan,
    adj: dict[int, list[int]],
) -> dict[int, BlockSnapshot]:
    projected: dict[int, BlockSnapshot] = {}
    for block in pre_cfg.blocks.values():
        projected_serial = patch_plan.relocation_map.rewrite_serial(block.serial)
        projected[projected_serial] = BlockSnapshot(
            serial=projected_serial,
            block_type=int(block.block_type),
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
            insn_snapshots=instructions or tuple(getattr(template_block, "insn_snapshots", ())),
            tail_opcode=tail_opcode,
        )
    return projected


def project_post_state(pre_cfg: FlowGraph, patch_plan: PatchPlan) -> FlowGraph:
    """Project a PatchPlan onto a new FlowGraph without mutating live MBA state."""
    simulated = simulate_edits(
        pre_cfg.as_adjacency_dict(),
        patch_plan_to_simulated_edits(patch_plan),
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
                        new_target=patch_plan.relocation_map.rewrite_serial(conditional),
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
            needs_fallthrough_clone = len(source_successors) == 2 or fallthrough_serial is not None
            if needs_fallthrough_clone and fallthrough_serial is None:
                fallthrough_serial = max({*result.keys(), clone_serial}, default=-1) + 1
                if fallthrough_serial == clone_serial:
                    fallthrough_serial += 1

            if duplicate_target is not None:
                clone_succs = [duplicate_target]
            elif len(source_successors) <= 1:
                clone_succs = source_successors
            else:
                clone_succs = []
                conditional_target = edit.conditional_target
                if conditional_target is None and source_successors:
                    conditional_target = source_successors[0]
                if conditional_target is not None:
                    clone_succs.append(conditional_target)
                if fallthrough_serial is not None:
                    clone_succs.append(fallthrough_serial)

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

    return SimulationResult(
        adj=result,
        created_clones=created_clones,
        clone_origins=clone_origins,
    )
