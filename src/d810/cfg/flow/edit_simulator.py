"""Simulate CFG edits on an adjacency list without mutating the MBA."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field

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
    PatchEdgeSplitTrampoline,
    PatchInsertBlock,
    PatchPlan,
    PatchRemoveEdge,
    PatchRedirectBranch,
    PatchRedirectGoto,
)


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
    new_target: int
    via_pred: int | None = None  # only for edge_split_redirect
    fallthrough_target: int | None = None  # only for create_conditional_redirect
    created_serial: int | None = None  # finalized serial for symbolic block creation
    secondary_created_serial: int | None = None  # second block for multi-block creation
    stop_serial_before: int | None = None
    stop_serial_after: int | None = None


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

        if edit.kind in ("goto_redirect", "conditional_redirect"):
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

    return SimulationResult(
        adj=result,
        created_clones=created_clones,
        clone_origins=clone_origins,
    )
