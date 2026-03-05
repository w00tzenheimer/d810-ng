"""Simulate CFG edits on an adjacency list without mutating the MBA."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field

from d810.cfg.graph_modification import (
    ConvertToGoto,
    CreateConditionalRedirect,
    EdgeRedirectViaPredSplit,
    GraphModification,
    RedirectBranch,
    RedirectGoto,
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

            case _:
                # Nop/Insert/Remove/Duplicate have no topology effect in preflight.
                continue

    return simulated


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

    for edit in edits:
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

        elif edit.kind == "create_conditional_redirect":
            # Model as creating a virtual conditional clone that source points to.
            clone_serial = max(result.keys(), default=-1) + 1
            clone_succs = [edit.new_target]
            if (
                edit.fallthrough_target is not None
                and edit.fallthrough_target != edit.new_target
            ):
                clone_succs.append(edit.fallthrough_target)
            result[clone_serial] = clone_succs
            created_clones.add(clone_serial)
            clone_origins[clone_serial] = edit

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
