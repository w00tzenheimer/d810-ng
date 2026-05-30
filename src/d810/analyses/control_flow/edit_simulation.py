"""Pure adjacency-graph edit simulation core (no PatchPlan / mutation deps).

This module holds the *pure* simulation primitives extracted from
:mod:`d810.transforms.edit_simulator` (dissolution A0 split, llr-lyly):

* :class:`SimulatedEdit` -- an abstract edit operation on an adjacency list.
* :class:`SimulationResult` -- the result of applying a list of edits.
* :func:`simulate_edits` -- apply a list of edits to a *copy* of an adjacency
  dict and return the post-edit adjacency plus created-clone bookkeeping.

None of these touch ``PatchPlan``, ``GraphModification``, or the live MBA --
they operate purely on ``dict[int, list[int]]`` adjacency maps.  This lets
read-only structural verifiers (e.g.
:mod:`d810.analyses.control_flow.graph_checks`) consume the simulation core
without an upward ``analyses -> transforms`` import.

The PatchPlan-coupled glue (``project_post_state``,
``patch_plan_to_simulated_edits``, ``graph_modifications_to_simulated_edits``,
etc.) stays in :mod:`d810.transforms.edit_simulator`, which re-imports the
names defined here so its existing consumers are unaffected.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field

from d810.core.logging import getLogger

logger = getLogger(__name__)


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

    kind: str  # "goto_redirect", "conditional_redirect", "convert_to_goto", "edge_split_redirect", ...
    source: int
    old_target: int
    new_target: int | None
    via_pred: int | None = None  # only for edge_split_redirect
    clone_until: int | None = None  # only for corridor edge_split_redirect
    fallthrough_target: int | None = None  # only for create_conditional_redirect
    duplicate_target: int | None = None  # only for duplicate_block
    source_successors: tuple[int, ...] = ()  # only for duplicate_block
    conditional_target: int | None = None  # duplicate/create_conditional info
    created_serial: int | None = None  # finalized serial for symbolic block creation
    secondary_created_serial: int | None = None  # second block for multi-block creation
    stop_serial_before: int | None = None
    stop_serial_after: int | None = None


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

        if edit.kind in (
            "private_terminal_suffix_anchor",
            "direct_terminal_lowering_anchor",
            "edge_split_corridor_anchor",
        ):
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
                # old_target not found — a prior edit already changed this
                # block's successor.  Skip rather than appending (which would
                # create a spurious extra successor and trigger
                # SUCC_MISMATCH rejection downstream).
                logger.warning(
                    "simulate_edits: %s on block %d skipped — old_target %d "
                    "not in current successors %s (new_target was %d)",
                    edit.kind, edit.source, edit.old_target, new_succs,
                    edit.new_target,
                )
                continue
            result[edit.source] = new_succs

        elif edit.kind == "convert_to_goto":
            # Replace ALL successors with single new_target
            result[edit.source] = [edit.new_target]

        elif edit.kind in {
            "edge_split_redirect",
            "clone_conditional_as_goto",
            "clone_conditional_as_goto_from_branch_arm",
        }:
            if edit.via_pred is not None:
                # Model pred-scoped clone edits: clone source block, rewire via_pred.
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
            # Keep Hex-Rays BLT_2WAY ordering: succset[0] is fallthrough,
            # succset[1] is the conditional branch target.
            clone_succs = [fallthrough_serial, edit.new_target]
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
            if len(new_succs) == 1:
                new_succs[0] = clone_serial
            else:
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
            explicit_conditional_clone = (
                edit.conditional_target is not None
                and edit.fallthrough_target is not None
            )

            fallthrough_serial = edit.secondary_created_serial
            needs_fallthrough_clone = (
                len(source_successors) == 2
                or fallthrough_serial is not None
                or explicit_conditional_clone
            )
            if needs_fallthrough_clone and fallthrough_serial is None:
                fallthrough_serial = max({*result.keys(), clone_serial}, default=-1) + 1
                if fallthrough_serial == clone_serial:
                    fallthrough_serial += 1

            if duplicate_target is not None:
                clone_succs = [duplicate_target]
            elif len(source_successors) <= 1 and not explicit_conditional_clone:
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

        elif edit.kind in (
            "private_terminal_suffix_clone",
            "direct_terminal_lowering_clone",
            "edge_split_corridor_clone",
        ):
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
