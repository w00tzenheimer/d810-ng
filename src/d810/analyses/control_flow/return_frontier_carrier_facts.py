"""Return-frontier carrier-fact detector (FlowGraph-snapshot, pre-mutation).

For each block whose tail is a return (or whose block kind is stop),
walk *backwards* over the immutable :class:`FlowGraph`
snapshot to find the FIRST block that writes the return slot
(rax-typed register or the return-slot stkvar) and record the carrier
identity of that writer's source operand.

Unlike the live return-frontier carrier audit in the optimizer layer,
which runs against the live ``mba_t`` *post*-pipeline, this detector
runs at FlowGraph-build time against the pre-mutation snapshot.  The
intent is to provide HCC's plan-emission stage with a stable,
immutable record of the carrier's def-chain blocks BEFORE any
``RedirectGoto`` / typed clone / ``InsertBlock`` mod can
collapse the def chain into a copy-prop-vulnerable shape.

Outputs are pure data (``ReturnFrontierCarrierFact`` records). The
HCC carrier-shred guard consumes the ``writer_path_blocks`` set to
reject any topology mod that would inject a foreign predecessor into
a block on the carrier-def path or rewrite an edge inside it.

This module follows the same idioms as
:func:`d810.analyses.control_flow.linearized_state_dag.detect_side_effect_corridors`:
- It runs against the FlowGraph snapshot (no live mba access).
- It introspects ``BlockSnapshot.kind`` / ``InsnSnapshot.kind`` and classifies
  each operand over the portable storage views produced by
  :mod:`d810.ir.insn_projection` (``Varnode`` for register / stack-known / lvar /
  const operands, :class:`~d810.ir.locations.WeakStackSlot` for a stack operand
  whose offset was not recovered), never over a raw backend operand slot.
- It is conservative: when the carrier cannot be cleanly captured (no
  lvar / stack-identity source on the writer), no fact is emitted.

Default bounds:
- BFS depth: 8 blocks back from the return tail (matches the audit's
  ``_DEFAULT_MAX_DEPTH``).
- BFS visited cap: 64 blocks (matches the audit).
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.ir.flowgraph import (
    BlockSnapshot,
    BlockKind,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
)
from d810.ir.varnode import Space, Varnode
from d810.ir.expressions import Move
from d810.ir.insn_projection import (
    operand_storages,
    primary_source_storage,
    project_assignment,
    result_storage,
)
from d810.ir.locations import RegisterLocation, StackSlot, WeakStackSlot
from d810.ir.value_refs import DefinitionRef
from d810.core import logging
from d810.analyses.control_flow.return_frontier_artifacts import (
    ReturnFrontierArtifactKind,
    ReturnFrontierArtifactPriors,
    ReturnFrontierCarrierClassification,
)

logger = logging.getLogger(
    "D810.analyses.control_flow.return_frontier_carrier_facts", logging.INFO
)

__all__ = [
    "ReturnFrontierCarrierFact",
    "detect_return_frontier_carrier_facts",
]


_DEFAULT_MAX_DEPTH = 8
_DEFAULT_MAX_VISITED = 64

_RETURN_WRITER_KINDS = frozenset(
    {
        InsnKind.MOV,
        InsnKind.STORE,
        InsnKind.ADD,
        InsnKind.XDU,
        InsnKind.XDS,
    }
)


# ---------------------------------------------------------------------------
# Operand classification over the canonical storage-view surface.
#
# Each predicate consumes a portable storage view -- a ``Varnode``
# (space + offset + size) for register / stack-known / lvar / const operands, or
# a :class:`~d810.ir.locations.WeakStackSlot` for a stack operand whose concrete
# offset was not recovered -- produced by
# :mod:`d810.ir.insn_projection`.  The detector never reads a raw backend
# ``InsnSnapshot.l/.r/.d`` operand slot: the projection layer owns that read and
# the accept-on-unknown stack case is now an explicit ``WeakStackSlot`` instead
# of a ``Space.UNKNOWN`` collapse.
# ---------------------------------------------------------------------------

def _is_register_storage(view: object | None) -> bool:
    return isinstance(view, Varnode) and view.space is Space.REGISTER


def _is_number_storage(view: object | None) -> bool:
    return isinstance(view, Varnode) and view.space is Space.CONST


def _is_stack_storage(view: object | None) -> bool:
    """True for both a concrete stack ``Varnode`` and a weak stack slot."""
    return isinstance(view, WeakStackSlot) or (
        isinstance(view, Varnode) and view.space is Space.STACK
    )


def _is_lvar_storage(view: object | None) -> bool:
    return isinstance(view, Varnode) and view.space is Space.LVAR


@dataclass(frozen=True, slots=True)
class ReturnFrontierCarrierFact:
    """Immutable record of a return-frontier writer's carrier identity.

    Attributes:
        ret_block: Serial of the return/stop block.
        writer_block: Serial of the block writing the return slot.
        walk_path: Block serials from writer_block ... ret_block (inclusive
            on both ends).  Length >= 1 (at minimum the writer is also the
            ret block).
        carrier_lvar_idx: lvar index of the writer's lvar source, or
            ``None`` if the source is not an lvar.
        carrier_stkoff: Canonical STACK storage offset of the writer's stack
            source, or ``None`` if the source is not a stkvar.
        writer_path_blocks: Frozenset of block serials whose preservation
            is required for the carrier identity to survive end-to-end
            (writer + immediate predecessors that reference the carrier
            by lvar / stack identity).  HCC uses this set to reject mods that
            would inject foreign predecessors or rewrite edges inside.
        classification: Recon carrier classification. The protected
            non-carrier class means the writer is not a recoverable return
            carrier, but topology rewrites must preserve it unless a later
            proof supplies a precise lowering.
        artifact_kind: Optional protected non-carrier writer shape.
    """

    ret_block: int
    writer_block: int
    walk_path: tuple[int, ...]
    carrier_lvar_idx: int | None
    carrier_stkoff: int | None
    writer_path_blocks: frozenset[int]
    classification: str = ReturnFrontierCarrierClassification.RETURN_CARRIER.value
    artifact_kind: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_return_block(blk: BlockSnapshot) -> bool:
    """True iff this block is a stop block or its tail is a return."""
    if blk.kind is BlockKind.STOP:
        return True
    if blk.tail_kind is InsnKind.RET:
        return True
    tail = blk.tail
    if tail is not None and tail.kind is InsnKind.RET:
        return True
    return False


def _dest_is_return_slot(
    insn: InsnSnapshot, *, return_stkoff: int
) -> bool:
    """Heuristic: writer's destination is rax (any register) OR the
    return-slot stkvar at ``return_stkoff``.

    We accept any register destination as a candidate because rax is the
    standard return register on x64 and OLLVM's pre-finalize lowering uses an
    lvar/stkvar intermediate.  This matches the audit's ``_dest_is_return_slot``.
    """
    dst = result_storage(insn)
    if _is_register_storage(dst):
        return True
    if _is_stack_storage(dst):
        dst_off = _operand_stack_offset(dst)
        if dst_off is None:
            return True  # accept-on-unknown (WeakStackSlot or no captured offset)
        return dst_off == int(return_stkoff)
    if _is_lvar_storage(dst):
        # The portable lvar identity does not expose the live lvar table index;
        # accept any lvar destination as a candidate (filtered downstream by
        # carrier capture).
        return True
    return False


def _is_trivial_copy(
    insn: InsnSnapshot,
    *,
    return_stkoff: int,
) -> bool:
    """True iff the insn is a pure trampoline copy (stkvar->reg or
    reg->stkvar of the return slot).  Walker treats these as transparent
    so it can find the upstream computation.

    Reads the portable projected assignment (llr-lxas): a MOV whose endpoints
    are a register and a stack slot, where the stack slot is the return slot or
    an unrecovered ``WeakStackSlot`` (the accept-on-unknown case is now explicit
    in the location type instead of a vendor ``stkoff is None`` check).
    """
    assignment = project_assignment(insn)
    if (
        assignment is None
        or assignment.target is None
        or not isinstance(assignment.value, Move)
    ):
        return False
    source = assignment.value.source
    if not isinstance(source, DefinitionRef):
        return False
    src_loc = source.location
    dst_loc = assignment.target.location
    # stkvar -> reg
    if isinstance(dst_loc, RegisterLocation):
        if isinstance(src_loc, WeakStackSlot):
            return True
        if isinstance(src_loc, StackSlot):
            return src_loc.offset == int(return_stkoff)
    # reg -> stkvar
    if isinstance(src_loc, RegisterLocation):
        if isinstance(dst_loc, WeakStackSlot):
            return True
        if isinstance(dst_loc, StackSlot):
            return dst_loc.offset == int(return_stkoff)
    return False


def _find_writer_in_block(
    blk: BlockSnapshot,
    *,
    return_stkoff: int,
    skip_trivial_copy: bool = True,
) -> InsnSnapshot | None:
    """Return the LAST instruction in ``blk`` that writes the return
    slot, ignoring trivial trampoline copies.  None if none found."""
    last: InsnSnapshot | None = None
    for insn in blk.insn_snapshots:
        if insn.kind not in _RETURN_WRITER_KINDS:
            continue
        if not _dest_is_return_slot(insn, return_stkoff=return_stkoff):
            continue
        if skip_trivial_copy and _is_trivial_copy(
            insn, return_stkoff=return_stkoff
        ):
            continue
        last = insn
    return last


def _operand_stack_offset(view: object | None) -> int | None:
    """Return the canonical STACK storage offset of a storage view, else ``None``.

    Returns the offset only for a concrete stack ``Varnode``; a
    :class:`~d810.ir.locations.WeakStackSlot` (stack, unknown offset) or a
    non-stack view yields ``None``.
    """
    if isinstance(view, Varnode) and view.space is Space.STACK:
        return int(view.offset)
    return None


def _writer_carrier_identity(
    writer: InsnSnapshot,
) -> tuple[int | None, int | None]:
    """Return ``(carrier_lvar_idx, carrier_stkoff)`` from the writer's
    source operand.  Both None means the carrier cannot be captured (writer
    was a const / sub-instruction / arithmetic).

    The portable storage view does NOT carry an lvar *table index* (the portable
    ``Varnode`` LVAR identity is a frame *offset*, not the live lvar table
    index), so ``carrier_lvar_idx`` is always ``None`` on this FlowGraph-snapshot
    path; only the canonical stack offset is recorded.  Exposing the live lvar
    table index would require a projection extension and is intentionally out of
    scope here (the live-mba audit in ``return_frontier_carrier_audit`` reads it
    directly).
    """
    src = primary_source_storage(writer)
    if src is None:
        return None, None
    carrier_stkoff: int | None = None
    if _is_stack_storage(src):
        carrier_stkoff = _operand_stack_offset(src)
    return None, carrier_stkoff


def _writer_const_value(writer: InsnSnapshot) -> int | None:
    """Return the constant value of the writer's source operand, else ``None``.

    A number source projects to a ``Varnode`` in ``Space.CONST`` whose
    ``offset`` carries the constant value.
    """
    src = primary_source_storage(writer)
    if _is_number_storage(src):
        return int(src.offset)
    return None


def _writer_is_state_variable_return_writer(
    writer: InsnSnapshot,
    *,
    state_var_stkoff: int | None,
) -> bool:
    if state_var_stkoff is None:
        return False
    src = primary_source_storage(writer)
    dst = result_storage(writer)
    if not _is_stack_storage(src) or not _is_stack_storage(dst):
        return False
    src_off = _operand_stack_offset(src)
    dst_off = _operand_stack_offset(dst)
    if src_off is None or dst_off is None:
        return False
    return src_off == int(state_var_stkoff) and dst_off != int(state_var_stkoff)


def _insn_references_carrier(
    insn: InsnSnapshot,
    *,
    carrier_lvar_idx: int | None,
    carrier_stkoff: int | None,
) -> bool:
    """True iff any operand of ``insn`` references the carrier by canonical
    STACK storage offset (stkoff match).

    ``carrier_lvar_idx`` is accepted for signature parity but never matchable on
    the FlowGraph-snapshot path: the portable storage view exposes an lvar frame
    *offset*, not the live lvar table index, so carrier identity here is keyed
    only on the canonical stack offset (see ``_writer_carrier_identity``).
    """
    if carrier_stkoff is None:
        return False
    for view in operand_storages(insn):
        if _is_stack_storage(view):
            view_off = _operand_stack_offset(view)
            if view_off is not None and view_off == int(carrier_stkoff):
                return True
    return False


def _block_references_carrier(
    blk: BlockSnapshot,
    *,
    carrier_lvar_idx: int | None,
    carrier_stkoff: int | None,
) -> bool:
    if carrier_lvar_idx is None and carrier_stkoff is None:
        return False
    for insn in blk.insn_snapshots:
        if _insn_references_carrier(
            insn,
            carrier_lvar_idx=carrier_lvar_idx,
            carrier_stkoff=carrier_stkoff,
        ):
            return True
    return False


def _protected_non_carrier_return_writer_fact(
    *,
    ret_serial: int,
    writer_serial: int,
    walk_path: tuple[int, ...],
    const_value: int | None = None,
) -> ReturnFrontierCarrierFact:
    protected = {int(writer_serial)}
    fact = ReturnFrontierCarrierFact(
        ret_block=int(ret_serial),
        writer_block=int(writer_serial),
        walk_path=tuple(int(s) for s in walk_path),
        carrier_lvar_idx=None,
        carrier_stkoff=None,
        writer_path_blocks=frozenset(protected),
        classification=(
            ReturnFrontierCarrierClassification
            .PROTECTED_NON_CARRIER_RETURN_WRITER.value
        ),
        artifact_kind=(
            ReturnFrontierArtifactKind.KNOWN_IMPOSSIBLE_CONSTANT_RETURN_WRITER.value
            if const_value is not None
            else ReturnFrontierArtifactKind.STATE_VARIABLE_RETURN_WRITER.value
        ),
    )
    logger.info(
        "RETURN_FRONTIER_CARRIER_FACT: ret=blk[%d] "
        "writer=blk[%d] path=%s classification=%s "
        "const=%s path_blocks=%s",
        fact.ret_block,
        fact.writer_block,
        list(fact.walk_path),
        fact.classification,
        (
            f"0x{int(const_value) & 0xFFFFFFFFFFFFFFFF:016x}"
            if const_value is not None
            else "<state-var>"
        ),
        sorted(fact.writer_path_blocks),
    )
    return fact


def _detect_protected_non_carrier_return_writer_facts_for_return(
    flow_graph: FlowGraph,
    *,
    ret_serial: int,
    return_stkoff: int,
    state_var_stkoff: int | None,
    artifact_priors: ReturnFrontierArtifactPriors,
    max_depth: int,
    max_visited: int,
) -> tuple[ReturnFrontierCarrierFact, ...]:
    """Find protected non-carrier return writers feeding a shared suffix.

    Normal carrier detection intentionally stops at the first concrete
    return writer.  Protected non-carrier artifacts are different: they can be
    one sibling writer among many terminal writers that share a final
    ``stkvar -> rax`` copy block.  Walk backward through transparent suffix
    blocks, inspect every concrete return writer at that frontier, and stop at
    each writer so the scan does not wander through unrelated handler topology.
    """
    facts: list[ReturnFrontierCarrierFact] = []
    visited: set[int] = {int(ret_serial)}
    frontier: list[tuple[int, int, tuple[int, ...]]] = [
        (int(ret_serial), 0, (int(ret_serial),))
    ]

    while frontier:
        if len(visited) > max_visited:
            break
        serial, depth, path = frontier.pop(0)
        if depth >= max_depth:
            continue
        cur_blk = flow_graph.blocks.get(serial)
        if cur_blk is None:
            continue
        for pserial in cur_blk.preds:
            pserial = int(pserial)
            if pserial in visited:
                continue
            visited.add(pserial)
            pblk = flow_graph.blocks.get(pserial)
            if pblk is None:
                continue
            new_path = path + (pserial,)
            writer = _find_writer_in_block(
                pblk,
                return_stkoff=return_stkoff,
            )
            if writer is not None:
                if _writer_is_state_variable_return_writer(
                    writer,
                    state_var_stkoff=state_var_stkoff,
                ):
                    facts.append(
                        _protected_non_carrier_return_writer_fact(
                            ret_serial=ret_serial,
                            writer_serial=pserial,
                            walk_path=new_path,
                        )
                    )
                    continue
                const_value = _writer_const_value(writer)
                if (
                    const_value is not None
                    and artifact_priors.is_known_impossible_return_constant(
                        const_value
                    )
                ):
                    facts.append(
                        _protected_non_carrier_return_writer_fact(
                            ret_serial=ret_serial,
                            writer_serial=pserial,
                            walk_path=new_path,
                            const_value=const_value,
                        )
                    )
                continue
            frontier.append((pserial, depth + 1, new_path))
    return tuple(facts)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


def detect_return_frontier_carrier_facts(
    flow_graph: FlowGraph | None,
    *,
    return_stkoff_hint: int | None = None,
    state_var_stkoff: int | None = None,
    artifact_priors: ReturnFrontierArtifactPriors | None = None,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    max_visited: int = _DEFAULT_MAX_VISITED,
) -> tuple[ReturnFrontierCarrierFact, ...]:
    """Detect carrier-def facts at every return-frontier block.

    For each block whose tail is a return (or whose block kind is stop), perform a
    bounded backward BFS along the FlowGraph predecessor edges to find
    the first block writing the return slot.  Capture the source
    operand's carrier identity (lvar idx or stack-identity offset).  Compute
    ``writer_path_blocks`` = the set of blocks on the writer's def
    chain that reference the same carrier, plus the writer itself.

    Returns a tuple of facts ordered by ``ret_block`` ascending for
    determinism.  Skips ret blocks where the carrier cannot be cleanly
    captured (e.g., writer source is a constant or sub-instruction).
    """
    if flow_graph is None:
        return ()
    effective_artifact_priors = artifact_priors or ReturnFrontierArtifactPriors()

    facts: list[ReturnFrontierCarrierFact] = []

    for ret_serial in sorted(flow_graph.blocks.keys()):
        ret_blk = flow_graph.blocks[ret_serial]
        if not _is_return_block(ret_blk):
            continue

        # Determine the return slot from a return-block stack-to-register
        # move; fall back only to an explicit caller/profile hint.
        return_stkoff = (
            int(return_stkoff_hint)
            if return_stkoff_hint is not None
            else None
        )
        for ins in ret_blk.insn_snapshots:
            if ins.kind is not InsnKind.MOV:
                continue
            s = primary_source_storage(ins)
            d = result_storage(ins)
            if s is None or d is None:
                continue
            if _is_stack_storage(s) and _is_register_storage(d):
                src_off = _operand_stack_offset(s)
                if src_off is not None:
                    return_stkoff = src_off
                    break
        if return_stkoff is None:
            continue

        artifact_facts = _detect_protected_non_carrier_return_writer_facts_for_return(
            flow_graph,
            ret_serial=ret_serial,
            return_stkoff=return_stkoff,
            state_var_stkoff=state_var_stkoff,
            artifact_priors=effective_artifact_priors,
            max_depth=max_depth,
            max_visited=max_visited,
        )
        artifact_keys = {
            (fact.ret_block, fact.writer_block, fact.classification)
            for fact in artifact_facts
        }
        facts.extend(artifact_facts)

        # Bounded BFS backward to find the writer.
        writer: InsnSnapshot | None = None
        writer_serial: int | None = None
        walk_path: tuple[int, ...] = ()

        local_writer = _find_writer_in_block(
            ret_blk,
            return_stkoff=return_stkoff,
        )
        if local_writer is not None:
            writer = local_writer
            writer_serial = ret_serial
            walk_path = (ret_serial,)
        else:
            visited: set[int] = {ret_serial}
            frontier: list[tuple[int, int, tuple[int, ...]]] = [
                (ret_serial, 0, (ret_serial,))
            ]
            hit_cap = False
            while frontier:
                if len(visited) > max_visited:
                    hit_cap = True
                    break
                serial, depth, path = frontier.pop(0)
                if depth >= max_depth:
                    continue
                cur_blk = flow_graph.blocks.get(serial)
                if cur_blk is None:
                    continue
                for pserial in cur_blk.preds:
                    if pserial in visited:
                        continue
                    visited.add(pserial)
                    pblk = flow_graph.blocks.get(pserial)
                    if pblk is None:
                        continue
                    pwriter = _find_writer_in_block(
                        pblk,
                        return_stkoff=return_stkoff,
                    )
                    new_path = path + (pserial,)
                    if pwriter is not None:
                        writer = pwriter
                        writer_serial = pserial
                        walk_path = new_path
                        frontier = []  # break outer
                        break
                    frontier.append((pserial, depth + 1, new_path))
            if writer is None:
                logger.debug(
                    "RETURN_FRONTIER_CARRIER_FACT: ret=blk[%d] "
                    "writer=<none> (cap=%s)",
                    ret_serial,
                    "1" if hit_cap else "0",
                )
                continue

        assert writer is not None and writer_serial is not None

        # Capture the carrier identity from the writer's source.
        if _writer_is_state_variable_return_writer(
            writer,
            state_var_stkoff=state_var_stkoff,
        ):
            fact = _protected_non_carrier_return_writer_fact(
                ret_serial=ret_serial,
                writer_serial=writer_serial,
                walk_path=walk_path,
            )
            key = (fact.ret_block, fact.writer_block, fact.classification)
            if key not in artifact_keys:
                facts.append(fact)
            continue

        carrier_lvar_idx, carrier_stkoff = _writer_carrier_identity(writer)
        if carrier_lvar_idx is None and carrier_stkoff is None:
            const_value = _writer_const_value(writer)
            if (
                const_value is not None
                and effective_artifact_priors.is_known_impossible_return_constant(
                    const_value
                )
            ):
                fact = _protected_non_carrier_return_writer_fact(
                    ret_serial=ret_serial,
                    writer_serial=writer_serial,
                    walk_path=walk_path,
                    const_value=const_value,
                )
                key = (fact.ret_block, fact.writer_block, fact.classification)
                if key not in artifact_keys:
                    facts.append(fact)
                continue
            # Writer's source is a constant / sub-instruction / something
            # we cannot key on.  Carrier already lost; emit no fact.
            logger.debug(
                "RETURN_FRONTIER_CARRIER_FACT: ret=blk[%d] writer=blk[%d] "
                "carrier=<unrecognized> skip",
                ret_serial,
                writer_serial,
            )
            continue

        # Compute writer_path_blocks: writer + any immediate predecessor
        # of writer that references the same carrier.  The HCC guard
        # uses this as the protected set.
        protected: set[int] = {int(writer_serial)}
        # Reverse the walk_path so the writer end is the seed; include
        # the path itself (handler exit -> writer fall-through is part
        # of the def chain).
        for s in walk_path:
            protected.add(int(s))

        writer_blk = flow_graph.blocks.get(writer_serial)
        if writer_blk is not None:
            for pserial in writer_blk.preds:
                pblk = flow_graph.blocks.get(pserial)
                if pblk is None:
                    continue
                if _block_references_carrier(
                    pblk,
                    carrier_lvar_idx=carrier_lvar_idx,
                    carrier_stkoff=carrier_stkoff,
                ):
                    protected.add(int(pserial))

        fact = ReturnFrontierCarrierFact(
            ret_block=int(ret_serial),
            writer_block=int(writer_serial),
            walk_path=tuple(int(s) for s in walk_path),
            carrier_lvar_idx=carrier_lvar_idx,
            carrier_stkoff=carrier_stkoff,
            writer_path_blocks=frozenset(protected),
        )
        facts.append(fact)
        logger.info(
            "RETURN_FRONTIER_CARRIER_FACT: ret=blk[%d] writer=blk[%d] "
            "path=%s carrier_lvar=%s|stkoff=%s path_blocks=%s",
            fact.ret_block,
            fact.writer_block,
            list(fact.walk_path),
            (
                str(fact.carrier_lvar_idx)
                if fact.carrier_lvar_idx is not None
                else "None"
            ),
            (
                f"0x{fact.carrier_stkoff:x}"
                if fact.carrier_stkoff is not None
                else "None"
            ),
            sorted(fact.writer_path_blocks),
        )

    return tuple(facts)
