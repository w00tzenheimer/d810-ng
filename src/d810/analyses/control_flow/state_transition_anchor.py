"State-transition anchor fact collector.\n\nThis collector observes LOCOPT-time state-machine transitions before\nIDA's MMAT_CALLS pass folds transit-state chains into direct writes.\n\nFor each ``mov #const, %var_<canonical_state_var>`` write at block B,\nthe collector walks B's direct successors to find the next block that\nwrites the same state variable, and records the implied transition.\n\nThis is the natural follow-up to :class:`StateWriteAnchorFactCollector`:\nanchors record per-block constants; transitions record the chain edges\nbetween those constants.  Preanalysis's eventual fact-backed correction will\ncompare LOCOPT-time transition graphs against GLBOPT1's reconstructed\nDAG and detect collapses that erased terminal-tail conditional returns\n(the byte5 chain ``STATE_385BBE2D -> STATE_10743C4C -> STATE_6107F8EC``\nis the motivating example: at LOCOPT the chain is encoded in pre-fold\nstate constants; by GLBOPT1 it has been collapsed to a single direct\nwrite of the eventually-reaching successor's constant).\n\nObservability-only: the collector never modifies microcode and has no\ninfluence on planning or CFG mutation.\n\nllr-3b41 S11 -- canonical-only.  A collector-local source iterator routes a\nmeta-rich :class:`~d810.ir.flowgraph.FlowGraph` block (the only shape a\nproduction fact target ever is) through ``InstructionProjection.from_block``,\nand an offline diag row carrying a parseable ``meta`` operand tree through the\nSAME canonical :func:`~d810.ir.insn_projection.project_diag_instruction`\nprojection.  ``dest_stkoff`` is read off the canonical ``Instruction.result``\nand ``src_l_value`` off the first canonical input, so a transition is anchored\non recovered stack/const semantics.  There is no meta-less fallback -- every\nproduction fact target is a canonical ``FlowGraph``.\n"
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass

from d810.capabilities.source_lifter import select_lifter
from d810.core.typing import Any, Iterable
from d810.ir.expressions import ValueOpKind
from d810.ir.instructions import Instruction
from d810.ir.insn_projection import (
    InstructionProjection,
)
from d810.ir.maturity import EARLY_FACT_COLLECTION_IR_MATURITIES
from d810.analyses.fact_collection_context import (
    FactCollectionContext,
    coerce_fact_collection_context,
    fact_provider_label,
)
from d810.analyses.value_flow.induction_carrier import (
    _canonical_opcode_name,
    _canonical_operands,
    _const_value_from_varnode,
    _reg_from_varnode,
    _stkoff_from_varnode,
    _value_op_from_instruction,
)
from d810.analyses.value_flow.state_write_anchor import (
    _block_start_ea_lookup,
    _block_succs,
    _DEST_VAR_RE,
)
from d810.analyses.value_flow.model import FactObservation


_TARGET_MATURITIES = EARLY_FACT_COLLECTION_IR_MATURITIES

# Hard cap on transit-chain walk length.  OLLVM state machines rarely
# have more than 4 transit blocks between state writes; 8 gives margin.
_MAX_TRANSIT_HOPS = 8


@dataclass(frozen=True)
class _StateTransitionInsn:
    """Uniform semantic view consumed by state_transition_anchor.

    Built solely from a canonical :class:`~d810.ir.instructions.Instruction`
    (llr-3b41 S11 deleted the legacy meta-less flat path).  Exposes ONLY the fields this collector reads -- ``dest_stkoff`` /
    ``src_l_value`` (the transition operands) plus identity/evidence fields
    (``block_serial`` / ``insn_index`` / ``ea`` / ``opcode_name`` / ``dstr``).

    For the canonical path ``dest_stkoff`` is the stack offset of
    ``Instruction.result`` (a ``Varnode`` in ``Space.STACK``; else ``None`` --
    an unknown-offset stack dest collapses to ``Varnode(UNKNOWN)`` /
    ``WeakStackSlot`` and yields ``None``, matching legacy) and ``src_l_value``
    is the const of the first canonical input (a ``Varnode`` in ``Space.CONST``;
    else ``None``).
    """

    block_serial: int
    insn_index: int
    ea: int | None
    opcode_name: str
    dstr: str
    dest_stkoff: int | None
    dest_reg: int | None
    src_l_value: int | None
    operation: ValueOpKind | None

    @classmethod
    def from_canonical(
        cls,
        *,
        block_serial: int,
        index: int,
        instruction: Instruction,
    ) -> "_StateTransitionInsn":
        dest, left, _right = _canonical_operands(instruction)
        attrs = instruction.attrs
        ea_raw = attrs.get("ea")
        return cls(
            block_serial=int(block_serial),
            insn_index=int(index),
            ea=int(ea_raw) if ea_raw is not None else None,
            opcode_name=_canonical_opcode_name(instruction),
            dstr=str(attrs.get("display_text") or ""),
            dest_stkoff=_stkoff_from_varnode(dest),
            dest_reg=_reg_from_varnode(dest),
            src_l_value=_const_value_from_varnode(left),
            operation=_value_op_from_instruction(instruction),
        )


def _iter_state_transition_insns(target: Any) -> Iterable[_StateTransitionInsn]:
    """Yield this collector's semantic record for every instruction in ``target``.

    Canonical-only (llr-3b41 S11): a meta-rich FlowGraph block is projected via
    ``InstructionProjection.from_block``; an offline diag row carrying a ``meta``
    operand tree is lifted via ``project_diag_instruction``.  The meta-less flat
    fallback was removed -- it was unreachable by any real source once every
    production fact target became a canonical ``FlowGraph``.  A registered live
    :class:`~d810.capabilities.source_lifter.SourceLifter` lifts a backend
    source to a portable flow graph first.
    """
    lifter = select_lifter(target)
    if lifter is not None:
        target = lifter.lift(target)

    blocks = getattr(target, "blocks", target)
    if isinstance(blocks, Mapping):
        block_iter = blocks.values()
    else:
        block_iter = blocks

    for blk in block_iter:
        block_serial = int(getattr(blk, "serial"))
        for index, instruction in enumerate(InstructionProjection.from_block(blk)):
            yield _StateTransitionInsn.from_canonical(
                block_serial=block_serial,
                index=index,
                instruction=instruction,
            )


def _is_state_const_write(insn: _StateTransitionInsn) -> bool:
    """Return ``True`` if ``insn`` writes a constant into state storage."""
    if insn.operation is not ValueOpKind.MOVE:
        return False
    if insn.dest_stkoff is None and insn.dest_reg is None:
        return False
    return insn.src_l_value is not None


def _state_storage_identity(insn: _StateTransitionInsn) -> tuple[str, int] | None:
    if insn.dest_stkoff is not None:
        return ("stk", int(insn.dest_stkoff))
    if insn.dest_reg is not None:
        return ("reg", int(insn.dest_reg))
    return None


def _dest_var_signature(insn: _StateTransitionInsn) -> str | None:
    """Return the ``%var_<offset>.<size>`` signature parsed from ``dstr``."""
    text = str(insn.dstr or "")
    match = _DEST_VAR_RE.search(text)
    if match is None:
        return None
    return f"%var_{match.group(1).upper()}.{match.group(2)}"


def _instruction_anchor_ea(
    insn: _StateTransitionInsn,
    block_start_ea_by_serial: dict[int, int | None],
) -> int | None:
    """Return a stable EA for an instruction.

    Falls back to ``block_start_ea + insn_index`` when ``insn.ea`` is
    zero/missing so the lifecycle has SOMETHING to correlate on.
    """
    if insn.ea is not None and int(insn.ea) != 0:
        return int(insn.ea)
    block_start = block_start_ea_by_serial.get(int(insn.block_serial))
    if block_start is None:
        return None
    return int(block_start) + int(insn.insn_index)


@dataclass(frozen=True)
class _SuccessorWalk:
    """Result of walking a source block's successor chain.

    ``successor_kind``:

    * ``direct`` -- single-successor with a state-write (1-hop).
    * ``transit`` -- single-successor chain ending in a state-write.
    * ``branch`` -- successor block has multiple successors; transit
      chain stops at the first branch (the branched arms belong to a
      conditional-transition fact, not this one).
    * ``loop`` -- chain re-entered an already-visited block.
    * ``exit`` -- chain ended at a block with no successors.
    * ``unresolved`` -- ``_MAX_TRANSIT_HOPS`` exhausted without finding a
      state-write.
    """

    successor_block: int | None
    next_state_const: int | None
    transit_blocks: tuple[int, ...]
    successor_kind: str


def _identify_canonical_state_storage(
    instructions: tuple[_StateTransitionInsn, ...],
) -> tuple[str, int] | None:
    """Return the storage identity with the most state-const writes.

    Uses simple frequency: the canonical state variable receives writes
    from every handler (often dozens of them), while byte-table or
    scratch-var writes appear once per source location.  Returns
    ``None`` when no stkoff has at least two state-const writes -- in
    that case the function is not a state-machine and there is nothing
    for this collector to observe.
    """
    counter: Counter[tuple[str, int]] = Counter()
    for insn in instructions:
        if not _is_state_const_write(insn):
            continue
        identity = _state_storage_identity(insn)
        if identity is None:
            continue
        counter[identity] += 1
    if not counter:
        return None
    # Most-written stkoff wins; ties broken by the smaller offset
    # (canonical state vars on x86_64 OLLVM are typically near the top
    # of the local frame).
    sorted_items = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    top_identity, top_count = sorted_items[0]
    if top_count < 2:
        return None
    return top_identity


def _state_const_at_block(
    instructions_by_block: dict[int, list[_StateTransitionInsn]],
    canonical_storage: tuple[str, int],
    block_serial: int,
) -> tuple[int, _StateTransitionInsn] | None:
    """Return ``(state_const, insn)`` for the first canonical state-write
    in ``block_serial``, or ``None``.
    """
    for insn in instructions_by_block.get(block_serial, ()):
        if not _is_state_const_write(insn):
            continue
        if _state_storage_identity(insn) != canonical_storage:
            continue
        const = int(insn.src_l_value or 0) & 0xFFFFFFFFFFFFFFFF
        return (const, insn)
    return None


def _walk_transit_chain(
    target: Any,
    source_block_serial: int,
    instructions_by_block: dict[int, list[_StateTransitionInsn]],
    canonical_storage: tuple[str, int],
) -> _SuccessorWalk:
    """Walk ``source_block_serial``'s successors looking for the next
    canonical state-var write.

    Returns a :class:`_SuccessorWalk` describing the result.  Single-
    successor walks only -- branches stop at ``successor_kind="branch"``
    so the conditional arms can be modeled by a different fact
    (``CONDITIONAL_TRANSITION``) when that infrastructure is added.
    """
    visited: set[int] = {source_block_serial}
    transit: list[int] = []
    cursor = source_block_serial
    for _ in range(_MAX_TRANSIT_HOPS):
        succs = _block_succs(target, cursor)
        if not succs:
            return _SuccessorWalk(
                successor_block=None,
                next_state_const=None,
                transit_blocks=tuple(transit),
                successor_kind="exit",
            )
        if len(succs) > 1:
            return _SuccessorWalk(
                successor_block=int(succs[0]),
                next_state_const=None,
                transit_blocks=tuple(transit),
                successor_kind="branch",
            )
        next_block = int(succs[0])
        if next_block in visited:
            return _SuccessorWalk(
                successor_block=next_block,
                next_state_const=None,
                transit_blocks=tuple(transit),
                successor_kind="loop",
            )
        visited.add(next_block)

        match = _state_const_at_block(
            instructions_by_block, canonical_storage, next_block
        )
        if match is not None:
            return _SuccessorWalk(
                successor_block=next_block,
                next_state_const=int(match[0]),
                transit_blocks=tuple(transit),
                successor_kind="direct" if not transit else "transit",
            )
        transit.append(next_block)
        cursor = next_block

    return _SuccessorWalk(
        successor_block=None,
        next_state_const=None,
        transit_blocks=tuple(transit),
        successor_kind="unresolved",
    )


class StateTransitionAnchorFactCollector:
    """Observe state-machine transitions at every maturity.

    For each canonical state-var write at block ``B``, walks ``B``'s
    successor chain until it finds the next canonical state-var write
    (or hits a branch / exit / loop) and emits a fact recording the
    source state constant, the chain of transit blocks, the next
    state constant (if found), and the successor kind.

    Cross-link with ``TerminalByteEmitterFact`` is intentionally NOT
    performed inside this collector; downstream consumers correlate on
    ``source_block_serial`` via
    :meth:`ValidatedFactView.terminal_byte_emit_sites_for_block` -- this
    keeps the collector strictly local-block / instruction-level and
    avoids depending on collection ordering.
    """

    name = "StateTransitionAnchorFactCollector"
    fact_kinds = frozenset({"StateTransitionAnchorFact"})
    maturities = _TARGET_MATURITIES

    def collect(
        self,
        target: Any,
        *,
        context: FactCollectionContext | None = None,
        func_ea: int | None = None,
        phase: str = "pre_d810",
        **legacy_fields: Any,
    ) -> tuple[FactObservation, ...]:
        context = coerce_fact_collection_context(
            context,
            func_ea=func_ea,
            phase=phase,
            legacy_fields=legacy_fields,
        )
        phase = context.phase
        maturity_text = fact_provider_label(context)
        instructions = tuple(_iter_state_transition_insns(target))
        if not instructions:
            return ()

        canonical_storage = _identify_canonical_state_storage(instructions)
        if canonical_storage is None:
            return ()

        instructions_by_block: dict[int, list[_StateTransitionInsn]] = {}
        for insn in instructions:
            instructions_by_block.setdefault(
                int(insn.block_serial), []
            ).append(insn)
        for items in instructions_by_block.values():
            items.sort(key=lambda i: int(i.insn_index))

        block_start_ea = _block_start_ea_lookup(target)

        observations: list[FactObservation] = []
        seen: set[tuple[int, int, int]] = set()

        for insn in instructions:
            if not _is_state_const_write(insn):
                continue
            if _state_storage_identity(insn) != canonical_storage:
                continue

            source_block = int(insn.block_serial)
            source_const = (
                int(insn.src_l_value or 0) & 0xFFFFFFFFFFFFFFFF
            )
            anchor_ea = _instruction_anchor_ea(insn, block_start_ea)
            if anchor_ea is None:
                continue
            dedupe = (source_block, int(insn.insn_index), int(anchor_ea))
            if dedupe in seen:
                continue
            seen.add(dedupe)

            walk = _walk_transit_chain(
                target,
                source_block,
                instructions_by_block,
                canonical_storage,
            )

            storage_kind, storage_offset = canonical_storage
            storage_key = (
                f"stkoff=0x{storage_offset:x}"
                if storage_kind == "stk"
                else f"reg={storage_offset}"
            )

            semantic_key = (
                f"state_transition_anchor:source_blk={source_block}:"
                f"source_const=0x{source_const:08x}:"
                f"insn={int(insn.insn_index)}:"
                f"ea=0x{int(anchor_ea):x}:"
                f"{storage_key}"
            )

            payload: dict[str, Any] = {
                "source_state_const": source_const,
                "source_state_const_hex": f"0x{source_const:08x}",
                "source_block_serial": source_block,
                "source_instruction_index": int(insn.insn_index),
                "source_instruction_ea": int(anchor_ea),
                "source_instruction_ea_hex": (
                    f"0x{int(anchor_ea) & 0xFFFFFFFFFFFFFFFF:016x}"
                ),
                "state_var_stkoff": (
                    storage_offset if storage_kind == "stk" else None
                ),
                "state_var_stkoff_hex": (
                    f"0x{storage_offset:x}" if storage_kind == "stk" else None
                ),
                "successor_block_serial": walk.successor_block,
                "next_state_const": walk.next_state_const,
                "next_state_const_hex": (
                    f"0x{walk.next_state_const:08x}"
                    if walk.next_state_const is not None
                    else None
                ),
                "transit_blocks": list(walk.transit_blocks),
                "successor_kind": walk.successor_kind,
                "dest_var_signature": _dest_var_signature(insn),
            }
            if storage_kind == "reg":
                payload["state_var_reg"] = storage_offset

            mop_target = (
                "?"
                if walk.next_state_const is None
                else f"0x{walk.next_state_const:08x}"
            )
            observations.append(
                FactObservation(
                    fact_id=semantic_key,
                    kind="StateTransitionAnchorFact",
                    semantic_key=semantic_key,
                    maturity=maturity_text,
                    phase=phase,
                    confidence=0.85,
                    source_block=source_block,
                    source_ea=int(anchor_ea),
                    block_fingerprint=(
                        f"blk[{source_block}].{int(insn.insn_index)}:"
                        f"{insn.opcode_name}"
                    ),
                    mop_signature=(
                        f"state_transition:0x{source_const:08x}->"
                        f"{mop_target}:kind={walk.successor_kind}"
                    ),
                    payload=payload,
                    evidence=(insn.dstr,),
                )
            )
        return tuple(observations)


__all__ = ["StateTransitionAnchorFactCollector"]
