"""State-transition anchor fact collector.

This collector observes LOCOPT-time state-machine transitions before
IDA's MMAT_CALLS pass folds transit-state chains into direct writes.

For each ``mov #const, %var_<canonical_state_var>`` write at block B,
the collector walks B's direct successors to find the next block that
writes the same state variable, and records the implied transition.

This is the natural follow-up to :class:`StateWriteAnchorFactCollector`:
anchors record per-block constants; transitions record the chain edges
between those constants.  Recon's eventual fact-backed correction will
compare LOCOPT-time transition graphs against GLBOPT1's reconstructed
DAG and detect collapses that erased terminal-tail conditional returns
(the byte5 chain ``STATE_385BBE2D -> STATE_10743C4C -> STATE_6107F8EC``
is the motivating example: at LOCOPT the chain is encoded in pre-fold
state constants; by GLBOPT1 it has been collapsed to a single direct
write of the eventually-reaching successor's constant).

Observability-only: the collector never modifies microcode and has no
influence on planning or CFG mutation.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from d810.core.typing import Any
from d810.analyses.value_flow.induction_carrier import (
    _MATURITY_VALUES,
    _InstructionView,
    _iter_instruction_views,
    _maturity_name,
)
from d810.analyses.value_flow.state_write_anchor import (
    _block_start_ea_lookup,
    _block_succs,
    _dest_var_signature,
    _instruction_anchor_ea,
    _is_state_const_write,
)
from d810.analyses.value_flow.model import FactObservation


_TARGET_MATURITIES = frozenset({
    _MATURITY_VALUES["MMAT_PREOPTIMIZED"],
    _MATURITY_VALUES["MMAT_LOCOPT"],
    _MATURITY_VALUES["MMAT_CALLS"],
    _MATURITY_VALUES["MMAT_GLBOPT1"],
})

# Hard cap on transit-chain walk length.  OLLVM state machines rarely
# have more than 4 transit blocks between state writes; 8 gives margin.
_MAX_TRANSIT_HOPS = 8


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


def _identify_canonical_state_var_stkoff(
    instructions: tuple[_InstructionView, ...],
) -> int | None:
    """Return the stkoff with the most state-const writes.

    Uses simple frequency: the canonical state variable receives writes
    from every handler (often dozens of them), while byte-table or
    scratch-var writes appear once per source location.  Returns
    ``None`` when no stkoff has at least two state-const writes -- in
    that case the function is not a state-machine and there is nothing
    for this collector to observe.
    """
    counter: Counter[int] = Counter()
    for insn in instructions:
        if not _is_state_const_write(insn):
            continue
        if insn.dest_stkoff is None:
            continue
        counter[int(insn.dest_stkoff)] += 1
    if not counter:
        return None
    # Most-written stkoff wins; ties broken by the smaller offset
    # (canonical state vars on x86_64 OLLVM are typically near the top
    # of the local frame).
    sorted_items = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    top_stkoff, top_count = sorted_items[0]
    if top_count < 2:
        return None
    return int(top_stkoff)


def _state_const_at_block(
    instructions_by_block: dict[int, list[_InstructionView]],
    canonical_stkoff: int,
    block_serial: int,
) -> tuple[int, _InstructionView] | None:
    """Return ``(state_const, insn)`` for the first canonical state-write
    in ``block_serial``, or ``None``.
    """
    for insn in instructions_by_block.get(block_serial, ()):
        if not _is_state_const_write(insn):
            continue
        if int(insn.dest_stkoff or -1) != canonical_stkoff:
            continue
        const = int(insn.src_l_value or 0) & 0xFFFFFFFFFFFFFFFF
        return (const, insn)
    return None


def _walk_transit_chain(
    target: Any,
    source_block_serial: int,
    instructions_by_block: dict[int, list[_InstructionView]],
    canonical_stkoff: int,
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
            instructions_by_block, canonical_stkoff, next_block
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
        func_ea: int,
        maturity: int,
        phase: str,
    ) -> tuple[FactObservation, ...]:
        maturity_text = _maturity_name(maturity)
        instructions = tuple(_iter_instruction_views(target))
        if not instructions:
            return ()

        canonical_stkoff = _identify_canonical_state_var_stkoff(instructions)
        if canonical_stkoff is None:
            return ()

        instructions_by_block: dict[int, list[_InstructionView]] = {}
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
            if int(insn.dest_stkoff or -1) != canonical_stkoff:
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
                canonical_stkoff,
            )

            semantic_key = (
                f"state_transition_anchor:source_blk={source_block}:"
                f"source_const=0x{source_const:08x}:"
                f"insn={int(insn.insn_index)}:"
                f"ea=0x{int(anchor_ea):x}:"
                f"stkoff=0x{canonical_stkoff:x}"
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
                "state_var_stkoff": canonical_stkoff,
                "state_var_stkoff_hex": f"0x{canonical_stkoff:x}",
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
