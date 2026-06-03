"""Stack-slot reaching-defs / liveness over a portable ``FlowGraph`` (Slice 1b).

The bridge from the portable IR to the Slice-1 lattices: read each
instruction's operand snapshots (``d`` = definition, ``l``/``r`` = uses) and
emit the per-block gen/kill (reaching) and use/def (liveness) facts the
:class:`ReachingDefsDomain` / :class:`LivenessDomain` consume, restricted to a
set of tracked stack offsets (the return-slot carrier, the real carrier such as
``a5+0xD0``, and the dispatcher state variable) so the lattices stay small.

No IDA: the ``FlowGraph`` is already a backend-neutral snapshot; the Hex-Rays
lift that builds it lives upstream. ``analyze_return_carrier`` runs both domains
and answers the carrier-delivery question for one terminal:

* which definitions of the return slot reach the terminal,
* whether the real carrier dominates it (a value is available to deliver),
* whether the dispatcher state variable is dead there (its entry-default write
  is removable).
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Iterable, Mapping, Optional
from d810.analyses.data_flow.configuration import Direction, FixpointConfiguration
from d810.analyses.data_flow.worklist import run_fixpoint
from d810.analyses.value_flow.liveness import BlockLivenessFacts, LivenessDomain
from d810.analyses.value_flow.reaching_defs import (
    BlockReachingFacts,
    ReachingDefsDomain,
    reaching_defs_of,
)

__all__ = [
    "CarrierVerdict",
    "analyze_return_carrier",
    "build_liveness_facts",
    "build_reaching_facts",
]


def _operand_stkoff(operand: object, tracked: set[int]) -> Optional[int]:
    """Return ``operand``'s stack offset if it is one of ``tracked``."""
    if operand is None:
        return None
    off = getattr(operand, "stkoff", None)
    if off is None:
        return None
    off = int(off)
    return off if off in tracked else None


def build_reaching_facts(
    flow_graph: object, tracked: Iterable[int]
) -> dict[int, BlockReachingFacts]:
    """Per-block reaching-def gen/kill for the tracked stack offsets."""
    tracked_set = {int(off) for off in tracked}
    facts: dict[int, BlockReachingFacts] = {}
    for serial, blk in flow_graph.blocks.items():
        gen: dict[int, set] = {}
        for insn in blk.insn_snapshots:
            dest = _operand_stkoff(getattr(insn, "d", None), tracked_set)
            if dest is not None:
                gen.setdefault(dest, set()).add((int(serial), int(insn.ea)))
        if gen:
            facts[int(serial)] = BlockReachingFacts(
                gen={loc: frozenset(sites) for loc, sites in gen.items()}
            )
    return facts


def build_liveness_facts(
    flow_graph: object, tracked: Iterable[int]
) -> dict[int, BlockLivenessFacts]:
    """Per-block use/def sets (block-granular) for the tracked stack offsets.

    ``used`` is upward-exposed (read before any redefinition in the block);
    ``defined`` is every tracked location written by the block (the kill set).
    """
    tracked_set = {int(off) for off in tracked}
    facts: dict[int, BlockLivenessFacts] = {}
    for serial, blk in flow_graph.blocks.items():
        used: set[int] = set()
        defined: set[int] = set()
        for insn in blk.insn_snapshots:
            for src in (getattr(insn, "l", None), getattr(insn, "r", None)):
                off = _operand_stkoff(src, tracked_set)
                if off is not None and off not in defined:
                    used.add(off)
            dest = _operand_stkoff(getattr(insn, "d", None), tracked_set)
            if dest is not None:
                defined.add(dest)
        if used or defined:
            facts[int(serial)] = BlockLivenessFacts(
                used=frozenset(used), defined=frozenset(defined)
            )
    return facts


@dataclass(frozen=True, slots=True)
class CarrierVerdict:
    """Reaching-defs / liveness answer at one return terminal."""

    return_reaching: frozenset
    carrier_dominates: bool
    state_dead: bool


def analyze_return_carrier(
    flow_graph: object,
    *,
    return_off: int,
    carrier_off: int,
    state_off: int,
    terminal_serial: int,
    exit_serials: Optional[Iterable[int]] = None,
    live_at_exit: Optional[Iterable[int]] = None,
) -> CarrierVerdict:
    """Run reaching-defs + liveness and report the carrier verdict at a terminal."""
    tracked = {int(return_off), int(carrier_off), int(state_off)}
    nodes = list(flow_graph.blocks)
    if exit_serials is None:
        exit_serials = [s for s in nodes if not tuple(flow_graph.successors(s))]
    if live_at_exit is None:
        live_at_exit = {int(return_off)}

    reaching = run_fixpoint(
        ReachingDefsDomain(build_reaching_facts(flow_graph, tracked)),
        nodes=nodes,
        entry_nodes=[flow_graph.entry_serial],
        successors_of=flow_graph.successors,
        predecessors_of=flow_graph.predecessors,
        config=FixpointConfiguration(direction=Direction.FORWARD),
        raise_on_nonconvergence=True,
    )
    live = run_fixpoint(
        LivenessDomain(build_liveness_facts(flow_graph, tracked)),
        nodes=nodes,
        entry_nodes=list(exit_serials),
        entry_state=frozenset(int(o) for o in live_at_exit),
        successors_of=flow_graph.successors,
        predecessors_of=flow_graph.predecessors,
        config=FixpointConfiguration(direction=Direction.BACKWARD),
        raise_on_nonconvergence=True,
    )

    in_terminal = reaching.in_states[int(terminal_serial)]
    return CarrierVerdict(
        return_reaching=reaching_defs_of(in_terminal, int(return_off)),
        carrier_dominates=bool(reaching_defs_of(in_terminal, int(carrier_off))),
        state_dead=int(state_off) not in live.out_states[int(terminal_serial)],
    )
