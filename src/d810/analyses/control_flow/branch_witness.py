"""Exact branch-witness model for dispatcher projection.

Projection may specialize or collapse dispatcher CFG only from an exact branch
witness.  A witness proves feasibility of one arm through a dispatcher compare
block; corridor liveness/use-def proves whether shortcutting over the selected
witness blocks is legal.  ``Abstain`` always means preserve the original branch
or corridor.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

from d810.core import logging
from d810.core.typing import Any, Protocol
from d810.ir.flowgraph import FlowGraph

logger = logging.getLogger("D810.analyses.control_flow.branch_witness")


class BranchWitnessProofKind(str, Enum):
    """Source of an exact branch-arm proof."""

    STATIC_EQUALITY_CHAIN = "static_equality_chain"
    EMULATION_EXACT = "emulation_exact"


@dataclass(frozen=True, slots=True)
class ExactBranchWitness:
    """One validated exact branch decision in a dispatcher projection.

    ``selected_successor`` is the immediate CFG successor chosen by the predicate
    under the witness state.  ``target_block`` is the semantic handler that the
    chain of witnesses ultimately reaches (for the last witness this equals
    ``selected_successor``; for intermediate chain steps it is the handler found
    after following the remaining chain).
    """

    state: int
    compare_block: int
    predicate: str  # "eq" or "ne"
    selected_successor: int
    rejected_successors: tuple[int, ...]
    target_block: int
    proof_kind: BranchWitnessProofKind
    compare_const: int | None = None
    evidence: str = "validated_against_current_cfg"


@dataclass(frozen=True, slots=True)
class BranchWitnessRow:
    """Per-state, per-compare branch-arm proof input.

    This is deliberately not a ``StateDispatcherRow``.  It describes the exact
    arm selected at one compare block for one projected state.  Endpoint routing
    remains the dispatcher's job; static branch projection consumes only this
    row model.
    """

    state: int
    compare_block: int
    predicate: str
    compare_const: int
    selected_successor: int
    rejected_successors: tuple[int, ...]
    router_kind: object | None = None
    evidence: str = "validated_against_current_cfg"


@dataclass(frozen=True, slots=True)
class BranchWitnessMap:
    """Per-compare exact branch-arm rows for one dispatcher entry."""

    rows: tuple[BranchWitnessRow, ...]
    dispatcher_entry_block: int
    dispatcher_blocks: frozenset[int]
    state_var_stkoff: int | None
    router_kind: object | None = None

    def row_for_state_compare(
        self, state: int, compare_block: int
    ) -> BranchWitnessRow | None:
        state_u = int(state) & 0xFFFFFFFF
        compare_i = int(compare_block)
        for row in self.rows:
            if (
                (int(row.state) & 0xFFFFFFFF) == state_u
                and int(row.compare_block) == compare_i
            ):
                return row
        return None


@dataclass(frozen=True, slots=True)
class BranchWitnessAbstain:
    """Projection must preserve the original branch/corridor."""

    reason: str = "abstain"


@dataclass(frozen=True, slots=True)
class BranchWitnessConflict:
    """Two exact proof sources disagree; preserve the original CFG."""

    reasons: tuple[str, ...] = ()


class EmulationBranchWitnessCapability(Protocol):
    """Optional exact branch-arm witness from emulation/concolic stepping."""

    def exact_branch_witness(
        self,
        flow_graph: FlowGraph,
        compare_block: int,
        state: int,
        state_var_stkoff: int | None,
    ) -> ExactBranchWitness | BranchWitnessAbstain:
        ...


def _int_or_none(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _compare_successors(block: object) -> tuple[int | None, int | None]:
    """Return (taken, fallthrough) for a conditional block, or (None, None)."""
    succs = tuple(int(s) for s in getattr(block, "succs", ()))
    if len(succs) != 2:
        return None, None
    tail = getattr(block, "tail", None)
    if tail is not None:
        dest = getattr(tail, "d", None)
        jump_target = _int_or_none(getattr(dest, "block_ref", None))
        if jump_target is not None and jump_target in succs:
            taken = jump_target
            fallthrough = next(s for s in succs if s != taken)
            return taken, fallthrough
    # Fall back: first successor is fallthrough, second is taken.
    return succs[1], succs[0]


def _operand_is_state_var(operand: object, state_var_stkoff: int) -> bool:
    if operand is None:
        return False
    if getattr(operand, "stkoff", None) is not None:
        return int(operand.stkoff) == int(state_var_stkoff)
    refs = getattr(operand, "stack_refs", ()) or ()
    return any(int(r) == int(state_var_stkoff) for r in refs)


def _operand_const_value(operand: object) -> int | None:
    if operand is None:
        return None
    if getattr(operand, "kind", None) is not None:
        kind_name = str(getattr(operand.kind, "value", operand.kind))
        if kind_name == "number":
            return _int_or_none(getattr(operand, "value", None))
    return _int_or_none(getattr(operand, "value", None))


def _predicate_value(value: object) -> str:
    return str(getattr(value, "value", value))


def _row_predicate_matches_block(row: BranchWitnessRow, block: object) -> bool:
    tail = getattr(block, "tail", None)
    if tail is None:
        return False
    pred = getattr(tail, "branch_predicate", None)
    return _predicate_value(pred) == str(row.predicate)


def _is_known_predicate(branch_kind: str) -> bool:
    return branch_kind in {"eq", "ne"}


def _block_compare_operands(
    block: object,
) -> tuple[int | None, object | None]:
    tail = getattr(block, "tail", None)
    if tail is None:
        return None, None
    left = getattr(tail, "l", None)
    right = getattr(tail, "r", None)
    const = _operand_const_value(left)
    state_op = right
    if const is None:
        const = _operand_const_value(right)
        state_op = left
    return const, state_op


def _evaluate_branch(
    predicate: str,
    state: int,
    compare_const: int,
    taken: int,
    fallthrough: int,
) -> tuple[int, tuple[int, ...]] | None:
    state_u = int(state) & 0xFFFFFFFF
    const_u = int(compare_const) & 0xFFFFFFFF
    if predicate == "eq":
        selected = int(taken) if state_u == const_u else int(fallthrough)
    elif predicate == "ne":
        selected = int(taken) if state_u != const_u else int(fallthrough)
    else:
        return None
    rejected = int(fallthrough) if selected == int(taken) else int(taken)
    return selected, (rejected,)


def static_witness_for_state(
    flow_graph: object,
    row: BranchWitnessRow,
    state: int,
    state_var_stkoff: int | None,
) -> ExactBranchWitness | BranchWitnessAbstain:
    """Return an exact static witness for ``state`` at ``row.compare_block``.

    Validates the recovered row against the current ``FlowGraph``.  Any mismatch
    returns ``BranchWitnessAbstain`` so projection preserves the original CFG.
    """
    state_u = int(state) & 0xFFFFFFFF
    row_state = _int_or_none(row.state)
    if row_state is None or (row_state & 0xFFFFFFFF) != state_u:
        return BranchWitnessAbstain("witness_state_mismatch")
    compare_serial = _int_or_none(row.compare_block)
    selected_serial = _int_or_none(row.selected_successor)
    if compare_serial is None or selected_serial is None:
        return BranchWitnessAbstain("row_missing_compare_or_successor")

    block = flow_graph.get_block(compare_serial)
    if block is None:
        return BranchWitnessAbstain("compare_block_absent")

    succs = tuple(int(s) for s in getattr(block, "succs", ()))
    if len(succs) != 2:
        return BranchWitnessAbstain("compare_block_not_two_way")

    predicate = str(row.predicate)
    if not _is_known_predicate(predicate):
        return BranchWitnessAbstain("unknown_predicate")

    if not _row_predicate_matches_block(row, block):
        return BranchWitnessAbstain("predicate_mismatch")

    tail = getattr(block, "tail", None)
    if tail is None or not getattr(tail, "is_conditional_jump", False):
        return BranchWitnessAbstain("compare_block_not_conditional")

    const, state_op = _block_compare_operands(block)
    row_const = _int_or_none(row.compare_const)
    if const is None or row_const is None or (int(const) & 0xFFFFFFFF) != (row_const & 0xFFFFFFFF):
        return BranchWitnessAbstain("state_constant_mismatch")

    if state_var_stkoff is not None and not _operand_is_state_var(state_op, state_var_stkoff):
        return BranchWitnessAbstain("state_variable_mismatch")

    row_rejected = tuple(int(s) for s in getattr(row, "rejected_successors", ()))
    if selected_serial not in succs:
        return BranchWitnessAbstain("selected_successor_not_a_successor")
    if len(row_rejected) != 1 or set((selected_serial, *row_rejected)) != set(succs):
        return BranchWitnessAbstain("row_successors_mismatch")

    taken, fallthrough = _compare_successors(block)
    if taken is None or fallthrough is None:
        return BranchWitnessAbstain("successor_parse_failure")

    evaluated = _evaluate_branch(predicate, state_u, row_const, taken, fallthrough)
    if evaluated is None:
        return BranchWitnessAbstain("unknown_predicate")
    selected, rejected = evaluated
    if selected != selected_serial or rejected != row_rejected:
        return BranchWitnessAbstain("selected_successor_mismatch")

    return ExactBranchWitness(
        state=state_u,
        compare_block=compare_serial,
        predicate=predicate,
        selected_successor=selected,
        rejected_successors=rejected,
        target_block=selected,
        proof_kind=BranchWitnessProofKind.STATIC_EQUALITY_CHAIN,
        compare_const=row_const & 0xFFFFFFFF,
        evidence=str(row.evidence),
    )


def _witnesses_conflict(
    static: ExactBranchWitness,
    emulated: ExactBranchWitness,
) -> tuple[str, ...]:
    reasons: list[str] = []
    fields = (
        "compare_block",
        "predicate",
        "selected_successor",
        "rejected_successors",
        "target_block",
        "compare_const",
    )
    for field in fields:
        if getattr(static, field) != getattr(emulated, field):
            reasons.append(
                f"{field}:static={getattr(static, field)!r}:"
                f"emulated={getattr(emulated, field)!r}"
            )
    return tuple(reasons)


def _resolve_row_witness(
    flow_graph: object,
    row: BranchWitnessRow,
    state: int,
    state_var_stkoff: int | None,
    *,
    emu: EmulationBranchWitnessCapability | None,
) -> ExactBranchWitness | BranchWitnessAbstain | BranchWitnessConflict:
    static = static_witness_for_state(flow_graph, row, state, state_var_stkoff)
    if emu is None:
        return static

    compare_block = _int_or_none(row.compare_block)
    if compare_block is None:
        return static

    emulated = emu.exact_branch_witness(
        flow_graph, compare_block, state, state_var_stkoff
    )
    if isinstance(static, ExactBranchWitness) and isinstance(
        emulated, ExactBranchWitness
    ):
        conflict_reasons = _witnesses_conflict(static, emulated)
        if conflict_reasons:
            return BranchWitnessConflict(conflict_reasons)
        return static
    if isinstance(static, ExactBranchWitness):
        return static
    if isinstance(emulated, ExactBranchWitness):
        return emulated
    return static


def resolve_exact_branch_witness(
    flow_graph: object,
    dispatcher: object,
    state: int,
    state_var_stkoff: int | None,
    *,
    emu: EmulationBranchWitnessCapability | None = None,
    branch_witness_map: BranchWitnessMap | None = None,
    live_block_for: Any | None = None,
) -> tuple[ExactBranchWitness, ...] | BranchWitnessAbstain | BranchWitnessConflict:
    """Resolve an exact branch-witness path for ``state``.

    Static equality-chain validation is tried first.  If it abstains, an optional
    ``EmulationBranchWitnessCapability`` is consulted.  If the two disagree, a
    ``BranchWitnessConflict`` is returned and the caller must preserve the CFG.

    ``dispatcher.lookup(state)`` is used only as the endpoint sanity check.  The
    witness path is built from explicit per-compare ``BranchWitnessRow`` values,
    never from endpoint-style ``StateDispatcherMap`` rows.
    """
    del live_block_for  # reserved for future concolic/live-block stepping
    state_u = int(state) & 0xFFFFFFFF
    endpoint = dispatcher.lookup(state_u)
    if endpoint is None:
        return BranchWitnessAbstain("state_uncovered_by_dispatcher")

    if branch_witness_map is None:
        return BranchWitnessAbstain("branch_witness_map_required")

    dispatcher_blocks = frozenset(
        int(b) for b in getattr(branch_witness_map, "dispatcher_blocks", ()) if b is not None
    )
    current = _int_or_none(branch_witness_map.dispatcher_entry_block)
    if current is None:
        return BranchWitnessAbstain("branch_witness_map_missing_entry")

    path: list[ExactBranchWitness] = []
    visited: set[int] = set()
    while current is not None:
        if current in visited:
            return BranchWitnessAbstain("compare_chain_cycle")
        visited.add(current)

        row = branch_witness_map.row_for_state_compare(state_u, current)
        if row is None:
            return BranchWitnessAbstain("compare_block_missing_witness_row")

        witness = _resolve_row_witness(
            flow_graph, row, state, state_var_stkoff, emu=emu
        )
        if isinstance(witness, (BranchWitnessAbstain, BranchWitnessConflict)):
            return witness

        path.append(witness)

        if int(witness.selected_successor) == int(endpoint):
            # Last step must route to the actual endpoint handler.
            if int(witness.target_block) != int(endpoint):
                return BranchWitnessAbstain("row_target_mismatches_endpoint")
            break

        if int(witness.selected_successor) not in dispatcher_blocks:
            # Selected successor left the dispatcher without reaching the endpoint.
            return BranchWitnessAbstain("selected_successor_not_dispatcher_endpoint")

        current = int(witness.selected_successor)

    if not path:
        return BranchWitnessAbstain("empty_witness_path")

    # Final selected successor must be the endpoint the dispatcher routes to.
    if int(path[-1].selected_successor) != int(endpoint):
        return BranchWitnessAbstain("witness_path_mismatches_endpoint")

    endpoint_i = int(endpoint)
    return tuple(replace(witness, target_block=endpoint_i) for witness in path)


__all__ = [
    "BranchWitnessAbstain",
    "BranchWitnessConflict",
    "BranchWitnessMap",
    "BranchWitnessProofKind",
    "BranchWitnessRow",
    "EmulationBranchWitnessCapability",
    "ExactBranchWitness",
    "resolve_exact_branch_witness",
    "static_witness_for_state",
]
