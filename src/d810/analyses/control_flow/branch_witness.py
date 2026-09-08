"""Exact branch-witness model for dispatcher projection.

Projection may specialize or collapse dispatcher CFG only from an exact branch
witness.  A witness proves feasibility of one arm through a dispatcher compare
block; corridor liveness/use-def proves whether shortcutting over the selected
witness blocks is legal.  ``Abstain`` always means preserve the original branch
or corridor.

d81-qlal -- canonical Instruction port.  The compare-block readers no longer
touch backend-shaped ``InsnSnapshot`` operand slots (``.l`` / ``.r`` / ``.d``).
They are strong-typed against the portable
:class:`~d810.ir.flowgraph.BlockSnapshot` and project the tail through the
canonical :func:`~d810.ir.insn_projection.project_instruction`:

* the conditional jump target (was ``tail.d.block_ref``) is read off
  ``Instruction.control.target``;
* the compared numeric constant (was ``_operand_const_value(tail.l/.r)``) is read
  off the slot-aligned :func:`~d810.ir.insn_projection.operand_storages` views
  via ``_const_value_from_varnode``;
* the state-variable operand identity (was ``tail.l/.r.stack_refs`` + storage
  identity) is read off the lift-boundary
  :func:`~d810.ir.insn_projection.operand_stack_offsets` /
  :func:`~d810.ir.insn_projection.operand_stack_refs` accessors;
* the branch predicate (was ``tail.branch_predicate``) is read off
  ``Instruction.control.predicate``.

Block topology stays direct on the typed ``FlowGraph`` / ``BlockSnapshot``.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

from d810.analyses.value_flow.induction_carrier import _const_value_from_varnode
from d810.core import logging
from d810.core.typing import Any, Protocol
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.ir.insn_projection import (
    operand_stack_offsets,
    operand_stack_refs,
    operand_storages,
    project_instruction,
)
from d810.ir.varnode import Varnode

logger = logging.getLogger("d810.analyses.control_flow.branch_witness")


class BranchPredicateKind(str, Enum):
    """The compare predicate a dispatcher branch tests.

    Was a bare ``str`` documented by an inline ``# "eq" or "ne"`` comment and
    allowlisted at one call site (:func:`_is_known_predicate`).  Any other
    string reached :func:`_evaluate_branch` and fell through to ``None``, i.e.
    a silent abstain rather than a type error.

    Members subclass ``str``, so comparisons against the bare names are
    unaffected.  Use :func:`predicate_name` where a plain ``str`` is required.
    """

    EQ = "eq"
    NE = "ne"


class BranchWitnessEvidenceKind(str, Enum):
    """How a branch-witness row was corroborated.

    The historical default, ``"validated_against_current_cfg"``, is a *claim*
    that validation happened, carried in a free-form string that any producer
    could set to anything.  Enumerating the corroborations that actually exist
    makes the claim checkable.
    """

    VALIDATED_AGAINST_CURRENT_CFG = "validated_against_current_cfg"
    LOCAL_INDIRECT_STATE_STORE_COMPARE = "local_indirect_state_store_compare"


class BranchWitnessAbstainReason(str, Enum):
    """Why projection must preserve the original branch or corridor.

    Every abstain reason this module can produce.  They are enumerated because
    an abstain reason is not merely diagnostic: at least one consumer branches
    on it by string equality to unlock a fallback
    (``minimal_unflatten_emit.py:956`` tests for
    ``SELECTED_SUCCESSOR_NOT_DISPATCHER_ENDPOINT``), which made a typo in a
    22-value string vocabulary a silent behaviour change.

    The field type stays a union with ``str`` so that callers outside this
    module -- which construct ``BranchWitnessAbstain`` from dynamic strings --
    keep working, and members subclass ``str`` so the equality tests that
    already exist continue to hold.
    """

    ABSTAIN = "abstain"
    # Row-vs-request mismatches.
    WITNESS_STATE_MISMATCH = "witness_state_mismatch"
    ROW_MISSING_COMPARE_OR_SUCCESSOR = "row_missing_compare_or_successor"
    ROW_SUCCESSORS_MISMATCH = "row_successors_mismatch"
    ROW_TARGET_MISMATCHES_ENDPOINT = "row_target_mismatches_endpoint"
    # Row-vs-current-CFG mismatches.
    COMPARE_BLOCK_ABSENT = "compare_block_absent"
    COMPARE_BLOCK_NOT_TWO_WAY = "compare_block_not_two_way"
    COMPARE_BLOCK_NOT_CONDITIONAL = "compare_block_not_conditional"
    PREDICATE_MISMATCH = "predicate_mismatch"
    UNKNOWN_PREDICATE = "unknown_predicate"
    STATE_CONSTANT_MISMATCH = "state_constant_mismatch"
    STATE_VARIABLE_MISMATCH = "state_variable_mismatch"
    SELECTED_SUCCESSOR_NOT_A_SUCCESSOR = "selected_successor_not_a_successor"
    SELECTED_SUCCESSOR_MISMATCH = "selected_successor_mismatch"
    SUCCESSOR_PARSE_FAILURE = "successor_parse_failure"
    # Chain-walk outcomes.
    STATE_UNCOVERED_BY_DISPATCHER = "state_uncovered_by_dispatcher"
    BRANCH_WITNESS_MAP_REQUIRED = "branch_witness_map_required"
    BRANCH_WITNESS_MAP_MISSING_ENTRY = "branch_witness_map_missing_entry"
    COMPARE_BLOCK_MISSING_WITNESS_ROW = "compare_block_missing_witness_row"
    COMPARE_CHAIN_CYCLE = "compare_chain_cycle"
    EMPTY_WITNESS_PATH = "empty_witness_path"
    SELECTED_SUCCESSOR_NOT_DISPATCHER_ENDPOINT = (
        "selected_successor_not_dispatcher_endpoint"
    )
    WITNESS_PATH_MISMATCHES_ENDPOINT = "witness_path_mismatches_endpoint"


def _enum_value(value: object) -> str:
    """Render an enum member as its value, anything else via ``str``.

    ``str(SomeStrEnum.MEMBER)`` returns ``"SomeStrEnum.MEMBER"``, not the
    value, so a bare ``str()`` coercion silently corrupts a field the moment a
    producer switches from a literal to a member.
    """
    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


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
    predicate: BranchPredicateKind | str
    selected_successor: int
    rejected_successors: tuple[int, ...]
    target_block: int
    proof_kind: BranchWitnessProofKind
    compare_const: int | None = None
    evidence: BranchWitnessEvidenceKind | str = (
        BranchWitnessEvidenceKind.VALIDATED_AGAINST_CURRENT_CFG
    )

    @property
    def predicate_name(self) -> str:
        """The predicate as a plain ``str``, whatever the field holds."""
        return _enum_value(self.predicate)

    @property
    def evidence_name(self) -> str:
        """The corroboration as a plain ``str``, whatever the field holds."""
        return _enum_value(self.evidence)


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
    predicate: BranchPredicateKind | str
    compare_const: int
    selected_successor: int
    rejected_successors: tuple[int, ...]
    router_kind: object | None = None
    evidence: BranchWitnessEvidenceKind | str = (
        BranchWitnessEvidenceKind.VALIDATED_AGAINST_CURRENT_CFG
    )

    @property
    def predicate_name(self) -> str:
        """The predicate as a plain ``str``, whatever the field holds."""
        return _enum_value(self.predicate)

    @property
    def evidence_name(self) -> str:
        """The corroboration as a plain ``str``, whatever the field holds."""
        return _enum_value(self.evidence)


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
            if (int(row.state) & 0xFFFFFFFF) == state_u and int(
                row.compare_block
            ) == compare_i:
                return row
        return None


@dataclass(frozen=True, slots=True)
class BranchWitnessAbstain:
    """Projection must preserve the original branch/corridor."""

    reason: BranchWitnessAbstainReason | str = BranchWitnessAbstainReason.ABSTAIN

    @property
    def reason_name(self) -> str:
        """The abstain reason as a plain ``str``, whatever the field holds."""
        return _enum_value(self.reason)


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
    ) -> ExactBranchWitness | BranchWitnessAbstain: ...


def _int_or_none(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _block_tail(block: BlockSnapshot | None) -> InsnSnapshot | None:
    """Return the block's tail instruction snapshot, or ``None``."""
    return block.tail if block is not None else None


def _compare_successors(block: BlockSnapshot) -> tuple[int | None, int | None]:
    """Return (taken, fallthrough) for a conditional block, or (None, None).

    The taken successor is read off the canonical
    ``Instruction.control.target`` (the projection populates it from the
    branch's block operand), never from the raw ``tail.d`` operand slot.
    """
    succs = tuple(int(s) for s in block.succs)
    if len(succs) != 2:
        return None, None
    tail = _block_tail(block)
    if tail is not None:
        control = project_instruction(tail).control
        jump_target = control.target if control is not None else None
        if jump_target is not None and int(jump_target) in succs:
            taken = int(jump_target)
            fallthrough = next(s for s in succs if s != taken)
            return taken, fallthrough
    # Fall back: first successor is fallthrough, second is taken.
    return succs[1], succs[0]


def _stack_offsets_for_slot(
    tail: InsnSnapshot, slot_index: int
) -> tuple[int | None, frozenset[int]]:
    """Return ``(named_offset, ref_set)`` for one compare operand slot.

    ``named_offset`` is the single stack cell the operand names (direct stack
    cell / address-of-stack / sole ref), and ``ref_set`` is every stack offset
    flattened from a possibly-nested compared sub-expression -- exactly the two
    facts the legacy ``storage_identity`` + ``stack_refs`` state-variable check
    read off the raw operand slot.
    """
    named = operand_stack_offsets(tail)[slot_index]
    refs = operand_stack_refs(tail)[slot_index]
    return named, refs


def _operand_slot_is_state_var(
    tail: InsnSnapshot, slot_index: int, state_var_stkoff: int
) -> bool:
    """Whether the compared operand at ``slot_index`` names the state variable."""
    named, refs = _stack_offsets_for_slot(tail, slot_index)
    target = int(state_var_stkoff)
    if named is not None and int(named) == target:
        return True
    return any(int(ref) == target for ref in refs)


def _predicate_value(value: object) -> str:
    """Stringify a predicate value (``PredicateKind`` or already a ``str``)."""
    return str(getattr(value, "value", value))


def _tail_predicate_value(block: BlockSnapshot) -> str | None:
    """Return the block tail's portable branch predicate as a string, else None.

    Read off the canonical ``Instruction.control.predicate`` (was
    ``tail.branch_predicate``).
    """
    tail = _block_tail(block)
    if tail is None:
        return None
    control = project_instruction(tail).control
    predicate = control.predicate if control is not None else None
    if predicate is None:
        return None
    return _predicate_value(predicate)


def _row_predicate_matches_block(row: BranchWitnessRow, block: BlockSnapshot) -> bool:
    predicate = _tail_predicate_value(block)
    if predicate is None:
        return False
    return predicate == _enum_value(row.predicate)


def _is_known_predicate(branch_kind: str) -> bool:
    """Whether the predicate is one this module can evaluate."""
    try:
        BranchPredicateKind(_enum_value(branch_kind))
    except ValueError:
        return False
    return True


def _block_compare_operands(
    block: BlockSnapshot,
) -> tuple[int | None, int | None]:
    """Return ``(compare_const, state_slot_index)`` for the tail compare.

    The numeric constant is read off the slot-aligned ``operand_storages``
    views (a ``NUMBER`` operand projects to ``Varnode(Space.CONST, value)``):
    a const on the LEFT makes the RIGHT slot the state operand and vice versa,
    mirroring the legacy left-first const probe exactly.  ``state_slot_index`` is
    ``0`` (``l``) or ``1`` (``r``) so the caller can resolve the state-variable
    identity through the canonical lift-boundary stack accessors.
    """
    tail = _block_tail(block)
    if tail is None:
        return None, None
    left, right, _dest = operand_storages(tail)
    left_vn = left if isinstance(left, Varnode) else None
    right_vn = right if isinstance(right, Varnode) else None
    const = _const_value_from_varnode(left_vn)
    state_slot_index = 1  # const on left -> state on right
    if const is None:
        const = _const_value_from_varnode(right_vn)
        state_slot_index = 0  # const on right -> state on left
    if const is None:
        return None, None
    return int(const), state_slot_index


def _evaluate_branch(
    predicate: str,
    state: int,
    compare_const: int,
    taken: int,
    fallthrough: int,
) -> tuple[int, tuple[int, ...]] | None:
    state_u = int(state) & 0xFFFFFFFF
    const_u = int(compare_const) & 0xFFFFFFFF
    if predicate == BranchPredicateKind.EQ:
        selected = int(taken) if state_u == const_u else int(fallthrough)
    elif predicate == BranchPredicateKind.NE:
        selected = int(taken) if state_u != const_u else int(fallthrough)
    else:
        return None
    rejected = int(fallthrough) if selected == int(taken) else int(taken)
    return selected, (rejected,)


def static_witness_for_state(
    flow_graph: FlowGraph,
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
        return BranchWitnessAbstain(BranchWitnessAbstainReason.WITNESS_STATE_MISMATCH)
    compare_serial = _int_or_none(row.compare_block)
    selected_serial = _int_or_none(row.selected_successor)
    if compare_serial is None or selected_serial is None:
        return BranchWitnessAbstain(
            BranchWitnessAbstainReason.ROW_MISSING_COMPARE_OR_SUCCESSOR
        )

    block = flow_graph.get_block(compare_serial)
    if block is None:
        return BranchWitnessAbstain(BranchWitnessAbstainReason.COMPARE_BLOCK_ABSENT)

    succs = tuple(int(s) for s in block.succs)
    if len(succs) != 2:
        return BranchWitnessAbstain(
            BranchWitnessAbstainReason.COMPARE_BLOCK_NOT_TWO_WAY
        )

    predicate = _enum_value(row.predicate)
    if not _is_known_predicate(predicate):
        return BranchWitnessAbstain(BranchWitnessAbstainReason.UNKNOWN_PREDICATE)

    if not _row_predicate_matches_block(row, block):
        return BranchWitnessAbstain(BranchWitnessAbstainReason.PREDICATE_MISMATCH)

    tail = _block_tail(block)
    if tail is None or not tail.is_conditional_jump:
        return BranchWitnessAbstain(
            BranchWitnessAbstainReason.COMPARE_BLOCK_NOT_CONDITIONAL
        )

    const, state_slot_index = _block_compare_operands(block)
    row_const = _int_or_none(row.compare_const)
    if (
        const is None
        or row_const is None
        or (int(const) & 0xFFFFFFFF) != (row_const & 0xFFFFFFFF)
    ):
        return BranchWitnessAbstain(BranchWitnessAbstainReason.STATE_CONSTANT_MISMATCH)

    if (
        state_var_stkoff is not None
        and state_slot_index is not None
        and not _operand_slot_is_state_var(tail, state_slot_index, state_var_stkoff)
    ):
        return BranchWitnessAbstain(BranchWitnessAbstainReason.STATE_VARIABLE_MISMATCH)

    row_rejected = tuple(int(s) for s in row.rejected_successors)
    if selected_serial not in succs:
        return BranchWitnessAbstain(
            BranchWitnessAbstainReason.SELECTED_SUCCESSOR_NOT_A_SUCCESSOR
        )
    if len(row_rejected) != 1 or set((selected_serial, *row_rejected)) != set(succs):
        return BranchWitnessAbstain(BranchWitnessAbstainReason.ROW_SUCCESSORS_MISMATCH)

    taken, fallthrough = _compare_successors(block)
    if taken is None or fallthrough is None:
        return BranchWitnessAbstain(BranchWitnessAbstainReason.SUCCESSOR_PARSE_FAILURE)

    evaluated = _evaluate_branch(predicate, state_u, row_const, taken, fallthrough)
    if evaluated is None:
        return BranchWitnessAbstain(BranchWitnessAbstainReason.UNKNOWN_PREDICATE)
    selected, rejected = evaluated
    if selected != selected_serial or rejected != row_rejected:
        return BranchWitnessAbstain(
            BranchWitnessAbstainReason.SELECTED_SUCCESSOR_MISMATCH
        )

    return ExactBranchWitness(
        state=state_u,
        compare_block=compare_serial,
        predicate=predicate,
        selected_successor=selected,
        rejected_successors=rejected,
        target_block=selected,
        proof_kind=BranchWitnessProofKind.STATIC_EQUALITY_CHAIN,
        compare_const=row_const & 0xFFFFFFFF,
        evidence=row.evidence,
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
    flow_graph: FlowGraph,
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
    flow_graph: FlowGraph,
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
        return BranchWitnessAbstain(
            BranchWitnessAbstainReason.STATE_UNCOVERED_BY_DISPATCHER
        )

    if branch_witness_map is None:
        return BranchWitnessAbstain(
            BranchWitnessAbstainReason.BRANCH_WITNESS_MAP_REQUIRED
        )

    dispatcher_blocks = frozenset(
        int(b) for b in branch_witness_map.dispatcher_blocks if b is not None
    )
    current = _int_or_none(branch_witness_map.dispatcher_entry_block)
    if current is None:
        return BranchWitnessAbstain(
            BranchWitnessAbstainReason.BRANCH_WITNESS_MAP_MISSING_ENTRY
        )

    path: list[ExactBranchWitness] = []
    visited: set[int] = set()
    while current is not None:
        if current in visited:
            return BranchWitnessAbstain(BranchWitnessAbstainReason.COMPARE_CHAIN_CYCLE)
        visited.add(current)

        row = branch_witness_map.row_for_state_compare(state_u, current)
        if row is None:
            return BranchWitnessAbstain(
                BranchWitnessAbstainReason.COMPARE_BLOCK_MISSING_WITNESS_ROW
            )

        witness = _resolve_row_witness(
            flow_graph, row, state, state_var_stkoff, emu=emu
        )
        if isinstance(witness, (BranchWitnessAbstain, BranchWitnessConflict)):
            return witness

        path.append(witness)

        if int(witness.selected_successor) == int(endpoint):
            # Last step must route to the actual endpoint handler.
            if int(witness.target_block) != int(endpoint):
                return BranchWitnessAbstain(
                    BranchWitnessAbstainReason.ROW_TARGET_MISMATCHES_ENDPOINT
                )
            break

        if int(witness.selected_successor) not in dispatcher_blocks:
            # Selected successor left the dispatcher without reaching the endpoint.
            return BranchWitnessAbstain(
                BranchWitnessAbstainReason.SELECTED_SUCCESSOR_NOT_DISPATCHER_ENDPOINT
            )

        current = int(witness.selected_successor)

    if not path:
        return BranchWitnessAbstain(BranchWitnessAbstainReason.EMPTY_WITNESS_PATH)

    # Final selected successor must be the endpoint the dispatcher routes to.
    if int(path[-1].selected_successor) != int(endpoint):
        return BranchWitnessAbstain(
            BranchWitnessAbstainReason.WITNESS_PATH_MISMATCHES_ENDPOINT
        )

    endpoint_i = int(endpoint)
    return tuple(replace(witness, target_block=endpoint_i) for witness in path)


__all__ = [
    "BranchPredicateKind",
    "BranchWitnessAbstain",
    "BranchWitnessAbstainReason",
    "BranchWitnessConflict",
    "BranchWitnessEvidenceKind",
    "BranchWitnessMap",
    "BranchWitnessProofKind",
    "BranchWitnessRow",
    "EmulationBranchWitnessCapability",
    "ExactBranchWitness",
    "resolve_exact_branch_witness",
    "static_witness_for_state",
]
