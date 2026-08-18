"""Exact portable proofs for a constant carried into dispatcher state.

The admitted shape is intentionally small::

    source: CONST32 -> REGISTER/TEMP carrier -> feeder
    feeder: carrier -> exact recovered state32 -> comparison region

The source block is retained, so effects before the final exact carrier
definition are harmless.  The feeder is bypassed by unflattening and therefore
must be wholly pure.  No text, backend opcode, or live microcode is consulted.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import FlowGraph
from d810.ir.insn_projection import InstructionProjection
from d810.ir.instructions import Instruction
from d810.ir.semantics import ControlTransferKind
from d810.ir.storage_identity import (
    StorageIdentity,
    StorageIdentityKind,
    storage_identity_from_varnode,
)
from d810.ir.varnode import Space, Varnode

__all__ = [
    "ExactCarrierStateWrite",
    "expected_u32_state_identities",
    "observes_u32_carrier_feeder_candidate",
    "observes_u32_state_feeder_candidate",
    "prove_exact_u32_carrier_state_write",
]


@dataclass(frozen=True, slots=True)
class ExactCarrierStateWrite:
    """One exact source-owned U32 state value and its pure feeder."""

    state: int
    source_serial: int
    feeder_serial: int
    comparison_entry_serial: int
    carrier: Varnode
    state_identity: StorageIdentity


def expected_u32_state_identities(
    *,
    state_var_stkoff: int | None,
    state_var_reg: int | None,
) -> frozenset[StorageIdentity]:
    """Return the exact recovered storage identities admitted for U32 state."""

    identities: set[StorageIdentity] = set()
    if state_var_stkoff is not None:
        identities.add(
            StorageIdentity(StorageIdentityKind.STACK, int(state_var_stkoff))
        )
    if state_var_reg is not None:
        identities.add(
            StorageIdentity(StorageIdentityKind.REGISTER, int(state_var_reg))
        )
    return frozenset(identities)


def _pure_goto_to(instruction: Instruction, target: int) -> bool:
    control = instruction.control
    return bool(
        control is not None
        and control.transfer is ControlTransferKind.GOTO
        and (control.target is None or int(control.target) == int(target))
        and not instruction.effects
        and instruction.memory is None
        and instruction.result is None
    )


def _is_exact_const_carrier_definition(
    instruction: Instruction,
    carrier: Varnode,
) -> bool:
    return bool(
        instruction.operation is ValueOpKind.MOVE
        and not instruction.effects
        and instruction.memory is None
        and instruction.control is None
        and instruction.result == carrier
        and int(carrier.size) == 4
        and carrier.space in {Space.REGISTER, Space.TEMP}
        and len(instruction.inputs) == 1
        and instruction.inputs[0].space is Space.CONST
        and int(instruction.inputs[0].size) == 4
    )


def observes_u32_state_feeder_candidate(
    flow_graph: FlowGraph,
    feeder_serial: int,
    *,
    state_var_stkoff: int | None,
    state_var_reg: int | None,
) -> bool:
    """Return whether ``feeder`` appears to write the exact U32 state cell.

    This is an observation gate, not an acceptance proof.  Callers use it to
    distinguish a malformed carrier corridor (which must fail closed) from an
    unrelated unresolved transition.  The full corridor is still admitted
    only by :func:`prove_exact_u32_carrier_state_write`.
    """

    feeder = flow_graph.get_block(int(feeder_serial))
    expected_identities = expected_u32_state_identities(
        state_var_stkoff=state_var_stkoff,
        state_var_reg=state_var_reg,
    )
    if feeder is None or not expected_identities:
        return False
    return any(
        instruction.result is not None
        and int(instruction.result.size) == 4
        and storage_identity_from_varnode(instruction.result) in expected_identities
        for instruction in InstructionProjection.from_block(feeder)
    )


def observes_u32_carrier_feeder_candidate(
    flow_graph: FlowGraph,
    source_serial: int,
    feeder_serial: int,
) -> bool:
    """Return whether a typed U32 carrier producer/consumer pair is present.

    Destination identity, CFG shape, instruction effects, and source ordering
    are intentionally not accepted here; the complete proof checks them.  This
    predicate only prevents unrelated direct-state/goto corridors from being
    mistaken for malformed carrier idioms.
    """

    source = flow_graph.get_block(int(source_serial))
    feeder = flow_graph.get_block(int(feeder_serial))
    if source is None or feeder is None:
        return False
    carriers = frozenset(
        instruction.result
        for instruction in InstructionProjection.from_block(source)
        if instruction.operation is ValueOpKind.MOVE
        and len(instruction.inputs) == 1
        and instruction.inputs[0].space is Space.CONST
        and int(instruction.inputs[0].size) == 4
        and instruction.result is not None
        and instruction.result.space in {Space.REGISTER, Space.TEMP}
        and int(instruction.result.size) == 4
    )
    if not carriers:
        return False
    return any(
        instruction.operation is ValueOpKind.MOVE
        and len(instruction.inputs) == 1
        and instruction.inputs[0] in carriers
        and int(instruction.inputs[0].size) == 4
        and instruction.result is not None
        and int(instruction.result.size) == 4
        for instruction in InstructionProjection.from_block(feeder)
    )


def prove_exact_u32_carrier_state_write(
    flow_graph: FlowGraph,
    source_serial: int,
    feeder_serial: int,
    *,
    state_var_stkoff: int | None,
    state_var_reg: int | None,
    required_comparison_serials: frozenset[int],
) -> ExactCarrierStateWrite | None:
    """Prove one exact ``CONST32 -> carrier -> state32`` graph corridor.

    Both CFG edges are exact sole-successor edges.  The source's final carrier
    definition must be the only definition of that carrier after the last
    effect/unknown barrier, and its suffix may contain only the matching pure
    GOTO.  The feeder contains exactly the carrier-to-state MOVE and an optional
    matching pure GOTO.  Every ambiguity fails closed.
    """

    source_serial = int(source_serial)
    feeder_serial = int(feeder_serial)
    source = flow_graph.get_block(source_serial)
    feeder = flow_graph.get_block(feeder_serial)
    if source is None or feeder is None:
        return None
    if tuple(int(target) for target in source.succs) != (feeder_serial,):
        return None
    feeder_successors = tuple(int(target) for target in feeder.succs)
    if len(feeder_successors) != 1 or feeder_successors[0] not in {
        int(s) for s in required_comparison_serials
    }:
        return None
    comparison_entry = feeder_successors[0]

    expected_identities = expected_u32_state_identities(
        state_var_stkoff=state_var_stkoff,
        state_var_reg=state_var_reg,
    )
    if not expected_identities:
        return None

    feeder_instructions = InstructionProjection.from_block(feeder)
    value_instructions = tuple(
        instruction
        for instruction in feeder_instructions
        if instruction.control is None
    )
    control_instructions = tuple(
        instruction
        for instruction in feeder_instructions
        if instruction.control is not None
    )
    if len(value_instructions) != 1 or len(control_instructions) > 1:
        return None
    feeder_move = value_instructions[0]
    feeder_state_identity = (
        None
        if feeder_move.result is None
        else storage_identity_from_varnode(feeder_move.result)
    )
    if (
        feeder_move.operation is not ValueOpKind.MOVE
        or feeder_move.effects
        or feeder_move.memory is not None
        or feeder_move.result is None
        or feeder_state_identity is None
        or feeder_state_identity not in expected_identities
        or int(feeder_move.result.size) != 4
        or len(feeder_move.inputs) != 1
    ):
        return None
    carrier = feeder_move.inputs[0]
    if carrier.space not in {Space.REGISTER, Space.TEMP} or int(carrier.size) != 4:
        return None
    if control_instructions and not _pure_goto_to(
        control_instructions[0], comparison_entry
    ):
        return None
    if any(
        instruction.effects or instruction.memory is not None
        for instruction in feeder_instructions
    ):
        return None

    source_instructions = InstructionProjection.from_block(source)
    candidate_indexes = tuple(
        index
        for index, instruction in enumerate(source_instructions)
        if _is_exact_const_carrier_definition(instruction, carrier)
    )
    if not candidate_indexes:
        return None
    candidate_index = candidate_indexes[-1]

    # A control transfer before the definition makes the apparent final write
    # potentially unreachable even though the source block itself is retained.
    if any(
        instruction.control is not None
        and instruction.control.transfer is not None
        for instruction in source_instructions[:candidate_index]
    ):
        return None

    # The source remains executable, so effects before the final overwrite are
    # retained.  After it, every instruction must be the source's exact GOTO.
    if any(
        not _pure_goto_to(instruction, feeder_serial)
        for instruction in source_instructions[candidate_index + 1 :]
    ):
        return None

    last_barrier = -1
    for index, instruction in enumerate(source_instructions[:candidate_index]):
        if (
            instruction.effects
            or instruction.memory is not None
            or instruction.operation is ValueOpKind.VENDOR
            or (
                instruction.control is not None
                and not _pure_goto_to(instruction, feeder_serial)
            )
        ):
            last_barrier = index
    definitions_after_barrier = tuple(
        instruction
        for instruction in source_instructions[last_barrier + 1 : candidate_index + 1]
        if instruction.result == carrier
    )
    if len(definitions_after_barrier) != 1:
        return None
    candidate = source_instructions[candidate_index]
    if not _is_exact_const_carrier_definition(candidate, carrier):
        return None
    return ExactCarrierStateWrite(
        state=int(candidate.inputs[0].offset) & 0xFFFFFFFF,
        source_serial=source_serial,
        feeder_serial=feeder_serial,
        comparison_entry_serial=comparison_entry,
        carrier=carrier,
        state_identity=feeder_state_identity,
    )
