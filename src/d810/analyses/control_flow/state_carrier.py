"""Exact portable proofs for a constant carried into dispatcher state.

The admitted shapes are intentionally small::

    source: CONST32 -> REGISTER/TEMP carrier -> feeder
    feeder: carrier -> exact recovered state32 -> comparison region

or a bounded expression variant where exact source-owned CONST32 register/temp
definitions feed a pure canonical XOR/ADD/SUB program into recovered state32.

The source block is retained, so effects before the final exact carrier
definition are harmless.  A wholly pure feeder may be bypassed.  A feeder with
a bounded pure semantic MOVE suffix is instead marked for predecessor-local
cloning so its body remains executable.  No text, backend opcode, or live
microcode is consulted.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.value_flow.state_write import (
    forward_eval_instruction,
    isolate_temporaries_for_forward_evaluation,
    resolve_varnode_from_maps,
)
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
    "ExactStateTransformFeeder",
    "expected_u32_state_identities",
    "observes_u32_carrier_feeder_candidate",
    "observes_u32_state_feeder_candidate",
    "observes_u32_state_transform_feeder_candidate",
    "prove_exact_u32_carrier_state_write",
    "prove_exact_u32_state_transform_feeder",
]


@dataclass(frozen=True, slots=True)
class ExactCarrierStateWrite:
    """One exact source-owned U32 state value and its bound feeder."""

    state: int
    source_serial: int
    feeder_serial: int
    comparison_entry_serial: int
    carrier: Varnode
    state_identity: StorageIdentity
    requires_feeder_clone: bool = False


@dataclass(frozen=True, slots=True)
class ExactStateTransformFeeder:
    """One exact bounded U32 expression into recovered state."""

    state: int
    source_serial: int
    feeder_serial: int
    comparison_entry_serial: int
    operation: ValueOpKind
    left: Varnode
    right: Varnode
    program: tuple[Instruction, ...]
    source_bindings: tuple[tuple[Varnode, int], ...]
    state_identity: StorageIdentity
    source_ea: int
    feeder_ea: int
    comparison_entry_ea: int
    state_feeder_serial: int | None = None
    state_feeder_ea: int | None = None


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


def observes_u32_state_transform_feeder_candidate(
    flow_graph: FlowGraph,
    feeder_serial: int,
) -> bool:
    """Observe a binary value write that may be a state-transform feeder.

    This intentionally recognizes unsupported or malformed binary writes too:
    once the corridor shape is observed, the exact proof must either validate
    the whole feeder or fail closed.  It is not route authority by itself.
    """

    feeder = flow_graph.get_block(int(feeder_serial))
    if feeder is None:
        return False
    return any(
        instruction.control is None
        and instruction.result is not None
        and len(instruction.inputs) == 2
        for instruction in InstructionProjection.from_block(feeder)
    )


def _stable_block_ea(flow_graph: FlowGraph, serial: int) -> int | None:
    block = flow_graph.get_block(int(serial))
    if block is None:
        return None
    ea = int(
        block.native_start_ea if block.native_start_ea is not None else block.start_ea
    )
    return ea if 0 < ea < 0xFFFFFFFFFFFFFFFF else None


def _exact_const_definition(
    instruction: Instruction,
    destination: Varnode,
) -> bool:
    return bool(
        instruction.operation is ValueOpKind.MOVE
        and instruction.control is None
        and instruction.memory is None
        and not instruction.effects
        and instruction.result == destination
        and destination.space in {Space.REGISTER, Space.TEMP}
        and int(destination.size) == 4
        and len(instruction.inputs) == 1
        and instruction.inputs[0].space is Space.CONST
        and int(instruction.inputs[0].size) == 4
    )


_STATE_TRANSFORM_VALUE_OPS = frozenset(
    {ValueOpKind.XOR, ValueOpKind.ADD, ValueOpKind.SUB}
)
_MAX_STATE_TRANSFORM_VALUE_INSTRUCTIONS = 3


def _is_exact_u32_value_instruction(instruction: Instruction) -> bool:
    return bool(
        instruction.operation in _STATE_TRANSFORM_VALUE_OPS
        and instruction.control is None
        and instruction.memory is None
        and not instruction.effects
        and instruction.result is not None
        and int(instruction.result.size) == 4
        and len(instruction.inputs) == 2
        and instruction.inputs[0] != instruction.inputs[1]
        and all(
            operand.space in {Space.REGISTER, Space.TEMP} and int(operand.size) == 4
            for operand in instruction.inputs
        )
    )


def prove_exact_u32_state_transform_feeder(
    flow_graph: FlowGraph,
    source_serial: int,
    feeder_serial: int,
    *,
    state_var_stkoff: int | None,
    state_var_reg: int | None,
    required_comparison_serials: frozenset[int],
    expected_state: int | None,
) -> ExactStateTransformFeeder | None:
    """Prove ``CONST32 definitions -> bounded pure expression -> state32``.

    The expression is a canonical U32 XOR/ADD/SUB program of at most three
    value instructions.  Every external input has one exact constant
    definition in the direct source block; canonical evaluation is delegated
    to the shared portable forward evaluator.  Operand order is preserved.
    Both graph edges are reciprocal sole edges, and neither the selected source
    suffix nor the feeder may contain an unproved instruction or effect.
    """

    source_serial = int(source_serial)
    feeder_serial = int(feeder_serial)
    source = flow_graph.get_block(source_serial)
    feeder = flow_graph.get_block(feeder_serial)
    source_ea = _stable_block_ea(flow_graph, source_serial)
    feeder_ea = _stable_block_ea(flow_graph, feeder_serial)
    if source is None or feeder is None or source_ea is None or feeder_ea is None:
        return None
    if tuple(int(target) for target in source.succs) != (feeder_serial,):
        return None
    if source_serial not in tuple(int(pred) for pred in feeder.preds):
        return None
    feeder_successors = tuple(int(target) for target in feeder.succs)
    if len(feeder_successors) != 1:
        return None
    required_comparisons = {int(s) for s in required_comparison_serials}
    comparison_entry = feeder_successors[0]
    state_feeder_serial: int | None = None
    state_feeder_ea: int | None = None
    state_feeder: object | None = None
    if comparison_entry not in required_comparisons:
        state_feeder_serial = comparison_entry
        state_feeder = flow_graph.get_block(state_feeder_serial)
        state_feeder_ea = _stable_block_ea(flow_graph, state_feeder_serial)
        if (
            state_feeder is None
            or state_feeder_ea is None
            or feeder_serial
            not in tuple(int(pred) for pred in state_feeder.preds)
            or len(state_feeder.succs) != 1
        ):
            return None
        comparison_entry = int(state_feeder.succs[0])
        if comparison_entry not in required_comparisons:
            return None
    comparison = flow_graph.get_block(comparison_entry)
    comparison_ea = _stable_block_ea(flow_graph, comparison_entry)
    if (
        comparison is None
        or comparison_ea is None
        or (
            state_feeder_serial if state_feeder_serial is not None else feeder_serial
        )
        not in tuple(int(pred) for pred in comparison.preds)
    ):
        return None

    expected_identities = expected_u32_state_identities(
        state_var_stkoff=state_var_stkoff,
        state_var_reg=state_var_reg,
    )
    if not expected_identities:
        return None

    feeder_instructions = InstructionProjection.from_block(feeder)
    values = tuple(
        insn
        for insn in feeder_instructions
        if isinstance(insn.operation, ValueOpKind) and insn.control is None
    )
    controls = tuple(insn for insn in feeder_instructions if insn.control is not None)
    if not 1 <= len(values) <= _MAX_STATE_TRANSFORM_VALUE_INSTRUCTIONS:
        return None
    if len(controls) > 1 or len(values) + len(controls) != len(feeder_instructions):
        return None
    if any(not _is_exact_u32_value_instruction(insn) for insn in values):
        return None
    if controls and feeder_instructions[-1] is not controls[0]:
        return None
    transform = values[-1]
    state_move: Instruction | None = None
    if state_feeder is not None:
        state_feeder_instructions = InstructionProjection.from_block(state_feeder)
        state_value_instructions = tuple(
            instruction
            for instruction in state_feeder_instructions
            if instruction.control is None
        )
        state_controls = tuple(
            instruction
            for instruction in state_feeder_instructions
            if instruction.control is not None
        )
        if (
            len(state_value_instructions) != 1
            or len(state_controls) > 1
            or len(state_value_instructions) + len(state_controls)
            != len(state_feeder_instructions)
            or (state_controls and state_feeder_instructions[-1] is not state_controls[0])
            or (
                state_controls
                and not _pure_goto_to(state_controls[0], comparison_entry)
            )
        ):
            return None
        state_move = state_value_instructions[0]
        if (
            state_move.operation is not ValueOpKind.MOVE
            or state_move.effects
            or state_move.memory is not None
            or len(state_move.inputs) != 1
            or state_move.inputs[0] != transform.result
            or state_move.result is None
            or int(state_move.result.size) != 4
        ):
            return None
        state_identity = storage_identity_from_varnode(state_move.result)
    else:
        state_identity = (
            None
            if transform.result is None
            else storage_identity_from_varnode(transform.result)
        )
    if (
        transform.result is None
        or int(transform.result.size) != 4
        or state_identity not in expected_identities
        or len(transform.inputs) != 2
    ):
        return None
    if state_move is not None and transform.result.space not in {
        Space.REGISTER,
        Space.TEMP,
    }:
        return None
    left, right = transform.inputs
    if controls and not _pure_goto_to(controls[0], comparison_entry):
        return None

    producer_indexes: dict[Varnode, int] = {}
    for index, instruction in enumerate(values):
        result = instruction.result
        if result is None or result in producer_indexes:
            return None
        if (
            instruction is not transform
            and storage_identity_from_varnode(result) in expected_identities
        ):
            return None
        producer_indexes[result] = index
    if any(
        producer_indexes.get(operand, -1) > index
        for index, instruction in enumerate(values)
        for operand in instruction.inputs
        if operand in producer_indexes
    ):
        return None
    if any(
        sum(result in later.inputs for later in values[index + 1 :]) != 1
        for index, result in enumerate(
            instruction.result for instruction in values[:-1]
        )
    ):
        return None

    external_operands = frozenset(
        operand
        for index, instruction in enumerate(values)
        for operand in instruction.inputs
        if producer_indexes.get(operand, index) >= index
    )
    if not external_operands:
        return None
    source_instructions = InstructionProjection.from_block(source)
    selected: dict[Varnode, int] = {}
    for operand in external_operands:
        indexes = tuple(
            index
            for index, instruction in enumerate(source_instructions)
            if _exact_const_definition(instruction, operand)
        )
        if len(indexes) != 1:
            return None
        selected[operand] = indexes[0]
    selected_indexes = frozenset(selected.values())
    if len(selected_indexes) != len(external_operands):
        return None
    first_definition = min(selected_indexes)
    for index, instruction in enumerate(source_instructions[first_definition:]):
        absolute_index = first_definition + index
        if absolute_index in selected_indexes:
            continue
        if not _pure_goto_to(instruction, feeder_serial):
            return None
    control_indexes = tuple(
        index
        for index, instruction in enumerate(source_instructions)
        if instruction.control is not None
    )
    if len(control_indexes) > 1 or (
        control_indexes and control_indexes[0] < max(selected_indexes)
    ):
        return None

    ordered_definitions = tuple(
        (operand, source_instructions[index])
        for operand, index in sorted(selected.items(), key=lambda item: item[1])
    )
    evaluation_program = values + (() if state_move is None else (state_move,))
    proof_sequence, _ = isolate_temporaries_for_forward_evaluation(
        tuple(instruction for _, instruction in ordered_definitions)
        + evaluation_program,
        occupied_register_offsets=frozenset(
            int(value.offset)
            for instruction in (
                tuple(instruction for _, instruction in ordered_definitions)
                + evaluation_program
            )
            for value in (*instruction.inputs, instruction.result)
            if value is not None and value.space is Space.REGISTER
        ),
    )
    shadow_definitions = proof_sequence[: len(ordered_definitions)]
    shadow_program = proof_sequence[len(ordered_definitions) :]

    stk_map: dict[int, int] = {}
    reg_map: dict[int, int] = {}
    evaluator_state_stkoff = (
        int(state_var_stkoff) if state_var_stkoff is not None else 0
    )
    source_bindings: list[tuple[Varnode, int]] = []
    for (operand, instruction), proof_instruction in zip(
        ordered_definitions,
        shadow_definitions,
        strict=True,
    ):
        expected_value = int(instruction.inputs[0].offset) & 0xFFFFFFFF
        forward_eval_instruction(
            proof_instruction,
            stk_map,
            reg_map,
            evaluator_state_stkoff,
        )
        resolved = resolve_varnode_from_maps(
            proof_instruction.result,
            stk_map,
            reg_map,
        )
        if resolved is None or (int(resolved) & 0xFFFFFFFF) != expected_value:
            return None
        source_bindings.append((operand, expected_value))

    state: int | None = None
    for instruction, proof_instruction in zip(
        evaluation_program,
        shadow_program,
        strict=True,
    ):
        if any(
            resolve_varnode_from_maps(operand, stk_map, reg_map) is None
            for operand in proof_instruction.inputs
        ):
            return None
        evaluated_state = forward_eval_instruction(
            proof_instruction,
            stk_map,
            reg_map,
            evaluator_state_stkoff,
        )
        result = proof_instruction.result
        if result is None:
            return None
        resolved = resolve_varnode_from_maps(result, stk_map, reg_map)
        if resolved is None:
            return None
        if instruction is transform or instruction is state_move:
            state = int(resolved) & 0xFFFFFFFF
            if (
                instruction.result is not None
                and instruction.result.space is Space.STACK
                and evaluated_state != state
            ):
                return None
    if state is None:
        return None
    if expected_state is not None and state != (int(expected_state) & 0xFFFFFFFF):
        return None
    return ExactStateTransformFeeder(
        state=state,
        source_serial=source_serial,
        feeder_serial=feeder_serial,
        comparison_entry_serial=comparison_entry,
        operation=transform.operation,
        left=left,
        right=right,
        program=tuple(evaluation_program),
        source_bindings=tuple(source_bindings),
        state_identity=state_identity,
        source_ea=source_ea,
        feeder_ea=feeder_ea,
        comparison_entry_ea=comparison_ea,
        state_feeder_serial=state_feeder_serial,
        state_feeder_ea=state_feeder_ea,
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
    GOTO.  The feeder starts with exactly the carrier-to-state MOVE and may then
    contain a bounded pure non-state MOVE suffix plus an optional matching GOTO.
    Such a suffix is not bypass authority: the returned receipt requires the
    emitter to clone the feeder for this predecessor.  Every ambiguity fails
    closed.
    """

    source_serial = int(source_serial)
    feeder_serial = int(feeder_serial)
    source = flow_graph.get_block(source_serial)
    feeder = flow_graph.get_block(feeder_serial)
    if source is None or feeder is None:
        return None
    if tuple(int(target) for target in source.succs) != (feeder_serial,):
        return None
    if source_serial not in tuple(int(pred) for pred in feeder.preds):
        return None
    feeder_successors = tuple(int(target) for target in feeder.succs)
    if len(feeder_successors) != 1 or feeder_successors[0] not in {
        int(s) for s in required_comparison_serials
    }:
        return None
    comparison_entry = feeder_successors[0]
    comparison = flow_graph.get_block(comparison_entry)
    if (
        comparison is None
        or feeder_serial not in tuple(int(pred) for pred in comparison.preds)
    ):
        return None

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
    if not value_instructions or len(control_instructions) > 1:
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
    if control_instructions and feeder_instructions[-1] is not control_instructions[0]:
        return None
    semantic_suffix = value_instructions[1:]
    if len(semantic_suffix) > 1:
        return None
    if any(
        instruction.operation is not ValueOpKind.MOVE
        or instruction.effects
        or instruction.memory is not None
        or instruction.control is not None
        or instruction.result is None
        or storage_identity_from_varnode(instruction.result) in expected_identities
        or len(instruction.inputs) != 1
        or instruction.inputs[0].space
        not in {Space.REGISTER, Space.TEMP, Space.STACK}
        or instruction.result.space not in {Space.REGISTER, Space.TEMP}
        or int(instruction.inputs[0].size) != int(instruction.result.size)
        for instruction in semantic_suffix
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
        instruction.control is not None and instruction.control.transfer is not None
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
        requires_feeder_clone=bool(semantic_suffix),
    )
