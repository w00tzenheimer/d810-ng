"""Exact portable comparison extraction shared by recovery and binding."""

from __future__ import annotations

from d810.analyses.control_flow.route_predicate import RouteComparison
from d810.analyses.control_flow.state_machine_analysis import _is_stop_block
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
)
from d810.ir.insn_projection import (
    Instruction,
    InstructionProjection,
    is_effect_free_operand_tree,
    operand_snapshots,
    project_instruction_sequence,
)
from d810.ir.semantics import ControlTransferKind, PredicateKind
from d810.ir.storage_identity import StorageIdentity, storage_identity_from_varnode
from d810.ir.varnode import Space


_ROUTE_OP_FOR_PREDICATE = {
    PredicateKind.EQ: "jz",
    PredicateKind.NE: "jnz",
    PredicateKind.UGT: "ja",
    PredicateKind.UGE: "jae",
    PredicateKind.ULT: "jb",
    PredicateKind.ULE: "jbe",
    PredicateKind.SGT: "jg",
    PredicateKind.SGE: "jge",
    PredicateKind.SLT: "jl",
    PredicateKind.SLE: "jle",
}


def _stable_flow_block(flow_graph: FlowGraph, serial: int) -> BlockSnapshot | None:
    block = flow_graph.get_block(int(serial))
    if block is None:
        return None
    ea = int(block.start_ea)
    return block if 0 < ea < 0xFFFFFFFFFFFFFFFF else None


def _is_exact_pure_xdu_route_prefix(
    raw_instructions,
    raw_branch,
    value_prefix,
    *,
    expected_identities: frozenset[StorageIdentity],
) -> bool:
    raw_prefix = tuple(
        instruction
        for instruction in raw_instructions
        if instruction is not raw_branch and instruction.kind is not InsnKind.NOP
    )
    if len(raw_prefix) != 1:
        return False
    xdu = raw_prefix[0]
    if (
        bool(xdu.is_call)
        or xdu.call_kind is not None
        or tuple(project_instruction_sequence(xdu)) != value_prefix
        or len(value_prefix) != 2
    ):
        return False
    add, zext = value_prefix
    if (
        add.operation is not ValueOpKind.ADD
        or zext.operation is not ValueOpKind.ZEXT
        or add.effects
        or add.memory is not None
        or add.control is not None
        or zext.effects
        or zext.memory is not None
        or zext.control is not None
        or len(add.inputs) != 2
        or add.result is None
        or add.result.space is not Space.TEMP
        or int(add.result.size) != 4
        or storage_identity_from_varnode(add.inputs[0]) not in expected_identities
        or add.inputs[1].space is not Space.CONST
        or int(add.inputs[1].size) != 4
        or zext.inputs != (add.result,)
        or zext.result is None
        or zext.result.space is not Space.REGISTER
        or int(zext.result.size) != 8
    ):
        return False
    return storage_identity_from_varnode(zext.result) not in expected_identities


def _is_exact_state_write_route_prefix(
    value_prefix: tuple[Instruction, ...],
    *,
    expected_identities: frozenset[StorageIdentity],
) -> bool:
    """Accept one pure state assignment before a route comparison.

    A canonical state-DAG producer may place the recovered state write in the
    same block as the comparison. Keep this exception exact: one MOVE, one
    constant input, no effects/control/memory, and a result in expected
    storage identity.
    """
    if len(value_prefix) != 1:
        return False
    write = value_prefix[0]
    if (
        write.operation is not ValueOpKind.MOVE
        or write.effects
        or write.memory is not None
        or write.control is not None
        or write.result is None
        or storage_identity_from_varnode(write.result) not in expected_identities
        or int(write.result.size) != 4
        or len(write.inputs) != 1
        or write.inputs[0].space is not Space.CONST
        or int(write.inputs[0].size) != 4
    ):
        return False
    return True


def current_u32_route_comparison(
    flow_graph: FlowGraph,
    serial: int,
    *,
    expected_identities: frozenset[StorageIdentity],
) -> tuple[RouteComparison, StorageIdentity, int, int] | None:
    """Rebuild one pure U32 comparison from current reciprocal instructions."""
    block = _stable_flow_block(flow_graph, int(serial))
    if block is None:
        return None
    successors = tuple(int(target) for target in block.succs)
    if len(successors) != 2 or successors[0] == successors[1] or int(serial) in successors:
        return None
    for target in successors:
        target_block = _stable_flow_block(flow_graph, target)
        if target_block is None:
            terminal = flow_graph.get_block(target)
            if not _is_stop_block(terminal):
                return None
            target_block = terminal
        if int(serial) not in tuple(int(pred) for pred in target_block.preds):
            return None
    raw_instructions = tuple(block.insn_snapshots)
    raw_branches = tuple(
        instruction
        for instruction in raw_instructions
        if instruction.control_transfer_kind is ControlTransferKind.CONDITIONAL_BRANCH
    )
    if len(raw_branches) != 1:
        return None
    raw_branch = raw_branches[0]
    block_ea = int(block.native_start_ea or block.start_ea)
    branch_ea = int(raw_branch.native_ea or raw_branch.ea)
    if (
        branch_ea < block_ea
        or not 0 < branch_ea < 0xFFFFFFFFFFFFFFFF
        or bool(raw_branch.is_call)
        or raw_branch.call_kind is not None
        or not all(is_effect_free_operand_tree(operand) for operand in operand_snapshots(raw_branch))
    ):
        return None
    # Projection turns a raw UNKNOWN into an empty VENDOR shell. That is not
    # positive router evidence: only the branch and raw NOPs may be ignored.
    # Keep the guard here so recovery and transaction binding cannot diverge.
    if any(
        instruction is not raw_branch and instruction.kind is InsnKind.UNKNOWN
        for instruction in raw_instructions
    ):
        return None
    instructions = InstructionProjection.from_block(block)
    branches = tuple(
        instruction
        for instruction in instructions
        if instruction.control is not None
        and instruction.control.transfer is ControlTransferKind.CONDITIONAL_BRANCH
    )
    if len(branches) != 1:
        return None
    branch = branches[0]
    if (
        branch.effects
        or branch.memory is not None
        or branch.control is None
        or branch.control.target not in successors
        or len(branch.inputs) != 2
    ):
        return None
    try:
        route_operation = _ROUTE_OP_FOR_PREDICATE[branch.control.predicate]
    except (KeyError, TypeError):
        return None
    nonbranch = tuple(instruction for instruction in instructions if instruction is not branch)
    vendor_shells = tuple(
        instruction
        for instruction in nonbranch
        if instruction.operation is ValueOpKind.VENDOR
        and not instruction.inputs
        and instruction.result is None
        and not instruction.effects
        and instruction.memory is None
        and instruction.control is None
    )
    value_prefix = tuple(instruction for instruction in nonbranch if instruction not in vendor_shells)
    if value_prefix and not (
        _is_exact_pure_xdu_route_prefix(
            raw_instructions,
            raw_branch,
            value_prefix,
            expected_identities=expected_identities,
        )
        or _is_exact_state_write_route_prefix(
            value_prefix, expected_identities=expected_identities,
        )
    ):
        return None
    if len(vendor_shells) + len(value_prefix) != len(nonbranch):
        return None
    state_operand, constant_operand = branch.inputs
    state_identity = storage_identity_from_varnode(state_operand)
    if (
        int(state_operand.size) != 4
        or state_identity not in expected_identities
        or constant_operand.space is not Space.CONST
        or int(constant_operand.size) != 4
    ):
        return None
    true_target = int(branch.control.target)
    false_targets = tuple(target for target in successors if target != true_target)
    if len(false_targets) != 1 or state_identity is None:
        return None
    comparison = RouteComparison(
        serial=int(serial),
        op=route_operation,
        const=int(constant_operand.offset) & 0xFFFFFFFF,
        true_target=true_target,
        false_target=false_targets[0],
    )
    return comparison, state_identity, block_ea, branch_ea


def current_u32_route_alias(flow_graph: FlowGraph, serial: int) -> int | None:
    """Rebuild one exact reciprocal control-only GOTO alias."""
    block = _stable_flow_block(flow_graph, int(serial))
    if block is None:
        return None
    successors = tuple(int(target) for target in block.succs)
    if len(successors) != 1 or successors[0] == int(serial):
        return None
    target = _stable_flow_block(flow_graph, successors[0])
    if target is None or int(serial) not in tuple(int(pred) for pred in target.preds):
        return None
    raw_instructions = tuple(block.insn_snapshots)
    if not raw_instructions:
        return successors[0] if getattr(block, "tail_kind", None) is InsnKind.GOTO else None
    non_nops = tuple(item for item in raw_instructions if item.kind is not InsnKind.NOP)
    if (
        len(non_nops) != 1
        or non_nops[0].kind is not InsnKind.GOTO
        or bool(non_nops[0].is_call)
        or non_nops[0].call_kind is not None
        or not all(
            is_effect_free_operand_tree(operand)
            for instruction in raw_instructions
            for operand in operand_snapshots(instruction)
        )
    ):
        return None
    instructions = InstructionProjection.from_block(block)
    gotos = tuple(
        instruction
        for instruction in instructions
        if instruction.control is not None
        and instruction.control.transfer is ControlTransferKind.GOTO
    )
    if len(gotos) != 1 or any(
        instruction is not gotos[0]
        and not (
            instruction.operation is ValueOpKind.VENDOR
            and not instruction.inputs
            and instruction.result is None
            and not instruction.effects
            and instruction.memory is None
            and instruction.control is None
        )
        for instruction in instructions
    ):
        return None
    control = gotos[0].control
    if control is None or (control.target is not None and int(control.target) != successors[0]):
        return None
    return successors[0]
