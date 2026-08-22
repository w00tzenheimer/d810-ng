"""Exact proof that one structurally reachable effect arm is infeasible.

The ordinary effect-reachability gate is intentionally structural.  This
module supplies one narrower semantic exception for a current-snapshot shape:
an exact constant state write enters one pure comparison, every other projected
ingress is unreachable, and the non-selected arm is an immediate private
CALL/STORE block.  The proof is replayable and persistence-friendly; it does
not weaken the general graph check or classify arbitrary effect corridors.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.graph_checks import reachable_from_adjacency
from d810.analyses.control_flow.route_predicate import DecisionDag, RouteComparison
from d810.analyses.value_flow.state_write import forward_eval_instruction
from d810.core.typing import Mapping
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
from d810.ir.insn_projection import InstructionProjection
from d810.ir.semantics import ControlTransferKind, PredicateKind
from d810.ir.storage_identity import (
    StorageIdentity,
    StorageIdentityKind,
    storage_identity_from_varnode,
)
from d810.ir.varnode import Space
from d810.core.legacy_keys import (
    EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA,
)


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
_BADADDR_64 = 0xFFFFFFFFFFFFFFFF


@dataclass(frozen=True, slots=True)
class ExactStateBranchEffectExclusion:
    """One exact source-state partition selecting away from a private effect."""

    normalized_state: int
    source_serial: int
    source_ea: int
    source_write_ea: int
    predicate_serial: int
    predicate_ea: int
    predicate_branch_ea: int
    selected_target_serial: int
    selected_target_ea: int
    discarded_effect_serial: int
    discarded_effect_ea: int
    state_identity: StorageIdentity

    def __post_init__(self) -> None:
        scalars = (
            self.normalized_state,
            self.source_serial,
            self.source_ea,
            self.source_write_ea,
            self.predicate_serial,
            self.predicate_ea,
            self.predicate_branch_ea,
            self.selected_target_serial,
            self.selected_target_ea,
            self.discarded_effect_serial,
            self.discarded_effect_ea,
        )
        if any(type(value) is not int for value in scalars):
            raise TypeError("exact exclusion scalars must be built-in ints")
        if not 0 <= self.normalized_state <= 0xFFFFFFFF:
            raise ValueError("normalized_state must be a U32 value")
        if any(value < 0 for value in (
            self.source_serial,
            self.predicate_serial,
            self.selected_target_serial,
            self.discarded_effect_serial,
        )):
            raise ValueError("exact exclusion serials must be non-negative")
        if any(not 0 < value < _BADADDR_64 for value in (
            self.source_ea,
            self.source_write_ea,
            self.predicate_ea,
            self.predicate_branch_ea,
            self.selected_target_ea,
            self.discarded_effect_ea,
        )):
            raise ValueError("exact exclusion EAs must be native addresses")
        if type(self.state_identity) is not StorageIdentity:
            raise TypeError("state_identity must be StorageIdentity")
        if type(self.state_identity.kind) is not StorageIdentityKind:
            raise TypeError("state_identity kind must be StorageIdentityKind")
        if type(self.state_identity.offset) is not int:
            raise TypeError("state_identity offset must be a built-in int")
        if self.state_identity.offset < 0:
            raise ValueError("state_identity offset must be non-negative")

    def to_metadata(self) -> dict[str, object]:
        return {
            "normalized_state": self.normalized_state,
            "source": {
                "serial": self.source_serial,
                "ea": self.source_ea,
                "write_ea": self.source_write_ea,
            },
            "predicate": {
                "serial": self.predicate_serial,
                "ea": self.predicate_ea,
                "branch_ea": self.predicate_branch_ea,
            },
            "selected_target": {
                "serial": self.selected_target_serial,
                "ea": self.selected_target_ea,
            },
            "discarded_effect": {
                "serial": self.discarded_effect_serial,
                "ea": self.discarded_effect_ea,
            },
            "state_identity": self.state_identity.to_record(),
        }


def _stable_block(graph: FlowGraph, serial: int) -> BlockSnapshot | None:
    if type(serial) is not int:
        return None
    block = graph.get_block(serial)
    if block is None:
        return None
    ea = _stable_ea(block)
    return block if ea is not None else None


def _stable_ea(block: BlockSnapshot) -> int | None:
    raw = block.native_start_ea
    if raw is None:
        raw = block.start_ea
    if type(raw) is not int:
        return None
    return raw if 0 < raw < _BADADDR_64 else None


def _instruction_ea(instruction: object) -> int | None:
    attrs = getattr(instruction, "attrs", None)
    raw = attrs.get("ea") if isinstance(attrs, Mapping) else None
    if type(raw) is not int:
        return None
    return raw if 0 < raw < _BADADDR_64 else None


def _graph_shape_exact(graph: FlowGraph) -> bool:
    if type(graph.entry_serial) is not int or type(graph.func_ea) is not int:
        return False
    block_ids = set(graph.blocks)
    if any(type(serial) is not int for serial in block_ids):
        return False
    for serial, block in graph.blocks.items():
        if type(block) is not BlockSnapshot or type(block.serial) is not int or block.serial != serial:
            return False
        if any(type(target) is not int for target in (*block.succs, *block.preds)):
            return False
        if any(target not in block_ids for target in (*block.succs, *block.preds)):
            return False
    return True


def _instruction_shape_exact(block: BlockSnapshot) -> bool:
    if type(block.insn_snapshots) is not tuple:
        return False
    for instruction in block.insn_snapshots:
        if type(instruction) is not InsnSnapshot:
            return False
        if type(instruction.ea) is not int:
            return False
        if instruction.native_ea is not None and type(instruction.native_ea) is not int:
            return False
        attrs = instruction.opcode_attrs
        if not isinstance(attrs, Mapping):
            return False
        if "ea" in attrs and type(attrs["ea"]) is not int:
            return False
    return True


def _proof_scalars_valid(proof: ExactStateBranchEffectExclusion) -> bool:
    if type(proof) is not ExactStateBranchEffectExclusion:
        return False
    if type(proof.state_identity) is not StorageIdentity:
        return False
    if (
        type(proof.state_identity.kind) is not StorageIdentityKind
        or type(proof.state_identity.offset) is not int
        or proof.state_identity.offset < 0
    ):
        return False
    scalars = (
        proof.normalized_state, proof.source_serial, proof.source_ea,
        proof.source_write_ea, proof.predicate_serial, proof.predicate_ea,
        proof.predicate_branch_ea, proof.selected_target_serial,
        proof.selected_target_ea, proof.discarded_effect_serial,
        proof.discarded_effect_ea,
    )
    if any(type(value) is not int for value in scalars):
        return False
    return bool(
        0 <= proof.normalized_state <= 0xFFFFFFFF
        and all(value >= 0 for value in (proof.source_serial, proof.predicate_serial, proof.selected_target_serial, proof.discarded_effect_serial))
        and all(
            0 < value < _BADADDR_64
            for value in (
                proof.source_ea,
                proof.source_write_ea,
                proof.predicate_ea,
                proof.predicate_branch_ea,
                proof.selected_target_ea,
                proof.discarded_effect_ea,
            )
        )
        and proof.state_identity.kind
        in {StorageIdentityKind.STACK, StorageIdentityKind.REGISTER}
    )


def _exact_source_state_write(
    block: BlockSnapshot,
    *,
    predicate_serial: int,
    state_identity: StorageIdentity,
) -> tuple[int, int] | None:
    """Replay one pure direct U32 write using the shared forward evaluator."""

    if not _instruction_shape_exact(block):
        return None

    instructions = InstructionProjection.from_block(block)
    value_instructions = []
    goto_count = 0
    for instruction in instructions:
        if instruction.effects or instruction.memory is not None:
            return None
        control = instruction.control
        if control is not None:
            if (
                control.transfer is not ControlTransferKind.GOTO
                or control.target is not None
                and (type(control.target) is not int or control.target != predicate_serial)
                or instruction.result is not None
                or instruction.inputs
            ):
                return None
            goto_count += 1
            continue
        if (
            instruction.operation is ValueOpKind.VENDOR
            and not instruction.inputs
            and instruction.result is None
        ):
            continue
        value_instructions.append(instruction)
    if len(value_instructions) != 1 or goto_count != 1:
        return None
    write = value_instructions[0]
    if (
        write.operation is not ValueOpKind.MOVE
        or len(write.inputs) != 1
        or write.inputs[0].space is not Space.CONST
        or type(write.inputs[0].size) is not int
        or write.inputs[0].size != 4
        or write.result is None
        or type(write.result.size) is not int
        or write.result.size != 4
        or storage_identity_from_varnode(write.result) != state_identity
    ):
        return None

    stk_map: dict[int, int] = {}
    reg_map: dict[int, int] = {}
    state_var_stkoff = (
        state_identity.offset
        if state_identity.kind is StorageIdentityKind.STACK
        else -1
    )
    for instruction in value_instructions:
        forward_eval_instruction(
            instruction,
            stk_map,
            reg_map,
            state_var_stkoff,
        )
    if state_identity.kind is StorageIdentityKind.STACK:
        state = stk_map.get(state_identity.offset)
    else:
        state = reg_map.get(state_identity.offset)
    write_ea = _instruction_ea(write)
    if state is None or write_ea is None:
        return None
    return state & 0xFFFFFFFF, write_ea


def _exact_route_comparison(
    block: BlockSnapshot,
    *,
    state_identity: StorageIdentity,
) -> tuple[RouteComparison, int] | None:
    if not _instruction_shape_exact(block):
        return None
    successors = tuple(block.succs)
    if len(successors) != 2 or successors[0] == successors[1]:
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
        or branch.control.predicate not in _ROUTE_OP_FOR_PREDICATE
        or len(branch.inputs) != 2
    ):
        return None
    for instruction in instructions:
        if instruction is branch:
            continue
        if not (
            instruction.operation is ValueOpKind.VENDOR
            and not instruction.inputs
            and instruction.result is None
            and not instruction.effects
            and instruction.memory is None
            and instruction.control is None
        ):
            return None
    state_operand, constant_operand = branch.inputs
    if (
        type(state_operand.size) is not int
        or state_operand.size != 4
        or storage_identity_from_varnode(state_operand) != state_identity
        or constant_operand.space is not Space.CONST
        or type(constant_operand.size) is not int
        or constant_operand.size != 4
        or type(constant_operand.offset) is not int
    ):
        return None
    if type(branch.control.target) is not int:
        return None
    true_target = branch.control.target
    false_targets = tuple(target for target in successors if target != true_target)
    branch_ea = _instruction_ea(branch)
    if len(false_targets) != 1 or branch_ea is None:
        return None
    return (
        RouteComparison(
            serial=block.serial,
            op=_ROUTE_OP_FOR_PREDICATE[branch.control.predicate],
            const=constant_operand.offset & 0xFFFFFFFF,
            true_target=true_target,
            false_target=false_targets[0],
        ),
        branch_ea,
    )


def _has_effect(block: BlockSnapshot) -> bool:
    return any(
        instruction.is_call
        or instruction.kind in {InsnKind.CALL, InsnKind.STORE}
        for instruction in block.insn_snapshots
    )


def _has_effect_at(block: BlockSnapshot, effect_ea: int) -> bool:
    """Require exactly one CALL/STORE site in the block at the claimed EA."""
    if not _instruction_shape_exact(block) or type(effect_ea) is not int:
        return False
    matches = []
    for instruction in block.insn_snapshots:
        native_ea = instruction.native_ea
        if native_ea is None:
            native_ea = instruction.ea
        if instruction.kind in (InsnKind.CALL, InsnKind.STORE) or instruction.is_call:
            matches.append(native_ea)
    return len(matches) == 1 and matches[0] == effect_ea


def build_exact_state_branch_effect_exclusion(
    source_graph: FlowGraph,
    projected_graph: FlowGraph,
    *,
    normalized_state: int,
    source_serial: int,
    predicate_serial: int,
    selected_target_serial: int,
    discarded_effect_serial: int,
    state_identity: StorageIdentity,
) -> ExactStateBranchEffectExclusion | None:
    """Build and immediately replay one exact effect-branch exclusion."""

    scalars = (
        normalized_state, source_serial, predicate_serial,
        selected_target_serial, discarded_effect_serial,
    )
    if (
        any(type(value) is not int for value in scalars)
        or any(value < 0 for value in scalars[1:])
        or not 0 <= normalized_state <= 0xFFFFFFFF
        or type(state_identity) is not StorageIdentity
        or type(state_identity.kind) is not StorageIdentityKind
        or type(state_identity.offset) is not int
        or state_identity.offset < 0
    ):
        return None
    if (
        type(source_graph) is not FlowGraph
        or type(projected_graph) is not FlowGraph
        or not _graph_shape_exact(source_graph)
        or not _graph_shape_exact(projected_graph)
    ):
        return None

    source = _stable_block(source_graph, source_serial)
    predicate = _stable_block(source_graph, predicate_serial)
    selected = _stable_block(source_graph, selected_target_serial)
    discarded = _stable_block(source_graph, discarded_effect_serial)
    if source is None or predicate is None or selected is None or discarded is None:
        return None
    state_write = _exact_source_state_write(
        source,
        predicate_serial=predicate_serial,
        state_identity=state_identity,
    )
    comparison = _exact_route_comparison(
        predicate,
        state_identity=state_identity,
    )
    if state_write is None or comparison is None:
        return None
    effect_eas = []
    for instruction in discarded.insn_snapshots:
        if instruction.kind in (InsnKind.CALL, InsnKind.STORE) or instruction.is_call:
            native_ea = instruction.native_ea
            if native_ea is None:
                native_ea = instruction.ea
            if type(native_ea) is not int:
                return None
            effect_eas.append(native_ea)
    if len(effect_eas) != 1:
        return None
    proof = ExactStateBranchEffectExclusion(
        normalized_state=normalized_state & 0xFFFFFFFF,
        source_serial=source_serial,
        source_ea=_stable_ea(source) or 0,
        source_write_ea=state_write[1],
        predicate_serial=predicate_serial,
        predicate_ea=_stable_ea(predicate) or 0,
        predicate_branch_ea=comparison[1],
        selected_target_serial=selected_target_serial,
        selected_target_ea=_stable_ea(selected) or 0,
        discarded_effect_serial=discarded_effect_serial,
        discarded_effect_ea=effect_eas[0],
        state_identity=state_identity,
    )
    if state_write[0] != proof.normalized_state:
        return None
    return (
        proof
        if validate_exact_state_branch_effect_exclusion(
            source_graph,
            projected_graph,
            proof,
        )
        else None
    )


def validate_exact_state_branch_effect_exclusion(
    source_graph: FlowGraph,
    projected_graph: FlowGraph,
    proof: ExactStateBranchEffectExclusion,
) -> bool:
    """Replay exact state, predicate, edge ownership, and projected ingress."""

    if type(source_graph) is not FlowGraph or type(projected_graph) is not FlowGraph:
        raise TypeError("exact exclusion graphs must be exact FlowGraph values")
    if not _graph_shape_exact(source_graph) or not _graph_shape_exact(projected_graph):
        return False
    if not _proof_scalars_valid(proof):
        return False
    source = _stable_block(source_graph, proof.source_serial)
    predicate = _stable_block(source_graph, proof.predicate_serial)
    selected = _stable_block(source_graph, proof.selected_target_serial)
    discarded = _stable_block(source_graph, proof.discarded_effect_serial)
    if source is None or predicate is None or selected is None or discarded is None:
        return False
    if (
        _stable_ea(source) != proof.source_ea
        or _stable_ea(predicate) != proof.predicate_ea
        or _stable_ea(selected) != proof.selected_target_ea
        or tuple(source.succs) != (proof.predicate_serial,)
        or proof.source_serial not in tuple(predicate.preds)
        or tuple(discarded.preds) != (proof.predicate_serial,)
        or not _has_effect_at(discarded, proof.discarded_effect_ea)
    ):
        return False
    state_write = _exact_source_state_write(
        source,
        predicate_serial=proof.predicate_serial,
        state_identity=proof.state_identity,
    )
    comparison = _exact_route_comparison(
        predicate,
        state_identity=proof.state_identity,
    )
    if (
        state_write is None
        or state_write
        != (proof.normalized_state, proof.source_write_ea)
        or comparison is None
        or comparison[1] != proof.predicate_branch_ea
    ):
        return False
    route = DecisionDag(
        32,
        {proof.predicate_serial: comparison[0]},
        proof.predicate_serial,
    ).route(proof.normalized_state)
    comparison_targets = {
        comparison[0].true_target,
        comparison[0].false_target,
    }
    if (
        route != proof.selected_target_serial
        or comparison_targets
        != {
            proof.selected_target_serial,
            proof.discarded_effect_serial,
        }
    ):
        return False

    projected_source = _stable_block(projected_graph, proof.source_serial)
    projected_predicate = _stable_block(projected_graph, proof.predicate_serial)
    projected_selected = _stable_block(projected_graph, proof.selected_target_serial)
    projected_discarded = _stable_block(
        projected_graph,
        proof.discarded_effect_serial,
    )
    if (
        projected_source is None
        or projected_predicate is None
        or projected_selected is None
        or projected_discarded is None
        or _stable_ea(projected_source) != proof.source_ea
        or _stable_ea(projected_predicate) != proof.predicate_ea
        or _stable_ea(projected_selected) != proof.selected_target_ea
        or tuple(projected_source.succs) != (proof.predicate_serial,)
        or tuple(projected_discarded.preds) != (proof.predicate_serial,)
        or not _has_effect_at(projected_discarded, proof.discarded_effect_ea)
    ):
        return False
    reachable = reachable_from_adjacency(
        projected_graph.as_adjacency_dict(),
        projected_graph.entry_serial,
    )
    reachable_predicate_preds = tuple(
        sorted(
            serial
            for serial in projected_predicate.preds
            if serial in reachable
        )
    )
    return bool(
        proof.source_serial in reachable
        and proof.predicate_serial in reachable
        and proof.selected_target_serial in reachable
        and proof.discarded_effect_serial in reachable
        and reachable_predicate_preds == (proof.source_serial,)
    )


__all__ = [
    "EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA",
    "ExactStateBranchEffectExclusion",
    "build_exact_state_branch_effect_exclusion",
    "validate_exact_state_branch_effect_exclusion",
]
