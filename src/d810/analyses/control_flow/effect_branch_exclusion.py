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
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind
from d810.ir.insn_projection import InstructionProjection
from d810.ir.semantics import ControlTransferKind, PredicateKind
from d810.ir.storage_identity import (
    StorageIdentity,
    StorageIdentityKind,
    storage_identity_from_record,
    storage_identity_from_varnode,
)
from d810.ir.varnode import Space


EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA = (
    "exact_state_branch_effect_exclusions"
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

    def to_metadata(self) -> dict[str, object]:
        return {
            "normalized_state": int(self.normalized_state),
            "source": {
                "serial": int(self.source_serial),
                "ea": int(self.source_ea),
                "write_ea": int(self.source_write_ea),
            },
            "predicate": {
                "serial": int(self.predicate_serial),
                "ea": int(self.predicate_ea),
                "branch_ea": int(self.predicate_branch_ea),
            },
            "selected_target": {
                "serial": int(self.selected_target_serial),
                "ea": int(self.selected_target_ea),
            },
            "discarded_effect": {
                "serial": int(self.discarded_effect_serial),
                "ea": int(self.discarded_effect_ea),
            },
            "state_identity": self.state_identity.to_record(),
        }


def _exact_int(value: object) -> int:
    if isinstance(value, bool):
        raise TypeError("boolean is not an exact integer")
    return int(value)


def exact_state_branch_effect_exclusion_from_metadata(
    payload: object,
) -> ExactStateBranchEffectExclusion | None:
    """Parse one persisted proof without accepting partial anchor shapes."""

    if not isinstance(payload, Mapping):
        return None

    def anchor(name: str, *fields: str) -> tuple[int, ...] | None:
        value = payload.get(name)
        if not isinstance(value, Mapping):
            return None
        try:
            return tuple(_exact_int(value[field]) for field in fields)
        except (KeyError, TypeError, ValueError, OverflowError):
            return None

    source = anchor("source", "serial", "ea", "write_ea")
    predicate = anchor("predicate", "serial", "ea", "branch_ea")
    selected = anchor("selected_target", "serial", "ea")
    discarded = anchor("discarded_effect", "serial", "ea")
    identity_payload = payload.get("state_identity")
    if (
        source is None
        or predicate is None
        or selected is None
        or discarded is None
        or not isinstance(identity_payload, Mapping)
    ):
        return None
    try:
        state = _exact_int(payload["normalized_state"])
        identity = storage_identity_from_record(identity_payload)
    except (KeyError, TypeError, ValueError, OverflowError):
        return None
    if not 0 <= state <= 0xFFFFFFFF:
        return None
    proof = ExactStateBranchEffectExclusion(
        normalized_state=state,
        source_serial=source[0],
        source_ea=source[1],
        source_write_ea=source[2],
        predicate_serial=predicate[0],
        predicate_ea=predicate[1],
        predicate_branch_ea=predicate[2],
        selected_target_serial=selected[0],
        selected_target_ea=selected[1],
        discarded_effect_serial=discarded[0],
        discarded_effect_ea=discarded[1],
        state_identity=identity,
    )
    return proof if _proof_scalars_valid(proof) else None


def _stable_block(graph: FlowGraph, serial: int) -> BlockSnapshot | None:
    block = graph.get_block(int(serial))
    if block is None:
        return None
    ea = _stable_ea(block)
    return block if ea is not None else None


def _stable_ea(block: BlockSnapshot) -> int | None:
    raw = block.native_start_ea
    if raw is None:
        raw = block.start_ea
    try:
        value = int(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    return value if 0 < value < _BADADDR_64 else None


def _instruction_ea(instruction: object) -> int | None:
    attrs = getattr(instruction, "attrs", None)
    raw = attrs.get("ea") if isinstance(attrs, Mapping) else None
    try:
        value = int(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    return value if 0 < value < _BADADDR_64 else None


def _proof_scalars_valid(proof: ExactStateBranchEffectExclusion) -> bool:
    return bool(
        0 <= int(proof.normalized_state) <= 0xFFFFFFFF
        and all(
            0 < int(value) < _BADADDR_64
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
                and int(control.target) != int(predicate_serial)
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
        or int(write.inputs[0].size) != 4
        or write.result is None
        or int(write.result.size) != 4
        or storage_identity_from_varnode(write.result) != state_identity
    ):
        return None

    stk_map: dict[int, int] = {}
    reg_map: dict[int, int] = {}
    state_var_stkoff = (
        int(state_identity.offset)
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
        state = stk_map.get(int(state_identity.offset))
    else:
        state = reg_map.get(int(state_identity.offset))
    write_ea = _instruction_ea(write)
    if state is None or write_ea is None:
        return None
    return int(state) & 0xFFFFFFFF, write_ea


def _exact_route_comparison(
    block: BlockSnapshot,
    *,
    state_identity: StorageIdentity,
) -> tuple[RouteComparison, int] | None:
    successors = tuple(int(serial) for serial in block.succs)
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
        int(state_operand.size) != 4
        or storage_identity_from_varnode(state_operand) != state_identity
        or constant_operand.space is not Space.CONST
        or int(constant_operand.size) != 4
    ):
        return None
    true_target = int(branch.control.target)
    false_targets = tuple(target for target in successors if target != true_target)
    branch_ea = _instruction_ea(branch)
    if len(false_targets) != 1 or branch_ea is None:
        return None
    return (
        RouteComparison(
            serial=int(block.serial),
            op=_ROUTE_OP_FOR_PREDICATE[branch.control.predicate],
            const=int(constant_operand.offset) & 0xFFFFFFFF,
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
    proof = ExactStateBranchEffectExclusion(
        normalized_state=int(normalized_state) & 0xFFFFFFFF,
        source_serial=int(source_serial),
        source_ea=int(_stable_ea(source) or 0),
        source_write_ea=int(state_write[1]),
        predicate_serial=int(predicate_serial),
        predicate_ea=int(_stable_ea(predicate) or 0),
        predicate_branch_ea=int(comparison[1]),
        selected_target_serial=int(selected_target_serial),
        selected_target_ea=int(_stable_ea(selected) or 0),
        discarded_effect_serial=int(discarded_effect_serial),
        discarded_effect_ea=int(_stable_ea(discarded) or 0),
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

    if not _proof_scalars_valid(proof):
        return False
    source = _stable_block(source_graph, proof.source_serial)
    predicate = _stable_block(source_graph, proof.predicate_serial)
    selected = _stable_block(source_graph, proof.selected_target_serial)
    discarded = _stable_block(source_graph, proof.discarded_effect_serial)
    if source is None or predicate is None or selected is None or discarded is None:
        return False
    if (
        _stable_ea(source) != int(proof.source_ea)
        or _stable_ea(predicate) != int(proof.predicate_ea)
        or _stable_ea(selected) != int(proof.selected_target_ea)
        or _stable_ea(discarded) != int(proof.discarded_effect_ea)
        or tuple(int(serial) for serial in source.succs)
        != (int(proof.predicate_serial),)
        or int(proof.source_serial)
        not in tuple(int(serial) for serial in predicate.preds)
        or tuple(int(serial) for serial in discarded.preds)
        != (int(proof.predicate_serial),)
        or not _has_effect(discarded)
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
        != (int(proof.normalized_state), int(proof.source_write_ea))
        or comparison is None
        or int(comparison[1]) != int(proof.predicate_branch_ea)
    ):
        return False
    route = DecisionDag(
        32,
        {int(proof.predicate_serial): comparison[0]},
        int(proof.predicate_serial),
    ).route(int(proof.normalized_state))
    comparison_targets = {
        int(comparison[0].true_target),
        int(comparison[0].false_target),
    }
    if (
        int(route) != int(proof.selected_target_serial)
        or comparison_targets
        != {
            int(proof.selected_target_serial),
            int(proof.discarded_effect_serial),
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
        or _stable_ea(projected_source) != int(proof.source_ea)
        or _stable_ea(projected_predicate) != int(proof.predicate_ea)
        or _stable_ea(projected_selected) != int(proof.selected_target_ea)
        or _stable_ea(projected_discarded) != int(proof.discarded_effect_ea)
        or tuple(int(serial) for serial in projected_source.succs)
        != (int(proof.predicate_serial),)
        or tuple(int(serial) for serial in projected_discarded.preds)
        != (int(proof.predicate_serial),)
    ):
        return False
    reachable = reachable_from_adjacency(
        projected_graph.as_adjacency_dict(),
        projected_graph.entry_serial,
    )
    reachable_predicate_preds = tuple(
        sorted(
            int(serial)
            for serial in projected_predicate.preds
            if int(serial) in reachable
        )
    )
    return bool(
        int(proof.source_serial) in reachable
        and int(proof.predicate_serial) in reachable
        and int(proof.selected_target_serial) in reachable
        and int(proof.discarded_effect_serial) in reachable
        and reachable_predicate_preds == (int(proof.source_serial),)
    )


__all__ = [
    "EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA",
    "ExactStateBranchEffectExclusion",
    "build_exact_state_branch_effect_exclusion",
    "exact_state_branch_effect_exclusion_from_metadata",
    "validate_exact_state_branch_effect_exclusion",
]
