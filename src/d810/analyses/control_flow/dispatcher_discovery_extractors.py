"""FlowGraph -> (comparisons, state_writes) extractors for the LiSA dispatcher discovery.

The two pieces of evidence :func:`discover_dispatcher` consumes, read straight off the portable
``FlowGraph`` (no IDA): the per-block state comparisons (:class:`StateArmComparison`) and the per-block
state-write value (:class:`StateValue`).  Both are minimal -- a comparison is "this block branches on
``s`` vs a large constant", a state write is "this block stores ``K`` (or an unresolved value -> ``⊤``)
to the state slot".  Neither is a shape: no recursion, no handler-chain assumption.

The comparison recognition mirrors ``dispatcher_recovery.build_state_dispatcher_map_from_flow_graph``
(EQ -> jump target is the equal arm, NE -> fall-through is the equal arm).  The state-write value
resolution is the const-or-``⊤`` lattice element; a future cut routes the ``⊤`` writes through the
injected ``ValRangeCapability`` instead of giving up.
"""

from __future__ import annotations

from d810.core.typing import Mapping

from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import FlowGraph
from d810.ir.insn_projection import InstructionProjection
from d810.ir.semantics import ControlTransferKind, PredicateKind
from d810.ir.storage_identity import (
    StorageIdentity,
    StorageIdentityKind,
    storage_identity_from_varnode,
)
from d810.ir.varnode import Space
from d810.analyses.control_flow.instruction_semantics import (
    split_const_storage_identity_from_branch,
)
from d810.analyses.control_flow.state_transition_domain import StateValue
from d810.analyses.control_flow.dispatcher_discovery_fixpoint import (
    StateArmComparison,
    DispatcherView,
    discover_dispatcher,
)

__all__ = [
    "extract_state_arm_comparisons",
    "extract_state_writes",
    "discover_dispatcher_from_flow_graph",
]

MIN_STATE_CONSTANT = 0x01000000
_EQUALITY = (PredicateKind.EQ, PredicateKind.NE)


def _stack_identity(offset: int) -> StorageIdentity:
    return StorageIdentity(StorageIdentityKind.STACK, int(offset))


def _constant_move_value(instruction) -> int | None:
    if instruction.operation is not ValueOpKind.MOVE or len(instruction.inputs) != 1:
        return None
    source = instruction.inputs[0]
    if source.space is not Space.CONST:
        return None
    return int(source.offset)


def _conditional_branch_instruction(block):
    instructions = InstructionProjection.from_block(block)
    for index in range(len(instructions) - 1, -1, -1):
        instruction = instructions[index]
        control = instruction.control
        if (
            control is not None
            and control.transfer is ControlTransferKind.CONDITIONAL_BRANCH
        ):
            return index, instruction
    return None, None


def extract_state_arm_comparisons(
    graph: FlowGraph,
    *,
    state_var_stkoff: int | None = None,
    min_state_constant: int = MIN_STATE_CONSTANT,
) -> dict[int, StateArmComparison]:
    """Every block whose tail branches on ``s == const`` -> a :class:`StateArmComparison`.

    When ``state_var_stkoff`` is given, only comparisons against that variable are kept (the
    dominant-state-var filter); otherwise every equality-vs-large-constant branch qualifies.
    """
    comparisons: dict[int, StateArmComparison] = {}
    for serial, blk in graph.blocks.items():
        branch_index, branch = _conditional_branch_instruction(blk)
        control = branch.control if branch is not None else None
        if control is None:
            continue
        pred = control.predicate
        if pred not in _EQUALITY:
            continue
        expected_identity = (
            _stack_identity(int(state_var_stkoff))
            if state_var_stkoff is not None
            else None
        )
        const, state_identity = split_const_storage_identity_from_branch(
            InstructionProjection.from_block(blk),
            int(branch_index),
            min_const=min_state_constant,
            expected_identity=expected_identity,
        )
        if const is None:
            continue
        if state_var_stkoff is not None and state_identity != expected_identity:
            continue
        taken = control.target
        fallthrough = next((s for s in blk.succs if s != taken), None)
        if taken is None or fallthrough is None:
            continue
        # EQ (jz K): the taken arm is reached when s == K. NE (jnz K): the fall-through is.
        if pred is PredicateKind.EQ:
            eq_target, ne_target = int(taken), int(fallthrough)
        else:
            eq_target, ne_target = int(fallthrough), int(taken)
        comparisons[int(serial)] = StateArmComparison(
            block=int(serial),
            const=int(const),
            eq_target=eq_target,
            ne_target=ne_target,
        )
    return comparisons


def extract_state_writes(
    graph: FlowGraph, *, state_var_stkoff: int
) -> dict[int, StateValue]:
    """Per-block strong-update value for the state variable (last write in the block wins).

    A constant store to the state slot yields ``StateValue.of(K)``; any other write to it (computed /
    register-sourced / MBA-obfuscated) yields ``⊤`` -- the value is unknown, made explicit rather
    than dropped.  Blocks with no write to the state slot are absent (the domain passes through).
    """
    target = _stack_identity(int(state_var_stkoff))
    writes: dict[int, StateValue] = {}
    for serial, blk in graph.blocks.items():
        block_write: StateValue | None = None
        for instruction in InstructionProjection.from_block(blk):
            if storage_identity_from_varnode(instruction.result) != target:
                continue
            const_value = _constant_move_value(instruction)
            if const_value is not None:
                block_write = StateValue.of(const_value)
            else:
                block_write = StateValue.top()
        if block_write is not None:
            writes[int(serial)] = block_write
    return writes


def discover_dispatcher_from_flow_graph(
    graph: FlowGraph,
    *,
    state_var_stkoff: int,
    initial_state: int | None,
    require_resolved_head: bool = False,
) -> DispatcherView:
    """Extract (comparisons, state_writes) off ``graph`` and run the discovery fixpoint.

    ``initial_state`` seeds the value-set at the function entry (the pre-header constant): without it
    the loop header stays ``⊤`` (P2).  When unknown, ``⊤`` is used and the head will read back as
    ``None`` -- set ``require_resolved_head`` to fail loud on that.
    """
    comparisons = extract_state_arm_comparisons(
        graph, state_var_stkoff=state_var_stkoff
    )
    state_writes = extract_state_writes(graph, state_var_stkoff=state_var_stkoff)
    blocks = graph.blocks
    return discover_dispatcher(
        nodes=list(blocks.keys()),
        entry_nodes=[int(graph.entry_serial)],
        successors_of=lambda s: blocks[int(s)].succs if int(s) in blocks else (),
        predecessors_of=lambda s: blocks[int(s)].preds if int(s) in blocks else (),
        state_writes=state_writes,
        comparisons=comparisons,
        entry_state=(
            StateValue.of(int(initial_state))
            if initial_state is not None
            else StateValue.top()
        ),
        require_resolved_head=require_resolved_head,
    )
