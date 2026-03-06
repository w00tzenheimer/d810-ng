"""Generic forward dataflow fixpoint engine.

Domain-agnostic worklist solver. Callers provide:
- entry state
- meet function (merge predecessor outputs)
- transfer function (transform state through a block)
- graph topology (predecessors, successors, node set)

The engine does NOT import IDA types. The MBA adapter below wraps IDA access.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.core.typing import (
    TYPE_CHECKING,
    Callable,
    Collection,
    Generic,
    Iterable,
    Protocol,
    TypeVar,
    runtime_checkable,
)

if TYPE_CHECKING:
    pass

logger = getLogger(__name__)

StateT = TypeVar("StateT")


@runtime_checkable
class MeetFunction(Protocol[StateT]):
    """Merge multiple predecessor output states into one input state."""

    def __call__(self, pred_outs: list[StateT]) -> StateT: ...


@runtime_checkable
class TransferFunction(Protocol[StateT]):
    """Transform input state through a single node, producing output state."""

    def __call__(self, node_id: int, in_state: StateT) -> StateT: ...


@dataclass(frozen=True)
class FixpointResult(Generic[StateT]):
    """Result of a forward fixpoint computation."""

    in_states: dict[int, StateT]
    out_states: dict[int, StateT]
    iterations: int


def run_forward_fixpoint(
    *,
    nodes: Collection[int],
    entry_node: int,
    entry_state: StateT,
    bottom: StateT,
    predecessors_of: Callable[[int], Iterable[int]],
    successors_of: Callable[[int], Iterable[int]],
    meet: MeetFunction[StateT],
    transfer: TransferFunction[StateT],
    max_iterations: int = 1000,
) -> FixpointResult[StateT]:
    """Run forward dataflow to fixpoint.

    Algorithm: LIFO worklist. Entry node gets entry_state. All others start
    at bottom. Converges when OUT stops changing for all blocks.

    Args:
        nodes: Set of node identifiers in the graph.
        entry_node: The entry node where dataflow begins.
        entry_state: Initial abstract state at the entry node.
        bottom: The bottom element of the lattice (initial state for all
            non-entry nodes).
        predecessors_of: Returns predecessors of a given node.
        successors_of: Returns successors of a given node.
        meet: Merges multiple predecessor output states into one.
        transfer: Computes output state from input state for a node.
        max_iterations: Safety bound to prevent infinite loops.

    Returns:
        FixpointResult with IN/OUT states for every node and iteration count.
    """
    in_states: dict[int, StateT] = {n: bottom for n in nodes}
    out_states: dict[int, StateT] = {n: bottom for n in nodes}
    in_states[entry_node] = entry_state

    worklist: list[int] = [entry_node]
    iterations = 0

    while worklist and iterations < max_iterations:
        node = worklist.pop()  # LIFO
        iterations += 1

        preds = list(predecessors_of(node))
        if preds:
            in_new = meet([out_states[p] for p in preds])
        else:
            in_new = in_states[node]

        if in_new != in_states[node]:
            in_states[node] = in_new

        out_new = transfer(node, in_new)

        if out_new != out_states[node]:
            out_states[node] = out_new
            for succ in successors_of(node):
                if succ not in worklist:
                    worklist.append(succ)

    return FixpointResult(
        in_states=in_states,
        out_states=out_states,
        iterations=iterations,
    )


def run_forward_fixpoint_on_mba(
    mba: object,
    *,
    entry_serial: int = 0,
    entry_state: StateT,
    bottom: StateT,
    meet: MeetFunction[StateT],
    transfer: TransferFunction[StateT],
    max_iterations: int = 1000,
) -> FixpointResult[StateT]:
    """Convenience wrapper that extracts graph topology from an IDA mba_t.

    Args:
        mba: An ``ida_hexrays.mba_t`` instance (typed as ``object`` to
            avoid a hard import dependency on IDA).
        entry_serial: Serial number of the entry block (default 0).
        entry_state: Initial abstract state at the entry block.
        bottom: Bottom element of the lattice.
        meet: Meet function for the domain.
        transfer: Transfer function for the domain.
        max_iterations: Safety bound.

    Returns:
        FixpointResult with IN/OUT states for every block serial.
    """
    nodes = list(range(mba.qty))  # type: ignore[attr-defined]

    def predecessors_of(serial: int) -> list[int]:
        return list(mba.get_mblock(serial).predset)  # type: ignore[attr-defined]

    def successors_of(serial: int) -> list[int]:
        return list(mba.get_mblock(serial).succset)  # type: ignore[attr-defined]

    return run_forward_fixpoint(
        nodes=nodes,
        entry_node=entry_serial,
        entry_state=entry_state,
        bottom=bottom,
        predecessors_of=predecessors_of,
        successors_of=successors_of,
        meet=meet,
        transfer=transfer,
        max_iterations=max_iterations,
    )


def transfer_block_insnwise(
    blk: object,
    in_state: StateT,
    transfer_single: Callable[..., None],
) -> StateT:
    """Helper: apply transfer_single to each instruction in a block.

    Walks ``blk.head -> ins.next`` linked list. ``transfer_single(mba, ins, state)``
    mutates *state* in-place. Returns the final state after all instructions.

    Args:
        blk: An ``ida_hexrays.mblock_t`` instance.
        in_state: The input state (will be shallow-copied before mutation).
        transfer_single: Callable ``(mba, ins, state) -> None`` that updates
            *state* in place for one instruction.

    Returns:
        The output state after processing all instructions in the block.
    """
    env = copy.copy(in_state)  # shallow copy for dict-based states
    ins = blk.head  # type: ignore[attr-defined]
    mba = blk.mba  # type: ignore[attr-defined]
    while ins:
        transfer_single(mba, ins, env)
        ins = ins.next  # type: ignore[attr-defined]
    return env


__all__ = [
    "FixpointResult",
    "MeetFunction",
    "TransferFunction",
    "run_forward_fixpoint",
    "run_forward_fixpoint_on_mba",
    "transfer_block_insnwise",
]
