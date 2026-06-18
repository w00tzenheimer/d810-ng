"""IDA-free lower-back contract prototype for LLVM M3.

This module intentionally stops before Hex-Rays mutation.  It models the tiny
contract a future LLVM->microcode dropper needs in order to destructure SSA PHI
nodes into edge moves while rejecting shapes that would need a real body emitter,
critical-edge splitting, or unsupported side-effect modeling.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, replace
from enum import Enum

__all__ = [
    "LlvmEdgeMove",
    "LlvmEdgeRewrite",
    "LlvmBridgeBlock",
    "LlvmLowerBackBlock",
    "LlvmLowerBackFunction",
    "LlvmLowerBackInstruction",
    "LlvmLowerBackPlan",
    "LlvmLowerBackResult",
    "LlvmLowerBackStatus",
    "LlvmLowerBackTerminator",
    "LlvmLowerBackTerminatorKind",
    "LlvmLowerBackUnsupportedKind",
    "LlvmLowerBackUnsupportedReason",
    "LlvmParallelCopyGroup",
    "LlvmPhiIncoming",
    "LlvmPhiNode",
    "LlvmValueRef",
    "plan_lower_back",
]


_SCALAR_TYPE_RE = re.compile(r"^i(?:1|8|16|32|64)$")


class LlvmLowerBackStatus(str, Enum):
    """Stable status values for M3 lower-back planning."""

    PLANNED = "planned"
    UNSUPPORTED = "unsupported"


class LlvmLowerBackUnsupportedKind(str, Enum):
    """Stable diagnostics for unsupported M3a lower-back shapes."""

    BRIDGE_LABEL_CONFLICT = "bridge_label_conflict"
    CRITICAL_EDGE_SPLIT_REQUIRED = "critical_edge_split_required"
    NON_SCALAR_PHI = "non_scalar_phi"
    PARALLEL_COPY_CONFLICT = "parallel_copy_conflict"
    PHI_PREDECESSOR_MISMATCH = "phi_predecessor_mismatch"
    UNKNOWN_BLOCK_TARGET = "unknown_block_target"
    UNSUPPORTED_CALL = "unsupported_call"
    UNSUPPORTED_CONTROL = "unsupported_control"
    UNSUPPORTED_MEMORY = "unsupported_memory"


class LlvmLowerBackTerminatorKind(str, Enum):
    """Tiny terminator vocabulary for the M3a contract model."""

    BRANCH = "branch"
    COND_BRANCH = "cond_branch"
    RETURN = "return"
    SWITCH = "switch"
    INDIRECTBR = "indirectbr"
    INVOKE = "invoke"
    LANDINGPAD = "landingpad"


@dataclass(frozen=True, slots=True)
class LlvmValueRef:
    """A small LLVM value reference used by the lower-back contract."""

    name: str
    type: str


@dataclass(frozen=True, slots=True)
class LlvmPhiIncoming:
    """One incoming PHI value and predecessor label, preserving source order."""

    predecessor: str
    value: LlvmValueRef


@dataclass(frozen=True, slots=True)
class LlvmPhiNode:
    """A scalar PHI node to be lowered into predecessor edge moves."""

    result: LlvmValueRef
    incoming: tuple[LlvmPhiIncoming, ...]


@dataclass(frozen=True, slots=True)
class LlvmLowerBackInstruction:
    """Non-terminator instruction placeholder for supported-subset checks."""

    opcode: str
    result: LlvmValueRef | None = None
    operands: tuple[LlvmValueRef, ...] = ()


@dataclass(frozen=True, slots=True)
class LlvmLowerBackTerminator:
    """Terminator payload used for target validation and unsupported control."""

    kind: LlvmLowerBackTerminatorKind
    targets: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LlvmLowerBackBlock:
    """One block in the lower-back planning contract."""

    label: str
    predecessors: tuple[str, ...]
    instructions: tuple[LlvmLowerBackInstruction, ...] = ()
    phis: tuple[LlvmPhiNode, ...] = ()
    terminator: LlvmLowerBackTerminator = LlvmLowerBackTerminator(
        LlvmLowerBackTerminatorKind.RETURN
    )


@dataclass(frozen=True, slots=True)
class LlvmLowerBackFunction:
    """A tiny LLVM CFG model for IDA-free lower-back planning."""

    name: str
    entry: str
    blocks: tuple[LlvmLowerBackBlock, ...]


@dataclass(frozen=True, slots=True)
class LlvmEdgeMove:
    """Out-of-SSA move to insert at the tail of a predecessor edge."""

    predecessor: str
    successor: str
    target: LlvmValueRef
    value: LlvmValueRef
    insertion_block: str | None = None


@dataclass(frozen=True, slots=True)
class LlvmBridgeBlock:
    """Inserted bridge block required to materialize one critical edge."""

    label: str
    predecessor: str
    successor: str


@dataclass(frozen=True, slots=True)
class LlvmEdgeRewrite:
    """CFG rewrite record for routing a critical edge through a bridge block."""

    predecessor: str
    successor: str
    bridge: str


@dataclass(frozen=True, slots=True)
class LlvmParallelCopyGroup:
    """Ordered parallel-copy group for one logical predecessor->successor edge."""

    predecessor: str
    successor: str
    insertion_block: str
    moves: tuple[LlvmEdgeMove, ...]


@dataclass(frozen=True, slots=True)
class LlvmLowerBackUnsupportedReason:
    """One fail-closed diagnostic from the lower-back planner."""

    kind: LlvmLowerBackUnsupportedKind
    block_label: str
    reason: str
    operation: str | None = None


@dataclass(frozen=True, slots=True)
class LlvmLowerBackPlan:
    """Planned lower-back actions for the supported M3a subset."""

    function_name: str
    entry: str
    block_order: tuple[str, ...]
    edge_moves: tuple[LlvmEdgeMove, ...]
    bridge_blocks: tuple[LlvmBridgeBlock, ...] = ()
    edge_rewrites: tuple[LlvmEdgeRewrite, ...] = ()
    parallel_copies: tuple[LlvmParallelCopyGroup, ...] = ()


@dataclass(frozen=True, slots=True)
class LlvmLowerBackResult:
    """Result of planning an LLVM lower-back contract."""

    status: LlvmLowerBackStatus
    plan: LlvmLowerBackPlan | None = None
    unsupported: tuple[LlvmLowerBackUnsupportedReason, ...] = ()

    @property
    def planned(self) -> bool:
        return self.status is LlvmLowerBackStatus.PLANNED

    @property
    def supported(self) -> bool:
        return self.planned

    @property
    def failed_closed(self) -> bool:
        return self.status is LlvmLowerBackStatus.UNSUPPORTED


def plan_lower_back(function: LlvmLowerBackFunction) -> LlvmLowerBackResult:
    """Plan the supported M3a lower-back subset for ``function``.

    The current prototype only emits out-of-SSA edge moves for scalar PHI nodes.
    Any unsupported block, control, side-effect, or malformed predecessor shape
    returns structured diagnostics and no plan.
    """

    blocks = {block.label: block for block in function.blocks}
    unsupported: list[LlvmLowerBackUnsupportedReason] = []
    if function.entry not in blocks:
        unsupported.append(
            LlvmLowerBackUnsupportedReason(
                kind=LlvmLowerBackUnsupportedKind.UNKNOWN_BLOCK_TARGET,
                block_label=function.entry,
                operation="entry",
                reason=f"entry block {function.entry!r} is not present",
            )
        )

    for block in function.blocks:
        _check_instructions(block, unsupported)
        _check_terminator(block, blocks, unsupported)

    pending_moves: dict[tuple[str, str], list[LlvmEdgeMove]] = defaultdict(list)
    for block in function.blocks:
        for phi in block.phis:
            _collect_phi_moves(block, phi, blocks, pending_moves, unsupported)

    (
        edge_moves,
        bridge_blocks,
        edge_rewrites,
        parallel_copies,
    ) = _plan_edge_move_groups(blocks, pending_moves, unsupported)

    if unsupported:
        return LlvmLowerBackResult(
            status=LlvmLowerBackStatus.UNSUPPORTED,
            unsupported=tuple(unsupported),
        )
    return LlvmLowerBackResult(
        status=LlvmLowerBackStatus.PLANNED,
        plan=LlvmLowerBackPlan(
            function_name=function.name,
            entry=function.entry,
            block_order=_block_order_with_bridges(function, bridge_blocks),
            edge_moves=tuple(edge_moves),
            bridge_blocks=tuple(bridge_blocks),
            edge_rewrites=tuple(edge_rewrites),
            parallel_copies=tuple(parallel_copies),
        ),
    )


def _check_instructions(
    block: LlvmLowerBackBlock,
    unsupported: list[LlvmLowerBackUnsupportedReason],
) -> None:
    for instruction in block.instructions:
        opcode = instruction.opcode
        if opcode == "call":
            unsupported.append(
                LlvmLowerBackUnsupportedReason(
                    kind=LlvmLowerBackUnsupportedKind.UNSUPPORTED_CALL,
                    block_label=block.label,
                    operation=opcode,
                    reason="call lowering is outside the M3a contract subset",
                )
            )
        elif opcode in {"load", "store", "atomicrmw", "cmpxchg"}:
            unsupported.append(
                LlvmLowerBackUnsupportedReason(
                    kind=LlvmLowerBackUnsupportedKind.UNSUPPORTED_MEMORY,
                    block_label=block.label,
                    operation=opcode,
                    reason="memory lowering is outside the M3a contract subset",
                )
            )


def _check_terminator(
    block: LlvmLowerBackBlock,
    blocks: dict[str, LlvmLowerBackBlock],
    unsupported: list[LlvmLowerBackUnsupportedReason],
) -> None:
    terminator = block.terminator
    if terminator.kind in {
        LlvmLowerBackTerminatorKind.INDIRECTBR,
        LlvmLowerBackTerminatorKind.INVOKE,
        LlvmLowerBackTerminatorKind.LANDINGPAD,
    }:
        unsupported.append(
            LlvmLowerBackUnsupportedReason(
                kind=LlvmLowerBackUnsupportedKind.UNSUPPORTED_CONTROL,
                block_label=block.label,
                operation=terminator.kind.value,
                reason=f"{terminator.kind.value} requires a real dropper control model",
            )
        )
    for target in terminator.targets:
        if target not in blocks:
            unsupported.append(
                LlvmLowerBackUnsupportedReason(
                    kind=LlvmLowerBackUnsupportedKind.UNKNOWN_BLOCK_TARGET,
                    block_label=block.label,
                    operation=terminator.kind.value,
                    reason=f"terminator targets unknown block {target!r}",
                )
            )


def _collect_phi_moves(
    block: LlvmLowerBackBlock,
    phi: LlvmPhiNode,
    blocks: dict[str, LlvmLowerBackBlock],
    pending_moves: dict[tuple[str, str], list[LlvmEdgeMove]],
    unsupported: list[LlvmLowerBackUnsupportedReason],
) -> None:
    if not _is_supported_scalar(phi.result.type):
        unsupported.append(
            LlvmLowerBackUnsupportedReason(
                kind=LlvmLowerBackUnsupportedKind.NON_SCALAR_PHI,
                block_label=block.label,
                operation="phi",
                reason=f"PHI result {phi.result.name!r} has unsupported type {phi.result.type!r}",
            )
        )
        return
    for incoming in phi.incoming:
        pred_label = incoming.predecessor
        pred = blocks.get(pred_label)
        if not _is_real_predecessor(pred, block):
            unsupported.append(
                LlvmLowerBackUnsupportedReason(
                    kind=LlvmLowerBackUnsupportedKind.PHI_PREDECESSOR_MISMATCH,
                    block_label=block.label,
                    operation="phi",
                    reason=(
                        f"PHI incoming predecessor {pred_label!r} is not a real "
                        f"predecessor of block {block.label!r}"
                    ),
                )
            )
            continue
        assert pred is not None
        pending_moves[(pred.label, block.label)].append(
            LlvmEdgeMove(
                predecessor=pred.label,
                successor=block.label,
                target=phi.result,
                value=incoming.value,
            )
        )


def _plan_edge_move_groups(
    blocks: dict[str, LlvmLowerBackBlock],
    pending_moves: dict[tuple[str, str], list[LlvmEdgeMove]],
    unsupported: list[LlvmLowerBackUnsupportedReason],
) -> tuple[
    list[LlvmEdgeMove],
    list[LlvmBridgeBlock],
    list[LlvmEdgeRewrite],
    list[LlvmParallelCopyGroup],
]:
    edge_moves: list[LlvmEdgeMove] = []
    bridge_blocks: list[LlvmBridgeBlock] = []
    edge_rewrites: list[LlvmEdgeRewrite] = []
    parallel_copies: list[LlvmParallelCopyGroup] = []
    generated_bridge_labels: dict[str, tuple[str, str]] = {}
    for predecessor_label, successor_label in pending_moves:
        moves = pending_moves[(predecessor_label, successor_label)]
        predecessor = blocks[predecessor_label]
        successor = blocks[successor_label]
        if _has_parallel_copy_conflict(moves):
            unsupported.append(
                LlvmLowerBackUnsupportedReason(
                    kind=LlvmLowerBackUnsupportedKind.PARALLEL_COPY_CONFLICT,
                    block_label=successor.label,
                    operation="parallel_copy",
                    reason=(
                        f"edge {predecessor.label!r}->{successor.label!r} has "
                        "overlapping source/target PHI copies and needs a temp plan"
                    ),
                )
            )
            continue
        insertion_block = predecessor.label
        if _requires_critical_edge_split(predecessor, successor):
            bridge_label = _bridge_label(predecessor.label, successor.label)
            if bridge_label in blocks:
                unsupported.append(
                    LlvmLowerBackUnsupportedReason(
                        kind=LlvmLowerBackUnsupportedKind.BRIDGE_LABEL_CONFLICT,
                        block_label=successor.label,
                        operation="critical_edge_split",
                        reason=(
                            f"bridge label {bridge_label!r} for edge "
                            f"{predecessor.label!r}->{successor.label!r} already names a block"
                        ),
                    )
                )
                continue
            previous_edge = generated_bridge_labels.get(bridge_label)
            current_edge = (predecessor.label, successor.label)
            if previous_edge is not None and previous_edge != current_edge:
                unsupported.append(
                    LlvmLowerBackUnsupportedReason(
                        kind=LlvmLowerBackUnsupportedKind.BRIDGE_LABEL_CONFLICT,
                        block_label=successor.label,
                        operation="critical_edge_split",
                        reason=(
                            f"bridge label {bridge_label!r} is shared by edges "
                            f"{previous_edge[0]!r}->{previous_edge[1]!r} and "
                            f"{predecessor.label!r}->{successor.label!r}"
                        ),
                    )
                )
                continue
            generated_bridge_labels[bridge_label] = current_edge
            bridge_blocks.append(
                LlvmBridgeBlock(
                    label=bridge_label,
                    predecessor=predecessor.label,
                    successor=successor.label,
                )
            )
            edge_rewrites.append(
                LlvmEdgeRewrite(
                    predecessor=predecessor.label,
                    successor=successor.label,
                    bridge=bridge_label,
                )
            )
            insertion_block = bridge_label
        planned_moves = tuple(replace(move, insertion_block=insertion_block) for move in moves)
        edge_moves.extend(planned_moves)
        parallel_copies.append(
            LlvmParallelCopyGroup(
                predecessor=predecessor.label,
                successor=successor.label,
                insertion_block=insertion_block,
                moves=planned_moves,
            )
        )
    return edge_moves, bridge_blocks, edge_rewrites, parallel_copies


def _requires_critical_edge_split(
    predecessor: LlvmLowerBackBlock,
    successor: LlvmLowerBackBlock,
) -> bool:
    if len(predecessor.terminator.targets) <= 1 or len(successor.predecessors) <= 1:
        return False
    # If the predecessor has multiple outgoing edges and the successor has
    # multiple incoming edges, the copy cannot be appended to either block tail
    # without affecting another edge.  A production dropper must split it.
    return True


def _has_parallel_copy_conflict(moves: list[LlvmEdgeMove]) -> bool:
    targets = tuple(move.target.name for move in moves)
    if len(set(targets)) != len(targets):
        return True
    sources = {move.value.name for move in moves}
    return bool(sources & set(targets))


def _bridge_label(predecessor: str, successor: str) -> str:
    return f"m3_split__{_label_fragment(predecessor)}__{_label_fragment(successor)}"


def _label_fragment(label: str) -> str:
    fragment = re.sub(r"[^A-Za-z0-9_.-]", "_", label)
    return fragment or "block"


def _block_order_with_bridges(
    function: LlvmLowerBackFunction,
    bridge_blocks: list[LlvmBridgeBlock],
) -> tuple[str, ...]:
    bridges_by_predecessor: dict[str, list[LlvmBridgeBlock]] = defaultdict(list)
    for bridge in bridge_blocks:
        bridges_by_predecessor[bridge.predecessor].append(bridge)
    order: list[str] = []
    for block in function.blocks:
        order.append(block.label)
        for bridge in sorted(bridges_by_predecessor.get(block.label, ()), key=lambda item: item.label):
            order.append(bridge.label)
    return tuple(order)


def _is_real_predecessor(
    predecessor: LlvmLowerBackBlock | None,
    successor: LlvmLowerBackBlock,
) -> bool:
    if predecessor is None:
        return False
    if predecessor.label not in successor.predecessors:
        return False
    return successor.label in predecessor.terminator.targets


def _is_supported_scalar(type_name: str) -> bool:
    return bool(_SCALAR_TYPE_RE.fullmatch(type_name.strip()))
