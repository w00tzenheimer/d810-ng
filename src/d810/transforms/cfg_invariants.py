"""Pure CFG structural contract checks.

These checks operate only on backend-neutral FlowGraph snapshots. Live
Hex-Rays verifier parity belongs under ``d810.hexrays.contracts``.
"""

from __future__ import annotations

from types import MappingProxyType

from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind
from d810.core.typing import Any, Iterable

from .report import InvariantViolation


_TERMINAL_TAIL_KINDS = frozenset(
    {InsnKind.GOTO, InsnKind.COND_JUMP, InsnKind.EQUALITY_JUMP}
)


def _violation(
    *,
    code: str,
    phase: str,
    message: str,
    block_serial: int | None,
    insn_ea: int | None = None,
    verify_code: int | None = None,
    details: dict[str, Any] | None = None,
) -> InvariantViolation:
    payload = dict(details or {})
    if verify_code is not None:
        payload["verify_code"] = int(verify_code)
    return InvariantViolation(
        code=code,
        phase=phase,
        message=message,
        block_serial=block_serial,
        insn_ea=insn_ea,
        details=MappingProxyType(payload) if payload else None,
    )


def _serials_for_scope(
    graph: FlowGraph,
    focus_serials: Iterable[int] | None,
) -> list[int]:
    if focus_serials is not None:
        return [int(s) for s in focus_serials]
    return sorted(int(s) for s in graph.blocks)


def _safe_get_block(graph: FlowGraph, serial: int) -> BlockSnapshot | None:
    return graph.get_block(int(serial))


def _tail_kind(blk: BlockSnapshot) -> InsnKind | None:
    if blk.tail_kind is not None:
        return blk.tail_kind
    tail = blk.tail
    if tail is not None:
        return tail.kind
    return None


def _expected_successor_count(blk: BlockSnapshot) -> int | None:
    if blk.kind in {
        BlockKind.STOP,
        BlockKind.EXTERNAL,
        BlockKind.ZERO_WAY,
    }:
        return 0
    if blk.kind is BlockKind.ONE_WAY:
        return 1
    if blk.kind is BlockKind.TWO_WAY:
        return 2
    if blk.kind is BlockKind.N_WAY:
        return len(blk.succs)
    if blk.kind is BlockKind.NONE:
        return 0
    return None


def block_list_consistency(
    graph: FlowGraph,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    """No-op for pure snapshots; linked-list ownership is backend-specific."""
    return []


def pred_succ_symmetry(
    graph: FlowGraph,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    violations: list[InvariantViolation] = []
    serials = _serials_for_scope(graph, focus_serials)

    for serial in serials:
        blk = _safe_get_block(graph, serial)
        if blk is None:
            continue
        for succ in blk.succs:
            succ_blk = _safe_get_block(graph, succ)
            if succ_blk is None:
                violations.append(
                    _violation(
                        code="CFG_50857_SUCC_OUT_OF_RANGE",
                        phase=phase,
                        message=f"Block {serial} successor {succ} is outside the FlowGraph",
                        block_serial=serial,
                        verify_code=50857,
                    )
                )
                continue
            if serial not in succ_blk.preds:
                violations.append(
                    _violation(
                        code="CFG_50858_SUCC_PRED_MISMATCH",
                        phase=phase,
                        message=(
                            f"Block {serial} -> {succ} exists in succs but "
                            "successor preds is missing this block"
                        ),
                        block_serial=serial,
                        verify_code=50858,
                    )
                )
        for pred in blk.preds:
            pred_blk = _safe_get_block(graph, pred)
            if pred_blk is None:
                violations.append(
                    _violation(
                        code="CFG_EDGE_PRED_MISSING_BLOCK",
                        phase=phase,
                        message=f"Block {serial} predecessor {pred} is outside the FlowGraph",
                        block_serial=serial,
                    )
                )
                continue
            if serial not in pred_blk.succs:
                violations.append(
                    _violation(
                        code="CFG_50861_PRED_SUCC_MISMATCH",
                        phase=phase,
                        message=f"Block {pred} -> {serial} missing in predecessor succs",
                        block_serial=serial,
                        verify_code=50861,
                    )
                )
    return violations


def predecessor_uniqueness(
    graph: FlowGraph,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    violations: list[InvariantViolation] = []
    for serial in _serials_for_scope(graph, focus_serials):
        blk = _safe_get_block(graph, serial)
        if blk is None:
            continue
        if len(set(blk.preds)) != len(blk.preds):
            violations.append(
                _violation(
                    code="CFG_50862_DUPLICATE_PRED",
                    phase=phase,
                    message=f"Block {serial} has duplicate predecessors",
                    block_serial=serial,
                    verify_code=50862,
                )
            )
    return violations


def block_type_vs_tail(
    graph: FlowGraph,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    violations: list[InvariantViolation] = []
    for serial in _serials_for_scope(graph, focus_serials):
        blk = _safe_get_block(graph, serial)
        if blk is None:
            continue
        expected_nsucc = _expected_successor_count(blk)
        if expected_nsucc is None:
            continue
        if len(blk.succs) != expected_nsucc:
            violations.append(
                _violation(
                    code="CFG_50856_BAD_NSUCC",
                    phase=phase,
                    message=(
                        f"Block {serial} kind={blk.kind.value} expects "
                        f"nsucc={expected_nsucc}, got {len(blk.succs)}"
                    ),
                    block_serial=serial,
                    verify_code=50856,
                )
            )
        tail_kind = _tail_kind(blk)
        if blk.kind is BlockKind.TWO_WAY and tail_kind not in {
            InsnKind.COND_JUMP,
            InsnKind.EQUALITY_JUMP,
        }:
            violations.append(
                _violation(
                    code="CFG_BLT2WAY_NON_JCC_TAIL",
                    phase=phase,
                    message=(
                        f"Block {serial} kind=two_way but tail kind={tail_kind} "
                        "is not conditional"
                    ),
                    block_serial=serial,
                )
            )
    return violations


def successor_set_matches_tail_semantics(
    graph: FlowGraph,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    violations: list[InvariantViolation] = []
    for serial in _serials_for_scope(graph, focus_serials):
        blk = _safe_get_block(graph, serial)
        if blk is None:
            continue
        tail_kind = _tail_kind(blk)
        if tail_kind is InsnKind.GOTO and len(blk.succs) != 1:
            violations.append(
                _violation(
                    code="CFG_50860_SUCC_MISMATCH",
                    phase=phase,
                    message=f"Block {serial} goto tail must have one successor",
                    block_serial=serial,
                    verify_code=50860,
                    details={"succset": tuple(blk.succs)},
                )
            )
        if tail_kind in {InsnKind.COND_JUMP, InsnKind.EQUALITY_JUMP} and len(blk.succs) != 2:
            violations.append(
                _violation(
                    code="CFG_50860_SUCC_MISMATCH",
                    phase=phase,
                    message=f"Block {serial} conditional tail must have two successors",
                    block_serial=serial,
                    verify_code=50860,
                    details={"succset": tuple(blk.succs)},
                )
            )
    return violations


def block_serial_range(
    graph: FlowGraph,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    violations: list[InvariantViolation] = []
    for serial in _serials_for_scope(graph, focus_serials):
        blk = _safe_get_block(graph, serial)
        if blk is None:
            continue
        if blk.serial not in graph.blocks:
            violations.append(
                _violation(
                    code="CFG_50851_SERIAL_OUT_OF_RANGE",
                    phase=phase,
                    message=f"Block at key {serial} has serial={blk.serial} outside graph keys",
                    block_serial=serial,
                    verify_code=50851,
                )
            )
    return violations


def block_closing_opcode_at_tail(
    graph: FlowGraph,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    violations: list[InvariantViolation] = []
    for serial in _serials_for_scope(graph, focus_serials):
        blk = _safe_get_block(graph, serial)
        if blk is None:
            continue
        insns = list(blk.iter_insns())
        for idx, insn in enumerate(insns[:-1]):
            if insn.kind in _TERMINAL_TAIL_KINDS:
                violations.append(
                    _violation(
                        code="CFG_50864_CLOSING_OPCODE_NOT_AT_TAIL",
                        phase=phase,
                        message=(
                            f"Block {serial}: terminal instruction kind "
                            f"{insn.kind.value} found at index {idx}, not tail"
                        ),
                        block_serial=serial,
                        insn_ea=insn.ea,
                        verify_code=50864,
                    )
                )
    return violations


def block_address_range(
    graph: FlowGraph,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    """Pure snapshots only carry start addresses; no range contract applies."""
    return []


def block_unknown_flags(
    graph: FlowGraph,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    """Backend flag-bit validity is checked by backend contract oracles."""
    return []
