"""Cleanup-family strategy for linear tail-goto block merge."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from d810.ir.flowgraph import FlowGraph, InsnKind, OperandKind
from d810.transforms.graph_modification import GraphModification, NopInstructions
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)

TAIL_GOTO_MERGE_METADATA_KEY = "tail_goto_merge_candidates"


@dataclass(frozen=True)
class TailGotoMergeCandidate:
    """A fallthrough 1-way block whose trailing goto can be NOPed."""

    block_serial: int
    successor_serial: int
    insn_ea: int


def _coerce_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_tail_goto_merge_candidates(
    raw: object,
) -> tuple[TailGotoMergeCandidate, ...]:
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        return ()
    candidates: list[TailGotoMergeCandidate] = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        block_serial = _coerce_int(item.get("block_serial"))
        successor_serial = _coerce_int(item.get("successor_serial"))
        insn_ea = _coerce_int(item.get("insn_ea"))
        if block_serial is None or successor_serial is None or insn_ea is None:
            continue
        candidates.append(
            TailGotoMergeCandidate(
                block_serial=block_serial,
                successor_serial=successor_serial,
                insn_ea=insn_ea,
            )
        )
    return tuple(candidates)


def _serialize_tail_goto_merge_candidates(
    candidates: Sequence[TailGotoMergeCandidate],
) -> list[dict[str, int]]:
    return [
        {
            "block_serial": candidate.block_serial,
            "successor_serial": candidate.successor_serial,
            "insn_ea": candidate.insn_ea,
        }
        for candidate in candidates
    ]


def serialize_tail_goto_merge_candidates(
    candidates: Sequence[TailGotoMergeCandidate],
) -> list[dict[str, int]]:
    """Serialize tail-goto merge candidates into FlowGraph metadata."""
    return _serialize_tail_goto_merge_candidates(candidates)


def _tail_targets_successor(tail_insn: object, successor_serial: int) -> bool:
    operands = (
        getattr(tail_insn, "d", None),
        getattr(tail_insn, "l", None),
        *tuple(getattr(tail_insn, "operands", ()) or ()),
    )
    for operand in operands:
        if operand is None:
            continue
        if getattr(operand, "kind", None) == OperandKind.BLOCK:
            block_ref = getattr(operand, "block_ref", None)
        else:
            block_ref = getattr(
                operand,
                "block_ref",
                getattr(operand, "block_num", None),
            )
        if block_ref is not None and int(block_ref) == int(successor_serial):
            return True
    return False


def _last_insn(block: object) -> object | None:
    insns = tuple(getattr(block, "insn_snapshots", ()) or ())
    return insns[-1] if insns else None


def _is_valid_tail_goto_merge_candidate(
    cfg: FlowGraph,
    candidate: TailGotoMergeCandidate,
) -> bool:
    block = cfg.blocks.get(candidate.block_serial)
    successor = cfg.blocks.get(candidate.successor_serial)
    if block is None or successor is None:
        return False
    if block.succs != (candidate.successor_serial,):
        return False
    if candidate.successor_serial != candidate.block_serial + 1:
        return False
    if successor.preds != (candidate.block_serial,):
        return False
    if candidate.block_serial == candidate.successor_serial:
        return False
    tail = _last_insn(block)
    if tail is None:
        return False
    if tail.kind != InsnKind.GOTO:
        return False
    if int(tail.ea) <= 0 or int(tail.ea) != int(candidate.insn_ea):
        return False
    return _tail_targets_successor(tail, candidate.successor_serial)


def collect_tail_goto_merge_candidates(
    cfg: FlowGraph | None,
) -> tuple[TailGotoMergeCandidate, ...]:
    """Collect validated tail-goto merge candidates from a FlowGraph."""
    if cfg is None:
        return ()
    candidates: list[TailGotoMergeCandidate] = []
    for block in cfg.blocks.values():
        if len(block.succs) != 1:
            continue
        tail = _last_insn(block)
        if tail is None or tail.kind != InsnKind.GOTO or int(tail.ea) <= 0:
            continue
        candidate = TailGotoMergeCandidate(
            block_serial=int(block.serial),
            successor_serial=int(block.succs[0]),
            insn_ea=int(tail.ea),
        )
        if _is_valid_tail_goto_merge_candidate(cfg, candidate):
            candidates.append(candidate)
    return tuple(candidates)


def extract_tail_goto_merge_candidates(
    flow_graph: FlowGraph | None,
) -> tuple[TailGotoMergeCandidate, ...]:
    """Read validated tail-goto merge candidates from FlowGraph metadata."""
    if flow_graph is None:
        return ()
    raw_candidates = _coerce_tail_goto_merge_candidates(
        flow_graph.metadata.get(TAIL_GOTO_MERGE_METADATA_KEY)
    )
    return tuple(
        candidate
        for candidate in raw_candidates
        if _is_valid_tail_goto_merge_candidate(flow_graph, candidate)
    )


def build_tail_goto_merge_modifications(
    candidates: Sequence[TailGotoMergeCandidate],
) -> list[GraphModification]:
    """Translate tail-goto merge candidates into instruction-NOP primitives."""
    return [
        NopInstructions(
            block_serial=candidate.block_serial,
            insn_eas=(candidate.insn_ea,),
        )
        for candidate in candidates
    ]


class TailGotoMergeStrategy:
    """Engine strategy wrapper for linear tail-goto merge cleanup."""

    name = "tail_goto_merge"
    family = FAMILY_CLEANUP

    def is_applicable(self, snapshot) -> bool:
        return bool(extract_tail_goto_merge_candidates(snapshot.flow_graph))

    def plan(self, snapshot) -> PlanFragment | None:
        candidates = extract_tail_goto_merge_candidates(snapshot.flow_graph)
        if not candidates:
            return None

        modifications = build_tail_goto_merge_modifications(candidates)
        if not modifications:
            return None

        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            ownership=OwnershipScope(
                blocks=frozenset(
                    candidate.block_serial for candidate in candidates
                ),
                edges=frozenset(
                    (candidate.block_serial, candidate.successor_serial)
                    for candidate in candidates
                ),
                transitions=frozenset(),
            ),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=0,
                transitions_resolved=0,
                blocks_freed=len(candidates),
                conflict_density=0.0,
            ),
            risk_score=0.05,
            metadata={
                TAIL_GOTO_MERGE_METADATA_KEY: (
                    _serialize_tail_goto_merge_candidates(candidates)
                ),
                "execution_policy": "nop_merge_blocks_relaxed",
                "safeguard_min_required": 1,
            },
            modifications=list(modifications),
        )


__all__ = [
    "TAIL_GOTO_MERGE_METADATA_KEY",
    "TailGotoMergeCandidate",
    "TailGotoMergeStrategy",
    "build_tail_goto_merge_modifications",
    "collect_tail_goto_merge_candidates",
    "extract_tail_goto_merge_candidates",
    "serialize_tail_goto_merge_candidates",
]
