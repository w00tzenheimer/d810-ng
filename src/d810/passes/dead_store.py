"""Plan dead-store removals from portable or live authoritative evidence."""

from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.value_flow.dead_store import (
    DeadStoreCandidate,
    DeadStoreEvidence,
)

from d810.ir.flowgraph import (
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.transforms.graph_modification import RemoveInstruction
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind

DEAD_STORE_EVIDENCE_METADATA_KEY = "dead_store_evidence"

__all__ = [
    "DeadStoreCandidate",
    "DEAD_STORE_EVIDENCE_METADATA_KEY",
    "DeadStoreEliminationStrategy",
    "build_dead_store_modifications",
    "collect_dead_store_candidates",
]


@dataclass(frozen=True)
class _Storage:
    kind: str
    identifier: int
    size: int


def _storage(operand: object | None) -> _Storage | None:
    if not isinstance(operand, MopSnapshot):
        return None
    size = int(operand.size)
    if size <= 0:
        return None
    if operand.kind is OperandKind.REGISTER and operand.reg is not None:
        return _Storage("register", int(operand.reg), size)
    if operand.kind is OperandKind.STACK and operand.stkoff is not None:
        return _Storage("stack", int(operand.stkoff), size)
    return None


def _is_direct_scalar(operand: object | None) -> bool:
    if not isinstance(operand, MopSnapshot):
        return False
    return operand.kind in {
        OperandKind.NUMBER,
        OperandKind.REGISTER,
        OperandKind.STACK,
    }


def _is_empty(operand: object | None) -> bool:
    return operand is None or (
        isinstance(operand, MopSnapshot) and operand.kind is OperandKind.EMPTY
    )


def _operand_uses_storage(operand: object | None, target: _Storage) -> bool:
    if not isinstance(operand, MopSnapshot):
        return False
    if _storage(operand) == target:
        return True
    return any(
        _operand_uses_storage(child, target)
        for child in (
            operand.sub_l,
            operand.sub_r,
            *operand.args,
        )
    )


def _is_safe_control_operand(operand: object | None) -> bool:
    """Accept only operands whose storage identity is explicit and scalar."""
    if not isinstance(operand, MopSnapshot):
        return operand is None
    if operand.sub_l is not None or operand.sub_r is not None or operand.args:
        return False
    return operand.kind in {
        OperandKind.EMPTY,
        OperandKind.NUMBER,
        OperandKind.REGISTER,
        OperandKind.STACK,
        OperandKind.BLOCK,
    }


def _is_direct_scalar_move(insn: InsnSnapshot) -> bool:
    return (
        insn.kind is InsnKind.MOV
        and _is_direct_scalar(insn.l)
        and _storage(insn.d) is not None
        and _is_empty(insn.r)
    )


def _crosses_instruction_safely(insn: InsnSnapshot, target: _Storage) -> bool:
    """Return whether this instruction can be crossed without losing proof."""
    if _is_direct_scalar_move(insn):
        return not _operand_uses_storage(insn.l, target)
    if insn.kind is InsnKind.NOP:
        return True
    if insn.kind in {
        InsnKind.GOTO,
        InsnKind.COND_JUMP,
        InsnKind.EQUALITY_JUMP,
        InsnKind.TABLE_JUMP,
        InsnKind.INDIRECT_JUMP,
    }:
        operands = (insn.l, insn.r, insn.d)
        return all(_is_safe_control_operand(operand) for operand in operands) and not any(
            _operand_uses_storage(operand, target) for operand in operands
        )
    return False


def _all_paths_redefine_before_use(
    graph: FlowGraph,
    *,
    start_serial: int,
    first_instruction: int,
    target: _Storage,
) -> bool:
    """Require a full target overwrite before any use on every CFG path."""
    visiting: set[tuple[int, int]] = set()
    completed: dict[tuple[int, int], bool] = {}

    def visit(serial: int, first_index: int) -> bool:
        key = (int(serial), int(first_index))
        if key in completed:
            return completed[key]
        # Re-entering a block with this value still live means there is a path
        # through a cycle that never reaches a full overwrite.
        if key in visiting:
            return False
        block = graph.blocks.get(int(serial))
        if block is None:
            return False
        visiting.add(key)
        try:
            for insn in block.insn_snapshots[first_index:]:
                if _is_direct_scalar_move(insn):
                    if _operand_uses_storage(insn.l, target):
                        completed[key] = False
                        return False
                    if _storage(insn.d) == target:
                        completed[key] = True
                        return True
                if not _crosses_instruction_safely(insn, target):
                    completed[key] = False
                    return False

            if not block.succs:
                # A local stack slot cannot be an ABI return value.  Reaching
                # function exit without reading it is therefore conclusive,
                # whereas a register may still carry an implicit return.
                completed[key] = target.kind == "stack"
                return completed[key]
            result = all(visit(successor, 0) for successor in block.succs)
            completed[key] = result
            return result
        finally:
            visiting.remove(key)

    return visit(start_serial, first_instruction)


def collect_dead_store_candidates(graph: FlowGraph | None) -> tuple[DeadStoreCandidate, ...]:
    """Collect only direct writes whose value is dead on every reachable path."""
    if graph is None:
        return ()
    candidates: list[DeadStoreCandidate] = []
    for block in graph.blocks.values():
        for ordinal, insn in enumerate(block.insn_snapshots):
            if not _is_direct_scalar_move(insn):
                continue
            destination = _storage(insn.d)
            if destination is None:
                continue
            if not _all_paths_redefine_before_use(
                graph,
                start_serial=block.serial,
                first_instruction=ordinal + 1,
                target=destination,
            ):
                continue
            candidates.append(
                DeadStoreCandidate(
                    block_serial=int(block.serial),
                    block_start_ea=int(block.start_ea),
                    insn_ea=int(insn.ea),
                    ordinal=ordinal,
                    opcode=int(insn.opcode),
                    destination=StorageIdentity(
                        StorageIdentityKind.REGISTER
                        if destination.kind == "register"
                        else StorageIdentityKind.STACK,
                        destination.identifier,
                    ),
                    destination_width=destination.size,
                )
            )
    return tuple(candidates)


def build_dead_store_modifications(
    candidates: tuple[DeadStoreCandidate, ...],
) -> list[RemoveInstruction]:
    """Translate proven candidate evidence into guarded microcode removals."""
    # Removing a later instruction first preserves the live ordinal fingerprint
    # of every earlier candidate in the same block.
    return [
        RemoveInstruction(
            block_serial=candidate.block_serial,
            block_start_ea=candidate.block_start_ea,
            insn_ea=candidate.insn_ea,
            ordinal=candidate.ordinal,
            opcode=candidate.opcode,
            destination_kind=candidate.destination_kind,
            destination_id=candidate.destination_id,
            destination_size=candidate.destination_size,
        )
        for candidate in sorted(
            candidates,
            key=lambda candidate: (candidate.block_serial, -candidate.ordinal),
        )
    ]


class DeadStoreEliminationStrategy:
    """Cleanup-family strategy for guarded scalar dead-store elimination."""

    name = "dead_store_elimination"
    family = "cleanup"

    @staticmethod
    def _candidates(snapshot) -> tuple[DeadStoreCandidate, ...]:
        graph = snapshot.flow_graph
        if graph is None:
            return ()
        evidence = graph.metadata.get(DEAD_STORE_EVIDENCE_METADATA_KEY)
        if isinstance(evidence, DeadStoreEvidence) and evidence.authoritative:
            return evidence.candidates
        return collect_dead_store_candidates(graph)

    def is_applicable(self, snapshot) -> bool:
        return bool(self._candidates(snapshot))

    def plan(self, snapshot):
        from d810.transforms.plan_fragment import (
            FAMILY_CLEANUP,
            BenefitMetrics,
            OwnershipScope,
            PlanFragment,
        )

        candidates = self._candidates(snapshot)
        if not candidates:
            return None
        modifications = build_dead_store_modifications(candidates)
        return PlanFragment(
            strategy_name=self.name,
            family=FAMILY_CLEANUP,
            ownership=OwnershipScope(
                blocks=frozenset(candidate.block_serial for candidate in candidates),
                edges=frozenset(),
                transitions=frozenset(),
            ),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=0,
                transitions_resolved=0,
                blocks_freed=0,
                conflict_density=0.0,
            ),
            risk_score=0.02,
            metadata={"safeguard_min_required": 1},
            modifications=modifications,
        )
