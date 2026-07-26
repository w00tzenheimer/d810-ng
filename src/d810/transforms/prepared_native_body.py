"""Portable facts for one immutable prepared native body."""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.fragment_authority import NormalizationWorkItemAuthority
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.flowgraph import BlockKind, InsnKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.transforms.fragment_plan import FragmentBlockRole, FragmentPlan


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not value.strip():
        raise ValueError(f"{label} must not be blank")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{label} must be an integer")
    if value < 0:
        raise ValueError(f"{label} must be non-negative")
    return value


def _unique(values: tuple[str, ...], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def _primitive_tree(value: object) -> bool:
    if isinstance(value, (str, int, bool, type(None))):
        return True
    return isinstance(value, tuple) and all(_primitive_tree(item) for item in value)


@dataclass(frozen=True, slots=True)
class PreparedNativeInstructionFact:
    """Portable semantic shape of one prepared backend instruction."""

    instruction_id: str
    native_ea: int
    opcode: int
    kind: InsnKind
    operand_shape: tuple[object, ...]
    writes_condition_codes: bool | None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "instruction_id",
            _identifier(self.instruction_id, "instruction id"),
        )
        object.__setattr__(
            self,
            "native_ea",
            _nonnegative_int(self.native_ea, "prepared instruction EA"),
        )
        object.__setattr__(
            self,
            "opcode",
            _nonnegative_int(self.opcode, "prepared instruction opcode"),
        )
        if not isinstance(self.kind, InsnKind):
            raise TypeError("prepared instruction kind must be portable")
        operand_shape = tuple(self.operand_shape)
        if not _primitive_tree(operand_shape):
            raise TypeError("prepared operand shape must contain only primitives")
        object.__setattr__(self, "operand_shape", operand_shape)
        if self.writes_condition_codes not in {True, False, None}:
            raise TypeError("prepared flag fact must be bool or None")


@dataclass(frozen=True, slots=True)
class PreparedNativeEdgeFact:
    """Plan-local, serial-free projected successor."""

    role: SemanticEdgeRole
    target_block_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.role, SemanticEdgeRole):
            raise TypeError("prepared edge requires a semantic role")
        object.__setattr__(
            self,
            "target_block_id",
            _identifier(self.target_block_id, "prepared edge target"),
        )


@dataclass(frozen=True, slots=True)
class PreparedNativeBlockFact:
    """Immutable identity, instruction, and projected-topology authority."""

    block_id: str
    semantic_anchor_ea: int
    stable_identity: StableBlockIdentity
    block_flags: int
    kind: BlockKind
    successors: tuple[PreparedNativeEdgeFact, ...]
    predecessor_block_ids: tuple[str, ...]
    terminator_ea: int | None
    terminator_kind: InsnKind
    instructions: tuple[PreparedNativeInstructionFact, ...]

    def __post_init__(self) -> None:
        block_id = _identifier(self.block_id, "prepared block id")
        semantic_anchor_ea = _nonnegative_int(
            self.semantic_anchor_ea,
            "prepared block semantic anchor",
        )
        if not isinstance(self.stable_identity, StableBlockIdentity):
            raise TypeError("prepared block requires stable native identity")
        if not self.stable_identity.native_ranges.contains(semantic_anchor_ea):
            raise ValueError("prepared block anchor escapes stable identity")
        if not isinstance(self.block_flags, int) or isinstance(self.block_flags, bool):
            raise TypeError("prepared block flags must be an integer")
        if not isinstance(self.kind, BlockKind):
            raise TypeError("prepared block kind must be portable")
        successors = tuple(self.successors)
        if any(not isinstance(edge, PreparedNativeEdgeFact) for edge in successors):
            raise TypeError("prepared block contains an invalid edge")
        predecessor_block_ids = tuple(
            _identifier(value, "prepared predecessor")
            for value in self.predecessor_block_ids
        )
        _unique(predecessor_block_ids, "prepared predecessor ids")
        expected_successors = {
            BlockKind.ZERO_WAY: 0,
            BlockKind.ONE_WAY: 1,
            BlockKind.TWO_WAY: 2,
        }.get(self.kind)
        if expected_successors is not None and len(successors) != expected_successors:
            raise ValueError("prepared block kind and successor count differ")
        terminator_ea = (
            None
            if self.terminator_ea is None
            else _nonnegative_int(self.terminator_ea, "prepared terminator EA")
        )
        if not isinstance(self.terminator_kind, InsnKind):
            raise TypeError("prepared terminator kind must be portable")
        instructions = tuple(self.instructions)
        if any(
            not isinstance(instruction, PreparedNativeInstructionFact)
            for instruction in instructions
        ):
            raise TypeError("prepared block instructions must be typed facts")
        _unique(
            tuple(instruction.instruction_id for instruction in instructions),
            "prepared instruction ids",
        )
        object.__setattr__(self, "block_id", block_id)
        object.__setattr__(self, "semantic_anchor_ea", semantic_anchor_ea)
        object.__setattr__(self, "successors", successors)
        object.__setattr__(self, "predecessor_block_ids", predecessor_block_ids)
        object.__setattr__(self, "terminator_ea", terminator_ea)
        object.__setattr__(self, "instructions", instructions)


@dataclass(frozen=True, slots=True)
class PreparedNativeBodyFact:
    """Complete portable authority for one prepared native body."""

    plan_id: str
    body_id: str
    native_ranges: tuple[NativeEaInterval, ...]
    entry_block_ids: tuple[str, ...]
    terminal_block_ids: tuple[str, ...]
    blocks: tuple[PreparedNativeBlockFact, ...]
    direct_transfer_operation_ids: tuple[str, ...] = ()
    preserved_native_transfer_block_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "plan_id", _identifier(self.plan_id, "plan id"))
        object.__setattr__(self, "body_id", _identifier(self.body_id, "body id"))
        native_ranges = tuple(self.native_ranges)
        if not native_ranges or any(
            not isinstance(native_range, NativeEaInterval)
            for native_range in native_ranges
        ):
            raise TypeError("prepared body requires typed native ranges")
        entry_block_ids = tuple(
            _identifier(value, "prepared entry block") for value in self.entry_block_ids
        )
        terminal_block_ids = tuple(
            _identifier(value, "prepared terminal block")
            for value in self.terminal_block_ids
        )
        blocks = tuple(self.blocks)
        if any(not isinstance(block, PreparedNativeBlockFact) for block in blocks):
            raise TypeError("prepared body blocks must be typed facts")
        block_ids = tuple(block.block_id for block in blocks)
        _unique(block_ids, "prepared block ids")
        if not set(entry_block_ids + terminal_block_ids) <= set(block_ids):
            raise ValueError("prepared entry or terminal block is outside the body")
        direct_transfer_operation_ids = tuple(
            _identifier(value, "prepared direct-transfer operation")
            for value in self.direct_transfer_operation_ids
        )
        _unique(
            direct_transfer_operation_ids,
            "prepared direct-transfer operation ids",
        )
        preserved_native_transfer_block_ids = tuple(
            _identifier(value, "prepared preserved native transfer block")
            for value in self.preserved_native_transfer_block_ids
        )
        _unique(
            preserved_native_transfer_block_ids,
            "prepared preserved native transfer block ids",
        )
        if not set(preserved_native_transfer_block_ids) <= set(block_ids):
            raise ValueError(
                "prepared preserved native transfers must belong to the body"
            )
        object.__setattr__(self, "native_ranges", native_ranges)
        object.__setattr__(self, "entry_block_ids", entry_block_ids)
        object.__setattr__(self, "terminal_block_ids", terminal_block_ids)
        object.__setattr__(self, "blocks", blocks)
        object.__setattr__(
            self,
            "direct_transfer_operation_ids",
            direct_transfer_operation_ids,
        )
        object.__setattr__(
            self,
            "preserved_native_transfer_block_ids",
            preserved_native_transfer_block_ids,
        )

    def block(self, block_id: str) -> PreparedNativeBlockFact:
        for block in self.blocks:
            if block.block_id == str(block_id):
                return block
        raise KeyError(block_id)

    @property
    def payload_signature(self) -> tuple[object, ...]:
        return tuple(
            (
                block.block_id,
                block.block_flags,
                tuple(
                    (
                        instruction.native_ea,
                        instruction.opcode,
                        instruction.operand_shape,
                    )
                    for instruction in block.instructions
                ),
            )
            for block in self.blocks
        )


@dataclass(frozen=True, slots=True)
class PreparedNativeBodyFactSnapshot:
    """Receipt-associated immutable body facts for one evidence generation."""

    plan_id: str
    evidence_generation: int
    snapshot_id: str
    bodies: tuple[PreparedNativeBodyFact, ...]

    def __post_init__(self) -> None:
        plan_id = _identifier(self.plan_id, "prepared snapshot plan id")
        evidence_generation = _nonnegative_int(
            self.evidence_generation,
            "prepared snapshot evidence generation",
        )
        snapshot_id = _identifier(
            self.snapshot_id,
            "prepared native-body snapshot id",
        )
        bodies = tuple(self.bodies)
        if not bodies or any(
            not isinstance(body, PreparedNativeBodyFact) for body in bodies
        ):
            raise TypeError("prepared snapshot requires typed native-body facts")
        if any(body.plan_id != plan_id for body in bodies):
            raise ValueError("prepared snapshot body plan lineage differs")
        _unique(
            tuple(body.body_id for body in bodies),
            "prepared snapshot body ids",
        )
        object.__setattr__(self, "plan_id", plan_id)
        object.__setattr__(self, "evidence_generation", evidence_generation)
        object.__setattr__(self, "snapshot_id", snapshot_id)
        object.__setattr__(self, "bodies", bodies)

    def body(self, body_id: str) -> PreparedNativeBodyFact:
        for body in self.bodies:
            if body.body_id == str(body_id):
                return body
        raise KeyError(body_id)


@dataclass(frozen=True, slots=True)
class PreparedNormalizationWorkItemSnapshot:
    """One exact receipt-backed publication plan and its prepared bodies."""

    source_plan_id: str
    source_atomic_group_id: str
    work_item_plan: FragmentPlan
    authority: NormalizationWorkItemAuthority
    prepared_bodies: PreparedNativeBodyFactSnapshot

    def __post_init__(self) -> None:
        source_plan_id = _identifier(
            self.source_plan_id,
            "prepared normalization source plan id",
        )
        source_atomic_group_id = _identifier(
            self.source_atomic_group_id,
            "prepared normalization source atomic group id",
        )
        work_item_plan = self.work_item_plan
        authority = self.authority
        prepared_bodies = self.prepared_bodies
        if not isinstance(work_item_plan, FragmentPlan):
            raise TypeError("prepared work item requires a FragmentPlan")
        if not isinstance(authority, NormalizationWorkItemAuthority):
            raise TypeError("prepared work item requires receipt authority")
        if not isinstance(prepared_bodies, PreparedNativeBodyFactSnapshot):
            raise TypeError("prepared work item requires typed body facts")
        scope = work_item_plan.work_item_scope
        if (
            authority.source_plan_id != source_plan_id
            or authority.source_atomic_group_id != source_atomic_group_id
            or scope is None
            or scope.work_item_id != work_item_plan.plan_id
            or authority.work_item_id != scope.work_item_id
            or prepared_bodies.plan_id != work_item_plan.plan_id
            or prepared_bodies.evidence_generation != authority.evidence_generation
        ):
            raise ValueError("prepared work-item receipt lineage differs")
        if tuple(body.body_id for body in work_item_plan.native_bodies) != tuple(
            body.body_id for body in prepared_bodies.bodies
        ):
            raise ValueError("prepared work-item body inventory differs")
        object.__setattr__(self, "source_plan_id", source_plan_id)
        object.__setattr__(
            self,
            "source_atomic_group_id",
            source_atomic_group_id,
        )

    def prepared_body_for(self, block_id: str) -> PreparedNativeBodyFact:
        """Return the prepared body that owns one imported work-item block."""
        block = self.work_item_plan.block(str(block_id))
        if block.role is not FragmentBlockRole.IMPORTED or block.native_body_id is None:
            raise KeyError(block_id)
        return self.prepared_bodies.body(block.native_body_id)


__all__ = [
    "PreparedNativeBlockFact",
    "PreparedNativeBodyFact",
    "PreparedNativeBodyFactSnapshot",
    "PreparedNativeEdgeFact",
    "PreparedNativeInstructionFact",
    "PreparedNormalizationWorkItemSnapshot",
]
