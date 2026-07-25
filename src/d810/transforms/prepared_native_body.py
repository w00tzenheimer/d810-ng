"""Portable facts for one immutable prepared native body."""

from __future__ import annotations

from dataclasses import dataclass

from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.flowgraph import BlockKind, InsnKind
from d810.ir.semantic_edge import SemanticEdgeRole


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
        object.__setattr__(self, "native_ranges", native_ranges)
        object.__setattr__(self, "entry_block_ids", entry_block_ids)
        object.__setattr__(self, "terminal_block_ids", terminal_block_ids)
        object.__setattr__(self, "blocks", blocks)
        object.__setattr__(
            self,
            "direct_transfer_operation_ids",
            direct_transfer_operation_ids,
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


__all__ = [
    "PreparedNativeBlockFact",
    "PreparedNativeBodyFact",
    "PreparedNativeEdgeFact",
    "PreparedNativeInstructionFact",
]
