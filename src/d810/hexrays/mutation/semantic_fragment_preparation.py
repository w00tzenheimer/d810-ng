"""Typed immutable authority prepared before semantic-fragment mutation."""

from __future__ import annotations

from dataclasses import dataclass

from d810.transforms.cfg_transaction import CfgProjection, TransactionAttemptId
from d810.transforms.fragment_plan import FragmentReturnSource
from d810.transforms.fragment_projection import FragmentProjectionInput
from d810.transforms.fragment_validation import ProjectedFragment
from d810.hexrays.mutation.semantic_fragment_inventory import (
    SemanticFragmentRootInventory,
)


def _identifier(value: str, label: str) -> str:
    value = str(value).strip()
    if not value:
        raise ValueError(f"{label} must not be blank")
    return value


def _unique(values: tuple[str, ...], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def sdk_operand_shape(operand: object, *, depth: int = 2) -> tuple:
    operand_type = int(getattr(operand, "t", -1))
    detail: object | None = None
    if operand_type >= 0:
        if hasattr(operand, "r"):
            detail = ("reg", int(operand.r))
        elif hasattr(getattr(operand, "nnn", None), "value"):
            detail = ("number", int(operand.nnn.value))
        elif depth > 0 and getattr(operand, "d", None) is not None:
            nested = operand.d
            detail = (
                "nested",
                int(getattr(nested, "opcode", -1)),
                sdk_operand_shape(nested.l, depth=depth - 1),
                sdk_operand_shape(nested.r, depth=depth - 1),
                sdk_operand_shape(nested.d, depth=depth - 1),
            )
    return (operand_type, int(getattr(operand, "size", 0)), detail)


def sdk_instruction_operand_shape(instruction: object) -> tuple[str]:
    return (repr(tuple(sdk_operand_shape(getattr(instruction, slot)) for slot in ("l", "r", "d"))),)


@dataclass(frozen=True, slots=True)
class PreparedNativeInstructionFact:
    instruction_id: str
    native_ea: int
    opcode: int
    operand_shape: tuple[str | int | None, ...]
    writes_condition_codes: bool | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "instruction_id", _identifier(self.instruction_id, "instruction id"))
        if int(self.native_ea) < 0:
            raise ValueError("prepared instruction EA must be nonnegative")
        shape = tuple(self.operand_shape)
        if any(not isinstance(value, (str, int, type(None))) for value in shape):
            raise TypeError("prepared operand shape must contain primitives")
        object.__setattr__(self, "native_ea", int(self.native_ea))
        object.__setattr__(self, "opcode", int(self.opcode))
        object.__setattr__(self, "operand_shape", shape)
        if self.writes_condition_codes not in {True, False, None}:
            raise TypeError("prepared flag fact must be bool or None")


@dataclass(frozen=True, slots=True)
class PreparedNativeBlockFact:
    block_id: str
    block_flags: int
    instructions: tuple[PreparedNativeInstructionFact, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "block_id", _identifier(self.block_id, "block id"))
        object.__setattr__(self, "block_flags", int(self.block_flags))
        instructions = tuple(self.instructions)
        if any(not isinstance(item, PreparedNativeInstructionFact) for item in instructions):
            raise TypeError("prepared block instructions must be typed facts")
        _unique(tuple(item.instruction_id for item in instructions), "instruction ids")
        object.__setattr__(self, "instructions", instructions)


@dataclass(frozen=True, slots=True)
class PreparedNativeBodyFact:
    plan_id: str
    body_id: str
    blocks: tuple[PreparedNativeBlockFact, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "plan_id", _identifier(self.plan_id, "plan id"))
        object.__setattr__(self, "body_id", _identifier(self.body_id, "body id"))
        blocks = tuple(self.blocks)
        if any(not isinstance(block, PreparedNativeBlockFact) for block in blocks):
            raise TypeError("prepared body blocks must be typed facts")
        _unique(tuple(block.block_id for block in blocks), "prepared block ids")
        object.__setattr__(self, "blocks", blocks)


@dataclass(frozen=True, slots=True)
class PreparedNativeBodyPayload:
    plan_id: str
    body_id: str
    rows: tuple[tuple[str, int, tuple[tuple[int, object], ...]], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "plan_id", _identifier(self.plan_id, "plan id"))
        object.__setattr__(self, "body_id", _identifier(self.body_id, "body id"))
        rows = tuple(self.rows)
        _unique(tuple(str(row[0]) for row in rows), "payload block ids")
        object.__setattr__(self, "rows", rows)


@dataclass(frozen=True, slots=True)
class PreparedNativeBodyPreparation:
    fact: PreparedNativeBodyFact
    payload: PreparedNativeBodyPayload

    def __post_init__(self) -> None:
        if (self.fact.plan_id, self.fact.body_id) != (
            self.payload.plan_id,
            self.payload.body_id,
        ):
            raise ValueError("native preparation fact and payload scope differ")
        if tuple(block.block_id for block in self.fact.blocks) != tuple(
            str(row[0]) for row in self.payload.rows
        ):
            raise ValueError("native preparation payload blocks differ from facts")

@dataclass(frozen=True, slots=True)
class PreparedReturnCarrierConstruction:
    carrier_id: str
    source: FragmentReturnSource
    return_width: int
    return_mreg: int
    operand_shape: tuple[str | int | None, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "carrier_id", _identifier(self.carrier_id, "carrier id"))
        return_width = int(self.return_width)
        return_mreg = int(self.return_mreg)
        if return_width <= 0 or return_mreg < 0:
            raise ValueError("prepared carrier width and mreg must be valid")
        if not isinstance(self.source, FragmentReturnSource):
            raise TypeError("prepared carrier source must be portable")
        operand_shape = tuple(self.operand_shape)
        if any(not isinstance(value, (str, int, type(None))) for value in operand_shape):
            raise TypeError("prepared carrier operand shape must contain primitives")
        object.__setattr__(self, "return_width", return_width)
        object.__setattr__(self, "return_mreg", return_mreg)
        object.__setattr__(self, "operand_shape", operand_shape)


@dataclass(frozen=True, slots=True)
class SemanticFragmentRealizationPayload:
    """Backend-local SDK payload; never semantic or validation authority."""

    native_body_rows: tuple[
        tuple[str, tuple[tuple[str, int, tuple[tuple[int, object], ...]], ...]], ...
    ]
    return_carrier_operands: tuple[tuple[str, object], ...]

    def __post_init__(self) -> None:
        bodies = tuple(self.native_body_rows)
        carriers = tuple(self.return_carrier_operands)
        _unique(tuple(str(row[0]) for row in bodies), "payload body ids")
        _unique(tuple(str(row[0]) for row in carriers), "payload carrier ids")
        object.__setattr__(self, "native_body_rows", bodies)
        object.__setattr__(self, "return_carrier_operands", carriers)


@dataclass(frozen=True, slots=True)
class SemanticFragmentSnapshotAuthority:
    plan_id: str
    atomic_group_id: str
    session_id: str
    generation: int
    projection_input: FragmentProjectionInput
    native_bodies: tuple[PreparedNativeBodyFact, ...]
    return_carrier_constructions: tuple[PreparedReturnCarrierConstruction, ...]

    def __post_init__(self) -> None:
        for name in ("plan_id", "atomic_group_id", "session_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        if not isinstance(self.projection_input, FragmentProjectionInput):
            raise TypeError("snapshot authority requires typed projection input")
        generation = int(self.generation)
        if generation < 0 or not str(self.projection_input.snapshot_id).strip():
            raise ValueError("snapshot authority generation/snapshot is invalid")
        bodies = tuple(self.native_bodies)
        carriers = tuple(self.return_carrier_constructions)
        _unique(tuple(body.body_id for body in bodies), "native body ids")
        _unique(tuple(item.carrier_id for item in carriers), "carrier ids")
        if any(body.plan_id != self.plan_id for body in bodies):
            raise ValueError("native body fact belongs to another plan")
        if any(not isinstance(body, PreparedNativeBodyFact) for body in bodies):
            raise TypeError("snapshot native bodies must be typed facts")
        if any(
            not isinstance(item, PreparedReturnCarrierConstruction)
            for item in carriers
        ):
            raise TypeError("snapshot carriers must be typed facts")
        object.__setattr__(self, "generation", generation)
        object.__setattr__(self, "native_bodies", bodies)
        object.__setattr__(self, "return_carrier_constructions", carriers)


@dataclass(frozen=True, slots=True)
class SemanticFragmentSnapshotPreparation:
    authority: SemanticFragmentSnapshotAuthority
    payload: SemanticFragmentRealizationPayload

    def __post_init__(self) -> None:
        body_ids = tuple(body.body_id for body in self.authority.native_bodies)
        carrier_ids = tuple(
            item.carrier_id for item in self.authority.return_carrier_constructions
        )
        if body_ids != tuple(row[0] for row in self.payload.native_body_rows):
            raise ValueError("snapshot payload body ids differ from facts")
        if carrier_ids != tuple(row[0] for row in self.payload.return_carrier_operands):
            raise ValueError("snapshot payload carrier ids differ from facts")


@dataclass(frozen=True, slots=True)
class PreparedSemanticFragmentAuthority:
    """Single-use realization authority bound to one exact preflight snapshot."""

    plan_id: str
    atomic_group_id: str
    session_id: str
    generation: int
    snapshot_id: str
    attempt_id: TransactionAttemptId
    root_inventory: SemanticFragmentRootInventory
    snapshot: SemanticFragmentSnapshotAuthority
    projection: ProjectedFragment
    cfg_projection: CfgProjection

    def __post_init__(self) -> None:
        for name in ("plan_id", "atomic_group_id", "session_id", "snapshot_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), name))
        generation = int(self.generation)
        if generation < 0:
            raise ValueError("prepared fragment generation must be nonnegative")
        if not isinstance(self.attempt_id, TransactionAttemptId):
            raise TypeError("prepared fragment attempt must be typed")
        if not isinstance(self.snapshot, SemanticFragmentSnapshotAuthority):
            raise TypeError("prepared fragment snapshot must be typed")
        if not isinstance(self.projection, ProjectedFragment):
            raise TypeError("prepared fragment projection must be typed")
        if not isinstance(self.cfg_projection, CfgProjection):
            raise TypeError("prepared fragment CFG projection must be typed")
        if not isinstance(self.root_inventory, SemanticFragmentRootInventory):
            raise TypeError("prepared fragment root inventory must be typed")
        if (
            self.attempt_id.plan_id != self.plan_id
            or self.snapshot.plan_id != self.plan_id
            or self.snapshot.atomic_group_id != self.atomic_group_id
            or self.snapshot.session_id != self.session_id
            or self.snapshot.generation != generation
            or self.snapshot.projection_input.snapshot_id != self.snapshot_id
            or self.root_inventory.plan_id != self.plan_id
            or self.root_inventory.atomic_group_id != self.atomic_group_id
            or self.cfg_projection.plan_id != self.plan_id
            or self.cfg_projection.snapshot_id != self.snapshot_id
        ):
            raise ValueError("prepared fragment authority scope is inconsistent")
        object.__setattr__(self, "generation", generation)

    @property
    def root_inventory_signature(self) -> tuple[tuple[str, str, str, str, bool], ...]:
        return tuple(
            (
                item.root_block_id,
                item.original_block_id,
                item.predecessor_block_id,
                item.role.value,
                item.requires_helper,
            )
            for item in self.root_inventory.items
        )


@dataclass(frozen=True, slots=True)
class PreparedSemanticFragment:
    authority: PreparedSemanticFragmentAuthority
    payload: SemanticFragmentRealizationPayload

    def __post_init__(self) -> None:
        body_ids = tuple(body.body_id for body in self.authority.snapshot.native_bodies)
        payload_body_ids = tuple(str(row[0]) for row in self.payload.native_body_rows)
        carrier_ids = tuple(
            item.carrier_id
            for item in self.authority.snapshot.return_carrier_constructions
        )
        payload_carrier_ids = tuple(str(row[0]) for row in self.payload.return_carrier_operands)
        if body_ids != payload_body_ids or carrier_ids != payload_carrier_ids:
            raise ValueError("prepared fragment payload keysets differ from facts")


__all__ = [
    "PreparedNativeBlockFact",
    "PreparedNativeBodyFact",
    "PreparedNativeBodyPayload",
    "PreparedNativeBodyPreparation",
    "PreparedNativeInstructionFact",
    "PreparedReturnCarrierConstruction",
    "PreparedSemanticFragmentAuthority",
    "PreparedSemanticFragment",
    "SemanticFragmentRealizationPayload",
    "SemanticFragmentSnapshotAuthority",
    "SemanticFragmentSnapshotPreparation",
    "sdk_instruction_operand_shape",
    "sdk_operand_shape",
]
