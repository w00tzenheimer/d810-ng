"""Immutable, IDA-free data model for sparse conditional constant propagation."""

from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass
from types import MappingProxyType

from d810.core.typing import Any, Iterable, Mapping


class OperandKind(enum.StrEnum):
    """Primitive operand categories understood by the SCCP solvers."""

    CONSTANT = "constant"
    VALUE = "value"
    UNSUPPORTED = "unsupported"


def _validate_index(value: Any, field: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{field} must be an integer")
    if value < 0:
        raise ValueError(f"{field} must be non-negative")


@dataclass(frozen=True, slots=True)
class SccpOperand:
    """A source operand with no live IDA/SWIG object references."""

    kind: OperandKind
    size: int
    constant: int | None = None
    value_id: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, OperandKind):
            try:
                object.__setattr__(self, "kind", OperandKind(self.kind))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid operand kind: {self.kind!r}") from exc
        _validate_index(self.size, "operand size")

        if self.kind is OperandKind.CONSTANT:
            if self.constant is None or self.value_id is not None:
                raise ValueError("CONSTANT operands require constant only")
            if not isinstance(self.constant, int) or isinstance(self.constant, bool):
                raise TypeError("constant must be an integer")
        elif self.kind is OperandKind.VALUE:
            if self.value_id is None or self.constant is not None:
                raise ValueError("VALUE operands require value_id only")
            _validate_index(self.value_id, "value_id")
        elif self.constant is not None or self.value_id is not None:
            raise ValueError("UNSUPPORTED operands cannot carry a value")


@dataclass(frozen=True, slots=True)
class SccpInstruction:
    """A normalized instruction in the primitive SCCP input model."""

    index: int
    block_index: int
    opcode: str
    ea: int
    size: int
    left: SccpOperand | None = None
    right: SccpOperand | None = None
    destination_value_id: int | None = None

    def __post_init__(self) -> None:
        _validate_index(self.index, "instruction index")
        _validate_index(self.block_index, "instruction block index")
        if not isinstance(self.ea, int) or isinstance(self.ea, bool):
            raise TypeError("instruction ea must be an integer")
        _validate_index(self.size, "instruction size")
        if not isinstance(self.opcode, str):
            raise TypeError("instruction opcode must be a normalized string")

        opcode = self.opcode.strip().lower()
        if opcode.startswith("m_"):
            opcode = opcode[2:]
        if not opcode:
            raise ValueError("instruction opcode cannot be empty")
        object.__setattr__(self, "opcode", opcode)

        if self.left is not None and not isinstance(self.left, SccpOperand):
            raise TypeError("left operand must be SccpOperand or None")
        if self.right is not None and not isinstance(self.right, SccpOperand):
            raise TypeError("right operand must be SccpOperand or None")
        if self.destination_value_id is not None and (
            not isinstance(self.destination_value_id, int)
            or isinstance(self.destination_value_id, bool)
        ):
            raise TypeError("destination value id must be an integer or None")
        if self.destination_value_id is not None and self.destination_value_id < 0:
            raise ValueError("destination value id must be non-negative")

    @property
    def destination(self) -> int | None:
        """Compatibility alias for callers that use the short field name."""

        return self.destination_value_id


@dataclass(frozen=True, slots=True)
class SccpBlock:
    """An ordered CFG block in the primitive SCCP input model."""

    index: int
    successors: tuple[int, ...]
    instruction_indices: tuple[int, ...]

    def __post_init__(self) -> None:
        _validate_index(self.index, "block index")
        successors = tuple(self.successors)
        instruction_indices = tuple(self.instruction_indices)
        for value in successors:
            _validate_index(value, "block successor")
        for value in instruction_indices:
            _validate_index(value, "block instruction index")
        object.__setattr__(self, "successors", successors)
        object.__setattr__(self, "instruction_indices", instruction_indices)


def _validate_program_structure(
    blocks: tuple[Any, ...], instructions: tuple[Any, ...]
) -> None:
    """Validate the complete primitive CFG/instruction boundary."""

    block_by_index: dict[int, SccpBlock] = {}
    for block in blocks:
        if not isinstance(block, SccpBlock):
            raise TypeError("program blocks must contain only SccpBlock")
        _validate_index(block.index, "block index")
        if not isinstance(block.successors, tuple) or not isinstance(
            block.instruction_indices, tuple
        ):
            raise TypeError("SccpBlock collections must be tuples")
        if block.index in block_by_index:
            raise ValueError(f"duplicate block index: {block.index}")
        block_by_index[block.index] = block
        for successor in block.successors:
            _validate_index(successor, "block successor")
        if len(block.successors) != len(set(block.successors)):
            raise ValueError(f"duplicate successor in block {block.index}")
        for instruction_index in block.instruction_indices:
            _validate_index(instruction_index, "block instruction index")

    instruction_by_index: dict[int, SccpInstruction] = {}
    for instruction in instructions:
        if not isinstance(instruction, SccpInstruction):
            raise TypeError("program instructions must contain only SccpInstruction")
        _validate_index(instruction.index, "instruction index")
        _validate_index(instruction.block_index, "instruction block index")
        if not isinstance(instruction.opcode, str) or not instruction.opcode:
            raise TypeError("instruction opcode must be a non-empty string")
        if not isinstance(instruction.ea, int) or isinstance(instruction.ea, bool):
            raise TypeError("instruction ea must be an integer")
        _validate_index(instruction.size, "instruction size")
        if instruction.left is not None and not isinstance(instruction.left, SccpOperand):
            raise TypeError("instruction left operand must be SccpOperand or None")
        if instruction.right is not None and not isinstance(instruction.right, SccpOperand):
            raise TypeError("instruction right operand must be SccpOperand or None")
        if instruction.destination_value_id is not None:
            _validate_index(instruction.destination_value_id, "destination value id")
        if instruction.index in instruction_by_index:
            raise ValueError(f"duplicate instruction index: {instruction.index}")
        instruction_by_index[instruction.index] = instruction

    for block in blocks:
        if any(successor not in block_by_index for successor in block.successors):
            missing = next(
                successor for successor in block.successors if successor not in block_by_index
            )
            raise ValueError(f"unknown successor: {missing}")

    referenced_indices: list[int] = []
    for block in blocks:
        for instruction_index in block.instruction_indices:
            if instruction_index in referenced_indices:
                raise ValueError(f"duplicate instruction index: {instruction_index}")
            if instruction_index not in instruction_by_index:
                raise ValueError(f"unknown instruction index: {instruction_index}")
            instruction = instruction_by_index[instruction_index]
            if instruction.block_index != block.index:
                raise ValueError(
                    f"instruction {instruction_index} belongs to another block"
                )
            referenced_indices.append(instruction_index)

    unreferenced = set(instruction_by_index).difference(referenced_indices)
    if unreferenced:
        missing = min(unreferenced)
        raise ValueError(f"unreferenced instruction: {missing}")


def _canonical(value: Any) -> Any:
    """Convert model values to JSON primitives deterministically."""

    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, Mapping):
        items = [(_canonical(key), _canonical(item)) for key, item in value.items()]
        items.sort(key=lambda pair: json.dumps(pair[0], sort_keys=True, separators=(",", ":")))
        return [[key, item] for key, item in items]
    if isinstance(value, (tuple, list)):
        return [_canonical(item) for item in value]
    if isinstance(value, (set, frozenset)):
        values = [_canonical(item) for item in value]
        return sorted(
            values,
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        )
    if isinstance(value, bytes):
        return {"__bytes__": value.hex()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"value is not JSON-canonicalizable: {type(value).__name__}")


def _freeze_primitive(value: Any) -> Any:
    """Recursively freeze JSON-like primitive containers.

    Snapshot keys are tuples of primitive values, but accepting nested lists,
    mappings, and sets here keeps the model boundary useful for adapters and
    tests while preventing a caller from mutating a program after hashing.
    Arbitrary/live objects are rejected rather than retained by reference.
    """

    if value is None or isinstance(value, (str, int, float, bool, bytes)):
        return value
    if isinstance(value, (tuple, list)):
        return tuple(_freeze_primitive(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze_primitive(item) for item in value)
    if isinstance(value, Mapping):
        frozen_items = [
            (_freeze_primitive(key), _freeze_primitive(item))
            for key, item in value.items()
        ]
        try:
            return MappingProxyType(dict(frozen_items))
        except TypeError as exc:
            raise TypeError("mapping keys must freeze to hashable primitives") from exc
    raise TypeError(f"value is not a supported primitive: {type(value).__name__}")


def _operand_payload(operand: SccpOperand | None) -> Any:
    if operand is None:
        return None
    return {
        "kind": operand.kind.value,
        "size": operand.size,
        "constant": operand.constant,
        "value_id": operand.value_id,
    }


def _instruction_payload(instruction: SccpInstruction) -> dict[str, Any]:
    return {
        "index": instruction.index,
        "block_index": instruction.block_index,
        "opcode": instruction.opcode,
        "ea": instruction.ea,
        "size": instruction.size,
        "left": _operand_payload(instruction.left),
        "right": _operand_payload(instruction.right),
        "destination_value_id": instruction.destination_value_id,
    }


@dataclass(frozen=True, slots=True)
class SccpProgram:
    """An immutable SCCP program and its direct value-use indexes."""

    blocks: tuple[SccpBlock, ...]
    instructions: tuple[SccpInstruction, ...]
    uses_by_value: Mapping[int, tuple[int, ...]]
    mop_keys_by_value: Mapping[int, Any]
    fingerprint: str

    def __post_init__(self) -> None:
        blocks = tuple(self.blocks)
        instructions = tuple(self.instructions)
        _validate_program_structure(blocks, instructions)
        if not isinstance(self.uses_by_value, Mapping):
            raise TypeError("uses_by_value must be a mapping")
        if not isinstance(self.mop_keys_by_value, Mapping):
            raise TypeError("mop_keys_by_value must be a mapping")
        if not isinstance(self.fingerprint, str):
            raise TypeError("fingerprint must be a string")

        object.__setattr__(self, "blocks", blocks)
        object.__setattr__(self, "instructions", instructions)
        instruction_indices = {instruction.index for instruction in instructions}
        uses: dict[int, tuple[int, ...]] = {}
        for value_id, raw_indices in self.uses_by_value.items():
            _validate_index(value_id, "use value id")
            try:
                indices = tuple(raw_indices)
            except TypeError as exc:
                raise TypeError(
                    f"use instruction indexes for value {value_id} must be iterable"
                ) from exc
            seen_indices: set[int] = set()
            for instruction_index in indices:
                _validate_index(instruction_index, "use instruction index")
                if instruction_index not in instruction_indices:
                    raise ValueError(f"unknown use instruction index: {instruction_index}")
                if instruction_index in seen_indices:
                    raise ValueError(f"duplicate use instruction index for value {value_id}")
                seen_indices.add(instruction_index)
            uses[value_id] = indices
        mop_keys = {
            value_id: _freeze_primitive(key)
            for value_id, key in self.mop_keys_by_value.items()
        }
        for value_id in mop_keys:
            _validate_index(value_id, "MOP key value id")
        object.__setattr__(self, "uses_by_value", MappingProxyType(uses))
        object.__setattr__(self, "mop_keys_by_value", MappingProxyType(mop_keys))

    @classmethod
    def from_parts(
        cls,
        blocks: Iterable[SccpBlock],
        instructions: Iterable[SccpInstruction],
        mop_keys_by_value: Mapping[int, Any],
        fingerprint_seed: Any = None,
    ) -> "SccpProgram":
        blocks_tuple = tuple(blocks)
        instructions_tuple = tuple(instructions)
        _validate_program_structure(blocks_tuple, instructions_tuple)
        if not isinstance(mop_keys_by_value, Mapping):
            raise TypeError("mop_keys_by_value must be a mapping")
        for value_id in mop_keys_by_value:
            _validate_index(value_id, "MOP key value id")

        uses: dict[int, list[int]] = {}
        for instruction in instructions_tuple:
            for operand in (instruction.left, instruction.right):
                if operand is None or operand.kind is not OperandKind.VALUE:
                    continue
                assert operand.value_id is not None
                indices = uses.setdefault(operand.value_id, [])
                if instruction.index not in indices:
                    indices.append(instruction.index)

        uses_tuple = {value_id: tuple(indices) for value_id, indices in uses.items()}
        mop_keys = {
            value_id: _freeze_primitive(key)
            for value_id, key in mop_keys_by_value.items()
        }
        frozen_fingerprint_seed = _freeze_primitive(fingerprint_seed)
        payload = {
            "blocks": [
                {
                    "index": block.index,
                    "successors": list(block.successors),
                    "instruction_indices": list(block.instruction_indices),
                }
                for block in blocks_tuple
            ],
            "instructions": [_instruction_payload(instruction) for instruction in instructions_tuple],
            "uses_by_value": uses_tuple,
            "mop_keys_by_value": mop_keys,
            "fingerprint_seed": frozen_fingerprint_seed,
        }
        canonical_json = json.dumps(
            _canonical(payload),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        fingerprint = hashlib.sha256(canonical_json).hexdigest()
        return cls(
            blocks=blocks_tuple,
            instructions=instructions_tuple,
            uses_by_value=uses_tuple,
            mop_keys_by_value=mop_keys,
            fingerprint=fingerprint,
        )

    def uses_for(self, value_id: int) -> tuple[int, ...]:
        return self.uses_by_value.get(value_id, ())

    def mop_key_for(self, value_id: int) -> Any | None:
        return self.mop_keys_by_value.get(value_id)


class SccpStatus(enum.StrEnum):
    """Terminal states of an SCCP solve."""

    CONVERGED = "converged"
    WORK_LIMIT = "work_limit"
    BLOCK_LIMIT = "block_limit"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class SccpResult:
    """Solver output, including proof and bounded-work telemetry."""

    status: SccpStatus
    constants: Mapping[Any, int | None]
    executable_edges: frozenset[tuple[int, int]]
    reachable_blocks: frozenset[int]
    program_fingerprint: str = ""
    backend: str = "python"
    cfg_events: int = 0
    value_events: int = 0
    peak_cfg_queue: int = 0
    peak_value_queue: int = 0
    adapter_seconds: float = 0.0
    solver_seconds: float = 0.0
    fallback_reason: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.status, SccpStatus):
            object.__setattr__(self, "status", SccpStatus(self.status))
        if self.status is not SccpStatus.CONVERGED and (
            self.constants or self.executable_edges or self.reachable_blocks
        ):
            raise ValueError("non-converged SCCP results must be proof-empty")
        object.__setattr__(self, "constants", MappingProxyType(dict(self.constants)))
        object.__setattr__(
            self,
            "executable_edges",
            frozenset((int(src), int(dst)) for src, dst in self.executable_edges),
        )
        object.__setattr__(self, "reachable_blocks", frozenset(int(x) for x in self.reachable_blocks))

    @classmethod
    def empty(
        cls,
        status: SccpStatus = SccpStatus.ERROR,
        *,
        program_fingerprint: str = "",
        backend: str = "python",
        fallback_reason: str = "",
        solver_seconds: float = 0.0,
    ) -> "SccpResult":
        return cls(
            status=status,
            constants={},
            executable_edges=frozenset(),
            reachable_blocks=frozenset(),
            program_fingerprint=program_fingerprint,
            backend=backend,
            solver_seconds=solver_seconds,
            fallback_reason=fallback_reason,
        )

    def is_edge_executable(self, src: int, dst: int) -> bool:
        if self.status is not SccpStatus.CONVERGED:
            return False
        return (int(src), int(dst)) in self.executable_edges

    def is_edge_dead(self, src: int, dst: int) -> bool:
        if self.status is not SccpStatus.CONVERGED:
            return False
        src = int(src)
        dst = int(dst)
        return src in self.reachable_blocks and (src, dst) not in self.executable_edges

    def dead_edges_among(self, edges: Iterable[tuple[int, int]]) -> frozenset[tuple[int, int]]:
        if self.status is not SccpStatus.CONVERGED:
            return frozenset()
        return frozenset(
            (int(src), int(dst))
            for src, dst in edges
            if self.is_edge_dead(src, dst)
        )

    def parity_key(self) -> tuple[Any, ...]:
        constants = tuple(
            sorted(
                self.constants.items(),
                key=lambda item: json.dumps(
                    _canonical(item[0]), sort_keys=True, separators=(",", ":")
                ),
            )
        )
        return (
            self.status.value,
            constants,
            tuple(sorted(self.executable_edges)),
            tuple(sorted(self.reachable_blocks)),
            self.program_fingerprint,
            self.cfg_events,
            self.value_events,
            self.peak_cfg_queue,
            self.peak_value_queue,
        )


__all__ = [
    "OperandKind",
    "SccpOperand",
    "SccpInstruction",
    "SccpBlock",
    "SccpProgram",
    "SccpStatus",
    "SccpResult",
]
