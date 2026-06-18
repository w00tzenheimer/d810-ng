"""Canonical portable instruction record.

``Instruction`` is the portable IR node for a lifted instruction.  Its
``operation`` field carries the semantic operation family; raw backend opcode
details are provenance-only attrs and must not authorize behavior.

Statement-level views such as :class:`d810.ir.statements.Assignment` and
:class:`d810.ir.statements.ConditionalBranch` remain separate projections over
the same source snapshot.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType

from d810.ir.semantics import (
    CallKind,
    ControlTransferKind,
    OperationKind,
    PredicateKind,
)
from d810.ir.varnode import Varnode

__all__ = [
    "Instruction",
    "InstructionControl",
    "InstructionEffect",
    "InstructionEffectKind",
    "InstructionMemoryAccess",
    "InstructionMemoryAccessKind",
    "InstructionSwitchCase",
]


@dataclass(frozen=True, slots=True)
class InstructionSwitchCase:
    """Portable switch/table branch case row."""

    values: tuple[int, ...]
    target: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "values", tuple(int(v) for v in self.values))
        object.__setattr__(self, "target", int(self.target))


@dataclass(frozen=True, slots=True)
class InstructionControl:
    """Typed control payload for an ``Instruction``.

    ``transfer`` is populated for branch/return operations.  Calls carry their
    own ``CallKind`` because calls have call effects and optional results rather
    than being control transfers in the portable vocabulary.
    """

    transfer: ControlTransferKind | None = None
    predicate: PredicateKind | None = None
    target: int | None = None
    fallthrough: int | None = None
    switch_cases: tuple[InstructionSwitchCase, ...] = ()
    indirect_target: Varnode | None = None
    call_kind: CallKind | None = None
    call_target: Varnode | None = None
    return_value: Varnode | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "switch_cases", tuple(self.switch_cases))


class InstructionEffectKind(str, Enum):
    """Coarse side-effect families currently exposed by snapshots."""

    STORE = "store"
    CALL = "call"


class InstructionMemoryAccessKind(str, Enum):
    """Portable memory alias contract for memory-shaped instructions."""

    DIRECT_CELL = "direct_cell"
    INDIRECT = "indirect"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class InstructionMemoryAccess:
    """Typed memory access contract for LOAD/STORE instructions.

    ``DIRECT_CELL`` means ``target`` is a concrete portable cell that can map to
    its own distinct alloca.  ``INDIRECT`` preserves pointer/segment-shaped
    operands but is not alias-safe enough for M1 LLVM lowering.
    """

    kind: InstructionMemoryAccessKind
    target: Varnode | None = None
    segment: Varnode | None = None
    value: Varnode | None = None
    width: int | None = None


@dataclass(frozen=True, slots=True)
class InstructionEffect:
    """Typed side-effect payload for an ``Instruction``."""

    kind: InstructionEffectKind
    target: Varnode | None = None
    segment: Varnode | None = None
    value: Varnode | None = None


@dataclass(frozen=True, slots=True)
class Instruction:
    """Canonical portable instruction.

    ``operation`` is the semantic operation.  ``attrs`` is provenance only:
    backend/source identifiers, raw opcode integer/name, maturity/stage fields,
    and instruction EA may live there, but analyses should switch on
    ``operation`` and typed payloads instead of raw attrs.
    """

    operation: OperationKind
    inputs: tuple[Varnode, ...] = ()
    result: Varnode | None = None
    effects: tuple[InstructionEffect, ...] = ()
    control: InstructionControl | None = None
    memory: InstructionMemoryAccess | None = None
    attrs: Mapping[str, object] = field(default_factory=dict, hash=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "inputs", tuple(self.inputs))
        object.__setattr__(self, "effects", tuple(self.effects))
        object.__setattr__(self, "attrs", MappingProxyType(dict(self.attrs)))
