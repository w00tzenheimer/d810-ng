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

from d810.ir.expressions import ExprRef
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
    call_args: tuple[Varnode, ...] = ()
    return_value: Varnode | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "switch_cases", tuple(self.switch_cases))
        object.__setattr__(self, "call_args", tuple(self.call_args))


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
    args: tuple[Varnode, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "args", tuple(self.args))


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
    input_exprs: tuple[ExprRef | None, ...] = field(default_factory=tuple, hash=False)
    """Operand-slot-indexed lifted expression trees for source operands.

    ``input_exprs[0]`` is the lifted ``ExprRef`` for the LEFT source operand
    (``insn.l``); for an ``m_stx`` STORE this is the STORED VALUE subtree.
    ``input_exprs[1]`` is the RIGHT source operand tree, or ``None``.
    Entries are ``None`` when ``_value_of`` cannot lift that operand.

    Evidence-only contract: no analysis reads this field yet (C-S1).
    C-S3 is the first consumer; ``input_exprs[0]`` is the stored-value slot
    for STORE instructions.
    """
    operand_expr_fragments: tuple[ExprRef, ...] = field(
        default_factory=tuple, hash=False
    )
    """Deep, flattened lifted expression fragments of the source operand trees.

    Unlike ``input_exprs`` -- which is a shallow, slot-indexed ``_value_of`` of
    each top-level operand and is ``None`` on an unsupported (non-binop) wrapper
    -- this is the recursive ``iter_operand_exprs`` walk of the SAME operands.
    A supported child expression buried under a vendor/widen wrapper (e.g. a
    ``(counter - #N)`` ``Sub`` under an ``m_xdu`` / ``m_jge`` host) survives
    here even when ``input_exprs`` lifts the top operand to ``None``.

    Evidence-only: ordered ``slot0-fragments ++ slot1-fragments``; never
    contains ``None``.
    """

    def __post_init__(self) -> None:
        object.__setattr__(self, "inputs", tuple(self.inputs))
        object.__setattr__(self, "effects", tuple(self.effects))
        object.__setattr__(self, "attrs", MappingProxyType(dict(self.attrs)))
        object.__setattr__(self, "input_exprs", tuple(self.input_exprs))
        object.__setattr__(
            self, "operand_expr_fragments", tuple(self.operand_expr_fragments)
        )
