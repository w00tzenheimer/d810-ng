"""Canonical portable instruction record.

``Instruction`` is the portable IR node for a lifted instruction.  Its
``operation`` field carries the semantic operation family; raw backend opcode
details are provenance-only attrs and must not authorize behavior.

This first ``llr-epu0`` slice is deliberately non-Varnode: ``llr-5b99`` has not
landed, so ``InsnSnapshot`` projection leaves ``inputs`` empty and ``result``
unset rather than inventing ad hoc operand/result objects.  Statement-level
views such as :class:`d810.ir.statements.Assignment` and
:class:`d810.ir.statements.ConditionalBranch` remain separate projections over
the same source snapshot.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from d810.ir.semantics import ControlTransferKind, OperationKind, PredicateKind
from d810.ir.value_refs import ValueRef

__all__ = [
    "Instruction",
    "InstructionControl",
]


@dataclass(frozen=True, slots=True)
class InstructionControl:
    """Minimal control-transfer payload for an ``Instruction``.

    The transfer kind is the semantic control-flow operation; ``predicate`` is
    populated for conditional branches.  Target block modeling stays outside
    this first slice because CFG topology already lives on ``FlowGraph``.
    """

    transfer: ControlTransferKind
    predicate: PredicateKind | None = None


@dataclass(frozen=True, slots=True)
class Instruction:
    """Canonical portable instruction.

    ``operation`` is the semantic operation.  ``attrs`` is provenance only:
    backend/source identifiers, raw opcode integer/name, maturity/stage fields,
    and instruction EA may live there, but analyses should switch on
    ``operation`` and typed payloads instead of raw attrs.
    """

    operation: OperationKind
    inputs: tuple[ValueRef, ...] = ()
    result: ValueRef | None = None
    effects: tuple[object, ...] = ()
    control: InstructionControl | None = None
    attrs: Mapping[str, object] = field(default_factory=dict, hash=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "inputs", tuple(self.inputs))
        object.__setattr__(self, "effects", tuple(self.effects))
        object.__setattr__(self, "attrs", MappingProxyType(dict(self.attrs)))
