"""Portable value-reference substrate (SSA-style).

Backend-neutral references to *values* -- a definition at a storage location, an
SSA value, a temporary, or the result of an instruction -- so portable analyses
can talk about value identity without vendor operand objects (Landing Sequence
LS8 substrate front-load).

Minimum viable scope: the reference families the recurrence / induction analyses
need.  ``ValueRef`` is the closed union over them.  Extend on demand.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Union
from d810.ir.handles import InsnHandle
from d810.ir.locations import StorageLocation

__all__ = [
    "DefinitionRef",
    "InstructionResultRef",
    "SSAValueRef",
    "TemporaryRef",
    "ValueRef",
]


@dataclass(frozen=True)
class DefinitionRef:
    """A versioned definition of a value at a storage location."""

    location: StorageLocation
    version: int = 0


@dataclass(frozen=True)
class SSAValueRef:
    """An SSA value identified by an opaque value id."""

    value_id: int


@dataclass(frozen=True)
class TemporaryRef:
    """A short-lived temporary identified by an opaque id."""

    temp_id: int


@dataclass(frozen=True)
class InstructionResultRef:
    """The ``result_index``-th result produced by an instruction."""

    insn: InsnHandle
    result_index: int = 0


ValueRef = Union[DefinitionRef, SSAValueRef, TemporaryRef, InstructionResultRef]
"""Closed union of the concrete value-reference families."""
