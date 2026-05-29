"""Portable memory-access patterns.

Backend-neutral description of how a loop accesses memory (sequential, strided,
indirect, or scalar), over the IR location substrate.  Net-new and unwired
(Landing Sequence LS8 S6).

Minimum viable scope: an affine ``base + index*stride`` pattern with a kind tag.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

from d810.ir.locations import StorageLocation

__all__ = ["AccessKind", "MemoryAccessPattern"]


class AccessKind(Enum):
    """How a memory location is traversed across loop iterations."""

    SCALAR = auto()
    SEQUENTIAL = auto()
    STRIDED = auto()
    INDIRECT = auto()


@dataclass(frozen=True)
class MemoryAccessPattern:
    """An affine memory access ``base + index*stride`` per iteration."""

    base: StorageLocation
    stride: int
    kind: AccessKind = AccessKind.STRIDED
