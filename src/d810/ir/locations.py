"""Portable storage-location substrate (LLVM / LiSA-style).

Backend-neutral dataclasses describing *where* a value lives, factored into the
IR layer so portable analyses (recurrence, induction, memory-access) can reason
about storage without vendor object shapes (Landing Sequence LS8 substrate
front-load).

Minimum viable scope: the concrete location families the recurrence / induction
/ memory-access analyses need.  ``StorageLocation`` is the closed union over
them.  Extend (or add families) on demand -- do NOT preload the universe of
addressing modes.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Union

__all__ = [
    "AggregateLocation",
    "MemoryCell",
    "RegisterLocation",
    "StackSlot",
    "StorageLocation",
    "WeakStackSlot",
]


@dataclass(frozen=True)
class StackSlot:
    """A stack-relative storage location (``offset`` from the frame base)."""

    offset: int
    size: int


@dataclass(frozen=True)
class RegisterLocation:
    """A machine / virtual register storage location."""

    register_id: int
    size: int


@dataclass(frozen=True)
class MemoryCell:
    """A memory storage location at a (currently concrete) address.

    Minimum viable: a concrete ``address``.  A symbolic base/displacement form
    can be added when an analysis needs it.
    """

    address: int
    size: int


@dataclass(frozen=True)
class WeakStackSlot:
    """A stack-relative location whose concrete offset could not be recovered.

    The LiSA-style *weak identifier*: a may-write to *some* stack slot, used
    when an analysis legitimately accepts a stkvar write on an unknown offset
    (e.g. a trampoline copy of the return slot).  Kept distinct from
    :class:`StackSlot` so ``StackSlot.offset`` stays a concrete ``int`` and the
    imprecision is explicit at every reader, never a silent ``offset=None``.
    """

    size: int = 0


@dataclass(frozen=True)
class AggregateLocation:
    """A composite location spanning ordered member locations (struct / array)."""

    members: tuple["StorageLocation", ...] = ()


StorageLocation = Union[
    StackSlot, RegisterLocation, MemoryCell, WeakStackSlot, AggregateLocation
]
"""Closed union of the concrete storage-location families."""
