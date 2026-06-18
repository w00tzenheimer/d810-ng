"""Portable P-Code-style operand identity.

A ``Varnode`` is a typeless sized slice: ``(space, offset, size)``.  The
identity spaces preserve the existing ``mop_identity`` key prefixes exactly
(``r`` / ``S`` / ``v`` / ``l``), so the S1 adapter can re-express
``mop_snapshot_key`` without changing persisted keys or diagnostics.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.ir.flowgraph import MopSnapshot, OperandKind

__all__ = [
    "Space",
    "Varnode",
    "varnode_from_mop_snapshot",
    "varnode_key",
    "varnode_offset",
]


class Space(Enum):
    """Portable operand space.

    The four identity-space values are the byte-stable key prefixes used by
    ``mop_snapshot_key``.  Temp/const/unknown are present for the spine type but
    intentionally do not produce identity keys in this slice.
    """

    REGISTER = "r"
    STACK = "S"
    GLOBAL = "v"
    LVAR = "l"
    TEMP = "t"
    CONST = "c"
    UNKNOWN = "?"


_IDENTITY_SPACES = frozenset(
    {Space.REGISTER, Space.STACK, Space.GLOBAL, Space.LVAR}
)


@dataclass(frozen=True, slots=True)
class Varnode:
    """A typeless sized operand slice."""

    space: Space
    offset: int
    size: int = 0


def varnode_key(vn: Varnode | None) -> str | None:
    """Return the stable identity key for identity spaces, else ``None``."""
    if vn is None or vn.space not in _IDENTITY_SPACES:
        return None
    return f"{vn.space.value}{vn.offset}"


def varnode_offset(vn: Varnode | None) -> int:
    """Return the numeric identity offset for identity spaces, else ``0``."""
    if vn is None or vn.space not in _IDENTITY_SPACES:
        return 0
    return int(vn.offset)


def varnode_from_mop_snapshot(mop: MopSnapshot | None) -> Varnode | None:
    """Adapt a portable ``MopSnapshot`` to ``Varnode``.

    This is not a live Hex-Rays ``mop_t`` converter.  It reads the already
    lifted ``d810.ir.flowgraph.MopSnapshot`` fields and preserves legacy
    identity behavior: keyed kinds with missing value fields map to
    ``UNKNOWN``, so their key is still ``None``.
    """
    if mop is None:
        return None
    size = int(mop.size or 0)
    kind = mop.kind
    if kind is OperandKind.REGISTER and mop.reg is not None:
        return Varnode(Space.REGISTER, int(mop.reg), size)
    if kind is OperandKind.STACK and mop.stkoff is not None:
        return Varnode(Space.STACK, int(mop.stkoff), size)
    if kind is OperandKind.GLOBAL and mop.gaddr is not None:
        return Varnode(Space.GLOBAL, int(mop.gaddr), size)
    if kind is OperandKind.LVAR and mop.lvar_off is not None:
        return Varnode(Space.LVAR, int(mop.lvar_off), size)
    if kind is OperandKind.NUMBER and mop.value is not None:
        return Varnode(Space.CONST, int(mop.value), size)
    return Varnode(Space.UNKNOWN, 0, size)
