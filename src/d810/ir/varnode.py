"""Portable P-Code-style operand identity.

A ``Varnode`` is a typeless sized slice: ``(space, offset, size)``.  The
identity spaces preserve the existing ``mop_identity`` key prefixes exactly
(``r`` / ``S`` / ``v`` / ``l``).  Analysis-facing grouping should use
``d810.ir.storage_identity.StorageIdentity``; these helpers remain the
Varnode-level adapter spine and preserve persisted key compatibility.
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

    The four identity-space values are the byte-stable key prefixes used by the
    storage identity layer.  Temp/const/unknown are present for the spine type
    but intentionally do not produce identity keys in this slice.
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
    """Return the legacy stable identity key for identity spaces."""
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
    ``UNKNOWN``, so their key is still ``None``.  During migration, older rich
    snapshots may not carry ``OperandKind`` but still expose lifted scalar
    fields (``gaddr``, ``stkoff``); those are accepted here without consulting
    live Hex-Rays alias fields such as ``.g`` or ``.s``.
    """
    if mop is None:
        return None
    size = int(getattr(mop, "size", 0) or 0)
    kind = getattr(mop, "kind", None)
    try:
        reg = mop.reg
    except AttributeError:
        reg = None
    try:
        stkoff = mop.stkoff
    except AttributeError:
        stkoff = None
    try:
        gaddr = mop.gaddr
    except AttributeError:
        gaddr = None
    try:
        lvar_off = mop.lvar_off
    except AttributeError:
        lvar_off = None
    try:
        value = mop.value
    except AttributeError:
        value = None
    kindless = kind is None
    if (kind is OperandKind.REGISTER or kindless) and reg is not None:
        return Varnode(Space.REGISTER, int(reg), size)
    if (kind is OperandKind.STACK or kindless) and stkoff is not None:
        return Varnode(Space.STACK, int(stkoff), size)
    if (kind is OperandKind.GLOBAL or kindless) and gaddr is not None:
        return Varnode(Space.GLOBAL, int(gaddr), size)
    if (kind is OperandKind.LVAR or kindless) and lvar_off is not None:
        return Varnode(Space.LVAR, int(lvar_off), size)
    if (kind is OperandKind.NUMBER or kindless) and value is not None:
        return Varnode(Space.CONST, int(value), size)
    return Varnode(Space.UNKNOWN, 0, size)
