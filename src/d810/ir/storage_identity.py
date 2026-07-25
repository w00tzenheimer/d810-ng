"""Portable storage-identity boundary for deobfuscation analyses.

``StorageIdentity`` is the analysis-facing identifier for locations that carry
state across deobfuscation decisions.  It is deliberately size-agnostic:
``STACK`` identity is ``(kind=STACK, offset=N)`` regardless of whether one
instruction reads a byte and another reads a dword.  Width belongs to the
expression/value layer, not to this identity layer.

Backend-specific operands may be adapted into this type at the lift boundary,
but portable analyses should group variables by ``StorageIdentity`` rather than
by ``MopSnapshot`` or raw operand slots.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.core.typing import Mapping
from d810.ir.flowgraph import InsnSnapshot, MopSnapshot
from d810.ir.varnode import Space, Varnode, varnode_from_mop_snapshot

__all__ = [
    "StorageIdentity",
    "StorageIdentityKind",
    "operand_storage_identities",
    "storage_identity_from_mop_snapshot",
    "storage_identity_from_record",
    "storage_identity_from_varnode",
    "storage_identity_key",
    "storage_identity_offset",
]


class StorageIdentityKind(Enum):
    """Storage namespaces that are stable enough to key analyses."""

    REGISTER = "r"
    STACK = "S"
    GLOBAL = "v"
    LVAR = "l"


_KIND_BY_SPACE = {
    Space.REGISTER: StorageIdentityKind.REGISTER,
    Space.STACK: StorageIdentityKind.STACK,
    Space.GLOBAL: StorageIdentityKind.GLOBAL,
    Space.LVAR: StorageIdentityKind.LVAR,
}

_KIND_BY_NAME = {kind.name.lower(): kind for kind in StorageIdentityKind}
_KIND_BY_PREFIX = {kind.value: kind for kind in StorageIdentityKind}


@dataclass(frozen=True, slots=True)
class StorageIdentity:
    """Size-agnostic storage identity for portable analyses."""

    kind: StorageIdentityKind
    offset: int

    @property
    def key(self) -> str:
        """Legacy-compatible stable key string."""
        return f"{self.kind.value}{int(self.offset)}"

    def to_record(self) -> dict[str, int | str]:
        """Serialize as a small diagnostic/persistence-friendly record."""
        return {
            "kind": self.kind.name.lower(),
            "prefix": self.kind.value,
            "offset": int(self.offset),
            "key": self.key,
        }


def storage_identity_from_record(
    record: Mapping[str, object],
) -> StorageIdentity:
    """Load a ``StorageIdentity`` from :meth:`StorageIdentity.to_record`.

    Accepts either ``kind`` (``"stack"``) or ``prefix`` (``"S"``) so persisted
    diagnostics can carry the readable form while older key-shaped evidence can
    still be replayed.
    """
    kind_obj = record.get("kind")
    prefix_obj = record.get("prefix")
    if kind_obj is not None:
        kind = _KIND_BY_NAME.get(str(kind_obj).lower())
    elif prefix_obj is not None:
        kind = _KIND_BY_PREFIX.get(str(prefix_obj))
    else:
        kind = None
    if kind is None:
        raise ValueError(f"unknown storage identity kind record: {record!r}")
    return StorageIdentity(kind=kind, offset=int(record["offset"]))


def storage_identity_from_varnode(vn: Varnode | None) -> StorageIdentity | None:
    """Return a size-agnostic identity for an identity-space ``Varnode``."""
    if vn is None:
        return None
    kind = _KIND_BY_SPACE.get(vn.space)
    if kind is None:
        return None
    return StorageIdentity(kind=kind, offset=int(vn.offset))


def storage_identity_from_mop_snapshot(
    mop: MopSnapshot | None,
) -> StorageIdentity | None:
    """Adapt a lifted portable operand snapshot into ``StorageIdentity``."""
    return storage_identity_from_varnode(varnode_from_mop_snapshot(mop))


def storage_identity_key(identity: StorageIdentity | None) -> str | None:
    """Return the stable key string, or ``None`` for missing identities."""
    return identity.key if identity is not None else None


def storage_identity_offset(identity: StorageIdentity | None) -> int:
    """Return the numeric storage offset, or ``0`` for missing identities."""
    return int(identity.offset) if identity is not None else 0


def operand_storage_identities(
    insn: InsnSnapshot,
) -> tuple[tuple[str, StorageIdentity], ...]:
    """Return storage identities for the portable ``l/r/d`` operand slots."""
    return tuple(
        (slot, identity)
        for slot, mop in (("l", insn.l), ("r", insn.r), ("d", insn.d))
        if (identity := storage_identity_from_mop_snapshot(mop)) is not None
    )
