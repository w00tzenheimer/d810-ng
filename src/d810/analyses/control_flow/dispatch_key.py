"""Dispatch-key transform vocabulary for state-machine recovery."""

from __future__ import annotations

from enum import Enum


class DispatchKeyTransformKind(str, Enum):
    """Shape of a recovered dispatcher-key transform.

    This is descriptive evidence, not trust authority.  Consumers that rewrite
    CFG/DAG state must combine this with a separate proof that authorizes the
    rewrite.
    """

    IDENTITY = "identity"
    AFFINE = "affine"
    XOR = "xor"
    MBA = "mba"
    HASH = "hash"
    MODULO = "modulo"
    TABLE_LOOKUP = "table_lookup"
    PREDICATE = "predicate"
    UNKNOWN = "unknown"


def dispatch_key_transform_kind_from_any(
    value: object | None,
) -> DispatchKeyTransformKind | None:
    """Coerce a transform-kind value into ``DispatchKeyTransformKind``."""

    if value is None:
        return None
    if isinstance(value, DispatchKeyTransformKind):
        return value
    try:
        return DispatchKeyTransformKind(str(value))
    except ValueError:
        return None


__all__ = [
    "DispatchKeyTransformKind",
    "dispatch_key_transform_kind_from_any",
]
