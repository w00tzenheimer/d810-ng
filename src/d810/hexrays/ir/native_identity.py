"""One identity for one live native object, shared by all of its proxies.

A Hex-Rays callback receives Python proxies, not C++ objects.  ``mblock_t.mba``
manufactures a fresh SWIG proxy on every access, so ``id(proxy)`` names the
wrapper rather than the ``mba_t`` behind it: two proxies for one live MBA get
two ``id`` values, and a *dead* proxy's ``id`` can be handed back to an
unrelated object.  Either failure silently corrupts a safe-point claim -- the
first lets one native epoch be claimed twice, the second lets a stale claim
suppress work on a genuinely new epoch.

This module produces the only identity D-810 keys native epochs on:

* a SWIG proxy is named by the C++ address behind ``this``;
* any other object (a test double, a compatibility shim) is named by a
  monotonically increasing incarnation serial whose lifetime is tied to that
  object -- through a weak reference when the type allows one, otherwise
  stamped on the instance -- so an address CPython recycles never resurrects
  a retired identity;
* anything that can support none of those is refused.

The returned value is a primitive: it retains no reference to the live object
and is safe to keep past callback return.
"""

from __future__ import annotations

import itertools
import weakref
from dataclasses import dataclass
from enum import Enum

__all__ = [
    "NativeIdentity",
    "NativeIdentityKind",
    "native_object_identity",
]


class NativeIdentityKind(str, Enum):
    """How one identity value was derived."""

    NATIVE_POINTER = "native_pointer"
    PROXY_INCARNATION = "proxy_incarnation"


@dataclass(frozen=True, slots=True)
class NativeIdentity:
    """Primitive, comparable name for one live native object."""

    kind: NativeIdentityKind
    value: int

    def __post_init__(self) -> None:
        if not isinstance(self.kind, NativeIdentityKind):
            raise TypeError("native identity kind must be a NativeIdentityKind")
        value = int(self.value)
        if value <= 0:
            raise ValueError("native identity value must be positive")
        object.__setattr__(self, "value", value)

    @property
    def is_native(self) -> bool:
        """Whether this identity is a real C++ address rather than a serial."""
        return self.kind is NativeIdentityKind.NATIVE_POINTER

    def __str__(self) -> str:
        return f"{self.kind.value}:0x{self.value:x}"


_INCARNATION_SERIALS = itertools.count(1)
# ``id`` -> (weak reference to the owner, serial).  An entry is authoritative
# only while its weak reference still resolves to the *same* object, so a
# recycled address can never inherit a retired serial even if the weakref
# callback has not run yet.
_INCARNATIONS: dict[int, tuple[weakref.ref, int]] = {}


_STAMP = "_d810_native_incarnation"


def _incarnation_serial(obj: object) -> int:
    """Serial that lives and dies with *obj*, never with its address."""
    address = id(obj)
    entry = _INCARNATIONS.get(address)
    if entry is not None and entry[0]() is obj:
        return entry[1]

    stamped = getattr(obj, _STAMP, None)
    if isinstance(stamped, int) and not isinstance(stamped, bool) and stamped > 0:
        return stamped

    serial = next(_INCARNATION_SERIALS)

    def _release(_reference: weakref.ref) -> None:
        current = _INCARNATIONS.get(address)
        if current is not None and current[1] == serial:
            del _INCARNATIONS[address]

    try:
        reference = weakref.ref(obj, _release)
    except TypeError:
        pass
    else:
        _INCARNATIONS[address] = (reference, serial)
        return serial

    # A ``__slots__`` or otherwise non-weak-referenceable object still needs a
    # lifetime-bound serial.  Stamping the instance ties the serial to the
    # object itself, which is exactly the guarantee ``id`` cannot give.  Live
    # SWIG proxies never reach here: they are named by ``this`` above.
    try:
        object.__setattr__(obj, _STAMP, serial)
    except (AttributeError, TypeError) as exc:
        raise TypeError(
            "native identity requires a SWIG proxy, a weak-referenceable "
            f"object, or a stampable instance, not {type(obj).__name__}"
        ) from exc
    return serial


def _native_pointer(obj: object) -> int | None:
    """Return the C++ address behind a SWIG proxy, or ``None``."""
    this = getattr(obj, "this", None)
    if this is None:
        return None
    try:
        pointer = int(this)
    except (TypeError, ValueError, OverflowError):
        return None
    # A null or negative ``this`` names no live object; refuse to key on it.
    return pointer if pointer > 0 else None


def native_object_identity(obj: object) -> NativeIdentity:
    """Name the live native object behind *obj* without retaining it."""
    if obj is None:
        raise TypeError("native identity requires a live object, not None")
    pointer = _native_pointer(obj)
    if pointer is not None:
        return NativeIdentity(
            kind=NativeIdentityKind.NATIVE_POINTER,
            value=pointer,
        )
    return NativeIdentity(
        kind=NativeIdentityKind.PROXY_INCARNATION,
        value=_incarnation_serial(obj),
    )
