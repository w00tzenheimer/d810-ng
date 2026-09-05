"""Identity of a live native object must not be a recyclable Python ``id``."""

from __future__ import annotations

import gc
import weakref
from types import SimpleNamespace

import pytest

from d810.hexrays.ir.native_identity import (
    NativeIdentity,
    NativeIdentityKind,
    native_object_identity,
)


class _WeakReferenceableFake:
    """A non-SWIG object that does support a weak reference."""


class _SwigProxy:
    """A stand-in for one SWIG proxy over a fixed C++ address."""

    def __init__(self, pointer: int) -> None:
        self.this = pointer


def test_two_proxies_over_one_pointer_share_one_identity() -> None:
    first = native_object_identity(_SwigProxy(0x7F0000001000))
    second = native_object_identity(_SwigProxy(0x7F0000001000))

    assert first == second
    assert first.kind is NativeIdentityKind.NATIVE_POINTER
    assert first.value == 0x7F0000001000
    assert first.is_native is True


@pytest.mark.parametrize("factory", [SimpleNamespace, _WeakReferenceableFake])
def test_repeated_calls_for_one_object_are_stable(factory) -> None:
    obj = factory()

    assert native_object_identity(obj) == native_object_identity(obj)


def test_distinct_pointers_are_distinct_identities() -> None:
    first = native_object_identity(_SwigProxy(0x7F0000001000))
    second = native_object_identity(_SwigProxy(0x7F0000002000))

    assert first != second


def test_non_native_object_never_reuses_a_recycled_python_id() -> None:
    """A dead object's ``id`` may be reused; its identity must not be."""

    seen: set[NativeIdentity] = set()
    addresses: set[int] = set()
    for _ in range(64):
        obj = SimpleNamespace()
        addresses.add(id(obj))
        identity = native_object_identity(obj)
        assert identity.kind is NativeIdentityKind.PROXY_INCARNATION
        assert identity.is_native is False
        assert identity not in seen
        seen.add(identity)
        del obj
        gc.collect()

    # The loop is only meaningful if CPython actually recycled an address.
    assert len(addresses) < 64
    assert len(seen) == 64


def test_identity_is_hashable_and_retains_no_reference_to_the_object() -> None:
    obj = _WeakReferenceableFake()
    identity = native_object_identity(obj)
    assert hash(identity) == hash(native_object_identity(obj))
    assert identity.kind is NativeIdentityKind.PROXY_INCARNATION

    observer = weakref.ref(obj)
    del obj
    gc.collect()

    # The registry that guarantees non-recycling must not keep the live
    # callback-local object alive.
    assert observer() is None


def test_unweakrefable_object_fails_closed() -> None:
    with pytest.raises(TypeError):
        native_object_identity(12345)


def test_none_fails_closed() -> None:
    with pytest.raises(TypeError):
        native_object_identity(None)


def test_non_positive_native_pointer_falls_back_to_an_incarnation() -> None:
    """A null ``this`` names no live object and must not become the key."""

    identity = native_object_identity(_SwigProxy(0))

    assert identity.kind is NativeIdentityKind.PROXY_INCARNATION


def test_native_identity_rejects_a_bad_kind() -> None:
    with pytest.raises(TypeError):
        NativeIdentity(kind="native_pointer", value=1)  # type: ignore[arg-type]
