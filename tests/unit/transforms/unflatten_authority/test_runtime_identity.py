"""Scope-owned runtime references replace content-derived internal join IDs."""

from __future__ import annotations

import pytest

from d810.core.runtime_identity import (
    RUNTIME_AUTHORITY_ID_PREFIX,
    RuntimeAuthorityKind,
    RuntimeAuthorityRef,
    RuntimeAuthorityScope,
)
from d810.transforms.unflatten_authority.ids import canonical_bytes


def test_scope_mints_monotonic_ordinals_per_kind() -> None:
    scope = RuntimeAuthorityScope("0x1400:g3")

    first_group = scope.mint(RuntimeAuthorityKind.ROUTE_GROUP)
    first_proof = scope.mint(RuntimeAuthorityKind.ROUTE_PROOF)
    second_proof = scope.mint(RuntimeAuthorityKind.ROUTE_PROOF)
    second_group = scope.mint(RuntimeAuthorityKind.ROUTE_GROUP)

    assert (first_group.kind, first_group.ordinal) == (
        RuntimeAuthorityKind.ROUTE_GROUP,
        1,
    )
    assert (second_group.kind, second_group.ordinal) == (
        RuntimeAuthorityKind.ROUTE_GROUP,
        2,
    )
    assert (first_proof.ordinal, second_proof.ordinal) == (1, 2)


def test_scope_owns_only_its_own_references() -> None:
    scope = RuntimeAuthorityScope("0x1400:g3")
    other = RuntimeAuthorityScope("0x1400:g3")

    owned = scope.mint(RuntimeAuthorityKind.CLAIM)
    foreign = other.mint(RuntimeAuthorityKind.CLAIM)

    assert scope.owns(owned) is True
    assert scope.owns(foreign) is False
    assert other.owns(foreign) is True
    assert other.owns(owned) is False


def test_equal_kind_and_ordinal_from_different_scopes_are_unequal() -> None:
    scope = RuntimeAuthorityScope("0x1400:g3")
    other = RuntimeAuthorityScope("0x1400:g3")

    owned = scope.mint(RuntimeAuthorityKind.EVIDENCE)
    foreign = other.mint(RuntimeAuthorityKind.EVIDENCE)

    assert (owned.kind, owned.ordinal) == (foreign.kind, foreign.ordinal)
    assert owned != foreign
    assert len({owned, foreign}) == 2
    rebuilt = RuntimeAuthorityRef(owned.kind, owned.ordinal, owned._owner)
    assert owned == rebuilt and hash(owned) == hash(rebuilt)


def test_scope_rejects_foreign_and_untyped_references() -> None:
    scope = RuntimeAuthorityScope("0x1400:g3")
    other = RuntimeAuthorityScope("0x1400:g3")
    foreign = other.mint(RuntimeAuthorityKind.SUBJECT)

    with pytest.raises(ValueError, match="another runtime authority scope"):
        scope.identity(foreign)
    with pytest.raises(TypeError, match="runtime authority reference"):
        scope.owns("runtime:0x1400:g3#subject000001")
    with pytest.raises(TypeError, match="runtime authority kind"):
        scope.mint("route_proof")


def test_scope_identity_and_reference_render_readably() -> None:
    scope = RuntimeAuthorityScope("0x1400:g3")
    ref = scope.mint(RuntimeAuthorityKind.ROUTE_PROOF)

    assert ref.render() == "route_proof000001"
    assert str(ref) == "route_proof000001"
    assert scope.identity(ref) == (
        f"{RUNTIME_AUTHORITY_ID_PREFIX}0x1400:g3#route_proof000001"
    )
    assert "0x1400:g3" in repr(scope)
    assert "_owner" not in repr(ref)


def test_scope_identity_orders_lexicographically_with_mint_order() -> None:
    scope = RuntimeAuthorityScope("0x1400:g3")
    refs = tuple(
        scope.mint(RuntimeAuthorityKind.ROUTE_PROOF) for _ in range(12)
    )

    identities = tuple(scope.identity(ref) for ref in refs)
    assert tuple(sorted(identities)) == identities


def test_runtime_reference_refuses_canonical_serialization() -> None:
    scope = RuntimeAuthorityScope("0x1400:g3")
    ref = scope.mint(RuntimeAuthorityKind.ROUTE_PROOF)

    with pytest.raises(TypeError, match="RuntimeAuthorityRef"):
        canonical_bytes(ref)
    with pytest.raises(TypeError, match="RuntimeAuthorityScope"):
        canonical_bytes(scope)


def test_runtime_reference_rejects_invalid_construction() -> None:
    scope = RuntimeAuthorityScope("0x1400:g3")
    ref = scope.mint(RuntimeAuthorityKind.ROUTE_PROOF)

    with pytest.raises(TypeError, match="runtime authority kind"):
        RuntimeAuthorityRef(2, 1, ref._owner)
    with pytest.raises(ValueError, match="positive"):
        RuntimeAuthorityRef(RuntimeAuthorityKind.ROUTE_PROOF, 0, ref._owner)
    with pytest.raises(TypeError, match="owner token"):
        RuntimeAuthorityRef(RuntimeAuthorityKind.ROUTE_PROOF, 1, None)
    with pytest.raises(ValueError, match="namespace"):
        RuntimeAuthorityScope("   ")


def test_runtime_reference_is_immutable_after_construction() -> None:
    scope = RuntimeAuthorityScope("0x1400:g3")
    ref = scope.mint(RuntimeAuthorityKind.ROUTE_PROOF)

    with pytest.raises(AttributeError):
        ref.ordinal = 5  # type: ignore[misc]
