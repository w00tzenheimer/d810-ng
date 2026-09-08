"""Owned structural values reject aliases and stale/forged handles."""

import pytest

from d810.core.runtime_identity import (
    RuntimeAuthorityArena,
    RuntimeAuthorityArenaError,
    RuntimeAuthorityScope,
)
from d810.core.structural_identity import (
    StructuralIdentityError,
    StructuralNodeKind as Kind,
    StructuralRef,
    compare_values,
)


def table():
    return RuntimeAuthorityArena(RuntimeAuthorityScope("test")).structural


def test_exact_typed_scalar_width_and_order_identity():
    terms = table()
    one = terms.intern(Kind.VALUE, None, (1,), ())
    truth = terms.intern(Kind.VALUE, None, (True,), ())
    assert one != truth
    assert terms.intern(Kind.VALUE, None, (1,), ()) is one
    assert terms.intern(Kind.OPERAND, 8, (), (one, truth)) != terms.intern(
        Kind.OPERAND, 16, (), (one, truth)
    )
    assert terms.intern(Kind.SEQUENCE, None, (), (one, truth)) != terms.intern(
        Kind.SEQUENCE, None, (), (truth, one)
    )


@pytest.mark.parametrize("payload", [([1],), ({"a": 1},), ((1,),), (object(),)])
def test_unsupported_descendants_never_enter_table(payload):
    terms = table()
    with pytest.raises(TypeError):
        terms.intern(Kind.VALUE, None, payload, ())
    assert len(terms) == 0


def test_reject_foreign_forged_and_wrong_kind_handles():
    terms, other = table(), table()
    ref = terms.intern(Kind.VALUE, None, (3,), ())
    with pytest.raises(StructuralIdentityError):
        other.resolve(ref, Kind.VALUE)
    forged = StructuralRef(ref.kind, ref.ordinal, ref.owner)
    with pytest.raises(StructuralIdentityError):
        terms.resolve(forged, Kind.VALUE)
    with pytest.raises(StructuralIdentityError):
        terms.resolve(ref, Kind.GRAPH)
    with pytest.raises(StructuralIdentityError):
        other.intern(Kind.SEQUENCE, None, (), (ref,))


def test_collision_bucket_never_substitutes_equality(monkeypatch):
    terms = table()
    monkeypatch.setattr(type(terms), "_key_hash", staticmethod(lambda key: 0))
    a = terms.intern(Kind.VALUE, None, (1,), ())
    b = terms.intern(Kind.VALUE, None, (2,), ())
    assert a != b
    assert terms.intern(Kind.VALUE, None, (1,), ()) is a


def test_published_nodes_are_immutable_and_reinitialization_cannot_rewrite():
    terms = table()
    ref = terms.intern(Kind.VALUE, None, (1,), ())
    node = terms.resolve(ref, Kind.VALUE)
    with pytest.raises(AttributeError):
        node.payload = (2,)
    node.__init__(Kind.VALUE, None, (2,), ())
    assert node.payload == (1,)
    terms.publish()
    assert terms.resolve(ref, Kind.VALUE).payload == (1,)
    with pytest.raises(StructuralIdentityError):
        terms.intern(Kind.VALUE, None, (2,), ())


def test_exact_cross_partition_comparison_and_owner_close():
    arena = RuntimeAuthorityArena(RuntimeAuthorityScope("test"))
    left, right = arena.structural, table()
    a = left.intern(Kind.VALUE, 8, (1,), ())
    b = right.intern(Kind.VALUE, 8, (1,), ())
    assert a != b
    assert compare_values(left, a, right, b)
    assert not compare_values(left, a, right, right.intern(Kind.VALUE, 16, (1,), ()))
    arena.close()
    assert len(left) == 0
    with pytest.raises(StructuralIdentityError):
        left.resolve(a, Kind.VALUE)
    with pytest.raises(StructuralIdentityError):
        compare_values(left, a, right, b)
    with pytest.raises(RuntimeAuthorityArenaError):
        _ = arena.structural
