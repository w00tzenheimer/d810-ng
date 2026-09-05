"""A lifecycle-owned arena is the only authority binding a ref to a record."""

from __future__ import annotations

import dataclasses

import pytest

from d810.core.runtime_identity import (
    RUNTIME_AUTHORITY_SIDECAR_FIELDS,
    RUNTIME_CLAIM_SIDECAR_FIELD,
    RuntimeAuthorityArena,
    RuntimeAuthorityArenaError,
    RuntimeAuthorityKind,
    RuntimeAuthorityRef,
    RuntimeAuthorityScope,
    RuntimeJoinRejected,
)
from d810.core.typing import NamedTuple
from d810.transforms.unflatten_authority.ids import canonical_bytes


@dataclasses.dataclass(frozen=True, slots=True)
class _Record:
    """A minimal immutable authority record, complete at construction."""

    label: str
    ea: int = 0


@dataclasses.dataclass
class _MutableRecord:
    label: str


class _PlainRecord:
    """A plain object: no frozen dataclass, no ``NamedTuple``, fields rebind."""

    def __init__(self, label: str) -> None:
        self.label = label


class _TupleRecord(NamedTuple):
    label: str
    ea: int = 0


def _arena(namespace: str = "0x1400:g3") -> RuntimeAuthorityArena:
    return RuntimeAuthorityArena(RuntimeAuthorityScope(namespace))


def test_mint_reads_back_the_exact_record_it_stored() -> None:
    arena = _arena()
    record = _Record("route group")

    ref = arena.mint(RuntimeAuthorityKind.ROUTE_GROUP, record)

    assert type(ref) is RuntimeAuthorityRef
    assert ref.kind is RuntimeAuthorityKind.ROUTE_GROUP
    assert arena.get(ref) is record
    assert arena.owns(ref) is True
    assert len(arena) == 1


def test_arena_mints_monotonic_ordinals_per_kind() -> None:
    arena = _arena()

    first_group = arena.mint(RuntimeAuthorityKind.ROUTE_GROUP, _Record("g1"))
    first_proof = arena.mint(RuntimeAuthorityKind.ROUTE_PROOF, _Record("p1"))
    second_proof = arena.mint(RuntimeAuthorityKind.ROUTE_PROOF, _Record("p2"))
    second_group = arena.mint(RuntimeAuthorityKind.ROUTE_GROUP, _Record("g2"))

    assert (first_group.ordinal, second_group.ordinal) == (1, 2)
    assert (first_proof.ordinal, second_proof.ordinal) == (1, 2)
    assert len(arena) == 4


def test_refs_and_records_iterate_in_mint_order_per_kind() -> None:
    arena = _arena()
    proofs = tuple(_Record(f"p{index}") for index in range(5))
    refs = tuple(
        arena.mint(RuntimeAuthorityKind.ROUTE_PROOF, record) for record in proofs
    )
    arena.mint(RuntimeAuthorityKind.CLAIM, _Record("claim"))

    assert tuple(arena.refs(RuntimeAuthorityKind.ROUTE_PROOF)) == refs
    assert tuple(arena.records(RuntimeAuthorityKind.ROUTE_PROOF)) == proofs
    assert tuple(arena.refs(RuntimeAuthorityKind.EVIDENCE)) == ()
    assert tuple(arena.records(RuntimeAuthorityKind.EVIDENCE)) == ()


def test_arena_rejects_a_reference_minted_by_another_scope() -> None:
    arena = _arena()
    foreign_scope = RuntimeAuthorityScope("0x1400:g3")
    foreign = foreign_scope.mint(RuntimeAuthorityKind.CLAIM)

    assert arena.owns(foreign) is False
    with pytest.raises(RuntimeAuthorityArenaError, match="another runtime authority scope"):
        arena.get(foreign)


def test_arena_rejects_a_reference_its_scope_owns_but_never_minted() -> None:
    scope = RuntimeAuthorityScope("0x1400:g3")
    arena = RuntimeAuthorityArena(scope)
    unminted = scope.mint(RuntimeAuthorityKind.SUBJECT)

    assert scope.owns(unminted) is True
    assert arena.owns(unminted) is False
    with pytest.raises(RuntimeAuthorityArenaError, match="never minted"):
        arena.get(unminted)


def test_closed_arena_refuses_to_mint_read_or_iterate() -> None:
    arena = _arena()
    ref = arena.mint(RuntimeAuthorityKind.EVIDENCE, _Record("evidence"))

    arena.close()

    assert arena.is_closed is True
    assert len(arena) == 0
    with pytest.raises(RuntimeAuthorityArenaError, match="closed"):
        arena.mint(RuntimeAuthorityKind.EVIDENCE, _Record("late"))
    with pytest.raises(RuntimeAuthorityArenaError, match="closed"):
        arena.get(ref)
    with pytest.raises(RuntimeAuthorityArenaError, match="closed"):
        arena.owns(ref)
    with pytest.raises(RuntimeAuthorityArenaError, match="closed"):
        tuple(arena.refs(RuntimeAuthorityKind.EVIDENCE))
    with pytest.raises(RuntimeAuthorityArenaError, match="closed"):
        tuple(arena.records(RuntimeAuthorityKind.EVIDENCE))
    arena.close()
    assert arena.is_closed is True


def test_stored_record_is_the_exact_object_and_a_copy_is_another_record() -> None:
    arena = _arena()
    record = _Record("claim", ea=0x1400)
    ref = arena.mint(RuntimeAuthorityKind.CLAIM, record)

    copy = dataclasses.replace(record, ea=0x1500)

    assert arena.get(ref) is record
    assert arena.get(ref) is not copy
    assert arena.get(ref).ea == 0x1400


def test_arena_refuses_canonical_serialization() -> None:
    arena = _arena()

    with pytest.raises(TypeError, match="RuntimeAuthorityArena"):
        canonical_bytes(arena)


def test_two_arenas_over_one_namespace_never_observe_each_other() -> None:
    left = _arena("0x1400:g3")
    right = _arena("0x1400:g3")

    left_ref = left.mint(RuntimeAuthorityKind.LEDGER, _Record("left"))
    right_ref = right.mint(RuntimeAuthorityKind.LEDGER, _Record("right"))

    assert (left_ref.kind, left_ref.ordinal) == (right_ref.kind, right_ref.ordinal)
    assert left_ref != right_ref
    assert left.get(left_ref).label == "left"
    assert right.get(right_ref).label == "right"
    assert left.owns(right_ref) is False and right.owns(left_ref) is False
    with pytest.raises(RuntimeAuthorityArenaError):
        left.get(right_ref)
    left.close()
    assert right.get(right_ref).label == "right"


def test_arena_requires_a_scope_and_an_immutable_record() -> None:
    with pytest.raises(TypeError, match="runtime authority scope"):
        RuntimeAuthorityArena("0x1400:g3")
    arena = _arena()
    with pytest.raises(TypeError, match="runtime authority kind"):
        arena.mint("claim", _Record("claim"))
    with pytest.raises(TypeError, match="frozen dataclass or NamedTuple"):
        arena.mint(RuntimeAuthorityKind.CLAIM, _MutableRecord("claim"))
    with pytest.raises(TypeError, match="frozen dataclass or NamedTuple"):
        arena.mint(RuntimeAuthorityKind.CLAIM, ["claim"])
    with pytest.raises(TypeError, match="frozen dataclass or NamedTuple"):
        arena.mint(RuntimeAuthorityKind.CLAIM, None)
    with pytest.raises(TypeError, match="runtime authority reference"):
        arena.get("route_group000001")
    assert len(arena) == 0


def test_arena_rejects_a_plain_mutable_object_at_mint() -> None:
    """The record allowlist is what makes ``get`` returning the exact object safe.

    A plain instance passes every "obviously mutable" denylist test -- it is
    not ``None``, not a mutable dataclass and not a builtin container -- while
    ``record.label = ...`` rebinds silently.  Storing one would let a holder of
    the record mutate authority the arena has already handed out.
    """

    arena = _arena()
    plain = _PlainRecord("claim")

    with pytest.raises(TypeError, match="frozen dataclass or NamedTuple"):
        arena.mint(RuntimeAuthorityKind.CLAIM, plain)

    assert len(arena) == 0
    assert tuple(arena.refs(RuntimeAuthorityKind.CLAIM)) == ()
    plain.label = "rewritten"  # the exact mutation the arena must never adopt
    assert plain.label == "rewritten"


def test_arena_rejects_records_that_are_immutable_but_unnamed() -> None:
    arena = _arena()

    for value in ("claim", 7, 7.5, True, b"claim", ("claim",), frozenset({"claim"})):
        with pytest.raises(TypeError, match="frozen dataclass or NamedTuple"):
            arena.mint(RuntimeAuthorityKind.CLAIM, value)
    with pytest.raises(TypeError, match="frozen dataclass or NamedTuple"):
        arena.mint(RuntimeAuthorityKind.CLAIM, _Record)  # the class, not an instance
    assert len(arena) == 0


def test_arena_accepts_a_named_tuple_record() -> None:
    arena = _arena()
    record = _TupleRecord("claim", ea=0x1400)

    ref = arena.mint(RuntimeAuthorityKind.CLAIM, record)

    assert arena.get(ref) is record
    with pytest.raises(AttributeError):
        arena.get(ref).label = "rewritten"  # type: ignore[misc]


def test_stored_record_cannot_be_rebound_through_the_arena() -> None:
    arena = _arena()
    ref = arena.mint(RuntimeAuthorityKind.CLAIM, _Record("claim", ea=0x1400))

    with pytest.raises(dataclasses.FrozenInstanceError):
        arena.get(ref).ea = 0x1500  # type: ignore[misc]
    assert arena.get(ref).ea == 0x1400


def test_arena_exposes_its_scope_without_taking_it_over() -> None:
    scope = RuntimeAuthorityScope("0x1400:g3")
    arena = RuntimeAuthorityArena(scope)
    ref = arena.mint(RuntimeAuthorityKind.ROUTE_GROUP, _Record("group"))

    assert arena.scope is scope
    assert arena.namespace == "0x1400:g3"
    assert scope.identity(ref) == "runtime:0x1400:g3#route_group000001"
    assert "0x1400:g3" in repr(arena)


def test_a_join_rejection_is_a_value_error_and_an_arena_error_is_not() -> None:
    """The two exceptions answer different questions and travel differently.

    A join rejection says the *input* to a correlation is not admissible, and
    the pipeline's graceful-abstention contract is ``except (TypeError,
    ValueError)`` -- so it must be a ``ValueError`` or every handler that was
    written to decline a bad producer input would instead let it abort a
    decompilation.  The arena's own error is an internal failure of an
    authority lookup and is deliberately not in that hierarchy: every holder
    of an arena translates it at its own boundary rather than letting it
    escape.
    """

    assert issubclass(RuntimeJoinRejected, ValueError)
    assert not issubclass(RuntimeJoinRejected, RuntimeError)
    assert issubclass(RuntimeAuthorityArenaError, RuntimeError)
    assert not issubclass(RuntimeAuthorityArenaError, ValueError)

    with pytest.raises(ValueError):
        raise RuntimeJoinRejected("a join refusal is a value error")


def test_the_sidecar_field_set_is_closed_and_names_private_fields_only() -> None:
    """Generic record-graph walkers key on this set; it must stay a closed set."""

    assert type(RUNTIME_AUTHORITY_SIDECAR_FIELDS) is frozenset
    assert RUNTIME_AUTHORITY_SIDECAR_FIELDS == {
        "_runtime_identity", "_runtime_binding", "_runtime_refs",
    }
    assert all(name.startswith("_") for name in RUNTIME_AUTHORITY_SIDECAR_FIELDS)
    # The claim factory writes the slot by this name and the walkers skip it by
    # this name; one constant, so they cannot drift apart.
    assert RUNTIME_CLAIM_SIDECAR_FIELD == "_runtime_refs"
    assert RUNTIME_CLAIM_SIDECAR_FIELD in RUNTIME_AUTHORITY_SIDECAR_FIELDS


def test_an_arena_is_reusable_only_until_its_owner_closes_it() -> None:
    """The closed branch is the one an owner makes reachable in production."""

    arena = RuntimeAuthorityArena(RuntimeAuthorityScope("0x1400:g3"))
    ref = arena.mint(RuntimeAuthorityKind.ROUTE_PROOF, _Record("proof"))
    assert arena.get(ref).label == "proof"

    arena.close()

    with pytest.raises(RuntimeAuthorityArenaError, match="closed"):
        arena.get(ref)
    arena.close()  # idempotent: an owner may close twice
    assert arena.is_closed
