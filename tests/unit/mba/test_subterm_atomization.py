"""Tests for deterministic repeated-subterm atomization."""

from __future__ import annotations

import pytest

from d810.mba.extension_api import (
    AtomizedNativeMbaCandidate,
    NativeMbaCandidate,
    atomize_native_candidate,
)
from d810.mba.subterm_atomization import (
    AtomizedMbaTerm,
    MbaAtomBinding,
    atomize_repeated_subterms,
)
from d810.mba.typed_term import TypedBvTerm, term_cost, term_fingerprint
from d810.mba.island_profile import profile_typed_term


def _leaf(name: str, *, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(None, width, leaf_key=("register", name))


def _constant(value: int, *, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(None, width, value=value)


def _binary(
    operation: str, left: TypedBvTerm, right: TypedBvTerm
) -> TypedBvTerm:
    return TypedBvTerm(operation, left.width, children=(left, right))


def _triggering_fixture() -> tuple[TypedBvTerm, TypedBvTerm, TypedBvTerm]:
    x = _leaf("v17")
    v135 = _leaf("v135")
    mask = _constant(0xFFFFFBFB)
    y = _binary("and", v135, mask)
    source = _binary(
        "add",
        _binary(
            "sub",
            _binary("xor", x, y),
            _binary(
                "add",
                _binary("and", x, y),
                _binary(
                    "mul",
                    _constant(2),
                    _binary("and", y, TypedBvTerm("bnot", 32, children=(x,))),
                ),
            ),
        ),
        _binary("mul", _constant(2), y),
    )
    return source, x, y


def _count_structural(term: TypedBvTerm, target: TypedBvTerm) -> int:
    return (term == target) + sum(
        _count_structural(child, target) for child in term.children
    )


def test_triggering_masked_subterm_is_atomized_and_restored() -> None:
    source, x, y = _triggering_fixture()

    assert _count_structural(source, y) == 4

    atomized = atomize_repeated_subterms(source)

    assert len(atomized.bindings) == 1
    assert atomized.bindings[0].original_subterm == y
    assert atomized.bindings[0].occurrence_count == 4
    assert term_cost(atomized.atomized_term)[0] < term_cost(source)[0]
    assert atomized.restore(atomized.atomized_term) == source

    atom = TypedBvTerm(None, 32, leaf_key=atomized.bindings[0].leaf_key)
    replacement = _binary("or", x, atom)
    assert atomized.restore(replacement) == _binary("or", x, y)
    assert term_fingerprint(atomized.restore(replacement)) == term_fingerprint(
        _binary("or", x, y)
    )


def _repeated(term: TypedBvTerm, *, count: int = 2) -> TypedBvTerm:
    result = term
    for _ in range(count - 1):
        result = _binary("add", result, term)
    return result


def test_ranking_prefers_saved_operator_nodes_then_occurrences() -> None:
    x = _leaf("x")
    y = _leaf("y")
    z = _leaf("z")
    small = _binary("and", x, y)
    large = _binary("or", _binary("xor", x, y), z)
    source = _binary("add", _repeated(small, count=4), _repeated(large, count=2))

    result = atomize_repeated_subterms(source, max_atoms=1)

    assert len(result.bindings) == 1
    assert result.bindings[0].original_subterm == small
    assert result.bindings[0].occurrence_count == 4
    assert result.bindings[0].saved_operator_nodes == 3


def test_nested_overlaps_select_outer_and_recompute_after_selection() -> None:
    x = _leaf("x")
    y = _leaf("y")
    inner = _binary("and", x, y)
    outer = _binary("or", inner, _leaf("z"))
    source = _binary("add", outer, outer)

    result = atomize_repeated_subterms(source, max_atoms=4)

    assert len(result.bindings) == 1
    assert result.bindings[0].original_subterm == outer
    assert result.bindings[0].occurrence_count == 2


def test_ties_are_resolved_by_lexicographically_smallest_fingerprint() -> None:
    first = _binary("and", _leaf("a"), _leaf("b"))
    second = _binary("or", _leaf("c"), _leaf("d"))
    source = _binary("add", _repeated(first), _repeated(second))

    result = atomize_repeated_subterms(source, max_atoms=1)

    assert result.bindings[0].original_subterm in (first, second)
    expected = min((first, second), key=term_fingerprint)
    assert result.bindings[0].original_subterm == expected


def test_atomization_limits_and_root_exclusion_are_deterministic() -> None:
    x = _leaf("x")
    y = _leaf("y")
    source = _binary("add", x, y)

    assert atomize_repeated_subterms(source, max_atoms=0).bindings == ()
    assert atomize_repeated_subterms(source, min_occurrences=1).bindings == ()
    assert atomize_repeated_subterms(source).atomized_term == source


def test_same_shape_terms_at_different_widths_have_distinct_atoms() -> None:
    source32 = _repeated(_binary("and", _leaf("x", width=32), _leaf("y", width=32)))
    source16 = _repeated(_binary("and", _leaf("x", width=16), _leaf("y", width=16)))

    result32 = atomize_repeated_subterms(source32)
    result16 = atomize_repeated_subterms(source16)

    assert result32.bindings[0].original_subterm.width == 32
    assert result16.bindings[0].original_subterm.width == 16
    assert result32.bindings[0].leaf_key != result16.bindings[0].leaf_key


def test_reserved_atom_namespace_collision_is_rejected() -> None:
    reserved_leaf = _leaf("reserved")
    reserved_leaf = TypedBvTerm(
        None,
        32,
        leaf_key=("d810.mba.atom.v1", 0, "not-generated-here"),
    )
    source = _repeated(_binary("and", reserved_leaf, _leaf("x")))

    with pytest.raises(ValueError, match="reserved"):
        atomize_repeated_subterms(source)


def test_restore_rejects_unknown_reserved_atom() -> None:
    source, _, _ = _triggering_fixture()
    atomized = atomize_repeated_subterms(source)
    unknown = TypedBvTerm(None, 32, leaf_key=("d810.mba.atom.v1", 99, "unknown"))

    with pytest.raises(ValueError, match="unknown"):
        atomized.restore(unknown)


def test_duplicate_binding_keys_are_rejected() -> None:
    source, _, _ = _triggering_fixture()
    atomized = atomize_repeated_subterms(source)
    binding = atomized.bindings[0]

    with pytest.raises(ValueError, match="duplicate"):
        AtomizedMbaTerm(
            original_term=atomized.original_term,
            atomized_term=atomized.atomized_term,
            bindings=(binding, binding),
        )


def test_malformed_binding_width_is_rejected() -> None:
    original = _binary("and", _leaf("x"), _leaf("y"))
    atom = TypedBvTerm(None, 32, leaf_key=("d810.mba.atom.v1", 0, "fp"))
    malformed = MbaAtomBinding(
        leaf_key=atom.leaf_key,
        original_subterm=_binary("and", _leaf("x", width=16), _leaf("y", width=16)),
        occurrence_count=2,
        saved_operator_nodes=1,
    )

    with pytest.raises(ValueError, match="width"):
        AtomizedMbaTerm(original, atom, (malformed,))


def test_restore_uses_reverse_binding_order_for_nested_bindings() -> None:
    x = _leaf("x")
    y = _leaf("y")
    z = _leaf("z")
    inner_key = ("d810.mba.atom.v1", 0, "inner")
    outer_key = ("d810.mba.atom.v1", 1, "outer")
    inner = _binary("and", y, z)
    outer = _binary("or", TypedBvTerm(None, 32, leaf_key=inner_key), x)
    inner_binding = MbaAtomBinding(inner_key, inner, 2, 1)
    outer_binding = MbaAtomBinding(outer_key, outer, 2, 1)
    atomized = AtomizedMbaTerm(
        original_term=_binary("or", inner, x),
        atomized_term=TypedBvTerm(None, 32, leaf_key=outer_key),
        bindings=(inner_binding, outer_binding),
    )

    assert atomized.restore(TypedBvTerm(None, 32, leaf_key=outer_key)) == _binary(
        "or", inner, x
    )


def _native_candidate(term: TypedBvTerm, *, context: object = None) -> NativeMbaCandidate:
    return NativeMbaCandidate(
        destination_size=term.width // 8,
        term=term,
        raw_term=term,
        profile=profile_typed_term(term),
        native_context=object() if context is None else context,
    )


def test_native_candidate_wrapper_is_portable_and_preserves_context_and_width() -> None:
    source, _, y = _triggering_fixture()
    context = object()
    candidate = _native_candidate(source, context=context)

    wrapped = atomize_native_candidate(candidate)

    assert isinstance(wrapped, AtomizedNativeMbaCandidate)
    assert wrapped.candidate.native_context is context
    assert wrapped.term.width == candidate.term.width == candidate.destination_size * 8
    atom = TypedBvTerm(None, 32, leaf_key=wrapped.view.bindings[0].leaf_key)
    restored = wrapped.restore_replacement(_binary("or", _leaf("v17"), atom))
    assert restored == _binary("or", _leaf("v17"), y)


def test_native_candidate_wrapper_rejects_candidate_view_identity_or_width_mismatch() -> None:
    source, _, _ = _triggering_fixture()
    candidate = _native_candidate(source)
    other = _repeated(_binary("and", _leaf("a"), _leaf("b")))
    other_view = atomize_repeated_subterms(other)

    with pytest.raises(ValueError, match="candidate"):
        AtomizedNativeMbaCandidate(candidate, other_view)

    width_view = atomize_repeated_subterms(
        _repeated(_binary("and", _leaf("a", width=16), _leaf("b", width=16)))
    )
    with pytest.raises(ValueError, match="width"):
        AtomizedNativeMbaCandidate(candidate, width_view)
