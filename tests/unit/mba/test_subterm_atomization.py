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


def test_ranking_uses_occurrence_count_when_saved_nodes_tie() -> None:
    one_node = _binary("and", _leaf("a"), _leaf("b"))
    two_nodes = _binary("or", _binary("xor", _leaf("c"), _leaf("d")), _leaf("e"))
    source = _binary(
        "add", _repeated(one_node, count=3), _repeated(two_nodes, count=2)
    )

    result = atomize_repeated_subterms(source, max_atoms=1)

    assert result.bindings[0].original_subterm == one_node
    assert result.bindings[0].saved_operator_nodes == 2
    assert result.bindings[0].occurrence_count == 3


def test_distinct_operator_terms_with_forced_fingerprint_collision_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _binary("and", _leaf("a"), _leaf("b"))
    second = _binary("or", _leaf("c"), _leaf("d"))
    source = _binary("add", first, second)
    monkeypatch.setattr(
        "d810.mba.subterm_atomization.term_fingerprint", lambda _term: "collision"
    )

    with pytest.raises(ValueError, match="collision"):
        atomize_repeated_subterms(source, min_occurrences=2)


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
    with pytest.raises(ValueError, match="min_occurrences"):
        atomize_repeated_subterms(source, min_occurrences=1)
    assert atomize_repeated_subterms(source).atomized_term == source


@pytest.mark.parametrize(
    ("min_occurrences", "min_operator_nodes", "max_atoms"),
    ((2, 1, 0), (2, 1, 1)),
)
def test_threshold_valid_boundaries_are_accepted(
    min_occurrences: int, min_operator_nodes: int, max_atoms: int
) -> None:
    source = _repeated(_binary("and", _leaf("x"), _leaf("y")))

    result = atomize_repeated_subterms(
        source,
        min_occurrences=min_occurrences,
        min_operator_nodes=min_operator_nodes,
        max_atoms=max_atoms,
    )

    assert len(result.bindings) <= max_atoms


@pytest.mark.parametrize("value", (0, 1, -1, True, 1.0))
def test_min_occurrences_requires_exact_int_at_least_two(value: object) -> None:
    source = _repeated(_binary("and", _leaf("x"), _leaf("y")))

    with pytest.raises((TypeError, ValueError)):
        atomize_repeated_subterms(source, min_occurrences=value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", (0, -1, False, 1.0))
def test_min_operator_nodes_requires_exact_int_at_least_one(value: object) -> None:
    source = _repeated(_binary("and", _leaf("x"), _leaf("y")))

    with pytest.raises((TypeError, ValueError)):
        atomize_repeated_subterms(source, min_operator_nodes=value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", (-1, False, 1.0))
def test_max_atoms_requires_exact_non_negative_int(value: object) -> None:
    source = _repeated(_binary("and", _leaf("x"), _leaf("y")))

    with pytest.raises((TypeError, ValueError)):
        atomize_repeated_subterms(source, max_atoms=value)  # type: ignore[arg-type]


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


def test_no_binding_mismatch_is_rejected_by_constructor_replay() -> None:
    original = _binary("add", _leaf("x"), _leaf("y"))
    wrong_atomized = _binary("add", _leaf("x"), _leaf("x"))

    with pytest.raises(ValueError, match="replay|derive|structure"):
        AtomizedMbaTerm(original, wrong_atomized, ())


def test_wrong_atomized_tree_is_rejected_by_constructor_replay() -> None:
    original_subterm = _binary("and", _leaf("x"), _leaf("y"))
    original = _binary("add", original_subterm, original_subterm)
    atomized = atomize_repeated_subterms(original)
    binding = atomized.bindings[0]
    wrong_atomized = _binary(
        "add",
        TypedBvTerm(None, 32, leaf_key=binding.leaf_key),
        _leaf("z"),
    )

    with pytest.raises(ValueError, match="replay|derive|structure"):
        AtomizedMbaTerm(original, wrong_atomized, (binding,))


def test_binding_fingerprint_must_match_original_subterm() -> None:
    original_subterm = _binary("and", _leaf("x"), _leaf("y"))

    with pytest.raises(ValueError, match="fingerprint"):
        MbaAtomBinding(
            ("d810.mba.atom.v1", 0, "wrong-fingerprint"),
            original_subterm,
            2,
            1,
        )


def test_binding_ordinals_must_match_sequence_order() -> None:
    original_subterm = _binary("and", _leaf("x"), _leaf("y"))
    fingerprint = term_fingerprint(original_subterm)
    key = ("d810.mba.atom.v1", 7, fingerprint)
    binding = MbaAtomBinding(key, original_subterm, 2, 1)
    original = _binary("add", original_subterm, original_subterm)
    atomized = _binary("add", TypedBvTerm(None, 32, leaf_key=key), TypedBvTerm(None, 32, leaf_key=key))

    with pytest.raises(ValueError, match="ordinal"):
        AtomizedMbaTerm(original, atomized, (binding,))


def test_reordered_binding_ordinals_are_rejected() -> None:
    inner = _binary("and", _leaf("x"), _leaf("y"))
    outer = _binary("or", inner, _leaf("z"))
    inner_key = ("d810.mba.atom.v1", 0, term_fingerprint(inner))
    outer_key = ("d810.mba.atom.v1", 1, term_fingerprint(outer))
    inner_binding = MbaAtomBinding(inner_key, inner, 2, 1)
    outer_binding = MbaAtomBinding(outer_key, outer, 2, 2)
    original = _binary("add", _leaf("q"), _leaf("q"))
    atomized = _binary(
        "add",
        TypedBvTerm(None, 32, leaf_key=outer_key),
        TypedBvTerm(None, 32, leaf_key=outer_key),
    )

    with pytest.raises(ValueError, match="ordinal|dependency|replay"):
        AtomizedMbaTerm(original, atomized, (outer_binding, inner_binding))


def test_false_occurrence_metadata_is_rejected_by_forward_replay() -> None:
    original_subterm = _binary("and", _leaf("x"), _leaf("y"))
    original = _binary("add", original_subterm, original_subterm)
    key = ("d810.mba.atom.v1", 0, term_fingerprint(original_subterm))
    binding = MbaAtomBinding(key, original_subterm, 3, 2)
    atomized = _binary(
        "add", TypedBvTerm(None, 32, leaf_key=key), TypedBvTerm(None, 32, leaf_key=key)
    )

    with pytest.raises(ValueError, match="occurrence|replay"):
        AtomizedMbaTerm(original, atomized, (binding,))


def test_forward_nested_binding_dependency_is_rejected() -> None:
    future_key = ("d810.mba.atom.v1", 1, "future")
    outer = _binary("or", TypedBvTerm(None, 32, leaf_key=future_key), _leaf("x"))
    outer_key = ("d810.mba.atom.v1", 0, term_fingerprint(outer))
    outer_binding = MbaAtomBinding(outer_key, outer, 2, 1)
    inner = _binary("and", _leaf("y"), _leaf("z"))
    inner_key = ("d810.mba.atom.v1", 1, term_fingerprint(inner))
    inner_binding = MbaAtomBinding(inner_key, inner, 2, 1)
    original = _binary("add", _leaf("q"), _leaf("q"))
    atomized = _binary(
        "add", TypedBvTerm(None, 32, leaf_key=outer_key), TypedBvTerm(None, 32, leaf_key=outer_key)
    )

    with pytest.raises(ValueError, match="dependency|forward"):
        AtomizedMbaTerm(original, atomized, (outer_binding, inner_binding))


def test_unknown_nested_binding_dependency_is_rejected() -> None:
    unknown_key = ("d810.mba.atom.v1", 9, "unknown")
    outer = _binary("or", TypedBvTerm(None, 32, leaf_key=unknown_key), _leaf("x"))
    outer_key = ("d810.mba.atom.v1", 0, term_fingerprint(outer))
    binding = MbaAtomBinding(outer_key, outer, 2, 1)
    original = _binary("add", _leaf("q"), _leaf("q"))
    atomized = _binary(
        "add", TypedBvTerm(None, 32, leaf_key=outer_key), TypedBvTerm(None, 32, leaf_key=outer_key)
    )

    with pytest.raises(ValueError, match="dependency|unknown"):
        AtomizedMbaTerm(original, atomized, (binding,))


def test_malformed_binding_width_is_rejected() -> None:
    original = _binary("and", _leaf("x"), _leaf("y"))
    original_subterm = _binary("and", _leaf("x", width=16), _leaf("y", width=16))
    atom = TypedBvTerm(
        None,
        32,
        leaf_key=("d810.mba.atom.v1", 0, term_fingerprint(original_subterm)),
    )
    malformed = MbaAtomBinding(
        leaf_key=atom.leaf_key,
        original_subterm=original_subterm,
        occurrence_count=2,
        saved_operator_nodes=1,
    )

    with pytest.raises(ValueError, match="width"):
        AtomizedMbaTerm(original, atom, (malformed,))


def test_restore_uses_reverse_binding_order_for_nested_bindings() -> None:
    x = _leaf("x")
    y = _leaf("y")
    z = _leaf("z")
    inner = _binary("and", y, z)
    inner_key = ("d810.mba.atom.v1", 0, term_fingerprint(inner))
    outer_source = _binary("or", inner, x)
    outer = _binary("or", TypedBvTerm(None, 32, leaf_key=inner_key), x)
    outer_key = ("d810.mba.atom.v1", 1, term_fingerprint(outer))
    inner_binding = MbaAtomBinding(inner_key, inner, 2, 1)
    outer_binding = MbaAtomBinding(outer_key, outer, 2, 1)
    original = _binary("add", outer_source, outer_source)
    atomized = AtomizedMbaTerm(
        original_term=original,
        atomized_term=_binary(
            "add",
            TypedBvTerm(None, 32, leaf_key=outer_key),
            TypedBvTerm(None, 32, leaf_key=outer_key),
        ),
        bindings=(inner_binding, outer_binding),
    )

    assert atomized.restore(atomized.atomized_term) == original


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


def test_native_candidate_wrapper_revalidates_adversarial_forged_views() -> None:
    source, _, _ = _triggering_fixture()
    candidate = _native_candidate(source)
    forged = object.__new__(AtomizedMbaTerm)
    object.__setattr__(forged, "original_term", source)
    object.__setattr__(forged, "atomized_term", _binary("add", _leaf("v17"), _leaf("v17")))
    object.__setattr__(forged, "bindings", ())

    with pytest.raises(ValueError, match="derive|structure"):
        AtomizedNativeMbaCandidate(candidate, forged)
