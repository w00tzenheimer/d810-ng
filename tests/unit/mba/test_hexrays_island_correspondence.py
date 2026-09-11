from d810.mba.typed_term import TypedBvTerm


def _leaf(name: str, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(None, width, leaf_key=(name,))


def _node(operation: str, left: TypedBvTerm, right: TypedBvTerm) -> TypedBvTerm:
    return TypedBvTerm(operation, left.width, children=(left, right))


def test_direct_commutative_swap_retains_root_and_reverses_leaf_provenance() -> None:
    from d810.backends.mba.hexrays_island import _canonical_native_nodes_by_path

    a, b = _leaf("a"), _leaf("b")
    raw = _node("mul", b, a)
    canonical = _node("mul", a, b)
    root, raw_left, raw_right = object(), object(), object()

    mapped = _canonical_native_nodes_by_path(
        raw, canonical, {(): root, (0,): raw_left, (1,): raw_right}
    )

    assert mapped[()] is root
    assert mapped[(0,)] is raw_right
    assert mapped[(1,)] is raw_left


def test_ac_rebracketed_group_remains_synthetic_and_unmapped() -> None:
    from d810.backends.mba.hexrays_island import _canonical_native_nodes_by_path

    a, b, c = _leaf("a"), _leaf("b"), _leaf("c")
    raw = _node("xor", a, _node("xor", b, c))
    canonical = _node("xor", _node("xor", a, b), c)
    raw_nodes = {path: object() for path in ((), (0,), (1,), (1, 0), (1, 1))}

    mapped = _canonical_native_nodes_by_path(raw, canonical, raw_nodes)

    assert (0,) not in mapped
    assert mapped[(0, 0)] is raw_nodes[(0,)]
    assert mapped[(0, 1)] is raw_nodes[(1, 0)]


def test_ambiguous_equal_occurrences_fall_back_without_cross_pairing() -> None:
    from d810.backends.mba.hexrays_island import _canonical_native_nodes_by_path

    a = _leaf("a")
    raw = _node("mul", a, a)
    canonical = _node("mul", a, a)
    root, first, second = object(), object(), object()

    mapped = _canonical_native_nodes_by_path(
        raw, canonical, {(): root, (0,): first, (1,): second}
    )

    assert mapped[()] is root
    assert mapped[(0,)] is first
    assert mapped[(1,)] is second


def test_correspondence_is_bounded_and_never_canonicalizes_subtrees(monkeypatch) -> None:
    import d810.backends.mba.hexrays_island as island

    monkeypatch.setattr(
        island,
        "canonicalize_mba_term",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("must not canonicalize correspondence subtrees")
        ),
    )
    monkeypatch.setattr(
        TypedBvTerm,
        "__hash__",
        lambda _self: (_ for _ in ()).throw(
            AssertionError("must not recursively hash correspondence subtrees")
        ),
    )
    leaves = [_leaf(name) for name in ("a", "b", "c", "d")]
    raw = _node("sub", _node("mul", leaves[1], leaves[0]), _node("and", leaves[3], leaves[2]))
    canonical = _node("sub", _node("mul", leaves[0], leaves[1]), _node("and", leaves[2], leaves[3]))

    result = island._direct_permutation_correspondence(raw, canonical)

    assert result is not None
    assert result.pair_evaluations <= 49
    assert result.path_pair_allocations <= 196


def test_operation_or_width_rewrite_has_no_direct_correspondence() -> None:
    from d810.backends.mba.hexrays_island import _direct_permutation_correspondence

    a, b = _leaf("a"), _leaf("b")
    assert _direct_permutation_correspondence(_node("mul", a, b), _node("add", a, b)) is None
    wide_a, wide_b = _leaf("a", 64), _leaf("b", 64)
    assert _direct_permutation_correspondence(_node("mul", a, b), _node("mul", wide_a, wide_b)) is None


def test_equal_commuted_compounds_stay_with_their_distinct_ancestry() -> None:
    from d810.backends.mba.hexrays_island import _canonical_native_nodes_by_path

    a, b = _leaf("a"), _leaf("b")
    first, second = _node("mul", b, a), _node("mul", b, a)
    assert first == second and first is not second
    one, two = TypedBvTerm(None, 32, value=1), TypedBvTerm(None, 32, value=2)
    raw = _node("sub", _node("add", first, one), _node("add", second, two))
    canonical = _node(
        "sub",
        _node("add", _node("mul", a, b), one),
        _node("add", _node("mul", a, b), two),
    )
    first_native, second_native = object(), object()
    mapped = _canonical_native_nodes_by_path(
        raw, canonical, {(0, 0): first_native, (1, 0): second_native}
    )
    assert mapped[(0, 0)] is first_native
    assert mapped[(1, 0)] is second_native
