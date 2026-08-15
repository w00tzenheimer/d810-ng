"""Runtime contract for the active native MBA POD matcher backend."""

from __future__ import annotations

import pytest

from d810.backends.mba.native_pod_matcher import matcher_backend
from d810.core.cymode import CythonMode


def _assert_native_result_matches_portable(native, portable) -> None:
    """The optimized matcher may use fewer structural comparisons."""

    assert native.matches == portable.matches
    assert native.comparison_budget_exceeded is portable.comparison_budget_exceeded
    assert native.candidate_term == portable.candidate_term
    assert native.comparisons <= portable.comparisons
    assert native.lazy_swaps <= portable.lazy_swaps


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_active_cython_pod_matcher_is_selected_when_cython_is_enabled() -> None:
    assert CythonMode().is_enabled()
    assert matcher_backend() == "cython"


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_cython_pod_matcher_returns_ac_bindings_and_honors_its_budget() -> None:
    from d810.speedups.mba.c_native_pod_matcher import match_pod_pattern

    pattern_rows = (
        (2, 0, 0, 0, 0, -1, -1),
        (2, 0, 1, 0, 0, -1, -1),
        (3, 1, -1, 0, 0, 0, 1),
    )
    candidate_rows = (
        (2, 0, 32, -1, -1, 0, 0, 0, 0),
        (2, 0, 32, -1, -1, 0, 1, 1, 1),
        (3, 1, 32, 0, 1, 0, -1, 2, 2),
    )

    matches, comparisons, lazy_swaps, exceeded = match_pod_pattern(
        pattern_rows,
        candidate_rows,
        2,
        2,
        64,
    )

    assert matches == ((0, 1), (1, 0))
    assert comparisons >= 3
    assert lazy_swaps == 1
    assert exceeded is False
    assert match_pod_pattern(pattern_rows, candidate_rows, 2, 2, 1)[3] is True


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_cython_pod_catalogue_matches_multiple_patterns_in_one_call() -> None:
    from d810.speedups.mba.c_native_pod_matcher import match_pod_catalogue

    pattern_rows = (
        (2, 0, 0, 0, 0, -1, -1),
        (2, 0, 1, 0, 0, -1, -1),
        (3, 1, -1, 0, 0, 0, 1),
    )
    constant_pattern_rows = (
        (1, 0, -1, 7, 0, -1, -1),
        (2, 0, 0, 0, 0, -1, -1),
        (3, 1, -1, 0, 0, 0, 1),
    )
    candidate_rows = (
        (2, 0, 32, -1, -1, 0, 0, 0, 0),
        (2, 0, 32, -1, -1, 0, 1, 1, 1),
        (3, 1, 32, 0, 1, 0, -1, 2, 2),
    )

    matches, comparisons, lazy_swaps, exceeded = match_pod_catalogue(
        ((pattern_rows, 2), (constant_pattern_rows, 1)),
        candidate_rows,
        2,
        64,
    )

    assert matches == (((0, 1), (1, 0)), ())
    assert comparisons >= 4
    assert lazy_swaps == 2
    assert exceeded is False


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_cython_catalogue_rejects_larger_pattern_before_structural_comparisons() -> (
    None
):
    """A pattern cannot structurally fit into a smaller candidate tree."""

    from d810.speedups.mba.c_native_pod_matcher import match_pod_catalogue

    # ``add(x, and(y, z))`` has five structural nodes; this ``add`` root has
    # only its two leaf children.  The cheap cardinality rejection must happen
    # before the bounded rollback matcher increments its comparison counter.
    larger_pattern = (
        (2, 0, 0, 0, 0, -1, -1),
        (2, 0, 1, 0, 0, -1, -1),
        (2, 0, 2, 0, 0, -1, -1),
        (3, 2, -1, 0, 0, 1, 2),
        (3, 1, -1, 0, 0, 0, 3),
    )
    candidate_rows = (
        (2, 0, 32, -1, -1, 0, 0, 0, 0),
        (2, 0, 32, -1, -1, 0, 1, 1, 1),
        (3, 1, 32, 0, 1, 0, -1, 2, 2),
    )

    matches, comparisons, lazy_swaps, exceeded = match_pod_catalogue(
        ((larger_pattern, 3),), candidate_rows, 2, 64
    )

    assert matches == ((),)
    assert comparisons == 0
    assert lazy_swaps == 0
    assert exceeded is False


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_cython_pod_matcher_flattens_associative_chains_with_bounded_rollback() -> None:
    from d810.speedups.mba.c_native_pod_matcher import match_pod_pattern

    pattern_rows = (
        (2, 0, 0, 0, 0, -1, -1),
        (2, 0, 1, 0, 0, -1, -1),
        (3, 1, -1, 0, 0, 0, 1),
        (2, 0, 2, 0, 0, -1, -1),
        (3, 1, -1, 0, 0, 2, 3),
    )
    candidate_rows = (
        (2, 0, 32, -1, -1, 0, 0, 0, 0),
        (2, 0, 32, -1, -1, 0, 1, 1, 1),
        (3, 1, 32, 0, 1, 0, -1, 2, 2),
        (2, 0, 32, -1, -1, 0, 3, 3, 3),
        (3, 1, 32, 2, 3, 0, -1, 4, 4),
    )

    matches, comparisons, lazy_swaps, exceeded = match_pod_pattern(
        pattern_rows,
        candidate_rows,
        4,
        3,
        64,
    )

    assert matches == (
        (0, 1, 3),
        (0, 3, 1),
        (1, 0, 3),
        (1, 3, 0),
        (3, 0, 1),
        (3, 1, 0),
    )
    assert comparisons > 0
    assert lazy_swaps == 0
    assert exceeded is False


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_cython_pod_matcher_rejects_malformed_candidate_row_schema() -> None:
    from d810.speedups.mba.c_native_pod_matcher import match_pod_pattern

    with pytest.raises(ValueError, match="candidate POD rows"):
        match_pod_pattern(
            ((2, 0, 0, 0, 0, -1, -1),),
            ((2, 0, 32, -1, -1, 0, 0, 0),),
            0,
            1,
            8,
        )


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_cython_pod_matcher_rejects_candidate_rows_above_fixed_capacity() -> None:
    from d810.speedups.mba.c_native_pod_matcher import match_pod_pattern

    rows = tuple((2, 0, 32, -1, -1, 0, index, index, index) for index in range(33))

    with pytest.raises(ValueError, match="fixed capacity"):
        match_pod_pattern(
            ((2, 0, 0, 0, 0, -1, -1),),
            rows,
            0,
            1,
            64,
        )


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_cython_pod_matcher_rejects_pattern_rows_above_fixed_capacity() -> None:
    """Both sides of the POD match must fit the fixed native work buffers."""

    from d810.speedups.mba.c_native_pod_matcher import match_pod_pattern

    pattern_rows = tuple((2, 0, -1, 0, 0, -1, -1) for _ in range(33))
    candidate_rows = ((2, 0, 32, -1, -1, 0, 0, 0, 0),)

    with pytest.raises(ValueError, match="fixed capacity"):
        match_pod_pattern(pattern_rows, candidate_rows, 0, 0, 64)


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_cython_pod_matcher_accepts_handler_comparison_budget() -> None:
    """The fixed result buffer must not lower the handler's work budget."""

    from d810.speedups.mba.c_native_pod_matcher import match_pod_pattern

    pattern_rows = ((2, 0, -1, 0, 0, -1, -1),)
    candidate_rows = ((2, 0, 32, -1, -1, 0, 0, 0, 0),)

    assert match_pod_pattern(pattern_rows, candidate_rows, 0, 0, 256) == (
        ((),),
        1,
        0,
        False,
    )


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_cython_pod_matcher_rejects_comparison_budget_above_fixed_work_limit() -> None:
    from d810.speedups.mba.c_native_pod_matcher import match_pod_pattern

    pattern_rows = ((2, 0, -1, 0, 0, -1, -1),)
    candidate_rows = ((2, 0, 32, -1, -1, 0, 0, 0, 0),)

    with pytest.raises(ValueError, match="fixed capacity"):
        match_pod_pattern(pattern_rows, candidate_rows, 0, 0, 257)


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_public_catalogue_keeps_associative_chain_matching_in_cython(
    monkeypatch,
) -> None:
    from d810.backends.mba import native_pod_matcher
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
    from d810.backends.mba.egglog_add_rule_compiler import compile_add_rule_catalogue
    from d810.backends.mba.native_mba_term_view import NativeMbaTermView

    rule = (
        compile_add_rule_catalogue()
        .receipt_for("Add_HackersDelightRule_2")
        .compiled_rule
    )
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    x = NativeMbaTermView(None, 32, leaf_key=("mop", "r", "x"))
    y = NativeMbaTermView(None, 32, leaf_key=("mop", "r", "y"))
    z = NativeMbaTermView(None, 32, leaf_key=("mop", "r", "z"))
    candidate = NativeMbaTermView(
        "add",
        32,
        children=(NativeMbaTermView("add", 32, children=(x, y)), z),
    )
    original = native_pod_matcher._match_pod_catalogue
    calls = 0

    def observed(*args):
        nonlocal calls
        calls += 1
        return original(*args)

    monkeypatch.setattr(native_pod_matcher, "_match_pod_catalogue", observed)

    _assert_native_result_matches_portable(
        catalogue.match_root(candidate, comparison_budget=64),
        catalogue._match_root_portable(candidate, comparison_budget=64),
    )
    assert calls == 1


def test_cython_pod_catalogue_adapter_matches_portable_catalogue() -> None:
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
    from d810.backends.mba.egglog_add_rule_compiler import compile_add_rule_catalogue
    from d810.backends.mba.native_mba_term_view import NativeMbaTermView
    from d810.backends.mba.native_pod_matcher import match_root_pod

    catalogue = CompiledPatternCatalogue.from_rules(
        compile_add_rule_catalogue().compiled_rules
    )
    x = NativeMbaTermView(None, 32, leaf_key=("mop", "r", "x"))
    y = NativeMbaTermView(None, 32, leaf_key=("mop", "r", "y"))
    two = NativeMbaTermView(None, 32, constant_value=2)
    candidate = NativeMbaTermView(
        "add",
        32,
        children=(
            NativeMbaTermView("xor", 32, children=(y, x)),
            NativeMbaTermView(
                "mul",
                32,
                children=(two, NativeMbaTermView("and", 32, children=(y, x))),
            ),
        ),
    )

    _assert_native_result_matches_portable(
        match_root_pod(catalogue, candidate, comparison_budget=64),
        catalogue._match_root_portable(candidate, comparison_budget=64),
    )


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_cython_pod_catalogue_reuses_packed_terms_without_view_rematerialization(
    monkeypatch,
) -> None:
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
    from d810.backends.mba.egglog_add_rule_compiler import compile_add_rule_catalogue
    from d810.backends.mba.native_mba_term_view import NativeMbaTermView

    catalogue = CompiledPatternCatalogue.from_rules(
        compile_add_rule_catalogue().compiled_rules
    )
    x = NativeMbaTermView(None, 32, leaf_key=("mop", "r", "x"))
    y = NativeMbaTermView(None, 32, leaf_key=("mop", "r", "y"))
    two = NativeMbaTermView(None, 32, constant_value=2)
    candidate = NativeMbaTermView(
        "add",
        32,
        children=(
            NativeMbaTermView("xor", 32, children=(x, y)),
            NativeMbaTermView(
                "mul",
                32,
                children=(two, NativeMbaTermView("and", 32, children=(x, y))),
            ),
        ),
    )

    def forbidden_rematerialization(_view):
        raise AssertionError("Cython matcher must reuse the packed typed-term cache")

    monkeypatch.setattr(
        NativeMbaTermView,
        "to_typed_term",
        forbidden_rematerialization,
    )

    result = catalogue.match_root(candidate, comparison_budget=64)

    assert result.matches
    assert result.candidate_term is not None


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_public_catalogue_match_uses_cython_pod_backend(monkeypatch) -> None:
    from d810.backends.mba import native_pod_matcher
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
    from d810.backends.mba.egglog_add_rule_compiler import compile_add_rule_catalogue
    from d810.backends.mba.native_mba_term_view import NativeMbaTermView

    catalogue = CompiledPatternCatalogue.from_rules(
        compile_add_rule_catalogue().compiled_rules
    )
    x = NativeMbaTermView(None, 32, leaf_key=("mop", "r", "x"))
    y = NativeMbaTermView(None, 32, leaf_key=("mop", "r", "y"))
    two = NativeMbaTermView(None, 32, constant_value=2)
    candidate = NativeMbaTermView(
        "add",
        32,
        children=(
            NativeMbaTermView("xor", 32, children=(x, y)),
            NativeMbaTermView(
                "mul",
                32,
                children=(two, NativeMbaTermView("and", 32, children=(x, y))),
            ),
        ),
    )
    calls = 0
    original = native_pod_matcher._match_pod_catalogue

    def observed(*args):
        nonlocal calls
        calls += 1
        return original(*args)

    monkeypatch.setattr(native_pod_matcher, "_match_pod_catalogue", observed)

    _assert_native_result_matches_portable(
        catalogue.match_root(candidate, comparison_budget=64),
        catalogue._match_root_portable(candidate, comparison_budget=64),
    )
    assert calls == 1


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_public_catalogue_uses_cython_at_the_handler_comparison_budget(
    monkeypatch,
) -> None:
    """The live handler's 256-comparison ceiling must remain accelerated."""

    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
    from d810.backends.mba.egglog_add_rule_compiler import compile_add_rule_catalogue
    from d810.backends.mba.native_mba_term_view import NativeMbaTermView

    catalogue = CompiledPatternCatalogue.from_rules(
        compile_add_rule_catalogue().compiled_rules
    )
    x = NativeMbaTermView(None, 32, leaf_key=("mop", "r", "x"))
    y = NativeMbaTermView(None, 32, leaf_key=("mop", "r", "y"))
    two = NativeMbaTermView(None, 32, constant_value=2)
    candidate = NativeMbaTermView(
        "add",
        32,
        children=(
            NativeMbaTermView("xor", 32, children=(x, y)),
            NativeMbaTermView(
                "mul",
                32,
                children=(two, NativeMbaTermView("and", 32, children=(x, y))),
            ),
        ),
    )

    def forbidden_portable(*_args, **_kwargs):
        raise AssertionError("handler-budget match must not fall back to Python")

    monkeypatch.setattr(
        CompiledPatternCatalogue, "_match_root_portable", forbidden_portable
    )

    result = catalogue.match_root(candidate, comparison_budget=256)

    assert result.matches
    assert result.matcher_backend == "cython"


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_public_catalogue_match_reuses_its_numeric_compiled_patterns(
    monkeypatch,
) -> None:
    from d810.backends.mba import native_pod_matcher
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
    from d810.backends.mba.egglog_add_rule_compiler import compile_add_rule_catalogue
    from d810.backends.mba.native_mba_term_view import NativeMbaTermView

    catalogue = CompiledPatternCatalogue.from_rules(
        compile_add_rule_catalogue().compiled_rules
    )
    assert all(
        pattern.pod_pattern is not None
        for pattern in catalogue.root_width_buckets[("add", 32)]
    )
    x = NativeMbaTermView(None, 32, leaf_key=("mop", "r", "x"))
    y = NativeMbaTermView(None, 32, leaf_key=("mop", "r", "y"))
    two = NativeMbaTermView(None, 32, constant_value=2)
    candidate = NativeMbaTermView(
        "add",
        32,
        children=(
            NativeMbaTermView("xor", 32, children=(x, y)),
            NativeMbaTermView(
                "mul",
                32,
                children=(two, NativeMbaTermView("and", 32, children=(x, y))),
            ),
        ),
    )

    def forbidden_encode(*_args):
        raise AssertionError("candidate matching must reuse catalogue POD patterns")

    monkeypatch.setattr(native_pod_matcher, "encode_symbolic_pattern", forbidden_encode)
    assert catalogue.match_root(candidate, comparison_budget=64).matches


def test_public_catalogue_match_falls_back_to_portable_oracle(monkeypatch) -> None:
    from d810.backends.mba import native_pod_matcher
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
    from d810.backends.mba.egglog_add_rule_compiler import compile_add_rule_catalogue
    from d810.backends.mba.native_mba_term_view import NativeMbaTermView

    rule = (
        compile_add_rule_catalogue()
        .receipt_for("Add_HackersDelightRule_2")
        .compiled_rule
    )
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    x = NativeMbaTermView(None, 32, leaf_key=("mop", "r", "x"))
    y = NativeMbaTermView(None, 32, leaf_key=("mop", "r", "y"))
    two = NativeMbaTermView(None, 32, constant_value=2)
    candidate = NativeMbaTermView(
        "add",
        32,
        children=(
            NativeMbaTermView("xor", 32, children=(x, y)),
            NativeMbaTermView(
                "mul",
                32,
                children=(two, NativeMbaTermView("and", 32, children=(x, y))),
            ),
        ),
    )
    monkeypatch.setattr(native_pod_matcher, "_match_pod_pattern", None)

    result = catalogue.match_root(candidate, comparison_budget=64)

    assert result == catalogue._match_root_portable(candidate, comparison_budget=64)
    assert result.matcher_backend == "python"
