"""Runtime contract for the active native MBA POD matcher backend."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from d810.backends.mba.native_pod_matcher import matcher_backend
from d810.core.cymode import CythonMode
from d810.mba.typed_term import term_fingerprint
from d810.backends.mba.compiled_pattern_catalogue import (
    NativeMatchSelection,
    NativeMatchStopReason,
)


@dataclass(frozen=True)
class _ParityCase:
    name: str
    catalogue: object
    candidate: object
    comparison_budget: int
    expected_selection: NativeMatchSelection
    expected_stop_reason: NativeMatchStopReason
    expected_match_count: int
    expected_nonempty: bool
    expected_raw_budget_exceeded: bool
    expected_canonical_budget_exceeded: bool
    expected_fallback_work: bool
    configure: object = None


def _match_semantics(result):
    """Return backend-neutral match and resource semantics for parity checks."""

    matches = tuple(
        (
            (match.rule.source_name, *match.rule.aliases),
            tuple(
                sorted(
                    (name, term_fingerprint(view.to_typed_term()))
                    for name, view in match.bindings.native.items()
                )
            ),
            tuple(
                sorted(
                    (name, term_fingerprint(term))
                    for name, term in match.bindings.terms.items()
                )
            ),
            term_fingerprint(match.bindings.materialize_replacement(match.rule)),
        )
        for match in result.matches
    )
    return (
        matches,
        result.comparisons,
        result.lazy_swaps,
        result.fallback_comparisons,
        result.fallback_commuted_branches,
        result.fallback_flattened_nodes,
        result.comparison_budget_exceeded,
        result.canonical_budget_exceeded,
        result.selection,
        result.stop_reason,
    )


def _active_and_python_results(monkeypatch, catalogue, candidate, *, budget=64):
    from d810.backends.mba import native_pod_matcher

    active = catalogue.match_root(candidate, comparison_budget=budget)
    with monkeypatch.context() as patch:
        patch.setattr(native_pod_matcher, "_match_pod_catalogue", None)
        python = catalogue.match_root(candidate, comparison_budget=budget)
    return active, python


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_active_cython_pod_matcher_is_selected_when_cython_is_enabled() -> None:
    assert CythonMode().is_enabled()
    assert matcher_backend() == "cython"


def test_public_catalogue_preserves_python_cython_semantics_for_terminal_states(
    monkeypatch,
) -> None:
    from d810.mba.ac_matching import AcMatchStopReason
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
    from d810.mba.certified_rule_compiler import (
        CompiledMbaRule,
        _enroll_admitted_rule,
        compile_add_rule_catalogue,
        compile_selected_rules_catalogue,
    )
    from d810.backends.mba.native_mba_term_view import NativeMbaTermView
    from d810.mba.dsl import Const, Var
    from d810.mba.rules._base import VerifiableRule
    from d810.mba.rules.xor import Xor_HackersDelightRule_3

    monkeypatch.setattr(VerifiableRule, "registry", dict(VerifiableRule.registry))

    add_rule = (
        compile_add_rule_catalogue()
        .receipt_for("Add_HackersDelightRule_2")
        .compiled_rule
    )
    assert add_rule is not None
    add_catalogue = CompiledPatternCatalogue.from_rules((add_rule,))
    xor_rule = (
        compile_selected_rules_catalogue({"xor": (Xor_HackersDelightRule_3,)})
        .receipt_for("xor", "Xor_HackersDelightRule_3")
        .compiled_rule
    )
    assert xor_rule is not None
    xor_catalogue = CompiledPatternCatalogue.from_rules((xor_rule,))
    value, captured = Var("value"), Const("captured")

    class CapturedCanonicalConstant(VerifiableRule):
        PATTERN = value + captured
        REPLACEMENT = captured

    provenance_rule = _enroll_admitted_rule(
        CompiledMbaRule(
            source_name=CapturedCanonicalConstant.__name__,
            aliases=(),
            rule_type=CapturedCanonicalConstant,
            proof_widths=(8, 16, 32, 64),
            guarded=False,
            family="add",
        )
    )
    provenance_catalogue = CompiledPatternCatalogue.from_rules((provenance_rule,))
    x = NativeMbaTermView(None, 32, leaf_key=("mop", "r", "x"))
    y = NativeMbaTermView(None, 32, leaf_key=("mop", "r", "y"))
    z = NativeMbaTermView(None, 32, leaf_key=("mop", "r", "z"))
    two = NativeMbaTermView(None, 32, constant_value=2)
    raw_candidate = NativeMbaTermView(
        "add",
        32,
        children=(
            NativeMbaTermView("xor", 32, children=(y, x)),
            NativeMbaTermView(
                "mul", 32, children=(two, NativeMbaTermView("and", 32, children=(y, x)))
            ),
        ),
    )
    fallback_candidate = NativeMbaTermView(
        "add",
        32,
        children=(
            NativeMbaTermView("add", 32, children=(x, y)),
            NativeMbaTermView("mul", 32, children=(
                NativeMbaTermView(None, 32, constant_value=-2),
                NativeMbaTermView("and", 32, children=(x, y)),
            )),
        ),
    )
    miss_candidate = NativeMbaTermView(
        "add", 32, children=(NativeMbaTermView("add", 32, children=(x, y)), z)
    )
    no_match_candidate = NativeMbaTermView("xor", 32, children=(x, y))
    unsupported_candidate = NativeMbaTermView(
        "unsupported_op", 32, children=(x, y)
    )

    def force_canonical_budget(patch):
        from d810.mba.canonical_pattern import CanonicalPatternMatchReport

        def exhausted(_self, _candidate, *, comparison_budget):
            return CanonicalPatternMatchReport(
                (), comparison_budget, 0, 0, AcMatchStopReason.COMPARISON_BUDGET
            )

        patch.setattr(
            CompiledPatternCatalogue, "match_canonical_root", exhausted
        )

    cases = (
        _ParityCase(
            "raw hit",
            add_catalogue,
            raw_candidate,
            64,
            NativeMatchSelection.RAW_POD,
            NativeMatchStopReason.MATCHED,
            1,
            True,
            False,
            False,
            False,
        ),
        _ParityCase(
            "canonical fallback hit",
            xor_catalogue,
            fallback_candidate,
            64,
            NativeMatchSelection.CANONICAL_FALLBACK,
            NativeMatchStopReason.MATCHED,
            1,
            True,
            False,
            False,
            True,
        ),
        _ParityCase(
            "canonical miss",
            add_catalogue,
            miss_candidate,
            64,
            NativeMatchSelection.NONE,
            NativeMatchStopReason.CANONICAL_MISS,
            0,
            False,
            False,
            False,
            True,
        ),
        _ParityCase(
            "raw budget",
            add_catalogue,
            raw_candidate,
            1,
            NativeMatchSelection.NONE,
            NativeMatchStopReason.RAW_BUDGET,
            0,
            False,
            True,
            False,
            False,
        ),
        _ParityCase(
            "unselected root family",
            add_catalogue,
            no_match_candidate,
            64,
            NativeMatchSelection.NONE,
            NativeMatchStopReason.CANONICAL_MISS,
            0,
            False,
            False,
            False,
            False,
        ),
        _ParityCase(
            "unsupported native operation",
            add_catalogue,
            unsupported_candidate,
            64,
            NativeMatchSelection.NONE,
            NativeMatchStopReason.RAW_UNSUPPORTED,
            0,
            False,
            False,
            False,
            False,
        ),
        _ParityCase(
            "canonical budget",
            add_catalogue,
            no_match_candidate,
            64,
            NativeMatchSelection.NONE,
            NativeMatchStopReason.CANONICAL_BUDGET,
            0,
            False,
            False,
            True,
            True,
            force_canonical_budget,
        ),
        _ParityCase(
            "provenance rejected",
            provenance_catalogue,
            NativeMbaTermView(
                "add",
                32,
                children=(
                    x,
                    NativeMbaTermView(
                        "neg", 32, children=(NativeMbaTermView(None, 32, constant_value=-5),)
                    ),
                ),
            ),
            64,
            NativeMatchSelection.NONE,
            NativeMatchStopReason.PROVENANCE_REJECTED,
            0,
            False,
            False,
            False,
            True,
        ),
    )

    for case in cases:
        with monkeypatch.context() as case_patch:
            if case.configure is not None:
                case.configure(case_patch)
            active, python = _active_and_python_results(
                case_patch,
                case.catalogue,
                case.candidate,
                budget=case.comparison_budget,
            )
        assert active.selection is case.expected_selection, case.name
        assert active.stop_reason is case.expected_stop_reason, case.name
        assert len(active.matches) == case.expected_match_count, case.name
        assert bool(active.matches) is case.expected_nonempty, case.name
        assert (
            active.comparison_budget_exceeded is case.expected_raw_budget_exceeded
        ), case.name
        assert (
            active.canonical_budget_exceeded is case.expected_canonical_budget_exceeded
        ), case.name
        fallback_work = (
            active.fallback_comparisons,
            active.fallback_commuted_branches,
            active.fallback_flattened_nodes,
        )
        if case.expected_fallback_work:
            assert any(fallback_work), case.name
        else:
            assert fallback_work == (0, 0, 0), case.name
        if CythonMode().is_enabled():
            assert active.matcher_backend == "cython", case.name
            assert python.matcher_backend == "python", case.name
        else:
            assert active.matcher_backend == python.matcher_backend == "python", case.name
        assert _match_semantics(active) == _match_semantics(python), case.name


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
    from d810.mba.certified_rule_compiler import compile_add_rule_catalogue
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

    active, python = _active_and_python_results(
        monkeypatch, catalogue, candidate, budget=64
    )
    assert _match_semantics(active) == _match_semantics(python)
    # The shared feasibility filter rejects this undersized chain before either
    # matcher spends comparison budget. The Cython adapter still owns the
    # empty-root result, while a separately sized candidate covers the native
    # matching call below.
    assert calls == 0


def test_cython_pod_catalogue_adapter_matches_portable_catalogue() -> None:
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
    from d810.mba.certified_rule_compiler import compile_add_rule_catalogue
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

    assert match_root_pod(catalogue, candidate, comparison_budget=64) == (
        catalogue._match_root_portable(candidate, comparison_budget=64)
    )


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_cython_catalogue_returns_clean_no_match_for_unselected_root_family(
    monkeypatch,
) -> None:
    """A missing root/width bucket is a no-match, never a Cython exception."""

    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
    from d810.mba.certified_rule_compiler import compile_add_rule_catalogue
    from d810.backends.mba.native_mba_term_view import NativeMbaTermView

    catalogue = CompiledPatternCatalogue.from_rules(
        compile_add_rule_catalogue().compiled_rules
    )
    candidate = NativeMbaTermView(
        "xor",
        32,
        children=(
            NativeMbaTermView(None, 32, leaf_key=("mop", "r", "x")),
            NativeMbaTermView(None, 32, leaf_key=("mop", "r", "y")),
        ),
    )

    native, python = _active_and_python_results(
        monkeypatch, catalogue, candidate, budget=64
    )

    assert _match_semantics(native) == _match_semantics(python)
    assert native.matches == ()
    assert native.comparison_budget_exceeded is False


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_cython_catalogue_shares_feasibility_before_tight_comparison_budget(
    monkeypatch,
) -> None:
    """An impossible first pattern cannot starve a later valid Cython match."""

    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
    from d810.mba.certified_rule_compiler import _compile_rule_families
    from d810.backends.mba.native_mba_term_view import NativeMbaTermView
    from d810.mba.dsl import Const, Var
    from d810.mba.rules._base import VerifiableRule

    # Local rule classes auto-register. Isolate that registry mutation so this
    # Cython regression cannot alter later production-rule inventory tests.
    monkeypatch.setattr(VerifiableRule, "registry", dict(VerifiableRule.registry))

    x, y, z = Var("x"), Var("y"), Var("z")
    zero = Const("zero", 0)

    class ImpossibleBeforeValidRule(VerifiableRule):
        PATTERN = x + (y & z)
        REPLACEMENT = PATTERN

    class ValidAfterImpossibleRule(VerifiableRule):
        PATTERN = x + zero
        REPLACEMENT = x

    rules = _compile_rule_families(
        {"add": (ImpossibleBeforeValidRule, ValidAfterImpossibleRule)}
    ).compiled_rules
    catalogue = CompiledPatternCatalogue.from_rules(rules)
    candidate = NativeMbaTermView(
        "add",
        32,
        children=(
            NativeMbaTermView(None, 32, leaf_key=("mop", "r", "x")),
            NativeMbaTermView(None, 32, constant_value=0),
        ),
    )

    native = catalogue.match_root(candidate, comparison_budget=5)

    assert native == catalogue._match_root_portable(candidate, comparison_budget=5)
    assert native.comparison_budget_exceeded is False
    assert tuple(match.rule.source_name for match in native.matches) == (
        "ValidAfterImpossibleRule",
    )


@pytest.mark.skipif(
    not CythonMode().is_enabled(), reason="requires the Cython POD matcher"
)
def test_cython_pod_catalogue_reuses_packed_terms_without_view_rematerialization(
    monkeypatch,
) -> None:
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
    from d810.mba.certified_rule_compiler import compile_add_rule_catalogue
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
    from d810.mba.certified_rule_compiler import compile_add_rule_catalogue
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

    assert catalogue.match_root(candidate, comparison_budget=64) == (
        catalogue._match_root_portable(candidate, comparison_budget=64)
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
    from d810.mba.certified_rule_compiler import compile_add_rule_catalogue
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
    from d810.mba.certified_rule_compiler import compile_add_rule_catalogue
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
    from d810.mba.certified_rule_compiler import compile_add_rule_catalogue
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
    monkeypatch.setattr(native_pod_matcher, "_match_pod_catalogue", None)

    result = catalogue.match_root(candidate, comparison_budget=64)

    assert result == catalogue._match_root_portable(candidate, comparison_budget=64)
    assert result.matcher_backend == "python"
