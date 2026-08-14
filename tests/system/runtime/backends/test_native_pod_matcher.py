"""Runtime contract for the active native MBA POD matcher backend."""

from __future__ import annotations

from d810.backends.mba.native_pod_matcher import matcher_backend
from d810.core.cymode import CythonMode


def test_active_cython_pod_matcher_is_selected_when_cython_is_enabled() -> None:
    assert CythonMode().is_enabled()
    assert matcher_backend() == "cython"


def test_cython_pod_matcher_returns_ac_bindings_and_honors_its_budget() -> None:
    from d810.speedups.mba.c_native_pod_matcher import match_pod_pattern

    pattern_rows = (
        (2, 0, 0, 0, 0, -1, -1),
        (2, 0, 1, 0, 0, -1, -1),
        (3, 1, -1, 0, 0, 0, 1),
    )
    candidate_rows = (
        (2, 0, 32, -1, -1, 0, 0, 0),
        (2, 0, 32, -1, -1, 0, 1, 1),
        (3, 1, 32, 0, 1, 0, -1, 2),
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


def test_cython_pod_catalogue_adapter_matches_portable_catalogue() -> None:
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
    from d810.backends.mba.egglog_add_rule_compiler import compile_add_rule_catalogue
    from d810.backends.mba.native_mba_term_view import NativeMbaTermView
    from d810.backends.mba.native_pod_matcher import match_root_pod

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
            NativeMbaTermView("xor", 32, children=(y, x)),
            NativeMbaTermView(
                "mul",
                32,
                children=(two, NativeMbaTermView("and", 32, children=(y, x))),
            ),
        ),
    )

    assert match_root_pod(catalogue, candidate, comparison_budget=64) == (
        catalogue.match_root(candidate, comparison_budget=64)
    )
