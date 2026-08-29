"""Direct native-term matching for the certified e-graph MBA catalogue."""

from __future__ import annotations

import pytest

from d810.mba.certified_rule_compiler import (
    CompiledMbaRule,
    _enroll_admitted_rule,
)
from d810.backends.mba.native_mba_term_view import NativeMbaTermView
from d810.ir.expr.dsl import SymbolicExpression
from d810.mba.dsl import Const, Var
from d810.mba.rules._base import VerifiableRule
from d810.mba.semantic_canonicalization import canonicalize_mba_term
from d810.mba.typed_term import canonicalize_ac_term
from d810.mba.rules.catalogue import MBA_RULE_FAMILIES
from tests.unit.mba._compiled_rule_fixture import admitted_rule


def _leaf(name: str) -> NativeMbaTermView:
    return NativeMbaTermView(None, 32, leaf_key=("mop", "r", name))


def _constant(value: int) -> NativeMbaTermView:
    return NativeMbaTermView(None, 32, constant_value=value)


def _node(name: str, *children: NativeMbaTermView) -> NativeMbaTermView:
    return NativeMbaTermView(name, 32, children=children)


def _rule(name: str, family: str = "add"):
    rule_type = next(
        rule for rule in MBA_RULE_FAMILIES[family] if rule.__name__ == name
    )
    return admitted_rule(rule_type, family=family)


def _xor_rule(name: str):
    return _rule(name, "xor")


def _admitted_probe_rule(name: str, pattern: SymbolicExpression):
    """Build a narrowly scoped admitted rule for catalogue boundary tests."""

    rule_type = type(
        name,
        (VerifiableRule,),
        {
            "pattern": pattern,
            "replacement": Var("x"),
            "CONSTRAINTS": (),
        },
    )
    return _enroll_admitted_rule(CompiledMbaRule(name, (), rule_type, (32,), False))


def _admitted_probe_rule_with_replacement(
    name: str, pattern: SymbolicExpression, replacement: SymbolicExpression
):
    rule_type = type(
        name,
        (VerifiableRule,),
        {
            "pattern": pattern,
            "replacement": replacement,
            "CONSTRAINTS": (),
        },
    )
    return _enroll_admitted_rule(CompiledMbaRule(name, (), rule_type, (32,), False))


def test_compiled_catalogue_matches_ac_operands_without_variant_rules() -> None:
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    rule = _rule("Add_HackersDelightRule_2")
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    x, y = _leaf("x"), _leaf("y")
    candidate = _node(
        "add",
        _node("mul", _node("and", y, x), _constant(2)),
        _node("xor", y, x),
    )

    result = catalogue.match_root(candidate)
    matches = result.matches

    assert len(matches) == 1
    assert result.comparison_budget_exceeded is False
    assert matches[0].rule is rule
    assert matches[0].bindings.materialize_replacement(rule) == canonicalize_ac_term(
        _node("add", x, y).to_typed_term()
    )


def test_match_root_raw_hit_skips_canonical_work(monkeypatch) -> None:
    from d810.backends.mba import compiled_pattern_catalogue as module
    from d810.backends.mba.compiled_pattern_catalogue import (
        CompiledPatternCatalogue,
        NativeMatchSelection,
        NativeMatchStopReason,
    )

    rule = _rule("Add_HackersDelightRule_2")
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    x, y = _leaf("x"), _leaf("y")
    candidate = _node(
        "add",
        _node("xor", y, x),
        _node("mul", _constant(2), _node("and", y, x)),
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("raw hit must not canonicalize")

    monkeypatch.setattr(module, "canonicalize_mba_term", forbidden)
    result = catalogue.match_root(candidate)

    assert result.matches
    assert result.selection is NativeMatchSelection.RAW_POD
    assert result.stop_reason is NativeMatchStopReason.MATCHED


def test_match_root_clean_raw_miss_uses_one_canonical_fallback(monkeypatch) -> None:
    from d810.backends.mba.compiled_pattern_catalogue import (
        CompiledPatternCatalogue,
        NativeMatchSelection,
        NativeMatchStopReason,
    )

    rule = _xor_rule("Xor_HackersDelightRule_3")
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    x, y = _leaf("x"), _leaf("y")
    candidate = _node(
        "add",
        _node("add", x, y),
        _node("mul", _constant(-2), _node("and", x, y)),
    )
    calls = 0
    original = CompiledPatternCatalogue.match_canonical_root

    def observed(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(CompiledPatternCatalogue, "match_canonical_root", observed)
    result = catalogue.match_root(candidate)

    assert calls == 1
    assert result.matches
    assert result.selection is NativeMatchSelection.CANONICAL_FALLBACK
    assert result.stop_reason is NativeMatchStopReason.MATCHED
    assert result.matches[0].bindings.native["x_0"] is x
    assert result.matches[0].bindings.native["x_1"] is y


def test_match_root_raw_budget_abstains_without_canonical_fallback(monkeypatch) -> None:
    from d810.backends.mba import compiled_pattern_catalogue as module
    from d810.backends.mba.compiled_pattern_catalogue import (
        CompiledPatternCatalogue,
        NativeMatchStopReason,
    )

    rule = _rule("Add_HackersDelightRule_2")
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    x, y = _leaf("x"), _leaf("y")
    candidate = _node("add", _node("xor", x, y), _node("mul", _constant(2), _node("and", x, y)))
    calls = 0

    def forbidden(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("raw budget exhaustion must not canonicalize")

    monkeypatch.setattr(module, "canonicalize_mba_term", forbidden)
    result = catalogue.match_root(candidate, comparison_budget=1)

    assert calls == 0
    assert result.matches == ()
    assert result.comparison_budget_exceeded is True
    assert result.stop_reason is NativeMatchStopReason.RAW_BUDGET


def test_match_root_uses_canonical_bucket_when_raw_root_bucket_is_empty() -> None:
    from d810.backends.mba.compiled_pattern_catalogue import (
        CompiledPatternCatalogue,
        NativeMatchSelection,
    )

    left, right = Var("x"), Var("y")
    rule = _admitted_probe_rule("CanonicalSubProbe", left + -right)
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    candidate = _node("sub", _leaf("x"), _leaf("y"))

    assert catalogue.root_width_buckets.get(("sub", 32), ()) == ()
    result = catalogue.match_root(candidate)

    assert result.matches
    assert result.selection is NativeMatchSelection.CANONICAL_FALLBACK


def test_match_root_rejects_flattened_ac_wildcard_capture() -> None:
    from d810.backends.mba.compiled_pattern_catalogue import (
        CompiledPatternCatalogue,
        NativeMatchSelection,
        NativeMatchStopReason,
    )

    left, right = Var("left"), Var("right")
    rule = _admitted_probe_rule("TwoOperandAddProbe", left + right)
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    candidate = _node("add", _node("add", _leaf("x"), _leaf("y")), _leaf("z"))

    result = catalogue.match_root(candidate)

    assert result.matches == ()
    assert result.selection is NativeMatchSelection.NONE
    assert result.stop_reason is NativeMatchStopReason.CANONICAL_MISS


def test_match_root_canonical_budget_is_a_bounded_noop(monkeypatch) -> None:
    from d810.backends.mba.compiled_pattern_catalogue import (
        CompiledPatternCatalogue,
        NativeMatchStopReason,
    )
    from d810.mba.ac_matching import AcMatchStopReason
    from d810.mba.canonical_pattern import CanonicalPatternMatchReport

    rule = _rule("Add_HackersDelightRule_2")
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    x, y = _leaf("x"), _leaf("y")
    candidate = _node("sub", x, y)
    budgets = []

    def exhausted(_self, _candidate, *, comparison_budget):
        budgets.append(comparison_budget)
        return CanonicalPatternMatchReport(
            (), comparison_budget, 0, 0, AcMatchStopReason.COMPARISON_BUDGET
        )

    monkeypatch.setattr(CompiledPatternCatalogue, "match_canonical_root", exhausted)
    result = catalogue.match_root(candidate)

    assert budgets == [64]
    assert result.matches == ()
    assert result.comparison_budget_exceeded is False
    assert result.stop_reason is NativeMatchStopReason.CANONICAL_BUDGET


def test_match_root_keeps_raw_resources_separate_from_fallback_resources(monkeypatch) -> None:
    from d810.backends.mba import native_pod_matcher
    from d810.backends.mba.compiled_pattern_catalogue import (
        CompiledPatternCatalogue,
        NativeMatchSelection,
        NativeMatchStopReason,
        NativePatternMatchResult,
    )

    rule = _xor_rule("Xor_HackersDelightRule_3")
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    x, y = _leaf("x"), _leaf("y")
    candidate = _node(
        "add",
        _node("add", x, y),
        _node("mul", _constant(-2), _node("and", x, y)),
    )
    raw = NativePatternMatchResult(
        (), 5, 2, candidate_term=None, stop_reason=NativeMatchStopReason.CLEAN_MISS
    )

    monkeypatch.setattr(native_pod_matcher, "match_root_pod", lambda *_args, **_kwargs: raw)
    original = CompiledPatternCatalogue.match_canonical_root

    def fallback(_self, _candidate, *, comparison_budget):
        report = original(_self, _candidate, comparison_budget=comparison_budget)
        return type(report)(
            report.matches,
            7,
            3,
            4,
            report.stop_reason,
            report.compatibility_bindings,
        )

    monkeypatch.setattr(CompiledPatternCatalogue, "match_canonical_root", fallback)
    result = catalogue.match_root(candidate)

    assert result.selection is NativeMatchSelection.CANONICAL_FALLBACK
    assert result.stop_reason is NativeMatchStopReason.MATCHED
    assert result.comparisons == 5
    assert result.lazy_swaps == 2
    assert result.fallback_comparisons == 7
    assert result.fallback_commuted_branches == 3
    assert result.fallback_flattened_nodes == 4
    assert result.comparison_budget_exceeded is False
    assert result.candidate_term == candidate.to_typed_term()


def test_match_root_groups_canonical_alternatives_before_path_resolution(monkeypatch) -> None:
    from d810.backends.mba import compiled_pattern_catalogue as module
    from d810.backends.mba.compiled_pattern_catalogue import (
        CompiledPatternCatalogue,
        NativeMatchSelection,
    )
    from d810.mba.canonical_pattern import (
        CanonicalFixedBindings,
        CanonicalPatternMatch,
        CanonicalPatternMatchReport,
    )
    from d810.mba.ac_matching import AcMatchStopReason

    rule = _xor_rule("Xor_HackersDelightRule_3")
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    x, y = _leaf("x"), _leaf("y")
    candidate = _node("add", x, _node("neg", y))
    compiled = catalogue.rules[0].canonical_by_width[32]
    tx, ty = x.to_typed_term(), y.to_typed_term()
    alternatives = tuple(
        CanonicalPatternMatch(
            compiled,
            CanonicalFixedBindings(
                {"x_0": first, "x_1": second},
                {"x_0": first_path, "x_1": second_path},
                32,
            ),
        )
        for first, second, first_path, second_path in (
            (tx, ty, (1,), (0,)),
            (ty, tx, (0,), (1,)),
        )
    )
    calls = []
    original_resolver = module.resolve_canonical_match_paths

    def observed(matches, **kwargs):
        calls.append(tuple(matches))
        return original_resolver(matches, **kwargs)

    monkeypatch.setattr(module, "resolve_canonical_match_paths", observed)
    monkeypatch.setattr(
        CompiledPatternCatalogue,
        "match_canonical_root",
        lambda *_args, **_kwargs: CanonicalPatternMatchReport(
            alternatives, 11, 2, 3, AcMatchStopReason.MATCHED
        ),
    )
    result = catalogue.match_root(candidate)

    assert result.selection is NativeMatchSelection.CANONICAL_FALLBACK
    assert len(calls) == 1
    assert len(calls[0]) == 2
    assert result.matches[0].bindings.native["x_0"] is x
    assert result.matches[0].bindings.native["x_1"] is y


def test_match_root_merges_compatibility_constant_without_native_path(monkeypatch) -> None:
    from d810.backends.mba.compiled_pattern_catalogue import (
        CompiledPatternCatalogue,
        NativeMatchSelection,
    )

    rule = _xor_rule("Xor_HackersDelightRule_3")
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    x, y = _leaf("x"), _leaf("y")
    candidate = _node(
        "add",
        _node("add", x, y),
        _node("mul", _constant(-2), _node("and", x, y)),
    )
    result = catalogue.match_root(candidate)

    assert result.selection is NativeMatchSelection.CANONICAL_FALLBACK
    assert result.matches
    assert result.matches[0].bindings.terms["2"].value == 2
    assert "2" not in result.matches[0].bindings.native


def test_match_root_rejects_canonical_pattern_constant_without_raw_provenance() -> None:
    from d810.backends.mba.compiled_pattern_catalogue import (
        CompiledPatternCatalogue,
        NativeMatchStopReason,
    )

    captured = Const("captured")
    value = Var("value")
    rule = _admitted_probe_rule_with_replacement(
        "CapturedCanonicalConstant",
        value + captured,
        captured,
    )
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    candidate = _node("add", _leaf("x"), _node("neg", _constant(-5)))

    result = catalogue.match_root(candidate)

    assert result.matches == ()
    assert result.stop_reason is NativeMatchStopReason.PROVENANCE_REJECTED


def test_match_root_allows_constraint_derived_replacement_constant_without_path() -> None:
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    rule = _rule("Add_SpecialConstantRule_3")
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    x = _leaf("x")
    candidate = _node(
        "sub",
        _node("xor", x, _constant(-2)),
        _node("neg", _node("mul", _constant(2), _node("or", x, _constant(1)))),
    )

    result = catalogue.match_root(candidate)

    assert result.matches
    assert result.fallback_comparisons == 13
    assert result.matches[0].bindings.terms["val_res"].value == 0
    assert "val_res" not in result.matches[0].bindings.native


def test_match_root_scopes_compatibility_bindings_to_each_template() -> None:
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    value = Var("value")
    first_constant = Const("first", 2)
    second_constant = Const("second", 2)
    first = _admitted_probe_rule_with_replacement(
        "FirstCompatibilityRule",
        value + first_constant,
        first_constant,
    )
    second = _admitted_probe_rule_with_replacement(
        "SecondCompatibilityRule",
        value + second_constant,
        second_constant,
    )
    catalogue = CompiledPatternCatalogue.from_rules((first, second))
    candidate = _node("add", _leaf("x"), _node("neg", _constant(-2)))

    result = catalogue.match_root(candidate)

    assert len(result.matches) == 2
    assert tuple(match.rule for match in result.matches) == (first, second)
    assert set(result.matches[0].bindings.terms) == {"value", "first"}
    assert set(result.matches[1].bindings.terms) == {"value", "second"}


def test_match_root_propagates_raw_runtime_errors(monkeypatch) -> None:
    from d810.backends.mba import native_pod_matcher
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    rule = _rule("Add_HackersDelightRule_2")
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))

    def fail(*_args, **_kwargs):
        raise RuntimeError("raw matcher failed")

    monkeypatch.setattr(native_pod_matcher, "match_root_pod", fail)
    with pytest.raises(RuntimeError, match="raw matcher failed"):
        catalogue.match_root(_node("sub", _leaf("x"), _leaf("y")))


def test_match_root_propagates_canonical_runtime_errors(monkeypatch) -> None:
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    rule = _xor_rule("Xor_HackersDelightRule_3")
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))

    def fail(*_args, **_kwargs):
        raise RuntimeError("canonical matcher failed")

    monkeypatch.setattr(CompiledPatternCatalogue, "match_canonical_root", fail)
    with pytest.raises(RuntimeError, match="canonical matcher failed"):
        catalogue.match_root(_node("add", _leaf("x"), _node("neg", _leaf("y"))))


@pytest.mark.parametrize("error", (TypeError, ValueError))
def test_match_root_propagates_canonical_type_and_value_errors(monkeypatch, error) -> None:
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    rule = _xor_rule("Xor_HackersDelightRule_3")
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))

    def fail(*_args, **_kwargs):
        raise error("canonical matcher failed")

    monkeypatch.setattr(CompiledPatternCatalogue, "match_canonical_root", fail)
    with pytest.raises(error, match="canonical matcher failed"):
        catalogue.match_root(_node("add", _leaf("x"), _node("neg", _leaf("y"))))


def test_compiled_catalogue_enforces_equal_constant_guard_and_materializes_terms() -> (
    None
):
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    rule = _rule("Add_SpecialConstantRule_1")
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    x = _leaf("x")
    accepted = _node(
        "add",
        _node("xor", x, _constant(0x55)),
        _node("mul", _constant(2), _node("and", x, _constant(0x55))),
    )
    rejected = _node(
        "add",
        _node("xor", x, _constant(0x55)),
        _node("mul", _constant(2), _node("and", x, _constant(0xAA))),
    )

    accepted_result = catalogue.match_root(accepted)
    accepted_matches = accepted_result.matches

    assert len(accepted_matches) == 1
    assert accepted_matches[0].bindings.materialize_replacement(
        rule
    ) == canonicalize_ac_term(_node("add", x, _constant(0x55)).to_typed_term())
    assert catalogue.match_root(rejected).matches == ()


def test_compiled_catalogue_preserves_certified_declaration_order() -> None:
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    first = _rule("Add_HackersDelightRule_2")
    second = _rule("Add_HackersDelightRule_3")
    assert first is not None and second is not None

    catalogue = CompiledPatternCatalogue.from_rules((second, first))

    assert tuple(item.rule for item in catalogue.rules) == (second, first)


def test_compiled_catalogue_rejects_unadmitted_rule_objects() -> None:
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    with pytest.raises(ValueError, match="admitted"):
        CompiledPatternCatalogue.from_rules((object(),))


def test_compiled_catalogue_drops_malformed_rules_but_keeps_unsupported_shift_legacy():
    """Malformed canonical trees cannot enter any executable catalogue bucket."""

    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    malformed = _admitted_probe_rule(
        "MalformedCatalogueProbe",
        SymbolicExpression(operation="add", left=Var("x"), right=None),
    )
    unsupported_shift = _admitted_probe_rule(
        "UnsupportedShiftCatalogueProbe", Var("x") << Const("shift", 1)
    )

    catalogue = CompiledPatternCatalogue.from_rules((malformed, unsupported_shift))

    assert tuple(item.rule for item in catalogue.rules) == (unsupported_shift,)
    assert all(
        all(item.rule is not malformed for item in bucket)
        for bucket in catalogue.root_width_buckets.values()
    )
    assert all(
        all(item.rule is not malformed for item in bucket)
        for bucket in catalogue.canonical_root_width_buckets.values()
    )
    assert ("shl", 32) in catalogue.root_width_buckets
    assert catalogue.root_width_buckets[("shl", 32)][0].rule is unsupported_shift


def test_compiled_catalogue_uses_root_width_buckets_and_refuses_comparison_overrun() -> (
    None
):
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    first = _rule("Add_HackersDelightRule_2")
    second = _rule("Add_HackersDelightRule_3")
    assert first is not None and second is not None
    catalogue = CompiledPatternCatalogue.from_rules((first, second))
    x, y = _leaf("x"), _leaf("y")
    candidate = _node(
        "add",
        _node("xor", x, y),
        _node("mul", _constant(2), _node("and", x, y)),
    )

    assert ("add", 32) in catalogue.root_width_buckets
    refused = catalogue.match_root(candidate, comparison_budget=1)

    assert refused.matches == ()
    assert refused.comparison_budget_exceeded is True
    assert refused.comparisons == 2


def test_compiled_catalogue_freezes_canonical_templates_from_admitted_rules():
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    rule = _xor_rule("Xor_HackersDelightRule_3")
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    compiled = catalogue.rules[0].canonical_by_width[32]

    assert compiled.pattern_term.operation == "sub"
    assert catalogue.canonical_root_width_buckets[("sub", 32)] == (catalogue.rules[0],)


def test_canonical_catalogue_match_keeps_fixed_portable_bindings_and_budget():
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    rule = _xor_rule("Xor_HackersDelightRule_3")
    assert rule is not None
    x, y = _leaf("x"), _leaf("y")
    candidate = _node(
        "add",
        _node("add", x, y),
        _node("mul", _constant(-2), _node("and", x, y)),
    )
    typed = canonicalize_mba_term(candidate.to_typed_term()).canonical_term
    catalogue = CompiledPatternCatalogue.from_rules((rule,))

    matched = catalogue.match_canonical_root(typed, comparison_budget=64)
    assert matched.stop_reason.value == "matched"
    assert matched.matches[0].bindings.terms["x_0"].leaf_key == x.leaf_key
    assert matched.matches[0].bindings.terms["x_1"].leaf_key == y.leaf_key

    with pytest.raises(ValueError, match="positive integer"):
        catalogue.match_canonical_root(typed, comparison_budget=0)


def test_canonical_catalogue_preserves_earlier_match_at_declaration_budget_boundary():
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
    from d810.mba.ac_matching import AcMatchStopReason

    rule = _xor_rule("Xor_HackersDelightRule_3")
    assert rule is not None
    x, y = _leaf("x"), _leaf("y")
    candidate = _node(
        "add",
        _node("add", x, y),
        _node("mul", _constant(-2), _node("and", x, y)),
    )
    typed = canonicalize_mba_term(candidate.to_typed_term()).canonical_term
    single = CompiledPatternCatalogue.from_rules((rule,))
    first_report = single.match_canonical_root(typed, comparison_budget=64)
    assert first_report.matches

    ordered = CompiledPatternCatalogue.from_rules((rule, rule))
    boundary = ordered.match_canonical_root(
        typed, comparison_budget=first_report.comparisons
    )

    assert boundary.matches
    assert all(
        match.compiled_pattern.declaration_index == 0 for match in boundary.matches
    )
    assert boundary.comparisons == first_report.comparisons
    assert boundary.stop_reason is AcMatchStopReason.COMPARISON_BUDGET


def test_canonical_catalogue_keeps_constraint_derived_bindings_without_paths():
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    rule = _rule("Add_SpecialConstantRule_3")
    assert rule is not None
    x = _leaf("x")
    candidate = _node(
        "add",
        _node("xor", x, _constant(-2)),
        _node(
            "mul",
            _constant(2),
            _node("or", x, _constant(1)),
        ),
    )
    typed = canonicalize_mba_term(candidate.to_typed_term()).canonical_term

    matched = CompiledPatternCatalogue.from_rules((rule,)).match_canonical_root(
        typed, comparison_budget=64
    )

    assert matched.matches
    binding = matched.matches[0].bindings
    assert binding.terms["val_res"].value == 0
    assert "val_res" not in binding.candidate_paths


def test_canonical_catalogue_uses_frozen_constraints_at_match_time(monkeypatch):
    import d810.backends.mba.compiled_pattern_catalogue as catalogue_module
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    rule = _rule("Add_SpecialConstantRule_3")
    assert rule is not None
    x = _leaf("x")
    candidate = _node(
        "add",
        _node("xor", x, _constant(-2)),
        _node("mul", _constant(2), _node("or", x, _constant(1))),
    )
    typed = canonicalize_mba_term(candidate.to_typed_term()).canonical_term
    catalogue = CompiledPatternCatalogue.from_rules((rule,))

    calls = 0

    def forbidden_symbolic_constraint_walk(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("canonical callback walked symbolic constraints")

    monkeypatch.setattr(
        catalogue_module,
        "_constraints_match_term",
        forbidden_symbolic_constraint_walk,
    )

    report = catalogue.match_canonical_root(typed, comparison_budget=64)

    assert report.matches
    assert calls == 0
