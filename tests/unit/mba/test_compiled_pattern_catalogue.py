"""Direct native-term matching for the certified Egglog MBA catalogue."""

from __future__ import annotations

import pytest

from d810.backends.mba.egglog_add_rule_compiler import compile_add_rule_catalogue
from d810.backends.mba.native_mba_term_view import NativeMbaTermView
from d810.mba.typed_term import canonicalize_ac_term


def _leaf(name: str) -> NativeMbaTermView:
    return NativeMbaTermView(None, 32, leaf_key=("mop", "r", name))


def _constant(value: int) -> NativeMbaTermView:
    return NativeMbaTermView(None, 32, constant_value=value)


def _node(name: str, *children: NativeMbaTermView) -> NativeMbaTermView:
    return NativeMbaTermView(name, 32, children=children)


def _rule(name: str):
    return compile_add_rule_catalogue().receipt_for(name).compiled_rule


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


def test_fixed_binding_extraction_does_not_rematch_or_construct_an_ast(
    monkeypatch,
) -> None:
    pytest.importorskip("egglog")
    from d810.backends.mba.egglog_saturation import (
        EgglogExtractionBudget,
        extract_bounded_term,
    )
    import d810.backends.mba.egglog_add_rule_compiler as compiler_module
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    rule = _rule("Add_HackersDelightRule_2")
    assert rule is not None
    x, y = _leaf("x"), _leaf("y")
    candidate = _node(
        "add",
        _node("xor", x, y),
        _node("mul", _constant(2), _node("and", x, y)),
    )
    match = (
        CompiledPatternCatalogue.from_rules((rule,)).match_root(candidate).matches[0]
    )
    monkeypatch.setattr(
        compiler_module,
        "apply_compiled_rule_to_term",
        lambda *_args: pytest.fail("fixed degree-one binding was rematched"),
    )

    result = extract_bounded_term(
        canonicalize_ac_term(candidate.to_typed_term()),
        (rule,),
        EgglogExtractionBudget(time_budget_ms=1000),
        destination_size=4,
        initial_replacements={
            id(match.rule): match.bindings.materialize_replacement(match.rule)
        },
    )

    assert result.replacement_ast is None
    assert result.replacement_term == canonicalize_ac_term(
        _node("add", x, y).to_typed_term()
    )
    assert result.receipt.degree == 1


def test_compiled_catalogue_rejects_unadmitted_rule_objects() -> None:
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    with pytest.raises(ValueError, match="admitted"):
        CompiledPatternCatalogue.from_rules((object(),))


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
