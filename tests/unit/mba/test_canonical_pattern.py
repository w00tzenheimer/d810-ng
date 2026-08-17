"""Portable canonical rule-template compilation and matching contracts."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from d810.backends.mba.egglog_add_rule_compiler import (
    compile_mba_rule_catalogue,
)
from d810.mba.dsl import Const, Var, Zext
from d810.mba.typed_term import TypedBvTerm, term_fingerprint


@dataclass(frozen=True)
class _TestRule:
    pattern: object
    replacement: object
    source_name: str = "TestRule"
    aliases: tuple[str, ...] = ()
    family: str = "add"
    proof_widths: tuple[int, ...] = (8, 16, 32, 64)
    guarded: bool = False
    constraints: tuple[object, ...] = ()
    DYNAMIC_CONSTS: dict[str, object] = None  # type: ignore[assignment]
    CONTEXT_VARS: dict[str, object] = None  # type: ignore[assignment]
    UPDATE_DESTINATION: str | None = None
    BIT_WIDTH: int = 32

    def __post_init__(self) -> None:
        if self.DYNAMIC_CONSTS is None:
            object.__setattr__(self, "DYNAMIC_CONSTS", {})
        if self.CONTEXT_VARS is None:
            object.__setattr__(self, "CONTEXT_VARS", {})


class _HookRule(_TestRule):
    def check_candidate(self, candidate: object) -> bool:
        return bool(candidate)


class _ChangedHookRule(_TestRule):
    def check_candidate(self, candidate: object) -> bool:
        return not bool(candidate)


class _PropertyRule:
    source_name = "PropertyRule"
    aliases = ()
    family = "add"
    proof_widths = (32,)
    guarded = False
    _PATTERN = Var("x") + Var("y")
    replacement = Var("x") ^ Var("y")

    @property
    def pattern(self):
        marker = 1
        assert marker == 1
        return self._PATTERN


def _leaf(name: str, width: int) -> TypedBvTerm:
    return TypedBvTerm(None, width, leaf_key=("candidate", name))


def _constant(value: int, width: int) -> TypedBvTerm:
    return TypedBvTerm(None, width, value=value)


def _node(
    operation: str, width: int, left: TypedBvTerm, right: TypedBvTerm | None = None
) -> TypedBvTerm:
    children = (left,) if right is None else (left, right)
    return TypedBvTerm(operation, width, children=children)


def _xor_subtraction_candidate(width: int) -> TypedBvTerm:
    x, y = _leaf("x", width), _leaf("y", width)
    return _node(
        "add",
        width,
        _node("add", width, x, y),
        _node(
            "mul",
            width,
            _constant(-2, width),
            _node("and", width, x, y),
        ),
    )


def _fake_pattern(pattern: object, replacement: object | None = None) -> _TestRule:
    return _TestRule(pattern, pattern if replacement is None else replacement)


def test_negative_coefficient_rule_and_sub_candidate_share_canonical_bucket():
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
    from d810.mba.canonical_pattern import compile_canonical_pattern
    from d810.mba.semantic_canonicalization import canonicalize_mba_term

    rule = compile_mba_rule_catalogue().receipt_for(
        "xor", "Xor_HackersDelightRule_3"
    ).compiled_rule
    assert rule is not None
    compiled = compile_canonical_pattern(rule, width=32, declaration_index=0)
    candidate = canonicalize_mba_term(_xor_subtraction_candidate(32)).canonical_term

    assert compiled.pattern_term.operation == "sub"
    assert (compiled.pattern_term.operation, 32) == (
        candidate.operation,
        candidate.width,
    )

    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    assert ("sub", 32) in catalogue.canonical_root_width_buckets
    report = catalogue.match_canonical_root(candidate, comparison_budget=64)
    assert report.matches
    binding_terms = report.matches[0].bindings.terms
    assert set(binding_terms) == {"x_0", "x_1"}


def test_pattern_var_and_pattern_const_have_distinct_terminal_contracts():
    from d810.mba.canonical_pattern import (
        compile_canonical_pattern,
        match_canonical_term_pattern,
    )

    var_pattern = compile_canonical_pattern(
        _fake_pattern(Var("x")), width=32, declaration_index=0
    )
    const_pattern = compile_canonical_pattern(
        _fake_pattern(Const("c")), width=32, declaration_index=0
    )

    assert match_canonical_term_pattern(
        var_pattern, _leaf("r0", 32), comparison_budget=4
    ).matches
    assert not match_canonical_term_pattern(
        const_pattern, _leaf("r0", 32), comparison_budget=4
    ).matches
    assert match_canonical_term_pattern(
        const_pattern, _constant(7, 32), comparison_budget=4
    ).matches


def test_repeated_variable_requires_exact_candidate_term_and_alias_shape():
    from d810.mba.canonical_pattern import (
        compile_canonical_pattern,
        match_canonical_term_pattern,
    )

    x = Var("x")
    pattern = compile_canonical_pattern(
        _fake_pattern(x + x), width=32, declaration_index=0
    )
    same = _node("add", 32, _leaf("x", 32), _leaf("x", 32))
    different = _node("add", 32, _leaf("x", 32), _leaf("y", 32))

    assert match_canonical_term_pattern(pattern, same, comparison_budget=8).matches
    assert not match_canonical_term_pattern(
        pattern, different, comparison_budget=8
    ).matches


@pytest.mark.parametrize("width", [8, 16, 32, 64])
def test_pattern_literals_are_masked_at_every_supported_width(width: int):
    from d810.mba.canonical_pattern import lower_symbolic_template

    lowered, terminal_kinds = lower_symbolic_template(Const("c", -1), width=width)
    assert lowered.value == (1 << width) - 1
    assert terminal_kinds == {}


def test_unsupported_dsl_pattern_fails_closed_and_is_not_canonical_eligible():
    from d810.mba.canonical_pattern import (
        CanonicalPatternUnsupported,
        compile_canonical_pattern,
    )

    with pytest.raises(CanonicalPatternUnsupported):
        compile_canonical_pattern(
            _fake_pattern(Zext(Var("x"), 64)), width=32, declaration_index=0
        )


def test_declaration_order_survives_canonical_alias_collapse():
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    first = compile_mba_rule_catalogue().receipt_for(
        "xor", "Xor_HackersDelightRule_3"
    ).compiled_rule
    second = compile_mba_rule_catalogue().receipt_for(
        "xor", "Xor_HackersDelightRule_3"
    ).compiled_rule
    assert first is not None and second is not None
    catalogue = CompiledPatternCatalogue.from_rules((first, second))
    canonical_entries = catalogue.canonical_root_width_buckets[("sub", 32)]
    assert tuple(entry.catalogue_index for entry in canonical_entries) == (0, 1)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda rule: _fake_pattern(rule.pattern, rule.pattern ^ Var("z")),
        lambda rule: _fake_pattern(rule.pattern + Var("z"), rule.replacement),
        lambda rule: _TestRule(
            rule.pattern,
            rule.replacement,
            constraints=(Var("x") == Var("y"),),
        ),
        lambda rule: _TestRule(
            rule.pattern,
            rule.replacement,
            DYNAMIC_CONSTS={"c": 1},
        ),
        lambda rule: _TestRule(
            rule.pattern,
            rule.replacement,
            CONTEXT_VARS={"dst": "r0"},
        ),
        lambda rule: _TestRule(
            rule.pattern,
            rule.replacement,
            UPDATE_DESTINATION="dst",
        ),
        lambda rule: _TestRule(
            rule.pattern,
            rule.replacement,
            proof_widths=(32,),
        ),
        lambda rule: _ChangedHookRule(rule.pattern, rule.replacement),
    ],
)
def test_semantic_fingerprint_changes_for_every_rule_semantic_input(mutator):
    from d810.mba.canonical_pattern import (
        canonical_rule_fingerprint,
        compile_canonical_pattern,
    )

    x, y = Var("x"), Var("y")
    base = _TestRule(x + y, x ^ y)
    changed = mutator(base)
    base_pattern = compile_canonical_pattern(base, width=32, declaration_index=0)
    changed_pattern = compile_canonical_pattern(
        changed, width=32, declaration_index=0
    )
    assert canonical_rule_fingerprint(base_pattern) != canonical_rule_fingerprint(
        changed_pattern
    )


def test_semantic_fingerprint_changes_when_canonicalizer_version_changes(monkeypatch):
    import d810.mba.canonical_pattern as canonical_pattern

    x, y = Var("x"), Var("y")
    base = _TestRule(x + y, x ^ y)
    baseline = canonical_pattern.canonical_rule_fingerprint(base, width=32)
    monkeypatch.setattr(canonical_pattern, "CANONICALIZER_SCHEMA_VERSION", 99)
    changed = canonical_pattern.canonical_rule_fingerprint(base, width=32)
    assert baseline != changed


def test_semantic_fingerprint_changes_when_property_getter_changes():
    from d810.mba.canonical_pattern import canonical_rule_fingerprint

    rule = _PropertyRule()
    baseline = canonical_rule_fingerprint(rule, width=32)
    original_property = type(rule).pattern

    @property
    def changed_pattern(self):
        marker = 2
        assert marker == 2
        return self._PATTERN

    type(rule).pattern = changed_pattern
    try:
        changed = canonical_rule_fingerprint(rule, width=32)
    finally:
        type(rule).pattern = original_property

    assert baseline != changed


def test_canonical_template_fingerprint_is_json_safe_and_stable():
    from d810.mba.canonical_pattern import compile_canonical_pattern

    x, y = Var("x"), Var("y")
    compiled = compile_canonical_pattern(
        _fake_pattern(x + y, x ^ y), width=32, declaration_index=3
    )
    assert isinstance(compiled.semantic_fingerprint, str)
    assert compiled.semantic_fingerprint == compile_canonical_pattern(
        _fake_pattern(x + y, x ^ y), width=32, declaration_index=3
    ).semantic_fingerprint
    assert term_fingerprint(compiled.pattern_term)
