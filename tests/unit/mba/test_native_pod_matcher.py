"""Packed native MBA matcher contracts independent of Hex-Rays runtime."""

from __future__ import annotations

from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
from d810.backends.mba.egglog_add_rule_compiler import (
    _compile_rule_families,
    compile_add_rule_catalogue,
)
from d810.backends.mba.native_mba_term_view import NativeMbaTermView
from d810.backends.mba.native_pod_matcher import (
    OP_ADD,
    PackedNativeMbaTerm,
    match_root_pod,
)
from d810.mba.rules.sub import Sub_HackersDelightRule_2
from d810.mba.typed_term import term_fingerprint
from d810.mba.dsl import Const, Var
from d810.mba.rules._base import VerifiableRule


_TIGHT_X, _TIGHT_Y, _TIGHT_Z = Var("tight_x"), Var("tight_y"), Var("tight_z")
_TIGHT_ZERO = Const("tight_zero", 0)


class _ImpossibleBeforeValidRule(VerifiableRule):
    """A valid schema that cannot fit into the three-node test candidate."""

    PATTERN = _TIGHT_X + (_TIGHT_Y & _TIGHT_Z)
    REPLACEMENT = PATTERN


class _ValidAfterImpossibleRule(VerifiableRule):
    """A later valid zero-addition simplification."""

    PATTERN = _TIGHT_X + _TIGHT_ZERO
    REPLACEMENT = _TIGHT_X


def _leaf(name: str) -> NativeMbaTermView:
    return NativeMbaTermView(
        None,
        32,
        leaf_key=("mop", "r", name),
        native_operand=object(),
    )


def _constant(value: int) -> NativeMbaTermView:
    return NativeMbaTermView(None, 32, constant_value=value)


def _node(name: str, *children: NativeMbaTermView) -> NativeMbaTermView:
    return NativeMbaTermView(name, 32, children=children)


def _rule(name: str):
    return compile_add_rule_catalogue().receipt_for(name).compiled_rule


def test_packed_view_separates_numeric_nodes_from_live_identity_sidecar() -> None:
    x, y = _leaf("x"), _leaf("y")
    packed = PackedNativeMbaTerm.from_view(_node("add", x, y))
    root = packed.nodes[packed.root_index]

    assert root.operation == OP_ADD
    assert all(type(node.literal_u64) is int for node in packed.nodes)
    assert packed.sidecar[root.left_index] is x
    assert packed.sidecar[root.right_index] is y


def test_packed_view_retains_associative_binary_structure_for_numeric_matching() -> (
    None
):
    x, y, z = _leaf("x"), _leaf("y"), _leaf("z")
    packed = PackedNativeMbaTerm.from_view(_node("add", _node("add", x, y), z))
    root = packed.nodes[packed.root_index]

    assert root.operation == OP_ADD
    assert packed.nodes[root.left_index].operation == OP_ADD
    assert len(packed.nodes) == 5


def test_packed_view_materializes_one_shared_portable_term() -> None:
    x, y = _leaf("x"), _leaf("y")
    candidate = _node("add", _node("xor", x, y), _constant(1))
    packed = PackedNativeMbaTerm.from_view(candidate)

    first = packed.typed_term()

    assert first == candidate.to_typed_term()
    assert packed.typed_term() is first
    assert packed.typed_term(packed.root_index) is first


def test_packed_view_uses_ac_identity_for_repeated_operand_checks(monkeypatch) -> None:
    a, b = _leaf("a"), _leaf("b")
    shared = _node("add", a, b)
    packed = PackedNativeMbaTerm.from_view(_node("xor", shared, shared))
    root = packed.nodes[packed.root_index]
    calls = 0
    original = NativeMbaTermView.canonical_children

    def observed(view: NativeMbaTermView):
        nonlocal calls
        calls += 1
        return original(view)

    monkeypatch.setattr(NativeMbaTermView, "canonical_children", observed)
    rows = packed.numeric_rows()

    assert rows[root.left_index][7] == rows[root.right_index][7]
    assert calls == 0


def test_pod_adapter_matches_portable_catalogue_exactly() -> None:
    rule = _rule("Add_HackersDelightRule_2")
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    x, y = _leaf("x"), _leaf("y")
    candidate = _node(
        "add",
        _node("xor", y, x),
        _node("mul", _constant(2), _node("and", y, x)),
    )

    assert match_root_pod(catalogue, candidate, comparison_budget=64) == (
        catalogue.match_root(candidate, comparison_budget=64)
    )


def test_pod_adapter_preserves_asymmetric_subtraction_bindings() -> None:
    """AC traversal must retain the binding orientation used by ``x - y``."""

    rules = _compile_rule_families({"sub": (Sub_HackersDelightRule_2,)}).compiled_rules
    catalogue = CompiledPatternCatalogue.from_rules(rules)
    a, b = _leaf("a"), _leaf("b")
    candidate = _node(
        "sub",
        _node("xor", a, b),
        _node("mul", _constant(2), _node("and", a, _node("bnot", b))),
    )

    def replacement_fingerprints(result):
        return tuple(
            term_fingerprint(match.bindings.materialize_replacement(match.rule))
            for match in result.matches
        )

    portable = catalogue._match_root_portable(candidate, comparison_budget=64)
    pod = match_root_pod(catalogue, candidate, comparison_budget=64)

    assert replacement_fingerprints(pod) == replacement_fingerprints(portable)


def test_shared_feasibility_filter_preserves_later_match_under_tight_budget() -> None:
    """Impossible earlier patterns must not consume the shared budget in either mode."""

    rules = _compile_rule_families(
        {"add": (_ImpossibleBeforeValidRule, _ValidAfterImpossibleRule)}
    ).compiled_rules
    catalogue = CompiledPatternCatalogue.from_rules(rules)
    candidate = _node("add", _leaf("x"), _constant(0))

    result = catalogue._match_root_portable(candidate, comparison_budget=5)

    assert result.comparison_budget_exceeded is False
    assert tuple(match.rule.source_name for match in result.matches) == (
        "_ValidAfterImpossibleRule",
    )
