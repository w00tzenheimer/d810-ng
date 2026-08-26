from __future__ import annotations

import random

import pytest

from d810.mba.subterm_atomization import atomize_repeated_subterms
from d810.mba.typed_term import TypedBvTerm, canonicalize_ac_term, term_fingerprint


def leaf(name: str, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(None, width, leaf_key=("register", name))


def const(value: int, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(None, width, value=value)


def op(name: str, *children: TypedBvTerm) -> TypedBvTerm:
    return TypedBvTerm(name, children[0].width, children=children)


def triggering_fixture(width: int = 32):
    x = leaf("v17", width)
    v135 = leaf("v135", width)
    y = op("and", v135, const((1 << width) - 0x404, width))
    source = op(
        "add",
        op(
            "sub",
            op("xor", x, y),
            op("add", op("and", x, y), op("mul", const(2, width), op("and", y, op("bnot", x)))),
        ),
        op("mul", const(2, width), y),
    )
    return source, x, y


def eval_python(term: TypedBvTerm, bindings: dict[tuple[object, ...], int]) -> int:
    mask = (1 << term.width) - 1
    if term.operation is None:
        return term.value if term.value is not None else bindings[term.leaf_key]
    values = [eval_python(child, bindings) for child in term.children]
    if term.operation == "bnot":
        return ~values[0] & mask
    if term.operation == "neg":
        return -values[0] & mask
    if term.operation == "and":
        return values[0] & values[1] & mask
    if term.operation == "or":
        return values[0] | values[1] & mask
    if term.operation == "xor":
        return values[0] ^ values[1] & mask
    if term.operation == "add":
        return (values[0] + values[1]) & mask
    if term.operation == "sub":
        return (values[0] - values[1]) & mask
    if term.operation == "mul":
        return (values[0] * values[1]) & mask
    raise AssertionError(term.operation)


@pytest.mark.parametrize("width", (8, 16, 32, 64))
@pytest.mark.parametrize("operation", ("and", "or", "xor", "add", "sub", "mul", "bnot", "neg"))
def test_private_evaluator_masks_every_supported_operation(width: int, operation: str) -> None:
    from d810.mba.bounded_synthesis import _evaluate_term

    a, b = leaf("a", width), leaf("b", width)
    term = op(operation, a) if operation in {"bnot", "neg"} else op(operation, a, b)
    values = {("register", "a"): (1 << width) - 1, ("register", "b"): 3}
    assert _evaluate_term(term, values) == eval_python(term, values)


def test_private_evaluator_handles_repeated_leaves_constants_and_missing_bindings() -> None:
    from d810.mba.bounded_synthesis import _evaluate_term

    x = leaf("x", 8)
    term = op("add", op("xor", x, x), const(257, 8))
    assert _evaluate_term(term, {x.leaf_key: 5}) == 1
    with pytest.raises(KeyError):
        _evaluate_term(term, {})


def test_witness_signatures_are_deterministic_and_match_bitvector_arithmetic() -> None:
    from d810.mba.bounded_synthesis import _evaluate_term, deterministic_witnesses

    source, _, _ = triggering_fixture(8)
    witnesses = deterministic_witnesses(source, count=12)
    assert witnesses == deterministic_witnesses(source, count=12)
    rng = random.Random(19)
    for binding in witnesses:
        assert _evaluate_term(source, binding) == eval_python(source, binding)
        for key in binding:
            assert 0 <= binding[key] < 256
        if rng.random() < 0.2:
            assert len(binding) == len(set(binding))


def test_bottom_up_enumeration_is_cost_ordered_ac_deduplicated_and_ordered_subtraction() -> None:
    from d810.mba.bounded_synthesis import MbaSynthesisBudget, enumerate_terms

    x, y = leaf("x"), leaf("y")
    terms, receipt = enumerate_terms((x, y), budget=MbaSynthesisBudget(max_generated_terms=60))
    assert receipt.generated_terms <= 60
    assert list(terms) == sorted(terms, key=lambda item: (item.cost, item.fingerprint))
    fps = [item.fingerprint for item in terms]
    assert len(fps) == len(set(fps))
    assert any(item.term == op("sub", x, y) for item in terms)
    assert not any(item.term == op("sub", y, x) and item.term == op("sub", x, y) for item in terms)


def test_enumeration_budget_variable_cap_and_receipt_are_stable() -> None:
    from d810.mba.bounded_synthesis import MbaSynthesisBudget, enumerate_terms

    a, b, c = leaf("a"), leaf("b"), leaf("c")
    budget = MbaSynthesisBudget(max_variables=2, max_generated_terms=3)
    first = enumerate_terms((c, b, a), budget=budget)
    second = enumerate_terms((a, c, b), budget=budget)
    assert first == second
    assert first[1].reason in {"too_many_variables", "generation_budget"}
    assert first[1].generated_terms <= 3


def test_triggering_residual_discovers_exact_or_replacement_and_negative_near_miss_fails() -> None:
    from d810.mba.bounded_synthesis import synthesize_residual

    source, x, _ = triggering_fixture()
    atomized = atomize_repeated_subterms(source)
    result = synthesize_residual(atomized)
    assert result.certified
    assert result.replacement is not None
    atom = TypedBvTerm(None, 32, leaf_key=atomized.bindings[0].leaf_key)
    expected = op("or", x, atom)
    assert term_fingerprint(result.replacement) == term_fingerprint(canonicalize_ac_term(expected))
    assert result.replacement_cost < result.source_cost

    near_miss = source
    # Change the coefficient in one of the repeated arithmetic terms.
    near_miss = op("add", near_miss.children[0], op("mul", const(3), near_miss.children[1]))
    near_atomized = atomize_repeated_subterms(near_miss)
    near_result = synthesize_residual(near_atomized)
    assert not near_result.certified


def test_certification_makes_four_fresh_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    from d810.mba import bounded_synthesis

    calls: list[int] = []

    def verify(pattern, replacement, *, options, engine=None):
        calls.append(options.bit_width)
        return True, None

    monkeypatch.setattr(bounded_synthesis, "verify_transformation", verify)
    x, y = leaf("x"), leaf("y")
    receipt = bounded_synthesis.certify_terms(op("add", x, y), op("add", y, x))
    assert receipt.certified
    assert calls == [8, 16, 32, 64]
