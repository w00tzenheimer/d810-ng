from __future__ import annotations

import hashlib
import math
import random
from dataclasses import FrozenInstanceError

import pytest

from d810.mba.subterm_atomization import atomize_repeated_subterms
from d810.mba.typed_term import (
    TypedBvTerm,
    canonicalize_ac_term,
    fixed_shift_term,
    term_cost,
    term_fingerprint,
)


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
    assert list(terms) == sorted(terms, key=lambda item: (item.cost, item.novel_constant_count, item.fingerprint))
    fps = [item.fingerprint for item in terms]
    assert len(fps) == len(set(fps))
    assert any(item.term == op("sub", x, y) for item in terms)
    assert any(item.term == op("sub", y, x) for item in terms)
    assert term_fingerprint(op("sub", x, y)) != term_fingerprint(op("sub", y, x))


def test_enumeration_budget_variable_cap_and_receipt_are_stable() -> None:
    from d810.mba.bounded_synthesis import MbaSynthesisBudget, enumerate_terms

    a, b, c = leaf("a"), leaf("b"), leaf("c")
    budget = MbaSynthesisBudget(max_variables=2, max_generated_terms=3)
    first = enumerate_terms((c, b, a), budget=budget)
    second = enumerate_terms((a, c, b), budget=budget)
    assert first == second
    assert first[1].reason in {"too_many_variables", "generation_budget"}
    assert first[1].generated_terms <= 3


def test_iterable_insertion_order_keeps_records_and_signatures_identical() -> None:
    from d810.mba.bounded_synthesis import MbaSynthesisBudget, enumerate_terms

    a, b = leaf("a", 8), leaf("b", 8)
    budget = MbaSynthesisBudget(max_generated_terms=20, max_candidate_operator_nodes=1)
    first = enumerate_terms((a, b), budget=budget)
    second = enumerate_terms((b, a), budget=budget)
    assert first == second


def test_triggering_residual_discovers_exact_or_replacement_and_negative_near_miss_fails() -> None:
    from d810.mba import bounded_synthesis
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
    near_atom = TypedBvTerm(None, 32, leaf_key=near_atomized.bindings[0].leaf_key)
    near_certification = bounded_synthesis.certify_terms(near_atomized.atomized_term, op("or", x, near_atom))
    assert not near_certification.certified
    assert tuple(receipt.width for receipt in near_certification.receipts) == (8, 16, 32, 64)
    assert all(not receipt.certified for receipt in near_certification.receipts)


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


def test_iterable_requires_terminals_and_operator_cap_is_enforced() -> None:
    from d810.mba.bounded_synthesis import MbaSynthesisBudget, enumerate_terms

    x, y = leaf("x"), leaf("y")
    with pytest.raises(ValueError, match="terminal"):
        enumerate_terms((op("add", x, y),), budget=MbaSynthesisBudget())
    terms, receipt = enumerate_terms((x,), budget=MbaSynthesisBudget(max_candidate_operator_nodes=0))
    assert all(item.cost[0] == 0 for item in terms)
    assert receipt.reason == "not_cheaper"


def test_capped_enumeration_is_prefix_of_uncapped_global_order() -> None:
    from d810.mba.bounded_synthesis import MbaSynthesisBudget, enumerate_terms

    x = leaf("x")
    small, _ = enumerate_terms((x,), budget=MbaSynthesisBudget(max_generated_terms=100))
    capped, receipt = enumerate_terms((x,), budget=MbaSynthesisBudget(max_generated_terms=5))
    assert [item.fingerprint for item in capped] == [item.fingerprint for item in small[:5]]
    assert receipt.reason == "generation_budget"


@pytest.mark.parametrize("cap", (1, 5, 37, 109))
def test_capped_enumeration_is_exact_prefix_of_complete_semantic_order(
    cap: int,
) -> None:
    from d810.mba.bounded_synthesis import MbaSynthesisBudget, enumerate_terms
    from d810.mba.semantic_canonicalization import canonicalize_mba_term

    x = leaf("x", 8)
    full, receipt = enumerate_terms(
        (x,),
        budget=MbaSynthesisBudget(
            max_candidate_operator_nodes=1,
            max_generated_terms=50_000,
        ),
    )
    capped, capped_receipt = enumerate_terms(
        (x,),
        budget=MbaSynthesisBudget(
            max_candidate_operator_nodes=1,
            max_generated_terms=cap,
        ),
    )

    assert receipt.reason == "not_cheaper"
    assert [item.fingerprint for item in capped] == [
        item.fingerprint for item in full[:cap]
    ]
    assert all(
        canonicalize_mba_term(item.term).canonical_term == item.term
        for item in full
    )
    if cap < len(full):
        assert capped_receipt.reason == "generation_budget"


def test_greater_than_two_operator_candidate_uses_semantic_canonical_form() -> None:
    from d810.mba.bounded_synthesis import _canonical_candidate
    from d810.mba.semantic_canonicalization import canonicalize_mba_term

    x, y, z = leaf("x"), leaf("y"), leaf("z")
    generated = op("add", op("add", x, z), op("neg", y))
    ac_only = canonicalize_ac_term(generated)
    expected = canonicalize_mba_term(ac_only).canonical_term

    assert term_cost(ac_only)[0] > 2
    assert expected == op("sub", op("add", x, z), y)
    assert term_cost(expected) < term_cost(ac_only)
    assert term_fingerprint(expected) != term_fingerprint(ac_only)
    assert _canonical_candidate(generated) == expected


def test_exact_budget_and_variable_reasons_are_preserved() -> None:
    from d810.mba.bounded_synthesis import MbaSynthesisBudget, enumerate_terms, synthesize_residual

    x, y = leaf("x"), leaf("y")
    _, receipt = enumerate_terms((x, y), budget=MbaSynthesisBudget(max_variables=1))
    assert receipt.reason == "too_many_variables"
    source, _, _ = triggering_fixture()
    atomized = atomize_repeated_subterms(source)
    result = synthesize_residual(atomized, budget=MbaSynthesisBudget(max_generated_terms=0))
    assert result.exhaustion.reason == "generation_budget"


def test_witnesses_cover_full_width_structured_rows_and_all_variables() -> None:
    from d810.mba.bounded_synthesis import deterministic_witnesses

    x, y = leaf("x", 64), leaf("y", 64)
    rows = deterministic_witnesses(op("xor", x, y), count=96)
    assert rows[0][x.leaf_key] == rows[0][y.leaf_key] == 0
    assert rows[1][x.leaf_key] == rows[1][y.leaf_key] == (1 << 64) - 1
    assert 0xAAAAAAAAAAAAAAAA in {row[x.leaf_key] for row in rows}
    assert 0x5555555555555555 in {row[x.leaf_key] for row in rows}
    assert all((1 << bit) in {row[x.leaf_key] for row in rows} for bit in range(64))
    assert all((1 << bit) in {row[y.leaf_key] for row in rows} for bit in range(64))
    with pytest.raises((TypeError, ValueError)):
        deterministic_witnesses(x, count=True)  # type: ignore[arg-type]


@pytest.mark.parametrize("width", (8, 16, 32, 64))
@pytest.mark.parametrize("variable_count", (1, 2, 3))
def test_default_witness_schedule_reserves_fingerprint_derived_rows(
    width: int,
    variable_count: int,
) -> None:
    from d810.mba.bounded_synthesis import deterministic_witnesses

    variables = tuple(leaf(f"x_{index}", width) for index in range(variable_count))
    term = variables[0]
    for variable in variables[1:]:
        term = op("xor", term, variable)
    rows = deterministic_witnesses(term, count=96)
    keys = tuple(variable.leaf_key for variable in variables)
    mask = (1 << width) - 1

    assert len(rows) == 96
    assert rows == deterministic_witnesses(term, count=96)
    assert rows[0] == {key: 0 for key in keys}
    assert rows[1] == {key: mask for key in keys}
    for key in keys:
        assert all(any(row[key] == 1 << bit for row in rows) for bit in range(width))

    first_fingerprint_index = 96 - max(1, 96 // 8)
    seed = hashlib.sha256(term_fingerprint(term).encode("ascii")).digest()
    expected = {}
    for key_index, key in enumerate(keys):
        digest = hashlib.sha256(
            seed
            + first_fingerprint_index.to_bytes(4, "big")
            + key_index.to_bytes(2, "big")
        ).digest()
        expected[key] = int.from_bytes(digest, "big") & mask
    assert rows[first_fingerprint_index] == expected


@pytest.mark.parametrize("operation", ("shl", "lshr", "rol", "ror"))
def test_fixed_operations_certify_at_all_widths(operation: str) -> None:
    from d810.mba.bounded_synthesis import certify_terms

    x = leaf("x", 32)
    left = TypedBvTerm(operation, 32, children=(x,), shift_count=3)
    assert certify_terms(left, left).certified


@pytest.mark.parametrize("count", (8, 31))
def test_fixed_rotate_count_invalid_at_minimum_proof_width_cannot_certify(
    count: int,
) -> None:
    from d810.mba.bounded_synthesis import certify_terms

    calls: list[int] = []

    def verify(pattern, replacement, *, options):
        calls.append(options.bit_width)
        return True, None

    x = leaf("x", 32)
    rotate = fixed_shift_term("ror", 32, x, count)
    pattern = op("add", rotate, const(0))
    certification = certify_terms(pattern, rotate, verifier=verify)

    assert not certification.certified
    assert tuple(receipt.width for receipt in certification.receipts) == (8, 16, 32, 64)
    assert all(not receipt.certified for receipt in certification.receipts)
    assert all(receipt.error and "fixed rotate" in receipt.error for receipt in certification.receipts)
    assert calls == []


@pytest.mark.parametrize("elapsed_ms", (True, -1, math.nan, math.inf, -math.inf))
def test_proof_receipt_rejects_invalid_or_nonfinite_elapsed_time(
    elapsed_ms: object,
) -> None:
    from d810.mba.bounded_synthesis import ProofReceipt

    with pytest.raises((TypeError, ValueError), match="elapsed_ms"):
        ProofReceipt(8, True, elapsed_ms)  # type: ignore[arg-type]


def test_proof_receipt_normalizes_elapsed_time_and_remains_immutable() -> None:
    from d810.mba.bounded_synthesis import ProofReceipt

    receipt = ProofReceipt(8, True, 0)
    assert receipt.elapsed_ms == 0.0
    assert type(receipt.elapsed_ms) is float
    with pytest.raises(FrozenInstanceError):
        receipt.elapsed_ms = 1.0  # type: ignore[misc]


def test_generalization_allows_eliminated_but_not_introduced_leaves() -> None:
    from d810.mba.bounded_synthesis import certify_terms, generalize_terms

    x, y = leaf("x"), leaf("y")
    zero = const(0)
    pattern_expr, replacement_expr = generalize_terms(op("xor", x, x), zero)
    assert pattern_expr is not None and replacement_expr is not None
    assert certify_terms(op("xor", x, x), zero).certified
    with pytest.raises(ValueError, match="unknown|replacement"):
        generalize_terms(x, op("or", x, y))


def test_width_relative_all_ones_constant_is_rebuilt_for_each_proof_width() -> None:
    from d810.mba.bounded_synthesis import (
        certify_terms,
        grammar_all_ones_origins,
    )

    x = leaf("x", 32)
    all_ones = const((1 << 32) - 1)
    pattern = op("bnot", x)
    replacement = op("xor", x, all_ones)
    assert certify_terms(
        pattern,
        replacement,
        width_relative_all_ones=grammar_all_ones_origins(replacement),
    ).certified


def test_synthesis_preserves_injected_and_fixed_all_ones_origins() -> None:
    from d810.mba.bounded_synthesis import synthesize_residual
    from d810.mba.subterm_atomization import AtomizedMbaTerm

    zero = const(0)
    injected_source = op("bnot", zero)
    injected = synthesize_residual(
        AtomizedMbaTerm(injected_source, injected_source, ())
    )
    assert injected.certified
    assert injected.replacement == const(0xFFFFFFFF)
    assert tuple(origin.occurrence_path for origin in injected.width_relative_all_ones) == ((),)
    assert all(
        origin.origin == "grammar_injected_all_ones"
        for origin in injected.width_relative_all_ones
    )

    fixed_mask = const(0xFFFFFFFF)
    fixed_source = op("xor", fixed_mask, zero)
    fixed = synthesize_residual(AtomizedMbaTerm(fixed_source, fixed_source, ()))
    assert fixed.certified
    assert fixed.replacement == fixed_mask
    assert fixed.width_relative_all_ones == ()
    assert fixed.certification.certified


def test_all_ones_origin_paths_distinguish_duplicate_equal_terminals() -> None:
    from d810.mba.bounded_synthesis import grammar_all_ones_origins

    mask = const(0xFFFFFFFF)
    duplicate = op("add", mask, mask)
    origins = grammar_all_ones_origins(duplicate)

    assert tuple(origin.occurrence_path for origin in origins) == ((0,), (1,))
    assert origins[0].terminal_fingerprint == origins[1].terminal_fingerprint


def test_synthesis_result_rejects_forged_origin_for_fixed_input_mask() -> None:
    from d810.mba.bounded_synthesis import (
        GrammarAllOnesOrigin,
        MbaCertification,
        MbaSynthesisResult,
        ProofReceipt,
    )

    mask = const(0xFFFFFFFF)
    zero = const(0)
    source = op("xor", mask, zero)
    proofs = MbaCertification(
        tuple(ProofReceipt(width, True, 0.0) for width in (8, 16, 32, 64))
    )
    forged = GrammarAllOnesOrigin(
        occurrence_path=(),
        terminal_fingerprint=term_fingerprint(mask),
        source_width=32,
    )

    with pytest.raises(ValueError, match="input|origin"):
        MbaSynthesisResult(
            source,
            mask,
            term_cost(source),
            term_cost(mask),
            proofs,
            None,
            (forged,),
        )


def test_synthesis_result_rejects_discovery_receipt_without_replacement() -> None:
    from d810.mba.bounded_synthesis import (
        MbaCertification,
        MbaDiscoveryReceipt,
        MbaSynthesisBudget,
        MbaSynthesisResult,
    )

    source = const(0)
    receipt = MbaDiscoveryReceipt(
        budget=MbaSynthesisBudget(),
        candidate_attempts=1,
        generated_terms=1,
        retained_terms=1,
        witness_identity="witness",
        selected_candidate_fingerprint="candidate",
        selected_candidate_rank=0,
        completion_reason="certified_candidate",
    )
    with pytest.raises(ValueError, match="discovery_receipt"):
        MbaSynthesisResult(
            source,
            None,
            term_cost(source),
            None,
            MbaCertification(()),
            None,
            discovery_receipt=receipt,
        )


def test_generic_synthesis_reaches_terminal_x_without_or_shortcut(monkeypatch: pytest.MonkeyPatch) -> None:
    from d810.mba import bounded_synthesis
    from d810.mba.bounded_synthesis import MbaCertification, ProofReceipt, synthesize_residual
    from d810.mba.subterm_atomization import AtomizedMbaTerm

    x, y = leaf("x"), leaf("y")
    source = op("or", op("and", x, y), op("and", x, op("bnot", y)))
    atomized = AtomizedMbaTerm(source, source, ())
    seen: list[TypedBvTerm] = []

    def fake_certify(pattern, replacement, **kwargs):
        seen.append(replacement)
        return MbaCertification(tuple(ProofReceipt(width, True, 0.0) for width in (8, 16, 32, 64)))

    monkeypatch.setattr(bounded_synthesis, "certify_terms", fake_certify)
    result = synthesize_residual(atomized)
    assert result.certified
    assert result.replacement == x
    assert seen == [x]


def test_operator_cap_zero_forbids_or_candidate() -> None:
    from d810.mba.bounded_synthesis import MbaSynthesisBudget, synthesize_residual
    from d810.mba.subterm_atomization import AtomizedMbaTerm

    x, y = leaf("x"), leaf("y")
    source = op("or", x, y)
    result = synthesize_residual(
        AtomizedMbaTerm(source, source, ()),
        budget=MbaSynthesisBudget(max_candidate_operator_nodes=0),
    )
    assert not result.certified
    assert result.exhaustion.reason in {"no_signature_match", "not_cheaper"}


def test_equal_cost_signature_reports_not_cheaper() -> None:
    from d810.mba.bounded_synthesis import synthesize_residual
    from d810.mba.subterm_atomization import AtomizedMbaTerm

    x = leaf("x")
    result = synthesize_residual(AtomizedMbaTerm(x, x, ()))
    assert not result.certified
    assert result.exhaustion.reason == "not_cheaper"


@pytest.mark.parametrize(
    ("budget", "expected_reason", "expected_generated"),
    (
        ({"max_variables": 0}, "too_many_variables", 0),
        ({"max_generated_terms": 0}, "generation_budget", 0),
        ({"max_candidate_attempts": 0}, "generation_budget", 0),
        ({}, "not_cheaper", 1),
    ),
)
def test_terminal_source_routes_through_all_budget_gates(
    budget: dict[str, int], expected_reason: str, expected_generated: int
) -> None:
    from d810.mba.bounded_synthesis import MbaSynthesisBudget, synthesize_residual
    from d810.mba.subterm_atomization import AtomizedMbaTerm

    x = leaf("x", 8)
    result = synthesize_residual(
        AtomizedMbaTerm(x, x, ()),
        budget=MbaSynthesisBudget(**budget),
    )

    assert not result.certified
    assert result.exhaustion is not None
    assert result.exhaustion.reason == expected_reason
    assert result.exhaustion.generated_terms == expected_generated


def test_iterable_leaf_and_constant_inputs_have_exact_terminal_prefix() -> None:
    from d810.mba.bounded_synthesis import MbaSynthesisBudget, enumerate_terms

    x = leaf("x")
    terms, receipt = enumerate_terms((const(7), x), budget=MbaSynthesisBudget(max_generated_terms=1))
    expected = min((const(7), x), key=lambda item: (term_fingerprint(item)))
    assert terms[0].term == expected
    assert receipt.reason == "generation_budget"
    terms, _ = enumerate_terms((const(7),), budget=MbaSynthesisBudget(max_generated_terms=1))
    assert terms[0].term == const(7)


def test_candidate_attempt_budget_bounds_canonicalization_work(monkeypatch: pytest.MonkeyPatch) -> None:
    from d810.mba import bounded_synthesis
    from d810.mba.bounded_synthesis import MbaSynthesisBudget, enumerate_terms

    x = leaf("x")
    calls = 0
    original = bounded_synthesis._canonical_candidate

    def counted(term):
        nonlocal calls
        calls += 1
        return original(term)

    monkeypatch.setattr(bounded_synthesis, "_canonical_candidate", counted)
    _, receipt = enumerate_terms(
        x,
        budget=MbaSynthesisBudget(max_generated_terms=6, max_candidate_attempts=6),
    )
    assert calls <= 6
    assert receipt.reason == "generation_budget"
    assert receipt.budget.max_candidate_attempts == 6


def test_distinct_novel_constant_count_and_injected_witness_shape() -> None:
    from d810.mba.bounded_synthesis import MbaSynthesisBudget, enumerate_terms

    x = leaf("x")
    terms, _ = enumerate_terms((x,), budget=MbaSynthesisBudget(max_generated_terms=500))
    nested = next(item for item in terms if item.fingerprint == term_fingerprint(canonicalize_ac_term(op("add", x, const(1)))))
    assert nested.novel_constant_count == 1
    budget = MbaSynthesisBudget(witness_count=2)
    with pytest.raises(ValueError, match="exactly"):
        enumerate_terms((x,), budget=budget, witnesses=({x.leaf_key: 0},))


def test_atom_cap_is_enforced() -> None:
    from d810.mba.bounded_synthesis import MbaSynthesisBudget, enumerate_terms

    x = leaf("x")
    atom = TypedBvTerm(None, 32, leaf_key=("d810.mba.atom.v1", 0, "fp"))
    _, receipt = enumerate_terms((x, atom), budget=MbaSynthesisBudget(max_atoms=0))
    assert receipt.reason == "too_many_variables"


def test_enumeration_callback_acceptance_is_not_an_exhaustion_receipt() -> None:
    from d810.mba.bounded_synthesis import MbaSynthesisBudget, enumerate_terms

    x = leaf("x")
    records, receipt = enumerate_terms(
        x,
        budget=MbaSynthesisBudget(max_generated_terms=5),
        on_candidate=lambda record: record.term == x,
    )
    assert records and receipt is None


def test_ror_evaluator_matches_independent_concrete_oracle() -> None:
    from d810.mba.bounded_synthesis import _evaluate_term

    x = leaf("x", 8)
    term = fixed_shift_term("ror", 8, x, 3)
    for value in (0, 1, 0x80, 0xCC, 0xFF):
        expected = ((value >> 3) | (value << 5)) & 0xFF
        assert _evaluate_term(term, {x.leaf_key: value}) == expected


def test_near_miss_exact_or_candidate_has_four_failed_receipts() -> None:
    from d810.mba.bounded_synthesis import certify_terms

    source, x, atom = triggering_fixture()
    near = op("add", source.children[0], op("mul", const(3), source.children[1]))
    near_atomized = atomize_repeated_subterms(near)
    replacement = op("or", x, TypedBvTerm(None, 32, leaf_key=near_atomized.bindings[0].leaf_key))
    certification = certify_terms(near_atomized.atomized_term, replacement)
    assert not certification.certified
    assert tuple(receipt.width for receipt in certification.receipts) == (8, 16, 32, 64)
    assert all(not receipt.certified for receipt in certification.receipts)


@pytest.mark.parametrize("result", ((False, None), ("true", None), (True, {"x": 1})))
def test_certification_fail_closed_for_nontrue_or_counterexample(
    result: tuple[object, object],
) -> None:
    from d810.mba.bounded_synthesis import certify_terms

    x = leaf("x")
    calls: list[int] = []

    def verify(pattern, replacement, *, options):
        calls.append(options.bit_width)
        return result

    receipt = certify_terms(x, x, verifier=verify)  # type: ignore[arg-type]
    assert not receipt.certified
    assert calls == [8, 16, 32, 64]


@pytest.mark.parametrize("failure", (RuntimeError("unavailable"), TimeoutError("timeout"), ValueError("backend error")))
def test_certification_fail_closed_for_backend_failures(failure: Exception) -> None:
    from d810.mba.bounded_synthesis import certify_terms

    x = leaf("x")
    calls: list[int] = []

    def verify(pattern, replacement, *, options):
        calls.append(options.bit_width)
        raise failure

    receipt = certify_terms(x, x, verifier=verify)
    assert not receipt.certified
    assert calls == [8, 16, 32, 64]


def test_enumeration_does_not_load_z3_in_fresh_process() -> None:
    import os
    import subprocess
    import sys
    from pathlib import Path

    code = """
from d810.mba.bounded_synthesis import MbaSynthesisBudget, enumerate_terms
from d810.mba.typed_term import TypedBvTerm
x = TypedBvTerm(None, 8, leaf_key=('register', 'x'))
enumerate_terms((x,), budget=MbaSynthesisBudget(max_generated_terms=1))
assert 'z3' not in __import__('sys').modules
"""
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    root = Path(__file__).resolve().parents[3]
    subprocess.run([sys.executable, "-c", code], cwd=root, env=env, check=True)
