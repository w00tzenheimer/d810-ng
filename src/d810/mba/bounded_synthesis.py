"""Bounded, deterministic discovery of small portable MBA identities.

This module is deliberately split into a cheap discovery phase and an exact
certification phase.  The evaluator and witness signatures are filters only;
the existing verification engine remains the authority for equivalence.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from d810.mba.dsl import Const, SymbolicExpression, Var
from d810.mba.subterm_atomization import AtomizedMbaTerm
from d810.mba.semantic_canonicalization import canonicalize_mba_term
from d810.mba.typed_term import (
    TypedBvTerm,
    leaf_key_fingerprint,
    term_cost,
    term_fingerprint,
)
from d810.mba.verifier import VerificationOptions, verify_transformation


CERTIFICATION_WIDTHS = (8, 16, 32, 64)
_SYNTHESIZED_UNARY = ("bnot", "neg")
_SYNTHESIZED_BINARY = ("and", "or", "xor", "add", "sub", "mul")
_ALL_ONES = object()


@dataclass(frozen=True, slots=True)
class MbaSynthesisBudget:
    max_atoms: int = 4
    max_variables: int = 3
    max_candidate_operator_nodes: int = 4
    max_generated_terms: int = 50_000
    witness_count: int = 96

    def __post_init__(self) -> None:
        for field_name in (
            "max_atoms",
            "max_variables",
            "max_candidate_operator_nodes",
            "max_generated_terms",
            "witness_count",
        ):
            value = getattr(self, field_name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        if self.witness_count == 0:
            raise ValueError("witness_count must be positive")


@dataclass(frozen=True, slots=True)
class MbaExhaustionReceipt:
    reason: str
    generated_terms: int
    budget: MbaSynthesisBudget

    def __post_init__(self) -> None:
        if self.reason not in {
            "too_many_variables",
            "generation_budget",
            "no_signature_match",
            "proof_failed",
            "not_cheaper",
        }:
            raise ValueError("unknown synthesis exhaustion reason")
        if type(self.generated_terms) is not int or self.generated_terms < 0:
            raise ValueError("generated_terms must be a non-negative integer")

    @property
    def exhausted(self) -> bool:
        return self.reason == "generation_budget"


@dataclass(frozen=True, slots=True)
class EnumeratedTerm:
    term: TypedBvTerm
    cost: tuple[int, int]
    fingerprint: str
    signature: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ProofReceipt:
    width: int
    verdict: bool
    elapsed_ms: float
    counterexample: Mapping[str, int] | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        if type(self.width) is not int or self.width not in CERTIFICATION_WIDTHS:
            raise ValueError("proof width must be 8, 16, 32, or 64")
        if type(self.verdict) is not bool:
            raise TypeError("proof verdict must be a boolean")
        if type(self.elapsed_ms) not in (int, float) or self.elapsed_ms < 0:
            raise ValueError("proof elapsed_ms must be non-negative")
        if self.counterexample is not None:
            object.__setattr__(self, "counterexample", dict(self.counterexample))

    @property
    def certified(self) -> bool:
        return self.verdict and self.error is None and self.counterexample is None


@dataclass(frozen=True, slots=True)
class MbaCertification:
    receipts: tuple[ProofReceipt, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "receipts", tuple(self.receipts))

    @property
    def certified(self) -> bool:
        return (
            len(self.receipts) == len(CERTIFICATION_WIDTHS)
            and tuple(receipt.width for receipt in self.receipts) == CERTIFICATION_WIDTHS
            and all(receipt.certified for receipt in self.receipts)
        )


@dataclass(frozen=True, slots=True)
class MbaSynthesisResult:
    source: TypedBvTerm
    replacement: TypedBvTerm | None
    source_cost: tuple[int, int]
    replacement_cost: tuple[int, int] | None
    certification: MbaCertification
    exhaustion: MbaExhaustionReceipt

    @property
    def certified(self) -> bool:
        return self.certification.certified and self.replacement is not None

    @property
    def proof_receipts(self) -> tuple[ProofReceipt, ...]:
        return self.certification.receipts


def _mask(width: int) -> int:
    return (1 << width) - 1


def _evaluate_term(
    term: TypedBvTerm, bindings: Mapping[tuple[object, ...], int]
) -> int:
    """Evaluate one candidate with modular arithmetic after every operation."""

    if term.operation is None:
        if term.value is not None:
            return term.value & _mask(term.width)
        assert term.leaf_key is not None
        if term.leaf_key not in bindings:
            raise KeyError(term.leaf_key)
        value = bindings[term.leaf_key]
        if type(value) is not int:
            raise TypeError("leaf bindings must contain integers")
        return value & _mask(term.width)
    values = tuple(_evaluate_term(child, bindings) for child in term.children)
    mask = _mask(term.width)
    if term.operation == "bnot":
        return (~values[0]) & mask
    if term.operation == "neg":
        return (-values[0]) & mask
    if term.operation == "and":
        return (values[0] & values[1]) & mask
    if term.operation == "or":
        return (values[0] | values[1]) & mask
    if term.operation == "xor":
        return (values[0] ^ values[1]) & mask
    if term.operation == "add":
        return (values[0] + values[1]) & mask
    if term.operation == "sub":
        return (values[0] - values[1]) & mask
    if term.operation == "mul":
        return (values[0] * values[1]) & mask
    if term.operation == "shl":
        return (values[0] << term.shift_count) & mask
    if term.operation == "lshr":
        return values[0] >> term.shift_count
    if term.operation == "rol":
        count = term.shift_count
        return ((values[0] << count) | (values[0] >> (term.width - count))) & mask if count else values[0]
    if term.operation == "ror":
        count = term.shift_count
        return ((values[0] >> count) | (values[0] << (term.width - count))) & mask if count else values[0]
    raise ValueError(f"unsupported evaluator operation: {term.operation}")


def _leaf_keys(term: TypedBvTerm) -> tuple[tuple[object, ...], ...]:
    found: dict[tuple[object, ...], None] = {}
    def visit(node: TypedBvTerm) -> None:
        if node.operation is None:
            if node.leaf_key is not None:
                found[node.leaf_key] = None
            return
        for child in node.children:
            visit(child)
    visit(term)
    return tuple(sorted(found, key=leaf_key_fingerprint))


def deterministic_witnesses(
    term: TypedBvTerm, *, count: int = 96
) -> tuple[dict[tuple[object, ...], int], ...]:
    if type(count) is not int or count <= 0:
        raise ValueError("count must be a positive integer")
    keys = _leaf_keys(term)
    width = term.width
    mask = _mask(width)
    seed = hashlib.sha256(term_fingerprint(term).encode("ascii")).digest()
    base_values = [0, mask, 1, mask ^ 1]
    base_values.extend(1 << bit for bit in range(width) if bit < 8)
    base_values.extend((0xAA & mask, 0x55 & mask))
    witnesses: list[dict[tuple[object, ...], int]] = []
    for index in range(count):
        row: dict[tuple[object, ...], int] = {}
        for key_index, key in enumerate(keys):
            if index < len(base_values):
                value = base_values[(index + key_index) % len(base_values)]
            else:
                digest = hashlib.sha256(seed + index.to_bytes(4, "big") + key_index.to_bytes(2, "big")).digest()
                value = int.from_bytes(digest, "big") & mask
            row[key] = value
        witnesses.append(row)
    return tuple(witnesses)


def _signature(term: TypedBvTerm, witnesses: tuple[Mapping[tuple[object, ...], int], ...]) -> tuple[int, ...]:
    return tuple(_evaluate_term(term, witness) for witness in witnesses)


def _input_terminals(term: TypedBvTerm) -> tuple[TypedBvTerm, ...]:
    leaves: dict[str, TypedBvTerm] = {}
    constants: dict[tuple[int, int], TypedBvTerm] = {}
    def visit(node: TypedBvTerm) -> None:
        if node.operation is None:
            if node.leaf_key is not None:
                leaves[term_fingerprint(node)] = node
            else:
                constants[(node.width, node.value)] = node
            return
        for child in node.children:
            visit(child)
    visit(term)
    width = term.width
    for value in (0, 1, 2, _mask(width)):
        constants.setdefault((width, value), TypedBvTerm(None, width, value=value))
    result = list(leaves.values()) + list(constants.values())
    return tuple(sorted(result, key=term_fingerprint))


def _canonical_candidate(term: TypedBvTerm) -> TypedBvTerm:
    return canonicalize_mba_term(term).canonical_term


def enumerate_terms(
    term_or_terminals: TypedBvTerm | Iterable[TypedBvTerm],
    *,
    budget: MbaSynthesisBudget | None = None,
    witnesses: tuple[Mapping[tuple[object, ...], int], ...] | None = None,
    on_candidate: Callable[[EnumeratedTerm], bool] | None = None,
) -> tuple[tuple[EnumeratedTerm, ...], MbaExhaustionReceipt]:
    budget = MbaSynthesisBudget() if budget is None else budget
    if isinstance(term_or_terminals, TypedBvTerm):
        source = term_or_terminals
        terminals = _input_terminals(source)
    else:
        terminals = tuple(term_or_terminals)
        if not terminals or any(not isinstance(item, TypedBvTerm) for item in terminals):
            raise TypeError("terminals must contain TypedBvTerm values")
        source = terminals[0]
        terminals = tuple(sorted(set(terminals), key=term_fingerprint))
    if any(item.width != source.width for item in terminals):
        raise ValueError("all terminals must have one width")
    all_key_set: set[tuple[object, ...]] = set()
    for terminal in terminals:
        all_key_set.update(_leaf_keys(terminal))
    keys = tuple(sorted(all_key_set, key=leaf_key_fingerprint))
    atom_count = sum(1 for key in keys if key and key[0] == "d810.mba.atom.v1")
    if len(keys) > budget.max_variables or atom_count > budget.max_atoms:
        return (), MbaExhaustionReceipt("too_many_variables", 0, budget)
    if witnesses is None:
        witness_seed = terminals[0]
        for terminal in terminals[1:]:
            witness_seed = TypedBvTerm("add", source.width, children=(witness_seed, terminal))
        witness_rows = deterministic_witnesses(witness_seed, count=budget.witness_count)
    else:
        witness_rows = witnesses
    records: dict[str, EnumeratedTerm] = {}
    by_cost: dict[int, list[TypedBvTerm]] = {0: []}
    generated = 0
    for candidate in terminals:
        if generated >= budget.max_generated_terms:
            return tuple(sorted(records.values(), key=lambda item: (item.cost, item.fingerprint))), MbaExhaustionReceipt("generation_budget", generated, budget)
        candidate = _canonical_candidate(candidate)
        fingerprint = term_fingerprint(candidate)
        if fingerprint in records:
            continue
        record = EnumeratedTerm(candidate, term_cost(candidate), fingerprint, _signature(candidate, witness_rows))
        records[fingerprint] = record
        by_cost.setdefault(0, []).append(candidate)
        generated += 1
        if on_candidate is not None and on_candidate(record):
            result = tuple(sorted(records.values(), key=lambda item: (item.cost, item.fingerprint)))
            return result, MbaExhaustionReceipt("not_cheaper", generated, budget)
    max_nodes = budget.max_candidate_operator_nodes
    for cost in range(1, max_nodes + 1):
        level: list[TypedBvTerm] = []
        remaining = budget.max_generated_terms - generated
        if remaining <= 0:
            result = tuple(sorted(records.values(), key=lambda item: (item.cost, item.fingerprint)))
            return result, MbaExhaustionReceipt("generation_budget", generated, budget)
        for unary in _SYNTHESIZED_UNARY:
            for child_cost in range(cost):
                for child in by_cost.get(child_cost, ()):
                    candidate = _canonical_candidate(TypedBvTerm(unary, source.width, children=(child,)))
                    if term_cost(candidate)[0] != cost:
                        continue
                    level.append(candidate)
                    if len(level) >= remaining:
                        break
                if len(level) >= remaining:
                    break
            if len(level) >= remaining:
                break
        if len(level) < remaining:
            for operation in _SYNTHESIZED_BINARY:
                for left_cost in range(cost):
                    right_cost = cost - left_cost - 1
                    if right_cost < 0:
                        continue
                    for left in by_cost.get(left_cost, ()):
                        for right in by_cost.get(right_cost, ()):
                            candidate = _canonical_candidate(TypedBvTerm(operation, source.width, children=(left, right)))
                            if term_cost(candidate)[0] != cost:
                                continue
                            level.append(candidate)
                            if len(level) >= remaining:
                                break
                        if len(level) >= remaining:
                            break
                    if len(level) >= remaining:
                        break
                if len(level) >= remaining:
                    break
        for candidate in sorted(level, key=term_fingerprint):
            if generated >= budget.max_generated_terms:
                result = tuple(sorted(records.values(), key=lambda item: (item.cost, item.fingerprint)))
                return result, MbaExhaustionReceipt("generation_budget", generated, budget)
            fingerprint = term_fingerprint(candidate)
            if fingerprint in records:
                continue
            if len(_leaf_keys(candidate)) > budget.max_variables:
                continue
            record = EnumeratedTerm(candidate, term_cost(candidate), fingerprint, _signature(candidate, witness_rows))
            records[fingerprint] = record
            level_for_cost = by_cost.setdefault(cost, [])
            level_for_cost.append(candidate)
            generated += 1
            if on_candidate is not None and on_candidate(record):
                result = tuple(sorted(records.values(), key=lambda item: (item.cost, item.fingerprint)))
                return result, MbaExhaustionReceipt("not_cheaper", generated, budget)
        if level and cost not in by_cost:
            by_cost[cost] = []
    result = tuple(sorted(records.values(), key=lambda item: (item.cost, item.fingerprint)))
    return result, MbaExhaustionReceipt("not_cheaper", generated, budget)


def _to_symbolic(term: TypedBvTerm) -> tuple[SymbolicExpression, tuple[tuple[object, ...], ...]]:
    keys = _leaf_keys(term)
    names = {key: f"x_{index}" for index, key in enumerate(keys)}
    def convert(node: TypedBvTerm) -> SymbolicExpression:
        if node.operation is None:
            if node.value is not None:
                return Const(f"const_{node.value}", node.value)
            assert node.leaf_key is not None
            return Var(names[node.leaf_key])
        children = tuple(convert(child) for child in node.children)
        if node.operation == "bnot":
            return ~children[0]
        if node.operation == "neg":
            return -children[0]
        left, right = children[0], children[1] if len(children) > 1 else None
        if node.operation == "add":
            return left + right
        if node.operation == "sub":
            return left - right
        if node.operation == "mul":
            return left * right
        if node.operation == "and":
            return left & right
        if node.operation == "or":
            return left | right
        if node.operation == "xor":
            return left ^ right
        raise ValueError("fixed shifts are not supported by symbolic proposal rendering")
    return convert(term), keys


def generalize_terms(pattern: TypedBvTerm, replacement: TypedBvTerm) -> tuple[SymbolicExpression, SymbolicExpression]:
    if pattern.width != replacement.width:
        raise ValueError("generalized terms must have matching widths")
    pattern_expr, keys = _to_symbolic(pattern)
    replacement_expr, replacement_keys = _to_symbolic(replacement)
    if keys != replacement_keys:
        raise ValueError("replacement introduces or loses generalized leaves")
    return pattern_expr, replacement_expr


def certify_terms(
    pattern: TypedBvTerm,
    replacement: TypedBvTerm,
    *,
    verifier: Callable[..., tuple[bool, Mapping[str, int] | None]] | None = None,
) -> MbaCertification:
    if pattern.width != replacement.width:
        return MbaCertification(())
    pattern_expr, replacement_expr = generalize_terms(pattern, replacement)
    verify = verify_transformation if verifier is None else verifier
    receipts: list[ProofReceipt] = []
    for width in CERTIFICATION_WIDTHS:
        started = time.monotonic()
        try:
            verdict, counterexample = verify(
                pattern_expr,
                replacement_expr,
                options=VerificationOptions(bit_width=width, timeout_ms=5_000),
            )
            elapsed = (time.monotonic() - started) * 1000.0
            receipts.append(ProofReceipt(width, verdict is True and counterexample is None, elapsed, counterexample))
        except Exception as exc:
            elapsed = (time.monotonic() - started) * 1000.0
            receipts.append(ProofReceipt(width, False, elapsed, None, f"{type(exc).__name__}: {exc}"))
    return MbaCertification(tuple(receipts))


def synthesize_residual(
    atomized: AtomizedMbaTerm,
    *,
    budget: MbaSynthesisBudget | None = None,
) -> MbaSynthesisResult:
    budget = MbaSynthesisBudget() if budget is None else budget
    source = atomized.atomized_term
    source_cost = term_cost(source)
    witnesses = deterministic_witnesses(source, count=budget.witness_count)
    source_signature = _signature(source, witnesses)
    had_signature = False
    had_proof_failure = False
    certified_candidate: list[tuple[EnumeratedTerm, MbaCertification]] = []

    def inspect(candidate: EnumeratedTerm) -> bool:
        nonlocal had_signature, had_proof_failure
        if candidate.cost >= source_cost or candidate.signature != source_signature:
            return False
        had_signature = True
        certification = certify_terms(source, candidate.term)
        if certification.certified:
            certified_candidate.append((candidate, certification))
            return True
        had_proof_failure = True
        return False

    terms, receipt = enumerate_terms(
        source, budget=budget, witnesses=witnesses, on_candidate=inspect
    )
    if certified_candidate:
        candidate, certification = certified_candidate[0]
        return MbaSynthesisResult(source, candidate.term, source_cost, candidate.cost, certification, receipt)
    for candidate in terms:
        if candidate.cost >= source_cost:
            continue
        if candidate.signature != source_signature:
            continue
        had_signature = True
        certification = certify_terms(source, candidate.term)
        if certification.certified:
            return MbaSynthesisResult(source, candidate.term, source_cost, candidate.cost, certification, receipt)
        had_proof_failure = True
    reason = "proof_failed" if had_proof_failure else "no_signature_match" if not had_signature else "not_cheaper"
    return MbaSynthesisResult(source, None, source_cost, None, MbaCertification(()), MbaExhaustionReceipt(reason, receipt.generated_terms, budget))


__all__ = [
    "CERTIFICATION_WIDTHS",
    "EnumeratedTerm",
    "MbaCertification",
    "MbaExhaustionReceipt",
    "MbaSynthesisBudget",
    "MbaSynthesisResult",
    "ProofReceipt",
    "_evaluate_term",
    "certify_terms",
    "deterministic_witnesses",
    "enumerate_terms",
    "generalize_terms",
    "synthesize_residual",
]
