"""Bounded, deterministic discovery of small portable MBA identities.

This module is deliberately split into a cheap discovery phase and an exact
certification phase.  The evaluator and witness signatures are filters only;
the existing verification engine remains the authority for equivalence.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from d810.mba.dsl import Const, SymbolicExpression, Var
from d810.mba.subterm_atomization import AtomizedMbaTerm
from d810.mba.semantic_canonicalization import canonicalize_mba_term
from d810.mba.typed_term import (
    TypedBvTerm,
    canonicalize_ac_term,
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
    max_candidate_attempts: int = 100_000
    witness_count: int = 96

    def __post_init__(self) -> None:
        for field_name in (
            "max_atoms",
            "max_variables",
            "max_candidate_operator_nodes",
            "max_generated_terms",
            "max_candidate_attempts",
            "witness_count",
        ):
            value = getattr(self, field_name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        if self.witness_count == 0:
            raise ValueError("witness_count must be positive")


@dataclass(frozen=True, slots=True, order=True)
class GrammarAllOnesOrigin:
    """One exact occurrence of the grammar-injected all-ones terminal."""

    occurrence_path: tuple[int, ...]
    terminal_fingerprint: str
    source_width: int
    origin: str = "grammar_injected_all_ones"

    def __post_init__(self) -> None:
        if (
            type(self.occurrence_path) is not tuple
            or any(type(index) is not int or index < 0 for index in self.occurrence_path)
        ):
            raise TypeError("occurrence_path must contain non-negative integers")
        if type(self.terminal_fingerprint) is not str or not self.terminal_fingerprint:
            raise TypeError("terminal_fingerprint must be a non-empty string")
        if type(self.source_width) is not int or self.source_width <= 0:
            raise TypeError("source_width must be a positive integer")
        if self.origin != "grammar_injected_all_ones":
            raise ValueError("unsupported terminal origin")


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
class MbaDiscoveryReceipt:
    """Truthful completion evidence for one bounded discovery run."""

    budget: MbaSynthesisBudget
    candidate_attempts: int
    generated_terms: int
    retained_terms: int
    witness_identity: str
    selected_candidate_fingerprint: str
    selected_candidate_rank: int
    completion_reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.budget, MbaSynthesisBudget):
            raise TypeError("discovery budget must be an MbaSynthesisBudget")
        for field_name in ("candidate_attempts", "generated_terms", "retained_terms", "selected_candidate_rank"):
            value = getattr(self, field_name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        if self.retained_terms > self.generated_terms:
            raise ValueError("retained_terms cannot exceed generated_terms")
        if self.selected_candidate_rank >= self.retained_terms:
            raise ValueError("selected candidate rank is outside retained terms")
        for field_name in ("witness_identity", "selected_candidate_fingerprint"):
            value = getattr(self, field_name)
            if type(value) is not str or not value:
                raise ValueError(f"{field_name} must be a non-empty string")
        if self.completion_reason != "certified_candidate":
            raise ValueError("unsupported discovery completion reason")


@dataclass(frozen=True, slots=True)
class EnumeratedTerm:
    term: TypedBvTerm
    cost: tuple[int, int]
    fingerprint: str
    signature: tuple[int, ...]
    novel_constant_count: int = 0
    width_relative_all_ones: tuple[GrammarAllOnesOrigin, ...] = ()


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
        if self.error is not None and (type(self.error) is not str or not self.error):
            raise ValueError("proof error must be a non-empty string or None")
        if self.counterexample is not None:
            if not isinstance(self.counterexample, Mapping):
                raise TypeError("counterexample must be a mapping")
            frozen: dict[str, int] = {}
            for key, value in self.counterexample.items():
                if type(key) is not str or not key or type(value) is not int:
                    raise TypeError("counterexample keys and values have exact types")
                frozen[key] = value
            object.__setattr__(self, "counterexample", MappingProxyType(dict(sorted(frozen.items()))))

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
    exhaustion: MbaExhaustionReceipt | None
    width_relative_all_ones: tuple[GrammarAllOnesOrigin, ...] = ()
    fixed_operation_descriptors: tuple[tuple[str, int, int], ...] = ()
    discovery_receipt: MbaDiscoveryReceipt | None = None

    def __post_init__(self) -> None:
        if self.source_cost != term_cost(self.source):
            raise ValueError("source_cost does not match source")
        if self.discovery_receipt is not None and not isinstance(
            self.discovery_receipt, MbaDiscoveryReceipt
        ):
            raise TypeError("discovery_receipt must be an MbaDiscoveryReceipt or None")
        if self.replacement is None:
            if self.replacement_cost is not None:
                raise ValueError("replacement_cost requires a replacement")
            if self.width_relative_all_ones or self.fixed_operation_descriptors:
                raise ValueError("failed synthesis cannot retain candidate descriptors")
            if self.discovery_receipt is not None:
                raise ValueError("discovery_receipt requires a replacement")
            return
        if (
            self.discovery_receipt is not None
            and self.discovery_receipt.selected_candidate_fingerprint
            != term_fingerprint(self.replacement)
        ):
            raise ValueError("discovery receipt does not identify the replacement")
        if self.replacement_cost != term_cost(self.replacement):
            raise ValueError("replacement_cost does not match replacement")
        validated_origins = _validate_all_ones_origins(
            self.source,
            self.replacement,
            self.width_relative_all_ones,
        )
        object.__setattr__(self, "width_relative_all_ones", validated_origins)
        expected_fixed = _fixed_operation_descriptors(self.source, self.replacement)
        if self.fixed_operation_descriptors != expected_fixed:
            raise ValueError("fixed operation descriptors do not match result terms")

    @property
    def certified(self) -> bool:
        return self.certification.certified and self.replacement is not None

    @property
    def proof_receipts(self) -> tuple[ProofReceipt, ...]:
        return self.certification.receipts


def _mask(width: int) -> int:
    return (1 << width) - 1


def _walk_term_paths(
    term: TypedBvTerm,
    path: tuple[int, ...] = (),
) -> Iterable[tuple[tuple[int, ...], TypedBvTerm]]:
    yield path, term
    for index, child in enumerate(term.children):
        yield from _walk_term_paths(child, path + (index,))


def grammar_all_ones_origins(
    term: TypedBvTerm,
) -> tuple[GrammarAllOnesOrigin, ...]:
    """Describe known grammar-origin mask occurrences without guessing origin."""

    mask = _mask(term.width)
    return tuple(
        GrammarAllOnesOrigin(path, term_fingerprint(node), term.width)
        for path, node in _walk_term_paths(term)
        if node.operation is None and node.value == mask
    )


def _term_at_path(term: TypedBvTerm, path: tuple[int, ...]) -> TypedBvTerm:
    current = term
    for index in path:
        try:
            current = current.children[index]
        except IndexError as exc:
            raise ValueError("all-ones origin path is outside the replacement") from exc
    return current


def _validate_all_ones_origins(
    source: TypedBvTerm,
    replacement: TypedBvTerm,
    origins: Iterable[GrammarAllOnesOrigin],
) -> tuple[GrammarAllOnesOrigin, ...]:
    frozen = tuple(origins)
    if any(not isinstance(origin, GrammarAllOnesOrigin) for origin in frozen):
        raise TypeError("width-relative all-ones origins have invalid types")
    if frozen != tuple(sorted(set(frozen))):
        raise ValueError("width-relative all-ones origins must be unique and ordered")
    input_mask_fingerprints = {
        term_fingerprint(node)
        for _path, node in _walk_term_paths(source)
        if node.operation is None and node.value == _mask(source.width)
    }
    for origin in frozen:
        if origin.source_width != source.width:
            raise ValueError("all-ones origin width does not match the source")
        target = _term_at_path(replacement, origin.occurrence_path)
        if (
            target.operation is not None
            or target.value != _mask(source.width)
            or term_fingerprint(target) != origin.terminal_fingerprint
        ):
            raise ValueError("all-ones origin does not identify a mask terminal")
        if origin.terminal_fingerprint in input_mask_fingerprints:
            raise ValueError("input-provided all-ones terminal cannot gain grammar origin")
    return frozen


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
    alternating_a = int.from_bytes(bytes((0xAA,)) * ((width + 7) // 8), "big") & mask
    alternating_b = int.from_bytes(bytes((0x55,)) * ((width + 7) // 8), "big") & mask
    rows: list[dict[tuple[object, ...], int]] = []
    for value in (0, mask, alternating_a, alternating_b):
        rows.append({key: value for key in keys})
    for bit in range(width):
        rows.append({key: 1 << bit for key in keys})
        if len(rows) >= count:
            break
    # Use the remaining rows for per-variable perturbations.  The shared
    # power rows above deliberately guarantee every bit for every variable.
    for key_index, key in enumerate(keys):
        for bit in range(width):
            row = {other: 0 for other in keys}
            row[key] = 1 << bit
            rows.append(row)
            if len(rows) >= count:
                break
        if len(rows) >= count:
            break
    witnesses: list[dict[tuple[object, ...], int]] = []
    for index in range(count):
        if index < len(rows):
            witnesses.append(rows[index])
            continue
        row = {}
        for key_index, key in enumerate(keys):
            digest = hashlib.sha256(seed + index.to_bytes(4, "big") + key_index.to_bytes(2, "big")).digest()
            row[key] = int.from_bytes(digest, "big") & mask
        witnesses.append(row)
    return tuple(witnesses)


def _validate_witnesses(
    witnesses: tuple[Mapping[tuple[object, ...], int], ...],
    *,
    keys: tuple[tuple[object, ...], ...],
    width: int,
    budget: MbaSynthesisBudget,
) -> tuple[Mapping[tuple[object, ...], int], ...]:
    if type(witnesses) is not tuple or len(witnesses) != budget.witness_count:
        raise ValueError("witnesses must be a tuple with exactly budget.witness_count rows")
    expected = set(keys)
    mask = _mask(width)
    checked: list[Mapping[tuple[object, ...], int]] = []
    for row in witnesses:
        if not isinstance(row, Mapping) or set(row) != expected:
            raise ValueError("each witness row must contain exactly the term leaf keys")
        normalized: dict[tuple[object, ...], int] = {}
        for key, value in row.items():
            if type(key) is not tuple or type(value) is not int or isinstance(value, bool):
                raise TypeError("witness keys and values have exact types")
            if not 0 <= value <= mask:
                raise ValueError("witness values must fit the term width")
            normalized[key] = value
        checked.append(normalized)
    return tuple(checked)


def _signature(term: TypedBvTerm, witnesses: tuple[Mapping[tuple[object, ...], int], ...]) -> tuple[int, ...]:
    return tuple(_evaluate_term(term, witness) for witness in witnesses)


def _witness_identity(
    witnesses: tuple[Mapping[tuple[object, ...], int], ...],
) -> str:
    payload = [
        [
            [list(leaf_key_fingerprint(key)), value]
            for key, value in sorted(row.items(), key=lambda item: leaf_key_fingerprint(item[0]))
        ]
        for row in witnesses
    ]
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


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
    # AC normalization is the hot-path discovery deduplicator.  The semantic
    # canonicalizer is still applied to the small candidate frontier where its
    # local rewrites can change cost; large generated trees are already bounded
    # and do not need repeated fixed-point tracing during enumeration.
    candidate = canonicalize_ac_term(term)
    if term_cost(candidate)[0] <= 2:
        return canonicalize_mba_term(candidate).canonical_term
    return candidate


def enumerate_terms(
    term_or_terminals: TypedBvTerm | Iterable[TypedBvTerm],
    *,
    budget: MbaSynthesisBudget | None = None,
    witnesses: tuple[Mapping[tuple[object, ...], int], ...] | None = None,
    on_candidate: Callable[[EnumeratedTerm], bool] | None = None,
    attempt_counter: dict[str, int] | None = None,
) -> tuple[tuple[EnumeratedTerm, ...], MbaExhaustionReceipt | None]:
    budget = MbaSynthesisBudget() if budget is None else budget
    candidate_attempts = 0

    class _CandidateAttemptLimit(Exception):
        pass

    def canonicalize_with_budget(term: TypedBvTerm) -> TypedBvTerm:
        nonlocal candidate_attempts
        if candidate_attempts >= budget.max_candidate_attempts:
            raise _CandidateAttemptLimit
        candidate_attempts += 1
        if attempt_counter is not None:
            attempt_counter["candidate_attempts"] = candidate_attempts
        return _canonical_candidate(term)

    if isinstance(term_or_terminals, TypedBvTerm):
        source = term_or_terminals
        input_constant_fps = {
            term_fingerprint(node)
            for node in _walk_terms(source)
            if node.operation is None and node.value is not None
        }
        terminal_candidates = _input_terminals(source)
    else:
        raw_terminals = tuple(term_or_terminals)
        if not raw_terminals or any(not isinstance(item, TypedBvTerm) for item in raw_terminals):
            raise TypeError("terminals must contain TypedBvTerm values")
        if any(item.operation is not None for item in raw_terminals):
            raise ValueError("iterable inputs must contain terminal terms")
        source = raw_terminals[0]
        input_constant_fps = {
            term_fingerprint(item) for item in raw_terminals if item.value is not None
        }
        dedup: dict[str, TypedBvTerm] = {}
        try:
            for item in raw_terminals:
                normalized = canonicalize_with_budget(item)
                dedup.setdefault(term_fingerprint(normalized), normalized)
        except _CandidateAttemptLimit:
            return (), MbaExhaustionReceipt("generation_budget", 0, budget)
        width = source.width
        for value in (0, 1, 2, _mask(width)):
            injected = TypedBvTerm(None, width, value=value)
            dedup.setdefault(term_fingerprint(injected), injected)
        terminal_candidates = tuple(sorted(dedup.values(), key=term_fingerprint))
    if any(item.width != source.width for item in terminal_candidates):
        raise ValueError("all terminals must have one width")
    all_key_set: set[tuple[object, ...]] = set()
    for terminal in terminal_candidates:
        all_key_set.update(_leaf_keys(terminal))
    keys = tuple(sorted(all_key_set, key=leaf_key_fingerprint))
    atom_count = sum(1 for key in keys if key and key[0] == "d810.mba.atom.v1")
    if len(keys) > budget.max_variables or atom_count > budget.max_atoms:
        return (), MbaExhaustionReceipt("too_many_variables", 0, budget)
    if witnesses is None:
        witness_seed = terminal_candidates[0]
        for terminal in terminal_candidates[1:]:
            witness_seed = TypedBvTerm("add", source.width, children=(witness_seed, terminal))
        witness_rows = deterministic_witnesses(witness_seed, count=budget.witness_count)
    else:
        witness_rows = _validate_witnesses(witnesses, keys=keys, width=source.width, budget=budget)
    records: dict[str, EnumeratedTerm] = {}
    by_cost: dict[int, list[TypedBvTerm]] = {0: []}
    generated = 0
    saw_unvisited = False

    grammar_mask_fingerprint = term_fingerprint(
        TypedBvTerm(None, source.width, value=_mask(source.width))
    )
    grammar_all_ones_available = grammar_mask_fingerprint not in input_constant_fps

    def make_record(candidate: TypedBvTerm) -> EnumeratedTerm:
        candidate_cost = term_cost(candidate)
        novel_fingerprints = {
            term_fingerprint(node)
            for node in _walk_terms(candidate)
            if node.operation is None
            and node.value is not None
            and term_fingerprint(node) not in input_constant_fps
        }
        origins = (
            grammar_all_ones_origins(candidate)
            if grammar_all_ones_available
            else ()
        )
        return EnumeratedTerm(
            candidate,
            candidate_cost,
            term_fingerprint(candidate),
            _signature(candidate, witness_rows),
            len(novel_fingerprints),
            origins,
        )

    def order_key(item: EnumeratedTerm) -> tuple[object, ...]:
        return (item.cost, item.novel_constant_count, item.fingerprint)

    terminal_frontier = sorted(
        (make_record(candidate) for candidate in terminal_candidates),
        key=order_key,
    )
    for record in terminal_frontier:
        if generated >= budget.max_generated_terms:
            saw_unvisited = True
            break
        records[record.fingerprint] = record
        by_cost[0].append(record.term)
        generated += 1
        if attempt_counter is not None:
            attempt_counter["generated_terms"] = generated
        if on_candidate is not None and on_candidate(record):
            result = tuple(sorted(records.values(), key=order_key))
            return result, None
    max_nodes = budget.max_candidate_operator_nodes
    for cost in range(1, max_nodes + 1):
        level: dict[str, TypedBvTerm] = {}
        remaining = budget.max_generated_terms - generated
        if remaining <= 0:
            saw_unvisited = True
            break
        def add_frontier(candidate: TypedBvTerm) -> None:
            if term_cost(candidate)[0] != cost or len(_leaf_keys(candidate)) > budget.max_variables:
                return
            fingerprint = term_fingerprint(candidate)
            if any(fingerprint == term_fingerprint(item) for item in by_cost.get(cost, ())):
                return
            level.setdefault(fingerprint, candidate)
        try:
            for unary in _SYNTHESIZED_UNARY:
                for child_cost in range(cost):
                    for child in by_cost.get(child_cost, ()):
                        candidate = canonicalize_with_budget(TypedBvTerm(unary, source.width, children=(child,)))
                        add_frontier(candidate)
            for operation in _SYNTHESIZED_BINARY:
                for left_cost in range(cost):
                    right_cost = cost - left_cost - 1
                    if right_cost < 0:
                        continue
                    for left in by_cost.get(left_cost, ()):
                        for right in by_cost.get(right_cost, ()):
                            candidate = canonicalize_with_budget(TypedBvTerm(operation, source.width, children=(left, right)))
                            add_frontier(candidate)
        except _CandidateAttemptLimit:
            saw_unvisited = True
            break
        frontier = sorted((make_record(candidate) for candidate in level.values()), key=order_key)
        # by_cost is the complete frontier, not merely the budget prefix. This
        # makes the consumed records an exact prefix of the uncapped order.
        by_cost[cost] = [record.term for record in frontier]
        for record in frontier:
            if generated >= budget.max_generated_terms:
                saw_unvisited = True
                break
            candidate = record.term
            fingerprint = record.fingerprint
            if fingerprint in records:
                continue
            records[fingerprint] = record
            generated += 1
            if attempt_counter is not None:
                attempt_counter["generated_terms"] = generated
            if on_candidate is not None:
                if on_candidate(record):
                    result = tuple(sorted(records.values(), key=order_key))
                    return result, None
        if saw_unvisited:
            break
    result = tuple(sorted(records.values(), key=order_key))
    reason = "generation_budget" if saw_unvisited else "not_cheaper"
    return result, MbaExhaustionReceipt(reason, generated, budget)


def _walk_terms(term: TypedBvTerm) -> Iterable[TypedBvTerm]:
    yield term
    for child in term.children:
        yield from _walk_terms(child)


def _fixed_operation_descriptors(
    *terms: TypedBvTerm,
) -> tuple[tuple[str, int, int], ...]:
    descriptors = {
        (node.operation, node.shift_count, node.width)
        for term in terms
        for node in _walk_terms(term)
        if node.operation in {"shl", "lshr", "rol", "ror"}
    }
    return tuple(sorted(descriptors))  # type: ignore[arg-type]


def _to_symbolic(
    term: TypedBvTerm,
    *,
    width: int,
    names: Mapping[tuple[object, ...], str],
    width_relative_all_ones_paths: frozenset[tuple[int, ...]] = frozenset(),
) -> SymbolicExpression:
    def convert(
        node: TypedBvTerm,
        path: tuple[int, ...],
    ) -> SymbolicExpression:
        if node.operation is None:
            if node.value is not None:
                value = _mask(width) if path in width_relative_all_ones_paths else node.value
                return Const(f"const_{value}", value)
            assert node.leaf_key is not None
            return Var(names[node.leaf_key])
        children = tuple(
            convert(child, path + (index,))
            for index, child in enumerate(node.children)
        )
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
        if node.operation in {"shl", "lshr"}:
            count = Const(f"shift_{node.shift_count}", node.shift_count)
            return children[0] << count if node.operation == "shl" else children[0] >> count
        if node.operation in {"rol", "ror"}:
            count = node.shift_count % width
            if count == 0:
                return children[0]
            if node.operation == "rol":
                left = children[0] << Const(f"shift_{count}", count)
                right = children[0] >> Const(f"shift_{width - count}", width - count)
            else:
                left = children[0] >> Const(f"shift_{count}", count)
                right = children[0] << Const(f"shift_{width - count}", width - count)
            return left | right
        raise ValueError(f"unsupported symbolic operation: {node.operation}")
    return convert(term, ())


def generalize_terms(
    pattern: TypedBvTerm,
    replacement: TypedBvTerm,
    *,
    width: int | None = None,
    width_relative_all_ones: Iterable[GrammarAllOnesOrigin] = (),
) -> tuple[SymbolicExpression, SymbolicExpression]:
    if pattern.width != replacement.width:
        raise ValueError("generalized terms must have matching widths")
    target_width = pattern.width if width is None else width
    if type(target_width) is not int or target_width <= 0:
        raise ValueError("width must be a positive integer")
    keys = _leaf_keys(pattern)
    names = {key: f"x_{index}" for index, key in enumerate(keys)}
    replacement_keys = _leaf_keys(replacement)
    if not set(replacement_keys).issubset(set(keys)):
        raise ValueError("replacement introduces an unknown generalized leaf")
    origins = _validate_all_ones_origins(pattern, replacement, width_relative_all_ones)
    replacement_paths = frozenset(origin.occurrence_path for origin in origins)
    return (
        _to_symbolic(pattern, width=target_width, names=names),
        _to_symbolic(
            replacement,
            width=target_width,
            names=names,
            width_relative_all_ones_paths=replacement_paths,
        ),
    )


def certify_terms(
    pattern: TypedBvTerm,
    replacement: TypedBvTerm,
    *,
    verifier: Callable[..., tuple[bool, Mapping[str, int] | None]] | None = None,
    width_relative_all_ones: Iterable[GrammarAllOnesOrigin] = (),
) -> MbaCertification:
    verify = verify_transformation if verifier is None else verifier
    origins = tuple(width_relative_all_ones)
    receipts: list[ProofReceipt] = []
    for width in CERTIFICATION_WIDTHS:
        started = time.monotonic()
        try:
            pattern_expr, replacement_expr = generalize_terms(
                pattern,
                replacement,
                width=width,
                width_relative_all_ones=origins,
            )
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
    if source.operation is None:
        source_keys = _leaf_keys(source)
        source_atoms = sum(
            1
            for key in source_keys
            if key and key[0] == "d810.mba.atom.v1"
        )
        if len(source_keys) > budget.max_variables or source_atoms > budget.max_atoms:
            return MbaSynthesisResult(
                source,
                None,
                source_cost,
                None,
                MbaCertification(()),
                MbaExhaustionReceipt("too_many_variables", 0, budget),
            )
        if budget.max_generated_terms == 0 or budget.max_candidate_attempts == 0:
            return MbaSynthesisResult(
                source,
                None,
                source_cost,
                None,
                MbaCertification(()),
                MbaExhaustionReceipt("generation_budget", 0, budget),
            )
        return MbaSynthesisResult(
            source,
            None,
            source_cost,
            None,
            MbaCertification(()),
            MbaExhaustionReceipt("not_cheaper", 1, budget),
        )
    witnesses = deterministic_witnesses(source, count=budget.witness_count)
    source_signature = _signature(source, witnesses)
    had_signature = False
    had_noncheaper_signature = False
    had_proof_failure = False
    failed_certification = MbaCertification(())
    certified_candidate: list[tuple[EnumeratedTerm, MbaCertification]] = []

    def inspect(candidate: EnumeratedTerm) -> bool:
        nonlocal had_signature, had_noncheaper_signature, had_proof_failure, failed_certification
        if candidate.signature != source_signature:
            return False
        had_signature = True
        if candidate.cost >= source_cost:
            had_noncheaper_signature = True
            return False
        certification = certify_terms(
            source,
            candidate.term,
            width_relative_all_ones=candidate.width_relative_all_ones,
        )
        if certification.certified:
            certified_candidate.append((candidate, certification))
            return True
        had_proof_failure = True
        failed_certification = certification
        return False

    attempt_counter: dict[str, int] = {}
    enumerated, receipt = enumerate_terms(
        source,
        budget=budget,
        witnesses=witnesses,
        on_candidate=inspect,
        attempt_counter=attempt_counter,
    )
    if certified_candidate:
        candidate, certification = certified_candidate[0]
        selected_rank = next(
            index
            for index, item in enumerate(enumerated)
            if item.fingerprint == candidate.fingerprint
        )
        discovery = MbaDiscoveryReceipt(
            budget=budget,
            candidate_attempts=attempt_counter.get("candidate_attempts", 0),
            generated_terms=attempt_counter.get("generated_terms", len(enumerated)),
            retained_terms=len(enumerated),
            witness_identity=_witness_identity(witnesses),
            selected_candidate_fingerprint=candidate.fingerprint,
            selected_candidate_rank=selected_rank,
            completion_reason="certified_candidate",
        )
        return MbaSynthesisResult(
            source,
            candidate.term,
            source_cost,
            candidate.cost,
            certification,
            None,
            candidate.width_relative_all_ones,
            _fixed_operation_descriptors(source, candidate.term),
            discovery,
        )
    reason = (
        "proof_failed"
        if had_proof_failure
        else "not_cheaper"
        if had_noncheaper_signature
        else "no_signature_match"
    )
    if receipt is not None and receipt.reason in {"too_many_variables", "generation_budget"}:
        final_reason = receipt.reason
    else:
        final_reason = reason
    certification = failed_certification if failed_certification.receipts else MbaCertification(())
    return MbaSynthesisResult(source, None, source_cost, None, certification, MbaExhaustionReceipt(final_reason, receipt.generated_terms, budget))


__all__ = [
    "CERTIFICATION_WIDTHS",
    "EnumeratedTerm",
    "GrammarAllOnesOrigin",
    "MbaCertification",
    "MbaDiscoveryReceipt",
    "MbaExhaustionReceipt",
    "MbaSynthesisBudget",
    "MbaSynthesisResult",
    "ProofReceipt",
    "_evaluate_term",
    "certify_terms",
    "deterministic_witnesses",
    "enumerate_terms",
    "generalize_terms",
    "grammar_all_ones_origins",
    "synthesize_residual",
]
