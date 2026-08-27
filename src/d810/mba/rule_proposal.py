"""Reviewable proposal objects and deterministic source rendering."""

from __future__ import annotations

import hashlib
import json
import keyword
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from d810.mba.bounded_synthesis import (
    CERTIFICATION_WIDTHS,
    GrammarAllOnesOrigin,
    MbaSynthesisResult,
    ProofReceipt,
)
from d810.mba.subterm_atomization import MbaAtomBinding
from d810.mba.term_codec import typed_term_to_dict
from d810.mba.typed_term import TypedBvTerm, leaf_key_fingerprint, term_cost, term_fingerprint


def _freeze_json(value: object) -> object:
    if value is None or type(value) in {bool, int, str}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("fixture values must be finite JSON values")
        return value
    if isinstance(value, Mapping):
        frozen = {}
        for key in sorted(value):
            if type(key) is not str:
                raise TypeError("fixture mapping keys must be strings")
            frozen[key] = _freeze_json(value[key])
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    raise TypeError("fixture must contain only JSON-safe values")


def _json_ready(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    return value


def _keys(term: TypedBvTerm) -> tuple[tuple[object, ...], ...]:
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


def _walk(term: TypedBvTerm):
    yield term
    for child in term.children:
        yield from _walk(child)


def _binding_dict(binding: MbaAtomBinding) -> dict[str, object]:
    return {
        "leaf_key": _json_ready(binding.leaf_key),
        "original_subterm": typed_term_to_dict(binding.original_subterm),
        "occurrence_count": binding.occurrence_count,
        "saved_operator_nodes": binding.saved_operator_nodes,
    }


def _proof_dict(receipt: ProofReceipt) -> dict[str, object]:
    return {
        "width": receipt.width,
        "verdict": receipt.verdict,
        "elapsed_ms": receipt.elapsed_ms,
        "counterexample": _json_ready(receipt.counterexample),
        "error": receipt.error,
    }


def _proof_identity_dict(receipt: ProofReceipt) -> dict[str, object]:
    """Return only stable proof facts for proposal identity."""
    return {
        "width": receipt.width,
        "verdict": receipt.verdict,
        "counterexample": _json_ready(receipt.counterexample),
        "error": receipt.error,
    }


def _origin_dict(origin: GrammarAllOnesOrigin) -> dict[str, object]:
    if not isinstance(origin, GrammarAllOnesOrigin):
        raise TypeError("width-relative all-ones origin has an invalid type")
    return {
        "origin": origin.origin,
        "occurrence_path": list(origin.occurrence_path),
        "source_width": origin.source_width,
        "terminal_fingerprint": origin.terminal_fingerprint,
    }


def proposal_fingerprint(**fields: object) -> str:
    """Compute the versioned digest for proposal semantic/provenance fields."""
    synthesis_result = fields.get("synthesis_result")
    if synthesis_result is not None and not isinstance(
        synthesis_result, MbaSynthesisResult
    ):
        raise TypeError("synthesis_result must be an MbaSynthesisResult")
    origins = fields.get("width_relative_all_ones")
    if origins is None:
        origins = (
            synthesis_result.width_relative_all_ones
            if isinstance(synthesis_result, MbaSynthesisResult)
            else ()
        )
    fixed_descriptors = fields.get("fixed_operation_descriptors")
    if fixed_descriptors is None:
        fixed_descriptors = (
            synthesis_result.fixed_operation_descriptors
            if isinstance(synthesis_result, MbaSynthesisResult)
            else ()
        )
    payload = {
        "schema_version": 1,
        "source_fingerprints": tuple(sorted(set(fields["source_fingerprints"]))),
        "occurrence_count": fields["occurrence_count"],
        "pattern": term_fingerprint(fields["pattern"]),
        "replacement": term_fingerprint(fields["replacement"]),
        "source_cost": tuple(fields["source_cost"]),
        "replacement_cost": tuple(fields["replacement_cost"]),
        "atomization_bindings": tuple(_binding_dict(item) for item in fields["atomization_bindings"]),
        "proof_receipts": tuple(_proof_identity_dict(item) for item in fields["proof_receipts"]),
        "class_name": fields["class_name"],
        "family": fields["family"],
        "description": fields["description"],
        "provenance": tuple(sorted(set(fields["provenance"]))),
        "fixture": _json_ready(_freeze_json(fields["fixture"])),
        "width_relative_all_ones": tuple(
            _origin_dict(item)
            for item in origins
        ),
        "fixed_operation_descriptors": tuple(sorted(set(fixed_descriptors))),
    }
    encoded = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(("mba-rule-proposal-v1:" + encoded).encode("ascii")).hexdigest()


def _expr_source(
    term: TypedBvTerm,
    names: Mapping[tuple[object, ...], str],
    width_relative_all_ones_paths: frozenset[tuple[int, ...]] = frozenset(),
    path: tuple[int, ...] = (),
) -> str:
    if term.operation is None:
        if term.value is not None:
            if path in width_relative_all_ones_paths:
                return 'Const("NEGATIVE_ONE", -1)'
            return f'Const("const_{term.value}", {term.value})'
        assert term.leaf_key is not None
        return names[term.leaf_key]
    child = tuple(
        _expr_source(
            item,
            names,
            width_relative_all_ones_paths,
            path + (index,),
        )
        for index, item in enumerate(term.children)
    )
    if term.operation == "bnot":
        return f"~({child[0]})"
    if term.operation == "neg":
        return f"-({child[0]})"
    if term.operation in {"add", "sub", "mul", "and", "or", "xor"}:
        operator = {"add": "+", "sub": "-", "mul": "*", "and": "&", "or": "|", "xor": "^"}[term.operation]
        return f"({child[0]} {operator} {child[1]})"
    if term.operation in {"shl", "lshr"}:
        operator = "<<" if term.operation == "shl" else ">>"
        return f"({child[0]} {operator} Const(\"shift_{term.shift_count}\", {term.shift_count}))"
    if term.operation in {"rol", "ror"}:
        return f'FixedRotate("{term.operation}", {child[0]}, {term.shift_count})'
    raise ValueError(f"cannot render unsupported operation: {term.operation}")


@dataclass(frozen=True, slots=True)
class MbaRuleProposal:
    proposal_fingerprint: str | None
    source_fingerprints: tuple[str, ...]
    occurrence_count: int
    pattern: TypedBvTerm
    replacement: TypedBvTerm
    source_cost: tuple[int, int]
    replacement_cost: tuple[int, int]
    atomization_bindings: tuple[MbaAtomBinding, ...]
    proof_receipts: tuple[ProofReceipt, ...]
    class_name: str
    family: str
    description: str
    provenance: tuple[str, ...]
    fixture: Mapping[str, object]
    fixed_operation_descriptors: tuple[tuple[str, int, int], ...] = ()
    synthesis_result: MbaSynthesisResult | None = None
    width_relative_all_ones: tuple[GrammarAllOnesOrigin, ...] = field(
        init=False,
        default=(),
    )

    def __post_init__(self) -> None:
        if self.proposal_fingerprint is not None and (type(self.proposal_fingerprint) is not str or not self.proposal_fingerprint):
            raise ValueError("proposal_fingerprint must be a non-empty string or None")
        if type(self.occurrence_count) is not int or self.occurrence_count <= 0:
            raise ValueError("occurrence_count must be positive")
        if type(self.pattern) is not TypedBvTerm or type(self.replacement) is not TypedBvTerm:
            raise TypeError("pattern and replacement must be TypedBvTerm values")
        if self.pattern.width != self.replacement.width:
            raise ValueError("pattern and replacement widths must match")
        for name, cost, expected in (("source_cost", self.source_cost, term_cost(self.pattern)), ("replacement_cost", self.replacement_cost, term_cost(self.replacement))):
            if type(cost) is not tuple or len(cost) != 2 or any(type(item) is not int or isinstance(item, bool) or item < 0 for item in cost):
                raise TypeError(f"{name} must be a pair of exact non-negative integers")
            if cost != expected:
                raise ValueError(f"{name} does not match its term")
        if self.replacement_cost >= self.source_cost:
            raise ValueError("replacement must be strictly cheaper")
        if type(self.source_fingerprints) is not tuple or any(type(item) is not str for item in self.source_fingerprints):
            raise ValueError("source_fingerprints must contain non-empty strings")
        if type(self.provenance) is not tuple or any(type(item) is not str for item in self.provenance):
            raise ValueError("provenance must contain non-empty strings")
        sources = tuple(sorted(set(self.source_fingerprints)))
        provenance = tuple(sorted(set(self.provenance)))
        if not sources or any(not item for item in sources):
            raise ValueError("source_fingerprints must contain non-empty strings")
        if any(not item for item in provenance):
            raise ValueError("provenance must contain non-empty strings")
        object.__setattr__(self, "source_fingerprints", sources)
        object.__setattr__(self, "provenance", provenance)
        if not isinstance(self.atomization_bindings, tuple) or any(not isinstance(item, MbaAtomBinding) for item in self.atomization_bindings):
            raise TypeError("atomization_bindings must contain MbaAtomBinding values")
        if not isinstance(self.proof_receipts, tuple) or tuple(item.width for item in self.proof_receipts) != CERTIFICATION_WIDTHS:
            raise ValueError("proof receipts must cover exactly 8, 16, 32, and 64 bits")
        if any(not isinstance(item, ProofReceipt) or not item.certified for item in self.proof_receipts):
            raise ValueError("proposal requires four complete true proof receipts")
        if type(self.class_name) is not str or not self.class_name.isascii() or not self.class_name.isidentifier() or keyword.iskeyword(self.class_name) or self.class_name.startswith("_"):
            raise ValueError("class_name must be an ASCII non-keyword public identifier")
        if type(self.family) is not str or not self.family.isascii() or not self.family:
            raise ValueError("family must be a non-empty ASCII string")
        if type(self.description) is not str or not self.description:
            raise ValueError("description must be a non-empty string")
        frozen_fixture = _freeze_json(self.fixture)
        if not isinstance(frozen_fixture, Mapping):
            raise TypeError("fixture must be a mapping")
        object.__setattr__(self, "fixture", frozen_fixture)
        synthesis_result = self.synthesis_result
        replacement_has_source_mask = any(
            node.operation is None
            and node.value == (1 << self.replacement.width) - 1
            for node in _walk(self.replacement)
        )
        if synthesis_result is None and replacement_has_source_mask:
            raise ValueError(
                "all-ones replacement provenance requires a synthesis_result"
            )
        if synthesis_result is not None:
            if not isinstance(synthesis_result, MbaSynthesisResult):
                raise TypeError("synthesis_result must be an MbaSynthesisResult")
            if (
                not synthesis_result.certified
                or synthesis_result.source != self.pattern
                or synthesis_result.replacement != self.replacement
                or synthesis_result.source_cost != self.source_cost
                or synthesis_result.replacement_cost != self.replacement_cost
                or synthesis_result.proof_receipts != self.proof_receipts
            ):
                raise ValueError("synthesis_result does not match proposal semantics")
            origins = synthesis_result.width_relative_all_ones
            if self.fixed_operation_descriptors != synthesis_result.fixed_operation_descriptors:
                raise ValueError("synthesis_result fixed operation descriptors do not match")
        else:
            origins = ()
        object.__setattr__(self, "width_relative_all_ones", origins)
        if type(self.fixed_operation_descriptors) is not tuple:
            raise TypeError("fixed_operation_descriptors must be a tuple")
        for descriptor in self.fixed_operation_descriptors:
            if type(descriptor) is not tuple or len(descriptor) != 3:
                raise TypeError("fixed operation descriptors must be (operation, count, width)")
            operation, count, width = descriptor
            if (
                operation not in {"shl", "lshr", "rol", "ror"}
                or type(count) is not int
                or type(width) is not int
            ):
                raise TypeError("fixed operation descriptors have invalid types")
            if count < 0 or width <= 0 or count >= width:
                raise ValueError("fixed operation descriptor count is outside its width")
            if operation in {"rol", "ror"} and width not in {8, 16, 32, 64}:
                raise ValueError("rotate descriptor width is unsupported")
            if operation in {"rol", "ror"} and count >= min(CERTIFICATION_WIDTHS):
                raise ValueError(
                    "fixed rotate count must be below minimum proof width"
                )
        object.__setattr__(self, "fixed_operation_descriptors", tuple(sorted(set(self.fixed_operation_descriptors))))
        if not set(_keys(self.replacement)).issubset(set(_keys(self.pattern))):
            raise ValueError("replacement introduces an unknown generalized leaf")
        actual_fixed_descriptors = {
            (node.operation, node.shift_count, node.width)
            for term in (self.pattern, self.replacement)
            for node in _walk(term)
            if node.operation in {"shl", "lshr", "rol", "ror"}
        }
        if set(self.fixed_operation_descriptors) != actual_fixed_descriptors:
            raise ValueError("fixed operation metadata does not match the certified terms")
        expected = proposal_fingerprint(
            source_fingerprints=self.source_fingerprints, occurrence_count=self.occurrence_count,
            pattern=self.pattern, replacement=self.replacement, source_cost=self.source_cost,
            replacement_cost=self.replacement_cost, atomization_bindings=self.atomization_bindings,
            proof_receipts=self.proof_receipts, class_name=self.class_name, family=self.family,
            description=self.description, provenance=self.provenance, fixture=self.fixture,
            width_relative_all_ones=self.width_relative_all_ones,
            fixed_operation_descriptors=self.fixed_operation_descriptors,
        )
        if self.proposal_fingerprint is not None and self.proposal_fingerprint != expected:
            raise ValueError("proposal_fingerprint does not match canonical payload")
        object.__setattr__(self, "proposal_fingerprint", expected)

    @property
    def fingerprint(self) -> str:
        assert self.proposal_fingerprint is not None
        return self.proposal_fingerprint

    @property
    def certified(self) -> bool:
        return True

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "proposal_fingerprint": self.fingerprint,
            "source_fingerprints": list(self.source_fingerprints),
            "occurrence_count": self.occurrence_count,
            "pattern": typed_term_to_dict(self.pattern),
            "replacement": typed_term_to_dict(self.replacement),
            "source_cost": list(self.source_cost),
            "replacement_cost": list(self.replacement_cost),
            "atomization_bindings": [_binding_dict(item) for item in self.atomization_bindings],
            "proof_receipts": [_proof_dict(item) for item in self.proof_receipts],
            "class_name": self.class_name,
            "family": self.family,
            "description": self.description,
            "provenance": list(self.provenance),
            "fixture": _json_ready(self.fixture),
            "width_relative_all_ones": [
                _origin_dict(item) for item in self.width_relative_all_ones
            ],
            "fixed_operation_descriptors": [list(item) for item in self.fixed_operation_descriptors],
        }


def render_rule_source(proposal: MbaRuleProposal) -> str:
    keys = _keys(proposal.pattern)
    names = {key: f"x_{index}" for index, key in enumerate(keys)}
    lines = ['"""Proposed MBA rule; review and admit explicitly."""', "", "from d810.mba.dsl import Const, FixedRotate, Var", "from d810.mba.rules._base import VerifiableRule", ""]
    lines.extend(f'{name} = Var("{name}")' for name in names.values())
    if names:
        lines.append("")
    lines.extend([
        f"class {proposal.class_name}(VerifiableRule):",
        f"    DESCRIPTION = {json.dumps(proposal.description, ensure_ascii=True)}",
        f"    WIDTH_RELATIVE_ALL_ONES = {tuple(_origin_dict(item) for item in proposal.width_relative_all_ones)!r}",
        f"    FIXED_OPERATION_DESCRIPTORS = {proposal.fixed_operation_descriptors!r}",
        "    WIDTH_POLYMORPHIC_DESCRIPTORS = {",
        "        'all_ones': WIDTH_RELATIVE_ALL_ONES,",
        "        'fixed_operations': FIXED_OPERATION_DESCRIPTORS,",
        "    }",
        f"    PATTERN = {_expr_source(proposal.pattern, names)}",
        f"    REPLACEMENT = {_expr_source(proposal.replacement, names, frozenset(item.occurrence_path for item in proposal.width_relative_all_ones))}",
        "",
    ])
    source = "\n".join(lines)
    if not source.isascii():
        raise ValueError("proposal source must be ASCII-only")
    return source


__all__ = ["MbaRuleProposal", "proposal_fingerprint", "render_rule_source"]
