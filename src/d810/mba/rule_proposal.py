"""Reviewable proposal objects and deterministic source rendering."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass

from d810.mba.bounded_synthesis import CERTIFICATION_WIDTHS, ProofReceipt
from d810.mba.subterm_atomization import MbaAtomBinding
from d810.mba.typed_term import TypedBvTerm, leaf_key_fingerprint, term_cost, term_fingerprint


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


def _expr_source(term: TypedBvTerm, names: Mapping[tuple[object, ...], str]) -> str:
    if term.operation is None:
        if term.value is not None:
            return f'Const("const_{term.value}", {term.value})'
        assert term.leaf_key is not None
        return names[term.leaf_key]
    child = tuple(_expr_source(item, names) for item in term.children)
    if term.operation == "bnot":
        return f"~({child[0]})"
    if term.operation == "neg":
        return f"-({child[0]})"
    if term.operation in {"add", "sub", "mul", "and", "or", "xor"}:
        operator = {"add": "+", "sub": "-", "mul": "*", "and": "&", "or": "|", "xor": "^"}[term.operation]
        return f"({child[0]} {operator} {child[1]})"
    raise ValueError(f"cannot render unsupported operation: {term.operation}")


@dataclass(frozen=True, slots=True)
class MbaRuleProposal:
    proposal_fingerprint: str
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

    def __post_init__(self) -> None:
        if type(self.proposal_fingerprint) is not str or not self.proposal_fingerprint:
            raise ValueError("proposal_fingerprint must be a non-empty string")
        if not isinstance(self.source_fingerprints, tuple) or not self.source_fingerprints:
            raise ValueError("source_fingerprints must be non-empty")
        if any(type(item) is not str or not item for item in self.source_fingerprints):
            raise ValueError("source_fingerprints must contain non-empty strings")
        if type(self.occurrence_count) is not int or self.occurrence_count <= 0:
            raise ValueError("occurrence_count must be positive")
        if type(self.pattern) is not TypedBvTerm or type(self.replacement) is not TypedBvTerm:
            raise TypeError("pattern and replacement must be TypedBvTerm values")
        if self.pattern.width != self.replacement.width:
            raise ValueError("pattern and replacement widths must match")
        if self.source_cost != term_cost(self.pattern):
            raise ValueError("source_cost does not match pattern")
        if self.replacement_cost != term_cost(self.replacement):
            raise ValueError("replacement_cost does not match replacement")
        if self.replacement_cost >= self.source_cost:
            raise ValueError("replacement must be strictly cheaper")
        if not isinstance(self.atomization_bindings, tuple) or any(
            not isinstance(item, MbaAtomBinding) for item in self.atomization_bindings
        ):
            raise TypeError("atomization_bindings must contain MbaAtomBinding values")
        if not isinstance(self.proof_receipts, tuple):
            raise TypeError("proof_receipts must be a tuple")
        if tuple(item.width for item in self.proof_receipts) != CERTIFICATION_WIDTHS:
            raise ValueError("proof receipts must cover exactly 8, 16, 32, and 64 bits")
        if any(not isinstance(item, ProofReceipt) or not item.certified for item in self.proof_receipts):
            raise ValueError("proposal requires four complete true proof receipts")
        if type(self.class_name) is not str or not self.class_name.isidentifier() or self.class_name.startswith("_"):
            raise ValueError("class_name must be a public Python identifier")
        if type(self.family) is not str or not self.family:
            raise ValueError("family must be a non-empty string")
        if type(self.description) is not str or not self.description:
            raise ValueError("description must be a non-empty string")
        if not isinstance(self.provenance, tuple) or any(type(item) is not str for item in self.provenance):
            raise TypeError("provenance must be a tuple of strings")
        if not isinstance(self.fixture, Mapping):
            raise TypeError("fixture must be a mapping")
        if _keys(self.pattern) != _keys(self.replacement):
            raise ValueError("replacement leaves do not match generalized pattern leaves")

    @property
    def fingerprint(self) -> str:
        return self.proposal_fingerprint

    @property
    def certified(self) -> bool:
        return True

    def to_dict(self) -> dict[str, object]:
        return {
            "proposal_fingerprint": self.proposal_fingerprint,
            "source_fingerprints": list(self.source_fingerprints),
            "occurrence_count": self.occurrence_count,
            "pattern_fingerprint": term_fingerprint(self.pattern),
            "replacement_fingerprint": term_fingerprint(self.replacement),
            "source_cost": list(self.source_cost),
            "replacement_cost": list(self.replacement_cost),
            "proof_receipts": [
                {
                    "width": receipt.width,
                    "verdict": receipt.verdict,
                    "elapsed_ms": receipt.elapsed_ms,
                    "counterexample": receipt.counterexample,
                    "error": receipt.error,
                }
                for receipt in self.proof_receipts
            ],
            "class_name": self.class_name,
            "family": self.family,
            "description": self.description,
            "fixture": dict(self.fixture),
        }


def render_rule_source(proposal: MbaRuleProposal) -> str:
    """Render source for human review; this function never imports it."""

    keys = _keys(proposal.pattern)
    names = {key: f"x_{index}" for index, key in enumerate(keys)}
    lines = [
        '"""Proposed MBA rule; review and admit explicitly."""',
        "",
        "from d810.mba.dsl import Const, Var",
        "from d810.mba.rules._base import VerifiableRule",
        "",
    ]
    lines.extend(f'{name} = Var("{name}")' for name in names.values())
    if names:
        lines.append("")
    description = json.dumps(proposal.description, ensure_ascii=True)
    lines.extend(
        [
            f"class {proposal.class_name}(VerifiableRule):",
            f"    DESCRIPTION = {description}",
            f"    PATTERN = {_expr_source(proposal.pattern, names)}",
            f"    REPLACEMENT = {_expr_source(proposal.replacement, names)}",
            "",
        ]
    )
    source = "\n".join(lines)
    if not source.isascii():
        raise ValueError("proposal source must be ASCII-only")
    return source


__all__ = ["MbaRuleProposal", "render_rule_source"]
