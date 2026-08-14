"""Immutable portable descriptors for the final native Z3 proof path.

Templates are admitted from already-certified catalogue objects only.  They
contain neither Z3 state nor native AST/mop objects: runtime code must still
validate the concrete terms and create a fresh native-width proof immediately
before reconstruction.
"""

from __future__ import annotations

import functools
import weakref
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from d810.backends.mba.egglog_add_rule_compiler import (
    CompiledEgglogRule,
    apply_compiled_rule_to_term,
    is_admitted_compiled_rule,
)
from d810.mba.dsl import SymbolicExpressionProtocol
from d810.mba.typed_term import SUPPORTED_OPERATIONS, TypedBvTerm


_TEMPLATE_WIDTHS = frozenset({8, 16, 32, 64})
_TEMPLATE_RULES: dict[int, weakref.ReferenceType[CompiledEgglogRule]] = {}


@dataclass(frozen=True)
class NativeProofShape:
    """A portable symbolic operation/terminal descriptor for one template."""

    operation: str | None
    name: str | None = None
    constant: int | None = None
    requires_constant: bool = False
    children: tuple[NativeProofShape, ...] = ()


@dataclass(frozen=True)
class TemplateValidation:
    """Exact fixed-width terms accepted for a single proof instantiation."""

    width: int
    original: TypedBvTerm
    replacement: TypedBvTerm
    leaf_keys: tuple[tuple[object, ...], ...]


@dataclass(frozen=True)
class NativeZ3ProofTemplate:
    """An admitted rule's immutable operation descriptor at one bit width."""

    source_name: str
    aliases: tuple[str, ...]
    family: str
    width: int
    declaration_identity: int
    original_shape: NativeProofShape
    replacement_shape: NativeProofShape

    @classmethod
    def from_compiled_rule(
        cls, rule: CompiledEgglogRule, *, width: int
    ) -> NativeZ3ProofTemplate | None:
        """Admit only an exact enrolled, width-preserving rule declaration."""

        if (
            not is_admitted_compiled_rule(rule)
            or width not in _TEMPLATE_WIDTHS
            or width not in rule.proof_widths
        ):
            return None
        try:
            original_shape = _shape_from_expression(rule.pattern)
            replacement_shape = _shape_from_expression(rule.replacement)
        except (TypeError, ValueError):
            return None
        _enroll_template_rule(rule)
        return cls(
            source_name=rule.source_name,
            aliases=tuple(rule.aliases),
            family=rule.family,
            width=width,
            declaration_identity=id(rule),
            original_shape=original_shape,
            replacement_shape=replacement_shape,
        )

    def validate_terms(
        self, original: TypedBvTerm, replacement: TypedBvTerm
    ) -> TemplateValidation | None:
        """Require the concrete terms to be this rule's exact materialization.

        ``apply_compiled_rule_to_term`` is the same declarative matcher used by
        bounded extraction.  It enforces constants, repeated bindings, AC
        structure, and rule constraints before we compare its materialized
        result with the rebuilt concrete replacement.
        """

        if original.width != self.width or replacement.width != self.width:
            return None
        try:
            expected = apply_compiled_rule_to_term_by_identity(
                self.declaration_identity, original
            )
        except (TypeError, ValueError):
            return None
        if expected is None or expected != replacement:
            return None
        return TemplateValidation(
            width=self.width,
            original=original,
            replacement=replacement,
            leaf_keys=_ordered_leaf_keys(original, replacement),
        )


def _shape_from_expression(expression: object) -> NativeProofShape:
    if not isinstance(expression, SymbolicExpressionProtocol):
        raise TypeError("template expression must be symbolic")
    operation = expression.operation
    if operation is None:
        if (
            not expression.is_leaf()
            or expression.left is not None
            or expression.right is not None
        ):
            raise ValueError("malformed template terminal")
        return NativeProofShape(
            operation=None,
            name=expression.name,
            constant=expression.value,
            requires_constant=bool(getattr(expression, "is_pattern_constant", False)),
        )
    if operation not in SUPPORTED_OPERATIONS or expression.left is None:
        raise ValueError("unsupported template operation")
    children = [_shape_from_expression(expression.left)]
    if expression.right is not None:
        children.append(_shape_from_expression(expression.right))
    expected_arity = 1 if operation in {"bnot", "neg"} else 2
    if len(children) != expected_arity:
        raise ValueError("malformed template operation")
    return NativeProofShape(operation=operation, children=tuple(children))


def _ordered_leaf_keys(*terms: TypedBvTerm) -> tuple[tuple[object, ...], ...]:
    ordered: dict[tuple[object, ...], None] = {}

    def visit(term: TypedBvTerm) -> None:
        if term.operation is None:
            if term.leaf_key is not None:
                ordered.setdefault(term.leaf_key, None)
            return
        for child in term.children:
            visit(child)

    for term in terms:
        visit(term)
    return tuple(ordered)


@functools.lru_cache(maxsize=32)
def _cached_templates(
    enrolled: tuple[tuple[int, CompiledEgglogRule], ...],
) -> Mapping[tuple[int, int], NativeZ3ProofTemplate]:
    templates: dict[tuple[int, int], NativeZ3ProofTemplate] = {}
    for identity, rule in enrolled:
        if id(rule) != identity or not is_admitted_compiled_rule(rule):
            continue
        for width in sorted(_TEMPLATE_WIDTHS.intersection(rule.proof_widths)):
            template = NativeZ3ProofTemplate.from_compiled_rule(rule, width=width)
            if template is not None:
                templates[(identity, width)] = template
    return MappingProxyType(templates)


def native_z3_proof_templates_for_rules(
    rules: Iterable[CompiledEgglogRule],
) -> Mapping[tuple[int, int], NativeZ3ProofTemplate]:
    """Return cached immutable descriptors keyed by exact rule identity and width."""

    enrolled = tuple((id(rule), rule) for rule in rules)
    return _cached_templates(enrolled)


def _enroll_template_rule(rule: CompiledEgglogRule) -> None:
    identity = id(rule)

    def discard(reference: weakref.ReferenceType[CompiledEgglogRule]) -> None:
        if _TEMPLATE_RULES.get(identity) is reference:
            _TEMPLATE_RULES.pop(identity, None)

    _TEMPLATE_RULES[identity] = weakref.ref(rule, discard)


def apply_compiled_rule_to_term_by_identity(
    declaration_identity: int, original: TypedBvTerm
) -> TypedBvTerm | None:
    """Resolve one still-live enrolled declaration without caching runtime state."""

    reference = _TEMPLATE_RULES.get(declaration_identity)
    rule = None if reference is None else reference()
    if rule is None or id(rule) != declaration_identity:
        return None
    return apply_compiled_rule_to_term(rule, original)
