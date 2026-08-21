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

from d810.mba.certified_rule_compiler import (
    CompiledMbaRule,
    _constraints_match_term,
    apply_compiled_rule_to_term,
    is_admitted_compiled_rule,
)
from d810.mba.dsl import SymbolicExpressionProtocol
from d810.mba.typed_term import (
    FIXED_SHIFT_OPERATIONS,
    SUPPORTED_OPERATIONS,
    TypedBvTerm,
)


_TEMPLATE_WIDTHS = frozenset({8, 16, 32, 64})
_AC_OPERATIONS = frozenset({"add", "and", "mul", "or", "xor"})
_TEMPLATE_RULES: dict[int, weakref.ReferenceType[CompiledMbaRule]] = {}


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
        cls, rule: CompiledMbaRule, *, width: int
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

        The immutable template shapes enforce exact operation/arity/width,
        masked constants, and repeated bindings directly.  We then apply the
        admitted rule's declarative constraints to those fixed bindings.  This
        deliberately avoids re-entering the generic symbolic matcher after
        native selection has already fixed the candidate.
        """

        if original.width != self.width or replacement.width != self.width:
            return None
        bindings: dict[str, TypedBvTerm] = {}
        if not _match_template_shape(
            self.original_shape,
            original,
            bindings,
            allow_new_bindings=True,
        ):
            return None
        if not _match_template_shape(
            self.replacement_shape,
            replacement,
            bindings,
            allow_new_bindings=False,
        ):
            return None
        rule = _template_rule_by_identity(self.declaration_identity)
        if rule is None:
            return None
        try:
            if not _constraints_match_term(rule, bindings, width=self.width):
                return None
        except (TypeError, ValueError):
            return None
        return TemplateValidation(
            width=self.width,
            original=original,
            replacement=replacement,
            leaf_keys=_ordered_leaf_keys(original, replacement),
        )

    def prove_validation(self, validation: TemplateValidation) -> bool:
        """Instantiate this exact template into a fresh fixed-width Z3 proof.

        This deliberately does *not* lower a Hex-Rays AST.  ``validate_terms``
        has already established that the candidate is this admitted rule with
        these exact fixed bindings.  We lower that template-validated
        materialization into a new bit-vector solver.  The handler retains its
        native-AST proof as the independent mutation gate.
        """

        if not isinstance(validation, TemplateValidation):
            return False
        if type(validation.width) is not int or validation.width != self.width:
            return False
        if type(validation.original) is not TypedBvTerm or type(
            validation.replacement
        ) is not TypedBvTerm:
            return False
        try:
            original_width = validation.original.width
            replacement_width = validation.replacement.width
        except (AttributeError, TypeError):
            return False
        if (
            type(original_width) is not int
            or type(replacement_width) is not int
            or original_width != self.width
            or replacement_width != self.width
        ):
            return False
        if not _is_exact_validated_term(validation.original, width=self.width):
            return False
        if not _is_exact_validated_term(validation.replacement, width=self.width):
            return False
        try:
            import z3
        except ImportError:
            return False

        variables: dict[tuple[object, ...], object] = {}
        # validate_terms has already matched these exact concrete bindings
        # against both immutable shapes.  Rebinding the shapes here adds a
        # second Python AC walk and was slower than the legacy AST path.
        # Lower the validated fixed-width terms directly into this fresh
        # solver instead.
        original = _lower_validated_term(
            validation.original, variables=variables, z3=z3
        )
        replacement = _lower_validated_term(
            validation.replacement, variables=variables, z3=z3
        )
        solver = z3.Solver()
        solver.set(timeout=50)
        solver.add(original != replacement)
        return solver.check() == z3.unsat


def _is_exact_validated_term(
    term: object,
    *,
    width: int,
    _active: set[int] | None = None,
) -> bool:
    """Validate forged-proof input without importing or invoking Z3."""

    if type(term) is not TypedBvTerm:
        return False
    active = set() if _active is None else _active
    marker = id(term)
    if marker in active:
        return False
    active.add(marker)
    try:
        try:
            operation = term.operation
            term_width = term.width
            value = term.value
            leaf_key = term.leaf_key
            children = term.children
            shift_count = term.shift_count
        except (AttributeError, TypeError):
            return False
        if type(term_width) is not int or term_width != width or term_width <= 0:
            return False
        if type(children) is not tuple:
            return False
        if operation is None:
            if children or shift_count is not None:
                return False
            if (value is None) == (leaf_key is None):
                return False
            if value is not None:
                return type(value) is int and 0 <= value < (1 << term_width)
            if type(leaf_key) is not tuple or not leaf_key:
                return False
            try:
                hash(leaf_key)
            except (TypeError, ValueError):
                return False
            return True
        if type(operation) is not str or operation not in SUPPORTED_OPERATIONS:
            return False
        if value is not None or leaf_key is not None:
            return False
        expected_arity = (
            1
            if operation in {"bnot", "neg"} | FIXED_SHIFT_OPERATIONS
            else 2
        )
        if len(children) != expected_arity:
            return False
        if operation in FIXED_SHIFT_OPERATIONS:
            if type(shift_count) is not int or not 0 <= shift_count < term_width:
                return False
            if operation in {"rol", "ror"} and term_width not in _TEMPLATE_WIDTHS:
                return False
        elif shift_count is not None:
            return False
        return all(
            _is_exact_validated_term(child, width=term_width, _active=active)
            for child in children
        )
    finally:
        active.remove(marker)


def _lower_validated_term(
    term: TypedBvTerm, *, variables: dict[tuple[object, ...], object], z3
):
    """Lower one already template-validated fixed-width term to Z3."""

    if type(term) is not TypedBvTerm:
        raise ValueError("validated term must be a TypedBvTerm")
    try:
        operation = term.operation
        width = term.width
        value = term.value
        leaf_key = term.leaf_key
        children = term.children
        shift_count = term.shift_count
    except AttributeError as exc:
        raise ValueError("validated term is missing required state") from exc
    if type(width) is not int or width <= 0:
        raise ValueError("validated term has an invalid width")
    if type(children) is not tuple:
        raise ValueError("validated operation has malformed children")
    if operation is None:
        if children:
            raise ValueError("validated terminal cannot have children")
        if shift_count is not None:
            raise ValueError("validated terminal cannot have shift_count")
        if (value is None) == (leaf_key is None):
            raise ValueError("validated terminal must have one value or leaf key")
        if value is not None:
            if type(value) is not int or not 0 <= value < (1 << width):
                raise ValueError("validated constant must be an integer")
            return z3.BitVecVal(value, width)
        if type(leaf_key) is not tuple or not leaf_key:
            raise ValueError("missing validated leaf key")
        try:
            hash(leaf_key)
        except (TypeError, ValueError) as exc:
            raise ValueError("validated leaf key must be hashable") from exc
        return variables.setdefault(
            leaf_key,
            z3.BitVec(f"mba_template_leaf_{len(variables)}", width),
        )
    if type(operation) is not str or operation not in SUPPORTED_OPERATIONS:
        raise ValueError("unsupported validated operation")
    if value is not None or leaf_key is not None:
        raise ValueError("validated operation cannot carry terminal state")
    expected_arity = (
        1
        if operation in {"bnot", "neg"} | FIXED_SHIFT_OPERATIONS
        else 2
    )
    if len(children) != expected_arity:
        raise ValueError("validated operation has malformed arity")
    for child in children:
        if type(child) is not TypedBvTerm:
            raise ValueError("validated operation has malformed children")
        try:
            child_width = child.width
        except (AttributeError, TypeError) as exc:
            raise ValueError("validated operation has malformed children") from exc
        if child_width != width:
            raise ValueError("validated operation has malformed children")
    if operation in FIXED_SHIFT_OPERATIONS:
        if type(shift_count) is not int or not 0 <= shift_count < width:
            raise ValueError("validated fixed shift has malformed shift_count")
        if operation in {"rol", "ror"} and width not in _TEMPLATE_WIDTHS:
            raise ValueError("validated rotate has an unsupported width")
    elif shift_count is not None:
        raise ValueError("validated non-shift operation has shift_count metadata")
    children = tuple(
        _lower_validated_term(child, variables=variables, z3=z3) for child in children
    )
    if operation == "shl":
        return children[0] << shift_count
    if operation == "lshr":
        return z3.LShR(children[0], shift_count)
    if operation == "rol":
        return z3.RotateLeft(children[0], shift_count)
    if operation == "ror":
        return z3.RotateRight(children[0], shift_count)
    operations = {
        "add": lambda: children[0] + children[1],
        "sub": lambda: children[0] - children[1],
        "mul": lambda: children[0] * children[1],
        "and": lambda: children[0] & children[1],
        "or": lambda: children[0] | children[1],
        "xor": lambda: children[0] ^ children[1],
        "neg": lambda: -children[0],
        "bnot": lambda: ~children[0],
    }
    operation = operations.get(operation)
    if operation is None:
        raise ValueError("unsupported validated operation")
    return operation()


def prove_typed_term_equivalence(
    original: TypedBvTerm, replacement: TypedBvTerm
) -> bool:
    """Delegate the portable typed-term proof to the single public seam."""

    from d810.mba.extension_api import (
        prove_typed_term_equivalence as _prove_typed_term_equivalence,
    )

    return _prove_typed_term_equivalence(original, replacement)


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
    if operation in FIXED_SHIFT_OPERATIONS:
        raise ValueError("fixed shifts require literal shift_count metadata")
    if operation not in SUPPORTED_OPERATIONS or expression.left is None:
        raise ValueError("unsupported template operation")
    children = [_shape_from_expression(expression.left)]
    if expression.right is not None:
        children.append(_shape_from_expression(expression.right))
    expected_arity = 1 if operation in {"bnot", "neg"} else 2
    if len(children) != expected_arity:
        raise ValueError("malformed template operation")
    return NativeProofShape(operation=operation, children=tuple(children))


def _match_template_shape(
    shape: NativeProofShape,
    term: TypedBvTerm,
    bindings: dict[str, TypedBvTerm],
    *,
    allow_new_bindings: bool,
) -> bool:
    """Validate one concrete fixed-width term against an immutable shape."""

    if term.width <= 0:
        return False
    if shape.operation is None:
        if term.operation is not None:
            return False
        if shape.constant is not None:
            if term.value is None:
                return False
            mask = (1 << term.width) - 1
            if term.value != (shape.constant & mask):
                return False
        if shape.requires_constant and term.value is None:
            return False
        if shape.name is None:
            return shape.constant is not None or shape.requires_constant
        bound = bindings.get(shape.name)
        if bound is None:
            if not allow_new_bindings:
                return False
            bindings[shape.name] = term
            return True
        return bound == term
    if term.operation != shape.operation or len(term.children) != len(shape.children):
        return False

    def match_children(
        children: tuple[TypedBvTerm, ...],
    ) -> bool:
        return all(
            _match_template_shape(
                child_shape,
                child_term,
                bindings,
                allow_new_bindings=allow_new_bindings,
            )
            for child_shape, child_term in zip(shape.children, children, strict=True)
        )

    checkpoint = dict(bindings)
    if match_children(term.children):
        return True
    bindings.clear()
    bindings.update(checkpoint)
    if shape.operation not in _AC_OPERATIONS or len(term.children) != 2:
        return False
    if match_children((term.children[1], term.children[0])):
        return True
    bindings.clear()
    bindings.update(checkpoint)
    return False


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
    enrolled: tuple[tuple[int, CompiledMbaRule], ...],
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
    rules: Iterable[CompiledMbaRule],
) -> Mapping[tuple[int, int], NativeZ3ProofTemplate]:
    """Return cached immutable descriptors keyed by exact rule identity and width."""

    enrolled = tuple((id(rule), rule) for rule in rules)
    return _cached_templates(enrolled)


def _enroll_template_rule(rule: CompiledMbaRule) -> None:
    identity = id(rule)

    def discard(reference: weakref.ReferenceType[CompiledMbaRule]) -> None:
        if _TEMPLATE_RULES.get(identity) is reference:
            _TEMPLATE_RULES.pop(identity, None)

    _TEMPLATE_RULES[identity] = weakref.ref(rule, discard)


def apply_compiled_rule_to_term_by_identity(
    declaration_identity: int, original: TypedBvTerm
) -> TypedBvTerm | None:
    """Resolve one still-live enrolled declaration without caching runtime state."""

    rule = _template_rule_by_identity(declaration_identity)
    return None if rule is None else apply_compiled_rule_to_term(rule, original)


def _template_rule_by_identity(
    declaration_identity: int,
) -> CompiledMbaRule | None:
    """Return one live admitted template declaration by exact identity."""

    reference = _TEMPLATE_RULES.get(declaration_identity)
    rule = None if reference is None else reference()
    if rule is None or id(rule) != declaration_identity:
        return None
    return rule
