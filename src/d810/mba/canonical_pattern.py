"""Portable canonical templates for already-certified MBA rules.

The canonical template layer deliberately knows nothing about IDA or provider
Z3.  It lowers the existing symbolic DSL into :class:`TypedBvTerm` values,
preserving the distinction between a wildcard variable and a constrained
constant placeholder.  Rule admission and proof certification remain owned by
the existing catalogue compiler; this module only compiles an admitted rule's
immutable semantic description for bounded matching.
"""

from __future__ import annotations

import hashlib
import dis
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from d810.core.typing import TYPE_CHECKING

from d810.mba.ac_matching import AcMatchStopReason
from d810.mba.dsl import SymbolicExpressionProtocol
from d810.mba.semantic_canonicalization import (
    CANONICALIZER_SCHEMA_VERSION,
    canonicalize_mba_term,
)
from d810.mba.typed_term import (
    FIXED_SHIFT_OPERATIONS,
    SUPPORTED_OPERATIONS,
    TypedBvTerm,
    canonicalize_ac_term,
    term_fingerprint,
)

if TYPE_CHECKING:
    from d810.mba.certified_rule_compiler import CompiledMbaRule


PatternLeafKey = tuple[str, str]

# These fields are callback-local adapter state, not declared rule semantics.
# Keep this policy shared with the certified snapshot encoder so a live match
# cannot perturb either side of the certificate binding.
TRANSIENT_RULE_STATE_FIELDS = frozenset(
    {
        "_current_blk",
        "_current_ins",
        "_runtime_constant_evaluator",
    }
)


class CanonicalPatternUnsupported(ValueError):
    """A DSL expression that is intentionally left on the legacy path."""


class CanonicalPatternMalformed(ValueError):
    """A malformed or opaque DSL expression that cannot authorize matching."""


@dataclass(frozen=True, slots=True)
class FrozenConstraintExpression:
    """A portable constraint expression captured during catalogue freezing."""

    operation: str | None = None
    value: int | None = None
    name: str | None = None
    children: tuple[FrozenConstraintExpression, ...] = ()


@dataclass(frozen=True, slots=True)
class FrozenConstraint:
    """One frozen comparison or logical constraint with no live DSL objects."""

    left: FrozenConstraintExpression | None = None
    right: FrozenConstraintExpression | None = None
    operation: str = "eq"
    children: tuple[FrozenConstraint, ...] = ()

    def __post_init__(self) -> None:
        comparisons = {"eq", "ne", "lt", "gt", "le", "ge"}
        logical_arity = {"and": 2, "or": 2, "not": 1}
        if self.operation in comparisons:
            if self.left is None or self.right is None or self.children:
                raise ValueError("comparison constraints require two expressions")
            return
        expected = logical_arity.get(self.operation)
        if expected is None or self.left is not None or self.right is not None:
            raise ValueError(f"unsupported frozen constraint operation: {self.operation}")
        if len(self.children) != expected:
            raise ValueError(
                f"frozen {self.operation} constraint requires {expected} children"
            )


@dataclass(frozen=True, slots=True)
class CanonicalCompiledPattern:
    """One width-specific canonical pattern and replacement template."""

    rule: "CompiledMbaRule"
    width: int
    pattern_term: TypedBvTerm
    replacement_template: TypedBvTerm
    terminal_kinds: Mapping[PatternLeafKey, str]
    semantic_fingerprint: str
    declaration_index: int
    constraints: tuple[FrozenConstraint, ...] = ()
    fixed_constant_values: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self.width) is not int or self.width <= 0:
            raise ValueError("width must be a positive integer")
        if self.pattern_term.width != self.width:
            raise ValueError("pattern term width does not match template width")
        if self.replacement_template.width != self.width:
            raise ValueError("replacement template width does not match template width")
        if type(self.semantic_fingerprint) is not str or not self.semantic_fingerprint:
            raise ValueError("semantic_fingerprint must be a non-empty string")
        if type(self.declaration_index) is not int or self.declaration_index < 0:
            raise ValueError("declaration_index must be non-negative")
        constraints = tuple(self.constraints)
        if any(not isinstance(item, FrozenConstraint) for item in constraints):
            raise ValueError("constraints must be frozen portable constraints")
        object.__setattr__(self, "constraints", constraints)
        fixed_constants = dict(self.fixed_constant_values)
        if any(
            type(name) is not str
            or not name
            or type(value) is not int
            for name, value in fixed_constants.items()
        ):
            raise ValueError("fixed_constant_values must map names to integers")
        object.__setattr__(self, "fixed_constant_values", MappingProxyType(fixed_constants))
        kinds = dict(self.terminal_kinds)
        for key, kind in kinds.items():
            if (
                type(key) is not tuple
                or len(key) != 2
                or key[0] not in {"pattern_var", "pattern_const"}
                or type(key[1]) is not str
                or not key[1]
                or kind != key[0]
            ):
                raise ValueError("terminal_kinds contains an invalid placeholder")
        object.__setattr__(self, "terminal_kinds", MappingProxyType(kinds))

    @property
    def root_shape(self) -> tuple[str | None, int, int]:
        return (self.pattern_term.operation, self.width, len(self.pattern_term.children))

    @property
    def canonical_pattern(self) -> TypedBvTerm:
        """Compatibility name for callers that describe the pattern as canonical."""

        return self.pattern_term

    @property
    def canonical_replacement(self) -> TypedBvTerm:
        """Compatibility name for the canonical replacement template."""

        return self.replacement_template

    def materialize_replacement(self, bindings: "CanonicalFixedBindings") -> TypedBvTerm:
        """Substitute fixed candidate terms into the canonical replacement."""

        return _materialize_template(self.replacement_template, bindings.terms)


@dataclass(frozen=True, slots=True)
class CanonicalFixedBindings:
    """Portable candidate terms and canonical paths for one structural match."""

    terms: Mapping[str, TypedBvTerm]
    candidate_paths: Mapping[str, tuple[int, ...]]
    width: int

    def __post_init__(self) -> None:
        terms = dict(self.terms)
        paths = {name: tuple(path) for name, path in self.candidate_paths.items()}
        if not set(paths).issubset(terms):
            raise ValueError("candidate_paths must refer to bound terms")
        if any(term.width != self.width for term in terms.values()):
            raise ValueError("binding terms must use the match width")
        object.__setattr__(self, "terms", MappingProxyType(terms))
        object.__setattr__(self, "candidate_paths", MappingProxyType(paths))

    @property
    def candidate_path_by_name(self) -> Mapping[str, tuple[int, ...]]:
        """Alias matching the existing AC matcher binding vocabulary."""

        return self.candidate_paths


@dataclass(frozen=True, slots=True)
class CanonicalPatternMatch:
    compiled_pattern: CanonicalCompiledPattern
    bindings: CanonicalFixedBindings


@dataclass(frozen=True, slots=True)
class CanonicalPatternMatchReport:
    matches: tuple[CanonicalPatternMatch, ...]
    comparisons: int
    commuted_branches: int
    flattened_nodes: int
    stop_reason: AcMatchStopReason
    compatibility_bindings: CanonicalFixedBindings | None = None

    @property
    def bindings(self) -> CanonicalFixedBindings | None:
        """Expose the first match for callers using the legacy report shape."""

        if self.compatibility_bindings is not None:
            return self.compatibility_bindings
        return self.matches[0].bindings if self.matches else None


CanonicalPatternMatchResult = CanonicalPatternMatchReport


def merge_canonical_bindings(
    bindings: CanonicalFixedBindings,
    compatibility_bindings: CanonicalFixedBindings | None,
) -> CanonicalFixedBindings:
    """Merge uniquely located compatibility-only bindings into one match."""

    if compatibility_bindings is None:
        return bindings
    terms = dict(bindings.terms)
    paths = dict(bindings.candidate_paths)
    for name, term in compatibility_bindings.terms.items():
        # The compatibility projection is derived from the first matcher
        # alternative and may contain ordinary variable bindings that differ
        # across symmetric alternatives.  Only import names absent from the
        # alternative; fixed constants are the compatibility-only case.
        if name in terms:
            continue
        terms[name] = term
        compatibility_path = compatibility_bindings.candidate_paths.get(name)
        if compatibility_path is None:
            continue
        paths[name] = compatibility_path
    return CanonicalFixedBindings(terms, paths, bindings.width)


def resolve_canonical_match_paths(
    matches: Iterable[CanonicalPatternMatch],
    *,
    canonical_to_raw_paths: Mapping[tuple[int, ...], tuple[int, ...]],
    placeholder_order: Iterable[str],
    required_names: Iterable[str] = (),
) -> tuple[CanonicalPatternMatch, ...]:
    """Resolve canonical bindings to unique raw paths and order the results.

    Canonical AC matching may produce several valid bindings after operand
    normalization.  Native reconstruction must use the exact source-order
    node for each binding; a canonical path without one unique raw provenance
    is therefore discarded.  Surviving alternatives are ordered by their raw
    paths in the declaration order captured by ``terminal_kinds`` so callers
    can select one deterministically without changing canonical matching.
    """

    ordered_names = tuple(placeholder_order)
    required = frozenset(required_names)
    resolved: list[tuple[tuple[object, ...], CanonicalPatternMatch]] = []
    for match in matches:
        bindings = match.bindings
        raw_paths: dict[str, tuple[int, ...]] = {}
        used_paths: set[tuple[int, ...]] = set()
        unresolved = False
        for name, canonical_path in bindings.candidate_paths.items():
            raw_path = canonical_to_raw_paths.get(tuple(canonical_path))
            if raw_path is None:
                unresolved = True
                break
            raw_path = tuple(raw_path)
            if raw_path in used_paths:
                unresolved = True
                break
            used_paths.add(raw_path)
            raw_paths[name] = raw_path
        if unresolved or not required.issubset(raw_paths):
            continue
        resolved_bindings = CanonicalFixedBindings(
            bindings.terms,
            raw_paths,
            bindings.width,
        )
        resolved_match = replace(match, bindings=resolved_bindings)
        score = tuple(
            raw_paths[name]
            for name in ordered_names
            if name in raw_paths
        )
        score += tuple(
            raw_paths[name]
            for name in sorted(raw_paths)
            if name not in ordered_names
        )
        resolved.append((score, resolved_match))
    resolved.sort(key=lambda item: item[0])
    return tuple(match for _score, match in resolved)


def _expression_or_raise(expression: object) -> SymbolicExpressionProtocol:
    if not isinstance(expression, SymbolicExpressionProtocol):
        raise CanonicalPatternMalformed(
            f"expression is not a supported symbolic DSL node: {type(expression).__name__}"
        )
    return expression


def lower_symbolic_template(
    expression: SymbolicExpressionProtocol,
    *,
    width: int,
) -> tuple[TypedBvTerm, Mapping[PatternLeafKey, str]]:
    """Lower one symbolic DSL tree to a typed placeholder term.

    Concrete DSL literals are represented as modular constants.  Symbolic
    ``Var`` and unconstrained ``Const`` leaves use distinct placeholder keys;
    the distinction is retained outside the structural term because both are
    terminal leaves in the portable vocabulary.
    """

    if type(width) is not int or width <= 0:
        raise ValueError("width must be a positive integer")
    node = _expression_or_raise(expression)
    operation = node.operation
    if operation is None:
        if node.left is not None or node.right is not None:
            raise CanonicalPatternMalformed("malformed symbolic leaf")
        if node.value is not None:
            if type(node.value) is not int:
                raise CanonicalPatternMalformed("symbolic literal is not an integer")
            return TypedBvTerm(None, width, value=node.value), {}
        name = node.name
        if type(name) is not str or not name:
            raise CanonicalPatternMalformed("symbolic placeholder has no name")
        kind = "pattern_const" if bool(getattr(node, "is_pattern_constant", False)) else "pattern_var"
        key: PatternLeafKey = (kind, name)
        return TypedBvTerm(None, width, leaf_key=key), {key: kind}

    if operation not in SUPPORTED_OPERATIONS:
        raise CanonicalPatternUnsupported(f"unsupported canonical DSL operation: {operation}")
    if node.left is None:
        raise CanonicalPatternMalformed(f"malformed {operation} expression")
    if operation in FIXED_SHIFT_OPERATIONS:
        if operation in {"shl", "lshr"}:
            raise CanonicalPatternUnsupported(
                f"symbolic {operation} requires a fixed-count term"
            )
        if node.right is None or node.right.operation is not None or type(node.right.value) is not int:
            raise CanonicalPatternUnsupported(
                f"symbolic {operation} requires a fixed-count constant"
            )
        count = node.right.value
        if operation in {"rol", "ror"}:
            count %= width
        if count < 0 or count >= width:
            raise CanonicalPatternUnsupported(
                f"symbolic {operation} count is outside the target width"
            )
        left, kinds = lower_symbolic_template(node.left, width=width)
        return TypedBvTerm(operation, width, children=(left,), shift_count=count), kinds
    if operation in {"bnot", "neg"}:
        if node.right is not None:
            raise CanonicalPatternMalformed(f"malformed unary {operation} expression")
        left, kinds = lower_symbolic_template(node.left, width=width)
        return TypedBvTerm(operation, width, children=(left,)), kinds
    if node.right is None:
        raise CanonicalPatternMalformed(f"malformed binary {operation} expression")
    left, left_kinds = lower_symbolic_template(node.left, width=width)
    right, right_kinds = lower_symbolic_template(node.right, width=width)
    kinds = dict(left_kinds)
    for key, kind in right_kinds.items():
        existing = kinds.get(key)
        if existing is not None and existing != kind:
            raise CanonicalPatternMalformed("placeholder kind changed for one name")
        kinds[key] = kind
    return TypedBvTerm(operation, width, children=(left, right)), kinds


def _fixed_constant_values(
    expression: SymbolicExpressionProtocol,
) -> Mapping[str, int]:
    """Collect names for concrete pattern constants without changing lowering."""

    values: dict[str, int] = {}

    def visit(node: SymbolicExpressionProtocol) -> None:
        if node.operation is None:
            if (
                bool(getattr(node, "is_pattern_constant", False))
                and type(node.name) is str
                and node.name
                and type(node.value) is int
            ):
                previous = values.get(node.name)
                if previous is not None and previous != node.value:
                    raise CanonicalPatternMalformed(
                        "one pattern constant name has multiple fixed values"
                    )
                values[node.name] = node.value
            return
        if node.left is None:
            raise CanonicalPatternMalformed("malformed symbolic expression")
        visit(node.left)
        if node.operation in FIXED_SHIFT_OPERATIONS:
            return
        if node.right is not None:
            visit(node.right)

    visit(_expression_or_raise(expression))
    return MappingProxyType(values)


def _rule_value(rule: object, name: str, default: object = None) -> object:
    value = getattr(rule, name, default)
    if callable(value) and name in {"pattern", "replacement"}:
        try:
            return value()
        except TypeError:
            return value
    return value


def _rule_constraint_values(rule: object) -> object:
    value = getattr(rule, "constraints", None)
    if value is None:
        value = getattr(rule, "CONSTRAINTS", ())
    if callable(value):
        try:
            value = value()
        except TypeError:
            pass
    return value if value is not None else ()


def _freeze_constraint_expression(expression: object) -> FrozenConstraintExpression:
    if type(expression) is int:
        return FrozenConstraintExpression(value=expression)
    node = _expression_or_raise(expression)
    operation = node.operation
    if operation is None:
        if node.left is not None or node.right is not None:
            raise CanonicalPatternMalformed("malformed symbolic constraint leaf")
        if node.value is not None:
            if type(node.value) is not int:
                raise CanonicalPatternMalformed(
                    "symbolic constraint literal is not an integer"
                )
            return FrozenConstraintExpression(value=node.value)
        if type(node.name) is not str or not node.name:
            raise CanonicalPatternMalformed("symbolic constraint placeholder has no name")
        return FrozenConstraintExpression(name=node.name)
    if operation not in SUPPORTED_OPERATIONS:
        raise CanonicalPatternUnsupported(
            f"unsupported canonical constraint operation: {operation}"
        )
    if node.left is None:
        raise CanonicalPatternMalformed(f"malformed constraint {operation} expression")
    left = _freeze_constraint_expression(node.left)
    if operation in {"bnot", "neg"}:
        if node.right is not None:
            raise CanonicalPatternMalformed(
                f"malformed unary constraint {operation} expression"
            )
        return FrozenConstraintExpression(operation=operation, children=(left,))
    if node.right is None:
        raise CanonicalPatternMalformed(f"malformed binary constraint {operation} expression")
    right = _freeze_constraint_expression(node.right)
    return FrozenConstraintExpression(operation=operation, children=(left, right))


def _constraint_operation(constraint: object) -> str:
    comparison = getattr(constraint, "op_name", None)
    if comparison is not None:
        if comparison not in {"ne", "lt", "gt", "le", "ge"}:
            raise CanonicalPatternMalformed(
                f"unsupported comparison operation: {comparison}"
            )
        return comparison
    if hasattr(constraint, "operand") and not hasattr(constraint, "left"):
        return "not"
    constraint_name = type(constraint).__name__
    if constraint_name == "AndConstraint":
        return "and"
    if constraint_name == "OrConstraint":
        return "or"
    if hasattr(constraint, "left") and hasattr(constraint, "right"):
        return "eq"
    raise CanonicalPatternMalformed(
        f"unsupported rule constraint type: {type(constraint).__name__}"
    )


def _freeze_constraint(constraint: object) -> FrozenConstraint:
    operation = _constraint_operation(constraint)
    if operation in {"and", "or"}:
        left = getattr(constraint, "left", None)
        right = getattr(constraint, "right", None)
        if left is None or right is None:
            raise CanonicalPatternMalformed(
                f"malformed logical constraint {operation}"
            )
        return FrozenConstraint(
            operation=operation,
            children=(_freeze_constraint(left), _freeze_constraint(right)),
        )
    if operation == "not":
        operand = getattr(constraint, "operand", None)
        if operand is None:
            raise CanonicalPatternMalformed("malformed logical constraint not")
        return FrozenConstraint(
            operation=operation,
            children=(_freeze_constraint(operand),),
        )
    left = getattr(constraint, "left", None)
    right = getattr(constraint, "right", None)
    if left is None or right is None:
        raise CanonicalPatternMalformed(
            f"malformed comparison constraint {operation}"
        )
    return FrozenConstraint(
        _freeze_constraint_expression(left),
        _freeze_constraint_expression(right),
        operation=operation,
    )


def _freeze_constraints(rule: object) -> tuple[FrozenConstraint, ...]:
    constraints = _rule_constraint_values(rule)
    try:
        values = tuple(constraints)
    except TypeError as exc:
        raise CanonicalPatternMalformed("rule constraints are not iterable") from exc
    frozen: list[FrozenConstraint] = []
    for constraint in values:
        frozen.append(_freeze_constraint(constraint))
    return tuple(frozen)


def _jsonable_semantics(value: object, active: set[int] | None = None) -> object:
    """Encode rule semantics without object-address-based ``repr`` values."""

    active = set() if active is None else active
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if _is_operational_d810_logger(value):
        return {"operational_logger": "d810"}
    identity = id(value)
    if identity in active:
        return {"opaque": "cyclic"}
    active.add(identity)
    try:
        if isinstance(value, SymbolicExpressionProtocol):
            return {
                "dsl": {
                    "operation": value.operation,
                    "name": value.name,
                    "value": value.value,
                    "pattern_constant": bool(
                        getattr(value, "is_pattern_constant", False)
                    ),
                    "left": _jsonable_semantics(value.left, active),
                    "right": _jsonable_semantics(value.right, active),
                    "constraint": _jsonable_semantics(
                        getattr(value, "constraint", None), active
                    ),
                }
            }
        if isinstance(value, property):
            return {
                "property": {
                    "fget": _jsonable_property_accessor(value.fget, active),
                    "fset": _jsonable_property_accessor(value.fset, active),
                    "fdel": _jsonable_property_accessor(value.fdel, active),
                }
            }
        if isinstance(value, Mapping):
            entries = [
                (_jsonable_semantics(key, active), _jsonable_semantics(item, active))
                for key, item in value.items()
                if not (type(key) is str and key in TRANSIENT_RULE_STATE_FIELDS)
            ]
            entries.sort(
                key=lambda pair: json.dumps(
                    pair[0], ensure_ascii=True, sort_keys=True, separators=(",", ":")
                )
            )
            return {"mapping": entries}
        if isinstance(value, (tuple, list, set, frozenset)):
            items = [_jsonable_semantics(item, active) for item in value]
            if isinstance(value, (set, frozenset)):
                items.sort(
                    key=lambda item: json.dumps(
                        item, ensure_ascii=True, sort_keys=True, separators=(",", ":")
                    )
                )
            return {"sequence": items}
        if isinstance(value, type):
            return {"type": f"{value.__module__}.{value.__qualname__}"}
        if callable(value):
            function = getattr(value, "__func__", value)
            code = getattr(function, "__code__", None)
            if code is None:
                return {
                    "callable": f"{getattr(function, '__module__', '')}."
                    f"{getattr(function, '__qualname__', type(function).__qualname__)}",
                    "opaque": "callable_without_code",
                }
            globals_map = getattr(function, "__globals__", {})
            loaded_names: set[str] = set()
            try:
                loaded_names = {
                    instruction.argval
                    for instruction in disassemble(code)
                    if instruction.opname in {"LOAD_GLOBAL", "LOAD_NAME"}
                    and isinstance(instruction.argval, str)
                }
            except (TypeError, ValueError):
                return {"callable": "opaque_code"}
            referenced = {
                name: _jsonable_semantics(globals_map[name], active)
                for name in sorted(loaded_names)
                if name in globals_map
            }
            return {
                "callable": f"{getattr(function, '__module__', '')}."
                f"{getattr(function, '__qualname__', type(function).__qualname__)}",
                "code": {
                    "bytecode": code.co_code.hex(),
                    "consts": _jsonable_semantics(code.co_consts, active),
                    "names": code.co_names,
                    "varnames": code.co_varnames,
                },
                "globals": referenced,
                "defaults": _jsonable_semantics(
                    getattr(function, "__defaults__", None), active
                ),
                "closure": _jsonable_semantics(
                    tuple(cell.cell_contents for cell in getattr(function, "__closure__", ()) or ()),
                    active,
                ),
            }
        attributes = getattr(value, "__dict__", None)
        if isinstance(attributes, dict):
            return {
                "object": f"{type(value).__module__}.{type(value).__qualname__}",
                "attributes": _jsonable_semantics(attributes, active),
            }
        return {
            "opaque": f"{type(value).__module__}.{type(value).__qualname__}"
        }
    finally:
        active.discard(identity)


def _is_operational_d810_logger(value: object) -> bool:
    """Keep mutable diagnostic logger internals out of rule semantics."""

    value_type = type(value)
    return (
        value_type.__module__ == "d810.core.logging"
        and value_type.__qualname__ == "D810Logger"
    )


def disassemble(code):
    """Small indirection that keeps callable fingerprinting testable."""

    return dis.get_instructions(code)


def _jsonable_property_accessor(
    accessor: object, active: set[int]
) -> object:
    """Serialize property implementation code without walking module globals."""

    if accessor is None:
        return None
    function = getattr(accessor, "__func__", accessor)
    code = getattr(function, "__code__", None)
    if code is None:
        return {
            "callable": f"{getattr(function, '__module__', '')}."
            f"{getattr(function, '__qualname__', type(function).__qualname__)}",
            "opaque": "callable_without_code",
        }
    return {
        "callable": f"{getattr(function, '__module__', '')}."
        f"{getattr(function, '__qualname__', type(function).__qualname__)}",
        "code": {
            "bytecode": code.co_code.hex(),
            "consts": _jsonable_semantics(code.co_consts, active),
            "names": code.co_names,
            "varnames": code.co_varnames,
            "freevars": code.co_freevars,
            "cellvars": code.co_cellvars,
        },
    }


def _rule_semantic_payload(
    rule: object,
    *,
    width: int,
    pattern_term: TypedBvTerm,
    replacement_template: TypedBvTerm,
    terminal_kinds: Mapping[PatternLeafKey, str],
) -> dict[str, object]:
    rule_type = getattr(rule, "rule_type", type(rule))
    implementation_names = (
        "pattern",
        "replacement",
        "check_candidate",
        "check_runtime_constraints",
        "get_constraints",
        "get_replacement",
    )
    implementations = []
    for name in implementation_names:
        implementation = getattr(rule_type, name, None)
        if implementation is not None:
            implementations.append((name, _jsonable_semantics(implementation)))
    return {
        "canonicalizer_schema_version": CANONICALIZER_SCHEMA_VERSION,
        "width": width,
        "canonical_pattern": term_fingerprint(pattern_term),
        "canonical_replacement": term_fingerprint(replacement_template),
        "terminal_kinds": sorted(
            (key, kind) for key, kind in terminal_kinds.items()
        ),
        "rule": {
            "type": f"{type(rule_type).__module__}.{getattr(rule_type, '__qualname__', type(rule_type).__qualname__)}"
            if not isinstance(rule_type, type)
            else f"{rule_type.__module__}.{rule_type.__qualname__}",
            "family": _rule_value(rule, "family", ""),
            "source_name": _rule_value(rule, "source_name", ""),
            "aliases": _rule_value(rule, "aliases", ()),
            "proof_widths": _rule_value(rule, "proof_widths", ()),
            "guarded": _rule_value(rule, "guarded", False),
            "pattern": _jsonable_semantics(_rule_value(rule, "pattern")),
            "replacement": _jsonable_semantics(_rule_value(rule, "replacement")),
            "constraints": _jsonable_semantics(_rule_constraint_values(rule)),
            "dynamic_constants": _jsonable_semantics(
                _rule_value(rule, "DYNAMIC_CONSTS", None)
                if _rule_value(rule, "DYNAMIC_CONSTS", None) is not None
                else getattr(rule_type, "DYNAMIC_CONSTS", {})
            ),
            "context_vars": _jsonable_semantics(
                _rule_value(rule, "CONTEXT_VARS", None)
                if _rule_value(rule, "CONTEXT_VARS", None) is not None
                else getattr(rule_type, "CONTEXT_VARS", {})
            ),
            "destination_policy": _jsonable_semantics(
                _rule_value(rule, "UPDATE_DESTINATION", None)
                if _rule_value(rule, "UPDATE_DESTINATION", None) is not None
                else getattr(rule_type, "UPDATE_DESTINATION", None)
            ),
            "bit_width": _rule_value(rule, "BIT_WIDTH", getattr(rule_type, "BIT_WIDTH", None)),
            "configuration": _jsonable_semantics(
                getattr(rule, "config", {})
            ),
            "implementations": implementations,
        },
    }


def _fingerprint_payload(payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def canonical_rule_fingerprint(
    compiled_pattern: CanonicalCompiledPattern | object,
    *,
    width: int | None = None,
    declaration_index: int = 0,
) -> str:
    """Return the persisted semantic digest for one compiled template."""

    if isinstance(compiled_pattern, CanonicalCompiledPattern):
        return compiled_pattern.semantic_fingerprint
    if width is None:
        proof_widths = _rule_value(compiled_pattern, "proof_widths", ())
        width = next(iter(proof_widths), 32)
    return compile_canonical_pattern(
        compiled_pattern,
        width=width,
        declaration_index=declaration_index,
    ).semantic_fingerprint


def compile_canonical_pattern(
    rule: "CompiledMbaRule",
    *,
    width: int,
    declaration_index: int,
) -> CanonicalCompiledPattern:
    """Compile one existing admitted rule into a width-specific template."""

    pattern_expression = _rule_value(rule, "pattern")
    replacement_expression = _rule_value(rule, "replacement")
    if pattern_expression is None or replacement_expression is None:
        raise CanonicalPatternMalformed("rule has no symbolic pattern/replacement")
    pattern_raw, pattern_kinds = lower_symbolic_template(
        pattern_expression, width=width
    )
    fixed_constant_values = _fixed_constant_values(pattern_expression)
    replacement_raw, replacement_kinds = lower_symbolic_template(
        replacement_expression, width=width
    )
    terminal_kinds = dict(pattern_kinds)
    for key, kind in replacement_kinds.items():
        existing = terminal_kinds.get(key)
        if existing is not None and existing != kind:
            raise CanonicalPatternMalformed("placeholder kind changed for one name")
        terminal_kinds[key] = kind
    pattern_term = canonicalize_mba_term(pattern_raw).canonical_term
    replacement_template = canonicalize_mba_term(replacement_raw).canonical_term
    payload = _rule_semantic_payload(
        rule,
        width=width,
        pattern_term=pattern_term,
        replacement_template=replacement_template,
        terminal_kinds=terminal_kinds,
    )
    return CanonicalCompiledPattern(
        rule=rule,
        width=width,
        pattern_term=pattern_term,
        replacement_template=replacement_template,
        terminal_kinds=terminal_kinds,
        semantic_fingerprint=_fingerprint_payload(payload),
        declaration_index=declaration_index,
        constraints=_freeze_constraints(rule),
        fixed_constant_values=fixed_constant_values,
    )


@dataclass(frozen=True, slots=True)
class _UnboundFrozenConstraintTerm:
    name: str


def _constant_fold_constraint(
    operation: str, values: tuple[int, ...], width: int
) -> int:
    mask = (1 << width) - 1
    if operation == "add":
        result = values[0] + values[1]
    elif operation == "sub":
        result = values[0] - values[1]
    elif operation == "mul":
        result = values[0] * values[1]
    elif operation == "and":
        result = values[0] & values[1]
    elif operation == "or":
        result = values[0] | values[1]
    elif operation == "xor":
        result = values[0] ^ values[1]
    elif operation == "neg":
        result = -values[0]
    elif operation == "bnot":
        result = ~values[0]
    else:
        raise ValueError(f"unsupported frozen constraint operation: {operation}")
    return result & mask


def _evaluate_frozen_constraint_expression(
    expression: FrozenConstraintExpression,
    bindings: dict[str, TypedBvTerm],
    *,
    width: int,
) -> TypedBvTerm | _UnboundFrozenConstraintTerm:
    if expression.operation is None:
        if expression.name is not None:
            return bindings.get(
                expression.name,
                _UnboundFrozenConstraintTerm(expression.name),
            )
        if expression.value is not None:
            return TypedBvTerm(None, width, value=expression.value)
        raise ValueError("frozen constraint terminal has no value or name")
    children = tuple(
        _evaluate_frozen_constraint_expression(child, bindings, width=width)
        for child in expression.children
    )
    if any(isinstance(child, _UnboundFrozenConstraintTerm) for child in children):
        raise ValueError("nested unbound frozen constraint expression")
    typed_children = tuple(child for child in children if isinstance(child, TypedBvTerm))
    if len(typed_children) != len(children):
        raise ValueError("frozen constraint expression has an invalid child")
    if all(child.operation is None and child.value is not None for child in typed_children):
        return TypedBvTerm(
            None,
            width,
            value=_constant_fold_constraint(
                expression.operation,
                tuple(int(child.value) for child in typed_children),
                width,
            ),
        )
    return canonicalize_ac_term(
        TypedBvTerm(expression.operation, width, children=typed_children)
    )


def _unsigned_frozen_constraint_value(
    term: TypedBvTerm | _UnboundFrozenConstraintTerm,
    *,
    width: int,
) -> int | None:
    if not isinstance(term, TypedBvTerm):
        return None
    if term.width != width or term.operation is not None or term.value is None:
        return None
    return int(term.value) & ((1 << width) - 1)


def _compare_frozen_constraint_terms(
    operation: str,
    left: TypedBvTerm,
    right: TypedBvTerm,
    *,
    width: int,
) -> bool:
    if operation == "eq":
        return left == right
    if operation == "ne":
        left_value = _unsigned_frozen_constraint_value(left, width=width)
        right_value = _unsigned_frozen_constraint_value(right, width=width)
        if left_value is not None and right_value is not None:
            return left_value != right_value
        return left != right
    left_value = _unsigned_frozen_constraint_value(left, width=width)
    right_value = _unsigned_frozen_constraint_value(right, width=width)
    if left_value is None or right_value is None:
        return False
    match operation:
        case "lt":
            return left_value < right_value
        case "gt":
            return left_value > right_value
        case "le":
            return left_value <= right_value
        case "ge":
            return left_value >= right_value
        case _:
            raise ValueError(f"unsupported comparison operation: {operation}")


def _evaluate_frozen_constraint(
    constraint: FrozenConstraint,
    bindings: dict[str, TypedBvTerm],
    *,
    width: int,
) -> bool:
    if constraint.operation in {"and", "or"}:
        left_constraint, right_constraint = constraint.children
        if constraint.operation == "and":
            attempted = dict(bindings)
            if not _evaluate_frozen_constraint(
                left_constraint, attempted, width=width
            ):
                return False
            if not _evaluate_frozen_constraint(
                right_constraint, attempted, width=width
            ):
                return False
            bindings.update(attempted)
            return True
        for branch in (left_constraint, right_constraint):
            attempted = dict(bindings)
            if _evaluate_frozen_constraint(branch, attempted, width=width):
                bindings.update(attempted)
                return True
        return False
    if constraint.operation == "not":
        return not _evaluate_frozen_constraint(
            constraint.children[0], dict(bindings), width=width
        )
    if constraint.left is None or constraint.right is None:
        return False
    left = _evaluate_frozen_constraint_expression(
        constraint.left,
        bindings,
        width=width,
    )
    right = _evaluate_frozen_constraint_expression(
        constraint.right,
        bindings,
        width=width,
    )
    if isinstance(left, _UnboundFrozenConstraintTerm):
        if constraint.operation != "eq" or isinstance(
            right, _UnboundFrozenConstraintTerm
        ):
            return False
        bindings[left.name] = right
        return True
    if isinstance(right, _UnboundFrozenConstraintTerm):
        if constraint.operation != "eq":
            return False
        bindings[right.name] = left
        return True
    return _compare_frozen_constraint_terms(
        constraint.operation,
        left,
        right,
        width=width,
    )


def evaluate_frozen_constraints(
    constraints: tuple[FrozenConstraint, ...],
    bindings: dict[str, TypedBvTerm],
    *,
    width: int,
) -> bool:
    """Evaluate pre-frozen constraints without touching symbolic DSL nodes."""

    for constraint in constraints:
        try:
            matched = _evaluate_frozen_constraint(constraint, bindings, width=width)
        except (TypeError, ValueError):
            return False
        if not matched:
            return False
    return True


def _placeholder(term: TypedBvTerm) -> PatternLeafKey | None:
    if term.operation is not None or term.leaf_key is None:
        return None
    if (
        len(term.leaf_key) == 2
        and term.leaf_key[0] in {"pattern_var", "pattern_const"}
        and type(term.leaf_key[1]) is str
    ):
        return (str(term.leaf_key[0]), str(term.leaf_key[1]))
    return None


def match_canonical_term_pattern(
    compiled_pattern: CanonicalCompiledPattern,
    candidate: TypedBvTerm,
    *,
    comparison_budget: int,
) -> CanonicalPatternMatchReport:
    """Compatibility wrapper for the single matcher core in ``ac_matching``."""

    from d810.mba.ac_matching import match_canonical_term_pattern as match_shared

    return match_shared(
        compiled_pattern,
        candidate,
        comparison_budget=comparison_budget,
    )


def _materialize_template(
    term: TypedBvTerm,
    bindings: Mapping[str, TypedBvTerm],
) -> TypedBvTerm:
    placeholder = _placeholder(term)
    if placeholder is not None:
        try:
            return bindings[placeholder[1]]
        except KeyError as exc:
            raise ValueError(f"unbound canonical placeholder: {placeholder[1]}") from exc
    if term.operation is None:
        return term
    return TypedBvTerm(
        term.operation,
        term.width,
        children=tuple(_materialize_template(child, bindings) for child in term.children),
    )


def canonical_template_payload(compiled_pattern: CanonicalCompiledPattern) -> dict[str, object]:
    """Return a stable JSON-safe snapshot fragment for one width."""

    return {
        "width": compiled_pattern.width,
        "pattern": term_fingerprint(compiled_pattern.pattern_term),
        "replacement": term_fingerprint(compiled_pattern.replacement_template),
        "terminal_kinds": [
            [key[0], key[1], kind]
            for key, kind in sorted(compiled_pattern.terminal_kinds.items())
        ],
        "semantic_fingerprint": compiled_pattern.semantic_fingerprint,
        "declaration_index": compiled_pattern.declaration_index,
    }


__all__ = [
    "CanonicalCompiledPattern",
    "CanonicalFixedBindings",
    "CanonicalPatternMatch",
    "CanonicalPatternMatchReport",
    "CanonicalPatternMatchResult",
    "CanonicalPatternMalformed",
    "CanonicalPatternUnsupported",
    "FrozenConstraint",
    "FrozenConstraintExpression",
    "PatternLeafKey",
    "canonical_rule_fingerprint",
    "canonical_template_payload",
    "compile_canonical_pattern",
    "evaluate_frozen_constraints",
    "lower_symbolic_template",
    "match_canonical_term_pattern",
]
