"""Portable certification and typed-term application for MBA rules.

This module has no provider runtime dependency. It admits verified rule
objects, preserves deterministic declaration receipts, and materializes
provider-neutral fixed-width terms.
"""

from __future__ import annotations

import enum
import functools
import weakref
from collections.abc import Collection, Iterator
from dataclasses import dataclass, replace
from types import MappingProxyType

from d810.core.typing import Any, Mapping
from d810.mba.backend_registry import get_verification_engine
from d810.mba.dsl import SymbolicExpressionProtocol
from d810.mba.typed_term import TypedBvTerm, canonicalize_ac_term
from d810.mba.rules._base import VerifiableRule
from d810.mba.rules.add import ADD_RULE_CLASSES
from d810.mba.rules.catalogue import (
    FAMILY_REJECTION_REASONS,
    MBA_RULE_FAMILIES,
)

_PORTABLE_FAMILIES = frozenset(
    {"add", "xor", "sub", "and", "or", "bnot", "neg", "mul"}
)
CERTIFICATE_WIDTHS = (8, 16, 32, 64)

_SUPPORTED_OPERATIONS = frozenset(
    {
        "add",
        "and",
        "bnot",
        "mul",
        "neg",
        "or",
        "rol",
        "ror",
        "sub",
        "xor",
    }
)
_UNARY_OPERATIONS = frozenset({"bnot", "neg"})
_FIXED_ROTATE_OPERATIONS = frozenset({"rol", "ror"})
_AC_OPERATIONS = frozenset({"add", "and", "mul", "or", "xor"})
_SUPPORTED_COMPARISON_OPERATIONS = frozenset({"eq", "ne", "lt", "gt", "le", "ge"})


def _verification_engine() -> Any:
    """Resolve the pure Z3 verifier through the backend-neutral registry."""

    return get_verification_engine("z3")


def verify_rule(rule: Any, *, bit_width: int) -> bool:
    return _verification_engine().verify_rule(rule, bit_width=bit_width)


def create_z3_variables(names: set[str], *, bit_width: int) -> Mapping[str, Any]:
    return _verification_engine().create_z3_variables(names, bit_width)


def constraint_to_z3(
    constraint: Any,
    z3_vars: Mapping[str, Any],
    *,
    bit_width: int,
) -> Any:
    return _verification_engine().constraint_to_z3(
        constraint, z3_vars, bit_width
    )


class RuleCompilationStatus(enum.StrEnum):
    COMPILED = "compiled"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"


@dataclass(frozen=True)
class CompiledMbaRule:
    source_name: str
    aliases: tuple[str, ...]
    rule_type: type[VerifiableRule]
    proof_widths: tuple[int, ...]
    guarded: bool
    family: str = "add"

    @property
    def pattern(self) -> SymbolicExpressionProtocol:
        return self.rule_type().pattern

    @property
    def replacement(self) -> SymbolicExpressionProtocol:
        return self.rule_type().replacement

    @property
    def constraints(self) -> tuple[Any, ...]:
        return tuple(self.rule_type().CONSTRAINTS)


_ADMITTED_RULES_BY_ID: dict[
    int,
    weakref.ReferenceType[CompiledMbaRule],
] = {}




@dataclass(frozen=True)
class RuleCompilationReceipt:
    source_name: str
    status: RuleCompilationStatus
    canonical_name: str | None
    compiled_rule: CompiledMbaRule | None
    reason: str | None = None
    family: str = "add"

    @property
    def key(self) -> tuple[str, str]:
        return (self.family, self.source_name)


@dataclass(frozen=True)
class MbaRuleCatalogue:
    receipts: tuple[RuleCompilationReceipt, ...]

    @property
    def entries(self) -> tuple[RuleCompilationReceipt, ...]:
        return self.receipts

    @property
    def compiled_rules(self) -> tuple[CompiledMbaRule, ...]:
        return tuple(
            receipt.compiled_rule
            for receipt in self.receipts
            if receipt.status is RuleCompilationStatus.COMPILED
            and receipt.compiled_rule is not None
        )

    @property
    def receipts_by_key(self) -> Mapping[tuple[str, str], RuleCompilationReceipt]:
        return MappingProxyType({receipt.key: receipt for receipt in self.receipts})

    def receipt_for(
        self, family: str, source_name: str | None = None
    ) -> RuleCompilationReceipt:
        add_compat_lookup = source_name is None
        if source_name is None:
            if any(receipt.family != "add" for receipt in self.receipts):
                raise TypeError(
                    "whole-corpus receipt lookup requires family and source_name"
                )
            source_name = family
            family = "add"
        for receipt in self.receipts:
            if receipt.family == family and receipt.source_name == source_name:
                return receipt
        if add_compat_lookup:
            raise KeyError(source_name)
        raise KeyError((family, source_name))




def _fixed_rotate_count(expression: Any, *, bit_width: int | None = None) -> int:
    count_node = expression.right
    if (
        count_node is None
        or count_node.operation is not None
        or count_node.left is not None
        or count_node.right is not None
        or type(count_node.value) is not int
        or not bool(getattr(count_node, "is_pattern_constant", False))
    ):
        raise ValueError(
            f"fixed {expression.operation} requires a literal count"
        )
    count = count_node.value
    if count < 0:
        raise ValueError(f"fixed {expression.operation} count must be non-negative")
    if bit_width is not None:
        if bit_width not in CERTIFICATE_WIDTHS:
            raise ValueError(f"unsupported fixed-rotate width: {bit_width}")
        if count >= bit_width:
            raise ValueError(
                f"fixed {expression.operation} count {count} is outside {bit_width}-bit width"
            )
    return count


def _validate_fixed_rotate_widths(expression: Any, *, bit_width: int) -> None:
    if not isinstance(expression, SymbolicExpressionProtocol):
        raise ValueError(
            f"expected symbolic expression, got {type(expression).__name__}"
        )
    if expression.operation is None:
        return
    if expression.operation in _FIXED_ROTATE_OPERATIONS:
        _fixed_rotate_count(expression, bit_width=bit_width)
        _validate_fixed_rotate_widths(expression.left, bit_width=bit_width)
        return
    if expression.left is not None:
        _validate_fixed_rotate_widths(expression.left, bit_width=bit_width)
    if expression.right is not None:
        _validate_fixed_rotate_widths(expression.right, bit_width=bit_width)


def _expression_fingerprint(expression: Any) -> tuple[Any, ...]:
    if not isinstance(expression, SymbolicExpressionProtocol):
        raise ValueError(
            f"expected symbolic expression, got {type(expression).__name__}"
        )

    operation = expression.operation
    if operation is None:
        if (
            not expression.is_leaf()
            or expression.left is not None
            or expression.right is not None
        ):
            raise ValueError("malformed symbolic expression leaf")
        return (
            "leaf",
            expression.name,
            expression.value,
            bool(getattr(expression, "is_pattern_constant", False)),
        )
    if operation not in _SUPPORTED_OPERATIONS:
        raise ValueError(f"unsupported expression operation: {operation}")
    if expression.is_leaf() or expression.left is None:
        raise ValueError(f"malformed {operation} expression")
    if operation in _FIXED_ROTATE_OPERATIONS:
        return (
            "fixed_operation",
            operation,
            _fixed_rotate_count(expression),
            _expression_fingerprint(expression.left),
        )
    if operation in _UNARY_OPERATIONS:
        if expression.right is not None:
            raise ValueError(f"malformed unary {operation} expression")
    elif expression.right is None:
        raise ValueError(f"malformed binary {operation} expression")
    return (
        "operation",
        operation,
        expression.name,
        expression.value,
        bool(getattr(expression, "is_pattern_constant", False)),
        _expression_fingerprint(expression.left),
        (
            None
            if expression.right is None
            else _expression_fingerprint(expression.right)
        ),
    )


def _constraint_fingerprint(constraint: Any) -> tuple[Any, ...]:
    if hasattr(constraint, "op_name"):
        if constraint.op_name not in _SUPPORTED_COMPARISON_OPERATIONS:
            raise ValueError(
                f"unsupported comparison constraint operation: {constraint.op_name}"
            )
        return (
            type(constraint).__name__,
            constraint.op_name,
            _expression_fingerprint(constraint.left),
            _expression_fingerprint(constraint.right),
        )
    if hasattr(constraint, "left") and hasattr(constraint, "right"):
        left = constraint.left
        right = constraint.right
        if hasattr(left, "operation") or left is None:
            return (
                type(constraint).__name__,
                _expression_fingerprint(left),
                _expression_fingerprint(right),
            )
        return (
            type(constraint).__name__,
            _constraint_fingerprint(left),
            _constraint_fingerprint(right),
        )
    if hasattr(constraint, "operand"):
        return (type(constraint).__name__, _constraint_fingerprint(constraint.operand))
    raise ValueError(f"unsupported constraint type: {type(constraint).__name__}")


def _rule_fingerprint(rule: VerifiableRule) -> tuple[Any, ...]:
    return (
        _expression_fingerprint(rule.pattern),
        _expression_fingerprint(rule.replacement),
        tuple(_constraint_fingerprint(item) for item in rule.CONSTRAINTS),
    )


def _enroll_admitted_rule(rule: CompiledMbaRule) -> CompiledMbaRule:
    rule_id = id(rule)

    def discard(reference: weakref.ReferenceType[CompiledMbaRule]) -> None:
        if _ADMITTED_RULES_BY_ID.get(rule_id) is reference:
            _ADMITTED_RULES_BY_ID.pop(rule_id, None)

    _ADMITTED_RULES_BY_ID[rule_id] = weakref.ref(rule, discard)
    return rule


def is_admitted_compiled_rule(rule: object) -> bool:
    """Accept only the exact canonical object enrolled by this module load."""

    if type(rule) is not CompiledMbaRule:
        return False
    enrolled = _ADMITTED_RULES_BY_ID.get(id(rule))
    return enrolled is not None and enrolled() is rule


def require_admitted_compiled_rules(
    rules: Collection[object],
) -> tuple[CompiledMbaRule, ...]:
    """Freeze an existing admitted rule sequence for downstream projections.

    This is deliberately only an identity/admission check.  It does not
    instantiate rule classes, verify Z3 schemas, or create another inventory.
    """

    frozen = tuple(rules)
    if any(not is_admitted_compiled_rule(rule) for rule in frozen):
        raise ValueError("compiled pattern catalogue requires admitted rules")
    return tuple(frozen)  # type: ignore[return-value]


def _expression_symbolic_names(expression: Any) -> set[str]:
    _expression_fingerprint(expression)
    if expression.operation is None:
        if expression.value is None and expression.name:
            return {expression.name}
        return set()
    names = _expression_symbolic_names(expression.left)
    if expression.right is not None:
        names.update(_expression_symbolic_names(expression.right))
    return names


def _constraint_symbolic_names(constraint: Any) -> set[str]:
    if hasattr(constraint, "op_name"):
        return _expression_symbolic_names(constraint.left) | _expression_symbolic_names(
            constraint.right
        )
    if hasattr(constraint, "left") and hasattr(constraint, "right"):
        if isinstance(constraint.left, SymbolicExpressionProtocol):
            return _expression_symbolic_names(
                constraint.left
            ) | _expression_symbolic_names(constraint.right)
        return _constraint_symbolic_names(constraint.left) | _constraint_symbolic_names(
            constraint.right
        )
    if hasattr(constraint, "operand"):
        return _constraint_symbolic_names(constraint.operand)
    raise ValueError(f"unsupported constraint type: {type(constraint).__name__}")


def _validate_declarative_constraints(rule: VerifiableRule, bit_width: int) -> None:
    names = _expression_symbolic_names(rule.pattern)
    names.update(_expression_symbolic_names(rule.replacement))
    for constraint in rule.CONSTRAINTS:
        names.update(_constraint_symbolic_names(constraint))
    z3_vars = create_z3_variables(names, bit_width=bit_width)
    for constraint in rule.CONSTRAINTS:
        constraint_to_z3(constraint, z3_vars, bit_width=bit_width)


def _compile_rule_families(
    rule_families: Mapping[str, tuple[type[VerifiableRule], ...]],
) -> MbaRuleCatalogue:
    family_names = set(rule_families)
    rejection_family_names = set(FAMILY_REJECTION_REASONS)
    conflicting_families = sorted(
        family_names & _PORTABLE_FAMILIES & rejection_family_names
    )
    if conflicting_families:
        raise ValueError(
            "conflicting MBA rule family policies: " + ", ".join(conflicting_families)
        )
    unclassified_families = sorted(
        family_names - _PORTABLE_FAMILIES - rejection_family_names
    )
    if unclassified_families:
        raise ValueError(
            "unclassified MBA rule families: " + ", ".join(unclassified_families)
        )

    canonical_by_fingerprint: dict[tuple[Any, ...], CompiledMbaRule] = {}
    staged_receipts: list[
        tuple[str, str, RuleCompilationStatus, str | None, str | None]
    ] = []

    for family, rule_types in rule_families.items():
        family_rejection_reason = FAMILY_REJECTION_REASONS.get(family)
        for rule_type in rule_types:
            source_name = rule_type.__name__
            if rule_type.get_constraints is not VerifiableRule.get_constraints:
                staged_receipts.append(
                    (
                        family,
                        source_name,
                        RuleCompilationStatus.REJECTED,
                        None,
                        "custom get_constraints is not portable",
                    )
                )
                continue
            if family_rejection_reason is not None:
                staged_receipts.append(
                    (
                        family,
                        source_name,
                        RuleCompilationStatus.REJECTED,
                        None,
                        family_rejection_reason,
                    )
                )
                continue
            if getattr(rule_type, "SKIP_VERIFICATION", False):
                staged_receipts.append(
                    (
                        family,
                        source_name,
                        RuleCompilationStatus.REJECTED,
                        None,
                        "verification skipped",
                    )
                )
                continue

            try:
                rule = rule_type()
                fingerprint = (family, _rule_fingerprint(rule))
                canonical = canonical_by_fingerprint.get(fingerprint)
                if canonical is not None:
                    canonical_by_fingerprint[fingerprint] = replace(
                        canonical, aliases=canonical.aliases + (source_name,)
                    )
                    staged_receipts.append(
                        (
                            family,
                            source_name,
                            RuleCompilationStatus.DUPLICATE,
                            canonical.source_name,
                            None,
                        )
                    )
                    continue

                for width in CERTIFICATE_WIDTHS:
                    _validate_fixed_rotate_widths(rule.pattern, bit_width=width)
                    _validate_fixed_rotate_widths(rule.replacement, bit_width=width)
                    _validate_declarative_constraints(rule, width)
                    if not verify_rule(rule, bit_width=width):
                        raise ValueError(f"verification returned false at {width} bits")
            except (AssertionError, TypeError, ValueError) as exc:
                staged_receipts.append(
                    (
                        family,
                        source_name,
                        RuleCompilationStatus.REJECTED,
                        None,
                        str(exc),
                    )
                )
                continue

            canonical_by_fingerprint[fingerprint] = CompiledMbaRule(
                family=family,
                source_name=source_name,
                aliases=(),
                rule_type=rule_type,
                proof_widths=CERTIFICATE_WIDTHS,
                guarded=bool(rule.CONSTRAINTS),
            )
            staged_receipts.append(
                (
                    family,
                    source_name,
                    RuleCompilationStatus.COMPILED,
                    source_name,
                    None,
                )
            )

    canonical_by_fingerprint = {
        fingerprint: _enroll_admitted_rule(compiled)
        for fingerprint, compiled in canonical_by_fingerprint.items()
    }
    compiled_by_name = {
        (compiled.family, compiled.source_name): compiled
        for compiled in canonical_by_fingerprint.values()
    }
    receipts = tuple(
        RuleCompilationReceipt(
            family=family,
            source_name=source_name,
            status=status,
            canonical_name=canonical_name,
            compiled_rule=(
                compiled_by_name.get((family, canonical_name))
                if canonical_name is not None
                else None
            ),
            reason=reason,
        )
        for family, source_name, status, canonical_name, reason in staged_receipts
    )
    return MbaRuleCatalogue(receipts)


def compile_mba_rule_catalogue() -> MbaRuleCatalogue:
    declaration_version = tuple(
        (family, tuple(rule_types)) for family, rule_types in MBA_RULE_FAMILIES.items()
    )
    return _compile_selected_rule_catalogue(
        tuple(MBA_RULE_FAMILIES),
        declaration_version,
    )


@functools.lru_cache(maxsize=32)
def _compile_selected_rule_catalogue(
    families: tuple[str, ...],
    declaration_version: tuple[tuple[str, tuple[type[VerifiableRule], ...]], ...],
) -> MbaRuleCatalogue:
    """Cache immutable certificates, never mutable provider-specific runtime state."""
    rule_families = dict(declaration_version)
    if families == ("add",):
        return MbaRuleCatalogue(_compile_rule_families(rule_families).receipts)
    return _compile_rule_families(rule_families)


def compiled_rules_for_families(
    families: Collection[str],
) -> tuple[CompiledMbaRule, ...]:
    requested = frozenset(families)
    unknown = sorted(requested - set(MBA_RULE_FAMILIES))
    if unknown:
        raise ValueError("unknown MBA rule families: " + ", ".join(unknown))

    canonical_families = tuple(
        family for family in MBA_RULE_FAMILIES if family in requested
    )
    declaration_version = tuple(
        (family, tuple(MBA_RULE_FAMILIES[family])) for family in canonical_families
    )
    catalogue = _compile_selected_rule_catalogue(
        canonical_families,
        declaration_version,
    )
    compiled_families = {rule.family for rule in catalogue.compiled_rules}
    receipts_only = sorted(requested - compiled_families)
    if receipts_only:
        raise ValueError(
            "MBA rule families have no compiled rules: " + ", ".join(receipts_only)
        )

    return tuple(rule for rule in catalogue.compiled_rules if rule.family in requested)


def compile_add_rule_catalogue() -> MbaRuleCatalogue:
    return _compile_selected_rule_catalogue(
        ("add",),
        (("add", tuple(ADD_RULE_CLASSES)),),
    )


def executable_rule_order_key(
    rule: CompiledMbaRule,
) -> tuple[str, str, tuple[str, ...]]:
    """Return the stable executable/provenance order for bounded extraction."""

    return (rule.family, rule.source_name, tuple(rule.aliases))


def _flatten_symbolic_ac(expression: Any, operation: str) -> tuple[Any, ...]:
    if getattr(expression, "operation", None) != operation:
        return (expression,)
    flattened: list[Any] = []
    flattened.extend(_flatten_symbolic_ac(expression.left, operation))
    flattened.extend(_flatten_symbolic_ac(expression.right, operation))
    return tuple(flattened)


def _flatten_term_ac(term: Any, operation: str) -> tuple[Any, ...]:
    if term.operation != operation:
        return (term,)
    flattened: list[Any] = []
    for child in term.children:
        flattened.extend(_flatten_term_ac(child, operation))
    return tuple(flattened)


def _iter_symbolic_term_matches(
    expression: Any,
    term: Any,
    bindings: dict[str, Any],
) -> Iterator[dict[str, Any]]:
    """Yield every deterministic binding environment for one symbolic match."""

    operation = expression.operation
    if operation is None:
        name = expression.name
        if not name:
            return
        if bool(getattr(expression, "is_pattern_constant", False)):
            if term.operation is not None or term.value is None:
                return
        if expression.value is not None:
            if term.operation is not None or term.value is None:
                return
            mask = (1 << term.width) - 1
            if term.value != (int(expression.value) & mask):
                return
        existing = bindings.get(name)
        if existing is not None:
            if existing == term:
                yield bindings
            return
        matched = dict(bindings)
        matched[name] = term
        yield matched
        return

    if operation != term.operation:
        return
    if operation in _FIXED_ROTATE_OPERATIONS:
        if (
            len(term.children) != 1
            or term.shift_count
            != _fixed_rotate_count(expression, bit_width=term.width)
        ):
            return
        yield from _iter_symbolic_term_matches(
            expression.left,
            term.children[0],
            bindings,
        )
        return
    if operation in _AC_OPERATIONS:
        pattern_items = _flatten_symbolic_ac(expression, operation)
        term_items = _flatten_term_ac(term, operation)
        if len(pattern_items) != len(term_items):
            return

        def match_items(
            index: int,
            remaining: tuple[Any, ...],
            current: dict[str, Any],
        ) -> Iterator[dict[str, Any]]:
            if index == len(pattern_items):
                if not remaining:
                    yield current
                return
            pattern_item = pattern_items[index]
            for candidate_index, candidate_item in enumerate(remaining):
                for attempted in _iter_symbolic_term_matches(
                    pattern_item,
                    candidate_item,
                    current,
                ):
                    yield from match_items(
                        index + 1,
                        remaining[:candidate_index] + remaining[candidate_index + 1 :],
                        attempted,
                    )

        yield from match_items(0, term_items, dict(bindings))
        return

    if expression.left is None or not term.children:
        return
    for left_bindings in _iter_symbolic_term_matches(
        expression.left,
        term.children[0],
        bindings,
    ):
        if operation in _UNARY_OPERATIONS:
            if expression.right is None and len(term.children) == 1:
                yield left_bindings
            continue
        if expression.right is None or len(term.children) != 2:
            continue
        yield from _iter_symbolic_term_matches(
            expression.right,
            term.children[1],
            left_bindings,
        )


@dataclass(frozen=True)
class _UnboundSymbolicTerm:
    name: str


def _constant_fold(operation: str, values: tuple[int, ...], width: int) -> int:
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
        raise ValueError(f"unsupported constraint operation: {operation}")
    return result & mask


def _evaluate_constraint_expression(
    expression: Any,
    bindings: dict[str, Any],
    *,
    width: int,
) -> Any:

    if not isinstance(expression, SymbolicExpressionProtocol):
        if type(expression) is int:
            return TypedBvTerm(operation=None, width=width, value=expression)
        raise ValueError("unsupported non-symbolic constraint expression")
    if expression.operation is None:
        if expression.name and expression.name in bindings:
            return bindings[expression.name]
        if expression.value is not None:
            return TypedBvTerm(
                operation=None,
                width=width,
                value=int(expression.value),
            )
        if expression.name:
            return _UnboundSymbolicTerm(expression.name)
        raise ValueError("unnamed constraint expression")

    if expression.operation in _FIXED_ROTATE_OPERATIONS:
        left = _evaluate_constraint_expression(
            expression.left,
            bindings,
            width=width,
        )
        if isinstance(left, _UnboundSymbolicTerm):
            raise ValueError("nested unbound constraint expression")
        return TypedBvTerm(
            operation=expression.operation,
            width=width,
            children=(left,),
            shift_count=_fixed_rotate_count(expression, bit_width=width),
        )

    left = _evaluate_constraint_expression(expression.left, bindings, width=width)
    right = (
        _evaluate_constraint_expression(expression.right, bindings, width=width)
        if expression.right is not None
        else None
    )
    if isinstance(left, _UnboundSymbolicTerm) or isinstance(
        right, _UnboundSymbolicTerm
    ):
        raise ValueError("nested unbound constraint expression")
    children = (left,) if right is None else (left, right)
    if all(child.operation is None and child.value is not None for child in children):
        return TypedBvTerm(
            operation=None,
            width=width,
            value=_constant_fold(
                expression.operation,
                tuple(int(child.value) for child in children),
                width,
            ),
        )
    return canonicalize_ac_term(
        TypedBvTerm(
            operation=expression.operation,
            width=width,
            children=children,
        )
    )


def _constraint_operation(constraint: Any) -> str:
    comparison = getattr(constraint, "op_name", None)
    if comparison is not None:
        if comparison not in _SUPPORTED_COMPARISON_OPERATIONS - {"eq"}:
            raise ValueError(f"unsupported comparison operation: {comparison}")
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
    raise ValueError(f"unsupported constraint type: {type(constraint).__name__}")


def _unsigned_constraint_value(term: Any, *, width: int) -> int | None:
    if not isinstance(term, TypedBvTerm):
        return None
    if term.width != width or term.operation is not None or term.value is None:
        return None
    return int(term.value) & ((1 << width) - 1)


def _compare_constraint_terms(
    operation: str,
    left: Any,
    right: Any,
    *,
    width: int,
) -> bool:
    if operation == "eq":
        return left == right
    if operation == "ne":
        left_value = _unsigned_constraint_value(left, width=width)
        right_value = _unsigned_constraint_value(right, width=width)
        if left_value is not None and right_value is not None:
            return left_value != right_value
        return left != right
    left_value = _unsigned_constraint_value(left, width=width)
    right_value = _unsigned_constraint_value(right, width=width)
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


def _match_constraint(
    constraint: Any,
    bindings: dict[str, Any],
    *,
    width: int,
) -> bool:
    operation = _constraint_operation(constraint)
    if operation in {"and", "or"}:
        left_constraint = getattr(constraint, "left", None)
        right_constraint = getattr(constraint, "right", None)
        if left_constraint is None or right_constraint is None:
            return False
        if operation == "and":
            attempted = dict(bindings)
            if not _match_constraint(left_constraint, attempted, width=width):
                return False
            if not _match_constraint(right_constraint, attempted, width=width):
                return False
            bindings.update(attempted)
            return True
        for branch in (left_constraint, right_constraint):
            attempted = dict(bindings)
            if _match_constraint(branch, attempted, width=width):
                bindings.update(attempted)
                return True
        return False
    if operation == "not":
        operand = getattr(constraint, "operand", None)
        if operand is None:
            return False
        return not _match_constraint(operand, dict(bindings), width=width)

    left_expression = getattr(constraint, "left", None)
    right_expression = getattr(constraint, "right", None)
    if left_expression is None or right_expression is None:
        return False
    try:
        left = _evaluate_constraint_expression(
            left_expression,
            bindings,
            width=width,
        )
        right = _evaluate_constraint_expression(
            right_expression,
            bindings,
            width=width,
        )
    except (TypeError, ValueError):
        return False
    if operation == "eq":
        if isinstance(left, _UnboundSymbolicTerm):
            if isinstance(right, _UnboundSymbolicTerm):
                return False
            bindings[left.name] = right
            return True
        if isinstance(right, _UnboundSymbolicTerm):
            bindings[right.name] = left
            return True
    elif isinstance(left, _UnboundSymbolicTerm) or isinstance(
        right, _UnboundSymbolicTerm
    ):
        return False
    return _compare_constraint_terms(operation, left, right, width=width)


def _constraints_match_term(
    rule: CompiledMbaRule,
    bindings: dict[str, Any],
    *,
    width: int,
) -> bool:
    for constraint in rule.constraints:
        try:
            matched = _match_constraint(constraint, bindings, width=width)
        except (TypeError, ValueError):
            return False
        if not matched:
            return False
    return True


def _materialize_symbolic_term(
    expression: Any,
    bindings: dict[str, Any],
    *,
    width: int,
) -> Any:

    if expression.operation is None:
        if expression.name and expression.name in bindings:
            return bindings[expression.name]
        if expression.value is None:
            raise ValueError(f"unbound symbolic leaf: {expression.name}")
        return TypedBvTerm(
            operation=None,
            width=width,
            value=int(expression.value),
        )
    if expression.left is None:
        raise ValueError("operator expression has no left child")
    left = _materialize_symbolic_term(expression.left, bindings, width=width)
    if expression.operation in _FIXED_ROTATE_OPERATIONS:
        return TypedBvTerm(
            operation=expression.operation,
            width=width,
            children=(left,),
            shift_count=_fixed_rotate_count(expression, bit_width=width),
        )
    right = (
        _materialize_symbolic_term(expression.right, bindings, width=width)
        if expression.right is not None
        else None
    )
    children = (left,) if right is None else (left, right)
    return canonicalize_ac_term(
        TypedBvTerm(
            operation=expression.operation,
            width=width,
            children=children,
        )
    )


def apply_compiled_rule_to_term(
    rule: CompiledMbaRule,
    term: Any,
) -> Any | None:
    """Ground one certified catalogue application without native AST fallback.

    The matcher implements the compiler's existing declarative constant and
    complement constraints over ``TypedBvTerm``.  It does not admit new rule
    schemas and never calls the legacy per-rule provider-specific specialization path.
    """

    if not is_admitted_compiled_rule(rule):
        return None
    if term.width not in rule.proof_widths:
        return None
    for bindings in _iter_symbolic_term_matches(rule.pattern, term, {}):
        constrained_bindings = dict(bindings)
        if not _constraints_match_term(
            rule,
            constrained_bindings,
            width=term.width,
        ):
            continue
        try:
            replacement = _materialize_symbolic_term(
                rule.replacement,
                constrained_bindings,
                width=term.width,
            )
        except (TypeError, ValueError):
            continue
        if replacement.width == term.width:
            return replacement
    return None
