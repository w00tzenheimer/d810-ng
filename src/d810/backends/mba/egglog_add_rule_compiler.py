"""Pure certificate catalogue for ADD rules that can be lowered to Egglog.

Canonical structural templates consume the admitted objects produced here;
they never reconstruct a second rule inventory or re-run proof compilation.
"""

from __future__ import annotations

import enum
import functools
import importlib
import weakref
from collections.abc import Collection, Iterator
from dataclasses import dataclass, replace
from types import MappingProxyType

from d810.backends.mba.z3 import constraint_to_z3, create_z3_variables, verify_rule
from d810.core.typing import Any, Mapping
from d810.mba.dsl import SymbolicExpressionProtocol
from d810.mba.rules._base import VerifiableRule
from d810.mba.rules.add import ADD_RULE_CLASSES
from d810.mba.rules.catalogue import (
    EGGLOG_CLOSED_FAMILIES,
    FAMILY_REJECTION_REASONS,
    MBA_RULE_FAMILIES,
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
        "sub",
        "xor",
    }
)
_UNARY_OPERATIONS = frozenset({"bnot", "neg"})
_AC_OPERATIONS = frozenset({"add", "and", "mul", "or", "xor"})
_SUPPORTED_COMPARISON_OPERATIONS = frozenset({"ne", "lt", "gt", "le", "ge"})


class RuleCompilationStatus(enum.StrEnum):
    COMPILED = "compiled"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"


@dataclass(frozen=True)
class CompiledEgglogAddRule:
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


CompiledEgglogRule = CompiledEgglogAddRule
_ADMITTED_RULES_BY_ID: dict[
    int,
    weakref.ReferenceType[CompiledEgglogAddRule],
] = {}


@dataclass(frozen=True)
class EgglogAddSpecialization:
    rule: CompiledEgglogAddRule
    candidate_ast: AstNode
    replacement_ast: AstNode
    bindings: dict[str, AstBase]
    rounds: int = 6

    @property
    def source_names(self) -> tuple[str, ...]:
        return (self.rule.source_name, *self.rule.aliases)

    @property
    def family(self) -> str:
        return self.rule.family


EgglogMbaSpecialization = EgglogAddSpecialization


@dataclass(frozen=True)
class RuleCompilationReceipt:
    source_name: str
    status: RuleCompilationStatus
    canonical_name: str | None
    compiled_rule: CompiledEgglogAddRule | None
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
    def compiled_rules(self) -> tuple[CompiledEgglogRule, ...]:
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


@dataclass(frozen=True)
class AddRuleCatalogue(MbaRuleCatalogue):
    """Backward-compatible ADD-only view of the MBA catalogue."""


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


def _enroll_admitted_rule(rule: CompiledEgglogRule) -> CompiledEgglogRule:
    rule_id = id(rule)

    def discard(reference: weakref.ReferenceType[CompiledEgglogAddRule]) -> None:
        if _ADMITTED_RULES_BY_ID.get(rule_id) is reference:
            _ADMITTED_RULES_BY_ID.pop(rule_id, None)

    _ADMITTED_RULES_BY_ID[rule_id] = weakref.ref(rule, discard)
    return rule


def is_admitted_compiled_rule(rule: object) -> bool:
    """Accept only the exact canonical object enrolled by this module load."""

    if type(rule) is not CompiledEgglogAddRule:
        return False
    enrolled = _ADMITTED_RULES_BY_ID.get(id(rule))
    return enrolled is not None and enrolled() is rule


def require_admitted_compiled_rules(
    rules: Collection[object],
) -> tuple[CompiledEgglogRule, ...]:
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
        family_names & EGGLOG_CLOSED_FAMILIES & rejection_family_names
    )
    if conflicting_families:
        raise ValueError(
            "conflicting MBA rule family policies: " + ", ".join(conflicting_families)
        )
    unclassified_families = sorted(
        family_names - EGGLOG_CLOSED_FAMILIES - rejection_family_names
    )
    if unclassified_families:
        raise ValueError(
            "unclassified MBA rule families: " + ", ".join(unclassified_families)
        )

    canonical_by_fingerprint: dict[tuple[Any, ...], CompiledEgglogRule] = {}
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

            canonical_by_fingerprint[fingerprint] = CompiledEgglogRule(
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
    """Cache immutable certificates, never mutable Egglog runtime state."""
    rule_families = dict(declaration_version)
    if families == ("add",):
        return AddRuleCatalogue(_compile_rule_families(rule_families).receipts)
    return _compile_rule_families(rule_families)


def compiled_rules_for_families(
    families: Collection[str],
) -> tuple[CompiledEgglogRule, ...]:
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


def compile_add_rule_catalogue() -> AddRuleCatalogue:
    return _compile_selected_rule_catalogue(
        ("add",),
        (("add", tuple(ADD_RULE_CLASSES)),),
    )


def executable_rule_order_key(
    rule: CompiledEgglogRule,
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
    from d810.backends.mba.egglog_saturation import (
        TypedBvTerm,
        canonicalize_ac_term,
    )

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


def _constraints_match_term(
    rule: CompiledEgglogRule,
    bindings: dict[str, Any],
    *,
    width: int,
) -> bool:
    for constraint in rule.constraints:
        if not hasattr(constraint, "left") or not hasattr(constraint, "right"):
            return False
        try:
            left = _evaluate_constraint_expression(
                constraint.left,
                bindings,
                width=width,
            )
            right = _evaluate_constraint_expression(
                constraint.right,
                bindings,
                width=width,
            )
        except (TypeError, ValueError):
            return False
        if isinstance(left, _UnboundSymbolicTerm):
            if isinstance(right, _UnboundSymbolicTerm):
                return False
            bindings[left.name] = right
            continue
        if isinstance(right, _UnboundSymbolicTerm):
            bindings[right.name] = left
            continue
        if left != right:
            return False
    return True


def _materialize_symbolic_term(
    expression: Any,
    bindings: dict[str, Any],
    *,
    width: int,
) -> Any:
    from d810.backends.mba.egglog_saturation import (
        TypedBvTerm,
        canonicalize_ac_term,
    )

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
    rule: CompiledEgglogRule,
    term: Any,
) -> Any | None:
    """Ground one certified catalogue application without native AST fallback.

    The matcher implements the compiler's existing declarative constant and
    complement constraints over ``TypedBvTerm``.  It does not admit new rule
    schemas and never calls the legacy per-rule Egglog specialization path.
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


def canonical_pattern_catalogue_for_rules(rules: Collection[object]) -> Any:
    """Freeze one canonical template catalogue for admitted rules.

    The bounded saturation backend uses this bridge instead of rebuilding a
    symbolic rule inventory or registering algebraic identities in Egglog.
    Keeping the import local avoids a compiler/catalogue cycle at module load.
    """

    from d810.backends.mba.egglog_structural_rules import (
        CompiledEgglogStructuralRule,
        structural_catalogue_for_rules,
    )
    from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue

    frozen_rules = tuple(rules)
    if frozen_rules and all(
        type(rule) is CompiledEgglogStructuralRule for rule in frozen_rules
    ):
        return structural_catalogue_for_rules(frozen_rules)
    if any(type(rule) is CompiledEgglogStructuralRule for rule in frozen_rules):
        raise ValueError("canonical catalogue cannot mix structural and DSL rules")

    return CompiledPatternCatalogue.from_rules(
        require_admitted_compiled_rules(frozen_rules)
    )


_OPCODE_BY_OPERATION: dict[str, int] = {}
_OPERATION_BY_OPCODE: dict[int, str] = {}
_VALID_DESTINATION_SIZES = frozenset({1, 2, 4, 8})
_RUNTIME_AST_PROXY_MODULES = frozenset(
    {"d810.hexrays.expr.p_ast", "d810.speedups.expr.c_ast"}
)


def _ensure_runtime() -> None:
    if _OPCODE_BY_OPERATION:
        return
    global AstBase, AstConstant, AstLeaf, AstNode, ida_hexrays
    ida_hexrays = importlib.import_module("ida_hexrays")
    ast_module = importlib.import_module("d810.hexrays.expr.ast")
    AstBase = ast_module.AstBase
    AstConstant = ast_module.AstConstant
    AstLeaf = ast_module.AstLeaf
    AstNode = ast_module.AstNode

    _OPCODE_BY_OPERATION.update(
        {
            "add": ida_hexrays.m_add,
            "and": ida_hexrays.m_and,
            "bnot": ida_hexrays.m_bnot,
            "mul": ida_hexrays.m_mul,
            "neg": ida_hexrays.m_neg,
            "or": ida_hexrays.m_or,
            "sub": ida_hexrays.m_sub,
            "xor": ida_hexrays.m_xor,
        }
    )
    _OPERATION_BY_OPCODE.update(
        {opcode: operation for operation, opcode in _OPCODE_BY_OPERATION.items()}
    )


def _bitexpr_type():
    return importlib.import_module("d810.backends.mba.egglog_backend").BitExpr


def _leaf_size(leaf: AstLeaf) -> int:
    size = int(getattr(leaf, "size", 0) or 0)
    if not size:
        size = int(getattr(leaf, "expected_size", 0) or 0)
    if not size:
        size = int(getattr(leaf, "dest_size", 0) or 0)
    return size


def _ast_fingerprint(ast: AstBase) -> tuple[Any, ...]:
    if isinstance(ast, AstNode):
        return (
            "node",
            int(ast.opcode),
            _ast_fingerprint(ast.left) if ast.left is not None else None,
            _ast_fingerprint(ast.right) if ast.right is not None else None,
        )
    if isinstance(ast, AstConstant):
        return ("constant", _leaf_size(ast), int(ast.value))
    if isinstance(ast, AstLeaf):
        mop = getattr(ast, "mop", None)
        try:
            hash(mop)
            identity = mop
        except TypeError:
            identity = repr(mop)
        return ("leaf", _leaf_size(ast), identity)
    raise TypeError(type(ast).__name__)


def _candidate_is_supported(ast: AstBase, destination_size: int) -> bool:
    if isinstance(ast, AstNode):
        if ast.opcode not in _OPERATION_BY_OPCODE:
            return False
        node_size = int(getattr(ast, "dest_size", 0) or 0)
        if node_size and node_size != destination_size:
            return False
        if ast.left is None:
            return False
        if not _candidate_is_supported(ast.left, destination_size):
            return False
        if ast.opcode in (ida_hexrays.m_bnot, ida_hexrays.m_neg):
            return ast.right is None
        return ast.right is not None and _candidate_is_supported(
            ast.right, destination_size
        )
    if isinstance(ast, AstConstant):
        return type(ast.value) is int and _leaf_size(ast) == destination_size
    if not isinstance(ast, AstLeaf):
        return False
    return _leaf_size(ast) == destination_size


def _unwrap_runtime_ast(ast: Any) -> AstBase | None:
    """Unwrap live copy-on-write AST proxies without importing their class.

    ``AstProxy`` is a Hex-Rays-side adapter and can come from either the pure
    Python or Cython AST implementation.  The portable compiler recognizes
    only that exact adapter name and reads its private target directly, then
    validates the resulting runtime AST class.  Unknown wrappers, missing
    targets, proxy cycles, and nested proxy chains beyond the small defensive
    bound fail closed.
    """
    _ensure_runtime()
    current = ast
    seen: set[int] = set()
    for _ in range(4):
        current_type = type(current)
        if current_type.__name__ != "AstProxy":
            return current if isinstance(current, AstBase) else None
        if current_type.__module__ not in _RUNTIME_AST_PROXY_MODULES:
            return None
        identity = id(current)
        if identity in seen:
            return None
        seen.add(identity)
        try:
            current = object.__getattribute__(current, "_target")
        except (AttributeError, TypeError):
            return None
    return None


def bind_symbolic_pattern(
    pattern: SymbolicExpressionProtocol,
    candidate_ast: Any,
    destination_size: int,
) -> dict[str, AstBase] | None:
    _ensure_runtime()
    if destination_size not in _VALID_DESTINATION_SIZES:
        return None
    if not _candidate_is_supported(candidate_ast, destination_size):
        return None

    bindings: dict[str, AstBase] = {}

    def bind(expression: SymbolicExpressionProtocol, ast: AstBase) -> bool:
        if expression.operation is None:
            if not expression.name:
                return False
            is_pattern_constant = bool(
                getattr(expression, "is_pattern_constant", False)
            )
            if is_pattern_constant:
                if not isinstance(ast, AstConstant):
                    return False
                if type(ast.value) is not int:
                    return False
                if expression.value is not None:
                    mask = (1 << (destination_size * 8)) - 1
                    if int(ast.value) != (int(expression.value) & mask):
                        return False
            existing = bindings.get(expression.name)
            if existing is not None:
                return _ast_fingerprint(existing) == _ast_fingerprint(ast)
            bindings[expression.name] = ast
            return True

        if not isinstance(ast, AstNode):
            return False
        expected_opcode = _OPCODE_BY_OPERATION.get(expression.operation)
        if expected_opcode is None or ast.opcode != expected_opcode:
            return False
        if expression.left is None or ast.left is None:
            return False
        if not bind(expression.left, ast.left):
            return False
        if expression.operation in _UNARY_OPERATIONS:
            return expression.right is None and ast.right is None
        return (
            expression.right is not None
            and ast.right is not None
            and bind(expression.right, ast.right)
        )

    return bindings if bind(pattern, candidate_ast) else None


def _bnot_constraint_holds(
    constraint: Any, bindings: dict[str, AstBase], destination_size: int
) -> bool | None:
    left = getattr(constraint, "left", None)
    right = getattr(constraint, "right", None)
    if not isinstance(left, SymbolicExpressionProtocol):
        return None
    if not isinstance(right, SymbolicExpressionProtocol) or right.operation != "bnot":
        return None
    if not left.is_leaf() or not left.name or right.left is None or not right.left.name:
        return False
    left_ast = bindings.get(left.name)
    operand_ast = bindings.get(right.left.name)
    if left_ast is None or operand_ast is None:
        return False
    if isinstance(left_ast, AstConstant) and isinstance(operand_ast, AstConstant):
        mask = (1 << (destination_size * 8)) - 1
        return int(left_ast.value) == ((~int(operand_ast.value)) & mask)
    return (
        isinstance(left_ast, AstNode)
        and left_ast.opcode == ida_hexrays.m_bnot
        and left_ast.right is None
        and left_ast.left is not None
        and _ast_fingerprint(left_ast.left) == _ast_fingerprint(operand_ast)
    )


def constraints_hold(
    rule: CompiledEgglogAddRule,
    bindings: dict[str, AstBase],
    destination_size: int,
) -> bool:
    _ensure_runtime()
    context: dict[str, Any] = dict(bindings)
    context["_width"] = destination_size * 8
    for constraint in rule.constraints:
        name, value = constraint.eval_and_define(context)
        if name is not None:
            if value is None:
                return False
            mask = (1 << (destination_size * 8)) - 1
            derived = AstConstant(name, int(value) & mask, destination_size)
            derived.dest_size = destination_size
            bindings[name] = derived
            context[name] = derived
        bnot_result = _bnot_constraint_holds(constraint, bindings, destination_size)
        if bnot_result is not None:
            if not bnot_result:
                return False
        elif not constraint.check(context):
            return False
    return True


def materialize_symbolic_expression(
    expression: SymbolicExpressionProtocol,
    bindings: dict[str, AstBase],
    destination_size: int,
) -> AstBase:
    _ensure_runtime()
    if expression.operation is None:
        if not expression.name:
            raise ValueError("unnamed symbolic leaf")
        bound = bindings.get(expression.name)
        if bound is not None:
            return bound.clone()
        if expression.value is None:
            raise ValueError(f"unbound symbolic leaf: {expression.name}")
        mask = (1 << (destination_size * 8)) - 1
        constant = AstConstant(
            expression.name, int(expression.value) & mask, destination_size
        )
        constant.dest_size = destination_size
        return constant
    opcode = _OPCODE_BY_OPERATION.get(expression.operation)
    if opcode is None or expression.left is None:
        raise ValueError(f"unsupported replacement operation: {expression.operation}")
    left = materialize_symbolic_expression(expression.left, bindings, destination_size)
    right = (
        materialize_symbolic_expression(expression.right, bindings, destination_size)
        if expression.right is not None
        else None
    )
    node = AstNode(opcode, left, right)
    node.dest_size = destination_size
    return node


def specialize(
    rule: CompiledEgglogAddRule,
    candidate_ast: AstNode,
    *,
    destination_size: int,
    rounds: int = 6,
) -> EgglogAddSpecialization | None:
    if not isinstance(rounds, int) or isinstance(rounds, bool) or not 1 <= rounds <= 6:
        return None
    candidate_ast = _unwrap_runtime_ast(candidate_ast)
    if not isinstance(candidate_ast, AstNode):
        return None
    bindings = bind_symbolic_pattern(rule.pattern, candidate_ast, destination_size)
    if bindings is None or not constraints_hold(rule, bindings, destination_size):
        return None
    replacement = materialize_symbolic_expression(
        rule.replacement, bindings, destination_size
    )
    if not isinstance(replacement, AstNode):
        return None
    specialization = EgglogAddSpecialization(
        rule, candidate_ast, replacement, bindings, rounds=rounds
    )
    return specialization if _prove_specialization(specialization) else None


def _dsl_to_bitexpr(
    expression: SymbolicExpressionProtocol,
    variables: dict[str, Any],
    specialization: EgglogAddSpecialization,
):
    import egglog

    BitExpr = _bitexpr_type()

    if expression.operation is None:
        if not expression.name:
            raise ValueError("unnamed symbolic leaf")
        if expression.value is not None:
            mask = (1 << (int(specialization.candidate_ast.dest_size) * 8)) - 1
            return BitExpr(int(expression.value) & mask)
        if expression.name in specialization.bindings:
            bound = specialization.bindings[expression.name]
            pattern_leaf = next(
                (
                    item
                    for item in _iter_symbolic_leaves(specialization.rule.pattern)
                    if item.name == expression.name
                ),
                None,
            )
            if isinstance(bound, AstConstant) and (
                pattern_leaf is None
                or bool(getattr(pattern_leaf, "is_pattern_constant", False))
            ):
                return BitExpr(int(bound.value))
        return variables.setdefault(
            expression.name, next(egglog.vars_(expression.name, BitExpr))
        )
    left = _dsl_to_bitexpr(expression.left, variables, specialization)
    right = (
        _dsl_to_bitexpr(expression.right, variables, specialization)
        if expression.right is not None
        else None
    )
    return _apply_bitexpr_operation(expression.operation, left, right)


def _iter_symbolic_leaves(expression: SymbolicExpressionProtocol):
    if expression.operation is None:
        yield expression
        return
    if expression.left is not None:
        yield from _iter_symbolic_leaves(expression.left)
    if expression.right is not None:
        yield from _iter_symbolic_leaves(expression.right)


def _apply_bitexpr_operation(operation: str, left: Any, right: Any):
    match operation:
        case "add":
            return left + right
        case "sub":
            return left - right
        case "mul":
            return left * right
        case "and":
            return left & right
        case "or":
            return left | right
        case "xor":
            return left ^ right
        case "neg":
            return -left
        case "bnot":
            return ~left
        case _:
            raise ValueError(f"unsupported Egglog operation: {operation}")


def _ast_to_bitexpr(ast: AstBase, leaf_names: dict[tuple[Any, ...], str]):
    _ensure_runtime()
    BitExpr = _bitexpr_type()

    if isinstance(ast, AstConstant):
        return BitExpr(int(ast.value))
    if isinstance(ast, AstLeaf):
        fingerprint = _ast_fingerprint(ast)
        name = leaf_names.setdefault(fingerprint, f"leaf_{len(leaf_names)}")
        return BitExpr.var(name)
    if not isinstance(ast, AstNode) or ast.left is None:
        raise ValueError("unsupported AST for Egglog")
    operation = _OPERATION_BY_OPCODE.get(ast.opcode)
    if operation is None:
        raise ValueError(f"unsupported AST opcode: {ast.opcode}")
    left = _ast_to_bitexpr(ast.left, leaf_names)
    right = _ast_to_bitexpr(ast.right, leaf_names) if ast.right is not None else None
    return _apply_bitexpr_operation(operation, left, right)


def _prove_specialization(specialization: EgglogAddSpecialization) -> bool:
    import egglog

    try:
        egraph = egglog.EGraph()
        variables: dict[str, Any] = {}
        pattern = _dsl_to_bitexpr(
            specialization.rule.pattern, variables, specialization
        )
        replacement = _dsl_to_bitexpr(
            specialization.rule.replacement, variables, specialization
        )
        leaf_names: dict[tuple[Any, ...], str] = {}
        candidate = _ast_to_bitexpr(specialization.candidate_ast, leaf_names)
        concrete_replacement = _ast_to_bitexpr(
            specialization.replacement_ast, leaf_names
        )
        egraph.register(egglog.rewrite(pattern).to(replacement))
        egraph.register(candidate)
        egraph.run(min(max(int(specialization.rounds), 1), 6))
        egraph.check(egglog.eq(candidate).to(concrete_replacement))
    except Exception:
        return False
    return True
