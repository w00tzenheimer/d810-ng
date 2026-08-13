"""Pure certificate catalogue for ADD rules that can be lowered to Egglog."""

from __future__ import annotations

import enum
from dataclasses import dataclass, replace

from d810.core.typing import Any
from d810.backends.mba.z3 import verify_rule
from d810.mba.dsl import SymbolicExpressionProtocol
from d810.mba.rules._base import VerifiableRule
from d810.mba.rules.add import ADD_RULE_CLASSES

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


@dataclass(frozen=True)
class RuleCompilationReceipt:
    source_name: str
    status: RuleCompilationStatus
    canonical_name: str | None
    compiled_rule: CompiledEgglogAddRule | None
    reason: str | None = None


@dataclass(frozen=True)
class AddRuleCatalogue:
    receipts: tuple[RuleCompilationReceipt, ...]

    @property
    def entries(self) -> tuple[RuleCompilationReceipt, ...]:
        return self.receipts

    @property
    def compiled_rules(self) -> tuple[CompiledEgglogAddRule, ...]:
        return tuple(
            receipt.compiled_rule
            for receipt in self.receipts
            if receipt.status is RuleCompilationStatus.COMPILED
            and receipt.compiled_rule is not None
        )

    def receipt_for(self, source_name: str) -> RuleCompilationReceipt:
        for receipt in self.receipts:
            if receipt.source_name == source_name:
                return receipt
        raise KeyError(source_name)


def _expression_fingerprint(expression: Any) -> tuple[Any, ...]:
    if not isinstance(expression, SymbolicExpressionProtocol):
        raise ValueError(
            f"expected symbolic expression, got {type(expression).__name__}"
        )

    operation = expression.operation
    if operation is None:
        if not expression.is_leaf() or expression.left is not None or expression.right is not None:
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


def compile_add_rule_catalogue() -> AddRuleCatalogue:
    canonical_by_fingerprint: dict[tuple[Any, ...], CompiledEgglogAddRule] = {}
    staged_receipts: list[tuple[str, RuleCompilationStatus, str | None, str | None]] = []

    for rule_type in ADD_RULE_CLASSES:
        source_name = rule_type.__name__
        if getattr(rule_type, "SKIP_VERIFICATION", False):
            staged_receipts.append(
                (source_name, RuleCompilationStatus.REJECTED, None, "verification skipped")
            )
            continue

        rule = rule_type()
        try:
            fingerprint = _rule_fingerprint(rule)
            canonical = canonical_by_fingerprint.get(fingerprint)
            if canonical is not None:
                canonical_by_fingerprint[fingerprint] = replace(
                    canonical, aliases=canonical.aliases + (source_name,)
                )
                staged_receipts.append(
                    (
                        source_name,
                        RuleCompilationStatus.DUPLICATE,
                        canonical.source_name,
                        None,
                    )
                )
                continue

            for width in CERTIFICATE_WIDTHS:
                if not verify_rule(rule, bit_width=width):
                    raise ValueError(f"verification returned false at {width} bits")
        except (AssertionError, TypeError, ValueError) as exc:
            staged_receipts.append(
                (source_name, RuleCompilationStatus.REJECTED, None, str(exc))
            )
            continue

        canonical_by_fingerprint[fingerprint] = CompiledEgglogAddRule(
            source_name=source_name,
            aliases=(),
            rule_type=rule_type,
            proof_widths=CERTIFICATE_WIDTHS,
            guarded=bool(rule.CONSTRAINTS),
        )
        staged_receipts.append(
            (source_name, RuleCompilationStatus.COMPILED, source_name, None)
        )

    compiled_by_name = {
        compiled.source_name: compiled for compiled in canonical_by_fingerprint.values()
    }
    receipts = tuple(
        RuleCompilationReceipt(
            source_name=source_name,
            status=status,
            canonical_name=canonical_name,
            compiled_rule=(
                compiled_by_name.get(canonical_name) if canonical_name is not None else None
            ),
            reason=reason,
        )
        for source_name, status, canonical_name, reason in staged_receipts
    )
    return AddRuleCatalogue(receipts)
