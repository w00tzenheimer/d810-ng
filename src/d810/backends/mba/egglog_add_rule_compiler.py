"""Pure certificate catalogue for ADD rules that can be lowered to Egglog."""

from __future__ import annotations

import enum
import importlib
from dataclasses import dataclass, replace

from d810.backends.mba.z3 import constraint_to_z3, create_z3_variables, verify_rule
from d810.core.typing import Any
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

    @property
    def pattern(self) -> SymbolicExpressionProtocol:
        return self.rule_type().pattern

    @property
    def replacement(self) -> SymbolicExpressionProtocol:
        return self.rule_type().replacement

    @property
    def constraints(self) -> tuple[Any, ...]:
        return tuple(self.rule_type().CONSTRAINTS)


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


def compile_add_rule_catalogue() -> AddRuleCatalogue:
    canonical_by_fingerprint: dict[tuple[Any, ...], CompiledEgglogAddRule] = {}
    staged_receipts: list[
        tuple[str, RuleCompilationStatus, str | None, str | None]
    ] = []

    for rule_type in ADD_RULE_CLASSES:
        source_name = rule_type.__name__
        if getattr(rule_type, "SKIP_VERIFICATION", False):
            staged_receipts.append(
                (
                    source_name,
                    RuleCompilationStatus.REJECTED,
                    None,
                    "verification skipped",
                )
            )
            continue
        if rule_type.get_constraints is not VerifiableRule.get_constraints:
            staged_receipts.append(
                (
                    source_name,
                    RuleCompilationStatus.REJECTED,
                    None,
                    "custom get_constraints is not portable",
                )
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
                _validate_declarative_constraints(rule, width)
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
                compiled_by_name.get(canonical_name)
                if canonical_name is not None
                else None
            ),
            reason=reason,
        )
        for source_name, status, canonical_name, reason in staged_receipts
    )
    return AddRuleCatalogue(receipts)


_OPCODE_BY_OPERATION: dict[str, int] = {}
_OPERATION_BY_OPCODE: dict[int, str] = {}
_VALID_DESTINATION_SIZES = frozenset({1, 2, 4, 8})


def _ensure_runtime() -> None:
    if _OPCODE_BY_OPERATION:
        return
    global AstBase, AstConstant, AstLeaf, AstNode, ida_hexrays
    ida_hexrays = importlib.import_module("ida_hexrays")
    ast_module = importlib.import_module("d810.hexrays.expr.p_ast")
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
    if not isinstance(ast, AstLeaf):
        return False
    return _leaf_size(ast) == destination_size


def bind_symbolic_pattern(
    pattern: SymbolicExpressionProtocol,
    candidate_ast: AstNode,
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
) -> EgglogAddSpecialization | None:
    bindings = bind_symbolic_pattern(rule.pattern, candidate_ast, destination_size)
    if bindings is None or not constraints_hold(rule, bindings, destination_size):
        return None
    replacement = materialize_symbolic_expression(
        rule.replacement, bindings, destination_size
    )
    if not isinstance(replacement, AstNode):
        return None
    specialization = EgglogAddSpecialization(rule, candidate_ast, replacement, bindings)
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
