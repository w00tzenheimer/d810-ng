"""Provider-specific lowering for already-certified MBA rules.

Portable admission, deterministic receipts, and typed-term applications live in
:mod:`d810.mba.certified_rule_compiler`. This module retains only the
runtime/native specialization that will move to the provider extension later.
"""

from __future__ import annotations

import importlib
from collections.abc import Collection
from dataclasses import dataclass

from d810.core.typing import Any
from d810.mba.certified_rule_compiler import (
    ADD_RULE_CLASSES,  # noqa: F401
    CERTIFICATE_WIDTHS,  # noqa: F401
    CompiledMbaRule,
    MBA_RULE_FAMILIES,  # noqa: F401
    MbaRuleCatalogue,  # noqa: F401
    RuleCompilationStatus,  # noqa: F401
    _UNARY_OPERATIONS,
    _constraints_match_term,  # noqa: F401
    _enroll_admitted_rule,  # noqa: F401
    _compile_rule_families,  # noqa: F401
    _compile_selected_rule_catalogue,  # noqa: F401
    apply_compiled_rule_to_term,  # noqa: F401
    compile_add_rule_catalogue,  # noqa: F401
    compile_mba_rule_catalogue,  # noqa: F401
    compiled_rules_for_families,  # noqa: F401
    is_admitted_compiled_rule,  # noqa: F401
    require_admitted_compiled_rules,
)
from d810.mba.dsl import SymbolicExpressionProtocol


@dataclass(frozen=True)
class EgglogAddSpecialization:
    rule: CompiledMbaRule
    candidate_ast: AstNode
    replacement_ast: AstNode
    bindings: dict[str, AstBase]
    saturation_rounds: int = 6

    @property
    def source_names(self) -> tuple[str, ...]:
        return (self.rule.source_name, *self.rule.aliases)

    @property
    def family(self) -> str:
        return self.rule.family


EgglogMbaSpecialization = EgglogAddSpecialization


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
    rule: CompiledMbaRule,
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
    rule: CompiledMbaRule,
    candidate_ast: AstNode,
    *,
    destination_size: int,
    saturation_rounds: int = 6,
) -> EgglogAddSpecialization | None:
    if (
        not isinstance(saturation_rounds, int)
        or isinstance(saturation_rounds, bool)
        or not 1 <= saturation_rounds <= 6
    ):
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
        rule,
        candidate_ast,
        replacement,
        bindings,
        saturation_rounds=saturation_rounds,
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
        egraph.run(min(max(int(specialization.saturation_rounds), 1), 6))
        egraph.check(egglog.eq(candidate).to(concrete_replacement))
    except Exception:
        return False
    return True
