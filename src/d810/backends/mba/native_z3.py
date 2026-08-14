"""One fixed-width native-AST equivalence gate for MBA candidates."""

from __future__ import annotations

from d810.core.typing import Any

import ida_hexrays


def prove_native_ast_equivalence(
    original: Any,
    replacement: Any,
    *,
    width: int,
) -> bool:
    """Prove two same-width supported native ASTs equal with bit-vector Z3.

    Callers must have already passed both trees through the island lowerer:
    casts, truncations, shifts, and unsupported opcodes are rejected there
    rather than silently modeled with weaker integer semantics here.
    """

    if type(width) is not int or width not in {8, 16, 32, 64}:
        return False
    try:
        import z3

        variables: dict[object, Any] = {}

        def visit(node: Any) -> Any:
            if node is None:
                raise ValueError("missing AST operand")
            if node.is_leaf():
                if node.is_constant():
                    return z3.BitVecVal(int(node.value), width)
                mop = getattr(node, "mop", None)
                try:
                    hash(mop)
                    key: object = ("mop", mop)
                except TypeError:
                    key = ("mop", repr(mop))
                return variables.setdefault(
                    key,
                    z3.BitVec(f"native_mba_leaf_{len(variables)}", width),
                )
            left = visit(getattr(node, "left", None))
            right_node = getattr(node, "right", None)
            right = visit(right_node) if right_node is not None else None
            operations = {
                ida_hexrays.m_add: lambda: left + right,
                ida_hexrays.m_sub: lambda: left - right,
                ida_hexrays.m_mul: lambda: left * right,
                ida_hexrays.m_and: lambda: left & right,
                ida_hexrays.m_or: lambda: left | right,
                ida_hexrays.m_xor: lambda: left ^ right,
                ida_hexrays.m_neg: lambda: -left,
                ida_hexrays.m_bnot: lambda: ~left,
            }
            operation = operations.get(getattr(node, "opcode", None))
            if operation is None:
                raise ValueError("unsupported AST opcode")
            return operation()

        solver = z3.Solver()
        solver.set(timeout=50)
        solver.add(visit(original) != visit(replacement))
        return solver.check() == z3.unsat
    except Exception:
        return False


__all__ = ["prove_native_ast_equivalence"]
