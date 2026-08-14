"""One fixed-width native-AST equivalence gate for MBA candidates."""

from __future__ import annotations

from d810.backends.mba.hexrays_island import lower_hexrays_island
from d810.core.typing import Any


def prove_native_ast_equivalence(
    original: Any,
    replacement: Any,
    *,
    width: int,
) -> bool:
    """Prove two same-width supported native ASTs equal with bit-vector Z3.

    Both trees first pass through the native island lowerer at exactly this
    destination width. Casts, truncations, shifts, unsupported opcodes, and
    mixed-width trees therefore fail closed before Z3 sees a term.
    """

    if type(width) is not int or width not in {8, 16, 32, 64}:
        return False
    try:
        import z3

        destination_size = width // 8
        original_lowering = lower_hexrays_island(
            original,
            destination_size=destination_size,
        )
        replacement_lowering = lower_hexrays_island(
            replacement,
            destination_size=destination_size,
        )
        if original_lowering.term is None or replacement_lowering.term is None:
            return False

        variables: dict[object, Any] = {}

        def visit(node: Any) -> Any:
            if node.width != width:
                raise ValueError("mixed-width typed term")
            if node.operation is None:
                if node.value is not None:
                    return z3.BitVecVal(int(node.value), width)
                if node.leaf_key is None:
                    raise ValueError("missing typed leaf identity")
                key = node.leaf_key
                return variables.setdefault(
                    key,
                    z3.BitVec(f"native_mba_leaf_{len(variables)}", width),
                )
            children = tuple(visit(child) for child in node.children)
            if len(children) not in {1, 2}:
                raise ValueError("invalid typed operator arity")
            left = children[0]
            right = children[1] if len(children) == 2 else None
            operations = {
                "add": lambda: left + right,
                "sub": lambda: left - right,
                "mul": lambda: left * right,
                "and": lambda: left & right,
                "or": lambda: left | right,
                "xor": lambda: left ^ right,
                "neg": lambda: -left,
                "bnot": lambda: ~left,
            }
            operation = operations.get(node.operation)
            if operation is None:
                raise ValueError("unsupported typed operation")
            return operation()

        solver = z3.Solver()
        solver.set(timeout=50)
        solver.add(
            visit(original_lowering.term) != visit(replacement_lowering.term)
        )
        return solver.check() == z3.unsat
    except Exception:
        return False


__all__ = ["prove_native_ast_equivalence"]
