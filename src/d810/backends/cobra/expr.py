"""Parse, evaluate and score CoBRA expressions.  No IDA dependency.

A tree here is a plain dict, one of::

    {"kind": "const", "value": int}
    {"kind": "var",   "name": str}
    {"kind": "un",    "op": "~" | "-", "a": tree}
    {"kind": "bin",   "op": "+|-|*|&|||^", "a": tree, "b": tree}

Deliberately not an ``AstNode``: that type lives in ``d810.hexrays`` and unit
tests are barred from importing it, so keeping the expression layer pure is
what makes it testable without IDA.
"""

from __future__ import annotations

import ast

# cobra-cli's tokenizer accepts only these (ExprParser.cpp).  No shifts.
_BINOPS: dict[type[ast.operator], str] = {
    ast.Add: "+",
    ast.Sub: "-",
    ast.Mult: "*",
    ast.BitAnd: "&",
    ast.BitOr: "|",
    ast.BitXor: "^",
}


class ExprParseError(Exception):
    """cobra-cli emitted something we refuse to interpret."""


def parse_cobra_output(text: str, varnames: list[str]) -> dict:
    """Parse cobra-cli output into a tree, mapping ``x0..xN`` to real names.

    Uses CPython's parser rather than a bespoke one.  That is sound, not a
    happy accident: cobra-cli and CPython agree on operator precedence.

        cobra ExprParser.cpp   * = 2, + = 3, - = 3, & = 5, ^ = 6, | = 7
                               (lower number binds tighter)
        CPython                *  >  + -  >  &  >  ^  >  |

    Same ordering, and unary ``~`` / ``-`` bind tightest in both.  A hand-rolled
    parser for a format with no published grammar is precisely where silent
    wrong answers come from.
    """
    varmap = {f"x{i}": name for i, name in enumerate(varnames)}
    try:
        parsed = ast.parse(text.strip(), mode="eval")
    except SyntaxError as exc:
        raise ExprParseError(f"could not parse {text!r}: {exc}") from exc
    return _convert(parsed.body, varmap)


def _convert(node: ast.AST, varmap: dict[str, str]) -> dict:
    if isinstance(node, ast.Constant):
        if not isinstance(node.value, int) or isinstance(node.value, bool):
            raise ExprParseError(f"non-integer constant {node.value!r}")
        return {"kind": "const", "value": node.value}

    if isinstance(node, ast.Name):
        if node.id not in varmap:
            raise ExprParseError(f"unknown variable {node.id!r}")
        return {"kind": "var", "name": varmap[node.id]}

    if isinstance(node, ast.BinOp):
        op = _BINOPS.get(type(node.op))
        if op is None:
            raise ExprParseError(
                f"unsupported operator {type(node.op).__name__}; "
                "cobra-cli cannot emit it"
            )
        return {
            "kind": "bin",
            "op": op,
            "a": _convert(node.left, varmap),
            "b": _convert(node.right, varmap),
        }

    if isinstance(node, ast.UnaryOp):
        if isinstance(node.op, ast.Invert):
            return {"kind": "un", "op": "~", "a": _convert(node.operand, varmap)}
        if isinstance(node.op, ast.USub):
            inner = _convert(node.operand, varmap)
            # Fold -<literal>: reconstruction wants a constant, not a negation.
            if inner["kind"] == "const":
                return {"kind": "const", "value": -inner["value"]}
            return {"kind": "un", "op": "-", "a": inner}
        if isinstance(node.op, ast.UAdd):
            return _convert(node.operand, varmap)
        raise ExprParseError(f"unsupported unary {type(node.op).__name__}")

    raise ExprParseError(f"unsupported syntax {type(node).__name__}")


def evaluate(tree: dict, values: dict[str, int], mask: int) -> int:
    """Evaluate *tree*, wrapping every result to *mask*."""
    kind = tree["kind"]
    if kind == "const":
        return tree["value"] & mask
    if kind == "var":
        return values[tree["name"]] & mask
    if kind == "un":
        operand = evaluate(tree["a"], values, mask)
        return ((-operand) & mask) if tree["op"] == "-" else ((~operand) & mask)

    left = evaluate(tree["a"], values, mask)
    right = evaluate(tree["b"], values, mask)
    op = tree["op"]
    if op == "+":
        return (left + right) & mask
    if op == "-":
        return (left - right) & mask
    if op == "*":
        return (left * right) & mask
    if op == "&":
        return left & right
    if op == "|":
        return left | right
    if op == "^":
        return left ^ right
    raise ExprParseError(f"unknown operator {op!r}")


def signature_of(
    tree: dict, leaf_names: list[str] | tuple[str, ...], bitwidth: int
) -> list[int]:
    """Evaluate *tree* at every 0/1 assignment of its leaves.

    Half of the solver's input.  ``cobra::Simplify`` is signature-driven, but
    the signature alone is **not** sufficient: it under-determines the function
    once constants are involved, and passing a null input expression silently
    disables CoBRA's evaluator, cost gate and XOR fallback.  Measured on
    ``((a^b)^97)`` at 8-bit -- 49 of 54 results refuted by Z3.  The original
    expression is marshalled alongside this; see ``cobra_shim.h``.

    Cost is ``2**n`` evaluations for ``n`` leaves -- 256 at 8 leaves versus
    65,536 at 16 -- which is why the leaf cap is the throttle that matters.
    """
    mask = (1 << bitwidth) - 1
    names = list(leaf_names)
    return [
        evaluate(tree, {name: (index >> bit) & 1 for bit, name in enumerate(names)}, mask)
        for index in range(1 << len(names))
    ]


def node_count(tree: dict) -> int:
    """Nodes in *tree*.  The size metric reconstruction actually emits."""
    kind = tree["kind"]
    if kind in ("const", "var"):
        return 1
    if kind == "un":
        return 1 + node_count(tree["a"])
    return 1 + node_count(tree["a"]) + node_count(tree["b"])


def accept_rewrite(original: dict, rewrite: dict) -> bool:
    """Accept *rewrite* only when it is strictly smaller than *original*.

    CoBRA is a canonicaliser, not a shrinker: on VM_DecryptPacket 26 of 55
    rewrites were LARGER than their input, so accepting unconditionally makes
    the output worse.  Comparing sizes costs one traversal, makes regression
    impossible by construction, and measured better than accepting everything
    (17.8% vs 12.0% total reduction).

    Equal size is rejected too -- churn without benefit.
    """
    return node_count(rewrite) < node_count(original)
