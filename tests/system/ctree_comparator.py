"""Prototype: IDA-ctree-native live-vs-live comparator.

Uses IDA's native ctree (``cfunc_t.body``) to count and compare decompiled
function structure without any text round-trip.  The ctree is the decompiler's
own AST — it sees every call node regardless of how the rendered pseudocode
represents the callee (plain name, cast expression, function-pointer cast, etc.).

Prototype limitations (by design):
- ``are_equivalent`` performs a STRICT structural-shape match on op-code
  sequences only.  It does NOT apply CodeComparator's cast-stripping,
  commutative-operand normalisation, or type-bucket equivalence classes.
  It is therefore stricter than semantic equivalence and best used as a fast
  pre-filter or for self/near-equivalence checks.
- ``structural_signature`` records the pre-order op sequence (both insns AND
  exprs) — it ignores leaf identities (variable indices, numeric values, names).
- ``count_ast_statements`` returns keys matching ``CodeComparator.count_ast_statements``
  so the two can be compared side-by-side.

IDA dependency guard
--------------------
All public functions raise ``RuntimeError`` when IDA is not available.  The
module-level ``try/except`` mirrors the pattern used in ``tests/system/conftest.py``
so import never fails in non-IDA environments.
"""

from __future__ import annotations

try:
    import ida_hexrays
except Exception:
    ida_hexrays = None  # type: ignore[assignment]


def _require_ida() -> None:
    """Raise RuntimeError if ida_hexrays is not available."""
    if ida_hexrays is None:
        raise RuntimeError(
            "ida_hexrays is not available — ctree_comparator requires IDA Pro."
        )


def _get_body(cfunc: object) -> object:
    """Return the ctree body from either a cfunc_t or its .body directly."""
    if hasattr(cfunc, "body"):
        return cfunc.body
    return cfunc


# ---------------------------------------------------------------------------
# count_ast_statements
# ---------------------------------------------------------------------------


def count_ast_statements(cfunc: object) -> dict:
    """Walk the ctree and return structural counts matching CodeComparator keys.

    Args:
        cfunc: A ``cfunc_t`` (or its ``.body`` citem directly).

    Returns:
        Dict with keys ``statements``, ``returns``, ``whiles``, ``gotos``,
        ``ifs``, ``calls``.

        - ``calls``      — ``cot_call`` expression nodes (every call site,
          including those wrapped in cast expressions that libclang may drop).
        - ``returns``    — ``cit_return`` instruction nodes.
        - ``whiles``     — ``cit_while`` + ``cit_do`` instruction nodes.
        - ``gotos``      — ``cit_goto`` instruction nodes.
        - ``ifs``        — ``cit_if`` instruction nodes.
        - ``statements`` — count of ALL ``cit_*`` instruction nodes visited
          (the cit_* namespace covers every statement kind).

    Raises:
        RuntimeError: If IDA is not available.

    Examples:
        >>> # (Doctest requires IDA; shown for documentation only.)
        >>> # counts = count_ast_statements(cfunc)
        >>> # assert set(counts) == {"statements", "returns", "whiles",
        >>> #                        "gotos", "ifs", "calls"}
    """
    _require_ida()

    counts: dict[str, int] = {
        "statements": 0,
        "returns": 0,
        "whiles": 0,
        "gotos": 0,
        "ifs": 0,
        "calls": 0,
    }

    class _CountVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

        def visit_expr(self, expr: object) -> int:  # type: ignore[override]
            if expr.op == ida_hexrays.cot_call:
                counts["calls"] += 1
            return 0

        def visit_insn(self, insn: object) -> int:  # type: ignore[override]
            op = insn.op
            # Every instruction node counts as a statement.
            counts["statements"] += 1
            if op == ida_hexrays.cit_return:
                counts["returns"] += 1
            elif op in (ida_hexrays.cit_while, ida_hexrays.cit_do):
                counts["whiles"] += 1
            elif op == ida_hexrays.cit_goto:
                counts["gotos"] += 1
            elif op == ida_hexrays.cit_if:
                counts["ifs"] += 1
            return 0

    _CountVisitor().apply_to(_get_body(cfunc), None)
    return counts


# ---------------------------------------------------------------------------
# structural_signature
# ---------------------------------------------------------------------------


def structural_signature(cfunc: object) -> tuple:
    """Return a normalized shape signature of the ctree.

    Walks every node (insns AND exprs) in pre-order via a CV_FAST visitor and
    records the ``item.op`` integer for each node.  The result is a tuple of
    op-codes that captures control-flow / expression structure while ignoring
    leaf identities (variable indices, numeric constants, names).

    This is deterministic for a given ctree and useful as a fast equivalence
    pre-filter (self-equivalence) or for detecting structural regressions.

    Prototype limitation: two functions that produce the same sequence of opcodes
    but differ only in constants/variable choices will be considered equal.  This
    is intentional — use ``CodeComparator.are_equivalent`` for value-sensitive
    comparison.

    Args:
        cfunc: A ``cfunc_t`` or its ``.body``.

    Returns:
        Non-empty tuple of integer op codes in visit order.

    Raises:
        RuntimeError: If IDA is not available.
    """
    _require_ida()

    ops: list[int] = []

    class _SigVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

        def visit_expr(self, expr: object) -> int:  # type: ignore[override]
            ops.append(int(expr.op))
            return 0

        def visit_insn(self, insn: object) -> int:  # type: ignore[override]
            ops.append(int(insn.op))
            return 0

    _SigVisitor().apply_to(_get_body(cfunc), None)
    return tuple(ops)


# ---------------------------------------------------------------------------
# are_equivalent
# ---------------------------------------------------------------------------


def are_equivalent(cfunc_a: object, cfunc_b: object) -> bool:
    """Return True if both cfuncs share the same structural op-code signature.

    This is a STRICT structural-shape match (prototype): it compares the
    pre-order sequence of ctree op codes for both functions.  It does NOT apply
    CodeComparator's cast-stripping, commutative-operand normalisation, or
    type-bucket equivalence classes, so it is stricter than semantic equivalence.

    Intended use cases:
    - Self-equivalence check (``are_equivalent(cfunc, cfunc)`` must be True).
    - Fast structural regression detection between two decompilations of the
      same function (e.g. before vs after a patch, or across runs).
    - Pre-filter before a more expensive semantic comparison.

    NOT suitable for:
    - Comparing the same logic implemented differently (e.g. ``a+b`` vs ``b+a``).
    - Cross-platform decompilation comparisons where IDA emits different op
      sequences for semantically equivalent code.

    Args:
        cfunc_a: First ``cfunc_t`` (or body).
        cfunc_b: Second ``cfunc_t`` (or body).

    Returns:
        True iff ``structural_signature(cfunc_a) == structural_signature(cfunc_b)``.

    Raises:
        RuntimeError: If IDA is not available.
    """
    return structural_signature(cfunc_a) == structural_signature(cfunc_b)
