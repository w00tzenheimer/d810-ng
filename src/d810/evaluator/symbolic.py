"""Symbolic probe helper — probe-based constant pre-filter.

Extracted from ``Z3ConstantOptimization.check_and_replace()`` in Phase 3
of the evaluator package refactor (see
``docs/plans/2026-02-18-evaluator-package-refactor.md``, section 4.5).

:func:`probe_is_constant` is a cheap heuristic that determines whether a
microcode AST evaluates to the same value across a small set of probe
bindings.  All variable leaves are set to the same probe value for each
run, so the cost is ``len(probe_values)`` concrete evaluations rather than
a full Z3 satisfiability check.

A positive result (``True``) means the expression *looks* constant — it
produced the same integer for every probe.  Callers must follow a positive
result with a proper Z3 equality check before trusting it.

A negative result (``False``) is a definitive counter-example: the
expression is *not* constant (it produced different values for at least two
probes).

Usage::

    from d810.evaluator.symbolic import probe_is_constant

    is_const, val = probe_is_constant(ast_node, leaf_info_list)
    if is_const:
        # Follow up with z3_check_mop_equality before acting
        ...
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def probe_is_constant(
    node: object,
    leaf_info_list: list,
    probe_values: list[int] | None = None,
) -> tuple[bool, int | None]:
    """Heuristic pre-filter: determine whether *node* evaluates to a constant.

    All variable leaves (identified via *leaf_info_list*) are bound to the
    same probe value for each evaluation run.  If every run produces the
    same integer, the expression is *probably* constant.  Callers should
    confirm with a Z3 satisfiability check.

    Args:
        node: Root of the microcode AST to evaluate.  Must support the
            interface expected by
            :func:`d810.evaluator.concrete.evaluate_concrete` (i.e. an
            ``AstBase``-like object).
        leaf_info_list: List of ``AstInfo``-like objects whose ``.ast``
            attribute exposes an ``ast_index`` integer.  Each entry
            represents one variable leaf in *node*.
        probe_values: Sequence of integer values to use as uniform leaf
            bindings.  Every leaf is set to the *same* value within one
            evaluation run.  Defaults to ``[0, 0xFFFFFFFF]`` when ``None``.

    Returns:
        A ``(is_constant, value)`` tuple:

        - ``(True, value)`` — all probe evaluations returned *value*.
        - ``(False, None)`` — at least two probes returned different
          results, or an :class:`~d810.errors.AstEvaluationException` /
          ``ZeroDivisionError`` was raised during evaluation.

    Examples:
        Constant expression (no variable leaves):

        >>> # All probes return 8 for "5 + 3"
        >>> # probe_is_constant(add_5_3_node, []) == (True, 8)
        ...

        Variable expression:

        >>> # probe_is_constant(x_plus_3_node, [x_info]) == (False, None)
        ...
    """
    # Lazy import keeps this module importable without IDA (unit tests).
    from d810.errors import AstEvaluationException
    from d810.evaluator.concrete import evaluate_concrete

    if probe_values is None:
        probe_values = [0, 0xFFFFFFFF]

    results: set[int] = set()
    try:
        for probe in probe_values:
            # Set every variable leaf to the same probe value.
            env: dict[int, int] = {
                li.ast.ast_index: probe
                for li in leaf_info_list
                if li.ast.ast_index is not None
            }
            val = evaluate_concrete(node, env)
            results.add(val)
    except (AstEvaluationException, ZeroDivisionError):
        logger.debug(
            "probe_is_constant: evaluation error for node=%r", node, exc_info=True
        )
        return False, None

    if len(results) == 1:
        return True, results.pop()
    return False, None


__all__ = ["probe_is_constant"]
