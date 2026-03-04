"""Unified evaluator entrypoints and helper abstractions."""
from __future__ import annotations

from d810.core.logging import getLogger
from d810.core.typing import TypeAlias
from d810.errors import AstEvaluationException
from d810.evaluator.concrete import _default_evaluator as _default_concrete_evaluator
from d810.evaluator.concrete import ConcreteEvaluator
from d810.evaluator.protocol import EvaluatorProtocol

_default_evaluator: EvaluatorProtocol = _default_concrete_evaluator


def evaluate_concrete(
    node: object,
    env: dict[int, int],
    *,
    evaluator: EvaluatorProtocol | None = None,
) -> int | None:
    """Evaluate AST node using the configured concrete evaluator backend."""
    ev = evaluator if evaluator is not None else _default_evaluator
    return ev.evaluate(node, env)  # type: ignore[union-attr]


# Abstract interpreter state alias.
ConstMap: TypeAlias = dict[str, tuple[int, int]]

logger = getLogger(__name__)


def probe_is_constant(
    node: object,
    leaf_info_list: list,
    probe_values: list[int] | None = None,
) -> tuple[bool, int | None]:
    """Heuristic pre-filter: determine whether *node* evaluates to a constant."""
    if probe_values is None:
        probe_values = [0, 0xFFFFFFFF]

    results: set[int] = set()
    try:
        for probe in probe_values:
            env: dict[int, int] = {
                li.ast.ast_index: probe
                for li in leaf_info_list
                if li.ast.ast_index is not None
            }
            val = evaluate_concrete(node, env)
            if val is None:
                return False, None
            results.add(val)
    except (AstEvaluationException, ZeroDivisionError):
        logger.debug(
            "probe_is_constant: evaluation error for node=%r", node, exc_info=True
        )
        return False, None

    if len(results) == 1:
        return True, results.pop()
    return False, None


__all__ = [
    "ConcreteEvaluator",
    "_default_evaluator",
    "evaluate_concrete",
    "ConstMap",
    "probe_is_constant",
]
