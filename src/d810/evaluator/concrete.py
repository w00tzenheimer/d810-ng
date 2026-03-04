"""Facade for concrete evaluator resolved via backend registry."""

from __future__ import annotations

from d810.evaluator.backend_registry import get_concrete_provider

_provider = get_concrete_provider("concrete")
ConcreteEvaluator = _provider.evaluator_type()
_default_evaluator = _provider.default_evaluator()


def evaluate_concrete(
    node: object,
    env: dict[int, int],
    *,
    evaluator: object | None = None,
) -> int:
    """Evaluate AST node using the configured concrete evaluator backend."""
    ev = evaluator if evaluator is not None else _default_evaluator
    return ev.evaluate(node, env)  # type: ignore[union-attr]


__all__ = [
    "ConcreteEvaluator",
    "evaluate_concrete",
    "_default_evaluator",
]

