"""Public API for the d810 evaluator package.

The evaluator package unifies the five previously scattered evaluation
paths in d810 under a common protocol and helper registry.  See
``docs/plans/2026-02-18-evaluator-package-refactor.md`` for the full
migration plan.

Exports (Phase 3):

- :class:`ConcreteEvaluator` — concrete AST interpreter
- :func:`evaluate_concrete` — public entry point for concrete evaluation
- :func:`probe_is_constant` — heuristic probe-based constant pre-filter
- :class:`HelperRegistry` — name-to-callable map for rotate/arithmetic helpers
- :func:`get_registry` — returns the module-level singleton registry
- :class:`EvaluatorProtocol` — typing.Protocol for evaluator implementations
- :class:`HelperCallable` — minimal Protocol for any ``(int, int) -> int`` helper
- :class:`HelperProtocol` — richer Protocol for named helpers with ``bit_width``

Example::

    from d810.evaluator.concrete import evaluate_concrete
    from d810.evaluator.helpers import get_registry
    from d810.evaluator.symbolic import probe_is_constant

    fn = get_registry().lookup("__ROL4__")
    assert fn is not None
    result = fn(0x12345678, 8)

    is_const, val = probe_is_constant(ast_node, leaf_info_list)
"""

from __future__ import annotations
