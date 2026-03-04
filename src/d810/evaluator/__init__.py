"""Public API for the d810 evaluator package.

The evaluator package unifies the five previously scattered evaluation
paths in d810 under a common protocol and helper registry.  See
``docs/plans/2026-02-18-evaluator-package-refactor.md`` for the full
migration plan.

Exports (Phase 3):

- :class:`ConcreteEvaluator` — concrete AST interpreter
- :func:`evaluate_concrete` — public entry point for concrete evaluation
- :func:`probe_is_constant` — heuristic probe-based constant pre-filter
- :class:`_RotateHelper` — Registrant base for rotate helpers; use ``_RotateHelper.lookup(name)``
- :class:`EvaluatorProtocol` — typing.Protocol for evaluator implementations
- :class:`HelperCallable` — minimal Protocol for any ``(int, int) -> int`` helper
- :class:`HelperProtocol` — richer Protocol for named helpers with ``bit_width``

Example::

    from d810.evaluator.evaluators import evaluate_concrete
    from d810.evaluator.helpers.rotate import _RotateHelper
    from d810.evaluator.evaluators import probe_is_constant

    fn = _RotateHelper.lookup("__ROL4__")
    assert fn is not None
    result = fn(0x12345678, 8)

    is_const, val = probe_is_constant(ast_node, leaf_info_list)
"""

from __future__ import annotations
