"""Trivial ctree optimization rule that counts nodes without modifying.

This rule serves as a smoke test for the ctree pipeline: it walks the
ctree body and counts expression nodes, but returns 0 (no modifications).
"""
from __future__ import annotations

from d810.core import typing

from d810.core import getLogger
from d810.hexrays.ctree_hooks import CtreeOptimizationRule

logger = getLogger("D810.optimizer")

# ---------------------------------------------------------------------------
# IDA imports are optional for testing.
# ---------------------------------------------------------------------------
try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None  # type: ignore[assignment]


class NoopCtreeCounter(CtreeOptimizationRule):
    """Counts ctree nodes without modifying anything.

    Auto-registered into ``CtreeOptimizationRule.registry``.
    """

    NAME = "noop_ctree_counter"
    DESCRIPTION = "Counts ctree nodes without modifying anything"

    def optimize_ctree(self, cfunc: typing.Any) -> int:
        """Walk the ctree and count nodes.

        :param cfunc: ``ida_hexrays.cfunc_t``
        :return: always 0 (no modifications)
        """
        count = 0
        if cfunc is not None and hasattr(cfunc, "body"):
            from d810.ctree.ast_iteration import iterate_all_subitems

            for _ in iterate_all_subitems(cfunc.body):
                count += 1
        logger.debug("NoopCtreeCounter: counted %d ctree nodes", count)
        return 0  # No modifications
