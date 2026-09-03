"""Shared construction helper for direct ``PatternOptimizer`` exercises.

Several IDA-runtime tests drive ``PatternOptimizer._try_matches`` (and its
neighbours) directly instead of building a live optimizer, because
``InstructionOptimizer.__init__`` needs a real IDA session. Those tests used
to bypass ``__init__`` with ``object.__new__`` and hand-set attributes at every
call site, so every new hot-path attribute broke them all at once with an
``AttributeError`` (d81-zgh9, d81-wx2z).

This module owns that construction in one place: when the hot path starts
reading a new attribute, mirror it in :func:`bare_pattern_optimizer` once and
every call site keeps working.

The module deliberately imports no ``ida_*`` module of its own; it only pulls in
the d810 handler (which does require IDA), so importers must guard with
``pytest.importorskip("ida_hexrays")`` as they already do.
"""

from __future__ import annotations

from d810.core.log_aggregates import RuleMatchAggregator
from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    PatternOptimizer,
)

__all__ = ["bare_pattern_optimizer"]


def bare_pattern_optimizer(**overrides: object) -> PatternOptimizer:
    """Build a partially-constructed ``PatternOptimizer``.

    The defaults mirror the attributes ``InstructionOptimizer.__init__`` sets
    that the match hot path reads -- including ``_rule_match_aggregate`` and
    ``_rule_match_aggregate_maturity`` (see
    ``d810/optimizers/microcode/instructions/handler.py``). Pass keyword
    overrides to deviate; overriding ``cur_maturity`` also moves the default
    aggregate maturity, exactly as ``__init__`` does.
    """

    attributes: dict[str, object] = {
        "stats": None,
        "cur_maturity": 7,
        "_use_nomut_matching": False,
        "_use_legacy_storage": False,
        "_run_later_callback": None,
        "_pending_replacement_rule": None,
        "_rule_match_aggregate": RuleMatchAggregator(),
    }
    attributes.update(overrides)
    attributes.setdefault(
        "_rule_match_aggregate_maturity", attributes["cur_maturity"]
    )

    optimizer = object.__new__(PatternOptimizer)
    for name, value in attributes.items():
        setattr(optimizer, name, value)
    return optimizer
