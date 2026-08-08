"""The one dispatcher-table shape that means total failure (ticket lpccp-w81p).

Both recovery paths emit ``[0, 2**32) -> dispatcher_entry`` when they find
nothing: an empty ``DecisionDag`` makes ``_interval_dispatcher_from_decision_dag``
return ``None``, the caller falls through to ``build_dispatch_tree``, and that
yields a single catch-all row.  It was then published and logged exactly like a
healthy table, so "recovered nothing" was indistinguishable from "recovered a
dispatcher" for every downstream consumer -- which is what made sub_7FFE50C44430
take hours to localize rather than minutes.

The check is deliberately narrow, so most of these cases pin what it must NOT
reject.  IDA-dependent (``condition_chain_analysis`` imports ``ida_hexrays``)
-> system/runtime, not a unit.
"""

from __future__ import annotations

import pytest

from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.backends.hexrays.evidence.condition_chain_analysis import (
    _is_degenerate_self_routing_table,
)

ENTRY = 4
FULL_SPACE = 1 << 32


def _table(rows: list[IntervalRow]) -> IntervalDispatcher:
    return IntervalDispatcher(rows, default_target=None, compute_default=False)


def test_rejects_whole_space_routing_back_to_the_entry() -> None:
    """The failure signature: every state routes to the block that routes."""
    table = _table([IntervalRow(lo=0, hi=FULL_SPACE, target=ENTRY)])
    assert _is_degenerate_self_routing_table(table, ENTRY) is True


class TestDoesNotFireOnLegitimateShapes:
    def test_multi_row_table_is_untouched(self) -> None:
        table = _table(
            [
                IntervalRow(lo=0, hi=0x40DF52, target=173),
                IntervalRow(lo=0x40DF52, hi=0x40DF53, target=98),
                IntervalRow(lo=0x40DF53, hi=FULL_SPACE, target=173),
            ]
        )
        assert _is_degenerate_self_routing_table(table, ENTRY) is False

    def test_whole_space_routing_to_a_real_handler_is_untouched(self) -> None:
        """A one-handler dispatcher names the HANDLER, not the entry."""
        table = _table([IntervalRow(lo=0, hi=FULL_SPACE, target=99)])
        assert _is_degenerate_self_routing_table(table, ENTRY) is False

    def test_narrow_row_targeting_the_entry_is_untouched(self) -> None:
        """A dispatcher self-loop on ONE state is a real, known row kind."""
        table = _table([IntervalRow(lo=0x402FE6E3, hi=0x402FE6E4, target=ENTRY)])
        assert _is_degenerate_self_routing_table(table, ENTRY) is False

    def test_absent_dispatcher_is_untouched(self) -> None:
        assert _is_degenerate_self_routing_table(None, ENTRY) is False

    def test_unknown_entry_serial_is_untouched(self) -> None:
        table = _table([IntervalRow(lo=0, hi=FULL_SPACE, target=ENTRY)])
        assert _is_degenerate_self_routing_table(table, None) is False

    def test_empty_table_is_untouched(self) -> None:
        assert _is_degenerate_self_routing_table(_table([]), ENTRY) is False


@pytest.mark.parametrize("hi", [FULL_SPACE, FULL_SPACE + 1])
def test_accepts_at_or_past_the_state_space_bound(hi: int) -> None:
    """``hi`` is exclusive; recovery has emitted both 0x100000000 and wider."""
    table = _table([IntervalRow(lo=0, hi=hi, target=ENTRY)])
    assert _is_degenerate_self_routing_table(table, ENTRY) is True


def test_partial_span_to_the_entry_is_untouched() -> None:
    """Not the whole space -> not the failure signature."""
    table = _table([IntervalRow(lo=0, hi=FULL_SPACE - 1, target=ENTRY)])
    assert _is_degenerate_self_routing_table(table, ENTRY) is False
