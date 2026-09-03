"""Unit tests for the pure multi-def (phi) resolution decisions.

IDA-free: the helpers under test take plain ``(block_serial, ins_ea)`` keys and
plain integer values, so the merge-resolution *decision* is testable without a
live ``mba_t``.  The Hex-Rays plumbing that produces those keys is covered by
``tests/system/runtime/evaluator``.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

# The package initializer imports live IDA modules; these decision tests
# deliberately exercise the pure-Python module without requiring IDA.
_package_name = "d810.evaluator.hexrays_microcode"
if _package_name not in sys.modules:
    _package = types.ModuleType(_package_name)
    _package.__path__ = [
        str(
            Path(__file__).resolve().parents[4]
            / "src"
            / "d810"
            / "evaluator"
            / "hexrays_microcode"
        )
    ]
    sys.modules[_package_name] = _package

from d810.evaluator.hexrays_microcode.p_multi_def import (  # noqa: E402
    agreed_value,
    select_def_index_for_predecessor,
)


class TestSelectDefIndexForPredecessor:
    def test_def_inside_the_predecessor_block_wins(self):
        # defs reaching a merge: one in blk 329, one in blk 398.
        defs = [(329, 0x1000), (398, 0x2000)]
        assert select_def_index_for_predecessor(defs, 329, {(398, 0x2000)}) == 0

    def test_last_def_inside_the_predecessor_block_wins(self):
        # Two defs in the same predecessor block: the LAST one reaches the edge.
        defs = [(329, 0x1000), (329, 0x1004), (398, 0x2000)]
        assert select_def_index_for_predecessor(defs, 329, set()) == 1

    def test_def_reaching_through_the_predecessor_is_selected(self):
        # blk 398 does not itself define the operand; the def flows in from 415.
        defs = [(329, 0x1000), (415, 0x2000)]
        assert select_def_index_for_predecessor(defs, 398, {(415, 0x2000)}) == 1

    def test_ambiguous_predecessor_reach_abstains(self):
        defs = [(329, 0x1000), (415, 0x2000)]
        assert (
            select_def_index_for_predecessor(defs, 398, {(329, 0x1000), (415, 0x2000)})
            is None
        )

    def test_no_matching_def_abstains(self):
        defs = [(329, 0x1000), (415, 0x2000)]
        assert select_def_index_for_predecessor(defs, 398, set()) is None

    def test_duplicate_reaching_keys_are_one_definition(self):
        defs = [(329, 0x1000), (415, 0x2000), (415, 0x2000)]
        assert select_def_index_for_predecessor(defs, 398, {(415, 0x2000)}) == 1

    def test_empty_defs_abstains(self):
        assert select_def_index_for_predecessor([], 398, {(415, 0x2000)}) is None


class TestAgreedValue:
    def test_all_defs_agreeing_yields_the_value(self):
        assert agreed_value([7, 7, 7]) == 7

    def test_disagreement_abstains(self):
        assert agreed_value([0x13A30BD4, 0x372FB61A]) is None

    def test_any_unresolved_def_abstains(self):
        assert agreed_value([7, None]) is None

    def test_zero_is_a_real_value_not_a_miss(self):
        assert agreed_value([0, 0]) == 0

    def test_empty_abstains(self):
        assert agreed_value([]) is None
