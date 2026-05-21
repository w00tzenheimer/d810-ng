"""Runtime tests for read-only ABC evidence collection."""
from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.optimizers.microcode.flow.flattening.abc_block_splitter import (
    ABCPatternInfo,
    ConditionalStateResolver,
)


class _ABCResolverForTest(ConditionalStateResolver):
    def _find_abc_pattern(self, block, predecessor_history=None):
        return ABCPatternInfo(
            block_serial=block.serial,
            instruction_ea=0x401000,
            cnst=1010001,
            condition_mop=object(),
            opcode=ida_hexrays.m_add,
            state_mop=object(),
        )

    def _resolve_target_for_state(self, state_value: int):
        target_serials = {
            1010001: 20,
            1010002: 21,
        }
        return SimpleNamespace(serial=target_serials[state_value])


def test_conditional_abc_resolution_returns_evidence_without_live_mutation():
    resolver = _ABCResolverForTest(SimpleNamespace(), SimpleNamespace())
    block = SimpleNamespace(serial=7)

    evidence = resolver.collect_resolution(block)

    assert evidence is not None
    assert evidence.pattern.block_serial == 7
    assert evidence.target0_serial == 20
    assert evidence.target1_serial == 21
    assert evidence.resolved_target_serial is None
    assert resolver.observed_blocks == {7}
