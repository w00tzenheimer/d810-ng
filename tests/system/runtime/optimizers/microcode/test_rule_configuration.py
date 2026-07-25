"""Regression tests for optimizer rule configuration reuse across projects."""

from __future__ import annotations

import ida_hexrays

from d810.optimizers.microcode.flow.handler import FlowOptimizationRule


class _ConfiguredFlowRule(FlowOptimizationRule):
    def optimize(self, blk) -> int:
        return 0


def test_omitted_maturities_restore_rule_defaults_after_project_override() -> None:
    rule = _ConfiguredFlowRule()
    default_maturities = tuple(rule.maturities)

    rule.configure({"maturities": ["MMAT_GLBOPT1"]})
    assert rule.maturities == [ida_hexrays.MMAT_GLBOPT1]

    rule.configure({"profile": "state_dispatcher_map"})

    assert tuple(rule.maturities) == default_maturities
