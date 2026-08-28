from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.evaluator.hexrays_microcode import tracker
from d810.evaluator.hexrays_microcode.tracker import InstructionDefUseCollector


def test_valid_pair_container_is_not_reported_as_unsupported(monkeypatch) -> None:
    """Removing the tracker ``mop_p`` branch must restore warning churn."""

    operand = SimpleNamespace(
        t=ida_hexrays.mop_p,
        size=8,
        dstr=lambda: ":(%var_lo.4,%var_hi.4)",
    )

    warnings: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        tracker.logger,
        "warning",
        lambda *args, **_kwargs: warnings.append(args),
    )

    collector = SimpleNamespace(
        unresolved_ins_mops=[],
        memory_unresolved_ins_mops=[],
        target_mops=[],
    )
    InstructionDefUseCollector.visit_mop(collector, operand, 0, False)

    assert warnings == []
    assert collector.unresolved_ins_mops == []
    assert collector.memory_unresolved_ins_mops == []
    assert collector.target_mops == []
