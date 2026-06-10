"""unflatten pass #5: cleanup_residual_dispatcher composes the portable cleanup-candidate lowering.

The candidate -> GraphModification lowering is already covered in transforms.cleanup_evidence; here
we lock the pass contract: no candidates -> empty plan, and candidates flow into planner_modifications.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.transforms.dispatcher_cleanup import cleanup_residual_dispatcher
from d810.transforms.plan import PatchPlan
import d810.transforms.dispatcher_cleanup as mod


def test_null_or_no_candidates_yield_empty_plan():
    assert cleanup_residual_dispatcher(None, None) == PatchPlan()
    assert cleanup_residual_dispatcher(object(), None, candidates=()) == PatchPlan()


def test_candidates_lower_into_planner_modifications(monkeypatch):
    # isolate the pass's composition from the (separately tested) candidate-lowering internals
    @dataclass
    class _Mod:
        tag: int

    monkeypatch.setattr(
        mod, "build_dispatcher_cleanup_modification", lambda c: _Mod(tag=c)
    )
    plan = cleanup_residual_dispatcher(object(), None, candidates=(1, 2, 3))
    assert tuple(m.tag for m in plan.planner_modifications) == (1, 2, 3)
    assert plan.steps == ()  # cleanup goes through the planner-modification channel
