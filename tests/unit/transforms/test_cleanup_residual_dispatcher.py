"""unflatten pass #5: cleanup_residual_dispatcher composes the portable cleanup-candidate lowering.

The candidate -> GraphModification lowering is already covered in transforms.cleanup_evidence; here
we lock the pass contract: no candidates -> empty plan, and candidates flow into planner_modifications.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.ir.flowgraph import FlowGraph
from d810.transforms.dispatcher_cleanup import cleanup_residual_dispatcher
from d810.transforms.plan import PatchPlan
import d810.transforms.dispatcher_cleanup as mod


def test_null_or_no_candidates_yield_empty_plan():
    for plan in (
        cleanup_residual_dispatcher(None, None),
        cleanup_residual_dispatcher(
            FlowGraph(blocks={}, entry_serial=0, func_ea=0),
            None,
            candidates=(),
        ),
    ):
        assert plan.steps == ()


def test_candidates_lower_into_planner_modifications(monkeypatch):
    # isolate the pass's composition from the (separately tested) candidate-lowering internals
    @dataclass
    class _Mod:
        tag: int

    monkeypatch.setattr(
        mod, "build_dispatcher_cleanup_modification", lambda c: _Mod(tag=c)
    )
    captured = {}

    def _compile(modifications, graph, *, block_refs_by_serial):
        captured["modifications"] = tuple(modifications)
        captured["graph"] = graph
        captured["block_refs_by_serial"] = block_refs_by_serial
        return PatchPlan()

    monkeypatch.setattr(mod, "compile_patch_plan", _compile)
    graph = FlowGraph(blocks={}, entry_serial=0, func_ea=0)
    plan = cleanup_residual_dispatcher(
        graph,
        None,
        candidates=(1, 2, 3),
    )
    assert tuple(m.tag for m in captured["modifications"]) == (1, 2, 3)
    assert captured["graph"] is graph
    assert captured["block_refs_by_serial"] is None
    assert plan.steps == ()  # cleanup goes through the planner-modification channel
