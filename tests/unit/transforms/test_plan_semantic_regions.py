"""§1a pass #3: plan_semantic_regions composes the portable DAG builder + region detector.

The real region-detection over a live-built DAG is golden-verified at wiring time; here we lock the
analysis-dependency contract: without the #1/#2 inputs (dispatcher serial + TransitionResult) the
plan is empty, never a crash.
"""
from __future__ import annotations

from d810.transforms.semantic_regions import SemanticRegionPlan, plan_semantic_regions
from d810.analyses.control_flow.transition_builder import TransitionResult


def test_null_inputs_yield_empty_plan():
    assert plan_semantic_regions(None, None) == SemanticRegionPlan()


def test_missing_dispatcher_serial_yields_empty_plan():
    # graph present + transitions present, but no dispatcher entry serial (recover_dispatcher #1)
    assert plan_semantic_regions(
        graph=object(),
        facts=None,
        transition_result=TransitionResult(),
        dispatcher_entry_serial=None,
    ) == SemanticRegionPlan()


def test_missing_transition_result_yields_empty_plan():
    # dispatcher serial present but no resolved transitions (resolve_state_transitions #2)
    assert plan_semantic_regions(
        graph=object(),
        facts=None,
        transition_result=None,
        dispatcher_entry_serial=12,
    ) == SemanticRegionPlan()
