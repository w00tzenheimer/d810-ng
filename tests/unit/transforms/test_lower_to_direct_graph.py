"""§1a pass #4: lower_to_direct_graph builds the direct-edge CFG from the transition map.

The portable half — edge construction — turns each resolved transition into a redirect off the
dispatcher onto the real successor handler. Region-fusion body materialization is the deferred
backend half. Golden verifies the full rewrite at wiring time.
"""
from __future__ import annotations

from d810.analyses.control_flow.transition_builder import StateTransition, TransitionResult
from d810.transforms.state_machine_unflatten import lower_to_direct_graph
from d810.transforms.plan import PatchPlan, PatchRedirectBranch, PatchRedirectGoto


class _Map:
    def __init__(self, mapping):
        self._m = mapping

    def resolve_target(self, state_value):
        return self._m.get(state_value)


def test_null_inputs_yield_empty_plan():
    assert lower_to_direct_graph(None, None) == PatchPlan()
    assert lower_to_direct_graph(object(), None, transition_result=TransitionResult()) == PatchPlan()


def test_builds_direct_goto_edges_off_the_dispatcher():
    tr = TransitionResult(transitions=[
        StateTransition(from_state=0, to_state=1, from_block=10),
        StateTransition(from_state=1, to_state=2, from_block=20),
    ])
    plan = lower_to_direct_graph(
        graph=object(), facts=None, transition_result=tr,
        dispatch_map=_Map({1: 11, 2: 22}), dispatcher_entry_serial=5,
    )
    assert len(plan.steps) == 2
    assert all(isinstance(s, PatchRedirectGoto) for s in plan.steps)
    assert (plan.steps[0].from_serial, plan.steps[0].old_target, plan.steps[0].new_target) == (10, 5, 11)
    assert (plan.steps[1].from_serial, plan.steps[1].old_target, plan.steps[1].new_target) == (20, 5, 22)


def test_conditional_transition_emits_branch_redirect_at_condition_block():
    tr = TransitionResult(transitions=[
        StateTransition(
            from_state=0, to_state=4, from_block=10, condition_block=9, is_conditional=True
        ),
    ])
    plan = lower_to_direct_graph(
        graph=object(), facts=None, transition_result=tr,
        dispatch_map=_Map({4: 44}), dispatcher_entry_serial=5,
    )
    assert len(plan.steps) == 1
    s = plan.steps[0]
    assert isinstance(s, PatchRedirectBranch)
    assert (s.from_serial, s.old_target, s.new_target) == (9, 5, 44)


def test_unresolved_and_dispatcher_selfloop_transitions_are_skipped():
    tr = TransitionResult(transitions=[
        StateTransition(from_state=0, to_state=1, from_block=10),  # -> 5 (== dispatcher: self-loop)
        StateTransition(from_state=0, to_state=9, from_block=20),  # 9 not in map (unresolved)
    ])
    plan = lower_to_direct_graph(
        graph=object(), facts=None, transition_result=tr,
        dispatch_map=_Map({1: 5}), dispatcher_entry_serial=5,
    )
    assert plan.steps == ()  # self-loop + unresolved both left for cleanup (#5)
