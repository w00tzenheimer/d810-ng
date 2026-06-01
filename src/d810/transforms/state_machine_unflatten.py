"""Lower a recovered state machine to a direct CFG — produce a PatchPlan (§1a pass #4 transform).

This is the "build the directed graph we want" step (LLVM-style): given the resolved state
transitions (#2) and the dispatcher map (#1), construct the direct-edge CFG by redirecting each
handler's dispatcher-bound exit straight onto its real successor handler — then let
``MutationBackend.apply`` materialize it and re-lift so the vendor optimizer recomputes dominance.
The reconstructed graph stays a directed graph with loops preserved as real cycles; we do NOT
flatten to acyclic.

Two halves, by §1a layer:

* **portable (here):** edge construction — one ``PatchRedirectGoto`` / ``PatchRedirectBranch`` per
  resolved transition, off ``dispatcher_entry_serial`` onto ``dispatch_map.resolve_target(to_state)``.
  This is the bulk of what the live composer does in-place; here it is a pure plan over the map.
* **backend (deferred):** region-fusion body materialization (``PatchInsertBlock`` capturing live
  handler bodies) — the part that needs live microcode; it stays behind ``MutationBackend.apply``.

``transition_result`` / ``dispatch_map`` / ``dispatcher_entry_serial`` are the §1a analysis
dependencies (#2 and #1). While they are ``None`` (driver wiring pending) the plan is empty — a
no-op the backend applies as nothing.
"""
from __future__ import annotations

from d810.core.typing import Protocol, runtime_checkable
from d810.ir.flowgraph import FlowGraph
from d810.analyses.value_flow.model import ValidatedFactView
from d810.analyses.control_flow.transition_builder import TransitionResult
from d810.transforms.plan import PatchPlan, PatchRedirectBranch, PatchRedirectGoto
from d810.transforms.semantic_regions import SemanticRegionPlan


@runtime_checkable
class _DispatcherMap(Protocol):
    """Minimal portable view of the recovered dispatcher map (#1)."""

    def resolve_target(self, state_value: int) -> int | None: ...


def lower_to_direct_graph(
    graph: FlowGraph | None,
    facts: ValidatedFactView | None,
    *,
    transition_result: TransitionResult | None = None,
    dispatch_map: _DispatcherMap | None = None,
    dispatcher_entry_serial: int | None = None,
    regions: SemanticRegionPlan | None = None,
) -> PatchPlan:
    """Build a ``PatchPlan`` that rewrites the dispatcher loop into direct handler->handler edges.

    Edge construction over the transition map (portable). Region-fusion body materialization is the
    deferred backend half (``PatchInsertBlock``); ``regions`` is accepted now so the wiring is stable.
    """
    if (
        graph is None
        or transition_result is None
        or not transition_result.transitions
        or dispatch_map is None
        or dispatcher_entry_serial is None
    ):
        return PatchPlan()

    steps: list[object] = []
    for transition in transition_result.transitions:
        target = dispatch_map.resolve_target(int(transition.to_state))
        if target is None or target == dispatcher_entry_serial:
            continue  # unresolved or self-loop back to dispatcher: leave for cleanup (#5)
        if transition.is_conditional:
            from_serial = transition.condition_block
            if from_serial is None:
                continue
            steps.append(
                PatchRedirectBranch(
                    from_serial=int(from_serial),
                    old_target=int(dispatcher_entry_serial),
                    new_target=int(target),
                )
            )
        else:
            steps.append(
                PatchRedirectGoto(
                    from_serial=int(transition.from_block),
                    old_target=int(dispatcher_entry_serial),
                    new_target=int(target),
                )
            )
    return PatchPlan(steps=tuple(steps))
