"""Plan semantic regions over a portable FlowGraph (§1a pass #3) — LLVM RegionInfo style.

This is the ``RegionInfo`` analog: detect maximal **linear** (single-entry / single-exit) handler
chains in the recon state DAG. A region is ``state_0 -> state_1 -> ... -> state_n`` where each node
has exactly one outgoing transition and the next exactly one incoming — the LLVM SESE region
specialised to straight-line chains.

It is a pure composition of already-portable analyses (no extraction from the live composer needed):

* ``build_live_linearized_state_dag_from_graph`` (portable; ``mba`` is optional) builds the DAG from
  the FlowGraph + the resolved transitions;
* ``detect_linear_transition_regions`` finds the maximal linear regions.

The two analysis dependencies are the LLVM ``AnalysisManager.getResult`` inputs: ``transition_result``
from pass #2 (``resolve_state_transitions``) and ``dispatcher_entry_serial`` / ``state_var_stkoff``
from pass #1 (``recover_dispatcher``). Until the driver threads those through the AnalysisManager they
default to ``None`` and the plan is empty (no dispatcher info -> no regions).
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.ir.flowgraph import FlowGraph
from d810.analyses.value_flow.model import ValidatedFactView
from d810.analyses.control_flow.transition_builder import TransitionResult
from d810.analyses.control_flow.linearized_state_dag import (
    build_live_linearized_state_dag_from_graph,
)
from d810.analyses.control_flow.dag_region_detection import (
    detect_linear_transition_regions,
)


@dataclass(frozen=True, slots=True)
class SemanticRegionPlan:
    """Maximal linear handler chains discovered over the recon DAG.

    Each region is the ordered tuple of handler block serials forming one straight-line chain
    (LLVM RegionInfo SESE-linear region).
    """

    linear_regions: tuple[tuple[int, ...], ...] = ()


def plan_semantic_regions(
    graph: FlowGraph | None,
    facts: ValidatedFactView | None,
    *,
    transition_result: TransitionResult | None = None,
    dispatcher_entry_serial: int | None = None,
    state_var_stkoff: int | None = None,
) -> SemanticRegionPlan:
    """Detect maximal linear handler-chain regions over a portable ``FlowGraph``.

    Real composition of the portable DAG builder + region detector. ``transition_result`` and
    ``dispatcher_entry_serial`` are the §1a analysis dependencies (#2 and #1); while they are
    ``None`` (driver wiring pending) the plan is empty.
    """
    if graph is None or transition_result is None or dispatcher_entry_serial is None:
        return SemanticRegionPlan()
    dag = build_live_linearized_state_dag_from_graph(
        flow_graph=graph,
        transition_result=transition_result,
        dispatcher_entry_serial=dispatcher_entry_serial,
        state_var_stkoff=state_var_stkoff,
    )
    regions = detect_linear_transition_regions(dag)
    linear_regions = tuple(
        tuple(int(node.key.handler_serial) for node in region) for region in regions
    )
    return SemanticRegionPlan(linear_regions=linear_regions)
