"Plan semantic regions over a portable FlowGraph (unflatten pass #3) \u2014 LLVM RegionInfo style.\n\nThis is the ``RegionInfo`` analog: detect maximal **linear** (single-entry / single-exit) handler\nchains in the preanalysis state DAG. A region is ``state_0 -> state_1 -> ... -> state_n`` where each node\nhas exactly one outgoing transition and the next exactly one incoming \u2014 the LLVM SESE region\nspecialised to straight-line chains.\n\nIt is a pure composition of already-portable analyses (no extraction from the live composer needed):\n\n* ``build_live_linearized_state_dag_from_graph`` (portable; ``mba`` is optional) builds the DAG from\n  the FlowGraph + the resolved transitions;\n* ``detect_linear_transition_regions`` finds the maximal linear regions.\n\nThe two analysis dependencies are the LLVM ``AnalysisManager.getResult`` inputs: ``transition_result``\nfrom pass #2 (``resolve_state_transitions``) and ``dispatcher_entry_serial`` / ``state_var_stkoff``\nfrom pass #1 (``recover_dispatcher``). Until the driver threads those through the AnalysisManager they\ndefault to ``None`` and the plan is empty (no dispatcher info -> no regions).\n"
from __future__ import annotations

from dataclasses import dataclass

from d810.core import logging
from d810.ir.flowgraph import FlowGraph
from d810.analyses.value_flow.model import ValidatedFactView
from d810.analyses.control_flow.transition_builder import TransitionResult
from d810.analyses.control_flow.linearized_state_dag import (
    build_live_linearized_state_dag_from_graph,
)
from d810.analyses.control_flow.dag_region_detection import (
    detect_linear_transition_regions,
)

logger = logging.getLogger("D810.unflat.regions")


@dataclass(frozen=True, slots=True)
class SemanticRegionPlan:
    "Maximal linear handler chains discovered over the preanalysis DAG.\n\n    Each region is the ordered tuple of handler block serials forming one straight-line chain\n    (LLVM RegionInfo SESE-linear region).\n    "

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
    ``dispatcher_entry_serial`` are the unflatten analysis dependencies (#2 and #1); while they are
    ``None`` (driver wiring pending) the plan is empty.
    """
    if (
        graph is None
        or transition_result is None
        or not transition_result.transitions
        or dispatcher_entry_serial is None
    ):
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
    logger.info(
        "unflat regions: dag_nodes=%d dag_edges=%d regions=%d entry=%s state_var=%s diag=%s",
        len(dag.nodes),
        len(dag.edges),
        len(linear_regions),
        dispatcher_entry_serial,
        state_var_stkoff,
        list(dag.diagnostics)[:8],
    )
    return SemanticRegionPlan(linear_regions=linear_regions)
