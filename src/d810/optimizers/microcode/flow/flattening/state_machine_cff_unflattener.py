"""§1a live entry point — the state-machine-CFF unflattener driven by the north-star call graph.

This is the runtime realization of the §1a pseudocode: at the maturity hook it lifts the live
``mba`` to a portable ``FunctionSource``, builds an ``AnalysisManager`` (facts), selects the
``HodurFamily``, and runs ``run_pipeline`` (family -> passes -> transforms -> backend.apply). The
ONLY live-mba touch points are the lifter + ``HexRaysMutationBackend`` (backends/hexrays).

GATED OFF by default behind ``D810_USE_S1A_PIPELINE`` — the legacy ``HodurUnflattener`` remains the
default path so the golden is unaffected. Turning the flag on routes the hodur family through the
§1a call graph; until the detection + reconstruction passes are fully ported it is intentionally
incomplete (``HodurFamily.detect`` is still inert), so this is the harness to iterate to
equivalence-or-better, not yet a replacement.
"""
from __future__ import annotations

import json
import os

import ida_hexrays

from d810.core import logging
from d810.core.observability_models import (
    BlockSnapshot as _DiagBlockSnapshot,
    DagEdge as _DiagDagEdge,
    DagNode as _DiagDagNode,
    Modification as _DiagModification,
)
from d810.core.observability_recon import (
    diagnostics_enabled as _recon_diagnostics_enabled,
    observe_dag,
    observe_modifications,
    observe_reachability,
    observe_state_dispatcher_rows,
)
from d810.hexrays.observability import (
    diagnostics_enabled as _capture_diagnostics_enabled,
    request_capture_mba_snapshot,
)
from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.analyses.control_flow.linearized_state_dag import (
    build_live_linearized_state_dag_from_graph,
)
from d810.transforms.state_machine_unflatten import lower_to_direct_graph
from d810.optimizers.microcode.flow.flattening.unflattening_rule_lifecycle import (
    ComposedUnflatteningRule,
)
from d810.backends.hexrays.lifter import lift_function
from d810.backends.hexrays.evidence.bst_analysis import analyze_bst_dispatcher
from d810.analyses.control_flow.dispatcher_recovery import recover_dispatcher
from d810.analyses.control_flow.transition_builder import _convert_bst_to_result
from d810.backends.hexrays.mutation.backend import HexRaysMutationBackend
from d810.passes.analysis_manager import AnalysisManager
from d810.passes.driver import run_pipeline
from d810.families.state_machine_cff.hodur_pipeline import HodurFamily

logger = logging.getLogger("D810.unflat.s1a", logging.DEBUG)


def _s1a_enabled() -> bool:
    return os.environ.get("D810_USE_S1A_PIPELINE", "0").strip() == "1"


class StateMachineCffUnflattener(ComposedUnflatteningRule):
    """Run the §1a pipeline for the state-machine-CFF (Hodur) family. Flag-gated, opt-in."""

    DESCRIPTION = "State-machine CFF unflattener via the §1a pipeline (families -> passes -> backend)"
    DEFAULT_UNFLATTENING_MATURITIES = [ida_hexrays.MMAT_GLBOPT1]
    # The §1a pipeline does its own dispatcher detection (HodurFamily.detect); bypass the
    # legacy flow-context unflattening gate (like the other ComposedUnflatteningRule subclasses).
    HAS_OWN_DISPATCHER_COLLECTOR = True

    def __init__(self) -> None:
        super().__init__()
        self._s1a_done_for_ea: int = -1

    def optimize(self, blk: "ida_hexrays.mblock_t") -> int:
        # Bind the live mba FIRST (mirrors HodurUnflattener.optimize): the base
        # ComposedUnflatteningRule only *annotates* ``self.mba`` and the cfg
        # dispatch loop never assigns it, so reading ``self.mba`` before this
        # binding raises AttributeError — which escapes ``func``'s narrow
        # except set into IDA's optblock callback, suppressing this very log
        # line and leaving AFTER == BEFORE (ticket llr-1330).
        self.mba = blk.mba
        logger.info(
            "s1a optimize: enabled=%s maturity=%s blk=%s",
            _s1a_enabled(),
            maturity_to_string(getattr(self.mba, "maturity", 0)),
            getattr(blk, "serial", "?"),
        )
        if not _s1a_enabled():
            return 0
        mba = self.mba
        func_ea = int(getattr(mba, "entry_ea", 0))
        if func_ea == self._s1a_done_for_ea:
            return 0  # one pipeline run per function/maturity
        self._s1a_done_for_ea = func_ea

        source = lift_function(mba, maturity=getattr(mba, "maturity", None))
        # Supply the live validated fact view (state observations) so resolve_state_transitions
        # has the transition evidence; without it the chain produces an empty plan.
        fact_view = None
        flow_ctx = getattr(self, "flow_context", None)
        if flow_ctx is not None:
            try:
                fact_view = flow_ctx.validated_fact_view(getattr(mba, "maturity", 0))
            except Exception:  # noqa: BLE001 — fact view is best-effort input
                logger.debug("s1a: validated_fact_view unavailable", exc_info=True)
        # Pre-mutation BST/interval evidence: walk the PRISTINE mba here (it still matches
        # source.flow_graph; the pipeline mutates it below) so the value-range dispatcher recovery
        # sees the intact BST. Gated on the diag capture — production never computes it. Consumed
        # only by the diag DAG rebuild to validate evidence-recovery against the oracle (llr-gp9d).
        bst_evidence = None
        if _capture_diagnostics_enabled():
            try:
                prelim = recover_dispatcher(source.flow_graph, fact_view)
                if getattr(prelim, "dispatcher_block_serial", None) is not None:
                    bst_evidence = analyze_bst_dispatcher(
                        mba,
                        int(prelim.dispatcher_block_serial),
                        getattr(prelim, "state_var_stkoff", None),
                    )
            except Exception:  # noqa: BLE001 — evidence recovery is best-effort diagnostics
                logger.debug("s1a: pre-pipeline BST evidence failed", exc_info=True)
        facts = AnalysisManager(source.flow_graph, input_facts=fact_view)
        backend = HexRaysMutationBackend()
        run_pipeline(
            source=source,
            family=HodurFamily(),
            backend=backend,
            facts=facts,
            project_config=None,
            maturity=getattr(mba, "maturity", None),
        )
        # Iteration diagnostics: where does the §1a chain stand for this function?
        rec = facts.get_analysis("recover_dispatcher")
        tr = facts.get_analysis("transition_result")
        regions = facts.get_analysis("plan_semantic_regions")
        logger.info(
            "s1a func=0x%x: input_facts=%s map_rows=%d transitions=%d regions=%d",
            func_ea,
            fact_view is not None,
            len(rec.dispatch_map.rows) if rec and rec.dispatch_map else 0,
            len(tr.transitions) if tr else 0,
            len(regions.linear_regions) if regions else 0,
        )
        # Diag DB: publish the §1a structural analysis so the SQLite diag tables are not blind to
        # this path (the legacy recon instrumentation does not run under the flag). llr-6dq7.
        self._publish_s1a_diagnostics(mba, source, rec, tr, regions, fact_view, bst_evidence)
        # Change accounting is the backend's concern (it lowered the plan); the §1a driver does not
        # yet surface an applied-count, so report 0 until the reconstruction passes land real plans.
        return 0

    def _publish_s1a_diagnostics(
        self, mba, source, rec, tr, regions, fact_view, bst_evidence=None
    ) -> None:
        """Populate the structured diag tables for the §1a path (otherwise blind under the flag).

        Two tiers:
        * ``state_dispatcher_rows`` -- keyed by func_ea + maturity, no snapshot ref; mirrors the
          backend's ``_observe_state_dispatcher_map``. Published whenever a recon subscriber exists.
        * ``block_classification`` / ``dag_edges`` / ``modifications`` -- snapshot-correlated, so they
          need a capture snapshot. We capture from the portable ``source.flow_graph`` (the stable,
          already-lifted graph the analyses ran on -- NOT the live mid-pipeline mba, which trips
          ``snapshot_mba``) and rebuild the DAG/plan here. The rebuild is GATED on an installed
          capture subscriber, so it only runs under ``--full-diagnostics``; production decompilation
          never pays for it. Best-effort: any failure degrades to a debug log, never breaks optimize.
        """
        dmap = getattr(rec, "dispatch_map", None) if rec is not None else None
        if dmap is None:
            return
        func_ea = int(getattr(mba, "entry_ea", 0) or 0)
        maturity = maturity_to_string(int(getattr(mba, "maturity", -1) or -1))
        if _recon_diagnostics_enabled():
            try:
                observe_state_dispatcher_rows(
                    func_ea=func_ea,
                    maturity=maturity,
                    dispatcher_entry_block=int(dmap.dispatcher_entry_block),
                    dispatcher_kind=dmap.source.name,
                    rows=dmap.rows,
                )
            except Exception:  # noqa: BLE001 — diagnostics must never break the optimize path
                logger.debug("s1a: observe_state_dispatcher_rows failed", exc_info=True)
        if source is None or not _capture_diagnostics_enabled():
            return
        try:
            snap = request_capture_mba_snapshot(
                blocks=_diag_blocks_from_flow_graph(source.flow_graph),
                label="s1a_recover_dispatcher",
                func_ea=func_ea,
                maturity=maturity,
                phase="post_pipeline",  # CHECK-constrained set in diag schema
            )
            if snap is None:
                return
            observe_reachability(
                snap,
                all_serials=tuple(source.flow_graph.blocks),
                reachable=tuple(getattr(rec, "reachable_block_serials", ()) or ()),
                bst_serials=tuple(getattr(rec, "bst_block_serials", ()) or ()),
            )
            entry_serial = int(dmap.dispatcher_entry_block)
            # Pre-mutation BST evidence (value-range dispatcher, handler ranges, pre-header/initial
            # state) recovered before the pipeline mutated the mba (passed in). DIAG-ONLY: validates
            # evidence-recovery WITHOUT touching production lowering, so a still-naive emission cannot
            # collapse the live output (llr-gp9d/mmfq/opck).
            bst = bst_evidence
            # Prefer the BST-derived rich transition_result: it backfills handlers reachable only
            # through wide BST range intervals (the range-backed states the exact-only §1a #2 omits),
            # so the diag DAG node/edge counts approach the legacy oracle instead of being capped by
            # the shallow exact-chain transitions.
            dag_tr = tr
            if bst is not None:
                try:
                    dag_tr = _convert_bst_to_result(bst)
                except Exception:  # noqa: BLE001 — fall back to the §1a transition_result
                    dag_tr = tr
            if dag_tr is not None and getattr(dag_tr, "transitions", None):
                dag = build_live_linearized_state_dag_from_graph(
                    flow_graph=source.flow_graph,
                    transition_result=dag_tr,
                    dispatcher_entry_serial=entry_serial,
                    state_var_stkoff=dmap.state_var_stkoff,
                    bst_node_blocks=(
                        tuple(sorted(int(b) for b in bst.bst_node_blocks))
                        if bst is not None
                        else ()
                    ),
                    handler_range_map=(bst.handler_range_map if bst is not None else None),
                    dispatcher=(bst.dispatcher if bst is not None else None),
                    pre_header_serial=(bst.pre_header_serial if bst is not None else None),
                    initial_state=(bst.initial_state if bst is not None else None),
                    mba=mba,
                    prefer_local_corridors=True,
                )
                observe_dag(snap, _diag_dag_nodes(dag), _diag_dag_edges(dag))
                plan = lower_to_direct_graph(
                    source.flow_graph,
                    fact_view,
                    transition_result=tr,
                    dispatch_map=dmap,
                    dispatcher_entry_serial=entry_serial,
                    state_var_stkoff=dmap.state_var_stkoff,
                    regions=regions,
                )
                observe_modifications(snap, _diag_modifications(plan))
        except Exception:  # noqa: BLE001 — diagnostics must never break the optimize path
            logger.debug("s1a: snapshot-correlated diagnostics failed", exc_info=True)


# ---------------------------------------------------------------------------
# Diag-model converters: §1a structural data -> SQLite diag rows. Diagnostics
# only; the caller gates them behind an installed capture subscriber.
# ---------------------------------------------------------------------------


def _diag_blocks_from_flow_graph(flow_graph) -> list[_DiagBlockSnapshot]:
    """Build diag block snapshots from the portable FlowGraph (never the live mba)."""
    blocks: list[_DiagBlockSnapshot] = []
    for serial, b in flow_graph.blocks.items():
        succs = [int(s) for s in getattr(b, "succs", ())]
        preds = [int(p) for p in getattr(b, "preds", ())]
        kind = getattr(b, "kind", None)
        type_name = (
            getattr(b, "type_name", None)
            or (kind.name if kind is not None else None)
            or f"BLT_{int(getattr(b, 'block_type', -1))}"
        )
        blocks.append(
            _DiagBlockSnapshot(
                serial=int(serial),
                block_type=int(getattr(b, "block_type", -1)),
                type_name=str(type_name),
                start_ea=int(getattr(b, "start_ea", 0) or 0),
                end_ea=int(getattr(b, "end_ea", 0) or 0),
                nsucc=int(getattr(b, "nsucc", len(succs))),
                npred=int(getattr(b, "npred", len(preds))),
                succs=succs,
                preds=preds,
            )
        )
    return blocks


def _diag_dag_nodes(dag) -> list[_DiagDagNode]:
    nodes: list[_DiagDagNode] = []
    for node in getattr(dag, "nodes", ()):
        state = int(getattr(getattr(node, "key", None), "state_const", 0) or 0)
        suffix = tuple(getattr(node, "shared_suffix_blocks", ()) or ())
        nodes.append(
            _DiagDagNode(
                state=state,
                state_hex=f"0x{state:016X}",
                entry_block=int(getattr(node, "entry_anchor", 0) or 0),
                classification=getattr(getattr(node, "kind", None), "name", "UNKNOWN"),
                shared_suffix=(json.dumps([int(s) for s in suffix]) if suffix else None),
            )
        )
    return nodes


def _diag_dag_edges(dag) -> list[_DiagDagEdge]:
    edges: list[_DiagDagEdge] = []
    for edge_id, edge in enumerate(getattr(dag, "edges", ())):
        anchor = getattr(edge, "source_anchor", None)
        src_state = getattr(getattr(edge, "source_key", None), "state_const", None)
        target_state = getattr(edge, "target_state", None)
        target_entry = getattr(edge, "target_entry_anchor", None)
        branch_arm = getattr(anchor, "branch_arm", None) if anchor is not None else None
        edges.append(
            _DiagDagEdge(
                edge_id=edge_id,
                source_state=(int(src_state) if src_state is not None else None),
                target_state=(int(target_state) if target_state is not None else None),
                edge_kind=getattr(getattr(edge, "kind", None), "name", "UNKNOWN"),
                source_block=(
                    int(anchor.block_serial) if anchor is not None else None
                ),
                source_arm=(int(branch_arm) if branch_arm is not None else None),
                target_entry=(int(target_entry) if target_entry is not None else None),
                ordered_path=json.dumps(
                    [int(s) for s in getattr(edge, "ordered_path", ())]
                ),
            )
        )
    return edges


def _diag_modifications(plan) -> list[_DiagModification]:
    try:
        graph_mods = plan.as_graph_modifications()
    except Exception:  # noqa: BLE001 — best-effort diagnostic conversion
        graph_mods = ()
    mods: list[_DiagModification] = []
    for idx, mod in enumerate(graph_mods):
        source_block = getattr(mod, "from_serial", None)
        if source_block is None:
            source_block = getattr(mod, "block_serial", None)
        target_block = getattr(mod, "new_target", None)
        if target_block is None:
            target_block = getattr(mod, "goto_target", None)
        old_target = getattr(mod, "old_target", None)
        mods.append(
            _DiagModification(
                mod_index=idx,
                mod_type=type(mod).__name__,
                source_block=(int(source_block) if source_block is not None else None),
                target_block=(int(target_block) if target_block is not None else None),
                old_target=(int(old_target) if old_target is not None else None),
                status="emitted",
            )
        )
    return mods
