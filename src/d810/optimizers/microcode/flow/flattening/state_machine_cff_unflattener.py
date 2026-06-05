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
from d810.analyses.control_flow.block_ownership_domain import \
    analyze_block_ownership
from d810.analyses.control_flow.dispatcher_discovery_extractors import (
    discover_dispatcher_from_flow_graph,
)
from d810.analyses.control_flow.dispatcher_recovery import recover_dispatcher
from d810.analyses.control_flow.linearized_state_dag import (
    build_live_linearized_state_dag_from_graph,
)
from d810.analyses.control_flow.read_state_cfg import read_dag_from
from d810.analyses.control_flow.semantic_transition import \
    facts_from_validated_view
from d810.analyses.control_flow.state_machine_analysis import (
    run_snapshot_constant_fixpoint,
)
from d810.analyses.control_flow.state_transition_domain import (
    StateValue,
    analyze_state_transitions,
)
from d810.analyses.control_flow.transition_builder import _convert_bst_to_result
from d810.backends.hexrays.evidence.bst_analysis import analyze_bst_dispatcher
from d810.backends.hexrays.lifter import lift_function
from d810.backends.hexrays.mutation.backend import HexRaysMutationBackend
from d810.capabilities.resolver import CapabilitySet
from d810.capabilities.use_def_safety import UseDefSafetyCapability
from d810.capabilities.value_range import ValRangeCapability
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
    observe_dag_local_facts,
    observe_modifications,
    observe_reachability,
    observe_state_dispatcher_rows,
)
from d810.evaluator.hexrays_microcode.use_def_dominance import (
    HexRaysUseDefSafetyBackend,
)
from d810.evaluator.hexrays_microcode.value_range_capability import (
    HexRaysValRangeCapability,
)
from d810.families.state_machine_cff.hodur_pipeline import HodurFamily
from d810.hexrays.observability import (
    diagnostics_enabled as _capture_diagnostics_enabled,
    request_capture_mba_snapshot,
)
from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.optimizers.microcode.flow.flattening.hodur.unflattener import (
    HodurUnflattener,
)
from d810.passes.analysis_manager import AnalysisManager
from d810.passes.driver import run_pipeline
from d810.transforms.state_machine_unflatten import lower_to_direct_graph

logger = logging.getLogger("D810.unflat.s1a", logging.DEBUG)


def _s1a_enabled() -> bool:
    return os.environ.get("D810_USE_S1A_PIPELINE", "0").strip() == "1"


class StateMachineCffUnflattener(HodurUnflattener):
    """§1a state-machine-CFF entry. Flag-gated, opt-in.

    By default (``D810_S1A_USE_HCC=1``) this rule IS the proven, framework-driven
    HandlerChainComposer-owned ``HodurUnflattener`` reconstruction (the ``returns=8``
    path; standalone ``StateWriteReconstructionStrategy`` is retired -- HCC owns the
    SWR orchestration).  It subclasses ``HodurUnflattener`` so every lifecycle hook
    (gating, pass-count, fact runtime) drives the real HCC machinery.  Set
    ``D810_S1A_USE_HCC=0`` to run the WIP portable §1a pipeline instead.
    """

    DESCRIPTION = "State-machine CFF unflattener (HCC reuse by default; portable §1a pipeline opt-in)"
    DEFAULT_UNFLATTENING_MATURITIES = [ida_hexrays.MMAT_GLBOPT1]
    # The portable §1a pipeline (D810_S1A_USE_HCC=0) does its own dispatcher detection
    # (HodurFamily.detect); bypass the legacy flow-context gate so it always runs.
    HAS_OWN_DISPATCHER_COLLECTOR = True

    def __init__(self) -> None:
        super().__init__()  # full HodurUnflattener (HCC) setup
        self._s1a_done_for_ea: int = -1
        self._use_hcc = os.environ.get("D810_S1A_USE_HCC", "1").strip() == "1"

    def optimize(self, blk: "ida_hexrays.mblock_t") -> int:
        # Bind the live mba FIRST (mirrors HodurUnflattener.optimize): the base
        # ComposedUnflatteningRule only *annotates* ``self.mba`` and the cfg
        # dispatch loop never assigns it, so reading ``self.mba`` before this
        # binding raises AttributeError — which escapes ``func``'s narrow
        # except set into IDA's optblock callback, suppressing this very log
        # line and leaving AFTER == BEFORE (ticket llr-1330).
        self.mba : ida_hexrays.mba_t = blk.mba
        logger.info(
            "s1a optimize: enabled=%s maturity=%s blk=%s",
            _s1a_enabled(),
            maturity_to_string(getattr(self.mba, "maturity", 0)),
            getattr(blk, "serial", "?"),
        )
        if not _s1a_enabled():
            return 0
        if self._use_hcc:
            # Run the proven inherited HCC reconstruction (the returns=8 path). Do NOT
            # also run the portable §1a pipeline below (double-apply). The §1a pipeline
            # is the later portable-ization goal, gated behind D810_S1A_USE_HCC=0.
            return super().optimize(blk)
        mba = self.mba
        func_ea: int = mba.entry_ea
        if func_ea == self._s1a_done_for_ea:
            return 0  # one pipeline run per function/maturity
        self._s1a_done_for_ea = func_ea

        source = lift_function(mba, maturity=mba.maturity)
        # Supply the live validated fact view (state observations) so resolve_state_transitions
        # has the transition evidence; without it the chain produces an empty plan.
        fact_view = None
        flow_ctx = getattr(self, "flow_context", None)
        if flow_ctx is not None:
            try:
                fact_view = flow_ctx.validated_fact_view(mba.maturity)
            except Exception:  # noqa: BLE001 — fact view is best-effort input
                logger.debug("s1a: validated_fact_view unavailable", exc_info=True)
        # Pre-mutation BST/interval evidence: walk the PRISTINE mba here (it still matches
        # source.flow_graph; the pipeline mutates it below) so the value-range dispatcher recovery
        # sees the intact BST. PROMOTED TO PRODUCTION (gap3+gap4, ticket llr-t1s8): #4's
        # LowerStateMachine consumes this through the AnalysisManager to build the BST-enriched DAG
        # whose CONDITIONAL_RETURN edges (interval-map classification, not the bounded mba walk)
        # materialize terminal returns — the §1a returns=0 -> returns=N fix. analyze_bst_dispatcher
        # lives in the hexrays backend (needs the live mba), which the portable LowerStateMachine
        # can't import, so the evidence is computed here in the entry and threaded as an opaque fact.
        # The LiSA-discovery diff log stays diag-only. Self-gating: no dispatcher -> no evidence ->
        # #4 stays on the committed shallow path (byte-identical).
        bst_evidence = None
        try:
            prelim = recover_dispatcher(source.flow_graph, fact_view)
            if getattr(prelim, "dispatcher_block_serial", None) is not None:
                bst_evidence = analyze_bst_dispatcher(
                    mba,
                    int(prelim.dispatcher_block_serial),
                    getattr(prelim, "state_var_stkoff", None),
                )
                if _capture_diagnostics_enabled():
                    self._log_lisa_discovery_diff(source.flow_graph, prelim, bst_evidence)
        except Exception:  # noqa: BLE001 — evidence recovery is best-effort
            logger.debug("s1a: pre-pipeline BST evidence failed", exc_info=True)
        facts = AnalysisManager(source.flow_graph, input_facts=fact_view)
        if bst_evidence is not None:
            facts.put_analysis("bst_evidence", bst_evidence)
        backend = HexRaysMutationBackend()
        # Provide the live value-range capability so RecoverStateTransitions can resolve handler
        # transitions the exact equality-chain leaves unresolved (the north-star
        # ``capabilities.optional(ValRangeCapability)``).
        capabilities = CapabilitySet(
            {
                ValRangeCapability: HexRaysValRangeCapability(mba),
                UseDefSafetyCapability: HexRaysUseDefSafetyBackend(),
            }
        )
        run_pipeline(
            source=source,
            family=HodurFamily(),
            backend=backend,
            facts=facts,
            project_config=None,
            maturity=mba.maturity,
            capabilities=capabilities,
        )
        # Iteration diagnostics: where does the §1a chain stand for this function?
        rec = facts.get_analysis("recover_dispatcher")
        tr = facts.get_analysis("transition_result")
        regions = facts.get_analysis("plan_semantic_regions")
        valrange_confirmable = facts.get_analysis("valrange_confirmable_count")
        logger.info(
            "s1a func=0x%x: input_facts=%s map_rows=%d transitions=%d regions=%d valrange_confirmable=%s",
            func_ea,
            fact_view is not None,
            len(rec.dispatch_map.rows) if rec and rec.dispatch_map else 0,
            len(tr.transitions) if tr else 0,
            len(regions.linear_regions) if regions else 0,
            valrange_confirmable,
        )
        # Diag DB: publish the §1a structural analysis so the SQLite diag tables are not blind to
        # this path (the legacy recon instrumentation does not run under the flag). llr-6dq7.
        self._publish_s1a_diagnostics(
            mba, source, rec, tr, regions, fact_view, bst_evidence, capabilities
        )
        # Change accounting is the backend's concern (it lowered the plan); the §1a driver does not
        # yet surface an applied-count, so report 0 until the reconstruction passes land real plans.
        return 0

    def _log_lisa_discovery_diff(self, flow_graph, prelim, bst_evidence) -> None:
        """Compare the LiSA value-set dispatcher discovery to analyze_bst_dispatcher (gap1 parity gate).

        Headline: does the fixpoint's exact-handler recovery (``handler_entry_by_state``) reach the BST
        walk's handler count, and how many range-routed handlers does it surface (the P1 promotion
        candidates the read-off does not yet fold into the exact map)? Diagnostics-only.
        """
        stkoff = getattr(prelim, "state_var_stkoff", None)
        if stkoff is None:
            return
        try:
            view = discover_dispatcher_from_flow_graph(
                flow_graph,
                state_var_stkoff=int(stkoff),
                initial_state=getattr(bst_evidence, "initial_state", None),
            )
        except Exception:  # noqa: BLE001 — the diff is diagnostics-only
            logger.debug("s1a: LiSA dispatcher discovery diff failed", exc_info=True)
            return
        logger.info(
            "s1a discover(LiSA): exact_handlers=%d range_handlers=%d head=%s | "
            "bst handlers=%d state_var=0x%x initial=%s",
            len(view.handler_entry_by_state),
            len(view.handler_range_map),
            view.dispatcher_entry,
            len(getattr(bst_evidence, "handler_state_map", {}) or {}),
            int(stkoff),
            getattr(bst_evidence, "initial_state", None),
        )

    def _dual_build_read_dag_diff(
        self, source, dmap, bst_evidence, dag_tr, func_ea, maturity
    ) -> None:
        """Diag-only: build the portable ``read_dag_from`` read-off and OBSERVE it to
        the diag DB under a separate snapshot (``s1a_read_dag_lisa``).

        The legacy DAG is observed under ``s1a_recover_dispatcher``; the read-off goes
        to ``s1a_read_dag_lisa``, both into ``dag_nodes`` / ``dag_node_blocks`` /
        ``dag_local_*``.  The parity diff (node-expansion gap, owner-set partition vs
        the legacy per-handler block assignment, each divergence = one heuristic to
        retire) is then a SQL query across the two snapshot labels -- not a log grep.
        Best-effort, never breaks optimize.
        """
        try:
            flow_graph = source.flow_graph
            view = discover_dispatcher_from_flow_graph(
                flow_graph,
                state_var_stkoff=int(dmap.state_var_stkoff),
                initial_state=getattr(bst_evidence, "initial_state", None),
            )
            blocks = flow_graph.blocks
            succ = {int(s): tuple(int(x) for x in b.succs) for s, b in blocks.items()}
            pred = {int(s): tuple(int(x) for x in b.preds) for s, b in blocks.items()}
            terminal = frozenset(int(s) for s, b in blocks.items() if b.nsucc == 0)
            handler_entries = frozenset(
                int(h) for h in view.handler_entry_by_state.values()
            )
            # KILL the STRUCTURAL dispatcher head (the loop header dmap.dispatcher_entry_block),
            # NOT the fixpoint's widest-value-set block (view.dispatcher_entry): the latter sits
            # mid-chain, so the head never gets killed and ownership cascades through the routing
            # chain into every handler.
            dispatcher_region = frozenset(
                {int(dmap.dispatcher_entry_block)}
            ) | frozenset(int(b) for b in view.bst_node_blocks)
            owner_result = analyze_block_ownership(
                nodes=list(succ),
                successors_of=lambda n: succ.get(int(n), ()),
                predecessors_of=lambda n: pred.get(int(n), ()),
                handler_entries=handler_entries,
                dispatcher_region=dispatcher_region,
            )
            my_dag = read_dag_from(
                view=view,
                owner_result=owner_result,
                transitions=dag_tr,
                successors_of=lambda n: succ.get(int(n), ()),
                predecessors_of=lambda n: pred.get(int(n), ()),
                terminal_exit_blocks=terminal,
                dispatcher_entry_serial=int(dmap.dispatcher_entry_block),
                state_var_stkoff=int(dmap.state_var_stkoff),
            )

            # Observe the read-off into the diag DB under a SEPARATE snapshot so the
            # diff vs the legacy DAG (label s1a_recover_dispatcher) is a SQL query over
            # dag_nodes / dag_node_blocks / dag_local_*, not a log grep.
            my_snap = request_capture_mba_snapshot(
                blocks=_diag_blocks_from_flow_graph(flow_graph),
                label="s1a_read_dag_lisa",
                func_ea=func_ea,
                maturity=maturity,
                phase="post_pipeline",
            )
            if my_snap is not None:
                observe_dag(my_snap, _diag_dag_nodes(my_dag), _diag_dag_edges(my_dag))
                observe_dag_local_facts(my_snap, my_dag)
                logger.info(
                    "s1a read_dag(LiSA): observed %d nodes / %d edges to diag snapshot "
                    "'s1a_read_dag_lisa' (SQL-diff vs 's1a_recover_dispatcher')",
                    len(my_dag.nodes),
                    len(my_dag.edges),
                )
        except Exception:  # noqa: BLE001 — diag-only, never break optimize
            logger.debug("s1a: read_dag dual-build observe failed", exc_info=True)

    def _publish_s1a_diagnostics(
        self, mba, source, rec, tr, regions, fact_view, bst_evidence=None, capabilities=None
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
            # Inc4 (llr-mmfq): measure the sound #2 StateTransitionDomain fixpoint against the ad-hoc
            # bst-walk + oracle BEFORE swapping it into the DAG. Pure logging, feeds nothing.
            if bst is not None and fact_view is not None:
                self._s1a_fixpoint_probe(source, bst, fact_view, entry_serial)
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
                observe_dag_local_facts(snap, dag)
                self._dual_build_read_dag_diff(
                    source, dmap, bst, dag_tr, func_ea, maturity
                )
                # Feed the BST-enriched DAG (built above) + the recovered BST node set so the #4
                # return-wiring (gap3) lowers the CONDITIONAL_RETURN edges here in the diag rebuild.
                # DIAG-ONLY: gated on --full-diagnostics + a capture subscriber, so it cannot touch
                # production lowering; it validates the translated return phase against the oracle.
                plan = lower_to_direct_graph(
                    source.flow_graph,
                    fact_view,
                    transition_result=tr,
                    dispatch_map=dmap,
                    dispatcher_entry_serial=entry_serial,
                    state_var_stkoff=dmap.state_var_stkoff,
                    regions=regions,
                    dag=dag,
                    bst_node_blocks=(
                        tuple(sorted(int(b) for b in bst.bst_node_blocks))
                        if bst is not None
                        else None
                    ),
                    dispatcher=(bst.dispatcher if bst is not None else None),
                    # Production-realistic claims: feed the SAME use-def-protected spine production
                    # uses (filtered emission) so the diag postprocess measures the real claim set,
                    # not the unfiltered greedy spine. ``live_source`` is the opaque live backend fn.
                    use_def_safety=(
                        capabilities.optional(UseDefSafetyCapability)
                        if capabilities is not None
                        else None
                    ),
                    live_function=getattr(source, "live_source", None),
                    # Const-prop out-stk maps (portable snapshot fixpoint) so the postprocess fixpoint
                    # feeder is no longer dead at constant_result=None. Diag-only (gated above).
                    constant_result=(
                        run_snapshot_constant_fixpoint(
                            source.flow_graph, dmap.state_var_stkoff
                        )
                        if dmap.state_var_stkoff is not None
                        else None
                    ),
                )
                observe_modifications(snap, _diag_modifications(plan))
        except Exception:  # noqa: BLE001 — diagnostics must never break the optimize path
            logger.debug("s1a: snapshot-correlated diagnostics failed", exc_info=True)

    def _s1a_fixpoint_probe(self, source, bst, fact_view, dispatcher_entry: int) -> None:
        """DIAG-ONLY: measure the sound #2 ``StateTransitionDomain`` fixpoint (llr-mmfq Inc4).

        Builds the value-set ``transition_result`` from the SAME per-block state-write evidence the
        fact view already carries (``StateWriteAnchor``) and the BST handler map, then logs its
        conditional-transition count against the ad-hoc ``bst.conditional_transitions`` walk (the diag
        DAG's CONDITIONAL_TRANSITION source) and the legacy oracle (66). Pure measurement: it feeds
        nothing into the DAG/plan, so production and the diag DAG are untouched. The check confirms
        whether the sound fixpoint constrains the over-count before the Inc5 swap.
        """
        try:
            blocks = source.flow_graph.blocks
            _, anchors = facts_from_validated_view(fact_view)
            state_writes = {
                int(a.block_serial): StateValue.of(int(a.state_const)) for a in anchors
            }
            handler_entry_by_state = {
                int(state): int(blk)
                for blk, state in bst.handler_state_map.items()
                if blk not in bst.bst_node_blocks
            }

            def _succ(serial):
                blk = blocks.get(serial)
                return [int(x) for x in getattr(blk, "succs", ())] if blk is not None else []

            def _pred(serial):
                blk = blocks.get(serial)
                return [int(x) for x in getattr(blk, "preds", ())] if blk is not None else []

            fixpoint_tr = analyze_state_transitions(
                nodes=list(blocks),
                entry_nodes=[int(dispatcher_entry)],
                successors_of=_succ,
                predecessors_of=_pred,
                state_writes=state_writes,
                dispatcher_entry=int(dispatcher_entry),
                handler_entry_by_state=handler_entry_by_state,
                entry_state=StateValue.top(),
            )
            cond = sum(1 for t in fixpoint_tr.transitions if t.is_conditional)
            bst_cond_edges = sum(
                len(v) for v in (bst.conditional_transitions or {}).values()
            )
            logger.info(
                "s1a #2 fixpoint-probe: fixpoint cond=%d uncond=%d total=%d handlers=%d "
                "writes=%d | bst_walk cond_edges=%d | oracle cond=66",
                cond,
                len(fixpoint_tr.transitions) - cond,
                len(fixpoint_tr.transitions),
                len(handler_entry_by_state),
                len(state_writes),
                bst_cond_edges,
            )
        except Exception:  # noqa: BLE001 — probe must never break the optimize path
            logger.debug("s1a: fixpoint probe failed", exc_info=True)


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
