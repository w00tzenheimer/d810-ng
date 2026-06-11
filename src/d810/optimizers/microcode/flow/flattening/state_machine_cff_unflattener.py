"""unflatten live entry point — the state-machine-CFF unflattener driven by the north-star call graph.

This is the runtime realization of the unflatten pseudocode: at the maturity hook it lifts the live
``mba`` to a portable ``FunctionSource``, builds an ``AnalysisManager`` (facts), and routes
through the registered state-machine-CFF profiles — ``select_family`` polls the
``StateMachineCffFamily`` registry (``HodurFamily``=equality-chain, ``ApproovFamily``=
switch/indirect) and the claiming profile's ``pipeline_for`` drives ``run_pipeline``. The ONLY
live-mba touch points are the lifter + ``HexRaysMutationBackend`` (backends/hexrays).

PRODUCTION PATH (M2 cutover, llr-ibpi): the unflatten chain+spine pipeline is the SOLE CFF unflattener.
The hodur configs route ``StateMachineCffUnflattener``; full-fleet golden parity verified at 3032/0.
The legacy HCC fork is removed and unflatten runs unconditionally — there is no enable/disable flag.
"""
from __future__ import annotations

import json

import ida_hexrays
from d810.analyses.control_flow.block_ownership_domain import \
    analyze_block_ownership
from d810.analyses.control_flow.dispatcher_discovery_extractors import (
    discover_dispatcher_from_flow_graph,
)
from d810.analyses.control_flow.dispatcher_recovery import (
    min_state_constant_from_config,
    recover_dispatcher,
    register_extra_dispatcher_resolver,
)
from d810.analyses.control_flow.linearized_state_dag import (
    build_live_linearized_state_dag_from_graph,
)
from d810.analyses.control_flow.read_state_cfg import read_dag_from
from d810.analyses.control_flow.semantic_transition import \
    facts_from_validated_view
from d810.analyses.control_flow.state_machine_analysis import (
    run_snapshot_constant_fixpoint,
)
from d810.analyses.control_flow.minimal_state_recovery import (
    diff_back_edge_transitions,
    diff_back_edge_transitions_partitioned,
    recover_state_write_transitions,
    recover_state_write_transitions_via_fixpoint,
    recover_state_write_transitions_via_multicell_fixpoint,
    recover_state_write_transitions_via_partitioned_fixpoint,
)
from d810.analyses.control_flow.router_resolver import (
    RouterResolutionContext,
    default_resolvers,
    select_router,
)
from d810.analyses.control_flow.state_transition_domain import (
    StateValue,
    analyze_state_transitions_concolic,
    state_value_fixpoint_result,
)
from d810.analyses.data_flow.concolic import (
    ConcolicValue,
    ConcreteStore,
    LocationRef,
    PrecisionStatus,
    fold_exact,
)
from d810.analyses.data_flow.concolic.emulation import EmulationCapability
from d810.analyses.control_flow.transition_builder import _convert_bst_to_result
from d810.backends.hexrays.evidence.bst_analysis import analyze_bst_dispatcher
from d810.analyses.control_flow.indirect_jump_resolver import (
    IndirectJumpDispatcherResolver,
)
from d810.backends.hexrays.evidence.dispatcher.indirect_jump_capability import (
    HexRaysIndirectJumpTableCapability,
)
from d810.backends.hexrays.evidence.emulation import HexRaysBlockEmulator
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
from d810.families.registry import select_family
from d810.hexrays.observability import (
    diagnostics_enabled as _capture_diagnostics_enabled,
    request_capture_mba_snapshot,
)
from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.optimizers.microcode.flow.flattening.unflattening_rule_lifecycle import (
    ComposedUnflatteningRule,
)
from d810.passes.analysis_manager import AnalysisManager
from d810.passes.driver import run_pipeline
from d810.transforms.state_machine_unflatten import lower_to_direct_graph

logger = logging.getLogger("D810.unflat", logging.DEBUG)


class StateMachineCffUnflattener(ComposedUnflatteningRule):
    """unflatten state-machine-CFF entry — the production CFF unflattener (M2 cutover, llr-ibpi).

    Routes through ``select_family`` over the registered ``StateMachineCffFamily`` profiles
    (``HodurFamily``=equality-chain, ``ApproovFamily``=switch/indirect) over a portable
    ``FunctionSource`` lifted from the live ``mba``. Standalone (inherits the lifecycle from
    ``ComposedUnflatteningRule``) — the legacy HCC path is retired.
    """

    DESCRIPTION = "State-machine CFF unflattener (unflatten chain+spine pipeline)"
    # EXPERIMENT (llr-m9r4): Tigress-indirect loses its state-write transitions
    # to DCE by GLBOPT1 (writes 37@LOCOPT / 36@CALLS / 0@GLBOPT1) even though the
    # handler blocks survive. Fire at CALLS (transitions + m_ijmp + handler blocks
    # all live) so recovery can read the transition map; the once-per-function
    # guard runs the pipeline at the earliest listed maturity.
    # EXPERIMENT (llr-m9r4): Tigress-indirect loses its state-write transitions
    # to DCE by GLBOPT1 (writes 37@LOCOPT / 36@CALLS / 0@GLBOPT1) even though the
    # handler blocks survive. Fire at CALLS (transitions + m_ijmp + handler blocks
    # all live) so recovery can read the transition map; the once-per-function
    # guard runs the pipeline at the earliest listed maturity. (LOCOPT recovery
    # tried for gap1 and reverted: back_edges collapse 36->3, main machine fails.)
    DEFAULT_UNFLATTENING_MATURITIES = [
        ida_hexrays.MMAT_CALLS,
        ida_hexrays.MMAT_GLBOPT1,
    ]
    # unflatten does its own dispatcher detection (the resolver chain); bypass the legacy
    # flow-context gate so it always runs.
    HAS_OWN_DISPATCHER_COLLECTOR = True

    def __init__(self) -> None:
        super().__init__()  # ComposedUnflatteningRule: flow_context + optblock lifecycle
        self._unflat_done_for_ea: int = -1

    def configure(self, kwargs):
        # Configure-time hook (project load, runs ONCE before any decompilation
        # prolog). The ComposedUnflatteningRule/FlowOptimizationRule chain sets
        # ``self.config = kwargs`` here, so this is where the unflatten indirect profile
        # registers pre-decompile materialization of the Tigress computed-goto
        # label bodies — the emulated engine does the equivalent in its own
        # ``configure`` (unflattener_emulated_dispatcher_engine.py). ``optimize``
        # runs per-decompilation AFTER prolog, which is too late to inject crefs
        # before the first MBA build, so materialization MUST live here (I1.5,
        # ticket llr-tm3i).
        super().configure(kwargs)
        # unflatten runs address-agnostic indirect-jump materialization for EVERY
        # project — no per-binary configured addresses, no profile flag (llr-trxj).
        # The per-function prolog hook (run_indirect_materialization_for_function)
        # STRUCTURALLY detects whether the function being decompiled is a
        # register-indirect (computed-goto) dispatcher and materializes its label
        # bodies before the first MBA build; it is a NO-OP for every function that
        # is not such a dispatcher (and records the EAs that ARE, which optimize()
        # queries as its ``_is_indirect`` maturity-routing signal). Arming is
        # therefore inert for hodur/approov/switch and needs nothing in config.
        # ``goto_table_info`` is retained ONLY as an OPTIONAL per-function override
        # (state base/slot/table geometry) for binaries where structural discovery
        # needs help; the shipped indirect config hardcodes NOTHING.
        try:
            from d810.hexrays.preanalysis.indirect_jump_labels import (
                materialize_discovered_indirect_label_targets,
                register_indirect_materialization,
                reset_indirect_materialization,
            )
        except Exception:  # noqa: BLE001 — preanalysis import is best-effort
            logger.warning(
                "unflat: indirect materialization import failed", exc_info=True
            )
            return
        # Clear any prior registration (fresh start for a reconfigured session),
        # then arm the prolog hook unconditionally. Arming only enables the
        # structural per-function detector; it does not itself touch any function.
        override = dict(self.config.get("goto_table_info", {}) or {})
        try:
            reset_indirect_materialization()
            register_indirect_materialization(override)
        except Exception:  # noqa: BLE001 — registration is best-effort
            logger.warning(
                "unflat: indirect prolog registration failed", exc_info=True
            )
        # Configure-time prepass: structurally discover and materialize EVERY
        # indirect-table dispatcher in the database NOW, before any decompile.
        # This SEEDS the recon facts the unflatten LiSA dispatcher discovery consumes —
        # the prolog hook alone materializes only the entry function, which is
        # insufficient for STANDALONE discovery (head=None otherwise, so the test
        # would only pass when a sibling seeded it first; llr-trxj isolation fix).
        # Address-agnostic + behavior-neutral for non-dispatcher functions
        # (discovery returns None), so it stays inert for hodur/approov/switch.
        try:
            for result in materialize_discovered_indirect_label_targets(override):
                logger.info(
                    "Tigress indirect (unflat) preanalysis 0x%X: success=%s "
                    "materialized=%d/%d",
                    result.function_ea,
                    result.success,
                    result.materialized_target_count,
                    result.target_count,
                )
        except Exception:  # noqa: BLE001 — prepass is best-effort
            logger.warning(
                "unflat: indirect target materialization prepass failed", exc_info=True
            )

    def optimize(self, blk: "ida_hexrays.mblock_t") -> int:
        # Bind the live mba FIRST: the base
        # ComposedUnflatteningRule only *annotates* ``self.mba`` and the cfg
        # dispatch loop never assigns it, so reading ``self.mba`` before this
        # binding raises AttributeError — which escapes ``func``'s narrow
        # except set into IDA's optblock callback, suppressing this very log
        # line and leaving AFTER == BEFORE (ticket llr-1330).
        self.mba : ida_hexrays.mba_t = blk.mba
        logger.info(
            "unflat optimize: maturity=%s blk=%s",
            maturity_to_string(getattr(self.mba, "maturity", 0)),
            getattr(blk, "serial", "?"),
        )
        mba = self.mba
        # Profile-scoped recovery maturity (llr-m9r4). The Tigress INDIRECT profile
        # must recover at MMAT_CALLS — its state-write transitions (and the
        # accumulation-loop guard) are constant-folded / DCE'd by GLBOPT1, so the
        # transition map reads empty there. Every OTHER profile recovers at
        # MMAT_GLBOPT1 exactly as before. The rule is registered for both
        # maturities (DEFAULT_UNFLATTENING_MATURITIES), so this gate routes each
        # profile to its own maturity and keeps non-indirect output byte-identical
        # (no golden movement). The indirect profile is detected STRUCTURALLY
        # (llr-trxj): the prolog hook materialized this function iff it is a
        # register-indirect computed-goto dispatcher, and recorded its EA — no
        # config key, no hardcoded addresses. (Matches the existing local-import
        # pattern for this IDA-bound preanalysis module elsewhere in configure().)
        from d810.hexrays.preanalysis.indirect_jump_labels import (
            is_materialized_indirect_dispatcher,
        )
        _is_indirect = is_materialized_indirect_dispatcher(int(mba.entry_ea))
        _target_maturity = (
            ida_hexrays.MMAT_CALLS if _is_indirect else ida_hexrays.MMAT_GLBOPT1
        )
        if mba.maturity != _target_maturity:
            return 0
        func_ea: int = mba.entry_ea
        if func_ea == self._unflat_done_for_ea:
            return 0  # one pipeline run per function/maturity
        self._unflat_done_for_ea = func_ea

        source = lift_function(mba, maturity=mba.maturity)
        # llr-dczv: register the PORTABLE indirect jump-table resolver into the
        # shared front-end (build_dispatch_map_any_kind) BEFORE any detection
        # (the prelim recover_dispatcher, select_family, run_pipeline) so the
        # Tigress indirect dispatcher is recognized end-to-end. The resolver is
        # IDA-free; the live binary table reads live behind the injected
        # HexRaysIndirectJumpTableCapability (bound to the fresh mba). accepts()
        # consults the capability even AFTER materialization removes the m_ijmp
        # (llr-tm3i), and the capability self-gates (None for non-dispatchers),
        # so this is inert on every non-indirect function (no golden regression).
        # Idempotent by name -> rebinds the fresh mba each decompilation.
        _cfg = getattr(self, "config", None)
        register_extra_dispatcher_resolver(
            IndirectJumpDispatcherResolver(
                indirect_tables=HexRaysIndirectJumpTableCapability(mba=mba),
                goto_table_info=(
                    _cfg.get("goto_table_info", {}) or {}
                    if isinstance(_cfg, dict)
                    else {}
                ),
            )
        )
        # Supply the live validated fact view (state observations) so resolve_state_transitions
        # has the transition evidence; without it the chain produces an empty plan.
        fact_view = None
        flow_ctx = getattr(self, "flow_context", None)
        if flow_ctx is not None:
            try:
                fact_view = flow_ctx.validated_fact_view(mba.maturity)
            except Exception:  # noqa: BLE001 — fact view is best-effort input
                logger.debug("unflat: validated_fact_view unavailable", exc_info=True)
        # Pre-mutation BST/interval evidence: walk the PRISTINE mba here (it still matches
        # source.flow_graph; the pipeline mutates it below) so the value-range dispatcher recovery
        # sees the intact BST. PROMOTED TO PRODUCTION (gap3+gap4, ticket llr-t1s8): #4's
        # LowerStateMachine consumes this through the AnalysisManager to build the BST-enriched DAG
        # whose CONDITIONAL_RETURN edges (interval-map classification, not the bounded mba walk)
        # materialize terminal returns — the unflatten returns=0 -> returns=N fix. analyze_bst_dispatcher
        # lives in the hexrays backend (needs the live mba), which the portable LowerStateMachine
        # can't import, so the evidence is computed here in the entry and threaded as an opaque fact.
        # The LiSA-discovery diff log stays diag-only. Self-gating: no dispatcher -> no evidence ->
        # #4 stays on the committed shallow path (byte-identical).
        bst_evidence = None
        prelim = None
        # Thread the rule's min_state_constant into the prelim recovery so the BST
        # evidence (and select_family below) agree on the threshold; defaults to the
        # module MIN_STATE_CONSTANT when the config omits it (golden byte-identical).
        prelim_min_state_constant = min_state_constant_from_config(
            getattr(self, "config", None)
        )
        try:
            prelim = recover_dispatcher(
                source.flow_graph,
                fact_view,
                min_state_constant=prelim_min_state_constant,
            )
            if getattr(prelim, "dispatcher_block_serial", None) is not None:
                bst_evidence = analyze_bst_dispatcher(
                    mba,
                    int(prelim.dispatcher_block_serial),
                    getattr(prelim, "state_var_stkoff", None),
                )
                if _capture_diagnostics_enabled():
                    self._log_lisa_discovery_diff(source.flow_graph, prelim, bst_evidence)
        except Exception:  # noqa: BLE001 — evidence recovery is best-effort
            logger.debug("unflat: pre-pipeline BST evidence failed", exc_info=True)
        facts = AnalysisManager(source.flow_graph, input_facts=fact_view)
        if bst_evidence is not None:
            facts.put_analysis("bst_evidence", bst_evidence)
        backend = HexRaysMutationBackend()
        # Provide the live value-range capability so RecoverStateTransitions can resolve handler
        # transitions the exact equality-chain leaves unresolved (the north-star
        # ``capabilities.optional(ValRangeCapability)``).
        cap_instances = {
            ValRangeCapability: HexRaysValRangeCapability(mba),
            UseDefSafetyCapability: HexRaysUseDefSafetyBackend(),
        }
        # Concolic precision oracle (M3 slice 1, llr-11du): the prove-exact-or-abstain
        # block emulator switch/indirect next-state folds consume. ADDITIVE — no standard
        # pass requires "emulation", and the INDIRECT pipeline that reads it never runs in
        # golden (no live indirect detector). Omitted when the dispatcher state var is
        # unknown (e.g. no dispatcher), so construction can never crash.
        state_var_stkoff = (
            getattr(bst_evidence, "state_var_stkoff", None)
            if bst_evidence is not None
            else None
        )
        if state_var_stkoff is None:
            state_var_stkoff = getattr(prelim, "state_var_stkoff", None)
        if state_var_stkoff is not None:
            state_cell = LocationRef.stack(int(state_var_stkoff), 8)
            cap_instances[EmulationCapability] = HexRaysBlockEmulator(
                mba=mba,
                state_var_stkoff=int(state_var_stkoff),
                state_cell=state_cell,
            )
        capabilities = CapabilitySet(cap_instances)
        # Route through the registered profiles (llr-ibpi): select_family polls the
        # StateMachineCffFamily registry (HodurFamily=equality-chain, ApproovFamily/
        # TigressFamily=switch/indirect) and returns the one whose detect claims this
        # graph; the selected profile's pipeline_for drives run_pipeline. The rule's
        # JSON config is threaded so a project may override the choice via the
        # router_resolution policy (llr-11du); empty config preserves registration order.
        project_config = getattr(self, "config", None)
        family = select_family(
            source.flow_graph,
            project_config=project_config,
            capabilities=backend.capabilities(),
        )
        if family is not None:
            run_pipeline(
                source=source,
                family=family,
                backend=backend,
                facts=facts,
                project_config=project_config,
                maturity=mba.maturity,
                capabilities=capabilities,
            )
        # Iteration diagnostics: where does the unflatten chain stand for this function?
        rec = facts.get_analysis("recover_dispatcher")
        tr = facts.get_analysis("transition_result")
        regions = facts.get_analysis("plan_semantic_regions")
        valrange_confirmable = facts.get_analysis("valrange_confirmable_count")
        logger.info(
            "unflat func=0x%x: input_facts=%s map_rows=%d transitions=%d regions=%d valrange_confirmable=%s",
            func_ea,
            fact_view is not None,
            len(rec.dispatch_map.rows) if rec and rec.dispatch_map else 0,
            len(tr.transitions) if tr else 0,
            len(regions.linear_regions) if regions else 0,
            valrange_confirmable,
        )
        # Diag DB: publish the unflatten structural analysis so the SQLite diag tables are not blind to
        # this path (the legacy recon instrumentation does not run under the flag). llr-6dq7.
        self._publish_unflat_diagnostics(
            mba, source, rec, tr, regions, fact_view, bst_evidence, capabilities
        )
        # Change accounting is the backend's concern (it lowered the plan); the unflatten driver does not
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
            logger.debug("unflat: LiSA dispatcher discovery diff failed", exc_info=True)
            return
        logger.info(
            "unflat discover(LiSA): exact_handlers=%d range_handlers=%d head=%s | "
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
        the diag DB under a separate snapshot (``unflat_read_dag_lisa``).

        The legacy DAG is observed under ``unflat_recover_dispatcher``; the read-off goes
        to ``unflat_read_dag_lisa``, both into ``dag_nodes`` / ``dag_node_blocks`` /
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
            # diff vs the legacy DAG (label unflat_recover_dispatcher) is a SQL query over
            # dag_nodes / dag_node_blocks / dag_local_*, not a log grep.
            my_snap = request_capture_mba_snapshot(
                blocks=_diag_blocks_from_flow_graph(flow_graph),
                label="unflat_read_dag_lisa",
                func_ea=func_ea,
                maturity=maturity,
                phase="post_pipeline",
            )
            if my_snap is not None:
                observe_dag(my_snap, _diag_dag_nodes(my_dag), _diag_dag_edges(my_dag))
                observe_dag_local_facts(my_snap, my_dag)
                logger.info(
                    "unflat read_dag(LiSA): observed %d nodes / %d edges to diag snapshot "
                    "'unflat_read_dag_lisa' (SQL-diff vs 'unflat_recover_dispatcher')",
                    len(my_dag.nodes),
                    len(my_dag.edges),
                )
        except Exception:  # noqa: BLE001 — diag-only, never break optimize
            logger.debug("unflat: read_dag dual-build observe failed", exc_info=True)

    def _publish_unflat_diagnostics(
        self, mba, source, rec, tr, regions, fact_view, bst_evidence=None, capabilities=None
    ) -> None:
        """Populate the structured diag tables for the unflatten path (otherwise blind under the flag).

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
                logger.debug("unflat: observe_state_dispatcher_rows failed", exc_info=True)
        if source is None or not _capture_diagnostics_enabled():
            return
        try:
            snap = request_capture_mba_snapshot(
                blocks=_diag_blocks_from_flow_graph(source.flow_graph),
                label="unflat_recover_dispatcher",
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
                self._unflat_fixpoint_probe(
                    source, bst, fact_view, entry_serial, mba=mba, dmap=dmap
                )
            # Prefer the BST-derived rich transition_result: it backfills handlers reachable only
            # through wide BST range intervals (the range-backed states the exact-only unflatten #2 omits),
            # so the diag DAG node/edge counts approach the legacy oracle instead of being capped by
            # the shallow exact-chain transitions.
            dag_tr = tr
            if bst is not None:
                try:
                    dag_tr = _convert_bst_to_result(bst)
                except Exception:  # noqa: BLE001 — fall back to the unflatten transition_result
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
            logger.debug("unflat: snapshot-correlated diagnostics failed", exc_info=True)

    def _unflat_fixpoint_probe(
        self, source, bst, fact_view, dispatcher_entry: int, *, mba=None, dmap=None
    ) -> None:
        """DIAG-ONLY: measure the sound #2 ``StateTransitionDomain`` fixpoint (llr-mmfq Inc4).

        Builds the value-set ``transition_result`` from the SAME per-block state-write evidence the
        fact view already carries (``StateWriteAnchor``) and the BST handler map, then logs its
        conditional-transition count against the ad-hoc ``bst.conditional_transitions`` walk (the diag
        DAG's CONDITIONAL_TRANSITION source) and the legacy oracle (66). Pure measurement: it feeds
        nothing into the DAG/plan, so production and the diag DAG are untouched. The check confirms
        whether the sound fixpoint constrains the over-count before the Inc5 swap.

        S4 increment B (ticket ``llr-1szn``): the anchor-only ``state_writes`` view marks every
        MBA / opaque next-state write ⊤ (pass-through), so the back-edge exit of those handlers
        yields no clean transition -- the under-count. A prove-exact-or-abstain Hex-Rays emulator
        (:class:`HexRaysBlockEmulator`, stepping the live block) + the concolic refiner
        (:func:`refine_concrete`/:func:`fold_exact`) folds those writes into concrete next-state
        constants where provable, surfacing the dropped transitions. Still strictly a probe (this
        whole method is a try/except diagnostic), so production / the diag DAG are untouched.
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

            def _run(writes):
                tr = analyze_state_transitions_concolic(
                    nodes=list(blocks),
                    entry_nodes=[int(dispatcher_entry)],
                    successors_of=_succ,
                    predecessors_of=_pred,
                    state_writes=writes,
                    dispatcher_entry=int(dispatcher_entry),
                    handler_entry_by_state=handler_entry_by_state,
                    entry_state=StateValue.top(),
                )
                return tr, sum(1 for t in tr.transitions if t.is_conditional)

            fixpoint_tr, cond_anchor = _run(state_writes)

            # S4 B: concrete-refine the unresolved (⊤ / pass-through) next-state writes.
            refined_writes, folded = self._refine_state_writes_concolic(
                base_writes=state_writes,
                dispatcher_entry=int(dispatcher_entry),
                predecessors_of=_pred,
                mba=mba,
                dmap=dmap,
            )
            cond = cond_anchor
            if folded:
                fixpoint_tr, cond = _run(refined_writes)

            bst_cond_edges = sum(
                len(v) for v in (bst.conditional_transitions or {}).values()
            )
            logger.info(
                "unflat #2 fixpoint-probe: fixpoint cond=%d (anchor-only=%d, concrete-folds=%d) "
                "uncond=%d total=%d handlers=%d writes=%d | bst_walk cond_edges=%d | oracle cond=66",
                cond,
                cond_anchor,
                folded,
                len(fixpoint_tr.transitions) - cond,
                len(fixpoint_tr.transitions),
                len(handler_entry_by_state),
                len(refined_writes),
                bst_cond_edges,
            )

            # S4 C1 shadow-diff (ticket llr-1szn): emit StateWriteTransition tuples from
            # the fixpoint's converged states THROUGH the same emission shell, and diff
            # per-back-edge against the production fold (recover_state_write_transitions).
            # Proves byte-equivalence where the fixpoint resolves a state + surfaces the
            # Case-2 opaque-XOR residual the flip (C) is gated on. Diagnostic only.
            state_var_stkoff = getattr(dmap, "state_var_stkoff", None)
            # Source the router the SAME way production does (the llr-oq8v resolver
            # chain): for the collapsed sub_7FFD BST, bst.dispatcher is None and the
            # exact state->handler map wins -- exactly what emit_minimal_unflatten uses.
            _dmap_rows = getattr(dmap, "rows", None) if dmap is not None else None
            dispatcher = select_router(
                default_resolvers(),
                RouterResolutionContext(
                    bst_router=getattr(bst, "dispatcher", None),
                    state_to_handler=dmap.state_to_handler() if _dmap_rows else None,
                    default_target=getattr(dmap, "default_target_block", None),
                    dispatcher_entry=int(dispatcher_entry),
                ),
            )
            if state_var_stkoff is not None and dispatcher is not None:
                fp_result = state_value_fixpoint_result(
                    nodes=list(blocks),
                    entry_nodes=[int(dispatcher_entry)],
                    successors_of=_succ,
                    predecessors_of=_pred,
                    state_writes=refined_writes,
                    handler_entry_by_state=handler_entry_by_state,
                    entry_state=StateValue.top(),
                )
                prod = recover_state_write_transitions(
                    source.flow_graph,
                    dispatcher,
                    int(state_var_stkoff),
                    dispatcher_entry_serial=int(dispatcher_entry),
                )
                shadow = recover_state_write_transitions_via_fixpoint(
                    source.flow_graph,
                    dispatcher,
                    dispatcher_entry_serial=int(dispatcher_entry),
                    out_states=fp_result.out_states,
                )
                d = diff_back_edge_transitions(prod, shadow)
                logger.info(
                    "unflat C1 shadow-diff: prod=%d fixpoint=%d matched=%d "
                    "case2_opaque=%d mismatch=%d",
                    d["prod_edges"],
                    d["fixpoint_edges"],
                    d["matched"],
                    d["case2_opaque"],
                    len(d["mismatch"]),
                )
                if d["mismatch"]:
                    logger.info("unflat C1 mismatch rows: %s", d["mismatch"][:20])

                # B1 (ticket llr-kz7n): the MULTI-CELL global const-fixpoint shadow —
                # reuses _transfer_snapshot_constant_block (stk+reg) so opaque
                # ``state = reg ^ reg`` back-edge writes fold to their const here,
                # closing the single-region mismatch the single-cell shadow leaves
                # unresolved.  Region-partitioned (Case-2) residual is B2.
                shadow_mc = recover_state_write_transitions_via_multicell_fixpoint(
                    source.flow_graph,
                    dispatcher,
                    int(state_var_stkoff),
                    dispatcher_entry_serial=int(dispatcher_entry),
                )
                dmc = diff_back_edge_transitions(prod, shadow_mc)
                logger.info(
                    "unflat C1 shadow-diff[B1 multicell]: prod=%d fixpoint=%d matched=%d "
                    "case2_opaque=%d mismatch=%d",
                    dmc["prod_edges"],
                    dmc["fixpoint_edges"],
                    dmc["matched"],
                    dmc["case2_opaque"],
                    len(dmc["mismatch"]),
                )
                if dmc["mismatch"]:
                    logger.info(
                        "unflat C1 mismatch rows[B1 multicell]: %s", dmc["mismatch"][:20]
                    )

                # B2 (ticket llr-kz7n): predecessor-PARTITIONED multi-cell fold —
                # reproduces the production Case-2 ``via_block`` opaque-split rows by
                # applying the back-edge transfer to each immediate predecessor's
                # OUT store separately.  Diffed with the via_block-aware diff so the
                # 16 sub_7FFD case2 residuals are verified edge-for-edge.
                shadow_pp = recover_state_write_transitions_via_partitioned_fixpoint(
                    source.flow_graph,
                    dispatcher,
                    int(state_var_stkoff),
                    dispatcher_entry_serial=int(dispatcher_entry),
                )
                dpp = diff_back_edge_transitions_partitioned(prod, shadow_pp)
                logger.info(
                    "unflat C1 shadow-diff[B2 partitioned]: prod=%d fixpoint=%d matched=%d "
                    "case2_opaque=%d mismatch=%d",
                    dpp["prod_edges"],
                    dpp["fixpoint_edges"],
                    dpp["matched"],
                    dpp["case2_opaque"],
                    len(dpp["mismatch"]),
                )
                if dpp["mismatch"]:
                    logger.info(
                        "unflat C1 mismatch rows[B2 partitioned]: %s", dpp["mismatch"][:20]
                    )
        except Exception:  # noqa: BLE001 — probe must never break the optimize path
            logger.debug("unflat: fixpoint probe failed", exc_info=True)

    def _refine_state_writes_concolic(
        self, *, base_writes, dispatcher_entry, predecessors_of, mba, dmap
    ):
        """Fold unresolved next-state writes into concrete constants (S4 B, diag-only).

        For each dispatcher back-edge predecessor that has NO resolved anchor (its next-state write
        is currently ⊤ / pass-through, the under-count source), run a prove-exact-or-abstain
        Hex-Rays block emulator and the concolic refiner over the live block. A fold is accepted
        only when :func:`fold_exact` confirms it against the abstract floor (here ⊤, which contains
        every value -- the emulator's own block-stepper is the soundness gate, never asserting a
        wrong constant). Returns ``(refined_writes, folded_count)``; on any miss the base view is
        returned unchanged (graceful degradation == the pure abstract probe).

        Measured on sub_7FFD3338C040: 7 unanchored back-edge predecessors are
        candidates, and the single-block / empty-store emulator folds 0 of them -- it correctly
        ABSTAINS rather than guess.  Those 7 are the opaque-const ``reg ^ reg`` next-state writers
        whose operands are program values defined in OTHER blocks; resolving them needs a
        predecessor-partitioned multi-block fold (the documented T2c disjunctive join), not a
        single-block constant fold.  This wiring is the sound seam for that later store-seeding;
        the probe stays a try/except diagnostic, so the count is reported but never authoritative.
        """
        state_stkoff = getattr(dmap, "state_var_stkoff", None)
        if mba is None or state_stkoff is None:
            return base_writes, 0

        state_cell = LocationRef.stack(int(state_stkoff), 8)
        emulator = HexRaysBlockEmulator(
            mba=mba, state_var_stkoff=int(state_stkoff), state_cell=state_cell
        )
        refined = dict(base_writes)
        folded = 0
        # Candidates: dispatcher back-edge predecessors not already resolved by an anchor.
        # These are exactly the handler exits whose next-state write the anchor view marks
        # ⊤ / pass-through (the under-count source the emulator tries to resolve).
        candidates = {
            int(p) for p in predecessors_of(int(dispatcher_entry))
        } - set(base_writes)
        empty_store = ConcreteStore.of({})
        for serial in sorted(candidates):
            live_block = self._live_mblock(mba, serial)
            if live_block is None:
                continue
            outcome = emulator.eval_block(live_block, empty_store)
            value = ConcolicValue.top(8)
            folded_value = fold_exact(value, outcome, state_cell)
            if folded_value.status is not PrecisionStatus.CONCRETE:
                continue
            concrete = folded_value.concrete
            if concrete is None:
                continue
            refined[serial] = StateValue.of(int(concrete))
            folded += 1
        if logger.debug_on:
            logger.debug(
                "unflat #2 concrete-refine: candidates=%d folded=%d", len(candidates), folded
            )
        return refined, folded

    @staticmethod
    def _live_mblock(mba, serial):
        """Resolve a live ``mblock_t`` by serial, tolerant of API shape; ``None`` on miss."""
        try:
            getter = getattr(mba, "get_mblock", None)
            if getter is not None:
                return getter(int(serial))
        except Exception:  # noqa: BLE001 — best-effort live-block resolution
            return None
        return None


# ---------------------------------------------------------------------------
# Diag-model converters: unflatten structural data -> SQLite diag rows. Diagnostics
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
