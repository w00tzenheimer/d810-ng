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
from d810.backends.hexrays.evidence.emulation_dispatcher_resolver import (
    EmulationDispatcherResolver,
)
from d810.backends.hexrays.evidence.machine_engines_capability import (
    HexRaysMachineRecoveryEnginesCapability,
)
from d810.capabilities.machine_engines import MachineRecoveryEnginesCapability
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
from d810.families.registry import registered_families, select_family
from d810.hexrays.ir_maturity import ir_maturity_to_ida
from d810.ir.maturity import IRMaturity
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
from d810.passes.unflatten.state_machine import LOWER_STATE_MACHINE_PLAN_METADATA
from d810.families.state_machine_cff.pipeline import standard_state_machine_passes
from d810.transforms.minimal_unflatten_emit import (
    TERMINAL_CARRIER_CONVERGENCE_METADATA,
)
from d810.transforms.state_machine_unflatten import lower_to_direct_graph

logger = logging.getLogger("D810.unflat", logging.DEBUG)


class _ReducedProductBypassFamily:
    """Synthetic ``Family`` for the reduced-product family-gate bypass (ticket llr-iy9i).

    The static ``select_family`` poll declines a non-identity-selector machine -- the
    XOR-masked ``switch((state ^ KEY) & MASK)`` (``abc_xor_dispatch``) -- because
    ``build_dispatch_map_any_kind`` finds no compare/switch SHAPE, so no registered
    profile (Hodur=equality-chain, Approov/Tigress=switch/indirect) claims the graph and
    the pipeline never runs. But the reduced-product ``RecoverDispatcher`` routes through
    ``recover_machine``, whose concolic engine SELF-ANCHORS such machines
    (``discover_anchors`` dominant-self-update fallback) and executes them -- the proven
    old-engine recovery. This synthetic family lets the SAME canonical five-pass spine run
    when no static family claimed the graph, so the concolic engine is reached.

    Structurally satisfies the ``Family`` Protocol (``detect`` + ``pipeline_for``) but is
    NOT a ``StateMachineCffFamily`` subclass -- it does NOT auto-register, so ``select_family``
    never returns it and every non-reduced_product config is byte-identical. It is
    instantiated DIRECTLY, only on the reduced_product path, only after ``select_family``
    returns ``None``.
    """

    name = "reduced_product_bypass"
    #: Recover at ``GLOBAL_ANALYZED`` (``MMAT_GLBOPT1``) -- the non-indirect stage the fine
    #: per-family maturity gate admits (matches the registered profiles' default). The XOR
    #: machine (abc_xor_dispatch) self-anchors + recovers here via the concolic engine.
    #: (A CALL_MODELED pre-fold stage was tried for the folded conditional-chain machines
    #: hardened_cond_chain_simple / unwrap_loops and REVERTED: those have only ONE
    #: ``state OP #const`` block at BOTH CALLS and GLBOPT1 -- their transitions are
    #: ``mov #const`` binary-search writes, which the concolic ``_discover`` cannot anchor at
    #: any maturity, so the extra stage helped nothing and only added cost/risk.)
    recovery_maturities = (IRMaturity.GLOBAL_ANALYZED,)

    def detect(self, graph, capabilities, context=None):
        """Claim every graph (truthy) -- the static poll already declined, so this is the
        deliberate reduced_product fallthrough. ``run_pipeline`` re-runs ``detect`` and
        bails on ``None``; returning a non-None sentinel lets the spine run."""
        return self

    def pipeline_for(self, match, context):
        """Run the canonical five-pass spine -- ``RecoverDispatcher`` takes the
        reduced-product branch (recover_machine -> concolic) because the project config
        sets ``recovery_engine == "reduced_product"``."""
        return standard_state_machine_passes()


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
    # Per-family recovery maturity (ticket llr-a93i): each ``StateMachineCffFamily``
    # DECLARES the maturities its shape is recoverable at (``recovery_maturities``); the
    # rule is registered at the UNION below and, after ``select_family`` picks a profile,
    # recovers only at one of THAT profile's declared maturities. This is the seam for
    # per-shape maturity routing -- e.g. a CALLS fallback for the pre-fold folded
    # equality-chains -- WITHOUT forcing every family to every maturity.
    #
    # Current declarations all resolve to MMAT_GLBOPT1 (the golden-tuned non-indirect
    # stage), so behaviour is the historical baseline. MMAT_CALLS stays registered for the
    # INDIRECT one-shot path (routed structurally below). LISTING a pre-fold MMAT_CALLS as
    # a co-equal stage for an equality-chain was tried and REVERTED: with per-(ea,maturity)
    # convergence a function recoverable at BOTH stages commits at the EARLIER one and
    # moves its tuned golden (regressed test_function_ollvm_fla_bcf_sub). MMAT_LOCOPT is
    # never registered -- pre-CALLS a 36-back-edge machine collapses to 3 and mis-recovers.
    DEFAULT_UNFLATTENING_MATURITIES = [
        ida_hexrays.MMAT_CALLS,
        ida_hexrays.MMAT_GLBOPT1,
    ]
    # unflatten does its own dispatcher detection (the resolver chain); bypass the legacy
    # flow-context gate so it always runs.
    HAS_OWN_DISPATCHER_COLLECTOR = True

    #: Hard safety bound on unflatten rounds per function/maturity. A single
    #: spine-redirect pass leaves the dispatcher's comparison ENTRY block reachable;
    #: IDA's optblock loop re-invokes ``optimize`` many times per GLBOPT1 phase, and
    #: each re-invocation re-lifts the post-redirect graph and lets the recovery
    #: discover + redirect the residual dispatcher once IDA's own optimize_global has
    #: collapsed it to a single recoverable edge (approov_real_pattern converges this
    #: way). The loop TERMINATES the moment recovery finds no dispatcher (the graph is
    #: fully unflattened), so this cap is only a backstop against a pathological
    #: non-converging graph -- it is generously above the observed convergence depth
    #: (~19 IDA-interleaved re-invocations for approov_real_pattern) (ticket llr-3gn4).
    _MAX_UNFLATTEN_ROUNDS: int = 64

    def __init__(self) -> None:
        super().__init__()  # ComposedUnflatteningRule: flow_context + optblock lifecycle
        #: ``(func_ea, maturity) -> rounds already run``. Bounded re-run counter
        #: (ticket llr-3gn4), now keyed per-(ea,maturity) for multi-maturity recovery
        #: (ticket llr-a93i): each maturity gets its own round budget, so a maturity
        #: that loops to the cap stops only ITSELF -- the other maturities still get
        #: their full budget.  Convergence (the function is fully unflattened) is the
        #: separate per-ea ``_unflat_done_eas`` terminal, which DOES stop every maturity.
        self._unflat_round_count: dict[tuple[int, int], int] = {}
        #: EAs whose unflatten has converged (recovery found no dispatcher to lower).
        #: Per-ea (not per-maturity): once a function is fully unflattened at ANY
        #: maturity, no later maturity should reprocess it.
        self._unflat_done_eas: set[int] = set()

    def _should_run_unflatten_round(
        self, func_ea: int, *, is_indirect: bool, maturity: int
    ) -> bool:
        """Bounded re-run gate (ticket llr-3gn4): may the unflatten run on ``func_ea`` now?

        The equality-chain / switch profile re-runs (bounded by ``_MAX_UNFLATTEN_ROUNDS``)
        so a residual dispatcher a single spine pass leaves behind is recovered + redirected
        on a later round, letting IDA's optimize_global converge to the dispatcher-free graph
        (approov_real_pattern needs the 2nd round's blk3-entry redirect). The INDIRECT_JUMP
        profile keeps the historical one-shot contract — its recover_terminal_tail /
        folded-loop-guard lowering is tuned for a single pass and re-running drops semantic
        body (the Tigress oracle's password check / XOR output / failure-zero write).

        Mutates the per-ea round bookkeeping when it returns ``True``: increments the round
        count, and on the round cap marks the ea terminal. ``mark_ea_converged`` (called from
        ``optimize`` once recovery reports no dispatcher) is the other terminal path.

        Returns ``True`` to proceed with a round, ``False`` to no-op (already converged,
        capped, or indirect-and-already-ran-once).
        """
        if func_ea in self._unflat_done_eas:
            return False
        key = (int(func_ea), int(maturity))
        rounds = self._unflat_round_count.get(key, 0)
        if is_indirect and rounds >= 1:
            return False  # INDIRECT keeps the historical one-shot contract
        if rounds >= self._MAX_UNFLATTEN_ROUNDS:
            # This (ea, maturity) hit the cap -- stop re-running it here, but DON'T mark
            # the whole ea done: a later maturity may still recover a dispatcher this
            # one could not (the folded equality-chain recovers earlier; a 36-back-edge
            # machine recovers later).  Per-ea convergence is reserved for an actual
            # fully-unflattened graph (``_mark_ea_converged``).
            return False
        self._unflat_round_count[key] = rounds + 1
        return True

    def _mark_ea_converged(self, func_ea: int) -> None:
        """Mark ``func_ea`` terminal — recovery found no dispatcher (graph fully unflattened)."""
        self._unflat_done_eas.add(func_ea)

    def _lower_plan_requested_terminal_convergence(self, facts: object) -> bool:
        getter = getattr(facts, "get_analysis", None)
        if not callable(getter):
            return False
        metadata = getter(LOWER_STATE_MACHINE_PLAN_METADATA, {}) or {}
        if not isinstance(metadata, dict):
            try:
                metadata = dict(metadata)
            except (TypeError, ValueError):
                return False
        return bool(metadata.get(TERMINAL_CARRIER_CONVERGENCE_METADATA))

    def _family_recovery_maturities(self, family) -> "frozenset[int]":
        """Resolve a profile's portable ``recovery_maturities`` (:class:`IRMaturity`) to
        ``ida_hexrays.MMAT_*`` constants — the FINE per-family maturity gate (ticket
        llr-a93i), via the backend adapter :func:`ir_maturity_to_ida`.

        Falls back to the base default (``GLOBAL_ANALYZED`` == ``MMAT_GLBOPT1``, the
        historical non-indirect stage) when a profile omits the attribute; an IRMaturity
        with no Hex-Rays mapping is skipped so a level this backend does not model is simply
        never gated in.
        """
        levels = (
            getattr(family, "recovery_maturities", None) or (IRMaturity.GLOBAL_ANALYZED,)
        )
        out: set[int] = set()
        for level in levels:
            try:
                out.add(ir_maturity_to_ida(level))
            except (ValueError, KeyError):
                continue
        return frozenset(out)

    def _config_recovery_maturities(self) -> "frozenset[int]":
        """Per-PROJECT recovery-maturity override (ticket llr-a93i).

        A project config may pin the recovery stage for its selected profile via
        ``recovery_maturity`` (an :class:`IRMaturity` NAME like ``"CALL_MODELED"`` or its
        value ``"ir.call.modeled"``). This is the config-driven knob that the per-shape
        config separation makes clean: the F6xxx project (folded sub-threshold
        equality-chains -- ``example_libobfuscated``/approov/tigress) recovers at
        ``CALL_MODELED`` (pre-fold, where its dispatcher is still intact), while ollvm's
        project keeps the default ``GLOBAL_ANALYZED`` stage its golden is tuned to --
        without a global maturity change or a cross-maturity fallback. Returns the override
        as ``{ida maturity}`` when set+valid, else empty (the family default applies).
        """
        cfg = getattr(self, "config", None)
        if not isinstance(cfg, dict):
            return frozenset()
        raw = cfg.get("recovery_maturity")
        if not raw:
            return frozenset()
        try:
            level = IRMaturity[raw] if raw in IRMaturity.__members__ else IRMaturity(raw)
            return frozenset({ir_maturity_to_ida(level)})
        except (KeyError, ValueError):
            return frozenset()

    def _union_recovery_maturities(self) -> "frozenset[int]":
        """Union of every registered profile's resolved ``recovery_maturities`` — the
        coarse early gate for the NON-indirect path (ticket llr-a93i). The rule does the
        (lift + prelim + select_family) work at a maturity ONLY if some profile declares
        it, so a function is not re-recovered at a stage no profile wants; the fine
        per-family gate then defers to the SELECTED profile's specific stage. Cached: the
        profile registry is fixed once the family modules import-register.
        """
        cache = getattr(self, "_union_maturities_cache", None)
        if cache is None:
            cache = frozenset().union(
                *(self._family_recovery_maturities(f) for f in registered_families())
            ) or frozenset({ida_hexrays.MMAT_GLBOPT1})
            self._union_maturities_cache = cache
        return cache

    @staticmethod
    def _uses_tigress_indirect_materialization(config: object) -> bool:
        """Return true only for the explicit Tigress indirect profile."""
        if not isinstance(config, dict):
            return False
        profile = str(config.get("profile", "") or "").strip().lower()
        return profile in {
            "tigress_indirect",
            "indirect_jump",
            "indirect_jump_table",
        }

    def configure(self, kwargs):
        # Configure-time hook (project load, runs ONCE). The
        # ComposedUnflatteningRule/FlowOptimizationRule chain sets
        # ``self.config = kwargs`` here.  The Tigress indirect profile registers
        # current-function computed-goto materialization here because ``optimize``
        # runs only AFTER Hex-Rays has built the first MBA.  The registration is
        # cheap; the flowchart event subscriber does the per-function work.
        super().configure(kwargs)
        if not self._uses_tigress_indirect_materialization(self.config):
            return
        try:
            from d810.core.project import register_project_reload_cleanup
            from d810.hexrays.preanalysis.indirect_jump_labels import (
                register_indirect_materialization,
                reset_indirect_materialization,
            )
        except Exception:  # noqa: BLE001 — preanalysis import is best-effort
            logger.warning(
                "unflat: indirect materialization import failed", exc_info=True
            )
            return
        # Clear any prior registration (fresh start for a reconfigured session),
        # then arm the flowchart event subscriber. If ``goto_table_info`` contains
        # the current function, that configured layout is used. Otherwise the
        # subscriber structurally discovers only the current function. It never
        # scans the whole IDB during project load.
        override = dict(self.config.get("goto_table_info", {}) or {})
        try:
            register_project_reload_cleanup(
                "hexrays.indirect_jump_label_materialization",
                reset_indirect_materialization,
            )
            reset_indirect_materialization()
            register_indirect_materialization(override)
        except Exception:  # noqa: BLE001 — registration is best-effort
            logger.warning(
                "unflat: indirect materialization registration failed", exc_info=True
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
        # Profile-scoped recovery maturity (llr-m9r4 + llr-a93i). The Tigress INDIRECT
        # profile recovers ONLY at MMAT_CALLS — its state-write transitions (and the
        # accumulation-loop guard) are constant-folded / DCE'd by GLBOPT1, so the
        # transition map reads empty there, and its terminal-tail / folded-loop-guard
        # lowering is tuned for a single CALLS pass (re-running drops semantic body).
        # The NON-indirect profile recovers at EVERY maturity from LOCOPT through GLBOPT2
        # (ticket llr-a93i): Hex-Rays folds the small equality-chains into structured
        # loops before GLBOPT1, so a GLBOPT1-only recovery misses them (map_rows=0) — the
        # same shapes the legacy EmulatedDispatcherUnflattener caught at MMAT_CALLS. Each
        # function commits at the earliest maturity whose dispatcher is intact + soundly
        # bridged; per-(ea,maturity) round budgeting + per-ea convergence keep an
        # already-unflattened function from being reprocessed later. The indirect profile
        # is detected STRUCTURALLY (llr-trxj): the flowchart event subscriber
        # materialized this function iff it is a register-indirect computed-goto
        # dispatcher, and recorded its EA — no config key, no hardcoded
        # addresses. (Matches the existing local-import pattern for this
        # IDA-bound preanalysis module elsewhere in configure().)
        from d810.hexrays.preanalysis.indirect_jump_labels import (
            is_materialized_indirect_dispatcher,
        )
        _is_indirect = is_materialized_indirect_dispatcher(int(mba.entry_ea))
        # INDIRECT keeps the historical one-shot MMAT_CALLS contract (its
        # terminal-tail / folded-loop-guard lowering is tuned for a single CALLS
        # pass).  The NON-indirect profile now recovers at EVERY maturity from LOCOPT
        # through GLBOPT2 (ticket llr-a93i) so folded equality-chains recover at the
        # pre-fold stage where their dispatcher is still alive.
        if _is_indirect:
            if mba.maturity != ida_hexrays.MMAT_CALLS:
                return 0
        elif int(mba.maturity) not in (
            self._union_recovery_maturities() | self._config_recovery_maturities()
        ):
            # No registered profile (nor a per-project ``recovery_maturity`` override)
            # recovers a non-indirect shape at this maturity; bail BEFORE the expensive
            # lift/prelim/select_family so a stage nothing wants costs nothing (ticket
            # llr-a93i). The fine per-family gate below still defers a profile that wants a
            # DIFFERENT stage within the union/override.
            return 0
        func_ea: int = mba.entry_ea
        # Bounded re-run (ticket llr-3gn4): re-running the unflatten on the re-lifted
        # post-redirect graph discovers + redirects a residual dispatcher a single pass
        # leaves behind, so IDA's optimize_global converges to the dispatcher-free graph.
        # An ea is terminal once recovery finds no dispatcher (the common clean case,
        # identical to the old one-shot behaviour) or the round cap is reached. Self-
        # terminating: a fully-unflattened graph yields no dispatcher, so the next round
        # emits no plan and marks the ea done. GATED to the NON-indirect profile — see
        # :meth:`_should_run_unflatten_round`.
        if not self._should_run_unflatten_round(
            func_ea, is_indirect=_is_indirect, maturity=int(mba.maturity)
        ):
            return 0

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
        # llr-a93i Slice 5: register the emulation-based resolver. It recovers
        # non-identity-selector machines (XOR-masked ``switch((state^KEY)&MASK)``) that the
        # static equality-chain/switch resolvers structurally cannot (their case labels are
        # sub-threshold byte projections; the compared operand is a computed ``m_xor`` tree). It
        # ranks at the LOWEST specificity, so a static win always wins and the expensive
        # emulation walk runs only when both static resolvers return map_rows=0.
        #
        # Registered UNCONDITIONALLY every decompile (like the indirect resolver above) so its
        # bound ``mba`` is always FRESH -- a stale ``mba`` left in the process-global registry by
        # a prior opted-in function would otherwise segfault when a later, non-opted-in function
        # consults the chain (idempotent-by-name replaces the prior instance). The per-project
        # opt-in is carried by ``enabled`` instead: when the config omits
        # ``"emulation_dispatcher"`` the resolver's ``accepts`` returns ``None`` immediately, so
        # it is completely inert and golden configs are byte-identical.
        register_extra_dispatcher_resolver(
            EmulationDispatcherResolver(
                mba=mba,
                enabled=bool(isinstance(_cfg, dict) and _cfg.get("emulation_dispatcher")),
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
        # Reduced-product recovery engines (ticket llr-iy9i): the live-mba spine
        # (DEFFAI) + concolic (the old-engine recovery behind the contract) the
        # ``RecoverDispatcher`` pass composes when the project config sets
        # ``recovery_engine == "reduced_product"``. Bound to a FRESH ``mba`` each
        # decompile (staleness rule). ``concolic_enabled`` carries the existing
        # ``emulation_dispatcher`` opt-in so a project that already enables the
        # emulation resolver also gets the concolic engine here. Registered
        # unconditionally so a later non-opted-in function never sees a stale ``mba``;
        # the orchestrator only consults this capability on the reduced_product path.
        # The concolic leg is the reduced_product path's recovery mechanism, so it
        # must be live whenever that engine is selected -- not only behind the older
        # ``emulation_dispatcher`` resolver opt-in. Enable on EITHER signal: the
        # explicit emulation-resolver opt-in OR ``recovery_engine == reduced_product``
        # (the orchestrator consults this capability only on that path, so enabling it
        # here is inert for every other project).
        _concolic_on = isinstance(_cfg, dict) and (
            bool(_cfg.get("emulation_dispatcher"))
            or _cfg.get("recovery_engine") == "reduced_product"
        )
        cap_instances[MachineRecoveryEnginesCapability] = (
            HexRaysMachineRecoveryEnginesCapability(
                mba=mba,
                min_state_constant=min_state_constant_from_config(
                    getattr(self, "config", None)
                ),
                concolic_enabled=bool(_concolic_on),
            )
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
        # Reduced-product family-gate bypass (ticket llr-iy9i): the static select_family
        # poll declines a non-identity-selector machine (XOR-masked
        # ``switch((state^KEY)&MASK)`` -- abc_xor_dispatch) because no compare/switch SHAPE
        # is found, so without this the pipeline (and thus RecoverDispatcher ->
        # recover_machine -> the SELF-ANCHORING concolic engine) never runs for it. When the
        # project config opts into the reduced-product engine, fall through to the canonical
        # five-pass spine via a synthetic bypass family so the concolic engine is reached
        # (it self-anchors via discover_anchors' dominant-self-update fallback -- the proven
        # old-engine recovery). SCOPED to recovery_engine == "reduced_product" ONLY: this
        # synthetic family is instantiated directly (never auto-registered), so every other
        # config (hodur/approov/tigress/ollvm -- which sets no such key) is byte-identical.
        if family is None and (
            isinstance(project_config, dict)
            and project_config.get("recovery_engine") == "reduced_product"
        ):
            if logger.debug_on:
                logger.debug(
                    "unflat: reduced_product family-gate bypass for func=0x%x at %s "
                    "(static select_family declined)",
                    int(mba.entry_ea),
                    maturity_to_string(int(mba.maturity)),
                )
            family = _ReducedProductBypassFamily()
        # Fine per-family maturity gate (ticket llr-a93i): a profile recovers ONLY at one
        # of its declared ``recovery_maturities``. When a family claims this graph but not
        # at the CURRENT maturity, skip (return 0) and wait for the stage it wants -- the
        # dispatcher is not converged, so a later maturity still recovers it. INDIRECT
        # bypasses this gate: it is routed to MMAT_CALLS structurally above, independent of
        # the selected family's declaration.
        # A per-project ``recovery_maturity`` override (config-driven, ticket llr-a93i)
        # REPLACES the selected profile's declared maturities for this project; absent it,
        # the profile's own ``recovery_maturities`` apply.
        _target_maturities = (
            self._config_recovery_maturities()
            or self._family_recovery_maturities(family)
        )
        if (
            family is not None
            and not _is_indirect
            and int(mba.maturity) not in _target_maturities
        ):
            if logger.debug_on:
                logger.debug(
                    "unflat: family=%s defers func=0x%x at %s (wants %s)",
                    getattr(family, "name", "?"),
                    int(mba.entry_ea),
                    maturity_to_string(int(mba.maturity)),
                    sorted(maturity_to_string(m) for m in _target_maturities),
                )
            return 0
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
        # Termination (ticket llr-3gn4): mark the ea done the moment recovery finds NO
        # dispatcher to lower -- the graph is clean or fully unflattened, so re-running
        # would only re-lift and re-detect nothing. The common case on the very first round
        # for every already-clean function (hodur / sub_7FFD / the 4 clean approov fns), so
        # they run once. A round that still SEES a dispatcher but emits no redirect is NOT
        # terminal: approov_real_pattern's residual blk3 entry only becomes recoverable
        # after IDA's interleaved optimize_global collapses it several re-invocations later.
        #
        # NOTE (ticket llr-a93i): this keys on the pipeline ``rec`` (a profile claimed and
        # recovered a dispatcher). With the current GLBOPT1-only family declarations that is
        # baseline behaviour. A future per-family CALLS FALLBACK (where a profile recovers
        # at more than one maturity) must make this maturity-aware -- converge only once the
        # function is unflattened or its LAST declared maturity is exhausted -- so an early
        # maturity that declines does not foreclose a later one.
        dispatcher_present = (
            rec is not None
            and getattr(rec, "dispatcher_block_serial", None) is not None
        )
        if not dispatcher_present:
            self._mark_ea_converged(func_ea)
        # Report 0 to IDA's optblock callback (historical contract): convergence is driven by
        # IDA's own optblock re-invocation cadence (it re-calls ``optimize`` per block per
        # GLBOPT1 round) interleaved with its optimize_global cleanup, which the bounded re-run
        # rides. Reporting the real change count instead makes IDA front-load an extra
        # optimize_global that partially collapses the residual dispatcher BEFORE the next
        # round can recover + redirect it, so the convergence redirect is never emitted and the
        # dispatcher survives (verified: returning the count regressed approov_real_pattern).
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
        self, mba, source, rec, tr, regions, fact_view, range_evidence=None, capabilities=None
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
                    dispatcher_kind=dmap.router_kind.name,
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
            bst = range_evidence
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
                    condition_chain_router=getattr(bst, "dispatcher", None),
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
