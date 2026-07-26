from __future__ import annotations

import contextlib
import dataclasses
import importlib
import json
import pathlib

from d810.core import (
    MOP_CONSTANT_CACHE,
    MOP_TO_AST_CACHE,
    typing,
)
from d810.core.decompilation_session import DecompilationSessionEvent
from d810.core.logging import getLogger
from d810.core.provider_phase import ProviderPhaseSnapshot
from d810.core.project import (
    emit_preanalysis_fact_collector_registration,
)
from d810.core.registry import EventEmitter
from d810.core.rule_scope import (
    FunctionRuleOverlay,
    RuleInferenceOverlay,
    RuleScopeEvent,
    RuleScopeInvalidation,
    RuleScopeService,
)
from d810.core.stats import OptimizationStatistics
from d810.backends.ast.z3 import Z3MopProver
from d810.backends.hexrays.registration import (
    ensure_hexrays_fact_lifter_registered,
)
from d810.diagnostics.post_d810_handoff import detect_post_d810_handoff_violations
from d810.evaluator.hexrays_microcode.dispatcher_artifacts import (
    plan_dispatcher_state_return_carrier_artifact,
)
from d810.hexrays.hooks.ctree_hooks import CtreeOptimizerManager
from d810.hexrays.hooks.hexrays_hooks import HexraysDecompilationHook
from d810.hexrays.hooks.optblock_adapter import BlockOptimizerManager
from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager
from d810.hexrays.ir_maturity import HexRaysMaturity
from d810.core.decompilation_session import DecompilationEvent
from d810.hexrays.lifecycle import HEXRAYS_MICROCODE_PROVIDER
from d810.optimizers.microcode.flow.context import FlowMaturityContext
from d810.optimizers.microcode.instructions.handler import (
    InstructionOptimizer,
)
from d810.passes.function_prior_config import (
    function_prior_keys,
    load_function_analysis_priors_from_config,
)
from d810.passes.function_priors import FunctionAnalysisPriors
from d810.passes.inferences import unflattening_inference
from d810.passes.pass_pipeline_factory import (
    PassPipelineSpec,
    build_pass_pipeline_spec,
    pass_pipeline_spec_from_config,
)
from d810.passes.analysis_runtime_factory import (
    build_analysis_runtime_bundle,
)
from d810.passes.scheduler import PassScheduler
from d810.passes.store import shutdown_all_writers
from d810.manager.decompilation_lifecycle import (
    DecompilationLifecycleCoordinator,
    FlowgraphReadyPayload,
)
from d810.manager.hexrays_pass_pipeline import build_hexrays_flowgraph_pipeline
from d810.manager.post_d810_runtime import HexRaysPostD810Runtime
from d810.manager.profiling import ProfilingController
from d810.manager.rule_scope_runtime import RuleScopeRuntime


D810_LOG_DIR_NAME = "d810_logs"

logger = getLogger("D810")


def _load_semantic_route_reference_oracle_registry(
    config,
    *,
    config_root: pathlib.Path | None = None,
):
    """Load the configured exact-input route manifests through one schema."""
    from d810.core.semantic_route_oracle import ReferenceRouteOracleRegistry

    raw_paths = config.get("semantic_route_oracle_manifests")
    if raw_paths is None:
        return None
    if (
        not isinstance(raw_paths, (list, tuple))
        or not raw_paths
        or any(not isinstance(item, str) or not item for item in raw_paths)
    ):
        raise ValueError(
            "semantic_route_oracle_manifests must be a non-empty array of paths"
        )
    root = (
        pathlib.Path(__file__).resolve().parents[1] / "conf"
        if config_root is None
        else pathlib.Path(config_root)
    ).resolve()
    manifests = []
    for raw_path in raw_paths:
        relative_path = pathlib.Path(raw_path)
        manifest_path = (root / relative_path).resolve()
        if relative_path.is_absolute() or (
            manifest_path != root and root not in manifest_path.parents
        ):
            raise ValueError(
                "semantic route oracle manifests must stay inside the "
                "configuration root"
            )
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(
                f"semantic route oracle manifest must be an object: {manifest_path}"
            )
        manifests.append(payload)
    return ReferenceRouteOracleRegistry.from_manifests(tuple(manifests))


def _build_native_preanalysis_key(*, function_ea, profile_config):
    """Hex-Rays backend port for lifecycle-owned portable identity."""
    from d810.backends.hexrays.native_preanalysis_key import (
        build_native_preanalysis_key,
    )

    return build_native_preanalysis_key(
        function_ea,
        profile_config=profile_config,
    )


def _initialize_resolver_attachment(
    session,
    *,
    semantic_route_reference_oracle_provider=None,
):
    """Create the optimizer-owned attachment before lower callbacks consume it."""
    from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
        resolver_session_state,
    )

    state = resolver_session_state(session)
    state.frontend_normalization_plan_provider = (
        session.frontend_normalization_plan_authority
    )
    state.semantic_route_reference_oracle_provider = (
        semantic_route_reference_oracle_provider
    )
    return state


def _build_current_mba_identity_index(*, session, mba):
    """Hex-Rays-owned live-index port injected into the lifecycle coordinator."""
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.detached_handler_island import stable_mba_identity
    from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
        resolver_session_state,
    )

    state = resolver_session_state(session)
    if state.preopt_union_import_active and state.identity_index is not None:
        return state.identity_index

    maturity_stage = HexRaysMaturity.from_id(int(getattr(mba, "maturity", 0) or 0))
    if maturity_stage is None:
        raise ValueError("current MBA identity index requires a known maturity")
    if maturity_stage.value < HexRaysMaturity.MMAT_LOCOPT.value:
        reference_oracle = state.semantic_route_reference_oracle_provider
        if (
            reference_oracle is None
            or reference_oracle.reference_oracle_scope_for(
                int(session.function_ea),
                session.native_key,
            )
            is None
        ):
            return None
        build_graph = getattr(mba, "build_graph", None)
        if not callable(build_graph):
            raise TypeError("current MBA identity index requires a live graph")
        build_graph()

    current_mba_identity_binding = state.current_mba_identity_binding_for(
        stable_mba_identity(mba)
    )
    from d810.core.maturity_labels import mmat_label
    from d810.core.observability import emit as emit_diagnostic
    from d810.core.observability_events import IdentityDecisionObserved

    maturity = mmat_label(int(getattr(mba, "maturity", 0) or 0))

    def _observe_identity(observation):
        identity = observation.identity
        anchor_ea = min(
            identity.exact_instruction_eas,
            default=identity.native_ranges.intervals[0].start_ea,
        )
        block = observation.result.block
        candidates = []
        for candidate in observation.candidates:
            candidate_identity = candidate.handle.stable_identity
            candidate_anchor_ea = candidate.anchor_ea
            if candidate_identity is None or candidate_anchor_ea is None:
                continue
            candidates.append(
                {
                    "block": (
                        f"blk{int(candidate.serial)}@0x{int(candidate_anchor_ea):X}"
                    ),
                    "serial": int(candidate.serial),
                    "anchor_ea": int(candidate_anchor_ea),
                    "provenance": candidate.handle.provenance.value,
                    "stable_identity": candidate_identity.to_dict(),
                }
            )
        emit_diagnostic(
            IdentityDecisionObserved(
                session_id=session.identity_key,
                func_ea=int(session.function_ea),
                decision_kind=observation.decision_kind,
                consumer="current_mba_identity_index",
                identity_role="block",
                native_key_json=identity.native_key.to_json(),
                exact_eas_json=json.dumps(sorted(identity.exact_instruction_eas)),
                native_ranges_json=json.dumps(
                    [
                        {
                            "start_ea": interval.start_ea,
                            "end_ea": interval.end_ea,
                        }
                        for interval in identity.native_ranges.intervals
                    ],
                    sort_keys=True,
                ),
                primary_anchor_ea=int(anchor_ea),
                current_serial=None if block is None else int(block.serial),
                mba_generation=int(observation.mba_generation),
                evidence_generation=int(observation.evidence_generation),
                maturity=maturity,
                outcome=observation.result.status.name.lower(),
                candidates_json=json.dumps(candidates, sort_keys=True),
                reason="current MBA stable-identity lookup",
            )
        )

    index = MbaBlockIdentityIndex.from_mba(
        mba,
        generation=0,
        native_key=session.native_key,
        evidence_generation=session.native_preanalysis.evidence_generation,
        maturity=int(mba.maturity),
        session_id=session.identity_key,
        current_mba_identity_binding=current_mba_identity_binding,
        decision_observer=_observe_identity,
    )
    state.bind_current_mba(index)
    return index


def _new_current_mba_mutation_gateway(
    *,
    session,
    identity_index,
    maturity: int,
    event_emitter,
):
    """Construct one Hex-Rays transaction controller over the current index."""
    from d810.hexrays.mutation.mba_mutation_events import MbaMutationGateway
    from d810.manager.fragment_publication_lifecycle import (
        SessionFragmentPublicationLifecycleAuthority,
    )

    return MbaMutationGateway(
        native_key=session.native_key,
        generation=int(identity_index.generation),
        session_id=session.identity_key,
        function_ea=int(session.function_ea),
        maturity=int(maturity),
        identity_index=identity_index,
        event_emitter=event_emitter,
        lifecycle_authority=SessionFragmentPublicationLifecycleAuthority(
            native_key=session.native_key,
            state=session.native_preanalysis,
        ),
    )


def _new_semantic_native_body_materializer(*, session, mba):
    """Construct the sole Hex-Rays native-body materialization capability."""
    from d810.hexrays.mutation.detached_handler_island import (
        CallsSemanticNativeBodyMaterializer,
        PreoptUnionSemanticNativeBodyMaterializer,
    )

    maturity = int(mba.maturity)
    native_maturity = HexRaysMaturity.from_id(maturity)
    if native_maturity in {
        HexRaysMaturity.MMAT_GENERATED,
        HexRaysMaturity.MMAT_PREOPTIMIZED,
    }:
        evidence_generation = int(session.native_preanalysis.evidence_generation)

        def observe_prepared_body_fact(plan, native_body, fact) -> None:
            session.frontend_normalization_plan_authority.record_prepared_body_fact(
                plan,
                native_body,
                fact,
                evidence_generation=evidence_generation,
            )

        return PreoptUnionSemanticNativeBodyMaterializer(
            mba=mba,
            function_ea=int(session.function_ea),
            prepared_fact_observer=observe_prepared_body_fact,
        )
    if native_maturity is HexRaysMaturity.MMAT_CALLS:

        def request_call_companions(
            ranges: tuple[tuple[int, int], ...],
        ) -> bool:
            from d810.core.observability import emit as emit_diagnostic
            from d810.core.observability_events import LifecycleEventObserved
            from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
                resolver_session_state,
            )

            state = resolver_session_state(session)
            changed = state.request_call_companion_ranges(ranges)
            restart_requested = session.native_preanalysis.request_generated_restart(
                evidence_family="call_companion_ranges",
                reason="CALLS requested analyzed native call companions",
            )
            accepted = bool(
                all(
                    tuple(map(int, native_range)) in state.pending_call_companion_ranges
                    for native_range in ranges
                )
                and (
                    restart_requested
                    or session.native_preanalysis.has_pending_generated_restart
                )
            )
            emit_diagnostic(
                LifecycleEventObserved(
                    session_id=session.identity_key,
                    func_ea=int(session.function_ea),
                    event_kind="semantic_native_body_companion_request",
                    provider="semantic_native_body_materializer",
                    maturity="MMAT_CALLS",
                    phase="canonical_semantic_preparation",
                    evidence_generation=int(
                        session.native_preanalysis.evidence_generation
                    ),
                    mba_generation_before=int(session.current_mba_generation),
                    mba_generation_after=int(session.current_mba_generation),
                    summary=(
                        "analyzed CALLS companion preparation "
                        f"{'requested' if accepted else 'rejected'}"
                    ),
                    payload={
                        "ranges": [
                            {
                                "start_ea": int(start_ea),
                                "end_ea": int(end_ea),
                            }
                            for start_ea, end_ea in ranges
                        ],
                        "queue_changed": bool(changed),
                        "restart_requested": bool(restart_requested),
                        "accepted": bool(accepted),
                    },
                )
            )
            return accepted

        return CallsSemanticNativeBodyMaterializer(
            mba=mba,
            function_ea=int(session.function_ea),
            request_call_companions=request_call_companions,
        )
    raise ValueError(
        "unsupported semantic native-body materializer maturity: "
        f"{maturity if native_maturity is None else native_maturity.name}"
    )


def maybe_run_tail_distinct(
    mba: typing.Any,
    *,
    mutation_gateway: typing.Any,
) -> None:
    """Env-gated hook: ``D810_TAIL_DISTINCT_BYTE`` topology-only experiment.

    Thin manager-level re-export of the implementation in
    :mod:`d810.hexrays.mutation.byte_emit_tail_isolation_runtime`.  The real
    helper lives outside ``d810.manager`` so optimizer call sites can
    import it without crossing the layered-architecture import contract
    (optimizers must not depend on ``d810.ui``, and manager transitively
    imports UI).
    """
    from d810.hexrays.mutation.byte_emit_tail_isolation_runtime import (
        maybe_run_tail_distinct as _impl,
    )

    _impl(mba, mutation_gateway=mutation_gateway)


def _maturity_name(maturity: int) -> str:
    """Map IDA maturity integer to a human-readable name for file labels."""
    try:
        import ida_hexrays

        _names = {
            ida_hexrays.MMAT_ZERO: "MMAT_ZERO",
            ida_hexrays.MMAT_GENERATED: "MMAT_GENERATED",
            ida_hexrays.MMAT_PREOPTIMIZED: "MMAT_PREOPTIMIZED",
            ida_hexrays.MMAT_LOCOPT: "MMAT_LOCOPT",
            ida_hexrays.MMAT_CALLS: "MMAT_CALLS",
            ida_hexrays.MMAT_GLBOPT1: "MMAT_GLBOPT1",
            ida_hexrays.MMAT_GLBOPT2: "MMAT_GLBOPT2",
            ida_hexrays.MMAT_GLBOPT3: "MMAT_GLBOPT3",
            ida_hexrays.MMAT_LVARS: "MMAT_LVARS",
        }
        return _names.get(maturity, f"MMAT_{maturity}")
    except ImportError:
        return f"MMAT_{maturity}"


@dataclasses.dataclass
class D810Manager:
    log_dir: pathlib.Path
    stats: OptimizationStatistics = dataclasses.field(
        default_factory=OptimizationStatistics
    )
    instruction_optimizer_rules: list = dataclasses.field(default_factory=list)
    instruction_optimizer_config: dict = dataclasses.field(default_factory=dict)
    block_optimizer_rules: list = dataclasses.field(default_factory=list)
    block_optimizer_config: dict = dataclasses.field(default_factory=dict)
    ctree_optimizer_rules: list = dataclasses.field(default_factory=list)
    ctree_optimizer_config: dict = dataclasses.field(default_factory=dict)
    config: dict = dataclasses.field(default_factory=dict)
    _semantic_route_reference_oracle_registry: object | None = dataclasses.field(
        default=None,
        init=False,
        repr=False,
    )
    event_emitter: EventEmitter = dataclasses.field(default_factory=EventEmitter)
    rule_scope_service: RuleScopeService = dataclasses.field(
        default_factory=RuleScopeService
    )
    block_pass_scheduler: PassScheduler = dataclasses.field(
        default_factory=PassScheduler
    )
    instruction_pass_scheduler: PassScheduler = dataclasses.field(
        default_factory=PassScheduler
    )
    profiling: ProfilingController = dataclasses.field(init=False)
    rule_scope_runtime: RuleScopeRuntime = dataclasses.field(init=False)
    instruction_optimizer: InstructionOptimizerManager = dataclasses.field(init=False)
    block_optimizer: BlockOptimizerManager = dataclasses.field(init=False)
    ctree_optimizer: CtreeOptimizerManager = dataclasses.field(init=False)
    hx_decompiler_hook: HexraysDecompilationHook = dataclasses.field(init=False)
    _started: bool = dataclasses.field(default=False, init=False)
    _preanalysis_runtime: typing.Any = dataclasses.field(default=None, init=False)
    _analysis_runtime: typing.Any = dataclasses.field(default=None, init=False)
    _analysis_bundle: typing.Any = dataclasses.field(default=None, init=False)
    decompilation_lifecycle: DecompilationLifecycleCoordinator = dataclasses.field(
        default=None, init=False
    )
    _post_d810_runtime: typing.Any = dataclasses.field(default=None, init=False)
    _database_identity: str = dataclasses.field(default="", init=False)
    _function_analysis_priors: dict[str, FunctionAnalysisPriors] = dataclasses.field(
        default_factory=dict, init=False
    )

    def __post_init__(self) -> None:
        self.profiling = ProfilingController(self.log_dir)
        self.rule_scope_runtime = RuleScopeRuntime(
            storage_factory=self._create_rule_scope_storage,
            rule_scope_service=self.rule_scope_service,
            event_emitter=self.event_emitter,
            log_dir=self.log_dir,
            project_name_provider=lambda: str(self.config.get("project_name", "")),
            config_provider=lambda: self.config,
        )

    @property
    def started(self):
        return self._started

    @property
    def profiler(self):
        return self.profiling.profiler

    @property
    def cprofiler(self):
        return self.profiling.cprofiler

    def prepare_native_preanalysis(self, function_ea: int) -> int:
        """Establish resolver evidence before the first top-level decompile.

        This is the manager-owned entry point for UI-triggered decompilations.
        It creates the same lifecycle session that the Hex-Rays hook will
        subsequently reuse, then resolves native computed-goto evidence before
        the first MBA is generated.  No function-EA registry or second UI
        preflight lifecycle is retained.
        """
        lifecycle = self.decompilation_lifecycle
        if lifecycle is None:
            return 0
        function_ea = int(function_ea)
        try:
            session, _created = lifecycle.ensure_hexrays_session(
                function_ea=function_ea,
                database_identity=self._database_identity,
            )

            from d810.optimizers.microcode.flow.jumps.computed_goto_resolver import (
                _has_unresolved_computed_goto,
                discover_static_native_bootstrap_routes,
                prepare_detached_handler_snippets,
                prepare_requested_detached_call_companions,
                prepare_terminal_return_carrier_evidence,
                stage_computed_goto_preanalysis,
            )
            from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
                resolver_session_state,
            )

            state = resolver_session_state(session)
            if state.snippet_capture_active:
                return 0
            resolution = state.portable_evidence.computed_goto_resolution
            if resolution is None:
                if not _has_unresolved_computed_goto(function_ea):
                    return 0
                resolution = stage_computed_goto_preanalysis(
                    function_ea,
                    state=state,
                )
                if resolution is None or not resolution.jmp_targets:
                    return 0
            if state.materialization is None and not state.materialized:
                state.begin_materialization(resolution)
            lifecycle.begin_native_preanalysis(session)
            try:
                companion_outcomes = prepare_requested_detached_call_companions(state)
                if companion_outcomes:
                    from d810.core.observability import emit as emit_diagnostic
                    from d810.core.observability_events import (
                        LifecycleEventObserved,
                    )

                    for outcome in companion_outcomes:
                        emit_diagnostic(
                            LifecycleEventObserved(
                                session_id=session.identity_key,
                                func_ea=int(session.function_ea),
                                event_kind=("semantic_native_body_companion_prepared"),
                                provider="manager_native_preanalysis",
                                phase="detached_calls_preparation",
                                evidence_generation=int(
                                    session.native_preanalysis.evidence_generation
                                ),
                                mba_generation_before=int(
                                    session.current_mba_generation
                                ),
                                mba_generation_after=int(
                                    session.current_mba_generation
                                ),
                                summary=(
                                    "analyzed CALLS companion "
                                    f"{'captured' if outcome.captured else 'abstained'}"
                                ),
                                payload={
                                    "native_range": {
                                        "start_ea": int(outcome.native_range[0]),
                                        "end_ea": int(outcome.native_range[1]),
                                    },
                                    "calls_native_ranges": [
                                        {
                                            "start_ea": int(start_ea),
                                            "end_ea": int(end_ea),
                                        }
                                        for start_ea, end_ea in (
                                            outcome.calls_native_ranges
                                        )
                                    ],
                                    "component_target_ea": (
                                        None
                                        if outcome.component_target_ea is None
                                        else int(outcome.component_target_ea)
                                    ),
                                    "preopt_call_eas": [
                                        int(ea) for ea in outcome.preopt_call_eas
                                    ],
                                    "calls_call_eas": [
                                        int(ea) for ea in outcome.calls_call_eas
                                    ],
                                    "mismatch_ea": (
                                        None
                                        if outcome.mismatch_ea is None
                                        else int(outcome.mismatch_ea)
                                    ),
                                    "captured": bool(outcome.captured),
                                    "reason": str(outcome.reason),
                                    "pending_ranges": [
                                        {
                                            "start_ea": int(start_ea),
                                            "end_ea": int(end_ea),
                                        }
                                        for start_ea, end_ea in (
                                            state.pending_call_companion_ranges
                                        )
                                    ],
                                },
                            )
                        )
                prepared_carriers = prepare_terminal_return_carrier_evidence(state)
                prepared_snippets = prepare_detached_handler_snippets(state)
                # Snippet preparation publishes the portable transfer
                # inventory that identifies the state selector.  Bootstrap
                # discovery must consume that completed inventory; running it
                # earlier always abstains with no selectors, while the later
                # flowchart fallback may already see materialization complete.
                discover_static_native_bootstrap_routes(function_ea, state)
                return (
                    sum(int(outcome.captured) for outcome in companion_outcomes)
                    + int(prepared_carriers)
                    + int(prepared_snippets)
                )
            finally:
                lifecycle.finish_native_preanalysis(session)
        except Exception:
            logger.debug(
                "native preanalysis preflight failed for func=0x%X",
                function_ea,
                exc_info=True,
            )
            return 0

    def decompile_with_native_preanalysis(
        self,
        function_ea: int,
        decompile: typing.Callable[[], typing.Any],
        invalidate_cached_cfunc: typing.Callable[[], None],
    ) -> typing.Any:
        """Run one top-level decompile plus bounded generated retries.

        CALLS can stage evidence for PREOPT but cannot restart generated
        microcode. This manager-owned controller performs the follow-up only
        after the first decompile unwinds; the retained session lets its
        flowchart callback issue the one supported ``MERR_REDO``.
        """
        function_ea = int(function_ea)
        result: typing.Any = None
        for _round in range(3):
            self.prepare_native_preanalysis(function_ea)
            from d810.optimizers.microcode.flow.jumps.computed_goto_resolver import (
                acquire_detached_call_stack_point_overlay,
            )

            session = self.decompilation_lifecycle.current_session(function_ea)
            overlay_lease = (
                None
                if session is None
                else acquire_detached_call_stack_point_overlay(session)
            )
            # Native preanalysis may generate top-level or snippet cfuncs while
            # capturing pristine templates.  None of those cache entries owns
            # the live decompile that follows this preparation round.
            try:
                invalidate_cached_cfunc()
                result = decompile()
            finally:
                if overlay_lease is not None:
                    overlay_lease.release()
            if self.decompilation_lifecycle.has_exhausted_poison_restart(function_ea):
                raise RuntimeError(
                    "native preanalysis poison restart exhausted for "
                    f"0x{function_ea:X}; refusing poisoned output"
                )
            if not self.decompilation_lifecycle.has_pending_generated_restart(
                function_ea
            ):
                break
        else:
            raise RuntimeError(
                "native preanalysis generated-restart budget exhausted with "
                f"a restart still pending for 0x{function_ea:X}"
            )
        return result

    @property
    def storage(self):
        return self.rule_scope_runtime.storage

    @storage.setter
    def storage(self, value):
        self.rule_scope_runtime.storage = value

    @property
    def analysis_db(self) -> pathlib.Path | None:
        """Path to the analysis SQLite database, or None when disabled."""
        bundle = getattr(self, "_analysis_bundle", None)
        if bundle is None:
            return None
        return bundle.db_path

    def configure(self, **kwargs):
        self.config = kwargs
        self._semantic_route_reference_oracle_registry = (
            _load_semantic_route_reference_oracle_registry(kwargs)
        )
        self.rule_scope_runtime.configure(kwargs)
        self._load_function_analysis_priors_from_config(
            kwargs.get("function_analysis_priors", {})
        )

    @staticmethod
    def _create_rule_scope_storage(target, *, backend: str = "sqlite"):
        from d810.core.persistence import create_optimization_storage

        return create_optimization_storage(target, backend=backend)

    @staticmethod
    def _coerce_module_names(value: typing.Any) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            items = (value,)
        else:
            try:
                items = tuple(value)
            except TypeError:
                items = (value,)
        return tuple(
            dict.fromkeys(str(item).strip() for item in items if str(item).strip())
        )

    def _load_preanalysis_profile_modules(self) -> None:
        for module_name in self._coerce_module_names(
            self.config.get("preanalysis_profile_modules")
        ):
            try:
                importlib.import_module(module_name)
            except Exception:
                logger.exception(
                    "Preanalysis profile module load failed: %s",
                    module_name,
                )

    def _load_function_analysis_priors_from_config(self, raw: typing.Any) -> None:
        self._function_analysis_priors = load_function_analysis_priors_from_config(raw)

    def snapshot_function_analysis_priors(self) -> dict[str, FunctionAnalysisPriors]:
        return dict(self._function_analysis_priors)

    def restore_function_analysis_priors(
        self,
        snapshot: dict[str, FunctionAnalysisPriors] | None,
    ) -> None:
        self._function_analysis_priors = dict(snapshot or {})

    def add_function_analysis_priors(
        self,
        function: str | int,
        priors: FunctionAnalysisPriors,
    ) -> None:
        existing = self.function_analysis_priors(function)
        merged = existing.merge(priors)
        for key in function_prior_keys(function):
            self._function_analysis_priors[key] = merged

    def function_analysis_priors(self, function: str | int) -> FunctionAnalysisPriors:
        for key in function_prior_keys(function):
            priors = self._function_analysis_priors.get(key)
            if priors is not None:
                return priors
        return FunctionAnalysisPriors()

    def function_analysis_priors_for_ea(self, func_ea: int) -> FunctionAnalysisPriors:
        identifiers: list[str | int] = [int(func_ea)]
        try:
            import ida_name

            name = ida_name.get_name(int(func_ea))
        except Exception:
            name = ""
        if name:
            identifiers.append(str(name))

        priors = FunctionAnalysisPriors()
        for identifier in identifiers:
            priors = priors.merge(self.function_analysis_priors(identifier))
        return priors

    def emit_rule_scope_invalidation(
        self,
        reason: RuleScopeEvent,
        *,
        project_name: str | None = None,
        func_eas: frozenset[int] | None = None,
        changed_rules: frozenset[str] | None = None,
    ) -> None:
        self.event_emitter.emit(
            reason,
            RuleScopeInvalidation(
                reason=reason,
                project_name=project_name,
                func_eas=func_eas,
                changed_rules=changed_rules,
            ),
        )

    @property
    def is_profiling(self) -> bool:
        return self.profiling.is_running

    def start_profiling(self, _event: DecompilationSessionEvent | None = None):
        self.profiling.start()

    def stop_profiling(
        self,
        _event: DecompilationSessionEvent | None = None,
    ) -> pathlib.Path | None:
        return self.profiling.stop()

    def enable_profiling(self):
        self.profiling.enable()

    def disable_profiling(self):
        self.profiling.disable()

    def dump_profiling_segment(self, new_maturity: int) -> None:
        self.profiling.dump_segment(_maturity_name(new_maturity))

    def _ensure_post_d810_runtime(self) -> HexRaysPostD810Runtime:
        if self._post_d810_runtime is None:
            self._post_d810_runtime = HexRaysPostD810Runtime(
                preanalysis_runtime=self._preanalysis_runtime,
                block_optimizer=self.block_optimizer,
                maturity_name_provider=_maturity_name,
                handoff_detector=detect_post_d810_handoff_violations,
            )
        return self._post_d810_runtime

    def capture_post_d810_mba(
        self,
        mba: typing.Any,
        maturity: int,
        snapshot: typing.Any = None,
    ) -> None:
        self._ensure_post_d810_runtime().capture_mba(mba, maturity, snapshot)

    def capture_post_d810_facts(
        self,
        mba: typing.Any,
        maturity: int,
        snapshot: typing.Any = None,
    ) -> None:
        self._ensure_post_d810_runtime().capture_facts(mba, maturity, snapshot)

    def _resolve_post_d810_linearization_context(
        self,
        mba: typing.Any,
        target_maturity: int,
    ) -> tuple[int | None, int | None]:
        return self._ensure_post_d810_runtime().resolve_linearization_context(
            mba,
            target_maturity,
        )

    def attach_post_d810_rendered_program(
        self,
        mba: typing.Any,
        maturity: int,
        snapshot: typing.Any = None,
    ) -> None:
        self._ensure_post_d810_runtime().attach_rendered_program(
            mba,
            maturity,
            snapshot,
        )

    def probe_post_d810_glbopt_dce(
        self,
        mba: typing.Any,
        maturity: int,
        snapshot: typing.Any = None,
    ) -> None:
        self._ensure_post_d810_runtime().probe_glbopt_dce(mba, maturity, snapshot)

    def validate_post_d810_handoff(
        self,
        mba: typing.Any,
        maturity: int,
        snapshot: typing.Any = None,
    ) -> None:
        self._ensure_post_d810_runtime().validate_handoff(mba, maturity, snapshot)

    def start(self):
        if self._started:
            self.stop()
        logger.debug("Starting manager...")
        # Ensure side-effect registrants are loaded before manager construction.
        from d810.optimizers.microcode.instructions.pattern_matching import (  # noqa: F401
            experimental,
        )

        try:
            from d810.mba.backend_registry import get_egglog_provider

            if bool(get_egglog_provider("egglog").is_available()):
                from d810.optimizers.microcode.flow.egraph import (  # noqa: F401
                    block_optimizer,
                )
                from d810.optimizers.microcode.instructions.egraph import (  # noqa: F401
                    egglog_handler,
                )
        except ImportError:
            pass

        self.rule_scope_service.attach(self.event_emitter)
        self._init_storage()
        self.rule_scope_service.set_overlay_provider(self._get_rule_overlay)
        self.rule_scope_service.set_active_inference(
            self.rule_scope_runtime.active_rule_inference
        )
        self.rule_scope_service.register_inference(
            "unflattening", unflattening_inference
        )

        # Instantiate core manager classes from registry
        self.instruction_optimizer = InstructionOptimizerManager(
            self.stats, self.log_dir, optimizer_cls=InstructionOptimizer
        )
        project_name = str(self.config.get("project_name", ""))
        idb_key = str(self.config.get("idb_key", project_name))
        self._database_identity = idb_key
        self.instruction_optimizer.configure(
            **self.instruction_optimizer_config,
            rule_scope_service=self.rule_scope_service,
            rule_scope_project_name=project_name,
            rule_scope_idb_key=idb_key,
            pass_scheduler=self.instruction_pass_scheduler,
        )
        self.block_optimizer = BlockOptimizerManager(
            self.stats, self.log_dir, ctx_cls=FlowMaturityContext
        )
        self.block_optimizer.configure(
            **self.block_optimizer_config,
            rule_scope_service=self.rule_scope_service,
            rule_scope_project_name=project_name,
            rule_scope_idb_key=idb_key,
            pass_scheduler=self.block_pass_scheduler,
            function_priors_provider=self.function_analysis_priors_for_ea,
            dispatcher_artifact_planner=plan_dispatcher_state_return_carrier_artifact,
        )
        for rule in self.instruction_optimizer_rules:
            rule.log_dir = self.log_dir
            self.instruction_optimizer.add_rule(rule)

        for cfg_rule in self.block_optimizer_rules:
            cfg_rule.log_dir = self.log_dir
            self.block_optimizer.add_rule(cfg_rule)

        # Build PassPipeline when feature flag is enabled (default OFF), or when
        # the explicit loop-carrier experiment is requested. Zero overhead when
        # both are disabled - no imports of pass modules occur.
        _pass_pipeline = None
        _pass_pipeline_spec = pass_pipeline_spec_from_config(self.config)
        if _pass_pipeline_spec is not None:
            _pass_pipeline = self._build_pass_pipeline(spec=_pass_pipeline_spec)

        # Build PreanalysisPhase when feature flag is enabled (default ON).
        # Passive collection with minimal overhead; disable with
        # "enable_analysis_pipeline": false in project config.
        self._analysis_bundle = None
        self._preanalysis_runtime = None
        self._analysis_runtime = None
        if self.config.get("enable_analysis_pipeline", True):
            self._analysis_bundle = build_analysis_runtime_bundle(
                log_dir=self.log_dir,
                config=dict(self.config),
            )
            if self._analysis_bundle is not None:
                self._preanalysis_runtime = self._analysis_bundle.preanalysis_runtime
                self._analysis_runtime = self._analysis_bundle.analysis_runtime

        self.decompilation_lifecycle = DecompilationLifecycleCoordinator(
            preanalysis_runtime=self._preanalysis_runtime,
            analysis_runtime=self._analysis_runtime,
            rule_scope_service=self.rule_scope_service,
            native_preanalysis_key_provider=lambda function_ea: (
                _build_native_preanalysis_key(
                    function_ea=function_ea,
                    profile_config=self.config,
                )
            ),
            event_emitter=self.event_emitter,
            current_mba_identity_index_builder=_build_current_mba_identity_index,
            mba_mutation_gateway_factory=_new_current_mba_mutation_gateway,
            semantic_native_body_materializer_factory=(
                _new_semantic_native_body_materializer
            ),
            resolver_attachment_initializer=lambda session: (
                _initialize_resolver_attachment(
                    session,
                    semantic_route_reference_oracle_provider=(
                        self._semantic_route_reference_oracle_registry
                    ),
                )
            ),
        )

        # The lifecycle coordinator owns top-level reset, capture, analysis,
        # and rule-scope delivery.  Adapters retain only the narrow fact-view
        # runtime seam they still need for optimizer-local consumers.
        self.instruction_optimizer.configure(
            decompilation_lifecycle=self.decompilation_lifecycle,
        )
        self.block_optimizer.configure(
            decompilation_lifecycle=self.decompilation_lifecycle,
        )
        if self._preanalysis_runtime is not None:
            # LS10: register the Hex-Rays live SourceLifter (import-time side
            # effect) before the induction collector runs, so a raw mba handed
            # directly to a collector can be lifted to a portable fact target.
            # Lazy import -- backends.facts.ida pulls ida_hexrays via
            # d810.hexrays.fact_target, so a module-top import would break
            # unit-test collectability of d810.manager. Dormant for the portable
            # targets the live pipeline passes today (FlowGraph / fact target).
            try:
                # Explicit idempotent ensure() through the backend registration
                # helper: a sys.modules-cached module would make re-import a
                # no-op and leave the registry empty after a
                # reset_live_lifters_for_tests().
                ensure_hexrays_fact_lifter_registered()
            except Exception:
                logger.exception("Hex-Rays live SourceLifter registration failed")
            self._load_preanalysis_profile_modules()
            emit_preanalysis_fact_collector_registration(
                runtime=self._preanalysis_runtime,
                project_config=dict(self.config),
            )
        if self._analysis_runtime is not None:
            self.block_optimizer.configure(
                validated_fact_view_provider=(
                    self._analysis_runtime.validated_fact_view
                ),
                fact_consumer_callback=(self._analysis_runtime.record_fact_consumers),
                flow_context_summary_provider=(
                    self._analysis_runtime.load_flow_context_summary
                ),
                planner_outcome_callback=(
                    self._analysis_runtime.record_planner_outcome
                ),
                flow_gate_outcome_callback=(
                    self._analysis_runtime.record_flow_gate_outcome
                ),
            )

        # Wire PassPipeline into BlockOptimizerManager so it fires at
        # MMAT_GLBOPT2, after the unflattener has run at MMAT_GLBOPT1.
        if _pass_pipeline is not None:
            self.block_optimizer.configure(pass_pipeline=_pass_pipeline)

        # Ctree collection and analysis use the same lifecycle port as the
        # microcode adapters.
        self.ctree_optimizer = CtreeOptimizerManager(
            self.stats,
            decompilation_lifecycle=self.decompilation_lifecycle,
        )

        for ctree_rule in self.ctree_optimizer_rules:
            ctree_rule.log_dir = self.log_dir
            self.ctree_optimizer.add_rule(ctree_rule)

        self.hx_decompiler_hook = HexraysDecompilationHook(
            self.event_emitter.emit,
            ctree_optimizer_manager=self.ctree_optimizer,
            block_optimizer=self.block_optimizer,
            decompilation_lifecycle=self.decompilation_lifecycle,
            database_identity=idb_key,
        )
        self._post_d810_runtime = None
        self._compile_rule_scope()
        self._install_hooks()
        self._started = True

    def _init_storage(self) -> None:
        self.rule_scope_runtime.initialize_storage()

    def _load_active_inference_from_storage(self) -> None:
        self.rule_scope_runtime.load_active_inference_from_storage()

    def _get_rule_overlay(self, function_ea: int) -> FunctionRuleOverlay | None:
        return self.rule_scope_runtime.get_rule_overlay(function_ea)

    def get_function_rule_override(self, function_addr: int):
        return self.rule_scope_runtime.get_function_rule_override(function_addr)

    def set_function_rule_override(
        self,
        *,
        function_addr: int,
        enabled_rules: typing.Optional[typing.Set[str]] = None,
        disabled_rules: typing.Optional[typing.Set[str]] = None,
        notes: str = "",
    ) -> None:
        self.rule_scope_runtime.set_function_rule_override(
            function_addr=function_addr,
            enabled_rules=enabled_rules,
            disabled_rules=disabled_rules,
            notes=notes,
        )

    def clear_function_rule_override(self, function_addr: int) -> None:
        self.rule_scope_runtime.clear_function_rule_override(function_addr)

    def get_function_tags(self, function_addr: int) -> set[str]:
        return self.rule_scope_runtime.get_function_tags(function_addr)

    def set_function_tags(
        self,
        *,
        function_addr: int,
        tags: typing.Optional[typing.Set[str]] = None,
    ) -> None:
        self.rule_scope_runtime.set_function_tags(
            function_addr=function_addr,
            tags=tags,
        )

    def set_active_rule_inference(
        self,
        *,
        inference_name: str,
        enabled_rules: typing.Optional[typing.Set[str]] = None,
        disabled_rules: typing.Optional[typing.Set[str]] = None,
        target_func_eas: typing.Optional[typing.Set[int]] = None,
        target_tags_any: typing.Optional[typing.Set[str]] = None,
        target_tags_all: typing.Optional[typing.Set[str]] = None,
        notes: str = "",
    ) -> None:
        self.rule_scope_runtime.set_active_rule_inference(
            inference_name=inference_name,
            enabled_rules=enabled_rules,
            disabled_rules=disabled_rules,
            target_func_eas=target_func_eas,
            target_tags_any=target_tags_any,
            target_tags_all=target_tags_all,
            notes=notes,
        )

    def clear_active_rule_inference(self) -> None:
        self.rule_scope_runtime.clear_active_rule_inference()

    def get_active_rule_inference(self) -> RuleInferenceOverlay | None:
        return self.rule_scope_runtime.get_active_rule_inference()

    def _compile_rule_scope(self) -> None:
        self.rule_scope_service.compile_base_rules(
            project_name=str(self.config.get("project_name", "")),
            instruction_rules=self.instruction_optimizer_rules,
            flow_rules=self.block_optimizer_rules,
            ctree_rules=self.ctree_optimizer_rules,
        )

    def _start_timer(self):
        self.profiling.start_timer()

    def _stop_timer(self, report: bool = True):
        self.profiling.stop_timer(report=report)

    def _on_session_started(self, event: DecompilationSessionEvent) -> None:
        """Reset observer-only state after the coordinator has opened a session."""
        self.start_profiling(event)
        self.stats.reset()
        MOP_CONSTANT_CACHE.clear()
        MOP_TO_AST_CACHE.clear()
        Z3MopProver().clear_caches()
        self.instruction_optimizer.reset_cycle_detection()
        self.instruction_optimizer.reset_run_later_state()
        self.block_optimizer.reset_pass_counter()
        self.block_optimizer.reset_pipeline_tracker()
        self.block_optimizer.reset_perf_counters()
        self._start_timer()

    def _on_session_finished(self, event: DecompilationSessionEvent) -> None:
        """Report observer-only state after the coordinator has closed a session."""
        self.stop_profiling(event)
        self.stats.report()
        logger.info("MOP_CONSTANT_CACHE stats: %s", MOP_CONSTANT_CACHE.stats)
        logger.info("MOP_TO_AST_CACHE stats: %s", MOP_TO_AST_CACHE.stats)
        self.block_optimizer.report_perf_counters()
        self._stop_timer()

    @staticmethod
    def _stable_identity_anchor(identity) -> int:
        return int(
            min(
                identity.exact_instruction_eas,
                default=identity.native_ranges.intervals[0].start_ea,
            )
        )

    @staticmethod
    def _on_mutation_planned(event) -> None:
        from d810.core.maturity_labels import mmat_label
        from d810.core.observability import emit as emit_diagnostic
        from d810.core.observability_events import (
            MutationPlanItemObserved,
            MutationPlanObserved,
        )

        items = []
        for item in event.items:
            source_anchor = item.source_anchor_ea
            if source_anchor is None and item.source_identity is not None:
                source_anchor = D810Manager._stable_identity_anchor(
                    item.source_identity
                )
            target_anchor = item.target_anchor_ea
            if target_anchor is None and item.target_identity is not None:
                target_anchor = D810Manager._stable_identity_anchor(
                    item.target_identity
                )
            items.append(
                MutationPlanItemObserved(
                    item_index=int(item.item_index),
                    mutation_kind=item.mutation_kind,
                    source_serial=(
                        int(item.source_serial)
                        if item.source_serial is not None and source_anchor is not None
                        else None
                    ),
                    source_anchor_ea=source_anchor,
                    source_identity_json=(
                        None
                        if item.source_identity is None
                        else json.dumps(item.source_identity.to_dict(), sort_keys=True)
                    ),
                    target_serial=(
                        int(item.target_serial)
                        if item.target_serial is not None and target_anchor is not None
                        else None
                    ),
                    target_anchor_ea=target_anchor,
                    target_identity_json=(
                        None
                        if item.target_identity is None
                        else json.dumps(item.target_identity.to_dict(), sort_keys=True)
                    ),
                    disposition=item.disposition,
                    reason=item.reason,
                )
            )
        emit_diagnostic(
            MutationPlanObserved(
                session_id=event.session_id,
                func_ea=int(event.function_ea),
                mutation_batch_id=event.mutation_batch_id,
                mutation_kind=event.kind.value,
                planned_operation_count=int(event.planned_operation_count),
                mba_generation=int(event.mba_generation),
                evidence_generation=int(event.evidence_generation),
                maturity=mmat_label(int(event.maturity)),
                description=event.description,
                items=tuple(items),
                fragment_plan_id=event.fragment_plan_id,
                fragment_atomic_group_id=event.fragment_atomic_group_id,
                fragment_plan_json=event.fragment_plan_json,
                root_publication_groups=(
                    D810Manager._fragment_root_group_observations(
                        event.root_publication_groups
                    )
                ),
            )
        )

    @staticmethod
    def _fragment_root_group_observations(groups):
        from d810.core.observability_events import (
            FragmentRootPublicationGroupObserved,
        )

        return tuple(
            FragmentRootPublicationGroupObserved(
                group_id=group.group_id,
                predecessor_block_id=group.predecessor_block_id,
                predecessor_anchor_ea=int(group.predecessor_anchor_ea),
                edge_ids=group.edge_ids,
                edge_roles=tuple(role.value for role in group.edge_roles),
                original_block_ids=group.original_block_ids,
                replacement_block_ids=group.replacement_block_ids,
                publication_attempted=group.publication_attempted,
                publication_succeeded=group.publication_succeeded,
                rollback_attempted=group.rollback_attempted,
                rollback_succeeded=group.rollback_succeeded,
            )
            for group in groups
        )

    @staticmethod
    def _fragment_validation_observations(*results):
        from d810.core.observability_events import (
            FragmentValidationOutcomeObserved,
        )

        observations = []
        for phase, result in results:
            if result is None:
                continue
            observations.extend(
                FragmentValidationOutcomeObserved(
                    phase=phase,
                    postcondition=outcome.postcondition.value,
                    subject_id=outcome.subject_id,
                    passed=outcome.passed,
                    reason=outcome.reason,
                    block_ids=outcome.block_ids,
                )
                for outcome in result.outcomes
            )
        return tuple(observations)

    @staticmethod
    def _fragment_failure_observations(failures):
        from d810.core.observability_events import (
            SemanticFragmentFailureObserved,
        )

        return tuple(
            SemanticFragmentFailureObserved(
                failure_kind=failure.failure_kind,
                phase=failure.phase,
                error_type=failure.error_type,
                error_message=failure.error_message,
                interr_code=failure.interr_code,
                verification_context=failure.verification_context,
            )
            for failure in failures
        )

    @staticmethod
    def _committed_version_transition_observations(transitions):
        observations = []
        for transition in transitions:
            retired = transition.retired_version
            if retired is not None:
                observations.append(
                    D810Manager._logical_version_transition_observation(
                        retired,
                        from_state="published",
                        to_state="retired",
                    )
                )
            promoted = transition.promoted_version
            if promoted is not None:
                observations.append(
                    D810Manager._logical_version_transition_observation(
                        promoted,
                        from_state="staged",
                        to_state="published",
                    )
                )
        return tuple(observations)

    @staticmethod
    def _aborted_version_transition_observations(versions):
        return tuple(
            D810Manager._logical_version_transition_observation(
                version,
                from_state="staged",
                to_state="aborted",
            )
            for version in versions
        )

    @staticmethod
    def _logical_version_transition_observation(
        version,
        *,
        from_state: str,
        to_state: str,
    ):
        from d810.core.observability_events import (
            LogicalBlockVersionTransitionObserved,
        )

        identity = version.handle.stable_identity
        predecessor = version.predecessor_version_id
        return LogicalBlockVersionTransitionObserved(
            proxy_token=version.version_id.proxy_token,
            version=version.version_id.version,
            physical_handle_token=version.handle.token,
            generation=version.generation,
            provenance=version.handle.provenance.value,
            stable_identity_json=(
                None
                if identity is None
                else json.dumps(identity.to_dict(), sort_keys=True)
            ),
            anchor_ea=(
                None
                if identity is None
                else D810Manager._stable_identity_anchor(identity)
            ),
            predecessor_version=(None if predecessor is None else predecessor.version),
            from_state=from_state,
            to_state=to_state,
        )

    @staticmethod
    def _on_semantic_fragment_route_oracle_compared(event) -> None:
        from d810.core.maturity_labels import mmat_label
        from d810.core.observability import emit as emit_diagnostic
        from d810.core.observability_events import (
            SemanticFragmentRouteOracleComparedObserved,
        )

        emit_diagnostic(
            SemanticFragmentRouteOracleComparedObserved(
                session_id=event.session_id,
                func_ea=int(event.function_ea),
                mutation_batch_id=event.mutation_batch_id,
                run_id=event.run_id,
                plan_id=event.plan_id,
                atomic_group_id=event.atomic_group_id,
                mba_generation=int(event.mba_generation),
                evidence_generation=int(event.evidence_generation),
                maturity=mmat_label(int(event.maturity)),
                reference_ledger_identities=event.reference_ledger_identities,
                comparisons=event.result.comparisons,
            )
        )

    @staticmethod
    def _on_mutation_committed(event) -> None:
        from d810.core.maturity_labels import mmat_label
        from d810.core.observability import emit as emit_diagnostic
        from d810.core.observability_events import MutationReceiptObserved

        receipt = event.receipt
        identities = tuple(receipt.affected_identities)
        emit_diagnostic(
            MutationReceiptObserved(
                session_id=event.session_id,
                func_ea=int(event.function_ea),
                mutation_batch_id=receipt.mutation_batch_id,
                mutation_kind=receipt.kind.value,
                pre_generation=int(receipt.pre_generation),
                post_generation=int(receipt.post_generation),
                planned_operation_count=int(receipt.planned_operation_count),
                applied_operation_count=int(receipt.operation_count),
                evidence_generation=int(event.evidence_generation),
                maturity=mmat_label(int(event.maturity)),
                outcome="committed",
                description=receipt.description,
                reason="",
                affected_identity_json=tuple(
                    json.dumps(identity.to_dict(), sort_keys=True)
                    for identity in identities
                ),
                affected_anchor_eas=tuple(
                    D810Manager._stable_identity_anchor(identity)
                    for identity in identities
                ),
                fragment_plan_id=receipt.fragment_plan_id,
                fragment_atomic_group_id=receipt.fragment_atomic_group_id,
                root_publication_groups=(
                    D810Manager._fragment_root_group_observations(
                        receipt.root_publication_groups
                    )
                ),
                fragment_staged=bool(receipt.fragment_plan_id),
                root_publication_attempted=receipt.root_publication_confirmed,
                root_publication_succeeded=receipt.root_publication_confirmed,
                rollback_attempted=False,
                rollback_succeeded=None,
                validation_outcomes=(
                    D810Manager._fragment_validation_observations(
                        (
                            "prepublication",
                            receipt.prepublication_validation,
                        ),
                        (
                            "postpublication",
                            receipt.postpublication_validation,
                        ),
                    )
                ),
                version_transitions=(
                    D810Manager._committed_version_transition_observations(
                        receipt.version_transitions
                    )
                ),
            )
        )

    @staticmethod
    def _on_mutation_aborted(event) -> None:
        from d810.core.maturity_labels import mmat_label
        from d810.core.observability import emit as emit_diagnostic
        from d810.core.observability_events import MutationReceiptObserved

        emit_diagnostic(
            MutationReceiptObserved(
                session_id=event.session_id,
                func_ea=int(event.function_ea),
                mutation_batch_id=event.mutation_batch_id,
                mutation_kind=event.kind.value,
                pre_generation=int(event.mba_generation),
                post_generation=int(event.mba_generation),
                planned_operation_count=int(event.planned_operation_count),
                applied_operation_count=int(event.applied_operation_count),
                evidence_generation=int(event.evidence_generation),
                maturity=mmat_label(int(event.maturity)),
                outcome="aborted",
                description=event.description,
                reason=event.reason,
                fragment_plan_id=event.fragment_plan_id,
                fragment_atomic_group_id=event.fragment_atomic_group_id,
                root_publication_groups=(
                    D810Manager._fragment_root_group_observations(
                        event.root_publication_groups
                    )
                ),
                fragment_staged=event.fragment_staged,
                root_publication_attempted=event.root_publication_attempted,
                root_publication_succeeded=event.root_publication_succeeded,
                rollback_attempted=event.rollback_attempted,
                rollback_succeeded=event.rollback_succeeded,
                validation_outcomes=(
                    D810Manager._fragment_validation_observations(
                        (
                            "prepublication",
                            event.prepublication_validation,
                        ),
                        (
                            "postpublication",
                            event.postpublication_validation,
                        ),
                    )
                ),
                fragment_failures=(
                    D810Manager._fragment_failure_observations(event.fragment_failures)
                ),
                version_transitions=(
                    D810Manager._aborted_version_transition_observations(
                        event.discarded_versions
                    )
                ),
            )
        )

    def _capture_flowgraph_ready(
        self,
        *,
        flow_graph: typing.Any,
        func_ea: int,
        maturity: int,
        maturity_name: str,
        producer: str | None = None,
        producer_stage_id: int | None = None,
        producer_stage_name: str | None = None,
        snapshot_stage: typing.Any = None,
        snapshot: typing.Any = None,
    ) -> None:
        """Adapt the Hex-Rays event payload to the permanent coordinator port."""
        del producer, producer_stage_id, producer_stage_name, snapshot_stage
        provider_phase = ProviderPhaseSnapshot(
            provider_name=HEXRAYS_MICROCODE_PROVIDER,
            provider_level=int(maturity),
            friendly_provider_level=str(maturity_name),
            ir_maturity=getattr(flow_graph, "metadata", {}).get("ir_maturity"),
        )
        self.decompilation_lifecycle.capture_flowgraph(
            FlowgraphReadyPayload(
                flow_graph=flow_graph,
                func_ea=int(func_ea),
                provider_phase=provider_phase,
                snapshot=snapshot,
            )
        )

    @staticmethod
    def _on_cfg_transaction_authority(event) -> None:
        """Translate typed Hex-Rays authority into core diagnostic records."""
        from d810.core.observability import emit as emit_diagnostic
        from d810.core.observability_events import (
            CfgCreationWitnessObserved,
            CfgTransactionAttemptObserved,
        )

        reservations = {item.plan_ref: item for item in event.reservations}
        receipts = {item.plan_ref: item for item in event.creation_receipts}
        invalidated = set(event.invalidated_refs)
        quantities_by_ref = {
            plan_ref: (before, after)
            for plan_ref, before, after in event.creation_quantities
        }
        witnesses = []
        for plan_ref in event.plan_refs:
            reservation = reservations.get(plan_ref)
            receipt = receipts.get(plan_ref)
            logical_version = (
                receipt.logical_version
                if receipt is not None
                else (None if reservation is None else reservation.logical_version)
            )
            quantities = quantities_by_ref.get(plan_ref)
            state = "planned"
            if reservation is not None:
                state = "reserved"
            if receipt is not None:
                state = "committed" if event.phase.value == "committed" else "bound"
            if plan_ref in invalidated:
                state = "invalidated"
            witnesses.append(
                CfgCreationWitnessObserved(
                    local_block_id=plan_ref.local_block_id,
                    provenance=(
                        None
                        if logical_version is None
                        else logical_version.handle.provenance.value
                    ),
                    reserved_handle_token=(
                        None
                        if logical_version is None
                        else logical_version.handle.token
                    ),
                    logical_proxy_token=(
                        None
                        if logical_version is None
                        else logical_version.version_id.proxy_token
                    ),
                    logical_version=(
                        None
                        if logical_version is None
                        else int(logical_version.version_id.version)
                    ),
                    logical_generation=(
                        None
                        if logical_version is None
                        else int(logical_version.generation)
                    ),
                    insertion_quantity_before=(
                        None if quantities is None else int(quantities[0])
                    ),
                    insertion_quantity_after=(
                        None if quantities is None else int(quantities[1])
                    ),
                    requested_insertion_serial=(
                        None if receipt is None else int(receipt.insertion_serial)
                    ),
                    returned_serial=(
                        None if receipt is None else int(receipt.returned_serial)
                    ),
                    invalidated=plan_ref in invalidated,
                    state=state,
                )
            )
        failure = event.failure
        emit_diagnostic(
            CfgTransactionAttemptObserved(
                session_id=event.session_id,
                func_ea=int(event.function_ea),
                plan_id=event.attempt_id.plan_id,
                attempt_id=event.attempt_id.attempt_id,
                phase=event.phase.value,
                phase_index=int(event.phase_index),
                mba_generation=int(event.mba_generation),
                evidence_generation=int(event.evidence_generation),
                mutation_started=bool(event.mutation_started),
                poisoned=bool(event.poisoned),
                first_failure_obligation=(
                    None if failure is None else failure.first_failed_obligation
                ),
                first_failure_phase=(
                    None if failure is None else failure.failure_phase
                ),
                first_failure_reason=(None if failure is None else failure.reason),
                interr_code=None if failure is None else failure.interr_code,
                creation_witnesses=tuple(witnesses),
            )
        )

    def _install_hooks(self):
        from d810.hexrays.mutation.mba_mutation_events import (
            MbaCfgTransactionAuthorityObserved,
            MbaMutationAborted,
            MbaMutationCommitted,
            MbaMutationPlanned,
            MbaSemanticFragmentRouteOracleCompared,
        )

        self.event_emitter.on(MbaMutationPlanned, self._on_mutation_planned)
        self.event_emitter.on(MbaMutationCommitted, self._on_mutation_committed)
        self.event_emitter.on(MbaMutationAborted, self._on_mutation_aborted)
        self.event_emitter.on(
            MbaCfgTransactionAuthorityObserved,
            self._on_cfg_transaction_authority,
        )
        self.event_emitter.on(
            MbaSemanticFragmentRouteOracleCompared,
            self._on_semantic_fragment_route_oracle_compared,
        )
        self.event_emitter.on(
            DecompilationEvent.SESSION_STARTED,
            self._on_session_started,
        )
        self.event_emitter.on(
            DecompilationEvent.SESSION_FINISHED,
            self._on_session_finished,
        )

        # The coordinator is the sole collection/capture route.  Both
        # maturity gates still emit the same portable payload, preserving the
        # existing lifter and snapshot timing while the phase deduplicates.
        self.event_emitter.on(
            DecompilationEvent.FLOWGRAPH_READY,
            self._capture_flowgraph_ready,
        )

        from d810.hexrays.preanalysis.flowchart_preanalysis import (
            run_flowchart_preanalysis_handlers,
        )

        self.event_emitter.on(
            DecompilationEvent.HEXRAYS_FLOWCHART_READY,
            run_flowchart_preanalysis_handlers,
        )

        from d810.hexrays.preanalysis.preopt_preanalysis import (
            run_preopt_preanalysis_handlers,
        )
        from d810.manager.hexrays_frontend_normalization import (
            install_live_frontend_normalization,
        )

        install_live_frontend_normalization()
        self.event_emitter.on(
            DecompilationEvent.HEXRAYS_PREOPT_READY,
            run_preopt_preanalysis_handlers,
        )

        from d810.hexrays.preanalysis.locopt_preanalysis import (
            run_locopt_preanalysis_handlers,
        )

        self.event_emitter.on(
            DecompilationEvent.HEXRAYS_LOCOPT_READY,
            run_locopt_preanalysis_handlers,
        )

        from d810.hexrays.preanalysis.callinfo_preanalysis import (
            run_callinfo_preanalysis_handlers,
        )

        self.event_emitter.on(
            DecompilationEvent.HEXRAYS_BUILD_CALLINFO,
            run_callinfo_preanalysis_handlers,
        )

        from d810.hexrays.preanalysis.stkpnts_preanalysis import (
            run_stkpnts_preanalysis_handlers,
        )

        self.event_emitter.on(
            DecompilationEvent.HEXRAYS_STKPNTS,
            run_stkpnts_preanalysis_handlers,
        )

        from d810.hexrays.preanalysis.calls_done_preanalysis import (
            run_calls_done_preanalysis_handlers,
        )

        self.event_emitter.on(
            DecompilationEvent.HEXRAYS_CALLS_DONE,
            run_calls_done_preanalysis_handlers,
        )

        self.event_emitter.on(
            DecompilationEvent.MATURITY_CHANGED, self.dump_profiling_segment
        )
        self.event_emitter.on(
            DecompilationEvent.POST_D810_CAPTURE,
            self._ensure_post_d810_runtime().capture_mba,
        )
        self.event_emitter.on(
            DecompilationEvent.POST_D810_CAPTURE,
            self._ensure_post_d810_runtime().attach_rendered_program,
        )
        self.event_emitter.on(
            DecompilationEvent.POST_D810_CAPTURE,
            self._ensure_post_d810_runtime().validate_handoff,
        )
        self.event_emitter.on(
            DecompilationEvent.POST_D810_CAPTURE,
            self._ensure_post_d810_runtime().probe_glbopt_dce,
        )

        self.instruction_optimizer.event_emitter = self.event_emitter
        self.block_optimizer.event_emitter = self.event_emitter
        self.instruction_optimizer.install()
        self.block_optimizer.install()
        self.hx_decompiler_hook.hook()

    def _build_pass_pipeline(
        self,
        *,
        spec: PassPipelineSpec | None = None,
        include_default_cleanup: bool = True,
        enable_loop_carrier_backedge_refresh: bool = False,
    ):
        """Compatibility delegate for constructing the Hex-Rays pass pipeline."""
        if spec is None:
            spec = build_pass_pipeline_spec(
                include_default_cleanup=include_default_cleanup,
                enable_loop_carrier_backedge_refresh=enable_loop_carrier_backedge_refresh,
            )

        def _fact_view_provider(func_ea: int, maturity: int | str):
            if self._analysis_runtime is None:
                return None
            if isinstance(maturity, int):
                maturity = _maturity_name(maturity)
            return self._analysis_runtime.validated_fact_view(func_ea, maturity)

        pipeline = build_hexrays_flowgraph_pipeline(
            spec,
            fact_view_provider=_fact_view_provider,
        )
        logger.info(
            "PassPipeline enabled: %s",
            repr(pipeline),
        )
        return pipeline

    def configure_instruction_optimizer(self, rules, **kwargs):
        self.instruction_optimizer_rules = list(rules)
        self.instruction_optimizer_config = kwargs

    def configure_block_optimizer(self, rules, **kwargs):
        self.block_optimizer_rules = list(rules)
        self.block_optimizer_config = kwargs

    def configure_ctree_optimizer(self, rules, **kwargs):
        self.ctree_optimizer_rules = list(rules)
        self.ctree_optimizer_config = kwargs

    def stop(self):
        if not self._started:
            return
        self._started = False
        from d810.manager.hexrays_frontend_normalization import (
            uninstall_live_frontend_normalization,
        )

        uninstall_live_frontend_normalization()
        self.instruction_optimizer.remove()
        self.block_optimizer.remove()
        self.hx_decompiler_hook.unhook()
        shutdown_all_writers()
        self.event_emitter.clear()
        self.stop_profiling()
        self.rule_scope_runtime.close()
        if self._analysis_bundle is not None:
            self._analysis_bundle.close()
            self._analysis_bundle = None
        self._preanalysis_runtime = None
        self._analysis_runtime = None


@contextlib.contextmanager
def d810_hooks_suppressed(manager: D810Manager):
    """Temporarily suppress d810ng optimization hooks for clean decompilation.

    Used to get pre-deobfuscation microcode snapshots by decompiling
    with d810ng hooks temporarily removed.

    Args:
        manager: The D810Manager instance whose hooks should be temporarily removed.

    Yields:
        None

    Example:
        >>> with d810_hooks_suppressed(state.manager):
        ...     # Decompile with hooks disabled to get pre-deobfuscation state
        ...     mba = gen_microcode(func_ea, maturity)
    """
    if not manager.started:
        # If manager not started, hooks aren't installed anyway
        yield
        return

    # Remove optimizer hooks
    manager.instruction_optimizer.remove()
    manager.block_optimizer.remove()
    try:
        yield
    finally:
        # Restore optimizer hooks
        manager.instruction_optimizer.install()
        manager.block_optimizer.install()


from d810.manager.state import D810State as D810State  # noqa: E402
