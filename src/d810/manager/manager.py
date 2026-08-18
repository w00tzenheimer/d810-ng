from __future__ import annotations

import contextlib
import copy
import dataclasses
import importlib
import json
import pathlib

from d810.core import (
    MOP_CONSTANT_CACHE,
    MOP_TO_AST_CACHE,
    typing,
)
from d810.core.deobfuscation_case import DeobfuscationCaseEvidence
from d810.core.decompilation_session import (
    DecompilationEvent,
    DecompilationSessionEvent,
)
from d810.core.logging import getLogger
from d810.core import native_perf
from d810.core.observability import get_active_diag_path
from d810.core.provider_phase import ProviderPhaseSnapshot
from d810.core.project import (
    emit_preanalysis_fact_collector_registration,
    restore_project_activation_registries,
    snapshot_project_activation_registries,
)
from d810.core.registry import EventEmitter
from d810.core.execution_scope import (
    ExecutionScopeEvent,
    ExecutionScopeInvalidation,
    ExecutionScopeService,
    ExpandedExecutionStage,
    FunctionExecutionMetadata,
)
from d810.core.stats import OptimizationStatistics
from d810.core.settings import get_settings
from d810.backends.ast.z3 import Z3MopProver
from d810.backends.hexrays.registration import (
    ensure_hexrays_fact_lifter_registered,
)
from d810.diagnostics.post_d810_handoff import detect_post_d810_handoff_violations
from d810.diagnostics.deobfuscation_case_repository import (
    DeobfuscationCaseRepository,
    SqliteCaseDiagnosticReader,
)
from d810.diagnostics.workbench_cleanup import DiagnosticCleanupService
from d810.diagnostics.workbench_inventory import DiagnosticInventoryService
from d810.diagnostics.workbench_models import (
    DiagnosticCleanupPlan,
    DiagnosticCleanupResult,
    DiagnosticDatabaseSummary,
    DiagnosticRecord,
    DiagnosticSnapshotSummary,
    DiagnosticViewKind,
)
from d810.evaluator.hexrays_microcode.dispatcher_artifacts import (
    plan_dispatcher_state_return_carrier_artifact,
)
from d810.evaluator.hexrays_microcode.sccp import (
    reset_sccp_session,
    sccp_session_stats,
)
from d810.hexrays.hooks.ctree_hooks import CtreeOptimizerManager
from d810.hexrays.hooks.hexrays_hooks import HexraysDecompilationHook
from d810.hexrays.hooks.optblock_adapter import BlockOptimizerManager
from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager
from d810.hexrays.ir_maturity import HexRaysMaturity, maturity_to_name
from d810.hexrays.utils.hexrays_formatters import string_to_maturity
from d810.hexrays.lifecycle import HEXRAYS_MICROCODE_PROVIDER
from d810.optimizers import load_optimizer_registries
from d810.optimizers.microcode.flow.context import FlowMaturityContext
from d810.optimizers.microcode.instructions.handler import (
    InstructionOptimizer,
)
from d810.optimizers.microcode.handler import (
    MaturityContractError,
    validate_rule_maturity_contract,
)
from d810.passes.function_prior_config import (
    function_prior_keys,
    load_function_analysis_priors_from_config,
)
from d810.passes.function_priors import FunctionAnalysisPriors
from d810.passes.inferences import unflattening_inference
from d810.passes.execution_stages import ExecutionPipeline
from d810.passes.constant_simplification import (
    CONSTANT_SIMPLIFICATION_PASS_ID,
    constant_simplification_provider_maturities,
)
from d810.passes.constant_simplification_options import (
    CompiledConstantSimplificationSchedule,
    ConstantPreparationOptions,
)
from d810.passes.pass_pipeline import PipelineConfigError
from d810.passes.pipeline_config_parser import pipeline_configs_from_project_config
from d810.passes.config_v2_hook_runtime import STATE_MACHINE_RUNTIME_HOST
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.passes.pass_pipeline_factory import (
    PassPipelineSpec,
    build_pass_pipeline_spec,
    pass_pipeline_spec_from_config,
)
from d810.passes.analysis_runtime_factory import (
    build_analysis_runtime_bundle,
)
from d810.passes.scheduler import PassScheduler
from d810.passes.state_machine_options import StateMachineCffOptions
from d810.passes.store import shutdown_all_writers
from d810.manager.decompilation_lifecycle import (
    AttestedExternalOracleGate,
    DecompilationLifecycleCoordinator,
    FlowgraphReadyPayload,
)
from d810.manager.config_v2_edit_models import (
    ConfigV2FieldSerializer,
    ConfigV2ProjectDraft,
    ConfigV2ProjectValidation,
)
from d810.manager.config_v2_editing import ConfigV2EditingService
from d810.manager.deobfuscation_case_service import DeobfuscationCaseService
from d810.manager.function_recipe_runtime import (
    FunctionRecipePersistenceError,
    FunctionRecipeRuntime,
)
from d810.manager.function_outcome import (
    build_function_outcome,
    render_function_outcome,
)
from d810.manager.function_recipe_activation import (
    select_workbench_recipe_projection,
)
from d810.core.function_storage_config import FunctionRecipeStorageConfig
from d810.manager.hexrays_pass_pipeline import build_hexrays_flowgraph_pipeline
from d810.manager.post_d810_runtime import HexRaysPostD810Runtime
from d810.manager.profiling import ProfilingController
from d810.manager.project_runtime import ProjectRuntimeSnapshot
from d810.manager.function_storage_runtime import FunctionStorageRuntime
from d810.manager.workbench_comparison import (
    ComparisonIdentity,
    WorkbenchComparisonService,
)
from d810.manager.workbench_models import (
    BaselineRef,
    D810OutputRef,
    DeobfuscationCaseSnapshot,
    DeobfuscationWorkbenchSnapshot,
    FunctionRef,
    ProjectConfigRef,
    WorkbenchComparisonSnapshot,
)
from d810.manager.workbench_service import WorkbenchService
from d810.manager.workbench_recipe_models import (
    FunctionPipelineOverride,
    PassCatalogEntry,
    PipelineRecipeDraft,
    RecipeValidation,
    RecipeCommandRequest,
    RecipeCommandResult,
)
from d810.manager.workbench_recipe_commands import WorkbenchRecipeCommandService
from d810.manager.workbench_recipe_analysis import collect_recipe_preflight_facts
from d810.manager.workbench_recipe_service import RecipeService

D810_LOG_DIR_NAME = "d810_logs"

_MAX_EVIDENCE_REBIND_RETRIES = 4
_MAX_POISON_RECOVERY_RETRIES = 1

logger = getLogger("d810")


def _cache_session_summary(cache) -> dict[str, int | float | None]:
    stats = cache.stats
    return {
        "seq": int(stats.seq),
        "size": int(stats.size),
        "weight": float(stats.weight),
        "hits": int(stats.hits),
        "misses": int(stats.misses),
        "max_size_ever": int(stats.max_size_ever),
        "max_weight_ever": float(stats.max_weight_ever),
        "lookups": int(stats.lookups),
        "insertions": int(stats.insertions),
        "replacements": int(stats.replacements),
        "capacity_evictions": int(stats.capacity_evictions),
        "expirations": int(stats.expirations),
        "explicit_removals": int(stats.explicit_removals),
        "weak_reference_removals": int(stats.weak_reference_removals),
        "configured_max_size": stats.configured_max_size,
        "configured_max_weight": stats.configured_max_weight,
    }


def _session_telemetry_summary() -> dict[str, object]:
    """Capture one detached summary before the next session can reset state."""

    summary: dict[str, object] = {}
    try:
        summary["sccp"] = dict(sccp_session_stats().as_dict())
    except Exception:
        summary["sccp"] = {"error": "unavailable"}
    try:
        summary["mop_constant_cache"] = _cache_session_summary(MOP_CONSTANT_CACHE)
    except Exception:
        summary["mop_constant_cache"] = {"error": "unavailable"}
    try:
        summary["mop_to_ast_cache"] = _cache_session_summary(MOP_TO_AST_CACHE)
    except Exception:
        summary["mop_to_ast_cache"] = {"error": "unavailable"}
    return summary


@dataclasses.dataclass(frozen=True, slots=True)
class _ActivationContainerSnapshot:
    """Identity plus contents for a live mutable activation container."""

    target: object
    contents: object


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
    """Hex-Rays backend port for lifecycle-owned identity provenance."""
    from d810.backends.hexrays.native_preanalysis_key import (
        resolve_native_preanalysis_identity,
    )

    return resolve_native_preanalysis_identity(
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
    resolution = session.input_identity_resolution
    state.semantic_route_reference_oracle_provider = (
        semantic_route_reference_oracle_provider
        if resolution is None or resolution.external_evidence_allowed
        else AttestedExternalOracleGate(
            delegate=semantic_route_reference_oracle_provider,
            identity_resolution=resolution,
        )
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
        reference_scope = (
            None
            if reference_oracle is None
            else reference_oracle.reference_oracle_scope_for(
                int(session.function_ea),
                session.native_key,
            )
        )
        frontend_evidence = (
            session.native_preanalysis.frontend_normalization_evidence_for(
                session.native_key
            )
        )
        if reference_scope is None and frontend_evidence is None:
            return None
        if maturity_stage is not HexRaysMaturity.MMAT_GENERATED:
            build_graph = getattr(mba, "build_graph", None)
            if not callable(build_graph):
                raise TypeError("current MBA identity index requires a live graph")
            build_graph()

    current_mba_identity_binding = state.current_mba_identity_binding_for(
        stable_mba_identity(mba)
    )
    from d810.core.observability import emit as emit_diagnostic
    from d810.core.observability_events import IdentityDecisionObserved

    maturity = f"maturity={maturity_to_name(int(getattr(mba, 'maturity', 0) or 0))}"

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


#: Maturities that have a native-body materializer.  Every other RECOGNIZED
#: maturity (``MMAT_LOCOPT``, ``MMAT_GLBOPT2``, ``MMAT_GLBOPT3``, ...) simply has
#: no capability to build -- that is a routine "not available at this stage",
#: not an error, and callers already fail closed on ``None``.
_SEMANTIC_NATIVE_BODY_MATURITIES: frozenset[HexRaysMaturity] = frozenset(
    {
        HexRaysMaturity.MMAT_GENERATED,
        HexRaysMaturity.MMAT_PREOPTIMIZED,
        HexRaysMaturity.MMAT_GLBOPT1,
        HexRaysMaturity.MMAT_CALLS,
    }
)


def _new_semantic_native_body_materializer(*, session, mba):
    """Construct the sole Hex-Rays native-body materialization capability.

    Returns ``None`` when the live maturity simply has no materializer.  A
    ``ValueError`` is reserved for a maturity id Hex-Rays does not define, which
    is a programming error rather than a pipeline stage without a capability.
    """
    from d810.hexrays.mutation.detached_handler_island import (
        CallsSemanticNativeBodyMaterializer,
        PreoptUnionSemanticNativeBodyMaterializer,
    )

    maturity = int(mba.maturity)
    native_maturity = HexRaysMaturity.from_id(maturity)
    if native_maturity is None:
        raise ValueError(
            f"unrecognized semantic native-body materializer maturity: {maturity}"
        )
    if native_maturity not in _SEMANTIC_NATIVE_BODY_MATURITIES:
        # Routine: MMAT_GLBOPT2 is reached on EVERY decompile.  Raising here made
        # the sole consumer (DecompilationLifecycleCoordinator
        # .new_semantic_native_body_materializer) swallow a ValueError and log a
        # full traceback at DEBUG on every run -- exception-as-control-flow for an
        # expected condition, and a standing red herring in any debug-logged dump.
        logger.debug(
            "no semantic native-body materializer at maturity %s; failing closed",
            native_maturity.name,
        )
        return None
    if native_maturity in {
        HexRaysMaturity.MMAT_GENERATED,
        HexRaysMaturity.MMAT_PREOPTIMIZED,
        HexRaysMaturity.MMAT_GLBOPT1,
    }:
        evidence_generation = int(session.native_preanalysis.evidence_generation)

        prepared_fact_observer = None
        if native_maturity is not HexRaysMaturity.MMAT_GLBOPT1:

            def observe_prepared_body_fact(plan, native_body, fact) -> None:
                session.frontend_normalization_plan_authority.record_prepared_body_fact(
                    plan,
                    native_body,
                    fact,
                    evidence_generation=evidence_generation,
                )

            prepared_fact_observer = observe_prepared_body_fact

        from d810.hexrays.mutation.detached_handler_island import (
            stable_mba_identity,
        )
        from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
            resolver_session_state,
        )

        resolver_state = resolver_session_state(session)
        return PreoptUnionSemanticNativeBodyMaterializer(
            mba=mba,
            function_ea=int(session.function_ea),
            prepared_fact_observer=prepared_fact_observer,
            current_identity_index=session.current_mba_identity_index,
            current_mba_identity_binding=(
                resolver_state.current_mba_identity_binding_for(
                    stable_mba_identity(mba)
                )
            ),
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
    # Unreachable: _SEMANTIC_NATIVE_BODY_MATURITIES is exactly the set handled
    # above, so anything else already returned None. Kept as a wiring assertion
    # so adding a maturity to that set without a branch fails loudly.
    raise ValueError(
        "semantic native-body materializer maturity has no branch: "
        f"{native_maturity.name}"
    )


def _active_diagnostic_paths() -> tuple[str, ...]:
    path = get_active_diag_path()
    return (path,) if path is not None else ()


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


class OptimizerRuntimeStateRestoreError(RuntimeError):
    """Raised when a started optimizer cannot be restored after activation."""


class OptimizerRuntimeStateCaptureError(RuntimeError):
    """Raised when a live adapter does not expose the snapshot protocol."""


class ManagerCleanupError(RuntimeError):
    """One labelled failure from the full manager cleanup path."""

    def __init__(self, label: str, error: BaseException):
        self.label = label
        self.original_error = error
        super().__init__(
            f"{label}: {type(error).__name__}: {error}"
        )


@dataclasses.dataclass
class D810Manager:
    log_dir: pathlib.Path
    diagnostic_active_paths_provider: typing.Callable[[], typing.Any] = (
        dataclasses.field(default=_active_diagnostic_paths, repr=False)
    )
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
    execution_scope_service: ExecutionScopeService = dataclasses.field(
        default_factory=ExecutionScopeService
    )
    block_pass_scheduler: PassScheduler = dataclasses.field(
        default_factory=PassScheduler
    )
    instruction_pass_scheduler: PassScheduler = dataclasses.field(
        default_factory=PassScheduler
    )
    profiling: ProfilingController = dataclasses.field(init=False)
    function_storage_runtime: FunctionStorageRuntime = dataclasses.field(init=False)
    comparison_service: WorkbenchComparisonService = dataclasses.field(init=False)
    recipe_service: RecipeService = dataclasses.field(init=False)
    function_recipe_runtime: FunctionRecipeRuntime = dataclasses.field(init=False)
    recipe_command_service: WorkbenchRecipeCommandService = dataclasses.field(
        init=False
    )
    workbench_service: WorkbenchService = dataclasses.field(init=False)
    diagnostic_inventory_service: DiagnosticInventoryService = dataclasses.field(
        init=False
    )
    diagnostic_cleanup_service: DiagnosticCleanupService = dataclasses.field(init=False)
    config_v2_editing_service: ConfigV2EditingService = dataclasses.field(init=False)
    instruction_optimizer: InstructionOptimizerManager = dataclasses.field(init=False)
    block_optimizer: BlockOptimizerManager = dataclasses.field(init=False)
    ctree_optimizer: CtreeOptimizerManager = dataclasses.field(init=False)
    hx_decompiler_hook: HexraysDecompilationHook = dataclasses.field(init=False)
    _started: bool = dataclasses.field(default=False, init=False)
    _runtime_invalidated: bool = dataclasses.field(default=False, init=False)
    _telemetry_lifecycle_stack: list[tuple[str, object, str, int, int]] = (
        dataclasses.field(
            default_factory=list,
            init=False,
            repr=False,
        )
    )
    _telemetry_lifecycle_depth: dict[tuple[str, object, str, int, int], int] = (
        dataclasses.field(
            default_factory=dict,
            init=False,
            repr=False,
        )
    )
    _preanalysis_runtime: typing.Any = dataclasses.field(default=None, init=False)
    _analysis_runtime: typing.Any = dataclasses.field(default=None, init=False)
    _analysis_bundle: typing.Any = dataclasses.field(default=None, init=False)
    decompilation_lifecycle: DecompilationLifecycleCoordinator = dataclasses.field(
        default=None, init=False
    )
    _post_d810_runtime: typing.Any = dataclasses.field(default=None, init=False)
    _database_identity: str = dataclasses.field(default="", init=False)
    _recon_phase: typing.Any = dataclasses.field(default=None, init=False)
    _recon_runtime: typing.Any = dataclasses.field(default=None, init=False)
    _recon_bundle: typing.Any = dataclasses.field(default=None, init=False)
    _flowgraph_ready_subscriber: typing.Any = dataclasses.field(
        default=None, init=False
    )
    _stage_c_topology_consumer: typing.Any = dataclasses.field(default=None, init=False)
    _function_analysis_priors: dict[str, FunctionAnalysisPriors] = dataclasses.field(
        default_factory=dict, init=False
    )
    _function_storage_config: FunctionRecipeStorageConfig | None = dataclasses.field(
        default=None,
        init=False,
        repr=False,
    )
    _native_patch_execution_journal: typing.Any = dataclasses.field(
        default=None,
        init=False,
        repr=False,
    )
    _native_patch_journal: typing.Any = dataclasses.field(
        default=None,
        init=False,
        repr=False,
    )
    _native_patch_gateway: typing.Any = dataclasses.field(
        default=None,
        init=False,
        repr=False,
    )
    _preparation_scripts: tuple[typing.Any, ...] = dataclasses.field(
        default=(), init=False, repr=False
    )
    _global_const_persistence_enabled: bool = dataclasses.field(
        default=False, init=False, repr=False
    )
    _constant_simplification_schedule: CompiledConstantSimplificationSchedule | None = dataclasses.field(
        default=None, init=False, repr=False
    )
    _explicitly_suppressed_rule_names: frozenset[str] = dataclasses.field(
        default_factory=frozenset,
        init=False,
        repr=False,
    )
    _constant_preparation_options: ConstantPreparationOptions = dataclasses.field(
        default_factory=ConstantPreparationOptions,
        init=False,
        repr=False,
    )
    _idb_preparation_journal: typing.Any = dataclasses.field(
        default=None, init=False, repr=False
    )
    _idb_preparation_gateway: typing.Any = dataclasses.field(
        default=None, init=False, repr=False
    )
    pre_hex_preparation: typing.Any = dataclasses.field(
        default=None, init=False, repr=False
    )
    _dead_edge_normalizer: typing.Any = dataclasses.field(
        default=None,
        init=False,
        repr=False,
    )
    _native_preanalysis_handlers_installed: bool = dataclasses.field(
        default=False,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        self.profiling = ProfilingController(self.log_dir)
        self.function_storage_runtime = FunctionStorageRuntime(
            storage_factory=self._create_function_storage,
            event_emitter=self.event_emitter,
            project_name_provider=lambda: str(self.config.get("project_name", "")),
            database_identity_provider=lambda: (
                self._database_identity or str(self.config.get("idb_key", ""))
            ),
        )
        self.comparison_service = WorkbenchComparisonService()
        workbench_registry = operational_config_v2_pass_registry()
        self.recipe_service = RecipeService(workbench_registry)
        self.function_recipe_runtime = FunctionRecipeRuntime(
            storage_provider=lambda: self.function_storage_runtime.storage,
            event_emitter=self.event_emitter,
            project_name_provider=lambda: str(self.config.get("project_name", "")),
            database_identity_provider=lambda: (
                self._database_identity or str(self.config.get("idb_key", ""))
            ),
        )
        self.workbench_service = WorkbenchService(
            self,
            registry=workbench_registry,
            maturity_name_provider=_maturity_name,
        )
        self.recipe_command_service = WorkbenchRecipeCommandService(
            identity_is_current=self.workbench_service.recipe_request_is_current,
        )
        diagnostic_quarantine_directory = self.log_dir / "diagnostic_quarantine"
        self.diagnostic_inventory_service = DiagnosticInventoryService(
            roots=(self.log_dir,),
            excluded_roots=(diagnostic_quarantine_directory,),
            active_paths_provider=self.diagnostic_active_paths_provider,
        )
        self.diagnostic_cleanup_service = DiagnosticCleanupService(
            active_paths_provider=self.diagnostic_active_paths_provider,
            quarantine_directory=diagnostic_quarantine_directory,
        )
        self.config_v2_editing_service = ConfigV2EditingService(workbench_registry)

    @property
    def started(self):
        return self._started

    @property
    def runtime_invalidated(self) -> bool:
        """Whether a failed live activation forced this manager safe-invalid."""

        return self._runtime_invalidated

    def capture_started_optimizer_runtime_state(self) -> dict[str, object]:
        """Capture both live optimizer adapters before a project switch.

        The adapters own their explicit, allowlisted snapshots.  Keeping this
        boundary strict prevents activation rollback from inspecting arbitrary
        IDA/SWIG object attributes.
        """

        if not self.started:
            return {}
        snapshots: dict[str, object] = {}
        for name in ("instruction_optimizer", "block_optimizer"):
            adapter = getattr(self, name, None)
            if adapter is None:
                continue
            capture = getattr(adapter, "capture_runtime_state", None)
            restore = getattr(adapter, "restore_runtime_state", None)
            if not callable(capture) or not callable(restore):
                raise OptimizerRuntimeStateCaptureError(
                    f"{name} adapter does not implement the runtime snapshot protocol"
                )
            snapshots[name] = {"adapter": adapter, "state": capture()}
        return snapshots

    def restore_started_optimizer_runtime_state(
        self,
        snapshots: dict[str, object],
    ) -> None:
        """Restore both live optimizer adapters, aggregating every failure."""

        errors: list[tuple[str, BaseException]] = []
        for name, raw_snapshot in snapshots.items():
            snapshot = raw_snapshot  # type: ignore[assignment]
            adapter = snapshot["adapter"]  # type: ignore[index]
            try:
                restore = getattr(adapter, "restore_runtime_state", None)
                if not callable(restore):
                    raise TypeError(
                        f"{name} adapter lost the runtime snapshot protocol"
                    )
                restore(snapshot["state"])  # type: ignore[index]
            except BaseException as exc:
                errors.append((name, exc))
        if errors:
            details = "; ".join(
                f"{name}: {type(error).__name__}: {error}"
                for name, error in errors
            )
            raise OptimizerRuntimeStateRestoreError(
                f"optimizer runtime restoration failed: {details}"
            ) from errors[0][1]

    def invalidate_runtime_after_activation_rollback(self) -> tuple[BaseException, ...]:
        """Stop and explicitly invalidate hooks after lossless restore fails."""

        self._runtime_invalidated = True
        errors: list[BaseException] = []
        try:
            errors.extend(self.stop(full_cleanup=True))
        except BaseException as exc:
            errors.append(exc)
        return tuple(errors)

    @property
    def profiler(self):
        return self.profiling.profiler

    @property
    def cprofiler(self):
        return self.profiling.cprofiler

    def prepare_native_preanalysis(self, function_ea: int) -> int:
        """Establish resolver evidence before the first top-level decompile.

        This explicit batch/headless entry point may generate auxiliary
        microcode for detached native ranges. It creates the lifecycle session
        that the subsequent top-level decompile reuses, then resolves native
        computed-goto evidence before the first MBA is generated. Interactive
        decompilation must not call it.
        """
        if not getattr(self, "_started", False):
            return 0
        lifecycle = getattr(self, "decompilation_lifecycle", None)
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
                from d810.manager.rhad_generated_checksum import (
                    observe_rhad_generated_reference_preparation,
                    prepare_rhad_generated_reference_templates,
                    reference_batch_for_native_key,
                )

                generated_reference_batch = reference_batch_for_native_key(
                    session.native_key
                )
                prepared_generated_checksum = (
                    prepare_rhad_generated_reference_templates(
                        state,
                        generated_reference_batch,
                    )
                    if generated_reference_batch is not None
                    else False
                )
                if generated_reference_batch is not None:
                    observe_rhad_generated_reference_preparation(
                        session,
                        batch=generated_reference_batch,
                        prepared=prepared_generated_checksum,
                    )
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
                    + int(prepared_generated_checksum)
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

    def prepare_idb_for_hexrays(self, function_ea: int, mode=None):
        """Apply the exact preparation key before native analysis or Hex-Rays."""

        from d810.manager.pre_hexrays_preparation import (
            PreparationBatchReceipt,
            PreparationMode,
        )

        selected_mode = PreparationMode.AUTOMATIC if mode is None else mode
        controller = getattr(self, "pre_hex_preparation", None)
        if controller is None:
            return PreparationBatchReceipt(
                function_ea=int(function_ea),
                mode=selected_mode,
            )
        return controller.prepare(int(function_ea), selected_mode)

    def preparation_status(self):
        """Return the portable pre-Hex preparation status snapshot."""

        controller = getattr(self, "pre_hex_preparation", None)
        if controller is None:
            from d810.manager.pre_hexrays_preparation import PreparationStatusSnapshot

            return PreparationStatusSnapshot()
        return controller.status_snapshot()

    def restore_idb_preparation(self, transaction_id):
        """Restore one preparation transaction through the destructive gateway."""

        gateway = getattr(self, "_idb_preparation_gateway", None)
        if gateway is None:
            raise RuntimeError("IDB preparation gateway is unavailable")
        return gateway.restore(transaction_id)

    def decompile_with_native_preanalysis(
        self,
        function_ea: int,
        decompile: typing.Callable[[], typing.Any],
        invalidate_cached_cfunc: typing.Callable[[], None],
        *,
        eager_native_preanalysis: bool = False,
    ) -> typing.Any:
        """Run one top-level decompile plus bounded generated retries.

        CALLS can stage evidence for PREOPT but cannot restart generated
        microcode. This manager-owned controller performs the follow-up only
        after the first decompile unwinds; the retained session lets its
        flowchart callback issue the one supported ``MERR_REDO``. Exhaustive
        native preanalysis may recursively generate auxiliary microcode, so it
        is disabled for ordinary interactive calls and requires an explicit
        headless opt-in.
        """
        if (
            not getattr(self, "_started", False)
            or getattr(self, "decompilation_lifecycle", None) is None
        ):
            raise RuntimeError("D810 manager is not started")
        function_ea = int(function_ea)
        result: typing.Any = None
        final_stage_c_collection: tuple[object, object] | None = None
        stage_c_native_result = None
        evidence_rebind_retries = 0
        poison_recovery_retries = 0
        recovery_mode = False

        from d810.analyses.control_flow.native_preanalysis_session import (
            GeneratedRestartConsumer,
            GeneratedRestartKind,
            GeneratedRestartReceipt,
        )

        lifecycle = self.decompilation_lifecycle

        preparation = self.prepare_idb_for_hexrays(function_ea)
        if not preparation.ok:
            raise RuntimeError(
                preparation.failure_reason
                or f"IDB preparation failed for 0x{function_ea:X}"
            )

        def pending_restart() -> GeneratedRestartReceipt | None:
            pending = getattr(lifecycle, "pending_generated_restart", None)
            if not callable(pending):
                raise RuntimeError(
                    "native preanalysis manager requires the typed "
                    "pending_generated_restart projection"
                )
            receipt = pending(function_ea)
            if receipt is not None and not isinstance(
                receipt,
                GeneratedRestartReceipt,
            ):
                raise TypeError(
                    "native preanalysis pending restart must be a "
                    "GeneratedRestartReceipt or None"
                )
            return receipt

        # Evidence rebinding retains its existing four-follow-up budget. Poison
        # recovery is a separate, explicit one-follow-up budget: it is never
        # folded into the evidence loop and never routed through MERR_REDO.
        while True:
            if not recovery_mode:
                if eager_native_preanalysis:
                    self.prepare_native_preanalysis(function_ea)
                else:
                    # Session ownership is cheap and required by Stage C and
                    # live callback collection. Keep it independent from the
                    # auxiliary microcode generation performed by exhaustive
                    # native preanalysis.
                    ensure_session = getattr(
                        lifecycle,
                        "ensure_hexrays_session",
                        None,
                    )
                    if callable(ensure_session):
                        ensure_session(
                            function_ea=function_ea,
                            database_identity=self._database_identity,
                        )
            from d810.optimizers.microcode.flow.jumps.computed_goto_resolver import (
                acquire_detached_call_stack_capacity_witness,
            )

            session = lifecycle.current_session(function_ea)
            stage_c_collector = None
            if session is not None and self._stage_c_collection_enabled(function_ea):
                from d810.manager.native_cfg_normalization import (
                    NativeCfgNormalizationCollector,
                )

                stage_c_collector = NativeCfgNormalizationCollector(
                    function_ea=function_ea,
                    native_key=session.native_key,
                    session_id=session.session_id,
                    parent_attempt_id=session.preanalysis_attempt_id,
                )
                if session.native_cfg_collector is not None:
                    raise RuntimeError(
                        "native CFG collector already attached to decompilation session"
                    )
                session.native_cfg_collector = stage_c_collector
            capacity_witness_lease = (
                None
                if session is None or recovery_mode
                else acquire_detached_call_stack_capacity_witness(session)
            )
            # Native preanalysis may generate top-level or snippet cfuncs while
            # capturing pristine templates.  None of those cache entries owns
            # the live decompile that follows this preparation round.
            try:
                invalidate_cached_cfunc()
                result = decompile()
            except BaseException:
                if stage_c_collector is not None:
                    stage_c_collector.close()
                raise
            finally:
                if capacity_witness_lease is not None:
                    capacity_witness_lease.release()
                if (
                    stage_c_collector is not None
                    and session is not None
                    and session.native_cfg_collector is stage_c_collector
                ):
                    session.native_cfg_collector = None
            if lifecycle.has_exhausted_poison_restart(function_ea):
                if stage_c_collector is not None:
                    stage_c_collector.close()
                raise RuntimeError(
                    "native preanalysis poison restart exhausted for "
                    f"0x{function_ea:X}; refusing poisoned output"
                )
            try:
                receipt = pending_restart()
            except BaseException:
                # Receipt projection is part of the controller boundary, not
                # the decompile callback's finally block.  A malformed or
                # failing projection must not strand a detached Stage-C
                # collector after the generated MBA has already unwound.
                if stage_c_collector is not None:
                    stage_c_collector.close()
                raise
            if receipt is None:
                if stage_c_collector is not None:
                    final_stage_c_collection = (stage_c_collector, result)
                break

            if recovery_mode:
                if stage_c_collector is not None:
                    stage_c_collector.close()
                raise RuntimeError(
                    "native preanalysis recovery decompile requested another "
                    f"restart for 0x{function_ea:X}"
                )

            if receipt.kind is GeneratedRestartKind.POISON_RECOVERY:
                if poison_recovery_retries >= _MAX_POISON_RECOVERY_RETRIES:
                    if stage_c_collector is not None:
                        stage_c_collector.close()
                    raise RuntimeError(
                        "native preanalysis poison restart budget exhausted with "
                        f"a restart still pending for 0x{function_ea:X}"
                    )
                consume = getattr(lifecycle, "consume_generated_restart", None)
                if not callable(consume):
                    if stage_c_collector is not None:
                        stage_c_collector.close()
                    raise RuntimeError(
                        "native preanalysis poison restart has no manager consumer"
                    )
                consumed = consume(
                    function_ea,
                    consumer=GeneratedRestartConsumer.MANAGER,
                )
                if consumed is None:
                    if stage_c_collector is not None:
                        stage_c_collector.close()
                    raise RuntimeError(
                        "native preanalysis poison restart was not consumed by manager"
                    )
                if not isinstance(consumed, GeneratedRestartReceipt):
                    if stage_c_collector is not None:
                        stage_c_collector.close()
                    raise TypeError(
                        "native preanalysis manager consumed restart must be a "
                        "GeneratedRestartReceipt"
                    )
                if consumed.kind is not GeneratedRestartKind.POISON_RECOVERY:
                    if stage_c_collector is not None:
                        stage_c_collector.close()
                    raise RuntimeError(
                        "native preanalysis manager consumed a "
                        f"{consumed.kind.name} receipt; expected "
                        f"{GeneratedRestartKind.POISON_RECOVERY.name}"
                    )
                poison_recovery_retries += 1
                recovery_mode = True
                if stage_c_collector is not None:
                    stage_c_collector.close()
                continue

            # Evidence receipts remain flowchart-owned; the manager never
            # consumes them.
            if evidence_rebind_retries >= _MAX_EVIDENCE_REBIND_RETRIES:
                if stage_c_collector is not None:
                    stage_c_collector.close()
                raise RuntimeError(
                    "native preanalysis restart budget exhausted: "
                    "evidence-rebind budget exhausted with "
                    f"a restart still pending for 0x{function_ea:X}"
                )
            if receipt.kind is not GeneratedRestartKind.EVIDENCE_REBIND:
                if stage_c_collector is not None:
                    stage_c_collector.close()
                raise RuntimeError(
                    "native preanalysis restart has an unsupported lifecycle kind "
                    f"for 0x{function_ea:X}"
                )
            evidence_rebind_retries += 1
            if stage_c_collector is not None:
                stage_c_collector.close()
        if final_stage_c_collection is not None:
            stage_c_collector, stage_c_result = final_stage_c_collection
            try:
                stage_c_outcome = stage_c_collector.take_topology_outcome()
                stage_c_consumer = getattr(self, "_stage_c_topology_consumer", None)
                if callable(stage_c_consumer):
                    stage_c_native_result = stage_c_consumer(
                        function_ea=function_ea,
                        native_key=stage_c_collector.native_key,
                        topology_outcome=stage_c_outcome,
                        decompilation_result=stage_c_result,
                        parent_attempt_id=stage_c_collector.parent_attempt_id,
                    )
                    if (
                        stage_c_native_result is not None
                        and stage_c_native_result.normalization is not None
                        and stage_c_native_result.normalization.outcome.value
                        == "applied"
                    ):
                        if stage_c_native_result.validated_cfunc is None:
                            raise RuntimeError(
                                "applied Stage C result lacks its validated cfunc"
                            )
                        result = stage_c_native_result.validated_cfunc
            finally:
                stage_c_collector.close()

        dead_edge_normalizer = getattr(self, "_dead_edge_normalizer", None)
        if (
            callable(dead_edge_normalizer)
            and not recovery_mode
            and (stage_c_native_result is None or stage_c_native_result.allow_stage_b)
        ):
            from d810.manager.native_normalization import NativeNormalizationOutcome

            native_outcome = dead_edge_normalizer(function_ea)
            if native_outcome.outcome is NativeNormalizationOutcome.APPLIED:
                # The gateway has completed its mandatory controlled redo, but
                # the object returned by the original top-level decompile was
                # captured before the certified byte overlay. Return a fresh
                # caller-owned result rather than an invalidated cfunc.
                invalidate_cached_cfunc()
                result = decompile()
        return result

    def _stage_c_collection_enabled(self, function_ea: int) -> bool:
        """Require native policy plus an exact lower-pass config-v2 opt-in."""
        from d810.manager.native_patch_policy import (
            native_patch_function_is_authorized,
        )

        config = getattr(self, "config", None)
        if not isinstance(config, dict) or not bool(
            config.get("native_patch_enabled", False)
        ):
            return False
        if not native_patch_function_is_authorized(
            globally_available=True,
            function_tags=self.get_function_tags(int(function_ea)),
        ):
            return False
        try:
            configs = pipeline_configs_from_project_config(config)
        except Exception:
            return False
        return any(
            config.pass_id == "lower_state_machine"
            and config.options.get("native_cfg_persistence") is True
            for config in configs
        )

    @property
    def storage(self):
        return self.function_storage_runtime.storage

    @storage.setter
    def storage(self, value):
        self.function_storage_runtime.storage = value

    @property
    def analysis_db(self) -> pathlib.Path | None:
        """Path to the analysis SQLite database, or None when disabled."""
        bundle = getattr(self, "_analysis_bundle", None)
        if bundle is None:
            return None
        return bundle.db_path

    def load_recon_hints(self, function_ea: int) -> typing.Any | None:
        """Return persisted hints without triggering collection or mutation."""
        runtime = self._recon_runtime
        if runtime is not None:
            return runtime.load_hints(int(function_ea))
        analysis_runtime = self._analysis_runtime
        if analysis_runtime is not None:
            return analysis_runtime.load_hints(int(function_ea))
        return None

    def get_recon_outcome_reports(self, function_ea: int) -> tuple[typing.Any, ...]:
        """Return a detached tuple of current cross-consumer reports."""
        runtime = self._recon_runtime
        if runtime is not None:
            return tuple(runtime.outcome_log.get_func_reports(int(function_ea)))
        analysis_runtime = self._analysis_runtime
        if analysis_runtime is not None:
            return tuple(
                analysis_runtime.outcome_log.get_func_reports(int(function_ea))
            )
        return ()

    def get_diagnostic_databases(self) -> tuple[DiagnosticDatabaseSummary, ...]:
        return self.diagnostic_inventory_service.databases()

    def get_diagnostic_snapshots(
        self, path: pathlib.Path | str
    ) -> tuple[DiagnosticSnapshotSummary, ...]:
        return self.diagnostic_inventory_service.snapshots(path)

    def get_diagnostic_records(
        self,
        path: pathlib.Path | str,
        snapshot_id: int,
        kind: DiagnosticViewKind,
    ) -> tuple[DiagnosticRecord, ...]:
        return self.diagnostic_inventory_service.records(path, snapshot_id, kind)

    def get_diagnostic_case_evidence(
        self,
        path: pathlib.Path | str,
        function_ea: int,
    ) -> DeobfuscationCaseEvidence | None:
        """Read one selected diagnostic database as an immutable case session."""
        repository = DeobfuscationCaseRepository(
            SqliteCaseDiagnosticReader((pathlib.Path(path),))
        )
        return repository.load(int(function_ea), None)

    def plan_diagnostic_selected_snapshots(
        self, path: pathlib.Path | str, snapshot_ids: typing.Sequence[int]
    ) -> DiagnosticCleanupPlan:
        return self.diagnostic_cleanup_service.plan_selected_snapshots(
            path, snapshot_ids
        )

    def plan_diagnostic_all_snapshots(
        self, path: pathlib.Path | str
    ) -> DiagnosticCleanupPlan:
        return self.diagnostic_cleanup_service.plan_all_snapshots(path)

    def plan_diagnostic_keep_latest(
        self, path: pathlib.Path | str, keep: int
    ) -> DiagnosticCleanupPlan:
        return self.diagnostic_cleanup_service.plan_keep_latest(path, keep)

    def plan_diagnostic_selected_databases(
        self, paths: typing.Iterable[pathlib.Path | str]
    ) -> DiagnosticCleanupPlan:
        return self.diagnostic_cleanup_service.plan_selected_databases(paths)

    def plan_diagnostic_all_closed_databases(
        self, paths: typing.Iterable[pathlib.Path | str]
    ) -> DiagnosticCleanupPlan:
        return self.diagnostic_cleanup_service.plan_all_closed_databases(paths)

    def plan_diagnostic_vacuum(
        self, paths: typing.Iterable[pathlib.Path | str]
    ) -> DiagnosticCleanupPlan:
        return self.diagnostic_cleanup_service.plan_vacuum(paths)

    def execute_diagnostic_cleanup(
        self,
        plan: DiagnosticCleanupPlan,
        *,
        checkpoint_wal: bool = True,
        vacuum_after: bool = False,
    ) -> DiagnosticCleanupResult:
        return self.diagnostic_cleanup_service.execute(
            plan,
            checkpoint_wal=checkpoint_wal,
            vacuum_after=vacuum_after,
        )

    def get_config_v2_serializer_manifest(self) -> tuple[ConfigV2FieldSerializer, ...]:
        return self.config_v2_editing_service.serializer_manifest()

    def create_config_v2_project_draft(
        self,
        project: object,
        *,
        destination: pathlib.Path,
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.create_draft(
            project,
            destination=destination,
        )

    def validate_config_v2_project_draft(
        self, draft: ConfigV2ProjectDraft
    ) -> ConfigV2ProjectValidation:
        return self.config_v2_editing_service.validate(draft)

    def set_config_v2_description(
        self, draft: ConfigV2ProjectDraft, description: str
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.set_description(draft, description)

    def add_config_v2_pass(
        self,
        draft: ConfigV2ProjectDraft,
        pass_id: str,
        *,
        index: int | None = None,
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.add_pass(draft, pass_id, index=index)

    def add_config_v2_passes(
        self,
        draft: ConfigV2ProjectDraft,
        pass_ids: tuple[str, ...],
        *,
        index: int | None = None,
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.add_passes(
            draft, pass_ids, index=index
        )

    def remove_config_v2_pass(
        self, draft: ConfigV2ProjectDraft, pass_index: int
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.remove_pass(draft, pass_index)

    def reorder_config_v2_pass(
        self,
        draft: ConfigV2ProjectDraft,
        pass_index: int,
        new_index: int,
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.reorder_pass(draft, pass_index, new_index)

    def set_config_v2_pass_options(
        self,
        draft: ConfigV2ProjectDraft,
        *,
        pass_index: int,
        options: typing.Mapping[str, object],
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.set_pass_options(
            draft,
            pass_index=pass_index,
            options=options,
        )

    def set_config_v2_pass_transforms(
        self,
        draft: ConfigV2ProjectDraft,
        *,
        pass_index: int,
        transform_ids: typing.Sequence[str],
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.set_pass_transforms(
            draft,
            pass_index=pass_index,
            transform_ids=transform_ids,
        )

    def set_config_v2_routing_override(
        self,
        draft: ConfigV2ProjectDraft,
        *,
        prefer: typing.Mapping[str, float],
        require: str | None,
        deny: typing.Sequence[str],
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.set_routing_override(
            draft,
            prefer=prefer,
            require=require,
            deny=deny,
        )

    def clear_config_v2_routing_override(
        self, draft: ConfigV2ProjectDraft
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.clear_routing_override(draft)

    def replace_config_v2_document(
        self,
        draft: ConfigV2ProjectDraft,
        document: typing.Mapping[str, object],
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.replace_document(draft, document)

    def materialize_recipe_as_config_v2(
        self,
        draft: ConfigV2ProjectDraft,
        recipe: PipelineRecipeDraft,
    ) -> ConfigV2ProjectDraft:
        return self.config_v2_editing_service.materialize_recipe(draft, recipe)

    def save_config_v2_project(
        self,
        draft: ConfigV2ProjectDraft,
        validation: ConfigV2ProjectValidation,
    ) -> object:
        return self.config_v2_editing_service.save(draft, validation)

    def capture_workbench_baseline(
        self,
        identity: ComparisonIdentity,
        pseudocode: str,
    ) -> BaselineRef:
        """Store one native Hex-Rays baseline as immutable evidence."""
        return self.comparison_service.capture_baseline(identity, pseudocode)

    def capture_workbench_d810_output(
        self,
        identity: ComparisonIdentity,
        pseudocode: str,
    ) -> D810OutputRef:
        """Store one normal D810 output as immutable evidence."""
        return self.comparison_service.capture_d810_output(identity, pseudocode)

    def get_workbench_comparison(
        self,
        identity: ComparisonIdentity,
    ) -> WorkbenchComparisonSnapshot:
        """Compare captured evidence only when its full identity is current."""
        return self.comparison_service.compare(identity)

    def get_workbench_recipe_catalog(self) -> tuple[PassCatalogEntry, ...]:
        return self.recipe_service.catalog()

    def get_workbench_recipe_inspection_catalog(
        self, pass_ids: tuple[str, ...]
    ) -> tuple[PassCatalogEntry, ...]:
        return self.recipe_service.inspection_catalog(pass_ids)

    def create_workbench_recipe_draft(
        self,
        snapshot: DeobfuscationWorkbenchSnapshot,
        project: object,
    ) -> PipelineRecipeDraft:
        override = self.get_workbench_function_recipe(snapshot.function.ea)
        if override is not None:
            return self.recipe_service.create_draft_from_override(
                override,
                function_ea=snapshot.function.ea,
                function_fingerprint=snapshot.function.fingerprint,
                workbench_generation=snapshot.generation,
                project_path=snapshot.project.project_path,
            )
        return self.recipe_service.create_draft(
            function_ea=snapshot.function.ea,
            function_fingerprint=snapshot.function.fingerprint,
            workbench_generation=snapshot.generation,
            project_path=snapshot.project.project_path,
            configs=pipeline_configs_from_project_config(project),
        )

    def create_active_workbench_recipe_draft(
        self,
        *,
        function_ea: int,
        project_path: str,
        project: object,
    ) -> PipelineRecipeDraft:
        """Create an in-memory recipe from the exact active config-v2 pipeline."""
        return self.recipe_service.create_draft(
            function_ea=function_ea,
            function_fingerprint=None,
            workbench_generation=0,
            project_path=project_path,
            configs=pipeline_configs_from_project_config(project),
        )

    def create_saved_workbench_recipe_draft(
        self,
        *,
        function_ea: int,
        function_fingerprint: str | None,
        workbench_generation: int,
        project_path: str,
    ) -> PipelineRecipeDraft | None:
        override = self.get_workbench_function_recipe(function_ea)
        if override is None:
            return None
        return self.recipe_service.create_draft_from_override(
            override,
            function_ea=function_ea,
            function_fingerprint=function_fingerprint,
            workbench_generation=workbench_generation,
            project_path=project_path,
        )

    def validate_workbench_recipe(
        self,
        draft: PipelineRecipeDraft,
        *,
        facts: object | None = None,
    ) -> RecipeValidation:
        return self.recipe_service.validate(draft, facts=facts)

    def add_workbench_recipe_pass(
        self,
        draft: PipelineRecipeDraft,
        pass_id: str,
    ) -> PipelineRecipeDraft:
        return self.recipe_service.add_pass(draft, pass_id)

    def remove_workbench_recipe_pass(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
    ) -> PipelineRecipeDraft:
        return self.recipe_service.remove_pass(draft, item_id)

    def set_workbench_recipe_pass_enabled(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
        enabled: bool,
    ) -> PipelineRecipeDraft:
        return self.recipe_service.set_enabled(draft, item_id, enabled)

    def reorder_workbench_recipe_pass(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
        new_index: int,
    ) -> PipelineRecipeDraft:
        return self.recipe_service.reorder_pass(draft, item_id, new_index)

    def replace_workbench_recipe_pass_options(
        self,
        draft: PipelineRecipeDraft,
        item_id: str,
        options: typing.Mapping[str, object],
    ) -> PipelineRecipeDraft:
        return self.recipe_service.replace_options(draft, item_id, options)

    def replace_workbench_recipe_state_cff_options(
        self,
        draft: PipelineRecipeDraft,
        options: StateMachineCffOptions,
    ) -> PipelineRecipeDraft:
        return self.recipe_service.replace_state_cff_options(draft, options)

    def get_workbench_recipe_state_cff_options(
        self,
        draft: PipelineRecipeDraft,
    ) -> StateMachineCffOptions:
        return self.recipe_service.state_cff_options(draft)

    def get_workbench_function_recipe(
        self,
        function_ea: int,
    ) -> FunctionPipelineOverride | None:
        return self.function_recipe_runtime.get(function_ea)

    def save_workbench_function_recipe(
        self,
        draft: PipelineRecipeDraft,
        validation: RecipeValidation,
    ) -> FunctionPipelineOverride:
        pass_configs_json = self.recipe_service.serialize_enabled_configs(draft)
        return self.function_recipe_runtime.save(
            draft,
            validation,
            pass_configs_json=pass_configs_json,
        )

    def clear_workbench_function_recipe(self, function_ea: int) -> bool:
        return self.function_recipe_runtime.clear(function_ea)

    def execute_workbench_apply_recipe_once(
        self,
        request: RecipeCommandRequest,
        draft: PipelineRecipeDraft,
        validation: RecipeValidation,
        *,
        lifecycle: typing.Callable[[PipelineRecipeDraft], bool],
    ) -> RecipeCommandResult:
        return self.recipe_command_service.execute_apply_once(
            request,
            draft,
            validation,
            lifecycle=lifecycle,
        )

    def execute_workbench_save_function_recipe(
        self,
        request: RecipeCommandRequest,
        draft: PipelineRecipeDraft,
        validation: RecipeValidation,
    ) -> RecipeCommandResult:
        return self.recipe_command_service.execute_save(
            request,
            draft,
            validation,
            persistence=self.save_workbench_function_recipe,
        )

    def get_workbench_snapshot(
        self,
        *,
        function_ea: int,
        function_name: str,
        function_fingerprint: str | None,
        project_snapshot: ProjectRuntimeSnapshot,
        project: typing.Any,
        facts: typing.Any | None = None,
        baseline: BaselineRef | None = None,
        latest_output: D810OutputRef | None = None,
    ) -> DeobfuscationWorkbenchSnapshot:
        """Collect one immutable read-only workbench snapshot."""
        project_scope = "project"
        initial_errors: tuple[str, ...] = ()
        saved_recipe: FunctionPipelineOverride | None = None
        try:
            override = self.function_recipe_runtime.get(function_ea)
            selection = select_workbench_recipe_projection(
                project,
                project_snapshot,
                override,
                function_ea=function_ea,
                function_fingerprint=function_fingerprint,
            )
            project = selection.project
            project_snapshot = selection.project_snapshot
            project_scope = selection.recipe_scope
            initial_errors = selection.errors
            if selection.recipe_scope == "saved-recipe-explicit":
                saved_recipe = override
        except FunctionRecipePersistenceError as exc:
            project_scope = "saved-recipe-blocked"
            initial_errors = (f"function recipe: {exc}",)
        return self.workbench_service.collect(
            function_ea=function_ea,
            function_name=function_name,
            function_fingerprint=function_fingerprint,
            project_snapshot=project_snapshot,
            project=project,
            facts=facts,
            baseline=baseline,
            latest_output=latest_output,
            project_scope=project_scope,
            saved_recipe=saved_recipe,
            initial_errors=initial_errors,
        )

    def get_deobfuscation_case_snapshot(
        self,
        *,
        function: FunctionRef,
        project: ProjectConfigRef,
        saved_recipe: FunctionPipelineOverride | None,
    ) -> DeobfuscationCaseSnapshot:
        """Project only closed, current-schema diagnostic databases for one function."""
        databases = self.diagnostic_inventory_service.databases()
        paths = tuple(
            pathlib.Path(database.path)
            for database in databases
            if (
                database.readable
                and not database.active
                and database.schema_version
                == SqliteCaseDiagnosticReader._SUPPORTED_SCHEMA_VERSION
                and int(function.ea) in database.function_eas
            )
        )
        repository = DeobfuscationCaseRepository(SqliteCaseDiagnosticReader(paths))
        return DeobfuscationCaseService(repository).collect(
            function=function,
            project=project,
            saved_recipe=saved_recipe,
        )

    def analyze_workbench_function(
        self,
        *,
        function_ea: int,
        target: object,
        provider_phase: object,
    ) -> object:
        """Collect and classify evidence without applying any rewrite."""
        if self._recon_runtime is not None:
            return self._recon_runtime.collect_and_analyze(
                int(function_ea),
                target,
                provider_phase,
                persist_hints=True,
            )
        if self._preanalysis_runtime is None or self._analysis_runtime is None:
            raise RuntimeError("Analysis runtime is not available")
        self._preanalysis_runtime.capture_facts(
            target,
            func_ea=int(function_ea),
            provider_phase=provider_phase,
            phase="workbench_analysis",
        )
        return self._analysis_runtime.analyze(int(function_ea))

    def analyze_workbench_recipe(
        self,
        *,
        function_ea: int,
        target: object,
        provider_phase: object,
    ) -> object:
        """Capture mutation-free live facts for Recipe Composer preflight."""
        return collect_recipe_preflight_facts(
            self._recon_runtime or self._preanalysis_runtime,
            function_ea=function_ea,
            target=target,
            provider_phase=provider_phase,
        )

    def configure(self, **kwargs):
        self.config = kwargs
        self._semantic_route_reference_oracle_registry = (
            _load_semantic_route_reference_oracle_registry(kwargs)
        )
        self._load_function_analysis_priors_from_config(
            kwargs.get("function_analysis_priors", {})
        )
        if self._started:
            self._sync_native_preanalysis_handlers()

    @staticmethod
    def _activation_copy(value: object) -> object:
        """Copy ordinary activation state without cloning live rule objects.

        Required live mutable containers are handled explicitly by
        :meth:`_snapshot_activation_object`; this fallback is for opaque,
        disposable implementation details only.
        """

        try:
            return copy.deepcopy(value)
        except Exception:  # noqa: BLE001 - some IDA/SWIG values are opaque
            return value

    @classmethod
    def _snapshot_activation_object(
        cls,
        obj: object | None,
        *,
        preserve: frozenset[str] = frozenset(),
    ) -> tuple[object | None, dict[str, object]] | None:
        if obj is None:
            return None
        attributes = getattr(obj, "__dict__", None)
        if not isinstance(attributes, dict):
            return (obj, {})

        def _preserve_nested_container(value: object) -> object:
            if isinstance(value, dict):
                return _ActivationContainerSnapshot(value, dict(value))
            if isinstance(value, list):
                return _ActivationContainerSnapshot(value, list(value))
            if isinstance(value, set):
                return _ActivationContainerSnapshot(value, set(value))
            return value

        def _preserved_value(name: str, value: object) -> object:
            if isinstance(value, dict):
                return _ActivationContainerSnapshot(value, dict(value))
            if isinstance(value, list):
                return _ActivationContainerSnapshot(value, list(value))
            if isinstance(value, set):
                return _ActivationContainerSnapshot(value, set(value))
            if name in {"pattern_storage", "_indexed_storage"}:
                object_dict = getattr(value, "__dict__", None)
                if isinstance(object_dict, dict):
                    contents = {
                        attr: _preserve_nested_container(attr_value)
                        for attr, attr_value in object_dict.items()
                    }
                    return _ActivationContainerSnapshot(value, contents)
            if name == "_stages" and isinstance(value, tuple):
                # Tuples are immutable; restoration rebinds the original tuple
                # object.  It is an internal stage descriptor, not a mutable
                # cache observed by callers.
                return value
            return value

        return (
            obj,
            {
                name: (
                    _preserved_value(name, value)
                    if name in preserve
                    else cls._activation_copy(value)
                )
                for name, value in attributes.items()
            },
        )

    @classmethod
    def _restore_activation_container(
        cls, snapshot: _ActivationContainerSnapshot
    ) -> object:
        target = snapshot.target
        contents = snapshot.contents
        if isinstance(contents, dict):
            restored_contents = {
                key: cls._restore_activation_container(value)
                if isinstance(value, _ActivationContainerSnapshot)
                else value
                for key, value in contents.items()
            }
        else:
            restored_contents = contents
        if isinstance(target, dict) and isinstance(contents, dict):
            target.clear()
            target.update(restored_contents)
        elif isinstance(target, list) and isinstance(contents, list):
            target.clear()
            target.extend(
                cls._restore_activation_container(value)
                if isinstance(value, _ActivationContainerSnapshot)
                else value
                for value in contents
            )
        elif isinstance(target, set) and isinstance(contents, set):
            target.clear()
            target.update(restored_contents)
        else:
            object_dict = getattr(target, "__dict__", None)
            if isinstance(object_dict, dict) and isinstance(contents, dict):
                object_dict.clear()
                object_dict.update(restored_contents)
        return target

    @classmethod
    def _restore_activation_object(cls, snapshot) -> None:
        if snapshot is None:
            return
        obj, attributes = snapshot
        if obj is None:
            return
        current = getattr(obj, "__dict__", None)
        if not isinstance(current, dict):
            return
        for name in tuple(current):
            if name not in attributes:
                try:
                    delattr(obj, name)
                except Exception:  # noqa: BLE001 - preserve the primary error
                    logger.exception(
                        "project activation rollback could not remove %s.%s",
                        type(obj).__name__,
                        name,
                    )
        for name, value in attributes.items():
            try:
                if isinstance(value, _ActivationContainerSnapshot):
                    value = cls._restore_activation_container(value)
                setattr(obj, name, value)
            except Exception:  # noqa: BLE001 - preserve the primary error
                logger.exception(
                    "project activation rollback could not restore %s.%s",
                    type(obj).__name__,
                    name,
                )

    def snapshot_project_activation_state(self) -> dict[str, object]:
        """Capture mutable manager/runtime state before project activation.

        Project loading stages against candidate rule objects, but manager
        configuration still touches the live execution-scope service and (when
        started) optimizer adapters.  This snapshot is intentionally private
        to the activation transaction and keeps object identity for live rules,
        schedulers, event emitters, and IDA-owned services.
        """

        instruction_optimizer = getattr(self, "instruction_optimizer", None)
        instruction_children = ()
        if instruction_optimizer is not None:
            instruction_children = tuple(
                self._snapshot_activation_object(
                    optimizer,
                    preserve=frozenset(
                        {
                            "rules",
                            "pattern_storage",
                            "_indexed_storage",
                            "_structural_rules_by_root_opcode",
                            "_allowed_root_opcodes",
                            "_active_cache",
                            "event_emitter",
                            "stats",
                            "log_dir",
                            "_run_later_callback",
                        }
                    ),
                )
                for optimizer in tuple(
                    getattr(instruction_optimizer, "instruction_optimizers", ())
                )
            )
            instruction_analyzer = self._snapshot_activation_object(
                getattr(instruction_optimizer, "analyzer", None),
                preserve=frozenset({"rules", "stats", "log_dir"}),
            )
        else:
            instruction_analyzer = None

        block_optimizer = getattr(self, "block_optimizer", None)
        block_rule_snapshots = ()
        if block_optimizer is not None:
            block_rule_snapshots = tuple(
                self._snapshot_activation_object(rule)
                for rule in tuple(getattr(block_optimizer, "cfg_rules", ()))
            )

        from d810.hexrays.preanalysis.indirect_jump_labels import (
            snapshot_indirect_materialization_registry,
        )

        return {
            "project_activation_registries": snapshot_project_activation_registries(),
            "indirect_materialization_registry": (
                snapshot_indirect_materialization_registry()
            ),
            "config": (self.config, self._activation_copy(self.config)),
            "semantic_registry": self._semantic_route_reference_oracle_registry,
            "priors": (
                self._function_analysis_priors,
                self._activation_copy(self._function_analysis_priors),
            ),
            "native_handlers": self._native_preanalysis_handlers_installed,
            "instruction_rules": self.instruction_optimizer_rules,
            "instruction_config": self.instruction_optimizer_config,
            "block_rules": self.block_optimizer_rules,
            "block_config": self.block_optimizer_config,
            "ctree_rules": self.ctree_optimizer_rules,
            "ctree_config": self.ctree_optimizer_config,
            "execution_scope": self._snapshot_activation_object(
                self.execution_scope_service,
                preserve=frozenset(
                    {
                        "_metadata_provider",
                        "_inference_registry",
                        "_attached_emitter",
                        "_stages",
                        "_active_cache",
                        "_metadata_cache",
                        "_hint_inferences",
                        "_hint_suppressions",
                    }
                ),
            ),
            "instruction_optimizer": self._snapshot_activation_object(
                instruction_optimizer,
                preserve=frozenset(
                    {
                        "instruction_optimizers",
                        "analyzer",
                        "event_emitter",
                        "stats",
                        "log_dir",
                        "_instruction_optimizer_type",
                        "instruction_visitor",
                        "_active_rule_cache",
                    }
                ),
            ),
            "instruction_children": instruction_children,
            "instruction_analyzer": instruction_analyzer,
            "block_optimizer": self._snapshot_activation_object(
                block_optimizer,
                preserve=frozenset(
                    {
                        "cfg_rules",
                        "event_emitter",
                        "stats",
                        "log_dir",
                        "_flow_context_type",
                        "_run_later_scheduler",
                        "_active_cache",
                    }
                ),
            ),
            "block_rule_snapshots": block_rule_snapshots,
            "instruction_scheduler": self._snapshot_activation_object(
                self.instruction_pass_scheduler,
                preserve=frozenset({"_pending_by_func"}),
            ),
            "block_scheduler": self._snapshot_activation_object(
                self.block_pass_scheduler,
                preserve=frozenset({"_pending_by_func"}),
            ),
        }

    def restore_project_activation_state(self, snapshot: dict[str, object]) -> None:
        """Restore a failed project activation without masking its exception."""

        config_ref, config_value = snapshot["config"]
        try:
            config_ref.clear()
            config_ref.update(self._activation_copy(config_value))
        except Exception:  # noqa: BLE001 - preserve the activation failure
            logger.exception("project activation config rollback failed")
        self.config = config_ref
        self._semantic_route_reference_oracle_registry = snapshot[
            "semantic_registry"
        ]
        priors_ref, priors_value = snapshot["priors"]
        try:
            priors_ref.clear()
            priors_ref.update(self._activation_copy(priors_value))
        except Exception:  # noqa: BLE001 - preserve the activation failure
            logger.exception("project activation priors rollback failed")
        self._function_analysis_priors = priors_ref
        self.instruction_optimizer_rules = snapshot["instruction_rules"]
        self.instruction_optimizer_config = snapshot["instruction_config"]
        self.block_optimizer_rules = snapshot["block_rules"]
        self.block_optimizer_config = snapshot["block_config"]
        self.ctree_optimizer_rules = snapshot["ctree_rules"]
        self.ctree_optimizer_config = snapshot["ctree_config"]
        self._restore_activation_object(snapshot["execution_scope"])
        self._restore_activation_object(snapshot["instruction_optimizer"])
        for child_snapshot in snapshot["instruction_children"]:
            self._restore_activation_object(child_snapshot)
        self._restore_activation_object(snapshot["instruction_analyzer"])
        self._restore_activation_object(snapshot["block_optimizer"])
        for rule_snapshot in snapshot["block_rule_snapshots"]:
            self._restore_activation_object(rule_snapshot)
        self._restore_activation_object(snapshot["instruction_scheduler"])
        self._restore_activation_object(snapshot["block_scheduler"])

        expected_native = bool(snapshot["native_handlers"])
        if self._native_preanalysis_handlers_installed != expected_native:
            try:
                if self._native_preanalysis_handlers_installed:
                    self._uninstall_native_preanalysis_handlers()
                if expected_native:
                    self._install_native_preanalysis_handlers()
            except Exception:  # noqa: BLE001 - preserve the activation failure
                logger.exception("project activation native handler rollback failed")
            self._native_preanalysis_handlers_installed = expected_native

        # Native-handler reconciliation can itself touch the indirect
        # materialization executor.  Restore profile-global registries last so
        # their identity and contents are exact after every rollback path.
        try:
            restore_project_activation_registries(
                snapshot["project_activation_registries"]
            )
            from d810.hexrays.preanalysis.indirect_jump_labels import (
                restore_indirect_materialization_registry,
            )

            restore_indirect_materialization_registry(
                snapshot["indirect_materialization_registry"]
            )
        except Exception:  # noqa: BLE001 - preserve the activation failure
            logger.exception("project activation registry rollback failed")

    def reconfigure_function_storage(
        self,
        config: FunctionRecipeStorageConfig | None,
    ) -> None:
        """Install application-owned recipe storage independently of projects."""

        self._function_storage_config = config
        self.function_storage_runtime.configure_storage(config)
        if not self._started:
            return
        if config is None:
            self.function_storage_runtime.close()
            return
        self.function_storage_runtime.initialize_storage(config)

    @staticmethod
    def _create_function_storage(target, *, backend: str = "sqlite"):
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

    def emit_execution_scope_invalidation(
        self,
        reason: ExecutionScopeEvent,
        *,
        project_name: str | None = None,
        func_eas: frozenset[int] | None = None,
        changed_targets: frozenset[str] | None = None,
        isolated: bool = False,
    ) -> None:
        """Notify execution-scope observers.

        Existing callers keep propagating emitter semantics.  Project
        activation passes ``isolated=True`` after its publication commit so
        observer failures are logged while every peer listener still runs.
        """

        payload = ExecutionScopeInvalidation(
            reason=reason,
            project_name=project_name,
            func_eas=func_eas,
            changed_targets=changed_targets,
        )
        if not isolated:
            self.event_emitter.emit(reason, payload)
            return
        for failure in self.event_emitter.emit_isolated(reason, payload):
            logger.warning(
                "execution-scope observer failed during isolated activation notification: %s",
                failure,
                exc_info=(type(failure), failure, failure.__traceback__),
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
            from d810.backends.hexrays.global_const_annotation import (
                pending_global_const_proposals,
            )
            from d810.backends.hexrays.global_const_observer import GlobalConstObserver

            # The pre-Hex preparation journal and proposal netnode are scoped
            # by the durable IDB identity, not the project/configuration key.
            # Reuse that same identity for the observer's pending lookup so a
            # project switch cannot make one database's proposals appear
            # pending in another database.
            preparation = getattr(self, "pre_hex_preparation", None)
            database_identity = getattr(
                preparation,
                "database_identity",
                self._database_identity,
            )
            lifecycle = getattr(self, "decompilation_lifecycle", None)
            current_mba_generation = getattr(
                lifecycle,
                "current_mba_generation",
                None,
            )
            if callable(current_mba_generation):

                def mba_generation_provider(
                    function_ea: int,
                    _provider=current_mba_generation,
                ) -> int:
                    return int(_provider(function_ea=int(function_ea)))

            else:
                mba_generation_provider = None
            self._post_d810_runtime = HexRaysPostD810Runtime(
                preanalysis_runtime=self._preanalysis_runtime,
                block_optimizer=self.block_optimizer,
                maturity_name_provider=_maturity_name,
                handoff_detector=detect_post_d810_handoff_violations,
                global_const_observer=GlobalConstObserver(
                    preparation_options=self._constant_preparation_options,
                    database_identity=database_identity,
                    pending_proposals=lambda: pending_global_const_proposals(
                        database_identity=database_identity,
                    ),
                ),
                mba_generation_provider=mba_generation_provider,
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
        self._runtime_invalidated = False
        logger.debug("Starting manager...")
        load_optimizer_registries()
        # Ensure side-effect registrants are loaded before manager construction.
        from d810.optimizers.microcode.instructions.pattern_matching import (  # noqa: F401
            experimental,
        )

        self.execution_scope_service.attach(self.event_emitter)
        self._init_storage()
        self.execution_scope_service.set_metadata_provider(self._get_execution_metadata)
        self.execution_scope_service.register_inference(
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
            execution_scope_service=self.execution_scope_service,
            execution_scope_project_name=project_name,
            execution_scope_idb_key=idb_key,
            pass_scheduler=self.instruction_pass_scheduler,
        )
        self.block_optimizer = BlockOptimizerManager(
            self.stats, self.log_dir, ctx_cls=FlowMaturityContext
        )
        self.block_optimizer.configure(
            **self.block_optimizer_config,
            execution_scope_service=self.execution_scope_service,
            execution_scope_project_name=project_name,
            execution_scope_idb_key=idb_key,
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

        self._native_patch_execution_journal = (
            self._new_native_patch_execution_journal()
        )
        self.decompilation_lifecycle = DecompilationLifecycleCoordinator(
            preanalysis_runtime=self._preanalysis_runtime,
            analysis_runtime=self._analysis_runtime,
            execution_scope_service=self.execution_scope_service,
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
            execution_journal=self._native_patch_execution_journal,
        )
        self._install_native_writer_migration()
        self._install_pre_hexrays_preparation()

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
            self.instruction_optimizer.configure(
                fact_consumer_callback=(self._analysis_runtime.record_fact_consumers),
            )
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
        self._compile_execution_scope()
        self._install_hooks()
        self._started = True

    def _init_storage(self) -> None:
        if self._function_storage_config is not None:
            self.function_storage_runtime.initialize_storage(
                self._function_storage_config
            )

    def _new_native_patch_execution_journal(self):
        """Open the manager-owned provenance store before any native request.

        Unlike the IDB mirror, this SQLite journal is the durable authority for
        parent/child attempt ordering.  It intentionally lives beside the
        manager's other diagnostic artifacts, never in a temporary directory.
        """
        from d810.core.execution_journal_store import ExecutionJournalStore

        self.log_dir.mkdir(parents=True, exist_ok=True)
        return ExecutionJournalStore(
            self.log_dir / "native_patch_execution.sqlite",
            callback_detail=get_settings().execution_callback_detail,
        )

    def _install_pre_hexrays_preparation(self) -> None:
        """Compose and recover the IDB-only preparation lane before hooks."""

        import hashlib

        from d810.backends.hexrays.global_const_annotation import (
            acknowledge_global_const_proposals,
            annotate_function_global_consts,
            pending_global_const_proposals,
        )
        from d810.backends.hexrays.input_identity_attestation import (
            NetnodeLocalDatabaseIdentityStore,
        )
        from d810.backends.hexrays.native_patch_lifecycle import (
            IdaCallerDiscovery,
            IdaCfuncCacheInvalidator,
            IdaControlledRedoDecompiler,
        )
        from d810.backends.ida.idb_preparation.gateway import (
            IdaPreparationByteWriter,
            IdbPreparationGateway,
        )
        from d810.backends.ida.idb_preparation.journal import (
            SQLitePreparationJournal,
        )
        from d810.backends.ida.idb_preparation.patch_ledger import IdaPatchLedger
        from d810.backends.ida.idb_preparation.script_runner import (
            TrustedPreparationScriptRunner,
        )
        from d810.backends.ida.idb_preparation.type_metadata import IdaTypeMetadata
        from d810.backends.ida.native_patch.reanalysis import IdaFunctionReanalyzer
        from d810.capabilities.idb_preparation import PreparationScriptDescriptor
        from d810.manager.pre_hexrays_preparation import PreHexPreparationController

        try:
            database_identity = NetnodeLocalDatabaseIdentityStore().load_or_create()
        except Exception:
            logger.exception(
                "pre-Hex-Rays preparation unavailable: durable IDB identity failed"
            )
            self.pre_hex_preparation = None
            return

        previous = self._idb_preparation_journal
        if previous is not None:
            previous.close()
        journal = SQLitePreparationJournal(
            self.log_dir / "idb_preparation_journal.sqlite"
        )

        def _native_ranges(identity: str) -> tuple[tuple[int, int], ...]:
            native_journal = self._native_patch_journal
            if native_journal is None:
                return ()
            return native_journal.active_operation_ranges(database_identity=identity)

        def _function_owner(ea: int) -> int | None:
            import ida_funcs

            function = ida_funcs.get_func(int(ea))
            return None if function is None else int(function.start_ea)

        gateway = IdbPreparationGateway(
            journal=journal,
            patch_ledger=IdaPatchLedger(),
            script_runner=TrustedPreparationScriptRunner(),
            byte_writer=IdaPreparationByteWriter(),
            current_database_identity=database_identity,
            native_active_ranges=_native_ranges,
            function_owner=_function_owner,
            reanalyzer=IdaFunctionReanalyzer(),
            cache_invalidator=IdaCfuncCacheInvalidator(),
            caller_discovery=IdaCallerDiscovery(),
            redo_decompiler=IdaControlledRedoDecompiler(),
            type_metadata=IdaTypeMetadata(),
        )
        self._idb_preparation_journal = journal
        self._idb_preparation_gateway = gateway
        recovery = gateway.recover_startup()
        for receipt in recovery:
            if not receipt.ok:
                logger.warning(
                    "pre-Hex-Rays preparation recovery incomplete for %s: %s",
                    receipt.transaction_id.value,
                    receipt.failure_reason,
                )

        type_step_path = (
            pathlib.Path(__file__).parents[1]
            / "backends/ida/idb_preparation/type_proposal_step.py"
        ).resolve()
        type_step_hash = hashlib.sha256(type_step_path.read_bytes()).hexdigest()
        type_step = PreparationScriptDescriptor(
            script_id="d810-global-const-types",
            display_name="D810 global const type proposals",
            path=str(type_step_path),
            source_sha256=type_step_hash,
            enabled=True,
            portable=True,
        )
        preparation_options = self._constant_preparation_options

        def _discover_type_proposals(function_ea: int):
            return annotate_function_global_consts(
                function_ea,
                database_identity=database_identity,
            )

        def _pending_type_proposals():
            return pending_global_const_proposals(
                database_identity=database_identity,
            )

        def _acknowledge_type_proposals(proposals):
            return acknowledge_global_const_proposals(
                proposals,
                database_identity=database_identity,
            )

        self.pre_hex_preparation = PreHexPreparationController(
            database_identity=database_identity,
            scripts=tuple(self._preparation_scripts),
            gateway=gateway,
            prepared_records=journal.transactions,
            transaction_type_deltas=journal.type_deltas,
            # Keep the real IDA whole-item discovery callback installed for the
            # lifetime of the controller.  Its current policy gates invocation
            # so a project can enable preparation without reinstalling hooks.
            discover_type_proposals=_discover_type_proposals,
            pending_type_proposals=_pending_type_proposals,
            acknowledge_type_proposals=_acknowledge_type_proposals,
            type_step_descriptor=type_step,
            preparation_options=preparation_options,
        )

    def reconfigure_execution_callback_detail(self, callback_detail: str) -> None:
        """Apply the persisted callback-retention choice to the live journal."""
        normalized_detail = str(callback_detail).strip().lower()
        if normalized_detail not in {"summary", "full"}:
            raise ValueError("callback_detail must be 'summary' or 'full'")
        journal = self._native_patch_execution_journal
        if journal is not None:
            journal.configure_callback_detail(normalized_detail)

    def _install_native_writer_migration(self) -> None:
        """Inject the one manager-authorized indirect-label executor.

        The lower Hex-Rays module retains no manager import.  Its registration
        resolves this default only after the manager has created the durable
        execution journal and the lifecycle session parent attempt.
        """
        from d810.backends.hexrays.native_patch_lifecycle import (
            IdaCallerDiscovery,
            IdaCfuncCacheInvalidator,
            IdaControlledRedoDecompiler,
        )
        from d810.backends.ida.native_patch.capture import IdaLiveDatabaseReader
        from d810.backends.ida.native_patch.gateway import (
            IdaNativeByteWriter,
            NativePatchGateway,
        )
        from d810.backends.ida.native_patch.encoder import MinimalX86BranchEncoder
        from d810.backends.ida.native_patch.origin_mapper import IdaNativeOriginMapper
        from d810.backends.ida.native_patch.native_cfg_observer import (
            capture_live_native_flowchart,
        )
        from d810.backends.ida.native_patch.native_cfg_plan import (
            capture_database_attestation,
        )
        from d810.backends.hexrays.ctree_fingerprint import fingerprint_ctree
        from d810.backends.hexrays.ctree_native_ranges import (
            capture_ctree_native_ranges,
        )
        from d810.backends.ida.native_patch.dead_edge_oracle import (
            build_dead_edge_semantic_plan,
            find_dead_edges_for_function,
        )
        from d810.backends.ida.native_patch.indirect_label_plan import (
            IndirectLabelPlanRequest,
            build_indirect_label_metadata_plan,
        )
        from d810.backends.ida.native_patch.issuer import (
            NativePatchIssuerRegistry,
            dead_edge_semantic_issuers,
            indirect_label_materializer_issuer,
            stage_c_native_cfg_issuer,
        )
        from d810.backends.ida.native_patch.journal import SQLiteNativePatchJournal
        from d810.backends.ida.native_patch.metadata import IdaMetadataActionExecutor
        from d810.backends.ida.native_patch.reanalysis import (
            IdaFunctionExtentRestorer,
            IdaFunctionFlowRestorer,
            IdaFunctionReanalyzer,
        )
        from d810.core.persistence import NetnodeOptimizationStorage
        from d810.hexrays.preanalysis.indirect_jump_labels import (
            IndirectLabelMaterializationResult,
            NativePatchPlanRequest,
            execute_legacy_indirect_materialization,
            set_indirect_materialization_default_executor,
        )
        from d810.hexrays.hooks.optimization_suppression import (
            suppress_d810_optimization,
        )
        from d810.manager.native_writer_migration import (
            ManagerOwnedDeadEdgeNormalizer,
            ManagerOwnedNativePatchRequestExecutor,
            PreparedNativePatchRequest,
            native_patch_function_is_authorized,
        )
        from d810.manager.native_cfg_normalization import (
            ManagerOwnedNativeCfgNormalizer,
        )
        from d810.manager.native_normalization import (
            NativeNormalizationRequest,
            authorize_and_apply,
            recover_startup,
        )
        from d810.transforms.native_cfg_normalization import validate_live_native_cfg

        self._dead_edge_normalizer = None

        # This profile predates the generic native-patch writer. Its proven
        # materialization needs IDA's transient flow-analysis hints, which are
        # intentionally not representable as durable generic metadata actions.
        # Select it before the generic opt-in gate: this is a separate,
        # explicitly configured compatibility executor, not an authorization
        # bypass for generic native patches.
        if bool(self.config.get("legacy_direct_indirect_materialization", False)):
            set_indirect_materialization_default_executor(
                execute_legacy_indirect_materialization
            )
            return

        if self._native_patch_journal is not None:
            self._native_patch_journal.close()
        self._native_patch_journal = SQLiteNativePatchJournal(
            self.log_dir / "native_patch_journal.sqlite"
        )
        certificate_store = self.storage
        if certificate_store is None or not hasattr(
            certificate_store, "set_native_patch_blob"
        ):
            certificate_store = NetnodeOptimizationStorage()

        # A destructive gateway is scoped to the open IDB, not to a loader
        # hash. The IDB-owned UUID survives unavailable input metadata and
        # keeps journal recovery from crossing databases.
        from d810.backends.hexrays.input_identity_attestation import (
            InputIdentityAttestationMalformed,
            NetnodeLocalDatabaseIdentityStore,
            NetnodeInputIdentityAttestationStore,
        )

        try:
            database_uuid = NetnodeLocalDatabaseIdentityStore().load_or_create()
        except Exception:
            logger.exception("native patch gateway skipped: unavailable IDB identity")
            set_indirect_materialization_default_executor(None)
            return
        try:
            attestation = NetnodeInputIdentityAttestationStore().load()
        except InputIdentityAttestationMalformed:
            logger.warning(
                "native Stage C evidence unavailable: malformed loader attestation"
            )
            attestation = None
        except Exception:
            logger.warning(
                "native Stage C evidence unavailable: loader attestation cannot load",
                exc_info=True,
            )
            attestation = None

        live_reader = IdaLiveDatabaseReader()
        branch_encoder = MinimalX86BranchEncoder()
        gateway = NativePatchGateway(
            journal=self._native_patch_journal,
            reader=live_reader,
            writer=IdaNativeByteWriter(),
            decode_replacement=branch_encoder.decode,
            reanalyzer=IdaFunctionReanalyzer(),
            extent_restorer=IdaFunctionExtentRestorer(),
            flow_restorer=IdaFunctionFlowRestorer(),
            metadata_executor=IdaMetadataActionExecutor(),
            cache_invalidator=IdaCfuncCacheInvalidator(),
            caller_discovery=IdaCallerDiscovery(),
            redo_decompiler=IdaControlledRedoDecompiler(),
            certificate_store=certificate_store,
            issuer_registry=NativePatchIssuerRegistry(
                (
                    indirect_label_materializer_issuer(),
                    *dead_edge_semantic_issuers(),
                    stage_c_native_cfg_issuer(),
                )
            ),
            current_database_identity=database_uuid,
            d810_version="native-writer-migration",
        )
        self._native_patch_gateway = gateway
        # Crash recovery is a startup responsibility, but the SQLite journal
        # is global while an IDB is not. Read the IDB-local UUID and
        # recover only transactions bearing this exact durable UUID; a missing
        # or malformed attestation fails closed rather than applying another
        # database's record to the open IDB.
        recover_startup(
            journal=self._native_patch_journal,
            gateway=gateway,
            database_identity=database_uuid,
        )

        enabled = bool(self.config.get("native_patch_enabled", False))
        if not enabled:
            set_indirect_materialization_default_executor(
                ManagerOwnedNativePatchRequestExecutor(
                    gateway=gateway,
                    user_enabled=lambda _request: False,
                    execution_journal=self._native_patch_execution_journal,
                    parent_attempt_for_request=lambda _request: (_ for _ in ()).throw(
                        RuntimeError("disabled native patch executor has no parent")
                    ),
                    build_plan=lambda _request, _attempt: (_ for _ in ()).throw(
                        RuntimeError("disabled native patch executor cannot lower")
                    ),
                )
            )
            return

        def _observe_stage_c_postconditions(
            *, function_ea, function_ranges, plan, target_graph
        ):
            import ida_hexrays

            with suppress_d810_optimization():
                cfunc = ida_hexrays.decompile(
                    int(function_ea), flags=ida_hexrays.DECOMP_NO_CACHE
                )
            if cfunc is None:
                raise RuntimeError("Stage C controlled redo produced no C-tree")
            projection = capture_ctree_native_ranges(
                cfunc,
                function_ranges=function_ranges,
            )
            structure = fingerprint_ctree(cfunc)
            native_operations_match = True
            for operation in plan.operations:
                current = live_reader.read_current_bytes(
                    operation.range.start_ea, operation.range.end_ea
                )
                if current is None:
                    native_operations_match = False
                    break
                decoded = branch_encoder.decode(
                    operation.range.start_ea,
                    current,
                    bitness=plan.bitness,
                )
                if decoded != operation.expected_after_shape:
                    native_operations_match = False
                    break
            native_cfg_postcondition = validate_live_native_cfg(
                target_graph,
                capture_live_native_flowchart(int(function_ea)),
            )
            if not native_operations_match and native_cfg_postcondition.matches:
                native_cfg_postcondition = dataclasses.replace(
                    native_cfg_postcondition,
                    matches=False,
                    reason="patched operation decode mismatch",
                )
            return projection, structure, native_cfg_postcondition, cfunc

        stage_c_normalizer = ManagerOwnedNativeCfgNormalizer(
            gateway=gateway,
            execution_journal=self._native_patch_execution_journal,
            reader=live_reader,
            origin_mapper=IdaNativeOriginMapper(),
            encoder=branch_encoder,
            input_attestation=attestation,
            capture_ranges=capture_ctree_native_ranges,
            fingerprint_ctree=fingerprint_ctree,
            post_apply_observer=_observe_stage_c_postconditions,
            capture_attestation=(
                capture_database_attestation
                if attestation is not None
                else lambda **_kwargs: None
            ),
        )

        def _consume_stage_c(**kwargs):
            parent_attempt_id = kwargs.pop("parent_attempt_id")
            if parent_attempt_id is None:
                raise RuntimeError("Stage C has no authorizing parent attempt")
            kwargs.pop("native_key", None)
            return stage_c_normalizer.normalize(
                **kwargs,
                parent_attempt_id=parent_attempt_id,
            )

        self._stage_c_topology_consumer = _consume_stage_c

        def _parent_attempt(request: NativePatchPlanRequest):
            session = self.decompilation_lifecycle.current_session(
                request.materialization.function_ea
            )
            if session is None or session.preanalysis_attempt_id is None:
                raise RuntimeError("native request has no active preanalysis attempt")
            return session.preanalysis_attempt_id

        def _build(
            request: NativePatchPlanRequest,
            authorizing_attempt_id,
        ) -> PreparedNativePatchRequest:
            plan_request = IndirectLabelPlanRequest(
                function_ea=request.materialization.function_ea,
                label_start=request.materialization.label_start,
                label_end=request.materialization.label_end,
                table_address=request.materialization.table_address,
                table_count=request.materialization.table_count,
                target_eas=request.materialization.target_eas,
                dispatch_jump_ea=request.dispatch_jump_ea,
                switch_start_ea=request.switch_start_ea,
                install_switch_info=request.install_switch_info,
                state_base=request.state_base,
                state_var_stkoff=request.state_var_stkoff,
            )
            plan = build_indirect_label_metadata_plan(
                plan_request,
                authorizing_attempt_id=authorizing_attempt_id,
            )

            def _observe() -> IndirectLabelMaterializationResult:
                import ida_funcs

                func = ida_funcs.get_func(request.materialization.function_ea)
                count = sum(
                    1
                    for target_ea in request.materialization.target_eas
                    if func is not None
                    and (owner := ida_funcs.get_func(target_ea)) is not None
                    and int(owner.start_ea) == int(func.start_ea)
                )
                return IndirectLabelMaterializationResult(
                    function_ea=request.materialization.function_ea,
                    table_address=request.materialization.table_address,
                    table_count=request.materialization.table_count,
                    label_start=request.materialization.label_start,
                    label_end=request.materialization.label_end,
                    target_count=len(request.materialization.target_eas),
                    materialized_target_count=count,
                    dispatch_jump_ea=request.dispatch_jump_ea,
                    jump_xref_count=sum(
                        action.kind.value == "update_xref"
                        for action in plan.operations[0].metadata_actions
                    ),
                    switch_info_installed=request.install_switch_info,
                    appended_tail=any(
                        action.kind.value == "function_tail_chunk"
                        for action in plan.operations[0].metadata_actions
                    ),
                    success=count == len(request.materialization.target_eas),
                    reason=(
                        "materialized"
                        if count == len(request.materialization.target_eas)
                        else "targets_still_missing"
                    ),
                )

            return PreparedNativePatchRequest(plan=plan, observe_result=_observe)

        set_indirect_materialization_default_executor(
            ManagerOwnedNativePatchRequestExecutor(
                gateway=gateway,
                user_enabled=lambda request: native_patch_function_is_authorized(
                    globally_available=bool(
                        self.config.get("native_patch_enabled", False)
                    ),
                    function_tags=self.get_function_tags(
                        request.materialization.function_ea
                    ),
                ),
                execution_journal=self._native_patch_execution_journal,
                parent_attempt_for_request=_parent_attempt,
                build_plan=_build,
            )
        )

        @contextlib.contextmanager
        def _dead_edge_parent_scope(function_ea: int):
            session = self.decompilation_lifecycle.current_session(function_ea)
            created = False
            if session is None or session.preanalysis_attempt_id is None:
                session, created = self.decompilation_lifecycle.ensure_hexrays_session(
                    function_ea=int(function_ea),
                    database_identity=self._database_identity,
                )
            if session.preanalysis_attempt_id is None:
                raise RuntimeError("native semantic pass has no preanalysis parent")
            try:
                yield session.preanalysis_attempt_id
            finally:
                if created:
                    self.decompilation_lifecycle.finish(session.native_key)

        def _discover_dead_edges(function_ea: int):
            session = self.decompilation_lifecycle.current_session(function_ea)
            if session is None:
                session, _created = self.decompilation_lifecycle.ensure_hexrays_session(
                    function_ea=int(function_ea),
                    database_identity=self._database_identity,
                )
            self.decompilation_lifecycle.begin_native_preanalysis(session)
            try:
                with suppress_d810_optimization():
                    return find_dead_edges_for_function(int(function_ea))
            finally:
                self.decompilation_lifecycle.finish_native_preanalysis(session)

        self._dead_edge_normalizer = ManagerOwnedDeadEdgeNormalizer(
            gateway=gateway,
            user_enabled=lambda function_ea: native_patch_function_is_authorized(
                globally_available=bool(self.config.get("native_patch_enabled", False)),
                function_tags=self.get_function_tags(function_ea),
            ),
            execution_journal=self._native_patch_execution_journal,
            parent_attempt_scope_for_function=_dead_edge_parent_scope,
            discover_candidates=_discover_dead_edges,
            build_plan=lambda function_ea, candidates, attempt_id: (
                build_dead_edge_semantic_plan(
                    function_ea,
                    candidates,
                    authorizing_attempt_id=attempt_id,
                )
            ),
            apply_plan=lambda plan: authorize_and_apply(
                NativeNormalizationRequest(plan=plan, user_enabled=True),
                gateway=gateway,
            ),
        )

    def _get_execution_metadata(
        self, function_ea: int
    ) -> FunctionExecutionMetadata | None:
        return self.function_storage_runtime.get_execution_metadata(function_ea)

    def get_function_tags(self, function_addr: int) -> set[str]:
        return self.function_storage_runtime.get_function_tags(function_addr)

    def set_function_tags(
        self,
        *,
        function_addr: int,
        tags: typing.Optional[typing.Set[str]] = None,
    ) -> None:
        self.function_storage_runtime.set_function_tags(
            function_addr=function_addr,
            tags=tags,
        )

    def is_native_patch_opted_in(self, function_addr: int) -> bool:
        """Read the persisted explicit consent for one native mutation target."""
        from d810.manager.native_writer_migration import (
            NATIVE_PATCH_FUNCTION_OPT_IN_TAG,
        )

        return NATIVE_PATCH_FUNCTION_OPT_IN_TAG in self.get_function_tags(function_addr)

    def set_native_patch_opted_in(self, *, function_addr: int, enabled: bool) -> None:
        """Persist explicit native-mutation consent for exactly one function."""
        from d810.manager.native_writer_migration import (
            NATIVE_PATCH_FUNCTION_OPT_IN_TAG,
        )

        tags = self.get_function_tags(function_addr)
        if enabled:
            tags.add(NATIVE_PATCH_FUNCTION_OPT_IN_TAG)
        else:
            tags.discard(NATIVE_PATCH_FUNCTION_OPT_IN_TAG)
        self.set_function_tags(function_addr=function_addr, tags=tags)

    def get_effective_execution_report(self, function_addr: int):
        """Return the same pass/stage decisions used by optimizer execution."""
        return self.execution_scope_service.explain(
            project_name=str(self.config.get("project_name", "")),
            idb_key=self._database_identity or str(self.config.get("idb_key", "")),
            func_ea=int(function_addr),
        )

    def _compile_execution_scope(self) -> None:
        registry = operational_config_v2_pass_registry()
        configs = pipeline_configs_from_project_config(self.config)
        implementations = {
            ExecutionPipeline.INSTRUCTION: tuple(self.instruction_optimizer_rules),
            ExecutionPipeline.FLOW: tuple(self.block_optimizer_rules),
            ExecutionPipeline.CTREE: tuple(self.ctree_optimizer_rules),
        }
        expanded: list[ExpandedExecutionStage] = []
        state_host_bound = False
        constant_schedule = self._constant_simplification_schedule
        for config in configs:
            for descriptor in registry.stages_for(config.pass_id):
                constant_stage = None
                if (
                    constant_schedule is not None
                    and str(config.pass_id) == str(CONSTANT_SIMPLIFICATION_PASS_ID)
                ):
                    constant_stage = constant_schedule.stage(str(descriptor.stage_id))
                    if not constant_stage.enabled:
                        continue
                candidates = implementations[descriptor.pipeline]
                implementation = next(
                    (
                        item
                        for item in candidates
                        if str(getattr(item, "name", item.__class__.__name__))
                        == descriptor.implementation_name
                    ),
                    None,
                )
                if (
                    implementation is None
                    and descriptor.implementation_name.lower()
                    in self._explicitly_suppressed_rule_names
                ):
                    continue
                if (
                    implementation is None
                    and not state_host_bound
                    and config.pass_id == "recover_dispatcher"
                ):
                    implementation = next(
                        (
                            item
                            for item in candidates
                            if str(getattr(item, "name", ""))
                            == STATE_MACHINE_RUNTIME_HOST
                        ),
                        None,
                    )
                    state_host_bound = implementation is not None
                if (
                    constant_stage is not None
                    and implementation is None
                    and (self.instruction_optimizer_rules or self.block_optimizer_rules)
                ):
                    raise PipelineConfigError(
                        f"{CONSTANT_SIMPLIFICATION_PASS_ID} stage "
                        f"{constant_stage.stage_id} implementation "
                        f"{constant_stage.implementation_name} is not registered"
                    )
                if constant_stage is not None:
                    supported_names = constant_simplification_provider_maturities(
                        constant_stage.supported_maturities
                    )
                    effective_names = constant_simplification_provider_maturities(
                        constant_stage.effective_maturities
                    )
                    supported = tuple(string_to_maturity(name) for name in supported_names)
                    effective = tuple(string_to_maturity(name) for name in effective_names)
                    if any(value is None for value in (*supported, *effective)):
                        raise PipelineConfigError(
                            f"{CONSTANT_SIMPLIFICATION_PASS_ID} stage "
                            f"{constant_stage.stage_id} has an unknown provider "
                            "maturity spelling"
                        )
                    if implementation is not None:
                        try:
                            validate_rule_maturity_contract(
                                implementation,
                                pass_id=CONSTANT_SIMPLIFICATION_PASS_ID,
                                stage_id=constant_stage.stage_id,
                                expected_supported=tuple(
                                    value for value in supported if value is not None
                                ),
                                expected_effective=tuple(
                                    value for value in effective if value is not None
                                ),
                            )
                        except MaturityContractError as exc:
                            raise PipelineConfigError(str(exc)) from exc
                    maturities = frozenset(
                        int(value) for value in effective if value is not None
                    )
                else:
                    maturities = frozenset(
                        int(value)
                        for value in getattr(implementation, "maturities", ())
                        if value is not None
                    )
                expanded.append(
                    ExpandedExecutionStage(
                        descriptor=descriptor,
                        implementation=implementation,
                        target=config.target,
                        maturities=maturities,
                    )
                )
        self.execution_scope_service.configure(expanded)

    def _start_timer(self):
        self.profiling.start_timer()

    def _stop_timer(self, report: bool = True):
        self.profiling.stop_timer(report=report)

    @staticmethod
    def _telemetry_lifecycle_key(
        event: DecompilationSessionEvent,
    ) -> tuple[str, object, str, int, int]:
        session_id = getattr(event, "session_id", None)
        session_value = getattr(session_id, "value", None)
        if isinstance(session_value, str) and session_value.strip():
            identity_kind = "session"
            identity_value: object = session_value
        else:
            # Older publishers may not carry a session_id.  Object identity is
            # deliberately fail-closed: distinct legacy events cannot merge
            # merely because their function/generation fields match.
            identity_kind = "legacy"
            identity_value = id(event)
        return (
            identity_kind,
            identity_value,
            str(event.database_identity),
            int(event.function_ea),
            int(event.top_level_epoch),
        )

    def _telemetry_lifecycle_state(
        self,
    ) -> tuple[
        list[tuple[str, object, str, int, int]],
        dict[tuple[str, object, str, int, int], int],
    ]:
        """Return lifecycle state, including compatibility instances made without init."""

        stack = getattr(self, "_telemetry_lifecycle_stack", None)
        if stack is None:
            stack = []
            self._telemetry_lifecycle_stack = stack
        depth = getattr(self, "_telemetry_lifecycle_depth", None)
        if depth is None:
            depth = {}
            self._telemetry_lifecycle_depth = depth
        return stack, depth

    def _safe_lifecycle_step(
        self,
        label: str,
        callback: typing.Callable[..., typing.Any],
        *args: typing.Any,
    ) -> bool:
        try:
            callback(*args)
            return True
        except BaseException as exc:
            cleanup_errors = getattr(self, "_cleanup_errors", None)
            if isinstance(cleanup_errors, list):
                cleanup_errors.append((label, exc))
            try:
                logger.exception("Decompilation lifecycle cleanup failed: %s", label)
            except BaseException:
                pass
            return False

    def _uninstall_native_preanalysis_handlers_if_installed(self) -> None:
        """Retry native-handler teardown until one uninstall succeeds."""
        if not getattr(self, "_native_preanalysis_handlers_installed", False):
            return
        if self._safe_lifecycle_step(
            "native.handlers.uninstall",
            self._uninstall_native_preanalysis_handlers,
        ):
            self._native_preanalysis_handlers_installed = False

    def _discard_telemetry_lifecycle(self) -> bool:
        stack, depth = self._telemetry_lifecycle_state()
        was_active = bool(stack)
        stack.clear()
        depth.clear()
        return was_active

    @staticmethod
    def _discard_native_perf_lifecycle() -> None:
        """Release native counter owners abandoned during manager teardown."""
        try:
            lifecycle_depth = int(native_perf.snapshot().get("lifecycle_depth", 0))
        except BaseException:
            return
        for _ in range(max(0, lifecycle_depth)):
            try:
                native_perf.end_session()
            except BaseException:
                return

    def _finish_telemetry_lifecycle(
        self,
        event: DecompilationSessionEvent | None,
    ) -> None:
        try:
            aggregate = _session_telemetry_summary()
        except BaseException:
            aggregate = {"error": "unavailable"}
        try:
            logger.debug("Decompilation session aggregate: %s", aggregate)
        except BaseException:
            # Telemetry must never prevent the lifecycle owner from releasing
            # the session or running its ordinary cleanup callbacks.
            pass
        first_error: BaseException | None = None
        for label, callback, args in (
            ("profiling.stop", self.stop_profiling, (event,)),
            ("optimization.report", self.stats.report, ()),
            ("block.perf_report", self.block_optimizer.report_perf_counters, ()),
            ("timer.stop", self._stop_timer, ()),
        ):
            try:
                callback(*args)
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
                try:
                    logger.exception(
                        "Decompilation lifecycle cleanup failed: %s", label
                    )
                except BaseException:
                    pass
        if first_error is not None:
            raise first_error.with_traceback(first_error.__traceback__)

    def _on_session_started(self, event: DecompilationSessionEvent) -> None:
        """Reset observer-only state after the coordinator has opened a session."""
        stack, depth = self._telemetry_lifecycle_state()
        key = self._telemetry_lifecycle_key(event)
        was_active = bool(stack)
        stack.append(key)
        depth[key] = depth.get(key, 0) + 1
        if not was_active:
            try:
                logger.info(
                    "[D810] Decompiling %s @ 0x%X",
                    self._function_display_name(int(event.function_ea)),
                    int(event.function_ea),
                )
            except BaseException:
                # User-facing telemetry must never prevent Hex-Rays lifecycle
                # ownership from opening or subsequently releasing a session.
                pass
        native_perf.begin_session(
            {
                "function_ea": int(event.function_ea),
                "database_identity": str(event.database_identity),
                "top_level_epoch": int(event.top_level_epoch),
                "session_id": str(getattr(event, "session_id", "")),
            }
        )
        if was_active:
            return
        native_perf.configure(get_settings().native_perf)
        if native_perf.enabled():
            self._ensure_native_perf_providers()
        reset_sccp_session()
        self.stats.reset()
        MOP_CONSTANT_CACHE.clear(reset_stats=True)
        MOP_TO_AST_CACHE.clear(reset_stats=True)
        Z3MopProver().clear_caches()
        self.instruction_optimizer.reset_cycle_detection()
        self.instruction_optimizer.reset_run_later_state()
        self.block_optimizer.reset_pass_counter()
        self.block_optimizer.reset_pipeline_tracker()
        self.block_optimizer.reset_perf_counters()
        self.start_profiling(event)
        self._start_timer()

    def _on_session_finished(self, event: DecompilationSessionEvent) -> None:
        """Report observer-only state after the coordinator has closed a session."""
        stack, depth = self._telemetry_lifecycle_state()
        key = self._telemetry_lifecycle_key(event)
        session_id = str(getattr(event, "session_id", ""))
        if not stack or stack[-1] != key:
            # Preserve strict LIFO ownership in both lifecycle registries.
            # native_perf records a mismatched close without mutating its
            # stack, while the aggregate owner remains available for the
            # eventual correct finish.
            native_perf.end_session(session_id)
            return

        stack.pop()
        remaining = depth.get(key, 1) - 1
        if remaining > 0:
            depth[key] = remaining
        else:
            depth.pop(key, None)
            self._emit_function_outcome(event)
        primary_error: BaseException | None = None
        receipt = None
        try:
            if not stack:
                depth.clear()
                self._finish_telemetry_lifecycle(event)
        except BaseException as exc:
            primary_error = exc
        finally:
            try:
                receipt = native_perf.end_session(session_id)
            except BaseException as close_error:
                if primary_error is None:
                    raise close_error
            else:
                if receipt is not None:
                    try:
                        logger.info("%s", receipt)
                    except BaseException as receipt_error:
                        if primary_error is None:
                            raise receipt_error
        if primary_error is not None:
            raise primary_error.with_traceback(primary_error.__traceback__)

    @staticmethod
    def _function_display_name(function_ea: int) -> str:
        try:
            import ida_name

            name = str(ida_name.get_name(int(function_ea)) or "").strip()
        except Exception:
            name = ""
        return name or f"sub_{int(function_ea):X}"

    def _emit_function_outcome(self, event: DecompilationSessionEvent) -> None:
        """Emit the sole terminal INFO story from structured session evidence."""
        function_ea = int(event.function_ea)
        try:
            hints = self.load_recon_hints(function_ea)
            reports = self.get_recon_outcome_reports(function_ea)
            journal = getattr(self, "_native_patch_execution_journal", None)
            attempts_for_session = getattr(journal, "attempts_for_session", None)
            attempts = (
                attempts_for_session(event.session_id)
                if callable(attempts_for_session)
                else ()
            )
            summary = build_function_outcome(
                function_ea=function_ea,
                function_name=self._function_display_name(function_ea),
                classification=(
                    None if hints is None else getattr(hints, "obfuscation_type", None)
                ),
                confidence=(
                    None if hints is None else getattr(hints, "confidence", None)
                ),
                reports=reports,
                attempts=attempts,
            )
            logger.info("%s", render_function_outcome(summary))
        except BaseException:
            # This observer must never interfere with Hex-Rays completion.
            logger.debug(
                "function outcome projection failed for func=0x%x",
                function_ea,
                exc_info=True,
            )

    @staticmethod
    def _ensure_native_perf_providers() -> None:
        """Select providers through the active backend dispatchers."""
        modules = (
            "d810.hexrays.ir.mop_utils",
            "d810.optimizers.microcode.instructions.pattern_matching.engine",
            "d810.hexrays.expr.ast",
        )
        for module_name in modules:
            try:
                module = importlib.import_module(module_name)
                register = getattr(module, "register_native_perf_provider", None)
                if register is not None:
                    register()
            except Exception as exc:
                native_perf.record_error(module_name, "load", exc)
                logger.debug(
                    "native performance provider unavailable: %s",
                    module_name,
                    exc_info=True,
                )
        if native_perf.enabled():
            native_perf.require_providers()

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
                maturity=f"maturity={maturity_to_name(int(event.maturity))}",
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
                maturity=f"maturity={maturity_to_name(int(event.maturity))}",
                reference_ledger_identities=event.reference_ledger_identities,
                comparisons=event.result.comparisons,
            )
        )

    @staticmethod
    def _on_mutation_committed(event) -> None:
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
                maturity=f"maturity={maturity_to_name(int(event.maturity))}",
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
                maturity=f"maturity={maturity_to_name(int(event.maturity))}",
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

        from d810.manager.rhad_generated_checksum import (
            observe_rhad_generated_reference_calls,
            observe_rhad_generated_reference_locopt,
            observe_rhad_generated_reference_preopt,
            publish_rhad_generated_reference_batch,
        )

        self.event_emitter.on(
            DecompilationEvent.HEXRAYS_GENERATED_READY,
            publish_rhad_generated_reference_batch,
        )

        from d810.hexrays.preanalysis.flowchart_preanalysis import (
            run_flowchart_preanalysis_handlers,
        )

        # Computed-goto materialization is a profile-specific compatibility
        # path.  Installing it for every project steals ordinary ``m_ijmp``
        # candidates from the selected IndirectBranchResolver before that
        # rule reaches LOCOPT.
        self._sync_native_preanalysis_handlers()
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
        self.event_emitter.on(
            DecompilationEvent.HEXRAYS_PREOPT_READY,
            observe_rhad_generated_reference_preopt,
        )

        from d810.hexrays.preanalysis.locopt_preanalysis import (
            run_locopt_preanalysis_handlers,
        )

        self.event_emitter.on(
            DecompilationEvent.HEXRAYS_LOCOPT_READY,
            run_locopt_preanalysis_handlers,
        )
        self.event_emitter.on(
            DecompilationEvent.HEXRAYS_LOCOPT_READY,
            observe_rhad_generated_reference_locopt,
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
            DecompilationEvent.HEXRAYS_CALLS_DONE,
            observe_rhad_generated_reference_calls,
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
            self._ensure_post_d810_runtime().observe_global_const_types,
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

    @staticmethod
    def _install_native_preanalysis_handlers() -> None:
        """Install manager-owned consumers of staged native evidence."""
        from d810.optimizers.microcode.flow.jumps.computed_goto_resolver import (
            install,
        )

        install()

    @staticmethod
    def _uninstall_native_preanalysis_handlers() -> None:
        """Remove manager-owned native-preanalysis seam handlers."""
        from d810.optimizers.microcode.flow.jumps.computed_goto_resolver import (
            uninstall,
        )

        uninstall()

    def _native_preanalysis_handlers_required(self) -> bool:
        """Return whether the active project can stage a generated restart."""
        return bool(
            self.config.get("legacy_direct_indirect_materialization", False)
            or self.config.get("config_v2_native_state_machine_active", False)
        )

    def _sync_native_preanalysis_handlers(self) -> None:
        """Keep the generated-restart consumer aligned with active config."""
        required = self._native_preanalysis_handlers_required()
        if required == self._native_preanalysis_handlers_installed:
            return
        if required:
            self._install_native_preanalysis_handlers()
        else:
            self._uninstall_native_preanalysis_handlers()
        self._native_preanalysis_handlers_installed = required

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
        if self.started:
            self._replace_started_instruction_rules(self.instruction_optimizer_rules)

    def configure_preparation_scripts(
        self,
        scripts,
        *,
        global_const_persistence_enabled: bool = False,
        constant_preparation_options: ConstantPreparationOptions | None = None,
    ) -> None:
        self._preparation_scripts = tuple(scripts)
        if constant_preparation_options is None:
            constant_preparation_options = (
                self._constant_simplification_schedule.preparation
                if self._constant_simplification_schedule is not None
                else ConstantPreparationOptions(
                    enabled=bool(global_const_persistence_enabled)
                )
            )
        if not isinstance(constant_preparation_options, ConstantPreparationOptions):
            raise TypeError(
                "constant_preparation_options must be ConstantPreparationOptions"
            )
        self._constant_preparation_options = constant_preparation_options
        self._global_const_persistence_enabled = bool(
            constant_preparation_options.enabled
        )
        controller = getattr(self, "pre_hex_preparation", None)
        if controller is not None:
            controller.configure_preparation_options(constant_preparation_options)
        runtime = getattr(self, "_post_d810_runtime", None)
        observer = getattr(runtime, "global_const_observer", None)
        if observer is not None:
            observer.configure(constant_preparation_options)

    def configure_constant_simplification_schedule(
        self,
        schedule: CompiledConstantSimplificationSchedule | None,
    ) -> None:
        """Install the immutable constant-stage schedule for live scoping."""

        self._constant_simplification_schedule = schedule
        preparation_options = (
            schedule.preparation
            if schedule is not None
            else ConstantPreparationOptions()
        )
        self._constant_preparation_options = preparation_options
        self._global_const_persistence_enabled = bool(preparation_options.enabled)
        controller = getattr(self, "pre_hex_preparation", None)
        if controller is not None:
            controller.configure_preparation_options(preparation_options)
        runtime = getattr(self, "_post_d810_runtime", None)
        observer = getattr(runtime, "global_const_observer", None)
        if observer is not None:
            observer.configure(preparation_options)

    def configure_block_optimizer(self, rules, **kwargs):
        self.block_optimizer_rules = list(rules)
        self.block_optimizer_config = kwargs
        if self.started:
            self._replace_started_block_rules(self.block_optimizer_rules)

    def _replace_started_instruction_rules(self, rules) -> None:
        """Replace the rules owned by the already-installed instruction hook.

        ``D810State`` keeps the portable project selection and the manager's
        live hook collections in separate layers.  A project switch must update
        both layers; otherwise the execution scope can name a newly enabled
        implementation that the hook never registered.  Older adapter objects
        do not expose a public replacement method, so the compatibility path
        clears their registration stores before adding the candidate set.
        """

        optimizer = getattr(self, "instruction_optimizer", None)
        if optimizer is None:
            return
        replace_rules = getattr(optimizer, "replace_rules", None)
        if callable(replace_rules):
            replace_rules(rules)
            optimizer._active_optimizers = []
            optimizer._active_instruction_rule_names_by_maturity.clear()
            optimizer._execution_scope_func_ea = -1
            invalidate_cache = getattr(
                optimizer, "_invalidate_residual_admission_cache", None
            )
            if callable(invalidate_cache):
                invalidate_cache()
            for child in (
                list(getattr(optimizer, "instruction_optimizers", ()) or ())
                + [getattr(optimizer, "analyzer", None)]
            ):
                invalidate = getattr(child, "invalidate", None)
                if callable(invalidate):
                    invalidate()
            return

        children = list(getattr(optimizer, "instruction_optimizers", ()))
        analyzer = getattr(optimizer, "analyzer", None)
        if analyzer is not None:
            children.append(analyzer)
        for child in children:
            collection = getattr(child, "rules", None)
            if collection is not None:
                clear = getattr(collection, "clear", None)
                if callable(clear):
                    clear()
                elif hasattr(collection, "_rules"):
                    collection._rules.clear()
            if hasattr(child, "pattern_storage"):
                child.pattern_storage = type(child.pattern_storage)(depth=1)
            if hasattr(child, "_indexed_storage"):
                child._indexed_storage = type(child._indexed_storage)()
            structural_rules = getattr(child, "_structural_rules_by_root_opcode", None)
            if structural_rules is not None:
                structural_rules.clear()
            allowed_opcodes = getattr(child, "_allowed_root_opcodes", None)
            if allowed_opcodes is not None:
                allowed_opcodes.clear()
            if hasattr(child, "_has_patternless_rule"):
                child._has_patternless_rule = False
            if hasattr(child, "_compiled_view"):
                child._compiled_view = None
            if hasattr(child, "_generation"):
                child._generation += 1
        optimizer._active_optimizers = []
        optimizer._active_instruction_rule_names_by_maturity.clear()
        optimizer._execution_scope_func_ea = -1
        invalidate_cache = getattr(optimizer, "_invalidate_residual_admission_cache", None)
        if callable(invalidate_cache):
            invalidate_cache()
        add_rule = getattr(optimizer, "add_rule", None)
        if callable(add_rule):
            for rule in rules:
                add_rule(rule)

    def _replace_started_block_rules(self, rules) -> None:
        """Replace the rules owned by the already-installed block hook."""

        optimizer = getattr(self, "block_optimizer", None)
        if optimizer is None:
            return
        replace_rules = getattr(optimizer, "replace_rules", None)
        if callable(replace_rules):
            replace_rules(rules)
            invalidate_context = getattr(optimizer, "_invalidate_flow_context", None)
            if callable(invalidate_context):
                invalidate_context("project rule collection replaced")
            reset_pipeline = getattr(optimizer, "reset_pipeline_tracker", None)
            if callable(reset_pipeline):
                reset_pipeline()
            return
        optimizer.cfg_rules = list(rules)
        configure_scheduler = getattr(optimizer, "_configure_rule_scheduler", None)
        configure_project = getattr(optimizer, "_configure_rule_project_config", None)
        for rule in optimizer.cfg_rules:
            if callable(configure_scheduler):
                configure_scheduler(rule)
            if callable(configure_project):
                configure_project(rule)
        invalidate_context = getattr(optimizer, "_invalidate_flow_context", None)
        if callable(invalidate_context):
            invalidate_context("project rule collection replaced")
        reset_pipeline = getattr(optimizer, "reset_pipeline_tracker", None)
        if callable(reset_pipeline):
            reset_pipeline()

    def configure_ctree_optimizer(self, rules, **kwargs):
        self.ctree_optimizer_rules = list(rules)
        self.ctree_optimizer_config = kwargs

    def stop(self, *, full_cleanup: bool = False):
        cleanup_errors: list[tuple[str, BaseException]] = []
        if full_cleanup:
            self._cleanup_errors = cleanup_errors
        if not self._started and not full_cleanup:
            telemetry_active = self._discard_telemetry_lifecycle()
            if telemetry_active:
                self._safe_lifecycle_step(
                    "profiling.stop",
                    self.stop_profiling,
                    None,
                )
                self._safe_lifecycle_step(
                    "timer.stop",
                    self._stop_timer,
                    False,
                )
                self._discard_native_perf_lifecycle()
            self._uninstall_native_preanalysis_handlers_if_installed()
            execution_scope_service = getattr(self, "execution_scope_service", None)
            detach = getattr(execution_scope_service, "detach", None)
            if callable(detach):
                self._safe_lifecycle_step("execution_scope.detach", detach)
            self.decompilation_lifecycle = None
            self._post_d810_runtime = None
            self._recon_phase = None
            self._recon_runtime = None
            self._recon_bundle = None
            self._flowgraph_ready_subscriber = None
            self._stage_c_topology_consumer = None
            preparation_journal = getattr(self, "_idb_preparation_journal", None)
            if preparation_journal is not None:
                self._safe_lifecycle_step(
                    "idb.preparation.close",
                    preparation_journal.close,
                )
                self._idb_preparation_journal = None
            self._idb_preparation_gateway = None
            self.pre_hex_preparation = None
            return None
        self._started = False
        telemetry_active = self._discard_telemetry_lifecycle()
        self._safe_lifecycle_step("profiling.stop", self.stop_profiling)
        if telemetry_active:
            self._safe_lifecycle_step("timer.stop", self._stop_timer, False)
            self._discard_native_perf_lifecycle()

        def _uninstall_frontend_normalization() -> None:
            from d810.manager.hexrays_frontend_normalization import (
                uninstall_live_frontend_normalization,
            )

            uninstall_live_frontend_normalization()

        def _clear_indirect_materialization_executor() -> None:
            from d810.hexrays.preanalysis.indirect_jump_labels import (
                set_indirect_materialization_default_executor,
            )

            set_indirect_materialization_default_executor(None)

        self._uninstall_native_preanalysis_handlers_if_installed()
        self._safe_lifecycle_step(
            "frontend.uninstall",
            _uninstall_frontend_normalization,
        )
        instruction_remove = getattr(
            getattr(self, "instruction_optimizer", None), "remove", None
        )
        if callable(instruction_remove):
            self._safe_lifecycle_step("instruction.remove", instruction_remove)
        block_remove = getattr(getattr(self, "block_optimizer", None), "remove", None)
        if callable(block_remove):
            self._safe_lifecycle_step("block.remove", block_remove)
        hook_unhook = getattr(getattr(self, "hx_decompiler_hook", None), "unhook", None)
        if callable(hook_unhook):
            self._safe_lifecycle_step("hooks.unhook", hook_unhook)
        analysis_runtime = getattr(self, "_analysis_runtime", None)
        flush_active_session = getattr(analysis_runtime, "flush_active_session", None)
        if callable(flush_active_session):
            self._safe_lifecycle_step(
                "analysis.flush_active_session",
                flush_active_session,
            )
        self._safe_lifecycle_step("writers.shutdown", shutdown_all_writers)
        execution_scope_service = getattr(self, "execution_scope_service", None)
        detach = getattr(execution_scope_service, "detach", None)
        if callable(detach):
            self._safe_lifecycle_step("execution_scope.detach", detach)
        event_clear = getattr(getattr(self, "event_emitter", None), "clear", None)
        if callable(event_clear):
            self._safe_lifecycle_step("event_emitter.clear", event_clear)
        self._safe_lifecycle_step(
            "executor.clear",
            _clear_indirect_materialization_executor,
        )
        native_patch_journal = getattr(self, "_native_patch_journal", None)
        if native_patch_journal is not None:
            self._safe_lifecycle_step(
                "native.patch.close",
                native_patch_journal.close,
            )
            self._native_patch_journal = None
        self._native_patch_gateway = None
        self._dead_edge_normalizer = None
        preparation_journal = self._idb_preparation_journal
        if preparation_journal is not None:
            self._safe_lifecycle_step(
                "idb.preparation.close",
                preparation_journal.close,
            )
            self._idb_preparation_journal = None
        self._idb_preparation_gateway = None
        self.pre_hex_preparation = None
        native_patch_execution_journal = getattr(
            self, "_native_patch_execution_journal", None
        )
        if native_patch_execution_journal is not None:
            self._safe_lifecycle_step(
                "native.execution.close",
                native_patch_execution_journal.close,
            )
            self._native_patch_execution_journal = None
        function_storage = getattr(self, "function_storage_runtime", None)
        function_storage_close = getattr(function_storage, "close", None)
        if callable(function_storage_close):
            self._safe_lifecycle_step("function_storage.close", function_storage_close)
        analysis_bundle = getattr(self, "_analysis_bundle", None)
        if analysis_bundle is not None:
            self._safe_lifecycle_step("analysis.bundle.close", analysis_bundle.close)
            self._analysis_bundle = None
        self._preanalysis_runtime = None
        self._analysis_runtime = None
        lifecycle = getattr(self, "decompilation_lifecycle", None)
        finish_hexrays_session = getattr(lifecycle, "finish_hexrays_session", None)
        if callable(finish_hexrays_session):
            self._safe_lifecycle_step(
                "decompilation.lifecycle.finish",
                finish_hexrays_session,
            )
        self.decompilation_lifecycle = None
        self._post_d810_runtime = None
        self._recon_phase = None
        self._recon_runtime = None
        self._recon_bundle = None
        self._flowgraph_ready_subscriber = None
        self._stage_c_topology_consumer = None
        self._database_identity = ""
        if full_cleanup:
            self._cleanup_errors = cleanup_errors
            errors = tuple(
                ManagerCleanupError(label, error)
                for label, error in cleanup_errors
            )
            del self._cleanup_errors
            return errors
        return None


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
