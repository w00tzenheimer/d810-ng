"""unflatten live entry point — the state-machine-CFF unflattener driven by the north-star call graph.

This is the runtime realization of the unflatten pseudocode: at the maturity hook it lifts the live
``mba`` to a portable ``FunctionSource``, routes facts through ``FunctionPassManager``, and routes
through the registered state-machine-CFF profiles — ``select_family`` polls the
``StateMachineCffFamily`` registry (``HodurFamily``=equality-chain, ``ApproovFamily``=
switch/indirect) and the claiming profile's ``pipeline_for`` drives the pass manager. The ONLY
live-mba touch points are the lifter + ``HexRaysMutationBackend`` (backends/hexrays).

PRODUCTION PATH (M2 cutover, llr-ibpi): the unflatten chain+spine pipeline is the SOLE CFF unflattener.
The hodur configs route ``StateMachineCffUnflattener``; full-fleet golden parity verified at 3032/0.
The legacy HCC fork is removed and unflatten runs unconditionally — there is no enable/disable flag.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping as ABCMapping

import ida_hexrays
from d810.analyses.control_flow.block_ownership_domain import analyze_block_ownership
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
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    MaterializedStateRoute,
    PortableMaterializedStateRoute,
    exact_materialized_handler_override_serial,
    instruction_backed_materialized_handler_owners,
    materialized_atomic_predicate_eas,
    materialized_state_register_candidates,
    materialized_dispatcher_router_native_ranges,
    mutation_authoritative_materialized_transfers,
    merge_materialized_handler_maps,
    missing_materialized_handler_targets,
    native_origin_blocks_in_ranges,
    override_materialized_handler_targets,
    plan_terminal_return_carrier_requests,
    plan_terminal_return_carrier_requests_from_native_routes,
    select_materialized_handler_owner_serial,
    unique_materialized_conditional_handler_entry_eas,
    unique_materialized_equality_target_eas,
    unique_materialized_state_register,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    BootstrapRouteBindingEvidence,
)
from d810.analyses.control_flow.frontend_normalization import (
    FrontendNormalizationEvidence,
)
from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
    canonical_terminal_state_targets,
)
from d810.analyses.control_flow.read_state_cfg import read_dag_from
from d810.analyses.control_flow.semantic_transition import (
    facts_from_validated_view,
    rebind_state_write_anchors,
)
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
from d810.analyses.control_flow.transition_builder import (
    _convert_condition_chain_to_result,
)
from d810.analyses.value_flow.model import FactConsumerRecord
from d810.backends.hexrays.evidence.condition_chain_analysis import (
    analyze_condition_chain_dispatcher,
)
from d810.backends.hexrays.evidence.residual_entry_bridge import (
    recognize_residual_entry_bridge,
)
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
from d810.capabilities.frontend_normalization import (
    FrontendNormalizationEvidenceCapability,
    FrontendNormalizationPlanCapability,
    FrontendNormalizationPreparedBodyCapability,
)
from d810.capabilities.resolver import CapabilitySet
from d810.capabilities.semantic_routes import (
    CanonicalSemanticCandidateEvidenceCapability,
    CanonicalSemanticEvidenceCapability,
    SemanticRouteReferenceOracleCapability,
)
from d810.capabilities.use_def_safety import UseDefSafetyCapability
from d810.capabilities.value_range import ValRangeCapability
from d810.core import logging
from d810.core.observability_models import (
    BlockSnapshot as _DiagBlockSnapshot,
    DagEdge as _DiagDagEdge,
    DagNode as _DiagDagNode,
    Modification as _DiagModification,
)
from d810.core.observability_preanalysis import (
    diagnostics_enabled as _preanalysis_diagnostics_enabled,
    observe_dag,
    observe_dag_local_facts,
    observe_fact_observation,
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
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.ir_maturity import ida_maturity_to_ir, ir_maturity_to_ida
from d810.ir.block_identity import (
    BlockHandleProvenance,
    NativeEaInterval,
    StableBlockIdentity,
)
from d810.ir.flowgraph import BlockKind
from d810.ir.maturity import IRMaturity
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.hexrays.observability import (
    diagnostics_enabled as _capture_diagnostics_enabled,
    request_capture_mba_snapshot,
)
from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.optimizers.microcode.flow.flattening.unflattening_rule_lifecycle import (
    ComposedUnflatteningRule,
)
from d810.optimizers.microcode.flow.flattening.semantic_evidence_adapter import (
    SessionCanonicalSemanticEvidenceProvider,
    SessionFrontendNormalizationEvidenceProvider,
)
from d810.optimizers.microcode.flow.jumps.computed_goto_resolver import (
    _build_conditional_handler_state_routes,
    _build_materialized_state_routes,
    _condition_chain_handler_transfers_from_recovery,
    recover_conditional_handler_bridge_transfers_from_mba,
    is_computed_goto_materialized,
)
from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
    ResolverSessionState,
)
from d810.hexrays.mutation.detached_handler_island import (
    find_materialized_handler_block_by_native_ea,
    find_unique_live_block_by_ea,
    find_unique_live_block_by_native_ea,
    imported_detached_snippet_conditional_boundary_evidence,
    imported_detached_snippet_direct_boundary_evidence,
    imported_detached_snippet_target_eas,
    stable_mba_identity,
)
from d810.passes.function_pass_manager import FunctionPassManager
from d810.passes.operational_config_v2 import operational_config_v2_pass_registry
from d810.passes.pipeline_config_parser import (
    PipelineV2Mode,
    pass_specs_from_project_config,
    pipeline_v2_mode_from_project_config,
)
from d810.passes.pipeline_v2_hook_bridge import STATE_MACHINE_NATIVE_PASS_IDS
from d810.passes.pipeline_shadow import compare_pipeline_v2_shadow
from d810.passes.unflatten.state_machine import LOWER_STATE_MACHINE_PLAN_METADATA
from d810.families.state_machine_cff.pipeline import (
    standard_state_machine_passes,
    state_machine_pass_registry,
)
from d810.passes.state_machine_spine import (
    semantic_evidence_state_machine_passes,
)
from d810.transforms.canonical_semantic_fragment import (
    CanonicalSemanticFragmentRejected,
)
from d810.transforms.minimal_unflatten_emit import (
    TERMINAL_CARRIER_CONVERGENCE_METADATA,
)
from d810.transforms.state_machine_unflatten import lower_to_direct_graph

logger = logging.getLogger("d810.unflat", logging.DEBUG)


def _unflatten_recovery_epoch_generation(
    *,
    current_evidence_generation: int,
    normalized_evidence_generation: int | None,
) -> int:
    """Select the evidence epoch actually represented by the live MBA.

    Recovery can discover and merge newer portable facts while operating on an
    MBA generated from an older normalization generation. Those newer facts do
    not describe a new live recovery epoch until normalization publication is
    postvalidated. Using the session's current generation here would let
    recovery reopen its own one-shot gate after every fact merge and repeatedly
    mutate stale microcode.
    """
    if normalized_evidence_generation is not None:
        return int(normalized_evidence_generation)
    return int(current_evidence_generation)


def _should_defer_unbound_materialized_preopt(
    state: ResolverSessionState | None,
) -> bool:
    """Keep structural recovery off an MBA built from stale resolver evidence."""
    return bool(
        isinstance(state, ResolverSessionState)
        and is_computed_goto_materialized(state)
        and state.native_preanalysis.needs_normalization_publication()
        and not _partial_canonical_composition_ready(state)
    )


def _request_materialized_recovery_generated_restart(
    state: ResolverSessionState | None,
) -> bool:
    """Bind evidence discovered by recovery into a fresh GENERATED MBA."""
    if (
        not isinstance(state, ResolverSessionState)
        or not is_computed_goto_materialized(state)
        or not state.native_preanalysis.needs_normalization_publication()
    ):
        return False
    if not state.native_preanalysis.request_generated_restart(
        evidence_family="dispatcher_recovery_evidence",
        reason=(
            "GLBOPT1 published portable dispatcher recovery evidence for "
            "fresh GENERATED/PREOPT binding"
        ),
    ):
        raise RuntimeError(
            "portable dispatcher recovery evidence did not acquire a "
            "generated restart"
        )
    return True


def _partial_canonical_composition_ready(
    state: ResolverSessionState | None,
) -> bool:
    """Require one receipted partial normalization before canonical composition."""
    if not isinstance(state, ResolverSessionState):
        return False
    lifecycle = state.native_preanalysis
    generation = int(lifecycle.evidence_generation)
    if (
        generation <= 0
        or lifecycle.normalization_published_postvalidated_generation == generation
        or lifecycle.normalization_work_item_publication_revision <= 0
        or lifecycle.normalization_last_published_work_item_id is None
        or not lifecycle.normalization_last_selected_obligation_ids
        or not lifecycle.normalization_last_remaining_obligation_ids
    ):
        return False
    candidate = lifecycle.canonical_semantic_candidate_evidence_for(state.native_key)
    frontend = lifecycle.frontend_normalization_evidence_for(state.native_key)
    return bool(
        isinstance(candidate, CanonicalSemanticEvidence)
        and isinstance(frontend, FrontendNormalizationEvidence)
        and candidate.native_key == state.native_key == frontend.native_key
        and int(candidate.generation) == generation
        and int(frontend.generation) == generation
    )


def _validated_materialized_target_eas(
    live_receipt_target_eas: object,
    resolver_state: object,
) -> frozenset[int]:
    """Join live import receipts with the portable PREOPT union inventory.

    A PREOPT union seed is an ownership fact published before MBA regeneration;
    it must remain eligible when CALLS rebuilds exact state-to-handler routing.
    Live detached-import receipts cover later adapter-local materialization, but
    cannot replace that portable inventory without dropping union-only handlers.
    """
    targets = {int(ea) for ea in live_receipt_target_eas if int(ea) > 0}
    preparation = getattr(
        getattr(resolver_state, "portable_evidence", None),
        "preopt_union_preparation",
        None,
    )
    if preparation is not None:
        targets.update(
            int(ea) for ea in getattr(preparation, "seed_eas", ()) if int(ea) > 0
        )
    return frozenset(targets)


def _postvalidated_canonical_terminal_state_targets(
    state: ResolverSessionState | None,
    *,
    state_var_reg: int | None,
) -> tuple[tuple[int, int], ...]:
    """Return terminal targets owned by the current normalized generation."""
    if not isinstance(state, ResolverSessionState) or state_var_reg is None:
        return ()
    evidence = state.native_preanalysis.canonical_semantic_evidence_for(
        state.native_key
    )
    return canonical_terminal_state_targets(
        evidence,
        state_variable=StorageIdentity(
            StorageIdentityKind.REGISTER,
            int(state_var_reg),
        ),
    )


def _materialized_identity_evidence_ready(
    analysis_seeds: ABCMapping[str, object],
) -> bool:
    """Return true only when every mutation-time identity is live and portable.

    Materialized native routes are recovered before their detached handlers are
    necessarily visible in the current MBA.  Rewriting that disposable graph
    with a partial state-to-block binding contaminates the graph later used for
    the controlled redo.  The mutation gate therefore requires the selector,
    dispatcher entry, at least one handler, and zero unresolved native targets
    in the *final* post-override/post-terminal inventory.  The preliminary
    portable binding misses remain diagnostic: exact imported-root ownership or
    a proven terminal route can legitimately discharge them later in the same
    evidence build.
    """
    return bool(
        analysis_seeds.get("materialized_state_var_reg") is not None
        and analysis_seeds.get("materialized_dispatcher_entry_serial") is not None
        and analysis_seeds.get("materialized_handler_by_state")
        and not analysis_seeds.get("unmapped_materialized_handler_targets")
    )


def _should_defer_incomplete_materialized_identity(
    *,
    materialized_computed_goto_profile: bool,
    materialized_evidence_ready: bool,
    uses_tigress_indirect_materialization: bool,
    canonical_composition_ready: bool = False,
) -> bool:
    """Keep partial imported identity read-only until the controlled redo.

    Tigress owns a separate direct, one-shot materialization contract and must
    not inherit the Rhad/native-evidence mutation gate.
    """
    return bool(
        materialized_computed_goto_profile
        and not materialized_evidence_ready
        and not uses_tigress_indirect_materialization
        and not canonical_composition_ready
    )


def _portable_materialized_dispatcher_region_identity(
    dispatcher_region_serials: frozenset[int],
    identity_index,
) -> StableBlockIdentity | None:
    """Project a complete current dispatcher region onto native identity."""
    identities = tuple(
        identity_index.identity_for_serial(int(serial))
        for serial in sorted(int(serial) for serial in dispatcher_region_serials)
    )
    if not identities or any(identity is None for identity in identities):
        return None
    return StableBlockIdentity.from_intervals(
        (
            interval
            for identity in identities
            if identity is not None
            for interval in identity.native_ranges.intervals
        ),
        native_key=identity_index.native_key,
    )


def _rebind_portable_materialized_dispatcher_region(
    identity: StableBlockIdentity | None,
    *,
    imported_native_eas_by_serial: ABCMapping[int, frozenset[int]],
    excluded_serials: frozenset[int] = frozenset(),
) -> frozenset[int]:
    """Expand one portable dispatcher region across imported block splits."""
    if identity is None:
        return frozenset()
    return frozenset(
        int(serial)
        for serial, native_eas in imported_native_eas_by_serial.items()
        if int(serial) not in excluded_serials
        and any(identity.native_ranges.contains(int(ea)) for ea in native_eas)
    )


def _portable_materialized_state_route_evidence(
    routes: tuple[MaterializedStateRoute, ...],
    identity_index,
    *,
    source_handler_regions_by_serial: (
        ABCMapping[int, StableBlockIdentity] | None
    ) = None,
) -> tuple[PortableMaterializedStateRoute, ...]:
    """Project mutation-time serial routes onto serial-free native identity."""
    evidence: list[PortableMaterializedStateRoute] = []
    source_handler_regions_by_serial = source_handler_regions_by_serial or {}

    def unique_enclosing_handler_region(
        source_identity: StableBlockIdentity,
    ) -> StableBlockIdentity | None:
        candidates = {
            region
            for region in source_handler_regions_by_serial.values()
            if all(
                region.native_ranges.contains(int(interval.start_ea))
                and region.native_ranges.contains(int(interval.end_ea) - 1)
                for interval in source_identity.native_ranges.intervals
            )
        }
        return next(iter(candidates)) if len(candidates) == 1 else None

    for route in routes:
        source_identity = identity_index.identity_for_serial(
            int(route.source_block_serial)
        )
        target_identity = identity_index.identity_for_serial(
            int(route.target_handler_serial)
        )
        source_handler_identity = None
        if route.source_handler_serial is not None:
            source_handler_identity = identity_index.identity_for_serial(
                int(route.source_handler_serial)
            )
            if source_handler_identity is None:
                continue
        if source_identity is None or (
            target_identity is None and route.target_native_ea is None
        ):
            continue
        source_handler_region_identity = (
            None
            if route.source_handler_serial is None
            else source_handler_regions_by_serial.get(int(route.source_handler_serial))
        )
        if source_handler_region_identity is None:
            source_handler_region_identity = unique_enclosing_handler_region(
                source_identity
            )
        evidence.append(
            PortableMaterializedStateRoute(
                source_identity=source_identity,
                state_constant=int(route.state_constant) & 0xFFFFFFFF,
                target_identity=target_identity,
                source_handler_identity=source_handler_identity,
                source_handler_region_identity=(source_handler_region_identity),
                handler_exit_proven=bool(route.handler_exit_proven),
                proof_kind=str(route.proof_kind),
                source_native_ea=(
                    None
                    if route.source_native_ea is None
                    else int(route.source_native_ea)
                ),
                target_native_ea=(
                    None
                    if route.target_native_ea is None
                    else int(route.target_native_ea)
                ),
            )
        )
    return tuple(dict.fromkeys(evidence))


def _rebind_portable_materialized_state_routes(
    evidence: tuple[PortableMaterializedStateRoute, ...],
    identity_index,
    *,
    handler_by_state: ABCMapping[int, int],
    flow_graph: object,
    imported_direct_boundary_evidence: tuple[object, ...] = (),
    imported_instruction_origins: ABCMapping[int, int] | None = None,
) -> tuple[MaterializedStateRoute, ...]:
    """Rebind portable routes only when live handler identity still agrees."""
    imported_instruction_origins = imported_instruction_origins or {}
    rejection_reasons: dict[
        str,
        list[tuple[int, int, int | None, int | None, str]],
    ] = {}

    def reject(
        reason: str,
        portable: PortableMaterializedStateRoute,
    ) -> None:
        intervals = portable.source_identity.native_ranges.intervals
        handler_intervals = (
            ()
            if portable.source_handler_region_identity is None
            else portable.source_handler_region_identity.native_ranges.intervals
        )
        rejection_reasons.setdefault(reason, []).append(
            (
                int(portable.state_constant) & 0xFFFFFFFF,
                int(intervals[0].start_ea) if intervals else 0,
                (
                    None
                    if portable.target_native_ea is None
                    else int(portable.target_native_ea)
                ),
                (None if not handler_intervals else int(handler_intervals[0].start_ea)),
                str(portable.proof_kind),
            )
        )

    def receipt_source_identity(
        portable: PortableMaterializedStateRoute,
    ) -> tuple[StableBlockIdentity | None, bool]:
        region = portable.source_handler_region_identity

        def target_matches(port: object) -> bool:
            target_ea = getattr(port, "target_ea", None)
            if target_ea is None:
                return region is not None
            target_ea = int(target_ea)
            if portable.target_native_ea is not None:
                return target_ea == int(portable.target_native_ea)
            return bool(
                portable.target_identity is not None
                and portable.target_identity.native_ranges.contains(target_ea)
            )

        exact: set[StableBlockIdentity] = set()
        regional: set[StableBlockIdentity] = set()
        for applied in imported_direct_boundary_evidence:
            port = getattr(applied, "port", None)
            if (
                port is None
                or getattr(port, "state_constant", None) is None
                or (
                    int(port.state_constant) & 0xFFFFFFFF
                    != int(portable.state_constant) & 0xFFFFFFFF
                )
                or not target_matches(port)
            ):
                continue
            source_eas = tuple(
                int(ea)
                for ea in (
                    getattr(port, "source_block_ea", 0),
                    getattr(port, "source_instruction_ea", 0),
                    getattr(port, "endpoint_block_ea", 0),
                )
                if int(ea) > 0
            )
            if region is not None and not any(
                region.native_ranges.contains(ea) for ea in source_eas
            ):
                continue
            endpoint_native_eas = tuple(
                dict.fromkeys(
                    int(imported_instruction_origins.get(int(anchor), int(anchor)))
                    for anchor in getattr(applied, "endpoint_anchor_eas", ())
                    if int(anchor) > 0
                )
            )
            if not endpoint_native_eas:
                continue
            identity = StableBlockIdentity.from_intervals(
                (NativeEaInterval(ea, ea + 1) for ea in endpoint_native_eas),
                native_key=portable.source_identity.native_key,
            )
            regional.add(identity)
            if any(
                portable.source_identity.native_ranges.contains(ea) for ea in source_eas
            ):
                exact.add(identity)
        candidates = exact or regional
        if len(candidates) == 1:
            return next(iter(candidates)), True
        return None, bool(candidates)

    routes: list[MaterializedStateRoute] = []
    for portable in evidence:
        receipt_identity, receipt_candidates = receipt_source_identity(portable)
        source = (
            None
            if receipt_identity is None
            else identity_index.rebind_imported_identity(receipt_identity).block
        )
        if (
            source is None
            and portable.handler_exit_proven
            and portable.source_handler_region_identity is not None
        ):
            # A replay-proven handler exit is a region-boundary fact.  The
            # mutation-time split identity can still rebind uniquely after a
            # rebuild, but to an interior block that no longer owns the exit.
            # Prefer the last surviving native anchor in the owned handler
            # region; an exact applied boundary receipt remains stronger.
            source = identity_index.rebind_region_exit(
                portable.source_handler_region_identity
            ).block
        if source is None:
            source = identity_index.rebind_identity(portable.source_identity).block
        if source is None and portable.source_handler_region_identity is not None:
            source = identity_index.rebind_region_exit(
                portable.source_handler_region_identity
            ).block
        if source is None and receipt_candidates:
            reject("ambiguous_receipt_source", portable)
            continue
        state = int(portable.state_constant) & 0xFFFFFFFF
        expected_target = handler_by_state.get(state)
        rebound_target = (
            None
            if portable.target_identity is None
            else identity_index.rebind_identity(portable.target_identity).block
        )
        if portable.proof_kind == "terminal_state_route":
            if rebound_target is not None:
                rebound_target_block = flow_graph.get_block(int(rebound_target.serial))
                if (
                    rebound_target_block is not None
                    and getattr(rebound_target_block, "kind", None)
                    is BlockKind.EXTERNAL
                ):
                    stop_serials = tuple(
                        int(block.serial)
                        for block in getattr(flow_graph, "blocks", {}).values()
                        if block.kind is BlockKind.STOP
                    )
                    target_serial = stop_serials[0] if len(stop_serials) == 1 else None
                else:
                    target_serial = int(rebound_target.serial)
            elif portable.target_native_ea is not None:
                stop_serials = tuple(
                    int(block.serial)
                    for block in getattr(flow_graph, "blocks", {}).values()
                    if block.kind is BlockKind.STOP
                )
                target_serial = stop_serials[0] if len(stop_serials) == 1 else None
            else:
                target_serial = None
        else:
            target_serial = (
                int(expected_target)
                if expected_target is not None
                else (None if rebound_target is None else int(rebound_target.serial))
            )
        source_handler = None
        if portable.source_handler_region_identity is not None:
            # Handler ownership is defined by the region entry, not by the
            # particular split block that happened to carry the old replay
            # object.  Across LOCOPT/CALLS that split can survive as a unique
            # but interior identity and misattribute the route to a sibling.
            source_handler = identity_index.rebind_region_entry(
                portable.source_handler_region_identity
            ).block
        if source_handler is None and portable.source_handler_identity is not None:
            source_handler = identity_index.rebind_identity(
                portable.source_handler_identity
            ).block
        if portable.source_handler_identity is not None and source_handler is None:
            reject("missing_source_handler", portable)
            continue
        if source is None or target_serial is None:
            reject(
                "missing_source" if source is None else "missing_target",
                portable,
            )
            continue
        if (
            flow_graph.get_block(int(source.serial)) is None
            or flow_graph.get_block(target_serial) is None
        ):
            reject("missing_flow_graph_block", portable)
            continue
        source_handle = identity_index.handle_for_serial(int(source.serial))
        source_is_imported = bool(
            source_handle is not None
            and source_handle.provenance is BlockHandleProvenance.IMPORTED_NATIVE
        )
        routes.append(
            MaterializedStateRoute(
                source_block_serial=int(source.serial),
                state_constant=state,
                target_handler_serial=target_serial,
                source_handler_serial=(
                    None if source_handler is None else int(source_handler.serial)
                ),
                handler_exit_proven=bool(portable.handler_exit_proven),
                proof_kind=str(portable.proof_kind),
                source_native_ea=(
                    int(portable.source_native_ea)
                    if portable.source_native_ea is not None
                    else (
                        portable.source_identity.native_ranges.intervals[0].start_ea
                        if source_is_imported
                        and portable.source_identity.native_ranges.intervals
                        else None
                    )
                ),
                target_native_ea=portable.target_native_ea,
            )
        )
    result = tuple(
        sorted(
            set(routes),
            key=lambda route: (
                int(route.source_block_serial),
                int(route.state_constant),
                int(route.target_handler_serial),
            ),
        )
    )
    if rejection_reasons:
        logger.info(
            "portable materialized state-route rebind rejections: %s",
            {
                reason: {
                    "count": len(rows),
                    "samples": [
                        (
                            "0x%08X" % state,
                            "0x%X" % source_ea,
                            None if target_ea is None else "0x%X" % target_ea,
                            (None if handler_ea is None else "0x%X" % handler_ea),
                            proof_kind,
                        )
                        for state, source_ea, target_ea, handler_ea, proof_kind in rows
                    ],
                }
                for reason, rows in sorted(rejection_reasons.items())
            },
        )
    return result


def _resolver_native_state_register(
    prelim: object | None,
    transfers: tuple[object, ...],
    *,
    materialized_computed_goto_profile: bool,
) -> int | None:
    """Join a stack-homed live state to one portable native selector.

    ``recover_dispatcher`` owns the current MBA identity and therefore remains
    stack-based when Hex-Rays homes the state variable.  Resolver transfers
    describe native replay and retain the original selector register.  The two
    identities may be joined only for the materialized computed-goto profile.
    With a live recovery model, that additionally requires a proven stack slot
    and one unanimous native selector.  A regenerated imported graph may no
    longer contain the legacy dispatcher at all; in that case, accept only the
    one register named by exact state-bearing materialized routes.  The live
    recovery object is never rewritten or relabeled as register-resident.
    """
    live_register = getattr(prelim, "state_var_reg", None)
    if live_register is not None:
        return int(live_register)
    if not materialized_computed_goto_profile:
        return None
    live_stack = getattr(prelim, "state_var_stkoff", None)
    if live_stack is not None:
        candidates = {
            int(register)
            for transfer in transfers
            for register in (getattr(transfer, "selector_state_var_reg", None),)
            if register is not None
        }
        return next(iter(candidates)) if len(candidates) == 1 else None
    if prelim is None or getattr(prelim, "dispatcher_block_serial", None) is None:
        return unique_materialized_state_register(transfers)
    return None


def _bind_materialized_handler_targets(
    flow_graph: object,
    equality_target_eas: ABCMapping[int, int],
    *,
    live_block_for_ea,
    entry_route_source_eas: ABCMapping[int, int] | None = None,
    entry_route_region_identities: ABCMapping[int, StableBlockIdentity] | None = None,
    live_block_for_region_identity=None,
    live_block_for_applied_exit_receipt=None,
) -> tuple[dict[int, int], dict[int, int], tuple[tuple[int, int], ...]]:
    """Rebind serial-free state routes to blocks in the current MBA.

    Resolver evidence carries native handler EAs across maturities.  Block
    serials do not cross that boundary: resolve every EA against the live MBA,
    validate that its lifted block owns instructions, and return only an
    ephemeral state-to-serial view for the current pass.  Multiple native entry
    EAs may legitimately land in one split/merged block; in that case the block
    remains a handler target but has no unique entry anchor.
    """
    handler_targets: dict[int, int] = {}
    handler_entry_eas: dict[int, int] = {}
    ambiguous_entry_serials: set[int] = set()
    missing: list[tuple[int, int]] = []
    get_block = getattr(flow_graph, "get_block", None)
    for state_constant, target_ea in sorted(equality_target_eas.items()):
        state_constant = int(state_constant) & 0xFFFFFFFF
        target_ea = int(target_ea)
        live_block = live_block_for_ea(target_ea)
        if (
            live_block is None
            and entry_route_region_identities is not None
            and callable(live_block_for_region_identity)
        ):
            region_identity = entry_route_region_identities.get(state_constant)
            if region_identity is not None:
                live_block = live_block_for_region_identity(region_identity)
        if live_block is None and callable(live_block_for_applied_exit_receipt):
            live_block = live_block_for_applied_exit_receipt(target_ea)
        if live_block is None and entry_route_source_eas is not None:
            source_ea = entry_route_source_eas.get(state_constant)
            if source_ea is not None:
                live_block = live_block_for_ea(int(source_ea))
        target_serial = int(live_block.serial) if live_block is not None else None
        graph_block = (
            get_block(target_serial)
            if callable(get_block) and target_serial is not None
            else None
        )
        if graph_block is None or not getattr(graph_block, "insn_snapshots", ()):
            missing.append((state_constant, target_ea))
            continue
        handler_targets[state_constant] = target_serial
        if target_serial in ambiguous_entry_serials:
            continue
        existing_entry_ea = handler_entry_eas.get(target_serial)
        if existing_entry_ea is None:
            handler_entry_eas[target_serial] = target_ea
        elif int(existing_entry_ea) != target_ea:
            handler_entry_eas.pop(target_serial, None)
            ambiguous_entry_serials.add(target_serial)
    return handler_targets, handler_entry_eas, tuple(missing)


def _rebind_current_native_ea(current_identity_index, native_ea: int):
    """Resolve one native instruction through receipt-backed current identity."""
    if current_identity_index is None or int(native_ea) <= 0:
        return None
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(int(native_ea), int(native_ea) + 1),),
        native_key=current_identity_index.native_key,
    )
    return current_identity_index.rebind_identity(identity).block


def _rebind_current_instruction_owner(
    current_identity_index,
    imported_instruction_origins: ABCMapping[int, int],
    instruction_ea: int,
):
    """Resolve a current instruction through its receipted native origin."""
    native_ea = int(
        imported_instruction_origins.get(int(instruction_ea), int(instruction_ea))
    )
    return _rebind_current_native_ea(current_identity_index, native_ea)


def _instruction_backed_portable_handler_overrides(
    flow_graph: object,
    equality_target_eas: ABCMapping[int, int],
    portable_handler_targets: ABCMapping[int, int],
) -> dict[int, int]:
    """Keep current-MBA portable handler bindings through live-map recovery."""
    get_block = getattr(flow_graph, "get_block", None)
    if not callable(get_block):
        return {}
    return {
        int(state) & 0xFFFFFFFF: int(portable_handler_targets[int(state)])
        for state in equality_target_eas
        if int(state) in portable_handler_targets
        and (
            (block := get_block(int(portable_handler_targets[int(state)]))) is not None
        )
        and bool(getattr(block, "insn_snapshots", ()))
    }


def _unique_materialized_handler_entry_route_source_eas(
    transfers: tuple[object, ...],
    equality_target_eas: ABCMapping[int, int],
) -> dict[int, int]:
    """Project exact native entry routes to one source EA per handler state.

    LOCOPT may fold a short handler entry into the state-writing block that
    immediately precedes it, eliminating every instruction at the handler EA.
    ``static_handler_entry_route`` retains that native relation without
    persisting a block serial.  A source used for more than one state/target
    pair (notably the Rhad bootstrap) is navigation evidence, not an identity
    alias, and is rejected before selecting a unique source for each state.
    """
    expected_targets = {
        int(state) & 0xFFFFFFFF: int(target_ea)
        for state, target_ea in equality_target_eas.items()
    }
    routes_by_source: dict[int, set[tuple[int, int]]] = {}
    for transfer in transfers:
        if getattr(transfer, "resolver_kind", None) != "static_handler_entry_route":
            continue
        state = getattr(transfer, "selector_state_constant", None)
        target_eas = tuple(int(ea) for ea in getattr(transfer, "target_eas", ()))
        source_ea = int(getattr(transfer, "source_block_ea", 0) or 0)
        if state is None or len(target_eas) != 1 or source_ea <= 0:
            continue
        normalized_state = int(state) & 0xFFFFFFFF
        target_ea = target_eas[0]
        if (
            expected_targets.get(normalized_state) != target_ea
            or source_ea == target_ea
        ):
            continue
        routes_by_source.setdefault(source_ea, set()).add((normalized_state, target_ea))

    sources_by_state: dict[int, set[int]] = {}
    for source_ea, routes in routes_by_source.items():
        if len(routes) != 1:
            continue
        state, _target_ea = next(iter(routes))
        sources_by_state.setdefault(state, set()).add(source_ea)
    return {
        state: next(iter(source_eas))
        for state, source_eas in sorted(sources_by_state.items())
        if len(source_eas) == 1
    }


def _unique_materialized_handler_region_identities(
    transfers: tuple[object, ...],
    equality_target_eas: ABCMapping[int, int],
    *,
    native_key,
) -> dict[int, StableBlockIdentity]:
    """Project exact handler routes to one portable owned-region identity.

    The exact entry EA can be folded out of a regenerated MBA.  Resolver-owned
    native ranges retain the complete identity corridor, so a current imported
    block can be rebound by the first surviving origin anchor.  Conflicting or
    malformed range claims abstain instead of selecting by current serial.
    """
    expected_targets = {
        int(state) & 0xFFFFFFFF: int(target_ea)
        for state, target_ea in equality_target_eas.items()
    }
    identities_by_state: dict[int, set[StableBlockIdentity]] = {}
    for transfer in transfers:
        if getattr(transfer, "resolver_kind", None) != "static_handler_entry_route":
            continue
        state = getattr(transfer, "selector_state_constant", None)
        target_eas = tuple(int(ea) for ea in getattr(transfer, "target_eas", ()))
        ranges = tuple(getattr(transfer, "owned_native_ranges", ()))
        if state is None or len(target_eas) != 1 or not ranges:
            continue
        normalized_state = int(state) & 0xFFFFFFFF
        target_ea = target_eas[0]
        if expected_targets.get(normalized_state) != target_ea:
            continue
        try:
            identity = StableBlockIdentity.from_intervals(
                (
                    NativeEaInterval(int(start_ea), int(end_ea))
                    for start_ea, end_ea in ranges
                ),
                native_key=native_key,
            )
        except (TypeError, ValueError):
            continue
        if not identity.native_ranges.contains(target_ea):
            continue
        identities_by_state.setdefault(normalized_state, set()).add(identity)
    return {
        state: next(iter(identities))
        for state, identities in sorted(identities_by_state.items())
        if len(identities) == 1
    }


def _bind_materialized_dispatcher_identity(
    imported_native_eas_by_serial: ABCMapping[int, frozenset[int]],
    transfers: tuple[object, ...],
    *,
    handler_serials: frozenset[int],
    live_block_for_entry_ea=None,
) -> tuple[int | None, frozenset[int]]:
    """Rebind stable dispatcher EAs to one current-MBA entry and region."""
    entry_eas = {
        int(entry_ea)
        for transfer in transfers
        for entry_ea in (getattr(transfer, "dispatcher_entry_ea", None),)
        if entry_ea is not None and int(entry_ea) > 0
    }
    router_eas = {
        int(router_ea)
        for transfer in transfers
        for router_ea in getattr(transfer, "dispatcher_router_eas", ())
        if int(router_ea) > 0
    }
    if callable(live_block_for_entry_ea):
        entry_candidates = {
            int(block.serial)
            for entry_ea in entry_eas
            for block in (live_block_for_entry_ea(int(entry_ea)),)
            if block is not None
        }
    else:
        entry_candidates = {
            int(serial)
            for serial, native_eas in imported_native_eas_by_serial.items()
            if native_eas.intersection(entry_eas)
        }
    router_serials = frozenset(
        int(serial)
        for serial, native_eas in imported_native_eas_by_serial.items()
        if int(serial) not in handler_serials and native_eas.intersection(router_eas)
    )
    entry_serial = next(iter(entry_candidates)) if len(entry_candidates) == 1 else None
    return entry_serial, router_serials


def _bound_bootstrap_route_bindings(
    state: ResolverSessionState,
) -> tuple[BootstrapRouteBindingEvidence, ...]:
    """Read PREOPT's serial-free binding for the live MBA lineage."""
    return state.native_preanalysis.bound_bootstrap_route_bindings(state.native_key)


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
    #: ``mov #const`` condition-chain writes, which the concolic ``_discover`` cannot anchor at
    #: any maturity, so the extra stage helped nothing and only added cost/risk.)
    recovery_maturities = (IRMaturity.GLOBAL_ANALYZED,)

    def detect(self, graph, capabilities, context=None):
        """Claim every graph (truthy) -- the static poll already declined, so this is the
        deliberate reduced_product fallthrough. The pass manager re-runs ``detect`` and
        bails on ``None``; returning a non-None sentinel lets the spine run."""
        return self

    def pipeline_for(self, match, context):
        """Run the canonical five-pass spine -- ``RecoverDispatcher`` takes the
        reduced-product branch (recover_machine -> concolic) because the project config
        sets ``recovery_engine == "reduced_product"``."""
        return standard_state_machine_passes()


class _MaterializedComputedGotoContinuationFamily:
    """Compose a fully materialized computed-goto graph as one fragment.

    A first unflattening round can remove the static dispatcher shape before a
    regenerated MBA contains every imported handler.  Once the live identity
    index proves the dispatcher entry and every handler with no missing target,
    static family detection is no longer the authority: the portable evidence
    itself is the exact current-snapshot dispatcher contract.  Publication must
    remain atomic: late per-edge mutation can pass ``mba.verify()`` yet leave
    Hex-Rays unable to produce a cfunc for the regenerated imported graph.
    """

    name = "materialized_computed_goto_continuation"
    # The evidence epoch may become complete at CALLS for an intact indirect
    # profile or at GLBOPT1 after GENERATED imports and PREOPT rebind the full
    # handler/route closure.  Admission follows that typed evidence state; it
    # is not tied to one sample function or native address.
    recovery_maturities = (
        IRMaturity.CALL_MODELED,
        IRMaturity.GLOBAL_ANALYZED,
    )

    def detect(self, graph, capabilities, context=None):
        return self

    def pipeline_for(self, match, context):
        return semantic_evidence_state_machine_passes()


class _CanonicalComputedGotoCompositionFamily:
    """Publish a partial canonical evidence group as one atomic fragment."""

    name = "canonical_computed_goto_composition"
    recovery_maturities = (
        IRMaturity.CALL_MODELED,
        IRMaturity.GLOBAL_ANALYZED,
    )

    def detect(self, graph, capabilities, context=None):
        return self

    def pipeline_for(self, match, context):
        return semantic_evidence_state_machine_passes()


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
        self._project_config: dict[str, object] = {}
        self._last_pipeline_v2_mode: str | None = None
        self._last_config_v2_pass_ids: tuple[str, ...] = ()
        self._pass_scheduler = None
        self._pass_manager = FunctionPassManager()
        self._pass_manager_session_by_func: dict[int, tuple[int, int, int]] = {}

    def set_project_config(self, config: object | None) -> None:
        """Attach project-level config-v2 options without changing rule options."""
        self._project_config = dict(config) if isinstance(config, ABCMapping) else {}

    def set_pass_scheduler(self, scheduler: object | None) -> None:
        self._pass_scheduler = scheduler

    def reset_pass_manager_state(self) -> None:
        """Reset manager-owned pipeline facts/scheduler state for a fresh session."""
        self._pass_manager.reset_all()
        self._pass_manager_session_by_func.clear()
        self._unflat_round_count.clear()
        self._unflat_done_eas.clear()

    def _reset_pass_manager_if_new_session(
        self,
        mba: object,
        *,
        evidence_generation: int = 0,
        stable_preopt_epoch: bool = False,
        imported_identity_ready: bool = False,
    ) -> None:
        func_ea = int(getattr(mba, "entry_ea", 0) or 0)
        if func_ea == 0:
            return
        preopt_epoch_is_stable = bool(stable_preopt_epoch)
        # Before PREOPT binds portable evidence, an underlying mba_t change
        # identifies a fresh native decompilation and must reset manager-local
        # state.  Once PREOPT has bound either imported identities or a narrow
        # bootstrap route, our own structural mutations can relocate mba_t
        # repeatedly; the stable epoch is then the bound evidence generation,
        # not the disposable address.
        mba_session_identity = 0 if preopt_epoch_is_stable else stable_mba_identity(mba)
        preopt_epoch_phase = (
            2 if imported_identity_ready else (1 if preopt_epoch_is_stable else 0)
        )
        session_signature = (
            mba_session_identity,
            int(evidence_generation),
            preopt_epoch_phase,
        )
        if self._pass_manager_session_by_func.get(func_ea) == session_signature:
            return
        self._pass_manager.reset_func(func_ea)
        self._pass_manager_session_by_func[func_ea] = session_signature
        self._unflat_round_count = {
            key: rounds
            for key, rounds in self._unflat_round_count.items()
            if int(key[0]) != func_ea
        }
        self._unflat_done_eas.discard(func_ea)

    def _should_run_unflatten_round(
        self,
        func_ea: int,
        *,
        is_indirect: bool,
        maturity: int,
        one_shot: bool = False,
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
        if (is_indirect or one_shot) and rounds >= 1:
            return False
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

    def _report_recovery_gate_decision(
        self,
        mba: object,
        *,
        resolver_state: object | None,
        decision: str,
        reason: str,
        imported_identity_ready: bool | None,
        recovery_epoch_phase: int,
        rounds_before: int,
    ) -> None:
        """Persist the CALLS recovery authority decision in the diagnostic DB."""
        flow_context = getattr(self, "flow_context", None)
        report = getattr(flow_context, "report_fact_consumers", None)
        if not callable(report):
            return
        native_preanalysis = (
            resolver_state.native_preanalysis
            if isinstance(resolver_state, ResolverSessionState)
            else None
        )
        report(
            (
                FactConsumerRecord(
                    consumer="state_machine_cff_unflattener",
                    strategy="recovery_gate",
                    fact_id="resolver_session:indirect_dispatcher_materialized",
                    maturity=maturity_to_string(int(getattr(mba, "maturity", 0))),
                    decision=decision,
                    reason=reason,
                    payload={
                        "normalization_published_postvalidated_generation": (
                            None
                            if native_preanalysis is None
                            else native_preanalysis.normalization_published_postvalidated_generation
                        ),
                        "evidence_generation": (
                            0
                            if native_preanalysis is None
                            else int(native_preanalysis.evidence_generation)
                        ),
                        "imported_identity_ready": imported_identity_ready,
                        "indirect_dispatcher_materialized": bool(
                            isinstance(resolver_state, ResolverSessionState)
                            and resolver_state.indirect_dispatcher_materialized
                        ),
                        "recovery_epoch_phase": int(recovery_epoch_phase),
                        "resolver_session_present": isinstance(
                            resolver_state, ResolverSessionState
                        ),
                        "rounds_before": int(rounds_before),
                    },
                ),
            )
        )

    def _report_canonical_composition_rejection(
        self,
        mba: object,
        rejection: CanonicalSemanticFragmentRejected,
    ) -> None:
        """Persist one typed, stable-EA canonical planning obligation."""
        flow_context = getattr(self, "flow_context", None)
        report = getattr(flow_context, "report_fact_consumers", None)
        if not callable(report):
            return
        anchor_ea = (
            int(rejection.anchor_ea)
            if rejection.anchor_ea is not None
            else int(getattr(mba, "entry_ea", 0) or 0)
        )
        rejection_payload = dict(rejection.payload)
        raw_attempts = rejection_payload.pop("composition_attempts", ())
        attempts = (
            tuple(raw_attempts) if isinstance(raw_attempts, (tuple, list)) else ()
        )
        maturity = maturity_to_string(int(getattr(mba, "maturity", 0)))
        records: list[FactConsumerRecord] = []
        for attempt_index, raw_attempt in enumerate(attempts):
            if not isinstance(raw_attempt, ABCMapping):
                continue
            attempt = dict(raw_attempt)
            kind = str(attempt.get("kind", "")).strip()
            outcome = str(attempt.get("outcome", "")).strip()
            if not kind or outcome not in {"accepted", "rejected"}:
                continue
            route_proof_ids = attempt.get("route_proof_ids")
            boundary_anchor = attempt.get("boundary_anchor_ea")
            rejection_anchor = attempt.get("rejection_anchor_ea")
            if (
                isinstance(route_proof_ids, (tuple, list))
                and route_proof_ids
                and isinstance(route_proof_ids[0], str)
                and route_proof_ids[0]
            ):
                attempt_identity = route_proof_ids[0]
            elif isinstance(boundary_anchor, str) and boundary_anchor:
                attempt_identity = boundary_anchor
            elif isinstance(rejection_anchor, str) and rejection_anchor:
                attempt_identity = rejection_anchor
            else:
                attempt_identity = f"index-{attempt_index}"
            reason_code = attempt.get("reason_code")
            reason = (
                str(reason_code)
                if outcome == "rejected"
                and isinstance(reason_code, str)
                and reason_code
                else "composition_plan_available"
            )
            records.append(
                FactConsumerRecord(
                    consumer="state_machine_cff_unflattener",
                    strategy="canonical_semantic_composition_attempt",
                    fact_id=(
                        f"canonical_composition_attempt:{kind}:{attempt_identity}"
                    ),
                    maturity=maturity,
                    decision=outcome,
                    reason=reason,
                    payload={"attempt_index": attempt_index, **attempt},
                )
            )
        payload = {
            "anchor_ea": f"0x{anchor_ea:X}",
            "detail": str(rejection),
            **rejection_payload,
        }
        records.append(
            FactConsumerRecord(
                consumer="state_machine_cff_unflattener",
                strategy="canonical_semantic_composition",
                fact_id=f"canonical_route:0x{anchor_ea:X}",
                maturity=maturity,
                decision="declined",
                reason=rejection.reason_code,
                payload=payload,
            )
        )
        report(tuple(records))

    def _promote_contextual_plan_after_canonical_rejection(
        self,
        rejection: CanonicalSemanticFragmentRejected,
    ) -> bool:
        """Turn one exact unresolved imported boundary into newer evidence."""
        if (
            rejection.reason_code != "published_imported_boundary_topology_unresolved"
            or rejection.anchor_ea is None
        ):
            return False
        resolver_state = self.current_resolver_session_state()
        if not isinstance(resolver_state, ResolverSessionState):
            return False
        lifecycle = resolver_state.native_preanalysis
        if not lifecycle.promote_contextual_patch_plan_for_anchor(
            resolver_state.native_key,
            int(rejection.anchor_ea),
        ):
            return False
        if not lifecycle.request_generated_restart(
            evidence_family="contextual_patch_plans",
            reason=(
                "C3 promoted a contextual patch plan for native source "
                f"0x{int(rejection.anchor_ea):X}"
            ),
        ):
            raise RuntimeError(
                "promoted contextual patch plan did not acquire a generated restart"
            )
        return True

    def _report_canonical_pipeline_exception(
        self,
        mba: object,
        error: Exception,
    ) -> None:
        """Persist one unexpected canonical-pipeline failure without consuming it."""
        flow_context = getattr(self, "flow_context", None)
        report = getattr(flow_context, "report_fact_consumers", None)
        if not callable(report):
            return
        error_anchor_ea = getattr(error, "anchor_ea", None)
        anchor_ea = (
            int(error_anchor_ea)
            if error_anchor_ea is not None
            else int(getattr(mba, "entry_ea", 0) or 0)
        )
        error_type = type(error)
        structured_payload = getattr(error, "payload", None)
        if not isinstance(structured_payload, ABCMapping):
            structured_payload = {}
        reason_code = getattr(error, "reason_code", None)
        if not isinstance(reason_code, str) or not reason_code.strip():
            reason_code = "canonical_pipeline_exception"
        payload = dict(structured_payload)
        payload.update(
            {
                "anchor_ea": f"0x{anchor_ea:X}",
                "exception_detail": str(error),
                "exception_type": (
                    f"{error_type.__module__}.{error_type.__qualname__}"
                ),
            }
        )
        report(
            (
                FactConsumerRecord(
                    consumer="state_machine_cff_unflattener",
                    strategy="canonical_semantic_composition",
                    fact_id=f"canonical_pipeline:0x{anchor_ea:X}",
                    maturity=maturity_to_string(int(getattr(mba, "maturity", 0))),
                    decision="declined",
                    reason=reason_code,
                    payload=payload,
                ),
            )
        )

    def _run_pipeline_with_canonical_diagnostics(
        self,
        mba: object,
        *,
        canonical_composition_ready: bool,
        materialized_evidence_ready: bool = False,
        run_pipeline: Callable[[], object],
    ) -> bool:
        """Run the pipeline while preserving typed declines and unexpected failures."""
        diagnostics_expected = bool(
            canonical_composition_ready or materialized_evidence_ready
        )
        try:
            run_pipeline()
        except CanonicalSemanticFragmentRejected as rejection:
            if diagnostics_expected:
                self._report_canonical_composition_rejection(mba, rejection)
            if not canonical_composition_ready:
                raise
            contextual_restart = (
                self._promote_contextual_plan_after_canonical_rejection(rejection)
            )
            logger.warning(
                "unflat: canonical composition declined for func=0x%x "
                "anchor=0x%x reason=%s contextual_restart=%s",
                int(mba.entry_ea),
                int(rejection.anchor_ea or mba.entry_ea),
                rejection.reason_code,
                contextual_restart,
            )
            return False
        except Exception as error:
            if diagnostics_expected:
                try:
                    self._report_canonical_pipeline_exception(mba, error)
                except Exception:
                    logger.exception(
                        "unflat: failed to persist canonical pipeline exception "
                        "for func=0x%x",
                        int(mba.entry_ea),
                    )
            raise
        return True

    def _fragment_publication_callback_change_count(
        self,
        mba: object,
        backend: HexRaysMutationBackend,
    ) -> int:
        """Report one callback change for any receipt-proven publication."""
        operation_count = backend.committed_fragment_operation_count
        if isinstance(operation_count, bool) or not isinstance(operation_count, int):
            raise TypeError("fragment callback accounting requires an integer count")
        if operation_count < 0:
            raise ValueError("fragment callback accounting cannot be negative")
        if operation_count == 0:
            return 0
        callback_change_count = 1
        flow_context = getattr(self, "flow_context", None)
        report = getattr(flow_context, "report_fact_consumers", None)
        if callable(report):
            function_ea = int(getattr(mba, "entry_ea", 0) or 0)
            report(
                (
                    FactConsumerRecord(
                        consumer="state_machine_cff_unflattener",
                        strategy="hexrays_callback_change_accounting",
                        fact_id=f"fragment_publication_callback:0x{function_ea:X}",
                        maturity=maturity_to_string(int(getattr(mba, "maturity", 0))),
                        decision="applied",
                        reason="committed_fragment_reported_to_hexrays",
                        payload={
                            "committed_fragment_operation_count": operation_count,
                            "reported_callback_change_count": callback_change_count,
                        },
                    ),
                )
            )
        return callback_change_count

    def _report_materialized_handler_completeness(
        self,
        mba: object,
        *,
        state_var_reg: int,
        resolver_target_count: int,
        live_handler_owner_count: int,
        terminal_state_targets: tuple[tuple[int, int], ...],
        missing_handler_targets: tuple[tuple[int, int], ...],
    ) -> None:
        """Persist the final native-EA handler-completeness decision."""
        flow_context = getattr(self, "flow_context", None)
        report = getattr(flow_context, "report_fact_consumers", None)
        if not callable(report):
            return

        def target_records(
            state_targets: tuple[tuple[int, int], ...],
        ) -> list[dict[str, str]]:
            return [
                {
                    "state": f"0x{int(state) & 0xFFFFFFFF:08X}",
                    "target_ea": f"0x{int(target_ea):X}",
                }
                for state, target_ea in sorted(
                    {
                        (
                            int(state) & 0xFFFFFFFF,
                            int(target_ea),
                        )
                        for state, target_ea in state_targets
                    }
                )
            ]

        terminal_records = target_records(terminal_state_targets)
        missing_records = target_records(missing_handler_targets)
        complete = not missing_records
        report(
            (
                FactConsumerRecord(
                    consumer="state_machine_cff_unflattener",
                    strategy="materialized_handler_completeness",
                    fact_id="resolver_session:materialized_handler_identity",
                    maturity=maturity_to_string(int(getattr(mba, "maturity", 0))),
                    decision="accepted" if complete else "declined",
                    reason=(
                        "complete_materialized_handler_identity"
                        if complete
                        else "missing_materialized_handler_targets"
                    ),
                    payload={
                        "first_missing_handler_target": (
                            None if complete else missing_records[0]
                        ),
                        "live_handler_owner_count": int(live_handler_owner_count),
                        "materialized_state_var_reg": int(state_var_reg),
                        "missing_handler_targets": missing_records,
                        "resolver_target_count": int(resolver_target_count),
                        "terminal_state_targets": terminal_records,
                    },
                ),
            )
        )

    def _log_pipeline_v2_shadow(
        self,
        project_config,
        family,
        source,
        backend,
        *,
        family_context=None,
    ) -> None:
        """Compare optional project PipelineConfig v2 against the live family pipeline."""
        if (
            pipeline_v2_mode_from_project_config(project_config)
            is not PipelineV2Mode.SHADOW_CHECK
        ):
            return
        config = (
            project_config
            if isinstance(project_config, ABCMapping)
            else getattr(project_config, "additional_configuration", {}) or {}
        )
        if not isinstance(config, ABCMapping) or "pipeline_v2" not in config:
            return
        try:
            match = family.detect(
                source.flow_graph,
                backend.capabilities(),
                context=(
                    family_context if family_context is not None else project_config
                ),
            )
            if match is None:
                return
            live_specs = tuple(family.pipeline_for(match, None))
            comparison = compare_pipeline_v2_shadow(
                project_config=project_config,
                registry=state_machine_pass_registry(),
                live_specs=live_specs,
            )
        except Exception:
            logger.warning(
                "unflat: pipeline_v2 shadow comparison failed for family=%s",
                getattr(family, "name", "?"),
                exc_info=True,
            )
            raise
        if not comparison.enabled:
            return
        if comparison.matches:
            logger.info(
                "unflat: pipeline_v2 shadow matches family=%s passes=%s",
                getattr(family, "name", "?"),
                list(comparison.live_pass_ids),
            )
            return
        logger.warning(
            "unflat: pipeline_v2 shadow mismatch family=%s configured=%s live=%s",
            getattr(family, "name", "?"),
            list(comparison.configured_pass_ids),
            list(comparison.live_pass_ids),
        )

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
        levels = getattr(family, "recovery_maturities", None) or (
            IRMaturity.GLOBAL_ANALYZED,
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
            level = (
                IRMaturity[raw] if raw in IRMaturity.__members__ else IRMaturity(raw)
            )
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
        self.mba: ida_hexrays.mba_t = blk.mba
        logger.info(
            "unflat optimize: maturity=%s blk=%s",
            maturity_to_string(getattr(self.mba, "maturity", 0)),
            getattr(blk, "serial", "?"),
        )
        # Delegate to the mba-only orchestration (ticket d81-1vlb). Every line of
        # the family-routed pipeline below operates on the live ``mba`` and never
        # references ``blk`` again, so the same body can be driven from a maturity
        # hook (the planned hook-driven MERR_LOOP fixpoint) as well as from IDA's
        # per-block optblock callback. ``optimize`` stays the optblock entrypoint.
        return self.run_state_machine_unflatten(self.mba)

    def run_state_machine_unflatten(self, mba: "ida_hexrays.mba_t") -> int:
        """Run the family-routed state-machine unflatten pipeline on a live ``mba``.

        Extracted verbatim from :meth:`optimize` (ticket d81-1vlb) so the same
        orchestration can be invoked from a maturity hook -- the planned
        hook-driven ``MERR_LOOP`` fixpoint that replaces IDA's per-block optblock
        re-invocation cadence -- as well as from the optblock callback. Behaviour
        is byte-identical: :meth:`optimize` binds ``self.mba`` and logs, then
        delegates here.

        Returns zero under the historical optblock contract when no fragment
        publication commits.  A receipt-proven FragmentPlan publication returns
        one logical change so Hex-Rays does not carry a mutation-created ``m_nop``
        into ctree generation.
        """
        self.mba = mba
        mba = self.mba
        resolver_state = self.current_resolver_session_state()
        if not isinstance(resolver_state, ResolverSessionState):
            resolver_state = None
        canonical_composition_ready = _partial_canonical_composition_ready(
            resolver_state
        )
        if _should_defer_unbound_materialized_preopt(resolver_state):
            self._report_recovery_gate_decision(
                mba,
                resolver_state=resolver_state,
                decision="declined",
                reason="preopt_evidence_generation_unbound",
                imported_identity_ready=False,
                recovery_epoch_phase=0,
                rounds_before=0,
            )
            logger.debug(
                "unflat: deferring materialized mutation until PREOPT binds "
                "evidence generation %d for func=0x%x",
                int(resolver_state.evidence_generation),
                int(getattr(mba, "entry_ea", 0) or 0),
            )
            return 0
        proceed, _is_indirect = self._should_recover(
            mba,
            canonical_composition_ready=canonical_composition_ready,
        )
        if not proceed:
            return 0
        func_ea: int = int(mba.entry_ea)

        source = lift_function(mba, maturity=mba.maturity)
        self._register_dispatcher_resolvers(mba)
        materialized_computed_goto_profile = bool(
            _is_indirect
            or (
                resolver_state is not None
                and is_computed_goto_materialized(resolver_state)
            )
        )
        (
            fact_view,
            prelim,
            range_evidence,
            analysis_seeds,
            facts,
        ) = self._build_recovery_evidence(
            mba,
            source,
            materialized_computed_goto_profile=(materialized_computed_goto_profile),
        )
        if (
            resolver_state is not None
            and resolver_state.native_preanalysis.has_pending_generated_restart
        ):
            logger.info(
                "unflat: deferring mutation for staged dispatcher recovery "
                "restart at evidence generation %d",
                int(resolver_state.evidence_generation),
            )
            return 0
        rule_config = getattr(self, "config", None)
        materialized_evidence_ready = bool(
            materialized_computed_goto_profile
            and _materialized_identity_evidence_ready(analysis_seeds)
        )
        if _should_defer_incomplete_materialized_identity(
            materialized_computed_goto_profile=(materialized_computed_goto_profile),
            materialized_evidence_ready=materialized_evidence_ready,
            uses_tigress_indirect_materialization=(
                self._uses_tigress_indirect_materialization(rule_config)
            ),
            canonical_composition_ready=canonical_composition_ready,
        ):
            logger.info(
                "unflat: deferring structural mutation until portable "
                "materialized identity is complete for func=0x%x at %s "
                "(handlers=%d missing=%d)",
                int(mba.entry_ea),
                maturity_to_string(int(mba.maturity)),
                len(analysis_seeds.get("materialized_handler_by_state") or {}),
                len(
                    analysis_seeds.get("portable_materialized_handler_identity_misses")
                    or analysis_seeds.get("unmapped_materialized_handler_targets")
                    or ()
                ),
            )
            return 0
        flow_context = self.flow_context
        mutation_gateway = (
            None if flow_context is None else flow_context.new_mba_mutation_gateway()
        )
        if mutation_gateway is None:
            logger.info(
                "unflat: deferring structural mutation without a "
                "coordinator-owned gateway for func=0x%x at %s",
                int(mba.entry_ea),
                maturity_to_string(int(mba.maturity)),
            )
            return 0
        semantic_native_body_materializer = (
            None
            if flow_context is None
            else flow_context.semantic_native_body_materializer()
        )
        backend = HexRaysMutationBackend(
            mutation_gateway=mutation_gateway,
            semantic_native_body_materializer=(semantic_native_body_materializer),
        )
        capabilities = self._build_capabilities(
            mba,
            prelim,
            range_evidence,
            resolver_state=resolver_state,
        )
        project_config = self._project_config or (
            rule_config if isinstance(rule_config, dict) else {}
        )
        family = self._select_family(
            mba,
            source,
            rule_config,
            backend,
            materialized_evidence_ready=materialized_evidence_ready,
            canonical_composition_ready=canonical_composition_ready,
        )
        if self._family_defers(mba, family, is_indirect=_is_indirect):
            return 0
        if family is not None:
            try:
                current_ir_maturity = ida_maturity_to_ir(int(mba.maturity))
            except ValueError:
                if logger.debug_on:
                    logger.debug(
                        "unflat: skipping func=0x%x at unsupported maturity %s",
                        int(mba.entry_ea),
                        maturity_to_string(int(mba.maturity)),
                    )
                return 0
            self._log_pipeline_v2_shadow(
                project_config,
                family,
                source,
                backend,
                family_context=rule_config,
            )
            pipeline_mode = pipeline_v2_mode_from_project_config(project_config)
            self._last_pipeline_v2_mode = pipeline_mode.value
            self._last_config_v2_pass_ids = ()
            shadow_gate_kwargs = {}
            if pipeline_mode is PipelineV2Mode.CONFIG_V2:
                configured_specs = pass_specs_from_project_config(
                    project_config,
                    operational_config_v2_pass_registry(),
                )
                configured_pass_ids = tuple(spec.pass_id for spec in configured_specs)
                self._last_config_v2_pass_ids = configured_pass_ids
                configured_native_specs = tuple(
                    spec
                    for spec in configured_specs
                    if spec.pass_id in STATE_MACHINE_NATIVE_PASS_IDS
                )
                if not configured_native_specs:
                    logger.warning(
                        "unflat: config-v2 project activated the live unflattener "
                        "without native state-machine spine specs for func=0x%x",
                        int(mba.entry_ea),
                    )
                    return 0
                native_specs = (
                    semantic_evidence_state_machine_passes()
                    if isinstance(
                        family,
                        (
                            _CanonicalComputedGotoCompositionFamily,
                            _MaterializedComputedGotoContinuationFamily,
                        ),
                    )
                    else configured_native_specs
                )
                if logger.debug_on:
                    logger.debug(
                        "unflat: executing config-v2 pipeline for func=0x%x "
                        "configured_passes=%s effective_native_passes=%s",
                        int(mba.entry_ea),
                        list(configured_pass_ids),
                        [spec.pass_id for spec in native_specs],
                    )
                shadow_gate_kwargs = {
                    "pipeline_v2_specs": native_specs,
                }
            elif pipeline_mode is PipelineV2Mode.SHADOW_CHECK:
                shadow_gate_kwargs = {
                    "pipeline_v2_shadow_registry": state_machine_pass_registry(),
                    "require_pipeline_v2_shadow_match": True,
                }

            def run_pipeline() -> None:
                self._pass_manager.run(
                    source=source,
                    family=family,
                    backend=backend,
                    project_config=rule_config,
                    maturity=current_ir_maturity,
                    capabilities=capabilities,
                    input_facts=fact_view,
                    analysis_seeds=analysis_seeds,
                    **shadow_gate_kwargs,
                )

            if not self._run_pipeline_with_canonical_diagnostics(
                mba,
                canonical_composition_ready=canonical_composition_ready,
                materialized_evidence_ready=materialized_evidence_ready,
                run_pipeline=run_pipeline,
            ):
                return self._fragment_publication_callback_change_count(mba, backend)
            facts = self._pass_manager.analysis_manager_for(func_ea) or facts
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
        # this path (the legacy preanalysis instrumentation does not run under the flag). llr-6dq7.
        self._publish_unflat_diagnostics(
            mba, source, rec, tr, regions, fact_view, range_evidence, capabilities
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
        if family is not None and not dispatcher_present:
            self._mark_ea_converged(func_ea)
        # Preserve the historical zero-return cadence for legacy PatchPlan and
        # no-op rounds: approov_real_pattern depends on IDA's interleaved
        # optimize_global cadence. A committed FragmentPlan is different: SDK
        # verifier 50409 requires the callback to acknowledge its live write.
        # Report one logical change, not the operation inventory, so the receipt
        # remains the detailed authority without exaggerating callback progress.
        return self._fragment_publication_callback_change_count(mba, backend)

    def _should_recover(
        self,
        mba: "ida_hexrays.mba_t",
        *,
        canonical_composition_ready: bool = False,
    ) -> "tuple[bool, bool]":
        """Maturity + bounded-round gate; returns ``(proceed, is_indirect)``."""
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
        # dispatcher, and recorded its EA — no config key, no hardcoded addresses.
        resolver_state = self.current_resolver_session_state()
        is_indirect = bool(
            isinstance(resolver_state, ResolverSessionState)
            and resolver_state.indirect_dispatcher_materialized
        )
        materialized_computed_goto_profile = bool(
            isinstance(resolver_state, ResolverSessionState)
            and is_computed_goto_materialized(resolver_state)
        )
        # INDIRECT keeps the historical one-shot MMAT_CALLS contract (its
        # terminal-tail / folded-loop-guard lowering is tuned for a single CALLS
        # pass).  The NON-indirect profile now recovers at EVERY maturity from LOCOPT
        # through GLBOPT2 (ticket llr-a93i) so folded equality-chains recover at the
        # pre-fold stage where their dispatcher is still alive.
        canonical_composition_admission = bool(
            canonical_composition_ready and not is_indirect
        )
        one_shot_recovery = bool(
            canonical_composition_admission or materialized_computed_goto_profile
        )
        if is_indirect:
            if mba.maturity != ida_hexrays.MMAT_CALLS:
                self._report_recovery_gate_decision(
                    mba,
                    resolver_state=resolver_state,
                    decision="declined",
                    reason="indirect_profile_requires_calls",
                    imported_identity_ready=None,
                    recovery_epoch_phase=0,
                    rounds_before=0,
                )
                return (False, is_indirect)
        elif canonical_composition_admission:
            if mba.maturity != ida_hexrays.MMAT_CALLS:
                self._report_recovery_gate_decision(
                    mba,
                    resolver_state=resolver_state,
                    decision="declined",
                    reason="canonical_composition_requires_calls",
                    imported_identity_ready=None,
                    recovery_epoch_phase=0,
                    rounds_before=0,
                )
                return (False, is_indirect)
        elif int(mba.maturity) not in (
            self._union_recovery_maturities() | self._config_recovery_maturities()
        ):
            # No registered profile (nor a per-project ``recovery_maturity`` override)
            # recovers a non-indirect shape at this maturity; bail BEFORE the expensive
            # lift/prelim/select_family so a stage nothing wants costs nothing (ticket
            # llr-a93i). The fine per-family gate below still defers a profile that wants a
            # DIFFERENT stage within the union/override.
            self._report_recovery_gate_decision(
                mba,
                resolver_state=resolver_state,
                decision="declined",
                reason="maturity_not_registered",
                imported_identity_ready=None,
                recovery_epoch_phase=0,
                rounds_before=0,
            )
            return (False, is_indirect)
        has_imported_identity = bool(imported_detached_snippet_target_eas(mba))
        current_evidence_generation = (
            int(resolver_state.evidence_generation)
            if isinstance(resolver_state, ResolverSessionState)
            else 0
        )
        normalized_evidence_generation = (
            resolver_state.native_preanalysis.normalization_published_postvalidated_generation
            if isinstance(resolver_state, ResolverSessionState)
            else None
        )
        stable_preopt_epoch = bool(
            has_imported_identity or normalized_evidence_generation is not None
        )
        recovery_epoch_phase = (
            2 if has_imported_identity else (1 if stable_preopt_epoch else 0)
        )
        self._reset_pass_manager_if_new_session(
            mba,
            evidence_generation=_unflatten_recovery_epoch_generation(
                current_evidence_generation=current_evidence_generation,
                normalized_evidence_generation=normalized_evidence_generation,
            ),
            stable_preopt_epoch=stable_preopt_epoch,
            imported_identity_ready=has_imported_identity,
        )
        # Bounded re-run (ticket llr-3gn4): re-running the unflatten on the re-lifted
        # post-redirect graph discovers + redirects a residual dispatcher a single pass
        # leaves behind, so IDA's optimize_global converges to the dispatcher-free graph.
        # An ea is terminal once recovery finds no dispatcher (the common clean case,
        # identical to the old one-shot behaviour) or the round cap is reached. Self-
        # terminating: a fully-unflattened graph yields no dispatcher, so the next round
        # emits no plan and marks the ea done. GATED to the NON-indirect profile — see
        # :meth:`_should_run_unflatten_round`.
        round_key = (int(mba.entry_ea), int(mba.maturity))
        rounds_before = int(self._unflat_round_count.get(round_key, 0))
        if not self._should_run_unflatten_round(
            int(mba.entry_ea),
            is_indirect=is_indirect,
            maturity=int(mba.maturity),
            one_shot=one_shot_recovery,
        ):
            if int(mba.entry_ea) in self._unflat_done_eas:
                decline_reason = "function_converged"
            elif canonical_composition_admission and rounds_before >= 1:
                decline_reason = "canonical_composition_already_attempted"
            elif is_indirect and rounds_before >= 1:
                decline_reason = "indirect_profile_already_attempted"
            elif materialized_computed_goto_profile and rounds_before >= 1:
                decline_reason = "materialized_profile_already_attempted"
            else:
                decline_reason = "round_budget_exhausted"
            self._report_recovery_gate_decision(
                mba,
                resolver_state=resolver_state,
                decision="declined",
                reason=decline_reason,
                imported_identity_ready=has_imported_identity,
                recovery_epoch_phase=recovery_epoch_phase,
                rounds_before=rounds_before,
            )
            return (False, is_indirect)
        self._report_recovery_gate_decision(
            mba,
            resolver_state=resolver_state,
            decision="accepted",
            reason="recovery_round_granted",
            imported_identity_ready=has_imported_identity,
            recovery_epoch_phase=recovery_epoch_phase,
            rounds_before=rounds_before,
        )
        return (True, is_indirect)

    def _register_dispatcher_resolvers(self, mba: "ida_hexrays.mba_t") -> None:
        """Register the indirect-jump + emulation dispatcher resolvers for this ``mba``."""
        # llr-dczv: register the PORTABLE indirect jump-table resolver into the
        # shared front-end (build_dispatch_map_any_kind) BEFORE any detection
        # (the prelim recover_dispatcher, select_family, pass manager) so the
        # Tigress indirect dispatcher is recognized end-to-end. The resolver is
        # IDA-free; the live binary table reads live behind the injected
        # HexRaysIndirectJumpTableCapability (bound to the fresh mba). accepts()
        # consults the capability even AFTER materialization removes the m_ijmp
        # (llr-tm3i). Registration remains unconditional so the process-global
        # slot is rebound to the fresh MBA, but ``enabled`` is profile-scoped:
        # non-Tigress profiles abstain before touching the live capability.
        # Idempotent by name -> rebinds the fresh mba each decompilation.
        _cfg = self.config
        register_extra_dispatcher_resolver(
            IndirectJumpDispatcherResolver(
                indirect_tables=HexRaysIndirectJumpTableCapability(mba=mba),
                goto_table_info=(
                    _cfg.get("goto_table_info", {}) or {}
                    if isinstance(_cfg, dict)
                    else {}
                ),
                enabled=self._uses_tigress_indirect_materialization(_cfg),
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
                enabled=bool(
                    isinstance(_cfg, dict) and _cfg.get("emulation_dispatcher")
                ),
            )
        )

    def _build_recovery_evidence(
        self,
        mba: "ida_hexrays.mba_t",
        source,
        *,
        materialized_computed_goto_profile: bool = False,
    ):
        """Build the pre-pipeline recovery inputs.

        Returns ``(fact_view, prelim, range_evidence, analysis_seeds, facts)``.
        """
        # Supply the live validated fact view (state observations) so resolve_state_transitions
        # has the transition evidence; without it the chain produces an empty plan.
        fact_view = None
        flow_ctx = getattr(self, "flow_context", None)
        if flow_ctx is not None:
            try:
                fact_view = flow_ctx.validated_fact_view(mba.maturity)
            except Exception:  # noqa: BLE001 — fact view is best-effort input
                logger.debug("unflat: validated_fact_view unavailable", exc_info=True)
        # Pre-mutation condition-chain/interval evidence: walk the PRISTINE mba here (it still matches
        # source.flow_graph; the pipeline mutates it below) so the value-range dispatcher recovery
        # sees the intact condition-chain. PROMOTED TO PRODUCTION (gap3+gap4, ticket llr-t1s8): #4's
        # LowerStateMachine consumes this through the AnalysisManager to build the condition-chain-enriched DAG
        # whose CONDITIONAL_RETURN edges (interval-map classification, not the bounded mba walk)
        # materialize terminal returns — the unflatten returns=0 -> returns=N fix. analyze_condition_chain_dispatcher
        # lives in the hexrays backend (needs the live mba), which the portable LowerStateMachine
        # can't import, so the evidence is computed here in the entry and threaded as an opaque fact.
        # The LiSA-discovery diff log stays diag-only. Self-gating: no dispatcher -> no evidence ->
        # #4 stays on the committed shallow path (byte-identical).
        range_evidence = None
        prelim = None
        # Thread the rule's min_state_constant into the prelim recovery so the condition-chain
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
                # Thread the recovered register identity so a register-resident
                # state var drives the same condition-chain analysis as a stack
                # state var.
                range_evidence = analyze_condition_chain_dispatcher(
                    mba,
                    int(prelim.dispatcher_block_serial),
                    getattr(prelim, "state_var_stkoff", None),
                    state_var_reg=getattr(prelim, "state_var_reg", None),
                )
                # An equality-only scan may choose a secondary flag register
                # while the dispatcher itself begins with a direct stack range
                # comparison. Probe the extractor without that register only
                # for this disagreement; an empty probe preserves the genuine
                # register-resident path.
                if (
                    getattr(prelim, "state_var_stkoff", None) is None
                    and getattr(prelim, "state_var_reg", None) is not None
                ):
                    stack_probe = analyze_condition_chain_dispatcher(
                        mba,
                        int(prelim.dispatcher_block_serial),
                    )
                    if (
                        getattr(stack_probe, "state_var_stkoff", None) is not None
                        and bool(
                            getattr(
                                getattr(stack_probe, "decision_dag", None),
                                "nodes",
                                None,
                            )
                        )
                    ):
                        range_evidence = stack_probe
                if _capture_diagnostics_enabled():
                    self._log_lisa_discovery_diff(
                        source.flow_graph, prelim, range_evidence
                    )
        except Exception:  # noqa: BLE001 — evidence recovery is best-effort
            logger.debug(
                "unflat: pre-pipeline condition-chain evidence failed", exc_info=True
            )
        # Optimizer-owned seam: resolver materialization is Hex-Rays-specific,
        # while the portable five-pass spine consumes only the immutable proof
        # tuple through AnalysisManager. This keeps d810.passes hexrays-agnostic.
        resolver_state = self.current_resolver_session_state()
        current_identity_index = (
            resolver_state.identity_index
            if isinstance(resolver_state, ResolverSessionState)
            else None
        )
        materialized_indirect_transfers = (
            resolver_state.materialized_transfers
            if isinstance(resolver_state, ResolverSessionState)
            else ()
        )
        if isinstance(resolver_state, ResolverSessionState) and prelim is not None:
            live_handler_evidence = _condition_chain_handler_transfers_from_recovery(
                materialized_indirect_transfers,
                source.flow_graph,
                prelim,
            )
            if live_handler_evidence:
                if resolver_state.native_preanalysis.merge_materialized_transfers(
                    resolver_state.native_key,
                    live_handler_evidence,
                ):
                    resolver_state.invalidate_current_mba_binding()
                materialized_indirect_transfers = resolver_state.materialized_transfers
        mutation_materialized_indirect_transfers = (
            mutation_authoritative_materialized_transfers(
                materialized_indirect_transfers
            )
        )
        materialized_state_var_reg = _resolver_native_state_register(
            prelim,
            materialized_indirect_transfers,
            materialized_computed_goto_profile=(materialized_computed_goto_profile),
        )
        state_register_candidates = materialized_state_register_candidates(
            materialized_indirect_transfers
        )
        candidate_state_var_reg = unique_materialized_state_register(
            materialized_indirect_transfers
        )
        if candidate_state_var_reg is not None:
            if materialized_state_var_reg != int(candidate_state_var_reg):
                logger.warning(
                    "materialized state-register conflict: recovered=%s resolver=%d",
                    materialized_state_var_reg,
                    int(candidate_state_var_reg),
                )
            if state_register_candidates != frozenset({candidate_state_var_reg}):
                logger.info(
                    "materialized state-register selected by state-bearing "
                    "evidence: selected=%d navigation_candidates=%s",
                    int(candidate_state_var_reg),
                    sorted(state_register_candidates),
                )
        elif len(state_register_candidates) > 1:
            logger.warning(
                "materialized state-register conflict: resolver_candidates=%s",
                sorted(state_register_candidates),
            )
        materialized_state_routes = ()
        legacy_handler_by_state: dict[int, int] = {}
        handler_targets: dict[int, int] = {}
        portable_handler_targets: dict[int, int] = {}
        materialized_handler_entry_eas: dict[int, int] = {}
        authoritative_handler_serials: frozenset[int] = frozenset()
        unmapped_materialized_handler_targets: tuple[tuple[int, int], ...] = ()
        portable_materialized_handler_identity_misses: tuple[tuple[int, int], ...] = ()
        entry_route_region_identities: dict[int, StableBlockIdentity] = {}
        materialized_dispatcher_entry_serial: int | None = None
        materialized_dispatcher_router_serials: frozenset[int] = frozenset()
        imported_instruction_origins = (
            dict(
                resolver_state.imported_instruction_origins_for(
                    stable_mba_identity(mba)
                )
            )
            if materialized_computed_goto_profile
            and isinstance(resolver_state, ResolverSessionState)
            else {}
        )
        imported_direct_boundary_evidence = (
            imported_detached_snippet_direct_boundary_evidence(mba)
            if materialized_computed_goto_profile
            else ()
        )
        imported_native_eas_by_serial = {
            int(block.serial): frozenset(
                int(imported_instruction_origins[int(instruction.ea)])
                for instruction in block.insn_snapshots
                if int(instruction.ea) in imported_instruction_origins
            )
            for block in source.flow_graph.blocks.values()
            if any(
                int(instruction.ea) in imported_instruction_origins
                for instruction in block.insn_snapshots
            )
        }
        if current_identity_index is None and isinstance(
            resolver_state, ResolverSessionState
        ):
            current_generation = int(getattr(mba, "maturity", 0) or 0)
            current_identity_index = MbaBlockIdentityIndex.from_flow_graph(
                generation=current_generation,
                native_key=resolver_state.native_key,
                evidence_generation=current_generation,
                flow_graph=source.flow_graph,
                session_id=(
                    f"callback:{int(getattr(mba, 'entry_ea', 0) or 0):X}:"
                    f"{current_generation}"
                ),
                imported_native_eas_by_serial=imported_native_eas_by_serial,
            )
        native_origin_eas_by_serial = {
            int(block.serial): frozenset(
                int(
                    imported_instruction_origins.get(
                        int(instruction.ea),
                        int(instruction.ea),
                    )
                )
                for instruction in block.insn_snapshots
                if int(instruction.ea) > 0
            )
            for block in source.flow_graph.blocks.values()
            if block.insn_snapshots
        }
        native_carrier_load_eas = tuple(
            sorted(
                {
                    int(load_ea)
                    for transfer in materialized_indirect_transfers
                    for load_ea in transfer.state_carrier_consumer_load_eas
                }
            )
        )
        native_carrier_consumer_serials_by_load_ea: dict[int, int] = {}
        for load_ea in native_carrier_load_eas:
            consumer_block = find_unique_live_block_by_native_ea(mba, load_ea)
            if consumer_block is None:
                continue
            consumer_serial = int(consumer_block.serial)
            graph_consumer = source.flow_graph.get_block(consumer_serial)
            if graph_consumer is None or not graph_consumer.insn_snapshots:
                continue
            native_carrier_consumer_serials_by_load_ea[load_ea] = consumer_serial
        if (
            materialized_computed_goto_profile
            and materialized_state_var_reg is not None
            and materialized_indirect_transfers
        ):
            validated_materialized_target_eas = _validated_materialized_target_eas(
                imported_detached_snippet_target_eas(mba),
                resolver_state,
            )
            equality_target_eas = unique_materialized_equality_target_eas(
                materialized_indirect_transfers,
                materialized_state_var_reg,
                validated_candidate_target_eas=validated_materialized_target_eas,
            )
            entry_route_source_eas = (
                _unique_materialized_handler_entry_route_source_eas(
                    materialized_indirect_transfers,
                    equality_target_eas,
                )
            )
            entry_route_region_identities = (
                _unique_materialized_handler_region_identities(
                    materialized_indirect_transfers,
                    equality_target_eas,
                    native_key=current_identity_index.native_key,
                )
            )

            def live_block_for_applied_exit_receipt(target_ea: int):
                candidate_serials: set[int] = set()
                for applied in imported_direct_boundary_evidence:
                    port = getattr(applied, "port", None)
                    if (
                        port is None
                        or int(getattr(port, "source_block_ea", 0) or 0)
                        != int(target_ea)
                        or int(getattr(port, "endpoint_block_ea", 0) or 0)
                        != int(target_ea)
                        or str(getattr(port, "delivery_mode", "")) != "terminal_goto"
                    ):
                        continue
                    anchors = {
                        int(ea)
                        for ea in getattr(applied, "endpoint_anchor_eas", ())
                        if int(ea) > 0
                    }
                    candidate_serials.update(
                        int(block.serial)
                        for block in source.flow_graph.blocks.values()
                        if any(
                            int(instruction.ea) in anchors
                            for instruction in block.insn_snapshots
                        )
                    )
                if len(candidate_serials) != 1:
                    return None
                return mba.get_mblock(next(iter(candidate_serials)))

            (
                handler_targets,
                materialized_handler_entry_eas,
                unmapped_materialized_handler_targets,
            ) = _bind_materialized_handler_targets(
                source.flow_graph,
                equality_target_eas,
                live_block_for_ea=lambda target_ea: (
                    _rebind_current_native_ea(current_identity_index, int(target_ea))
                    or find_unique_live_block_by_ea(mba, int(target_ea))
                    or find_materialized_handler_block_by_native_ea(mba, int(target_ea))
                    or find_unique_live_block_by_native_ea(mba, int(target_ea))
                ),
                entry_route_source_eas=entry_route_source_eas,
                entry_route_region_identities=entry_route_region_identities,
                live_block_for_region_identity=(
                    None
                    if current_identity_index is None
                    else lambda identity: (
                        current_identity_index.rebind_region_entry(identity).block
                    )
                ),
                live_block_for_applied_exit_receipt=(
                    live_block_for_applied_exit_receipt
                ),
            )
            authoritative_handler_serials = frozenset(
                int(serial) for serial in handler_targets.values()
            )
            portable_handler_targets = dict(handler_targets)
            (
                materialized_dispatcher_entry_serial,
                materialized_dispatcher_router_serials,
            ) = _bind_materialized_dispatcher_identity(
                imported_native_eas_by_serial,
                materialized_indirect_transfers,
                handler_serials=authoritative_handler_serials,
                live_block_for_entry_ea=lambda entry_ea: (
                    find_unique_live_block_by_ea(mba, int(entry_ea))
                    or find_unique_live_block_by_native_ea(mba, int(entry_ea))
                ),
            )
            logger.info(
                "materialized portable identity rebind: state_reg=%d "
                "handlers=%d entry=%s routers=%d missing=%d",
                int(materialized_state_var_reg),
                len(handler_targets),
                (
                    None
                    if materialized_dispatcher_entry_serial is None
                    else "blk%d" % int(materialized_dispatcher_entry_serial)
                ),
                len(materialized_dispatcher_router_serials),
                len(unmapped_materialized_handler_targets),
            )
            portable_materialized_handler_identity_misses = tuple(
                unmapped_materialized_handler_targets
            )
            if unmapped_materialized_handler_targets:
                logger.info(
                    "materialized portable identity missing targets: %s",
                    tuple(
                        "state=0x%08X@0x%X" % (int(state), int(target_ea))
                        for state, target_ea in (unmapped_materialized_handler_targets)
                    ),
                )
        if (
            prelim is not None
            and prelim.dispatch_map is not None
            and prelim.dispatcher_block_serial is not None
            and materialized_state_var_reg is not None
            and materialized_indirect_transfers
        ):
            materialized_dispatcher_entry_serial = int(prelim.dispatcher_block_serial)
            _, observed_state_write_anchors = facts_from_validated_view(fact_view)

            def current_block_serial_for_instruction_ea(
                instruction_ea: int,
            ) -> int | None:
                block = _rebind_current_instruction_owner(
                    current_identity_index,
                    imported_instruction_origins,
                    int(instruction_ea),
                )
                return None if block is None else int(block.serial)

            state_write_anchors = rebind_state_write_anchors(
                observed_state_write_anchors,
                block_serial_for_instruction_ea=(
                    current_block_serial_for_instruction_ea
                ),
            )
            if len(state_write_anchors) != len(observed_state_write_anchors):
                rebound_instruction_eas = frozenset(
                    int(anchor.instruction_ea)
                    for anchor in state_write_anchors
                    if anchor.instruction_ea is not None
                )
                abstained_labels = tuple(
                    (
                        "state=0x%08X@missing-ea"
                        % (int(anchor.state_const) & 0xFFFFFFFF)
                        if anchor.instruction_ea is None
                        else "state=0x%08X@0x%X"
                        % (
                            int(anchor.state_const) & 0xFFFFFFFF,
                            int(anchor.instruction_ea),
                        )
                    )
                    for anchor in observed_state_write_anchors
                    if anchor.instruction_ea is None
                    or int(anchor.instruction_ea) not in rebound_instruction_eas
                )
                logger.info(
                    "portable state-write anchor rebind: observed=%d "
                    "rebound=%d abstained=%d examples=%s",
                    len(observed_state_write_anchors),
                    len(state_write_anchors),
                    len(abstained_labels),
                    abstained_labels[:8],
                )
            register_fixpoint = run_snapshot_constant_fixpoint(
                source.flow_graph,
                -1,
            )
            exact_state_to_handler = prelim.dispatch_map.state_to_handler()
            legacy_handler_by_state = {
                int(state): int(serial)
                for state, serial in exact_state_to_handler.items()
            }
            handler_states, handler_targets, handler_serials = (
                merge_materialized_handler_maps(
                    exact_state_to_handler,
                    (
                        range_evidence.handler_state_map
                        if range_evidence is not None
                        else {}
                    ),
                    (
                        range_evidence.dispatcher.to_handler_state_map()
                        if range_evidence is not None
                        and range_evidence.dispatcher is not None
                        else {}
                    ),
                )
            )
            imported_target_eas = _validated_materialized_target_eas(
                imported_detached_snippet_target_eas(mba),
                resolver_state,
            )
            equality_target_eas = unique_materialized_equality_target_eas(
                materialized_indirect_transfers,
                materialized_state_var_reg,
                validated_candidate_target_eas=imported_target_eas,
            )
            materialized_handler_overrides = (
                _instruction_backed_portable_handler_overrides(
                    source.flow_graph,
                    equality_target_eas,
                    portable_handler_targets,
                )
            )
            materialized_handler_owners = (
                instruction_backed_materialized_handler_owners(
                    equality_target_eas,
                    handler_targets,
                    source.flow_graph,
                )
            )
            materialized_handler_owners.update(materialized_handler_overrides)
            atomic_predicate_eas = materialized_atomic_predicate_eas(
                materialized_indirect_transfers
            )
            imported_handler_serials: set[int] = set()
            for state_constant, target_ea in equality_target_eas.items():
                target_block = (
                    _rebind_current_native_ea(
                        current_identity_index,
                        int(target_ea),
                    )
                    or find_materialized_handler_block_by_native_ea(
                        mba,
                        int(target_ea),
                        required_native_eas=atomic_predicate_eas,
                    )
                )
                if target_block is None:
                    continue
                target_serial = int(target_block.serial)
                graph_target = source.flow_graph.get_block(target_serial)
                if graph_target is None or not graph_target.insn_snapshots:
                    continue
                selected_owner = select_materialized_handler_owner_serial(
                    state_constant=int(state_constant),
                    instruction_backed_owners=materialized_handler_owners,
                    exact_target_serial=target_serial,
                    exact_target_ea=int(target_ea),
                    flow_graph=source.flow_graph,
                    atomic_predicate_eas=atomic_predicate_eas,
                    native_instruction_eas_by_serial=native_origin_eas_by_serial,
                )
                if selected_owner != target_serial:
                    existing_entry_ea = materialized_handler_entry_eas.get(
                        selected_owner
                    )
                    if existing_entry_ea is None:
                        materialized_handler_entry_eas[selected_owner] = int(target_ea)
                    elif int(existing_entry_ea) != int(target_ea):
                        del materialized_handler_entry_eas[selected_owner]
                    selected_block = source.flow_graph.get_block(selected_owner)
                    if selected_block is not None:
                        logger.info(
                            "instruction-backed handler owner retained: "
                            "state=0x%X target_ea=0x%X live=blk%d@0x%X "
                            "imported_clone=blk%d@0x%X",
                            int(state_constant),
                            int(target_ea),
                            selected_owner,
                            int(selected_block.start_ea),
                            target_serial,
                            int(graph_target.start_ea),
                        )
                    continue
                exact_instruction_owner = any(
                    int(instruction.ea) == int(target_ea)
                    for instruction in graph_target.insn_snapshots
                )
                if exact_instruction_owner:
                    materialized_handler_owners[int(state_constant)] = target_serial
                override_serial = exact_materialized_handler_override_serial(
                    target_ea=int(target_ea),
                    target_serial=target_serial,
                    target_native_identity_ea=int(target_ea),
                    imported_target_eas=imported_target_eas,
                )
                if override_serial is None:
                    continue
                materialized_handler_overrides[int(state_constant)] = override_serial
                materialized_handler_owners[int(state_constant)] = override_serial
                materialized_handler_entry_eas[override_serial] = int(target_ea)
                if int(target_ea) in imported_target_eas:
                    imported_handler_serials.add(override_serial)
                logger.info(
                    "exact materialized handler target override: state=0x%X "
                    "target_ea=0x%X live=blk%d@0x%X",
                    int(state_constant),
                    int(target_ea),
                    target_serial,
                    int(graph_target.start_ea),
                )
            handler_states, handler_targets, handler_serials = (
                override_materialized_handler_targets(
                    handler_targets,
                    handler_serials,
                    materialized_handler_overrides,
                )
            )
            for (
                target_serial,
                target_ea,
            ) in unique_materialized_conditional_handler_entry_eas(
                materialized_indirect_transfers,
                handler_targets,
            ).items():
                target_block = find_materialized_handler_block_by_native_ea(
                    mba,
                    int(target_ea),
                    required_native_eas=atomic_predicate_eas,
                )
                if target_block is None or int(target_block.serial) != int(
                    target_serial
                ):
                    continue
                existing_entry_ea = materialized_handler_entry_eas.get(
                    int(target_serial)
                )
                if existing_entry_ea is not None and int(existing_entry_ea) != int(
                    target_ea
                ):
                    del materialized_handler_entry_eas[int(target_serial)]
                    logger.warning(
                        "materialized handler native-entry conflict: "
                        "blk%d@0x%X entries=[0x%X,0x%X]",
                        int(target_serial),
                        int(target_block.start),
                        int(existing_entry_ea),
                        int(target_ea),
                    )
                    continue
                materialized_handler_entry_eas[int(target_serial)] = int(target_ea)
                logger.info(
                    "conditional handler native-entry ownership: "
                    "target_ea=0x%X live=blk%d@0x%X",
                    int(target_ea),
                    int(target_serial),
                    int(target_block.start),
                )
            authoritative_handler_serials = frozenset(
                int(serial) for serial in handler_targets.values()
            )
            materialized_router_eas = frozenset(
                int(ea)
                for transfer in materialized_indirect_transfers
                for ea in transfer.dispatcher_router_eas
            )
            live_materialized_routers: set[int] = set()
            for router_ea in sorted(materialized_router_eas):
                router_block = find_unique_live_block_by_ea(mba, router_ea)
                if router_block is None:
                    continue
                router_serial = int(router_block.serial)
                if router_serial in authoritative_handler_serials:
                    continue
                graph_router = source.flow_graph.get_block(router_serial)
                if graph_router is not None:
                    live_materialized_routers.add(router_serial)
            proven_router_ranges = materialized_dispatcher_router_native_ranges(
                materialized_indirect_transfers
            )
            live_materialized_routers.update(
                serial
                for serial in native_origin_blocks_in_ranges(
                    native_origin_eas_by_serial,
                    proven_router_ranges,
                )
                if serial not in authoritative_handler_serials
            )
            materialized_dispatcher_router_serials = frozenset(
                live_materialized_routers
            )
            if materialized_dispatcher_router_serials:
                logger.info(
                    "materialized dispatcher routers: %s",
                    ",".join(
                        "blk%d@0x%X"
                        % (
                            serial,
                            int(source.flow_graph.get_block(serial).start_ea),
                        )
                        for serial in sorted(materialized_dispatcher_router_serials)
                    ),
                )
            materialized_state_routes = _build_materialized_state_routes(
                source.flow_graph,
                state_write_anchors=state_write_anchors,
                in_stk_maps=register_fixpoint.in_stk_maps,
                in_reg_maps=register_fixpoint.in_reg_maps,
                out_stk_maps=register_fixpoint.out_stk_maps,
                out_reg_maps=register_fixpoint.out_reg_maps,
                dispatcher_entry_serial=int(prelim.dispatcher_block_serial),
                state_var_reg=materialized_state_var_reg,
                handler_serials=handler_serials,
                authoritative_handler_serials=authoritative_handler_serials,
                dispatcher_block_serials=frozenset(
                    {
                        int(prelim.dispatcher_block_serial),
                        *(
                            int(serial)
                            for serial in prelim.dispatch_map.dispatcher_blocks
                        ),
                        *(
                            int(serial)
                            for serial in (
                                range_evidence.condition_chain_blocks
                                if range_evidence is not None
                                else ()
                            )
                        ),
                        *(
                            int(serial)
                            for serial in (
                                range_evidence.decision_dag.nodes
                                if range_evidence is not None
                                and range_evidence.decision_dag is not None
                                else ()
                            )
                        ),
                    }
                ),
                transfers=mutation_materialized_indirect_transfers,
                handler_states=handler_states,
                handler_targets=handler_targets,
                replacement_handler_serials=frozenset(
                    int(serial) for serial in imported_handler_serials
                ),
                exact_handler_override_serials=frozenset(
                    int(serial) for serial in materialized_handler_overrides.values()
                ),
                handler_entry_eas_by_serial=materialized_handler_entry_eas,
                handler_target_resolver=(
                    range_evidence.decision_dag.route
                    if range_evidence is not None
                    and range_evidence.decision_dag is not None
                    and range_evidence.decision_dag.nodes
                    else (
                        range_evidence.dispatcher.lookup
                        if range_evidence is not None
                        and range_evidence.dispatcher is not None
                        else None
                    )
                ),
                condition_chain_dag=(
                    range_evidence.decision_dag if range_evidence is not None else None
                ),
                applied_direct_boundary_evidence=(imported_direct_boundary_evidence),
            )
            terminal_state_targets: list[tuple[int, int]] = []
            for route in materialized_state_routes:
                if route.proof_kind != "terminal_state_route":
                    continue
                target_ea = route.target_native_ea
                if target_ea is None:
                    terminal_block = source.flow_graph.get_block(
                        int(route.target_handler_serial)
                    )
                    if terminal_block is not None:
                        target_ea = int(terminal_block.start_ea)
                if target_ea is not None and 0 < int(target_ea) < 0xFFFFFFFFFFFFFFFF:
                    terminal_state_targets.append(
                        (int(route.state_constant), int(target_ea))
                    )
            terminal_state_targets.extend(
                _postvalidated_canonical_terminal_state_targets(
                    resolver_state,
                    state_var_reg=materialized_state_var_reg,
                )
            )
            unmapped_materialized_handler_targets = (
                missing_materialized_handler_targets(
                    equality_target_eas,
                    materialized_handler_owners,
                    terminal_state_targets=terminal_state_targets,
                )
            )
            self._report_materialized_handler_completeness(
                mba,
                state_var_reg=int(materialized_state_var_reg),
                resolver_target_count=len(equality_target_eas),
                live_handler_owner_count=len(materialized_handler_owners),
                terminal_state_targets=tuple(terminal_state_targets),
                missing_handler_targets=unmapped_materialized_handler_targets,
            )
            if unmapped_materialized_handler_targets:
                logger.info(
                    "materialized handler map incomplete: %s",
                    ",".join(
                        "state=0x%08X@0x%X" % (state, target_ea)
                        for state, target_ea in unmapped_materialized_handler_targets
                    ),
                )
            terminal_carrier_requests = tuple(
                dict.fromkeys(
                    (
                        *plan_terminal_return_carrier_requests(
                            source.flow_graph,
                            materialized_state_routes,
                            state_var_reg=materialized_state_var_reg,
                        ),
                        *plan_terminal_return_carrier_requests_from_native_routes(
                            materialized_indirect_transfers,
                            tuple(
                                applied.port
                                for applied in imported_direct_boundary_evidence
                            ),
                            state_var_reg=materialized_state_var_reg,
                        ),
                    )
                )
            )
            if terminal_carrier_requests:
                resolver_state = self.current_resolver_session_state()
                if isinstance(resolver_state, ResolverSessionState):
                    resolver_state.native_preanalysis.merge_terminal_return_carrier_requests(
                        resolver_state.native_key,
                        terminal_carrier_requests,
                    )
                logger.info(
                    "terminal return-carrier requests: %s",
                    [
                        (
                            hex(int(request.source_handler_ea)),
                            hex(int(request.terminal_target_ea)),
                            hex(int(request.state_constant)),
                        )
                        for request in terminal_carrier_requests
                    ],
                )

            def resolve_live_target_serial(target_ea: int) -> int | None:
                target_block = (
                    _rebind_current_native_ea(
                        current_identity_index,
                        int(target_ea),
                    )
                    or find_materialized_handler_block_by_native_ea(
                        mba,
                        int(target_ea),
                        required_native_eas=atomic_predicate_eas,
                    )
                )
                target_serial = (
                    int(target_block.serial) if target_block is not None else None
                )
                graph_target = (
                    source.flow_graph.get_block(target_serial)
                    if target_serial is not None
                    else None
                )
                logger.info(
                    "conditional bridge live target: target_ea=0x%X live=%s graph=%s",
                    int(target_ea),
                    (
                        None
                        if target_block is None
                        else "blk%d@0x%X"
                        % (int(target_block.serial), int(target_block.start))
                    ),
                    (
                        None
                        if graph_target is None
                        else "blk%d@0x%X"
                        % (int(graph_target.serial), int(graph_target.start_ea))
                    ),
                )
                return target_serial

            def resolve_conditional_arm_sources(
                transfer: MaterializedIndirectTransfer,
            ) -> tuple[int, int] | None:
                source_block = find_unique_live_block_by_ea(
                    mba,
                    int(transfer.source_jmp_ea),
                )
                if source_block is None:
                    native_source_serials = tuple(
                        int(block.serial)
                        for block in source.flow_graph.blocks.values()
                        if block.preds
                        and block.insn_snapshots
                        and block.insn_snapshots[-1].is_conditional_jump
                        and int(block.insn_snapshots[-1].ea)
                        == int(transfer.source_jmp_ea)
                    )
                    if len(native_source_serials) == 1:
                        source_block = mba.get_mblock(native_source_serials[0])
                if (
                    source_block is None
                    or int(source_block.nsucc()) != 2
                    or source_block.tail is None
                    or int(source_block.tail.opcode)
                    not in (int(ida_hexrays.m_jz), int(ida_hexrays.m_jnz))
                    or source_block.tail.d.t != ida_hexrays.mop_b
                    or transfer.predicate_true_is_taken is None
                ):
                    return None
                successors = tuple(int(serial) for serial in source_block.succset)
                taken = int(source_block.tail.d.b)
                if len(successors) != 2 or taken not in successors:
                    return None
                fallthrough = next(
                    serial for serial in successors if int(serial) != taken
                )
                if transfer.predicate_true_is_taken:
                    return taken, int(fallthrough)
                return int(fallthrough), taken

            conditional_handler_routes = _build_conditional_handler_state_routes(
                source.flow_graph,
                mutation_materialized_indirect_transfers,
                exact_handler_by_state=handler_targets,
                target_serial_resolver=resolve_live_target_serial,
                arm_source_serial_resolver=resolve_conditional_arm_sources,
            )
            materialized_state_routes = tuple(
                dict.fromkeys((*materialized_state_routes, *conditional_handler_routes))
            )
            route_state_candidates: dict[int, set[int]] = {}
            for route in materialized_state_routes:
                if (
                    route.source_handler_serial is None
                    or int(route.source_handler_serial)
                    != int(route.source_block_serial)
                    or not route.handler_exit_proven
                ):
                    continue
                route_source = source.flow_graph.get_block(
                    int(route.source_block_serial)
                )
                if route_source is None or not route_source.insn_snapshots:
                    continue
                predicate = route_source.insn_snapshots[-1]
                if not predicate.is_conditional_jump or int(predicate.ea) <= 0:
                    continue
                route_state_candidates.setdefault(int(predicate.ea), set()).add(
                    int(route.state_constant) & 0xFFFFFFFF
                )
            inherited_states_by_predicate_ea = {
                predicate_ea: next(iter(states))
                for predicate_ea, states in route_state_candidates.items()
                if len(states) == 1
            }
            conditional_bridges = recover_conditional_handler_bridge_transfers_from_mba(
                materialized_indirect_transfers,
                mba,
                inherited_states_by_predicate_ea=(inherited_states_by_predicate_ea),
            )
            if conditional_bridges:
                if isinstance(resolver_state, ResolverSessionState):
                    if resolver_state.native_preanalysis.merge_materialized_transfers(
                        resolver_state.native_key,
                        conditional_bridges,
                    ):
                        resolver_state.invalidate_current_mba_binding()
                    materialized_indirect_transfers = (
                        resolver_state.materialized_transfers
                    )
                else:
                    materialized_indirect_transfers = tuple(
                        dict.fromkeys(
                            (*materialized_indirect_transfers, *conditional_bridges)
                        )
                    )
                mutation_materialized_indirect_transfers = (
                    mutation_authoritative_materialized_transfers(
                        materialized_indirect_transfers
                    )
                )
        portable_state_route_evidence = ()
        if (
            materialized_computed_goto_profile
            and isinstance(resolver_state, ResolverSessionState)
            and current_identity_index is not None
        ):
            if (
                not imported_instruction_origins
                and prelim is not None
                and prelim.dispatch_map is not None
                and prelim.dispatcher_block_serial is not None
            ):
                native_dispatcher_region_serials = frozenset(
                    {
                        int(prelim.dispatcher_block_serial),
                        *(
                            int(serial)
                            for serial in prelim.dispatch_map.dispatcher_blocks
                        ),
                        *(
                            int(serial)
                            for serial in (
                                getattr(
                                    range_evidence,
                                    "condition_chain_blocks",
                                    (),
                                )
                                if range_evidence is not None
                                else ()
                            )
                        ),
                        *(
                            int(serial)
                            for serial in (
                                getattr(
                                    getattr(range_evidence, "decision_dag", None),
                                    "nodes",
                                    (),
                                )
                                if range_evidence is not None
                                else ()
                            )
                        ),
                    }
                )
                portable_dispatcher_region = (
                    _portable_materialized_dispatcher_region_identity(
                        native_dispatcher_region_serials,
                        current_identity_index,
                    )
                )
                if portable_dispatcher_region is not None:
                    changed = resolver_state.native_preanalysis.merge_portable_dispatcher_region_identity(
                        resolver_state.native_key,
                        portable_dispatcher_region,
                    )
                    logger.info(
                        "portable materialized dispatcher-region evidence: "
                        "blocks=%d intervals=%d changed=%s",
                        len(native_dispatcher_region_serials),
                        len(portable_dispatcher_region.native_ranges.intervals),
                        changed,
                    )
            if not imported_instruction_origins and materialized_state_routes:
                region_candidates_by_handler: dict[int, set[StableBlockIdentity]] = {}
                for state, region_identity in entry_route_region_identities.items():
                    handler_serial = handler_targets.get(int(state) & 0xFFFFFFFF)
                    if handler_serial is None:
                        continue
                    region_candidates_by_handler.setdefault(
                        int(handler_serial), set()
                    ).add(region_identity)
                source_handler_regions_by_serial = {
                    serial: next(iter(regions))
                    for serial, regions in region_candidates_by_handler.items()
                    if len(regions) == 1
                }
                portable_state_route_evidence = (
                    _portable_materialized_state_route_evidence(
                        materialized_state_routes,
                        current_identity_index,
                        source_handler_regions_by_serial=(
                            source_handler_regions_by_serial
                        ),
                    )
                )
                if portable_state_route_evidence:
                    changed = (
                        resolver_state.native_preanalysis.merge_portable_state_routes(
                            resolver_state.native_key,
                            portable_state_route_evidence,
                        )
                    )
                    resolver_evidence = (
                        resolver_state.native_preanalysis.resolver_evidence
                    )
                    stored_portable_routes = (
                        ()
                        if resolver_evidence is None
                        else resolver_evidence.state_routes
                    )
                    logger.info(
                        "portable materialized state-route evidence: "
                        "published=%d total=%d changed=%s",
                        len(portable_state_route_evidence),
                        len(stored_portable_routes),
                        changed,
                    )
            if _request_materialized_recovery_generated_restart(resolver_state):
                logger.info(
                    "portable dispatcher recovery staged GENERATED restart: "
                    "generation=%d",
                    int(resolver_state.evidence_generation),
                )
            resolver_evidence = resolver_state.native_preanalysis.resolver_evidence
            stored_portable_routes = (
                () if resolver_evidence is None else resolver_evidence.state_routes
            )
            rebound_portable_routes = _rebind_portable_materialized_state_routes(
                stored_portable_routes,
                current_identity_index,
                handler_by_state=handler_targets,
                flow_graph=source.flow_graph,
                imported_direct_boundary_evidence=(imported_direct_boundary_evidence),
                imported_instruction_origins=(imported_instruction_origins),
            )
            if rebound_portable_routes:
                materialized_state_routes = tuple(
                    dict.fromkeys(
                        (*materialized_state_routes, *rebound_portable_routes)
                    )
                )
            logger.info(
                "portable materialized state-route rebind: stored=%d rebound=%d "
                "live=%d",
                len(stored_portable_routes),
                len(rebound_portable_routes),
                len(materialized_state_routes),
            )
            stored_dispatcher_identity = (
                None
                if resolver_evidence is None
                else resolver_evidence.dispatcher_region_identity
            )
            unfiltered_rebound_dispatcher_region = (
                _rebind_portable_materialized_dispatcher_region(
                    stored_dispatcher_identity,
                    imported_native_eas_by_serial=imported_native_eas_by_serial,
                )
            )
            dispatcher_handler_overlap = frozenset(
                unfiltered_rebound_dispatcher_region & authoritative_handler_serials
            )
            if dispatcher_handler_overlap:
                logger.info(
                    "portable dispatcher/handler overlap: %s",
                    [
                        {
                            "block": (
                                f"blk{int(serial)}@"
                                f"0x{int(source.flow_graph.get_block(int(serial)).start_ea):X}"
                            ),
                            "native_eas": [
                                f"0x{int(ea):X}"
                                for ea in sorted(
                                    imported_native_eas_by_serial.get(
                                        int(serial), frozenset()
                                    )
                                )
                            ],
                        }
                        for serial in sorted(dispatcher_handler_overlap)
                    ],
                )
            rebound_dispatcher_region = frozenset(
                unfiltered_rebound_dispatcher_region - authoritative_handler_serials
            )
            if rebound_dispatcher_region:
                materialized_dispatcher_router_serials = frozenset(
                    {
                        *materialized_dispatcher_router_serials,
                        *rebound_dispatcher_region,
                    }
                )
            logger.info(
                "portable materialized dispatcher-region rebind: stored=%s "
                "rebound=%d live=%d",
                stored_dispatcher_identity is not None,
                len(rebound_dispatcher_region),
                len(materialized_dispatcher_router_serials),
            )
        residual_entry_bridge_evidence = (
            recognize_residual_entry_bridge(mba)
            if materialized_computed_goto_profile
            else None
        )
        imported_conditional_boundary_evidence = (
            imported_detached_snippet_conditional_boundary_evidence(mba)
            if materialized_computed_goto_profile
            else ()
        )
        if materialized_computed_goto_profile and logger.info_on:
            router_eas = {
                int(router_ea)
                for transfer in materialized_indirect_transfers
                for router_ea in transfer.dispatcher_router_eas
            }
            logger.info(
                "imported native-origin router blocks: origins=%d blocks=%s "
                "live_boundaries=%s",
                len(imported_instruction_origins),
                [
                    {
                        "block": (
                            f"blk{int(serial)}@"
                            f"0x{int(source.flow_graph.get_block(int(serial)).start_ea):X}"
                        ),
                        "router_eas": [
                            f"0x{int(ea):X}" for ea in sorted(native_eas & router_eas)
                        ],
                        "preds": [
                            (
                                f"blk{int(pred)}@"
                                f"0x{int(source.flow_graph.get_block(int(pred)).start_ea):X}"
                            )
                            for pred in source.flow_graph.get_block(int(serial)).preds
                        ],
                    }
                    for serial, native_eas in imported_native_eas_by_serial.items()
                    if native_eas & router_eas
                ],
                [
                    {
                        "block": (
                            f"blk{int(serial)}@"
                            f"0x{int(source.flow_graph.get_block(int(serial)).start_ea):X}"
                        ),
                        "native_range": (
                            f"0x{min(native_eas):X}-0x{max(native_eas):X}"
                        ),
                        "live_preds": [
                            (
                                f"blk{int(pred)}@"
                                f"0x{int(source.flow_graph.get_block(int(pred)).start_ea):X}"
                            )
                            for pred in source.flow_graph.get_block(int(serial)).preds
                            if int(pred) not in imported_native_eas_by_serial
                        ],
                    }
                    for serial, native_eas in imported_native_eas_by_serial.items()
                    if any(
                        int(pred) not in imported_native_eas_by_serial
                        for pred in source.flow_graph.get_block(int(serial)).preds
                    )
                ],
            )
        for load_ea in native_carrier_load_eas:
            if load_ea in native_carrier_consumer_serials_by_load_ea:
                continue
            authoritative_consumers = {
                int(serial)
                for serial, entry_ea in materialized_handler_entry_eas.items()
                if int(entry_ea) == int(load_ea)
            }
            if len(authoritative_consumers) == 1:
                native_carrier_consumer_serials_by_load_ea[load_ea] = next(
                    iter(authoritative_consumers)
                )
        if native_carrier_load_eas:
            logger.info(
                "native stack-carrier consumer ownership: resolved=%s unresolved=%s",
                {
                    f"0x{int(load_ea):X}": "blk%d@0x%X"
                    % (
                        int(serial),
                        int(source.flow_graph.get_block(serial).start_ea),
                    )
                    for load_ea, serial in sorted(
                        native_carrier_consumer_serials_by_load_ea.items()
                    )
                },
                [
                    f"0x{int(load_ea):X}"
                    for load_ea in native_carrier_load_eas
                    if load_ea not in native_carrier_consumer_serials_by_load_ea
                ],
            )
        if materialized_computed_goto_profile:
            logger.info(
                "imported boundary-port evidence: direct=%d conditional=%d "
                "predicates=%s",
                len(imported_direct_boundary_evidence),
                len(imported_conditional_boundary_evidence),
                [
                    "0x%X" % int(evidence.port.predicate_ea)
                    for evidence in imported_conditional_boundary_evidence
                ],
            )
        bound_bootstrap_routes = (
            _bound_bootstrap_route_bindings(resolver_state)
            if materialized_computed_goto_profile
            and isinstance(resolver_state, ResolverSessionState)
            else ()
        )
        analysis_seeds = {
            "range_evidence": range_evidence,
            "materialized_indirect_transfers": (
                mutation_materialized_indirect_transfers
            ),
            "imported_direct_boundary_evidence": (imported_direct_boundary_evidence),
            "imported_conditional_boundary_evidence": (
                imported_conditional_boundary_evidence
            ),
            "imported_native_eas_by_serial": imported_native_eas_by_serial,
            "current_block_identity_index": current_identity_index,
            "native_carrier_consumer_serials_by_load_ea": (
                native_carrier_consumer_serials_by_load_ea
            ),
            "materialized_state_routes": materialized_state_routes,
            "legacy_handler_by_state": legacy_handler_by_state,
            "materialized_handler_by_state": {
                int(state): int(serial) for state, serial in handler_targets.items()
            },
            "materialized_state_var_reg": materialized_state_var_reg,
            "materialized_handler_entry_eas": materialized_handler_entry_eas,
            "authoritative_handler_serials": authoritative_handler_serials,
            "portable_materialized_handler_identity_misses": (
                portable_materialized_handler_identity_misses
            ),
            "unmapped_materialized_handler_targets": (
                unmapped_materialized_handler_targets
            ),
            "materialized_dispatcher_entry_serial": (
                materialized_dispatcher_entry_serial
            ),
            "materialized_dispatcher_router_serials": (
                materialized_dispatcher_router_serials
            ),
            "residual_entry_bridge_evidence": residual_entry_bridge_evidence,
            "materialized_computed_goto_profile": bool(
                materialized_computed_goto_profile
            ),
        }
        if bound_bootstrap_routes:
            analysis_seeds["bound_bootstrap_routes"] = bound_bootstrap_routes
        facts = self._pass_manager.facts_for(
            source,
            input_facts=fact_view,
            analysis_seeds=analysis_seeds,
        )
        return (fact_view, prelim, range_evidence, analysis_seeds, facts)

    def _build_capabilities(
        self,
        mba: "ida_hexrays.mba_t",
        prelim,
        range_evidence,
        *,
        resolver_state: ResolverSessionState | None = None,
    ):
        """Assemble the live capability set the pass pipeline consumes."""
        _cfg = getattr(self, "config", None)
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
            getattr(range_evidence, "state_var_stkoff", None)
            if range_evidence is not None
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
        if isinstance(resolver_state, ResolverSessionState):
            semantic_evidence_provider = SessionCanonicalSemanticEvidenceProvider(
                function_ea=int(mba.entry_ea),
                native_key=resolver_state.native_key,
                state=resolver_state.native_preanalysis,
            )
            cap_instances[CanonicalSemanticEvidenceCapability] = (
                semantic_evidence_provider
            )
            cap_instances[CanonicalSemanticCandidateEvidenceCapability] = (
                semantic_evidence_provider
            )
            cap_instances[FrontendNormalizationEvidenceCapability] = (
                SessionFrontendNormalizationEvidenceProvider(
                    function_ea=int(mba.entry_ea),
                    native_key=resolver_state.native_key,
                    state=resolver_state.native_preanalysis,
                )
            )
            plan_provider = resolver_state.frontend_normalization_plan_provider
            if isinstance(
                plan_provider,
                FrontendNormalizationPlanCapability,
            ):
                cap_instances[FrontendNormalizationPlanCapability] = plan_provider
            if isinstance(
                plan_provider,
                FrontendNormalizationPreparedBodyCapability,
            ):
                cap_instances[FrontendNormalizationPreparedBodyCapability] = (
                    plan_provider
                )
            reference_oracle_provider = (
                resolver_state.semantic_route_reference_oracle_provider
            )
            if isinstance(
                reference_oracle_provider,
                SemanticRouteReferenceOracleCapability,
            ):
                cap_instances[SemanticRouteReferenceOracleCapability] = (
                    reference_oracle_provider
                )
        return CapabilitySet(cap_instances)

    def _select_family(
        self,
        mba: "ida_hexrays.mba_t",
        source,
        rule_config,
        backend,
        *,
        materialized_evidence_ready: bool = False,
        canonical_composition_ready: bool = False,
    ):
        """Poll the family registry (reduced-product bypass on opt-in). Returns family|None."""
        if materialized_evidence_ready and not self._uses_tigress_indirect_materialization(
            rule_config
        ):
            logger.info(
                "unflat: complete materialized identity resumes canonical fragment composition "
                "for func=0x%x at %s",
                int(mba.entry_ea),
                maturity_to_string(int(mba.maturity)),
            )
            return _MaterializedComputedGotoContinuationFamily()
        if canonical_composition_ready and not self._uses_tigress_indirect_materialization(
            rule_config
        ):
            logger.info(
                "unflat: partial canonical evidence resumes fragment composition "
                "for func=0x%x at %s",
                int(mba.entry_ea),
                maturity_to_string(int(mba.maturity)),
            )
            return _CanonicalComputedGotoCompositionFamily()

        # Route through the registered profiles (llr-ibpi): select_family polls the
        # StateMachineCffFamily registry (HodurFamily=equality-chain, ApproovFamily/
        # TigressFamily=switch/indirect) and returns the one whose detect claims this
        # graph; the selected profile's pipeline_for drives the pass manager. The rule's
        # JSON config is threaded so a project may override the choice via the
        # router_resolution policy (llr-11du); empty config preserves registration order.
        family = select_family(
            source.flow_graph,
            project_config=rule_config,
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
            isinstance(rule_config, dict)
            and rule_config.get("recovery_engine") == "reduced_product"
        ):
            if logger.debug_on:
                logger.debug(
                    "unflat: reduced_product family-gate bypass for func=0x%x at %s "
                    "(static select_family declined)",
                    int(mba.entry_ea),
                    maturity_to_string(int(mba.maturity)),
                )
            family = _ReducedProductBypassFamily()
        return family

    def _family_defers(
        self, mba: "ida_hexrays.mba_t", family, *, is_indirect: bool
    ) -> bool:
        """True when the selected family wants a DIFFERENT maturity (caller returns 0)."""
        # Fine per-family maturity gate (ticket llr-a93i): a profile recovers ONLY at one
        # of its declared ``recovery_maturities``. When a family claims this graph but not
        # at the CURRENT maturity, skip (return 0) and wait for the stage it wants -- the
        # dispatcher is not converged, so a later maturity still recovers it. INDIRECT
        # bypasses this gate: it is routed to MMAT_CALLS structurally above, independent of
        # the selected family's declaration.
        # A per-project ``recovery_maturity`` override (config-driven, ticket llr-a93i)
        # REPLACES the selected profile's declared maturities for this project; absent it,
        # the profile's own ``recovery_maturities`` apply.
        configured_maturities = self._config_recovery_maturities()
        _target_maturities = configured_maturities or self._family_recovery_maturities(
            family
        )
        deferred = bool(
            family is not None
            and not is_indirect
            and int(mba.maturity) not in _target_maturities
        )
        if family is not None:
            flow_context = getattr(self, "flow_context", None)
            report = getattr(flow_context, "report_fact_consumers", None)
            if callable(report):
                family_name = str(getattr(family, "name", "unknown"))
                report(
                    (
                        FactConsumerRecord(
                            consumer="state_machine_cff_unflattener",
                            strategy="family_maturity_admission",
                            fact_id=f"family:{family_name}",
                            maturity=maturity_to_string(int(mba.maturity)),
                            decision="declined" if deferred else "accepted",
                            reason=(
                                "family_maturity_deferred"
                                if deferred
                                else "family_maturity_admitted"
                            ),
                            payload={
                                "configured_override": bool(configured_maturities),
                                "current_maturity": int(mba.maturity),
                                "family_name": family_name,
                                "indirect_bypass": bool(is_indirect),
                                "target_maturities": sorted(
                                    int(maturity)
                                    for maturity in _target_maturities
                                ),
                            },
                        ),
                    )
                )
        if deferred:
            if logger.debug_on:
                logger.debug(
                    "unflat: family=%s defers func=0x%x at %s (wants %s)",
                    getattr(family, "name", "?"),
                    int(mba.entry_ea),
                    maturity_to_string(int(mba.maturity)),
                    sorted(maturity_to_string(m) for m in _target_maturities),
                )
            return True
        return False

    def _log_lisa_discovery_diff(self, flow_graph, prelim, range_evidence) -> None:
        """Compare the LiSA value-set dispatcher discovery to analyze_condition_chain_dispatcher (gap1 parity gate).

        Headline: does the fixpoint's exact-handler recovery (``handler_entry_by_state``) reach the condition-chain
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
                initial_state=getattr(range_evidence, "initial_state", None),
            )
        except Exception:  # noqa: BLE001 — the diff is diagnostics-only
            logger.debug("unflat: LiSA dispatcher discovery diff failed", exc_info=True)
            return
        logger.info(
            "unflat discover(LiSA): exact_handlers=%d range_handlers=%d head=%s | "
            "condition-chain handlers=%d state_var=0x%x initial=%s",
            len(view.handler_entry_by_state),
            len(view.handler_range_map),
            view.dispatcher_entry,
            len(getattr(range_evidence, "handler_state_map", {}) or {}),
            int(stkoff),
            getattr(range_evidence, "initial_state", None),
        )

    def _dual_build_read_dag_diff(
        self, source, dmap, range_evidence, dag_tr, func_ea, maturity
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
                initial_state=getattr(range_evidence, "initial_state", None),
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
            ) | frozenset(int(b) for b in view.condition_chain_blocks)
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
        self,
        mba,
        source,
        rec,
        tr,
        regions,
        fact_view,
        range_evidence=None,
        capabilities=None,
    ) -> None:
        "Populate the structured diag tables for the unflatten path (otherwise blind under the flag).\n\n        Two tiers:\n        * ``state_dispatcher_rows`` -- keyed by func_ea + maturity, no snapshot ref; mirrors the\n          backend's ``_observe_state_dispatcher_map``. Published whenever a preanalysis subscriber exists.\n        * ``block_classification`` / ``dag_edges`` / ``modifications`` -- snapshot-correlated, so they\n          need a capture snapshot. We capture from the portable ``source.flow_graph`` (the stable,\n          already-lifted graph the analyses ran on -- NOT the live mid-pipeline mba, which trips\n          ``snapshot_mba``) and rebuild the DAG/plan here. The rebuild is GATED on an installed\n          capture subscriber, so it only runs under ``--full-diagnostics``; production decompilation\n          never pays for it. Best-effort: any failure degrades to a debug log, never breaks optimize.\n"
        func_ea = int(getattr(mba, "entry_ea", 0) or 0)
        maturity = maturity_to_string(int(getattr(mba, "maturity", -1) or -1))
        dmap = getattr(rec, "dispatch_map", None) if rec is not None else None
        # A missing map used to look identical to a diagnostics failure: this
        # method returned before creating a snapshot, leaving no structured way
        # to distinguish "pipeline recovered nothing" from "rows were dropped".
        # Record the recovery status first. This is diagnostics-only and works
        # for stack, register, and materialized-indirect dispatchers alike.
        if source is not None and _capture_diagnostics_enabled():
            try:
                status_snap = request_capture_mba_snapshot(
                    blocks=_diag_blocks_from_flow_graph(source.flow_graph),
                    label="unflat_recovery_status",
                    func_ea=func_ea,
                    maturity=maturity,
                    phase="post_pipeline",
                )
                if status_snap is not None:
                    observe_fact_observation(
                        status_snap,
                        func_ea,
                        (
                            {
                                "fact_id": f"unflat-recovery-status:{func_ea:x}:{maturity}",
                                "kind": "UnflattenRecoveryStatus",
                                "semantic_key": "unflatten_recovery_status",
                                "maturity": maturity,
                                "phase": "post_pipeline",
                                "confidence": 1.0,
                                "source_block": getattr(
                                    rec, "dispatcher_block_serial", None
                                ),
                                "source_ea": None,
                                "block_fingerprint": None,
                                "mop_signature": None,
                                "payload": {
                                    "recovery_present": rec is not None,
                                    "dispatch_map_present": dmap is not None,
                                    "map_rows": len(getattr(dmap, "rows", ()) or ()),
                                    "dispatcher_entry": getattr(
                                        dmap, "dispatcher_entry_block", None
                                    ),
                                    "state_var_stkoff": getattr(
                                        rec, "state_var_stkoff", None
                                    ),
                                    "state_var_reg": getattr(
                                        rec, "state_var_reg", None
                                    ),
                                },
                                "evidence": (),
                            },
                        ),
                    )
            except Exception:  # noqa: BLE001 -- diagnostics must never change recovery
                logger.debug(
                    "unflat: recovery-status diagnostics failed", exc_info=True
                )
        if dmap is None:
            return
        if _preanalysis_diagnostics_enabled():
            try:
                observe_state_dispatcher_rows(
                    func_ea=func_ea,
                    maturity=maturity,
                    dispatcher_entry_block=int(dmap.dispatcher_entry_block),
                    dispatcher_kind=dmap.router_kind.name,
                    rows=dmap.rows,
                )
            except Exception:  # noqa: BLE001 — diagnostics must never break the optimize path
                logger.debug(
                    "unflat: observe_state_dispatcher_rows failed", exc_info=True
                )
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
                condition_chain_serials=tuple(
                    getattr(rec, "condition_chain_block_serials", ()) or ()
                ),
            )
            entry_serial = int(dmap.dispatcher_entry_block)
            # Pre-mutation condition-chain evidence (value-range dispatcher, handler ranges, pre-header/initial
            # state) recovered before the pipeline mutated the mba (passed in). DIAG-ONLY: validates
            # evidence-recovery WITHOUT touching production lowering, so a still-naive emission cannot
            # collapse the live output (llr-gp9d/mmfq/opck).
            condition_chain = range_evidence
            # Inc4 (llr-mmfq): measure the sound #2 StateTransitionDomain fixpoint against the ad-hoc
            # condition-chain walk + oracle BEFORE swapping it into the DAG. Pure logging, feeds nothing.
            if condition_chain is not None and fact_view is not None:
                self._unflat_fixpoint_probe(
                    source, condition_chain, fact_view, entry_serial, mba=mba, dmap=dmap
                )
            # Prefer the condition-chain-derived rich transition_result: it backfills handlers reachable only
            # through wide condition-chain range intervals (the range-backed states the exact-only unflatten #2 omits),
            # so the diag DAG node/edge counts approach the legacy oracle instead of being capped by
            # the shallow exact-chain transitions.
            dag_tr = tr
            if condition_chain is not None:
                try:
                    dag_tr = _convert_condition_chain_to_result(condition_chain)
                except Exception:  # noqa: BLE001 — fall back to the unflatten transition_result
                    dag_tr = tr
            if dag_tr is not None and getattr(dag_tr, "transitions", None):
                dag = build_live_linearized_state_dag_from_graph(
                    flow_graph=source.flow_graph,
                    transition_result=dag_tr,
                    dispatcher_entry_serial=entry_serial,
                    state_var_stkoff=dmap.state_var_stkoff,
                    condition_chain_blocks=(
                        tuple(
                            sorted(
                                int(b) for b in condition_chain.condition_chain_blocks
                            )
                        )
                        if condition_chain is not None
                        else ()
                    ),
                    handler_range_map=(
                        condition_chain.handler_range_map
                        if condition_chain is not None
                        else None
                    ),
                    dispatcher=(
                        condition_chain.dispatcher
                        if condition_chain is not None
                        else None
                    ),
                    pre_header_serial=(
                        condition_chain.pre_header_serial
                        if condition_chain is not None
                        else None
                    ),
                    initial_state=(
                        condition_chain.initial_state
                        if condition_chain is not None
                        else None
                    ),
                    mba=mba,
                    prefer_local_corridors=True,
                )
                observe_dag(snap, _diag_dag_nodes(dag), _diag_dag_edges(dag))
                observe_dag_local_facts(snap, dag)
                self._dual_build_read_dag_diff(
                    source, dmap, condition_chain, dag_tr, func_ea, maturity
                )
                # Feed the condition-chain-enriched DAG (built above) + the recovered condition-chain node set so the #4
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
                    condition_chain_blocks=(
                        tuple(
                            sorted(
                                int(b) for b in condition_chain.condition_chain_blocks
                            )
                        )
                        if condition_chain is not None
                        else None
                    ),
                    dispatcher=(
                        condition_chain.dispatcher
                        if condition_chain is not None
                        else None
                    ),
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
            logger.debug(
                "unflat: snapshot-correlated diagnostics failed", exc_info=True
            )

    def _unflat_fixpoint_probe(
        self,
        source,
        condition_chain,
        fact_view,
        dispatcher_entry: int,
        *,
        mba=None,
        dmap=None,
    ) -> None:
        """DIAG-ONLY: measure the sound #2 ``StateTransitionDomain`` fixpoint (llr-mmfq Inc4).

        Builds the value-set ``transition_result`` from the SAME per-block state-write evidence the
        fact view already carries (``StateWriteAnchor``) and the condition-chain handler map, then logs its
        conditional-transition count against the ad-hoc ``condition_chain.conditional_transitions`` walk (the diag
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
                for blk, state in condition_chain.handler_state_map.items()
                if blk not in condition_chain.condition_chain_blocks
            }

            def _succ(serial):
                blk = blocks.get(serial)
                return (
                    [int(x) for x in getattr(blk, "succs", ())]
                    if blk is not None
                    else []
                )

            def _pred(serial):
                blk = blocks.get(serial)
                return (
                    [int(x) for x in getattr(blk, "preds", ())]
                    if blk is not None
                    else []
                )

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

            condition_chain_cond_edges = sum(
                len(v) for v in (condition_chain.conditional_transitions or {}).values()
            )
            logger.info(
                "unflat #2 fixpoint-probe: fixpoint cond=%d (anchor-only=%d, concrete-folds=%d) "
                "uncond=%d total=%d handlers=%d writes=%d | condition_chain_walk cond_edges=%d | oracle cond=66",
                cond,
                cond_anchor,
                folded,
                len(fixpoint_tr.transitions) - cond,
                len(fixpoint_tr.transitions),
                len(handler_entry_by_state),
                len(refined_writes),
                condition_chain_cond_edges,
            )

            # S4 C1 shadow-diff (ticket llr-1szn): emit StateWriteTransition tuples from
            # the fixpoint's converged states THROUGH the same emission shell, and diff
            # per-back-edge against the production fold (recover_state_write_transitions).
            # Proves byte-equivalence where the fixpoint resolves a state + surfaces the
            # Case-2 opaque-XOR residual the flip (C) is gated on. Diagnostic only.
            state_var_stkoff = getattr(dmap, "state_var_stkoff", None)
            # Source the router the SAME way production does (the llr-oq8v resolver
            # chain): for the collapsed sub_7FFD condition-chain, condition_chain.dispatcher is None and the
            # exact state->handler map wins -- exactly what emit_minimal_unflatten uses.
            _dmap_rows = getattr(dmap, "rows", None) if dmap is not None else None
            dispatcher = select_router(
                default_resolvers(),
                RouterResolutionContext(
                    condition_chain_router=getattr(condition_chain, "dispatcher", None),
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
                        "unflat C1 mismatch rows[B1 multicell]: %s",
                        dmc["mismatch"][:20],
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
                        "unflat C1 mismatch rows[B2 partitioned]: %s",
                        dpp["mismatch"][:20],
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
        candidates = {int(p) for p in predecessors_of(int(dispatcher_entry))} - set(
            base_writes
        )
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
                "unflat #2 concrete-refine: candidates=%d folded=%d",
                len(candidates),
                folded,
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
                shared_suffix=(
                    json.dumps([int(s) for s in suffix]) if suffix else None
                ),
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
                source_block=(int(anchor.block_serial) if anchor is not None else None),
                source_arm=(int(branch_arm) if branch_arm is not None else None),
                target_entry=(int(target_entry) if target_entry is not None else None),
                ordered_path=json.dumps(
                    [int(s) for s in getattr(edge, "ordered_path", ())]
                ),
            )
        )
    return edges


def _diag_modifications(plan) -> list[_DiagModification]:
    mods: list[_DiagModification] = []
    for idx, mod in enumerate(getattr(plan, "steps", ())):
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
