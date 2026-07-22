"""PREOPT union delivery for resolver-proven computed-goto handler islands."""

from __future__ import annotations

import ida_hexrays

from d810.analyses.control_flow.detached_handler_island import (
    ConditionalHandlerBridgePlan,
    ConditionalHandlerTargetTopology,
    ConditionalRouteEvidence,
    conditional_bridge_pre_dce_target_eas,
    conditional_bridge_route_evidence_converged,
    DetachedHandlerIslandPlan,
    DetachedRouteEvidence,
    DetachedSnippetTerminalEvidence,
    plan_live_handler_template_replacements,
    plan_detached_snippet_routes,
    plan_detached_snippet_terminal_routes,
    plan_conditional_handler_bridges,
    select_detached_source_path,
    select_boundary_owned_terminal_source_blocks,
    select_unique_block_native_ea,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    is_conditional_handler_bridge_kind,
    materialized_terminal_target_eas_by_source,
    plan_residual_state_route_bridges,
    unique_materialized_equality_target_eas,
)
from d810.backends.hexrays.evidence.detached_handler_island import (
    recognize_detached_handler_island,
)
from d810.backends.hexrays.evidence.residual_entry_bridge import (
    recognize_conditional_handler_bridges,
)
from d810.core.logging import getLogger
from d810.core.project import register_project_reload_cleanup
from d810.hexrays.mutation import (
    detached_handler_island as detached_handler_island_mutation,
)
from d810.hexrays.mutation.detached_handler_island import (
    capture_call_result_carriers,
    capture_detached_handler_call_templates,
    clear_detached_handler_call_templates,
    clear_imported_detached_snippet_roots,
    clear_terminal_return_carrier_templates,
    detached_snippet_conditional_evidence,
    detached_snippet_template_block_eas,
    detached_snippet_template_generation,
    detached_snippet_replacement_evidence,
    detached_snippet_replacement_arm_states,
    find_unique_live_block_by_ea,
    find_unique_live_block_by_native_ea,
    has_instruction_backed_native_block,
    has_detached_snippet_template,
    has_detached_replacement_snippet_template,
    imported_detached_snippet_direct_boundary_evidence,
    imported_detached_snippet_target_eas,
    imported_detached_snippet_instruction_origins,
    materialize_detached_handler_island,
    materialize_preopt_union_snippet_templates,
    materialize_detached_replacement_snippet_templates,
    materialize_detached_snippet_templates,
    refine_transient_terminal_return_type,
    reconcile_imported_callinfo_with_live_native_calls,
    redirect_live_target_predecessors,
    restore_call_result_carriers,
    restore_detached_call_result_definitions,
    restore_terminal_return_carriers,
    stable_mba_identity,
)
from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
from d810.hexrays.mutation.mba_mutation_events import MbaMutationGateway
from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.transforms.graph_modification import SyntheticRegisterNonzeroCondition
from d810.hexrays.preanalysis.calls_done_preanalysis import (
    register_calls_done_preanalysis_handler,
    unregister_calls_done_preanalysis_handler,
)
from d810.hexrays.preanalysis.locopt_preanalysis import (
    register_locopt_preanalysis_handler,
    unregister_locopt_preanalysis_handler,
)
from d810.hexrays.preanalysis.preopt_preanalysis import (
    register_preopt_preanalysis_handler,
    unregister_preopt_preanalysis_handler,
)
from d810.optimizers.microcode.flow.handler import (
    FlowOptimizationRule,
    FlowRulePriority,
)
from d810.optimizers.microcode.flow.jumps.computed_goto_resolver import (
    get_prepared_preopt_union_closure,
    is_computed_goto_materialized,
    recover_conditional_handler_bridge_transfers_from_mba,
)
from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
    ResolverSessionState,
    resolver_session_state,
)

logger = getLogger("D810.optimizer.materialized_computed_goto_island")
_CALLS_HANDLER_NAME = "materialized_computed_goto_island.calls_done"
_LOCOPT_HANDLER_NAME = "materialized_computed_goto_island.locopt"
_PREOPT_HANDLER_NAME = "materialized_computed_goto_island.preopt"
_PROJECT_CLEANUP_NAME = "materialized_computed_goto_island"


def _block_instruction_eas(block: object) -> tuple[int, ...]:
    instruction_eas: list[int] = []
    instruction = block.head
    while instruction is not None:
        instruction_eas.append(int(instruction.ea))
        if instruction is block.tail:
            break
        instruction = instruction.next
    return tuple(instruction_eas)


def _boundary_owned_terminal_source_blocks(
    mba: object,
    terminal_origins: tuple[tuple[int, int], ...],
) -> frozenset[int]:
    """Find terminal sources whose incoming edges were all redirected.

    Applied direct-port evidence is authoritative only for its exact endpoint
    and old-successor topology.  The predecessor-subset check keeps an
    uncovered sibling path eligible for the legacy resolver fallback.
    """
    applied = imported_detached_snippet_direct_boundary_evidence(mba)
    if not applied:
        return frozenset()

    endpoint_blocks_by_old_successor: dict[int, set[int]] = {}
    for evidence in applied:
        port = evidence.port
        if port.delivery_mode != "redirect_edge" or not port.old_successor_eas:
            continue
        for old_successor_ea in port.old_successor_eas:
            endpoint_blocks_by_old_successor.setdefault(
                int(old_successor_ea),
                set(),
            )
        endpoint_blocks = {
            int(block.serial): block
            for anchor_ea in evidence.endpoint_anchor_eas
            for block in (
                find_unique_live_block_by_ea(
                    mba,
                    int(anchor_ea),
                    exact_instruction_ea=int(anchor_ea),
                ),
            )
            if block is not None
        }
        if len(endpoint_blocks) != 1:
            endpoint = find_unique_live_block_by_ea(
                mba,
                int(port.endpoint_block_ea),
            )
            endpoint_blocks = (
                {} if endpoint is None else {int(endpoint.serial): endpoint}
            )
        if len(endpoint_blocks) != 1:
            continue
        endpoint_serial = next(iter(endpoint_blocks))
        for old_successor_ea in port.old_successor_eas:
            endpoint_blocks_by_old_successor.setdefault(
                int(old_successor_ea),
                set(),
            ).add(int(endpoint_serial))
    if not endpoint_blocks_by_old_successor:
        return frozenset()

    instruction_origins = dict(imported_detached_snippet_instruction_origins(mba))
    source_native_ea_by_block: dict[int, int] = {}
    predecessor_blocks_by_source: dict[int, frozenset[int]] = {}
    for imported_exit_ea, _native_exit_ea in terminal_origins:
        source = find_unique_live_block_by_ea(mba, int(imported_exit_ea))
        if source is None:
            continue
        source_serial = int(source.serial)
        imported_instruction_eas = _block_instruction_eas(source)
        native_instruction_eas = tuple(
            int(instruction_origins.get(int(ea), int(ea)))
            for ea in imported_instruction_eas
        )
        native_block_ea = select_unique_block_native_ea(
            int(instruction_origins.get(int(source.start), int(source.start))),
            native_instruction_eas,
        )
        if native_block_ea is None:
            continue
        source_native_ea_by_block[source_serial] = int(native_block_ea)
        predecessor_blocks_by_source[source_serial] = frozenset(
            int(predecessor) for predecessor in source.predset
        )

    selected = select_boundary_owned_terminal_source_blocks(
        source_native_ea_by_block=source_native_ea_by_block,
        predecessor_blocks_by_source=predecessor_blocks_by_source,
        redirect_endpoint_blocks_by_old_successor_ea={
            native_ea: frozenset(endpoint_blocks)
            for native_ea, endpoint_blocks in (endpoint_blocks_by_old_successor.items())
        },
    )
    if selected:
        logger.info(
            "detached terminal fallback suppressed by applied boundary ports: "
            "sources=%s",
            [
                f"blk{serial}@0x{source_native_ea_by_block[serial]:X}"
                for serial in sorted(selected)
            ],
        )
    return selected


def _capture_calls_done_templates(
    *,
    function_ea: int,
    mba: object,
    decision: object,
) -> None:
    del decision
    capture_detached_handler_call_templates(int(function_ea), mba)


def _disable_calls_done_capture() -> None:
    unregister_calls_done_preanalysis_handler(_CALLS_HANDLER_NAME)
    unregister_locopt_preanalysis_handler(_LOCOPT_HANDLER_NAME)
    unregister_preopt_preanalysis_handler(_PREOPT_HANDLER_NAME)
    clear_detached_handler_call_templates()
    clear_terminal_return_carrier_templates()


def _preopt_union_import_key(function_ea: int, mba: object) -> tuple[int, int, int]:
    return (
        int(function_ea),
        stable_mba_identity(mba),
        detached_snippet_template_generation(int(function_ea)),
    )


def _preopt_union_generation_was_processed(
    state: ResolverSessionState,
    function_ea: int,
    mba: object,
) -> bool:
    key = _preopt_union_import_key(function_ea, mba)
    return (
        key in state.preopt_union_imported_mbas
        or key in state.preopt_union_mutated_mbas
    )


def _preopt_union_owns_mba(
    state: ResolverSessionState,
    function_ea: int,
    mba: object,
) -> bool:
    """Whether this live MBA is already owned by any PREOPT union generation."""
    ownership_key = (int(function_ea), stable_mba_identity(mba))
    return any(
        key[:2] == ownership_key
        for key in (
            *state.preopt_union_imported_mbas,
            *state.preopt_union_mutated_mbas,
        )
    )


def _record_preopt_modification(
    decision: dict[str, object],
    **details: object,
) -> None:
    current_details = decision.get("details")
    merged_details = dict(current_details) if isinstance(current_details, dict) else {}
    merged_details.update(details)
    decision["microcode_modified"] = True
    decision["details"] = merged_details


def _restore_preopt_terminal_return_carriers(
    *,
    function_ea: int,
    mba: object,
    decision: dict[str, object],
) -> None:
    """Restore carriers, then import one prepared union before LOCOPT/CALLS."""
    restored = restore_terminal_return_carriers(mba, int(function_ea))
    return_type_refined = refine_transient_terminal_return_type(
        mba,
        int(function_ea),
    )
    if restored > 0 or return_type_refined:
        _record_preopt_modification(
            decision,
            terminal_return_carriers=int(restored),
            terminal_return_type_refined=bool(return_type_refined),
        )
        logger.info(
            "PREOPT restored %d terminal return carrier(s) and refined_return=%s "
            "before local and call analysis",
            int(restored),
            bool(return_type_refined),
        )

    session = decision.get("session")
    if session is None:
        return
    try:
        state = resolver_session_state(session)
    except (TypeError, ValueError):
        return

    preparation = get_prepared_preopt_union_closure(state)
    if (
        preparation is None
        or not preparation.prepared
        or not preparation.published
        or preparation.primary_seed_ea is None
        or state.preopt_union_import_active
        or _preopt_union_generation_was_processed(state, int(function_ea), mba)
    ):
        return

    primary_seed_ea = int(preparation.primary_seed_ea)
    mutation_gateway = decision.get("mutation_gateway")
    if not isinstance(mutation_gateway, MbaMutationGateway):
        logger.info(
            "PREOPT union import skipped: func=0x%X reason=mutation_gateway",
            int(function_ea),
        )
        return
    qty_before_import = int(mba.qty)
    state.preopt_union_import_active = True
    try:
        imported = materialize_preopt_union_snippet_templates(
            mba,
            int(function_ea),
            (primary_seed_ea,),
            mutation_gateway=mutation_gateway,
        )
    finally:
        state.preopt_union_import_active = False
    qty_after_import = int(mba.qty)
    requested_roots = {primary_seed_ea}
    expected_boundary_ports = len(state.boundary_ports.direct) + len(
        state.boundary_ports.conditional
    )
    seed_eas = preparation.seed_eas or (primary_seed_ea,)
    missing_instruction_backed_seed_eas = tuple(
        int(seed_ea)
        for seed_ea in seed_eas
        if not has_instruction_backed_native_block(mba, int(seed_ea))
    )
    seeds_are_instruction_backed = not missing_instruction_backed_seed_eas
    logger.info(
        "PREOPT union import result: func=0x%X roots=%s applied=%d "
        "expected=%d abstained=%d seeds_instruction_backed=%s",
        int(function_ea),
        tuple(hex(int(root_ea)) for root_ea in imported),
        len(imported.applied_boundary_ports),
        expected_boundary_ports,
        len(imported.abstained_boundary_ports),
        seeds_are_instruction_backed,
    )
    if (
        set(imported) != requested_roots
        or len(imported.applied_boundary_ports) != expected_boundary_ports
        or imported.abstained_boundary_ports
        or not seeds_are_instruction_backed
    ):
        logger.info(
            "PREOPT union import abstained: func=0x%X primary=0x%X "
            "roots=%s applied_ports=%d expected_ports=%d "
            "abstained_ports=%d instruction_backed_seeds=%s",
            int(function_ea),
            primary_seed_ea,
            [hex(int(root_ea)) for root_ea in imported],
            len(imported.applied_boundary_ports),
            expected_boundary_ports,
            len(imported.abstained_boundary_ports),
            seeds_are_instruction_backed,
        )
        block_delta = qty_after_import - qty_before_import
        if block_delta != 0:
            state.preopt_union_mutated_mbas.add(
                _preopt_union_import_key(int(function_ea), mba)
            )
            _record_preopt_modification(
                decision,
                preopt_union_post_mutation_abstention=True,
                preopt_union_block_delta=int(block_delta),
                preopt_union_imported_roots=tuple(int(root_ea) for root_ea in imported),
                preopt_union_applied_boundary_ports=len(
                    imported.applied_boundary_ports
                ),
                preopt_union_expected_boundary_ports=expected_boundary_ports,
                preopt_union_abstained_boundary_ports=len(
                    imported.abstained_boundary_ports
                ),
                preopt_union_instruction_backed_seeds=seeds_are_instruction_backed,
                preopt_union_missing_instruction_backed_seed_eas=(
                    missing_instruction_backed_seed_eas
                ),
            )
            logger.error(
                "PREOPT union import abstained after mutating the live MBA; "
                "legacy fallback suppressed: func=0x%X block_delta=%d",
                int(function_ea),
                int(block_delta),
            )
        return

    state.bind_current_imported_instruction_origins(
        stable_mba_identity(mba),
        tuple(imported_detached_snippet_instruction_origins(mba)),
    )
    state.preopt_union_imported_mbas.add(
        _preopt_union_import_key(int(function_ea), mba)
    )
    state.native_preanalysis.mark_preopt_bound()
    _record_preopt_modification(
        decision,
        preopt_union_root_ea=primary_seed_ea,
        preopt_union_seed_count=len(seed_eas),
        preopt_union_boundary_port_count=expected_boundary_ports,
    )
    logger.info(
        "PREOPT union import succeeded: func=0x%X primary=0x%X "
        "seeds=%s boundary_ports=%d bound_generation=%d",
        int(function_ea),
        primary_seed_ea,
        [hex(int(seed_ea)) for seed_ea in seed_eas],
        expected_boundary_ports,
        int(state.native_preanalysis.bound_preopt_generation or 0),
    )


def _candidate_plans(
    state: ResolverSessionState,
) -> tuple[DetachedHandlerIslandPlan, ...]:
    transfers = state.materialized_transfers
    state_registers = {
        int(transfer.selector_state_var_reg)
        for transfer in transfers
        if transfer.resolver_kind == "static_equality_fixpoint"
        and transfer.selector_state_var_reg is not None
    }
    if len(state_registers) != 1:
        return ()
    state_register = next(iter(state_registers))
    state_targets = tuple(
        sorted(
            unique_materialized_equality_target_eas(
                transfers,
                state_register,
            ).items()
        )
    )
    if not state_targets:
        return ()

    residual_routes = tuple(
        DetachedRouteEvidence(
            source_predicate_ea=int(transfer.source_jmp_ea),
            detached_entry_ea=int(transfer.target_eas[0]),
        )
        for transfer in transfers
        if transfer.resolver_kind == "residual_state_route"
        and len(transfer.target_eas) == 1
    )
    conditional_routes = tuple(
        ConditionalRouteEvidence(
            source_predicate_ea=int(transfer.source_jmp_ea),
            condition_code=int(transfer.condition_code),
            true_target_ea=int(transfer.true_target_ea),
            false_target_ea=int(transfer.false_target_ea),
        )
        for transfer in transfers
        if is_conditional_handler_bridge_kind(transfer.resolver_kind)
        and transfer.condition_code is not None
        and transfer.true_target_ea is not None
        and transfer.false_target_ea is not None
    )

    plans: list[DetachedHandlerIslandPlan] = []
    for residual in residual_routes:
        source_path = select_detached_source_path(
            residual_routes=(residual,),
            conditional_routes=conditional_routes,
        )
        if source_path is None or source_path.detached_is_true:
            continue
        plan = recognize_detached_handler_island(
            source_path=source_path,
            state_register=state_register,
            state_targets=state_targets,
        )
        if plan is not None and plan not in plans:
            plans.append(plan)
    return tuple(plans)


def _candidate_conditional_bridge_plans(
    state: ResolverSessionState,
) -> tuple[ConditionalHandlerBridgePlan, ...]:
    transfers = state.materialized_transfers
    if not conditional_bridge_route_evidence_converged(transfers):
        return ()
    state_registers = {
        int(transfer.selector_state_var_reg)
        for transfer in transfers
        if transfer.resolver_kind == "static_equality_fixpoint"
        and transfer.selector_state_var_reg is not None
    }
    if len(state_registers) != 1:
        return ()
    state_register = next(iter(state_registers))
    state_targets = unique_materialized_equality_target_eas(
        transfers,
        state_register,
    )
    if not state_targets:
        return ()
    return plan_conditional_handler_bridges(
        transfers,
        state_targets=state_targets,
        state_register=state_register,
        state_size=4,
    )


def _apply_residual_state_route_bridges(
    mba: object,
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    mutation_gateway: MbaMutationGateway,
) -> int:
    """Redirect live one-way state-write exits to resolver-proven handlers."""
    evidence = tuple(
        transfer
        for transfer in transfers
        if transfer.resolver_kind == "residual_state_route_evidence"
    )
    if not evidence:
        return 0
    live_blocks_by_ea: dict[int, int] = {}
    one_way_sources: set[int] = set()
    for transfer in evidence:
        source = find_unique_live_block_by_ea(
            mba,
            int(transfer.source_jmp_ea),
        )
        if source is not None:
            live_blocks_by_ea[int(transfer.source_jmp_ea)] = int(source.serial)
            if int(source.nsucc()) == 1:
                one_way_sources.add(int(source.serial))
        for target_ea in transfer.target_eas:
            target = find_unique_live_block_by_native_ea(mba, int(target_ea))
            if target is not None:
                live_blocks_by_ea[int(target_ea)] = int(target.serial)
    plans = plan_residual_state_route_bridges(
        evidence,
        live_blocks_by_ea=live_blocks_by_ea,
        one_way_source_blocks=frozenset(one_way_sources),
    )
    if not plans:
        return 0
    boundary_owned_routes: set[tuple[int, int, int]] = set()
    for applied in imported_detached_snippet_direct_boundary_evidence(mba):
        port = applied.port
        if (
            port.delivery_mode != "redirect_edge"
            or port.resolver_kind != "residual_state_route_evidence"
            or port.state_constant is None
        ):
            continue
        endpoint_blocks = {
            int(block.serial): block
            for anchor_ea in applied.endpoint_anchor_eas
            for block in (
                find_unique_live_block_by_ea(
                    mba,
                    int(anchor_ea),
                    exact_instruction_ea=int(anchor_ea),
                ),
            )
            if block is not None
        }
        if len(endpoint_blocks) != 1:
            endpoint = find_unique_live_block_by_ea(
                mba,
                int(port.endpoint_block_ea),
            )
            endpoint_blocks = (
                {} if endpoint is None else {int(endpoint.serial): endpoint}
            )
        if len(endpoint_blocks) != 1:
            continue
        boundary_owned_routes.add(
            (
                next(iter(endpoint_blocks)),
                int(port.state_constant),
                int(port.target_ea),
            )
        )
    actionable_plans = tuple(
        plan
        for plan in plans
        if (
            int(plan.source_block_serial),
            int(plan.state_constant),
            int(plan.target_ea),
        )
        not in boundary_owned_routes
    )
    if len(actionable_plans) != len(plans):
        logger.info(
            "legacy residual routes suppressed by applied PREOPT ports: rows=%s",
            [
                (
                    f"blk{int(plan.source_block_serial)}@0x{int(plan.source_write_ea):X}",
                    f"0x{int(plan.state_constant):X}",
                    f"0x{int(plan.target_ea):X}",
                )
                for plan in plans
                if (
                    int(plan.source_block_serial),
                    int(plan.state_constant),
                    int(plan.target_ea),
                )
                in boundary_owned_routes
            ],
        )
    if not actionable_plans:
        return 0
    modifier = DeferredGraphModifier(
        mba,
        mutation_gateway=mutation_gateway.new_transaction(),
    )
    for plan in actionable_plans:
        source = mba.get_mblock(int(plan.source_block_serial))
        if (
            source is None
            or int(source.nsucc()) != 1
            or int(source.succset[0]) == int(plan.target_block_serial)
        ):
            continue
        modifier.queue_goto_change(
            block_serial=int(plan.source_block_serial),
            new_target=int(plan.target_block_serial),
            description=(
                f"residual state route 0x{int(plan.source_write_ea):X} "
                f"state=0x{int(plan.state_constant):X} -> "
                f"0x{int(plan.target_ea):X}"
            ),
            rule_priority=1000,
        )
    return int(modifier.apply(defer_post_apply_maintenance=True))


def _apply_detached_snippet_terminal_routes(
    mba: object,
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    mutation_gateway: MbaMutationGateway,
) -> int:
    """Replace imported terminal m_ijmps with exact resolver-target edges."""
    terminal_origins = (
        detached_handler_island_mutation.imported_detached_snippet_terminal_origins(mba)
    )
    state_registers = {
        int(transfer.selector_state_var_reg)
        for transfer in transfers
        if transfer.resolver_kind
        in {
            "condition_chain_handler_evidence",
            "static_equality_fixpoint",
        }
        and transfer.selector_state_var_reg is not None
    }
    if len(state_registers) == 1:
        resolver_targets = materialized_terminal_target_eas_by_source(
            transfers,
            next(iter(state_registers)),
        )
    else:
        resolver_target_sets: dict[int, set[int]] = {}
        for transfer in transfers:
            if transfer.resolver_kind not in (
                "static_fixpoint",
                "detached_static_fixpoint",
            ):
                continue
            resolver_target_sets.setdefault(int(transfer.source_jmp_ea), set()).update(
                int(target_ea) for target_ea in transfer.target_eas
            )
        resolver_targets = {
            native_exit_ea: tuple(sorted(targets))
            for native_exit_ea, targets in resolver_target_sets.items()
        }
    origin_set = {
        (int(imported_exit_ea), int(native_exit_ea))
        for imported_exit_ea, native_exit_ea in terminal_origins
    }
    for native_exit_ea, target_eas in resolver_targets.items():
        if len(target_eas) != 1:
            continue
        source = find_unique_live_block_by_ea(mba, int(native_exit_ea))
        tail = None if source is None else source.tail
        if (
            source is None
            or int(source.nsucc()) != 0
            or tail is None
            or int(tail.opcode) != int(ida_hexrays.m_ijmp)
            or int(tail.ea) != int(native_exit_ea)
        ):
            continue
        origin_set.add((int(native_exit_ea), int(native_exit_ea)))
    terminal_origins = tuple(sorted(origin_set))
    if not terminal_origins:
        return 0
    source_blocks_by_imported_ea: dict[int, int] = {}
    target_blocks_by_ea: dict[int, int] = {}
    zero_way_source_blocks: set[int] = set()
    for imported_exit_ea, native_exit_ea in terminal_origins:
        source = find_unique_live_block_by_ea(mba, int(imported_exit_ea))
        if source is not None:
            source_blocks_by_imported_ea[int(imported_exit_ea)] = int(source.serial)
            if int(source.nsucc()) == 0:
                zero_way_source_blocks.add(int(source.serial))
        for target_ea in resolver_targets.get(int(native_exit_ea), ()):
            target = find_unique_live_block_by_ea(mba, int(target_ea))
            if target is not None:
                target_blocks_by_ea[int(target_ea)] = int(target.serial)
    already_routed_source_blocks = _boundary_owned_terminal_source_blocks(
        mba,
        terminal_origins,
    )
    plans = plan_detached_snippet_terminal_routes(
        tuple(
            DetachedSnippetTerminalEvidence(
                imported_exit_ea=int(imported_exit_ea),
                native_exit_ea=int(native_exit_ea),
            )
            for imported_exit_ea, native_exit_ea in terminal_origins
        ),
        resolver_targets=resolver_targets,
        source_blocks_by_imported_ea=source_blocks_by_imported_ea,
        target_blocks_by_ea=target_blocks_by_ea,
        zero_way_source_blocks=frozenset(zero_way_source_blocks),
        already_routed_source_blocks=already_routed_source_blocks,
    )
    logger.info(
        "detached terminal route planner: origins=%s resolver_targets=%s "
        "source_blocks=%s target_blocks=%s plans=%s",
        [(hex(imported), hex(native)) for imported, native in terminal_origins],
        {
            hex(native): [hex(target) for target in targets]
            for native, targets in resolver_targets.items()
            if native in {native for _imported, native in terminal_origins}
        },
        {hex(ea): serial for ea, serial in source_blocks_by_imported_ea.items()},
        {hex(ea): serial for ea, serial in target_blocks_by_ea.items()},
        [
            (
                plan.source_block_serial,
                plan.target_block_serial,
                hex(plan.native_exit_ea),
                hex(plan.target_ea),
            )
            for plan in plans
        ],
    )
    if not plans:
        return 0
    modifier = DeferredGraphModifier(
        mba,
        mutation_gateway=mutation_gateway.new_transaction(),
    )
    for plan in plans:
        modifier.queue_terminal_goto_change(
            block_serial=int(plan.source_block_serial),
            goto_target=int(plan.target_block_serial),
            description=(
                f"detached snippet native exit 0x{int(plan.native_exit_ea):X} "
                f"-> 0x{int(plan.target_ea):X}"
            ),
            priority=5,
        )
    return int(modifier.apply(defer_post_apply_maintenance=True))


def _apply_live_resolver_cut_counterparts(
    mba: object,
    *,
    mutation_gateway: MbaMutationGateway,
) -> int:
    """Rebind imported resolver-cut terminal ports to exact native sources.

    The detached-snippet importer applies each direct boundary port to the
    imported copy.  When the native source still survives in the regenerated
    MBA, the same portable evidence must also close that counterpart; otherwise
    the original zero-way ``m_ijmp`` remains reachable beside its routed copy.
    """
    candidates_by_source: dict[int, set[tuple[int, int, int, int]]] = {}
    for evidence in imported_detached_snippet_direct_boundary_evidence(mba):
        port = evidence.port
        if str(port.delivery_mode) != "terminal_goto":
            continue
        source_ea = int(port.source_instruction_ea)
        target_ea = int(port.target_ea)
        source = find_unique_live_block_by_ea(mba, source_ea)
        target = find_unique_live_block_by_ea(mba, target_ea)
        tail = None if source is None else source.tail
        if (
            source is None
            or target is None
            or int(source.nsucc()) != 0
            or tail is None
            or int(tail.opcode) != int(ida_hexrays.m_ijmp)
            or int(tail.ea) != source_ea
        ):
            continue
        candidates_by_source.setdefault(source_ea, set()).add(
            (
                int(source.serial),
                int(target.serial),
                source_ea,
                target_ea,
            )
        )

    plans: list[tuple[int, int, int, int]] = []
    claimed_source_serials: set[int] = set()
    for source_ea, candidates in sorted(candidates_by_source.items()):
        if len(candidates) != 1:
            logger.warning(
                "refusing ambiguous native resolver-cut counterpart at 0x%X: %s",
                source_ea,
                sorted(candidates),
            )
            continue
        candidate = next(iter(candidates))
        source_serial = int(candidate[0])
        if source_serial in claimed_source_serials:
            logger.warning(
                "refusing duplicate native resolver-cut source blk%d@0x%X",
                source_serial,
                source_ea,
            )
            continue
        claimed_source_serials.add(source_serial)
        plans.append(candidate)

    if not plans:
        return 0
    modifier = DeferredGraphModifier(
        mba,
        mutation_gateway=mutation_gateway.new_transaction(),
    )
    for source_serial, target_serial, source_ea, target_ea in plans:
        modifier.queue_terminal_goto_change(
            block_serial=source_serial,
            goto_target=target_serial,
            description=(
                f"native resolver-cut counterpart blk{source_serial}@0x{source_ea:X} "
                f"-> blk{target_serial}@0x{target_ea:X}"
            ),
            priority=5,
        )
    return int(modifier.apply(transactional=True, staged_atomic=True))


def _materialize_missing_detached_snippets(
    mba: object,
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    mutation_gateway: MbaMutationGateway,
    require_live_residual_source: bool = True,
    expected_template_maturity: int | None = None,
    allow_raw_preopt_calls: bool = False,
    import_native_preopt_ranges: bool = False,
) -> int:
    """Import exact missing targets before source-scoped routes are applied."""
    live_eas: set[int] = set()
    live_target_eas: set[int] = set()
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        if int(block.start) > 0:
            live_eas.add(int(block.start))
        instruction_eas: list[int] = []
        instruction = block.head
        while instruction is not None:
            if int(instruction.ea) > 0:
                live_eas.add(int(instruction.ea))
                instruction_eas.append(int(instruction.ea))
            if instruction is block.tail:
                break
            instruction = instruction.next
        if instruction_eas:
            if int(block.start) > 0:
                live_target_eas.add(int(block.start))
            target_ea = select_unique_block_native_ea(
                int(block.start),
                tuple(instruction_eas),
            )
            if target_ea is not None:
                live_target_eas.add(int(target_ea))
    imported_targets = imported_detached_snippet_target_eas(mba)
    live_eas.update(imported_targets)
    live_target_eas.update(imported_targets)
    plans = plan_detached_snippet_routes(
        transfers,
        live_eas=frozenset(live_eas),
        live_target_eas=frozenset(live_target_eas),
    )
    plans = tuple(
        plan
        for plan in plans
        if has_detached_snippet_template(
            int(mba.entry_ea),
            int(plan.target_ea),
        )
    )
    logger.info(
        "detached snippet LOCOPT planner: func=0x%X transfers=%d live_eas=%d plans=%s",
        int(mba.entry_ea),
        len(transfers),
        len(live_eas),
        [
            (
                hex(int(plan.source_ea)),
                hex(int(plan.target_ea)),
                hex(int(plan.state_constant)),
                plan.evidence_kind,
            )
            for plan in plans
        ],
    )
    if not plans:
        return 0
    admissible_plans = []
    for plan in plans:
        source = find_unique_live_block_by_ea(mba, int(plan.source_ea))
        if (
            require_live_residual_source
            and plan.evidence_kind == "residual_state_route_evidence"
            and (source is None or int(source.nsucc()) != 1)
        ):
            logger.info(
                "detached snippet LOCOPT evidence skipped: source=0x%X "
                "target=0x%X kind=%s block=%s",
                int(plan.source_ea),
                int(plan.target_ea),
                plan.evidence_kind,
                (
                    None
                    if source is None
                    else (
                        int(source.serial),
                        hex(int(source.start)),
                    )
                ),
            )
            continue
        admissible_plans.append(plan)
    plans = tuple(admissible_plans)
    target_eas = tuple(dict.fromkeys(int(plan.target_ea) for plan in plans))
    if not target_eas:
        return 0
    roots = materialize_detached_snippet_templates(
        mba,
        int(mba.entry_ea),
        target_eas,
        mutation_gateway=mutation_gateway,
        expected_template_maturity=expected_template_maturity,
        allow_raw_preopt_calls=allow_raw_preopt_calls,
        import_native_preopt_ranges=import_native_preopt_ranges,
    )
    if set(roots) != set(target_eas):
        logger.info(
            "detached snippet LOCOPT import abstained: requested=%s roots=%s",
            [hex(int(target_ea)) for target_ea in target_eas],
            {hex(int(ea)): int(serial) for ea, serial in roots.items()},
        )
        return 0
    return len(roots)


def _materialize_live_handler_replacements(
    mba: object,
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    state: ResolverSessionState,
    mutation_gateway: MbaMutationGateway,
) -> int:
    """Restore a cached two-arm handler after LOCOPT folded its predicate."""
    function_ea = int(mba.entry_ea)
    if not is_computed_goto_materialized(state):
        logger.info(
            "CALLS live-handler replacement abstained: func=0x%X "
            "reason=profile_not_materialized",
            function_ea,
        )
        return 0
    state_registers = {
        int(transfer.selector_state_var_reg)
        for transfer in transfers
        if transfer.resolver_kind == "static_equality_fixpoint"
        and transfer.selector_state_var_reg is not None
    }
    if len(state_registers) != 1:
        logger.info(
            "CALLS live-handler replacement abstained: func=0x%X "
            "reason=state_register_count registers=%s",
            function_ea,
            sorted(state_registers),
        )
        return 0
    state_targets = unique_materialized_equality_target_eas(
        transfers,
        next(iter(state_registers)),
    )
    imported_targets = frozenset(imported_detached_snippet_target_eas(mba))
    candidate_targets = tuple(sorted(set(int(ea) for ea in state_targets.values())))
    candidate_rows = tuple(
        (
            int(target_ea),
            int(target_ea) in imported_targets,
            has_detached_replacement_snippet_template(function_ea, target_ea),
        )
        for target_ea in candidate_targets
    )
    logger.info(
        "CALLS live-handler replacement candidates: func=0x%X "
        "state_register=%d states=%d imported=%s candidates=%s",
        function_ea,
        next(iter(state_registers)),
        len(state_targets),
        [hex(ea) for ea in sorted(imported_targets)],
        [
            (hex(target_ea), imported, cached)
            for target_ea, imported, cached in candidate_rows
        ],
    )
    evidence = tuple(
        row
        for target_ea in candidate_targets
        if target_ea not in imported_targets
        and has_detached_replacement_snippet_template(function_ea, target_ea)
        for row in (detached_snippet_replacement_evidence(function_ea, target_ea),)
        if row is not None
    )
    if not evidence:
        return 0

    complete_live_branch_eas = frozenset(
        int(row.predicate_ea)
        for row in recognize_conditional_handler_bridges(
            mba,
            state_register=next(iter(state_registers)),
            state_targets=state_targets,
        )
    )
    resolver_target_sets: dict[int, set[int]] = {}
    for transfer in transfers:
        if transfer.resolver_kind not in (
            "static_fixpoint",
            "detached_static_fixpoint",
        ):
            continue
        resolver_target_sets.setdefault(int(transfer.source_jmp_ea), set()).update(
            int(target_ea) for target_ea in transfer.target_eas
        )
    plans = plan_live_handler_template_replacements(
        evidence,
        state_targets=state_targets,
        complete_live_branch_eas=complete_live_branch_eas,
        resolver_targets={
            source_ea: tuple(sorted(targets))
            for source_ea, targets in resolver_target_sets.items()
        },
    )
    logger.info(
        "CALLS live-handler replacement planner: func=0x%X evidence=%s plans=%s",
        function_ea,
        [
            (
                hex(int(row.target_ea)),
                hex(int(row.conditional_branch_ea)),
                [hex(int(ea)) for ea in row.terminal_exit_eas],
                bool(row.calls_verify_safe),
            )
            for row in evidence
        ],
        [
            (
                hex(int(plan.target_ea)),
                [hex(int(state)) for state in plan.selector_states],
                hex(int(plan.conditional_branch_ea)),
                [
                    (hex(int(source_ea)), hex(int(target_ea)))
                    for source_ea, target_ea in plan.terminal_routes
                ],
            )
            for plan in plans
        ],
    )
    if not plans:
        return 0
    old_target_serials: dict[int, int] = {}
    import_only_targets: set[int] = set()
    for plan in plans:
        target_ea = int(plan.target_ea)
        old_target = find_unique_live_block_by_ea(mba, target_ea)
        if old_target is None:
            logger.info(
                "CALLS live-handler replacement import abstained: "
                "target=0x%X reason=old_live_target_missing",
                target_ea,
            )
            return 0
        predecessor_serials = tuple(int(serial) for serial in old_target.predset)
        if not predecessor_serials:
            logger.info(
                "CALLS live-handler replacement import-only: "
                "target=0x%X old=blk%d@0x%X reason=no_live_predecessors",
                target_ea,
                int(old_target.serial),
                target_ea,
            )
            import_only_targets.add(target_ea)
            continue
        for predecessor_serial in predecessor_serials:
            predecessor = mba.get_mblock(predecessor_serial)
            if (
                predecessor is None
                or int(predecessor.serial) == 0
                or int(predecessor.nsucc()) != 1
                or int(predecessor.succset[0]) != int(old_target.serial)
            ):
                logger.info(
                    "CALLS live-handler replacement import abstained: "
                    "target=0x%X old=blk%d@0x%X predecessor=%s "
                    "reason=predecessor_not_exact_one_way",
                    target_ea,
                    int(old_target.serial),
                    target_ea,
                    (
                        "missing"
                        if predecessor is None
                        else "blk%d@0x%X"
                        % (int(predecessor.serial), int(predecessor.start))
                    ),
                )
                return 0
        old_target_serials[target_ea] = int(old_target.serial)
    roots = materialize_detached_replacement_snippet_templates(
        mba,
        function_ea,
        tuple(int(plan.target_ea) for plan in plans),
        mutation_gateway=mutation_gateway,
    )
    requested = {int(plan.target_ea) for plan in plans}
    if set(roots) != requested:
        logger.info(
            "CALLS live-handler replacement import abstained: requested=%s roots=%s",
            [hex(ea) for ea in sorted(requested)],
            {hex(int(ea)): int(serial) for ea, serial in roots.items()},
        )
        return 0
    redirect_map = {
        int(old_target_serials[target_ea]): int(root_serial)
        for target_ea, root_serial in roots.items()
        if target_ea in old_target_serials
    }
    redirected = (
        redirect_live_target_predecessors(
            mba,
            redirect_map,
            mutation_gateway=mutation_gateway,
        )
        if redirect_map
        else 0
    )
    if redirect_map and redirected <= 0:
        logger.info(
            "CALLS live-handler replacement import abstained after import: "
            "targets=%s reason=predecessor_redirect_failed",
            [hex(ea) for ea in sorted(requested)],
        )
        return 0
    logger.info(
        "CALLS live-handler replacement connected: roots=%s redirects=%d "
        "import_only=%s",
        {
            hex(int(target_ea)): "blk%d@0x%X" % (int(root_serial), int(target_ea))
            for target_ea, root_serial in roots.items()
        },
        int(redirected),
        [hex(int(target_ea)) for target_ea in sorted(import_only_targets)],
    )
    released_keeps = _release_replaced_native_handler_keeps(
        mba,
        tuple(sorted(requested)),
    )
    if released_keeps:
        logger.info(
            "CALLS live-handler replacement released native MBL_KEEP roots: %s",
            [
                "blk%d@0x%X" % (int(serial), int(start_ea))
                for serial, start_ea in released_keeps
            ],
        )
    return len(roots)


def _release_replaced_native_handler_keeps(
    mba: object,
    target_eas: tuple[int, ...],
) -> tuple[tuple[int, int], ...]:
    """Release capture-only KEEP flags after exact handler replacement.

    LOCOPT marks native detached corridors ``MBL_KEEP`` so their microcode can
    be captured before DCE.  Once a verified replacement template has been
    imported, those native blocks are stale.  Clear KEEP only when a block is
    both owned by one replaced template and unreachable from the MBA entry;
    imported synthetic roots and unrelated/reachable KEEP roots remain intact.
    Hex-Rays' normal global sweep can then remove the stale native island.
    """
    protected_eas = {
        int(block_ea)
        for target_ea in target_eas
        for block_ea in detached_snippet_template_block_eas(
            int(mba.entry_ea),
            int(target_ea),
        )
    }
    if not protected_eas or int(mba.qty) <= 0:
        return ()

    reachable: set[int] = {0}
    pending = [0]
    for serial in pending:
        block = mba.get_mblock(int(serial))
        if block is None:
            continue
        for successor in block.succset:
            successor = int(successor)
            if successor in reachable or not 0 <= successor < int(mba.qty):
                continue
            reachable.add(successor)
            pending.append(successor)

    released: list[tuple[int, int]] = []
    for serial in range(int(mba.qty)):
        if serial in reachable:
            continue
        block = mba.get_mblock(serial)
        if block is None or not (int(block.flags) & int(ida_hexrays.MBL_KEEP)):
            continue
        block_eas = {int(block.start)}
        instruction = block.head
        while instruction is not None:
            block_eas.add(int(instruction.ea))
            if instruction is block.tail:
                break
            instruction = instruction.next
        if block_eas.isdisjoint(protected_eas):
            continue
        block.flags &= ~int(ida_hexrays.MBL_KEEP)
        block.mark_lists_dirty()
        released.append((int(block.serial), int(block.start)))
    if released:
        mba.mark_chains_dirty()
    return tuple(released)


def _recover_imported_conditional_bridge_transfers(
    mba: object,
    transfers: tuple[MaterializedIndirectTransfer, ...],
    *,
    state: ResolverSessionState,
) -> tuple[MaterializedIndirectTransfer, ...]:
    """Publish live imported predicates before terminal routing folds them."""
    origins = imported_detached_snippet_instruction_origins(mba)
    if not origins:
        return transfers
    state_registers = {
        int(transfer.selector_state_var_reg)
        for transfer in transfers
        if transfer.resolver_kind
        in {
            "condition_chain_handler_evidence",
            "static_equality_fixpoint",
        }
        and transfer.selector_state_var_reg is not None
    }
    if len(state_registers) != 1:
        return transfers
    state_register = next(iter(state_registers))
    state_targets = unique_materialized_equality_target_eas(
        transfers,
        state_register,
    )
    native_arm_states: dict[int, tuple[int, int]] = {}
    for target_ea in sorted(set(int(ea) for ea in state_targets.values())):
        if not has_detached_snippet_template(
            int(mba.entry_ea),
            target_ea,
        ):
            continue
        evidence = detached_snippet_conditional_evidence(
            int(mba.entry_ea),
            target_ea,
        )
        if evidence is None:
            continue
        states = detached_snippet_replacement_arm_states(
            int(mba.entry_ea),
            target_ea,
            state_register=state_register,
            conditional_branch_ea=int(evidence.conditional_branch_ea),
            conditional_target_eas=tuple(
                int(ea) for ea in evidence.conditional_target_eas
            ),
        )
        if states is not None:
            native_arm_states[int(evidence.conditional_branch_ea)] = states
    arm_states_by_imported_predicate = {
        int(imported_ea): (
            int(native_arm_states[int(native_ea)][1]),
            int(native_arm_states[int(native_ea)][0]),
        )
        for imported_ea, native_ea in origins
        if int(native_ea) in native_arm_states
    }
    logger.info(
        "CALLS imported conditional bridge join: native=%s imported=%s",
        {
            hex(predicate_ea): tuple(hex(state) for state in states)
            for predicate_ea, states in native_arm_states.items()
        },
        {
            hex(predicate_ea): tuple(hex(state) for state in states)
            for predicate_ea, states in arm_states_by_imported_predicate.items()
        },
    )
    produced = recover_conditional_handler_bridge_transfers_from_mba(
        transfers,
        mba,
        imported_predicate_eas=frozenset(
            int(imported_ea) for imported_ea, _native_ea in origins
        ),
        arm_states_by_predicate_ea=arm_states_by_imported_predicate,
    )
    if not produced:
        native_by_imported = {
            int(imported_ea): int(native_ea) for imported_ea, native_ea in origins
        }
        candidate_rows: list[tuple[object, ...]] = []
        for serial in range(int(mba.qty)):
            block = mba.get_mblock(serial)
            tail = block.tail
            if (
                tail is None
                or int(tail.ea) not in native_by_imported
                or int(tail.opcode)
                not in (int(ida_hexrays.m_jz), int(ida_hexrays.m_jnz))
            ):
                continue
            successors: list[tuple[object, ...]] = []
            for successor_serial in block.succset:
                successor = mba.get_mblock(int(successor_serial))
                instructions: list[tuple[str, str]] = []
                instruction = successor.head
                while instruction is not None:
                    instructions.append(
                        (
                            hex(
                                native_by_imported.get(
                                    int(instruction.ea),
                                    int(instruction.ea),
                                )
                            ),
                            str(instruction),
                        )
                    )
                    if instruction is successor.tail:
                        break
                    instruction = instruction.next
                successor_anchor = (
                    instructions[0][0] if instructions else hex(int(successor.start))
                )
                successors.append(
                    (
                        f"blk{int(successor.serial)}@{successor_anchor}",
                        instructions,
                    )
                )
            candidate_rows.append(
                (
                    f"blk{int(block.serial)}@0x{native_by_imported[int(tail.ea)]:X}",
                    (
                        int(tail.opcode),
                        int(tail.l.t),
                        int(tail.l.size),
                        int(tail.r.t),
                        int(tail.r.size),
                        int(tail.d.t),
                        (
                            int(tail.d.b)
                            if int(tail.d.t) == int(ida_hexrays.mop_b)
                            else None
                        ),
                        tuple(int(serial) for serial in block.succset),
                        arm_states_by_imported_predicate.get(int(tail.ea)),
                    ),
                    successors,
                )
            )
        logger.info(
            "CALLS imported conditional bridge abstained: candidates=%s",
            candidate_rows,
        )
        return transfers
    if state.native_preanalysis.merge_materialized_transfers(
        state.native_key,
        produced,
    ):
        state.invalidate_current_mba_binding()
    merged = state.materialized_transfers
    native_by_imported = {
        int(imported_ea): int(native_ea) for imported_ea, native_ea in origins
    }
    logger.info(
        "CALLS imported conditional bridge evidence: predicates=%s",
        [
            (
                hex(int(transfer.source_jmp_ea)),
                hex(native_by_imported.get(int(transfer.source_jmp_ea), 0)),
                hex(int(transfer.predicate_false_state)),
                hex(int(transfer.false_target_ea)),
                hex(int(transfer.predicate_true_state)),
                hex(int(transfer.true_target_ea)),
            )
            for transfer in produced
            if transfer.predicate_false_state is not None
            and transfer.false_target_ea is not None
            and transfer.predicate_true_state is not None
            and transfer.true_target_ea is not None
        ],
    )
    return merged


def _materialize_locopt_preanalysis(
    *,
    function_ea: int,
    mba: object,
    decision: dict[str, object],
) -> None:
    """Import already-LOCOPT snippets before Hex-Rays performs call analysis.

    The ``hxe_locopt`` callback is not a global-optimization restart seam.
    Returning ``MERR_LOOP`` from it aborts decompilation (INTERR 50443).  The
    imported templates have already completed local optimization, so they can
    join the current MBA and proceed directly into call analysis.
    """
    session = decision.get("session")
    if session is None:
        return
    try:
        state = resolver_session_state(session)
    except (TypeError, ValueError):
        return
    mutation_gateway = decision.get("mutation_gateway")
    if not isinstance(mutation_gateway, MbaMutationGateway):
        logger.info(
            "LOCOPT preanalysis skipped: func=0x%X reason=mutation_gateway",
            int(function_ea),
        )
        return
    transfers = state.materialized_transfers
    imported = _materialize_missing_detached_snippets(
        mba,
        transfers,
        mutation_gateway=mutation_gateway,
        require_live_residual_source=False,
        expected_template_maturity=int(ida_hexrays.MMAT_LOCOPT),
    )
    if imported <= 0:
        return
    decision["microcode_modified"] = True
    decision["details"] = {
        "imported_snippets": int(imported),
        "residual_bridges": 0,
    }
    logger.info(
        "LOCOPT preanalysis materialized %d detached snippet root(s) before "
        "call analysis; continuing without a maturity restart",
        int(imported),
    )


def _keep_cached_detached_snippet_blocks(
    mba: object,
    transfers: tuple[MaterializedIndirectTransfer, ...],
) -> int:
    """Keep exact detached corridors while they are still visible at LOCOPT."""
    target_eas: set[int] = set()
    for transfer in transfers:
        if (
            transfer.resolver_kind == "residual_state_route_evidence"
            and len(transfer.target_eas) == 1
        ):
            target_eas.add(int(transfer.target_eas[0]))
            continue
        if (
            transfer.resolver_kind != "static_equality_fixpoint"
            or transfer.condition_code not in (4, 5)
        ):
            continue
        target_ea = (
            transfer.true_target_ea
            if transfer.condition_code == 4
            else transfer.false_target_ea
        )
        if target_ea is not None and int(target_ea) in transfer.target_eas:
            target_eas.add(int(target_ea))

    protected_eas = {
        int(block_ea)
        for target_ea in target_eas
        for block_ea in detached_snippet_template_block_eas(
            int(mba.entry_ea),
            int(target_ea),
        )
    }
    kept = 0
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        block_eas = {int(block.start)}
        instruction = block.head
        while instruction is not None:
            block_eas.add(int(instruction.ea))
            if instruction is block.tail:
                break
            instruction = instruction.next
        if block_eas.isdisjoint(protected_eas):
            continue
        if int(block.flags) & int(ida_hexrays.MBL_KEEP):
            continue
        block.flags |= int(ida_hexrays.MBL_KEEP)
        block.mark_lists_dirty()
        kept += 1
    if kept:
        mba.mark_chains_dirty()
    return kept


def _apply_conditional_bridge_plans(
    mba: object,
    plans: tuple[ConditionalHandlerBridgePlan, ...],
    *,
    state: ResolverSessionState,
    mutation_gateway: MbaMutationGateway,
) -> int:
    """Apply exact live-predicate bridges through the deferred CFG mutator."""
    transfers = state.materialized_transfers
    target_topologies = _conditional_bridge_target_topologies(
        mba,
        plans,
        transfers,
    )
    imported_target_eas = frozenset(imported_detached_snippet_target_eas(mba))

    applied = 0
    for plan in sorted(
        plans,
        key=lambda candidate: int(candidate.source_predicate_ea),
        reverse=True,
    ):
        if (
            plan.predicate_compare_register is not None
            or plan.predicate_compare_constant is not None
        ):
            logger.info(
                "conditional bridge staged for live comparison: predicate=0x%X",
                int(plan.source_predicate_ea),
            )
            continue
        detached_target_eas = conditional_bridge_pre_dce_target_eas(
            plan,
            target_topologies=target_topologies,
            imported_target_eas=imported_target_eas,
        )
        if not detached_target_eas:
            logger.info(
                "conditional bridge not needed: predicate=0x%X "
                "reason=no_router_only_multiblock_target",
                int(plan.source_predicate_ea),
            )
            continue
        if plan.state_register is None or int(plan.state_size) <= 0:
            logger.info(
                "conditional bridge queue abstained: predicate=0x%X "
                "reason=state_register_missing",
                int(plan.source_predicate_ea),
            )
            continue
        false_state = int(plan.false_state)
        true_state = int(plan.true_state)
        false_state_write_ea = None
        true_state_write_ea = None
        terminal_exit_bridges: list[tuple[int, int, int]] = []
        arm_state_proof_failed = False
        for target_ea in detached_target_eas:
            if int(target_ea) in imported_target_eas:
                continue
            topology = target_topologies[int(target_ea)]
            dominant_write = _dominant_target_state_write(
                mba,
                target_ea=int(target_ea),
                dispatcher_serial=int(topology.dispatcher_block),
                state_register=int(plan.state_register),
                state_size=int(plan.state_size),
            )
            if dominant_write is None:
                arm_state_proof_failed = True
                break
            write_ea, state_value = dominant_write
            terminal_exit = _linear_detached_target_exit(
                mba,
                target_ea=int(target_ea),
                dispatcher_serial=int(topology.dispatcher_block),
            )
            if terminal_exit is not None:
                exit_serial, exit_ea = terminal_exit
                terminal_exit_bridges.append(
                    (
                        int(exit_serial),
                        int(topology.dispatcher_block),
                        int(exit_ea),
                    )
                )
            if int(target_ea) == int(plan.false_target_ea):
                false_state = int(state_value)
                false_state_write_ea = int(write_ea)
            elif int(target_ea) == int(plan.true_target_ea):
                true_state = int(state_value)
                true_state_write_ea = int(write_ea)
            else:
                arm_state_proof_failed = True
                break
        if arm_state_proof_failed:
            logger.info(
                "conditional bridge queue abstained: predicate=0x%X "
                "reason=detached_target_state_write_unproven",
                int(plan.source_predicate_ea),
            )
            continue
        source = find_unique_live_block_by_ea(mba, int(plan.source_predicate_ea))
        false_target = find_unique_live_block_by_ea(mba, int(plan.false_target_ea))
        true_target = find_unique_live_block_by_ea(mba, int(plan.true_target_ea))
        if (
            source is None
            or false_target is None
            or true_target is None
            or source.tail is None
            or int(source.tail.ea) != int(plan.source_predicate_ea)
            or int(source.nsucc()) not in (1, 2)
            or int(false_target.serial) == int(true_target.serial)
        ):
            logger.info(
                "conditional bridge queue abstained: predicate=0x%X "
                "false=0x%X true=0x%X",
                int(plan.source_predicate_ea),
                int(plan.false_target_ea),
                int(plan.true_target_ea),
            )
            continue
        old_dispatcher = int(source.succset[0])
        modifier = DeferredGraphModifier(
            mba,
            mutation_gateway=mutation_gateway.new_transaction(),
        )
        for exit_serial, dispatcher_serial, exit_ea in terminal_exit_bridges:
            modifier.queue_terminal_goto_change(
                block_serial=exit_serial,
                goto_target=dispatcher_serial,
                description=(
                    f"materialized target exit 0x{exit_ea:X} -> "
                    f"dispatcher for predicate 0x{int(plan.source_predicate_ea):X}"
                ),
                priority=5,
            )
        modifier.queue_lower_conditional_state_transition(
            source_serial=int(source.serial),
            old_dispatcher_serial=old_dispatcher,
            rewrite_from_ea=int(plan.source_predicate_ea),
            condition_operand=SyntheticRegisterNonzeroCondition(
                predicate_reg=int(plan.predicate_register),
                predicate_size=int(plan.predicate_size),
            ),
            false_target_serial=int(false_target.serial),
            true_target_serial=int(true_target.serial),
            state_register=plan.state_register,
            state_size=int(plan.state_size),
            false_state=false_state,
            true_state=true_state,
            false_state_write_ea=false_state_write_ea,
            true_state_write_ea=true_state_write_ea,
            proof_id=f"materialized_conditional_bridge:0x{int(plan.source_predicate_ea):X}",
            description=(
                f"materialized conditional bridge 0x{int(plan.source_predicate_ea):X} "
                f"-> 0x{int(plan.false_target_ea):X}/0x{int(plan.true_target_ea):X}"
            ),
            rule_priority=1000,
        )
        applied += int(modifier.apply(defer_post_apply_maintenance=True))
    return applied


def _dominant_target_state_write(
    mba: object,
    *,
    target_ea: int,
    dispatcher_serial: int,
    state_register: int,
    state_size: int,
) -> tuple[int, int] | None:
    """Find the last constant state write on a target's linear entry prefix."""
    block = find_unique_live_block_by_ea(mba, int(target_ea))
    if block is None:
        return None
    visited: set[int] = set()
    result: tuple[int, int] | None = None
    while int(block.serial) not in visited and len(visited) < 32:
        serial = int(block.serial)
        if serial == int(dispatcher_serial):
            break
        visited.add(serial)
        instruction = block.head
        while instruction is not None:
            if (
                int(instruction.opcode) == int(ida_hexrays.m_mov)
                and int(instruction.d.t) == int(ida_hexrays.mop_r)
                and int(instruction.d.r) == int(state_register)
                and int(instruction.d.size) == int(state_size)
                and int(instruction.l.t) == int(ida_hexrays.mop_n)
                and int(instruction.l.size) == int(state_size)
            ):
                result = (
                    int(instruction.ea),
                    int(instruction.l.nnn.value) & ((1 << (8 * int(state_size))) - 1),
                )
            if instruction is block.tail:
                break
            instruction = instruction.next
        if int(block.nsucc()) != 1:
            break
        successor_serial = int(block.succset[0])
        if successor_serial == int(dispatcher_serial):
            break
        successor = mba.get_mblock(successor_serial)
        if successor is None:
            return None
        block = successor
    return result


def _linear_detached_target_exit(
    mba: object,
    *,
    target_ea: int,
    dispatcher_serial: int,
) -> tuple[int, int] | None:
    """Find a 0-way indirect exit on a target's unique linear corridor."""
    block = find_unique_live_block_by_ea(mba, int(target_ea))
    if block is None:
        return None
    visited: set[int] = set()
    while int(block.serial) not in visited and len(visited) < 32:
        serial = int(block.serial)
        if serial == int(dispatcher_serial):
            return None
        visited.add(serial)
        if int(block.nsucc()) == 0:
            tail = block.tail
            if tail is not None and int(tail.opcode) == int(ida_hexrays.m_ijmp):
                return serial, int(tail.ea)
            return None
        if int(block.nsucc()) != 1:
            return None
        successor_serial = int(block.succset[0])
        if successor_serial == int(dispatcher_serial):
            return None
        successor = mba.get_mblock(successor_serial)
        if successor is None:
            return None
        block = successor
    return None


def _conditional_bridge_target_topologies(
    mba: object,
    plans: tuple[ConditionalHandlerBridgePlan, ...],
    transfers: tuple[MaterializedIndirectTransfer, ...],
) -> dict[int, ConditionalHandlerTargetTopology]:
    """Project exact equality leaves onto live LOCOPT target topology.

    The equality resolver supplies both the payload target and the common
    dispatcher fallback.  A topology is admitted only when all matching
    resolver records identify one live router block and one live dispatcher
    block for the target.
    """
    planned_targets = {
        int(target_ea)
        for plan in plans
        for target_ea in (plan.false_target_ea, plan.true_target_ea)
    }
    planned_states_by_target: dict[int, set[int]] = {}
    for plan in plans:
        planned_states_by_target.setdefault(int(plan.false_target_ea), set()).add(
            int(plan.false_state) & 0xFFFFFFFF
        )
        planned_states_by_target.setdefault(int(plan.true_target_ea), set()).add(
            int(plan.true_state) & 0xFFFFFFFF
        )
    route_owners: dict[int, set[int]] = {}
    dispatchers: dict[int, set[int]] = {}
    for transfer in transfers:
        if transfer.resolver_kind == "static_equality_fixpoint":
            targets = tuple(int(target_ea) for target_ea in transfer.target_eas)
            if len(targets) != 2 or targets[0] == targets[1]:
                continue
            for target_ea in targets:
                if target_ea not in planned_targets:
                    continue
                dispatcher_ea = targets[1] if target_ea == targets[0] else targets[0]
                router = find_unique_live_block_by_ea(
                    mba,
                    int(transfer.source_jmp_ea),
                )
                if router is None:
                    # Byte-patch materialization can consume the terminal
                    # register-indirect jump before LOCOPT.  The resolver's
                    # source-block anchor remains live and identifies the same
                    # equality leaf without reconstructing native semantics.
                    router = find_unique_live_block_by_ea(
                        mba,
                        int(transfer.source_block_ea),
                    )
                target = find_unique_live_block_by_ea(mba, target_ea)
                dispatcher = find_unique_live_block_by_ea(mba, dispatcher_ea)
                if target is None or dispatcher is None:
                    continue
                dispatchers.setdefault(target_ea, set()).add(int(dispatcher.serial))
                if router is not None:
                    route_owners.setdefault(target_ea, set()).add(int(router.serial))
            continue
        if (
            transfer.resolver_kind != "residual_state_route"
            or transfer.selector_state_constant is None
            or len(transfer.target_eas) != 1
        ):
            continue
        target_ea = int(transfer.target_eas[0])
        state = int(transfer.selector_state_constant) & 0xFFFFFFFF
        if (
            target_ea not in planned_targets
            or state not in planned_states_by_target.get(target_ea, set())
        ):
            continue
        route_owner = find_unique_live_block_by_ea(
            mba,
            int(transfer.source_jmp_ea),
        )
        if route_owner is None:
            continue
        route_owners.setdefault(target_ea, set()).add(int(route_owner.serial))

    topologies: dict[int, ConditionalHandlerTargetTopology] = {}
    for target_ea in sorted(planned_targets):
        dispatcher_candidates = dispatchers.get(target_ea, set())
        if len(dispatcher_candidates) != 1:
            continue
        target = find_unique_live_block_by_ea(mba, target_ea)
        if target is None:
            continue
        predecessors = tuple(int(serial) for serial in target.predset)
        matching_owners = set(predecessors).intersection(
            route_owners.get(target_ea, set())
        )
        if len(matching_owners) != 1:
            continue
        router_serial = next(iter(matching_owners))
        dispatcher_serial = next(iter(dispatcher_candidates))
        topologies[target_ea] = ConditionalHandlerTargetTopology(
            target_ea=target_ea,
            router_block=router_serial,
            dispatcher_block=dispatcher_serial,
            predecessor_blocks=predecessors,
            successor_blocks=tuple(int(serial) for serial in target.succset),
        )
    return topologies


class MaterializedComputedGotoIslandRule(FlowOptimizationRule):
    """Import one resolver-proven PREOPT union before LOCOPT drops it."""

    NAME = "MaterializedComputedGotoIslandRule"
    DESCRIPTION = "Materializes a proven detached computed-goto handler island"
    CATEGORY = "Indirect Jumps"
    USES_DEFERRED_CFG = True
    SAFE_MATURITIES = None
    # Imported predicate/handler evidence must be connected before the generic
    # state-machine pass classifies unmatched states as terminal exits.
    PRIORITY = int(FlowRulePriority.UNFLATTEN) + 50

    def __init__(self) -> None:
        super().__init__()
        self.maturities = [ida_hexrays.MMAT_LOCOPT, ida_hexrays.MMAT_CALLS]

    def configure(self, kwargs: object) -> None:
        super().configure(kwargs)
        unregister_calls_done_preanalysis_handler(_CALLS_HANDLER_NAME)
        unregister_locopt_preanalysis_handler(_LOCOPT_HANDLER_NAME)
        clear_detached_handler_call_templates()
        register_preopt_preanalysis_handler(
            _PREOPT_HANDLER_NAME,
            _restore_preopt_terminal_return_carriers,
        )
        register_project_reload_cleanup(
            _PROJECT_CLEANUP_NAME,
            _disable_calls_done_capture,
        )

    def reset_pass_manager_state(self) -> None:
        state = self.current_resolver_session_state()
        if isinstance(state, ResolverSessionState):
            state.attempted_mbas.clear()
        clear_imported_detached_snippet_roots()

    def optimize(self, blk: object) -> int:
        mba = blk.mba
        maturity = int(mba.maturity)
        if maturity not in (
            int(ida_hexrays.MMAT_LOCOPT),
            int(ida_hexrays.MMAT_CALLS),
        ):
            return 0
        function_ea = int(mba.entry_ea)
        state = self.current_resolver_session_state()
        if not isinstance(state, ResolverSessionState):
            return 0
        flow_context = self.flow_context
        mutation_gateway = (
            None if flow_context is None else flow_context.new_mba_mutation_gateway()
        )
        if not isinstance(mutation_gateway, MbaMutationGateway):
            logger.info(
                "computed-goto island abstained: func=0x%X reason=mutation_gateway",
                function_ea,
            )
            return 0
        mba_identity = (
            function_ea,
            stable_mba_identity(mba),
            maturity,
            detached_snippet_template_generation(function_ea),
        )
        if mba_identity in state.attempted_mbas:
            return 0
        state.attempted_mbas.add(mba_identity)
        preopt_union_owns_mba = _preopt_union_owns_mba(
            state,
            function_ea,
            mba,
        )

        if maturity == int(ida_hexrays.MMAT_CALLS):
            transfers = state.materialized_transfers
            terminal_carriers = restore_terminal_return_carriers(
                mba,
                function_ea,
            )
            replacement_imports = (
                _materialize_live_handler_replacements(
                    mba,
                    transfers,
                    state=state,
                    mutation_gateway=mutation_gateway,
                )
                if not preopt_union_owns_mba
                else 0
            )
            missing_imports = (
                _materialize_missing_detached_snippets(
                    mba,
                    transfers,
                    mutation_gateway=mutation_gateway,
                    require_live_residual_source=True,
                    expected_template_maturity=int(ida_hexrays.MMAT_LOCOPT),
                )
                if not preopt_union_owns_mba
                else 0
            )
            reconciled_calls = reconcile_imported_callinfo_with_live_native_calls(mba)
            # Snippets imported during LOCOPT are already present when this
            # CALLS rule runs, so neither import counter is a reliable signal
            # that their cross-maturity arm-state evidence still needs to be
            # joined. The recovery is self-gating on imported origins and
            # returns the input unchanged when there is nothing to publish.
            transfers = _recover_imported_conditional_bridge_transfers(
                mba,
                transfers,
                state=state,
            )
            live_resolver_cuts = (
                _apply_live_resolver_cut_counterparts(
                    mba,
                    mutation_gateway=mutation_gateway,
                )
                if not preopt_union_owns_mba
                else 0
            )
            terminal_routes = (
                _apply_detached_snippet_terminal_routes(
                    mba,
                    transfers,
                    mutation_gateway=mutation_gateway,
                )
                if not preopt_union_owns_mba
                else 0
            )
            residual_bridges = (
                _apply_residual_state_route_bridges(
                    mba,
                    transfers,
                    mutation_gateway=mutation_gateway,
                )
                if not preopt_union_owns_mba
                else 0
            )
            bridge_plans = (
                _candidate_conditional_bridge_plans(state)
                if not preopt_union_owns_mba
                else ()
            )
            try:
                conditional_bridges = (
                    _apply_conditional_bridge_plans(
                        mba,
                        bridge_plans,
                        state=state,
                        mutation_gateway=mutation_gateway,
                    )
                    if bridge_plans
                    else 0
                )
            except Exception:
                logger.warning(
                    "CALLS conditional handler bridge batch failed: func=0x%X plans=%d",
                    function_ea,
                    len(bridge_plans),
                    exc_info=True,
                )
                conditional_bridges = 0
            restored_call_definitions = (
                restore_detached_call_result_definitions(mba, function_ea)
                if is_computed_goto_materialized(state)
                else 0
            )
            graph_changes = (
                int(terminal_carriers)
                + int(replacement_imports)
                + int(missing_imports)
                + int(reconciled_calls)
                + int(live_resolver_cuts)
                + int(terminal_routes)
                + int(residual_bridges)
                + int(conditional_bridges)
                + int(restored_call_definitions)
            )
            if graph_changes:
                logger.info(
                    "CALLS restored %d terminal return carrier(s), imported %d "
                    "live-handler replacement(s) and %d "
                    "cross-maturity missing target(s), reconciled %d imported "
                    "callinfo record(s), rebound %d native resolver-cut "
                    "counterpart(s), materialized "
                    "%d detached terminal route(s) and %d residual state-route "
                    "bridge(s), plus %d conditional handler bridge(s) and %d "
                    "analyzed call-result definition(s)",
                    int(terminal_carriers),
                    int(replacement_imports),
                    int(missing_imports),
                    int(reconciled_calls),
                    int(live_resolver_cuts),
                    int(terminal_routes),
                    int(residual_bridges),
                    int(conditional_bridges),
                    int(restored_call_definitions),
                )
                return graph_changes
            resolver_evidence = state.native_preanalysis.resolver_evidence
            cached_carriers = (
                ()
                if resolver_evidence is None
                else resolver_evidence.call_result_carriers
            )
            logger.info(
                "call-result carrier restore phase: cached=%d",
                len(cached_carriers),
            )
            restored = restore_call_result_carriers(mba, cached_carriers)
            if restored:
                state.native_preanalysis.clear_call_result_carriers(state.native_key)
                logger.info(
                    "restored %d call-result carrier(s) after state lowering",
                    int(restored),
                )
            return int(restored)

        if preopt_union_owns_mba:
            logger.info(
                "LOCOPT detached island and bridge materialization "
                "suppressed after PREOPT union ownership: func=0x%X",
                function_ea,
            )
            return 0

        transfers = state.materialized_transfers
        kept_snippet_blocks = _keep_cached_detached_snippet_blocks(
            mba,
            transfers,
        )
        terminal_routes = _apply_detached_snippet_terminal_routes(
            mba,
            transfers,
            mutation_gateway=mutation_gateway,
        )
        residual_bridges = _apply_residual_state_route_bridges(
            mba,
            transfers,
            mutation_gateway=mutation_gateway,
        )
        pre_dce_changes = (
            int(kept_snippet_blocks) + int(terminal_routes) + int(residual_bridges)
        )
        if kept_snippet_blocks or terminal_routes or residual_bridges:
            logger.info(
                "kept %d detached snippet block(s), materialized %d detached "
                "terminal route(s), and %d residual state-route bridge(s) "
                "before LOCOPT DCE",
                int(kept_snippet_blocks),
                int(terminal_routes),
                int(residual_bridges),
            )

        island_plans = _candidate_plans(state)
        bridge_plans = _candidate_conditional_bridge_plans(state)
        logger.info(
            "computed-goto island planner: func=0x%X maturity=%s islands=%d bridges=%d",
            function_ea,
            maturity_to_string(maturity),
            len(island_plans),
            len(bridge_plans),
        )
        if island_plans or bridge_plans:
            captured_carriers = capture_call_result_carriers(mba)
            materialized = 0
            materialized_predicates: set[int] = set()
            for plan in sorted(
                island_plans,
                key=lambda candidate: int(candidate.source_predicate_ea),
                reverse=True,
            ):
                try:
                    applied = materialize_detached_handler_island(
                        mba,
                        plan,
                        mutation_gateway=mutation_gateway,
                    )
                except Exception:
                    logger.warning(
                        "detached handler island failed: func=0x%X predicate=0x%X",
                        function_ea,
                        int(plan.source_predicate_ea),
                        exc_info=True,
                    )
                    applied = False
                if applied:
                    materialized += 1
                    materialized_predicates.add(int(plan.source_predicate_ea))
            remaining_bridges = tuple(
                plan
                for plan in bridge_plans
                if int(plan.source_predicate_ea) not in materialized_predicates
            )
            try:
                bridged = (
                    _apply_conditional_bridge_plans(
                        mba,
                        remaining_bridges,
                        state=state,
                        mutation_gateway=mutation_gateway,
                    )
                    if remaining_bridges
                    else 0
                )
            except Exception:
                logger.warning(
                    "conditional handler bridge batch failed: func=0x%X plans=%d",
                    function_ea,
                    len(remaining_bridges),
                    exc_info=True,
                )
                bridged = 0
            if bridged:
                state.native_preanalysis.merge_call_result_carriers(
                    state.native_key,
                    captured_carriers,
                )
            changed = pre_dce_changes + int(materialized) + int(bridged)
            if changed:
                logger.info(
                    "materialized %d detached island(s) and %d conditional "
                    "handler bridge(s) before LOCOPT DCE",
                    int(materialized),
                    int(bridged),
                )
                return changed
        return pre_dce_changes


__all__ = ["MaterializedComputedGotoIslandRule"]
