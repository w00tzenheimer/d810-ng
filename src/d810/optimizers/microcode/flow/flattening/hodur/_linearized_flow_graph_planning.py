from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.linearized_flow_graph_fragment_planning import (
    LinearizedFlowGraphPlanningCallbacks,
    LinearizedFlowGraphPlanningContext,
    LinearizedFlowGraphPlanningResult,
)
from d810.optimizers.microcode.flow.flattening.hodur._helpers import blk_label
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)


@dataclass(frozen=True, slots=True)
class LinearizedFlowGraphPlanSetup:
    builder: object
    state_var_stkoff: int | None
    dispatcher: object | None
    blocked_sources: frozenset[int]
    dispatcher_region: frozenset[int]
    bst_node_blocks: frozenset[int]
    original_blocks: frozenset[int]
    transition_result: object
    pre_header_serial: int | None
    projectable: bool
    round_limit: int


def prepare_linearized_flow_graph_plan_setup(
    *,
    snapshot: object,
    state_machine: object,
    bst_result: object,
    flow_graph: object,
    mba: object | None,
    same_maturity_rerun: bool,
    logger: object,
    build_modification_builder: object,
    resolve_state_var_stkoff: object,
    supports_projected_replanning: object,
    flow_graph_block_serials: object,
    is_original_pre_header_candidate: object,
    transition_result_cls: object,
) -> LinearizedFlowGraphPlanSetup:
    bst_node_blocks = frozenset(
        int(block)
        for block in (getattr(bst_result, "bst_node_blocks", set()) or set())
    )
    builder = build_modification_builder(snapshot)
    state_var_stkoff = resolve_state_var_stkoff(snapshot, state_machine)
    dispatcher = getattr(bst_result, "dispatcher", None)
    blocked_sources = frozenset(
        int(serial)
        for serial in (getattr(snapshot, "lfg_redirected_blocks", ()) or ())
    )
    dispatcher_region = bst_node_blocks
    original_blocks = frozenset(int(block) for block in flow_graph_block_serials(flow_graph))
    transition_result = transition_result_cls(
        transitions=list(state_machine.transitions),
        handlers=dict(state_machine.handlers),
        assignment_map=dict(state_machine.assignment_map),
        initial_state=state_machine.initial_state,
        pre_header_serial=getattr(bst_result, "pre_header_serial", None),
        strategy_name="linearized_flow_graph",
        resolved_count=len(state_machine.transitions),
    )

    raw_pre_header = (
        None if same_maturity_rerun else getattr(bst_result, "pre_header_serial", None)
    )
    entry_serial = getattr(getattr(snapshot, "reachability", None), "entry_serial", None)
    pre_header_serial = (
        raw_pre_header
        if is_original_pre_header_candidate(
            flow_graph,
            pre_header_serial=raw_pre_header,
            entry_serial=entry_serial,
        )
        else None
    )
    if raw_pre_header is not None and pre_header_serial is None:
        logger.info(
            "LFG DAG: suppressing non-entry pre-header candidate %s (entry=%s)",
            blk_label(mba, raw_pre_header),
            blk_label(mba, entry_serial) if entry_serial is not None else "<none>",
        )

    projectable = bool(supports_projected_replanning(flow_graph))
    round_limit = 1 if same_maturity_rerun else 2
    return LinearizedFlowGraphPlanSetup(
        builder=builder,
        state_var_stkoff=state_var_stkoff,
        dispatcher=dispatcher,
        blocked_sources=blocked_sources,
        dispatcher_region=dispatcher_region,
        bst_node_blocks=bst_node_blocks,
        original_blocks=original_blocks,
        transition_result=transition_result,
        pre_header_serial=pre_header_serial,
        projectable=projectable,
        round_limit=round_limit,
    )


def build_linearized_flow_graph_planning_context(
    *,
    flow_graph: object,
    mba: object | None,
    state_machine: object,
    dispatcher_serial: int,
    setup: LinearizedFlowGraphPlanSetup,
) -> LinearizedFlowGraphPlanningContext:
    dispatcher = setup.dispatcher
    return LinearizedFlowGraphPlanningContext(
        flow_graph=flow_graph,
        builder=setup.builder,
        mba=mba,
        state_machine=state_machine,
        dispatcher_serial=int(dispatcher_serial),
        bst_node_blocks=setup.bst_node_blocks,
        dispatcher_region=setup.dispatcher_region,
        state_var_stkoff=setup.state_var_stkoff,
        dispatcher_lookup=(dispatcher.lookup if dispatcher is not None else None),
        dispatcher=dispatcher,
        pre_header_serial=setup.pre_header_serial,
        original_blocks=setup.original_blocks,
        same_maturity_rerun=bool(setup.round_limit == 1),
        projectable=bool(setup.projectable),
        round_limit=int(setup.round_limit),
        initial_state=(
            int(state_machine.initial_state)
            if state_machine.initial_state is not None
            else None
        ),
        blocked_sources=setup.blocked_sources,
    )


def build_linearized_flow_graph_planning_callbacks(
    *,
    snapshot: object,
    state_machine: object,
    bst_result: object,
    mba: object | None,
    setup: LinearizedFlowGraphPlanSetup,
    build_round_summary: object,
    build_projected_mba: object,
    project_flow_graph: object,
    resolve_redirect_safe_target_entry: object,
    resolve_initial_entry: object,
    emit_dag_redirect: object,
    collect_residual_dispatcher_predecessors: object,
    emit_residual_dispatcher_handoffs: object,
    disconnect_bst_comparison_nodes: object,
) -> LinearizedFlowGraphPlanningCallbacks:
    return LinearizedFlowGraphPlanningCallbacks(
        build_round_summary=lambda current_flow_graph, dag_round_mba: build_round_summary(
            snapshot=snapshot,
            state_machine=state_machine,
            bst_result=bst_result,
            transition_result=setup.transition_result,
            current_flow_graph=current_flow_graph,
            dag_round_mba=dag_round_mba,
            dispatcher_serial=int(snapshot.bst_dispatcher_serial),
            state_var_stkoff=setup.state_var_stkoff,
            pre_header_serial=setup.pre_header_serial,
            bst_node_blocks=setup.bst_node_blocks,
        ),
        build_projected_mba=build_projected_mba,
        project_flow_graph=project_flow_graph,
        resolve_redirect_safe_target_entry=lambda dag, edge, bst_node_blocks: resolve_redirect_safe_target_entry(
            dag,
            edge,
            bst_node_blocks=set(int(block) for block in bst_node_blocks),
        ),
        resolve_initial_entry=lambda dag, initial_state, bst_node_blocks: resolve_initial_entry(
            dag,
            initial_state,
            bst_node_blocks=set(int(block) for block in bst_node_blocks),
        ),
        emit_dag_redirect=lambda *,
            edge,
            dag,
            flow_graph,
            state,
            report_exit_handlers,
            report_exit_owned_blocks,
            terminal_source_keys,
            terminal_source_handlers,
            terminal_source_owned_blocks,
            terminal_protected_blocks: emit_dag_redirect(
                edge=edge,
                dag=dag,
                builder=setup.builder,
                modifications=state.modifications,
                owned_blocks=state.owned_blocks,
                owned_edges=state.owned_edges,
                owned_transitions=state.owned_transitions,
                emitted=state.emitted,
                claimed_1way=state.claimed_1way,
                claimed_2way=state.claimed_2way,
                claimed_exits=state.claimed_exits,
                claimed_path_edges=state.claimed_path_edges,
                blocked_sources=state.blocked_sources,
                terminal_source_keys=set(terminal_source_keys),
                terminal_source_handlers=set(terminal_source_handlers),
                terminal_source_owned_blocks=set(terminal_source_owned_blocks),
                terminal_protected_blocks=set(terminal_protected_blocks),
                report_exit_handlers=set(report_exit_handlers),
                report_exit_owned_blocks=set(report_exit_owned_blocks),
                bst_node_blocks=set(int(block) for block in setup.bst_node_blocks),
                dispatcher_region=set(int(block) for block in setup.dispatcher_region),
                flow_graph=flow_graph,
                state_var_stkoff=setup.state_var_stkoff,
                dispatcher_lookup=(
                    setup.dispatcher.lookup if setup.dispatcher is not None else None
                ),
                dispatcher=setup.dispatcher,
                mba=mba,
            ),
        collect_residual_dispatcher_predecessors=lambda current_flow_graph, dispatcher_serial, bst_node_blocks, reachable_from_serial: collect_residual_dispatcher_predecessors(
            current_flow_graph,
            dispatcher_serial,
            bst_node_blocks=set(int(block) for block in bst_node_blocks),
            reachable_from_serial=reachable_from_serial,
        ),
        emit_residual_dispatcher_handoffs=lambda *,
            dag,
            projected_flow_graph,
            state,
            redirected_blocks: emit_residual_dispatcher_handoffs(
                dag=dag,
                state_machine=state_machine,
                projected_flow_graph=projected_flow_graph,
                dispatcher_serial=int(snapshot.bst_dispatcher_serial),
                bst_node_blocks=set(int(block) for block in setup.bst_node_blocks),
                builder=setup.builder,
                modifications=state.modifications,
                owned_blocks=state.owned_blocks,
                owned_edges=state.owned_edges,
                owned_transitions=state.owned_transitions,
                emitted=state.emitted,
                claimed_1way=state.claimed_1way,
                claimed_2way=state.claimed_2way,
                state_var_stkoff=setup.state_var_stkoff,
                dispatcher_lookup=(
                    setup.dispatcher.lookup if setup.dispatcher is not None else None
                ),
                dispatcher=setup.dispatcher,
                mba=mba,
                redirected_blocks=redirected_blocks,
            ),
        disconnect_bst_comparison_nodes=lambda bst_node_blocks, dispatcher_serial, state: disconnect_bst_comparison_nodes(
            set(int(block) for block in bst_node_blocks),
            dispatcher_serial,
            setup.builder,
            state.modifications,
            state.emitted,
            mba=mba,
        ),
    )


def log_linearized_flow_graph_plan_result(
    logger: object,
    *,
    mba: object | None,
    result: LinearizedFlowGraphPlanningResult,
) -> None:
    if result.unresolved_bst_targets:
        logger.info(
            "LFG DAG: preserving BST cleanup because %d targets still resolve only inside BST region",
            result.unresolved_bst_targets,
        )
    if result.cleanup_gate_reason == "residual_dispatcher_predecessors":
        logger.info(
            "LFG DAG: preserving post-apply BST cleanup because residual non-BST dispatcher predecessors remain: %s",
            [blk_label(mba, serial) for serial in result.residual_dispatcher_preds],
        )

    logger.info(
        "LFG DAG: emitted %d redirects (%d unconditional, %d conditional); "
        "%d terminal edges ignored, %d unknown edges ignored, %d skipped conflicts; "
        "%d BST disconnects",
        result.transition_count + result.conditional_count,
        result.transition_count,
        result.conditional_count,
        result.terminal_skipped,
        result.unknown_skipped,
        result.skipped_count,
        result.disconnect_count,
    )


def build_linearized_flow_graph_plan_fragment(
    *,
    strategy_name: str,
    family: str,
    prerequisites: list[str],
    state_machine: object,
    bst_node_blocks: frozenset[int],
    result: LinearizedFlowGraphPlanningResult,
) -> PlanFragment:
    ownership = OwnershipScope(
        blocks=result.owned_blocks,
        edges=result.owned_edges,
        transitions=result.owned_transitions,
    )
    benefit = BenefitMetrics(
        handlers_resolved=len(state_machine.handlers),
        transitions_resolved=result.transition_count + result.conditional_count,
        blocks_freed=len(bst_node_blocks),
        conflict_density=0.0,
    )
    return PlanFragment(
        strategy_name=strategy_name,
        family=family,
        modifications=list(result.modifications),
        ownership=ownership,
        prerequisites=prerequisites,
        expected_benefit=benefit,
        risk_score=0.1,
        metadata={
            "handlers_visited": len(state_machine.handlers),
            "resolved_count": result.transition_count + result.conditional_count,
            "dag_transition_count": result.transition_count,
            "dag_conditional_count": result.conditional_count,
            "dag_terminal_skipped": result.terminal_skipped,
            "dag_unknown_skipped": result.unknown_skipped,
            "skipped_count": result.skipped_count,
            "disconnect_count": result.disconnect_count,
            "allow_post_apply_bst_cleanup": result.cleanup_gate_reason is None,
            "post_apply_bst_cleanup_reason": result.cleanup_gate_reason,
            "residual_dispatcher_preds": result.residual_dispatcher_preds,
            "residual_dispatcher_redirect_count": result.residual_dispatcher_redirect_count,
            "residual_dispatcher_normalized_count": result.residual_dispatcher_normalized_count,
            "dead_island_cleanup_count": result.dead_island_cleanup_count,
            "unresolved_bst_targets": result.unresolved_bst_targets,
            "bst_convert_count": 0,
            "goto_nop_count": 0,
            "goto_skip_count": 0,
            "nop_state_values": {},
            "safeguard_min_required": 1,
        },
    )


__all__ = [
    "LinearizedFlowGraphPlanSetup",
    "build_linearized_flow_graph_plan_fragment",
    "build_linearized_flow_graph_planning_callbacks",
    "build_linearized_flow_graph_planning_context",
    "log_linearized_flow_graph_plan_result",
    "prepare_linearized_flow_graph_plan_setup",
]
