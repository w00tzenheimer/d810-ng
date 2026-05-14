"""Redirect residual dispatcher feeders into dominating exact-node heads."""
from __future__ import annotations

from d810.core import logging
from d810.core.algorithm_metadata import algorithm_metadata
from d810.cfg.residual_target_resolution import (
    collect_owned_exact_sources,
    collect_supported_exact_entries,
    is_structured_conditional_path_feeder,
    is_supplemental_feeder_bypass,
    resolve_frontier_target_entry,
)
from d810.cfg.semantic_conditional_lowering import (
    collect_exact_conditional_alias_sites,
    is_straight_line_handoff,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.semantic_exact_node import (
    _SUB7FFD_FUNC_EA,
    build_semantic_exact_round_summary,
)
from d810.optimizers.microcode.flow.flattening.hodur.profile_gate import (
    accepts_exact_sub7ffd_glbopt1,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_node import (
    collect_exact_conditional_sites,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_fork import (
    collect_exact_conditional_fork_sites,
)
from d810.optimizers.microcode.flow.flattening.hodur.prototypes import (
    collect_exact_conditional_bridge_sites,
)
from d810.recon.flow.graph_reachability import (
    collect_residual_dispatcher_predecessors,
)
from d810.recon.flow.residual_handoff_discovery import (
    dispatcher_exact_state_target,
    resolve_dag_entry_for_state,
    resolve_normalized_alias_entry_for_state,
    state_has_semantic_support,
    supplemental_selected_entry_for_state,
)
from d810.recon.flow.target_entry_resolution import (
    resolve_exact_dag_entry_for_state,
    resolve_semantic_reference_entry_for_state,
)
from d810.recon.flow.state_machine_analysis import can_reach_return_snapshot
from d810.recon.flow.state_machine_analysis import find_last_state_write_site_snapshot
from d810.optimizers.microcode.flow.flattening.hodur.residual_handoff_backend import (
    HexRaysResidualFrontierEvidenceBackend,
    ResidualFrontierEvidenceBackend,
)

logger = logging.getLogger(
    "D810.hodur.strategy.exact_node_frontier_bypass",
    logging.DEBUG,
)
_RESIDUAL_FRONTIER_EVIDENCE_BACKEND: ResidualFrontierEvidenceBackend = (
    HexRaysResidualFrontierEvidenceBackend()
)


def _collect_exact_source_blocks(round_summary, flow_graph) -> set[int]:
    """Return exact-node source blocks already recognized by exact lowerers."""
    source_blocks = {
        int(site.source_block)
        for site in collect_exact_conditional_sites(round_summary, flow_graph)
    }
    source_blocks.update(
        int(site.source_block)
        for site in collect_exact_conditional_alias_sites(round_summary, flow_graph)
    )
    source_blocks.update(
        int(site.source_block)
        for site in collect_exact_conditional_fork_sites(round_summary, flow_graph)
    )
    source_blocks.update(
        int(site.source_block)
        for site in collect_exact_conditional_bridge_sites(round_summary, flow_graph)
    )
    return source_blocks


def _collect_trivial_frontier_zero_state_write_modification(
    *,
    setup,
    flow_graph,
    source_block: int,
    dispatcher_serial: int,
    state_var_stkoff: int,
    expected_state: int,
):
    """Zero a stale local ``state = CONST`` after a 1-way frontier bypass.

    Frontier bypass rewires trivial dispatcher feeders away from the BST. When
    the source block still contains the original constant state handoff, that
    write becomes pure flattening scaffolding and must be stripped in the same
    stage or it will survive into the final pseudocode.
    """

    block = flow_graph.get_block(int(source_block))
    if block is None:
        return None
    succs = tuple(int(succ) for succ in getattr(block, "succs", ()))
    if succs != (int(dispatcher_serial),):
        return None

    site = find_last_state_write_site_snapshot(
        flow_graph,
        int(source_block),
        int(state_var_stkoff),
    )
    if site is None:
        return None
    if (int(site.state_value) & 0xFFFFFFFF) != (int(expected_state) & 0xFFFFFFFF):
        return None
    insn_ea = int(getattr(site, "insn_ea", 0) or 0)
    if insn_ea == 0:
        return None
    if tuple(getattr(site, "unsafe_trailing_insn_eas", ())):
        return None
    if len(tuple(getattr(site, "trailing_insn_eas", ()))) > 1:
        return None
    return setup.builder.zero_state_write(int(source_block), insn_ea)


@algorithm_metadata(
    algorithm_id="hodur.exact_node_frontier_bypass",
    family="semantic_exact_node_lowering",
    summary="Bypass residual dispatcher feeders into dominating exact-node heads after node lowering.",
    use_cases=(
        "Redirect reachable non-BST predecessors of the dispatcher to the semantic entry of an already-supported exact node.",
        "Enable post-apply BST cleanup by shrinking residual dispatcher feeders for the exact-node strategy family.",
    ),
    examples=(
        "Redirect a 1-way residual predecessor that writes `0x5FE86821` to the exact node head for that state instead of re-entering the BST.",
        "Retarget a 2-way residual frontier arm from dispatcher to the dominating exact-node head for a supported conditional node family.",
    ),
    tags=("exact-node", "frontier-bypass", "dispatcher", "bst", "entry-bypass"),
    related_paths=(
        "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/exact_node_frontier_bypass.py",
        "src/d810/recon/flow/residual_handoff_resolution.py",
        "src/d810/recon/flow/graph_reachability.py",
    ),
)
class ExactNodeFrontierBypassStrategy:
    prerequisites: list[str] = []
    _collect_residual_dispatcher_predecessors = staticmethod(
        collect_residual_dispatcher_predecessors
    )

    @property
    def name(self) -> str:
        return "exact_node_frontier_bypass"

    @property
    def family(self) -> str:
        return FAMILY_DIRECT

    def is_applicable(self, snapshot) -> bool:
        if not accepts_exact_sub7ffd_glbopt1(
            snapshot,
            expected_entry_ea=_SUB7FFD_FUNC_EA,
        ):
            return False
        return (
            getattr(snapshot, "state_machine", None) is not None
            and getattr(snapshot, "bst_result", None) is not None
            and getattr(snapshot, "flow_graph", None) is not None
            and getattr(snapshot, "bst_dispatcher_serial", -1) >= 0
        )

    def plan(self, snapshot) -> PlanFragment | None:
        if not self.is_applicable(snapshot):
            return None

        setup, round_summary = build_semantic_exact_round_summary(snapshot)
        flow_graph = snapshot.flow_graph
        state_machine = snapshot.state_machine
        mba = snapshot.mba
        assert flow_graph is not None
        assert state_machine is not None
        assert mba is not None

        state_variable = _RESIDUAL_FRONTIER_EVIDENCE_BACKEND.resolve_state_variable(
            state_machine=state_machine,
        )
        if state_variable is None:
            return None
        state_var_stkoff = int(state_variable.stkoff)

        bst_blocks = {
            int(block)
            for block in getattr(snapshot.bst_result, "bst_node_blocks", set()) or set()
        }
        dispatcher_model = getattr(setup, "dispatcher", None)
        if dispatcher_model is None:
            dispatcher_model = getattr(snapshot.bst_result, "dispatcher", None)
        dispatcher_serial = int(snapshot.bst_dispatcher_serial)
        residual_preds = collect_residual_dispatcher_predecessors(
            flow_graph,
            dispatcher_serial,
            bst_node_blocks=bst_blocks,
            reachable_from_serial=getattr(getattr(snapshot, "reachability", None), "entry_serial", None),
        )
        if not residual_preds:
            return None

        exact_source_blocks = _collect_exact_source_blocks(round_summary, flow_graph)
        supported_entries = collect_supported_exact_entries(
            round_summary,
            exact_source_blocks=exact_source_blocks,
            bst_blocks=bst_blocks,
            is_straight_line_handoff_fn=is_straight_line_handoff,
            resolve_dag_entry_for_state_fn=resolve_dag_entry_for_state,
        )
        owned_exact_sources = collect_owned_exact_sources(
            round_summary,
            exact_source_blocks=exact_source_blocks,
            is_straight_line_handoff_fn=is_straight_line_handoff,
        )
        terminal_source_owned_blocks = {
            int(block) for block in getattr(round_summary, "terminal_source_owned_blocks", ()) or ()
        }
        terminal_protected_blocks = {
            int(block) for block in getattr(round_summary, "terminal_protected_blocks", ()) or ()
        }

        modifications: list = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        owned_transitions: set[tuple[int, int]] = set()
        accepted_bypasses: list[tuple[int, int, int]] = []
        accepted_supplemental_bypasses: list[tuple[int, int, int]] = []
        accepted_zero_state_write_cleanups: list[tuple[int, int, int]] = []
        skipped_no_state = 0
        skipped_unsupported_entry = 0
        skipped_non_dispatcher_edge = 0
        skipped_owned_source = 0
        skipped_structured_conditional_feeder = 0

        for pred_serial in residual_preds:
            pred_block = flow_graph.get_block(int(pred_serial))
            if pred_block is None:
                continue
            succs = tuple(int(succ) for succ in getattr(pred_block, "succs", ()))
            if dispatcher_serial not in succs:
                skipped_non_dispatcher_edge += 1
                continue

            state_write = (
                _RESIDUAL_FRONTIER_EVIDENCE_BACKEND.resolve_singleton_state_write(
                    mba,
                    int(pred_serial),
                    state_variable=state_variable,
                )
            )
            if state_write is None:
                skipped_no_state += 1
                continue
            state_value = int(state_write.state_value) & 0xFFFFFFFF
            if is_structured_conditional_path_feeder(
                round_summary.dag,
                pred_serial=int(pred_serial),
                state_value=state_value,
            ):
                skipped_structured_conditional_feeder += 1
                continue
            raw_state = state_value
            residual_effective_evidence = (
                _RESIDUAL_FRONTIER_EVIDENCE_BACKEND.resolve_residual_effective_target(
                    round_summary.dag,
                    pred_serial=int(pred_serial),
                    state_value=raw_state,
                    dispatcher_model=dispatcher_model,
                    bst_node_blocks=bst_blocks,
                    state_variable=state_variable,
                    mba=mba,
                )
            )
            residual_effective_target = residual_effective_evidence.target_entry
            exact_dispatch_target, target_entry = resolve_frontier_target_entry(
                round_summary.dag,
                pred_serial=int(pred_serial),
                state_value=raw_state,
                dispatcher_model=dispatcher_model,
                bst_blocks=bst_blocks,
                semantic_reference_program=getattr(round_summary, "semantic_reference_program", None),
                residual_effective_target=residual_effective_target,
                dispatcher_exact_state_target_fn=dispatcher_exact_state_target,
                supplemental_selected_entry_for_state_fn=supplemental_selected_entry_for_state,
                resolve_exact_dag_entry_for_state_fn=resolve_exact_dag_entry_for_state,
                resolve_semantic_reference_entry_for_state_fn=resolve_semantic_reference_entry_for_state,
                resolve_dag_entry_for_state_fn=resolve_dag_entry_for_state,
                resolve_normalized_alias_entry_for_state_fn=resolve_normalized_alias_entry_for_state,
            )
            if (
                target_entry is None
                or int(target_entry) in bst_blocks
                or int(target_entry) == int(pred_serial)
            ):
                skipped_unsupported_entry += 1
                continue

            allow_supplemental_bypass = is_supplemental_feeder_bypass(
                flow_graph=flow_graph,
                pred_serial=int(pred_serial),
                pred_block=pred_block,
                state_value=int(state_value) & 0xFFFFFFFF,
                exact_dispatch_target=None if exact_dispatch_target is None else int(exact_dispatch_target),
                target_entry=int(target_entry),
                bst_blocks=bst_blocks,
                supported_entries=supported_entries,
                owned_exact_sources=owned_exact_sources,
                terminal_source_owned_blocks=terminal_source_owned_blocks,
                terminal_protected_blocks=terminal_protected_blocks,
                dag=round_summary.dag,
                state_has_semantic_support_fn=state_has_semantic_support,
                can_reach_return_fn=can_reach_return_snapshot,
            )
            if int(pred_serial) in owned_exact_sources:
                skipped_owned_source += 1
                continue
            if (
                int(target_entry) not in supported_entries
                and not allow_supplemental_bypass
            ):
                skipped_unsupported_entry += 1
                continue

            emission_mode = None
            if len(succs) == 1 and succs[0] == dispatcher_serial:
                modifications.append(
                    setup.builder.goto_redirect(
                        source_block=int(pred_serial),
                        target_block=int(target_entry),
                        old_target=dispatcher_serial,
                    )
                )
                if allow_supplemental_bypass:
                    emission_mode = "frontier_supplemental_goto_bypass"
                else:
                    emission_mode = "frontier_goto_bypass"
                zero_state_write_mod = _collect_trivial_frontier_zero_state_write_modification(
                    setup=setup,
                    flow_graph=flow_graph,
                    source_block=int(pred_serial),
                    dispatcher_serial=dispatcher_serial,
                    state_var_stkoff=int(state_var_stkoff),
                    expected_state=int(state_value) & 0xFFFFFFFF,
                )
                if zero_state_write_mod is not None:
                    modifications.append(zero_state_write_mod)
                    accepted_zero_state_write_cleanups.append(
                        (
                            int(pred_serial),
                            int(state_value) & 0xFFFFFFFF,
                            int(target_entry),
                        )
                    )
            elif len(succs) == 2:
                modifications.append(
                    setup.builder.edge_redirect(
                        source_block=int(pred_serial),
                        target_block=int(target_entry),
                        old_target=dispatcher_serial,
                    )
                )
                if allow_supplemental_bypass:
                    emission_mode = "frontier_supplemental_branch_bypass"
                else:
                    emission_mode = "frontier_branch_bypass"
            else:
                continue

            owned_blocks.add(int(pred_serial))
            owned_edges.add((int(pred_serial), int(target_entry)))
            owned_transitions.add((int(state_value) & 0xFFFFFFFF, int(target_entry)))
            record = (int(pred_serial), int(state_value) & 0xFFFFFFFF, int(target_entry))
            if allow_supplemental_bypass:
                accepted_supplemental_bypasses.append(record)
            else:
                accepted_bypasses.append(record)
            logger.info(
                "EXACT NODE FRONTIER BYPASS: blk[%d] state=0x%08X -> blk[%d] via %s",
                int(pred_serial),
                int(state_value) & 0xFFFFFFFF,
                int(target_entry),
                emission_mode,
            )

        if not modifications:
            logger.info(
                "EXACT NODE FRONTIER BYPASS: no accepted bypasses "
                "(residual=%d supported_entries=%d owned_sources=%d overlap=%d no_state=%d unsupported=%d non_dispatcher=%d)",
                len(residual_preds),
                len(supported_entries),
                len(owned_exact_sources),
                skipped_owned_source,
                skipped_no_state,
                skipped_unsupported_entry,
                skipped_non_dispatcher_edge,
            )
            return None

        logger.info(
            "EXACT NODE FRONTIER BYPASS: accepted=%d supplemental=%d residual=%d supported_entries=%d "
            "owned_sources=%d overlap=%d no_state=%d unsupported=%d non_dispatcher=%d "
            "structured_conditional_feeder=%d zero_state_cleanups=%d",
            len(accepted_bypasses),
            len(accepted_supplemental_bypasses),
            len(residual_preds),
            len(supported_entries),
            len(owned_exact_sources),
            skipped_owned_source,
            skipped_no_state,
            skipped_unsupported_entry,
            skipped_non_dispatcher_edge,
            skipped_structured_conditional_feeder,
            len(accepted_zero_state_write_cleanups),
        )

        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=OwnershipScope(
                blocks=frozenset(owned_blocks),
                edges=frozenset(owned_edges),
                transitions=frozenset(owned_transitions),
            ),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=len(accepted_bypasses) + len(accepted_supplemental_bypasses),
                transitions_resolved=len(accepted_bypasses) + len(accepted_supplemental_bypasses),
                blocks_freed=0,
                conflict_density=0.1,
            ),
            risk_score=0.2,
            metadata={
                "accepted_bypasses": tuple(accepted_bypasses),
                "accepted_supplemental_bypasses": tuple(accepted_supplemental_bypasses),
                "accepted_zero_state_write_cleanups": tuple(accepted_zero_state_write_cleanups),
                "safeguard_min_required": max(
                    1,
                    len(accepted_bypasses) + len(accepted_supplemental_bypasses),
                ),
                "allow_post_apply_bst_cleanup": True,
                "post_apply_bst_cleanup_group": "exact_nodes",
                "skipped_structured_conditional_feeder": int(skipped_structured_conditional_feeder),
            },
        )
