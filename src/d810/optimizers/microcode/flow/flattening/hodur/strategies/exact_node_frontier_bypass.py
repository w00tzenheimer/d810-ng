"""Redirect residual dispatcher feeders into dominating exact-node heads."""
from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.core import logging
from d810.core.algorithm_metadata import algorithm_metadata
from d810.cfg.semantic_region_lowering import (
    _collect_semantic_entry_by_label,
    _collect_semantic_successors_by_state,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.semantic_exact_node import (
    _SUB7FFD_FUNC_EA,
    _is_straight_line_handoff,
    build_semantic_exact_round_summary,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_node import (
    collect_exact_conditional_sites,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_alias import (
    collect_exact_conditional_alias_sites,
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
from d810.recon.flow.residual_handoff_resolution import (
    resolve_effective_target_entry as resolve_effective_residual_target_entry,
    resolve_singleton_state_write_value,
)

logger = logging.getLogger(
    "D810.hodur.strategy.exact_node_frontier_bypass",
    logging.DEBUG,
)


def _resolve_semantic_reference_alias_entry(
    dag,
    semantic_reference_program,
    *,
    pred_serial: int,
    state_value: int,
) -> int | None:
    """Resolve a raw alias state through the semantic reference program."""
    semantic_successors_by_state = _collect_semantic_successors_by_state(
        semantic_reference_program
    )
    semantic_entry_by_label = _collect_semantic_entry_by_label(
        semantic_reference_program
    )
    if not semantic_successors_by_state or not semantic_entry_by_label:
        return None

    relevant_edges = [
        edge
        for edge in getattr(dag, "edges", ()) or ()
        if getattr(edge, "target_state", None) is not None
        and (int(getattr(edge, "target_state")) & 0xFFFFFFFF) == (int(state_value) & 0xFFFFFFFF)
        and int(pred_serial) in tuple(int(node) for node in getattr(edge, "ordered_path", ()) or ())
    ]
    if not relevant_edges:
        return None

    source_sites: set[tuple[int, int | None]] = set()
    for edge in relevant_edges:
        source_state = getattr(getattr(edge, "source_key", None), "state_const", None)
        if source_state is None:
            continue
        source_anchor = getattr(edge, "source_anchor", None)
        source_block = getattr(source_anchor, "block_serial", None)
        source_sites.add(
            (
                int(source_state) & 0xFFFFFFFF,
                None if source_block is None else int(source_block),
            )
        )

    for source_state, source_block in source_sites:
        semantic_labels = tuple(semantic_successors_by_state.get(source_state, ()))
        if not semantic_labels:
            continue
        source_edges = [
            edge
            for edge in getattr(dag, "edges", ()) or ()
            if getattr(getattr(edge, "source_key", None), "state_const", None) is not None
            and (int(getattr(getattr(edge, "source_key", None), "state_const")) & 0xFFFFFFFF) == source_state
            and (
                source_block is None
                or int(
                    getattr(getattr(edge, "source_anchor", None), "block_serial", -1)
                )
                == source_block
            )
        ]
        matched_labels: set[str] = set()
        unmatched_alias_edges: list[object] = []
        for edge in source_edges:
            target_state_attr = getattr(edge, "target_state", None)
            if target_state_attr is None:
                continue
            target_state_value = int(target_state_attr) & 0xFFFFFFFF
            direct_label = f"STATE_{target_state_value:08X}"
            if direct_label in semantic_labels:
                matched_labels.add(direct_label)
            else:
                unmatched_alias_edges.append(edge)
        unmatched_labels = [
            label for label in semantic_labels if label not in matched_labels
        ]
        if len(unmatched_alias_edges) != 1 or len(unmatched_labels) != 1:
            continue
        alias_edge = unmatched_alias_edges[0]
        ordered_path = tuple(int(node) for node in getattr(alias_edge, "ordered_path", ()) or ())
        if int(pred_serial) not in ordered_path:
            continue
        target_entry = semantic_entry_by_label.get(unmatched_labels[0])
        if target_entry is not None and int(target_entry) != int(pred_serial):
            return int(target_entry)
    return None


def _resolve_frontier_target_entry(
    dag,
    *,
    pred_serial: int,
    state_value: int,
    dispatcher_model,
    bst_blocks: set[int],
    semantic_reference_program: object | None,
    state_var_stkoff: int | None,
    mba: object | None,
) -> tuple[int | None, int | None]:
    """Resolve the best semantic entry for a residual feeder state write."""
    raw_state = int(state_value) & 0xFFFFFFFF
    exact_dispatch_target = dispatcher_exact_state_target(
        raw_state,
        dispatcher=dispatcher_model,
    )
    residual_effective_target = None
    synthetic_target_entry = supplemental_selected_entry_for_state(
        dag,
        raw_state,
    )
    if (
        dispatcher_model is not None
        and state_var_stkoff is not None
        and mba is not None
    ):
        synthetic_edge = SimpleNamespace(
            source_anchor=SimpleNamespace(block_serial=int(pred_serial), branch_arm=None),
            source_key=SimpleNamespace(state_const=None),
            target_key=None,
            target_state=raw_state,
            target_label=f"STATE_{raw_state:08X}",
            target_entry_anchor=synthetic_target_entry,
            ordered_path=(int(pred_serial),),
        )
        residual_effective_target = resolve_effective_residual_target_entry(
            dag,
            synthetic_edge,
            bst_node_blocks=bst_blocks,
            state_var_stkoff=int(state_var_stkoff),
            dispatcher_lookup=getattr(dispatcher_model, "lookup", None),
            dispatcher=dispatcher_model,
            mba=mba,
        )
    exact_dag_entry = resolve_exact_dag_entry_for_state(
        dag,
        raw_state,
        dispatcher_region=bst_blocks,
    )
    direct_semantic_entry = resolve_semantic_reference_entry_for_state(
        raw_state,
        semantic_reference_program=semantic_reference_program,
        dispatcher_region=bst_blocks,
    )
    target_entry = resolve_dag_entry_for_state(
        dag,
        raw_state,
        bst_node_blocks=bst_blocks,
    )
    normalized_alias_entry = resolve_normalized_alias_entry_for_state(
        dag,
        raw_state,
        source_block=int(pred_serial),
        bst_node_blocks=bst_blocks,
    )
    semantic_alias_entry = _resolve_semantic_reference_alias_entry(
        dag,
        semantic_reference_program,
        pred_serial=int(pred_serial),
        state_value=raw_state,
    )
    if (
        residual_effective_target is not None
        and int(residual_effective_target) != int(pred_serial)
    ):
        target_entry = int(residual_effective_target)
    if (
        residual_effective_target is None
        and exact_dag_entry is not None
        and int(exact_dag_entry) != int(pred_serial)
    ):
        target_entry = int(exact_dag_entry)
    if (
        residual_effective_target is None
        and
        direct_semantic_entry is not None
        and int(direct_semantic_entry) != int(pred_serial)
    ):
        target_entry = int(direct_semantic_entry)
    if (
        residual_effective_target is None
        and
        semantic_alias_entry is not None
        and semantic_alias_entry != int(pred_serial)
        and semantic_alias_entry != target_entry
    ):
        target_entry = int(semantic_alias_entry)
    preferred_alias_entry = normalized_alias_entry
    if (
        preferred_alias_entry is not None
        and preferred_alias_entry != int(pred_serial)
        and (
            target_entry is None
            or int(target_entry) == int(pred_serial)
            or (
                exact_dispatch_target is not None
                and int(target_entry) == int(exact_dispatch_target)
            )
        )
    ):
        target_entry = int(preferred_alias_entry)
    if (
        target_entry is None
        or int(target_entry) in bst_blocks
        or int(target_entry) == int(pred_serial)
    ):
        target_entry = supplemental_selected_entry_for_state(
            dag,
            raw_state,
        )
    if target_entry is not None:
        target_entry = int(target_entry)
    return (
        None if exact_dispatch_target is None else int(exact_dispatch_target),
        target_entry,
    )


def _collect_supported_exact_entries(round_summary, flow_graph, *, bst_blocks: set[int]) -> set[int]:
    """Return exact-node entry blocks that are safe BST bypass targets."""
    supported_entries = {
        int(site.source_block)
        for site in collect_exact_conditional_sites(round_summary, flow_graph)
    }
    supported_entries.update(
        int(site.source_block)
        for site in collect_exact_conditional_alias_sites(round_summary, flow_graph)
    )
    supported_entries.update(
        int(site.source_block)
        for site in collect_exact_conditional_fork_sites(round_summary, flow_graph)
    )
    supported_entries.update(
        int(site.source_block)
        for site in collect_exact_conditional_bridge_sites(round_summary, flow_graph)
    )
    for plannable in getattr(round_summary, "plannable_edges", ()):
        edge = getattr(plannable, "edge", None)
        if edge is None or not _is_straight_line_handoff(edge):
            continue
        target_state = getattr(edge, "target_state", None)
        if target_state is None:
            continue
        target_entry = resolve_dag_entry_for_state(
            round_summary.dag,
            int(target_state) & 0xFFFFFFFF,
            bst_node_blocks=bst_blocks,
        )
        if target_entry is None or int(target_entry) in bst_blocks:
            continue
        supported_entries.add(int(target_entry))
    return supported_entries


def _collect_owned_exact_sources(round_summary, flow_graph) -> set[int]:
    """Return source blocks already owned by earlier exact-node lowerers."""
    owned_sources = {
        int(site.source_block)
        for site in collect_exact_conditional_sites(round_summary, flow_graph)
    }
    owned_sources.update(
        int(site.source_block)
        for site in collect_exact_conditional_alias_sites(round_summary, flow_graph)
    )
    owned_sources.update(
        int(site.source_block)
        for site in collect_exact_conditional_fork_sites(round_summary, flow_graph)
    )
    owned_sources.update(
        int(site.source_block)
        for site in collect_exact_conditional_bridge_sites(round_summary, flow_graph)
    )
    for plannable in getattr(round_summary, "plannable_edges", ()):
        edge = getattr(plannable, "edge", None)
        if edge is None or not _is_straight_line_handoff(edge):
            continue
        source_anchor = getattr(edge, "source_anchor", None)
        source_block = getattr(source_anchor, "block_serial", None)
        if source_block is None:
            continue
        owned_sources.add(int(source_block))
    return owned_sources


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


def _is_supplemental_feeder_bypass(
    *,
    flow_graph,
    pred_serial: int,
    pred_block,
    state_value: int,
    exact_dispatch_target: int | None,
    target_entry: int,
    bst_blocks: set[int],
    supported_entries: set[int],
    owned_exact_sources: set[int],
    terminal_source_owned_blocks: set[int],
    terminal_protected_blocks: set[int],
    dag,
) -> bool:
    """Return whether a residual dispatcher feeder is safe for supplemental bypass.

    This path exists for synthetic corridor/feed blocks that still write one
    semantic state and jump back into the dispatcher, but whose resolved DAG
    entry was not part of the first-wave exact-head inventory.
    """
    pred_serial = int(pred_serial)
    target_entry = int(target_entry)
    if target_entry in bst_blocks or target_entry in supported_entries:
        return False
    if pred_serial == target_entry:
        return False
    if pred_serial in terminal_source_owned_blocks or pred_serial in terminal_protected_blocks:
        return False
    if pred_serial in owned_exact_sources:
        return False
    if int(getattr(pred_block, "nsucc", 0)) != 1:
        return False
    succs = tuple(int(succ) for succ in getattr(pred_block, "succs", ()))
    if len(succs) != 1:
        return False
    if not (
        state_has_semantic_support(dag, int(state_value) & 0xFFFFFFFF)
        or (
            exact_dispatch_target is not None
            and int(exact_dispatch_target) != int(target_entry)
        )
        or can_reach_return_snapshot(flow_graph, int(target_entry))
    ):
        return False
    return True


def _is_structured_conditional_path_feeder(
    dag,
    *,
    pred_serial: int,
    state_value: int,
) -> bool:
    """Return whether ``pred_serial`` is the feeder row for a conditional path.

    If the live DAG already models a conditional semantic edge as
    ``source_head -> feeder_row -> target_entry``, then the structured-region
    lowerer should own that source arm. Redirecting the feeder row itself keeps
    the flattened encoding alive and competes with the source-arm rewrite.
    """

    raw_state = int(state_value) & 0xFFFFFFFF
    pred_serial = int(pred_serial)
    for edge in getattr(dag, "edges", ()) or ():
        target_state = getattr(edge, "target_state", None)
        if target_state is None or (int(target_state) & 0xFFFFFFFF) != raw_state:
            continue
        source_anchor = getattr(edge, "source_anchor", None)
        if getattr(source_anchor, "branch_arm", None) is None:
            continue
        ordered_path = tuple(
            int(block) for block in getattr(edge, "ordered_path", ()) or ()
        )
        if len(ordered_path) < 2:
            continue
        if int(ordered_path[0]) == pred_serial:
            continue
        if int(ordered_path[1]) != pred_serial:
            continue
        return True
    return False


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
        mba = getattr(snapshot, "mba", None)
        if mba is None or int(getattr(mba, "entry_ea", 0)) != _SUB7FFD_FUNC_EA:
            return False
        if int(getattr(mba, "maturity", ida_hexrays.MMAT_ZERO)) != ida_hexrays.MMAT_GLBOPT1:
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

        state_var = getattr(state_machine, "state_var", None)
        if state_var is None or getattr(state_var, "t", None) != ida_hexrays.mop_S:
            return None
        state_var_stkoff = getattr(getattr(state_var, "s", None), "off", None)
        if state_var_stkoff is None:
            return None

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

        supported_entries = _collect_supported_exact_entries(
            round_summary,
            flow_graph,
            bst_blocks=bst_blocks,
        )
        owned_exact_sources = _collect_owned_exact_sources(round_summary, flow_graph)
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

            state_value = resolve_singleton_state_write_value(
                mba,
                int(pred_serial),
                state_var_stkoff=int(state_var_stkoff),
            )
            if state_value is None:
                skipped_no_state += 1
                continue
            if _is_structured_conditional_path_feeder(
                round_summary.dag,
                pred_serial=int(pred_serial),
                state_value=int(state_value) & 0xFFFFFFFF,
            ):
                skipped_structured_conditional_feeder += 1
                continue
            exact_dispatch_target, target_entry = _resolve_frontier_target_entry(
                round_summary.dag,
                pred_serial=int(pred_serial),
                state_value=int(state_value) & 0xFFFFFFFF,
                dispatcher_model=dispatcher_model,
                bst_blocks=bst_blocks,
                semantic_reference_program=getattr(round_summary, "semantic_reference_program", None),
                state_var_stkoff=int(state_var_stkoff),
                mba=mba,
            )
            if (
                target_entry is None
                or int(target_entry) in bst_blocks
                or int(target_entry) == int(pred_serial)
            ):
                skipped_unsupported_entry += 1
                continue

            allow_supplemental_bypass = _is_supplemental_feeder_bypass(
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
