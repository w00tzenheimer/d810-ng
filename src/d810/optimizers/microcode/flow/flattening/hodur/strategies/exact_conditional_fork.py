"""Experimental lowering for exact conditional nodes with two semantic exits."""
from __future__ import annotations

from dataclasses import dataclass, replace
import os
import re

import ida_hexrays

from d810.core import logging
from d810.core.algorithm_metadata import algorithm_metadata
from d810.cfg.flow.conditional_alias import (
    analyze_duplicate_alias_conditional_sites,
)
from d810.cfg.graph_modification import NopInstructions, ZeroStateWrite
from d810.cfg.semantic_region_lowering import (
    _collect_semantic_entry_by_label,
    _collect_semantic_successors_by_state,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.semantic_exact_node import (
    _SUB7FFD_FUNC_EA,
    build_semantic_exact_round_summary,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_node import (
    _conditional_distance_to_return,
    _compute_postdominator_tree,
    _edge_kind_name,
    _site_key,
)
from d810.recon.flow.path_horizon import resolve_transition_path_horizon
from d810.recon.flow.residual_handoff_resolution import (
    resolve_effective_target_entry,
)
from d810.recon.flow.residual_handoff_discovery import (
    resolve_normalized_alias_entry_for_state,
    resolve_redirect_safe_entry_from_node,
    resolve_redirect_safe_target_entry,
    supplemental_selected_entry_for_state,
)
from d810.recon.flow.target_entry_resolution import (
    resolve_exact_dag_entry_for_state,
    resolve_semantic_reference_entry_for_state,
)
from d810.recon.flow.graph_reachability import collect_residual_dispatcher_predecessors
from d810.recon.flow.state_machine_analysis import (
    run_snapshot_constant_fixpoint,
)

logger = logging.getLogger(
    "D810.hodur.strategy.exact_conditional_fork",
    logging.DEBUG,
)

_STATE_LABEL_RE = re.compile(r"^STATE_([0-9A-Fa-f]{8})(?:_fallback)?$")

__all__ = [
    "ConditionalForkExactNodeArm",
    "ConditionalForkExactNodeSite",
    "ExactConditionalForkInventory",
    "ExactConditionalForkNodeLoweringStrategy",
    "analyze_exact_conditional_fork_sites",
    "collect_exact_conditional_fork_sites",
]


@dataclass(frozen=True, slots=True)
class ConditionalForkExactNodeArm:
    target_state: int
    target_entry: int
    first_hop: int
    tail: int
    ordered_path: tuple[int, ...]
    transition_edge: object
    return_distance: int | None


@dataclass(frozen=True, slots=True)
class ConditionalForkExactNodeSite:
    source_block: int
    follow_block: int | None
    arms: tuple[ConditionalForkExactNodeArm, ConditionalForkExactNodeArm]


@dataclass(frozen=True, slots=True)
class ExactConditionalForkInventory:
    selected_count: int
    candidate_blocks: tuple[int, ...]
    plannable_incomplete_blocks: tuple[int, ...]
    shape_rejected_blocks: tuple[int, ...]
    clean_fork_blocks: tuple[int, ...] = ()
    boundary_preservation_blocks: tuple[int, ...] = ()
    alias_handled_blocks: tuple[int, ...] = ()


def _require_clean_fork_paths() -> bool:
    """Default exact-fork lowering to Hex-Rays-friendly clean fork shapes.

    The structuring lab showed that preserving physical block boundaries is a
    weak objective: Hex-Rays may fold those blocks anyway. Exact fork lowering
    should therefore only own sites that already look like a clean two-arm
    fork. Shared-suffix or multi-pred arm tails are boundary-preservation
    problems and should remain with HCC/SWR unless explicitly bisecting.
    """

    return (
        os.environ.get("D810_EXACT_CONDITIONAL_FORK_REQUIRE_CLEAN", "1").strip()
        != "0"
    )


def _path_from_source(
    *,
    source_block: int,
    first_hop: int,
    ordered_path: tuple[int, ...],
) -> tuple[int, ...] | None:
    if not ordered_path:
        return None
    try:
        source_index = ordered_path.index(int(source_block))
    except ValueError:
        return None
    path = ordered_path[source_index:]
    if len(path) < 2:
        return None
    if int(path[1]) != int(first_hop):
        return None
    return path


def _path_edges_exist(flow_graph, path: tuple[int, ...]) -> bool:
    for current, nxt in zip(path, path[1:]):
        block = flow_graph.get_block(int(current))
        if block is None:
            return False
        succs = tuple(int(succ) for succ in getattr(block, "succs", ()) or ())
        if int(nxt) not in succs:
            return False
    return True


def _single_pred_path_blocks(flow_graph, path: tuple[int, ...]) -> bool:
    for block_serial in path:
        block = flow_graph.get_block(int(block_serial))
        if block is None:
            return False
        if int(getattr(block, "npred", 0)) != 1:
            return False
    return True


def _normalize_clean_fork_arms(
    flow_graph,
    *,
    source_block: int,
    arms: tuple[ConditionalForkExactNodeArm, ConditionalForkExactNodeArm],
    dispatcher_region: set[int],
) -> tuple[ConditionalForkExactNodeArm, ConditionalForkExactNodeArm] | None:
    paths: list[tuple[int, ...]] = []
    for arm in arms:
        path = _path_from_source(
            source_block=source_block,
            first_hop=arm.first_hop,
            ordered_path=arm.ordered_path,
        )
        if path is None or not _path_edges_exist(flow_graph, path):
            return None
        paths.append(path)

    terminal_blocks = {int(path[-1]) for path in paths}
    if len(terminal_blocks) == len(arms):
        if all(_single_pred_path_blocks(flow_graph, path[1:]) for path in paths):
            return arms
        return None

    if len(terminal_blocks) != 1:
        return None

    shared_join = next(iter(terminal_blocks))
    join_block = flow_graph.get_block(shared_join)
    if join_block is None:
        return None
    if shared_join in dispatcher_region:
        return None
    join_succs = tuple(int(succ) for succ in getattr(join_block, "succs", ()) or ())
    if len(join_succs) != 1:
        return None
    if any(succ in dispatcher_region for succ in join_succs):
        return None
    if tuple(getattr(join_block, "insn_snapshots", ()) or ()):
        return None

    if any(len(path) < 3 for path in paths):
        return None
    arm_tails = tuple(int(path[-2]) for path in paths)
    if len(set(arm_tails)) != len(arms):
        return None
    join_preds = {int(pred) for pred in getattr(join_block, "preds", ()) or ()}
    if join_preds != set(arm_tails):
        return None
    if int(getattr(join_block, "npred", 0)) != len(arms):
        return None

    seen_path_blocks: set[int] = set()
    for path in paths:
        arm_path = path[1:-1]
        if not _single_pred_path_blocks(flow_graph, arm_path):
            return None
        for block_serial in arm_path:
            if int(block_serial) in seen_path_blocks:
                return None
            seen_path_blocks.add(int(block_serial))

    return tuple(
        replace(arm, tail=int(path[-2]))
        for arm, path in zip(arms, paths)
    )


def _collect_conditional_fork_scope(
    dag: object,
    *,
    source_block: int,
) -> tuple[set[int], set[tuple[int, int]]]:
    owned_blocks: set[int] = {source_block}
    owned_edges: set[tuple[int, int]] = set()

    for sibling in getattr(dag, "edges", ()) or ():
        key = _site_key(sibling)
        if key is None or key[1] != source_block:
            continue
        if _edge_kind_name(sibling) != "CONDITIONAL_TRANSITION":
            continue
        path = tuple(int(node) for node in getattr(sibling, "ordered_path", ()) or ())
        if not path:
            continue
        owned_blocks.update(path)
        owned_edges.update(zip(path, path[1:]))
    return owned_blocks, owned_edges


def _effective_transition_target_entry(
    edge: object,
    *,
    dag: object,
    dag_nodes: tuple[object, ...],
    semantic_reference_program: object | None,
    bst_node_blocks: set[int],
    state_var_stkoff: int | None,
    dispatcher_lookup: object | None,
    dispatcher: object | None,
    mba: object | None,
) -> int | None:
    source_block = getattr(getattr(edge, "source_anchor", None), "block_serial", None)
    target_state_value = getattr(edge, "target_state", None)
    raw_target_entry_anchor = getattr(edge, "target_entry_anchor", None)
    exact_dag_entry = None
    direct_semantic_entry = None
    supplemental_selected_entry = None
    normalized_alias_entry = None
    if target_state_value is not None:
        exact_dag_entry = resolve_exact_dag_entry_for_state(
            dag,
            int(target_state_value),
            dispatcher_region=bst_node_blocks,
        )
        direct_semantic_entry = resolve_semantic_reference_entry_for_state(
            int(target_state_value),
            semantic_reference_program=semantic_reference_program,
            dispatcher_region=bst_node_blocks,
        )
        if (
            direct_semantic_entry is not None
            and direct_semantic_entry != source_block
        ):
            return int(direct_semantic_entry)
        supplemental_selected_entry = supplemental_selected_entry_for_state(
            dag,
            int(target_state_value),
        )
        if (
            supplemental_selected_entry is not None
            and supplemental_selected_entry != source_block
            and (
                raw_target_entry_anchor is None
                or int(supplemental_selected_entry) != int(raw_target_entry_anchor)
            )
        ):
            return int(supplemental_selected_entry)
        try:
            normalized_alias_entry = resolve_normalized_alias_entry_for_state(
                dag,
                int(target_state_value),
                source_block=(
                    None if source_block is None else int(source_block)
                ),
                bst_node_blocks=bst_node_blocks,
            )
        except Exception:
            normalized_alias_entry = None
        if (
            normalized_alias_entry is not None
            and normalized_alias_entry != source_block
            and (
                raw_target_entry_anchor is None
                or int(normalized_alias_entry) != int(raw_target_entry_anchor)
            )
        ):
            return int(normalized_alias_entry)
        if exact_dag_entry is not None and exact_dag_entry != source_block:
            return int(exact_dag_entry)
    try:
        effective_target_entry = resolve_effective_target_entry(
            dag,
            edge,
            bst_node_blocks=bst_node_blocks,
            state_var_stkoff=state_var_stkoff,
            dispatcher_lookup=dispatcher_lookup,
            dispatcher=dispatcher,
            mba=mba,
        )
    except Exception:
        effective_target_entry = None
    if effective_target_entry is not None:
        if (
            normalized_alias_entry is not None
            and normalized_alias_entry != source_block
            and raw_target_entry_anchor is not None
            and int(effective_target_entry) == int(raw_target_entry_anchor)
        ):
            return int(normalized_alias_entry)
        return int(effective_target_entry)

    try:
        target_entry = resolve_redirect_safe_target_entry(
            dag,
            edge,
            bst_node_blocks=bst_node_blocks,
        )
    except Exception:
        target_entry = None

    if normalized_alias_entry is not None and normalized_alias_entry != source_block:
        return int(normalized_alias_entry)
    if target_entry is not None:
        return int(target_entry)

    target_key = getattr(edge, "target_key", None)
    target_handler = getattr(target_key, "handler_serial", None)
    target_state = getattr(target_key, "state_const", None)
    if target_handler is not None:
        for node in dag_nodes:
            node_key = getattr(node, "key", None)
            if node_key is None:
                continue
            if int(getattr(node_key, "handler_serial", -1)) != int(target_handler):
                continue
            node_state = getattr(node_key, "state_const", None)
            if target_state is not None and node_state is not None:
                if int(node_state) & 0xFFFFFFFF != int(target_state) & 0xFFFFFFFF:
                    continue
            entry_anchor = getattr(node, "entry_anchor", None)
            if entry_anchor is not None:
                return int(entry_anchor)
    target_label = str(getattr(edge, "target_label", "") or "")
    if target_label:
        for node in dag_nodes:
            state_label = str(getattr(node, "state_label", "") or "")
            if state_label != target_label:
                continue
            entry_anchor = getattr(node, "entry_anchor", None)
            if entry_anchor is not None:
                return int(entry_anchor)
    target_entry_anchor = getattr(edge, "target_entry_anchor", None)
    if target_entry_anchor is None:
        return None
    return int(target_entry_anchor)


def _resolve_semantic_target_override_entry(
    target_label: str,
    *,
    dag_nodes: tuple[object, ...],
    semantic_entry_by_label: dict[str, int],
    dag: object,
    bst_blocks: set[int],
) -> int | None:
    """Resolve a semantic-reference target label to a family entry.

    For fallback labels, prefer the semantic-family entry over a redirect-safe
    corridor lead. That keeps alias normalization aligned with the rendered
    semantic reference program instead of re-entering through a transient
    corridor block.
    """
    target_entry_anchor = semantic_entry_by_label.get(target_label)
    dag_target_label = (
        f"0x{target_label[len('STATE_'):]}"
        if target_label.startswith("STATE_")
        else target_label
    )
    matched_node = None
    for node in dag_nodes:
        if str(getattr(node, "state_label", "") or "") == dag_target_label:
            matched_node = node
            break

    if matched_node is not None and target_label.endswith("_fallback"):
        if target_entry_anchor is not None:
            return int(target_entry_anchor)
        entry_anchor = getattr(matched_node, "entry_anchor", None)
        if entry_anchor is not None:
            return int(entry_anchor)
        for block in getattr(matched_node, "exclusive_blocks", ()) or ():
            return int(block)
        for block in getattr(matched_node, "owned_blocks", ()) or ():
            return int(block)

    if matched_node is not None:
        target_entry_anchor = resolve_redirect_safe_entry_from_node(
            matched_node,
            dag=dag,
            bst_node_blocks=bst_blocks,
        )
        if target_entry_anchor is not None:
            return int(target_entry_anchor)

    if target_entry_anchor is not None:
        return int(target_entry_anchor)
    return None


def _ordered_path_first_hop(
    ordered_path: tuple[int, ...],
    *,
    source_block: int,
) -> int | None:
    if not ordered_path:
        return None
    try:
        source_index = ordered_path.index(int(source_block))
    except ValueError:
        return int(ordered_path[1]) if len(ordered_path) >= 2 else None
    next_index = source_index + 1
    if next_index >= len(ordered_path):
        return None
    return int(ordered_path[next_index])


def _safe_zero_state_write_modification(
    *,
    setup,
    flow_graph,
    edge: object,
    tail_block_serial: int,
    constant_result,
) -> ZeroStateWrite | None:
    state_var_stkoff = getattr(setup, "state_var_stkoff", None)
    if state_var_stkoff is None:
        return None
    ordered_path = tuple(int(node) for node in getattr(edge, "ordered_path", ()) or ())
    if not ordered_path:
        return None
    resolved = resolve_transition_path_horizon(
        edge,
        flow_graph=flow_graph,
        ordered_path=ordered_path,
        state_var_stkoff=int(state_var_stkoff),
        constant_result=constant_result,
    )
    if resolved is None:
        return None
    horizon_block, site = resolved
    if int(horizon_block) != int(tail_block_serial):
        return None
    expected_state = getattr(edge, "target_state", None)
    if expected_state is None:
        return None
    if int(site.state_value) & 0xFFFFFFFF != int(expected_state) & 0xFFFFFFFF:
        return None
    return setup.builder.zero_state_write(int(horizon_block), int(site.insn_ea))


def _trivial_tail_state_write_cleanup_modification(
    *,
    setup,
    flow_graph,
    tail_block_serial: int,
    expected_state: int,
) -> NopInstructions | None:
    """Remove a trivial local ``state = CONST`` handoff before a redirected goto.

    This is the preferred cleanup for leaf fork-arm tails shaped like:

    ``mov #STATE, state_var``
    ``goto successor``

    Once the successor is redirected to the semantic target, the local state
    assignment is pure flattened-dispatcher scaffolding and can be NOP'd
    entirely.
    """

    state_var_stkoff = getattr(setup, "state_var_stkoff", None)
    if state_var_stkoff is None:
        return None
    block = flow_graph.get_block(int(tail_block_serial))
    if block is None:
        return None
    insns = tuple(getattr(block, "insn_snapshots", ()) or ())
    if len(insns) != 2:
        return None

    write_insn, tail_insn = insns
    if getattr(write_insn, "opcode", None) != ida_hexrays.m_mov:
        return None
    if getattr(tail_insn, "opcode", None) != ida_hexrays.m_goto:
        return None

    dest = getattr(write_insn, "d", None)
    src = getattr(write_insn, "l", None)
    if dest is None or src is None:
        return None
    if getattr(dest, "t", None) != ida_hexrays.mop_S:
        return None
    if getattr(dest, "stkoff", None) != int(state_var_stkoff):
        return None
    if getattr(src, "t", None) != ida_hexrays.mop_n:
        return None
    value = getattr(src, "value", None)
    if value is None:
        return None
    if (int(value) & 0xFFFFFFFF) != (int(expected_state) & 0xFFFFFFFF):
        return None
    insn_ea = int(getattr(write_insn, "ea", 0) or 0)
    if insn_ea == 0:
        return None
    return setup.builder.nop_instruction(int(tail_block_serial), insn_ea)


def _fallback_zero_state_write_modification(
    *,
    setup,
    flow_graph,
    tail_block_serial: int,
    expected_state: int,
    debug_label: str | None = None,
) -> ZeroStateWrite | None:
    """Zero a redirected arm's local state write when the tail block proves it directly.

    This is narrower than the path-horizon helper above. It only fires when the
    tail block itself contains exactly one constant write to the tracked state
    slot and that write matches the semantic arm target. This covers simple leaf
    tails like ``blk[16]`` / ``blk[17]`` where the redirect is correct but the
    stale ``state = ...`` assignment would otherwise survive in pseudocode.
    """

    state_var_stkoff = getattr(setup, "state_var_stkoff", None)
    if state_var_stkoff is None:
        if debug_label is not None:
            logger.info(
                "EXACT CONDITIONAL FORK: %s zero-state fallback skipped (missing_state_var_stkoff)",
                debug_label,
            )
        return None
    block = flow_graph.get_block(int(tail_block_serial))
    if block is None:
        if debug_label is not None:
            logger.info(
                "EXACT CONDITIONAL FORK: %s zero-state fallback skipped (missing_tail_block=%d)",
                debug_label,
                tail_block_serial,
            )
        return None

    matched_insn_ea: int | None = None
    state_write_count = 0
    expected_state = int(expected_state) & 0xFFFFFFFF
    for insn in tuple(getattr(block, "insn_snapshots", ()) or ()):
        if getattr(insn, "opcode", None) != ida_hexrays.m_mov:
            continue
        dest = getattr(insn, "d", None)
        src = getattr(insn, "l", None)
        if dest is None or src is None:
            continue
        if getattr(dest, "t", None) != ida_hexrays.mop_S:
            continue
        if getattr(dest, "stkoff", None) != int(state_var_stkoff):
            continue
        state_write_count += 1
        if getattr(src, "t", None) != ida_hexrays.mop_n:
            if debug_label is not None:
                logger.info(
                    "EXACT CONDITIONAL FORK: %s zero-state fallback rejected (nonconst_state_write blk=%d ea=0x%x src_t=%s)",
                    debug_label,
                    tail_block_serial,
                    int(getattr(insn, "ea", 0) or 0),
                    getattr(src, "t", None),
                )
            return None
        value = getattr(src, "value", None)
        if value is None:
            if debug_label is not None:
                logger.info(
                    "EXACT CONDITIONAL FORK: %s zero-state fallback rejected (missing_state_value blk=%d ea=0x%x)",
                    debug_label,
                    tail_block_serial,
                    int(getattr(insn, "ea", 0) or 0),
                )
            return None
        if (int(value) & 0xFFFFFFFF) != expected_state:
            if debug_label is not None:
                logger.info(
                    "EXACT CONDITIONAL FORK: %s zero-state fallback rejected (state_mismatch blk=%d ea=0x%x saw=0x%08X expected=0x%08X)",
                    debug_label,
                    tail_block_serial,
                    int(getattr(insn, "ea", 0) or 0),
                    int(value) & 0xFFFFFFFF,
                    expected_state,
                )
            return None
        matched_insn_ea = int(getattr(insn, "ea", 0) or 0)

    if state_write_count != 1 or matched_insn_ea in (None, 0):
        if debug_label is not None:
            logger.info(
                "EXACT CONDITIONAL FORK: %s zero-state fallback skipped (state_write_count=%d matched_ea=%s)",
                debug_label,
                state_write_count,
                "None" if matched_insn_ea in (None, 0) else hex(int(matched_insn_ea)),
            )
        return None
    if debug_label is not None:
        logger.info(
            "EXACT CONDITIONAL FORK: %s zero-state fallback accepted blk=%d ea=0x%x",
            debug_label,
            tail_block_serial,
            int(matched_insn_ea),
        )
    return setup.builder.zero_state_write(int(tail_block_serial), int(matched_insn_ea))


def analyze_exact_conditional_fork_sites(
    round_summary,
    flow_graph,
    *,
    bst_node_blocks: set[int] | None = None,
    dispatcher_region: set[int] | None = None,
    state_var_stkoff: int | None = None,
    dispatcher_lookup: object | None = None,
    dispatcher: object | None = None,
    mba: object | None = None,
) -> tuple[tuple[ConditionalForkExactNodeSite, ...], ExactConditionalForkInventory]:
    dag = round_summary.dag
    dag_nodes = tuple(getattr(dag, "nodes", ()) or ())
    structured_region_states = {
        int(state) & 0xFFFFFFFF
        for region in tuple(getattr(round_summary, "structured_regions", ()) or ())
        for state in tuple(getattr(region, "state_values", ()) or ())
    }
    semantic_reference_program = getattr(round_summary, "semantic_reference_program", None)
    semantic_successors_by_state = _collect_semantic_successors_by_state(
        semantic_reference_program
    )
    semantic_entry_by_label = _collect_semantic_entry_by_label(
        semantic_reference_program
    )
    bst_blocks = {int(block) for block in (bst_node_blocks or set())}
    forbidden_corridor_blocks = {
        int(block) for block in (dispatcher_region or set())
    }
    forbidden_corridor_blocks.update(bst_blocks)
    postdom_tree = _compute_postdominator_tree(flow_graph)
    return_distance = _conditional_distance_to_return(flow_graph)
    alias_handled_blocks = {
        int(site.source_block)
        for site in analyze_duplicate_alias_conditional_sites(round_summary, flow_graph)
    }
    transition_edges_by_source: dict[int, list[object]] = {}
    return_edges_by_source: dict[int, list[object]] = {}
    for edge in getattr(dag, "edges", ()) or ():
        key = _site_key(edge)
        if key is None:
            continue
        source_block = key[1]
        kind_name = _edge_kind_name(edge)
        if kind_name == "CONDITIONAL_TRANSITION":
            transition_edges_by_source.setdefault(source_block, []).append(edge)
        elif kind_name == "CONDITIONAL_RETURN":
            return_edges_by_source.setdefault(source_block, []).append(edge)

    def _dedup_transition_edges(source_block: int) -> tuple[object, ...]:
        unique: dict[tuple[int, int, int], object] = {}
        for edge in transition_edges_by_source.get(source_block, []):
            ordered_path = tuple(int(node) for node in getattr(edge, "ordered_path", ()) or ())
            first_hop = _ordered_path_first_hop(
                ordered_path,
                source_block=int(source_block),
            )
            target_entry = _effective_transition_target_entry(
                edge,
                dag=dag,
                dag_nodes=dag_nodes,
                semantic_reference_program=semantic_reference_program,
                bst_node_blocks=bst_blocks,
                state_var_stkoff=state_var_stkoff,
                dispatcher_lookup=dispatcher_lookup,
                dispatcher=dispatcher,
                mba=mba,
            )
            if first_hop is None or not ordered_path or target_entry is None:
                continue
            signature = (
                int(first_hop),
                int(ordered_path[-1]),
                int(target_entry),
            )
            unique.setdefault(signature, edge)
        return tuple(unique.values())

    candidate_blocks = tuple(
        sorted(
            source_block
            for source_block in transition_edges_by_source
            if (
                len(_dedup_transition_edges(source_block)) == 2
                and not return_edges_by_source.get(source_block)
                and source_block not in alias_handled_blocks
            )
        )
    )
    selected: list[ConditionalForkExactNodeSite] = []
    plannable_incomplete_blocks: set[int] = set()
    shape_rejected_blocks: set[int] = set()
    clean_fork_blocks: set[int] = set()
    boundary_preservation_blocks: set[int] = set()
    require_clean_fork_paths = _require_clean_fork_paths()
    for source_block in sorted(transition_edges_by_source):
        dag_edges = _dedup_transition_edges(source_block)
        if source_block in alias_handled_blocks:
            continue
        if return_edges_by_source.get(source_block):
            continue
        if dag_edges:
            source_state_value = getattr(
                getattr(dag_edges[0], "source_key", None),
                "state_const",
                None,
            )
            if (
                source_state_value is not None
                and (int(source_state_value) & 0xFFFFFFFF) in structured_region_states
            ):
                continue
        source_snapshot = flow_graph.get_block(source_block)
        if source_snapshot is None or int(getattr(source_snapshot, "nsucc", 0)) != 2:
            shape_rejected_blocks.add(source_block)
            continue
        succs = tuple(int(succ) for succ in getattr(source_snapshot, "succs", ()))
        if len(dag_edges) != 2:
            continue

        semantic_target_override_by_edge_id: dict[int, tuple[int, int | None]] = {}
        semantic_source_state = int(
            getattr(getattr(dag_edges[0], "source_key", None), "state_const", 0)
            & 0xFFFFFFFF
        )
        semantic_labels = tuple(
            semantic_successors_by_state.get(semantic_source_state, ())
        )
        if semantic_labels:
            matched_labels: set[str] = set()
            unmatched_alias_edges: list[object] = []
            for edge in dag_edges:
                target_state_value = int(getattr(edge, "target_state", 0) & 0xFFFFFFFF)
                direct_label = f"STATE_{target_state_value:08X}"
                if direct_label in semantic_labels:
                    matched_labels.add(direct_label)
                else:
                    unmatched_alias_edges.append(edge)
            unmatched_labels = [
                label for label in semantic_labels if label not in matched_labels
            ]
            if len(unmatched_alias_edges) == 1 and len(unmatched_labels) == 1:
                target_label = unmatched_labels[0]
                target_entry_anchor = _resolve_semantic_target_override_entry(
                    target_label,
                    dag_nodes=dag_nodes,
                    semantic_entry_by_label=semantic_entry_by_label,
                    dag=dag,
                    bst_blocks=bst_blocks,
                )
                if target_entry_anchor is not None:
                    target_state_override: int | None = None
                    match = _STATE_LABEL_RE.match(target_label)
                    if match is not None:
                        target_state_override = int(match.group(1), 16) & 0xFFFFFFFF
                    semantic_target_override_by_edge_id[id(unmatched_alias_edges[0])] = (
                        int(target_entry_anchor),
                        target_state_override,
                    )

        dag_arms = []
        for edge in dag_edges:
            ordered_path = tuple(int(node) for node in getattr(edge, "ordered_path", ()) or ())
            first_hop = _ordered_path_first_hop(
                ordered_path,
                source_block=source_block,
            )
            override = semantic_target_override_by_edge_id.get(id(edge))
            dag_arms.append(
                (
                    (
                        int(override[1])
                        if override is not None and override[1] is not None
                        else int(getattr(edge, "target_state", 0) & 0xFFFFFFFF)
                    ),
                    first_hop,
                    ordered_path[-1] if ordered_path else None,
                    (
                        int(override[0])
                        if override is not None
                        else _effective_transition_target_entry(
                            edge,
                            dag=dag,
                            dag_nodes=dag_nodes,
                            semantic_reference_program=semantic_reference_program,
                            bst_node_blocks=bst_blocks,
                            state_var_stkoff=state_var_stkoff,
                            dispatcher_lookup=dispatcher_lookup,
                            dispatcher=dispatcher,
                            mba=mba,
                        )
                    ),
                )
            )
        arms_by_first_hop: dict[int, ConditionalForkExactNodeArm] = {}
        for edge in dag_edges:
            ordered_path = tuple(int(node) for node in getattr(edge, "ordered_path", ()) or ())
            first_hop = _ordered_path_first_hop(
                ordered_path,
                source_block=source_block,
            )
            override = semantic_target_override_by_edge_id.get(id(edge))
            target_entry_anchor = (
                int(override[0])
                if override is not None
                else _effective_transition_target_entry(
                    edge,
                    dag=dag,
                    dag_nodes=dag_nodes,
                    semantic_reference_program=semantic_reference_program,
                    bst_node_blocks=bst_blocks,
                    state_var_stkoff=state_var_stkoff,
                    dispatcher_lookup=dispatcher_lookup,
                    dispatcher=dispatcher,
                    mba=mba,
                )
            )
            if first_hop is None or not ordered_path or target_entry_anchor is None:
                shape_rejected_blocks.add(source_block)
                continue
            tail = int(ordered_path[-1])
            target_entry = int(target_entry_anchor)
            if target_entry in succs:
                shape_rejected_blocks.add(source_block)
                continue
            if first_hop not in succs or first_hop in arms_by_first_hop:
                shape_rejected_blocks.add(source_block)
                continue
            arms_by_first_hop[first_hop] = ConditionalForkExactNodeArm(
                target_state=(
                    int(override[1])
                    if override is not None and override[1] is not None
                    else int(getattr(edge, "target_state", 0) & 0xFFFFFFFF)
                ),
                target_entry=target_entry,
                first_hop=first_hop,
                tail=tail,
                ordered_path=ordered_path,
                transition_edge=edge,
                return_distance=return_distance.get(first_hop),
            )
        if set(arms_by_first_hop) != set(succs):
            plannable_incomplete_blocks.add(source_block)
            logger.info(
                "EXACT CONDITIONAL FORK: source blk=%d incomplete succs=%s dag_arms=%s",
                source_block,
                succs,
                dag_arms,
            )
            continue

        arms = tuple(arms_by_first_hop[succ] for succ in succs)
        clean_arms = _normalize_clean_fork_arms(
            flow_graph,
            source_block=source_block,
            arms=arms,
            dispatcher_region=forbidden_corridor_blocks,
        )
        if clean_arms is not None:
            arms = clean_arms
            clean_fork_blocks.add(source_block)
        else:
            boundary_preservation_blocks.add(source_block)
            if require_clean_fork_paths:
                shape_rejected_blocks.add(source_block)
                logger.info(
                    "EXACT CONDITIONAL FORK: source blk=%d rejected"
                    " reason=non_clean_fork_path succs=%s arms=%s",
                    source_block,
                    succs,
                    tuple(
                        (
                            int(arm.first_hop),
                            int(arm.tail),
                            int(arm.target_entry),
                            tuple(int(block) for block in arm.ordered_path),
                        )
                        for arm in arms
                    ),
                )
                continue

        follow_block = None
        if postdom_tree is not None:
            follow_block = getattr(postdom_tree, "idom", {}).get(source_block)
        selected.append(
            ConditionalForkExactNodeSite(
                source_block=source_block,
                follow_block=follow_block,
                arms=arms,
            )
        )
    return (
        tuple(selected),
        ExactConditionalForkInventory(
            selected_count=len(selected),
            candidate_blocks=candidate_blocks,
            plannable_incomplete_blocks=tuple(sorted(plannable_incomplete_blocks)),
            shape_rejected_blocks=tuple(sorted(shape_rejected_blocks)),
            clean_fork_blocks=tuple(sorted(clean_fork_blocks)),
            boundary_preservation_blocks=tuple(
                sorted(boundary_preservation_blocks)
            ),
            alias_handled_blocks=tuple(sorted(alias_handled_blocks)),
        ),
    )


def collect_exact_conditional_fork_sites(round_summary, flow_graph) -> tuple[ConditionalForkExactNodeSite, ...]:
    sites, _inventory = analyze_exact_conditional_fork_sites(round_summary, flow_graph)
    return sites


@algorithm_metadata(
    algorithm_id="hodur.exact_conditional_fork_lowering",
    family="semantic_exact_node_lowering",
    summary="Lower exact conditional nodes whose two outgoing arms both lead to semantic successors.",
    use_cases=(
        "Lower an exact semantic predicate with two semantic targets and no terminal return sibling.",
        "Own both conditional exits together instead of treating either branch as a standalone direct edge.",
    ),
    examples=(
        "Lower a `STATE_5FE86821`-style exact node when both branch arms resolve to semantic successor states.",
        "Preserve a two-way semantic fork by redirecting both branch tails to their exact target entries.",
    ),
    tags=("exact-node", "conditional", "fork", "two-way", "predicate-aware"),
    related_paths=(
        "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/exact_conditional_fork.py",
        "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/exact_conditional_node.py",
    ),
)
class ExactConditionalForkNodeLoweringStrategy:
    prerequisites: list[str] = []

    @property
    def name(self) -> str:
        return "exact_conditional_fork_lowering"

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
        mba = snapshot.mba
        assert flow_graph is not None
        assert mba is not None

        sites, inventory = analyze_exact_conditional_fork_sites(
            round_summary,
            flow_graph,
            bst_node_blocks=set(int(block) for block in setup.bst_node_blocks),
            dispatcher_region=set(
                int(block) for block in getattr(setup, "dispatcher_region", ())
            ),
            state_var_stkoff=setup.state_var_stkoff,
            dispatcher_lookup=(
                setup.dispatcher.lookup if setup.dispatcher is not None else None
            ),
            dispatcher=setup.dispatcher,
            mba=mba,
        )
        if not sites:
            logger.info(
                "EXACT CONDITIONAL FORK: no exact fork sites found"
                " (candidates=%s plannable_incomplete=%s shape_rejected=%s"
                " clean_fork=%s boundary_preservation=%s)",
                inventory.candidate_blocks,
                inventory.plannable_incomplete_blocks,
                inventory.shape_rejected_blocks,
                inventory.clean_fork_blocks,
                inventory.boundary_preservation_blocks,
            )
            return None
        logger.info(
            "EXACT CONDITIONAL FORK: inventory selected=%d candidates=%s"
            " plannable_incomplete=%s shape_rejected=%s clean_fork=%s"
            " boundary_preservation=%s alias_handled=%s",
            inventory.selected_count,
            inventory.candidate_blocks,
            inventory.plannable_incomplete_blocks,
            inventory.shape_rejected_blocks,
            inventory.clean_fork_blocks,
            inventory.boundary_preservation_blocks,
            inventory.alias_handled_blocks,
        )

        modifications: list = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        owned_transitions: set[tuple[int, int]] = set()
        accepted_edges: list[tuple[int, int]] = []
        constant_result = run_snapshot_constant_fixpoint(
            flow_graph,
            int(setup.state_var_stkoff),
        )
        for site in sites:
            site_blocks, site_edges = _collect_conditional_fork_scope(
                round_summary.dag,
                source_block=site.source_block,
            )
            for arm in site.arms:
                tail_snapshot = flow_graph.get_block(arm.tail)
                if tail_snapshot is None:
                    continue
                source_state = int(
                    getattr(
                        getattr(arm.transition_edge, "source_key", None),
                        "state_const",
                        0,
                    )
                    & 0xFFFFFFFF
                )
                if int(getattr(tail_snapshot, "npred", 0)) > 1:
                    modifications.append(
                        setup.builder.edge_redirect(
                            arm.tail,
                            arm.target_entry,
                            via_pred=site.source_block,
                            rule_priority=660,
                        )
                    )
                    emission_mode = "fork_pred_split"
                else:
                    modifications.append(
                        setup.builder.goto_redirect(
                            arm.tail,
                            arm.target_entry,
                        )
                    )
                    emission_mode = "fork_redirect"
                state_write_cleanup = _trivial_tail_state_write_cleanup_modification(
                    setup=setup,
                    flow_graph=flow_graph,
                    tail_block_serial=int(arm.tail),
                    expected_state=int(arm.target_state),
                )
                if state_write_cleanup is None:
                    state_write_cleanup = _safe_zero_state_write_modification(
                        setup=setup,
                        flow_graph=flow_graph,
                        edge=arm.transition_edge,
                        tail_block_serial=int(arm.tail),
                        constant_result=constant_result,
                    )
                if state_write_cleanup is None:
                    state_write_cleanup = _fallback_zero_state_write_modification(
                        setup=setup,
                        flow_graph=flow_graph,
                        tail_block_serial=int(arm.tail),
                        expected_state=int(arm.target_state),
                        debug_label=(
                            f"source=0x{source_state:08X} blk={site.source_block} "
                            f"tail={arm.tail} target=0x{int(arm.target_state) & 0xFFFFFFFF:08X}"
                        ),
                    )
                if state_write_cleanup is not None:
                    modifications.append(state_write_cleanup)
                site_edges.add((arm.tail, arm.target_entry))
                owned_transitions.add((source_state, arm.target_state))
                accepted_edges.append((source_state, arm.target_state))
                logger.info(
                    "EXACT CONDITIONAL FORK: source=0x%08X blk=%d arm_first_hop=%d tail=%d target=0x%08X entry=%d mode=%s cleanup=%s follow=%s dist=%s owned_blocks=%s",
                    source_state,
                    site.source_block,
                    arm.first_hop,
                    arm.tail,
                    arm.target_state,
                    arm.target_entry,
                    emission_mode,
                    (
                        "none"
                        if state_write_cleanup is None
                        else type(state_write_cleanup).__name__
                    ),
                    "None" if site.follow_block is None else str(site.follow_block),
                    "None" if arm.return_distance is None else str(arm.return_distance),
                    sorted(site_blocks),
                )
            owned_blocks.update(site_blocks)
            owned_edges.update(site_edges)

        if not modifications:
            return None

        residual_dispatcher_preds = collect_residual_dispatcher_predecessors(
            flow_graph,
            int(snapshot.bst_dispatcher_serial),
            bst_node_blocks=set(int(block) for block in setup.bst_node_blocks),
            reachable_from_serial=getattr(getattr(snapshot, "reachability", None), "entry_serial", None),
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
                handlers_resolved=len(accepted_edges),
                transitions_resolved=len(accepted_edges),
                blocks_freed=0,
                conflict_density=0.2,
            ),
            risk_score=0.25,
            metadata={
                "accepted_edges": tuple(accepted_edges),
                "safeguard_min_required": max(1, len(modifications)),
                "allow_post_apply_bst_cleanup": False,
                "post_apply_bst_cleanup_group": "exact_nodes",
                "post_apply_bst_cleanup_reason": "exact_conditional_fork_lowering",
                "residual_dispatcher_preds": tuple(int(serial) for serial in residual_dispatcher_preds),
                "site_count": len(sites),
                "clean_fork_blocks": inventory.clean_fork_blocks,
                "boundary_preservation_blocks": (
                    inventory.boundary_preservation_blocks
                ),
            },
        )
