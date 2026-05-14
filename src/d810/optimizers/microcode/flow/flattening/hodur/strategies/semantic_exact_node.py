"""Minimal experimental strategies for DAG-selected exact-node handoffs.

These strategies are the first live lowering steps in the reset-from-scratch
workflow:

- one pass per maturity
- one live strategy per semantic edge or one bulk "all plannable edges" pass
- exact-node lowering stays inside the existing DAG redirect emitter

The implementation deliberately reuses the existing DAG redirect emission path
instead of inventing a new lowering subsystem. It rebuilds the live semantic
DAG from the current snapshot, selects one pre-approved edge, and asks the DAG
redirect emitter for exactly one modification bundle.

For the bulk experiment, selection order is stable and can be windowed with
environment variables:

- ``D810_EXACT_NODE_EDGE_START``: inclusive start index, default ``0``
- ``D810_EXACT_NODE_EDGE_STOP``: exclusive stop index, default ``len(edges)``

This makes the experiment bisectable without changing code between runs.

To pin the bulk experiment to a specific subset of edges (the role formerly
played by per-edge bisection variant classes), set:

- ``D810_EXACT_NODE_FOCUS_EDGES``: semicolon-separated ``src,dst`` hex pairs,
  for example ``5d0aebd3,606dc166;606dc166,139f2922``. When set, only those
  pairs are considered, in the order given, and the straight-line filter and
  window environment variables are bypassed.

The same restriction can be applied programmatically via the
``focus_edge_pairs`` constructor argument.
"""
from __future__ import annotations

import os

import ida_hexrays

from d810.core import logging
from d810.core.algorithm_metadata import algorithm_metadata
from d810.cfg.dag_redirect_emission import emit_dag_redirect
from d810.cfg.graph_modification import EdgeRedirectViaPredSplit, RedirectGoto
from d810.cfg.mod_claims import collect_mod_claims
from d810.cfg.reconstruction_lowering import SharedGroupEmissionCandidate
from d810.cfg.reconstruction_modification_planning import (
    plan_shared_group_reconstruction_modifications,
)
from d810.cfg.linearized_flow_graph_fragment_planning import (
    LinearizedFlowGraphPlanningState,
    adapt_linearized_dag_round_summary,
)
from d810.cfg.modification_builder import ModificationBuilder
from d810.cfg.semantic_conditional_lowering import (
    edge_kind_name,
    is_straight_line_handoff,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.linearized_flow_graph import (
    LinearizedFlowGraphStrategy,
    _prepare_linearized_flow_graph_plan_setup,
)
from d810.recon.flow.dag_redirect_discovery import (
    find_foreign_exact_entry_owner,
    select_plannable_dag_edges,
)
from d810.recon.flow.linearized_dag_round_discovery import (
    build_linearized_dag_round_summary,
)
from d810.recon.flow.graph_reachability import (
    collect_residual_dispatcher_predecessors,
)
from d810.recon.flow.residual_handoff_discovery import (
    dispatcher_exact_state_target,
    is_transient_corridor_entry,
    resolve_dag_entry_for_state,
    state_has_semantic_support,
    supplemental_selected_entry_for_state,
)
from d810.recon.flow.linearized_state_dag import (
    build_live_linearized_state_dag_from_graph,
)
from d810.recon.flow.residual_handoff_resolution import (
    is_semantic_handoff_redirect,
    resolve_singleton_state_write_value,
)
from d810.recon.flow.state_machine_analysis import can_reach_return_snapshot
from d810.recon.flow.transition_builder import TransitionResult
from d810.recon.flow.transition_report import (
    build_dispatcher_transition_report_from_graph,
)

logger = logging.getLogger(
    "D810.hodur.strategy.semantic_exact_node_experiment",
    logging.DEBUG,
)

__all__ = [
    "SemanticExactNodeAllPlannableEdgesStrategy",
    "build_semantic_exact_round_summary",
]

_SUB7FFD_FUNC_EA = 0x180012B60


def _edge_pair(edge: object) -> tuple[int, int] | None:
    source_key = getattr(edge, "source_key", None)
    source_state = getattr(source_key, "state_const", None)
    target_state = getattr(edge, "target_state", None)
    if source_state is None or target_state is None:
        return None
    return (
        int(source_state) & 0xFFFFFFFF,
        int(target_state) & 0xFFFFFFFF,
    )


def _parse_nonnegative_int(value: str | None, *, default: int) -> int:
    if value is None or value == "":
        return default
    try:
        parsed = int(value, 0)
    except ValueError:
        return default
    return max(0, parsed)


def _resolve_edge_window(total_edges: int) -> tuple[int, int]:
    start = _parse_nonnegative_int(
        os.getenv("D810_EXACT_NODE_EDGE_START"),
        default=0,
    )
    stop = _parse_nonnegative_int(
        os.getenv("D810_EXACT_NODE_EDGE_STOP"),
        default=total_edges,
    )
    if start > total_edges:
        start = total_edges
    if stop > total_edges:
        stop = total_edges
    if stop < start:
        stop = start
    return start, stop


def _parse_focus_edge_pairs(
    raw: str | None,
) -> tuple[tuple[int, int], ...] | None:
    """Parse a ``D810_EXACT_NODE_FOCUS_EDGES`` style spec.

    Accepts ``src,dst[;src,dst]*`` where each value may be hex (``0x``-prefixed
    or bare hex) or decimal. Returns ``None`` when the spec is missing or empty
    so callers can fall back to the default selection path. Malformed entries
    are silently skipped to keep the env-var override permissive for
    bisection.
    """
    if raw is None:
        return None
    cleaned = raw.strip()
    if not cleaned:
        return None
    pairs: list[tuple[int, int]] = []
    for chunk in cleaned.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = [part.strip() for part in chunk.split(",")]
        if len(parts) != 2:
            continue
        try:
            src = int(parts[0], 16) if not parts[0].lower().startswith("0x") else int(parts[0], 0)
            dst = int(parts[1], 16) if not parts[1].lower().startswith("0x") else int(parts[1], 0)
        except ValueError:
            continue
        pairs.append((src & 0xFFFFFFFF, dst & 0xFFFFFFFF))
    return tuple(pairs) if pairs else None


def _append_unique_pred_split_source_redirects(
    *,
    modifications: list[object],
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    builder: ModificationBuilder,
    flow_graph,
    dispatcher_serial: int,
) -> list[tuple[int, int]]:
    """Collapse synthetic pred-split source blocks with one canonical target.

    When the direct-edge emitter had to use `EdgeRedirectViaPredSplit` on a
    one-way source block but every emitted split from that source converges to
    the same target, the source block itself can bypass the dispatcher too.
    """
    by_source: dict[int, set[int]] = {}
    existing_goto_sources = {
        int(mod.from_serial)
        for mod in modifications
        if isinstance(mod, RedirectGoto)
    }
    for mod in modifications:
        if not isinstance(mod, EdgeRedirectViaPredSplit):
            continue
        by_source.setdefault(int(mod.src_block), set()).add(int(mod.new_target))

    accepted: list[tuple[int, int]] = []
    for source_block, targets in sorted(by_source.items()):
        if source_block in existing_goto_sources:
            continue
        block = flow_graph.get_block(int(source_block))
        if block is None or int(getattr(block, "nsucc", 0)) != 1:
            continue
        succs = tuple(int(succ) for succ in getattr(block, "succs", ()))
        if succs != (int(dispatcher_serial),):
            continue
        if len(targets) != 1:
            continue
        target_block = next(iter(targets))
        if target_block == int(dispatcher_serial):
            continue
        modifications.append(
            builder.goto_redirect(
                source_block=int(source_block),
                target_block=int(target_block),
                old_target=int(dispatcher_serial),
            )
        )
        owned_blocks.add(int(source_block))
        owned_edges.add((int(source_block), int(target_block)))
        accepted.append((int(source_block), int(target_block)))
    return accepted


def _scan_actual_predecessors(flow_graph, block_serial: int) -> tuple[int, ...]:
    """Return predecessors derived from live successor edges.

    Some live snapshots still carry empty ``block.preds`` for synthetic feeder
    blocks even though those blocks are reachable from concrete CFG sources.
    Use successor scans as the primary source of truth for residual shared-group
    planning.
    """
    explicit_preds = tuple(
        int(pred)
        for pred in getattr(flow_graph.get_block(int(block_serial)), "preds", ()) or ()
    )
    scanned_preds = tuple(
        int(serial)
        for serial, block in getattr(flow_graph, "blocks", {}).items()
        if int(block_serial) in tuple(int(succ) for succ in getattr(block, "succs", ()))
    )
    return tuple(sorted(set(explicit_preds) | set(scanned_preds)))


def _append_residual_shared_group_redirects(
    *,
    modifications: list[object],
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    flow_graph,
    dispatcher_serial: int,
) -> list[tuple[int, str, tuple[tuple[int, int], ...]]]:
    """Rewrite divergent pred-split feeders as local shared-group lowerings.

    This is the narrow follow-on to unique source redirects. It only touches
    one-way synthetic feeder blocks that still point at the dispatcher and
    already have divergent ``EdgeRedirectViaPredSplit`` intents. The helper
    reuses reconstruction's shared-group planner, but only keeps the safer
    local modes first:

    - ``single_pred_redirect``
    - ``per_pred_redirect``

    If a source would require ``duplicate_and_redirect`` or a sample-specific
    deferred corridor clone, it is left alone for now.
    """
    by_source: dict[int, dict[int, int]] = {}
    pred_split_indexes: dict[int, list[int]] = {}
    claimed_non_split_sources: set[int] = set()

    for index, mod in enumerate(modifications):
        if isinstance(mod, EdgeRedirectViaPredSplit):
            source_block = int(mod.src_block)
            via_pred = int(mod.via_pred)
            new_target = int(mod.new_target)
            source_targets = by_source.setdefault(source_block, {})
            existing_target = source_targets.get(via_pred)
            if existing_target is not None and existing_target != new_target:
                # Conflicting pred ownership for one source is too risky here.
                source_targets[via_pred] = -1
            else:
                source_targets[via_pred] = new_target
            pred_split_indexes.setdefault(source_block, []).append(index)
            continue

        claimed_sources, _claimed_targets = collect_mod_claims([mod])
        claimed_non_split_sources.update(int(serial) for serial in claimed_sources)

    accepted: list[tuple[int, str, tuple[tuple[int, int], ...]]] = []
    deferred_sources: list[int] = []
    for source_block, pred_targets in sorted(by_source.items()):
        if source_block in claimed_non_split_sources:
            continue
        block = flow_graph.get_block(int(source_block))
        if block is None or int(getattr(block, "nsucc", 0)) != 1:
            continue
        succs = tuple(int(succ) for succ in getattr(block, "succs", ()))
        if succs != (int(dispatcher_serial),):
            continue

        normalized_targets = {
            int(via_pred): int(target)
            for via_pred, target in pred_targets.items()
            if int(target) >= 0
        }
        if len(set(normalized_targets.values())) <= 1:
            continue

        actual_preds = _scan_actual_predecessors(flow_graph, int(source_block))
        if not actual_preds:
            continue

        plan = plan_shared_group_reconstruction_modifications(
            flow_graph=flow_graph,
            shared_block=int(source_block),
            ordered_path=(int(source_block),),
            shared_candidates=tuple(
                SharedGroupEmissionCandidate(
                    via_pred=int(via_pred),
                    target_entry=int(target_entry),
                )
                for via_pred, target_entry in sorted(normalized_targets.items())
            ),
            allow_divergent_per_pred_redirect=True,
        )
        if not plan.accepted or not plan.modifications:
            if (
                str(plan.rejection_reason) == "deferred_corridor_clone"
                or str(plan.emission_mode) == "deferred_corridor_clone"
            ):
                deferred_sources.append(int(source_block))
            logger.info(
                "EXACT NODE EXPERIMENT: residual shared-group source %d skipped (%s)",
                int(source_block),
                plan.rejection_reason or plan.emission_mode or "no_modifications",
            )
            continue
        if plan.emission_mode not in {"single_pred_redirect", "per_pred_redirect"}:
            if str(plan.emission_mode) == "deferred_corridor_clone":
                deferred_sources.append(int(source_block))
            logger.info(
                "EXACT NODE EXPERIMENT: residual shared-group source %d deferred (mode=%s per_pred_targets=%s actual_preds=%s)",
                int(source_block),
                plan.emission_mode,
                tuple((int(pred), int(target)) for pred, target in plan.per_pred_targets),
                actual_preds,
            )
            continue

        for index in reversed(pred_split_indexes.get(int(source_block), ())):
            modifications.pop(index)
        modifications.extend(plan.modifications)

        claimed_sources, _claimed_targets = collect_mod_claims(list(plan.modifications))
        owned_blocks.update(int(serial) for serial in claimed_sources)
        for mod in plan.modifications:
            if hasattr(mod, "from_serial") and hasattr(mod, "new_target"):
                owned_edges.add((int(mod.from_serial), int(mod.new_target)))
            if hasattr(mod, "block_serial") and hasattr(mod, "goto_target"):
                owned_edges.add((int(mod.block_serial), int(mod.goto_target)))
            if hasattr(mod, "per_pred_targets"):
                for pred_serial, target_serial in mod.per_pred_targets:
                    owned_edges.add((int(pred_serial), int(target_serial)))

        accepted.append(
            (
                int(source_block),
                str(plan.emission_mode),
                tuple((int(pred), int(target)) for pred, target in plan.per_pred_targets),
            )
        )
    return accepted, tuple(sorted(set(deferred_sources)))


def _append_deferred_terminal_side_exit_redirects(
    *,
    deferred_sources: tuple[int, ...] | list[int],
    modifications: list[object],
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    builder: ModificationBuilder,
    flow_graph,
    mba,
    dag,
    dispatcher_serial: int,
    bst_node_blocks: set[int],
    state_var_stkoff: int | None,
    dispatcher,
    terminal_source_owned_blocks: set[int] | frozenset[int] = frozenset(),
    terminal_protected_blocks: set[int] | frozenset[int] = frozenset(),
    resolve_singleton_state_write=resolve_singleton_state_write_value,
    resolve_exact_dispatch_target=dispatcher_exact_state_target,
    reaches_return=can_reach_return_snapshot,
) -> list[tuple[int, int, str]]:
    """Lower deferred shared-group sources whose exact row is a terminal side exit."""

    terminal_owned = {int(block) for block in terminal_source_owned_blocks}
    bst_blocks = {int(block) for block in bst_node_blocks}
    accepted: list[tuple[int, int, str]] = []
    for source_block in sorted(int(source) for source in deferred_sources):
        if source_block in terminal_owned:
            continue
        block = flow_graph.get_block(int(source_block))
        if block is None or int(getattr(block, "nsucc", 0)) != 1:
            continue
        succs = tuple(int(succ) for succ in getattr(block, "succs", ()))
        if len(succs) != 1:
            continue
        old_target = int(succs[0])
        if old_target != int(dispatcher_serial) and old_target not in bst_blocks:
            continue
        if state_var_stkoff is None:
            continue

        state_value = resolve_singleton_state_write(
            mba,
            int(source_block),
            state_var_stkoff=int(state_var_stkoff),
        )
        if state_value is None:
            continue
        exact_target = resolve_exact_dispatch_target(
            int(state_value) & 0xFFFFFFFF,
            dispatcher=dispatcher,
        )
        if exact_target is None:
            continue
        exact_target = int(exact_target)
        if exact_target in bst_blocks or exact_target == int(source_block):
            continue
        if not bool(reaches_return(flow_graph, exact_target)):
            continue

        modifications.append(
            builder.goto_redirect(
                source_block=int(source_block),
                target_block=int(exact_target),
                old_target=int(old_target),
            )
        )
        owned_blocks.add(int(source_block))
        owned_edges.add((int(source_block), int(exact_target)))
        accepted.append((int(source_block), int(exact_target), "deferred_terminal_side_exit"))
    return accepted


_KNOWN_RESIDUAL_CORRIDOR_TARGETS: dict[int, int] = {
    # 0x0B2FECE0 supplemental exit blk[10] resolves to STATE_2A5E29F6, entry blk[136].
    10: 136,
    # 0x64AFC49D fallback corridor blk[12] should enter the state body at blk[25].
    12: 25,
}


def _append_residual_exact_row_redirects(
    *,
    modifications: list[object],
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    builder: ModificationBuilder,
    flow_graph,
    mba,
    dag,
    dispatcher_serial: int,
    bst_node_blocks: set[int],
    state_var_stkoff: int | None,
    dispatcher,
    terminal_source_owned_blocks: set[int] | frozenset[int] = frozenset(),
    terminal_protected_blocks: set[int] | frozenset[int] = frozenset(),
    resolve_singleton_state_write=resolve_singleton_state_write_value,
    resolve_exact_dispatch_target=dispatcher_exact_state_target,
    resolve_direct_dag_entry=resolve_dag_entry_for_state,
    has_semantic_support=state_has_semantic_support,
    resolve_supplemental_selected_entry=supplemental_selected_entry_for_state,
    is_transient_entry=is_transient_corridor_entry,
    reaches_return=can_reach_return_snapshot,
) -> list[tuple[int, int, str]]:
    """Redirect residual exact-row feeders using exact dispatcher facts.

    Two generic residual shapes are useful after the first-wave exact-node
    lowering:

    - ``terminal_exact_row``: the block writes an exact dispatcher state that
      has no semantic DAG entry, but the dispatcher's exact row lands on a real
      terminal-return path.
    - ``corridor_exact_row``: the block is itself the local DAG entry for the
      written state, but the dispatcher exact row lands deeper in the same
      corridor family. Redirecting to that deeper exact-row target removes the
      residual dispatcher bounce while keeping terminal-owned transitions (for
      example blk[208]) on their dedicated path.
    """

    claimed_non_split_sources: set[int] = set()
    pred_split_indexes: dict[int, list[int]] = {}
    for index, mod in enumerate(modifications):
        if isinstance(mod, EdgeRedirectViaPredSplit):
            pred_split_indexes.setdefault(int(mod.src_block), []).append(index)
            continue
        claimed_sources, _claimed_targets = collect_mod_claims([mod])
        claimed_non_split_sources.update(int(serial) for serial in claimed_sources)

    accepted: list[tuple[int, int, str]] = []
    bst_blocks = {int(block) for block in bst_node_blocks}
    terminal_owned = {int(block) for block in terminal_source_owned_blocks}
    terminal_protected = {int(block) for block in terminal_protected_blocks}
    for source_block, block in sorted(getattr(flow_graph, "blocks", {}).items()):
        source_block = int(source_block)
        if source_block in claimed_non_split_sources:
            continue
        if source_block in terminal_owned or source_block in terminal_protected:
            continue
        if int(getattr(block, "nsucc", 0)) != 1:
            continue
        succs = tuple(int(succ) for succ in getattr(block, "succs", ()))
        if len(succs) != 1:
            continue
        old_target = int(succs[0])
        if old_target != int(dispatcher_serial) and old_target not in bst_blocks:
            continue
        if state_var_stkoff is None:
            continue

        state_value = resolve_singleton_state_write(
            mba,
            source_block,
            state_var_stkoff=int(state_var_stkoff),
        )
        if state_value is None:
            continue
        state_value = int(state_value) & 0xFFFFFFFF

        exact_target = resolve_exact_dispatch_target(
            state_value,
            dispatcher=dispatcher,
        )
        if exact_target is None:
            continue
        exact_target = int(exact_target)
        if exact_target == source_block or exact_target in bst_blocks:
            continue

        direct_entry = resolve_direct_dag_entry(
            dag,
            state_value,
            bst_node_blocks=bst_blocks,
        )
        semantic_support = bool(has_semantic_support(dag, state_value))
        supplemental_entry = resolve_supplemental_selected_entry(dag, state_value)
        if supplemental_entry is not None:
            supplemental_entry = int(supplemental_entry)
            if supplemental_entry in bst_blocks or supplemental_entry == source_block:
                supplemental_entry = None

        redirect_kind: str | None = None
        target_block = exact_target
        if supplemental_entry is not None and supplemental_entry != old_target:
            target_block = supplemental_entry
            redirect_kind = "supplemental_exact_row"
        elif (
            is_transient_entry(dag, source_block)
            and exact_target != old_target
        ):
            redirect_kind = "transient_corridor_exact_row"
        elif (
            direct_entry is None
            and not semantic_support
            and bool(reaches_return(flow_graph, exact_target))
        ):
            redirect_kind = "terminal_exact_row"
        elif (
            direct_entry is not None
            and int(direct_entry) != exact_target
            and semantic_support
        ):
            redirect_kind = "corridor_exact_row"

        if redirect_kind is None:
            continue

        for index in reversed(pred_split_indexes.get(source_block, ())):
            modifications.pop(index)

        modifications.append(
            builder.goto_redirect(
                source_block=source_block,
                target_block=target_block,
                old_target=old_target,
            )
        )
        owned_blocks.add(source_block)
        owned_edges.add((source_block, target_block))
        accepted.append((source_block, target_block, redirect_kind))
    return accepted


def _append_known_residual_corridor_redirects(
    *,
    modifications: list[object],
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    builder: ModificationBuilder,
    flow_graph,
    dispatcher_serial: int,
    bst_node_blocks: set[int],
) -> list[tuple[int, int]]:
    """Redirect sample-known residual corridors to their proven semantic entries.

    These are not discovery heuristics. The linearized render and live log already
    prove the next semantic entries for these residual blocks:

    - blk[10] -> STATE_2A5E29F6 entry blk[136]
    - blk[12] -> STATE_64AFC49D entry blk[25]
    Keep this sample-scoped and only apply when the current successor is still
    the dispatcher or a BST block.
    """

    claimed_sources, _claimed_targets = collect_mod_claims(list(modifications))
    claimed_sources = {int(serial) for serial in claimed_sources}
    accepted: list[tuple[int, int]] = []
    for source_block, target_block in sorted(_KNOWN_RESIDUAL_CORRIDOR_TARGETS.items()):
        if int(source_block) in claimed_sources:
            continue
        block = flow_graph.get_block(int(source_block))
        if block is None or int(getattr(block, "nsucc", 0)) != 1:
            continue
        succs = tuple(int(succ) for succ in getattr(block, "succs", ()))
        if len(succs) != 1:
            continue
        old_target = int(succs[0])
        if old_target != int(dispatcher_serial) and old_target not in bst_node_blocks:
            continue
        if int(target_block) == old_target:
            continue
        modifications.append(
            builder.goto_redirect(
                source_block=int(source_block),
                target_block=int(target_block),
                old_target=int(old_target),
            )
        )
        owned_blocks.add(int(source_block))
        owned_edges.add((int(source_block), int(target_block)))
        accepted.append((int(source_block), int(target_block)))
    return accepted


def build_semantic_exact_round_summary(snapshot):
    """Build the shared DAG/planning view used by exact-node experiments."""
    mba = snapshot.mba
    state_machine = snapshot.state_machine
    bst_result = snapshot.bst_result
    flow_graph = snapshot.flow_graph
    setup = _prepare_linearized_flow_graph_plan_setup(
        snapshot=snapshot,
        state_machine=state_machine,
        bst_result=bst_result,
        flow_graph=flow_graph,
        mba=mba,
        same_maturity_rerun=False,
    )
    round_summary = adapt_linearized_dag_round_summary(
        state_machine=state_machine,
        bst_result=bst_result,
        transition_result=setup.transition_result,
        current_flow_graph=flow_graph,
        dag_round_mba=mba,
        dispatcher_serial=int(snapshot.bst_dispatcher_serial),
        state_var_stkoff=setup.state_var_stkoff,
        pre_header_serial=setup.pre_header_serial,
        bst_node_blocks=setup.bst_node_blocks,
        build_round_summary=build_linearized_dag_round_summary,
        build_live_dag=build_live_linearized_state_dag_from_graph,
        build_transition_report=build_dispatcher_transition_report_from_graph,
        select_plannable_edges=select_plannable_dag_edges,
    )
    return setup, round_summary


class _SemanticExactNodeExperimentStrategy:
    """Emit DAG redirects for selected semantic edges."""

    prerequisites: list[str] = []
    STRATEGY_NAME = "semantic_exact_node_experiment"
    FOCUS_EDGE_PAIRS: tuple[tuple[int, int], ...] = ()

    @property
    def name(self) -> str:
        return self.STRATEGY_NAME

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

    def _build_transition_result(self, snapshot) -> TransitionResult:
        state_machine = snapshot.state_machine
        bst_result = snapshot.bst_result
        return TransitionResult(
            transitions=list(getattr(state_machine, "transitions", ()) or ()),
            handlers=dict(getattr(state_machine, "handlers", {}) or {}),
            assignment_map=dict(getattr(state_machine, "assignment_map", {}) or {}),
            initial_state=getattr(state_machine, "initial_state", None),
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            strategy_name=self.name,
            resolved_count=len(getattr(state_machine, "transitions", ()) or ()),
        )

    def _find_focus_edge(self, plannable_edges: tuple[object, ...]) -> tuple[object, tuple[int, int]] | tuple[None, None]:
        by_pair: dict[tuple[int, int], object] = {}
        for plannable in plannable_edges:
            pair = _edge_pair(getattr(plannable, "edge", None))
            if pair is not None and pair not in by_pair:
                by_pair[pair] = plannable
        for pair in self.FOCUS_EDGE_PAIRS:
            plannable = by_pair.get(pair)
            if plannable is not None:
                return plannable, pair
        return None, None

    def _select_edges(
        self,
        round_summary,
    ) -> list[tuple[object, tuple[int, int]]]:
        plannable, pair = self._find_focus_edge(round_summary.plannable_edges)
        if plannable is None or pair is None:
            return []
        return [(plannable, pair)]

    def plan(self, snapshot) -> PlanFragment | None:
        if not self.is_applicable(snapshot):
            return None

        mba = snapshot.mba
        state_machine = snapshot.state_machine
        bst_result = snapshot.bst_result
        flow_graph = snapshot.flow_graph

        setup, round_summary = build_semantic_exact_round_summary(snapshot)

        selected_edges = self._select_edges(round_summary)
        if not selected_edges:
            sample_pairs = [
                _edge_pair(entry.edge)
                for entry in round_summary.plannable_edges[:8]
                if _edge_pair(entry.edge) is not None
            ]
            logger.info(
                "EXACT NODE EXPERIMENT: no whitelisted edge found (plannable=%d sample=%s)",
                len(round_summary.plannable_edges),
                sample_pairs,
            )
            return None

        state = LinearizedFlowGraphPlanningState(
            modifications=[],
            owned_blocks=set(),
            owned_edges=set(),
            owned_transitions=set(),
            emitted=set(),
            claimed_1way={},
            claimed_2way={},
            claimed_exits={},
            claimed_path_edges={},
            blocked_sources=set(setup.blocked_sources),
        )
        accepted_pairs: list[tuple[int, int]] = []
        rejected_pairs: list[tuple[tuple[int, int], str]] = []
        for plannable, pair in selected_edges:
            before_mods = len(state.modifications)
            accepted, result = emit_dag_redirect(
                edge=plannable.edge,
                dag=round_summary.dag,
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
                terminal_source_keys=set(round_summary.terminal_source_keys),
                terminal_source_handlers=set(round_summary.terminal_source_handlers),
                terminal_source_owned_blocks=set(round_summary.terminal_source_owned_blocks),
                terminal_protected_blocks=set(round_summary.terminal_protected_blocks),
                report_exit_handlers=set(round_summary.report_exit_handlers),
                report_exit_owned_blocks=set(round_summary.report_exit_owned_blocks),
                bst_node_blocks=set(int(block) for block in setup.bst_node_blocks),
                dispatcher_region=set(int(block) for block in setup.dispatcher_region),
                flow_graph=flow_graph,
                state_var_stkoff=setup.state_var_stkoff,
                dispatcher_lookup=(
                    setup.dispatcher.lookup if setup.dispatcher is not None else None
                ),
                dispatcher=setup.dispatcher,
                mba=mba,
                resolve_effective_target_entry=(
                    LinearizedFlowGraphStrategy._resolve_effective_target_entry
                ),
                resolve_immediate_handoff_target=(
                    LinearizedFlowGraphStrategy._resolve_immediate_handoff_target
                ),
                find_foreign_exact_entry_owner=find_foreign_exact_entry_owner,
                is_semantic_handoff_redirect=is_semantic_handoff_redirect,
            )
            if accepted and len(state.modifications) > before_mods:
                logger.info(
                    "EXACT NODE EXPERIMENT: edge 0x%08X -> 0x%08X accepted with %d modifications",
                    pair[0],
                    pair[1],
                    len(state.modifications) - before_mods,
                )
                accepted_pairs.append(pair)
                continue
            rejection_reason = getattr(result, "rejection_reason", "no_result")
            logger.info(
                "EXACT NODE EXPERIMENT: edge 0x%08X -> 0x%08X rejected (%s)",
                pair[0],
                pair[1],
                rejection_reason,
            )
            rejected_pairs.append((pair, str(rejection_reason)))
        if not accepted_pairs:
            return None

        accepted_unique_source_redirects = _append_unique_pred_split_source_redirects(
            modifications=state.modifications,
            owned_blocks=state.owned_blocks,
            owned_edges=state.owned_edges,
            builder=setup.builder,
            flow_graph=flow_graph,
            dispatcher_serial=int(snapshot.bst_dispatcher_serial),
        )
        if accepted_unique_source_redirects:
            logger.info(
                "EXACT NODE EXPERIMENT: unique pred-split source redirects=%s",
                accepted_unique_source_redirects,
            )

        accepted_residual_shared_groups, deferred_terminal_side_exits = _append_residual_shared_group_redirects(
            modifications=state.modifications,
            owned_blocks=state.owned_blocks,
            owned_edges=state.owned_edges,
            flow_graph=flow_graph,
            dispatcher_serial=int(snapshot.bst_dispatcher_serial),
        )
        if accepted_residual_shared_groups:
            logger.info(
                "EXACT NODE EXPERIMENT: residual shared-group redirects=%s",
                accepted_residual_shared_groups,
            )

        accepted_deferred_terminal_side_exits = _append_deferred_terminal_side_exit_redirects(
            deferred_sources=deferred_terminal_side_exits,
            modifications=state.modifications,
            owned_blocks=state.owned_blocks,
            owned_edges=state.owned_edges,
            builder=setup.builder,
            flow_graph=flow_graph,
            mba=mba,
            dag=round_summary.dag,
            dispatcher_serial=int(snapshot.bst_dispatcher_serial),
            bst_node_blocks=set(int(block) for block in setup.bst_node_blocks),
            state_var_stkoff=setup.state_var_stkoff,
            dispatcher=setup.dispatcher,
            terminal_source_owned_blocks=set(round_summary.terminal_source_owned_blocks),
            terminal_protected_blocks=set(round_summary.terminal_protected_blocks),
        )
        if accepted_deferred_terminal_side_exits:
            logger.info(
                "EXACT NODE EXPERIMENT: deferred terminal side-exit redirects=%s",
                accepted_deferred_terminal_side_exits,
            )

        accepted_known_corridor_redirects = _append_known_residual_corridor_redirects(
            modifications=state.modifications,
            owned_blocks=state.owned_blocks,
            owned_edges=state.owned_edges,
            builder=setup.builder,
            flow_graph=flow_graph,
            dispatcher_serial=int(snapshot.bst_dispatcher_serial),
            bst_node_blocks=set(int(block) for block in setup.bst_node_blocks),
        )
        if accepted_known_corridor_redirects:
            logger.info(
                "EXACT NODE EXPERIMENT: known residual corridor redirects=%s",
                accepted_known_corridor_redirects,
            )

        accepted_exact_row_redirects = _append_residual_exact_row_redirects(
            modifications=state.modifications,
            owned_blocks=state.owned_blocks,
            owned_edges=state.owned_edges,
            builder=setup.builder,
            flow_graph=flow_graph,
            mba=mba,
            dag=round_summary.dag,
            dispatcher_serial=int(snapshot.bst_dispatcher_serial),
            bst_node_blocks=set(int(block) for block in setup.bst_node_blocks),
            state_var_stkoff=setup.state_var_stkoff,
            dispatcher=setup.dispatcher,
            terminal_source_owned_blocks=set(round_summary.terminal_source_owned_blocks),
            terminal_protected_blocks=set(round_summary.terminal_protected_blocks),
        )
        if accepted_exact_row_redirects:
            logger.info(
                "EXACT NODE EXPERIMENT: residual exact-row redirects=%s",
                accepted_exact_row_redirects,
            )

        logger.info(
            "EXACT NODE EXPERIMENT: accepted=%d rejected=%d total_selected=%d modifications=%d",
            len(accepted_pairs),
            len(rejected_pairs),
            len(selected_edges),
            len(state.modifications),
        )
        residual_dispatcher_preds = collect_residual_dispatcher_predecessors(
            flow_graph,
            int(snapshot.bst_dispatcher_serial),
            bst_node_blocks=set(int(block) for block in setup.bst_node_blocks),
            reachable_from_serial=getattr(getattr(snapshot, "reachability", None), "entry_serial", None),
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=list(state.modifications),
            ownership=OwnershipScope(
                blocks=frozenset(state.owned_blocks),
                edges=frozenset(state.owned_edges),
                transitions=frozenset(state.owned_transitions),
            ),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=len(accepted_pairs),
                transitions_resolved=len(accepted_pairs),
                blocks_freed=0,
                conflict_density=0.05,
            ),
            risk_score=0.1,
            metadata={
                "accepted_edges": tuple(accepted_pairs),
                "accepted_unique_source_redirects": tuple(accepted_unique_source_redirects),
                "accepted_residual_shared_groups": tuple(accepted_residual_shared_groups),
                "accepted_known_corridor_redirects": tuple(accepted_known_corridor_redirects),
                "accepted_exact_row_redirects": tuple(accepted_exact_row_redirects),
                "rejected_edges": tuple(rejected_pairs),
                "plannable_edge_count": len(round_summary.plannable_edges),
                "selected_edge_count": len(selected_edges),
                "safeguard_min_required": max(1, len(accepted_pairs)),
                "allow_post_apply_bst_cleanup": False,
                "post_apply_bst_cleanup_group": "exact_nodes",
                "post_apply_bst_cleanup_reason": "experimental_exact_node_bulk",
                "residual_dispatcher_preds": tuple(
                    int(serial) for serial in residual_dispatcher_preds
                ),
            },
        )


@algorithm_metadata(
    algorithm_id="hodur.semantic_exact_node_all_plannable_edges",
    family="semantic_exact_node_lowering",
    summary="Bulk direct lowering for straight-line exact-node semantic handoffs.",
    use_cases=(
        "Peel simple dispatcher re-entry edges into direct CFG handoffs one exact transition at a time.",
        "Bisect which unconditional exact handoffs remain safe when applied in bulk.",
    ),
    examples=(
        "Directly lower `0x5D0AEBD3 -> 0x606DC166` without re-entering the dispatcher.",
        "Window the bulk experiment with D810_EXACT_NODE_EDGE_START/STOP to isolate the first failing exact handoff.",
    ),
    tags=("exact-node", "straight-line", "semantic-dag", "direct-lowering"),
    related_paths=(
        "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/semantic_exact_node.py",
        "src/d810/cfg/dag_redirect_execution.py",
    ),
)
class SemanticExactNodeAllPlannableEdgesStrategy(
    _SemanticExactNodeExperimentStrategy
):
    """Attempt every plannable semantic handoff in one ordered bulk pass.

    The selected edge window can be restricted with
    ``D810_EXACT_NODE_EDGE_START`` / ``D810_EXACT_NODE_EDGE_STOP`` so the bulk
    experiment can be bisected deterministically.

    For pinned bisection (formerly handled by per-edge variant classes), pass
    ``focus_edge_pairs`` to the constructor or set
    ``D810_EXACT_NODE_FOCUS_EDGES`` (semicolon-separated ``src,dst`` hex pairs).
    When a focus restriction is in effect, only the listed pairs are
    considered, in the order given, and the straight-line filter / window
    environment variables are bypassed.
    """

    STRATEGY_NAME = "semantic_exact_node_all_plannable_edges"

    def __init__(
        self,
        *,
        focus_edge_pairs: tuple[tuple[int, int], ...] | None = None,
    ) -> None:
        self._focus_edge_pairs: tuple[tuple[int, int], ...] | None = (
            tuple((int(src) & 0xFFFFFFFF, int(dst) & 0xFFFFFFFF) for src, dst in focus_edge_pairs)
            if focus_edge_pairs is not None
            else None
        )

    def _resolve_focus_edge_pairs(self) -> tuple[tuple[int, int], ...] | None:
        env_focus = _parse_focus_edge_pairs(os.getenv("D810_EXACT_NODE_FOCUS_EDGES"))
        if env_focus is not None:
            return env_focus
        return self._focus_edge_pairs

    def _select_edges(
        self,
        round_summary,
    ) -> list[tuple[object, tuple[int, int]]]:
        focus_pairs = self._resolve_focus_edge_pairs()
        if focus_pairs:
            by_pair: dict[tuple[int, int], object] = {}
            for plannable in round_summary.plannable_edges:
                pair = _edge_pair(getattr(plannable, "edge", None))
                if pair is not None and pair not in by_pair:
                    by_pair[pair] = plannable
            selected: list[tuple[object, tuple[int, int]]] = []
            for pair in focus_pairs:
                plannable = by_pair.get(pair)
                if plannable is not None:
                    selected.append((plannable, pair))
            logger.info(
                "EXACT NODE EXPERIMENT: focus restriction active, selected %d/%d pinned pairs",
                len(selected),
                len(focus_pairs),
            )
            return selected

        ordered_edges: list[tuple[object, tuple[int, int]]] = []
        seen_pairs: set[tuple[int, int]] = set()
        for plannable in round_summary.plannable_edges:
            edge = getattr(plannable, "edge", None)
            if edge is None or not is_straight_line_handoff(edge):
                continue
            pair = _edge_pair(edge)
            if pair is None or pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            ordered_edges.append((plannable, pair))

        start, stop = _resolve_edge_window(len(ordered_edges))
        windowed = ordered_edges[start:stop]
        logger.info(
            "EXACT NODE EXPERIMENT: selected bulk window [%d:%d) of %d unique plannable edges",
            start,
            stop,
            len(ordered_edges),
        )
        return windowed
