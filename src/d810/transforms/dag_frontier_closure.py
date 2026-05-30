"""DAG-authoritative frontier closure for HCC reconstruction.

The reconstructed state DAG is the semantic authority; live/projected CFG SCCs
are only the verifier.  This module detects projected CFG SCCs that merge
distinct DAG SCCs without DAG mutual reachability, then closes the first
violating frontier with a DAG-proven redirect.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
import os

from d810.transforms.edit_simulator import project_post_state
from d810.ir.flowgraph import InsnKind
from d810.transforms.graph_modification import (
    CreateConditionalRedirect,
    DuplicateBlock,
    InsertBlock,
    RedirectBranch,
    RedirectGoto,
)
from d810.transforms.plan import compile_patch_plan
from d810.analyses.control_flow.scc import compute_live_cfg_sccs, nontrivial_sccs
from d810.core import logging

logger = logging.getLogger("D810.cfg.dag_frontier_closure")


RedirectKey = tuple[int, int, int]
_FALSE_ENV_VALUES = {"0", "false", "no", "off"}


@dataclass(frozen=True, slots=True)
class SemanticSccLeak:
    """One projected CFG path that violates DAG condensation direction."""

    cfg_scc_blocks: frozenset[int]
    from_dag_scc: int
    to_dag_scc: int
    path: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class UnresolvedFrontier:
    """A semantic SCC leak with no DAG-proven CFG rewrite."""

    leak: SemanticSccLeak
    source_block: int
    observed_target: int
    branch_arm: int | None
    reason: str
    candidate_targets: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class ResolvedFrontier:
    """A semantic SCC leak closed by a non-DAG-edge structural proof."""

    leak: SemanticSccLeak | None
    source_block: int
    observed_target: int
    branch_arm: int | None
    reason: str
    target_block: int
    payload: dict[str, object]


@dataclass(frozen=True, slots=True)
class FrontierClosureDiagnosticRow:
    """Structured diagnostic row for DB persistence."""

    kind: str
    reason: str | None
    source_block: int | None
    observed_target: int | None
    branch_arm: int | None
    from_dag_scc: int | None
    to_dag_scc: int | None
    candidate_targets: tuple[int, ...] = ()
    path: tuple[int, ...] = ()
    cfg_scc_size: int | None = None
    payload: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class FrontierClosureResult:
    """Result of one DAG-authoritative frontier-closure planning run."""

    modifications: tuple[object, ...]
    emitted_modifications: tuple[object, ...]
    dropped_modifications: tuple[object, ...]
    stale_hazard_override_keys: frozenset[RedirectKey]
    leaks_before: tuple[SemanticSccLeak, ...]
    leaks_after: tuple[SemanticSccLeak, ...]
    resolved_frontiers: tuple[ResolvedFrontier, ...]
    unresolved_frontiers: tuple[UnresolvedFrontier, ...]
    diagnostic_rows: tuple[FrontierClosureDiagnosticRow, ...]

    @property
    def changed(self) -> bool:
        return bool(self.emitted_modifications)


@dataclass(frozen=True, slots=True)
class _DagIndexes:
    block_to_sccs: dict[int, frozenset[int]]
    scc_reachability: dict[int, frozenset[int]]
    choices_by_anchor: dict[tuple[int, int | None], tuple["_FrontierChoice", ...]]
    cyclic_scc_ids: frozenset[int]
    entry_by_state: dict[int, int]


@dataclass(frozen=True, slots=True)
class _BstIntervalFrontierRow:
    snapshot_id: int | None
    row_index: int | None
    lo: int
    hi: int
    target_block: int


@dataclass(frozen=True, slots=True)
class _FrontierChoice:
    source_block: int
    branch_arm: int | None
    target_block: int
    edge_kind: str
    proof: tuple[object, ...]
    is_path_step: bool
    payload: dict[str, object] | None = None


def plan_dag_authoritative_frontier_closure(
    *,
    dag: object,
    flow_graph: object,
    modifications: list[object] | tuple[object, ...],
    dispatcher_serial: int,
    bst_node_blocks: set[int] | frozenset[int] | tuple[int, ...] = (),
    bst_interval_rows: tuple[object, ...] | list[object] | None = None,
    max_iterations: int = 32,
) -> FrontierClosureResult:
    """Close projected CFG semantic-SCC leaks using only DAG-proven edges.

    ``modifications`` is treated as the current HCC batch.  Frontier closure is
    deliberately additive: it may append a missing DAG-proven redirect, but it
    must not delete already-planned HCC materialization/redirect mods.  Those
    existing mods may carry payload or block-shaping needed by Hex-Rays even
    when the projected CFG makes them look like a semantic backpath.

    A separate proof set marks DAG-proven redirects whose removal recreates a
    semantic SCC leak.  That proof set is diagnostic-only by default: stale
    hazards have already proven that a redirect crosses live value flow, so the
    executor must not bypass them unless the experimental override is explicitly
    enabled.
    """
    if not _env_enabled("D810_DAG_FRONTIER_CLOSURE", default=True):
        return FrontierClosureResult(
            modifications=tuple(modifications),
            emitted_modifications=(),
            dropped_modifications=(),
            stale_hazard_override_keys=frozenset(),
            leaks_before=(),
            leaks_after=(),
            resolved_frontiers=(),
            unresolved_frontiers=(),
            diagnostic_rows=(),
        )

    indexes = _build_indexes(dag)
    if not indexes.block_to_sccs or not indexes.choices_by_anchor:
        return FrontierClosureResult(
            modifications=tuple(modifications),
            emitted_modifications=(),
            dropped_modifications=(),
            stale_hazard_override_keys=frozenset(),
            leaks_before=(),
            leaks_after=(),
            resolved_frontiers=(),
            unresolved_frontiers=(),
            diagnostic_rows=(),
        )

    frontier_blocks = {int(dispatcher_serial)}
    frontier_blocks.update(int(block) for block in bst_node_blocks)
    if bst_interval_rows is None:
        interval_rows = _load_latest_bst_interval_rows(flow_graph)
        if interval_rows:
            logger.info(
                "DAG_FRONTIER_CLOSURE: using DB fallback for BST interval "
                "frontier proof rows=%d func_ea=0x%x",
                len(interval_rows),
                int(getattr(flow_graph, "func_ea", 0) or 0),
            )
    else:
        interval_rows = _coerce_bst_interval_rows(bst_interval_rows)

    current_modifications = list(modifications)
    projected = _project(flow_graph, current_modifications)
    leaks_before = _find_semantic_scc_leaks(projected, indexes)
    emitted: list[object] = []
    dropped: list[object] = []
    resolved: list[ResolvedFrontier] = []
    seen_signatures: set[tuple[tuple[int, int, int] | str, ...]] = set()

    for _iteration in range(max(0, int(max_iterations))):
        signature = _modification_signature(current_modifications)
        if signature in seen_signatures:
            logger.info(
                "DAG_FRONTIER_CLOSURE: stopping after repeated modification "
                "signature at iteration %d",
                _iteration,
            )
            break
        seen_signatures.add(signature)
        leaks = _find_semantic_scc_leaks(projected, indexes)
        action = None
        if leaks:
            action = _select_frontier_action(
                projected,
                leaks,
                indexes,
                current_modifications=current_modifications,
                frontier_blocks=frontier_blocks,
                base_flow_graph=flow_graph,
                bst_interval_rows=interval_rows,
            )
        if action is None:
            action = _select_dispatcher_state_residue_action(
                projected,
                indexes,
                current_modifications=current_modifications,
                dispatcher_serial=dispatcher_serial,
                base_flow_graph=flow_graph,
                bst_interval_rows=interval_rows,
            )
        if action is None:
            action = _select_shared_condition_entry_clone_action(
                projected,
                indexes,
                current_modifications=current_modifications,
                dispatcher_serial=dispatcher_serial,
                base_flow_graph=flow_graph,
            )
        if action is None:
            break
        current_modifications, emitted_mod, dropped_mod, resolved_frontier = action
        if emitted_mod is not None:
            emitted.append(emitted_mod)
        if dropped_mod is not None:
            dropped.append(dropped_mod)
        if resolved_frontier is not None:
            resolved.append(resolved_frontier)
        projected = _project(flow_graph, current_modifications)

    leaks_after = _find_semantic_scc_leaks(projected, indexes)
    unresolved_frontiers = _find_unresolved_frontiers(
        projected,
        leaks_after,
        indexes,
        frontier_blocks=frontier_blocks,
    )
    diagnostic_rows = _build_diagnostic_rows(
        leaks_before=leaks_before,
        leaks_after=leaks_after,
        resolved_frontiers=tuple(resolved),
        unresolved_frontiers=unresolved_frontiers,
    )
    override_keys: set[RedirectKey] = set()
    if _env_enabled("D810_DAG_FRONTIER_STALE_OVERRIDES", default=False):
        override_keys = _collect_stale_hazard_override_keys(
            dag=dag,
            flow_graph=flow_graph,
            modifications=current_modifications,
            indexes=indexes,
            frontier_blocks=frontier_blocks,
        )

    if emitted or dropped or override_keys or leaks_before or unresolved_frontiers:
        logger.info(
            "DAG_FRONTIER_CLOSURE: leaks_before=%d leaks_after=%d "
            "emitted=%s dropped=%s stale_overrides=%s unresolved=%d",
            len(leaks_before),
            len(leaks_after),
            [_mod_summary(mod) for mod in emitted],
            [_mod_summary(mod) for mod in dropped],
            sorted(override_keys),
            len(unresolved_frontiers),
        )
        for prefix, leaks in (
            ("before", leaks_before),
            ("after", leaks_after),
        ):
            for leak in leaks[:4]:
                logger.info(
                    "DAG_FRONTIER_CLOSURE_LEAK_%s: dag_scc=%d->%d "
                    "path=%s cfg_scc_size=%d",
                    prefix.upper(),
                    leak.from_dag_scc,
                    leak.to_dag_scc,
                    list(leak.path),
                    len(leak.cfg_scc_blocks),
                )
        for unresolved in unresolved_frontiers[:4]:
            logger.info(
                "DAG_FRONTIER_CLOSURE_UNRESOLVED: reason=%s "
                "source=blk[%d] observed=blk[%d] arm=%s "
                "dag_scc=%d->%d candidates=%s path=%s",
                unresolved.reason,
                unresolved.source_block,
                unresolved.observed_target,
                unresolved.branch_arm,
                unresolved.leak.from_dag_scc,
                unresolved.leak.to_dag_scc,
                list(unresolved.candidate_targets),
                list(unresolved.leak.path),
            )

    return FrontierClosureResult(
        modifications=tuple(current_modifications),
        emitted_modifications=tuple(emitted),
        dropped_modifications=tuple(dropped),
        stale_hazard_override_keys=frozenset(override_keys),
        leaks_before=tuple(leaks_before),
        leaks_after=tuple(leaks_after),
        resolved_frontiers=tuple(resolved),
        unresolved_frontiers=tuple(unresolved_frontiers),
        diagnostic_rows=diagnostic_rows,
    )


def _env_enabled(name: str, *, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    return raw.strip().lower() not in _FALSE_ENV_VALUES


def _project(flow_graph: object, modifications: list[object]) -> object:
    try:
        patch_plan = compile_patch_plan(modifications, flow_graph)  # type: ignore[arg-type]
        return project_post_state(flow_graph, patch_plan)  # type: ignore[arg-type]
    except Exception:
        logger.debug("DAG_FRONTIER_CLOSURE: projection failed", exc_info=True)
        return flow_graph


def _build_indexes(dag: object) -> _DagIndexes:
    node_to_scc: dict[object, int] = {}
    scc_nodes: dict[int, set[object]] = defaultdict(set)
    cyclic_scc_ids: set[int] = set()
    for fallback_id, scc in enumerate(getattr(dag, "sccs", ()) or ()):
        scc_id = int(getattr(scc, "scc_id", fallback_id))
        scc_nodes_tuple = tuple(getattr(scc, "nodes", ()) or ())
        is_cyclic = bool(getattr(scc, "is_cyclic", len(scc_nodes_tuple) > 1))
        if is_cyclic:
            cyclic_scc_ids.add(scc_id)
        for key in scc_nodes_tuple:
            try:
                hash(key)
            except Exception:
                continue
            node_to_scc[key] = scc_id
            scc_nodes[scc_id].add(key)

    block_to_sccs_mut: dict[int, set[int]] = defaultdict(set)
    state_to_entries: dict[int, set[int]] = defaultdict(set)
    for node in getattr(dag, "nodes", ()) or ():
        key = getattr(node, "key", None)
        if key not in node_to_scc:
            continue
        scc_id = node_to_scc[key]
        for block in _node_blocks(node):
            block_to_sccs_mut[int(block)].add(scc_id)
        state_const = getattr(key, "state_const", None)
        entry = _node_entry_block(node)
        if state_const is not None and entry is not None:
            state_to_entries[int(state_const) & 0xFFFFFFFFFFFFFFFF].add(int(entry))

    dag_succs: dict[int, set[int]] = defaultdict(set)
    choices_by_anchor_mut: dict[tuple[int, int | None], list[_FrontierChoice]] = (
        defaultdict(list)
    )
    for edge in getattr(dag, "edges", ()) or ():
        source_key = getattr(edge, "source_key", None)
        source_scc = node_to_scc.get(source_key)
        target_key = getattr(edge, "target_key", None)
        target_scc = node_to_scc.get(target_key)
        if source_scc is not None and target_scc is not None:
            dag_succs[source_scc].add(target_scc)

        anchor = getattr(edge, "source_anchor", None)
        source_block = getattr(anchor, "block_serial", None)
        if source_block is None:
            continue
        branch_arm_raw = getattr(anchor, "branch_arm", None)
        branch_arm = None if branch_arm_raw is None else int(branch_arm_raw)
        edge_kind = _edge_kind_name(edge)
        if edge_kind not in {
            "TRANSITION",
            "CONDITIONAL_TRANSITION",
            "CONDITIONAL_RETURN",
            "EXIT_ROUTINE",
        }:
            continue
        anchor_key = (int(source_block), branch_arm)
        for target, is_path_step in _edge_frontier_targets(edge, int(source_block)):
            choices_by_anchor_mut[anchor_key].append(
                _FrontierChoice(
                    source_block=int(source_block),
                    branch_arm=branch_arm,
                    target_block=int(target),
                    edge_kind=edge_kind,
                    proof=(
                        int(source_block),
                        branch_arm,
                        int(target),
                        edge_kind,
                        bool(is_path_step),
                    ),
                    is_path_step=bool(is_path_step),
                )
            )
        ordered_path = tuple(
            int(block) for block in (getattr(edge, "ordered_path", ()) or ())
        )
        for path_source, path_target in zip(ordered_path, ordered_path[1:]):
            if int(path_source) == int(path_target):
                continue
            choices_by_anchor_mut[(int(path_source), None)].append(
                _FrontierChoice(
                    source_block=int(path_source),
                    branch_arm=None,
                    target_block=int(path_target),
                    edge_kind=edge_kind,
                    proof=(
                        int(path_source),
                        None,
                        int(path_target),
                        f"{edge_kind}_CHAIN",
                        True,
                    ),
                    is_path_step=True,
                )
            )
        target_entry = getattr(edge, "target_entry_anchor", None)
        if ordered_path and target_entry is not None:
            path_tail = int(ordered_path[-1])
            if path_tail != int(target_entry):
                choices_by_anchor_mut[(path_tail, None)].append(
                    _FrontierChoice(
                        source_block=path_tail,
                        branch_arm=None,
                        target_block=int(target_entry),
                        edge_kind=edge_kind,
                        proof=(
                            path_tail,
                            None,
                            int(target_entry),
                            f"{edge_kind}_CHAIN_TARGET",
                            False,
                        ),
                        is_path_step=False,
                    )
                )

    scc_ids = set(scc_nodes)
    scc_ids.update(dag_succs)
    for succs in dag_succs.values():
        scc_ids.update(succs)
    reachability = {
        scc_id: frozenset(_reachable_sccs(scc_id, dag_succs))
        for scc_id in scc_ids
    }
    choices_by_anchor = {
        key: tuple(_dedupe_choices(value))
        for key, value in choices_by_anchor_mut.items()
    }
    return _DagIndexes(
        block_to_sccs={
            block: frozenset(sccs)
            for block, sccs in block_to_sccs_mut.items()
        },
        scc_reachability=reachability,
        choices_by_anchor=choices_by_anchor,
        cyclic_scc_ids=frozenset(cyclic_scc_ids),
        entry_by_state={
            state: next(iter(entries))
            for state, entries in state_to_entries.items()
            if len(entries) == 1
        },
    )


def _node_entry_block(node: object) -> int | None:
    for attr in ("entry_anchor", "handler_serial"):
        value = getattr(node, attr, None)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _node_blocks(node: object) -> frozenset[int]:
    out: set[int] = set()
    for attr in (
        "handler_serial",
        "entry_anchor",
        "owned_blocks",
        "exclusive_blocks",
        "shared_suffix_blocks",
    ):
        value = getattr(node, attr, None)
        if value is None:
            continue
        if isinstance(value, (tuple, list, set, frozenset)):
            for serial in value:
                try:
                    out.add(int(serial))
                except (TypeError, ValueError):
                    continue
        else:
            try:
                out.add(int(value))
            except (TypeError, ValueError):
                continue
    for segment in getattr(node, "local_segments", ()) or ():
        for serial in getattr(segment, "blocks", ()) or ():
            try:
                out.add(int(serial))
            except (TypeError, ValueError):
                continue
    return frozenset(out)


def _edge_kind_name(edge: object) -> str:
    kind = getattr(edge, "kind", None)
    name = getattr(kind, "name", None)
    if name:
        return str(name)
    text = str(kind)
    return text.rsplit(".", 1)[-1]


def _edge_frontier_targets(edge: object, source_block: int) -> tuple[tuple[int, bool], ...]:
    targets: list[tuple[int, bool]] = []
    ordered_path = tuple(
        int(block) for block in (getattr(edge, "ordered_path", ()) or ())
    )
    if ordered_path:
        try:
            source_index = ordered_path.index(int(source_block))
        except ValueError:
            source_index = -1
        if source_index >= 0 and source_index + 1 < len(ordered_path):
            targets.append((int(ordered_path[source_index + 1]), True))

    target_entry = getattr(edge, "target_entry_anchor", None)
    if target_entry is not None:
        targets.append((int(target_entry), False))

    deduped: list[tuple[int, bool]] = []
    seen: set[int] = set()
    for target, is_path_step in targets:
        if target == source_block or target < 0 or target in seen:
            continue
        seen.add(target)
        deduped.append((target, is_path_step))
    return tuple(deduped)


def _dedupe_choices(choices: list[_FrontierChoice]) -> tuple[_FrontierChoice, ...]:
    out: list[_FrontierChoice] = []
    seen: set[tuple[int, int | None, int]] = set()
    for choice in choices:
        key = (choice.source_block, choice.branch_arm, choice.target_block)
        if key in seen:
            continue
        seen.add(key)
        out.append(choice)
    return tuple(out)


def _reachable_sccs(start: int, dag_succs: dict[int, set[int]]) -> set[int]:
    out: set[int] = {int(start)}
    queue: deque[int] = deque([int(start)])
    while queue:
        current = queue.popleft()
        for succ in dag_succs.get(current, set()):
            if succ in out:
                continue
            out.add(succ)
            queue.append(succ)
    return out


def _find_semantic_scc_leaks(
    flow_graph: object,
    indexes: _DagIndexes,
    *,
    include_noncyclic_bridges: bool = False,
) -> tuple[SemanticSccLeak, ...]:
    block_succs = {
        int(serial): tuple(int(succ) for succ in getattr(block, "succs", ()) or ())
        for serial, block in (getattr(flow_graph, "blocks", {}) or {}).items()
    }
    cfg_sccs = nontrivial_sccs(compute_live_cfg_sccs(block_succs))
    leaks: list[SemanticSccLeak] = []
    for cfg_scc in cfg_sccs:
        blocks = frozenset(int(block) for block in cfg_scc.blocks)
        scc_to_blocks: dict[int, set[int]] = defaultdict(set)
        for block in blocks:
            for dag_scc in indexes.block_to_sccs.get(block, frozenset()):
                if (
                    not include_noncyclic_bridges
                    and dag_scc not in indexes.cyclic_scc_ids
                ):
                    continue
                scc_to_blocks[int(dag_scc)].add(block)
        if len(scc_to_blocks) < 2:
            continue
        if include_noncyclic_bridges:
            cyclic_dag_sccs = set(scc_to_blocks) & set(indexes.cyclic_scc_ids)
            if len(cyclic_dag_sccs) < 2:
                continue
        dag_scc_ids = sorted(scc_to_blocks)
        for left_idx, left in enumerate(dag_scc_ids):
            for right in dag_scc_ids[left_idx + 1:]:
                if (
                    include_noncyclic_bridges
                    and left not in indexes.cyclic_scc_ids
                    and right not in indexes.cyclic_scc_ids
                ):
                    continue
                left_reaches_right = right in indexes.scc_reachability.get(
                    left, frozenset({left})
                )
                right_reaches_left = left in indexes.scc_reachability.get(
                    right, frozenset({right})
                )
                if left_reaches_right and right_reaches_left:
                    continue
                if left_reaches_right and not right_reaches_left:
                    path = _shortest_path(
                        block_succs,
                        starts=scc_to_blocks[right],
                        goals=scc_to_blocks[left],
                        allowed_blocks=blocks,
                    )
                    if path:
                        leaks.append(
                            SemanticSccLeak(blocks, right, left, tuple(path))
                        )
                    continue
                if right_reaches_left and not left_reaches_right:
                    path = _shortest_path(
                        block_succs,
                        starts=scc_to_blocks[left],
                        goals=scc_to_blocks[right],
                        allowed_blocks=blocks,
                    )
                    if path:
                        leaks.append(
                            SemanticSccLeak(blocks, left, right, tuple(path))
                        )
                    continue
                # No DAG order between the components: either CFG direction is
                # illegal. Pick the shorter witness path for deterministic
                # diagnostics and frontier selection.
                left_path = _shortest_path(
                    block_succs,
                    starts=scc_to_blocks[left],
                    goals=scc_to_blocks[right],
                    allowed_blocks=blocks,
                )
                right_path = _shortest_path(
                    block_succs,
                    starts=scc_to_blocks[right],
                    goals=scc_to_blocks[left],
                    allowed_blocks=blocks,
                )
                candidates = [
                    (left, right, left_path),
                    (right, left, right_path),
                ]
                candidates = [item for item in candidates if item[2]]
                if candidates:
                    source_scc, target_scc, path = min(
                        candidates, key=lambda item: (len(item[2]), item[0], item[1])
                    )
                    leaks.append(
                        SemanticSccLeak(blocks, source_scc, target_scc, tuple(path))
                    )
    return tuple(leaks)


def _shortest_path(
    adj: dict[int, tuple[int, ...]],
    *,
    starts: set[int],
    goals: set[int],
    allowed_blocks: frozenset[int],
) -> tuple[int, ...]:
    queue: deque[tuple[int, tuple[int, ...]]] = deque(
        (int(start), (int(start),)) for start in sorted(starts)
    )
    seen = {int(start) for start in starts}
    goal_set = {int(goal) for goal in goals}
    while queue:
        current, path = queue.popleft()
        if current in goal_set:
            return path
        for succ in adj.get(current, ()):
            succ = int(succ)
            if succ not in allowed_blocks or succ in seen:
                continue
            seen.add(succ)
            queue.append((succ, (*path, succ)))
    return ()


def _select_frontier_action(
    projected_flow_graph: object,
    leaks: tuple[SemanticSccLeak, ...],
    indexes: _DagIndexes,
    *,
    current_modifications: list[object],
    frontier_blocks: set[int],
    base_flow_graph: object,
    bst_interval_rows: tuple[_BstIntervalFrontierRow, ...],
) -> tuple[
    list[object],
    object | None,
    object | None,
    ResolvedFrontier | None,
] | None:
    for leak in sorted(leaks, key=lambda item: (len(item.path), item.path)):
        path = leak.path
        if len(path) < 2:
            continue
        for source, observed_target in zip(path, path[1:]):
            block = projected_flow_graph.get_block(int(source))
            if block is None:
                continue
            succs = tuple(int(succ) for succ in getattr(block, "succs", ()) or ())
            if int(observed_target) not in succs:
                continue
            arm = succs.index(int(observed_target)) if len(succs) > 1 else None
            choices = _choices_for_observed_edge(
                indexes,
                source=int(source),
                arm=arm,
                observed_target=int(observed_target),
                frontier_blocks=frontier_blocks,
            )
            if not choices:
                bst_choice = _bst_interval_proven_frontier_choice(
                    projected_flow_graph,
                    indexes,
                    leak=leak,
                    source=int(source),
                    arm=arm,
                    observed_target=int(observed_target),
                    succs=succs,
                    interval_rows=bst_interval_rows,
                )
                if bst_choice is not None:
                    choices = (bst_choice,)
                else:
                    choices = ()
            if not choices:
                same_scc_choice = None
                if _env_enabled(
                    "D810_DAG_FRONTIER_SAME_SCC_ALTERNATE",
                    default=False,
                ):
                    same_scc_choice = _same_scc_alternate_successor_choice(
                        indexes,
                        leak=leak,
                        source=int(source),
                        arm=arm,
                        observed_target=int(observed_target),
                        succs=succs,
                    )
                if same_scc_choice is None:
                    continue
                choices = (same_scc_choice,)
            choice = choices[0]
            replacement = _replace_or_add_redirect(
                current_modifications,
                projected_flow_graph=projected_flow_graph,
                base_flow_graph=base_flow_graph,
                source=int(source),
                observed_target=int(observed_target),
                choice=choice,
            )
            if replacement is not None:
                resolved_frontier = None
                if choice.edge_kind == "BST_INTERVAL_PROVEN_FRONTIER":
                    resolved_frontier = ResolvedFrontier(
                        leak=leak,
                        source_block=int(source),
                        observed_target=int(observed_target),
                        branch_arm=arm,
                        reason="bst_interval_proven_frontier",
                        target_block=int(choice.target_block),
                        payload=dict(choice.payload or {}),
                    )
                new_mods, emitted_mod, dropped_mod = replacement
                return new_mods, emitted_mod, dropped_mod, resolved_frontier
    return None


def _select_dispatcher_state_residue_action(
    projected_flow_graph: object,
    indexes: _DagIndexes,
    *,
    current_modifications: list[object],
    dispatcher_serial: int,
    base_flow_graph: object,
    bst_interval_rows: tuple[_BstIntervalFrontierRow, ...],
) -> tuple[
    list[object],
    object | None,
    object | None,
    ResolvedFrontier | None,
] | None:
    if not bst_interval_rows:
        return None
    dispatcher_serial = int(dispatcher_serial)
    state_stkoff = _dispatcher_state_stkoff(projected_flow_graph, dispatcher_serial)
    if state_stkoff is None:
        state_stkoff = _dispatcher_state_stkoff(base_flow_graph, dispatcher_serial)
    if state_stkoff is None:
        return None

    blocks = getattr(projected_flow_graph, "blocks", {}) or {}
    for source in sorted(int(serial) for serial in blocks):
        block = projected_flow_graph.get_block(source)
        if block is None:
            continue
        succs = tuple(int(succ) for succ in getattr(block, "succs", ()) or ())
        if succs != (dispatcher_serial,):
            continue
        state_const = _state_write_constant(block, state_stkoff)
        if state_const is None:
            continue
        state_const &= 0xFFFFFFFFFFFFFFFF
        raw_choices = tuple(indexes.choices_by_anchor.get((source, None), ()))
        if any(choice.is_path_step for choice in raw_choices):
            continue
        choices = tuple(
            choice
            for choice in raw_choices
            if (
                not choice.is_path_step
                and int(choice.target_block) != dispatcher_serial
                and _is_direct_dag_frontier_choice(choice)
            )
        )
        for choice in choices:
            interval = _interval_for_state_target(
                bst_interval_rows,
                state_const=state_const,
                target_block=int(choice.target_block),
            )
            if interval is None:
                continue
            replacement = _replace_or_add_redirect(
                current_modifications,
                projected_flow_graph=projected_flow_graph,
                base_flow_graph=base_flow_graph,
                source=source,
                observed_target=dispatcher_serial,
                choice=_FrontierChoice(
                    source_block=source,
                    branch_arm=None,
                    target_block=int(choice.target_block),
                    edge_kind="DAG_BST_INTERVAL_DISPATCHER_RESIDUE",
                    proof=(
                        source,
                        None,
                        dispatcher_serial,
                        int(choice.target_block),
                        "DAG_BST_INTERVAL_DISPATCHER_RESIDUE",
                        _compact_state_hex(state_const),
                        choice.proof,
                        (interval.lo, interval.hi, interval.target_block),
                    ),
                    is_path_step=False,
                    payload={
                        "proof": "DAG_BST_INTERVAL_DISPATCHER_RESIDUE",
                        "state": _compact_state_hex(state_const),
                        "state_hex": f"0x{state_const:016x}",
                        "source": source,
                        "observed": dispatcher_serial,
                        "candidate": int(choice.target_block),
                        "dag_choice_proof": tuple(choice.proof),
                        "interval": _interval_payload(interval),
                    },
                ),
            )
            if replacement is None:
                continue
            new_mods, emitted_mod, dropped_mod = replacement
            return (
                new_mods,
                emitted_mod,
                dropped_mod,
                ResolvedFrontier(
                    leak=None,
                    source_block=source,
                    observed_target=dispatcher_serial,
                    branch_arm=None,
                    reason="dag_bst_interval_dispatcher_residue",
                    target_block=int(choice.target_block),
                    payload={
                        "proof": "DAG_BST_INTERVAL_DISPATCHER_RESIDUE",
                        "state": _compact_state_hex(state_const),
                        "state_hex": f"0x{state_const:016x}",
                        "source": source,
                        "observed": dispatcher_serial,
                        "candidate": int(choice.target_block),
                        "dag_choice_proof": tuple(choice.proof),
                        "interval": _interval_payload(interval),
                    },
                ),
            )
    return None


def _select_shared_condition_entry_clone_action(
    projected_flow_graph: object,
    indexes: _DagIndexes,
    *,
    current_modifications: list[object],
    dispatcher_serial: int,
    base_flow_graph: object,
) -> tuple[
    list[object],
    object | None,
    object | None,
    ResolvedFrontier | None,
] | None:
    """Clone shared condition entries that are DAG-backed but structurally fused.

    This is a structuring repair, not a semantic-SCC rewrite.  It handles the
    pattern where HCC has a DAG-proven entry edge into a shared two-way
    condition block, but multiple incoming CFG paths keep Hex-Rays presenting
    the condition as a ``goto LABEL`` into a residual ``while (1)`` loop.  The
    clone preserves the condition and both arms; it only gives the proven
    predecessor a private copy.
    """

    if not _env_enabled("D810_DAG_FRONTIER_SHARED_CONDITION_CLONE", default=True):
        return None

    state_stkoff = _dispatcher_state_stkoff(projected_flow_graph, dispatcher_serial)
    if state_stkoff is None:
        state_stkoff = _dispatcher_state_stkoff(base_flow_graph, dispatcher_serial)
    if state_stkoff is None:
        return None

    blocks = getattr(projected_flow_graph, "blocks", {}) or {}
    for source in sorted(int(serial) for serial in blocks):
        block = projected_flow_graph.get_block(source)
        if block is None:
            continue
        succs = tuple(int(succ) for succ in getattr(block, "succs", ()) or ())
        if len(succs) != 2:
            continue
        preds = tuple(int(pred) for pred in getattr(block, "preds", ()) or ())
        if len(preds) < 2:
            continue
        if not _is_shared_condition_clone_block(block, state_stkoff):
            continue
        if not _condition_successors_are_dag_proven(indexes, source, succs):
            continue

        base_block = base_flow_graph.get_block(source)
        base_succs = (
            tuple(int(succ) for succ in getattr(base_block, "succs", ()) or ())
            if base_block
            else ()
        )
        if len(base_succs) != 2:
            continue

        for pred in sorted(preds):
            pred_block = projected_flow_graph.get_block(pred)
            if pred_block is None:
                continue
            pred_succs = tuple(
                int(succ) for succ in getattr(pred_block, "succs", ()) or ()
            )
            if pred_succs != (source,):
                continue
            base_pred = base_flow_graph.get_block(pred)
            base_pred_succs = (
                tuple(int(succ) for succ in getattr(base_pred, "succs", ()) or ())
                if base_pred
                else ()
            )
            entry_choice = _direct_dag_entry_choice(indexes, pred=pred, target=source)
            if entry_choice is None:
                continue
            if _has_duplicate_block_mod(
                current_modifications,
                source_block=source,
                pred_serial=pred,
            ):
                continue
            if _has_conditional_redirect_mod(
                current_modifications,
                source_block=pred,
                ref_block=source,
            ):
                continue

            mod: object
            dropped_mod: object | None = None
            if source in base_pred_succs:
                mod = DuplicateBlock(
                    source_block=source,
                    target_block=None,
                    pred_serial=pred,
                    patch_kind="dag_entry_shared_condition_clone",
                )
                new_modifications = [*current_modifications, mod]
            else:
                dropped_mod = _find_redirect_to_target_mod(
                    current_modifications,
                    source=pred,
                    new_target=source,
                )
                if dropped_mod is None:
                    continue
                # BLT_2WAY succset order is [fallthrough, conditional target].
                mod = CreateConditionalRedirect(
                    source_block=pred,
                    ref_block=source,
                    conditional_target=int(succs[1]),
                    fallthrough_target=int(succs[0]),
                )
                new_modifications = [
                    existing
                    for existing in current_modifications
                    if existing is not dropped_mod
                ]
                new_modifications.append(mod)
            logger.info(
                "DAG_FRONTIER_CLOSURE: cloning DAG-proven shared condition "
                "blk[%d] for pred=blk[%d] proof=%s",
                source,
                pred,
                entry_choice.proof,
            )
            return (
                new_modifications,
                mod,
                dropped_mod,
                ResolvedFrontier(
                    leak=None,
                    source_block=pred,
                    observed_target=source,
                    branch_arm=None,
                    reason="dag_entry_shared_condition_clone",
                    target_block=source,
                    payload={
                        "proof": "DAG_ENTRY_SHARED_CONDITION_CLONE",
                        "predecessor": pred,
                        "condition_block": source,
                        "condition_successors": succs,
                        "dag_entry_proof": tuple(entry_choice.proof),
                    },
                ),
            )
    return None


def _direct_dag_entry_choice(
    indexes: _DagIndexes,
    *,
    pred: int,
    target: int,
) -> _FrontierChoice | None:
    choices = indexes.choices_by_anchor.get((int(pred), None), ())
    for choice in choices:
        if int(choice.target_block) != int(target):
            continue
        if choice.is_path_step:
            continue
        if not _is_direct_dag_frontier_choice(choice):
            continue
        return choice
    return None


def _condition_successors_are_dag_proven(
    indexes: _DagIndexes,
    source: int,
    succs: tuple[int, int],
) -> bool:
    for arm, succ in enumerate(succs):
        choices = indexes.choices_by_anchor.get((int(source), arm), ())
        if not any(int(choice.target_block) == int(succ) for choice in choices):
            return False
    return True


def _is_shared_condition_clone_block(block: object, state_stkoff: int) -> bool:
    if _state_write_constant(block, state_stkoff) is None:
        return False
    insns = tuple(getattr(block, "insn_snapshots", ()) or ())
    if len(insns) < 2:
        return False
    tail = insns[-1]
    if getattr(tail, "kind", InsnKind.UNKNOWN) != InsnKind.EQUALITY_JUMP:
        return False
    for insn in insns[:-1]:
        if not _is_dispatcher_state_mov(insn, state_stkoff):
            return False
    return True


def _is_dispatcher_state_mov(insn: object, state_stkoff: int) -> bool:
    if getattr(insn, "kind", InsnKind.UNKNOWN) != InsnKind.MOV:
        return False
    dest = getattr(insn, "d", None)
    src = getattr(insn, "l", None)
    if dest is None or src is None:
        return False
    try:
        dest_stkoff = int(getattr(dest, "stkoff", None))
    except (TypeError, ValueError):
        return False
    if dest_stkoff != int(state_stkoff):
        return False
    return getattr(src, "value", None) is not None


def _has_duplicate_block_mod(
    modifications: list[object],
    *,
    source_block: int,
    pred_serial: int,
) -> bool:
    for mod in modifications:
        info = _duplicate_info(mod)
        if info == (int(source_block), int(pred_serial)):
            return True
    return False


def _has_conditional_redirect_mod(
    modifications: list[object],
    *,
    source_block: int,
    ref_block: int,
) -> bool:
    for mod in modifications:
        info = _conditional_redirect_info(mod)
        if info == (int(source_block), int(ref_block)):
            return True
    return False


def _find_redirect_to_target_mod(
    modifications: list[object],
    *,
    source: int,
    new_target: int,
) -> object | None:
    for mod in modifications:
        info = _redirect_info(mod)
        if info is None:
            continue
        mod_source, _old_target, mod_target = info
        if int(mod_source) == int(source) and int(mod_target) == int(new_target):
            return mod
    return None


def _is_direct_dag_frontier_choice(choice: _FrontierChoice) -> bool:
    if choice.is_path_step or len(choice.proof) < 5:
        return False
    proof_kind = str(choice.proof[3])
    if proof_kind.endswith("_CHAIN_TARGET"):
        return True
    return bool(choice.proof[4]) is False and proof_kind in {
        "TRANSITION",
        "CONDITIONAL_TRANSITION",
        "CONDITIONAL_RETURN",
        "EXIT_ROUTINE",
    }


def _find_unresolved_frontiers(
    projected_flow_graph: object,
    leaks: tuple[SemanticSccLeak, ...],
    indexes: _DagIndexes,
    *,
    frontier_blocks: set[int],
) -> tuple[UnresolvedFrontier, ...]:
    unresolved: list[UnresolvedFrontier] = []
    for leak in sorted(leaks, key=lambda item: (len(item.path), item.path)):
        path = leak.path
        if len(path) < 2:
            continue
        for source, observed_target in zip(path, path[1:]):
            block = projected_flow_graph.get_block(int(source))
            if block is None:
                continue
            succs = tuple(int(succ) for succ in getattr(block, "succs", ()) or ())
            if int(observed_target) not in succs:
                continue
            arm = succs.index(int(observed_target)) if len(succs) > 1 else None
            choices = _choices_for_observed_edge(
                indexes,
                source=int(source),
                arm=arm,
                observed_target=int(observed_target),
                frontier_blocks=frontier_blocks,
            )
            if choices:
                break
            same_scc_choice = _same_scc_alternate_successor_choice(
                indexes,
                leak=leak,
                source=int(source),
                arm=arm,
                observed_target=int(observed_target),
                succs=succs,
            )
            if same_scc_choice is not None:
                unresolved.append(
                    UnresolvedFrontier(
                        leak=leak,
                        source_block=int(source),
                        observed_target=int(observed_target),
                        branch_arm=arm,
                        reason="same_scc_alternate_disabled",
                        candidate_targets=(int(same_scc_choice.target_block),),
                    )
                )
                break
            unresolved.append(
                UnresolvedFrontier(
                    leak=leak,
                    source_block=int(source),
                    observed_target=int(observed_target),
                    branch_arm=arm,
                    reason=_unresolved_frontier_reason(
                        indexes,
                        source=int(source),
                        arm=arm,
                        observed_target=int(observed_target),
                    ),
                )
            )
            break
    return tuple(unresolved)


def _build_diagnostic_rows(
    *,
    leaks_before: tuple[SemanticSccLeak, ...],
    leaks_after: tuple[SemanticSccLeak, ...],
    resolved_frontiers: tuple[ResolvedFrontier, ...],
    unresolved_frontiers: tuple[UnresolvedFrontier, ...],
) -> tuple[FrontierClosureDiagnosticRow, ...]:
    rows: list[FrontierClosureDiagnosticRow] = []
    rows.extend(_leak_diagnostic_rows("leak_before", leaks_before))
    rows.extend(_leak_diagnostic_rows("leak_after", leaks_after))
    for resolved in resolved_frontiers:
        leak = resolved.leak
        from_dag_scc = int(leak.from_dag_scc) if leak is not None else None
        to_dag_scc = int(leak.to_dag_scc) if leak is not None else None
        path = (
            tuple(int(block) for block in leak.path)
            if leak is not None
            else (
                int(resolved.source_block),
                int(resolved.observed_target),
                int(resolved.target_block),
            )
        )
        cfg_scc_size = len(leak.cfg_scc_blocks) if leak is not None else None
        rows.append(
            FrontierClosureDiagnosticRow(
                kind="resolved",
                reason=resolved.reason,
                source_block=int(resolved.source_block),
                observed_target=int(resolved.observed_target),
                branch_arm=resolved.branch_arm,
                from_dag_scc=from_dag_scc,
                to_dag_scc=to_dag_scc,
                candidate_targets=(int(resolved.target_block),),
                path=path,
                cfg_scc_size=cfg_scc_size,
                payload={
                    "verifier": "dag_frontier_closure",
                    "behavior": "repair_authorized",
                    **dict(resolved.payload),
                },
            )
        )
    for unresolved in unresolved_frontiers:
        leak = unresolved.leak
        rows.append(
            FrontierClosureDiagnosticRow(
                kind="unresolved",
                reason=unresolved.reason,
                source_block=int(unresolved.source_block),
                observed_target=int(unresolved.observed_target),
                branch_arm=unresolved.branch_arm,
                from_dag_scc=int(leak.from_dag_scc),
                to_dag_scc=int(leak.to_dag_scc),
                candidate_targets=tuple(
                    int(target) for target in unresolved.candidate_targets
                ),
                path=tuple(int(block) for block in leak.path),
                cfg_scc_size=len(leak.cfg_scc_blocks),
                payload={
                    "verifier": "dag_frontier_closure",
                    "behavior": "diagnostic_only",
                },
            )
        )
    return tuple(rows)


def _leak_diagnostic_rows(
    kind: str,
    leaks: tuple[SemanticSccLeak, ...],
) -> tuple[FrontierClosureDiagnosticRow, ...]:
    rows: list[FrontierClosureDiagnosticRow] = []
    for leak in leaks:
        source_block = leak.path[0] if leak.path else None
        observed_target = leak.path[1] if len(leak.path) > 1 else None
        rows.append(
            FrontierClosureDiagnosticRow(
                kind=kind,
                reason="semantic_scc_leak",
                source_block=(
                    int(source_block) if source_block is not None else None
                ),
                observed_target=(
                    int(observed_target) if observed_target is not None else None
                ),
                branch_arm=None,
                from_dag_scc=int(leak.from_dag_scc),
                to_dag_scc=int(leak.to_dag_scc),
                path=tuple(int(block) for block in leak.path),
                cfg_scc_size=len(leak.cfg_scc_blocks),
                payload={
                    "verifier": "dag_frontier_closure",
                    "behavior": "diagnostic_only",
                },
            )
        )
    return tuple(rows)


def _unresolved_frontier_reason(
    indexes: _DagIndexes,
    *,
    source: int,
    arm: int | None,
    observed_target: int,
) -> str:
    raw_choices = list(indexes.choices_by_anchor.get((int(source), arm), ()))
    if arm is not None:
        raw_choices.extend(indexes.choices_by_anchor.get((int(source), None), ()))
    if not raw_choices:
        return "no_dag_choice_for_source"
    matching_choices = [
        choice
        for choice in raw_choices
        if int(choice.target_block) == int(observed_target)
    ]
    if matching_choices:
        if any(choice.is_path_step for choice in matching_choices):
            return "observed_edge_is_dag_path_step"
        return "observed_edge_is_dag_target"
    return "no_alternate_dag_choice"


def _choices_for_observed_edge(
    indexes: _DagIndexes,
    *,
    source: int,
    arm: int | None,
    observed_target: int,
    frontier_blocks: set[int],
) -> tuple[_FrontierChoice, ...]:
    raw_choices = list(indexes.choices_by_anchor.get((int(source), arm), ()))
    if arm is not None:
        raw_choices.extend(indexes.choices_by_anchor.get((int(source), None), ()))
    matching_choices = [
        choice
        for choice in raw_choices
        if int(choice.target_block) == int(observed_target)
    ]
    if any(choice.is_path_step for choice in matching_choices):
        return ()
    choices = [
        choice for choice in raw_choices
        if int(choice.target_block) != int(observed_target)
    ]
    if matching_choices:
        path_step_choices = [choice for choice in choices if choice.is_path_step]
        if path_step_choices:
            choices = path_step_choices
    if not choices:
        return ()
    choices.sort(
        key=lambda choice: (
            int(choice.target_block) in frontier_blocks,
            not choice.is_path_step,
            int(choice.target_block),
        )
    )
    return tuple(choices)


def _same_scc_alternate_successor_choice(
    indexes: _DagIndexes,
    *,
    leak: SemanticSccLeak,
    source: int,
    arm: int | None,
    observed_target: int,
    succs: tuple[int, ...],
) -> _FrontierChoice | None:
    """Close a dispatch frontier by keeping the edge in its DAG SCC.

    This is deliberately narrower than generic SCC splitting.  It fires only on
    the verifier's witness path, only when ``source`` is owned by the leaking
    semantic DAG SCC, and only when the same live conditional already has an
    alternate successor owned by that same DAG SCC.  That covers dispatcher
    guard false-arms that glue a state region to the next state's chain after
    HCC has already lowered the real DAG transitions.
    """

    source_sccs = indexes.block_to_sccs.get(int(source), frozenset())
    if int(leak.from_dag_scc) not in source_sccs:
        return None
    observed_sccs = indexes.block_to_sccs.get(int(observed_target), frozenset())
    if int(leak.from_dag_scc) in observed_sccs:
        return None

    candidates: list[int] = []
    for succ in succs:
        succ = int(succ)
        if succ == int(observed_target):
            continue
        succ_sccs = indexes.block_to_sccs.get(succ, frozenset())
        if int(leak.from_dag_scc) not in succ_sccs:
            continue
        candidates.append(succ)
    if not candidates:
        return None

    target = min(candidates)
    return _FrontierChoice(
        source_block=int(source),
        branch_arm=arm,
        target_block=int(target),
        edge_kind="SAME_DAG_SCC_FRONTIER",
        proof=(
            int(source),
            arm,
            int(observed_target),
            int(target),
            "SAME_DAG_SCC_FRONTIER",
            int(leak.from_dag_scc),
            int(leak.to_dag_scc),
        ),
        is_path_step=True,
    )


def _bst_interval_proven_frontier_choice(
    flow_graph: object,
    indexes: _DagIndexes,
    *,
    leak: SemanticSccLeak,
    source: int,
    arm: int | None,
    observed_target: int,
    succs: tuple[int, ...],
    interval_rows: tuple[_BstIntervalFrontierRow, ...],
) -> _FrontierChoice | None:
    """Close a BST singleton frontier using persisted interval evidence.

    This is intentionally not a same-SCC heuristic. It fires only when the
    live source block is an equality comparison against state ``K``, the
    alternate successor is both the DAG entry for ``K`` and the persisted
    singleton interval target ``[K, K+1)``, and the observed successor is an
    adjacent non-singleton/range interval target.
    """

    if len(succs) != 2 or int(observed_target) not in succs:
        return None
    if not interval_rows:
        return None
    alternate_succs = tuple(int(succ) for succ in succs if int(succ) != int(observed_target))
    if len(alternate_succs) != 1:
        return None
    candidate = int(alternate_succs[0])

    block = flow_graph.get_block(int(source))
    if block is None:
        return None
    state_const = _equality_compare_constant(block)
    if state_const is None:
        return None
    state_const &= 0xFFFFFFFFFFFFFFFF

    dag_entry = indexes.entry_by_state.get(state_const)
    if dag_entry is None or int(dag_entry) != candidate:
        return None

    singleton = _singleton_interval_for_state(
        interval_rows,
        state_const=state_const,
        target_block=candidate,
    )
    if singleton is None:
        return None

    sibling_rows = _adjacent_range_siblings(
        interval_rows,
        state_const=state_const,
        target_block=int(observed_target),
    )
    if not sibling_rows:
        return None

    payload = {
        "proof": "BST_INTERVAL_PROVEN_FRONTIER",
        "state": _compact_state_hex(state_const),
        "state_hex": f"0x{state_const:016x}",
        "source": int(source),
        "observed": int(observed_target),
        "candidate": int(candidate),
        "singleton_interval": _interval_payload(singleton),
        "observed_sibling_intervals": [
            _interval_payload(row) for row in sibling_rows
        ],
    }
    return _FrontierChoice(
        source_block=int(source),
        branch_arm=arm,
        target_block=int(candidate),
        edge_kind="BST_INTERVAL_PROVEN_FRONTIER",
        proof=(
            int(source),
            arm,
            int(observed_target),
            int(candidate),
            "BST_INTERVAL_PROVEN_FRONTIER",
            _compact_state_hex(state_const),
            tuple((row.lo, row.hi, row.target_block) for row in sibling_rows),
        ),
        is_path_step=True,
        payload=payload,
    )


def _equality_compare_constant(block: object) -> int | None:
    succs = tuple(int(succ) for succ in getattr(block, "succs", ()) or ())
    if len(succs) != 2:
        return None
    tail = getattr(block, "tail", None)
    if tail is None:
        insns = tuple(getattr(block, "insn_snapshots", ()) or ())
        tail = insns[-1] if insns else None
    if tail is None:
        return None
    if getattr(tail, "kind", InsnKind.UNKNOWN) != InsnKind.EQUALITY_JUMP:
        return None

    left = getattr(tail, "l", None)
    right = getattr(tail, "r", None)
    constants: list[int] = []
    non_constants = 0
    for operand in (left, right):
        if operand is None:
            continue
        value = getattr(operand, "value", None)
        if value is not None:
            try:
                constants.append(int(value))
                continue
            except (TypeError, ValueError):
                return None
        non_constants += 1

    if not constants:
        # Older unit fixtures may only populate ``operands``. Do a narrow
        # fallback over operands that expose an immediate ``value``.
        for operand in getattr(tail, "operands", ()) or ():
            value = getattr(operand, "value", None)
            if value is None:
                continue
            try:
                constants.append(int(value))
            except (TypeError, ValueError):
                return None
    if len(constants) != 1 or non_constants == 0:
        return None
    return int(constants[0])


def _dispatcher_state_stkoff(flow_graph: object, dispatcher_serial: int) -> int | None:
    block = flow_graph.get_block(int(dispatcher_serial))
    if block is None:
        return None
    tail = getattr(block, "tail", None)
    if tail is None:
        insns = tuple(getattr(block, "insn_snapshots", ()) or ())
        tail = insns[-1] if insns else None
    if tail is None:
        return None
    constants = 0
    stack_offsets: list[int] = []
    for operand in (getattr(tail, "l", None), getattr(tail, "r", None)):
        if operand is None:
            continue
        if getattr(operand, "value", None) is not None:
            constants += 1
            continue
        stkoff = getattr(operand, "stkoff", None)
        if stkoff is None:
            continue
        try:
            stack_offsets.append(int(stkoff))
        except (TypeError, ValueError):
            continue
    if constants != 1 or len(stack_offsets) != 1:
        return None
    return stack_offsets[0]


def _state_write_constant(block: object, state_stkoff: int) -> int | None:
    for insn in reversed(tuple(getattr(block, "insn_snapshots", ()) or ())):
        insn_kind = getattr(insn, "kind", InsnKind.UNKNOWN)
        if insn_kind == InsnKind.GOTO:
            continue
        if insn_kind != InsnKind.MOV:
            continue
        dest = getattr(insn, "d", None)
        src = getattr(insn, "l", None)
        if dest is None or src is None:
            continue
        try:
            dest_stkoff = int(getattr(dest, "stkoff", None))
        except (TypeError, ValueError):
            continue
        if dest_stkoff != int(state_stkoff):
            continue
        value = getattr(src, "value", None)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return None


def _singleton_interval_for_state(
    rows: tuple[_BstIntervalFrontierRow, ...],
    *,
    state_const: int,
    target_block: int,
) -> _BstIntervalFrontierRow | None:
    for row in rows:
        if int(row.target_block) != int(target_block):
            continue
        if int(row.lo) == int(state_const) and int(row.hi) == int(state_const) + 1:
            return row
    return None


def _adjacent_range_siblings(
    rows: tuple[_BstIntervalFrontierRow, ...],
    *,
    state_const: int,
    target_block: int,
) -> tuple[_BstIntervalFrontierRow, ...]:
    siblings: list[_BstIntervalFrontierRow] = []
    for row in rows:
        if int(row.target_block) != int(target_block):
            continue
        width = int(row.hi) - int(row.lo)
        if width <= 1:
            continue
        if int(row.hi) == int(state_const) or int(row.lo) == int(state_const) + 1:
            siblings.append(row)
    return tuple(siblings)


def _interval_for_state_target(
    rows: tuple[_BstIntervalFrontierRow, ...],
    *,
    state_const: int,
    target_block: int,
) -> _BstIntervalFrontierRow | None:
    for row in rows:
        if int(row.target_block) != int(target_block):
            continue
        if int(row.lo) <= int(state_const) < int(row.hi):
            return row
    return None


def _interval_payload(row: _BstIntervalFrontierRow) -> dict[str, object]:
    return {
        "snapshot_id": row.snapshot_id,
        "row_index": row.row_index,
        "lo": _compact_state_hex(row.lo),
        "hi": _compact_state_hex(row.hi),
        "target": int(row.target_block),
    }


def _compact_state_hex(value: int) -> str:
    value = int(value) & 0xFFFFFFFFFFFFFFFF
    width = 8 if value <= 0xFFFFFFFF else 16
    return f"0x{value:0{width}X}"


def _coerce_bst_interval_rows(
    rows: tuple[object, ...] | list[object] | tuple[_BstIntervalFrontierRow, ...],
) -> tuple[_BstIntervalFrontierRow, ...]:
    out: list[_BstIntervalFrontierRow] = []
    for row in rows or ():
        if isinstance(row, _BstIntervalFrontierRow):
            out.append(row)
            continue
        snapshot_id = _row_value(row, "snapshot_id")
        row_index = _row_value(row, "row_index")
        lo = _row_value(row, "lo")
        hi = _row_value(row, "hi")
        target = _row_value(row, "target_block")
        if target is None:
            target = _row_value(row, "target")
        try:
            out.append(
                _BstIntervalFrontierRow(
                    snapshot_id=(
                        int(snapshot_id) if snapshot_id is not None else None
                    ),
                    row_index=int(row_index) if row_index is not None else None,
                    lo=_parse_int(lo),
                    hi=_parse_int(hi),
                    target_block=_parse_int(target),
                )
            )
        except (TypeError, ValueError):
            continue
    return tuple(out)


def _row_value(row: object, key: str) -> object | None:
    if isinstance(row, dict):
        return row.get(key)
    return getattr(row, key, None)


def _parse_int(value: object) -> int:
    if isinstance(value, str):
        return int(value, 0)
    return int(value)  # type: ignore[arg-type]


def _load_latest_bst_interval_rows(flow_graph: object) -> tuple[_BstIntervalFrontierRow, ...]:
    try:
        from d810.core.observability import get_active_diag_conn
    except Exception:
        return ()
    func_ea = int(getattr(flow_graph, "func_ea", 0) or 0)
    try:
        conn = get_active_diag_conn(func_ea)
    except Exception:
        return ()
    if conn is None:
        return ()
    func_hex = f"0x{func_ea & 0xFFFFFFFFFFFFFFFF:016x}"
    try:
        row = conn.execute(
            """
            SELECT r.snapshot_id
            FROM bst_interval_dispatcher_rows r
            JOIN snapshots s ON s.id = r.snapshot_id
            WHERE s.func_ea_hex = ?
            GROUP BY r.snapshot_id
            ORDER BY r.snapshot_id DESC
            LIMIT 1
            """,
            (func_hex,),
        ).fetchone()
        if row is None and func_ea == 0:
            row = conn.execute(
                "SELECT snapshot_id FROM bst_interval_dispatcher_rows "
                "GROUP BY snapshot_id ORDER BY snapshot_id DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return ()
        snapshot_id = int(row[0])
        rows = conn.execute(
            """
            SELECT snapshot_id, row_index, lo_i64, hi_i64, target_block
            FROM bst_interval_dispatcher_rows
            WHERE snapshot_id = ?
            ORDER BY row_index
            """,
            (snapshot_id,),
        ).fetchall()
    except Exception:
        return ()
    return tuple(
        _BstIntervalFrontierRow(
            snapshot_id=int(row[0]),
            row_index=int(row[1]),
            lo=int(row[2]),
            hi=int(row[3]),
            target_block=int(row[4]),
        )
        for row in rows
    )


def _replace_or_add_redirect(
    current_modifications: list[object],
    *,
    projected_flow_graph: object,
    base_flow_graph: object,
    source: int,
    observed_target: int,
    choice: _FrontierChoice,
) -> tuple[list[object], object | None, object | None] | None:
    desired_target = int(choice.target_block)
    source = int(source)
    observed_target = int(observed_target)

    new_modifications = list(current_modifications)
    for mod in current_modifications:
        if _redirect_info(mod) == (source, observed_target, desired_target):
            return None
        if _insert_info(mod) == (source, observed_target, desired_target):
            return None

    base_block = base_flow_graph.get_block(source)
    succs = (
        tuple(int(succ) for succ in getattr(base_block, "succs", ()) or ())
        if base_block
        else ()
    )
    if observed_target not in succs:
        return None
    if len(succs) == 1:
        mod = RedirectGoto(
            from_serial=source,
            old_target=observed_target,
            new_target=desired_target,
        )
    elif desired_target in succs:
        if choice.edge_kind not in {
            "BST_INTERVAL_PROVEN_FRONTIER",
            "SAME_DAG_SCC_FRONTIER",
        }:
            return None
        mod = InsertBlock(
            pred_serial=source,
            old_target_serial=observed_target,
            succ_serial=desired_target,
            instructions=(),
        )
    else:
        mod = RedirectBranch(
            from_serial=source,
            old_target=observed_target,
            new_target=desired_target,
        )
    new_modifications.append(mod)
    logger.info(
        "DAG_FRONTIER_CLOSURE: emitting frontier redirect %s proof=%s",
        _mod_summary(mod),
        choice.proof,
    )
    return new_modifications, mod, None


def _collect_stale_hazard_override_keys(
    *,
    dag: object,
    flow_graph: object,
    modifications: list[object],
    indexes: _DagIndexes,
    frontier_blocks: set[int],
) -> set[RedirectKey]:
    override_keys: set[RedirectKey] = set()
    for idx, mod in enumerate(modifications):
        info = _redirect_info(mod)
        if info is None:
            continue
        source, old_target, new_target = info
        if int(old_target) not in frontier_blocks:
            continue
        if not _is_dag_proven_redirect(
            indexes,
            source=source,
            old_target=old_target,
            new_target=new_target,
        ):
            continue
        without = [m for pos, m in enumerate(modifications) if pos != idx]
        projected_without = _project(flow_graph, without)
        leaks = _find_semantic_scc_leaks(projected_without, indexes)
        if any(
            _path_contains_edge(leak.path, source, old_target)
            or _leak_scc_contains_edge(
                projected_without,
                leak,
                source,
                old_target,
            )
            for leak in leaks
        ):
            override_keys.add((int(source), int(old_target), int(new_target)))
    return override_keys


def _is_dag_proven_redirect(
    indexes: _DagIndexes,
    *,
    source: int,
    old_target: int,
    new_target: int,
) -> bool:
    for anchor_key, choices in indexes.choices_by_anchor.items():
        anchor_source, _arm = anchor_key
        if int(anchor_source) != int(source):
            continue
        if any(int(choice.target_block) == int(new_target) for choice in choices):
            return True
    return False


def _path_contains_edge(path: tuple[int, ...], source: int, target: int) -> bool:
    return any(
        int(left) == int(source) and int(right) == int(target)
        for left, right in zip(path, path[1:])
    )


def _leak_scc_contains_edge(
    flow_graph: object,
    leak: SemanticSccLeak,
    source: int,
    target: int,
) -> bool:
    if int(source) not in leak.cfg_scc_blocks or int(target) not in leak.cfg_scc_blocks:
        return False
    block = flow_graph.get_block(int(source))
    if block is None:
        return False
    return int(target) in {
        int(succ) for succ in (getattr(block, "succs", ()) or ())
    }


def _redirect_info(mod: object) -> tuple[int, int, int] | None:
    if isinstance(mod, RedirectGoto):
        return (int(mod.from_serial), int(mod.old_target), int(mod.new_target))
    if isinstance(mod, RedirectBranch):
        return (int(mod.from_serial), int(mod.old_target), int(mod.new_target))
    return None


def _insert_info(mod: object) -> tuple[int, int, int] | None:
    if not isinstance(mod, InsertBlock):
        return None
    old_target = mod.old_target_serial
    if old_target is None:
        old_target = mod.succ_serial
    return (int(mod.pred_serial), int(old_target), int(mod.succ_serial))


def _duplicate_info(mod: object) -> tuple[int, int] | None:
    if not isinstance(mod, DuplicateBlock):
        return None
    if mod.pred_serial is None:
        return None
    return (int(mod.source_block), int(mod.pred_serial))


def _conditional_redirect_info(mod: object) -> tuple[int, int] | None:
    if not isinstance(mod, CreateConditionalRedirect):
        return None
    return (int(mod.source_block), int(mod.ref_block))


def _mod_summary(mod: object) -> str:
    info = _redirect_info(mod)
    if info is None:
        insert_info = _insert_info(mod)
        if insert_info is not None:
            source, old_target, new_target = insert_info
            return f"InsertBlock(blk[{source}] {old_target}->new->{new_target})"
        duplicate_info = _duplicate_info(mod)
        if duplicate_info is not None:
            source, pred = duplicate_info
            return f"DuplicateBlock(blk[{source}] pred=blk[{pred}])"
        conditional_info = _conditional_redirect_info(mod)
        if conditional_info is not None:
            source, ref = conditional_info
            return f"CreateConditionalRedirect(blk[{source}] ref=blk[{ref}])"
        return type(mod).__name__
    source, old_target, new_target = info
    return f"{type(mod).__name__}(blk[{source}] {old_target}->{new_target})"


def _modification_signature(
    modifications: list[object],
) -> tuple[tuple[object, ...] | str, ...]:
    signature: list[tuple[object, ...] | str] = []
    for mod in modifications:
        info = _redirect_info(mod)
        if info is not None:
            signature.append(info)
            continue
        insert_info = _insert_info(mod)
        if insert_info is not None:
            signature.append(
                (
                    "InsertBlock",
                    insert_info[0],
                    insert_info[1],
                    insert_info[2],
                )
            )
            continue
        duplicate_info = _duplicate_info(mod)
        if duplicate_info is not None:
            signature.append(("DuplicateBlock", duplicate_info[0], duplicate_info[1]))
            continue
        conditional_info = _conditional_redirect_info(mod)
        if conditional_info is not None:
            signature.append(
                (
                    "CreateConditionalRedirect",
                    conditional_info[0],
                    conditional_info[1],
                )
            )
            continue
        signature.append(type(mod).__name__)
    return tuple(signature)


__all__ = [
    "FrontierClosureResult",
    "FrontierClosureDiagnosticRow",
    "RedirectKey",
    "ResolvedFrontier",
    "SemanticSccLeak",
    "UnresolvedFrontier",
    "plan_dag_authoritative_frontier_closure",
]
