"""Pure residual handoff discovery helpers.

These helpers answer semantic target-resolution questions for residual
dispatcher handoffs without choosing or applying any lowering policy.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.flowgraph import InsnKind, OperandKind
from d810.backends.hexrays.evidence.bst_analysis import _forward_eval_insn
from d810.recon.flow.dag_index import build_dag_node_maps
from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateNodeKind,
)

_MOVE_OPCODE = 4
_NUMBER_OPERAND = 2
_STACK_OPERAND = 5


@dataclass(frozen=True, slots=True)
class ResidualSourceHandoffFacts:
    """Pure discovery facts for one residual dispatcher source block."""

    source_block: int
    current_preds: tuple[int, ...]
    source_has_state_write: bool
    assignment_map_handoff: tuple[int, int] | None
    projected_snapshot_handoff: tuple[int, int] | None
    immediate_handoff: tuple[int, int] | None
    synthesized_handoff: tuple[int, int] | None
    live_immediate_handoff: tuple[int, int] | None
    live_synthesized_handoff: tuple[int, int] | None
    successor_handoff: tuple[int, int] | None
    live_successor_handoff: tuple[int, int] | None
    source_level_handoff: tuple[int, int] | None
    projected_path_handoff: tuple[int, int] | None
    handoff: tuple[int, int] | None


@dataclass(frozen=True, slots=True)
class EffectiveTargetEntryResolution:
    """Pure discovery result for one residual redirect target."""

    source_block: int
    target_entry: int | None
    normalized_nonexact_target: int | None
    immediate_handoff: tuple[int, int] | None
    synthesized_handoff: tuple[int, int] | None


def dispatcher_has_exact_state_row(
    state_value: int | None,
    *,
    dispatcher: object | None = None,
) -> bool:
    """Return whether ``dispatcher`` has an exact one-state row for ``state_value``."""
    if state_value is None or dispatcher is None:
        return False

    rows = getattr(dispatcher, "_rows", None)
    if not rows:
        return False

    for row in rows:
        lo = getattr(row, "lo", None)
        hi = getattr(row, "hi", None)
        if lo is None or hi is None:
            continue
        lo = int(lo) & 0xFFFFFFFF
        hi = int(hi) & 0xFFFFFFFF
        if lo > state_value:
            break
        if lo == state_value and hi - lo == 1:
            return True
    return False


def dispatcher_exact_state_target(
    state_value: int | None,
    *,
    dispatcher: object | None = None,
) -> int | None:
    """Return the dispatch target for an exact one-state row, if any."""
    if state_value is None or dispatcher is None:
        return None

    rows = getattr(dispatcher, "_rows", None)
    if not rows:
        return None

    for row in rows:
        lo = getattr(row, "lo", None)
        hi = getattr(row, "hi", None)
        if lo is None or hi is None:
            continue
        lo = int(lo) & 0xFFFFFFFF
        hi = int(hi) & 0xFFFFFFFF
        if lo > state_value:
            break
        if lo == state_value and hi - lo == 1:
            return int(getattr(row, "target", 0))
    return None


def supplemental_selected_entry_for_state(
    dag: LinearizedStateDag,
    state_value: int | None,
) -> int | None:
    """Return a DAG-selected supplemental semantic entry for ``state_value``."""
    if state_value is None:
        return None
    raw_value = int(state_value) & 0xFFFFFFFF
    for candidate_state, anchor in getattr(dag, "supplemental_selected_entries", ()) or ():
        if (int(candidate_state) & 0xFFFFFFFF) == raw_value:
            return int(anchor)
    return None


def is_transient_corridor_entry(
    dag: LinearizedStateDag,
    block_serial: int,
) -> bool:
    """Return whether ``block_serial`` is a transient corridor entry in the DAG."""
    transient_entries = getattr(dag, "transient_entry_blocks", ()) or ()
    return int(block_serial) in {int(block) for block in transient_entries}


def has_live_exact_residual_handoff(
    mba: object,
    residual_preds: tuple[int, ...],
    *,
    state_var_stkoff: int | None,
    dispatcher: object | None,
    resolve_state_via_valranges: object | None = None,
) -> bool:
    """Return whether any residual predecessor already writes an exact dispatcher row."""
    if mba is None or dispatcher is None or state_var_stkoff is None:
        return False

    for block_serial in residual_preds:
        state_value = resolve_singleton_state_write_value(
            mba,
            int(block_serial),
            state_var_stkoff=state_var_stkoff,
            resolve_state_via_valranges=resolve_state_via_valranges,
        )
        if state_value is None:
            continue
        if not dispatcher_has_exact_state_row(state_value, dispatcher=dispatcher):
            continue
        target = dispatcher_exact_state_target(state_value, dispatcher=dispatcher)
        if target is None or int(target) == int(block_serial):
            continue
        return True
    return False


def resolve_path_lead_entry_from_node(
    dag: LinearizedStateDag,
    node: StateDagNode,
    *,
    bst_node_blocks: set[int],
) -> int | None:
    """Return a unique non-BST path lead for ``node``, if one exists."""
    outgoing_paths = tuple(
        edge.ordered_path
        for edge in dag.edges
        if edge.source_key == node.key and edge.ordered_path
    )
    if not outgoing_paths:
        return None

    blocks_on_outgoing_paths = {
        block_serial
        for path in outgoing_paths
        for block_serial in path
    }
    if node.entry_anchor in blocks_on_outgoing_paths:
        return None

    path_starts = sorted(
        {
            path[0]
            for path in outgoing_paths
            if path[0] not in bst_node_blocks
        }
    )
    if len(path_starts) != 1:
        return None
    return path_starts[0]


def resolve_redirect_safe_entry_from_node(
    node: StateDagNode,
    *,
    dag: LinearizedStateDag | None = None,
    bst_node_blocks: set[int],
) -> int | None:
    """Return a non-BST entry representative for ``node``."""
    if dag is not None:
        path_lead_entry = resolve_path_lead_entry_from_node(
            dag,
            node,
            bst_node_blocks=bst_node_blocks,
        )
        if path_lead_entry is not None:
            return path_lead_entry
    candidates = (
        node.entry_anchor,
        *node.exclusive_blocks,
        *node.owned_blocks,
    )
    for block_serial in candidates:
        if block_serial not in bst_node_blocks:
            return block_serial
    return node.entry_anchor if node.entry_anchor not in bst_node_blocks else None


def resolve_redirect_safe_target_entry(
    dag: LinearizedStateDag,
    edge: StateDagEdge,
    *,
    bst_node_blocks: set[int],
) -> int | None:
    """Return the semantic redirect-safe entry for one residual handoff edge."""
    target_entry = edge.target_entry_anchor
    explicit_target_entry = (
        target_entry
        if target_entry is not None and target_entry not in bst_node_blocks
        else None
    )
    target_node = (
        build_dag_node_maps(dag).node_by_key.get(edge.target_key)
        if edge.target_key is not None
        else None
    )
    labeled_entry = None
    if edge.target_label:
        labeled_matches = [
            node for node in dag.nodes if node.state_label == edge.target_label
        ]
        if len(labeled_matches) == 1:
            labeled_entry = resolve_redirect_safe_entry_from_node(
                labeled_matches[0],
                dag=dag,
                bst_node_blocks=bst_node_blocks,
            )
    if (
        labeled_entry is not None
        and edge.target_label
        and edge.target_label.endswith("_fallback")
    ):
        return labeled_entry
    if target_node is not None:
        safe_target_entry = resolve_redirect_safe_entry_from_node(
            target_node,
            dag=dag,
            bst_node_blocks=bst_node_blocks,
        )
        if (
            explicit_target_entry is not None
            and safe_target_entry is not None
            and explicit_target_entry != safe_target_entry
        ):
            if explicit_target_entry in edge.ordered_path:
                return safe_target_entry
            return explicit_target_entry
        if safe_target_entry is not None:
            return safe_target_entry
    if labeled_entry is not None:
        return labeled_entry
    if explicit_target_entry is None:
        return None
    return explicit_target_entry


def resolve_dag_entry_for_state(
    dag: LinearizedStateDag,
    state_value: int | None,
    *,
    bst_node_blocks: set[int] | None = None,
) -> int | None:
    """Resolve the best semantic entry for ``state_value``."""
    if state_value is None:
        return None
    for node in dag.nodes:
        if node.key.state_const == state_value:
            return resolve_redirect_safe_entry_from_node(
                node,
                dag=dag,
                bst_node_blocks=bst_node_blocks or set(),
            )
    for node in dag.nodes:
        lo = node.key.range_lo
        hi = node.key.range_hi
        if lo is None or hi is None:
            continue
        if lo <= state_value <= hi:
            return resolve_redirect_safe_entry_from_node(
                node,
                dag=dag,
                bst_node_blocks=bst_node_blocks or set(),
            )
    return None


def state_has_semantic_support(
    dag: LinearizedStateDag,
    state_value: int | None,
) -> bool:
    """Return whether ``state_value`` appears in any semantic edge."""
    if state_value is None:
        return False
    raw_value = state_value & 0xFFFFFFFF
    for edge in dag.edges:
        if edge.target_state is not None and (edge.target_state & 0xFFFFFFFF) == raw_value:
            return True
        if (
            edge.source_key.state_const is not None
            and (edge.source_key.state_const & 0xFFFFFFFF) == raw_value
        ):
            return True
    return False


def is_raw_state_label(label: str, state_value: int) -> bool:
    """Return whether ``label`` is the raw hex label for ``state_value``."""
    if label.endswith("_fallback"):
        return False
    try:
        return int(label, 16) == (state_value & 0xFFFFFFFF)
    except Exception:
        return False


def resolve_nonlocal_state_entry(
    dag: LinearizedStateDag,
    state_value: int | None,
    *,
    forbidden_blocks: set[int],
    bst_node_blocks: set[int],
) -> int | None:
    """Resolve a semantic entry for ``state_value`` that avoids ``forbidden_blocks``."""
    if state_value is None:
        return None
    raw_value = state_value & 0xFFFFFFFF

    best_score: tuple[int, int, int, int] | None = None
    best_entry: int | None = None
    for node in dag.nodes:
        matches_exact = node.key.state_const == raw_value
        matches_range = (
            node.key.range_lo is not None
            and node.key.range_hi is not None
            and node.key.range_lo <= raw_value <= node.key.range_hi
        )
        if not (matches_exact or matches_range):
            continue
        entry = resolve_redirect_safe_entry_from_node(
            node,
            dag=dag,
            bst_node_blocks=bst_node_blocks,
        )
        if entry is None or entry in forbidden_blocks:
            continue
        score = (
            1 if matches_exact else 0,
            1 if node.kind == StateNodeKind.EXACT else 0,
            1 if entry in node.exclusive_blocks else 0,
            1 if not is_raw_state_label(node.state_label, raw_value) else 0,
        )
        if best_score is None or score > best_score:
            best_score = score
            best_entry = entry
    return best_entry


def resolve_contextual_dag_entry_for_state(
    dag: LinearizedStateDag,
    state_value: int | None,
    *,
    source_block: int,
    bst_node_blocks: set[int],
) -> int | None:
    """Resolve the best semantic entry for ``state_value`` relative to ``source_block``."""
    if state_value is None:
        return None

    best_match: tuple[int, int, int] | None = None
    best_entry: int | None = None
    for edge in dag.edges:
        if edge.target_state is None or (edge.target_state & 0xFFFFFFFF) != state_value:
            continue
        target_entry = resolve_redirect_safe_target_entry(
            dag,
            edge,
            bst_node_blocks=bst_node_blocks,
        )
        if target_entry is None or target_entry == source_block:
            continue

        on_path = source_block in edge.ordered_path
        source_match = edge.source_anchor.block_serial == source_block
        if not on_path and not source_match:
            continue

        path_index = edge.ordered_path.index(source_block) if on_path else -1
        if on_path and target_entry in edge.ordered_path:
            nonlocal_entry = resolve_nonlocal_state_entry(
                dag,
                state_value,
                forbidden_blocks=set(edge.ordered_path),
                bst_node_blocks=bst_node_blocks,
            )
            if nonlocal_entry is not None:
                target_entry = nonlocal_entry
        is_path_tail = 1 if edge.ordered_path and edge.ordered_path[-1] == source_block else 0
        score = (
            is_path_tail,
            1 if source_match else 0,
            path_index,
        )
        if best_match is None or score > best_match:
            best_match = score
            best_entry = target_entry

    return best_entry


def resolve_normalized_alias_entry_for_state(
    dag: LinearizedStateDag,
    state_value: int | None,
    *,
    source_block: int | None,
    bst_node_blocks: set[int],
) -> int | None:
    """Resolve a non-raw alias entry for ``state_value``."""
    if state_value is None:
        return None

    raw_value = state_value & 0xFFFFFFFF
    node_by_key = {}
    for node in dag.nodes:
        key = getattr(node, "key", None)
        try:
            hash(key)
        except Exception:
            continue
        node_by_key[key] = node
    best_match: tuple[int, int, int, int, int] | None = None
    best_entry: int | None = None

    for node in dag.nodes:
        if node.key.state_const != raw_value:
            continue
        entry = resolve_redirect_safe_entry_from_node(
            node,
            dag=dag,
            bst_node_blocks=bst_node_blocks,
        )
        if entry is None or entry == source_block:
            continue
        raw_exact_node = (
            node.kind == StateNodeKind.EXACT
            and node.key.state_const == raw_value
            and is_raw_state_label(node.state_label, raw_value)
        )
        if is_raw_state_label(node.state_label, raw_value) and not raw_exact_node:
            continue
        score = (
            2 if raw_exact_node else 0,
            1 if node.state_label.endswith("_fallback") else 0,
            1 if entry in node.exclusive_blocks else 0,
            1 if entry in node.owned_blocks else 0,
            -entry,
        )
        if best_match is None or score > best_match:
            best_match = score
            best_entry = entry

    for edge in dag.edges:
        if edge.target_state is None or (edge.target_state & 0xFFFFFFFF) != raw_value:
            continue
        target_entry = resolve_redirect_safe_target_entry(
            dag,
            edge,
            bst_node_blocks=bst_node_blocks,
        )
        if target_entry is None:
            continue
        target_node = node_by_key.get(edge.target_key) if edge.target_key is not None else None
        raw_exact_target = (
            target_node is not None
            and target_node.kind == StateNodeKind.EXACT
            and target_node.key.state_const == raw_value
            and target_entry == target_node.entry_anchor
            and is_raw_state_label(edge.target_label or "", raw_value)
        )
        if is_raw_state_label(edge.target_label, raw_value) and not raw_exact_target:
            continue
        on_path = source_block is not None and source_block in edge.ordered_path
        source_match = (
            source_block is not None and edge.source_anchor.block_serial == source_block
        )
        score = (
            2 if raw_exact_target else 0,
            2 if edge.target_label.endswith("_fallback") else 0,
            1 if on_path else 0,
            1 if source_match else 0,
            len(edge.ordered_path),
        )
        if best_match is None or score > best_match:
            best_match = score
            best_entry = target_entry

    if best_entry is not None and best_entry == source_block:
        return None
    return best_entry


def resolve_owner_semantic_entry_for_blocks(
    dag: LinearizedStateDag,
    *,
    anchor_candidates: tuple[int, ...],
    source_block: int,
    bst_node_blocks: set[int],
) -> int | None:
    """Resolve the owner semantic entry for concrete CFG anchor candidates."""
    if not anchor_candidates:
        return None

    def _owns_candidate(node: StateDagNode, block_serial: int) -> bool:
        if block_serial == node.entry_anchor or block_serial in node.owned_blocks:
            return True
        return any(block_serial in segment.blocks for segment in node.local_segments)

    owners = [
        node
        for node in dag.nodes
        if node.kind == StateNodeKind.EXACT
        and node.key.state_const is not None
        and any(_owns_candidate(node, block_serial) for block_serial in anchor_candidates)
    ]
    if not owners:
        return None

    min_anchor = min(anchor_candidates)
    owners.sort(
        key=lambda node: (
            0 if any(block in node.exclusive_blocks for block in anchor_candidates) else 1,
            0 if any(block == node.entry_anchor for block in anchor_candidates) else 1,
            abs(node.entry_anchor - min_anchor),
        )
    )
    for owner in owners:
        entry = resolve_redirect_safe_entry_from_node(
            owner,
            dag=dag,
            bst_node_blocks=bst_node_blocks,
        )
        if entry is not None and entry != source_block:
            return entry
    return None


def resolve_owner_family_fallback_entry(
    dag: LinearizedStateDag,
    *,
    via_pred: int,
    source_block: int,
    bst_node_blocks: set[int],
) -> int | None:
    """Resolve a family fallback entry for a via-pred loopback alias."""
    def _owns_candidate(node: StateDagNode, block_serial: int) -> bool:
        if block_serial == node.entry_anchor or block_serial in node.owned_blocks:
            return True
        return any(block_serial in segment.blocks for segment in node.local_segments)

    owners = [
        node
        for node in dag.nodes
        if node.kind == StateNodeKind.EXACT
        and node.key.state_const is not None
        and _owns_candidate(node, via_pred)
    ]
    if not owners:
        return None

    owner_candidates: list[tuple[tuple[int, int, int], StateDagNode, int]] = []
    for node in owners:
        entry = resolve_redirect_safe_entry_from_node(
            node,
            dag=dag,
            bst_node_blocks=bst_node_blocks,
        )
        if entry is None:
            continue
        owner_candidates.append(
            (
                (
                    0 if via_pred == entry else 1,
                    0 if via_pred in node.exclusive_blocks else 1,
                    abs(entry - via_pred),
                ),
                node,
                entry,
            )
        )
    if not owner_candidates:
        return None
    owner_candidates.sort(key=lambda item: item[0])
    _, owner, _owner_entry = owner_candidates[0]
    base_state = owner.key.state_const & 0xFFFFFFFF
    fallback_label = f"0x{base_state:08X}_fallback"
    fallback_nodes: list[tuple[tuple[int, int], int]] = []
    for node in dag.nodes:
        if node.state_label != fallback_label:
            continue
        entry = resolve_redirect_safe_entry_from_node(
            node,
            dag=dag,
            bst_node_blocks=bst_node_blocks,
        )
        if entry is None or entry in {source_block, via_pred}:
            continue
        fallback_nodes.append(
            (
                (
                    0 if entry > via_pred else 1,
                    abs(entry - via_pred),
                ),
                entry,
            )
        )
    if not fallback_nodes:
        return None

    fallback_nodes.sort(key=lambda item: item[0])
    return fallback_nodes[0][1]


def resolve_cover_fallback_entry_for_state(
    dag: LinearizedStateDag,
    state_value: int | None,
    *,
    source_block: int,
    bst_node_blocks: set[int],
    dispatcher: object | None = None,
) -> int | None:
    """Resolve the nearest non-exact cover fallback for ``state_value``."""
    if state_value is None:
        return None

    cover_state: int | None = None
    cover_interval_target: int | None = None
    rows = getattr(dispatcher, "_rows", None) if dispatcher is not None else None
    if rows:
        previous_exact_row = None
        for row in rows:
            lo = getattr(row, "lo", None)
            hi = getattr(row, "hi", None)
            if lo is None or hi is None:
                continue
            lo = int(lo) & 0xFFFFFFFF
            hi = int(hi) & 0xFFFFFFFF
            if hi - lo == 1:
                if lo <= state_value:
                    previous_exact_row = row
            if lo <= state_value < hi:
                if previous_exact_row is not None:
                    cover_state = int(getattr(previous_exact_row, "lo", 0)) & 0xFFFFFFFF
                cover_interval_target = int(getattr(row, "target", 0))
                break
            if lo >= state_value:
                break
        if cover_state is None and previous_exact_row is not None:
            cover_state = int(getattr(previous_exact_row, "lo", 0)) & 0xFFFFFFFF

    candidate_states: list[int] = []
    if cover_state is not None:
        candidate_states.append(cover_state)

    for candidate_state in candidate_states:
        exact_entry = resolve_dag_entry_for_state(
            dag,
            candidate_state,
            bst_node_blocks=bst_node_blocks,
        )
        if exact_entry is not None and exact_entry != source_block:
            return exact_entry

    fallback_states_from_dag = sorted(
        {
            int(node.state_label.split("_fallback", 1)[0], 16)
            for node in dag.nodes
            if node.state_label.startswith("0x")
            and node.state_label.endswith("_fallback")
            and resolve_redirect_safe_entry_from_node(
                node,
                dag=dag,
                bst_node_blocks=bst_node_blocks,
            )
            not in {None, source_block}
            and int(node.state_label.split("_fallback", 1)[0], 16) < state_value
        },
        reverse=True,
    )
    candidate_states.extend(
        state for state in fallback_states_from_dag if state not in candidate_states
    )

    for candidate_state in candidate_states:
        fallback_label = f"0x{candidate_state:08X}_fallback"
        candidates = sorted(
            {
                entry
                for node in dag.nodes
                for entry in (
                    resolve_redirect_safe_entry_from_node(
                        node,
                        dag=dag,
                        bst_node_blocks=bst_node_blocks,
                    ),
                )
                if (
                    node.state_label == fallback_label
                    and entry is not None
                    and entry != source_block
                )
            }
        )
        if candidates:
            return candidates[0]
    semantic_cover_target = resolve_owner_semantic_entry_for_blocks(
        dag,
        anchor_candidates=(cover_interval_target,) if cover_interval_target is not None else (),
        source_block=source_block,
        bst_node_blocks=bst_node_blocks,
    )
    if semantic_cover_target is not None:
        return semantic_cover_target
    if (
        cover_interval_target is not None
        and cover_interval_target not in bst_node_blocks
        and cover_interval_target != source_block
    ):
        return cover_interval_target
    return None


def resolve_loopback_alias_fallback_entry(
    dag: LinearizedStateDag,
    state_value: int,
    *,
    source_block: int,
    via_pred: int | None,
    bst_node_blocks: set[int],
    dispatcher: object | None,
) -> int | None:
    """Resolve a nonlocal fallback when a loopback alias would self-target."""
    if via_pred is None:
        return None

    family_fallback = resolve_owner_family_fallback_entry(
        dag,
        via_pred=via_pred,
        source_block=source_block,
        bst_node_blocks=bst_node_blocks,
    )
    if family_fallback is not None:
        return family_fallback

    cover_fallback = resolve_cover_fallback_entry_for_state(
        dag,
        state_value,
        source_block=via_pred,
        bst_node_blocks=bst_node_blocks,
        dispatcher=dispatcher,
    )
    if cover_fallback is not None and cover_fallback not in {source_block, via_pred}:
        return cover_fallback

    lookup_callable = getattr(dispatcher, "lookup", None) if dispatcher is not None else None
    if callable(lookup_callable) and not dispatcher_has_exact_state_row(
        state_value,
        dispatcher=dispatcher,
    ):
        try:
            resolved = lookup_callable(state_value)
        except Exception:
            resolved = None
        if (
            resolved is not None
            and int(resolved) not in bst_node_blocks
            and int(resolved) not in {source_block, via_pred}
        ):
            return int(resolved)
    return None


def resolve_nonexact_dispatch_target(
    dag: LinearizedStateDag,
    state_value: int | None,
    *,
    source_block: int,
    bst_node_blocks: set[int],
    dispatcher: object | None,
    dispatcher_lookup: object | None = None,
) -> int | None:
    """Resolve a semantic target for a non-exact dispatcher state."""
    if state_value is None:
        return None
    if dispatcher_has_exact_state_row(state_value, dispatcher=dispatcher):
        return None

    lookup_callable = getattr(dispatcher, "lookup", None) if dispatcher is not None else None
    if lookup_callable is None and callable(dispatcher_lookup):
        lookup_callable = dispatcher_lookup
    if callable(lookup_callable):
        try:
            resolved = lookup_callable(state_value)
        except Exception:
            resolved = None
        semantic_resolved = resolve_owner_semantic_entry_for_blocks(
            dag,
            anchor_candidates=(int(resolved),) if resolved is not None else (),
            source_block=source_block,
            bst_node_blocks=bst_node_blocks,
        )
        if semantic_resolved is not None:
            return semantic_resolved
        if (
            resolved is not None
            and int(resolved) not in bst_node_blocks
            and int(resolved) != source_block
        ):
            return int(resolved)

    normalized_alias_target = resolve_normalized_alias_entry_for_state(
        dag,
        state_value,
        source_block=source_block,
        bst_node_blocks=bst_node_blocks,
    )
    if normalized_alias_target is not None:
        return normalized_alias_target

    cover_fallback_entry = resolve_cover_fallback_entry_for_state(
        dag,
        state_value,
        source_block=source_block,
        bst_node_blocks=bst_node_blocks,
        dispatcher=dispatcher,
    )
    if cover_fallback_entry is not None and cover_fallback_entry != source_block:
        return cover_fallback_entry
    return None


def resolve_projected_path_tail_target(
    dag: LinearizedStateDag,
    *,
    source_block: int,
    bst_node_blocks: set[int],
    dispatcher: object | None = None,
    predecessor_hints: tuple[int, ...] | None = None,
    require_predecessor_match: bool = False,
) -> tuple[int | None, int] | None:
    """Resolve the best semantic tail target reachable from ``source_block``."""
    best_match: tuple[int, int, int, int] | None = None
    best_target: tuple[int | None, int] | None = None
    matched_targets: set[tuple[int | None, int]] = set()
    pred_hints = tuple(int(pred) for pred in predecessor_hints or ())

    for edge in dag.edges:
        if edge.kind not in (
            SemanticEdgeKind.TRANSITION,
            SemanticEdgeKind.CONDITIONAL_TRANSITION,
        ):
            continue
        if not edge.ordered_path or source_block not in edge.ordered_path:
            continue
        target_entry = resolve_redirect_safe_target_entry(
            dag,
            edge,
            bst_node_blocks=bst_node_blocks,
        )
        if target_entry is None or target_entry == source_block:
            continue
        if edge.target_state is not None and edge.target_key is None:
            nonexact_target = resolve_nonexact_dispatch_target(
                dag,
                edge.target_state,
                source_block=source_block,
                bst_node_blocks=bst_node_blocks,
                dispatcher=dispatcher,
                dispatcher_lookup=(getattr(dispatcher, "lookup", None) if dispatcher is not None else None),
            )
            if nonexact_target is not None and nonexact_target != source_block:
                target_entry = nonexact_target

        path_index = edge.ordered_path.index(source_block)
        if target_entry in edge.ordered_path:
            nonlocal_entry = resolve_nonlocal_state_entry(
                dag,
                edge.target_state,
                forbidden_blocks=set(edge.ordered_path),
                bst_node_blocks=bst_node_blocks,
            )
            if nonlocal_entry is not None:
                target_entry = nonlocal_entry
        path_pred = int(edge.ordered_path[path_index - 1]) if path_index > 0 else None
        if (
            edge.target_state is not None
            and path_pred is not None
            and target_entry == path_pred
            and not dispatcher_has_exact_state_row(
                edge.target_state,
                dispatcher=dispatcher,
            )
        ):
            fallback_target = resolve_loopback_alias_fallback_entry(
                dag,
                edge.target_state,
                source_block=source_block,
                via_pred=path_pred,
                bst_node_blocks=bst_node_blocks,
                dispatcher=dispatcher,
            )
            if fallback_target is not None:
                target_entry = fallback_target
        pred_match = 1 if pred_hints and path_pred is not None and path_pred in pred_hints else 0
        if pred_hints:
            if path_pred is None:
                continue
            if require_predecessor_match and not pred_match:
                continue
            if not require_predecessor_match and not pred_match:
                continue

        is_path_tail = 1 if path_index + 1 == len(edge.ordered_path) else 0
        is_source_anchor = 1 if edge.source_anchor.block_serial == source_block else 0
        score = (
            pred_match,
            is_path_tail,
            is_source_anchor,
            len(edge.ordered_path),
            -path_index,
        )
        if pred_match:
            matched_targets.add((edge.target_state, target_entry))
        if best_match is None or score > best_match:
            best_match = score
            best_target = (edge.target_state, target_entry)

    if pred_hints and len(matched_targets) > 1:
        return None
    return best_target


def _is_immediate_conditional_leaf_tail_for_state(
    dag: LinearizedStateDag,
    *,
    source_block: int,
    state_value: int,
    predecessor_hints: tuple[int, ...],
) -> bool:
    raw_value = int(state_value) & 0xFFFFFFFF
    pred_hints = tuple(int(pred) for pred in predecessor_hints)
    for edge in dag.edges:
        if edge.kind != SemanticEdgeKind.CONDITIONAL_TRANSITION:
            continue
        if edge.target_state is None or (int(edge.target_state) & 0xFFFFFFFF) != raw_value:
            continue
        if source_block not in edge.ordered_path:
            continue
        path_index = edge.ordered_path.index(source_block)
        if path_index <= 0 or path_index != len(edge.ordered_path) - 1:
            continue
        if edge.source_anchor.kind.name != "CONDITIONAL_BRANCH":
            continue
        try:
            branch_index = edge.ordered_path.index(edge.source_anchor.block_serial)
        except ValueError:
            continue
        if path_index != branch_index + 1:
            continue
        path_pred = int(edge.ordered_path[path_index - 1])
        if pred_hints and path_pred not in pred_hints:
            continue
        return True
    return False


def iter_residual_prefix_handoffs(
    dag: LinearizedStateDag,
    *,
    source_block: int,
    bst_node_blocks: set[int],
    dispatcher: object | None = None,
) -> list[tuple[StateDagEdge, int, int]]:
    """Enumerate prefix handoff candidates for one residual dispatcher feeder."""
    candidates: list[tuple[tuple[int, int, int, int, int, int], StateDagEdge, int, int]] = []
    for edge in dag.edges:
        if edge.kind not in (
            SemanticEdgeKind.TRANSITION,
            SemanticEdgeKind.CONDITIONAL_TRANSITION,
        ):
            continue
        if not edge.ordered_path or source_block not in edge.ordered_path:
            continue
        path_index = edge.ordered_path.index(source_block)
        if path_index <= 0:
            continue
        via_pred = edge.ordered_path[path_index - 1]
        target_entry = resolve_redirect_safe_target_entry(
            dag,
            edge,
            bst_node_blocks=bst_node_blocks,
        )
        if target_entry is None:
            continue
        if edge.target_state is not None and edge.target_key is None:
            nonexact_target = resolve_nonexact_dispatch_target(
                dag,
                edge.target_state,
                source_block=via_pred,
                bst_node_blocks=bst_node_blocks,
                dispatcher=dispatcher,
                dispatcher_lookup=(getattr(dispatcher, "lookup", None) if dispatcher is not None else None),
            )
            if nonexact_target is not None:
                target_entry = nonexact_target
        if target_entry in bst_node_blocks:
            continue
        if target_entry in {source_block, via_pred}:
            continue
        score = (
            1 if path_index + 1 == len(edge.ordered_path) else 0,
            1 if edge.source_anchor.block_serial == via_pred else 0,
            len(edge.ordered_path),
            -path_index,
            via_pred,
            target_entry,
        )
        candidates.append((score, edge, via_pred, target_entry))
    candidates.sort(key=lambda item: item[0], reverse=True)
    return [(edge, via_pred, target_entry) for _, edge, via_pred, target_entry in candidates]


def iter_live_block_insns(block: object):
    """Yield live mblock instructions with a defensive loop bound."""
    insn = getattr(block, "head", None)
    seen = 0
    while insn is not None and seen < 4096:
        yield insn
        insn = getattr(insn, "next", None)
        seen += 1


def iter_live_block_succs(block: object) -> tuple[int, ...]:
    """Return block successors from a live mblock-like object."""
    succset = getattr(block, "succset", None)
    if succset is not None:
        return tuple(int(succ) for succ in succset)
    succs = getattr(block, "succs", None)
    if succs is not None:
        return tuple(int(succ) for succ in succs)
    nsucc = getattr(block, "nsucc", None)
    succ = getattr(block, "succ", None)
    if callable(nsucc) and callable(succ):
        try:
            return tuple(int(succ(i)) for i in range(int(nsucc())))
        except Exception:
            return ()
    return ()


def mop_stkoff(mop: object | None) -> int | None:
    """Extract a stack offset from a live or snapshotted mop-like object."""
    if mop is None:
        return None
    stack_ref = getattr(mop, "s", None)
    if stack_ref is not None:
        off = getattr(stack_ref, "off", None)
        if callable(off):
            try:
                off = off()
            except Exception:
                off = None
        if off is not None:
            return int(off)
    stkoff = getattr(mop, "stkoff", None)
    if callable(stkoff):
        try:
            stkoff = stkoff()
        except Exception:
            stkoff = None
    if stkoff is not None:
        return int(stkoff)
    return None


def mop_const_value(mop: object | None) -> int | None:
    """Extract an integer literal from a live or snapshotted mop-like object."""
    if mop is None:
        return None
    nnn = getattr(mop, "nnn", None)
    if nnn is not None:
        value = getattr(nnn, "value", None)
        if callable(value):
            try:
                value = value()
            except Exception:
                value = None
        if value is not None:
            return int(value)
    value = getattr(mop, "value", None)
    if callable(value):
        try:
            value = value()
        except Exception:
            value = None
    if value is not None:
        return int(value)
    return None


def _kind_matches(
    value: object,
    legacy_name: str,
    numeric_value: int,
    portable_kind: object,
) -> bool:
    if value == portable_kind:
        return True
    portable_value = getattr(portable_kind, "value", portable_kind)
    if isinstance(portable_value, str) and value == portable_value:
        return True
    if value == legacy_name or str(value) == legacy_name:
        return True
    try:
        return int(value) == int(numeric_value)
    except Exception:
        return False


def _is_move_insn(insn: object) -> bool:
    kind = getattr(insn, "kind", None)
    if _kind_matches(kind, "m_mov", _MOVE_OPCODE, InsnKind.MOV):
        return True
    return _kind_matches(
        getattr(insn, "opcode", None),
        "m_mov",
        _MOVE_OPCODE,
        InsnKind.MOV,
    )


def _is_stack_operand(mop: object | None) -> bool:
    if mop is None:
        return False
    kind = getattr(mop, "kind", None)
    if _kind_matches(kind, "mop_S", _STACK_OPERAND, OperandKind.STACK):
        return True
    return _kind_matches(
        getattr(mop, "t", None),
        "mop_S",
        _STACK_OPERAND,
        OperandKind.STACK,
    )


def _is_number_operand(mop: object | None) -> bool:
    if mop is None:
        return False
    kind = getattr(mop, "kind", None)
    if _kind_matches(kind, "mop_n", _NUMBER_OPERAND, OperandKind.NUMBER):
        return True
    return _kind_matches(
        getattr(mop, "t", None),
        "mop_n",
        _NUMBER_OPERAND,
        OperandKind.NUMBER,
    )


def is_state_var_dest(dest: object | None, state_var_stkoff: int) -> bool:
    """Return whether ``dest`` writes the tracked state stack slot."""
    if dest is None:
        return False
    if not _is_stack_operand(dest):
        return False
    return mop_stkoff(dest) == state_var_stkoff


def resolve_singleton_state_write_value(
    mba: object,
    block_serial: int,
    *,
    state_var_stkoff: int | None,
    resolve_state_via_valranges: object | None = None,
) -> int | None:
    """Resolve a single concrete state value written in ``block_serial``."""
    if mba is None or state_var_stkoff is None:
        return None
    try:
        block = mba.get_mblock(block_serial)
    except Exception:
        return None
    if block is None:
        return None

    resolved_values: set[int] = set()
    stk_map: dict[int, int] = {}
    reg_map: dict[int, int] = {}
    state_write_seen = False
    for insn in iter_live_block_insns(block):
        dest = getattr(insn, "d", None)
        state_dest = is_state_var_dest(dest, state_var_stkoff)
        if state_dest:
            state_write_seen = True
            if _is_move_insn(insn):
                source = getattr(insn, "l", None)
                value = mop_const_value(source)
                if value is not None:
                    resolved_values.add(value & 0xFFFFFFFF)
                    continue
        try:
            resolved = _forward_eval_insn(
                insn,
                stk_map,
                reg_map,
                state_var_stkoff,
                mba=mba,
            )
        except Exception:
            resolved = None
        if state_dest and resolved is not None:
            resolved_values.add(int(resolved) & 0xFFFFFFFF)
            continue
        if not state_dest:
            continue
        if not hasattr(dest, "s") or not hasattr(mba, "vars"):
            continue
        if not callable(resolve_state_via_valranges):
            continue
        try:
            resolved = resolve_state_via_valranges(block, dest, insn)
        except Exception:
            resolved = None
        if resolved is not None:
            resolved_values.add(int(resolved) & 0xFFFFFFFF)

    if not state_write_seen:
        return None
    if len(resolved_values) != 1:
        return None
    return next(iter(resolved_values))


def block_has_state_var_write(
    mba: object,
    block_serial: int,
    *,
    state_var_stkoff: int | None,
) -> bool:
    """Return whether ``block_serial`` writes the tracked state variable."""
    if mba is None or state_var_stkoff is None:
        return False
    try:
        block = mba.get_mblock(block_serial)
    except Exception:
        return False
    if block is None:
        return False

    for insn in iter_live_block_insns(block):
        if is_state_var_dest(getattr(insn, "d", None), state_var_stkoff):
            return True
    return False


def resolve_evaluated_handoff_state_via_pred(
    mba: object,
    *,
    via_pred: int,
    source_block: int,
    state_var_stkoff: int | None,
) -> int | None:
    """Forward-evaluate the state value across ``via_pred -> source_block``."""
    if mba is None or state_var_stkoff is None:
        return None
    try:
        pred_blk = mba.get_mblock(via_pred)
        src_blk = mba.get_mblock(source_block)
    except Exception:
        return None
    if pred_blk is None or src_blk is None:
        return None

    stk_map: dict[int, int] = {}
    reg_map: dict[int, int] = {}
    final_value: int | None = None
    for blk in (pred_blk, src_blk):
        for insn in iter_live_block_insns(blk):
            try:
                resolved = _forward_eval_insn(
                    insn,
                    stk_map,
                    reg_map,
                    state_var_stkoff,
                    mba=mba,
                )
            except Exception:
                resolved = None
            if resolved is not None:
                final_value = int(resolved) & 0xFFFFFFFF
    if final_value is not None:
        return final_value
    resolved = stk_map.get(state_var_stkoff)
    if resolved is None:
        return None
    return int(resolved) & 0xFFFFFFFF


def resolve_immediate_handoff_target(
    dag: LinearizedStateDag,
    mba: object,
    block_serial: int,
    *,
    state_var_stkoff: int | None,
    bst_node_blocks: set[int],
    dispatcher_lookup: object | None,
    dispatcher: object | None = None,
) -> tuple[int, int] | None:
    """Resolve an immediate local state write as a semantic handoff target."""
    if mba is None or state_var_stkoff is None:
        return None
    try:
        block = mba.get_mblock(block_serial)
    except Exception:
        return None
    if block is None:
        return None

    written_states: set[int] = set()
    for insn in iter_live_block_insns(block):
        if _is_move_insn(insn):
            d = insn.d
            l = insn.l
            if (
                d is not None
                and _is_stack_operand(d)
                and mop_stkoff(d) == state_var_stkoff
                and l is not None
                and _is_number_operand(l)
            ):
                value = mop_const_value(l)
                if value is not None:
                    written_states.add(int(value) & 0xFFFFFFFF)

    if len(written_states) != 1:
        return None

    state_value = next(iter(written_states))
    exact_dispatcher_target = dispatcher_exact_state_target(
        state_value,
        dispatcher=dispatcher,
    )
    if exact_dispatcher_target == block_serial:
        return None
    direct_entry = resolve_dag_entry_for_state(
        dag,
        state_value,
        bst_node_blocks=bst_node_blocks,
    )
    exact_dispatcher_row = dispatcher_has_exact_state_row(
        state_value,
        dispatcher=dispatcher,
    )
    if dispatcher is not None and exact_dispatcher_row and direct_entry == block_serial:
        return None
    if exact_dispatcher_row:
        if direct_entry is None or direct_entry == block_serial:
            return None
        return (state_value, direct_entry)

    nonexact_target = resolve_nonexact_dispatch_target(
        dag,
        state_value,
        source_block=block_serial,
        bst_node_blocks=bst_node_blocks,
        dispatcher=dispatcher,
        dispatcher_lookup=dispatcher_lookup,
    )
    normalized_alias_target = resolve_normalized_alias_entry_for_state(
        dag,
        state_value,
        source_block=block_serial,
        bst_node_blocks=bst_node_blocks,
    )
    contextual_target = resolve_contextual_dag_entry_for_state(
        dag,
        state_value,
        source_block=block_serial,
        bst_node_blocks=bst_node_blocks,
    )
    target_entry = nonexact_target or direct_entry or normalized_alias_target or contextual_target
    if target_entry is None or target_entry == block_serial:
        return None
    return (state_value, target_entry)


def resolve_projected_snapshot_handoff_target(
    dag: LinearizedStateDag,
    flow_graph: object,
    block_serial: int,
    *,
    state_var_stkoff: int | None,
    bst_node_blocks: set[int],
    dispatcher: object | None,
) -> tuple[int, int] | None:
    """Resolve a projected insn snapshot handoff target."""
    if flow_graph is None or state_var_stkoff is None:
        return None
    try:
        block = flow_graph.get_block(block_serial)
    except Exception:
        return None
    if block is None:
        return None

    written_states: set[int] = set()
    for insn in tuple(getattr(block, "insn_snapshots", ())):
        if not _is_move_insn(insn):
            continue
        dest = getattr(insn, "d", None)
        src = getattr(insn, "l", None)
        if not is_state_var_dest(dest, state_var_stkoff):
            continue
        value = mop_const_value(src)
        if value is None:
            return None
        written_states.add(int(value) & 0xFFFFFFFF)

    if len(written_states) != 1:
        return None

    state_value = next(iter(written_states))
    exact_dispatcher_target = dispatcher_exact_state_target(
        state_value,
        dispatcher=dispatcher,
    )
    if exact_dispatcher_target == block_serial:
        return None
    direct_entry = resolve_dag_entry_for_state(
        dag,
        state_value,
        bst_node_blocks=bst_node_blocks,
    )
    if dispatcher_has_exact_state_row(state_value, dispatcher=dispatcher):
        if direct_entry is None or direct_entry == block_serial:
            return None
        return (state_value, direct_entry)
    return None


def resolve_assignment_map_handoff_target(
    dag: LinearizedStateDag,
    state_machine: object | None,
    block_serial: int,
    *,
    bst_node_blocks: set[int],
    dispatcher: object | None,
) -> tuple[int, int] | None:
    """Resolve a handoff target from the state machine assignment map."""
    if state_machine is None:
        return None
    assignment_map = getattr(state_machine, "assignment_map", None) or {}
    insns = assignment_map.get(block_serial)
    if not insns:
        return None

    state_value: int | None = None
    for insn in insns:
        if not _is_move_insn(insn):
            continue
        src = getattr(insn, "l", None)
        if not _is_number_operand(src):
            continue
        try:
            value = int(src.nnn.value) & 0xFFFFFFFF
        except Exception:
            value = mop_const_value(src)
            if value is not None:
                value &= 0xFFFFFFFF
        if value is None:
            continue
        if state_value is None:
            state_value = value
        elif state_value != value:
            return None

    if state_value is None:
        return None

    exact_dispatcher_target = dispatcher_exact_state_target(
        state_value,
        dispatcher=dispatcher,
    )
    if exact_dispatcher_target == block_serial:
        return None
    direct_entry = resolve_dag_entry_for_state(
        dag,
        state_value,
        bst_node_blocks=bst_node_blocks,
    )
    if dispatcher_has_exact_state_row(state_value, dispatcher=dispatcher):
        if direct_entry is None or direct_entry == block_serial:
            return None
        return (state_value, direct_entry)
    return None


def resolve_synthesized_handoff_target(
    dag: LinearizedStateDag,
    mba: object,
    block_serial: int,
    *,
    state_var_stkoff: int | None,
    bst_node_blocks: set[int],
    dispatcher: object | None,
    via_pred: int | None = None,
    resolve_state_via_valranges: object | None = None,
) -> tuple[int, int] | None:
    """Synthesize a residual handoff target from forward-evaluated state writes."""
    state_value = resolve_singleton_state_write_value(
        mba,
        block_serial,
        state_var_stkoff=state_var_stkoff,
        resolve_state_via_valranges=resolve_state_via_valranges,
    )
    if state_value is None and via_pred is not None:
        state_value = resolve_evaluated_handoff_state_via_pred(
            mba,
            via_pred=via_pred,
            source_block=block_serial,
            state_var_stkoff=state_var_stkoff,
        )
    if state_value is None:
        return None
    exact_dispatcher_target = dispatcher_exact_state_target(
        state_value,
        dispatcher=dispatcher,
    )
    if exact_dispatcher_target == block_serial:
        return None
    direct_entry = resolve_dag_entry_for_state(
        dag,
        state_value,
        bst_node_blocks=bst_node_blocks,
    )
    exact_dispatcher_row = dispatcher_has_exact_state_row(
        state_value,
        dispatcher=dispatcher,
    )
    if exact_dispatcher_row:
        if direct_entry is None or direct_entry == block_serial:
            return None
        return (state_value, direct_entry)
    contextual_source = via_pred if via_pred is not None else block_serial
    cover_fallback_entry = resolve_cover_fallback_entry_for_state(
        dag,
        state_value,
        source_block=contextual_source,
        bst_node_blocks=bst_node_blocks,
        dispatcher=dispatcher,
    )
    if cover_fallback_entry is not None and cover_fallback_entry != block_serial:
        return (state_value, cover_fallback_entry)

    nonexact_target = None
    if dispatcher is None or state_has_semantic_support(dag, state_value):
        nonexact_target = resolve_nonexact_dispatch_target(
            dag,
            state_value,
            source_block=contextual_source,
            bst_node_blocks=bst_node_blocks,
            dispatcher=dispatcher,
            dispatcher_lookup=(getattr(dispatcher, "lookup", None) if dispatcher is not None else None),
        )
    if nonexact_target is not None and nonexact_target != block_serial:
        return (state_value, nonexact_target)

    target_entry = resolve_contextual_dag_entry_for_state(
        dag,
        state_value,
        source_block=contextual_source,
        bst_node_blocks=bst_node_blocks,
    )
    normalized_alias_target = None
    if dispatcher is None or state_has_semantic_support(dag, state_value):
        normalized_alias_target = resolve_normalized_alias_entry_for_state(
            dag,
            state_value,
            source_block=contextual_source,
            bst_node_blocks=bst_node_blocks,
        )
        if normalized_alias_target is not None:
            target_entry = normalized_alias_target
    if target_entry is not None and via_pred is not None and target_entry == via_pred:
        fallback_target = resolve_loopback_alias_fallback_entry(
            dag,
            state_value,
            source_block=block_serial,
            via_pred=via_pred,
            bst_node_blocks=bst_node_blocks,
            dispatcher=dispatcher,
        )
        if fallback_target is not None:
            target_entry = fallback_target
    if target_entry is not None and target_entry != block_serial:
        return (state_value, target_entry)

    if dispatcher is None or state_has_semantic_support(dag, state_value):
        target_entry = resolve_dag_entry_for_state(
            dag,
            state_value,
            bst_node_blocks=bst_node_blocks,
        )
        if target_entry is not None and target_entry != block_serial:
            return (state_value, target_entry)

    owner_entry = resolve_owner_semantic_entry_for_blocks(
        dag,
        anchor_candidates=((contextual_source,) if via_pred is not None else (block_serial,)),
        source_block=block_serial,
        bst_node_blocks=bst_node_blocks,
    )
    if owner_entry is not None and owner_entry != block_serial:
        return (state_value, owner_entry)

    if dispatcher is not None and not state_has_semantic_support(dag, state_value):
        return None

    return None


def resolve_single_successor_handoff_target(
    dag: LinearizedStateDag,
    mba: object,
    block_serial: int,
    *,
    state_var_stkoff: int | None,
    bst_node_blocks: set[int],
    dispatcher_lookup: object | None,
    dispatcher: object | None = None,
    resolve_state_via_valranges: object | None = None,
) -> tuple[int, int] | None:
    """Resolve a residual source through a single successor state-write feeder."""
    if mba is None:
        return None
    try:
        block = mba.get_mblock(block_serial)
    except Exception:
        return None
    if block is None:
        return None

    succs = iter_live_block_succs(block)
    if len(succs) != 1:
        return None
    successor_serial = int(succs[0])
    if successor_serial == int(block_serial) or successor_serial in bst_node_blocks:
        return None

    handoff = resolve_immediate_handoff_target(
        dag,
        mba,
        successor_serial,
        state_var_stkoff=state_var_stkoff,
        bst_node_blocks=bst_node_blocks,
        dispatcher_lookup=dispatcher_lookup,
        dispatcher=dispatcher,
    )
    if handoff is None:
        handoff = resolve_synthesized_handoff_target(
            dag,
            mba,
            successor_serial,
            state_var_stkoff=state_var_stkoff,
            bst_node_blocks=bst_node_blocks,
            dispatcher=dispatcher,
            via_pred=int(block_serial),
            resolve_state_via_valranges=resolve_state_via_valranges,
        )
    if handoff is None:
        handoff = resolve_projected_path_tail_target(
            dag,
            source_block=successor_serial,
            bst_node_blocks=bst_node_blocks,
            dispatcher=dispatcher,
            predecessor_hints=(int(block_serial),),
            require_predecessor_match=True,
        )
    if handoff is None:
        return None

    state_value, target_entry = handoff
    if int(target_entry) == int(block_serial):
        return None
    return (int(state_value), int(target_entry))


def _is_backward_same_corridor_target(
    edge: StateDagEdge,
    *,
    source_block: int,
    target_entry: int,
) -> bool:
    if not edge.ordered_path:
        return False
    try:
        source_index = edge.ordered_path.index(source_block)
        target_index = edge.ordered_path.index(target_entry)
    except ValueError:
        return False
    return target_index <= source_index


def resolve_effective_target_entry(
    dag: LinearizedStateDag,
    edge: StateDagEdge,
    *,
    bst_node_blocks: set[int],
    state_var_stkoff: int | None,
    dispatcher_lookup: object | None,
    dispatcher: object | None,
    mba: object,
    resolve_state_via_valranges: object | None = None,
) -> EffectiveTargetEntryResolution:
    """Resolve the best semantic target for one residual handoff edge."""
    target_entry = resolve_redirect_safe_target_entry(
        dag,
        edge,
        bst_node_blocks=bst_node_blocks,
    )
    source_block = (
        edge.ordered_path[-1] if edge.ordered_path else edge.source_anchor.block_serial
    )
    normalized_nonexact_target = None
    if (
        edge.target_state is not None
        and dispatcher is not None
        and not dispatcher_has_exact_state_row(
            edge.target_state,
            dispatcher=dispatcher,
        )
        and is_raw_state_label(edge.target_label or "", edge.target_state)
    ):
        normalized_nonexact_target = resolve_nonexact_dispatch_target(
            dag,
            edge.target_state,
            source_block=source_block,
            bst_node_blocks=bst_node_blocks,
            dispatcher=dispatcher,
            dispatcher_lookup=dispatcher_lookup,
        )
        if (
            normalized_nonexact_target is not None
            and normalized_nonexact_target != source_block
            and normalized_nonexact_target != target_entry
        ):
            target_entry = normalized_nonexact_target

    immediate_handoff = resolve_immediate_handoff_target(
        dag,
        mba,
        source_block,
        state_var_stkoff=state_var_stkoff,
        bst_node_blocks=bst_node_blocks,
        dispatcher_lookup=dispatcher_lookup,
        dispatcher=dispatcher,
    )
    synthesized_handoff = None
    if immediate_handoff is None:
        via_pred = edge.ordered_path[-2] if len(edge.ordered_path) >= 2 else None
        synthesized_handoff = resolve_synthesized_handoff_target(
            dag,
            mba,
            source_block,
            state_var_stkoff=state_var_stkoff,
            bst_node_blocks=bst_node_blocks,
            dispatcher=dispatcher,
            via_pred=via_pred,
            resolve_state_via_valranges=resolve_state_via_valranges,
        )

    selected_handoff = immediate_handoff or synthesized_handoff
    if selected_handoff is not None:
        immediate_state, immediate_target_entry = selected_handoff
        immediate_direct_entry = resolve_dag_entry_for_state(
            dag,
            immediate_state,
            bst_node_blocks=bst_node_blocks,
        )
        if (
            edge.target_state is not None
            and dispatcher is not None
            and not dispatcher_has_exact_state_row(
                edge.target_state,
                dispatcher=dispatcher,
            )
            and immediate_state == (edge.target_state & 0xFFFFFFFF)
            and target_entry is not None
            and target_entry not in bst_node_blocks
            and immediate_target_entry != target_entry
        ):
            if not (
                immediate_direct_entry is not None
                and immediate_direct_entry == immediate_target_entry
            ):
                return EffectiveTargetEntryResolution(
                    source_block=int(source_block),
                    target_entry=target_entry,
                    normalized_nonexact_target=normalized_nonexact_target,
                    immediate_handoff=immediate_handoff,
                    synthesized_handoff=synthesized_handoff,
                )
        if _is_backward_same_corridor_target(
            edge,
            source_block=source_block,
            target_entry=immediate_target_entry,
        ):
            fallback_target_entry = resolve_cover_fallback_entry_for_state(
                dag,
                immediate_state,
                source_block=source_block,
                bst_node_blocks=bst_node_blocks,
                dispatcher=dispatcher,
            )
            if (
                fallback_target_entry is not None
                and not _is_backward_same_corridor_target(
                    edge,
                    source_block=source_block,
                    target_entry=fallback_target_entry,
                )
            ):
                immediate_target_entry = fallback_target_entry
            elif (
                normalized_nonexact_target is not None
                and not _is_backward_same_corridor_target(
                    edge,
                    source_block=source_block,
                    target_entry=normalized_nonexact_target,
                )
            ):
                return EffectiveTargetEntryResolution(
                    source_block=int(source_block),
                    target_entry=normalized_nonexact_target,
                    normalized_nonexact_target=normalized_nonexact_target,
                    immediate_handoff=immediate_handoff,
                    synthesized_handoff=synthesized_handoff,
                )
            elif (
                target_entry is not None
                and not _is_backward_same_corridor_target(
                    edge,
                    source_block=source_block,
                    target_entry=target_entry,
                )
            ):
                return EffectiveTargetEntryResolution(
                    source_block=int(source_block),
                    target_entry=target_entry,
                    normalized_nonexact_target=normalized_nonexact_target,
                    immediate_handoff=immediate_handoff,
                    synthesized_handoff=synthesized_handoff,
                )
        elif (
            target_entry is not None
            and target_entry not in bst_node_blocks
            and immediate_target_entry != target_entry
            and edge.target_state is not None
            and (immediate_state & 0xFFFFFFFF) == (edge.target_state & 0xFFFFFFFF)
        ):
            return EffectiveTargetEntryResolution(
                source_block=int(source_block),
                target_entry=target_entry,
                normalized_nonexact_target=normalized_nonexact_target,
                immediate_handoff=immediate_handoff,
                synthesized_handoff=synthesized_handoff,
            )
        target_entry = immediate_target_entry

    return EffectiveTargetEntryResolution(
        source_block=int(source_block),
        target_entry=target_entry,
        normalized_nonexact_target=normalized_nonexact_target,
        immediate_handoff=immediate_handoff,
        synthesized_handoff=synthesized_handoff,
    )


def collect_residual_source_handoff_facts(
    dag: LinearizedStateDag,
    *,
    state_machine: object | None,
    projected_flow_graph: object,
    source_block: int,
    current_preds: tuple[int, ...],
    state_var_stkoff: int | None,
    bst_node_blocks: set[int],
    dispatcher_lookup: object | None,
    dispatcher: object | None = None,
    analysis_mba: object | None = None,
    live_mba: object | None = None,
) -> ResidualSourceHandoffFacts:
    """Collect all discovery-only residual handoff facts for ``source_block``."""
    source_has_state_write = (
        block_has_state_var_write(
            analysis_mba,
            source_block,
            state_var_stkoff=state_var_stkoff,
        )
        or (
            live_mba is not None
            and analysis_mba is not live_mba
            and block_has_state_var_write(
                live_mba,
                source_block,
                state_var_stkoff=state_var_stkoff,
            )
        )
    )

    assignment_map_handoff = resolve_assignment_map_handoff_target(
        dag,
        state_machine,
        source_block,
        bst_node_blocks=bst_node_blocks,
        dispatcher=dispatcher,
    )
    projected_snapshot_handoff = resolve_projected_snapshot_handoff_target(
        dag,
        projected_flow_graph,
        source_block,
        state_var_stkoff=state_var_stkoff,
        bst_node_blocks=bst_node_blocks,
        dispatcher=dispatcher,
    )
    immediate_handoff = resolve_immediate_handoff_target(
        dag,
        analysis_mba,
        source_block,
        state_var_stkoff=state_var_stkoff,
        bst_node_blocks=bst_node_blocks,
        dispatcher_lookup=dispatcher_lookup,
        dispatcher=dispatcher,
    )

    synthesized_handoff = None
    if immediate_handoff is None:
        if len(current_preds) == 1:
            synthesized_handoff = resolve_synthesized_handoff_target(
                dag,
                analysis_mba,
                source_block,
                state_var_stkoff=state_var_stkoff,
                bst_node_blocks=bst_node_blocks,
                dispatcher=dispatcher,
                via_pred=current_preds[0],
            )
        if synthesized_handoff is None:
            synthesized_handoff = resolve_synthesized_handoff_target(
                dag,
                analysis_mba,
                source_block,
                state_var_stkoff=state_var_stkoff,
                bst_node_blocks=bst_node_blocks,
                dispatcher=dispatcher,
            )

    live_immediate_handoff = None
    live_synthesized_handoff = None
    successor_handoff = None
    live_successor_handoff = None
    if live_mba is not None and analysis_mba is not live_mba:
        live_immediate_handoff = resolve_immediate_handoff_target(
            dag,
            live_mba,
            source_block,
            state_var_stkoff=state_var_stkoff,
            bst_node_blocks=bst_node_blocks,
            dispatcher_lookup=dispatcher_lookup,
            dispatcher=dispatcher,
        )
        if live_immediate_handoff is None:
            if len(current_preds) == 1:
                live_synthesized_handoff = resolve_synthesized_handoff_target(
                    dag,
                    live_mba,
                    source_block,
                    state_var_stkoff=state_var_stkoff,
                    bst_node_blocks=bst_node_blocks,
                    dispatcher=dispatcher,
                    via_pred=current_preds[0],
                )
            if live_synthesized_handoff is None:
                live_synthesized_handoff = resolve_synthesized_handoff_target(
                    dag,
                    live_mba,
                    source_block,
                    state_var_stkoff=state_var_stkoff,
                    bst_node_blocks=bst_node_blocks,
                    dispatcher=dispatcher,
                )

    source_level_handoff = (
        immediate_handoff
        or synthesized_handoff
        or live_immediate_handoff
        or live_synthesized_handoff
    )
    if source_level_handoff is None:
        successor_handoff = resolve_single_successor_handoff_target(
            dag,
            analysis_mba,
            source_block,
            state_var_stkoff=state_var_stkoff,
            bst_node_blocks=bst_node_blocks,
            dispatcher_lookup=dispatcher_lookup,
            dispatcher=dispatcher,
        )
        if (
            successor_handoff is None
            and live_mba is not None
            and analysis_mba is not live_mba
        ):
            live_successor_handoff = resolve_single_successor_handoff_target(
                dag,
                live_mba,
                source_block,
                state_var_stkoff=state_var_stkoff,
                bst_node_blocks=bst_node_blocks,
                dispatcher_lookup=dispatcher_lookup,
                dispatcher=dispatcher,
            )

    source_level_handoff = (
        source_level_handoff
        or successor_handoff
        or live_successor_handoff
    )
    projected_path_handoff = None
    if not (
        source_has_state_write
        and len(current_preds) > 1
        and source_level_handoff is None
    ):
        projected_path_handoff = resolve_projected_path_tail_target(
            dag,
            source_block=source_block,
            bst_node_blocks=bst_node_blocks,
            dispatcher=dispatcher,
            predecessor_hints=current_preds if current_preds else None,
        )

    prefer_projected_leaf_handoff = (
        projected_path_handoff is not None
        and source_level_handoff is not None
        and (int(projected_path_handoff[0]) & 0xFFFFFFFF)
        == (int(source_level_handoff[0]) & 0xFFFFFFFF)
        and int(projected_path_handoff[1]) != int(source_level_handoff[1])
        and _is_immediate_conditional_leaf_tail_for_state(
            dag,
            source_block=int(source_block),
            state_value=int(projected_path_handoff[0]),
            predecessor_hints=current_preds,
        )
    )

    handoff = (
        projected_path_handoff
        if prefer_projected_leaf_handoff
        else (
            assignment_map_handoff
            or projected_snapshot_handoff
            or source_level_handoff
            or projected_path_handoff
        )
    )
    return ResidualSourceHandoffFacts(
        source_block=int(source_block),
        current_preds=tuple(int(pred) for pred in current_preds),
        source_has_state_write=bool(source_has_state_write),
        assignment_map_handoff=assignment_map_handoff,
        projected_snapshot_handoff=projected_snapshot_handoff,
        immediate_handoff=immediate_handoff,
        synthesized_handoff=synthesized_handoff,
        live_immediate_handoff=live_immediate_handoff,
        live_synthesized_handoff=live_synthesized_handoff,
        successor_handoff=successor_handoff,
        live_successor_handoff=live_successor_handoff,
        source_level_handoff=source_level_handoff,
        projected_path_handoff=projected_path_handoff,
        handoff=handoff,
    )


__all__ = [
    "EffectiveTargetEntryResolution",
    "ResidualSourceHandoffFacts",
    "collect_residual_source_handoff_facts",
    "dispatcher_exact_state_target",
    "dispatcher_has_exact_state_row",
    "has_live_exact_residual_handoff",
    "is_transient_corridor_entry",
    "block_has_state_var_write",
    "is_raw_state_label",
    "is_state_var_dest",
    "iter_residual_prefix_handoffs",
    "iter_live_block_insns",
    "mop_const_value",
    "mop_stkoff",
    "resolve_assignment_map_handoff_target",
    "resolve_path_lead_entry_from_node",
    "resolve_contextual_dag_entry_for_state",
    "resolve_cover_fallback_entry_for_state",
    "resolve_dag_entry_for_state",
    "resolve_evaluated_handoff_state_via_pred",
    "resolve_effective_target_entry",
    "resolve_immediate_handoff_target",
    "resolve_loopback_alias_fallback_entry",
    "resolve_nonexact_dispatch_target",
    "resolve_nonlocal_state_entry",
    "resolve_normalized_alias_entry_for_state",
    "resolve_owner_family_fallback_entry",
    "resolve_owner_semantic_entry_for_blocks",
    "resolve_projected_snapshot_handoff_target",
    "resolve_projected_path_tail_target",
    "resolve_redirect_safe_entry_from_node",
    "resolve_redirect_safe_target_entry",
    "resolve_singleton_state_write_value",
    "resolve_synthesized_handoff_target",
    "state_has_semantic_support",
    "supplemental_selected_entry_for_state",
]
