"""Pure residual handoff discovery helpers.

These helpers answer semantic target-resolution questions for residual
dispatcher handoffs without choosing or applying any lowering policy.
"""

from __future__ import annotations

from d810.recon.flow.dag_index import build_dag_node_maps
from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateNodeKind,
)


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
    best_match: tuple[int, int, int, int] | None = None
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
        if is_raw_state_label(node.state_label, raw_value):
            continue
        score = (
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
        if is_raw_state_label(edge.target_label, raw_value):
            continue
        on_path = source_block is not None and source_block in edge.ordered_path
        source_match = (
            source_block is not None and edge.source_anchor.block_serial == source_block
        )
        score = (
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

    normalized_alias_target = resolve_normalized_alias_entry_for_state(
        dag,
        state_value,
        source_block=source_block,
        bst_node_blocks=bst_node_blocks,
    )
    if normalized_alias_target is not None:
        return normalized_alias_target

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


__all__ = [
    "dispatcher_exact_state_target",
    "dispatcher_has_exact_state_row",
    "is_raw_state_label",
    "iter_residual_prefix_handoffs",
    "resolve_path_lead_entry_from_node",
    "resolve_contextual_dag_entry_for_state",
    "resolve_cover_fallback_entry_for_state",
    "resolve_dag_entry_for_state",
    "resolve_loopback_alias_fallback_entry",
    "resolve_nonexact_dispatch_target",
    "resolve_nonlocal_state_entry",
    "resolve_normalized_alias_entry_for_state",
    "resolve_owner_family_fallback_entry",
    "resolve_owner_semantic_entry_for_blocks",
    "resolve_projected_path_tail_target",
    "resolve_redirect_safe_entry_from_node",
    "resolve_redirect_safe_target_entry",
    "state_has_semantic_support",
]
