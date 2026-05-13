"""Pure semantic target-resolution helpers for cfg lowering."""

from __future__ import annotations

from d810.cfg.dag_index import build_dag_node_maps


def _node_kind_name(node: object) -> str:
    return str(getattr(getattr(node, "kind", None), "name", "") or getattr(node, "kind", "") or "")


def dispatcher_has_exact_state_row(
    state_value: int | None,
    *,
    dispatcher: object | None = None,
) -> bool:
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


def is_raw_state_label(label: str, state_value: int) -> bool:
    if label.endswith("_fallback"):
        return False
    try:
        return int(label, 16) == (state_value & 0xFFFFFFFF)
    except Exception:
        return False


def resolve_path_lead_entry_from_node(
    dag: object,
    node: object,
    *,
    bst_node_blocks: set[int],
) -> int | None:
    outgoing_paths = tuple(
        edge.ordered_path
        for edge in getattr(dag, "edges", ()) or ()
        if getattr(edge, "source_key", None) == getattr(node, "key", None)
        and getattr(edge, "ordered_path", None)
    )
    if not outgoing_paths:
        return None
    blocks_on_outgoing_paths = {
        int(block_serial)
        for path in outgoing_paths
        for block_serial in path
    }
    entry_anchor = int(getattr(node, "entry_anchor", -1))
    if entry_anchor in blocks_on_outgoing_paths:
        return None
    path_starts = sorted(
        {
            int(path[0])
            for path in outgoing_paths
            if int(path[0]) not in bst_node_blocks
        }
    )
    if len(path_starts) != 1:
        return None
    return int(path_starts[0])


def resolve_redirect_safe_entry_from_node(
    node: object,
    *,
    dag: object | None = None,
    bst_node_blocks: set[int],
) -> int | None:
    if dag is not None:
        path_lead_entry = resolve_path_lead_entry_from_node(
            dag,
            node,
            bst_node_blocks=bst_node_blocks,
        )
        if path_lead_entry is not None:
            return path_lead_entry
    candidates = (
        getattr(node, "entry_anchor", None),
        *(getattr(node, "exclusive_blocks", ()) or ()),
        *(getattr(node, "owned_blocks", ()) or ()),
    )
    for block_serial in candidates:
        if block_serial is None:
            continue
        if int(block_serial) not in bst_node_blocks:
            return int(block_serial)
    entry_anchor = getattr(node, "entry_anchor", None)
    if entry_anchor is None:
        return None
    return int(entry_anchor) if int(entry_anchor) not in bst_node_blocks else None


def resolve_redirect_safe_target_entry(
    dag: object,
    edge: object,
    *,
    bst_node_blocks: set[int],
) -> int | None:
    target_entry = getattr(edge, "target_entry_anchor", None)
    explicit_target_entry = (
        int(target_entry)
        if target_entry is not None and int(target_entry) not in bst_node_blocks
        else None
    )
    target_node = (
        build_dag_node_maps(dag).node_by_key.get(getattr(edge, "target_key", None))
        if getattr(edge, "target_key", None) is not None
        else None
    )
    labeled_entry = None
    target_label = str(getattr(edge, "target_label", "") or "")
    if target_label:
        labeled_matches = [
            node for node in getattr(dag, "nodes", ()) or ()
            if str(getattr(node, "state_label", "") or "") == target_label
        ]
        if len(labeled_matches) == 1:
            labeled_entry = resolve_redirect_safe_entry_from_node(
                labeled_matches[0],
                dag=dag,
                bst_node_blocks=bst_node_blocks,
            )
    if labeled_entry is not None and target_label.endswith("_fallback"):
        return labeled_entry
    if target_node is not None:
        safe_target_entry = resolve_redirect_safe_entry_from_node(
            target_node,
            dag=dag,
            bst_node_blocks=bst_node_blocks,
        )
        ordered_path = tuple(int(block) for block in (getattr(edge, "ordered_path", ()) or ()))
        if (
            explicit_target_entry is not None
            and safe_target_entry is not None
            and explicit_target_entry != safe_target_entry
        ):
            if explicit_target_entry in ordered_path:
                return safe_target_entry
            return explicit_target_entry
        if safe_target_entry is not None:
            return safe_target_entry
    if labeled_entry is not None:
        return labeled_entry
    return explicit_target_entry


def resolve_dag_entry_for_state(
    dag: object,
    state_value: int | None,
    *,
    bst_node_blocks: set[int] | None = None,
) -> int | None:
    if state_value is None:
        return None
    for node in getattr(dag, "nodes", ()) or ():
        key = getattr(node, "key", None)
        if getattr(key, "state_const", None) == state_value:
            return resolve_redirect_safe_entry_from_node(
                node,
                dag=dag,
                bst_node_blocks=bst_node_blocks or set(),
            )
    for node in getattr(dag, "nodes", ()) or ():
        key = getattr(node, "key", None)
        lo = getattr(key, "range_lo", None)
        hi = getattr(key, "range_hi", None)
        if lo is None or hi is None:
            continue
        if int(lo) <= int(state_value) <= int(hi):
            return resolve_redirect_safe_entry_from_node(
                node,
                dag=dag,
                bst_node_blocks=bst_node_blocks or set(),
            )
    return None


def resolve_normalized_alias_entry_for_state(
    dag: object,
    state_value: int | None,
    *,
    source_block: int | None,
    bst_node_blocks: set[int],
) -> int | None:
    if state_value is None:
        return None

    raw_value = int(state_value) & 0xFFFFFFFF
    node_by_key: dict[object, object] = {}
    for node in getattr(dag, "nodes", ()) or ():
        key = getattr(node, "key", None)
        try:
            hash(key)
        except Exception:
            continue
        node_by_key[key] = node
    best_match: tuple[int, int, int, int, int] | None = None
    best_entry: int | None = None

    for node in getattr(dag, "nodes", ()) or ():
        key = getattr(node, "key", None)
        if getattr(key, "state_const", None) != raw_value:
            continue
        entry = resolve_redirect_safe_entry_from_node(
            node,
            dag=dag,
            bst_node_blocks=bst_node_blocks,
        )
        if entry is None or entry == source_block:
            continue
        node_label = str(getattr(node, "state_label", "") or "")
        raw_exact_node = (
            _node_kind_name(node) == "EXACT"
            and getattr(key, "state_const", None) == raw_value
            and is_raw_state_label(node_label, raw_value)
        )
        if is_raw_state_label(node_label, raw_value) and not raw_exact_node:
            continue
        score = (
            2 if raw_exact_node else 0,
            1 if node_label.endswith("_fallback") else 0,
            1 if entry in {int(block) for block in (getattr(node, "exclusive_blocks", ()) or ())} else 0,
            1 if entry in {int(block) for block in (getattr(node, "owned_blocks", ()) or ())} else 0,
            -entry,
        )
        if best_match is None or score > best_match:
            best_match = score
            best_entry = entry

    for edge in getattr(dag, "edges", ()) or ():
        target_state = getattr(edge, "target_state", None)
        if target_state is None or (int(target_state) & 0xFFFFFFFF) != raw_value:
            continue
        target_entry = resolve_redirect_safe_target_entry(
            dag,
            edge,
            bst_node_blocks=bst_node_blocks,
        )
        if target_entry is None:
            continue
        target_node = node_by_key.get(getattr(edge, "target_key", None))
        edge_label = str(getattr(edge, "target_label", "") or "")
        target_key = getattr(target_node, "key", None) if target_node is not None else None
        raw_exact_target = (
            target_node is not None
            and _node_kind_name(target_node) == "EXACT"
            and getattr(target_key, "state_const", None) == raw_value
            and target_entry == int(getattr(target_node, "entry_anchor", -1))
            and is_raw_state_label(edge_label, raw_value)
        )
        if is_raw_state_label(edge_label, raw_value) and not raw_exact_target:
            continue
        ordered_path = tuple(int(block) for block in (getattr(edge, "ordered_path", ()) or ()))
        source_anchor = getattr(edge, "source_anchor", None)
        source_anchor_block = getattr(source_anchor, "block_serial", None)
        on_path = source_block is not None and source_block in ordered_path
        source_match = source_block is not None and source_anchor_block == source_block
        score = (
            2 if raw_exact_target else 0,
            2 if edge_label.endswith("_fallback") else 0,
            1 if on_path else 0,
            1 if source_match else 0,
            len(ordered_path),
        )
        if best_match is None or score > best_match:
            best_match = score
            best_entry = target_entry

    if best_entry is not None and best_entry == source_block:
        return None
    return best_entry


def resolve_owner_semantic_entry_for_blocks(
    dag: object,
    *,
    anchor_candidates: tuple[int, ...],
    source_block: int,
    bst_node_blocks: set[int],
) -> int | None:
    if not anchor_candidates:
        return None

    def _owns_candidate(node: object, block_serial: int) -> bool:
        if block_serial == int(getattr(node, "entry_anchor", -1)):
            return True
        if block_serial in {int(block) for block in (getattr(node, "owned_blocks", ()) or ())}:
            return True
        return any(
            block_serial in {int(block) for block in (getattr(segment, "blocks", ()) or ())}
            for segment in (getattr(node, "local_segments", ()) or ())
        )

    owners = [
        node
        for node in getattr(dag, "nodes", ()) or ()
        if _node_kind_name(node) == "EXACT"
        and getattr(getattr(node, "key", None), "state_const", None) is not None
        and any(_owns_candidate(node, block_serial) for block_serial in anchor_candidates)
    ]
    if not owners:
        return None

    min_anchor = min(anchor_candidates)
    owners.sort(
        key=lambda node: (
            0 if any(block in {int(value) for value in (getattr(node, "exclusive_blocks", ()) or ())} for block in anchor_candidates) else 1,
            0 if any(block == int(getattr(node, "entry_anchor", -1)) for block in anchor_candidates) else 1,
            abs(int(getattr(node, "entry_anchor", min_anchor)) - min_anchor),
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


def resolve_cover_fallback_entry_for_state(
    dag: object,
    state_value: int | None,
    *,
    source_block: int,
    bst_node_blocks: set[int],
    dispatcher: object | None = None,
) -> int | None:
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
            if hi - lo == 1 and lo <= state_value:
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

    if cover_state is not None:
        exact_entry = resolve_dag_entry_for_state(
            dag,
            cover_state,
            bst_node_blocks=bst_node_blocks,
        )
        if exact_entry is not None and exact_entry != source_block:
            return exact_entry

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
        and int(cover_interval_target) not in bst_node_blocks
        and int(cover_interval_target) != source_block
    ):
        return int(cover_interval_target)
    return None


def resolve_nonexact_dispatch_target(
    dag: object,
    state_value: int | None,
    *,
    source_block: int,
    bst_node_blocks: set[int],
    dispatcher: object | None,
    dispatcher_lookup: object | None = None,
) -> int | None:
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


__all__ = [
    "dispatcher_exact_state_target",
    "dispatcher_has_exact_state_row",
    "is_raw_state_label",
    "resolve_nonexact_dispatch_target",
    "resolve_normalized_alias_entry_for_state",
    "resolve_owner_semantic_entry_for_blocks",
]
