"""Backend-neutral residual dispatcher frontier target resolution.

The routines here classify residual dispatcher feeders and choose semantic
frontier targets from DAG/CFG evidence.  They intentionally accept callback
resolvers from the caller instead of importing recon or backend modules; Hodur
keeps strategy ordering, live state-write extraction, and modification emission.
"""
from __future__ import annotations

import re
from types import SimpleNamespace

from d810.cfg.dag_index import build_dag_node_maps
from d810.core.typing import Callable, Iterable


_STATE_LABEL_RE = re.compile(r"^STATE_([0-9A-Fa-f]{8})(?:(_fallback))?$")
_RAW_STATE_LABEL_RE = re.compile(r"^0x([0-9A-Fa-f]{8})(?:(_fallback))?$")
_STATE_LABEL_PREFIX_RE = re.compile(
    r"^STATE_([0-9A-Fa-f]{8})(?:(_fallback))?(?:__.+)?$"
)
_RAW_STATE_LABEL_PREFIX_RE = re.compile(
    r"^0x([0-9A-Fa-f]{8})(?:(_fallback))?(?:__.+)?$"
)

__all__ = [
    "collect_owned_exact_sources",
    "collect_supported_exact_entries",
    "dispatcher_exact_state_target",
    "dispatcher_has_exact_state_row",
    "is_raw_state_label",
    "is_structured_conditional_path_feeder",
    "is_supplemental_feeder_bypass",
    "resolve_nonexact_dispatch_target",
    "resolve_normalized_alias_entry_for_state",
    "resolve_owner_semantic_entry_for_blocks",
    "resolve_frontier_target_entry",
    "resolve_semantic_reference_alias_entry",
]


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


def _normalize_semantic_target_label(label_text: str | None) -> str | None:
    text = str(label_text or "").strip()
    if not text:
        return None
    state_match = _STATE_LABEL_PREFIX_RE.match(text)
    if state_match is not None:
        state_hex = state_match.group(1).upper()
        fallback_suffix = "_fallback" if state_match.group(2) else ""
        return f"STATE_{state_hex}{fallback_suffix}"
    raw_match = _RAW_STATE_LABEL_PREFIX_RE.match(text)
    if raw_match is not None:
        state_hex = raw_match.group(1).upper()
        fallback_suffix = "_fallback" if raw_match.group(2) else ""
        return f"STATE_{state_hex}{fallback_suffix}"
    return None


def _collect_semantic_entry_by_label(
    semantic_reference_program: object | None,
) -> dict[str, int]:
    if semantic_reference_program is None:
        return {}
    entries: dict[str, int] = {}
    for node in getattr(semantic_reference_program, "nodes", ()) or ():
        label_text = str(getattr(node, "label_text", "") or "")
        entry_anchor = getattr(node, "entry_anchor", None)
        if not label_text or entry_anchor is None:
            continue
        entry_value = int(entry_anchor)
        entries[label_text] = entry_value
        normalized_label = _normalize_semantic_target_label(label_text)
        if normalized_label is not None:
            entries.setdefault(normalized_label, entry_value)
        raw_match = _RAW_STATE_LABEL_RE.match(label_text)
        if raw_match is not None:
            suffix = raw_match.group(2) or ""
            entries[f"STATE_{raw_match.group(1).upper()}{suffix}"] = entry_value
            continue
        state_match = _STATE_LABEL_RE.match(label_text)
        if state_match is not None:
            suffix = state_match.group(2) or ""
            entries[f"0x{state_match.group(1).upper()}{suffix}"] = entry_value
    return entries


def _collect_semantic_successors_by_state(
    semantic_reference_program: object | None,
) -> dict[int, tuple[str, ...]]:
    if semantic_reference_program is None:
        return {}
    lines = tuple(getattr(semantic_reference_program, "lines", ()) or ())
    by_state: dict[int, list[str]] = {}
    for node in getattr(semantic_reference_program, "nodes", ()) or ():
        label_text = str(getattr(node, "label_text", "") or "")
        match = _STATE_LABEL_PREFIX_RE.match(label_text)
        if match is None:
            match = _RAW_STATE_LABEL_PREFIX_RE.match(label_text)
        if match is None:
            continue
        source_state = int(match.group(1), 16) & 0xFFFFFFFF
        line_start = int(getattr(node, "line_start", 0) or 0)
        line_end = int(getattr(node, "line_end", 0) or 0)
        targets: list[str] = []
        for line in lines:
            line_no = int(getattr(line, "line_no", 0) or 0)
            if line_no < line_start or line_no > line_end:
                continue
            target_label = getattr(line, "target_label", None)
            if target_label is None:
                continue
            targets.append(str(target_label))
        if targets:
            existing = by_state.setdefault(source_state, [])
            for target in targets:
                if target not in existing:
                    existing.append(target)
    return {
        int(source_state) & 0xFFFFFFFF: tuple(targets)
        for source_state, targets in by_state.items()
        if targets
    }


def resolve_semantic_reference_alias_entry(
    dag: object,
    semantic_reference_program: object | None,
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


def resolve_frontier_target_entry(
    dag: object,
    *,
    pred_serial: int,
    state_value: int,
    dispatcher_model: object | None,
    bst_blocks: set[int],
    semantic_reference_program: object | None,
    state_var_stkoff: int | None,
    mba: object | None,
    dispatcher_exact_state_target_fn: Callable[..., int | None],
    supplemental_selected_entry_for_state_fn: Callable[..., int | None],
    resolve_effective_target_entry_fn: Callable[..., int | None],
    resolve_exact_dag_entry_for_state_fn: Callable[..., int | None],
    resolve_semantic_reference_entry_for_state_fn: Callable[..., int | None],
    resolve_dag_entry_for_state_fn: Callable[..., int | None],
    resolve_normalized_alias_entry_for_state_fn: Callable[..., int | None],
    resolve_semantic_reference_alias_entry_fn: Callable[..., int | None] = resolve_semantic_reference_alias_entry,
) -> tuple[int | None, int | None]:
    """Resolve the best semantic entry for a residual feeder state write."""
    # TODO(backend-adapter-cleanup): This cfg-layer resolver is intentionally
    # backend-neutral, but the current API still accepts `mba` and
    # `state_var_stkoff` as opaque context solely to forward them into the
    # caller-supplied `resolve_effective_target_entry_fn` callback. That kept the
    # Hodur extraction small and behavior-preserving, but the cleaner endpoint is
    # a tiny resolver protocol/dataclass owned by the caller/backend adapter
    # (for example `ResidualTargetResolutionContext`) so cfg never exposes
    # Hex-Rays-shaped parameters in its public signature.
    raw_state = int(state_value) & 0xFFFFFFFF
    exact_dispatch_target = dispatcher_exact_state_target_fn(
        raw_state,
        dispatcher=dispatcher_model,
    )
    residual_effective_target = None
    synthetic_target_entry = supplemental_selected_entry_for_state_fn(
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
        residual_effective_target = resolve_effective_target_entry_fn(
            dag,
            synthetic_edge,
            bst_node_blocks=bst_blocks,
            state_var_stkoff=int(state_var_stkoff),
            dispatcher_lookup=getattr(dispatcher_model, "lookup", None),
            dispatcher=dispatcher_model,
            mba=mba,
        )
    exact_dag_entry = resolve_exact_dag_entry_for_state_fn(
        dag,
        raw_state,
        dispatcher_region=bst_blocks,
    )
    direct_semantic_entry = resolve_semantic_reference_entry_for_state_fn(
        raw_state,
        semantic_reference_program=semantic_reference_program,
        dispatcher_region=bst_blocks,
    )
    target_entry = resolve_dag_entry_for_state_fn(
        dag,
        raw_state,
        bst_node_blocks=bst_blocks,
    )
    normalized_alias_entry = resolve_normalized_alias_entry_for_state_fn(
        dag,
        raw_state,
        source_block=int(pred_serial),
        bst_node_blocks=bst_blocks,
    )
    semantic_alias_entry = resolve_semantic_reference_alias_entry_fn(
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
        target_entry = supplemental_selected_entry_for_state_fn(
            dag,
            raw_state,
        )
    if target_entry is not None:
        target_entry = int(target_entry)
    return (
        None if exact_dispatch_target is None else int(exact_dispatch_target),
        target_entry,
    )


def collect_supported_exact_entries(
    round_summary: object,
    *,
    exact_source_blocks: Iterable[int],
    bst_blocks: set[int],
    is_straight_line_handoff_fn: Callable[[object], bool],
    resolve_dag_entry_for_state_fn: Callable[..., int | None],
) -> set[int]:
    """Return exact-node entry blocks that are safe BST bypass targets."""
    supported_entries = {int(source_block) for source_block in exact_source_blocks}
    for plannable in getattr(round_summary, "plannable_edges", ()):
        edge = getattr(plannable, "edge", None)
        if edge is None or not is_straight_line_handoff_fn(edge):
            continue
        target_state = getattr(edge, "target_state", None)
        if target_state is None:
            continue
        target_entry = resolve_dag_entry_for_state_fn(
            round_summary.dag,
            int(target_state) & 0xFFFFFFFF,
            bst_node_blocks=bst_blocks,
        )
        if target_entry is None or int(target_entry) in bst_blocks:
            continue
        supported_entries.add(int(target_entry))
    return supported_entries


def collect_owned_exact_sources(
    round_summary: object,
    *,
    exact_source_blocks: Iterable[int],
    is_straight_line_handoff_fn: Callable[[object], bool],
) -> set[int]:
    """Return source blocks already owned by earlier exact-node lowerers."""
    owned_sources = {int(source_block) for source_block in exact_source_blocks}
    for plannable in getattr(round_summary, "plannable_edges", ()):
        edge = getattr(plannable, "edge", None)
        if edge is None or not is_straight_line_handoff_fn(edge):
            continue
        source_anchor = getattr(edge, "source_anchor", None)
        source_block = getattr(source_anchor, "block_serial", None)
        if source_block is None:
            continue
        owned_sources.add(int(source_block))
    return owned_sources


def is_supplemental_feeder_bypass(
    *,
    flow_graph: object,
    pred_serial: int,
    pred_block: object,
    state_value: int,
    exact_dispatch_target: int | None,
    target_entry: int,
    bst_blocks: set[int],
    supported_entries: set[int],
    owned_exact_sources: set[int],
    terminal_source_owned_blocks: set[int],
    terminal_protected_blocks: set[int],
    dag: object,
    state_has_semantic_support_fn: Callable[..., bool],
    can_reach_return_fn: Callable[[object, int], bool],
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
        state_has_semantic_support_fn(dag, int(state_value) & 0xFFFFFFFF)
        or (
            exact_dispatch_target is not None
            and int(exact_dispatch_target) != int(target_entry)
        )
        or can_reach_return_fn(flow_graph, int(target_entry))
    ):
        return False
    return True


def is_structured_conditional_path_feeder(
    dag: object,
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
