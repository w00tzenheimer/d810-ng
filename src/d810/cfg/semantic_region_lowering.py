from __future__ import annotations

from dataclasses import dataclass
import re
from types import SimpleNamespace

from d810.core import logging
from d810.core.algorithm_metadata import algorithm_metadata
from d810.cfg.state_dag_key import StateDagNodeKey
from d810.cfg.residual_target_resolution import (
    dispatcher_exact_state_target,
    dispatcher_has_exact_state_row,
    is_raw_state_label,
    resolve_normalized_alias_entry_for_state,
    resolve_nonexact_dispatch_target,
    resolve_owner_semantic_entry_for_blocks,
)
from d810.cfg.target_entry_resolution import (
    resolve_edge_target_entry,
    resolve_exact_dag_entry_for_state,
    resolve_semantic_reference_entry_for_state,
)


_STATE_LABEL_RE = re.compile(r"^STATE_([0-9A-Fa-f]{8})(?:(_fallback))?$")
_RAW_STATE_LABEL_RE = re.compile(r"^0x([0-9A-Fa-f]{8})(?:(_fallback))?$")
_STATE_LABEL_PREFIX_RE = re.compile(
    r"^STATE_([0-9A-Fa-f]{8})(?:(_fallback))?(?:__.+)?$"
)
_RAW_STATE_LABEL_PREFIX_RE = re.compile(
    r"^0x([0-9A-Fa-f]{8})(?:(_fallback))?(?:__.+)?$"
)
logger = logging.getLogger("D810.cfg.semantic_region_lowering")


@dataclass(frozen=True, slots=True)
class SemanticRegionLoweringSite:
    """One admissible semantic transition inside a structured region."""

    region_name: str
    site_kind: str
    source_state: int
    target_state: int
    source_entry_anchor: int
    source_anchor_block: int
    target_entry_anchor: int
    ordered_path: tuple[int, ...]
    edge: object
    semantic_target_label: str | None = None
    successor_state_value: int | None = None


@dataclass(frozen=True, slots=True)
class SemanticRegionFallbackLowering:
    """Fallback semantic-head lowering derived directly from a region contract."""

    emission_mode: str
    horizon_block: int
    target_entry_anchor: int


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


def _semantic_state_value_from_label(label_text: str | None) -> int | None:
    normalized = _normalize_semantic_target_label(label_text)
    if normalized is None:
        return None
    match = _STATE_LABEL_RE.match(normalized)
    if match is None:
        return None
    return int(match.group(1), 16) & 0xFFFFFFFF


def _infer_semantic_target_from_entry(
    dag: object,
    *,
    target_entry_anchor: int | None,
    target_state_value: int,
) -> tuple[str | None, int | None]:
    if target_entry_anchor is None:
        return None, None
    normalized_target_state = int(target_state_value) & 0xFFFFFFFF
    for node in getattr(dag, "nodes", ()) or ():
        owned_blocks = {
            int(block)
            for block in (
                getattr(node, "exclusive_blocks", ())
                or ()
            )
        }
        owned_blocks.update(
            int(block)
            for block in (
                getattr(node, "owned_blocks", ())
                or ()
            )
        )
        owned_blocks.update(
            int(block)
            for segment in (
                getattr(node, "local_segments", ())
                or ()
            )
            for block in (getattr(segment, "blocks", ()) or ())
        )
        if (
            int(getattr(node, "entry_anchor", -1)) != int(target_entry_anchor)
            and int(target_entry_anchor) not in owned_blocks
        ):
            continue
        candidate_label = _normalize_semantic_target_label(
            getattr(node, "state_label", None)
        )
        candidate_state = _semantic_state_value_from_label(candidate_label)
        if candidate_label is None or candidate_state is None:
            continue
        if candidate_state == normalized_target_state and not candidate_label.endswith("_fallback"):
            continue
        return candidate_label, candidate_state
    return None, None


def _select_site_horizon_block(
    site: SemanticRegionLoweringSite,
) -> int | None:
    branch_arm = getattr(getattr(site.edge, "source_anchor", None), "branch_arm", None)
    if branch_arm is not None:
        source_anchor_block = int(site.source_anchor_block)
        if (
            source_anchor_block >= 0
            and source_anchor_block in site.ordered_path
        ):
            return source_anchor_block
    if int(site.source_entry_anchor) >= 0:
        return int(site.source_entry_anchor)
    return None


@algorithm_metadata(
    algorithm_id="cfg.semantic_region_lowering",
    family="structured_region_semantic_lowering",
    summary="Filters structured-region transitions down to admissible semantic-entry lowering sites.",
    use_cases=(
        "Prevent region-first lowering from entering a semantic region through feeder rows or dispatcher-owned aliases.",
        "Provide a minimal semantic-region contract before compiling into GraphModification primitives.",
    ),
    examples=(
        "Accept an exact transition whose source anchor matches the source node entry anchor and whose target entry is non-BST.",
        "Reject a feeder row that only writes the next state but does not equal the semantic source node entry anchor.",
    ),
    tags=("semantic-region", "structured-lowering", "entry-admissibility", "sese"),
    related_paths=(
        "src/d810/cfg/semantic_region_lowering.py",
        "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/linearized_flow_graph.py",
    ),
)
def collect_admissible_region_lowering_sites(
    *,
    region,
    dag,
    node_by_key: dict[object, object],
    dispatcher_region: set[int] | frozenset[int],
    semantic_reference_program: object | None = None,
    dispatcher: object | None = None,
) -> tuple[SemanticRegionLoweringSite, ...]:
    """Return region-owned transitions that are safe semantic entries.

    This is intentionally narrower than "all outgoing region edges". A site is
    admissible only when the live DAG still says we are entering from the
    semantic source node's entry anchor rather than from a feeder row or
    dispatcher-owned alias block.
    """

    allowed_pairs = {
        (int(source_state), int(target_state))
        for source_state, target_state in getattr(region, "internal_state_edges", ())
    }
    region_states = {
        int(state) & 0xFFFFFFFF for state in getattr(region, "state_values", ())
    }
    exit_states = {
        int(state) & 0xFFFFFFFF for state in getattr(region, "exit_state_values", ())
    }
    dispatcher_blocks = {int(block) for block in dispatcher_region}
    accepted: list[SemanticRegionLoweringSite] = []

    semantic_entry_by_label = _collect_semantic_entry_by_label(
        semantic_reference_program
    )
    semantic_successors_by_state = _merge_region_contract_semantic_successors_by_state(
        region=region,
        semantic_successors_by_state=_collect_semantic_successors_by_state(
            semantic_reference_program
        ),
        semantic_entry_by_label=semantic_entry_by_label,
    )
    semantic_successors_by_state = _augment_region_contract_semantic_successors_by_state(
        region=region,
        dag=dag,
        semantic_successors_by_state=semantic_successors_by_state,
        semantic_entry_by_label=semantic_entry_by_label,
        dispatcher_blocks=dispatcher_blocks,
    )
    if str(getattr(region, "region_name", "")) == "sub7ffd_10743c4c_branch_region":
        logger.info(
            "semantic region contract: region=%s semantic_successors=%s",
            str(getattr(region, "region_name", "")),
            {
                f"0x{int(source_state) & 0xFFFFFFFF:08X}": tuple(str(label) for label in targets)
                for source_state, targets in semantic_successors_by_state.items()
                if (int(source_state) & 0xFFFFFFFF) in {
                    0x10743C4C,
                    0x6107F8EC,
                    0x7C2C0220,
                }
            },
        )

    for edge in getattr(dag, "edges", ()):
        source_state = getattr(getattr(edge, "source_key", None), "state_const", None)
        target_state = getattr(edge, "target_state", None)
        if source_state is None or target_state is None:
            continue
        source_state_value = int(source_state) & 0xFFFFFFFF
        target_state_value = int(target_state) & 0xFFFFFFFF
        debug_branch_alias = (
            str(getattr(region, "region_name", "")) == "sub7ffd_10743c4c_branch_region"
            and source_state_value == 0x6107F8EC
            and target_state_value == 0x4C77464F
        )
        if source_state_value == target_state_value:
            if debug_branch_alias:
                logger.info("semantic region reject: self-loop raw branch alias")
            continue
        state_pair = (source_state_value, target_state_value)
        semantic_labels = tuple(semantic_successors_by_state.get(source_state_value, ()))
        direct_semantic_label_candidates = (
            f"STATE_{target_state_value:08X}",
            f"0x{target_state_value:08X}",
        )
        has_direct_semantic_successor = any(
            label in semantic_labels for label in direct_semantic_label_candidates
        )
        site_kind: str | None = None
        if state_pair in allowed_pairs:
            site_kind = "internal"
        elif (
            source_state_value in region_states
            and target_state_value in exit_states
        ):
            site_kind = (
                "exit"
                if not semantic_labels or has_direct_semantic_successor
                else "exit_alias_candidate"
            )
        if site_kind is None:
            if (
                semantic_successors_by_state
                and source_state_value in region_states
                and source_state_value in semantic_successors_by_state
                and target_state_value not in region_states
            ):
                site_kind = "exit_alias_candidate"
        if site_kind is None:
            if (
                source_state_value in region_states
                and target_state_value not in region_states
                and is_raw_state_label(
                    str(getattr(edge, "target_label", "") or ""),
                    target_state_value,
                )
            ):
                site_kind = "exit_alias_candidate"
        # Terminal self-anchor: the region wraps a single state X with no
        # internal edges (no chain inside the region). For incoming DAG edges
        # from outside the region, treat the predecessor handler as a redirect
        # site so HCC can lower the dispatcher arm directly to X's entry anchor
        # instead of bouncing through the BST. This makes single-state terminal
        # regions actionable even when their semantic-program exit_state edges
        # are not present in the live DAG.
        if (
            site_kind is None
            and not allowed_pairs
            and len(region_states) == 1
            and target_state_value in region_states
            and source_state_value not in region_states
        ):
            site_kind = "terminal_self_anchor"
        if site_kind is None:
            if debug_branch_alias:
                logger.info(
                    "semantic region reject: no site kind src=0x%08X target=0x%08X semantic_labels=%s exit_states=%s",
                    source_state_value,
                    target_state_value,
                    semantic_labels,
                    sorted(int(state) for state in exit_states),
                )
            continue
        if (
            site_kind == "internal"
            and semantic_successors_by_state
            and source_state_value not in semantic_successors_by_state
        ):
            logger.info(
                "semantic region defer descendant internal site: region=%s src=0x%08X target=0x%08X path=%s",
                str(getattr(region, "region_name", "")),
                source_state_value,
                target_state_value,
                tuple(int(serial) for serial in (getattr(edge, "ordered_path", ()) or ())),
            )
            continue

        target_resolution = resolve_edge_target_entry(
            edge,
            node_by_key=node_by_key,
            dispatcher_region=dispatcher_blocks,
        )
        target_entry_anchor = target_resolution.target_entry
        raw_nonexact_target_applied = False
        ordered_path = tuple(
            int(serial) for serial in getattr(edge, "ordered_path", ()) or ()
        )
        nonexact_source_block = (
            ordered_path[-1]
            if ordered_path
            else int(getattr(getattr(edge, "source_anchor", None), "block_serial", -1))
        )
        if (
            dispatcher is not None
            and not dispatcher_has_exact_state_row(
                target_state_value,
                dispatcher=dispatcher,
            )
            and is_raw_state_label(
                str(getattr(edge, "target_label", "") or ""),
                target_state_value,
            )
        ):
            normalized_alias_entry = resolve_normalized_alias_entry_for_state(
                dag,
                target_state_value,
                source_block=nonexact_source_block,
                bst_node_blocks=dispatcher_blocks,
            )
            supplemental_selected_entry = _resolve_supplemental_selected_entry(
                dag,
                target_state_value,
            )
            nonexact_target_entry = resolve_nonexact_dispatch_target(
                dag,
                target_state_value,
                source_block=nonexact_source_block,
                bst_node_blocks=dispatcher_blocks,
                dispatcher=dispatcher,
            )
            if (
                source_state_value == 0x6107F8EC
                and target_state_value == 0x4C77464F
            ):
                logger.info(
                    "semantic region raw-nonexact override src=0x%08X target=0x%08X label=%s source_block=%s current=%s normalized=%s supplemental=%s nonexact=%s",
                    source_state_value,
                    target_state_value,
                    str(getattr(edge, "target_label", "") or ""),
                    int(nonexact_source_block),
                    None if target_resolution.target_entry is None else int(target_resolution.target_entry),
                    normalized_alias_entry,
                    supplemental_selected_entry,
                    nonexact_target_entry,
                )
            owner_semantic_head = _resolve_owner_semantic_head_for_candidates(
                dag,
                source_block=int(nonexact_source_block),
                dispatcher_blocks=dispatcher_blocks,
                candidates=(
                    supplemental_selected_entry,
                ),
            )
            generic_owner_semantic_head = _resolve_owner_semantic_head_for_candidates(
                dag,
                source_block=int(nonexact_source_block),
                dispatcher_blocks=dispatcher_blocks,
                candidates=(
                    target_resolution.target_entry,
                    normalized_alias_entry,
                    nonexact_target_entry,
                ),
            )
            preferred_candidates: list[int | None] = []
            if owner_semantic_head is not None:
                preferred_candidates.append(int(owner_semantic_head))
            if generic_owner_semantic_head is not None:
                preferred_candidates.append(int(generic_owner_semantic_head))
            preferred_candidates.extend(
                (
                    target_resolution.target_entry,
                    normalized_alias_entry,
                    nonexact_target_entry,
                    supplemental_selected_entry,
                )
            )
            preferred_raw_target = None
            for candidate in preferred_candidates:
                if candidate is None:
                    continue
                preferred_raw_target = int(candidate)
                break
            if preferred_raw_target is not None:
                target_entry_anchor = int(preferred_raw_target)
                raw_nonexact_target_applied = True
        semantic_target_label: str | None = None
        if not raw_nonexact_target_applied:
            target_entry_anchor, semantic_target_label = (
                _resolve_direct_semantic_successor_override(
                    dag=dag,
                    source_state=source_state_value,
                    target_state=target_state_value,
                    current_target_entry=target_entry_anchor,
                    ordered_path=ordered_path,
                    semantic_successors_by_state=semantic_successors_by_state,
                    semantic_entry_by_label=semantic_entry_by_label,
                    semantic_reference_program=semantic_reference_program,
                    dispatcher_blocks=dispatcher_blocks,
                )
            )
        inferred_semantic_target_label, inferred_successor_state_value = (
            _infer_semantic_target_from_entry(
                dag,
                target_entry_anchor=target_entry_anchor,
                target_state_value=target_state_value,
            )
        )
        if semantic_target_label is None and inferred_semantic_target_label is not None:
            semantic_target_label = inferred_semantic_target_label
        target_entry_anchor = _prefer_exact_target_head_over_path_entry(
            dag=dag,
            site_kind=site_kind,
            target_state=target_state_value,
            current_target_entry=target_entry_anchor,
            semantic_target_label=semantic_target_label,
            ordered_path=ordered_path,
            dispatcher_blocks=dispatcher_blocks,
        )
        if target_entry_anchor is None and site_kind != "exit_alias_candidate":
            if debug_branch_alias:
                logger.info("semantic region reject: no target entry after resolution")
            continue

        source_node = node_by_key.get(getattr(edge, "source_key", None))
        if source_node is None:
            if debug_branch_alias:
                logger.info("semantic region reject: no source node")
            continue

        source_entry_anchor = int(getattr(source_node, "entry_anchor", -1))
        source_owned_blocks = {
            int(block)
            for block in (
                getattr(source_node, "exclusive_blocks", ())
                or getattr(source_node, "owned_blocks", ())
                or ()
            )
        }
        source_owned_blocks.update(
            int(block)
            for block in (
                getattr(source_node, "shared_suffix_blocks", ())
                or ()
            )
        )
        source_owned_blocks.update(
            int(block)
            for segment in (
                getattr(source_node, "local_segments", ())
                or ()
            )
            for block in getattr(segment, "blocks", ()) or ()
        )
        if source_entry_anchor >= 0:
            source_owned_blocks.add(int(source_entry_anchor))
        target_entry_anchor = (
            int(target_entry_anchor) if target_entry_anchor is not None else -1
        )
        source_anchor_block = int(getattr(getattr(edge, "source_anchor", None), "block_serial", -1))
        exact_target_entry = resolve_exact_dag_entry_for_state(
            dag,
            target_state_value,
            dispatcher_region=dispatcher_blocks,
            allow_dispatcher_exact_head=True,
        )
        exact_source_entry = resolve_exact_dag_entry_for_state(
            dag,
            source_state_value,
            dispatcher_region=dispatcher_blocks,
            allow_dispatcher_exact_head=True,
        )
        exact_source_node = None
        if exact_source_entry is not None:
            for candidate_node in getattr(dag, "nodes", ()) or ():
                candidate_key = getattr(candidate_node, "key", None)
                candidate_state = getattr(candidate_key, "state_const", None)
                if (
                    candidate_state is not None
                    and (int(candidate_state) & 0xFFFFFFFF) == source_state_value
                    and int(getattr(candidate_node, "entry_anchor", -1)) == int(exact_source_entry)
                ):
                    exact_source_node = candidate_node
                    break
        if (
            source_entry_anchor in dispatcher_blocks
            and exact_source_entry is not None
            and int(exact_source_entry) not in dispatcher_blocks
            and int(exact_source_entry) != source_entry_anchor
        ):
            source_entry_anchor = int(exact_source_entry)
            source_owned_blocks.add(int(exact_source_entry))
            if exact_source_node is not None:
                source_owned_blocks.update(
                    int(block)
                    for block in (
                        getattr(exact_source_node, "exclusive_blocks", ())
                        or ()
                    )
                )
                source_owned_blocks.update(
                    int(block)
                    for block in (
                        getattr(exact_source_node, "owned_blocks", ())
                        or ()
                    )
                )
                source_owned_blocks.update(
                    int(block)
                    for block in (
                        getattr(exact_source_node, "shared_suffix_blocks", ())
                        or ()
                    )
                )
                source_owned_blocks.update(
                    int(block)
                    for segment in (
                        getattr(exact_source_node, "local_segments", ())
                        or ()
                    )
                    for block in getattr(segment, "blocks", ()) or ()
                )
        source_is_exact_head = (
            source_entry_anchor >= 0
            and exact_source_entry is not None
            and int(source_entry_anchor) == int(exact_source_entry)
        )
        target_is_exact_head = (
            target_entry_anchor >= 0
            and exact_target_entry is not None
            and int(target_entry_anchor) == int(exact_target_entry)
        )
        target_is_supplemental_selected_head = (
            target_entry_anchor >= 0
            and _resolve_supplemental_selected_entry(dag, target_state_value)
            is not None
            and int(target_entry_anchor)
            == int(_resolve_supplemental_selected_entry(dag, target_state_value))
        )

        if source_entry_anchor < 0 or (
            target_entry_anchor < 0 and site_kind != "exit_alias_candidate"
        ):
            if debug_branch_alias:
                logger.info(
                    "semantic region reject: invalid source/target entry source_entry=%s target_entry=%s kind=%s",
                    source_entry_anchor,
                    target_entry_anchor,
                    site_kind,
                )
            continue
        if (
            source_entry_anchor in dispatcher_blocks
            and not source_is_exact_head
        ) or (
            target_entry_anchor in dispatcher_blocks
            and site_kind != "exit_alias_candidate"
            and not target_is_exact_head
            and not target_is_supplemental_selected_head
        ):
            if debug_branch_alias:
                logger.info(
                    "semantic region reject: dispatcher entry source_entry=%s target_entry=%s source_exact=%s target_exact=%s target_supp=%s",
                    source_entry_anchor,
                    target_entry_anchor,
                    source_is_exact_head,
                    target_is_exact_head,
                    target_is_supplemental_selected_head,
                )
            continue
        if source_anchor_block not in source_owned_blocks:
            if debug_branch_alias:
                logger.info(
                    "semantic region reject: source anchor not owned source_block=%s owned=%s source_entry=%s exact_source_entry=%s",
                    source_anchor_block,
                    sorted(source_owned_blocks),
                    source_entry_anchor,
                    exact_source_entry,
                )
            continue

        accepted.append(
                SemanticRegionLoweringSite(
                    region_name=str(getattr(region, "region_name", "")),
                    site_kind=site_kind,
                    source_state=int(source_state) & 0xFFFFFFFF,
                    target_state=int(target_state) & 0xFFFFFFFF,
                    source_entry_anchor=source_entry_anchor,
                    source_anchor_block=source_anchor_block,
                    target_entry_anchor=target_entry_anchor,
                    ordered_path=ordered_path,
                    edge=edge,
                semantic_target_label=semantic_target_label,
                successor_state_value=(
                    inferred_successor_state_value
                    if inferred_successor_state_value is not None
                    else (
                        _semantic_state_value_from_label(semantic_target_label)
                        if semantic_target_label is not None
                        else int(target_state) & 0xFFFFFFFF
                    )
                ),
            )
        )

    accepted = _normalize_semantic_alias_targets(
        accepted,
        semantic_successors_by_state=semantic_successors_by_state,
        semantic_entry_by_label=semantic_entry_by_label,
    )
    accepted = _synthesize_missing_conditional_exit_sites(
        accepted,
        region_name=str(getattr(region, "region_name", "")),
        region_states=region_states,
        semantic_successors_by_state=semantic_successors_by_state,
        semantic_entry_by_label=semantic_entry_by_label,
        semantic_reference_program=semantic_reference_program,
        dag=dag,
        dispatcher_blocks=dispatcher_blocks,
    )

    if str(getattr(region, "region_name", "")) == "sub7ffd_10743c4c_branch_region":
        for site in accepted:
            logger.info(
                "semantic region site: region=%s kind=%s src=0x%08X target=0x%08X succ=%s source_entry=%s source_anchor=%s branch_arm=%s target_entry=%s semantic_label=%s path=%s",
                str(getattr(region, "region_name", "")),
                site.site_kind,
                int(site.source_state) & 0xFFFFFFFF,
                int(site.target_state) & 0xFFFFFFFF,
                None
                if site.successor_state_value is None
                else f"0x{int(site.successor_state_value) & 0xFFFFFFFF:08X}",
                int(site.source_entry_anchor),
                int(site.source_anchor_block),
                getattr(getattr(site.edge, "source_anchor", None), "branch_arm", None),
                int(site.target_entry_anchor),
                site.semantic_target_label,
                tuple(int(serial) for serial in site.ordered_path),
            )

    accepted.sort(
        key=lambda site: (
            site.site_kind,
            site.source_state,
            site.target_state,
            site.source_entry_anchor,
            site.target_entry_anchor,
            len(site.ordered_path),
        )
    )
    return tuple(accepted)


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


def _resolve_supplemental_selected_entry(
    dag: object,
    state_value: int,
) -> int | None:
    normalized_state = int(state_value) & 0xFFFFFFFF
    for candidate_state, anchor in getattr(dag, "supplemental_selected_entries", ()) or ():
        if (int(candidate_state) & 0xFFFFFFFF) == normalized_state:
            return int(anchor)
    return None


def _resolve_owner_semantic_head_for_candidates(
    dag: object,
    *,
    source_block: int,
    dispatcher_blocks: set[int],
    candidates: tuple[int | None, ...],
) -> int | None:
    anchor_candidates = tuple(
        int(candidate)
        for candidate in candidates
        if candidate is not None
    )
    if not anchor_candidates:
        return None
    owner_entry = resolve_owner_semantic_entry_for_blocks(
        dag,
        anchor_candidates=anchor_candidates,
        source_block=int(source_block),
        bst_node_blocks=dispatcher_blocks,
    )
    if owner_entry is None:
        return None
    return int(owner_entry)


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


def _preferred_semantic_labels_for_state(
    *,
    state_value: int,
    semantic_entry_by_label: dict[str, int],
) -> tuple[str, ...]:
    normalized_state = int(state_value) & 0xFFFFFFFF
    candidates: list[str] = []
    seen: set[str] = set()
    for label in semantic_entry_by_label:
        normalized_label = _normalize_semantic_target_label(label)
        if normalized_label is None:
            continue
        if _semantic_state_value_from_label(normalized_label) != normalized_state:
            continue
        if normalized_label in seen:
            continue
        seen.add(normalized_label)
        candidates.append(normalized_label)
    if not candidates:
        return ()
    candidates.sort(
        key=lambda label: (
            0 if label.startswith("STATE_") else 1,
            0 if not label.endswith("_fallback") else 1,
            label,
        )
    )
    return tuple(candidates)


def _merge_region_contract_semantic_successors_by_state(
    *,
    region: object,
    semantic_successors_by_state: dict[int, tuple[str, ...]],
    semantic_entry_by_label: dict[str, int],
) -> dict[int, tuple[str, ...]]:
    merged: dict[int, list[str]] = {
        int(source_state) & 0xFFFFFFFF: list(targets)
        for source_state, targets in semantic_successors_by_state.items()
        if targets
    }
    internal_targets_by_source: dict[int, list[int]] = {}
    for source_state, target_state in getattr(region, "internal_state_edges", ()) or ():
        normalized_source = int(source_state) & 0xFFFFFFFF
        normalized_target = int(target_state) & 0xFFFFFFFF
        bucket = internal_targets_by_source.setdefault(normalized_source, [])
        if normalized_target not in bucket:
            bucket.append(normalized_target)

    region_exit_states = [
        int(state) & 0xFFFFFFFF
        for state in getattr(region, "exit_state_values", ()) or ()
    ]
    region_states = {
        int(state) & 0xFFFFFFFF for state in getattr(region, "state_values", ()) or ()
    }
    for source_state in (
        int(state) & 0xFFFFFFFF for state in region_states
    ):
        contract_successor_states = internal_targets_by_source.get(source_state)
        is_leaf_exit_source = not contract_successor_states
        if not contract_successor_states:
            contract_successor_states = region_exit_states
        if not contract_successor_states:
            continue
        target_labels: list[str] = []
        for target_state in contract_successor_states:
            preferred_labels = _preferred_semantic_labels_for_state(
                state_value=target_state,
                semantic_entry_by_label=semantic_entry_by_label,
            )
            if not preferred_labels:
                continue
            label = preferred_labels[0]
            if label not in target_labels:
                target_labels.append(label)
        if not target_labels:
            continue
        existing_labels = [
            str(label)
            for label in merged.get(source_state, ())
            if isinstance(label, str)
        ]
        if is_leaf_exit_source:
            has_lossy_raw_exit_contract = False
            for target_state in contract_successor_states:
                preferred_labels = _preferred_semantic_labels_for_state(
                    state_value=target_state,
                    semantic_entry_by_label=semantic_entry_by_label,
                )
                if not preferred_labels:
                    has_lossy_raw_exit_contract = True
                    break
            existing_non_region_labels: list[str] = []
            for label in existing_labels:
                label_state = _semantic_state_value_from_label(label)
                if label_state is None or label_state in region_states:
                    continue
                if label not in existing_non_region_labels:
                    existing_non_region_labels.append(label)
            if (
                not has_lossy_raw_exit_contract
                and 1 < len(existing_non_region_labels) <= 2
            ):
                merged[source_state] = existing_non_region_labels
                continue
        # Region-owned sources should use their immediate semantic contract,
        # not every descendant label that happened to be rendered inside a
        # collapsed semantic-reference node span. Preserve the semantic
        # reference's local successor order when it already mentions the same
        # immediate targets, then append any missing contract labels.
        filtered_existing: list[str] = []
        target_label_set = set(target_labels)
        for label in existing_labels:
            if label in target_label_set and label not in filtered_existing:
                filtered_existing.append(label)
        if filtered_existing:
            merged[source_state] = filtered_existing
        else:
            merged[source_state] = list(target_labels)
    return {
        int(source_state) & 0xFFFFFFFF: tuple(targets)
        for source_state, targets in merged.items()
        if targets
    }


def _augment_region_contract_semantic_successors_by_state(
    *,
    region: object,
    dag: object,
    semantic_successors_by_state: dict[int, tuple[str, ...]],
    semantic_entry_by_label: dict[str, int],
    dispatcher_blocks: set[int],
) -> dict[int, tuple[str, ...]]:
    if not semantic_successors_by_state:
        return {}

    augmented: dict[int, list[str]] = {
        int(source_state) & 0xFFFFFFFF: list(targets)
        for source_state, targets in semantic_successors_by_state.items()
        if targets
    }
    internal_source_states = {
        int(source_state) & 0xFFFFFFFF
        for source_state, _target_state in getattr(region, "internal_state_edges", ()) or ()
    }
    region_states = {
        int(state) & 0xFFFFFFFF for state in getattr(region, "state_values", ()) or ()
    }
    region_exit_states = tuple(
        int(state) & 0xFFFFFFFF for state in getattr(region, "exit_state_values", ()) or ()
    )
    if not region_exit_states:
        return {
            int(source_state) & 0xFFFFFFFF: tuple(targets)
            for source_state, targets in augmented.items()
            if targets
        }

    for source_state in region_states:
        if source_state in internal_source_states:
            continue
        existing = augmented.setdefault(int(source_state) & 0xFFFFFFFF, [])
        source_entry_anchor = resolve_exact_dag_entry_for_state(
            dag,
            source_state,
            dispatcher_region=dispatcher_blocks,
            allow_dispatcher_exact_head=True,
        )
        for exit_state in region_exit_states:
            preferred_labels = [
                str(label)
                for label in _preferred_semantic_labels_for_state(
                    state_value=exit_state,
                    semantic_entry_by_label=semantic_entry_by_label,
                )
                if label not in existing
            ]
            labels_describe_raw_self = bool(preferred_labels) and all(
                (_semantic_state_value_from_label(label) == (int(exit_state) & 0xFFFFFFFF))
                and not str(label).endswith("_fallback")
                for label in preferred_labels
            )
            if not preferred_labels or labels_describe_raw_self:
                normalized_alias_entry = None
                has_raw_exit_alias_family = any(
                    (
                        getattr(getattr(node, "key", None), "state_const", None) is not None
                        and (int(getattr(getattr(node, "key", None), "state_const")) & 0xFFFFFFFF)
                        == (int(exit_state) & 0xFFFFFFFF)
                        and is_raw_state_label(
                            str(getattr(node, "state_label", "") or ""),
                            int(exit_state) & 0xFFFFFFFF,
                        )
                    )
                    for node in getattr(dag, "nodes", ()) or ()
                )
                if source_entry_anchor is not None and has_raw_exit_alias_family:
                    normalized_alias_entry = resolve_normalized_alias_entry_for_state(
                        dag,
                        exit_state,
                        source_block=int(source_entry_anchor),
                        bst_node_blocks=dispatcher_blocks,
                    )
                for candidate_entry in (
                    normalized_alias_entry,
                    _resolve_supplemental_selected_entry(dag, exit_state),
                    resolve_exact_dag_entry_for_state(
                        dag,
                        exit_state,
                        dispatcher_region=dispatcher_blocks,
                        allow_dispatcher_exact_head=True,
                    ),
                ):
                    if candidate_entry is None:
                        continue
                    inferred_label, inferred_state = _infer_semantic_target_from_entry(
                        dag,
                        target_entry_anchor=int(candidate_entry),
                        target_state_value=int(exit_state) & 0xFFFFFFFF,
                    )
                    if (
                        inferred_label is None
                        or inferred_state is None
                        or (int(inferred_state) & 0xFFFFFFFF) in region_states
                    ):
                        continue
                    if inferred_label not in existing:
                        existing.append(str(inferred_label))
                    preferred_labels = []
                    break
            for label in preferred_labels:
                if label not in existing:
                    existing.append(str(label))

    return {
        int(source_state) & 0xFFFFFFFF: tuple(targets)
        for source_state, targets in augmented.items()
        if targets
    }


def _normalize_semantic_alias_targets(
    sites: list[SemanticRegionLoweringSite],
    *,
    semantic_successors_by_state: dict[int, tuple[str, ...]],
    semantic_entry_by_label: dict[str, int],
) -> list[SemanticRegionLoweringSite]:
    if not sites or not semantic_successors_by_state or not semantic_entry_by_label:
        return list(sites)

    sites_by_source: dict[int, list[SemanticRegionLoweringSite]] = {}
    for site in sites:
        sites_by_source.setdefault(int(site.source_state), []).append(site)

    normalized: list[SemanticRegionLoweringSite] = []
    for source_state, source_sites in sites_by_source.items():
        semantic_labels = tuple(semantic_successors_by_state.get(source_state, ()))
        branch_semantic_label_by_arm: dict[int, str] = {}
        conditional_branch_arms = {
            int(branch_arm)
            for site in source_sites
            for branch_arm in (
                getattr(getattr(site.edge, "source_anchor", None), "branch_arm", None),
            )
            if branch_arm in (0, 1)
        }
        if len(semantic_labels) == 2 and conditional_branch_arms == {0, 1}:
            for site in source_sites:
                branch_arm = getattr(
                    getattr(site.edge, "source_anchor", None),
                    "branch_arm",
                    None,
                )
                if branch_arm not in (0, 1):
                    continue
                current_label = _normalize_semantic_target_label(site.semantic_target_label)
                if current_label is None:
                    direct_label = f"STATE_{int(site.target_state) & 0xFFFFFFFF:08X}"
                    if direct_label in semantic_labels:
                        current_label = direct_label
                if current_label is None or current_label not in semantic_labels:
                    continue
                branch_semantic_label_by_arm.setdefault(int(branch_arm), str(current_label))
            if (
                len(branch_semantic_label_by_arm) == 2
                and len(set(branch_semantic_label_by_arm.values())) == 1
            ):
                # Descendant-polluted projected paths can make both arms look
                # like the same semantic successor. In that case the observed
                # labels are not trustworthy; fall back to the immediate
                # semantic contract order instead of pinning both arms to the
                # same child.
                branch_semantic_label_by_arm = {}
            if len(branch_semantic_label_by_arm) == 1:
                missing_arm = 1 - next(iter(branch_semantic_label_by_arm))
                unmatched_labels = [
                    str(label)
                    for label in semantic_labels
                    if str(label) not in branch_semantic_label_by_arm.values()
                ]
                if len(unmatched_labels) == 1:
                    branch_semantic_label_by_arm[missing_arm] = unmatched_labels[0]
            if len(branch_semantic_label_by_arm) != 2:
                # Semantic reference successors preserve source order:
                # first target is the taken/conditional arm, second is
                # fallthrough.
                branch_semantic_label_by_arm = {
                    1: str(semantic_labels[0]),
                    0: str(semantic_labels[1]),
                }
        elif len(semantic_labels) == 2:
            branch_semantic_label_by_arm = {
                1: str(semantic_labels[0]),
                0: str(semantic_labels[1]),
            }
        matched_labels = {
            f"STATE_{site.target_state:08X}"
            for site in source_sites
            if site.site_kind != "exit_alias_candidate"
        }
        unmatched_labels = [
            label for label in semantic_labels if label not in matched_labels
        ]
        alias_sites = [site for site in source_sites if site.site_kind == "exit_alias_candidate"]
        alias_site_override: dict[int, SemanticRegionLoweringSite] = {}
        if alias_sites and len(unmatched_labels) == 1:
            target_label = unmatched_labels[0]
            target_entry_anchor = semantic_entry_by_label.get(target_label)
            if target_entry_anchor is not None:
                successor_state_value: int | None = None
                match = _STATE_LABEL_RE.match(target_label)
                if match is not None:
                    successor_state_value = int(match.group(1), 16) & 0xFFFFFFFF
                for alias_site in alias_sites:
                    normalized_target_state = (
                        int(successor_state_value) & 0xFFFFFFFF
                        if successor_state_value is not None
                        else int(alias_site.target_state) & 0xFFFFFFFF
                    )
                    alias_site_override[id(alias_site)] = SemanticRegionLoweringSite(
                        region_name=alias_site.region_name,
                        site_kind="exit",
                        source_state=alias_site.source_state,
                        target_state=normalized_target_state,
                        source_entry_anchor=alias_site.source_entry_anchor,
                        source_anchor_block=alias_site.source_anchor_block,
                        target_entry_anchor=int(target_entry_anchor),
                        ordered_path=alias_site.ordered_path,
                        edge=_clone_edge_with_normalized_target(
                            alias_site.edge,
                            target_state=normalized_target_state,
                            target_entry_anchor=int(target_entry_anchor),
                            target_label=target_label,
                            ordered_path=tuple(
                                int(serial) for serial in (alias_site.ordered_path or ())
                            ),
                        ),
                        semantic_target_label=target_label,
                        successor_state_value=successor_state_value,
                    )

        def _remap_site_to_semantic_successor(
            site: SemanticRegionLoweringSite,
        ) -> SemanticRegionLoweringSite:
            if not semantic_labels:
                return site

            target_state_value = int(site.target_state) & 0xFFFFFFFF
            successor_state_value = (
                target_state_value
                if site.successor_state_value is None
                else int(site.successor_state_value) & 0xFFFFFFFF
            )
            current_target_entry = int(site.target_entry_anchor)
            direct_target_label = f"STATE_{target_state_value:08X}"

            branch_arm = getattr(
                getattr(site.edge, "source_anchor", None),
                "branch_arm",
                None,
            )
            normalized_ordered_path = tuple(int(serial) for serial in (site.ordered_path or ()))
            current_source_anchor_block = int(
                getattr(
                    getattr(site.edge, "source_anchor", None),
                    "block_serial",
                    site.source_anchor_block,
                )
            )
            normalized_source_anchor_block = (
                int(normalized_ordered_path[0])
                if normalized_ordered_path
                and current_source_anchor_block not in normalized_ordered_path
                else int(current_source_anchor_block)
            )
            if branch_arm in (0, 1) and branch_semantic_label_by_arm:
                branch_target_label = branch_semantic_label_by_arm[int(branch_arm)]
                branch_target_entry = semantic_entry_by_label.get(branch_target_label)
                branch_successor_state_value = _semantic_state_value_from_label(
                    branch_target_label
                )
                if (
                    branch_target_entry is not None
                    and branch_successor_state_value is not None
                ):
                    normalized_ordered_path = tuple(
                        int(serial) for serial in (site.ordered_path or ())
                    )
                    return SemanticRegionLoweringSite(
                        region_name=site.region_name,
                        site_kind="exit",
                        source_state=site.source_state,
                        target_state=int(branch_successor_state_value) & 0xFFFFFFFF,
                        source_entry_anchor=site.source_entry_anchor,
                        source_anchor_block=site.source_anchor_block,
                        target_entry_anchor=int(branch_target_entry),
                        ordered_path=normalized_ordered_path,
                        edge=_clone_edge_with_normalized_target(
                            site.edge,
                            target_state=int(branch_successor_state_value) & 0xFFFFFFFF,
                            target_entry_anchor=int(branch_target_entry),
                            target_label=str(branch_target_label),
                            ordered_path=normalized_ordered_path,
                            source_anchor_block=normalized_source_anchor_block,
                            source_anchor_branch_arm=int(branch_arm),
                        ),
                        semantic_target_label=str(branch_target_label),
                        successor_state_value=(
                            int(branch_successor_state_value) & 0xFFFFFFFF
                        ),
                    )

            current_label = _normalize_semantic_target_label(site.semantic_target_label)
            if current_label is None:
                current_label = direct_target_label
            current_label_state = _semantic_state_value_from_label(current_label)
            current_label_entry = semantic_entry_by_label.get(current_label)
            direct_target_is_semantic_successor = direct_target_label in semantic_labels
            stale_current_label_for_target = (
                current_label in semantic_labels
                and direct_target_is_semantic_successor
                and current_label_state is not None
                and current_label_state != target_state_value
            )
            stale_current_entry_for_label = (
                current_label in semantic_labels
                and current_target_entry >= 0
                and current_label_entry is not None
                and int(current_label_entry) != current_target_entry
                and direct_target_is_semantic_successor
                and current_label_state is not None
                and current_label_state != target_state_value
            )
            stale_successor_for_direct_target = (
                direct_target_is_semantic_successor
                and successor_state_value != target_state_value
                and current_label in semantic_labels
            )
            if (
                current_label in semantic_labels
                and not stale_current_label_for_target
                and not stale_current_entry_for_label
                and not stale_successor_for_direct_target
            ):
                if branch_arm not in (0, 1) and branch_semantic_label_by_arm:
                    matching_arms = [
                        int(arm)
                        for arm, label in branch_semantic_label_by_arm.items()
                        if str(label) == str(current_label)
                    ]
                    if len(matching_arms) == 1:
                        inferred_branch_arm = int(matching_arms[0])
                        return SemanticRegionLoweringSite(
                            region_name=site.region_name,
                            site_kind=site.site_kind,
                            source_state=site.source_state,
                            target_state=site.target_state,
                            source_entry_anchor=site.source_entry_anchor,
                            source_anchor_block=normalized_source_anchor_block,
                            target_entry_anchor=site.target_entry_anchor,
                            ordered_path=normalized_ordered_path,
                            edge=_clone_edge_with_normalized_target(
                                site.edge,
                                target_state=int(site.target_state) & 0xFFFFFFFF,
                                target_entry_anchor=int(site.target_entry_anchor),
                                target_label=str(current_label),
                                ordered_path=normalized_ordered_path,
                                source_anchor_block=normalized_source_anchor_block,
                                source_anchor_branch_arm=inferred_branch_arm,
                            ),
                            semantic_target_label=str(current_label),
                            successor_state_value=successor_state_value,
                        )
                return site

            ordered_path = {
                int(block_serial)
                for block_serial in (site.ordered_path or ())
            }

            best_choice: tuple[tuple[int, int, int, int, int], str, int, int] | None = None
            for label in semantic_labels:
                entry_anchor = semantic_entry_by_label.get(label)
                state_value = _semantic_state_value_from_label(label)
                if entry_anchor is None or state_value is None:
                    continue
                entry_anchor = int(entry_anchor)
                state_value = int(state_value) & 0xFFFFFFFF
                score = (
                    1 if state_value == target_state_value else 0,
                    1 if state_value == successor_state_value else 0,
                    1 if entry_anchor == current_target_entry else 0,
                    1 if entry_anchor in ordered_path else 0,
                    -abs(entry_anchor - current_target_entry),
                )
                if best_choice is None or score > best_choice[0]:
                    best_choice = (score, str(label), state_value, entry_anchor)

            if best_choice is None:
                return site

            best_score, best_label, best_state_value, best_entry_anchor = best_choice
            if all(component <= 0 for component in best_score[:4]):
                return site

            inferred_branch_arm = None
            if branch_arm in (0, 1):
                inferred_branch_arm = int(branch_arm)
            elif branch_semantic_label_by_arm:
                matching_arms = [
                    int(arm)
                    for arm, label in branch_semantic_label_by_arm.items()
                    if str(label) == str(best_label)
                ]
                if len(matching_arms) == 1:
                    inferred_branch_arm = int(matching_arms[0])
            return SemanticRegionLoweringSite(
                region_name=site.region_name,
                site_kind="exit" if site.site_kind == "exit_alias_candidate" else site.site_kind,
                source_state=site.source_state,
                target_state=int(best_state_value) & 0xFFFFFFFF,
                source_entry_anchor=site.source_entry_anchor,
                source_anchor_block=normalized_source_anchor_block,
                target_entry_anchor=int(best_entry_anchor),
                ordered_path=normalized_ordered_path,
                edge=_clone_edge_with_normalized_target(
                    site.edge,
                    target_state=int(best_state_value) & 0xFFFFFFFF,
                    target_entry_anchor=int(best_entry_anchor),
                    target_label=str(best_label),
                    ordered_path=normalized_ordered_path,
                    source_anchor_block=normalized_source_anchor_block,
                    source_anchor_branch_arm=inferred_branch_arm,
                ),
                semantic_target_label=str(best_label),
                successor_state_value=int(best_state_value) & 0xFFFFFFFF,
            )

        for site in source_sites:
            remapped_site = _remap_site_to_semantic_successor(
                alias_site_override.get(id(site), site)
            )
            if remapped_site.site_kind == "exit_alias_candidate":
                continue
            normalized.append(remapped_site)
    return normalized


def _clone_edge_with_normalized_target(
    edge: object,
    *,
    target_state: int,
    target_entry_anchor: int,
    target_label: str | None,
    ordered_path: tuple[int, ...],
    source_anchor_block: int | None = None,
    source_anchor_branch_arm: int | None = None,
) -> object:
    edge_data = {}
    if hasattr(edge, "__dict__"):
        edge_data.update(vars(edge))
    else:
        for name in (
            "source_key",
            "target_key",
            "kind",
            "last_write_site",
            "source_anchor",
            "site",
        ):
            value = getattr(edge, name, None)
            if value is not None:
                edge_data[name] = value
    observed_target_state = getattr(
        edge,
        "observed_target_state",
        getattr(edge, "target_state", None),
    )
    edge_data.update(
        {
            "observed_target_state": (
                int(observed_target_state) & 0xFFFFFFFF
                if observed_target_state is not None
                else None
            ),
            "target_state": int(target_state) & 0xFFFFFFFF,
            "target_entry_anchor": int(target_entry_anchor),
            "target_label": target_label,
            "ordered_path": tuple(int(serial) for serial in ordered_path),
        }
    )
    edge_data.setdefault("source_key", getattr(edge, "source_key", None))
    edge_data.setdefault("target_key", getattr(edge, "target_key", None))
    edge_data.setdefault("kind", getattr(edge, "kind", None))
    edge_data.setdefault("last_write_site", getattr(edge, "last_write_site", None))
    edge_data.setdefault("source_anchor", getattr(edge, "source_anchor", None))
    edge_data.setdefault("site", getattr(edge, "site", None))
    if source_anchor_block is not None or source_anchor_branch_arm is not None:
        current_source_anchor = edge_data.get("source_anchor", None)
        edge_data["source_anchor"] = SimpleNamespace(
            block_serial=(
                int(source_anchor_block)
                if source_anchor_block is not None
                else getattr(current_source_anchor, "block_serial", None)
            ),
            kind=getattr(current_source_anchor, "kind", None),
            branch_arm=(
                int(source_anchor_branch_arm)
                if source_anchor_branch_arm is not None
                else getattr(current_source_anchor, "branch_arm", None)
            ),
        )
    return SimpleNamespace(**edge_data)


def _truncate_ordered_path_for_child_entry(
    ordered_path: tuple[int, ...] | list[int] | None,
    *,
    child_entry_anchor: int,
) -> tuple[int, ...]:
    path = tuple(int(serial) for serial in (ordered_path or ()))
    child_entry = int(child_entry_anchor)
    if child_entry < 0 or not path:
        return path
    try:
        child_index = path.index(child_entry)
    except ValueError:
        return path
    return path[: child_index + 1]


def _build_semantic_child_ordered_path(
    site: SemanticRegionLoweringSite,
    *,
    child_entry_anchor: int,
) -> tuple[int, ...]:
    child_entry = int(child_entry_anchor)
    if child_entry < 0:
        return tuple(int(serial) for serial in (site.ordered_path or ()))
    source_anchor_block = int(
        getattr(
            getattr(site.edge, "source_anchor", None),
            "block_serial",
            site.source_anchor_block,
        )
    )
    branch_arm = getattr(getattr(site.edge, "source_anchor", None), "branch_arm", None)
    if branch_arm in (0, 1) and source_anchor_block >= 0 and source_anchor_block != child_entry:
        return (source_anchor_block, child_entry)
    source_entry_anchor = int(site.source_entry_anchor)
    if source_entry_anchor >= 0 and source_entry_anchor != child_entry:
        return (source_entry_anchor, child_entry)
    if source_anchor_block >= 0 and source_anchor_block != child_entry:
        return (source_anchor_block, child_entry)
    return (child_entry,)


def _normalize_branch_horizon_path(
    ordered_path: tuple[int, ...] | list[int] | None,
    *,
    source_anchor_block: int,
) -> tuple[int, ...]:
    path = tuple(int(serial) for serial in (ordered_path or ()))
    source_anchor = int(source_anchor_block)
    if source_anchor < 0:
        return path
    if source_anchor in path:
        path = path[path.index(source_anchor) :]
    elif not path or int(path[0]) != source_anchor:
        path = (source_anchor,) + path
    if len(path) >= 2 and int(path[0]) == source_anchor:
        return (int(path[0]), int(path[1]))
    return (source_anchor,)


def _collect_observed_conditional_branch_contexts(
    dag: object | None,
    *,
    source_state_value: int,
) -> dict[int, tuple[object, int, tuple[int, ...]]]:
    if dag is None:
        return {}
    contexts: dict[int, tuple[tuple[int, int, int, int], object, int, tuple[int, ...]]] = {}
    for edge in getattr(dag, "edges", ()) or ():
        source_key = getattr(edge, "source_key", None)
        if source_key is None:
            continue
        try:
            edge_source_state = int(getattr(source_key, "state_const")) & 0xFFFFFFFF
        except (TypeError, ValueError):
            continue
        if edge_source_state != (int(source_state_value) & 0xFFFFFFFF):
            continue
        source_anchor = getattr(edge, "source_anchor", None)
        branch_arm = getattr(source_anchor, "branch_arm", None)
        if branch_arm not in (0, 1):
            continue
        source_anchor_block = int(getattr(source_anchor, "block_serial", -1))
        normalized_path = _normalize_branch_horizon_path(
            getattr(edge, "ordered_path", ()) or (),
            source_anchor_block=source_anchor_block,
        )
        if not normalized_path:
            continue
        score = (
            0 if str(getattr(edge, "kind", "")) == "conditional_transition" else 1,
            len(normalized_path),
            0 if len(normalized_path) >= 2 else 1,
            abs(int(normalized_path[0]) - source_anchor_block),
        )
        branch_arm_value = int(branch_arm)
        current = contexts.get(branch_arm_value)
        if current is None or score < current[0]:
            contexts[branch_arm_value] = (
                score,
                source_key,
                source_anchor_block,
                normalized_path,
            )
    return {
        int(branch_arm): (source_key, int(source_anchor_block), tuple(normalized_path))
        for branch_arm, (_, source_key, source_anchor_block, normalized_path) in contexts.items()
    }


def _synthesize_missing_conditional_exit_sites(
    sites: list[SemanticRegionLoweringSite],
    *,
    region_name: str | None = None,
    region_states: set[int],
    semantic_successors_by_state: dict[int, tuple[str, ...]],
    semantic_entry_by_label: dict[str, int],
    semantic_reference_program: object | None = None,
    dag: object | None = None,
    dispatcher_blocks: set[int] | None = None,
) -> list[SemanticRegionLoweringSite]:
    if not sites or not semantic_successors_by_state or not semantic_entry_by_label:
        return list(sites)

    synthesized: list[SemanticRegionLoweringSite] = list(sites)
    sites_by_source: dict[int, list[SemanticRegionLoweringSite]] = {}
    for site in sites:
        sites_by_source.setdefault(int(site.source_state) & 0xFFFFFFFF, []).append(site)

    def _canonicalize_semantic_labels(
        labels: tuple[str, ...] | list[str],
    ) -> tuple[str, ...]:
        preferred_by_state: dict[int | str, tuple[tuple[int, int, str], str]] = {}
        order: list[int | str] = []
        for raw_label in labels:
            label = str(raw_label)
            normalized_label = _normalize_semantic_target_label(label) or label
            label_state = _semantic_state_value_from_label(normalized_label)
            label_key: int | str = (
                int(label_state) & 0xFFFFFFFF
                if label_state is not None
                else normalized_label
            )
            if label_key not in preferred_by_state:
                order.append(label_key)
            score = (
                0 if normalized_label.startswith("STATE_") else 1,
                0 if not normalized_label.endswith("_fallback") else 1,
                normalized_label,
            )
            current = preferred_by_state.get(label_key)
            if current is None or score < current[0]:
                preferred_by_state[label_key] = (score, normalized_label)
        return tuple(
            preferred_by_state[label_key][1]
            for label_key in order
            if label_key in preferred_by_state
        )

    for source_state, source_sites in sites_by_source.items():
        semantic_labels = _canonicalize_semantic_labels(
            tuple(semantic_successors_by_state.get(source_state, ()))
        )
        if len(semantic_labels) != 2:
            continue
        conditional_sites = [
            site
            for site in source_sites
            if getattr(getattr(site.edge, "source_anchor", None), "branch_arm", None) in (0, 1)
        ]
        if not conditional_sites:
            continue
        observed_branch_arms = {
            int(getattr(getattr(site.edge, "source_anchor", None), "branch_arm", -1))
            for site in conditional_sites
        }
        if len(observed_branch_arms) != 1:
            continue
        template_branch_arm = next(iter(observed_branch_arms))
        template_site = min(
            conditional_sites,
            key=lambda site: (
                len(tuple(int(serial) for serial in (site.ordered_path or ()))),
                int(site.target_entry_anchor),
                int(site.target_state) & 0xFFFFFFFF,
            ),
        )
        existing_labels: set[str] = set()
        for site in conditional_sites:
            if site.semantic_target_label is not None:
                existing_labels.add(str(site.semantic_target_label))
                continue
            successor_state = site.successor_state_value
            if successor_state is None:
                successor_state = int(site.target_state) & 0xFFFFFFFF
            existing_labels.add(f"STATE_{int(successor_state) & 0xFFFFFFFF:08X}")
        unmatched_labels = [
            str(label) for label in semantic_labels if str(label) not in existing_labels
        ]
        if len(unmatched_labels) != 1:
            continue
        target_label = unmatched_labels[0]
        target_entry_anchor = semantic_entry_by_label.get(target_label)
        successor_state_value = _semantic_state_value_from_label(target_label)
        if target_entry_anchor is None or successor_state_value is None:
            continue
        successor_state_value = int(successor_state_value) & 0xFFFFFFFF
        if successor_state_value in region_states:
            continue
        missing_branch_arm = 1 - int(template_branch_arm)
        template_edge = template_site.edge
        source_entry_anchor = int(template_site.source_entry_anchor)
        source_key = StateDagNodeKey(
            handler_serial=int(source_entry_anchor),
            state_const=int(source_state) & 0xFFFFFFFF,
        )
        observed_context_by_arm = _collect_observed_conditional_branch_contexts(
            dag,
            source_state_value=int(source_state) & 0xFFFFFFFF,
        )
        observed_context = observed_context_by_arm.get(int(missing_branch_arm))
        source_anchor_block = int(source_entry_anchor)
        ordered_path = (int(source_entry_anchor),)
        if observed_context is not None:
            observed_source_key, observed_source_anchor_block, observed_ordered_path = observed_context
            observed_source_entry_anchor = int(
                getattr(observed_source_key, "handler_serial", observed_source_anchor_block)
            )
            if observed_source_entry_anchor >= 0:
                source_entry_anchor = int(observed_source_entry_anchor)
            source_key = observed_source_key
            source_anchor_block = int(observed_source_anchor_block)
            ordered_path = tuple(int(serial) for serial in observed_ordered_path)
        synthetic_edge = SimpleNamespace(
            source_key=source_key,
            target_key=None,
            target_state=int(successor_state_value),
            kind=getattr(template_edge, "kind", None),
            last_write_site=getattr(template_edge, "last_write_site", None),
            source_anchor=SimpleNamespace(
                block_serial=int(source_anchor_block),
                kind=getattr(
                    getattr(template_edge, "source_anchor", None),
                    "kind",
                    None,
                ),
                branch_arm=int(missing_branch_arm),
            ),
            target_entry_anchor=int(target_entry_anchor),
            target_label=str(target_label),
            ordered_path=tuple(int(serial) for serial in ordered_path),
            site=getattr(template_edge, "site", None),
        )
        synthesized.append(
            SemanticRegionLoweringSite(
                region_name=template_site.region_name,
                site_kind="exit",
                source_state=int(source_state) & 0xFFFFFFFF,
                target_state=int(successor_state_value) & 0xFFFFFFFF,
                source_entry_anchor=int(source_entry_anchor),
                source_anchor_block=int(source_anchor_block),
                target_entry_anchor=int(target_entry_anchor),
                ordered_path=tuple(int(serial) for serial in ordered_path),
                edge=synthetic_edge,
                semantic_target_label=str(target_label),
                successor_state_value=int(successor_state_value) & 0xFFFFFFFF,
            )
        )

    if dag is None:
        return synthesized

    dispatcher_region = {
        int(block) for block in (dispatcher_blocks or ())
    }
    existing_signatures = {
        (
            int(site.source_state) & 0xFFFFFFFF,
            int(site.successor_state_value) & 0xFFFFFFFF,
            (
                int(branch_arm)
                if (
                    branch_arm := getattr(
                        getattr(site.edge, "source_anchor", None),
                        "branch_arm",
                        None,
                    )
                )
                is not None
                else -1
            ),
        )
        for site in synthesized
        if site.successor_state_value is not None
    }
    for source_state, semantic_labels in semantic_successors_by_state.items():
        semantic_labels = _canonicalize_semantic_labels(tuple(semantic_labels))
        if len(semantic_labels) != 2:
            if (
                str(region_name or "") == "sub7ffd_10743c4c_branch_region"
                and (int(source_state) & 0xFFFFFFFF) == 0x6107F8EC
            ):
                logger.info(
                    "semantic region synth skip: region=%s src=0x%08X reason=semantic_label_count labels=%s",
                    str(region_name or ""),
                    int(source_state) & 0xFFFFFFFF,
                    tuple(str(label) for label in semantic_labels),
                )
            continue
        source_state_value = int(source_state) & 0xFFFFFFFF
        if source_state_value not in region_states:
            continue
        existing_source_sites = sites_by_source.get(source_state_value, [])
        if existing_source_sites:
            if (
                str(region_name or "") == "sub7ffd_10743c4c_branch_region"
                and source_state_value == 0x6107F8EC
            ):
                logger.info(
                    "semantic region synth skip: region=%s src=0x%08X reason=existing_sites count=%d",
                    str(region_name or ""),
                    source_state_value,
                    len(existing_source_sites),
                )
            continue
        source_entry_anchor = resolve_semantic_reference_entry_for_state(
            source_state_value,
            semantic_reference_program=semantic_reference_program,
            dispatcher_region=dispatcher_region,
            allow_dispatcher_exact_head=True,
        )
        if source_entry_anchor is None:
            source_entry_anchor = resolve_exact_dag_entry_for_state(
                dag,
                source_state_value,
                dispatcher_region=dispatcher_region,
                allow_dispatcher_exact_head=True,
            )
        if source_entry_anchor is None:
            if (
                str(region_name or "") == "sub7ffd_10743c4c_branch_region"
                and source_state_value == 0x6107F8EC
            ):
                logger.info(
                    "semantic region synth skip: region=%s src=0x%08X reason=no_source_entry",
                    str(region_name or ""),
                    source_state_value,
                )
            continue
        source_entry_anchor = int(source_entry_anchor)
        if source_entry_anchor < 0:
            continue
        observed_context_by_arm = _collect_observed_conditional_branch_contexts(
            dag,
            source_state_value=source_state_value,
        )
        default_source_key = StateDagNodeKey(
            handler_serial=int(source_entry_anchor),
            state_const=int(source_state_value) & 0xFFFFFFFF,
        )
        for branch_arm, target_label in ((1, semantic_labels[0]), (0, semantic_labels[1])):
            successor_state_value = _semantic_state_value_from_label(target_label)
            target_entry_anchor = semantic_entry_by_label.get(str(target_label))
            if successor_state_value is None or target_entry_anchor is None:
                if (
                    str(region_name or "") == "sub7ffd_10743c4c_branch_region"
                    and source_state_value == 0x6107F8EC
                ):
                    logger.info(
                        "semantic region synth skip: region=%s src=0x%08X reason=missing_target_entry label=%s state=%s",
                        str(region_name or ""),
                        source_state_value,
                        str(target_label),
                        successor_state_value,
                    )
                continue
            successor_state_value = int(successor_state_value) & 0xFFFFFFFF
            target_entry_anchor = int(target_entry_anchor)
            site_kind = (
                "internal"
                if successor_state_value in region_states
                else "exit"
            )
            signature = (
                int(source_state_value) & 0xFFFFFFFF,
                int(successor_state_value) & 0xFFFFFFFF,
                int(branch_arm),
            )
            if signature in existing_signatures:
                continue
            observed_context = observed_context_by_arm.get(int(branch_arm))
            branch_source_entry_anchor = int(source_entry_anchor)
            branch_source_anchor_block = int(source_entry_anchor)
            branch_ordered_path = (int(source_entry_anchor),)
            branch_source_key = default_source_key
            if observed_context is not None:
                observed_source_key, observed_source_anchor_block, observed_ordered_path = observed_context
                observed_source_entry_anchor = int(
                    getattr(observed_source_key, "handler_serial", observed_source_anchor_block)
                )
                if observed_source_entry_anchor >= 0:
                    branch_source_entry_anchor = int(observed_source_entry_anchor)
                branch_source_anchor_block = int(observed_source_anchor_block)
                branch_ordered_path = tuple(int(serial) for serial in observed_ordered_path)
                branch_source_key = observed_source_key
            synthetic_edge = SimpleNamespace(
                source_key=branch_source_key,
                target_key=None,
                target_state=int(successor_state_value) & 0xFFFFFFFF,
                kind="conditional_transition",
                last_write_site=None,
                source_anchor=SimpleNamespace(
                    block_serial=int(branch_source_anchor_block),
                    kind="conditional_transition",
                    branch_arm=int(branch_arm),
                ),
                target_entry_anchor=int(target_entry_anchor),
                target_label=str(target_label),
                ordered_path=tuple(int(serial) for serial in branch_ordered_path),
                site=None,
            )
            synthesized.append(
                SemanticRegionLoweringSite(
                    region_name=str(region_name or "synthetic_conditional_region_site"),
                    site_kind=site_kind,
                    source_state=int(source_state_value) & 0xFFFFFFFF,
                    target_state=int(successor_state_value) & 0xFFFFFFFF,
                    source_entry_anchor=int(branch_source_entry_anchor),
                    source_anchor_block=int(branch_source_anchor_block),
                    target_entry_anchor=int(target_entry_anchor),
                    ordered_path=tuple(int(serial) for serial in branch_ordered_path),
                    edge=synthetic_edge,
                    semantic_target_label=str(target_label),
                    successor_state_value=int(successor_state_value) & 0xFFFFFFFF,
                )
            )
            existing_signatures.add(signature)
            if (
                str(region_name or "") == "sub7ffd_10743c4c_branch_region"
                and source_state_value == 0x6107F8EC
            ):
                logger.info(
                    "semantic region synth add: region=%s src=0x%08X branch_arm=%d succ=0x%08X target_entry=%d label=%s",
                    str(region_name or ""),
                    source_state_value,
                    int(branch_arm),
                    int(successor_state_value) & 0xFFFFFFFF,
                    int(target_entry_anchor),
                    str(target_label),
                )

    return synthesized


def override_exit_sites_with_child_region_entries(
    sites: tuple[SemanticRegionLoweringSite, ...] | list[SemanticRegionLoweringSite],
    *,
    current_region_name: str,
    structured_regions: tuple[object, ...] | list[object],
    dag: object,
    dispatcher_region: set[int] | frozenset[int],
    semantic_reference_program: object | None = None,
    dispatcher: object | None = None,
) -> tuple[SemanticRegionLoweringSite, ...]:
    if not sites or not structured_regions:
        return tuple(sites)

    child_entry_states = {
        int(getattr(region, "entry_state")) & 0xFFFFFFFF
        for region in structured_regions
        if str(getattr(region, "region_name", "")) != str(current_region_name)
        and getattr(region, "entry_state", None) is not None
    }
    if not child_entry_states:
        return tuple(sites)

    dispatcher_blocks = {int(block) for block in dispatcher_region}
    semantic_entry_by_label = _collect_semantic_entry_by_label(
        semantic_reference_program
    )
    child_region_names_by_state = {
        int(getattr(region, "entry_state")) & 0xFFFFFFFF: str(getattr(region, "region_name", ""))
        for region in structured_regions
        if str(getattr(region, "region_name", "")) != str(current_region_name)
        and getattr(region, "entry_state", None) is not None
    }
    overridden: list[SemanticRegionLoweringSite] = []
    for site in sites:
        raw_target_state = int(site.target_state) & 0xFFFFFFFF
        inferred_target_state = (
            int(site.successor_state_value) & 0xFFFFFFFF
            if site.successor_state_value is not None
            else (
                _semantic_state_value_from_label(site.semantic_target_label)
                if site.semantic_target_label is not None
                else raw_target_state
            )
        )
        effective_target_state = (
            raw_target_state
            if raw_target_state in child_entry_states
            else inferred_target_state
        )
        if (
            site.site_kind not in {"exit", "exit_alias_candidate"}
            or effective_target_state not in child_entry_states
        ):
            overridden.append(site)
            continue
        branch_arm = getattr(getattr(site.edge, "source_anchor", None), "branch_arm", None)
        target_source_block = (
            int(site.ordered_path[1])
            if (
                branch_arm is not None
                and len(site.ordered_path) >= 2
                and int(site.ordered_path[0])
                in {
                    int(site.source_entry_anchor),
                    int(site.source_anchor_block),
                }
            )
            else (
                int(site.ordered_path[-1])
                if site.ordered_path
                else int(site.source_anchor_block)
            )
        )
        normalized_child_entry = resolve_normalized_alias_entry_for_state(
            dag,
            effective_target_state,
            source_block=target_source_block,
            bst_node_blocks=dispatcher_blocks,
        )
        supplemental_selected_entry = _resolve_supplemental_selected_entry(
            dag,
            effective_target_state,
        )
        semantic_target_label = str(
            site.semantic_target_label or f"STATE_{effective_target_state:08X}"
        )
        direct_effective_target_label = f"STATE_{int(effective_target_state) & 0xFFFFFFFF:08X}"
        current_semantic_target_state = _semantic_state_value_from_label(
            semantic_target_label
        )
        if (
            direct_effective_target_label in semantic_entry_by_label
            and current_semantic_target_state is not None
            and current_semantic_target_state != int(effective_target_state) & 0xFFFFFFFF
        ):
            semantic_target_label = direct_effective_target_label
        semantic_reference_entry = semantic_entry_by_label.get(semantic_target_label)
        if semantic_reference_entry is not None:
            semantic_reference_entry = int(semantic_reference_entry)
        else:
            semantic_reference_entry = resolve_semantic_reference_entry_for_state(
                effective_target_state,
                semantic_reference_program=semantic_reference_program,
                dispatcher_region=dispatcher_blocks,
                allow_dispatcher_exact_head=True,
            )
        if (
            semantic_reference_entry is not None
            and int(semantic_reference_entry) in dispatcher_blocks
        ):
            semantic_reference_entry = int(semantic_reference_entry)
        child_exact_entry = resolve_exact_dag_entry_for_state(
            dag,
            effective_target_state,
            dispatcher_region=dispatcher_blocks,
            allow_dispatcher_exact_head=True,
        )
        exact_dispatcher_entry = dispatcher_exact_state_target(
            effective_target_state,
            dispatcher=dispatcher,
        )
        source_entry_anchor = int(site.source_entry_anchor)

        def _normalize_entry(value: int | None) -> int | None:
            return None if value is None else int(value)

        normalized_child_entry = _normalize_entry(normalized_child_entry)
        supplemental_selected_entry = _normalize_entry(supplemental_selected_entry)
        semantic_reference_entry = _normalize_entry(semantic_reference_entry)
        child_exact_entry = _normalize_entry(child_exact_entry)
        exact_dispatcher_entry = _normalize_entry(exact_dispatcher_entry)
        owner_child_entry = _resolve_owner_semantic_head_for_candidates(
            dag,
            source_block=target_source_block,
            dispatcher_blocks=dispatcher_blocks,
            candidates=(
                supplemental_selected_entry,
            ),
        )
        generic_owner_child_entry = _resolve_owner_semantic_head_for_candidates(
            dag,
            source_block=target_source_block,
            dispatcher_blocks=dispatcher_blocks,
            candidates=(
                normalized_child_entry,
                semantic_reference_entry,
                child_exact_entry,
                site.target_entry_anchor,
            ),
        )

        distinct_child_entry = None
        for candidate in (child_exact_entry, exact_dispatcher_entry):
            if candidate is None:
                continue
            if candidate == source_entry_anchor:
                continue
            distinct_child_entry = candidate
            break

        current_target_entry = int(site.target_entry_anchor)
        current_matches_effective_target = (
            current_target_entry >= 0
            and (
                current_target_entry == normalized_child_entry
                or current_target_entry == semantic_reference_entry
                or current_target_entry == child_exact_entry
                or current_target_entry == exact_dispatcher_entry
            )
        )

        if owner_child_entry is not None and owner_child_entry != source_entry_anchor:
            child_entry_anchor = owner_child_entry
        elif (
            normalized_child_entry is not None
            and normalized_child_entry != source_entry_anchor
            and (
                not current_matches_effective_target
                or current_target_entry in dispatcher_blocks
                or current_target_entry == source_entry_anchor
            )
        ):
            child_entry_anchor = normalized_child_entry
        elif (
            exact_dispatcher_entry is not None
            and exact_dispatcher_entry != source_entry_anchor
            and (
                current_target_entry == source_entry_anchor
                or semantic_reference_entry == source_entry_anchor
                or child_exact_entry == source_entry_anchor
                or normalized_child_entry == source_entry_anchor
            )
        ):
            child_entry_anchor = exact_dispatcher_entry
        elif (
            current_matches_effective_target
            and current_target_entry not in dispatcher_blocks
            and current_target_entry != source_entry_anchor
        ):
            child_entry_anchor = current_target_entry
        else:
            child_entry_anchor = (
                (
                    child_exact_entry
                    if child_exact_entry != source_entry_anchor
                    else None
                )
                or exact_dispatcher_entry
                or (
                    generic_owner_child_entry
                    if generic_owner_child_entry != source_entry_anchor
                    else None
                )
                or current_target_entry
                or semantic_reference_entry
                or child_exact_entry
                or normalized_child_entry
                or distinct_child_entry
            )
        logger.info(
            "semantic region child-entry override: region=%s child=%s target=0x%08X label=%s current=%s normalized_child=%s supplemental=%s owner_child=%s generic_owner_child=%s semantic_ref=%s child_exact=%s dispatcher_exact=%s",
            current_region_name,
            child_region_names_by_state.get(effective_target_state),
            effective_target_state,
            semantic_target_label,
            int(site.target_entry_anchor),
            (
                None
                if normalized_child_entry is None
                else int(normalized_child_entry)
            ),
            (
                None
                if supplemental_selected_entry is None
                else int(supplemental_selected_entry)
            ),
            (
                None
                if owner_child_entry is None
                else int(owner_child_entry)
            ),
            (
                None
                if generic_owner_child_entry is None
                else int(generic_owner_child_entry)
            ),
            (
                None
                if semantic_reference_entry is None
                else int(semantic_reference_entry)
            ),
            (
                None
                if child_exact_entry is None
                else int(child_exact_entry)
            ),
            (
                None
                if exact_dispatcher_entry is None
                else int(exact_dispatcher_entry)
            ),
        )
        if child_entry_anchor is None:
            overridden.append(site)
            continue
        normalized_successor_state = int(effective_target_state) & 0xFFFFFFFF
        normalized_target_label = semantic_target_label
        current_successor_state = (
            None
            if site.successor_state_value is None
            else int(site.successor_state_value) & 0xFFFFFFFF
        )
        current_target_label = (
            None
            if site.semantic_target_label is None
            else str(site.semantic_target_label)
        )
        normalized_ordered_path = tuple(int(serial) for serial in (site.ordered_path or ()))
        if (
            int(child_entry_anchor) != int(site.target_entry_anchor)
            or current_successor_state != normalized_successor_state
            or current_target_label != normalized_target_label
        ):
            normalized_ordered_path = _build_semantic_child_ordered_path(
                site,
                child_entry_anchor=int(child_entry_anchor),
            )
        if (
            int(child_entry_anchor) == int(site.target_entry_anchor)
            and current_successor_state == normalized_successor_state
            and current_target_label == normalized_target_label
            and tuple(int(serial) for serial in (site.ordered_path or ()))
            == normalized_ordered_path
        ):
            overridden.append(site)
            continue
        overridden.append(
            SemanticRegionLoweringSite(
                region_name=site.region_name,
                site_kind=site.site_kind,
                source_state=site.source_state,
                target_state=normalized_successor_state,
                source_entry_anchor=site.source_entry_anchor,
                source_anchor_block=site.source_anchor_block,
                target_entry_anchor=int(child_entry_anchor),
                ordered_path=normalized_ordered_path,
                edge=_clone_edge_with_normalized_target(
                    site.edge,
                    target_state=normalized_successor_state,
                    target_entry_anchor=int(child_entry_anchor),
                    target_label=normalized_target_label,
                    ordered_path=normalized_ordered_path,
                ),
                semantic_target_label=normalized_target_label,
                successor_state_value=normalized_successor_state,
            )
        )
    normalized_overrides: list[SemanticRegionLoweringSite] = []
    for site in overridden:
        normalized_label = (
            None
            if getattr(site, "semantic_target_label", None) is None
            else str(getattr(site, "semantic_target_label"))
        )
        normalized_successor = (
            _semantic_state_value_from_label(normalized_label)
            if normalized_label is not None
            else None
        )
        current_successor = getattr(site, "successor_state_value", None)
        if (
            normalized_label is None
            or normalized_successor is None
            or current_successor is None
            or (int(current_successor) & 0xFFFFFFFF)
            == (int(normalized_successor) & 0xFFFFFFFF)
        ):
            normalized_overrides.append(site)
            continue
        normalized_overrides.append(
            SemanticRegionLoweringSite(
                region_name=str(getattr(site, "region_name", "")),
                site_kind=str(getattr(site, "site_kind", "")),
                source_state=int(getattr(site, "source_state", 0)) & 0xFFFFFFFF,
                target_state=int(getattr(site, "target_state", 0)) & 0xFFFFFFFF,
                source_entry_anchor=int(getattr(site, "source_entry_anchor", -1)),
                source_anchor_block=int(getattr(site, "source_anchor_block", -1)),
                target_entry_anchor=int(getattr(site, "target_entry_anchor", -1)),
                ordered_path=tuple(int(serial) for serial in (getattr(site, "ordered_path", ()) or ())),
                edge=getattr(site, "edge", None),
                semantic_target_label=normalized_label,
                successor_state_value=int(normalized_successor) & 0xFFFFFFFF,
            )
        )

    return _prune_descendant_child_exit_sites(
        tuple(normalized_overrides),
        child_entry_states=child_entry_states,
    )


def _prune_descendant_child_exit_sites(
    sites: tuple[SemanticRegionLoweringSite, ...],
    *,
    child_entry_states: set[int],
) -> tuple[SemanticRegionLoweringSite, ...]:
    if not sites or not child_entry_states:
        return tuple(sites)

    grouped: dict[tuple[int, int], list[SemanticRegionLoweringSite]] = {}
    for site in sites:
        grouped.setdefault(
            (
                int(site.source_state) & 0xFFFFFFFF,
                int(site.source_entry_anchor),
            ),
            [],
        ).append(site)

    kept: list[SemanticRegionLoweringSite] = []
    for source_key, source_sites in grouped.items():
        del source_key
        child_sites = [
            site
            for site in source_sites
            if site.site_kind in {"exit", "exit_alias_candidate"}
            and site.successor_state_value is not None
            and (int(site.successor_state_value) & 0xFFFFFFFF) in child_entry_states
            and int(site.target_entry_anchor) >= 0
        ]
        if len(child_sites) < 2:
            kept.extend(source_sites)
            continue

        pruned_ids: set[int] = set()
        for site in child_sites:
            ordered_path = tuple(int(block) for block in (site.ordered_path or ()))
            if not ordered_path:
                continue
            for sibling in child_sites:
                if site is sibling:
                    continue
                if (
                    site.successor_state_value is not None
                    and sibling.successor_state_value is not None
                    and (int(site.successor_state_value) & 0xFFFFFFFF)
                    == (int(sibling.successor_state_value) & 0xFFFFFFFF)
                ):
                    continue
                sibling_entry = int(sibling.target_entry_anchor)
                if sibling_entry < 0 or sibling_entry == int(site.target_entry_anchor):
                    continue
                try:
                    sibling_index = ordered_path.index(sibling_entry)
                except ValueError:
                    continue
                if sibling_index <= 0:
                    continue
                pruned_ids.add(id(site))
                logger.info(
                    "semantic region descendant child prune: region=%s src=0x%08X target=0x%08X succ=0x%08X via_child=0x%08X child_entry=%d path=%s",
                    site.region_name,
                    int(site.source_state) & 0xFFFFFFFF,
                    int(site.target_state) & 0xFFFFFFFF,
                    int(site.successor_state_value) & 0xFFFFFFFF,
                    int(sibling.successor_state_value) & 0xFFFFFFFF,
                    sibling_entry,
                    ordered_path,
                )
                break
        kept.extend(site for site in source_sites if id(site) not in pruned_ids)
    return tuple(kept)


def _resolve_direct_semantic_successor_override(
    *,
    dag: object,
    source_state: int,
    target_state: int,
    current_target_entry: int | None,
    ordered_path: tuple[int, ...],
    semantic_successors_by_state: dict[int, tuple[str, ...]],
    semantic_entry_by_label: dict[str, int],
    semantic_reference_program: object | None,
    dispatcher_blocks: set[int],
) -> tuple[int | None, str | None]:
    semantic_labels = tuple(semantic_successors_by_state.get(source_state, ()))
    direct_labels = tuple(
        label
        for label in semantic_labels
        if label in (
            f"STATE_{target_state:08X}",
            f"0x{target_state:08X}",
        )
    )
    if len(direct_labels) != 1:
        return current_target_entry, None

    target_label = direct_labels[0]
    semantic_target_entry = semantic_entry_by_label.get(target_label)
    if semantic_target_entry is None:
        semantic_target_entry = resolve_semantic_reference_entry_for_state(
            target_state,
            semantic_reference_program=semantic_reference_program,
            dispatcher_region=dispatcher_blocks,
            allow_dispatcher_exact_head=True,
        )
        if semantic_target_entry is None:
            return current_target_entry, None
    semantic_target_entry = int(semantic_target_entry)
    exact_dag_entry = resolve_exact_dag_entry_for_state(
        dag,
        target_state,
        dispatcher_region=dispatcher_blocks,
        allow_dispatcher_exact_head=True,
    )
    if semantic_target_entry in dispatcher_blocks and semantic_target_entry != exact_dag_entry:
        return current_target_entry, None
    current_entry = (
        int(current_target_entry) if current_target_entry is not None else None
    )
    if current_entry == semantic_target_entry:
        return current_entry, target_label

    current_is_nonhead = (
        current_entry is None
        or current_entry in ordered_path
        or current_entry != exact_dag_entry
    )
    semantic_is_exact_head = (
        exact_dag_entry is None or semantic_target_entry == int(exact_dag_entry)
    )
    if current_is_nonhead and semantic_is_exact_head:
        return semantic_target_entry, target_label
    return current_entry, None


def _prefer_exact_target_head_over_path_entry(
    *,
    dag: object,
    site_kind: str,
    target_state: int,
    current_target_entry: int | None,
    semantic_target_label: str | None,
    ordered_path: tuple[int, ...],
    dispatcher_blocks: set[int],
) -> int | None:
    if current_target_entry is None:
        return None
    if site_kind not in {"exit", "exit_alias_candidate"}:
        return int(current_target_entry)

    current_entry = int(current_target_entry)
    exact_dag_entry = resolve_exact_dag_entry_for_state(
        dag,
        target_state,
        dispatcher_region=dispatcher_blocks,
        allow_dispatcher_exact_head=True,
    )
    if exact_dag_entry is None:
        return current_entry
    exact_dag_entry = int(exact_dag_entry)
    if exact_dag_entry == current_entry:
        return current_entry
    if semantic_target_label is not None:
        semantic_state = _semantic_state_value_from_label(semantic_target_label)
        if (
            str(semantic_target_label).endswith("_fallback")
            or (
                semantic_state is not None
                and (int(semantic_state) & 0xFFFFFFFF) != (int(target_state) & 0xFFFFFFFF)
            )
        ):
            return current_entry
    return exact_dag_entry


@algorithm_metadata(
    algorithm_id="cfg.semantic_region_fallback_lowering",
    family="structured_region_semantic_lowering",
    summary="Builds a semantic-head fallback lowering when the generic reconstruction planner rejects a region-owned site.",
    use_cases=(
        "Compile region-owned successor state writes into direct semantic-entry transfers when shared-group planning is too conservative.",
        "Preserve the linearized semantic program contract without re-entering the dispatcher for known region successors.",
    ),
    examples=(
        "Turn a conditional region exit that still writes 0x2315233C into a branch redirect to STATE_2315233C's semantic entry.",
        "Turn a region-internal successor 0x139F2922 -> 0x63F502FA into a direct handoff to STATE_63F502FA's semantic head.",
    ),
    tags=("semantic-region", "fallback-lowering", "semantic-head", "structured-lowering"),
    related_paths=(
        "src/d810/cfg/semantic_region_lowering.py",
        "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/linearized_flow_graph.py",
    ),
)
def build_region_contract_fallback_lowering(
    *,
    site: SemanticRegionLoweringSite,
    rejection_reason: str | None,
) -> SemanticRegionFallbackLowering | None:
    """Return a direct semantic-head lowering when the region contract is strong enough.

    This is intentionally narrow. It only fires for admissible semantic sites
    that the generic planner rejected for shared-group / via-pred reasons. In
    those cases, the linearized region contract is a better guide than the
    live dispatcher-oriented path shape.
    """

    normalized_reason = str(rejection_reason or "")
    if normalized_reason not in {"missing_via_pred", "missing_keep_pred"}:
        return None
    horizon_block = _select_site_horizon_block(site)
    if horizon_block is None or site.target_entry_anchor < 0:
        return None
    ordered_path = tuple(int(serial) for serial in (site.ordered_path or ()))
    if not ordered_path:
        return None
    source_anchor_block = int(
        getattr(
            getattr(site.edge, "source_anchor", None),
            "block_serial",
            site.source_anchor_block,
        )
    )
    if ordered_path[0] not in {
        int(site.source_entry_anchor),
        int(source_anchor_block),
    }:
        return None

    branch_arm = getattr(getattr(site.edge, "source_anchor", None), "branch_arm", None)
    emission_mode = (
        "conditional_arm"
        if branch_arm is not None
        else "direct"
    )
    return SemanticRegionFallbackLowering(
        emission_mode=emission_mode,
        horizon_block=int(horizon_block),
        target_entry_anchor=int(site.target_entry_anchor),
    )


def build_region_preferred_conditional_lowering(
    *,
    site: SemanticRegionLoweringSite,
) -> SemanticRegionFallbackLowering | None:
    """Prefer source-arm emission for semantic conditional sites.

    Region-first lowering should not bounce through a one-way feeder row when we
    already know the semantic source head and target head. If the source edge is
    a conditional branch owned by the semantic source entry, compile it as a
    direct conditional-arm redirect from that source head.
    """

    branch_arm = getattr(getattr(site.edge, "source_anchor", None), "branch_arm", None)
    if branch_arm is None:
        return None
    horizon_block = _select_site_horizon_block(site)
    if horizon_block is None or site.target_entry_anchor < 0:
        return None
    ordered_path = tuple(int(serial) for serial in (site.ordered_path or ()))
    if not ordered_path:
        return None
    source_anchor_block = int(
        getattr(
            getattr(site.edge, "source_anchor", None),
            "block_serial",
            site.source_anchor_block,
        )
    )
    if ordered_path[0] not in {
        int(site.source_entry_anchor),
        int(source_anchor_block),
    }:
        return None
    return SemanticRegionFallbackLowering(
        emission_mode="conditional_arm",
        horizon_block=int(horizon_block),
        target_entry_anchor=int(site.target_entry_anchor),
    )


def build_region_preferred_direct_lowering(
    *,
    site: SemanticRegionLoweringSite,
) -> SemanticRegionFallbackLowering | None:
    """Prefer direct source-head emission for single-block semantic handoffs.

    This covers dispatcher-backed exact rows that are already admissible
    semantic heads. Once the region contract says the source block itself is
    the owned semantic entry and the ordered path is a single block, there is
    no value in routing through the generic reconstruction planner first.
    """

    branch_arm = getattr(getattr(site.edge, "source_anchor", None), "branch_arm", None)
    if branch_arm is not None:
        return None
    horizon_block = _select_site_horizon_block(site)
    if horizon_block is None or site.target_entry_anchor < 0:
        return None
    if not site.ordered_path or int(site.ordered_path[0]) != int(site.source_entry_anchor):
        return None
    if len(site.ordered_path) != 1:
        return None
    return SemanticRegionFallbackLowering(
        emission_mode="direct",
        horizon_block=int(horizon_block),
        target_entry_anchor=int(site.target_entry_anchor),
    )


__all__ = [
    "SemanticRegionFallbackLowering",
    "SemanticRegionLoweringSite",
    "build_region_contract_fallback_lowering",
    "build_region_preferred_direct_lowering",
    "build_region_preferred_conditional_lowering",
    "collect_admissible_region_lowering_sites",
    "override_exit_sites_with_child_region_entries",
]
