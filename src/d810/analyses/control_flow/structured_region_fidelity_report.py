"""Structured-region fidelity reporting and sub_7FFD may-only probe collection.

Reporting-only producer (no CFG mutation, no IDA runtime calls). Consumes the
reconstruction round's accepted-pair bookkeeping, the semantic DAG, the
postprocess plan, and emits:

- ``build_structured_region_fidelity_report`` — main fidelity reporter. Walks
  bridge/feeder log entries against a late-rewrite semantic index and classifies
  each entry as ``unmatched`` / ``outside_structured_regions`` /
  ``structured_leakage``. Emits INFO logs and returns the
  ``structured_region_fidelity`` dict.
- ``collect_sub7ffd_may_only_probe_blocks`` — sub_7FFD-specific probe-block
  collector. Returns the leaked-frontier block/target tuples that feed into the
  ``post_apply_may_only_probe_blocks`` fragment metadata.

The private ``_build_late_rewrite_semantic_indexes`` helper is only used by
``build_structured_region_fidelity_report`` and is kept module-private.
"""
from __future__ import annotations

from d810.ir.state_edge_pair import state_edge_pair, format_state_pair

from collections import Counter, defaultdict

from d810.core import logging
from d810.analyses.control_flow.edge_metadata import edge_kind_name
from d810.analyses.control_flow.frontier_override_discovery import (
    _bridge_exit_block_for_edge,
    _late_rewrite_memberships,
)

logger = logging.getLogger(
    "D810.recon.flow.structured_region_fidelity_report",
    logging.DEBUG,
)

# Duplicated here to keep this reporter independent of the hodur strategy module.
# Must stay in sync with ``reconstruction._SUB7FFD_INITIAL_REGION_NAME``.
_SUB7FFD_INITIAL_REGION_NAME = "sub7ffd_initial_semantic_region"


__all__ = [
    "build_structured_region_fidelity_report",
    "collect_sub7ffd_may_only_probe_blocks",
]






def _build_late_rewrite_semantic_indexes(
    *,
    dag,
    dispatcher_region: set[int],
    dispatcher_serial: int,
    structured_regions,
    structured_region_candidate_pairs: dict[str, list[tuple[int, int]]],
    structured_region_accepted_pairs: dict[str, set[tuple[int, int]]],
) -> tuple[
    dict[tuple[int, int], list[dict[str, object]]],
    dict[tuple[int, int, int | None], list[dict[str, object]]],
]:
    bridge_index: dict[tuple[int, int], list[dict[str, object]]] = defaultdict(list)
    feeder_index: dict[tuple[int, int, int | None], list[dict[str, object]]] = defaultdict(list)
    for edge in getattr(dag, "edges", ()):
        target_entry = getattr(edge, "target_entry_anchor", None)
        if target_entry is None:
            continue
        pair = state_edge_pair(edge)
        memberships = _late_rewrite_memberships(
            pair=pair,
            structured_regions=structured_regions,
            structured_region_candidate_pairs=structured_region_candidate_pairs,
            structured_region_accepted_pairs=structured_region_accepted_pairs,
        )
        record = {
            "pair": pair,
            "edge_kind": edge_kind_name(edge),
            "memberships": memberships,
        }
        bridge_exit_block = _bridge_exit_block_for_edge(
            edge,
            dispatcher_region=dispatcher_region,
            dispatcher_serial=dispatcher_serial,
        )
        if bridge_exit_block is not None:
            bridge_index[(int(bridge_exit_block), int(target_entry))].append(record)
        feeder_index[
            (
                int(edge.source_anchor.block_serial),
                int(target_entry),
                getattr(edge.source_anchor, "branch_arm", None),
            )
        ].append(record)
    return dict(bridge_index), dict(feeder_index)


def build_structured_region_fidelity_report(
    *,
    logger,
    mba,
    structured_region_accepted_counts: Counter[str],
    structured_regions,
    structured_region_candidate_pairs: dict[str, list[tuple[int, int]]],
    structured_region_accepted_pairs: dict[str, set[tuple[int, int]]],
    dispatcher_region: set[int],
    dispatcher_serial: int,
    dag,
    postprocess_plan,
) -> dict[str, object]:
    primary_region_edges = int(
        sum(len(pairs) for pairs in structured_region_accepted_pairs.values())
    )
    bridge_recovery_edges = len(postprocess_plan.bridge_plan.modifications)
    feeder_recovery_edges = len(postprocess_plan.feeder_plan.modifications) + len(
        postprocess_plan.fixpoint_feeder_plan.modifications
    )
    return_recovery_edges = len(postprocess_plan.return_plan.modifications)
    late_local_redirect_edges = (
        bridge_recovery_edges + feeder_recovery_edges + return_recovery_edges
    )
    logger.info(
        "RECON DAG: fidelity primary_region_edges=%d bridge_recovery_edges=%d late_local_redirect_edges=%d",
        primary_region_edges,
        bridge_recovery_edges,
        late_local_redirect_edges,
    )

    bridge_index, feeder_index = _build_late_rewrite_semantic_indexes(
        dag=dag,
        dispatcher_region=dispatcher_region,
        dispatcher_serial=dispatcher_serial,
        structured_regions=structured_regions,
        structured_region_candidate_pairs=structured_region_candidate_pairs,
        structured_region_accepted_pairs=structured_region_accepted_pairs,
    )
    leak_units: Counter[str] = Counter()
    leak_roles: Counter[str] = Counter()
    detailed_entries: list[dict[str, object]] = []

    def _record_entry(
        *,
        planner: str,
        source_block: int,
        target_block: int,
        branch_arm: int | None,
        tag: str,
        matches: list[dict[str, object]],
    ) -> None:
        if not matches:
            logger.info(
                "RECON DAG: late rewrite planner=%s blk[%d]%s -> blk[%d] tag=%s semantic=unmatched",
                planner,
                source_block,
                f".arm{branch_arm}" if branch_arm is not None else "",
                target_block,
                tag,
            )
            detailed_entries.append(
                {
                    "planner": planner,
                    "source_block": source_block,
                    "target_block": target_block,
                    "branch_arm": branch_arm,
                    "tag": tag,
                    "semantic_status": "unmatched",
                }
            )
            return

        pair_labels = sorted({format_state_pair(match["state_edge_pair"]) for match in matches})
        edge_kinds = sorted({str(match["edge_kind"]) for match in matches})
        memberships = [
            membership
            for match in matches
            for membership in match["memberships"]
        ]
        if not memberships:
            logger.info(
                "RECON DAG: late rewrite planner=%s blk[%d]%s -> blk[%d] tag=%s states=%s edge_kinds=%s structural_role=outside_structured_regions",
                planner,
                source_block,
                f".arm{branch_arm}" if branch_arm is not None else "",
                target_block,
                tag,
                pair_labels,
                edge_kinds,
            )
            detailed_entries.append(
                {
                    "planner": planner,
                    "source_block": source_block,
                    "target_block": target_block,
                    "branch_arm": branch_arm,
                    "tag": tag,
                    "semantic_status": "outside_structured_regions",
                    "state_pairs": tuple(pair_labels),
                    "edge_kinds": tuple(edge_kinds),
                }
            )
            return

        unit_labels = sorted({membership["leak_unit"] for membership in memberships})
        role_labels = sorted({membership["role"] for membership in memberships})
        primary_statuses = sorted({membership["primary_status"] for membership in memberships})
        for membership in memberships:
            leak_units[str(membership["leak_unit"])] += 1
            leak_roles[str(membership["role"])] += 1
        logger.info(
            "RECON DAG: late rewrite planner=%s blk[%d]%s -> blk[%d] tag=%s states=%s edge_kinds=%s leak_units=%s roles=%s primary_status=%s",
            planner,
            source_block,
            f".arm{branch_arm}" if branch_arm is not None else "",
            target_block,
            tag,
            pair_labels,
            edge_kinds,
            unit_labels,
            role_labels,
            primary_statuses,
        )
        detailed_entries.append(
            {
                "planner": planner,
                "source_block": source_block,
                "target_block": target_block,
                "branch_arm": branch_arm,
                "tag": tag,
                "semantic_status": "structured_leakage",
                "state_pairs": tuple(pair_labels),
                "edge_kinds": tuple(edge_kinds),
                "leak_units": tuple(unit_labels),
                "roles": tuple(role_labels),
                "primary_status": tuple(primary_statuses),
            }
        )

    for entry in postprocess_plan.bridge_plan.log_entries:
        matches = bridge_index.get((int(entry.source_block), int(entry.target_block)), [])
        _record_entry(
            planner="bridge",
            source_block=int(entry.source_block),
            target_block=int(entry.target_block),
            branch_arm=getattr(entry, "branch_arm", None),
            tag=str(entry.tag),
            matches=matches,
        )
    for entry in postprocess_plan.feeder_plan.log_entries:
        matches = feeder_index.get(
            (
                int(entry.source_block),
                int(entry.target_block),
                getattr(entry, "branch_arm", None),
            ),
            [],
        )
        _record_entry(
            planner="feeder",
            source_block=int(entry.source_block),
            target_block=int(entry.target_block),
            branch_arm=getattr(entry, "branch_arm", None),
            tag=str(entry.tag),
            matches=matches,
        )

    if leak_units:
        logger.info(
            "RECON DAG: leaked semantic units: %s",
            ", ".join(f"{unit}={count}" for unit, count in leak_units.most_common()),
        )
    if leak_roles:
        logger.info(
            "RECON DAG: leaked semantic roles: %s",
            ", ".join(f"{role}={count}" for role, count in leak_roles.most_common()),
        )

    return {
        "primary_region_edges": primary_region_edges,
        "bridge_recovery_edges": bridge_recovery_edges,
        "late_local_redirect_edges": late_local_redirect_edges,
        "leaked_units": tuple((unit, count) for unit, count in leak_units.most_common()),
        "leaked_roles": tuple((role, count) for role, count in leak_roles.most_common()),
        "late_rewrite_entries": tuple(detailed_entries),
    }


def collect_sub7ffd_may_only_probe_blocks(
    *,
    structured_region_fidelity: dict[str, object],
    structured_frontier_overrides: list[dict[str, object]],
    postprocess_plan,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Return leaked-frontier blocks for the explicit may-only liveness probe.

    The old microcode dump bug effectively replaced may-lists with
    may-minus-must on the live MBA.  We do not want to do that globally again,
    but for sub_7FFD exploration we can probe the same effect explicitly on the
    leaked initial frontier blocks that still fall out into bridge/local
    recovery.
    """
    block_serials: set[int] = set()
    structured_frontier_targets: set[int] = set()
    leaked_entries = structured_region_fidelity.get("late_rewrite_entries", ())
    if isinstance(leaked_entries, tuple):
        iterable_entries = leaked_entries
    elif isinstance(leaked_entries, list):
        iterable_entries = tuple(leaked_entries)
    else:
        iterable_entries = ()

    for entry in iterable_entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("semantic_status") != "structured_leakage":
            continue
        leak_units = {
            str(unit)
            for unit in entry.get("leak_units", ())
            if unit is not None
        }
        if not any(
            unit.startswith(f"{_SUB7FFD_INITIAL_REGION_NAME}:")
            for unit in leak_units
        ):
            continue
        source_block = entry.get("source_block")
        if isinstance(source_block, int):
            block_serials.add(source_block)

    for entry in structured_frontier_overrides:
        if not isinstance(entry, dict):
            continue
        roles = {str(role) for role in entry.get("roles", ()) if role is not None}
        if not roles & {"exit_frontier", "post_exit_frontier"}:
            continue
        source_block = entry.get("source_block")
        if isinstance(source_block, int):
            block_serials.add(source_block)
        target_entry = entry.get("target_entry")
        if isinstance(target_entry, int):
            structured_frontier_targets.add(target_entry)

    for entry in getattr(getattr(postprocess_plan, "bridge_plan", None), "log_entries", ()):
        source_block = getattr(entry, "source_block", None)
        target_block = getattr(entry, "target_block", None)
        if not isinstance(source_block, int) or not isinstance(target_block, int):
            continue
        if target_block in structured_frontier_targets:
            block_serials.add(source_block)

    return tuple(sorted(block_serials)), tuple(sorted(structured_frontier_targets))
