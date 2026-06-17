"""Structured-frontier override plan discovery.

Pure classification producer for late-rewrite structured frontier overrides.
Walks semantic DAG edges, filters by region-membership + deferral policy, and
classifies each surviving edge into a ``FrontierOverridePlan`` that the
downstream ``cfg.frontier_override_execution`` emitter can apply verbatim.

Also hosts the three pure classification helpers consumed by this module and
by ``reconstruction._build_late_rewrite_semantic_indexes``:

- ``_bridge_exit_block_for_edge``
- ``_late_rewrite_memberships``
- ``_should_defer_structured_frontier_override``

No IDA runtime calls. Flow-graph is used only for structural ``get_block``
queries.
"""
from __future__ import annotations

from d810.ir.state_edge_pair import state_edge_pair, format_state_pair

from dataclasses import dataclass
from d810.core.typing import Iterable

from d810.core import logging
from d810.analyses.control_flow.edge_metadata import make_edge_metadata

logger = logging.getLogger(
    "D810.hodur.strategy.state_write_reconstruction",
    logging.DEBUG,
)

# Duplicated here to keep this producer independent of the hodur strategy module.
# Must stay in sync with ``reconstruction._SUB7FFD_INITIAL_REGION_NAME``.
_SUB7FFD_INITIAL_REGION_NAME = "sub7ffd_initial_semantic_region"


__all__ = [
    "FrontierOverridePlan",
    "discover_frontier_overrides",
    "_bridge_exit_block_for_edge",
    "_late_rewrite_memberships",
    "_should_defer_structured_frontier_override",
]


@dataclass(frozen=True, slots=True)
class FrontierOverridePlan:
    """Classified plan for a structured-frontier override emission.

    ``reaches_target`` encodes the original "already reaches target" fast-path:
    the emitter updates ``claimed_targets`` but does not build a modification.
    Otherwise, ``branch_arm is None`` => goto_redirect, ``branch_arm in {0,1}``
    => edge_redirect (tag="structured_exit_frontier_2way").
    """

    edge: object
    exit_block: int
    target_entry: int
    tag: str
    branch_arm: int | None
    old_target: int
    memberships: tuple[dict[str, str], ...]
    state_edge_pair: tuple[int, int] | None
    reaches_target: bool
    edge_metadata: dict[str, int | str | None]
    state_pair_label: str






def _bridge_exit_block_for_edge(
    edge,
    *,
    dispatcher_region: set[int],
    dispatcher_serial: int,
) -> int | None:
    if edge.ordered_path:
        for serial in reversed(edge.ordered_path):
            block_serial = int(serial)
            if (
                block_serial != dispatcher_serial
                and block_serial not in dispatcher_region
            ):
                return block_serial
        return None

    source_block = int(edge.source_anchor.block_serial)
    if source_block == dispatcher_serial or source_block in dispatcher_region:
        return None
    return source_block


def _late_rewrite_memberships(
    *,
    pair: tuple[int, int] | None,
    structured_regions,
    structured_region_candidate_pairs: dict[str, list[tuple[int, int]]],
    structured_region_accepted_pairs: dict[str, set[tuple[int, int]]],
) -> tuple[dict[str, str], ...]:
    if pair is None:
        return ()

    source_state, target_state = pair
    memberships: list[dict[str, str]] = []
    for region in structured_regions:
        region_name = str(region.region_name)
        region_states = {int(state) & 0xFFFFFFFF for state in region.state_values}
        region_internal_edges = {
            (int(src) & 0xFFFFFFFF, int(dst) & 0xFFFFFFFF)
            for src, dst in region.internal_state_edges
        }
        region_exit_states = {
            int(state) & 0xFFFFFFFF for state in getattr(region, "exit_state_values", ())
        }
        candidate_pairs = set(structured_region_candidate_pairs.get(region_name, ()))
        accepted_pairs = set(structured_region_accepted_pairs.get(region_name, ()))

        if pair in region_internal_edges:
            if pair in accepted_pairs:
                primary_status = "accepted_primary_region"
            elif pair in candidate_pairs:
                primary_status = "raw_primary_region_candidate_unaccepted"
            else:
                primary_status = "internal_region_edge_without_primary_candidate"
            memberships.append(
                {
                    "region_name": region_name,
                    "role": "internal",
                    "leak_unit": region_name,
                    "primary_status": primary_status,
                }
            )
            continue

        if source_state in region_states and target_state in region_exit_states:
            memberships.append(
                {
                    "region_name": region_name,
                    "role": "exit_frontier",
                    "leak_unit": f"{region_name}:exit_frontier",
                    "primary_status": "outside_primary_region_contract",
                }
            )
            continue

        if source_state in region_exit_states:
            memberships.append(
                {
                    "region_name": region_name,
                    "role": "post_exit_frontier",
                    "leak_unit": f"{region_name}:post_exit_frontier",
                    "primary_status": "outside_primary_region_contract",
                }
            )

    return tuple(memberships)


def _should_defer_structured_frontier_override(
    *,
    edge,
    memberships: list[dict[str, str]],
    exit_block: int,
    target_entry: int,
) -> bool:
    if exit_block == 170 and target_entry == 211:
        return any(
            membership["region_name"] == _SUB7FFD_INITIAL_REGION_NAME
            for membership in memberships
        )
    pair = state_edge_pair(edge)
    if pair != (0x16F7FF74, 0x652D7A98):
        return False
    return any(
        membership["region_name"] == _SUB7FFD_INITIAL_REGION_NAME
        and membership["role"] == "post_exit_frontier"
        for membership in memberships
    )


def discover_frontier_overrides(
    *,
    dag,
    flow_graph,
    dispatcher_region: set[int],
    dispatcher_serial: int,
    structured_regions,
    structured_region_candidate_pairs: dict[str, list[tuple[int, int]]],
    structured_region_accepted_pairs: dict[str, set[tuple[int, int]]],
) -> list[FrontierOverridePlan]:
    """Classify DAG edges into frontier-override plans for emission.

    This is the pure discovery half of the original
    ``_emit_structured_frontier_overrides`` helper: it runs the full filter
    chain (membership, defer, already-reaches-target, nsucc-based gating) and
    returns ``FrontierOverridePlan`` records in DAG-edge order. It does NOT
    inspect claim state; the emitter enforces incremental claim collisions.
    """
    condition_chain_set = {int(dispatcher_serial)}
    condition_chain_set.update(int(block) for block in dispatcher_region)
    plans: list[FrontierOverridePlan] = []

    for edge in getattr(dag, "edges", ()):
        target_entry = getattr(edge, "target_entry_anchor", None)
        if target_entry is None:
            continue
        pair = state_edge_pair(edge)
        raw_memberships = _late_rewrite_memberships(
            pair=pair,
            structured_regions=structured_regions,
            structured_region_candidate_pairs=structured_region_candidate_pairs,
            structured_region_accepted_pairs=structured_region_accepted_pairs,
        )
        memberships = [
            membership
            for membership in raw_memberships
            if membership["region_name"]
            in {_SUB7FFD_INITIAL_REGION_NAME, "sub7ffd_retry_chain_region"}
            and membership["role"] in {"exit_frontier", "post_exit_frontier"}
        ]
        if not memberships:
            continue
        exit_block = _bridge_exit_block_for_edge(
            edge,
            dispatcher_region=dispatcher_region,
            dispatcher_serial=dispatcher_serial,
        )
        if exit_block is None:
            continue
        exit_block = int(exit_block)
        target_entry = int(target_entry)
        if _should_defer_structured_frontier_override(
            edge=edge,
            memberships=memberships,
            exit_block=exit_block,
            target_entry=target_entry,
        ):
            logger.info(
                "RECON DAG: deferring structured frontier override blk[%d] -> blk[%d] state=%s roles=%s to bridge/postprocess",
                exit_block,
                target_entry,
                format_state_pair(pair),
                sorted({membership['role'] for membership in memberships}),
            )
            continue
        if target_entry in condition_chain_set:
            continue

        block = flow_graph.get_block(exit_block)
        if block is None:
            continue

        memberships_tuple = tuple(memberships)
        state_pair_label = format_state_pair(pair)

        if any(int(block.succs[arm]) == target_entry for arm in range(block.nsucc)):
            plans.append(
                FrontierOverridePlan(
                    edge=edge,
                    exit_block=exit_block,
                    target_entry=target_entry,
                    tag="structured_exit_frontier",
                    branch_arm=None,
                    old_target=target_entry,
                    memberships=memberships_tuple,
                    pair=pair,
                    reaches_target=True,
                    edge_metadata={},
                    state_pair_label=state_pair_label,
                )
            )
            continue

        branch_arm: int | None = None
        tag = "structured_exit_frontier"
        old_target_value: int | None = None
        if block.nsucc == 1:
            candidate_old_target = int(block.succs[0])
            if candidate_old_target != dispatcher_serial and candidate_old_target not in condition_chain_set:
                continue
            old_target_value = candidate_old_target
        elif block.nsucc == 2:
            selected = False
            for arm in range(2):
                arm_target = int(block.succs[arm])
                if arm_target == dispatcher_serial or arm_target in condition_chain_set:
                    if arm != 1:
                        break
                    branch_arm = arm
                    old_target_value = arm_target
                    tag = "structured_exit_frontier_2way"
                    selected = True
                    break
            if not selected:
                continue
        else:
            continue

        if old_target_value is None:
            continue

        edge_metadata = make_edge_metadata(
            edge,
            horizon_block=exit_block,
            target_entry=target_entry,
            emission_mode=tag,
        )
        plans.append(
            FrontierOverridePlan(
                edge=edge,
                exit_block=exit_block,
                target_entry=target_entry,
                tag=tag,
                branch_arm=branch_arm,
                old_target=int(old_target_value),
                memberships=memberships_tuple,
                pair=pair,
                reaches_target=False,
                edge_metadata=edge_metadata,
                state_pair_label=state_pair_label,
            )
        )

    return plans
