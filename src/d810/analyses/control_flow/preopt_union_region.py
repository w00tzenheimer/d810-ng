"""Plan one PREOPT range union from resolver-owned handler closures."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.analyses.control_flow.detached_handler_island import (
    merge_detached_snippet_ranges,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
)
from d810.core.typing import Collection, Sequence


class PreoptUnionAbstentionReason(str, Enum):
    MISSING_OWNED_RANGES = "missing_owned_ranges"
    AMBIGUOUS_OWNED_RANGES = "ambiguous_owned_ranges"


@dataclass(frozen=True, slots=True)
class PreoptUnionAbstention:
    target_ea: int
    reason: PreoptUnionAbstentionReason


@dataclass(frozen=True, slots=True)
class PreoptUnionRegionPlan:
    seed_eas: tuple[int, ...]
    seed_native_ranges: tuple[
        tuple[int, tuple[tuple[int, int], ...]],
        ...,
    ]
    primary_seed_ea: int | None
    native_ranges: tuple[tuple[int, int], ...]
    abstentions: tuple[PreoptUnionAbstention, ...]


def plan_preopt_union_region(
    transfers: Sequence[MaterializedIndirectTransfer],
) -> PreoptUnionRegionPlan:
    """Union unique pre-patch native closures for proven handler entries."""
    ranges_by_target: dict[int, set[tuple[tuple[int, int], ...]]] = {}
    route_targets: set[int] = set()
    for transfer in transfers:
        if (
            transfer.resolver_kind != "static_handler_entry_route"
            or len(transfer.target_eas) != 1
        ):
            continue
        target_ea = int(transfer.target_eas[0])
        route_targets.add(target_ea)
        normalized = merge_detached_snippet_ranges(
            tuple(
                (int(start_ea), int(end_ea))
                for start_ea, end_ea in transfer.owned_native_ranges
            )
        )
        if normalized:
            ranges_by_target.setdefault(target_ea, set()).add(normalized)

    selected_targets: list[int] = []
    selected_seed_ranges: list[tuple[int, tuple[tuple[int, int], ...]]] = []
    selected_ranges: list[tuple[int, int]] = []
    abstentions: list[PreoptUnionAbstention] = []
    for target_ea in sorted(route_targets):
        candidates = ranges_by_target.get(target_ea, set())
        if not candidates:
            abstentions.append(
                PreoptUnionAbstention(
                    target_ea,
                    PreoptUnionAbstentionReason.MISSING_OWNED_RANGES,
                )
            )
            continue
        if len(candidates) != 1:
            abstentions.append(
                PreoptUnionAbstention(
                    target_ea,
                    PreoptUnionAbstentionReason.AMBIGUOUS_OWNED_RANGES,
                )
            )
            continue
        target_ranges = next(iter(candidates))
        selected_targets.append(target_ea)
        selected_seed_ranges.append((target_ea, target_ranges))
        selected_ranges.extend(target_ranges)

    seed_eas = tuple(selected_targets)
    return PreoptUnionRegionPlan(
        seed_eas=seed_eas,
        seed_native_ranges=tuple(selected_seed_ranges),
        primary_seed_ea=(None if not seed_eas else seed_eas[0]),
        native_ranges=merge_detached_snippet_ranges(tuple(selected_ranges)),
        abstentions=tuple(abstentions),
    )


def select_missing_preopt_union_region(
    plan: PreoptUnionRegionPlan,
    live_native_eas: Collection[int],
) -> PreoptUnionRegionPlan:
    """Restrict one union plan to handler entries absent from the live MBA."""
    live = {int(ea) for ea in live_native_eas}
    selected_seed_ranges = tuple(
        (int(seed_ea), native_ranges)
        for seed_ea, native_ranges in plan.seed_native_ranges
        if int(seed_ea) not in live
    )
    seed_eas = tuple(seed_ea for seed_ea, _ranges in selected_seed_ranges)
    native_ranges = merge_detached_snippet_ranges(
        tuple(
            native_range
            for _seed_ea, ranges in selected_seed_ranges
            for native_range in ranges
        )
    )
    return PreoptUnionRegionPlan(
        seed_eas=seed_eas,
        seed_native_ranges=selected_seed_ranges,
        primary_seed_ea=(None if not seed_eas else seed_eas[0]),
        native_ranges=native_ranges,
        abstentions=plan.abstentions,
    )


__all__ = [
    "PreoptUnionAbstention",
    "PreoptUnionAbstentionReason",
    "PreoptUnionRegionPlan",
    "plan_preopt_union_region",
    "select_missing_preopt_union_region",
]
