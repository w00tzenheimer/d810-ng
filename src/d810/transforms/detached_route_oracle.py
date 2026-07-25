"""Reference-equivalence proof for staged, unpublished semantic routes."""

from __future__ import annotations

from dataclasses import dataclass, replace

from d810.core.semantic_route_oracle import (
    ReferenceRouteRewrite,
    RouteCaptureLane,
    RouteOracleComparison,
    SemanticRouteObservation,
    SemanticRouteShape,
    SemanticTransferKind,
    compare_route_maturities,
)
from d810.ir.flowgraph import InsnKind
from d810.transforms.fragment_plan import FragmentOperation, FragmentPlan
from d810.transforms.fragment_validation import ProjectedFragment


_DETACHED_MATURITY = "DETACHED_PREPUBLICATION"
_CANDIDATE_VARIANT = "detached_prepublication"


class DetachedRouteOracleRejected(ValueError):
    """The staged fragment lacks complete reference-oracle authority."""


@dataclass(frozen=True, slots=True)
class DetachedRouteOracleResult:
    """All reference comparisons for one staged fragment transaction."""

    plan_id: str
    atomic_group_id: str
    comparisons: tuple[RouteOracleComparison, ...]

    def __post_init__(self) -> None:
        if not str(self.plan_id) or not str(self.atomic_group_id):
            raise ValueError("detached route oracle requires a fragment scope")
        comparisons = tuple(self.comparisons)
        if not comparisons or any(
            not isinstance(comparison, RouteOracleComparison)
            for comparison in comparisons
        ):
            raise ValueError("detached route oracle requires route comparisons")
        object.__setattr__(self, "comparisons", comparisons)

    @property
    def passed(self) -> bool:
        return all(comparison.outcome == "matched" for comparison in self.comparisons)

    @property
    def first_failure(self) -> RouteOracleComparison | None:
        return next(
            (
                comparison
                for comparison in self.comparisons
                if comparison.outcome != "matched"
            ),
            None,
        )


def _reachable_block_ids(projection: ProjectedFragment) -> frozenset[str]:
    by_id = {block.block_id: block for block in projection.blocks}
    pending = [projection.entry_block_id]
    reached: set[str] = set()
    while pending:
        block_id = pending.pop()
        if block_id in reached:
            continue
        reached.add(block_id)
        block = by_id.get(block_id)
        if block is not None:
            pending.extend(block.successors)
    return frozenset(reached)


def _semantic_transfer_kind(kind: InsnKind) -> SemanticTransferKind:
    if kind is InsnKind.GOTO:
        return SemanticTransferKind.DIRECT
    if kind in {InsnKind.COND_JUMP, InsnKind.EQUALITY_JUMP}:
        return SemanticTransferKind.CONDITIONAL
    if kind in {InsnKind.INDIRECT_JUMP, InsnKind.TABLE_JUMP}:
        return SemanticTransferKind.INDIRECT
    if kind is InsnKind.RET:
        return SemanticTransferKind.RETURN
    return SemanticTransferKind.UNKNOWN


def _reference_observation(route: ReferenceRouteRewrite) -> SemanticRouteObservation:
    target_ea = route.direct_target_ea
    if (
        route.final_transfer_kind is not SemanticTransferKind.DIRECT
        or target_ea is None
    ):
        return SemanticRouteObservation(
            route_id=route.route_id,
            lane=RouteCaptureLane.REFERENCE,
            maturity=_DETACHED_MATURITY,
            outcome="rejected",
            shape=None,
            reason=f"reference route {route.route_id} is not one direct rewrite",
        )
    return SemanticRouteObservation(
        route_id=route.route_id,
        lane=RouteCaptureLane.REFERENCE,
        maturity=_DETACHED_MATURITY,
        outcome="observed",
        shape=SemanticRouteShape(
            route_id=route.route_id,
            lane=RouteCaptureLane.REFERENCE,
            maturity=_DETACHED_MATURITY,
            owner_ea=int(route.owner_ea),
            rewrite_anchor_ea=int(route.rewrite_anchor_ea),
            owner_block_start_ea=int(route.owner_ea),
            instruction_eas=(int(route.rewrite_anchor_ea),),
            terminator_ea=int(route.rewrite_anchor_ea),
            terminator_opcode=InsnKind.GOTO.value,
            transfer_kind=SemanticTransferKind.DIRECT,
            direct_target_ea=int(target_ea),
            true_target_ea=None,
            false_target_ea=None,
            predicate_kind=None,
            successor_eas=(int(target_ea),),
            physical_fallthrough_ea=None,
            reachable_from_entry=True,
        ),
        reason="",
    )


def _candidate_failure(
    route: ReferenceRouteRewrite,
    reason: str,
) -> SemanticRouteObservation:
    return SemanticRouteObservation(
        route_id=route.route_id,
        lane=RouteCaptureLane.CANDIDATE,
        maturity=_DETACHED_MATURITY,
        outcome="invalid",
        shape=None,
        reason=reason,
    )


def _candidate_observation(
    plan: FragmentPlan,
    projection: ProjectedFragment,
    operation: FragmentOperation,
    route: ReferenceRouteRewrite,
    reachable_block_ids: frozenset[str],
) -> SemanticRouteObservation:
    try:
        source = projection.block(operation.source_block_id)
        source_plan = plan.block(operation.source_block_id)
    except KeyError:
        return _candidate_failure(
            route,
            f"route {route.route_id} has no staged source block",
        )
    identity = source_plan.stable_identity
    if identity is None or not identity.native_ranges.contains(route.owner_ea):
        return _candidate_failure(
            route,
            f"route {route.route_id} staged source does not own 0x{route.owner_ea:X}",
        )
    if (
        source.terminator_ea != route.rewrite_anchor_ea
        or route.rewrite_anchor_ea not in source.instruction_eas
    ):
        return _candidate_failure(
            route,
            f"route {route.route_id} rewrite anchor is not the staged terminator",
        )
    successor_blocks = []
    for block_id in source.successors:
        try:
            successor_blocks.append(plan.block(block_id))
        except KeyError:
            return _candidate_failure(
                route,
                f"route {route.route_id} has an unowned staged successor {block_id!r}",
            )
    successor_eas = tuple(
        sorted(int(block.semantic_anchor_ea) for block in successor_blocks)
    )
    transfer_kind = _semantic_transfer_kind(source.terminator_kind)
    direct_target_ea = (
        int(successor_blocks[0].semantic_anchor_ea)
        if transfer_kind is SemanticTransferKind.DIRECT and len(successor_blocks) == 1
        else None
    )
    owner_start_ea = min(
        int(interval.start_ea) for interval in identity.native_ranges.intervals
    )
    return SemanticRouteObservation(
        route_id=route.route_id,
        lane=RouteCaptureLane.CANDIDATE,
        maturity=_DETACHED_MATURITY,
        outcome="observed",
        shape=SemanticRouteShape(
            route_id=route.route_id,
            lane=RouteCaptureLane.CANDIDATE,
            maturity=_DETACHED_MATURITY,
            owner_ea=int(route.owner_ea),
            rewrite_anchor_ea=int(route.rewrite_anchor_ea),
            owner_block_start_ea=owner_start_ea,
            instruction_eas=source.instruction_eas,
            terminator_ea=int(source.terminator_ea),
            terminator_opcode=source.terminator_kind.value,
            transfer_kind=transfer_kind,
            direct_target_ea=direct_target_ea,
            true_target_ea=None,
            false_target_ea=None,
            predicate_kind=None,
            successor_eas=successor_eas,
            physical_fallthrough_ea=None,
            reachable_from_entry=(source.block_id in reachable_block_ids),
        ),
        reason="",
    )


def compare_detached_route_oracle(
    plan: FragmentPlan,
    projection: ProjectedFragment,
) -> DetachedRouteOracleResult:
    """Compare every selected reference route before any live root is published."""
    if not isinstance(plan, FragmentPlan):
        raise TypeError("detached route oracle requires a FragmentPlan")
    if not isinstance(projection, ProjectedFragment):
        raise TypeError("detached route oracle requires a ProjectedFragment")
    if plan.reference_oracle_run is None:
        raise DetachedRouteOracleRejected(
            "detached route oracle requires one pinned reference run"
        )

    selected: list[tuple[FragmentOperation, ReferenceRouteRewrite]] = []
    for operation in plan.operations:
        rewrite = operation.direct_transfer_rewrite
        if rewrite is None:
            continue
        if rewrite.reference_route is None:
            raise DetachedRouteOracleRejected(
                f"operation {operation.operation_id!r} has no reference route"
            )
        selected.append((operation, rewrite.reference_route))
    if not selected:
        raise DetachedRouteOracleRejected(
            "detached route oracle requires selected semantic rewrites"
        )

    reachable_block_ids = _reachable_block_ids(projection)
    comparisons: list[RouteOracleComparison] = []
    for operation, route in selected:
        reference = _reference_observation(route)
        candidate = _candidate_observation(
            plan,
            projection,
            operation,
            route,
            reachable_block_ids,
        )
        (comparison,) = compare_route_maturities(
            route,
            {_DETACHED_MATURITY: reference},
            {_DETACHED_MATURITY: candidate},
            maturity_order=(_DETACHED_MATURITY,),
            candidate_variant=_CANDIDATE_VARIANT,
        )
        comparisons.append(comparison)

    first_failure_index = next(
        (
            index
            for index, comparison in enumerate(comparisons)
            if comparison.outcome != "matched"
        ),
        None,
    )
    comparisons = [
        replace(
            comparison,
            first_divergence=(
                first_failure_index is not None and index == first_failure_index
            ),
        )
        for index, comparison in enumerate(comparisons)
    ]
    return DetachedRouteOracleResult(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        comparisons=tuple(comparisons),
    )


__all__ = [
    "DetachedRouteOracleRejected",
    "DetachedRouteOracleResult",
    "compare_detached_route_oracle",
]
