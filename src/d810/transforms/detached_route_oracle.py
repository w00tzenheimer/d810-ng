"""Reference-equivalence proof for staged, unpublished semantic routes."""

from __future__ import annotations

from dataclasses import dataclass, replace

from d810.core.semantic_route_oracle import (
    ReferenceRouteRewrite,
    ReferenceRouteOracleSelection,
    RouteCaptureLane,
    RouteOracleComparison,
    SemanticRouteObservation,
    SemanticRouteShape,
    SemanticTransferKind,
    compare_route_maturities,
)
from d810.ir.flowgraph import BlockKind, InsnKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.semantics import PredicateKind
from d810.transforms.fragment_plan import (
    FragmentOperation,
    FragmentPlan,
    FragmentReferenceRouteAuthority,
)
from d810.transforms.fragment_validation import (
    FragmentBindingState,
    ProjectedFragment,
    ProjectedFragmentBlock,
    projected_publication_authority_roots,
)


_DETACHED_MATURITY = "DETACHED_PREPUBLICATION"
_CANDIDATE_VARIANT = "detached_prepublication"

_REFERENCE_PREDICATE_BY_PORTABLE = {
    PredicateKind.EQ: "z",
    PredicateKind.NE: "nz",
    PredicateKind.UGE: "ae",
    PredicateKind.UGT: "a",
    PredicateKind.ULE: "be",
    PredicateKind.ULT: "b",
    PredicateKind.SGE: "ge",
    PredicateKind.SGT: "g",
    PredicateKind.SLE: "le",
    PredicateKind.SLT: "l",
}


class DetachedRouteOracleRejected(ValueError):
    """The staged fragment lacks complete reference-oracle authority."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str,
        payload: dict[str, object] | None = None,
    ) -> None:
        super().__init__(str(message))
        self.reason_code = str(reason_code)
        self.payload = {} if payload is None else dict(payload)


class _ProjectedRouteOwnershipError(ValueError):
    """A staged physical route lacks reconstructible plan ownership."""


@dataclass(frozen=True, slots=True)
class _OwnedProjectedRouteSuccessors:
    semantic_block_ids: tuple[str, ...]
    conditional_fallthrough_block_id: str | None


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


def _conditional_candidate_anchor(operation: FragmentOperation) -> int | None:
    if (
        operation.direct_transfer_rewrite is not None
        or operation.predicate_anchor_ea is None
        or operation.roles
        != frozenset(
            {
                SemanticEdgeRole.CONDITIONAL_TAKEN,
                SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
            }
        )
    ):
        return None
    return int(operation.predicate_anchor_ea)


def _conditional_reference_predicate(
    operation: FragmentOperation,
    *,
    reference_spelling: str | None = None,
) -> str | None:
    materialization = operation.storage_predicate_materialization
    normalization = operation.computed_branch_normalization
    portable_predicate = (
        materialization.predicate_kind
        if materialization is not None
        else normalization.predicate_kind
        if normalization is not None
        else None
    )
    if portable_predicate is None:
        return None
    if reference_spelling == portable_predicate.value:
        return portable_predicate.value
    return _REFERENCE_PREDICATE_BY_PORTABLE.get(portable_predicate)


def _conditional_operation_semantically_matches(
    plan: FragmentPlan,
    operation: FragmentOperation,
    route: ReferenceRouteRewrite,
) -> bool:
    candidate_anchor_ea = _conditional_candidate_anchor(operation)
    if (
        route.final_transfer_kind is not SemanticTransferKind.CONDITIONAL
        or candidate_anchor_ea is None
        or route.true_target_ea is None
        or route.false_target_ea is None
        or candidate_anchor_ea != int(route.owner_ea)
        or _conditional_reference_predicate(
            operation,
            reference_spelling=route.predicate_kind,
        )
        != route.predicate_kind
        or not any(
            int(start_ea) <= candidate_anchor_ea < int(end_ea)
            for start_ea, end_ea in route.corridor
        )
    ):
        return False
    source = plan.block(operation.source_block_id)
    source_identity = source.stable_identity
    if source_identity is None or not source_identity.native_ranges.contains(
        int(route.owner_ea)
    ):
        return False
    edge_by_role = {edge.role: edge for edge in operation.edges}
    expected_targets = (
        (SemanticEdgeRole.CONDITIONAL_TAKEN, int(route.true_target_ea)),
        (SemanticEdgeRole.CONDITIONAL_FALLTHROUGH, int(route.false_target_ea)),
    )
    return all(
        (edge := edge_by_role.get(role)) is not None
        and (target_identity := plan.block(edge.target_block_id).stable_identity)
        is not None
        and target_identity.native_ranges.contains(target_ea)
        for role, target_ea in expected_targets
    )


def _candidate_rewrite_anchor(operation: FragmentOperation) -> int | None:
    rewrite = operation.direct_transfer_rewrite
    if rewrite is not None:
        return int(rewrite.rewrite_anchor_ea)
    return _conditional_candidate_anchor(operation)


def bind_fragment_reference_oracle(
    plan: FragmentPlan,
    selection: ReferenceRouteOracleSelection,
) -> FragmentPlan:
    """Bind donor semantics to every exact candidate rewrite in one plan."""

    if not isinstance(plan, FragmentPlan):
        raise TypeError("reference oracle binding requires a FragmentPlan")
    if not isinstance(selection, ReferenceRouteOracleSelection):
        raise TypeError("reference oracle binding requires a route selection")
    if plan.reference_oracle_run is not None or any(
        operation.reference_route_authority is not None for operation in plan.operations
    ):
        raise DetachedRouteOracleRejected(
            "fragment plan already carries reference oracle authority",
            reason_code="fragment_reference_authority_already_bound",
        )
    root_anchors = tuple(
        int(plan.block(root_block_id).semantic_anchor_ea)
        for root_block_id in plan.roots
    )
    if root_anchors != (int(selection.publication_root_ea),):
        raise DetachedRouteOracleRejected(
            "fragment and reference selection require one exact publication root",
            reason_code="fragment_reference_publication_root_mismatch",
            payload={
                "planned_publication_roots": tuple(
                    f"0x{anchor_ea:X}" for anchor_ea in root_anchors
                ),
                "selected_publication_root": (
                    f"0x{int(selection.publication_root_ea):X}"
                ),
            },
        )
    direct_operations = tuple(
        operation
        for operation in plan.operations
        if operation.direct_transfer_rewrite is not None
    )
    selected_anchors = tuple(route.rewrite_anchor_ea for route in selection.routes)
    route_by_operation_id: dict[str, ReferenceRouteRewrite] = {}
    coordinate_rebindings: list[dict[str, object]] = []
    unused_operation_ids = {operation.operation_id for operation in plan.operations}
    missing_routes: list[ReferenceRouteRewrite] = []
    for route in selection.routes:
        if route.final_transfer_kind is SemanticTransferKind.DIRECT:
            direct_candidates = tuple(
                operation
                for operation in direct_operations
                if operation.operation_id in unused_operation_ids
            )
            exact_matches = tuple(
                operation
                for operation in direct_candidates
                if operation.direct_transfer_rewrite is not None
                and int(operation.direct_transfer_rewrite.rewrite_anchor_ea)
                == int(route.rewrite_anchor_ea)
            )
            if len(exact_matches) == 1:
                (selected_operation,) = exact_matches
            else:
                semantic_matches: list[FragmentOperation] = []
                for operation in direct_candidates:
                    rewrite = operation.direct_transfer_rewrite
                    assert rewrite is not None
                    target = plan.block(operation.edges[0].target_block_id)
                    target_identity = target.stable_identity
                    if (
                        route.direct_target_ea is not None
                        and int(rewrite.owner_anchor_ea) == int(route.owner_ea)
                        and rewrite.owner_identity.native_ranges.contains(
                            route.owner_ea
                        )
                        and target_identity is not None
                        and target_identity.native_ranges.contains(
                            route.direct_target_ea
                        )
                        and any(
                            start_ea <= int(rewrite.rewrite_anchor_ea) < end_ea
                            for start_ea, end_ea in route.corridor
                        )
                        and all(
                            any(
                                start_ea <= ea < end_ea
                                for start_ea, end_ea in route.corridor
                            )
                            for ea in rewrite.proof_corridor_instruction_eas
                        )
                    ):
                        semantic_matches.append(operation)
                if len(semantic_matches) != 1:
                    missing_routes.append(route)
                    continue
                (selected_operation,) = semantic_matches
        elif route.final_transfer_kind is SemanticTransferKind.CONDITIONAL:
            conditional_candidates = tuple(
                operation
                for operation in plan.operations
                if operation.operation_id in unused_operation_ids
                and _conditional_candidate_anchor(operation) is not None
            )
            exact_matches = tuple(
                operation
                for operation in conditional_candidates
                if _conditional_candidate_anchor(operation)
                == int(route.rewrite_anchor_ea)
                and _conditional_reference_predicate(operation) == route.predicate_kind
            )
            if len(exact_matches) == 1:
                (selected_operation,) = exact_matches
            else:
                semantic_matches = tuple(
                    operation
                    for operation in conditional_candidates
                    if _conditional_operation_semantically_matches(
                        plan,
                        operation,
                        route,
                    )
                )
                if len(semantic_matches) != 1:
                    missing_routes.append(route)
                    continue
                (selected_operation,) = semantic_matches
        else:
            missing_routes.append(route)
            continue

        candidate_anchor_ea = _candidate_rewrite_anchor(selected_operation)
        assert candidate_anchor_ea is not None
        route_by_operation_id[selected_operation.operation_id] = route
        unused_operation_ids.remove(selected_operation.operation_id)
        if candidate_anchor_ea != int(route.rewrite_anchor_ea):
            coordinate_rebindings.append(
                {
                    "candidate_rewrite_anchor_ea": (f"0x{candidate_anchor_ea:X}"),
                    "operation_id": selected_operation.operation_id,
                    "reference_patch_anchor_ea": (
                        f"0x{int(route.rewrite_anchor_ea):X}"
                    ),
                    "reference_route_id": route.route_id,
                }
            )

    unexpected_operations = tuple(
        operation
        for operation in direct_operations
        if operation.operation_id in unused_operation_ids
    )
    planned_operations = tuple(
        operation
        for operation in plan.operations
        if operation.operation_id in route_by_operation_id
        or operation in unexpected_operations
    )
    planned_anchors = tuple(
        anchor_ea
        for operation in planned_operations
        if (anchor_ea := _candidate_rewrite_anchor(operation)) is not None
    )
    if (
        missing_routes
        or unexpected_operations
        or not planned_anchors
        or len(set(planned_anchors)) != len(planned_anchors)
    ):
        raise DetachedRouteOracleRejected(
            "fragment and reference selection require exact rewrite anchors",
            reason_code="fragment_reference_rewrite_anchor_set_mismatch",
            payload={
                "coordinate_rebindings": tuple(coordinate_rebindings),
                "missing_rewrite_anchors": tuple(
                    f"0x{int(route.rewrite_anchor_ea):X}" for route in missing_routes
                ),
                "planned_rewrite_anchors": tuple(
                    f"0x{anchor_ea:X}" for anchor_ea in planned_anchors
                ),
                "selected_rewrite_anchors": tuple(
                    f"0x{anchor_ea:X}" for anchor_ea in selected_anchors
                ),
                "unexpected_rewrite_anchors": tuple(
                    f"0x{int(anchor_ea):X}"
                    for operation in unexpected_operations
                    if (anchor_ea := _candidate_rewrite_anchor(operation)) is not None
                ),
            },
        )

    bound_operations: list[FragmentOperation] = []
    for operation in plan.operations:
        route = route_by_operation_id.get(operation.operation_id)
        if route is None:
            bound_operations.append(operation)
            continue
        candidate_anchor_ea = _candidate_rewrite_anchor(operation)
        assert candidate_anchor_ea is not None
        bound_operations.append(
            replace(
                operation,
                reference_route_authority=FragmentReferenceRouteAuthority(
                    reference_route=route,
                    candidate_rewrite_anchor_ea=candidate_anchor_ea,
                ),
            )
        )
    return replace(
        plan,
        operations=tuple(bound_operations),
        reference_oracle_run=selection.run,
    )


def _reachable_block_ids(
    plan: FragmentPlan,
    projection: ProjectedFragment,
) -> frozenset[str]:
    by_id = {block.block_id: block for block in projection.blocks}
    pending = list(projected_publication_authority_roots(plan, projection))
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
    if route.final_transfer_kind is SemanticTransferKind.DIRECT:
        target_ea = route.direct_target_ea
        if target_ea is None:
            return SemanticRouteObservation(
                route_id=route.route_id,
                lane=RouteCaptureLane.REFERENCE,
                maturity=_DETACHED_MATURITY,
                outcome="rejected",
                shape=None,
                reason=f"reference route {route.route_id} has no direct target",
            )
        terminator_kind = InsnKind.GOTO
        direct_target_ea = int(target_ea)
        true_target_ea = None
        false_target_ea = None
        predicate_kind = None
        successor_eas = (int(target_ea),)
        physical_fallthrough_ea = None
    elif route.final_transfer_kind is SemanticTransferKind.CONDITIONAL:
        if (
            route.true_target_ea is None
            or route.false_target_ea is None
            or route.predicate_kind is None
        ):
            return SemanticRouteObservation(
                route_id=route.route_id,
                lane=RouteCaptureLane.REFERENCE,
                maturity=_DETACHED_MATURITY,
                outcome="rejected",
                shape=None,
                reason=f"reference route {route.route_id} is incomplete",
            )
        terminator_kind = InsnKind.EQUALITY_JUMP
        direct_target_ea = None
        true_target_ea = int(route.true_target_ea)
        false_target_ea = int(route.false_target_ea)
        predicate_kind = str(route.predicate_kind)
        successor_eas = tuple(sorted((true_target_ea, false_target_ea)))
        physical_fallthrough_ea = false_target_ea
    else:
        return SemanticRouteObservation(
            route_id=route.route_id,
            lane=RouteCaptureLane.REFERENCE,
            maturity=_DETACHED_MATURITY,
            outcome="rejected",
            shape=None,
            reason=f"reference route {route.route_id} is not a semantic rewrite",
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
            terminator_opcode=terminator_kind.value,
            transfer_kind=route.final_transfer_kind,
            direct_target_ea=direct_target_ea,
            true_target_ea=true_target_ea,
            false_target_ea=false_target_ea,
            predicate_kind=predicate_kind,
            successor_eas=successor_eas,
            physical_fallthrough_ea=physical_fallthrough_ea,
            reachable_from_entry=True,
        ),
        reason="",
    )


def _candidate_failure(
    route: ReferenceRouteRewrite,
    reason: str,
    *,
    failed_invariant: str | None = None,
) -> SemanticRouteObservation:
    return SemanticRouteObservation(
        route_id=route.route_id,
        lane=RouteCaptureLane.CANDIDATE,
        maturity=_DETACHED_MATURITY,
        outcome="invalid",
        shape=None,
        reason=reason,
        failed_invariant=failed_invariant,
    )


def _candidate_terminator_failure(
    route: ReferenceRouteRewrite,
    source: ProjectedFragmentBlock,
) -> SemanticRouteObservation:
    source_block_id = source.block_id
    instruction_eas = tuple(int(ea) for ea in source.instruction_eas)
    terminator_ea_value = source.terminator_ea
    terminator_ea = None if terminator_ea_value is None else int(terminator_ea_value)
    terminator_kind = source.terminator_kind
    expected_rewrite_anchor_ea = int(route.rewrite_anchor_ea)
    failed_invariant = (
        "staged_rewrite_anchor_missing"
        if expected_rewrite_anchor_ea not in instruction_eas
        else "staged_rewrite_terminator_mismatch"
    )
    staged_terminator = "none" if terminator_ea is None else f"0x{terminator_ea:X}"
    staged_instruction_eas = ",".join(f"0x{ea:X}" for ea in instruction_eas)
    return _candidate_failure(
        route,
        f"route {route.route_id} {failed_invariant}: "
        f"source_block_id={source_block_id!r} "
        f"expected_rewrite_anchor_ea=0x{expected_rewrite_anchor_ea:X} "
        f"staged_terminator_ea={staged_terminator} "
        f"staged_terminator_kind={terminator_kind.value} "
        f"staged_instruction_eas=[{staged_instruction_eas}]",
        failed_invariant=failed_invariant,
    )


def _owned_projected_route_successors(
    plan: FragmentPlan,
    projection: ProjectedFragment,
    operation: FragmentOperation,
    source: ProjectedFragmentBlock,
) -> _OwnedProjectedRouteSuccessors:
    operation_helpers = tuple(
        helper
        for helper in projection.fallthrough_helpers
        if helper.operation_id == operation.operation_id
    )
    if len(operation_helpers) > 1:
        raise _ProjectedRouteOwnershipError(
            f"route operation {operation.operation_id!r} has multiple staged helpers"
        )
    helper = None if not operation_helpers else operation_helpers[0]
    expected_helper_id = f"fallthrough-helper:{operation.operation_id}"
    fallthrough_edges = tuple(
        edge
        for edge in operation.edges
        if edge.role
        in {
            SemanticEdgeRole.CALL_FALLTHROUGH,
            SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
        }
    )
    if helper is not None:
        if (
            helper.helper_block_id != expected_helper_id
            or helper.source_block_id != operation.source_block_id
            or len(fallthrough_edges) != 1
            or helper.semantic_target_block_id != fallthrough_edges[0].target_block_id
        ):
            raise _ProjectedRouteOwnershipError(
                f"route operation {operation.operation_id!r} has a drifted "
                "fallthrough helper descriptor"
            )
        try:
            helper_block = projection.block(helper.helper_block_id)
            helper_binding = projection.binding(helper.helper_block_id)
            source_binding = projection.binding(operation.source_block_id)
            semantic_target = plan.block(helper.semantic_target_block_id)
        except KeyError as exc:
            raise _ProjectedRouteOwnershipError(
                f"route operation {operation.operation_id!r} has an incomplete "
                "fallthrough helper witness"
            ) from exc
        if (
            helper.helper_block_id not in source.successors
            or helper_block.kind is not BlockKind.ONE_WAY
            or helper_block.successors != (semantic_target.block_id,)
            or helper_block.predecessors != (source.block_id,)
            or helper_block.physical_position != source.physical_position + 1
            or helper_block.adjacent_fallthrough_target_id is not None
            or helper_block.instruction_eas
            or helper_block.terminator_ea is not None
            or helper_block.terminator_kind is not InsnKind.GOTO
            or helper_binding.state is not FragmentBindingState.STAGED
            or helper_binding.stable_identity is not None
            or helper_binding.generation != source_binding.generation
        ):
            raise _ProjectedRouteOwnershipError(
                f"route operation {operation.operation_id!r} has a malformed "
                "fallthrough helper witness; "
                f"source_successors={source.successors!r} "
                f"helper_kind={helper_block.kind.value!r} "
                f"helper_successors={helper_block.successors!r} "
                f"helper_predecessors={helper_block.predecessors!r} "
                f"positions=({source.physical_position!r},"
                f"{helper_block.physical_position!r}) "
                f"adjacent={helper_block.adjacent_fallthrough_target_id!r} "
                f"instruction_eas={helper_block.instruction_eas!r} "
                f"terminator=({helper_block.terminator_ea!r},"
                f"{helper_block.terminator_kind.value!r}) "
                f"binding=({helper_binding.state.value!r},"
                f"{helper_binding.stable_identity!r},"
                f"{helper_binding.generation!r}) "
                f"source_generation={source_binding.generation!r}"
            )

    semantic_block_ids: list[str] = []
    for block_id in source.successors:
        if helper is not None and block_id == helper.helper_block_id:
            semantic_block_ids.append(helper.semantic_target_block_id)
            continue
        try:
            semantic_block_ids.append(plan.block(block_id).block_id)
        except KeyError as exc:
            raise _ProjectedRouteOwnershipError(
                f"route operation {operation.operation_id!r} has an unowned "
                f"staged successor {block_id!r}"
            ) from exc
    return _OwnedProjectedRouteSuccessors(
        semantic_block_ids=tuple(semantic_block_ids),
        conditional_fallthrough_block_id=(
            None
            if helper is None
            or fallthrough_edges[0].role is not SemanticEdgeRole.CONDITIONAL_FALLTHROUGH
            else helper.helper_block_id
        ),
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
    except KeyError:
        return _candidate_failure(
            route,
            f"route {route.route_id} has no staged source block",
        )
    rewrite = operation.direct_transfer_rewrite
    if route.final_transfer_kind is SemanticTransferKind.DIRECT:
        if rewrite is None:
            return _candidate_failure(
                route,
                f"route {route.route_id} has no staged direct rewrite",
            )
        owner_identity = rewrite.owner_identity
        owner_anchor_ea = int(rewrite.owner_anchor_ea)
        predicate_kind = None
    elif route.final_transfer_kind is SemanticTransferKind.CONDITIONAL:
        candidate_anchor_ea = _conditional_candidate_anchor(operation)
        source_plan_block = plan.block(operation.source_block_id)
        owner_identity = source_plan_block.stable_identity
        if candidate_anchor_ea is None or owner_identity is None:
            return _candidate_failure(
                route,
                f"route {route.route_id} has no staged conditional authority",
            )
        owner_anchor_ea = candidate_anchor_ea
        predicate_kind = _conditional_reference_predicate(
            operation,
            reference_spelling=route.predicate_kind,
        )
    else:
        return _candidate_failure(
            route,
            f"route {route.route_id} has no supported staged transfer",
        )
    if owner_anchor_ea != route.owner_ea or not owner_identity.native_ranges.contains(
        route.owner_ea
    ):
        return _candidate_failure(
            route,
            f"route {route.route_id} staged rewrite does not own 0x{route.owner_ea:X}",
        )
    if (
        source.terminator_ea != route.rewrite_anchor_ea
        or route.rewrite_anchor_ea not in source.instruction_eas
    ):
        return _candidate_terminator_failure(route, source)
    try:
        owned_successors = _owned_projected_route_successors(
            plan,
            projection,
            operation,
            source,
        )
    except _ProjectedRouteOwnershipError as exc:
        return _candidate_failure(
            route,
            f"route {route.route_id} {exc}",
            failed_invariant="staged_helper_ownership",
        )
    successor_blocks = tuple(
        plan.block(block_id) for block_id in owned_successors.semantic_block_ids
    )
    operation_target_ids = frozenset(edge.target_block_id for edge in operation.edges)
    if frozenset(owned_successors.semantic_block_ids) != operation_target_ids:
        return _candidate_failure(
            route,
            f"route {route.route_id} staged successors drifted from its operation",
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
    true_target_ea: int | None = None
    false_target_ea: int | None = None
    physical_fallthrough_ea: int | None = None
    if route.final_transfer_kind is SemanticTransferKind.CONDITIONAL:
        edge_by_role = {edge.role: edge for edge in operation.edges}
        true_edge = edge_by_role.get(SemanticEdgeRole.CONDITIONAL_TAKEN)
        false_edge = edge_by_role.get(SemanticEdgeRole.CONDITIONAL_FALLTHROUGH)
        if (
            true_edge is None
            or false_edge is None
            or source.adjacent_fallthrough_target_id
            != (
                owned_successors.conditional_fallthrough_block_id
                or false_edge.target_block_id
            )
        ):
            return _candidate_failure(
                route,
                f"route {route.route_id} has no exact semantic fallthrough",
            )
        true_target_ea = int(plan.block(true_edge.target_block_id).semantic_anchor_ea)
        false_target_ea = int(plan.block(false_edge.target_block_id).semantic_anchor_ea)
        physical_fallthrough_ea = false_target_ea
    owner_start_ea = min(
        int(interval.start_ea) for interval in owner_identity.native_ranges.intervals
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
            true_target_ea=true_target_ea,
            false_target_ea=false_target_ea,
            predicate_kind=predicate_kind,
            successor_eas=successor_eas,
            physical_fallthrough_ea=physical_fallthrough_ea,
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
            "detached route oracle requires one pinned reference run",
            reason_code="detached_reference_run_missing",
        )

    selected: list[tuple[FragmentOperation, ReferenceRouteRewrite]] = []
    for operation in plan.operations:
        authority = operation.reference_route_authority
        if authority is None:
            if operation.direct_transfer_rewrite is not None:
                raise DetachedRouteOracleRejected(
                    f"operation {operation.operation_id!r} has no reference route",
                    reason_code="detached_operation_reference_route_missing",
                    payload={"operation_id": operation.operation_id},
                )
            continue
        selected.append((operation, authority.semantic_route))
    if not selected:
        raise DetachedRouteOracleRejected(
            "detached route oracle requires selected semantic rewrites",
            reason_code="detached_semantic_rewrites_missing",
        )

    reachable_block_ids = _reachable_block_ids(plan, projection)
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
    "bind_fragment_reference_oracle",
    "compare_detached_route_oracle",
]
