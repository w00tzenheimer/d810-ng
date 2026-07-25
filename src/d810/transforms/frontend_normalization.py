"""Plan complete frontend-normalization fragments from portable native proofs."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace

from d810.analyses.control_flow.frontend_normalization import (
    DetachedSemanticClosureImportRequest,
    FrontendNormalizationEvidence,
    FrontendNormalizationEvidenceRejected,
    NativeIndirectTransferProof,
    NativeTransferEndpoint,
    NativeTransferShape,
    native_anchor_matches,
    plan_detached_semantic_closure_import,
    unique_block_for_native_anchor,
)
from d810.analyses.control_flow.native_semantic_closure import (
    NativeBlock,
    NativeEdge,
    NativeEdgeKind,
    NativeTerminalKind,
)
from d810.ir.block_identity import (
    NativeEaInterval,
    StableBlockIdentity,
    stable_block_identity_semantic_anchor,
    stable_block_identity_from_snapshot,
    stable_block_identity_token,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind
from d810.ir.predicate_expressions import exact_branch_predicate_kind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.semantics import PredicateKind, inverted_predicate_kind
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentConditionalSelectEnvelope,
    FragmentComputedBranchNormalization,
    FragmentEdge,
    FragmentFlagCorridor,
    FragmentImportedConditionalSelectEnvelope,
    FragmentNativeBody,
    FragmentOperation,
    FragmentPlan,
    FragmentPublicationPurpose,
    FragmentValueSite,
    FragmentWorkItemScope,
)


_BADADDR = 0xFFFFFFFFFFFFFFFF


@dataclass(frozen=True, slots=True)
class ProjectedRouteCorridorBlock:
    """One snapshot-local block reference paired with its required EA anchor."""

    serial: int
    anchor_ea: int

    def __post_init__(self) -> None:
        serial = int(self.serial)
        anchor_ea = int(self.anchor_ea)
        if serial < 0:
            raise ValueError("projected corridor block serial must be non-negative")
        if not 0 <= anchor_ea < _BADADDR:
            raise ValueError("projected corridor block requires a valid EA anchor")
        object.__setattr__(self, "serial", serial)
        object.__setattr__(self, "anchor_ea", anchor_ea)

    @property
    def label(self) -> str:
        return f"blk{self.serial}@0x{self.anchor_ea:X}"

    def to_payload(self) -> dict[str, object]:
        return {
            "label": self.label,
            "serial": self.serial,
            "anchor_ea": f"0x{self.anchor_ea:X}",
        }


@dataclass(frozen=True, slots=True)
class ProjectedRouteCorridorFailure:
    """EA-anchored explanation for one projected corridor boundary failure."""

    reason_code: str
    edge_role: str
    context_anchor_ea: int
    corridor_block: ProjectedRouteCorridorBlock | None
    boundary_block: ProjectedRouteCorridorBlock | None

    def __post_init__(self) -> None:
        reason_code = str(self.reason_code).strip()
        edge_role = str(self.edge_role).strip()
        context_anchor_ea = int(self.context_anchor_ea)
        if not reason_code:
            raise ValueError("projected corridor failure reason must not be empty")
        if not edge_role:
            raise ValueError("projected corridor failure edge role must not be empty")
        if not 0 <= context_anchor_ea < _BADADDR:
            raise ValueError("projected corridor failure requires a valid context EA")
        object.__setattr__(self, "reason_code", reason_code)
        object.__setattr__(self, "edge_role", edge_role)
        object.__setattr__(self, "context_anchor_ea", context_anchor_ea)

    def to_payload(self) -> dict[str, object]:
        return {
            "reason_code": self.reason_code,
            "edge_role": self.edge_role,
            "context_anchor_ea": f"0x{self.context_anchor_ea:X}",
            "corridor_block": (
                None
                if self.corridor_block is None
                else self.corridor_block.to_payload()
            ),
            "boundary_block": (
                None
                if self.boundary_block is None
                else self.boundary_block.to_payload()
            ),
        }

    def description(self) -> str:
        corridor_label = (
            "unanchored corridor block"
            if self.corridor_block is None
            else self.corridor_block.label
        )
        boundary_label = (
            "unanchored boundary block"
            if self.boundary_block is None
            else self.boundary_block.label
        )
        if self.reason_code == "external_predecessor":
            return f"external predecessor {boundary_label} -> {corridor_label}"
        if self.reason_code == "external_successor":
            return f"external successor {corridor_label} -> {boundary_label}"
        return f"{self.reason_code} at {corridor_label}"


class FrontendNormalizationCorridorRejected(FrontendNormalizationEvidenceRejected):
    """Projected normalization routes have an open EA-anchored boundary."""

    def __init__(self, failure: ProjectedRouteCorridorFailure) -> None:
        if not isinstance(failure, ProjectedRouteCorridorFailure):
            raise TypeError(
                "frontend normalization corridor rejection requires "
                "a projected corridor failure"
            )
        self.failure = failure
        super().__init__(
            f"original route corridor is not closed: {failure.description()}"
        )


@dataclass(frozen=True, slots=True)
class FrontendNormalizationGenerationPlan:
    """Complete portable intent plus one connected publication work item."""

    complete_plan: FragmentPlan
    work_item_plan: FragmentPlan

    def __post_init__(self) -> None:
        if not isinstance(self.complete_plan, FragmentPlan) or not isinstance(
            self.work_item_plan,
            FragmentPlan,
        ):
            raise TypeError(
                "frontend normalization generation requires FragmentPlan values"
            )
        if (
            self.complete_plan.publication_purpose
            is not FragmentPublicationPurpose.FRONTEND_NORMALIZATION
            or self.work_item_plan.publication_purpose
            is not FragmentPublicationPurpose.FRONTEND_NORMALIZATION
        ):
            raise TypeError(
                "frontend normalization generation requires normalization plans"
            )
        if self.complete_plan.native_key != self.work_item_plan.native_key:
            raise FrontendNormalizationEvidenceRejected(
                "frontend normalization generation native identity drifted"
            )


@dataclass(frozen=True, slots=True)
class _BoundTransferProof:
    proof: NativeIndirectTransferProof
    source: BlockSnapshot
    endpoints: tuple[
        tuple[NativeTransferEndpoint, BlockSnapshot | None],
        ...,
    ]
    corridor: tuple[BlockSnapshot, ...]


@dataclass(frozen=True, slots=True)
class _ImportedTransferProof:
    """One transfer whose source exists only in the detached native closure."""

    proof: NativeIndirectTransferProof
    source: NativeBlock
    endpoints: tuple[
        tuple[
            NativeTransferEndpoint,
            BlockSnapshot | None,
            NativeBlock | None,
        ],
        ...,
    ]
    corridor: tuple[NativeBlock, ...]


@dataclass(frozen=True, slots=True)
class _BoundConditionalSelectEnvelope:
    """One exact live conditional-select shape owned by a portable proof."""

    predicate_ea: int
    observed_predicate_kind: PredicateKind
    selected_value: BlockSnapshot
    join: BlockSnapshot


@dataclass(frozen=True, slots=True)
class _BoundImportedConditionalSelectEnvelope:
    """Exact native routing blocks consumed by one imported semantic branch."""

    source_branch_ea: int
    selected_value_ea: int
    selected_value: NativeBlock
    join: NativeBlock


def _bind_corridor_block(
    graph: FlowGraph,
    identity: StableBlockIdentity,
    *,
    preferred_anchor_ea: int | None = None,
    preferred_block: BlockSnapshot | None = None,
) -> BlockSnapshot | None:
    anchor_ea = (
        stable_block_identity_semantic_anchor(identity)
        if preferred_anchor_ea is None
        else int(preferred_anchor_ea)
    )
    matches = native_anchor_matches(graph, identity, anchor_ea)
    if preferred_block is not None:
        preferred = tuple(
            block
            for block in matches
            if int(block.serial) == int(preferred_block.serial)
        )
        if len(preferred) == 1:
            return preferred[0]
    return matches[0] if len(matches) == 1 else None


def _bind_source_block(
    graph: FlowGraph,
    proof: NativeIndirectTransferProof,
) -> BlockSnapshot | None:
    matches = native_anchor_matches(
        graph,
        proof.source_identity,
        proof.source_anchor_ea,
    )
    if len(matches) == 1:
        return matches[0]
    if proof.shape is not NativeTransferShape.CONDITIONAL:
        return None
    conditional_owners = tuple(
        block
        for block in matches
        if block.tail is not None
        and block.tail.is_conditional_jump
        and int(block.tail.ea) == int(proof.predicate_anchor_ea)
    )
    return conditional_owners[0] if len(conditional_owners) == 1 else None


def _bind_proof(
    graph: FlowGraph,
    proof: NativeIndirectTransferProof,
) -> _BoundTransferProof | None:
    source = _bind_source_block(graph, proof)
    if source is None:
        return None
    endpoints: list[tuple[NativeTransferEndpoint, BlockSnapshot | None]] = []
    for endpoint in proof.endpoints:
        target = unique_block_for_native_anchor(
            graph,
            endpoint.identity,
            endpoint.anchor_ea,
        )
        endpoints.append((endpoint, target))

    corridor: list[BlockSnapshot] = []
    for index, identity in enumerate(proof.flag_corridor):
        preferred_anchor_ea = None
        if index == 0:
            preferred_anchor_ea = proof.condition_producer_ea
        if index == len(proof.flag_corridor) - 1:
            preferred_anchor_ea = proof.predicate_anchor_ea
        block = _bind_corridor_block(
            graph,
            identity,
            preferred_anchor_ea=preferred_anchor_ea,
            preferred_block=(source if index == len(proof.flag_corridor) - 1 else None),
        )
        if block is None:
            return None
        if corridor and int(corridor[-1].serial) == int(block.serial):
            continue
        if any(int(item.serial) == int(block.serial) for item in corridor):
            return None
        corridor.append(block)
    return _BoundTransferProof(
        proof=proof,
        source=source,
        endpoints=tuple(endpoints),
        corridor=tuple(corridor),
    )


def _proof_is_faithful(binding: _BoundTransferProof) -> bool:
    proof = binding.proof
    if proof.shape is NativeTransferShape.DIRECT:
        target = binding.endpoints[0][1]
        if target is None:
            return False
        return binding.source.kind is BlockKind.ONE_WAY and binding.source.succs == (
            int(target.serial),
        )

    if any(target is None for _endpoint, target in binding.endpoints):
        return False
    target_by_role = {endpoint.role: block for endpoint, block in binding.endpoints}
    taken = target_by_role[SemanticEdgeRole.CONDITIONAL_TAKEN]
    fallthrough = target_by_role[SemanticEdgeRole.CONDITIONAL_FALLTHROUGH]
    tail = binding.source.tail
    explicit_target = None if tail is None or tail.d is None else tail.d.block_ref
    return bool(
        binding.source.kind is BlockKind.TWO_WAY
        and len(binding.source.succs) == 2
        and set(binding.source.succs) == {int(taken.serial), int(fallthrough.serial)}
        and tail is not None
        and tail.is_conditional_jump
        and int(tail.ea) == int(proof.predicate_anchor_ea)
        and explicit_target is not None
        and int(explicit_target) == int(taken.serial)
    )


def _bind_conditional_select_envelope(
    graph: FlowGraph,
    binding: _BoundTransferProof,
) -> _BoundConditionalSelectEnvelope | None:
    """Bind one exact CMOV-style split without relying on block serials later."""
    proof = binding.proof
    source = binding.source
    tail = source.tail
    if (
        proof.shape is not NativeTransferShape.CONDITIONAL
        or proof.predicate_kind is None
        or proof.predicate_anchor_ea is None
        or source.kind is not BlockKind.TWO_WAY
        or len(source.succs) != 2
        or tail is None
        or not tail.is_conditional_jump
        or int(tail.ea) == int(proof.predicate_anchor_ea)
    ):
        return None
    observed_predicate = exact_branch_predicate_kind(
        source.insn_snapshots,
        condition_producer_ea=int(proof.condition_producer_ea),
    )
    inverted_predicate = inverted_predicate_kind(proof.predicate_kind)
    if observed_predicate not in {
        proof.predicate_kind,
        inverted_predicate,
    }:
        return None
    explicit_target = None if tail.d is None else tail.d.block_ref
    if explicit_target is None:
        return None
    nonexplicit_targets = tuple(
        int(serial) for serial in source.succs if int(serial) != int(explicit_target)
    )
    if int(explicit_target) not in source.succs or len(nonexplicit_targets) != 1:
        return None
    semantic_true_target = (
        int(explicit_target)
        if observed_predicate is proof.predicate_kind
        else nonexplicit_targets[0]
    )

    candidates: list[tuple[BlockSnapshot, BlockSnapshot]] = []
    for selected_serial in source.succs:
        selected = graph.blocks.get(int(selected_serial))
        if selected is None:
            continue
        other_serials = tuple(
            int(serial)
            for serial in source.succs
            if int(serial) != int(selected.serial)
        )
        if len(other_serials) != 1:
            continue
        join = graph.blocks.get(other_serials[0])
        selected_instructions = selected.insn_snapshots
        join_tail = None if join is None else join.tail
        if (
            join is None
            or semantic_true_target != int(selected.serial)
            or selected.kind is not BlockKind.ONE_WAY
            or selected.succs != (int(join.serial),)
            or tuple(graph.predecessors(int(selected.serial))) != (int(source.serial),)
            or set(graph.predecessors(int(join.serial)))
            != {int(source.serial), int(selected.serial)}
            or len(selected_instructions) != 1
            or selected_instructions[0].value_op_kind is not ValueOpKind.MOVE
            or int(selected_instructions[0].ea) != int(tail.ea)
            or join.kind is not BlockKind.ZERO_WAY
            or join_tail is None
            or join_tail.kind is not InsnKind.INDIRECT_JUMP
            or int(join_tail.ea) != int(proof.source_transfer_ea)
        ):
            continue
        candidates.append((selected, join))
    if len(candidates) != 1:
        return None
    selected, join = candidates[0]
    return _BoundConditionalSelectEnvelope(
        predicate_ea=int(tail.ea),
        observed_predicate_kind=observed_predicate,
        selected_value=selected,
        join=join,
    )


def _conditional_select_diagnostic(
    graph: FlowGraph,
    binding: _BoundTransferProof,
) -> str:
    """Render one serial-safe portable shape for the diagnostic database."""

    def label(serial: int) -> str:
        block = graph.blocks.get(int(serial))
        return (
            f"blk{int(serial)}@missing"
            if block is None
            else f"blk{int(serial)}@0x{int(block.start_ea):X}"
        )

    def operand_row(operand) -> object:
        if operand is None:
            return None
        return (
            operand.kind.value,
            int(operand.size),
            operand.reg,
            operand.value,
            (None if operand.sub_kind is None else operand.sub_kind.value),
            (
                None
                if operand.sub_value_op_kind is None
                else operand.sub_value_op_kind.value
            ),
            operand_row(operand.sub_l),
            operand_row(operand.sub_r),
        )

    def block_row(block: BlockSnapshot) -> tuple[object, ...]:
        tail = block.tail
        explicit_target = (
            None
            if tail is None or tail.d is None or tail.d.block_ref is None
            else label(int(tail.d.block_ref))
        )
        return (
            label(int(block.serial)),
            block.kind.value,
            tuple(label(serial) for serial in block.succs),
            tuple(label(serial) for serial in graph.predecessors(block.serial)),
            (
                None
                if tail is None
                else (
                    f"0x{int(tail.ea):X}",
                    tail.kind.value,
                    (
                        None
                        if tail.predicate_kind is None
                        else tail.predicate_kind.value
                    ),
                    explicit_target,
                    operand_row(tail.l),
                    operand_row(tail.r),
                )
            ),
            tuple(
                (
                    f"0x{int(instruction.ea):X}",
                    instruction.kind.value,
                    (
                        None
                        if instruction.value_op_kind is None
                        else instruction.value_op_kind.value
                    ),
                    (
                        None
                        if instruction.predicate_kind is None
                        else instruction.predicate_kind.value
                    ),
                )
                for instruction in block.insn_snapshots
            ),
        )

    source = binding.source
    neighbour_serials = {
        int(source.serial),
        *(int(serial) for serial in source.succs),
        *(
            int(successor)
            for serial in source.succs
            for successor in graph.blocks.get(int(serial), source).succs
        ),
    }
    rows = tuple(
        block_row(graph.blocks[serial])
        for serial in sorted(neighbour_serials)
        if serial in graph.blocks
    )
    return (
        f"proof_predicate={binding.proof.predicate_kind.value!r} "
        f"predicate_anchor=0x{int(binding.proof.predicate_anchor_ea):X} "
        f"transfer=0x{int(binding.proof.source_transfer_ea):X} "
        f"portable_shape={rows!r}"
    )


def _graph_identities(
    graph: FlowGraph,
    evidence: FrontendNormalizationEvidence,
    serials: set[int],
) -> dict[int, StableBlockIdentity] | None:
    identities: dict[int, StableBlockIdentity] = {}
    for serial in sorted(serials):
        block = graph.blocks.get(int(serial))
        if block is None:
            return None
        identity = stable_block_identity_from_snapshot(
            block,
            native_key=evidence.native_key,
        )
        if identity is None:
            return None
        identities[int(block.serial)] = identity
    if len(set(identities.values())) != len(identities):
        return None
    return identities


def _native_block_identity(
    native_block: NativeBlock,
    evidence: FrontendNormalizationEvidence,
    *,
    exact_instruction_eas: tuple[int, ...] = (),
) -> StableBlockIdentity:
    block_start_ea = int(native_block.start_ea)
    block_end_ea = int(native_block.end_ea)
    exact_eas = tuple(
        sorted(
            {
                block_start_ea,
                *(int(ea) for ea in exact_instruction_eas),
            }
        )
    )
    if any(not block_start_ea <= ea < block_end_ea for ea in exact_eas):
        raise FrontendNormalizationEvidenceRejected(
            "imported block exact anchors escaped their native CFG owner"
        )
    return StableBlockIdentity.from_intervals(
        (
            NativeEaInterval(
                block_start_ea,
                block_end_ea,
            ),
        ),
        native_key=evidence.native_key,
        exact_instruction_eas=exact_eas,
    )


def _request_native_block(
    request: DetachedSemanticClosureImportRequest,
    anchor_ea: int,
) -> NativeBlock | None:
    matches = tuple(
        native_block
        for entry_ea in request.semantic_closure.included_block_eas
        for native_block in (request.native_cfg.blocks_by_ea.get(int(entry_ea)),)
        if native_block is not None
        and int(native_block.start_ea) <= int(anchor_ea) < int(native_block.end_ea)
    )
    return matches[0] if len(matches) == 1 else None


def _publication_native_entry_eas(
    request: DetachedSemanticClosureImportRequest,
) -> frozenset[int]:
    """Select the control-flow component exposed by the missing-entry roots."""
    range_owned_seed_eas: list[int] = []
    for seed in request.semantic_closure.seed_provenance:
        if not seed.owned_native_ranges:
            continue
        if any(
            not any(
                int(closure_range.start_ea) <= int(owned_range.start_ea)
                and int(owned_range.end_ea) <= int(closure_range.end_ea)
                for closure_range in request.semantic_closure.native_ranges
            )
            for owned_range in seed.owned_native_ranges
        ):
            raise FrontendNormalizationEvidenceRejected(
                f"range-owned handler seed 0x{int(seed.entry_ea):X} "
                "escapes its semantic closure"
            )
        range_owned_seed_eas.append(int(seed.entry_ea))
    publication_root_eas = tuple(
        sorted(
            {
                *(int(entry_ea) for entry_ea in request.required_entry_eas),
                *range_owned_seed_eas,
            }
        )
    )
    pending = [
        int(native_block.start_ea)
        for entry_ea in publication_root_eas
        for native_block in (_request_native_block(request, int(entry_ea)),)
        if native_block is not None
    ]
    if len(pending) != len(publication_root_eas):
        raise FrontendNormalizationEvidenceRejected(
            "detached import entry is not owned by one native closure block"
        )

    reachable: set[int] = set()
    while pending:
        entry_ea = pending.pop()
        if entry_ea in reachable:
            continue
        reachable.add(entry_ea)
        native_block = request.native_cfg.blocks_by_ea[entry_ea]
        for edge in native_block.outgoing_edges:
            if edge.kind is NativeEdgeKind.CALL or edge.target_ea is None:
                continue
            target = _request_native_block(request, int(edge.target_ea))
            if target is None:
                continue
            target_entry_ea = int(target.start_ea)
            if target_entry_ea not in reachable:
                pending.append(target_entry_ea)
    return frozenset(reachable)


def _bind_imported_proof(
    graph: FlowGraph,
    request: DetachedSemanticClosureImportRequest,
    proof: NativeIndirectTransferProof,
) -> _ImportedTransferProof | None:
    """Bind a proof only when its absent source belongs uniquely to the closure."""
    live_source_matches = native_anchor_matches(
        graph,
        proof.source_identity,
        proof.source_anchor_ea,
    )
    if live_source_matches:
        raise FrontendNormalizationEvidenceRejected(
            f"transfer proof {proof.proof_id!r} has "
            f"{len(live_source_matches)} live source candidates but cannot "
            "bind its complete shape"
        )
    source = _request_native_block(
        request,
        proof.source_anchor_ea,
    )
    if source is None:
        source_identity_ranges = tuple(
            (int(interval.start_ea), int(interval.end_ea))
            for interval in proof.source_identity.native_ranges.intervals
        )
        detached_block_ranges = tuple(
            (
                int(native_block.start_ea),
                int(native_block.end_ea),
            )
            for entry_ea in request.semantic_closure.included_block_eas
            for native_block in (request.native_cfg.blocks_by_ea.get(int(entry_ea)),)
            if native_block is not None
        )
        raise FrontendNormalizationEvidenceRejected(
            f"transfer proof {proof.proof_id!r} source "
            f"0x{proof.source_anchor_ea:X} is not owned by one detached block; "
            f"source_identity={source_identity_ranges!r} "
            f"detached_blocks={detached_block_ranges!r}"
        )

    endpoints: list[
        tuple[
            NativeTransferEndpoint,
            BlockSnapshot | None,
            NativeBlock | None,
        ]
    ] = []
    for endpoint in proof.endpoints:
        live_target = unique_block_for_native_anchor(
            graph,
            endpoint.identity,
            endpoint.anchor_ea,
        )
        native_target = (
            None
            if live_target is not None
            else _request_native_block(request, endpoint.anchor_ea)
        )
        if live_target is None and native_target is None:
            raise FrontendNormalizationEvidenceRejected(
                f"transfer proof {proof.proof_id!r} target "
                f"0x{endpoint.anchor_ea:X} is unavailable"
            )
        endpoints.append((endpoint, live_target, native_target))

    corridor: list[NativeBlock] = []
    for index, identity in enumerate(proof.flag_corridor):
        anchor_ea = stable_block_identity_semantic_anchor(identity)
        if index == 0 and proof.condition_producer_ea is not None:
            anchor_ea = int(proof.condition_producer_ea)
        if index == len(proof.flag_corridor) - 1:
            anchor_ea = int(proof.predicate_anchor_ea)
        if native_anchor_matches(graph, identity, anchor_ea):
            raise FrontendNormalizationEvidenceRejected(
                f"transfer proof {proof.proof_id!r} flag corridor mixes "
                f"detached and live ownership at 0x{anchor_ea:X}"
            )
        native_block = _request_native_block(request, anchor_ea)
        if native_block is None:
            raise FrontendNormalizationEvidenceRejected(
                f"transfer proof {proof.proof_id!r} flag corridor anchor "
                f"0x{anchor_ea:X} is not owned by one detached block"
            )
        if corridor and int(corridor[-1].start_ea) == int(native_block.start_ea):
            continue
        if any(int(item.start_ea) == int(native_block.start_ea) for item in corridor):
            raise FrontendNormalizationEvidenceRejected(
                f"transfer proof {proof.proof_id!r} flag corridor repeats "
                f"detached block 0x{native_block.start_ea:X}"
            )
        corridor.append(native_block)
    return _ImportedTransferProof(
        proof=proof,
        source=source,
        endpoints=tuple(endpoints),
        corridor=tuple(corridor),
    )


def _bind_imported_conditional_select_envelope(
    request: DetachedSemanticClosureImportRequest,
    binding: _ImportedTransferProof,
) -> _BoundImportedConditionalSelectEnvelope | None:
    """Own an exact source/select/join shape when the transfer is downstream."""
    proof = binding.proof
    source = binding.source
    transfer_ea = int(proof.source_transfer_ea)
    if proof.shape is not NativeTransferShape.CONDITIONAL:
        return None
    if int(source.start_ea) <= transfer_ea < int(source.end_ea):
        selected_ea = proof.conditional_select_ea
        join_ea = proof.conditional_select_join_ea
        if selected_ea is None or join_ea is None:
            return None
        selected_ea = int(selected_ea)
        join_ea = int(join_ea)
        control_edges = tuple(
            edge
            for edge in source.outgoing_edges
            if edge.kind is not NativeEdgeKind.CALL
        )
        endpoint_eas = {int(endpoint.anchor_ea) for endpoint in proof.endpoints}
        if (
            source.terminal is not NativeTerminalKind.STOP
            or len(control_edges) != len(endpoint_eas)
            or {
                int(edge.target_ea)
                for edge in control_edges
                if edge.target_ea is not None
            }
            != endpoint_eas
            or any(
                edge.kind is not NativeEdgeKind.INDIRECT
                or not edge.resolver_proven
                or edge.provenance != "resolver_proven_native_cut"
                or edge.target_ea is None
                or edge.source_instruction_ea is None
                or int(edge.source_instruction_ea) != transfer_ea
                for edge in control_edges
            )
        ):
            raise FrontendNormalizationEvidenceRejected(
                f"transfer proof {proof.proof_id!r} same-block "
                "conditional-select join lacks resolver ownership"
            )
        return _BoundImportedConditionalSelectEnvelope(
            source_branch_ea=selected_ea,
            selected_value_ea=selected_ea,
            selected_value=NativeBlock(
                start_ea=selected_ea,
                end_ea=join_ea,
                outgoing_edges=(
                    NativeEdge(
                        kind=NativeEdgeKind.FALLTHROUGH,
                        target_ea=join_ea,
                        source_instruction_ea=selected_ea,
                    ),
                ),
            ),
            join=NativeBlock(
                start_ea=join_ea,
                end_ea=int(source.end_ea),
                outgoing_edges=control_edges,
                terminal=NativeTerminalKind.STOP,
            ),
        )

    control_edges = tuple(
        edge for edge in source.outgoing_edges if edge.kind is not NativeEdgeKind.CALL
    )
    edge_by_kind = {edge.kind: edge for edge in control_edges}
    branch_eas = {edge.source_instruction_ea for edge in control_edges}
    join = _request_native_block(request, transfer_ea)
    if (
        len(control_edges) != 2
        or set(edge_by_kind)
        != {
            NativeEdgeKind.CONDITIONAL_TRUE,
            NativeEdgeKind.CONDITIONAL_FALSE,
        }
        or None in branch_eas
        or len(branch_eas) != 1
        or join is None
        or int(join.start_ea) == int(source.start_ea)
    ):
        raise FrontendNormalizationEvidenceRejected(
            f"transfer proof {proof.proof_id!r} imported conditional-select "
            "source or join is incomplete"
        )
    successor_entries = {
        int(target.start_ea)
        for edge in control_edges
        if edge.target_ea is not None
        for target in (_request_native_block(request, int(edge.target_ea)),)
        if target is not None
    }
    join_entry_ea = int(join.start_ea)
    selected_entries = successor_entries - {join_entry_ea}
    if (
        len(successor_entries) != 2
        or join_entry_ea not in successor_entries
        or len(selected_entries) != 1
    ):
        raise FrontendNormalizationEvidenceRejected(
            f"transfer proof {proof.proof_id!r} imported conditional-select "
            "source does not own one selected-value arm and one join arm"
        )
    selected = request.native_cfg.blocks_by_ea.get(next(iter(selected_entries)))
    selected_control_edges = (
        ()
        if selected is None
        else tuple(
            edge
            for edge in selected.outgoing_edges
            if edge.kind is not NativeEdgeKind.CALL
        )
    )
    join_control_edges = tuple(
        edge for edge in join.outgoing_edges if edge.kind is not NativeEdgeKind.CALL
    )
    if (
        selected is None
        or len(selected_control_edges) != 1
        or selected_control_edges[0].kind
        not in {
            NativeEdgeKind.DIRECT_JUMP,
            NativeEdgeKind.FALLTHROUGH,
        }
        or selected_control_edges[0].target_ea is None
        or int(selected_control_edges[0].target_ea) != join_entry_ea
        or len(join_control_edges) != 1
        or join_control_edges[0].kind is not NativeEdgeKind.INDIRECT
        or not join_control_edges[0].resolver_proven
        or join_control_edges[0].source_instruction_ea is None
        or int(join_control_edges[0].source_instruction_ea) != transfer_ea
    ):
        raise FrontendNormalizationEvidenceRejected(
            f"transfer proof {proof.proof_id!r} imported conditional-select "
            "selected-value or indirect-join topology is incomplete"
        )
    return _BoundImportedConditionalSelectEnvelope(
        source_branch_ea=int(next(iter(branch_eas))),
        selected_value_ea=int(selected.start_ea),
        selected_value=selected,
        join=join,
    )


def _live_block_at_native_ea(
    graph: FlowGraph,
    ea: int,
) -> BlockSnapshot | None:
    matches = tuple(
        block
        for block in graph.blocks.values()
        if int(ea)
        in {
            int(block.start_ea),
            *(int(instruction.ea) for instruction in block.insn_snapshots),
        }
    )
    return matches[0] if len(matches) == 1 else None


def _entry_root_corridor_serials(
    graph: FlowGraph,
    root_serials: tuple[int, ...],
) -> set[int]:
    """Return every live block on an entry-to-publication-root path."""
    entry_serial = int(graph.entry_serial)
    forward_reachable = {entry_serial}
    pending = [entry_serial]
    while pending:
        serial = pending.pop()
        block = graph.blocks.get(serial)
        if block is None:
            continue
        for successor in block.succs:
            successor = int(successor)
            if successor in forward_reachable:
                continue
            forward_reachable.add(successor)
            pending.append(successor)

    root_ancestors = {int(serial) for serial in root_serials}
    pending = list(root_ancestors)
    while pending:
        serial = pending.pop()
        for predecessor in graph.predecessors(serial):
            predecessor = int(predecessor)
            if predecessor in root_ancestors:
                continue
            root_ancestors.add(predecessor)
            pending.append(predecessor)
    return forward_reachable & root_ancestors


def _projected_route_corridor_serials(
    graph: FlowGraph,
    relevant_serials: set[int],
) -> set[int]:
    """Close projected outgoing routes without guessing incoming boundaries."""

    def block_ref(serial: int) -> ProjectedRouteCorridorBlock | None:
        block = graph.blocks.get(int(serial))
        if block is None:
            return None
        candidates = (
            int(block.start_ea),
            *(int(instruction.ea) for instruction in block.insn_snapshots),
        )
        anchor_ea = next(
            (ea for ea in candidates if 0 <= ea < _BADADDR),
            None,
        )
        if anchor_ea is None:
            return None
        return ProjectedRouteCorridorBlock(
            serial=int(block.serial),
            anchor_ea=anchor_ea,
        )

    def reject(
        *,
        reason_code: str,
        edge_role: str,
        corridor_serial: int | None,
        boundary_serial: int | None,
    ) -> None:
        raise FrontendNormalizationCorridorRejected(
            ProjectedRouteCorridorFailure(
                reason_code=reason_code,
                edge_role=edge_role,
                context_anchor_ea=int(graph.func_ea),
                corridor_block=(
                    None if corridor_serial is None else block_ref(corridor_serial)
                ),
                boundary_block=(
                    None if boundary_serial is None else block_ref(boundary_serial)
                ),
            )
        )

    relevant = {int(serial) for serial in relevant_serials}
    corridor: set[int] = set()
    pending: deque[tuple[int, int]] = deque()
    for serial in sorted(relevant):
        block = graph.blocks.get(serial)
        if block is None:
            reject(
                reason_code="missing_relevant_block",
                edge_role="relevant_member",
                corridor_serial=None,
                boundary_serial=None,
            )
        for successor in sorted(int(item) for item in block.succs):
            if successor not in relevant:
                pending.append((serial, successor))
    while pending:
        predecessor, serial = pending.popleft()
        if serial in relevant or serial in corridor:
            continue
        block = graph.blocks.get(serial)
        if block is None:
            reject(
                reason_code="missing_successor_block",
                edge_role="outgoing_successor",
                corridor_serial=predecessor,
                boundary_serial=None,
            )
        corridor.add(serial)
        for successor in sorted(int(item) for item in block.succs):
            if successor not in relevant and successor not in corridor:
                pending.append((serial, successor))

    closed_serials = relevant | corridor
    for serial in sorted(closed_serials):
        block = graph.blocks.get(serial)
        if block is None:
            reject(
                reason_code="missing_corridor_block",
                edge_role="corridor_member",
                corridor_serial=None,
                boundary_serial=None,
            )
        external_predecessors = sorted(
            int(predecessor)
            for predecessor in graph.predecessors(serial)
            if int(predecessor) not in closed_serials
        )
        if external_predecessors:
            reject(
                reason_code="external_predecessor",
                edge_role="incoming_predecessor",
                corridor_serial=serial,
                boundary_serial=external_predecessors[0],
            )
        external_successors = sorted(
            int(successor)
            for successor in block.succs
            if int(successor) not in closed_serials
        )
        if external_successors:
            reject(
                reason_code="external_successor",
                edge_role="outgoing_successor",
                corridor_serial=serial,
                boundary_serial=external_successors[0],
            )
    return corridor


def plan_frontend_computed_branch_normalization(
    graph: FlowGraph,
    evidence: FrontendNormalizationEvidence,
    *,
    detached_import_request: DetachedSemanticClosureImportRequest | None = None,
) -> FragmentPlan | None:
    """Build one closed, atomic normalization plan or abstain without mutation."""
    if not isinstance(graph, FlowGraph):
        raise TypeError("frontend branch normalization requires a FlowGraph")
    if not isinstance(evidence, FrontendNormalizationEvidence):
        raise TypeError(
            "frontend branch normalization requires portable normalization evidence"
        )

    import_request = detached_import_request
    if import_request is None:
        import_request = plan_detached_semantic_closure_import(graph, evidence)
    elif not isinstance(import_request, DetachedSemanticClosureImportRequest):
        raise TypeError("frontend normalization import request is not portable")
    elif (
        import_request.native_key != evidence.native_key
        or int(import_request.generation) != int(evidence.generation)
        or import_request.atomic_group_id != evidence.atomic_group_id
        or import_request.semantic_closure != evidence.semantic_closure
        or import_request.native_cfg != evidence.native_cfg
    ):
        raise FrontendNormalizationEvidenceRejected(
            "frontend normalization import request authority drifted"
        )
    live_bindings: list[_BoundTransferProof] = []
    imported_bindings: list[_ImportedTransferProof] = []
    for proof in evidence.transfer_proofs:
        binding = _bind_proof(graph, proof)
        if binding is not None:
            live_bindings.append(binding)
            continue
        imported_binding = (
            None
            if import_request is None
            else _bind_imported_proof(graph, import_request, proof)
        )
        if imported_binding is None:
            raise FrontendNormalizationEvidenceRejected(
                f"transfer proof {proof.proof_id!r} cannot bind to a unique "
                "live or detached source"
            )
        imported_bindings.append(imported_binding)
    if not imported_bindings and all(
        _proof_is_faithful(binding) for binding in live_bindings
    ):
        return None

    live_conditional_selects: dict[str, _BoundConditionalSelectEnvelope] = {}
    for binding in live_bindings:
        if _proof_is_faithful(binding):
            continue
        proof = binding.proof
        tail = binding.source.tail
        is_split_conditional_candidate = bool(
            proof.shape is NativeTransferShape.CONDITIONAL
            and proof.predicate_anchor_ea is not None
            and binding.source.kind is BlockKind.TWO_WAY
            and tail is not None
            and tail.is_conditional_jump
            and int(tail.ea) != int(proof.predicate_anchor_ea)
        )
        if not is_split_conditional_candidate:
            continue
        envelope = _bind_conditional_select_envelope(graph, binding)
        if envelope is None:
            raise FrontendNormalizationEvidenceRejected(
                f"transfer proof {proof.proof_id!r} live conditional-select "
                "envelope is incomplete or ambiguous; "
                f"{_conditional_select_diagnostic(graph, binding)}"
            )
        live_conditional_selects[proof.proof_id] = envelope

    source_serials = tuple(int(binding.source.serial) for binding in live_bindings)
    source_serial_set = set(source_serials)
    if any(
        int(block.serial) in source_serial_set
        for envelope in live_conditional_selects.values()
        for block in (envelope.selected_value, envelope.join)
    ):
        raise FrontendNormalizationEvidenceRejected(
            "live conditional-select envelope overlaps another transfer source"
        )
    if (
        not source_serials
        or len(source_serial_set) != len(source_serials)
        or int(graph.entry_serial) in source_serials
        or any(not graph.predecessors(serial) for serial in source_serials)
    ):
        raise FrontendNormalizationEvidenceRejected(
            "normalization requires unique non-entry live transfer sources "
            "with published predecessors"
        )
    root_source_serials = tuple(
        serial
        for serial in source_serials
        if any(
            predecessor not in source_serial_set
            for predecessor in graph.predecessors(serial)
        )
    )
    if not root_source_serials:
        raise FrontendNormalizationEvidenceRejected(
            "normalization has no live transfer-source publication root"
        )
    entry_root_corridor_serials = _entry_root_corridor_serials(
        graph,
        root_source_serials,
    )
    if not set(root_source_serials) <= entry_root_corridor_serials:
        raise FrontendNormalizationEvidenceRejected(
            "normalization publication roots are not reachable from function entry"
        )

    body_id = f"native-body:{evidence.atomic_group_id}"
    imported_native_blocks: dict[int, NativeBlock] = {}
    imported_identities: dict[int, StableBlockIdentity] = {}
    imported_ids: dict[int, str] = {}
    imported_binding_by_entry: dict[int, _ImportedTransferProof] = {}
    for binding in imported_bindings:
        entry_ea = int(binding.source.start_ea)
        if entry_ea in imported_binding_by_entry:
            raise FrontendNormalizationEvidenceRejected(
                f"detached source 0x{entry_ea:X} has multiple proof owners"
            )
        imported_binding_by_entry[entry_ea] = binding
    imported_conditional_selects = {
        binding.proof.proof_id: envelope
        for binding in imported_bindings
        for envelope in (
            (
                None
                if import_request is None
                else _bind_imported_conditional_select_envelope(
                    import_request,
                    binding,
                )
            ),
        )
        if envelope is not None
    }
    absorbed_native_entry_owners: dict[int, str] = {}
    for proof_id, envelope in imported_conditional_selects.items():
        for native_block in (envelope.selected_value, envelope.join):
            entry_ea = int(native_block.start_ea)
            previous_owner = absorbed_native_entry_owners.setdefault(
                entry_ea,
                proof_id,
            )
            if previous_owner != proof_id:
                raise FrontendNormalizationEvidenceRejected(
                    f"imported conditional-select block 0x{entry_ea:X} "
                    "belongs to multiple semantic envelopes"
                )
    absorbed_native_entries = frozenset(absorbed_native_entry_owners)
    overlapping_proof_sources = absorbed_native_entries & set(imported_binding_by_entry)
    if overlapping_proof_sources:
        raise FrontendNormalizationEvidenceRejected(
            "imported conditional-select routing blocks overlap transfer "
            f"sources {tuple(hex(ea) for ea in sorted(overlapping_proof_sources))!r}"
        )
    proof_owned_native_entries = frozenset(imported_binding_by_entry)
    if import_request is not None:
        publication_native_entries = _publication_native_entry_eas(import_request)
        for entry_ea in import_request.semantic_closure.included_block_eas:
            if int(entry_ea) not in publication_native_entries:
                continue
            if int(entry_ea) in absorbed_native_entries:
                continue
            native_block = import_request.native_cfg.blocks_by_ea[int(entry_ea)]
            imported_binding = imported_binding_by_entry.get(int(entry_ea))
            proof_exact_eas = (
                ()
                if imported_binding is None
                else tuple(
                    int(ea)
                    for proof_identity in (
                        imported_binding.proof.source_identity,
                        *imported_binding.proof.flag_corridor,
                    )
                    for ea in proof_identity.exact_instruction_eas
                    if int(native_block.start_ea) <= int(ea) < int(native_block.end_ea)
                )
            )
            identity = _native_block_identity(
                native_block,
                evidence,
                exact_instruction_eas=proof_exact_eas,
            )
            if (
                imported_binding is None
                and unique_block_for_native_anchor(
                    graph,
                    identity,
                    int(native_block.start_ea),
                )
                is not None
            ):
                continue
            imported_native_blocks[int(entry_ea)] = native_block
            imported_identities[int(entry_ea)] = identity
            imported_ids[int(entry_ea)] = (
                f"native[{stable_block_identity_token(identity)}]:imported"
            )
        if not imported_native_blocks:
            raise FrontendNormalizationEvidenceRejected(
                "detached closure contains no unpublished native blocks"
            )

    def imported_id_for_anchor(anchor_ea: int) -> str | None:
        if import_request is None:
            return None
        native_block = _request_native_block(import_request, int(anchor_ea))
        if native_block is None:
            return None
        return imported_ids.get(int(native_block.start_ea))

    for binding in live_bindings:
        for endpoint, target in binding.endpoints:
            if target is None and imported_id_for_anchor(endpoint.anchor_ea) is None:
                raise FrontendNormalizationEvidenceRejected(
                    f"proof {binding.proof.proof_id!r} target "
                    f"0x{endpoint.anchor_ea:X} is unavailable"
                )
    for binding in imported_bindings:
        if int(binding.source.start_ea) not in imported_ids:
            raise FrontendNormalizationEvidenceRejected(
                f"proof {binding.proof.proof_id!r} detached source is not "
                "owned by the import request"
            )
        for _endpoint, live_target, native_target in binding.endpoints:
            if live_target is not None:
                continue
            if native_target is None or int(native_target.start_ea) not in imported_ids:
                raise FrontendNormalizationEvidenceRejected(
                    f"proof {binding.proof.proof_id!r} detached target is not "
                    "owned by the import request"
                )

    relevant_serials = set(source_serials)
    for binding in live_bindings:
        relevant_serials.update(
            int(target.serial)
            for _endpoint, target in binding.endpoints
            if target is not None
        )
        relevant_serials.update(int(block.serial) for block in binding.corridor)
    for envelope in live_conditional_selects.values():
        relevant_serials.update(
            {
                int(envelope.selected_value.serial),
                int(envelope.join.serial),
            }
        )
    for binding in imported_bindings:
        relevant_serials.update(
            int(live_target.serial)
            for _endpoint, live_target, _native_target in binding.endpoints
            if live_target is not None
        )
    relevant_serials.update(entry_root_corridor_serials)
    for native_block in imported_native_blocks.values():
        for edge in native_block.outgoing_edges:
            if edge.kind is NativeEdgeKind.CALL or edge.target_ea is None:
                continue
            live_target = _live_block_at_native_ea(graph, int(edge.target_ea))
            if live_target is not None:
                relevant_serials.add(int(live_target.serial))
    projected_route_corridor_serials = _projected_route_corridor_serials(
        graph,
        relevant_serials,
    )
    relevant_serials.update(projected_route_corridor_serials)

    identities = _graph_identities(graph, evidence, relevant_serials)
    if identities is None:
        raise FrontendNormalizationEvidenceRejected(
            "normalization route corridor lacks unique stable identities"
        )
    base_ids = {
        serial: f"native[{stable_block_identity_token(identity)}]"
        for serial, identity in identities.items()
    }
    original_ids = {serial: f"{base_ids[serial]}:original" for serial in source_serials}
    replacement_ids = {
        serial: f"{base_ids[serial]}:replacement" for serial in source_serials
    }

    def published_id(serial: int) -> str:
        return replacement_ids.get(int(serial), base_ids[int(serial)])

    blocks: list[FragmentBlock] = []
    for serial in sorted(relevant_serials):
        identity = identities[serial]
        semantic_anchor_ea = stable_block_identity_semantic_anchor(identity)
        if serial in replacement_ids:
            original_id = original_ids[serial]
            blocks.extend(
                (
                    FragmentBlock(
                        block_id=original_id,
                        role=FragmentBlockRole.ORIGINAL,
                        materialization=(FragmentBlockMaterialization.REUSE_PUBLISHED),
                        semantic_anchor_ea=semantic_anchor_ea,
                        stable_identity=identity,
                    ),
                    FragmentBlock(
                        block_id=replacement_ids[serial],
                        role=FragmentBlockRole.REPLACEMENT,
                        materialization=(FragmentBlockMaterialization.CLONE_PUBLISHED),
                        semantic_anchor_ea=semantic_anchor_ea,
                        stable_identity=identity,
                        replaces_block_id=original_id,
                    ),
                )
            )
            continue
        blocks.append(
            FragmentBlock(
                block_id=base_ids[serial],
                role=FragmentBlockRole.EXTERNAL,
                materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
                semantic_anchor_ea=semantic_anchor_ea,
                stable_identity=identity,
            )
        )
    for entry_ea, native_block in sorted(imported_native_blocks.items()):
        identity = imported_identities[entry_ea]
        blocks.append(
            FragmentBlock(
                block_id=imported_ids[entry_ea],
                role=FragmentBlockRole.IMPORTED,
                materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
                semantic_anchor_ea=int(native_block.start_ea),
                stable_identity=identity,
                native_body_id=body_id,
            )
        )

    operations: list[FragmentOperation] = []
    flag_corridors: list[FragmentFlagCorridor] = []
    for binding in live_bindings:
        proof = binding.proof
        source_block_id = replacement_ids[int(binding.source.serial)]
        conditional_select = live_conditional_selects.get(proof.proof_id)
        operations.append(
            FragmentOperation(
                operation_id=proof.proof_id,
                source_block_id=source_block_id,
                predicate_anchor_ea=proof.predicate_anchor_ea,
                computed_branch_normalization=(
                    None
                    if conditional_select is None
                    else FragmentComputedBranchNormalization(
                        predicate_kind=proof.predicate_kind,
                        normalization_start_ea=int(proof.source_anchor_ea),
                        condition_producer_ea=int(proof.condition_producer_ea),
                        unresolved_transfer_ea=int(proof.source_transfer_ea),
                        relocated_instruction_eas=proof.relocated_instruction_eas,
                        conditional_select_envelope=(
                            FragmentConditionalSelectEnvelope(
                                predicate_ea=conditional_select.predicate_ea,
                                observed_predicate_kind=(
                                    conditional_select.observed_predicate_kind
                                ),
                                selected_value_block_id=base_ids[
                                    int(conditional_select.selected_value.serial)
                                ],
                                join_block_id=base_ids[
                                    int(conditional_select.join.serial)
                                ],
                            )
                        ),
                    )
                ),
                edges=tuple(
                    FragmentEdge(
                        role=endpoint.role,
                        target_block_id=(
                            published_id(target.serial)
                            if target is not None
                            else str(imported_id_for_anchor(endpoint.anchor_ea))
                        ),
                    )
                    for endpoint, target in binding.endpoints
                ),
            )
        )
        if proof.shape is not NativeTransferShape.CONDITIONAL:
            continue
        producer_block_id = published_id(binding.corridor[0].serial)
        consumer_block_id = published_id(binding.corridor[-1].serial)
        value_id = f"condition-code:{proof.proof_id}"
        flag_corridors.append(
            FragmentFlagCorridor(
                corridor_id=f"flag-corridor:{proof.proof_id}",
                producer=FragmentValueSite(
                    site_id=f"flag-producer:{proof.proof_id}",
                    block_id=producer_block_id,
                    value_id=value_id,
                    instruction_ea=int(proof.condition_producer_ea),
                ),
                consumer=FragmentValueSite(
                    site_id=f"flag-consumer:{proof.proof_id}",
                    block_id=consumer_block_id,
                    value_id=value_id,
                    instruction_ea=int(proof.predicate_anchor_ea),
                ),
                block_path=tuple(
                    published_id(block.serial) for block in binding.corridor
                ),
                permitted_flag_write_eas=proof.permitted_flag_write_eas,
            )
        )

    for binding in imported_bindings:
        proof = binding.proof
        source_block_id = imported_ids[int(binding.source.start_ea)]
        imported_conditional_select = imported_conditional_selects.get(proof.proof_id)
        imported_edges: list[FragmentEdge] = []
        for endpoint, live_target, native_target in binding.endpoints:
            target_block_id = (
                published_id(int(live_target.serial))
                if live_target is not None
                else imported_ids[int(native_target.start_ea)]
            )
            imported_edges.append(
                FragmentEdge(
                    role=endpoint.role,
                    target_block_id=target_block_id,
                )
            )
        operations.append(
            FragmentOperation(
                operation_id=proof.proof_id,
                source_block_id=source_block_id,
                predicate_anchor_ea=proof.predicate_anchor_ea,
                computed_branch_normalization=(
                    None
                    if proof.shape is not NativeTransferShape.CONDITIONAL
                    else FragmentComputedBranchNormalization(
                        predicate_kind=proof.predicate_kind,
                        normalization_start_ea=int(proof.source_anchor_ea),
                        condition_producer_ea=int(proof.condition_producer_ea),
                        unresolved_transfer_ea=int(proof.source_transfer_ea),
                        relocated_instruction_eas=proof.relocated_instruction_eas,
                        conditional_select_envelope=(
                            None
                            if imported_conditional_select is None
                            else FragmentImportedConditionalSelectEnvelope(
                                source_branch_ea=(
                                    imported_conditional_select.source_branch_ea
                                ),
                                selected_value_ea=(
                                    imported_conditional_select.selected_value_ea
                                ),
                                selected_value_identity=_native_block_identity(
                                    imported_conditional_select.selected_value,
                                    evidence,
                                    exact_instruction_eas=(
                                        imported_conditional_select.selected_value_ea,
                                    ),
                                ),
                                join_identity=_native_block_identity(
                                    imported_conditional_select.join,
                                    evidence,
                                    exact_instruction_eas=(proof.source_transfer_ea,),
                                ),
                            )
                        ),
                    )
                ),
                edges=tuple(imported_edges),
            )
        )
        if proof.shape is not NativeTransferShape.CONDITIONAL:
            continue
        corridor_block_ids = tuple(
            imported_ids[int(native_block.start_ea)]
            for native_block in binding.corridor
        )
        value_id = f"condition-code:{proof.proof_id}"
        flag_corridors.append(
            FragmentFlagCorridor(
                corridor_id=f"flag-corridor:{proof.proof_id}",
                producer=FragmentValueSite(
                    site_id=f"flag-producer:{proof.proof_id}",
                    block_id=corridor_block_ids[0],
                    value_id=value_id,
                    instruction_ea=int(proof.condition_producer_ea),
                ),
                consumer=FragmentValueSite(
                    site_id=f"flag-consumer:{proof.proof_id}",
                    block_id=corridor_block_ids[-1],
                    value_id=value_id,
                    instruction_ea=int(proof.predicate_anchor_ea),
                ),
                block_path=corridor_block_ids,
                permitted_flag_write_eas=proof.permitted_flag_write_eas,
            )
        )

    native_bodies: tuple[FragmentNativeBody, ...] = ()
    if import_request is not None:
        terminal_block_ids: list[str] = []

        def target_block_id(target_ea: int) -> str | None:
            imported_target_id = imported_id_for_anchor(int(target_ea))
            if imported_target_id is not None:
                return imported_target_id
            live_target = _live_block_at_native_ea(graph, int(target_ea))
            return (
                None if live_target is None else published_id(int(live_target.serial))
            )

        for entry_ea, native_block in sorted(imported_native_blocks.items()):
            source_block_id = imported_ids[entry_ea]
            if entry_ea in proof_owned_native_entries:
                continue
            control_edges = tuple(
                edge
                for edge in native_block.outgoing_edges
                if edge.kind is not NativeEdgeKind.CALL
            )
            if not control_edges:
                if native_block.terminal is NativeTerminalKind.NONE:
                    raise FrontendNormalizationEvidenceRejected(
                        f"detached block 0x{entry_ea:X} has no control edge "
                        "or terminal proof"
                    )
                terminal_block_ids.append(source_block_id)
                continue

            operation_id = f"native-body-edge@0x{entry_ea:X}"
            if len(control_edges) == 1:
                edge = control_edges[0]
                if edge.target_ea is None or edge.kind not in {
                    NativeEdgeKind.DIRECT_JUMP,
                    NativeEdgeKind.FALLTHROUGH,
                    NativeEdgeKind.CALL_FALLTHROUGH,
                    NativeEdgeKind.INDIRECT,
                }:
                    raise FrontendNormalizationEvidenceRejected(
                        f"detached block 0x{entry_ea:X} has an unsupported "
                        "single-edge shape"
                    )
                if edge.kind is NativeEdgeKind.INDIRECT and not edge.resolver_proven:
                    raise FrontendNormalizationEvidenceRejected(
                        f"detached block 0x{entry_ea:X} has an unproved indirect edge"
                    )
                target_id = target_block_id(int(edge.target_ea))
                if target_id is None:
                    raise FrontendNormalizationEvidenceRejected(
                        f"detached block 0x{entry_ea:X} {edge.kind.value} "
                        f"target 0x{int(edge.target_ea):X} is unavailable"
                    )
                operations.append(
                    FragmentOperation(
                        operation_id=operation_id,
                        source_block_id=source_block_id,
                        edges=(
                            FragmentEdge(
                                role=(
                                    SemanticEdgeRole.CALL_FALLTHROUGH
                                    if edge.kind is NativeEdgeKind.CALL_FALLTHROUGH
                                    else SemanticEdgeRole.DIRECT
                                ),
                                target_block_id=target_id,
                            ),
                        ),
                    )
                )
                continue

            edge_by_kind = {edge.kind: edge for edge in control_edges}
            if len(control_edges) != 2 or set(edge_by_kind) != {
                NativeEdgeKind.CONDITIONAL_TRUE,
                NativeEdgeKind.CONDITIONAL_FALSE,
            }:
                raise FrontendNormalizationEvidenceRejected(
                    f"detached block 0x{entry_ea:X} has an unsupported multi-edge shape"
                )
            true_edge = edge_by_kind[NativeEdgeKind.CONDITIONAL_TRUE]
            false_edge = edge_by_kind[NativeEdgeKind.CONDITIONAL_FALSE]
            predicate_anchors = {
                edge.source_instruction_ea for edge in (true_edge, false_edge)
            }
            if (
                true_edge.target_ea is None
                or false_edge.target_ea is None
                or None in predicate_anchors
                or len(predicate_anchors) != 1
            ):
                raise FrontendNormalizationEvidenceRejected(
                    f"detached conditional block 0x{entry_ea:X} lacks one "
                    "predicate and two targets"
                )
            true_target_id = target_block_id(int(true_edge.target_ea))
            false_target_id = target_block_id(int(false_edge.target_ea))
            if (
                true_target_id is None
                or false_target_id is None
                or true_target_id == false_target_id
            ):
                raise FrontendNormalizationEvidenceRejected(
                    f"detached conditional block 0x{entry_ea:X} has "
                    "unavailable or aliased targets"
                )
            operations.append(
                FragmentOperation(
                    operation_id=operation_id,
                    source_block_id=source_block_id,
                    predicate_anchor_ea=int(next(iter(predicate_anchors))),
                    edges=(
                        FragmentEdge(
                            role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                            target_block_id=true_target_id,
                        ),
                        FragmentEdge(
                            role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                            target_block_id=false_target_id,
                        ),
                    ),
                )
            )
        imported_block_ids = set(imported_ids.values())
        semantic_entry_block_ids = {
            edge.target_block_id
            for operation in operations
            if operation.source_block_id not in imported_block_ids
            for edge in operation.edges
            if edge.target_block_id in imported_block_ids
        }
        semantic_entry_block_ids.update(
            imported_block_id
            for seed in import_request.semantic_closure.seed_provenance
            for imported_block_id in (imported_id_for_anchor(int(seed.entry_ea)),)
            if imported_block_id is not None
        )
        semantic_entry_block_ids.update(
            imported_block_id
            for required_entry_ea in import_request.required_entry_eas
            for imported_block_id in (imported_id_for_anchor(required_entry_ea),)
            if imported_block_id is not None
        )
        entry_block_ids = tuple(
            imported_ids[entry_ea]
            for entry_ea in sorted(imported_native_blocks)
            if imported_ids[entry_ea] in semantic_entry_block_ids
        )
        if not entry_block_ids:
            raise FrontendNormalizationEvidenceRejected(
                "detached import has no live-boundary or proof-owned body entry"
            )
        native_bodies = (
            FragmentNativeBody(
                body_id=body_id,
                block_ids=tuple(
                    imported_ids[entry_ea]
                    for entry_ea in sorted(imported_native_blocks)
                ),
                entry_block_ids=entry_block_ids,
                terminal_block_ids=tuple(terminal_block_ids),
                native_ranges=tuple(
                    NativeEaInterval(
                        int(native_range.start_ea),
                        int(native_range.end_ea),
                    )
                    for native_range in import_request.native_ranges
                ),
                proof_ids=import_request.proof_ids,
            ),
        )

    roots = tuple(replacement_ids[serial] for serial in root_source_serials)
    owned_originals = tuple(
        original_ids[int(binding.source.serial)] for binding in live_bindings
    )
    plan_id = (
        f"frontend-normalization:"
        f"0x{evidence.native_key.function_rva:X}:g{evidence.generation}"
    )
    proof_ids = tuple(proof.proof_id for proof in evidence.transfer_proofs)
    return FragmentPlan(
        plan_id=plan_id,
        atomic_group_id=evidence.atomic_group_id,
        publication_purpose=FragmentPublicationPurpose.FRONTEND_NORMALIZATION,
        native_key=evidence.native_key,
        blocks=tuple(blocks),
        roots=roots,
        owned_originals=owned_originals,
        prohibited_dispatcher_blocks=(),
        operations=tuple(operations),
        work_item_scope=FragmentWorkItemScope(
            work_item_id=f"{plan_id}:complete",
            selected_obligation_ids=proof_ids,
            remaining_obligation_ids=(),
            unreachable_obligation_ids=(),
        ),
        native_bodies=native_bodies,
        flag_corridors=tuple(flag_corridors),
    )


def _merged_native_ranges(
    plan: FragmentPlan,
    block_ids: set[str],
) -> tuple[NativeEaInterval, ...]:
    consumed_envelope_identities = tuple(
        identity
        for operation in plan.operations
        if operation.source_block_id in block_ids
        and operation.computed_branch_normalization is not None
        and isinstance(
            operation.computed_branch_normalization.conditional_select_envelope,
            FragmentImportedConditionalSelectEnvelope,
        )
        for identity in (
            operation.computed_branch_normalization.conditional_select_envelope.selected_value_identity,
            operation.computed_branch_normalization.conditional_select_envelope.join_identity,
        )
    )
    intervals = sorted(
        (
            *(
                interval
                for block_id in block_ids
                for interval in plan.block(
                    block_id
                ).stable_identity.native_ranges.intervals
            ),
            *(
                interval
                for identity in consumed_envelope_identities
                for interval in identity.native_ranges.intervals
            ),
        ),
        key=lambda interval: (int(interval.start_ea), int(interval.end_ea)),
    )
    merged: list[NativeEaInterval] = []
    for interval in intervals:
        if not merged or int(interval.start_ea) > int(merged[-1].end_ea):
            merged.append(interval)
            continue
        previous = merged[-1]
        merged[-1] = NativeEaInterval(
            int(previous.start_ea),
            max(int(previous.end_ea), int(interval.end_ea)),
        )
    return tuple(merged)


def _select_frontend_root_component(
    plan: FragmentPlan,
    evidence: FrontendNormalizationEvidence,
) -> FragmentPlan:
    """Select one live-root component and defer detached proof-owned siblings."""
    if (
        plan.publication_purpose
        is not FragmentPublicationPurpose.FRONTEND_NORMALIZATION
    ):
        raise TypeError("frontend work-item selection requires a normalization plan")
    operation_by_source = {
        operation.source_block_id: operation for operation in plan.operations
    }

    def root_component(
        root_block_id: str,
    ) -> tuple[set[str], set[str], tuple[FragmentFlagCorridor, ...]]:
        block_ids: set[str] = set()
        operation_ids: set[str] = set()
        pending = [root_block_id]
        while pending:
            block_id = pending.pop()
            if block_id in block_ids:
                continue
            block_ids.add(block_id)
            operation = operation_by_source.get(block_id)
            if operation is None:
                continue
            operation_ids.add(operation.operation_id)
            pending.extend(edge.target_block_id for edge in operation.edges)

        flag_corridors = tuple(
            corridor
            for corridor in plan.flag_corridors
            if corridor.consumer.block_id in block_ids
        )
        dependency_block_ids = {
            block_id
            for corridor in flag_corridors
            for block_id in (
                corridor.producer.block_id,
                corridor.consumer.block_id,
                *corridor.block_path,
            )
        }
        while dependency_block_ids - block_ids:
            pending.extend(dependency_block_ids - block_ids)
            while pending:
                block_id = pending.pop()
                if block_id in block_ids:
                    continue
                block_ids.add(block_id)
                operation = operation_by_source.get(block_id)
                if operation is None:
                    continue
                operation_ids.add(operation.operation_id)
                pending.extend(edge.target_block_id for edge in operation.edges)
            flag_corridors = tuple(
                corridor
                for corridor in plan.flag_corridors
                if corridor.consumer.block_id in block_ids
            )
            dependency_block_ids = {
                block_id
                for corridor in flag_corridors
                for block_id in (
                    corridor.producer.block_id,
                    corridor.consumer.block_id,
                    *corridor.block_path,
                )
            }
        return block_ids, operation_ids, flag_corridors

    publication_root_components = tuple(
        (root_block_id, *root_component(root_block_id)) for root_block_id in plan.roots
    )
    proof_owned_native_body_entry_ids: set[str] = set()
    semantic_closure = evidence.semantic_closure
    if semantic_closure is not None:
        declared_native_body_entry_ids = {
            entry_block_id
            for native_body in plan.native_bodies
            for entry_block_id in native_body.entry_block_ids
        }
        for seed in semantic_closure.seed_provenance:
            matches = tuple(
                block.block_id
                for block in plan.blocks
                if block.role is FragmentBlockRole.IMPORTED
                and block.stable_identity is not None
                and block.stable_identity.native_ranges.contains(int(seed.entry_ea))
            )
            if len(matches) > 1:
                raise FrontendNormalizationEvidenceRejected(
                    f"proof-owned native-body entry 0x{int(seed.entry_ea):X} "
                    "is ambiguous"
                )
            if not matches:
                continue
            if matches[0] not in declared_native_body_entry_ids:
                raise FrontendNormalizationEvidenceRejected(
                    f"proof-owned native-body entry 0x{int(seed.entry_ea):X} "
                    "is not declared by its body"
                )
            proof_owned_native_body_entry_ids.add(matches[0])
    proof_owned_native_body_components = tuple(
        (entry_block_id, *root_component(entry_block_id))
        for entry_block_id in sorted(proof_owned_native_body_entry_ids)
    )
    # Proof ownership keeps a detached component as a future obligation. It
    # does not give that component authority to join the current publication.
    dispositioned_operation_ids = {
        operation_id
        for _root_block_id, _block_ids, operation_ids, _corridors in (
            *publication_root_components,
            *proof_owned_native_body_components,
        )
        for operation_id in operation_ids
    }
    (
        selected_root,
        selected_block_ids,
        selected_operation_ids,
        selected_flag_corridors,
    ) = min(
        publication_root_components,
        key=lambda component: (
            len(component[2]),
            len(component[1]),
            len(component[3]),
            int(plan.block(component[0]).semantic_anchor_ea),
            str(component[0]),
        ),
    )

    selected_replacements = {
        block_id
        for block_id in selected_block_ids
        if plan.block(block_id).role is FragmentBlockRole.REPLACEMENT
    }
    selected_originals = {
        str(plan.block(block_id).replaces_block_id)
        for block_id in selected_replacements
    }
    selected_block_ids.update(selected_originals)
    selected_block_ids.update(
        block.block_id
        for block in plan.blocks
        if block.role is FragmentBlockRole.EXTERNAL
    )

    proof_ids = tuple(proof.proof_id for proof in evidence.transfer_proofs)
    pending_proof_ids = tuple(
        proof_id
        for proof_id in proof_ids
        if any(operation.operation_id == proof_id for operation in plan.operations)
    )
    selected_proof_ids = tuple(
        proof_id for proof_id in pending_proof_ids if proof_id in selected_operation_ids
    )
    if not selected_proof_ids:
        raise FrontendNormalizationEvidenceRejected(
            "selected normalization root owns no portable proof obligation"
        )
    remaining_proof_ids = tuple(
        proof_id
        for proof_id in pending_proof_ids
        if proof_id not in selected_proof_ids
        and proof_id in dispositioned_operation_ids
    )
    unreachable_proof_ids = tuple(
        proof_id
        for proof_id in pending_proof_ids
        if proof_id not in dispositioned_operation_ids
    )

    selected_operations = tuple(
        operation
        for operation in plan.operations
        if operation.operation_id in selected_operation_ids
    )
    selected_imported_ids = {
        block_id
        for block_id in selected_block_ids
        if plan.block(block_id).role is FragmentBlockRole.IMPORTED
    }
    selected_native_bodies: tuple[FragmentNativeBody, ...] = ()
    scoped_body_id: str | None = None
    if selected_imported_ids:
        if len(plan.native_bodies) != 1:
            raise FrontendNormalizationEvidenceRejected(
                "frontend work item requires exactly one portable native body"
            )
        native_body = plan.native_bodies[0]
        scoped_body_id = (
            f"{native_body.body_id}:root@"
            f"0x{int(plan.block(selected_root).semantic_anchor_ea):X}"
        )
        imported_entry_ids = {
            edge.target_block_id
            for operation in selected_operations
            if plan.block(operation.source_block_id).role
            is not FragmentBlockRole.IMPORTED
            for edge in operation.edges
            if edge.target_block_id in selected_imported_ids
        }
        imported_entry_ids.update(
            set(native_body.entry_block_ids) & selected_imported_ids
        )
        if not imported_entry_ids:
            raise FrontendNormalizationEvidenceRejected(
                "selected native body has no publication boundary entry"
            )
        selected_native_bodies = (
            FragmentNativeBody(
                body_id=scoped_body_id,
                block_ids=tuple(
                    block_id
                    for block_id in native_body.block_ids
                    if block_id in selected_imported_ids
                ),
                entry_block_ids=tuple(
                    block_id
                    for block_id in native_body.block_ids
                    if block_id in imported_entry_ids
                ),
                terminal_block_ids=tuple(
                    block_id
                    for block_id in native_body.terminal_block_ids
                    if block_id in selected_imported_ids
                ),
                native_ranges=_merged_native_ranges(plan, selected_imported_ids),
                proof_ids=tuple(
                    proof_id
                    for proof_id in native_body.proof_ids
                    if proof_id in selected_proof_ids
                ),
            ),
        )

    selected_blocks = tuple(
        replace(block, native_body_id=scoped_body_id)
        if block.block_id in selected_imported_ids
        else block
        for block in plan.blocks
        if block.block_id in selected_block_ids
    )
    root_anchor_ea = int(plan.block(selected_root).semantic_anchor_ea)
    work_item_suffix = f"root@0x{root_anchor_ea:X}"
    return FragmentPlan(
        plan_id=f"{plan.plan_id}:{work_item_suffix}",
        atomic_group_id=f"{plan.atomic_group_id}:{work_item_suffix}",
        publication_purpose=plan.publication_purpose,
        native_key=plan.native_key,
        blocks=selected_blocks,
        roots=tuple(root for root in plan.roots if root in selected_block_ids),
        owned_originals=tuple(
            original
            for original in plan.owned_originals
            if original in selected_originals
        ),
        prohibited_dispatcher_blocks=tuple(
            block_id
            for block_id in plan.prohibited_dispatcher_blocks
            if block_id in selected_block_ids
        ),
        operations=selected_operations,
        work_item_scope=FragmentWorkItemScope(
            work_item_id=f"{plan.plan_id}:{work_item_suffix}",
            selected_obligation_ids=selected_proof_ids,
            remaining_obligation_ids=remaining_proof_ids,
            unreachable_obligation_ids=unreachable_proof_ids,
        ),
        native_bodies=selected_native_bodies,
        flag_corridors=selected_flag_corridors,
    )


def plan_next_frontend_normalization_work_item(
    graph: FlowGraph,
    evidence: FrontendNormalizationEvidence,
    *,
    detached_import_request: DetachedSemanticClosureImportRequest | None = None,
) -> FragmentPlan | None:
    """Plan one connected normalization publication without claiming its siblings."""
    generation_plan = plan_frontend_normalization_generation(
        graph,
        evidence,
        detached_import_request=detached_import_request,
    )
    return None if generation_plan is None else generation_plan.work_item_plan


def plan_frontend_normalization_generation(
    graph: FlowGraph,
    evidence: FrontendNormalizationEvidence,
    *,
    detached_import_request: DetachedSemanticClosureImportRequest | None = None,
) -> FrontendNormalizationGenerationPlan | None:
    """Retain complete intent while selecting one connected publication."""
    complete_plan = plan_frontend_computed_branch_normalization(
        graph,
        evidence,
        detached_import_request=detached_import_request,
    )
    if complete_plan is None:
        return None
    return FrontendNormalizationGenerationPlan(
        complete_plan=complete_plan,
        work_item_plan=_select_frontend_root_component(
            complete_plan,
            evidence,
        ),
    )


__all__ = [
    "FrontendNormalizationGenerationPlan",
    "plan_frontend_computed_branch_normalization",
    "plan_frontend_normalization_generation",
    "plan_next_frontend_normalization_work_item",
]
