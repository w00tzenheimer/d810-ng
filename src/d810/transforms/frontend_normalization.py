"""Plan complete frontend-normalization fragments from portable native proofs."""

from __future__ import annotations

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
    NativeEdgeKind,
    NativeTerminalKind,
)
from d810.ir.block_identity import (
    NativeEaInterval,
    StableBlockIdentity,
    stable_block_identity_from_snapshot,
)
from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentEdge,
    FragmentFlagCorridor,
    FragmentNativeBody,
    FragmentOperation,
    FragmentPlan,
    FragmentPublicationPurpose,
    FragmentValueSite,
    FragmentWorkItemScope,
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


def _semantic_anchor(identity: StableBlockIdentity) -> int:
    if identity.exact_instruction_eas:
        return min(identity.exact_instruction_eas)
    return identity.native_ranges.intervals[0].start_ea


def _identity_token(identity: StableBlockIdentity) -> str:
    return ",".join(
        f"0x{interval.start_ea:X}-0x{interval.end_ea:X}"
        for interval in identity.native_ranges.intervals
    )


def _bind_corridor_block(
    graph: FlowGraph,
    identity: StableBlockIdentity,
    *,
    preferred_anchor_ea: int | None = None,
    preferred_block: BlockSnapshot | None = None,
) -> BlockSnapshot | None:
    anchor_ea = (
        _semantic_anchor(identity)
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
    pending = [
        int(native_block.start_ea)
        for entry_ea in request.required_entry_eas
        for native_block in (_request_native_block(request, int(entry_ea)),)
        if native_block is not None
    ]
    if len(pending) != len(request.required_entry_eas):
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
        anchor_ea = _semantic_anchor(identity)
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
) -> set[int] | None:
    """Close projected outgoing routes without guessing incoming boundaries."""
    relevant = {int(serial) for serial in relevant_serials}
    corridor: set[int] = set()
    pending = [
        int(successor)
        for serial in relevant
        for successor in graph.blocks[serial].succs
        if int(successor) not in relevant
    ]
    while pending:
        serial = pending.pop()
        if serial in relevant or serial in corridor:
            continue
        block = graph.blocks.get(serial)
        if block is None:
            return None
        corridor.add(serial)
        pending.extend(
            int(successor)
            for successor in block.succs
            if int(successor) not in relevant and int(successor) not in corridor
        )

    closed_serials = relevant | corridor
    for serial in closed_serials:
        block = graph.blocks.get(serial)
        if block is None:
            return None
        neighbours = {
            *(int(successor) for successor in block.succs),
            *(int(predecessor) for predecessor in graph.predecessors(serial)),
        }
        if not neighbours <= closed_serials:
            return None
    return corridor


def plan_frontend_computed_branch_normalization(
    graph: FlowGraph,
    evidence: FrontendNormalizationEvidence,
) -> FragmentPlan | None:
    """Build one closed, atomic normalization plan or abstain without mutation."""
    if not isinstance(graph, FlowGraph):
        raise TypeError("frontend branch normalization requires a FlowGraph")
    if not isinstance(evidence, FrontendNormalizationEvidence):
        raise TypeError(
            "frontend branch normalization requires portable normalization evidence"
        )

    import_request = plan_detached_semantic_closure_import(graph, evidence)
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

    source_serials = tuple(int(binding.source.serial) for binding in live_bindings)
    source_serial_set = set(source_serials)
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
    proof_owned_native_entries = frozenset(imported_binding_by_entry)
    if import_request is not None:
        publication_native_entries = _publication_native_entry_eas(import_request)
        for entry_ea in import_request.semantic_closure.included_block_eas:
            if int(entry_ea) not in publication_native_entries:
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
                    if int(native_block.start_ea)
                    <= int(ea)
                    < int(native_block.end_ea)
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
                f"native[{_identity_token(identity)}]:imported"
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
    if projected_route_corridor_serials is None:
        raise FrontendNormalizationEvidenceRejected(
            "original route corridor is not closed"
        )
    relevant_serials.update(projected_route_corridor_serials)

    identities = _graph_identities(graph, evidence, relevant_serials)
    if identities is None:
        raise FrontendNormalizationEvidenceRejected(
            "normalization route corridor lacks unique stable identities"
        )
    base_ids = {
        serial: f"native[{_identity_token(identity)}]"
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
        semantic_anchor_ea = _semantic_anchor(identity)
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
        operations.append(
            FragmentOperation(
                operation_id=proof.proof_id,
                source_block_id=source_block_id,
                predicate_anchor_ea=proof.predicate_anchor_ea,
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
                        f"detached block 0x{entry_ea:X} has an unproved "
                        "indirect edge"
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
                    f"detached block 0x{entry_ea:X} has an unsupported "
                    "multi-edge shape"
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
        entry_block_ids = tuple(
            str(imported_id_for_anchor(entry_ea))
            for entry_ea in import_request.required_entry_eas
        )
        if any(block_id == "None" for block_id in entry_block_ids):
            raise FrontendNormalizationEvidenceRejected(
                "detached import entry is not owned by the planned native body"
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
        ),
        native_bodies=native_bodies,
        flag_corridors=tuple(flag_corridors),
    )


def _merged_native_ranges(
    plan: FragmentPlan,
    block_ids: set[str],
) -> tuple[NativeEaInterval, ...]:
    intervals = sorted(
        (
            interval
            for block_id in block_ids
            for interval in plan.block(block_id).stable_identity.native_ranges.intervals
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
    """Return the first stable publication-root component and its obligations."""
    if (
        plan.publication_purpose
        is not FragmentPublicationPurpose.FRONTEND_NORMALIZATION
    ):
        raise TypeError("frontend work-item selection requires a normalization plan")
    selected_root = min(
        plan.roots,
        key=lambda block_id: (
            int(plan.block(block_id).semantic_anchor_ea),
            str(block_id),
        ),
    )
    operation_by_source = {
        operation.source_block_id: operation for operation in plan.operations
    }
    selected_block_ids: set[str] = set()
    selected_operation_ids: set[str] = set()
    pending = [selected_root]
    while pending:
        block_id = pending.pop()
        if block_id in selected_block_ids:
            continue
        selected_block_ids.add(block_id)
        operation = operation_by_source.get(block_id)
        if operation is None:
            continue
        selected_operation_ids.add(operation.operation_id)
        pending.extend(edge.target_block_id for edge in operation.edges)

    selected_flag_corridors = tuple(
        corridor
        for corridor in plan.flag_corridors
        if corridor.consumer.block_id in selected_block_ids
    )
    dependency_block_ids = {
        block_id
        for corridor in selected_flag_corridors
        for block_id in (
            corridor.producer.block_id,
            corridor.consumer.block_id,
            *corridor.block_path,
        )
    }
    while dependency_block_ids - selected_block_ids:
        pending.extend(dependency_block_ids - selected_block_ids)
        while pending:
            block_id = pending.pop()
            if block_id in selected_block_ids:
                continue
            selected_block_ids.add(block_id)
            operation = operation_by_source.get(block_id)
            if operation is None:
                continue
            selected_operation_ids.add(operation.operation_id)
            pending.extend(edge.target_block_id for edge in operation.edges)
        selected_flag_corridors = tuple(
            corridor
            for corridor in plan.flag_corridors
            if corridor.consumer.block_id in selected_block_ids
        )
        dependency_block_ids = {
            block_id
            for corridor in selected_flag_corridors
            for block_id in (
                corridor.producer.block_id,
                corridor.consumer.block_id,
                *corridor.block_path,
            )
        }

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
        if any(
            operation.operation_id == proof_id for operation in plan.operations
        )
    )
    selected_proof_ids = tuple(
        proof_id
        for proof_id in pending_proof_ids
        if proof_id in selected_operation_ids
    )
    if not selected_proof_ids:
        raise FrontendNormalizationEvidenceRejected(
            "selected normalization root owns no portable proof obligation"
        )
    remaining_proof_ids = tuple(
        proof_id
        for proof_id in pending_proof_ids
        if proof_id not in selected_proof_ids
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
        if not imported_entry_ids:
            imported_entry_ids = set(native_body.entry_block_ids) & (
                selected_imported_ids
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
        ),
        native_bodies=selected_native_bodies,
        flag_corridors=selected_flag_corridors,
    )


def plan_next_frontend_normalization_work_item(
    graph: FlowGraph,
    evidence: FrontendNormalizationEvidence,
) -> FragmentPlan | None:
    """Plan one connected normalization publication without claiming its siblings."""
    complete_plan = plan_frontend_computed_branch_normalization(graph, evidence)
    if complete_plan is None:
        return None
    return _select_frontend_root_component(complete_plan, evidence)


__all__ = [
    "plan_frontend_computed_branch_normalization",
    "plan_next_frontend_normalization_work_item",
]
