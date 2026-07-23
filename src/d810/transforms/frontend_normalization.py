"""Plan complete frontend-normalization fragments from portable native proofs."""

from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.frontend_normalization import (
    DetachedSemanticClosureImportRequest,
    FrontendNormalizationEvidence,
    NativeIndirectTransferProof,
    NativeTransferEndpoint,
    NativeTransferShape,
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
) -> BlockSnapshot | None:
    anchor_ea = (
        _semantic_anchor(identity)
        if preferred_anchor_ea is None
        else int(preferred_anchor_ea)
    )
    return unique_block_for_native_anchor(graph, identity, anchor_ea)


def _bind_proof(
    graph: FlowGraph,
    proof: NativeIndirectTransferProof,
) -> _BoundTransferProof | None:
    source = unique_block_for_native_anchor(
        graph,
        proof.source_identity,
        proof.source_anchor_ea,
    )
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
        return (
            binding.source.kind is BlockKind.ONE_WAY
            and binding.source.succs == (int(target.serial),)
        )

    if any(target is None for _endpoint, target in binding.endpoints):
        return False
    target_by_role = {
        endpoint.role: block for endpoint, block in binding.endpoints
    }
    taken = target_by_role[SemanticEdgeRole.CONDITIONAL_TAKEN]
    fallthrough = target_by_role[SemanticEdgeRole.CONDITIONAL_FALLTHROUGH]
    tail = binding.source.tail
    explicit_target = (
        None
        if tail is None or tail.d is None
        else tail.d.block_ref
    )
    return bool(
        binding.source.kind is BlockKind.TWO_WAY
        and len(binding.source.succs) == 2
        and set(binding.source.succs)
        == {int(taken.serial), int(fallthrough.serial)}
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
) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (
            NativeEaInterval(
                int(native_block.start_ea),
                int(native_block.end_ea),
            ),
        ),
        native_key=evidence.native_key,
        exact_instruction_eas=(int(native_block.start_ea),),
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
    bindings: list[_BoundTransferProof] = []
    for proof in evidence.transfer_proofs:
        binding = _bind_proof(graph, proof)
        if binding is None:
            return None
        bindings.append(binding)
    if all(_proof_is_faithful(binding) for binding in bindings):
        return None

    source_serials = tuple(int(binding.source.serial) for binding in bindings)
    source_serial_set = set(source_serials)
    if (
        len(source_serial_set) != len(source_serials)
        or int(graph.entry_serial) in source_serials
        or any(not graph.predecessors(serial) for serial in source_serials)
    ):
        return None
    root_source_serials = tuple(
        serial
        for serial in source_serials
        if any(
            predecessor not in source_serial_set
            for predecessor in graph.predecessors(serial)
        )
    )
    if not root_source_serials:
        return None

    body_id = f"native-body:{evidence.atomic_group_id}"
    imported_native_blocks: dict[int, NativeBlock] = {}
    imported_identities: dict[int, StableBlockIdentity] = {}
    imported_ids: dict[int, str] = {}
    if import_request is not None:
        for entry_ea in import_request.semantic_closure.included_block_eas:
            native_block = import_request.native_cfg.blocks_by_ea[int(entry_ea)]
            identity = _native_block_identity(native_block, evidence)
            if (
                unique_block_for_native_anchor(
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
            return None

    def imported_id_for_anchor(anchor_ea: int) -> str | None:
        if import_request is None:
            return None
        native_block = _request_native_block(import_request, int(anchor_ea))
        if native_block is None:
            return None
        return imported_ids.get(int(native_block.start_ea))

    for binding in bindings:
        for endpoint, target in binding.endpoints:
            if target is None and imported_id_for_anchor(endpoint.anchor_ea) is None:
                return None

    relevant_serials = set(source_serials)
    for binding in bindings:
        relevant_serials.update(
            int(target.serial)
            for _endpoint, target in binding.endpoints
            if target is not None
        )
        relevant_serials.update(int(block.serial) for block in binding.corridor)
    for root_serial in root_source_serials:
        relevant_serials.update(graph.predecessors(root_serial))
    for native_block in imported_native_blocks.values():
        for edge in native_block.outgoing_edges:
            if edge.kind is NativeEdgeKind.CALL or edge.target_ea is None:
                continue
            live_target = _live_block_at_native_ea(graph, int(edge.target_ea))
            if live_target is not None:
                relevant_serials.add(int(live_target.serial))

    identities = _graph_identities(graph, evidence, relevant_serials)
    if identities is None:
        return None
    base_ids = {
        serial: f"native[{_identity_token(identity)}]"
        for serial, identity in identities.items()
    }
    original_ids = {
        serial: f"{base_ids[serial]}:original" for serial in source_serials
    }
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
                        materialization=(
                            FragmentBlockMaterialization.REUSE_PUBLISHED
                        ),
                        semantic_anchor_ea=semantic_anchor_ea,
                        stable_identity=identity,
                    ),
                    FragmentBlock(
                        block_id=replacement_ids[serial],
                        role=FragmentBlockRole.REPLACEMENT,
                        materialization=(
                            FragmentBlockMaterialization.CLONE_PUBLISHED
                        ),
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
    for binding in bindings:
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

    native_bodies: tuple[FragmentNativeBody, ...] = ()
    if import_request is not None:
        terminal_block_ids: list[str] = []

        def target_block_id(target_ea: int) -> str | None:
            imported_target_id = imported_id_for_anchor(int(target_ea))
            if imported_target_id is not None:
                return imported_target_id
            live_target = _live_block_at_native_ea(graph, int(target_ea))
            return (
                None
                if live_target is None
                else published_id(int(live_target.serial))
            )

        for entry_ea, native_block in sorted(imported_native_blocks.items()):
            source_block_id = imported_ids[entry_ea]
            control_edges = tuple(
                edge
                for edge in native_block.outgoing_edges
                if edge.kind is not NativeEdgeKind.CALL
            )
            if not control_edges:
                if native_block.terminal is NativeTerminalKind.NONE:
                    return None
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
                    return None
                if (
                    edge.kind is NativeEdgeKind.INDIRECT
                    and not edge.resolver_proven
                ):
                    return None
                target_id = target_block_id(int(edge.target_ea))
                if target_id is None:
                    return None
                operations.append(
                    FragmentOperation(
                        operation_id=operation_id,
                        source_block_id=source_block_id,
                        edges=(
                            FragmentEdge(
                                role=(
                                    SemanticEdgeRole.CALL_FALLTHROUGH
                                    if edge.kind
                                    is NativeEdgeKind.CALL_FALLTHROUGH
                                    else SemanticEdgeRole.DIRECT
                                ),
                                target_block_id=target_id,
                            ),
                        ),
                    )
                )
                continue

            edge_by_kind = {edge.kind: edge for edge in control_edges}
            if (
                len(control_edges) != 2
                or set(edge_by_kind)
                != {
                    NativeEdgeKind.CONDITIONAL_TRUE,
                    NativeEdgeKind.CONDITIONAL_FALSE,
                }
            ):
                return None
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
                return None
            true_target_id = target_block_id(int(true_edge.target_ea))
            false_target_id = target_block_id(int(false_edge.target_ea))
            if (
                true_target_id is None
                or false_target_id is None
                or true_target_id == false_target_id
            ):
                return None
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
            return None
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

    roots = tuple(
        replacement_ids[serial] for serial in root_source_serials
    )
    owned_originals = tuple(
        original_ids[int(binding.source.serial)] for binding in bindings
    )
    return FragmentPlan(
        plan_id=(
            f"frontend-normalization:"
            f"0x{evidence.native_key.function_rva:X}:g{evidence.generation}"
        ),
        atomic_group_id=evidence.atomic_group_id,
        publication_purpose=FragmentPublicationPurpose.FRONTEND_NORMALIZATION,
        native_key=evidence.native_key,
        blocks=tuple(blocks),
        roots=roots,
        owned_originals=owned_originals,
        prohibited_dispatcher_blocks=(),
        operations=tuple(operations),
        native_bodies=native_bodies,
        flag_corridors=tuple(flag_corridors),
    )


__all__ = ["plan_frontend_computed_branch_normalization"]
