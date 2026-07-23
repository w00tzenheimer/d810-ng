"""Plan complete frontend-normalization fragments from portable native proofs."""

from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.frontend_normalization import (
    FrontendNormalizationEvidence,
    NativeIndirectTransferProof,
    NativeTransferEndpoint,
    NativeTransferShape,
    unique_block_for_native_anchor,
)
from d810.ir.block_identity import (
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
    FragmentOperation,
    FragmentPlan,
    FragmentPublicationPurpose,
    FragmentValueSite,
)


@dataclass(frozen=True, slots=True)
class _BoundTransferProof:
    proof: NativeIndirectTransferProof
    source: BlockSnapshot
    endpoints: tuple[tuple[NativeTransferEndpoint, BlockSnapshot], ...]
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
    endpoints: list[tuple[NativeTransferEndpoint, BlockSnapshot]] = []
    for endpoint in proof.endpoints:
        target = unique_block_for_native_anchor(
            graph,
            endpoint.identity,
            endpoint.anchor_ea,
        )
        if target is None:
            return None
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
        corridor.append(block)
    if len({block.serial for block in corridor}) != len(corridor):
        return None
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
        return (
            binding.source.kind is BlockKind.ONE_WAY
            and binding.source.succs == (int(target.serial),)
        )

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
) -> dict[int, StableBlockIdentity] | None:
    identities: dict[int, StableBlockIdentity] = {}
    for block in graph.blocks.values():
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

    bindings: list[_BoundTransferProof] = []
    for proof in evidence.transfer_proofs:
        binding = _bind_proof(graph, proof)
        if binding is None:
            return None
        bindings.append(binding)
    if all(_proof_is_faithful(binding) for binding in bindings):
        return None

    source_serials = tuple(int(binding.source.serial) for binding in bindings)
    if (
        len(set(source_serials)) != len(source_serials)
        or int(graph.entry_serial) in source_serials
        or any(not graph.predecessors(serial) for serial in source_serials)
    ):
        return None
    identities = _graph_identities(graph, evidence)
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
    for block in sorted(graph.blocks.values(), key=lambda item: int(item.serial)):
        serial = int(block.serial)
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
                        target_block_id=published_id(target.serial),
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

    roots = tuple(
        replacement_ids[int(binding.source.serial)] for binding in bindings
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
        flag_corridors=tuple(flag_corridors),
    )


__all__ = ["plan_frontend_computed_branch_normalization"]
