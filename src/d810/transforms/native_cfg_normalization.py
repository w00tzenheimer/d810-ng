"""Freeze pass-owned CFG changes and bind them to C-tree native ranges."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum

from d810.core.execution_journal import ExecutionEffectRef
from d810.ir.edge_state_contract import EdgeStateContract
from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.ir.maturity import IRMaturity
from d810.ir.native_range_projection import (
    CtreeNativeRangeProjection,
    NativeRange,
)

__all__ = [
    "FrozenNativeCfgTopology",
    "NativeCfgBlockRangeBinding",
    "NativeCfgEdgeIntent",
    "NativeCfgEdgeKind",
    "NativeCfgFreezeOutcome",
    "NativeCfgFreezeReason",
    "NativeCfgNormalizationIntent",
    "NativeCfgPassMutationObservation",
    "NativeCfgTopologyFreezeOutcome",
    "ObservedEdgeStateContract",
    "bind_ctree_native_ranges",
    "cfg_fingerprint",
    "freeze_native_cfg_topology",
]


class NativeCfgEdgeKind(str, Enum):
    REDIRECT = "redirect"
    FORCE_TAKEN = "force_taken"
    FORCE_FALLTHROUGH = "force_fallthrough"


class NativeCfgFreezeReason(str, Enum):
    NO_CHANGED_EDGES = "no_changed_edges"
    FUNCTION_MISMATCH = "function_mismatch"
    MATURITY_MISMATCH = "maturity_mismatch"
    ADDED_BLOCK = "added_block"
    REANCHORED_BLOCK = "reanchored_block"
    BODY_REWRITE_UNSUPPORTED = "body_rewrite_unsupported"
    MISSING_NATIVE_ANCHOR = "missing_native_anchor"
    DANGLING_FINAL_EDGE = "dangling_final_edge"
    OBSERVATION_CHAIN_MISMATCH = "observation_chain_mismatch"
    UNOWNED_EDGE_CHANGE = "unowned_edge_change"
    MULTI_STEP_EDGE_UNSUPPORTED = "multi_step_edge_unsupported"
    EDGE_STATE_CONTRACT_REQUIRED = "edge_state_contract_required"
    UNSUPPORTED_EDGE_SHAPE = "unsupported_edge_shape"
    MISSING_CTREE_NATIVE_RANGE = "missing_ctree_native_range"
    AMBIGUOUS_CTREE_NATIVE_RANGE = "ambiguous_ctree_native_range"
    MISSING_PIPELINE_FREEZE = "missing_pipeline_freeze"


@dataclass(frozen=True, slots=True)
class ObservedEdgeStateContract:
    source_block: int
    inherited_successors: tuple[int, ...]
    final_successors: tuple[int, ...]
    contract: EdgeStateContract

    def __post_init__(self) -> None:
        if not isinstance(self.source_block, int) or isinstance(
            self.source_block, bool
        ):
            raise TypeError("source_block must be an int")
        if not isinstance(self.inherited_successors, tuple) or not isinstance(
            self.final_successors, tuple
        ):
            raise TypeError("successor sets must be tuples")
        if not isinstance(self.contract, EdgeStateContract):
            raise TypeError("contract must be an EdgeStateContract")


@dataclass(frozen=True, slots=True)
class NativeCfgPassMutationObservation:
    pass_id: str
    maturity: IRMaturity
    pre_graph: FlowGraph
    post_graph: FlowGraph
    plan_fingerprint: str
    receipt_ref: ExecutionEffectRef
    edge_state_contracts: tuple[ObservedEdgeStateContract, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.pass_id, str) or not self.pass_id.strip():
            raise ValueError("pass_id must not be blank")
        if not isinstance(self.maturity, IRMaturity):
            raise TypeError("maturity must be an IRMaturity")
        if not isinstance(self.pre_graph, FlowGraph) or not isinstance(
            self.post_graph, FlowGraph
        ):
            raise TypeError("pre_graph and post_graph must be FlowGraph values")
        if not isinstance(self.plan_fingerprint, str) or not self.plan_fingerprint:
            raise ValueError("plan_fingerprint must not be blank")
        if not isinstance(self.receipt_ref, ExecutionEffectRef):
            raise TypeError("receipt_ref must be an ExecutionEffectRef")
        if not isinstance(self.edge_state_contracts, tuple) or not all(
            isinstance(item, ObservedEdgeStateContract)
            for item in self.edge_state_contracts
        ):
            raise TypeError(
                "edge_state_contracts must contain ObservedEdgeStateContract values"
            )


@dataclass(frozen=True, slots=True)
class NativeCfgEdgeIntent:
    source_block: int
    source_native_ea: int
    inherited_successors: tuple[int, ...]
    final_successors: tuple[int, ...]
    target_native_eas: tuple[int, ...]
    kind: NativeCfgEdgeKind
    owner_pass_ids: tuple[str, ...]
    receipt_refs: tuple[ExecutionEffectRef, ...]
    state_contract: EdgeStateContract


@dataclass(frozen=True, slots=True)
class FrozenNativeCfgTopology:
    function_ea: int
    maturity: IRMaturity
    baseline_graph: FlowGraph
    final_graph: FlowGraph
    baseline_cfg_fingerprint: str
    target_cfg_fingerprint: str
    edge_intents: tuple[NativeCfgEdgeIntent, ...]
    topology_hash: str


@dataclass(frozen=True, slots=True)
class NativeCfgBlockRangeBinding:
    block_serial: int
    microcode_native_ea: int
    ctree_statement_indices: tuple[int, ...]
    native_ranges: tuple[NativeRange, ...]


@dataclass(frozen=True, slots=True)
class NativeCfgNormalizationIntent:
    function_ea: int
    maturity: IRMaturity
    baseline_cfg_fingerprint: str
    target_cfg_fingerprint: str
    target_ctree_range_fingerprint: str
    block_range_bindings: tuple[NativeCfgBlockRangeBinding, ...]
    edge_intents: tuple[NativeCfgEdgeIntent, ...]
    intent_hash: str


@dataclass(frozen=True, slots=True)
class NativeCfgTopologyFreezeOutcome:
    topology: FrozenNativeCfgTopology | None = None
    reason: NativeCfgFreezeReason | None = None

    def __post_init__(self) -> None:
        if (self.topology is None) == (self.reason is None):
            raise ValueError("outcome must contain exactly one of topology or reason")


@dataclass(frozen=True, slots=True)
class NativeCfgFreezeOutcome:
    intent: NativeCfgNormalizationIntent | None = None
    reason: NativeCfgFreezeReason | None = None

    def __post_init__(self) -> None:
        if (self.intent is None) == (self.reason is None):
            raise ValueError("outcome must contain exactly one of intent or reason")


def _hash(value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _block_projection(block: BlockSnapshot) -> tuple[object, ...]:
    tail = block.tail
    return (
        block.serial,
        block.native_start_ea,
        tuple(block.succs),
        block.tail_kind.value if block.tail_kind is not None else None,
        tail.native_ea if tail is not None else None,
        tuple(
            (
                insn.kind.value,
                insn.native_ea,
                insn.raw_opcode,
            )
            for insn in block.insn_snapshots[:-1]
        ),
    )


def cfg_fingerprint(graph: FlowGraph) -> str:
    return _hash(
        (
            graph.func_ea,
            graph.entry_serial,
            tuple(
                _block_projection(block)
                for block in sorted(graph.blocks.values(), key=lambda item: item.serial)
            ),
        )
    )


def _edge_kind(
    inherited: tuple[int, ...],
    final: tuple[int, ...],
) -> NativeCfgEdgeKind | None:
    if len(inherited) == 1 and len(final) == 1 and inherited != final:
        return NativeCfgEdgeKind.REDIRECT
    if len(inherited) == 2 and len(final) == 1:
        if final[0] == inherited[0]:
            return NativeCfgEdgeKind.FORCE_TAKEN
        if final[0] == inherited[1]:
            return NativeCfgEdgeKind.FORCE_FALLTHROUGH
    if len(inherited) == 2 and len(final) == 2 and inherited != final:
        return NativeCfgEdgeKind.REDIRECT
    return None


def _order_observations(
    baseline_fingerprint: str,
    target_fingerprint: str,
    observations: tuple[NativeCfgPassMutationObservation, ...],
) -> tuple[NativeCfgPassMutationObservation, ...] | None:
    remaining = list(observations)
    ordered: list[NativeCfgPassMutationObservation] = []
    current = baseline_fingerprint
    seen = {current}
    while current != target_fingerprint:
        matches = [
            item for item in remaining if cfg_fingerprint(item.pre_graph) == current
        ]
        if len(matches) != 1:
            return None
        item = matches[0]
        remaining.remove(item)
        next_fingerprint = cfg_fingerprint(item.post_graph)
        if next_fingerprint in seen or next_fingerprint == current:
            return None
        seen.add(next_fingerprint)
        ordered.append(item)
        current = next_fingerprint
    if remaining:
        return None
    return tuple(ordered)


def _failure(reason: NativeCfgFreezeReason) -> NativeCfgTopologyFreezeOutcome:
    return NativeCfgTopologyFreezeOutcome(reason=reason)


def freeze_native_cfg_topology(
    *,
    function_ea: int,
    maturity: IRMaturity,
    baseline_graph: FlowGraph,
    final_graph: FlowGraph,
    observations: tuple[NativeCfgPassMutationObservation, ...],
) -> NativeCfgTopologyFreezeOutcome:
    if baseline_graph.func_ea != function_ea or final_graph.func_ea != function_ea:
        return _failure(NativeCfgFreezeReason.FUNCTION_MISMATCH)
    if not isinstance(maturity, IRMaturity):
        return _failure(NativeCfgFreezeReason.MATURITY_MISMATCH)

    baseline_ids = set(baseline_graph.blocks)
    final_ids = set(final_graph.blocks)
    if final_ids.difference(baseline_ids):
        return _failure(NativeCfgFreezeReason.ADDED_BLOCK)
    for serial in final_ids:
        baseline_block = baseline_graph.blocks[serial]
        final_block = final_graph.blocks[serial]
        if (
            baseline_block.native_start_ea is None
            or final_block.native_start_ea is None
            or baseline_block.tail is None
            or baseline_block.tail.native_ea is None
        ):
            return _failure(NativeCfgFreezeReason.MISSING_NATIVE_ANCHOR)
        if baseline_block.native_start_ea != final_block.native_start_ea:
            return _failure(NativeCfgFreezeReason.REANCHORED_BLOCK)
        if baseline_block.insn_snapshots[:-1] != final_block.insn_snapshots[:-1]:
            return _failure(NativeCfgFreezeReason.BODY_REWRITE_UNSUPPORTED)
        if any(target not in final_ids for target in final_block.succs):
            return _failure(NativeCfgFreezeReason.DANGLING_FINAL_EDGE)

    changed_sources = tuple(
        serial
        for serial in sorted(baseline_ids & final_ids)
        if baseline_graph.blocks[serial].succs != final_graph.blocks[serial].succs
    )
    if not changed_sources:
        return _failure(NativeCfgFreezeReason.NO_CHANGED_EDGES)

    baseline_fingerprint = cfg_fingerprint(baseline_graph)
    target_fingerprint = cfg_fingerprint(final_graph)
    ordered = _order_observations(
        baseline_fingerprint,
        target_fingerprint,
        observations,
    )
    if ordered is None:
        return _failure(NativeCfgFreezeReason.OBSERVATION_CHAIN_MISMATCH)
    if any(
        item.maturity is not maturity
        or item.pre_graph.func_ea != function_ea
        or item.post_graph.func_ea != function_ea
        for item in ordered
    ):
        return _failure(NativeCfgFreezeReason.MATURITY_MISMATCH)

    edge_intents: list[NativeCfgEdgeIntent] = []
    for source in changed_sources:
        owners: list[
            tuple[NativeCfgPassMutationObservation, ObservedEdgeStateContract]
        ] = []
        for observation in ordered:
            before = observation.pre_graph.blocks.get(source)
            after = observation.post_graph.blocks.get(source)
            if before is None or after is None or before.succs == after.succs:
                continue
            contracts = [
                item
                for item in observation.edge_state_contracts
                if item.source_block == source
                and item.inherited_successors == before.succs
                and item.final_successors == after.succs
            ]
            if len(contracts) != 1:
                return _failure(NativeCfgFreezeReason.EDGE_STATE_CONTRACT_REQUIRED)
            owners.append((observation, contracts[0]))
        if not owners:
            return _failure(NativeCfgFreezeReason.UNOWNED_EDGE_CHANGE)
        if len(owners) != 1:
            return _failure(NativeCfgFreezeReason.MULTI_STEP_EDGE_UNSUPPORTED)
        observation, state_evidence = owners[0]
        if not state_evidence.contract.permits_control_only_relink:
            return _failure(NativeCfgFreezeReason.EDGE_STATE_CONTRACT_REQUIRED)

        baseline_block = baseline_graph.blocks[source]
        final_block = final_graph.blocks[source]
        kind = _edge_kind(baseline_block.succs, final_block.succs)
        if kind is None:
            return _failure(NativeCfgFreezeReason.UNSUPPORTED_EDGE_SHAPE)
        target_native_eas: list[int] = []
        for target in final_block.succs:
            target_ea = final_graph.blocks[target].native_start_ea
            if target_ea is None:
                return _failure(NativeCfgFreezeReason.MISSING_NATIVE_ANCHOR)
            target_native_eas.append(target_ea)
        source_ea = baseline_block.tail.native_ea
        if source_ea is None:
            return _failure(NativeCfgFreezeReason.MISSING_NATIVE_ANCHOR)
        edge_intents.append(
            NativeCfgEdgeIntent(
                source_block=source,
                source_native_ea=source_ea,
                inherited_successors=baseline_block.succs,
                final_successors=final_block.succs,
                target_native_eas=tuple(target_native_eas),
                kind=kind,
                owner_pass_ids=(observation.pass_id,),
                receipt_refs=(observation.receipt_ref,),
                state_contract=state_evidence.contract,
            )
        )

    topology_content = (
        function_ea,
        maturity.value,
        baseline_fingerprint,
        target_fingerprint,
        tuple(
            (
                item.source_block,
                item.source_native_ea,
                item.inherited_successors,
                item.final_successors,
                item.target_native_eas,
                item.kind.value,
                item.owner_pass_ids,
                tuple((ref.kind, ref.ref_id) for ref in item.receipt_refs),
                item.state_contract.proof_ids,
            )
            for item in edge_intents
        ),
    )
    return NativeCfgTopologyFreezeOutcome(
        topology=FrozenNativeCfgTopology(
            function_ea=function_ea,
            maturity=maturity,
            baseline_graph=baseline_graph,
            final_graph=final_graph,
            baseline_cfg_fingerprint=baseline_fingerprint,
            target_cfg_fingerprint=target_fingerprint,
            edge_intents=tuple(edge_intents),
            topology_hash=_hash(topology_content),
        )
    )


def bind_ctree_native_ranges(
    *,
    frozen: FrozenNativeCfgTopology,
    target_projection: CtreeNativeRangeProjection,
) -> NativeCfgFreezeOutcome:
    if target_projection.function_ea != frozen.function_ea:
        return NativeCfgFreezeOutcome(reason=NativeCfgFreezeReason.FUNCTION_MISMATCH)
    statement_by_index = {
        item.citem_index: item for item in target_projection.statements
    }
    reverse = dict(target_projection.ea_to_statement_indices)
    bindings: list[NativeCfgBlockRangeBinding] = []
    for serial, block in sorted(frozen.final_graph.blocks.items()):
        anchor = block.native_start_ea
        if anchor is None:
            return NativeCfgFreezeOutcome(
                reason=NativeCfgFreezeReason.MISSING_NATIVE_ANCHOR
            )
        indices = reverse.get(anchor, ())
        matching = tuple(
            statement_by_index[index]
            for index in indices
            if index in statement_by_index
            and any(span.contains(anchor) for span in statement_by_index[index].ranges)
        )
        if not matching:
            return NativeCfgFreezeOutcome(
                reason=NativeCfgFreezeReason.MISSING_CTREE_NATIVE_RANGE
            )
        range_sets = {item.ranges for item in matching}
        if len(range_sets) != 1:
            return NativeCfgFreezeOutcome(
                reason=NativeCfgFreezeReason.AMBIGUOUS_CTREE_NATIVE_RANGE
            )
        bindings.append(
            NativeCfgBlockRangeBinding(
                block_serial=serial,
                microcode_native_ea=anchor,
                ctree_statement_indices=tuple(
                    sorted(item.citem_index for item in matching)
                ),
                native_ranges=matching[0].ranges,
            )
        )

    binding_projection = tuple(
        (
            item.block_serial,
            item.microcode_native_ea,
            item.ctree_statement_indices,
            tuple((span.start_ea, span.end_ea) for span in item.native_ranges),
        )
        for item in bindings
    )
    intent_hash = _hash(
        (
            frozen.topology_hash,
            target_projection.fingerprint,
            binding_projection,
        )
    )
    return NativeCfgFreezeOutcome(
        intent=NativeCfgNormalizationIntent(
            function_ea=frozen.function_ea,
            maturity=frozen.maturity,
            baseline_cfg_fingerprint=frozen.baseline_cfg_fingerprint,
            target_cfg_fingerprint=frozen.target_cfg_fingerprint,
            target_ctree_range_fingerprint=target_projection.fingerprint,
            block_range_bindings=tuple(bindings),
            edge_intents=frozen.edge_intents,
            intent_hash=intent_hash,
        )
    )
