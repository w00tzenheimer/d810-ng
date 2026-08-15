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
    CtreeStatementNativeRanges,
    NativeRange,
)

__all__ = [
    "FrozenNativeCfgTopology",
    "NativeCfgBlockRangeBinding",
    "NativeCfgEdgeIntent",
    "NativeCfgEdgeKind",
    "NativeCfgFreezeOutcome",
    "NativeCfgFreezeReason",
    "NativeCfgPostcondition",
    "NativeCfgProjection",
    "NativeCfgNormalizationIntent",
    "NativeCfgPassMutationObservation",
    "NativeCfgTopologyFreezeOutcome",
    "NativeFlowchartBlock",
    "ObservedEdgeStateContract",
    "bind_ctree_native_ranges",
    "cfg_fingerprint",
    "freeze_native_cfg_topology",
    "project_target_native_cfg",
    "validate_live_native_cfg",
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
    inherited_target_native_eas: tuple[int, ...]
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
    detail: str | None = None

    def __post_init__(self) -> None:
        if (self.topology is None) == (self.reason is None):
            raise ValueError("outcome must contain exactly one of topology or reason")


@dataclass(frozen=True, slots=True)
class NativeCfgFreezeOutcome:
    intent: NativeCfgNormalizationIntent | None = None
    reason: NativeCfgFreezeReason | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        if (self.intent is None) == (self.reason is None):
            raise ValueError("outcome must contain exactly one of intent or reason")


@dataclass(frozen=True, slots=True)
class NativeFlowchartBlock:
    """One live IDA basic block, expressed without backend-owned objects."""

    start_ea: int
    end_ea: int
    successor_eas: tuple[int, ...]

    def __post_init__(self) -> None:
        if int(self.end_ea) <= int(self.start_ea):
            raise ValueError("native flowchart block range must be non-empty")
        object.__setattr__(self, "start_ea", int(self.start_ea))
        object.__setattr__(self, "end_ea", int(self.end_ea))
        object.__setattr__(
            self,
            "successor_eas",
            tuple(dict.fromkeys(int(ea) for ea in self.successor_eas)),
        )


@dataclass(frozen=True, slots=True)
class NativeCfgProjection:
    """CFG quotient keyed by stable native anchors instead of block serials."""

    entry_ea: int
    successor_eas_by_anchor: tuple[tuple[int, tuple[int, ...]], ...]

    @property
    def fingerprint(self) -> str:
        return _hash((self.entry_ea, self.successor_eas_by_anchor))


@dataclass(frozen=True, slots=True)
class NativeCfgPostcondition:
    expected: NativeCfgProjection
    observed: NativeCfgProjection
    live_flowchart_fingerprint: str
    matches: bool
    reason: str | None = None


def _hash(value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _block_projection(block: BlockSnapshot) -> tuple[object, ...]:
    tail = block.tail
    return (
        block.serial,
        _block_native_anchor(block),
        tuple(block.succs),
        block.tail_kind.value if block.tail_kind is not None else None,
        tail.native_ea if tail is not None else None,
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


def _reachable_serials(graph: FlowGraph) -> tuple[int, ...]:
    pending = [int(graph.entry_serial)]
    visited: set[int] = set()
    while pending:
        serial = pending.pop()
        if serial in visited:
            continue
        block = graph.blocks.get(serial)
        if block is None:
            raise ValueError(f"missing reachable microcode block {serial}")
        visited.add(serial)
        pending.extend(int(target) for target in block.succs)
    return tuple(sorted(visited))


def project_target_native_cfg(graph: FlowGraph) -> NativeCfgProjection:
    """Project the target microcode graph onto its stable native-EA anchors."""

    reachable = _reachable_serials(graph)
    anchors: dict[int, int] = {}
    for serial in reachable:
        block = graph.blocks[serial]
        if _is_addressless_stop_sentinel(block):
            continue
        anchor = _block_native_anchor(block)
        if anchor is None:
            raise ValueError(f"reachable block {serial} has no native anchor")
        anchors[serial] = anchor
    if graph.entry_serial not in anchors:
        raise ValueError("target microcode entry has no native anchor")
    successors_by_anchor: dict[int, set[int]] = {
        anchor: set() for anchor in anchors.values()
    }
    for serial, source_anchor in anchors.items():
        for target_serial in graph.blocks[serial].succs:
            target = graph.blocks[int(target_serial)]
            if _is_addressless_stop_sentinel(target):
                continue
            target_anchor = anchors.get(int(target_serial))
            if target_anchor is None:
                raise ValueError(
                    f"reachable target block {target_serial} has no native anchor"
                )
            # Hex-Rays may split several microblocks at the same native EA.
            # They are one native anchor, so their internal edge collapses.
            if target_anchor != source_anchor:
                successors_by_anchor[source_anchor].add(target_anchor)
    rows = tuple(
        (anchor, tuple(sorted(targets)))
        for anchor, targets in sorted(successors_by_anchor.items())
    )
    return NativeCfgProjection(
        entry_ea=anchors[int(graph.entry_serial)],
        successor_eas_by_anchor=rows,
    )


def _live_flowchart_fingerprint(blocks: tuple[NativeFlowchartBlock, ...]) -> str:
    return _hash(
        tuple(
            (
                block.start_ea,
                block.end_ea,
                tuple(sorted(block.successor_eas)),
            )
            for block in sorted(blocks, key=lambda item: item.start_ea)
        )
    )


def _observe_anchor_quotient(
    expected: NativeCfgProjection,
    blocks: tuple[NativeFlowchartBlock, ...],
) -> NativeCfgProjection:
    blocks_by_start = {block.start_ea: block for block in blocks}
    if len(blocks_by_start) != len(blocks):
        raise ValueError("live flowchart contains duplicate block starts")
    for block in blocks:
        missing = set(block.successor_eas).difference(blocks_by_start)
        if missing:
            formatted = ",".join(f"0x{ea:X}" for ea in sorted(missing))
            raise ValueError(f"live flowchart has foreign successors: {formatted}")

    expected_anchors = tuple(
        anchor for anchor, _targets in expected.successor_eas_by_anchor
    )
    block_start_by_anchor: dict[int, int] = {}
    anchors_by_block_start: dict[int, list[int]] = {
        block.start_ea: [] for block in blocks
    }
    for anchor in expected_anchors:
        containing = [
            block for block in blocks if block.start_ea <= anchor < block.end_ea
        ]
        if len(containing) != 1:
            raise ValueError(
                f"native anchor 0x{anchor:X} belongs to {len(containing)} live blocks"
            )
        owner = containing[0]
        block_start_by_anchor[anchor] = owner.start_ea
        anchors_by_block_start[owner.start_ea].append(anchor)
    for anchors in anchors_by_block_start.values():
        anchors.sort()

    def first_downstream_anchors(start_ea: int) -> tuple[set[int], bool]:
        def walk(current: int, path: frozenset[int]) -> tuple[set[int], bool]:
            if current in path:
                return set(), True
            block_anchors = anchors_by_block_start[current]
            if block_anchors:
                return {block_anchors[0]}, False
            successors = blocks_by_start[current].successor_eas
            if not successors:
                return set(), True
            found: set[int] = set()
            unresolved_path = False
            next_path = path | {current}
            for successor in successors:
                downstream, unresolved = walk(successor, next_path)
                found.update(downstream)
                unresolved_path = unresolved_path or unresolved
            return found, unresolved_path

        return walk(int(start_ea), frozenset())

    rows = []
    expected_targets_by_anchor = dict(expected.successor_eas_by_anchor)
    for anchor in expected_anchors:
        block_start = block_start_by_anchor[anchor]
        block_anchors = anchors_by_block_start[block_start]
        position = block_anchors.index(anchor)
        if position + 1 < len(block_anchors):
            targets = {block_anchors[position + 1]}
        else:
            targets: set[int] = set()
            for successor in blocks_by_start[block_start].successor_eas:
                downstream, unresolved = first_downstream_anchors(successor)
                if unresolved and expected_targets_by_anchor[anchor]:
                    raise ValueError(
                        f"live path from anchor 0x{anchor:X} reaches no target anchor"
                    )
                targets.update(downstream)
        rows.append((anchor, tuple(sorted(targets))))
    return NativeCfgProjection(
        entry_ea=expected.entry_ea,
        successor_eas_by_anchor=tuple(sorted(rows)),
    )


def validate_live_native_cfg(
    target_graph: FlowGraph,
    live_blocks: tuple[NativeFlowchartBlock, ...],
) -> NativeCfgPostcondition:
    """Compare the complete live flowchart with the target anchor quotient.

    Multiple target microblocks may be represented by one linearized native
    block after a conditional terminator becomes NOPs.  Anchors inside that
    block are therefore linked in address order before physical block edges
    are followed.  This mirrors Hex-Rays' EA synchronization without assuming
    that its snapshot-local block serials survive native reanalysis.
    """

    expected = project_target_native_cfg(target_graph)
    physical_fingerprint = _live_flowchart_fingerprint(live_blocks)
    try:
        observed = _observe_anchor_quotient(expected, live_blocks)
    except ValueError as error:
        observed = NativeCfgProjection(expected.entry_ea, ())
        return NativeCfgPostcondition(
            expected=expected,
            observed=observed,
            live_flowchart_fingerprint=physical_fingerprint,
            matches=False,
            reason=str(error),
        )
    return NativeCfgPostcondition(
        expected=expected,
        observed=observed,
        live_flowchart_fingerprint=physical_fingerprint,
        matches=observed == expected,
        reason=None if observed == expected else "native anchor CFG mismatch",
    )


def _edge_kind(
    inherited: tuple[int, ...],
    final: tuple[int, ...],
) -> NativeCfgEdgeKind | None:
    if len(inherited) == 1 and len(final) == 1 and inherited != final:
        return NativeCfgEdgeKind.REDIRECT
    if len(inherited) == 2 and len(final) == 1:
        if final[0] == inherited[0]:
            return NativeCfgEdgeKind.FORCE_FALLTHROUGH
        if final[0] == inherited[1]:
            return NativeCfgEdgeKind.FORCE_TAKEN
    if len(inherited) == 2 and len(final) == 2 and inherited != final:
        return NativeCfgEdgeKind.REDIRECT
    return None


def _is_addressless_stop_sentinel(block: BlockSnapshot) -> bool:
    """Whether ``block`` is Hex-Rays' non-native terminal sentinel."""
    return bool(
        not block.succs and not block.insn_snapshots and block.native_start_ea is None
    )


def _block_native_candidates(block: BlockSnapshot) -> tuple[int, ...]:
    """Return stable native origins represented by a microcode block."""
    candidates: list[int] = []
    if block.native_start_ea is not None:
        candidates.append(int(block.native_start_ea))
    for instruction in block.insn_snapshots:
        if (
            instruction.native_ea is not None
            and int(instruction.native_ea) not in candidates
        ):
            candidates.append(int(instruction.native_ea))
    return tuple(candidates)


def _block_native_anchor(block: BlockSnapshot) -> int | None:
    """Resolve the first native origin represented by a microcode block."""
    candidates = _block_native_candidates(block)
    return candidates[0] if candidates else None


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


def _failure(
    reason: NativeCfgFreezeReason,
    detail: str | None = None,
) -> NativeCfgTopologyFreezeOutcome:
    return NativeCfgTopologyFreezeOutcome(reason=reason, detail=detail)


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
        if _is_addressless_stop_sentinel(baseline_block) and (
            _is_addressless_stop_sentinel(final_block)
        ):
            continue
        baseline_anchor = _block_native_anchor(baseline_block)
        final_anchor = _block_native_anchor(final_block)
        if baseline_anchor is None or final_anchor is None:
            return _failure(
                NativeCfgFreezeReason.MISSING_NATIVE_ANCHOR,
                "block="
                f"{serial} baseline_anchor={baseline_anchor} "
                f"final_anchor={final_anchor}",
            )
        if baseline_anchor != final_anchor:
            return _failure(NativeCfgFreezeReason.REANCHORED_BLOCK)
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
        observation_edges = tuple(
            (
                item.pass_id,
                cfg_fingerprint(item.pre_graph)[:12],
                cfg_fingerprint(item.post_graph)[:12],
            )
            for item in observations
        )
        return _failure(
            NativeCfgFreezeReason.OBSERVATION_CHAIN_MISMATCH,
            f"baseline={baseline_fingerprint[:12]} "
            f"target={target_fingerprint[:12]} observations={observation_edges}",
        )
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
        inherited_target_native_eas: list[int] = []
        for target in baseline_block.succs:
            target_ea = _block_native_anchor(baseline_graph.blocks[target])
            if target_ea is None:
                return _failure(
                    NativeCfgFreezeReason.MISSING_NATIVE_ANCHOR,
                    f"source={source} inherited_target={target}",
                )
            inherited_target_native_eas.append(target_ea)
        target_native_eas: list[int] = []
        for target in final_block.succs:
            target_ea = _block_native_anchor(final_graph.blocks[target])
            if target_ea is None:
                return _failure(
                    NativeCfgFreezeReason.MISSING_NATIVE_ANCHOR,
                    f"source={source} final_target={target}",
                )
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
                inherited_target_native_eas=tuple(inherited_target_native_eas),
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
                item.inherited_target_native_eas,
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
    if not target_projection.statements:
        return NativeCfgFreezeOutcome(
            reason=NativeCfgFreezeReason.MISSING_CTREE_NATIVE_RANGE,
            detail="target C-tree projection contains no statements",
        )
    statement_by_index = {
        item.citem_index: item for item in target_projection.statements
    }
    reverse = dict(target_projection.ea_to_statement_indices)
    source_native_eas = {
        edge.source_block: edge.source_native_ea for edge in frozen.edge_intents
    }
    bindings: list[NativeCfgBlockRangeBinding] = []
    for serial, block in sorted(frozen.final_graph.blocks.items()):
        if _is_addressless_stop_sentinel(block):
            continue
        anchors = _block_native_candidates(block)
        source_native_ea = source_native_eas.get(serial)
        if source_native_ea is not None:
            anchors = (
                source_native_ea,
                *(anchor for anchor in anchors if anchor != source_native_ea),
            )
        if not anchors:
            continue
        selected: (
            tuple[
                int,
                tuple[CtreeStatementNativeRanges, ...],
            ]
            | None
        ) = None
        for anchor in anchors:
            indices = set(reverse.get(anchor, ()))
            indices.update(
                item.citem_index
                for item in target_projection.statements
                if any(span.contains(anchor) for span in item.ranges)
            )
            matching = tuple(
                statement_by_index[index]
                for index in sorted(indices)
                if index in statement_by_index
                and any(
                    span.contains(anchor) for span in statement_by_index[index].ranges
                )
            )
            if not matching:
                continue
            range_sets = {item.ranges for item in matching}
            if len(range_sets) != 1:
                if serial not in source_native_eas:
                    selected = None
                    break
                return NativeCfgFreezeOutcome(
                    reason=NativeCfgFreezeReason.AMBIGUOUS_CTREE_NATIVE_RANGE,
                    detail=f"block={serial} anchor=0x{anchor:X}",
                )
            selected = (anchor, matching)
            break
        if selected is None:
            continue
        anchor, matching = selected
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
            # The native plan and certificate use the stable EA-anchor
            # quotient, not Hex-Rays block serials.  The latter are meaningful
            # only inside this one microcode snapshot and cannot be recaptured
            # from IDA's post-reanalysis flowchart.
            target_cfg_fingerprint=project_target_native_cfg(
                frozen.final_graph
            ).fingerprint,
            target_ctree_range_fingerprint=target_projection.fingerprint,
            block_range_bindings=tuple(bindings),
            edge_intents=frozen.edge_intents,
            intent_hash=intent_hash,
        )
    )
