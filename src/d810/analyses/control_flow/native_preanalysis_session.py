"""Portable evidence owned by one top-level decompilation session.

This module intentionally contains no live MBA, Hex-Rays, manager, or
optimizer dependency.  The lifecycle coordinator owns one instance directly;
live adapters may attach a current-generation index separately, but may not
become the authority for evidence generation or restart decisions.
"""

from __future__ import annotations

from dataclasses import MISSING, dataclass, field, fields, replace
from enum import Enum

from d810.analyses.control_flow.call_abi import StackCallAbiProof
from d810.analyses.control_flow.detached_handler_island import (
    DetachedSnippetBoundaryPorts,
    normalize_detached_snippet_boundary_ports,
)
from d810.analyses.control_flow.frontend_normalization import (
    FrontendNormalizationEvidence,
    FrontendNormalizationEvidenceRejected,
    NativeIndirectTransferProof,
    NativeTransferEndpoint,
    NativeTransferShape,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    PortableMaterializedStateRoute,
    PortableStateWriteRouteEvidence,
    TerminalReturnCarrierRequest,
    condition_code_predicate,
    is_conditional_handler_bridge_kind,
)
from d810.analyses.control_flow.native_semantic_closure import (
    NativeBlock,
    NativeCfg,
    NativeEdgeKind,
    NativeSemanticClosure,
)
from d810.analyses.control_flow.residual_entry_bridge import EntryBridgeEvidence
from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
    SemanticCarrierProof,
    SemanticCorridorPoint,
    SemanticPredicateKind,
    SemanticPredicateProof,
    SemanticRouteDestination,
    SemanticRouteProof,
    SemanticRouteProofKind,
    SemanticRouteShape,
    SemanticStateWriteProof,
)
from d810.analyses.control_flow.terminal_return_carrier_evidence import (
    TerminalReturnCarrierEvidence,
    TerminalReturnCarrierEvidenceRejected,
)
from d810.core.native_preanalysis_key import (
    NativePreanalysisKey,
    NativePreanalysisKeyMismatch,
)
from d810.core import getLogger
from d810.core.typing import Callable, Mapping, NamedTuple, Protocol, runtime_checkable
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind

logger = getLogger(__name__)

_CONDITIONAL_BRIDGE_IDENTITY_FIELDS = (
    "source_jmp_ea",
    "source_block_ea",
    "materialized_anchor_eas",
    "target_eas",
    "resolver_kind",
)


def _merge_compatible_conditional_bridge_evidence(
    existing: MaterializedIndirectTransfer,
    incoming: MaterializedIndirectTransfer,
) -> MaterializedIndirectTransfer | None:
    """Refresh one predicate without discarding an earlier exact arm proof."""
    for name in _CONDITIONAL_BRIDGE_IDENTITY_FIELDS:
        if getattr(existing, name) != getattr(incoming, name):
            return None
    enriched: dict[str, object] = {}
    for item in fields(MaterializedIndirectTransfer):
        if item.name in _CONDITIONAL_BRIDGE_IDENTITY_FIELDS:
            continue
        if item.default is MISSING:
            return None
        old_value = getattr(existing, item.name)
        new_value = getattr(incoming, item.name)
        if new_value == item.default:
            continue
        if old_value == item.default:
            enriched[item.name] = new_value
            continue
        if old_value != new_value:
            return None
    return replace(existing, **enriched) if enriched else existing


@dataclass(frozen=True, slots=True)
class NativePreanalysisFacts:
    """Normalized portable evidence for one exact native-analysis identity."""

    key: NativePreanalysisKey
    native_cfg: NativeCfg
    semantic_closure: NativeSemanticClosure | None
    transfers: tuple[MaterializedIndirectTransfer, ...]
    boundary_ports: DetachedSnippetBoundaryPorts

    def __post_init__(self) -> None:
        if not isinstance(self.key, NativePreanalysisKey):
            raise TypeError("native preanalysis facts require a native key")
        if not isinstance(self.native_cfg, NativeCfg):
            raise TypeError("native preanalysis facts require a native CFG")
        if self.semantic_closure is not None and not isinstance(
            self.semantic_closure,
            NativeSemanticClosure,
        ):
            raise TypeError("semantic closure must be portable native evidence")
        if not all(
            isinstance(transfer, MaterializedIndirectTransfer)
            for transfer in self.transfers
        ):
            raise TypeError("native preanalysis transfers must be portable facts")
        normalized_transfers = tuple(
            sorted(
                set(self.transfers),
                key=lambda transfer: (
                    int(transfer.source_jmp_ea),
                    int(transfer.source_block_ea),
                    tuple(int(ea) for ea in transfer.materialized_anchor_eas),
                    tuple(int(ea) for ea in transfer.target_eas),
                    str(transfer.resolver_kind),
                    repr(transfer),
                ),
            )
        )
        normalized_ports = normalize_detached_snippet_boundary_ports(
            tuple(self.boundary_ports.direct),
            tuple(self.boundary_ports.conditional),
        )
        object.__setattr__(self, "transfers", normalized_transfers)
        object.__setattr__(self, "boundary_ports", normalized_ports)

    def require_key(self, expected: NativePreanalysisKey) -> None:
        """Reject evidence captured for another input/function/profile/SDK."""
        if self.key == expected:
            return
        raise NativePreanalysisKeyMismatch(
            expected,
            self.key,
            expected.mismatch_fields(self.key),
        )


class BootstrapRouteProofKind(Enum):
    """Authority used to publish one bootstrap state route."""

    STATIC_NATIVE = "static_native"
    CALLS_LIVE = "calls_live"


@dataclass(frozen=True, slots=True)
class BootstrapRouteEvidence:
    """Serial-free route preserved while an MBA is regenerated."""

    source_identity: StableBlockIdentity
    source_anchor_ea: int
    state: int
    handler_identity: StableBlockIdentity
    handler_anchor_ea: int
    proof_kind: BootstrapRouteProofKind

    def __post_init__(self) -> None:
        source_anchor_ea = int(self.source_anchor_ea)
        handler_anchor_ea = int(self.handler_anchor_ea)
        if not self.source_identity.native_ranges.contains(source_anchor_ea):
            raise ValueError("bootstrap source anchor is outside source identity")
        if not self.handler_identity.native_ranges.contains(handler_anchor_ea):
            raise ValueError("bootstrap handler anchor is outside handler identity")
        object.__setattr__(self, "source_anchor_ea", source_anchor_ea)
        object.__setattr__(self, "handler_anchor_ea", handler_anchor_ea)
        object.__setattr__(self, "state", int(self.state))

    @property
    def key(self) -> tuple[StableBlockIdentity, int]:
        return self.source_identity, int(self.state)

    def diagnostic_payload(
        self, *, generation: int, rebound: bool
    ) -> dict[str, object]:
        return {
            "source_ea": f"0x{self.source_anchor_ea:X}",
            "state": f"0x{int(self.state):X}",
            "handler_ea": f"0x{self.handler_anchor_ea:X}",
            "generation": int(generation),
            "proof_kind": self.proof_kind.value,
            "rebound": bool(rebound),
        }


@dataclass(frozen=True, slots=True)
class BootstrapRouteBindingEvidence:
    """Serial-free binding of one bootstrap route in a later live snapshot."""

    route: BootstrapRouteEvidence
    source_identity: StableBlockIdentity
    handler_identity: StableBlockIdentity
    evidence_generation: int

    def __post_init__(self) -> None:
        if not self.source_identity.native_ranges.contains(
            int(self.route.source_anchor_ea)
        ):
            raise ValueError("bound bootstrap source identity lost its anchor")
        if not self.handler_identity.native_ranges.contains(
            int(self.route.handler_anchor_ea)
        ):
            raise ValueError("bound bootstrap handler identity lost its anchor")
        generation = int(self.evidence_generation)
        if generation < 0:
            raise ValueError("bootstrap binding generation must be non-negative")
        object.__setattr__(self, "evidence_generation", generation)


@dataclass(frozen=True, slots=True)
class CallResultCarrier:
    """Serial-free call-result carrier captured before later restoration."""

    call_ea: int
    carrier_ea: int
    branch_ea: int
    callee_ea: int
    carrier_ida_stkoff: int
    value_size: int
    branch_opcode: int


class ComputedGotoPatchPlan(NamedTuple):
    """Portable native byte-patch plan for one computed-goto site."""

    jmp_ea: int
    block_entry: int
    patch_start: int
    patch_bytes: bytes
    region_end: int
    insn_heads: tuple[int, ...]
    new_block_eas: tuple[int, ...]
    target_eas: tuple[int, ...] = ()
    condition_code: int | None = None
    true_target_ea: int | None = None
    false_target_ea: int | None = None
    selector_register_name: str | None = None
    selector_compare_constant: int | None = None
    selector_state_on_left: bool | None = None
    source_register_values: tuple[tuple[str, int], ...] = ()
    condition_producer_ea: int | None = None


@dataclass(frozen=True)
class ComputedGotoResolution:
    """Portable targets and native delivery evidence for one function."""

    function_ea: int
    jmp_targets: Mapping[int, tuple[int, ...]]
    reachable_eas: tuple[int, ...]
    arch: str
    executed_insns: int
    seeds_run: int
    stop_reasons: tuple[str, ...] = field(default_factory=tuple)
    patch_plans: tuple[ComputedGotoPatchPlan, ...] = field(default_factory=tuple)
    block_entries: tuple[int, ...] = field(default_factory=tuple)
    function_context_register_values: tuple[tuple[str, int], ...] = field(
        default_factory=tuple
    )
    corridor_register_snapshots: tuple[tuple[int, tuple[tuple[str, int], ...]], ...] = (
        field(default_factory=tuple)
    )
    dispatcher_context_register_values: tuple[tuple[str, int], ...] = field(
        default_factory=tuple
    )
    native_stack_frame_offsets: tuple[tuple[int, tuple[int, ...]], ...] = field(
        default_factory=tuple
    )
    conditional_state_choices: tuple[MaterializedIndirectTransfer, ...] = field(
        default_factory=tuple
    )

    @property
    def site_count(self) -> int:
        return len(self.jmp_targets)

    @property
    def target_count(self) -> int:
        return sum(len(targets) for targets in self.jmp_targets.values())


def _unique_native_block_for_anchor(
    native_cfg: NativeCfg,
    anchor_ea: int,
    *,
    description: str,
) -> NativeBlock:
    anchor_ea = int(anchor_ea)
    matches = tuple(
        block
        for block in native_cfg.blocks_by_ea.values()
        if int(block.start_ea) <= anchor_ea < int(block.end_ea)
    )
    if len(matches) != 1:
        raise FrontendNormalizationEvidenceRejected(
            f"{description} 0x{anchor_ea:X} requires one native CFG owner"
        )
    return matches[0]


def _native_block_identity(
    native_key: NativePreanalysisKey,
    block: NativeBlock,
    *,
    exact_eas: tuple[int, ...],
) -> StableBlockIdentity:
    normalized_exact_eas = tuple(sorted({int(ea) for ea in exact_eas}))
    if not normalized_exact_eas or any(
        not int(block.start_ea) <= ea < int(block.end_ea)
        for ea in normalized_exact_eas
    ):
        raise FrontendNormalizationEvidenceRejected(
            "native block identity exact anchors escaped their CFG owner"
        )
    return StableBlockIdentity.from_intervals(
        (
            NativeEaInterval(
                int(block.start_ea),
                int(block.end_ea),
            ),
        ),
        native_key=native_key,
        exact_instruction_eas=normalized_exact_eas,
    )


def _patch_plan_source_identity(
    native_key: NativePreanalysisKey,
    plan: ComputedGotoPatchPlan,
    *,
    exact_eas: tuple[int, ...],
) -> StableBlockIdentity:
    """Validate one patched extent and retain its synthesized source identity."""
    block_entry = int(plan.block_entry)
    patch_start = int(plan.patch_start)
    region_end = int(plan.region_end)
    jmp_ea = int(plan.jmp_ea)
    insn_heads = tuple(int(ea) for ea in plan.insn_heads)
    new_block_eas = tuple(int(ea) for ea in plan.new_block_eas)
    if (
        block_entry < 0
        or patch_start < block_entry
        or region_end <= patch_start
        or not patch_start <= jmp_ea < region_end
        or not insn_heads
        or insn_heads[0] != patch_start
        or any(not patch_start <= ea < region_end for ea in insn_heads)
        or any(ea not in insn_heads for ea in new_block_eas)
    ):
        raise FrontendNormalizationEvidenceRejected(
            "computed transfer patch has no exact native source extent"
        )
    normalized_exact_eas = tuple(sorted({int(ea) for ea in exact_eas}))
    if not normalized_exact_eas or any(
        not patch_start <= ea < region_end for ea in normalized_exact_eas
    ):
        raise FrontendNormalizationEvidenceRejected(
            "computed transfer source anchors escaped their patch extent"
        )
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(patch_start, region_end),),
        native_key=native_key,
        exact_instruction_eas=normalized_exact_eas,
    )


def _patch_plan_condition_identity(
    native_key: NativePreanalysisKey,
    plan: ComputedGotoPatchPlan,
    *,
    condition_producer_ea: int,
) -> StableBlockIdentity:
    """Retain the pre-patch producer corridor owned by one computed transfer."""
    block_entry = int(plan.block_entry)
    patch_start = int(plan.patch_start)
    condition_producer_ea = int(condition_producer_ea)
    if not block_entry <= condition_producer_ea < patch_start:
        raise FrontendNormalizationEvidenceRejected(
            "conditional patch does not preserve its condition producer"
        )
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(block_entry, patch_start),),
        native_key=native_key,
        exact_instruction_eas=(condition_producer_ea,),
    )


def _resolver_target_identity(
    native_key: NativePreanalysisKey,
    target_ea: int,
) -> StableBlockIdentity:
    """Retain one destination exactly as proved by the resolver ledger."""
    return StableBlockIdentity.from_instruction_eas(
        (int(target_ea),),
        native_key=native_key,
    )


def _patch_plan_frontend_proof(
    native_key: NativePreanalysisKey,
    plan: ComputedGotoPatchPlan,
    *,
    atomic_group_id: str,
) -> NativeIndirectTransferProof:
    target_eas = tuple(int(ea) for ea in plan.target_eas)
    proof_id = f"native-indirect-transfer@0x{int(plan.jmp_ea):X}"
    provenance = (
        ("provider", "native-computed-goto"),
        ("source_jmp_ea", f"0x{int(plan.jmp_ea):X}"),
        ("patch_block_entry_ea", f"0x{int(plan.block_entry):X}"),
        ("patch_start_ea", f"0x{int(plan.patch_start):X}"),
        ("patch_region_end_ea", f"0x{int(plan.region_end):X}"),
    )
    if len(target_eas) == 1:
        source_anchor_ea = int(plan.patch_start)
        source_identity = _patch_plan_source_identity(
            native_key,
            plan,
            exact_eas=(source_anchor_ea,),
        )
        return NativeIndirectTransferProof(
            proof_id=proof_id,
            atomic_group_id=atomic_group_id,
            shape=NativeTransferShape.DIRECT,
            source_identity=source_identity,
            source_anchor_ea=source_anchor_ea,
            source_transfer_ea=int(plan.jmp_ea),
            endpoints=(
                NativeTransferEndpoint(
                    role=SemanticEdgeRole.DIRECT,
                    identity=_resolver_target_identity(
                        native_key,
                        target_eas[0],
                    ),
                    anchor_ea=target_eas[0],
                ),
            ),
            diagnostic_provenance=provenance,
        )

    if (
        len(target_eas) != 2
        or plan.condition_code is None
        or plan.true_target_ea is None
        or plan.false_target_ea is None
        or plan.condition_producer_ea is None
        or len(plan.insn_heads) < 2
        or len(plan.new_block_eas) < 2
    ):
        raise FrontendNormalizationEvidenceRejected(
            "conditional patch plan lacks complete predicate evidence"
        )
    true_target_ea = int(plan.true_target_ea)
    false_target_ea = int(plan.false_target_ea)
    normalization_start_ea = int(plan.patch_start)
    predicate_ea = int(plan.new_block_eas[0])
    condition_producer_ea = int(plan.condition_producer_ea)
    predicate_kind = condition_code_predicate(plan.condition_code)
    if (
        true_target_ea == false_target_ea
        or {true_target_ea, false_target_ea} != set(target_eas)
        or predicate_ea != int(plan.insn_heads[-2])
        or predicate_kind is None
    ):
        raise FrontendNormalizationEvidenceRejected(
            "conditional patch plan topology is inconsistent"
        )
    source_identity = _patch_plan_source_identity(
        native_key,
        plan,
        exact_eas=(normalization_start_ea, predicate_ea),
    )
    condition_identity = _patch_plan_condition_identity(
        native_key,
        plan,
        condition_producer_ea=condition_producer_ea,
    )
    corridor_identities = (condition_identity, source_identity)
    endpoints = tuple(
        NativeTransferEndpoint(
            role=role,
            identity=_resolver_target_identity(
                native_key,
                target_ea,
            ),
            anchor_ea=target_ea,
        )
        for role, target_ea in (
            (SemanticEdgeRole.CONDITIONAL_TAKEN, true_target_ea),
            (
                SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                false_target_ea,
            ),
        )
    )
    return NativeIndirectTransferProof(
        proof_id=proof_id,
        atomic_group_id=atomic_group_id,
        shape=NativeTransferShape.CONDITIONAL,
        source_identity=source_identity,
        source_anchor_ea=normalization_start_ea,
        source_transfer_ea=int(plan.jmp_ea),
        endpoints=endpoints,
        predicate_kind=predicate_kind,
        predicate_anchor_ea=predicate_ea,
        condition_producer_ea=condition_producer_ea,
        flag_corridor=corridor_identities,
        permitted_flag_write_eas=frozenset({condition_producer_ea}),
        diagnostic_provenance=(
            *provenance,
            ("condition_code", str(int(plan.condition_code))),
        ),
    )


def _field_complete_static_state_choice(
    transfer: MaterializedIndirectTransfer,
) -> bool:
    """Whether one portable bridge owns an original compare/CMOV choice."""
    predicate_register = transfer.predicate_register
    predicate_stack = transfer.predicate_stack_ida_stkoff
    target_eas = (transfer.true_target_ea, transfer.false_target_ea)
    state_values = (
        transfer.predicate_true_state,
        transfer.predicate_false_state,
    )
    anchors = tuple(int(ea) for ea in transfer.materialized_anchor_eas)
    return bool(
        is_conditional_handler_bridge_kind(str(transfer.resolver_kind))
        and transfer.predicate_preserve_live
        and transfer.condition_code in {2, 3, 4, 5, 6, 7, 12, 13, 14, 15}
        and transfer.predicate_true_is_taken in (True, False)
        and transfer.selector_state_var_reg is not None
        and transfer.predicate_size is not None
        and int(transfer.predicate_size) > 0
        and transfer.predicate_compare_constant is not None
        and transfer.predicate_compare_register is None
        and (predicate_register is None) != (predicate_stack is None)
        and len(anchors) == 2
        and anchors[-1] == int(transfer.source_jmp_ea)
        and all(value is not None for value in target_eas)
        and all(value is not None for value in state_values)
        and int(target_eas[0]) != int(target_eas[1])
        and int(state_values[0]) != int(state_values[1])
        and set(int(ea) for ea in transfer.target_eas)
        == {int(target_eas[0]), int(target_eas[1])}
        and transfer.state_carrier_store_ea is None
        and not transfer.state_carrier_consumer_load_eas
    )


def _static_state_choice_envelope(
    native_cfg: NativeCfg,
    source: NativeBlock,
) -> tuple[tuple[NativeBlock, ...], int]:
    """Prove one closed native corridor ending at one indirect frontier."""
    blocks: dict[int, NativeBlock] = {}
    successors: dict[int, set[int]] = {}
    frontier_rows: list[tuple[int, int]] = []
    pending = [int(source.start_ea)]
    while pending:
        entry_ea = pending.pop()
        if entry_ea in blocks:
            continue
        if len(blocks) >= 32:
            raise FrontendNormalizationEvidenceRejected(
                "static state-choice envelope exceeds the bounded native corridor"
            )
        block = native_cfg.blocks_by_ea.get(entry_ea)
        if block is None:
            raise FrontendNormalizationEvidenceRejected(
                "static state-choice envelope lost a native CFG block"
            )
        blocks[entry_ea] = block
        control_edges = tuple(
            edge
            for edge in block.outgoing_edges
            if edge.kind is not NativeEdgeKind.CALL
        )
        if any(edge.kind is NativeEdgeKind.CALL for edge in block.outgoing_edges):
            raise FrontendNormalizationEvidenceRejected(
                "static state-choice envelope crosses a native call"
            )
        indirect_edges = tuple(
            edge for edge in control_edges if edge.kind is NativeEdgeKind.INDIRECT
        )
        if indirect_edges:
            if (
                len(control_edges) != 1
                or len(indirect_edges) != 1
                or not indirect_edges[0].resolver_proven
                or indirect_edges[0].source_instruction_ea is None
            ):
                raise FrontendNormalizationEvidenceRejected(
                    "static state-choice envelope has an ambiguous indirect frontier"
                )
            frontier_rows.append(
                (
                    entry_ea,
                    int(indirect_edges[0].source_instruction_ea),
                )
            )
            successors[entry_ea] = set()
            continue
        if not control_edges:
            raise FrontendNormalizationEvidenceRejected(
                "static state-choice envelope terminates before its indirect frontier"
            )
        block_successors: set[int] = set()
        for edge in control_edges:
            if (
                edge.kind
                not in {
                    NativeEdgeKind.DIRECT_JUMP,
                    NativeEdgeKind.FALLTHROUGH,
                    NativeEdgeKind.CALL_FALLTHROUGH,
                    NativeEdgeKind.CONDITIONAL_TRUE,
                    NativeEdgeKind.CONDITIONAL_FALSE,
                }
                or edge.target_ea is None
            ):
                raise FrontendNormalizationEvidenceRejected(
                    "static state-choice envelope has an unsupported native edge"
                )
            target = _unique_native_block_for_anchor(
                native_cfg,
                int(edge.target_ea),
                description="static state-choice envelope target",
            )
            target_entry_ea = int(target.start_ea)
            block_successors.add(target_entry_ea)
            if target_entry_ea not in blocks:
                pending.append(target_entry_ea)
        successors[entry_ea] = block_successors

    if len(frontier_rows) != 1:
        raise FrontendNormalizationEvidenceRejected(
            "static state-choice envelope requires one indirect frontier"
        )
    frontier_entry_ea, transfer_ea = frontier_rows[0]
    reaches_frontier = {frontier_entry_ea}
    changed = True
    while changed:
        changed = False
        for entry_ea, target_eas in successors.items():
            if entry_ea in reaches_frontier or not target_eas:
                continue
            if all(target_ea in reaches_frontier for target_ea in target_eas):
                reaches_frontier.add(entry_ea)
                changed = True
    if set(blocks) != reaches_frontier:
        raise FrontendNormalizationEvidenceRejected(
            "static state-choice envelope has a route outside its indirect frontier"
        )
    return (
        tuple(blocks[entry_ea] for entry_ea in sorted(blocks)),
        transfer_ea,
    )


def _static_state_choice_frontend_proof(
    native_key: NativePreanalysisKey,
    native_cfg: NativeCfg,
    transfer: MaterializedIndirectTransfer,
    *,
    atomic_group_id: str,
) -> NativeIndirectTransferProof | None:
    """Project one exact compare/CMOV state choice into frontend authority."""
    if not _field_complete_static_state_choice(transfer):
        return None
    producer_ea, predicate_ea = (
        int(ea) for ea in transfer.materialized_anchor_eas
    )
    source = _unique_native_block_for_anchor(
        native_cfg,
        int(transfer.source_block_ea),
        description="static state-choice source",
    )
    if (
        int(source.start_ea) != int(transfer.source_block_ea)
        or not int(source.start_ea) <= producer_ea < int(source.end_ea)
        or not int(source.start_ea) <= predicate_ea < int(source.end_ea)
    ):
        raise FrontendNormalizationEvidenceRejected(
            "static state-choice producer and predicate require one native source"
        )
    predicate_kind = condition_code_predicate(int(transfer.condition_code))
    if predicate_kind is None:
        raise FrontendNormalizationEvidenceRejected(
            "static state-choice condition code has no portable predicate"
        )
    envelope, unresolved_transfer_ea = _static_state_choice_envelope(
        native_cfg,
        source,
    )
    source_identity = StableBlockIdentity.from_intervals(
        tuple(
            NativeEaInterval(int(block.start_ea), int(block.end_ea))
            for block in envelope
        ),
        native_key=native_key,
        exact_instruction_eas=(producer_ea, predicate_ea),
    )
    flag_identity = _native_block_identity(
        native_key,
        source,
        exact_eas=(producer_ea, predicate_ea),
    )
    true_target_ea = int(transfer.true_target_ea)
    false_target_ea = int(transfer.false_target_ea)
    true_target = _unique_native_block_for_anchor(
        native_cfg,
        true_target_ea,
        description="static state-choice true target",
    )
    false_target = _unique_native_block_for_anchor(
        native_cfg,
        false_target_ea,
        description="static state-choice false target",
    )
    true_pair = (SemanticEdgeRole.CONDITIONAL_TAKEN, true_target_ea, true_target)
    false_pair = (
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
        false_target_ea,
        false_target,
    )
    if not bool(transfer.predicate_true_is_taken):
        true_pair, false_pair = (
            (
                SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                true_target_ea,
                true_target,
            ),
            (
                SemanticEdgeRole.CONDITIONAL_TAKEN,
                false_target_ea,
                false_target,
            ),
        )
    return NativeIndirectTransferProof(
        proof_id=f"native-state-choice@0x{predicate_ea:X}",
        atomic_group_id=atomic_group_id,
        shape=NativeTransferShape.CONDITIONAL,
        source_identity=source_identity,
        source_anchor_ea=predicate_ea,
        source_transfer_ea=unresolved_transfer_ea,
        endpoints=tuple(
            NativeTransferEndpoint(
                role=role,
                identity=_native_block_identity(
                    native_key,
                    target,
                    exact_eas=(target_ea,),
                ),
                anchor_ea=target_ea,
            )
            for role, target_ea, target in (true_pair, false_pair)
        ),
        predicate_kind=predicate_kind,
        predicate_anchor_ea=predicate_ea,
        condition_producer_ea=producer_ea,
        flag_corridor=(flag_identity,),
        permitted_flag_write_eas=frozenset({producer_ea}),
        diagnostic_provenance=(
            ("provider", str(transfer.resolver_kind)),
            (
                "predicate_storage",
                (
                    f"reg:{int(transfer.predicate_register)}"
                    if transfer.predicate_register is not None
                    else f"stack:{int(transfer.predicate_stack_ida_stkoff)}"
                ),
            ),
            (
                "predicate_constant",
                f"0x{int(transfer.predicate_compare_constant):X}",
            ),
            ("predicate_true_state", f"0x{int(transfer.predicate_true_state):X}"),
            (
                "predicate_false_state",
                f"0x{int(transfer.predicate_false_state):X}",
            ),
        ),
    )


def _semantic_corridor_point(
    native_key: NativePreanalysisKey,
    native_cfg: NativeCfg,
    anchor_ea: int,
    *,
    description: str,
) -> SemanticCorridorPoint:
    block = _unique_native_block_for_anchor(
        native_cfg,
        int(anchor_ea),
        description=description,
    )
    return SemanticCorridorPoint(
        _native_block_identity(
            native_key,
            block,
            exact_eas=(int(anchor_ea),),
        ),
        int(anchor_ea),
    )


def _entry_consumer_semantic_route_proof(
    native_key: NativePreanalysisKey,
    native_cfg: NativeCfg,
    transfer: MaterializedIndirectTransfer,
    *,
    atomic_group_id: str,
) -> SemanticRouteProof | None:
    """Project one field-complete carried choice without provider-name routing."""
    consumer_load_eas = tuple(
        int(ea) for ea in transfer.state_carrier_consumer_load_eas
    )
    target_eas = (
        transfer.true_target_ea,
        transfer.false_target_ea,
    )
    state_values = (
        transfer.predicate_true_state,
        transfer.predicate_false_state,
    )
    width = 0 if transfer.predicate_size is None else int(transfer.predicate_size)
    if (
        len(consumer_load_eas) != 1
        or transfer.state_carrier_store_ea is None
        or transfer.state_carrier_stack_displacement is None
        or transfer.state_carrier_ida_stkoff is None
        or transfer.predicate_stack_ida_stkoff is None
        or not 1 <= width <= 8
        or transfer.condition_code not in {4, 5}
        or transfer.predicate_true_is_taken not in (True, False)
        or any(value is None for value in target_eas)
        or any(value is None for value in state_values)
        or int(target_eas[0]) == int(target_eas[1])
        or int(state_values[0]) == int(state_values[1])
        or set(int(ea) for ea in transfer.target_eas)
        != {int(target_eas[0]), int(target_eas[1])}
        or int(transfer.state_carrier_store_ea)
        not in {int(ea) for ea in transfer.materialized_anchor_eas}
        or not transfer.owned_native_ranges
    ):
        return None

    predicate_ea = int(transfer.source_jmp_ea)
    store_ea = int(transfer.state_carrier_store_ea)
    consumer_ea = int(consumer_load_eas[0])
    try:
        predicate_origin = _semantic_corridor_point(
            native_key,
            native_cfg,
            predicate_ea,
            description="semantic predicate origin",
        )
        carrier_definition = _semantic_corridor_point(
            native_key,
            native_cfg,
            store_ea,
            description="semantic carrier definition",
        )
        consumer = _semantic_corridor_point(
            native_key,
            native_cfg,
            consumer_ea,
            description="semantic entry consumer",
        )
        consumer_block = _unique_native_block_for_anchor(
            native_cfg,
            consumer_ea,
            description="semantic entry consumer",
        )
        if not any(
            int(start_ea) <= int(consumer_block.start_ea)
            and int(consumer_block.end_ea) <= int(end_ea)
            for start_ea, end_ea in transfer.owned_native_ranges
        ):
            return None
        true_target = _semantic_corridor_point(
            native_key,
            native_cfg,
            int(target_eas[0]),
            description="semantic true target",
        )
        false_target = _semantic_corridor_point(
            native_key,
            native_cfg,
            int(target_eas[1]),
            description="semantic false target",
        )
    except FrontendNormalizationEvidenceRejected:
        return None

    predicate_corridor = tuple(
        dict.fromkeys((predicate_origin, carrier_definition, consumer))
    )
    carrier_corridor = tuple(dict.fromkeys((carrier_definition, consumer)))
    true_pair = (int(state_values[0]), true_target)
    false_pair = (int(state_values[1]), false_target)
    if transfer.predicate_true_is_taken:
        taken_pair, fallthrough_pair = true_pair, false_pair
    else:
        taken_pair, fallthrough_pair = false_pair, true_pair
    if int(transfer.condition_code) == 4:
        equality_true, equality_false = taken_pair, fallthrough_pair
    else:
        equality_true, equality_false = fallthrough_pair, taken_pair

    return SemanticRouteProof(
        proof_id=(
            f"state-choice@0x{consumer_ea:X}:"
            f"0x{equality_true[0] & 0xFFFFFFFF:X}:"
            f"0x{equality_false[0] & 0xFFFFFFFF:X}"
        ),
        atomic_group_id=atomic_group_id,
        proof_kind=SemanticRouteProofKind.STATE_CHOICE,
        shape=SemanticRouteShape.CONDITIONAL,
        source_identity=consumer.identity,
        source_anchor_ea=consumer.anchor_ea,
        source_owner_identity=consumer.identity,
        source_owner_anchor_ea=consumer.anchor_ea,
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                state_constant=int(equality_true[0]) & 0xFFFFFFFF,
                target_identity=equality_true[1].identity,
                target_anchor_ea=equality_true[1].anchor_ea,
            ),
            SemanticRouteDestination(
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                state_constant=int(equality_false[0]) & 0xFFFFFFFF,
                target_identity=equality_false[1].identity,
                target_anchor_ea=equality_false[1].anchor_ea,
            ),
        ),
        predicate=SemanticPredicateProof(
            kind=SemanticPredicateKind.STORAGE_EQUALS,
            origin=predicate_origin,
            consumer=consumer,
            corridor=predicate_corridor,
            storage_identity=StorageIdentity(
                StorageIdentityKind.STACK,
                int(transfer.predicate_stack_ida_stkoff),
            ),
            width=width,
            compare_constant=0,
        ),
        carriers=(
            SemanticCarrierProof(
                carrier_id=f"state-carrier@0x{store_ea:X}:0x{consumer_ea:X}",
                definition=carrier_definition,
                consumers=(consumer,),
                corridor=carrier_corridor,
                storage_identity=StorageIdentity(
                    StorageIdentityKind.STACK,
                    int(transfer.state_carrier_ida_stkoff),
                ),
                width=width,
                state_values=(
                    int(state_values[0]) & 0xFFFFFFFF,
                    int(state_values[1]) & 0xFFFFFFFF,
                ),
                permitted_write_eas=frozenset({store_ea}),
            ),
        ),
        diagnostic_provenance=(
            ("provider_resolver_kind", str(transfer.resolver_kind)),
        ),
    )


@dataclass(frozen=True, slots=True)
class PreoptUnionPreparationResult:
    """EA-keyed outcome of one production PREOPT union preparation."""

    function_ea: int
    prepared: bool
    published: bool
    primary_seed_ea: int | None = None
    seed_eas: tuple[int, ...] = ()
    native_ranges: tuple[tuple[int, int], ...] = ()
    imported_block_entry_eas: tuple[int, ...] = ()
    entry_consumer_routes: tuple[MaterializedIndirectTransfer, ...] = ()
    entry_consumer_port_diagnostic: tuple[tuple[str, object], ...] = ()
    abstention_reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PrepatchPreoptUnionSource:
    """PREOPT source captured before native byte delivery changes reachability."""

    primary_seed_ea: int
    seed_eas: tuple[int, ...]
    seed_native_ranges: tuple[tuple[int, tuple[tuple[int, int], ...]], ...]
    native_ranges: tuple[tuple[int, int], ...]
    imported_block_entry_eas: tuple[int, ...]
    cfg: NativeCfg
    closure: NativeSemanticClosure


@dataclass(frozen=True, slots=True)
class ResolverPortableEvidence:
    """Typed resolver facts owned by one exact lifecycle identity."""

    key: NativePreanalysisKey
    state_routes: tuple[PortableMaterializedStateRoute, ...] = ()
    state_write_routes: tuple[PortableStateWriteRouteEvidence, ...] = ()
    dispatcher_region_identity: StableBlockIdentity | None = None
    terminal_return_carrier_requests: tuple[TerminalReturnCarrierRequest, ...] = ()
    terminal_return_carriers: tuple[TerminalReturnCarrierEvidence, ...] = ()
    call_result_carriers: tuple[CallResultCarrier, ...] = ()
    call_abi_proofs: tuple[tuple[int, StackCallAbiProof], ...] = ()
    bootstrap_route_bindings: tuple[
        tuple[tuple[StableBlockIdentity, int], BootstrapRouteBindingEvidence], ...
    ] = ()
    computed_goto_resolution: ComputedGotoResolution | None = None
    preopt_union_preparation: PreoptUnionPreparationResult | None = None
    prepatch_preopt_union_source: PrepatchPreoptUnionSource | None = None
    preopt_entry_bridges: tuple[EntryBridgeEvidence, ...] = ()

    def require_key(self, expected: NativePreanalysisKey) -> None:
        """Reject resolver evidence captured for another native identity."""
        if self.key == expected:
            return
        raise NativePreanalysisKeyMismatch(
            expected,
            self.key,
            expected.mismatch_fields(self.key),
        )


@dataclass(frozen=True, slots=True)
class EvidenceLifecycleTransition:
    operation: str
    previous_generation: int
    resulting_generation: int
    evidence_family: str
    outcome: str
    reason: str


@dataclass(slots=True)
class NativePreanalysisSessionState:
    """First-class portable evidence and epoch authority for a lifecycle."""

    evidence_generation: int = 0
    portable_evidence_ready_generation: int | None = None
    normalization_staged_generation: int | None = None
    normalization_validated_generation: int | None = None
    normalization_published_postvalidated_generation: int | None = None
    normalization_work_item_publication_revision: int = 0
    normalization_last_published_work_item_id: str | None = None
    normalization_last_selected_obligation_ids: tuple[str, ...] = ()
    normalization_last_remaining_obligation_ids: tuple[str, ...] = ()
    normalization_last_unreachable_obligation_ids: tuple[str, ...] = ()
    canonical_semantic_plan_generation: int | None = None
    semantic_fragment_staged_generation: int | None = None
    semantic_fragment_validated_generation: int | None = None
    semantic_fragment_published_postvalidated_generation: int | None = None
    receipt_committed_generation: int | None = None
    facts: NativePreanalysisFacts | None = None
    resolver_evidence: ResolverPortableEvidence | None = None
    bootstrap_routes: dict[tuple[StableBlockIdentity, int], BootstrapRouteEvidence] = (
        field(default_factory=dict)
    )
    conflicted_bootstrap_keys: set[tuple[StableBlockIdentity, int]] = field(
        default_factory=set
    )
    rebound_bootstrap_keys: set[tuple[StableBlockIdentity, int]] = field(
        default_factory=set
    )
    rebound_bootstrap_generations: dict[tuple[StableBlockIdentity, int], int] = field(
        default_factory=dict
    )
    published_bootstrap_keys: set[tuple[StableBlockIdentity, int]] = field(
        default_factory=set
    )
    transfer_inventory_revision: int = 0
    published_transfer_inventory_revision: int | None = None
    state_write_route_inventory_revision: int = 0
    published_state_write_route_inventory_revision: int | None = None
    bound_state_write_route_generation: int | None = None
    redo_generation: int | None = None
    pending_generated_restart_generation: int | None = None
    event_observer: Callable[[EvidenceLifecycleTransition], None] | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        generation = int(self.evidence_generation)
        if generation < 0:
            raise ValueError("portable evidence generation must be non-negative")
        self.evidence_generation = generation
        if self.portable_evidence_ready_generation is None and generation > 0:
            self.portable_evidence_ready_generation = generation
        marker_names = (
            "portable_evidence_ready_generation",
            "normalization_staged_generation",
            "normalization_validated_generation",
            "normalization_published_postvalidated_generation",
            "canonical_semantic_plan_generation",
            "semantic_fragment_staged_generation",
            "semantic_fragment_validated_generation",
            "semantic_fragment_published_postvalidated_generation",
            "receipt_committed_generation",
        )
        for name in marker_names:
            value = getattr(self, name)
            if value is None:
                continue
            value = int(value)
            if value <= 0:
                raise ValueError("lifecycle generation markers must be positive")
            if value > generation:
                raise ValueError(
                    "lifecycle generation cannot exceed portable evidence"
                )
            setattr(self, name, value)
        if (
            self.portable_evidence_ready_generation is not None
            and self.portable_evidence_ready_generation != generation
        ):
            raise ValueError(
                "portable evidence-ready generation must equal current evidence"
            )
        publication_revision = int(
            self.normalization_work_item_publication_revision
        )
        if publication_revision < 0:
            raise ValueError(
                "normalization work-item publication revision cannot be negative"
            )
        work_item_id = self.normalization_last_published_work_item_id
        selected_obligation_ids = tuple(
            str(value).strip()
            for value in self.normalization_last_selected_obligation_ids
        )
        remaining_obligation_ids = tuple(
            str(value).strip()
            for value in self.normalization_last_remaining_obligation_ids
        )
        unreachable_obligation_ids = tuple(
            str(value).strip()
            for value in self.normalization_last_unreachable_obligation_ids
        )
        if publication_revision == 0:
            if (
                work_item_id is not None
                or selected_obligation_ids
                or remaining_obligation_ids
                or unreachable_obligation_ids
            ):
                raise ValueError(
                    "unpublished normalization work item cannot retain authority"
                )
        elif (
            work_item_id is None
            or not str(work_item_id).strip()
            or not selected_obligation_ids
            or any(not value for value in selected_obligation_ids)
            or any(not value for value in remaining_obligation_ids)
            or any(not value for value in unreachable_obligation_ids)
            or len(set(selected_obligation_ids)) != len(selected_obligation_ids)
            or len(set(remaining_obligation_ids))
            != len(remaining_obligation_ids)
            or len(set(unreachable_obligation_ids))
            != len(unreachable_obligation_ids)
            or (
                len(
                    set(
                        (
                            *selected_obligation_ids,
                            *remaining_obligation_ids,
                            *unreachable_obligation_ids,
                        )
                    )
                )
                != len(selected_obligation_ids)
                + len(remaining_obligation_ids)
                + len(unreachable_obligation_ids)
            )
        ):
            raise ValueError(
                "published normalization work item requires disjoint obligations"
            )
        self.normalization_work_item_publication_revision = publication_revision
        self.normalization_last_published_work_item_id = (
            None if work_item_id is None else str(work_item_id).strip()
        )
        self.normalization_last_selected_obligation_ids = selected_obligation_ids
        self.normalization_last_remaining_obligation_ids = (
            remaining_obligation_ids
        )
        self.normalization_last_unreachable_obligation_ids = (
            unreachable_obligation_ids
        )

        normalization_order = (
            self.normalization_published_postvalidated_generation or 0,
            self.normalization_validated_generation or 0,
            self.normalization_staged_generation or 0,
            self.portable_evidence_ready_generation or 0,
        )
        if normalization_order != tuple(sorted(normalization_order)):
            raise ValueError("invalid normalization lifecycle generation order")

        semantic_order = (
            self.receipt_committed_generation or 0,
            self.semantic_fragment_published_postvalidated_generation or 0,
            self.semantic_fragment_validated_generation or 0,
            self.semantic_fragment_staged_generation or 0,
            self.canonical_semantic_plan_generation or 0,
            self.normalization_published_postvalidated_generation or 0,
        )
        if semantic_order != tuple(sorted(semantic_order)):
            raise ValueError("invalid semantic lifecycle generation order")

    def _require_current_portable_evidence(self) -> int:
        generation = int(self.evidence_generation)
        if (
            generation <= 0
            or self.portable_evidence_ready_generation != generation
        ):
            raise RuntimeError(
                "lifecycle transition requires the current portable evidence generation"
            )
        return generation

    def _mark_lifecycle_generation(
        self,
        *,
        attribute: str,
        operation: str,
        evidence_family: str,
        prerequisite_attribute: str | None = None,
        prerequisite_error: str = "",
    ) -> bool:
        generation = self._require_current_portable_evidence()
        if (
            prerequisite_attribute is not None
            and getattr(self, prerequisite_attribute) != generation
        ):
            raise RuntimeError(prerequisite_error)
        previous = getattr(self, attribute)
        if previous == generation:
            return False
        setattr(self, attribute, generation)
        self._observe_transition(
            operation=operation,
            previous_generation=0 if previous is None else int(previous),
            evidence_family=evidence_family,
            reason=f"{operation.replace('_', ' ')} for portable generation {generation}",
        )
        return True

    def _fragment_publication_mark_normalization_staged(self) -> bool:
        """Record construction of a detached normalization fragment."""
        return self._mark_lifecycle_generation(
            attribute="normalization_staged_generation",
            operation="normalization_staged",
            evidence_family="frontend_normalization",
        )

    def _fragment_publication_mark_normalization_validated(self) -> bool:
        """Record successful validation of the staged normalization fragment."""
        return self._mark_lifecycle_generation(
            attribute="normalization_validated_generation",
            operation="normalization_validated",
            evidence_family="frontend_normalization",
            prerequisite_attribute="normalization_staged_generation",
            prerequisite_error=(
                "normalization validation requires the current staged generation"
            ),
        )

    def _fragment_publication_mark_normalization_published_and_postvalidated(
        self,
    ) -> bool:
        """Advance normalization authority only after publication postvalidation."""
        return self._mark_lifecycle_generation(
            attribute="normalization_published_postvalidated_generation",
            operation="normalization_published_postvalidated",
            evidence_family="frontend_normalization",
            prerequisite_attribute="normalization_validated_generation",
            prerequisite_error=(
                "normalization publication requires the current validated generation"
            ),
        )

    def _fragment_publication_commit_normalization_work_item(
        self,
        *,
        work_item_id: str,
        selected_obligation_ids: tuple[str, ...],
        remaining_obligation_ids: tuple[str, ...],
        unreachable_obligation_ids: tuple[str, ...],
    ) -> bool:
        """Record one receipted work item without overstating generation authority."""
        generation = self._require_current_portable_evidence()
        if (
            self.normalization_staged_generation != generation
            or self.normalization_validated_generation != generation
        ):
            raise RuntimeError(
                "normalization work-item commit requires current validated staging"
            )
        work_item_id = str(work_item_id).strip()
        selected = tuple(str(value).strip() for value in selected_obligation_ids)
        remaining = tuple(str(value).strip() for value in remaining_obligation_ids)
        unreachable = tuple(
            str(value).strip() for value in unreachable_obligation_ids
        )
        if (
            not work_item_id
            or not selected
            or any(not value for value in (*selected, *remaining, *unreachable))
            or len(set(selected)) != len(selected)
            or len(set(remaining)) != len(remaining)
            or len(set(unreachable)) != len(unreachable)
            or len(set((*selected, *remaining, *unreachable)))
            != len(selected) + len(remaining) + len(unreachable)
        ):
            raise ValueError(
                "normalization work-item commit requires disjoint obligations"
            )
        self.normalization_work_item_publication_revision += 1
        self.normalization_last_published_work_item_id = work_item_id
        self.normalization_last_selected_obligation_ids = selected
        self.normalization_last_remaining_obligation_ids = remaining
        self.normalization_last_unreachable_obligation_ids = unreachable
        if not remaining:
            return self._fragment_publication_mark_normalization_published_and_postvalidated()

        published = self.normalization_published_postvalidated_generation
        self.normalization_staged_generation = published
        self.normalization_validated_generation = published
        self._observe_transition(
            operation="normalization_work_item_published",
            previous_generation=0 if published is None else int(published),
            evidence_family="frontend_normalization",
            reason=(
                f"work item {work_item_id} published with {len(selected)} "
                f"selected, {len(remaining)} remaining, and "
                f"{len(unreachable)} root-unreachable obligations"
            ),
        )
        return False

    def _fragment_publication_abort_normalization(self, *, reason: str) -> bool:
        """Discard current transient normalization state without moving authority."""
        generation = self._require_current_portable_evidence()
        if (
            self.normalization_staged_generation != generation
            and self.normalization_validated_generation != generation
        ):
            return False
        published = self.normalization_published_postvalidated_generation
        self.normalization_staged_generation = published
        self.normalization_validated_generation = published
        self._observe_transition(
            operation="normalization_aborted",
            previous_generation=generation,
            evidence_family="frontend_normalization",
            outcome="aborted",
            reason=str(reason),
        )
        return True

    def needs_normalization_publication(self) -> bool:
        """Return whether current portable evidence lacks normalized authority."""
        return (
            self.normalization_published_postvalidated_generation
            != self.evidence_generation
        )

    def mark_canonical_semantic_plan_ready(self) -> bool:
        """Record a canonical pass plan over the current normalized generation."""
        return self._mark_lifecycle_generation(
            attribute="canonical_semantic_plan_generation",
            operation="canonical_semantic_plan_ready",
            evidence_family="semantic_lowering",
            prerequisite_attribute=(
                "normalization_published_postvalidated_generation"
            ),
            prerequisite_error=(
                "canonical semantic planning requires current normalized authority"
            ),
        )

    def _fragment_publication_mark_semantic_fragment_staged(self) -> bool:
        """Record detached construction of the current canonical semantic plan."""
        return self._mark_lifecycle_generation(
            attribute="semantic_fragment_staged_generation",
            operation="semantic_fragment_staged",
            evidence_family="semantic_lowering",
            prerequisite_attribute="canonical_semantic_plan_generation",
            prerequisite_error=(
                "semantic fragment staging requires the current canonical plan"
            ),
        )

    def _fragment_publication_mark_semantic_fragment_validated(self) -> bool:
        """Record successful validation of the staged semantic fragment."""
        return self._mark_lifecycle_generation(
            attribute="semantic_fragment_validated_generation",
            operation="semantic_fragment_validated",
            evidence_family="semantic_lowering",
            prerequisite_attribute="semantic_fragment_staged_generation",
            prerequisite_error=(
                "semantic fragment validation requires the current staged generation"
            ),
        )

    def _fragment_publication_mark_semantic_fragment_published_and_postvalidated(
        self,
    ) -> bool:
        """Advance semantic authority only after publication postvalidation."""
        return self._mark_lifecycle_generation(
            attribute="semantic_fragment_published_postvalidated_generation",
            operation="semantic_fragment_published_postvalidated",
            evidence_family="semantic_lowering",
            prerequisite_attribute="semantic_fragment_validated_generation",
            prerequisite_error=(
                "semantic fragment publication requires the current validated generation"
            ),
        )

    def _fragment_publication_mark_receipt_committed(self) -> bool:
        """Record the receipt only after semantic publication postvalidation."""
        return self._mark_lifecycle_generation(
            attribute="receipt_committed_generation",
            operation="receipt_committed",
            evidence_family="semantic_lowering",
            prerequisite_attribute=(
                "semantic_fragment_published_postvalidated_generation"
            ),
            prerequisite_error=(
                "receipt commit requires current postvalidated semantic publication"
            ),
        )

    def _fragment_publication_abort_semantic_fragment(self, *, reason: str) -> bool:
        """Discard current transient semantic state without moving authority."""
        generation = self._require_current_portable_evidence()
        if (
            self.semantic_fragment_staged_generation != generation
            and self.semantic_fragment_validated_generation != generation
        ):
            return False
        published = self.semantic_fragment_published_postvalidated_generation
        self.semantic_fragment_staged_generation = published
        self.semantic_fragment_validated_generation = published
        self._observe_transition(
            operation="semantic_fragment_aborted",
            previous_generation=generation,
            evidence_family="semantic_lowering",
            outcome="aborted",
            reason=str(reason),
        )
        return True

    def _observe_transition(
        self,
        *,
        operation: str,
        previous_generation: int,
        evidence_family: str,
        outcome: str = "accepted",
        reason: str = "",
    ) -> None:
        observer = self.event_observer
        if observer is None:
            return
        try:
            observer(
                EvidenceLifecycleTransition(
                    operation=operation,
                    previous_generation=int(previous_generation),
                    resulting_generation=int(self.evidence_generation),
                    evidence_family=evidence_family,
                    outcome=outcome,
                    reason=reason,
                )
            )
        except Exception:
            logger.debug("evidence lifecycle observer failed", exc_info=True)

    def _resolver_evidence_for(
        self,
        key: NativePreanalysisKey,
    ) -> ResolverPortableEvidence:
        evidence = self.resolver_evidence
        if evidence is None:
            evidence = ResolverPortableEvidence(key=key)
            self.resolver_evidence = evidence
            return evidence
        evidence.require_key(key)
        return evidence

    def resolver_evidence_for(
        self,
        key: NativePreanalysisKey,
    ) -> ResolverPortableEvidence:
        """Return the typed resolver aggregate for one exact native identity."""
        return self._resolver_evidence_for(key)

    def frontend_normalization_evidence_for(
        self,
        key: NativePreanalysisKey,
    ) -> FrontendNormalizationEvidence | None:
        """Project the complete native transfer ledger into one generic generation.

        Final state-machine routes are intentionally absent.  This capability
        contains only native computed transfers proved as faithful direct or
        conditional branch shapes.  A detached closure is included only when
        missing destinations must also be made available.
        """
        facts = self.facts
        resolver_evidence = self._resolver_evidence_for(key)
        resolution = resolver_evidence.computed_goto_resolution
        if (
            not isinstance(resolution, ComputedGotoResolution)
            or not resolution.patch_plans
            or int(self.evidence_generation) <= 0
        ):
            return None
        semantic_closure = None
        native_cfg = None
        if facts is not None:
            facts.require_key(key)
            if facts.semantic_closure is not None:
                semantic_closure = facts.semantic_closure
                native_cfg = facts.native_cfg
        atomic_group_id = (
            f"frontend-normalization:g{int(self.evidence_generation)}"
        )
        patch_plans = tuple(
            sorted(
                resolution.patch_plans,
                key=lambda item: int(item.jmp_ea),
            )
        )
        patch_proofs = tuple(
            _patch_plan_frontend_proof(
                key,
                plan,
                atomic_group_id=atomic_group_id,
            )
            for plan in patch_plans
        )
        state_choice_proofs = (
            ()
            if facts is None
            else tuple(
                proof
                for transfer in facts.transfers
                for proof in (
                    _static_state_choice_frontend_proof(
                        key,
                        facts.native_cfg,
                        transfer,
                        atomic_group_id=atomic_group_id,
                    ),
                )
                if proof is not None
            )
        )
        return FrontendNormalizationEvidence(
            native_key=key,
            generation=int(self.evidence_generation),
            atomic_group_id=atomic_group_id,
            transfer_proofs=(*patch_proofs, *state_choice_proofs),
            semantic_closure=semantic_closure,
            native_cfg=native_cfg,
        )

    def canonical_semantic_evidence_for(
        self,
        key: NativePreanalysisKey,
    ) -> CanonicalSemanticEvidence | None:
        """Project postvalidated native state delivery into canonical proofs."""
        resolver_evidence = self._resolver_evidence_for(key)
        generation = int(self.evidence_generation)
        preparation = resolver_evidence.preopt_union_preparation
        entry_consumer_routes = (
            ()
            if preparation is None
            else tuple(dict.fromkeys(preparation.entry_consumer_routes))
        )
        if (
            generation <= 0
            or self.normalization_published_postvalidated_generation != generation
            or (not resolver_evidence.state_write_routes and not entry_consumer_routes)
        ):
            return None

        atomic_group_id = f"canonical-semantic:g{generation}"
        terminal_carriers = resolver_evidence.terminal_return_carriers
        matched_terminal_carriers: set[TerminalReturnCarrierEvidence] = set()
        direct_proofs: list[SemanticRouteProof] = []
        for route in resolver_evidence.state_write_routes:
            matching_terminal_carriers = tuple(
                carrier
                for carrier in terminal_carriers
                if carrier.state_write_ea == int(route.source_write_ea)
                and int(carrier.request.state_var_reg) == int(route.state_var_reg)
                and int(carrier.request.state_constant)
                == (int(route.state_constant) & 0xFFFFFFFF)
                and int(carrier.request.terminal_target_ea) == int(route.target_ea)
                and int(route.source_write_ea)
                in carrier.capture_identity.exact_instruction_eas
                and int(route.source_write_ea)
                in route.write_identity.exact_instruction_eas
                and int(route.target_ea)
                in carrier.terminal_identity.exact_instruction_eas
                and int(route.target_ea) in route.target_identity.exact_instruction_eas
            )
            if len(matching_terminal_carriers) > 1:
                return None
            terminal_carrier = (
                matching_terminal_carriers[0] if matching_terminal_carriers else None
            )
            if terminal_carrier is not None:
                matched_terminal_carriers.add(terminal_carrier)
            proof_kind = (
                SemanticRouteProofKind.TERMINAL_RETURN
                if terminal_carrier is not None
                else SemanticRouteProofKind.STATE_ASSIGNMENT
            )
            direct_proofs.append(
                SemanticRouteProof(
                    proof_id=(
                        f"{proof_kind.value}@0x{int(route.delivery_ea):X}:"
                        f"0x{int(route.state_constant) & 0xFFFFFFFF:X}"
                    ),
                    atomic_group_id=atomic_group_id,
                    proof_kind=proof_kind,
                    shape=SemanticRouteShape.DIRECT,
                    source_identity=route.delivery_identity,
                    source_anchor_ea=int(route.delivery_ea),
                    destinations=(
                        SemanticRouteDestination(
                            role=SemanticEdgeRole.DIRECT,
                            state_constant=int(route.state_constant) & 0xFFFFFFFF,
                            target_identity=route.target_identity,
                            target_anchor_ea=int(route.target_ea),
                            terminal=terminal_carrier is not None,
                        ),
                    ),
                    state_write=SemanticStateWriteProof(
                        identity=route.write_identity,
                        instruction_ea=int(route.source_write_ea),
                        state_variable=StorageIdentity(
                            StorageIdentityKind.REGISTER,
                            int(route.state_var_reg),
                        ),
                        width=4,
                        state_constant=int(route.state_constant) & 0xFFFFFFFF,
                        corridor_instruction_eas=tuple(
                            int(ea) for ea in route.corridor_instruction_eas
                        ),
                    ),
                    terminal_return_carrier=terminal_carrier,
                    diagnostic_provenance=(
                        ("provider_proof_kind", route.proof_kind.value),
                        ("delivery_kind", route.delivery_kind.value),
                    ),
                )
            )
        if matched_terminal_carriers != set(terminal_carriers):
            return None
        conditional_proofs: list[SemanticRouteProof] = []
        if entry_consumer_routes:
            facts = self.facts
            if (
                facts is None
                or preparation is None
                or not preparation.prepared
                or not preparation.published
            ):
                return None
            facts.require_key(key)
            for route in entry_consumer_routes:
                proof = _entry_consumer_semantic_route_proof(
                    key,
                    facts.native_cfg,
                    route,
                    atomic_group_id=atomic_group_id,
                )
                if proof is None:
                    return None
                conditional_proofs.append(proof)
        proofs = (*direct_proofs, *conditional_proofs)
        return CanonicalSemanticEvidence(
            native_key=key,
            generation=generation,
            atomic_group_id=atomic_group_id,
            route_proofs=proofs,
        )

    def _replace_resolver_evidence(
        self,
        key: NativePreanalysisKey,
        *,
        evidence_family: str,
        evidence_reason: str,
        advance_generation: bool = True,
        **changes: object,
    ) -> bool:
        current = self._resolver_evidence_for(key)
        updated = replace(current, **changes)
        if updated == current:
            return False
        self.resolver_evidence = updated
        if advance_generation:
            self.mark_evidence_changed(
                evidence_family=evidence_family,
                reason=evidence_reason,
            )
        return True

    def merge_portable_state_routes(
        self,
        key: NativePreanalysisKey,
        routes: tuple[PortableMaterializedStateRoute, ...],
    ) -> bool:
        """Merge serial-free logical routes into lifecycle-owned evidence."""
        for route in routes:
            for identity in (
                route.source_identity,
                route.target_identity,
                route.source_handler_identity,
                route.source_handler_region_identity,
            ):
                if identity is not None and identity.native_key != key:
                    raise NativePreanalysisKeyMismatch(
                        key,
                        identity.native_key,
                        key.mismatch_fields(identity.native_key),
                    )
        current = self._resolver_evidence_for(key)
        merged = tuple(dict.fromkeys((*current.state_routes, *routes)))
        return self._replace_resolver_evidence(
            key,
            evidence_family="portable_state_routes",
            evidence_reason="portable state-route evidence changed",
            state_routes=merged,
        )

    def merge_state_write_routes(
        self,
        key: NativePreanalysisKey,
        routes: tuple[PortableStateWriteRouteEvidence, ...],
    ) -> bool:
        """Merge native write-to-delivery route authority into the lifecycle."""
        for route in routes:
            for identity in (
                route.write_identity,
                route.delivery_identity,
                route.target_identity,
            ):
                if identity.native_key != key:
                    raise NativePreanalysisKeyMismatch(
                        key,
                        identity.native_key,
                        key.mismatch_fields(identity.native_key),
                    )
        current = self._resolver_evidence_for(key)
        merged = tuple(dict.fromkeys((*current.state_write_routes, *routes)))
        changed = self._replace_resolver_evidence(
            key,
            evidence_family="state_write_routes",
            evidence_reason="native state-write route evidence changed",
            state_write_routes=merged,
        )
        if changed:
            self.state_write_route_inventory_revision += 1
        return changed

    def merge_portable_dispatcher_region_identity(
        self,
        key: NativePreanalysisKey,
        identity: StableBlockIdentity,
    ) -> bool:
        """Merge the portable native region owned by one dispatcher."""
        if identity.native_key != key:
            raise NativePreanalysisKeyMismatch(
                key,
                identity.native_key,
                key.mismatch_fields(identity.native_key),
            )
        current = self._resolver_evidence_for(key)
        previous = current.dispatcher_region_identity
        merged = StableBlockIdentity.from_intervals(
            (
                *(previous.native_ranges.intervals if previous is not None else ()),
                *identity.native_ranges.intervals,
            ),
            native_key=key,
        )
        return self._replace_resolver_evidence(
            key,
            evidence_family="dispatcher_region_identity",
            evidence_reason="portable dispatcher-region identity changed",
            dispatcher_region_identity=merged,
        )

    def merge_terminal_return_carrier_requests(
        self,
        key: NativePreanalysisKey,
        requests: tuple[TerminalReturnCarrierRequest, ...],
    ) -> bool:
        """Merge exact return-carrier requests under lifecycle ownership."""
        current = self._resolver_evidence_for(key)
        merged = tuple(
            dict.fromkeys((*current.terminal_return_carrier_requests, *requests))
        )
        return self._replace_resolver_evidence(
            key,
            evidence_family="terminal_return_carrier_requests",
            evidence_reason="terminal return-carrier evidence changed",
            terminal_return_carrier_requests=merged,
        )

    def merge_terminal_return_carriers(
        self,
        key: NativePreanalysisKey,
        carriers: tuple[TerminalReturnCarrierEvidence, ...],
    ) -> bool:
        """Merge portable terminal ABI carriers without choosing conflicts."""
        if any(
            not isinstance(carrier, TerminalReturnCarrierEvidence)
            for carrier in carriers
        ):
            raise TypeError(
                "resolver terminal return-carrier evidence requires typed carriers"
            )
        for carrier in carriers:
            if carrier.native_key != key:
                raise NativePreanalysisKeyMismatch(
                    key,
                    carrier.native_key,
                    key.mismatch_fields(carrier.native_key),
                )

        def identity(
            carrier: TerminalReturnCarrierEvidence,
        ) -> tuple[int, int, int, int]:
            request = carrier.request
            return (
                int(request.source_handler_ea),
                int(request.terminal_target_ea),
                int(request.state_var_reg),
                int(request.state_constant) & 0xFFFFFFFF,
            )

        current = self._resolver_evidence_for(key)
        by_identity = {
            identity(carrier): carrier for carrier in current.terminal_return_carriers
        }
        for carrier in carriers:
            carrier_identity = identity(carrier)
            previous = by_identity.get(carrier_identity)
            if previous is not None and previous != carrier:
                raise TerminalReturnCarrierEvidenceRejected(
                    "conflicting terminal carrier evidence for one request"
                )
            by_identity[carrier_identity] = carrier
        merged = tuple(by_identity[item] for item in sorted(by_identity))
        return self._replace_resolver_evidence(
            key,
            evidence_family="terminal_return_carriers",
            evidence_reason="portable terminal return-carrier evidence changed",
            terminal_return_carriers=merged,
        )

    def merge_call_abi_proof(
        self,
        key: NativePreanalysisKey,
        *,
        call_ea: int,
        proof: StackCallAbiProof,
    ) -> bool:
        """Install one native-call-EA keyed ABI proof deterministically."""
        if not isinstance(proof, StackCallAbiProof):
            raise TypeError("resolver call ABI evidence requires a typed proof")
        current = self._resolver_evidence_for(key)
        proofs = dict(current.call_abi_proofs)
        proofs[int(call_ea)] = proof
        merged = tuple(sorted(proofs.items()))
        return self._replace_resolver_evidence(
            key,
            evidence_family="call_abi_proofs",
            evidence_reason="call ABI evidence changed",
            advance_generation=False,
            call_abi_proofs=merged,
        )

    def merge_call_result_carriers(
        self,
        key: NativePreanalysisKey,
        carriers: tuple[CallResultCarrier, ...],
    ) -> bool:
        """Retain serial-free call-result facts without requesting a redo."""
        if not all(isinstance(carrier, CallResultCarrier) for carrier in carriers):
            raise TypeError("resolver call-result evidence requires typed carriers")
        current = self._resolver_evidence_for(key)
        merged = tuple(dict.fromkeys((*current.call_result_carriers, *carriers)))
        return self._replace_resolver_evidence(
            key,
            evidence_family="call_result_carriers",
            evidence_reason="call-result carrier evidence changed",
            advance_generation=False,
            call_result_carriers=merged,
        )

    def clear_call_result_carriers(self, key: NativePreanalysisKey) -> bool:
        """Acknowledge call-result facts consumed by a later live maturity."""
        return self._replace_resolver_evidence(
            key,
            evidence_family="call_result_carriers",
            evidence_reason="call-result carrier evidence cleared",
            advance_generation=False,
            call_result_carriers=(),
        )

    def set_computed_goto_resolution(
        self,
        key: NativePreanalysisKey,
        resolution: ComputedGotoResolution,
    ) -> bool:
        """Publish native computed-goto evidence as frontend-ready evidence."""
        if not isinstance(resolution, ComputedGotoResolution):
            raise TypeError("computed-goto resolution must be portable evidence")
        previous = self._resolver_evidence_for(key).computed_goto_resolution
        changes_frontend_authority = bool(
            resolution.patch_plans
            or (
                isinstance(previous, ComputedGotoResolution)
                and previous.patch_plans
            )
        )
        return self._replace_resolver_evidence(
            key,
            evidence_family="computed_goto_resolution",
            evidence_reason="computed-goto resolution changed",
            advance_generation=changes_frontend_authority,
            computed_goto_resolution=resolution,
        )

    def set_preopt_union_preparation(
        self,
        key: NativePreanalysisKey,
        preparation: PreoptUnionPreparationResult | None,
    ) -> bool:
        """Replace the portable PREOPT preparation outcome."""
        if preparation is not None and not isinstance(
            preparation,
            PreoptUnionPreparationResult,
        ):
            raise TypeError("PREOPT union preparation must be portable evidence")
        return self._replace_resolver_evidence(
            key,
            evidence_family="preopt_union_preparation",
            evidence_reason="PREOPT union preparation changed",
            advance_generation=False,
            preopt_union_preparation=preparation,
        )

    def set_prepatch_preopt_union_source(
        self,
        key: NativePreanalysisKey,
        source: PrepatchPreoptUnionSource | None,
    ) -> bool:
        """Replace the serial-free native source used by PREOPT regeneration."""
        if source is not None and not isinstance(source, PrepatchPreoptUnionSource):
            raise TypeError("prepatch PREOPT source must be portable evidence")
        return self._replace_resolver_evidence(
            key,
            evidence_family="prepatch_preopt_union_source",
            evidence_reason="prepatch PREOPT union source changed",
            advance_generation=False,
            prepatch_preopt_union_source=source,
        )

    def merge_preopt_entry_bridge_evidence(
        self,
        key: NativePreanalysisKey,
        evidence: EntryBridgeEvidence,
    ) -> bool:
        """Retain serial-free PREOPT entry choices across regeneration."""
        if not isinstance(evidence, EntryBridgeEvidence):
            raise TypeError("PREOPT entry bridge must be portable evidence")
        current = self._resolver_evidence_for(key)

        def semantic_identity(row: EntryBridgeEvidence) -> tuple[int, ...]:
            return (
                int(row.conditional_tail_ea or row.predicate_ea),
                int(row.source_store_ea),
                int(row.condition_code),
                int(row.taken_state_constant),
                int(row.fallthrough_state_constant),
            )

        if evidence not in current.preopt_entry_bridges and any(
            semantic_identity(row) == semantic_identity(evidence)
            for row in current.preopt_entry_bridges
        ):
            self._observe_transition(
                operation="evidence_coalesced",
                previous_generation=int(self.evidence_generation),
                evidence_family="preopt_entry_bridge",
                reason=(
                    "equivalent stable entry bridge observed after maturity-local "
                    "block splitting"
                ),
            )
            return False
        merged = tuple(
            sorted(
                set((*current.preopt_entry_bridges, evidence)),
                key=lambda row: (
                    int(row.conditional_tail_ea or row.predicate_ea),
                    int(row.source_store_ea),
                    int(row.taken_state_constant),
                    int(row.fallthrough_state_constant),
                ),
            )
        )
        return self._replace_resolver_evidence(
            key,
            evidence_family="preopt_entry_bridge",
            evidence_reason="PREOPT entry-bridge evidence changed",
            preopt_entry_bridges=merged,
        )

    def record_bootstrap_route_binding(
        self,
        key: NativePreanalysisKey,
        binding: BootstrapRouteBindingEvidence,
    ) -> bool:
        """Retain a serial-free PREOPT binding under lifecycle ownership."""
        for identity in (
            binding.route.source_identity,
            binding.route.handler_identity,
            binding.source_identity,
            binding.handler_identity,
        ):
            if identity.native_key != key:
                raise NativePreanalysisKeyMismatch(
                    key,
                    identity.native_key,
                    key.mismatch_fields(identity.native_key),
                )
        route_key = binding.route.key
        if (
            self.bootstrap_routes.get(route_key) != binding.route
            or route_key in self.conflicted_bootstrap_keys
            or self.rebound_bootstrap_generations.get(route_key)
            != int(binding.evidence_generation)
        ):
            return False
        current = self._resolver_evidence_for(key)
        bindings = dict(current.bootstrap_route_bindings)
        if bindings.get(route_key) == binding:
            return False
        bindings[route_key] = binding
        merged = tuple(
            sorted(
                bindings.items(),
                key=lambda item: (
                    int(item[0][1]),
                    item[0][0].native_ranges.diagnostic_label(),
                ),
            )
        )
        return self._replace_resolver_evidence(
            key,
            evidence_family="bootstrap_route_bindings",
            evidence_reason="PREOPT bootstrap-route binding changed",
            advance_generation=False,
            bootstrap_route_bindings=merged,
        )

    def bound_bootstrap_route_bindings(
        self,
        key: NativePreanalysisKey,
    ) -> tuple[BootstrapRouteBindingEvidence, ...]:
        """Return bindings owned by the postvalidated normalization epoch."""
        current = self._resolver_evidence_for(key)
        bound_generation = self.normalization_published_postvalidated_generation
        if bound_generation is None:
            return ()
        bindings = {
            binding
            for route_key, binding in current.bootstrap_route_bindings
            if binding.evidence_generation == bound_generation
            and self.bootstrap_routes.get(route_key) == binding.route
            and route_key not in self.conflicted_bootstrap_keys
        }
        return tuple(
            sorted(
                bindings,
                key=lambda binding: (
                    int(binding.route.source_anchor_ea),
                    int(binding.route.state),
                    int(binding.route.handler_anchor_ea),
                ),
            )
        )

    def merge_native_facts(
        self,
        key: NativePreanalysisKey,
        *,
        native_cfg: NativeCfg | None = None,
        semantic_closure: NativeSemanticClosure | None = None,
        transfers: tuple[MaterializedIndirectTransfer, ...] | None = None,
        boundary_ports: DetachedSnippetBoundaryPorts | None = None,
    ) -> bool:
        """Merge one complete portable view through the lifecycle authority."""
        current = self.facts
        facts = NativePreanalysisFacts(
            key=key,
            native_cfg=(
                native_cfg
                if native_cfg is not None
                else NativeCfg({})
                if current is None
                else current.native_cfg
            ),
            semantic_closure=(
                semantic_closure
                if semantic_closure is not None
                else None
                if current is None
                else current.semantic_closure
            ),
            transfers=(
                transfers
                if transfers is not None
                else ()
                if current is None
                else current.transfers
            ),
            boundary_ports=(
                boundary_ports
                if boundary_ports is not None
                else (
                    DetachedSnippetBoundaryPorts((), ())
                    if current is None
                    else current.boundary_ports
                )
            ),
        )
        return self.merge_facts(key, facts)

    def merge_materialized_transfers(
        self,
        key: NativePreanalysisKey,
        transfers: tuple[MaterializedIndirectTransfer, ...],
    ) -> bool:
        """Merge portable transfers, refreshing compatible predicate snapshots."""
        current = () if self.facts is None else self.facts.transfers
        merged = list(current)
        for transfer in transfers:
            resolver_kind = str(transfer.resolver_kind)
            if is_conditional_handler_bridge_kind(resolver_kind):
                matching_indices = [
                    index
                    for index, existing in enumerate(merged)
                    if is_conditional_handler_bridge_kind(str(existing.resolver_kind))
                    and int(existing.source_jmp_ea) == int(transfer.source_jmp_ea)
                ]
                if (
                    len(matching_indices) == 1
                    and merged[matching_indices[0]] == transfer
                ):
                    continue
                if matching_indices:
                    combined = transfer
                    compatible_indices: list[int] = []
                    for index in matching_indices:
                        candidate = _merge_compatible_conditional_bridge_evidence(
                            merged[index],
                            combined,
                        )
                        if candidate is None:
                            continue
                        combined = candidate
                        compatible_indices.append(index)
                    if not compatible_indices:
                        if transfer not in merged:
                            merged.append(transfer)
                        continue
                    first_index = compatible_indices[0]
                    merged[first_index] = combined
                    for duplicate_index in reversed(compatible_indices[1:]):
                        del merged[duplicate_index]
                    continue
            if transfer not in merged:
                merged.append(transfer)
        normalized = tuple(merged)
        if normalized == current:
            return False
        return self.merge_native_facts(key, transfers=normalized)

    def discover_static_native_bootstrap_route(
        self,
        key: NativePreanalysisKey,
        *,
        source_anchor_ea: int,
        state_constant: int,
        handler_anchor_ea: int,
    ) -> bool:
        """Record exact native bootstrap anchors as serial-free evidence."""
        source_anchor_ea = int(source_anchor_ea)
        handler_anchor_ea = int(handler_anchor_ea)
        if source_anchor_ea <= 0 or handler_anchor_ea <= 0:
            return False
        source_identity = StableBlockIdentity.from_intervals(
            (NativeEaInterval(source_anchor_ea, source_anchor_ea + 1),),
            native_key=key,
        )
        handler_identity = StableBlockIdentity.from_intervals(
            (NativeEaInterval(handler_anchor_ea, handler_anchor_ea + 1),),
            native_key=key,
        )
        return self.merge_bootstrap_route(
            BootstrapRouteEvidence(
                source_identity=source_identity,
                source_anchor_ea=source_anchor_ea,
                state=int(state_constant),
                handler_identity=handler_identity,
                handler_anchor_ea=handler_anchor_ea,
                proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
            )
        )

    def merge_facts(
        self,
        key: NativePreanalysisKey,
        facts: NativePreanalysisFacts,
    ) -> bool:
        """Install changed normalized facts and advance their evidence epoch."""
        facts.require_key(key)
        if self.facts == facts:
            return False
        if self.facts is None:
            transfer_inventory_changed = bool(facts.transfers)
        else:
            transfer_inventory_changed = self.facts.transfers != facts.transfers
        self.facts = facts
        if transfer_inventory_changed:
            self.transfer_inventory_revision += 1
        self.mark_evidence_changed(
            evidence_family="native_facts",
            reason="normalized native facts changed",
        )
        return True

    def mark_evidence_changed(self, *, evidence_family: str, reason: str) -> None:
        """Advance a bound epoch, or coalesce first-pass native evidence.

        Flowchart discovery can establish several mutually-dependent native
        facts before the first PREOPT MBA exists.  They all describe the same
        requested rebuild and therefore share generation one.  Once PREOPT has
        bound that generation, a later fact is a real new epoch and may request
        its own controlled redo.
        """
        previous_generation = int(self.evidence_generation)
        if (
            self.normalization_published_postvalidated_generation is None
            and self.evidence_generation > 0
        ):
            self.portable_evidence_ready_generation = self.evidence_generation
            self._observe_transition(
                operation="evidence_coalesced",
                previous_generation=previous_generation,
                evidence_family=evidence_family,
                reason=(
                    f"{reason}; first-pass evidence shares the pending PREOPT generation"
                ),
            )
            return
        restart_pending = self.pending_generated_restart_generation is not None
        self.evidence_generation += 1
        self.portable_evidence_ready_generation = self.evidence_generation
        self.redo_generation = None
        self.pending_generated_restart_generation = (
            self.evidence_generation if restart_pending else None
        )
        self._observe_transition(
            operation="evidence_changed",
            previous_generation=previous_generation,
            evidence_family=evidence_family,
            reason=reason,
        )

    def merge_bootstrap_route(self, evidence: BootstrapRouteEvidence) -> bool:
        """Merge only changed portable evidence and invalidate PREOPT binding."""
        key = evidence.key
        current = self.bootstrap_routes.get(key)
        if current == evidence:
            return False
        if (
            current is not None
            and current.proof_kind is BootstrapRouteProofKind.STATIC_NATIVE
        ):
            if evidence.proof_kind is not BootstrapRouteProofKind.STATIC_NATIVE:
                return False
        if current is not None and current != evidence:
            self.conflicted_bootstrap_keys.add(key)
            self.bootstrap_routes.pop(key, None)
            self.rebound_bootstrap_keys.discard(key)
            self.rebound_bootstrap_generations.pop(key, None)
            self.published_bootstrap_keys.discard(key)
        else:
            self.bootstrap_routes[key] = evidence
        self.mark_evidence_changed(
            evidence_family="bootstrap_routes",
            reason="portable bootstrap-route evidence changed",
        )
        return True

    def mark_bootstrap_route_rebound(self, evidence: BootstrapRouteEvidence) -> bool:
        """Record that a unique PREOPT binding consumed this exact route."""
        key = evidence.key
        if (
            self.bootstrap_routes.get(key) != evidence
            or key in self.conflicted_bootstrap_keys
            or self.rebound_bootstrap_generations.get(key) == self.evidence_generation
        ):
            return False
        self.rebound_bootstrap_keys.add(key)
        self.rebound_bootstrap_generations[key] = self.evidence_generation
        # Publication is generation-scoped even though the portable route key
        # is stable across rebuilds.
        self.published_bootstrap_keys.discard(key)
        return True

    def pending_rebound_bootstrap_routes(
        self,
    ) -> tuple[BootstrapRouteEvidence, ...]:
        """Return rebound routes that still need snapshot-bound diagnostics."""
        pending: list[BootstrapRouteEvidence] = []
        for key in sorted(
            self.rebound_bootstrap_keys - self.published_bootstrap_keys,
            key=lambda item: (
                int(item[1]),
                item[0].native_ranges.diagnostic_label(),
            ),
        ):
            evidence = self.bootstrap_routes.get(key)
            if evidence is None or key in self.conflicted_bootstrap_keys:
                continue
            pending.append(evidence)
        return tuple(pending)

    def mark_rebound_bootstrap_routes_published(
        self,
        routes: tuple[BootstrapRouteEvidence, ...],
    ) -> None:
        """Acknowledge only routes whose snapshot event was emitted."""
        for route in routes:
            key = route.key
            if (
                self.bootstrap_routes.get(key) == route
                and key in self.rebound_bootstrap_keys
                and key not in self.conflicted_bootstrap_keys
            ):
                self.published_bootstrap_keys.add(key)

    def pending_materialized_transfers_for_publication(
        self,
    ) -> tuple[MaterializedIndirectTransfer, ...]:
        """Return the current complete inventory once per evidence generation."""
        if (
            self.published_transfer_inventory_revision
            == self.transfer_inventory_revision
            or self.facts is None
            or not self.facts.transfers
        ):
            return ()
        return self.facts.transfers

    def mark_materialized_transfers_published(
        self,
        transfers: tuple[MaterializedIndirectTransfer, ...],
    ) -> None:
        """Acknowledge only an event containing the exact current inventory."""
        if self.facts is not None and transfers == self.facts.transfers:
            self.published_transfer_inventory_revision = (
                self.transfer_inventory_revision
            )

    def pending_state_write_routes_for_publication(
        self,
    ) -> tuple[PortableStateWriteRouteEvidence, ...]:
        """Return the current portable route inventory once per revision."""
        current = self.resolver_evidence
        if (
            self.published_state_write_route_inventory_revision
            == self.state_write_route_inventory_revision
            or current is None
            or not current.state_write_routes
        ):
            return ()
        return current.state_write_routes

    def mark_state_write_routes_published(
        self,
        routes: tuple[PortableStateWriteRouteEvidence, ...],
    ) -> None:
        """Acknowledge only an event containing the exact current inventory."""
        current = self.resolver_evidence
        if current is not None and routes == current.state_write_routes:
            self.published_state_write_route_inventory_revision = (
                self.state_write_route_inventory_revision
            )

    def needs_state_write_route_binding(self) -> bool:
        """Return whether this evidence generation still needs live routing."""
        current = self.resolver_evidence
        return bool(
            current is not None
            and current.state_write_routes
            and self.bound_state_write_route_generation != self.evidence_generation
        )

    def mark_state_write_routes_bound(self) -> None:
        """Acknowledge complete live binding for the current evidence epoch."""
        if (
            self.resolver_evidence is not None
            and self.resolver_evidence.state_write_routes
        ):
            self.bound_state_write_route_generation = self.evidence_generation

    def request_controlled_redo(self) -> bool:
        """Allow exactly one redo request for a changed evidence generation."""
        if self.redo_generation == self.evidence_generation:
            return False
        self.redo_generation = self.evidence_generation
        return True

    @property
    def has_pending_generated_restart(self) -> bool:
        """Whether CALLS staged a controller-owned generated-MBA restart."""
        return self.pending_generated_restart_generation == self.evidence_generation

    def request_generated_restart(self) -> bool:
        """Stage one CALLS-discovered restart for a later flowchart callback.

        ``hxe_calls_done`` has no documented microcode-error return contract.
        The owning decompile controller must initiate a follow-up pass; its
        flowchart callback then consumes this request and returns ``MERR_REDO``.
        """
        generation = int(self.evidence_generation)
        if not self.request_controlled_redo():
            self._observe_transition(
                operation="generated_restart_requested",
                previous_generation=generation,
                evidence_family="controller_restart",
                outcome="declined",
                reason="evidence generation already owns a controlled redo",
            )
            return False
        self.pending_generated_restart_generation = self.evidence_generation
        self._observe_transition(
            operation="generated_restart_requested",
            previous_generation=generation,
            evidence_family="controller_restart",
            reason="CALLS staged a controller-owned generated-MBA restart",
        )
        return True

    def consume_generated_restart(self) -> bool:
        """Consume the current generation's staged flowchart restart once."""
        if not self.has_pending_generated_restart:
            return False
        generation = int(self.evidence_generation)
        self.pending_generated_restart_generation = None
        self._observe_transition(
            operation="generated_restart_consumed",
            previous_generation=generation,
            evidence_family="controller_restart",
            reason="flowchart consumed the staged generated-MBA restart",
        )
        return True

    def needs_bootstrap_route_binding(self) -> bool:
        """Whether a current portable route still lacks a live PREOPT bind."""
        return any(
            key not in self.conflicted_bootstrap_keys
            and self.rebound_bootstrap_generations.get(key) != self.evidence_generation
            for key in self.bootstrap_routes
        )


@runtime_checkable
class ResolverEvidenceAttachment(Protocol):
    """Lower-layer view of a resolver attachment bound to lifecycle evidence."""

    native_preanalysis: NativePreanalysisSessionState
    native_key: NativePreanalysisKey
    indirect_label_materialized: bool
    indirect_dispatcher_materialized: bool

    def invalidate_current_mba_binding(self) -> None:
        """Drop the attachment's generation-local live lookup."""

    def release_live_bindings(self) -> None:
        """Drop all callback-local state at top-level session completion."""


@runtime_checkable
class ResolverSessionOwner(Protocol):
    """Typed lifecycle context capable of owning one resolver attachment."""

    native_preanalysis: NativePreanalysisSessionState
    native_key: NativePreanalysisKey
    resolver_attachment: ResolverEvidenceAttachment | None


@runtime_checkable
class ResolverLifecycleSession(ResolverSessionOwner, Protocol):
    """Known lifecycle session fields consumed by lower-layer callbacks."""

    native_preanalysis_depth: int

    @property
    def identity_key(self) -> str:
        """Return the durable live-binding owner identifier."""


def attached_resolver_session_state(
    session: object,
) -> ResolverEvidenceAttachment | None:
    """Return the existing named resolver attachment without reflection."""
    if not isinstance(session, ResolverSessionOwner):
        raise TypeError("resolver attachment requires a typed lifecycle owner")
    attachment = session.resolver_attachment
    if attachment is not None and not isinstance(
        attachment,
        ResolverEvidenceAttachment,
    ):
        raise TypeError("lifecycle resolver attachment is not a typed port")
    return attachment


__all__ = [
    "BootstrapRouteBindingEvidence",
    "BootstrapRouteEvidence",
    "BootstrapRouteProofKind",
    "CallResultCarrier",
    "ComputedGotoPatchPlan",
    "ComputedGotoResolution",
    "NativePreanalysisFacts",
    "NativePreanalysisSessionState",
    "PreoptUnionPreparationResult",
    "PrepatchPreoptUnionSource",
    "ResolverEvidenceAttachment",
    "ResolverPortableEvidence",
    "ResolverLifecycleSession",
    "ResolverSessionOwner",
    "attached_resolver_session_state",
]
