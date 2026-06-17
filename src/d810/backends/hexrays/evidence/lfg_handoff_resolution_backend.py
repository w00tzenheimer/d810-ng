"""LFG residual-handoff resolution backend boundary."""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import AbstractSet, Protocol
from d810.analyses.control_flow.residual_handoff_discovery import (
    resolve_assignment_map_handoff_target,
    resolve_immediate_handoff_target,
    resolve_projected_path_tail_target,
    resolve_projected_snapshot_handoff_target,
)
from d810.backends.hexrays.evidence.residual_handoff_resolution import (
    resolve_effective_target_entry,
    resolve_synthesized_handoff_target,
)


@dataclass(frozen=True, slots=True)
class EffectiveTargetEntryRequest:
    dag: object
    edge: object
    condition_chain_blocks: AbstractSet[int]
    state_var_stkoff: int | None
    dispatcher_lookup: object | None
    dispatcher: object | None
    mba: object


@dataclass(frozen=True, slots=True)
class EffectiveTargetEntryResponse:
    target_entry: int | None


@dataclass(frozen=True, slots=True)
class SynthesizedHandoffTargetRequest:
    dag: object
    mba: object
    block_serial: int
    state_var_stkoff: int | None
    condition_chain_blocks: AbstractSet[int]
    dispatcher: object | None
    via_pred: int | None = None


@dataclass(frozen=True, slots=True)
class ProjectedPathTailTargetRequest:
    dag: object
    source_block: int
    condition_chain_blocks: AbstractSet[int]
    dispatcher: object | None = None
    predecessor_hints: tuple[int, ...] | None = None
    require_predecessor_match: bool = False


@dataclass(frozen=True, slots=True)
class ImmediateHandoffTargetRequest:
    dag: object
    mba: object
    block_serial: int
    state_var_stkoff: int | None
    condition_chain_blocks: AbstractSet[int]
    dispatcher_lookup: object | None
    dispatcher: object | None = None


@dataclass(frozen=True, slots=True)
class ProjectedSnapshotHandoffTargetRequest:
    dag: object
    flow_graph: object
    block_serial: int
    state_var_stkoff: int | None
    condition_chain_blocks: AbstractSet[int]
    dispatcher: object | None


@dataclass(frozen=True, slots=True)
class AssignmentMapHandoffTargetRequest:
    dag: object
    state_machine: object | None
    block_serial: int
    condition_chain_blocks: AbstractSet[int]
    dispatcher: object | None


@dataclass(frozen=True, slots=True)
class HandoffTargetResponse:
    target: tuple[int, int] | None


@dataclass(frozen=True, slots=True)
class ProjectedPathTailTargetResponse:
    target: tuple[int | None, int] | None


class LinearizedFlowGraphHandoffResolutionBackend(Protocol):
    """Backend boundary for LFG residual-handoff target callbacks."""

    def resolve_effective_target_entry(
        self,
        request: EffectiveTargetEntryRequest,
    ) -> EffectiveTargetEntryResponse:
        """Resolve the effective target entry for a DAG edge."""

    def resolve_synthesized_handoff_target(
        self,
        request: SynthesizedHandoffTargetRequest,
    ) -> HandoffTargetResponse:
        """Resolve a synthesized handoff target."""

    def resolve_projected_path_tail_target(
        self,
        request: ProjectedPathTailTargetRequest,
    ) -> ProjectedPathTailTargetResponse:
        """Resolve a projected path-tail handoff target."""

    def resolve_immediate_handoff_target(
        self,
        request: ImmediateHandoffTargetRequest,
    ) -> HandoffTargetResponse:
        """Resolve an immediate handoff target."""

    def resolve_projected_snapshot_handoff_target(
        self,
        request: ProjectedSnapshotHandoffTargetRequest,
    ) -> HandoffTargetResponse:
        """Resolve a projected snapshot handoff target."""

    def resolve_assignment_map_handoff_target(
        self,
        request: AssignmentMapHandoffTargetRequest,
    ) -> HandoffTargetResponse:
        """Resolve a handoff target from state-machine assignment evidence."""


class HodurLinearizedFlowGraphHandoffResolutionBackend:
    """Default LFG handoff-resolution backend."""

    def resolve_effective_target_entry(
        self,
        request: EffectiveTargetEntryRequest,
    ) -> EffectiveTargetEntryResponse:
        return EffectiveTargetEntryResponse(
            target_entry=resolve_effective_target_entry(
                request.dag,
                request.edge,
                condition_chain_blocks=set(int(block) for block in request.condition_chain_blocks),
                state_var_stkoff=request.state_var_stkoff,
                dispatcher_lookup=request.dispatcher_lookup,
                dispatcher=request.dispatcher,
                mba=request.mba,
            )
        )

    def resolve_synthesized_handoff_target(
        self,
        request: SynthesizedHandoffTargetRequest,
    ) -> HandoffTargetResponse:
        return HandoffTargetResponse(
            target=resolve_synthesized_handoff_target(
                request.dag,
                request.mba,
                int(request.block_serial),
                state_var_stkoff=request.state_var_stkoff,
                condition_chain_blocks=set(int(block) for block in request.condition_chain_blocks),
                dispatcher=request.dispatcher,
                via_pred=request.via_pred,
            )
        )

    def resolve_projected_path_tail_target(
        self,
        request: ProjectedPathTailTargetRequest,
    ) -> ProjectedPathTailTargetResponse:
        return ProjectedPathTailTargetResponse(
            target=resolve_projected_path_tail_target(
                request.dag,
                source_block=int(request.source_block),
                condition_chain_blocks=set(int(block) for block in request.condition_chain_blocks),
                dispatcher=request.dispatcher,
                predecessor_hints=request.predecessor_hints,
                require_predecessor_match=bool(request.require_predecessor_match),
            )
        )

    def resolve_immediate_handoff_target(
        self,
        request: ImmediateHandoffTargetRequest,
    ) -> HandoffTargetResponse:
        return HandoffTargetResponse(
            target=resolve_immediate_handoff_target(
                request.dag,
                request.mba,
                int(request.block_serial),
                state_var_stkoff=request.state_var_stkoff,
                condition_chain_blocks=set(int(block) for block in request.condition_chain_blocks),
                dispatcher_lookup=request.dispatcher_lookup,
                dispatcher=request.dispatcher,
            )
        )

    def resolve_projected_snapshot_handoff_target(
        self,
        request: ProjectedSnapshotHandoffTargetRequest,
    ) -> HandoffTargetResponse:
        return HandoffTargetResponse(
            target=resolve_projected_snapshot_handoff_target(
                request.dag,
                request.flow_graph,
                int(request.block_serial),
                state_var_stkoff=request.state_var_stkoff,
                condition_chain_blocks=set(int(block) for block in request.condition_chain_blocks),
                dispatcher=request.dispatcher,
            )
        )

    def resolve_assignment_map_handoff_target(
        self,
        request: AssignmentMapHandoffTargetRequest,
    ) -> HandoffTargetResponse:
        return HandoffTargetResponse(
            target=resolve_assignment_map_handoff_target(
                request.dag,
                request.state_machine,
                int(request.block_serial),
                condition_chain_blocks=set(int(block) for block in request.condition_chain_blocks),
                dispatcher=request.dispatcher,
            )
        )


DEFAULT_HODUR_LFG_HANDOFF_RESOLUTION_BACKEND: LinearizedFlowGraphHandoffResolutionBackend = (
    HodurLinearizedFlowGraphHandoffResolutionBackend()
)


__all__ = [
    "AssignmentMapHandoffTargetRequest",
    "DEFAULT_HODUR_LFG_HANDOFF_RESOLUTION_BACKEND",
    "EffectiveTargetEntryRequest",
    "EffectiveTargetEntryResponse",
    "HandoffTargetResponse",
    "HodurLinearizedFlowGraphHandoffResolutionBackend",
    "ImmediateHandoffTargetRequest",
    "LinearizedFlowGraphHandoffResolutionBackend",
    "ProjectedPathTailTargetRequest",
    "ProjectedPathTailTargetResponse",
    "ProjectedSnapshotHandoffTargetRequest",
    "SynthesizedHandoffTargetRequest",
]
