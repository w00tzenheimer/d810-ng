"""Ports used to observe and prove pass-owned native CFG normalization."""

from __future__ import annotations

from d810.core.typing import TYPE_CHECKING, Protocol, runtime_checkable
from d810.ir.edge_state_contract import EdgeStateContract
from d810.ir.flowgraph import FlowGraph
from d810.ir.maturity import IRMaturity

if TYPE_CHECKING:
    from d810.transforms.native_cfg_normalization import (
        FrozenNativeCfgTopology,
        NativeCfgPassMutationObservation,
    )

__all__ = ["NativeCfgFreezeObserver", "NativeEdgeStateProofCapability"]


@runtime_checkable
class NativeEdgeStateProofCapability(Protocol):
    """Prove that one pass-owned CFG edge rewrite preserves machine state."""

    def prove_edge_transition(
        self,
        *,
        graph: FlowGraph,
        source_block: int,
        inherited_successors: tuple[int, ...],
        final_successors: tuple[int, ...],
        semantic_proof_ids: tuple[str, ...],
    ) -> EdgeStateContract | None: ...


@runtime_checkable
class NativeCfgFreezeObserver(Protocol):
    """Collect eligible pass mutations and freeze one end-of-pipeline topology."""

    def observe_native_cfg_mutation(
        self,
        observation: NativeCfgPassMutationObservation,
    ) -> None: ...

    def freeze_native_cfg_topology(
        self,
        *,
        function_ea: int,
        maturity: IRMaturity,
        baseline_graph: FlowGraph,
        final_graph: FlowGraph,
        scheduled_pass_ids: tuple[str, ...],
    ) -> FrozenNativeCfgTopology | None: ...
