"""FLOWGRAPH_READY event subscriber for portable recon/fact collection."""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.core.provider_phase import ProviderPhaseSnapshot
from d810.core.typing import Any

logger = getLogger("D810.recon.flowgraph_ready")


@dataclass(eq=False, slots=True)
class FlowGraphReadySubscriber:
    """Dispatch portable ``FLOWGRAPH_READY`` payloads into recon runtimes."""

    recon_phase: Any | None
    recon_runtime: Any | None
    provider_name: str

    def __call__(
        self,
        *,
        flow_graph: Any,
        func_ea: int,
        maturity: int,
        maturity_name: str,
        producer: str | None = None,
        producer_stage_id: int | None = None,
        producer_stage_name: str | None = None,
        snapshot_stage: Any = None,
        snapshot: Any = None,
    ) -> None:
        """Run recon collectors and pre-D810 fact capture for one flow graph.

        ``producer`` / stage fields are part of the event payload contract even
        though this subscriber currently only needs the provider phase aliases.
        Keeping them on the callable signature preserves the explicit event
        shape and catches unexpected positional use.
        """
        del producer, producer_stage_id, producer_stage_name, snapshot_stage
        if self.recon_phase is None and self.recon_runtime is None:
            return
        provider_phase = ProviderPhaseSnapshot(
            provider_name=self.provider_name,
            provider_level=int(maturity),
            friendly_provider_level=str(maturity_name),
        )
        if self.recon_phase is not None:
            try:
                self.recon_phase.run_microcode_collectors(
                    flow_graph,
                    func_ea=int(func_ea),
                    provider_phase=provider_phase,
                )
            except Exception:
                logger.exception(
                    "ReconPhase FLOWGRAPH_READY collection failed at "
                    "func=0x%x maturity=%s",
                    int(func_ea),
                    maturity_name,
                )
        if self.recon_runtime is not None:
            try:
                self.recon_runtime.capture_maturity_facts(
                    flow_graph,
                    func_ea=int(func_ea),
                    provider_phase=provider_phase,
                    phase="pre_d810",
                    snapshot=snapshot,
                )
            except Exception:
                logger.exception(
                    "FactLifecycleRuntime FLOWGRAPH_READY capture failed at "
                    "func=0x%x maturity=%s",
                    int(func_ea),
                    maturity_name,
                )
