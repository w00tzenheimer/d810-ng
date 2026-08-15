"""Manager-owned collection and lifecycle for one Stage C pipeline run."""

from __future__ import annotations

from d810.core.execution_journal import DecompilationSessionId
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.flowgraph import FlowGraph
from d810.ir.maturity import IRMaturity
from d810.transforms.native_cfg_normalization import (
    FrozenNativeCfgTopology,
    NativeCfgFreezeReason,
    NativeCfgPassMutationObservation,
    NativeCfgTopologyFreezeOutcome,
    freeze_native_cfg_topology as _freeze_native_cfg_topology,
)

__all__ = ["NativeCfgNormalizationCollector"]


class NativeCfgNormalizationCollector:
    """One exact-function, exact-key, exact-session Stage C observation owner."""

    def __init__(
        self,
        *,
        function_ea: int,
        native_key: NativePreanalysisKey,
        session_id: DecompilationSessionId,
    ) -> None:
        if not isinstance(function_ea, int) or isinstance(function_ea, bool):
            raise TypeError("function_ea must be an int")
        if not isinstance(native_key, NativePreanalysisKey):
            raise TypeError("native_key must be a NativePreanalysisKey")
        if not isinstance(session_id, DecompilationSessionId):
            raise TypeError("session_id must be a DecompilationSessionId")
        self.function_ea = function_ea
        self.native_key = native_key
        self.session_id = session_id
        self._observations: list[NativeCfgPassMutationObservation] = []
        self._outcome: NativeCfgTopologyFreezeOutcome | None = None
        self._scheduled_pass_ids: tuple[str, ...] = ()
        self._frozen = False
        self._transferred = False
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def observation_count(self) -> int:
        return len(self._observations)

    @property
    def scheduled_pass_ids(self) -> tuple[str, ...]:
        return self._scheduled_pass_ids

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("native CFG collector is closed")

    def observe_native_cfg_mutation(
        self,
        observation: NativeCfgPassMutationObservation,
    ) -> None:
        self._require_open()
        if self._frozen:
            raise RuntimeError("native CFG collector is already frozen")
        if not isinstance(observation, NativeCfgPassMutationObservation):
            raise TypeError("observation must be a NativeCfgPassMutationObservation")
        if (
            observation.pre_graph.func_ea != self.function_ea
            or observation.post_graph.func_ea != self.function_ea
        ):
            raise ValueError("native CFG observation function mismatch")
        self._observations.append(observation)

    def freeze_native_cfg_topology(
        self,
        *,
        function_ea: int,
        maturity: IRMaturity,
        baseline_graph: FlowGraph,
        final_graph: FlowGraph,
        scheduled_pass_ids: tuple[str, ...],
    ) -> FrozenNativeCfgTopology | None:
        self._require_open()
        if self._frozen:
            raise RuntimeError("native CFG collector is already frozen")
        if not isinstance(scheduled_pass_ids, tuple) or not all(
            isinstance(pass_id, str) and pass_id.strip()
            for pass_id in scheduled_pass_ids
        ):
            raise TypeError("scheduled_pass_ids must contain non-empty strings")
        self._frozen = True
        self._scheduled_pass_ids = scheduled_pass_ids
        if function_ea != self.function_ea:
            self._outcome = NativeCfgTopologyFreezeOutcome(
                reason=NativeCfgFreezeReason.FUNCTION_MISMATCH
            )
            return None
        self._outcome = _freeze_native_cfg_topology(
            function_ea=function_ea,
            maturity=maturity,
            baseline_graph=baseline_graph,
            final_graph=final_graph,
            observations=tuple(self._observations),
        )
        return self._outcome.topology

    def take_topology_outcome(self) -> NativeCfgTopologyFreezeOutcome:
        self._require_open()
        if self._transferred:
            raise RuntimeError("native CFG topology outcome was already transferred")
        self._transferred = True
        if self._outcome is None:
            self._outcome = NativeCfgTopologyFreezeOutcome(
                reason=NativeCfgFreezeReason.MISSING_PIPELINE_FREEZE
            )
        return self._outcome

    def close(self) -> None:
        if self._closed:
            return
        self._observations.clear()
        self._closed = True
