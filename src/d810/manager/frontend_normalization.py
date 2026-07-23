"""Manager-owned orchestration for receipt-backed frontend normalization."""

from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.frontend_normalization import (
    FrontendNormalizationEvidence,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.capabilities.frontend_normalization import (
    FrontendNormalizationEvidenceCapability,
)
from d810.capabilities.resolver import CapabilitySet
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.flowgraph import FlowGraph
from d810.ir.maturity import IRMaturity
from d810.passes.frontend_normalization import (
    standard_frontend_normalization_passes,
)
from d810.passes.function_pass_manager import FunctionPassManager


class FrontendNormalizationPublicationError(RuntimeError):
    """A backend changed or partially staged CFG authority without a receipt."""


@dataclass(frozen=True, slots=True)
class SessionFrontendNormalizationEvidenceProvider:
    """Expose one session's portable native transfer evidence to generic passes."""

    function_ea: int
    native_key: NativePreanalysisKey
    state: NativePreanalysisSessionState

    def __post_init__(self) -> None:
        if int(self.function_ea) < 0:
            raise ValueError("frontend normalization function EA must be non-negative")
        if not isinstance(self.native_key, NativePreanalysisKey):
            raise TypeError("frontend normalization requires a native key")
        if not isinstance(self.state, NativePreanalysisSessionState):
            raise TypeError("frontend normalization requires session evidence state")
        object.__setattr__(self, "function_ea", int(self.function_ea))

    def evidence_for(
        self,
        function_ea: int,
    ) -> FrontendNormalizationEvidence | None:
        if int(function_ea) != self.function_ea:
            return None
        return self.state.frontend_normalization_evidence_for(self.native_key)


@dataclass(frozen=True, slots=True)
class FrontendNormalizationRunResult:
    """Observable result of one manager-owned normalization generation."""

    graph: FlowGraph
    microcode_modified: bool
    published_generation: int | None
    published_work_item_id: str | None = None
    remaining_obligation_count: int = 0


@dataclass(frozen=True, slots=True)
class _FixedEvidenceProvider:
    evidence: FrontendNormalizationEvidence

    def evidence_for(
        self,
        function_ea: int,
    ) -> FrontendNormalizationEvidence:
        return self.evidence


def _validate_current_evidence(
    evidence: object,
    *,
    native_key: NativePreanalysisKey,
    generation: int,
) -> FrontendNormalizationEvidence:
    if not isinstance(evidence, FrontendNormalizationEvidence):
        raise TypeError(
            "frontend normalization provider returned non-portable evidence"
        )
    if evidence.native_key != native_key:
        raise FrontendNormalizationPublicationError(
            "frontend normalization evidence belongs to another native identity"
        )
    if int(evidence.generation) != int(generation):
        raise FrontendNormalizationPublicationError(
            "frontend normalization evidence generation is not current"
        )
    return evidence


def run_frontend_normalization_pipeline(
    *,
    source: object,
    backend: object,
    evidence_provider: FrontendNormalizationEvidenceCapability,
    lifecycle_state: NativePreanalysisSessionState,
    native_key: NativePreanalysisKey,
    project_config: object | None = None,
    pass_manager: FunctionPassManager | None = None,
) -> FrontendNormalizationRunResult:
    """Run the generic PREOPT tier and accept only receipt-backed publication."""
    if not isinstance(lifecycle_state, NativePreanalysisSessionState):
        raise TypeError("frontend normalization requires session lifecycle state")
    if not isinstance(native_key, NativePreanalysisKey):
        raise TypeError("frontend normalization requires a native key")
    graph = getattr(source, "flow_graph", None)
    if not isinstance(graph, FlowGraph):
        raise TypeError("frontend normalization source requires a portable FlowGraph")
    function_ea = int(getattr(source, "func_ea"))
    if int(graph.func_ea) != function_ea:
        raise FrontendNormalizationPublicationError(
            "frontend normalization source function identity drifted"
        )

    generation = int(lifecycle_state.evidence_generation)
    before_published = lifecycle_state.normalization_published_postvalidated_generation
    before_work_item_revision = (
        lifecycle_state.normalization_work_item_publication_revision
    )
    if before_published == generation:
        return FrontendNormalizationRunResult(
            graph=graph,
            microcode_modified=False,
            published_generation=generation,
        )

    evidence = evidence_provider.evidence_for(function_ea)
    if evidence is None:
        return FrontendNormalizationRunResult(
            graph=graph,
            microcode_modified=False,
            published_generation=before_published,
        )
    current_evidence = _validate_current_evidence(
        evidence,
        native_key=native_key,
        generation=generation,
    )

    manager = pass_manager if pass_manager is not None else FunctionPassManager()
    manager.reset_func(function_ea)
    final_graph = manager.run(
        source=source,
        family=None,
        backend=backend,
        project_config=project_config,
        maturity=IRMaturity.CANONICAL,
        capabilities=CapabilitySet().with_capability(
            FrontendNormalizationEvidenceCapability,
            _FixedEvidenceProvider(current_evidence),
        ),
        pipeline_v2_specs=standard_frontend_normalization_passes(),
    )
    if not isinstance(final_graph, FlowGraph):
        raise TypeError("frontend normalization backend returned a non-portable graph")

    after_published = lifecycle_state.normalization_published_postvalidated_generation
    after_work_item_revision = (
        lifecycle_state.normalization_work_item_publication_revision
    )
    work_item_published = (
        after_work_item_revision == before_work_item_revision + 1
    )
    if after_work_item_revision not in {
        before_work_item_revision,
        before_work_item_revision + 1,
    }:
        raise FrontendNormalizationPublicationError(
            "frontend normalization published multiple work items in one pass"
        )
    if after_published == generation:
        return FrontendNormalizationRunResult(
            graph=final_graph,
            microcode_modified=True,
            published_generation=generation,
            published_work_item_id=(
                lifecycle_state.normalization_last_published_work_item_id
                if work_item_published
                else None
            ),
        )
    if work_item_published:
        remaining = (
            lifecycle_state.normalization_last_remaining_obligation_ids
        )
        if not remaining:
            raise FrontendNormalizationPublicationError(
                "partial normalization receipt lacks remaining obligations"
            )
        return FrontendNormalizationRunResult(
            graph=final_graph,
            microcode_modified=True,
            published_generation=after_published,
            published_work_item_id=(
                lifecycle_state.normalization_last_published_work_item_id
            ),
            remaining_obligation_count=len(remaining),
        )

    graph_changed = final_graph != graph
    partial_current_publication = (
        lifecycle_state.normalization_staged_generation == generation
        or lifecycle_state.normalization_validated_generation == generation
    )
    if graph_changed or partial_current_publication:
        raise FrontendNormalizationPublicationError(
            "frontend normalization backend changed or staged the live graph "
            "without a current receipt-backed normalization publication"
        )
    return FrontendNormalizationRunResult(
        graph=graph,
        microcode_modified=False,
        published_generation=after_published,
    )


__all__ = [
    "FrontendNormalizationPublicationError",
    "FrontendNormalizationRunResult",
    "SessionFrontendNormalizationEvidenceProvider",
    "run_frontend_normalization_pipeline",
]
