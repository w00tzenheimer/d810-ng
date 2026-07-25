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
from d810.core.fragment_authority import NormalizationWorkItemAuthority
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.flowgraph import FlowGraph
from d810.ir.maturity import IRMaturity
from d810.passes.frontend_normalization import (
    FRONTEND_NORMALIZATION_PLAN_INTENT,
    standard_frontend_normalization_passes,
)
from d810.passes.function_pass_manager import FunctionPassManager
from d810.transforms.fragment_plan import (
    FragmentPlan,
    FragmentPublicationPurpose,
)


class FrontendNormalizationPublicationError(RuntimeError):
    """A backend changed or partially staged CFG authority without a receipt."""


@dataclass(slots=True)
class SessionFrontendNormalizationPlanAuthority:
    """Manager-owned, generation-keyed PREOPT plan intent."""

    function_ea: int
    native_key: NativePreanalysisKey
    _plan: FragmentPlan | None = None
    _authority: NormalizationWorkItemAuthority | None = None
    _evidence_generation: int | None = None

    def __post_init__(self) -> None:
        function_ea = int(self.function_ea)
        if function_ea < 0:
            raise ValueError(
                "frontend normalization plan function EA must be non-negative"
            )
        if not isinstance(self.native_key, NativePreanalysisKey):
            raise TypeError("frontend normalization plan requires a native key")
        object.__setattr__(self, "function_ea", function_ea)

    def record_receipted_plan(
        self,
        plan: FragmentPlan,
        *,
        authority: NormalizationWorkItemAuthority,
    ) -> None:
        """Retain complete intent only after one selected work item commits."""
        if not isinstance(plan, FragmentPlan):
            raise TypeError(
                "frontend normalization plan authority requires a FragmentPlan"
            )
        if (
            plan.publication_purpose
            is not FragmentPublicationPurpose.FRONTEND_NORMALIZATION
        ):
            raise TypeError(
                "frontend normalization plan authority requires normalization intent"
            )
        if plan.native_key != self.native_key:
            raise FrontendNormalizationPublicationError(
                "frontend normalization plan belongs to another native identity"
            )
        if not isinstance(authority, NormalizationWorkItemAuthority):
            raise TypeError(
                "frontend normalization plan requires typed receipt authority"
            )
        generation = int(authority.evidence_generation)
        if (
            authority.source_plan_id != plan.plan_id
            or authority.source_atomic_group_id != plan.atomic_group_id
        ):
            raise FrontendNormalizationPublicationError(
                "frontend normalization receipt authority changed plan lineage"
            )
        previous_generation = self._evidence_generation
        if previous_generation is not None and generation < previous_generation:
            raise FrontendNormalizationPublicationError(
                "frontend normalization plan authority generation regressed"
            )
        if previous_generation == generation:
            if self._plan != plan:
                raise FrontendNormalizationPublicationError(
                    "frontend normalization plan intent changed within one generation"
                )
            previous_authority = self._authority
            if previous_authority is None:
                raise RuntimeError(
                    "frontend normalization plan lost its receipt authority"
                )
            if authority == previous_authority:
                return
            if not authority.is_immediate_successor_of(previous_authority):
                raise FrontendNormalizationPublicationError(
                    "frontend normalization receipt revision did not advance "
                    "exactly once within one generation"
                )
        self._plan = plan
        self._authority = authority
        self._evidence_generation = generation

    def plan_for(
        self,
        function_ea: int,
        evidence_generation: int,
    ) -> tuple[FragmentPlan, NormalizationWorkItemAuthority] | None:
        """Return intent only for its exact function and evidence generation."""
        if (
            int(function_ea) != self.function_ea
            or int(evidence_generation) != self._evidence_generation
            or self._plan is None
            or self._authority is None
        ):
            return None
        return self._plan, self._authority


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
    plan_authority: SessionFrontendNormalizationPlanAuthority,
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
    if not isinstance(
        plan_authority,
        SessionFrontendNormalizationPlanAuthority,
    ):
        raise TypeError("frontend normalization requires manager-owned plan authority")
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
    work_item_published = after_work_item_revision == before_work_item_revision + 1
    if after_work_item_revision not in {
        before_work_item_revision,
        before_work_item_revision + 1,
    }:
        raise FrontendNormalizationPublicationError(
            "frontend normalization published multiple work items in one pass"
        )
    analysis_manager = manager.analysis_manager_for(function_ea)
    complete_plan = (
        None
        if analysis_manager is None
        else analysis_manager.get_analysis(
            FRONTEND_NORMALIZATION_PLAN_INTENT,
            None,
        )
    )
    if work_item_published:
        if not isinstance(complete_plan, FragmentPlan):
            raise FrontendNormalizationPublicationError(
                "receipt-backed normalization lacks complete portable plan intent"
            )
        work_item_id = lifecycle_state.normalization_last_published_work_item_id
        if work_item_id is None:
            raise FrontendNormalizationPublicationError(
                "receipt-backed normalization lacks its work-item identity"
            )
        plan_authority.record_receipted_plan(
            complete_plan,
            authority=NormalizationWorkItemAuthority(
                evidence_generation=generation,
                publication_revision=after_work_item_revision,
                source_plan_id=complete_plan.plan_id,
                source_atomic_group_id=complete_plan.atomic_group_id,
                work_item_id=work_item_id,
                published_operation_ids=(
                    lifecycle_state.normalization_last_published_operation_ids
                ),
                selected_obligation_ids=(
                    lifecycle_state.normalization_last_selected_obligation_ids
                ),
                remaining_obligation_ids=(
                    lifecycle_state.normalization_last_remaining_obligation_ids
                ),
                unreachable_obligation_ids=(
                    lifecycle_state.normalization_last_unreachable_obligation_ids
                ),
            ),
        )
    if after_published == generation:
        if not work_item_published:
            raise FrontendNormalizationPublicationError(
                "normalization generation advanced without a work-item receipt"
            )
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
        remaining = lifecycle_state.normalization_last_remaining_obligation_ids
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
    "SessionFrontendNormalizationPlanAuthority",
    "run_frontend_normalization_pipeline",
]
