"""Manager-owned orchestration for receipt-backed frontend normalization."""

from __future__ import annotations

from dataclasses import dataclass, field, replace

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
from d810.capabilities.semantic_routes import (
    SemanticRouteReferenceOracleCapability,
)
from d810.core.fragment_authority import NormalizationWorkItemAuthority
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.flowgraph import FlowGraph
from d810.ir.maturity import IRMaturity
from d810.passes.frontend_normalization import (
    FRONTEND_NORMALIZATION_GENERATION_PLAN,
    standard_frontend_normalization_passes,
)
from d810.passes.function_pass_manager import FunctionPassManager
from d810.transforms.fragment_plan import (
    FragmentBlockRole,
    FragmentNativeBody,
    FragmentPlan,
    FragmentPublicationPurpose,
)
from d810.transforms.frontend_normalization import (
    FrontendNormalizationGenerationPlan,
)
from d810.transforms.prepared_native_body import (
    PreparedNativeBodyFact,
    PreparedNativeBodyFactSnapshot,
    PreparedNormalizationWorkItemSnapshot,
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
    _pending_prepared_body_facts: dict[tuple[int, str, str], PreparedNativeBodyFact] = (
        field(default_factory=dict)
    )
    _receipted_prepared_work_items: dict[
        tuple[int, str, str],
        PreparedNormalizationWorkItemSnapshot,
    ] = field(default_factory=dict)

    def __post_init__(self) -> None:
        function_ea = int(self.function_ea)
        if function_ea < 0:
            raise ValueError(
                "frontend normalization plan function EA must be non-negative"
            )
        if not isinstance(self.native_key, NativePreanalysisKey):
            raise TypeError("frontend normalization plan requires a native key")
        object.__setattr__(self, "function_ea", function_ea)

    def record_receipted_generation(
        self,
        generation_plan: FrontendNormalizationGenerationPlan,
        *,
        authority: NormalizationWorkItemAuthority,
    ) -> None:
        """Retain complete intent and the exact prepared work item that committed."""
        if not isinstance(generation_plan, FrontendNormalizationGenerationPlan):
            raise TypeError(
                "frontend normalization authority requires a generation plan"
            )
        plan = generation_plan.complete_plan
        work_item_plan = generation_plan.work_item_plan
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
        work_item_scope = work_item_plan.work_item_scope
        if (
            work_item_scope is None
            or work_item_scope.work_item_id != work_item_plan.plan_id
            or authority.work_item_id != work_item_plan.plan_id
            or authority.published_operation_ids
            != tuple(
                operation.operation_id for operation in work_item_plan.operations
            )
            or authority.selected_obligation_ids
            != work_item_scope.selected_obligation_ids
            or authority.remaining_obligation_ids
            != work_item_scope.remaining_obligation_ids
            or authority.unreachable_obligation_ids
            != work_item_scope.unreachable_obligation_ids
        ):
            raise FrontendNormalizationPublicationError(
                "frontend normalization receipt changed work-item lineage"
            )
        complete_operations = {
            operation.operation_id: operation for operation in plan.operations
        }
        if any(
            complete_operations.get(operation.operation_id) != operation
            for operation in work_item_plan.operations
        ):
            raise FrontendNormalizationPublicationError(
                "frontend normalization work item changed complete-plan operations"
            )
        complete_blocks = {block.block_id: block for block in plan.blocks}
        for work_item_block in work_item_plan.blocks:
            complete_block = complete_blocks.get(work_item_block.block_id)
            if complete_block is None:
                raise FrontendNormalizationPublicationError(
                    "frontend normalization work item invented a block owner"
                )
            if work_item_block.role is FragmentBlockRole.IMPORTED:
                work_item_block = replace(
                    work_item_block,
                    native_body_id=complete_block.native_body_id,
                )
            if work_item_block != complete_block:
                raise FrontendNormalizationPublicationError(
                    "frontend normalization work item changed complete-plan blocks"
                )
        for work_item_body in work_item_plan.native_bodies:
            complete_body_matches = tuple(
                complete_body
                for complete_body in plan.native_bodies
                if set(work_item_body.block_ids).issubset(complete_body.block_ids)
                and set(work_item_body.proof_ids).issubset(complete_body.proof_ids)
            )
            if len(complete_body_matches) != 1:
                raise FrontendNormalizationPublicationError(
                    "frontend normalization work item changed native-body ownership"
                )
        missing_prepared_body_ids = tuple(
            native_body.body_id
            for native_body in work_item_plan.native_bodies
            if (
                generation,
                work_item_plan.plan_id,
                native_body.body_id,
            )
            not in self._pending_prepared_body_facts
        )
        if missing_prepared_body_ids:
            raise FrontendNormalizationPublicationError(
                "frontend normalization receipt lacks prepared native-body facts: "
                f"{missing_prepared_body_ids!r}"
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
        if work_item_plan.native_bodies:
            prepared_bodies = PreparedNativeBodyFactSnapshot(
                plan_id=work_item_plan.plan_id,
                evidence_generation=generation,
                snapshot_id=(
                    f"prepared-native-body:{work_item_plan.plan_id}:"
                    f"g{generation}:r{int(authority.publication_revision)}"
                ),
                bodies=tuple(
                    self._pending_prepared_body_facts[
                        (generation, work_item_plan.plan_id, native_body.body_id)
                    ]
                    for native_body in work_item_plan.native_bodies
                ),
            )
            prepared_work_item = PreparedNormalizationWorkItemSnapshot(
                source_plan_id=plan.plan_id,
                source_atomic_group_id=plan.atomic_group_id,
                work_item_plan=work_item_plan,
                authority=authority,
                prepared_bodies=prepared_bodies,
            )
            work_item_key = (generation, plan.plan_id, work_item_plan.plan_id)
            previous_work_item = self._receipted_prepared_work_items.get(work_item_key)
            if previous_work_item is not None and previous_work_item != prepared_work_item:
                raise FrontendNormalizationPublicationError(
                    "prepared normalization work item changed after its receipt"
                )
            self._receipted_prepared_work_items[work_item_key] = prepared_work_item
        self._plan = plan
        self._authority = authority
        self._evidence_generation = generation

    def record_prepared_body_fact(
        self,
        plan: FragmentPlan,
        native_body: FragmentNativeBody,
        fact: PreparedNativeBodyFact,
        *,
        evidence_generation: int,
    ) -> None:
        """Retain portable preparation privately until its exact plan commits."""
        if not isinstance(plan, FragmentPlan):
            raise TypeError("prepared body authority requires a FragmentPlan")
        if not isinstance(native_body, FragmentNativeBody):
            raise TypeError("prepared body authority requires a FragmentNativeBody")
        if not isinstance(fact, PreparedNativeBodyFact):
            raise TypeError("prepared body authority requires typed portable facts")
        generation = int(evidence_generation)
        if generation < 0:
            raise ValueError("prepared body evidence generation must be non-negative")
        if (
            plan.publication_purpose
            is not FragmentPublicationPurpose.FRONTEND_NORMALIZATION
            or plan.native_key != self.native_key
        ):
            raise FrontendNormalizationPublicationError(
                "prepared body belongs to another normalization authority"
            )
        planned_bodies = tuple(
            candidate
            for candidate in plan.native_bodies
            if candidate.body_id == native_body.body_id
        )
        if len(planned_bodies) != 1 or planned_bodies[0] != native_body:
            raise FrontendNormalizationPublicationError(
                "prepared body changed native-body ownership"
            )
        if fact.plan_id != plan.plan_id or fact.body_id != native_body.body_id:
            raise FrontendNormalizationPublicationError(
                "prepared body fact changed plan lineage"
            )
        if (
            fact.native_ranges != native_body.native_ranges
            or fact.entry_block_ids != native_body.entry_block_ids
            or fact.terminal_block_ids != native_body.terminal_block_ids
            or tuple(block.block_id for block in fact.blocks) != native_body.block_ids
        ):
            raise FrontendNormalizationPublicationError(
                "prepared body fact changed native-body inventory"
            )
        for block in fact.blocks:
            plan_block = plan.block(block.block_id)
            if (
                block.semantic_anchor_ea != plan_block.semantic_anchor_ea
                or block.stable_identity != plan_block.stable_identity
            ):
                raise FrontendNormalizationPublicationError(
                    "prepared body fact changed block identity"
                )
        current_generation = self._evidence_generation
        if current_generation is not None and generation < current_generation:
            raise FrontendNormalizationPublicationError(
                "prepared body evidence generation regressed"
            )
        key = (generation, plan.plan_id, native_body.body_id)
        previous = self._pending_prepared_body_facts.get(key)
        if previous is not None:
            if previous != fact:
                raise FrontendNormalizationPublicationError(
                    "prepared body facts changed within one plan generation"
                )
            return
        self._pending_prepared_body_facts[key] = fact

    def prepared_work_item_for(
        self,
        function_ea: int,
        evidence_generation: int,
        source_plan_id: str,
        block_id: str,
    ) -> PreparedNormalizationWorkItemSnapshot | None:
        """Expose the exact receipted work item that prepared one imported block."""
        if (
            int(function_ea) != self.function_ea
            or int(evidence_generation) != self._evidence_generation
            or str(source_plan_id)
            != (None if self._plan is None else self._plan.plan_id)
            or self._plan is None
            or self._authority is None
        ):
            return None
        matches = tuple(
            snapshot
            for (
                generation,
                retained_source_plan_id,
                _work_item_id,
            ), snapshot in self._receipted_prepared_work_items.items()
            if generation == int(evidence_generation)
            and retained_source_plan_id == str(source_plan_id)
            and any(
                candidate.block_id == str(block_id)
                and candidate.role is FragmentBlockRole.IMPORTED
                for candidate in snapshot.work_item_plan.blocks
            )
        )
        if not matches:
            return None
        if len(matches) != 1:
            raise FrontendNormalizationPublicationError(
                "prepared normalization block has multiple receipt owners"
            )
        return matches[0]

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
    reference_oracle_provider: SemanticRouteReferenceOracleCapability | None = None,
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
    capabilities = CapabilitySet().with_capability(
        FrontendNormalizationEvidenceCapability,
        _FixedEvidenceProvider(current_evidence),
    )
    if reference_oracle_provider is not None:
        capabilities = capabilities.with_capability(
            SemanticRouteReferenceOracleCapability,
            reference_oracle_provider,
        )
    final_graph = manager.run(
        source=source,
        family=None,
        backend=backend,
        project_config=project_config,
        maturity=IRMaturity.CANONICAL,
        capabilities=capabilities,
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
    generation_plan = (
        None
        if analysis_manager is None
        else analysis_manager.get_analysis(
            FRONTEND_NORMALIZATION_GENERATION_PLAN,
            None,
        )
    )
    if work_item_published:
        if not isinstance(generation_plan, FrontendNormalizationGenerationPlan):
            raise FrontendNormalizationPublicationError(
                "receipt-backed normalization lacks its portable generation plan"
            )
        work_item_id = lifecycle_state.normalization_last_published_work_item_id
        if work_item_id is None:
            raise FrontendNormalizationPublicationError(
                "receipt-backed normalization lacks its work-item identity"
            )
        complete_plan = generation_plan.complete_plan
        plan_authority.record_receipted_generation(
            generation_plan,
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
