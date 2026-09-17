"""Gateway-owned semantic-fragment publication and rollback."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.core.events import EventEmitter
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.mba_mutation_events import (
    MbaCfgTransactionAuthorityObserved,
    MbaMutationAborted,
    MbaMutationCommitted,
    MbaMutationGateway,
    MbaMutationPlanned,
    MbaMutationRootPublicationGroup,
    StructuralMutationKind,
)
from d810.hexrays.mutation.semantic_fragment_publication import (
    SemanticFragmentPublicationRejected,
    SemanticFragmentRollbackFailed,
)
from d810.hexrays.mutation import semantic_fragment_publication as publication
from d810.hexrays.mutation.semantic_fragment_inventory import (
    SemanticFragmentRootInventory,
    SemanticFragmentRootInventoryItem,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.block_identity import (
    CurrentMbaBlockIdentityBinding,
    CurrentMbaIdentityBindingSnapshot,
    NativeEaInterval,
    StableBlockIdentity,
)
from d810.ir.flowgraph import BlockKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.manager.fragment_publication_lifecycle import (
    SessionFragmentPublicationLifecycleAuthority,
)
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentEdge,
    FragmentDataFlowObligation,
    FragmentDataFlowRole,
    FragmentFlagCorridor,
    FragmentNativeBody,
    FragmentOperation,
    FragmentPlan,
    FragmentPublicationPurpose,
    FragmentRangeAssumption,
    FragmentRangeObservation,
    FragmentReturnCarrier,
    FragmentReturnSource,
    FragmentReturnSourceKind,
    FragmentTerminalReturn,
    FragmentTerminalRoute,
    FragmentValueSite,
    FragmentWorkItemScope,
)
from d810.transforms.fragment_projection import (
    FragmentProjectionFailure,
    FragmentProjectionBlockInput,
    FragmentProjectionInput,
)
from d810.transforms.cfg_transaction import PlanBlockRef, TransactionAttemptId
from d810.transforms.cfg_transaction import (
    CfgGenerationPoisoned,
    CfgTransactionPhase,
)
from d810.hexrays.mutation.semantic_fragment_preparation import (
    PreparedSemanticFragment,
    SemanticFragmentRealizationPayload,
    SemanticFragmentSnapshotAuthority,
    SemanticFragmentSnapshotPreparation,
)
from d810.transforms.fragment_validation import (
    FragmentBindingState,
    FragmentValidationOutcome,
    FragmentValidationResult,
    FragmentValidationPostcondition,
    ProjectedFragment,
    ProjectedFragmentBlock,
    ProjectedDataFlowRelation,
    ProjectedIdentityBinding,
    PublishedFragmentGraphObservation,
    PublishedFragmentObservation,
    validate_published_fragment_projection,
)
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key(function_rva=0x40A560)
_DEFAULT_LIFECYCLE = object()


def _identity(start_ea: int) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(start_ea, start_ea + 0x10),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(start_ea,),
    )


def _block(
    block_id: str,
    role: FragmentBlockRole,
    start_ea: int,
    *,
    identity: StableBlockIdentity | None = None,
    replaces: str | None = None,
) -> FragmentBlock:
    return FragmentBlock(
        block_id=block_id,
        role=role,
        materialization=(
            FragmentBlockMaterialization.CLONE_PUBLISHED
            if role is FragmentBlockRole.REPLACEMENT
            else FragmentBlockMaterialization.REUSE_PUBLISHED
        ),
        semantic_anchor_ea=start_ea,
        stable_identity=_identity(start_ea) if identity is None else identity,
        replaces_block_id=replaces,
    )


def _plan() -> FragmentPlan:
    original_identity = _identity(0x401000)
    return FragmentPlan(
        plan_id="gateway-fragment",
        atomic_group_id="route@0x401000",
        publication_purpose=FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING,
        native_key=NATIVE_KEY,
        blocks=(
            _block("entry", FragmentBlockRole.EXTERNAL, 0x400000),
            _block(
                "original",
                FragmentBlockRole.ORIGINAL,
                0x401000,
                identity=original_identity,
            ),
            _block(
                "replacement",
                FragmentBlockRole.REPLACEMENT,
                0x401000,
                identity=original_identity,
                replaces="original",
            ),
            _block("target", FragmentBlockRole.EXTERNAL, 0x402000),
            _block("dispatcher", FragmentBlockRole.EXTERNAL, 0x403000),
        ),
        roots=("replacement",),
        owned_originals=("original",),
        prohibited_dispatcher_blocks=("dispatcher",),
        operations=(
            FragmentOperation(
                operation_id="direct-route",
                source_block_id="replacement",
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id="target",
                    ),
                ),
            ),
        ),
    )


def _plan_with_terminal_effects() -> FragmentPlan:
    plan = _plan()
    replacement_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x401000, 0x401004),
    )
    terminal_range = NativeEaInterval(0x404000, 0x404010)
    terminal_identity = StableBlockIdentity.from_intervals(
        (terminal_range,),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x404000,),
    )
    terminal = FragmentBlock(
        block_id="terminal",
        role=FragmentBlockRole.IMPORTED,
        materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
        semantic_anchor_ea=0x404000,
        stable_identity=terminal_identity,
        native_body_id="terminal-body",
    )
    blocks = tuple(
        replace(block, stable_identity=replacement_identity)
        if block.block_id in {"original", "replacement"}
        else block
        for block in plan.blocks
    ) + (terminal,)
    operation = replace(
        plan.operations[0],
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.DIRECT,
                target_block_id=terminal.block_id,
            ),
        ),
    )
    return replace(
        plan,
        blocks=blocks,
        operations=(operation,),
        return_carriers=(
            FragmentReturnCarrier(
                carrier_id="return-value",
                block_id="replacement",
                state_write_ea=0x401000,
                carrier_ea=0x401004,
                operation=ValueOpKind.MOVE,
                source=FragmentReturnSource(
                    kind=FragmentReturnSourceKind.CONSTANT,
                    width=4,
                    constant=7,
                ),
                return_width=4,
                corridor_instruction_eas=(0x401000, 0x401004),
            ),
        ),
        terminal_returns=(
            FragmentTerminalReturn(
                return_id="function-return",
                block_id=terminal.block_id,
                instruction_ea=0x404000,
                return_width=4,
            ),
        ),
        terminal_routes=(
            FragmentTerminalRoute(
                terminal_route_id="terminal-route",
                operation_id=operation.operation_id,
                carrier_id="return-value",
                return_id="function-return",
            ),
        ),
        native_bodies=(
            FragmentNativeBody(
                body_id="terminal-body",
                block_ids=(terminal.block_id,),
                entry_block_ids=(terminal.block_id,),
                terminal_block_ids=(terminal.block_id,),
                native_ranges=(terminal_range,),
                proof_ids=("proof:terminal-body",),
            ),
        ),
    )


def _semantic_lifecycle() -> NativePreanalysisSessionState:
    state = NativePreanalysisSessionState(evidence_generation=1)
    state._fragment_publication_mark_normalization_staged()
    state._fragment_publication_mark_normalization_validated()
    state._fragment_publication_mark_normalization_published_and_postvalidated()
    state.mark_canonical_semantic_plan_ready()
    return state


class _ReceiptLifecycleAuthority:
    def __init__(self) -> None:
        self.evidence_generation = 1
        self.events: list[tuple[str, object]] = []

    def record_fragment_plan_ready(self, plan: FragmentPlan) -> None:
        del plan

    def record_fragment_staged(self, plan: FragmentPlan) -> None:
        self.events.append(("staged", plan))

    def record_fragment_validated(
        self,
        plan: FragmentPlan,
        validation,
    ) -> None:
        self.events.append(("validated", (plan, validation)))

    def abort_fragment_publication(
        self,
        plan: FragmentPlan,
        *,
        reason: str,
    ) -> None:
        self.events.append(("aborted", (plan, reason)))

    def commit_fragment_publication(
        self,
        plan: FragmentPlan,
        receipt,
    ) -> None:
        self.events.append(("committed", (plan, receipt)))

    def request_poisoned_generation_restart(self, plan, failure) -> bool:
        self.events.append(("poisoned", (plan, failure)))
        return True


def _gateway(
    plan: FragmentPlan,
    *,
    lifecycle_authority: object = _DEFAULT_LIFECYCLE,
):
    if lifecycle_authority is _DEFAULT_LIFECYCLE:
        lifecycle_authority = (
            NativePreanalysisSessionState(evidence_generation=1)
            if plan.publication_purpose
            is FragmentPublicationPurpose.FRONTEND_NORMALIZATION
            else _semantic_lifecycle()
        )
    if isinstance(lifecycle_authority, NativePreanalysisSessionState):
        lifecycle_authority = SessionFragmentPublicationLifecycleAuthority(
            native_key=NATIVE_KEY,
            state=lifecycle_authority,
        )
    evidence_generation = (
        0
        if lifecycle_authority is None
        else int(lifecycle_authority.evidence_generation)
    )
    serials = {
        "entry": 0,
        "original": 1,
        "target": 2,
        "dispatcher": 3,
    }
    index = MbaBlockIdentityIndex.from_bindings(
        session_id="fragment-session",
        generation=5,
        evidence_generation=evidence_generation,
        native_key=NATIVE_KEY,
        bindings=tuple(
            (plan.block(block_id).stable_identity, serial)
            for block_id, serial in serials.items()
        ),
    )
    emitter = EventEmitter()
    committed: list[MbaMutationCommitted] = []
    aborted: list[MbaMutationAborted] = []
    emitter.on(MbaMutationCommitted, committed.append)
    emitter.on(MbaMutationAborted, aborted.append)
    gateway = MbaMutationGateway(
        native_key=NATIVE_KEY,
        generation=5,
        session_id="fragment-session",
        function_ea=0x40A560,
        maturity=1,
        identity_index=index,
        event_emitter=emitter,
        lifecycle_authority=lifecycle_authority,
    )
    return gateway, committed, aborted


class _FragmentBackend:
    def __init__(
        self,
        gateway: MbaMutationGateway,
        *,
        invalid_preprojection: bool = False,
        invalid_postobservation: bool = False,
        raise_during_stage: bool = False,
        raise_during_discard: bool = False,
        raise_during_publish: bool = False,
        raise_during_rollback: bool = False,
        omit_semantic_edge_record: bool = False,
        disconnect_root_after_publication: bool = False,
        raise_after_insertion: bool = False,
        raise_after_observation: bool = False,
        current_mba_identity_binding: CurrentMbaIdentityBindingSnapshot | None = None,
    ) -> None:
        self.get_mblock_calls = 0

        def get_mblock(_serial: int):
            self.get_mblock_calls += 1
            raise AssertionError("poisoned publication must not resolve live blocks")

        self.mba = SimpleNamespace(qty=4, get_mblock=get_mblock)
        self.gateway = gateway
        self.invalid_preprojection = invalid_preprojection
        self.invalid_postobservation = invalid_postobservation
        self.raise_during_stage = raise_during_stage
        self.raise_during_discard = raise_during_discard
        self.raise_during_publish = raise_during_publish
        self.raise_during_rollback = raise_during_rollback
        self.omit_semantic_edge_record = omit_semantic_edge_record
        self.disconnect_root_after_publication = disconnect_root_after_publication
        self.raise_after_insertion = raise_after_insertion
        self.raise_after_observation = raise_after_observation
        self.current_mba_identity_binding = (
            CurrentMbaIdentityBindingSnapshot((), ())
            if current_mba_identity_binding is None
            else current_mba_identity_binding
        )
        self.calls: list[str] = []
        self.root_published = False
        self.projection: ProjectedFragment | None = None
        self.original_handle = None
        self.replacement_handle = None

    def _snapshot_semantic_fragment_inputs(
        self,
        plan: FragmentPlan,
    ) -> SemanticFragmentSnapshotPreparation:
        self.calls.append("snapshot")
        bindings = (
            self._published_binding(plan, "entry", 0),
            self._published_binding(plan, "original", 1),
            self._published_binding(plan, "target", 2),
            self._published_binding(plan, "dispatcher", 3),
        )
        target_successors = ("original",) if self.invalid_preprojection else ()
        original_predecessors = ("entry", "target") if self.invalid_preprojection else ("entry",)
        projection_input = FragmentProjectionInput(
            snapshot_id="snapshot:gateway-fragment",
            entry_block_id="entry",
            blocks=(
                FragmentProjectionBlockInput("entry", BlockKind.ONE_WAY, ("original",), (), 0, None),
                FragmentProjectionBlockInput(
                    "original",
                    BlockKind.ZERO_WAY,
                    (),
                    original_predecessors,
                    1,
                    None,
                    instruction_eas=(0x401000, 0x401004),
                ),
                FragmentProjectionBlockInput(
                    "target",
                    BlockKind.ONE_WAY if target_successors else BlockKind.ZERO_WAY,
                    target_successors,
                    (),
                    2,
                    None,
                ),
                FragmentProjectionBlockInput("dispatcher", BlockKind.ZERO_WAY, (), (), 3, None),
            ),
            identity_bindings=bindings,
        )
        return SemanticFragmentSnapshotPreparation(
            authority=SemanticFragmentSnapshotAuthority(
                plan_id=plan.plan_id,
                atomic_group_id=plan.atomic_group_id,
                session_id=self.gateway.session_id,
                generation=self.gateway.generation,
                projection_input=projection_input,
                native_bodies=(),
                return_carrier_constructions=(),
            ),
            payload=SemanticFragmentRealizationPayload(
                native_body_rows=(),
                return_carrier_operands=(),
            ),
        )

    def _semantic_fragment_current_mba_identity_binding(
        self,
        _plan: FragmentPlan,
    ) -> CurrentMbaIdentityBindingSnapshot:
        return self.current_mba_identity_binding

    def _plan_semantic_fragment_root_publication_inventory(
        self,
        plan: FragmentPlan,
    ) -> SemanticFragmentRootInventory:
        self.calls.append("plan-roots")
        return SemanticFragmentRootInventory(
            plan_id=plan.plan_id,
            atomic_group_id=plan.atomic_group_id,
            items=(
                SemanticFragmentRootInventoryItem(
                    edge_id="replacement:entry:direct",
                    root_block_id="replacement",
                    original_block_id="original",
                    predecessor_block_id="entry",
                    role=SemanticEdgeRole.DIRECT,
                    requires_helper=False,
                ),
            ),
        )

    def _published_binding(
        self,
        plan: FragmentPlan,
        block_id: str,
        serial: int,
    ) -> ProjectedIdentityBinding:
        handle = self.gateway.identity_index.handle_for_serial(serial)
        assert handle is not None
        proxy = self.gateway.identity_index.logical_proxy_for_handle(handle)
        assert proxy is not None
        version = proxy.resolve()
        assert version is not None
        return ProjectedIdentityBinding(
            block_id=block_id,
            logical_owner_id=proxy.proxy_token,
            version=version.version_id.version,
            generation=version.generation,
            state=FragmentBindingState.PUBLISHED,
            stable_identity=plan.block(block_id).stable_identity,
        )

    def _realize_projected_fragment(
        self,
        plan: FragmentPlan,
        prepared_fragment: PreparedSemanticFragment | None = None,
    ) -> ProjectedFragment:
        self.calls.append("stage")
        assert isinstance(prepared_fragment, PreparedSemanticFragment)
        if self.raise_during_stage:
            try:
                raise LookupError(
                    "fragment plan requires an imported native-body materializer"
                )
            except LookupError:
                verifier_error = RuntimeError("INTERR: 50856")
                verifier_error.d810_interr_code = 50856
                verifier_error.d810_verification_context = (
                    "staged semantic fragment rollback sweep"
                )
                raise verifier_error
        index = self.gateway.identity_index
        original = index.handle_for_serial(1)
        assert original is not None
        replacement = index.create_native_handle(
            plan.block("replacement").stable_identity
        )
        self.gateway._record_fragment_mutation_started(plan)
        staged = self.gateway.stage_replacement(
            original=original,
            replacement=replacement,
            returned_serial=4,
        )
        if not self.omit_semantic_edge_record:
            self.gateway.record_edge_redirect(
                source=replacement,
                target=index.handle_for_serial(2),
            )
        proxy = index.logical_proxy_for_handle(original)
        assert proxy is not None
        published = proxy.resolve()
        assert published is not None
        self.original_handle = original
        self.replacement_handle = replacement
        if self.raise_after_insertion:
            error = RuntimeError("INTERR: 50856 after fragment insertion")
            error.d810_interr_code = 50856
            raise error

        entry_successor = "original" if self.invalid_preprojection else "replacement"
        original_predecessors = ("entry",) if self.invalid_preprojection else ()
        replacement_predecessors = () if self.invalid_preprojection else ("entry",)
        projection = ProjectedFragment(
            entry_block_id="entry",
            blocks=(
                ProjectedFragmentBlock(
                    block_id="entry",
                    kind=BlockKind.ONE_WAY,
                    successors=(entry_successor,),
                    predecessors=(),
                    physical_position=0,
                    adjacent_fallthrough_target_id=None,
                ),
                ProjectedFragmentBlock(
                    block_id="replacement",
                    kind=BlockKind.ONE_WAY,
                    successors=("target",),
                    predecessors=replacement_predecessors,
                    physical_position=1,
                    adjacent_fallthrough_target_id=None,
                ),
                ProjectedFragmentBlock(
                    block_id="target",
                    kind=BlockKind.ZERO_WAY,
                    successors=(),
                    predecessors=("replacement",),
                    physical_position=2,
                    adjacent_fallthrough_target_id=None,
                ),
                ProjectedFragmentBlock(
                    block_id="original",
                    kind=BlockKind.ZERO_WAY,
                    successors=(),
                    predecessors=original_predecessors,
                    physical_position=3,
                    adjacent_fallthrough_target_id=None,
                ),
                ProjectedFragmentBlock(
                    block_id="dispatcher",
                    kind=BlockKind.ZERO_WAY,
                    successors=(),
                    predecessors=(),
                    physical_position=4,
                    adjacent_fallthrough_target_id=None,
                ),
            ),
            identity_bindings=(
                self._published_binding(plan, "entry", 0),
                ProjectedIdentityBinding(
                    block_id="original",
                    logical_owner_id=proxy.proxy_token,
                    version=published.version_id.version,
                    generation=published.generation,
                    state=FragmentBindingState.PUBLISHED,
                    stable_identity=plan.block("original").stable_identity,
                ),
                ProjectedIdentityBinding(
                    block_id="replacement",
                    logical_owner_id=proxy.proxy_token,
                    version=staged.version_id.version,
                    generation=staged.generation,
                    state=FragmentBindingState.STAGED,
                    stable_identity=plan.block("replacement").stable_identity,
                    previous_version=published.version_id.version,
                ),
                self._published_binding(plan, "target", 2),
                self._published_binding(plan, "dispatcher", 3),
            ),
        )
        plan_versions = {
            "original": published,
            "replacement": staged,
        }
        for block_id, serial in (("entry", 0), ("target", 2), ("dispatcher", 3)):
            handle = index.handle_for_serial(serial)
            assert handle is not None
            plan_proxy = index.logical_proxy_for_handle(handle)
            assert plan_proxy is not None
            plan_version = plan_proxy.resolve()
            assert plan_version is not None
            plan_versions[block_id] = plan_version
        self.gateway._record_fragment_plan_bindings(
            plan,
            tuple(
                (
                    PlanBlockRef(plan.plan_id, block.block_id),
                    plan_versions[block.block_id],
                )
                for block in plan.blocks
            ),
        )
        self.projection = projection
        return projection

    def _realize_semantic_patch_plan(self, patch_plan, prepared_fragment):
        """Test port adapter; concrete runtime dispatches PatchSteps directly."""
        return self._realize_projected_fragment(
            patch_plan.semantic_contract.fragment_plan,
            prepared_fragment,
        )

    def _discard_staged_semantic_fragment(self, _plan: FragmentPlan) -> None:
        self.calls.append("discard")
        if self.raise_during_discard:
            raise RuntimeError(
                "staged semantic fragment discard cannot remove entry or stop blocks"
            )

    def _prepare_semantic_fragment_root_publication(
        self,
        plan: FragmentPlan,
        inventory: SemanticFragmentRootInventory,
    ):
        assert inventory.plan_id == plan.plan_id
        assert inventory.atomic_group_id == plan.atomic_group_id
        self.calls.append("prepare-roots")
        return "prior-root-authority"

    def _publish_semantic_root_groups(
        self,
        plan: FragmentPlan,
        rollback_token,
    ) -> None:
        assert rollback_token == "prior-root-authority"
        self.calls.append("publish-roots")
        self.gateway._record_fragment_root_group_publication_attempted(
            plan,
            "root-group:entry",
        )
        self.root_published = True
        if self.raise_during_publish:
            raise RuntimeError("partial root publication")
        self.gateway._record_fragment_root_group_publication_succeeded(
            plan,
            "root-group:entry",
        )

    def _publish_semantic_patch_roots(self, patch_plan, rollback_token) -> None:
        self._publish_semantic_root_groups(
            patch_plan.semantic_contract.fragment_plan,
            rollback_token,
        )

    def _rebuild_semantic_fragment_chains(self, _plan: FragmentPlan) -> None:
        self.calls.append("rebuild")

    def _observe_published_semantic_fragment_graph(
        self,
        plan: FragmentPlan,
    ) -> PublishedFragmentObservation:
        self.calls.append("observe")
        assert self.root_published
        assert self.gateway.receipts == ()
        assert self.projection is not None
        if self.raise_after_observation:
            error = RuntimeError("INTERR: 50860 after fragment observation")
            error.d810_interr_code = 50860
            raise error
        projection = self.projection
        if self.disconnect_root_after_publication:
            replacements = {
                "entry": replace(
                    projection.block("entry"),
                    successors=("target",),
                ),
                "replacement": replace(
                    projection.block("replacement"),
                    predecessors=(),
                ),
                "target": replace(
                    projection.block("target"),
                    predecessors=("entry", "replacement"),
                ),
            }
            projection = replace(
                projection,
                blocks=tuple(
                    replacements.get(block.block_id, block)
                    for block in projection.blocks
                ),
            )
        validation = validate_published_fragment_projection(plan, projection)
        if not self.disconnect_root_after_publication:
            assert validation.passed
        outcomes = validation.outcomes
        if self.invalid_postobservation:
            outcomes = tuple(
                outcome
                for outcome in outcomes
                if not (
                    outcome.postcondition
                    is FragmentValidationPostcondition.ORIGINAL_SUPERSESSION
                    and outcome.subject_id == "original"
                )
            )
        semantics = PublishedFragmentObservation(
            plan_id=plan.plan_id,
            atomic_group_id=plan.atomic_group_id,
            published_root_ids=plan.roots,
            observable_operations=plan.operations,
            semantic_outcomes=outcomes,
            fallthrough_helpers=projection.fallthrough_helpers,
            root_fallthrough_helpers=projection.root_fallthrough_helpers,
        )
        return PublishedFragmentGraphObservation(
            projection=projection,
            semantics=semantics,
        )

    def _rollback_semantic_fragment_roots(
        self,
        plan: FragmentPlan,
        rollback_token,
    ) -> None:
        assert rollback_token == "prior-root-authority"
        self.calls.append("rollback-roots")
        self.gateway._record_fragment_root_group_rollback_attempted(
            plan,
            "root-group:entry",
        )
        if self.raise_during_rollback:
            self.gateway._record_fragment_root_group_rollback_finished(
                plan,
                "root-group:entry",
                succeeded=False,
            )
            raise RuntimeError("root rollback failed")
        self.root_published = False
        self.gateway._record_fragment_root_group_rollback_finished(
            plan,
            "root-group:entry",
            succeeded=True,
        )

    def _complete_semantic_fragment_publication(self, _plan: FragmentPlan) -> None:
        self.calls.append("complete")


def test_gateway_commits_only_after_pre_and_post_semantic_validation() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(gateway)
    original = gateway.identity_index.handle_for_serial(1)
    assert original is not None
    proxy = gateway.identity_index.logical_proxy_for_handle(original)
    assert proxy is not None
    planned: list[MbaMutationPlanned] = []
    authority_events: list[MbaCfgTransactionAuthorityObserved] = []
    gateway.event_emitter.on(MbaMutationPlanned, planned.append)
    gateway.event_emitter.on(
        MbaCfgTransactionAuthorityObserved,
        authority_events.append,
    )

    receipt = gateway.execute_patch_transaction(backend, plan)

    assert backend.calls == [
        "plan-roots",
        "snapshot",
        "stage",
        "prepare-roots",
        "publish-roots",
        "rebuild",
        "observe",
        "complete",
    ]
    assert receipt.kind is StructuralMutationKind.FRAGMENT_PUBLICATION
    assert receipt.fragment_plan_id == plan.plan_id
    assert receipt.fragment_atomic_group_id == plan.atomic_group_id
    assert receipt.prepublication_validation.passed
    assert receipt.postpublication_validation.passed
    assert receipt.root_publication_confirmed
    assert receipt.operation_count == 3
    assert receipt.planned_operation_count == 3
    assert len(planned) == 1
    assert planned[0].planned_operation_count == 3
    assert tuple(item.mutation_kind for item in planned[0].items) == (
        "semantic_fragment_replacement_materialization",
        "semantic_fragment_direct",
        "semantic_fragment_root_direct",
    )
    assert planned[0].items[2].source_anchor_ea == 0x400000
    assert planned[0].items[2].source_identity == plan.block("entry").stable_identity
    assert planned[0].items[2].target_anchor_ea == 0x401000
    assert (
        planned[0].items[2].target_identity == plan.block("replacement").stable_identity
    )
    assert len(receipt.version_transitions) == 1
    assert gateway.generation == 6
    assert proxy.resolve().handle is backend.replacement_handle
    assert len(committed) == 1
    assert aborted == []
    assert [event.phase for event in authority_events] == [
        CfgTransactionPhase.PLANNED,
        CfgTransactionPhase.PROJECTED,
        CfgTransactionPhase.PREFLIGHTED,
        CfgTransactionPhase.BOUND,
        CfgTransactionPhase.REALIZING,
        CfgTransactionPhase.OBSERVED,
        CfgTransactionPhase.COMMITTED,
    ]
    assert len({event.attempt_id for event in authority_events}) == 1
    assert all(
        event.attempt_id.plan_id == plan.plan_id for event in authority_events
    )


def test_post_root_live_cfg_contract_runs_before_commit(monkeypatch) -> None:
    plan = _plan()
    gateway, committed, _aborted = _gateway(plan)
    calls = []
    original = publication.CfgContract.verify_projection

    def verify_projection(contract, projection, *, scope="full"):
        calls.append(projection)
        if len(calls) == 3:
            raise RuntimeError("post-root observed CFG rejected")
        return original(contract, projection, scope=scope)

    monkeypatch.setattr(
        publication.CfgContract,
        "verify_projection",
        verify_projection,
    )
    with pytest.raises(CfgGenerationPoisoned, match="post-root observed CFG rejected"):
        gateway.execute_patch_transaction(_FragmentBackend(gateway), plan)

    assert len(calls) == 3
    assert committed == []
    assert gateway.transaction_failure.failure_phase == "postpublication_validation"


def test_gateway_receipts_current_mba_identity_binding_only_after_commit() -> None:
    plan = _plan()
    gateway, _committed, _aborted = _gateway(plan)
    origins = (
        (0xFFFFFFFFFFFFFF01, 0x401000),
        (0xFFFFFFFFFFFFFF02, 0x401004),
    )
    identity = plan.block("replacement").stable_identity
    assert identity is not None
    snapshot = CurrentMbaIdentityBindingSnapshot(
        instruction_origins=origins,
        block_bindings=(
            CurrentMbaBlockIdentityBinding(
                stable_identity=identity,
                live_instruction_eas=frozenset(
                    live_ea for live_ea, _native_ea in origins
                ),
            ),
        ),
    )
    backend = _FragmentBackend(
        gateway,
        current_mba_identity_binding=snapshot,
    )

    receipt = gateway.execute_patch_transaction(backend, plan)

    assert receipt.current_mba_identity_binding == snapshot
    assert not hasattr(receipt, "current_mba_instruction_origins")


def test_gateway_inventories_terminal_effects_as_first_class_fragment_items() -> None:
    plan = _plan_with_terminal_effects()
    gateway, _committed, aborted = _gateway(plan)
    planned: list[MbaMutationPlanned] = []
    gateway.event_emitter.on(MbaMutationPlanned, planned.append)
    inventory = SemanticFragmentRootInventory(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        items=(
            SemanticFragmentRootInventoryItem(
                edge_id="replacement:entry:direct",
                root_block_id="replacement",
                original_block_id="original",
                predecessor_block_id="entry",
                role=SemanticEdgeRole.DIRECT,
                requires_helper=True,
            ),
        ),
    )

    gateway._begin_semantic_fragment_batch(
        SimpleNamespace(mba=SimpleNamespace(qty=4)),
        plan,
        inventory,
        TransactionAttemptId.new(plan.plan_id),
        "direct-begin-snapshot",
    )

    assert len(planned) == 1
    assert planned[0].planned_operation_count == 7
    assert tuple(item.mutation_kind for item in planned[0].items) == (
        "semantic_fragment_replacement_materialization",
        "semantic_fragment_native_body_materialization",
        "semantic_fragment_return_carrier_materialization",
        "semantic_fragment_terminal_return_materialization",
        "semantic_fragment_direct",
        "semantic_fragment_root_fallthrough_helper",
        "semantic_fragment_root_direct",
    )
    carrier_item = planned[0].items[2]
    assert carrier_item.source_anchor_ea == 0x401000
    assert carrier_item.target_anchor_ea == 0x401004
    assert carrier_item.source_identity == plan.block("replacement").stable_identity
    assert carrier_item.target_identity == plan.block("replacement").stable_identity
    terminal_item = planned[0].items[3]
    assert terminal_item.source_anchor_ea == 0x404000
    assert terminal_item.source_identity == plan.block("terminal").stable_identity

    gateway.abort(reason="terminal inventory unit-test cleanup")

    assert len(aborted) == 1


def test_gateway_advances_semantic_lifecycle_only_after_receipt_commit() -> None:
    plan = _plan()
    lifecycle = _semantic_lifecycle()
    gateway, _committed, _aborted = _gateway(
        plan,
        lifecycle_authority=lifecycle,
    )

    receipt = gateway.execute_patch_transaction(_FragmentBackend(gateway), plan)

    assert receipt.evidence_generation == 1
    assert lifecycle.semantic_fragment_staged_generation == 1
    assert lifecycle.semantic_fragment_validated_generation == 1
    assert lifecycle.semantic_fragment_published_postvalidated_generation == 1
    assert lifecycle.receipt_committed_generation == 1
    assert lifecycle.normalization_published_postvalidated_generation == 1


def test_gateway_records_canonical_plan_ready_before_semantic_staging() -> None:
    plan = _plan()
    timeline: list[str] = []
    lifecycle = NativePreanalysisSessionState(
        evidence_generation=1,
        portable_evidence_ready_generation=1,
        normalization_staged_generation=1,
        normalization_validated_generation=1,
        normalization_published_postvalidated_generation=1,
    )
    lifecycle.event_observer = lambda transition: timeline.append(
        transition.operation
    )
    gateway, _committed, _aborted = _gateway(
        plan,
        lifecycle_authority=lifecycle,
    )

    gateway.execute_patch_transaction(_FragmentBackend(gateway), plan)

    assert lifecycle.canonical_semantic_plan_generation == 1
    assert timeline[:3] == [
        "canonical_semantic_plan_ready",
        "semantic_fragment_staged",
        "semantic_fragment_validated",
    ]


def test_lifecycle_authority_rejects_receipt_from_older_evidence_generation() -> None:
    plan = _plan()
    gateway, _committed, _aborted = _gateway(plan)
    old_receipt = gateway.execute_patch_transaction(
        _FragmentBackend(gateway),
        plan,
    )
    current = NativePreanalysisSessionState(evidence_generation=2)
    current._fragment_publication_mark_normalization_staged()
    current._fragment_publication_mark_normalization_validated()
    current._fragment_publication_mark_normalization_published_and_postvalidated()
    current.mark_canonical_semantic_plan_ready()
    authority = SessionFragmentPublicationLifecycleAuthority(
        native_key=NATIVE_KEY,
        state=current,
    )
    authority.record_fragment_staged(plan)
    authority.record_fragment_validated(
        plan,
        old_receipt.prepublication_validation,
    )

    with pytest.raises(ValueError, match="evidence generation"):
        authority.commit_fragment_publication(plan, old_receipt)

    assert current.semantic_fragment_published_postvalidated_generation is None
    assert current.receipt_committed_generation is None


def test_gateway_drives_receipt_backed_lifecycle_port() -> None:
    plan = _plan()
    lifecycle = _ReceiptLifecycleAuthority()
    gateway, _committed, _aborted = _gateway(
        plan,
        lifecycle_authority=lifecycle,
    )

    receipt = gateway.execute_patch_transaction(_FragmentBackend(gateway), plan)

    assert [event for event, _payload in lifecycle.events] == [
        "staged",
        "validated",
        "committed",
    ]
    assert lifecycle.events[-1][1] == (plan, receipt)


def test_gateway_advances_only_normalization_for_normalization_plan() -> None:
    plan = replace(
        _plan(),
        publication_purpose=FragmentPublicationPurpose.FRONTEND_NORMALIZATION,
        work_item_scope=FragmentWorkItemScope(
            work_item_id="gateway-fragment:complete",
            selected_obligation_ids=("route",),
            remaining_obligation_ids=(),
            unreachable_obligation_ids=("dead-route",),
        ),
    )
    lifecycle = NativePreanalysisSessionState(evidence_generation=1)
    gateway, _committed, _aborted = _gateway(
        plan,
        lifecycle_authority=lifecycle,
    )

    gateway.execute_patch_transaction(_FragmentBackend(gateway), plan)

    assert lifecycle.normalization_staged_generation == 1
    assert lifecycle.normalization_validated_generation == 1
    assert lifecycle.normalization_published_postvalidated_generation == 1
    assert lifecycle.normalization_last_unreachable_obligation_ids == (
        "dead-route",
    )
    assert lifecycle.canonical_semantic_plan_generation is None
    assert lifecycle.semantic_fragment_staged_generation is None
    assert lifecycle.receipt_committed_generation is None


def test_partial_normalization_receipt_does_not_advance_generation_authority() -> (
    None
):
    plan = replace(
        _plan(),
        publication_purpose=FragmentPublicationPurpose.FRONTEND_NORMALIZATION,
        work_item_scope=FragmentWorkItemScope(
            work_item_id="gateway-fragment:root@0x401000",
            selected_obligation_ids=("route@0x401000",),
            remaining_obligation_ids=("route@0x402000",),
            unreachable_obligation_ids=("route@0x403000",),
        ),
    )
    lifecycle = NativePreanalysisSessionState(evidence_generation=1)
    gateway, committed, aborted = _gateway(
        plan,
        lifecycle_authority=lifecycle,
    )

    receipt = gateway.execute_patch_transaction(_FragmentBackend(gateway), plan)

    assert receipt in gateway.receipts
    assert len(committed) == 1
    assert aborted == []
    assert lifecycle.normalization_staged_generation is None
    assert lifecycle.normalization_validated_generation is None
    assert lifecycle.normalization_published_postvalidated_generation is None
    assert lifecycle.normalization_work_item_publication_revision == 1
    assert (
        lifecycle.normalization_last_published_work_item_id
        == "gateway-fragment:root@0x401000"
    )
    assert lifecycle.normalization_last_selected_obligation_ids == (
        "route@0x401000",
    )
    assert lifecycle.normalization_last_remaining_obligation_ids == (
        "route@0x402000",
    )
    assert lifecycle.normalization_last_unreachable_obligation_ids == (
        "route@0x403000",
    )


def test_postpublication_failure_poisons_transient_semantic_lifecycle() -> None:
    plan = _plan()
    lifecycle = _semantic_lifecycle()
    gateway, _committed, _aborted = _gateway(
        plan,
        lifecycle_authority=lifecycle,
    )

    with pytest.raises(CfgGenerationPoisoned):
        gateway.execute_patch_transaction(
            _FragmentBackend(gateway, invalid_postobservation=True),
            plan,
        )

    assert lifecycle.semantic_fragment_staged_generation is None
    assert lifecycle.semantic_fragment_validated_generation is None
    assert lifecycle.semantic_fragment_published_postvalidated_generation is None
    assert lifecycle.receipt_committed_generation is None
    assert lifecycle.canonical_semantic_plan_generation == 1
    assert lifecycle.has_pending_generated_restart


def test_postpublication_poison_restores_prior_normalization_authority() -> None:
    plan = replace(
        _plan(),
        publication_purpose=FragmentPublicationPurpose.FRONTEND_NORMALIZATION,
        work_item_scope=FragmentWorkItemScope(
            work_item_id="gateway-fragment:complete",
            selected_obligation_ids=("route",),
            remaining_obligation_ids=(),
            unreachable_obligation_ids=(),
        ),
    )
    lifecycle = NativePreanalysisSessionState(
        evidence_generation=2,
        portable_evidence_ready_generation=2,
        normalization_staged_generation=1,
        normalization_validated_generation=1,
        normalization_published_postvalidated_generation=1,
    )
    gateway, _committed, _aborted = _gateway(
        plan,
        lifecycle_authority=lifecycle,
    )

    with pytest.raises(CfgGenerationPoisoned):
        gateway.execute_patch_transaction(
            _FragmentBackend(gateway, invalid_postobservation=True),
            plan,
        )

    assert lifecycle.normalization_staged_generation == 1
    assert lifecycle.normalization_validated_generation == 1
    assert lifecycle.normalization_published_postvalidated_generation == 1
    assert lifecycle.has_pending_generated_restart
    assert lifecycle.evidence_generation == 2


def test_receipt_event_precedes_committed_semantic_lifecycle_authority() -> None:
    plan = _plan()
    timeline: list[str] = []
    lifecycle = _semantic_lifecycle()
    lifecycle.event_observer = lambda transition: timeline.append(
        transition.operation
    )
    gateway, _committed, _aborted = _gateway(
        plan,
        lifecycle_authority=lifecycle,
    )
    gateway.event_emitter.on(
        MbaMutationCommitted,
        lambda _event: timeline.append("mutation_receipt_committed"),
    )

    gateway.execute_patch_transaction(_FragmentBackend(gateway), plan)

    assert timeline == [
        "semantic_fragment_staged",
        "semantic_fragment_validated",
        "mutation_receipt_committed",
        "semantic_fragment_published_postvalidated",
        "receipt_committed",
    ]


def test_fragment_publication_requires_lifecycle_authority() -> None:
    plan = _plan()
    gateway, _committed, _aborted = _gateway(
        plan,
        lifecycle_authority=None,
    )
    backend = _FragmentBackend(gateway)

    with pytest.raises(TypeError, match="lifecycle authority"):
        gateway.execute_patch_transaction(backend, plan)

    assert backend.calls == []


def test_commit_observer_failure_cannot_trigger_postcommit_root_rollback() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(gateway)

    def _raise(_event) -> None:
        raise RuntimeError("diagnostic sink unavailable")

    gateway.event_emitter.on(MbaMutationCommitted, _raise)

    receipt = gateway.execute_patch_transaction(backend, plan)

    assert receipt.root_publication_confirmed
    assert backend.root_published
    assert "rollback-roots" not in backend.calls
    assert gateway.active is False
    assert gateway.observation_failures[-1].phase == "committed"
    assert len(committed) == 1
    assert aborted == []


def test_inventory_divergence_poisons_without_recovery() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(gateway, omit_semantic_edge_record=True)

    with pytest.raises(CfgGenerationPoisoned, match="operation inventory mismatch"):
        gateway.execute_patch_transaction(backend, plan)

    assert backend.root_published
    assert backend.calls[-1] == "observe"
    assert "rollback-roots" not in backend.calls
    assert "discard" not in backend.calls
    assert gateway.generation == 5
    assert gateway.receipts == ()
    assert committed == []
    assert len(aborted) == 1
    assert "planned=3 applied=2" in aborted[0].reason


def test_prepublication_failure_discards_stage_without_exposing_roots() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(gateway, invalid_preprojection=True)
    original = gateway.identity_index.handle_for_serial(1)
    proxy = gateway.identity_index.logical_proxy_for_handle(original)

    with pytest.raises(
        SemanticFragmentPublicationRejected,
        match="prepublication.*original_supersession:original",
    ):
        gateway.execute_patch_transaction(backend, plan)

    assert backend.calls == ["plan-roots", "snapshot"]
    assert not backend.root_published
    assert proxy.resolve().handle is original
    assert gateway.generation == 5
    assert committed == []
    assert aborted == []


def test_preflight_rejection_is_clean_and_same_generation_remains_usable() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)

    with pytest.raises(SemanticFragmentPublicationRejected):
        gateway.execute_patch_transaction(
            _FragmentBackend(gateway, invalid_preprojection=True),
            plan,
        )

    assert gateway.generation == 5
    assert gateway.generation_poisoned is False
    assert gateway.transaction_failure is not None
    assert gateway.transaction_failure.phase is CfgTransactionPhase.REJECTED_CLEAN
    assert gateway.transaction_failure.first_failed_obligation == (
        "original_supersession:original"
    )
    receipt = gateway.execute_patch_transaction(_FragmentBackend(gateway), plan)
    assert receipt.pre_generation == 5
    assert receipt.post_generation == 6
    assert len(committed) == 1
    assert aborted == []


@pytest.mark.parametrize(
    "failpoint,failed_phase,interr_code,expected_tail",
    (
        (
            "raise_after_insertion",
            "stage",
            50856,
            ("plan-roots", "snapshot", "stage"),
        ),
        (
            "raise_after_observation",
            "postpublication_observation",
            50860,
            (
                "plan-roots",
                "snapshot",
                "stage",
                "prepare-roots",
                "publish-roots",
                "rebuild",
                "observe",
            ),
        ),
    ),
)
def test_live_divergence_poisons_generation_without_cleanup_and_restarts_once(
    failpoint: str,
    failed_phase: str,
    interr_code: int,
    expected_tail: tuple[str, ...],
) -> None:
    plan = _plan()
    lifecycle = _semantic_lifecycle()
    gateway, committed, aborted = _gateway(
        plan,
        lifecycle_authority=lifecycle,
    )
    backend = _FragmentBackend(gateway, **{failpoint: True})

    with pytest.raises(CfgGenerationPoisoned) as caught:
        gateway.execute_patch_transaction(backend, plan)

    failure = caught.value.failure
    assert failure.phase is CfgTransactionPhase.POISONED_RESTART_REQUIRED
    assert failure.live_mutation_started is True
    assert failure.failure_phase == failed_phase
    assert failure.interr_code == interr_code
    assert failure.first_failed_obligation == f"runtime:{failed_phase}"
    assert gateway.generation_poisoned is True
    assert gateway.mutation_started is True
    assert gateway.transaction_failure == failure
    assert tuple(backend.calls) == expected_tail
    assert "rollback-roots" not in backend.calls
    assert "rebuild" not in backend.calls[len(expected_tail) :]
    assert "discard" not in backend.calls
    assert committed == []
    assert len(aborted) == 1
    assert lifecycle.has_pending_generated_restart
    assert gateway.lifecycle_authority is not None
    assert not gateway.lifecycle_authority.request_poisoned_generation_restart(
        plan,
        failure,
    )
    assert lifecycle.consume_generated_restart()
    assert not lifecycle.consume_generated_restart()

    get_mblock_calls = backend.get_mblock_calls
    with pytest.raises(CfgGenerationPoisoned):
        gateway.resolve_serial(1)
    with pytest.raises(CfgGenerationPoisoned):
        gateway.resolve_block(backend.replacement_handle)
    with pytest.raises(CfgGenerationPoisoned):
        gateway.execute_patch_transaction(_FragmentBackend(gateway), plan)
    assert backend.get_mblock_calls == get_mblock_calls


def test_generation_poison_invalidates_sibling_gateway_over_shared_index() -> None:
    plan = _plan()
    lifecycle = _semantic_lifecycle()
    gateway, _committed, _aborted = _gateway(
        plan,
        lifecycle_authority=lifecycle,
    )
    sibling = gateway.new_transaction()

    with pytest.raises(CfgGenerationPoisoned):
        gateway.execute_patch_transaction(
            _FragmentBackend(gateway, raise_after_insertion=True),
            plan,
        )

    assert sibling.generation_poisoned
    assert sibling.transaction_failure == gateway.transaction_failure
    with pytest.raises(CfgGenerationPoisoned):
        sibling.resolve_serial(1)
    with pytest.raises(CfgGenerationPoisoned):
        sibling.identity_index.identity_for_serial(1)
    with pytest.raises(CfgGenerationPoisoned):
        sibling.begin_batch(StructuralMutationKind.BLOCK_INSERT)
    with pytest.raises(CfgGenerationPoisoned):
        sibling.new_transaction()
    with pytest.raises(CfgGenerationPoisoned):
        sibling.identity_index.advance_generation()

    fresh_gateway, _fresh_committed, _fresh_aborted = _gateway(
        plan,
        lifecycle_authority=_semantic_lifecycle(),
    )
    assert fresh_gateway.identity_index is not sibling.identity_index
    assert fresh_gateway.generation_poisoned is False


@pytest.mark.parametrize(
    "operation",
    (
        lambda index: index.identity_for_serial(0),
        lambda index: index.create_synthetic_handle(),
        lambda index: index.begin_transaction("late-transaction"),
        lambda index: index.record_realized_serial(
            transaction_id="late-transaction",
            expected_serial=0,
            returned_serial=0,
        ),
        lambda index: index.refresh_from_flow_graph(object()),
    ),
    ids=("resolve", "allocate", "begin", "record", "refresh"),
)
def test_shared_poison_rejects_direct_identity_index_operations(operation) -> None:
    plan = _plan()
    gateway, _committed, _aborted = _gateway(
        plan,
        lifecycle_authority=_semantic_lifecycle(),
    )
    identity_index = gateway.identity_index

    with pytest.raises(CfgGenerationPoisoned):
        gateway.execute_patch_transaction(
            _FragmentBackend(gateway, raise_after_insertion=True),
            plan,
        )

    with pytest.raises(CfgGenerationPoisoned):
        operation(identity_index)


@pytest.mark.parametrize(
    "category,postcondition",
    (
        ("duplicate-or-unknown-ownership", FragmentValidationPostcondition.IDENTITY_OWNERSHIP),
        ("missing-route-arms", FragmentValidationPostcondition.IDENTITY_OWNERSHIP),
        ("incomplete-terminal", FragmentValidationPostcondition.TERMINAL_RETURN_INTEGRITY),
        ("invalid-topology", FragmentValidationPostcondition.BLOCK_TOPOLOGY),
        ("unreachable-root", FragmentValidationPostcondition.ROOT_REACHABILITY),
        ("stale-or-ambiguous-binding", FragmentValidationPostcondition.IDENTITY_OWNERSHIP),
        ("data-flow", FragmentValidationPostcondition.USE_DEF_INTEGRITY),
        ("flag-corridor", FragmentValidationPostcondition.FLAG_CORRIDOR_INTEGRITY),
        ("value-range", FragmentValidationPostcondition.VALUE_RANGE_PROVEN),
        ("atomic-fit", FragmentValidationPostcondition.TERMINAL_ROUTE_ATOMICITY),
    ),
)
def test_every_preflight_obligation_rejects_before_any_mutation(
    monkeypatch,
    category: str,
    postcondition: FragmentValidationPostcondition,
) -> None:
    plan = _plan()
    definition = FragmentValueSite(
        site_id="value.def",
        block_id="replacement",
        value_id="value",
        instruction_ea=0x401000,
        storage_identity=StorageIdentity(StorageIdentityKind.REGISTER, 10),
        width=4,
    )
    use = FragmentValueSite(
        site_id="value.use",
        block_id="replacement",
        value_id="value",
        instruction_ea=0x401004,
        storage_identity=definition.storage_identity,
        width=4,
    )
    if category == "data-flow":
        plan = replace(
            plan,
            data_flow_obligations=(
                FragmentDataFlowObligation(
                    obligation_id="value-flow",
                    role=FragmentDataFlowRole.STATE_VALUE,
                    definition=definition,
                    uses=(use,),
                ),
            ),
        )
    elif category == "flag-corridor":
        plan = replace(
            plan,
            flag_corridors=(
                FragmentFlagCorridor(
                    corridor_id="value-flags",
                    producer=definition,
                    consumer=use,
                    block_path=("replacement",),
                    permitted_flag_write_eas=frozenset({0x401000}),
                ),
            ),
        )
    elif category == "value-range":
        plan = replace(
            plan,
            data_flow_obligations=(
                FragmentDataFlowObligation(
                    obligation_id="value-flow",
                    role=FragmentDataFlowRole.STATE_VALUE,
                    definition=definition,
                    uses=(use,),
                ),
            ),
            value_range_assumptions=(
                FragmentRangeAssumption(
                    assumption_id="value-domain",
                    site=definition,
                    observation=FragmentRangeObservation.AFTER_INSTRUCTION,
                    lo=0,
                    hi=1,
                ),
            ),
        )
    elif category in {"incomplete-terminal", "atomic-fit"}:
        plan = _plan_with_terminal_effects()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(gateway)
    generation = gateway.generation
    snapshot_preparation = backend._snapshot_semantic_fragment_inputs(plan)
    snapshot_inputs = snapshot_preparation.authority.projection_input
    backend.calls.clear()
    blocks = list(snapshot_inputs.blocks)
    bindings = list(snapshot_inputs.identity_bindings)
    if category == "duplicate-or-unknown-ownership":
        bindings[2] = replace(
            bindings[0],
            block_id="target",
        )
    elif category == "missing-route-arms":
        blocks = [block for block in blocks if block.block_id != "target"]
        bindings = [binding for binding in bindings if binding.block_id != "target"]
    elif category == "invalid-topology":
        blocks[1] = replace(blocks[1], physical_position=blocks[0].physical_position)
    elif category == "unreachable-root":
        snapshot_inputs = replace(snapshot_inputs, entry_block_id="dispatcher")
    elif category == "stale-or-ambiguous-binding":
        bindings[1] = replace(bindings[1], state=FragmentBindingState.STAGED)
    mutated_inputs = replace(
        snapshot_inputs,
        blocks=tuple(blocks),
        identity_bindings=tuple(bindings),
        data_flow_relations=(
            (
                ProjectedDataFlowRelation(
                    value_id="value",
                    definition_site_id="value.def",
                    use_site_id="value.use",
                    use_def_observed=True,
                    def_use_observed=True,
                ),
            )
            if category == "value-range"
            else snapshot_inputs.data_flow_relations
        ),
    )
    mutated = replace(
        snapshot_preparation,
        authority=replace(
            snapshot_preparation.authority,
            projection_input=mutated_inputs,
        ),
    )
    monkeypatch.setattr(
        backend,
        "_snapshot_semantic_fragment_inputs",
        lambda _plan: (backend.calls.append("snapshot") or mutated),
    )

    with pytest.raises(SemanticFragmentPublicationRejected) as caught:
        gateway.execute_patch_transaction(backend, plan)

    assert postcondition in {
        failure.postcondition for failure in caught.value.validation.failures
    }
    assert caught.value.validation.failures[0].subject_id
    assert caught.value.validation.failures[0].reason
    assert backend.calls == ["plan-roots", "snapshot"]
    assert gateway.active is False
    assert gateway.generation == generation
    assert gateway.receipts == ()
    assert committed == []
    assert aborted == []


def test_typed_projection_failure_classification_does_not_depend_on_reason_wording(
    monkeypatch,
) -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(gateway)
    monkeypatch.setattr(
        backend,
        "_snapshot_semantic_fragment_inputs",
        lambda _plan: (_ for _ in ()).throw(
            FragmentProjectionFailure(
                FragmentValidationPostcondition.VALUE_RANGE_PROVEN,
                "range-proof",
                "arbitrary wording with no classification keywords",
            )
        ),
    )

    with pytest.raises(SemanticFragmentPublicationRejected) as caught:
        gateway.execute_patch_transaction(backend, plan)

    assert caught.value.validation.failures == (
        FragmentValidationOutcome(
            postcondition=FragmentValidationPostcondition.VALUE_RANGE_PROVEN,
            subject_id="range-proof",
            passed=False,
            reason="arbitrary wording with no classification keywords",
        ),
    )
    assert gateway.active is False
    assert gateway.receipts == ()
    assert committed == []
    assert aborted == []


def test_postpublication_failure_poisons_without_restoring_roots() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(gateway, invalid_postobservation=True)
    original = gateway.identity_index.handle_for_serial(1)
    proxy = gateway.identity_index.logical_proxy_for_handle(original)

    with pytest.raises(CfgGenerationPoisoned, match="postpublication"):
        gateway.execute_patch_transaction(backend, plan)

    assert backend.calls == [
        "plan-roots",
        "snapshot",
        "stage",
        "prepare-roots",
        "publish-roots",
        "rebuild",
        "observe",
    ]
    assert backend.root_published
    assert proxy.resolve().handle is original
    assert gateway.generation == 5
    assert committed == []
    assert len(aborted) == 1
    assert gateway.transaction_failure is not None
    assert gateway.transaction_failure.first_failed_obligation == (
        "postvalidation_coverage:original_supersession:original"
    )


def test_postpublication_detached_operation_poisons_before_receipt() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(
        gateway,
        disconnect_root_after_publication=True,
    )

    with pytest.raises(CfgGenerationPoisoned, match="postpublication"):
        gateway.execute_patch_transaction(backend, plan)

    assert backend.calls == [
        "plan-roots",
        "snapshot",
        "stage",
        "prepare-roots",
        "publish-roots",
        "rebuild",
        "observe",
    ]
    assert committed == []
    assert gateway.receipts == ()
    assert len(aborted) == 1
    assert aborted[0].postpublication_validation is not None
    failures = {
        (outcome.postcondition, outcome.subject_id): outcome
        for outcome in aborted[0].postpublication_validation.failures
    }
    operation_failure = failures[
        (
            FragmentValidationPostcondition.OPERATION_REACHABILITY,
            "direct-route",
        )
    ]
    assert operation_failure.block_ids == ("replacement",)
    assert aborted[0].rollback_attempted is False
    assert aborted[0].rollback_succeeded is None


def test_partial_root_publication_exception_poisons_without_rollback() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(gateway, raise_during_publish=True)

    with pytest.raises(CfgGenerationPoisoned, match="partial root publication"):
        gateway.execute_patch_transaction(backend, plan)

    assert backend.calls == [
        "plan-roots",
        "snapshot",
        "stage",
        "prepare-roots",
        "publish-roots",
    ]
    assert backend.root_published
    assert committed == []
    assert len(aborted) == 1


def test_poison_path_never_invokes_even_a_failing_rollback() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(
        gateway,
        invalid_postobservation=True,
        raise_during_rollback=True,
    )

    with pytest.raises(CfgGenerationPoisoned, match="postpublication"):
        gateway.execute_patch_transaction(backend, plan)

    assert backend.root_published
    assert "rollback-roots" not in backend.calls
    assert "discard" not in backend.calls
    assert gateway.generation == 5
    assert committed == []
    assert len(aborted) == 1
    assert "postpublication" in aborted[0].reason


def test_stage_verifier_and_rollback_failures_remain_separate() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(
        gateway,
        raise_during_stage=True,
        raise_during_discard=True,
    )

    with pytest.raises(
        SemanticFragmentRollbackFailed,
        match="staged semantic fragment discard",
    ):
        gateway.execute_patch_transaction(backend, plan)

    assert backend.calls == ["plan-roots", "snapshot", "stage", "discard"]
    assert committed == []
    assert len(aborted) == 1
    assert [
        (
            failure.failure_kind,
            failure.phase,
            failure.error_type,
            failure.error_message,
            failure.interr_code,
            failure.verification_context,
        )
        for failure in aborted[0].fragment_failures
    ] == [
        (
            "stage",
            "stage",
            "LookupError",
            "fragment plan requires an imported native-body materializer",
            None,
            "",
        ),
        (
            "verifier",
            "stage_cleanup",
            "RuntimeError",
            "INTERR: 50856",
            50856,
            "staged semantic fragment rollback sweep",
        ),
        (
            "rollback",
            "rollback",
            "RuntimeError",
            "staged semantic fragment discard cannot remove entry or stop blocks",
            None,
            "",
        ),
    ]


def test_backend_without_complete_internal_publication_port_is_rejected() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)

    with pytest.raises(TypeError, match="complete semantic-fragment backend port"):
        gateway.execute_patch_transaction(
            SimpleNamespace(mba=SimpleNamespace(qty=4)), plan
        )

    assert not gateway.active
    assert committed == []
    assert aborted == []


def test_generic_commit_cannot_bypass_fragment_postvalidation() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    gateway.begin_batch(
        StructuralMutationKind.FRAGMENT_PUBLICATION,
        serial_quantity=4,
        planned_operation_count=1,
        fragment_plan=plan,
        fragment_root_publication_groups=(
            MbaMutationRootPublicationGroup(
                group_id="root-group:entry",
                predecessor_block_id="entry",
                predecessor_anchor_ea=plan.block("entry").semantic_anchor_ea,
                edge_ids=("replacement:entry:direct",),
                edge_roles=(SemanticEdgeRole.DIRECT,),
                original_block_ids=("original",),
                replacement_block_ids=("replacement",),
            ),
        ),
    )
    gateway.record_edge_redirect()

    with pytest.raises(
        RuntimeError,
        match="cannot commit before semantic postvalidation",
    ):
        gateway.commit()

    assert gateway.active
    assert gateway.generation == 5
    assert committed == []
    gateway.abort(reason="test cleanup")
    assert len(aborted) == 1
