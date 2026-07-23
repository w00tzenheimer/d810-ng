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
from d810.hexrays.mutation.semantic_fragment_inventory import (
    SemanticFragmentRootInventory,
    SemanticFragmentRootInventoryItem,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.flowgraph import BlockKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.manager.fragment_publication_lifecycle import (
    SessionFragmentPublicationLifecycleAuthority,
)
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentEdge,
    FragmentNativeBody,
    FragmentOperation,
    FragmentPlan,
    FragmentPublicationPurpose,
    FragmentReturnCarrier,
    FragmentReturnSource,
    FragmentReturnSourceKind,
    FragmentTerminalReturn,
    FragmentTerminalRoute,
    FragmentWorkItemScope,
)
from d810.transforms.fragment_validation import (
    FragmentBindingState,
    FragmentValidationPostcondition,
    ProjectedFragment,
    ProjectedFragmentBlock,
    ProjectedIdentityBinding,
    PublishedFragmentObservation,
    validate_fragment_projection,
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
        raise_during_publish: bool = False,
        raise_during_rollback: bool = False,
        omit_semantic_edge_record: bool = False,
    ) -> None:
        self.mba = SimpleNamespace(qty=4)
        self.gateway = gateway
        self.invalid_preprojection = invalid_preprojection
        self.invalid_postobservation = invalid_postobservation
        self.raise_during_publish = raise_during_publish
        self.raise_during_rollback = raise_during_rollback
        self.omit_semantic_edge_record = omit_semantic_edge_record
        self.calls: list[str] = []
        self.root_published = False
        self.projection: ProjectedFragment | None = None
        self.original_handle = None
        self.replacement_handle = None

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

    def _stage_semantic_fragment(self, plan: FragmentPlan) -> ProjectedFragment:
        self.calls.append("stage")
        index = self.gateway.identity_index
        original = index.handle_for_serial(1)
        assert original is not None
        replacement = index.create_native_handle(
            plan.block("replacement").stable_identity
        )
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
                ),
                ProjectedFragmentBlock(
                    block_id="replacement",
                    kind=BlockKind.ONE_WAY,
                    successors=("target",),
                    predecessors=replacement_predecessors,
                    physical_position=1,
                ),
                ProjectedFragmentBlock(
                    block_id="target",
                    kind=BlockKind.ZERO_WAY,
                    successors=(),
                    predecessors=("replacement",),
                    physical_position=2,
                ),
                ProjectedFragmentBlock(
                    block_id="original",
                    kind=BlockKind.ZERO_WAY,
                    successors=(),
                    predecessors=original_predecessors,
                    physical_position=3,
                ),
                ProjectedFragmentBlock(
                    block_id="dispatcher",
                    kind=BlockKind.ZERO_WAY,
                    successors=(),
                    predecessors=(),
                    physical_position=4,
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
        self.projection = projection
        return projection

    def _discard_staged_semantic_fragment(self, _plan: FragmentPlan) -> None:
        self.calls.append("discard")

    def _prepare_semantic_fragment_root_publication(
        self,
        plan: FragmentPlan,
        inventory: SemanticFragmentRootInventory,
    ):
        assert inventory.plan_id == plan.plan_id
        assert inventory.atomic_group_id == plan.atomic_group_id
        self.calls.append("prepare-roots")
        return "prior-root-authority"

    def _publish_semantic_fragment_roots(
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

    def _rebuild_semantic_fragment_chains(self, _plan: FragmentPlan) -> None:
        self.calls.append("rebuild")

    def _observe_published_semantic_fragment(
        self,
        plan: FragmentPlan,
    ) -> PublishedFragmentObservation:
        self.calls.append("observe")
        assert self.root_published
        assert self.gateway.receipts == ()
        assert self.projection is not None
        validation = validate_fragment_projection(plan, self.projection)
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
        return PublishedFragmentObservation(
            plan_id=plan.plan_id,
            atomic_group_id=plan.atomic_group_id,
            published_root_ids=plan.roots,
            observable_operations=plan.operations,
            semantic_outcomes=outcomes,
            fallthrough_helpers=self.projection.fallthrough_helpers,
            root_fallthrough_helpers=self.projection.root_fallthrough_helpers,
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
    gateway.event_emitter.on(MbaMutationPlanned, planned.append)

    receipt = gateway.publish_semantic_fragment(backend, plan)

    assert backend.calls == [
        "plan-roots",
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
            ),
        ),
    )

    gateway._begin_semantic_fragment_batch(
        SimpleNamespace(mba=SimpleNamespace(qty=4)),
        plan,
        inventory,
    )

    assert len(planned) == 1
    assert planned[0].planned_operation_count == 6
    assert tuple(item.mutation_kind for item in planned[0].items) == (
        "semantic_fragment_replacement_materialization",
        "semantic_fragment_native_body_materialization",
        "semantic_fragment_return_carrier_materialization",
        "semantic_fragment_terminal_return_materialization",
        "semantic_fragment_direct",
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

    receipt = gateway.publish_semantic_fragment(_FragmentBackend(gateway), plan)

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

    gateway.publish_semantic_fragment(_FragmentBackend(gateway), plan)

    assert lifecycle.canonical_semantic_plan_generation == 1
    assert timeline[:3] == [
        "canonical_semantic_plan_ready",
        "semantic_fragment_staged",
        "semantic_fragment_validated",
    ]


def test_lifecycle_authority_rejects_receipt_from_older_evidence_generation() -> None:
    plan = _plan()
    gateway, _committed, _aborted = _gateway(plan)
    old_receipt = gateway.publish_semantic_fragment(
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

    receipt = gateway.publish_semantic_fragment(_FragmentBackend(gateway), plan)

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
        ),
    )
    lifecycle = NativePreanalysisSessionState(evidence_generation=1)
    gateway, _committed, _aborted = _gateway(
        plan,
        lifecycle_authority=lifecycle,
    )

    gateway.publish_semantic_fragment(_FragmentBackend(gateway), plan)

    assert lifecycle.normalization_staged_generation == 1
    assert lifecycle.normalization_validated_generation == 1
    assert lifecycle.normalization_published_postvalidated_generation == 1
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
        ),
    )
    lifecycle = NativePreanalysisSessionState(evidence_generation=1)
    gateway, committed, aborted = _gateway(
        plan,
        lifecycle_authority=lifecycle,
    )

    receipt = gateway.publish_semantic_fragment(_FragmentBackend(gateway), plan)

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


def test_postpublication_failure_aborts_transient_semantic_lifecycle() -> None:
    plan = _plan()
    lifecycle = _semantic_lifecycle()
    gateway, _committed, _aborted = _gateway(
        plan,
        lifecycle_authority=lifecycle,
    )

    with pytest.raises(SemanticFragmentPublicationRejected):
        gateway.publish_semantic_fragment(
            _FragmentBackend(gateway, invalid_postobservation=True),
            plan,
        )

    assert lifecycle.semantic_fragment_staged_generation is None
    assert lifecycle.semantic_fragment_validated_generation is None
    assert lifecycle.semantic_fragment_published_postvalidated_generation is None
    assert lifecycle.receipt_committed_generation is None
    assert lifecycle.canonical_semantic_plan_generation == 1


def test_postpublication_failure_restores_prior_normalization_authority() -> None:
    plan = replace(
        _plan(),
        publication_purpose=FragmentPublicationPurpose.FRONTEND_NORMALIZATION,
        work_item_scope=FragmentWorkItemScope(
            work_item_id="gateway-fragment:complete",
            selected_obligation_ids=("route",),
            remaining_obligation_ids=(),
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

    with pytest.raises(SemanticFragmentPublicationRejected):
        gateway.publish_semantic_fragment(
            _FragmentBackend(gateway, invalid_postobservation=True),
            plan,
        )

    assert lifecycle.normalization_staged_generation == 1
    assert lifecycle.normalization_validated_generation == 1
    assert lifecycle.normalization_published_postvalidated_generation == 1
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

    gateway.publish_semantic_fragment(_FragmentBackend(gateway), plan)

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
        gateway.publish_semantic_fragment(backend, plan)

    assert backend.calls == []


def test_commit_observer_failure_cannot_trigger_postcommit_root_rollback() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(gateway)

    def _raise(_event) -> None:
        raise RuntimeError("diagnostic sink unavailable")

    gateway.event_emitter.on(MbaMutationCommitted, _raise)

    receipt = gateway.publish_semantic_fragment(backend, plan)

    assert receipt.root_publication_confirmed
    assert backend.root_published
    assert "rollback-roots" not in backend.calls
    assert gateway.active is False
    assert gateway.observation_failures[-1].phase == "committed"
    assert len(committed) == 1
    assert aborted == []


def test_gateway_aborts_when_applied_operations_do_not_match_inventory() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(gateway, omit_semantic_edge_record=True)

    with pytest.raises(
        RuntimeError,
        match=r"operation inventory mismatch: planned=3 applied=2",
    ):
        gateway.publish_semantic_fragment(backend, plan)

    assert not backend.root_published
    assert backend.calls[-3:] == ["rollback-roots", "rebuild", "discard"]
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
        gateway.publish_semantic_fragment(backend, plan)

    assert backend.calls == ["plan-roots", "stage", "discard"]
    assert not backend.root_published
    assert proxy.resolve().handle is original
    assert gateway.generation == 5
    assert committed == []
    assert len(aborted) == 1
    assert "original_supersession:original" in aborted[0].reason


def test_postpublication_failure_restores_roots_then_discards_stage() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(gateway, invalid_postobservation=True)
    original = gateway.identity_index.handle_for_serial(1)
    proxy = gateway.identity_index.logical_proxy_for_handle(original)

    with pytest.raises(
        SemanticFragmentPublicationRejected,
        match="postpublication.*postvalidation_coverage",
    ):
        gateway.publish_semantic_fragment(backend, plan)

    assert backend.calls == [
        "plan-roots",
        "stage",
        "prepare-roots",
        "publish-roots",
        "rebuild",
        "observe",
        "rollback-roots",
        "rebuild",
        "discard",
    ]
    assert not backend.root_published
    assert proxy.resolve().handle is original
    assert gateway.generation == 5
    assert committed == []
    assert len(aborted) == 1


def test_partial_root_publication_exception_still_rolls_back() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(gateway, raise_during_publish=True)

    with pytest.raises(RuntimeError, match="partial root publication"):
        gateway.publish_semantic_fragment(backend, plan)

    assert backend.calls == [
        "plan-roots",
        "stage",
        "prepare-roots",
        "publish-roots",
        "rollback-roots",
        "rebuild",
        "discard",
    ]
    assert not backend.root_published
    assert committed == []
    assert len(aborted) == 1


def test_rollback_failure_is_fatal_and_never_commits_a_receipt() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(
        gateway,
        invalid_postobservation=True,
        raise_during_rollback=True,
    )

    with pytest.raises(SemanticFragmentRollbackFailed, match="root rollback failed"):
        gateway.publish_semantic_fragment(backend, plan)

    assert backend.root_published
    assert "discard" in backend.calls
    assert gateway.generation == 5
    assert committed == []
    assert len(aborted) == 1
    assert "rollback failed" in aborted[0].reason


def test_backend_without_complete_internal_publication_port_is_rejected() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)

    with pytest.raises(TypeError, match="complete semantic-fragment backend port"):
        gateway.publish_semantic_fragment(
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
