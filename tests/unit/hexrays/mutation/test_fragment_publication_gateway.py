"""Gateway-owned semantic-fragment publication and rollback."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from d810.hexrays.mutation import mba_mutation_events as mutation_events
from d810.hexrays.mutation import semantic_fragment_publication as publication
from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.core.events import EventEmitter
from d810.core.semantic_route_oracle import (
    ReferenceRouteRewrite,
    RouteOracleRun,
    SemanticTransferKind,
)
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.mba_mutation_events import (
    MbaCfgTransactionAuthorityObserved,
    MbaMutationAborted,
    MbaMutationCommitted,
    MbaMutationGateway,
    MbaMutationPlanned,
    MbaMutationRootPublicationGroup,
    MbaSemanticFragmentRouteOracleCompared,
    StructuralMutationKind,
)
from d810.hexrays.mutation.semantic_fragment_publication import (
    SemanticFragmentPublicationRejected,
    SemanticFragmentRollbackFailed,
)
from d810.hexrays.mutation.semantic_fragment_preparation import (
    PreparedSemanticFragment,
    PreparedSemanticFragmentAuthority,
    SemanticFragmentRealizationPayload,
    SemanticFragmentSnapshotAuthority,
    SemanticFragmentSnapshotPreparation,
)
from d810.hexrays.mutation.semantic_fragment_inventory import (
    SemanticFragmentRootInventory,
    SemanticFragmentRootInventoryItem,
)
from d810.hexrays.mutation.semantic_fragment_profile import (
    SemanticFragmentPublicationProfile,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.block_identity import (
    CurrentMbaBlockIdentityBinding,
    CurrentMbaIdentityBindingSnapshot,
    NativeEaInterval,
    StableBlockIdentity,
)
from d810.ir.flowgraph import BlockKind, InsnKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.manager.fragment_publication_lifecycle import (
    SessionFragmentPublicationLifecycleAuthority,
)
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentDirectTransferRewrite,
    FragmentEdge,
    FragmentNativeBody,
    FragmentOperation,
    FragmentPlan,
    FragmentPublicationPurpose,
    FragmentReferenceRouteAuthority,
    FragmentReturnCarrier,
    FragmentReturnSource,
    FragmentReturnSourceKind,
    FragmentTerminalReturn,
    FragmentTerminalRoute,
    FragmentWorkItemScope,
)
from d810.transforms.fragment_projection import (
    FragmentProjectionBlockInput,
    FragmentProjectionInput,
    fragment_cfg_projection,
    project_fragment,
)
from d810.transforms.cfg_transaction import (
    CfgGenerationPoisoned,
    CfgTransactionPhase,
    PlanBlockRef,
    TransactionAttemptId,
)
from d810.transforms.fragment_validation import (
    FragmentBindingState,
    FragmentValidationPostcondition,
    ProjectedFragment,
    ProjectedFragmentBlock,
    ProjectedIdentityBinding,
    PublishedFragmentObservation,
    PublishedFragmentGraphObservation,
    validate_published_fragment_projection,
)
from d810.transforms.fragment_to_patch import lower_fragment_plan
from tests.native_preanalysis import make_native_key


_FIXTURE_SHA256 = "a" * 64
NATIVE_KEY = make_native_key(
    input_identity=f"sha256:{_FIXTURE_SHA256}",
    function_rva=0x40A560,
)
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


def test_generated_plan_inventory_excludes_logical_in_place_root_write() -> None:
    plan = _plan()
    inventory = SemanticFragmentRootInventory(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        items=(
            SemanticFragmentRootInventoryItem(
                edge_id="root:entry:direct:original",
                root_block_id="replacement",
                original_block_id="original",
                predecessor_block_id="entry",
                role=SemanticEdgeRole.DIRECT,
                requires_helper=False,
            ),
        ),
    )
    gateway, _committed, _aborted = _gateway(plan)

    cfg_ready = gateway._fragment_plan_items(plan, inventory)
    generated = gateway._fragment_plan_items(
        plan,
        inventory,
        SemanticFragmentPublicationProfile.GENERATED_GRAPH_FREE,
    )

    assert len(cfg_ready) == 3
    assert len(generated) == 2
    assert tuple(item.mutation_kind for item in generated) == (
        "semantic_fragment_replacement_materialization",
        "semantic_fragment_direct",
    )


def _plan_with_reference_route() -> FragmentPlan:
    plan = _plan()
    source_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x401000, 0x401004),
    )
    reference_route = ReferenceRouteRewrite(
        route_id="rhad:0x40A560:flow_route:0x401004",
        function_ea=0x40A560,
        owner_ea=0x401000,
        rewrite_anchor_ea=0x401004,
        corridor=((0x401000, 0x401010),),
        reference_phase="flow_route",
        original_transfer_kind=SemanticTransferKind.CONDITIONAL,
        final_transfer_kind=SemanticTransferKind.DIRECT,
        direct_target_ea=0x402000,
        reference_ledger_identity="flow_route:0x401004",
        reference_ledger_json='{"status":"committed"}',
    )
    operation = FragmentOperation(
        operation_id="route:state_assignment@0x401004:0x1",
        source_block_id="replacement",
        direct_transfer_rewrite=FragmentDirectTransferRewrite(
            route_proof_id="state_assignment@0x401004:0x1",
            owner_identity=source_identity,
            owner_anchor_ea=0x401000,
            rewrite_anchor_ea=0x401004,
            delivery_region=NativeEaInterval(0x401004, 0x401010),
            proof_corridor_instruction_eas=(0x401000, 0x401004),
            superseded_instruction_eas=(0x401004,),
            source_transfer_kind=SemanticTransferKind.CONDITIONAL,
        ),
        reference_route_authority=FragmentReferenceRouteAuthority(
            reference_route=reference_route,
            candidate_rewrite_anchor_ea=0x401004,
            imported_closure_block_ids=(),
        ),
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.DIRECT,
                target_block_id="target",
            ),
        ),
    )
    return replace(
        plan,
        blocks=tuple(
            replace(block, stable_identity=source_identity)
            if block.block_id in {"original", "replacement"}
            else block
            for block in plan.blocks
        ),
        operations=(operation,),
        reference_oracle_run=RouteOracleRun(
            run_id="a560-v33-gateway-route",
            function_ea=0x40A560,
            fixture_sha256=_FIXTURE_SHA256,
            reference_binary_sha256="b" * 64,
            candidate_binary_sha256=_FIXTURE_SHA256,
            reference_commit="21b0d4783703bc4fb6910cfae51d92cd683d2c65",
            runtime_image="d810-idapro-9.3-test-runtime:py313-v1",
            runtime_image_id="sha256:" + "c" * 64,
            cache_disabled=True,
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
                state_write_block_id="replacement",
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

    def request_cfg_generation_restart(self, attempt, failure) -> bool:
        self.events.append(("cfg_poisoned", (attempt, failure)))
        return True

    def committed_semantic_ownership(self):
        return ()


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
        stage_cleanup_failed: bool = False,
        raise_during_discard: bool = False,
        raise_during_publish: bool = False,
        raise_during_rollback: bool = False,
        omit_semantic_edge_record: bool = False,
        disconnect_root_after_publication: bool = False,
        raise_after_insertion: bool = False,
        raise_after_observation: bool = False,
        current_mba_identity_binding: CurrentMbaIdentityBindingSnapshot | None = None,
        finalized_current_mba_identity_binding: CurrentMbaIdentityBindingSnapshot
        | None = None,
        malformed_route_projection: bool = False,
        raise_during_generated_verify: bool = False,
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
        self.stage_cleanup_failed = stage_cleanup_failed
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
        self.finalized_current_mba_identity_binding = (
            finalized_current_mba_identity_binding
        )
        self.malformed_route_projection = malformed_route_projection
        self.raise_during_generated_verify = raise_during_generated_verify
        self.calls: list[str] = []
        self.root_published = False
        self.projection: ProjectedFragment | None = None
        self.original_handle = None
        self.replacement_handle = None

    def _generated_semantic_fragment_plan_handle(
        self,
        plan: FragmentPlan,
        block_id: str,
    ):
        serial_by_id = {
            "entry": 0,
            "original": 1,
            "replacement": 1,
            "target": 2,
            "dispatcher": 3,
        }
        handle = self.gateway.identity_index.handle_for_serial(
            serial_by_id[str(block_id)]
        )
        assert handle is not None
        return handle

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
        original_predecessors = (
            ("entry", "target") if self.invalid_preprojection else ("entry",)
        )
        projection_input = FragmentProjectionInput(
            snapshot_id="snapshot:gateway-fragment",
            entry_block_id="entry",
            blocks=(
                FragmentProjectionBlockInput(
                    "entry",
                    BlockKind.ONE_WAY,
                    ("original",),
                    (),
                    0,
                    None,
                    None,
                    InsnKind.GOTO,
                ),
                FragmentProjectionBlockInput(
                    "original",
                    BlockKind.ZERO_WAY,
                    (),
                    original_predecessors,
                    1,
                    None,
                    None,
                    InsnKind.UNKNOWN,
                    instruction_eas=(0x401000, 0x401004),
                ),
                FragmentProjectionBlockInput(
                    "target",
                    (BlockKind.ONE_WAY if target_successors else BlockKind.ZERO_WAY),
                    target_successors,
                    (),
                    2,
                    None,
                    None,
                    (InsnKind.GOTO if target_successors else InsnKind.UNKNOWN),
                ),
                FragmentProjectionBlockInput(
                    "dispatcher",
                    BlockKind.ZERO_WAY,
                    (),
                    (),
                    3,
                    None,
                    None,
                    InsnKind.UNKNOWN,
                ),
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
                constant_materializations=(),
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

    def _realize_semantic_patch_plan(
        self,
        patch_plan,
        prepared_fragment: PreparedSemanticFragment,
    ) -> ProjectedFragment:
        plan = patch_plan.semantic_contract.fragment_plan
        self.calls.append("stage")
        assert self.gateway._active_prepared_semantic_fragment is prepared_fragment
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
                if self.stage_cleanup_failed:
                    verifier_error.d810_semantic_stage_cleanup_failed = True
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
        route_rewrite = plan.operations[0].direct_transfer_rewrite
        route_instruction_eas = (0x401000, 0x401004)
        route_terminator_ea = (
            None if route_rewrite is None else route_rewrite.rewrite_anchor_ea
        )
        route_terminator_kind = (
            InsnKind.GOTO
            if route_rewrite is None
            else (
                InsnKind.COND_JUMP if self.malformed_route_projection else InsnKind.GOTO
            )
        )
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
                    terminator_ea=None,
                    terminator_kind=InsnKind.GOTO,
                ),
                ProjectedFragmentBlock(
                    block_id="replacement",
                    kind=BlockKind.ONE_WAY,
                    successors=("target",),
                    predecessors=replacement_predecessors,
                    physical_position=1,
                    adjacent_fallthrough_target_id=None,
                    instruction_eas=route_instruction_eas,
                    terminator_ea=route_terminator_ea,
                    terminator_kind=route_terminator_kind,
                ),
                ProjectedFragmentBlock(
                    block_id="target",
                    kind=BlockKind.ZERO_WAY,
                    successors=(),
                    predecessors=("replacement",),
                    physical_position=2,
                    adjacent_fallthrough_target_id=None,
                    terminator_ea=None,
                    terminator_kind=InsnKind.UNKNOWN,
                ),
                ProjectedFragmentBlock(
                    block_id="original",
                    kind=BlockKind.ZERO_WAY,
                    successors=(),
                    predecessors=original_predecessors,
                    physical_position=3,
                    adjacent_fallthrough_target_id=None,
                    instruction_eas=(0x401000, 0x401004),
                    terminator_ea=None,
                    terminator_kind=InsnKind.UNKNOWN,
                ),
                ProjectedFragmentBlock(
                    block_id="dispatcher",
                    kind=BlockKind.ZERO_WAY,
                    successors=(),
                    predecessors=(),
                    physical_position=4,
                    adjacent_fallthrough_target_id=None,
                    terminator_ea=None,
                    terminator_kind=InsnKind.UNKNOWN,
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
        published_versions = {}
        for block_id, serial in (("entry", 0), ("target", 2), ("dispatcher", 3)):
            handle = index.handle_for_serial(serial)
            assert handle is not None
            owner = index.logical_proxy_for_handle(handle)
            assert owner is not None
            version = owner.resolve()
            assert version is not None
            published_versions[block_id] = version
        self.gateway._record_fragment_plan_bindings(
            plan,
            (
                (PlanBlockRef(plan.plan_id, "entry"), published_versions["entry"]),
                (PlanBlockRef(plan.plan_id, "original"), published),
                (PlanBlockRef(plan.plan_id, "replacement"), staged),
                (PlanBlockRef(plan.plan_id, "target"), published_versions["target"]),
                (
                    PlanBlockRef(plan.plan_id, "dispatcher"),
                    published_versions["dispatcher"],
                ),
            ),
        )
        return projection

    def _observe_staged_semantic_fragment(
        self,
        _plan: FragmentPlan,
    ) -> ProjectedFragment:
        self.calls.append("observe-staged")
        assert self.projection is not None
        return replace(self.projection)

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

    def _publish_semantic_patch_roots(
        self,
        patch_plan,
        rollback_token,
    ) -> None:
        plan = patch_plan.semantic_contract.fragment_plan
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

    def _observe_published_semantic_fragment_graph(
        self,
        plan: FragmentPlan,
    ) -> PublishedFragmentGraphObservation:
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
        return PublishedFragmentGraphObservation(
            projection=projection,
            semantics=PublishedFragmentObservation(
                plan_id=plan.plan_id,
                atomic_group_id=plan.atomic_group_id,
                published_root_ids=plan.roots,
                observable_operations=plan.operations,
                semantic_outcomes=outcomes,
                fallthrough_helpers=projection.fallthrough_helpers,
                root_fallthrough_helpers=projection.root_fallthrough_helpers,
            ),
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

    def _finalize_semantic_fragment_for_commit(self, _plan: FragmentPlan) -> None:
        assert self.gateway._active_postpublication_validation is not None
        assert self.gateway._active_postpublication_validation.passed
        assert self.gateway.receipts == ()
        self.calls.append("finalize")
        if self.finalized_current_mba_identity_binding is not None:
            self.current_mba_identity_binding = (
                self.finalized_current_mba_identity_binding
            )

    def _verify_generated_semantic_fragment(self, _plan: FragmentPlan) -> None:
        self.calls.append("verify-generated")
        if self.raise_during_generated_verify:
            raise RuntimeError("generated post-write verifier failure")


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
        "observe-staged",
        "prepare-roots",
        "publish-roots",
        "rebuild",
        "observe",
        "finalize",
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
    assert [event.phase_index for event in authority_events] == list(range(7))
    assert len({event.attempt_id for event in authority_events}) == 1
    assert all(event.attempt_id.plan_id == plan.plan_id for event in authority_events)


def test_generated_preflight_rejection_is_clean_and_write_free() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(gateway, invalid_preprojection=True)

    with pytest.raises(SemanticFragmentPublicationRejected, match="prepublication"):
        gateway.execute_patch_transaction(
            backend,
            plan,
            SemanticFragmentPublicationProfile.GENERATED_GRAPH_FREE,
        )

    assert backend.calls == ["plan-roots", "snapshot"]
    assert gateway.mutation_started is False
    assert gateway.generation_poisoned is False
    assert committed == []
    assert aborted == []
    assert gateway.receipts == ()


def test_generated_postwrite_verifier_failure_poisons_without_rollback() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(gateway, raise_during_generated_verify=True)

    with pytest.raises(CfgGenerationPoisoned, match="post-write verifier"):
        gateway.execute_patch_transaction(
            backend,
            plan,
            SemanticFragmentPublicationProfile.GENERATED_GRAPH_FREE,
        )

    assert backend.calls == [
        "plan-roots",
        "snapshot",
        "stage",
        "observe-staged",
        "verify-generated",
    ]
    assert gateway.mutation_started is True
    assert gateway.generation_poisoned is True
    assert committed == []
    assert len(aborted) == 1
    assert aborted[0].rollback_attempted is False
    assert aborted[0].rollback_succeeded is None


def test_gateway_commits_reference_matched_route_before_root_publication() -> None:
    plan = _plan_with_reference_route()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(gateway)
    compared: list[MbaSemanticFragmentRouteOracleCompared] = []
    gateway.event_emitter.on(
        MbaSemanticFragmentRouteOracleCompared,
        compared.append,
    )

    receipt = gateway.execute_patch_transaction(backend, plan)

    assert len(compared) == 1
    assert compared[0].result.passed
    assert receipt.detached_route_oracle == compared[0].result
    assert backend.calls.index("stage") < backend.calls.index("prepare-roots")
    assert len(committed) == 1
    assert aborted == []


def test_route_oracle_inventory_preserves_mixed_operation_order() -> None:
    direct_operation = _plan_with_reference_route().operations[0]
    conditional_route = ReferenceRouteRewrite(
        route_id="rhad:0x40A560:flow_route:0x404000",
        function_ea=0x40A560,
        owner_ea=0x404000,
        rewrite_anchor_ea=0x404000,
        corridor=((0x404000, 0x404010),),
        reference_phase="flow_route",
        original_transfer_kind=SemanticTransferKind.INDIRECT,
        final_transfer_kind=SemanticTransferKind.CONDITIONAL,
        true_target_ea=0x405000,
        false_target_ea=0x406000,
        predicate_kind="z",
        reference_ledger_identity="flow_route:0x404000",
        reference_ledger_json='{"status":"committed"}',
    )
    conditional_operation = SimpleNamespace(
        direct_transfer_rewrite=None,
        reference_route_authority=FragmentReferenceRouteAuthority(
            reference_route=conditional_route,
            candidate_rewrite_anchor_ea=0x404000,
            imported_closure_block_ids=(),
        ),
    )
    plan = SimpleNamespace(operations=(direct_operation, conditional_operation))

    assert mutation_events._fragment_reference_ledger_identities(plan) == (
        (
            direct_operation.reference_route_authority.reference_route.route_id,
            direct_operation.reference_route_authority.reference_route.reference_ledger_identity,
        ),
        (conditional_route.route_id, conditional_route.reference_ledger_identity),
    )


def test_gateway_realization_semantics_mismatch_poisons_before_observation() -> None:
    plan = _plan_with_reference_route()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(gateway, malformed_route_projection=True)
    compared: list[MbaSemanticFragmentRouteOracleCompared] = []
    gateway.event_emitter.on(
        MbaSemanticFragmentRouteOracleCompared,
        compared.append,
    )

    with pytest.raises(
        CfgGenerationPoisoned,
        match="block:replacement:terminator",
    ):
        gateway.execute_patch_transaction(backend, plan)

    assert backend.calls == [
        "plan-roots",
        "snapshot",
        "stage",
    ]
    assert not backend.root_published
    assert compared == []
    assert committed == []
    assert len(aborted) == 1
    assert not aborted[0].root_publication_attempted
    assert gateway.generation_poisoned
    assert gateway.transaction_failure is not None
    assert gateway.transaction_failure.failure_phase == "stage"


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
    finalized_origins = tuple(
        (int(live_ea) + 0x10, int(native_ea)) for live_ea, native_ea in origins
    )
    finalized_snapshot = CurrentMbaIdentityBindingSnapshot(
        instruction_origins=finalized_origins,
        block_bindings=(
            CurrentMbaBlockIdentityBinding(
                stable_identity=identity,
                live_instruction_eas=frozenset(
                    live_ea for live_ea, _native_ea in finalized_origins
                ),
            ),
        ),
    )
    backend = _FragmentBackend(
        gateway,
        current_mba_identity_binding=snapshot,
        finalized_current_mba_identity_binding=finalized_snapshot,
    )

    receipt = gateway.execute_patch_transaction(backend, plan)

    assert receipt.current_mba_identity_binding == finalized_snapshot
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
    backend = _FragmentBackend(gateway)
    snapshot_preparation = backend._snapshot_semantic_fragment_inputs(plan)
    snapshot = snapshot_preparation.authority.projection_input
    projection = ProjectedFragment(
        entry_block_id="entry",
        blocks=(
            ProjectedFragmentBlock(
                block_id="entry",
                kind=BlockKind.ONE_WAY,
                successors=("original",),
                predecessors=(),
                physical_position=0,
                adjacent_fallthrough_target_id=None,
                terminator_ea=None,
                terminator_kind=InsnKind.GOTO,
            ),
            ProjectedFragmentBlock(
                block_id="original",
                kind=BlockKind.ZERO_WAY,
                successors=(),
                predecessors=("entry",),
                physical_position=1,
                adjacent_fallthrough_target_id=None,
                terminator_ea=None,
                terminator_kind=InsnKind.UNKNOWN,
            ),
            ProjectedFragmentBlock(
                block_id="target",
                kind=BlockKind.ZERO_WAY,
                successors=(),
                predecessors=(),
                physical_position=2,
                adjacent_fallthrough_target_id=None,
                terminator_ea=None,
                terminator_kind=InsnKind.UNKNOWN,
            ),
            ProjectedFragmentBlock(
                block_id="dispatcher",
                kind=BlockKind.ZERO_WAY,
                successors=(),
                predecessors=(),
                physical_position=3,
                adjacent_fallthrough_target_id=None,
                terminator_ea=None,
                terminator_kind=InsnKind.UNKNOWN,
            ),
        ),
        identity_bindings=snapshot.identity_bindings,
    )
    projection = project_fragment(plan, snapshot, inventory)
    projection = replace(
        projection,
        blocks=tuple(
            replace(
                block,
                instruction_eas=(0x404000,),
                terminator_ea=0x404000,
                terminator_kind=InsnKind.RET,
            )
            if block.block_id == "terminal"
            else block
            for block in projection.blocks
        ),
        return_carriers=plan.return_carriers,
        terminal_returns=plan.terminal_returns,
    )
    attempt = TransactionAttemptId.new(
        plan.plan_id,
        gateway.session_id,
        gateway.generation,
    )
    prepared = PreparedSemanticFragment(
        authority=PreparedSemanticFragmentAuthority(
            plan_id=plan.plan_id,
            atomic_group_id=plan.atomic_group_id,
            session_id=gateway.session_id,
            generation=gateway.generation,
            snapshot_id=snapshot.snapshot_id,
            attempt_id=attempt,
            root_inventory=inventory,
            snapshot=snapshot_preparation.authority,
            projection=projection,
            cfg_projection=fragment_cfg_projection(plan, snapshot, projection),
        ),
        payload=snapshot_preparation.payload,
    )

    gateway._begin_semantic_fragment_batch(
        backend,
        plan,
        inventory,
        attempt,
        snapshot.snapshot_id,
        prepared,
        lower_fragment_plan(plan, prepared),
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
    publications = lifecycle.committed_semantic_publications
    assert len(publications) == 1
    assert publications[0].plan_id == plan.plan_id
    assert publications[0].atomic_group_id == plan.atomic_group_id
    assert publications[0].evidence_generation == 1
    assert tuple(owner.operation_id for owner in publications[0].owners) == (
        "direct-route",
    )
    assert (
        publications[0].owners[0].stable_identity
        == plan.block("replacement").stable_identity
    )


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
    lifecycle.event_observer = lambda transition: timeline.append(transition.operation)
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
            selected_obligation_ids=("direct-route",),
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
    assert lifecycle.normalization_last_unreachable_obligation_ids == ("dead-route",)
    assert lifecycle.canonical_semantic_plan_generation is None
    assert lifecycle.semantic_fragment_staged_generation is None
    assert lifecycle.receipt_committed_generation is None


def test_partial_normalization_receipt_does_not_advance_generation_authority() -> None:
    plan = replace(
        _plan(),
        publication_purpose=FragmentPublicationPurpose.FRONTEND_NORMALIZATION,
        work_item_scope=FragmentWorkItemScope(
            work_item_id="gateway-fragment:root@0x401000",
            selected_obligation_ids=("direct-route",),
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
    assert lifecycle.normalization_last_published_operation_ids == ("direct-route",)
    assert (
        lifecycle.normalization_last_published_work_item_id
        == "gateway-fragment:root@0x401000"
    )
    assert lifecycle.normalization_last_selected_obligation_ids == ("direct-route",)
    assert lifecycle.normalization_last_remaining_obligation_ids == ("route@0x402000",)
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
    assert lifecycle.committed_semantic_publications == ()
    assert lifecycle.canonical_semantic_plan_generation == 1
    assert lifecycle.has_pending_generated_restart


def test_postpublication_poison_restores_prior_normalization_authority() -> None:
    plan = replace(
        _plan(),
        publication_purpose=FragmentPublicationPurpose.FRONTEND_NORMALIZATION,
        work_item_scope=FragmentWorkItemScope(
            work_item_id="gateway-fragment:complete",
            selected_obligation_ids=("direct-route",),
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
    lifecycle.event_observer = lambda transition: timeline.append(transition.operation)
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
        "semantic_fragment_ownership_committed",
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
    assert backend.calls[-2:] == ["observe", "finalize"]
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
    assert gateway.transaction_failure.reason == (
        "prepublication semantic validation failed: "
        "original_supersession:original - "
        "owned original remains reachable from publication authority"
    )
    receipt = gateway.execute_patch_transaction(_FragmentBackend(gateway), plan)
    assert receipt.pre_generation == 5
    assert receipt.post_generation == 6
    assert len(committed) == 1
    assert aborted == []


@pytest.mark.parametrize(
    "failpoint,failed_phase,interr_code",
    (
        ("raise_after_insertion", "stage", 50856),
        ("raise_after_observation", "postpublication_observation", 50860),
    ),
)
def test_live_divergence_poisons_generation_without_cleanup_and_restarts_once(
    failpoint: str,
    failed_phase: str,
    interr_code: int,
) -> None:
    plan = _plan()
    lifecycle = _semantic_lifecycle()
    gateway, committed, aborted = _gateway(
        plan,
        lifecycle_authority=lifecycle,
    )
    backend = _FragmentBackend(gateway, **{failpoint: True})
    authority_events: list[MbaCfgTransactionAuthorityObserved] = []
    gateway.event_emitter.on(
        MbaCfgTransactionAuthorityObserved,
        authority_events.append,
    )

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
    assert authority_events[-1].phase is (CfgTransactionPhase.POISONED_RESTART_REQUIRED)
    assert authority_events[-1].failure == failure
    assert authority_events[-1].poisoned
    assert [event.phase_index for event in authority_events] == list(
        range(len(authority_events))
    )
    assert "rollback-roots" not in backend.calls
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
    gateway, _committed, _aborted = _gateway(
        plan,
        lifecycle_authority=_semantic_lifecycle(),
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


@pytest.mark.parametrize(
    "operation",
    (
        lambda index: index.identity_for_serial(0),
        lambda index: index.create_observed_ephemeral_handle(),
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
        "observe-staged",
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
        "observe-staged",
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
        "observe-staged",
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


def test_failed_stage_cleanup_is_not_retried_after_possible_compaction() -> None:
    plan = _plan()
    gateway, committed, aborted = _gateway(plan)
    backend = _FragmentBackend(
        gateway,
        raise_during_stage=True,
        stage_cleanup_failed=True,
        raise_during_discard=True,
    )

    with pytest.raises(SemanticFragmentRollbackFailed, match="INTERR: 50856"):
        gateway.execute_patch_transaction(backend, plan)

    assert backend.calls == ["plan-roots", "snapshot", "stage"]
    assert committed == []
    assert len(aborted) == 1
    assert aborted[0].rollback_attempted
    assert not aborted[0].rollback_succeeded
    assert [
        (failure.failure_kind, failure.phase, failure.interr_code)
        for failure in aborted[0].fragment_failures
    ] == [
        ("stage", "stage", None),
        ("verifier", "stage_cleanup", 50856),
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
