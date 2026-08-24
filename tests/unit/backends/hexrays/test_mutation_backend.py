from __future__ import annotations

from dataclasses import replace
import sys
from types import ModuleType, SimpleNamespace

import pytest

from d810.analyses.control_flow.native_preanalysis_session import (
    CommittedSemanticFragmentOwnership,
    NativePreanalysisSessionState,
    SemanticFragmentBlockOwner,
)
from d810.ir.expressions import ValueOpKind
from d810.backends.hexrays.mutation.backend import (
    HexRaysMutationBackend,
    HexRaysPatchPlanRuntime,
)
from d810.core.events import EventEmitter
from d810.core import observability_preanalysis
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.mba_mutation_events import (
    MbaCfgTransactionAuthorityObserved,
    MbaMutationGateway,
    MbaMutationPlanned,
    StructuralMutationKind,
)
from d810.hexrays.mutation.patch_transaction import (
    HexRaysPatchTransactionParticipant,
    PatchTransactionPostObservationRejected,
    PatchTransactionPreflightRejected,
    _patch_plan_observation_items,
)
from d810.hexrays.mutation.semantic_ownership import (
    PatchPlanSemanticOwnershipOverlap,
    find_patch_plan_semantic_ownership_overlap,
    format_patch_plan_semantic_ownership_overlap,
)
from d810.hexrays.mutation.semantic_fragment_profile import (
    SemanticFragmentPublicationProfile,
)
from d810.ir.block_identity import (
    CurrentMbaBlockIdentityBinding,
    CurrentMbaIdentityBindingSnapshot,
    NativeEaInterval,
    StableBlockIdentity,
)
from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
    PredicateKind,
)
from d810.ir.maturity import MaturityEnvelope
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.manager.fragment_publication_lifecycle import (
    SessionFragmentPublicationLifecycleAuthority,
)
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.transforms.cfg_transaction import (
    BoundCfgTransaction,
    CfgGenerationPoisoned,
    CfgProjection,
    CfgTransactionPhase,
    LogicalBlockRef,
    NativeBlockRef,
    PlanBlockRef,
    PreparedCfgTransaction,
)
from d810.transforms.unflatten_authority.ids import authority_id
from d810.transforms.unflatten_authority.ids import claim_id
from d810.transforms.unflatten_authority import model as authority_model
from d810.transforms.unflatten_authority import views as authority_views
from d810.transforms.dispatcher_corridor_coverage import (
    DISPATCHER_CORRIDOR_COVERAGE_METADATA,
    DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA,
    analyze_dispatcher_corridor_coverage,
    build_dispatcher_removal_forecast,
)
from d810.transforms.edit_simulator import project_patch_plan
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentEdge,
    FragmentOperation,
    FragmentPlan,
    FragmentPublicationPurpose,
)
from d810.transforms.graph_modification import (
    LowerConditionalStateTransition,
    RedirectGoto,
    SyntheticRegisterNonzeroCondition,
)
from d810.transforms.plan import (
    PatchBypassDispatcherTrampoline,
    PatchConvertToGoto,
    PatchEdgeSplitTrampoline,
    PatchLowerConditionalStateTransition,
    PatchPhaseCycleLowering,
    PatchPlan,
    PatchRemoveEdge,
    PatchRedirectBranch,
    PatchRedirectGoto,
    PatchRemoveEdge,
    PatchScalarizeLocalAliasAccess,
)
from tests.native_preanalysis import make_native_key


MUTATION_GATEWAY = object()
NATIVE_KEY = make_native_key()


def _ref(serial: int) -> LogicalBlockRef:
    return LogicalBlockRef("backend-test", f"block:{int(serial)}", 0)


def _source_coordinates(*serials: int):
    return tuple((_ref(serial), int(serial)) for serial in serials)


def _fragment_identity(start_ea: int) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(start_ea, start_ea + 0x10),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(start_ea,),
    )


def _fragment_plan() -> FragmentPlan:
    original_identity = _fragment_identity(0x401000)
    return FragmentPlan(
        plan_id="backend-fragment",
        atomic_group_id="backend-route",
        publication_purpose=(FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING),
        native_key=NATIVE_KEY,
        blocks=(
            FragmentBlock(
                block_id="entry",
                role=FragmentBlockRole.EXTERNAL,
                materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
                semantic_anchor_ea=0x400000,
                stable_identity=_fragment_identity(0x400000),
            ),
            FragmentBlock(
                block_id="original",
                role=FragmentBlockRole.ORIGINAL,
                materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
                semantic_anchor_ea=0x401000,
                stable_identity=original_identity,
            ),
            FragmentBlock(
                block_id="replacement",
                role=FragmentBlockRole.REPLACEMENT,
                materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
                semantic_anchor_ea=0x401000,
                stable_identity=original_identity,
                replaces_block_id="original",
            ),
            FragmentBlock(
                block_id="target",
                role=FragmentBlockRole.EXTERNAL,
                materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
                semantic_anchor_ea=0x402000,
                stable_identity=_fragment_identity(0x402000),
            ),
            FragmentBlock(
                block_id="dispatcher",
                role=FragmentBlockRole.EXTERNAL,
                materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
                semantic_anchor_ea=0x403000,
                stable_identity=_fragment_identity(0x403000),
            ),
        ),
        roots=("replacement",),
        owned_originals=("original",),
        prohibited_dispatcher_blocks=("dispatcher",),
        operations=(
            FragmentOperation(
                operation_id="backend-direct-route",
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


def _current_mba_identity_binding() -> CurrentMbaIdentityBindingSnapshot:
    live_ea = 0xF10000
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401020),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x401010,),
    )
    return CurrentMbaIdentityBindingSnapshot(
        instruction_origins=((live_ea, 0x401010),),
        block_bindings=(
            CurrentMbaBlockIdentityBinding(
                stable_identity=identity,
                live_instruction_eas=frozenset({live_ea}),
            ),
        ),
    )


def _make_block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *,
    kind: BlockKind | None = None,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=(),
        kind=(
            kind
            or (
                BlockKind.TWO_WAY
                if len(succs) == 2
                else BlockKind.ONE_WAY
                if len(succs) == 1
                else BlockKind.N_WAY
                if len(succs) > 2
                else BlockKind.ZERO_WAY
            )
        ),
        tail_kind=InsnKind.COND_JUMP if len(succs) == 2 else None,
    )


def _make_cfg(
    edges: list[tuple[int, int]],
    *,
    stop_serials: tuple[int, ...] = (),
    entry_serial: int = 0,
) -> FlowGraph:
    succs: dict[int, list[int]] = {}
    preds: dict[int, list[int]] = {}
    nodes = {entry_serial, *stop_serials}
    for src, dst in edges:
        nodes.add(src)
        nodes.add(dst)
        succs.setdefault(src, []).append(dst)
        preds.setdefault(dst, []).append(src)
    blocks = {
        serial: _make_block(
            serial,
            tuple(succs.get(serial, ())),
            tuple(preds.get(serial, ())),
            kind=BlockKind.STOP if serial in stop_serials else None,
        )
        for serial in nodes
    }
    return FlowGraph(blocks=blocks, entry_serial=entry_serial, func_ea=0x1000)


class _FakeTranslator:
    def __init__(self, cfg: FlowGraph) -> None:
        self.cfg = cfg
        self.lower_calls: list[PatchPlan] = []
        self.lift_count = 0
        self.contract = None

    def lift(self, _live_source: object) -> FlowGraph:
        self.lift_count += 1
        return self.cfg

    def lower(
        self,
        rewrite_plan: PatchPlan,
        _live_source: object,
        *,
        mutation_gateway: object,
        bound_transaction: BoundCfgTransaction,
        post_apply_hook=None,
    ) -> int:
        assert bound_transaction.prepared.attempt_id == (
            mutation_gateway.current_transaction_attempt
        )
        assert post_apply_hook is None
        mutation_gateway.begin_batch(
            StructuralMutationKind.BLOCK_REPLACE,
            serial_quantity=int(_live_source.qty),
            planned_operation_count=len(rewrite_plan.steps),
            transaction_attempt=bound_transaction.prepared.attempt_id,
            patch_plan_id=rewrite_plan.plan_id,
            patch_plan_refs=tuple(spec.block_id for spec in rewrite_plan.new_blocks),
        )
        mutation_gateway.begin_patch_realization(
            bound_transaction.prepared.attempt_id,
            plan_refs=tuple(spec.block_id for spec in rewrite_plan.new_blocks),
        )
        self.lower_calls.append(rewrite_plan)
        return len(rewrite_plan.steps)


def _native_ref(serial: int) -> NativeBlockRef:
    return NativeBlockRef(
        StableBlockIdentity.from_instruction_eas(
            (0x1000 + int(serial),),
            native_key=NATIVE_KEY,
        )
    )


def _ordinary_gateway(
    cfg: FlowGraph,
    plan: PatchPlan,
    *,
    native_key=NATIVE_KEY,
    event_emitter: EventEmitter | None = None,
    lifecycle_authority: object | None = None,
) -> MbaMutationGateway:
    index = MbaBlockIdentityIndex.from_flow_graph(
        session_id="backend-test",
        generation=int(plan.source_generation or 0),
        maturity=0,
        snapshot_id=plan.snapshot_id,
        native_key=native_key,
        flow_graph=cfg,
    )
    return MbaMutationGateway(
        session_id=index.session_id,
        generation=index.generation,
        maturity=0,
        native_key=native_key,
        identity_index=index,
        event_emitter=event_emitter,
        lifecycle_authority=lifecycle_authority,
    )


def _ordinary_plan(step_type, *, serials: tuple[int, ...], **coordinates) -> PatchPlan:
    refs = {serial: _native_ref(serial) for serial in serials}
    if step_type is PatchRedirectGoto:
        step = PatchRedirectGoto(
            from_serial=refs[coordinates["from_serial"]],
            old_target=refs[coordinates["old_target"]],
            new_target=refs[coordinates["new_target"]],
        )
    elif step_type is PatchConvertToGoto:
        step = PatchConvertToGoto(
            block_serial=refs[coordinates["block_serial"]],
            goto_target=refs[coordinates["goto_target"]],
        )
    else:
        raise TypeError("unsupported ordinary test step")
    return PatchPlan(
        source_maturity=MaturityEnvelope(
            ir=None,
            provider="hexrays",
            provider_id=0,
        ),
        source_generation=0,
        steps=(step,),
        source_coordinates=tuple((refs[serial], serial) for serial in serials),
    )


def test_patch_plan_observation_uses_new_and_old_redirect_targets() -> None:
    cfg = _make_cfg([(0, 1), (1, 2)], stop_serials=(2,))
    plan = _ordinary_plan(
        PatchRedirectGoto,
        serials=(0, 1, 2),
        from_serial=0,
        old_target=1,
        new_target=2,
    )

    item = _patch_plan_observation_items(plan, cfg)[0]

    assert item.source_serial == 0
    assert item.source_anchor_ea == 0x1000
    assert item.old_target_serial == 1
    assert item.target_serial == 2
    assert item.target_anchor_ea == 0x1002


def test_patch_plan_observation_encodes_conditional_multi_target_shape() -> None:
    refs = {serial: _native_ref(serial) for serial in range(4)}
    step = PatchLowerConditionalStateTransition(
        source_serial=refs[0],
        old_dispatcher_serial=refs[1],
        rewrite_from_ea=0x5000,
        condition_operand=object(),
        false_target_serial=refs[2],
        true_target_serial=refs[3],
    )
    plan = PatchPlan(
        steps=(step,),
        source_coordinates=tuple((refs[serial], serial) for serial in range(4)),
    )
    cfg = _make_cfg([(0, 1), (1, 2), (2, 3)], stop_serials=(3,))

    item = _patch_plan_observation_items(plan, cfg)[0]

    assert item.source_serial == 0
    assert item.old_target_serial == 1
    assert item.target_serial == 3
    assert item.target_anchor_ea == 0x1003
    assert "false_target=0x1002" in item.reason


@pytest.mark.parametrize("shape", ["trampoline", "phase_cycle", "edge_split"])
def test_patch_plan_observation_preserves_generic_multi_target_refs(shape) -> None:
    refs = {serial: _native_ref(serial) for serial in range(6)}
    if shape == "trampoline":
        step = PatchBypassDispatcherTrampoline(
            source_serial=refs[0],
            trampoline_serial=refs[1],
            target_serial=refs[2],
        )
        expected_target = 2
        expected_extra = {1}
    elif shape == "phase_cycle":
        step = PatchPhaseCycleLowering(
            header_entries=(refs[0],),
            header_target=refs[1],
            body_entries=(refs[2],),
            body_target=refs[3],
            next_phase_entries=(refs[4],),
            next_phase_target=refs[5],
        )
        expected_target = 1
        expected_extra = {2, 3, 4, 5}
    else:
        step = PatchEdgeSplitTrampoline(
            block_id=PlanBlockRef("shape-plan", "split"),
            source_serial=refs[0],
            via_pred=refs[1],
            old_target=refs[2],
            apply_old_target=refs[3],
            new_target=refs[4],
            template_block=refs[5],
        )
        expected_target = 4
        expected_old_target = 3
        expected_extra = {1, 2, 5}
    plan = PatchPlan(
        plan_id="shape-plan",
        steps=(step,),
        source_coordinates=tuple((refs[serial], serial) for serial in range(6)),
    )
    cfg = _make_cfg([(serial, serial + 1) for serial in range(5)], stop_serials=(5,))

    item = _patch_plan_observation_items(plan, cfg)[0]

    assert item.target_serial == expected_target
    if shape == "edge_split":
        assert item.old_target_serial == expected_old_target
    assert {target.serial for target in item.additional_targets} == expected_extra


def test_patch_plan_observation_retains_removed_edge_target() -> None:
    refs = {serial: _native_ref(serial) for serial in range(2)}
    plan = PatchPlan(
        steps=(PatchRemoveEdge(from_serial=refs[0], to_serial=refs[1]),),
        source_coordinates=((refs[0], 0), (refs[1], 1)),
    )
    cfg = _make_cfg([(0, 1)], stop_serials=(1,))

    item = _patch_plan_observation_items(plan, cfg)[0]

    assert item.target_serial is None
    assert item.old_target_serial == 1
    assert item.old_target_anchor_ea == 0x1001


def test_apply_rejects_plan_that_orphans_reachable_terminal() -> None:
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 3)],
        stop_serials=(3,),
    )
    # Keep the rejected projected region effectful: this is not an empty STOP
    # block whose disappearance could be dismissed as harmless cleanup.
    cfg = replace(
        cfg,
        blocks={
            **cfg.blocks,
            3: replace(
                cfg.blocks[3],
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0x70,
                        ea=0x1003,
                        operands=(),
                        kind=InsnKind.CALL,
                        is_call=True,
                    ),
                ),
            ),
        },
    )
    plan = _ordinary_plan(
        PatchRedirectGoto,
        serials=(1, 2, 3),
        from_serial=2,
        old_target=3,
        new_target=1,
    )
    translator = _FakeTranslator(cfg)
    emitter = EventEmitter()
    planned: list[MbaMutationPlanned] = []
    emitter.on(MbaMutationPlanned, planned.append)
    phases: list[MbaCfgTransactionAuthorityObserved] = []
    emitter.on(MbaCfgTransactionAuthorityObserved, phases.append)
    translator = _FakeTranslator(cfg)
    gateway = _ordinary_gateway(cfg, plan, event_emitter=emitter)
    backend = HexRaysMutationBackend(
        mutation_gateway=gateway,
        translator=translator,
    )

    execution = backend.execute_patch_plan(
        plan,
        SimpleNamespace(qty=cfg.num_blocks),
        pre_cfg=cfg,
    )
    result = execution.graph

    assert result is cfg
    assert execution.applied_count == 0
    assert gateway.receipts == ()
    assert len(planned) == 1
    assert planned[0].planned_operation_count == len(plan.steps)
    assert len(planned[0].items) == len(plan.steps)
    assert all(item.disposition == "planned" for item in planned[0].items)
    assert planned[0].items[0].old_target_serial == 3
    assert planned[0].items[0].target_serial == 1
    assert translator.lower_calls == []
    assert translator.lift_count == 0
    assert backend.last_patch_failure is not None
    assert backend.last_patch_failure.unflatten_verdict is None
    assert not backend._mutation_gateway.mutation_started
    assert [event.phase for event in phases] == [
        CfgTransactionPhase.PLANNED,
        CfgTransactionPhase.PROJECTED,
        CfgTransactionPhase.REJECTED_CLEAN,
    ]
    assert all(not event.mutation_started for event in phases)
    failure = phases[-1].failure
    assert failure is not None
    assert not failure.live_mutation_started
    assert "effectful=reachable effectful blocks became unreachable" in failure.reason
    assert "lost=blk3@0x1003" in failure.reason


def test_apply_rejects_plan_that_collapses_entry_reachability() -> None:
    cfg = _make_cfg([(serial, serial + 1) for serial in range(24)])
    plan = _ordinary_plan(
        PatchRedirectGoto,
        serials=(0, 1),
        from_serial=0,
        old_target=1,
        new_target=0,
    )
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is cfg
    assert translator.lower_calls == []
    assert translator.lift_count == 1
    assert backend.last_patch_failure is not None
    assert backend.last_patch_failure.unflatten_verdict is None
    assert not backend._mutation_gateway.mutation_started


def _comparison_dispatcher_forest_cfg() -> FlowGraph:
    """A broad router forest whose direct-route plan intentionally retires it."""
    return _make_cfg(
        [
            (0, 1),
            (1, 2),
            (2, 3),
            (2, 5),
            (3, 4),
            *((serial, target) for serial in range(5, 31) for target in (4, serial + 1)),
            (31, 4),
        ],
        stop_serials=(4,),
    )


def _comparison_dispatcher_forest_observed_cfg(
    *,
    direct_target: int,
) -> FlowGraph:
    """Model a live CFG whose direct entry route replaces blk1 -> blk2."""
    return _make_cfg(
        [
            (0, 1),
            (1, direct_target),
            (2, 3),
            (2, 5),
            (3, 4),
            *((serial, target) for serial in range(5, 31) for target in (4, serial + 1)),
            (31, 4),
        ],
        stop_serials=(4,),
    )


def _typed_bootstrap_authority_plan(
    cfg: FlowGraph,
    *,
    template: PatchPlan,
    dispatcher_entry_serial: int,
    dispatcher_member_serials: tuple[int, ...],
    authoritative_handler_serials: tuple[int, ...],
    coverage,
    removal_forecast=None,
    route_edge: tuple[int, int] | None = None,
    route_terminal: bool = False,
) -> PatchPlan:
    """Build a typed proposal around the plan's direct semantic route."""
    from d810.analyses.control_flow.semantic_route_evidence import (
        CanonicalSemanticEvidence,
        SemanticRouteDestination,
        SemanticRouteProof,
        SemanticRouteProofKind,
        SemanticRouteShape,
        SemanticStateWriteDeliveryKind,
        SemanticStateWriteProof,
    )
    from d810.ir.block_identity import NativeEaInterval
    from d810.transforms.unflatten_authority.model import UseDefFragmentWitness
    from d810.transforms.unflatten_authority.proposal import (
        attach_typed_proposal,
        canonical_redirect_manifest,
    )

    state = StorageIdentity(StorageIdentityKind.STACK, 4)
    if route_edge is None:
        route_edge = next(
            (serial, block.succs[0])
            for serial, block in sorted(cfg.blocks.items())
            if len(block.succs) == 1
        )
    source_serial, target_serial = route_edge
    source_block = cfg.blocks[source_serial]
    if len(source_block.succs) != 1:
        raise ValueError("typed bootstrap route source must be one-way")
    projected = project_patch_plan(cfg, template, snapshot_id=template.snapshot_id)
    projected_source = projected.graph.blocks.get(source_serial)
    if projected_source is None or tuple(projected_source.succs) != (target_serial,):
        raise ValueError("typed bootstrap route must match projected topology")
    source_blocks = {}
    for serial, block in cfg.blocks.items():
        if serial == source_serial:
            instruction = InsnSnapshot(
                opcode=0,
                ea=block.start_ea,
                native_ea=block.start_ea,
                operands=(),
                l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=1),
                d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,)),
                kind=InsnKind.MOV,
                value_op_kind=ValueOpKind.MOVE,
            )
        else:
            instruction = InsnSnapshot(
                opcode=0,
                ea=block.start_ea,
                native_ea=block.start_ea,
                operands=(),
                kind=InsnKind.NOP,
            )
        source_blocks[serial] = replace(block, insn_snapshots=(instruction,))
    object.__setattr__(cfg, "blocks", source_blocks)

    refs = {serial: _native_ref(serial) for serial in sorted(cfg.blocks)}
    source_ref = refs[source_serial]
    target_ref = refs[target_serial]
    source_ea = source_block.start_ea
    target_ea = cfg.blocks[target_serial].start_ea
    state_write = SemanticStateWriteProof(
        source_ref.identity,
        source_ea,
        state,
        4,
        1,
        (source_ea,),
        None,
        (),
        SemanticStateWriteDeliveryKind.DIRECT,
    )
    route = SemanticRouteProof(
        authority_id(("typed-bootstrap-route", template.plan_id, source_serial, target_serial)),
        authority_id(("typed-bootstrap-group", template.plan_id)),
        SemanticRouteProofKind.BOOTSTRAP,
        SemanticRouteShape.DIRECT,
        source_ref.identity,
        source_ea,
        (SemanticRouteDestination(
            SemanticEdgeRole.DIRECT, 1, target_ref.identity, target_ea,
            terminal=route_terminal,
        ),),
        NativeEaInterval(source_ea, source_ea + 1),
        state_write=state_write,
    )
    evidence = CanonicalSemanticEvidence(
        NATIVE_KEY,
        1,
        route.atomic_group_id,
        (route,),
    )
    template = replace(
        template,
        plan_id=authority_id(("typed-bootstrap-plan", template.plan_id)),
        snapshot_id=authority_id(("typed-bootstrap-snapshot", template.snapshot_id)),
        source_generation=1,
        source_coordinates=tuple((refs[serial], serial) for serial in sorted(refs)),
        metadata=(),
    )
    manifest = canonical_redirect_manifest(template)
    witness = UseDefFragmentWitness(
        authority_id("typed-bootstrap-witness"),
        state,
        manifest.owner_refs,
        manifest.digest,
        True,
        True,
        0,
        (),
    )
    return attach_typed_proposal(
        template,
        source=cfg,
        block_refs_by_serial=refs,
        canonical_route_evidence=evidence,
        selected_route_proof_ids=(route.proof_id,),
        exact_state_effect_exclusions=(),
        dispatcher_entry_serial=dispatcher_entry_serial,
        dispatcher_member_serials=dispatcher_member_serials,
        authoritative_handler_serials=authoritative_handler_serials,
        state_identity=state,
        use_def_witness=witness,
        corridor_coverage=coverage,
        dispatcher_removal_forecast=removal_forecast,
    )


def test_apply_rejects_unbound_comparison_dispatcher_removal_below_raw_threshold() -> None:
    """Stamped producer metadata cannot bypass the generic entry-count gate."""
    cfg = _comparison_dispatcher_forest_cfg()
    plan = _ordinary_plan(
        PatchRedirectGoto,
        serials=(1, 2, 3),
        from_serial=1,
        old_target=2,
        new_target=3,
    )
    coverage = analyze_dispatcher_corridor_coverage(
        cfg,
        modifications=(RedirectGoto(from_serial=1, old_target=2, new_target=3),),
        dispatcher_entry_serial=2,
    )
    plan = plan.with_metadata(
        **{
            DISPATCHER_CORRIDOR_COVERAGE_METADATA: coverage.to_metadata(),
            DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA: {
                "proof_status": "accepted",
                "reason": "untrusted_stamped_metadata",
            },
        }
    )

    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is cfg
    assert translator.lower_calls == []
    assert translator.lift_count == 1


def test_apply_rejects_dispatcher_removal_proof_when_one_handler_is_lost() -> None:
    cfg = _comparison_dispatcher_forest_cfg()
    raw_plan = _ordinary_plan(
        PatchRedirectGoto,
        serials=(1, 2, 3),
        from_serial=1,
        old_target=2,
        new_target=3,
    )
    coverage = analyze_dispatcher_corridor_coverage(
        cfg,
        modifications=(RedirectGoto(from_serial=1, old_target=2, new_target=3),),
        dispatcher_entry_serial=2,
    )
    removal_forecast = build_dispatcher_removal_forecast(
        cfg,
        coverage=coverage,
        dispatcher_entry_serial=2,
    )
    plan = _typed_bootstrap_authority_plan(
        cfg,
        template=raw_plan,
        dispatcher_entry_serial=2,
        coverage=coverage,
        dispatcher_member_serials=(1, 2, *range(5, 32)),
        authoritative_handler_serials=(1,),
        removal_forecast=removal_forecast,
    )

    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is cfg
    assert translator.lower_calls == []
    assert translator.lift_count == 1


def test_apply_rejects_recomputed_stale_dispatcher_coverage_proof() -> None:
    """A plan cannot relabel an actual residual corridor out of existence."""
    cfg = _comparison_dispatcher_forest_cfg()
    template = _ordinary_plan(
        PatchRedirectGoto,
        serials=(1, 2, 3),
        from_serial=1,
        old_target=2,
        new_target=3,
    )
    coverage = analyze_dispatcher_corridor_coverage(
        cfg,
        modifications=(RedirectGoto(from_serial=1, old_target=2, new_target=3),),
        dispatcher_entry_serial=2,
    )
    stale_coverage = replace(
        coverage,
        covered_corridors=(),
        residual_corridors=(),
    )
    stale_plan = _typed_bootstrap_authority_plan(
        cfg,
        template=template,
        dispatcher_entry_serial=2,
        dispatcher_member_serials=(1, 2, *range(5, 32)),
        authoritative_handler_serials=(1,),
        coverage=stale_coverage,
    )

    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, stale_plan),
        translator=translator,
    )

    result = backend.apply(
        stale_plan,
        live_source=SimpleNamespace(qty=cfg.num_blocks),
    )

    assert result is cfg
    assert translator.lower_calls == []
    assert translator.lift_count == 1


def test_small_full_retirement_poisons_when_observed_graph_differs_from_projection() -> None:
    """Observed corridor drift rejects with a canonical observed safety case."""
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 3), (2, 5), (3, 4), (5, 4)],
        stop_serials=(4,),
    )
    template = _ordinary_plan(
        PatchRedirectGoto,
        serials=(1, 2, 3),
        from_serial=1,
        old_target=2,
        new_target=3,
    )
    coverage = analyze_dispatcher_corridor_coverage(
        cfg,
        modifications=(RedirectGoto(from_serial=1, old_target=2, new_target=3),),
        dispatcher_entry_serial=2,
    )
    projected = project_patch_plan(cfg, template, snapshot_id=template.snapshot_id)
    removal_forecast = build_dispatcher_removal_forecast(
        cfg,
        coverage=coverage,
        dispatcher_entry_serial=2,
    )
    plan = _typed_bootstrap_authority_plan(
        cfg,
        template=template,
        dispatcher_entry_serial=2,
        dispatcher_member_serials=(1, 2, 5),
        authoritative_handler_serials=(3,),
        coverage=coverage,
        route_edge=(1, 3),
        removal_forecast=removal_forecast,
    )
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(
            cfg,
            plan,
            lifecycle_authority=SessionFragmentPublicationLifecycleAuthority(
                native_key=NATIVE_KEY,
                state=NativePreanalysisSessionState(evidence_generation=1),
            ),
        ),
        # The fake translator deliberately leaves the dispatcher unchanged
        # after lower(); the generic small-CFG gate alone would pass.
        translator=translator,
    )

    from d810.hexrays.mutation.patch_transaction import PatchTransactionPoisoned
    with pytest.raises(PatchTransactionPoisoned) as raised:
        backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert isinstance(raised.value.__cause__, PatchTransactionPostObservationRejected)
    assert translator.lower_calls == [plan]
    assert translator.lift_count == 2
    observed_verdict = raised.value.unflatten_verdict
    assert observed_verdict is not None
    assert observed_verdict.phase is authority_model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
    assert observed_verdict.accepted is False
    assert observed_verdict.safety_case is not None
    assert any(
        item.key.dimension is authority_model.SafetyDimension.CORRIDOR_COVERAGE
        and item.state is not authority_model.ObligationState.SATISFIED
        for item in observed_verdict.failed_obligations
    )


def test_partial_coverage_drift_rejects_before_any_mutation() -> None:
    """A partial plan must reconcile every applied corridor with live CFG fact."""
    cfg = _make_cfg(
        [(0, 1), (0, 5), (1, 2), (5, 2), (2, 3), (2, 4)],
        stop_serials=(3, 4),
    )
    template = _ordinary_plan(
        PatchRedirectGoto,
        serials=(1, 2, 3),
        from_serial=1,
        old_target=2,
        new_target=3,
    )
    coverage = analyze_dispatcher_corridor_coverage(
        cfg,
        modifications=(RedirectGoto(from_serial=1, old_target=2, new_target=3),),
        dispatcher_entry_serial=2,
    )
    assert len(coverage.covered_corridors) == 1
    assert len(coverage.residual_corridors) == 1
    plan = _typed_bootstrap_authority_plan(
        cfg,
        template=template,
        dispatcher_entry_serial=2,
        dispatcher_member_serials=(1, 2, 5),
        authoritative_handler_serials=(3,),
        coverage=coverage,
        route_edge=(1, 3),
    )
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(
            cfg,
            plan,
            lifecycle_authority=SessionFragmentPublicationLifecycleAuthority(
                native_key=NATIVE_KEY,
                state=NativePreanalysisSessionState(evidence_generation=1),
            ),
        ),
        # The planned 0 -> 1 -> 2 corridor remains live after lower().
        translator=(translator := _FakeTranslator(cfg)),
    )

    assert backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks)) is cfg

    assert isinstance(backend.last_patch_failure, PatchTransactionPreflightRejected)
    assert translator.lower_calls == []
    assert translator.lift_count == 1


def test_project_patch_plan_lowers_conditional_state_to_canonical_two_way() -> None:
    """Every preflight consumer sees the typed lowering's logical CFG."""
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 5)],
        stop_serials=(3, 4, 5),
    )
    refs = {serial: _native_ref(serial) for serial in cfg.blocks}
    plan = PatchPlan(
        source_maturity=MaturityEnvelope(ir=None, provider="hexrays", provider_id=0),
        source_generation=0,
        snapshot_id="canonical-lower-projection",
        steps=(
            PatchLowerConditionalStateTransition(
                source_serial=refs[1],
                old_dispatcher_serial=refs[2],
                rewrite_from_ea=0x1001,
                condition_operand=SyntheticRegisterNonzeroCondition(9, 4),
                false_target_serial=refs[3],
                true_target_serial=refs[4],
            ),
        ),
        source_coordinates=tuple((refs[serial], serial) for serial in cfg.blocks),
    )

    projected = project_patch_plan(cfg, plan, snapshot_id=plan.snapshot_id).graph

    assert projected.blocks[1].succs == (3, 4)
    assert projected.blocks[1].kind is BlockKind.TWO_WAY
    assert projected.blocks[1].tail_kind is InsnKind.COND_JUMP
    assert projected.blocks[3].preds == (1,)
    assert projected.blocks[4].preds == (1,)


def test_unresolved_conditional_lowering_is_rejected_before_mutation() -> None:
    """An omitted typed coordinate cannot make preflight keep stale topology."""
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 5)],
        stop_serials=(3, 4, 5),
    )
    refs = {serial: _native_ref(serial) for serial in cfg.blocks}
    plan = PatchPlan(
        source_maturity=MaturityEnvelope(ir=None, provider="hexrays", provider_id=0),
        source_generation=0,
        snapshot_id="unresolved-lower-projection",
        steps=(
            PatchLowerConditionalStateTransition(
                source_serial=refs[1],
                old_dispatcher_serial=refs[2],
                rewrite_from_ea=0x1001,
                condition_operand=SyntheticRegisterNonzeroCondition(9, 4),
                false_target_serial=refs[3],
                true_target_serial=refs[4],
            ),
        ),
        source_coordinates=tuple(
            (refs[serial], serial) for serial in cfg.blocks if serial != 4
        ),
    )
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is cfg
    assert translator.lower_calls == []
    assert isinstance(backend.last_patch_failure, PatchTransactionPreflightRejected)
    assert "conditional state lowering" in str(backend.last_patch_failure)


def test_preflight_rejects_redirect_that_strands_reachable_call_block() -> None:
    """A cleanup redirect may not discard an executable call block."""
    base_cfg = _make_cfg([(0, 1), (1, 2)])
    call_block = replace(
        base_cfg.blocks[1],
        insn_snapshots=(
            InsnSnapshot(
                opcode=0,
                ea=0x1001,
                operands=(),
                kind=InsnKind.CALL,
            ),
        ),
    )
    cfg = FlowGraph(
        blocks={**base_cfg.blocks, 1: call_block},
        entry_serial=base_cfg.entry_serial,
        func_ea=base_cfg.func_ea,
    )
    plan = _ordinary_plan(
        PatchRedirectGoto,
        serials=(0, 1),
        from_serial=0,
        old_target=1,
        new_target=0,
    )
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is cfg
    assert translator.lower_calls == []
    assert isinstance(backend.last_patch_failure, PatchTransactionPreflightRejected)
    assert "effectful" in str(backend.last_patch_failure)


def test_conditional_lowering_coordinate_outside_snapshot_is_rejected_cleanly() -> None:
    """A present but unresolvable coordinate cannot leak a raw projection error."""
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 5)],
        stop_serials=(3, 4, 5),
    )
    refs = {serial: _native_ref(serial) for serial in cfg.blocks}
    plan = PatchPlan(
        source_maturity=MaturityEnvelope(ir=None, provider="hexrays", provider_id=0),
        source_generation=0,
        snapshot_id="out-of-snapshot-lower-projection",
        steps=(
            PatchLowerConditionalStateTransition(
                source_serial=refs[1],
                old_dispatcher_serial=refs[2],
                rewrite_from_ea=0x1001,
                condition_operand=SyntheticRegisterNonzeroCondition(9, 4),
                false_target_serial=refs[3],
                true_target_serial=refs[4],
            ),
        ),
        source_coordinates=tuple(
            (refs[serial], 99 if serial == 4 else serial) for serial in cfg.blocks
        ),
    )
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is cfg
    assert translator.lower_calls == []
    assert isinstance(backend.last_patch_failure, PatchTransactionPreflightRejected)
    assert "conditional state lowering" in str(backend.last_patch_failure)


def test_observed_native_call_serial_shift_does_not_poison() -> None:
    """Post-observation effect checks bind native effects, not old serials."""
    call = InsnSnapshot(
        opcode=57,
        ea=0x1010,
        native_ea=0x401010,
        operands=(),
        kind=InsnKind.CALL,
    )
    cfg = _make_cfg([(0, 1), (1, 2), (2, 3)])
    cfg_blocks = dict(cfg.blocks)
    cfg_blocks[1] = replace(
        cfg_blocks[1],
        start_ea=0x401010,
        native_start_ea=0x401010,
        insn_snapshots=(call,),
    )
    cfg = replace(cfg, blocks=cfg_blocks)
    plan = _ordinary_plan(
        PatchRedirectGoto,
        serials=(2, 3),
        from_serial=2,
        old_target=3,
        new_target=3,
    )

    observed_blocks = {
        10: replace(cfg.blocks[0], serial=10, succs=(11,), preds=()),
        11: replace(cfg.blocks[1], serial=11, succs=(12,), preds=(10,)),
        12: replace(cfg.blocks[2], serial=12, succs=(13,), preds=(11,)),
        13: replace(cfg.blocks[3], serial=13, succs=(), preds=(12,)),
    }
    observed = FlowGraph(
        blocks=observed_blocks,
        entry_serial=10,
        func_ea=cfg.func_ea,
    )

    class _ShiftedObservationTranslator(_FakeTranslator):
        def lift(self, _live_source: object) -> FlowGraph:
            self.lift_count += 1
            return cfg if self.lift_count == 1 else observed

    translator = _ShiftedObservationTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is observed
    assert translator.lower_calls == [plan]


def test_partial_coverage_without_proof_rejects_before_any_mutation() -> None:
    """Coverage truth is required even when a partial plan lacks a proof."""
    cfg = _make_cfg(
        [(0, 1), (0, 5), (1, 2), (5, 2), (2, 3), (2, 4)],
        stop_serials=(3, 4),
    )
    template = _ordinary_plan(
        PatchRedirectGoto,
        serials=(1, 2, 3),
        from_serial=1,
        old_target=2,
        new_target=3,
    )
    coverage = analyze_dispatcher_corridor_coverage(
        cfg,
        modifications=(RedirectGoto(from_serial=1, old_target=2, new_target=3),),
        dispatcher_entry_serial=2,
    )
    assert len(coverage.covered_corridors) == 1
    assert len(coverage.residual_corridors) == 1
    plan = _typed_bootstrap_authority_plan(
        cfg,
        template=template,
        dispatcher_entry_serial=2,
        dispatcher_member_serials=(1, 2, 5),
        authoritative_handler_serials=(3,),
        coverage=coverage,
        route_edge=(1, 3),
    )
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(
            cfg,
            plan,
            lifecycle_authority=SessionFragmentPublicationLifecycleAuthority(
                native_key=NATIVE_KEY,
                state=NativePreanalysisSessionState(evidence_generation=1),
            ),
        ),
        # The live CFG remains unchanged after the planned redirect.
        translator=translator,
    )

    assert backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks)) is cfg
    assert translator.lower_calls == []



def test_clean_binding_failure_preserves_original_exception(monkeypatch) -> None:
    """A pre-mutation binding error preserves the original failure."""
    # A partial plan needs no narrow full-retirement authority, so binding is
    # the first failure after its valid projected coverage check.
    cfg = _make_cfg(
        [(0, 1), (0, 5), (1, 2), (5, 2), (2, 3), (2, 4)],
        stop_serials=(3, 4),
    )
    plan = _ordinary_plan(
        PatchRedirectGoto,
        serials=(1, 2, 3),
        from_serial=1,
        old_target=2,
        new_target=3,
    )
    monkeypatch.setattr(
        "d810.hexrays.mutation.patch_transaction.bind_patch_plan",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("binding boom")),
    )
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=_FakeTranslator(cfg),
    )

    with pytest.raises(RuntimeError, match="binding boom"):
        backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

def test_same_plan_clean_retries_mint_distinct_transaction_attempt_ids(
    monkeypatch,
) -> None:
    """Two clean retries receive distinct transaction attempt IDs."""
    cfg = _make_cfg(
        [(0, 1), (0, 5), (1, 2), (5, 2), (2, 3), (2, 4)],
        stop_serials=(3, 4),
    )
    plan = _ordinary_plan(
        PatchRedirectGoto,
        serials=(1, 2, 3),
        from_serial=1,
        old_target=2,
        new_target=3,
    )
    failure_reasons = iter(("binding retry one", "binding retry two"))

    def reject_binding(*_args, **_kwargs):
        raise RuntimeError(next(failure_reasons))

    monkeypatch.setattr(
        "d810.hexrays.mutation.patch_transaction.bind_patch_plan",
        reject_binding,
    )
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=_FakeTranslator(cfg),
    )

    for reason in ("binding retry one", "binding retry two"):
        with pytest.raises(RuntimeError, match=reason):
            backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

def test_early_transaction_failure_mints_attempt_id(monkeypatch) -> None:
    """A failure before participant construction still mints an attempt ID."""
    cfg = _make_cfg(
        [(0, 1), (0, 5), (1, 2), (5, 2), (2, 3), (2, 4)],
        stop_serials=(3, 4),
    )
    plan = _ordinary_plan(
        PatchRedirectGoto,
        serials=(1, 2, 3),
        from_serial=1,
        old_target=2,
        new_target=3,
    )
    def fail_before_participant(*_args, **_kwargs):
        raise RuntimeError("early transaction setup failure")

    monkeypatch.setattr(
        "d810.hexrays.mutation.patch_transaction.execute_patch_transaction",
        fail_before_participant,
    )
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=_FakeTranslator(cfg),
    )

    with pytest.raises(RuntimeError, match="early transaction setup failure"):
        backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

def test_apply_lowers_plan_when_reachability_is_preserved() -> None:
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 3)],
        stop_serials=(3,),
    )
    plan = _ordinary_plan(
        PatchConvertToGoto,
        serials=(0, 1),
        block_serial=0,
        goto_target=1,
    )
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is cfg
    assert translator.lower_calls == [plan]
    assert translator.lift_count == 2


def _state_with_committed_semantic_owner(
    identity: StableBlockIdentity,
) -> NativePreanalysisSessionState:
    state = NativePreanalysisSessionState(evidence_generation=1)
    state._fragment_publication_mark_normalization_staged()
    state._fragment_publication_mark_normalization_validated()
    state._fragment_publication_mark_normalization_published_and_postvalidated()
    state.mark_canonical_semantic_plan_ready()
    state._fragment_publication_mark_semantic_fragment_staged()
    state._fragment_publication_mark_semantic_fragment_validated()
    state._fragment_publication_mark_semantic_fragment_published_and_postvalidated()
    state._fragment_publication_mark_receipt_committed()
    state._fragment_publication_commit_semantic_ownership(
        CommittedSemanticFragmentOwnership(
            plan_id="committed-semantic-plan",
            atomic_group_id="committed-semantic-group",
            evidence_generation=1,
            owners=(
                SemanticFragmentBlockOwner(
                    operation_id="committed-conditional",
                    source_block_id="native-body-edge@0x40C10A",
                    stable_identity=identity,
                ),
            ),
        )
    )
    return state


def test_apply_cleanly_rejects_patch_overlapping_committed_semantic_owner() -> None:
    cfg = _make_cfg([(0, 1), (1, 2)], stop_serials=(2,))
    plan = replace(
        _ordinary_plan(
            PatchConvertToGoto,
            serials=(0, 1),
            block_serial=0,
            goto_target=1,
        ),
        source_generation=1,
    )
    state = _state_with_committed_semantic_owner(_native_ref(0).identity)
    first_authority = SessionFragmentPublicationLifecycleAuthority(
        native_key=NATIVE_KEY,
        state=state,
    )
    second_authority = SessionFragmentPublicationLifecycleAuthority(
        native_key=NATIVE_KEY,
        state=state,
    )
    assert first_authority is not second_authority
    emitter = EventEmitter()
    phases: list[MbaCfgTransactionAuthorityObserved] = []
    emitter.on(MbaCfgTransactionAuthorityObserved, phases.append)
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(
            cfg,
            plan,
            event_emitter=emitter,
            lifecycle_authority=second_authority,
        ),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is cfg
    assert translator.lower_calls == []
    assert translator.lift_count == 1
    assert backend.last_patch_execution is None
    assert [event.phase for event in phases] == [
        CfgTransactionPhase.PLANNED,
        CfgTransactionPhase.PROJECTED,
        CfgTransactionPhase.REJECTED_CLEAN,
    ]
    failure = phases[-1].failure
    assert failure is not None
    assert not failure.live_mutation_started
    assert "committed-semantic-plan" in failure.reason
    assert "committed-conditional" in failure.reason
    assert "0x1000" in failure.reason


def test_shared_semantic_overlap_proof_is_serial_free_and_stable() -> None:
    cfg = _make_cfg([(0, 1), (1, 2)], stop_serials=(2,))
    plan = replace(
        _ordinary_plan(
            PatchConvertToGoto,
            serials=(0, 1),
            block_serial=0,
            goto_target=1,
        ),
        source_generation=1,
    )
    state = _state_with_committed_semantic_owner(_native_ref(0).identity)
    gateway = _ordinary_gateway(cfg, plan)

    overlap = find_patch_plan_semantic_ownership_overlap(
        plan,
        gateway.identity_index,
        state.committed_semantic_ownership(),
    )

    assert isinstance(overlap, PatchPlanSemanticOwnershipOverlap)
    assert overlap.publication.plan_id == "committed-semantic-plan"
    assert overlap.owner.operation_id == "committed-conditional"
    assert overlap.identity == _native_ref(0).identity
    assert not hasattr(overlap, "serial")
    assert not hasattr(overlap, "coordinate")
    reason = format_patch_plan_semantic_ownership_overlap(overlap)
    assert "committed-semantic-plan" in reason
    assert "committed-conditional" in reason
    assert "0x1000" in reason
    assert plan.plan_id not in reason

    disjoint = replace(
        plan,
        steps=(
            PatchConvertToGoto(
                block_serial=_native_ref(1),
                goto_target=_native_ref(2),
            ),
        ),
        source_coordinates=((_native_ref(1), 1), (_native_ref(2), 2)),
    )
    assert (
        find_patch_plan_semantic_ownership_overlap(
            disjoint,
            gateway.identity_index,
            state.committed_semantic_ownership(),
        )
        is None
    )


def test_apply_allows_patch_disjoint_from_committed_semantic_owner() -> None:
    cfg = _make_cfg([(0, 1), (1, 2)], stop_serials=(2,))
    plan = replace(
        _ordinary_plan(
            PatchConvertToGoto,
            serials=(1, 2),
            block_serial=1,
            goto_target=2,
        ),
        source_generation=1,
    )
    state = _state_with_committed_semantic_owner(_native_ref(0).identity)
    authority = SessionFragmentPublicationLifecycleAuthority(
        native_key=NATIVE_KEY,
        state=state,
    )
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(
            cfg,
            plan,
            lifecycle_authority=authority,
        ),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is cfg
    assert translator.lower_calls == [plan]
    assert translator.lift_count == 2


def test_backend_poisons_when_observed_graph_collapses_entry_reachability() -> None:
    pre_cfg = _make_cfg(
        [(serial, serial + 1) for serial in range(25)],
        stop_serials=(25,),
    )
    post_cfg = _make_cfg(
        [
            (0, 1),
            (1, 2),
            (2, 1),
            *((serial, serial + 1) for serial in range(3, 25)),
        ],
        stop_serials=(25,),
    )
    plan = _ordinary_plan(
        PatchConvertToGoto,
        serials=(0, 1),
        block_serial=0,
        goto_target=1,
    )
    emitter = EventEmitter()
    phases: list[MbaCfgTransactionAuthorityObserved] = []
    emitter.on(MbaCfgTransactionAuthorityObserved, phases.append)

    class _CollapsingTranslator(_FakeTranslator):
        def lift(self, _live_source: object) -> FlowGraph:
            self.lift_count += 1
            return post_cfg if self.lower_calls else pre_cfg

    lifecycle_state = NativePreanalysisSessionState(evidence_generation=0)
    gateway = _ordinary_gateway(
        pre_cfg,
        plan,
        event_emitter=emitter,
        lifecycle_authority=SessionFragmentPublicationLifecycleAuthority(
            native_key=NATIVE_KEY,
            state=lifecycle_state,
        ),
    )
    backend = HexRaysMutationBackend(
        mutation_gateway=gateway,
        translator=_CollapsingTranslator(pre_cfg),
    )

    with pytest.raises(CfgGenerationPoisoned):
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))

    assert gateway.generation_poisoned
    assert phases[-1].phase is CfgTransactionPhase.POISONED_RESTART_REQUIRED
    assert phases[-1].failure is not None
    assert (
        phases[-1].failure.first_failed_obligation
        == "runtime:post_observation_contract"
    )
    assert lifecycle_state.has_pending_generated_restart
    assert backend.last_patch_execution is None


def test_backend_poisons_when_observed_graph_strands_reachable_call() -> None:
    """Post-apply observation independently preserves executable call blocks."""
    pre_cfg = _make_cfg([(0, 1), (1, 2)])
    pre_cfg = replace(
        pre_cfg,
        blocks={
            **pre_cfg.blocks,
            1: replace(
                pre_cfg.blocks[1],
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=0x1001,
                        operands=(),
                        kind=InsnKind.CALL,
                        is_call=True,
                    ),
                ),
            ),
        },
    )
    observed_cfg = _make_cfg([(0, 0), (1, 2)])
    plan = _ordinary_plan(
        PatchConvertToGoto,
        serials=(0, 1),
        block_serial=0,
        goto_target=1,
    )

    class _StrandingTranslator(_FakeTranslator):
        def lift(self, _live_source: object) -> FlowGraph:
            self.lift_count += 1
            return observed_cfg if self.lower_calls else pre_cfg

    gateway = _ordinary_gateway(pre_cfg, plan)
    backend = HexRaysMutationBackend(
        mutation_gateway=gateway,
        translator=_StrandingTranslator(pre_cfg),
    )

    with pytest.raises(CfgGenerationPoisoned):
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))

    assert gateway.generation_poisoned
    assert backend.last_patch_execution is None


def _local_alias_store_cfg(*, extra_call: bool = False) -> FlowGraph:
    cfg = _make_cfg([(0, 1), (1, 2)], stop_serials=(2,))
    store = InsnSnapshot(
        opcode=58,
        ea=0x1101,
        native_ea=0x1101,
        operands=(),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=1),
        d=MopSnapshot(kind=OperandKind.LVAR, size=8),
        kind=InsnKind.STORE,
        display_text="stx #1.4, ds.2, %var_398.8",
    )
    instructions = (store,)
    if extra_call:
        instructions += (
            InsnSnapshot(
                opcode=57,
                ea=0x1102,
                native_ea=0x1102,
                operands=(),
                kind=InsnKind.CALL,
                is_call=True,
            ),
        )
    return replace(
        cfg,
        blocks={
            **cfg.blocks,
            1: replace(
                cfg.blocks[1],
                start_ea=0x1001,
                native_start_ea=0x1001,
                insn_snapshots=instructions,
            ),
        },
    )


def _local_alias_scalarization_plan() -> PatchPlan:
    ref = _native_ref(1)
    return PatchPlan(
        source_maturity=MaturityEnvelope(
            ir=None,
            provider="hexrays",
            provider_id=0,
        ),
        source_generation=0,
        steps=(
            PatchScalarizeLocalAliasAccess(
                block_serial=ref,
                host_ea=0x1101,
                host_opcode=58,
                alias_token="%var_398",
                base_token="%var_398",
                value_size=4,
            ),
        ),
        source_coordinates=((ref, 1),),
    )


def _typed_local_alias_fixture(
    *, two_hosts: bool = False, sibling_kind: InsnKind = InsnKind.STORE,
) -> tuple[FlowGraph, PatchPlan]:
    """Build a real producer proposal with one reachable STORE owner."""

    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

    source, proposal, _exclusion, refs = exact_fixture()
    source = replace(
        source,
        blocks={
            **source.blocks,
            2: replace(
                source.blocks[2],
                insn_snapshots=(InsnSnapshot(
                    opcode=0,
                    ea=0x3000,
                    native_ea=0x3000,
                    operands=(),
                    l=MopSnapshot(kind=OperandKind.LVAR, size=4),
                    display_text="store %var_alias",
                    kind=InsnKind.STORE,
                ),),
            ),
        },
    )
    if two_hosts:
        from dataclasses import replace as dataclass_replace
        from d810.transforms.unflatten_authority import producer_api

        source = replace(
            source,
            blocks={
                **source.blocks,
                2: replace(
                    source.blocks[2],
                    insn_snapshots=(
                        source.blocks[2].insn_snapshots[0],
                        InsnSnapshot(
                            opcode=0,
                            ea=0x3001,
                            native_ea=0x3001,
                            operands=(),
                            l=MopSnapshot(kind=OperandKind.LVAR, size=4),
                            display_text=(
                                "store %var_alias2"
                                if sibling_kind is InsnKind.STORE
                                else "call %var_sibling"
                            ),
                            kind=sibling_kind,
                            is_call=sibling_kind is InsnKind.CALL,
                        ),
                    ),
                ),
            },
        )
        old_identity = refs[2].identity
        refs = {
            **refs,
            2: NativeBlockRef(StableBlockIdentity.from_instruction_eas(
                (0x3000, 0x3001), native_key=old_identity.native_key,
            )),
        }
        route_proofs = tuple(
            dataclass_replace(
                proof,
                destinations=tuple(
                    dataclass_replace(destination, target_identity=refs[2].identity)
                    if destination.target_identity == old_identity else destination
                    for destination in proof.destinations
                ),
            )
            for proof in proposal.route_evidence.route_proofs
        )
        route_evidence = dataclass_replace(
            proposal.route_evidence, route_proofs=route_proofs,
        )
        proposal = producer_api.build_proposal(
            plan_id=proposal.plan_id,
            source=source,
            block_refs_by_serial=refs,
            source_generation=proposal.source_identity_catalog.generation,
            canonical_route_evidence=route_evidence,
                exact_state_effect_exclusions=(_exclusion,),
            dispatcher_entry_serial=1,
            dispatcher_member_serials=(0, 1),
            authoritative_handler_serials=(2,),
            state_identity=proposal.plan_inputs.state_identity,
            use_def_witness=proposal.use_def_witness,
        )
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("typed-local-alias-snapshot"),
        source_maturity=MaturityEnvelope(ir=None, provider="hexrays", provider_id=0),
        source_generation=proposal.source_identity_catalog.generation,
        steps=(
            PatchRedirectGoto(refs[0], refs[1], refs[1]),
            PatchRedirectBranch(refs[1], refs[2], refs[2]),
            PatchRemoveEdge(refs[2], refs[3]),
            PatchRemoveEdge(refs[2], refs[4]),
            PatchScalarizeLocalAliasAccess(
                block_serial=refs[2],
                host_ea=0x3000,
                host_opcode=0,
                alias_token="%var_alias",
                base_token="%var_398",
                value_size=4,
            ),
            *(() if not two_hosts or sibling_kind is not InsnKind.STORE else (
                PatchScalarizeLocalAliasAccess(
                    block_serial=refs[2],
                    host_ea=0x3001,
                    host_opcode=0,
                    alias_token="%var_alias2",
                    base_token="%var_399",
                    value_size=4,
                ),
            )),
        ),
        source_coordinates=tuple((ref, serial) for serial, ref in refs.items()),
        unflatten_proposal=proposal,
    )
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest
    proposal = replace(
        proposal,
        plan_inputs=replace(
            proposal.plan_inputs,
            dispatcher_member_refs=(refs[0], refs[1]),
        ),
        use_def_witness=replace(
            proposal.use_def_witness,
            redirect_owner_refs=canonical_redirect_manifest(plan).owner_refs,
            redirect_digest=canonical_redirect_manifest(plan).digest,
        ),
    )
    plan = replace(plan, unflatten_proposal=proposal)
    return source, plan


def _typed_lowering_fixture() -> tuple[FlowGraph, PatchPlan]:
    """Build typed lower authority with a no-op redirect on a one-way source."""

    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture
    from d810.transforms.unflatten_authority.proposal import canonical_redirect_manifest

    source, original_proposal, exclusion, refs = exact_fixture()
    from d810.transforms.unflatten_authority import producer_api
    proposal = producer_api.build_proposal(
        plan_id=original_proposal.plan_id,
        source=source,
        block_refs_by_serial=refs,
        source_generation=original_proposal.source_identity_catalog.generation,
        canonical_route_evidence=original_proposal.route_evidence,
        exact_state_effect_exclusions=(exclusion,),
        dispatcher_entry_serial=0,
        dispatcher_member_serials=(0,),
        authoritative_handler_serials=(2,),
        state_identity=original_proposal.plan_inputs.state_identity,
        use_def_witness=original_proposal.use_def_witness,
    )
    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("typed-lowering-snapshot"),
        source_maturity=MaturityEnvelope(ir=None, provider="hexrays", provider_id=0),
        source_generation=proposal.source_identity_catalog.generation,
        steps=(
            PatchRedirectGoto(refs[0], refs[1], refs[1]),
            PatchLowerConditionalStateTransition(
                source_serial=refs[1],
                old_dispatcher_serial=refs[2],
                rewrite_from_ea=0x2001,
                condition_operand="typed-live-predicate",
                false_target_serial=refs[2],
                true_target_serial=refs[3],
            ),
        ),
        source_coordinates=tuple((ref, serial) for serial, ref in refs.items()),
        unflatten_proposal=proposal,
    )
    manifest = canonical_redirect_manifest(plan)
    proposal = replace(
        proposal,
        use_def_witness=replace(
            proposal.use_def_witness,
            redirect_owner_refs=manifest.owner_refs,
            redirect_digest=manifest.digest,
        ),
    )
    return source, replace(plan, unflatten_proposal=proposal)


def _observed_scalarized_cfg(
    source: FlowGraph,
    *,
    reachable: bool = True,
    host_call: bool = False,
) -> FlowGraph:
    block = source.blocks[1]
    scalar_move = (
        InsnSnapshot(
            opcode=57,
            ea=0x1101,
            native_ea=0x1101,
            operands=(),
            kind=InsnKind.CALL,
            is_call=True,
        )
        if host_call
        else InsnSnapshot(
            opcode=4,
            ea=0x1101,
            native_ea=0x1101,
            operands=(),
            l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=1),
            d=MopSnapshot(kind=OperandKind.LVAR, size=4),
            kind=InsnKind.MOV,
            display_text="mov #1.4, %var_398.4",
        )
    )
    observed = replace(
        source,
        blocks={
            **source.blocks,
            1: replace(block, insn_snapshots=(scalar_move,)),
        },
    )
    if reachable:
        return observed
    return _make_cfg([(0, 2), (1, 2)], stop_serials=(2,))


def _observed_typed_local_alias_cfg(
    source: FlowGraph, *, two_hosts: bool = False, drop_second: bool = False,
) -> FlowGraph:
    block = source.blocks[2]
    observations = (
        InsnSnapshot(
            opcode=4,
            ea=0x3000,
            native_ea=0x3000,
            operands=(),
            l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=1),
            d=MopSnapshot(kind=OperandKind.LVAR, size=4),
            kind=InsnKind.MOV,
            display_text="mov #1.4, %var_398.4",
        ),
    )
    if two_hosts and not drop_second:
        observations += (
            InsnSnapshot(
                opcode=4,
                ea=0x3001,
                native_ea=0x3001,
                operands=(),
                l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=2),
                d=MopSnapshot(kind=OperandKind.LVAR, size=4),
                kind=InsnKind.MOV,
                display_text="mov #2.4, %var_399.4",
            ),
        )
    return replace(
        source,
        blocks={
            **source.blocks,
            2: replace(
                block,
                insn_snapshots=observations,
            ),
        },
    )


def _typed_effect_subject(case: authority_model.SemanticSafetyCase, ea: int):
    return next(
        subject for subject in case.subjects
        if subject.kind is authority_model.SemanticSubjectKind.EFFECT
        and type(subject.locator) is authority_model.EffectSubjectLocator
        and subject.locator.instruction_ea == ea
    )


def _assert_typed_effect_cell(
    case: authority_model.SemanticSafetyCase,
    *,
    ea: int,
    state: authority_model.ObligationState | tuple[authority_model.ObligationState, ...],
    rule: authority_model.UnflattenJustificationRule,
) -> None:
    subject = _typed_effect_subject(case, ea)
    key = authority_model.ObligationKey(
        subject, authority_model.SafetyDimension.EFFECT_PRESERVATION,
    )
    cell = next(cell for cell in case.obligation_index.cells if cell.key == key)
    expected_states = (state,) if type(state) is authority_model.ObligationState else state
    assert cell.state in expected_states
    justification_ids = (
        cell.supporting_justification_ids + cell.refuting_justification_ids
    )
    justifications = tuple(
        item for item in case.justifications
        if item.justification_id in justification_ids
    )
    assert any(item.rule is rule and item.conclusion == key for item in justifications)


def _mutate_typed_alias_host(source: FlowGraph, **changes: object) -> FlowGraph:
    block = source.blocks[2]
    observation = replace(block.insn_snapshots[0], **changes)
    return replace(
        source,
        blocks={2: replace(block, insn_snapshots=(observation,)), **{
            serial: item for serial, item in source.blocks.items() if serial != 2
        }},
    )


def _typed_alias_backend(
    pre_cfg: FlowGraph, plan: PatchPlan, observed_cfg: FlowGraph,
) -> HexRaysMutationBackend:
    class _ScalarizingTranslator(_FakeTranslator):
        def lift(self, _live_source: object) -> FlowGraph:
            self.lift_count += 1
            return observed_cfg if self.lower_calls else pre_cfg

    gateway = _ordinary_gateway(
        pre_cfg,
        plan,
        native_key=next(
            ref.identity.native_key
            for ref, _serial in plan.source_coordinates
            if isinstance(ref, NativeBlockRef)
        ),
    )
    return HexRaysMutationBackend(
        mutation_gateway=gateway,
        translator=_ScalarizingTranslator(pre_cfg),
    )


def test_backend_typed_authority_emits_two_canonical_phase_payloads(monkeypatch) -> None:
    """Typed authority records projected and observed canonical verdicts."""

    pre_cfg, plan = _typed_local_alias_fixture()
    observed_cfg = _observed_typed_local_alias_cfg(pre_cfg)
    backend = _typed_alias_backend(pre_cfg, plan, observed_cfg)
    import d810.hexrays.observability as authority_observability
    phase_observations = []
    monkeypatch.setattr(
        authority_observability,
        "observe_unflatten_authority_phase",
        lambda *, observation_factory, **_kwargs: phase_observations.extend(
            observation_factory()
        ),
    )
    result = backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))

    assert result is observed_cfg
    assert backend.last_patch_execution is not None
    execution = backend.last_patch_execution
    assert execution.projected_unflatten_verdict is not None
    assert execution.observed_unflatten_verdict is not None
    assert len(phase_observations) == 2
    projected_payload, observed_payload = (
        item.payload for item in phase_observations
    )
    assert projected_payload["phase"] == execution.projected_unflatten_verdict.phase.value
    assert observed_payload["phase"] == execution.observed_unflatten_verdict.phase.value
    assert projected_payload["authority_id"] == execution.projected_unflatten_verdict.authority_id
    assert observed_payload["authority_id"] == execution.observed_unflatten_verdict.authority_id
    assert projected_payload["case_id"] == execution.projected_unflatten_verdict.case_id
    assert observed_payload["case_id"] == execution.observed_unflatten_verdict.case_id
    assert projected_payload["phase"] == "projected_preflight"
    assert observed_payload["phase"] == "observed_post_apply"
    assert projected_payload["authority_id"] == observed_payload["authority_id"]
    assert projected_payload["case_id"] and observed_payload["case_id"]
    assert projected_payload["case_id"] != observed_payload["case_id"]
    assert projected_payload["binding_id"] is None
    assert observed_payload["binding_id"]
    for payload in (projected_payload, observed_payload):
        assert payload["plan_id"] == plan.plan_id
        assert payload["attempt_id"]
        assert payload["session_id"]
    assert projected_payload["generation"] == execution.projected_unflatten_verdict.safety_case.candidate_generation
    assert observed_payload["generation"] == execution.observed_unflatten_verdict.safety_case.candidate_generation


def test_canonical_phase_observer_contains_subscriber_failure(
    monkeypatch,
) -> None:
    """The fire-and-forget diagnostic boundary contains subscriber failures."""

    import d810.hexrays.observability as authority_observability
    from d810.transforms.unflatten_authority.diagnostics import phase_observation

    verdict = authority_model.UnflattenAuthorityVerdict(
        False,
        authority_model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        authority_model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        authority_id("observer-authority"),
        None,
        None,
        authority_id("observer-candidate"),
        None,
        (),
    )
    observation = phase_observation(
        verdict,
        maturity="MMAT_GLBOPT1",
        source_ea=0x401000,
    )

    monkeypatch.setattr(authority_observability, "diagnostics_enabled", lambda: True)
    monkeypatch.setattr(authority_observability, "mba_to_block_snapshots", lambda _mba: ())
    monkeypatch.setattr(
        authority_observability,
        "request_capture_mba_snapshot",
        lambda **_kwargs: object(),
    )
    subscriber_calls = []

    def fail_subscriber(*args, **kwargs):
        subscriber_calls.append((args, kwargs))
        raise RuntimeError("diagnostic subscriber failed")

    monkeypatch.setattr(
        observability_preanalysis,
        "observe_fact_observation",
        fail_subscriber,
    )

    authority_observability.observe_unflatten_authority_phase(
        mba=SimpleNamespace(func_ea=0x401000, maturity=0),
        verdict=verdict,
        observations=(observation,),
    )
    assert len(subscriber_calls) == 1


def test_canonical_phase_observer_contains_registry_probe_failure(
    monkeypatch,
) -> None:
    import d810.hexrays.observability as authority_observability

    monkeypatch.setattr(
        authority_observability,
        "diagnostics_enabled",
        lambda: (_ for _ in ()).throw(RuntimeError("registry failed")),
    )
    authority_observability.observe_unflatten_authority_phase(
        mba=SimpleNamespace(func_ea=0x401000, maturity=0),
        verdict=object(),
    )


def test_canonical_phase_observer_rejects_non_singleton_rows(
    monkeypatch,
) -> None:
    import d810.hexrays.observability as authority_observability

    verdict = authority_model.UnflattenAuthorityVerdict(
        False,
        authority_model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        authority_model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        authority_id("observer-cardinality-authority"),
        None,
        None,
        authority_id("observer-cardinality-candidate"),
        None,
        (),
    )
    captures = []
    monkeypatch.setattr(authority_observability, "diagnostics_enabled", lambda: True)
    monkeypatch.setattr(
        authority_observability,
        "request_capture_mba_snapshot",
        lambda **kwargs: captures.append(kwargs),
    )
    for observations in ((), (object(),), (object(), object())):
        authority_observability.observe_unflatten_authority_phase(
            mba=SimpleNamespace(func_ea=0x401000, maturity=0),
            verdict=verdict,
            observations=observations,
        )
    assert captures == []


def test_typed_canonical_acceptance_does_not_reapply_failed_generic_gate(monkeypatch) -> None:
    """The accepted typed verdict is final at the transaction boundary."""

    pre_cfg, plan = _typed_local_alias_fixture()
    observed_cfg = _observed_typed_local_alias_cfg(pre_cfg)
    backend = _typed_alias_backend(pre_cfg, plan, observed_cfg)
    from d810.analyses.control_flow.graph_checks import EntryReachabilityResult
    from d810.hexrays.mutation import patch_transaction
    from d810.transforms.unflatten_authority import transaction_api

    failed_entry = EntryReachabilityResult(
        passed=False,
        pre_reachable_count=10,
        post_reachable_count=0,
        retained_ratio=0.0,
        min_pre_reachable=0,
        min_retained_ratio=1.0,
        reason="forced_test_failure",
    )
    captured = {}
    real_prepare = transaction_api.prepare_unflatten_authority_timed
    real_entry_check = patch_transaction.check_entry_reachability_not_collapsed
    entry_check_calls = 0

    def staged_entry_check(*args, **kwargs):
        nonlocal entry_check_calls
        entry_check_calls += 1
        if entry_check_calls == 1:
            return failed_entry
        return real_entry_check(*args, **kwargs)

    monkeypatch.setattr(
        patch_transaction,
        "check_entry_reachability_not_collapsed",
        staged_entry_check,
    )

    def capture_prepare(**kwargs):
        captured["generic_gates"] = kwargs["generic_gates"]
        accepted_gates = replace(
            kwargs["generic_gates"],
            entry=real_entry_check(
                kwargs["source"],
                post_adj=kwargs["projection"].graph.as_adjacency_dict(),
            ),
        )
        result = real_prepare(**{**kwargs, "generic_gates": accepted_gates})
        captured["result"] = result
        return result

    monkeypatch.setattr(
        transaction_api, "prepare_unflatten_authority_timed", capture_prepare,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))

    assert result is observed_cfg
    assert backend.last_patch_failure is None
    assert backend._translator.lower_calls
    gates = captured["generic_gates"]
    assert gates.entry is failed_entry
    assert isinstance(
        captured["result"], transaction_api.TimedUnflattenAuthorityResult,
    )
    assert captured["result"].result.__class__ is authority_model.UnflattenAuthorityPreparationAccepted


def test_backend_canonical_projected_rejection_is_decisive(monkeypatch) -> None:
    """A canonical preflight rejection is fatal before mutation."""

    pre_cfg, plan = _typed_local_alias_fixture()
    observed_cfg = pre_cfg
    backend = _typed_alias_backend(pre_cfg, plan, observed_cfg)
    from d810.transforms.unflatten_authority import transaction_api

    rejected = authority_model.UnflattenAuthorityVerdict(
        False,
        authority_model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        authority_model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        authority_id("canonical-projected-rejection"), None, None,
        authority_id("canonical-projected-candidate"), None, (),
    )
    monkeypatch.setattr(
        transaction_api,
        "prepare_unflatten_authority_timed",
        lambda **_kwargs: transaction_api.TimedUnflattenAuthorityResult(
            authority_model.UnflattenAuthorityPreparationRejected(rejected),
            transaction_api.PhaseTimings(inventory_ms=1.0, binding_ms=1.0, evaluation_ms=1.0),
        ),
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))

    assert result is observed_cfg
    assert backend.last_patch_execution is None
    assert backend.last_patch_failure is not None
    assert backend.last_patch_failure.unflatten_verdict is rejected


def test_backend_applicable_unflatten_not_applicable_is_decisive(monkeypatch) -> None:
    """An applicable unflatten route may not fall through as ordinary."""

    pre_cfg, plan = _typed_local_alias_fixture()
    backend = _typed_alias_backend(pre_cfg, plan, pre_cfg)
    from d810.transforms.unflatten_authority import transaction_api

    monkeypatch.setattr(
        transaction_api,
        "prepare_unflatten_authority_timed",
        lambda **_kwargs: transaction_api.TimedUnflattenAuthorityResult(
            authority_model.UnflattenAuthorityNotApplicable(
                route=transaction_api.UnflattenPlanRoute.ORDINARY,
            ),
            transaction_api.PhaseTimings(
                inventory_ms=1.0, binding_ms=1.0, evaluation_ms=1.0,
            ),
        ),
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))

    assert result is pre_cfg
    assert backend.last_patch_execution is None
    assert isinstance(backend.last_patch_failure, PatchTransactionPreflightRejected)
    assert str(backend.last_patch_failure) == (
        "applicable unflatten route returned not-applicable"
    )
    assert backend.last_patch_failure.unflatten_verdict is None
    assert backend._translator.lower_calls == []


def test_backend_canonical_projected_prepare_exception_is_decisive(monkeypatch) -> None:
    pre_cfg, plan = _typed_local_alias_fixture()
    backend = _typed_alias_backend(pre_cfg, plan, pre_cfg)
    from d810.transforms.unflatten_authority import transaction_api

    def raise_prepare(**_kwargs):
        raise RuntimeError("projected canonical prepare exploded")

    monkeypatch.setattr(transaction_api, "prepare_unflatten_authority_timed", raise_prepare)

    with pytest.raises(RuntimeError, match="projected canonical prepare exploded"):
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))
    assert backend.last_patch_execution is None


def test_backend_malformed_projected_canonical_prepare_is_decisive(monkeypatch) -> None:
    pre_cfg, plan = _typed_local_alias_fixture()
    backend = _typed_alias_backend(pre_cfg, plan, pre_cfg)
    from d810.transforms.unflatten_authority import transaction_api

    monkeypatch.setattr(transaction_api, "prepare_unflatten_authority_timed", lambda **_kwargs: object())

    with pytest.raises(TypeError, match="malformed outcome"):
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))
    assert backend.last_patch_execution is None


def test_backend_canonical_observed_rejection_is_decisive(monkeypatch) -> None:
    """A canonical post-apply rejection poisons after mutation."""

    pre_cfg, plan = _typed_local_alias_fixture()
    observed_cfg = pre_cfg
    backend = _typed_alias_backend(pre_cfg, plan, observed_cfg)
    from d810.transforms.unflatten_authority import transaction_api

    def reject_observed(**_kwargs):
        return transaction_api.TimedUnflattenAuthorityResult(
            authority_model.UnflattenAuthorityVerdict(
                False,
                authority_model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
                authority_model.UnflattenAuthorityReason.LIVE_BINDING_FAILED,
                authority_id("canonical-observed-rejection"), None, None,
                authority_id("canonical-observed-candidate"), None, (),
            ),
            transaction_api.PhaseTimings(inventory_ms=1.0, binding_ms=1.0, evaluation_ms=1.0),
        )

    monkeypatch.setattr(
        transaction_api, "revalidate_observed_unflatten_authority_timed", reject_observed,
    )

    from d810.hexrays.mutation.patch_transaction import PatchTransactionPoisoned

    with pytest.raises(PatchTransactionPoisoned) as raised:
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))
    assert isinstance(raised.value.__cause__, PatchTransactionPostObservationRejected)
    assert raised.value.__cause__.unflatten_verdict is not None


def test_backend_canonical_observed_revalidate_exception_is_decisive(monkeypatch) -> None:
    pre_cfg, plan = _typed_local_alias_fixture()
    backend = _typed_alias_backend(pre_cfg, plan, pre_cfg)
    from d810.transforms.unflatten_authority import transaction_api

    def raise_revalidate(**_kwargs):
        raise RuntimeError("observed canonical revalidate exploded")

    monkeypatch.setattr(
        transaction_api,
        "revalidate_observed_unflatten_authority_timed",
        raise_revalidate,
    )

    from d810.hexrays.mutation.patch_transaction import PatchTransactionPoisoned

    with pytest.raises(PatchTransactionPoisoned, match="observed canonical revalidate exploded"):
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))


def test_backend_canonical_bind_rejection_is_decisive(monkeypatch) -> None:
    """A bind-only canonical rejection cleanly aborts before mutation."""

    pre_cfg, plan = _typed_local_alias_fixture()
    observed_cfg = pre_cfg
    backend = _typed_alias_backend(pre_cfg, plan, observed_cfg)
    import d810.hexrays.observability as authority_observability
    from d810.transforms.unflatten_authority import transaction_api

    phase_observations = []
    monkeypatch.setattr(
        authority_observability,
        "observe_unflatten_authority_phase",
        lambda *, observation_factory, **_kwargs: phase_observations.extend(
            observation_factory()
        ),
    )

    rejected = authority_model.UnflattenAuthorityVerdict(
        False,
        authority_model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        authority_model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        authority_id("canonical-bind-rejection"), None, None,
        authority_id("canonical-bind-candidate"), None, (),
    )
    monkeypatch.setattr(
        transaction_api,
        "bind_prepared_unflatten_authority",
        lambda **_kwargs: authority_model.UnflattenAuthorityBindingRejected(rejected),
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))

    assert result is observed_cfg
    assert backend.last_patch_execution is None
    assert backend.last_patch_failure is not None
    assert backend.last_patch_failure.unflatten_verdict is rejected
    assert len(phase_observations) == 1
    assert phase_observations[0].payload["accepted"] is False
    assert phase_observations[0].payload["reason"] == "projected_binding_failed"
    assert phase_observations[0].payload["authority_id"] == rejected.authority_id


def test_backend_canonical_bind_exception_is_decisive(monkeypatch) -> None:
    pre_cfg, plan = _typed_local_alias_fixture()
    backend = _typed_alias_backend(pre_cfg, plan, pre_cfg)
    from d810.transforms.unflatten_authority import transaction_api

    def raise_bind(**_kwargs):
        raise RuntimeError("canonical bind exploded")

    monkeypatch.setattr(transaction_api, "bind_prepared_unflatten_authority", raise_bind)

    with pytest.raises(RuntimeError, match="canonical bind exploded"):
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))
    assert backend.last_patch_execution is None


def test_backend_canonical_observed_provenance_drift_is_decisive(monkeypatch) -> None:
    """Observed provenance drift poisons after mutation."""

    pre_cfg, plan = _typed_local_alias_fixture()
    observed_cfg = pre_cfg
    backend = _typed_alias_backend(pre_cfg, plan, observed_cfg)
    from d810.transforms.unflatten_authority import transaction_api

    def accept_bind(**kwargs):
        prepared = kwargs["prepared"]
        patch_binding = kwargs["patch_binding"]
        authority = object.__new__(authority_model.BoundUnflattenAuthority)
        object.__setattr__(authority, "binding_id", authority_id("canonical-bind"))
        object.__setattr__(authority, "prepared", prepared)
        object.__setattr__(authority, "attempt_id", patch_binding.attempt_id)
        object.__setattr__(authority, "session_id", patch_binding.session_id)
        object.__setattr__(authority, "generation", patch_binding.generation)
        object.__setattr__(authority, "live_maturity", patch_binding.maturity)
        object.__setattr__(authority, "live_bindings", patch_binding.bindings)
        object.__setattr__(authority, "patch_binding", patch_binding)
        return authority_model.UnflattenAuthorityBindingAccepted(authority)

    monkeypatch.setattr(transaction_api, "bind_prepared_unflatten_authority", accept_bind)

    def reject_provenance(*_args, **_kwargs):
        raise ValueError("observed authority provenance drift")

    monkeypatch.setattr(
        transaction_api,
        "revalidate_bound_patch_plan_against_prepared",
        reject_provenance,
    )

    from d810.hexrays.mutation.patch_transaction import PatchTransactionPoisoned

    with pytest.raises(PatchTransactionPoisoned) as raised:
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))
    assert isinstance(raised.value.__cause__, PatchTransactionPostObservationRejected)
    assert "observed authority provenance drift" in str(raised.value.__cause__.__cause__)


def test_backend_accepts_exact_reachable_local_alias_store_scalarization(monkeypatch) -> None:
    """A typed scalarization may replace only its exact local-alias STORE."""

    pre_cfg, plan = _typed_local_alias_fixture()
    observed_cfg = _observed_typed_local_alias_cfg(pre_cfg)

    backend = _typed_alias_backend(pre_cfg, plan, observed_cfg)
    import d810.hexrays.observability as authority_observability
    phase_observations = []

    monkeypatch.setattr(
        authority_observability,
        "observe_unflatten_authority_phase",
        lambda *, observation_factory, **_kwargs: phase_observations.extend(
            observation_factory()
        ),
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))
    assert result is observed_cfg
    assert backend.last_patch_execution is not None
    execution = backend.last_patch_execution
    assert execution is not None
    assert execution.projected_unflatten_verdict is not None
    assert execution.observed_unflatten_verdict is not None
    assert execution.projected_unflatten_verdict.safety_case is not None
    assert execution.observed_unflatten_verdict.safety_case is not None
    projected_ledger = authority_views.semantic_loss_ledger(
        execution.projected_unflatten_verdict.safety_case,
    )
    observed_ledger = authority_views.semantic_loss_ledger(
        execution.observed_unflatten_verdict.safety_case,
    )
    assert projected_ledger.rows == ()
    assert len(observed_ledger.rows) == 1
    loss_row = observed_ledger.rows[0]
    assert loss_row.kind is authority_model.SemanticLossKind.LOCAL_ALIAS_SCALARIZATION
    assert loss_row.anchored_location == "blk2@0x3000"
    assert any(
        type(claim) is authority_model.LocalAliasEffectScalarizationClaim
        for claim in execution.projected_unflatten_verdict.safety_case.claims
    )
    assert len(phase_observations) == 2
    projected_payload, observed_payload = (
        item.payload for item in phase_observations
    )
    assert "parity" not in projected_payload
    assert "parity" not in observed_payload
    assert projected_payload["observed_only_loss"] == ()
    assert len(observed_payload["observed_only_loss"]) == 1
    observed_only = observed_payload["observed_only_loss"][0]
    assert observed_only["anchor"] == "blk2@0x3000"
    assert observed_only["classification"] == "local_alias_scalarization"
    for payload in (projected_payload, observed_payload):
        timings = payload["timings"]
        assert all(
            isinstance(timings[name], float) and timings[name] >= 0.0
            for name in (
                "inventory_ms", "binding_ms", "evaluation_ms", "views_ms",
                "total_authority_ms",
            )
        )
        assert timings["total_authority_ms"] == pytest.approx(
            timings["inventory_ms"]
            + timings["binding_ms"]
            + timings["evaluation_ms"]
            + timings["views_ms"]
        )


def test_backend_accepts_two_typed_local_alias_hosts_in_one_owner() -> None:
    pre_cfg, plan = _typed_local_alias_fixture(two_hosts=True)
    observed = _observed_typed_local_alias_cfg(pre_cfg, two_hosts=True)
    backend = _typed_alias_backend(pre_cfg, plan, observed)

    result = backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))
    assert result is observed
    execution = backend.last_patch_execution
    assert execution is not None
    verdict = execution.observed_unflatten_verdict
    assert verdict is not None and verdict.safety_case is not None
    ledger = authority_views.semantic_loss_ledger(verdict.safety_case)
    assert tuple(row.anchored_location for row in ledger.rows) == (
        "blk2@0x3000", "blk2@0x3000",
    )
    assert len({row.claim_ids for row in ledger.rows}) == 2
    pre_cfg, full_plan = _typed_local_alias_fixture(two_hosts=True)
    plan = replace(full_plan, steps=full_plan.steps[:-1])
    observed = _observed_typed_local_alias_cfg(pre_cfg, two_hosts=True)
    observed = replace(
        observed,
        blocks={
            **observed.blocks,
            2: replace(
                observed.blocks[2],
                insn_snapshots=(
                    observed.blocks[2].insn_snapshots[0],
                    replace(
                        observed.blocks[2].insn_snapshots[1],
                        kind=InsnKind.NOP,
                        display_text="nop",
                    ),
                ),
            ),
        },
    )
    backend = _typed_alias_backend(pre_cfg, plan, observed)
    with pytest.raises(CfgGenerationPoisoned) as caught:
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))
    verdict = caught.value.unflatten_verdict
    assert verdict is not None and verdict.safety_case is not None
    case = verdict.safety_case
    _assert_typed_effect_cell(
        case,
        ea=0x3000,
        state=authority_model.ObligationState.SATISFIED,
        rule=authority_model.UnflattenJustificationRule.LOCAL_ALIAS_SCALARIZATION_PROVEN,
    )
    _assert_typed_effect_cell(
        case,
        ea=0x3001,
        state=authority_model.ObligationState.VIOLATED,
        rule=authority_model.UnflattenJustificationRule.EFFECT_LOST_UNACCOUNTED,
    )
    ledger = authority_views.semantic_loss_ledger(case)
    sibling_subject = _typed_effect_subject(case, 0x3001)
    sibling_row = next(row for row in ledger.rows if row.source_subject == sibling_subject)
    assert sibling_row.kind is authority_model.SemanticLossKind.UNCLASSIFIED
    assert sibling_row.claim_ids == ()


def test_backend_rejects_unclaimed_typed_local_alias_sibling_call() -> None:
    pre_cfg, plan = _typed_local_alias_fixture(
        two_hosts=True, sibling_kind=InsnKind.CALL,
    )
    observed = _observed_typed_local_alias_cfg(pre_cfg, two_hosts=True)
    sibling_nop = replace(
        observed.blocks[2].insn_snapshots[1],
        kind=InsnKind.NOP,
        display_text="nop",
    )
    observed = replace(
        observed,
        blocks={2: replace(
            observed.blocks[2],
            insn_snapshots=(observed.blocks[2].insn_snapshots[0], sibling_nop),
        ), **{serial: block for serial, block in observed.blocks.items() if serial != 2}},
    )
    backend = _typed_alias_backend(pre_cfg, plan, observed)
    with pytest.raises(CfgGenerationPoisoned) as caught:
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))
    verdict = caught.value.unflatten_verdict
    assert verdict is not None and verdict.safety_case is not None
    case = verdict.safety_case
    _assert_typed_effect_cell(
        case,
        ea=0x3000,
        state=authority_model.ObligationState.SATISFIED,
        rule=authority_model.UnflattenJustificationRule.LOCAL_ALIAS_SCALARIZATION_PROVEN,
    )
    _assert_typed_effect_cell(
        case,
        ea=0x3001,
        state=authority_model.ObligationState.VIOLATED,
        rule=authority_model.UnflattenJustificationRule.EFFECT_LOST_UNACCOUNTED,
    )
    sibling_subject = _typed_effect_subject(case, 0x3001)
    sibling_row = next(
        row for row in authority_views.semantic_loss_ledger(case).rows
        if row.source_subject == sibling_subject
    )
    assert sibling_row.kind is authority_model.SemanticLossKind.UNCLASSIFIED
    assert sibling_row.claim_ids == ()


def test_backend_rejects_duplicate_typed_local_alias_host_coordinate() -> None:
    pre_cfg, plan = _typed_local_alias_fixture(two_hosts=True)
    duplicate = replace(plan.steps[-1], host_ea=0x3000)
    plan = replace(plan, steps=(*plan.steps[:-1], duplicate))
    backend = _typed_alias_backend(
        pre_cfg, plan, _observed_typed_local_alias_cfg(pre_cfg, two_hosts=True),
    )
    assert backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks)) is pre_cfg
    assert backend.last_patch_execution is None


def test_backend_rejects_ambiguous_typed_local_alias_observation() -> None:
    pre_cfg, plan = _typed_local_alias_fixture()
    observed = _observed_typed_local_alias_cfg(pre_cfg)
    host = observed.blocks[2].insn_snapshots[0]
    observed = replace(
        observed,
        blocks={
            **observed.blocks,
            2: replace(observed.blocks[2], insn_snapshots=(host, replace(host))),
        },
    )
    backend = _typed_alias_backend(pre_cfg, plan, observed)
    with pytest.raises(CfgGenerationPoisoned):
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))


def test_backend_accepts_typed_local_alias_without_optional_value_size() -> None:
    pre_cfg, plan = _typed_local_alias_fixture()
    plan = replace(plan, steps=(*plan.steps[:-1], replace(plan.steps[-1], value_size=None)))
    observed = _observed_typed_local_alias_cfg(pre_cfg)
    backend = _typed_alias_backend(pre_cfg, plan, observed)
    result = backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))
    assert result is observed
    execution = backend.last_patch_execution
    assert execution is not None
    verdict = execution.observed_unflatten_verdict
    assert verdict is not None and verdict.safety_case is not None
    ledger = authority_views.semantic_loss_ledger(verdict.safety_case)
    assert len(ledger.rows) == 1
    assert ledger.rows[0].kind is authority_model.SemanticLossKind.LOCAL_ALIAS_SCALARIZATION


def test_backend_rejects_typed_local_alias_source_token_substring() -> None:
    pre_cfg, plan = _typed_local_alias_fixture()
    plan = replace(
        plan,
        steps=(*plan.steps[:-1], replace(plan.steps[-1], alias_token="%var_alia")),
    )
    backend = _typed_alias_backend(
        pre_cfg, plan, _observed_typed_local_alias_cfg(pre_cfg),
    )
    assert backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks)) is pre_cfg
    assert backend.last_patch_execution is None


def test_backend_rejects_unchanged_typed_local_alias_store() -> None:
    pre_cfg, plan = _typed_local_alias_fixture()
    observed = _mutate_typed_alias_host(
        pre_cfg,
        kind=InsnKind.STORE,
        opcode=0,
        display_text="store %var_alias",
    )
    backend = _typed_alias_backend(pre_cfg, plan, observed)
    with pytest.raises(CfgGenerationPoisoned) as caught:
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))
    verdict = caught.value.unflatten_verdict
    assert verdict is not None and verdict.safety_case is not None
    ledger = authority_views.semantic_loss_ledger(verdict.safety_case)
    assert ledger.rows == ()
    case = verdict.safety_case
    _assert_typed_effect_cell(
        case,
        ea=0x3000,
        state=authority_model.ObligationState.INCONSISTENT,
        rule=authority_model.UnflattenJustificationRule.EFFECT_LOST_UNACCOUNTED,
    )
    effect_subject = _typed_effect_subject(case, 0x3000)
    owner_key = authority_model.ObligationKey(
        effect_subject,
        authority_model.SafetyDimension.STRUCTURAL_ACCOUNTING,
    )
    owner_cell = next(cell for cell in case.obligation_index.cells if cell.key == owner_key)
    assert owner_cell.state is authority_model.ObligationState.SATISFIED
    assert all(
        failed.key != owner_key for failed in verdict.failed_obligations
    )


@pytest.mark.parametrize(
    ("instruction_kind", "display_text"),
    (
        (InsnKind.NOP, "nop"),
        (InsnKind.MOV, "mov #1.4, %var_other.4"),
        (InsnKind.MOV, "mov #1.4, %var_399.4"),
        (InsnKind.MOV, "mov unrelated_%var_398_suffix"),
        (InsnKind.MOV, "mov %var_398.4, %var_other.4"),
        (InsnKind.MOV, "mov #1.4, %var_398.8"),
        (InsnKind.MOV, "mov #1.4, %var_398.04"),
        (InsnKind.MOV, "mov #1.4, %var_398." + "9" * 5000),
    ),
)
def test_backend_rejects_typed_local_alias_wrong_scalarized_observation(
    instruction_kind: InsnKind, display_text: str,
) -> None:
    pre_cfg, plan = _typed_local_alias_fixture()
    observed = _observed_typed_local_alias_cfg(pre_cfg)
    observed = replace(
        observed,
        blocks={
            **observed.blocks,
            2: replace(
                observed.blocks[2],
                insn_snapshots=(replace(
                    observed.blocks[2].insn_snapshots[0],
                    kind=instruction_kind,
                    display_text=display_text,
                ),),
            ),
        },
    )
    backend = _typed_alias_backend(pre_cfg, plan, observed)
    with pytest.raises(CfgGenerationPoisoned) as caught:
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))
    verdict = caught.value.unflatten_verdict
    assert verdict is not None and verdict.safety_case is not None
    _assert_typed_effect_cell(
        verdict.safety_case,
        ea=0x3000,
        state=(
            authority_model.ObligationState.VIOLATED,
            authority_model.ObligationState.INCONSISTENT,
        ),
        rule=authority_model.UnflattenJustificationRule.EFFECT_LOST_UNACCOUNTED,
    )
    assert not any(
        row.kind is authority_model.SemanticLossKind.LOCAL_ALIAS_SCALARIZATION
        for row in authority_views.semantic_loss_ledger(verdict.safety_case).rows
    )


@pytest.mark.parametrize(
    "changes",
    (
        {"opcode": 999},
        {"d": MopSnapshot(kind=OperandKind.LVAR, size=8), "l": MopSnapshot(kind=OperandKind.NUMBER, size=8, value=1), "display_text": "mov #1.8, %var_398.8"},
    ),
)
def test_backend_rejects_typed_local_alias_noncanonical_mov_observation(
    changes: dict[str, object],
) -> None:
    pre_cfg, plan = _typed_local_alias_fixture()
    observed = _mutate_typed_alias_host(_observed_typed_local_alias_cfg(pre_cfg), **changes)
    backend = _typed_alias_backend(pre_cfg, plan, observed)
    with pytest.raises(CfgGenerationPoisoned) as caught:
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))
    verdict = caught.value.unflatten_verdict
    assert verdict.safety_case is not None
    _assert_typed_effect_cell(
        verdict.safety_case,
        ea=0x3000,
        state=(
            authority_model.ObligationState.VIOLATED,
            authority_model.ObligationState.INCONSISTENT,
        ),
        rule=authority_model.UnflattenJustificationRule.EFFECT_LOST_UNACCOUNTED,
    )
    assert not any(
        row.kind is authority_model.SemanticLossKind.LOCAL_ALIAS_SCALARIZATION
        for row in authority_views.semantic_loss_ledger(verdict.safety_case).rows
    )


def test_backend_rejects_typed_local_alias_wrong_host_ea_precase() -> None:
    pre_cfg, plan = _typed_local_alias_fixture()
    observed = _mutate_typed_alias_host(
        _observed_typed_local_alias_cfg(pre_cfg),
        ea=0x3004,
        native_ea=0x3004,
    )
    backend = _typed_alias_backend(pre_cfg, plan, observed)
    with pytest.raises(CfgGenerationPoisoned) as caught:
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))
    verdict = caught.value.unflatten_verdict
    assert verdict is not None
    assert verdict.safety_case is None
    assert verdict.failed_obligations == ()
    assert verdict.reason is authority_model.UnflattenAuthorityReason.LIVE_BINDING_FAILED


def test_backend_rejects_typed_local_alias_stale_host_text_claim() -> None:
    pre_cfg, plan = _typed_local_alias_fixture()
    alias_step = replace(plan.steps[-1], host_text_sha1="0" * 16)
    plan = replace(plan, steps=(*plan.steps[:-1], alias_step))
    backend = _typed_alias_backend(pre_cfg, plan, _observed_typed_local_alias_cfg(pre_cfg))
    assert backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks)) is pre_cfg
    assert backend.last_patch_execution is None


def test_backend_rejects_typed_local_alias_host_call_transition() -> None:
    pre_cfg, plan = _typed_local_alias_fixture()
    observed = _observed_typed_local_alias_cfg(pre_cfg)
    observed = replace(
        observed,
        blocks={
            **observed.blocks,
            2: replace(
                observed.blocks[2],
                insn_snapshots=(replace(
                    observed.blocks[2].insn_snapshots[0],
                    opcode=57,
                    kind=InsnKind.CALL,
                    is_call=True,
                    display_text="call %var_other",
                ),),
            ),
        },
    )
    backend = _typed_alias_backend(pre_cfg, plan, observed)
    with pytest.raises(CfgGenerationPoisoned) as caught:
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))
    verdict = caught.value.unflatten_verdict
    assert verdict is not None and verdict.safety_case is not None
    assert verdict.reason in {
        authority_model.UnflattenAuthorityReason.OBLIGATION_UNPROVEN,
        authority_model.UnflattenAuthorityReason.OBLIGATION_INCONSISTENT,
        authority_model.UnflattenAuthorityReason.OBLIGATION_VIOLATED,
    }
    assert verdict.failed_obligations
    _assert_typed_effect_cell(
        verdict.safety_case,
        ea=0x3000,
        state=(
            authority_model.ObligationState.VIOLATED,
            authority_model.ObligationState.INCONSISTENT,
        ),
        rule=authority_model.UnflattenJustificationRule.EFFECT_LOST_UNACCOUNTED,
    )
    assert not any(
        row.kind is authority_model.SemanticLossKind.LOCAL_ALIAS_SCALARIZATION
        for row in authority_views.semantic_loss_ledger(verdict.safety_case).rows
    )


def test_backend_rejects_typed_local_alias_unreachable_owner() -> None:
    pre_cfg, plan = _typed_local_alias_fixture()
    observed = _observed_typed_local_alias_cfg(pre_cfg)
    observed = replace(
        observed,
        blocks={
            **observed.blocks,
            1: replace(observed.blocks[1], succs=(3,), kind=BlockKind.ONE_WAY),
            2: replace(observed.blocks[2], preds=()),
            3: replace(observed.blocks[3], preds=(1,)),
        },
    )
    backend = _typed_alias_backend(pre_cfg, plan, observed)
    with pytest.raises(CfgGenerationPoisoned) as caught:
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))
    verdict = caught.value.unflatten_verdict
    assert verdict is not None and verdict.safety_case is not None
    assert verdict.reason in {
        authority_model.UnflattenAuthorityReason.OBLIGATION_UNPROVEN,
        authority_model.UnflattenAuthorityReason.OBLIGATION_INCONSISTENT,
        authority_model.UnflattenAuthorityReason.OBLIGATION_VIOLATED,
    }
    assert verdict.failed_obligations
    _assert_typed_effect_cell(
        verdict.safety_case,
        ea=0x3000,
        state=(
            authority_model.ObligationState.VIOLATED,
            authority_model.ObligationState.INCONSISTENT,
        ),
        rule=authority_model.UnflattenJustificationRule.EFFECT_LOST_UNACCOUNTED,
    )
    assert not any(
        row.kind is authority_model.SemanticLossKind.LOCAL_ALIAS_SCALARIZATION
        for row in authority_views.semantic_loss_ledger(verdict.safety_case).rows
    )


@pytest.mark.parametrize(
    "failure_kind",
    ("unmatched_call", "unreachable_block", "host_call"),
)
def test_backend_does_not_widen_local_alias_effect_scalarization(
    failure_kind: str,
) -> None:
    """Calls and control-flow loss remain outside scalarization authority."""

    pre_cfg = _local_alias_store_cfg(extra_call=failure_kind == "unmatched_call")
    observed_cfg = _observed_scalarized_cfg(
        pre_cfg,
        reachable=failure_kind != "unreachable_block",
        host_call=failure_kind == "host_call",
    )
    plan = _local_alias_scalarization_plan()

    class _ScalarizingTranslator(_FakeTranslator):
        def lift(self, _live_source: object) -> FlowGraph:
            self.lift_count += 1
            return observed_cfg if self.lower_calls else pre_cfg

    gateway = _ordinary_gateway(pre_cfg, plan)
    backend = HexRaysMutationBackend(
        mutation_gateway=gateway,
        translator=_ScalarizingTranslator(pre_cfg),
    )

    with pytest.raises(CfgGenerationPoisoned):
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))

    assert gateway.generation_poisoned
    assert backend.last_patch_execution is None


def test_backend_accepts_only_replayed_exact_infeasible_effect_loss() -> None:
    """A typed exact-effect claim authorizes only its replayed effect loss."""

    pre_cfg, plan = _typed_lowering_fixture()
    observed_cfg = project_patch_plan(
        pre_cfg, plan, snapshot_id=plan.snapshot_id,
    ).graph
    backend = _typed_alias_backend(pre_cfg, plan, observed_cfg)

    assert backend.apply(
        plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks),
    ) is observed_cfg
    assert backend.last_patch_execution is not None
    execution = backend.last_patch_execution
    assert execution.projected_unflatten_verdict is not None
    assert execution.projected_unflatten_verdict.accepted
    assert execution.observed_unflatten_verdict is not None
    assert execution.observed_unflatten_verdict.accepted
    assert any(
        type(claim) is authority_model.ExactInfeasibleEffectClaim
        for claim in execution.projected_unflatten_verdict.safety_case.claims
    )


def test_backend_rejects_forged_effect_exclusion_before_mutation() -> None:
    pre_cfg, plan = _typed_lowering_fixture()
    proposal = plan.unflatten_proposal
    assert proposal is not None
    claim = next(
        claim for claim in proposal.claims
        if type(claim) is authority_model.ExactInfeasibleEffectClaim
    )
    forged_claim = object.__new__(type(claim))
    for field_name in claim.__dataclass_fields__:
        object.__setattr__(
            forged_claim,
            field_name,
            claim.normalized_state + 1
            if field_name == "normalized_state"
            else getattr(claim, field_name),
        )
    object.__setattr__(forged_claim, "claim_id", claim_id(forged_claim))
    forged_claim.__post_init__()
    forged_proposal = replace(
        proposal,
        claims=tuple(
            forged_claim if item is claim else item
            for item in proposal.claims
        ),
    )
    plan = replace(plan, unflatten_proposal=forged_proposal)
    translator = _FakeTranslator(pre_cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(pre_cfg, plan),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))

    assert result is pre_cfg
    assert translator.lower_calls == []
    assert isinstance(backend.last_patch_failure, PatchTransactionPreflightRejected)


def test_backend_rejects_foreign_native_binding_before_lowering() -> None:
    """A reference from another native authority cannot reach the translator."""

    cfg = _make_cfg([(0, 1)], stop_serials=(1,))
    plan = _ordinary_plan(
        PatchConvertToGoto,
        serials=(0, 1),
        block_serial=0,
        goto_target=1,
    )
    foreign_ref = NativeBlockRef(
        StableBlockIdentity.from_instruction_eas(
            (0x1000,),
            native_key=make_native_key(input_identity="sha256:foreign-input"),
        )
    )
    foreign_plan = replace(
        plan,
        steps=(replace(plan.steps[0], block_serial=foreign_ref),),
        source_coordinates=((foreign_ref, 0), plan.source_coordinates[1]),
    )
    translator = _FakeTranslator(cfg)
    gateway = _ordinary_gateway(cfg, foreign_plan)
    backend = HexRaysMutationBackend(
        mutation_gateway=gateway,
        translator=translator,
    )

    with pytest.raises(ValueError):
        backend.apply(
            foreign_plan,
            live_source=SimpleNamespace(qty=cfg.num_blocks),
        )

    assert translator.lower_calls == []
    assert not gateway.mutation_started
    assert not gateway.generation_poisoned


def test_backend_persists_observed_dispatcher_verdict_after_late_contract_poison() -> None:
    """A post-observation contract failure cannot erase computed CFG evidence."""
    cfg = _make_cfg(
        [(0, 1), (0, 5), (1, 2), (5, 2), (2, 3), (2, 4)],
        stop_serials=(3, 4),
    )
    plan = _ordinary_plan(
        PatchRedirectGoto,
        serials=(1, 2, 3),
        from_serial=1,
        old_target=2,
        new_target=3,
    )
    coverage = analyze_dispatcher_corridor_coverage(
        cfg,
        modifications=(RedirectGoto(from_serial=1, old_target=2, new_target=3),),
        dispatcher_entry_serial=2,
    )
    assert coverage.planned_completion_status == "planned_partial_residual_dispatcher"
    projected = project_patch_plan(cfg, plan, snapshot_id=plan.snapshot_id)

    class _ProjectedTranslator(_FakeTranslator):
        def lift(self, _live_source: object) -> FlowGraph:
            self.lift_count += 1
            return projected.graph if self.lower_calls else cfg

    class _LateFailingContract:
        def __init__(self) -> None:
            self.projection_checks = 0

        def verify_projection(self, _projection: object, *, scope: str) -> None:
            assert scope == "full"
            self.projection_checks += 1
            if self.projection_checks == 2:
                raise RuntimeError("late post-observation contract failure")

        def verify(self, _mba: object, *, projection: object, phase: str) -> None:
            assert projection is not None
            assert phase == "pre"

    translator = _ProjectedTranslator(cfg)
    translator.contract = _LateFailingContract()
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    with pytest.raises(CfgGenerationPoisoned):
        backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

def test_backend_commits_the_complete_ordinary_patch_transaction_timeline() -> None:
    cfg = _make_cfg([(0, 1)], stop_serials=(1,))
    plan = _ordinary_plan(
        PatchConvertToGoto,
        serials=(0, 1),
        block_serial=0,
        goto_target=1,
    )
    emitter = EventEmitter()
    phases: list[MbaCfgTransactionAuthorityObserved] = []
    emitter.on(MbaCfgTransactionAuthorityObserved, phases.append)
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan, event_emitter=emitter),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is cfg
    execution = backend.last_patch_execution
    assert execution is not None
    assert execution.applied_count == 1
    assert execution.receipt.operation_count == 1
    assert execution.receipt.planned_operation_count == 1
    assert [event.phase for event in phases] == [
        CfgTransactionPhase.PLANNED,
        CfgTransactionPhase.PROJECTED,
        CfgTransactionPhase.PREFLIGHTED,
        CfgTransactionPhase.BOUND,
        CfgTransactionPhase.REALIZING,
        CfgTransactionPhase.OBSERVED,
        CfgTransactionPhase.COMMITTED,
    ]


def test_backend_mints_successive_attempts_from_live_identity_generation() -> None:
    """A committed child transaction must not leave backend attempt authority stale."""
    cfg = _make_cfg([(0, 1), (1, 2)], stop_serials=(2,))
    first_plan = _ordinary_plan(
        PatchConvertToGoto,
        serials=(0, 1),
        block_serial=0,
        goto_target=1,
    )
    emitter = EventEmitter()
    phases: list[MbaCfgTransactionAuthorityObserved] = []
    emitter.on(MbaCfgTransactionAuthorityObserved, phases.append)
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, first_plan, event_emitter=emitter),
        translator=translator,
    )
    live_source = SimpleNamespace(qty=cfg.num_blocks)

    assert backend.apply(first_plan, live_source=live_source) is cfg
    current_index = backend._mutation_gateway.identity_index
    second_plan = replace(
        _ordinary_plan(
            PatchConvertToGoto,
            serials=(1, 2),
            block_serial=1,
            goto_target=2,
        ),
        snapshot_id=current_index.snapshot_id,
        source_generation=current_index.generation,
    )
    assert backend.apply(second_plan, live_source=live_source) is cfg

    assert translator.lower_calls == [first_plan, second_plan]
    committed_attempts = [
        event.attempt_id
        for event in phases
        if event.phase is CfgTransactionPhase.COMMITTED
    ]
    assert len(committed_attempts) == 2
    assert committed_attempts[0] != committed_attempts[1]
    assert int(committed_attempts[1].generation) > int(committed_attempts[0].generation)


def test_patch_pipeline_runtime_preserves_exact_pre_cfg_authority() -> None:
    cfg = _make_cfg([(0, 1)], stop_serials=(1,))
    plan = _ordinary_plan(
        PatchConvertToGoto,
        serials=(0, 1),
        block_serial=0,
        goto_target=1,
    )
    translator = _FakeTranslator(cfg)
    runtime = HexRaysPatchPlanRuntime(translator)
    live = SimpleNamespace(qty=cfg.num_blocks)
    gateway = _ordinary_gateway(cfg, plan)

    pre_cfg = runtime.lift(live)
    execution = runtime.execute_patch_plan(
        plan,
        live,
        mutation_gateway=gateway,
        pre_cfg=pre_cfg,
    )

    assert execution.applied_count == 1
    assert execution.graph is cfg
    assert translator.lift_count == 2


def test_backend_poisons_when_realized_operation_inventory_differs() -> None:
    cfg = _make_cfg([(0, 1)], stop_serials=(1,))
    plan = _ordinary_plan(
        PatchConvertToGoto,
        serials=(0, 1),
        block_serial=0,
        goto_target=1,
    )
    emitter = EventEmitter()
    phases: list[MbaCfgTransactionAuthorityObserved] = []
    emitter.on(MbaCfgTransactionAuthorityObserved, phases.append)

    class _MismatchedTranslator(_FakeTranslator):
        def lower(self, *args, **kwargs) -> int:
            super().lower(*args, **kwargs)
            return 2

    lifecycle_state = NativePreanalysisSessionState(evidence_generation=0)
    gateway = _ordinary_gateway(
        cfg,
        plan,
        event_emitter=emitter,
        lifecycle_authority=SessionFragmentPublicationLifecycleAuthority(
            native_key=NATIVE_KEY,
            state=lifecycle_state,
        ),
    )
    backend = HexRaysMutationBackend(
        mutation_gateway=gateway,
        translator=_MismatchedTranslator(cfg),
    )

    with pytest.raises(CfgGenerationPoisoned):
        backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert gateway.generation_poisoned
    assert phases[-1].phase is CfgTransactionPhase.POISONED_RESTART_REQUIRED
    assert phases[-1].failure is not None
    assert phases[-1].failure.first_failed_obligation == "runtime:observation"
    assert lifecycle_state.has_pending_generated_restart


def test_patch_participant_preserves_one_immutable_authority_through_observation() -> (
    None
):
    cfg = _make_cfg([(0, 1)], stop_serials=(1,))
    source_ref = NativeBlockRef(
        StableBlockIdentity.from_instruction_eas((0x1000,), native_key=NATIVE_KEY)
    )
    target_ref = NativeBlockRef(
        StableBlockIdentity.from_instruction_eas((0x1001,), native_key=NATIVE_KEY)
    )
    plan = PatchPlan(
        snapshot_id="participant-snapshot",
        source_maturity=MaturityEnvelope(ir=None, provider="hexrays", provider_id=0),
        source_generation=4,
        steps=(
            PatchConvertToGoto(
                block_serial=source_ref,
                goto_target=target_ref,
            ),
        ),
        source_coordinates=((source_ref, 0), (target_ref, 1)),
    )
    cfg = FlowGraph(
        blocks=cfg.blocks,
        entry_serial=cfg.entry_serial,
        func_ea=cfg.func_ea,
        metadata={"snapshot_id": plan.snapshot_id},
    )
    index = MbaBlockIdentityIndex.from_flow_graph(
        session_id="participant-session",
        generation=4,
        maturity=0,
        snapshot_id=plan.snapshot_id,
        native_key=NATIVE_KEY,
        flow_graph=cfg,
    )
    emitter = EventEmitter()
    phase_events: list[MbaCfgTransactionAuthorityObserved] = []
    emitter.on(MbaCfgTransactionAuthorityObserved, phase_events.append)
    gateway = MbaMutationGateway(
        session_id=index.session_id,
        generation=index.generation,
        native_key=NATIVE_KEY,
        identity_index=index,
        event_emitter=emitter,
    )
    live = SimpleNamespace(qty=cfg.num_blocks)
    contract_events: list[str] = []

    class _Contract:
        def verify_projection(self, projection, *, scope="focused"):
            assert projection is projected
            assert scope == "full"
            contract_events.append("projection_verified")
            return ()

        def verify(self, mba, *, projection, phase):
            assert mba is live
            assert projection is projected
            assert phase == "pre"
            contract_events.append("live_preflighted")
            return ()

    class _Translator:
        def lower(
            self,
            candidate,
            mba,
            *,
            mutation_gateway,
            bound_transaction,
            post_apply_hook=None,
        ):
            assert candidate is plan
            assert mba is live
            assert mutation_gateway is gateway
            assert bound_transaction is bound
            assert bound_transaction.prepared is prepared
            assert post_apply_hook is None
            gateway.begin_batch(
                StructuralMutationKind.BLOCK_REPLACE,
                serial_quantity=live.qty,
                planned_operation_count=len(plan.steps),
                transaction_attempt=prepared.attempt_id,
                patch_plan_id=plan.plan_id,
            )
            gateway.begin_patch_realization(prepared.attempt_id, plan_refs=())
            return 1

        def lift(self, mba):
            assert mba is live
            return cfg

    participant = HexRaysPatchTransactionParticipant(
        gateway=gateway,
        translator=_Translator(),
        mba=live,
        plan=plan,
        contract=_Contract(),
    )
    projected = participant.project(plan, cfg)
    prepared = participant.preflight(projected)
    bound = participant.bind(prepared, gateway.identity_index)
    realized = participant.realize(bound, gateway)
    observed = participant.observe(realized, live)

    assert isinstance(projected, CfgProjection)
    assert isinstance(prepared, PreparedCfgTransaction)
    assert isinstance(bound, BoundCfgTransaction)
    assert bound.prepared is prepared
    assert observed is cfg
    assert contract_events == ["projection_verified", "live_preflighted"]
    assert [event.phase for event in phase_events] == [
        CfgTransactionPhase.PLANNED,
        CfgTransactionPhase.PROJECTED,
        CfgTransactionPhase.PREFLIGHTED,
        CfgTransactionPhase.BOUND,
        CfgTransactionPhase.REALIZING,
        CfgTransactionPhase.OBSERVED,
    ]


def test_publish_fragment_uses_independent_receipt_backed_gateway() -> None:
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 3)],
        stop_serials=(3,),
    )
    translator = _FakeTranslator(cfg)
    plan = _fragment_plan()
    published = []
    snapshot = _current_mba_identity_binding()

    class _Gateway:
        def __init__(self, name: str) -> None:
            self.name = name

        def new_transaction(self):
            return _Gateway("fragment")

        def execute_patch_transaction(
            self,
            fragment_backend,
            fragment_plan,
            _publication_profile,
        ):
            published.append((self.name, fragment_backend, fragment_plan))
            return SimpleNamespace(
                current_mba_identity_binding=snapshot,
                operation_count=260,
            )

    fragment_backend = object()
    backend = HexRaysMutationBackend(
        mutation_gateway=_Gateway("root"),
        translator=translator,
        fragment_backend_factory=lambda live_source, gateway, _profile: (
            fragment_backend
            if live_source == "LIVE" and gateway.name == "fragment"
            else None
        ),
    )

    result = backend.apply(plan, live_source="LIVE")

    assert result is cfg
    assert published == [("fragment", fragment_backend, plan)]
    assert translator.lift_count == 1
    assert backend.committed_current_mba_identity_binding() is snapshot
    assert backend.committed_fragment_operation_count == 260


def test_publish_generated_fragment_never_lifts_graph_free_mba() -> None:
    cfg = _make_cfg([(0, 1)], stop_serials=(1,))
    translator = _FakeTranslator(cfg)
    plan = _fragment_plan()
    published = []
    constructed = []
    live = object()

    class _Gateway:
        def new_transaction(self):
            return self

        def execute_patch_transaction(
            self,
            fragment_backend,
            fragment_plan,
            publication_profile,
        ):
            published.append(
                (fragment_backend, fragment_plan, publication_profile)
            )
            return SimpleNamespace(
                current_mba_identity_binding=_current_mba_identity_binding(),
                operation_count=13,
            )

    fragment_backend = object()
    backend = HexRaysMutationBackend(
        mutation_gateway=_Gateway(),
        translator=translator,
        fragment_backend_factory=lambda live_source, _gateway, profile: (
            constructed.append((live_source, profile)) or fragment_backend
        ),
    )

    result = backend.apply(
        plan,
        live_source=live,
        publication_profile=(
            SemanticFragmentPublicationProfile.GENERATED_GRAPH_FREE
        ),
    )

    assert result is live
    assert translator.lift_count == 0
    assert constructed == [
        (live, SemanticFragmentPublicationProfile.GENERATED_GRAPH_FREE)
    ]
    assert published == [
        (
            fragment_backend,
            plan,
            SemanticFragmentPublicationProfile.GENERATED_GRAPH_FREE,
        )
    ]
    assert backend.committed_fragment_operation_count == 13


def test_publish_fragment_exposes_no_prior_origins_after_abort() -> None:
    cfg = _make_cfg([(0, 1)], stop_serials=(1,))
    translator = _FakeTranslator(cfg)
    snapshot = _current_mba_identity_binding()

    class _Gateway:
        fail = False

        def new_transaction(self):
            return self

        def execute_patch_transaction(
            self,
            _fragment_backend,
            _fragment_plan,
            _publication_profile,
        ):
            if self.fail:
                raise RuntimeError("publication aborted")
            return SimpleNamespace(
                current_mba_identity_binding=snapshot,
                operation_count=17,
            )

    gateway = _Gateway()
    backend = HexRaysMutationBackend(
        mutation_gateway=gateway,
        translator=translator,
        fragment_backend_factory=lambda _live_source, _transaction, _profile: object(),
    )
    plan = _fragment_plan()
    backend.apply(plan, live_source=object())
    assert backend.committed_current_mba_identity_binding() is snapshot

    gateway.fail = True
    with pytest.raises(RuntimeError, match="publication aborted"):
        backend.apply(plan, live_source=object())

    assert backend.committed_current_mba_identity_binding() is None
    assert backend.committed_fragment_operation_count == 17


def test_default_fragment_backend_receives_native_body_materializer(
    monkeypatch,
) -> None:
    cfg = _make_cfg([(0, 1)], stop_serials=(1,))
    translator = _FakeTranslator(cfg)
    materializer = object()
    constructed = []

    class _Modifier:
        def __init__(
            self,
            live_source,
            *,
            mutation_gateway,
            semantic_native_body_materializer,
            semantic_fragment_publication_profile,
        ) -> None:
            constructed.append(
                (
                    live_source,
                    mutation_gateway,
                    semantic_native_body_materializer,
                    semantic_fragment_publication_profile,
                )
            )

    deferred_modifier = ModuleType("d810.hexrays.mutation.deferred_modifier")
    deferred_modifier.DeferredGraphModifier = _Modifier
    monkeypatch.setitem(
        sys.modules,
        "d810.hexrays.mutation.deferred_modifier",
        deferred_modifier,
    )
    backend = HexRaysMutationBackend(
        mutation_gateway=MUTATION_GATEWAY,
        translator=translator,
        semantic_native_body_materializer=materializer,
    )

    fragment_backend = backend._new_fragment_backend(
        "LIVE",
        MUTATION_GATEWAY,
        SemanticFragmentPublicationProfile.CFG_READY,
    )

    assert isinstance(fragment_backend, _Modifier)
    assert constructed == [
        (
            "LIVE",
            MUTATION_GATEWAY,
            materializer,
            SemanticFragmentPublicationProfile.CFG_READY,
        )
    ]


def test_full_dispatcher_retirement_uses_ordinary_contract_when_entry_reachability_passes():
    """A full dispatcher retirement completes without entry authority on the dispatcher node."""
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 3), (2, 5), (3, 4), (5, 4)],
        stop_serials=(4,),
    )
    template = _ordinary_plan(
        PatchRedirectGoto,
        serials=(1, 2, 3),
        from_serial=1,
        old_target=2,
        new_target=3,
    )
    coverage = analyze_dispatcher_corridor_coverage(
        cfg,
        modifications=(RedirectGoto(from_serial=1, old_target=2, new_target=3),),
        dispatcher_entry_serial=2,
    )
    assert coverage.planned_completion_status == "planned_dispatcher_corridors_covered"
    projected = project_patch_plan(cfg, template, snapshot_id=template.snapshot_id)
    removal_forecast = build_dispatcher_removal_forecast(
        cfg,
        coverage=coverage,
        dispatcher_entry_serial=2,
    )
    plan = _typed_bootstrap_authority_plan(
        cfg,
        template=template,
        dispatcher_entry_serial=2,
        dispatcher_member_serials=(1, 2, 5),
        authoritative_handler_serials=(3,),
        coverage=coverage,
        route_edge=(1, 3),
        removal_forecast=removal_forecast,
    )
    projected = project_patch_plan(cfg, plan, snapshot_id=plan.snapshot_id)

    class _ProjectedTranslator(_FakeTranslator):
        def lift(self, _live_source: object) -> FlowGraph:
            self.lift_count += 1
            return projected.graph if self.lower_calls else cfg

    translator = _ProjectedTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is projected.graph
    assert backend.last_patch_failure is None
    assert translator.lower_calls == [plan]
    assert translator.lift_count == 2
    execution = backend.last_patch_execution
    assert execution is not None
    verdict = execution.projected_unflatten_verdict
    assert verdict is not None and verdict.safety_case is not None
    case = verdict.safety_case
    assert any(
        item.key.subject.role is authority_model.SemanticSubjectRole.SOURCE_ENTRY
        and item.key.dimension is authority_model.SafetyDimension.ENTRY_REACHABILITY
        for item in case.obligation_index.cells
    )
    assert not any(
        item.key.subject.role is authority_model.SemanticSubjectRole.DISPATCHER_ENTRY
        and item.key.dimension is authority_model.SafetyDimension.ENTRY_REACHABILITY
        for item in case.obligation_index.cells
    )
    assert all(
        item.conclusion.dimension is authority_model.SafetyDimension.STRUCTURAL_ACCOUNTING
        for item in case.justifications
        if item.rule is authority_model.UnflattenJustificationRule.RETIRED_INFRASTRUCTURE_PROVEN
    )


def test_small_noncyclic_retirement_uses_transaction_owned_contract():
    """Producer forecast status cannot replace transaction-owned obligations."""
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 3), (2, 5), (3, 4), (5, 4)],
        stop_serials=(4,),
    )
    plan = _ordinary_plan(
        PatchRedirectGoto,
        serials=(1, 2, 3),
        from_serial=1,
        old_target=2,
        new_target=3,
    )
    coverage = analyze_dispatcher_corridor_coverage(
        cfg,
        modifications=(RedirectGoto(from_serial=1, old_target=2, new_target=3),),
        dispatcher_entry_serial=2,
    )
    removal_forecast = build_dispatcher_removal_forecast(
        cfg,
        coverage=coverage,
        dispatcher_entry_serial=2,
    )
    plan = _typed_bootstrap_authority_plan(
        cfg,
        template=plan,
        dispatcher_entry_serial=2,
        dispatcher_member_serials=(1, 2, 5),
        authoritative_handler_serials=(3,),
        coverage=coverage,
        route_edge=(1, 3),
        removal_forecast=removal_forecast,
    )
    # The typed bootstrap mutates source instruction identity while attaching
    # its proposal.  The transaction must project from that final typed plan.
    projected = project_patch_plan(cfg, plan, snapshot_id=plan.snapshot_id)

    class _ProjectedTranslator(_FakeTranslator):
        def lift(self, _live_source: object) -> FlowGraph:
            self.lift_count += 1
            return projected.graph if self.lower_calls else cfg

    translator = _ProjectedTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is projected.graph
    assert backend.last_patch_failure is None
    assert translator.lower_calls == [plan]
    assert translator.lift_count == 2
    execution = backend.last_patch_execution
    assert execution is not None
    projected_verdict = execution.projected_unflatten_verdict
    assert projected_verdict is not None and projected_verdict.safety_case is not None
    retirement_result = projected_verdict.safety_case.retirement_phase_result
    assert retirement_result is not None
    member = next(
        item
        for item in retirement_result.members
        if item.anchor_ea == cfg.blocks[1].start_ea
    )
    assert member.classification is authority_model.RetirementPhaseClassification.RETAINED

def test_backend_reports_unclaimed_typed_local_alias_sibling_store_loss() -> None:
    pre_cfg, full_plan = _typed_local_alias_fixture(two_hosts=True)
    plan = replace(full_plan, steps=full_plan.steps[:-1])
    observed = _observed_typed_local_alias_cfg(pre_cfg, two_hosts=True)
    observed = replace(
        observed,
        blocks={
            **observed.blocks,
            2: replace(
                observed.blocks[2],
                insn_snapshots=(
                    observed.blocks[2].insn_snapshots[0],
                    replace(
                        observed.blocks[2].insn_snapshots[1],
                        kind=InsnKind.NOP,
                        display_text="nop",
                    ),
                ),
            ),
        },
    )
    backend = _typed_alias_backend(pre_cfg, plan, observed)
    with pytest.raises(CfgGenerationPoisoned) as caught:
        backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))
    verdict = caught.value.unflatten_verdict
    assert verdict is not None and verdict.safety_case is not None
    case = verdict.safety_case
    _assert_typed_effect_cell(
        case,
        ea=0x3000,
        state=authority_model.ObligationState.SATISFIED,
        rule=authority_model.UnflattenJustificationRule.LOCAL_ALIAS_SCALARIZATION_PROVEN,
    )
    _assert_typed_effect_cell(
        case,
        ea=0x3001,
        state=authority_model.ObligationState.VIOLATED,
        rule=authority_model.UnflattenJustificationRule.EFFECT_LOST_UNACCOUNTED,
    )
    ledger = authority_views.semantic_loss_ledger(case)
    sibling_subject = _typed_effect_subject(case, 0x3001)
    sibling_row = next(row for row in ledger.rows if row.source_subject == sibling_subject)
    assert sibling_row.kind is authority_model.SemanticLossKind.UNCLASSIFIED
    assert sibling_row.claim_ids == ()



def test_backend_preserves_unclaimed_typed_local_alias_sibling_store() -> None:
    pre_cfg, full_plan = _typed_local_alias_fixture(two_hosts=True)
    plan = replace(full_plan, steps=full_plan.steps[:-1])
    observed = _observed_typed_local_alias_cfg(pre_cfg, two_hosts=True)
    observed = replace(
        observed,
        blocks={
            **observed.blocks,
            2: replace(
                observed.blocks[2],
                insn_snapshots=(
                    observed.blocks[2].insn_snapshots[0],
                    replace(
                        pre_cfg.blocks[2].insn_snapshots[1],
                        display_text="store %var_alias2",
                    ),
                ),
            ),
        },
    )
    backend = _typed_alias_backend(pre_cfg, plan, observed)
    result = backend.apply(plan, live_source=SimpleNamespace(qty=pre_cfg.num_blocks))
    assert result is observed
    execution = backend.last_patch_execution
    assert execution is not None
    verdict = execution.observed_unflatten_verdict
    assert verdict is not None and verdict.safety_case is not None
    ledger = authority_views.semantic_loss_ledger(verdict.safety_case)
    assert len(ledger.rows) == 1
    alias_claim = next(
        claim for claim in verdict.safety_case.claims
        if type(claim) is authority_model.LocalAliasEffectScalarizationClaim
    )
    assert ledger.rows[0].claim_ids == (alias_claim.claim_id,)



def test_observed_lowering_identity_drift_still_poisoned() -> None:
    """Typed observed identity drift remains a decisive rejection."""
    cfg, plan = _typed_lowering_fixture()
    observed = project_patch_plan(cfg, plan, snapshot_id=plan.snapshot_id).graph
    observed = replace(
        observed,
        blocks={
            **observed.blocks,
            1: replace(
                observed.blocks[1],
                start_ea=0x1999,
                native_start_ea=0x1999,
            ),
        },
    )

    class _DriftedObservationTranslator(_FakeTranslator):
        def lift(self, _live_source: object) -> FlowGraph:
            self.lift_count += 1
            return cfg if self.lift_count == 1 else observed

    translator = _DriftedObservationTranslator(cfg)
    native_key = next(
        ref.identity.native_key
        for ref, _serial in plan.source_coordinates
        if isinstance(ref, NativeBlockRef)
    )
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan, native_key=native_key),
        translator=translator,
    )

    with pytest.raises(CfgGenerationPoisoned):
        backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert translator.lower_calls == [plan]




def test_small_switch_retirement_rejects_detached_cyclic_residue() -> None:
    """The exact pre-fix switch island must be rejected before native mutation."""
    cfg = _make_cfg(
        [
            (0, 2),
            *((2, target) for target in (3, 4, 5, 6, 7)),
            (3, 8),
            (4, 8),
            (5, 8),
            (6, 9),
            (7, 8),
            (8, 2),
        ],
        stop_serials=(9,),
    )
    modifications = (
        RedirectGoto(from_serial=0, old_target=2, new_target=3),
        RedirectGoto(from_serial=3, old_target=8, new_target=4),
        RedirectGoto(from_serial=4, old_target=8, new_target=5),
        RedirectGoto(from_serial=5, old_target=8, new_target=6),
    )
    refs = {serial: _native_ref(serial) for serial in cfg.blocks}
    used_serials = {
        coordinate
        for modification in modifications
        for coordinate in (
            modification.from_serial,
            modification.old_target,
            modification.new_target,
        )
    }
    template = PatchPlan(
        source_maturity=MaturityEnvelope(ir=None, provider="hexrays", provider_id=0),
        source_generation=0,
        steps=tuple(
            PatchRedirectGoto(
                from_serial=refs[modification.from_serial],
                old_target=refs[modification.old_target],
                new_target=refs[modification.new_target],
            )
            for modification in modifications
        ),
        source_coordinates=tuple(
            (refs[serial], serial) for serial in sorted(used_serials)
        ),
    )
    coverage = analyze_dispatcher_corridor_coverage(
        cfg,
        modifications=modifications,
        dispatcher_entry_serial=2,
    )
    projected = project_patch_plan(cfg, template, snapshot_id=template.snapshot_id)
    removal_forecast = build_dispatcher_removal_forecast(
        cfg,
        coverage=coverage,
        dispatcher_entry_serial=2,
    )
    plan = _typed_bootstrap_authority_plan(
        cfg,
        template=template,
        dispatcher_entry_serial=2,
        dispatcher_member_serials=(2, 3, 4, 5, 6, 7, 8),
        authoritative_handler_serials=(4,),
        coverage=coverage,
        route_edge=(3, 4),
        removal_forecast=removal_forecast,
    )
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    result = backend.apply(
        plan,
        live_source=SimpleNamespace(qty=max(cfg.blocks) + 1),
    )

    assert result is cfg
    assert translator.lower_calls == []
    assert isinstance(backend.last_patch_failure, PatchTransactionPreflightRejected)


def test_small_switch_retirement_accepts_exact_terminal_cycle_break() -> None:
    """A typed merge redirect may break the otherwise detached switch SCC."""
    cfg = _make_cfg(
        [
            (0, 2),
            *((2, target) for target in (3, 4, 5, 6, 7)),
            (3, 8),
            (4, 8),
            (5, 8),
            (6, 9),
            (7, 8),
            (8, 2),
        ],
        stop_serials=(9,),
    )
    refs = {serial: _native_ref(serial) for serial in cfg.blocks}
    modifications = (
        RedirectGoto(from_serial=0, old_target=2, new_target=3),
        RedirectGoto(from_serial=3, old_target=8, new_target=4),
        RedirectGoto(from_serial=4, old_target=8, new_target=5),
        RedirectGoto(from_serial=5, old_target=8, new_target=6),
        RedirectGoto(from_serial=8, old_target=2, new_target=6),
    )
    template = PatchPlan(
        source_maturity=MaturityEnvelope(ir=None, provider="hexrays", provider_id=0),
        source_generation=0,
        steps=tuple(
            PatchRedirectGoto(
                from_serial=refs[mod.from_serial],
                old_target=refs[mod.old_target],
                new_target=refs[mod.new_target],
            )
            for mod in modifications
        ),
        source_coordinates=tuple(
            (refs[serial], serial)
            for serial in sorted(
                {
                    coordinate
                    for modification in modifications
                    for coordinate in (
                        modification.from_serial,
                        modification.old_target,
                        modification.new_target,
                    )
                }
            )
        ),
    )
    coverage = analyze_dispatcher_corridor_coverage(
        cfg,
        modifications=modifications,
        dispatcher_entry_serial=2,
    )
    projected = project_patch_plan(cfg, template, snapshot_id=template.snapshot_id)
    removal_forecast = build_dispatcher_removal_forecast(
        cfg,
        coverage=coverage,
        dispatcher_entry_serial=2,
    )
    assert coverage.planned_completion_status == "planned_dispatcher_corridors_covered"
    from d810.transforms.dispatcher_corridor_coverage import (
        forecast_terminal_switch_cycle_break,
    )
    removal_forecast = forecast_terminal_switch_cycle_break(
        cfg,
        post_graph=projected.graph,
        patch_plan=template,
        coverage=removal_forecast,
        dispatcher_entry_serial=2,
        authoritative_handler_serials=frozenset({3, 4, 5, 6}),
    )
    plan = _typed_bootstrap_authority_plan(
        cfg,
        template=template,
        dispatcher_entry_serial=2,
        dispatcher_member_serials=(2, 7, 8),
        authoritative_handler_serials=(6,),
        coverage=coverage,
        route_edge=(5, 6),
        route_terminal=True,
        removal_forecast=removal_forecast,
    )

    class _ProjectedTranslator(_FakeTranslator):
        def lift(self, _live_source: object) -> FlowGraph:
            self.lift_count += 1
            return projected.graph if self.lower_calls else cfg

    translator = _ProjectedTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    result = backend.apply(
        plan,
        live_source=SimpleNamespace(qty=max(cfg.blocks) + 1),
    )

    assert result is cfg
    assert translator.lower_calls == []
    assert isinstance(backend.last_patch_failure, PatchTransactionPreflightRejected)


def test_below_threshold_dispatcher_retirement_still_requires_narrow_proof():
    """A failed ordinary entry gate may not be waived by an unbound claim."""
    cfg = _comparison_dispatcher_forest_cfg()
    plan = _ordinary_plan(
        PatchRedirectGoto,
        serials=(1, 2, 3),
        from_serial=1,
        old_target=2,
        new_target=3,
    )
    coverage = analyze_dispatcher_corridor_coverage(
        cfg,
        modifications=(RedirectGoto(from_serial=1, old_target=2, new_target=3),),
        dispatcher_entry_serial=2,
    )
    assert coverage.planned_completion_status == "planned_dispatcher_corridors_covered"
    plan = plan.with_metadata(
        **{DISPATCHER_CORRIDOR_COVERAGE_METADATA: coverage.to_metadata()}
    )
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is cfg
    assert translator.lower_calls == []
    assert backend.last_patch_failure is not None
    assert "projected unflatten authority rejected" in str(backend.last_patch_failure)
def test_corridor_coverage_drift_is_rejected_by_observed_retirement_obligation():
    """A changed live CFG poisons after canonical observed corridor revalidation."""
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 3), (2, 5), (3, 4), (5, 4)],
        stop_serials=(4,),
    )
    template = _ordinary_plan(
        PatchRedirectGoto,
        serials=(1, 2, 3),
        from_serial=1,
        old_target=2,
        new_target=3,
    )
    coverage = analyze_dispatcher_corridor_coverage(
        cfg,
        modifications=(RedirectGoto(from_serial=1, old_target=2, new_target=3),),
        dispatcher_entry_serial=2,
    )
    plan = _typed_bootstrap_authority_plan(
        cfg,
        template=template,
        dispatcher_entry_serial=2,
        dispatcher_member_serials=(1, 2, 5),
        authoritative_handler_serials=(3,),
        coverage=coverage,
        route_edge=(1, 3),
    )
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )
    from d810.hexrays.mutation.patch_transaction import PatchTransactionPoisoned

    with pytest.raises(PatchTransactionPoisoned) as raised:
        backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert isinstance(raised.value.__cause__, PatchTransactionPostObservationRejected)
    assert translator.lower_calls == [plan]
    assert translator.lift_count == 2
    verdict = raised.value.unflatten_verdict
    assert verdict is not None
    assert verdict.phase is authority_model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
    assert verdict.reason is authority_model.UnflattenAuthorityReason.OBLIGATION_VIOLATED
    assert any(
        item.key.dimension is authority_model.SafetyDimension.CORRIDOR_COVERAGE
        for item in verdict.failed_obligations
    )
