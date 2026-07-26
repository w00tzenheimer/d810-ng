from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

import pytest

from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.backends.hexrays.mutation.backend import (
    HexRaysMutationBackend,
    HexRaysPatchPlanRuntime,
)
from d810.core.events import EventEmitter
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.mba_mutation_events import (
    MbaCfgTransactionAuthorityObserved,
    MbaMutationGateway,
    StructuralMutationKind,
)
from d810.hexrays.mutation.patch_transaction import (
    HexRaysPatchTransactionParticipant,
)
from d810.ir.block_identity import (
    CurrentMbaBlockIdentityBinding,
    CurrentMbaIdentityBindingSnapshot,
    NativeEaInterval,
    StableBlockIdentity,
)
from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph
from d810.ir.maturity import MaturityEnvelope
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
    PreparedCfgTransaction,
)
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentEdge,
    FragmentOperation,
    FragmentPlan,
    FragmentPublicationPurpose,
)
from d810.transforms.plan import PatchConvertToGoto, PatchPlan, PatchRedirectGoto
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
        kind=kind or (BlockKind.ONE_WAY if len(succs) == 1 else BlockKind.ZERO_WAY),
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
    event_emitter: EventEmitter | None = None,
    lifecycle_authority: object | None = None,
) -> MbaMutationGateway:
    index = MbaBlockIdentityIndex.from_flow_graph(
        session_id="backend-test",
        generation=int(plan.source_generation or 0),
        maturity=0,
        snapshot_id=plan.snapshot_id,
        native_key=NATIVE_KEY,
        flow_graph=cfg,
    )
    return MbaMutationGateway(
        session_id=index.session_id,
        generation=index.generation,
        maturity=0,
        native_key=NATIVE_KEY,
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


def test_apply_rejects_plan_that_orphans_reachable_terminal() -> None:
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 3)],
        stop_serials=(3,),
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
    phases: list[MbaCfgTransactionAuthorityObserved] = []
    emitter.on(MbaCfgTransactionAuthorityObserved, phases.append)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan, event_emitter=emitter),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is cfg
    assert translator.lower_calls == []
    assert translator.lift_count == 1
    assert [event.phase for event in phases] == [
        CfgTransactionPhase.PLANNED,
        CfgTransactionPhase.PROJECTED,
        CfgTransactionPhase.REJECTED_CLEAN,
    ]
    assert all(not event.mutation_started for event in phases)


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

        def execute_patch_transaction(self, fragment_backend, fragment_plan):
            published.append((self.name, fragment_backend, fragment_plan))
            return SimpleNamespace(
                current_mba_identity_binding=snapshot,
            )

    fragment_backend = object()
    backend = HexRaysMutationBackend(
        mutation_gateway=_Gateway("root"),
        translator=translator,
        fragment_backend_factory=lambda live_source, gateway: (
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


def test_publish_fragment_exposes_no_prior_origins_after_abort() -> None:
    cfg = _make_cfg([(0, 1)], stop_serials=(1,))
    translator = _FakeTranslator(cfg)
    snapshot = _current_mba_identity_binding()

    class _Gateway:
        fail = False

        def new_transaction(self):
            return self

        def execute_patch_transaction(self, _fragment_backend, _fragment_plan):
            if self.fail:
                raise RuntimeError("publication aborted")
            return SimpleNamespace(
                current_mba_identity_binding=snapshot,
            )

    gateway = _Gateway()
    backend = HexRaysMutationBackend(
        mutation_gateway=gateway,
        translator=translator,
        fragment_backend_factory=lambda _live_source, _transaction: object(),
    )
    plan = _fragment_plan()
    backend.apply(plan, live_source=object())
    assert backend.committed_current_mba_identity_binding() is snapshot

    gateway.fail = True
    with pytest.raises(RuntimeError, match="publication aborted"):
        backend.apply(plan, live_source=object())

    assert backend.committed_current_mba_identity_binding() is None


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
        ) -> None:
            constructed.append(
                (
                    live_source,
                    mutation_gateway,
                    semantic_native_body_materializer,
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

    fragment_backend = backend._new_fragment_backend("LIVE", MUTATION_GATEWAY)

    assert isinstance(fragment_backend, _Modifier)
    assert constructed == [("LIVE", MUTATION_GATEWAY, materializer)]
