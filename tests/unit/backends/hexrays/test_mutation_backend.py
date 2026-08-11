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
    StructuralMutationKind,
)
from d810.hexrays.mutation.patch_transaction import (
    HexRaysPatchTransactionParticipant,
    PatchTransactionPreflightRejected,
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
from d810.transforms.dispatcher_corridor_coverage import (
    DISPATCHER_CORRIDOR_COVERAGE_METADATA,
    DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA,
    analyze_dispatcher_corridor_coverage,
    build_dispatcher_removal_preflight_proof,
    canonicalize_observed_dispatcher_graph,
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
    PatchConvertToGoto,
    PatchLowerConditionalStateTransition,
    PatchPlan,
    PatchRedirectGoto,
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
    translator = _FakeTranslator(cfg)
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


def _executed_fragment_safety() -> dict[str, bool]:
    return {
        "fragment_atomic": True,
        "non_state_use_def_veto": True,
        "non_state_use_def_checked": True,
        "non_state_use_def_severances_zero": True,
    }


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


def _comparison_dispatcher_forest_plan(
    cfg: FlowGraph,
    *,
    authoritative_handlers: frozenset[int],
) -> PatchPlan:
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
    projected = project_patch_plan(cfg, plan, snapshot_id=plan.snapshot_id)
    proof = build_dispatcher_removal_preflight_proof(
        cfg,
        post_graph=projected.graph,
        coverage=coverage,
        dispatcher_entry_serial=2,
        authoritative_handler_serials=authoritative_handlers,
        dispatcher_region_serials=frozenset({2, *range(5, 32)}),
        producer_safety=_executed_fragment_safety(),
    )
    return plan.with_metadata(
        **{
            DISPATCHER_CORRIDOR_COVERAGE_METADATA: coverage.to_metadata(),
            DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA: proof.to_metadata(),
        }
    )


def test_apply_rejects_unbound_comparison_dispatcher_removal_below_raw_threshold(
    monkeypatch,
) -> None:
    """Stamped producer metadata cannot bypass the generic entry-count gate."""
    cfg = _comparison_dispatcher_forest_cfg()
    plan = _comparison_dispatcher_forest_plan(
        cfg,
        authoritative_handlers=frozenset({3, 4}),
    )
    proof = plan.metadata_dict()[DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA]
    assert proof["proof_status"] == "accepted"
    assert [anchor["ea"] for anchor in proof["pre_reachable_terminals"]] == [
        0x1004
    ]
    assert [anchor["ea"] for anchor in proof["post_reachable_terminals"]] == [
        0x1004
    ]

    translator = _FakeTranslator(cfg)
    observed_outcomes = []
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_unflatten_dispatcher_corridor_coverage",
        lambda **kwargs: observed_outcomes.append(kwargs),
    )
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is cfg
    assert translator.lower_calls == []
    assert translator.lift_count == 1
    assert len(observed_outcomes) == 1
    rejected_payloads = [
        observation.payload
        for observation in observed_outcomes[0]["observations"]
    ]
    assert {payload["application_status"] for payload in rejected_payloads} == {
        "rejected_preflight"
    }
    rejected_proof = next(
        observation.payload
        for observation in observed_outcomes[0]["observations"]
        if observation.kind == "UnflattenDispatcherRemovalPreflightProof"
    )
    projected_validation = rejected_proof["projected_validation"]
    assert projected_validation["validation_status"] == "rejected"
    assert projected_validation["reason"] == "dispatcher_removal_proof_drift"
    assert projected_validation["proof"]["reason"] == "producer_safety_missing"


def test_apply_rejects_dispatcher_removal_proof_when_one_handler_is_lost(
    monkeypatch,
) -> None:
    cfg = _comparison_dispatcher_forest_cfg()
    plan = _comparison_dispatcher_forest_plan(
        cfg,
        authoritative_handlers=frozenset({3, 4, 5}),
    )
    proof = plan.metadata_dict()[DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA]
    assert proof["proof_status"] == "rejected"
    assert proof["reason"] == "authoritative_handler_lost"

    translator = _FakeTranslator(cfg)
    observed_outcomes = []
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_unflatten_dispatcher_corridor_coverage",
        lambda **kwargs: observed_outcomes.append(kwargs),
    )
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is cfg
    assert translator.lower_calls == []
    assert translator.lift_count == 1
    assert len(observed_outcomes) == 1
    rejected_payloads = [
        observation.payload
        for observation in observed_outcomes[0]["observations"]
    ]
    assert {payload["application_status"] for payload in rejected_payloads} == {
        "rejected_preflight"
    }
    assert any(
        payload.get("proof_status") == "rejected"
        and payload.get("reason") == "authoritative_handler_lost"
        for payload in rejected_payloads
    )


def test_apply_rejects_dispatcher_removal_when_coverage_metadata_is_stale() -> None:
    """The preflight must rederive residual corridors from the actual projection."""
    cfg = _comparison_dispatcher_forest_cfg()
    plan = _comparison_dispatcher_forest_plan(
        cfg,
        authoritative_handlers=frozenset({3, 4}),
    )
    stale_coverage = dict(
        plan.metadata_dict()[DISPATCHER_CORRIDOR_COVERAGE_METADATA]
    )
    stale_coverage["covered_corridors"] = []
    stale_plan = plan.with_metadata(
        **{DISPATCHER_CORRIDOR_COVERAGE_METADATA: stale_coverage}
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


def test_apply_rejects_recomputed_stale_dispatcher_coverage_proof(
    monkeypatch,
) -> None:
    """A plan cannot relabel an actual residual corridor out of existence."""
    cfg = _comparison_dispatcher_forest_cfg()
    plan = _comparison_dispatcher_forest_plan(
        cfg,
        authoritative_handlers=frozenset({3, 4}),
    )
    stale_coverage = replace(
        analyze_dispatcher_corridor_coverage(
            cfg,
            modifications=(RedirectGoto(from_serial=1, old_target=2, new_target=3),),
            dispatcher_entry_serial=2,
        ),
        covered_corridors=(),
        residual_corridors=(),
    )
    projected = project_patch_plan(cfg, plan, snapshot_id=plan.snapshot_id)
    stale_proof = build_dispatcher_removal_preflight_proof(
        cfg,
        post_graph=projected.graph,
        coverage=stale_coverage,
        dispatcher_entry_serial=2,
        authoritative_handler_serials=frozenset({3, 4}),
        dispatcher_region_serials=frozenset({2, *range(5, 32)}),
        producer_safety=_executed_fragment_safety(),
    )
    assert stale_proof.passed
    stale_plan = plan.with_metadata(
        **{
            DISPATCHER_CORRIDOR_COVERAGE_METADATA: stale_coverage.to_metadata(),
            DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA: stale_proof.to_metadata(),
        }
    )

    translator = _FakeTranslator(cfg)
    observed_outcomes = []
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_unflatten_dispatcher_corridor_coverage",
        lambda **kwargs: observed_outcomes.append(kwargs),
    )
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
    assert len(observed_outcomes) == 1
    assert {
        observation.payload["outcome_reason"]
        for observation in observed_outcomes[0]["observations"]
    } == {
        "projected reachability rejected: terminal=; "
        "entry=entry reachability collapsed; "
        "dispatcher_removal=dispatcher_removal_proof_coverage_drift; "
        "dispatcher_coverage=dispatcher_corridor_coverage_drift"
    }


def test_small_full_retirement_poisons_when_observed_graph_differs_from_projection(
    monkeypatch,
) -> None:
    """Ordinary preflight never weakens exact observed-coverage validation."""
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
    projected = project_patch_plan(cfg, plan, snapshot_id=plan.snapshot_id)
    proof = build_dispatcher_removal_preflight_proof(
        cfg,
        post_graph=projected.graph,
        coverage=coverage,
        dispatcher_entry_serial=2,
        authoritative_handler_serials=frozenset({3, 4}),
        dispatcher_region_serials=frozenset({2}),
        producer_safety=_executed_fragment_safety(),
    )
    assert proof.passed
    plan = plan.with_metadata(
        **{
            DISPATCHER_CORRIDOR_COVERAGE_METADATA: coverage.to_metadata(),
            DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA: proof.to_metadata(),
        }
    )
    outcomes = []
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_unflatten_dispatcher_corridor_coverage",
        lambda **kwargs: outcomes.append(kwargs),
    )
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(
            cfg,
            plan,
            lifecycle_authority=SessionFragmentPublicationLifecycleAuthority(
                native_key=NATIVE_KEY,
                state=NativePreanalysisSessionState(evidence_generation=0),
            ),
        ),
        # The fake translator deliberately leaves the dispatcher unchanged
        # after lower(); the generic small-CFG gate alone would pass.
        translator=translator,
    )

    with pytest.raises(CfgGenerationPoisoned):
        backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert backend.last_patch_failure is not None
    assert "dispatcher_corridor_coverage_drift" in str(backend.last_patch_failure)
    assert translator.lower_calls == [plan]
    assert translator.lift_count == 2
    payloads = [item.payload for item in outcomes[0]["observations"]]
    assert {payload["application_status"] for payload in payloads} == {
        "poisoned_restart_required"
    }
    proof_payload = next(
        payload
        for payload in payloads
        if payload.get("observed_coverage_validation") is not None
    )
    assert proof_payload["observed_coverage_validation"][
        "validation_status"
    ] == "rejected"
    assert proof_payload["observed_coverage_validation"]["reason"] == (
        "dispatcher_corridor_coverage_drift"
    )


def test_partial_coverage_drift_never_publishes_nonexistent_applied_corridor(
    monkeypatch,
) -> None:
    """A partial plan must reconcile every applied corridor with live CFG fact."""
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
    assert len(coverage.covered_corridors) == 1
    assert len(coverage.residual_corridors) == 1
    projected = project_patch_plan(cfg, plan, snapshot_id=plan.snapshot_id)
    proof = build_dispatcher_removal_preflight_proof(
        cfg,
        post_graph=projected.graph,
        coverage=coverage,
        dispatcher_entry_serial=2,
        authoritative_handler_serials=frozenset({3, 4}),
        dispatcher_region_serials=frozenset({2}),
        producer_safety=_executed_fragment_safety(),
    )
    plan = plan.with_metadata(
        **{
            DISPATCHER_CORRIDOR_COVERAGE_METADATA: coverage.to_metadata(),
            DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA: proof.to_metadata(),
        }
    )
    outcomes = []
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_unflatten_dispatcher_corridor_coverage",
        lambda **kwargs: outcomes.append(kwargs),
    )
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(
            cfg,
            plan,
            lifecycle_authority=SessionFragmentPublicationLifecycleAuthority(
                native_key=NATIVE_KEY,
                state=NativePreanalysisSessionState(evidence_generation=0),
            ),
        ),
        # The planned 0 -> 1 -> 2 corridor remains live after lower().
        translator=_FakeTranslator(cfg),
    )

    with pytest.raises(CfgGenerationPoisoned):
        backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    corridor_payloads = [
        item.payload
        for item in outcomes[0]["observations"]
        if item.kind == "UnflattenDispatcherCorridorCoverage"
    ]
    assert {
        (
            payload["planned_coverage"],
            payload["coverage"],
            payload["application_status"],
        )
        for payload in corridor_payloads
    } == {
        ("covered", "residual", "poisoned_restart_required"),
        ("residual", "residual", "poisoned_restart_required"),
    }
    assert {
        payload["observed_coverage_validation"]["reason"]
        for payload in corridor_payloads
    } == {"dispatcher_corridor_coverage_drift"}
    assert all(payload["coverage"] != "covered" for payload in corridor_payloads)


def test_lower_conditional_coverage_uses_the_logical_post_topology() -> None:
    """A conditional-state lowering must not drift only because it inserts a helper."""
    cfg = _make_cfg(
        [(0, 1), (0, 5), (1, 2), (5, 2), (2, 3)],
        stop_serials=(3, 4),
    )
    post_cfg = _make_cfg(
        [(0, 1), (0, 6), (1, 2), (1, 5), (2, 4), (6, 3), (3, 4)],
        stop_serials=(4, 5),
    )
    post_anchors = {
        0: 0x1000,
        1: 0x1001,
        2: 0x9002,
        3: 0x1002,
        4: 0x1003,
        5: 0x1004,
        6: 0x1005,
    }
    post_blocks = {
        serial: replace(
            block,
            start_ea=post_anchors[serial],
            native_start_ea=post_anchors[serial],
        )
        for serial, block in post_cfg.blocks.items()
    }
    post_blocks[2] = replace(
        post_blocks[2],
        kind=BlockKind.ONE_WAY,
        tail_kind=InsnKind.GOTO,
    )
    post_blocks[1] = replace(
        post_blocks[1],
        insn_snapshots=(
            InsnSnapshot(
                opcode=0x71,
                ea=0x1001,
                native_ea=0x1001,
                operands=(),
                l=MopSnapshot(kind=OperandKind.REGISTER, reg=9, size=4),
                r=MopSnapshot(kind=OperandKind.NUMBER, value=0, size=4),
                kind=InsnKind.COND_JUMP,
                predicate_kind=PredicateKind.NE,
            ),
        ),
    )
    post_cfg = replace(post_cfg, blocks=post_blocks)
    refs = {serial: _native_ref(serial) for serial in cfg.blocks}
    lowering = LowerConditionalStateTransition(
        source_serial=1,
        old_dispatcher_serial=2,
        rewrite_from_ea=0x1001,
        condition_operand=SyntheticRegisterNonzeroCondition(9, 4),
        false_target_serial=3,
        true_target_serial=4,
    )
    coverage = analyze_dispatcher_corridor_coverage(
        cfg,
        modifications=(lowering,),
        dispatcher_entry_serial=2,
    )
    assert len(coverage.covered_corridors) == 1
    assert len(coverage.residual_corridors) == 1
    plan = PatchPlan(
        source_maturity=MaturityEnvelope(
            ir=None,
            provider="hexrays",
            provider_id=0,
        ),
        source_generation=0,
        snapshot_id="lower-conditional-coverage",
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
        source_coordinates=tuple((refs[serial], serial) for serial in (1, 2, 3, 4)),
    ).with_metadata(
        **{DISPATCHER_CORRIDOR_COVERAGE_METADATA: coverage.to_metadata()}
    )

    class _LogicalPostTranslator(_FakeTranslator):
        def lift(self, _live_source: object) -> FlowGraph:
            self.lift_count += 1
            return post_cfg if self.lower_calls else cfg

    translator = _LogicalPostTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is post_cfg
    assert translator.lower_calls == [plan]


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


def _shifted_conditional_lowering_observed_graph() -> FlowGraph:
    """A helper at the function entry shifts the later live block serials."""
    observed = _make_cfg(
        [(0, 1), (1, 2), (1, 5), (2, 4), (3, 6)],
        stop_serials=(4, 5, 6),
    )
    starts = {
        0: 0x1000,
        1: 0x1001,
        2: 0x1000,  # synthetic adjacent fall-through helper
        3: 0x1002,
        4: 0x1003,
        5: 0x1004,
        6: 0x1005,
    }
    blocks = {
        serial: replace(
            block,
            start_ea=starts[serial],
            native_start_ea=starts[serial],
        )
        for serial, block in observed.blocks.items()
    }
    blocks[1] = replace(
        blocks[1],
        insn_snapshots=(
            InsnSnapshot(
                opcode=0x71,
                ea=0x1001,
                native_ea=0x1001,
                operands=(),
                l=MopSnapshot(kind=OperandKind.REGISTER, reg=9, size=4),
                r=MopSnapshot(kind=OperandKind.NUMBER, value=0, size=4),
                kind=InsnKind.COND_JUMP,
                predicate_kind=PredicateKind.NE,
            ),
        ),
    )
    blocks[2] = replace(
        blocks[2],
        kind=BlockKind.ONE_WAY,
        tail_kind=InsnKind.GOTO,
    )
    return replace(observed, blocks=blocks)


def _conditional_lowering_plan_with_coverage(cfg: FlowGraph) -> PatchPlan:
    refs = {serial: _native_ref(serial) for serial in cfg.blocks}
    lowering = LowerConditionalStateTransition(
        source_serial=1,
        old_dispatcher_serial=2,
        rewrite_from_ea=0x1001,
        condition_operand=SyntheticRegisterNonzeroCondition(9, 4),
        false_target_serial=3,
        true_target_serial=4,
    )
    coverage = analyze_dispatcher_corridor_coverage(
        cfg,
        modifications=(lowering,),
        dispatcher_entry_serial=2,
    )
    return PatchPlan(
        source_maturity=MaturityEnvelope(ir=None, provider="hexrays", provider_id=0),
        source_generation=0,
        snapshot_id="shifted-lower-observation",
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
        source_coordinates=tuple((refs[serial], serial) for serial in (1, 2, 3, 4)),
        metadata=((DISPATCHER_CORRIDOR_COVERAGE_METADATA, coverage.to_metadata()),),
    )


def test_observed_lowering_with_helper_serial_shift_does_not_poison() -> None:
    """Observed coverage is checked after mapping synthetic helpers to stable EAs."""
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 5)],
        stop_serials=(3, 4, 5),
    )
    plan = _conditional_lowering_plan_with_coverage(cfg)
    observed = _shifted_conditional_lowering_observed_graph()

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


def test_observed_lowering_canonicalizes_helper_topology_onto_pre_snapshot() -> None:
    """Physical helper serials are removed from the semantic observation graph."""
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 5)],
        stop_serials=(3, 4, 5),
    )
    plan = _conditional_lowering_plan_with_coverage(cfg)
    observed = _shifted_conditional_lowering_observed_graph()

    canonical = canonicalize_observed_dispatcher_graph(cfg, observed, plan)

    assert canonical.blocks[1].succs == (3, 4)
    assert canonical.blocks[1].kind is BlockKind.TWO_WAY
    assert canonical.blocks[1].tail_kind is InsnKind.COND_JUMP
    assert canonical.blocks[3].succs == ()
    assert canonical.blocks[4].succs == ()
    assert canonical.blocks[5].succs == ()


def test_observed_terminal_kind_drift_is_not_hidden_by_canonicalization() -> None:
    """Serial normalization must not restore STOP kinds lost by live lowering."""
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 5)],
        stop_serials=(3, 4, 5),
    )
    plan = _conditional_lowering_plan_with_coverage(cfg)
    observed = _shifted_conditional_lowering_observed_graph()
    observed = replace(
        observed,
        blocks={
            serial: replace(
                block,
                kind=BlockKind.ZERO_WAY,
                tail_kind=None,
            )
            if serial in {4, 5, 6}
            else block
            for serial, block in observed.blocks.items()
        },
    )

    class _DriftedTerminalTranslator(_FakeTranslator):
        def lift(self, _live_source: object) -> FlowGraph:
            self.lift_count += 1
            return cfg if self.lift_count == 1 else observed

    translator = _DriftedTerminalTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    with pytest.raises(CfgGenerationPoisoned):
        backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert translator.lower_calls == [plan]


def test_observed_lowering_transaction_uses_canonical_identity_boundary(monkeypatch) -> None:
    """The transaction caller must route observed validation through one seam."""
    from d810.transforms import dispatcher_corridor_coverage as coverage_module

    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 5)],
        stop_serials=(3, 4, 5),
    )
    plan = _conditional_lowering_plan_with_coverage(cfg)
    observed = _shifted_conditional_lowering_observed_graph()
    calls = []
    original = coverage_module.canonicalize_observed_dispatcher_graph

    def record_call(pre_graph, observed_graph, patch_plan):
        calls.append((pre_graph, observed_graph, patch_plan))
        return original(pre_graph, observed_graph, patch_plan)

    monkeypatch.setattr(
        coverage_module,
        "canonicalize_observed_dispatcher_graph",
        record_call,
        raising=False,
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

    assert backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks)) is observed
    assert calls == [(cfg, observed, plan)]


def test_observed_lowering_identity_drift_still_poisoned() -> None:
    """A changed stable block-start EA cannot be hidden by serial canonicalization."""
    cfg = _make_cfg(
        [(0, 1), (1, 2), (2, 5)],
        stop_serials=(3, 4, 5),
    )
    plan = _conditional_lowering_plan_with_coverage(cfg)
    observed = _shifted_conditional_lowering_observed_graph()
    observed = replace(
        observed,
        blocks={
            **observed.blocks,
            5: replace(
                observed.blocks[5],
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
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    with pytest.raises(CfgGenerationPoisoned):
        backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert translator.lower_calls == [plan]


def test_partial_coverage_without_proof_never_publishes_nonexistent_applied_corridor(
    monkeypatch,
) -> None:
    """Coverage truth is required even when a partial plan lacks a proof."""
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
    assert len(coverage.covered_corridors) == 1
    assert len(coverage.residual_corridors) == 1
    plan = plan.with_metadata(
        **{DISPATCHER_CORRIDOR_COVERAGE_METADATA: coverage.to_metadata()}
    )
    outcomes = []
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_unflatten_dispatcher_corridor_coverage",
        lambda **kwargs: outcomes.append(kwargs),
    )
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(
            cfg,
            plan,
            lifecycle_authority=SessionFragmentPublicationLifecycleAuthority(
                native_key=NATIVE_KEY,
                state=NativePreanalysisSessionState(evidence_generation=0),
            ),
        ),
        # The live CFG remains unchanged after the planned redirect.
        translator=_FakeTranslator(cfg),
    )

    with pytest.raises(CfgGenerationPoisoned):
        backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    corridor_payloads = [
        item.payload
        for item in outcomes[0]["observations"]
        if item.kind == "UnflattenDispatcherCorridorCoverage"
    ]
    assert {
        (
            payload["planned_coverage"],
            payload["coverage"],
            payload["application_status"],
        )
        for payload in corridor_payloads
    } == {
        ("covered", "residual", "poisoned_restart_required"),
        ("residual", "residual", "poisoned_restart_required"),
    }


def test_stale_partial_coverage_rejects_before_mutation(monkeypatch) -> None:
    """A stale partial corridor inventory is a clean preflight failure."""
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
    stale_coverage = coverage.to_metadata()
    stale_coverage["covered_corridors"] = []
    plan = plan.with_metadata(
        **{DISPATCHER_CORRIDOR_COVERAGE_METADATA: stale_coverage}
    )
    outcomes = []
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_unflatten_dispatcher_corridor_coverage",
        lambda **kwargs: outcomes.append(kwargs),
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
    corridor_payloads = [
        item.payload
        for item in outcomes[0]["observations"]
        if item.kind == "UnflattenDispatcherCorridorCoverage"
    ]
    assert {payload["application_status"] for payload in corridor_payloads} == {
        "rejected_preflight"
    }
    assert {
        payload["projected_coverage_validation"]["reason"]
        for payload in corridor_payloads
    } == {"dispatcher_corridor_coverage_drift"}


def test_non_dict_dispatcher_coverage_metadata_rejects_before_lowering(
    monkeypatch,
) -> None:
    """A present malformed coverage claim is a fail-closed transaction input."""
    cfg = _make_cfg([(0, 1), (1, 2)], stop_serials=(2,))
    plan = _ordinary_plan(
        PatchConvertToGoto,
        serials=(1, 2),
        block_serial=1,
        goto_target=2,
    ).with_metadata(**{DISPATCHER_CORRIDOR_COVERAGE_METADATA: []})
    outcomes = []
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_unflatten_dispatcher_corridor_coverage",
        lambda **kwargs: outcomes.append(kwargs),
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
    assert "dispatcher_corridor_coverage_missing" in str(backend.last_patch_failure)
    assert len(outcomes) == 1
    rejected_payloads = [
        observation.payload for observation in outcomes[0]["observations"]
    ]
    assert rejected_payloads
    assert all(
        payload["application_status"] == "rejected_preflight"
        for payload in rejected_payloads
    )
    assert any(
        payload.get("projected_coverage_validation", {}).get("reason")
        == "dispatcher_corridor_coverage_missing"
        for payload in rejected_payloads
    )


def test_scalar_nested_dispatcher_coverage_metadata_rejects_with_typed_reason(
    monkeypatch,
) -> None:
    """Nested coverage shape errors never reach obligation derivation or lowering."""
    cfg = _make_cfg([(0, 1), (1, 2)], stop_serials=(2,))
    malformed_coverage = {
        "function_ea": cfg.func_ea,
        "dispatcher": {
            "serial": 1,
            "ea": 0x1001,
            "label": "blk1@0x1001",
        },
        "enumeration_complete": True,
        "covered_corridors": [],
        "residual_corridors": 7,
    }
    plan = _ordinary_plan(
        PatchConvertToGoto,
        serials=(1, 2),
        block_serial=1,
        goto_target=2,
    ).with_metadata(
        **{DISPATCHER_CORRIDOR_COVERAGE_METADATA: malformed_coverage}
    )
    outcomes = []
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_unflatten_dispatcher_corridor_coverage",
        lambda **kwargs: outcomes.append(kwargs),
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
    assert "dispatcher_corridor_coverage_malformed" in str(
        backend.last_patch_failure
    )
    assert "TypeError" not in str(backend.last_patch_failure)
    assert len(outcomes) == 1
    rejected_payloads = [
        observation.payload for observation in outcomes[0]["observations"]
    ]
    assert rejected_payloads
    assert all(
        payload["application_status"] == "rejected_preflight"
        for payload in rejected_payloads
    )
    assert any(
        payload.get("projected_coverage_validation", {}).get("reason")
        == "dispatcher_corridor_coverage_malformed"
        for payload in rejected_payloads
    )


def test_clean_binding_failure_publishes_terminal_dispatcher_outcome(
    monkeypatch,
) -> None:
    """A pre-mutation error cannot leave coverage permanently pending."""
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
    coverage = analyze_dispatcher_corridor_coverage(
        cfg,
        modifications=(RedirectGoto(from_serial=1, old_target=2, new_target=3),),
        dispatcher_entry_serial=2,
    )
    plan = plan.with_metadata(
        **{DISPATCHER_CORRIDOR_COVERAGE_METADATA: coverage.to_metadata()}
    )
    outcomes = []
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_unflatten_dispatcher_corridor_coverage",
        lambda **kwargs: outcomes.append(kwargs),
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

    payloads = [item.payload for item in outcomes[0]["observations"]]
    assert {payload["application_status"] for payload in payloads} == {
        "rejected_clean"
    }
    assert {payload["outcome_reason"] for payload in payloads} == {"binding boom"}


def test_same_plan_clean_retries_publish_distinct_transaction_attempt_ids(
    monkeypatch,
) -> None:
    """Two clean retries must not collapse to the collector's unknown attempt."""
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
    plan = plan.with_metadata(
        **{DISPATCHER_CORRIDOR_COVERAGE_METADATA: coverage.to_metadata()}
    )
    outcomes = []
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_unflatten_dispatcher_corridor_coverage",
        lambda **kwargs: outcomes.append(kwargs),
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

    payloads = [
        item.payload
        for outcome in outcomes
        for item in outcome["observations"]
        if item.kind == "UnflattenDispatcherCorridorCoverage"
    ]
    attempt_by_reason = {
        payload["outcome_reason"]: payload["attempt_id"] for payload in payloads
    }
    assert set(attempt_by_reason) == {"binding retry one", "binding retry two"}
    assert "unknown" not in set(attempt_by_reason.values())
    assert len(set(attempt_by_reason.values())) == 2


def test_early_transaction_failure_publishes_minted_attempt_id(monkeypatch) -> None:
    """A failure before participant construction cannot fall back to unknown."""
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
    plan = plan.with_metadata(
        **{DISPATCHER_CORRIDOR_COVERAGE_METADATA: coverage.to_metadata()}
    )
    outcomes = []
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_unflatten_dispatcher_corridor_coverage",
        lambda **kwargs: outcomes.append(kwargs),
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

    payloads = [
        item.payload
        for item in outcomes[0]["observations"]
        if item.kind == "UnflattenDispatcherCorridorCoverage"
    ]
    assert {payload["application_status"] for payload in payloads} == {
        "rejected_clean"
    }
    assert {payload["attempt_id"] for payload in payloads} != {None}
    assert "unknown" not in {payload["attempt_id"] for payload in payloads}


def test_preflight_rejection_persists_projected_proof_validation(monkeypatch) -> None:
    """A stale plan records the recomputed projected proof, not its optimism."""
    cfg = _comparison_dispatcher_forest_cfg()
    plan = _comparison_dispatcher_forest_plan(
        cfg,
        authoritative_handlers=frozenset({3, 4}),
    )
    stale_coverage = dict(plan.metadata_dict()[DISPATCHER_CORRIDOR_COVERAGE_METADATA])
    stale_coverage["covered_corridors"] = []
    stale_plan = plan.with_metadata(
        **{DISPATCHER_CORRIDOR_COVERAGE_METADATA: stale_coverage}
    )
    outcomes = []
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_unflatten_dispatcher_corridor_coverage",
        lambda **kwargs: outcomes.append(kwargs),
    )
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, stale_plan),
        translator=_FakeTranslator(cfg),
    )

    assert backend.apply(stale_plan, live_source=SimpleNamespace(qty=cfg.num_blocks)) is cfg

    proof_payload = next(
        item.payload
        for item in outcomes[0]["observations"]
        if item.kind == "UnflattenDispatcherRemovalPreflightProof"
    )
    projected_validation = proof_payload["projected_validation"]
    assert projected_validation["validation_status"] == "rejected"
    assert projected_validation["reason"] == "dispatcher_removal_proof_coverage_drift"
    assert projected_validation["proof"] is None


def test_malformed_proof_evidence_does_not_mask_clean_preflight_rejection(
    monkeypatch,
) -> None:
    """Malformed diagnostic-only evidence cannot replace the typed rejection."""
    cfg = _comparison_dispatcher_forest_cfg()
    plan = _comparison_dispatcher_forest_plan(
        cfg,
        authoritative_handlers=frozenset({3, 4}),
    )
    malformed_proof = dict(
        plan.metadata_dict()[DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA]
    )
    malformed_proof["lost_blocks"] = 7
    malformed_plan = plan.with_metadata(
        **{DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA: malformed_proof}
    )
    outcomes = []
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_unflatten_dispatcher_corridor_coverage",
        lambda **kwargs: outcomes.append(kwargs),
    )
    translator = _FakeTranslator(cfg)
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, malformed_plan),
        translator=translator,
    )

    assert (
        backend.apply(malformed_plan, live_source=SimpleNamespace(qty=cfg.num_blocks))
        is cfg
    )

    assert translator.lower_calls == []
    assert backend.last_patch_failure is not None
    proof_payload = next(
        observation.payload
        for observation in outcomes[0]["observations"]
        if observation.kind == "UnflattenDispatcherRemovalPreflightProof"
    )
    assert proof_payload["lost_blocks_malformed"] is True


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


def test_backend_persists_observed_dispatcher_verdict_after_late_contract_poison(
    monkeypatch,
) -> None:
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
    plan = plan.with_metadata(
        **{DISPATCHER_CORRIDOR_COVERAGE_METADATA: coverage.to_metadata()}
    )
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

    outcomes = []
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_unflatten_dispatcher_corridor_coverage",
        lambda **kwargs: outcomes.append(kwargs),
    )
    translator = _ProjectedTranslator(cfg)
    translator.contract = _LateFailingContract()
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    with pytest.raises(CfgGenerationPoisoned):
        backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    coverage_payload = next(
        observation.payload
        for observation in outcomes[0]["observations"]
        if observation.kind == "UnflattenDispatcherCorridorCoverageSummary"
    )
    assert coverage_payload["observed_coverage_validation"]["validation_status"] == (
        "accepted"
    )


def test_dispatcher_outcome_publisher_failure_never_masks_poisoned_transaction(
    monkeypatch,
) -> None:
    """Diagnostic construction failure preserves the original poison exception."""
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
    plan = plan.with_metadata(
        **{DISPATCHER_CORRIDOR_COVERAGE_METADATA: coverage.to_metadata()}
    )
    projected = project_patch_plan(cfg, plan, snapshot_id=plan.snapshot_id)

    class _ProjectedTranslator(_FakeTranslator):
        def lift(self, _live_source: object) -> FlowGraph:
            self.lift_count += 1
            return projected.graph if self.lower_calls else cfg

    class _LateFailingContract:
        def __init__(self) -> None:
            self.projection_checks = 0

        def verify_projection(self, _projection: object, *, scope: str) -> None:
            self.projection_checks += 1
            if self.projection_checks == 2:
                raise RuntimeError("late post-observation contract failure")

        def verify(self, _mba: object, *, projection: object, phase: str) -> None:
            assert projection is not None
            assert phase == "pre"

    from d810.transforms import dispatcher_corridor_coverage as coverage_module

    def fail_diagnostic_construction(*_args: object, **_kwargs: object) -> tuple[object, ...]:
        raise RuntimeError("malformed diagnostic payload")

    monkeypatch.setattr(
        coverage_module,
        "collect_unflatten_dispatcher_outcome_observations_from_metadata",
        fail_diagnostic_construction,
    )
    translator = _ProjectedTranslator(cfg)
    translator.contract = _LateFailingContract()
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    with pytest.raises(CfgGenerationPoisoned) as raised:
        backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert "late post-observation contract failure" in str(raised.value)


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
    """A small full retirement need not synthesize missing proof authority."""
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
    assert coverage.planned_completion_status == "planned_dispatcher_corridors_covered"
    plan = plan.with_metadata(
        **{DISPATCHER_CORRIDOR_COVERAGE_METADATA: coverage.to_metadata()}
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
    assert translator.lower_calls == [plan]
    assert backend.last_patch_failure is None


def test_small_noncyclic_retirement_uses_ordinary_contract_despite_rejected_proof():
    """A rejected narrow proof alone must not disable ordinary safe rewrites."""
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
    projected = project_patch_plan(cfg, plan, snapshot_id=plan.snapshot_id)
    proof = build_dispatcher_removal_preflight_proof(
        cfg,
        post_graph=projected.graph,
        coverage=coverage,
        dispatcher_entry_serial=2,
        authoritative_handler_serials=frozenset({3, 4}),
        dispatcher_region_serials=frozenset({2}),
        producer_safety={},
    )
    assert not proof.passed
    plan = plan.with_metadata(
        **{
            DISPATCHER_CORRIDOR_COVERAGE_METADATA: coverage.to_metadata(),
            DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA: proof.to_metadata(),
        }
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

    result = backend.apply(plan, live_source=SimpleNamespace(qty=cfg.num_blocks))

    assert result is projected.graph
    assert translator.lower_calls == [plan]
    assert translator.lift_count == 2
    assert backend.last_patch_failure is None


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
    plan = PatchPlan(
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
    projected = project_patch_plan(cfg, plan, snapshot_id=plan.snapshot_id)
    proof = build_dispatcher_removal_preflight_proof(
        cfg,
        post_graph=projected.graph,
        coverage=coverage,
        dispatcher_entry_serial=2,
        authoritative_handler_serials=frozenset({3, 4, 5, 6}),
        dispatcher_region_serials=frozenset({2}),
        producer_safety={},
    )
    assert proof.reason == "untyped_lost_block"
    plan = plan.with_metadata(
        **{
            DISPATCHER_CORRIDOR_COVERAGE_METADATA: coverage.to_metadata(),
            DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA: proof.to_metadata(),
        }
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
    assert backend.last_patch_failure is not None
    assert "untyped_lost_block" in str(backend.last_patch_failure)


def test_small_switch_retirement_accepts_exact_terminal_cycle_break(
    monkeypatch,
) -> None:
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
    plan = PatchPlan(
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
    projected = project_patch_plan(cfg, plan, snapshot_id=plan.snapshot_id)
    proof = build_dispatcher_removal_preflight_proof(
        cfg,
        post_graph=projected.graph,
        coverage=coverage,
        dispatcher_entry_serial=2,
        authoritative_handler_serials=frozenset({3, 4, 5, 6}),
        dispatcher_region_serials=frozenset({2}),
        producer_safety={},
    )
    assert coverage.planned_completion_status == "planned_dispatcher_corridors_covered"
    assert not proof.passed
    assert proof.reason == "untyped_lost_block"
    plan = plan.with_metadata(
        **{
            DISPATCHER_CORRIDOR_COVERAGE_METADATA: coverage.to_metadata(),
            DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA: proof.to_metadata(),
        }
    )

    class _ProjectedTranslator(_FakeTranslator):
        def lift(self, _live_source: object) -> FlowGraph:
            self.lift_count += 1
            return projected.graph if self.lower_calls else cfg

    translator = _ProjectedTranslator(cfg)
    outcomes = []
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_unflatten_dispatcher_corridor_coverage",
        lambda **kwargs: outcomes.append(kwargs),
    )
    backend = HexRaysMutationBackend(
        mutation_gateway=_ordinary_gateway(cfg, plan),
        translator=translator,
    )

    result = backend.apply(
        plan,
        live_source=SimpleNamespace(qty=max(cfg.blocks) + 1),
    )

    assert result is projected.graph
    assert translator.lower_calls == [plan]
    assert backend.last_patch_failure is None
    assert len(outcomes) == 1
    proof_payload = next(
        observation.payload
        for observation in outcomes[0]["observations"]
        if observation.kind == "UnflattenDispatcherRemovalPreflightProof"
    )
    projected_validation = proof_payload["projected_validation"]
    assert projected_validation["validation_status"] == "accepted"
    assert projected_validation["reason"] == "terminal_switch_cycle_break"
    observed_validation = proof_payload["observed_validation"]
    assert observed_validation["validation_status"] == "accepted"
    assert observed_validation["reason"] == "terminal_switch_cycle_break"
    cycle_break = observed_validation["terminal_switch_cycle_break"]
    assert cycle_break["dispatcher"] == {
        "serial": 2,
        "ea": 0x1002,
        "label": "blk2@0x1002",
    }
    assert cycle_break["shared_merge"] == {
        "serial": 8,
        "ea": 0x1008,
        "label": "blk8@0x1008",
    }


def test_below_threshold_dispatcher_retirement_still_requires_narrow_proof(
    monkeypatch,
):
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
    outcomes = []
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_unflatten_dispatcher_corridor_coverage",
        lambda **kwargs: outcomes.append(kwargs),
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
    assert "dispatcher_removal_proof_missing" in str(backend.last_patch_failure)
    assert len(outcomes) == 1


def test_observed_corridor_coverage_drift_remains_fatal(monkeypatch):
    """Coverage drift rejects even when the ordinary entry gate itself passes."""
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
    stale_coverage = dict(coverage.to_metadata())
    stale_coverage["covered_corridors"] = []
    stale_coverage["residual_corridors"] = []
    plan = plan.with_metadata(
        **{DISPATCHER_CORRIDOR_COVERAGE_METADATA: stale_coverage}
    )
    outcomes = []
    monkeypatch.setattr(
        observability_preanalysis,
        "observe_unflatten_dispatcher_corridor_coverage",
        lambda **kwargs: outcomes.append(kwargs),
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
    assert "dispatcher_coverage=dispatcher_corridor_coverage_drift" in str(
        backend.last_patch_failure
    )
    assert "dispatcher_removal=" not in str(backend.last_patch_failure)
    assert len(outcomes) == 1
