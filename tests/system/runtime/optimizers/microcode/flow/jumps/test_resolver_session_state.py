"""Runtime-layer tests for session-owned computed-goto evidence."""

from __future__ import annotations

import importlib.util
from dataclasses import replace
from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.detached_handler_island import (
    DetachedSnippetBoundaryPortOwner,
    DetachedSnippetBoundaryPorts,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    TerminalReturnCarrierRequest,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    BootstrapRouteBindingEvidence,
    BootstrapRouteEvidence,
    BootstrapRouteProofKind,
    CallResultCarrier,
    ComputedGotoResolution,
    NativePreanalysisFacts,
    NativePreanalysisSessionState,
    PreoptUnionPreparationResult,
)
from d810.analyses.control_flow.native_semantic_closure import NativeCfg
from d810.analyses.control_flow.residual_entry_bridge import EntryBridgeEvidence
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.mba_mutation_events import (
    MbaMutationGateway,
    StructuralMutationKind,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
    ResolverSessionState,
    resolver_session_state,
)
from d810.optimizers.microcode.flow.jumps.computed_goto_resolver import (
    _native_entry_corridor_serials,
    _on_calls_done_preanalysis,
    _on_flowchart_preanalysis,
    rebind_live_preopt_routes,
    discover_static_native_bootstrap_routes,
)
from tests.native_preanalysis import make_native_key

NATIVE_KEY = make_native_key()


def _native_facts(
    transfers: tuple[MaterializedIndirectTransfer, ...] = (),
) -> NativePreanalysisFacts:
    return NativePreanalysisFacts(
        key=NATIVE_KEY,
        native_cfg=NativeCfg({}),
        semantic_closure=None,
        transfers=transfers,
        boundary_ports=DetachedSnippetBoundaryPorts((), ()),
    )


def test_resolver_session_state_has_a_dedicated_module() -> None:
    assert (
        importlib.util.find_spec(
            "d810.optimizers.microcode.flow.jumps.resolver_session_state"
        )
        is not None
    )


def test_resolver_session_state_reuses_the_named_lifecycle_attachment() -> None:
    """A hot-reloaded resolver module must recover the preflight attachment."""
    native_preanalysis = NativePreanalysisSessionState()
    original = ResolverSessionState(
        native_preanalysis=native_preanalysis, native_key=NATIVE_KEY
    )
    session = SimpleNamespace(
        native_preanalysis=native_preanalysis,
        resolver_attachment=original,
        native_key=NATIVE_KEY,
    )

    assert resolver_session_state(session) is original
    assert session.resolver_attachment is original


def test_call_result_carriers_are_lifecycle_owned_across_live_binding_release() -> None:
    native_preanalysis = NativePreanalysisSessionState()
    state = ResolverSessionState(
        native_preanalysis=native_preanalysis, native_key=NATIVE_KEY
    )
    first = CallResultCarrier(
        call_ea=0x401000,
        carrier_ea=0x401002,
        branch_ea=0x401004,
        callee_ea=0x402000,
        carrier_ida_stkoff=-4,
        value_size=4,
        branch_opcode=1,
    )
    second = replace(
        first,
        call_ea=0x401010,
        carrier_ea=0x401012,
        branch_ea=0x401014,
    )

    assert native_preanalysis.merge_call_result_carriers(
        NATIVE_KEY,
        (first, second),
    )

    assert native_preanalysis.resolver_evidence is not None
    assert native_preanalysis.resolver_evidence.call_result_carriers == (
        first,
        second,
    )
    state.release_live_bindings()
    assert native_preanalysis.resolver_evidence.call_result_carriers == (
        first,
        second,
    )


def test_imported_instruction_origins_are_current_mba_owned_and_normalized() -> None:
    state = ResolverSessionState(
        native_preanalysis=NativePreanalysisSessionState(), native_key=NATIVE_KEY
    )

    assert state.bind_current_imported_instruction_origins(
        0x1234,
        (
            (0xFFFFFFFFFFFFFF02, 0x40EAA8),
            (0xFFFFFFFFFFFFFF01, 0x40EAA7),
            (0xFFFFFFFFFFFFFF01, 0x40EAA7),
        ),
    )
    assert state.imported_instruction_origins_for(0x1234) == (
        (0xFFFFFFFFFFFFFF01, 0x40EAA7),
        (0xFFFFFFFFFFFFFF02, 0x40EAA8),
    )
    assert state.imported_instruction_origins_for(0x5678) == ()
    assert not state.bind_current_imported_instruction_origins(
        0x1234,
        (
            (0xFFFFFFFFFFFFFF02, 0x40EAA8),
            (0xFFFFFFFFFFFFFF01, 0x40EAA7),
        ),
    )

    state.release_live_bindings()

    assert state.current_mba_token is None
    assert state.current_imported_instruction_origins == ()


@pytest.mark.parametrize(
    ("mba_token", "origins"),
    (
        (0, ()),
        (0x1234, ((0, 0x40EAA7),)),
        (0x1234, ((0xFFFFFFFFFFFFFF01, 0),)),
        (
            0x1234,
            (
                (0xFFFFFFFFFFFFFF01, 0x40EAA7),
                (0xFFFFFFFFFFFFFF01, 0x40EAA8),
            ),
        ),
    ),
)
def test_current_mba_imported_origins_reject_invalid_coordinates(
    mba_token: int,
    origins: tuple[tuple[int, int], ...],
) -> None:
    state = ResolverSessionState(
        native_preanalysis=NativePreanalysisSessionState(), native_key=NATIVE_KEY
    )

    with pytest.raises(ValueError):
        state.bind_current_imported_instruction_origins(mba_token, origins)


def test_portable_dispatcher_region_merges_without_snapshot_serials() -> None:
    state = ResolverSessionState(
        native_preanalysis=NativePreanalysisSessionState(), native_key=NATIVE_KEY
    )
    first = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),), native_key=NATIVE_KEY
    )
    second = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAB1, 0x40EAB2),), native_key=NATIVE_KEY
    )

    assert state.native_preanalysis.merge_portable_dispatcher_region_identity(
        state.native_key,
        first,
    )
    assert state.evidence_generation == 1
    assert not state.native_preanalysis.merge_portable_dispatcher_region_identity(
        state.native_key,
        first,
    )
    assert state.native_preanalysis.merge_portable_dispatcher_region_identity(
        state.native_key,
        second,
    )
    assert state.evidence_generation == 1
    assert state.native_preanalysis.resolver_evidence is not None
    assert (
        state.native_preanalysis.resolver_evidence.dispatcher_region_identity
        == StableBlockIdentity.from_intervals(
            (
                NativeEaInterval(0x40EAA7, 0x40EAA8),
                NativeEaInterval(0x40EAB1, 0x40EAB2),
            ),
            native_key=NATIVE_KEY,
        )
    )


def test_session_evidence_rebinds_once_in_its_new_generation() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),), native_key=NATIVE_KEY
    )
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    evidence = BootstrapRouteEvidence(
        source_identity=source,
        source_anchor_ea=0x40D348,
        state=0x699BC698,
        handler_identity=handler,
        handler_anchor_ea=0x40EAA7,
        proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
    )

    assert state.native_preanalysis.merge_bootstrap_route(evidence)
    assert session.native_preanalysis.evidence_generation == 1
    assert state.native_preanalysis.request_controlled_redo()
    assert not state.native_preanalysis.request_controlled_redo()

    state.bind_current_mba(
        MbaBlockIdentityIndex.from_bindings(
            generation=1, bindings=((source, 17), (handler, 42)), native_key=NATIVE_KEY
        )
    )
    rebound = state.rebind_bootstrap_route(
        source_identity=source,
        state=0x699BC698,
    )

    assert rebound is not None
    assert rebound.source.serial == 17
    assert rebound.handler.serial == 42
    assert rebound.evidence.diagnostic_payload(generation=1, rebound=True) == {
        "source_ea": "0x40D348",
        "state": "0x699BC698",
        "handler_ea": "0x40EAA7",
        "generation": 1,
        "proof_kind": "static_native",
        "rebound": True,
    }


def test_generated_restart_is_staged_once_then_consumed_by_flowchart(
    monkeypatch,
) -> None:
    import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as resolver

    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(
            evidence_generation=2,
            bound_preopt_generation=2,
        ),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    redo: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(
        resolver,
        "request_hexrays_redo",
        lambda decision, reason, **details: (
            decision.__setitem__("request_redo", True),
            redo.append((reason, details)),
        ),
    )

    assert state.native_preanalysis.request_generated_restart()
    assert not state.native_preanalysis.request_generated_restart()
    # Evidence discovered later in the same decompile (for example terminal
    # return-carrier requests during GLBOPT) belongs to the already-staged
    # controller retry.  It must advance that pending generation rather than
    # silently cancelling the restart before the controller regains control.
    state.native_preanalysis.mark_evidence_changed(
        evidence_family="test_evidence",
        reason="test evidence changed",
    )
    assert state.native_preanalysis.evidence_generation == 3
    assert state.native_preanalysis.pending_generated_restart_generation == 3
    decision = {"session": session, "request_redo": False}

    _on_flowchart_preanalysis(
        function_ea=0x40D200,
        mba=object(),
        decision=decision,
    )

    assert decision["request_redo"] is True
    assert redo == [
        (
            "computed_goto_calls_evidence_rebind",
            {"function_ea": 0x40D200, "evidence_generation": 3},
        )
    ]
    assert not state.native_preanalysis.has_pending_generated_restart


def test_replaying_identical_conditional_bridge_is_an_evidence_noop() -> None:
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(
            evidence_generation=4,
            bound_preopt_generation=4,
        ),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    before = MaterializedIndirectTransfer(
        source_jmp_ea=0x401010,
        source_block_ea=0x401000,
        materialized_anchor_eas=(),
        target_eas=(0x402000,),
    )
    bridge = MaterializedIndirectTransfer(
        source_jmp_ea=0x40E20E,
        source_block_ea=0x40E1F6,
        materialized_anchor_eas=(0x40E20E,),
        target_eas=(0x40F12D, 0x40DC04),
        resolver_kind="static_conditional_state_choice_bridge",
    )
    after = MaterializedIndirectTransfer(
        source_jmp_ea=0x403010,
        source_block_ea=0x403000,
        materialized_anchor_eas=(),
        target_eas=(0x404000,),
    )
    state.native_preanalysis.facts = _native_facts((before, bridge, after))

    assert not state.native_preanalysis.merge_materialized_transfers(
        state.native_key, (bridge,)
    )
    assert frozenset(state.materialized_transfers) == {before, bridge, after}
    assert state.evidence_generation == 4


def test_weaker_conditional_bridge_refresh_cannot_erase_arm_state_evidence() -> None:
    """A regenerated MBA may retain topology after losing the arm constants."""
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(
            evidence_generation=4,
            bound_preopt_generation=4,
        ),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    exact = MaterializedIndirectTransfer(
        source_jmp_ea=0x40DC24,
        source_block_ea=0x40D200,
        materialized_anchor_eas=(0x40DC24,),
        target_eas=(0x40DDF9, 0x40E4A1),
        condition_code=5,
        true_target_ea=0x40DDF9,
        false_target_ea=0x40E4A1,
        selector_state_var_reg=28,
        predicate_true_state=0xD88462B5,
        predicate_false_state=0x0EC95CE7,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
        resolver_kind="conditional_handler_bridge",
    )
    weaker_refresh = MaterializedIndirectTransfer(
        source_jmp_ea=0x40DC24,
        source_block_ea=0x40D200,
        materialized_anchor_eas=(0x40DC24,),
        target_eas=(0x40DDF9, 0x40E4A1),
        condition_code=5,
        true_target_ea=0x40DDF9,
        false_target_ea=0x40E4A1,
        selector_state_var_reg=28,
        resolver_kind="conditional_handler_bridge",
    )
    state.native_preanalysis.facts = _native_facts((exact,))

    assert not state.native_preanalysis.merge_materialized_transfers(
        state.native_key, (weaker_refresh,)
    )
    assert state.materialized_transfers == (exact,)
    assert state.evidence_generation == 4


def test_weaker_conditional_bridge_refresh_cannot_inherit_states_across_sources() -> (
    None
):
    """A predicate anchor does not authorize transplanting proof provenance."""
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(
            evidence_generation=4,
            bound_preopt_generation=4,
        ),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    exact = MaterializedIndirectTransfer(
        source_jmp_ea=0x40E04B,
        source_block_ea=0x40DFA2,
        materialized_anchor_eas=(0x40E04B,),
        target_eas=(0x40F177, 0x40D848),
        condition_code=5,
        true_target_ea=0x40F177,
        false_target_ea=0x40D848,
        selector_state_var_reg=28,
        predicate_true_state=0x6BD791A0,
        predicate_false_state=0x0698355C,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
        resolver_kind="conditional_handler_bridge",
    )
    regenerated = replace(
        exact,
        source_block_ea=0x40D200,
        predicate_true_state=None,
        predicate_false_state=None,
        predicate_true_is_taken=None,
        predicate_preserve_live=False,
    )
    state.native_preanalysis.facts = _native_facts((exact,))

    assert state.native_preanalysis.merge_materialized_transfers(
        state.native_key, (regenerated,)
    )
    assert frozenset(state.materialized_transfers) == {exact, regenerated}
    refreshed = next(
        transfer
        for transfer in state.materialized_transfers
        if transfer.source_block_ea == 0x40D200
    )
    assert refreshed.predicate_true_state is None
    assert refreshed.predicate_false_state is None
    assert state.evidence_generation == 5


def test_calls_ignores_obsolete_mba_after_generated_restart_is_staged(
    monkeypatch,
) -> None:
    import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as resolver
    import d810.hexrays.mutation.detached_handler_island as island

    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(
            evidence_generation=4,
            bound_preopt_generation=4,
        ),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    state.materialized = True
    assert state.native_preanalysis.request_generated_restart()
    analyzed: list[object] = []
    monkeypatch.setattr(
        resolver,
        "_recover_condition_chain_handler_transfers_from_mba",
        lambda transfers, mba: analyzed.append(mba) or (),
    )
    monkeypatch.setattr(
        island,
        "imported_detached_snippet_instruction_origins",
        lambda mba: (),
    )
    decision = {"session": session}

    resolver._on_calls_done_preanalysis(
        function_ea=0x40D200,
        mba=object(),
        decision=decision,
    )

    assert decision == {"session": session}
    assert analyzed == []
    assert state.evidence_generation == 4
    assert state.native_preanalysis.has_pending_generated_restart


def test_bootstrap_route_is_published_only_after_current_preopt_rebind() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),), native_key=NATIVE_KEY
    )
    state = ResolverSessionState(
        native_preanalysis=NativePreanalysisSessionState(), native_key=NATIVE_KEY
    )
    route = BootstrapRouteEvidence(
        source_identity=source,
        source_anchor_ea=0x40D348,
        state=0x699BC698,
        handler_identity=handler,
        handler_anchor_ea=0x40EAA7,
        proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
    )

    assert state.native_preanalysis.merge_bootstrap_route(route)
    assert state.bound_bootstrap_routes() == ()

    state.bind_current_mba(
        MbaBlockIdentityIndex.from_bindings(
            generation=0,
            evidence_generation=1,
            bindings=((source, 17), (handler, 42)),
            native_key=NATIVE_KEY,
        )
    )
    assert (
        state.rebind_bootstrap_route(
            source_identity=source,
            state=0x699BC698,
        )
        is not None
    )
    assert state.native_preanalysis.mark_bootstrap_route_rebound(route)
    assert state.bound_bootstrap_routes() == ()
    binding = BootstrapRouteBindingEvidence(
        route=route,
        source_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x40D313, 0x40D34A),), native_key=NATIVE_KEY
        ),
        handler_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x40EAA1, 0x40EAB7),), native_key=NATIVE_KEY
        ),
        evidence_generation=1,
    )
    assert state.native_preanalysis.record_bootstrap_route_binding(
        state.native_key,
        binding,
    )

    assert state.native_preanalysis.mark_preopt_bound()
    assert state.bound_bootstrap_routes() == (route,)
    assert state.native_preanalysis.bound_bootstrap_route_bindings(
        state.native_key
    ) == (binding,)

    # Later CALLS facts may advance the shared evidence epoch without
    # regenerating the already-routed MBA.  The route remains tied to the
    # generation that actually bound this live MBA.
    state.native_preanalysis.mark_evidence_changed(
        evidence_family="test_evidence",
        reason="test evidence changed",
    )
    assert state.evidence_generation == 2
    assert state.bound_bootstrap_routes() == (route,)
    assert state.native_preanalysis.bound_bootstrap_route_bindings(
        state.native_key
    ) == (binding,)


def test_preflight_discovery_discards_pre_redo_serials() -> None:
    """Native preflight names anchors; only PREOPT provides live serials."""
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),), native_key=NATIVE_KEY
    )
    state = resolver_session_state(
        SimpleNamespace(
            native_preanalysis=NativePreanalysisSessionState(),
            resolver_attachment=None,
            native_key=NATIVE_KEY,
        )
    )

    assert state.native_preanalysis.discover_static_native_bootstrap_route(
        state.native_key,
        source_anchor_ea=0x40D348,
        state_constant=0x699BC698,
        handler_anchor_ea=0x40EAA7,
    )
    assert state.evidence_generation == 1
    assert state.native_preanalysis.request_controlled_redo()

    state.bind_current_mba(
        MbaBlockIdentityIndex.from_bindings(
            generation=1,
            bindings=((source, 170), (handler, 420)),
            native_key=NATIVE_KEY,
        )
    )
    rebound = state.rebind_bootstrap_route(
        source_identity=source,
        state=0x699BC698,
    )
    assert rebound is not None
    assert (rebound.source.serial, rebound.handler.serial) == (170, 420)


def test_preflight_discovery_names_both_anchors_without_a_live_mba() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401020, 0x401021),), native_key=NATIVE_KEY
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401100, 0x401101),), native_key=NATIVE_KEY
    )
    state = resolver_session_state(
        SimpleNamespace(
            native_preanalysis=NativePreanalysisSessionState(),
            resolver_attachment=None,
            native_key=NATIVE_KEY,
        )
    )

    assert state.native_preanalysis.discover_static_native_bootstrap_route(
        state.native_key,
        source_anchor_ea=0x401020,
        state_constant=0x12345678,
        handler_anchor_ea=0x401100,
    )
    assert state.native_preanalysis.request_controlled_redo()

    state.bind_current_mba(
        MbaBlockIdentityIndex.from_bindings(
            generation=0,
            evidence_generation=1,
            bindings=((source, 170), (handler, 420)),
            native_key=NATIVE_KEY,
        )
    )
    rebound = state.rebind_bootstrap_route(
        source_identity=source,
        state=0x12345678,
    )

    assert rebound is not None
    assert (rebound.source.serial, rebound.handler.serial) == (170, 420)


def test_rebinding_survives_mutation_lineage_without_changing_evidence_epoch() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),), native_key=NATIVE_KEY
    )
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(evidence_generation=1),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    state.native_preanalysis.bootstrap_routes[(source, 0x699BC698)] = (
        BootstrapRouteEvidence(
            source_identity=source,
            source_anchor_ea=0x40D348,
            state=0x699BC698,
            handler_identity=handler,
            handler_anchor_ea=0x40EAA7,
            proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
        )
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=0,
        evidence_generation=1,
        bindings=((source, 17), (handler, 42)),
        native_key=NATIVE_KEY,
    )
    state.bind_current_mba(index)

    gateway = MbaMutationGateway(
        generation=0,
        session_id="identity-index",
        identity_index=index,
        native_key=NATIVE_KEY,
    )
    gateway.record(StructuralMutationKind.EDGE_REDIRECT)
    rebound = state.rebind_bootstrap_route(
        source_identity=source,
        state=0x699BC698,
    )

    assert index.evidence_generation == 1
    assert rebound is not None
    assert rebound.generation == 1


def test_bootstrap_rebind_can_select_the_unique_imported_handler_clone() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),), native_key=NATIVE_KEY
    )
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(evidence_generation=1),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    route = BootstrapRouteEvidence(
        source_identity=source,
        source_anchor_ea=0x40D348,
        state=0x699BC698,
        handler_identity=handler,
        handler_anchor_ea=0x40EAA7,
        proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
    )
    state.native_preanalysis.bootstrap_routes[route.key] = route
    index = MbaBlockIdentityIndex.from_bindings(
        generation=0,
        evidence_generation=1,
        bindings=((source, 7), (handler, 9)),
        native_key=NATIVE_KEY,
    )
    index.begin_transaction(10)
    imported = index.create_imported_native_handle(handler)
    index.record_insert(
        insertion_serial=10,
        created=imported,
        returned_serial=10,
    )
    state.bind_current_mba(index)

    assert (
        state.rebind_bootstrap_route(
            source_identity=source,
            state=0x699BC698,
        )
        is None
    )
    rebound = state.rebind_bootstrap_route(
        source_identity=source,
        state=0x699BC698,
        prefer_imported_handler=True,
    )

    assert rebound is not None
    assert rebound.source.serial == 7
    assert rebound.handler.serial == 10
    assert rebound.handler.handle is imported


def test_preopt_route_consumption_uses_the_injected_mutation_gateway(
    monkeypatch,
) -> None:
    import ida_hexrays
    import d810.hexrays.mutation.deferred_modifier as modifier_module

    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401020, 0x401021),), native_key=NATIVE_KEY
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401100, 0x401101),), native_key=NATIVE_KEY
    )
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    route = BootstrapRouteEvidence(
        source_identity=source,
        source_anchor_ea=0x401020,
        state=0x12345678,
        handler_identity=handler,
        handler_anchor_ea=0x401100,
        proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
    )
    assert state.native_preanalysis.merge_bootstrap_route(route)
    state.bind_current_mba(
        MbaBlockIdentityIndex.from_bindings(
            generation=0,
            evidence_generation=1,
            bindings=((source, 7), (handler, 9)),
            native_key=NATIVE_KEY,
        )
    )

    class _Block:
        def __init__(self, *, tail: object | None = None, successor: int = 0) -> None:
            self.tail = tail
            self._successor = successor

        def nsucc(self) -> int:
            return 1

        def succ(self, _index: int) -> int:
            return self._successor

    class _Mba:
        def __init__(self) -> None:
            self.blocks = {
                7: _Block(
                    tail=SimpleNamespace(
                        ea=0x401020,
                        opcode=ida_hexrays.m_goto,
                    ),
                    successor=3,
                ),
                9: _Block(),
            }

        def get_mblock(self, serial: int) -> _Block | None:
            return self.blocks.get(int(serial))

    queued: list[tuple[int, int]] = []

    class _Modifier:
        def __init__(self, mba: object, *, mutation_gateway: object) -> None:
            assert mba is not None
            assert mutation_gateway == "gateway"

        def queue_goto_change(
            self, *, block_serial: int, new_target: int, **_kwargs
        ) -> None:
            queued.append((int(block_serial), int(new_target)))

        def apply(self, **_kwargs) -> int:
            return 1

    monkeypatch.setattr(modifier_module, "DeferredGraphModifier", _Modifier)
    state.native_preanalysis.set_preopt_union_preparation(
        state.native_key,
        PreoptUnionPreparationResult(
            function_ea=0x401000,
            prepared=True,
            published=True,
            primary_seed_ea=0x401080,
        ),
    )
    decision = {
        "session": session,
        "mutation_gateway": "gateway",
        "details": {"preopt_union_root_ea": 0x401080},
    }

    state.preopt_union_import_active = True
    rebind_live_preopt_routes(
        function_ea=0x401000,
        mba=_Mba(),
        decision=decision,
    )
    assert queued == []
    assert session.native_preanalysis.bound_preopt_generation is None
    state.preopt_union_import_active = False
    # The union importer binds the evidence generation before the later
    # bootstrap handler gets its turn.  Route rebinding is independently
    # pending and must still run in that same PREOPT callback.
    assert session.native_preanalysis.mark_preopt_bound()

    rebind_live_preopt_routes(
        function_ea=0x401000,
        mba=_Mba(),
        decision=decision,
    )

    assert queued == [(7, 9)]
    assert decision["microcode_modified"] is True
    assert session.native_preanalysis.bound_preopt_generation == 1
    assert session.native_preanalysis.pending_rebound_bootstrap_routes() == (route,)


def test_preopt_route_consumption_materializes_a_zero_way_goto(monkeypatch) -> None:
    import ida_hexrays
    import d810.hexrays.mutation.deferred_modifier as modifier_module

    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),), native_key=NATIVE_KEY
    )
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    route = BootstrapRouteEvidence(
        source_identity=source,
        source_anchor_ea=0x40D348,
        state=0x699BC698,
        handler_identity=handler,
        handler_anchor_ea=0x40EAA7,
        proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
    )
    assert state.native_preanalysis.merge_bootstrap_route(route)
    state.bind_current_mba(
        MbaBlockIdentityIndex.from_bindings(
            generation=0,
            evidence_generation=1,
            bindings=((source, 29), (handler, 42)),
            native_key=NATIVE_KEY,
        )
    )

    class _Block:
        def __init__(self, serial: int, *, tail: object | None = None) -> None:
            self.serial = int(serial)
            self.start = 0x40D313 if serial == 29 else 0x40EAA7
            self.head = tail
            self.tail = tail

        def nsucc(self) -> int:
            return 0

        def succ(self, _index: int) -> int:
            raise IndexError

    class _Mba:
        entry_ea = 0x40D200
        qty = 43

        def __init__(self) -> None:
            self.blocks = {
                29: _Block(
                    29,
                    tail=SimpleNamespace(
                        ea=0x40D348,
                        opcode=ida_hexrays.m_goto,
                    ),
                ),
                42: _Block(42),
            }

        def get_mblock(self, serial: int) -> _Block | None:
            return self.blocks.get(int(serial))

    queued: list[tuple[int, int]] = []

    class _Modifier:
        def __init__(self, mba: object, *, mutation_gateway: object) -> None:
            assert mba is not None
            assert mutation_gateway == "gateway"

        def queue_terminal_goto_change(
            self, *, block_serial: int, goto_target: int, **_kwargs
        ) -> None:
            queued.append((int(block_serial), int(goto_target)))

        def apply(self, **_kwargs) -> int:
            return 1

    monkeypatch.setattr(modifier_module, "DeferredGraphModifier", _Modifier)
    decision = {"session": session, "mutation_gateway": "gateway"}

    rebind_live_preopt_routes(
        function_ea=0x40D200,
        mba=_Mba(),
        decision=decision,
    )

    assert queued == [(29, 42)]
    assert decision["microcode_modified"] is True
    assert session.native_preanalysis.bound_preopt_generation == 1


def test_preopt_routes_static_conditional_taken_arm_through_gateway(
    monkeypatch,
) -> None:
    import ida_hexrays
    import d810.hexrays.mutation.deferred_modifier as modifier_module

    predicate_ea = 0x40E20E
    true_target_ea = 0x40F12D
    source_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(predicate_ea, predicate_ea + 1),), native_key=NATIVE_KEY
    )
    target_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(true_target_ea, true_target_ea + 1),), native_key=NATIVE_KEY
    )
    false_target_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40DC04, 0x40DC05),), native_key=NATIVE_KEY
    )
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    assert state.native_preanalysis.merge_materialized_transfers(
        state.native_key,
        (
            MaterializedIndirectTransfer(
                source_jmp_ea=predicate_ea,
                source_block_ea=0x40E1F6,
                materialized_anchor_eas=(predicate_ea,),
                target_eas=(true_target_ea, 0x40DC04),
                condition_code=4,
                true_target_ea=true_target_ea,
                false_target_ea=0x40DC04,
                selector_state_var_reg=28,
                predicate_true_state=0x3AF41FBE,
                predicate_false_state=0x85AE90D3,
                predicate_true_is_taken=True,
                predicate_preserve_live=True,
                resolver_kind="static_conditional_state_choice_bridge",
            ),
        ),
    )
    state.bind_current_mba(
        MbaBlockIdentityIndex.from_bindings(
            generation=0,
            evidence_generation=1,
            bindings=(
                (source_identity, 7),
                (target_identity, 9),
                (false_target_identity, 11),
            ),
            native_key=NATIVE_KEY,
        )
    )

    class _Block:
        def __init__(
            self,
            *,
            tail: object | None = None,
            successors: tuple[int, ...] = (),
        ) -> None:
            self.tail = tail
            self._successors = successors

        def nsucc(self) -> int:
            return len(self._successors)

        def succ(self, index: int) -> int:
            return self._successors[index]

    class _Mba:
        def __init__(self) -> None:
            self.blocks = {
                7: _Block(
                    tail=SimpleNamespace(
                        ea=predicate_ea,
                        opcode=ida_hexrays.m_jz,
                        d=SimpleNamespace(t=ida_hexrays.mop_b, b=8),
                    ),
                    successors=(6, 8),
                ),
                9: _Block(),
                11: _Block(),
            }

        def get_mblock(self, serial: int) -> _Block | None:
            return self.blocks.get(int(serial))

    queued: list[tuple[int, int, int | None]] = []

    class _Modifier:
        def __init__(self, mba: object, *, mutation_gateway: object) -> None:
            assert mba is not None
            assert mutation_gateway == "gateway"

        def queue_conditional_target_change(
            self,
            *,
            block_serial: int,
            new_target: int,
            old_target: int | None = None,
            **_kwargs,
        ) -> None:
            queued.append((int(block_serial), int(new_target), old_target))

        def apply(self, **kwargs) -> int:
            assert kwargs == {"transactional": True, "staged_atomic": True}
            return 1

    monkeypatch.setattr(modifier_module, "DeferredGraphModifier", _Modifier)
    decision = {"session": session, "mutation_gateway": "gateway"}

    rebind_live_preopt_routes(
        function_ea=0x40D200,
        mba=_Mba(),
        decision=decision,
    )

    assert queued == [(7, 9, 8)]
    assert decision["microcode_modified"] is True
    assert session.native_preanalysis.bound_preopt_generation == 1


def test_preopt_materializes_zero_way_static_conditional_through_gateway(
    monkeypatch,
) -> None:
    import ida_hexrays
    import d810.hexrays.mutation.deferred_modifier as modifier_module

    predicate_ea = 0x40E20E
    taken_target_ea = 0x40F12D
    fallthrough_target_ea = 0x40DC04
    source_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(predicate_ea, predicate_ea + 1),), native_key=NATIVE_KEY
    )
    taken_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(taken_target_ea, taken_target_ea + 1),), native_key=NATIVE_KEY
    )
    fallthrough_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(fallthrough_target_ea, fallthrough_target_ea + 1),),
        native_key=NATIVE_KEY,
    )
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    assert state.native_preanalysis.merge_materialized_transfers(
        state.native_key,
        (
            MaterializedIndirectTransfer(
                source_jmp_ea=predicate_ea,
                source_block_ea=0x40E1F6,
                materialized_anchor_eas=(predicate_ea,),
                target_eas=(taken_target_ea, fallthrough_target_ea),
                condition_code=4,
                true_target_ea=taken_target_ea,
                false_target_ea=fallthrough_target_ea,
                selector_state_var_reg=28,
                predicate_true_state=0x3AF41FBE,
                predicate_false_state=0x85AE90D3,
                predicate_true_is_taken=True,
                predicate_preserve_live=True,
                resolver_kind="static_conditional_state_choice_bridge",
            ),
        ),
    )
    state.bind_current_mba(
        MbaBlockIdentityIndex.from_bindings(
            generation=0,
            evidence_generation=1,
            bindings=(
                (source_identity, 7),
                (taken_identity, 9),
                (fallthrough_identity, 11),
            ),
            native_key=NATIVE_KEY,
        )
    )

    class _Block:
        def __init__(self, *, tail: object | None = None) -> None:
            self.tail = tail

        def nsucc(self) -> int:
            return 0

        def succ(self, _index: int) -> int:
            raise IndexError

    class _Mba:
        maturity = ida_hexrays.MMAT_GENERATED

        def __init__(self) -> None:
            self.blocks = {
                7: _Block(
                    tail=SimpleNamespace(
                        ea=predicate_ea,
                        opcode=ida_hexrays.m_jcnd,
                        l=SimpleNamespace(t=ida_hexrays.mop_d),
                        r=SimpleNamespace(t=ida_hexrays.mop_z),
                        d=SimpleNamespace(t=ida_hexrays.mop_v, v=taken_target_ea),
                    )
                ),
                9: _Block(),
                11: _Block(),
            }

        def get_mblock(self, serial: int) -> _Block | None:
            return self.blocks.get(int(serial))

    queued: list[tuple[int, int, int, int]] = []

    class _Modifier:
        def __init__(self, mba: object, *, mutation_gateway: object) -> None:
            assert mba is not None
            assert mutation_gateway == "gateway"

        def queue_materialize_zero_way_conditional(
            self,
            *,
            source_serial: int,
            predicate_ea: int,
            taken_target_serial: int,
            fallthrough_target_serial: int,
            **_kwargs,
        ) -> None:
            queued.append(
                (
                    int(source_serial),
                    int(predicate_ea),
                    int(taken_target_serial),
                    int(fallthrough_target_serial),
                )
            )

        def apply(self, **kwargs) -> int:
            assert kwargs == {"transactional": True, "staged_atomic": True}
            return 1

    monkeypatch.setattr(modifier_module, "DeferredGraphModifier", _Modifier)
    decision = {"session": session, "mutation_gateway": "gateway"}

    rebind_live_preopt_routes(
        function_ea=0x40D200,
        mba=_Mba(),
        decision=decision,
    )

    assert queued == [(7, predicate_ea, 9, 11)]
    assert decision["microcode_modified"] is True
    assert session.native_preanalysis.bound_preopt_generation == 1

    state.native_preanalysis.set_preopt_union_preparation(
        state.native_key,
        PreoptUnionPreparationResult(
            function_ea=0x40D200,
            prepared=True,
            published=True,
            primary_seed_ea=taken_target_ea,
        ),
    )
    state.native_preanalysis.mark_evidence_changed(
        evidence_family="test_evidence",
        reason="test evidence changed",
    )
    rebind_live_preopt_routes(
        function_ea=0x40D200,
        mba=_Mba(),
        decision={
            "session": session,
            "mutation_gateway": "gateway",
        },
    )

    assert queued == [(7, predicate_ea, 9, 11)]
    assert session.native_preanalysis.bound_preopt_generation == 1

    rebind_live_preopt_routes(
        function_ea=0x40D200,
        mba=_Mba(),
        decision={
            "session": session,
            "mutation_gateway": "gateway",
            "details": {"preopt_union_root_ea": taken_target_ea},
        },
    )

    assert queued == [(7, predicate_ea, 9, 11)]
    assert session.native_preanalysis.bound_preopt_generation == 2


def test_prepared_union_applies_only_the_external_entry_bridge_port(
    monkeypatch,
) -> None:
    from d810.optimizers.microcode.flow.jumps import computed_goto_resolver

    function_ea = 0x40A560
    taken_state = 0xA0716E5B
    fallthrough_state = 0xEC71CA67
    taken_target = 0x40C26D
    fallthrough_target = 0x40B9A6
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    evidence = EntryBridgeEvidence(
        predicate_ea=0x40A5A0,
        condition_code=5,
        predicate_stack_identity=(0x20, 4),
        stack_cell_identity=(0x80, 4),
        taken_state_constant=taken_state,
        fallthrough_state_constant=fallthrough_state,
        source_store_ea=0x40A5AE,
        canonical_stack_cell_identity=(0x40, 4),
        canonical_predicate_stack_identity=(-0x20, 4),
        predicate_block_ea=0x40A59D,
        conditional_tail_ea=0x40A5AB,
    )
    assert state.native_preanalysis.merge_preopt_entry_bridge_evidence(
        state.native_key,
        evidence,
    )
    assert state.native_preanalysis.merge_materialized_transfers(
        state.native_key,
        (
            MaterializedIndirectTransfer(
                source_jmp_ea=0x40C253,
                source_block_ea=0x40C253,
                materialized_anchor_eas=(),
                target_eas=(taken_target,),
                selector_state_var_reg=20,
                selector_state_constant=taken_state,
                resolver_kind="static_handler_entry_route",
            ),
            MaterializedIndirectTransfer(
                source_jmp_ea=0x40B98C,
                source_block_ea=0x40B98C,
                materialized_anchor_eas=(),
                target_eas=(fallthrough_target,),
                selector_state_var_reg=20,
                selector_state_constant=fallthrough_state,
                resolver_kind="static_handler_entry_route",
            ),
            MaterializedIndirectTransfer(
                source_jmp_ea=0x40B000,
                source_block_ea=0x40B000,
                materialized_anchor_eas=(),
                target_eas=(0x40B100, 0x40B200),
                condition_code=5,
                true_target_ea=0x40B100,
                false_target_ea=0x40B200,
                selector_state_var_reg=20,
                predicate_true_is_taken=True,
                predicate_preserve_live=True,
                resolver_kind="static_conditional_state_choice_bridge",
            ),
        ),
    )
    assert state.native_preanalysis.discover_static_native_bootstrap_route(
        state.native_key,
        source_anchor_ea=0x40A5C8,
        state_constant=0xABB95547,
        handler_anchor_ea=0x40BECC,
    )
    state.native_preanalysis.set_preopt_union_preparation(
        state.native_key,
        PreoptUnionPreparationResult(
            function_ea=function_ea,
            prepared=True,
            published=True,
            primary_seed_ea=taken_target,
        ),
    )
    state.bind_current_mba(
        MbaBlockIdentityIndex.from_bindings(
            generation=0,
            evidence_generation=state.evidence_generation,
            bindings=(),
            native_key=NATIVE_KEY,
        )
    )
    captured: list[tuple[object, ...]] = []

    def apply_ports(mba, applied_function_ea, ports, *, mutation_gateway):
        captured.append((mba, applied_function_ea, ports, mutation_gateway))
        return (object(),)

    monkeypatch.setattr(
        computed_goto_resolver,
        "_capture_preopt_entry_bridge_evidence",
        lambda _state, _mba: False,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "apply_live_conditional_boundary_ports",
        apply_ports,
    )
    mba = SimpleNamespace(entry_ea=function_ea, qty=0)
    decision = {"session": session, "mutation_gateway": "gateway"}

    rebind_live_preopt_routes(
        function_ea=function_ea,
        mba=mba,
        decision=decision,
    )

    assert len(captured) == 1
    assert captured[0][0] is mba
    assert captured[0][1] == function_ea
    assert captured[0][3] == "gateway"
    ports = captured[0][2]
    assert len(ports) == 1
    assert ports[0].predicate_ea == 0x40A5AB
    assert ports[0].logical_source_anchor_ea == 0x40A5C8
    assert ports[0].resolver_kind == "preopt_entry_bridge"
    assert ports[0].source_owner is DetachedSnippetBoundaryPortOwner.LIVE
    assert decision["microcode_modified"] is True
    assert (
        session.native_preanalysis.bound_preopt_generation
        == state.evidence_generation
    )


def test_owned_preopt_union_does_not_recapture_mutated_entry_bridge(
    monkeypatch,
) -> None:
    from d810.optimizers.microcode.flow.jumps import computed_goto_resolver

    function_ea = 0x40A560
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    assert state.native_preanalysis.merge_preopt_entry_bridge_evidence(
        state.native_key,
        EntryBridgeEvidence(
            predicate_ea=0x40A5AB,
            condition_code=5,
            predicate_stack_identity=(-0x20, 4),
            stack_cell_identity=(0x40, 4),
            taken_state_constant=0xA0716E5B,
            fallthrough_state_constant=0xEC71CA67,
            source_store_ea=0x40A5AE,
            predicate_block_ea=0x40A59D,
            conditional_tail_ea=0x40A5AB,
        ),
    )
    assert state.native_preanalysis.mark_preopt_bound()
    state.preopt_union_imported_mbas.add((function_ea, 77, 0))
    state.bind_current_imported_instruction_origins(77, ())
    captures: list[object] = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "_capture_preopt_entry_bridge_evidence",
        lambda _state, current_mba: captures.append(current_mba) or True,
    )
    mba = SimpleNamespace(entry_ea=function_ea, qty=0)

    rebind_live_preopt_routes(
        function_ea=function_ea,
        mba=mba,
        decision={"session": session},
    )

    assert captures == []
    assert state.evidence_generation == 1
    assert state.native_preanalysis.bound_preopt_generation == 1


def test_materialization_and_transfer_accumulation_are_session_owned() -> None:
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    resolution = object()
    first_transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x401010,
        source_block_ea=0x401000,
        materialized_anchor_eas=(0x401010,),
        target_eas=(0x401100,),
    )
    second_transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x401020,
        source_block_ea=0x401018,
        materialized_anchor_eas=(0x401020,),
        target_eas=(0x401200,),
    )

    state.begin_materialization(resolution)
    assert state.materialization is not None
    assert state.materialization.resolution is resolution
    assert state.native_preanalysis.merge_materialized_transfers(
        state.native_key, (first_transfer,)
    )
    assert state.native_preanalysis.merge_materialized_transfers(
        state.native_key, (first_transfer, second_transfer)
    )
    state.complete_materialization()

    assert state.materialized is True
    assert state.materialization is None
    assert state.materialized_transfers == (first_transfer, second_transfer)
    assert state.native_preanalysis.facts is not None
    assert state.native_preanalysis.facts.transfers == (
        first_transfer,
        second_transfer,
    )
    assert "materialized_transfers" not in ResolverSessionState.__dataclass_fields__


def test_native_cfg_and_boundary_ports_have_one_session_owned_authority() -> None:
    native = NativePreanalysisSessionState()
    state = ResolverSessionState(native_preanalysis=native, native_key=NATIVE_KEY)
    ports = DetachedSnippetBoundaryPorts((), ())

    assert state.native_preanalysis.merge_native_facts(
        state.native_key, native_cfg=NativeCfg({}), boundary_ports=ports
    )
    assert isinstance(native.facts, NativePreanalysisFacts)
    assert state.boundary_ports is native.facts.boundary_ports
    assert "boundary_ports" not in PreoptUnionPreparationResult.__dataclass_fields__


def test_native_entry_corridor_crosses_a_same_ea_split_without_following_a_loop() -> (
    None
):
    """A tail-less Hex-Rays precursor is not a native dispatcher backedge."""
    blocks = {
        0: SimpleNamespace(start_ea=0x401000, succs=(1,), tail=None),
        1: SimpleNamespace(
            start_ea=0x401000,
            succs=(2,),
            tail=SimpleNamespace(ea=0x401004),
        ),
        2: SimpleNamespace(
            start_ea=0x401020,
            succs=(1,),
            tail=SimpleNamespace(ea=0x401024),
        ),
    }
    graph = SimpleNamespace(
        entry_serial=0,
        get_block=lambda serial: blocks.get(int(serial)),
    )

    assert _native_entry_corridor_serials(graph) == (0, 1, 2)


def test_preflight_bootstrap_discovery_uses_the_portable_selector(
    monkeypatch,
) -> None:
    """The native proof needs no dispatcher register or live MBA serial."""
    import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as resolver

    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    state.begin_materialization(
        ComputedGotoResolution(
            function_ea=0x40D200,
            jmp_targets={0x40D37F: (0x40EAA7,)},
            reachable_eas=(),
            arch="x86",
            executed_insns=1,
            seeds_run=0,
            block_entries=(0x40EAA7,),
        )
    )
    state.native_preanalysis.merge_materialized_transfers(
        state.native_key,
        (
            MaterializedIndirectTransfer(
                source_jmp_ea=0x40D37F,
                source_block_ea=0x40D370,
                materialized_anchor_eas=(0x40D37F,),
                target_eas=(0x40EAA7,),
                selector_state_var_reg=28,
                source_register_values=((20, 0xD1978CAF),),
            ),
        ),
    )
    replay_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        resolver,
        "_native_entry_bootstrap_seeds",
        lambda function_ea, selector_mregs: (
            resolver.NativeEntryBootstrapSeed(
                source_anchor_ea=0x40D348,
                direct_target_ea=0x40D370,
                state_mreg=28,
                state_constant=0x699BC698,
            ),
        ),
    )
    monkeypatch.setattr(
        resolver,
        "_resolve_concrete_dispatch_corridor",
        lambda source, **kwargs: replay_calls.append({"source": source, **kwargs})
        or 0x40EAA7,
    )

    assert discover_static_native_bootstrap_routes(0x40D200, state)
    assert replay_calls[0]["source"] == 0x40D348
    assert replay_calls[0]["initial_mregs"][28] == 0x699BC698
    route = next(iter(state.native_preanalysis.bootstrap_routes.values()))
    assert route.source_anchor_ea == 0x40D348
    assert route.handler_anchor_ea == 0x40EAA7


def test_native_entry_bootstrap_scan_crosses_calls_before_selector_assignment(
    monkeypatch,
) -> None:
    """A returned prologue call cannot erase a later callee-saved seed."""
    import ida_ua
    import idaapi
    import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as resolver

    function_ea = 0x40A560
    mnemonics = {
        function_ea: "call",
        function_ea + 5: "mov",
        function_ea + 10: "jmp",
    }

    def decode(instruction, ea: int) -> int:
        destination = instruction.ops[0]
        source = instruction.ops[1]
        destination.type = idaapi.o_void
        source.type = idaapi.o_void
        if ea == function_ea:
            destination.type = idaapi.o_near
            destination.addr = 0x40F830
            return 5
        if ea == function_ea + 5:
            destination.type = idaapi.o_reg
            destination.reg = 3
            source.type = idaapi.o_imm
            source.value = 0xABB95547
            return 5
        if ea == function_ea + 10:
            destination.type = idaapi.o_near
            destination.addr = 0x40A5F0
            return 5
        return 0

    monkeypatch.setattr(ida_ua, "decode_insn", decode)
    monkeypatch.setattr(
        idaapi,
        "print_insn_mnem",
        lambda ea: mnemonics.get(int(ea), ""),
    )
    monkeypatch.setattr(
        resolver,
        "_native_register_mreg",
        lambda name: 20 if name == "ebx" else None,
    )

    assert resolver._native_entry_bootstrap_seeds(
        function_ea,
        frozenset({20}),
    ) == (
        resolver.NativeEntryBootstrapSeed(
            source_anchor_ea=function_ea + 10,
            direct_target_ea=0x40A5F0,
            state_mreg=20,
            state_constant=0xABB95547,
        ),
    )


def test_preflight_bootstrap_discovery_replays_a_proven_dispatcher_entry_target(
    monkeypatch,
) -> None:
    """A known dispatcher entry is navigation, not the state-specific handler."""
    import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as resolver

    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    state.begin_materialization(
        ComputedGotoResolution(
            function_ea=0x40A560,
            jmp_targets={0x40A5E3: (0x40A5F0, 0x40C898)},
            reachable_eas=(),
            arch="x86",
            executed_insns=1,
            seeds_run=0,
            block_entries=(0x40A5F0, 0x40A70E),
        )
    )
    state.native_preanalysis.merge_materialized_transfers(
        state.native_key,
        (
            MaterializedIndirectTransfer(
                source_jmp_ea=0x40A5E3,
                source_block_ea=0x40A5CA,
                materialized_anchor_eas=(0x40A5E3,),
                target_eas=(0x40A5F0, 0x40C898),
                selector_state_var_reg=20,
            ),
            MaterializedIndirectTransfer(
                source_jmp_ea=0x40A5C8,
                source_block_ea=0x40A5C8,
                materialized_anchor_eas=(),
                target_eas=(0x40A70E,),
                selector_state_var_reg=20,
                selector_state_constant=0x357A351E,
                resolver_kind="static_handler_entry_route",
            ),
        ),
    )
    monkeypatch.setattr(
        resolver,
        "_native_entry_bootstrap_seeds",
        lambda function_ea, selector_mregs: (
            resolver.NativeEntryBootstrapSeed(
                source_anchor_ea=0x40A5C8,
                direct_target_ea=0x40A5F0,
                state_mreg=20,
                state_constant=0xABB95547,
            ),
        ),
    )
    replay_calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        resolver,
        "_resolve_concrete_dispatch_corridor",
        lambda *args, **kwargs: replay_calls.append((args, kwargs)) or 0x40A70E,
    )

    assert discover_static_native_bootstrap_routes(0x40A560, state)
    assert len(replay_calls) == 1
    route = next(iter(state.native_preanalysis.bootstrap_routes.values()))
    assert route.source_anchor_ea == 0x40A5C8
    assert route.state == 0xABB95547
    assert route.handler_anchor_ea == 0x40A70E


def test_calls_done_uses_serial_free_native_discovery_as_fallback(monkeypatch) -> None:
    """Direct hook decompiles retain the manager preflight's native proof."""
    import d810.hexrays.mutation.detached_handler_island as island
    import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as resolver

    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    state.begin_materialization(object())
    decision = {"session": session}
    mba = object()
    discovered: list[tuple[int, object]] = []
    redo: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        island, "imported_detached_snippet_instruction_origins", lambda mba: ()
    )
    monkeypatch.setattr(
        resolver, "_keep_static_equality_route_blocks", lambda mba, transfers: 0
    )
    monkeypatch.setattr(
        resolver,
        "_recover_static_equality_route_transfers_from_mba",
        lambda resolution, transfers, mba: (),
    )
    monkeypatch.setattr(
        resolver,
        "_recover_condition_chain_handler_transfers_from_mba",
        lambda transfers, mba: (),
    )
    monkeypatch.setattr(
        resolver,
        "recover_conditional_handler_bridge_transfers_from_mba",
        lambda transfers, mba, imported_predicate_eas: (),
    )
    monkeypatch.setattr(resolver, "_entry_bridge_ready", lambda **_kwargs: False)
    monkeypatch.setattr(
        resolver,
        "_materialize_residual_state_routes_from_mba",
        lambda resolution, transfers, mba: (0, ()),
    )
    monkeypatch.setattr(
        resolver,
        "discover_static_native_bootstrap_routes",
        lambda function_ea, state: discovered.append((function_ea, state)) or True,
    )
    monkeypatch.setattr(
        resolver,
        "request_hexrays_redo",
        lambda decision, reason, **kwargs: redo.append((reason, kwargs)),
    )

    _on_calls_done_preanalysis(
        function_ea=0x401000,
        mba=mba,
        decision=decision,
    )

    assert discovered == [(0x401000, state)]
    assert redo == [
        (
            "computed_goto_bootstrap_route",
            {"function_ea": 0x401000, "evidence_generation": 0},
        )
    ]


def test_calls_done_refreshes_completed_preopt_union_before_requesting_redo(
    monkeypatch,
) -> None:
    """CALLS facts discovered after byte delivery must survive a fresh MBA."""
    import d810.hexrays.mutation.detached_handler_island as island
    import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as resolver

    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    choice = MaterializedIndirectTransfer(
        source_jmp_ea=0x40E20E,
        source_block_ea=0x40E1F6,
        materialized_anchor_eas=(0x40E20E,),
        target_eas=(),
        selector_state_var_reg=28,
        predicate_true_state=0x3AF41FBE,
        predicate_false_state=0x85AE90D3,
        resolver_kind="static_conditional_state_choice",
    )
    handler = MaterializedIndirectTransfer(
        source_jmp_ea=0x40F121,
        source_block_ea=0x40F121,
        materialized_anchor_eas=(),
        target_eas=(0x40F12D,),
        selector_state_var_reg=28,
        selector_state_constant=0x3AF41FBE,
        resolver_kind="condition_chain_handler_evidence",
    )
    bridge = MaterializedIndirectTransfer(
        source_jmp_ea=0x40E20E,
        source_block_ea=0x40E1F6,
        materialized_anchor_eas=(0x40E20E,),
        target_eas=(0x40F12D, 0x40DC04),
        resolver_kind="static_conditional_state_choice_bridge",
    )
    state.native_preanalysis.facts = _native_facts((choice,))
    state.materialized = True
    state.native_preanalysis.evidence_generation = 1
    state.native_preanalysis.bound_preopt_generation = 1
    redo: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        island,
        "imported_detached_snippet_instruction_origins",
        lambda _mba: (),
    )
    monkeypatch.setattr(
        resolver,
        "_recover_condition_chain_handler_transfers_from_mba",
        lambda transfers, mba: (handler,),
    )
    monkeypatch.setattr(
        resolver,
        "recover_conditional_handler_bridge_transfers_from_mba",
        lambda transfers, mba, imported_predicate_eas: (bridge,),
    )
    monkeypatch.setattr(
        resolver,
        "_refresh_preopt_union_from_calls_evidence",
        lambda current_state, mba: current_state is state,
    )
    monkeypatch.setattr(
        resolver,
        "request_hexrays_redo",
        lambda decision, reason, **kwargs: redo.append((reason, kwargs)),
    )

    decision = {"session": session}
    _on_calls_done_preanalysis(
        function_ea=0x40D200,
        mba=object(),
        decision=decision,
    )

    assert frozenset(state.materialized_transfers) == {choice, handler, bridge}
    assert decision["defer_generated_restart"] is True
    assert state.native_preanalysis.has_pending_generated_restart
    assert redo == [
        (
            "computed_goto_calls_evidence",
            {"function_ea": 0x40D200, "evidence_generation": 3},
        )
    ]


def test_calls_done_stages_restart_when_preopt_union_refresh_abstains(
    monkeypatch,
) -> None:
    import d810.hexrays.mutation.detached_handler_island as island
    import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as resolver

    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    existing = MaterializedIndirectTransfer(
        source_jmp_ea=0x40AC95,
        source_block_ea=0x40AC70,
        materialized_anchor_eas=(0x40AC95,),
        target_eas=(0x40AF00, 0x40B03E),
        resolver_kind="static_conditional_state_choice_bridge",
    )
    discovered = MaterializedIndirectTransfer(
        source_jmp_ea=0x40AFB5,
        source_block_ea=0x40AF00,
        materialized_anchor_eas=(0x40AFB5,),
        target_eas=(0x40B03E, 0x40C20C),
        resolver_kind="static_conditional_state_choice_bridge",
    )
    state.native_preanalysis.facts = _native_facts((existing,))
    state.materialized = True
    state.native_preanalysis.evidence_generation = 1
    state.native_preanalysis.bound_preopt_generation = 1
    redo: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        island,
        "imported_detached_snippet_instruction_origins",
        lambda _mba: (),
    )
    monkeypatch.setattr(
        resolver,
        "_recover_condition_chain_handler_transfers_from_mba",
        lambda _transfers, _mba: (discovered,),
    )
    monkeypatch.setattr(
        resolver,
        "recover_conditional_handler_bridge_transfers_from_mba",
        lambda _transfers, _mba, imported_predicate_eas: (),
    )
    monkeypatch.setattr(
        resolver,
        "_refresh_preopt_union_from_calls_evidence",
        lambda _state, _mba: False,
    )
    monkeypatch.setattr(
        resolver,
        "request_hexrays_redo",
        lambda decision, reason, **kwargs: redo.append((reason, kwargs)),
    )
    decision = {"session": session}

    _on_calls_done_preanalysis(
        function_ea=0x40A560,
        mba=object(),
        decision=decision,
    )

    assert decision["defer_generated_restart"] is True
    assert state.native_preanalysis.has_pending_generated_restart
    assert redo == [
        (
            "computed_goto_calls_evidence",
            {"function_ea": 0x40A560, "evidence_generation": 2},
        )
    ]


@pytest.mark.parametrize(
    "preopt_refresh_outcome",
    (True, False, "raise"),
)
def test_calls_done_retains_changed_evidence_during_active_materialization(
    monkeypatch, preopt_refresh_outcome: bool | str
) -> None:
    import d810.hexrays.mutation.detached_handler_island as island
    import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as resolver

    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    existing = MaterializedIndirectTransfer(
        source_jmp_ea=0x40AC95,
        source_block_ea=0x40AC70,
        materialized_anchor_eas=(0x40AC95,),
        target_eas=(0x40AF00, 0x40B03E),
        resolver_kind="static_conditional_state_choice_bridge",
    )
    discovered = MaterializedIndirectTransfer(
        source_jmp_ea=0x40AFB5,
        source_block_ea=0x40AF00,
        materialized_anchor_eas=(0x40AFB5,),
        target_eas=(0x40B03E, 0x40C20C),
        resolver_kind="static_conditional_state_choice_bridge",
    )
    state.native_preanalysis.facts = _native_facts((existing,))
    state.native_preanalysis.evidence_generation = 1
    state.native_preanalysis.bound_preopt_generation = 1
    state.begin_materialization(object())
    redo: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        island,
        "imported_detached_snippet_instruction_origins",
        lambda _mba: (),
    )
    monkeypatch.setattr(
        resolver,
        "_keep_static_equality_route_blocks",
        lambda _mba, _transfers: 0,
    )
    monkeypatch.setattr(
        resolver,
        "_recover_static_equality_route_transfers_from_mba",
        lambda _resolution, _transfers, _mba: (),
    )
    monkeypatch.setattr(
        resolver,
        "_recover_condition_chain_handler_transfers_from_mba",
        lambda _transfers, _mba: (discovered,),
    )
    monkeypatch.setattr(
        resolver,
        "recover_conditional_handler_bridge_transfers_from_mba",
        lambda _transfers, _mba, imported_predicate_eas: (),
    )
    monkeypatch.setattr(
        resolver,
        "discover_static_native_bootstrap_routes",
        lambda _function_ea, _state: False,
    )
    monkeypatch.setattr(resolver, "_entry_bridge_ready", lambda **_kwargs: False)
    monkeypatch.setattr(
        resolver,
        "_materialize_residual_state_routes_from_mba",
        lambda _resolution, _transfers, _mba: (0, ()),
    )
    def refresh_preopt(_state, _mba):
        if preopt_refresh_outcome == "raise":
            raise RuntimeError("refresh failed")
        return preopt_refresh_outcome

    monkeypatch.setattr(
        resolver,
        "_refresh_preopt_union_from_calls_evidence",
        refresh_preopt,
    )
    monkeypatch.setattr(
        resolver,
        "request_hexrays_redo",
        lambda decision, reason, **kwargs: redo.append((reason, kwargs)),
    )
    decision = {"session": session}

    _on_calls_done_preanalysis(
        function_ea=0x40A560,
        mba=object(),
        decision=decision,
    )

    assert frozenset(state.materialized_transfers) == {existing, discovered}
    assert decision["defer_generated_restart"] is True
    assert state.native_preanalysis.has_pending_generated_restart
    assert redo == [
        (
            "computed_goto_calls_evidence",
            {
                "function_ea": 0x40A560,
                "materialized_count": 0,
                "round": 1,
            },
        )
    ]


def test_terminal_requests_and_live_bindings_are_released_with_the_session() -> None:
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    request = TerminalReturnCarrierRequest(
        source_handler_ea=0x401000,
        terminal_target_ea=0x401100,
        state_var_reg=20,
        state_constant=0x12345678,
    )

    assert state.native_preanalysis.merge_terminal_return_carrier_requests(
        state.native_key,
        (request,),
    )
    state.identity_index = object()
    assert state.begin_snippet_capture(0x401000)

    state.release_live_bindings()

    assert state.native_preanalysis.resolver_evidence is not None
    assert (
        state.native_preanalysis.resolver_evidence.terminal_return_carrier_requests
        == (request,)
    )
    assert state.identity_index is None
    assert state.materialization is None
    assert not state.snippet_capture_active
