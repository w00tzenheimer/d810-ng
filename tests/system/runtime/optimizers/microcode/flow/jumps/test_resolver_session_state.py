"""Runtime-layer tests for session-owned computed-goto evidence."""

from __future__ import annotations

import importlib.util
from dataclasses import replace
from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.detached_handler_island import (
    DetachedSnippetBoundaryPorts,
)
from d810.analyses.control_flow.call_abi import (
    StackCallAbiEvidence,
    StackCallAbiProof,
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
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.mba_mutation_events import (
    MbaMutationGateway,
    StructuralMutationKind,
)
from d810.ir.block_identity import (
    MbaBlockHandle,
    NativeEaInterval,
    StableBlockIdentity,
)
from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
    ResolverSessionState,
    resolver_session_state,
)
from d810.optimizers.microcode.flow.jumps.computed_goto_resolver import (
    _native_entry_corridor_serials,
    _on_build_callinfo,
    _on_calls_done_preanalysis,
    _on_flowchart_preanalysis,
    discover_static_native_bootstrap_routes,
)
from tests.native_preanalysis import make_native_key

NATIVE_KEY = make_native_key()


def _publish_normalization(state: NativePreanalysisSessionState) -> None:
    assert state._fragment_publication_mark_normalization_staged()
    assert state._fragment_publication_mark_normalization_validated()
    assert state._fragment_publication_mark_normalization_published_and_postvalidated()


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


def test_imported_root_handles_are_current_mba_owned_and_serial_free() -> None:
    state = ResolverSessionState(
        native_preanalysis=NativePreanalysisSessionState(), native_key=NATIVE_KEY
    )
    target_ea = 0x40BECC
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(target_ea, target_ea + 0x10),),
        native_key=NATIVE_KEY,
    )
    handle = MbaBlockHandle.imported_native(
        identity,
        session_id="resolver-test",
        token="imported-root",
    )

    assert state.bind_current_imported_instruction_origins(0x1234, ())
    state.bind_current_imported_root_handles(
        0x1234,
        ((target_ea, handle),),
    )

    assert state.imported_root_handles_for(0x1234) == ((target_ea, handle),)
    assert state.imported_root_handles_for(0x5678) == ()
    assert not hasattr(handle, "serial")

    assert state.bind_current_imported_instruction_origins(0x5678, ())
    assert state.current_imported_root_handles == ()


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
            normalization_staged_generation=2,
            normalization_validated_generation=2,
            normalization_published_postvalidated_generation=2,
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


def test_callinfo_transfer_stages_one_controller_restart_and_rebinds_next_generation(
    monkeypatch,
) -> None:
    import ida_hexrays
    import ida_nalt

    import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as resolver

    function_ea = 0x40A560
    call_ea = 0x40B943
    existing_reentry_ea = 0x40B970
    discovered_reentry_ea = 0x40B956
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={existing_reentry_ea: (0x40B980,)},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    discovered = MaterializedIndirectTransfer(
        source_jmp_ea=discovered_reentry_ea,
        source_block_ea=0x40B940,
        materialized_anchor_eas=(discovered_reentry_ea,),
        target_eas=(0x40B980,),
        resolver_kind="detached_static_fixpoint",
    )
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        resolver_attachment=None,
        native_key=NATIVE_KEY,
    )
    state = resolver_session_state(session)
    lifecycle = state.native_preanalysis
    assert lifecycle.set_computed_goto_resolution(NATIVE_KEY, resolution)
    assert lifecycle.merge_facts(NATIVE_KEY, _native_facts())
    assert lifecycle.evidence_generation == 1
    _publish_normalization(lifecycle)

    transitions: list[str] = []
    lifecycle.event_observer = lambda transition: transitions.append(
        transition.operation
    )
    redo: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(resolver, "_copy_mcallinfo", None)
    monkeypatch.setattr(
        resolver,
        "imported_detached_snippet_instruction_origins",
        lambda _mba: (),
    )
    monkeypatch.setattr(ida_nalt, "get_op_tinfo", lambda *_args: False)
    monkeypatch.setattr(
        resolver,
        "_detached_static_terminal_transfers",
        lambda _resolution, entry_eas, *, entry_context_transfers=(): (
            (discovered,)
            if entry_eas == (0x40B940,) and entry_context_transfers == ()
            else ()
        ),
    )
    observed_reentries: list[frozenset[int]] = []

    def no_stack_adjustment(_call_ea, reentry_eas):
        observed_reentries.append(reentry_eas)
        return True if discovered_reentry_ea in reentry_eas else None

    monkeypatch.setattr(
        resolver,
        "native_corridor_has_no_stack_adjustment",
        no_stack_adjustment,
    )
    monkeypatch.setattr(
        resolver,
        "native_call_stack_deficit",
        lambda _block, _call_ea: 12,
    )
    monkeypatch.setattr(
        resolver,
        "collect_three_argument_callee_purged_evidence",
        lambda _block, **_kwargs: StackCallAbiEvidence(
            word_size=4,
            outgoing_stack_offsets=(-12, -8, -4),
            call_stack_deficit=12,
            argument_values_proven=True,
            continuation_is_linear=True,
            continuation_reaches_proven_reentry=True,
            caller_stack_adjustment=0,
            has_authoritative_type=False,
        ),
    )
    proof = StackCallAbiProof(3, 12)
    monkeypatch.setattr(
        resolver,
        "prove_three_argument_callee_purged_call",
        lambda _evidence: proof,
    )
    monkeypatch.setattr(
        resolver,
        "apply_three_argument_stdcall_type",
        lambda _call_type, candidate: candidate == proof,
    )
    prepared_callinfo = object()
    monkeypatch.setattr(
        resolver,
        "build_three_argument_stdcall_callinfo",
        lambda _block, _call_type, _proof: prepared_callinfo,
    )
    monkeypatch.setattr(
        resolver,
        "request_hexrays_redo",
        lambda decision, reason, **details: (
            decision.__setitem__("request_redo", True),
            redo.append((reason, details)),
        ),
    )
    block = SimpleNamespace(
        mba=SimpleNamespace(qty=0),
        start=0x40B940,
        tail=SimpleNamespace(opcode=ida_hexrays.m_icall, ea=call_ea),
    )
    decision: dict[str, object] = {"callinfo": None, "session": session}

    _on_build_callinfo(
        function_ea=function_ea,
        block=block,
        call_type=object(),
        decision=decision,
    )

    assert observed_reentries == [
        frozenset({existing_reentry_ea}),
        frozenset({discovered_reentry_ea, existing_reentry_ea}),
    ]
    assert state.materialized_transfers == (discovered,)
    assert decision["callinfo"] is prepared_callinfo
    assert lifecycle.evidence_generation == 2
    assert lifecycle.has_pending_generated_restart
    assert transitions == [
        "evidence_changed",
        "generated_restart_requested",
    ]

    flowchart_decision = {"session": session, "request_redo": False}
    _on_flowchart_preanalysis(
        function_ea=function_ea,
        mba=object(),
        decision=flowchart_decision,
    )

    assert flowchart_decision["request_redo"] is True
    assert redo == [
        (
            "computed_goto_calls_evidence_rebind",
            {"function_ea": function_ea, "evidence_generation": 2},
        )
    ]
    assert transitions == [
        "evidence_changed",
        "generated_restart_requested",
        "generated_restart_consumed",
    ]
    assert not lifecycle.has_pending_generated_restart

    _publish_normalization(lifecycle)
    assert lifecycle.normalization_published_postvalidated_generation == 2


def test_replaying_identical_conditional_bridge_is_an_evidence_noop() -> None:
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(
            evidence_generation=4,
            normalization_staged_generation=4,
            normalization_validated_generation=4,
            normalization_published_postvalidated_generation=4,
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
            normalization_staged_generation=4,
            normalization_validated_generation=4,
            normalization_published_postvalidated_generation=4,
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
            normalization_staged_generation=4,
            normalization_validated_generation=4,
            normalization_published_postvalidated_generation=4,
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
            normalization_staged_generation=4,
            normalization_validated_generation=4,
            normalization_published_postvalidated_generation=4,
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

    _publish_normalization(state.native_preanalysis)
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
    index.begin_transaction("imported-handler-clone", 10)
    imported = index.create_imported_native_handle(handler)
    index.record_insert(
        transaction_id="imported-handler-clone",
        insertion_serial=10,
        created=imported,
        returned_serial=10,
    )
    index.commit_proxy_transaction("imported-handler-clone")
    index.advance_generation()
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
    state.native_preanalysis.normalization_published_postvalidated_generation = 1
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
    state.native_preanalysis.normalization_published_postvalidated_generation = 1
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
    state.native_preanalysis.normalization_published_postvalidated_generation = 1
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
