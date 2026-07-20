"""Runtime-layer tests for session-owned computed-goto evidence."""

from __future__ import annotations

import importlib.util
from dataclasses import replace
from types import SimpleNamespace

from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    TerminalReturnCarrierRequest,
)
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.mba_mutation_events import (
    MbaMutationGateway,
    StructuralMutationKind,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
    BootstrapRouteBindingEvidence,
    BootstrapRouteEvidence,
    BootstrapRouteProofKind,
    ResolverSessionState,
    resolver_session_state,
)
from d810.optimizers.microcode.flow.jumps.computed_goto_resolver import (
    ComputedGotoResolution,
    PreoptUnionPreparationResult,
    _native_entry_corridor_serials,
    _on_calls_done_preanalysis,
    _on_flowchart_preanalysis,
    _on_preopt_bootstrap_route,
    discover_static_native_bootstrap_routes,
)


def test_resolver_session_state_has_a_dedicated_module() -> None:
    assert (
        importlib.util.find_spec(
            "d810.optimizers.microcode.flow.jumps.resolver_session_state"
        )
        is not None
    )


def test_resolver_session_state_uses_a_reload_stable_extension_key() -> None:
    """A hot-reloaded resolver module must recover the preflight attachment."""
    native_preanalysis = NativePreanalysisSessionState()
    original = ResolverSessionState(native_preanalysis=native_preanalysis)
    session = SimpleNamespace(
        native_preanalysis=native_preanalysis,
        extensions={
            "d810.optimizers.microcode.flow.jumps.resolver_session_state": original
        },
    )

    assert resolver_session_state(session) is original
    assert session.extensions == {
        "d810.optimizers.microcode.flow.jumps.resolver_session_state": original
    }


def test_call_result_carriers_are_owned_and_released_by_the_session() -> None:
    state = ResolverSessionState(
        native_preanalysis=NativePreanalysisSessionState(),
    )
    first = object()
    second = object()

    state.cache_call_result_carriers((first, second))

    assert state.call_result_carriers == (first, second)
    state.release_live_bindings()
    assert state.call_result_carriers == ()


def test_portable_dispatcher_region_merges_without_snapshot_serials() -> None:
    state = ResolverSessionState(
        native_preanalysis=NativePreanalysisSessionState(),
    )
    first = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),)
    )
    second = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAB1, 0x40EAB2),)
    )

    assert state.merge_portable_dispatcher_region_identity(first)
    assert state.evidence_generation == 1
    assert not state.merge_portable_dispatcher_region_identity(first)
    assert state.merge_portable_dispatcher_region_identity(second)
    assert state.evidence_generation == 1
    assert state.portable_dispatcher_region_identity == StableBlockIdentity.from_intervals(
        (
            NativeEaInterval(0x40EAA7, 0x40EAA8),
            NativeEaInterval(0x40EAB1, 0x40EAB2),
        )
    )


def test_session_evidence_rebinds_once_in_its_new_generation() -> None:
    source = StableBlockIdentity.from_intervals((NativeEaInterval(0x40D348, 0x40D349),))
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),)
    )
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        extensions={},
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

    assert state.merge_bootstrap_route(evidence)
    assert session.native_preanalysis.evidence_generation == 1
    assert state.request_controlled_redo()
    assert not state.request_controlled_redo()

    state.bind_current_mba(
        MbaBlockIdentityIndex.from_bindings(
            generation=1,
            bindings=((source, 17), (handler, 42)),
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
        extensions={},
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

    assert state.request_generated_restart()
    assert not state.request_generated_restart()
    # Evidence discovered later in the same decompile (for example terminal
    # return-carrier requests during GLBOPT) belongs to the already-staged
    # controller retry.  It must advance that pending generation rather than
    # silently cancelling the restart before the controller regains control.
    state.native_preanalysis.mark_evidence_changed()
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
        extensions={},
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
    state.materialized_transfers = (before, bridge, after)

    assert not state.merge_materialized_transfers((bridge,))
    assert state.materialized_transfers == (before, bridge, after)
    assert state.evidence_generation == 4


def test_weaker_conditional_bridge_refresh_cannot_erase_arm_state_evidence() -> None:
    """A regenerated MBA may retain topology after losing the arm constants."""
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(
            evidence_generation=4,
            bound_preopt_generation=4,
        ),
        extensions={},
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
    state.materialized_transfers = (exact,)

    assert not state.merge_materialized_transfers((weaker_refresh,))
    assert state.materialized_transfers == (exact,)
    assert state.evidence_generation == 4


def test_weaker_conditional_bridge_refresh_cannot_inherit_states_across_sources() -> None:
    """A predicate anchor does not authorize transplanting proof provenance."""
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(
            evidence_generation=4,
            bound_preopt_generation=4,
        ),
        extensions={},
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
    state.materialized_transfers = (exact,)

    assert state.merge_materialized_transfers((regenerated,))
    assert state.materialized_transfers == (exact, regenerated)
    assert state.materialized_transfers[1].predicate_true_state is None
    assert state.materialized_transfers[1].predicate_false_state is None
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
        extensions={},
    )
    state = resolver_session_state(session)
    state.materialized = True
    assert state.request_generated_restart()
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
    source = StableBlockIdentity.from_intervals((NativeEaInterval(0x40D348, 0x40D349),))
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),)
    )
    state = ResolverSessionState(
        native_preanalysis=NativePreanalysisSessionState(),
    )
    route = BootstrapRouteEvidence(
        source_identity=source,
        source_anchor_ea=0x40D348,
        state=0x699BC698,
        handler_identity=handler,
        handler_anchor_ea=0x40EAA7,
        proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
    )

    assert state.merge_bootstrap_route(route)
    assert state.bound_bootstrap_routes() == ()

    state.bind_current_mba(
        MbaBlockIdentityIndex.from_bindings(
            generation=0,
            evidence_generation=1,
            bindings=((source, 17), (handler, 42)),
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
            (NativeEaInterval(0x40D313, 0x40D34A),)
        ),
        handler_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x40EAA1, 0x40EAB7),)
        ),
        evidence_generation=1,
    )
    assert state.record_bootstrap_route_binding(binding)

    assert state.native_preanalysis.mark_preopt_bound()
    assert state.bound_bootstrap_routes() == (route,)
    assert state.bound_bootstrap_route_bindings() == (binding,)

    # Later CALLS facts may advance the shared evidence epoch without
    # regenerating the already-routed MBA.  The route remains tied to the
    # generation that actually bound this live MBA.
    state.native_preanalysis.mark_evidence_changed()
    assert state.evidence_generation == 2
    assert state.bound_bootstrap_routes() == (route,)
    assert state.bound_bootstrap_route_bindings() == (binding,)


def test_preflight_discovery_discards_pre_redo_serials() -> None:
    """Native preflight names anchors; only PREOPT provides live serials."""
    source = StableBlockIdentity.from_intervals((NativeEaInterval(0x40D348, 0x40D349),))
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),)
    )
    state = resolver_session_state(
        SimpleNamespace(
            native_preanalysis=NativePreanalysisSessionState(),
            extensions={},
        )
    )

    assert state.discover_static_native_bootstrap_route(
        source_anchor_ea=0x40D348,
        state_constant=0x699BC698,
        handler_anchor_ea=0x40EAA7,
    )
    assert state.evidence_generation == 1
    assert state.request_controlled_redo()

    state.bind_current_mba(
        MbaBlockIdentityIndex.from_bindings(
            generation=1,
            bindings=((source, 170), (handler, 420)),
        )
    )
    rebound = state.rebind_bootstrap_route(
        source_identity=source,
        state=0x699BC698,
    )
    assert rebound is not None
    assert (rebound.source.serial, rebound.handler.serial) == (170, 420)


def test_preflight_discovery_names_both_anchors_without_a_live_mba() -> None:
    source = StableBlockIdentity.from_intervals((NativeEaInterval(0x401020, 0x401021),))
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401100, 0x401101),)
    )
    state = resolver_session_state(
        SimpleNamespace(
            native_preanalysis=NativePreanalysisSessionState(),
            extensions={},
        )
    )

    assert state.discover_static_native_bootstrap_route(
        source_anchor_ea=0x401020,
        state_constant=0x12345678,
        handler_anchor_ea=0x401100,
    )
    assert state.request_controlled_redo()

    state.bind_current_mba(
        MbaBlockIdentityIndex.from_bindings(
            generation=0,
            evidence_generation=1,
            bindings=((source, 170), (handler, 420)),
        )
    )
    rebound = state.rebind_bootstrap_route(
        source_identity=source,
        state=0x12345678,
    )

    assert rebound is not None
    assert (rebound.source.serial, rebound.handler.serial) == (170, 420)


def test_rebinding_survives_mutation_lineage_without_changing_evidence_epoch() -> None:
    source = StableBlockIdentity.from_intervals((NativeEaInterval(0x40D348, 0x40D349),))
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),)
    )
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(evidence_generation=1),
        extensions={},
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
    )
    state.bind_current_mba(index)

    gateway = MbaMutationGateway(
        generation=0,
        session_id="identity-index",
        identity_index=index,
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
        (NativeEaInterval(0x40D348, 0x40D349),)
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),)
    )
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(evidence_generation=1),
        extensions={},
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
    )
    index.begin_transaction(10)
    imported = index.create_imported_native_handle(handler)
    index.record_insert(
        insertion_serial=10,
        created=imported,
        returned_serial=10,
    )
    state.bind_current_mba(index)

    assert state.rebind_bootstrap_route(
        source_identity=source,
        state=0x699BC698,
    ) is None
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

    source = StableBlockIdentity.from_intervals((NativeEaInterval(0x401020, 0x401021),))
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401100, 0x401101),)
    )
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        extensions={},
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
    assert state.merge_bootstrap_route(route)
    state.bind_current_mba(
        MbaBlockIdentityIndex.from_bindings(
            generation=0,
            evidence_generation=1,
            bindings=((source, 7), (handler, 9)),
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
    state.preopt_union_preparation = PreoptUnionPreparationResult(
        function_ea=0x401000,
        prepared=True,
        published=True,
        primary_seed_ea=0x401080,
        boundary_ports=SimpleNamespace(direct=(), conditional=()),
    )
    decision = {
        "session": session,
        "mutation_gateway": "gateway",
        "details": {"preopt_union_root_ea": 0x401080},
    }

    state.preopt_union_import_active = True
    _on_preopt_bootstrap_route(
        function_ea=0x401000,
        mba=_Mba(),
        decision=decision,
    )
    assert queued == []
    assert session.native_preanalysis.bound_preopt_generation is None
    state.preopt_union_import_active = False

    _on_preopt_bootstrap_route(
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

    source = StableBlockIdentity.from_intervals((NativeEaInterval(0x40D348, 0x40D349),))
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),)
    )
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        extensions={},
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
    assert state.merge_bootstrap_route(route)
    state.bind_current_mba(
        MbaBlockIdentityIndex.from_bindings(
            generation=0,
            evidence_generation=1,
            bindings=((source, 29), (handler, 42)),
        )
    )

    class _Block:
        def __init__(self, serial: int, *, tail: object | None = None) -> None:
            self.serial = int(serial)
            self.start = 0x40D313 if serial == 29 else 0x40EAA7
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

        def restore_pruned_direct_now(
            self,
            source_block: object,
            target_block: object,
        ) -> bool:
            queued.append((int(source_block.serial), int(target_block.serial)))
            return True

    monkeypatch.setattr(modifier_module, "DeferredGraphModifier", _Modifier)
    decision = {"session": session, "mutation_gateway": "gateway"}

    _on_preopt_bootstrap_route(
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
        (NativeEaInterval(predicate_ea, predicate_ea + 1),)
    )
    target_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(true_target_ea, true_target_ea + 1),)
    )
    false_target_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40DC04, 0x40DC05),)
    )
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        extensions={},
    )
    state = resolver_session_state(session)
    assert state.merge_materialized_transfers(
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
        )
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

    _on_preopt_bootstrap_route(
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
        (NativeEaInterval(predicate_ea, predicate_ea + 1),)
    )
    taken_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(taken_target_ea, taken_target_ea + 1),)
    )
    fallthrough_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(fallthrough_target_ea, fallthrough_target_ea + 1),)
    )
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        extensions={},
    )
    state = resolver_session_state(session)
    assert state.merge_materialized_transfers(
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
        )
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

    _on_preopt_bootstrap_route(
        function_ea=0x40D200,
        mba=_Mba(),
        decision=decision,
    )

    assert queued == [(7, predicate_ea, 9, 11)]
    assert decision["microcode_modified"] is True
    assert session.native_preanalysis.bound_preopt_generation == 1

    state.preopt_union_preparation = PreoptUnionPreparationResult(
        function_ea=0x40D200,
        prepared=True,
        published=True,
        primary_seed_ea=taken_target_ea,
        boundary_ports=SimpleNamespace(
            direct=(),
            conditional=(
                SimpleNamespace(
                    predicate_ea=predicate_ea,
                    taken_target_ea=taken_target_ea,
                    fallthrough_target_ea=fallthrough_target_ea,
                ),
            ),
        ),
    )
    state.native_preanalysis.mark_evidence_changed()
    _on_preopt_bootstrap_route(
        function_ea=0x40D200,
        mba=_Mba(),
        decision={
            "session": session,
            "mutation_gateway": "gateway",
        },
    )

    assert queued == [(7, predicate_ea, 9, 11)]
    assert session.native_preanalysis.bound_preopt_generation == 1

    _on_preopt_bootstrap_route(
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


def test_materialization_and_transfer_accumulation_are_session_owned() -> None:
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        extensions={},
    )
    state = resolver_session_state(session)
    resolution = object()
    first_transfer = object()
    second_transfer = object()

    state.begin_materialization(resolution)
    assert state.materialization is not None
    assert state.materialization.resolution is resolution
    assert state.merge_materialized_transfers((first_transfer,))
    assert state.merge_materialized_transfers((first_transfer, second_transfer))
    state.complete_materialization()

    assert state.materialized is True
    assert state.materialization is None
    assert state.materialized_transfers == (first_transfer, second_transfer)


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
        native_preanalysis=NativePreanalysisSessionState(), extensions={}
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
    state.merge_materialized_transfers(
        (
            MaterializedIndirectTransfer(
                source_jmp_ea=0x40D37F,
                source_block_ea=0x40D370,
                materialized_anchor_eas=(0x40D37F,),
                target_eas=(0x40EAA7,),
                selector_state_var_reg=28,
                source_register_values=((20, 0xD1978CAF),),
            ),
        )
    )
    replay_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        resolver,
        "_native_entry_bootstrap_seeds",
        lambda function_ea, selector_mregs: ((0x40D348, 28, 0x699BC698),),
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


def test_calls_done_uses_serial_free_native_discovery_as_fallback(monkeypatch) -> None:
    """Direct hook decompiles retain the manager preflight's native proof."""
    import d810.hexrays.mutation.detached_handler_island as island
    import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as resolver

    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        extensions={},
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
        extensions={},
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
    state.materialized_transfers = (choice,)
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

    assert state.materialized_transfers == (choice, handler, bridge)
    assert decision["defer_generated_restart"] is True
    assert state.native_preanalysis.has_pending_generated_restart
    assert redo == [
        (
            "computed_goto_preopt_template_refreshed",
            {"function_ea": 0x40D200, "evidence_generation": 3},
        )
    ]


def test_terminal_requests_and_live_bindings_are_released_with_the_session() -> None:
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        extensions={},
    )
    state = resolver_session_state(session)
    request = TerminalReturnCarrierRequest(
        source_handler_ea=0x401000,
        terminal_target_ea=0x401100,
        state_var_reg=20,
        state_constant=0x12345678,
    )

    assert state.merge_terminal_return_carrier_requests((request,))
    state.identity_index = object()
    assert state.begin_snippet_capture(0x401000)

    state.release_live_bindings()

    assert state.terminal_return_carrier_requests == (request,)
    assert state.identity_index is None
    assert state.materialization is None
    assert not state.snippet_capture_active
