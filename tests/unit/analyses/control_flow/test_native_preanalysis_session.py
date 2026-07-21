"""Portable evidence ownership for one top-level decompilation."""

from __future__ import annotations

import importlib

import pytest

from d810.analyses.control_flow.call_abi import StackCallAbiProof
from d810.analyses.control_flow.detached_handler_island import (
    DetachedSnippetBoundaryPorts,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    PortableMaterializedStateRoute,
    TerminalReturnCarrierRequest,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    BootstrapRouteBindingEvidence,
    BootstrapRouteEvidence,
    BootstrapRouteProofKind,
    ComputedGotoResolution,
    PreoptUnionPreparationResult,
    PrepatchPreoptUnionSource,
    NativePreanalysisSessionState,
)
from d810.analyses.control_flow.native_semantic_closure import (
    NativeCfg,
    NativeSemanticClosure,
)
from d810.core.native_preanalysis_key import NativePreanalysisKeyMismatch
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from tests.native_preanalysis import make_native_key

NATIVE_KEY = make_native_key()


def test_changed_route_evidence_advances_once_and_binds_once() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),), native_key=NATIVE_KEY
    )
    state = NativePreanalysisSessionState()
    route = BootstrapRouteEvidence(
        source_identity=source,
        source_anchor_ea=0x40D348,
        state=0x699BC698,
        handler_identity=handler,
        handler_anchor_ea=0x40EAA7,
        proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
    )

    assert state.merge_bootstrap_route(route)
    assert state.evidence_generation == 1
    assert not state.merge_bootstrap_route(route)
    assert state.evidence_generation == 1
    assert state.request_controlled_redo()
    assert not state.request_controlled_redo()
    assert state.needs_preopt_binding()
    state.mark_preopt_bound()
    assert not state.needs_preopt_binding()
    assert state.bound_preopt_generation == 1


def test_first_pass_native_evidence_coalesces_until_preopt_binds() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401020, 0x401021),), native_key=NATIVE_KEY
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401100, 0x401101),), native_key=NATIVE_KEY
    )
    state = NativePreanalysisSessionState()

    state.mark_evidence_changed()
    assert state.evidence_generation == 1
    assert state.merge_bootstrap_route(
        BootstrapRouteEvidence(
            source_identity=source,
            source_anchor_ea=0x401020,
            state=0x12345678,
            handler_identity=handler,
            handler_anchor_ea=0x401100,
            proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
        )
    )
    assert state.evidence_generation == 1

    assert state.mark_preopt_bound()
    state.mark_evidence_changed()
    assert state.evidence_generation == 2


def test_rebound_bootstrap_route_is_acknowledged_only_after_publication() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401020, 0x401021),), native_key=NATIVE_KEY
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401100, 0x401101),), native_key=NATIVE_KEY
    )
    route = BootstrapRouteEvidence(
        source_identity=source,
        source_anchor_ea=0x401020,
        state=0x12345678,
        handler_identity=handler,
        handler_anchor_ea=0x401100,
        proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
    )
    state = NativePreanalysisSessionState()
    assert state.merge_bootstrap_route(route)
    assert state.mark_bootstrap_route_rebound(route)
    assert state.pending_rebound_bootstrap_routes() == (route,)
    state.mark_rebound_bootstrap_routes_published((route,))
    assert state.pending_rebound_bootstrap_routes() == ()


def test_lifecycle_owns_serial_free_bootstrap_binding_evidence() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401020, 0x401021),), native_key=NATIVE_KEY
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401100, 0x401101),), native_key=NATIVE_KEY
    )
    route = BootstrapRouteEvidence(
        source_identity=source,
        source_anchor_ea=0x401020,
        state=0x12345678,
        handler_identity=handler,
        handler_anchor_ea=0x401100,
        proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
    )
    state = NativePreanalysisSessionState()
    assert state.merge_bootstrap_route(route)
    assert state.mark_bootstrap_route_rebound(route)
    binding = BootstrapRouteBindingEvidence(
        route=route,
        source_identity=source,
        handler_identity=handler,
        evidence_generation=state.evidence_generation,
    )

    assert state.record_bootstrap_route_binding(NATIVE_KEY, binding)
    assert state.mark_preopt_bound()
    assert state.bound_bootstrap_route_bindings(NATIVE_KEY) == (binding,)


def test_lifecycle_owns_typed_resolver_evidence_and_coalesces_first_generation() -> (
    None
):
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),), native_key=NATIVE_KEY
    )
    target = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x402000, 0x402010),), native_key=NATIVE_KEY
    )
    route = PortableMaterializedStateRoute(
        source_identity=source,
        state_constant=0x1234,
        target_identity=target,
    )
    terminal_request = TerminalReturnCarrierRequest(
        source_handler_ea=0x401000,
        terminal_target_ea=0x403000,
        state_var_reg=8,
        state_constant=0x1234,
    )
    proof = StackCallAbiProof(argument_count=3, stack_argument_bytes=12)
    state = NativePreanalysisSessionState()

    assert state.merge_portable_state_routes(NATIVE_KEY, (route,))
    assert state.merge_portable_dispatcher_region_identity(NATIVE_KEY, source)
    assert state.merge_terminal_return_carrier_requests(
        NATIVE_KEY,
        (terminal_request,),
    )
    assert state.merge_call_abi_proof(
        NATIVE_KEY,
        call_ea=0x401004,
        proof=proof,
    )

    evidence = state.resolver_evidence
    assert evidence is not None
    assert evidence.key == NATIVE_KEY
    assert evidence.state_routes == (route,)
    assert evidence.dispatcher_region_identity == source
    assert evidence.terminal_return_carrier_requests == (terminal_request,)
    assert evidence.call_abi_proofs == ((0x401004, proof),)
    assert state.evidence_generation == 1

    assert not state.merge_portable_state_routes(NATIVE_KEY, (route,))
    assert not state.merge_call_abi_proof(
        NATIVE_KEY,
        call_ea=0x401004,
        proof=proof,
    )
    assert state.evidence_generation == 1


def test_lifecycle_rejects_resolver_evidence_for_another_native_key() -> None:
    state = NativePreanalysisSessionState()
    other_key = make_native_key(profile_fingerprint="sha256:other-profile")
    proof = StackCallAbiProof(argument_count=3, stack_argument_bytes=12)

    assert state.merge_call_abi_proof(
        NATIVE_KEY,
        call_ea=0x401004,
        proof=proof,
    )
    assert state.evidence_generation == 0
    with pytest.raises(NativePreanalysisKeyMismatch):
        state.merge_call_abi_proof(
            other_key,
            call_ea=0x401004,
            proof=proof,
        )


def test_lifecycle_rejects_cross_key_portable_route_identity() -> None:
    other_key = make_native_key(profile_fingerprint="sha256:other-profile")
    route = PortableMaterializedStateRoute(
        source_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x401000, 0x401010),),
            native_key=other_key,
        ),
        state_constant=0x1234,
        target_identity=None,
    )

    with pytest.raises(NativePreanalysisKeyMismatch):
        NativePreanalysisSessionState().merge_portable_state_routes(
            NATIVE_KEY,
            (route,),
        )


def test_lifecycle_owns_portable_call_result_carriers() -> None:
    module = importlib.import_module(
        "d810.analyses.control_flow.native_preanalysis_session"
    )
    assert hasattr(module, "CallResultCarrier")
    carrier = module.CallResultCarrier(
        call_ea=0x401004,
        carrier_ea=0x401006,
        branch_ea=0x401008,
        callee_ea=0x404000,
        carrier_ida_stkoff=-4,
        value_size=4,
        branch_opcode=1,
    )
    state = NativePreanalysisSessionState()

    assert state.merge_call_result_carriers(NATIVE_KEY, (carrier,))
    assert not state.merge_call_result_carriers(NATIVE_KEY, (carrier,))
    assert state.resolver_evidence is not None
    assert state.resolver_evidence.call_result_carriers == (carrier,)


def test_lifecycle_owns_portable_resolution_and_union_evidence() -> None:
    state = NativePreanalysisSessionState()
    resolution = ComputedGotoResolution(
        function_ea=0x401000,
        jmp_targets={0x401010: (0x402000,)},
        reachable_eas=(0x401000, 0x401010, 0x402000),
        arch="x86_64",
        executed_insns=17,
        seeds_run=1,
    )
    preparation = PreoptUnionPreparationResult(
        function_ea=0x401000,
        prepared=True,
        published=True,
        primary_seed_ea=0x402000,
    )
    cfg = NativeCfg({})
    closure = NativeSemanticClosure(
        included_block_eas=(),
        native_ranges=(),
        proven_internal_edges=(),
        abstentions=(),
        seed_provenance=(),
        proven_import_boundary_edges=(),
    )
    source = PrepatchPreoptUnionSource(
        primary_seed_ea=0x402000,
        seed_eas=(0x402000,),
        seed_native_ranges=((0x402000, ((0x402000, 0x402010),)),),
        native_ranges=((0x402000, 0x402010),),
        imported_block_entry_eas=(0x402000,),
        cfg=cfg,
        closure=closure,
    )

    assert state.set_computed_goto_resolution(NATIVE_KEY, resolution)
    assert state.set_preopt_union_preparation(NATIVE_KEY, preparation)
    assert state.set_prepatch_preopt_union_source(NATIVE_KEY, source)

    evidence = state.resolver_evidence
    assert evidence is not None
    assert evidence.computed_goto_resolution is resolution
    assert evidence.preopt_union_preparation is preparation
    assert evidence.prepatch_preopt_union_source is source
    assert state.evidence_generation == 0


def test_lifecycle_merges_native_transfer_facts_and_static_bootstrap_routes() -> None:
    state = NativePreanalysisSessionState()
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x401010,
        source_block_ea=0x401000,
        materialized_anchor_eas=(0x401010,),
        target_eas=(0x402000,),
        resolver_kind="static_handler_entry_route",
    )

    assert state.merge_native_facts(
        NATIVE_KEY,
        native_cfg=NativeCfg({}),
        boundary_ports=DetachedSnippetBoundaryPorts((), ()),
    )
    assert state.merge_materialized_transfers(NATIVE_KEY, (transfer,))
    assert state.facts is not None
    assert state.facts.transfers == (transfer,)
    assert state.discover_static_native_bootstrap_route(
        NATIVE_KEY,
        source_anchor_ea=0x401010,
        state_constant=0x1234,
        handler_anchor_ea=0x402000,
    )
    assert len(state.bootstrap_routes) == 1
