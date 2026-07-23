"""Portable evidence ownership for one top-level decompilation."""

from __future__ import annotations

import importlib
from dataclasses import fields, replace

import pytest

from d810.analyses.control_flow.call_abi import StackCallAbiProof
from d810.analyses.control_flow.detached_handler_island import (
    DetachedSnippetBoundaryPorts,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    PortableMaterializedStateRoute,
    PortableStateWriteRouteEvidence,
    StateWriteRouteDeliveryKind,
    StateWriteRouteProofKind,
    TerminalReturnCarrierRequest,
)
from d810.analyses.control_flow.frontend_normalization import (
    FrontendNormalizationEvidenceRejected,
    NativeTransferShape,
)
from d810.analyses.control_flow.semantic_route_evidence import (
    SemanticPredicateKind,
    SemanticRouteProofKind,
    SemanticRouteShape,
)
from d810.analyses.control_flow.terminal_return_carrier_evidence import (
    TerminalReturnCarrierEvidence,
    TerminalReturnCarrierEvidenceRejected,
    TerminalReturnCarrierSource,
    TerminalReturnCarrierSourceKind,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    BootstrapRouteBindingEvidence,
    BootstrapRouteEvidence,
    BootstrapRouteProofKind,
    ComputedGotoPatchPlan,
    ComputedGotoResolution,
    PreoptUnionPreparationResult,
    PrepatchPreoptUnionSource,
    NativePreanalysisSessionState,
)
from d810.analyses.control_flow.residual_entry_bridge import EntryBridgeEvidence
from d810.analyses.control_flow.native_semantic_closure import (
    NativeBlock,
    NativeCfg,
    NativeEdge,
    NativeEdgeKind,
    NativeRange,
    NativeSemanticClosure,
    NativeTerminalKind,
)
from d810.core.native_preanalysis_key import NativePreanalysisKeyMismatch
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.expressions import ValueOpKind
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from tests.native_preanalysis import make_native_key

NATIVE_KEY = make_native_key()


def _publish_normalization(state: NativePreanalysisSessionState) -> None:
    assert state._fragment_publication_mark_normalization_staged()
    assert state._fragment_publication_mark_normalization_validated()
    assert state._fragment_publication_mark_normalization_published_and_postvalidated()


@pytest.mark.parametrize(
    "method_name",
    (
        "mark_normalization_staged",
        "mark_normalization_validated",
        "mark_normalization_published_and_postvalidated",
        "abort_normalization",
        "mark_semantic_fragment_staged",
        "mark_semantic_fragment_validated",
        "mark_semantic_fragment_published_and_postvalidated",
        "mark_receipt_committed",
        "abort_semantic_fragment",
    ),
)
def test_session_state_has_no_public_fragment_publication_transition(
    method_name: str,
) -> None:
    state = NativePreanalysisSessionState()

    assert not hasattr(state, method_name)


def test_legacy_preopt_binding_authority_is_removed() -> None:
    field_names = {item.name for item in fields(NativePreanalysisSessionState)}
    state = NativePreanalysisSessionState()

    assert "bound_preopt_generation" not in field_names
    assert not hasattr(state, "needs_preopt_binding")
    assert not hasattr(state, "mark_preopt_bound")


def test_lifecycle_rejects_incoherent_generation_snapshots() -> None:
    with pytest.raises(ValueError, match="normalization lifecycle generation order"):
        NativePreanalysisSessionState(
            evidence_generation=1,
            normalization_published_postvalidated_generation=1,
        )

    with pytest.raises(ValueError, match="semantic lifecycle generation order"):
        NativePreanalysisSessionState(
            evidence_generation=1,
            portable_evidence_ready_generation=1,
            normalization_staged_generation=1,
            normalization_validated_generation=1,
            normalization_published_postvalidated_generation=1,
            receipt_committed_generation=1,
        )

    with pytest.raises(ValueError, match="cannot exceed portable evidence"):
        NativePreanalysisSessionState(
            evidence_generation=1,
            portable_evidence_ready_generation=2,
        )


def test_lifecycle_tracks_normalization_and_semantic_generations_independently() -> (
    None
):
    state = NativePreanalysisSessionState()

    state.mark_evidence_changed(
        evidence_family="test_evidence",
        reason="portable evidence became ready",
    )

    assert state.portable_evidence_ready_generation == 1
    assert state.needs_normalization_publication()
    with pytest.raises(
        RuntimeError,
        match="normalization validation requires the current staged generation",
    ):
        state._fragment_publication_mark_normalization_validated()

    assert state._fragment_publication_mark_normalization_staged()
    assert state._fragment_publication_mark_normalization_validated()
    assert state._fragment_publication_mark_normalization_published_and_postvalidated()
    assert not state.needs_normalization_publication()
    assert state.normalization_staged_generation == 1
    assert state.normalization_validated_generation == 1
    assert state.normalization_published_postvalidated_generation == 1

    # A faithful PREOPT normalization is not state-machine lowering authority.
    assert state.canonical_semantic_plan_generation is None
    assert state.semantic_fragment_staged_generation is None
    assert state.semantic_fragment_validated_generation is None
    assert state.semantic_fragment_published_postvalidated_generation is None
    assert state.receipt_committed_generation is None

    with pytest.raises(
        RuntimeError,
        match="semantic fragment staging requires the current canonical plan",
    ):
        state._fragment_publication_mark_semantic_fragment_staged()

    assert state.mark_canonical_semantic_plan_ready()
    assert state._fragment_publication_mark_semantic_fragment_staged()
    assert state._fragment_publication_mark_semantic_fragment_validated()
    assert state._fragment_publication_mark_semantic_fragment_published_and_postvalidated()
    assert state._fragment_publication_mark_receipt_committed()
    assert state.canonical_semantic_plan_generation == 1
    assert state.semantic_fragment_staged_generation == 1
    assert state.semantic_fragment_validated_generation == 1
    assert state.semantic_fragment_published_postvalidated_generation == 1
    assert state.receipt_committed_generation == 1


def test_normalization_abort_preserves_previous_published_authority() -> None:
    observed = []
    state = NativePreanalysisSessionState(event_observer=observed.append)
    state.mark_evidence_changed(
        evidence_family="test_evidence",
        reason="first portable generation",
    )
    state._fragment_publication_mark_normalization_staged()
    state._fragment_publication_mark_normalization_validated()
    state._fragment_publication_mark_normalization_published_and_postvalidated()

    state.mark_evidence_changed(
        evidence_family="test_evidence",
        reason="second portable generation",
    )
    assert state.evidence_generation == 2
    state._fragment_publication_mark_normalization_staged()
    state._fragment_publication_mark_normalization_validated()
    assert state._fragment_publication_abort_normalization(reason="postpublication validation failed")

    assert state.portable_evidence_ready_generation == 2
    assert state.normalization_staged_generation == 1
    assert state.normalization_validated_generation == 1
    assert state.normalization_published_postvalidated_generation == 1
    assert state.needs_normalization_publication()
    assert observed[-1].operation == "normalization_aborted"
    assert observed[-1].outcome == "aborted"
    with pytest.raises(
        RuntimeError,
        match="normalization publication requires the current validated generation",
    ):
        state._fragment_publication_mark_normalization_published_and_postvalidated()


def test_semantic_abort_preserves_previous_receipt_authority() -> None:
    state = NativePreanalysisSessionState()
    state.mark_evidence_changed(
        evidence_family="test_evidence",
        reason="first portable generation",
    )
    state._fragment_publication_mark_normalization_staged()
    state._fragment_publication_mark_normalization_validated()
    state._fragment_publication_mark_normalization_published_and_postvalidated()
    state.mark_canonical_semantic_plan_ready()
    state._fragment_publication_mark_semantic_fragment_staged()
    state._fragment_publication_mark_semantic_fragment_validated()
    state._fragment_publication_mark_semantic_fragment_published_and_postvalidated()
    state._fragment_publication_mark_receipt_committed()

    state.mark_evidence_changed(
        evidence_family="test_evidence",
        reason="second portable generation",
    )
    state._fragment_publication_mark_normalization_staged()
    state._fragment_publication_mark_normalization_validated()
    state._fragment_publication_mark_normalization_published_and_postvalidated()
    state.mark_canonical_semantic_plan_ready()
    state._fragment_publication_mark_semantic_fragment_staged()
    state._fragment_publication_mark_semantic_fragment_validated()
    assert state._fragment_publication_abort_semantic_fragment(reason="published graph drifted")

    assert state.normalization_published_postvalidated_generation == 2
    assert state.canonical_semantic_plan_generation == 2
    assert state.semantic_fragment_staged_generation == 1
    assert state.semantic_fragment_validated_generation == 1
    assert state.semantic_fragment_published_postvalidated_generation == 1
    assert state.receipt_committed_generation == 1


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
    assert state.needs_normalization_publication()
    _publish_normalization(state)
    assert not state.needs_normalization_publication()
    assert state.normalization_published_postvalidated_generation == 1


def test_evidence_observer_sees_normalization_lifecycle_transitions() -> None:
    observed = []
    state = NativePreanalysisSessionState(event_observer=observed.append)

    state.mark_evidence_changed(
        evidence_family="test_evidence",
        reason="test evidence changed",
    )
    _publish_normalization(state)

    assert [
        (row.operation, row.previous_generation, row.resulting_generation)
        for row in observed
    ] == [
        ("evidence_changed", 0, 1),
        ("normalization_staged", 0, 1),
        ("normalization_validated", 0, 1),
        ("normalization_published_postvalidated", 0, 1),
    ]


def test_evidence_observer_sees_generated_restart_request_and_consumption() -> None:
    observed = []
    state = NativePreanalysisSessionState(
        evidence_generation=2,
        normalization_staged_generation=1,
        normalization_validated_generation=1,
        normalization_published_postvalidated_generation=1,
        event_observer=observed.append,
    )

    assert state.request_generated_restart()
    assert not state.request_generated_restart()
    assert state.consume_generated_restart()

    assert [
        (row.operation, row.outcome, row.evidence_family, row.reason)
        for row in observed
    ] == [
        (
            "generated_restart_requested",
            "accepted",
            "controller_restart",
            "CALLS staged a controller-owned generated-MBA restart",
        ),
        (
            "generated_restart_requested",
            "declined",
            "controller_restart",
            "evidence generation already owns a controlled redo",
        ),
        (
            "generated_restart_consumed",
            "accepted",
            "controller_restart",
            "flowchart consumed the staged generated-MBA restart",
        ),
    ]


def test_resolver_evidence_observer_names_the_changed_family() -> None:
    observed = []
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401000, 0x401010),), native_key=NATIVE_KEY
    )
    target = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x402000, 0x402010),), native_key=NATIVE_KEY
    )
    state = NativePreanalysisSessionState(event_observer=observed.append)

    assert state.merge_portable_state_routes(
        NATIVE_KEY,
        (
            PortableMaterializedStateRoute(
                source_identity=source,
                state_constant=0x1234,
                target_identity=target,
            ),
        ),
    )

    assert observed[-1].evidence_family == "portable_state_routes"
    assert observed[-1].reason == "portable state-route evidence changed"


def test_lifecycle_owns_native_state_write_delivery_routes() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40A5B2, 0x40A5C9),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40A5B2, 0x40A5C8),
    )
    target = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40BECC, 0x40BECD),),
        native_key=NATIVE_KEY,
    )
    route = PortableStateWriteRouteEvidence(
        write_identity=source,
        delivery_identity=source,
        source_write_ea=0x40A5B2,
        delivery_ea=0x40A5C8,
        delivery_region_start_ea=0x40A5B8,
        delivery_region_end_ea=0x40A5CD,
        corridor_instruction_eas=(0x40A5B2, 0x40A5B8, 0x40A5C2, 0x40A5C8),
        state_var_reg=16,
        state_constant=0xABB95547,
        target_identity=target,
        target_ea=0x40BECC,
    )
    observed = []
    state = NativePreanalysisSessionState(event_observer=observed.append)

    assert state.merge_state_write_routes(NATIVE_KEY, (route,))
    assert not state.merge_state_write_routes(NATIVE_KEY, (route,))
    assert state.resolver_evidence is not None
    assert state.resolver_evidence.state_write_routes == (route,)
    assert state.state_write_route_inventory_revision == 1
    assert state.pending_state_write_routes_for_publication() == (route,)
    assert state.needs_state_write_route_binding()
    state.mark_state_write_routes_published((route,))
    assert state.pending_state_write_routes_for_publication() == ()
    state.mark_state_write_routes_bound()
    assert not state.needs_state_write_route_binding()
    assert observed[-1].evidence_family == "state_write_routes"
    assert observed[-1].reason == "native state-write route evidence changed"


def test_lifecycle_owns_portable_terminal_return_carrier_semantics() -> None:
    capture_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40C7E5, 0x40C7F4),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40C7E5, 0x40C7EA),
    )
    terminal_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40C898, 0x40C8A0),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40C898,),
    )
    request = TerminalReturnCarrierRequest(
        source_handler_ea=0x40C7E5,
        terminal_target_ea=0x40C898,
        state_var_reg=20,
        state_constant=0x19A7218A,
    )
    carrier = TerminalReturnCarrierEvidence(
        request=request,
        capture_identity=capture_identity,
        terminal_identity=terminal_identity,
        state_write_ea=0x40C7E5,
        carrier_ea=0x40C7EA,
        operation=ValueOpKind.MOVE,
        source=TerminalReturnCarrierSource(
            kind=TerminalReturnCarrierSourceKind.STORAGE_VALUE,
            width=4,
            storage_identity=StorageIdentity(
                StorageIdentityKind.GLOBAL,
                0x48B8A4,
            ),
        ),
        return_width=4,
        corridor_instruction_eas=(0x40C7E5, 0x40C7EA),
    )
    state = NativePreanalysisSessionState()

    assert state.merge_terminal_return_carriers(NATIVE_KEY, (carrier,))
    assert not state.merge_terminal_return_carriers(NATIVE_KEY, (carrier,))
    assert state.resolver_evidence is not None
    assert state.resolver_evidence.terminal_return_carriers == (carrier,)

    conflicting = replace(
        carrier,
        capture_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x40C7E5, 0x40C7F4),),
            native_key=NATIVE_KEY,
            exact_instruction_eas=(0x40C7E5, 0x40C7EB),
        ),
        carrier_ea=0x40C7EB,
        corridor_instruction_eas=(0x40C7E5, 0x40C7EB),
    )
    with pytest.raises(
        TerminalReturnCarrierEvidenceRejected,
        match="conflicting terminal carrier evidence",
    ):
        state.merge_terminal_return_carriers(NATIVE_KEY, (conflicting,))

    other_key = make_native_key(profile_fingerprint="sha256:other-profile")
    with pytest.raises(NativePreanalysisKeyMismatch):
        NativePreanalysisSessionState().merge_terminal_return_carriers(
            other_key,
            (carrier,),
        )


def test_canonical_semantic_evidence_projects_only_postvalidated_state_routes() -> (
    None
):
    write_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40A5B2, 0x40A5B8),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40A5B2,),
    )
    delivery_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40A5B8, 0x40A5CD),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40A5C8,),
    )
    target_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40BECC, 0x40BED0),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40BECC,),
    )
    route = PortableStateWriteRouteEvidence(
        write_identity=write_identity,
        delivery_identity=delivery_identity,
        source_write_ea=0x40A5B2,
        delivery_ea=0x40A5C8,
        delivery_region_start_ea=0x40A5B8,
        delivery_region_end_ea=0x40A5CD,
        corridor_instruction_eas=(0x40A5B2, 0x40A5B8, 0x40A5C2, 0x40A5C8),
        state_var_reg=16,
        state_constant=0xABB95547,
        target_identity=target_identity,
        target_ea=0x40BECC,
        proof_kind=StateWriteRouteProofKind.STATE_ASSIGNMENT,
        delivery_kind=StateWriteRouteDeliveryKind.DIRECT_TARGET,
    )
    state = NativePreanalysisSessionState()
    assert state.merge_state_write_routes(NATIVE_KEY, (route,))

    assert state.canonical_semantic_evidence_for(NATIVE_KEY) is None

    _publish_normalization(state)
    evidence = state.canonical_semantic_evidence_for(NATIVE_KEY)

    assert evidence is not None
    assert evidence.native_key == NATIVE_KEY
    assert evidence.generation == state.evidence_generation == 1
    assert evidence.atomic_group_id == "canonical-semantic:g1"
    assert len(evidence.route_proofs) == 1
    proof = evidence.route_proofs[0]
    assert proof.proof_kind is SemanticRouteProofKind.STATE_ASSIGNMENT
    assert proof.shape is SemanticRouteShape.DIRECT
    assert proof.source_identity == delivery_identity
    assert proof.source_anchor_ea == 0x40A5C8
    assert proof.destinations[0].role is SemanticEdgeRole.DIRECT
    assert proof.destinations[0].target_identity == target_identity
    assert proof.destinations[0].target_anchor_ea == 0x40BECC
    assert proof.destinations[0].state_constant == 0xABB95547
    assert proof.state_write is not None
    assert proof.state_write.identity == write_identity
    assert proof.state_write.instruction_ea == 0x40A5B2
    assert proof.state_write.state_variable.kind is StorageIdentityKind.REGISTER
    assert proof.state_write.state_variable.offset == 16
    assert proof.state_write.width == 4
    assert proof.state_write.corridor_instruction_eas == (
        0x40A5B2,
        0x40A5B8,
        0x40A5C2,
        0x40A5C8,
    )
    assert dict(proof.diagnostic_provenance) == {
        "provider_proof_kind": "state_assignment",
        "delivery_kind": "direct_target",
    }


def test_canonical_semantic_evidence_groups_terminal_carrier_with_its_route() -> None:
    capture_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40C7E5, 0x40C7F4),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40C7E5, 0x40C7EA, 0x40C7F0),
    )
    terminal_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40C898, 0x40C8A0),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40C898,),
    )
    request = TerminalReturnCarrierRequest(
        source_handler_ea=0x40C7E5,
        terminal_target_ea=0x40C898,
        state_var_reg=20,
        state_constant=0x19A7218A,
    )
    carrier = TerminalReturnCarrierEvidence(
        request=request,
        capture_identity=capture_identity,
        terminal_identity=terminal_identity,
        state_write_ea=0x40C7E5,
        carrier_ea=0x40C7EA,
        operation=ValueOpKind.MOVE,
        source=TerminalReturnCarrierSource(
            kind=TerminalReturnCarrierSourceKind.STORAGE_VALUE,
            width=4,
            storage_identity=StorageIdentity(
                StorageIdentityKind.GLOBAL,
                0x48B8A4,
            ),
        ),
        return_width=4,
        corridor_instruction_eas=(0x40C7E5, 0x40C7EA),
    )
    route = PortableStateWriteRouteEvidence(
        write_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x40C7E5, 0x40C7E6),),
            native_key=NATIVE_KEY,
        ),
        delivery_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x40C7F0, 0x40C7F1),),
            native_key=NATIVE_KEY,
        ),
        source_write_ea=0x40C7E5,
        delivery_ea=0x40C7F0,
        delivery_region_start_ea=0x40C7E5,
        delivery_region_end_ea=0x40C7F4,
        corridor_instruction_eas=(0x40C7E5, 0x40C7EA, 0x40C7F0),
        state_var_reg=20,
        state_constant=0x19A7218A,
        target_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x40C898, 0x40C899),),
            native_key=NATIVE_KEY,
        ),
        target_ea=0x40C898,
    )
    state = NativePreanalysisSessionState()
    assert state.merge_state_write_routes(NATIVE_KEY, (route,))
    assert state.merge_terminal_return_carriers(NATIVE_KEY, (carrier,))
    _publish_normalization(state)

    evidence = state.canonical_semantic_evidence_for(NATIVE_KEY)

    assert evidence is not None
    assert len(evidence.route_proofs) == 1
    proof = evidence.route_proofs[0]
    assert proof.proof_kind is SemanticRouteProofKind.TERMINAL_RETURN
    assert proof.destinations[0].terminal
    assert proof.terminal_return_carrier == carrier

    unmatched_terminal = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D000, 0x40D008),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40D000,),
    )
    unmatched = replace(
        carrier,
        request=replace(request, terminal_target_ea=0x40D000),
        terminal_identity=unmatched_terminal,
    )
    rejected = NativePreanalysisSessionState()
    assert rejected.merge_state_write_routes(NATIVE_KEY, (route,))
    assert rejected.merge_terminal_return_carriers(NATIVE_KEY, (unmatched,))
    _publish_normalization(rejected)
    assert rejected.canonical_semantic_evidence_for(NATIVE_KEY) is None


def test_canonical_semantic_evidence_projects_complete_entry_consumer() -> None:
    predicate_ea = 0x1008
    store_ea = 0x1014
    consumer_ea = 0x2000
    true_target_ea = 0x3000
    false_target_ea = 0x4000
    true_state = 0xAABBCCDD
    false_state = 0x11223344
    cfg = NativeCfg(
        {
            0x1000: NativeBlock(
                start_ea=0x1000,
                end_ea=0x1010,
            ),
            0x1010: NativeBlock(
                start_ea=0x1010,
                end_ea=0x1020,
            ),
            consumer_ea: NativeBlock(
                start_ea=consumer_ea,
                end_ea=0x2020,
            ),
            true_target_ea: NativeBlock(
                start_ea=true_target_ea,
                end_ea=0x3010,
            ),
            false_target_ea: NativeBlock(
                start_ea=false_target_ea,
                end_ea=0x4010,
            ),
        }
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=0x1000,
        materialized_anchor_eas=(store_ea,),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=5,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        predicate_stack_ida_stkoff=0x30,
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        state_carrier_store_ea=store_ea,
        state_carrier_stack_displacement=0x40,
        state_carrier_consumer_load_eas=(consumer_ea,),
        state_carrier_ida_stkoff=0x40,
        owned_native_ranges=((consumer_ea, 0x2020),),
        resolver_kind="provider-specific-diagnostic-name",
    )
    state = NativePreanalysisSessionState()
    assert state.merge_native_facts(
        NATIVE_KEY,
        native_cfg=cfg,
        transfers=(transfer,),
        boundary_ports=DetachedSnippetBoundaryPorts((), ()),
    )
    assert state.set_preopt_union_preparation(
        NATIVE_KEY,
        PreoptUnionPreparationResult(
            function_ea=0x1000,
            prepared=True,
            published=True,
            entry_consumer_routes=(transfer,),
        ),
    )
    _publish_normalization(state)

    evidence = state.canonical_semantic_evidence_for(NATIVE_KEY)

    assert evidence is not None
    assert len(evidence.route_proofs) == 1
    proof = evidence.route_proofs[0]
    assert proof.proof_kind is SemanticRouteProofKind.STATE_CHOICE
    assert proof.shape is SemanticRouteShape.CONDITIONAL
    assert proof.source_anchor_ea == consumer_ea
    assert proof.predicate is not None
    assert proof.predicate.kind is SemanticPredicateKind.STORAGE_EQUALS
    assert proof.predicate.storage_identity.kind is StorageIdentityKind.STACK
    assert proof.predicate.storage_identity.offset == 0x30
    assert proof.predicate.width == 4
    assert proof.predicate.compare_constant == 0
    assert tuple(point.anchor_ea for point in proof.predicate.corridor) == (
        predicate_ea,
        store_ea,
        consumer_ea,
    )
    assert len(proof.carriers) == 1
    carrier = proof.carriers[0]
    assert carrier.definition.anchor_ea == store_ea
    assert tuple(point.anchor_ea for point in carrier.consumers) == (consumer_ea,)
    assert carrier.storage_identity.kind is StorageIdentityKind.STACK
    assert carrier.storage_identity.offset == 0x40
    assert carrier.state_values == (true_state, false_state)
    assert {
        (destination.role, destination.state_constant, destination.target_anchor_ea)
        for destination in proof.destinations
    } == {
        (
            SemanticEdgeRole.CONDITIONAL_TAKEN,
            false_state,
            false_target_ea,
        ),
        (
            SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
            true_state,
            true_target_ea,
        ),
    }
    assert dict(proof.diagnostic_provenance) == {
        "provider_resolver_kind": "provider-specific-diagnostic-name"
    }

    incomplete = replace(transfer, predicate_stack_ida_stkoff=None)
    rejected = NativePreanalysisSessionState()
    assert rejected.merge_native_facts(
        NATIVE_KEY,
        native_cfg=cfg,
        transfers=(incomplete,),
        boundary_ports=DetachedSnippetBoundaryPorts((), ()),
    )
    assert rejected.set_preopt_union_preparation(
        NATIVE_KEY,
        PreoptUnionPreparationResult(
            function_ea=0x1000,
            prepared=True,
            published=True,
            entry_consumer_routes=(incomplete,),
        ),
    )
    direct_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x5000, 0x5010),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x5000,),
    )
    direct_target_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x6000, 0x6010),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x6000,),
    )
    assert rejected.merge_state_write_routes(
        NATIVE_KEY,
        (
            PortableStateWriteRouteEvidence(
                write_identity=direct_identity,
                delivery_identity=direct_identity,
                source_write_ea=0x5000,
                delivery_ea=0x5000,
                delivery_region_start_ea=0x5000,
                delivery_region_end_ea=0x5010,
                corridor_instruction_eas=(0x5000,),
                state_var_reg=20,
                state_constant=0x12345678,
                target_identity=direct_target_identity,
                target_ea=0x6000,
            ),
        ),
    )
    _publish_normalization(rejected)
    assert rejected.canonical_semantic_evidence_for(NATIVE_KEY) is None


def test_state_write_delivery_route_rejects_mismatched_native_key() -> None:
    other_key = make_native_key(profile_fingerprint="sha256:other-profile")
    route = PortableStateWriteRouteEvidence(
        write_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x40A5B2, 0x40A5C9),),
            native_key=other_key,
        ),
        delivery_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x40A5C8, 0x40A5C9),),
            native_key=other_key,
        ),
        source_write_ea=0x40A5B2,
        delivery_ea=0x40A5C8,
        delivery_region_start_ea=0x40A5B8,
        delivery_region_end_ea=0x40A5CD,
        corridor_instruction_eas=(0x40A5B2, 0x40A5C8),
        state_var_reg=16,
        state_constant=0xABB95547,
        target_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x40BECC, 0x40BECD),),
            native_key=other_key,
        ),
        target_ea=0x40BECC,
    )

    with pytest.raises(NativePreanalysisKeyMismatch):
        NativePreanalysisSessionState().merge_state_write_routes(
            NATIVE_KEY,
            (route,),
        )


def test_first_pass_native_evidence_coalesces_until_normalization_publishes() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401020, 0x401021),), native_key=NATIVE_KEY
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401100, 0x401101),), native_key=NATIVE_KEY
    )
    state = NativePreanalysisSessionState()

    state.mark_evidence_changed(
        evidence_family="test_evidence",
        reason="test evidence changed",
    )
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

    _publish_normalization(state)
    state.mark_evidence_changed(
        evidence_family="test_evidence",
        reason="test evidence changed",
    )
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
    _publish_normalization(state)
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


def test_lifecycle_owns_portable_preopt_entry_bridge_evidence() -> None:
    evidence = EntryBridgeEvidence(
        predicate_ea=0x40A5A0,
        condition_code=5,
        predicate_stack_identity=(0x20, 4),
        stack_cell_identity=(0x80, 4),
        taken_state_constant=0xA0716E5B,
        fallthrough_state_constant=0xEC71CA67,
        source_store_ea=0x40A5C0,
        canonical_stack_cell_identity=(0x40, 4),
        canonical_predicate_stack_identity=(-0x20, 4),
        predicate_block_ea=0x40A560,
        taken_arm_entry_ea=0x40A5C0,
        fallthrough_arm_entry_ea=0x40A5B0,
        conditional_tail_ea=0x40A5AB,
    )
    state = NativePreanalysisSessionState()

    assert state.merge_preopt_entry_bridge_evidence(NATIVE_KEY, evidence)
    assert not state.merge_preopt_entry_bridge_evidence(NATIVE_KEY, evidence)
    assert state.resolver_evidence is not None
    assert state.resolver_evidence.preopt_entry_bridges == (evidence,)
    assert state.evidence_generation == 1

    split_live_observation = replace(
        evidence,
        predicate_block_ea=0x40A59D,
        taken_arm_entry_ea=0x40A5AE,
        fallthrough_arm_entry_ea=0x40A5B7,
    )
    assert not state.merge_preopt_entry_bridge_evidence(
        NATIVE_KEY,
        split_live_observation,
    )
    assert state.resolver_evidence.preopt_entry_bridges == (evidence,)
    assert state.evidence_generation == 1


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


def test_lifecycle_projects_complete_native_patch_ledger_as_frontend_evidence() -> (
    None
):
    producer_ea = 0x1005
    predicate_ea = 0x1014
    direct_ea = 0x1100
    true_target_ea = 0x2000
    false_target_ea = 0x3000
    cfg = NativeCfg(
        {
            0x1000: NativeBlock(
                start_ea=0x1000,
                end_ea=0x1010,
                outgoing_edges=(
                    NativeEdge(
                        kind=NativeEdgeKind.FALLTHROUGH,
                        target_ea=0x1010,
                        source_instruction_ea=0x100C,
                    ),
                ),
            ),
            0x1010: NativeBlock(
                start_ea=0x1010,
                end_ea=0x1020,
                outgoing_edges=(
                    NativeEdge(
                        kind=NativeEdgeKind.CONDITIONAL_TRUE,
                        target_ea=true_target_ea,
                        source_instruction_ea=predicate_ea,
                    ),
                    NativeEdge(
                        kind=NativeEdgeKind.CONDITIONAL_FALSE,
                        target_ea=false_target_ea,
                        source_instruction_ea=predicate_ea,
                    ),
                ),
            ),
            direct_ea: NativeBlock(
                start_ea=direct_ea,
                end_ea=0x1110,
                outgoing_edges=(
                    NativeEdge(
                        kind=NativeEdgeKind.DIRECT_JUMP,
                        target_ea=true_target_ea,
                        source_instruction_ea=direct_ea,
                    ),
                ),
            ),
            true_target_ea: NativeBlock(
                start_ea=true_target_ea,
                end_ea=0x2010,
                terminal=NativeTerminalKind.RETURN,
            ),
            false_target_ea: NativeBlock(
                start_ea=false_target_ea,
                end_ea=0x3010,
                terminal=NativeTerminalKind.RETURN,
            ),
            0x4000: NativeBlock(
                start_ea=0x4000,
                end_ea=0x4010,
                outgoing_edges=(
                    NativeEdge(
                        kind=NativeEdgeKind.FALLTHROUGH,
                        target_ea=0x5000,
                        source_instruction_ea=0x400C,
                    ),
                ),
            ),
        }
    )
    closure = NativeSemanticClosure(
        included_block_eas=(true_target_ea, false_target_ea),
        native_ranges=(
            NativeRange(true_target_ea, 0x2010),
            NativeRange(false_target_ea, 0x3010),
        ),
        proven_internal_edges=(),
        abstentions=(),
        seed_provenance=(),
    )
    conditional = ComputedGotoPatchPlan(
        jmp_ea=0x1018,
        block_entry=0x1000,
        patch_start=0x1010,
        patch_bytes=b"\x90",
        region_end=0x1020,
        insn_heads=(0x1010, predicate_ea, 0x101A),
        new_block_eas=(predicate_ea, 0x101A),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=5,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        condition_producer_ea=producer_ea,
    )
    direct = ComputedGotoPatchPlan(
        jmp_ea=0x1108,
        block_entry=direct_ea,
        patch_start=direct_ea,
        patch_bytes=b"\x90",
        region_end=0x1110,
        insn_heads=(direct_ea,),
        new_block_eas=(direct_ea,),
        target_eas=(true_target_ea,),
    )
    resolution = ComputedGotoResolution(
        function_ea=0x401000,
        jmp_targets={
            conditional.jmp_ea: conditional.target_eas,
            direct.jmp_ea: direct.target_eas,
        },
        reachable_eas=(0x401000,),
        arch="x86",
        executed_insns=17,
        seeds_run=0,
        patch_plans=(conditional, direct),
    )
    state = NativePreanalysisSessionState()
    assert state.set_computed_goto_resolution(NATIVE_KEY, resolution)
    assert state.merge_native_facts(
        NATIVE_KEY,
        native_cfg=cfg,
        semantic_closure=closure,
        boundary_ports=DetachedSnippetBoundaryPorts((), ()),
    )

    evidence = state.frontend_normalization_evidence_for(NATIVE_KEY)

    assert evidence is not None
    assert evidence.generation == 1
    assert evidence.atomic_group_id == "frontend-normalization:g1"
    assert evidence.native_cfg is cfg
    assert evidence.semantic_closure is closure
    proofs = {proof.proof_id: proof for proof in evidence.transfer_proofs}
    conditional_proof = proofs["native-indirect-transfer@0x1018"]
    assert conditional_proof.shape is NativeTransferShape.CONDITIONAL
    assert conditional_proof.source_anchor_ea == predicate_ea
    assert conditional_proof.condition_producer_ea == producer_ea
    assert tuple(
        (
            identity.native_ranges.intervals[0].start_ea,
            identity.native_ranges.intervals[0].end_ea,
        )
        for identity in conditional_proof.flag_corridor
    ) == ((0x1000, 0x1010), (0x1010, 0x1020))
    assert conditional_proof.permitted_flag_write_eas == frozenset(
        {producer_ea}
    )
    assert {
        (endpoint.role, endpoint.anchor_ea)
        for endpoint in conditional_proof.endpoints
    } == {
        (SemanticEdgeRole.CONDITIONAL_TAKEN, true_target_ea),
        (SemanticEdgeRole.CONDITIONAL_FALLTHROUGH, false_target_ea),
    }
    direct_proof = proofs["native-indirect-transfer@0x1108"]
    assert direct_proof.shape is NativeTransferShape.DIRECT
    assert direct_proof.source_anchor_ea == direct_ea
    assert direct_proof.endpoints[0].role is SemanticEdgeRole.DIRECT
    assert direct_proof.endpoints[0].anchor_ea == true_target_ea


def test_frontend_evidence_owns_patch_corridor_and_ledger_target() -> None:
    producer_ea = 0x1005
    patch_start = 0x1010
    predicate_ea = patch_start
    branch_ea = 0x1016
    true_target_ea = 0x2000
    false_target_ea = 0x3000
    cfg = NativeCfg(
        {
            false_target_ea: NativeBlock(
                start_ea=false_target_ea,
                end_ea=0x3010,
                terminal=NativeTerminalKind.RETURN,
            ),
        }
    )
    closure = NativeSemanticClosure(
        included_block_eas=(false_target_ea,),
        native_ranges=(NativeRange(false_target_ea, 0x3010),),
        proven_internal_edges=(),
        abstentions=(),
        seed_provenance=(),
    )
    conditional = ComputedGotoPatchPlan(
        jmp_ea=0x1018,
        block_entry=0x1000,
        patch_start=patch_start,
        patch_bytes=b"\x90" * 0x10,
        region_end=0x1020,
        insn_heads=(patch_start, predicate_ea, branch_ea),
        new_block_eas=(predicate_ea, branch_ea),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=5,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        condition_producer_ea=producer_ea,
    )
    downstream = ComputedGotoPatchPlan(
        jmp_ea=0x2008,
        block_entry=true_target_ea,
        patch_start=true_target_ea,
        patch_bytes=b"\x90" * 0x10,
        region_end=0x2010,
        insn_heads=(true_target_ea,),
        new_block_eas=(true_target_ea,),
        target_eas=(false_target_ea,),
    )
    resolution = ComputedGotoResolution(
        function_ea=0x401000,
        jmp_targets={
            conditional.jmp_ea: conditional.target_eas,
            downstream.jmp_ea: downstream.target_eas,
        },
        reachable_eas=(0x401000,),
        arch="x86",
        executed_insns=17,
        seeds_run=0,
        patch_plans=(conditional, downstream),
    )
    state = NativePreanalysisSessionState()
    assert state.set_computed_goto_resolution(NATIVE_KEY, resolution)
    assert state.merge_native_facts(
        NATIVE_KEY,
        native_cfg=cfg,
        semantic_closure=closure,
        boundary_ports=DetachedSnippetBoundaryPorts((), ()),
    )

    evidence = state.frontend_normalization_evidence_for(NATIVE_KEY)

    assert evidence is not None
    proofs = {proof.proof_id: proof for proof in evidence.transfer_proofs}
    conditional_proof = proofs["native-indirect-transfer@0x1018"]
    downstream_proof = proofs["native-indirect-transfer@0x2008"]
    assert conditional_proof.source_anchor_ea == predicate_ea
    assert tuple(
        (
            identity.native_ranges.intervals[0].start_ea,
            identity.native_ranges.intervals[0].end_ea,
        )
        for identity in conditional_proof.flag_corridor
    ) == ((0x1000, patch_start), (patch_start, 0x1020))
    assert conditional_proof.source_identity == conditional_proof.flag_corridor[-1]
    assert conditional_proof.source_identity.exact_instruction_eas == frozenset(
        {predicate_ea}
    )
    taken_endpoint = next(
        endpoint
        for endpoint in conditional_proof.endpoints
        if endpoint.role is SemanticEdgeRole.CONDITIONAL_TAKEN
    )
    assert taken_endpoint.identity.exact_instruction_eas == frozenset(
        {true_target_ea}
    )
    assert taken_endpoint.identity.native_ranges.intervals == (
        NativeEaInterval(true_target_ea, true_target_ea + 1),
    )
    assert downstream_proof.source_anchor_ea == true_target_ea


def test_frontend_evidence_rejects_the_whole_ledger_without_a_flag_producer() -> (
    None
):
    predicate_ea = 0x1014
    direct_ea = 0x1100
    true_target_ea = 0x2000
    false_target_ea = 0x3000
    cfg = NativeCfg(
        {
            0x1010: NativeBlock(
                start_ea=0x1010,
                end_ea=0x1020,
                outgoing_edges=(
                    NativeEdge(
                        kind=NativeEdgeKind.CONDITIONAL_TRUE,
                        target_ea=true_target_ea,
                        source_instruction_ea=predicate_ea,
                    ),
                    NativeEdge(
                        kind=NativeEdgeKind.CONDITIONAL_FALSE,
                        target_ea=false_target_ea,
                        source_instruction_ea=predicate_ea,
                    ),
                ),
            ),
            direct_ea: NativeBlock(
                start_ea=direct_ea,
                end_ea=0x1110,
                outgoing_edges=(
                    NativeEdge(
                        kind=NativeEdgeKind.DIRECT_JUMP,
                        target_ea=true_target_ea,
                        source_instruction_ea=direct_ea,
                    ),
                ),
            ),
            true_target_ea: NativeBlock(
                start_ea=true_target_ea,
                end_ea=0x2010,
                terminal=NativeTerminalKind.RETURN,
            ),
            false_target_ea: NativeBlock(
                start_ea=false_target_ea,
                end_ea=0x3010,
                terminal=NativeTerminalKind.RETURN,
            ),
        }
    )
    closure = NativeSemanticClosure(
        included_block_eas=(true_target_ea, false_target_ea),
        native_ranges=(
            NativeRange(true_target_ea, 0x2010),
            NativeRange(false_target_ea, 0x3010),
        ),
        proven_internal_edges=(),
        abstentions=(),
        seed_provenance=(),
    )
    incomplete = ComputedGotoPatchPlan(
        jmp_ea=0x1018,
        block_entry=0x1010,
        patch_start=0x1010,
        patch_bytes=b"\x90",
        region_end=0x1020,
        insn_heads=(0x1010, predicate_ea, 0x101A),
        new_block_eas=(predicate_ea, 0x101A),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=5,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
    )
    direct = ComputedGotoPatchPlan(
        jmp_ea=0x1108,
        block_entry=direct_ea,
        patch_start=direct_ea,
        patch_bytes=b"\x90",
        region_end=0x1110,
        insn_heads=(direct_ea,),
        new_block_eas=(direct_ea,),
        target_eas=(true_target_ea,),
    )
    resolution = ComputedGotoResolution(
        function_ea=0x401000,
        jmp_targets={
            incomplete.jmp_ea: incomplete.target_eas,
            direct.jmp_ea: direct.target_eas,
        },
        reachable_eas=(0x401000,),
        arch="x86",
        executed_insns=17,
        seeds_run=0,
        patch_plans=(direct, incomplete),
    )
    state = NativePreanalysisSessionState()
    assert state.set_computed_goto_resolution(NATIVE_KEY, resolution)
    assert state.merge_native_facts(
        NATIVE_KEY,
        native_cfg=cfg,
        semantic_closure=closure,
        boundary_ports=DetachedSnippetBoundaryPorts((), ()),
    )

    with pytest.raises(
        FrontendNormalizationEvidenceRejected,
        match="complete predicate evidence",
    ):
        state.frontend_normalization_evidence_for(NATIVE_KEY)
