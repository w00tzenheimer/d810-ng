"""Canonical semantic-route evidence lowers to portable fragment plans."""

from __future__ import annotations

from dataclasses import replace

import pytest

from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
    SemanticCarrierProof,
    SemanticCorridorPoint,
    SemanticPredicateKind,
    SemanticPredicateProof,
    SemanticRouteDestination,
    SemanticRouteProof,
    SemanticRouteProofKind,
    SemanticRouteShape,
    SemanticStateWriteProof,
    bind_canonical_semantic_evidence,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    TerminalReturnCarrierRequest,
)
from d810.analyses.control_flow.terminal_return_carrier_evidence import (
    TerminalReturnCarrierEvidence,
    TerminalReturnCarrierSource,
    TerminalReturnCarrierSourceKind,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms.canonical_semantic_fragment import (
    CanonicalSemanticFragmentRejected,
    build_canonical_semantic_fragment_plan,
)
from d810.transforms.fragment_plan import (
    FragmentBlockRole,
    FragmentDataFlowRole,
    FragmentPublicationPurpose,
    FragmentReturnSourceKind,
)
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key(function_rva=0x1000)


def _identity(ea: int) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(ea, ea + 1),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(ea,),
    )


def _wide_identity(start_ea: int, end_ea: int) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(start_ea, end_ea),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=range(start_ea, end_ea),
    )


def _block(
    serial: int,
    ea: int,
    *,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    insn_eas: tuple[int, ...] | None = None,
) -> BlockSnapshot:
    insn_eas = (ea,) if insn_eas is None else insn_eas
    return BlockSnapshot(
        serial=serial,
        block_type=len(succs),
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=ea,
        insn_snapshots=tuple(
            InsnSnapshot(opcode=0, ea=insn_ea, operands=())
            for insn_ea in insn_eas
        ),
    )


def _direct_bound_evidence() -> tuple[FlowGraph, object]:
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(20,), preds=()),
            20: _block(20, 0x1100, succs=(30,), preds=(10,)),
            30: _block(30, 0x1400, succs=(20,), preds=(20,)),
            40: _block(40, 0x1200, succs=(), preds=()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    source_identity = _identity(0x1100)
    evidence = CanonicalSemanticEvidence(
        native_key=NATIVE_KEY,
        generation=3,
        atomic_group_id="canonical-semantic:g3",
        route_proofs=(
            SemanticRouteProof(
                proof_id="state-assignment@0x1100",
                atomic_group_id="canonical-semantic:g3",
                proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
                shape=SemanticRouteShape.DIRECT,
                source_identity=source_identity,
                source_anchor_ea=0x1100,
                destinations=(
                    SemanticRouteDestination(
                        role=SemanticEdgeRole.DIRECT,
                        state_constant=0xAABBCCDD,
                        target_identity=_identity(0x1200),
                        target_anchor_ea=0x1200,
                    ),
                ),
                state_write=SemanticStateWriteProof(
                    identity=source_identity,
                    instruction_ea=0x1100,
                    state_variable=StorageIdentity(
                        StorageIdentityKind.REGISTER,
                        20,
                    ),
                    width=4,
                    state_constant=0xAABBCCDD,
                    corridor_instruction_eas=(0x1100,),
                ),
            ),
        ),
    )
    bound = bind_canonical_semantic_evidence(graph, evidence)
    assert bound is not None
    return graph, bound


def test_direct_semantic_route_builds_closed_portable_fragment_plan() -> None:
    graph, bound = _direct_bound_evidence()

    plan = build_canonical_semantic_fragment_plan(
        graph,
        bound,
        prohibited_dispatcher_serials=(30,),
    )

    assert (
        plan.publication_purpose
        is FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING
    )
    assert plan.atomic_group_id == "canonical-semantic:g3"
    assert len(plan.roots) == 1
    root = plan.block(plan.roots[0])
    assert root.role is FragmentBlockRole.REPLACEMENT
    assert root.semantic_anchor_ea == 0x1100
    assert plan.block(str(root.replaces_block_id)).role is FragmentBlockRole.ORIGINAL
    assert tuple(
        (edge.role, plan.block(edge.target_block_id).semantic_anchor_ea)
        for edge in plan.operations[0].edges
    ) == ((SemanticEdgeRole.DIRECT, 0x1200),)
    assert tuple(
        plan.block(block_id).semantic_anchor_ea
        for block_id in plan.prohibited_dispatcher_blocks
    ) == (0x1400,)
    assert any(
        block.role is FragmentBlockRole.EXTERNAL
        and block.semantic_anchor_ea == 0x1000
        for block in plan.blocks
    )
    assert all("serial" not in block.block_id for block in plan.blocks)


def test_partial_bound_atomic_group_is_rejected() -> None:
    graph, bound = _direct_bound_evidence()

    with pytest.raises(
        CanonicalSemanticFragmentRejected,
        match="bound route set does not match atomic evidence",
    ):
        build_canonical_semantic_fragment_plan(
            graph,
            replace(bound, routes=()),
            prohibited_dispatcher_serials=(30,),
        )


def test_storage_conditional_keeps_both_arms_and_data_flow_in_one_plan() -> None:
    producer_identity = _wide_identity(0x1080, 0x1090)
    source_identity = _identity(0x1100)
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(15,), preds=()),
            15: _block(
                15,
                0x1080,
                succs=(20,),
                preds=(10,),
                insn_eas=(0x1080, 0x1088),
            ),
            20: _block(20, 0x1100, succs=(30,), preds=(15,)),
            30: _block(30, 0x1400, succs=(20,), preds=(20,)),
            40: _block(40, 0x1200, succs=(), preds=()),
            50: _block(50, 0x1300, succs=(), preds=()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    predicate_storage = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    carrier_storage = StorageIdentity(StorageIdentityKind.STACK, 0x48)
    proof = SemanticRouteProof(
        proof_id="state-choice@0x1100",
        atomic_group_id="canonical-semantic:g4",
        proof_kind=SemanticRouteProofKind.STATE_CHOICE,
        shape=SemanticRouteShape.CONDITIONAL,
        source_identity=source_identity,
        source_anchor_ea=0x1100,
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                state_constant=0xAABBCCDD,
                target_identity=_identity(0x1200),
                target_anchor_ea=0x1200,
            ),
            SemanticRouteDestination(
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                state_constant=0x11223344,
                target_identity=_identity(0x1300),
                target_anchor_ea=0x1300,
            ),
        ),
        predicate=SemanticPredicateProof(
            kind=SemanticPredicateKind.STORAGE_EQUALS,
            origin=SemanticCorridorPoint(producer_identity, 0x1080),
            consumer=SemanticCorridorPoint(source_identity, 0x1100),
            corridor=(
                SemanticCorridorPoint(producer_identity, 0x1080),
                SemanticCorridorPoint(source_identity, 0x1100),
            ),
            storage_identity=predicate_storage,
            width=4,
            compare_constant=0,
        ),
        carriers=(
            SemanticCarrierProof(
                carrier_id="entry-state-choice",
                definition=SemanticCorridorPoint(producer_identity, 0x1088),
                consumers=(SemanticCorridorPoint(source_identity, 0x1100),),
                corridor=(
                    SemanticCorridorPoint(producer_identity, 0x1088),
                    SemanticCorridorPoint(source_identity, 0x1100),
                ),
                storage_identity=carrier_storage,
                width=4,
                state_values=(0xAABBCCDD, 0x11223344),
                permitted_write_eas=frozenset({0x1088}),
            ),
        ),
    )
    evidence = CanonicalSemanticEvidence(
        native_key=NATIVE_KEY,
        generation=4,
        atomic_group_id="canonical-semantic:g4",
        route_proofs=(proof,),
    )
    bound = bind_canonical_semantic_evidence(graph, evidence)
    assert bound is not None

    plan = build_canonical_semantic_fragment_plan(
        graph,
        bound,
        prohibited_dispatcher_serials=(30,),
    )

    operation = plan.operations[0]
    assert operation.predicate_anchor_ea == 0x1100
    assert operation.roles == frozenset(
        {
            SemanticEdgeRole.CONDITIONAL_TAKEN,
            SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
        }
    )
    assert {obligation.role for obligation in plan.data_flow_obligations} == {
        FragmentDataFlowRole.CONDITION,
        FragmentDataFlowRole.CARRIER,
    }
    condition = next(
        obligation
        for obligation in plan.data_flow_obligations
        if obligation.role is FragmentDataFlowRole.CONDITION
    )
    assert condition.definition.storage_identity == predicate_storage
    assert condition.definition.instruction_ea == 0x1080
    assert condition.uses[0].instruction_ea == 0x1100
    carrier = next(
        obligation
        for obligation in plan.data_flow_obligations
        if obligation.role is FragmentDataFlowRole.CARRIER
    )
    assert carrier.definition.storage_identity == carrier_storage
    assert carrier.definition.instruction_ea == 0x1088
    assert carrier.uses[0].instruction_ea == 0x1100


def test_terminal_route_groups_carrier_return_and_edge_atomically() -> None:
    capture_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1100, 0x1110),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1100, 0x1105),
    )
    terminal_identity = StableBlockIdentity.from_instruction_eas(
        (0x1200, 0x1208),
        native_key=NATIVE_KEY,
    )
    state_constant = 0x19A7218A
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(20,), preds=()),
            20: _block(
                20,
                0x1100,
                succs=(30,),
                preds=(10,),
                insn_eas=(0x1100, 0x1105),
            ),
            30: _block(30, 0x1400, succs=(20, 40), preds=(20,)),
            40: _block(
                40,
                0x1200,
                succs=(),
                preds=(30,),
                insn_eas=(0x1200, 0x1208),
            ),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    carrier = TerminalReturnCarrierEvidence(
        request=TerminalReturnCarrierRequest(
            source_handler_ea=0x1100,
            terminal_target_ea=0x1200,
            state_var_reg=20,
            state_constant=state_constant,
        ),
        capture_identity=capture_identity,
        terminal_identity=terminal_identity,
        state_write_ea=0x1100,
        carrier_ea=0x1105,
        terminal_return_ea=0x1208,
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
        corridor_instruction_eas=(0x1100, 0x1105),
    )
    proof = SemanticRouteProof(
        proof_id="terminal-return@0x1100",
        atomic_group_id="canonical-semantic:g5",
        proof_kind=SemanticRouteProofKind.TERMINAL_RETURN,
        shape=SemanticRouteShape.DIRECT,
        source_identity=capture_identity,
        source_anchor_ea=0x1100,
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.DIRECT,
                state_constant=state_constant,
                target_identity=terminal_identity,
                target_anchor_ea=0x1200,
                terminal=True,
            ),
        ),
        state_write=SemanticStateWriteProof(
            identity=capture_identity,
            instruction_ea=0x1100,
            state_variable=StorageIdentity(
                StorageIdentityKind.REGISTER,
                20,
            ),
            width=4,
            state_constant=state_constant,
            corridor_instruction_eas=(0x1100,),
        ),
        terminal_return_carrier=carrier,
    )
    evidence = CanonicalSemanticEvidence(
        native_key=NATIVE_KEY,
        generation=5,
        atomic_group_id="canonical-semantic:g5",
        route_proofs=(proof,),
    )
    bound = bind_canonical_semantic_evidence(graph, evidence)
    assert bound is not None

    plan = build_canonical_semantic_fragment_plan(
        graph,
        bound,
        prohibited_dispatcher_serials=(30,),
    )

    assert len(plan.return_carriers) == 1
    assert plan.return_carriers[0].carrier_ea == 0x1105
    assert (
        plan.return_carriers[0].source.kind
        is FragmentReturnSourceKind.STORAGE_VALUE
    )
    assert len(plan.terminal_returns) == 1
    terminal_return = plan.terminal_returns[0]
    assert terminal_return.instruction_ea == 0x1208
    assert plan.block(terminal_return.block_id).role is FragmentBlockRole.REPLACEMENT
    assert len(plan.terminal_routes) == 1
    assert plan.terminal_routes[0].operation_id == plan.operations[0].operation_id
    assert len(plan.owned_originals) == 2


def test_terminal_routes_share_one_owned_return_block_atomically() -> None:
    terminal_identity = _identity(0x1200)
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(20, 25), preds=()),
            20: _block(
                20,
                0x1100,
                succs=(30,),
                preds=(10,),
                insn_eas=(0x1100, 0x1105),
            ),
            25: _block(
                25,
                0x1150,
                succs=(30,),
                preds=(10,),
                insn_eas=(0x1150, 0x1155),
            ),
            30: _block(30, 0x1400, succs=(20, 25, 40), preds=(20, 25)),
            40: _block(40, 0x1200, succs=(), preds=(30,)),
        },
        entry_serial=10,
        func_ea=0x1000,
    )

    def terminal_proof(
        source_ea: int,
        carrier_ea: int,
        state_constant: int,
    ) -> SemanticRouteProof:
        capture_identity = StableBlockIdentity.from_intervals(
            (NativeEaInterval(source_ea, source_ea + 0x10),),
            native_key=NATIVE_KEY,
            exact_instruction_eas=(source_ea, carrier_ea),
        )
        carrier = TerminalReturnCarrierEvidence(
            request=TerminalReturnCarrierRequest(
                source_handler_ea=source_ea,
                terminal_target_ea=0x1200,
                state_var_reg=20,
                state_constant=state_constant,
            ),
            capture_identity=capture_identity,
            terminal_identity=terminal_identity,
            state_write_ea=source_ea,
            carrier_ea=carrier_ea,
            terminal_return_ea=0x1200,
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
            corridor_instruction_eas=(source_ea, carrier_ea),
        )
        return SemanticRouteProof(
            proof_id=f"terminal-return@0x{source_ea:X}",
            atomic_group_id="canonical-semantic:shared-terminal",
            proof_kind=SemanticRouteProofKind.TERMINAL_RETURN,
            shape=SemanticRouteShape.DIRECT,
            source_identity=capture_identity,
            source_anchor_ea=source_ea,
            destinations=(
                SemanticRouteDestination(
                    role=SemanticEdgeRole.DIRECT,
                    state_constant=state_constant,
                    target_identity=terminal_identity,
                    target_anchor_ea=0x1200,
                    terminal=True,
                ),
            ),
            state_write=SemanticStateWriteProof(
                identity=capture_identity,
                instruction_ea=source_ea,
                state_variable=StorageIdentity(
                    StorageIdentityKind.REGISTER,
                    20,
                ),
                width=4,
                state_constant=state_constant,
                corridor_instruction_eas=(source_ea,),
            ),
            terminal_return_carrier=carrier,
        )

    evidence = CanonicalSemanticEvidence(
        native_key=NATIVE_KEY,
        generation=6,
        atomic_group_id="canonical-semantic:shared-terminal",
        route_proofs=(
            terminal_proof(0x1100, 0x1105, 0x11),
            terminal_proof(0x1150, 0x1155, 0x22),
        ),
    )
    bound = bind_canonical_semantic_evidence(graph, evidence)
    assert bound is not None

    plan = build_canonical_semantic_fragment_plan(
        graph,
        bound,
        prohibited_dispatcher_serials=(30,),
    )

    assert len(plan.return_carriers) == 2
    assert len(plan.terminal_routes) == 2
    assert len(plan.terminal_returns) == 1
    assert len(plan.owned_originals) == 3
    assert {
        route.return_id for route in plan.terminal_routes
    } == {plan.terminal_returns[0].return_id}


def test_dispatcher_fed_semantic_target_remains_internal_not_a_root() -> None:
    def direct_proof(
        source_ea: int,
        target_ea: int,
        state_constant: int,
    ) -> SemanticRouteProof:
        source_identity = _identity(source_ea)
        return SemanticRouteProof(
            proof_id=f"state-assignment@0x{source_ea:X}",
            atomic_group_id="canonical-semantic:g6",
            proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
            shape=SemanticRouteShape.DIRECT,
            source_identity=source_identity,
            source_anchor_ea=source_ea,
            destinations=(
                SemanticRouteDestination(
                    role=SemanticEdgeRole.DIRECT,
                    state_constant=state_constant,
                    target_identity=_identity(target_ea),
                    target_anchor_ea=target_ea,
                ),
            ),
            state_write=SemanticStateWriteProof(
                identity=source_identity,
                instruction_ea=source_ea,
                state_variable=StorageIdentity(
                    StorageIdentityKind.REGISTER,
                    20,
                ),
                width=4,
                state_constant=state_constant,
                corridor_instruction_eas=(source_ea,),
            ),
        )

    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(20,), preds=()),
            20: _block(20, 0x1100, succs=(90,), preds=(10,)),
            30: _block(30, 0x1200, succs=(90,), preds=(90,)),
            40: _block(40, 0x1300, succs=(), preds=()),
            90: _block(90, 0x1400, succs=(20, 30), preds=(20, 30)),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    evidence = CanonicalSemanticEvidence(
        native_key=NATIVE_KEY,
        generation=6,
        atomic_group_id="canonical-semantic:g6",
        route_proofs=(
            direct_proof(0x1100, 0x1200, 0x11),
            direct_proof(0x1200, 0x1300, 0x22),
        ),
    )
    bound = bind_canonical_semantic_evidence(graph, evidence)
    assert bound is not None

    plan = build_canonical_semantic_fragment_plan(
        graph,
        bound,
        prohibited_dispatcher_serials=(90,),
    )

    assert tuple(plan.block(root).semantic_anchor_ea for root in plan.roots) == (
        0x1100,
    )
    first_operation = next(
        operation
        for operation in plan.operations
        if plan.block(operation.source_block_id).semantic_anchor_ea == 0x1100
    )
    assert (
        plan.block(first_operation.edges[0].target_block_id).role
        is FragmentBlockRole.REPLACEMENT
    )
    assert (
        plan.block(first_operation.edges[0].target_block_id).semantic_anchor_ea
        == 0x1200
    )


def test_shared_external_target_rejects_bound_identity_drift() -> None:
    def direct_proof(source_ea: int, state_constant: int) -> SemanticRouteProof:
        source_identity = _identity(source_ea)
        return SemanticRouteProof(
            proof_id=f"state-assignment@0x{source_ea:X}",
            atomic_group_id="canonical-semantic:shared-external",
            proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
            shape=SemanticRouteShape.DIRECT,
            source_identity=source_identity,
            source_anchor_ea=source_ea,
            destinations=(
                SemanticRouteDestination(
                    role=SemanticEdgeRole.DIRECT,
                    state_constant=state_constant,
                    target_identity=_identity(0x1300),
                    target_anchor_ea=0x1300,
                ),
            ),
            state_write=SemanticStateWriteProof(
                identity=source_identity,
                instruction_ea=source_ea,
                state_variable=StorageIdentity(
                    StorageIdentityKind.REGISTER,
                    20,
                ),
                width=4,
                state_constant=state_constant,
                corridor_instruction_eas=(source_ea,),
            ),
        )

    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(20, 30), preds=()),
            20: _block(20, 0x1100, succs=(90,), preds=(10,)),
            30: _block(30, 0x1200, succs=(90,), preds=(10,)),
            40: _block(40, 0x1300, succs=(), preds=(90,)),
            90: _block(90, 0x1400, succs=(20, 30, 40), preds=(20, 30)),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    evidence = CanonicalSemanticEvidence(
        native_key=NATIVE_KEY,
        generation=7,
        atomic_group_id="canonical-semantic:shared-external",
        route_proofs=(
            direct_proof(0x1100, 0x11),
            direct_proof(0x1200, 0x22),
        ),
    )
    bound = bind_canonical_semantic_evidence(graph, evidence)
    assert bound is not None
    second_route = bound.routes[1]
    second_destination = second_route.destinations[0]
    corrupted = replace(
        bound,
        routes=(
            bound.routes[0],
            replace(
                second_route,
                destinations=(
                    replace(
                        second_destination,
                        block=replace(
                            second_destination.block,
                            identity=_wide_identity(0x1300, 0x1310),
                        ),
                    ),
                ),
            ),
        ),
    )

    with pytest.raises(
        CanonicalSemanticFragmentRejected,
        match="external identity drifted",
    ):
        build_canonical_semantic_fragment_plan(
            graph,
            corrupted,
            prohibited_dispatcher_serials=(90,),
        )
