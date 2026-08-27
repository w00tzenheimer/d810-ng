"""Portable semantic-route evidence and all-or-nothing live binding."""

from __future__ import annotations

from dataclasses import replace
import copy
import gc
import weakref
from types import SimpleNamespace

import pytest
import d810.analyses.control_flow.semantic_route_evidence as route_evidence

from d810.backends.hexrays.evidence.condition_chain_analysis import (
    build_condition_chain_walker_provider,
)
from d810.capabilities.providers import (
    register_condition_chain_walkers,
    reset_providers_for_tests,
)

from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalRouteAssessment,
    CanonicalRouteMaterialization,
    CanonicalRouteAssessmentPhase,
    CanonicalRouteAssessmentRejection,
    CanonicalRouteBindingFailure,
    CanonicalRouteBindingResult,
    CanonicalRouteBindingStage,
    CanonicalSemanticEvidence,
    CanonicalSemanticEvidenceProductionAbstention,
    CanonicalSemanticEvidenceProductionContext,
    CanonicalSemanticEvidenceProductionReason,
    CanonicalSemanticEvidenceProductionResult,
    CanonicalSemanticEvidenceProductionStage,
    SemanticRouteFact,
    SemanticRouteFactKind,
    SemanticBootstrapRouteWitness,
    DecisionDagRouteWitness,
    SemanticDagComparison,
    SemanticDecisionDagWitness,
    SemanticCarrierProof,
    SemanticCorridorPoint,
    SemanticPredicateKind,
    SemanticPredicateProof,
    SemanticRouteDestination,
    SemanticRouteEvidenceRejected,
    SemanticRouteProof,
    SemanticRouteProofKind,
    SemanticRouteShape,
    SemanticStateWriteDeliveryKind,
    SemanticStateWriteProof,
    SemanticStateDagProof,
    SemanticStatePartitionProof,
    SemanticPartitionMemberProof,
    StatePartitionMemberWitness,
    StatePartitionGroupWitness,
    assess_canonical_route,
    bind_canonical_semantic_evidence,
    bind_canonical_semantic_evidence_result,
    build_canonical_semantic_evidence,
    canonical_semantic_evidence_from_proofs,
    prove_partitioned_state_member,
    validate_canonical_route_materialization,
    validate_canonical_route_assessment,
)
from d810.analyses.control_flow.route_comparison import current_u32_route_comparison
from d810.analyses.control_flow.route_predicate import RouteComparison
from d810.analyses.control_flow.semantic_transition import NativeBoundTransitionRoute
from d810.analyses.control_flow.state_carrier import (
    ExactCarrierStateWrite,
    prove_exact_u32_state_transform_feeder,
)
from d810.transforms.unflatten_authority.ids import canonical_bytes, semantic_graph_fingerprint
from d810.capabilities.semantic_routes import CanonicalSemanticEvidenceCapability
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.ir.flowgraph import InsnKind, MopSnapshot, OperandKind, PredicateKind
from d810.ir.semantics import CallKind, ControlTransferKind
from d810.ir.insn_projection import project_instruction_effect_sites
from d810.ir.instructions import InstructionEffectKind, InstructionEffectSite
from d810.ir.expressions import ValueOpKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.ir.varnode import Space, Varnode
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key(function_rva=0x1000)


def _accepted(result):
    assert result.abstention is None
    assert result.evidence is not None
    return result.evidence


def _recanonicalize_evidence(
    evidence: CanonicalSemanticEvidence,
    route_proofs: tuple[SemanticRouteProof, ...],
) -> CanonicalSemanticEvidence:
    return canonical_semantic_evidence_from_proofs(
        native_key=evidence.native_key,
        generation=evidence.generation,
        proofs=route_proofs,
    )


def _unsafe_evidence(
    evidence: CanonicalSemanticEvidence,
    route_proofs: tuple[SemanticRouteProof, ...],
) -> CanonicalSemanticEvidence:
    forged = object.__new__(CanonicalSemanticEvidence)
    object.__setattr__(forged, "native_key", evidence.native_key)
    object.__setattr__(forged, "generation", evidence.generation)
    object.__setattr__(forged, "atomic_group_id", evidence.atomic_group_id)
    object.__setattr__(forged, "route_proofs", route_proofs)
    return forged


def _native_bound_production_inputs(*, generation: int = 1):
    graph = _direct_graph()
    identities = {serial: _identity(int(block.start_ea)) for serial, block in graph.blocks.items()}
    fact = SemanticRouteFact(
        SemanticRouteFactKind.NATIVE_BOUND,
        1,
        1,
        0x1100,
        0xAABBCCDD,
        2,
        None,
        None,
        (1,),
        (),
        "native:typed-result",
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        generation,
        "canonical-semantic:typed-result",
        StorageIdentity(StorageIdentityKind.REGISTER, 20),
        tuple(graph.blocks.values()),
        tuple(identities.items()),
    )
    return fact, context


def test_production_result_abstains_with_closed_empty_group_reason() -> None:
    _fact, context = _native_bound_production_inputs()
    result = build_canonical_semantic_evidence((), context)
    assert result.evidence is None
    assert result.abstention is not None
    assert result.abstention.reason is CanonicalSemanticEvidenceProductionReason.EMPTY_GROUP
    assert result.abstention.stage is CanonicalSemanticEvidenceProductionStage.GROUP


def test_canonical_ids_ignore_human_group_and_fact_labels() -> None:
    fact, context = _native_bound_production_inputs()
    labeled = _accepted(build_canonical_semantic_evidence((fact,), context))
    relabeled = _accepted(build_canonical_semantic_evidence(
        (replace(fact, fact_id="a-different-diagnostic-label"),),
        replace(context, atomic_group_id="another-human-group-label"),
    ))

    assert relabeled.atomic_group_id == labeled.atomic_group_id
    assert tuple(proof.proof_id for proof in relabeled.route_proofs) == tuple(
        proof.proof_id for proof in labeled.route_proofs
    )


def test_canonical_ids_ignore_serial_permutation_of_equivalent_inputs() -> None:
    fact, context = _native_bound_production_inputs()
    original = _accepted(build_canonical_semantic_evidence((fact,), context))

    serial_map = {0: 10, 1: 20, 2: 30}
    permuted_blocks = tuple(
        replace(
            block,
            serial=serial_map[block.serial],
            succs=tuple(serial_map[item] for item in block.succs),
            preds=tuple(serial_map[item] for item in block.preds),
        )
        for block in reversed(context.blocks)
    )
    permuted_fact = replace(
        fact,
        owner_serial=serial_map[fact.owner_serial],
        source_serial=serial_map[fact.source_serial],
        target_serial=serial_map[fact.target_serial],
        path_serials=tuple(serial_map[item] for item in fact.path_serials),
        path_edges=tuple(
            (serial_map[source], serial_map[target])
            for source, target in fact.path_edges
        ),
    )
    permuted_context = replace(
        context,
        atomic_group_id="permuted-human-group-label",
        blocks=permuted_blocks,
        identities_by_serial=tuple(
            (serial_map[serial], identity)
            for serial, identity in reversed(context.identities_by_serial)
        ),
        entry_serial=serial_map[context.entry_serial],
    )
    permuted = _accepted(build_canonical_semantic_evidence(
        (permuted_fact,), permuted_context,
    ))

    assert permuted.atomic_group_id == original.atomic_group_id
    assert tuple(proof.proof_id for proof in permuted.route_proofs) == tuple(
        proof.proof_id for proof in original.route_proofs
    )


@pytest.mark.parametrize("forgery", ("group", "proof", "coordinated"))
def test_canonical_model_rejects_forged_content_ids(forgery: str) -> None:
    fact, context = _native_bound_production_inputs()
    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    forged_group = "sha256:" + "1" * 64
    forged_proof = "sha256:" + "2" * 64
    group_id = forged_group if forgery != "proof" else evidence.atomic_group_id
    proof_group = forged_group if forgery != "proof" else evidence.atomic_group_id
    proof_id = forged_proof if forgery != "group" else evidence.route_proofs[0].proof_id
    forged = object.__new__(CanonicalSemanticEvidence)
    object.__setattr__(forged, "native_key", evidence.native_key)
    object.__setattr__(forged, "generation", evidence.generation)
    object.__setattr__(forged, "atomic_group_id", group_id)
    object.__setattr__(
        forged,
        "route_proofs",
        (replace(
            evidence.route_proofs[0],
            atomic_group_id=proof_group,
            proof_id=proof_id,
        ),),
    )

    with pytest.raises(SemanticRouteEvidenceRejected, match="(content-derived|one atomic group)"):
        CanonicalSemanticEvidence.__post_init__(forged)
    binding = bind_canonical_semantic_evidence_result(_direct_graph(), forged)
    assert binding.bound_evidence is None
    assert tuple(item.stage for item in binding.failures) == (
        CanonicalRouteBindingStage.CANONICAL_IDENTITY,
    )
    with pytest.raises(SemanticRouteEvidenceRejected, match="content-derived"):
        assess_canonical_route(
            CanonicalRouteMaterialization.capture(
                _direct_graph(),
                phase=CanonicalRouteAssessmentPhase.SOURCE,
                generation=evidence.generation,
            ),
            forged,
        )


def test_canonical_model_rejects_human_supplied_ids() -> None:
    with pytest.raises(SemanticRouteEvidenceRejected, match="(content-derived|one atomic group)"):
        CanonicalSemanticEvidence(
            native_key=NATIVE_KEY,
            generation=3,
            atomic_group_id="human-group",
            route_proofs=(_proof(),),
        )


def test_factory_rejects_legacy_call_shapes() -> None:
    with pytest.raises(TypeError):
        canonical_semantic_evidence_from_proofs(
            native_key=NATIVE_KEY,
            generation=3,
            route_proofs=(_proof(),),
        )
    with pytest.raises(TypeError):
        canonical_semantic_evidence_from_proofs(
            NATIVE_KEY, 3, "human-group", (_proof(),),
        )


def test_route_materialization_uses_typed_graph_projection_for_transitional_opaque_operands() -> None:
    graph = _direct_graph()
    original = graph.blocks[1].insn_snapshots[0]
    opaque = replace(
        original,
        operands=(object(), object()),
        operand_slots=(("l", object()), ("d", object())),
    )
    graph = FlowGraph(
        {**graph.blocks, 1: replace(graph.blocks[1], insn_snapshots=(opaque,))},
        graph.entry_serial,
        graph.func_ea,
    )
    assert semantic_graph_fingerprint(graph)
    materialization = CanonicalRouteMaterialization.capture(
        graph,
        phase=CanonicalRouteAssessmentPhase.SOURCE,
        generation=3,
    )
    assert materialization.graph_fingerprint == semantic_graph_fingerprint(graph)


def test_production_result_requires_exactly_one_outcome() -> None:
    with pytest.raises(ValueError, match="exactly one outcome"):
        CanonicalSemanticEvidenceProductionResult()


def test_production_result_abstains_with_typed_negative_generation_context() -> None:
    fact, context = _native_bound_production_inputs(generation=-1)
    result = build_canonical_semantic_evidence((fact,), context)
    assert result.evidence is None
    assert result.abstention is not None
    assert result.abstention.reason is CanonicalSemanticEvidenceProductionReason.NEGATIVE_GENERATION
    assert result.abstention.stage is CanonicalSemanticEvidenceProductionStage.CONTEXT


def test_production_result_carries_fact_coordinate_for_missing_identity() -> None:
    fact, context = _native_bound_production_inputs()
    result = build_canonical_semantic_evidence((replace(fact, target_serial=99),), context)
    assert result.abstention is not None
    assert result.abstention.reason is CanonicalSemanticEvidenceProductionReason.ASSIGNMENT_IDENTITY_MISSING
    assert result.abstention.stage is CanonicalSemanticEvidenceProductionStage.FACT
    assert result.abstention.coordinate is not None
    assert result.abstention.coordinate.target_serial == 99


def test_bootstrap_production_uses_bootstrap_identity_reason() -> None:
    fact, context = _native_bound_production_inputs()
    witness = SemanticBootstrapRouteWitness(
        entry_serial=0,
        source_serial=1,
        source_instruction_ea=0x1100,
        owner_serial=2,
        dispatcher_serial=3,
        state_identity=context.state_identity,
        state_constant=fact.state_constant,
        state_width=4,
        corridor_serials=(1, 2, 3),
        corridor_anchors=(0x1100, 0x1200, 0x1300),
        preserved_effect_sites=(),
        decision_dag_witness=DecisionDagRouteWitness(
            context.state_identity,
            fact.state_constant,
            2,
            0x1200,
            (2,),
            (0x1200,),
            (),
            (),
        ),
    )
    bootstrap_fact = replace(
        fact,
        kind=SemanticRouteFactKind.BOOTSTRAP,
        owner_serial=2,
        source_serial=1,
        source_instruction_ea=0x1100,
        target_serial=2,
        path_serials=(1, 2),
        path_edges=((1, 2),),
        bootstrap_witness=witness,
        decision_dag_witness=witness.decision_dag_witness,
    )
    result = build_canonical_semantic_evidence((bootstrap_fact,), context)
    assert result.evidence is None
    assert result.abstention is not None
    assert result.abstention.reason is CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_IDENTITY_MISSING
    assert result.abstention.stage is CanonicalSemanticEvidenceProductionStage.FACT


def test_forged_raw_bootstrap_record_abstains_without_attribute_leak() -> None:
    fact, context = _native_bound_production_inputs()
    forged = copy.copy(fact)
    object.__setattr__(forged, "kind", SemanticRouteFactKind.BOOTSTRAP)
    object.__setattr__(forged, "bootstrap_witness", None)
    result = build_canonical_semantic_evidence((forged,), context)
    assert result.evidence is None
    assert result.abstention is not None
    assert result.abstention.reason is CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_IDENTITY_MISSING
    assert result.abstention.stage is CanonicalSemanticEvidenceProductionStage.FACT


def test_bootstrap_production_and_binding_replay_entry_corridor() -> None:
    state = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    constant = 0xB2FD8FB6

    def identity(ea: int, *instruction_eas: int) -> StableBlockIdentity:
        return StableBlockIdentity.from_intervals(
            (NativeEaInterval(ea, ea + 0x20),),
            native_key=NATIVE_KEY,
            exact_instruction_eas=instruction_eas or (ea,),
        )

    def call(ea: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=0,
            ea=ea,
            operands=(),
            kind=InsnKind.CALL,
            call_kind=CallKind.DIRECT,
            l=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=0x1234),
        )

    branch = InsnSnapshot(
        opcode=0,
        ea=0x1601,
        operands=(),
        kind=InsnKind.COND_JUMP,
        control_transfer_kind=ControlTransferKind.CONDITIONAL_BRANCH,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=constant),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=7),
    )
    state_store = InsnSnapshot(
        opcode=0,
        ea=0x1109,
        operands=(),
        kind=InsnKind.STORE,
        value_op_kind=ValueOpKind.STORE,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=constant),
        d=MopSnapshot(
            kind=OperandKind.ADDRESS,
            size=8,
            stack_refs=(0x40,),
            sub_l=MopSnapshot(
                kind=OperandKind.STACK,
                size=4,
                stkoff=0x40,
                stack_refs=(0x40,),
            ),
        ),
    )
    graph = FlowGraph(
        blocks={
            0: _block(0, 0x1000, succs=(1,), preds=()),
            1: replace(
                _block(1, 0x1100, succs=(3,), preds=(0,)),
                insn_snapshots=(state_store,),
            ),
            3: replace(_block(3, 0x1300, succs=(5,), preds=(1,)), insn_snapshots=(call(0x1308),)),
            5: replace(_block(5, 0x1500, succs=(6,), preds=(3,)), insn_snapshots=(call(0x1508),)),
            6: replace(_block(6, 0x1600, succs=(7, 11), preds=(5,)), insn_snapshots=(branch,)),
            7: _block(7, 0x1700, succs=(), preds=(6,)),
            11: _block(11, 0x1B00, succs=(), preds=(6,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    identities = tuple(
        (
            serial,
            identity(
                block.start_ea,
                *(instruction.ea for instruction in block.insn_snapshots),
            ),
        )
        for serial, block in graph.blocks.items()
    )
    dag = DecisionDagRouteWitness(
        state,
        constant,
        6,
        0x1600,
        (6,),
        (0x1600,),
        ((6, RouteComparison(6, "jz", constant, 7, 11)),),
        (),
    )
    bootstrap = SemanticBootstrapRouteWitness(
        0,
        1,
        0x1109,
        5,
        6,
        state,
        constant,
        4,
        (1, 3, 5, 6),
        (0x1109, 0x1300, 0x1500, 0x1600),
        (
            InstructionEffectSite(0x1109, InstructionEffectKind.STORE, 0x1109),
            InstructionEffectSite(0x1308, InstructionEffectKind.CALL, 0x1308),
            InstructionEffectSite(0x1508, InstructionEffectKind.CALL, 0x1508),
        ),
        dag,
    )
    fact = SemanticRouteFact(
        kind=SemanticRouteFactKind.BOOTSTRAP,
        owner_serial=5,
        source_serial=1,
        source_instruction_ea=0x1109,
        state_constant=constant,
        target_serial=7,
        owner_anchor_ea=0x1500,
        target_anchor_ea=0x1700,
        path_serials=(1, 3, 5),
        path_edges=((1, 3), (3, 5)),
        fact_id="bootstrap:hodur",
        decision_dag_witness=dag,
        bootstrap_witness=bootstrap,
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        1,
        "canonical-semantic:bootstrap",
        state,
        tuple(graph.blocks.values()),
        identities,
        0,
    )
    result = build_canonical_semantic_evidence((fact,), context)
    evidence = _accepted(result)
    assert bind_canonical_semantic_evidence(graph, evidence) is not None
    proof = evidence.route_proofs[0]
    assert canonical_bytes(proof.bootstrap) == canonical_bytes(proof.bootstrap)
    assert canonical_bytes(evidence) == canonical_bytes(evidence)
    with pytest.raises(TypeError, match="no canonical encoding"):
        canonical_bytes(bootstrap)

    # Reads/comparisons of the state cell remain valid after the exact write.
    state_read = InsnSnapshot(
        opcode=0,
        ea=0x1110,
        operands=(),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=10),
    )
    read_graph = replace(
        graph,
        blocks={
            **graph.blocks,
            1: replace(graph.blocks[1], insn_snapshots=(state_store, state_read)),
        },
    )
    assert bind_canonical_semantic_evidence(read_graph, evidence) is not None

    def bind_with_extra_source_instructions(
        *extras: InsnSnapshot,
        expect_bound: bool = False,
    ) -> None:
        extra_graph = replace(
            graph,
            blocks={
                **graph.blocks,
                1: replace(
                    graph.blocks[1],
                    insn_snapshots=(state_store, *extras),
                ),
            },
        )
        extra_effects = project_instruction_effect_sites(
            replace(graph.blocks[1], insn_snapshots=extras)
        )
        extra_bootstrap = replace(
            proof.bootstrap,
            preserved_effect_sites=tuple(
                sorted(
                    (*proof.bootstrap.preserved_effect_sites, *extra_effects),
                    key=lambda site: (site.instruction_ea, site.host_instruction_ea, site.kind.value),
                )
            ),
        )
        extra_proof = replace(proof, bootstrap=extra_bootstrap)
        extra_evidence = _recanonicalize_evidence(evidence, (extra_proof,))
        bound = bind_canonical_semantic_evidence(extra_graph, extra_evidence)
        assert (bound is not None) is expect_bound

    address_materialization = InsnSnapshot(
        opcode=0,
        ea=0x1111,
        operands=(),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
        l=MopSnapshot(
            kind=OperandKind.ADDRESS,
            size=8,
            stack_refs=(0x40,),
            sub_l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
        ),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=10),
    )
    address_call = InsnSnapshot(
        opcode=0,
        ea=0x1112,
        operands=(),
        kind=InsnKind.CALL,
        call_kind=CallKind.DIRECT,
        l=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=10),
    )
    bind_with_extra_source_instructions(address_materialization, address_call)

    address_store = replace(
        state_store,
        ea=0x1112,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=10),
    )
    bind_with_extra_source_instructions(address_materialization, address_store)

    unrelated_store = replace(
        state_store,
        ea=0x1113,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=9),
        d=MopSnapshot(
            kind=OperandKind.ADDRESS,
            size=8,
            stack_refs=(0x60,),
            sub_l=MopSnapshot(
                kind=OperandKind.STACK,
                size=4,
                stkoff=0x60,
                stack_refs=(0x60,),
            ),
        ),
    )
    bind_with_extra_source_instructions(unrelated_store, expect_bound=True)

    def forged_evidence(forged_proof):
        altered = copy.copy(evidence)
        object.__setattr__(altered, "route_proofs", (forged_proof,))
        return altered

    # Destination target drift cannot be hidden by an unchanged embedded DAG.
    forged_destination = replace(
        proof.destinations[0],
        target_identity=dict(identities)[11],
        target_anchor_ea=0x1B00,
    )
    forged_proof = copy.copy(proof)
    object.__setattr__(forged_proof, "destinations", (forged_destination,))
    assert bind_canonical_semantic_evidence(graph, forged_evidence(forged_proof)) is None

    # A bootstrap-local state write drift cannot be accepted against proof.state_write.
    forged_bootstrap = copy.copy(proof.bootstrap)
    object.__setattr__(
        forged_bootstrap,
        "state_write",
        replace(proof.bootstrap.state_write, state_constant=0x12345678),
    )
    forged_proof = copy.copy(proof)
    object.__setattr__(forged_proof, "bootstrap", forged_bootstrap)
    assert bind_canonical_semantic_evidence(graph, forged_evidence(forged_proof)) is None

    # A bootstrap-local DAG target drift cannot be accepted against the route.
    forged_bootstrap = copy.copy(proof.bootstrap)
    object.__setattr__(
        forged_bootstrap,
        "state_dag",
        replace(
            proof.bootstrap.state_dag,
            target_identity=dict(identities)[11],
            target_anchor_ea=0x1B00,
        ),
    )
    forged_proof = copy.copy(proof)
    object.__setattr__(forged_proof, "bootstrap", forged_bootstrap)
    assert bind_canonical_semantic_evidence(graph, forged_evidence(forged_proof)) is None

    drifted = replace(graph.blocks[3], preds=(1, 11))
    drifted_graph = replace(graph, blocks={**graph.blocks, 3: drifted})
    assert bind_canonical_semantic_evidence(drifted_graph, evidence) is None

    # Constructor-bypassed nested DAG proposals remain typed producer
    # abstentions instead of leaking shape errors from canonicalization.
    for field_name in ("aliases", "comparisons", "path_serials"):
        malformed_dag = copy.copy(dag)
        object.__setattr__(malformed_dag, field_name, None)
        malformed_bootstrap = copy.copy(bootstrap)
        object.__setattr__(malformed_bootstrap, "decision_dag_witness", malformed_dag)
        malformed_fact = copy.copy(fact)
        object.__setattr__(malformed_fact, "decision_dag_witness", malformed_dag)
        object.__setattr__(malformed_fact, "bootstrap_witness", malformed_bootstrap)
        result = build_canonical_semantic_evidence((malformed_fact,), context)
        assert result.evidence is None
        assert result.abstention is not None
        assert result.abstention.reason is CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_DAG_INVALID
        assert result.abstention.stage is CanonicalSemanticEvidenceProductionStage.FACT

    malformed_bootstrap = copy.copy(bootstrap)
    object.__setattr__(malformed_bootstrap, "corridor_serials", None)
    malformed_fact = copy.copy(fact)
    object.__setattr__(malformed_fact, "bootstrap_witness", malformed_bootstrap)
    result = build_canonical_semantic_evidence((malformed_fact,), context)
    assert result.evidence is None
    assert result.abstention is not None
    assert result.abstention.reason is CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_CORRIDOR_INVALID
    assert result.abstention.stage is CanonicalSemanticEvidenceProductionStage.FACT


def test_shared_effect_site_projection_keeps_nested_call_and_store_hosts() -> None:
    nested_call = MopSnapshot(
        kind=OperandKind.SUBINSN,
        sub_kind=InsnKind.CALL,
        sub_l=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=0x1234),
    )
    nested_store = MopSnapshot(
        kind=OperandKind.SUBINSN,
        sub_kind=InsnKind.STORE,
        sub_l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
    )
    block = _block(
        1,
        0x1100,
        succs=(),
        preds=(),
        insn_eas=(),
    )
    block = replace(
        block,
        insn_snapshots=(
            InsnSnapshot(
                opcode=0,
                ea=0x1120,
                operands=(),
                kind=InsnKind.MOV,
                value_op_kind=ValueOpKind.MOVE,
                l=nested_call,
            ),
            InsnSnapshot(
                opcode=0,
                ea=0x1130,
                operands=(),
                kind=InsnKind.MOV,
                value_op_kind=ValueOpKind.MOVE,
                l=nested_store,
            ),
            InsnSnapshot(
                opcode=0,
                ea=0x1140,
                operands=(),
                kind=InsnKind.CALL,
                call_kind=CallKind.DIRECT,
            ),
            InsnSnapshot(
                opcode=0,
                ea=0x1150,
                operands=(),
                kind=InsnKind.MOV,
                value_op_kind=ValueOpKind.MOVE,
                l=nested_call,
                r=nested_store,
            ),
            InsnSnapshot(
                opcode=0,
                ea=0x1160,
                operands=(),
                kind=InsnKind.MOV,
                value_op_kind=ValueOpKind.MOVE,
                l=nested_call,
                r=nested_call,
            ),
        ),
    )
    sites = project_instruction_effect_sites(block)
    assert tuple((site.instruction_ea, site.kind) for site in sites) == (
        (0x1120, InstructionEffectKind.CALL),
        (0x1130, InstructionEffectKind.STORE),
        (0x1140, InstructionEffectKind.CALL),
        (0x1150, InstructionEffectKind.CALL),
        (0x1150, InstructionEffectKind.STORE),
        (0x1160, InstructionEffectKind.CALL),
        (0x1160, InstructionEffectKind.CALL),
    )


def test_production_result_abstains_on_missing_dag_path_anchor() -> None:
    fact, context = _native_bound_production_inputs()
    dag_fact = replace(
        fact,
        kind=SemanticRouteFactKind.DECISION_DAG,
        decision_dag_witness=DecisionDagRouteWitness(
            context.state_identity,
            fact.state_constant,
            1,
            0x9999,
            (1,),
            (0x9999,),
            (),
            (),
        ),
    )
    result = build_canonical_semantic_evidence((dag_fact,), context)
    assert result.abstention is not None
    assert result.abstention.reason is CanonicalSemanticEvidenceProductionReason.DECISION_DAG_PATH_ANCHOR


def test_production_result_converts_only_final_model_rejection(monkeypatch) -> None:
    fact, context = _native_bound_production_inputs()

    class RejectingModel:
        def __init__(self, **_kwargs):
            raise SemanticRouteEvidenceRejected("model rejection")

    monkeypatch.setattr(route_evidence, "CanonicalSemanticEvidence", RejectingModel)
    result = build_canonical_semantic_evidence((fact,), context)
    assert result.abstention is not None
    assert result.abstention.reason is CanonicalSemanticEvidenceProductionReason.CANONICAL_MODEL_REJECTED
    assert result.abstention.stage is CanonicalSemanticEvidenceProductionStage.CANONICAL_MODEL


def test_production_result_propagates_unexpected_model_exception(monkeypatch) -> None:
    fact, context = _native_bound_production_inputs()

    class ExplodingModel:
        def __init__(self, **_kwargs):
            raise RuntimeError("unexpected model failure")

    monkeypatch.setattr(route_evidence, "CanonicalSemanticEvidence", ExplodingModel)
    with pytest.raises(RuntimeError, match="unexpected model failure"):
        build_canonical_semantic_evidence((fact,), context)


def _typed_dag_fact(
    *,
    aliases: tuple[tuple[int, int], ...] = (),
    comparisons: tuple[tuple[int, RouteComparison], ...] = (),
    state_identity: StorageIdentity | None = None,
):
    fact, context = _native_bound_production_inputs()
    return (
        replace(
            fact,
            kind=SemanticRouteFactKind.DECISION_DAG,
            decision_dag_witness=DecisionDagRouteWitness(
                context.state_identity if state_identity is None else state_identity,
                fact.state_constant,
                1,
                0x1100,
                (1,),
                (0x1100,),
                comparisons,
                aliases,
            ),
        ),
        context,
    )


@pytest.mark.parametrize(
    ("aliases", "comparisons", "reason"),
    (
        (
            ((1, 2), (1, 2)),
            (),
            "decision_dag_alias_duplicate_source",
        ),
        (
            (),
            (
                (2, RouteComparison(2, "jz", 1, 2, 1)),
                (2, RouteComparison(2, "jz", 1, 2, 1)),
            ),
            "decision_dag_comparison_duplicate_node",
        ),
        (
            ((2, 1),),
            ((2, RouteComparison(2, "jz", 1, 2, 1)),),
            "decision_dag_alias_comparison_overlap",
        ),
        (
            ((1, 2), (2, 1)),
            (),
            "decision_dag_alias_cycle",
        ),
    ),
)
def test_malformed_typed_dag_proposals_are_fact_abstentions(
    aliases, comparisons, reason
) -> None:
    fact, context = _typed_dag_fact(aliases=aliases, comparisons=comparisons)
    result = build_canonical_semantic_evidence((fact,), context)
    assert result.abstention is not None
    assert result.abstention.stage is CanonicalSemanticEvidenceProductionStage.FACT
    assert result.abstention.reason.value == reason


def test_typed_dag_state_identity_mismatch_is_fact_abstention() -> None:
    fact, context = _typed_dag_fact(
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 0x40)
    )
    result = build_canonical_semantic_evidence((fact,), context)
    assert result.abstention is not None
    assert result.abstention.stage is CanonicalSemanticEvidenceProductionStage.FACT
    assert result.abstention.reason.value == "decision_dag_state_identity_mismatch"


def test_typed_dag_conflicting_alias_target_has_distinct_reason() -> None:
    fact, context = _typed_dag_fact(aliases=((1, 2), (1, 0)))
    result = build_canonical_semantic_evidence((fact,), context)
    assert result.abstention is not None
    assert result.abstention.stage is CanonicalSemanticEvidenceProductionStage.FACT
    assert result.abstention.reason.value == "decision_dag_alias_conflicting_target"


def test_production_abstention_rejects_untyped_reason_and_detail() -> None:
    with pytest.raises(TypeError, match="typed reason"):
        CanonicalSemanticEvidenceProductionAbstention(
            reason="old-string-reason",
            stage=CanonicalSemanticEvidenceProductionStage.FACT,
        )
    with pytest.raises(TypeError, match="typed abstention"):
        CanonicalSemanticEvidenceProductionResult(abstention="old-enum")
    with pytest.raises(TypeError, match="detail"):
        CanonicalSemanticEvidenceProductionAbstention(
            reason=CanonicalSemanticEvidenceProductionReason.EMPTY_GROUP,
            stage=CanonicalSemanticEvidenceProductionStage.GROUP,
            detail=object(),
        )


@pytest.fixture(autouse=True)
def _register_condition_chain_walkers():
    register_condition_chain_walkers(build_condition_chain_walker_provider())
    yield
    reset_providers_for_tests()


def test_recovery_producer_binds_via_owned_stack_write_without_legacy_proof() -> None:
    graph = FlowGraph(
        blocks={
            1: _block(1, 0x1100, succs=(2,), preds=()),
            2: replace(
                _block(2, 0x1200, succs=(3,), preds=(1,)),
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=0x1201,
                        native_ea=0x1201,
                        operands=(),
                        l=MopSnapshot(
                            kind=OperandKind.NUMBER,
                            size=4,
                            value=0xAABBCCDD,
                        ),
                        d=MopSnapshot(
                            kind=OperandKind.STACK,
                            size=4,
                            stkoff=0x40,
                        ),
                        kind=InsnKind.MOV,
                        value_op_kind=ValueOpKind.MOVE,
                    ),
                ),
            ),
            3: _block(3, 0x1300, succs=(), preds=(2,)),
        },
        entry_serial=1,
        func_ea=0x1000,
    )
    identities = {
        serial: _identity(int(block.start_ea))
        for serial, block in graph.blocks.items()
    }
    identities[2] = _identity(0x1201)
    evidence = _accepted(build_canonical_semantic_evidence(
        (
            SemanticRouteFact(
                SemanticRouteFactKind.DECISION_DAG,
                1,
                2,
                0x1201,
                0xAABBCCDD,
                3,
                0x1100,
                0x1300,
                (1, 2),
                ((1, 2),),
            ),
        ),
        CanonicalSemanticEvidenceProductionContext(
            NATIVE_KEY,
            1,
            "canonical-semantic:test",
            StorageIdentity(StorageIdentityKind.STACK, 0x40),
            tuple(graph.blocks.values()),
            tuple(identities.items()),
        ),
    ))
    assert evidence is not None
    proof = evidence.route_proofs[0]
    assert proof is not None
    assert proof.source_identity == identities[2]
    assert proof.source_owner_identity == identities[1]
    assert proof.state_write is not None
    assert proof.state_write.identity == identities[2]
    assert proof.state_write.instruction_ea == 0x1201


def test_recovery_producer_binds_native_direct_write_and_abstains_ambiguous() -> None:
    graph = _direct_graph()
    identities = {serial: _identity(int(block.start_ea)) for serial, block in graph.blocks.items()}
    route = NativeBoundTransitionRoute(
        fact_id="native:test",
        source_instruction_ea=0x1100,
        source_block_serial=1,
        state_constant=0xAABBCCDD,
        target_handler_serial=2,
    )
    fact = SemanticRouteFact(
        SemanticRouteFactKind.NATIVE_BOUND,
        1,
        1,
        route.source_instruction_ea,
        route.state_constant,
        route.target_handler_serial,
        None,
        None,
        (1,),
        (),
        route.fact_id,
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        1,
        "canonical-semantic:test",
        StorageIdentity(StorageIdentityKind.REGISTER, 20),
        tuple(graph.blocks.values()),
        tuple(identities.items()),
    )
    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    proof = evidence.route_proofs[0]
    assert proof is not None
    assert proof.state_write is not None
    assert proof.state_write.instruction_ea == 0x1100
    rejected = build_canonical_semantic_evidence(
        (replace(fact, source_instruction_ea=0x1101),), context
    )
    assert rejected.abstention is not None
    ambiguous = replace(graph.blocks[1], insn_snapshots=graph.blocks[1].insn_snapshots * 2)
    malformed = _accepted(build_canonical_semantic_evidence(
        (fact,), replace(context, blocks=(graph.blocks[0], ambiguous, graph.blocks[2]))
    ))
    assert malformed is not None
    assert bind_canonical_semantic_evidence(
        replace(graph, blocks={0: graph.blocks[0], 1: ambiguous, 2: graph.blocks[2]}),
        malformed,
    ) is None


def test_partition_producer_uses_delivery_interval_containing_feeder_write() -> None:
    graph, _ = _composite_partition_evidence()
    state = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    identities = {
        serial: _identity(int(block.start_ea))
        for serial, block in graph.blocks.items()
    }
    identities[2] = StableBlockIdentity.from_intervals(
        (
            NativeEaInterval(0x1000, 0x1001),
            NativeEaInterval(0x1200, 0x1201),
        ),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1200,),
    )
    member = StatePartitionMemberWitness(1, 2, state, 7)
    group = StatePartitionGroupWitness(
        "partition-group:interval-test", 2, 0x1200, state, (member,)
    )
    fact = SemanticRouteFact(
        SemanticRouteFactKind.STATE_PARTITION,
        1, 2, 0x1200, 7, 6, 0x1100, 0x1600, (1, 2), ((1, 2),),
        partition_witness=group,
        decision_dag_witness=DecisionDagRouteWitness(
            state, 7, 5, 0x1500, (5,), (0x1500,),
            ((5, RouteComparison(5, "jz", 7, 6, 4)),), (),
        ),
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY, 0, "canonical-semantic:interval", state,
        tuple(graph.blocks.values()), tuple(identities.items()),
    )
    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    assert evidence.route_proofs[0].delivery_region == NativeEaInterval(0x1200, 0x1201)


def test_recovery_canonical_group_abstains_when_one_mixed_route_lacks_witness() -> None:
    graph = _direct_graph()
    identities = {serial: _identity(int(block.start_ea)) for serial, block in graph.blocks.items()}
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        1,
        "canonical-semantic:test",
        StorageIdentity(StorageIdentityKind.REGISTER, 20),
        tuple(graph.blocks.values()),
        tuple(identities.items()),
    )
    good = SemanticRouteFact(SemanticRouteFactKind.NATIVE_BOUND, 1, 1, 0x1100, 0xAABBCCDD, 2, None, None, (1,), (), "native:good")
    missing = replace(good, target_serial=99)
    rejected = build_canonical_semantic_evidence((good, missing), context)
    assert rejected.abstention is not None


def test_recovery_producer_emits_serial_independent_state_transform() -> None:
    from tests.unit.preanalysis.flow.test_minimal_state_recovery import (
        _captured_nested_state_transform_fixture,
    )

    graph, dag, _transition, _dispatcher = _captured_nested_state_transform_fixture()
    witness = prove_exact_u32_state_transform_feeder(
        graph,
        285,
        446,
        state_var_stkoff=0x64,
        state_var_reg=None,
        required_comparison_serials=frozenset({4, *dag.nodes}),
        expected_state=0x28F25B96,
    )
    assert witness is not None
    identities = {
        serial: _identity(int(block.native_start_ea or block.start_ea))
        for serial, block in graph.blocks.items()
    }
    facts = (
        SemanticRouteFact(
            SemanticRouteFactKind.STATE_TRANSFORM,
            285,
            285,
            witness.source_ea,
            witness.state,
            118,
            witness.source_ea,
            0x180016680,
            (285,),
            (),
            transform_witness=witness,
        ),
    )
    evidence = _accepted(build_canonical_semantic_evidence(
        facts,
        CanonicalSemanticEvidenceProductionContext(
            NATIVE_KEY,
            0,
            "canonical-semantic:transform",
            StorageIdentity(StorageIdentityKind.STACK, 0x64),
            tuple(graph.blocks.values()),
            tuple(identities.items()),
        ),
    ))
    assert evidence.generation == 0
    proof = evidence.route_proofs[0]
    assert proof.proof_kind is SemanticRouteProofKind.STATE_TRANSFORM
    assert proof.state_write is None
    assert proof.state_transform is not None
    assert proof.state_transform.operation is witness.operation
    assert proof.state_transform.source_identity == identities[285]
    bound = bind_canonical_semantic_evidence(graph, evidence)
    assert bound is not None
    serial_map = {int(serial): int(serial) + 1000 for serial in graph.blocks}
    def shift_mop(mop):
        if mop is None:
            return None
        return replace(
            mop,
            block_ref=(
                None
                if mop.block_ref is None
                else serial_map[int(mop.block_ref)]
            ),
            switch_cases=tuple(
                (values, serial_map[int(target)])
                for values, target in mop.switch_cases
            ),
            sub_l=shift_mop(mop.sub_l),
            sub_r=shift_mop(mop.sub_r),
            args=tuple(shift_mop(arg) for arg in mop.args),
        )

    shifted_graph = FlowGraph(
        {
            serial_map[int(serial)]: replace(
                block,
                serial=serial_map[int(serial)],
                succs=tuple(serial_map[int(item)] for item in block.succs),
                preds=tuple(serial_map[int(item)] for item in block.preds),
                insn_snapshots=tuple(
                    replace(
                        instruction,
                        operands=tuple(shift_mop(operand) for operand in instruction.operands),
                        operand_slots=tuple(
                            (name, shift_mop(operand))
                            for name, operand in instruction.operand_slots
                        ),
                        l=shift_mop(instruction.l),
                        r=shift_mop(instruction.r),
                        d=shift_mop(instruction.d),
                    )
                    for instruction in block.insn_snapshots
                ),
            )
            for serial, block in graph.blocks.items()
        },
        serial_map[int(graph.entry_serial)],
        graph.func_ea,
    )
    shifted_witness = prove_exact_u32_state_transform_feeder(
        shifted_graph,
        serial_map[285],
        serial_map[446],
        state_var_stkoff=0x64,
        state_var_reg=None,
        required_comparison_serials=frozenset({serial_map[4]}),
        expected_state=0x28F25B96,
    )
    assert shifted_witness is not None
    assert bind_canonical_semantic_evidence(shifted_graph, evidence) is not None
    changed_transform = replace(
        proof.state_transform,
        program=tuple(reversed(proof.state_transform.program)),
    )
    changed_proof = replace(proof, state_transform=changed_transform)
    changed_evidence = _recanonicalize_evidence(evidence, (changed_proof,))
    assert bind_canonical_semantic_evidence(graph, changed_evidence) is None
    drifted_destination = replace(
        proof.destinations[0], target_anchor_ea=proof.destinations[0].target_anchor_ea + 1
    )
    drifted_proof = replace(proof, destinations=(drifted_destination,))
    assert bind_canonical_semantic_evidence(
        graph, _recanonicalize_evidence(evidence, (drifted_proof,))
    ) is None


def _identity(ea: int) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(ea, ea + 0x10),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(ea,),
    )


def _proof() -> SemanticRouteProof:
    source = _identity(0x1100)
    return SemanticRouteProof(
        proof_id="state-assignment@0x1100",
        atomic_group_id="canonical-semantic:g3",
        proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
        shape=SemanticRouteShape.DIRECT,
        source_identity=source,
        source_anchor_ea=0x1100,
        delivery_region=NativeEaInterval(0x1100, 0x1101),
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.DIRECT,
                state_constant=0xAABBCCDD,
                target_identity=_identity(0x1200),
                target_anchor_ea=0x1200,
            ),
        ),
        state_write=SemanticStateWriteProof(
            identity=source,
            instruction_ea=0x1100,
            state_variable=StorageIdentity(
                StorageIdentityKind.REGISTER,
                20,
            ),
            width=4,
            state_constant=0xAABBCCDD,
            corridor_instruction_eas=(0x1100,),
            authority_transfer_ea=None,
            preserved_call_instruction_eas=(),
        ),
    )


def _storage_choice_proof() -> SemanticRouteProof:
    source = _identity(0x1100)
    producer = _identity(0x1080)
    return SemanticRouteProof(
        proof_id="state-choice@0x1100",
        atomic_group_id="canonical-semantic:g3",
        proof_kind=SemanticRouteProofKind.STATE_CHOICE,
        shape=SemanticRouteShape.CONDITIONAL,
        source_identity=source,
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
            origin=SemanticCorridorPoint(producer, 0x1080),
            consumer=SemanticCorridorPoint(source, 0x1100),
            corridor=(
                SemanticCorridorPoint(producer, 0x1080),
                SemanticCorridorPoint(source, 0x1100),
            ),
            storage_identity=StorageIdentity(
                StorageIdentityKind.STACK,
                0x40,
            ),
            width=4,
            compare_constant=0,
        ),
        carriers=(
            SemanticCarrierProof(
                carrier_id="entry-state-choice",
                definition=SemanticCorridorPoint(producer, 0x1088),
                consumers=(SemanticCorridorPoint(source, 0x1100),),
                corridor=(
                    SemanticCorridorPoint(producer, 0x1088),
                    SemanticCorridorPoint(source, 0x1100),
                ),
                storage_identity=StorageIdentity(
                    StorageIdentityKind.STACK,
                    0x48,
                ),
                width=4,
                state_values=(0xAABBCCDD, 0x11223344),
                permitted_write_eas=frozenset({0x1088}),
            ),
        ),
    )


def _evidence(*proofs: SemanticRouteProof) -> CanonicalSemanticEvidence:
    return canonical_semantic_evidence_from_proofs(
        native_key=NATIVE_KEY,
        generation=3,
        proofs=proofs or (_proof(),),
    )


def _block(
    serial: int,
    ea: int,
    *,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    insn_eas: tuple[int, ...] = (),
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=len(succs),
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=ea,
        insn_snapshots=tuple(
            InsnSnapshot(opcode=0, ea=insn_ea, operands=()) for insn_ea in insn_eas
        ),
    )


def _graph(*, include_target: bool = True) -> FlowGraph:
    blocks = {
        0: _block(0, 0x1000, succs=(1,), preds=()),
        1: BlockSnapshot(
            serial=1,
            block_type=1,
            succs=(),
            preds=(0,),
            flags=0,
            start_ea=0x1100,
            insn_snapshots=(
                InsnSnapshot(
                    opcode=0,
                    ea=0x1100,
                    operands=(),
                    l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0xAABBCCDD),
                    d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=20),
                    kind=InsnKind.MOV,
                    value_op_kind=ValueOpKind.MOVE,
                ),
            ),
        ),
    }
    if include_target:
        blocks[2] = _block(2, 0x1200, succs=(), preds=())
    return FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)


def _direct_graph(*, reciprocal: bool = True) -> FlowGraph:
    graph = _graph()
    target = graph.blocks[2]
    source = graph.blocks[1]
    return FlowGraph(
        blocks={
            **graph.blocks,
            1: replace(source, succs=(2,)),
            2: replace(target, preds=(1,) if reciprocal else ()),
        },
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )


def _partition_graph() -> FlowGraph:
    """Owner -> shared feeder graph for partition-proof unit tests."""
    owner = BlockSnapshot(
        serial=1,
        block_type=1,
        succs=(2,),
        preds=(),
        flags=0,
        start_ea=0x1100,
        insn_snapshots=(
            InsnSnapshot(
                opcode=0,
                ea=0x1100,
                operands=(),
                l=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=7),
                d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=16),
                kind=InsnKind.MOV,
                value_op_kind=ValueOpKind.MOVE,
            ),
        ),
    )
    feeder = BlockSnapshot(
        serial=2,
        block_type=1,
        succs=(),
        preds=(1,),
        flags=0,
        start_ea=0x1200,
        insn_snapshots=(
            InsnSnapshot(
                opcode=0,
                ea=0x1200,
                operands=(),
                l=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=16),
                d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
                kind=InsnKind.MOV,
                value_op_kind=ValueOpKind.MOVE,
            ),
        ),
    )
    return FlowGraph(
        blocks={1: owner, 2: feeder},
        entry_serial=1,
        func_ea=0x1000,
    )


def test_partition_prover_derives_owner_out_maps_from_immutable_graph() -> None:
    graph, _evidence = _composite_partition_evidence()
    forged = StatePartitionMemberWitness(
        owner_serial=1,
        feeder_serial=2,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 0x40),
        state_constant=7,
    )
    assert prove_partitioned_state_member(
        graph,
        forged,
        feeder_instruction_ea=0x1200,
        state_var_stkoff=0x40,
        state_var_reg=None,
    )


def test_partition_group_rejects_incomplete_sibling_set() -> None:
    member = StatePartitionMemberWitness(
        owner_serial=1,
        feeder_serial=2,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 0x40),
        state_constant=7,
    )
    sibling = StatePartitionMemberWitness(
        owner_serial=3,
        feeder_serial=2,
        state_identity=member.state_identity,
        state_constant=9,
    )
    group = StatePartitionGroupWitness(
        group_id="partition-group:shared-feeder",
        feeder_serial=2,
        feeder_instruction_ea=0x1200,
        state_identity=member.state_identity,
        members=(member, sibling),
    )
    fact = SemanticRouteFact(
        SemanticRouteFactKind.STATE_PARTITION,
        owner_serial=1,
        source_serial=2,
        source_instruction_ea=0x1200,
        state_constant=7,
        target_serial=3,
        owner_anchor_ea=0x1100,
        target_anchor_ea=0x1300,
        path_serials=(1, 2),
        path_edges=((1, 2),),
        partition_witness=group,
    )
    graph = _partition_graph()
    graph = FlowGraph(
        blocks={
            **graph.blocks,
            3: _block(3, 0x1300, succs=(2,), preds=()),
            4: _block(4, 0x1400, succs=(), preds=()),
        },
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )
    identities = {serial: _identity(int(block.start_ea)) for serial, block in graph.blocks.items()}
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        0,
        "canonical-semantic:partition",
        member.state_identity,
        tuple(graph.blocks.values()),
        tuple(identities.items()),
    )
    result = build_canonical_semantic_evidence((fact,), context)
    assert result.abstention is not None
    assert result.abstention.reason.value == "partition_group_incomplete"


def _composite_partition_evidence() -> tuple[FlowGraph, CanonicalSemanticEvidence]:
    base = _partition_graph()
    graph = FlowGraph(
        blocks={
            **base.blocks,
            2: replace(base.blocks[2], succs=(5,)),
            4: _block(4, 0x1400, succs=(), preds=(5,)),
            5: BlockSnapshot(
                serial=5,
                block_type=2,
                succs=(6, 4),
                preds=(2,),
                flags=0,
                start_ea=0x1500,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=0x1500,
                        operands=(),
                        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
                        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
                        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=6),
                        kind=InsnKind.COND_JUMP,
                        branch_predicate=PredicateKind.EQ,
                        is_conditional_jump=True,
                    ),
                ),
            ),
            6: _block(6, 0x1600, succs=(), preds=(5,)),
        },
        entry_serial=base.entry_serial,
        func_ea=base.func_ea,
    )
    identities = {
        serial: _identity(int(block.start_ea))
        for serial, block in graph.blocks.items()
    }
    state_identity = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    member = SemanticPartitionMemberProof(
        owner_identity=identities[1],
        owner_anchor_ea=0x1100,
        state_constant=7,
    )
    partition = SemanticStatePartitionProof(
        group_id=route_evidence._canonical_partition_group_id(
            identities[2],
            0x1200,
            state_identity,
            (member,),
        ),
        feeder_identity=identities[2],
        feeder_anchor_ea=0x1200,
        feeder_instruction_ea=0x1200,
        state_identity=state_identity,
        members=(member,),
    )
    entry = SemanticCorridorPoint(identities[5], 0x1500)
    target = SemanticCorridorPoint(identities[6], 0x1600)
    false_target = SemanticCorridorPoint(identities[4], 0x1400)
    comparison = SemanticDagComparison(
        node=entry,
        operation="jz",
        constant=7,
        true_target=target,
        false_target=false_target,
    )
    witness = SemanticDecisionDagWitness(
        state_identity=state_identity,
        state_constant=7,
        entry=entry,
        path=(entry,),
        comparisons=(comparison,),
        aliases=(),
    )
    dag = SemanticStateDagProof(
        witness=witness,
        source_identity=identities[2],
        source_anchor_ea=0x1200,
        target_identity=identities[6],
        target_anchor_ea=0x1600,
        entry_identity=identities[5],
        entry_anchor_ea=0x1500,
        path=(entry,),
    )
    proof = SemanticRouteProof(
        proof_id="partition-composite:test",
        atomic_group_id="canonical-semantic:partition-composite",
        proof_kind=SemanticRouteProofKind.STATE_PARTITION,
        shape=SemanticRouteShape.DIRECT,
        source_identity=identities[2],
        source_anchor_ea=0x1200,
        source_owner_identity=identities[1],
        source_owner_anchor_ea=0x1100,
        delivery_region=NativeEaInterval(0x1200, 0x1210),
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.DIRECT,
                state_constant=7,
                target_identity=identities[6],
                target_anchor_ea=0x1600,
            ),
        ),
        state_partition=partition,
        state_dag=dag,
    )
    return graph, canonical_semantic_evidence_from_proofs(
        native_key=NATIVE_KEY,
        generation=3,
        proofs=(proof,),
    )


def test_composite_partition_and_dag_binding_replays_both_authorities() -> None:
    graph, evidence = _composite_partition_evidence()
    assert bind_canonical_semantic_evidence(graph, evidence) is not None


@pytest.mark.parametrize("mutation", ("constant", "identity", "coalesced_target"))
def test_composite_partition_requires_dag_witness_cross_binding(mutation: str) -> None:
    _graph, evidence = _composite_partition_evidence()
    proof = evidence.route_proofs[0]
    if mutation == "constant":
        drifted_witness = replace(
            proof.state_dag.witness,
            state_constant=8,
        )
        with pytest.raises(SemanticRouteEvidenceRejected, match="state partition"):
            replace(
                proof,
                state_dag=replace(proof.state_dag, witness=drifted_witness),
            )
    elif mutation == "identity":
        drifted_witness = replace(
            proof.state_dag.witness,
            state_identity=StorageIdentity(StorageIdentityKind.STACK, 0x44),
        )
        with pytest.raises(SemanticRouteEvidenceRejected, match="state partition"):
            replace(
                proof,
                state_dag=replace(proof.state_dag, witness=drifted_witness),
            )
    else:
        member = replace(proof.state_partition.members[0], state_constant=9)
        partition = replace(
            proof.state_partition,
            group_id=route_evidence._canonical_partition_group_id(
                proof.state_partition.feeder_identity,
                proof.state_partition.feeder_instruction_ea,
                proof.state_partition.state_identity,
                (member,),
            ),
            members=(member,),
        )
        with pytest.raises(SemanticRouteEvidenceRejected, match="state partition"):
            replace(
                proof,
                state_partition=partition,
                destinations=(replace(proof.destinations[0], state_constant=9),),
            )


def test_composite_partition_binder_rejects_forged_dag_state_drift() -> None:
    graph, evidence = _composite_partition_evidence()
    proof = evidence.route_proofs[0]
    forged = object.__new__(SemanticRouteProof)
    for name in proof.__dataclass_fields__:
        object.__setattr__(forged, name, getattr(proof, name))
    object.__setattr__(
        forged,
        "state_dag",
        replace(
            proof.state_dag,
            witness=replace(proof.state_dag.witness, state_constant=9),
        ),
    )
    assert bind_canonical_semantic_evidence(
        graph,
            _unsafe_evidence(evidence, (forged,)),
    ) is None


@pytest.mark.parametrize(
    "mutation",
    (
        lambda graph: FlowGraph(
            {
                **graph.blocks,
                2: replace(graph.blocks[2], succs=()),
            },
            graph.entry_serial,
            graph.func_ea,
        ),
        lambda graph: FlowGraph(
            {
                **graph.blocks,
                5: replace(graph.blocks[5], preds=()),
            },
            graph.entry_serial,
            graph.func_ea,
        ),
        lambda graph: FlowGraph(
            {
                **graph.blocks,
                2: replace(graph.blocks[2], succs=(4, 5)),
            },
            graph.entry_serial,
            graph.func_ea,
        ),
    ),
)
def test_composite_partition_rejects_nonreciprocal_or_ambiguous_feeder_entry(
    mutation,
) -> None:
    graph, evidence = _composite_partition_evidence()
    assert bind_canonical_semantic_evidence(mutation(graph), evidence) is None


def _ordinary_decision_dag_evidence(
    *, address_store: bool = False
) -> tuple[FlowGraph, CanonicalSemanticEvidence]:
    graph, _partition_evidence = _composite_partition_evidence()
    state_write = (
        replace(
            graph.blocks[2].insn_snapshots[0],
            l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
            d=MopSnapshot(
                kind=OperandKind.ADDRESS,
                size=8,
                stack_refs=(0x40,),
                sub_l=MopSnapshot(
                    kind=OperandKind.STACK,
                    size=4,
                    stkoff=0x40,
                    stack_refs=(0x40,),
                ),
            ),
            kind=InsnKind.STORE,
            value_op_kind=ValueOpKind.STORE,
        )
        if address_store
        else replace(
            graph.blocks[2].insn_snapshots[0],
            l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
            d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
        )
    )
    source = replace(
        graph.blocks[2],
        succs=(5,),
        insn_snapshots=(state_write,),
    )
    graph = FlowGraph(
        {
            **graph.blocks,
            2: source,
            5: replace(graph.blocks[5], preds=(2,)),
        },
        graph.entry_serial,
        graph.func_ea,
    )
    identities = {
        serial: _identity(int(block.start_ea))
        for serial, block in graph.blocks.items()
    }
    state_identity = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    entry = SemanticCorridorPoint(identities[5], 0x1500)
    witness = DecisionDagRouteWitness(
        state_identity,
        7,
        5,
        0x1500,
        (5,),
        (0x1500,),
        ((5, RouteComparison(5, "jz", 7, 6, 4)),),
        (),
    )
    fact = SemanticRouteFact(
        SemanticRouteFactKind.DECISION_DAG,
        2,
        2,
        0x1200,
        7,
        6,
        0x1200,
        0x1600,
        (2,),
        (),
        decision_dag_witness=witness,
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        0,
        "canonical-semantic:ordinary-dag",
        state_identity,
        tuple(graph.blocks.values()),
        tuple(identities.items()),
    )
    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    return graph, evidence


def test_ordinary_decision_dag_builds_assignment_and_dag_proofs() -> None:
    _graph, evidence = _ordinary_decision_dag_evidence()
    proof = evidence.route_proofs[0]
    assert proof.proof_kind is SemanticRouteProofKind.STATE_DAG
    assert proof.state_write is not None
    assert proof.state_write.instruction_ea == 0x1200
    assert proof.state_write.state_variable == StorageIdentity(StorageIdentityKind.STACK, 0x40)
    assert proof.state_write.width == 4
    assert proof.state_write.delivery_kind is SemanticStateWriteDeliveryKind.INDIRECT
    assert proof.state_write.corridor_instruction_eas == (0x1200,)
    assert proof.state_dag is not None


def test_ordinary_decision_dag_binds_assignment_and_dag_proofs() -> None:
    graph, evidence = _ordinary_decision_dag_evidence()
    assert bind_canonical_semantic_evidence(graph, evidence) is not None


def test_address_form_store_survives_production_and_canonical_binding() -> None:
    graph, evidence = _ordinary_decision_dag_evidence(address_store=True)
    fact = SemanticRouteFact(
        SemanticRouteFactKind.DECISION_DAG,
        2,
        2,
        0x1200,
        7,
        6,
        0x1200,
        0x1600,
        (2,),
        (),
        decision_dag_witness=DecisionDagRouteWitness(
            StorageIdentity(StorageIdentityKind.STACK, 0x40),
            7,
            5,
            0x1500,
            (5,),
            (0x1500,),
            ((5, RouteComparison(5, "jz", 7, 6, 4)),),
            (),
        ),
    )
    result = build_canonical_semantic_evidence(
        (fact,),
        CanonicalSemanticEvidenceProductionContext(
            NATIVE_KEY,
            0,
            "canonical-semantic:ordinary-dag-store",
            StorageIdentity(StorageIdentityKind.STACK, 0x40),
            tuple(graph.blocks.values()),
            tuple(
                (serial, _identity(int(block.start_ea)))
                for serial, block in graph.blocks.items()
            ),
        ),
    )
    produced = _accepted(result)
    assert produced.route_proofs[0].state_write is not None
    assert bind_canonical_semantic_evidence(graph, produced) is not None


@pytest.mark.parametrize(
    "mutation",
    (
        "narrow",
        "wide",
        "wrong_state",
        "wrong_identity",
        "ambiguous",
        "alias_register",
        "memory_register",
    ),
)
def test_address_form_store_binding_rejects_noncanonical_mutations(mutation: str) -> None:
    graph, evidence = _ordinary_decision_dag_evidence(address_store=True)
    source = graph.blocks[2]
    snapshot = source.insn_snapshots[0]
    if mutation in {"narrow", "wide", "wrong_state"}:
        left = snapshot.l
        assert left is not None
        if mutation == "narrow":
            left = replace(left, size=1)
        elif mutation == "wide":
            left = replace(left, size=8)
        else:
            left = replace(left, value=8)
        snapshots = (replace(snapshot, l=left),)
    elif mutation == "wrong_identity":
        snapshots = (
            replace(
                snapshot,
                d=MopSnapshot(
                    kind=OperandKind.ADDRESS,
                    size=8,
                    stack_refs=(0x44,),
                    sub_l=MopSnapshot(
                        kind=OperandKind.STACK,
                        size=4,
                        stkoff=0x44,
                        stack_refs=(0x44,),
                    ),
                ),
            ),
        )
    elif mutation == "alias_register":
        snapshots = (
            replace(
                snapshot,
                d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=9),
            ),
        )
    elif mutation == "memory_register":
        snapshots = (
            replace(
                snapshot,
                l=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=9),
                r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
            ),
        )
    else:
        snapshots = (
            snapshot,
            replace(snapshot, ea=0x1204),
        )
    mutated = FlowGraph(
        {
            **graph.blocks,
            2: replace(source, insn_snapshots=snapshots),
        },
        graph.entry_serial,
        graph.func_ea,
    )
    assert bind_canonical_semantic_evidence(mutated, evidence) is None


@pytest.mark.parametrize(
    "mutation",
    (
        lambda proof: replace(
            proof,
            state_write=replace(proof.state_write, state_constant=8),
        ),
        lambda proof: replace(
            proof,
            state_write=replace(
                proof.state_write,
                state_variable=StorageIdentity(StorageIdentityKind.STACK, 0x44),
            ),
        ),
        lambda proof: replace(
            proof,
            state_write=replace(
                proof.state_write,
                identity=_identity(0x1100),
                instruction_ea=0x1100,
                corridor_instruction_eas=(0x1100,),
            ),
        ),
        lambda proof: replace(
            proof,
            state_write=replace(
                proof.state_write,
                instruction_ea=0x1201,
                corridor_instruction_eas=(0x1201,),
            ),
        ),
        lambda proof: replace(
            proof,
            state_write=replace(proof.state_write, width=8),
        ),
    ),
)
def test_ordinary_decision_dag_requires_cross_bound_state_write_invariants(mutation) -> None:
    _graph, evidence = _ordinary_decision_dag_evidence()
    with pytest.raises(SemanticRouteEvidenceRejected, match="state DAG"):
        mutation(evidence.route_proofs[0])


def test_ordinary_decision_dag_requires_destination_state_to_match_write() -> None:
    _graph, evidence = _ordinary_decision_dag_evidence()
    proof = evidence.route_proofs[0]
    with pytest.raises(SemanticRouteEvidenceRejected, match="state DAG"):
        replace(
            proof,
            destinations=(replace(proof.destinations[0], state_constant=8),),
        )


def test_ordinary_decision_dag_rejects_coordinated_write_drift() -> None:
    graph, evidence = _ordinary_decision_dag_evidence()
    proof = evidence.route_proofs[0]
    drifted_source = replace(
        graph.blocks[2].insn_snapshots[0],
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8),
    )
    drifted_graph = FlowGraph(
        {**graph.blocks, 2: replace(graph.blocks[2], insn_snapshots=(drifted_source,))},
        graph.entry_serial,
        graph.func_ea,
    )
    drifted_write = replace(proof.state_write, state_constant=8)
    forged_proof = object.__new__(SemanticRouteProof)
    for name in proof.__dataclass_fields__:
        object.__setattr__(forged_proof, name, getattr(proof, name))
    object.__setattr__(forged_proof, "state_write", drifted_write)
    forged_evidence = object.__new__(CanonicalSemanticEvidence)
    object.__setattr__(forged_evidence, "native_key", evidence.native_key)
    object.__setattr__(forged_evidence, "generation", evidence.generation)
    object.__setattr__(forged_evidence, "atomic_group_id", evidence.atomic_group_id)
    object.__setattr__(forged_evidence, "route_proofs", (forged_proof,))
    assert bind_canonical_semantic_evidence(drifted_graph, forged_evidence) is None


def test_ordinary_decision_dag_rejects_missing_source_to_entry_successor() -> None:
    graph, evidence = _ordinary_decision_dag_evidence()
    source = replace(graph.blocks[2], succs=())
    graph = FlowGraph(
        {**graph.blocks, 2: source},
        graph.entry_serial,
        graph.func_ea,
    )
    assert bind_canonical_semantic_evidence(graph, evidence) is None


def test_ordinary_decision_dag_rejects_missing_entry_predecessor() -> None:
    graph, evidence = _ordinary_decision_dag_evidence()
    entry = replace(graph.blocks[5], preds=())
    graph = FlowGraph(
        {**graph.blocks, 5: entry},
        graph.entry_serial,
        graph.func_ea,
    )
    assert bind_canonical_semantic_evidence(graph, evidence) is None


@pytest.mark.parametrize(
    "mutation",
    (
        lambda instruction: replace(instruction, kind=InsnKind.NOP),
        lambda instruction: replace(
            instruction,
            l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8),
        ),
        lambda instruction: replace(
            instruction,
            d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x44),
        ),
        lambda instruction: replace(
            instruction,
            l=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=7),
            d=MopSnapshot(kind=OperandKind.STACK, size=8, stkoff=0x40),
        ),
    ),
)
def test_ordinary_decision_dag_rejects_state_write_drift(mutation) -> None:
    graph, evidence = _ordinary_decision_dag_evidence()
    source = graph.blocks[2]
    drifted_graph = FlowGraph(
        {**graph.blocks, 2: replace(source, insn_snapshots=(mutation(source.insn_snapshots[0]),))},
        graph.entry_serial,
        graph.func_ea,
    )
    assert bind_canonical_semantic_evidence(drifted_graph, evidence) is None


def test_ordinary_decision_dag_rejects_state_write_ea_drift() -> None:
    graph, evidence = _ordinary_decision_dag_evidence()
    proof = evidence.route_proofs[0]
    drifted_write = replace(
        proof.state_write,
        instruction_ea=0x1201,
        corridor_instruction_eas=(0x1201,),
    )
    with pytest.raises(SemanticRouteEvidenceRejected, match="state DAG"):
        replace(proof, state_write=drifted_write)


def test_ordinary_decision_dag_rejects_dag_drift() -> None:
    graph, evidence = _ordinary_decision_dag_evidence()
    proof = evidence.route_proofs[0]
    drifted_witness = replace(
        proof.state_dag.witness,
        comparisons=(replace(proof.state_dag.witness.comparisons[0], constant=8),),
    )
    drifted_dag = replace(proof.state_dag, witness=drifted_witness)
    assert bind_canonical_semantic_evidence(
        graph,
        _recanonicalize_evidence(
            evidence, (replace(proof, state_dag=drifted_dag),),
        ),
    ) is None


def test_ordinary_decision_dag_accepts_serial_permutation() -> None:
    graph, evidence = _ordinary_decision_dag_evidence()
    serial_map = {1: 101, 2: 102, 4: 104, 5: 105, 6: 106}
    shifted = {
        serial_map[serial]: replace(
            block,
            serial=serial_map[serial],
            succs=tuple(serial_map[item] for item in block.succs),
            preds=tuple(serial_map[item] for item in block.preds),
            insn_snapshots=tuple(
                replace(
                    instruction,
                    d=(
                        None
                        if instruction.d is None
                        else replace(
                            instruction.d,
                            block_ref=(
                                None
                                if instruction.d.block_ref is None
                                else serial_map[int(instruction.d.block_ref)]
                            ),
                        )
                    ),
                )
                for instruction in block.insn_snapshots
            ),
        )
        for serial, block in graph.blocks.items()
    }
    shifted_graph = FlowGraph(shifted, serial_map[graph.entry_serial], graph.func_ea)
    assert bind_canonical_semantic_evidence(shifted_graph, evidence) is not None


def test_shared_writer_owner_specific_states_bind_as_partition_composite() -> None:
    graph, _composite = _composite_partition_evidence()
    graph = FlowGraph(
        {
            **graph.blocks,
            2: replace(graph.blocks[2], preds=(1, 3)),
            3: BlockSnapshot(
                serial=3,
                block_type=1,
                succs=(2,),
                preds=(),
                flags=0,
                start_ea=0x1300,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=0x1300,
                        native_ea=0x1300,
                        operands=(),
                        l=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=9),
                        d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=16),
                        kind=InsnKind.MOV,
                        value_op_kind=ValueOpKind.MOVE,
                    ),
                ),
            ),
        },
        graph.entry_serial,
        graph.func_ea,
    )
    identities = {
        serial: _identity(int(block.start_ea))
        for serial, block in graph.blocks.items()
    }
    state_identity = StorageIdentity(StorageIdentityKind.STACK, 0x40)

    group = StatePartitionGroupWitness(
        "partition-group:shared-writer",
        2,
        0x1200,
        state_identity,
        (
            StatePartitionMemberWitness(1, 2, state_identity, 7),
            StatePartitionMemberWitness(3, 2, state_identity, 9),
        ),
    )

    def fact(owner: int, state: int, target: int, other_target: int) -> SemanticRouteFact:
        witness = DecisionDagRouteWitness(
            state_identity,
            state,
            5,
            0x1500,
            (5,),
            (0x1500,),
            ((5, RouteComparison(5, "jz", 7, 6, 4)),),
            (),
        )
        return SemanticRouteFact(
            SemanticRouteFactKind.STATE_PARTITION,
            owner,
            2,
            0x1200,
            state,
            target,
            int(graph.blocks[owner].start_ea),
            int(graph.blocks[target].start_ea),
            (owner, 2),
            ((owner, 2),),
            decision_dag_witness=witness,
            partition_witness=group,
        )

    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        0,
        "canonical-semantic:shared-writer",
        state_identity,
        tuple(graph.blocks.values()),
        tuple(identities.items()),
    )
    evidence = _accepted(build_canonical_semantic_evidence(
        (fact(1, 7, 6, 4), fact(3, 9, 4, 6)),
        context,
    ))
    assert {proof.proof_kind for proof in evidence.route_proofs} == {
        SemanticRouteProofKind.STATE_PARTITION,
    }
    assert bind_canonical_semantic_evidence(graph, evidence) is not None

    drifted_owner = replace(
        graph.blocks[3],
        insn_snapshots=(
            replace(
                graph.blocks[3].insn_snapshots[0],
                l=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=10),
            ),
        ),
    )
    assert bind_canonical_semantic_evidence(
        FlowGraph(
            {**graph.blocks, 3: drifted_owner},
            graph.entry_serial,
            graph.func_ea,
        ),
        evidence,
    ) is None
    assert bind_canonical_semantic_evidence(
        FlowGraph(
            {**graph.blocks, 2: replace(graph.blocks[2], preds=(1,))},
            graph.entry_serial,
            graph.func_ea,
        ),
        evidence,
    ) is None


def test_carrier_only_wide_projection_cannot_claim_target_without_partition_dag() -> None:
    wide_constant = MopSnapshot(kind=OperandKind.NUMBER, size=8, value=7)
    wide_carrier = MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=16)
    narrow_carrier = MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=16)
    state = MopSnapshot(
        kind=OperandKind.STACK,
        size=4,
        stkoff=0x40,
        stack_refs=(0x40,),
    )
    graph = FlowGraph(
        blocks={
            2: BlockSnapshot(
                serial=2,
                block_type=1,
                succs=(3,),
                preds=(),
                flags=0,
                start_ea=0x1200,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=0x1200,
                        native_ea=0x1200,
                        operands=(),
                        l=wide_constant,
                        d=wide_carrier,
                        kind=InsnKind.MOV,
                        value_op_kind=ValueOpKind.MOVE,
                    ),
                ),
            ),
            3: BlockSnapshot(
                serial=3,
                block_type=1,
                succs=(4,),
                preds=(2,),
                flags=0,
                start_ea=0x1300,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=0x1300,
                        native_ea=0x1300,
                        operands=(),
                        l=narrow_carrier,
                        d=state,
                        kind=InsnKind.MOV,
                        value_op_kind=ValueOpKind.MOVE,
                    ),
                ),
            ),
            4: _block(4, 0x1400, succs=(), preds=(3,)),
            5: _block(5, 0x1500, succs=(), preds=()),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    identities = {
        serial: _identity(int(block.start_ea))
        for serial, block in graph.blocks.items()
    }
    state_identity = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    fact = SemanticRouteFact(
        SemanticRouteFactKind.STATE_CARRIER,
        owner_serial=2,
        source_serial=2,
        source_instruction_ea=0x1200,
        state_constant=7,
        target_serial=5,
        owner_anchor_ea=0x1200,
        target_anchor_ea=0x1500,
        path_serials=(2,),
        path_edges=(),
        carrier_witness=ExactCarrierStateWrite(
            state=7,
            source_serial=2,
            feeder_serial=3,
            comparison_entry_serial=4,
            carrier=Varnode(Space.REGISTER, 16, 8),
            state_identity=state_identity,
        ),
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        0,
        "canonical-semantic:wide-carrier-red",
        state_identity,
        tuple(graph.blocks.values()),
        tuple(identities.items()),
    )
    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    assert bind_canonical_semantic_evidence(graph, evidence) is None


def test_composite_partition_rejects_wrong_dag_target_path_and_comparison() -> None:
    graph, evidence = _composite_partition_evidence()
    proof = evidence.route_proofs[0]
    target4 = _identity(0x1400)
    with pytest.raises(SemanticRouteEvidenceRejected, match="state partition"):
        replace(
            proof,
            destinations=(replace(proof.destinations[0], target_identity=target4, target_anchor_ea=0x1400),),
        )
    with pytest.raises(SemanticRouteEvidenceRejected, match="state-DAG path"):
        bad_path = replace(
            proof.state_dag,
            path=(SemanticCorridorPoint(_identity(0x1400), 0x1400),),
        )
        replace(proof, state_dag=bad_path)
    bad_comparison = replace(
        proof.state_dag.witness,
        comparisons=(replace(proof.state_dag.witness.comparisons[0], constant=8),),
    )
    bad_dag = replace(proof.state_dag, witness=bad_comparison)
    assert bind_canonical_semantic_evidence(
            graph, _unsafe_evidence(evidence, (replace(proof, state_dag=bad_dag),))
    ) is None


def test_composite_partition_and_dag_accept_serial_permutation() -> None:
    graph, evidence = _composite_partition_evidence()
    serial_map = {1: 101, 2: 102, 4: 104, 5: 105, 6: 106}
    shifted = {
        serial_map[serial]: replace(
            block,
            serial=serial_map[serial],
            succs=tuple(serial_map[item] for item in block.succs),
            preds=tuple(serial_map[item] for item in block.preds),
            insn_snapshots=tuple(
                replace(
                    instruction,
                    d=(
                        None
                        if instruction.d is None
                        else replace(
                            instruction.d,
                            block_ref=(
                                None
                                if instruction.d.block_ref is None
                                else serial_map[int(instruction.d.block_ref)]
                            ),
                        )
                    ),
                )
                for instruction in block.insn_snapshots
            ),
        )
        for serial, block in graph.blocks.items()
    }
    shifted_graph = FlowGraph(shifted, serial_map[graph.entry_serial], graph.func_ea)
    assert bind_canonical_semantic_evidence(shifted_graph, evidence) is not None


def test_partition_binding_rejects_unlisted_reciprocal_feeder_predecessor() -> None:
    graph, evidence = _composite_partition_evidence()
    feeder = replace(graph.blocks[2], preds=(1, 3))
    extra_owner = _block(3, 0x1300, succs=(2,), preds=())
    graph = FlowGraph(
        {**graph.blocks, 2: feeder, 3: extra_owner},
        graph.entry_serial,
        graph.func_ea,
    )
    assert bind_canonical_semantic_evidence(graph, evidence) is None


def test_partition_binding_rejects_comparison_operation_change_with_same_branch() -> None:
    graph, evidence = _composite_partition_evidence()
    proof = evidence.route_proofs[0]
    changed = replace(
        proof.state_dag.witness.comparisons[0],
        operation="jbe",
    )
    changed_witness = replace(proof.state_dag.witness, comparisons=(changed,))
    changed_dag = replace(proof.state_dag, witness=changed_witness)
    assert bind_canonical_semantic_evidence(
        graph,
            _unsafe_evidence(evidence, (replace(proof, state_dag=changed_dag),)),
    ) is None


def test_decision_dag_rejects_duplicate_conflicting_alias_owner() -> None:
    _graph, evidence = _composite_partition_evidence()
    witness = evidence.route_proofs[0].state_dag.witness
    source = witness.entry
    target = witness.comparisons[0].true_target
    other = witness.comparisons[0].false_target
    with pytest.raises(SemanticRouteEvidenceRejected, match="duplicate sources"):
        replace(witness, aliases=((source, target), (source, other)))
    comparison = witness.comparisons[0]
    with pytest.raises(SemanticRouteEvidenceRejected, match="duplicate nodes"):
        replace(witness, comparisons=(comparison, comparison))
    alias_a = comparison.false_target
    alias_b = comparison.true_target
    with pytest.raises(SemanticRouteEvidenceRejected, match="cycle"):
        replace(witness, aliases=((alias_a, alias_b), (alias_b, alias_a)))


def test_decision_dag_rejects_unused_nonedge_alias_at_bind() -> None:
    graph, evidence = _composite_partition_evidence()
    proof = evidence.route_proofs[0]
    witness = proof.state_dag.witness
    alias_source = SemanticCorridorPoint(
        _identity(0x1400),
        0x1400,
    )
    alias_target = witness.comparisons[0].true_target
    changed_witness = replace(witness, aliases=((alias_source, alias_target),))
    changed_dag = replace(proof.state_dag, witness=changed_witness)
    assert bind_canonical_semantic_evidence(
        graph,
            _unsafe_evidence(evidence, (replace(proof, state_dag=changed_dag),)),
    ) is None


def test_route_comparison_requires_exact_predicate_kind() -> None:
    graph, _evidence = _composite_partition_evidence()
    branch = graph.blocks[5].insn_snapshots[0]
    forged = replace(
        branch,
        branch_predicate=SimpleNamespace(name="EQ"),
        predicate_kind=SimpleNamespace(name="EQ"),
    )
    forged_graph = FlowGraph(
        {**graph.blocks, 5: replace(graph.blocks[5], insn_snapshots=(forged,))},
        graph.entry_serial,
        graph.func_ea,
    )
    assert current_u32_route_comparison(
        forged_graph,
        5,
        expected_identities=frozenset({StorageIdentity(StorageIdentityKind.STACK, 0x40)}),
    ) is None


def test_partition_producer_rejects_same_group_id_with_conflicting_members() -> None:
    base = _partition_graph()
    graph = FlowGraph(
        {
            **base.blocks,
            3: _block(3, 0x1300, succs=(2,), preds=()),
            4: _block(4, 0x1400, succs=(), preds=()),
        },
        base.entry_serial,
        base.func_ea,
    )
    state_identity = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    member1 = StatePartitionMemberWitness(1, 2, state_identity, 7)
    member3 = StatePartitionMemberWitness(3, 2, state_identity, 9)
    group1 = StatePartitionGroupWitness("same-group", 2, 0x1200, state_identity, (member1,))
    group3 = StatePartitionGroupWitness("same-group", 2, 0x1200, state_identity, (member3,))
    fact1 = SemanticRouteFact(
        SemanticRouteFactKind.STATE_PARTITION, 1, 2, 0x1200, 7, 4, 0x1100, 0x1400,
        (1, 2), ((1, 2),), partition_witness=group1,
    )
    fact3 = replace(
        fact1,
        owner_serial=3,
        state_constant=9,
        owner_anchor_ea=0x1300,
        path_serials=(3, 2),
        path_edges=((3, 2),),
        partition_witness=group3,
    )
    identities = {serial: _identity(int(block.start_ea)) for serial, block in graph.blocks.items()}
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY, 0, "canonical-semantic:conflict", state_identity,
        tuple(graph.blocks.values()), tuple(identities.items()),
    )
    result = build_canonical_semantic_evidence((fact1, fact3), context)
    assert result.abstention is not None
    assert result.abstention.reason.value == "partition_group_incomplete"


def test_partition_group_id_is_canonical_and_order_invariant() -> None:
    graph = _partition_graph()
    identities = {serial: _identity(int(block.start_ea)) for serial, block in graph.blocks.items()}
    identities[3] = _identity(0x1300)
    state = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    members = (
        SemanticPartitionMemberProof(identities[1], 0x1100, 7),
        SemanticPartitionMemberProof(identities[3], 0x1300, 9),
    )
    group_id = route_evidence._canonical_partition_group_id(
        identities[2], 0x1200, state, members
    )
    first = SemanticStatePartitionProof(
        group_id, identities[2], 0x1200, 0x1200, state, members
    )
    second = SemanticStatePartitionProof(
        group_id, identities[2], 0x1200, 0x1200, state, tuple(reversed(members))
    )
    assert first.group_id == second.group_id == group_id
    with pytest.raises(SemanticRouteEvidenceRejected, match="group id"):
        replace(first, group_id="partition-group:forged")


def test_direct_assignment_proof_requires_matching_state_write() -> None:
    proof = _proof()

    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="state assignment requires its exact state write",
    ):
        replace(proof, state_write=None)
    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="state constant",
    ):
        replace(
            proof,
            destinations=(
                replace(
                    proof.destinations[0],
                    state_constant=0x11223344,
                ),
            ),
        )


def test_direct_state_assignment_replays_delivery_edge() -> None:
    proof = replace(
        _proof(),
        state_write=replace(
            _proof().state_write,
            delivery_kind=SemanticStateWriteDeliveryKind.DIRECT,
        ),
    )

    bound = bind_canonical_semantic_evidence(_direct_graph(), _evidence(proof))
    assert bound is not None


def test_state_write_binding_accepts_one_semantic_occurrence_at_shared_native_ea() -> None:
    """A shared native coordinate is not ambiguous when only one write matches."""
    graph = _direct_graph()
    source = graph.blocks[1]
    non_state_write = replace(
        source.insn_snapshots[0],
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0x12345678),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=19),
    )
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            1: replace(
                source,
                insn_snapshots=(non_state_write, source.insn_snapshots[0]),
            ),
        },
    )

    assert bind_canonical_semantic_evidence(graph, _evidence()) is not None


def test_state_write_binding_rejects_two_semantic_occurrences_at_shared_native_ea() -> None:
    """The state-write claim remains ambiguous when both same-EA writes match."""
    graph = _direct_graph()
    source = graph.blocks[1]
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            1: replace(
                source,
                insn_snapshots=(source.insn_snapshots[0], source.insn_snapshots[0]),
            ),
        },
    )

    assert bind_canonical_semantic_evidence(graph, _evidence()) is None


def test_state_write_binding_rejects_conflicting_same_state_writer_at_shared_native_ea() -> None:
    """A same-EA write to the claimed state remains semantically ambiguous."""
    graph = _direct_graph()
    source = graph.blocks[1]
    conflicting_state_write = replace(
        source.insn_snapshots[0],
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0x12345678),
    )
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            1: replace(
                source,
                insn_snapshots=(conflicting_state_write, source.insn_snapshots[0]),
            ),
        },
    )

    assert bind_canonical_semantic_evidence(graph, _evidence()) is None


def test_state_write_binding_accepts_unrelated_same_ea_stack_store() -> None:
    """An unrelated same-EA store is not a second writer of register state."""
    graph = _direct_graph()
    source = graph.blocks[1]
    unrelated_store = InsnSnapshot(
        opcode=0,
        ea=0x1100,
        operands=(),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x44),
        kind=InsnKind.STORE,
        value_op_kind=ValueOpKind.STORE,
    )
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            1: replace(
                source,
                insn_snapshots=(unrelated_store, source.insn_snapshots[0]),
            ),
        },
    )

    assert bind_canonical_semantic_evidence(graph, _evidence()) is not None


def test_route_assessment_is_minted_only_by_the_trusted_binding_kernel() -> None:
    materialization = CanonicalRouteMaterialization.capture(
            _direct_graph(), phase=CanonicalRouteAssessmentPhase.SOURCE,
            generation=3,
    )
    assessment = assess_canonical_route(materialization, _evidence())
    assert type(assessment) is CanonicalRouteAssessment
    assert assessment.accepted
    assert assessment.rejection_reason is None
    assert assessment.evidence_id == assessment.evidence.atomic_group_id
    assert assessment.proof_ids == tuple(
        sorted(proof.proof_id for proof in assessment.evidence.route_proofs)
    )
    assert validate_canonical_route_assessment(assessment) is assessment
    with pytest.raises(TypeError, match="minted"):
        CanonicalRouteAssessment()
    with pytest.raises(TypeError):
        replace(assessment, graph_fingerprint="sha256:" + "b" * 64)
    object.__setattr__(assessment, "evidence_id", "forged-evidence-id")
    with pytest.raises(ValueError):
        validate_canonical_route_assessment(assessment)


def test_materialization_and_assessment_require_exact_registry_identity() -> None:
    for name in (
        "_register_materialization", "_register_assessment",
        "_materialization_state", "_assessment_state",
    ):
        assert not hasattr(route_evidence, name)

    materialization = CanonicalRouteMaterialization.capture(
        _direct_graph(), phase=CanonicalRouteAssessmentPhase.SOURCE, generation=3,
    )
    clone = object.__new__(CanonicalRouteMaterialization)
    for name in CanonicalRouteMaterialization.__dataclass_fields__:
        object.__setattr__(clone, name, getattr(materialization, name))
    with pytest.raises((TypeError, ValueError)):
        validate_canonical_route_materialization(clone)
    object.__setattr__(materialization, "generation", 4)
    with pytest.raises((TypeError, ValueError)):
        validate_canonical_route_materialization(materialization)
    materialization = CanonicalRouteMaterialization.capture(
        _direct_graph(), phase=CanonicalRouteAssessmentPhase.SOURCE, generation=3,
    )
    object.__setattr__(materialization.blocks[1], "succs", (999,))
    with pytest.raises((TypeError, ValueError)):
        validate_canonical_route_materialization(materialization)

    materialization = CanonicalRouteMaterialization.capture(
        _direct_graph(), phase=CanonicalRouteAssessmentPhase.SOURCE, generation=3,
    )
    assessment = assess_canonical_route(materialization, _evidence())
    assessment_clone = object.__new__(CanonicalRouteAssessment)
    for name in CanonicalRouteAssessment.__dataclass_fields__:
        object.__setattr__(assessment_clone, name, getattr(assessment, name))
    with pytest.raises((TypeError, ValueError)):
        validate_canonical_route_assessment(assessment_clone)
    object.__setattr__(assessment, "graph_fingerprint", "sha256:" + "f" * 64)
    object.__setattr__(assessment, "_seal", "sha256:" + "0" * 64)
    with pytest.raises((TypeError, ValueError)):
        validate_canonical_route_assessment(assessment)


def test_route_authority_registry_does_not_retain_results() -> None:
    """The closed identity registries must not become process-lifetime owners."""

    materializations: list[CanonicalRouteMaterialization] = []
    assessments: list[CanonicalRouteAssessment] = []
    materialization_refs: list[weakref.ReferenceType[CanonicalRouteMaterialization]] = []
    assessment_refs: list[weakref.ReferenceType[CanonicalRouteAssessment]] = []
    for _ in range(25):
        materialization = CanonicalRouteMaterialization.capture(
            _direct_graph(), phase=CanonicalRouteAssessmentPhase.SOURCE, generation=3,
        )
        assessment = assess_canonical_route(materialization, _evidence())
        materializations.append(materialization)
        assessments.append(assessment)
        materialization_refs.append(weakref.ref(materialization))
        assessment_refs.append(weakref.ref(assessment))

    assert all(reference() is not None for reference in materialization_refs)
    assert all(reference() is not None for reference in assessment_refs)
    del materializations, assessments
    del materialization, assessment
    gc.collect()
    assert all(reference() is None for reference in materialization_refs)
    assert all(reference() is None for reference in assessment_refs)


def test_route_assessment_rejects_unbound_unique_endpoint_without_authority() -> None:
    assessment = assess_canonical_route(
        CanonicalRouteMaterialization.capture(
            _graph(include_target=False), phase=CanonicalRouteAssessmentPhase.PROJECTED,
            generation=4,
        ), _evidence(),
    )
    assert assessment.rejected
    assert assessment.bound_evidence is None
    assert assessment.rejection_reason is CanonicalRouteAssessmentRejection.ROUTE_BINDING_FAILED


def test_typed_binding_result_reports_stage_and_seals_assessment_failures() -> None:
    evidence = _evidence()
    graph = _graph(include_target=False)
    result = bind_canonical_semantic_evidence_result(graph, evidence)
    assert type(result) is CanonicalRouteBindingResult
    assert result.bound_evidence is None
    assert tuple(item.stage for item in result.failures) == (
        CanonicalRouteBindingStage.DESTINATION_IDENTITY,
    )
    failure = result.failures[0]
    assert type(failure) is CanonicalRouteBindingFailure
    assessment = assess_canonical_route(
        CanonicalRouteMaterialization.capture(
            graph,
            phase=CanonicalRouteAssessmentPhase.PROJECTED,
            generation=4,
        ),
        evidence,
    )
    assert assessment.binding_failures == result.failures
    assert validate_canonical_route_assessment(assessment) is assessment
    object.__setattr__(assessment, "binding_failures", ())
    with pytest.raises((TypeError, ValueError)):
        validate_canonical_route_assessment(assessment)


def test_route_assessment_is_in_memory_and_seals_bound_mapping() -> None:
    assessment = assess_canonical_route(
        CanonicalRouteMaterialization.capture(
            _direct_graph(), phase=CanonicalRouteAssessmentPhase.SOURCE,
            generation=3,
        ), _evidence(),
    )
    with pytest.raises(TypeError, match="canonical encoding"):
        canonical_bytes(assessment)
    with pytest.raises(TypeError, match="copied"):
        copy.copy(assessment)
    forged_bound = replace(assessment.bound_evidence, routes=())
    object.__setattr__(assessment, "bound_evidence", forged_bound)
    with pytest.raises(ValueError):
        validate_canonical_route_assessment(assessment)


@pytest.mark.parametrize("family", ("destinations", "carriers"))
def test_bound_route_nested_collections_require_exact_tuples(family: str) -> None:
    materialization = CanonicalRouteMaterialization.capture(
        _direct_graph(), phase=CanonicalRouteAssessmentPhase.SOURCE, generation=3,
    )
    assessment = assess_canonical_route(materialization, _evidence())
    route = assessment.bound_evidence.routes[0]
    if family == "destinations":
        forged_route = replace(route, destinations=list(route.destinations))
    elif family == "carriers":
        forged_route = replace(route, carriers=list(route.carriers))
    forged_bound = replace(assessment.bound_evidence, routes=(forged_route,))
    object.__setattr__(assessment, "bound_evidence", forged_bound)
    with pytest.raises((TypeError, ValueError)):
        validate_canonical_route_assessment(assessment)


@pytest.mark.parametrize("reciprocal", (False,))
def test_direct_state_assignment_rejects_delivery_edge_drift(reciprocal: bool) -> None:
    proof = replace(
        _proof(),
        state_write=replace(
            _proof().state_write,
            delivery_kind=SemanticStateWriteDeliveryKind.DIRECT,
        ),
    )

    assert bind_canonical_semantic_evidence(
        _direct_graph(reciprocal=reciprocal), _evidence(proof)
    ) is None


def test_direct_state_assignment_accepts_extra_target_predecessor() -> None:
    proof = replace(
        _proof(),
        state_write=replace(
            _proof().state_write,
            delivery_kind=SemanticStateWriteDeliveryKind.DIRECT,
        ),
    )
    graph = _direct_graph()
    target = graph.blocks[2]
    graph = replace(graph, blocks={**graph.blocks, 2: replace(target, preds=(1, 0))})

    assert bind_canonical_semantic_evidence(graph, _evidence(proof)) is not None


def test_direct_state_assignment_rejects_extra_source_successor() -> None:
    proof = replace(
        _proof(),
        state_write=replace(
            _proof().state_write,
            delivery_kind=SemanticStateWriteDeliveryKind.DIRECT,
        ),
    )
    graph = _direct_graph()
    source = graph.blocks[1]
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            1: replace(source, succs=(2, 0)),
        },
    )

    assert bind_canonical_semantic_evidence(graph, _evidence(proof)) is None


@pytest.mark.parametrize("transfer_kind", ("goto", "nop"))
def test_direct_state_assignment_replays_authority_transfer(transfer_kind: str) -> None:
    from d810.ir.semantics import CallKind

    source_identity = StableBlockIdentity.from_instruction_eas(
        (0x1100, 0x1101, 0x1102, 0x1103),
        native_key=NATIVE_KEY,
    )
    baseline = _proof()
    state_write = replace(
        baseline.state_write,
        identity=source_identity,
        delivery_kind=SemanticStateWriteDeliveryKind.DIRECT,
        corridor_instruction_eas=(0x1100, 0x1101, 0x1102),
        preserved_call_instruction_eas=(0x1101,),
        authority_transfer_ea=0x1103,
    )
    proof = replace(
        baseline,
        source_identity=source_identity,
        source_anchor_ea=0x1102,
        delivery_region=NativeEaInterval(0x1100, 0x1104),
        state_write=state_write,
    )
    graph = _direct_graph()
    source = graph.blocks[1]
    transfer = (
        InsnSnapshot(
            opcode=0,
            ea=0x1103,
            operands=(),
            d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2),
            kind=InsnKind.GOTO,
        )
        if transfer_kind == "goto"
        else InsnSnapshot(opcode=0, ea=0x1103, operands=(), kind=InsnKind.NOP)
    )
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            1: replace(
                source,
                insn_snapshots=(
                    source.insn_snapshots[0],
                    InsnSnapshot(
                        opcode=0,
                        ea=0x1101,
                        operands=(),
                        kind=InsnKind.CALL,
                        call_kind=CallKind.DIRECT,
                        is_call=True,
                    ),
                    InsnSnapshot(opcode=0, ea=0x1102, operands=(), kind=InsnKind.NOP),
                    transfer,
                ),
            ),
        },
    )

    bound = bind_canonical_semantic_evidence(graph, _evidence(proof))
    if transfer_kind == "goto":
        assert bound is not None
    else:
        assert bound is None


def test_direct_proof_separates_anchor_identity_from_delivery_region() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1100, 0x1101),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1100,),
    )
    baseline = _proof()

    proof = replace(
        baseline,
        source_identity=source,
        delivery_region=NativeEaInterval(0x1100, 0x1110),
        state_write=replace(baseline.state_write, identity=source),
    )

    assert proof.source_identity.native_ranges.intervals == (
        NativeEaInterval(0x1100, 0x1101),
    )
    assert proof.delivery_region == NativeEaInterval(0x1100, 0x1110)


def test_conditional_proof_requires_both_semantic_arms() -> None:
    proof = _proof()

    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="both conditional roles",
    ):
        replace(
            proof,
            proof_kind=SemanticRouteProofKind.STATE_CHOICE,
            shape=SemanticRouteShape.CONDITIONAL,
            delivery_region=None,
            predicate=SemanticPredicateProof(
                kind=SemanticPredicateKind.PRESERVE_LIVE,
                origin=SemanticCorridorPoint(_identity(0x1100), 0x1100),
                consumer=SemanticCorridorPoint(_identity(0x1100), 0x1100),
                corridor=(SemanticCorridorPoint(_identity(0x1100), 0x1100),),
                true_is_taken=True,
            ),
            state_write=None,
        )


def test_storage_predicate_requires_carrier_and_complete_corridors() -> None:
    source = _identity(0x1100)
    producer = _identity(0x1080)
    target_a = _identity(0x1200)
    target_b = _identity(0x1300)
    predicate_storage = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    carrier_storage = StorageIdentity(StorageIdentityKind.STACK, 0x48)
    predicate = SemanticPredicateProof(
        kind=SemanticPredicateKind.STORAGE_EQUALS,
        origin=SemanticCorridorPoint(producer, 0x1080),
        consumer=SemanticCorridorPoint(source, 0x1100),
        corridor=(
            SemanticCorridorPoint(producer, 0x1080),
            SemanticCorridorPoint(source, 0x1100),
        ),
        storage_identity=predicate_storage,
        width=4,
        compare_constant=0,
    )
    carrier = SemanticCarrierProof(
        carrier_id="entry-state-choice",
        definition=SemanticCorridorPoint(producer, 0x1088),
        consumers=(SemanticCorridorPoint(source, 0x1100),),
        corridor=(
            SemanticCorridorPoint(producer, 0x1088),
            SemanticCorridorPoint(source, 0x1100),
        ),
        storage_identity=carrier_storage,
        width=4,
        state_values=(0xAABBCCDD, 0x11223344),
        permitted_write_eas=frozenset({0x1088}),
    )
    proof = SemanticRouteProof(
        proof_id="state-choice@0x1100",
        atomic_group_id="canonical-semantic:g3",
        proof_kind=SemanticRouteProofKind.STATE_CHOICE,
        shape=SemanticRouteShape.CONDITIONAL,
        source_identity=source,
        source_anchor_ea=0x1100,
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                state_constant=0xAABBCCDD,
                target_identity=target_a,
                target_anchor_ea=0x1200,
            ),
            SemanticRouteDestination(
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                state_constant=0x11223344,
                target_identity=target_b,
                target_anchor_ea=0x1300,
            ),
        ),
        predicate=predicate,
        carriers=(carrier,),
    )

    assert proof.predicate == predicate
    assert proof.carriers == (carrier,)
    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="storage predicate requires one carrier proof",
    ):
        replace(proof, carriers=())
    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="corridor must end at its consumer",
    ):
        replace(
            predicate,
            corridor=(SemanticCorridorPoint(producer, 0x1080),),
        )
    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="carrier state values must match destination states",
    ):
        replace(
            proof,
            carriers=(
                replace(
                    carrier,
                    state_values=(0xAABBCCDD, 0x55667788),
                ),
            ),
        )


def test_atomic_group_binding_abstains_instead_of_partially_binding() -> None:
    evidence = _evidence()

    assert (
        bind_canonical_semantic_evidence(_graph(include_target=False), evidence) is None
    )

    bound = bind_canonical_semantic_evidence(_graph(), evidence)

    assert bound is not None
    assert bound.atomic_group_id == evidence.atomic_group_id
    assert len(bound.routes) == 1
    assert bound.routes[0].source.serial == 1
    assert bound.routes[0].source.anchor_ea == 0x1100
    assert bound.routes[0].destinations[0].block.serial == 2
    assert bound.routes[0].destinations[0].block.anchor_ea == 0x1200


def test_binding_uses_exact_identity_when_branch_ea_has_a_helper_owner() -> None:
    source_identity = StableBlockIdentity.from_instruction_eas(
        (0x1100, 0x1105),
        native_key=NATIVE_KEY,
    )
    proof = replace(
        _proof(),
        source_identity=source_identity,
        source_anchor_ea=0x1105,
        delivery_region=NativeEaInterval(0x1105, 0x1106),
        state_write=SemanticStateWriteProof(
            identity=source_identity,
            instruction_ea=0x1100,
            state_variable=StorageIdentity(
                StorageIdentityKind.REGISTER,
                20,
            ),
            width=4,
            state_constant=0xAABBCCDD,
            corridor_instruction_eas=(0x1100, 0x1105),
            authority_transfer_ea=None,
            preserved_call_instruction_eas=(),
        ),
    )
    graph = FlowGraph(
        blocks={
            0: _block(0, 0x1000, succs=(1,), preds=()),
            1: replace(
                _block(
                    1,
                    0x1100,
                    succs=(3, 5),
                    preds=(0,),
                    insn_eas=(0x1100, 0x1105),
                ),
                insn_snapshots=(
                    InsnSnapshot(
                        0,
                        0x1100,
                        (),
                        l=MopSnapshot(
                            kind=OperandKind.NUMBER,
                            size=4,
                            value=0xAABBCCDD,
                        ),
                        d=MopSnapshot(
                            kind=OperandKind.REGISTER,
                            size=4,
                            reg=20,
                        ),
                        kind=InsnKind.MOV,
                        value_op_kind=ValueOpKind.MOVE,
                    ),
                    InsnSnapshot(0, 0x1105, (), kind=InsnKind.NOP),
                ),
            ),
            2: _block(2, 0x1200, succs=(), preds=(3, 5)),
            3: _block(3, 0x1105, succs=(2,), preds=(1,)),
            5: _block(
                5,
                0x1105,
                succs=(2,),
                preds=(1,),
                insn_eas=(0x1105,),
            ),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    bound = bind_canonical_semantic_evidence(graph, _evidence(proof))

    assert bound is not None
    assert bound.routes[0].source.serial == 1
    assert bound.routes[0].source.anchor_ea == 0x1105


def test_conditional_corridors_bind_all_or_abstain() -> None:
    proof = _storage_choice_proof()
    graph = FlowGraph(
        blocks={
            0: _block(0, 0x1000, succs=(1,), preds=()),
            1: _block(
                1,
                0x1080,
                succs=(2,),
                preds=(0,),
                insn_eas=(0x1080, 0x1088),
            ),
            2: _block(2, 0x1100, succs=(3, 4), preds=(1,)),
            3: _block(3, 0x1200, succs=(), preds=(2,)),
            4: _block(4, 0x1300, succs=(), preds=(2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    bound = bind_canonical_semantic_evidence(
        graph,
        _evidence(proof),
    )

    assert bound is None

    graph_without_producer = FlowGraph(
        blocks={
            0: _block(0, 0x1000, succs=(2,), preds=()),
            2: _block(2, 0x1100, succs=(3, 4), preds=(0,)),
            3: _block(3, 0x1200, succs=(), preds=(2,)),
            4: _block(4, 0x1300, succs=(), preds=(2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    assert (
        bind_canonical_semantic_evidence(
            graph_without_producer,
            _evidence(proof),
        )
        is None
    )


def test_semantic_evidence_capability_is_structural() -> None:
    evidence = _evidence()

    class _Provider:
        def evidence_for(self, function_ea: int):
            return evidence if int(function_ea) == 0x1000 else None

    assert isinstance(_Provider(), CanonicalSemanticEvidenceCapability)
