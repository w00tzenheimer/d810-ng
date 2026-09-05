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
    DecisionDagComparisonWitness,
    RuntimeRouteIdentity,
    runtime_semantic_evidence_from_proofs,
    runtime_semantic_route_scope,
    semantic_evidence_with_additional_proofs,
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
    SemanticDagNamespaceBridge,
    SemanticDagEndpointKind,
    SemanticLogicalDagEndpoint,
    SemanticDecisionDagWitness,
    SemanticSwitchTableHandoff,
    SemanticCarrierProof,
    SemanticCorridorPoint,
    SemanticPredicateKind,
    SemanticPredicateProof,
    SemanticRouteDestination,
    SemanticRouteEvidenceRejected,
    SemanticRouteProof,
    SemanticRouteProofKind,
    SemanticRouteShape,
    SemanticPhysicalStateWriteWitness,
    SemanticRecoveredStateWriteWitness,
    SemanticStateWriteDeliveryKind,
    SemanticStateWriteProof,
    SemanticStateDagProof,
    SemanticStatePartitionProof,
    SemanticPartitionMemberProof,
    SemanticPartitionMemberReplacementWitness,
    StatePartitionConditionalEdgeWitness,
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
from d810.analyses.control_flow.route_comparison import (
    ExactU32XduNamespaceBridge,
    current_u32_route_comparison,
)
from d810.analyses.control_flow.route_predicate import RouteComparison
from d810.analyses.control_flow.semantic_transition import NativeBoundTransitionRoute
from d810.analyses.control_flow.state_carrier import (
    ExactCarrierStateWrite,
    prove_exact_u32_state_transform_feeder,
)
from d810.transforms.unflatten_authority.ids import (
    canonical_bytes,
    canonical_decode,
    semantic_graph_fingerprint,
    validate_canonical_roundtrip,
)
from d810.core.runtime_identity import (
    RuntimeAuthorityKind,
    RuntimeAuthorityScope,
    is_runtime_authority_identity,
)
from d810.capabilities.semantic_routes import CanonicalSemanticEvidenceCapability
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.ir.flowgraph import BlockKind, InsnKind, MopSnapshot, OperandKind, PredicateKind
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


def _unsafe_field_replace(value: object, **changes: object) -> object:
    """Build adversarial nested evidence without rerunning its constructor."""

    forged = object.__new__(type(value))
    for name in value.__dataclass_fields__:
        object.__setattr__(
            forged,
            name,
            changes.get(name, getattr(value, name)),
        )
    return forged


def _native_bound_production_inputs(*, generation: int = 1):
    graph = _direct_graph()
    state_identity = StorageIdentity(StorageIdentityKind.REGISTER, 20)
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
        physical_state_write=SemanticPhysicalStateWriteWitness(
            route_evidence._instruction_projection(graph.blocks[1].insn_snapshots[0]),
            state_identity,
            4,
            0xAABBCCDD,
        ),
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        generation,
        "canonical-semantic:typed-result",
        state_identity,
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
            tuple(DecisionDagComparisonWitness(serial, comparison, context.state_identity) for serial, comparison in ()),
            (),
        ),
    )
    bootstrap_fact = replace(
        fact,
        kind=SemanticRouteFactKind.BOOTSTRAP,
        physical_state_write=None,
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
            7: BlockSnapshot(
                serial=7,
                block_type=1,
                succs=(8,),
                preds=(6,),
                flags=0,
                start_ea=0x1700,
                insn_snapshots=(InsnSnapshot(
                    opcode=0,
                    ea=0x1700,
                    operands=(),
                    kind=InsnKind.TABLE_JUMP,
                    l=MopSnapshot(kind=OperandKind.SUBINSN, size=4, stack_refs=(0x40,)),
                    r=MopSnapshot(
                        kind=OperandKind.CASE_LIST,
                        switch_cases=(((constant,), 8), ((constant + 1,), 8)),
                    ),
                ),),
            ),
            8: _block(8, 0x1800, succs=(), preds=(7,)),
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
        tuple(DecisionDagComparisonWitness(serial, comparison, state) for serial, comparison in ((6, RouteComparison(6, "jz", constant, 7, 11)),)),
        (),
        handoff_dispatcher_serial=7,
        handoff_dispatcher_anchor_ea=0x1700,
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
        target_serial=8,
        owner_anchor_ea=0x1500,
        target_anchor_ea=0x1800,
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
    binding = bind_canonical_semantic_evidence_result(graph, evidence)
    assert binding.bound_evidence is not None, binding.failures

    proof = evidence.route_proofs[0]
    _ordinary_graph, ordinary_evidence = _ordinary_decision_dag_evidence()
    ordinary = ordinary_evidence.route_proofs[0]
    assert proof.state_write is not None and proof.state_dag is not None
    assert proof.state_dag.switch_handoff is not None
    assert proof.state_dag.switch_handoff.dispatcher.anchor_ea == 0x1700
    assert ordinary.state_write is not None and ordinary.state_dag is not None
    co_keyed_witness = replace(
        ordinary.state_dag.witness,
        state_constant=proof.destinations[0].state_constant,
    )
    co_keyed_state_dag = replace(
        ordinary.state_dag,
        witness=co_keyed_witness,
        target_identity=proof.destinations[0].target_identity,
        target_anchor_ea=proof.destinations[0].target_anchor_ea,
    )
    co_keyed_dag = replace(
        ordinary,
        proof_id="decision-dag:co-keyed-bootstrap",
        destinations=proof.destinations,
        state_write=replace(
            ordinary.state_write,
            state_constant=proof.destinations[0].state_constant,
        ),
        state_dag=co_keyed_state_dag,
    )
    distinct_kinds = canonical_semantic_evidence_from_proofs(
        NATIVE_KEY, 1, (proof, co_keyed_dag),
    )
    assert len(distinct_kinds.route_proofs) == 2
    assert {item.proof_kind for item in distinct_kinds.route_proofs} == {
        SemanticRouteProofKind.BOOTSTRAP,
        SemanticRouteProofKind.STATE_DAG,
    }
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
        physical_state_write=None,
        decision_dag_witness=DecisionDagRouteWitness(
            context.state_identity,
            fact.state_constant,
            1,
            0x9999,
            (1,),
            (0x9999,),
            tuple(DecisionDagComparisonWitness(serial, comparison, context.state_identity) for serial, comparison in ()),
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
    assert result.abstention.detail == "model rejection"


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
            physical_state_write=None,
            decision_dag_witness=DecisionDagRouteWitness(
                context.state_identity if state_identity is None else state_identity,
                fact.state_constant,
                1,
                0x1100,
                (1,),
                (0x1100,),
                tuple(DecisionDagComparisonWitness(serial, comparison, context.state_identity if state_identity is None else state_identity) for serial, comparison in comparisons),
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
        physical_state_write=SemanticPhysicalStateWriteWitness(
            route_evidence._instruction_projection(graph.blocks[1].insn_snapshots[0]),
            StorageIdentity(StorageIdentityKind.REGISTER, 20),
            4,
            route.state_constant,
        ),
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
    malformed = build_canonical_semantic_evidence(
        (fact,), replace(context, blocks=(graph.blocks[0], ambiguous, graph.blocks[2]))
    )
    assert malformed.evidence is None
    assert malformed.abstention is not None
    assert (
        malformed.abstention.reason
        is CanonicalSemanticEvidenceProductionReason.NATIVE_BOUND_SOURCE_ASSIGNMENT_INVALID
    )


def test_dispatcher_map_fact_mints_canonical_state_assignment() -> None:
    """An exact dispatcher-map verdict enters the same canonical route model."""

    graph = _direct_graph()
    identities = {
        serial: _identity(int(block.start_ea))
        for serial, block in graph.blocks.items()
    }
    state = StorageIdentity(StorageIdentityKind.REGISTER, 20)
    fact = SemanticRouteFact(
        SemanticRouteFactKind.DISPATCHER_MAP,
        1,
        1,
        0x1100,
        0xAABBCCDD,
        2,
        0x1100,
        0x1200,
        (1,),
        (),
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        1,
        "canonical-semantic:dispatcher-map",
        state,
        tuple(graph.blocks.values()),
        tuple(identities.items()),
    )

    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    proof = evidence.route_proofs[0]

    assert proof.proof_kind is SemanticRouteProofKind.STATE_ASSIGNMENT
    assert proof.state_write is not None
    assert proof.state_write.state_variable == state
    assert proof.diagnostic_provenance == (("fact_kind", "dispatcher_map"),)
    binding = bind_canonical_semantic_evidence_result(graph, evidence)
    assert binding.bound_evidence is not None, binding.failures


def test_native_bound_producer_binds_exact_physical_carrier_write() -> None:
    """A native receipt without a state-MOV witness cannot override context."""
    graph = _direct_graph()
    identities = {
        serial: _identity(int(block.start_ea))
        for serial, block in graph.blocks.items()
    }
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
        "native:physical-carrier",
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        1,
        "canonical-semantic:physical-carrier",
        StorageIdentity(StorageIdentityKind.STACK, 0x40),
        tuple(graph.blocks.values()),
        tuple(identities.items()),
    )

    result = build_canonical_semantic_evidence((fact,), context)
    assert result.evidence is None
    assert result.abstention is not None
    assert result.abstention.reason is (
        CanonicalSemanticEvidenceProductionReason.NATIVE_BOUND_SOURCE_ASSIGNMENT_INVALID
    )


def _native_bound_receipt_with_later_state_write(
    *,
    physical_writes: int = 1,
    physical_constant: int = 0xAABBCCDD,
    physical_identity: StorageIdentity | None = None,
    physical_width: int = 4,
    physical_serial: int = 1,
    physical_ea: int = 0x1108,
) -> tuple[FlowGraph, SemanticRouteFact, CanonicalSemanticEvidenceProductionContext]:
    """One receipt at 0x1100 and configurable physical MOV state writers."""
    graph = _direct_graph()
    state_identity = physical_identity or StorageIdentity(StorageIdentityKind.STACK, 0x40)
    writes = tuple(
        InsnSnapshot(
            opcode=0,
            ea=physical_ea + index * 4,
            operands=(),
            l=MopSnapshot(kind=OperandKind.NUMBER, size=physical_width, value=physical_constant),
            d=(
                MopSnapshot(kind=OperandKind.STACK, size=physical_width, stkoff=0x40)
                if state_identity.kind is StorageIdentityKind.STACK
                else MopSnapshot(kind=OperandKind.REGISTER, size=physical_width, reg=state_identity.offset)
            ),
            kind=InsnKind.MOV,
            value_op_kind=ValueOpKind.MOVE,
        )
        for index in range(physical_writes)
    )
    blocks = dict(graph.blocks)
    if physical_serial == 1:
        source = graph.blocks[1]
        blocks[1] = replace(source, insn_snapshots=(*source.insn_snapshots, *writes))
    else:
        blocks[physical_serial] = BlockSnapshot(
            serial=physical_serial,
            block_type=0,
            succs=(),
            preds=(),
            flags=0,
            start_ea=physical_ea,
            insn_snapshots=writes,
        )
    graph = FlowGraph(
        blocks=blocks,
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )
    identities = {
        serial: _identity(int(block.start_ea))
        for serial, block in graph.blocks.items()
    }
    identities[1] = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1100, 0x1110),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1100, *(int(write.ea) for write in writes)),
    )
    fact = SemanticRouteFact(
        SemanticRouteFactKind.NATIVE_BOUND,
        1,
        1,
        0x1100,
        0xAABBCCDD,
        2,
        0x1100,
        0x1200,
        (1,),
        (),
        "native:separate-state-write",
        physical_state_write=SemanticPhysicalStateWriteWitness(
            route_evidence._instruction_projection(writes[0]),
            state_identity,
            physical_width,
            0xAABBCCDD,
        ),
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        1,
        "canonical-semantic:separate-state-write",
        StorageIdentity(StorageIdentityKind.STACK, 0x40),
        tuple(graph.blocks.values()),
        tuple(identities.items()),
    )
    return graph, fact, context


def test_native_bound_producer_keeps_receipt_provenance_and_binds_later_state_write() -> None:
    """A receipt can precede its one exact physical U32 state write."""
    graph, fact, context = _native_bound_receipt_with_later_state_write()

    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    proof = evidence.route_proofs[0]

    assert proof.source_anchor_ea == 0x1100
    assert proof.state_write is not None
    assert proof.state_write.instruction_ea == 0x1108
    assert proof.state_write.state_variable == StorageIdentity(StorageIdentityKind.STACK, 0x40)
    assert bind_canonical_semantic_evidence(graph, evidence) is not None


def test_decision_assignment_binds_predecessor_write_and_goto_delivery_separately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    constant = 0x1AEA4348
    write = InsnSnapshot(
        opcode=0,
        ea=0x1704,
        operands=(),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=constant),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
    )
    delivery = InsnSnapshot(
        opcode=0,
        ea=0x1710,
        operands=(),
        l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=3),
        kind=InsnKind.GOTO,
    )
    graph = FlowGraph(
        blocks={
            70: replace(_block(70, 0x1700, succs=(71,), preds=()), insn_snapshots=(write,)),
            71: replace(_block(71, 0x1710, succs=(3,), preds=(70,)), insn_snapshots=(delivery,)),
            3: BlockSnapshot(
                serial=3,
                block_type=2,
                succs=(47, 48),
                preds=(71,),
                flags=0,
                start_ea=0x1300,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=0x1300,
                        operands=(),
                        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
                        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=constant),
                        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=47),
                        kind=InsnKind.COND_JUMP,
                        branch_predicate=PredicateKind.EQ,
                        is_conditional_jump=True,
                    ),
                ),
            ),
            47: _block(47, 0x1470, succs=(), preds=(3,)),
            48: _block(48, 0x1480, succs=(), preds=(3,)),
        },
        entry_serial=70,
        func_ea=0x1000,
    )
    identities = {
        70: StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x1700, 0x1710),), native_key=NATIVE_KEY,
            exact_instruction_eas=(0x1704,),
        ),
        71: _identity(0x1710),
        3: _identity(0x1300),
        47: _identity(0x1470),
        48: _identity(0x1480),
    }
    fact = SemanticRouteFact(
        SemanticRouteFactKind.DECISION_DAG,
        71,
        71,
        0x1710,
        constant,
        47,
        0x1710,
        0x1470,
        (71,),
        (),
        decision_dag_witness=DecisionDagRouteWitness(
            state,
            constant,
            3,
            0x1300,
            (3,),
            (0x1300,),
            (
                DecisionDagComparisonWitness(
                    3,
                    RouteComparison(3, "jz", constant, 47, 48),
                    state,
                ),
            ),
            (),
        ),
        physical_state_write=SemanticPhysicalStateWriteWitness(
            route_evidence._instruction_projection(write),
            state,
            4,
            constant,
            source_serial=70,
        ),
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY, 1, "canonical-semantic:predecessor-delivery", state,
        tuple(graph.blocks.values()), tuple(identities.items()),
    )

    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    proof = evidence.route_proofs[0]
    assert proof.source_identity == identities[71]
    assert proof.source_owner_identity == identities[70]
    assert proof.state_write is not None
    assert proof.state_write.identity == identities[70]
    assert proof.state_write.corridor_instruction_eas == (0x1704, 0x1710)
    assert bind_canonical_semantic_evidence(graph, evidence) is not None

    drifted = replace(
        graph,
        blocks={
            **graph.blocks,
            70: replace(graph.blocks[70], succs=(3,)),
        },
    )
    assert bind_canonical_semantic_evidence(drifted, evidence) is None

    nop_delivery = replace(
        graph,
        blocks={
            **graph.blocks,
            71: replace(
                graph.blocks[71],
                insn_snapshots=(
                    replace(delivery, kind=InsnKind.NOP, l=None),
                ),
            ),
        },
    )
    assert bind_canonical_semantic_evidence(nop_delivery, evidence) is None

    wrong_goto_target = replace(
        graph,
        blocks={
            **graph.blocks,
            71: replace(
                graph.blocks[71],
                insn_snapshots=(replace(
                    delivery,
                    l=replace(delivery.l, block_ref=48),
                ),),
            ),
        },
    )
    assert bind_canonical_semantic_evidence(wrong_goto_target, evidence) is None

    second_predecessor = replace(_block(72, 0x1720, succs=(71,), preds=()))
    ambiguous_delivery = replace(
        graph,
        blocks={
            **graph.blocks,
            71: replace(graph.blocks[71], preds=(70, 72)),
            72: second_predecessor,
        },
    )
    assert bind_canonical_semantic_evidence(ambiguous_delivery, evidence) is None

    missing_physical = build_canonical_semantic_evidence(
        (replace(fact, physical_state_write=None),),
        context,
    )
    assert missing_physical.evidence is None
    assert missing_physical.abstention is not None
    assert (
        missing_physical.abstention.reason
        is CanonicalSemanticEvidenceProductionReason.NATIVE_BOUND_SOURCE_ASSIGNMENT_INVALID
    )

    wrong_writer = replace(
        fact,
        physical_state_write=replace(
            fact.physical_state_write,
            source_serial=48,
        ),
    )
    rejected = build_canonical_semantic_evidence((wrong_writer,), context)
    assert rejected.evidence is None
    assert rejected.abstention is not None
    assert (
        rejected.abstention.reason
        is CanonicalSemanticEvidenceProductionReason.NATIVE_BOUND_SOURCE_ASSIGNMENT_INVALID
    )

    original_project_instruction = route_evidence.project_instruction

    def project_with_drifted_canonical_target(snapshot: InsnSnapshot):
        instruction = original_project_instruction(snapshot)
        if snapshot is delivery:
            assert instruction.control is not None
            return replace(
                instruction,
                control=replace(instruction.control, target=48),
            )
        return instruction

    monkeypatch.setattr(
        route_evidence,
        "project_instruction",
        project_with_drifted_canonical_target,
    )
    canonical_target_drift = build_canonical_semantic_evidence((fact,), context)
    assert canonical_target_drift.evidence is None


def test_state_assignment_split_alias_store_mints_exact_semantic_owner() -> None:
    """A split STORE assignment binds through alias owner, writer, and GOTO."""

    state = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    physical_constant = 0xDD1FF05BF465445C
    constant = physical_constant & 0xFFFFFFFF
    alias_definition = InsnSnapshot(
        opcode=0,
        ea=0x1690,
        operands=(),
        l=MopSnapshot(
            kind=OperandKind.ADDRESS,
            size=8,
            stack_refs=(0x40,),
            sub_l=MopSnapshot(
                kind=OperandKind.STACK, size=4, stkoff=0x40,
            ),
        ),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=3),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
    )
    store = InsnSnapshot(
        opcode=0,
        ea=0x1704,
        operands=(),
        l=MopSnapshot(
            kind=OperandKind.NUMBER, size=8, value=physical_constant,
        ),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=3),
        kind=InsnKind.STORE,
        value_op_kind=ValueOpKind.STORE,
    )
    delivery = InsnSnapshot(
        opcode=0,
        ea=0x1710,
        operands=(),
        l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=47),
        kind=InsnKind.GOTO,
    )
    graph = FlowGraph(
        blocks={
            69: replace(
                _block(69, 0x1690, succs=(70,), preds=()),
                insn_snapshots=(alias_definition,),
            ),
            70: replace(
                _block(70, 0x1700, succs=(71,), preds=(69,)),
                insn_snapshots=(store,),
            ),
            71: replace(
                _block(71, 0x1710, succs=(47,), preds=(70,)),
                insn_snapshots=(delivery,),
            ),
            47: _block(
                47, 0x1470, succs=(), preds=(71,), insn_eas=(0x1470,),
            ),
        },
        entry_serial=69,
        func_ea=0x1000,
    )
    identities = {
        serial: route_evidence.stable_block_identity_from_snapshot(
            block, native_key=NATIVE_KEY,
        )
        for serial, block in graph.blocks.items()
    }
    assert all(identity is not None for identity in identities.values())
    physical = SemanticPhysicalStateWriteWitness(
        route_evidence._instruction_projection(store),
        state,
        4,
        constant,
        source_serial=70,
        alias_definition_instruction=(
            route_evidence._instruction_projection(alias_definition)
        ),
        alias_definition_serial=69,
        physical_width=8,
        state_lane_offset=0,
    )
    fact = SemanticRouteFact(
        SemanticRouteFactKind.NATIVE_BOUND,
        69,
        71,
        0x1710,
        constant,
        47,
        0x1690,
        0x1470,
        (69, 70, 71),
        ((69, 70), (70, 71)),
        physical_state_write=physical,
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        1,
        "canonical-semantic:split-alias-store-assignment",
        state,
        tuple(graph.blocks.values()),
        tuple(identities.items()),
    )

    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    proof = evidence.route_proofs[0]
    assert proof.proof_kind is SemanticRouteProofKind.STATE_ASSIGNMENT
    assert proof.source_identity == identities[71]
    assert proof.source_owner_identity == identities[69]
    assert proof.source_owner_anchor_ea == 0x1690
    assert proof.state_write is not None
    assert proof.state_write.identity == identities[70]
    binding = bind_canonical_semantic_evidence_result(graph, evidence)
    assert binding.bound_evidence is not None, binding.failures

    wrong_owner_edge = replace(
        graph,
        blocks={
            **graph.blocks,
            69: replace(graph.blocks[69], succs=(71,)),
        },
    )
    assert bind_canonical_semantic_evidence(wrong_owner_edge, evidence) is None

    wrong_alias = replace(
        alias_definition,
        l=MopSnapshot(
            kind=OperandKind.ADDRESS,
            size=8,
            stack_refs=(0x44,),
            sub_l=MopSnapshot(
                kind=OperandKind.STACK, size=4, stkoff=0x44,
            ),
        ),
    )
    alias_drift = replace(
        graph,
        blocks={
            **graph.blocks,
            69: replace(graph.blocks[69], insn_snapshots=(wrong_alias,)),
        },
    )
    assert bind_canonical_semantic_evidence(alias_drift, evidence) is None


def test_shared_goto_delivery_closes_and_rebinds_every_physical_writer() -> None:
    """A shared delivery is authority only when its full writer partition binds."""

    state = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    first_constant = 0x1AEA4348
    second_constant = 0x7EC4A11D

    def state_write(ea: int, constant: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=0,
            ea=ea,
            operands=(),
            l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=constant),
            d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
            kind=InsnKind.MOV,
            value_op_kind=ValueOpKind.MOVE,
        )

    first_write = state_write(0x1704, first_constant)
    second_write = state_write(0x1724, second_constant)
    delivery = InsnSnapshot(
        opcode=0,
        ea=0x1730,
        operands=(),
        l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=3),
        kind=InsnKind.GOTO,
    )
    graph = FlowGraph(
        blocks={
            70: replace(_block(70, 0x1700, succs=(71,), preds=()), insn_snapshots=(first_write,)),
            72: replace(_block(72, 0x1720, succs=(71,), preds=()), insn_snapshots=(second_write,)),
            71: replace(_block(71, 0x1730, succs=(3,), preds=(70, 72)), insn_snapshots=(delivery,)),
            3: BlockSnapshot(
                serial=3,
                block_type=2,
                succs=(47, 48),
                preds=(71,),
                flags=0,
                start_ea=0x1300,
                insn_snapshots=(InsnSnapshot(
                    opcode=0,
                    ea=0x1300,
                    operands=(),
                    l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
                    r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=first_constant),
                    d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=47),
                    kind=InsnKind.COND_JUMP,
                    branch_predicate=PredicateKind.EQ,
                    is_conditional_jump=True,
                ),),
            ),
            47: _block(47, 0x1470, succs=(), preds=(3,)),
            48: _block(48, 0x1480, succs=(), preds=(3,)),
        },
        entry_serial=70,
        func_ea=0x1000,
    )
    identities = {
        serial: route_evidence.stable_block_identity_from_snapshot(
            block, native_key=NATIVE_KEY,
        )
        for serial, block in graph.blocks.items()
    }
    assert all(identity is not None for identity in identities.values())

    def fact(
        writer_serial: int,
        write: InsnSnapshot,
        constant: int,
        target_serial: int,
    ) -> SemanticRouteFact:
        return SemanticRouteFact(
            SemanticRouteFactKind.DECISION_DAG,
            writer_serial,
            71,
            0x1730,
            constant,
            target_serial,
            int(write.ea),
            int(graph.blocks[target_serial].start_ea),
            (writer_serial, 71),
            ((writer_serial, 71),),
            decision_dag_witness=DecisionDagRouteWitness(
                state,
                constant,
                3,
                0x1300,
                (3,),
                (0x1300,),
                (DecisionDagComparisonWitness(
                    3,
                    RouteComparison(3, "jz", first_constant, 47, 48),
                    state,
                ),),
                (),
            ),
            physical_state_write=SemanticPhysicalStateWriteWitness(
                route_evidence._instruction_projection(write),
                state,
                4,
                constant,
                source_serial=writer_serial,
            ),
        )

    first_fact = fact(70, first_write, first_constant, 47)
    second_fact = fact(72, second_write, second_constant, 48)
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        1,
        "canonical-semantic:shared-predecessor-delivery",
        state,
        tuple(graph.blocks.values()),
        tuple(identities.items()),
    )

    evidence = _accepted(build_canonical_semantic_evidence(
        (first_fact, second_fact), context,
    ))
    deliveries = tuple(
        proof.state_write.physical_delivery
        for proof in evidence.route_proofs
    )
    assert deliveries[0] == deliveries[1]
    assert tuple(member.instruction_ea for member in deliveries[0].members) == (
        0x1704,
        0x1724,
    )
    assert bind_canonical_semantic_evidence(graph, evidence) is not None

    omitted = build_canonical_semantic_evidence((first_fact,), context)
    assert omitted.evidence is None
    assert omitted.abstention.reason is CanonicalSemanticEvidenceProductionReason.NATIVE_BOUND_SOURCE_ASSIGNMENT_INVALID

    extra_predecessor = replace(
        graph,
        blocks={
            **graph.blocks,
            71: replace(graph.blocks[71], preds=(70, 72, 73)),
            73: _block(73, 0x1730, succs=(71,), preds=()),
        },
    )
    assert bind_canonical_semantic_evidence(extra_predecessor, evidence) is None

    identity_drift = replace(
        graph,
        blocks={
            **graph.blocks,
            72: replace(graph.blocks[72], start_ea=0x1730),
        },
    )
    assert bind_canonical_semantic_evidence(identity_drift, evidence) is None

    first_proof = evidence.route_proofs[0]
    first_delivery = first_proof.state_write.physical_delivery
    sibling_index = next(
        index
        for index, member in enumerate(first_delivery.members)
        if member.identity != first_proof.state_write.identity
    )
    wrong_sibling = _unsafe_field_replace(
        first_delivery.members[sibling_index],
        physical_state_write=_unsafe_field_replace(
            first_delivery.members[sibling_index].physical_state_write,
            state_constant=(
                first_delivery.members[sibling_index].state_constant ^ 1
            ),
        ),
    )
    forged_members = list(first_delivery.members)
    forged_members[sibling_index] = wrong_sibling
    forged_delivery = replace(
        first_delivery,
        members=tuple(forged_members),
    )
    forged_proof = replace(
        first_proof,
        state_write=replace(
            first_proof.state_write,
            physical_delivery=forged_delivery,
        ),
    )
    forged = _recanonicalize_evidence(
        evidence,
        (forged_proof, evidence.route_proofs[1]),
    )
    assert bind_canonical_semantic_evidence(graph, forged) is None


def test_shared_goto_delivery_closes_exact_alias_store_writer() -> None:
    """A split physical delivery retains an exact predecessor alias STORE."""

    state = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    store_constant = 0xF465445C
    mov_constant = 0x1AEA4348
    alias_definition = InsnSnapshot(
        opcode=0, ea=0x1690, operands=(),
        l=MopSnapshot(
            kind=OperandKind.ADDRESS, size=8, stack_refs=(0x40,),
            sub_l=MopSnapshot(
                kind=OperandKind.STACK, size=4, stkoff=0x40,
            ),
        ),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=3),
        kind=InsnKind.MOV, value_op_kind=ValueOpKind.MOVE,
    )
    store = InsnSnapshot(
        opcode=0, ea=0x1704, operands=(),
        l=MopSnapshot(
            kind=OperandKind.NUMBER, size=8,
            value=0xDD1FF05BF465445C,
        ),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=3),
        kind=InsnKind.STORE, value_op_kind=ValueOpKind.STORE,
    )
    mov = InsnSnapshot(
        opcode=0, ea=0x1724, operands=(),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=mov_constant),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
        kind=InsnKind.MOV, value_op_kind=ValueOpKind.MOVE,
    )
    delivery = InsnSnapshot(
        opcode=0, ea=0x1730, operands=(),
        l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=3),
        kind=InsnKind.GOTO,
    )
    graph = FlowGraph(
        blocks={
            69: replace(
                _block(69, 0x1690, succs=(70,), preds=()),
                insn_snapshots=(alias_definition,),
            ),
            70: replace(
                _block(70, 0x1700, succs=(71,), preds=(69,)),
                insn_snapshots=(store,),
            ),
            72: replace(
                _block(72, 0x1720, succs=(71,), preds=()),
                insn_snapshots=(mov,),
            ),
            71: replace(
                _block(71, 0x1730, succs=(3,), preds=(70, 72)),
                insn_snapshots=(delivery,),
            ),
            3: BlockSnapshot(
                serial=3, block_type=2, succs=(47, 48), preds=(71,),
                flags=0, start_ea=0x1300,
                insn_snapshots=(InsnSnapshot(
                    opcode=0, ea=0x1300, operands=(),
                    l=MopSnapshot(
                        kind=OperandKind.STACK, size=4, stkoff=0x40,
                    ),
                    r=MopSnapshot(
                        kind=OperandKind.NUMBER, size=4,
                        value=store_constant,
                    ),
                    d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=47),
                    kind=InsnKind.COND_JUMP,
                    branch_predicate=PredicateKind.EQ,
                    is_conditional_jump=True,
                ),),
            ),
            47: _block(47, 0x1470, succs=(), preds=(3,)),
            48: _block(48, 0x1480, succs=(), preds=(3,)),
        },
        entry_serial=69,
        func_ea=0x1000,
    )
    identities = {
        serial: route_evidence.stable_block_identity_from_snapshot(
            block, native_key=NATIVE_KEY,
        )
        for serial, block in graph.blocks.items()
    }
    assert all(identity is not None for identity in identities.values())

    def fact(
        owner_serial: int,
        writer_serial: int,
        write: InsnSnapshot,
        constant: int,
        target_serial: int,
        physical: SemanticPhysicalStateWriteWitness,
    ) -> SemanticRouteFact:
        route_path = (
            (writer_serial, 71)
            if owner_serial == writer_serial
            else (owner_serial, writer_serial, 71)
        )
        return SemanticRouteFact(
            SemanticRouteFactKind.DECISION_DAG,
            owner_serial, 71, 0x1730, constant, target_serial,
            int(graph.blocks[owner_serial].start_ea),
            int(graph.blocks[target_serial].start_ea),
            route_path, tuple(zip(route_path, route_path[1:])),
            decision_dag_witness=DecisionDagRouteWitness(
                state, constant, 3, 0x1300, (3,), (0x1300,),
                (DecisionDagComparisonWitness(
                    3,
                    RouteComparison(3, "jz", store_constant, 47, 48),
                    state,
                ),),
                (),
            ),
            physical_state_write=physical,
        )

    facts = (
        fact(
            69, 70, store, store_constant, 47,
            SemanticPhysicalStateWriteWitness(
                route_evidence._instruction_projection(store),
                state, 4, store_constant, source_serial=70,
                alias_definition_instruction=(
                    route_evidence._instruction_projection(alias_definition)
                ),
                alias_definition_serial=69,
                physical_width=8,
                state_lane_offset=0,
            ),
        ),
        fact(
            72, 72, mov, mov_constant, 48,
            SemanticPhysicalStateWriteWitness(
                route_evidence._instruction_projection(mov),
                state, 4, mov_constant, source_serial=72,
            ),
        ),
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY, 1, "canonical-semantic:shared-alias-store-delivery",
        state, tuple(graph.blocks.values()), tuple(identities.items()),
    )

    evidence = _accepted(build_canonical_semantic_evidence(facts, context))
    delivery_proof = evidence.route_proofs[0].state_write.physical_delivery
    assert delivery_proof is not None
    assert {
        member.source_instruction.kind for member in delivery_proof.members
    } == {InsnKind.MOV, InsnKind.STORE}
    binding = bind_canonical_semantic_evidence_result(graph, evidence)
    assert binding.bound_evidence is not None, binding.failures

    changed_alias = replace(
        alias_definition,
        l=MopSnapshot(
            kind=OperandKind.ADDRESS,
            size=8,
            stack_refs=(0x44,),
            sub_l=MopSnapshot(
                kind=OperandKind.STACK, size=4, stkoff=0x44,
            ),
        ),
    )
    alias_drift = replace(
        graph,
        blocks={
            **graph.blocks,
            69: replace(graph.blocks[69], insn_snapshots=(changed_alias,)),
        },
    )
    assert bind_canonical_semantic_evidence(alias_drift, evidence) is None

    changed_store = replace(
        store,
        d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=4),
    )
    store_drift = replace(
        graph,
        blocks={
            **graph.blocks,
            70: replace(graph.blocks[70], insn_snapshots=(changed_store,)),
        },
    )
    assert bind_canonical_semantic_evidence(store_drift, evidence) is None

    alias_clobber = InsnSnapshot(
        opcode=0,
        ea=0xF000000000001691,
        native_ea=0x1690,
        operands=(),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=0),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=3),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
    )
    clobbered_alias_graph = replace(
        graph,
        blocks={
            **graph.blocks,
            69: replace(
                graph.blocks[69],
                insn_snapshots=(alias_definition, alias_clobber),
            ),
        },
    )
    assert bind_canonical_semantic_evidence(
        clobbered_alias_graph, evidence,
    ) is None
    clobbered_identities = tuple(
        (
            serial,
            route_evidence.stable_block_identity_from_snapshot(
                block, native_key=NATIVE_KEY,
            ),
        )
        for serial, block in clobbered_alias_graph.blocks.items()
    )
    assert all(identity is not None for _serial, identity in clobbered_identities)
    clobbered_production = build_canonical_semantic_evidence(
        facts,
        replace(
            context,
            blocks=tuple(clobbered_alias_graph.blocks.values()),
            identities_by_serial=clobbered_identities,
        ),
    )
    assert clobbered_production.evidence is None
    assert clobbered_production.abstention is not None
    assert (
        clobbered_production.abstention.reason
        is CanonicalSemanticEvidenceProductionReason.
        NATIVE_BOUND_SOURCE_ASSIGNMENT_INVALID
    )


def test_alias_store_binding_replays_predecessor_definition_and_exact_store() -> None:
    state = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    physical_constant = 0xDD1FF05BF465445C
    constant = physical_constant & 0xFFFFFFFF
    alias_definition = InsnSnapshot(
        opcode=0,
        ea=0x7000,
        operands=(),
        l=MopSnapshot(
            kind=OperandKind.ADDRESS,
            size=8,
            stack_refs=(0x40,),
            sub_l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
        ),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=3),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
    )
    store = InsnSnapshot(
        opcode=0,
        ea=0x8000,
        operands=(),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=physical_constant),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=3),
        kind=InsnKind.STORE,
        value_op_kind=ValueOpKind.STORE,
    )
    graph = FlowGraph(
        blocks={
            7: replace(_block(7, 0x7000, succs=(8,), preds=()), insn_snapshots=(alias_definition,)),
            8: replace(_block(8, 0x8000, succs=(2,), preds=(7,)), insn_snapshots=(store,)),
            2: _block(2, 0x2000, succs=(), preds=(8,)),
            20: _block(20, 0xA000, succs=(), preds=()),
        },
        entry_serial=7,
        func_ea=0x1000,
    )
    identities = {serial: _identity(int(block.start_ea)) for serial, block in graph.blocks.items()}
    witness = SemanticPhysicalStateWriteWitness(
        route_evidence._instruction_projection(store),
        state,
        4,
        constant,
        source_serial=8,
        alias_definition_instruction=route_evidence._instruction_projection(alias_definition),
        alias_definition_serial=7,
        physical_width=8,
        state_lane_offset=0,
    )
    fact = SemanticRouteFact(
        SemanticRouteFactKind.DECISION_DAG,
        7,
        8,
        0x8000,
        constant,
        20,
        0x7000,
        0xA000,
        (7, 8),
        ((7, 8),),
        physical_state_write=witness,
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY, 1, "canonical-semantic:alias-store", state,
        tuple(graph.blocks.values()), tuple(identities.items()),
    )

    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    binding = bind_canonical_semantic_evidence_result(graph, evidence)
    assert binding.bound_evidence is not None, binding.failures

    legacy_source_owner_fact = replace(
        fact,
        owner_serial=8,
        owner_anchor_ea=0x8000,
        path_serials=(8,),
        path_edges=(),
    )
    normalized = _accepted(build_canonical_semantic_evidence(
        (legacy_source_owner_fact,), context,
    ))
    normalized_proof = normalized.route_proofs[0]
    assert normalized_proof.source_owner_identity == identities[7]
    assert normalized_proof.source_owner_anchor_ea == 0x7000
    normalized_binding = bind_canonical_semantic_evidence_result(
        graph, normalized,
    )
    assert normalized_binding.bound_evidence is not None, normalized_binding.failures

    changed_alias = replace(
        alias_definition,
        l=MopSnapshot(
            kind=OperandKind.ADDRESS,
            size=8,
            stack_refs=(0x44,),
            sub_l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x44),
        ),
    )
    drifted = replace(
        graph,
        blocks={
            **graph.blocks,
            7: replace(graph.blocks[7], insn_snapshots=(changed_alias,)),
        },
    )
    assert bind_canonical_semantic_evidence(drifted, evidence) is None

    proof = evidence.route_proofs[0]
    changed_constant = constant ^ 1
    forged_witness = _unsafe_field_replace(
        proof.state_write.physical_state_write,
        state_constant=changed_constant,
    )
    forged_write = replace(
        proof.state_write,
        state_constant=changed_constant,
        physical_state_write=forged_witness,
    )
    forged_proof = replace(
        proof,
        state_write=forged_write,
        destinations=(replace(
            proof.destinations[0], state_constant=changed_constant,
        ),),
    )
    forged = _recanonicalize_evidence(evidence, (forged_proof,))
    assert bind_canonical_semantic_evidence(graph, forged) is None

    for field, value in (("physical_width", 4), ("state_lane_offset", 1)):
        forged_witness = _unsafe_field_replace(
            proof.state_write.physical_state_write,
            **{field: value},
        )
        forged_write = replace(
            proof.state_write,
            physical_state_write=forged_witness,
        )
        forged = _recanonicalize_evidence(
            evidence,
            (replace(proof, state_write=forged_write),),
        )
        assert bind_canonical_semantic_evidence(graph, forged) is None

    forged_store_projection = replace(
        proof.state_write.physical_state_write.source_instruction,
        d=replace(
            proof.state_write.physical_state_write.source_instruction.d,
            reg=4,
        ),
    )
    forged_witness = _unsafe_field_replace(
        proof.state_write.physical_state_write,
        source_instruction=forged_store_projection,
    )
    forged_write = replace(
        proof.state_write,
        physical_state_write=forged_witness,
    )
    forged = _recanonicalize_evidence(
        evidence,
        (replace(proof, state_write=forged_write),),
    )
    assert bind_canonical_semantic_evidence(graph, forged) is None


def _guarded_alias_store_inputs():
    state = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    full_value = 0xDD1FF05BF465445C
    alias_definition = InsnSnapshot(
        opcode=0,
        ea=0x7000,
        operands=(),
        l=MopSnapshot(
            kind=OperandKind.ADDRESS,
            size=8,
            stack_refs=(0x40,),
            sub_l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
        ),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=3),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
    )
    store = InsnSnapshot(
        opcode=0,
        ea=0x8000,
        operands=(),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=full_value),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=3),
        kind=InsnKind.STORE,
        value_op_kind=ValueOpKind.STORE,
    )
    branch = InsnSnapshot(
        opcode=44,
        ea=0x8004,
        operands=(),
        l=MopSnapshot(kind=OperandKind.STACK, size=8, stkoff=0x40),
        r=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=full_value),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2),
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=PredicateKind.NE,
    )
    graph = FlowGraph(
        blocks={
            7: replace(
                _block(7, 0x7000, succs=(8,), preds=()),
                insn_snapshots=(alias_definition,),
            ),
            8: replace(
                _block(8, 0x8000, succs=(2, 20), preds=(7,)),
                insn_snapshots=(store, branch),
            ),
            2: _block(2, 0x2000, succs=(), preds=(8,), insn_eas=(0x2000,)),
            20: _block(20, 0xA000, succs=(), preds=(8,), insn_eas=(0xA000,)),
        },
        entry_serial=7,
        func_ea=0x1000,
    )
    identities = {
        serial: route_evidence.stable_block_identity_from_snapshot(
            block,
            native_key=NATIVE_KEY,
        )
        for serial, block in graph.blocks.items()
    }
    assert all(identity is not None for identity in identities.values())
    physical = SemanticPhysicalStateWriteWitness(
        route_evidence._instruction_projection(store),
        state,
        4,
        full_value & 0xFFFFFFFF,
        source_serial=8,
        alias_definition_instruction=route_evidence._instruction_projection(
            alias_definition
        ),
        alias_definition_serial=7,
        physical_width=8,
        state_lane_offset=0,
    )
    guarded = route_evidence.prove_semantic_physical_guard_selection(
        graph,
        guard_serial=8,
        selected_target_serial=20,
        physical_state_write=physical,
    )
    assert guarded is not None
    physical = replace(physical, guarded_selection=guarded)
    fact = SemanticRouteFact(
        SemanticRouteFactKind.DECISION_DAG,
        7,
        8,
        0x8000,
        full_value & 0xFFFFFFFF,
        20,
        0x7000,
        0xA000,
        (7, 8),
        ((7, 8),),
        physical_state_write=physical,
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        1,
        "canonical-semantic:guarded-alias-store",
        state,
        tuple(graph.blocks.values()),
        tuple(identities.items()),
    )
    return graph, fact, context, branch, store


def test_guarded_alias_store_assignment_produces_and_binds_exact_full_width_edge() -> None:
    graph, fact, context, _branch, _store = _guarded_alias_store_inputs()

    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    proof = evidence.route_proofs[0]
    assert proof.proof_kind is SemanticRouteProofKind.STATE_ASSIGNMENT
    assert proof.state_write is not None
    assert proof.state_write.physical_state_write is not None
    assert proof.state_write.physical_state_write.guarded_selection is None
    with pytest.raises(SemanticRouteEvidenceRejected):
        replace(proof.state_write, physical_state_write=fact.physical_state_write)
    guarded = proof.state_write.guarded_selection
    assert guarded is not None
    assert guarded.width == 8
    assert guarded.constant == 0xDD1FF05BF465445C
    assert guarded.guard.identity == proof.source_identity
    assert guarded.selected_target.identity == proof.destinations[0].target_identity
    assert validate_canonical_roundtrip(evidence, CanonicalSemanticEvidence)
    binding = bind_canonical_semantic_evidence_result(graph, evidence)
    assert binding.bound_evidence is not None, binding.failures


@pytest.mark.parametrize(
    "drift",
    (
        "polarity",
        "full-value",
        "width",
        "state-identity",
        "target",
        "topology",
        "order",
        "intervening-effect",
        "intervening-control",
    ),
)
def test_guarded_alias_store_assignment_rejects_live_guard_drift(drift: str) -> None:
    graph, fact, context, branch, store = _guarded_alias_store_inputs()
    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    guard = graph.blocks[8]
    blocks = dict(graph.blocks)
    if drift == "polarity":
        changed = replace(branch, branch_predicate=PredicateKind.EQ)
        blocks[8] = replace(guard, insn_snapshots=(store, changed))
    elif drift == "full-value":
        changed = replace(
            branch,
            r=replace(branch.r, value=0xDD1FF15BF465445C),
        )
        blocks[8] = replace(guard, insn_snapshots=(store, changed))
    elif drift == "width":
        changed = replace(
            branch,
            l=replace(branch.l, size=4),
            r=replace(branch.r, size=4, value=0xF465445C),
        )
        blocks[8] = replace(guard, insn_snapshots=(store, changed))
    elif drift == "state-identity":
        changed = replace(branch, l=replace(branch.l, stkoff=0x44))
        blocks[8] = replace(guard, insn_snapshots=(store, changed))
    elif drift == "target":
        changed = replace(
            branch,
            d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=20),
        )
        blocks[8] = replace(guard, insn_snapshots=(store, changed))
    elif drift == "topology":
        blocks[20] = replace(blocks[20], preds=())
    elif drift == "order":
        blocks[8] = replace(guard, insn_snapshots=(branch, store))
    elif drift == "intervening-effect":
        intervening = InsnSnapshot(
            opcode=0,
            ea=0x8002,
            operands=(),
            l=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=0),
            d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=4),
            kind=InsnKind.STORE,
            value_op_kind=ValueOpKind.STORE,
        )
        blocks[8] = replace(
            guard,
            insn_snapshots=(store, intervening, branch),
        )
    else:
        intervening = InsnSnapshot(
            opcode=0,
            ea=0x8002,
            operands=(),
            l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=20),
            kind=InsnKind.GOTO,
        )
        blocks[8] = replace(
            guard,
            insn_snapshots=(store, intervening, branch),
        )
    drifted = FlowGraph(blocks, graph.entry_serial, graph.func_ea)

    assert bind_canonical_semantic_evidence(drifted, evidence) is None


@pytest.mark.parametrize(
    ("field", "value"),
    (("state_constant", 0xAABBCCDC), ("physical_width", 8), ("state_lane_offset", 1)),
)
def test_direct_physical_move_binding_rederives_literal_width_and_lane(
    field: str,
    value: int,
) -> None:
    fact, context = _native_bound_production_inputs()
    graph = FlowGraph(
        {block.serial: block for block in context.blocks},
        entry_serial=0,
        func_ea=0x1000,
    )
    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    proof = evidence.route_proofs[0]
    witness_changes = {field: value}
    forged_witness = _unsafe_field_replace(
        proof.state_write.physical_state_write,
        **witness_changes,
    )
    state_constant = (
        int(value) if field == "state_constant" else proof.state_write.state_constant
    )
    forged_write = replace(
        proof.state_write,
        state_constant=state_constant,
        physical_state_write=forged_witness,
    )
    forged_proof = replace(
        proof,
        state_write=forged_write,
        destinations=(replace(
            proof.destinations[0], state_constant=state_constant,
        ),),
    )
    forged = _recanonicalize_evidence(evidence, (forged_proof,))

    assert bind_canonical_semantic_evidence(graph, forged) is None


@pytest.mark.parametrize(
    "case",
    ("zero", "multiple", "wrong-constant", "wrong-identity", "non-u32", "different-block"),
)
def test_native_bound_producer_rejects_nonunique_or_nonmatching_physical_state_mov(case: str) -> None:
    """Receipt provenance never authorizes an inferred or foreign state MOV."""
    graph, fact, context = _native_bound_receipt_with_later_state_write()
    source = graph.blocks[1]
    witness = fact.physical_state_write
    assert witness is not None
    if case == "zero":
        graph = FlowGraph(
            blocks={**graph.blocks, 1: replace(source, insn_snapshots=source.insn_snapshots[:1])},
            entry_serial=graph.entry_serial,
            func_ea=graph.func_ea,
        )
        context = replace(context, blocks=tuple(graph.blocks.values()))
    elif case == "multiple":
        duplicate = replace(source.insn_snapshots[-1], ea=0x110C)
        graph = FlowGraph(
            blocks={**graph.blocks, 1: replace(source, insn_snapshots=(*source.insn_snapshots, duplicate))},
            entry_serial=graph.entry_serial,
            func_ea=graph.func_ea,
        )
        identities = dict(context.identities_by_serial)
        identities[1] = StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x1100, 0x1110),), native_key=NATIVE_KEY,
            exact_instruction_eas=(0x1100, 0x1108, 0x110C),
        )
        context = replace(context, blocks=tuple(graph.blocks.values()), identities_by_serial=tuple(identities.items()))
    elif case == "wrong-constant":
        wrong = replace(source.insn_snapshots[-1], l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7))
        graph = FlowGraph(
            blocks={**graph.blocks, 1: replace(source, insn_snapshots=(*source.insn_snapshots[:-1], wrong))},
            entry_serial=graph.entry_serial,
            func_ea=graph.func_ea,
        )
        context = replace(context, blocks=tuple(graph.blocks.values()))
    elif case == "wrong-identity":
        fact = replace(
            fact,
            physical_state_write=replace(
                witness,
                state_identity=StorageIdentity(StorageIdentityKind.REGISTER, 20),
            ),
        )
    elif case == "non-u32":
        wrong = replace(
            source.insn_snapshots[-1],
            l=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=0xAABBCCDD),
            d=MopSnapshot(kind=OperandKind.STACK, size=8, stkoff=0x40),
        )
        graph = FlowGraph(
            blocks={**graph.blocks, 1: replace(source, insn_snapshots=(*source.insn_snapshots[:-1], wrong))},
            entry_serial=graph.entry_serial,
            func_ea=graph.func_ea,
        )
        context = replace(context, blocks=tuple(graph.blocks.values()))
    else:
        foreign = replace(source.insn_snapshots[-1], ea=0x1300)
        graph = FlowGraph(
            blocks={
                **graph.blocks,
                1: replace(source, insn_snapshots=source.insn_snapshots[:1]),
                3: BlockSnapshot(3, 0, (), (), 0, 0x1300, (foreign,)),
            },
            entry_serial=graph.entry_serial,
            func_ea=graph.func_ea,
        )
        context = replace(context, blocks=tuple(graph.blocks.values()))

    result = build_canonical_semantic_evidence((fact,), context)
    assert result.evidence is None
    assert result.abstention is not None


def test_native_bound_physical_state_write_ea_drift_rejects_binding() -> None:
    """Binding replays the physical coordinate rather than the receipt EA."""
    graph, fact, context = _native_bound_receipt_with_later_state_write()
    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    source = graph.blocks[1]
    drifted = replace(source.insn_snapshots[-1], ea=0x110C)
    observed = FlowGraph(
        blocks={**graph.blocks, 1: replace(source, insn_snapshots=(*source.insn_snapshots[:-1], drifted))},
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )

    assert bind_canonical_semantic_evidence(observed, evidence) is None


def test_native_bound_physical_state_write_rejects_store_at_the_same_ea() -> None:
    """A same-coordinate STORE cannot substitute for the bound physical MOV."""
    graph, fact, context = _native_bound_receipt_with_later_state_write()
    source = graph.blocks[1]
    store = replace(
        source.insn_snapshots[-1],
        kind=InsnKind.STORE,
        value_op_kind=ValueOpKind.STORE,
    )
    observed = FlowGraph(
        blocks={
            **graph.blocks,
            1: replace(
                source,
                insn_snapshots=(*source.insn_snapshots[:-1], store),
            ),
        },
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )
    context = replace(context, blocks=tuple(observed.blocks.values()))

    result = build_canonical_semantic_evidence((fact,), context)

    assert result.evidence is None
    assert result.abstention is not None


def test_native_bound_canonical_id_changes_with_physical_write_witness() -> None:
    """The canonical proof ID commits to the exact bound physical MOV record."""
    graph, fact, context = _native_bound_receipt_with_later_state_write()
    original = _accepted(build_canonical_semantic_evidence((fact,), context))
    source = graph.blocks[1]
    changed = replace(source.insn_snapshots[-1], raw_opcode=0x99)
    changed_graph = FlowGraph(
        blocks={
            **graph.blocks,
            1: replace(
                source,
                insn_snapshots=(*source.insn_snapshots[:-1], changed),
            ),
        },
        entry_serial=graph.entry_serial,
        func_ea=graph.func_ea,
    )
    changed_fact = replace(
        fact,
        physical_state_write=replace(
            fact.physical_state_write,
            source_instruction=route_evidence._instruction_projection(changed),
        ),
    )
    changed_context = replace(
        context,
        blocks=tuple(changed_graph.blocks.values()),
    )

    changed_evidence = _accepted(
        build_canonical_semantic_evidence((changed_fact,), changed_context),
    )

    assert changed_evidence.route_proofs[0].proof_id != original.route_proofs[0].proof_id


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
            tuple(DecisionDagComparisonWitness(serial, comparison, state) for serial, comparison in ((5, RouteComparison(5, "jz", 7, 6, 4)),)), (),
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


def _loop_guard_terminal_delivery_fixture() -> tuple[FlowGraph, CanonicalSemanticEvidence]:
    """One physical outer-state route ending in MOV/XDU/logical STOP."""
    outer = StorageIdentity(StorageIdentityKind.STACK, 24)
    ret_source = StorageIdentity(StorageIdentityKind.STACK, 12)
    ret_copy = StorageIdentity(StorageIdentityKind.STACK, 36)

    def eq(ea: int, constant: int, target: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=44, ea=ea, operands=(), kind=InsnKind.EQUALITY_JUMP,
            l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=24),
            r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=constant),
            d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=target),
            branch_predicate=PredicateKind.EQ, is_conditional_jump=True,
            control_transfer_kind=ControlTransferKind.CONDITIONAL_BRANCH,
            compare_width=4,
        )
    write = InsnSnapshot(
        opcode=0, ea=0x2300, operands=(), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=9),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=24),
    )
    move = InsnSnapshot(
        opcode=0, ea=0x2404, operands=(), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=12),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=36),
    )
    xdu = InsnSnapshot(
        opcode=0, ea=0x2504, operands=(), kind=InsnKind.XDU,
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=36),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=0),
    )
    sibling_move = InsnSnapshot(
        opcode=0, ea=0x1504, operands=(), kind=InsnKind.MOV,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0xFFFFFFFF),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=36),
    )
    blocks = {
        2: BlockSnapshot(2, 2, (3, 6), (23,), 0, 0x1200, (eq(0x1204, 0, 6),)),
        3: BlockSnapshot(3, 2, (4, 9), (2,), 0, 0x1300, (eq(0x1304, 1, 9),)),
        4: BlockSnapshot(4, 2, (5, 24), (3,), 0, 0x1400, (eq(0x1404, 9, 24),)),
        5: BlockSnapshot(5, 1, (25,), (4,), 0, 0x1500, (sibling_move,)),
        6: BlockSnapshot(6, 0, (), (2,), 0, 0x1600, ()),
        9: BlockSnapshot(9, 0, (), (3,), 0, 0x1900, ()),
        23: BlockSnapshot(23, 1, (2,), (), 0, 0x2300, (write,)),
        24: BlockSnapshot(24, 1, (25,), (4,), 0, 0x2400, (move,)),
        25: BlockSnapshot(25, 1, (26,), (24, 5), 0, 0x2500, (xdu,)),
        26: BlockSnapshot(26, 0, (), (25,), 0, 0xFFFFFFFFFFFFFFFF, (), BlockKind.STOP),
    }
    graph = FlowGraph(blocks, entry_serial=23, func_ea=0x1000)
    identities = {
        serial: route_evidence.stable_block_identity_from_snapshot(block, native_key=NATIVE_KEY)
        for serial, block in blocks.items() if serial != 26
    }
    assert all(identity is not None for identity in identities.values())
    point = lambda serial, ea: SemanticCorridorPoint(identities[serial], ea)
    witness = SemanticDecisionDagWitness(
        outer, 9, point(2, 0x1200),
        (point(2, 0x1200), point(3, 0x1300), point(4, 0x1400)),
        (
            SemanticDagComparison(point(2, 0x1200), "jz", 0, point(6, 0x1600), point(3, 0x1300), outer),
            SemanticDagComparison(point(3, 0x1300), "jz", 1, point(9, 0x1900), point(4, 0x1400), outer),
            SemanticDagComparison(point(4, 0x1400), "jz", 9, point(24, 0x2400), point(5, 0x1500), outer),
        ), (),
    )
    dag = SemanticStateDagProof(
        witness, identities[23], 0x2300, identities[24], 0x2400,
        identities[2], 0x1200, (point(23, 0x2300), point(2, 0x1200)),
        witness.path,
    )
    logical_exit = SemanticLogicalDagEndpoint(
        SemanticDagEndpointKind.FUNCTION_EXIT, 26, "test", "stop", 1,
    )
    transport = route_evidence.SemanticReturnValueTransportProof(
        point(24, 0x2400), route_evidence._instruction_projection(move), ret_source, 4,
        ret_copy, 4, point(25, 0x2500), route_evidence._instruction_projection(xdu),
        ret_copy, 4, 8, logical_exit,
    )
    delivery = route_evidence.SemanticTerminalDeliveryProof(
        route_evidence._instruction_projection(write), outer, 4, 9, dag,
        point(24, 0x2400), transport,
    )
    state_write = SemanticStateWriteProof(
        identities[23], 0x2300, outer, 4, 9, (0x2300,), None, (),
    )
    proof = SemanticRouteProof(
        proof_id="pending", atomic_group_id="pending",
        proof_kind=SemanticRouteProofKind.TERMINAL_DELIVERY,
        shape=SemanticRouteShape.DIRECT,
        source_identity=identities[2], source_anchor_ea=0x1200,
        source_owner_identity=identities[23], source_owner_anchor_ea=0x2300,
        delivery_region=NativeEaInterval(0x1200, 0x1201),
        destinations=(SemanticRouteDestination(SemanticEdgeRole.DIRECT, 9, identities[24], 0x2400, terminal=True),),
        state_write=state_write, terminal_delivery=delivery,
    )
    return graph, _evidence(proof)


def test_loop_guard_terminal_delivery_binds_outer_dag_and_transport() -> None:
    graph, evidence = _loop_guard_terminal_delivery_fixture()
    assert bind_canonical_semantic_evidence(graph, evidence) is not None


@pytest.mark.parametrize("drift_kind", ("opcode", "constant_width"))
def test_loop_guard_terminal_delivery_constructor_rejects_non_u32_mov(
    drift_kind: str,
) -> None:
    _graph, evidence = _loop_guard_terminal_delivery_fixture()
    delivery = evidence.route_proofs[0].terminal_delivery
    assert delivery is not None
    write = delivery.state_write_instruction
    if drift_kind == "opcode":
        drifted_write = replace(write, kind=InsnKind.VALUE)
    else:
        assert write.l is not None
        drifted_write = replace(write, l=replace(write.l, size=8))
    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="loop-guard terminal delivery evidence disagrees",
    ):
        replace(delivery, state_write_instruction=drifted_write)


@pytest.mark.parametrize(
    "drift_kind",
    (
        "outer_write_storage",
        "outer_write_constant",
        "outer_write_width",
        "comparison_constant",
        "comparison_polarity",
        "comparison_target",
        "transport_move_source",
        "transport_move_destination",
        "transport_move_width",
        "transport_extra_writer",
        "selected_edge_nonreciprocal",
        "carrier_xdu_width",
        "carrier_xdu_source",
        "carrier_successor",
        "logical_exit_predecessor",
    ),
)
def test_loop_guard_terminal_delivery_rejects_bound_component_drift(drift_kind: str) -> None:
    graph, evidence = _loop_guard_terminal_delivery_fixture()
    blocks = dict(graph.blocks)
    if drift_kind == "outer_write_storage":
        block = blocks[23]
        blocks[23] = replace(block, insn_snapshots=(replace(block.insn_snapshots[0], d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=25)),))
    elif drift_kind == "outer_write_constant":
        block = blocks[23]
        blocks[23] = replace(block, insn_snapshots=(replace(block.insn_snapshots[0], l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8)),))
    elif drift_kind == "outer_write_width":
        block = blocks[23]
        blocks[23] = replace(block, insn_snapshots=(replace(block.insn_snapshots[0], d=MopSnapshot(kind=OperandKind.STACK, size=8, stkoff=24)),))
    elif drift_kind == "comparison_constant":
        block = blocks[4]
        blocks[4] = replace(block, insn_snapshots=(replace(block.insn_snapshots[0], r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8)),))
    elif drift_kind == "comparison_polarity":
        block = blocks[4]
        blocks[4] = replace(block, insn_snapshots=(replace(block.insn_snapshots[0], branch_predicate=PredicateKind.NE),))
    elif drift_kind == "comparison_target":
        block = blocks[4]
        blocks[4] = replace(block, insn_snapshots=(replace(block.insn_snapshots[0], d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=5)),))
    elif drift_kind == "transport_move_source":
        block = blocks[24]
        blocks[24] = replace(block, insn_snapshots=(replace(block.insn_snapshots[0], l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=16)),))
    elif drift_kind == "transport_move_destination":
        block = blocks[24]
        blocks[24] = replace(block, insn_snapshots=(replace(block.insn_snapshots[0], d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=40)),))
    elif drift_kind == "transport_move_width":
        block = blocks[24]
        blocks[24] = replace(block, insn_snapshots=(replace(block.insn_snapshots[0], d=MopSnapshot(kind=OperandKind.STACK, size=8, stkoff=36)),))
    elif drift_kind == "transport_extra_writer":
        block = blocks[24]
        blocks[24] = replace(block, insn_snapshots=(*block.insn_snapshots, InsnSnapshot(opcode=0, ea=0x2408, operands=(), kind=InsnKind.MOV, l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0), d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=36))))
    elif drift_kind == "selected_edge_nonreciprocal":
        blocks[25] = replace(blocks[25], preds=(5,))
    elif drift_kind == "carrier_xdu_width":
        block = blocks[25]
        blocks[25] = replace(block, insn_snapshots=(replace(block.insn_snapshots[0], d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=0)),))
    elif drift_kind == "carrier_xdu_source":
        block = blocks[25]
        blocks[25] = replace(block, insn_snapshots=(replace(block.insn_snapshots[0], l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=40)),))
    elif drift_kind == "carrier_successor":
        blocks[25] = replace(blocks[25], succs=())
    else:
        blocks[26] = replace(blocks[26], preds=())
    drifted = FlowGraph(blocks, graph.entry_serial, graph.func_ea)
    assert bind_canonical_semantic_evidence(drifted, evidence) is None


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


def test_canonical_factory_deduplicates_repeated_authoritative_payload() -> None:
    proof = _proof()
    choice = _storage_choice_proof()

    single = canonical_semantic_evidence_from_proofs(NATIVE_KEY, 3, (proof,))
    repeated = canonical_semantic_evidence_from_proofs(NATIVE_KEY, 3, (proof, proof))
    ordered = canonical_semantic_evidence_from_proofs(NATIVE_KEY, 3, (proof, choice))
    reordered = canonical_semantic_evidence_from_proofs(
        NATIVE_KEY, 3, (choice, proof, choice, proof),
    )

    assert len(repeated.route_proofs) == 1
    assert repeated.atomic_group_id == single.atomic_group_id
    assert repeated.route_proofs[0].proof_id == single.route_proofs[0].proof_id
    assert len(reordered.route_proofs) == 2
    assert reordered.atomic_group_id == ordered.atomic_group_id
    assert tuple(proof.proof_id for proof in reordered.route_proofs) == tuple(
        proof.proof_id for proof in ordered.route_proofs
    )


def test_canonical_factory_rejects_one_input_id_with_divergent_payload() -> None:
    proof = _proof()

    with pytest.raises(SemanticRouteEvidenceRejected, match="divergent authoritative payload"):
        canonical_semantic_evidence_from_proofs(
            NATIVE_KEY,
            3,
            (proof, replace(
                proof,
                destinations=(replace(proof.destinations[0], target_anchor_ea=0x1201),),
            )),
        )


def test_canonical_factory_merges_diagnostic_provenance_outside_authority_seal() -> None:
    proof = _proof()
    first = replace(proof, diagnostic_provenance=(("fact_id", "first"),))
    second = replace(proof, diagnostic_provenance=(("fact_id", "second"),))

    clean = canonical_semantic_evidence_from_proofs(NATIVE_KEY, 3, (proof,))
    merged = canonical_semantic_evidence_from_proofs(NATIVE_KEY, 3, (second, first))

    assert merged.atomic_group_id == clean.atomic_group_id
    assert merged.route_proofs[0].proof_id == clean.route_proofs[0].proof_id
    assert merged.route_proofs[0].diagnostic_provenance == (
        ("fact_id", "first"),
        ("fact_id", "second"),
    )


def test_runtime_factory_mints_scope_owned_identities() -> None:
    scope = runtime_semantic_route_scope(NATIVE_KEY, 3)
    evidence = runtime_semantic_evidence_from_proofs(
        NATIVE_KEY, 3, (_proof(), _storage_choice_proof()), scope=scope,
    )

    identity = evidence.runtime_identity
    assert type(identity) is RuntimeRouteIdentity
    assert identity.scope is scope
    assert scope.owns(identity.group_ref)
    assert evidence.atomic_group_id == scope.identity(identity.group_ref)
    assert all(
        is_runtime_authority_identity(proof.proof_id)
        for proof in evidence.route_proofs
    )
    assert tuple(proof.proof_id for proof in evidence.route_proofs) == tuple(
        scope.identity(ref) for ref in identity.proof_refs
    )
    assert all(
        proof.atomic_group_id == evidence.atomic_group_id
        for proof in evidence.route_proofs
    )


def test_runtime_factory_namespace_ignores_the_human_group_label() -> None:
    first = runtime_semantic_route_scope(NATIVE_KEY, 3)
    second = runtime_semantic_route_scope(NATIVE_KEY, 3)

    assert first.namespace == second.namespace
    assert first is not second
    assert runtime_semantic_evidence_from_proofs(
        NATIVE_KEY, 3, (_proof(),), scope=first,
    ).atomic_group_id == runtime_semantic_evidence_from_proofs(
        NATIVE_KEY, 3, (_proof(),), scope=second,
    ).atomic_group_id


def test_runtime_factory_deduplicates_by_direct_fields() -> None:
    proof = _proof()
    choice = _storage_choice_proof()
    first = replace(proof, diagnostic_provenance=(("fact_id", "first"),))
    second = replace(proof, diagnostic_provenance=(("fact_id", "second"),))

    single = runtime_semantic_evidence_from_proofs(
        NATIVE_KEY, 3, (proof,), scope=runtime_semantic_route_scope(NATIVE_KEY, 3),
    )
    merged = runtime_semantic_evidence_from_proofs(
        NATIVE_KEY, 3, (second, first), scope=runtime_semantic_route_scope(NATIVE_KEY, 3),
    )
    ordered = runtime_semantic_evidence_from_proofs(
        NATIVE_KEY, 3, (proof, choice), scope=runtime_semantic_route_scope(NATIVE_KEY, 3),
    )
    reordered = runtime_semantic_evidence_from_proofs(
        NATIVE_KEY,
        3,
        (choice, proof, choice, proof),
        scope=runtime_semantic_route_scope(NATIVE_KEY, 3),
    )

    assert len(merged.route_proofs) == 1
    assert merged.atomic_group_id == single.atomic_group_id
    assert merged.route_proofs[0].diagnostic_provenance == (
        ("fact_id", "first"),
        ("fact_id", "second"),
    )
    assert len(reordered.route_proofs) == 2
    # Ordering is a function of the native coordinates, not of input order.
    assert tuple(
        (item.proof_id, item.source_anchor_ea, item.proof_kind)
        for item in reordered.route_proofs
    ) == tuple(
        (item.proof_id, item.source_anchor_ea, item.proof_kind)
        for item in ordered.route_proofs
    )


def test_runtime_evidence_rejects_a_foreign_scope() -> None:
    evidence = runtime_semantic_evidence_from_proofs(
        NATIVE_KEY, 3, (_proof(),), scope=runtime_semantic_route_scope(NATIVE_KEY, 3),
    )
    stranger = runtime_semantic_route_scope(NATIVE_KEY, 3)

    with pytest.raises(SemanticRouteEvidenceRejected, match="another scope"):
        RuntimeRouteIdentity(
            scope=stranger,
            group_ref=evidence.runtime_identity.group_ref,
            proof_refs=evidence.runtime_identity.proof_refs,
        )
    # An identity string is a readable projection, not the ownership proof:
    # it is deterministic in the native function, the generation, and mint
    # order, so a second scope over the same bundle renders the same strings.
    # Ownership lives in the reference, which the record above enforces.
    stranger.mint(RuntimeAuthorityKind.ROUTE_GROUP)
    rebound = RuntimeRouteIdentity(
        scope=stranger,
        group_ref=stranger.mint(RuntimeAuthorityKind.ROUTE_GROUP),
        proof_refs=(stranger.mint(RuntimeAuthorityKind.ROUTE_PROOF),),
    )
    with pytest.raises(SemanticRouteEvidenceRejected, match="not scope-derived"):
        CanonicalSemanticEvidence(
            native_key=evidence.native_key,
            generation=evidence.generation,
            atomic_group_id=evidence.atomic_group_id,
            route_proofs=evidence.route_proofs,
            _runtime_identity=rebound,
        )


def test_evidence_rejects_mixed_runtime_and_content_identities() -> None:
    canonical = canonical_semantic_evidence_from_proofs(NATIVE_KEY, 3, (_proof(),))
    scope = RuntimeAuthorityScope("mixed")
    runtime_id = scope.identity(scope.mint(RuntimeAuthorityKind.ROUTE_PROOF))

    forged = _unsafe_evidence(
        canonical,
        (replace(canonical.route_proofs[0], proof_id=runtime_id),),
    )
    with pytest.raises(SemanticRouteEvidenceRejected, match="content-derived"):
        CanonicalSemanticEvidence.__post_init__(forged)


def test_runtime_route_identity_rejects_every_malformed_shape() -> None:
    scope = runtime_semantic_route_scope(NATIVE_KEY, 3)
    group_ref = scope.mint(RuntimeAuthorityKind.ROUTE_GROUP)
    proof_ref = scope.mint(RuntimeAuthorityKind.ROUTE_PROOF)

    with pytest.raises(TypeError, match="requires a runtime scope"):
        RuntimeRouteIdentity(
            scope="0x1000:g3", group_ref=group_ref, proof_refs=(proof_ref,),
        )
    with pytest.raises(TypeError, match="requires a group reference"):
        RuntimeRouteIdentity(
            scope=scope, group_ref=None, proof_refs=(proof_ref,),
        )
    with pytest.raises(TypeError, match="requires exact proof references"):
        RuntimeRouteIdentity(
            scope=scope, group_ref=group_ref, proof_refs=[proof_ref],
        )
    with pytest.raises(TypeError, match="requires exact proof references"):
        RuntimeRouteIdentity(scope=scope, group_ref=group_ref, proof_refs=())
    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="group reference has the wrong kind",
    ):
        RuntimeRouteIdentity(
            scope=scope, group_ref=proof_ref, proof_refs=(proof_ref,),
        )
    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="proof references have the wrong kind",
    ):
        RuntimeRouteIdentity(
            scope=scope, group_ref=group_ref, proof_refs=(group_ref,),
        )
    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="proof references have the wrong kind",
    ):
        RuntimeRouteIdentity(
            scope=scope, group_ref=group_ref, proof_refs=("route_proof000001",),
        )
    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="duplicate proof references",
    ):
        RuntimeRouteIdentity(
            scope=scope, group_ref=group_ref, proof_refs=(proof_ref, proof_ref),
        )


def test_runtime_route_scope_and_factory_reject_untyped_inputs() -> None:
    scope = runtime_semantic_route_scope(NATIVE_KEY, 3)

    with pytest.raises(TypeError, match="requires a native key"):
        runtime_semantic_route_scope("0x1000", 3)
    with pytest.raises(TypeError, match="requires a runtime scope"):
        runtime_semantic_evidence_from_proofs(
            NATIVE_KEY, 3, (_proof(),), scope=RuntimeAuthorityScope("0x1000:g3").namespace,
        )
    with pytest.raises(
        SemanticRouteEvidenceRejected, match="requires route proofs",
    ):
        runtime_semantic_evidence_from_proofs(NATIVE_KEY, 3, (), scope=scope)
    with pytest.raises(TypeError, match="remint requires canonical evidence"):
        semantic_evidence_with_additional_proofs(_proof(), (_proof(),))


def test_runtime_merge_rejects_one_input_id_with_divergent_payload() -> None:
    proof = _proof()
    divergent = replace(
        proof,
        destinations=(replace(proof.destinations[0], target_anchor_ea=0x1201),),
    )

    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="divergent authoritative payload",
    ) as rejection:
        runtime_semantic_evidence_from_proofs(
            NATIVE_KEY,
            3,
            (proof, divergent),
            scope=runtime_semantic_route_scope(NATIVE_KEY, 3),
        )
    assert "destinations" in str(rejection.value)
    assert repr(proof.proof_id) in str(rejection.value)


def test_runtime_merge_exempts_scope_local_ids_from_the_divergence_check() -> None:
    """Two scopes over one namespace render the same ids for unlike bundles."""

    first = runtime_semantic_evidence_from_proofs(
        NATIVE_KEY, 3, (_proof(),), scope=runtime_semantic_route_scope(NATIVE_KEY, 3),
    )
    second = runtime_semantic_evidence_from_proofs(
        NATIVE_KEY,
        3,
        (_storage_choice_proof(),),
        scope=runtime_semantic_route_scope(NATIVE_KEY, 3),
    )
    assert (
        first.route_proofs[0].proof_id == second.route_proofs[0].proof_id
    )

    merged = runtime_semantic_evidence_from_proofs(
        NATIVE_KEY,
        3,
        (*first.route_proofs, *second.route_proofs),
        scope=runtime_semantic_route_scope(NATIVE_KEY, 3),
    )
    assert len(merged.route_proofs) == 2


def test_runtime_evidence_rejects_every_inconsistent_identity_pairing() -> None:
    scope = runtime_semantic_route_scope(NATIVE_KEY, 3)
    evidence = runtime_semantic_evidence_from_proofs(
        NATIVE_KEY, 3, (_proof(),), scope=scope,
    )
    canonical = canonical_semantic_evidence_from_proofs(NATIVE_KEY, 3, (_proof(),))

    # Runtime group id, content-derived proof id.
    mixed = _unsafe_evidence(
        evidence,
        (replace(
            evidence.route_proofs[0],
            proof_id=canonical.route_proofs[0].proof_id,
        ),),
    )
    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="mixes runtime and content-derived route ids",
    ):
        CanonicalSemanticEvidence.__post_init__(mixed)

    # A runtime bundle whose scope is gone keeps its representation check only.
    stripped = _unsafe_evidence(evidence, evidence.route_proofs)
    CanonicalSemanticEvidence.__post_init__(stripped)
    assert stripped.runtime_identity is None

    # A scope that did not mint these proof ids.
    stranger = runtime_semantic_route_scope(NATIVE_KEY, 3)
    stranger.mint(RuntimeAuthorityKind.ROUTE_GROUP)
    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="atomic group id is not scope-derived",
    ):
        CanonicalSemanticEvidence(
            native_key=evidence.native_key,
            generation=evidence.generation,
            atomic_group_id=evidence.atomic_group_id,
            route_proofs=evidence.route_proofs,
            _runtime_identity=RuntimeRouteIdentity(
                scope=stranger,
                group_ref=stranger.mint(RuntimeAuthorityKind.ROUTE_GROUP),
                proof_refs=(stranger.mint(RuntimeAuthorityKind.ROUTE_PROOF),),
            ),
        )

    # A scope whose group id matches but whose proof references do not.
    aligned = runtime_semantic_route_scope(NATIVE_KEY, 3)
    group_ref = aligned.mint(RuntimeAuthorityKind.ROUTE_GROUP)
    aligned.mint(RuntimeAuthorityKind.ROUTE_PROOF)
    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="proof ids are not scope-derived",
    ):
        CanonicalSemanticEvidence(
            native_key=evidence.native_key,
            generation=evidence.generation,
            atomic_group_id=evidence.atomic_group_id,
            route_proofs=evidence.route_proofs,
            _runtime_identity=RuntimeRouteIdentity(
                scope=aligned,
                group_ref=group_ref,
                proof_refs=(aligned.mint(RuntimeAuthorityKind.ROUTE_PROOF),),
            ),
        )

    # A scope carried alongside content-derived identities.
    with pytest.raises(
        SemanticRouteEvidenceRejected,
        match="requires a scope-derived atomic group id",
    ):
        CanonicalSemanticEvidence(
            native_key=canonical.native_key,
            generation=canonical.generation,
            atomic_group_id=canonical.atomic_group_id,
            route_proofs=canonical.route_proofs,
            _runtime_identity=evidence.runtime_identity,
        )


def test_runtime_identity_property_tolerates_a_rebuilt_record() -> None:
    """The accessor and the revalidation path must agree about a bare record."""

    evidence = canonical_semantic_evidence_from_proofs(NATIVE_KEY, 3, (_proof(),))
    rebuilt = _unsafe_evidence(evidence, evidence.route_proofs)

    assert rebuilt.runtime_identity is None
    CanonicalSemanticEvidence.__post_init__(rebuilt)
    grown = semantic_evidence_with_additional_proofs(
        rebuilt, (_storage_choice_proof(),),
    )
    assert grown.runtime_identity is None
    assert len(grown.route_proofs) == 2


def test_semantic_evidence_remint_keeps_the_identity_discipline() -> None:
    scope = runtime_semantic_route_scope(NATIVE_KEY, 3)
    runtime = runtime_semantic_evidence_from_proofs(
        NATIVE_KEY, 3, (_proof(),), scope=scope,
    )
    canonical = canonical_semantic_evidence_from_proofs(NATIVE_KEY, 3, (_proof(),))
    choice = _storage_choice_proof()

    grown = semantic_evidence_with_additional_proofs(runtime, (choice,))
    recanonicalized = semantic_evidence_with_additional_proofs(canonical, (choice,))

    assert grown.runtime_identity is not None
    assert grown.runtime_identity.scope is scope
    assert len(grown.route_proofs) == 2
    # A remint in the same scope hands out identities the superseded bundle
    # never used, so the two bundles cannot be confused for one another.
    assert not (
        {proof.proof_id for proof in grown.route_proofs}
        & {proof.proof_id for proof in runtime.route_proofs}
    )
    assert grown.atomic_group_id != runtime.atomic_group_id
    assert recanonicalized.runtime_identity is None
    assert all(
        proof.proof_id.startswith("sha256:")
        for proof in recanonicalized.route_proofs
    )


def test_canonical_evidence_still_rejects_duplicate_final_proof_ids() -> None:
    evidence = canonical_semantic_evidence_from_proofs(NATIVE_KEY, 3, (_proof(),))
    proof = evidence.route_proofs[0]

    forged = object.__new__(CanonicalSemanticEvidence)
    object.__setattr__(forged, "native_key", evidence.native_key)
    object.__setattr__(forged, "generation", evidence.generation)
    object.__setattr__(forged, "atomic_group_id", evidence.atomic_group_id)
    object.__setattr__(forged, "route_proofs", (proof, proof))
    with pytest.raises(SemanticRouteEvidenceRejected, match="duplicate proof ids"):
        CanonicalSemanticEvidence.__post_init__(forged)


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


def _conditional_partition_graph(*, predicate: PredicateKind = PredicateKind.EQ) -> FlowGraph:
    """Exact carrier owner selects the shared feeder with its final branch."""
    base = _partition_graph()
    owner = base.blocks[1]
    branch = InsnSnapshot(
        opcode=0, ea=0x1104, operands=(), kind=InsnKind.COND_JUMP,
        control_transfer_kind=ControlTransferKind.CONDITIONAL_BRANCH,
        branch_predicate=predicate, is_conditional_jump=True,
        l=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=3),
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2),
    )
    feeder = replace(base.blocks[2], succs=(4,))
    sibling = _block(3, 0x1300, succs=(), preds=(1,))
    comparison = _block(4, 0x1400, succs=(), preds=(2,))
    return FlowGraph(
        blocks={
            1: replace(owner, succs=(3, 2), insn_snapshots=(*owner.insn_snapshots, branch)),
            2: feeder,
            3: sibling,
            4: comparison,
        },
        entry_serial=1,
        func_ea=0x1000,
    )


def test_partition_prover_accepts_sealed_conditional_owner_edge() -> None:
    graph = _conditional_partition_graph()
    tail = graph.blocks[1].tail
    assert tail is not None
    member = StatePartitionMemberWitness(
        owner_serial=1, feeder_serial=2,
        state_identity=StorageIdentity(StorageIdentityKind.STACK, 0x40),
        state_constant=7,
        conditional_edge=StatePartitionConditionalEdgeWitness(
            0x1104, route_evidence.instruction_projection_without_block_references(tail),
            SemanticEdgeRole.CONDITIONAL_TAKEN, 3,
        ),
    )
    assert prove_partitioned_state_member(
        graph, member, feeder_instruction_ea=0x1200,
        state_var_stkoff=0x40, state_var_reg=None,
    )


@pytest.mark.parametrize("drift", ("sibling", "role", "predicate", "transfer"))
def test_partition_prover_rejects_conditional_owner_witness_drift(drift: str) -> None:
    graph = _conditional_partition_graph()
    tail = graph.blocks[1].tail
    assert tail is not None
    witness = StatePartitionConditionalEdgeWitness(
        0x1104, route_evidence.instruction_projection_without_block_references(tail),
        SemanticEdgeRole.CONDITIONAL_TAKEN, 3,
    )
    if drift == "sibling":
        witness = replace(witness, sibling_serial=4)
    elif drift == "role":
        witness = replace(witness, edge_role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH)
    elif drift == "predicate":
        graph = _conditional_partition_graph(predicate=PredicateKind.NE)
    else:
        witness = replace(witness, transfer_instruction_ea=0x1108)
    member = StatePartitionMemberWitness(
        1, 2, StorageIdentity(StorageIdentityKind.STACK, 0x40), 7, witness,
    )
    assert not prove_partitioned_state_member(
        graph, member, feeder_instruction_ea=0x1200,
        state_var_stkoff=0x40, state_var_reg=None,
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


def test_partition_group_with_conditional_edge_is_compared_by_group_id() -> None:
    """Instruction projections may contain mappings and are not hash keys."""
    graph = _conditional_partition_graph()
    tail = graph.blocks[1].tail
    assert tail is not None
    state = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    member = StatePartitionMemberWitness(
        owner_serial=1,
        feeder_serial=2,
        state_identity=state,
        state_constant=7,
        conditional_edge=StatePartitionConditionalEdgeWitness(
            0x1104,
            route_evidence.instruction_projection_without_block_references(tail),
            SemanticEdgeRole.CONDITIONAL_TAKEN,
            3,
        ),
    )
    sibling = StatePartitionMemberWitness(
        owner_serial=3,
        feeder_serial=2,
        state_identity=state,
        state_constant=9,
    )
    group = StatePartitionGroupWitness(
        group_id="partition-group:conditional-shared-feeder",
        feeder_serial=2,
        feeder_instruction_ea=0x1200,
        state_identity=state,
        members=(member, sibling),
    )
    fact = SemanticRouteFact(
        SemanticRouteFactKind.STATE_PARTITION,
        owner_serial=1,
        source_serial=2,
        source_instruction_ea=0x1200,
        state_constant=7,
        target_serial=4,
        owner_anchor_ea=0x1100,
        target_anchor_ea=0x1400,
        path_serials=(1, 2),
        path_edges=((1, 2),),
        partition_witness=group,
    )
    identities = {
        serial: _identity(int(block.start_ea))
        for serial, block in graph.blocks.items()
    }
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        0,
        "canonical-semantic:conditional-partition",
        state,
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
        state_identity=state_identity,
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
        source_to_entry_corridor=(
            SemanticCorridorPoint(identities[2], 0x1200),
            entry,
        ),
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


def test_state_dag_replays_exact_source_to_entry_corridor() -> None:
    """A state write may reach its comparison DAG through one typed corridor."""
    graph, evidence = _composite_partition_evidence()
    graph = FlowGraph(
        {
            **graph.blocks,
            2: replace(graph.blocks[2], succs=(3,)),
            3: _block(3, 0x1300, succs=(5,), preds=(2,)),
            5: replace(graph.blocks[5], preds=(3,)),
        },
        graph.entry_serial,
        graph.func_ea,
    )
    proof = evidence.route_proofs[0]
    corridor = (
        SemanticCorridorPoint(_identity(0x1200), 0x1200),
        SemanticCorridorPoint(_identity(0x1300), 0x1300),
        SemanticCorridorPoint(_identity(0x1500), 0x1500),
    )
    dag = replace(proof.state_dag, source_to_entry_corridor=corridor)
    corridor_evidence = _recanonicalize_evidence(
        evidence, (replace(proof, state_dag=dag),),
    )

    assert bind_canonical_semantic_evidence(graph, corridor_evidence) is not None


@pytest.mark.parametrize("mutation", ("missing", "wrong", "changed_edge"))
def test_state_dag_rejects_nonexact_source_to_entry_corridor(mutation: str) -> None:
    graph, evidence = _composite_partition_evidence()
    graph = FlowGraph(
        {
            **graph.blocks,
            2: replace(graph.blocks[2], succs=(3,)),
            3: _block(3, 0x1300, succs=(5,), preds=(2,)),
            5: replace(graph.blocks[5], preds=(3,)),
        },
        graph.entry_serial,
        graph.func_ea,
    )
    proof = evidence.route_proofs[0]
    source = SemanticCorridorPoint(_identity(0x1200), 0x1200)
    middle = SemanticCorridorPoint(_identity(0x1300), 0x1300)
    entry = SemanticCorridorPoint(_identity(0x1500), 0x1500)
    if mutation == "missing":
        corridor = (source, entry)
    elif mutation == "wrong":
        corridor = (source, SemanticCorridorPoint(_identity(0x1400), 0x1400), entry)
    else:
        corridor = (source, middle, entry)
        graph = FlowGraph(
            {**graph.blocks, 3: replace(graph.blocks[3], succs=())},
            graph.entry_serial,
            graph.func_ea,
        )
    dag = replace(proof.state_dag, source_to_entry_corridor=corridor)
    corridor_evidence = _unsafe_evidence(
        evidence, (replace(proof, state_dag=dag),),
    )

    assert bind_canonical_semantic_evidence(graph, corridor_evidence) is None


def test_state_dag_rejects_repeated_source_to_entry_corridor_point() -> None:
    _graph, evidence = _composite_partition_evidence()
    dag = evidence.route_proofs[0].state_dag
    source = SemanticCorridorPoint(_identity(0x1200), 0x1200)

    with pytest.raises(SemanticRouteEvidenceRejected, match="source-to-entry corridor"):
        replace(dag, source_to_entry_corridor=(source, source, dag.path[0]))


def test_state_partition_switch_handoff_binds_final_table_handler() -> None:
    """Partition and ordinary paths share the one typed DAG-to-table authority."""
    graph, evidence = _composite_partition_evidence()
    table_jump = InsnSnapshot(
        opcode=0,
        ea=0x1600,
        operands=(),
        kind=InsnKind.TABLE_JUMP,
        l=MopSnapshot(kind=OperandKind.SUBINSN, size=4, stack_refs=(0x40,)),
        r=MopSnapshot(kind=OperandKind.CASE_LIST, switch_cases=(((7,), 7), ((8,), 7))),
    )
    graph = FlowGraph(
        {
            **graph.blocks,
            6: BlockSnapshot(
                serial=6,
                block_type=1,
                succs=(7,),
                preds=(5,),
                flags=0,
                start_ea=0x1600,
                insn_snapshots=(table_jump,),
            ),
            7: _block(7, 0x1700, succs=(), preds=(6,)),
        },
        graph.entry_serial,
        graph.func_ea,
    )
    proof = evidence.route_proofs[0]
    state = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    final_target = _identity(0x1700)
    dag = replace(
        proof.state_dag,
        target_identity=final_target,
        target_anchor_ea=0x1700,
        switch_handoff=SemanticSwitchTableHandoff(
            SemanticCorridorPoint(_identity(0x1600), 0x1600), state, 7,
        ),
    )
    handoff_proof = replace(
        proof,
        destinations=(replace(
            proof.destinations[0], target_identity=final_target, target_anchor_ea=0x1700,
        ),),
        state_dag=dag,
    )
    handoff_evidence = _recanonicalize_evidence(evidence, (handoff_proof,))
    assert bind_canonical_semantic_evidence(graph, handoff_evidence) is not None


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
    *, address_store: bool = False, distinct_owner: bool = False,
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
            1: (
                replace(graph.blocks[1], succs=(2,))
                if distinct_owner
                else graph.blocks[1]
            ),
            2: replace(source, preds=(1,)) if distinct_owner else source,
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
        tuple(DecisionDagComparisonWitness(serial, comparison, state_identity) for serial, comparison in ((5, RouteComparison(5, "jz", 7, 6, 4)),)),
        (),
    )
    fact = SemanticRouteFact(
        SemanticRouteFactKind.DECISION_DAG,
        1 if distinct_owner else 2,
        2,
        0x1200,
        7,
        6,
        0x1100 if distinct_owner else 0x1200,
        0x1600,
        (1, 2) if distinct_owner else (2,),
        ((1, 2),) if distinct_owner else (),
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
    assert proof.state_write.state_variable == StorageIdentity(
        StorageIdentityKind.STACK,
        0x40,
    )
    assert proof.state_write.width == 4
    assert proof.state_write.delivery_kind is SemanticStateWriteDeliveryKind.INDIRECT
    assert proof.state_write.corridor_instruction_eas == (0x1200,)
    assert proof.state_dag is not None


def test_decision_dag_proof_retains_distinct_delivery_owner() -> None:
    graph, evidence = _ordinary_decision_dag_evidence(distinct_owner=True)

    proof = evidence.route_proofs[0]

    assert proof.source_owner_identity == _identity(graph.blocks[1].start_ea)
    assert proof.source_owner_anchor_ea == graph.blocks[1].start_ea


def test_decision_dag_canonicalizes_typed_namespace_bridge_into_payload() -> None:
    """The producer preserves the raw bridge; binding remains the authority."""
    graph, _ = _ordinary_decision_dag_evidence()
    identities = {serial: _identity(int(block.start_ea)) for serial, block in graph.blocks.items()}
    state = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    result = StorageIdentity(StorageIdentityKind.REGISTER, 8)
    raw = DecisionDagRouteWitness(
        state, 7, 5, 0x1500, (5,), (0x1500,),
        (DecisionDagComparisonWitness(5, RouteComparison(5, "jz", 7, 6, 4), state),), (),
        (ExactU32XduNamespaceBridge(5, 0x1500, 0x1500, state, result, 4, 8),),
    )
    fact = SemanticRouteFact(SemanticRouteFactKind.DECISION_DAG, 2, 2, 0x1200, 7, 6, 0x1200, 0x1600, (2,), (), decision_dag_witness=raw)
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        0,
        "bridge-payload",
        state,
        tuple(graph.blocks.values()),
        tuple(identities.items()),
    )
    evidence = _accepted(build_canonical_semantic_evidence((fact,), context))
    bridge = evidence.route_proofs[0].state_dag.witness.bridges[0]
    assert isinstance(bridge, SemanticDagNamespaceBridge)
    assert (bridge.source_identity, bridge.result_identity, bridge.instruction_ea) == (state, result, 0x1500)
    assert validate_canonical_roundtrip(
        evidence,
        CanonicalSemanticEvidence,
    ) == evidence
    assert canonical_decode(canonical_bytes(evidence)) == evidence

    changed_bridge = replace(
        raw.bridges[0],
        result_identity=StorageIdentity(StorageIdentityKind.REGISTER, 16),
    )
    changed_fact = replace(
        fact,
        decision_dag_witness=replace(raw, bridges=(changed_bridge,)),
    )
    changed = _accepted(build_canonical_semantic_evidence((changed_fact,), context))
    assert changed.route_proofs[0].proof_id != evidence.route_proofs[0].proof_id


def test_decision_dag_typed_namespace_coordinates_reject_forged_constructors() -> None:
    """Raw and canonical handoffs admit only exact, typed coordinates."""

    state = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    result = StorageIdentity(StorageIdentityKind.REGISTER, 8)
    comparison = RouteComparison(5, "jz", 7, 6, 4)
    with pytest.raises(ValueError, match="exact nonnegative serial"):
        DecisionDagComparisonWitness(6, comparison, state)
    with pytest.raises(TypeError, match="exact typed coordinates"):
        ExactU32XduNamespaceBridge(5, 0, 0x1500, state, result, 4, 8)
    with pytest.raises(TypeError, match="exact typed coordinates"):
        ExactU32XduNamespaceBridge(5, 0x1500, 0x1500, state, state, 4, 8)
    point = SemanticCorridorPoint(_identity(0x1500), 0x1500)
    with pytest.raises(TypeError, match="exact typed coordinates"):
        SemanticDagNamespaceBridge(point, 0, state, result, 4, 8)
    with pytest.raises(TypeError, match="exact typed coordinates"):
        SemanticDagNamespaceBridge(point, 0x1500, state, state, 4, 8)


def test_ordinary_decision_dag_binds_assignment_and_dag_proofs() -> None:
    graph, evidence = _ordinary_decision_dag_evidence()
    assert bind_canonical_semantic_evidence(graph, evidence) is not None


def _switch_handoff_graph(*, include_unrelated_lower_table: bool = False) -> FlowGraph:
    """The ordinary DAG leaf is a real table dispatcher, not the final handler."""
    graph, _evidence = _ordinary_decision_dag_evidence()
    table_jump = InsnSnapshot(
        opcode=0,
        ea=0x1600,
        operands=(),
        kind=InsnKind.TABLE_JUMP,
        l=MopSnapshot(kind=OperandKind.SUBINSN, size=4, stack_refs=(0x40,)),
        # The analyzer deliberately ignores degenerate one-row tables.
        r=MopSnapshot(kind=OperandKind.CASE_LIST, switch_cases=(((7,), 7), ((8,), 7))),
    )
    blocks = {
            **graph.blocks,
            5: replace(graph.blocks[5], succs=(6, 4)),
            6: BlockSnapshot(
                serial=6,
                block_type=1,
                succs=(7,),
                preds=(5,),
                flags=0,
                start_ea=0x1600,
                insn_snapshots=(table_jump,),
            ),
            7: _block(7, 0x1700, succs=(), preds=(6,)),
        }
    if include_unrelated_lower_table:
        blocks[0] = BlockSnapshot(
            serial=0,
            block_type=2,
            succs=(4, 5),
            preds=(),
            flags=0,
            start_ea=0x1000,
            insn_snapshots=(replace(
                table_jump,
                ea=0x1000,
                r=MopSnapshot(
                    kind=OperandKind.CASE_LIST,
                    switch_cases=(((7,), 4), ((8,), 5)),
                ),
            ),),
        )
    return FlowGraph(
        blocks,
        graph.entry_serial,
        graph.func_ea,
    )


def _ordinary_switch_handoff_production(
    *, handoff_serial: int = 6, handoff_anchor: int = 0x1600,
    state_constant: int = 7, target_serial: int = 7,
) -> tuple[FlowGraph, CanonicalSemanticEvidenceProductionResult]:
    graph = _switch_handoff_graph()
    identities = {serial: _identity(int(block.start_ea)) for serial, block in graph.blocks.items()}
    state = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    raw = DecisionDagRouteWitness(
        state, state_constant, 5, 0x1500, (5,), (0x1500,),
        (DecisionDagComparisonWitness(5, RouteComparison(5, "jz", 7, 6, 4), state),),
        (), handoff_dispatcher_serial=handoff_serial,
        handoff_dispatcher_anchor_ea=handoff_anchor,
    )
    fact = SemanticRouteFact(
        SemanticRouteFactKind.DECISION_DAG, 2, 2, 0x1200, state_constant,
        target_serial, 0x1200, int(graph.blocks[target_serial].start_ea), (2,), (),
        decision_dag_witness=raw,
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY, 0, "switch-handoff:ordinary", state,
        tuple(graph.blocks.values()), tuple(identities.items()),
    )
    return graph, build_canonical_semantic_evidence((fact,), context)


def _ordinary_switch_handoff_evidence(
    *, handoff_serial: int = 6, handoff_anchor: int = 0x1600,
    state_constant: int = 7, target_serial: int = 7,
) -> tuple[FlowGraph, CanonicalSemanticEvidence]:
    graph, result = _ordinary_switch_handoff_production(
        handoff_serial=handoff_serial,
        handoff_anchor=handoff_anchor,
        state_constant=state_constant,
        target_serial=target_serial,
    )
    return graph, _accepted(result)


def test_decision_dag_switch_handoff_is_canonicalized_and_bound() -> None:
    graph, evidence = _ordinary_switch_handoff_evidence()
    handoff = evidence.route_proofs[0].state_dag.switch_handoff
    assert handoff == SemanticSwitchTableHandoff(
        SemanticCorridorPoint(_identity(0x1600), 0x1600),
        StorageIdentity(StorageIdentityKind.STACK, 0x40),
        7,
    )
    assert bind_canonical_semantic_evidence(graph, evidence) is not None


def test_decision_dag_switch_handoff_uses_exact_bound_dispatcher() -> None:
    graph, evidence = _ordinary_switch_handoff_evidence()
    graph = _switch_handoff_graph(include_unrelated_lower_table=True)

    assert bind_canonical_semantic_evidence(graph, evidence) is not None


def test_decision_dag_switch_handoff_rejects_final_handler_adjacency_drift() -> None:
    graph, evidence = _ordinary_switch_handoff_evidence()
    drifted = FlowGraph(
        {**graph.blocks, 7: replace(graph.blocks[7], preds=())},
        graph.entry_serial,
        graph.func_ea,
    )

    assert bind_canonical_semantic_evidence(drifted, evidence) is None


@pytest.mark.parametrize(
    ("handoff_serial", "handoff_anchor", "state_constant", "target_serial"),
    (
        (5, 0x1500, 7, 7),  # comparison node is not the table dispatcher
        (6, 0x1601, 7, 7),  # no exact stable table-dispatcher anchor
        (6, 0x1600, 7, 4),  # table mapping resolves to a different final handler
    ),
)
def test_decision_dag_switch_handoff_rejects_exact_mapping_drift(
    handoff_serial: int,
    handoff_anchor: int,
    state_constant: int,
    target_serial: int,
) -> None:
    graph, evidence = _ordinary_switch_handoff_evidence(
        handoff_serial=handoff_serial,
        handoff_anchor=handoff_anchor,
        state_constant=state_constant,
        target_serial=target_serial,
    )
    assert bind_canonical_semantic_evidence(graph, evidence) is None


def test_decision_dag_producer_rejects_state_claim_without_matching_source_write() -> None:
    _graph, result = _ordinary_switch_handoff_production(state_constant=8)

    assert result.evidence is None
    assert result.abstention is not None
    assert result.abstention.reason is CanonicalSemanticEvidenceProductionReason.NATIVE_BOUND_SOURCE_ASSIGNMENT_INVALID


def _namespace_bridge_decision_dag_evidence(
    *,
    bridge_mode: str = "exact",
) -> tuple[FlowGraph, CanonicalSemanticEvidence]:
    """One real two-node DAG whose child consumes an exact XDU namespace."""

    state = StorageIdentity(StorageIdentityKind.STACK, 52)
    register = StorageIdentity(StorageIdentityKind.REGISTER, 0)
    xdu = InsnSnapshot(
        opcode=0,
        ea=0x1300,
        operands=(),
        kind=InsnKind.XDU,
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=52),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=0),
    )
    root_branch = InsnSnapshot(
        opcode=0,
        ea=0x1304,
        operands=(),
        kind=InsnKind.COND_JUMP,
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=52),
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=4),
        branch_predicate=PredicateKind.SLE,
        is_conditional_jump=True,
    )
    child_branch = InsnSnapshot(
        opcode=0,
        ea=0x1400,
        operands=(),
        kind=InsnKind.COND_JUMP,
        l=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=0),
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=7),
        branch_predicate=PredicateKind.SLE,
        is_conditional_jump=True,
    )
    state_write = InsnSnapshot(
        opcode=0,
        ea=0x1200,
        operands=(),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=52),
    )
    graph = FlowGraph(
        {
            2: BlockSnapshot(2, 1, (3,), (), 0, 0x1200, (state_write,)),
            3: BlockSnapshot(3, 2, (4, 6), (2,), 0, 0x1300, (xdu, root_branch)),
            4: BlockSnapshot(4, 2, (7, 8), (3,), 0, 0x1400, (child_branch,)),
            6: _block(6, 0x1600, succs=(), preds=(3,)),
            7: _block(7, 0x1700, succs=(), preds=(4,)),
            8: _block(8, 0x1800, succs=(), preds=(4,)),
        },
        entry_serial=2,
        func_ea=0x1200,
    )
    exact_bridge = ExactU32XduNamespaceBridge(
        3,
        0x1300,
        0x1300 if bridge_mode != "wrong_ea" else 0x1301,
        state,
        register,
        4,
        8,
    )
    bridges = () if bridge_mode == "missing" else (exact_bridge,)
    if bridge_mode == "extra":
        bridges += (
            ExactU32XduNamespaceBridge(
                4,
                0x1400,
                0x1400,
                register,
                StorageIdentity(StorageIdentityKind.REGISTER, 16),
                4,
                8,
            ),
        )
    witness = DecisionDagRouteWitness(
        state,
        7,
        3,
        0x1300,
        (3, 4),
        (0x1300, 0x1400),
        (
            DecisionDagComparisonWitness(
                3, RouteComparison(3, "jle", 7, 4, 6), state,
            ),
            DecisionDagComparisonWitness(
                4, RouteComparison(4, "jle", 7, 7, 8), register,
            ),
        ),
        (),
        bridges,
    )
    fact = SemanticRouteFact(
        SemanticRouteFactKind.DECISION_DAG,
        2,
        2,
        0x1200,
        7,
        7,
        0x1200,
        0x1700,
        (2,),
        (),
        decision_dag_witness=witness,
    )
    identities = tuple(
        (serial, _identity(int(block.start_ea)))
        for serial, block in graph.blocks.items()
    )
    evidence = _accepted(
        build_canonical_semantic_evidence(
            (fact,),
            CanonicalSemanticEvidenceProductionContext(
                NATIVE_KEY,
                0,
                f"canonical-semantic:namespace-bridge:{bridge_mode}",
                state,
                tuple(graph.blocks.values()),
                identities,
            ),
        )
    )
    return graph, evidence


def test_decision_dag_binds_exact_xdu_namespace_bridge_end_to_end() -> None:
    graph, evidence = _namespace_bridge_decision_dag_evidence()

    bound = bind_canonical_semantic_evidence(graph, evidence)

    assert bound is not None
    witness = evidence.route_proofs[0].state_dag.witness
    assert tuple(item.state_identity for item in witness.comparisons) == (
        StorageIdentity(StorageIdentityKind.STACK, 52),
        StorageIdentity(StorageIdentityKind.REGISTER, 0),
    )
    assert len(witness.bridges) == 1


@pytest.mark.parametrize("bridge_mode", ("missing", "wrong_ea", "extra"))
def test_decision_dag_rejects_unclosed_xdu_namespace_bridge(bridge_mode: str) -> None:
    graph, evidence = _namespace_bridge_decision_dag_evidence(
        bridge_mode=bridge_mode,
    )

    assert bind_canonical_semantic_evidence(graph, evidence) is None


@pytest.mark.parametrize(
    "xdu_mutation",
    (
        lambda xdu: replace(xdu, kind=InsnKind.MOV),
        lambda xdu: replace(
            xdu,
            d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=0),
        ),
        lambda xdu: replace(xdu, is_call=True),
    ),
)
def test_decision_dag_rejects_xdu_namespace_bridge_instruction_drift(
    xdu_mutation,
) -> None:
    graph, evidence = _namespace_bridge_decision_dag_evidence()
    root = graph.blocks[3]
    xdu, branch = root.insn_snapshots
    drifted = FlowGraph(
        {
            **graph.blocks,
            3: replace(root, insn_snapshots=(xdu_mutation(xdu), branch)),
        },
        graph.entry_serial,
        graph.func_ea,
    )

    assert bind_canonical_semantic_evidence(drifted, evidence) is None


def test_decision_dag_rejects_namespace_use_outside_canonical_bridge_edges() -> None:
    graph, evidence = _namespace_bridge_decision_dag_evidence()
    root = graph.blocks[3]
    child = graph.blocks[4]
    drifted = FlowGraph(
        {
            **graph.blocks,
            3: replace(root, succs=(6, 7)),
            4: replace(child, preds=()),
            6: replace(graph.blocks[6], preds=(3,)),
            7: replace(graph.blocks[7], preds=(3, 4)),
        },
        graph.entry_serial,
        graph.func_ea,
    )

    assert bind_canonical_semantic_evidence(drifted, evidence) is None


def _recovered_value_arm_evidence(
    kind: InsnKind,
) -> tuple[FlowGraph, CanonicalSemanticEvidence, SemanticRecoveredStateWriteWitness]:
    """One conditional arm whose state result needs a recovered witness."""
    graph, _ordinary = _ordinary_decision_dag_evidence()
    state_identity = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    source_instruction = replace(
        graph.blocks[2].insn_snapshots[0],
        kind=kind,
        value_op_kind=(ValueOpKind.SUB if kind is InsnKind.SUB else None),
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=1),
    )
    graph = FlowGraph(
        {**graph.blocks, 2: replace(graph.blocks[2], insn_snapshots=(source_instruction,))},
        graph.entry_serial,
        graph.func_ea,
    )
    identities = tuple(
        (serial, _identity(int(block.start_ea)))
        for serial, block in graph.blocks.items()
    )
    dag_witness = DecisionDagRouteWitness(
        state_identity, 7, 5, 0x1500, (5,), (0x1500,),
        tuple(DecisionDagComparisonWitness(serial, comparison, state_identity) for serial, comparison in ((5, RouteComparison(5, "jz", 7, 6, 4)),)), (),
    )
    recovered = SemanticRecoveredStateWriteWitness(
        route_evidence._instruction_projection(source_instruction), state_identity, 4, 7,
    )
    fact = SemanticRouteFact(
        SemanticRouteFactKind.DECISION_DAG, 2, 2, 0x1200, 7, 6,
        0x1200, 0x1600, (2,), (),
        decision_dag_witness=dag_witness,
        recovered_state_write=recovered,
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY, 0, "canonical-semantic:recovered-arm", state_identity,
        tuple(graph.blocks.values()), identities,
    )
    return graph, _accepted(build_canonical_semantic_evidence((fact,), context)), recovered


@pytest.mark.parametrize(
    "kind", (InsnKind.MOV, InsnKind.VALUE, InsnKind.ADD, InsnKind.SUB),
)
def test_decision_dag_binds_exact_recovered_value_conditional_arm(
    kind: InsnKind,
) -> None:
    graph, evidence, recovered = _recovered_value_arm_evidence(kind)

    proof = evidence.route_proofs[0]

    assert proof.state_write is not None
    assert proof.state_write.recovered_state_write == recovered
    assert bind_canonical_semantic_evidence(graph, evidence) is not None


@pytest.mark.parametrize(
    "mutation",
    (
        lambda graph: FlowGraph(
            {**graph.blocks, 2: replace(
                graph.blocks[2],
                insn_snapshots=(replace(graph.blocks[2].insn_snapshots[0], r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=2)),),
            )}, graph.entry_serial, graph.func_ea,
        ),
        lambda graph: FlowGraph(
            {**graph.blocks, 2: replace(
                graph.blocks[2],
                insn_snapshots=(replace(graph.blocks[2].insn_snapshots[0], d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x44)),),
            )}, graph.entry_serial, graph.func_ea,
        ),
        lambda graph: FlowGraph(
            {**graph.blocks, 2: replace(
                graph.blocks[2],
                insn_snapshots=(replace(graph.blocks[2].insn_snapshots[0], d=MopSnapshot(kind=OperandKind.STACK, size=8, stkoff=0x40)),),
            )}, graph.entry_serial, graph.func_ea,
        ),
    ),
)
def test_recovered_value_conditional_arm_rejects_source_operation_drift(mutation) -> None:
    graph, evidence, _recovered = _recovered_value_arm_evidence(InsnKind.VALUE)
    assert bind_canonical_semantic_evidence(mutation(graph), evidence) is None


def test_recovered_value_witness_rejects_mismatched_route_value() -> None:
    graph, _ordinary = _ordinary_decision_dag_evidence()
    state_identity = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    source_instruction = replace(graph.blocks[2].insn_snapshots[0], kind=InsnKind.VALUE)

    with pytest.raises(SemanticRouteEvidenceRejected, match="does not match decision-DAG route"):
        SemanticRouteFact(
            SemanticRouteFactKind.DECISION_DAG, 2, 2, 0x1200, 7, 6,
            0x1200, 0x1600, (2,), (),
            decision_dag_witness=DecisionDagRouteWitness(
                state_identity, 7, 5, 0x1500, (5,), (0x1500,),
                tuple(DecisionDagComparisonWitness(serial, comparison, state_identity) for serial, comparison in ((5, RouteComparison(5, "jz", 7, 6, 4)),)), (),
            ),
            recovered_state_write=SemanticRecoveredStateWriteWitness(
                route_evidence._instruction_projection(source_instruction), state_identity, 4, 8,
            ),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("width", True),
        ("width", "4"),
        ("recovered_state", True),
        ("recovered_state", "7"),
    ),
)
def test_recovered_state_write_witness_rejects_coercible_scalars(
    field: str, value: object,
) -> None:
    """Producer-owned recovered arithmetic never normalizes caller scalars."""
    graph, _ordinary = _ordinary_decision_dag_evidence()
    state_identity = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    instruction = route_evidence._instruction_projection(
        replace(graph.blocks[2].insn_snapshots[0], kind=InsnKind.VALUE)
    )
    values = {"width": 4, "recovered_state": 7}
    values[field] = value
    with pytest.raises((TypeError, SemanticRouteEvidenceRejected)):
        SemanticRecoveredStateWriteWitness(
            instruction, state_identity, **values,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("serial", True),
        ("serial", "7"),
        ("version", True),
        ("version", "0"),
        ("session_id", True),
        ("session_id", "   "),
        ("proxy_token", 7),
        ("proxy_token", "   "),
    ),
)
def test_semantic_logical_dag_endpoint_rejects_coercible_identity_scalars(
    field: str, value: object,
) -> None:
    """Endpoint identity uses the same exact scalar contract as LogicalBlockRef."""
    values: dict[str, object] = {
        "kind": SemanticDagEndpointKind.FUNCTION_EXIT,
        "serial": 7,
        "session_id": "semantic-route-test",
        "proxy_token": "logical-function-exit",
        "version": 0,
    }
    values[field] = value
    with pytest.raises((TypeError, SemanticRouteEvidenceRejected)):
        SemanticLogicalDagEndpoint(**values)


def test_semantic_logical_dag_endpoint_canonical_roundtrip_preserves_exact_identity() -> None:
    endpoint = SemanticLogicalDagEndpoint(
        SemanticDagEndpointKind.FUNCTION_EXIT,
        7,
        "semantic-route-test",
        "logical-function-exit",
        0,
    )
    assert validate_canonical_roundtrip(
        endpoint,
        SemanticLogicalDagEndpoint,
    ) == endpoint
    assert canonical_decode(canonical_bytes(endpoint)) == endpoint


def test_logical_exit_shape_requires_an_exact_block_snapshot() -> None:
    """A lookalike object cannot mint a logical DAG endpoint."""
    from d810.analyses.control_flow.logical_route_endpoint import (
        is_exact_logical_function_exit_shape,
    )

    class Lookalike:
        kind = BlockKind.ZERO_WAY
        succs = ()
        insn_snapshots = ()
        native_start_ea = None
        start_ea = 0xFFFFFFFFFFFFFFFF

    assert not is_exact_logical_function_exit_shape(Lookalike())


def _logical_exit_decision_dag_evidence(
    endpoint_kind: BlockKind = BlockKind.ZERO_WAY,
) -> tuple[FlowGraph, CanonicalSemanticEvidence]:
    graph, _ordinary = _ordinary_decision_dag_evidence()
    logical_exit = BlockSnapshot(
        serial=7,
        block_type=1,
        succs=(),
        preds=(5,),
        flags=0,
        start_ea=0xFFFFFFFFFFFFFFFF,
        insn_snapshots=(),
        kind=endpoint_kind,
    )
    graph = FlowGraph(
        {
            **graph.blocks,
            2: replace(
                graph.blocks[2],
                insn_snapshots=(
                    replace(
                        graph.blocks[2].insn_snapshots[0],
                        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8),
                    ),
                ),
            ),
            5: replace(
                graph.blocks[5],
                succs=(7, 6),
                insn_snapshots=(
                    replace(
                        graph.blocks[5].insn_snapshots[0],
                        d=replace(graph.blocks[5].insn_snapshots[0].d, block_ref=7),
                    ),
                ),
            ),
            6: replace(graph.blocks[6], preds=(5,)),
            7: logical_exit,
        },
        graph.entry_serial,
        graph.func_ea,
    )
    identities = {
        serial: _identity(int(block.start_ea))
        for serial, block in graph.blocks.items()
        if serial != 7
    }
    state_identity = StorageIdentity(StorageIdentityKind.STACK, 0x40)
    fact = SemanticRouteFact(
        SemanticRouteFactKind.DECISION_DAG,
        2,
        2,
        0x1200,
        8,
        6,
        0x1200,
        0x1600,
        (2,),
        (),
        decision_dag_witness=DecisionDagRouteWitness(
            state_identity,
            8,
            5,
            0x1500,
            (5,),
            (0x1500,),
            tuple(DecisionDagComparisonWitness(serial, comparison, state_identity) for serial, comparison in ((5, RouteComparison(5, "jz", 7, 7, 6)),)),
            (),
        ),
    )
    logical_endpoint = SemanticLogicalDagEndpoint(
        kind=SemanticDagEndpointKind.FUNCTION_EXIT,
        serial=7,
        session_id="semantic-route-test",
        proxy_token="logical-function-exit",
        version=0,
    )
    context = CanonicalSemanticEvidenceProductionContext(
        NATIVE_KEY,
        0,
        "canonical-semantic:logical-exit-dag",
        state_identity,
        tuple(graph.blocks.values()),
        tuple(identities.items()),
        logical_endpoints_by_serial=((7, logical_endpoint),),
    )
    return graph, _accepted(build_canonical_semantic_evidence((fact,), context))


@pytest.mark.parametrize("endpoint_kind", (BlockKind.ZERO_WAY, BlockKind.STOP))
def test_decision_dag_binds_exact_logical_function_exit_sibling(
    endpoint_kind: BlockKind,
) -> None:
    graph, evidence = _logical_exit_decision_dag_evidence(endpoint_kind)
    comparison = evidence.route_proofs[0].state_dag.witness.comparisons[0]
    assert comparison.true_target == SemanticLogicalDagEndpoint(
        kind=SemanticDagEndpointKind.FUNCTION_EXIT,
        serial=7,
        session_id="semantic-route-test",
        proxy_token="logical-function-exit",
        version=0,
    )
    assert bind_canonical_semantic_evidence(graph, evidence) is not None


def test_production_context_rejects_native_identity_for_logical_exit_serial() -> None:
    logical_exit = BlockSnapshot(
        serial=7,
        block_type=1,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0xFFFFFFFFFFFFFFFF,
        insn_snapshots=(),
        kind=BlockKind.ZERO_WAY,
    )
    endpoint = SemanticLogicalDagEndpoint(
        kind=SemanticDagEndpointKind.FUNCTION_EXIT,
        serial=7,
        session_id="semantic-route-test",
        proxy_token="logical-function-exit",
        version=0,
    )
    with pytest.raises(SemanticRouteEvidenceRejected, match="overlaps native"):
        CanonicalSemanticEvidenceProductionContext(
            native_key=NATIVE_KEY,
            generation=0,
            atomic_group_id="canonical-semantic:logical-overlap",
            state_identity=StorageIdentity(StorageIdentityKind.STACK, 0x40),
            blocks=(logical_exit,),
            identities_by_serial=((7, _identity(0x1700)),),
            logical_endpoints_by_serial=((7, endpoint),),
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "wrong_serial",
        "session",
        "token",
        "version",
        "successor",
        "wrong_kind",
        "instruction",
        "native_looking",
        "changed_edge",
    ),
)
def test_logical_function_exit_endpoint_rejects_topology_or_edge_drift(mutation: str) -> None:
    graph, evidence = _logical_exit_decision_dag_evidence()
    if mutation in {"wrong_serial", "session", "token", "version"}:
        comparison = evidence.route_proofs[0].state_dag.witness.comparisons[0]
        forged_endpoint = replace(
            comparison.true_target,
            **{
                "wrong_serial": {"serial": 8},
                "session": {"session_id": "drifted-session"},
                "token": {"proxy_token": "drifted-token"},
                "version": {"version": 1},
            }[mutation],
        )
        forged_witness = replace(
            evidence.route_proofs[0].state_dag.witness,
            comparisons=(replace(comparison, true_target=forged_endpoint),),
        )
        forged_dag = replace(evidence.route_proofs[0].state_dag, witness=forged_witness)
        forged = _unsafe_evidence(
            evidence,
            (replace(evidence.route_proofs[0], state_dag=forged_dag),),
        )
        assert bind_canonical_semantic_evidence(graph, forged) is None
        return
    if mutation == "successor":
        graph = FlowGraph(
            {**graph.blocks, 7: replace(graph.blocks[7], succs=(6,))},
            graph.entry_serial,
            graph.func_ea,
        )
    elif mutation == "wrong_kind":
        graph = FlowGraph(
            {**graph.blocks, 7: replace(graph.blocks[7], kind=BlockKind.ONE_WAY)},
            graph.entry_serial,
            graph.func_ea,
        )
    elif mutation == "instruction":
        graph = FlowGraph(
            {
                **graph.blocks,
                7: replace(
                    graph.blocks[7],
                    insn_snapshots=(InsnSnapshot(opcode=0, ea=0x1601, operands=()),),
                ),
            },
            graph.entry_serial,
            graph.func_ea,
        )
    elif mutation == "native_looking":
        graph = FlowGraph(
            {**graph.blocks, 7: replace(graph.blocks[7], start_ea=0x1700)},
            graph.entry_serial,
            graph.func_ea,
        )
    else:
        graph = FlowGraph(
            {
                **graph.blocks,
                5: replace(
                    graph.blocks[5],
                    succs=(6, 7),
                    insn_snapshots=(
                        replace(
                            graph.blocks[5].insn_snapshots[0],
                            d=replace(
                                graph.blocks[5].insn_snapshots[0].d,
                                block_ref=6,
                            ),
                        ),
                    ),
                ),
            },
            graph.entry_serial,
            graph.func_ea,
        )
    assert bind_canonical_semantic_evidence(graph, evidence) is None


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
            tuple(DecisionDagComparisonWitness(serial, comparison, StorageIdentity(StorageIdentityKind.STACK, 0x40)) for serial, comparison in ((5, RouteComparison(5, "jz", 7, 6, 4)),)),
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


def test_partition_producer_accepts_exact_cross_family_member_closure() -> None:
    graph, _composite = _composite_partition_evidence()
    branch = InsnSnapshot(
        opcode=0,
        ea=0x1304,
        native_ea=0x1304,
        operands=(),
        l=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=3),
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2),
        kind=InsnKind.COND_JUMP,
        control_transfer_kind=ControlTransferKind.CONDITIONAL_BRANCH,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    graph = FlowGraph(
        {
            **graph.blocks,
            0: BlockSnapshot(
                serial=0,
                block_type=2,
                succs=(1, 3),
                preds=(),
                flags=0,
                start_ea=0x1000,
                insn_snapshots=(),
            ),
            1: replace(graph.blocks[1], preds=(0,)),
            2: replace(graph.blocks[2], preds=(1, 3)),
            5: replace(graph.blocks[5], preds=(2, 7)),
            3: BlockSnapshot(
                serial=3,
                block_type=1,
                succs=(7, 2),
                preds=(0,),
                flags=0,
                start_ea=0x1300,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=0x1300,
                        native_ea=0x1300,
                        operands=(),
                        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=9),
                        d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=16),
                        kind=InsnKind.MOV,
                        value_op_kind=ValueOpKind.MOVE,
                    ),
                    branch,
                ),
            ),
            7: BlockSnapshot(
                serial=7,
                block_type=1,
                succs=(5,),
                preds=(3,),
                flags=0,
                start_ea=0x1700,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=0x1700,
                        native_ea=0x1700,
                        operands=(),
                        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=9),
                        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=0x40),
                        kind=InsnKind.MOV,
                        value_op_kind=ValueOpKind.MOVE,
                    ),
                ),
            ),
        },
        0,
        graph.func_ea,
    )
    identities = {
        serial: route_evidence.stable_block_identity_from_snapshot(
            block, native_key=NATIVE_KEY,
        )
        for serial, block in graph.blocks.items()
        if serial != 0
    }
    assert all(identity is not None for identity in identities.values())
    state_identity = StorageIdentity(StorageIdentityKind.STACK, 0x40)

    group = StatePartitionGroupWitness(
        "partition-group:shared-writer",
        2,
        0x1200,
        state_identity,
        (
                StatePartitionMemberWitness(1, 2, state_identity, 7),
                StatePartitionMemberWitness(
                    3,
                    2,
                    state_identity,
                    9,
                    StatePartitionConditionalEdgeWitness(
                        0x1304,
                        route_evidence.instruction_projection_without_block_references(branch),
                        SemanticEdgeRole.CONDITIONAL_TAKEN,
                        7,
                    ),
                ),
        ),
    )
    assert prove_partitioned_state_member(
        graph, group.members[0], feeder_instruction_ea=0x1200,
        state_var_stkoff=0x40, state_var_reg=None,
    )
    assert prove_partitioned_state_member(
        graph, group.members[1], feeder_instruction_ea=0x1200,
        state_var_stkoff=0x40, state_var_reg=None,
    )

    def fact(owner: int, state: int, target: int, other_target: int) -> SemanticRouteFact:
        witness = DecisionDagRouteWitness(
            state_identity,
            state,
            5,
            0x1500,
            (5,),
            (0x1500,),
            tuple(DecisionDagComparisonWitness(serial, comparison, state_identity) for serial, comparison in ((5, RouteComparison(5, "jz", 7, 6, 4)),)),
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
    partition_member = fact(1, 7, 6, 4)
    stronger_sibling = SemanticRouteFact(
        SemanticRouteFactKind.DECISION_DAG,
        3,
        7,
        0x1700,
        9,
        4,
        int(graph.blocks[3].start_ea),
        int(graph.blocks[4].start_ea),
        (3, 7),
        ((3, 7),),
        decision_dag_witness=DecisionDagRouteWitness(
            state_identity,
            9,
            5,
            0x1500,
            (5,),
            (0x1500,),
            (
                DecisionDagComparisonWitness(
                    5,
                    RouteComparison(5, "jz", 7, 6, 4),
                    state_identity,
                ),
            ),
            (),
        ),
        partition_member_replacement=SemanticPartitionMemberReplacementWitness(
            group.group_id, 3, state_identity, 9, 4, group,
        ),
    )
    evidence = _accepted(build_canonical_semantic_evidence(
        (partition_member, stronger_sibling), context,
    ))
    assert {proof.proof_kind for proof in evidence.route_proofs} == {
        SemanticRouteProofKind.STATE_PARTITION,
        SemanticRouteProofKind.STATE_DAG,
    }
    binding = bind_canonical_semantic_evidence_result(graph, evidence)
    assert binding.bound_evidence is not None, binding.failures

    feeder_instruction = graph.blocks[2].insn_snapshots[0]
    feeder_drift = FlowGraph(
        {
            **graph.blocks,
            2: replace(
                graph.blocks[2],
                insn_snapshots=(replace(
                    feeder_instruction,
                    l=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=17),
                ),),
            ),
        },
        graph.entry_serial,
        graph.func_ea,
    )
    assert bind_canonical_semantic_evidence(feeder_drift, evidence) is None
    replacement_source = graph.blocks[7].insn_snapshots[0]
    replacement_drift = FlowGraph(
        {
            **graph.blocks,
            7: replace(
                graph.blocks[7],
                insn_snapshots=(replace(
                    replacement_source,
                    l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8),
                ),),
            ),
        },
        graph.entry_serial,
        graph.func_ea,
    )
    assert bind_canonical_semantic_evidence(replacement_drift, evidence) is None

    def assert_incomplete(candidate_facts: tuple[SemanticRouteFact, ...]) -> None:
        result = build_canonical_semantic_evidence(candidate_facts, context)
        assert result.abstention is not None
        assert result.abstention.reason is CanonicalSemanticEvidenceProductionReason.PARTITION_GROUP_INCOMPLETE

    with pytest.raises(SemanticRouteEvidenceRejected, match="immutable group"):
        replace(
            stronger_sibling.partition_member_replacement,
            group_id="partition-group:wrong",
        )
    with pytest.raises(SemanticRouteEvidenceRejected, match="immutable group"):
        replace(
            stronger_sibling.partition_member_replacement,
            state_identity=StorageIdentity(StorageIdentityKind.STACK, 0x44),
        )
    assert_incomplete((
        partition_member,
        stronger_sibling,
        replace(stronger_sibling, fact_id="partition-member:duplicate"),
    ))
    all_replaced_member = replace(
        stronger_sibling,
        owner_serial=1,
        state_constant=7,
        target_serial=6,
        owner_anchor_ea=int(graph.blocks[1].start_ea),
        target_anchor_ea=int(graph.blocks[6].start_ea),
        path_serials=(1, 7),
        path_edges=((1, 7),),
        decision_dag_witness=DecisionDagRouteWitness(
            state_identity, 7, 5, 0x1500, (5,), (0x1500,),
            (DecisionDagComparisonWitness(
                5, RouteComparison(5, "jz", 7, 6, 4), state_identity,
            ),),
            (),
        ),
        partition_member_replacement=SemanticPartitionMemberReplacementWitness(
            group.group_id, 1, state_identity, 7, 6, group,
        ),
    )
    assert_incomplete((all_replaced_member, stronger_sibling))
    with pytest.raises(TypeError, match="only exact decision-DAG"):
        replace(stronger_sibling, kind=SemanticRouteFactKind.STATE_TRANSFORM)


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
            source_instruction_ea=0x1200,
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


def test_current_u32_route_comparison_accepts_only_exact_plain_xdu_prefix() -> None:
    """A live native root may widen the compared state value without an ADD."""
    state = StorageIdentity(StorageIdentityKind.STACK, 52)
    xdu = InsnSnapshot(
        opcode=0,
        ea=0x1300,
        operands=(),
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=52),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=0),
        kind=InsnKind.XDU,
    )
    branch = InsnSnapshot(
        opcode=0,
        ea=0x1304,
        operands=(),
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=52),
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=4),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.SLE,
        is_conditional_jump=True,
    )

    def graph_with(prefix: tuple[InsnSnapshot, ...]) -> FlowGraph:
        return FlowGraph(
            {
                3: BlockSnapshot(
                    serial=3,
                    block_type=2,
                    succs=(4, 5),
                    preds=(0,),
                    flags=0,
                    start_ea=0x1300,
                    insn_snapshots=(*prefix, branch),
                ),
                4: _block(4, 0x1400, succs=(), preds=(3,)),
                5: _block(5, 0x1500, succs=(), preds=(3,)),
            },
            entry_serial=3,
            func_ea=0x1300,
        )

    expected = (RouteComparison(3, "jle", 7, 4, 5), state, 0x1300, 0x1304)
    assert current_u32_route_comparison(
        graph_with((xdu,)), 3, expected_identities=frozenset({state}),
    ) == expected

    wrong_identity = replace(
        xdu, l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=56),
    )
    wrong_input_width = replace(
        xdu, l=MopSnapshot(kind=OperandKind.STACK, size=8, stkoff=52),
    )
    wrong_result_width = replace(
        xdu, d=MopSnapshot(kind=OperandKind.REGISTER, size=4, reg=0),
    )
    non_xdu = replace(xdu, kind=InsnKind.MOV)
    effectful_xdu = replace(xdu, is_call=True)
    extra_value_work = InsnSnapshot(
        opcode=0,
        ea=0x1302,
        operands=(),
        l=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=0),
        d=MopSnapshot(kind=OperandKind.REGISTER, size=8, reg=1),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
    )
    for prefix in (
        (wrong_identity,),
        (wrong_input_width,),
        (wrong_result_width,),
        (non_xdu,),
        (effectful_xdu,),
        (xdu, extra_value_work),
    ):
        assert current_u32_route_comparison(
            graph_with(prefix), 3, expected_identities=frozenset({state}),
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


def test_state_write_binding_uses_native_origin_for_generated_live_ea() -> None:
    """Canonical proof coordinates bind through a generated instruction's origin."""
    graph = _direct_graph()
    source = graph.blocks[1]
    state_write = source.insn_snapshots[0]
    graph = replace(
        graph,
        blocks={
            **graph.blocks,
            1: replace(
                source,
                insn_snapshots=(
                    replace(
                        state_write,
                        ea=0xF000000000001100,
                        native_ea=state_write.ea,
                    ),
                ),
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


def test_bound_block_index_derives_stable_identities_once_for_repeated_resolutions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repeated route resolution consumes one immutable graph-local index."""

    base = _direct_graph()
    filler_count = 64
    graph = FlowGraph(
        {
            **base.blocks,
            **{
                serial: _block(
                    serial,
                    0x2000 + serial * 0x10,
                    succs=(),
                    preds=(),
                )
                for serial in range(3, 3 + filler_count)
            },
        },
        entry_serial=base.entry_serial,
        func_ea=base.func_ea,
    )
    calls = 0
    original = route_evidence.stable_block_identity_from_snapshot

    def counted_identity(*args: object, **kwargs: object):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(route_evidence, "stable_block_identity_from_snapshot", counted_identity)

    index = route_evidence._BoundBlockIndex.build(graph, NATIVE_KEY)
    for _ in range(12):
        assert index.resolve(_identity(0x1100), 0x1100) is not None
        assert index.resolve(_identity(0x1200), 0x1200) is not None
    assert calls == len(graph.blocks)
    legacy_block_visits = 12 * 2 * len(graph.blocks)
    assert calls * 20 < legacy_block_visits


def test_bound_block_index_rejects_wrong_key_and_missing_or_wrong_anchor() -> None:
    graph = _direct_graph()
    index = route_evidence._BoundBlockIndex.build(graph, NATIVE_KEY)
    wrong_key = make_native_key(function_rva=0x2000)
    foreign_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1100, 0x1110),),
        native_key=wrong_key,
        exact_instruction_eas=(0x1100,),
    )

    assert index.resolve(foreign_identity, 0x1100) is None
    assert index.resolve(_identity(0x1100), 0x1101) is None
    assert index.resolve(_identity(0x1100), 0x1200) is None


def test_bound_block_index_preserves_unique_anchor_identity_fallback() -> None:
    graph = FlowGraph(
        {1: _block(1, 0x1100, succs=(), preds=())},
        entry_serial=1,
        func_ea=0x1000,
    )
    index = route_evidence._BoundBlockIndex.build(graph, NATIVE_KEY)

    bound = index.resolve(_identity(0x1100), 0x1100)

    assert bound is not None
    assert bound.serial == 1
    assert bound.identity == _identity(0x1100)


def test_bound_block_index_prefers_one_exact_identity_among_duplicate_anchors() -> None:
    exact = _block(1, 0x1100, succs=(), preds=(), insn_eas=(0x1101,))
    sibling = _block(2, 0x1100, succs=(), preds=(), insn_eas=(0x1102,))
    graph = FlowGraph({1: exact, 2: sibling}, entry_serial=1, func_ea=0x1000)
    identity = route_evidence.stable_block_identity_from_snapshot(
        exact, native_key=NATIVE_KEY,
    )
    assert identity is not None

    bound = route_evidence._BoundBlockIndex.build(graph, NATIVE_KEY).resolve(
        identity, 0x1100,
    )

    assert bound is not None
    assert bound.serial == 1


def test_bound_block_index_rejects_duplicate_exact_identity_ambiguity() -> None:
    first = _block(1, 0x1100, succs=(), preds=(), insn_eas=(0x1101,))
    second = replace(first, serial=2)
    graph = FlowGraph({1: first, 2: second}, entry_serial=1, func_ea=0x1000)
    identity = route_evidence.stable_block_identity_from_snapshot(
        first, native_key=NATIVE_KEY,
    )
    assert identity is not None

    assert route_evidence._BoundBlockIndex.build(graph, NATIVE_KEY).resolve(
        identity, 0x1100,
    ) is None


def test_bound_block_index_uses_native_coordinates_and_excludes_badaddr() -> None:
    block = BlockSnapshot(
        serial=1,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0xFFFFFFFFFFFFFFFF,
        native_start_ea=0x1100,
        insn_snapshots=(InsnSnapshot(
            opcode=0,
            ea=0xFFFFFFFFFFFFFFFF,
            native_ea=0x1101,
            operands=(),
        ),),
    )
    graph = FlowGraph({1: block}, entry_serial=1, func_ea=0x1000)
    identity = route_evidence.stable_block_identity_from_snapshot(
        block, native_key=NATIVE_KEY,
    )
    assert identity is not None

    index = route_evidence._BoundBlockIndex.build(graph, NATIVE_KEY)

    assert 0xFFFFFFFFFFFFFFFF not in index.blocks_by_anchor
    assert index.resolve(identity, 0x1100).serial == 1
    assert index.resolve(identity, 0x1101).serial == 1


def test_bound_block_index_excludes_logical_endpoint_identity_and_binding_bypasses_it() -> None:
    graph, evidence = _logical_exit_decision_dag_evidence()

    index = route_evidence._BoundBlockIndex.build(graph, NATIVE_KEY)

    assert 7 not in index.identities_by_serial
    assert bind_canonical_semantic_evidence(graph, evidence) is not None


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
